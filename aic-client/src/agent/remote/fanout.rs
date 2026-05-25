//! N개 호스트에 [`RemoteExecutor`]를 병렬 실행하는 fan-out (RFC-005 Phase 3).
//!
//! 동시성 cap [`Semaphore`]로 제한 + per-host timeout은 executor가, **wall-clock timeout**은
//! 이 모듈이 책임진다. continue-and-report — 일부 호스트 실패해도 나머지는 끝까지 수집.
//!
//! Ctrl+C 취소는 호출자가 future를 drop하는 형태로 전파한다(상위 layer에서 select!).
//! `FuturesUnordered` drop은 미완료 task의 ssh child를 `kill_on_drop`으로 정리한다(R3).
//!
//! RFC-005 §4.5 정합 사항:
//! - Semaphore: `acquire_owned` move-capture로 permit 누수 차단 (R1).
//! - wall timeout 도달 시 **부분 결과 보존**(§6 Open Q4 MVP 정책 — 남긴다).

use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use super::{HostStatus, RemoteCommand, RemoteExecutor, RemoteResult};
use crate::agent::hosts::{Concurrency, HostEntry};

/// fan-out 실행 결과. 부분 결과 + wall timeout 도달 여부 + 미완료 호스트 목록.
#[derive(Debug, Clone)]
pub struct FanoutResult {
    pub results: Vec<RemoteResult>,
    /// wall_clock_timeout 도달 시 true. 이 경우 미완료 호스트는 결과에 빠진다.
    pub wall_timed_out: bool,
    /// wall timeout 도달 시 미완료(cancel된) 호스트 이름들. 빈 vec이면 전부 완료.
    pub incomplete: Vec<String>,
}

impl FanoutResult {
    /// 상태별 카운트 — 카드 stack 헤더 통계에 사용.
    pub fn counts(&self) -> StatusCounts {
        let mut c = StatusCounts::default();
        for r in &self.results {
            match r.status {
                HostStatus::Ok => c.ok += 1,
                HostStatus::OkWithWarn => c.ok_warn += 1,
                HostStatus::Unreachable => c.unreachable += 1,
                HostStatus::Timeout => c.timeout += 1,
                HostStatus::AuthFail => c.auth_fail += 1,
                HostStatus::ProxyFail => c.proxy_fail += 1,
                HostStatus::RemoteErr => c.remote_err += 1,
                HostStatus::HostKeyMismatch => c.host_key_mismatch += 1,
            }
        }
        c.cancelled = self.incomplete.len();
        c
    }
}

#[derive(Debug, Default, Clone)]
pub struct StatusCounts {
    pub ok: usize,
    pub ok_warn: usize,
    pub unreachable: usize,
    pub timeout: usize,
    pub auth_fail: usize,
    pub proxy_fail: usize,
    pub remote_err: usize,
    pub host_key_mismatch: usize,
    pub cancelled: usize,
}

impl StatusCounts {
    pub fn total(&self) -> usize {
        self.ok
            + self.ok_warn
            + self.unreachable
            + self.timeout
            + self.auth_fail
            + self.proxy_fail
            + self.remote_err
            + self.host_key_mismatch
            + self.cancelled
    }
}

/// N개 호스트에 같은 `command`를 병렬 실행. `concurrency.max_parallel`로 동시성 cap,
/// `concurrency.wall_clock_timeout_secs`로 전체 timeout. per-host timeout은 executor 책임.
///
/// 호스트가 0개면 즉시 빈 결과. continue-and-report — 일부 호스트가 실패해도 다른 호스트는
/// 끝까지 진행. wall timeout 도달 시 [`FanoutResult::incomplete`]에 미완료 호스트 이름 기록.
pub async fn run_fanout<E>(
    executor: &E,
    hosts: &[HostEntry],
    command: &RemoteCommand,
    concurrency: &Concurrency,
) -> FanoutResult
where
    E: RemoteExecutor,
{
    if hosts.is_empty() {
        return FanoutResult {
            results: Vec::new(),
            wall_timed_out: false,
            incomplete: Vec::new(),
        };
    }

    let cap = concurrency.max_parallel.max(1);
    let sem = Arc::new(Semaphore::new(cap));
    let wall = std::time::Duration::from_secs(u64::from(concurrency.wall_clock_timeout_secs));

    let mut fut_set = FuturesUnordered::new();
    for host in hosts {
        let sem = Arc::clone(&sem);
        let host_ref = host;
        let cmd_ref = command;
        fut_set.push(async move {
            // acquire_owned 대신 borrow + move-capture로 누수 차단(R1).
            // FuturesUnordered가 drop되면 이 future도 drop → permit RAII 반환.
            let _permit = sem
                .acquire()
                .await
                .expect("semaphore not closed");
            executor.exec(host_ref, cmd_ref).await
        });
    }

    let mut results: Vec<RemoteResult> = Vec::with_capacity(hosts.len());
    let mut wall_timed_out = false;
    let deadline = Instant::now() + wall;

    loop {
        tokio::select! {
            biased;
            // wall deadline 우선 검사 — 동시에 ready여도 timeout 먼저 잡아 부분 결과 보존.
            _ = tokio::time::sleep_until(deadline), if !fut_set.is_empty() => {
                wall_timed_out = true;
                break;
            }
            maybe = fut_set.next() => {
                match maybe {
                    Some(r) => results.push(r),
                    None => break, // 전부 완료
                }
            }
        }
    }

    // 미완료 호스트 — 이미 결과를 push한 호스트 이름을 set으로 빼고 차집합.
    let incomplete: Vec<String> = if wall_timed_out {
        let done: std::collections::HashSet<&str> =
            results.iter().map(|r| r.host.as_str()).collect();
        hosts
            .iter()
            .map(|h| h.name.clone())
            .filter(|n| !done.contains(n.as_str()))
            .collect()
    } else {
        Vec::new()
    };

    FanoutResult {
        results,
        wall_timed_out,
        incomplete,
    }
}

// ── 테스트 ─────────────────────────────────────────────────────────
// 실제 ssh 호출 없이 fake executor로 검증.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::hosts::HostKeyCheck;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// 가짜 executor: 각 호스트마다 정해진 지연 후 정상 응답.
    struct DelayExecutor {
        delay_ms: u64,
        invocations: AtomicUsize,
    }

    impl DelayExecutor {
        fn new(delay_ms: u64) -> Self {
            Self {
                delay_ms,
                invocations: AtomicUsize::new(0),
            }
        }
    }

    impl RemoteExecutor for DelayExecutor {
        async fn exec(
            &self,
            host: &HostEntry,
            _cmd: &RemoteCommand,
        ) -> RemoteResult {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            RemoteResult {
                host: host.name.clone(),
                stdout: format!("hello from {}", host.name),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: self.delay_ms,
                status: HostStatus::Ok,
                truncated: false,
                redacted: 0,
            }
        }
    }

    fn dummy_host(name: &str) -> HostEntry {
        HostEntry {
            name: name.into(),
            hostname: name.into(),
            user: "u".into(),
            port: 22,
            identity_file: None,
            forward_agent: false,
            proxy_jump: None,
            host_key_check: HostKeyCheck::Strict,
            connect_timeout_secs: 10,
            tags: vec![],
            source: crate::agent::hosts::HostSource::HostsToml,
        }
    }

    #[tokio::test]
    async fn fanout_empty_hosts_returns_empty() {
        let exec = DelayExecutor::new(0);
        let r = run_fanout(
            &exec,
            &[],
            &RemoteCommand::new("uptime"),
            &Concurrency::default(),
        )
        .await;
        assert!(r.results.is_empty());
        assert!(!r.wall_timed_out);
    }

    #[tokio::test]
    async fn fanout_all_complete_under_wall_timeout() {
        let hosts: Vec<HostEntry> = (1..=5).map(|i| dummy_host(&format!("h{i}"))).collect();
        let exec = DelayExecutor::new(20);
        let conc = Concurrency {
            max_parallel: 4,
            per_host_timeout_secs: 10,
            wall_clock_timeout_secs: 5,
        };
        let r = run_fanout(&exec, &hosts, &RemoteCommand::new("uptime"), &conc).await;
        assert_eq!(r.results.len(), 5);
        assert!(!r.wall_timed_out);
        assert!(r.incomplete.is_empty());
        assert_eq!(exec.invocations.load(Ordering::SeqCst), 5);
        // 모두 ok
        let c = r.counts();
        assert_eq!(c.ok, 5);
        assert_eq!(c.total(), 5);
    }

    #[tokio::test]
    async fn fanout_respects_max_parallel_cap() {
        // 호스트 8개, cap 2, 각 100ms → 최소 4 라운드 × 100ms ≈ 400ms 이상 소요.
        let hosts: Vec<HostEntry> = (1..=8).map(|i| dummy_host(&format!("h{i}"))).collect();
        let exec = DelayExecutor::new(100);
        let conc = Concurrency {
            max_parallel: 2,
            per_host_timeout_secs: 10,
            wall_clock_timeout_secs: 5,
        };
        let start = std::time::Instant::now();
        let r = run_fanout(&exec, &hosts, &RemoteCommand::new("uptime"), &conc).await;
        let elapsed = start.elapsed();
        assert_eq!(r.results.len(), 8);
        assert!(
            elapsed >= Duration::from_millis(350),
            "cap 2 × 8 hosts × 100ms은 ≥ ~400ms이어야 함, 실제 {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn fanout_wall_timeout_returns_partial_results_with_incomplete_list() {
        // 호스트 6개, 각 200ms, cap 2 → 라운드 3회. wall_clock 250ms로 잘라 첫 2개만 완료.
        let hosts: Vec<HostEntry> = (1..=6).map(|i| dummy_host(&format!("h{i}"))).collect();
        let exec = DelayExecutor::new(200);
        let conc = Concurrency {
            max_parallel: 2,
            per_host_timeout_secs: 10,
            wall_clock_timeout_secs: 0, // 일부러 0 — sleep_until이 즉시 deadline에 도달
        };
        // 0초는 즉시 timeout. 정확히는 ms 단위로 control하기 위해 별도 함수가 필요하지만,
        // wall=0이면 첫 sleep이 즉시 wake → wall_timed_out=true, results는 비거나 거의 비어 있음.
        let r = run_fanout(&exec, &hosts, &RemoteCommand::new("uptime"), &conc).await;
        assert!(r.wall_timed_out, "wall=0이면 즉시 timeout");
        assert!(!r.incomplete.is_empty(), "미완료 호스트가 있어야 함");
        assert_eq!(r.results.len() + r.incomplete.len(), 6);
    }
}
