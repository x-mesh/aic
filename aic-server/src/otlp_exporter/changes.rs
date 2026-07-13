//! aicd OTLP changes exporter — 프로세스 생명주기 전이(start/exit/rss 급증).
//!
//! opt-in(config `[aicd.exporter]`의 `changes_enabled`, 기본 exporter 활성 시 true)으로, aicd가
//! 주기적으로 프로세스 테이블을 스냅샷하고 **직전 tick과 diff**해 전이만 OTLP Logs(scope=
//! `aic.changes`)로 push한다.
//!
//! **왜 `proc_delta`를 안 쓰나**: aic-client의 `proc_delta`는 `mem_top_proc` probe가 남긴 텍스트를
//! 파싱하는 순수 함수인데, 그 probe가 `| head -n 15`로 상위 15개만 뽑는다. 프로세스 테이블 전체를
//! 못 보므로 **exit를 원천적으로 탐지할 수 없다**(사라진 pid는 current 목록에 없으니 순회 대상이
//! 아니다). 여기서는 aicd가 이미 들고 있는 `sysinfo::System`으로 전체 테이블을 직접 읽는다 —
//! `aic` 프로세스를 spawn할 필요도, JSON wire 계약을 하나 더 유지할 필요도 없다.
//!
//! **spool**: 다른 logs exporter와 동일하게 append만 한다. 드레인은 host metrics task(`serve`)가
//! 단독으로 수행한다(spool.rs 모듈 doc 참고) — 여기서 드레인하면 같은 디렉토리를 두 task가 동시에
//! 스캔해 경합한다.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::watch;

use super::backoff::Backoff;
use super::logs_proto::{self, ChangeEntry, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// 개별 이벤트로 내보낼 프로세스 수 상한(RSS 상위 N).
///
/// 전체 pid를 다 보내면 빌드 서버/cron 호스트에서 초당 수백 건이 나와 ClickHouse 카디널리티가
/// 터진다. 상위 N 밖의 전이는 개수만 집계해 `churn` 한 줄로 보낸다 — "무슨 일이 있었나"는 잃지
/// 않으면서 행 수는 상수로 묶는다.
const TOP_N: usize = 20;

/// RSS가 이 배수 이상으로 뛰면 `rss_spike`로 본다. 완만한 증가는 메트릭(`system.memory.*`)이 이미
/// 보여주므로, 여기서는 "갑자기 튀었다"만 이벤트로 승격한다.
const RSS_SPIKE_RATIO: f64 = 1.5;
/// 작은 프로세스가 2배 뛰는 건(1MB→2MB) 노이즈다. 절대 증가량이 이 값을 넘을 때만 spike.
const RSS_SPIKE_MIN_DELTA: u64 = 64 * 1024 * 1024;

/// changes exporter 실행 설정.
#[derive(Debug, Clone)]
pub struct ChangesConfig {
    /// OTLP collector base URL. `/v1/logs`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 프로세스 스냅샷 주기.
    pub interval: Duration,
    /// 오프라인 spool. host metrics/events/connections config와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. exporter task들이 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<super::ExporterHealth>,
}

/// 한 프로세스의 관측값 — diff에 필요한 최소치만.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcSnap {
    name: String,
    /// **바이트**. sysinfo `p.memory()`가 바이트를 준다 — `ps`의 KiB와 헷갈리면 1024배가 틀어진다.
    rss: u64,
}

/// 프로세스 테이블 전이 하나.
#[derive(Debug, Clone, PartialEq)]
struct Transition {
    subject: String,
    action: &'static str,
    prev_state: Option<String>,
    new_state: Option<String>,
    summary: String,
    /// 정렬용 — 이 전이가 걸린 프로세스의 현재(또는 마지막) RSS.
    weight: u64,
}

/// 프로세스 테이블을 스냅샷하고 직전 tick과 diff한다.
///
/// `prev`가 `None`인 첫 tick은 **baseline**이다. 그때 보이는 수백 개 프로세스를 전부 `start`로
/// 내보내면 aicd 재시작 시각에 가짜 "변경 폭발"이 생기고, 하필 그 순간이 사람들이 RCA를 들여다볼
/// 확률이 가장 높은 때다. 그래서 첫 tick은 요약 한 줄만 `baseline`으로 남기고 넘어간다.
struct ProcSampler {
    sys: System,
    prev: Option<HashMap<u32, ProcSnap>>,
}

impl ProcSampler {
    fn new() -> Self {
        Self {
            sys: System::new(),
            prev: None,
        }
    }

    /// 한 tick 전진 — 스냅샷 후 직전과 diff한 전이 목록을 돌려준다.
    fn tick(&mut self) -> Vec<Transition> {
        // 메모리만 갱신한다(`nothing().with_memory()`). cpu/디스크/환경변수까지 채우면 macOS의
        // full refresh가 눈에 띄게 느려진다 — host_metrics가 같은 이유로 범위를 좁혀 둔 것과 동일.
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_memory(),
        );

        let current: HashMap<u32, ProcSnap> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                (
                    pid.as_u32(),
                    ProcSnap {
                        name: p.name().to_string_lossy().into_owned(),
                        rss: p.memory(),
                    },
                )
            })
            .collect();

        let transitions = match self.prev.take() {
            None => vec![Transition {
                subject: "process-table".to_string(),
                action: "baseline",
                prev_state: None,
                new_state: Some(current.len().to_string()),
                summary: format!("프로세스 {}개 baseline 수립", current.len()),
                weight: u64::MAX,
            }],
            Some(prev) => diff(&prev, &current),
        };
        self.prev = Some(current);
        transitions
    }
}

/// 두 스냅샷의 전이를 뽑는다 — 순수 함수(테스트 가능).
///
/// pid만으로 조인하면 **pid 재사용**에 걸린다: 커널이 종료된 pid를 재발급하면 전혀 다른 프로세스의
/// RSS를 이전 프로세스와 비교해 헛된 `rss_spike`를 만든다. 그래서 `(pid, name)` 쌍이 같을 때만
/// 동일 프로세스로 보고, 이름이 다르면 exit + start 두 전이로 가른다.
fn diff(prev: &HashMap<u32, ProcSnap>, current: &HashMap<u32, ProcSnap>) -> Vec<Transition> {
    let mut out = Vec::new();

    for (pid, now) in current {
        match prev.get(pid) {
            Some(before) if before.name == now.name => {
                if is_spike(before.rss, now.rss) {
                    out.push(Transition {
                        subject: format!("{}:{pid}", now.name),
                        action: "rss_spike",
                        prev_state: Some(before.rss.to_string()),
                        new_state: Some(now.rss.to_string()),
                        summary: format!(
                            "{}({pid}) RSS {} → {}",
                            now.name,
                            fmt_bytes(before.rss),
                            fmt_bytes(now.rss)
                        ),
                        weight: now.rss,
                    });
                }
            }
            // pid 재사용: 같은 번호, 다른 프로세스 → 죽고 새로 뜬 것으로 가른다.
            Some(before) => {
                out.push(exit_transition(*pid, before));
                out.push(start_transition(*pid, now));
            }
            None => out.push(start_transition(*pid, now)),
        }
    }

    for (pid, before) in prev {
        if !current.contains_key(pid) {
            out.push(exit_transition(*pid, before));
        }
    }

    out
}

fn start_transition(pid: u32, p: &ProcSnap) -> Transition {
    Transition {
        subject: format!("{}:{pid}", p.name),
        action: "start",
        prev_state: None,
        new_state: Some(p.rss.to_string()),
        summary: format!("{}({pid}) 시작", p.name),
        weight: p.rss,
    }
}

fn exit_transition(pid: u32, p: &ProcSnap) -> Transition {
    Transition {
        subject: format!("{}:{pid}", p.name),
        action: "exit",
        prev_state: Some(p.rss.to_string()),
        new_state: None,
        summary: format!("{}({pid}) 종료", p.name),
        weight: p.rss,
    }
}

/// 배수와 절대 증가량을 **둘 다** 넘겨야 spike다. 배수만 보면 1MB→2MB가 걸리고, 절대량만 보면
/// 원래 큰 프로세스의 자연스러운 등락이 걸린다.
fn is_spike(before: u64, now: u64) -> bool {
    now > before
        && now.saturating_sub(before) >= RSS_SPIKE_MIN_DELTA
        && now as f64 >= before as f64 * RSS_SPIKE_RATIO
}

/// 상위 [`TOP_N`]개만 개별 이벤트로 두고, 나머지는 `churn` 한 줄로 접는다.
fn cap(mut transitions: Vec<Transition>) -> Vec<Transition> {
    if transitions.len() <= TOP_N {
        return transitions;
    }
    transitions.sort_by(|a, b| b.weight.cmp(&a.weight));
    let dropped = transitions.split_off(TOP_N);
    let starts = dropped.iter().filter(|t| t.action == "start").count();
    let exits = dropped.iter().filter(|t| t.action == "exit").count();
    transitions.push(Transition {
        subject: "process-table".to_string(),
        action: "churn",
        prev_state: None,
        new_state: Some(dropped.len().to_string()),
        summary: format!("그 외 프로세스 전이 {}건 (start {starts}, exit {exits})", dropped.len()),
        weight: 0,
    });
    transitions
}

/// 재전송 중복을 ReplacingMergeTree가 흡수하도록 하는 idempotency 키.
fn record_id(host: &str, t: &Transition, bucket: u64) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    host.hash(&mut h);
    t.subject.hash(&mut h);
    t.action.hash(&mut h);
    t.new_state.hash(&mut h);
    bucket.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn fmt_bytes(b: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    format!("{:.0}MB", b as f64 / MIB)
}

/// changes exporter를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
pub async fn serve_changes(
    cfg: ChangesConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = super::logs_url(&cfg.endpoint);
    tracing::info!(
        url = %url,
        interval_secs = cfg.interval.as_secs(),
        "OTLP changes exporter 시작"
    );

    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut backoff = Backoff::new();
    let mut sampler = ProcSampler::new();
    // host_metrics와 같은 방식으로 얻어야 세 signal(metrics/connections/changes)의 resource가
    // 같은 host.id로 묶인다.
    let host_name = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                // sysinfo의 전체 프로세스 refresh는 blocking이다 — task 루프를 막지 않도록
                // spawn_blocking으로 감싸고, sampler를 넘겼다 돌려받아 직전 tick 상태를 보존한다
                // (host_metrics의 single-flight 패턴과 동일).
                let (returned, transitions) = match tokio::task::spawn_blocking(move || {
                    let t = sampler.tick();
                    (sampler, t)
                })
                .await
                {
                    Ok(pair) => pair,
                    Err(_) => break, // sampler panic — task 종료.
                };
                sampler = returned;

                let transitions = cap(transitions);
                if transitions.is_empty() {
                    continue;
                }

                let now_ns = super::unix_nanos_now();
                let bucket = now_ns / 1_000_000_000 / cfg.interval.as_secs().max(1);
                let entries: Vec<ChangeEntry<'_>> = transitions
                    .iter()
                    .map(|t| ChangeEntry {
                        change_type: "process",
                        subject: &t.subject,
                        action: t.action,
                        prev_state: t.prev_state.as_deref(),
                        new_state: t.new_state.as_deref(),
                        confidence: "observed",
                        source: "collector:sysinfo",
                        record_id: "",
                        summary: &t.summary,
                    })
                    .collect();
                // record_id는 소유 문자열이 필요해 따로 만들고 나서 엮는다.
                let ids: Vec<String> = transitions
                    .iter()
                    .map(|t| record_id(&host_name, t, bucket))
                    .collect();
                let entries: Vec<ChangeEntry<'_>> = entries
                    .into_iter()
                    .zip(ids.iter())
                    .map(|(e, id)| ChangeEntry { record_id: id, ..e })
                    .collect();

                let resource = ResourceAttrs {
                    host_name: &host_name,
                    host_id: &host_id,
                    os_type: &os_type,
                    host_ip: None,
                };
                let body = logs_proto::encode_changes(
                    &entries,
                    &resource,
                    &cfg.service_version,
                    now_ns,
                );

                if !backoff.ready() {
                    if let Err(e) = cfg.spool.append(SignalKind::Logs, &body) {
                        tracing::warn!(error = %e, "OTLP changes spool append 실패 — 이 배치 유실");
                    }
                    continue;
                }

                match super::push_logs(&client, &url, cfg.token.as_deref(), body.clone()).await {
                    Ok(()) => {
                        backoff.on_success();
                        cfg.health.record_ok();
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "OTLP changes push 실패 — spool에 적재");
                        if let Err(e2) = cfg.spool.append(SignalKind::Logs, &body) {
                            tracing::warn!(error = %e2, "OTLP changes spool append 실패 — 이 배치 유실");
                        }
                        backoff.on_failure();
                        cfg.health.record_fail();
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("OTLP changes exporter 종료");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(name: &str, rss: u64) -> ProcSnap {
        ProcSnap {
            name: name.to_string(),
            rss,
        }
    }

    fn map(items: &[(u32, &str, u64)]) -> HashMap<u32, ProcSnap> {
        items.iter().map(|(pid, n, r)| (*pid, snap(n, *r))).collect()
    }

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn diff_reports_start_and_exit() {
        let prev = map(&[(1, "nginx", 10 * MIB), (2, "java", 500 * MIB)]);
        let current = map(&[(1, "nginx", 10 * MIB), (3, "redis", 20 * MIB)]);
        let out = diff(&prev, &current);

        let started = out.iter().find(|t| t.action == "start").unwrap();
        assert_eq!(started.subject, "redis:3");
        assert_eq!(started.prev_state, None, "시작 전에는 상태가 없다");

        let exited = out.iter().find(|t| t.action == "exit").unwrap();
        assert_eq!(exited.subject, "java:2");
        assert_eq!(exited.new_state, None, "종료 후에는 상태가 없다");

        // 변화 없는 nginx는 전이가 아니다 — edge-triggered의 핵심.
        assert!(!out.iter().any(|t| t.subject.starts_with("nginx")));
    }

    #[test]
    fn diff_detects_rss_spike_only_when_both_thresholds_are_crossed() {
        // 배수는 충족하지만 절대 증가량이 작다(1MB→2MB) → 노이즈, spike 아님.
        let out = diff(&map(&[(1, "small", MIB)]), &map(&[(1, "small", 2 * MIB)]));
        assert!(out.is_empty(), "작은 프로세스의 2배 증가는 spike가 아니다");

        // 절대량은 크지만 배수가 작다(1000MB→1050MB) → 자연스러운 등락, spike 아님.
        let out = diff(&map(&[(1, "big", 1000 * MIB)]), &map(&[(1, "big", 1050 * MIB)]));
        assert!(out.is_empty(), "큰 프로세스의 완만한 증가는 spike가 아니다");

        // 둘 다 충족(100MB→300MB) → spike.
        let out = diff(&map(&[(1, "java", 100 * MIB)]), &map(&[(1, "java", 300 * MIB)]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].action, "rss_spike");
        assert_eq!(out[0].prev_state.as_deref(), Some((100 * MIB).to_string().as_str()));
    }

    #[test]
    fn diff_splits_pid_reuse_into_exit_plus_start() {
        // 같은 pid, 다른 프로세스 — RSS를 비교하면 헛된 spike가 나온다.
        let prev = map(&[(1, "old", 10 * MIB)]);
        let current = map(&[(1, "new", 900 * MIB)]);
        let out = diff(&prev, &current);

        assert_eq!(out.len(), 2, "재사용된 pid는 exit + start 두 전이다");
        assert!(out.iter().any(|t| t.action == "exit" && t.subject == "old:1"));
        assert!(out.iter().any(|t| t.action == "start" && t.subject == "new:1"));
        assert!(
            !out.iter().any(|t| t.action == "rss_spike"),
            "pid 재사용을 rss_spike로 오인하면 안 된다"
        );
    }

    #[test]
    fn cap_folds_the_tail_into_one_churn_row() {
        let many: Vec<Transition> = (0..TOP_N as u32 + 5)
            .map(|i| start_transition(i, &snap("p", i as u64)))
            .collect();
        let out = cap(many);

        assert_eq!(out.len(), TOP_N + 1, "상위 N + churn 한 줄");
        let churn = out.last().unwrap();
        assert_eq!(churn.action, "churn");
        assert_eq!(churn.new_state.as_deref(), Some("5"));
        // 살아남은 건 RSS 상위 — 가장 무거운 프로세스가 가장 볼 가치가 있다.
        assert!(out[0].weight >= out[1].weight);
    }

    #[test]
    fn cap_leaves_a_small_batch_alone() {
        let few = vec![start_transition(1, &snap("a", MIB))];
        assert_eq!(cap(few).len(), 1);
    }

    #[test]
    fn first_tick_is_a_baseline_not_a_flood_of_starts() {
        // aicd 재시작 시 수백 개 프로세스가 전부 "새로 시작됨"으로 나가면, 하필 사람들이 RCA를
        // 들여다보는 그 순간에 가짜 변경 폭발이 생긴다.
        let mut s = ProcSampler::new();
        let first = s.tick();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].action, "baseline");
        assert!(s.prev.is_some(), "baseline 이후에는 비교 대상이 생긴다");

        // 두 번째 tick부터는 실제 diff — 같은 순간이라면 전이가 거의 없다.
        let second = s.tick();
        assert!(
            !second.iter().any(|t| t.action == "baseline"),
            "baseline은 한 번만"
        );
    }

    #[test]
    fn record_id_is_stable_within_a_bucket_and_changes_across_them() {
        let t = start_transition(1, &snap("nginx", MIB));
        assert_eq!(record_id("h", &t, 100), record_id("h", &t, 100));
        assert_ne!(record_id("h", &t, 100), record_id("h", &t, 101));
        assert_ne!(record_id("h", &t, 100), record_id("other", &t, 100));
    }
}
