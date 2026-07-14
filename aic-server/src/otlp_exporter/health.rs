//! exporter 전송 건강 상태 — 네 exporter task가 공유하는 카운터.
//!
//! 왜 필요한가: exporter는 aicd 안에서 조용히 돈다. push가 계속 실패해도 aicd 로그에만 WARN이
//! 남을 뿐, chat을 쓰는 사람은 "내 행위가 서버로 나가고 있다"고 **믿을 뿐 확인할 방법이 없다**.
//! 실제로 구버전 aicd가 exporter 없이 돌던 동안 아무도 눈치채지 못한 사고가 있었다. 그래서
//! 전송 성패를 카운터로 남기고, `GetExporterStatus` IPC로 chat status bar가 읽어간다.
//!
//! 네 task(host metrics/events/connections/agent)가 같은 인스턴스를 `Arc`로 공유한다 — 사람이
//! 알고 싶은 건 "이 호스트의 텔레메트리가 서버에 닿고 있나"이지 어느 signal이 실패했는지가
//! 아니기 때문이다. 개별 signal의 실패는 로그에 남는다.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use super::{SignalKind, Spool};

/// exporter 전송 카운터 + spool 참조. 모든 필드는 lock-free다(push 경로에 락을 넣지 않는다).
#[derive(Debug)]
pub struct ExporterHealth {
    push_ok_total: AtomicU64,
    push_fail_total: AtomicU64,
    /// 마지막 push 성공 시각(unix seconds). 0이면 "성공한 적 없음".
    last_ok_unix: AtomicU64,
    /// agent exporter task(`serve_agent`)가 **지금 살아있는지**. config 플래그가 아니라 실제 생존
    /// 여부를 담는다 — `agent_enabled=true`여도 endpoint 미설정·spool 실패로 task가 안 뜨거나,
    /// 떴다가 죽을 수 있고, 그 경우 이벤트는 똑같이 버려지기 때문이다. 사람이 알아야 하는 건
    /// 설정값이 아니라 **지금 내 이벤트를 받아 갈 구독자가 있느냐**다.
    ///
    /// **"떴다"가 아니라 "살아있다"**임에 유의: spawn 여부만 새기면 단방향 래치가 되어, task가
    /// 죽은 뒤에도 영원히 "살아있음"으로 남는다. 그래서 값은 task 안의 RAII 가드
    /// ([`AgentLiveGuard`])가 켜고, 종료(정상·에러·panic) 시 Drop이 반드시 끈다.
    /// 초기값 false(=아직 구독자 없음)도 사실과 어긋나지 않는다.
    agent_live: AtomicBool,
    /// 오프라인 spool — 밀린 배치 수/버린 수를 여기서 읽는다.
    spool: Arc<Spool>,
    /// collector base URL(표시용).
    endpoint: String,
}

impl ExporterHealth {
    pub fn new(endpoint: String, spool: Arc<Spool>) -> Self {
        Self {
            push_ok_total: AtomicU64::new(0),
            push_fail_total: AtomicU64::new(0),
            last_ok_unix: AtomicU64::new(0),
            agent_live: AtomicBool::new(false),
            spool,
            endpoint,
        }
    }

    /// agent exporter task의 생존 여부를 기록한다.
    ///
    /// **단방향 래치가 아니다** — 반드시 `false`로 되돌아갈 수 있어야 한다. "떴다"와 "살아있다"는
    /// 다른 명제다: `serve_agent`가 endpoint 오류·spool 실패·panic으로 죽으면 구독자는 사라지는데,
    /// 켜진 채로 남으면 `/record now`가 그 뒤로도 영원히 "잘 기록됐다"고 보고한다. 그래서 task 종료
    /// 시 반드시 꺼지도록 [`AgentLiveGuard`]로 감싸 쓴다.
    pub fn set_agent_live(&self, live: bool) {
        self.agent_live.store(live, Ordering::Relaxed);
    }

    /// push 1건 성공. 마지막 성공 시각도 갱신한다.
    pub fn record_ok(&self) {
        self.push_ok_total.fetch_add(1, Ordering::Relaxed);
        self.last_ok_unix.store(unix_now_secs(), Ordering::Relaxed);
    }

    /// push 1건 실패(spool에 적재됨).
    pub fn record_fail(&self) {
        self.push_fail_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 현재 상태 스냅샷 — IPC 응답으로 그대로 나간다.
    pub fn snapshot(&self) -> aic_common::ExporterStatus {
        let last_ok = self.last_ok_unix.load(Ordering::Relaxed);
        aic_common::ExporterStatus {
            enabled: true, // 이 객체가 존재한다는 것 자체가 exporter 활성이라는 뜻이다.
            // 이 aicd는 값을 **안다** — 그래서 Some이다. `None`은 이 필드를 모르는 구버전만 낸다.
            agent_enabled: Some(self.agent_live.load(Ordering::Relaxed)),
            endpoint: self.endpoint.clone(),
            push_ok_total: self.push_ok_total.load(Ordering::Relaxed),
            push_fail_total: self.push_fail_total.load(Ordering::Relaxed),
            // 아직 한 번도 성공한 적 없으면 None — "10초 전 성공"과 "성공한 적 없음"은 전혀 다른
            // 상태라, 0초로 뭉개지 않는다.
            last_ok_secs_ago: (last_ok > 0).then(|| unix_now_secs().saturating_sub(last_ok)),
            spool_batches: self.spool.batch_count() as u64,
            // R3: SignalKind별로 쿼터/드랍 카운터가 나뉘었지만, chat status bar가 알고 싶은 건
            // "데이터가 실제로 유실됐는가" 하나이지 어느 kind에서 드랍됐는지가 아니다 — 셋을 합산.
            spool_dropped: [SignalKind::Metrics, SignalKind::Logs, SignalKind::AppLogs]
                .into_iter()
                .map(|k| self.spool.dropped_count(k))
                .sum(),
        }
    }
}

/// agent exporter task의 **생존 구간**을 표시하는 RAII 가드.
///
/// 생성 시 `agent_live=true`, drop 시 `false`. task 안에서 들고 있으면 정상 종료·에러 종료·panic
/// (unwind) 어느 경로로 나가든 Drop이 실행되므로, "떴다가 죽었는데 살아있다고 보고"하는 창이 없다.
///
/// **왜 `JoinHandle::is_finished()`가 아닌가**: health를 읽는 쪽(`GetExporterStatus` 핸들러)은
/// handle을 들고 있지 않다 — `ExporterHealth`만 `Arc`로 공유한다. 상태를 읽는 지점에서 확인할 수
/// 있어야 하므로, 살아있음을 health 자신에 새기는 가드가 맞다.
pub struct AgentLiveGuard {
    health: Arc<ExporterHealth>,
}

impl AgentLiveGuard {
    /// 가드를 만들며 즉시 "살아있음"으로 표시한다.
    pub fn new(health: Arc<ExporterHealth>) -> Self {
        health.set_agent_live(true);
        Self { health }
    }
}

impl Drop for AgentLiveGuard {
    fn drop(&mut self) {
        self.health.set_agent_live(false);
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> ExporterHealth {
        let dir = tempfile::tempdir().unwrap();
        let quotas = aic_common::SpoolQuotas {
            metrics: 1024 * 1024,
            logs: 1024 * 1024,
            app_logs: 1024 * 1024,
        };
        let spool = Arc::new(Spool::open(dir.path().to_path_buf(), quotas).unwrap());
        // tempdir이 drop되면 경로가 사라지지만, batch_count는 실패 시 0을 돌려주므로 테스트에
        // 지장이 없다. 카운터 동작만 검증한다.
        std::mem::forget(dir);
        ExporterHealth::new("http://localhost:4318".to_string(), spool)
    }

    #[test]
    fn fresh_health_has_never_succeeded() {
        let h = health();
        let s = h.snapshot();
        assert_eq!(s.push_ok_total, 0);
        assert_eq!(s.push_fail_total, 0);
        // 성공한 적 없음은 None — "방금 성공(0초 전)"과 구분되어야 한다.
        assert_eq!(s.last_ok_secs_ago, None);
    }

    #[test]
    fn agent_live_guard_clears_liveness_on_every_exit_including_panic() {
        // **단방향 래치 회귀 테스트**: "떴다"는 "살아있다"가 아니다. serve_agent가 endpoint 오류·
        // spool 실패·panic으로 죽으면 구독자는 사라지는데, agent_live가 켜진 채 남으면
        // `/record now`가 그 뒤로 영원히 "잘 기록됐다"(Delivered)고 조용한 성공을 보고한다.
        let h = Arc::new(health());
        assert_eq!(h.snapshot().agent_enabled, Some(false), "초기값은 미기동");

        // 정상 종료: 가드가 scope를 벗어나면 꺼진다.
        {
            let _live = AgentLiveGuard::new(h.clone());
            assert_eq!(
                h.snapshot().agent_enabled,
                Some(true),
                "가드가 살아있는 동안은 켜져 있어야"
            );
        }
        assert_eq!(
            h.snapshot().agent_enabled,
            Some(false),
            "task가 끝났는데 살아있다고 보고한다(단방향 래치)"
        );

        // panic 경로: unwind에서도 Drop이 돌아 꺼져야 한다(exporter task의 panic이 정확히 이 경우다).
        let h2 = h.clone();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _live = AgentLiveGuard::new(h2);
            panic!("exporter task가 죽었다");
        }));
        assert!(res.is_err(), "panic이 나야 하는 테스트");
        assert_eq!(
            h.snapshot().agent_enabled,
            Some(false),
            "panic으로 죽었는데 살아있다고 보고한다"
        );
    }

    #[test]
    fn agent_liveness_is_reported_and_defaults_to_not_live() {
        // chat `/record now <메모>`가 "이 메모가 서버에 남는가"를 판단하는 유일한 근거다.
        // 이 aicd는 값을 아는 버전이므로 **항상 Some**을 낸다 — None(모름)은 구버전만 낸다.
        let h = health();
        assert_eq!(
            h.snapshot().agent_enabled,
            Some(false),
            "task가 아직 안 떴으면 false여야 한다(사실과 어긋나지 않게)"
        );

        // agent exporter task가 실제로 뜨면 true.
        h.set_agent_live(true);
        assert_eq!(h.snapshot().agent_enabled, Some(true));

        // 부모 게이트(enabled)와는 별개의 축이다 — 이 객체가 존재하면 부모는 켜진 것이다.
        assert!(h.snapshot().enabled);
    }

    #[test]
    fn ok_and_fail_are_counted_separately() {
        let h = health();
        h.record_ok();
        h.record_ok();
        h.record_fail();
        let s = h.snapshot();
        assert_eq!(s.push_ok_total, 2);
        assert_eq!(s.push_fail_total, 1);
        // 성공한 적이 있으므로 이제 Some이고, 방금이라 0초 근처다.
        assert!(s.last_ok_secs_ago.is_some_and(|secs| secs <= 1));
    }

    #[test]
    fn endpoint_is_carried_for_display() {
        let h = health();
        assert_eq!(h.snapshot().endpoint, "http://localhost:4318");
        assert!(h.snapshot().enabled);
    }
}
