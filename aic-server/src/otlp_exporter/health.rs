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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::{SignalKind, Spool};

/// exporter 전송 카운터 + spool 참조. 모든 필드는 lock-free다(push 경로에 락을 넣지 않는다).
#[derive(Debug)]
pub struct ExporterHealth {
    push_ok_total: AtomicU64,
    push_fail_total: AtomicU64,
    /// 마지막 push 성공 시각(unix seconds). 0이면 "성공한 적 없음".
    last_ok_unix: AtomicU64,
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
            spool,
            endpoint,
        }
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
