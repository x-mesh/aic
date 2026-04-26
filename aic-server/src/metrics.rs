//! 데몬 metric — uptime + IPC 요청 누적 수 (atomic counter).
//!
//! `init()`을 main 시작 시 1회 호출. 이후 IPC 핸들러에서 `record_ipc_request()`로 카운트.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

static DAEMON_STARTED_AT: OnceLock<Instant> = OnceLock::new();
static IPC_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);

/// 데몬 시작 시점을 기록한다. 멱등 — 두 번 호출해도 첫 번째 값 유지.
pub fn init() {
    let _ = DAEMON_STARTED_AT.set(Instant::now());
}

/// 시작 이후 경과 시간(초). `init()` 호출 전이면 0.
pub fn uptime_secs() -> u64 {
    DAEMON_STARTED_AT
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0)
}

/// IPC 요청 1건을 카운터에 추가.
pub fn record_ipc_request() {
    IPC_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// 누적 IPC 요청 수.
pub fn ipc_request_count() -> u64 {
    IPC_REQUEST_COUNT.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_increments_count() {
        let before = ipc_request_count();
        record_ipc_request();
        record_ipc_request();
        assert!(ipc_request_count() >= before + 2);
    }

    #[test]
    fn uptime_returns_value_after_init() {
        init();
        // init은 멱등이라 다른 테스트가 먼저 호출했어도 OK
        let _ = uptime_secs(); // 0 또는 그 이상
    }
}
