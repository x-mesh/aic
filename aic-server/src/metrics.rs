//! 데몬 metric — uptime + IPC 요청 누적 수 (atomic counter).
//!
//! `init()`을 main 시작 시 1회 호출. 이후 IPC 핸들러에서 `record_ipc_request()`로 카운트.
//!
//! Phase 3 centralized-record-store에서 도입되는 central store / attach 관련 metric은
//! [`AicdMetrics`] (aicd 측)와 [`AttachMetrics`] (aic-session 측) 구조체에 보관한다.
//! 기존 `init()`/`uptime_secs()`/`record_ipc_request()`/`ipc_request_count()` 자유 함수는
//! legacy 호출자와의 호환을 위해 그대로 유지한다.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use aic_common::MetricsSnapshot;

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

// ── AicdMetrics ────────────────────────────────────────────────

/// `aicd` (supervisor daemon) 측에서 관측하는 central store / attach metric.
///
/// - `central_store_push_total`: CommandRecordStore에 push된 record 누적 수 (R14.1).
/// - `attach_connections`: Attach_UDS의 현재 활성 연결 수 (R14.2, gauge).
/// - `attach_open_total`: 수신한 `AttachOpen` 프레임 누적 수 (R14.3).
///
/// `Arc<AicdMetrics>`로 공유해 Control_UDS / AttachServer / SessionProcessorPool에서 동시
/// 증가시킨다. 구조체 자체는 `Default`를 구현해 테스트에서 쉽게 인스턴스화할 수 있다.
#[derive(Debug, Default)]
pub struct AicdMetrics {
    central_store_push_total: AtomicU64,
    attach_connections: AtomicU64,
    attach_open_total: AtomicU64,
}

impl AicdMetrics {
    /// 모든 카운터를 0으로 초기화한 신규 instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// CommandRecordStore push 1건을 카운트 (R14.1).
    pub fn inc_central_store_push(&self) {
        self.central_store_push_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 현재까지의 `central_store_push_total` 값.
    pub fn central_store_push_total(&self) -> u64 {
        self.central_store_push_total.load(Ordering::Relaxed)
    }

    /// Attach_UDS 연결 1건 시작 — gauge 증가 (R14.2).
    pub fn inc_attach_connection(&self) {
        self.attach_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Attach_UDS 연결 1건 종료 — gauge 감소. 0 underflow는 방지.
    pub fn dec_attach_connection(&self) {
        // fetch_update으로 saturating 감소. attach_connections는 gauge라 음수가 의미 없음.
        let _ = self.attach_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(1)),
        );
    }

    /// 현재 활성 Attach_UDS 연결 수.
    pub fn attach_connections(&self) -> u64 {
        self.attach_connections.load(Ordering::Relaxed)
    }

    /// `AttachOpen` 수신 1건을 카운트 (R14.3).
    pub fn inc_attach_open(&self) {
        self.attach_open_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 현재까지의 `attach_open_total` 값.
    pub fn attach_open_total(&self) -> u64 {
        self.attach_open_total.load(Ordering::Relaxed)
    }

    /// 현재 카운터 값으로 [`MetricsSnapshot`] 을 빌드한다.
    ///
    /// aicd 자체는 ring buffer가 없으므로 `uptime_secs`/`ipc_request_count`는 글로벌
    /// 카운터에서 읽고, `rb_*` / `last_command_secs_ago`는 snapshot에서 기본값(0/None)을
    /// 그대로 둔다. 필요 시 호출자가 다른 필드를 `..`로 덮어쓸 수 있다.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: uptime_secs(),
            pid: std::process::id(),
            ipc_request_count: ipc_request_count(),
            rb_used: 0,
            rb_capacity: 0,
            last_command_secs_ago: None,
            central_store_push_total: self.central_store_push_total(),
            attach_connections: self.attach_connections(),
            attach_open_total: self.attach_open_total(),
            dropped_bytes: 0,
            attach_reconnect_total: 0,
        }
    }
}

// ── AttachMetrics ──────────────────────────────────────────────

/// `aic-session` 측 Attach 관련 metric (R14.4, R14.5).
///
/// - `dropped_bytes`: bounded byte channel backpressure로 drop된 누적 byte 수.
/// - `attach_reconnect_total`: Attach_UDS 재연결 시도 누적 수.
///
/// `Arc<AttachMetrics>`로 BoundedByteChannel / AttachClient reconnect task에서 공유한다.
///
/// `dropped_bytes`는 `Arc<AtomicU64>` 로 보관해 `BoundedByteChannel::dropped_handle()` 과
/// **동일한 인스턴스를 공유**할 수 있도록 한다. 이렇게 하면 channel 측에서 drop 을
/// 관측해 카운터를 `fetch_add` 하는 것만으로 `AttachMetrics::dropped_bytes()` 가 자동
/// 반영되어, 호출자가 별도의 mirror 코드를 쓸 필요가 없다 (task 3.4 의 핵심 설계).
#[derive(Debug, Default)]
pub struct AttachMetrics {
    dropped_bytes: Arc<AtomicU64>,
    attach_reconnect_total: AtomicU64,
}

impl AttachMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// drop된 byte 수를 누적. backpressure 경로에서 호출.
    pub fn add_dropped_bytes(&self, n: u64) {
        if n > 0 {
            self.dropped_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// `dropped_bytes` 카운터의 공유 핸들을 반환한다.
    ///
    /// `BoundedByteChannel::new_with_dropped_counter()` 에 이 핸들을 넘기면
    /// channel 이 drop 을 관측할 때마다 같은 `AtomicU64` 가 증가한다. 즉
    /// `AttachClient::try_send` 쪽에서 별도의 `metrics.add_dropped_bytes(len)` 을
    /// 부를 필요 없이 metric 이 자동 동기화된다 (task 3.4 의 "channel 내부에서
    /// 이미 수행" 주석 대응).
    pub fn dropped_bytes_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dropped_bytes)
    }

    /// 현재까지의 `dropped_bytes` 값.
    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes.load(Ordering::Relaxed)
    }

    /// Attach_UDS 재연결 시도 1건을 카운트.
    pub fn inc_attach_reconnect(&self) {
        self.attach_reconnect_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 현재까지의 `attach_reconnect_total` 값.
    pub fn attach_reconnect_total(&self) -> u64 {
        self.attach_reconnect_total.load(Ordering::Relaxed)
    }

    /// 본 구조체의 값을 [`MetricsSnapshot`] 에 덮어쓴다.
    ///
    /// aic-session의 `GetMetrics` 핸들러가 기존 ring buffer 기반 snapshot을 만든 뒤
    /// 호출해 attach 쪽 필드만 채우는 용도로 사용한다.
    pub fn fill_snapshot(&self, snap: &mut MetricsSnapshot) {
        snap.dropped_bytes = self.dropped_bytes();
        snap.attach_reconnect_total = self.attach_reconnect_total();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 기존 자유 함수 회귀 테스트 ─────────────────────────────

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

    // ── AicdMetrics ────────────────────────────────────────────

    #[test]
    fn aicd_metrics_defaults_to_zero() {
        let m = AicdMetrics::new();
        assert_eq!(m.central_store_push_total(), 0);
        assert_eq!(m.attach_connections(), 0);
        assert_eq!(m.attach_open_total(), 0);
    }

    #[test]
    fn aicd_metrics_inc_counters() {
        let m = AicdMetrics::new();
        for _ in 0..5 {
            m.inc_central_store_push();
        }
        for _ in 0..3 {
            m.inc_attach_open();
        }
        assert_eq!(m.central_store_push_total(), 5);
        assert_eq!(m.attach_open_total(), 3);
    }

    #[test]
    fn aicd_metrics_attach_connection_gauge_saturates() {
        let m = AicdMetrics::new();
        m.inc_attach_connection();
        m.inc_attach_connection();
        assert_eq!(m.attach_connections(), 2);
        m.dec_attach_connection();
        assert_eq!(m.attach_connections(), 1);
        // 0 아래로 내려가지 않아야 함 — underflow 없이 0에서 멈춤
        m.dec_attach_connection();
        m.dec_attach_connection();
        m.dec_attach_connection();
        assert_eq!(m.attach_connections(), 0);
    }

    #[test]
    fn aicd_metrics_snapshot_reflects_counters() {
        init(); // uptime/pid가 snapshot에 채워지는 경로 확인
        let m = AicdMetrics::new();
        m.inc_central_store_push();
        m.inc_central_store_push();
        m.inc_attach_open();
        m.inc_attach_connection();

        let snap = m.snapshot();
        assert_eq!(snap.central_store_push_total, 2);
        assert_eq!(snap.attach_open_total, 1);
        assert_eq!(snap.attach_connections, 1);
        assert_eq!(snap.dropped_bytes, 0);
        assert_eq!(snap.attach_reconnect_total, 0);
        assert_eq!(snap.pid, std::process::id());
    }

    #[test]
    fn aicd_metrics_counters_are_thread_safe() {
        use std::sync::Arc;
        use std::thread;

        let m = Arc::new(AicdMetrics::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m2 = m.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    m2.inc_central_store_push();
                    m2.inc_attach_open();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.central_store_push_total(), 8_000);
        assert_eq!(m.attach_open_total(), 8_000);
    }

    // ── AttachMetrics ──────────────────────────────────────────

    #[test]
    fn attach_metrics_defaults_to_zero() {
        let m = AttachMetrics::new();
        assert_eq!(m.dropped_bytes(), 0);
        assert_eq!(m.attach_reconnect_total(), 0);
    }

    #[test]
    fn attach_metrics_add_dropped_bytes_accumulates() {
        let m = AttachMetrics::new();
        m.add_dropped_bytes(100);
        m.add_dropped_bytes(250);
        m.add_dropped_bytes(0); // no-op
        assert_eq!(m.dropped_bytes(), 350);
    }

    #[test]
    fn attach_metrics_inc_reconnect() {
        let m = AttachMetrics::new();
        for _ in 0..4 {
            m.inc_attach_reconnect();
        }
        assert_eq!(m.attach_reconnect_total(), 4);
    }

    #[test]
    fn attach_metrics_fill_snapshot_overwrites_fields() {
        let m = AttachMetrics::new();
        m.add_dropped_bytes(512);
        m.inc_attach_reconnect();
        m.inc_attach_reconnect();

        let mut snap = MetricsSnapshot::default();
        snap.uptime_secs = 42;
        snap.pid = 12345;
        m.fill_snapshot(&mut snap);

        assert_eq!(snap.dropped_bytes, 512);
        assert_eq!(snap.attach_reconnect_total, 2);
        // 기존 필드는 영향받지 않아야 함
        assert_eq!(snap.uptime_secs, 42);
        assert_eq!(snap.pid, 12345);
    }

    #[test]
    fn attach_metrics_dropped_bytes_handle_shares_counter() {
        // handle 을 통해 직접 fetch_add 하면 metrics.dropped_bytes() 가 같은 값을
        // 돌려준다. 이 공유는 BoundedByteChannel::new_with_dropped_counter() 와의
        // 통합 지점이다 (task 3.4).
        let m = AttachMetrics::new();
        let handle = m.dropped_bytes_handle();
        assert_eq!(m.dropped_bytes(), 0);
        assert_eq!(handle.load(Ordering::Relaxed), 0);

        handle.fetch_add(128, Ordering::Relaxed);
        assert_eq!(m.dropped_bytes(), 128);

        // 반대 방향: add_dropped_bytes 도 handle 에 반영된다.
        m.add_dropped_bytes(72);
        assert_eq!(handle.load(Ordering::Relaxed), 200);
    }
}
