//! aicd log collector (RFC-006). 하위 모듈은 이후 태스크(t8 filter, t9 limiter 등)가 채운다.
//!
//! t6 추가분(볼륨 안전장치, RFC-006 §6 — "이게 핵심이다"): 로그는 명령 이벤트의 100~1000배다.
//! 에이전트에서 막지 않으면 collector보다 네트워크와 spool 디스크가 먼저 터진다. [`filter`]가
//! min_severity로, [`limiter`]가 서비스당 token-bucket으로 볼륨을 줄인다 — 둘 다
//! `exporter::serve_logs`가 라인을 버퍼에 쌓기 전에 통과시킨다(severity가 싸므로 먼저).
//!
//! ★ 불변식 ★ 드롭은 [`DropCounters`]로만 집계한다. **드롭 시점에 합성 `LogLine`을 만들어
//! 파이프라인에 넣지 않는다** — 폭주 중에 일어나는 일이라, 그 순간 로그를 더 만들면 폭주에
//! 기름을 붓는다(Vector/Promtail도 카운터 메트릭만 쓴다). `encode.rs`가 이 카운터를
//! `aic.log.dropped` 게이지로 노출한다.

pub mod checkpoint;
pub mod container;
pub mod exporter;
pub mod file;
pub mod filter;
pub mod journald;
pub mod limiter;
pub mod self_layer;

pub use exporter::{serve_logs, LogsExporterConfig};
pub use filter::passes_severity;
pub use limiter::Limiter;
pub use self_layer::SelfLogLayer;

use std::sync::atomic::{AtomicU64, Ordering};

/// 드롭 사유별 카운터. 폭주와 무관하게 고정 비용이다(atomic 증가뿐 — 새 할당도, 새
/// `LogLine`도 만들지 않는다).
///
/// - `by_severity`: [`filter::passes_severity`]에서 걸림.
/// - `by_rate_limit`: [`Limiter::try_acquire`] 토큰 부족.
/// - `by_channel_full`: 수집기가 `mpsc::Sender::try_send`에 실패했을 때 수집기 쪽에서 올린다
///   (이 태스크 범위 밖 — 수집기 태스크가 아직 없다).
/// - `by_spool_quota`: spool `AppLogs` 쿼터 초과. `Spool`이 이미 `dropped_count`로 세고 있으므로
///   여기 별도 로직을 두지 않고, 메트릭을 만들 때 `Spool::dropped_count(SignalKind::AppLogs)`
///   값을 그대로 복사해 넣는다(스냅샷 시점에 read-through).
#[derive(Debug, Default)]
pub struct DropCounters {
    pub by_severity: AtomicU64,
    pub by_rate_limit: AtomicU64,
    pub by_channel_full: AtomicU64,
    pub by_spool_quota: AtomicU64,
}

impl DropCounters {
    pub fn new() -> Self {
        Self::default()
    }

    /// `(reason, count)` 스냅샷 — `encode_metrics`가 `aic.log.dropped` 게이지 data point를
    /// 만드는 데 쓴다. 사유별로 별도 data point를 만들되, 서비스 태그는 붙이지 않는다
    /// (카디널리티 방어 — 이 태스크 계약 §3).
    pub fn snapshot(&self) -> [(&'static str, u64); 4] {
        [
            ("severity", self.by_severity.load(Ordering::Relaxed)),
            ("rate_limit", self.by_rate_limit.load(Ordering::Relaxed)),
            ("channel_full", self.by_channel_full.load(Ordering::Relaxed)),
            ("spool_quota", self.by_spool_quota.load(Ordering::Relaxed)),
        ]
    }
}
