//! aicd OTLP events exporter (SRE t7).
//!
//! `CommandRecordStore::subscribe()`(broadcast tap)을 구독해, ring에 실제로 삽입된 finished
//! command record마다 OTLP LogRecord(scope=`aic.events`)를 만들어 `{endpoint}/v1/logs`로 push한다.
//! host_metrics exporter(t6, `serve`)와 달리 주기 tick이 아니라 **push 기반**(tap 이벤트가 오는
//! 즉시 인코딩+전송)이다.
//!
//! t8: push 실패 시 공유 [`super::Spool`]에 적재해 유실을 막는다. **드레인은 하지 않는다** —
//! 이 task는 push 기반이라 자연스러운 tick이 없고, 드레인 주체는 host metrics task(`serve`)로
//! 단일화되어 있다(spool.rs 모듈 doc 참고). 이 task는 자기 push 성패만으로 자신의 backoff를
//! 독립적으로 관리한다 — 세 task가 backoff 상태를 공유하지 않는 이유는 공유하려면
//! `Arc<Mutex<Backoff>>` 동기화가 필요한데, 각 task의 실패는 어차피 같은 collector 도달 불가를
//! 반영하므로 독립 backoff로도 동일한 효과(재시도 폭주 억제)를 얻으면서 구현이 단순해진다.
//!
//! shutdown 처리는 다른 exporter task와 동일하게 shared `watch::Receiver<bool>`를 구독한다.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, watch};

use crate::command_record_store::CommandRecordStore;

use super::backoff::Backoff;
use super::logs_proto::{self, CommandEvent, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — host metrics exporter와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// events exporter 실행 설정.
#[derive(Clone)]
pub struct EventsConfig {
    /// OTLP collector base URL. `/v1/logs`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// tap을 구독할 store.
    pub store: CommandRecordStore,
    /// 오프라인 spool(SRE t8). host metrics/connections config와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 네 exporter task가 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<super::ExporterHealth>,
}

/// events exporter를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
pub async fn serve_events(
    cfg: EventsConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = super::logs_url(&cfg.endpoint);
    let mut rx = cfg.store.subscribe();

    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();
    let mut backoff = Backoff::new();

    tracing::info!(url = %url, "OTLP events exporter 시작");

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Ok(record) => {
                        let ev = CommandEvent {
                            id: &record.id,
                            command: record.command.as_deref(),
                            exit_code: record.exit_code,
                            capture_quality: capture_quality_label(record.capture_quality),
                        };
                        let resource = ResourceAttrs {
                            host_name: &host_name,
                            host_id: &host_id,
                            os_type: &os_type,
                            host_ip: None,
                        };
                        let body = logs_proto::encode_command_event(
                            &ev,
                            &resource,
                            &cfg.service_version,
                            super::unix_nanos_now(),
                        );

                        if !backoff.ready() {
                            // backoff 윈도 안 — push 시도 없이 바로 spool(무유실). 드레인은 이 task가
                            // 하지 않는다(serve 담당, 모듈 doc 참고).
                            if let Err(e) = cfg.spool.append(SignalKind::Logs, &body) {
                                tracing::warn!(error = %e, record_id = %record.id, "OTLP events spool append 실패 — 이 이벤트 유실");
                            }
                            continue;
                        }

                        match super::push_logs(&client, &url, cfg.token.as_deref(), body.clone()).await {
                            Ok(()) => {
                                backoff.on_success();
                                cfg.health.record_ok();
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, record_id = %record.id, "OTLP events push 실패 — spool에 적재");
                                if let Err(e2) = cfg.spool.append(SignalKind::Logs, &body) {
                                    tracing::warn!(error = %e2, record_id = %record.id, "OTLP events spool append 실패 — 이 이벤트 유실");
                                }
                                backoff.on_failure();
                                cfg.health.record_fail();
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        // consumer가 producer를 못 따라감 — 채널 용량 초과분은 유실.
                        tracing::warn!(skipped, "events tap lagged — 일부 command 이벤트 유실");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("OTLP events exporter 종료");
    Ok(())
}

/// `CaptureQuality`를 attr 문자열로. `Debug` 유도 대신 고정 매핑을 써서 OTLP wire에 나가는
/// 문자열이 enum 내부 표현 변경에 우연히 흔들리지 않게 한다.
fn capture_quality_label(q: aic_common::CaptureQuality) -> &'static str {
    use aic_common::CaptureQuality;
    match q {
        CaptureQuality::FullOutput => "FullOutput",
        CaptureQuality::MetadataOnly => "MetadataOnly",
        CaptureQuality::RedactedOutput => "RedactedOutput",
        CaptureQuality::BinaryOmitted => "BinaryOmitted",
        CaptureQuality::TruncatedOutput => "TruncatedOutput",
        CaptureQuality::Unknown => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_quality_label_covers_all_variants() {
        use aic_common::CaptureQuality;
        assert_eq!(
            capture_quality_label(CaptureQuality::FullOutput),
            "FullOutput"
        );
        assert_eq!(
            capture_quality_label(CaptureQuality::MetadataOnly),
            "MetadataOnly"
        );
        assert_eq!(
            capture_quality_label(CaptureQuality::RedactedOutput),
            "RedactedOutput"
        );
        assert_eq!(
            capture_quality_label(CaptureQuality::BinaryOmitted),
            "BinaryOmitted"
        );
        assert_eq!(
            capture_quality_label(CaptureQuality::TruncatedOutput),
            "TruncatedOutput"
        );
        assert_eq!(capture_quality_label(CaptureQuality::Unknown), "Unknown");
    }
}
