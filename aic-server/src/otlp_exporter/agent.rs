//! aicd OTLP agent-events exporter.
//!
//! [`AgentEventBus`](crate::agent_event_bus::AgentEventBus) tap을 구독해, chat/agent가 보낸
//! 행위마다 OTLP LogRecord(scope=`aic.agent`)를 만들어 `{endpoint}/v1/logs`로 push한다.
//! events exporter(`serve_events`)와 동일한 push 기반 구조 — 주기 tick이 아니라 tap 이벤트가
//! 오는 즉시 인코딩+전송한다.
//!
//! spool/backoff 규약도 events와 같다: push 실패 시 공유 [`super::Spool`]에 적재해 유실을 막고,
//! **드레인은 하지 않는다**(드레인 주체는 host metrics task로 단일화 — spool.rs 모듈 doc 참고).
//! backoff는 이 task가 독립적으로 관리한다.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, watch};

use crate::agent_event_bus::AgentEventBus;

use super::backoff::Backoff;
use super::logs_proto::{self, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// agent exporter 실행 설정.
#[derive(Clone)]
pub struct AgentConfig {
    /// OTLP collector base URL. `/v1/logs`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 구독할 agent 행위 tap.
    pub bus: AgentEventBus,
    /// 오프라인 spool. 다른 exporter task와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 네 exporter task가 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<super::ExporterHealth>,
}

/// agent exporter를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
pub async fn serve_agent(
    cfg: AgentConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = super::logs_url(&cfg.endpoint);
    let mut rx = cfg.bus.subscribe();

    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();
    let mut backoff = Backoff::new();

    tracing::info!(url = %url, "OTLP agent exporter 시작");

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Ok(ev) => {
                        let resource = ResourceAttrs {
                            host_name: &host_name,
                            host_id: &host_id,
                            os_type: &os_type,
                            host_ip: None,
                        };
                        let body = logs_proto::encode_agent_event(
                            &ev,
                            &resource,
                            &cfg.service_version,
                            super::unix_nanos_now(),
                        );

                        if !backoff.ready() {
                            // backoff 윈도 안 — push 시도 없이 바로 spool(무유실).
                            if let Err(e) = cfg.spool.append(SignalKind::Logs, &body) {
                                tracing::warn!(error = %e, kind = %ev.kind, "OTLP agent spool append 실패 — 이 이벤트 유실");
                            }
                            continue;
                        }

                        match super::push_logs(&client, &url, cfg.token.as_deref(), body.clone()).await {
                            Ok(()) => {
                                backoff.on_success();
                                cfg.health.record_ok();
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, kind = %ev.kind, "OTLP agent push 실패 — spool에 적재");
                                if let Err(e2) = cfg.spool.append(SignalKind::Logs, &body) {
                                    tracing::warn!(error = %e2, kind = %ev.kind, "OTLP agent spool append 실패 — 이 이벤트 유실");
                                }
                                backoff.on_failure();
                                cfg.health.record_fail();
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "agent tap lagged — 일부 agent 이벤트 유실");
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
    tracing::info!("OTLP agent exporter 종료");
    Ok(())
}
