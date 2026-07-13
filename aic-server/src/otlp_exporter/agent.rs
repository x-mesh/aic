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
                            agent_event_time_unix_nano(ev.ts, super::unix_nanos_now()),
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

/// LogRecord `time_unix_nano`로 쓸 시각을 고른다. **"사람이 순간을 남긴다"**는 의미상
/// push 시각(`now`)이 아니라 행위가 실제로 일어난 시각(`ts` = `AgentEvent.ts`)을 우선한다 —
/// aicd가 밀리거나 tap이 지연돼도 기록에는 원래 순간이 남아야 한다.
///
/// `ts`가 epoch 0 이하이거나(비정상 초기값), chrono 표현 범위를 벗어나거나(연도 대략
/// 1677~2262 밖 — `timestamp_nanos_opt()`가 `None`), `now`보다 미래(시계 skew 방어)면
/// `now`로 폴백한다: 미래 시각이나 epoch 0을 그대로 collector에 보내지 않기 위한 불변식이다.
fn agent_event_time_unix_nano(ts: chrono::DateTime<chrono::Utc>, now: u64) -> u64 {
    match ts.timestamp_nanos_opt() {
        Some(nanos) if nanos > 0 => {
            let nanos = nanos as u64;
            if nanos <= now {
                nanos
            } else {
                now
            }
        }
        _ => now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use std::collections::BTreeMap;

    fn event_with_ts(ts: chrono::DateTime<chrono::Utc>) -> aic_common::AgentEvent {
        aic_common::AgentEvent {
            kind: "tool.run_command".to_string(),
            summary: "ls -la".to_string(),
            severity: "INFO".to_string(),
            attrs: BTreeMap::new(),
            ts,
        }
    }

    // ts를 고정값으로 넣고 그 값이 그대로(변환 없이) 나오는지 본다 — now()와 비교하지 않는
    // 결정적 검증. `NOW`는 ts보다 한참 뒤의 임의 고정 시각이라 "미래 시각 폴백" 분기를 타지
    // 않는다.
    const PAST_TS_NANOS: i64 = 1_700_000_000_000_000_000; // 2023-11-14 UTC 근방
    const NOW_NANOS: u64 = 1_800_000_000_000_000_000; // 2027-01 근방, PAST_TS_NANOS보다 미래

    #[test]
    fn valid_ts_is_used_as_is_not_now() {
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(PAST_TS_NANOS);
        let got = agent_event_time_unix_nano(ts, NOW_NANOS);
        assert_eq!(got, PAST_TS_NANOS as u64);
        assert_ne!(
            got, NOW_NANOS,
            "now()로 대체되면 안 된다 — ts가 그대로 나와야 한다"
        );
    }

    #[test]
    fn epoch_zero_ts_falls_back_to_now() {
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(0);
        let got = agent_event_time_unix_nano(ts, NOW_NANOS);
        assert_eq!(got, NOW_NANOS);
    }

    #[test]
    fn future_ts_falls_back_to_now() {
        // ts가 now보다 미래면(시계 skew) 그대로 보내지 않고 now로 폴백한다.
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(NOW_NANOS as i64 + 1);
        let got = agent_event_time_unix_nano(ts, NOW_NANOS);
        assert_eq!(got, NOW_NANOS);
    }

    /// LogRecord.time_unix_nano가 AgentEvent.ts에서 유래하는지 encode 결과(protobuf)까지
    /// 디코드해 end-to-end로 확인한다.
    #[test]
    fn encoded_log_record_time_comes_from_agent_event_ts() {
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(PAST_TS_NANOS);
        let ev = event_with_ts(ts);
        let resource = ResourceAttrs {
            host_name: "web-1",
            host_id: "id-abc",
            os_type: "linux",
            host_ip: None,
        };
        let time_unix_nano = agent_event_time_unix_nano(ev.ts, NOW_NANOS);
        let body = logs_proto::encode_agent_event(&ev, &resource, "0.24.0", time_unix_nano);

        let req =
            logs_proto::ExportLogsServiceRequest::decode(body.as_slice()).expect("valid protobuf");
        let lr = &req.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(lr.time_unix_nano, PAST_TS_NANOS as u64);
        assert_ne!(
            lr.time_unix_nano, NOW_NANOS,
            "LogRecord 시각이 push 시각(now)이 아니라 AgentEvent.ts여야 한다"
        );
    }
}
