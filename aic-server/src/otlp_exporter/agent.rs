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

use super::backoff::Backoff;
use super::logs_proto::{self, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// agent exporter 실행 설정.
pub struct AgentConfig {
    /// OTLP collector base URL. `/v1/logs`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// **이미 구독을 마친** agent 행위 tap receiver.
    ///
    /// 왜 `AgentEventBus`가 아니라 `Receiver`인가: 예전엔 bus를 넘겨 task **안에서**
    /// `subscribe()`했다. 그러면 spawn과 첫 구독 사이에 유실 창이 생긴다 — broadcast는 replay가
    /// 없어서, 그 창에 publish된 이벤트는 구독자가 없는 것으로 취급돼 조용히 사라진다. aicd 기동
    /// 직후는 chat이 붙는 시점과 정확히 겹치므로 실제로 밟히는 경로다.
    ///
    /// 그래서 **부모(aicd_main)가 spawn 전에 구독**하고 그 receiver를 여기로 넘긴다. 구독이 끝난
    /// 뒤에야 task가 뜨고 `set_agent_live(true)`가 켜지므로, 창 자체가 존재하지 않는다(구독 시점
    /// 이후 publish된 이벤트는 task가 읽기 전이라도 채널 버퍼에 남아 있다가 전달된다).
    pub rx: broadcast::Receiver<aic_common::AgentEvent>,
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
    // 구독은 **부모가 spawn 전에** 이미 끝냈다(AgentConfig::rx 참고) — 여기서 subscribe하면
    // spawn~구독 사이에 유실 창이 생긴다.
    let mut rx = cfg.rx;

    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();
    let mut backoff = Backoff::new();
    // ts 폴백 경고를 처음 한 번만 WARN으로 올린다(이후는 DEBUG) — 시계가 어긋난 호스트에선 모든
    // 이벤트가 폴백을 타므로, 그대로 두면 로그가 폭주한다. 정상 경로에선 아예 찍히지 않는다.
    let mut ts_fallback_warned = false;

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
                        // observed = aicd가 이 행위를 관측(수신·인코딩)한 시각, event = 행위가
                        // 실제로 일어난 시각. 둘을 분리해야 spool에 쌓였다 드레인된 이벤트를
                        // 수신 측이 구분할 수 있다.
                        let observed_ns = super::unix_nanos_now();
                        let (event_ns, fallback) = agent_event_time_unix_nano(ev.ts, observed_ns);
                        if let Some(reason) = fallback {
                            if ts_fallback_warned {
                                tracing::debug!(reason, ts = %ev.ts, kind = %ev.kind, "AgentEvent.ts 폴백(중복 경고 억제)");
                            } else {
                                ts_fallback_warned = true;
                                tracing::warn!(
                                    reason,
                                    ts = %ev.ts,
                                    observed_ns,
                                    kind = %ev.kind,
                                    "AgentEvent.ts가 비정상 — 관측 시각으로 대체한다(이후 동일 경고는 debug로만)"
                                );
                            }
                        }
                        let body = logs_proto::encode_agent_event(
                            &ev,
                            &resource,
                            &cfg.service_version,
                            event_ns,
                            observed_ns,
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

/// LogRecord `time_unix_nano`(= 이벤트 발생 시각)로 쓸 값을 고른다. **"사람이 순간을 남긴다"**는
/// 의미상 관측/push 시각(`now`)이 아니라 행위가 실제로 일어난 시각(`ts` = `AgentEvent.ts`)을
/// 쓴다 — aicd가 밀리거나 tap이 지연돼도 기록에는 원래 순간이 남아야 한다.
/// (`observed_time_unix_nano`는 이 함수와 무관하게 항상 `now`다 — 호출부 참고.)
///
/// `ts`가 epoch 0 이하이거나(비정상 초기값), chrono 표현 범위를 벗어나거나(연도 대략
/// 1677~2262 밖 — `timestamp_nanos_opt()`가 `None`), `now`보다 미래(시계 skew 방어)면 `now`로
/// 폴백한다: 미래 시각이나 epoch 0을 그대로 collector에 보내지 않기 위한 불변식이다.
///
/// 폴백이 일어나면 그 사유를 `Some(reason)`으로 함께 돌려준다 — 조용히 삼키면 시계 skew나 버그를
/// 영영 모른다. 로깅은 호출부가 한다(폭주 억제를 위해 첫 1회만 WARN).
fn agent_event_time_unix_nano(
    ts: chrono::DateTime<chrono::Utc>,
    now: u64,
) -> (u64, Option<&'static str>) {
    match ts.timestamp_nanos_opt() {
        None => (now, Some("out_of_range")),
        Some(nanos) if nanos <= 0 => (now, Some("non_positive")),
        Some(nanos) => {
            let nanos = nanos as u64;
            if nanos <= now {
                (nanos, None)
            } else {
                (now, Some("future"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_event_bus::AgentEventBus;
    use prost::Message as _;
    use std::collections::BTreeMap;

    #[test]
    fn subscribing_before_spawn_leaves_no_loss_window() {
        // C: 구독이 task **안**에서 일어나면 spawn~구독 사이가 "구독자 0"인 창이 되고, 그 창에
        // publish된 이벤트는 broadcast에 replay가 없어 조용히 사라진다. aicd 기동 직후는 chat이
        // 붙는 시점과 겹쳐 실제로 밟히는 경로다.
        //
        // 계약: `load_agent_config`가 하듯 **부모가 먼저 subscribe**하면, task가 아직 recv()를
        // 한 번도 돌리지 않은 상태에서 publish된 이벤트도 채널 버퍼에 보존돼 나중에 수신된다.
        // 이 테스트는 receiver를 만들어 두고 **아무도 읽지 않는 동안** publish한 뒤, 그때서야
        // 읽어서 이벤트가 살아있는지 본다(= task가 늦게 시작해도 유실 없음).
        let bus = AgentEventBus::new();

        // 부모가 spawn 전에 구독(= AgentConfig.rx). 이 시점에 구독자 수는 1이어야 한다.
        let mut rx = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1, "구독이 성립하지 않았다");

        // task가 아직 안 떴다고 가정하고(=recv 호출 전) 이벤트를 publish한다.
        bus.publish(event_with_ts(chrono::Utc::now()));

        // 이제서야 task가 읽기 시작한다 — 유실 없이 받아야 한다.
        let got = rx.try_recv().expect("구독 후 publish된 이벤트가 유실됐다");
        assert_eq!(got.kind, "tool.run_command");
    }

    #[test]
    fn publishing_before_any_subscriber_is_lost() {
        // 위 테스트의 대우(對偶) — 구독 **전에** publish하면 정말로 사라진다는 걸 고정한다.
        // 이게 사실이 아니라면 위 테스트는 아무것도 증명하지 않는다(구독 순서가 무의미해진다).
        let bus = AgentEventBus::new();
        bus.publish(event_with_ts(chrono::Utc::now())); // 구독자 0 — 버려진다
        let mut rx = bus.subscribe();
        assert!(
            rx.try_recv().is_err(),
            "구독 전 이벤트가 replay됐다 — 그렇다면 구독 순서는 애초에 문제가 아니다"
        );
    }

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
        let (got, fallback) = agent_event_time_unix_nano(ts, NOW_NANOS);
        assert_eq!(got, PAST_TS_NANOS as u64);
        assert_ne!(
            got, NOW_NANOS,
            "now()로 대체되면 안 된다 — ts가 그대로 나와야 한다"
        );
        assert!(fallback.is_none(), "정상 경로에선 폴백 사유가 없어야 한다");
    }

    #[test]
    fn epoch_zero_ts_falls_back_to_now() {
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(0);
        let (got, fallback) = agent_event_time_unix_nano(ts, NOW_NANOS);
        assert_eq!(got, NOW_NANOS);
        assert_eq!(fallback, Some("non_positive"));
    }

    #[test]
    fn future_ts_falls_back_to_now() {
        // ts가 now보다 미래면(시계 skew) 그대로 보내지 않고 now로 폴백한다.
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(NOW_NANOS as i64 + 1);
        let (got, fallback) = agent_event_time_unix_nano(ts, NOW_NANOS);
        assert_eq!(got, NOW_NANOS);
        assert_eq!(fallback, Some("future"));
    }

    /// LogRecord의 두 시각이 **서로 다른 출처**에서 오는지 encode 결과(protobuf)까지 디코드해
    /// end-to-end로 확인한다: `time_unix_nano` = 행위 발생 시각(`AgentEvent.ts`),
    /// `observed_time_unix_nano` = aicd가 관측한 시각(now). 둘이 같아지면(뭉개지면) FAILED다.
    #[test]
    fn encoded_log_record_separates_event_time_from_observed_time() {
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(PAST_TS_NANOS);
        let ev = event_with_ts(ts);
        let resource = ResourceAttrs {
            host_name: "web-1",
            host_id: "id-abc",
            os_type: "linux",
            host_ip: None,
        };
        let (event_ns, _) = agent_event_time_unix_nano(ev.ts, NOW_NANOS);
        let body = logs_proto::encode_agent_event(&ev, &resource, "0.24.0", event_ns, NOW_NANOS);

        let req =
            logs_proto::ExportLogsServiceRequest::decode(body.as_slice()).expect("valid protobuf");
        let lr = &req.resource_logs[0].scope_logs[0].log_records[0];

        // 발생 시각은 ts에서 온다.
        assert_eq!(lr.time_unix_nano, PAST_TS_NANOS as u64);
        // 관측 시각은 now에서 온다.
        assert_eq!(lr.observed_time_unix_nano, NOW_NANOS);
        // 그리고 둘은 분리되어 있다 — 같은 값이면 "언제 관측했나"가 사라진다(spool 드레인 구분 불가).
        assert_ne!(
            lr.time_unix_nano, lr.observed_time_unix_nano,
            "event time과 observed time을 같은 값으로 뭉개면 안 된다"
        );
    }

    /// 폴백 경로에서는 두 시각이 **같아지는 게 맞다** — ts를 못 믿어 관측 시각으로 대체했으므로
    /// 발생 시각도 관측 시각이다. 위 테스트의 `assert_ne!`가 폴백까지 금지하는 게 아님을 못박는다.
    #[test]
    fn fallback_makes_both_times_the_observed_time() {
        let ev = event_with_ts(chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(0));
        let resource = ResourceAttrs {
            host_name: "web-1",
            host_id: "id-abc",
            os_type: "linux",
            host_ip: None,
        };
        let (event_ns, fallback) = agent_event_time_unix_nano(ev.ts, NOW_NANOS);
        assert!(fallback.is_some());
        let body = logs_proto::encode_agent_event(&ev, &resource, "0.24.0", event_ns, NOW_NANOS);

        let req =
            logs_proto::ExportLogsServiceRequest::decode(body.as_slice()).expect("valid protobuf");
        let lr = &req.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(lr.time_unix_nano, NOW_NANOS);
        assert_eq!(lr.observed_time_unix_nano, NOW_NANOS);
    }
}
