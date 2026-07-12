//! aicd OTLP host-metrics exporter (SRE t6).
//!
//! opt-in(config `[aicd.exporter]`, 기본 off)으로, aicd가 주기적으로 host metrics(cpu/load/mem/
//! swap/disk/net)를 sysinfo로 수집 → OTLP protobuf 인코딩(송신 문자열 전부 redaction 통과) →
//! `{endpoint}/v1/metrics`로 HTTP POST한다. 실패하면 다음 주기까지 단순 skip한다(spool/backoff는
//! 후속 t8 범위 — 여기서 만들지 않는다).
//!
//! aicd_main의 기존 병렬 task 패턴(webhook_server)과 동일하게 **같은 shutdown watch 채널을 구독**해
//! SIGTERM/Shutdown 시 graceful하게 끝난다. off면 `load_exporter_config`가 `None`을 반환해 task 자체가
//! spawn되지 않으므로 코드 경로가 완전히 비활성이다(기존 동작 회귀 0).
//!
//! 경계(SRE-SCOPE-BOUNDARY): 이건 aic가 "push"로 확장되는 지점이라 문서상 sre-agent 몫과 겹칠 수
//! 있으나, 여기서는 **상태 없는 주기 전송**(anomaly score·fingerprint DB·기억 없음)만 한다. 통계
//! 감시/기억은 여전히 중앙 rca-server(sre-agent) 몫이다.
//!
//! t7 추가분: [`events`](events)는 `CommandRecordStore`의 tap(broadcast)을 구독해 command 종료를
//! OTLP Logs로, [`connections`](connections)는 주기적으로 `aic snapshot inventory --json`을
//! spawn해 얻은 connections/inventory 스냅샷을 OTLP Logs로 각각 `{endpoint}/v1/logs`에 push한다.
//! 두 task 모두 host metrics task(`serve`)와 동일하게 독립 tokio task로 떠서 같은 shutdown watch를
//! 공유한다(aicd_main.rs). 각각 config `[aicd.exporter]`의 `events_enabled`/`connections_enabled`로
//! 개별 on/off된다.
//!
//! t8 추가분(오프라인 durability): 세 task 모두 push 실패 시 [`spool::Spool`]에 인코딩 결과를
//! 그대로 적재한다(`Arc<Spool>`을 세 Config가 공유 — 상한/드레인 상태를 하나로 일관되게 추적하기
//! 위함). 실패가 연속되면 [`backoff::Backoff`]가 재시도 간격을 1s→...→60s로 늘려 죽은 collector를
//! 매 tick마다 두들기지 않는다. **드레인은 host metrics task(`serve`)만 담당한다** — `enabled=true`
//! 면 `events_enabled`/`connections_enabled` 값과 무관하게 반드시 뜨는 유일한 task라, spool에
//! events/connections가 쌓아 둔 항목도 포함해 항상 드레인 주체가 존재함을 보장할 수 있다. 세 task가
//! 각자 드레인하면 같은 spool 디렉토리를 동시에 스캔/삭제하며 경합할 수 있어 단일 주체로 좁혔다.

mod backoff;
mod connections;
mod encode;
mod events;
mod host_metrics;
mod logs_proto;
mod ntp;
mod spool;

pub use connections::{serve_connections, ConnectionsConfig};
pub use events::{serve_events, EventsConfig};
pub use spool::{Spool, SignalKind};

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// exporter task 실행 설정(런타임 형태). config에서 resolve해 넘긴다.
#[derive(Debug, Clone)]
pub struct ExporterConfig {
    /// OTLP collector base URL. `/v1/metrics`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// 수집·push 주기.
    pub interval: Duration,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 오프라인 spool(SRE t8). events/connections config와 동일 인스턴스를 공유한다 — `serve`가
    /// 유일한 드레인 주체(모듈 doc 참고).
    pub spool: Arc<Spool>,
    /// 드레인 한 tick당 최대 배치 수(속도 제한). config `[aicd.exporter].spool_drain_batch_limit`.
    pub drain_batch_limit: usize,
}

/// HTTP 요청 전체 타임아웃 — hung collector가 exporter task를 무한 대기시키지 않게 한다.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// exporter를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
/// bind가 아니라 아웃바운드라 시작 실패는 client build 정도뿐이며, 그 경우 에러를 반환한다
/// (호출부는 aicd 전체를 abort하지 않고 경고만 — exporter는 opt-in 부가 기능).
pub async fn serve(cfg: ExporterConfig, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = metrics_url(&cfg.endpoint);
    let logs_endpoint = logs_url(&cfg.endpoint);
    tracing::info!(
        url = %url,
        interval_secs = cfg.interval.as_secs(),
        authed = cfg.token.is_some(),
        "OTLP exporter 시작"
    );

    let mut sampler = host_metrics::HostSampler::new();
    let mut ticker = tokio::time::interval(cfg.interval);
    // 밀린 tick이 몰아치지 않게(느린 push 후 따라잡기 폭주 방지). 첫 tick은 즉시 완료된다.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // t8: 이 task가 spool의 유일한 드레인 주체다(모듈 doc 참고) — backoff도 드레인+신규 push를
    // 아우르는 하나의 tick 성패로 판단한다.
    let mut backoff = backoff::Backoff::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                // sysinfo refresh(statvfs 등)는 blocking 가능 → spawn_blocking으로 감싸 task 루프를
                // 막지 않는다(hung NFS/SMB mount에서도 shutdown 반응성 유지). sampler를 넘겼다 돌려받아
                // i/o delta 상태를 보존한다(single-flight).
                let (returned, sample) = match tokio::task::spawn_blocking(move || {
                    let s = sampler.sample();
                    (sampler, s)
                })
                .await
                {
                    Ok(pair) => pair,
                    Err(_) => break, // sampler panic — task 종료.
                };
                sampler = returned;

                let body = encode::encode_metrics(&sample, &cfg.service_version, unix_nanos_now());

                if !backoff.ready() {
                    // backoff 윈도 안 — collector가 여전히 다운됐다고 보고 네트워크 시도(드레인·
                    // 신규 push 둘 다) 자체를 건너뛴다. 새 sample은 유실시키지 않고 spool에만 쌓는다.
                    if let Err(e) = cfg.spool.append(SignalKind::Metrics, &body) {
                        tracing::warn!(error = %e, "OTLP metrics spool append 실패 — 이 샘플 유실");
                    }
                    continue;
                }

                let mut tick_failed = false;

                // (1) 드레인 — 밀린 배치를 FIFO로 먼저 흘려보낸다(새 데이터보다 오래된 데이터 우선).
                let drain_report = cfg
                    .spool
                    .drain(cfg.drain_batch_limit, |kind, batch_body| {
                        let client = &client;
                        let url = &url;
                        let logs_endpoint = &logs_endpoint;
                        let token = cfg.token.as_deref();
                        async move {
                            match kind {
                                SignalKind::Metrics => push(client, url, token, batch_body).await,
                                SignalKind::Logs => push_logs(client, logs_endpoint, token, batch_body).await,
                            }
                        }
                    })
                    .await;
                if drain_report.drained > 0 || drain_report.failed {
                    tracing::debug!(
                        drained = drain_report.drained,
                        failed = drain_report.failed,
                        "OTLP spool 드레인"
                    );
                }
                if drain_report.failed {
                    tick_failed = true;
                }

                // (2) 신규 샘플 송신.
                if let Err(e) = push(&client, &url, cfg.token.as_deref(), body.clone()).await {
                    tracing::warn!(error = %e, "OTLP metrics push 실패 — spool에 적재");
                    if let Err(e2) = cfg.spool.append(SignalKind::Metrics, &body) {
                        tracing::warn!(error = %e2, "OTLP metrics spool append 실패 — 이 샘플 유실");
                    }
                    tick_failed = true;
                }

                if tick_failed {
                    backoff.on_failure();
                } else {
                    backoff.on_success();
                }
            }
            changed = shutdown.changed() => {
                // 채널이 닫혔거나(sender drop) true로 바뀌면 종료.
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("OTLP exporter 종료");
    Ok(())
}

/// OTLP protobuf 본문을 collector로 POST한다. 2xx가 아니면 에러.
async fn push(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> anyhow::Result<()> {
    let mut req = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("collector가 {status} 응답");
    }
    Ok(())
}

/// base endpoint에 `/v1/metrics`를 붙인다(중복 슬래시 방지).
fn metrics_url(endpoint: &str) -> String {
    format!("{}/v1/metrics", endpoint.trim_end_matches('/'))
}

/// base endpoint에 `/v1/logs`를 붙인다(중복 슬래시 방지). t7: events/connections가 공유.
/// private이지만 하위 모듈(events/connections)은 조상 모듈의 private 항목을 볼 수 있어
/// `super::logs_url(...)`로 그대로 쓴다(metrics_url/push와 동일 관례 — pub 불필요).
fn logs_url(endpoint: &str) -> String {
    format!("{}/v1/logs", endpoint.trim_end_matches('/'))
}

/// OTLP Logs protobuf 본문을 collector로 POST한다. events/connections가 공유하는 전송 helper —
/// `push`(metrics 전용)와 동일한 형태지만 Content-Type/URL이 다르므로 별도 함수로 둔다.
async fn push_logs(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> anyhow::Result<()> {
    let mut req = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("collector가 {status} 응답");
    }
    Ok(())
}

/// 현재 시각을 unix epoch 나노초로. 시스템 시계가 epoch 이전이면 0(비정상 환경 방어).
fn unix_nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_url_appends_path_without_double_slash() {
        assert_eq!(metrics_url("http://h:4318"), "http://h:4318/v1/metrics");
        assert_eq!(metrics_url("http://h:4318/"), "http://h:4318/v1/metrics");
    }

    #[test]
    fn logs_url_appends_path_without_double_slash() {
        assert_eq!(logs_url("http://h:4318"), "http://h:4318/v1/logs");
        assert_eq!(logs_url("http://h:4318/"), "http://h:4318/v1/logs");
    }

    #[test]
    fn unix_nanos_is_monotonic_ish() {
        let a = unix_nanos_now();
        let b = unix_nanos_now();
        assert!(b >= a);
        assert!(a > 0, "실제 호스트라면 epoch 이후여야 함");
    }
}
