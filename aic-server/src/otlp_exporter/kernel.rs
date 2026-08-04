//! 로컬 rca-agent(RCA-eBPF)의 커널 카운터 delta를 `aic.kernel.*` metric으로 push한다 (PRD Lane C).
//!
//! **왜 aicd를 거치는가**: rca-agent는 OTLP **gRPC**로만 내보내고 플랫폼(rca-web)은 OTLP
//! **HTTP/protobuf**만 받는다. wire가 맞지 않아 직행 push가 불가능하므로, 커널 신호가 플랫폼에
//! 도달하는 현실적인 경로는 aicd 릴레이뿐이다.
//!
//! **무엇을 보내는가 — 숫자만.** 번들의 `observations.delta`(신호별 카운터 증가분)만 metric으로
//! 변환한다. PID/comm/cgroup entity를 담은 `top`·`findings`·`correlation_hint`는 **호스트 밖으로
//! 내보내지 않는다** — 전송 표면을 최소화하고, 판정 힌트는 로컬 해석층(chat/diagnose)에 남긴다.
//!
//! **수집 방식(fallback 경로)**: 논블로킹 `GET /countersz`가 rca-agent에 아직 없어서, 짧은
//! window의 `POST /collectz`로 delta를 받는다. 서버는 동시 collect를 막지도 거부하지도 않으므로
//! (`internal/control/collector.go`에 가드 없음) 겹치지 않게 하는 건 소비자 책임인데, 이 태스크는
//! 단일 루프에서 순차로 await하고 tick도 `MissedTickBehavior::Skip`이라 **인플라이트가 구조적으로
//! 1**이다. 다만 사용자가 같은 시각에 chat/CLI로 collect를 부르면 window가 겹칠 수 있다 —
//! 서버가 각자 window를 돌려 각자 답하므로 오류는 없고, 문서화된 한계다.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;

use super::backoff::Backoff;
use super::encode;
use super::host_metrics::{HostSample, MetricPoint, MetricValue, ResourceAttrs};
use super::spool::{SignalKind, Spool};

/// `/collectz` 응답 상한 — 신호를 많이 켠 호스트도 수백 KB 수준이다.
const MAX_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
/// window 위에 얹는 요청 timeout 여유.
const REQUEST_MARGIN: Duration = Duration::from_secs(15);

pub struct KernelConfig {
    /// OTLP collector base URL. `/v1/metrics`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// rca-agent control API base URL(loopback 검증을 통과한 값).
    pub agent_url: String,
    /// 수집 tick 간격.
    pub interval: Duration,
    /// 한 tick의 측정 window. `interval`보다 짧아야 한다.
    pub window: Duration,
    /// 오프라인 spool(SRE t8). 다른 exporter task와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 다른 exporter task와 공유한다.
    pub health: Arc<super::ExporterHealth>,
}

/// host가 loopback인지 강제한다 — 커널 evidence를 원격에서 당겨오지 않는다.
///
/// aic-client의 `ensure_loopback`과 같은 불변식이지만, aic-server는 의도적으로 aic-client에
/// 의존하지 않으므로(host metrics 샘플러와 동일 관례) 여기 최소 구현을 둔다.
pub fn ensure_loopback(raw: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(raw.trim_end_matches('/'))
        .map_err(|e| anyhow::anyhow!("rca-agent URL 파싱 실패: {raw} ({e})"))?;
    match url.scheme() {
        "http" | "https" => {}
        other => anyhow::bail!("지원하지 않는 rca-agent URL scheme: {other}"),
    }
    let host = url.host_str().unwrap_or_default();
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let is_loopback = bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !is_loopback {
        anyhow::bail!("rca-agent URL은 loopback만 허용됩니다: {host}");
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// `rca.evidence.v1` 번들 → `aic.kernel.*` metric points. **순수 함수.**
///
/// `observations.delta`는 `{signal: {metric: count}}` 모양이라 이름을
/// `aic.kernel.<signal>.<metric>`으로 평탄화한다. 값이 0인 항목도 보낸다 — "이 window에 아무 일도
/// 없었다"는 사실 자체가 시계열의 정보이고, 빠지면 소비자가 결측과 0을 구분할 수 없다.
///
/// 숫자가 아닌 값이나 예상 밖 구조는 조용히 건너뛴다(파싱 실패 = 빈 목록). metric 이름은 OTLP
/// 인코더가 `&'static str`을 요구하므로 알려진 신호·메트릭 조합만 상수로 매핑한다 — 모르는
/// 조합은 버린다(rca-agent가 신호를 추가하면 여기 한 줄이 늘어난다).
pub fn build_metric_points(bundle_json: &str) -> Vec<MetricPoint> {
    let Ok(v) = serde_json::from_str::<Value>(bundle_json) else {
        return Vec::new();
    };
    let Some(delta) = v
        .get("observations")
        .and_then(|o| o.get("delta"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };

    let mut points = Vec::new();
    for (signal, metrics) in delta {
        let Some(metrics) = metrics.as_object() else {
            continue;
        };
        for (metric, value) in metrics {
            let Some(name) = metric_name(signal, metric) else {
                continue;
            };
            let Some(n) = value.as_i64() else { continue };
            points.push(MetricPoint {
                name,
                unit: "1",
                value: MetricValue::Int(n),
            });
        }
    }
    // 인코딩 결과를 결정적으로 만들어 골든 비교와 디버깅을 쉽게 한다.
    points.sort_by_key(|p| p.name);
    points
}

/// (signal, metric) → metric 이름. 알려진 조합만 통과시킨다(allowlist).
fn metric_name(signal: &str, metric: &str) -> Option<&'static str> {
    Some(match (signal, metric) {
        ("context_switch", "switches") => "aic.kernel.context_switches",
        ("process_lifecycle", "fork") => "aic.kernel.forks",
        ("process_lifecycle", "exit") => "aic.kernel.exits",
        ("oom", "kills") => "aic.kernel.oom_kills",
        ("capability_check", "failures") => "aic.kernel.capability_failures",
        ("block_io", "ios") => "aic.kernel.block_ios",
        ("file_io", "reads") => "aic.kernel.file_reads",
        ("file_io", "writes") => "aic.kernel.file_writes",
        ("syscall", "calls") => "aic.kernel.syscalls",
        ("scheduler", "runqueue_events") => "aic.kernel.runqueue_events",
        _ => return None,
    })
}

/// 커널 카운터 수집 루프. shutdown 신호까지 tick마다 collect → encode → push한다.
pub async fn serve_kernel(
    cfg: KernelConfig,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .build()?;
    serve_kernel_with(cfg, shutdown, &client).await
}

async fn serve_kernel_with(
    cfg: KernelConfig,
    mut shutdown: watch::Receiver<bool>,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let url = super::metrics_url(&cfg.endpoint);
    let collect_url = format!(
        "{}/collectz?profile=incident&duration={}s",
        cfg.agent_url,
        cfg.window.as_secs()
    );
    tracing::info!(
        url = %url,
        agent = %cfg.agent_url,
        interval_secs = cfg.interval.as_secs(),
        window_secs = cfg.window.as_secs(),
        "OTLP kernel exporter 시작"
    );

    // host_metrics와 같은 방식으로 얻어야 같은 host.id로 다른 signal과 상관관계를 지을 수 있다.
    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let os_desc = sysinfo::System::long_os_version().unwrap_or_default();

    let mut ticker = tokio::time::interval(cfg.interval);
    // 수집이 window만큼 블록하므로 밀린 tick을 몰아 치면 collect가 겹친다 — Skip이 곧 상호배제다.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut backoff = Backoff::new();
    // 연결 실패는 rca-agent 미기동이라는 흔한 정상 상태다 — 상태 전이에서만 WARN하고 그 뒤엔 조용히.
    let mut collect_failing = false;

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                let bundle = match collect_once(client, &collect_url, cfg.window).await {
                    Ok(b) => {
                        if collect_failing {
                            tracing::info!("rca-agent 커널 수집 복구");
                            collect_failing = false;
                        }
                        b
                    }
                    Err(e) => {
                        // 수집 실패는 push를 시도조차 안 했으므로 health/backoff를 건드리지 않는다
                        // (docker/connections exporter와 동일 원칙).
                        if !collect_failing {
                            collect_failing = true;
                            tracing::warn!(error = %e, "rca-agent 커널 수집 실패 — 다음 주기까지 skip");
                        } else {
                            tracing::debug!(error = %e, "rca-agent 커널 수집 실패 지속");
                        }
                        continue;
                    }
                };

                let points = build_metric_points(&bundle);
                if points.is_empty() {
                    tracing::debug!("커널 delta 없음(활성 신호 0 또는 미지원 신호) — 이번 tick 생략");
                    continue;
                }
                let sample = HostSample {
                    resource: ResourceAttrs {
                        host_name: host_name.clone(),
                        host_id: host_id.clone(),
                        os_type: os_type.clone(),
                        arch: arch.clone(),
                        os_desc: os_desc.clone(),
                    },
                    points,
                    // 커널 task는 프로세스를 수집하지 않는다 — entity는 보내지 않는다는 원칙 그대로다.
                    top_processes: Vec::new(),
                    process_inventory: Vec::new(),
                };
                let body = encode::encode_metrics(
                    &sample,
                    &cfg.service_version,
                    super::unix_nanos_now(),
                    None,
                );

                if !backoff.ready() {
                    if let Err(e) = cfg.spool.append(SignalKind::Metrics, &body) {
                        tracing::warn!(error = %e, "OTLP kernel spool append 실패 — 이 샘플 유실");
                    }
                    continue;
                }
                match super::push(client, &url, cfg.token.as_deref(), body.clone()).await {
                    Ok(()) => {
                        backoff.on_success();
                        cfg.health.record_ok();
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "OTLP kernel push 실패 — spool에 적재");
                        if let Err(e2) = cfg.spool.append(SignalKind::Metrics, &body) {
                            tracing::warn!(error = %e2, "OTLP kernel spool append 실패 — 이 샘플 유실");
                        }
                        backoff.on_failure();
                        cfg.health.record_fail();
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("OTLP kernel exporter 종료");
    Ok(())
}

/// 한 번의 `/collectz` 수집. window만큼 블록하므로 timeout은 window + 여유다.
async fn collect_once(
    client: &reqwest::Client,
    url: &str,
    window: Duration,
) -> anyhow::Result<String> {
    let resp = client
        .post(url)
        .timeout(window + REQUEST_MARGIN)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("rca-agent 요청 실패: {e}"))?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        anyhow::bail!("rca-agent 번들이 비정상적으로 큼 ({} bytes)", bytes.len());
    }
    if !status.is_success() {
        anyhow::bail!("rca-agent 오류 {status}");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &str = r#"{
      "schema_version": "rca.evidence.v1",
      "observations": {
        "delta": {
          "context_switch": {"switches": 105959},
          "process_lifecycle": {"fork": 17, "exit": 14},
          "oom": {"kills": 0}
        },
        "top": {"oom": {"by_comm": {"python": 3}}},
        "findings": [{"signal":"oom","severity":"warning"}]
      }
    }"#;

    #[test]
    fn build_metric_points_flattens_delta_only() {
        let pts = build_metric_points(BUNDLE);
        let names: Vec<&str> = pts.iter().map(|p| p.name).collect();
        assert_eq!(
            names,
            vec![
                "aic.kernel.context_switches",
                "aic.kernel.exits",
                "aic.kernel.forks",
                "aic.kernel.oom_kills",
            ]
        );
        // entity를 담은 top/findings는 metric으로 새어 나가지 않는다.
        assert!(!names
            .iter()
            .any(|n| n.contains("comm") || n.contains("top")));
    }

    #[test]
    fn build_metric_points_keeps_zero_values() {
        // 0은 결측과 다르다 — "이 window엔 OOM이 없었다"는 사실을 보낸다.
        let pts = build_metric_points(BUNDLE);
        let oom = pts
            .iter()
            .find(|p| p.name == "aic.kernel.oom_kills")
            .expect("oom point");
        match oom.value {
            MetricValue::Int(v) => assert_eq!(v, 0),
            MetricValue::Double(_) => panic!("커널 카운터는 Int여야 한다"),
        }
    }

    #[test]
    fn build_metric_points_drops_unknown_signals() {
        // 모르는 신호/메트릭은 버린다(metric 이름이 &'static str이라 allowlist가 필요).
        let b = r#"{"observations":{"delta":{"future_signal":{"whatever":5}}}}"#;
        assert!(build_metric_points(b).is_empty());
    }

    #[test]
    fn build_metric_points_degrades_on_bad_input() {
        assert!(build_metric_points("not json").is_empty());
        assert!(build_metric_points("{}").is_empty());
        assert!(build_metric_points(r#"{"observations":{"delta":42}}"#).is_empty());
    }

    #[test]
    fn ensure_loopback_accepts_loopback_only() {
        assert!(ensure_loopback("http://127.0.0.1:9090").is_ok());
        assert!(ensure_loopback("http://localhost:9090/").is_ok());
        assert!(ensure_loopback("http://[::1]:9090").is_ok());
        // 원격 rca-agent는 거부 — 커널 evidence는 호스트 경계를 넘지 않는다.
        assert!(ensure_loopback("http://10.0.0.5:9090").is_err());
        assert!(ensure_loopback("https://agent.example.com").is_err());
        assert!(ensure_loopback("file:///etc/passwd").is_err());
    }

    #[test]
    fn ensure_loopback_strips_trailing_slash() {
        assert_eq!(
            ensure_loopback("http://127.0.0.1:9090/").unwrap(),
            "http://127.0.0.1:9090"
        );
    }
}
