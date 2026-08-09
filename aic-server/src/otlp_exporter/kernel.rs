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
//! **수집 방식 — `duration=0` 논블로킹 폴링.** `POST /collectz?duration=0`은 대기 없이
//! 즉시 스냅샷만 돌려준다(rca-agent `observations.go`의 `if duration > 0`이 대기 블록을 감싼다;
//! 실측 13~18ms vs `duration=5s`의 5017ms). aicd는 응답의 **누적 카운터(`observations.end`)를
//! 두 폴에 걸쳐 차분**해 이번 틱의 증가분을 만든다.
//!
//! 짧은 window를 블로킹으로 재던 이전 방식은 **틱 간격의 일부만 관측**했다(60초 중 10초 = 5/6
//! 미관측). 그 사이 fork storm이 나면 통째로 안 보인다. 폴링은 두 폴 사이 전 구간을 담고,
//! 블로킹이 없어 동시 collect 경합도 사라진다.
//!
//! **감수 사항**: `duration=0` 동작은 실측으로 확인했지만 rca-agent의 문서화된 계약은 아직
//! 아니다(그쪽 PRD Q3). 계약이 확정되기 전까지는 이 전제가 바뀔 수 있다.

use std::collections::BTreeMap;
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
/// 폴 요청 timeout. 대기가 없어 실측 13~18ms지만, 부하 상황의 여유를 크게 둔다.
const POLL_TIMEOUT: Duration = Duration::from_secs(15);

pub struct KernelConfig {
    /// OTLP collector base URL. `/v1/metrics`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// rca-agent control API base URL(loopback 검증을 통과한 값).
    pub agent_url: String,
    /// 폴 간격. 두 폴 사이의 카운터 증가분이 곧 보고 단위다.
    pub interval: Duration,
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
pub fn read_counters(bundle_json: &str) -> BTreeMap<&'static str, i64> {
    let mut out = BTreeMap::new();
    let Ok(v) = serde_json::from_str::<Value>(bundle_json) else {
        return out;
    };
    let Some(end) = v
        .get("observations")
        .and_then(|o| o.get("end"))
        .and_then(Value::as_object)
    else {
        return out;
    };
    for (signal, metrics) in end {
        let Some(metrics) = metrics.as_object() else {
            continue;
        };
        for (metric, value) in metrics {
            let Some(name) = metric_name(signal, metric) else {
                continue;
            };
            let Some(n) = value.as_i64() else { continue };
            out.insert(name, n);
        }
    }
    out
}

/// 두 폴의 누적 카운터 차분 → metric points. **순수 함수.**
///
/// `prev`가 없으면(첫 폴) 빈 목록이다 — 기준선이 없으면 "이번 틱에 얼마나 늘었나"를 말할 수
/// 없고, 누적값을 그대로 보내면 시계열이 첫 점에서 거대한 계단을 만든다.
///
/// **카운터가 후퇴하면 그 항목을 버린다.** rca-agent가 재시작하면 커널 맵이 0부터 다시 세므로
/// `cur - prev`가 음수가 되는데, 그걸 보내면 존재하지 않은 감소가 시계열에 남는다. 그 한 구간만
/// 폐기하고 다음 틱부터 새 기준선으로 정상 재개한다.
///
/// 값이 0인 항목도 보낸다 — "이 구간에 아무 일도 없었다"와 "수집이 멈췄다"는 다른 사실이다.
pub fn diff_counters(
    prev: Option<&BTreeMap<&'static str, i64>>,
    cur: &BTreeMap<&'static str, i64>,
) -> Vec<MetricPoint> {
    let Some(prev) = prev else { return Vec::new() };
    let mut points = Vec::new();
    for (name, cur_v) in cur {
        let Some(prev_v) = prev.get(name) else {
            continue;
        };
        let d = cur_v - prev_v;
        if d < 0 {
            continue; // 카운터 후퇴(에이전트 재시작) — 이 구간 폐기.
        }
        points.push(MetricPoint {
            name,
            unit: "1",
            value: MetricValue::Int(d),
        });
    }
    // BTreeMap 순회라 이미 이름순이지만, 인코딩 결정성을 명시적으로 고정한다.
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

/// OOM kill 이산 이벤트 하나 — ring buffer의 개별 사건.
///
/// 카운터(metric)와 달리 "누가 죽었나"가 핵심이라 comm을 싣는다. **이것이 이 경로에서 유일하게
/// 나가는 entity**이고, 인코더의 redaction 게이트를 값 단위로 통과한 뒤 송신된다
/// (`logs_proto::string_value` → `redact_str`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OomEvent {
    /// ring buffer가 매긴 단조 증가 sequence. 중복 발행 방지의 기준이다.
    pub seq: u64,
    /// victim 프로세스명. 비어 있으면 `unknown`.
    pub comm: String,
}

/// 번들 → **아직 보내지 않은** OOM 이산 이벤트와 이번에 본 최대 seq.
///
/// **왜 seq가 필요한가**: `duration=0` 폴에서 `top.oom.events`는 window가 아니라 **ring buffer
/// 전체**를 돌려준다(실측: 821초 전 이벤트도 그대로 들어 있다). 매 폴마다 같은 사건이 다시
/// 오므로, seq로 걸러내지 않으면 한 번의 OOM이 틱마다 재발행된다.
///
/// 그래서 `after_seq`보다 큰 것만 새 사건으로 본다. 반환하는 최대 seq는 **필터 전 전체 기준**이라,
/// 호출부가 그대로 저장하면 다음 폴에서 같은 사건을 다시 보지 않는다.
///
/// 두 번째 반환값은 ring에서 **실제로 관측한** 최대 seq다(사건이 없으면 0). `after_seq`로
/// 클램프하지 않는다 — 클램프하면 rca-agent 재시작으로 seq가 1부터 다시 매겨진 상황(후퇴)을
/// 호출부가 구분할 수 없어, 새 OOM이 전부 옛 커서에 걸려 영구 누락된다.
///
/// ring 용량(실측 16)을 넘겨 유실된 사건은 번들의 `dropped_events`가 알려 주지만, 그건 카운터
/// (`aic.kernel.oom_kills`)가 이미 총량으로 담고 있어 여기서 따로 복원하지 않는다.
pub fn build_oom_events(bundle_json: &str, after_seq: u64) -> (Vec<OomEvent>, u64) {
    let Ok(v) = serde_json::from_str::<Value>(bundle_json) else {
        return (Vec::new(), 0);
    };
    let Some(items) = v
        .get("observations")
        .and_then(|o| o.get("top"))
        .and_then(|t| t.get("oom"))
        .and_then(|o| o.get("events"))
        .and_then(Value::as_array)
    else {
        return (Vec::new(), 0);
    };

    let mut max_seq = 0u64;
    let mut events = Vec::new();
    for e in items {
        let Some(seq) = e.get("seq").and_then(Value::as_u64) else {
            continue;
        };
        max_seq = max_seq.max(seq);
        if seq <= after_seq {
            continue;
        }
        let comm = e
            .get("comm")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .unwrap_or("unknown");
        events.push(OomEvent {
            seq,
            comm: comm.to_string(),
        });
    }
    events.sort_by_key(|e| e.seq);
    (events, max_seq)
}

/// ring seq가 되돌아갔는지 — rca-agent 재시작으로 ring이 리셋된 신호.
///
/// 관측값 0은 "이번 폴에 사건이 없었다"이지 후퇴가 아니다. 여기서 0을 후퇴로 읽으면
/// 사건 없는 평범한 폴마다 커서가 0으로 밀려 이미 보낸 사건을 전부 재발행한다.
pub fn oom_ring_restarted(last_seq: u64, observed_max: u64) -> bool {
    observed_max > 0 && observed_max < last_seq
}

/// 폴 한 번의 OOM seq 커서 전이. **순수 함수** — 상태 전이만 따로 검증할 수 있게 분리했다.
///
/// - `delivered == false`: 배치가 push도 spool도 못 됐다 = 어디에도 남지 않았다. 커서를
///   붙잡아 다음 폴에서 다시 시도한다(중복은 `record_id`가 흡수한다).
/// - ring 리셋: 관측값을 그대로 새 기준선으로 삼는다. `max`로 올리면 옛 커서가 남아 재시작
///   이후의 사건이 영구히 걸러진다.
/// - 그 외: 단조 증가.
pub fn next_oom_cursor(last_seq: u64, observed_max: u64, delivered: bool) -> u64 {
    if !delivered {
        return last_seq;
    }
    if oom_ring_restarted(last_seq, observed_max) {
        return observed_max;
    }
    last_seq.max(observed_max)
}

/// 재전송 중복을 수신측 ReplacingMergeTree가 흡수하도록 하는 idempotency 키.
///
/// changes exporter의 방식(host + subject + action + bucket)에 **ring seq를 더한다** — 같은
/// victim이 같은 분에 여러 번 죽으면 별개 사건인데, seq가 없으면 하나로 접혀 유실된다.
fn oom_record_id(host: &str, comm: &str, seq: u64, bucket: u64) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    host.hash(&mut h);
    comm.hash(&mut h);
    "oom_kill".hash(&mut h);
    seq.hash(&mut h);
    bucket.hash(&mut h);
    format!("{:016x}", h.finish())
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
    let logs_url = super::logs_url(&cfg.endpoint);
    // duration=0 — 대기 없이 스냅샷만 받는다(모듈 doc 참고).
    let collect_url = format!("{}/collectz?profile=incident&duration=0", cfg.agent_url);
    tracing::info!(
        url = %url,
        agent = %cfg.agent_url,
        interval_secs = cfg.interval.as_secs(),
        mode = "duration=0 polling",
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
    // 직전 폴의 누적 카운터. 첫 폴은 기준선만 잡고 아무것도 보내지 않는다.
    let mut prev_counters: Option<BTreeMap<&'static str, i64>> = None;
    // 이미 내보낸 OOM 이벤트의 최대 seq. ring은 매 폴마다 통째로 오므로(오래된 이벤트 포함)
    // 이 값보다 큰 것만 새 사건이다. 첫 폴에서는 기준선만 잡는다(아래 oom_baseline).
    let mut last_oom_seq: u64 = 0;
    // 첫 tick을 지났는지. OOM 기준선 판정에 쓴다(카운터는 prev_counters로 같은 판정을 한다).
    let mut first_seen = false;

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                let bundle = match collect_once(client, &collect_url).await {
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

                // 이산 이벤트(OOM)는 카운터와 독립적으로 내보낸다 — 한쪽이 비어도 다른 쪽은 보낸다.
                //
                // **첫 폴은 seq 기준선만 잡고 보내지 않는다.** ring은 window가 아니라 버퍼 전체를
                // 돌려주므로(실측: 821초 전 사건도 들어 있다), 기준선 없이 보내면 aicd가 재시작될
                // 때마다 옛 사건이 되살아난다. record_id의 시각 버킷이 재시작 시각으로 달라져
                // 수신측 중복 제거도 통과해 버린다. 그 대가로 재시작 구간의 사건은 놓치지만,
                // 없는 사건을 만들어 내는 것보다 낫다(카운터의 첫 폴 규칙과 같은 판단).
                let (mut oom_events, max_seq) = build_oom_events(&bundle, last_oom_seq);
                let oom_baseline = !first_seen;
                if oom_baseline && max_seq > 0 {
                    tracing::debug!(max_seq, "첫 폴 — OOM ring seq 기준선만 잡는다");
                }
                // rca-agent가 재시작하면 ring seq가 1부터 다시 매겨진다. 커서를 `max`로만
                // 전진시키면 재시작 뒤의 사건이 전부 `seq <= last_oom_seq`에 걸려 **aicd가 사는
                // 동안 영구 누락**된다(카운터 쪽은 `diff_counters`가 후퇴를 이미 처리한다).
                // 관측 최대 seq가 커서보다 작으면 ring이 리셋된 것이다. 이때 ring에 남은 사건은
                // 재시작 **이후**의 새 사건이므로(옛 ring은 에이전트와 함께 사라졌다) 커서를
                // 무시하고 전부 새로 잡는다 — aicd 첫 폴의 기준선 규칙과 달리 여기서는 옛 사건이
                // 되살아날 여지가 없다.
                let ring_restarted = oom_ring_restarted(last_oom_seq, max_seq);
                if ring_restarted {
                    tracing::info!(
                        max_seq,
                        last_oom_seq,
                        "OOM ring seq 후퇴 — rca-agent 재시작으로 보고 커서를 재설정한다"
                    );
                    let (fresh, _) = build_oom_events(&bundle, 0);
                    oom_events = fresh;
                }

                let mut delivered = true;
                if !oom_baseline && !oom_events.is_empty() {
                    delivered = push_oom_events(
                        client,
                        &cfg,
                        &logs_url,
                        &oom_events,
                        &host_name,
                        &host_id,
                        &os_type,
                        &mut backoff,
                    )
                    .await;
                }
                // 전송 실패라도 **spool에 적재됐으면** seq를 전진시킨다 — 되돌리면 다음 폴에서
                // 같은 사건을 중복 발행한다. 반대로 spool 적재까지 실패했으면 그 배치는 어디에도
                // 남지 않았으므로 커서를 붙잡아 다음 폴에서 다시 시도한다(중복은 record_id가
                // 흡수한다).
                if !delivered {
                    tracing::warn!(
                        max_seq,
                        last_oom_seq,
                        "OOM 배치가 전송·spool 모두 실패 — seq 커서를 전진시키지 않는다"
                    );
                }
                last_oom_seq = next_oom_cursor(last_oom_seq, max_seq, delivered);

                let cur = read_counters(&bundle);
                let points = diff_counters(prev_counters.as_ref(), &cur);
                let first_poll = prev_counters.is_none();
                prev_counters = Some(cur);
                first_seen = true;
                if points.is_empty() {
                    if first_poll {
                        tracing::debug!("첫 폴 — 누적 카운터 기준선만 잡고 전송은 다음 tick부터");
                    } else {
                        tracing::debug!("커널 증가분 없음(활성 신호 0 또는 카운터 후퇴) — 이번 tick 생략");
                    }
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

/// OOM 이산 이벤트를 `aic.changes` scope LogRecord로 내보낸다.
///
/// scope를 새로 만들지 않고 재사용하는 이유: 수신측에 이미 라우팅과 `event_pattern` 룰이 있어
/// **배포 순서 함정(미등록 scope는 200 OK 무음 폐기)을 피하면서 즉시 소비**된다.
/// `change_type=kernel`이 커널 출처임을 구분한다.
///
/// 반환값은 이 배치가 **어딘가에 남았는지**다 — push 성공이거나 spool 적재 성공이면 `true`,
/// 둘 다 실패해 배치가 사라졌으면 `false`. 호출부는 `false`일 때 seq 커서를 붙잡아 다음 폴에서
/// 다시 시도한다(중복은 `record_id`가 흡수한다).
#[allow(clippy::too_many_arguments)]
async fn push_oom_events(
    client: &reqwest::Client,
    cfg: &KernelConfig,
    logs_url: &str,
    events: &[OomEvent],
    host_name: &str,
    host_id: &str,
    os_type: &str,
    backoff: &mut Backoff,
) -> bool {
    use super::logs_proto::{self, ChangeEntry};

    let now_ns = super::unix_nanos_now();
    // 재전송 멱등 키의 시각 버킷 — changes exporter와 같은 분 단위 해상도.
    let bucket = now_ns / 60_000_000_000;
    let ids: Vec<String> = events
        .iter()
        .map(|e| oom_record_id(host_name, &e.comm, e.seq, bucket))
        .collect();
    let states: Vec<String> = events.iter().map(|e| e.seq.to_string()).collect();
    let summaries: Vec<String> = events
        .iter()
        .map(|e| format!("OOM kill: {} (seq {})", e.comm, e.seq))
        .collect();

    let entries: Vec<ChangeEntry<'_>> = events
        .iter()
        .enumerate()
        .map(|(i, e)| ChangeEntry {
            change_type: "kernel",
            subject: &e.comm,
            action: "oom_kill",
            prev_state: None,
            new_state: Some(&states[i]),
            // 커널이 직접 관측한 사건이지만 victim 귀속은 증명이 아니다(ring 집계 기반).
            confidence: "observed",
            source: "collector:rca-agent",
            record_id: &ids[i],
            summary: &summaries[i],
        })
        .collect();

    let resource = logs_proto::ResourceAttrs {
        host_name,
        host_id,
        os_type,
        host_ip: None,
    };
    let body = logs_proto::encode_changes(&entries, &resource, &cfg.service_version, now_ns);

    if !backoff.ready() {
        return match cfg.spool.append(SignalKind::Logs, &body) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "OTLP kernel OOM spool append 실패 — 이 배치 유실");
                false
            }
        };
    }
    match super::push_logs(client, logs_url, cfg.token.as_deref(), body.clone()).await {
        Ok(_) => {
            backoff.on_success();
            cfg.health.record_ok();
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "OTLP kernel OOM push 실패 — spool에 적재");
            let spooled = match cfg.spool.append(SignalKind::Logs, &body) {
                Ok(()) => true,
                Err(e2) => {
                    tracing::warn!(error = %e2, "OTLP kernel OOM spool append 실패 — 이 배치 유실");
                    false
                }
            };
            backoff.on_failure();
            cfg.health.record_fail();
            spooled
        }
    }
}

/// 한 번의 `/collectz?duration=0` 폴. 대기가 없으므로 timeout은 짧게 잡는다.
async fn collect_once(client: &reqwest::Client, url: &str) -> anyhow::Result<String> {
    let resp = client
        .post(url)
        .timeout(POLL_TIMEOUT)
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

    /// `duration=0` 폴의 실제 응답 모양 — 서버가 계산한 `delta`는 10ms 창이라 무의미하고,
    /// 우리가 쓰는 건 누적 `end`와 ring 전체를 담은 `top.oom.events`다.
    const POLL: &str = r#"{
      "schema_version": "rca.evidence.v1",
      "observations": {
        "delta": {"context_switch": {"switches": 3}, "process_lifecycle": {"fork": 0}},
        "end": {
          "context_switch": {"switches": 272950998},
          "process_lifecycle": {"fork": 384327, "exit": 384000},
          "oom": {"kills": 3}
        },
        "top": {"oom": {"available": true, "basis": "event_ring_window", "ring_capacity": 16,
          "events": [
            {"seq": 1, "comm": "python3", "pid": 2338843, "age_seconds": 821.5},
            {"seq": 2, "comm": "node", "pid": 2338999, "age_seconds": 12.0}
          ]}}
      }
    }"#;

    fn counters(pairs: &[(&'static str, i64)]) -> BTreeMap<&'static str, i64> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn read_counters_takes_cumulative_end_not_delta() {
        let c = read_counters(POLL);
        // delta(3)가 아니라 end(272950998)를 읽어야 한다 — duration=0의 delta는 10ms 창이다.
        assert_eq!(c.get("aic.kernel.context_switches"), Some(&272_950_998));
        assert_eq!(c.get("aic.kernel.forks"), Some(&384_327));
        assert_eq!(c.get("aic.kernel.oom_kills"), Some(&3));
        // 모르는 신호는 버린다(metric 이름이 &'static str이라 allowlist가 필요).
        assert!(read_counters(r#"{"observations":{"end":{"future":{"x":1}}}}"#).is_empty());
        assert!(read_counters("not json").is_empty());
    }

    #[test]
    fn diff_counters_reports_increase_between_polls() {
        let prev = counters(&[("aic.kernel.forks", 100), ("aic.kernel.oom_kills", 2)]);
        let cur = counters(&[("aic.kernel.forks", 161), ("aic.kernel.oom_kills", 2)]);
        let pts = diff_counters(Some(&prev), &cur);
        let get = |n: &str| {
            pts.iter().find(|p| p.name == n).map(|p| match p.value {
                MetricValue::Int(v) => v,
                MetricValue::Double(_) => panic!("커널 카운터는 Int여야 한다"),
            })
        };
        assert_eq!(get("aic.kernel.forks"), Some(61));
        // 변화가 없어도 0을 보낸다 — "아무 일 없었다"와 "수집이 멈췄다"는 다른 사실이다.
        assert_eq!(get("aic.kernel.oom_kills"), Some(0));
    }

    #[test]
    fn diff_counters_first_poll_emits_nothing() {
        // 기준선이 없으면 증가분을 말할 수 없다. 누적값을 그대로 보내면 첫 점이 거대한 계단이 된다.
        let cur = counters(&[("aic.kernel.forks", 384_327)]);
        assert!(diff_counters(None, &cur).is_empty());
    }

    #[test]
    fn diff_counters_drops_backwards_counter() {
        // rca-agent가 재시작하면 커널 맵이 0부터 다시 센다 — 음수 증가분을 보내면 안 된다.
        let prev = counters(&[("aic.kernel.forks", 500), ("aic.kernel.exits", 10)]);
        let cur = counters(&[("aic.kernel.forks", 7), ("aic.kernel.exits", 12)]);
        let pts = diff_counters(Some(&prev), &cur);
        let names: Vec<&str> = pts.iter().map(|p| p.name).collect();
        assert_eq!(
            names,
            vec!["aic.kernel.exits"],
            "후퇴한 forks는 이 구간 폐기"
        );
    }

    #[test]
    fn build_oom_events_returns_only_unseen_seqs() {
        // 첫 폴: ring 전체가 새 사건이다.
        let (ev, max) = build_oom_events(POLL, 0);
        assert_eq!(max, 2);
        assert_eq!(
            ev,
            vec![
                OomEvent {
                    seq: 1,
                    comm: "python3".into()
                },
                OomEvent {
                    seq: 2,
                    comm: "node".into()
                },
            ]
        );
        // 같은 ring을 다시 폴해도 재발행하지 않는다(중복 방지의 핵심).
        let (ev2, max2) = build_oom_events(POLL, 2);
        assert!(ev2.is_empty());
        assert_eq!(max2, 2);
        // 이 테스트가 지키는 것: 커서보다 **작은** 관측 최대값이 그대로 보인다.
        // 클램프하면 rca-agent 재시작(seq 리셋)을 폴 루프가 구분하지 못해, 재시작 뒤의 OOM이
        // 전부 옛 커서에 걸려 영구 누락된다.
        let (ev4, max4) = build_oom_events(POLL, 100);
        assert!(ev4.is_empty(), "커서보다 작은 seq는 아직 새 사건이 아니다");
        assert_eq!(max4, 2, "후퇴 감지를 위해 관측값을 그대로 돌려줘야 한다");
        // 일부만 본 상태면 그 뒤만 새 사건이다.
        let (ev3, _) = build_oom_events(POLL, 1);
        assert_eq!(ev3.len(), 1);
        assert_eq!(ev3[0].seq, 2);
    }

    /// 이 테스트가 지키는 것: 폴 루프의 커서 상태 전이 전체. 순수 함수로 뽑아 두지 않으면
    /// 이 로직은 네트워크가 있는 async 루프 안에만 있어 아무도 검증하지 못한다.
    #[test]
    fn next_oom_cursor_covers_every_transition() {
        // 정상 전진.
        assert_eq!(next_oom_cursor(5, 9, true), 9);
        // 사건 없음(관측 0) — 커서 유지. 여기서 0으로 밀리면 보낸 사건이 전부 재발행된다.
        assert_eq!(next_oom_cursor(5, 0, true), 5);
        // 같은 ring 재관측 — 제자리.
        assert_eq!(next_oom_cursor(5, 5, true), 5);
        // ring 리셋(rca-agent 재시작): 관측값이 새 기준선. `max`였다면 5로 남아 재시작 이후의
        // 사건(seq 1..2)이 영구 누락된다.
        assert_eq!(next_oom_cursor(5, 2, true), 2);
        // 전송·spool 모두 실패 — 어디에도 안 남았으니 커서를 붙잡는다.
        assert_eq!(next_oom_cursor(5, 9, false), 5);
        // 실패 + ring 리셋: 커서를 유지해 다음 폴에서 리셋을 다시 감지하고 재시도한다.
        assert_eq!(next_oom_cursor(5, 2, false), 5);
        // 첫 폴(기준선) — 0에서 시작해 관측값을 그대로 잡는다.
        assert_eq!(next_oom_cursor(0, 7, true), 7);
    }

    #[test]
    fn oom_ring_restarted_ignores_empty_ring() {
        assert!(oom_ring_restarted(10, 3), "관측값이 커서보다 작으면 리셋");
        assert!(!oom_ring_restarted(10, 0), "사건 없음은 리셋이 아니다");
        assert!(!oom_ring_restarted(10, 10));
        assert!(!oom_ring_restarted(0, 5), "첫 폴은 리셋이 아니다");
    }

    #[test]
    fn build_oom_events_degrades_on_bad_input() {
        // 파싱 실패·구조 불일치는 빈 목록 + "관측 없음"(0). 호출부는 0을 커서 유지로 읽는다
        // — 여기서 `after_seq`를 되돌려주면 관측 없음과 후퇴를 구분할 수 없다.
        for bad in [
            "not json",
            "{}",
            r#"{"observations":{"top":{"oom":{"events":"nope"}}}}"#,
        ] {
            let (ev, max) = build_oom_events(bad, 7);
            assert!(ev.is_empty());
            assert_eq!(max, 0, "관측이 없으면 0 — after_seq로 클램프하지 않는다");
        }
        // seq 없는 항목은 건너뛴다.
        let (ev, _) = build_oom_events(
            r#"{"observations":{"top":{"oom":{"events":[{"comm":"x"}]}}}}"#,
            0,
        );
        assert!(ev.is_empty());
        // comm이 비면 unknown — 사건 자체는 버리지 않는다.
        let (ev, _) = build_oom_events(
            r#"{"observations":{"top":{"oom":{"events":[{"seq":9,"comm":"  "}]}}}}"#,
            0,
        );
        assert_eq!(
            ev,
            vec![OomEvent {
                seq: 9,
                comm: "unknown".into()
            }]
        );
    }

    #[test]
    fn oom_record_id_separates_events_by_seq() {
        // 같은 victim이 같은 분에 두 번 죽으면 별개 사건이다 — seq가 없으면 하나로 접힌다.
        let a = oom_record_id("h1", "python3", 1, 100);
        assert_eq!(a, oom_record_id("h1", "python3", 1, 100));
        assert_ne!(a, oom_record_id("h1", "python3", 2, 100));
        assert_ne!(a, oom_record_id("h2", "python3", 1, 100));
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
