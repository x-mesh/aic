//! aicd OTLP docker 디스크 사용량 exporter (SRE t7: A3).
//!
//! opt-in(config `[aicd.exporter]`의 `docker_enabled`, **기본 false** — 아래 "왜 기본 false인가"
//! 참고)으로, aicd가 주기적으로 `docker system df --format json`을 spawn해 이미지/컨테이너/볼륨/
//! 빌드 캐시가 차지한 디스크 크기와 회수 가능량을 얻은 뒤 OTLP Metrics(scope=`aicd`)로 인코딩해
//! `{endpoint}/v1/metrics`로 push한다. `docker stats`는 쓰지 않는다 — CPU% 샘플링 창 때문에
//! 실측 2.05초가 걸리는데(API 소켓으로 쳐도 동일), `docker system df`는 0.19초다. 이 task의
//! 목적은 디스크지 CPU가 아니다.
//!
//! **패턴은 [`connections`](super::connections)를 따른다**: spawn 실패/timeout/non-zero exit/
//! 출력 상한 초과 4중 방어 + 실패 시 push/spool/backoff와 무관하게 다음 주기까지 조용히 skip.
//! host metrics tick(60초, in-process sysinfo)을 외부 프로세스 spawn이 막지 않도록 독립 tokio
//! task로 뜬다(aicd_main.rs). 4중 방어는 두 exporter가 공유하는 [`super::proc::run_capped`]에
//! 모여 있다 — orphan 프로세스 방지와 스트리밍 출력 상한이 거기서 보장된다.
//!
//! **파싱만은 다르다**: `docker system df --format json`의 출력은 JSON 배열이 아니라
//! **NDJSON**(줄당 객체 하나)이다. `connections.rs`처럼 `serde_json::from_slice(전체)`를 쓰면
//! 최상위가 배열이 아니라서 100% 실패한다 — 반드시 줄 단위로 파싱한다. 값도 전부 사람이 읽는
//! 문자열(`"82.64GB"`, `"39.93GB (48%)"`)이라 [`parse_docker_size`]로 바이트로 바꾼다.
//!
//! **metric은 무차원 스칼라, 컨테이너별 차원 없음**: `Type`(Images/Containers/Local Volumes/
//! Build Cache)을 attribute가 아니라 **metric 이름으로 펼친다**. 컨테이너 단위 attr을 넣지 않는
//! 이유 — 수신측(rca) metric 읽기 경로에 attrs 필터가 없어 여러 값이 평균으로 뭉개진다.
//!
//! **왜 기본 false인가**: 이 exporter 하나만 Docker라는 외부 CLI 존재에 의존한다(events/
//! connections/changes/agent는 모두 `aic` 자체 spawn 또는 in-process sysinfo/tap이라 항상
//! 가용). Docker가 없는 호스트에서 `enabled=true`로 부모 게이트만 켜면 이 task가 매 tick마다
//! spawn 실패를 겪고 WARN 로그만 쌓는다 — 실질적 이득 없이 노이즈다. 그래서 부모 게이트와 별개로
//! `docker_enabled` 자체를 opt-in(기본 false)으로 둔다(events/connections/changes/agent의
//! "부모 게이트 true면 기본 true" 관례에서 의도적으로 벗어난 유일한 플래그).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::watch;

use super::backoff::Backoff;
use super::encode;
use super::host_metrics::{HostSample, MetricPoint, MetricValue, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// `docker system df --format json` stdout 상한. 정상 출력은 카테고리 4줄뿐이라 이 한도를 훨씬
/// 밑돈다 — 초과분은 신뢰할 수 없는 출력으로 간주해 이번 주기를 스킵한다.
///
/// 상한은 [`super::proc::run_capped`]가 **스트리밍으로 읽으면서** 강제하므로 실제로 메모리를
/// 묶는다(출력을 전부 버퍼링한 뒤 길이를 재는 건 방어가 아니라 사후 확인이다 — 그렇게 짜면 무한
/// 출력이 검사에 도달하기 전에 이미 메모리를 먹는다).
const MAX_DF_OUTPUT_BYTES: usize = 256 * 1024;

/// docker exporter 실행 설정.
#[derive(Debug, Clone)]
pub struct DockerConfig {
    /// OTLP collector base URL. `/v1/metrics`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 캡처 주기.
    pub interval: Duration,
    /// spawn할 `docker` 실행 파일 경로(보통 PATH 탐색에 맡기는 `"docker"`).
    pub docker_bin: PathBuf,
    /// `docker system df` 프로세스 타임아웃(hung 방어).
    pub timeout: Duration,
    /// 오프라인 spool(SRE t8). 다른 exporter task와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 다른 exporter task와 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<super::ExporterHealth>,
}

/// docker exporter를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
pub async fn serve_docker(
    cfg: DockerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = super::metrics_url(&cfg.endpoint);
    tracing::info!(
        url = %url,
        interval_secs = cfg.interval.as_secs(),
        docker_bin = %cfg.docker_bin.display(),
        "OTLP docker exporter 시작"
    );

    // host_metrics와 동일 방식으로 얻어야 같은 host.id로 다른 signal들과 상관관계를 지을 수 있다.
    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let os_desc = sysinfo::System::long_os_version().unwrap_or_default();

    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut backoff = Backoff::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                match capture_docker_df(&cfg.docker_bin, cfg.timeout).await {
                    Ok(lines) => {
                        let points = build_metric_points(&lines);
                        if points.is_empty() {
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
                        };
                        let body = encode::encode_metrics(&sample, &cfg.service_version, super::unix_nanos_now());

                        if !backoff.ready() {
                            if let Err(e) = cfg.spool.append(SignalKind::Metrics, &body) {
                                tracing::warn!(error = %e, "OTLP docker spool append 실패 — 이 샘플 유실");
                            }
                            continue;
                        }

                        match super::push(&client, &url, cfg.token.as_deref(), body.clone()).await {
                            Ok(()) => {
                                backoff.on_success();
                                cfg.health.record_ok();
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "OTLP docker push 실패 — spool에 적재");
                                if let Err(e2) = cfg.spool.append(SignalKind::Metrics, &body) {
                                    tracing::warn!(error = %e2, "OTLP docker spool append 실패 — 이 샘플 유실");
                                }
                                backoff.on_failure();
                                cfg.health.record_fail();
                            }
                        }
                    }
                    Err(e) => {
                        // 캡처 자체의 문제(미설치/데몬 다운/권한 없음/hang)라 push/spool/backoff와
                        // 무관하게 다음 주기까지 skip한다 — connections.rs와 동일 원칙. health를
                        // 건드리지 않는다: health는 "push가 성공/실패했나"만 추적하고, 캡처 실패는
                        // 애초에 push를 시도조차 하지 않았기 때문이다.
                        tracing::warn!(error = %e, "docker system df 캡처/파싱 실패 — 다음 주기까지 skip");
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
    tracing::info!("OTLP docker exporter 종료");
    Ok(())
}

/// `docker_bin system df --format json`을 spawn해 stdout을 NDJSON 라인 단위로 파싱한다.
///
/// spawn 실패(미설치)/timeout(hang)/non-zero exit(데몬 다운·권한 없음 모두 동일 경로)/출력 상한
/// 초과 4중 방어는 [`super::proc::run_capped`]가 담당한다 — orphan 프로세스 방지(`kill_on_drop` +
/// 명시적 kill)와 **스트리밍 상한**(버퍼링 후 사후 확인이 아니라 읽는 도중 차단)이 거기 있다.
///
/// 개별 라인의 JSON 파싱 실패는 [`parse_ndjson_lines`]가 그 라인만 건너뛴다 — 전부 실패하면
/// 여기서 `Err`로 승격해 이번 주기를 skip한다.
async fn capture_docker_df(
    docker_bin: &std::path::Path,
    timeout: Duration,
) -> anyhow::Result<Vec<DfLine>> {
    let mut cmd = tokio::process::Command::new(docker_bin);
    cmd.args(["system", "df", "--format", "json"]);

    let stdout =
        super::proc::run_capped(cmd, timeout, MAX_DF_OUTPUT_BYTES, "docker system df").await?;

    let lines = parse_ndjson_lines(&stdout);
    if lines.is_empty() {
        anyhow::bail!("docker system df 출력에서 파싱 가능한 라인이 하나도 없음");
    }
    Ok(lines)
}

/// `docker system df --format json`의 NDJSON(줄당 JSON 객체 1개) 출력을 순수 함수로 파싱한다.
/// **주의**: 최상위가 배열이 아니다 — `serde_json::from_slice(전체)`를 쓰면 100% 실패한다
/// (connections.rs의 `InventorySnapshot` 파싱을 그대로 복사하면 걸리는 함정, 모듈 doc 참고).
/// 한 줄의 파싱 실패는 그 줄만 버리고 나머지는 살린다 — Docker 버전에 따라 필드가 늘거나 알 수
/// 없는 줄이 섞여도 다른 카테고리의 metric은 여전히 나가야 한다.
fn parse_ndjson_lines(stdout: &[u8]) -> Vec<DfLine> {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|line| match serde_json::from_str::<DfLine>(line) {
            Ok(entry) => Some(entry),
            Err(e) => {
                tracing::debug!(error = %e, line, "docker system df 라인 파싱 실패 — 이 라인만 skip");
                None
            }
        })
        .collect()
}

/// `docker system df --format json`이 내는 사람이 읽는 크기 문자열을 바이트로 바꾼다. docker는
/// go-units `HumanSize`(10진 SI, 1000배수)로 포맷한다 — 1024가 아니라 1000 기준이다.
///
/// 처리해야 하는 실제 형태 셋:
/// - `"82.64GB"` — `Size` 필드, 퍼센트 없음.
/// - `"39.93GB (48%)"` — `Reclaimable` 필드, `"<크기> (<퍼센트>)"`.
/// - `"21.66GB"` — Build Cache의 `Reclaimable`은 퍼센트가 없다(둘 다 처리해야 함).
///
/// 인식 못 하는 형식은 `None` — 호출부가 그 metric point만 생략한다(0으로 채우지 않는다: 측정
/// 불가는 point 생략이지, "측정했더니 0"이 아니다).
fn parse_docker_size(raw: &str) -> Option<u64> {
    // "39.93GB (48%)"의 뒷부분(퍼센트 괄호)을 버린다 — 앞 토큰만 크기다.
    let head = raw.split_whitespace().next()?;
    let split_at = head.find(|c: char| c.is_ascii_alphabetic())?;
    let (num_part, unit_part) = head.split_at(split_at);
    let num: f64 = num_part.parse().ok()?;
    if !num.is_finite() || num < 0.0 {
        return None;
    }
    let multiplier: f64 = match unit_part {
        "B" => 1.0,
        "kB" => 1_000.0,
        "MB" => 1_000_000.0,
        "GB" => 1_000_000_000.0,
        "TB" => 1_000_000_000_000.0,
        "PB" => 1_000_000_000_000_000.0,
        _ => return None,
    };
    Some((num * multiplier).round() as u64)
}

/// 파싱된 df 라인들을 OTLP metric point로 펼친다. `Type`을 attribute가 아니라 metric 이름으로
/// 펼치는 이유는 모듈 doc 참고(수신측 attrs 필터 부재로 평균에 뭉개지는 것을 막기 위함). 컨테이너는
/// `Reclaimable` metric을 내지 않는다(스펙상 usage만).
///
/// 바이트 파싱에 실패한 개별 값은 그 point만 생략한다 — 한 카테고리의 값 하나가 이상해도 나머지
/// 카테고리/필드는 그대로 나간다.
fn build_metric_points(lines: &[DfLine]) -> Vec<MetricPoint> {
    let mut points = Vec::new();
    for line in lines {
        let (usage_name, reclaimable_name): (&'static str, Option<&'static str>) =
            match line.kind.as_str() {
                "Images" => (
                    "aic.docker.image.disk.usage",
                    Some("aic.docker.image.disk.reclaimable"),
                ),
                "Containers" => ("aic.docker.container.disk.usage", None),
                "Local Volumes" => (
                    "aic.docker.volume.disk.usage",
                    Some("aic.docker.volume.disk.reclaimable"),
                ),
                "Build Cache" => (
                    "aic.docker.build_cache.disk.usage",
                    Some("aic.docker.build_cache.disk.reclaimable"),
                ),
                other => {
                    // 알 수 없는 Type(신규 Docker 버전이 카테고리를 추가한 경우 등) — 이 라인만
                    // 건너뛰고 나머지는 그대로 처리한다.
                    tracing::debug!(kind = other, "docker system df의 알 수 없는 Type — skip");
                    continue;
                }
            };

        if let Some(bytes) = parse_docker_size(&line.size) {
            points.push(MetricPoint {
                name: usage_name,
                unit: "By",
                value: MetricValue::Int(bytes as i64),
            });
        }

        if let (Some(name), Some(raw)) = (reclaimable_name, line.reclaimable.as_deref()) {
            if let Some(bytes) = parse_docker_size(raw) {
                points.push(MetricPoint {
                    name,
                    unit: "By",
                    value: MetricValue::Int(bytes as i64),
                });
            }
        }
    }
    points
}

// ── NDJSON wire contract (`docker system df --format json`의 실제 줄 형태) ────────────────

#[derive(Debug, Deserialize)]
struct DfLine {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Size")]
    size: String,
    /// Build Cache는 퍼센트 없이(`"21.66GB"`), 나머지는 퍼센트를 붙여(`"39.93GB (48%)"`) 온다.
    /// 필드 자체가 없는 버전 skew도 있을 수 있어 `Option` + `default`로 방어한다.
    #[serde(rename = "Reclaimable", default)]
    reclaimable: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// 실제 `docker system df --format json` 출력(TASK-CONTEXT.md 픽스처) — 4개 카테고리 NDJSON.
    const REAL_DF_OUTPUT: &str = concat!(
        r#"{"Active":"3","Reclaimable":"39.93GB (48%)","Size":"82.64GB","TotalCount":"179","Type":"Images"}"#,
        "\n",
        r#"{"Active":"2","Reclaimable":"224.5kB (0%)","Size":"222.6MB","TotalCount":"3","Type":"Containers"}"#,
        "\n",
        r#"{"Active":"2","Reclaimable":"7.824GB (94%)","Size":"8.3GB","TotalCount":"30","Type":"Local Volumes"}"#,
        "\n",
        r#"{"Active":"0","Reclaimable":"21.66GB","Size":"42.6GB","TotalCount":"344","Type":"Build Cache"}"#,
        "\n",
    );

    /// stdout에 고정 텍스트를 출력하는 실행 가능한 shell 스크립트를 만든다(실제 `docker` 바이너리
    /// 없이 spawn+timeout+parse 파이프라인 전체를 결정적으로 검증하기 위한 test double).
    fn fake_docker_bin(dir: &tempfile::TempDir, script: &str) -> std::path::PathBuf {
        let path = dir.path().join("fake-docker");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "#!/bin/sh\n{script}").unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    // ── 바이트 파서 ─────────────────────────────────────────────────────────

    #[test]
    fn parse_docker_size_handles_plain_size() {
        assert_eq!(parse_docker_size("82.64GB"), Some(82_640_000_000));
    }

    #[test]
    fn parse_docker_size_strips_trailing_percentage() {
        assert_eq!(parse_docker_size("39.93GB (48%)"), Some(39_930_000_000));
    }

    #[test]
    fn parse_docker_size_handles_size_without_percentage() {
        // Build Cache의 Reclaimable은 퍼센트가 없다 — 있는 경우와 별도 경로로 다뤄야 한다.
        assert_eq!(parse_docker_size("21.66GB"), Some(21_660_000_000));
    }

    #[test]
    fn parse_docker_size_handles_kilobytes() {
        assert_eq!(parse_docker_size("224.5kB"), Some(224_500));
    }

    #[test]
    fn parse_docker_size_handles_bytes_and_zero() {
        assert_eq!(parse_docker_size("0B"), Some(0));
        assert_eq!(parse_docker_size("512B"), Some(512));
    }

    #[test]
    fn parse_docker_size_rejects_unrecognized_input() {
        assert_eq!(parse_docker_size(""), None);
        assert_eq!(parse_docker_size("N/A"), None);
        assert_eq!(
            parse_docker_size("12.3XB"),
            None,
            "모르는 단위는 None이어야 한다"
        );
    }

    // ── NDJSON 파싱 ─────────────────────────────────────────────────────────

    #[test]
    fn parse_ndjson_lines_parses_all_four_categories() {
        let lines = parse_ndjson_lines(REAL_DF_OUTPUT.as_bytes());
        assert_eq!(lines.len(), 4);
        let kinds: Vec<&str> = lines.iter().map(|l| l.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["Images", "Containers", "Local Volumes", "Build Cache"]
        );
    }

    #[test]
    fn parse_ndjson_lines_skips_only_the_malformed_line() {
        let mixed = format!(
            "{}\nnot even json\n{}",
            r#"{"Active":"3","Reclaimable":"39.93GB (48%)","Size":"82.64GB","TotalCount":"179","Type":"Images"}"#,
            r#"{"Active":"0","Reclaimable":"21.66GB","Size":"42.6GB","TotalCount":"344","Type":"Build Cache"}"#,
        );
        let lines = parse_ndjson_lines(mixed.as_bytes());
        assert_eq!(lines.len(), 2, "망가진 한 줄만 빠지고 나머지는 살아야 한다");
        assert_eq!(lines[0].kind, "Images");
        assert_eq!(lines[1].kind, "Build Cache");
    }

    #[test]
    fn parse_ndjson_lines_on_whole_blob_json_array_would_fail_but_line_by_line_succeeds() {
        // connections.rs 패턴(serde_json::from_slice(전체))을 그대로 썼다면 최상위가 배열이 아니라
        // 여기서 즉시 실패한다 — 그 회귀를 잡기 위한 대조 테스트.
        assert!(serde_json::from_slice::<Vec<DfLine>>(REAL_DF_OUTPUT.as_bytes()).is_err());
        assert_eq!(parse_ndjson_lines(REAL_DF_OUTPUT.as_bytes()).len(), 4);
    }

    // ── metric point 구성 ───────────────────────────────────────────────────

    #[test]
    fn build_metric_points_emits_seven_named_scalars_with_correct_bytes() {
        let lines = parse_ndjson_lines(REAL_DF_OUTPUT.as_bytes());
        let points = build_metric_points(&lines);

        let get = |name: &str| {
            points
                .iter()
                .find(|p| p.name == name)
                .map(|p| match p.value {
                    MetricValue::Int(v) => v,
                    MetricValue::Double(_) => panic!("docker metric은 항상 Int(바이트)여야 함"),
                })
        };

        assert_eq!(get("aic.docker.image.disk.usage"), Some(82_640_000_000));
        assert_eq!(
            get("aic.docker.image.disk.reclaimable"),
            Some(39_930_000_000)
        );
        assert_eq!(get("aic.docker.container.disk.usage"), Some(222_600_000));
        assert_eq!(get("aic.docker.volume.disk.usage"), Some(8_300_000_000));
        assert_eq!(
            get("aic.docker.volume.disk.reclaimable"),
            Some(7_824_000_000)
        );
        assert_eq!(
            get("aic.docker.build_cache.disk.usage"),
            Some(42_600_000_000)
        );
        assert_eq!(
            get("aic.docker.build_cache.disk.reclaimable"),
            Some(21_660_000_000)
        );

        assert_eq!(
            points.len(),
            7,
            "정확히 7개 — 컨테이너 reclaimable은 스펙상 없다"
        );
        assert!(
            !points
                .iter()
                .any(|p| p.name == "aic.docker.container.disk.reclaimable"),
            "컨테이너는 usage만 낸다"
        );
        for p in &points {
            assert_eq!(p.unit, "By", "모든 docker metric은 무차원 바이트");
        }
    }

    #[test]
    fn build_metric_points_skips_only_the_unparseable_value() {
        let lines = vec![
            DfLine {
                kind: "Images".to_string(),
                size: "not a size".to_string(),
                reclaimable: Some("39.93GB (48%)".to_string()),
            },
            DfLine {
                kind: "Build Cache".to_string(),
                size: "42.6GB".to_string(),
                reclaimable: Some("21.66GB".to_string()),
            },
        ];
        let points = build_metric_points(&lines);
        // Images.usage는 파싱 실패해 생략되지만 Images.reclaimable과 Build Cache 둘 다는 살아야 한다
        // — "모르는 값은 0이 아니라 생략"의 핵심 invariant.
        assert!(points
            .iter()
            .all(|p| p.name != "aic.docker.image.disk.usage"));
        assert!(points
            .iter()
            .any(|p| p.name == "aic.docker.image.disk.reclaimable"));
        assert!(points
            .iter()
            .any(|p| p.name == "aic.docker.build_cache.disk.usage"));
        assert!(points
            .iter()
            .any(|p| p.name == "aic.docker.build_cache.disk.reclaimable"));
    }

    #[test]
    fn build_metric_points_ignores_unknown_type_without_panicking() {
        let lines = vec![DfLine {
            kind: "Some Future Category".to_string(),
            size: "1GB".to_string(),
            reclaimable: None,
        }];
        assert!(build_metric_points(&lines).is_empty());
    }

    // ── capture_docker_df: spawn/timeout/exit/파싱 4중 방어 ────────────────────

    use super::super::proc::testutil::{is_text_file_busy, retry_busy};

    #[tokio::test]
    async fn capture_docker_df_parses_real_ndjson_output_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(&dir, &format!("cat <<'EOF'\n{REAL_DF_OUTPUT}EOF"));

        let lines = capture_docker_df(&bin, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].kind, "Images");
        assert_eq!(lines[0].size, "82.64GB");
    }

    #[tokio::test]
    async fn capture_docker_df_errors_on_nonzero_exit() {
        // 데몬 다운/권한 없음 둘 다 non-zero exit로 나오므로 동일 경로 — 별도 분기 불필요.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(
            &dir,
            "echo 'failed to connect to the docker API at unix:///var/run/docker.sock' >&2; exit 1",
        );
        let err = capture_docker_df(&bin, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("종료"), "err={err}");
    }

    #[tokio::test]
    async fn capture_docker_df_times_out_on_hung_process() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(&dir, "sleep 30");
        let err = retry_busy(|| capture_docker_df(&bin, Duration::from_millis(100)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("끝나지 않음"), "err={err}");
    }

    #[tokio::test]
    async fn capture_docker_df_errors_on_spawn_failure_when_docker_not_installed() {
        let missing = std::path::PathBuf::from("/definitely/does/not/exist/docker");
        assert!(capture_docker_df(&missing, Duration::from_secs(5))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn capture_docker_df_errors_when_every_line_fails_to_parse() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(&dir, "echo 'not json at all'");
        assert!(
            retry_busy(|| capture_docker_df(&bin, Duration::from_secs(5)))
                .await
                .is_err()
        );
    }

    /// **회귀 가드**: timeout 시 spawn된 `docker`가 실제로 죽어야 한다. `tokio::time::timeout`은
    /// future만 drop할 뿐 자식 프로세스를 죽이지 않는다 — aicd는 상주 데몬이고 이 task는 60초마다
    /// 도니, docker가 hang하는 환경이면 orphan이 매 tick 쌓인다. 플래그가 켜졌는지가 아니라
    /// **프로세스가 사라졌는지**를 확인한다(재시도 전략은 `super::proc::testutil` 참고).
    #[tokio::test]
    async fn capture_docker_df_timeout_kills_the_child_process() {
        use super::super::proc::testutil::{alive, hang_script, read_pid, GRACES};

        for grace in GRACES {
            let dir = tempfile::tempdir().unwrap();
            let pidfile = dir.path().join("pid");
            let bin = fake_docker_bin(&dir, &hang_script(&pidfile));

            let err = capture_docker_df(&bin, grace).await.unwrap_err();
            // 스크립트 exec race(ETXTBSY) — 자식이 아예 안 떴다. 다시 시도한다.
            if is_text_file_busy(&err) {
                continue;
            }
            assert!(err.to_string().contains("끝나지 않음"), "err={err}");

            // pid가 없으면 자식이 기동 전이었다 — 죽일 자식이 없었으니 단정하지 않는다(공허 통과 방지).
            let Some(pid) = read_pid(&pidfile) else {
                continue;
            };
            assert!(
                !alive(pid),
                "timeout 후에도 docker(pid={pid})가 살아 있다 — orphan 누수"
            );
            return;
        }
        panic!("자식이 한 번도 기동하지 못해 orphan 여부를 검증하지 못했다");
    }

    /// **회귀 가드**: 무한 출력은 전부 버퍼링되기 전에 스트리밍 도중 끊긴다. 사후 확인 방식
    /// (`wait_with_output()` 후 길이 검사)이라면 이 테스트는 끝나지 않거나 OOM으로 죽는다.
    #[tokio::test]
    async fn capture_docker_df_cuts_off_unbounded_output_mid_stream() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(
            &dir,
            "while :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done",
        );

        // 바깥 timeout을 안쪽보다 넉넉히 줘야 "상한 때문에 끊겼다"와 "timeout이라 끊겼다"가 구분된다.
        let err = tokio::time::timeout(
            Duration::from_secs(20),
            retry_busy(|| capture_docker_df(&bin, Duration::from_secs(15))),
        )
        .await
        .expect("상한이 스트리밍으로 강제되지 않아 무한 출력에 매달렸다")
        .unwrap_err();

        assert!(err.to_string().contains("상한"), "err={err}");
    }

    // ── serve_docker: 캡처 실패가 task를 죽이지 않고, 다른 signal이 공유하는 health/spool도 오염하지 않는다 ──

    #[tokio::test]
    async fn serve_docker_survives_missing_binary_without_touching_shared_health_or_spool() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(Spool::open(dir.path().to_path_buf(), 1024 * 1024).unwrap());
        let health = Arc::new(super::super::ExporterHealth::new(
            "http://127.0.0.1:1".to_string(),
            spool.clone(),
        ));

        let cfg = DockerConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            interval: Duration::from_millis(15),
            docker_bin: std::path::PathBuf::from("/definitely/does/not/exist/docker"),
            timeout: Duration::from_secs(5),
            spool: spool.clone(),
            health: health.clone(),
        };

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_docker(cfg, rx));
        // interval(15ms)보다 훨씬 긴 유예를 둬 여러 tick이 반드시 발생하게 한다.
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send_replace(true);
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve_docker가 shutdown 후 hang됨")
            .expect("serve_docker task가 panic함");
        assert!(
            result.is_ok(),
            "캡처 반복 실패가 task 자체를 죽이면 안 됨: {result:?}"
        );

        // 캡처 실패는 push를 시도조차 하지 않으므로, 다른 exporter task와 공유하는 health/spool은
        // 전혀 건드리지 않는다 — docker 미설치가 events/connections/changes/agent의 건강 카운터를
        // 오염시키지 않는다는 증거.
        let snap = health.snapshot();
        assert_eq!(snap.push_ok_total, 0);
        assert_eq!(snap.push_fail_total, 0);
        assert_eq!(
            spool.batch_count(),
            0,
            "캡처 실패는 spool에 아무것도 남기지 않는다"
        );
    }
}
