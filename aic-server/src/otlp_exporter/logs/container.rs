//! docker json-file 컨테이너 로그 수집기 (RFC-006 t10) — `FileTail`(t9) 재사용, spawn 없음.
//!
//! ★★★ RFC-006 §4.2 원안(`docker logs --follow` spawn) 폐기 ★★★
//!
//! §4.2는 `docker logs --follow --since=<ts>` spawn + `docker ps` 폴링 + "컨테이너별 마지막
//! 타임스탬프" 체크포인트를 제안했지만, 조사 결과 세 겹으로 깨진다:
//!
//! 1. **`docker logs -f`는 json-file 로테이션 시 조용히 멈춘다** — moby#23913, moby#37646(미해결).
//!    `max-size`가 걸린 모든 프로덕션 컨테이너에서 첫 로테이션에 죽는다.
//! 2. **Engine API의 `since`는 초 해상도 정수**다. 재접속마다 최대 1초가 중복되거나 샌다 —
//!    Vector조차 이를 못 피해 `since - 1`로 일부러 겹쳐 요청하고 메모리에서 dedup한다.
//! 3. **컨테이너당 자식 프로세스 1개**는 스케일이 안 되고, containerd/CRI-O엔 Docker API가 없다.
//!
//! Vector(kubernetes_logs) / OTel filelog / Filebeat(container input) / Fluent Bit — 조사한 4개
//! 구현이 전부 **파일 tail**을 쓴다(Vector의 `docker_logs`만 API 방식인데, 디스크 체크포인트가
//! 없어 재시작마다 재읽기/중복이 난다).
//!
//! ## → 파일 tail. `t9`의 [`FileTail`](super::file::FileTail)을 그대로 재사용한다.
//!
//! 이 모듈이 새로 만드는 건 **경로 발견(glob) + 라인 파서** 둘뿐이다. fingerprint/rotation/
//! offset/truncate 판정은 전부 `FileTail`에 위임한다 — 새 tail 로직을 짜지 않는다.
//!
//! **★ 경로에 컨테이너 id가 박혀 있다는 게 핵심이다.** 경로 규약이
//! `/var/lib/docker/containers/<id>/<id>-json.log`라, 컨테이너를 재생성하면 id가 바뀌어 경로
//! 자체가 달라진다 — 새 파일로 인식되고 fingerprint도 다르다. RFC §4.2가 걱정한 "이름은 같은데
//! 다른 컨테이너 → 체크포인트를 버리고 `--since=now`로 되돌아가는 로직"이 통째로 불필요해진다.
//! 재생성 중복 문제가 설계적으로 소멸한다(DoD 3).
//!
//! ## 깨진 라인은 파서가 `None`으로 버린다
//!
//! `file.rs`의 [`LineParser`]는 `Fn(&str) -> Option<LogLine>`이다. json-file 한 줄이 깨져 있으면
//! ([`build_container_log_line`]) 카운터를 올리고 `None`을 반환하고, `FileTail`이 그 자리에서
//! 버린다 — 파싱 실패 라인은 파이프라인에 **절대 도달하지 않는다.**
//!
//! ## podman은 범위 밖
//!
//! 경로 규약(`/var/run/containers/storage/...` 등)이 docker와 다르다. v1은 docker json-file
//! 드라이버만 다룬다.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use aic_common::redaction::redact;
use aic_common::LogLine;

use super::checkpoint::CheckpointStore;
use super::file::{FileTail, LineParser};
use super::DropCounters;

/// docker의 기본 컨테이너 로그 디렉토리. 컨테이너별 하위 디렉토리(`<id>/`) 안에
/// `<id>-json.log`가 있다.
const DEFAULT_CONTAINERS_DIR: &str = "/var/lib/docker/containers";

/// 새 컨테이너를 잡아내는 재스캔 주기. 매 tick(1초)마다 전체 디렉토리를 훑는 건 컨테이너 수가
/// 많을 때 낭비라, tick보다 느슨한 별도 주기로 분리한다.
const RESCAN_INTERVAL: Duration = Duration::from_secs(5);

/// 이미 추적 중인 파일들을 읽는 주기. `file.rs::serve_files`의 1초 폴링과 동일한 관례.
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// container 수집기 실행 설정.
#[derive(Debug, Clone)]
pub struct ContainerCollectorConfig {
    /// docker 컨테이너 로그 베이스 디렉토리. 테스트에서 tempdir로 교체한다.
    pub containers_dir: PathBuf,
    /// `record_id` 계산에 넘기는 host.
    pub host: String,
}

impl Default for ContainerCollectorConfig {
    fn default() -> Self {
        Self {
            containers_dir: PathBuf::from(DEFAULT_CONTAINERS_DIR),
            host: "unknown".to_string(),
        }
    }
}

/// JSON/시간 파싱 실패 카운터. `DropCounters`(mod.rs)와 별개다 — mod.rs는 이 태스크의 수정
/// 대상이 아니고(볼륨 안전장치 드롭 사유만 다룬다), 여기 카운터는 "라인 자체가 깨져서 해석할 수
/// 없었다"는, 성격이 다른 실패 사유다.
#[derive(Debug, Default)]
pub struct ContainerParseCounters {
    /// JSON으로 파싱 불가하거나(반쪽 라인 등), object가 아니거나, `log` 필드가 없거나 문자열이
    /// 아닌 경우.
    pub invalid_json: AtomicU64,
    /// JSON 자체는 유효하지만 `time` 필드가 없거나 RFC3339로 파싱되지 않는 경우.
    pub invalid_time: AtomicU64,
}

impl ContainerParseCounters {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── 순수 함수: docker json-file 한 줄 파싱 ──────────────────────────────────

/// `docker json-file` 로그 드라이버가 쓰는 한 줄의 필드. `time_raw`는 아직 파싱하지 않은 문자열
/// 그대로다 — JSON 자체가 깨진 경우(`invalid_json`)와 시간 형식만 깨진 경우(`invalid_time`)를
/// 구분해서 세기 위해 두 단계로 나눈다.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerJsonFields {
    log: String,
    stream: String,
    time_raw: Option<String>,
}

/// 한 줄(JSON object)을 [`DockerJsonFields`]로 뽑는다. 유효한 JSON이 아니거나, object가
/// 아니거나, `log` 필드가 없거나 문자열이 아니면 `None`(반쪽 라인·중첩 이스케이프 실패·log 필드
/// 부재가 전부 여기서 걸린다). `stream`이 없으면 `"stdout"`으로 기본값을 둔다(docker는 항상
/// 채우지만, 방어적으로).
fn parse_docker_json_line(raw: &str) -> Option<DockerJsonFields> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = value.as_object()?;
    let log = obj.get("log")?.as_str()?.to_string();
    let stream = obj
        .get("stream")
        .and_then(|v| v.as_str())
        .unwrap_or("stdout")
        .to_string();
    let time_raw = obj
        .get("time")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Some(DockerJsonFields {
        log,
        stream,
        time_raw,
    })
}

/// `time` 필드(RFC3339, 나노초 정밀도 허용)를 파싱한다.
fn parse_docker_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// docker json-file 한 줄 → [`LogLine`]. 실패하면 `counters`를 올리고 `None`을 반환한다 —
/// `FileTail`이 `None`인 줄을 그 자리에서 버린다.
///
/// - `severity`: `stream == "stderr"` → WARN, 그 외(`stdout` 포함 기본값) → INFO.
/// - `message`: `log`의 trailing `\n`을 제거한 뒤 `redact()`.
/// - `attrs`: `container_id`(전체), 있으면 `image`.
fn build_container_log_line(
    raw: &str,
    container_id: &str,
    service: &str,
    image: Option<&str>,
    counters: &ContainerParseCounters,
) -> Option<LogLine> {
    let Some(fields) = parse_docker_json_line(raw) else {
        counters.invalid_json.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let Some(ts) = fields.time_raw.as_deref().and_then(parse_docker_time) else {
        counters.invalid_time.fetch_add(1, Ordering::Relaxed);
        return None;
    };

    let mut attrs = BTreeMap::new();
    attrs.insert("container_id".to_string(), container_id.to_string());
    if let Some(img) = image {
        attrs.insert("image".to_string(), img.to_string());
    }
    let (message, _report) = redact(fields.log.trim_end_matches('\n'));
    let severity = if fields.stream == "stderr" {
        "WARN"
    } else {
        "INFO"
    };

    Some(LogLine {
        source: "container".to_string(),
        service: service.to_string(),
        severity: severity.to_string(),
        message,
        attrs,
        ts,
        record_id: String::new(), // FileTail::emit_lines가 fingerprint:offset으로 덮어쓴다.
    })
}

/// 컨테이너 하나에 대한 [`LineParser`]를 만든다. `container_id`/`service`/`image`를 클로저가
/// 캡처해 두어, 라인마다 다시 계산하지 않는다(그 값들은 컨테이너 발견 시점에 한 번만 읽는다 —
/// [`resolve_container_meta`]).
///
/// 깨진 json-file 라인은 `None`이 되어 `FileTail`이 그 자리에서 버린다 — 파이프라인에 닿지
/// 않는다. 버린 사실은 `build_container_log_line`이 `counters`에 기록한다.
fn container_line_parser(
    container_id: String,
    service: String,
    image: Option<String>,
    counters: Arc<ContainerParseCounters>,
) -> Arc<LineParser> {
    Arc::new(move |raw: &str| {
        build_container_log_line(raw, &container_id, &service, image.as_deref(), &counters)
    })
}

// ── 경로 발견 ────────────────────────────────────────────────────────────

/// `<containers_dir>/*/*-json.log`를 나열한다. `docker ps` 폴링은 필요 없다 — 이 함수를
/// 주기적으로(재스캔 주기) 다시 부르는 것만으로 새 컨테이너가 잡힌다.
///
/// - 컨테이너 디렉토리 하나를 못 읽어도(방금 삭제됨 등) 전체 스캔을 실패시키지 않고 건너뛴다.
/// - **심볼릭 링크는 따라가지 않는다**(경로 탈출 방지) — `symlink_metadata`(lstat 성격)로 실제
///   엔트리 타입을 확인하고, 심링크면 제외한다.
/// - 베이스 디렉토리 자체를 못 읽으면(권한 없음 등) `Err`를 그대로 전파한다 — 호출부
///   (`run_container_collector`)가 이 경우를 "수집기 비활성화" 신호로 다룬다.
pub fn discover_container_logs(containers_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(containers_dir)? {
        let Ok(entry) = entry else { continue };
        let container_dir = entry.path();
        let Ok(inner_entries) = std::fs::read_dir(&container_dir) else {
            continue;
        };
        for item in inner_entries {
            let Ok(item) = item else { continue };
            let path = item.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with("-json.log") {
                continue;
            }
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if !meta.file_type().is_symlink() => out.push(path),
                _ => {}
            }
        }
    }
    Ok(out)
}

/// 로그 파일 경로에서 컨테이너 id를 뽑는다(부모 디렉토리 이름). docker의 경로 규약
/// (`<containers_dir>/<id>/<id>-json.log`)에 의존한다.
pub fn container_id_from_log_path(path: &Path) -> Option<String> {
    path.parent()?.file_name()?.to_str().map(|s| s.to_string())
}

/// 짧은 id(앞 12자) — `service` 폴백에 쓴다(docker CLI 관례와 동일).
fn short_container_id(container_id: &str) -> String {
    container_id.chars().take(12).collect()
}

/// `config.v2.json`에서 뽑은 컨테이너 메타데이터.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerMeta {
    /// 컨테이너 이름(`Name` 필드의 앞 `/` 제거). 못 읽으면 짧은 id로 폴백.
    pub service: String,
    /// 이미지 참조(`Config.Image`, 없으면 top-level `Image`). 못 읽으면 `None`(비목표 —
    /// attrs에서 생략된다).
    pub image: Option<String>,
}

/// `<container_dir>/config.v2.json`을 읽어 서비스명/이미지를 뽑는다. 파일이 없거나, 읽을 수
/// 없거나, 유효한 JSON이 아니거나, `Name` 필드가 비어 있으면 짧은 id로 폴백한다 — 절대 panic하지
/// 않는다.
pub fn resolve_container_meta(container_dir: &Path, container_id: &str) -> ContainerMeta {
    let fallback_service = short_container_id(container_id);
    let Ok(content) = std::fs::read_to_string(container_dir.join("config.v2.json")) else {
        return ContainerMeta {
            service: fallback_service,
            image: None,
        };
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return ContainerMeta {
            service: fallback_service,
            image: None,
        };
    };
    let service = value
        .get("Name")
        .and_then(|n| n.as_str())
        .map(|s| s.trim_start_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_service);
    let image = value
        .get("Config")
        .and_then(|c| c.get("Image"))
        .and_then(|i| i.as_str())
        .or_else(|| value.get("Image").and_then(|i| i.as_str()))
        .map(|s| s.to_string());
    ContainerMeta { service, image }
}

// ── 수집기 드라이버 ──────────────────────────────────────────────────────

/// 발견한 경로에 대해 `FileTail`을 만들어 `tails`에 등록한다(이미 있으면 아무것도 하지 않음 —
/// 호출부가 미리 `contains_key`로 걸러도 되지만, 여기서도 한 번 더 방어한다).
fn add_tail(
    tails: &mut HashMap<PathBuf, FileTail>,
    log_path: PathBuf,
    host: &str,
    parse_counters: &Arc<ContainerParseCounters>,
) {
    if tails.contains_key(&log_path) {
        return;
    }
    let container_id = match container_id_from_log_path(&log_path) {
        Some(id) => id,
        None => {
            tracing::warn!(path = %log_path.display(), "컨테이너 id를 경로에서 뽑을 수 없음 — 건너뜀");
            return;
        }
    };
    let container_dir = log_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let meta = resolve_container_meta(&container_dir, &container_id);
    let parser = container_line_parser(
        container_id.clone(),
        meta.service,
        meta.image,
        parse_counters.clone(),
    );
    // label은 체크포인트 키(`file/<label>`)로만 쓰인다 — service는 파서가 이미 결정했으므로
    // 여기서는 컨테이너 id를 그대로 label로 써서 유일성만 보장하면 된다.
    let tail = FileTail::with_parser(log_path.clone(), container_id, host.to_string(), parser);
    tails.insert(log_path, tail);
}

/// container 수집기를 실행한다. `shutdown`이 true가 되면 진행 중인 라운드를 정리하고 종료한다.
///
/// **베이스 디렉토리를 최초에 못 읽으면(권한 없음/미설치) 에러를 위로 던지지 않는다** — 명확한
/// 경고만 남기고 이 수집기만 비활성화된 채 `Ok(())`를 반환한다. 호출부가 `?`로 전파했다면 aicd
/// 전체가 죽었을 것이다(daemon/다른 수집기는 계속 살아야 한다).
pub async fn run_container_collector(
    cfg: ContainerCollectorConfig,
    tx: mpsc::Sender<LogLine>,
    checkpoint: Arc<CheckpointStore>,
    drop_counters: Arc<DropCounters>,
    parse_counters: Arc<ContainerParseCounters>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let initial = match discover_container_logs(&cfg.containers_dir) {
        Ok(found) => found,
        Err(e) => {
            match e.kind() {
                io::ErrorKind::NotFound => {
                    tracing::info!(
                        dir = %cfg.containers_dir.display(),
                        "컨테이너 로그 디렉토리 없음 — container 수집기 비활성화"
                    );
                }
                io::ErrorKind::PermissionDenied => {
                    tracing::warn!(
                        dir = %cfg.containers_dir.display(),
                        error = %e,
                        "컨테이너 로그 디렉토리 권한 없음 — container 수집기만 비활성화(aicd는 계속 실행)"
                    );
                }
                _ => {
                    tracing::warn!(
                        dir = %cfg.containers_dir.display(),
                        error = %e,
                        "컨테이너 로그 디렉토리 스캔 실패 — container 수집기만 비활성화(aicd는 계속 실행)"
                    );
                }
            }
            return Ok(());
        }
    };

    tracing::info!(
        dir = %cfg.containers_dir.display(),
        found = initial.len(),
        "container 수집기 시작"
    );

    let mut tails: HashMap<PathBuf, FileTail> = HashMap::new();
    for path in initial {
        add_tail(&mut tails, path, &cfg.host, &parse_counters);
    }

    let mut tick_timer = tokio::time::interval(TICK_INTERVAL);
    tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut rescan_timer = tokio::time::interval(RESCAN_INTERVAL);
    rescan_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = tick_timer.tick() => {
                for tail in tails.values_mut() {
                    if let Err(e) = tail.tick(&tx, &drop_counters, &checkpoint) {
                        tracing::warn!(error = %e, "container tail tick 실패");
                    }
                }
            }
            _ = rescan_timer.tick() => {
                match discover_container_logs(&cfg.containers_dir) {
                    Ok(found) => {
                        for path in found {
                            add_tail(&mut tails, path, &cfg.host, &parse_counters);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "컨테이너 로그 재스캔 실패 — 다음 주기에 재시도");
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

    tracing::info!("container 수집기 종료");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn test_checkpoint() -> (tempfile::TempDir, Arc<CheckpointStore>) {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(dir.path().join("checkpoints")).unwrap();
        (dir, Arc::new(store))
    }

    /// fingerprint 임계(1024B, file.rs)를 넘기기 위한 패딩 + 실제 라인들을 이어붙인다.
    fn padded_lines(lines: &[&str]) -> Vec<u8> {
        let mut content = Vec::new();
        for line in lines {
            content.extend_from_slice(line.as_bytes());
            content.push(b'\n');
        }
        while content.len() < 1024 {
            content.extend_from_slice(b"{\"log\":\"padding\\n\",\"stream\":\"stdout\",\"time\":\"2026-01-01T00:00:00.000000000Z\"}\n");
        }
        content
    }

    /// docker json-file 한 줄 + **물리적** 줄바꿈(파일에 append할 때 쓰는 실제 `\n` 바이트).
    /// 주의: JSON 문자열 안의 `\n`(`log` 필드 끝의 이스케이프)은 콘텐츠일 뿐 파일의 줄 구분자가
    /// 아니다 — `FileTail::drain_complete_lines`는 실제 `0x0A` 바이트로만 줄을 끊으므로, 이 함수가
    /// 반환하는 문자열 끝에 그 실제 바이트를 붙여 둬야 파일에 append했을 때 "완결된 라인"으로
    /// 인식된다.
    fn docker_line(log: &str, stream: &str, time: &str) -> String {
        // log 필드 안의 백슬래시/따옴표를 이스케이프해 유효한 JSON 문자열로 만든다.
        let escaped = log.replace('\\', "\\\\").replace('"', "\\\"");
        format!("{{\"log\":\"{escaped}\\n\",\"stream\":\"{stream}\",\"time\":\"{time}\"}}\n")
    }

    fn write_container_log(base: &Path, container_id: &str, initial_lines: &[&str]) -> PathBuf {
        let dir = base.join(container_id);
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join(format!("{container_id}-json.log"));
        std::fs::write(&log_path, padded_lines(initial_lines)).unwrap();
        log_path
    }

    fn write_config_v2(base: &Path, container_id: &str, name: &str, image: Option<&str>) {
        let dir = base.join(container_id);
        std::fs::create_dir_all(&dir).unwrap();
        let image_json = match image {
            Some(img) => format!(r#""Config":{{"Image":"{img}"}},"#),
            None => String::new(),
        };
        let content = format!(r#"{{{image_json}"Name":"/{name}"}}"#);
        std::fs::write(dir.join("config.v2.json"), content).unwrap();
    }

    fn append(path: &Path, bytes: &[u8]) {
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    fn recv_all(rx: &mut mpsc::Receiver<LogLine>) -> Vec<LogLine> {
        let mut out = Vec::new();
        while let Ok(line) = rx.try_recv() {
            out.push(line);
        }
        out
    }

    // ── DoD 1: docker json-file 라인 디코딩 ─────────────────────────────────

    #[test]
    fn docker_json_line_decodes() {
        let counters = ContainerParseCounters::new();
        let raw = r#"{"log":"nginx: something\n","stream":"stdout","time":"2026-07-13T08:00:00.123456789Z"}"#;
        let line =
            build_container_log_line(raw, "abc123", "nginx", Some("nginx:latest"), &counters)
                .expect("valid docker json line");
        assert_eq!(line.message, "nginx: something");
        assert_eq!(line.source, "container");
        assert_eq!(line.service, "nginx");
        assert_eq!(line.severity, "INFO");
        assert_eq!(
            line.attrs.get("container_id").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            line.attrs.get("image").map(String::as_str),
            Some("nginx:latest")
        );
        assert_eq!(
            line.ts,
            chrono::DateTime::parse_from_rfc3339("2026-07-13T08:00:00.123456789Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        );
        assert_eq!(counters.invalid_json.load(Ordering::Relaxed), 0);
        assert_eq!(counters.invalid_time.load(Ordering::Relaxed), 0);
    }

    // ── DoD 2: stream → severity ────────────────────────────────────────────

    #[test]
    fn stderr_stream_maps_to_warn() {
        let counters = ContainerParseCounters::new();
        let stderr_line = build_container_log_line(
            &docker_line("boom", "stderr", "2026-07-13T08:00:00Z"),
            "id",
            "svc",
            None,
            &counters,
        )
        .unwrap();
        assert_eq!(stderr_line.severity, "WARN");

        let stdout_line = build_container_log_line(
            &docker_line("ok", "stdout", "2026-07-13T08:00:00Z"),
            "id",
            "svc",
            None,
            &counters,
        )
        .unwrap();
        assert_eq!(stdout_line.severity, "INFO");
    }

    // ── DoD 3: 컨테이너 재생성 → 다른 경로 → 새 fingerprint, 중복 없음 ───────

    #[test]
    fn container_recreation_yields_new_fingerprint_no_duplicate() {
        let base = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();

        // 같은 이름("web")으로 재생성된 두 "세대" — id가 다르므로 경로가 다르다. 초기 패딩
        // 내용도 세대마다 다르게 둬서(현실에서도 서로 다른 컨테이너의 로그는 동일하지 않다)
        // fingerprint가 우연히 같아지는 경우를 배제한다.
        write_config_v2(base.path(), "gen0-id", "web", None);
        let path0 = write_container_log(base.path(), "gen0-id", &["gen0-marker"]);
        write_config_v2(base.path(), "gen1-id", "web", None);
        let path1 = write_container_log(base.path(), "gen1-id", &["gen1-marker"]);

        assert_ne!(path0, path1, "재생성된 컨테이너는 경로 자체가 달라야 함");

        let parse_counters = Arc::new(ContainerParseCounters::new());
        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();

        let mut tails: HashMap<PathBuf, FileTail> = HashMap::new();
        add_tail(&mut tails, path0.clone(), "host-a", &parse_counters);
        add_tail(&mut tails, path1.clone(), "host-a", &parse_counters);
        assert_eq!(
            tails.len(),
            2,
            "서로 다른 경로는 별개의 FileTail로 추적되어야 함"
        );

        for tail in tails.values_mut() {
            tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        }
        recv_all(&mut rx); // 최초 확립 — 백필 없음

        append(
            &path0,
            docker_line("gen0-line", "stdout", "2026-07-13T08:00:00Z").as_bytes(),
        );
        append(
            &path1,
            docker_line("gen1-line", "stdout", "2026-07-13T08:00:01Z").as_bytes(),
        );

        for tail in tails.values_mut() {
            tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        }
        let got = recv_all(&mut rx);
        assert!(got.iter().any(|l| l.message == "gen0-line"));
        assert!(got.iter().any(|l| l.message == "gen1-line"));
        assert_eq!(
            got.len(),
            2,
            "중복 없이 각 세대에서 정확히 1줄씩만 나와야 함"
        );
        // record_id는 fingerprint:offset 기반이다 — 서로 다른 초기 내용(fingerprint가 다름)을
        // 가진 두 파일이면 자연히 달라진다.
        assert_ne!(got[0].record_id, got[1].record_id);
    }

    // ── DoD 4: 재스캔 사이 새 컨테이너 발견 ──────────────────────────────────

    #[test]
    fn glob_discovers_new_containers() {
        let base = tempfile::tempdir().unwrap();
        write_container_log(base.path(), "existing-id", &[]);

        let first = discover_container_logs(base.path()).unwrap();
        assert_eq!(first.len(), 1);

        // "tick 사이"에 새 컨테이너가 뜬다.
        write_container_log(base.path(), "new-id", &[]);

        let second = discover_container_logs(base.path()).unwrap();
        assert_eq!(second.len(), 2, "다음 스캔에서 새 컨테이너가 잡혀야 함");
    }

    // ── DoD 5: 권한 없음 → 이 수집기만 비활성화 ──────────────────────────────

    /// root는 퍼미션 비트를 무시한다(`CAP_DAC_OVERRIDE`) — `chmod 000`을 걸어도 그냥 읽힌다.
    /// 컨테이너 안에서 테스트를 돌리면(docker 기본이 root다) "권한 없음" 상황 자체를 만들 수
    /// 없어, 수집기가 정상 동작하며 타임아웃까지 돈다. 제품 버그가 아니라 **테스트가 전제를
    /// 만들지 못하는 환경**이므로 건너뛴다. (CI의 ubuntu-latest는 non-root라 실제로 검증된다.)
    fn running_as_root() -> bool {
        // SAFETY: geteuid는 언제나 성공하고 부수효과가 없다.
        unsafe { libc::geteuid() == 0 }
    }

    #[tokio::test]
    async fn permission_denied_disables_only_this_collector() {
        use std::os::unix::fs::PermissionsExt;

        if running_as_root() {
            eprintln!("root에서는 chmod 000이 무의미하므로 건너뜀 — running_as_root() 주석 참고");
            return;
        }

        let base = tempfile::tempdir().unwrap();
        let restricted = base.path().join("no-access");
        std::fs::create_dir_all(&restricted).unwrap();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();

        let (_cp_dir, checkpoint) = test_checkpoint();
        let (tx, _rx) = mpsc::channel(16);
        let drop_counters = Arc::new(DropCounters::new());
        let parse_counters = Arc::new(ContainerParseCounters::new());
        let (_sd_tx, sd_rx) = watch::channel(false);

        let cfg = ContainerCollectorConfig {
            containers_dir: restricted.clone(),
            host: "test-host".to_string(),
        };

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_container_collector(cfg, tx, checkpoint, drop_counters, parse_counters, sd_rx),
        )
        .await;

        // 테스트 디렉토리 정리를 위해 권한을 복구한다(복구 전엔 tempdir Drop의 재귀 삭제가 실패할
        // 수 있다).
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o755)).unwrap();

        let outcome = result.expect("권한 없음은 즉시 반환되어야 함(무한 대기 금지)");
        assert!(
            outcome.is_ok(),
            "권한 없음은 이 수집기만 비활성화해야 함 — Err를 위로 던지면 aicd가 죽는다"
        );
    }

    // ── DoD 6: 서비스명 = config.v2.json Name, 폴백 = 짧은 id ────────────────

    #[test]
    fn service_name_from_config_v2_json() {
        let base = tempfile::tempdir().unwrap();
        write_config_v2(
            base.path(),
            "abcdef1234567890",
            "my-nginx",
            Some("nginx:1.25"),
        );

        let meta =
            resolve_container_meta(&base.path().join("abcdef1234567890"), "abcdef1234567890");
        assert_eq!(meta.service, "my-nginx");
        assert_eq!(meta.image.as_deref(), Some("nginx:1.25"));
    }

    #[test]
    fn falls_back_to_short_id_when_config_unreadable() {
        let base = tempfile::tempdir().unwrap();
        let container_dir = base.path().join("abcdef1234567890fedcba");
        std::fs::create_dir_all(&container_dir).unwrap();
        // config.v2.json이 아예 없다.

        let meta = resolve_container_meta(&container_dir, "abcdef1234567890fedcba");
        assert_eq!(
            meta.service, "abcdef123456",
            "짧은 id(앞 12자)로 폴백해야 함"
        );
        assert_eq!(meta.image, None);

        // 존재하지만 유효한 JSON이 아닌 경우도 동일하게 폴백해야 함.
        std::fs::write(container_dir.join("config.v2.json"), "not valid json {{{").unwrap();
        let meta2 = resolve_container_meta(&container_dir, "abcdef1234567890fedcba");
        assert_eq!(meta2.service, "abcdef123456");
    }

    // ── DoD 7: 적대적 입력 ───────────────────────────────────────────────────

    #[test]
    fn truncated_json_line_is_skipped_and_counted() {
        let counters = ContainerParseCounters::new();

        // 반쪽 JSON.
        assert!(build_container_log_line(
            r#"{"log":"partial line without closing"#,
            "id",
            "svc",
            None,
            &counters
        )
        .is_none());

        // log 필드 부재.
        assert!(build_container_log_line(
            r#"{"stream":"stdout","time":"2026-07-13T08:00:00Z"}"#,
            "id",
            "svc",
            None,
            &counters
        )
        .is_none());

        // time이 RFC3339가 아님.
        assert!(build_container_log_line(
            r#"{"log":"hi\n","stream":"stdout","time":"not-a-timestamp"}"#,
            "id",
            "svc",
            None,
            &counters
        )
        .is_none());

        assert_eq!(
            counters.invalid_json.load(Ordering::Relaxed),
            2,
            "반쪽 JSON + log 필드 부재"
        );
        assert_eq!(
            counters.invalid_time.load(Ordering::Relaxed),
            1,
            "time 형식 오류"
        );
    }

    #[test]
    fn nested_escaped_json_in_log_field_parses_without_panic() {
        let counters = ContainerParseCounters::new();
        // 애플리케이션 자신이 JSON을 로그로 남기는 흔한 케이스 — log 필드 값 자체가 이스케이프된
        // JSON 문자열이다.
        let raw = r#"{"log":"{\"nested\":\"value\",\"n\":1}\n","stream":"stdout","time":"2026-07-13T08:00:00Z"}"#;
        let line = build_container_log_line(raw, "id", "svc", None, &counters)
            .expect("유효한 JSON이므로 파싱에 성공해야 함");
        assert_eq!(line.message, r#"{"nested":"value","n":1}"#);
        assert_eq!(counters.invalid_json.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn oversized_log_field_parses_without_panic() {
        let counters = ContainerParseCounters::new();
        let huge = "x".repeat(1024 * 1024);
        let raw =
            format!(r#"{{"log":"{huge}\n","stream":"stdout","time":"2026-07-13T08:00:00Z"}}"#);
        let line = build_container_log_line(&raw, "id", "svc", None, &counters)
            .expect("1MB log 필드도 panic 없이 파싱되어야 함");
        assert_eq!(line.message.len(), 1024 * 1024);
    }

    #[test]
    fn invalid_utf8_in_log_field_does_not_panic() {
        // file.rs::drain_complete_lines가 raw 바이트를 String::from_utf8_lossy로 변환한 뒤
        // 파서를 부르므로, 이 파서가 실제로 받는 문자열은 이미 유효한 UTF-8이다(깨진 바이트는
        // U+FFFD로 치환됨). 여기서는 그 치환 결과를 흉내 내 파서가 patic 없이 처리하는지만
        // 확인한다.
        let counters = ContainerParseCounters::new();
        let raw = "{\"log\":\"bad byte here: \u{FFFD}\\n\",\"stream\":\"stdout\",\"time\":\"2026-07-13T08:00:00Z\"}";
        let line = build_container_log_line(raw, "id", "svc", None, &counters)
            .expect("치환 문자가 섞여도 파싱에 성공해야 함");
        assert!(line.message.contains('\u{FFFD}'));
    }

    /// 실제 파일에 유효하지 않은 UTF-8 바이트를 직접 써서, `FileTail` → 파서 전 구간까지
    /// end-to-end로 panic이 없는지 확인한다.
    #[test]
    fn invalid_utf8_bytes_in_real_file_do_not_panic_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = write_container_log(dir.path(), "id-utf8", &[]);
        write_config_v2(dir.path(), "id-utf8", "svc", None);

        let parse_counters = Arc::new(ContainerParseCounters::new());
        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tails: HashMap<PathBuf, FileTail> = HashMap::new();
        add_tail(&mut tails, path.clone(), "host-a", &parse_counters);
        for tail in tails.values_mut() {
            tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        }
        recv_all(&mut rx);

        // 유효하지 않은 UTF-8 바이트(0xFF)를 log 값 안에 직접 심는다.
        let mut bad_line = br#"{"log":"broken "#.to_vec();
        bad_line.push(0xFF);
        bad_line.extend_from_slice(br#" byte\n","stream":"stdout","time":"2026-07-13T08:00:00Z"}"#);
        bad_line.push(b'\n');
        append(&path, &bad_line);

        for tail in tails.values_mut() {
            tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        }
        // panic만 안 나면 충분 — 내용 자체는 lossy 변환된 채로 스킵되거나 통과할 수 있다.
        let _ = recv_all(&mut rx);
    }

    // ── 심볼릭 링크는 따라가지 않는다 ────────────────────────────────────────

    #[test]
    fn symlinked_log_file_is_not_followed() {
        let base = tempfile::tempdir().unwrap();
        let container_dir = base.path().join("linked-id");
        std::fs::create_dir_all(&container_dir).unwrap();

        // 실제 로그는 컨테이너 디렉토리 밖에 두고, 안에는 심링크만 둔다(경로 탈출 시나리오).
        let outside_target = base.path().join("outside.log");
        std::fs::write(&outside_target, padded_lines(&["should-not-be-followed"])).unwrap();
        let link_path = container_dir.join("linked-id-json.log");
        std::os::unix::fs::symlink(&outside_target, &link_path).unwrap();

        let found = discover_container_logs(base.path()).unwrap();
        assert!(
            found.is_empty(),
            "심볼릭 링크된 로그 파일은 발견 목록에 포함되면 안 됨: {found:?}"
        );
    }

    // ── 스트레스: 컨테이너 200개 × 다수 라인 — FD 누수 0, 완료 ───────────────

    /// FD 번호 하나가 가리키는 경로를 얻는다.
    ///
    /// Linux는 `/proc/self/fd/<N>`이 심볼릭 링크라 `read_link`로 풀린다.
    #[cfg(target_os = "linux")]
    fn path_of_fd(fd: i32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
    }

    /// macOS의 `/dev/fd/<N>`은 심볼릭 링크가 아니라 character device라 `read_link`가 실패한다 —
    /// `fcntl(fd, F_GETPATH, buf)`가 유일한 경로 획득 수단이다.
    #[cfg(target_os = "macos")]
    fn path_of_fd(fd: i32) -> Option<PathBuf> {
        use std::os::unix::ffi::OsStrExt;

        let mut buf = [0 as libc::c_char; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH의 계약은 "PATH_MAX 바이트 버퍼"이고 buf가 정확히 그 크기다. 이미 닫힌
        // FD 번호를 넘겨도 -1(EBADF)을 돌려줄 뿐 UB가 아니다.
        let rc = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
        if rc == -1 {
            return None;
        }
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
    }

    /// 이 프로세스가 열어 둔 FD 중 **`dir` 아래의 파일을 가리키는 것만** 모은다.
    ///
    /// 예전 구현은 `/dev/fd` 엔트리 수(= 프로세스 전역 FD 개수)를 측정 전후로 비교했는데,
    /// `cargo test`는 한 프로세스 안에서 테스트를 **스레드로 병렬 실행**한다 — 측정 구간 사이에
    /// 다른 테스트가 연 파일이 그대로 잡혀 flaky했다(`+5` 여유는 병렬 부하 앞에서 무의미하다).
    /// 우리 tempdir로 범위를 좁히면 다른 테스트의 FD는 각자 다른 tempdir을 가리키므로 자동으로
    /// 배제되고, 여유값 없이 **정확한 개수**를 단언할 수 있다.
    ///
    /// ★ 경로 비교 전에 양쪽을 canonicalize한다. macOS의 tempdir은 `/var/folders/...`인데
    /// `F_GETPATH`는 `/private/var/folders/...`를 돌려준다(`/var`가 `/private/var`의 심링크) —
    /// canonicalize를 빠뜨리면 매칭이 0건이 되어 "누수 없음"으로 조용히 통과하는 **공허한
    /// 테스트**가 된다.
    fn open_fds_under(dir: &Path) -> Vec<PathBuf> {
        let root = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());

        let fd_dir = if cfg!(target_os = "linux") {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        // FD 번호를 먼저 스냅샷으로 걷어낸다 — read_dir 이터레이터 자신이 들고 있는 FD를
        // 해석 대상에서 빼기 위함이다(닫힌 뒤엔 EBADF로 걸러진다).
        let fds: Vec<i32> = std::fs::read_dir(fd_dir)
            .unwrap_or_else(|e| panic!("{fd_dir} 열기 실패 — FD 검사가 불가능하다: {e}"))
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
            .collect();

        fds.into_iter()
            .filter_map(path_of_fd)
            .map(|p| p.canonicalize().unwrap_or(p))
            .filter(|p| p.starts_with(&root))
            .collect()
    }

    #[test]
    fn stress_200_containers_many_lines_completes_without_fd_leak() {
        let base = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let parse_counters = Arc::new(ContainerParseCounters::new());
        let (tx, mut rx) = mpsc::channel(1 << 16);
        let drop_counters = DropCounters::new();

        const N_CONTAINERS: usize = 200;
        const LINES_PER_CONTAINER: usize = 10;

        let mut tails: HashMap<PathBuf, FileTail> = HashMap::new();
        let mut paths = Vec::with_capacity(N_CONTAINERS);
        for i in 0..N_CONTAINERS {
            let id = format!("stress-{i:04}");
            write_config_v2(base.path(), &id, &format!("svc-{i}"), None);
            let path = write_container_log(base.path(), &id, &[]);
            paths.push(path);
        }

        let discovered = discover_container_logs(base.path()).unwrap();
        assert_eq!(discovered.len(), N_CONTAINERS);
        for path in discovered {
            add_tail(&mut tails, path, "host-a", &parse_counters);
        }
        assert_eq!(tails.len(), N_CONTAINERS);

        // 최초 확립(백필 없음).
        for tail in tails.values_mut() {
            tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        }
        recv_all(&mut rx);

        // ★ 공허한 테스트 방지 — 여기서 0이 나오면 FD→경로 해석이 실패한 것이지 "누수가 없는"
        // 게 아니다. 아래의 "≤ N" / "= 0" 단언은 0건 매칭에서도 전부 통과해 버리므로, 헬퍼가
        // 실제로 값을 잡아낸다는 것을 먼저 증명한다.
        let established = open_fds_under(base.path());
        assert_eq!(
            established.len(),
            N_CONTAINERS,
            "확립 tick 후 tempdir을 가리키는 열린 FD가 컨테이너당 정확히 1개여야 함 \
             (0이면 FD→경로 해석 실패 = 아무것도 검증하지 못하는 공허한 테스트다)"
        );

        for path in &paths {
            let mut buf = Vec::new();
            for line_no in 0..LINES_PER_CONTAINER {
                buf.extend_from_slice(
                    docker_line(&format!("line-{line_no}"), "stdout", "2026-07-13T08:00:00Z")
                        .as_bytes(),
                );
            }
            append(path, &buf);
        }

        for tail in tails.values_mut() {
            tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        }
        let got = recv_all(&mut rx);
        assert_eq!(
            got.len(),
            N_CONTAINERS * LINES_PER_CONTAINER,
            "모든 컨테이너의 모든 라인이 유실 없이 처리되어야 함"
        );
        assert_eq!(
            drop_counters.by_channel_full.load(Ordering::Relaxed),
            0,
            "채널 용량을 넉넉히 뒀으므로 드롭이 없어야 함"
        );

        // 로테이션/재오픈 경로를 다 돈 뒤에도 tail당 열린 핸들은 여전히 1개뿐이어야 한다.
        // 전역 개수가 아니라 우리 tempdir을 가리키는 FD만 세므로 병렬로 도는 다른 테스트의
        // 파일은 애초에 후보에 들어오지 않는다 — 여유값이 필요 없다.
        let after_tick = open_fds_under(base.path());
        assert!(
            after_tick.len() <= N_CONTAINERS,
            "FD 누수 — 컨테이너당 최대 1개(≤{N_CONTAINERS})여야 하는데 {}개가 열려 있다: {:?}",
            after_tick.len(),
            &after_tick[..after_tick.len().min(5)]
        );

        // 핸들이 실제로 닫히는지 — 지금까지 아무도 검증하지 않던 부분이다.
        drop(tails);
        let after_drop = open_fds_under(base.path());
        assert!(
            after_drop.is_empty(),
            "FileTail을 drop한 뒤에도 로그 파일을 가리키는 FD가 남아 있다(핸들 누수): {after_drop:?}"
        );
    }

    // ── 2단계 필터링 배선(엔드투엔드): 파싱 실패 라인이 외부로 새지 않음 ─────

    #[tokio::test(start_paused = true)]
    async fn parse_error_lines_never_reach_external_channel_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        write_config_v2(dir.path(), "e2e-id", "svc", None);
        let path = write_container_log(dir.path(), "e2e-id", &[]);

        let (_cp_dir, checkpoint) = test_checkpoint();
        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = Arc::new(DropCounters::new());
        let parse_counters = Arc::new(ContainerParseCounters::new());
        let (sd_tx, sd_rx) = watch::channel(false);

        let cfg = ContainerCollectorConfig {
            containers_dir: dir.path().to_path_buf(),
            host: "host-a".to_string(),
        };
        let handle = tokio::spawn(run_container_collector(
            cfg,
            tx,
            checkpoint,
            drop_counters,
            parse_counters.clone(),
            sd_rx,
        ));

        async fn settle() {
            for _ in 0..200 {
                tokio::task::yield_now().await;
            }
        }
        settle().await; // 최초 확립(백필 없음)
        tokio::time::advance(TICK_INTERVAL).await;
        settle().await;
        recv_all(&mut rx);

        // 정상 라인 하나 + 깨진 라인 하나를 같이 붙인다.
        let mut buf = Vec::new();
        buf.extend_from_slice(
            docker_line("good-line", "stdout", "2026-07-13T08:00:00Z").as_bytes(),
        );
        buf.extend_from_slice(b"{\"log\":\"broken without close\n");
        append(&path, &buf);

        tokio::time::advance(TICK_INTERVAL).await;
        settle().await;

        let got = recv_all(&mut rx);
        assert_eq!(
            got.len(),
            1,
            "깨진 라인은 외부 채널에 도달하면 안 됨: {got:?}"
        );
        assert_eq!(got[0].message, "good-line");
        assert!(
            parse_counters.invalid_json.load(Ordering::Relaxed) >= 1,
            "깨진 라인은 카운터로만 남아야 함"
        );

        sd_tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "shutdown 후 정상 종료해야 함");
        result.unwrap().unwrap().unwrap();
    }
}
