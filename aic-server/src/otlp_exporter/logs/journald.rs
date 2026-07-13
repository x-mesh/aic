//! journald 로그 수집기 — `journalctl` spawn 방식 (RFC-006 §4.1, t8).
//!
//! FFI(`sd-journal`) 대신 `journalctl` 프로세스를 spawn한다. FFI는 배포 환경별 libsystemd 링크
//! 문제를 떠안는다 — `connections.rs`가 이미 `aic snapshot inventory --json`을 spawn하는 선례를
//! 남겼다(RFC §4.1). 다만 그 선례를 그대로 베끼면 안 된다: `connections.rs`는
//! `wait_with_output()`으로 자식 종료를 기다리는 one-shot이고, `--follow`는 **끝나지 않는다** —
//! 여기는 `Child`를 계속 들고 있다가 shutdown 시 명시적으로 죽이는 long-running 패턴이 필요하다.
//!
//! ## journalctl spawn 계약
//!
//! - **`--cursor`가 아니라 `--after-cursor`.** `--cursor`는 그 엔트리를 포함해서 재시작마다 1건씩
//!   중복시킨다.
//! - `--follow` 단독은 마지막 몇 줄만 뱉는다 — 커서가 없으면 **`--since=now`를 명시**해야
//!   RFC의 "백필 안 함"(§4.5)이 성립한다.
//! - `--show-cursor`가 있어야 출력에서 `__CURSOR`를 받는다.
//! - **stderr를 반드시 별도로 소비한다.** piped로 열어놓고 안 읽으면 파이프 버퍼(리눅스 64KiB)가
//!   차는 순간 journalctl이 `write(2)`에서 블록하고 stdout도 함께 멈춘다. `tokio::select!`에서
//!   stdout/stderr를 동시에 읽는다. stderr 라인은 `target: "aic_server::otlp_exporter::logs"`로만
//!   흘린다 — 이 target이 [`super::self_layer::LOOP_TARGETS`](super::self_layer)의
//!   `aic_server::otlp_exporter` prefix에 걸려, self-log capture layer가 이 라인을 다시 로그
//!   파이프라인으로 먹이는 되먹임 루프를 원천 차단한다.
//! - **자식은 죽는다.** `lines.next_line()`이 `Ok(None)`(EOF)이면 journalctl이 죽은 것이다.
//!   즉시 재spawn하면 크래시 루프가 되므로 [`super::super::backoff::Backoff`](super::super::backoff)
//!   (1s→60s+jitter)로 간격을 벌린 뒤 저장된 커서로 이어붙여 재spawn한다.
//! - shutdown 정리 순서는 **`start_kill()` → 리더 drop → `wait().await`** 고정이다. 순서를
//!   뒤집어 `wait()`부터 부르면 데드락이다 — 자식이 꽉 찬 파이프에 블록돼 있고 우리는 읽기를
//!   멈춘 상태에서 서로 기다리게 된다. `kill_on_drop(true)`는 panic/abort 대비 안전망으로만
//!   켠다(tokio 문서: 정상 경로에서 destructor의 kill은 "best-effort", 좀비 방지를 보장 안 함) —
//!   정상 shutdown은 항상 위 순서를 명시적으로 밟는다.
//! - **`--boot`는 쓰지 않는다.** systemd 242에서 `--boot=all` 도입, 250부터 `--follow`가 `--boot`를
//!   암묵 적용, 258에서 다시 override 가능 — `current_boot_only` 류 옵션을 넣으면 systemd 버전마다
//!   동작이 갈린다. v1은 이 옵션 자체를 만들지 않는 편이 안전하다(버전 파싱 분기보다 안전한
//!   기본값 — 필요해지면 `journalctl --version`을 파싱해 분기).
//!
//! ## 필드 매핑
//!
//! - `service` = `_SYSTEMD_UNIT` → 없으면 `SYSLOG_IDENTIFIER` → 없으면 `"unknown"`
//! - `severity` = `PRIORITY`(0..7): `<=3` ERROR / `4` WARN / `5..=6` INFO / `7` DEBUG
//! - `ts` = `__REALTIME_TIMESTAMP`(마이크로초 문자열)
//! - `record_id` = `checkpoint::record_id(Some(cursor), host, &line)` — `__CURSOR`가 자연키
//! - `message` = `redact(MESSAGE).0`. journald의 non-UTF8 필드는 JSON에서 문자열이 아니라
//!   **바이트 배열**(`"MESSAGE": [72, 101, ...]`)로 온다 — lossy 변환으로 처리한다.
//!
//! ## 플랫폼
//!
//! Linux 전용. macOS에서는 이 수집기를 아예 띄우지 않는다(no-op 스텁) — journald 자체가 없는
//! 플랫폼이라 "지원 안 함"이 제품 결정이지, `ntp.rs`처럼 syscall이 없어서가 아니다. 그래도
//! `ntp.rs`와 동일한 원칙을 따른다: 파싱 로직은 순수 함수로 분리해 macOS에서도 테스트하고,
//! `#[cfg]`는 spawn 경계에만 둔다.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::{mpsc, watch};

use aic_common::redaction::redact;
use aic_common::LogLine;

#[cfg(target_os = "linux")]
use super::super::backoff::Backoff;
use super::checkpoint::CheckpointStore;
use super::DropCounters;

/// 이 소스의 체크포인트 키 (`CheckpointStore::save/load`에 그대로 넘긴다). Linux 전용 spawn
/// 루프(및 그 테스트)에서만 쓰인다 — macOS non-test 빌드에선 사용처가 없어 dead_code로 잡힌다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CHECKPOINT_KEY: &str = "journald";

/// journalctl 바이너리 기본 이름 — PATH에서 찾는다.
const DEFAULT_JOURNALCTL_BIN: &str = "journalctl";

/// journald 수집기 실행 설정. Linux/비-Linux 양쪽에서 동일한 모양으로 존재해 호출부가 플랫폼
/// 분기 없이 항상 이 struct를 만들어 넘길 수 있게 한다(실제 spawn 동작만 플랫폼별로 갈린다).
#[derive(Debug, Clone)]
pub struct JournaldCollectorConfig {
    /// journalctl 바이너리 경로/이름. 기본은 PATH의 `"journalctl"`. 테스트에서 가짜 바이너리로
    /// 교체해 spawn 계약(EOF→backoff, 바이너리 부재, shutdown kill)을 실제 systemd 없이 검증한다.
    pub journalctl_bin: PathBuf,
    /// `record_id`의 자연키 해시에 필요한 호스트 식별자.
    pub host: String,
}

impl Default for JournaldCollectorConfig {
    fn default() -> Self {
        Self {
            journalctl_bin: PathBuf::from(DEFAULT_JOURNALCTL_BIN),
            host: "unknown".to_string(),
        }
    }
}

// ── 순수 함수 (양쪽 OS에서 테스트) ─────────────────────────────────────────
//
// `run_once`(Linux 전용 spawn 루프)의 유일한 non-test 호출부다. macOS 빌드에선 그 호출부가
// cfg로 빠지므로 non-test 빌드에서 dead_code로 잡힌다 — ntp.rs의 `interpret`/`TIME_ERROR`와
// 동일한 이유로 `cfg_attr`를 붙인다.

/// journald `PRIORITY`(0..7, syslog severity)를 우리 4단계 severity로 매핑한다.
/// 파싱 실패/범위 밖 값은 INFO로 폴백한다(관측 유실보다 과다 수집이 안전).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn severity_from_priority(priority: &str) -> &'static str {
    match priority.trim().parse::<u8>() {
        Ok(0..=3) => "ERROR",
        Ok(4) => "WARN",
        Ok(5..=6) => "INFO",
        Ok(7) => "DEBUG",
        _ => "INFO",
    }
}

/// `journalctl` 인자 목록. 커서가 있으면 `--after-cursor=<c>`로 이어붙이고(`--cursor`는 그
/// 엔트리를 중복 포함하므로 절대 쓰지 않는다), 없으면 `--since=now`로 시작해 백필하지 않는다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn build_journalctl_args(cursor: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--follow".to_string(),
        "--all".to_string(),
        "--show-cursor".to_string(),
        "--output=json".to_string(),
        "--no-pager".to_string(),
    ];
    match cursor {
        Some(c) => args.push(format!("--after-cursor={c}")),
        None => args.push("--since=now".to_string()),
    }
    args
}

/// `parse_journal_json`이 뽑아낸 결과. `cursor`는 체크포인트 저장 및 다음 재spawn의
/// `--after-cursor` 인자로 쓰인다 — `line.record_id`에서 역산하지 않고 별도로 들고 다닌다.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ParsedJournalLine {
    pub line: LogLine,
    pub cursor: Option<String>,
}

/// `journalctl --output=json`이 뱉는 한 줄(JSON object)을 [`LogLine`]으로 정규화한다. 파싱
/// 불가능한(유효 JSON이 아니거나 object가 아닌) 라인은 `None` — 호출부는 그 줄을 건너뛴다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_journal_json(raw: &str, host: &str) -> Option<ParsedJournalLine> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let obj = value.as_object()?;

    let cursor = extract_str(obj, "__CURSOR");
    let service = extract_str(obj, "_SYSTEMD_UNIT")
        .or_else(|| extract_str(obj, "SYSLOG_IDENTIFIER"))
        .unwrap_or_else(|| "unknown".to_string());
    let priority = extract_str(obj, "PRIORITY").unwrap_or_default();
    let severity = severity_from_priority(&priority);
    let ts = extract_str(obj, "__REALTIME_TIMESTAMP")
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(chrono::DateTime::from_timestamp_micros)
        .unwrap_or_else(chrono::Utc::now);

    let raw_message = extract_message(obj);
    let (message, _report) = redact(&raw_message);

    let mut attrs = std::collections::BTreeMap::new();
    if let Some(pid) = extract_str(obj, "_PID") {
        attrs.insert("pid".to_string(), pid);
    }
    if let Some(unit) = extract_str(obj, "_SYSTEMD_UNIT") {
        attrs.insert("unit".to_string(), unit);
    }
    if let Some(facility) = extract_str(obj, "SYSLOG_FACILITY") {
        attrs.insert("syslog_facility".to_string(), facility);
    }

    let mut line = LogLine {
        source: "journald".to_string(),
        service,
        severity: severity.to_string(),
        message,
        attrs,
        ts,
        record_id: String::new(),
    };
    line.record_id = super::checkpoint::record_id(cursor.as_deref(), host, &line);

    Some(ParsedJournalLine { line, cursor })
}

/// journald JSON 필드는 UTF-8이면 문자열로 온다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn extract_str(obj: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// `MESSAGE` 필드 전용 추출. non-UTF8이면 journald가 문자열 대신 바이트 배열(JSON 정수 배열,
/// `"MESSAGE": [72, 101, 108, ...]`)로 내보낸다 — 그 경우 lossy 변환한다(OTel collector의
/// `convert_message_bytes` 옵션이 존재하는 이유와 동일한 함정).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn extract_message(obj: &serde_json::Map<String, Value>) -> String {
    match obj.get("MESSAGE") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => {
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|v| v.as_u64())
                .map(|n| n as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    }
}

// ── Linux 전용 spawn 루프 ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_spawn {
    use super::*;
    use std::process::Stdio;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncBufReadExt, BufReader};

    /// `run_once` 한 번의 결과. 바깥 루프(`run_journald_collector`)가 이걸 보고 backoff/재spawn/
    /// 조기 종료를 결정한다.
    enum RunOutcome {
        /// shutdown 신호로 이 라운드에서 정상 종료(자식은 이미 kill+reap 완료).
        ShutdownRequested,
        /// stdout EOF(자식이 죽음, 정상/비정상 불문). backoff 후 재spawn 대상.
        ChildExited,
        /// 자식 spawn 자체가 실패(바이너리 부재 등). 이 수집기를 완전히 비활성화한다.
        SpawnFailed(std::io::Error),
    }

    /// backoff 상태 + 마지막 커서를 들고 다니며 `journalctl`을 반복 spawn하는 수집기.
    struct JournaldCollector {
        bin: PathBuf,
        host: String,
        checkpoints: Arc<CheckpointStore>,
        backoff: Backoff,
        cursor: Option<String>,
    }

    impl JournaldCollector {
        fn new(bin: PathBuf, host: String, checkpoints: Arc<CheckpointStore>) -> Self {
            let cursor = checkpoints.load(CHECKPOINT_KEY);
            Self {
                bin,
                host,
                checkpoints,
                backoff: Backoff::new(),
                cursor,
            }
        }

        /// 자식 하나를 spawn해 stdout/stderr를 동시에 소비하다가, EOF 또는 shutdown 신호에
        /// 도달하면 반환한다.
        async fn run_once(
            &mut self,
            tx: &mpsc::Sender<LogLine>,
            drop_counters: &DropCounters,
            shutdown: &mut watch::Receiver<bool>,
        ) -> RunOutcome {
            let args = build_journalctl_args(self.cursor.as_deref());
            let mut cmd = tokio::process::Command::new(&self.bin);
            cmd.args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                // panic/abort 대비 안전망으로만 — 정상 shutdown은 아래에서 명시적으로
                // start_kill()→drop→wait()를 밟는다(모듈 doc 참고).
                .kill_on_drop(true);

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => return RunOutcome::SpawnFailed(e),
            };

            let stdout = child
                .stdout
                .take()
                .expect("stdout은 Stdio::piped()로 열었다");
            let stderr = child
                .stderr
                .take()
                .expect("stderr은 Stdio::piped()로 열었다");
            let mut stdout_lines = BufReader::new(stdout).lines();
            let mut stderr_lines = BufReader::new(stderr).lines();
            let mut stdout_done = false;
            let mut stderr_done = false;

            loop {
                if stdout_done {
                    break;
                }
                tokio::select! {
                    line = stdout_lines.next_line(), if !stdout_done => {
                        match line {
                            Ok(Some(raw)) => {
                                if let Some(parsed) = parse_journal_json(&raw, &self.host) {
                                    if let Some(cursor) = parsed.cursor {
                                        self.cursor = Some(cursor.clone());
                                        if let Err(e) = self.checkpoints.save(CHECKPOINT_KEY, &cursor) {
                                            tracing::warn!(
                                                target: "aic_server::otlp_exporter::logs",
                                                error = %e,
                                                "journald 체크포인트 저장 실패"
                                            );
                                        }
                                    }
                                    if tx.try_send(parsed.line).is_err() {
                                        drop_counters.by_channel_full.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            Ok(None) => stdout_done = true,
                            Err(e) => {
                                tracing::warn!(
                                    target: "aic_server::otlp_exporter::logs",
                                    error = %e,
                                    "journalctl stdout 읽기 실패 — 재spawn"
                                );
                                stdout_done = true;
                            }
                        }
                    }
                    line = stderr_lines.next_line(), if !stderr_done => {
                        match line {
                            // target을 명시해 self-log capture layer의 LOOP_TARGETS
                            // (`aic_server::otlp_exporter` prefix)에 걸리게 한다 — 안 그러면
                            // journalctl stderr 라인이 다시 로그 채널로 먹혀 되먹임 루프가 된다.
                            Ok(Some(raw)) => {
                                tracing::warn!(
                                    target: "aic_server::otlp_exporter::logs",
                                    line = %raw,
                                    "journalctl stderr"
                                );
                            }
                            Ok(None) => stderr_done = true,
                            Err(_) => stderr_done = true,
                        }
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            // ★ 순서 고정 ★ start_kill() → 리더 drop → wait().await.
                            // 뒤집으면 데드락이다 — 자식이 꽉 찬 파이프에 블록된 채 우리는
                            // 읽기를 멈춘 상태로 서로 기다리게 된다.
                            let _ = child.start_kill();
                            drop(stdout_lines);
                            drop(stderr_lines);
                            let _ = child.wait().await;
                            return RunOutcome::ShutdownRequested;
                        }
                    }
                }
            }

            // stdout EOF — 자식이 죽었다(정상/크래시 불문). 좀비 방지를 위해 reap한다.
            drop(stderr_lines);
            let _ = child.wait().await;
            RunOutcome::ChildExited
        }
    }

    /// journald 수집기를 실행한다. `shutdown`이 true가 되면 진행 중인 라운드를 정리하고
    /// graceful하게 종료한다.
    ///
    /// **자식 spawn 실패는 에러를 위로 던지지 않는다** — 명확한 경고를 남기고 이 수집기만
    /// 비활성화한다(`Ok(())` 반환). 호출부가 `?`로 전파했다면 aicd 전체가 죽었을 것이다.
    pub async fn run_journald_collector(
        cfg: JournaldCollectorConfig,
        tx: mpsc::Sender<LogLine>,
        drop_counters: Arc<DropCounters>,
        checkpoints: Arc<CheckpointStore>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let mut collector = JournaldCollector::new(cfg.journalctl_bin, cfg.host, checkpoints);

        tracing::info!(bin = %collector.bin.display(), "journald 수집기 시작");

        loop {
            if *shutdown.borrow() {
                break;
            }
            match collector.run_once(&tx, &drop_counters, &mut shutdown).await {
                RunOutcome::ShutdownRequested => break,
                RunOutcome::ChildExited => {
                    collector.backoff.on_failure();
                    tokio::select! {
                        _ = wait_for_backoff_ready(&collector.backoff) => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
                RunOutcome::SpawnFailed(e) if is_permanent_spawn_error(&e) => {
                    tracing::warn!(
                        error = %e,
                        bin = %collector.bin.display(),
                        "journalctl spawn 실패(영구) — journald 수집기 비활성화(aicd는 계속 실행)"
                    );
                    return Ok(());
                }
                RunOutcome::SpawnFailed(e) => {
                    // 일시적 실패(fd 고갈, fork 실패 등)로 수집기를 영구히 죽이면, 호스트가
                    // 잠깐 자원 부족에 빠진 것만으로 journald 로그가 재시작 전까지 조용히
                    // 끊긴다 — fd 고갈은 정확히 로그를 봐야 하는 순간에 일어난다. backoff로
                    // 물러섰다가 다시 붙는다.
                    tracing::warn!(
                        error = %e,
                        bin = %collector.bin.display(),
                        "journalctl spawn 실패(일시적) — backoff 후 재시도"
                    );
                    collector.backoff.on_failure();
                    tokio::select! {
                        _ = wait_for_backoff_ready(&collector.backoff) => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        tracing::info!("journald 수집기 종료");
        Ok(())
    }

    /// spawn 실패가 **영구적**인가 — 재시도해도 같은 결과인가.
    ///
    /// 영구: 바이너리 부재(`NotFound`), 실행 권한 없음(`PermissionDenied`).
    /// 일시적: fd 고갈(`EMFILE`/`ENFILE`), fork 실패(`EAGAIN`/`ENOMEM`), `ETXTBSY` 등 — 이걸
    /// 영구로 취급하면 호스트가 잠깐 자원 부족에 빠진 것만으로 로그 수집이 재시작 전까지
    /// 조용히 끊긴다.
    fn is_permanent_spawn_error(e: &std::io::Error) -> bool {
        matches!(
            e.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        )
    }

    /// `Backoff`는 남은 시간을 노출하지 않으므로(t8 계약 — `ready()` bool만 공개) 짧은 간격으로
    /// polling한다. paused clock 테스트에서도 `tokio::time::advance`가 이 sleep들을 그대로
    /// 앞당기므로 정확히 동작한다.
    async fn wait_for_backoff_ready(backoff: &Backoff) {
        while !backoff.ready() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        fn test_checkpoints(dir: &std::path::Path) -> Arc<CheckpointStore> {
            Arc::new(CheckpointStore::open(dir.join("checkpoints")).unwrap())
        }

        /// 실행될 때마다 `marker_path`에 한 줄을 append하고 즉시 종료(EOF)하는 셸 스크립트를
        /// 만든다 — "즉시 EOF를 뱉는 가짜 바이너리"로 crash-loop 시나리오를 결정적으로 재현한다.
        fn fake_binary_recording_invocations(
            dir: &std::path::Path,
            marker_path: &std::path::Path,
        ) -> PathBuf {
            let script_path = dir.join("fake-journalctl-eof");
            let mut f = std::fs::File::create(&script_path).unwrap();
            writeln!(f, "#!/bin/sh").unwrap();
            writeln!(f, "echo run >> {}", marker_path.display()).unwrap();
            drop(f);
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
            script_path
        }

        fn count_lines(path: &std::path::Path) -> usize {
            std::fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .count()
        }

        /// 마커 파일의 줄 수가 `n` 이상이 될 때까지 기다린다(실시간 상한).
        async fn wait_for_lines(marker: &std::path::Path, n: usize, what: &str) -> usize {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let c = count_lines(marker);
                if c >= n {
                    return c;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "{what}: {n}줄을 기다렸지만 10초 안에 {c}줄에 그침"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        /// 자식 EOF → 즉시 재spawn이 아니라 backoff만큼 물러섰다 재spawn하는지(크래시 루프 방지).
        ///
        /// **`start_paused = true`(가상 시계)를 쓰지 않는다.** 자식은 진짜 프로세스이고 마커
        /// 쓰기도 진짜 파일 I/O라, 가상 시계로는 그 완료를 기다릴 수 없다. 둘을 섞으면 이런 일이
        /// 벌어진다: 마커 1줄이 보이자마자 `advance()`를 불러도 collector는 아직 EOF를 못 읽어
        /// `backoff.on_failure()`를 호출하기 전이다 → backoff 기준 시각이 뒤로 밀려 우리가 앞당긴
        /// 만큼으로는 절대 깨어나지 않는다. 게다가 조건 폴링을 `yield_now`로 돌리면 런타임이
        /// idle이 되지 않아 auto-advance마저 멈춘다.
        ///
        /// backoff 기본이 1s(+jitter ≤20%)라 실시간으로 돌려도 1.5초면 끝난다 — 그 값을 치르고
        /// 결정성을 산다.
        #[tokio::test]
        async fn child_eof_triggers_backoff_respawn() {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("invocations.log");
            std::fs::write(&marker, "").unwrap();
            let bin = fake_binary_recording_invocations(dir.path(), &marker);

            let checkpoints = test_checkpoints(dir.path());
            let (tx, _rx) = mpsc::channel(16);
            let drop_counters = Arc::new(DropCounters::new());
            let (_sd_tx, sd_rx) = watch::channel(false);

            let cfg = JournaldCollectorConfig {
                journalctl_bin: bin,
                host: "test-host".to_string(),
            };
            let handle = tokio::spawn(run_journald_collector(
                cfg,
                tx,
                drop_counters,
                checkpoints,
                sd_rx,
            ));

            let first_count = wait_for_lines(&marker, 1, "최초 spawn").await;

            // backoff 윈도(1s+) 안에서는 재spawn되면 안 된다 — 크래시 루프 방지의 핵심.
            // 300ms는 backoff 하한(1s)에 한참 못 미치므로, 여기서 늘어나면 즉시 재spawn 버그다.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                count_lines(&marker),
                first_count,
                "backoff 윈도 안에서는 재spawn되면 안 됨(크래시 루프 방지)"
            );

            // 1s + jitter(≤20%)가 지나면 재spawn되어야 한다. 상한은 wait_for_lines가 쥐고 있다.
            wait_for_lines(&marker, first_count + 1, "backoff 경과 후 재spawn").await;

            handle.abort();
        }

        #[tokio::test]
        async fn journalctl_binary_missing_disables_collector_but_daemon_lives() {
            let dir = tempfile::tempdir().unwrap();
            let checkpoints = test_checkpoints(dir.path());
            let (tx, _rx) = mpsc::channel(16);
            let drop_counters = Arc::new(DropCounters::new());
            let (_sd_tx, sd_rx) = watch::channel(false);

            let cfg = JournaldCollectorConfig {
                journalctl_bin: PathBuf::from("/nonexistent/aic-test-journalctl-xyz"),
                host: "test-host".to_string(),
            };

            let result = run_journald_collector(cfg, tx, drop_counters, checkpoints, sd_rx).await;
            assert!(
                result.is_ok(),
                "바이너리 부재는 수집기만 비활성화해야 함 — Err를 위로 던지면 aicd가 죽는다"
            );
        }

        /// spawn 실패를 **전부** 영구로 취급하면, 호스트가 잠깐 fd를 다 쓴 것만으로 journald
        /// 로그가 aicd 재시작 전까지 조용히 끊긴다 — fd 고갈은 정확히 로그를 봐야 하는 순간에
        /// 일어난다. 영구(`NotFound`/`PermissionDenied`)와 일시적(그 외)을 가르는 판정을 고정한다.
        #[test]
        fn only_notfound_and_permission_denied_are_permanent_spawn_errors() {
            use std::io::{Error, ErrorKind};

            for kind in [ErrorKind::NotFound, ErrorKind::PermissionDenied] {
                assert!(
                    is_permanent_spawn_error(&Error::from(kind)),
                    "{kind:?}는 재시도해도 같은 결과 — 비활성화가 맞다"
                );
            }

            // fd 고갈(EMFILE/ENFILE), fork 실패(EAGAIN/ENOMEM), ETXTBSY — 전부 일시적이다.
            for raw in [
                libc::EMFILE,
                libc::ENFILE,
                libc::EAGAIN,
                libc::ENOMEM,
                libc::ETXTBSY,
            ] {
                let e = Error::from_raw_os_error(raw);
                assert!(
                    !is_permanent_spawn_error(&e),
                    "errno {raw}({e})는 일시적 — backoff 후 재시도해야 한다"
                );
            }
        }

        #[tokio::test]
        async fn shutdown_kills_child_and_reaps() {
            let dir = tempfile::tempdir().unwrap();
            let script_path = dir.path().join("fake-journalctl-hang");
            std::fs::write(&script_path, "#!/bin/sh\nsleep 100\n").unwrap();
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();

            let checkpoints = test_checkpoints(dir.path());
            let (tx, _rx) = mpsc::channel(16);
            let drop_counters = Arc::new(DropCounters::new());
            let (sd_tx, sd_rx) = watch::channel(false);

            let cfg = JournaldCollectorConfig {
                journalctl_bin: script_path,
                host: "test-host".to_string(),
            };
            let handle = tokio::spawn(run_journald_collector(
                cfg,
                tx,
                drop_counters,
                checkpoints,
                sd_rx,
            ));

            // 자식이 확실히 뜬 뒤 shutdown을 보낸다(real time — paused clock을 쓰지 않는다,
            // 실제 프로세스 kill/reap을 실시간으로 검증해야 한다).
            tokio::time::sleep(Duration::from_millis(200)).await;
            sd_tx.send(true).unwrap();

            let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
            assert!(
                result.is_ok(),
                "shutdown 후 5초 내에 끝나야 함 — sleep 100까지 블록되면 kill+reap이 안 된 것"
            );
            result.unwrap().unwrap().unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_spawn::run_journald_collector;

/// macOS 등 비-Linux 플랫폼에선 journald 수집기를 아예 띄우지 않는다(모듈 doc — "Linux 전용").
/// 호출부가 플랫폼 분기 없이 항상 이 함수를 부를 수 있게 no-op 스텁을 유지한다.
#[cfg(not(target_os = "linux"))]
pub async fn run_journald_collector(
    _cfg: JournaldCollectorConfig,
    _tx: mpsc::Sender<LogLine>,
    _drop_counters: Arc<DropCounters>,
    _checkpoints: Arc<CheckpointStore>,
    _shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tracing::info!("journald 수집기는 Linux 전용 — 이 플랫폼에서는 비활성(no-op)");
    Ok(())
}

// ── 순수 파서 유닛 테스트 (양쪽 OS에서 실행) ───────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_journal_json_maps_priority_to_severity() {
        let cases = [
            ("0", "ERROR"),
            ("1", "ERROR"),
            ("2", "ERROR"),
            ("3", "ERROR"),
            ("4", "WARN"),
            ("5", "INFO"),
            ("6", "INFO"),
            ("7", "DEBUG"),
        ];
        for (priority, expected) in cases {
            let raw = format!(
                r#"{{"__CURSOR":"c1","_SYSTEMD_UNIT":"nginx.service","PRIORITY":"{priority}","MESSAGE":"hi","__REALTIME_TIMESTAMP":"1000000"}}"#
            );
            let parsed = parse_journal_json(&raw, "host-a").expect("valid json");
            assert_eq!(
                parsed.line.severity, expected,
                "priority {priority} should map to {expected}"
            );
        }
    }

    #[test]
    fn parse_journal_json_handles_byte_array_message() {
        // "Hel" = [72, 101, 108]
        let raw = r#"{"__CURSOR":"c1","_SYSTEMD_UNIT":"nginx.service","PRIORITY":"6","MESSAGE":[72,101,108],"__REALTIME_TIMESTAMP":"1000000"}"#;
        let parsed = parse_journal_json(raw, "host-a").expect("valid json");
        assert_eq!(parsed.line.message, "Hel");
    }

    #[test]
    fn service_falls_back_to_syslog_identifier_then_unknown() {
        let with_unit = r#"{"__CURSOR":"c1","_SYSTEMD_UNIT":"nginx.service","SYSLOG_IDENTIFIER":"nginx","PRIORITY":"6","MESSAGE":"m","__REALTIME_TIMESTAMP":"1"}"#;
        assert_eq!(
            parse_journal_json(with_unit, "h").unwrap().line.service,
            "nginx.service"
        );

        let without_unit = r#"{"__CURSOR":"c1","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","MESSAGE":"m","__REALTIME_TIMESTAMP":"1"}"#;
        assert_eq!(
            parse_journal_json(without_unit, "h").unwrap().line.service,
            "sshd"
        );

        let neither =
            r#"{"__CURSOR":"c1","PRIORITY":"6","MESSAGE":"m","__REALTIME_TIMESTAMP":"1"}"#;
        assert_eq!(
            parse_journal_json(neither, "h").unwrap().line.service,
            "unknown"
        );
    }

    #[test]
    fn args_use_after_cursor_not_cursor() {
        let args = build_journalctl_args(Some("s=abc;i=1"));
        assert!(
            args.iter().any(|a| a == "--after-cursor=s=abc;i=1"),
            "args={args:?}"
        );
        assert!(
            !args
                .iter()
                .any(|a| a == "--cursor" || a.starts_with("--cursor=")),
            "--cursor(포함 재전송)가 들어가면 안 됨: args={args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "--since=now"),
            "커서가 있으면 --since=now를 쓰면 안 됨: args={args:?}"
        );
    }

    #[test]
    fn args_use_since_now_when_no_checkpoint() {
        let args = build_journalctl_args(None);
        assert!(args.iter().any(|a| a == "--since=now"), "args={args:?}");
        assert!(
            !args.iter().any(|a| a.starts_with("--after-cursor")),
            "커서가 없으면 --after-cursor가 들어가면 안 됨: args={args:?}"
        );
    }

    #[test]
    fn message_is_redacted() {
        let raw = r#"{"__CURSOR":"c1","_SYSTEMD_UNIT":"app.service","PRIORITY":"3","MESSAGE":"contact user@example.com now","__REALTIME_TIMESTAMP":"1"}"#;
        let parsed = parse_journal_json(raw, "host-a").expect("valid json");
        assert!(
            parsed.line.message.contains("[REDACTED:email]"),
            "message={}",
            parsed.line.message
        );
        assert!(!parsed.line.message.contains("user@example.com"));
    }

    #[test]
    fn record_id_uses_cursor_as_natural_key() {
        let raw = r#"{"__CURSOR":"s=abc123;i=456","_SYSTEMD_UNIT":"app.service","PRIORITY":"6","MESSAGE":"hello","__REALTIME_TIMESTAMP":"1"}"#;
        let parsed = parse_journal_json(raw, "host-a").expect("valid json");
        assert_eq!(parsed.cursor.as_deref(), Some("s=abc123;i=456"));
        assert_eq!(parsed.line.record_id, "log:s=abc123;i=456");
    }
}

#[cfg(not(target_os = "linux"))]
#[cfg(test)]
mod macos_tests {
    use super::*;

    #[tokio::test]
    async fn journald_collector_is_noop_on_macos() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoints = Arc::new(CheckpointStore::open(dir.path().join("checkpoints")).unwrap());
        let (tx, _rx) = mpsc::channel(16);
        let drop_counters = Arc::new(DropCounters::new());
        let (_sd_tx, sd_rx) = watch::channel(false);
        let cfg = JournaldCollectorConfig {
            journalctl_bin: PathBuf::from("journalctl"),
            host: "test-host".to_string(),
        };

        let result = run_journald_collector(cfg, tx, drop_counters, checkpoints, sd_rx).await;
        assert!(result.is_ok(), "macOS에서는 no-op으로 즉시 성공해야 함");
    }
}
