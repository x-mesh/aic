//! `aic history` read-only CLI (Phase 3.1, Task 1.8).
//!
//! 이 모듈은 **`aicd` Control_UDS만** 조회하는 신규 read-only CLI를 구현한다.
//! Phase 3.1의 Dual_Write(로컬 RingBuffer + aicd `CommandRecordStore`)가 실제로
//! 동작하는지 사용자가 직접 확인하는 용도다 — 즉, aicd에 record가 쌓였는지
//! 돌려봄으로써 dual-write health를 관측한다.
//!
//! 기존 `handle_history`(main.rs)는 세션 로컬 소켓을 조회했는데, R3.6은 `aic history`가
//! "Phase 3.1에서 도입되는 신규 read-only CLI로서 Control_UDS를 통해 `aicd`
//! CommandRecordStore만 조회한다"라고 규정한다. 본 모듈이 그 의미를 가진다.
//!
//! Session 결정 우선순위 (R3.6):
//! 1. `--session <id>` (명시 인자)
//! 2. env `AIC_SESSION_ID`
//! 3. `aicd` registry의 가장 최근 세션 (`UdsClient::list_sessions`)
//!
//! 해당 세션이 없으면 user-friendly 에러로 종료한다.

use crate::uds_client::UdsClient;
use aic_common::{aicd_socket_path, CommandRecord, SessionInfo};
use chrono::{DateTime, Utc};

// ── ANSI 색상 상수 (main.rs와 일치) ────────────────────────────────
const COL_RESET: &str = "\x1b[0m";
const COL_BOLD: &str = "\x1b[1m";
const COL_DIM: &str = "\x1b[90m";
const COL_CYAN: &str = "\x1b[36m";
const COL_GREEN: &str = "\x1b[32m";
const COL_RED: &str = "\x1b[31m";

/// `aic history` 구현. 실패 시 stderr에 에러 메시지를 출력하고 non-zero로 종료한다.
///
/// - `session`: `--session <id>` 사용자 인자
/// - `limit`: 표시할 record 최대 수 (기본 20)
/// - `failed`: non-zero exit만 표시 (backwards-compat 플래그)
/// - `json`: JSON 출력
pub async fn run(session: Option<String>, limit: usize, failed: bool, json: bool) {
    let sock = aicd_socket_path();
    let client = UdsClient::new(sock.clone());

    // Phase 3.1: aicd가 떠 있지 않으면 의미 있는 record 조회가 불가능하다.
    // ping을 먼저 찍어 user-friendly 에러를 내려준다.
    match client.ping().await {
        Ok(true) => {}
        _ => {
            eprintln!(
                "{COL_RED}✗{COL_RESET} aicd가 실행 중이지 않습니다 ({}).\n  시작: {COL_BOLD}aic daemon start{COL_RESET}",
                sock.display()
            );
            std::process::exit(1);
        }
    }

    // Session 결정: --session > AIC_SESSION_ID > aicd registry 최신
    let session_id = match resolve_session_id(&client, session.as_deref()).await {
        Ok(id) => id,
        Err(msg) => {
            eprintln!("{COL_RED}✗{COL_RESET} {msg}");
            std::process::exit(1);
        }
    };

    // aicd CommandRecordStore 조회.
    let records = match client
        .get_recent_commands_for_session(&session_id, limit)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} aicd record 조회 실패 (session={session_id}): {e}");
            std::process::exit(1);
        }
    };

    let filtered: Vec<CommandRecord> = if failed {
        records.into_iter().filter(|r| r.exit_code != 0).collect()
    } else {
        records
    };

    if json {
        match serde_json::to_string_pretty(&filtered) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("JSON 직렬화 실패: {e}");
                std::process::exit(2);
            }
        }
        return;
    }

    if filtered.is_empty() {
        println!("{COL_DIM}저장된 record 없음 (session={session_id}){COL_RESET}");
        return;
    }

    // 세션 label(사용자 tag)은 best-effort로 registry에서 찾는다.
    let label = client.list_sessions().await.ok().and_then(|sessions| {
        sessions
            .into_iter()
            .find(|s| s.id == session_id)
            .and_then(|s| s.label)
    });

    print_table(&session_id, label.as_deref(), &filtered);
}

/// 우선순위에 따라 session_id를 결정한다.
/// - 1. explicit argument
/// - 2. `AIC_SESSION_ID` env
/// - 3. aicd registry의 가장 최근 세션 (`last_seen_at` desc, tie-break `created_at` desc)
pub(crate) async fn resolve_session_id(
    client: &UdsClient,
    explicit: Option<&str>,
) -> Result<String, String> {
    if let Some(id) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(id.to_string());
    }
    if let Ok(env_id) = std::env::var("AIC_SESSION_ID") {
        let trimmed = env_id.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    // aicd registry fallback — 가장 최근 세션.
    let mut sessions = client
        .list_sessions()
        .await
        .map_err(|e| format!("aicd 세션 목록 조회 실패: {e}"))?;
    if sessions.is_empty() {
        return Err(
            "활성 세션을 찾을 수 없습니다. aic-session을 먼저 실행하거나 --session <id>로 지정하세요.".to_string(),
        );
    }
    pick_most_recent(&mut sessions);
    Ok(sessions
        .into_iter()
        .next()
        .expect("non-empty after sort")
        .id)
}

/// `last_seen_at` 내림차순(없으면 `created_at`) 정렬 후, 첫 번째가 가장 최근.
pub(crate) fn pick_most_recent(sessions: &mut [SessionInfo]) {
    sessions.sort_by(|a, b| {
        let ka = session_recency_key(a);
        let kb = session_recency_key(b);
        kb.cmp(&ka)
    });
}

fn session_recency_key(info: &SessionInfo) -> DateTime<Utc> {
    info.last_seen_at.unwrap_or(info.created_at)
}

/// 표 형식으로 record를 출력한다 (main.rs의 기존 포맷과 유사).
fn print_table(session_id: &str, label: Option<&str>, records: &[CommandRecord]) {
    let label_part = label.map(|l| format!(" [{l}]")).unwrap_or_default();
    println!(
        "{COL_BOLD}aic history{COL_RESET} {COL_DIM}(session={session_id}{label_part}, {} record){COL_RESET}",
        records.len()
    );
    for rec in records {
        let id = record_id_short(&rec.id);
        let when = format_rfc3339(rec.timestamp);
        let exit = format_exit_code(rec.exit_code);
        let src = source_quality_label(rec);
        let dur = duration_label(rec);
        let cmd = rec.command.as_deref().unwrap_or("(no command)");
        let cmd = truncate_command(cmd, 70);
        let cwd_part = rec
            .cwd
            .as_deref()
            .map(|c| format!("  {COL_DIM}({c}){COL_RESET}"))
            .unwrap_or_default();
        println!(
            "  {COL_CYAN}{id:<8}{COL_RESET}  {exit}  {COL_DIM}{when:<20}{COL_RESET}  {COL_DIM}{src:<10}{COL_RESET}  {COL_DIM}{dur:>6}{COL_RESET}  {cmd}{cwd_part}"
        );
    }
}

/// `source/quality` 결합 라벨 — 예: `pty/full`, `hook/meta`, `run/trunc`.
fn source_quality_label(rec: &CommandRecord) -> String {
    format!(
        "{}/{}",
        rec.capture_mode.short_label(),
        rec.capture_quality.short_label()
    )
}

fn duration_label(rec: &CommandRecord) -> String {
    rec.duration_ms
        .map(aic_common::format_duration_ms)
        .unwrap_or_else(|| "-".to_string())
}

fn record_id_short(id: &str) -> String {
    let max = id.len().min(8);
    id[..max].to_string()
}

fn format_rfc3339(ts: DateTime<Utc>) -> String {
    // 초 단위 RFC3339 UTC. 테스트 안정성을 위해 Z 접미.
    ts.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn format_exit_code(code: i32) -> String {
    if code == 0 {
        format!("{COL_GREEN}✓{COL_RESET}")
    } else {
        format!("{COL_RED}✗{code:<3}{COL_RESET}")
    }
}

fn truncate_command(cmd: &str, max: usize) -> String {
    if cmd.chars().count() <= max {
        return cmd.to_string();
    }
    let mut s: String = cmd.chars().take(max.saturating_sub(1)).collect();
    s.push('…');
    s
}

// 테스트용으로 노출되는 table 렌더러(raw, no color) — snapshot 비교에 사용된다.
#[cfg(test)]
pub(crate) fn render_table_plain(session_id: &str, records: &[CommandRecord]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "aic history (session={session_id}, {} record)\n",
        records.len()
    ));
    for rec in records {
        let id = record_id_short(&rec.id);
        let when = format_rfc3339(rec.timestamp);
        let exit_str = if rec.exit_code == 0 {
            "✓".to_string()
        } else {
            format!("✗{}", rec.exit_code)
        };
        let src = source_quality_label(rec);
        let dur = duration_label(rec);
        let cmd = rec.command.as_deref().unwrap_or("(no command)");
        let cmd = truncate_command(cmd, 70);
        let cwd_part = rec
            .cwd
            .as_deref()
            .map(|c| format!("  ({c})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {id:<8}  {exit_str:<4}  {when:<20}  {src:<10}  {dur:>6}  {cmd}{cwd_part}\n"
        ));
    }
    out
}

#[cfg(test)]
pub(crate) fn render_json(records: &[CommandRecord]) -> String {
    serde_json::to_string_pretty(records).expect("serialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::{
        encode_frame, CaptureMode, CaptureQuality, CommandRecord, IpcRequest, IpcResponse,
        SessionInfo, SessionState,
    };
    use chrono::{TimeZone, Utc};
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// AIC_SESSION_ID 환경변수를 건드리는 테스트는 프로세스-글로벌 상태라
    /// 병렬 실행 시 서로 간섭한다. 모듈 단위 Mutex로 직렬화한다.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn ts(ms: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_millis_opt(ms).unwrap()
    }

    fn sample_session(id: &str, created_ms: i64, seen_ms: Option<i64>) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            pid: 4242,
            state: SessionState::Attached,
            created_at: ts(created_ms),
            last_seen_at: seen_ms.map(ts),
            last_command_at: None,
            attached_tty: None,
            shell: None,
            cwd: None,
            label: None,
        }
    }

    fn sample_record(id: &str, command: &str, exit_code: i32, ts_ms: i64) -> CommandRecord {
        CommandRecord {
            id: id.to_string(),
            command: Some(command.to_string()),
            exit_code,
            output_lines: vec![format!("out-{command}")],
            timestamp: ts(ts_ms),
            capture_mode: CaptureMode::Pty,
            capture_quality: CaptureQuality::FullOutput,
            output_metadata: None,
            cwd: None,
            duration_ms: None,
        }
    }

    // ── pick_most_recent 정렬 로직 ──────────────────────────────────

    #[test]
    fn pick_most_recent_prefers_last_seen_at() {
        let mut sessions = vec![
            sample_session("aaaaaaaa", 1_000, Some(10_000)),
            sample_session("bbbbbbbb", 2_000, Some(20_000)),
            sample_session("cccccccc", 3_000, Some(5_000)),
        ];
        pick_most_recent(&mut sessions);
        assert_eq!(sessions[0].id, "bbbbbbbb");
    }

    #[test]
    fn pick_most_recent_falls_back_to_created_at_when_seen_missing() {
        let mut sessions = vec![
            sample_session("aaaaaaaa", 1_000, None),
            sample_session("bbbbbbbb", 2_000, None),
            sample_session("cccccccc", 3_000, None),
        ];
        pick_most_recent(&mut sessions);
        assert_eq!(sessions[0].id, "cccccccc");
    }

    #[test]
    fn pick_most_recent_mixed_seen_and_created() {
        // last_seen이 있는 쪽이 더 크면 그게 우선.
        let mut sessions = vec![
            sample_session("aaaaaaaa", 1_000, Some(50_000)),
            sample_session("bbbbbbbb", 100_000, None), // created만 큼
        ];
        pick_most_recent(&mut sessions);
        assert_eq!(sessions[0].id, "bbbbbbbb");
    }

    // ── JSON 포맷 ────────────────────────────────────────────────

    #[test]
    fn render_json_pretty_preserves_records() {
        let records = vec![
            sample_record("1111111111111111", "ls", 0, 1_000),
            sample_record("2222222222222222", "fail", 2, 2_000),
        ];
        let out = render_json(&records);
        // JSON이 직렬화 가능해야 하고, command와 exit_code가 포함되어야 한다.
        assert!(out.contains("\"ls\""));
        assert!(out.contains("\"fail\""));
        assert!(out.contains("\"exit_code\": 2"));
        // 2개 record가 들어 있는지 확인.
        let back: Vec<CommandRecord> = serde_json::from_str(&out).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].id, "1111111111111111");
        assert_eq!(back[1].exit_code, 2);
    }

    // ── 표(table) 포맷 스냅샷 ────────────────────────────────────

    #[test]
    fn render_table_plain_empty_still_shows_header() {
        let out = render_table_plain("deadbeef", &[]);
        assert_eq!(out, "aic history (session=deadbeef, 0 record)\n");
    }

    #[test]
    fn render_table_plain_single_record_snapshot() {
        let records = vec![sample_record("1111222233334444", "ls -la", 0, 1_000)];
        let out = render_table_plain("abcd1234", &records);
        let expected = "\
aic history (session=abcd1234, 1 record)
  11112222  ✓     1970-01-01T00:00:01Z  pty/full         -  ls -la
";
        assert_eq!(out, expected);
    }

    #[test]
    fn render_table_plain_shows_quality_source_duration_cwd() {
        let mut rec = sample_record("aaaabbbbccccdddd", "cargo build", 101, 2_000);
        rec.capture_mode = CaptureMode::Hook;
        rec.capture_quality = CaptureQuality::MetadataOnly;
        rec.cwd = Some("/tmp/proj".to_string());
        rec.duration_ms = Some(1_300);
        let out = render_table_plain("sess0001", &[rec]);
        assert!(out.contains("hook/meta"), "source/quality label: {out}");
        assert!(out.contains("1.3s"), "duration label: {out}");
        assert!(out.contains("(/tmp/proj)"), "cwd suffix: {out}");
    }

    #[test]
    fn render_table_plain_failed_record_shows_exit_code() {
        let records = vec![sample_record("aaaabbbbccccdddd", "cargo build", 101, 2_000)];
        let out = render_table_plain("sess0001", &records);
        // exit_code가 101로 출력되는지 확인
        assert!(out.contains("✗101"));
        assert!(out.contains("cargo build"));
    }

    #[test]
    fn render_table_plain_truncates_long_command() {
        let long_cmd = "a".repeat(200);
        let records = vec![sample_record("deadbeefdeadbeef", &long_cmd, 0, 3_000)];
        let out = render_table_plain("s", &records);
        // 표시 길이는 70자 이하 + 생략기호
        assert!(out.contains("…"));
        assert!(!out.contains(&"a".repeat(200)));
    }

    // ── format_rfc3339 안정성 ─────────────────────────────────────

    #[test]
    fn format_rfc3339_is_stable_utc_seconds() {
        let s = format_rfc3339(ts(1_700_000_000_000));
        // 초 단위 Z 접미 포맷
        assert_eq!(s, "2023-11-14T22:13:20Z");
    }

    // ── resolve_session_id — priority chain via mock aicd ─────────────

    /// 주어진 응답 목록을 순서대로 돌려주는 간이 mock aicd socket server를
    /// 띄우고 (socket_path, TempDir)을 반환한다.
    async fn mock_aicd(responses: Vec<IpcResponse>) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aicd.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        tokio::spawn(async move {
            for resp in responses {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                // request frame 수신 후 버림
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    continue;
                }
                let payload_len = u32::from_be_bytes(len_buf) as usize;
                let mut payload = vec![0u8; payload_len];
                if stream.read_exact(&mut payload).await.is_err() {
                    continue;
                }
                let _req: IpcRequest = match serde_json::from_slice(&payload) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let body = serde_json::to_vec(&resp).unwrap();
                let frame = encode_frame(&body);
                let _ = stream.write_all(&frame).await;
            }
        });
        (sock_path, dir)
    }

    fn ts_dt(ms: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_millis_opt(ms).unwrap()
    }

    fn sample_info_full(id: &str, created_ms: i64, seen_ms: Option<i64>) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            pid: 4242,
            state: SessionState::Attached,
            created_at: ts_dt(created_ms),
            last_seen_at: seen_ms.map(ts_dt),
            last_command_at: None,
            attached_tty: None,
            shell: None,
            cwd: None,
            label: None,
        }
    }

    #[tokio::test]
    async fn resolve_session_id_uses_explicit_when_provided() {
        let _g = env_guard();
        // aicd에 연결되지 않아도 explicit이면 즉시 반환되어야 한다.
        let client = UdsClient::new(PathBuf::from("/tmp/nonexistent-aic-hist-test.sock"));
        let id = resolve_session_id(&client, Some("  deadbeef  "))
            .await
            .unwrap();
        assert_eq!(id, "deadbeef");
    }

    #[tokio::test]
    async fn resolve_session_id_uses_env_when_explicit_missing() {
        let _g = env_guard();
        // SAFETY: guard 하에 프로세스 env를 독점.
        std::env::set_var("AIC_SESSION_ID", "envsess1");
        let client = UdsClient::new(PathBuf::from("/tmp/nonexistent-aic-hist-test2.sock"));
        let id = resolve_session_id(&client, None).await.unwrap();
        assert_eq!(id, "envsess1");
        std::env::remove_var("AIC_SESSION_ID");
    }

    #[tokio::test]
    async fn resolve_session_id_falls_back_to_registry_most_recent() {
        let _g = env_guard();
        // env 방해가 없도록 확실히 제거.
        std::env::remove_var("AIC_SESSION_ID");
        let sessions = vec![
            sample_info_full("oldsess1", 1_000, Some(10_000)),
            sample_info_full("newsess2", 2_000, Some(50_000)),
            sample_info_full("midsess3", 3_000, Some(30_000)),
        ];
        let (sock, _dir) = mock_aicd(vec![IpcResponse::Sessions(sessions)]).await;
        let client = UdsClient::new(sock);
        let id = resolve_session_id(&client, None).await.unwrap();
        assert_eq!(id, "newsess2");
    }

    #[tokio::test]
    async fn resolve_session_id_errors_when_no_sessions_available() {
        let _g = env_guard();
        std::env::remove_var("AIC_SESSION_ID");
        let (sock, _dir) = mock_aicd(vec![IpcResponse::Sessions(vec![])]).await;
        let client = UdsClient::new(sock);
        let err = resolve_session_id(&client, None).await.unwrap_err();
        assert!(err.contains("활성 세션"), "actual: {err}");
    }

    #[tokio::test]
    async fn resolve_session_id_propagates_list_sessions_error() {
        let _g = env_guard();
        std::env::remove_var("AIC_SESSION_ID");
        let (sock, _dir) = mock_aicd(vec![IpcResponse::Error {
            message: "registry unavailable".to_string(),
        }])
        .await;
        let client = UdsClient::new(sock);
        let err = resolve_session_id(&client, None).await.unwrap_err();
        assert!(err.contains("세션 목록 조회 실패"), "actual: {err}");
    }
}
