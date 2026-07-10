//! Crit onset 직전 터미널 명령 상관관계 증거 (RCA 강화 ② — "무엇이 방금 실행됐나").
//!
//! 자원 스냅샷은 "무엇이 이상한가"만 답한다. RCA의 1순위 질문 — "무엇이 **바뀌어서**
//! 이상해졌나" — 는 onset 직전에 터미널에서 실행된 명령이 가장 직접적인 후보다. aic는
//! `aicd`가 전 세션의 명령 기록(ring)을 이미 들고 있으므로, Crit onset 시점에
//! `ListSessions` + `GetRecentCommandsForSession`으로 window 내 명령을 모아
//! RCA 인시던트 증거(Timeline)로 붙인다.
//!
//! 원칙:
//! - **best-effort**: aicd 미실행·소켓 없음·window 내 기록 없음 → `None` (인시던트 생성은 계속).
//! - **결정적 코어**: 네트워크 fetch(`collect_*`)와 순수 포맷터(`format_evidence`)를 분리해
//!   포맷터는 IPC 없이 단위 테스트한다.
//! - redaction은 `rca::append_evidence`가 저장 직전에 일괄 적용하므로 여기선 하지 않는다.
//! - 소켓 경로는 `AIC_AICD_SOCKET` env로 override 가능 — 테스트 격리(HOME 격리로는
//!   `/tmp/aic-{uid}` 소켓이 안 가려짐)와 비표준 배치 디버깅용.

use aic_common::{CommandRecord, SessionInfo};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// onset 직전 몇 초의 명령을 증거로 볼지. 너무 길면 무관한 명령이 노이즈로 붙고,
/// 너무 짧으면 빌드처럼 오래 걸리는 원인 명령의 완료 시각을 놓친다.
pub(crate) const WINDOW_SECS: i64 = 15 * 60;

/// 세션당 aicd에 요청할 record 수 — 서버 per-session ring 상한(64)과 동일하게 전량 요청.
const FETCH_COUNT: usize = 64;

/// 증거 본문에 담을 세션당 최대 명령 수(onset에 가까운 최신 우선). evidence 파일 비대 방지.
const MAX_COMMANDS_PER_SESSION: usize = 20;

/// 명령 한 줄의 최대 문자 수 — heredoc/한 줄 스크립트가 증거를 잡아먹지 않게.
const MAX_COMMAND_CHARS: usize = 200;

/// auto-RCA가 쓰는 진입점: 기본 aicd 소켓(또는 `AIC_AICD_SOCKET`)에서 수집한다.
///
/// 내부에서 current-thread 런타임을 만들어 block하므로 **blocking 스레드 전용**이다
/// (호출부 `capture_incident`는 chat_tui의 `spawn_blocking`에서 돈다). async 컨텍스트에서
/// 부르면 tokio가 panic한다.
pub(crate) fn collect(window_end: DateTime<Utc>) -> Option<String> {
    collect_with_socket(&aicd_socket(), window_end)
}

/// 소켓 경로 주입 변형(테스트 seam). 소켓 파일이 없으면 런타임 생성 전에 early-out.
pub(crate) fn collect_with_socket(sock: &Path, window_end: DateTime<Utc>) -> Option<String> {
    if !sock.exists() {
        return None;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(collect_async(sock.to_path_buf(), window_end))
}

/// `AIC_AICD_SOCKET` override 반영한 aicd control 소켓 경로.
fn aicd_socket() -> PathBuf {
    std::env::var_os("AIC_AICD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(aic_common::aicd_socket_path)
}

async fn collect_async(sock: PathBuf, window_end: DateTime<Utc>) -> Option<String> {
    let client = crate::uds_client::UdsClient::new(sock);
    let sessions = client.list_sessions().await.ok()?;
    let mut gathered: Vec<(SessionInfo, Vec<CommandRecord>)> = Vec::with_capacity(sessions.len());
    for info in sessions {
        // 세션 하나 조회 실패는 그 세션만 비운다 — 다른 세션의 증거는 살린다.
        let records = client
            .get_recent_commands_for_session(&info.id, FETCH_COUNT)
            .await
            .unwrap_or_default();
        gathered.push((info, records));
    }
    format_evidence(&gathered, window_end)
}

/// 순수 포맷터: window 내 record만 남기고 세션별 섹션 텍스트를 만든다.
/// window 내 record가 하나도 없으면 `None` — 증거 없는 Timeline 이벤트를 만들지 않는다.
pub(crate) fn format_evidence(
    sessions: &[(SessionInfo, Vec<CommandRecord>)],
    window_end: DateTime<Utc>,
) -> Option<String> {
    let window_start = window_end - chrono::Duration::seconds(WINDOW_SECS);
    // 세션 id 순 정렬 — 출력을 결정적으로.
    let mut ordered: Vec<&(SessionInfo, Vec<CommandRecord>)> = sessions.iter().collect();
    ordered.sort_by(|a, b| a.0.id.cmp(&b.0.id));

    let mut sections: Vec<String> = Vec::new();
    for (info, records) in ordered {
        let in_window: Vec<&CommandRecord> = records
            .iter()
            .filter(|r| r.timestamp >= window_start && r.timestamp <= window_end)
            .collect();
        if in_window.is_empty() {
            continue;
        }
        // onset에 가까운 최신 명령이 원인 후보로 더 중요 — 초과분은 앞(과거)에서 자른다.
        let omitted = in_window.len().saturating_sub(MAX_COMMANDS_PER_SESSION);
        let shown = &in_window[omitted..];

        let mut header = format!("### session {}", info.id);
        if let Some(label) = &info.label {
            header.push_str(&format!(" (label={label})"));
        }
        if let Some(cwd) = &info.cwd {
            header.push_str(&format!(" cwd={}", cwd.display()));
        }
        let mut lines = vec![header];
        if omitted > 0 {
            lines.push(format!("(window 내 이전 명령 {omitted}건 생략)"));
        }
        for r in shown {
            let cmd = r
                .command
                .as_deref()
                .map(sanitize_command)
                .unwrap_or_else(|| "(unknown command)".to_string());
            lines.push(format!(
                "{} exit={} {}",
                r.timestamp.format("%H:%M:%S"),
                r.exit_code,
                cmd
            ));
        }
        sections.push(lines.join("\n"));
    }
    if sections.is_empty() {
        return None;
    }

    let header = format!(
        "terminal commands within {}m before Crit onset (window {} → {} UTC), all aicd sessions.\n\
         onset에 시간적으로 가까운 명령이 유력한 변경/원인 후보. exit≠0 = 실패한 명령.",
        WINDOW_SECS / 60,
        window_start.format("%H:%M:%S"),
        window_end.format("%H:%M:%S"),
    );
    Some(format!("{header}\n\n{}", sections.join("\n\n")))
}

/// 명령 텍스트를 증거 한 줄로: 개행/탭을 공백으로 눌러 펴고 char 경계 안전하게 자른다.
fn sanitize_command(cmd: &str) -> String {
    let flat: String = cmd
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect();
    super::auto_rca::truncate_chars(&flat, MAX_COMMAND_CHARS)
}

/// 간이 mock aicd — `ListSessions`/`GetRecentCommandsForSession`만 응답하는 std 스레드 서버.
/// terminal_evidence와 auto_rca 양쪽 테스트가 공유한다. 연결 수는 `1 + sessions.len()`
/// (list 1회 + 세션당 1회)로 고정이며, 클라이언트가 중간에 끊겨도 스레드는 조용히 남는다
/// (테스트는 join하지 않는다 — 프로세스 종료로 정리).
#[cfg(test)]
pub(crate) fn spawn_mock_aicd(
    sock: &Path,
    sessions: Vec<SessionInfo>,
    records_by_session: std::collections::HashMap<String, Vec<CommandRecord>>,
) -> std::thread::JoinHandle<()> {
    use std::io::{Read, Write};
    let listener = std::os::unix::net::UnixListener::bind(sock).expect("bind mock aicd");
    let total_conns = 1 + sessions.len();
    std::thread::spawn(move || {
        for _ in 0..total_conns {
            let (mut stream, _) = match listener.accept() {
                Ok(x) => x,
                Err(_) => return,
            };
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_err() {
                continue;
            }
            let n = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; n];
            if stream.read_exact(&mut payload).is_err() {
                continue;
            }
            let req: aic_common::IpcRequest = match serde_json::from_slice(&payload) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let resp = match req {
                aic_common::IpcRequest::ListSessions => {
                    aic_common::IpcResponse::Sessions(sessions.clone())
                }
                aic_common::IpcRequest::GetRecentCommandsForSession { id, .. } => {
                    aic_common::IpcResponse::CommandRecords(
                        records_by_session.get(&id).cloned().unwrap_or_default(),
                    )
                }
                _ => aic_common::IpcResponse::Error {
                    message: "mock aicd: unexpected request".to_string(),
                },
            };
            let body = serde_json::to_vec(&resp).expect("serialize mock response");
            let _ = stream.write_all(&aic_common::encode_frame(&body));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::SessionState;
    use std::collections::HashMap;

    fn ts(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn session(id: &str, label: Option<&str>, cwd: Option<&str>) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            pid: 100,
            state: SessionState::Attached,
            created_at: ts("2026-07-10T11:00:00Z"),
            last_seen_at: None,
            last_command_at: None,
            attached_tty: None,
            shell: None,
            cwd: cwd.map(PathBuf::from),
            label: label.map(|s| s.to_string()),
        }
    }

    fn record(command: Option<&str>, exit_code: i32, at: &str) -> CommandRecord {
        CommandRecord {
            command: command.map(|s| s.to_string()),
            exit_code,
            timestamp: ts(at),
            ..Default::default()
        }
    }

    const ONSET: &str = "2026-07-10T12:00:00Z";

    #[test]
    fn format_filters_to_window_and_skips_empty_sessions() {
        let sessions = vec![
            (
                session("aaaa0001", Some("main"), Some("/work/app")),
                vec![
                    record(Some("git pull"), 0, "2026-07-10T11:30:00Z"), // window 밖(-30m)
                    record(Some("docker build -t app ."), 0, "2026-07-10T11:50:00Z"),
                    record(Some("./stress.sh"), 137, "2026-07-10T11:59:00Z"),
                ],
            ),
            // window 내 record가 없는 세션은 섹션 자체가 빠진다.
            (
                session("bbbb0002", None, None),
                vec![record(Some("ls"), 0, "2026-07-10T09:00:00Z")],
            ),
        ];
        let body = format_evidence(&sessions, ts(ONSET)).expect("Some");
        assert!(body.contains("### session aaaa0001 (label=main) cwd=/work/app"));
        assert!(body.contains("11:50:00 exit=0 docker build -t app ."));
        assert!(body.contains("11:59:00 exit=137 ./stress.sh"));
        assert!(!body.contains("git pull"), "window 밖 record는 제외");
        assert!(!body.contains("bbbb0002"), "빈 세션은 섹션 생략");
        assert!(body.contains("window 11:45:00 → 12:00:00 UTC"));
    }

    #[test]
    fn format_caps_per_session_and_keeps_newest() {
        // window 내 25건 → 최신 20건만, 과거 5건은 생략 note.
        let records: Vec<CommandRecord> = (0..25)
            .map(|i| {
                record(
                    Some(&format!("cmd{i}")),
                    0,
                    &format!("2026-07-10T11:50:{:02}Z", i * 2),
                )
            })
            .collect();
        let sessions = vec![(session("cccc0003", None, None), records)];
        let body = format_evidence(&sessions, ts(ONSET)).expect("Some");
        assert!(body.contains("(window 내 이전 명령 5건 생략)"));
        assert!(!body.contains("cmd4 "), "가장 오래된 5건(cmd0..4)은 생략");
        assert!(body.contains("cmd5"));
        assert!(body.contains("cmd24"));
    }

    #[test]
    fn format_sanitizes_multiline_and_unknown_commands() {
        let long = "x".repeat(300);
        let sessions = vec![(
            session("dddd0004", None, None),
            vec![
                record(Some("echo a\necho b"), 0, "2026-07-10T11:55:00Z"),
                record(None, 1, "2026-07-10T11:56:00Z"),
                record(Some(&long), 0, "2026-07-10T11:57:00Z"),
            ],
        )];
        let body = format_evidence(&sessions, ts(ONSET)).expect("Some");
        assert!(body.contains("echo a echo b"), "개행은 공백으로 평탄화");
        assert!(body.contains("exit=1 (unknown command)"));
        // 300자 명령은 200자 + '…'로 잘린다. ("exit=0"의 'x'가 섞이지 않게 명령 부분만 센다)
        let truncated_line = body.lines().find(|l| l.contains("11:57:00")).unwrap();
        assert!(truncated_line.ends_with('…'));
        let cmd_part = truncated_line.split("exit=0 ").nth(1).unwrap();
        assert_eq!(cmd_part.chars().filter(|c| *c == 'x').count(), 200);
    }

    #[test]
    fn format_returns_none_when_nothing_in_window() {
        let sessions = vec![(
            session("eeee0005", None, None),
            vec![record(Some("old"), 0, "2026-07-10T08:00:00Z")],
        )];
        assert!(format_evidence(&sessions, ts(ONSET)).is_none());
        assert!(format_evidence(&[], ts(ONSET)).is_none());
    }

    #[test]
    fn collect_returns_none_when_socket_missing() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("no-aicd.sock");
        assert!(collect_with_socket(&sock, ts(ONSET)).is_none());
    }

    #[test]
    fn collect_fetches_and_formats_from_mock_aicd() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("aicd.sock");
        let mut records = HashMap::new();
        records.insert(
            "aaaa0001".to_string(),
            vec![record(
                Some("cargo build --release"),
                0,
                "2026-07-10T11:58:00Z",
            )],
        );
        // record 없는 세션도 목록엔 있다 — fetch는 성공하되 섹션에선 빠져야 한다.
        records.insert("bbbb0002".to_string(), Vec::new());
        let _mock = spawn_mock_aicd(
            &sock,
            vec![
                session("aaaa0001", None, Some("/work/app")),
                session("bbbb0002", None, None),
            ],
            records,
        );

        let body = collect_with_socket(&sock, ts(ONSET)).expect("mock aicd 증거 수집");
        assert!(body.contains("11:58:00 exit=0 cargo build --release"));
        assert!(!body.contains("bbbb0002"));
    }
}
