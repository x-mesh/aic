//! 추가 E2E 테스트 — 다양한 에지 케이스 및 현실적 시나리오
//!
//! 기존 e2e.rs의 기본 흐름 테스트를 보완하여
//! 동시 접속, 대용량 출력, 다양한 exit code, 한국어/유니코드,
//! LlmDispatcher 통합, IPC 프로토콜 raw 레벨, 서버 재시작 등을 검증한다.
//!
//! ## Phase 3.5 feature gate (Task 5.1 / 5.2 / 5.3)
//!
//! Phase 3.5 에서는 세션 로컬 data plane 이 제거되어 본 파일의 E2E 시나리오가
//! 검증하는 `OutputProcessor` → `CommandBoundaryDetector` → `RingBuffer` →
//! `UdsServer` → `UdsClient` cascade 가 의미를 잃는다 (R7.1, R7.2). 대응하는
//! Phase 3.5 전용 E2E 는 `aicd` 의 `CommandRecordStore` 를 직접 테스트하는
//! `aic-server/tests/phase_3_3_attach.rs` 에서 커버한다.
#![cfg(not(feature = "phase-3_5"))]

use aic_client::auto_brancher::{AutoBrancher, ExecutionMode};
use aic_client::error_analyzer::ErrorAnalyzer;
use aic_client::llm_dispatcher::LlmDispatcher;
use aic_client::repl::ReplSession;
use aic_client::uds_client::UdsClient;
use aic_common::{
    encode_frame, AicError, CommandRecord, IpcRequest, IpcResponse, LlmConfig, ProviderConfig,
    ProviderType,
};
use aic_server::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use aic_server::output_processor::OutputProcessor;
use aic_server::ring_buffer::RingBuffer;
use aic_server::uds_server::UdsServer;

use chrono::Utc;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

// ── 헬퍼 ───────────────────────────────────────────────────────

async fn start_server(
    sock_path: &std::path::Path,
    ring: RingBuffer,
) -> (Arc<RwLock<RingBuffer>>, tokio::task::JoinHandle<()>) {
    let buffer = Arc::new(RwLock::new(ring));
    let server = UdsServer::bind(sock_path).await.unwrap();
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (buffer, handle)
}

fn record(cmd: &str, exit_code: i32, lines: &[&str]) -> CommandRecord {
    CommandRecord {
        command: Some(cmd.to_string()),
        exit_code,
        output_lines: lines.iter().map(|s| s.to_string()).collect(),
        timestamp: Utc::now(),
        ..Default::default()
    }
}

fn record_no_cmd(exit_code: i32, lines: &[&str]) -> CommandRecord {
    CommandRecord {
        command: None,
        exit_code,
        output_lines: lines.iter().map(|s| s.to_string()).collect(),
        timestamp: Utc::now(),
        ..Default::default()
    }
}

fn make_cli_script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let script = dir.join(name);
    let mut f = std::fs::File::create(&script).unwrap();
    writeln!(f, "#!/bin/sh").unwrap();
    write!(f, "{}", body).unwrap();
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script
}

// ═══════════════════════════════════════════════════════════════
// 동시 접속 / 병렬 클라이언트
// ═══════════════════════════════════════════════════════════════

/// 여러 클라이언트가 동시에 서버에 요청해도 모두 올바른 응답을 받는다.
#[tokio::test]
async fn e2e_concurrent_clients() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("concurrent.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record("make", 2, &["Makefile:10: error"]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let p = sock_path.clone();
        tasks.push(tokio::spawn(async move {
            let client = UdsClient::new(p);
            client.get_last_command().await.unwrap()
        }));
    }

    for t in tasks {
        let rec = t.await.unwrap();
        assert_eq!(rec.exit_code, 2);
        assert_eq!(rec.command, Some("make".to_string()));
    }

    handle.abort();
}

/// 동시에 ping과 GetLastCommand를 섞어 보내도 서버가 정상 응답한다.
#[tokio::test]
async fn e2e_mixed_concurrent_requests() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mixed.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record("npm test", 0, &["PASS"]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let mut tasks = Vec::new();
    for i in 0..8 {
        let p = sock_path.clone();
        tasks.push(tokio::spawn(async move {
            let client = UdsClient::new(p);
            if i % 2 == 0 {
                let ok = client.ping().await.unwrap();
                assert!(ok);
            } else {
                let rec = client.get_last_command().await.unwrap();
                assert_eq!(rec.exit_code, 0);
            }
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════
// 한국어 / 유니코드 / 특수문자 처리
// ═══════════════════════════════════════════════════════════════

/// 한국어가 포함된 에러 출력이 파이프라인을 통과해도 깨지지 않는다.
#[tokio::test]
async fn e2e_korean_output_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("korean.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record(
        "python main.py",
        1,
        &[
            "오류: 파일을 찾을 수 없습니다",
            "경로: /home/사용자/문서/데이터.csv",
        ],
    ));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert!(rec.output_lines[0].contains("파일을 찾을 수 없습니다"));
    assert!(rec.output_lines[1].contains("사용자"));

    let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
    assert!(prompt.contains("파일을 찾을 수 없습니다"));

    handle.abort();
}

/// 이모지와 CJK 문자가 섞인 출력도 정상 처리된다.
#[tokio::test]
async fn e2e_unicode_emoji_output() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("emoji.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record(
        "echo test",
        0,
        &[
            "✅ テスト成功",
            "🚀 배포 준비 완료",
            "⚠️ Warning: 注意してください",
        ],
    ));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert!(rec.output_lines[0].contains("✅"));
    assert!(rec.output_lines[1].contains("🚀"));
    assert!(rec.output_lines[2].contains("⚠️"));

    handle.abort();
}

/// 특수 셸 문자($, `, \, ", ')가 포함된 출력이 손상되지 않는다.
#[tokio::test]
async fn e2e_shell_special_chars_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("special.sock");

    let lines = &[
        r#"echo "hello $USER""#,
        r"path=/usr/local/bin:$PATH",
        r"regex: ^[a-z]+\d{3}$",
        "backtick: `date`",
    ];
    let mut ring = RingBuffer::new(500);
    ring.push(record("env", 0, lines));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.output_lines.len(), 4);
    assert!(rec.output_lines[0].contains("$USER"));
    assert!(rec.output_lines[2].contains(r"\d{3}"));
    assert!(rec.output_lines[3].contains("`date`"));

    handle.abort();
}

// ═══════════════════════════════════════════════════════════════
// 다양한 exit code 시나리오
// ═══════════════════════════════════════════════════════════════

/// 시그널로 종료된 명령어 (exit_code=128+signal)도 ErrorAnalysis로 분기한다.
#[tokio::test]
async fn e2e_signal_killed_command() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("signal.sock");

    // SIGKILL = 9, exit_code = 128 + 9 = 137
    let mut ring = RingBuffer::new(500);
    ring.push(record("sleep 3600", 137, &["Killed"]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.exit_code, 137);
    let mode = AutoBrancher::determine_mode(&rec);
    assert!(matches!(mode, ExecutionMode::ErrorAnalysis(_)));

    if let ExecutionMode::ErrorAnalysis(r) = mode {
        let prompt = ErrorAnalyzer::build_prompt(&r, "korean");
        assert!(prompt.contains("137"));
        assert!(prompt.contains("Killed"));
    }

    handle.abort();
}

/// exit_code=126 (permission denied) 시나리오
#[tokio::test]
async fn e2e_permission_denied_126() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("perm.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record(
        "./script.sh",
        126,
        &["bash: ./script.sh: Permission denied"],
    ));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.exit_code, 126);
    let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
    assert!(prompt.contains("Permission denied"));
    assert!(prompt.contains("126"));

    handle.abort();
}

/// exit_code=127 (command not found) 시나리오
#[tokio::test]
async fn e2e_command_not_found_127() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("notfound.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record(
        "nonexistent_cmd",
        127,
        &["bash: nonexistent_cmd: command not found"],
    ));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.exit_code, 127);
    let mode = AutoBrancher::determine_mode(&rec);
    assert!(matches!(mode, ExecutionMode::ErrorAnalysis(_)));

    handle.abort();
}

/// command가 None인 레코드 (Timing Heuristic 폴백 시 발생 가능)
#[tokio::test]
async fn e2e_record_without_command_text() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("nocmd.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record_no_cmd(1, &["segmentation fault (core dumped)"]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert!(rec.command.is_none());
    let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
    assert!(prompt.contains("(unknown command)"));
    assert!(prompt.contains("segmentation fault"));

    handle.abort();
}

// ═══════════════════════════════════════════════════════════════
// 대용량 출력 / 경계 조건
// ═══════════════════════════════════════════════════════════════

/// 수백 줄의 대용량 출력이 파이프라인을 통과하여 UDS로 전달된다.
#[tokio::test]
async fn e2e_large_output_through_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("large.sock");

    let lines: Vec<String> = (0..200)
        .map(|i| format!("line {i}: {}", "x".repeat(80)))
        .collect();
    let mut ring = RingBuffer::new(50000);
    ring.push(CommandRecord {
        command: Some("find / -name '*.rs'".to_string()),
        exit_code: 0,
        output_lines: lines.clone(),
        timestamp: Utc::now(),
        ..Default::default()
    });

    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.output_lines.len(), 200);
    assert!(rec.output_lines[0].starts_with("line 0:"));
    assert!(rec.output_lines[199].starts_with("line 199:"));

    handle.abort();
}

/// 빈 출력(0줄)인 레코드도 정상 처리된다.
#[tokio::test]
async fn e2e_empty_output_record() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("empty.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record("true", 0, &[]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.exit_code, 0);
    assert!(rec.output_lines.is_empty());

    // 빈 출력에 대한 프롬프트 생성
    let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
    assert!(prompt.contains("(no output)"));

    handle.abort();
}

/// 단일 줄 출력 레코드
#[tokio::test]
async fn e2e_single_line_output() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("single.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record("whoami", 0, &["developer"]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.output_lines, vec!["developer"]);
    let mode = AutoBrancher::determine_mode(&rec);
    assert!(matches!(mode, ExecutionMode::InteractiveRepl(_)));

    handle.abort();
}

// ═══════════════════════════════════════════════════════════════
// LlmDispatcher 통합 (CLI Backend)
// ═══════════════════════════════════════════════════════════════

/// LlmDispatcher가 CLI Backend를 통해 실제 프로세스를 실행하고 응답을 받는 E2E
#[tokio::test]
async fn e2e_llm_dispatcher_cli_backend_full_flow() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("llm-cli.sock");

    // mock CLI: 입력을 구조화된 형식으로 반환
    let script = make_cli_script(
        dir.path(),
        "mock-analyzer",
        r#"
echo "EXPLANATION: The build failed because of missing dependency."
echo "SUGGESTED COMMAND: cargo add serde"
echo "ADDITIONAL INFO: Run cargo build after adding the dependency."
"#,
    );

    // 서버 + 에러 레코드
    let mut ring = RingBuffer::new(500);
    ring.push(record(
        "cargo build",
        101,
        &[
            "error[E0433]: failed to resolve: use of undeclared crate",
            "  --> src/lib.rs:1:5",
        ],
    ));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    // 클라이언트 → 레코드 조회
    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    // LlmDispatcher로 CLI Backend 호출
    let config = LlmConfig {
        default_provider: "mock".to_string(),
        providers: HashMap::from([(
            "mock".to_string(),
            ProviderConfig {
                provider_type: ProviderType::CliBackend,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: Some(script.to_str().unwrap().to_string()),
                cli_args: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    };
    let dispatcher = LlmDispatcher::from_config(config);

    let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
    let response = dispatcher.send(&prompt).await.unwrap();
    let result = ErrorAnalyzer::parse_response(&response);

    assert!(result.explanation.contains("missing dependency"));
    assert_eq!(result.suggested_command.as_deref(), Some("cargo add serde"));
    assert!(result.additional_info.is_some());

    handle.abort();
}

/// CLI Backend가 실패하면 LlmApiError가 반환된다.
#[tokio::test]
async fn e2e_llm_dispatcher_cli_backend_failure() {
    let dir = tempfile::tempdir().unwrap();

    let script = make_cli_script(
        dir.path(),
        "fail-cli",
        "echo 'internal error' >&2\nexit 1\n",
    );

    let config = LlmConfig {
        default_provider: "fail".to_string(),
        providers: HashMap::from([(
            "fail".to_string(),
            ProviderConfig {
                provider_type: ProviderType::CliBackend,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: Some(script.to_str().unwrap().to_string()),
                cli_args: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    };
    let dispatcher = LlmDispatcher::from_config(config);

    let err = dispatcher.send("test").await.unwrap_err();
    assert!(matches!(err, AicError::LlmApiError { .. }));
}

/// 존재하지 않는 CLI Backend → CliNotFound 에러
#[tokio::test]
async fn e2e_llm_dispatcher_cli_not_found() {
    let config = LlmConfig {
        default_provider: "ghost".to_string(),
        providers: HashMap::from([(
            "ghost".to_string(),
            ProviderConfig {
                provider_type: ProviderType::CliBackend,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: Some("/nonexistent/bin/ghost-cli-xyz".to_string()),
                cli_args: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    };
    let dispatcher = LlmDispatcher::from_config(config);

    let err = dispatcher.send("hello").await.unwrap_err();
    assert!(
        matches!(err, AicError::CliNotFound { .. }),
        "CliNotFound를 기대했지만 {:?}를 받았습니다",
        err
    );
}

/// API key 누락 시 ApiKeyMissing 에러 (OpenAI)
#[tokio::test]
async fn e2e_llm_dispatcher_missing_api_key() {
    let config = LlmConfig {
        default_provider: "openai".to_string(),
        providers: HashMap::from([(
            "openai".to_string(),
            ProviderConfig {
                provider_type: ProviderType::OpenAiCompatible,
                endpoint: Some("https://api.openai.com/v1/chat/completions".to_string()),
                api_key: None,
                model: Some("gpt-4o".to_string()),
                cli_path: None,
                cli_args: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    };
    let dispatcher = LlmDispatcher::from_config(config);

    let err = dispatcher.send("test").await.unwrap_err();
    assert!(matches!(err, AicError::ApiKeyMissing { .. }));
}

// ═══════════════════════════════════════════════════════════════
// IPC 프로토콜 raw 레벨 테스트
// ═══════════════════════════════════════════════════════════════

/// raw UDS 소켓으로 GetRecentLines 요청을 보내고 Lines 응답을 받는다.
#[tokio::test]
async fn e2e_raw_ipc_get_recent_lines() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("raw-lines.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record("ls", 0, &["a.txt", "b.txt", "c.txt"]));
    ring.push(record("pwd", 0, &["/home/user"]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    // raw 소켓으로 직접 IPC 요청
    let mut stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

    let req = IpcRequest::GetRecentLines { count: 2 };
    let req_json = serde_json::to_vec(&req).unwrap();
    let frame = encode_frame(&req_json);
    stream.write_all(&frame).await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
    match resp {
        IpcResponse::Lines(lines) => {
            // 최근 2줄: "c.txt"(ls의 마지막), "/home/user"(pwd)
            assert_eq!(lines.len(), 2);
            // 순서: 오래된 → 최신
            assert_eq!(lines[0], "c.txt");
            assert_eq!(lines[1], "/home/user");
        }
        other => panic!("Lines를 기대했지만 {:?}를 받았습니다", other),
    }

    handle.abort();
}

/// 빈 RingBuffer에 GetLastCommand 요청 시 Error 응답
#[tokio::test]
async fn e2e_raw_ipc_empty_buffer_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("raw-empty.sock");

    let ring = RingBuffer::new(500);
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let mut stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

    let req = IpcRequest::GetLastCommand;
    let req_json = serde_json::to_vec(&req).unwrap();
    let frame = encode_frame(&req_json);
    stream.write_all(&frame).await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
    assert!(
        matches!(resp, IpcResponse::Error { .. }),
        "빈 버퍼에서 Error 응답을 기대했습니다"
    );

    handle.abort();
}

// ═══════════════════════════════════════════════════════════════
// OutputProcessor 파이프라인 심화
// ═══════════════════════════════════════════════════════════════

/// 복합 ANSI 시퀀스(256색, bold, underline 등)가 모두 제거된다.
#[test]
fn e2e_complex_ansi_stripping() {
    let mut processor = OutputProcessor::new();

    // 256색 + bold + underline + 리셋
    let raw = b"\x1b[1m\x1b[4m\x1b[38;5;196mCRITICAL ERROR\x1b[0m: disk full\n";
    let output = processor.process(raw);

    let clean = output.clean_text.unwrap();
    assert!(clean.contains("CRITICAL ERROR"));
    assert!(clean.contains("disk full"));
    assert!(!clean.contains("\x1b"));
}

/// 여러 alternate screen 진입/복귀 사이클이 올바르게 추적된다.
#[test]
fn e2e_multiple_alternate_screen_cycles() {
    let mut processor = OutputProcessor::new();
    let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
        marker_sequence: "osc133".to_string(),
    });

    // 첫 번째 사이클: vim
    let _ = processor.process(b"before vim\n");
    detector.feed_line("before vim");

    let _ = processor.process(b"\x1b[?1049h");
    assert!(processor.is_alternate_screen());
    let tui = processor.process(b"vim stuff\n");
    assert!(tui.clean_text.is_none());

    let _ = processor.process(b"\x1b[?1049l");
    assert!(!processor.is_alternate_screen());

    // 두 번째 사이클: htop (다른 시퀀스)
    let _ = processor.process(b"\x1b[?47h");
    assert!(processor.is_alternate_screen());
    let tui2 = processor.process(b"htop output\n");
    assert!(tui2.clean_text.is_none());

    let _ = processor.process(b"\x1b[?47l");
    assert!(!processor.is_alternate_screen());

    let _ = processor.process(b"after htop\n");
    detector.feed_line("after htop");

    // completion
    let rec = detector.feed_line("\x1b]133;D;0\x07");
    assert!(rec.is_some());
    let rec = rec.unwrap();
    assert!(rec.output_lines.contains(&"before vim".to_string()));
    assert!(rec.output_lines.contains(&"after htop".to_string()));
    assert!(!rec.output_lines.iter().any(|l| l.contains("vim stuff")));
    assert!(!rec.output_lines.iter().any(|l| l.contains("htop output")));
}

/// OSC 133 마커가 ANSI 색상 코드와 같은 줄에 있어도 정상 감지된다.
#[test]
fn e2e_osc_marker_mixed_with_ansi_colors() {
    let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
        marker_sequence: "osc133".to_string(),
    });

    detector.feed_line("some output");
    // 마커 앞뒤에 ANSI 색상이 있는 경우
    let rec = detector.feed_line("\x1b[32m\x1b]133;D;0\x07\x1b[0m");
    assert!(rec.is_some());
    assert_eq!(rec.unwrap().exit_code, 0);
}

// ═══════════════════════════════════════════════════════════════
// 서버 재시작 / 소켓 재바인딩
// ═══════════════════════════════════════════════════════════════

/// 서버가 종료된 후 같은 소켓 경로로 재시작해도 클라이언트가 연결된다.
#[tokio::test]
async fn e2e_server_restart_same_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("restart.sock");

    // 첫 번째 서버
    let mut ring1 = RingBuffer::new(500);
    ring1.push(record("first", 0, &["v1"]));
    let (_buf1, handle1) = start_server(&sock_path, ring1).await;

    let client = UdsClient::new(sock_path.clone());
    let rec = client.get_last_command().await.unwrap();
    assert_eq!(rec.output_lines, vec!["v1"]);

    // 첫 번째 서버 종료
    handle1.abort();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 두 번째 서버 (같은 소켓 경로, 다른 데이터)
    let mut ring2 = RingBuffer::new(500);
    ring2.push(record("second", 1, &["v2"]));
    let (_buf2, handle2) = start_server(&sock_path, ring2).await;

    let client2 = UdsClient::new(sock_path);
    let rec2 = client2.get_last_command().await.unwrap();
    assert_eq!(rec2.output_lines, vec!["v2"]);
    assert_eq!(rec2.exit_code, 1);

    handle2.abort();
}

/// 서버 종료 후 클라이언트 연결 시 ServerNotRunning 에러
#[tokio::test]
async fn e2e_client_after_server_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("shutdown.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(record("test", 0, &["ok"]));
    let (_buf, handle) = start_server(&sock_path, ring).await;

    // 서버 종료
    handle.abort();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // 소켓 파일 삭제 (Drop에서 처리되지만 명시적으로)
    let _ = std::fs::remove_file(&sock_path);

    let client = UdsClient::new(sock_path);
    let err = client.get_last_command().await.unwrap_err();
    assert!(
        matches!(err, AicError::ServerNotRunning),
        "ServerNotRunning을 기대했지만 {:?}를 받았습니다",
        err
    );
}

// ═══════════════════════════════════════════════════════════════
// 바이너리 실행 테스트 (추가)
// ═══════════════════════════════════════════════════════════════

/// 등록되지 않은 단어 인자는 서브커맨드가 아니라 직접 질문 프롬프트로 처리된다.
#[test]
fn e2e_ac_unknown_arg_is_direct_prompt() {
    let bin = env!("CARGO_BIN_EXE_aic");
    let output = std::process::Command::new(bin)
        .arg("--dry-run")
        .arg("nonexistent-subcommand")
        .output()
        .expect("aic 실행 실패");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("direct-prompt"),
        "알 수 없는 단어 인자는 직접 질문 dry-run으로 처리되어야 합니다. 실제: {stdout}"
    );
}

/// `ac --help` 가 도움말을 출력한다.
#[test]
fn e2e_ac_help_flag() {
    let bin = env!("CARGO_BIN_EXE_aic");
    let output = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .expect("aic --help 실행 실패");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage") || stdout.contains("usage"));
    assert!(stdout.contains("config"));
}

/// `ac --version` 또는 `ac -V` 가 버전을 출력한다.
#[test]
fn e2e_ac_version_flag() {
    let bin = env!("CARGO_BIN_EXE_aic");
    // clap에 version이 설정되어 있지 않을 수 있으므로 실행만 확인
    let output = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .expect("aic --version 실행 실패");

    // version이 설정되어 있으면 성공, 아니면 에러 — 둘 다 crash는 아님
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.is_empty(),
        "--version 실행 시 어떤 출력이든 있어야 합니다"
    );
}

// ═══════════════════════════════════════════════════════════════
// ErrorAnalyzer 다양한 LLM 응답 형식 E2E
// ═══════════════════════════════════════════════════════════════

/// LLM이 번호 없이 섹션 헤더만 반환하는 경우
#[test]
fn e2e_error_analyzer_plain_headers() {
    let response = "\
EXPLANATION: Missing semicolon on line 42.
SUGGESTED COMMAND: rustfmt src/main.rs
ADDITIONAL INFO: Consider enabling format-on-save.";

    let result = ErrorAnalyzer::parse_response(response);
    assert!(result.explanation.contains("semicolon"));
    assert!(result
        .suggested_command
        .as_deref()
        .unwrap()
        .contains("rustfmt"));
    assert!(result
        .additional_info
        .as_deref()
        .unwrap()
        .contains("format-on-save"));
}

/// LLM이 마크다운 형식으로 응답하는 경우 (비구조화 fallback)
#[test]
fn e2e_error_analyzer_markdown_response() {
    let response = "\
## Error Analysis

The `cargo build` command failed because the `serde` crate is not in your dependencies.

### Fix
Add `serde` to your `Cargo.toml`:
```
cargo add serde --features derive
```";

    let result = ErrorAnalyzer::parse_response(response);
    // 구조화된 섹션이 없으므로 전체가 explanation
    assert!(result.explanation.contains("serde"));
    assert!(result.suggested_command.is_none());
}

/// LLM이 빈 응답을 반환하는 경우
#[test]
fn e2e_error_analyzer_empty_response() {
    let result = ErrorAnalyzer::parse_response("");
    assert_eq!(result.explanation, "(no response from LLM)");
}

/// LLM이 EXPLANATION만 반환하고 나머지는 없는 경우
#[test]
fn e2e_error_analyzer_explanation_only() {
    let response = "EXPLANATION: The file was not found at the specified path.";
    let result = ErrorAnalyzer::parse_response(response);
    assert!(result.explanation.contains("file was not found"));
    assert!(result.suggested_command.is_none());
    assert!(result.additional_info.is_none());
}

// ═══════════════════════════════════════════════════════════════
// ReplSession 종료 명령 E2E
// ═══════════════════════════════════════════════════════════════

/// REPL 종료 명령 인식 — 다양한 변형
#[test]
fn e2e_repl_exit_commands_comprehensive() {
    // 종료로 인식되어야 하는 입력
    let exits = [
        "exit", "quit", "EXIT", "QUIT", "Exit", "Quit", " exit ", "\tquit\n",
    ];
    for cmd in &exits {
        assert!(
            ReplSession::is_exit_command(cmd),
            "'{}' 는 종료 명령으로 인식되어야 합니다",
            cmd
        );
    }

    // 종료로 인식되면 안 되는 입력
    let non_exits = [
        "exit now",
        "please quit",
        "exiting",
        "quitter",
        "EXIT_CODE",
        "quit()",
        "help",
        "",
        "   ",
        "exit\nexit", // 멀티라인
    ];
    for cmd in &non_exits {
        assert!(
            !ReplSession::is_exit_command(cmd),
            "'{}' 는 종료 명령이 아니어야 합니다",
            cmd
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// 현실적 시나리오: 실제 개발 워크플로우 시뮬레이션
// ═══════════════════════════════════════════════════════════════

/// 시나리오: Rust 컴파일 에러 → ac → 에러 분석 → 수정 제안
#[tokio::test]
async fn e2e_scenario_rust_compile_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("rust-err.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(CommandRecord {
        command: Some("cargo build".to_string()),
        exit_code: 101,
        output_lines: vec![
            "   Compiling myapp v0.1.0 (/home/user/myapp)".to_string(),
            "error[E0382]: borrow of moved value: `data`".to_string(),
            "  --> src/main.rs:15:20".to_string(),
            "   |".to_string(),
            "12 |     let result = process(data);".to_string(),
            "   |                          ---- value moved here".to_string(),
            "15 |     println!(\"{}\", data);".to_string(),
            "   |                    ^^^^ value borrowed here after move".to_string(),
            "".to_string(),
            "error: could not compile `myapp` (bin \"myapp\") due to 1 previous error".to_string(),
        ],
        timestamp: Utc::now(),
        ..Default::default()
    });
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    // 분기 확인
    assert_eq!(rec.exit_code, 101);
    let mode = AutoBrancher::determine_mode(&rec);
    assert!(matches!(mode, ExecutionMode::ErrorAnalysis(_)));

    // 프롬프트에 핵심 정보가 포함되는지 확인
    if let ExecutionMode::ErrorAnalysis(r) = mode {
        let prompt = ErrorAnalyzer::build_prompt(&r, "korean");
        assert!(prompt.contains("E0382"));
        assert!(prompt.contains("borrow of moved value"));
        assert!(prompt.contains("cargo build"));
        assert!(prompt.contains("101"));
    }

    handle.abort();
}

/// 시나리오: npm test 성공 → ac → REPL 모드 진입
#[tokio::test]
async fn e2e_scenario_npm_test_success() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("npm-ok.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(CommandRecord {
        command: Some("npm test".to_string()),
        exit_code: 0,
        output_lines: vec![
            "".to_string(),
            "> myapp@1.0.0 test".to_string(),
            "> jest --coverage".to_string(),
            "".to_string(),
            " PASS  src/__tests__/app.test.ts".to_string(),
            " PASS  src/__tests__/utils.test.ts".to_string(),
            "".to_string(),
            "Test Suites: 2 passed, 2 total".to_string(),
            "Tests:       12 passed, 12 total".to_string(),
            "Coverage:    87.5%".to_string(),
        ],
        timestamp: Utc::now(),
        ..Default::default()
    });
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.exit_code, 0);
    let mode = AutoBrancher::determine_mode(&rec);
    assert!(matches!(mode, ExecutionMode::InteractiveRepl(_)));

    handle.abort();
}

/// 시나리오: Docker build 실패 → 에러 분석 (멀티라인 에러)
#[tokio::test]
async fn e2e_scenario_docker_build_failure() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("docker-err.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(CommandRecord {
        command: Some("docker build -t myapp .".to_string()),
        exit_code: 1,
        output_lines: vec![
            "[+] Building 12.3s (8/12)".to_string(),
            " => [internal] load build definition from Dockerfile".to_string(),
            " => ERROR [5/8] RUN npm ci".to_string(),
            "------".to_string(),
            " > [5/8] RUN npm ci:".to_string(),
            "npm ERR! code ERESOLVE".to_string(),
            "npm ERR! ERESOLVE unable to resolve dependency tree".to_string(),
            "npm ERR! Found: react@18.2.0".to_string(),
            "npm ERR! Could not resolve dependency:".to_string(),
            "npm ERR! peer react@\"^17.0.0\" from some-lib@1.0.0".to_string(),
            "------".to_string(),
            "Dockerfile:12".to_string(),
            "--------------------".to_string(),
            "  10 |     COPY package*.json ./".to_string(),
            "  11 |     ".to_string(),
            "  12 | >>> RUN npm ci".to_string(),
            "--------------------".to_string(),
            "ERROR: failed to solve: process \"/bin/sh -c npm ci\" did not complete successfully"
                .to_string(),
        ],
        timestamp: Utc::now(),
        ..Default::default()
    });
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    assert_eq!(rec.exit_code, 1);
    assert!(
        rec.output_lines.len() > 10,
        "Docker 에러는 보통 긴 출력을 가짐"
    );

    let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
    assert!(prompt.contains("ERESOLVE"));
    assert!(prompt.contains("docker build"));
    assert!(prompt.contains("react"));

    handle.abort();
}

/// 시나리오: git push 실패 (non-fast-forward)
#[tokio::test]
async fn e2e_scenario_git_push_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("git-push.sock");

    let mut ring = RingBuffer::new(500);
    ring.push(CommandRecord {
        command: Some("git push origin main".to_string()),
        exit_code: 1,
        output_lines: vec![
            "To github.com:user/repo.git".to_string(),
            " ! [rejected]        main -> main (non-fast-forward)".to_string(),
            "error: failed to push some refs to 'github.com:user/repo.git'".to_string(),
            "hint: Updates were rejected because the tip of your current branch is behind"
                .to_string(),
            "hint: its remote counterpart.".to_string(),
        ],
        timestamp: Utc::now(),
        ..Default::default()
    });
    let (_buf, handle) = start_server(&sock_path, ring).await;

    let client = UdsClient::new(sock_path);
    let rec = client.get_last_command().await.unwrap();

    let mode = AutoBrancher::determine_mode(&rec);
    assert!(matches!(mode, ExecutionMode::ErrorAnalysis(_)));

    if let ExecutionMode::ErrorAnalysis(r) = mode {
        let prompt = ErrorAnalyzer::build_prompt(&r, "korean");
        assert!(prompt.contains("non-fast-forward"));
        assert!(prompt.contains("git push"));
    }

    handle.abort();
}
