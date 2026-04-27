//! End-to-End 테스트
//!
//! 실제 바이너리 실행 및 전체 컴포넌트 파이프라인을 검증한다.
//!
//! 시나리오:
//! 1. `ac config` 서브커맨드 출력 검증
//! 2. 서버 미실행 시 `ac` 실행 → 에러 메시지 검증
//! 3. 서버(UdsServer + RingBuffer) → 클라이언트(UdsClient) 전체 흐름
//! 4. 에러 명령어 → AutoBrancher → ErrorAnalyzer 파이프라인
//! 5. 성공 명령어 → AutoBrancher → InteractiveRepl 분기 검증
//! 6. OutputProcessor → CommandBoundaryDetector → RingBuffer → UdsServer → UdsClient 전체 파이프라인
//! 7. CLI Backend를 통한 에러 분석 E2E

use aic_client::auto_brancher::{AutoBrancher, ExecutionMode};
use aic_client::error_analyzer::ErrorAnalyzer;
use aic_client::uds_client::UdsClient;
use aic_common::CommandRecord;
use aic_server::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use aic_server::output_processor::OutputProcessor;
use aic_server::ring_buffer::RingBuffer;
use aic_server::uds_server::UdsServer;

use chrono::Utc;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

// ── 헬퍼 ───────────────────────────────────────────────────────

fn make_error_record() -> CommandRecord {
    CommandRecord {
        command: Some("cargo build".to_string()),
        exit_code: 1,
        output_lines: vec![
            "error[E0308]: mismatched types".to_string(),
            "  --> src/main.rs:10:5".to_string(),
            "help: try using a conversion method".to_string(),
        ],
        timestamp: Utc::now(),
        ..Default::default()
    }
}

fn make_success_record() -> CommandRecord {
    CommandRecord {
        command: Some("cargo test".to_string()),
        exit_code: 0,
        output_lines: vec![
            "running 5 tests".to_string(),
            "test result: ok. 5 passed".to_string(),
        ],
        timestamp: Utc::now(),
        ..Default::default()
    }
}

/// UdsServer를 시작하고 RingBuffer에 레코드를 적재한 상태로 반환한다.
async fn start_server_with_record(
    sock_path: &std::path::Path,
    record: CommandRecord,
) -> (Arc<RwLock<RingBuffer>>, tokio::task::JoinHandle<()>) {
    let mut ring = RingBuffer::new(500);
    ring.push(record);
    let buffer = Arc::new(RwLock::new(ring));

    let server = UdsServer::bind(sock_path).await.unwrap();
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    // 서버가 준비될 때까지 잠시 대기
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (buffer, handle)
}

/// mock CLI echo 스크립트를 생성한다.
fn create_mock_cli(dir: &std::path::Path) -> PathBuf {
    let script = dir.join("mock-llm-cli");
    let mut f = std::fs::File::create(&script).unwrap();
    writeln!(f, "#!/bin/sh").unwrap();
    // 입력을 구조화된 형식으로 echo (ErrorAnalyzer가 파싱할 수 있도록)
    writeln!(
        f,
        r#"echo "EXPLANATION: The command failed due to a type mismatch error.""#
    )
    .unwrap();
    writeln!(f, r#"echo "SUGGESTED COMMAND: cargo build --release""#).unwrap();
    writeln!(f, r#"echo "ADDITIONAL INFO: Check your type annotations.""#).unwrap();
    drop(f);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    script
}

/// mock 설정 파일을 생성한다.
fn create_mock_config(dir: &std::path::Path, cli_path: &str) -> PathBuf {
    let config_dir = dir.join("aic");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");

    let config_content = format!(
        r#"[server]
max_buffer_lines = 500

[server.boundary_strategy]
method = "prompt_marker"

[llm]
default_provider = "mock-cli"

[llm.providers.mock-cli]
provider_type = "CliBackend"
cli_path = "{cli_path}"
"#
    );

    std::fs::write(&config_path, config_content).unwrap();
    dir.to_path_buf()
}

// ── E2E 테스트 ─────────────────────────────────────────────────

/// 1. `ac config` 서브커맨드가 설정 경로를 출력하는지 검증
#[test]
fn e2e_ac_config_subcommand() {
    let bin = env!("CARGO_BIN_EXE_aic");
    // 인터랙티브 UI이므로 stdin을 닫아서 즉시 종료되게 함
    let output = std::process::Command::new(bin)
        .arg("config")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("aic config 실행 실패");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // 인터랙티브 UI에서는 "설정 파일:" 형식으로 출력
    assert!(
        stdout.contains("설정 파일:"),
        "aic config 출력에 '설정 파일:'이 포함되어야 합니다. 실제: {stdout}"
    );
    assert!(
        stdout.contains("config.toml"),
        "aic config 출력에 'config.toml'이 포함되어야 합니다. 실제: {stdout}"
    );
}

/// 2. 세션 밖에서 `aic` 실행 → 안내 메시지 검증
#[test]
fn e2e_ac_without_session_shows_guidance() {
    // 임시 소켓 경로를 사용하여 서버가 없는 상황을 보장
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("nonexistent.sock");

    // 임시 설정 파일 생성 (존재하지 않는 소켓 경로 지정)
    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("aic").join("config.toml");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();

    let config_content = format!(
        r#"[server]
max_buffer_lines = 500
socket_path = "{}"

[server.boundary_strategy]
method = "prompt_marker"

[llm]
default_provider = "openai"
"#,
        sock_path.display()
    );
    std::fs::write(&config_path, config_content).unwrap();

    let bin = env!("CARGO_BIN_EXE_aic");
    // HOME과 세션 env를 격리해서 현재 개발 터미널의 aic-session을 상속하지 않게 한다.
    // 세션 밖에서 직접 `aic`를 실행하면 사용법 안내 후 정상 종료한다.
    let output = std::process::Command::new(bin)
        .env("XDG_CONFIG_HOME", config_dir.to_str().unwrap())
        .env("HOME", config_dir.to_str().unwrap())
        .env_remove("AIC_SESSION")
        .env_remove("AIC_SESSION_ID")
        .env_remove("HISTFILE")
        .output()
        .expect("aic 실행 실패");

    assert!(
        output.status.success(),
        "세션 밖 aic는 안내 후 정상 종료해야 합니다. stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("aic-session"),
        "stderr에 세션 안내 메시지가 포함되어야 합니다. 실제: {stderr}"
    );
}

/// 3. UdsServer + 에러 레코드 → UdsClient → GetLastCommand → 에러 레코드 수신
#[tokio::test]
async fn e2e_server_client_error_record_flow() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("e2e-error.sock");

    let error_record = make_error_record();
    let (_buffer, handle) = start_server_with_record(&sock_path, error_record.clone()).await;

    // UdsClient로 연결
    let client = UdsClient::new(sock_path);

    // ping 확인
    let ping_ok = client.ping().await.unwrap();
    assert!(ping_ok, "서버에 ping이 성공해야 합니다");

    // GetLastCommand
    let record = client.get_last_command().await.unwrap();
    assert_eq!(record.command, Some("cargo build".to_string()));
    assert_eq!(record.exit_code, 1);
    assert_eq!(record.output_lines.len(), 3);
    assert!(record.output_lines[0].contains("E0308"));

    // AutoBrancher → ErrorAnalysis 분기
    let mode = AutoBrancher::determine_mode(&record);
    assert!(
        matches!(mode, ExecutionMode::ErrorAnalysis(_)),
        "exit_code=1이므로 ErrorAnalysis여야 합니다"
    );

    // ErrorAnalyzer 프롬프트 생성 검증
    if let ExecutionMode::ErrorAnalysis(rec) = mode {
        let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
        assert!(prompt.contains("cargo build"));
        assert!(prompt.contains("E0308"));
        assert!(prompt.contains("EXIT_CODE: 1"));
    }

    handle.abort();
}

/// 4. UdsServer + 성공 레코드 → UdsClient → AutoBrancher → InteractiveRepl 분기
#[tokio::test]
async fn e2e_server_client_success_record_flow() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("e2e-success.sock");

    let success_record = make_success_record();
    let (_buffer, handle) = start_server_with_record(&sock_path, success_record).await;

    let client = UdsClient::new(sock_path);
    let record = client.get_last_command().await.unwrap();

    assert_eq!(record.exit_code, 0);

    let mode = AutoBrancher::determine_mode(&record);
    assert!(
        matches!(mode, ExecutionMode::InteractiveRepl(_)),
        "exit_code=0이므로 InteractiveRepl이어야 합니다"
    );

    handle.abort();
}

/// 5. 전체 파이프라인: OutputProcessor → CommandBoundaryDetector → RingBuffer
///    → UdsServer → UdsClient → AutoBrancher → ErrorAnalyzer
#[tokio::test]
async fn e2e_full_pipeline_error_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("e2e-pipeline.sock");

    // 1) 파이프라인 시뮬레이션: PTY 출력 → 컴포넌트 체인
    let mut processor = OutputProcessor::new();
    let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
        marker_sequence: "osc133".to_string(),
    });
    let mut ring = RingBuffer::new(500);

    // ANSI 색상이 포함된 에러 출력 시뮬레이션
    let raw_output = b"\x1b[31merror[E0308]: mismatched types\x1b[0m\n";
    let completion = b"\x1b]133;D;1\x07";

    // OutputProcessor로 ANSI strip
    let processed = processor.process(raw_output);
    assert!(processed.clean_text.is_some());

    // clean text를 CommandBoundaryDetector에 전달
    if let Some(ref text) = processed.clean_text {
        for line in text.lines() {
            let stripped = strip_ansi_escapes::strip(line.as_bytes());
            let clean = String::from_utf8_lossy(&stripped);
            if !clean.is_empty() {
                detector.feed_line(&clean);
            }
        }
    }

    // completion marker 전달 → CommandRecord 생성
    let marker_str = String::from_utf8_lossy(completion);
    let record = detector.feed_line(&marker_str);
    assert!(
        record.is_some(),
        "completion marker 후 레코드가 생성되어야 합니다"
    );

    let record = record.unwrap();
    assert_eq!(record.exit_code, 1);
    ring.push(record);

    // 2) UdsServer 시작
    let buffer = Arc::new(RwLock::new(ring));
    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3) UdsClient로 조회
    let client = UdsClient::new(sock_path);
    let fetched = client.get_last_command().await.unwrap();
    assert_eq!(fetched.exit_code, 1);
    assert!(fetched.output_lines.iter().any(|l| l.contains("E0308")));

    // 4) AutoBrancher → ErrorAnalysis
    let mode = AutoBrancher::determine_mode(&fetched);
    assert!(matches!(mode, ExecutionMode::ErrorAnalysis(_)));

    // 5) ErrorAnalyzer 프롬프트 생성
    if let ExecutionMode::ErrorAnalysis(rec) = mode {
        let prompt = ErrorAnalyzer::build_prompt(&rec, "korean");
        assert!(prompt.contains("E0308"));
        assert!(prompt.contains("EXIT_CODE: 1"));

        // 6) LLM 응답 파싱 (mock 응답)
        let mock_response = "EXPLANATION: Type mismatch in main.rs\nSUGGESTED COMMAND: cargo build\nADDITIONAL INFO: Check line 10";
        let result = ErrorAnalyzer::parse_response(mock_response);
        assert!(result.explanation.contains("Type mismatch"));
        assert!(result.suggested_command.is_some());
        assert!(result.additional_info.is_some());
    }

    handle.abort();
}

/// 6. Alternate Screen 출력이 RingBuffer에 저장되지 않는 E2E 검증
#[tokio::test]
async fn e2e_alternate_screen_filtering() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("e2e-altscreen.sock");

    let mut processor = OutputProcessor::new();
    let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
        marker_sequence: "osc133".to_string(),
    });
    let mut ring = RingBuffer::new(500);

    // 일반 출력
    let normal = b"normal line\n";
    let output = processor.process(normal);
    if let Some(ref text) = output.clean_text {
        for line in text.lines() {
            if !line.is_empty() {
                detector.feed_line(line);
            }
        }
    }

    // Alternate screen 진입 → TUI 출력 → 복귀
    let enter_alt = b"\x1b[?1049h";
    let tui_output = b"vim content here\n";
    let exit_alt = b"\x1b[?1049l";

    let _ = processor.process(enter_alt);
    assert!(processor.is_alternate_screen());

    let tui_processed = processor.process(tui_output);
    assert!(
        tui_processed.clean_text.is_none(),
        "alternate screen 중 clean_text는 None"
    );

    let _ = processor.process(exit_alt);
    assert!(!processor.is_alternate_screen());

    // 복귀 후 일반 출력
    let after = b"after vim\n";
    let output = processor.process(after);
    if let Some(ref text) = output.clean_text {
        for line in text.lines() {
            if !line.is_empty() {
                detector.feed_line(line);
            }
        }
    }

    // completion marker
    let marker = "\x1b]133;D;0\x07";
    if let Some(record) = detector.feed_line(marker) {
        ring.push(record);
    }

    // UDS 서버로 검증
    let buffer = Arc::new(RwLock::new(ring));
    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = UdsClient::new(sock_path);
    let record = client.get_last_command().await.unwrap();

    assert_eq!(record.exit_code, 0);
    let all_text = record.output_lines.join(" ");
    assert!(
        all_text.contains("normal line"),
        "일반 출력이 포함되어야 합니다"
    );
    assert!(
        all_text.contains("after vim"),
        "복귀 후 출력이 포함되어야 합니다"
    );
    assert!(
        !all_text.contains("vim content"),
        "alternate screen 중 출력은 포함되지 않아야 합니다"
    );

    handle.abort();
}

/// 7. CLI Backend를 통한 에러 분석 E2E (ac 바이너리 실행)
#[tokio::test]
async fn e2e_error_analysis_with_cli_backend() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("e2e-cli.sock");

    // 에러 레코드로 서버 시작
    let (_buffer, handle) = start_server_with_record(&sock_path, make_error_record()).await;

    // mock CLI 스크립트 생성
    let cli_script = create_mock_cli(dir.path());

    // UdsClient로 레코드 조회 → ErrorAnalyzer → mock CLI 실행
    let client = UdsClient::new(sock_path.clone());
    let record = client.get_last_command().await.unwrap();

    // ErrorAnalyzer로 프롬프트 생성
    let prompt = ErrorAnalyzer::build_prompt(&record, "korean");

    // mock CLI 실행 (LlmDispatcher 대신 직접 실행)
    let cli_output = std::process::Command::new(cli_script.to_str().unwrap())
        .arg(&prompt)
        .output()
        .expect("mock CLI 실행 실패");

    assert!(cli_output.status.success());
    let response = String::from_utf8_lossy(&cli_output.stdout);

    // ErrorAnalyzer로 응답 파싱
    let result = ErrorAnalyzer::parse_response(&response);
    assert!(
        result.explanation.contains("type mismatch"),
        "explanation에 에러 원인이 포함되어야 합니다: {}",
        result.explanation
    );
    assert!(
        result.suggested_command.is_some(),
        "수정 명령어 제안이 있어야 합니다"
    );

    handle.abort();
}

/// 8. 다중 명령어 순차 실행 후 마지막 명령어만 조회되는 E2E
#[tokio::test]
async fn e2e_multiple_commands_last_record() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("e2e-multi.sock");

    let mut ring = RingBuffer::new(500);

    // 3개의 명령어 레코드를 순차적으로 push
    ring.push(CommandRecord {
        command: Some("ls".to_string()),
        exit_code: 0,
        output_lines: vec!["file1.txt".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });
    ring.push(CommandRecord {
        command: Some("cat nonexistent".to_string()),
        exit_code: 1,
        output_lines: vec!["cat: nonexistent: No such file or directory".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });
    ring.push(CommandRecord {
        command: Some("echo done".to_string()),
        exit_code: 0,
        output_lines: vec!["done".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });

    let buffer = Arc::new(RwLock::new(ring));
    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = UdsClient::new(sock_path);
    let record = client.get_last_command().await.unwrap();

    // 마지막 명령어(echo done)가 반환되어야 함
    assert_eq!(record.command, Some("echo done".to_string()));
    assert_eq!(record.exit_code, 0);
    assert_eq!(record.output_lines, vec!["done"]);

    // exit_code == 0 → InteractiveRepl
    let mode = AutoBrancher::determine_mode(&record);
    assert!(matches!(mode, ExecutionMode::InteractiveRepl(_)));

    handle.abort();
}

/// 9. RingBuffer 용량 초과 시 오래된 레코드 제거 E2E
#[tokio::test]
async fn e2e_ring_buffer_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("e2e-evict.sock");

    // max_lines=5인 작은 버퍼
    let mut ring = RingBuffer::new(5);

    // 총 7줄의 레코드를 push → 처음 2줄은 evict되어야 함
    ring.push(CommandRecord {
        command: Some("cmd1".to_string()),
        exit_code: 0,
        output_lines: vec!["old1".to_string(), "old2".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });
    ring.push(CommandRecord {
        command: Some("cmd2".to_string()),
        exit_code: 1,
        output_lines: vec!["new1".to_string(), "new2".to_string(), "new3".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });
    // 총 5줄 → 정확히 max_lines
    // 하나 더 push하면 eviction 발생
    ring.push(CommandRecord {
        command: Some("cmd3".to_string()),
        exit_code: 0,
        output_lines: vec!["latest1".to_string(), "latest2".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });

    assert!(ring.total_lines() <= 5);

    let buffer = Arc::new(RwLock::new(ring));
    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = UdsClient::new(sock_path);
    let record = client.get_last_command().await.unwrap();

    // 마지막 레코드가 반환되어야 함
    assert_eq!(record.command, Some("cmd3".to_string()));
    assert_eq!(record.output_lines, vec!["latest1", "latest2"]);

    handle.abort();
}

/// 10. `ac config` 바이너리가 mock 설정 파일을 올바르게 로드하는지 검증
#[test]
fn e2e_ac_config_with_custom_config() {
    let dir = tempfile::tempdir().unwrap();
    let cli_path = "/usr/local/bin/mock-cli";
    let config_dir = create_mock_config(dir.path(), cli_path);

    let bin = env!("CARGO_BIN_EXE_aic");
    // 인터랙티브 UI이므로 stdin을 닫아서 즉시 종료되게 함
    // "현재 설정 보기"를 선택하기 위해 "0\n"을 입력
    let mut child = std::process::Command::new(bin)
        .arg("config")
        .env("XDG_CONFIG_HOME", config_dir.to_str().unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("aic config 실행 실패");

    // stdin에 "0\n3\n" 입력 (현재 설정 보기 → 종료)
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"0\n3\n");
    }

    let output = child.wait_with_output().expect("출력 대기 실패");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // 설정 파일 경로가 출력되어야 함
    assert!(
        stdout.contains("config.toml"),
        "설정 파일 경로가 출력되어야 합니다. 실제: {stdout}"
    );
}
