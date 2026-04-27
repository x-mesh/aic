//! aic-session: PTY 셸 래퍼 데몬.
//!
//! 사용자의 기본 셸을 PTY 자식 프로세스로 실행하고, 입출력을 투명하게 중계하면서
//! 출력 스트림을 전처리하여 RingBuffer에 저장한다.
//! UDS를 통해 AIC_Client의 데이터 요청을 처리한다.
//!
//! Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 10.1

use aic_common::CommandRecord;
use aic_server::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use aic_server::lock::DaemonLock;
use aic_server::output_processor::OutputProcessor;
use aic_server::pty_manager::PtyManager;
use aic_server::ring_buffer::RingBuffer;
use aic_server::telemetry;
use aic_server::uds_server::UdsServer;

use clap::Parser;
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::RwLock;

/// PTY 셸 래퍼 데몬. 사용자의 기본 셸을 PTY로 실행하고, 출력 스트림을 RingBuffer에
/// 저장하여 UDS로 클라이언트(`aic`)에 제공한다.
#[derive(Parser, Debug)]
#[command(
    name = "aic-session",
    version,
    about = "PTY 셸 래퍼 데몬",
    long_about = None,
)]
struct Cli {
    /// 사용할 셸 경로 override (기본: $SHELL → /bin/sh)
    #[arg(long, value_name = "PATH")]
    shell: Option<String>,
    /// 자동 hook 설정 skip — ~/.aic/hooks.{shell} 갱신 안 함
    #[arg(long)]
    no_hook: bool,
    /// 새 session_id를 생성해 stdout에 출력하고 종료 (PTY 시작 안 함)
    #[arg(long)]
    print_session_id: bool,
}

// ── 터미널 유틸리티 (libc) ─────────────────────────────────────

/// 현재 터미널 크기(rows, cols)를 반환한다.
fn get_terminal_size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
            && ws.ws_row > 0
            && ws.ws_col > 0
        {
            (ws.ws_row, ws.ws_col)
        } else {
            (24, 80) // 기본값
        }
    }
}

/// 터미널을 raw mode로 설정하고 이전 termios를 반환한다.
/// UTF-8 입력 처리를 위해 IUTF8 플래그를 유지한다.
fn set_raw_mode() -> anyhow::Result<libc::termios> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
            anyhow::bail!("tcgetattr 실패");
        }

        let mut raw = orig;
        libc::cfmakeraw(&mut raw);

        // UTF-8 멀티바이트 입력 처리 유지 (macOS/Linux)
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            raw.c_iflag |= libc::IUTF8;
        }

        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
            anyhow::bail!("tcsetattr 실패");
        }

        Ok(orig)
    }
}

/// 터미널을 원래 모드로 복원한다.
fn restore_terminal(orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
    }
}

fn should_store_record(record: &CommandRecord) -> bool {
    let Some(command) = record.command.as_deref() else {
        return true;
    };

    let cmd_base = command
        .split_whitespace()
        .next()
        .and_then(|s| s.rsplit('/').next())
        .unwrap_or("");

    !matches!(cmd_base, "aic" | "ac" | "aic-session")
}

// ── 메인 ───────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // --print-session-id: 새 ID 생성만 하고 종료 (PTY 시작 X). 외부 스크립트가 미리 ID를 잡을 때 사용.
    if cli.print_session_id {
        println!("{}", aic_common::generate_session_id());
        return Ok(());
    }

    // --shell <path>: $SHELL env override (PtyManager가 SHELL env로 셸을 spawn하므로).
    if let Some(ref shell) = cli.shell {
        // SAFETY: 단일 스레드 시점에서 env 조작 (tokio runtime 시작 전이지만 main attribute 사용 시
        // tokio가 이미 만든 상태일 수 있음 — 그래도 PtyManager spawn 전이라 안전).
        unsafe {
            std::env::set_var("SHELL", shell);
        }
    }

    // --no-hook: 향후 PtyManager에 전달 예정. 현재는 no-op이지만 surface는 노출.
    let _no_hook = cli.no_hook;

    // -1. telemetry 초기화 (stderr + ~/.local/state/aic/server.log JSONL daily rotate, max 7일)
    let _telemetry_guard = telemetry::init().ok();
    aic_server::metrics::init();

    // 0. Session_ID 생성 및 세션별 소켓/lock 경로 결정
    let session_id = aic_common::generate_session_id();
    let session_dir = aic_common::session_dir();
    std::fs::create_dir_all(&session_dir)
        .map_err(|e| anyhow::anyhow!("세션 디렉토리 생성 실패: {} — {e}", session_dir.display()))?;

    // Stale 세션 정리 — 이전 비정상 종료로 남은 소켓/PID 파일 삭제
    aic_server::lock::cleanup_stale_sessions();

    let sock = aic_common::session_socket_path(&session_id);
    let lock_path = sock.with_extension("pid"); // session-{id}.pid

    // 세션별 PID lock 획득 — 동일 Session_ID의 중복 실행만 방지
    let _daemon_lock = match DaemonLock::acquire(&lock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("⚠ {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        session_id = %session_id,
        pid = std::process::id(),
        socket = %sock.display(),
        lock = %lock_path.display(),
        "aic-session 시작 — Session_ID 생성, PID lock 획득"
    );

    let (rows, cols) = get_terminal_size();

    // 1. PTY 셸 실행
    let mut pty = PtyManager::spawn_shell(rows, cols, &session_id)?;
    let hook_status = pty.check_hook_status();
    let shell_name = pty.shell_name().to_string();
    let reader = pty.take_reader()?;
    let mut writer = pty.take_writer()?;

    // 1.5. 훅 설정 확인 및 처리
    match hook_status {
        aic_server::pty_manager::HookStatus::Configured => {
            // 이미 설정됨, 아무것도 안 함
        }
        aic_server::pty_manager::HookStatus::NeedsSetup { fallback_path } => {
            // 안내 메시지 출력
            let msg = aic_server::pty_manager::get_hook_setup_message(&shell_name);
            if !msg.is_empty() {
                eprintln!("{}", msg);
            }
            // 폴백: source 명령어로 훅 주입
            std::thread::sleep(std::time::Duration::from_millis(200));
            let source_cmd = format!("source '{}' 2>/dev/null\n", fallback_path.display());
            writer.write_all(source_cmd.as_bytes())?;
            writer.flush()?;
        }
        aic_server::pty_manager::HookStatus::Unsupported => {
            // 지원하지 않는 셸, TimingHeuristic으로 폴백 (이미 설정됨)
        }
    }

    // 2. 터미널 raw mode 설정
    let orig_termios = set_raw_mode()?;

    // 3. 공유 상태 생성
    let ring_buffer = Arc::new(RwLock::new(RingBuffer::new(500)));

    // 4. UDS 서버 바인딩 (sock은 main 시작 시 lock 획득과 함께 결정됨)
    let uds_server = UdsServer::bind(&sock).await?;
    tracing::info!(shell = %shell_name, socket = %sock.display(), "PTY 셸 spawn 및 UDS 서버 bind 완료");

    // 5. UDS 서버 루프
    let buf_for_uds = Arc::clone(&ring_buffer);
    let uds_handle = tokio::spawn(async move {
        uds_server.serve(buf_for_uds).await;
    });

    // 5.5. aicd registry에 best-effort 등록 — aicd가 미실행이면 silent skip한다.
    //      Phase 1.4: 이 단계에서는 PTY ownership을 옮기지 않고, 단지 supervisor에게
    //      "이 세션이 활성"임을 알려 `aic sessions`/`status`가 중앙 registry를
    //      소스 오브 트루스로 쓰게 한다.
    let session_info_for_register = aic_common::SessionInfo {
        id: session_id.clone(),
        pid: std::process::id(),
        state: aic_common::SessionState::Attached,
        created_at: chrono::Utc::now(),
        attached_tty: aic_server::aicd_client::current_tty(),
        shell: Some(shell_name.clone()),
        cwd: std::env::current_dir().ok(),
    };
    aic_server::aicd_client::register_session(session_info_for_register).await;

    // 6. stdin → PTY 입력 relay (blocking thread)
    let stdin_handle = tokio::task::spawn_blocking(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
                Err(_) => break,
            }
        }
    });

    // 7. PTY 출력 → OutputProcessor → stdout + CommandBoundaryDetector → RingBuffer
    let buf_for_output = Arc::clone(&ring_buffer);
    let output_handle = tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut processor = OutputProcessor::new();
        let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
            marker_sequence: "osc133".to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        let mut buf = [0u8; 4096];

        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buf[..n];
                    let output = processor.process(chunk);

                    // passthrough: 원본 바이트를 사용자 터미널로 출력
                    let _ = stdout.write_all(&output.passthrough);
                    let _ = stdout.flush();

                    // OSC 133 마커를 먼저 boundary detector에 전달
                    for marker in &output.osc133_markers {
                        if let Some(record) = detector.feed_line(marker) {
                            let buf_clone = buf_for_output.clone();
                            let rt = tokio::runtime::Handle::current();
                            rt.block_on(async {
                                let mut rb = buf_clone.write().await;
                                if should_store_record(&record) {
                                    rb.push(record);
                                }
                            });
                        }
                    }

                    // clean text가 있으면 CommandBoundaryDetector → RingBuffer
                    if let Some(ref text) = output.clean_text {
                        for line in text.lines() {
                            if let Some(record) = detector.feed_line(line) {
                                let buf_clone = buf_for_output.clone();
                                // RingBuffer에 동기적으로 쓰기 (blocking context)
                                let rt = tokio::runtime::Handle::current();
                                rt.block_on(async {
                                    let mut rb = buf_clone.write().await;
                                    if should_store_record(&record) {
                                        rb.push(record);
                                    }
                                });
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 8. SIGWINCH 핸들러
    let pty_master_for_resize = Arc::new(std::sync::Mutex::new(pty));
    let pty_for_sigwinch = Arc::clone(&pty_master_for_resize);
    let sigwinch_handle = tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = match signal(SignalKind::window_change()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("SIGWINCH 핸들러 등록 실패: {e}");
                return;
            }
        };
        while sig.recv().await.is_some() {
            let (rows, cols) = get_terminal_size();
            if let Ok(pty) = pty_for_sigwinch.lock() {
                let _ = pty.resize(rows, cols);
            }
        }
    });

    // 9. 셸 종료 대기
    //    중요: SIGWINCH 핸들러도 같은 mutex를 잡으므로, lock 안에서 wait하면 데드락이다.
    //    spawn 직전에 짧게 lock 잡고 child만 take, lock 해제 후 lock 밖에서 wait한다.
    let mut child_for_wait = pty_master_for_resize
        .lock()
        .ok()
        .and_then(|mut pty| pty.take_child());
    let wait_handle = tokio::task::spawn_blocking(move || {
        if let Some(child) = child_for_wait.as_mut() {
            let _ = child.wait();
        }
    });

    // 9.5 외부 종료 시그널 핸들러 (SIGTERM, SIGINT)
    //     셸 종료/PTY EOF/외부 시그널 중 먼저 발생하는 것을 트리거로 정리한다.
    let shutdown_signal = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        match (sigterm.as_mut(), sigint.as_mut()) {
            (Some(t), Some(i)) => {
                tokio::select! {
                    _ = t.recv() => "SIGTERM",
                    _ = i.recv() => "SIGINT",
                }
            }
            (Some(t), None) => {
                t.recv().await;
                "SIGTERM"
            }
            (None, Some(i)) => {
                i.recv().await;
                "SIGINT"
            }
            (None, None) => std::future::pending().await,
        }
    };

    // 셸 종료 / PTY 출력 종료 / 외부 시그널 중 먼저 발생하는 것을 대기
    let trigger = tokio::select! {
        _ = wait_handle => "shell-exit",
        _ = output_handle => "pty-eof",
        sig = shutdown_signal => sig,
    };

    // 10. Graceful 정리
    //     순서: 터미널 복원 → aicd unregister → 백그라운드 task abort → 세션 소켓 unlink
    //     → DaemonLock drop(자동 lock 해제)
    restore_terminal(&orig_termios);
    aic_server::aicd_client::unregister_session(&session_id).await;
    uds_handle.abort();
    stdin_handle.abort();
    sigwinch_handle.abort();
    let _ = std::fs::remove_file(&sock); // session-{session_id}.sock 삭제

    tracing::info!(
        trigger = trigger,
        session_id = %session_id,
        socket = %sock.display(),
        "aic-session shutdown — 세션 소켓 삭제 완료"
    );

    // _daemon_lock은 함수 종료 시 자동 drop → fcntl lock 해제 (PID 파일은 stale 정리로 처리)
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn record(command: Option<&str>) -> CommandRecord {
        CommandRecord {
            command: command.map(str::to_string),
            exit_code: 1,
            output_lines: vec!["output".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        }
    }

    #[test]
    fn stores_user_commands() {
        assert!(should_store_record(&record(Some("cargo build"))));
        assert!(should_store_record(&record(Some("/usr/bin/git status"))));
        assert!(should_store_record(&record(None)));
    }

    #[test]
    fn skips_aic_internal_commands() {
        assert!(!should_store_record(&record(Some("aic"))));
        assert!(!should_store_record(&record(Some("aic --help"))));
        assert!(!should_store_record(&record(Some("ac status"))));
        assert!(!should_store_record(&record(Some("/tmp/bin/aic-session"))));
    }
}
