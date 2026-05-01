//! `aic-session` runtime orchestration.
//!
//! Binary `main.rs` is intentionally kept thin: CLI parsing, environment setup,
//! telemetry, and then this runtime.

use crate::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use crate::lock::DaemonLock;
use crate::output_processor::OutputProcessor;
use crate::pty_manager::{HookPolicy, PtyManager};
use crate::ring_buffer::RingBuffer;
use crate::uds_server::UdsServer;
use aic_common::CommandRecord;
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Runtime options derived from the `aic-session` CLI.
#[derive(Debug, Clone, Copy)]
pub struct SessionRuntimeConfig {
    pub hook_policy: HookPolicy,
}

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
            (24, 80)
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

/// Run one foreground `aic-session` until the shell exits, PTY reaches EOF, or
/// the process receives SIGTERM/SIGINT.
pub async fn run(config: SessionRuntimeConfig) -> anyhow::Result<()> {
    // 0. Session_ID 생성 및 세션별 소켓/lock 경로 결정
    let session_dir = aic_common::session_dir();
    std::fs::create_dir_all(&session_dir)
        .map_err(|e| anyhow::anyhow!("세션 디렉토리 생성 실패: {} — {e}", session_dir.display()))?;

    // Stale 세션 정리 — 이전 비정상 종료로 남은 소켓/PID 파일 삭제
    crate::lock::cleanup_stale_sessions();

    let session_id = aic_common::generate_unused_session_id(16)
        .ok_or_else(|| anyhow::anyhow!("충돌 없는 Session_ID를 생성하지 못했습니다"))?;
    let sock = aic_common::session_socket_path(&session_id);
    let lock_path = sock.with_extension("pid");

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
    let mut pty =
        PtyManager::spawn_shell_with_hook_policy(rows, cols, &session_id, config.hook_policy)?;
    let hook_status = pty.check_hook_status();
    let shell_name = pty.shell_name().to_string();
    let reader = pty.take_reader()?;
    let mut writer = pty.take_writer()?;

    // 1.5. 훅 설정 확인 및 처리
    match hook_status {
        crate::pty_manager::HookStatus::Configured => {}
        crate::pty_manager::HookStatus::NeedsSetup { fallback_path } => {
            let msg = crate::pty_manager::get_hook_setup_message(&shell_name);
            if !msg.is_empty() {
                eprintln!("{}", msg);
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            let source_cmd = format!("source '{}' 2>/dev/null\n", fallback_path.display());
            writer.write_all(source_cmd.as_bytes())?;
            writer.flush()?;
        }
        crate::pty_manager::HookStatus::Unsupported => {}
        crate::pty_manager::HookStatus::Disabled => {}
    }

    // 2. 터미널 raw mode 설정
    let orig_termios = set_raw_mode()?;

    // 3. 공유 상태 생성
    let ring_buffer = Arc::new(RwLock::new(RingBuffer::new(500)));

    // 4. UDS 서버 바인딩
    let uds_server = UdsServer::bind(&sock).await?;
    tracing::info!(shell = %shell_name, socket = %sock.display(), "PTY 셸 spawn 및 UDS 서버 bind 완료");

    // 5. UDS 서버 루프
    let buf_for_uds = Arc::clone(&ring_buffer);
    let uds_handle = tokio::spawn(async move {
        uds_server.serve(buf_for_uds).await;
    });

    // 5.5. aicd registry에 best-effort 등록 — aicd가 미실행이면 silent skip한다.
    let now = chrono::Utc::now();
    let session_info_for_register = aic_common::SessionInfo {
        id: session_id.clone(),
        pid: std::process::id(),
        state: aic_common::SessionState::Attached,
        created_at: now,
        last_seen_at: Some(now),
        last_command_at: None,
        attached_tty: crate::aicd_client::current_tty(),
        shell: Some(shell_name.clone()),
        cwd: std::env::current_dir().ok(),
        label: None,
    };
    crate::aicd_client::register_session(session_info_for_register).await;

    let heartbeat_session_id = session_id.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            // The parent aic-session process cwd does not follow `cd` inside the
            // child shell. Keep heartbeat as liveness-only so hook-reported cwd
            // is not overwritten by stale parent cwd.
            crate::aicd_client::heartbeat_session(&heartbeat_session_id, None).await;
        }
    });

    // 6. stdin → PTY 입력 relay (blocking thread)
    let stdin_handle = tokio::task::spawn_blocking(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
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

                    let _ = stdout.write_all(&output.passthrough);
                    let _ = stdout.flush();

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

                    if let Some(ref text) = output.clean_text {
                        for line in text.lines() {
                            if let Some(record) = detector.feed_line(line) {
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

    let trigger = tokio::select! {
        _ = wait_handle => "shell-exit",
        _ = output_handle => "pty-eof",
        sig = shutdown_signal => sig,
    };

    // 10. Graceful 정리
    restore_terminal(&orig_termios);
    crate::aicd_client::unregister_session(&session_id).await;
    uds_handle.abort();
    stdin_handle.abort();
    heartbeat_handle.abort();
    sigwinch_handle.abort();
    let _ = std::fs::remove_file(&sock);

    tracing::info!(
        trigger = trigger,
        session_id = %session_id,
        socket = %sock.display(),
        "aic-session shutdown — 세션 소켓 삭제 완료"
    );

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
