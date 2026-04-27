//! `aicd` — 사용자당 하나의 supervisor daemon (Phase 1 sub-step 1).
//!
//! 현재 구현 범위:
//! - singleton PID lock 획득 (`aicd.pid`)
//! - control UDS 바인드 (`aicd.sock`)
//! - SIGINT/SIGTERM 또는 control `Shutdown` 신호 수신 시 종료
//! - `Ping → Pong`만 응답
//!
//! 의도적으로 비범위:
//! - session registry, attach relay, PTY ownership — 이후 sub-step에서 추가.

use aic_common::{aicd_lock_path, aicd_socket_path};
use aic_server::control_server::{ControlContext, ControlServer};
use aic_server::hook_events::HookEventStore;
use aic_server::lock::DaemonLock;
use aic_server::session_registry::SessionRegistry;
use clap::Parser;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;

/// aicd CLI.
#[derive(Debug, Parser)]
#[command(
    name = "aicd",
    about = "aic supervisor daemon",
    long_about = "aicd: 사용자당 하나만 실행되는 supervisor daemon. \
                  control UDS를 통해 aic CLI와 aic-session에 lifecycle/registry를 제공한다.",
    version
)]
struct Cli {
    /// 로그를 stderr로 출력 (default는 tracing의 기본 layer 사용).
    #[arg(long)]
    foreground: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let _telemetry = aic_server::telemetry::init()?;
    tracing::info!(
        pid = std::process::id(),
        foreground = cli.foreground,
        "aicd 시작"
    );

    // singleton lock — 이미 실행 중이면 즉시 실패한다.
    let lock_path = aicd_lock_path();
    let _lock = DaemonLock::acquire(&lock_path).map_err(|e| {
        eprintln!("aicd 시작 실패: {e}");
        e
    })?;
    tracing::info!(path = %lock_path.display(), "aicd lock 획득");

    // control UDS bind
    let sock_path = aicd_socket_path();
    let server = ControlServer::bind(&sock_path).await?;
    tracing::info!(path = %server.socket_path().display(), "aicd control 소켓 바인드");

    // shutdown notify — control Shutdown(추후) 또는 signal에서 사용.
    let shutdown = Arc::new(Notify::new());

    // SIGINT/SIGTERM → shutdown notify
    let signal_shutdown = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler 등록 실패");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler 등록 실패");
        tokio::select! {
            _ = sigint.recv() => tracing::info!("SIGINT 수신"),
            _ = sigterm.recv() => tracing::info!("SIGTERM 수신"),
        }
        signal_shutdown.notify_one();
    });

    let registry = SessionRegistry::new();
    let hook_events = HookEventStore::new();
    server
        .serve(ControlContext {
            shutdown,
            registry,
            hook_events,
        })
        .await;
    tracing::info!("aicd 종료");
    Ok(())
}
