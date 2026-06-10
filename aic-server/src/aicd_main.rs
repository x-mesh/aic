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

use aic_common::{
    aicd_attach_socket_path, aicd_lock_path, aicd_registry_path, aicd_socket_path,
};
use aic_server::attach_server::AttachServer;
use aic_server::command_record_store::CommandRecordStore;
use aic_server::control_server::{spawn_reconcile_loop, ControlContext, ControlServer};
use aic_server::lock::DaemonLock;
use aic_server::session_processor_pool::SessionProcessorPool;
use aic_server::session_registry::SessionRegistry;
use clap::Parser;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;

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

    // shutdown 신호 — control Shutdown 요청 또는 signal에서 사용. watch는
    // level-triggered라 control/attach serve 루프가 모두 같은 채널을 구독해도
    // 한 번의 send(true)로 둘 다 깨어난다 (Notify::notify_one은 한쪽만 깨워 hang).
    let (shutdown, _shutdown_rx) = watch::channel(false);

    // SIGINT/SIGTERM → shutdown 신호
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler 등록 실패");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler 등록 실패");
        tokio::select! {
            _ = sigint.recv() => tracing::info!("SIGINT 수신"),
            _ = sigterm.recv() => tracing::info!("SIGTERM 수신"),
        }
        signal_shutdown.send_replace(true);
    });

    let registry_path = aicd_registry_path();
    let registry = match SessionRegistry::load_snapshot(&registry_path, chrono::Utc::now()) {
        Ok(registry) => {
            tracing::info!(path = %registry_path.display(), count = registry.len().await, "registry snapshot 로드");
            registry
        }
        Err(e) => {
            tracing::warn!(path = %registry_path.display(), error = %e, "registry snapshot 로드 실패, 빈 registry 사용");
            SessionRegistry::new()
        }
    };
    let record_store = CommandRecordStore::new();
    let metrics = Arc::new(aic_server::metrics::AicdMetrics::new());

    // Attach_UDS (R5.1, R5.2) — aic-session 이 PTY bytes 를 중앙으로 보내는 경로.
    // Control_UDS 와는 완전히 분리된 소켓이며, SessionProcessorPool + CommandRecordStore
    // 를 공유해 받은 bytes 를 바로 session 별 record 로 구성한다 (R5.9, R5.10).
    //
    // bind 에 실패하면 aicd 전체 기동을 abort — attach 가 없으면 Phase 3.4
    // 빌드의 aic-session 은 Local_Fallback 으로 내려가 RSS 개선이 사라진다.
    let attach_sock_path = aicd_attach_socket_path();
    let attach_pool = Arc::new(SessionProcessorPool::new());
    let attach_server = AttachServer::bind(
        &attach_sock_path,
        Arc::clone(&metrics),
        Arc::clone(&attach_pool),
        record_store.clone(),
    )
    .await?;
    tracing::info!(path = %attach_sock_path.display(), "aicd attach 소켓 바인드");

    let control_ctx = ControlContext {
        shutdown: shutdown.clone(),
        registry: registry.clone(),
        record_store,
        registry_path: Some(registry_path.clone()),
        metrics,
    };

    // 주기적 stale 세션 reconcile — request 트래픽이 없어도 active → detached 전환이 수렴하도록.
    let reconcile_handle = spawn_reconcile_loop(control_ctx.clone());

    // AttachServer 는 별도 task 로 spawn 하여 Control_UDS serve 루프와 나란히 동작한다.
    // 같은 `shutdown` Notify 를 공유하므로 SIGTERM/Shutdown 요청 시 둘 다 깨어난다.
    let attach_shutdown = shutdown.clone();
    let attach_handle = tokio::spawn(async move {
        attach_server.serve(attach_shutdown).await;
    });

    // SRE R2: webhook alert ingestion (opt-in). config [aicd.webhook]에서 활성화 시
    // 별도 task로 HTTP 리스너를 띄우고 동일 shutdown watch를 공유한다(graceful 종료).
    let webhook_handle = match load_webhook_config() {
        Some(cfg) => {
            let wh_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::webhook_server::serve(cfg, wh_shutdown).await {
                    tracing::warn!(error = %e, "webhook 리스너 종료(에러)");
                }
            }))
        }
        None => None,
    };

    server.serve(control_ctx).await;

    // Control 루프가 빠져나오면 attach 루프도 동일 notify 로 이미 깨어난 상태.
    // join 하여 in-flight 연결 정리 시간을 준다.
    let _ = attach_handle.await;
    // webhook 리스너도 동일 shutdown watch를 구독하므로 graceful 종료된다.
    if let Some(h) = webhook_handle {
        let _ = h.await;
    }

    reconcile_handle.abort();
    // 소켓 파일 정리 — AttachServer 는 Drop 구현이 없으므로 명시 remove.
    let _ = std::fs::remove_file(&attach_sock_path);
    if let Err(e) = registry.save_snapshot(&registry_path).await {
        tracing::warn!(path = %registry_path.display(), error = %e, "registry snapshot 최종 저장 실패");
    }
    tracing::info!("aicd 종료");
    Ok(())
}

/// config.toml `[aicd.webhook]`을 읽어 webhook 설정을 만든다(활성+유효할 때만 Some).
/// secret은 환경변수 `AIC_WEBHOOK_SECRET`가 config 평문보다 우선한다(aicd는 keychain 미resolve).
fn load_webhook_config() -> Option<aic_server::webhook_server::WebhookConfig> {
    let path = aic_common::paths::config_file_path();
    let content = std::fs::read_to_string(&path).ok()?;
    let app: aic_common::AppConfig = toml::from_str(&content)
        .map_err(|e| tracing::warn!(error = %e, "config 파싱 실패 — webhook 비활성"))
        .ok()?;
    let w = app.aicd.webhook;
    if !w.enabled {
        return None;
    }
    // aicd 옆에 있는 aic 바이너리를 우선, 없으면 PATH.
    let aic_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("aic")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("aic"));
    let secret = std::env::var("AIC_WEBHOOK_SECRET").ok().or(w.secret);
    Some(aic_server::webhook_server::WebhookConfig {
        listen_addr: w.listen_addr,
        secret,
        rate_limit_per_min: w.rate_limit_per_min,
        dedup_ttl: std::time::Duration::from_secs(w.dedup_ttl_secs),
        auto_diagnose: w.auto_diagnose,
        follow_up: w.follow_up,
        aic_bin,
    })
}
