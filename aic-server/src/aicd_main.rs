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
use aic_server::agent_event_bus::AgentEventBus;
use aic_server::attach_server::AttachServer;
use aic_server::command_record_store::CommandRecordStore;
use aic_server::control_server::{spawn_reconcile_loop, ControlContext, ControlServer};
use aic_server::lock::DaemonLock;
use aic_server::otlp_exporter::Spool as OtlpSpool;
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
    version = env!("AIC_BUILD_INFO")
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
    // t7: events exporter가 tap을 구독하려면 ControlContext로 move되기 전에 clone해 둬야 한다.
    let events_record_store = record_store.clone();
    let metrics = Arc::new(aic_server::metrics::AicdMetrics::new());
    // agent exporter도 같은 이유로 bus를 미리 clone해 둔다 — ControlContext가 소유권을 가져간다.
    let agent_bus = AgentEventBus::new();
    let exporter_agent_bus = agent_bus.clone();

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
        agent_bus,
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

    // SRE t6/t7/t8: OTLP exporter 3종(host metrics/events/connections) 모두 같은 `[aicd.exporter]`
    // 섹션을 읽고, enabled+endpoint 유효할 때 같은 오프라인 spool(t8, `~/.aic/otlp-spool/`)을
    // `Arc`로 공유한다 — 파일 스캔·상한 추적을 한 곳에서 일관되게 하기 위함(otlp_exporter 모듈
    // doc 참고). 섹션을 한 번만 읽어 세 load_*_config에 넘긴다(이전엔 함수마다 파일을 따로
    // 읽었다).
    let exporter_section = read_exporter_section();
    let exporter_spool = open_exporter_spool(exporter_section.as_ref());

    // SRE t6: OTLP host-metrics exporter (opt-in). 별도 task로 주기 수집→push 루프를 띄우고 동일
    // shutdown watch를 공유한다(webhook과 같은 패턴). off면 아래 config가 None이라 task 자체가
    // 뜨지 않아 코드 경로가 완전히 비활성이다(기존 동작 회귀 0). t8: spool의 유일한 드레인 주체
    // (enabled=true면 반드시 뜨는 유일한 task라서 — otlp_exporter 모듈 doc 참고).
    let exporter_handle = match load_exporter_config(exporter_section.clone(), exporter_spool.clone()) {
        Some(cfg) => {
            let ex_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::serve(cfg, ex_shutdown).await {
                    tracing::warn!(error = %e, "OTLP exporter 종료(에러)");
                }
            }))
        }
        None => None,
    };

    // SRE t7: OTLP events exporter (opt-in, [aicd.exporter] enabled=true + events_enabled=true).
    // CommandRecordStore tap을 구독해 finished command record를 실시간으로 push한다. host
    // metrics(exporter_handle)와 독립적으로 켜고 끌 수 있어 별도 task로 뜬다.
    let events_handle = match load_events_config(events_record_store, exporter_section.clone(), exporter_spool.clone()) {
        Some(cfg) => {
            let ev_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::serve_events(cfg, ev_shutdown).await {
                    tracing::warn!(error = %e, "OTLP events exporter 종료(에러)");
                }
            }))
        }
        None => None,
    };

    // SRE t7: OTLP connections exporter (opt-in, [aicd.exporter] enabled=true +
    // connections_enabled=true). 주기적으로 `aic snapshot inventory --json`을 spawn한다.
    let connections_handle = match load_connections_config(exporter_section.clone(), exporter_spool.clone()) {
        Some(cfg) => {
            let conn_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::serve_connections(cfg, conn_shutdown).await {
                    tracing::warn!(error = %e, "OTLP connections exporter 종료(에러)");
                }
            }))
        }
        None => None,
    };

    // OTLP agent exporter (opt-in, [aicd.exporter] enabled=true + agent_enabled=true).
    // AgentEventBus tap을 구독해 chat/agent 행위를 실시간으로 push한다. events와 같은 push 기반
    // 구조지만, 소스가 store가 아니라 bus라 별도 task로 둔다.
    let agent_handle = match load_agent_config(
        exporter_agent_bus,
        exporter_section.clone(),
        exporter_spool.clone(),
    ) {
        Some(cfg) => {
            let ag_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::serve_agent(cfg, ag_shutdown).await {
                    tracing::warn!(error = %e, "OTLP agent exporter 종료(에러)");
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
    // exporter task도 동일 shutdown watch를 구독하므로 graceful 종료된다.
    if let Some(h) = exporter_handle {
        let _ = h.await;
    }
    // t7: events/connections exporter도 동일 shutdown watch를 구독하므로 graceful 종료된다.
    if let Some(h) = events_handle {
        let _ = h.await;
    }
    if let Some(h) = connections_handle {
        let _ = h.await;
    }
    if let Some(h) = agent_handle {
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
    let aic_bin = resolve_aic_bin();
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

/// config.toml `[aicd.exporter]` 섹션을 읽는다. 세 exporter task(host metrics/events/connections)가
/// 공유하는 단일 파싱 지점 — spool을 셋이 공유해야 해서(t8) 예전처럼 함수마다 따로 읽지 않는다.
/// 파일이 없거나 파싱에 실패하면 `None`(= 세 exporter 모두 비활성, 기존 동작과 동일).
fn read_exporter_section() -> Option<aic_common::AicdExporterConfig> {
    let path = aic_common::paths::config_file_path();
    let content = std::fs::read_to_string(&path).ok()?;
    let app: aic_common::AppConfig = toml::from_str(&content)
        .map_err(|e| tracing::warn!(error = %e, "config 파싱 실패 — exporter 비활성"))
        .ok()?;
    Some(app.aicd.exporter)
}

/// `[aicd.exporter]`가 활성(enabled+endpoint 유효)이면 오프라인 spool(t8, `~/.aic/otlp-spool/`)을
/// 열어 세 exporter task가 공유할 `Arc`로 반환한다. 디렉토리를 못 열면(권한 등) spool 없이 exporter
/// 전체를 비활성 처리한다 — spool 없는 "즉시 skip" 폴백 모드는 따로 두지 않는다(무유실 보장이
/// exporter의 존재 이유라, spool이 없으면 t6/t7 시절 동작으로 조용히 되돌아가는 것보다 명시적으로
/// 꺼지는 편이 안전하다).
fn open_exporter_spool(ex: Option<&aic_common::AicdExporterConfig>) -> Option<Arc<OtlpSpool>> {
    let ex = ex?;
    if !ex.enabled || ex.endpoint.trim().is_empty() {
        return None;
    }
    match OtlpSpool::open(aic_common::paths::otlp_spool_dir(), ex.spool_max_bytes) {
        Ok(spool) => Some(Arc::new(spool)),
        Err(e) => {
            tracing::warn!(error = %e, "OTLP spool 디렉토리 열기 실패 — exporter 전체 비활성");
            None
        }
    }
}

/// `[aicd.exporter]`(이미 파싱된 섹션)와 공유 spool로부터 OTLP host-metrics exporter 설정을
/// 만든다(활성+endpoint 유효+spool 준비 완료일 때만 Some). token은 환경변수
/// `AIC_EXPORTER_TOKEN`가 config 평문보다 우선한다(aicd는 keychain 미resolve — webhook secret과
/// 동일 관례).
fn load_exporter_config(
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
) -> Option<aic_server::otlp_exporter::ExporterConfig> {
    let ex = ex?;
    if !ex.enabled {
        return None;
    }
    if ex.endpoint.trim().is_empty() {
        tracing::warn!("exporter enabled이지만 endpoint 미설정 — exporter 비활성");
        return None;
    }
    let spool = spool?; // open_exporter_spool이 이미 같은 조건으로 시도 — 실패했으면 여기도 비활성.
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::ExporterConfig {
        endpoint: ex.endpoint,
        token,
        interval: std::time::Duration::from_secs(ex.interval_secs.max(1)),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        spool,
        drain_batch_limit: ex.spool_drain_batch_limit,
    })
}

/// aicd 옆에 있는 `aic` 바이너리를 우선, 없으면 PATH — webhook(`aic diagnose` spawn)과 t7
/// connections exporter(`aic snapshot inventory` spawn)가 공유하는 탐색 규칙.
fn resolve_aic_bin() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("aic")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("aic"))
}

/// `[aicd.exporter]`(이미 파싱된 섹션)와 공유 spool로부터 OTLP events exporter 설정을 만든다
/// (exporter 전체 enabled + `events_enabled` 둘 다 true + endpoint 유효 + spool 준비 완료일 때만
/// Some). `store`는 호출부가 미리 clone해 넘긴 tap 구독용 `CommandRecordStore`.
fn load_events_config(
    store: CommandRecordStore,
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
) -> Option<aic_server::otlp_exporter::EventsConfig> {
    let ex = ex?;
    if !ex.enabled || !ex.events_enabled {
        return None;
    }
    if ex.endpoint.trim().is_empty() {
        tracing::warn!("exporter enabled이지만 endpoint 미설정 — events exporter 비활성");
        return None;
    }
    let spool = spool?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::EventsConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        store,
        spool,
    })
}

/// `[aicd.exporter]`(이미 파싱된 섹션)와 공유 spool로부터 OTLP connections exporter 설정을 만든다
/// (exporter 전체 enabled + `connections_enabled` 둘 다 true + endpoint 유효 + spool 준비 완료일
/// 때만 Some).
/// `[aicd.exporter]`와 공유 spool로부터 OTLP agent exporter 설정을 만든다(exporter 전체
/// enabled + `agent_enabled` 둘 다 true + endpoint 유효 + spool 준비 완료일 때만 Some).
/// `bus`는 호출부가 미리 clone해 넘긴 tap — ControlContext가 원본 소유권을 가져가기 때문이다.
fn load_agent_config(
    bus: AgentEventBus,
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
) -> Option<aic_server::otlp_exporter::AgentConfig> {
    let ex = ex?;
    if !ex.enabled || !ex.agent_enabled {
        return None;
    }
    if ex.endpoint.trim().is_empty() {
        tracing::warn!("exporter enabled이지만 endpoint 미설정 — agent exporter 비활성");
        return None;
    }
    let spool = spool?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::AgentConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        bus,
        spool,
    })
}

fn load_connections_config(
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
) -> Option<aic_server::otlp_exporter::ConnectionsConfig> {
    let ex = ex?;
    if !ex.enabled || !ex.connections_enabled {
        return None;
    }
    if ex.endpoint.trim().is_empty() {
        tracing::warn!("exporter enabled이지만 endpoint 미설정 — connections exporter 비활성");
        return None;
    }
    let spool = spool?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::ConnectionsConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        interval: std::time::Duration::from_secs(ex.connections_interval_secs.max(1)),
        aic_bin: resolve_aic_bin(),
        timeout: std::time::Duration::from_secs(15),
        spool,
    })
}
