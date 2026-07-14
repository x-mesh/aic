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

use aic_common::{aicd_attach_socket_path, aicd_lock_path, aicd_registry_path, aicd_socket_path};
use aic_common::{AicdExporterConfig, AicdLogsConfig, AppConfig, LogLine};
use aic_server::agent_event_bus::AgentEventBus;
use aic_server::attach_server::AttachServer;
use aic_server::command_record_store::CommandRecordStore;
use aic_server::control_server::{spawn_reconcile_loop, ControlContext, ControlServer};
use aic_server::lock::DaemonLock;
use aic_server::otlp_exporter::logs::checkpoint::CheckpointStore;
use aic_server::otlp_exporter::logs::container::{
    ContainerCollectorConfig, ContainerParseCounters,
};
use aic_server::otlp_exporter::logs::file::FileTail;
use aic_server::otlp_exporter::logs::journald::JournaldCollectorConfig;
use aic_server::otlp_exporter::logs::{serve_logs, DropCounters, LogsExporterConfig};
use aic_server::otlp_exporter::Spool as OtlpSpool;
use aic_server::session_processor_pool::SessionProcessorPool;
use aic_server::session_registry::SessionRegistry;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};

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

    // RFC-006 로그 수집기 — self-log layer는 tracing subscriber를 단 한 번(전역 `.init()`)만
    // 등록할 수 있어, 뒤에서 `read_exporter_section`/`read_logs_config`(경고 로깅 포함, 의도적으로
    // telemetry 초기화 이후에 호출한다)로 다시 읽기 전에 "로그 채널을 만들지/self 수집기를 붙일지"
    // 를 미리 알아야 한다. 그래서 `precheck_logs_gate`가 조용히(경고 없이) 같은 config.toml을
    // 한 번 더 파싱해 두 게이트만 뽑는다 — 실패하면 항상 off(로그는 기본 opt-in이므로 안전한
    // 폴백). 여기서 만든 채널은 이후 ControlContext.logs_tx / serve_logs / 각 수집기가 그대로
    // 재사용한다(같은 채널 하나를 여러 producer가 공유).
    let logs_precheck = precheck_logs_gate();
    let (logs_tx, logs_rx): (
        Option<mpsc::Sender<LogLine>>,
        Option<mpsc::Receiver<LogLine>>,
    ) = if logs_precheck.parent_enabled {
        let (tx, rx) = mpsc::channel(LOGS_CHANNEL_CAPACITY);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let self_log_tx = if logs_precheck.self_enabled {
        logs_tx.clone()
    } else {
        None
    };

    let _telemetry = aic_server::telemetry::init_with_logs(self_log_tx)?;
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

    // SRE t6/t7/t8: OTLP exporter 3종(host metrics/events/connections) 모두 같은 `[aicd.exporter]`
    // 섹션을 읽고, enabled+endpoint 유효할 때 같은 오프라인 spool(t8, `~/.aic/otlp-spool/`)을
    // `Arc`로 공유한다 — 파일 스캔·상한 추적을 한 곳에서 일관되게 하기 위함(otlp_exporter 모듈
    // doc 참고). 섹션을 한 번만 읽어 세 load_*_config에 넘긴다(이전엔 함수마다 파일을 따로
    // 읽었다).
    let exporter_section = read_exporter_section();
    let exporter_spool = open_exporter_spool(exporter_section.as_ref());
    // [aicd.logs] 섹션(SRE R2/RFC-006). 섹션이 없거나 config 자체를 못 읽어도 항상
    // `AicdLogsConfig::default()`가 나온다(하위 수집기 전부 off) — Option을 쓰지 않는 이유는
    // exporter_section과 달리 이 값 자체에 이미 "완전 비활성"을 표현하는 안전한 기본이 있어서다.
    let logs_section = read_logs_config();
    // logs exporter(`serve_logs`)와 metrics exporter(`serve`)가 `aic.log.dropped` 카운터를
    // 공유해야 metrics 쪽 게이지가 실제 드롭을 반영한다(t6가 남긴 배선 부채 — 안 그러면 항상 0).
    let log_drop_counters = Arc::new(DropCounters::new());
    // 네 exporter task가 공유하는 전송 건강 카운터. chat status bar가 `GetExporterStatus`로 읽어
    // "지금 서버로 나가고 있나"를 사람 눈에 보이게 한다. exporter가 비활성이면 None이고, IPC는
    // `enabled: false`를 돌려준다(꺼짐과 실패는 사용자에게 전혀 다른 상태다).
    let exporter_health = exporter_spool.as_ref().map(|spool| {
        Arc::new(aic_server::otlp_exporter::ExporterHealth::new(
            exporter_section
                .as_ref()
                .map(|ex| ex.endpoint.clone())
                .unwrap_or_default(),
            spool.clone(),
        ))
    });

    let control_ctx = ControlContext {
        shutdown: shutdown.clone(),
        registry: registry.clone(),
        record_store,
        registry_path: Some(registry_path.clone()),
        metrics,
        agent_bus,
        exporter_health: exporter_health.clone(),
        // t12: logs exporter가 배선되어 채널이 생겼으면(`logs_precheck.parent_enabled`) 그 Sender를
        // 그대로 공유한다 — `aic-client`의 `PushLogLines`가 이 채널을 통해 serve_logs까지 흐른다.
        // 로그가 off(기본)면 `None` 그대로라 기존 동작(수신은 하되 조용히 버림)과 동일하다.
        logs_tx: logs_tx.clone(),
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

    // SRE t6: OTLP host-metrics exporter (opt-in). 별도 task로 주기 수집→push 루프를 띄우고 동일
    // shutdown watch를 공유한다(webhook과 같은 패턴). off면 아래 config가 None이라 task 자체가
    // 뜨지 않아 코드 경로가 완전히 비활성이다(기존 동작 회귀 0). t8: spool의 유일한 드레인 주체
    // (enabled=true면 반드시 뜨는 유일한 task라서 — otlp_exporter 모듈 doc 참고).
    let exporter_handle = match load_exporter_config(
        exporter_section.clone(),
        exporter_spool.clone(),
        exporter_health.clone(),
        log_drop_counters.clone(),
    ) {
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
    let events_handle = match load_events_config(
        events_record_store,
        exporter_section.clone(),
        exporter_spool.clone(),
        exporter_health.clone(),
    ) {
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
    let connections_handle = match load_connections_config(
        exporter_section.clone(),
        exporter_spool.clone(),
        exporter_health.clone(),
    ) {
        Some(cfg) => {
            let conn_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) =
                    aic_server::otlp_exporter::serve_connections(cfg, conn_shutdown).await
                {
                    tracing::warn!(error = %e, "OTLP connections exporter 종료(에러)");
                }
            }))
        }
        None => None,
    };

    // OTLP changes exporter (opt-in, [aicd.exporter] enabled=true + changes_enabled=true).
    // 프로세스 테이블을 주기적으로 스냅샷해 직전 tick과 diff → start/exit/rss_spike 전이만 push한다.
    let changes_handle = match load_changes_config(
        exporter_section.clone(),
        exporter_spool.clone(),
        exporter_health.clone(),
    ) {
        Some(cfg) => {
            let ch_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::serve_changes(cfg, ch_shutdown).await {
                    tracing::warn!(error = %e, "OTLP changes exporter 종료(에러)");
                }
            }))
        }
        None => None,
    };

    // A3: OTLP docker exporter (opt-in, [aicd.exporter] enabled=true + docker_enabled=true —
    // 부모 게이트가 켜져도 docker_enabled 기본값 자체가 false다, otlp_exporter::docker 모듈 doc
    // 참고). 주기적으로 `docker system df --format json`을 spawn한다. host metrics tick(in-process
    // sysinfo)을 외부 프로세스 spawn이 막지 않도록 독립 task로 뜬다.
    let docker_handle = match load_docker_config(
        exporter_section.clone(),
        exporter_spool.clone(),
        exporter_health.clone(),
    ) {
        Some(cfg) => {
            let dk_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::serve_docker(cfg, dk_shutdown).await {
                    tracing::warn!(error = %e, "OTLP docker exporter 종료(에러)");
                }
            }))
        }
        None => None,
    };

    // OTLP agent exporter (opt-in, [aicd.exporter] enabled=true + agent_enabled=true).
    // AgentEventBus tap을 구독해 chat/agent 행위를 실시간으로 push한다. events와 같은 push 기반
    // 구조지만, 소스가 store가 아니라 bus라 별도 task로 둔다.
    //
    // config 플래그를 health에 먼저 새긴다 — chat이 "설정이 꺼짐"과 "설정은 켰는데 뜨지 못함"을
    // 구분해 안내하려면 **두 축 모두** 필요하다(후자에 "설정을 켜라"고 하면 오진이다).
    if let (Some(health), Some(ex)) = (exporter_health.as_ref(), exporter_section.as_ref()) {
        health.set_agent_configured(ex.enabled && ex.agent_enabled);
    }
    let agent_handle = match load_agent_config(
        exporter_agent_bus,
        exporter_section.clone(),
        exporter_spool.clone(),
        exporter_health.clone(),
    ) {
        Some(cfg) => {
            // **구독은 이미 성립했다**(load_agent_config가 spawn 전에 subscribe한다). 구독이 성립한
            // 순간이 곧 "이 이벤트는 버려지지 않는다"가 참이 되는 시점이므로, **spawn 전에** 살아있음을
            // 새긴다. task가 켜게 두면 spawn~task 시작 사이가 거짓 false인 창이 되어, 멀쩡히 전달될
            // 메모를 "유실"로 오보한다(그 창은 aicd 기동 직후 = chat이 붙는 시점과 겹친다).
            // 끄는 건 task 안의 AgentLiveGuard가 종료 시 맡는다(죽으면 false로 되돌아간다).
            if let Some(health) = exporter_health.as_ref() {
                health.set_agent_live(true);
            }
            let ag_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::serve_agent(cfg, ag_shutdown).await {
                    tracing::warn!(error = %e, "OTLP agent exporter 종료(에러)");
                }
            }))
        }
        None => None,
    };

    // ── RFC-006: aicd 로그 수집기(opt-in, [aicd.exporter] enabled=true + logs_enabled=true) ──
    //
    // 부모 게이트가 꺼져 있으면(기본) `logs_tx`/`logs_rx`가 이미 `None`이라 아래 매치들이 전부
    // `None`으로 떨어지고, serve_logs도 journald/container/file 수집기도 뜨지 않는다 — 기존
    // 5개 exporter task와 동일한 "조건부 spawn" 패턴이다. journald는 이 함수 호출 자체는
    // 플랫폼 무관이지만 `run_journald_collector`가 non-Linux에서 즉시 no-op으로 반환한다
    // (`journald.rs` 모듈 doc — "Linux 전용").
    let logs_exporter_cfg = load_logs_exporter_config(
        exporter_section.clone(),
        exporter_spool.clone(),
        exporter_health.clone(),
        logs_section.clone(),
        log_drop_counters.clone(),
    );
    let logs_handle = match (logs_exporter_cfg, logs_rx) {
        (Some(cfg), Some(rx)) => {
            let lg_shutdown = shutdown.subscribe();
            Some(tokio::spawn(async move {
                if let Err(e) = serve_logs(cfg, rx, lg_shutdown).await {
                    tracing::warn!(error = %e, "OTLP logs exporter 종료(에러)");
                }
            }))
        }
        _ => None,
    };

    // 수집기(journald/container/file) 전용 체크포인트 저장소. logs_tx가 있을 때만(=로그가 켜져
    // 있을 때만) 연다 — 디렉토리를 못 열면(권한 등) 수집기 셋 다 비활성화한다(체크포인트 없이
    // 파일/journald tail을 시작하면 재시작마다 어디까지 읽었는지 알 수 없다).
    let log_checkpoint_store = if logs_tx.is_some() {
        match CheckpointStore::open(aic_common::paths::log_checkpoint_dir()) {
            Ok(store) => Some(Arc::new(store)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "로그 체크포인트 디렉토리 열기 실패 — journald/container/file 수집기 비활성화"
                );
                None
            }
        }
    } else {
        None
    };
    let log_host = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());

    let journald_handle = match (logs_tx.clone(), log_checkpoint_store.clone()) {
        (Some(tx), Some(cp)) if logs_section.journald.enabled => {
            let jd_shutdown = shutdown.subscribe();
            let jd_cfg = JournaldCollectorConfig {
                host: log_host.clone(),
                ..Default::default()
            };
            let jd_drop = log_drop_counters.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::logs::journald::run_journald_collector(
                    jd_cfg,
                    tx,
                    jd_drop,
                    cp,
                    jd_shutdown,
                )
                .await
                {
                    tracing::warn!(error = %e, "journald 수집기 종료(에러)");
                }
            }))
        }
        _ => None,
    };

    let container_handle = match (logs_tx.clone(), log_checkpoint_store.clone()) {
        (Some(tx), Some(cp)) if logs_section.container.enabled => {
            let ct_shutdown = shutdown.subscribe();
            let ct_cfg = ContainerCollectorConfig {
                host: log_host.clone(),
                ..Default::default()
            };
            let ct_drop = log_drop_counters.clone();
            let parse_counters = Arc::new(ContainerParseCounters::new());
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::logs::container::run_container_collector(
                    ct_cfg,
                    tx,
                    cp,
                    ct_drop,
                    parse_counters,
                    ct_shutdown,
                )
                .await
                {
                    tracing::warn!(error = %e, "container 수집기 종료(에러)");
                }
            }))
        }
        _ => None,
    };

    let file_handle = match (logs_tx.clone(), log_checkpoint_store.clone()) {
        (Some(tx), Some(cp)) if !logs_section.files.is_empty() => {
            let tails: Vec<FileTail> = logs_section
                .files
                .iter()
                .map(|entry| {
                    FileTail::new(
                        PathBuf::from(&entry.path),
                        entry.label.clone(),
                        log_host.clone(),
                    )
                })
                .collect();
            let fl_shutdown = shutdown.subscribe();
            let fl_drop = log_drop_counters.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = aic_server::otlp_exporter::logs::file::serve_files(
                    tails,
                    tx,
                    cp,
                    fl_drop,
                    fl_shutdown,
                )
                .await
                {
                    tracing::warn!(error = %e, "파일 tail 수집기 종료(에러)");
                }
            }))
        }
        _ => None,
    };
    // agent exporter의 생존(`agent_live`)은 **위에서 spawn 전에 켰다**(구독이 성립한 시점이 곧
    // "이벤트가 버려지지 않는다"가 참이 되는 시점이다). 끄는 건 task 안의 `AgentLiveGuard`가
    // 종료(정상·에러·panic) 시 맡는다 — 켜기와 끄기의 주체를 나눠야 유실 창도, 단방향 래치도 없다.

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
    if let Some(h) = changes_handle {
        let _ = h.await;
    }
    if let Some(h) = docker_handle {
        let _ = h.await;
    }
    // RFC-006 로그 수집기도 동일 shutdown watch를 구독하므로 graceful 종료된다.
    if let Some(h) = logs_handle {
        let _ = h.await;
    }
    if let Some(h) = journald_handle {
        let _ = h.await;
    }
    if let Some(h) = container_handle {
        let _ = h.await;
    }
    if let Some(h) = file_handle {
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

/// logs 채널/self-log layer를 만들지 결정하기 위한 최소 게이트. `main()` 맨 앞
/// (`telemetry::init_with_logs` 호출 전)에서만 쓰인다 — 그 시점엔 아직 tracing subscriber가
/// 없어 `tracing::warn!`을 호출해도 아무 데도 기록되지 않으므로, 이 함수는 의도적으로 경고
/// 로깅을 하지 않는다(뒤에서 `read_exporter_section`/`read_logs_config`가 같은 파일을 한 번 더
/// 읽으며 경고를 남긴다 — 그때는 subscriber가 이미 준비되어 있다).
struct LogsPrecheck {
    /// 로그 채널(`logs_tx`/`logs_rx`)을 만들지. `[aicd.exporter]`의 `enabled && logs_enabled &&
    /// endpoint 유효`.
    parent_enabled: bool,
    /// self-log layer(aicd 자신의 tracing 이벤트)까지 채널에 붙일지.
    /// `parent_enabled && [aicd.logs.self].enabled`.
    self_enabled: bool,
}

fn precheck_logs_gate() -> LogsPrecheck {
    let off = LogsPrecheck {
        parent_enabled: false,
        self_enabled: false,
    };
    let path = aic_common::paths::config_file_path();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return off;
    };
    let Ok(app) = toml::from_str::<AppConfig>(&content) else {
        return off;
    };
    logs_precheck_from_config(&app)
}

/// `precheck_logs_gate`의 순수 부분 — 이미 파싱된 `AppConfig`에서 두 게이트만 뽑는다. 파일
/// I/O가 없어 단위 테스트가 결정적이다.
fn logs_precheck_from_config(app: &AppConfig) -> LogsPrecheck {
    let ex = &app.aicd.exporter;
    let parent_enabled = ex.enabled && ex.logs_enabled && !ex.endpoint.trim().is_empty();
    let self_enabled = parent_enabled && app.aicd.logs.self_.enabled;
    LogsPrecheck {
        parent_enabled,
        self_enabled,
    }
}

/// config.toml `[aicd.logs]` 섹션을 읽는다. 파일이 없거나 파싱에 실패해도 `AicdLogsConfig`의
/// `#[serde(default)]` 필드들이 전부 "off"로 떨어지므로(각 수집기 하위 설정의 `enabled` 기본이
/// false), `read_exporter_section`과 달리 `Option`이 아니라 값 자체를 반환한다 — 실패와 "섹션
/// 없음"을 호출부가 구분할 필요가 없다(둘 다 "수집기 0개"로 수렴).
fn read_logs_config() -> AicdLogsConfig {
    let path = aic_common::paths::config_file_path();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return AicdLogsConfig::default();
    };
    match toml::from_str::<AppConfig>(&content) {
        Ok(app) => app.aicd.logs,
        Err(e) => {
            tracing::warn!(error = %e, "config 파싱 실패 — 로그 수집기 전부 비활성");
            AicdLogsConfig::default()
        }
    }
}

/// logs 채널(`mpsc::channel::<LogLine>`) 용량. `max_lines_per_sec` 기본값(1000)의 몇 배를 버퍼로
/// 두어, batch flush(`batch_max_ms` 기본 2000ms) 사이 순간 버스트를 흡수한다 — 채널이 가득 차면
/// `DropCounters::by_channel_full`만 오르고 수집기는 막히지 않는다(모듈 doc 불변식).
const LOGS_CHANNEL_CAPACITY: usize = 8192;

/// `[aicd.exporter]`(enabled+logs_enabled+endpoint 유효)와 공유 spool/health, `[aicd.logs]`
/// 설정으로부터 logs exporter 설정을 만든다. 다른 `load_*_config` 헬퍼와 동일한 게이트 패턴.
fn load_logs_exporter_config(
    ex: Option<AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
    health: Option<Arc<aic_server::otlp_exporter::ExporterHealth>>,
    logs_cfg: AicdLogsConfig,
    drop_counters: Arc<DropCounters>,
) -> Option<LogsExporterConfig> {
    let ex = ex?;
    if !ex.enabled || !ex.logs_enabled {
        return None;
    }
    if ex.endpoint.trim().is_empty() {
        tracing::warn!("exporter enabled이지만 endpoint 미설정 — logs exporter 비활성");
        return None;
    }
    let spool = spool?;
    let health = health?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(LogsExporterConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        batch_max_lines: logs_cfg.batch_max_lines,
        batch_max_bytes: logs_cfg.batch_max_bytes,
        batch_max_ms: logs_cfg.batch_max_ms,
        spool,
        health,
        logs_cfg,
        drop_counters,
    })
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
    // R3: SpoolQuotas는 spool_max_bytes(기존 단일 상한)에서 metrics 25% / logs 25% / app_logs
    // 50%로 파생한다(하위호환 기본 분배) — 소스별 override는 아직 config 표면에 없다.
    let quotas =
        aic_common::SpoolQuotas::from_spool_max_bytes(ex.spool_max_bytes, None, None, None);
    match OtlpSpool::open(aic_common::paths::otlp_spool_dir(), quotas) {
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
    health: Option<Arc<aic_server::otlp_exporter::ExporterHealth>>,
    drop_counters: Arc<DropCounters>,
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
    let health = health?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::ExporterConfig {
        endpoint: ex.endpoint,
        token,
        interval: std::time::Duration::from_secs(ex.interval_secs.max(1)),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        spool,
        drain_batch_limit: ex.spool_drain_batch_limit,
        health,
        // t12: 호출부(main)가 logs exporter(`serve_logs`)와 공유하는 동일 `Arc`를 넘긴다 — 두
        // task의 카운터가 합쳐져야 `aic.log.dropped` 게이지가 실제 드롭을 반영한다.
        drop_counters,
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
    health: Option<Arc<aic_server::otlp_exporter::ExporterHealth>>,
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
    let health = health?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::EventsConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        store,
        spool,
        health,
    })
}

/// `[aicd.exporter]`(이미 파싱된 섹션)와 공유 spool로부터 OTLP connections exporter 설정을 만든다
/// (exporter 전체 enabled + `connections_enabled` 둘 다 true + endpoint 유효 + spool 준비 완료일
/// 때만 Some).
/// `[aicd.exporter]`와 공유 spool로부터 OTLP agent exporter 설정을 만든다(exporter 전체
/// enabled + `agent_enabled` 둘 다 true + endpoint 유효 + spool 준비 완료일 때만 Some).
/// `bus`는 호출부가 미리 clone해 넘긴 tap — ControlContext가 원본 소유권을 가져가기 때문이다.
///
/// **여기서 `bus.subscribe()`를 한다**(task 안이 아니라). 이 함수가 `Some`을 돌려준 시점엔 이미
/// 구독이 성립해 있으므로, 이후 publish되는 이벤트는 task가 아직 `rx.recv()`를 돌리기 전이라도
/// 채널 버퍼에 보존된다. task 안에서 구독하면 spawn~구독 사이가 "구독자 0"인 창이 되어, 그 사이
/// 이벤트가 조용히 사라진다 — aicd 기동 직후는 chat이 붙는 시점과 정확히 겹쳐 실제로 밟힌다.
fn load_agent_config(
    bus: AgentEventBus,
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
    health: Option<Arc<aic_server::otlp_exporter::ExporterHealth>>,
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
    let health = health?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::AgentConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        // 구독을 **지금** 성립시킨다 — 이 값이 존재한다는 것 자체가 "구독자 있음"이다.
        rx: bus.subscribe(),
        spool,
        health,
    })
}

fn load_connections_config(
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
    health: Option<Arc<aic_server::otlp_exporter::ExporterHealth>>,
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
    let health = health?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::ConnectionsConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        interval: std::time::Duration::from_secs(ex.connections_interval_secs.max(1)),
        aic_bin: resolve_aic_bin(),
        timeout: std::time::Duration::from_secs(15),
        spool,
        health,
    })
}

/// changes exporter 설정 로더. connections와 동일한 게이트(부모 `enabled` + 자기 플래그 +
/// endpoint)를 통과해야 task가 뜬다. `aic` 바이너리를 spawn하지 않으므로 `aic_bin`/`timeout`이
/// 없다 — 프로세스 테이블은 aicd가 sysinfo로 직접 읽는다.
fn load_changes_config(
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
    health: Option<Arc<aic_server::otlp_exporter::ExporterHealth>>,
) -> Option<aic_server::otlp_exporter::ChangesConfig> {
    let ex = ex?;
    if !ex.enabled || !ex.changes_enabled {
        return None;
    }
    if ex.endpoint.trim().is_empty() {
        tracing::warn!("exporter enabled이지만 endpoint 미설정 — changes exporter 비활성");
        return None;
    }
    let spool = spool?;
    let health = health?;
    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::ChangesConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        interval: std::time::Duration::from_secs(ex.changes_interval_secs.max(1)),
        spool,
        health,
    })
}

/// A3: docker exporter 설정 로더. `docker_enabled`는 부모 게이트(`enabled`)가 켜져도 기본
/// false다(otlp_exporter::docker 모듈 doc 참고) — 그래서 다른 로더와 달리 명시적으로 true로
/// 설정된 환경에서만 task가 뜬다.
///
/// `docker_bin`은 **기동 시 절대경로로 resolve**한다. 예전엔 `PathBuf::from("docker")`로 PATH
/// 탐색에 맡겼는데, aicd는 launchd/systemd로 뜨고 그 환경의 PATH는 셸이 아니라 서비스 매니저
/// 기본값이라(`/usr/bin:/bin:/usr/sbin:/sbin`) `/usr/local/bin/docker`를 못 찾았다 — 실환경에서
/// 매 tick `ENOENT`만 났다. 이제 PATH + 표준 설치 위치를 뒤져(`resolve_docker_bin`) 절대경로를
/// 잡고, **못 찾으면 task를 아예 띄우지 않는다**: 60초마다 WARN을 쏟는 대신 기동 시 한 번만
/// 남긴다(`docker_enabled=true`인데 docker가 없는 상황).
fn load_docker_config(
    ex: Option<aic_common::AicdExporterConfig>,
    spool: Option<Arc<OtlpSpool>>,
    health: Option<Arc<aic_server::otlp_exporter::ExporterHealth>>,
) -> Option<aic_server::otlp_exporter::DockerConfig> {
    let ex = ex?;
    if !ex.enabled || !ex.docker_enabled {
        return None;
    }
    if ex.endpoint.trim().is_empty() {
        tracing::warn!("exporter enabled이지만 endpoint 미설정 — docker exporter 비활성");
        return None;
    }

    // 파일시스템 탐색(resolve_docker_bin)보다 **먼저** 남은 게이트를 통과시킨다 — spool/health가
    // 없으면 exporter는 어차피 안 뜨는데, 순서를 뒤집으면 뜨지도 않을 task를 위해 디스크를 뒤지고
    // "docker를 못 찾았다"는 오해를 부르는 WARN까지 남긴다(진짜 원인은 spool/health인데).
    let spool = spool?;
    let health = health?;

    let configured = ex.docker_bin.as_deref().map(std::path::Path::new);
    let docker_bin = match aic_server::otlp_exporter::resolve_docker_bin(configured) {
        Some(p) => p,
        None => {
            // 한 번만 경고하고 task를 띄우지 않는다 — 매 tick 실패 로그를 쌓지 않기 위함.
            tracing::warn!(
                configured = ?ex.docker_bin,
                "docker 실행 파일을 찾지 못해 docker exporter 비활성 \
                 ([aicd.exporter].docker_bin으로 절대경로를 지정할 수 있다)"
            );
            return None;
        }
    };

    let token = std::env::var("AIC_EXPORTER_TOKEN").ok().or(ex.token);
    Some(aic_server::otlp_exporter::DockerConfig {
        endpoint: ex.endpoint,
        token,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        interval: std::time::Duration::from_secs(ex.docker_interval_secs.max(1)),
        docker_bin,
        timeout: std::time::Duration::from_secs(15),
        spool,
        health,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_str: &str) -> AppConfig {
        toml::from_str(toml_str).expect("valid AppConfig toml")
    }

    const BASE: &str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"
"#;

    /// DoD 1: `[aicd.logs]` 섹션이 없는 config → 두 게이트 모두 off.
    #[test]
    fn logs_precheck_off_when_section_absent() {
        let app = parse(BASE);
        let gate = logs_precheck_from_config(&app);
        assert!(!gate.parent_enabled);
        assert!(!gate.self_enabled);
    }

    /// `[aicd.exporter]`가 있어도 `logs_enabled`가 false(기본)면 여전히 off.
    #[test]
    fn logs_precheck_off_when_logs_enabled_false() {
        let toml_str = format!(
            "{BASE}\n[aicd.exporter]\nenabled = true\nendpoint = \"http://127.0.0.1:4318\"\n"
        );
        let app = parse(&toml_str);
        let gate = logs_precheck_from_config(&app);
        assert!(!gate.parent_enabled, "logs_enabled 기본값(false)이므로 off");
        assert!(!gate.self_enabled);
    }

    /// DoD 2 시나리오: `logs_enabled = true` + `[aicd.logs.self] enabled = true` → 둘 다 on.
    #[test]
    fn logs_precheck_on_when_logs_and_self_enabled() {
        let toml_str = format!(
            "{BASE}\n\
             [aicd.exporter]\n\
             enabled = true\n\
             endpoint = \"http://127.0.0.1:4318\"\n\
             logs_enabled = true\n\
             \n\
             [aicd.logs.self]\n\
             enabled = true\n"
        );
        let app = parse(&toml_str);
        let gate = logs_precheck_from_config(&app);
        assert!(gate.parent_enabled);
        assert!(gate.self_enabled);
    }

    /// 부모는 켜졌지만 self는 안 켜졌으면 채널은 만들되 self-log layer는 안 붙는다.
    #[test]
    fn logs_precheck_parent_on_self_off_when_self_not_enabled() {
        let toml_str = format!(
            "{BASE}\n[aicd.exporter]\nenabled = true\nendpoint = \"http://127.0.0.1:4318\"\nlogs_enabled = true\n"
        );
        let app = parse(&toml_str);
        let gate = logs_precheck_from_config(&app);
        assert!(gate.parent_enabled);
        assert!(
            !gate.self_enabled,
            "[aicd.logs.self] enabled 기본값은 false"
        );
    }

    /// endpoint가 비어 있으면 exporter.enabled/logs_enabled가 true여도 off(다른 exporter task와
    /// 동일한 "endpoint 유효" 게이트).
    #[test]
    fn logs_precheck_off_when_endpoint_empty() {
        let toml_str = format!("{BASE}\n[aicd.exporter]\nenabled = true\nlogs_enabled = true\n");
        let app = parse(&toml_str);
        let gate = logs_precheck_from_config(&app);
        assert!(!gate.parent_enabled);
    }

    fn test_spool() -> (tempfile::TempDir, Arc<OtlpSpool>) {
        let dir = tempfile::tempdir().unwrap();
        let quotas = aic_common::SpoolQuotas {
            metrics: 1024 * 1024,
            logs: 1024 * 1024,
            app_logs: 1024 * 1024,
        };
        let spool = OtlpSpool::open(dir.path().join("otlp-spool"), quotas).unwrap();
        (dir, Arc::new(spool))
    }

    fn test_health(spool: Arc<OtlpSpool>) -> Arc<aic_server::otlp_exporter::ExporterHealth> {
        Arc::new(aic_server::otlp_exporter::ExporterHealth::new(
            "http://127.0.0.1:4318".to_string(),
            spool,
        ))
    }

    /// `[aicd.exporter]` 섹션 자체가 없으면(`None`) logs exporter config도 없다.
    #[test]
    fn load_logs_exporter_config_none_when_section_absent() {
        let (_dir, spool) = test_spool();
        let health = test_health(spool.clone());
        let cfg = load_logs_exporter_config(
            None,
            Some(spool),
            Some(health),
            AicdLogsConfig::default(),
            Arc::new(DropCounters::new()),
        );
        assert!(cfg.is_none());
    }

    /// `logs_enabled = false`(기본)면 exporter 전체가 enabled여도 logs exporter는 안 만든다.
    #[test]
    fn load_logs_exporter_config_none_when_logs_enabled_false() {
        let (_dir, spool) = test_spool();
        let health = test_health(spool.clone());
        let ex = AicdExporterConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:4318".to_string(),
            ..AicdExporterConfig::default()
        };
        assert!(!ex.logs_enabled, "logs_enabled 기본값은 false여야 함");
        let cfg = load_logs_exporter_config(
            Some(ex),
            Some(spool),
            Some(health),
            AicdLogsConfig::default(),
            Arc::new(DropCounters::new()),
        );
        assert!(cfg.is_none());
    }

    /// 게이트를 모두 통과하면 `batch_max_lines`/`batch_max_ms`가 `[aicd.logs]` 값을 그대로
    /// 반영한 `LogsExporterConfig`가 나온다.
    #[test]
    fn load_logs_exporter_config_builds_when_gates_pass() {
        let (_dir, spool) = test_spool();
        let health = test_health(spool.clone());
        let ex = AicdExporterConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:4318".to_string(),
            logs_enabled: true,
            ..AicdExporterConfig::default()
        };
        let logs_cfg = AicdLogsConfig {
            batch_max_lines: 42,
            batch_max_ms: 999,
            ..Default::default()
        };
        let cfg = load_logs_exporter_config(
            Some(ex),
            Some(spool),
            Some(health),
            logs_cfg,
            Arc::new(DropCounters::new()),
        )
        .expect("게이트 통과 시 Some이어야 함");
        assert_eq!(cfg.batch_max_lines, 42);
        assert_eq!(cfg.batch_max_ms, 999);
        assert_eq!(cfg.endpoint, "http://127.0.0.1:4318");
    }

    /// spool이 없으면(다른 exporter와 동일 게이트) endpoint/enabled가 맞아도 None.
    #[test]
    fn load_logs_exporter_config_none_when_spool_missing() {
        let ex = AicdExporterConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:4318".to_string(),
            logs_enabled: true,
            ..AicdExporterConfig::default()
        };
        let cfg = load_logs_exporter_config(
            Some(ex),
            None,
            None,
            AicdLogsConfig::default(),
            Arc::new(DropCounters::new()),
        );
        assert!(cfg.is_none());
    }
}
