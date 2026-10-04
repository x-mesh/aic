//! aicd 로그 수집 파이프라인 end-to-end (RFC-006 t12 — 배선 검증).
//!
//! t12 이전까지 로그 파이프라인의 **부품은 다 있었지만 배선이 없었다**. `aicd_main.rs`가
//! `ControlContext.logs_tx: None`을 넘겨 `aic-client`가 IPC로 보낸 로그가 조용히 버려졌고,
//! `ExporterConfig::drop_counters`가 자체 `Arc`라 `aic.log.dropped` 메트릭이 영원히 0이었다.
//! 이 파일의 테스트들은 **그 배선이 실제로 살아 있는지**를 collector가 받은 바이트로 증명한다 —
//! "배선했다"는 주장을 믿을 근거를 코드가 아니라 wire에서 찾는다.
//!
//! 검증 대상 3종:
//!   - [`self_log_reaches_collector_as_aic_logs_scope`] (DoD 2) — aicd 자신의 `tracing` 이벤트가
//!     `SelfLogLayer` → 채널 → `serve_logs` → `/v1/logs`(scope=`aic.logs`)까지 도달.
//!   - [`ipc_pushed_log_lines_reach_collector`] (DoD 3) — `PushLogLines` IPC(= `aic-client`가
//!     보내는 것과 **동일한 프레임**)가 control UDS → `ControlContext.logs_tx` → `serve_logs` →
//!     collector까지 도달.
//!   - [`dropped_lines_appear_in_metrics_as_aic_log_dropped`] (DoD 4) — `serve_logs`가 센 드롭이
//!     `serve`(metrics task)가 인코딩하는 `aic.log.dropped` 게이지에 나타난다(= 두 task가 **같은**
//!     `Arc<DropCounters>`를 본다).
//!
//! DoD 1(`[aicd.logs]` 섹션 없는 config → 수집기 0개, 기존 4개 exporter 무변화)은 이 파일이 아니라
//! `aicd_main.rs`의 유닛 테스트(`logs_precheck_off_when_section_absent` 등)가 게이트 함수 자체를
//! 검증하고, 기존 통합 테스트(`otlp_exporter_integration.rs`/`otlp_spool_integration.rs`)가
//! 그대로 통과하는 것으로 회귀 0을 보인다 — 로그가 꺼지면 채널조차 만들어지지 않아 코드 경로가
//! 통째로 비활성이기 때문이다.
//!
//! ★ `PushLogLines`의 aic-client 쪽 절반(버퍼링/2초 주기 flush/`libc::atexit`)은 여기 범위가
//! 아니다 — 그건 `aic-client/tests/log_sink_integration.rs`가 이미 검증한다. 여기서는 **aicd가
//! 그 프레임을 받아 실제로 흘려보내는지**만 본다(t12가 소유한 절반).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use aic_common::{encode_frame, AicdLogsConfig, IpcRequest, IpcResponse, LogLine, SpoolQuotas};
use aic_server::control_server::{ControlContext, ControlServer};
use aic_server::otlp_exporter::encode::{ExportMetricsServiceRequest, MetricData, NumberValue};
use aic_server::otlp_exporter::logs::self_layer::{is_loop_target, SelfLogLayer};
use aic_server::otlp_exporter::logs::{serve_logs, DropCounters, LogsExporterConfig};
use aic_server::otlp_exporter::logs_proto::{AnyValueOneof, ExportLogsServiceRequest};
use aic_server::otlp_exporter::{serve, ExporterConfig, ExporterHealth, Spool};

/// mock collector가 받은 요청 본문 하나. 어느 시그널로 왔는지는 채널을 갈라 구분한다.
type Bodies = mpsc::Sender<Vec<u8>>;

/// `/v1/logs`(+ 선택적으로 `/v1/metrics`)를 받는 mock OTLP collector를 띄우고 base URL을 돌려준다.
/// `otlp_exporter_integration.rs`/`otlp_spool_integration.rs`의 하네스와 동일한 형태다.
async fn spawn_mock_collector(logs_tx: Bodies, metrics_tx: Bodies) -> String {
    use axum::extract::State;
    use axum::http::StatusCode;

    async fn take_logs(State(tx): State<Bodies>, body: axum::body::Bytes) -> StatusCode {
        let _ = tx.try_send(body.to_vec());
        StatusCode::OK
    }
    async fn take_metrics(State(tx): State<Bodies>, body: axum::body::Bytes) -> StatusCode {
        let _ = tx.try_send(body.to_vec());
        StatusCode::OK
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route(
            "/v1/logs",
            axum::routing::post(take_logs).with_state(logs_tx),
        )
        .route(
            "/v1/metrics",
            axum::routing::post(take_metrics).with_state(metrics_tx),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// TempDir을 반드시 살려서 반환한다 — drop되면 spool 디렉토리가 사라진다.
/// 런타임 디렉토리로 바로 쓸 수 있는 0700 tempdir.
///
/// `tempfile::tempdir()`는 umask를 따라 보통 0755로 만들어지는데, 소켓의 부모 디렉토리는
/// `ensure_runtime_dir`이 0700만 신뢰한다(`/tmp` 선점 방어). 검사를 푸는 대신 테스트가
/// 실제 런타임 디렉토리와 같은 권한을 갖춘다.
fn runtime_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("런타임 디렉토리 권한 설정");
    dir
}

fn test_spool() -> (tempfile::TempDir, Arc<Spool>) {
    let dir = tempfile::tempdir().unwrap();
    let quotas = SpoolQuotas {
        metrics: 16 * 1024 * 1024,
        logs: 16 * 1024 * 1024,
        app_logs: 16 * 1024 * 1024,
    };
    let spool = Spool::open(dir.path().join("otlp-spool"), quotas).unwrap();
    (dir, Arc::new(spool))
}

fn logs_exporter_config(
    endpoint: &str,
    spool: Arc<Spool>,
    logs_cfg: AicdLogsConfig,
    drop_counters: Arc<DropCounters>,
) -> LogsExporterConfig {
    let health = Arc::new(ExporterHealth::new(endpoint.to_string(), spool.clone()));
    LogsExporterConfig {
        endpoint: endpoint.to_string(),
        token: None,
        service_version: "0.0.0-test".to_string(),
        // 라인 하나가 들어오면 즉시 flush — 테스트가 타이머를 기다리지 않게 한다.
        batch_max_lines: 1,
        batch_max_bytes: 4 * 1024 * 1024,
        batch_max_ms: 60_000,
        spool,
        health,
        logs_cfg,
        drop_counters,
        live: None,
    }
}

/// mock collector가 받은 `/v1/logs` 본문을 디코딩해 scope=`aic.logs`의 body 문자열들을 모은다.
fn decode_log_bodies(raw: &[u8]) -> Vec<String> {
    let req = ExportLogsServiceRequest::decode(raw).expect("valid OTLP logs protobuf");
    let mut out = Vec::new();
    for rl in &req.resource_logs {
        for sl in &rl.scope_logs {
            assert_eq!(
                sl.scope.as_ref().unwrap().name,
                "aic.logs",
                "로그는 5번째 scope인 aic.logs로 나가야 한다(기존 4개 scope와 구분)"
            );
            for lr in &sl.log_records {
                if let Some(AnyValueOneof::StringValue(s)) =
                    lr.body.as_ref().and_then(|b| b.value.clone())
                {
                    out.push(s);
                }
            }
        }
    }
    out
}

/// collector가 받은 본문들 중 `needle`을 body로 가진 로그가 나올 때까지 기다린다.
async fn wait_for_log_body(rx: &mut mpsc::Receiver<Vec<u8>>, needle: &str) -> String {
    let deadline = Duration::from_secs(10);
    let found = tokio::time::timeout(deadline, async {
        loop {
            let raw = rx.recv().await.expect("collector 채널이 닫힘");
            for body in decode_log_bodies(&raw) {
                if body.contains(needle) {
                    return body;
                }
            }
        }
    })
    .await;
    found.unwrap_or_else(|_| panic!("'{needle}'을 담은 로그가 collector에 도달하지 않음"))
}

// ── DoD 2: aicd 자체 로그(self) → mock collector ────────────────────────────

/// `logs_enabled = true` + `[aicd.logs.self] enabled = true`에 해당하는 배선(= `telemetry::
/// init_with_logs(Some(tx))`가 붙이는 `SelfLogLayer`)만으로 aicd 자신의 `tracing` 이벤트가
/// collector까지 도달한다.
///
/// 전역 subscriber(`.init()`)가 아니라 `with_default`(스코프 한정)를 쓴다 — 프로세스당 전역
/// subscriber는 한 번만 설치할 수 있어서, 그걸 쓰면 이 파일에 테스트를 하나밖에 못 둔다.
/// 프로덕션(`telemetry.rs`)과 **동일한 per-layer `filter_fn(is_loop_target)`**을 붙여, 재귀 차단
/// 필터가 정상 로그까지 삼키지는 않는지도 같이 본다.
#[tokio::test]
async fn self_log_reaches_collector_as_aic_logs_scope() {
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    let (logs_body_tx, mut logs_body_rx) = mpsc::channel(64);
    let (metrics_body_tx, _metrics_body_rx) = mpsc::channel(64);
    let endpoint = spawn_mock_collector(logs_body_tx, metrics_body_tx).await;

    let (_dir, spool) = test_spool();
    let (line_tx, line_rx) = mpsc::channel::<LogLine>(64);
    let cfg = logs_exporter_config(
        &endpoint,
        spool,
        AicdLogsConfig::default(),
        Arc::new(DropCounters::new()),
    );
    let (sd_tx, sd_rx) = watch::channel(false);
    let handle = tokio::spawn(serve_logs(cfg, line_rx, sd_rx));

    // 프로덕션과 동일 구성: SelfLogLayer + per-layer loop-target 필터.
    let layer =
        SelfLogLayer::new(line_tx).with_filter(filter_fn(|md| !is_loop_target(md.target())));
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!(target: "aic_server::web", "SELF-LOG-E2E-MARKER 디스크가 부족합니다");
    });

    let body = wait_for_log_body(&mut logs_body_rx, "SELF-LOG-E2E-MARKER").await;
    assert!(
        body.contains("디스크가 부족합니다"),
        "메시지 본문이 보존되어야 함: {body}"
    );

    sd_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("shutdown 후 종료해야 함")
        .unwrap()
        .unwrap();
}

// ── DoD 3: aic-client의 PushLogLines IPC → aicd → mock collector ────────────

fn client_log_line(message: &str) -> LogLine {
    LogLine {
        source: "aic".to_string(),
        // aic-client가 붙이는 service — aicd 자신("aicd")과 구분된다.
        service: "aic".to_string(),
        severity: "WARN".to_string(),
        message: message.to_string(),
        attrs: BTreeMap::new(),
        ts: chrono::Utc::now(),
        record_id: format!("log:test:{message}"),
    }
}

/// `aic-client`의 `log_sink`가 보내는 것과 **동일한 프레임**(`encode_frame(IpcRequest::
/// PushLogLines)`)을 control UDS로 직접 쏘고, 그 라인이 `ControlContext.logs_tx` → `serve_logs` →
/// mock collector까지 도달하는지 본다.
///
/// t12 이전에는 `logs_tx`가 `None`이라 이 경로가 **조용히 끊겨** 있었다 — `Pong`은 그대로 돌아와서
/// 클라이언트는 성공했다고 믿었다. 이 테스트가 없으면 그 상태와 지금을 구분할 수 없다.
#[tokio::test]
async fn ipc_pushed_log_lines_reach_collector() {
    let (logs_body_tx, mut logs_body_rx) = mpsc::channel(64);
    let (metrics_body_tx, _metrics_body_rx) = mpsc::channel(64);
    let endpoint = spawn_mock_collector(logs_body_tx, metrics_body_tx).await;

    let (_dir, spool) = test_spool();
    let (line_tx, line_rx) = mpsc::channel::<LogLine>(64);
    let cfg = logs_exporter_config(
        &endpoint,
        spool,
        AicdLogsConfig::default(),
        Arc::new(DropCounters::new()),
    );
    let (sd_tx, sd_rx) = watch::channel(false);
    let logs_handle = tokio::spawn(serve_logs(cfg, line_rx, sd_rx));

    // aicd control 서버 — aicd_main이 만드는 것과 동일하게 logs_tx를 배선한 ControlContext.
    let sock_dir = runtime_tempdir();
    let sock_path = sock_dir.path().join("aicd.sock");
    let server = ControlServer::bind(&sock_path).await.unwrap();
    let (ctl_shutdown, _) = watch::channel(false);
    let ctx = ControlContext {
        shutdown: ctl_shutdown.clone(),
        registry: aic_server::session_registry::SessionRegistry::new(),
        record_store: aic_server::command_record_store::CommandRecordStore::new(),
        registry_path: None,
        metrics: Arc::new(aic_server::metrics::AicdMetrics::new()),
        agent_bus: aic_server::agent_event_bus::AgentEventBus::new(),
        self_update_health: Arc::new(aic_server::self_update::SelfUpdateHealth::new()),
        exporter_health: None,
        // ★ 이게 t12가 배선한 지점 ★ — 이전엔 None이었다.
        logs_tx: Some(line_tx),
        flush_tx: None,
        process_inventory: None,
    };
    let serve_handle = tokio::spawn(async move { server.serve(ctx).await });

    // aic-client가 하는 것과 동일하게: 연결 → 길이 프레임 → 응답 읽기.
    let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let req = IpcRequest::PushLogLines {
        lines: vec![client_log_line("IPC-E2E-MARKER 클라이언트가 보낸 로그")],
    };
    let payload = serde_json::to_vec(&req).unwrap();
    client.write_all(&encode_frame(&payload)).await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    client.read_exact(&mut resp_buf).await.unwrap();
    let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
    assert_eq!(resp, IpcResponse::Pong);

    let body = wait_for_log_body(&mut logs_body_rx, "IPC-E2E-MARKER").await;
    assert!(
        body.contains("클라이언트가 보낸 로그"),
        "IPC로 넘어온 메시지 본문이 보존되어야 함: {body}"
    );

    ctl_shutdown.send(true).unwrap();
    sd_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), serve_handle).await;
    tokio::time::timeout(Duration::from_secs(5), logs_handle)
        .await
        .expect("shutdown 후 종료해야 함")
        .unwrap()
        .unwrap();
}

// ── DoD 4: 드롭 → metrics의 aic.log.dropped ────────────────────────────────

/// `serve_logs`(드롭을 세는 task)와 `serve`(metrics를 인코딩하는 task)가 **같은
/// `Arc<DropCounters>`**를 볼 때만 통과한다. t6가 남긴 부채는 정확히 이것이었다 — 둘이 각자 `Arc`를
/// 들면 metrics의 `aic.log.dropped`가 영원히 0이라, "안 보내고 있다"와 "보낼 게 없다"를 중앙에서
/// 구분할 수 없다.
///
/// 드롭 수단은 **min_severity 필터**다(rate limit이 아니다). 토큰버킷은 실시간으로 리필되므로 CPU
/// 경합이 심하면 통과/드롭 개수가 흔들리지만, severity 필터는 순수 함수라 시계와 무관하다.
#[tokio::test]
async fn dropped_lines_appear_in_metrics_as_aic_log_dropped() {
    let (logs_body_tx, _logs_body_rx) = mpsc::channel(64);
    let (metrics_body_tx, mut metrics_body_rx) = mpsc::channel(64);
    let endpoint = spawn_mock_collector(logs_body_tx, metrics_body_tx).await;

    let (_dir, spool) = test_spool();
    // ★ 하나의 Arc를 두 task가 공유한다 — 이게 검증 대상이다.
    let drop_counters = Arc::new(DropCounters::new());
    let health = Arc::new(ExporterHealth::new(endpoint.clone(), spool.clone()));

    // min_severity=WARN → DEBUG 라인은 전부 severity 필터에서 드롭된다.
    let logs_cfg = AicdLogsConfig {
        min_severity: "WARN".to_string(),
        max_lines_per_sec: 100_000, // rate limit은 이 테스트에서 절대 걸리지 않게.
        ..Default::default()
    };
    let (line_tx, line_rx) = mpsc::channel::<LogLine>(64);
    let logs_cfg_full = LogsExporterConfig {
        endpoint: endpoint.clone(),
        token: None,
        service_version: "0.0.0-test".to_string(),
        batch_max_lines: 1,
        batch_max_bytes: 4 * 1024 * 1024,
        batch_max_ms: 60_000,
        spool: spool.clone(),
        health: health.clone(),
        logs_cfg,
        drop_counters: Arc::clone(&drop_counters),
        live: None,
    };
    let (sd_tx, sd_rx) = watch::channel(false);
    let logs_handle = tokio::spawn(serve_logs(logs_cfg_full, line_rx, sd_rx));

    // metrics task — 같은 drop_counters Arc를 들고 주기적으로 인코딩/push한다.
    let metrics_cfg = ExporterConfig {
        endpoint: endpoint.clone(),
        token: None,
        interval: Duration::from_millis(100),
        service_version: "0.0.0-test".to_string(),
        spool: spool.clone(),
        drain_batch_limit: 20,
        spool_max_age: None,
        health,
        drop_counters: Arc::clone(&drop_counters),
        directory_snapshot_enabled: false,
        process_io_diagnostics_enabled: false,
        process_enabled: false,
        process_inventory_enabled: false,
        process_inventory_store: None,
        live: None,
    };
    let (msd_tx, msd_rx) = watch::channel(false);
    let metrics_handle = tokio::spawn(async move {
        let (_ftx, frx) = tokio::sync::mpsc::channel::<aic_server::otlp_exporter::FlushRequest>(1);
        serve(metrics_cfg, msd_rx, frx).await
    });

    // DEBUG 3줄 — min_severity=WARN에 전부 걸린다.
    for i in 0..3 {
        let mut line = client_log_line(&format!("drop-{i}"));
        line.severity = "DEBUG".to_string();
        line_tx.send(line).await.unwrap();
    }

    // metrics가 `aic.log.dropped{reason=severity} > 0`을 실어 보낼 때까지 기다린다.
    let dropped = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let raw = metrics_body_rx.recv().await.expect("metrics 채널이 닫힘");
            if let Some(v) = severity_drop_count(&raw) {
                if v > 0 {
                    return v;
                }
            }
        }
    })
    .await
    .expect("aic.log.dropped가 metrics에 나타나지 않음 — 두 task가 같은 Arc를 안 보고 있다");

    assert_eq!(
        dropped, 3,
        "DEBUG 3줄이 severity 필터에서 드롭되어 metrics에 그대로 반영되어야 함"
    );

    sd_tx.send(true).unwrap();
    msd_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), logs_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), metrics_handle).await;
}

/// metrics 본문에서 `aic.log.dropped{reason="severity"}` 게이지 값을 뽑는다. 없으면 `None`.
fn severity_drop_count(raw: &[u8]) -> Option<i64> {
    let req = ExportMetricsServiceRequest::decode(raw).ok()?;
    for rm in &req.resource_metrics {
        for sm in &rm.scope_metrics {
            for m in &sm.metrics {
                if m.name != "aic.log.dropped" {
                    continue;
                }
                let MetricData::Gauge(gauge) = m.data.as_ref()?;
                for dp in &gauge.data_points {
                    let is_severity = dp.attributes.iter().any(|kv| {
                        kv.key == "reason"
                            && matches!(
                                kv.value.as_ref().and_then(|v| v.value.as_ref()),
                                Some(aic_server::otlp_exporter::encode::AnyValueOneof::StringValue(s)) if s == "severity"
                            )
                    });
                    if !is_severity {
                        continue;
                    }
                    if let Some(NumberValue::AsInt(v)) = dp.value.as_ref() {
                        return Some(*v);
                    }
                }
            }
        }
    }
    None
}

// ── #43: 밀린 파일 줄은 버리지 않고 속도에 맞춰 전부 넘긴다 ─────────────────

/// aicd가 멈췄다 뜨면 파일에는 그동안의 줄이 한꺼번에 밀려 있다. 이전에는 파일 tail이 EOF까지
/// 한 번에 채널로 밀어 넣어 `channel_full`로 버리고, exporter의 서비스별 limiter(버스트 = 1초분)가
/// 나머지를 `rate_limit`으로 버렸다(실측: 15,833줄 중 1,363줄만 도착).
///
/// 파일 tail이 exporter와 같은 초당 속도로 읽기를 늦추면, 파일 → 채널 → limiter → collector 전
/// 구간에서 한 줄도 버려지지 않고 순서대로 도착해야 한다. 채널은 일부러 작게 둬 채널 쪽
/// 역압도 함께 지나가게 한다.
#[tokio::test]
async fn file_backlog_is_paced_through_the_limiter_without_drops() {
    use aic_common::AicdLogServiceOverride;
    use aic_server::otlp_exporter::logs::checkpoint::CheckpointStore;
    use aic_server::otlp_exporter::logs::file::{serve_files, FileTail};
    use std::io::Write as _;

    const RATE: u32 = 200;
    const BACKLOG: usize = 600;

    let (logs_body_tx, mut logs_body_rx) = mpsc::channel(1024);
    let (metrics_body_tx, _metrics_body_rx) = mpsc::channel(64);
    let endpoint = spawn_mock_collector(logs_body_tx, metrics_body_tx).await;

    let mut logs_cfg = AicdLogsConfig {
        max_lines_per_sec: RATE,
        ..AicdLogsConfig::default()
    };
    // 파일 소스의 기본 기준은 WARN이다 — 실제 syslog 설정처럼 이 서비스만 INFO까지 받는다.
    logs_cfg.services.insert(
        "app".to_string(),
        AicdLogServiceOverride {
            min_severity: Some("INFO".to_string()),
            ..Default::default()
        },
    );
    let drop_counters = Arc::new(DropCounters::new());
    let (_spool_dir, spool) = test_spool();
    let mut cfg = logs_exporter_config(&endpoint, spool, logs_cfg, drop_counters.clone());
    cfg.batch_max_lines = 100;
    cfg.batch_max_ms = 200;

    let (line_tx, line_rx) = mpsc::channel::<LogLine>(64);
    let (sd_tx, sd_rx) = watch::channel(false);
    let exporter = tokio::spawn(serve_logs(cfg, line_rx, sd_rx.clone()));

    let dir = tempfile::tempdir().unwrap();
    let checkpoint = Arc::new(CheckpointStore::open(dir.path().join("checkpoints")).unwrap());
    let path = dir.path().join("app.log");
    std::fs::write(
        &path,
        "padding-line-to-reach-fingerprint-threshold\n".repeat(32),
    )
    .unwrap();
    let tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string())
        .with_max_lines_per_sec(RATE);
    let collector = tokio::spawn(serve_files(vec![tail], line_tx, checkpoint, sd_rx));

    // 수집기는 파일을 처음 볼 때 현재 크기부터 읽는다(백필 없음). 확립 전에 밀어 넣은 줄은 설계대로
    // 읽히지 않으므로, 고정 sleep 대신 표식 줄이 collector에 실제로 도착할 때까지 표식을 거듭 써서
    // 확립과 전 구간 배선을 먼저 증명한다(느린 runner에서 300ms sleep이 모자라 0줄 도착한 적 있음).
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            writeln!(file, "ready-marker").unwrap();
            let arrived = tokio::time::timeout(Duration::from_millis(500), async {
                loop {
                    let raw = logs_body_rx.recv().await.expect("collector 채널이 닫힘");
                    if decode_log_bodies(&raw).iter().any(|b| b == "ready-marker") {
                        break;
                    }
                }
            })
            .await;
            if arrived.is_ok() {
                break;
            }
        }
    })
    .await
    .expect("수집기가 파일을 확립하지 못함");
    for i in 0..BACKLOG {
        writeln!(file, "backlog-line-{i:04}").unwrap();
    }
    drop(file);

    let expected: Vec<String> = (0..BACKLOG)
        .map(|i| format!("backlog-line-{i:04}"))
        .collect();
    let mut got = Vec::new();
    let deadline = Duration::from_secs(20);
    tokio::time::timeout(deadline, async {
        while got.len() < BACKLOG {
            let raw = logs_body_rx.recv().await.expect("collector 채널이 닫힘");
            got.extend(
                decode_log_bodies(&raw)
                    .into_iter()
                    .filter(|b| b.starts_with("backlog-line-")),
            );
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{BACKLOG}줄 중 {}줄만 도착", got.len()));

    assert_eq!(got, expected, "밀린 줄이 빠짐없이 순서대로 도착해야 함");
    use std::sync::atomic::Ordering;
    assert_eq!(drop_counters.by_rate_limit.load(Ordering::Relaxed), 0);
    assert_eq!(drop_counters.by_channel_full.load(Ordering::Relaxed), 0);

    sd_tx.send(true).unwrap();
    for handle in [exporter, collector] {
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("shutdown 후 종료해야 함")
            .unwrap()
            .unwrap();
    }
}
