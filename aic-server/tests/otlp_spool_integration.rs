//! SRE t8: 오프라인 spool 통합 테스트 — mock collector를 내렸다 올려, 다운 구간에 실패한 배치가
//! 전부 spool에 쌓였다가 복구 후 드레인으로 무유실 재전송되는지 검증한다.
//!
//! DoD가 요구하는 "중앙 다운 30분 시뮬 → 복구 후 드레인 무유실"은 실제 30분을 기다리는 대신
//! backoff/tick 주기를 축약해 검증한다 — 핵심은 시간 길이가 아니라 "다운 구간 배치가 전부
//! spool→드레인된다"는 성질이다. spool 상한 초과(oldest drop) 자체는
//! `aic_server::otlp_exporter`(spool.rs) 내부 단위 테스트로 이미 커버한다(파일시스템/Arc 상태를
//! 직접 조작하는 편이 여기(외부 크레이트)보다 더 정밀하게 검증 가능해서다).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aic_server::otlp_exporter::{serve, ExporterConfig, SignalKind, Spool};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use tokio::sync::{mpsc, watch};

#[derive(Clone)]
struct MockState {
    up: Arc<AtomicBool>,
    metrics_tx: mpsc::Sender<Vec<u8>>,
    logs_tx: mpsc::Sender<Vec<u8>>,
}

async fn metrics_handler(State(state): State<MockState>, body: Bytes) -> StatusCode {
    if !state.up.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let _ = state.metrics_tx.send(body.to_vec()).await;
    StatusCode::OK
}

async fn logs_handler(State(state): State<MockState>, body: Bytes) -> StatusCode {
    if !state.up.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let _ = state.logs_tx.send(body.to_vec()).await;
    StatusCode::OK
}

#[tokio::test]
async fn spool_drains_all_downtime_batches_after_collector_recovers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let up = Arc::new(AtomicBool::new(false)); // "중앙 다운" 상태로 시작.
    let (metrics_tx, mut metrics_rx) = mpsc::channel::<Vec<u8>>(256);
    let (logs_tx, mut logs_rx) = mpsc::channel::<Vec<u8>>(256);
    let state = MockState { up: up.clone(), metrics_tx, logs_tx };
    let app = Router::new()
        .route("/v1/metrics", post(metrics_handler))
        .route("/v1/logs", post(logs_handler))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let spool = Arc::new(Spool::open(dir.path().join("otlp-spool"), 16 * 1024 * 1024).unwrap());

    // 다운 구간 시작 전 이미 spool에 남아 있던 배치(예: 이전 aicd 실행에서 events/connections
    // task가 push 실패로 적재해 둔 것)를 하나 심어 둔다 — 드레인이 host metrics 자기 배치뿐 아니라
    // logs 태그 배치도 올바른 endpoint(`/v1/logs`)로 재전송하는지 같이 검증한다.
    spool.append(SignalKind::Logs, b"preexisting-logs-batch").unwrap();

    let (sd_tx, sd_rx) = watch::channel(false);
    let cfg = ExporterConfig {
        endpoint: format!("http://{addr}"),
        token: None,
        interval: Duration::from_millis(30),
        service_version: "9.9.9".to_string(),
        spool: spool.clone(),
        drain_batch_limit: 50,
    };
    let handle = tokio::spawn(async move { serve(cfg, sd_rx).await });

    // "중앙 다운" 구간 — 여러 tick이 지나는 동안 push가 계속 실패해 spool에 쌓여야 한다.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        metrics_rx.try_recv().is_err(),
        "다운 구간엔 collector가 metrics를 하나도 못 받아야 함"
    );
    let spooled_during_downtime = spool.batch_count();
    assert!(
        spooled_during_downtime >= 1,
        "다운 구간 동안 최소 한 개는 spool에 쌓여야 함(preexisting 포함): {spooled_during_downtime}"
    );

    // 복구 — collector를 살리고, backoff 윈도(첫 실패 기준 최대 ~1.25s)를 넘겨 드레인이 재개될
    // 시간을 준다.
    up.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // 다운 구간 동안 쌓인 배치가 전부 드레인되어 spool이 비어야 한다 — 무유실의 핵심 단언.
    assert_eq!(spool.batch_count(), 0, "복구 후엔 spool이 완전히 비어야 함(무유실)");

    let mut received_logs = Vec::new();
    while let Ok(body) = logs_rx.try_recv() {
        received_logs.push(body);
    }
    assert!(
        received_logs.iter().any(|b| b == b"preexisting-logs-batch"),
        "미리 심어둔 logs 배치도 드레인 때 올바른 /v1/logs로 도달해야 함"
    );

    let mut received_metrics_count = 0usize;
    while metrics_rx.try_recv().is_ok() {
        received_metrics_count += 1;
    }
    assert!(
        received_metrics_count >= spooled_during_downtime.saturating_sub(1), // preexisting은 logs 채널
        "다운 구간에 쌓인 metrics 배치가 드레인으로 전부 collector에 도달해야 함: \
         received={received_metrics_count} spooled={spooled_during_downtime}"
    );

    sd_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
}
