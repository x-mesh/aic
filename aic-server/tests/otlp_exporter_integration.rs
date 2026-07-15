//! SRE t6: OTLP exporter 통합 테스트 — 실제 host metrics를 수집해 mock collector로 push한다.
//!
//! 중앙 rca-server가 아직 없으므로, DoD의 "로컬 rca-server로 메트릭 적재 확인"을 in-process
//! mock HTTP 서버 수신 검증으로 대체한다. exporter task를 실제로 돌려 (1) `/v1/metrics`로 POST가
//! 오는지, (2) Content-Type이 application/x-protobuf인지, (3) Bearer 토큰이 실리는지, (4) 본문이
//! 유효한 OTLP(service.name=aicd, 알려진 metric name 포함)인지, (5) shutdown watch로 graceful하게
//! 끝나는지를 확인한다.

use std::sync::Arc;
use std::time::Duration;

use aic_server::otlp_exporter::{serve, DropCounters, ExporterConfig, ExporterHealth, Spool};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use tokio::sync::{mpsc, watch};

/// 테스트 전용 임시 spool. `TempDir`을 반환값에 같이 묶어 두지 않으면 drop 시 디렉토리가
/// 삭제되어 spool이 파일을 못 쓴다 — 호출부가 `_dir`을 테스트 스코프 끝까지 들고 있어야 한다.
fn test_spool() -> (tempfile::TempDir, Arc<Spool>) {
    let dir = tempfile::tempdir().unwrap();
    let quotas = aic_common::SpoolQuotas {
        metrics: 16 * 1024 * 1024,
        logs: 16 * 1024 * 1024,
        app_logs: 16 * 1024 * 1024,
    };
    let spool = Spool::open(dir.path().join("otlp-spool"), quotas).unwrap();
    (dir, Arc::new(spool))
}

/// mock collector가 수신한 요청의 관심 필드.
#[derive(Debug)]
struct Captured {
    content_type: Option<String>,
    authorization: Option<String>,
    body: Vec<u8>,
}

async fn collect(
    State(tx): State<mpsc::Sender<Captured>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let header_str = |k: &header::HeaderName| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let _ = tx
        .send(Captured {
            content_type: header_str(&header::CONTENT_TYPE),
            authorization: header_str(&header::AUTHORIZATION),
            body: body.to_vec(),
        })
        .await;
    StatusCode::OK
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn exporter_pushes_valid_otlp_to_collector() {
    // mock collector: /v1/metrics 수신 시 Captured를 채널로 흘려보낸다.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel::<Captured>(8);
    let app = Router::new()
        .route("/v1/metrics", post(collect))
        .with_state(tx);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // exporter task 기동 — 짧은 주기로 곧 첫 push가 오게 한다.
    let (sd_tx, sd_rx) = watch::channel(false);
    let (_spool_dir, spool) = test_spool();
    let health = Arc::new(ExporterHealth::new(format!("http://{addr}"), spool.clone()));
    let cfg = ExporterConfig {
        endpoint: format!("http://{addr}"),
        token: Some("test-token".to_string()),
        interval: Duration::from_millis(50),
        service_version: "9.9.9".to_string(),
        spool,
        drain_batch_limit: 20,
        spool_max_age: None,
        health,
        drop_counters: Arc::new(DropCounters::new()),
    };
    let handle = tokio::spawn(async move { { let (_ftx, frx) = tokio::sync::mpsc::channel::<aic_server::otlp_exporter::FlushRequest>(1); serve(cfg, sd_rx, frx).await } });

    // 첫 수신을 최대 5초 기다린다(실제 sysinfo 수집 + POST).
    let captured = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("collector가 5초 내 요청을 받지 못함")
        .expect("채널이 닫힘");

    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-protobuf"),
        "Content-Type이 protobuf여야 함"
    );
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer test-token"),
        "Bearer 토큰이 실려야 함"
    );
    assert!(!captured.body.is_empty(), "본문이 비어있음");
    // 유효 OTLP 본문 표식(protobuf 안에 UTF-8 문자열로 저장됨).
    assert!(contains(&captured.body, b"aicd"), "service.name=aicd 누락");
    assert!(
        contains(&captured.body, b"system.cpu.utilization"),
        "알려진 metric name 누락"
    );

    // shutdown watch로 graceful 종료 확인 — serve()가 Ok로 반환되어야 한다.
    sd_tx.send(true).unwrap();
    let joined = tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("exporter가 3초 내 종료하지 못함(shutdown 회귀)")
        .expect("task join 실패");
    assert!(joined.is_ok(), "serve()가 Ok로 끝나야 함: {joined:?}");
}

/// token 미설정 시 Authorization 헤더 없이 전송되는지(localhost collector 경로).
#[tokio::test]
async fn exporter_without_token_sends_no_auth_header() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel::<Captured>(8);
    let app = Router::new()
        .route("/v1/metrics", post(collect))
        .with_state(tx);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let (sd_tx, sd_rx) = watch::channel(false);
    let (_spool_dir, spool) = test_spool();
    let health = Arc::new(ExporterHealth::new(format!("http://{addr}"), spool.clone()));
    let cfg = ExporterConfig {
        endpoint: format!("http://{addr}"),
        token: None,
        interval: Duration::from_millis(50),
        service_version: "9.9.9".to_string(),
        spool,
        drain_batch_limit: 20,
        spool_max_age: None,
        health,
        drop_counters: Arc::new(DropCounters::new()),
    };
    let handle = tokio::spawn(async move { { let (_ftx, frx) = tokio::sync::mpsc::channel::<aic_server::otlp_exporter::FlushRequest>(1); serve(cfg, sd_rx, frx).await } });

    let captured = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("collector가 요청을 받지 못함")
        .expect("채널이 닫힘");
    assert!(
        captured.authorization.is_none(),
        "token 미설정 시 Authorization 헤더가 없어야 함"
    );

    sd_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
}
