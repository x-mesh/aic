//! RFC-006 t7: `SelfLogLayer` 재귀 차단 통합 테스트.
//!
//! `SelfLogLayer` + `serve_logs`를 실제로 조립해, push가 계속 실패하는 상황(mock collector가
//! 503 고정)에서 self-log 재귀가 스택 오버플로로 이어지지 않는지 검증한다.
//!
//! 재귀 시나리오(모듈 doc 참고): exporter task가 push 실패 → `tracing::warn!` → `SelfLogLayer`가
//! 그 이벤트를 `LogLine`으로 만들어 로그 채널로 `try_send` → `serve_logs`가 그 `LogLine`을 다시
//! push 시도 → 또 실패 → `tracing::warn!` → ... 이 테스트는 `SelfLogLayer`와 `serve_logs`가
//! **같은 채널**을 공유하도록 조립해 이 피드백 루프를 실제로 만든 뒤, `LOOP_TARGETS` per-layer
//! filter가 그걸 끊는지 확인한다.
//!
//! 전역 subscriber(`.init()`)를 써서 프로덕션(`telemetry::init_with_logs`)과 동일한 fast path를
//! 재현한다 — `tracing-core`의 재진입 가드(`can_enter`)는 `SCOPED_COUNT == 0`인 전역 subscriber
//! 에서는 우회되므로, 이 테스트가 재귀를 막는 건 오직 `LOOP_TARGETS` 필터(방어 1)와
//! `on_event` 안에서 `tracing::` 매크로를 호출하지 않는 규율(방어 2)뿐이다. `set_global_default`는
//! 프로세스당 1회만 성공하므로 이 파일엔 테스트 함수를 하나만 둔다.
//!
//! 레벨 필터(`EnvFilter`)를 일부러 붙이지 않는다 — 모든 레벨(TRACE 포함)이 그대로
//! `SelfLogLayer`의 filter까지 도달하게 해, `AIC_LOG=debug` 상당(hyper/reqwest 내부 로그까지
//! 전부 열린 최악의 경우)을 자연히 커버한다.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use aic_common::LogLine;
use aic_server::otlp_exporter::logs::self_layer::{is_loop_target, SelfLogLayer};
use aic_server::otlp_exporter::logs::{serve_logs, LogsExporterConfig};
use aic_server::otlp_exporter::{ExporterHealth, Spool};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use tokio::sync::{mpsc, watch};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

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

/// 항상 503을 반환하는 mock collector — push가 절대 성공하지 않는다.
async fn always_unavailable() -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}

#[tokio::test]
async fn self_log_does_not_recurse_under_push_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/v1/logs", post(always_unavailable));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let (_dir, spool) = test_spool();
    let health = Arc::new(ExporterHealth::new(format!("http://{addr}"), spool.clone()));

    // SelfLogLayer와 serve_logs가 **같은 채널**을 공유한다 — self-log가 만든 LogLine을
    // serve_logs가 push하려다 실패하면 다시 tracing::warn!을 내고, 그 이벤트가 다시 이 layer로
    // 들어오는 게 재귀 위험의 실체다. LOOP_TARGETS가 그 두 번째 warn!을 걸러내야 루프가 끊긴다.
    let (log_tx, log_rx) = mpsc::channel::<LogLine>(32);

    let self_log_layer = SelfLogLayer::new(log_tx.clone());
    let dropped = self_log_layer.dropped_counter();
    let filtered = self_log_layer.with_filter(filter_fn(|md| !is_loop_target(md.target())));

    // 프로덕션 telemetry::init_with_logs()와 동일하게 전역 subscriber로 등록한다 — 재진입 가드가
    // 우회되는 fast path(SCOPED_COUNT == 0)를 그대로 재현하기 위함. 레벨 필터를 붙이지 않아
    // TRACE까지 전부 이 layer의 filter까지 도달한다(AIC_LOG=debug 상당 최악의 경우).
    tracing_subscriber::registry().with(filtered).init();

    let cfg = LogsExporterConfig {
        endpoint: format!("http://{addr}"),
        token: None,
        service_version: "0.0.0-test".to_string(),
        // 라인마다 즉시 flush → push 시도 → 503 실패 → tracing::warn!("push 실패") 유도.
        batch_max_lines: 1,
        batch_max_ms: 60_000,
        spool: spool.clone(),
        health,
        logs_cfg: aic_common::AicdLogsConfig::default(),
        drop_counters: Arc::new(aic_server::otlp_exporter::logs::DropCounters::new()),
    };
    let (sd_tx, sd_rx) = watch::channel(false);
    let handle = tokio::spawn(serve_logs(cfg, log_rx, sd_rx));

    // 정상 target의 로그를 채널로 여러 차례 흘려보내 push 실패 → warn! → self_log_layer 재유입 →
    // (LOOP_TARGETS가 막아야 하는) 되먹임을 여러 번 유도한다.
    for i in 0..20 {
        tracing::warn!(target: "aic_server::web", iteration = i, "테스트용 정상 로그");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // 스택 오버플로가 났다면 프로세스가 죽어 여기 도달하지 못한다. 타임아웃 없이 최소 1개 배치가
    // spool에 쌓이는지(push가 계속 실패하므로) 확인해 exporter task가 살아서 계속 도는지 검증한다.
    tokio::time::timeout(Duration::from_secs(5), async {
        while spool.batch_count() < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("타임아웃 없이 최소 1개 배치는 spool에 쌓여야 함(push가 계속 실패하므로)");

    // graceful shutdown이 타임아웃 없이 끝나야 한다 — 재귀 루프에 갇혀 있다면 여기서 멈춘다.
    sd_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("serve_logs가 타임아웃 없이 종료되어야 함(재귀로 멈춰있지 않음)")
        .unwrap()
        .unwrap();

    // 채널은 여전히 유계(mpsc::channel(32))였고, 가득 찼더라도 dropped 카운터만 올랐을 뿐 panic
    // 없이 여기까지 왔다는 것 자체가 방어 2(on_event 안 try_send만 사용)의 증거다.
    let _ = dropped.load(Ordering::Relaxed);
}
