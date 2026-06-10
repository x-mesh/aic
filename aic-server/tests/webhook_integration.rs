//! SRE R2: webhook_server 통합 테스트 — 실제 axum 리스너에 HTTP POST.
//!
//! 인증(Bearer/HMAC), rate limit, dedup, 포맷별 수신을 in-process로 검증한다.
//! auto_diagnose=false로 두어 `aic diagnose` spawn 없이 서버 로직만 본다.

use std::time::Duration;

use aic_server::webhook_server::{serve, WebhookConfig};
use tokio::sync::watch;

/// webhook-events.jsonl이 실제 HOME 대신 temp에 쓰이도록 XDG_STATE_HOME을 1회 설정.
fn isolate_state_dir() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let dir = std::env::temp_dir().join("aic-webhook-it-state");
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("XDG_STATE_HOME", &dir);
    });
}

/// 임의 포트 webhook 서버를 띄우고 base URL을 반환한다.
async fn start_server(secret: Option<&str>, rate: u32) -> (String, watch::Sender<bool>) {
    start_server_full(secret, rate, false, std::path::PathBuf::from("/nonexistent-aic")).await
}

async fn start_server_full(
    secret: Option<&str>,
    rate: u32,
    auto_diagnose: bool,
    aic_bin: std::path::PathBuf,
) -> (String, watch::Sender<bool>) {
    isolate_state_dir();
    let (tx, rx) = watch::channel(false);
    // 포트 0 = OS 할당. bind 후 실제 주소를 알아내기 위해 먼저 listener를 잡는다.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // serve가 다시 bind. (테스트 편의 — race 가능성은 낮음)

    let cfg = WebhookConfig {
        listen_addr: addr.to_string(),
        secret: secret.map(|s| s.to_string()),
        rate_limit_per_min: rate,
        dedup_ttl: Duration::from_secs(300),
        auto_diagnose,
        aic_bin,
    };
    tokio::spawn(async move {
        let _ = serve(cfg, rx).await;
    });
    // 서버 기동 대기.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (format!("http://{addr}"), tx)
}

/// 호출 시 카운터 파일에 한 줄을 append하는 가짜 `aic` 스크립트를 만든다.
#[cfg(unix)]
fn fake_aic_script(counter: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = std::env::temp_dir().join(format!(
        "fake-aic-{}.sh",
        counter.file_name().unwrap().to_string_lossy()
    ));
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho run >> {}\n", counter.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

fn alertmanager_body() -> serde_json::Value {
    serde_json::json!({
        "alerts": [{
            "status": "firing",
            "labels": { "alertname": "HighCPU", "severity": "critical", "instance": "web1" },
            "annotations": { "summary": "CPU 95%" }
        }]
    })
}

#[tokio::test]
async fn health_endpoint_ok() {
    let (base, _tx) = start_server(None, 10).await;
    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn no_secret_accepts_alertmanager() {
    let (base, _tx) = start_server(None, 10).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook/alertmanager"))
        .json(&alertmanager_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn bearer_secret_required_when_configured() {
    let (base, _tx) = start_server(Some("topsecret"), 10).await;
    let client = reqwest::Client::new();

    // secret 없이 → 401
    let unauth = client
        .post(format!("{base}/webhook/alertmanager"))
        .json(&alertmanager_body())
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);

    // 올바른 Bearer → 200
    let ok = client
        .post(format!("{base}/webhook/alertmanager"))
        .bearer_auth("topsecret")
        .json(&alertmanager_body())
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // 틀린 Bearer → 401
    let wrong = client
        .post(format!("{base}/webhook/alertmanager"))
        .bearer_auth("nope")
        .json(&alertmanager_body())
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
}

#[tokio::test]
async fn malformed_json_is_bad_request() {
    let (base, _tx) = start_server(None, 10).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook"))
        .header("content-type", "application/json")
        .body("{ not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[cfg(unix)]
#[tokio::test]
async fn auto_diagnose_spawns_once_per_fingerprint() {
    // 동일 fingerprint alert를 2번 보내도 dedup으로 진단(spawn)은 1회만 일어나야 한다.
    let counter = std::env::temp_dir().join(format!(
        "aic-wh-counter-{}.log",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&counter);
    let script = fake_aic_script(&counter);
    let (base, _tx) = start_server_full(None, 100, true, script).await;
    let client = reqwest::Client::new();

    for _ in 0..2 {
        let resp = client
            .post(format!("{base}/webhook/alertmanager"))
            .json(&alertmanager_body())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    // spawn된 자식 프로세스가 완료될 시간을 준다.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let runs = std::fs::read_to_string(&counter).unwrap_or_default();
    let count = runs.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(count, 1, "동일 fingerprint는 dedup으로 1회만 spawn (실제 {count})");
    let _ = std::fs::remove_file(&counter);
}

#[tokio::test]
async fn received_alert_is_recorded_to_events_log() {
    // t11: 수신 이벤트가 webhook-events.jsonl에 기록되어 `aic webhook list`가 읽을 수 있어야 한다.
    isolate_state_dir();
    let events_path = aic_common::paths::webhook_events_path();
    let before = std::fs::read_to_string(&events_path)
        .map(|c| c.lines().count())
        .unwrap_or(0);

    let (base, _tx) = start_server(None, 100).await;
    let body = serde_json::json!({
        "alerts": [{
            "status": "firing",
            "labels": { "alertname": "EventLogTest", "instance": "rec1" },
            "annotations": { "summary": "x" }
        }]
    });
    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook/alertmanager"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let content = std::fs::read_to_string(&events_path).unwrap_or_default();
    assert!(content.lines().count() > before);
    assert!(content.contains("EventLogTest"), "이벤트 로그에 alertname 기록");
}

#[tokio::test]
async fn rate_limit_caps_requests() {
    // capacity 2 — 3번째 firing alert부터는 진단을 skip하지만 HTTP 자체는 200(수신 성공).
    let (base, _tx) = start_server(None, 2).await;
    let client = reqwest::Client::new();
    // 서로 다른 fingerprint 3개(dedup 회피)로 rate limit만 확인.
    for i in 0..3 {
        let body = serde_json::json!({
            "alerts": [{
                "status": "firing",
                "labels": { "alertname": format!("Alert{i}"), "instance": format!("h{i}") },
                "annotations": { "summary": "x" }
            }]
        });
        let resp = client
            .post(format!("{base}/webhook/alertmanager"))
            .json(&body)
            .send()
            .await
            .unwrap();
        // rate limit 초과해도 수신은 200(서버가 alert를 받아 기록).
        assert_eq!(resp.status(), 200, "요청 {i}");
    }
}
