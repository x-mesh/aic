//! RCA-eBPF Phase 1: rca-agent pull 클라이언트(rca_agent) 통합 테스트.
//!
//! wiremock in-process HTTP mock 서버로 `/collectz` pull과 `/featuresz` 조회 경로를
//! 검증한다. 실제 rca-agent 없이 CI(ubuntu/macos)에서 동작한다. mock 서버는
//! 127.0.0.1에 바인드되므로 loopback 강제와도 양립한다.

use aic_client::agent::rca_agent::RcaAgentClient;
use aic_common::RcaAgentConfig;
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg(url: &str) -> RcaAgentConfig {
    RcaAgentConfig {
        enabled: true,
        url: url.to_string(),
    }
}

#[tokio::test]
async fn collect_posts_incident_profile_and_returns_bundle() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/collectz"))
        .and(query_param("profile", "incident"))
        .and(query_param("duration", "30s"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schema_version": "rca.evidence.v1",
            "profile": "incident",
            "observations": { "delta": { "context_switch": { "switches": 1000 } } },
            "quality": { "ready": true, "signal_count": 3 }
        })))
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let out = client
        .run("rca_agent_collect", &json!({ "duration_secs": 30 }))
        .await
        .expect("collect should succeed");
    assert!(out.contains("rca.evidence.v1"));
    assert!(out.contains("context_switch"));
}

#[tokio::test]
async fn collect_clamps_window_below_minimum() {
    let server = MockServer::start().await;
    // 하한(5s) 미만 요청은 5s로 clamp되어 나가야 한다.
    Mock::given(method("POST"))
        .and(path("/collectz"))
        .and(query_param("duration", "5s"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "schema_version": "rca.evidence.v1" })),
        )
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let out = client
        .run("rca_agent_collect", &json!({ "duration_secs": 1 }))
        .await
        .expect("clamped collect should succeed");
    assert!(out.contains("rca.evidence.v1"));
}

#[tokio::test]
async fn features_returns_attach_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/featuresz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "oom": { "enabled": true, "attach": "oom/mark_victim + event:fentry" },
            "kernel_capabilities": { "btf": true, "tracing": true }
        })))
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let out = client
        .run("rca_agent_features", &json!({}))
        .await
        .expect("features should succeed");
    assert!(out.contains("mark_victim"));
    assert!(out.contains("kernel_capabilities"));
}

/// 비-2xx 응답이 삼켜지지 않고 상태코드·본문과 함께 올라오는지 검증한다.
///
/// **409는 실제 rca-agent의 계약이 아니다.** 동시 collect를 막는 가드가 서버에 없고
/// (`internal/control/collector.go`에 mutex 0건, "collect already in progress" 문자열도
/// 저장소 전체에 0건), 여기서는 임의의 비-2xx 오류를 대표시키는 목일 뿐이다.
/// 따라서 이 목을 근거로 "서버가 경합을 막아 준다"고 설계하면 안 된다 —
/// aicd 주기 수집을 붙일 때는 수집 중 tick을 건너뛰는 **자체 상호배제**가 필요하다.
#[tokio::test]
async fn agent_error_status_is_surfaced() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/collectz"))
        .respond_with(ResponseTemplate::new(409).set_body_string("collect already in progress"))
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let err = client
        .run("rca_agent_collect", &json!({}))
        .await
        .unwrap_err();
    assert!(err.message.contains("409"));
    assert!(err.message.contains("already in progress"));
}
