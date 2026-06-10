//! SRE R1: 관측 백엔드 도구(obs_tools) 통합 테스트.
//!
//! wiremock in-process HTTP mock 서버로 Prometheus/Loki/ES 질의 경로와
//! SSRF 방어(redirect 비추적)를 검증한다. 실제 백엔드 없이 CI(ubuntu/macos)에서 동작.

use std::collections::HashMap;

use aic_client::agent::obs_tools::ObsClient;
use aic_common::{BackendConfig, BackendType, ObservabilityConfig};
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg(name: &str, backend_type: BackendType, url: &str) -> ObservabilityConfig {
    let mut backends = HashMap::new();
    backends.insert(
        name.to_string(),
        BackendConfig {
            backend_type,
            url: url.to_string(),
            auth: None,
        },
    );
    ObservabilityConfig { backends }
}

#[tokio::test]
async fn prometheus_instant_query_roundtrip() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/query"))
        .and(query_param("query", "up"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "data": { "resultType": "vector", "result": [] }
        })))
        .mount(&server)
        .await;

    let client = ObsClient::new(&cfg("prom", BackendType::Prometheus, &server.uri())).unwrap();
    let out = client
        .run("prometheus_query", &json!({ "backend": "prom", "query": "up" }))
        .await
        .expect("query should succeed");
    assert!(out.contains("success"));
    assert!(out.contains("resultType"));
}

#[tokio::test]
async fn prometheus_range_query_uses_range_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/query_range"))
        .and(query_param("step", "30s"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "data": { "resultType": "matrix", "result": [] }
        })))
        .mount(&server)
        .await;

    let client = ObsClient::new(&cfg("prom", BackendType::Prometheus, &server.uri())).unwrap();
    let out = client
        .run(
            "prometheus_query",
            &json!({
                "backend": "prom",
                "query": "rate(http_requests_total[5m])",
                "start": "1700000000",
                "end": "1700003600",
                "step": "30s"
            }),
        )
        .await
        .expect("range query should succeed");
    assert!(out.contains("matrix"));
}

#[tokio::test]
async fn loki_query_roundtrip() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/loki/api/v1/query_range"))
        .and(query_param("query", "{app=\"api\"}"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "data": { "resultType": "streams", "result": [] }
        })))
        .mount(&server)
        .await;

    let client = ObsClient::new(&cfg("logs", BackendType::Loki, &server.uri())).unwrap();
    let out = client
        .run(
            "loki_query",
            &json!({ "backend": "logs", "query": "{app=\"api\"}" }),
        )
        .await
        .expect("loki query should succeed");
    assert!(out.contains("streams"));
}

#[tokio::test]
async fn es_search_posts_query_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/logs-*/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": { "total": { "value": 0 }, "hits": [] }
        })))
        .mount(&server)
        .await;

    let client = ObsClient::new(&cfg("es", BackendType::Elasticsearch, &server.uri())).unwrap();
    let out = client
        .run(
            "es_search",
            &json!({ "backend": "es", "index": "logs-*", "query": "level:ERROR" }),
        )
        .await
        .expect("es search should succeed");
    assert!(out.contains("hits"));
}

#[tokio::test]
async fn redirect_is_not_followed() {
    // SSRF 방어 (A1): 백엔드가 메타데이터 endpoint로 302 redirect해도 추적하지 않는다.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/query"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
        )
        .mount(&server)
        .await;

    let client = ObsClient::new(&cfg("prom", BackendType::Prometheus, &server.uri())).unwrap();
    let result = client
        .run("prometheus_query", &json!({ "backend": "prom", "query": "up" }))
        .await;
    // redirect를 따라가지 않으므로 302 응답이 그대로 비-성공 에러로 반환된다(메타데이터 fetch 안 함).
    let err = result.expect_err("302 must not be followed");
    assert!(err.message.contains("302") || err.message.contains("백엔드 오류"));
}

#[tokio::test]
async fn victoriametrics_promql_compatibility() {
    // R1-vm-verify: VictoriaMetrics는 Prometheus /api/v1/query 와이어를 그대로 구현한다.
    // backend_type="Prometheus"로 등록하면 prometheus_query 도구가 코드 변경 없이 동작함을 확인.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/query"))
        .and(query_param("query", "vm_app_version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            // VictoriaMetrics 응답도 Prometheus와 동일한 status/data 구조.
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{
                    "metric": { "__name__": "vm_app_version", "version": "victoria-metrics" },
                    "value": [1700000000, "1"]
                }]
            }
        })))
        .mount(&server)
        .await;

    let client = ObsClient::new(&cfg("vm", BackendType::Prometheus, &server.uri())).unwrap();
    let out = client
        .run(
            "prometheus_query",
            &json!({ "backend": "vm", "query": "vm_app_version" }),
        )
        .await
        .expect("VictoriaMetrics PromQL query should succeed via Prometheus backend type");
    assert!(out.contains("success"));
    assert!(out.contains("victoria-metrics"));
}

#[tokio::test]
async fn unregistered_backend_rejected_before_network() {
    let client = ObsClient::new(&cfg("prom", BackendType::Prometheus, "http://127.0.0.1:1")).unwrap();
    let err = client
        .run("prometheus_query", &json!({ "backend": "ghost", "query": "up" }))
        .await
        .expect_err("unregistered backend must be rejected");
    assert!(err.message.contains("등록되지 않은"));
}
