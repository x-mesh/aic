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

/// process_tree를 켠 호스트 크기의 번들. 노드 하나가 600B 남짓이라 `nodes`만으로 수백 KB가 된다.
fn bundle_with_process_tree(nodes: usize) -> serde_json::Value {
    let nodes: Vec<_> = (0..nodes)
        .map(|i| {
            json!({
                "pid": 10_000 + i, "ppid": 1730, "fork_ppid": 1730,
                "start_boottime_ns": 863_987_800_000_000u64 + i as u64, "start_precision": "ns",
                "start_age_seconds": 12.4, "comm": "java", "exe": "/usr/lib/jvm/java-21/bin/java",
                "exe_source": "proc_exe", "cgroup_id": 9123,
                "cgroup_path": "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b.slice/cri-containerd-3f9c.scope",
                "ns_pid": 7, "ns_level": 1, "state": "live", "source": "event",
                "in_window": {"forked": true, "execed": true, "exited": false},
                "window": {"cpu_ns": 9_800_000_000u64, "runq_wait_us": 1_830_000, "runq_count": 5120,
                           "block_io_bytes": 73_400_320, "block_io_count": 812}
            })
        })
        .collect();
    json!({
        "schema_version": "rca.evidence.v1",
        "observations": {
            "findings": [{"signal": "oom", "metric": "kills", "severity": "warning", "value": 1}],
            "delta": {"process_tree": {"forks": 31, "ringbuf_drops_fork": 0}},
            "top": {
                "oom": {"available": true, "events": [{"seq": 1, "pid": 48190, "comm": "java"}]},
                "process_tree": {
                    "available": true, "schema": "process_tree.v1", "loss_in_window": false,
                    "nodes_total": nodes.len(), "nodes": nodes, "exited": []
                }
            }
        }
    })
}

/// 공용 읽기 상한(512KB)과 LLM 출력 상한(64KB)을 모두 넘는 번들도 유효한 JSON으로 와야 한다.
/// 바이트 단위로 자르면 `kernel_findings`가 파싱에 실패해 finding이 조용히 사라진다.
#[tokio::test]
async fn oversized_bundle_stays_valid_json_and_keeps_findings() {
    let bundle = bundle_with_process_tree(1024);
    assert!(
        bundle.to_string().len() > 512 * 1024,
        "재현 조건: 512KB 초과"
    );

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/collectz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(bundle))
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let out = client.collect(5).await.expect("collect should succeed");
    assert!(out.len() <= 64 * 1024, "len={}", out.len());

    let v: serde_json::Value = serde_json::from_str(&out).expect("출력이 유효한 JSON이어야 한다");
    let obs = &v["observations"];
    assert_eq!(obs["findings"][0]["signal"], "oom");
    assert_eq!(obs["delta"]["process_tree"]["forks"], 31);
    let tree = &obs["top"]["process_tree"];
    assert_eq!(tree["available"], true, "스칼라 플래그는 남아야 한다");
    // #74: 트리 원문은 생략 표식이 아니라 요약으로 바뀐다.
    assert!(tree["aic_summary_of_bytes"].as_u64().unwrap() > 0);
    assert!(tree.get("nodes").is_none());
    assert!(tree["top_nodes"].is_object());
    assert_eq!(
        obs["top"]["oom"]["events"][0]["seq"], 1,
        "작은 항목은 그대로"
    );
}

/// 번들 읽기 상한을 넘으면 깨진 JSON을 넘기지 않고 크기를 알리는 오류로 실패한다.
#[tokio::test]
async fn bundle_over_read_cap_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/collectz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(bundle_with_process_tree(5000)))
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let err = client.collect(5).await.unwrap_err();
    assert!(err.message.contains("bytes"), "{}", err.message);
}

const BLACKBOX_ID: &str = "0123456789abcdef";

/// 준비된 고정본은 요약으로 돌아오고, 문자열은 redaction을 거친다.
#[tokio::test]
async fn blackbox_ready_capture_is_summarized() {
    let frames: Vec<serde_json::Value> = (0..90)
        .map(|s| {
            json!({"at": format!("t{s}"), "counters": {"exits": 1}, "live_nodes": 10,
                         "system": {"procs_blocked": s % 7}})
        })
        .collect();
    let capture = json!({
        "schema": "process_tree_blackbox.v1", "id": BLACKBOX_ID, "state": "ready",
        "triggers": [{"id": "fatal_signal", "at": "t60",
                      "cause": {"comm": "app", "exe": "/srv/app", "signal": 11}}],
        "range": {"start": "t0", "end": "t89", "pre": 60_000_000_000u64, "post": 30_000_000_000u64, "merged": false},
        "frames": frames,
        "exited": [{"pid": 7, "comm": "app", "closed_by": "exit_event", "exit_age_seconds": 1.0,
                    "signal": 11, "argv_path": "redis://user:pass@cache:6379"}],
        "snapshots": {"at_trigger": {"nodes": []}, "at_end": {"nodes": []}},
        "loss": {"frames_missed": 0, "exited_overwritten_in_range": 0, "triggers_dropped": 0}
    });
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/blackboxz/{BLACKBOX_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(capture))
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let out = client
        .blackbox(BLACKBOX_ID)
        .await
        .expect("blackbox should succeed");
    let v: serde_json::Value = serde_json::from_str(&out).expect("유효한 JSON");
    assert_eq!(v["triggers"][0]["id"], "fatal_signal");
    assert_eq!(v["frames"]["count"], 90);
    assert_eq!(v["frames"]["system_peaks"]["procs_blocked"]["max"], 6.0);
    assert!(v.get("aic_summary_of_bytes").is_some());
    assert!(!out.contains("user:pass"), "비밀값이 남았다");
}

#[tokio::test]
async fn blackbox_capturing_and_missing_have_clear_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/blackboxz/{BLACKBOX_ID}")))
        .respond_with(ResponseTemplate::new(409).set_body_string("capturing"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/blackboxz/fedcba9876543210"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let client = RcaAgentClient::new(&cfg(&server.uri())).unwrap().unwrap();
    let err = client.blackbox(BLACKBOX_ID).await.unwrap_err();
    assert!(err.message.contains("캡처 중"), "{}", err.message);
    let err = client.blackbox("fedcba9876543210").await.unwrap_err();
    assert!(err.message.contains("찾지 못했습니다"), "{}", err.message);
    let err = client.blackbox("../healthz").await.unwrap_err();
    assert!(err.message.contains("형식"), "{}", err.message);
}
