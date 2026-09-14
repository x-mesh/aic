//! SRE R6: headless(비대화·TTY 없음) e2e 테스트.
//!
//! SRE는 aic를 서버(cron/systemd/webhook spawn)에서 TTY 없이 돌린다. 이 테스트는
//! `aic` 바이너리를 stdin 닫힌 subprocess로 실행해 headless 경로가 동작하고 **상태 변경
//! 명령이 자동 실행되지 않음**(보안 속성)을 고정한다. 외부 LLM/네트워크 없이 동작.

#![cfg(unix)]

use std::process::Command;

/// HOME/XDG를 임시로 격리한 aic 명령을 만든다(실제 홈 오염 방지 + keychain 우회).
fn aic_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aic"));
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("cfg"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("AIC_NO_KEYCHAIN", "1")
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null()); // TTY 없음(비대화)
    cmd
}

#[test]
fn diagnose_headless_produces_evidence_without_tty() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aic_cmd(tmp.path())
        .args(["diagnose", "--no-analyze", "generic"])
        .output()
        .expect("aic diagnose 실행 실패");
    assert!(out.status.success(), "exit 비정상: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("# diagnose"), "stdout={stdout}");
    assert!(stdout.contains("## evidence"), "stdout={stdout}");
    // 최소 한 개 probe 결과(date/host/os 등)가 수집되어야 한다.
    assert!(stdout.contains("## "), "probe 섹션 없음: {stdout}");
}

#[test]
fn audit_subcommands_run_headless() {
    let tmp = tempfile::tempdir().unwrap();
    // diagnose가 audit 이벤트를 남긴다.
    aic_cmd(tmp.path())
        .args(["diagnose", "--no-analyze", "cpu"])
        .output()
        .unwrap();

    // verify: 빈/유효 로그 → exit 0.
    let verify = aic_cmd(tmp.path())
        .args(["audit", "verify"])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "audit verify exit: {:?}",
        verify.status
    );

    // tail --json: 유효한 JSON 배열.
    let tail = aic_cmd(tmp.path())
        .args(["audit", "tail", "-n", "10", "--json"])
        .output()
        .unwrap();
    assert!(tail.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&tail.stdout).expect("tail --json은 JSON");
    assert!(parsed.is_array(), "tail --json은 배열: {parsed}");

    // search --kind: headless 동작.
    let search = aic_cmd(tmp.path())
        .args(["audit", "search", "--kind", "headless_diagnose", "--json"])
        .output()
        .unwrap();
    assert!(search.status.success());
    let s: serde_json::Value =
        serde_json::from_slice(&search.stdout).expect("search --json은 JSON");
    assert!(s.is_array());
}

#[test]
fn webhook_list_runs_headless() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aic_cmd(tmp.path())
        .args(["webhook", "list", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("webhook list --json은 JSON");
    assert!(parsed.is_array());
}

#[test]
fn config_get_runs_headless() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aic_cmd(tmp.path())
        .args(["config", "get", "llm.default_provider"])
        .output()
        .unwrap();
    // 설정 파일이 없으면 default("openai")가 나오거나 path-not-found(비-0)일 수 있다.
    // 핵심은 hang 없이 종료하는 것.
    let _ = out.status;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("openai") || stderr.contains("not found") || out.status.success(),
        "stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn workload_discovery_and_inspect_do_not_create_configuration() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("cfg").join("aic");
    let discover = aic_cmd(tmp.path())
        .args(["workload", "discover", "--json"])
        .output()
        .unwrap();
    assert!(
        discover.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&discover.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&discover.stdout).unwrap();
    assert_eq!(report["report"]["schema_version"], 1);
    assert!(!config_dir.join("workloads.toml").exists());
    if let Some(candidate_id) = report["report"]["candidates"]
        .as_array()
        .and_then(|candidates| candidates.first())
        .and_then(|candidate| candidate["id"].as_str())
    {
        let inspect = aic_cmd(tmp.path())
            .args(["workload", "inspect", candidate_id, "--json"])
            .output()
            .unwrap();
        assert!(
            inspect.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&inspect.stderr)
        );
        assert!(!config_dir.join("workloads.toml").exists());
    }

    let failed = aic_cmd(tmp.path())
        .args(["workload", "enable", "missing", "--fingerprint", "stale"])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!config_dir.join("workloads.toml").exists());
}

#[test]
fn workload_monitor_is_a_headless_public_command_and_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let monitor = aic_cmd(tmp.path())
        .args(["workload", "monitor", "missing", "--json"])
        .output()
        .unwrap();
    assert!(!monitor.status.success());
    assert!(String::from_utf8_lossy(&monitor.stderr).contains("candidate"));
}

#[test]
fn workload_status_and_history_read_local_history() {
    use aic_common::workload::{
        MemcachedMetrics, WorkloadAdapter, WorkloadDefinition, WorkloadDriverMode, WorkloadMetrics,
        WorkloadSample, WorkloadSampleOutcome, WorkloadSelector, WorkloadStore,
        WORKLOAD_SAMPLE_SCHEMA_VERSION,
    };
    use chrono::{Duration, Utc};

    let empty = tempfile::tempdir().unwrap();
    let empty_status = aic_cmd(empty.path())
        .args(["workload", "status", "--json"])
        .output()
        .unwrap();
    assert!(empty_status.status.success());
    let empty_status: serde_json::Value = serde_json::from_slice(&empty_status.stdout).unwrap();
    assert_eq!(empty_status["workloads"], serde_json::json!([]));

    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("cfg/aic");
    std::fs::create_dir_all(&config_dir).unwrap();
    let redis_definition = WorkloadDefinition {
        id: "redis-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/redis-server".into(),
        },
        adapter: WorkloadAdapter::Redis,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: None,
    };
    let memcached_definition = WorkloadDefinition {
        id: "memcached-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/memcached".into(),
        },
        adapter: WorkloadAdapter::Memcached,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: None,
    };
    std::fs::write(
        config_dir.join("workloads.toml"),
        toml::to_string_pretty(&WorkloadStore {
            workloads: vec![redis_definition, memcached_definition],
        })
        .unwrap(),
    )
    .unwrap();
    let state_dir = tmp.path().join("state/aic");
    std::fs::create_dir_all(&state_dir).unwrap();
    let memcached_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "memcached-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::Memcached,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "127.0.0.1:11211".into(),
            metrics: WorkloadMetrics::Memcached(MemcachedMetrics {
                curr_connections: 1,
                bytes: 2,
                cmd_get: 3,
                cmd_set: 4,
                get_hits: 5,
                get_misses: 6,
                evictions: 7,
            }),
        },
    };
    let legacy_redis_sample = serde_json::json!({
        "schema_version": WORKLOAD_SAMPLE_SCHEMA_VERSION,
        "workload_id": "redis-test",
        "captured_at": (Utc::now() - Duration::minutes(10)).to_rfc3339(),
        "outcome": "collected",
        "endpoint": "127.0.0.1:6379",
        "metrics": {
            "connected_clients": 1, "used_memory": 2, "total_commands_processed": 3,
            "instantaneous_ops_per_sec": 4, "keyspace_hits": 5, "keyspace_misses": 6
        }
    });
    std::fs::write(
        state_dir.join("workload-history.jsonl"),
        format!(
            "{}\n{}\nnot-json\n",
            legacy_redis_sample,
            serde_json::to_string(&memcached_sample).unwrap()
        ),
    )
    .unwrap();

    let status = aic_cmd(tmp.path())
        .args(["workload", "status", "--json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(status["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .all(|workload| workload["state"] == "stale"));

    let history = aic_cmd(tmp.path())
        .args(["workload", "history", "redis-test", "--json"])
        .output()
        .unwrap();
    assert!(history.status.success());
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(history["samples"].as_array().unwrap().len(), 1);
    assert_eq!(history["samples"][0]["adapter"], "redis");

    let memcached_history = aic_cmd(tmp.path())
        .args(["workload", "history", "memcached-test", "--json"])
        .output()
        .unwrap();
    assert!(memcached_history.status.success());
    let memcached_history: serde_json::Value =
        serde_json::from_slice(&memcached_history.stdout).unwrap();
    assert_eq!(memcached_history["samples"][0]["adapter"], "memcached");

    let missing = aic_cmd(tmp.path())
        .args(["workload", "history", "missing", "--json"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("not configured"));
}

#[test]
fn workload_enable_requires_current_fingerprint_and_persists_explicitly() {
    let tmp = tempfile::tempdir().unwrap();
    let discover = aic_cmd(tmp.path())
        .args(["workload", "discover", "--json"])
        .output()
        .unwrap();
    assert!(discover.status.success());
    let report: serde_json::Value = serde_json::from_slice(&discover.stdout).unwrap();
    let candidate = report["report"]["candidates"]
        .as_array()
        .and_then(|candidates| {
            candidates.iter().find(|candidate| {
                !candidate["selector"].is_null()
                    && candidate["ambiguity"].as_array().is_some_and(Vec::is_empty)
            })
        })
        .expect("현재 aic 프로세스에서 활성화 가능한 workload 후보가 있어야 함");
    let id = candidate["id"].as_str().unwrap();
    let fingerprint = candidate["fingerprint"].as_str().unwrap();

    let stale = aic_cmd(tmp.path())
        .args(["workload", "enable", id, "--fingerprint", "stale"])
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(!tmp.path().join("cfg/aic/workloads.toml").exists());

    let enabled = aic_cmd(tmp.path())
        .args([
            "workload",
            "enable",
            id,
            "--fingerprint",
            fingerprint,
            "--endpoint",
            "tcp://127.0.0.1:16379",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        enabled.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    let saved = std::fs::read_to_string(tmp.path().join("cfg/aic/workloads.toml")).unwrap();
    assert!(saved.contains(id));
    assert!(saved.contains("endpoint = \"tcp://127.0.0.1:16379\""));

    let listed = aic_cmd(tmp.path())
        .args(["workload", "list", "--json"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let configured: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(configured["configured"][0]["id"], id);
}

#[test]
fn workload_enable_rejects_conflicting_auth_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let output = aic_cmd(tmp.path())
        .args([
            "workload",
            "enable",
            "candidate",
            "--fingerprint",
            "fingerprint",
            "--endpoint",
            "tcp://127.0.0.1:6379",
            "--auth-env",
            "REDIS_PASSWORD",
            "--auth-keychain",
            "redis-monitor",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used"));
}

/// 보안 속성: 비대화(TTY 없음)에서 NeedsConfirm 명령은 자동 실행되지 않는다.
/// webhook/cron이 spawn한 진단이 상태 변경 명령을 자동 실행하면 안 되는 핵심 불변식.
#[test]
fn needs_confirm_command_is_rejected_when_non_interactive() {
    use aic_client::agent::run_command::execute_with_corr;
    use aic_client::agent::Sandbox;

    let sandbox = Sandbox::from_cwd().expect("sandbox");
    // systemctl restart = NeedsConfirm(상태 변경). 비대화 confirm 클로저는 항상 false.
    let args = serde_json::json!({ "command": "systemctl restart nginx" });
    let result = execute_with_corr(&args, &sandbox, "test-corr", |_, _, _| false).unwrap();
    assert!(
        result.contains("[denied]"),
        "NeedsConfirm은 비대화에서 거부되어야 함: {result}"
    );
    // 명령이 실제로 실행된 흔적(stdout)이 없어야 한다.
    assert!(!result.contains("Active:"), "명령이 실행됨: {result}");
}
