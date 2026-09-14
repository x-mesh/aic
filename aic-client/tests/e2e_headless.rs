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
        ClickHouseMetrics, ElasticsearchMetrics, EtcdMetrics, MemcachedMetrics, MongoDbMetrics,
        MySqlMetrics, NginxMetrics, OpenSearchMetrics, PostgreSqlMetrics, PrometheusMetrics,
        RabbitMqMetrics, WorkloadAdapter, WorkloadDefinition, WorkloadDriverMode, WorkloadMetrics,
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
    let nginx_definition = WorkloadDefinition {
        id: "nginx-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/sbin/nginx".into(),
        },
        adapter: WorkloadAdapter::Nginx,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:18080".into(),
            username: Some("aic_monitor".into()),
            secret_ref: Some("env:NGINX_PASSWORD".into()),
            database: None,
            auth_source: None,
        }),
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
    let postgresql_definition = WorkloadDefinition {
        id: "postgresql-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/postgres".into(),
        },
        adapter: WorkloadAdapter::PostgreSql,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:5432".into(),
            username: Some("aic_monitor".into()),
            secret_ref: None,
            database: Some("postgres".into()),
            auth_source: None,
        }),
    };
    let mysql_definition = WorkloadDefinition {
        id: "mysql-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/sbin/mysqld".into(),
        },
        adapter: WorkloadAdapter::MySql,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:3306".into(),
            username: Some("aic_monitor".into()),
            secret_ref: Some("env:MYSQL_PASSWORD".into()),
            database: Some("metrics".into()),
            auth_source: None,
        }),
    };
    let mongodb_definition = WorkloadDefinition {
        id: "mongodb-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/mongod".into(),
        },
        adapter: WorkloadAdapter::MongoDb,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:27017".into(),
            username: Some("aic_monitor".into()),
            secret_ref: Some("env:MONGODB_PASSWORD".into()),
            database: None,
            auth_source: Some("admin".into()),
        }),
    };
    let prometheus_definition = WorkloadDefinition {
        id: "prometheus-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/prometheus".into(),
        },
        adapter: WorkloadAdapter::Prometheus,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:9090".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        }),
    };
    let clickhouse_definition = WorkloadDefinition {
        id: "clickhouse-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/clickhouse-server".into(),
        },
        adapter: WorkloadAdapter::ClickHouse,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:18123".into(),
            username: Some("aic_monitor".into()),
            secret_ref: Some("env:CLICKHOUSE_PASSWORD".into()),
            database: None,
            auth_source: None,
        }),
    };
    let etcd_definition = WorkloadDefinition {
        id: "etcd-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/etcd".into(),
        },
        adapter: WorkloadAdapter::Etcd,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:12379".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        }),
    };
    let elasticsearch_definition = WorkloadDefinition {
        id: "elasticsearch-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/java".into(),
        },
        adapter: WorkloadAdapter::Elasticsearch,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:19200".into(),
            username: Some("aic_monitor".into()),
            secret_ref: Some("env:ELASTICSEARCH_PASSWORD".into()),
            database: None,
            auth_source: None,
        }),
    };
    let opensearch_definition = WorkloadDefinition {
        id: "opensearch-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/bin/java".into(),
        },
        adapter: WorkloadAdapter::OpenSearch,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:19201".into(),
            username: Some("aic_monitor".into()),
            secret_ref: Some("env:OPENSEARCH_PASSWORD".into()),
            database: None,
            auth_source: None,
        }),
    };
    let rabbitmq_definition = WorkloadDefinition {
        id: "rabbitmq-test".into(),
        selector: WorkloadSelector::Executable {
            path: "/usr/sbin/rabbitmq-server".into(),
        },
        adapter: WorkloadAdapter::RabbitMq,
        driver_mode: WorkloadDriverMode::MonitorReady,
        connection: Some(aic_common::workload::WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:15672".into(),
            username: Some("aic_monitor".into()),
            secret_ref: Some("env:RABBITMQ_PASSWORD".into()),
            database: None,
            auth_source: None,
        }),
    };
    std::fs::write(
        config_dir.join("workloads.toml"),
        toml::to_string_pretty(&WorkloadStore {
            workloads: vec![
                redis_definition,
                nginx_definition,
                memcached_definition,
                postgresql_definition,
                mysql_definition,
                mongodb_definition,
                prometheus_definition,
                clickhouse_definition,
                etcd_definition,
                elasticsearch_definition,
                opensearch_definition,
                rabbitmq_definition,
            ],
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
    let nginx_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "nginx-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::Nginx,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:18080".into(),
            metrics: WorkloadMetrics::Nginx(NginxMetrics {
                active_connections: 1,
                accepts_total: 2,
                handled_total: 3,
                requests_total: 4,
                reading: 5,
                writing: 6,
                waiting: 7,
            }),
        },
    };
    let postgresql_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "postgresql-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::PostgreSql,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:5432".into(),
            metrics: WorkloadMetrics::PostgreSql(PostgreSqlMetrics {
                numbackends: 1,
                xact_commit: 2,
                xact_rollback: 3,
                blks_read: 4,
                blks_hit: 5,
                tup_returned: 6,
                tup_fetched: 7,
                tup_inserted: 8,
                tup_updated: 9,
                tup_deleted: 10,
                conflicts: 11,
                temp_files: 12,
                temp_bytes: 13,
                deadlocks: 14,
            }),
        },
    };
    let mysql_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "mysql-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::MySql,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:3306".into(),
            metrics: WorkloadMetrics::MySql(MySqlMetrics {
                threads_connected: 1,
                threads_running: 2,
                connections: 3,
                aborted_connects: 4,
                questions: 5,
                slow_queries: 6,
                bytes_received: 7,
                bytes_sent: 8,
            }),
        },
    };
    let mongodb_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "mongodb-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::MongoDb,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:27017".into(),
            metrics: WorkloadMetrics::MongoDb(MongoDbMetrics {
                connections_current: 1,
                connections_available: 2,
                connections_total_created: 3,
                opcounters_query: 4,
                opcounters_get_more: 5,
                opcounters_command: 6,
                network_bytes_in: 7,
                network_bytes_out: 8,
                network_num_requests: 9,
                uptime_seconds: 10,
            }),
        },
    };
    let prometheus_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "prometheus-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::Prometheus,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:9090".into(),
            metrics: WorkloadMetrics::Prometheus(PrometheusMetrics {
                config_last_reload_successful: 1,
                tsdb_head_series: 2,
                tsdb_head_chunks: 3,
                tsdb_head_samples_appended_total: 4,
                engine_queries: 5,
                process_resident_memory_bytes: 6,
                process_virtual_memory_bytes: 7,
                go_goroutines: 8,
            }),
        },
    };
    let clickhouse_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "clickhouse-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::ClickHouse,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:18123".into(),
            metrics: WorkloadMetrics::ClickHouse(ClickHouseMetrics {
                queries: 1,
                merges: 2,
                part_mutations: 3,
                replicated_fetches: 4,
                replicated_sends: 5,
                tcp_connections: 6,
                http_connections: 7,
                memory_tracking_bytes: 8,
                uptime_seconds: 9,
                memory_resident_bytes: 10,
            }),
        },
    };
    let etcd_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "etcd-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::Etcd,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:12379".into(),
            metrics: WorkloadMetrics::Etcd(EtcdMetrics {
                server_has_leader: 1,
                server_is_leader: 0,
                leader_changes_seen_total: 2,
                proposals_applied_total: 3,
                proposals_committed_total: 4,
                proposals_failed_total: 5,
                proposals_pending: 6,
                mvcc_db_total_size_bytes: 7,
                mvcc_db_total_size_in_use_bytes: 8,
                process_resident_memory_bytes: 9,
            }),
        },
    };
    let elasticsearch_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "elasticsearch-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::Elasticsearch,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:19200".into(),
            metrics: WorkloadMetrics::Elasticsearch(ElasticsearchMetrics {
                nodes_total: 1,
                indices_count: 2,
                shards_total: 3,
                shards_primaries: 4,
                docs_count: 5,
                docs_deleted: 6,
                store_size_bytes: 7,
                fs_total_bytes: 8,
                fs_available_bytes: 9,
            }),
        },
    };
    let opensearch_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "opensearch-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::OpenSearch,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:19201".into(),
            metrics: WorkloadMetrics::OpenSearch(OpenSearchMetrics {
                nodes_total: 11,
                indices_count: 12,
                shards_total: 13,
                shards_primaries: 14,
                docs_count: 15,
                docs_deleted: 16,
                store_size_bytes: 17,
                fs_total_bytes: 18,
                fs_available_bytes: 19,
            }),
        },
    };
    let rabbitmq_sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: "rabbitmq-test".into(),
        captured_at: Utc::now() - Duration::minutes(10),
        adapter: WorkloadAdapter::RabbitMq,
        outcome: WorkloadSampleOutcome::Collected {
            endpoint: "tcp://127.0.0.1:15672".into(),
            metrics: WorkloadMetrics::RabbitMq(RabbitMqMetrics {
                messages: 1,
                messages_ready: 2,
                messages_unacknowledged: 3,
                queues: 4,
                connections: 5,
                channels: 6,
                consumers: 7,
                exchanges: 8,
                message_stats_publish_total: 9,
                message_stats_deliver_get_total: 10,
            }),
        },
    };
    std::fs::write(
        state_dir.join("workload-history.jsonl"),
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\nnot-json\n",
            legacy_redis_sample,
            serde_json::to_string(&nginx_sample).unwrap(),
            serde_json::to_string(&memcached_sample).unwrap(),
            serde_json::to_string(&postgresql_sample).unwrap(),
            serde_json::to_string(&mysql_sample).unwrap(),
            serde_json::to_string(&mongodb_sample).unwrap(),
            serde_json::to_string(&prometheus_sample).unwrap(),
            serde_json::to_string(&clickhouse_sample).unwrap(),
            serde_json::to_string(&etcd_sample).unwrap(),
            serde_json::to_string(&elasticsearch_sample).unwrap(),
            serde_json::to_string(&opensearch_sample).unwrap(),
            serde_json::to_string(&rabbitmq_sample).unwrap()
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
    let output = aic_cmd(tmp.path())
        .args(["workload", "history", "nginx-test", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["samples"][0]["adapter"], "nginx");
    assert_eq!(value["samples"][0]["metrics"]["waiting"], 7);

    let memcached_history = aic_cmd(tmp.path())
        .args(["workload", "history", "memcached-test", "--json"])
        .output()
        .unwrap();
    assert!(memcached_history.status.success());
    let memcached_history: serde_json::Value =
        serde_json::from_slice(&memcached_history.stdout).unwrap();
    assert_eq!(memcached_history["samples"][0]["adapter"], "memcached");

    let postgresql_history = aic_cmd(tmp.path())
        .args(["workload", "history", "postgresql-test", "--json"])
        .output()
        .unwrap();
    assert!(postgresql_history.status.success());
    let postgresql_history: serde_json::Value =
        serde_json::from_slice(&postgresql_history.stdout).unwrap();
    assert_eq!(postgresql_history["samples"][0]["adapter"], "postgre_sql");
    assert_eq!(postgresql_history["samples"][0]["metrics"]["deadlocks"], 14);

    let mysql_history = aic_cmd(tmp.path())
        .args(["workload", "history", "mysql-test", "--json"])
        .output()
        .unwrap();
    assert!(mysql_history.status.success());
    let mysql_history: serde_json::Value = serde_json::from_slice(&mysql_history.stdout).unwrap();
    assert_eq!(mysql_history["samples"][0]["adapter"], "my_sql");
    assert_eq!(mysql_history["samples"][0]["metrics"]["bytes_sent"], 8);

    let mongodb_history = aic_cmd(tmp.path())
        .args(["workload", "history", "mongodb-test", "--json"])
        .output()
        .unwrap();
    assert!(mongodb_history.status.success());
    let mongodb_history: serde_json::Value =
        serde_json::from_slice(&mongodb_history.stdout).unwrap();
    assert_eq!(mongodb_history["samples"][0]["adapter"], "mongo_db");
    assert_eq!(
        mongodb_history["samples"][0]["metrics"]["uptime_seconds"],
        10
    );

    let prometheus_history = aic_cmd(tmp.path())
        .args(["workload", "history", "prometheus-test", "--json"])
        .output()
        .unwrap();
    assert!(prometheus_history.status.success());
    let prometheus_history: serde_json::Value =
        serde_json::from_slice(&prometheus_history.stdout).unwrap();
    assert_eq!(prometheus_history["samples"][0]["adapter"], "prometheus");
    assert_eq!(
        prometheus_history["samples"][0]["metrics"]["go_goroutines"],
        8
    );

    let clickhouse_history = aic_cmd(tmp.path())
        .args(["workload", "history", "clickhouse-test", "--json"])
        .output()
        .unwrap();
    assert!(clickhouse_history.status.success());
    let clickhouse_history: serde_json::Value =
        serde_json::from_slice(&clickhouse_history.stdout).unwrap();
    assert_eq!(clickhouse_history["samples"][0]["adapter"], "click_house");
    assert_eq!(
        clickhouse_history["samples"][0]["metrics"]["memory_resident_bytes"],
        10
    );

    let etcd_history = aic_cmd(tmp.path())
        .args(["workload", "history", "etcd-test", "--json"])
        .output()
        .unwrap();
    assert!(etcd_history.status.success());
    let etcd_history: serde_json::Value = serde_json::from_slice(&etcd_history.stdout).unwrap();
    assert_eq!(etcd_history["samples"][0]["adapter"], "etcd");
    assert_eq!(
        etcd_history["samples"][0]["metrics"]["process_resident_memory_bytes"],
        9
    );
    for (id, adapter, expected) in [
        ("elasticsearch-test", "elasticsearch", 9),
        ("opensearch-test", "open_search", 19),
    ] {
        let output = aic_cmd(tmp.path())
            .args(["workload", "history", id, "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["samples"][0]["adapter"], adapter);
        assert_eq!(
            value["samples"][0]["metrics"]["fs_available_bytes"],
            expected
        );
    }
    let output = aic_cmd(tmp.path())
        .args(["workload", "history", "rabbitmq-test", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["samples"][0]["adapter"], "rabbit_mq");
    assert_eq!(
        value["samples"][0]["metrics"]["message_stats_deliver_get_total"],
        10
    );

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
    let postgresql = candidate["adapter"] == "postgre_sql";
    let mysql = candidate["adapter"] == "my_sql";
    let mongodb = candidate["adapter"] == "mongo_db";
    let prometheus = candidate["adapter"] == "prometheus";
    let clickhouse = candidate["adapter"] == "click_house";
    let etcd = candidate["adapter"] == "etcd";
    let elasticsearch = candidate["adapter"] == "elasticsearch";
    let opensearch = candidate["adapter"] == "open_search";

    let stale = aic_cmd(tmp.path())
        .args(["workload", "enable", id, "--fingerprint", "stale"])
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(!tmp.path().join("cfg/aic/workloads.toml").exists());

    let mut enabled = aic_cmd(tmp.path());
    enabled.args([
        "workload",
        "enable",
        id,
        "--fingerprint",
        fingerprint,
        "--endpoint",
        if postgresql {
            "tcp://127.0.0.1:5432"
        } else if mysql {
            "tcp://127.0.0.1:3306"
        } else if mongodb {
            "tcp://127.0.0.1:27017"
        } else if prometheus {
            "tcp://127.0.0.1:19090"
        } else if clickhouse {
            "tcp://127.0.0.1:18123"
        } else if etcd {
            "tcp://127.0.0.1:12379"
        } else if elasticsearch {
            "tcp://127.0.0.1:19200"
        } else if opensearch {
            "tcp://127.0.0.1:19201"
        } else {
            "tcp://127.0.0.1:16379"
        },
    ]);
    if postgresql {
        enabled.args(["--username", "aic_monitor", "--database", "postgres"]);
    } else if mysql {
        enabled.args(["--username", "aic_monitor", "--database", "metrics"]);
    } else if mongodb {
        enabled.args([
            "--username",
            "aic_monitor",
            "--auth-env",
            "MONGODB_PASSWORD",
            "--auth-source",
            "admin",
        ]);
    } else if clickhouse {
        enabled.args([
            "--username",
            "aic_monitor",
            "--auth-env",
            "CLICKHOUSE_PASSWORD",
        ]);
    } else if elasticsearch || opensearch {
        enabled.args([
            "--username",
            "aic_monitor",
            "--auth-env",
            if elasticsearch {
                "ELASTICSEARCH_PASSWORD"
            } else {
                "OPENSEARCH_PASSWORD"
            },
        ]);
    }
    let enabled = enabled.arg("--json").output().unwrap();
    assert!(
        enabled.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    let saved = std::fs::read_to_string(tmp.path().join("cfg/aic/workloads.toml")).unwrap();
    assert!(saved.contains(id));
    assert!(saved.contains(if postgresql {
        "endpoint = \"tcp://127.0.0.1:5432\""
    } else if mysql {
        "endpoint = \"tcp://127.0.0.1:3306\""
    } else if mongodb {
        "endpoint = \"tcp://127.0.0.1:27017\""
    } else if prometheus {
        "endpoint = \"tcp://127.0.0.1:19090\""
    } else if clickhouse {
        "endpoint = \"tcp://127.0.0.1:18123\""
    } else if etcd {
        "endpoint = \"tcp://127.0.0.1:12379\""
    } else if elasticsearch {
        "endpoint = \"tcp://127.0.0.1:19200\""
    } else if opensearch {
        "endpoint = \"tcp://127.0.0.1:19201\""
    } else {
        "endpoint = \"tcp://127.0.0.1:16379\""
    }));
    if postgresql {
        assert!(saved.contains("username = \"aic_monitor\""));
        assert!(saved.contains("database = \"postgres\""));
    } else if mysql {
        assert!(saved.contains("username = \"aic_monitor\""));
        assert!(saved.contains("database = \"metrics\""));
    } else if mongodb {
        assert!(saved.contains("username = \"aic_monitor\""));
        assert!(saved.contains("secret_ref = \"env:MONGODB_PASSWORD\""));
        assert!(saved.contains("auth_source = \"admin\""));
    } else if clickhouse {
        assert!(saved.contains("username = \"aic_monitor\""));
        assert!(saved.contains("secret_ref = \"env:CLICKHOUSE_PASSWORD\""));
    } else if elasticsearch || opensearch {
        assert!(saved.contains("username = \"aic_monitor\""));
        assert!(saved.contains(if elasticsearch {
            "secret_ref = \"env:ELASTICSEARCH_PASSWORD\""
        } else {
            "secret_ref = \"env:OPENSEARCH_PASSWORD\""
        }));
    }

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

#[test]
fn workload_enable_requires_endpoint_for_database() {
    let tmp = tempfile::tempdir().unwrap();
    let output = aic_cmd(tmp.path())
        .args([
            "workload",
            "enable",
            "candidate",
            "--fingerprint",
            "fingerprint",
            "--database",
            "postgres",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--database"));
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
