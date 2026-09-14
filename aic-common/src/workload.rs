//! Workload discovery contracts shared by the CLI and chat paths.

use serde::{Deserialize, Serialize};

pub const WORKLOAD_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadSelector {
    SystemdUnit {
        unit: String,
    },
    Executable {
        path: String,
    },
    JvmMain {
        executable: String,
        main_class: String,
    },
}

impl WorkloadSelector {
    pub fn stable_id(&self) -> String {
        match self {
            Self::SystemdUnit { unit } => format!("systemd:{unit}"),
            Self::Executable { path } => format!("exe:{path}"),
            Self::JvmMain {
                executable,
                main_class,
            } => format!("jvm:{executable}:{main_class}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadAdapter {
    Nginx,
    Jvm,
    Redis,
    PostgreSql,
    MySql,
    MongoDb,
    Kafka,
    Elasticsearch,
    OpenSearch,
    RabbitMq,
    HaProxy,
    Prometheus,
    ClickHouse,
    Etcd,
    Consul,
    Memcached,
    Generic,
}

/// Driver capability that the local evidence has established for a workload.
///
/// A detected process does not prove that AIC can access a service socket, credentials, or
/// protocol metrics. Drivers must advance this state only after their own read-only checks pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadDriverMode {
    #[default]
    DetectOnly,
    InspectReady,
    MonitorReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBinding {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadCandidate {
    pub id: String,
    pub fingerprint: String,
    pub selector: Option<WorkloadSelector>,
    pub adapter: WorkloadAdapter,
    /// `None` means that no workload driver is available for this process type.
    #[serde(default)]
    pub driver_mode: Option<WorkloadDriverMode>,
    pub bindings: Vec<RuntimeBinding>,
    #[serde(default)]
    pub ambiguity: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadDefinition {
    pub id: String,
    pub selector: WorkloadSelector,
    pub adapter: WorkloadAdapter,
    /// Older workload definitions predate drivers and default to detect-only.
    #[serde(default)]
    pub driver_mode: WorkloadDriverMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReport {
    pub schema_version: u32,
    pub evidence_coverage: String,
    pub candidates: Vec<WorkloadCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    Inspect,
    DriverInspect,
    Enable,
    ProcessResourceMonitoring,
    NginxAdapterMonitoring,
    JvmAdapterMonitoring,
    ServiceAdapterMonitoring,
    NginxJvmTopologyCorrelation,
    RcaEvidenceAttachment,
    LocalRetention,
    RcaWebExport,
    BoundedOnDemandProfiling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalReadiness {
    Available,
    Planned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCost {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalEffects {
    pub persistence: bool,
    pub privilege: bool,
    pub outbound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadProposal {
    pub id: String,
    pub kind: ProposalKind,
    pub candidate_id: String,
    pub evidence: Vec<String>,
    pub reason: String,
    pub expected_signals: Vec<String>,
    pub cost: ProposalCost,
    pub effects: ProposalEffects,
    pub readiness: ProposalReadiness,
    pub command: Option<String>,
    #[serde(default)]
    pub related_candidate_ids: Vec<String>,
}

/// Numeric metrics returned by one bounded Redis INFO probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisMetrics {
    pub connected_clients: u64,
    pub used_memory: u64,
    pub total_commands_processed: u64,
    pub instantaneous_ops_per_sec: u64,
    pub keyspace_hits: u64,
    pub keyspace_misses: u64,
}

/// Result of a one-shot Redis monitor probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisMonitorReport {
    pub candidate_id: String,
    pub monitor_ready: bool,
    pub metrics: RedisMetrics,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_selector_does_not_include_runtime_binding() {
        let selector = WorkloadSelector::Executable {
            path: "/usr/sbin/nginx".into(),
        };
        assert_eq!(selector.stable_id(), "exe:/usr/sbin/nginx");
        let old = RuntimeBinding {
            pid: 42,
            start_time: 1,
        };
        let new = RuntimeBinding {
            pid: 42,
            start_time: 2,
        };
        assert_ne!(old, new);
    }

    #[test]
    fn schema_round_trips_as_json_and_toml() {
        let definition = WorkloadDefinition {
            id: "jvm:/usr/bin/java:example.Main".to_string(),
            selector: WorkloadSelector::JvmMain {
                executable: "/usr/bin/java".to_string(),
                main_class: "example.Main".to_string(),
            },
            adapter: WorkloadAdapter::Jvm,
            driver_mode: WorkloadDriverMode::DetectOnly,
        };
        let json = serde_json::to_string(&definition).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadDefinition>(&json).unwrap(),
            definition
        );
        let toml = toml::to_string(&definition).unwrap();
        assert_eq!(
            toml::from_str::<WorkloadDefinition>(&toml).unwrap(),
            definition
        );
    }

    #[test]
    fn old_definition_defaults_to_detect_only_driver() {
        let json = r#"{
            "id": "exe:/usr/sbin/nginx",
            "selector": { "executable": { "path": "/usr/sbin/nginx" } },
            "adapter": "nginx"
        }"#;
        let definition: WorkloadDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(definition.driver_mode, WorkloadDriverMode::DetectOnly);
    }

    #[test]
    fn proposals_round_trip_available_and_planned_shapes() {
        let available = WorkloadProposal {
            id: "inspect:candidate".into(),
            kind: ProposalKind::Inspect,
            candidate_id: "candidate".into(),
            evidence: vec!["process inventory".into()],
            reason: "Inspect the current candidate.".into(),
            expected_signals: vec!["bindings".into()],
            cost: ProposalCost::Low,
            effects: ProposalEffects {
                persistence: false,
                privilege: false,
                outbound: false,
            },
            readiness: ProposalReadiness::Available,
            command: Some("/workload inspect candidate".into()),
            related_candidate_ids: Vec::new(),
        };
        let mut planned = available.clone();
        planned.id = "retention:candidate".into();
        planned.kind = ProposalKind::LocalRetention;
        planned.readiness = ProposalReadiness::Planned;
        planned.command = None;
        for proposal in [available, planned] {
            let json = serde_json::to_string(&proposal).unwrap();
            assert_eq!(
                serde_json::from_str::<WorkloadProposal>(&json).unwrap(),
                proposal
            );
        }
    }

    #[test]
    fn redis_monitor_report_serializes_numeric_metrics() {
        let report = RedisMonitorReport {
            candidate_id: "exe:/usr/bin/redis-server".into(),
            monitor_ready: true,
            metrics: RedisMetrics {
                connected_clients: 2,
                used_memory: 4096,
                total_commands_processed: 10,
                instantaneous_ops_per_sec: 3,
                keyspace_hits: 8,
                keyspace_misses: 1,
            },
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["monitor_ready"], true);
        assert_eq!(json["metrics"]["used_memory"], 4096);
        assert!(json["metrics"]["used_memory"].is_u64());
    }
}
