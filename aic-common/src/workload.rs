//! Workload discovery contracts shared by the CLI and chat paths.

use crate::paths;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

pub const REDIS_INFO_REQUEST: &[u8] = b"*1\r\n$4\r\nINFO\r\n";
pub const REDIS_SERVER_INFO_REQUEST: &[u8] = b"*2\r\n$4\r\nINFO\r\n$6\r\nSERVER\r\n";
#[cfg(unix)]
pub const REDIS_SOCKET_PATHS: &[&str] = &[
    "/run/redis/redis-server.sock",
    "/var/run/redis/redis-server.sock",
    "/tmp/redis.sock",
];
pub const REDIS_LOOPBACK_ENDPOINT: &str = "127.0.0.1:6379";
pub const DRIVER_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
pub const REDIS_RESPONSE_BYTES: usize = 64 * 1024;
pub const WORKLOAD_SAMPLE_SCHEMA_VERSION: u32 = 1;
pub const REDIS_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
pub const MAX_WORKLOAD_HISTORY_SAMPLES: usize = 1440;
pub const WORKLOAD_HISTORY_FILE: &str = "workload-history.jsonl";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisProbeError {
    Unreachable(String),
    Rejected(String),
    Malformed(String),
}

impl fmt::Display for RedisProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(detail) => write!(f, "Redis unreachable: {detail}"),
            Self::Rejected(detail) => write!(f, "Redis rejected request: {detail}"),
            Self::Malformed(detail) => write!(f, "Redis malformed response: {detail}"),
        }
    }
}

impl std::error::Error for RedisProbeError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadStore {
    #[serde(default)]
    pub workloads: Vec<WorkloadDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisWorkloadSample {
    pub schema_version: u32,
    pub workload_id: String,
    pub captured_at: DateTime<Utc>,
    #[serde(flatten)]
    pub outcome: RedisSampleOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RedisSampleOutcome {
    Collected {
        endpoint: String,
        metrics: RedisMetrics,
    },
    Failed {
        reason: RedisSampleFailure,
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisSampleFailure {
    Unreachable,
    Rejected,
    Malformed,
}

pub fn workloads_file_path() -> PathBuf {
    paths::config_file_path().with_file_name("workloads.toml")
}

pub fn workload_history_path() -> PathBuf {
    paths::state_dir().join(WORKLOAD_HISTORY_FILE)
}

pub fn load_workload_history(path: &Path) -> Result<Vec<RedisWorkloadSample>> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut samples = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect::<Vec<RedisWorkloadSample>>();
    samples.sort_by_key(|sample| sample.captured_at);
    Ok(samples)
}

pub fn monitor_redis() -> std::result::Result<(String, RedisMetrics), RedisProbeError> {
    let mut errors = Vec::new();
    #[cfg(unix)]
    for path in REDIS_SOCKET_PATHS {
        match monitor_redis_unix_socket(Path::new(path)) {
            Ok(metrics) => return Ok(((*path).to_string(), metrics)),
            Err(error) => errors.push(error),
        }
    }
    let endpoint: SocketAddr = REDIS_LOOPBACK_ENDPOINT
        .parse()
        .expect("valid Redis endpoint");
    match monitor_redis_tcp(endpoint) {
        Ok(metrics) => Ok((REDIS_LOOPBACK_ENDPOINT.to_string(), metrics)),
        Err(error) => {
            errors.push(error);
            Err(preferred_redis_error(errors))
        }
    }
}

fn preferred_redis_error(errors: Vec<RedisProbeError>) -> RedisProbeError {
    errors
        .into_iter()
        .max_by_key(|error| match error {
            RedisProbeError::Rejected(_) => 2,
            RedisProbeError::Malformed(_) => 1,
            RedisProbeError::Unreachable(_) => 0,
        })
        .unwrap_or_else(|| RedisProbeError::Unreachable("no endpoint".into()))
}

pub fn probe_redis_server() -> std::result::Result<(), RedisProbeError> {
    #[cfg(unix)]
    for path in REDIS_SOCKET_PATHS {
        if probe_redis_server_unix_socket(Path::new(path)).is_ok() {
            return Ok(());
        }
    }
    let endpoint: SocketAddr = REDIS_LOOPBACK_ENDPOINT
        .parse()
        .expect("valid Redis endpoint");
    probe_redis_server_tcp(endpoint)
}

pub fn monitor_redis_stream(
    stream: &mut (impl Read + Write),
) -> std::result::Result<RedisMetrics, RedisProbeError> {
    stream.write_all(REDIS_INFO_REQUEST).map_err(unreachable)?;
    stream.flush().map_err(unreachable)?;
    let response = read_redis_info_response(stream, REDIS_RESPONSE_BYTES)?;
    parse_redis_info(&response)
}

pub fn read_redis_info_response(
    stream: &mut impl Read,
    response_cap: usize,
) -> std::result::Result<String, RedisProbeError> {
    let mut consumed = 1;
    let mut prefix = [0_u8; 1];
    stream.read_exact(&mut prefix).map_err(unreachable)?;
    if prefix[0] == b'-' {
        return Err(RedisProbeError::Rejected(read_resp_line(
            stream,
            response_cap,
            &mut consumed,
        )?));
    }
    if prefix[0] != b'$' {
        return Err(RedisProbeError::Malformed(
            "Redis INFO returned malformed RESP".into(),
        ));
    }
    let length = read_resp_line(stream, response_cap, &mut consumed)?
        .parse::<usize>()
        .map_err(|_| {
            RedisProbeError::Malformed("Redis INFO returned an invalid bulk length".into())
        })?;
    if length > response_cap.saturating_sub(consumed).saturating_sub(2) {
        return Err(RedisProbeError::Malformed(
            "Redis INFO response exceeded the byte cap".into(),
        ));
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).map_err(unreachable)?;
    let mut terminator = [0_u8; 2];
    stream.read_exact(&mut terminator).map_err(unreachable)?;
    if terminator != *b"\r\n" {
        return Err(RedisProbeError::Malformed(
            "Redis INFO returned a malformed bulk terminator".into(),
        ));
    }
    String::from_utf8(body).map_err(|error| RedisProbeError::Malformed(error.to_string()))
}

pub fn parse_redis_info(info: &str) -> std::result::Result<RedisMetrics, RedisProbeError> {
    let mut values = std::collections::BTreeMap::new();
    for line in info
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (key, value) = line.split_once(':').ok_or_else(|| {
            RedisProbeError::Malformed("Redis INFO contains a malformed line".into())
        })?;
        if values.insert(key, value).is_some() {
            return Err(RedisProbeError::Malformed(format!(
                "Redis INFO contains a duplicate metric: {key}"
            )));
        }
    }
    let metric = |key| {
        values
            .get(key)
            .ok_or_else(|| RedisProbeError::Malformed(format!("Redis INFO is missing {key}")))
            .and_then(|value| {
                value.parse().map_err(|_| {
                    RedisProbeError::Malformed(format!("Redis INFO metric is not numeric: {key}"))
                })
            })
    };
    Ok(RedisMetrics {
        connected_clients: metric("connected_clients")?,
        used_memory: metric("used_memory")?,
        total_commands_processed: metric("total_commands_processed")?,
        instantaneous_ops_per_sec: metric("instantaneous_ops_per_sec")?,
        keyspace_hits: metric("keyspace_hits")?,
        keyspace_misses: metric("keyspace_misses")?,
    })
}

fn read_resp_line(
    stream: &mut impl Read,
    cap: usize,
    consumed: &mut usize,
) -> std::result::Result<String, RedisProbeError> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while *consumed < cap {
        stream.read_exact(&mut byte).map_err(unreachable)?;
        *consumed += 1;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line)
                .map_err(|error| RedisProbeError::Malformed(error.to_string()));
        }
    }
    Err(RedisProbeError::Malformed(
        "Redis INFO response exceeded the byte cap".into(),
    ))
}

fn unreachable(error: std::io::Error) -> RedisProbeError {
    RedisProbeError::Unreachable(error.to_string())
}

fn monitor_redis_tcp(endpoint: SocketAddr) -> std::result::Result<RedisMetrics, RedisProbeError> {
    let mut stream =
        TcpStream::connect_timeout(&endpoint, DRIVER_CONNECT_TIMEOUT).map_err(unreachable)?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    monitor_redis_stream(&mut stream)
}

fn probe_redis_server_tcp(endpoint: SocketAddr) -> std::result::Result<(), RedisProbeError> {
    let mut stream =
        TcpStream::connect_timeout(&endpoint, DRIVER_CONNECT_TIMEOUT).map_err(unreachable)?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    probe_redis_server_stream(&mut stream)
}

#[cfg(unix)]
fn monitor_redis_unix_socket(path: &Path) -> std::result::Result<RedisMetrics, RedisProbeError> {
    let mut stream = UnixStream::connect(path).map_err(unreachable)?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    monitor_redis_stream(&mut stream)
}

#[cfg(unix)]
fn probe_redis_server_unix_socket(path: &Path) -> std::result::Result<(), RedisProbeError> {
    let mut stream = UnixStream::connect(path).map_err(unreachable)?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    probe_redis_server_stream(&mut stream)
}

fn probe_redis_server_stream(
    stream: &mut (impl Read + Write),
) -> std::result::Result<(), RedisProbeError> {
    stream
        .write_all(REDIS_SERVER_INFO_REQUEST)
        .map_err(unreachable)?;
    stream.flush().map_err(unreachable)?;
    let response = read_redis_info_response(stream, REDIS_RESPONSE_BYTES)?;
    if response.contains("# Server") {
        Ok(())
    } else {
        Err(RedisProbeError::Malformed(
            "Redis INFO SERVER was not accepted".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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

    #[test]
    fn redis_probe_rejects_noauth_and_malformed_responses() {
        assert!(matches!(
            read_redis_info_response(&mut Cursor::new(b"-NOAUTH Authentication required.\r\n"), 128),
            Err(RedisProbeError::Rejected(detail)) if detail.contains("NOAUTH")
        ));
        assert!(matches!(
            read_redis_info_response(&mut Cursor::new(b"+OK\r\n"), 32),
            Err(RedisProbeError::Malformed(_))
        ));
        assert!(matches!(
            preferred_redis_error(vec![
                RedisProbeError::Rejected("NOAUTH".into()),
                RedisProbeError::Unreachable("connection refused".into()),
            ]),
            RedisProbeError::Rejected(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn redis_monitor_stream_parses_complete_info_response() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let body = concat!(
            "# Clients\r\nconnected_clients:3\r\n",
            "# Memory\r\nused_memory:4096\r\n",
            "# Stats\r\ntotal_commands_processed:17\r\n",
            "instantaneous_ops_per_sec:2\r\n",
            "keyspace_hits:11\r\nkeyspace_misses:4\r\n"
        );
        let response = format!("${}\r\n{}\r\n", body.len(), body);
        let (mut peer, mut client) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut request = [0_u8; REDIS_INFO_REQUEST.len()];
            peer.read_exact(&mut request).unwrap();
            assert_eq!(&request, REDIS_INFO_REQUEST);
            peer.write_all(response.as_bytes()).unwrap();
        });

        let metrics = monitor_redis_stream(&mut client).unwrap();
        assert_eq!(metrics.connected_clients, 3);
        assert_eq!(metrics.total_commands_processed, 17);
        assert_eq!(metrics.keyspace_misses, 4);
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn redis_monitor_stream_times_out_without_response() {
        use std::os::unix::net::UnixStream;

        let (_peer, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        assert!(matches!(
            monitor_redis_stream(&mut client),
            Err(RedisProbeError::Unreachable(_))
        ));
    }

    #[test]
    fn history_loader_skips_corrupt_and_torn_lines() {
        let path = std::env::temp_dir().join(format!(
            "aic-workload-history-{}-{}.jsonl",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let sample = RedisWorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "redis".into(),
            captured_at: Utc::now(),
            outcome: RedisSampleOutcome::Failed {
                reason: RedisSampleFailure::Rejected,
                detail: "NOAUTH".into(),
            },
        };
        fs::write(
            &path,
            format!(
                "{}\nnot-json\n{{\"schema_version\":",
                serde_json::to_string(&sample).unwrap()
            ),
        )
        .unwrap();
        assert_eq!(load_workload_history(&path).unwrap(), vec![sample]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn redis_samples_round_trip_collected_and_failed_outcomes() {
        let captured_at = Utc::now();
        let samples = [
            RedisWorkloadSample {
                schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
                workload_id: "redis".into(),
                captured_at,
                outcome: RedisSampleOutcome::Collected {
                    endpoint: REDIS_LOOPBACK_ENDPOINT.into(),
                    metrics: RedisMetrics {
                        connected_clients: 1,
                        used_memory: 2,
                        total_commands_processed: 3,
                        instantaneous_ops_per_sec: 4,
                        keyspace_hits: 5,
                        keyspace_misses: 6,
                    },
                },
            },
            RedisWorkloadSample {
                schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
                workload_id: "redis".into(),
                captured_at,
                outcome: RedisSampleOutcome::Failed {
                    reason: RedisSampleFailure::Unreachable,
                    detail: "Redis endpoint is unavailable".into(),
                },
            },
        ];
        for sample in samples {
            let encoded = serde_json::to_string(&sample).unwrap();
            assert_eq!(
                serde_json::from_str::<RedisWorkloadSample>(&encoded).unwrap(),
                sample
            );
        }
    }

    #[test]
    fn redis_monitor_reports_unavailable_endpoint() {
        let endpoint: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(matches!(
            monitor_redis_tcp(endpoint),
            Err(RedisProbeError::Unreachable(_))
        ));
    }
}
