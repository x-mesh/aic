//! Deterministic local workload discovery and explicit definition storage.

use crate::config::ConfigManager;
use aic_common::workload::{ProposalCost, ProposalReadiness};
use aic_common::{
    DiscoveryReport, ProposalEffects, ProposalKind, RuntimeBinding, WorkloadAdapter,
    WorkloadCandidate, WorkloadDefinition, WorkloadDriverMode, WorkloadProposal, WorkloadSelector,
    WORKLOAD_SCHEMA_VERSION,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const MAX_PROCESSES: usize = 4096;
const MAX_CANDIDATES: usize = 256;
const MAX_COMMAND_TOKENS: usize = 16;
const MAX_TOKEN_BYTES: usize = 256;
#[cfg(target_os = "linux")]
const MAX_CGROUP_BYTES: u64 = 8 * 1024;
const MAX_SUMMARY_BYTES: usize = 512;
const MAX_RELATIONSHIP_PROPOSALS: usize = 32;
const DRIVER_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
const DRIVER_RESPONSE_BYTES: usize = 1024;
const REDIS_LOOPBACK_ENDPOINT: &str = "127.0.0.1:6379";
const POSTGRES_LOOPBACK_ENDPOINT: &str = "127.0.0.1:5432";
const NGINX_CONFIG_PATHS: &[&str] = &["/etc/nginx/nginx.conf", "/usr/local/etc/nginx/nginx.conf"];
#[cfg(unix)]
const REDIS_SOCKET_PATHS: &[&str] = &[
    "/run/redis/redis-server.sock",
    "/var/run/redis/redis-server.sock",
    "/tmp/redis.sock",
];
#[cfg(unix)]
const POSTGRES_SOCKET_PATHS: &[&str] = &[
    "/run/postgresql/.s.PGSQL.5432",
    "/var/run/postgresql/.s.PGSQL.5432",
    "/tmp/.s.PGSQL.5432",
];

#[derive(Debug, Clone)]
struct ProcessRow {
    pid: u32,
    start_time: u64,
    name: String,
    exe: Option<String>,
    cmd: Vec<String>,
    systemd_unit: Option<String>,
    ambiguity: Vec<String>,
}

type CandidateGroup = (
    Option<WorkloadSelector>,
    WorkloadAdapter,
    Vec<RuntimeBinding>,
    Vec<String>,
);

struct ProposalSpec {
    id: String,
    kind: ProposalKind,
    reason: String,
    expected_signals: Vec<String>,
    cost: ProposalCost,
    effects: ProposalEffects,
    related_candidate_ids: Vec<String>,
}

/// Evidence from a bounded local access check. It never contains configuration content or
/// credentials, and it does not imply that metric collection is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverInspection {
    pub mode: WorkloadDriverMode,
    pub evidence: Vec<String>,
    pub pending_checks: Vec<String>,
}

pub fn discover() -> Result<DiscoveryReport> {
    let mut system = System::new();
    let refresh = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);

    let mut rows = system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let pid = pid.as_u32();
            let exe = process.exe().map(|p| p.to_string_lossy().to_string());
            let mut ambiguity = Vec::new();
            if exe.is_none() {
                ambiguity.push("executable_unavailable".to_string());
            }
            let mut cmd = process
                .cmd()
                .iter()
                .take(MAX_COMMAND_TOKENS)
                .map(|v| truncate(&v.to_string_lossy(), MAX_TOKEN_BYTES))
                .collect::<Vec<_>>();
            if process.cmd().len() > MAX_COMMAND_TOKENS {
                ambiguity.push("command_truncated".to_string());
            }
            if cmd.is_empty() {
                cmd.push(process.name().to_string_lossy().to_string());
            }
            let systemd_unit = read_systemd_unit(pid, &mut ambiguity);
            ProcessRow {
                pid,
                start_time: process.start_time(),
                name: process.name().to_string_lossy().to_string(),
                exe,
                cmd,
                systemd_unit,
                ambiguity,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.exe
            .cmp(&b.exe)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    rows.truncate(MAX_PROCESSES);
    let mut report = discover_rows(rows);
    for candidate in &mut report.candidates {
        if candidate.driver_mode.is_some() {
            candidate.driver_mode = Some(inspect_driver(candidate).mode);
        }
    }
    Ok(report)
}

fn discover_rows(rows: Vec<ProcessRow>) -> DiscoveryReport {
    let mut groups: BTreeMap<String, CandidateGroup> = BTreeMap::new();
    for row in rows {
        let (selector, adapter, mut ambiguity) = classify(&row);
        ambiguity.extend(row.ambiguity);
        ambiguity.sort();
        ambiguity.dedup();
        let key = selector
            .as_ref()
            .map(WorkloadSelector::stable_id)
            .unwrap_or_else(|| format!("generic:{}:{}", row.name, row.pid));
        let entry = groups
            .entry(key)
            .or_insert_with(|| (selector.clone(), adapter, Vec::new(), ambiguity.clone()));
        entry.2.push(RuntimeBinding {
            pid: row.pid,
            start_time: row.start_time,
        });
        entry.3.extend(ambiguity);
        entry.3.sort();
        entry.3.dedup();
    }

    let mut candidates = groups
        .into_values()
        .map(|(selector, adapter, mut bindings, ambiguity)| {
            bindings.sort_by_key(|binding| (binding.pid, binding.start_time));
            let id = selector
                .as_ref()
                .map(WorkloadSelector::stable_id)
                .unwrap_or_else(|| format!("generic:{}", bindings[0].pid));
            let fingerprint = fingerprint(&id, &bindings);
            WorkloadCandidate {
                id,
                fingerprint,
                selector,
                adapter,
                driver_mode: driver_mode(adapter),
                bindings,
                ambiguity,
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        adapter_priority(a.adapter)
            .cmp(&adapter_priority(b.adapter))
            .then_with(|| {
                a.ambiguity
                    .is_empty()
                    .cmp(&b.ambiguity.is_empty())
                    .reverse()
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.truncate(MAX_CANDIDATES);
    DiscoveryReport {
        schema_version: WORKLOAD_SCHEMA_VERSION,
        evidence_coverage:
            "process_name, executable, bounded_command, pid, start_time, linux_cgroup".to_string(),
        candidates,
    }
}

fn driver_mode(adapter: WorkloadAdapter) -> Option<WorkloadDriverMode> {
    match adapter {
        WorkloadAdapter::Generic => None,
        _ => Some(WorkloadDriverMode::DetectOnly),
    }
}

/// Perform the small read-only local check that is available for this adapter.
///
/// This function intentionally supports only endpoints with a fixed local default. It never
/// reads configuration contents, accepts remote endpoints, or attempts authentication.
pub fn inspect_driver(candidate: &WorkloadCandidate) -> DriverInspection {
    let evidence = match candidate.adapter {
        WorkloadAdapter::Nginx => probe_nginx_config(),
        WorkloadAdapter::Redis => probe_redis(),
        WorkloadAdapter::PostgreSql => probe_postgres(),
        _ => None,
    };
    let mode = if evidence.is_some() {
        WorkloadDriverMode::InspectReady
    } else {
        WorkloadDriverMode::DetectOnly
    };
    DriverInspection {
        mode,
        evidence: evidence.into_iter().collect(),
        pending_checks: if mode == WorkloadDriverMode::InspectReady {
            vec!["monitoring driver implementation".to_string()]
        } else {
            driver_next_checks(candidate.adapter)
                .iter()
                .map(|check| (*check).to_string())
                .collect()
        },
    }
}

fn probe_nginx_config() -> Option<String> {
    NGINX_CONFIG_PATHS.iter().find_map(|path| {
        File::open(path)
            .ok()
            .map(|_| format!("nginx configuration is readable at {path}"))
    })
}

fn probe_redis() -> Option<String> {
    #[cfg(unix)]
    for path in REDIS_SOCKET_PATHS {
        if probe_redis_unix_socket(Path::new(path)).is_ok() {
            return Some(format!("Redis INFO SERVER accepted at local socket {path}"));
        }
    }

    let endpoint = REDIS_LOOPBACK_ENDPOINT
        .parse()
        .expect("valid Redis endpoint");
    probe_redis_tcp(endpoint)
        .ok()
        .map(|_| format!("Redis INFO SERVER accepted at {REDIS_LOOPBACK_ENDPOINT}"))
}

fn probe_postgres() -> Option<String> {
    #[cfg(unix)]
    for path in POSTGRES_SOCKET_PATHS {
        if probe_postgres_unix_socket(Path::new(path)).is_ok() {
            return Some(format!(
                "PostgreSQL accepted a local socket connection at {path}"
            ));
        }
    }

    let endpoint = POSTGRES_LOOPBACK_ENDPOINT
        .parse()
        .expect("valid PostgreSQL endpoint");
    probe_postgres_tcp(endpoint)
        .ok()
        .map(|_| format!("PostgreSQL startup accepted at {POSTGRES_LOOPBACK_ENDPOINT}"))
}

fn probe_postgres_tcp(endpoint: SocketAddr) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&endpoint, DRIVER_CONNECT_TIMEOUT)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    probe_postgres_stream(&mut stream)
}

fn probe_redis_tcp(endpoint: SocketAddr) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&endpoint, DRIVER_CONNECT_TIMEOUT)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    probe_redis_stream(&mut stream)
}

#[cfg(unix)]
fn probe_redis_unix_socket(path: &Path) -> Result<(), String> {
    let mut stream = UnixStream::connect(path).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    probe_redis_stream(&mut stream)
}

fn probe_redis_stream(stream: &mut (impl Read + Write)) -> Result<(), String> {
    stream
        .write_all(b"INFO SERVER\r\n")
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response = [0_u8; DRIVER_RESPONSE_BYTES];
    let read = stream
        .read(&mut response)
        .map_err(|error| error.to_string())?;
    let response = std::str::from_utf8(&response[..read]).map_err(|error| error.to_string())?;
    if response.contains("# Server") {
        Ok(())
    } else {
        Err("Redis INFO SERVER was not accepted".to_string())
    }
}

fn probe_postgres_stream(stream: &mut (impl Read + Write)) -> Result<(), String> {
    // PostgreSQL protocol v3 startup packet with no credentials. An `R` authentication request
    // or an `E` error response proves that the endpoint speaks PostgreSQL without authenticating.
    stream
        .write_all(b"\0\0\0\t\0\x03\0\0\0")
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response = [0_u8; 1];
    stream
        .read_exact(&mut response)
        .map_err(|error| error.to_string())?;
    match response[0] {
        b'R' | b'E' => Ok(()),
        _ => Err("PostgreSQL startup was not accepted".to_string()),
    }
}

#[cfg(unix)]
fn probe_postgres_unix_socket(path: &Path) -> Result<(), String> {
    let mut stream = UnixStream::connect(path).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(|error| error.to_string())?;
    probe_postgres_stream(&mut stream)
}

/// Return the read-only prerequisites that a driver must verify before it can collect service data.
pub fn driver_next_checks(adapter: WorkloadAdapter) -> &'static [&'static str] {
    match adapter {
        WorkloadAdapter::Nginx => &["config access", "stub status or logs"],
        WorkloadAdapter::Redis => &["local socket or TCP access", "INFO permission"],
        WorkloadAdapter::PostgreSql => &["local socket or DSN", "pg_isready"],
        WorkloadAdapter::Jvm => &["JMX or process access", "runtime metrics access"],
        WorkloadAdapter::Kafka => &["broker endpoint", "admin API access"],
        WorkloadAdapter::Elasticsearch | WorkloadAdapter::OpenSearch => {
            &["local HTTP endpoint", "cluster API access"]
        }
        WorkloadAdapter::RabbitMq => &["management endpoint", "read-only API access"],
        WorkloadAdapter::MySql => &["local socket or DSN", "read-only status access"],
        WorkloadAdapter::MongoDb => &["local endpoint", "read-only server status access"],
        WorkloadAdapter::HaProxy => &["stats socket or endpoint", "read-only stats access"],
        WorkloadAdapter::Prometheus => &["local HTTP endpoint", "read-only query access"],
        WorkloadAdapter::ClickHouse => &["local endpoint", "read-only system query access"],
        WorkloadAdapter::Etcd => &["local endpoint", "read-only status access"],
        WorkloadAdapter::Consul => &["local endpoint", "read-only API access"],
        WorkloadAdapter::Memcached => &["local socket", "stats command access"],
        WorkloadAdapter::Generic => &[],
    }
}

fn adapter_priority(adapter: WorkloadAdapter) -> u8 {
    match adapter {
        WorkloadAdapter::Nginx => 0,
        WorkloadAdapter::Jvm => 1,
        WorkloadAdapter::Redis
        | WorkloadAdapter::PostgreSql
        | WorkloadAdapter::MySql
        | WorkloadAdapter::MongoDb
        | WorkloadAdapter::Kafka
        | WorkloadAdapter::Elasticsearch
        | WorkloadAdapter::OpenSearch
        | WorkloadAdapter::RabbitMq
        | WorkloadAdapter::HaProxy
        | WorkloadAdapter::Prometheus
        | WorkloadAdapter::ClickHouse
        | WorkloadAdapter::Etcd
        | WorkloadAdapter::Consul
        | WorkloadAdapter::Memcached => 2,
        WorkloadAdapter::Generic => 3,
    }
}

fn classify(row: &ProcessRow) -> (Option<WorkloadSelector>, WorkloadAdapter, Vec<String>) {
    let mut ambiguity = Vec::new();
    let Some(exe) = &row.exe else {
        return (None, WorkloadAdapter::Generic, ambiguity);
    };
    let executable = exe.rsplit('/').next().unwrap_or(exe);
    let service_selector = || {
        row.systemd_unit
            .clone()
            .map(|unit| WorkloadSelector::SystemdUnit { unit })
            .or_else(|| Some(WorkloadSelector::Executable { path: exe.clone() }))
    };
    let named_service = |names: &[&str], adapter| {
        names
            .iter()
            .any(|name| row.name == *name || executable == *name)
            .then(|| (service_selector(), adapter, ambiguity.clone()))
    };
    if let Some(result) = named_service(&["nginx"], WorkloadAdapter::Nginx) {
        return result;
    }
    if let Some(result) = named_service(&["redis-server", "valkey-server"], WorkloadAdapter::Redis)
    {
        return result;
    }
    if let Some(result) = named_service(&["postgres", "postmaster"], WorkloadAdapter::PostgreSql) {
        return result;
    }
    if let Some(result) = named_service(&["mysqld", "mariadbd"], WorkloadAdapter::MySql) {
        return result;
    }
    if let Some(result) = named_service(&["mongod"], WorkloadAdapter::MongoDb) {
        return result;
    }
    if let Some(result) = named_service(&["rabbitmq-server"], WorkloadAdapter::RabbitMq) {
        return result;
    }
    if let Some(result) = named_service(&["haproxy"], WorkloadAdapter::HaProxy) {
        return result;
    }
    if let Some(result) = named_service(&["prometheus"], WorkloadAdapter::Prometheus) {
        return result;
    }
    if let Some(result) = named_service(&["clickhouse-server"], WorkloadAdapter::ClickHouse) {
        return result;
    }
    if let Some(result) = named_service(&["etcd"], WorkloadAdapter::Etcd) {
        return result;
    }
    if let Some(result) = named_service(&["consul"], WorkloadAdapter::Consul) {
        return result;
    }
    if let Some(result) = named_service(&["memcached"], WorkloadAdapter::Memcached) {
        return result;
    }
    if row.name == "beam.smp" && row.cmd.iter().any(|token| token.contains("rabbitmq")) {
        return (service_selector(), WorkloadAdapter::RabbitMq, ambiguity);
    }
    if row.name == "java" || exe.ends_with("/java") {
        if let Some(main) = row
            .cmd
            .iter()
            .find(|token| !token.starts_with('-') && !token.ends_with("java"))
        {
            let java_adapter = if main.contains("kafka.Kafka") {
                WorkloadAdapter::Kafka
            } else if main.contains("org.elasticsearch") {
                WorkloadAdapter::Elasticsearch
            } else if main.contains("org.opensearch") {
                WorkloadAdapter::OpenSearch
            } else {
                WorkloadAdapter::Jvm
            };
            return (
                Some(WorkloadSelector::JvmMain {
                    executable: exe.clone(),
                    main_class: main.clone(),
                }),
                java_adapter,
                ambiguity,
            );
        }
        ambiguity.push("jvm_main_unavailable".to_string());
        return (None, WorkloadAdapter::Jvm, ambiguity);
    }
    (
        Some(WorkloadSelector::Executable { path: exe.clone() }),
        WorkloadAdapter::Generic,
        ambiguity,
    )
}

fn read_systemd_unit(pid: u32, ambiguity: &mut Vec<String>) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/cgroup");
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => {
                ambiguity.push("cgroup_unavailable".to_string());
                return None;
            }
        };
        let mut text = String::new();
        if file
            .take(MAX_CGROUP_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            ambiguity.push("cgroup_unavailable".to_string());
            return None;
        }
        systemd_unit_from_cgroup(&text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, ambiguity);
        None
    }
}

#[cfg(any(target_os = "linux", test))]
fn systemd_unit_from_cgroup(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let unit = line.rsplit('/').next()?.trim();
        unit.ends_with(".service").then(|| unit.to_string())
    })
}

pub fn inspect(candidate_id: &str) -> Result<(DiscoveryReport, WorkloadCandidate)> {
    let report = discover()?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.id == candidate_id)
        .cloned()
        .context("workload candidate was not found")?;
    Ok((report, candidate))
}

pub fn proposals(report: &DiscoveryReport) -> Vec<WorkloadProposal> {
    let mut proposals = Vec::new();
    for candidate in &report.candidates {
        if candidate.adapter == WorkloadAdapter::Generic {
            continue;
        }
        proposals.push(available_proposal(
            candidate,
            ProposalSpec {
                id: format!("inspect:{}", candidate.id),
                kind: ProposalKind::Inspect,
                reason: "Inspect the discovered workload before configuration.".into(),
                expected_signals: strings(vec!["selector", "bindings", "ambiguity"]),
                cost: ProposalCost::Low,
                effects: ProposalEffects {
                    persistence: false,
                    privilege: false,
                    outbound: false,
                },
                related_candidate_ids: Vec::new(),
            },
            format!("/workload inspect {}", candidate.id),
        ));
        if candidate.driver_mode == Some(WorkloadDriverMode::DetectOnly) {
            proposals.push(planned_proposal(
                candidate,
                ProposalSpec {
                    id: format!("driver-inspect:{}", candidate.id),
                    kind: ProposalKind::DriverInspect,
                    reason: format!(
                        "Verify read-only access before advancing the {:?} driver.",
                        candidate.adapter
                    ),
                    expected_signals: strings(driver_next_checks(candidate.adapter).to_vec()),
                    cost: ProposalCost::Low,
                    effects: ProposalEffects {
                        persistence: false,
                        privilege: false,
                        outbound: false,
                    },
                    related_candidate_ids: Vec::new(),
                },
            ));
        }
        if candidate.selector.is_some() && candidate.ambiguity.is_empty() {
            proposals.push(available_proposal(
                candidate,
                ProposalSpec {
                    id: format!("enable:{}", candidate.id),
                    kind: ProposalKind::Enable,
                    reason: "Store an explicit workload definition after confirmation.".into(),
                    expected_signals: strings(vec!["stable selector", "configured workload"]),
                    cost: ProposalCost::Low,
                    effects: ProposalEffects {
                        persistence: true,
                        privilege: false,
                        outbound: false,
                    },
                    related_candidate_ids: Vec::new(),
                },
                format!(
                    "/workload enable {} {}",
                    candidate.id, candidate.fingerprint
                ),
            ));
        }
    }
    let nginx = report.candidates.iter().filter(|candidate| {
        candidate.adapter == WorkloadAdapter::Nginx
            && candidate.driver_mode == Some(WorkloadDriverMode::MonitorReady)
            && candidate.selector.is_some()
            && candidate.ambiguity.is_empty()
    });
    let jvms = report
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.adapter == WorkloadAdapter::Jvm
                && candidate.driver_mode == Some(WorkloadDriverMode::MonitorReady)
                && candidate.selector.is_some()
                && candidate.ambiguity.is_empty()
        })
        .collect::<Vec<_>>();
    for nginx_candidate in nginx {
        for jvm_candidate in &jvms {
            if proposals
                .iter()
                .filter(|proposal| proposal.kind == ProposalKind::NginxJvmTopologyCorrelation)
                .count()
                >= MAX_RELATIONSHIP_PROPOSALS
            {
                return proposals;
            }
            proposals.push(planned_proposal(
                nginx_candidate,
                ProposalSpec {
                    id: format!(
                        "nginx-jvm-topology:{}:{}",
                        nginx_candidate.id, jvm_candidate.id
                    ),
                    kind: ProposalKind::NginxJvmTopologyCorrelation,
                    reason: "Correlate nginx ingress with the JVM service topology.".into(),
                    expected_signals: strings(vec![
                        "upstream relationship",
                        "request failures",
                        "latency correlation",
                    ]),
                    cost: ProposalCost::Medium,
                    effects: ProposalEffects {
                        persistence: true,
                        privilege: false,
                        outbound: false,
                    },
                    related_candidate_ids: vec![jvm_candidate.id.clone()],
                },
            ));
        }
    }
    proposals
}

fn available_proposal(
    candidate: &WorkloadCandidate,
    spec: ProposalSpec,
    command: String,
) -> WorkloadProposal {
    WorkloadProposal {
        id: spec.id,
        kind: spec.kind,
        candidate_id: candidate.id.clone(),
        evidence: evidence(candidate),
        reason: spec.reason,
        expected_signals: spec.expected_signals,
        cost: spec.cost,
        effects: spec.effects,
        readiness: ProposalReadiness::Available,
        command: Some(command),
        related_candidate_ids: spec.related_candidate_ids,
    }
}

fn planned_proposal(candidate: &WorkloadCandidate, spec: ProposalSpec) -> WorkloadProposal {
    WorkloadProposal {
        id: spec.id,
        kind: spec.kind,
        candidate_id: candidate.id.clone(),
        evidence: evidence(candidate),
        reason: spec.reason,
        expected_signals: spec.expected_signals,
        cost: spec.cost,
        effects: spec.effects,
        readiness: ProposalReadiness::Planned,
        command: None,
        related_candidate_ids: spec.related_candidate_ids,
    }
}

fn evidence(candidate: &WorkloadCandidate) -> Vec<String> {
    let mut evidence = vec![
        format!("adapter={:?}", candidate.adapter),
        format!("bindings={}", candidate.bindings.len()),
    ];
    if !candidate.ambiguity.is_empty() {
        evidence.push(format!("ambiguity={}", candidate.ambiguity.join(",")));
    }
    evidence
}

fn strings(values: Vec<&str>) -> Vec<String> {
    values.into_iter().map(str::to_string).collect()
}

pub fn list_configured() -> Result<Vec<WorkloadDefinition>> {
    let path = workloads_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let store: WorkloadStore = toml::from_str(&content).context("parse workloads.toml")?;
    Ok(store.workloads)
}

pub fn enable(candidate_id: &str, expected_fingerprint: &str) -> Result<WorkloadDefinition> {
    let (_, candidate) = inspect(candidate_id)?;
    if candidate.fingerprint != expected_fingerprint {
        bail!("workload candidate changed; discover again before enabling");
    }
    if !candidate.ambiguity.is_empty() || candidate.selector.is_none() {
        bail!("ambiguous workload candidates cannot be enabled");
    }
    let definition = WorkloadDefinition {
        id: candidate.id,
        selector: candidate.selector.unwrap(),
        adapter: candidate.adapter,
        driver_mode: candidate.driver_mode.unwrap_or_default(),
    };
    save_definition(&definition)?;
    Ok(definition)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Explanation {
    proposal_id: String,
    priority: usize,
    summary: String,
}

pub fn validate_llm_explanations(
    raw: &str,
    proposals: &[WorkloadProposal],
) -> Result<Vec<(String, String)>> {
    let explanations = parse_llm_explanations(raw)?;
    let valid = proposals
        .iter()
        .map(|proposal| proposal.id.as_str())
        .collect::<BTreeSet<_>>();
    if explanations.len() != proposals.len() {
        bail!("workload analysis must cover every proposal");
    }
    let mut result = BTreeMap::new();
    let mut priorities = BTreeSet::new();
    for explanation in &explanations {
        if !valid.contains(explanation.proposal_id.as_str()) {
            bail!("unknown workload proposal id");
        }
        if explanation.summary.is_empty() || explanation.summary.len() > MAX_SUMMARY_BYTES {
            bail!("workload explanation is too large");
        }
        priorities.insert(explanation.priority);
        if result
            .insert(
                explanation.proposal_id.clone(),
                crate::redaction::redact(&explanation.summary).0,
            )
            .is_some()
        {
            bail!("duplicate workload proposal explanation");
        }
    }
    if priorities.len() != proposals.len() || priorities.iter().copied().ne(1..=proposals.len()) {
        bail!("workload analysis priorities must be contiguous");
    }
    let mut ordered = explanations
        .into_iter()
        .map(|explanation| (explanation.priority, explanation.proposal_id))
        .collect::<Vec<_>>();
    ordered.sort_by_key(|(priority, _)| *priority);
    Ok(ordered
        .into_iter()
        .map(|(_, id)| {
            (
                id.clone(),
                result.remove(&id).expect("validated proposal id"),
            )
        })
        .collect())
}

fn parse_llm_explanations(raw: &str) -> Result<Vec<Explanation>> {
    if let Ok(explanations) = serde_json::from_str(raw) {
        return Ok(explanations);
    }

    for (start, _) in raw.match_indices('[') {
        let mut values =
            serde_json::Deserializer::from_str(&raw[start..]).into_iter::<Vec<Explanation>>();
        if let Some(Ok(explanations)) = values.next() {
            return Ok(explanations);
        }
    }

    bail!("invalid workload explanation JSON")
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct WorkloadStore {
    #[serde(default)]
    workloads: Vec<WorkloadDefinition>,
}

fn workloads_path() -> PathBuf {
    ConfigManager::config_path().with_file_name("workloads.toml")
}

fn save_definition(definition: &WorkloadDefinition) -> Result<()> {
    let path = workloads_path();
    let parent = path.parent().context("workloads path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let lock_path = path.with_extension("toml.lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    flock(&lock, libc::LOCK_EX)?;
    let mut store = if path.exists() {
        toml::from_str(&fs::read_to_string(&path)?).context("parse workloads.toml")?
    } else {
        WorkloadStore::default()
    };
    if !store
        .workloads
        .iter()
        .any(|existing| existing.id == definition.id)
    {
        store.workloads.push(definition.clone());
    }
    store.workloads.sort_by(|a, b| a.id.cmp(&b.id));
    let text = toml::to_string_pretty(&store).context("serialize workloads.toml")?;
    let temporary = path.with_extension("toml.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    let directory = File::open(parent)?;
    directory.sync_all()?;
    flock(&lock, libc::LOCK_UN)?;
    Ok(())
}

fn flock(file: &File, operation: i32) -> Result<()> {
    #[cfg(unix)]
    unsafe {
        if libc::flock(std::os::fd::AsRawFd::as_raw_fd(file), operation) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn fingerprint(id: &str, bindings: &[RuntimeBinding]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    for binding in bindings {
        hasher.update(binding.pid.to_le_bytes());
        hasher.update(binding.start_time.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        let mut end = max;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        value[..end].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, start_time: u64, name: &str, exe: Option<&str>, cmd: &[&str]) -> ProcessRow {
        ProcessRow {
            pid,
            start_time,
            name: name.into(),
            exe: exe.map(str::to_string),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            systemd_unit: None,
            ambiguity: Vec::new(),
        }
    }

    #[test]
    fn discovery_is_order_invariant_and_pid_reuse_changes_fingerprint() {
        let first = discover_rows(vec![
            row(2, 1, "nginx", Some("/usr/sbin/nginx"), &[]),
            row(1, 1, "nginx", Some("/usr/sbin/nginx"), &[]),
        ]);
        let reversed = discover_rows(vec![
            row(1, 1, "nginx", Some("/usr/sbin/nginx"), &[]),
            row(2, 1, "nginx", Some("/usr/sbin/nginx"), &[]),
        ]);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&reversed).unwrap()
        );
        let reused = discover_rows(vec![row(1, 2, "nginx", Some("/usr/sbin/nginx"), &[])]);
        assert_eq!(first.candidates[0].id, reused.candidates[0].id);
        assert_ne!(
            first.candidates[0].fingerprint,
            reused.candidates[0].fingerprint
        );
    }

    #[test]
    fn discovery_prioritizes_supported_adapters_before_generic_processes() {
        let report = discover_rows(vec![
            row(1, 1, "helper", Some("/usr/bin/helper"), &[]),
            row(2, 1, "java", Some("/usr/bin/java"), &["example.Main"]),
            row(3, 1, "nginx", Some("/usr/sbin/nginx"), &[]),
        ]);
        assert_eq!(report.candidates[0].adapter, WorkloadAdapter::Nginx);
        assert_eq!(report.candidates[1].adapter, WorkloadAdapter::Jvm);
        assert_eq!(report.candidates[2].adapter, WorkloadAdapter::Generic);
    }

    #[test]
    fn discovery_classifies_major_service_processes() {
        let report = discover_rows(vec![
            row(1, 1, "redis-server", Some("/usr/bin/redis-server"), &[]),
            row(2, 1, "postgres", Some("/usr/lib/postgresql/postgres"), &[]),
            row(3, 1, "mysqld", Some("/usr/sbin/mysqld"), &[]),
            row(4, 1, "mongod", Some("/usr/bin/mongod"), &[]),
            row(5, 1, "haproxy", Some("/usr/sbin/haproxy"), &[]),
            row(6, 1, "prometheus", Some("/usr/local/bin/prometheus"), &[]),
            row(
                7,
                1,
                "clickhouse-server",
                Some("/usr/bin/clickhouse-server"),
                &[],
            ),
            row(8, 1, "etcd", Some("/usr/local/bin/etcd"), &[]),
            row(9, 1, "consul", Some("/usr/bin/consul"), &[]),
            row(10, 1, "memcached", Some("/usr/bin/memcached"), &[]),
        ]);
        let adapters = report
            .candidates
            .iter()
            .map(|candidate| candidate.adapter)
            .collect::<Vec<_>>();
        for adapter in [
            WorkloadAdapter::Redis,
            WorkloadAdapter::PostgreSql,
            WorkloadAdapter::MySql,
            WorkloadAdapter::MongoDb,
            WorkloadAdapter::HaProxy,
            WorkloadAdapter::Prometheus,
            WorkloadAdapter::ClickHouse,
            WorkloadAdapter::Etcd,
            WorkloadAdapter::Consul,
            WorkloadAdapter::Memcached,
        ] {
            assert!(adapters.contains(&adapter), "missing {adapter:?}");
        }
    }

    #[test]
    fn discovery_classifies_java_service_main_classes() {
        let report = discover_rows(vec![
            row(1, 1, "java", Some("/usr/bin/java"), &["kafka.Kafka"]),
            row(
                2,
                1,
                "java",
                Some("/usr/bin/java"),
                &["org.elasticsearch.bootstrap.Elasticsearch"],
            ),
            row(
                3,
                1,
                "java",
                Some("/usr/bin/java"),
                &["org.opensearch.bootstrap.OpenSearch"],
            ),
        ]);
        assert!(report
            .candidates
            .iter()
            .any(|candidate| candidate.adapter == WorkloadAdapter::Kafka));
        assert!(report
            .candidates
            .iter()
            .any(|candidate| candidate.adapter == WorkloadAdapter::Elasticsearch));
        assert!(report
            .candidates
            .iter()
            .any(|candidate| candidate.adapter == WorkloadAdapter::OpenSearch));
    }

    #[test]
    fn ambiguous_candidates_have_no_enable_proposal() {
        let report = discover_rows(vec![row(1, 1, "java", Some("/usr/bin/java"), &["-Xmx1g"])]);
        assert!(proposals(&report)
            .iter()
            .all(|proposal| proposal.kind != ProposalKind::Enable));
    }

    #[test]
    fn generic_candidates_have_no_discovery_proposals() {
        let report = discover_rows(vec![row(1, 1, "helper", Some("/usr/bin/helper"), &[])]);
        assert!(proposals(&report).is_empty());
    }

    #[test]
    fn command_token_truncation_preserves_utf8_boundaries() {
        let token = "가".repeat(MAX_TOKEN_BYTES);
        let truncated = truncate(&token, MAX_TOKEN_BYTES);
        assert!(truncated.len() <= MAX_TOKEN_BYTES);
        assert!(truncated.is_char_boundary(truncated.len()));
        assert!(token.starts_with(&truncated));
    }

    #[test]
    fn systemd_unit_parser_handles_cgroup_line_endings() {
        assert_eq!(
            systemd_unit_from_cgroup("0::/system.slice/nginx.service\n"),
            Some("nginx.service".to_string())
        );
        assert_eq!(
            systemd_unit_from_cgroup(
                "11:memory:/system.slice/orders.service\n0::/user.slice/user-1000.slice\n"
            ),
            Some("orders.service".to_string())
        );
        assert_eq!(
            systemd_unit_from_cgroup("0::/user.slice/user-1000.slice\n"),
            None
        );
    }

    #[test]
    fn explanation_validation_is_strict_and_redacts_summaries() {
        let report = discover_rows(vec![row(1, 1, "nginx", Some("/usr/sbin/nginx"), &[])]);
        let proposals = proposals(&report);
        let proposal_id = &proposals[0].id;
        let valid = serde_json::to_string(
            &proposals
                .iter()
                .enumerate()
                .map(|(index, proposal)| {
                    serde_json::json!({
                        "proposal_id": proposal.id,
                        "priority": index + 1,
                        "summary": "token=secret-value",
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(validate_llm_explanations(&valid, &proposals).is_ok());
        assert!(validate_llm_explanations(
            &format!("Analysis follows.\n{valid}\nEnd of analysis."),
            &proposals
        )
        .is_ok());
        assert!(validate_llm_explanations(&format!("```json\n{valid}\n```"), &proposals).is_ok());
        assert!(validate_llm_explanations("analysis without JSON", &proposals).is_err());
        assert!(validate_llm_explanations(
            r#"[{"proposal_id":"unknown","priority":1,"summary":"x"}]"#,
            &proposals
        )
        .is_err());
        assert!(validate_llm_explanations(
            &format!(
                r#"[{{"proposal_id":"{proposal_id}","priority":1,"summary":"x","command":"rm"}}]"#
            ),
            &proposals
        )
        .is_err());
    }

    #[test]
    fn detect_only_drivers_propose_access_checks_not_monitoring() {
        let report = discover_rows(vec![
            row(1, 1, "nginx", Some("/usr/sbin/nginx"), &[]),
            row(2, 1, "java", Some("/usr/bin/java"), &["example.Main"]),
        ]);
        let proposals = proposals(&report);
        assert_eq!(
            report.candidates[0].driver_mode,
            Some(WorkloadDriverMode::DetectOnly)
        );
        assert!(proposals
            .iter()
            .filter(|proposal| proposal.kind == ProposalKind::DriverInspect)
            .all(|proposal| proposal.readiness == ProposalReadiness::Planned));
        assert!(proposals.iter().all(|proposal| {
            !matches!(
                proposal.kind,
                ProposalKind::NginxAdapterMonitoring
                    | ProposalKind::JvmAdapterMonitoring
                    | ProposalKind::ServiceAdapterMonitoring
                    | ProposalKind::NginxJvmTopologyCorrelation
            )
        }));
        for proposal in &proposals {
            let executable = matches!(proposal.kind, ProposalKind::Inspect | ProposalKind::Enable);
            assert_eq!(
                proposal.readiness == ProposalReadiness::Available,
                executable
            );
            assert_eq!(proposal.command.is_some(), executable);
            assert!(!proposal.evidence.is_empty());
            assert!(!proposal.expected_signals.is_empty());
        }
    }

    #[test]
    fn redis_driver_declares_read_only_prerequisites() {
        assert_eq!(
            driver_next_checks(WorkloadAdapter::Redis),
            ["local socket or TCP access", "INFO permission"]
        );
    }

    #[test]
    fn unsupported_driver_stays_detect_only() {
        let candidate = WorkloadCandidate {
            id: "exe:/usr/bin/java".into(),
            fingerprint: "test".into(),
            selector: Some(WorkloadSelector::Executable {
                path: "/usr/bin/java".into(),
            }),
            adapter: WorkloadAdapter::Jvm,
            driver_mode: Some(WorkloadDriverMode::DetectOnly),
            bindings: Vec::new(),
            ambiguity: Vec::new(),
        };
        let inspection = inspect_driver(&candidate);
        assert_eq!(inspection.mode, WorkloadDriverMode::DetectOnly);
        assert!(inspection.evidence.is_empty());
        assert_eq!(
            inspection.pending_checks,
            ["JMX or process access", "runtime metrics access"]
        );
    }

    #[test]
    fn inspect_ready_driver_does_not_repeat_its_access_proposal() {
        let report = DiscoveryReport {
            schema_version: WORKLOAD_SCHEMA_VERSION,
            evidence_coverage: "test".into(),
            candidates: vec![WorkloadCandidate {
                id: "exe:/usr/bin/redis-server".into(),
                fingerprint: "test".into(),
                selector: Some(WorkloadSelector::Executable {
                    path: "/usr/bin/redis-server".into(),
                }),
                adapter: WorkloadAdapter::Redis,
                driver_mode: Some(WorkloadDriverMode::InspectReady),
                bindings: Vec::new(),
                ambiguity: Vec::new(),
            }],
        };
        assert!(proposals(&report)
            .iter()
            .all(|proposal| proposal.kind != ProposalKind::DriverInspect));
    }

    #[cfg(unix)]
    #[test]
    fn redis_probe_accepts_only_the_info_server_response() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let (mut peer, mut client) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut request = [0_u8; 13];
            peer.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"INFO SERVER\r\n");
            peer.write_all(b"$10\r\n# Server\r\n").unwrap();
        });
        assert!(probe_redis_stream(&mut client).is_ok());
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn postgres_probe_uses_an_unauthenticated_startup_packet() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let (mut peer, mut client) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut request = [0_u8; 9];
            peer.read_exact(&mut request).unwrap();
            assert_eq!(request, [0, 0, 0, 9, 0, 3, 0, 0, 0]);
            peer.write_all(b"R").unwrap();
        });
        assert!(probe_postgres_stream(&mut client).is_ok());
        server.join().unwrap();
    }
}
