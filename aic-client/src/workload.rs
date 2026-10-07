//! Deterministic local workload discovery and explicit definition storage.

use aic_common::workload::{
    adapter_definitions_conflict, load_workload_history, monitor_clickhouse_with_connection,
    monitor_elasticsearch_with_connection, monitor_etcd_with_connection,
    monitor_haproxy_with_connection, monitor_memcached_with_connection,
    monitor_mongodb_with_connection, monitor_mysql_with_connection, monitor_nginx_with_connection,
    monitor_opensearch_with_connection, monitor_postgresql_with_connection,
    monitor_prometheus_with_connection, monitor_rabbitmq_with_connection,
    monitor_redis_with_connection, workload_history_path, workloads_file_path,
    ClickHouseMonitorReport, ElasticsearchMonitorReport, EtcdMonitorReport, HaProxyMonitorReport,
    MemcachedMonitorReport, MongoDbMonitorReport, MySqlMonitorReport, NginxMonitorReport,
    OpenSearchMonitorReport, PostgreSqlMonitorReport, PrometheusMonitorReport, ProposalCost,
    ProposalReadiness, RabbitMqMonitorReport, RedisMonitorReport, WorkloadMonitorReport,
    WorkloadProbeError, WorkloadSample, WorkloadStore, WORKLOAD_SAMPLE_INTERVAL,
};
use aic_common::{
    DiscoveryReport, ProposalEffects, ProposalKind, RuntimeBinding, WorkloadAdapter,
    WorkloadCandidate, WorkloadConnectionConfig, WorkloadContainer, WorkloadDefinition,
    WorkloadDriverMode, WorkloadProposal, WorkloadSelector, WORKLOAD_SCHEMA_VERSION,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
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
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const MAX_PROCESSES: usize = 4096;
const MAX_CANDIDATES: usize = 256;
const MAX_COMMAND_TOKENS: usize = 16;
const MAX_TOKEN_BYTES: usize = 256;
#[cfg(target_os = "linux")]
const MAX_CGROUP_BYTES: u64 = 8 * 1024;
const CONTAINER_ID_MIN_HEX: usize = 12;
const CONTAINER_ID_MAX_HEX: usize = 64;
const CONTAINER_ID_PREFIX: &str = "container";
const CONTAINERIZED_WORKLOAD_AMBIGUITY: &str = "containerized_workload";
const MAX_SUMMARY_BYTES: usize = 512;
const MAX_RELATIONSHIP_PROPOSALS: usize = 32;
const DRIVER_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
const POSTGRES_LOOPBACK_ENDPOINT: &str = "127.0.0.1:5432";
const NGINX_CONFIG_PATHS: &[&str] = &["/etc/nginx/nginx.conf", "/usr/local/etc/nginx/nginx.conf"];
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
    container: Option<ContainerEvidence>,
    /// Docker `config.v2.json`에서 읽은 이름과 이미지. 다른 런타임이거나 읽지 못하면 `None`.
    container_name: Option<String>,
    container_image: Option<String>,
    ambiguity: Vec<String>,
}

type CandidateGroup = (
    String,
    Option<WorkloadSelector>,
    WorkloadAdapter,
    Vec<RuntimeBinding>,
    Vec<String>,
    Option<WorkloadContainer>,
);

#[derive(Debug, Clone, Copy, Default)]
struct NamespaceIds {
    pid: Option<u64>,
    mnt: Option<u64>,
    root: Option<FileIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerRuntime {
    Docker,
    Containerd,
    Podman,
    Lxc,
    PidNamespace,
    RootFs,
    Isolated,
}

impl ContainerRuntime {
    fn label(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Containerd => "containerd",
            Self::Podman => "podman",
            Self::Lxc => "lxc",
            Self::PidNamespace => "pidns",
            Self::RootFs => "rootfs",
            Self::Isolated => "isolated",
        }
    }

    /// 런타임이 붙인 컨테이너 id나 이름이 있어 같은 컨테이너를 다시 찾을 수 있는가. 네임스페이스나
    /// 루트 파일시스템 차이로만 추정한 격리(snap, 샌드박스 등)는 무엇인지 모른다.
    fn identifies_container(self) -> bool {
        matches!(
            self,
            Self::Docker | Self::Containerd | Self::Podman | Self::Lxc
        )
    }
}

#[derive(Debug, Clone)]
struct ContainerEvidence {
    runtime: ContainerRuntime,
    key: String,
}

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
    discover_with_driver_checks(true)
}

fn discover_for_monitor() -> Result<DiscoveryReport> {
    discover_with_driver_checks(false)
}

fn discover_with_driver_checks(check_drivers: bool) -> Result<DiscoveryReport> {
    let mut system = System::new();
    let refresh = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
    let scanner_pid = std::process::id();
    let own_namespaces = read_namespace_ids(scanner_pid);

    let mut rows = system
        .processes()
        .iter()
        .filter(|(pid, _)| pid.as_u32() != scanner_pid)
        // Linux의 `processes()`는 스레드도 돌려준다. 스레드가 binding이 되면 fingerprint가 스레드
        // 생성·종료마다 바뀌고, 스캐너 자신의 워커 스레드까지 후보가 된다. 커널 스레드는 감시할
        // 서비스가 아닌데 실행 파일이 없어 pid마다 후보가 되어 `MAX_CANDIDATES`를 채웠다.
        .filter(|(_, process)| process.thread_kind().is_none())
        .map(|(pid, process)| {
            let pid = pid.as_u32();
            let mut ambiguity = Vec::new();
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
            let exe = process
                .exe()
                .map(|p| without_deleted_suffix(&p.to_string_lossy()).to_string())
                .or_else(|| executable_from_argv0(&cmd));
            if exe.is_none() {
                ambiguity.push("executable_unavailable".to_string());
            }
            let cgroup = read_cgroup_text(pid, &mut ambiguity);
            let systemd_unit = cgroup.as_deref().and_then(systemd_unit_from_cgroup);
            let process_namespaces = read_namespace_ids(pid);
            let container = container_evidence(
                cgroup.as_deref().and_then(container_marker_from_cgroup),
                own_namespaces,
                process_namespaces,
            );
            ProcessRow {
                pid,
                start_time: process.start_time(),
                name: process.name().to_string_lossy().to_string(),
                exe,
                cmd,
                systemd_unit,
                container,
                container_name: None,
                container_image: None,
                ambiguity,
            }
        })
        .collect::<Vec<_>>();
    attach_docker_meta(
        &mut rows,
        Path::new(aic_common::docker::DOCKER_CONTAINERS_DIR),
    );
    rows.sort_by(|a, b| {
        a.exe
            .cmp(&b.exe)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    rows.truncate(MAX_PROCESSES);
    let mut report = discover_rows(rows);
    if check_drivers {
        for candidate in &mut report.candidates {
            if candidate.driver_mode.is_some() && candidate.ambiguity.is_empty() {
                candidate.driver_mode = Some(inspect_driver(candidate).mode);
            }
        }
    }
    Ok(report)
}

fn discover_rows(rows: Vec<ProcessRow>) -> DiscoveryReport {
    let mut groups: BTreeMap<String, CandidateGroup> = BTreeMap::new();
    for row in rows {
        let (selector, adapter, mut ambiguity) = classify(&row);
        ambiguity.extend(row.ambiguity);
        let group_base = selector
            .as_ref()
            .map(WorkloadSelector::stable_id)
            .unwrap_or_else(|| format!("generic:{}:{}", row.name, row.pid));
        let id_base = selector
            .as_ref()
            .map(WorkloadSelector::stable_id)
            .unwrap_or_else(|| format!("generic:{}", row.pid));
        let container = row.container.as_ref().map(|container| WorkloadContainer {
            runtime: container.runtime.label().to_string(),
            id: container.key.clone(),
            name: row.container_name.clone(),
            image: row.container_image.clone(),
        });
        let (key, id) = if let Some(evidence) = &row.container {
            if !evidence.runtime.identifies_container() {
                ambiguity.push(CONTAINERIZED_WORKLOAD_AMBIGUITY.to_string());
            }
            // Compose는 컨테이너를 다시 만들 때 id를 바꾸고 이름은 유지한다.
            let label = row.container_name.as_deref().unwrap_or(&evidence.key);
            let prefix = format!(
                "{CONTAINER_ID_PREFIX}:{}:{label}:",
                evidence.runtime.label(),
            );
            (
                format!("{prefix}{group_base}"),
                format!("{prefix}{id_base}"),
            )
        } else {
            (group_base, id_base)
        };
        ambiguity.sort();
        ambiguity.dedup();
        let entry = groups.entry(key).or_insert_with(|| {
            (
                id,
                selector.clone(),
                adapter,
                Vec::new(),
                ambiguity.clone(),
                container,
            )
        });
        entry.3.push(RuntimeBinding {
            pid: row.pid,
            start_time: row.start_time,
        });
        entry.4.extend(ambiguity);
        entry.4.sort();
        entry.4.dedup();
    }

    let mut candidates = groups
        .into_values()
        .map(
            |(id, selector, adapter, mut bindings, ambiguity, container)| {
                bindings.sort_by_key(|binding| (binding.pid, binding.start_time));
                let fingerprint = fingerprint(&id, &bindings);
                WorkloadCandidate {
                    id,
                    fingerprint,
                    selector,
                    adapter,
                    driver_mode: driver_mode(adapter),
                    bindings,
                    ambiguity,
                    container,
                }
            },
        )
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
            .then_with(|| a.container.is_some().cmp(&b.container.is_some()))
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.truncate(MAX_CANDIDATES);
    DiscoveryReport {
        schema_version: WORKLOAD_SCHEMA_VERSION,
        evidence_coverage:
            "process_name, executable, cmdline_argv0, bounded_command, pid, start_time, linux_cgroup, linux_container_cgroup, linux_pid_namespace, linux_mount_namespace".to_string(),
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
        WorkloadAdapter::Memcached => probe_memcached(),
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
    aic_common::workload::probe_redis_server()
        .ok()
        .map(|_| "Redis INFO SERVER accepted at fixed local endpoint".to_string())
}

fn probe_memcached() -> Option<String> {
    aic_common::workload::probe_memcached_server()
        .ok()
        .map(|_| "Memcached stats accepted at fixed local endpoint".to_string())
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

pub fn monitor_candidate(candidate_id: &str) -> Result<WorkloadMonitorReport> {
    let report = discover_for_monitor()?;
    let configured = list_configured()?;
    let candidate_id = &resolve_workload_ref(
        candidate_id,
        report
            .candidates
            .iter()
            .map(|candidate| candidate.id.as_str()),
    )?;
    let connection = configured
        .into_iter()
        .find(|definition| definition.id == *candidate_id)
        .and_then(|definition| definition.connection);
    let candidate = select_monitor_candidate(&report, candidate_id, connection.is_some())?;
    probe_with_connection(candidate, connection.as_ref())
}

/// 후보 하나를 주어진 연결로 한 번 점검한다. 연결이 없으면 어댑터의 고정 기본 주소를 쓴다.
pub fn probe_with_connection(
    candidate: &WorkloadCandidate,
    connection: Option<&WorkloadConnectionConfig>,
) -> Result<WorkloadMonitorReport> {
    let report = match candidate.adapter {
        WorkloadAdapter::HaProxy => {
            let connection = connection.ok_or_else(|| {
                anyhow::anyhow!("HAProxy monitor requires an explicit connection")
            })?;
            WorkloadMonitorReport::HaProxy(HaProxyMonitorReport {
                candidate_id: candidate.id.clone(),
                adapter: WorkloadAdapter::HaProxy,
                monitor_ready: true,
                metrics: monitor_haproxy_with_connection(connection)
                    .map(|(_, metrics)| metrics)
                    .map_err(|error| safe_monitor_error(WorkloadAdapter::HaProxy, error))?,
            })
        }
        WorkloadAdapter::Nginx => {
            let connection = connection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Nginx monitor requires an explicit connection"))?;
            WorkloadMonitorReport::Nginx(NginxMonitorReport {
                candidate_id: candidate.id.clone(),
                adapter: WorkloadAdapter::Nginx,
                monitor_ready: true,
                metrics: monitor_nginx_with_connection(connection)
                    .map(|(_, metrics)| metrics)
                    .map_err(|error| safe_monitor_error(WorkloadAdapter::Nginx, error))?,
            })
        }
        WorkloadAdapter::Redis => WorkloadMonitorReport::Redis(RedisMonitorReport {
            candidate_id: candidate.id.clone(),
            monitor_ready: true,
            metrics: monitor_redis_with_connection(connection)
                .map(|(_, metrics)| metrics)
                .map_err(|error| safe_monitor_error(WorkloadAdapter::Redis, error))?,
        }),
        WorkloadAdapter::Memcached => WorkloadMonitorReport::Memcached(MemcachedMonitorReport {
            candidate_id: candidate.id.clone(),
            adapter: WorkloadAdapter::Memcached,
            monitor_ready: true,
            metrics: monitor_memcached_with_connection(connection)
                .map(|(_, metrics)| metrics)
                .map_err(|error| safe_monitor_error(WorkloadAdapter::Memcached, error))?,
        }),
        WorkloadAdapter::PostgreSql => {
            let connection = connection.ok_or_else(|| {
                anyhow::anyhow!("PostgreSQL monitor requires an explicit connection")
            })?;
            WorkloadMonitorReport::PostgreSql(PostgreSqlMonitorReport {
                candidate_id: candidate.id.clone(),
                adapter: WorkloadAdapter::PostgreSql,
                monitor_ready: true,
                metrics: monitor_postgresql_with_connection(connection)
                    .map(|(_, metrics)| metrics)
                    .map_err(|error| safe_monitor_error(WorkloadAdapter::PostgreSql, error))?,
            })
        }
        WorkloadAdapter::MySql => {
            let connection = connection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("MySQL monitor requires an explicit connection"))?;
            WorkloadMonitorReport::MySql(MySqlMonitorReport {
                candidate_id: candidate.id.clone(),
                adapter: WorkloadAdapter::MySql,
                monitor_ready: true,
                metrics: monitor_mysql_with_connection(connection)
                    .map(|(_, metrics)| metrics)
                    .map_err(|error| safe_monitor_error(WorkloadAdapter::MySql, error))?,
            })
        }
        WorkloadAdapter::MongoDb => {
            let connection = connection.ok_or_else(|| {
                anyhow::anyhow!("MongoDB monitor requires an explicit connection")
            })?;
            WorkloadMonitorReport::MongoDb(MongoDbMonitorReport {
                candidate_id: candidate.id.clone(),
                adapter: WorkloadAdapter::MongoDb,
                monitor_ready: true,
                metrics: monitor_mongodb_with_connection(connection)
                    .map(|(_, metrics)| metrics)
                    .map_err(|error| safe_monitor_error(WorkloadAdapter::MongoDb, error))?,
            })
        }
        WorkloadAdapter::Prometheus => WorkloadMonitorReport::Prometheus(PrometheusMonitorReport {
            candidate_id: candidate.id.clone(),
            adapter: WorkloadAdapter::Prometheus,
            monitor_ready: true,
            metrics: monitor_prometheus_with_connection(connection)
                .map(|(_, metrics)| metrics)
                .map_err(|error| safe_monitor_error(WorkloadAdapter::Prometheus, error))?,
        }),
        WorkloadAdapter::ClickHouse => WorkloadMonitorReport::ClickHouse(ClickHouseMonitorReport {
            candidate_id: candidate.id.clone(),
            adapter: WorkloadAdapter::ClickHouse,
            monitor_ready: true,
            metrics: monitor_clickhouse_with_connection(connection)
                .map(|(_, metrics)| metrics)
                .map_err(|error| safe_monitor_error(WorkloadAdapter::ClickHouse, error))?,
        }),
        WorkloadAdapter::Etcd => WorkloadMonitorReport::Etcd(EtcdMonitorReport {
            candidate_id: candidate.id.clone(),
            adapter: WorkloadAdapter::Etcd,
            monitor_ready: true,
            metrics: monitor_etcd_with_connection(connection)
                .map(|(_, metrics)| metrics)
                .map_err(|error| safe_monitor_error(WorkloadAdapter::Etcd, error))?,
        }),
        WorkloadAdapter::Elasticsearch => {
            WorkloadMonitorReport::Elasticsearch(ElasticsearchMonitorReport {
                candidate_id: candidate.id.clone(),
                adapter: WorkloadAdapter::Elasticsearch,
                monitor_ready: true,
                metrics: monitor_elasticsearch_with_connection(connection)
                    .map(|(_, metrics)| metrics)
                    .map_err(|error| safe_monitor_error(WorkloadAdapter::Elasticsearch, error))?,
            })
        }
        WorkloadAdapter::OpenSearch => WorkloadMonitorReport::OpenSearch(OpenSearchMonitorReport {
            candidate_id: candidate.id.clone(),
            adapter: WorkloadAdapter::OpenSearch,
            monitor_ready: true,
            metrics: monitor_opensearch_with_connection(connection)
                .map(|(_, metrics)| metrics)
                .map_err(|error| safe_monitor_error(WorkloadAdapter::OpenSearch, error))?,
        }),
        WorkloadAdapter::RabbitMq => WorkloadMonitorReport::RabbitMq(RabbitMqMonitorReport {
            candidate_id: candidate.id.clone(),
            adapter: WorkloadAdapter::RabbitMq,
            monitor_ready: true,
            metrics: monitor_rabbitmq_with_connection(connection)
                .map(|(_, metrics)| metrics)
                .map_err(|error| safe_monitor_error(WorkloadAdapter::RabbitMq, error))?,
        }),
        _ => bail!("workload candidate does not support monitoring"),
    };
    Ok(report)
}

fn safe_monitor_error(adapter: WorkloadAdapter, error: WorkloadProbeError) -> anyhow::Error {
    let adapter_name = match adapter {
        WorkloadAdapter::HaProxy => "HAProxy",
        WorkloadAdapter::Nginx => "Nginx",
        WorkloadAdapter::Redis => "Redis",
        WorkloadAdapter::Memcached => "Memcached",
        WorkloadAdapter::PostgreSql => "PostgreSQL",
        WorkloadAdapter::MySql => "MySQL",
        WorkloadAdapter::MongoDb => "MongoDB",
        WorkloadAdapter::Prometheus => "Prometheus",
        WorkloadAdapter::ClickHouse => "ClickHouse",
        WorkloadAdapter::Etcd => "etcd",
        WorkloadAdapter::Elasticsearch => "Elasticsearch",
        WorkloadAdapter::OpenSearch => "OpenSearch",
        WorkloadAdapter::RabbitMq => "RabbitMQ",
        _ => "Workload",
    };
    let detail = match error {
        WorkloadProbeError::Unreachable(_) => "endpoint is unavailable",
        WorkloadProbeError::Rejected(_) => "rejected the monitor request",
        WorkloadProbeError::Malformed(_) => "returned an invalid monitor response",
    };
    anyhow::anyhow!("{adapter_name} monitor probe failed: {detail}")
}

fn select_monitor_candidate<'a>(
    report: &'a DiscoveryReport,
    candidate_id: &str,
    has_saved_connection: bool,
) -> Result<&'a WorkloadCandidate> {
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.id == candidate_id)
        .ok_or_else(|| anyhow::anyhow!("requested workload candidate was not discovered"))?;
    if !is_monitor_adapter(candidate.adapter) {
        bail!("workload candidate does not support monitoring");
    }
    if !candidate.ambiguity.is_empty() {
        bail!("workload monitor candidate is ambiguous");
    }
    // 저장된 연결이 없으면 고정 기본 주소로 조회한다. 같은 어댑터의 후보가 여럿이면 그 주소가
    // 어느 후보의 것인지 알 수 없다.
    if has_saved_connection {
        return Ok(candidate);
    }
    let count = report
        .candidates
        .iter()
        .filter(|other| other.adapter == candidate.adapter)
        .count();
    if count != 1 {
        bail!("workload monitor requires exactly one unambiguous adapter candidate, found {count}");
    }
    Ok(candidate)
}

fn is_monitor_adapter(adapter: WorkloadAdapter) -> bool {
    matches!(
        adapter,
        WorkloadAdapter::Redis
            | WorkloadAdapter::HaProxy
            | WorkloadAdapter::Nginx
            | WorkloadAdapter::Memcached
            | WorkloadAdapter::PostgreSql
            | WorkloadAdapter::MySql
            | WorkloadAdapter::MongoDb
            | WorkloadAdapter::Prometheus
            | WorkloadAdapter::ClickHouse
            | WorkloadAdapter::Etcd
            | WorkloadAdapter::Elasticsearch
            | WorkloadAdapter::OpenSearch
            | WorkloadAdapter::RabbitMq
    )
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

fn read_cgroup_text(pid: u32, ambiguity: &mut Vec<String>) -> Option<String> {
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
        Some(text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, ambiguity);
        None
    }
}

/// 비루트는 다른 사용자 프로세스의 `/proc/<pid>/exe`를 읽지 못한다. argv[0]은 프로세스가
/// 바꿀 수 있으므로, 절대 경로이면서 실재하는 파일일 때만 대체 증거로 받는다.
fn executable_from_argv0(cmd: &[String]) -> Option<String> {
    let argv0 = cmd.first()?;
    let path = std::path::Path::new(argv0);
    (path.is_absolute() && path.is_file()).then(|| argv0.clone())
}

/// 패키지 업그레이드로 실행 파일이 바뀌면 커널은 `/proc/<pid>/exe` 끝에 ` (deleted)`를 붙인다.
/// 그대로 두면 재시작 전후로 같은 서비스의 후보 id가 달라진다.
fn without_deleted_suffix(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

fn systemd_unit_from_cgroup(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let unit = line.rsplit('/').next()?.trim();
        unit.ends_with(".service").then(|| unit.to_string())
    })
}

#[cfg(target_os = "linux")]
fn read_namespace_ids(pid: u32) -> NamespaceIds {
    use std::os::unix::fs::MetadataExt;

    // EACCES is expected for some root-owned processes, so failed reads remain absent evidence.
    NamespaceIds {
        pid: fs::read_link(format!("/proc/{pid}/ns/pid"))
            .ok()
            .and_then(|link| namespace_inode(&link.to_string_lossy())),
        mnt: fs::read_link(format!("/proc/{pid}/ns/mnt"))
            .ok()
            .and_then(|link| namespace_inode(&link.to_string_lossy())),
        root: fs::metadata(format!("/proc/{pid}/root"))
            .ok()
            .map(|metadata| FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }),
    }
}

#[cfg(not(target_os = "linux"))]
fn read_namespace_ids(_pid: u32) -> NamespaceIds {
    NamespaceIds::default()
}

#[cfg(any(target_os = "linux", test))]
fn namespace_inode(link: &str) -> Option<u64> {
    let (_, inode) = link.split_once(":[")?;
    inode.strip_suffix(']')?.parse().ok()
}

fn container_evidence(
    marker: Option<ContainerEvidence>,
    own: NamespaceIds,
    process: NamespaceIds,
) -> Option<ContainerEvidence> {
    marker
        .or_else(|| {
            (own.pid
                .zip(process.pid)
                .filter(|(own, process)| own != process))
            .map(|(_, pid)| {
                let key = match (own.mnt, process.mnt) {
                    (Some(own), Some(mnt)) if own != mnt => format!("{pid}-{mnt}"),
                    _ => pid.to_string(),
                };
                ContainerEvidence {
                    runtime: ContainerRuntime::PidNamespace,
                    key,
                }
            })
        })
        .or_else(|| {
            own.root
                .zip(process.root)
                .filter(|(own, process)| own != process)
                .map(|(_, root)| ContainerEvidence {
                    runtime: ContainerRuntime::RootFs,
                    key: format!("{}-{}", root.device, root.inode),
                })
        })
        .or_else(|| {
            let different_mount = own
                .mnt
                .zip(process.mnt)
                .is_some_and(|(own, process)| own != process);
            let rootfs_unknown = own.root.is_none() || process.root.is_none();
            (different_mount && rootfs_unknown).then(|| {
                let mnt = process.mnt.expect("different mount namespaces are present");
                ContainerEvidence {
                    runtime: ContainerRuntime::Isolated,
                    key: mnt.to_string(),
                }
            })
        })
}

fn container_marker_from_cgroup(text: &str) -> Option<ContainerEvidence> {
    for line in text.lines() {
        let components = line.split('/').map(str::trim).collect::<Vec<_>>();
        for component in &components {
            let component = *component;
            for (prefix, suffix, runtime) in [
                ("docker-", ".scope", ContainerRuntime::Docker),
                ("cri-containerd-", ".scope", ContainerRuntime::Containerd),
                ("libpod-", ".scope", ContainerRuntime::Podman),
            ] {
                if let Some(id) = component
                    .strip_prefix(prefix)
                    .and_then(|value| value.strip_suffix(suffix))
                    .filter(|id| is_container_hex_id(id))
                {
                    return Some(ContainerEvidence {
                        runtime,
                        key: id.to_ascii_lowercase(),
                    });
                }
            }
        }
        for pair in components.windows(2) {
            if pair[0] == "docker" && is_container_hex_id(pair[1]) {
                return Some(ContainerEvidence {
                    runtime: ContainerRuntime::Docker,
                    key: pair[1].to_ascii_lowercase(),
                });
            }
        }
        if components
            .iter()
            .any(|component| component.contains("kubepods"))
        {
            if let Some(id) = components
                .iter()
                .copied()
                .find(|component| is_container_hex_id(component))
            {
                return Some(ContainerEvidence {
                    runtime: ContainerRuntime::Containerd,
                    key: id.to_ascii_lowercase(),
                });
            }
        }
        if let Some(name) = components
            .windows(2)
            .find(|pair| pair[0] == "lxc")
            .map(|pair| pair[1])
            .filter(|name| !name.is_empty())
        {
            return Some(ContainerEvidence {
                runtime: ContainerRuntime::Lxc,
                key: truncate(name, MAX_TOKEN_BYTES),
            });
        }
    }
    None
}

/// Docker 컨테이너의 이름과 이미지를 붙인다. 메타데이터 파일은 root만 읽을 수 있어, 비root
/// 탐색에서는 이름 없이 id로 남는다.
fn attach_docker_meta(rows: &mut [ProcessRow], containers_dir: &Path) {
    let mut cache: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    for row in rows {
        let Some(evidence) = &row.container else {
            continue;
        };
        if evidence.runtime != ContainerRuntime::Docker {
            continue;
        }
        let (name, image) = cache
            .entry(evidence.key.clone())
            .or_insert_with(|| {
                let meta = aic_common::docker::read_docker_container_meta(
                    &containers_dir.join(&evidence.key),
                );
                (meta.name, meta.image)
            })
            .clone();
        row.container_name = name;
        row.container_image = image;
    }
}

fn is_container_hex_id(id: &str) -> bool {
    (CONTAINER_ID_MIN_HEX..=CONTAINER_ID_MAX_HEX).contains(&id.len())
        && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn inspect(candidate_id: &str) -> Result<(DiscoveryReport, WorkloadCandidate)> {
    let report = discover()?;
    let candidate_id = &resolve_workload_ref(
        candidate_id,
        report
            .candidates
            .iter()
            .map(|candidate| candidate.id.as_str()),
    )?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.id == *candidate_id)
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
    for definition in &store.workloads {
        if let Some(connection) = &definition.connection {
            connection.validate_for(definition.adapter)?;
        }
    }
    Ok(store.workloads)
}

pub const STALE_AFTER: Duration = WORKLOAD_SAMPLE_INTERVAL.saturating_mul(3);
pub const DEFAULT_HISTORY_LIMIT: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionState {
    Fresh,
    Stale,
    NoSamples,
    AmbiguousDefinitions,
    NotCollected,
}

impl CollectionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::NoSamples => "no_samples",
            Self::AmbiguousDefinitions => "ambiguous_definitions",
            Self::NotCollected => "not_collected",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkloadStatusEntry {
    pub workload_id: String,
    pub adapter: WorkloadAdapter,
    pub driver_mode: WorkloadDriverMode,
    pub state: CollectionState,
    pub last_sample: Option<WorkloadSample>,
    pub age_secs: Option<u64>,
}

pub fn derive_status(
    definitions: &[WorkloadDefinition],
    samples: &[WorkloadSample],
    now: DateTime<Utc>,
) -> Vec<WorkloadStatusEntry> {
    definitions
        .iter()
        .map(|definition| {
            if !is_monitor_adapter(definition.adapter) {
                return WorkloadStatusEntry {
                    workload_id: definition.id.clone(),
                    adapter: definition.adapter,
                    driver_mode: definition.driver_mode,
                    state: CollectionState::NotCollected,
                    last_sample: None,
                    age_secs: None,
                };
            }
            let last_sample = samples
                .iter()
                .filter(|sample| {
                    sample.workload_id == definition.id && sample.adapter == definition.adapter
                })
                .max_by_key(|sample| sample.captured_at)
                .cloned();
            let age_secs = last_sample.as_ref().map(|sample| {
                now.signed_duration_since(sample.captured_at)
                    .num_seconds()
                    .max(0) as u64
            });
            let same_adapter = definitions
                .iter()
                .filter(|other| other.adapter == definition.adapter)
                .collect::<Vec<_>>();
            let state = if adapter_definitions_conflict(&same_adapter) {
                CollectionState::AmbiguousDefinitions
            } else if let Some(age_secs) = age_secs {
                if Duration::from_secs(age_secs) > STALE_AFTER {
                    CollectionState::Stale
                } else {
                    CollectionState::Fresh
                }
            } else {
                CollectionState::NoSamples
            };
            WorkloadStatusEntry {
                workload_id: definition.id.clone(),
                adapter: definition.adapter,
                driver_mode: definition.driver_mode,
                state,
                last_sample,
                age_secs,
            }
        })
        .collect()
}

pub fn status() -> Result<Vec<WorkloadStatusEntry>> {
    let definitions = list_configured()?;
    let samples = load_workload_history(&workload_history_path())?;
    Ok(derive_status(&definitions, &samples, Utc::now()))
}

pub fn history(workload_id: &str, limit: usize) -> Result<Vec<WorkloadSample>> {
    let configured = list_configured()?;
    let workload_id = &resolve_workload_ref(
        workload_id,
        configured.iter().map(|definition| definition.id.as_str()),
    )?;
    if !configured
        .iter()
        .any(|definition| definition.id == *workload_id)
    {
        bail!("workload is not configured");
    }
    let mut samples = load_workload_history(&workload_history_path())?
        .into_iter()
        .filter(|sample| sample.workload_id == *workload_id)
        .collect::<Vec<_>>();
    samples.sort_by_key(|sample| sample.captured_at);
    let skip = samples.len().saturating_sub(limit);
    Ok(samples.into_iter().skip(skip).collect())
}

pub fn enable(candidate_id: &str, expected_fingerprint: &str) -> Result<WorkloadDefinition> {
    enable_with_connection(candidate_id, expected_fingerprint, None)
}

pub fn enable_with_connection(
    candidate_id: &str,
    expected_fingerprint: &str,
    connection: Option<WorkloadConnectionConfig>,
) -> Result<WorkloadDefinition> {
    let (_, candidate) = inspect(candidate_id)?;
    if candidate.fingerprint != expected_fingerprint {
        bail!("workload candidate changed; discover again before enabling");
    }
    enable_candidate(&candidate, connection)
}

/// 방금 탐색한 후보를 저장한다. 같은 id의 정의가 있으면 새 연결로 바꾼다.
///
/// fingerprint를 다시 확인하지 않는다. 대화형 등록에서는 사용자가 이 탐색 결과에서 후보를 직접
/// 골랐고, PostgreSQL처럼 접속마다 자식 프로세스를 띄우는 서비스는 몇 초 사이에도 fingerprint가
/// 바뀐다.
pub fn enable_candidate(
    candidate: &WorkloadCandidate,
    connection: Option<WorkloadConnectionConfig>,
) -> Result<WorkloadDefinition> {
    if !candidate.ambiguity.is_empty() || candidate.selector.is_none() {
        bail!("ambiguous workload candidates cannot be enabled");
    }
    // 고정 기본 주소(127.0.0.1의 표준 포트)는 호스트의 서비스를 가리킨다. 컨테이너 안의 서비스는
    // 공개한 포트나 컨테이너 주소로만 닿는다.
    if candidate.container.is_some() && connection.is_none() {
        bail!("container workload monitoring requires an explicit --endpoint");
    }
    validate_enable_connection(candidate.adapter, connection.as_ref())?;
    let definition = WorkloadDefinition {
        id: candidate.id.clone(),
        selector: candidate.selector.clone().expect("checked above"),
        adapter: candidate.adapter,
        driver_mode: candidate.driver_mode.unwrap_or_default(),
        connection,
    };
    save_definition(&definition)?;
    Ok(definition)
}

/// 어댑터가 보통 듣는 TCP 포트. HAProxy는 Unix 소켓이라 없다.
pub fn default_tcp_port(adapter: WorkloadAdapter) -> Option<u16> {
    Some(match adapter {
        WorkloadAdapter::PostgreSql => 5432,
        WorkloadAdapter::MySql => 3306,
        WorkloadAdapter::MongoDb => 27017,
        WorkloadAdapter::Redis => 6379,
        WorkloadAdapter::Memcached => 11211,
        WorkloadAdapter::Prometheus => 9090,
        WorkloadAdapter::ClickHouse => 8123,
        WorkloadAdapter::Etcd => 2379,
        WorkloadAdapter::Elasticsearch | WorkloadAdapter::OpenSearch => 9200,
        WorkloadAdapter::RabbitMq => 15672,
        WorkloadAdapter::Nginx => 80,
        _ => return None,
    })
}

/// 대화형 등록이 미리 채우는 연결 값.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionDefaults {
    pub endpoint: Option<String>,
    pub username: Option<String>,
    pub database: Option<String>,
}

/// 후보에 닿을 연결 값을 제안한다. 주소는 호스트 프로세스면 loopback의 기본 포트, docker
/// 컨테이너면 공개한 포트, 공개하지 않았으면 컨테이너 IP다. 사용자와 DB는 docker 컨테이너의
/// 환경 변수(`POSTGRES_USER` 등)에서, 없으면 이미지의 기본값에서 온다. 비밀번호는 제안하지 않는다.
pub fn suggest_connection(candidate: &WorkloadCandidate) -> ConnectionDefaults {
    suggest_connection_in(
        candidate,
        Path::new(aic_common::docker::DOCKER_CONTAINERS_DIR),
    )
}

fn suggest_connection_in(
    candidate: &WorkloadCandidate,
    containers_dir: &Path,
) -> ConnectionDefaults {
    let meta = candidate
        .container
        .as_ref()
        .filter(|container| container.runtime == "docker")
        .map(|container| {
            aic_common::docker::read_docker_container_meta(&containers_dir.join(&container.id))
        });
    let endpoint = default_tcp_port(candidate.adapter).and_then(|port| {
        if candidate.container.is_none() {
            return Some(format!("tcp://127.0.0.1:{port}"));
        }
        // docker가 아닌 런타임은 공개 포트를 알 수 없다.
        let meta = meta.as_ref()?;
        if let Some(published) = meta
            .published_tcp
            .iter()
            .find(|published| published.container_port == port)
        {
            let host = match published.host_ip.as_str() {
                "" | "0.0.0.0" | "::" => "127.0.0.1".to_string(),
                ip if ip.contains(':') => format!("[{ip}]"),
                ip => ip.to_string(),
            };
            return Some(format!("tcp://{host}:{}", published.host_port));
        }
        match meta.network_ips.first() {
            Some(ip) => Some(format!("tcp://{ip}:{port}")),
            // host 네트워크 컨테이너는 호스트의 포트를 그대로 쓴다.
            None => Some(format!("tcp://127.0.0.1:{port}")),
        }
    });
    let env = |key: &str| {
        meta.as_ref()
            .and_then(|meta| meta.env(key))
            .map(str::to_string)
    };
    let (username, database) = match candidate.adapter {
        // 공식 postgres 이미지는 POSTGRES_DB가 없으면 사용자 이름의 DB를 만든다.
        WorkloadAdapter::PostgreSql => {
            let user = env("POSTGRES_USER").unwrap_or_else(|| "postgres".to_string());
            let database = env("POSTGRES_DB").unwrap_or_else(|| user.clone());
            (Some(user), Some(database))
        }
        WorkloadAdapter::MySql => (
            env("MYSQL_USER")
                .or_else(|| env("MARIADB_USER"))
                .or_else(|| Some("root".to_string())),
            env("MYSQL_DATABASE").or_else(|| env("MARIADB_DATABASE")),
        ),
        WorkloadAdapter::MongoDb => (env("MONGO_INITDB_ROOT_USERNAME"), None),
        _ => (None, None),
    };
    ConnectionDefaults {
        endpoint,
        username,
        database,
    }
}

/// 사람이 부르는 짧은 이름. 컨테이너는 컨테이너 이름, 실행 파일은 파일 이름이다.
pub fn short_name(id: &str) -> &str {
    if let Some(rest) = id.strip_prefix("container:") {
        if let Some(name) = rest.split(':').nth(1) {
            return name;
        }
    }
    if let Some(unit) = id.strip_prefix("systemd:") {
        return unit;
    }
    id.rsplit('/').next().unwrap_or(id)
}

/// 사용자가 준 이름을 전체 id로 바꾼다. 정확한 id, 짧은 이름, id의 일부 순서로 찾는다. 여럿이
/// 맞으면 고르지 않고 후보를 보여 준다. 하나도 맞지 않으면 입력을 그대로 돌려 호출자가 "없음"을
/// 알리게 한다.
pub fn resolve_workload_ref<'a>(
    input: &str,
    ids: impl IntoIterator<Item = &'a str>,
) -> Result<String> {
    let ids = ids.into_iter().collect::<BTreeSet<_>>();
    if ids.contains(input) {
        return Ok(input.to_string());
    }
    for matches in [
        ids.iter()
            .filter(|id| short_name(id) == input)
            .collect::<Vec<_>>(),
        ids.iter()
            .filter(|id| id.contains(input))
            .collect::<Vec<_>>(),
    ] {
        match matches.as_slice() {
            [] => continue,
            [one] => return Ok((**one).to_string()),
            many => bail!(
                "'{input}' matches several workloads; use the full id: {}",
                many.iter().map(|id| **id).collect::<Vec<_>>().join(", ")
            ),
        }
    }
    Ok(input.to_string())
}

pub fn is_enableable_monitor_candidate(candidate: &WorkloadCandidate) -> bool {
    is_monitor_adapter(candidate.adapter)
        && candidate.selector.is_some()
        && candidate.ambiguity.is_empty()
}

/// `enable`에 연결 정보를 반드시 넣어야 하는가. TTY 대화의 `/discover` 다중 선택은 연결을 묻지
/// 못하므로 이런 후보를 대화형 등록으로 보낸다.
pub fn needs_connection(candidate: &WorkloadCandidate) -> bool {
    requires_explicit_connection(candidate.adapter) || candidate.container.is_some()
}

pub fn adapter_display_name(adapter: WorkloadAdapter) -> String {
    adapter_label(adapter)
}

fn requires_explicit_connection(adapter: WorkloadAdapter) -> bool {
    matches!(
        adapter,
        WorkloadAdapter::PostgreSql
            | WorkloadAdapter::MySql
            | WorkloadAdapter::MongoDb
            | WorkloadAdapter::Nginx
            | WorkloadAdapter::HaProxy
    )
}

fn validate_enable_connection(
    adapter: WorkloadAdapter,
    connection: Option<&WorkloadConnectionConfig>,
) -> Result<()> {
    if requires_explicit_connection(adapter) && connection.is_none() {
        bail!("database workload monitoring requires an explicit connection");
    }
    if let Some(connection) = connection {
        connection.validate_for(adapter)?;
    }
    Ok(())
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

fn workloads_path() -> std::path::PathBuf {
    workloads_file_path()
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
    // 같은 id를 다시 enable하면 연결을 고친다는 뜻이다. 예전에는 기존 정의를 남기고 새 값을
    // 조용히 버려서, 잘못 넣은 endpoint를 고칠 방법이 정의 파일 수정뿐이었다.
    store
        .workloads
        .retain(|existing| existing.id != definition.id);
    store.workloads.push(definition.clone());
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

fn adapter_label(adapter: WorkloadAdapter) -> String {
    format!("{adapter:?}").to_lowercase()
}

fn snake_label(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn container_label(container: &WorkloadContainer) -> String {
    let short_id = container.id.chars().take(12).collect::<String>();
    format!(
        "container={} runtime={} id={} image={}",
        container.name.as_deref().unwrap_or("-"),
        container.runtime,
        short_id,
        container.image.as_deref().unwrap_or("-"),
    )
}

fn list_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn shell_quote(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | ':' | '-' | '@'));
    if plain {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

/// 제안을 셸에서 실행할 `aic workload …` 명령으로 바꾼다. `WorkloadProposal::command`는 TTY
/// 대화의 `/workload …` 문법이라 셸에 그대로 붙이면 동작하지 않는다.
pub fn shell_command(proposal: &WorkloadProposal, candidate: &WorkloadCandidate) -> Option<String> {
    proposal.command.as_ref()?;
    let id = shell_quote(&candidate.id);
    match proposal.kind {
        ProposalKind::Inspect => Some(format!("aic workload inspect {id}")),
        ProposalKind::Enable => {
            let mut command = format!(
                "aic workload enable {id} --fingerprint {}",
                candidate.fingerprint
            );
            if needs_connection(candidate) {
                command.push_str(" --endpoint <tcp://HOST:PORT>");
            }
            Some(command)
        }
        _ => None,
    }
}

/// `aic workload discover`의 사람용 출력. 기본은 어댑터가 붙은 후보만 보인다 — 일반
/// 프로세스는 감시할 방법이 없는데 수백 줄을 차지한다.
pub fn render_discover(report: &DiscoveryReport, all: bool) -> String {
    let shown = report
        .candidates
        .iter()
        .filter(|candidate| all || candidate.adapter != WorkloadAdapter::Generic)
        .collect::<Vec<_>>();
    let hidden = report.candidates.len() - shown.len();
    let mut out = format!("workload candidates: {}", shown.len());
    if hidden > 0 {
        out.push_str(&format!(
            " ({hidden} generic processes hidden; --all shows them)"
        ));
    }
    out.push('\n');
    for candidate in &shown {
        out.push_str(&format!(
            "{:<13} {}\n              pids={} fingerprint={} ambiguity={}\n",
            adapter_label(candidate.adapter),
            candidate.id,
            candidate.bindings.len(),
            candidate.fingerprint,
            list_or_dash(&candidate.ambiguity),
        ));
        if let Some(container) = &candidate.container {
            out.push_str(&format!("              {}\n", container_label(container)));
        }
    }
    if shown
        .iter()
        .any(|candidate| candidate.adapter != WorkloadAdapter::Generic)
    {
        out.push_str("next: aic workload inspect <id>\n");
    }
    out
}

/// `aic workload inspect`의 사람용 출력.
pub fn render_inspect(
    candidate: &WorkloadCandidate,
    driver: &DriverInspection,
    proposals: &[WorkloadProposal],
) -> String {
    let pids = candidate
        .bindings
        .iter()
        .map(|binding| binding.pid.to_string())
        .collect::<Vec<_>>();
    let mut out = format!(
        "{}\nadapter={}\nfingerprint={}\ndriver_mode={}\ndriver_evidence={}\ndriver_pending_checks={}\nambiguity={}\npids={}\n",
        candidate.id,
        adapter_label(candidate.adapter),
        candidate.fingerprint,
        snake_label(&driver.mode),
        list_or_dash(&driver.evidence),
        list_or_dash(&driver.pending_checks),
        list_or_dash(&candidate.ambiguity),
        list_or_dash(&pids),
    );
    if let Some(container) = &candidate.container {
        out.push_str(&format!("{}\n", container_label(container)));
    }
    if proposals.is_empty() {
        return out;
    }
    out.push_str("proposals:\n");
    for proposal in proposals {
        let action = shell_command(proposal, candidate).unwrap_or_else(|| proposal.reason.clone());
        out.push_str(&format!(
            "  [{}] {}: {}\n",
            snake_label(&proposal.readiness),
            snake_label(&proposal.kind),
            action
        ));
    }
    out
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
            container: None,
            container_name: None,
            container_image: None,
            ambiguity: Vec::new(),
        }
    }

    fn container_row(
        pid: u32,
        start_time: u64,
        name: &str,
        exe: Option<&str>,
        cmd: &[&str],
        runtime: ContainerRuntime,
        key: &str,
    ) -> ProcessRow {
        let mut row = row(pid, start_time, name, exe, cmd);
        row.container = Some(ContainerEvidence {
            runtime,
            key: key.to_string(),
        });
        row
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn discovery_does_not_bind_userland_threads() {
        // 스레드마다 binding이 생기면 fingerprint가 스레드 생성·종료에 따라 바뀌어, discover 직후의
        // enable이 "candidate changed"로 거부된다. 스캐너 자신의 워커 스레드도 후보로 올라온다.
        use std::sync::mpsc;
        let (tid_tx, tid_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let stop_rx = std::sync::Arc::new(std::sync::Mutex::new(stop_rx));
        let workers = (0..3)
            .map(|_| {
                let tid_tx = tid_tx.clone();
                let stop_rx = stop_rx.clone();
                std::thread::spawn(move || {
                    tid_tx.send(unsafe { libc::gettid() } as u32).unwrap();
                    let _ = stop_rx.lock().unwrap().recv();
                })
            })
            .collect::<Vec<_>>();
        let tids = (0..3)
            .map(|_| tid_rx.recv().unwrap())
            .collect::<BTreeSet<_>>();

        let report = discover_with_driver_checks(false).unwrap();

        drop(stop_tx);
        for worker in workers {
            worker.join().unwrap();
        }
        let bound = report
            .candidates
            .iter()
            .flat_map(|candidate| &candidate.bindings)
            .filter(|binding| tids.contains(&binding.pid))
            .count();
        assert_eq!(bound, 0, "스레드 {tids:?}가 후보 binding에 들어감");
    }

    /// 이 테스트가 지키는 것: 커널 스레드가 후보 상한을 채우지 않는 것. pid 2는 리눅스에서
    /// 커널 스레드를 만드는 `kthreadd`다.
    #[cfg(target_os = "linux")]
    #[test]
    fn discovery_skips_kernel_threads() {
        let report = discover_with_driver_checks(false).unwrap();
        let kthreadd = report
            .candidates
            .iter()
            .flat_map(|candidate| &candidate.bindings)
            .any(|binding| binding.pid == 2);
        assert!(!kthreadd, "kthreadd가 후보 binding에 들어감");
    }

    #[test]
    fn a_replaced_executable_keeps_its_candidate_id() {
        assert_eq!(
            without_deleted_suffix("/usr/sbin/nginx (deleted)"),
            "/usr/sbin/nginx"
        );
        assert_eq!(without_deleted_suffix("/usr/sbin/nginx"), "/usr/sbin/nginx");
    }

    #[test]
    fn discover_output_hides_generic_processes_unless_all() {
        let report = discover_rows(vec![
            row(10, 1, "nginx", Some("/usr/sbin/nginx"), &[]),
            row(11, 1, "bash", Some("/usr/bin/bash"), &[]),
            row(12, 1, "cron", Some("/usr/sbin/cron"), &[]),
        ]);
        let short = render_discover(&report, false);
        assert!(short.starts_with("workload candidates: 1 (2 generic processes hidden"));
        assert!(short.contains("exe:/usr/sbin/nginx"));
        assert!(!short.contains("/usr/bin/bash"));
        assert!(short.contains("next: aic workload inspect <id>"));

        let all = render_discover(&report, true);
        assert!(all.starts_with("workload candidates: 3\n"));
        assert!(all.contains("/usr/bin/bash"));
    }

    /// 이 테스트가 지키는 것: 대화형 등록이 제안하는 기본 주소가 실제로 닿는 곳인 것. 호스트는
    /// loopback의 표준 포트, docker는 공개 포트, 공개하지 않았으면 컨테이너 IP다.
    #[test]
    fn endpoint_suggestions_follow_where_the_service_listens() {
        let dir = tempfile::tempdir().unwrap();
        let write = |id: &str, body: &str| {
            std::fs::create_dir_all(dir.path().join(id)).unwrap();
            std::fs::write(dir.path().join(id).join("config.v2.json"), body).unwrap();
        };
        let published = "a".repeat(64);
        let wildcard = "b".repeat(64);
        let private = "c".repeat(64);
        let host_net = "d".repeat(64);
        write(
            &published,
            r#"{"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"15432"}]},"Networks":{"n":{"IPAddress":"172.19.0.2"}}}}"#,
        );
        write(
            &wildcard,
            r#"{"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"5433"}]}}}"#,
        );
        write(
            &private,
            r#"{"NetworkSettings":{"Ports":{"5432/tcp":null},"Networks":{"n":{"IPAddress":"172.19.0.3"}}}}"#,
        );
        write(
            &host_net,
            r#"{"NetworkSettings":{"Ports":{},"Networks":{"host":{"IPAddress":""}}}}"#,
        );
        let candidate = |container: Option<&str>| WorkloadCandidate {
            id: "x".into(),
            fingerprint: "f".into(),
            selector: Some(WorkloadSelector::Executable {
                path: "/usr/local/bin/postgres".into(),
            }),
            adapter: WorkloadAdapter::PostgreSql,
            driver_mode: None,
            bindings: Vec::new(),
            ambiguity: Vec::new(),
            container: container.map(|id| WorkloadContainer {
                runtime: "docker".into(),
                id: id.to_string(),
                name: None,
                image: None,
            }),
        };
        let suggest = |id: Option<&str>| suggest_connection_in(&candidate(id), dir.path()).endpoint;
        assert_eq!(suggest(None).as_deref(), Some("tcp://127.0.0.1:5432"));
        assert_eq!(
            suggest(Some(&published)).as_deref(),
            Some("tcp://127.0.0.1:15432")
        );
        assert_eq!(
            suggest(Some(&wildcard)).as_deref(),
            Some("tcp://127.0.0.1:5433")
        );
        assert_eq!(
            suggest(Some(&private)).as_deref(),
            Some("tcp://172.19.0.3:5432")
        );
        assert_eq!(
            suggest(Some(&host_net)).as_deref(),
            Some("tcp://127.0.0.1:5432")
        );
        let mut podman = candidate(Some(&published));
        podman.container.as_mut().unwrap().runtime = "podman".into();
        assert_eq!(suggest_connection_in(&podman, dir.path()).endpoint, None);
    }

    #[test]
    fn short_names_and_references_resolve_to_one_workload() {
        let pg = "container:docker:dnx-postgres-1:exe:/usr/local/bin/postgres";
        let nginx = "exe:/usr/sbin/nginx";
        let nginx_container = "container:docker:web:exe:/usr/sbin/nginx";
        assert_eq!(short_name(pg), "dnx-postgres-1");
        assert_eq!(short_name(nginx), "nginx");
        assert_eq!(short_name("systemd:redis.service"), "redis.service");
        let ids = [pg, nginx, nginx_container];
        assert_eq!(resolve_workload_ref(pg, ids).unwrap(), pg);
        assert_eq!(resolve_workload_ref("dnx-postgres-1", ids).unwrap(), pg);
        assert_eq!(resolve_workload_ref("postgres-1", ids).unwrap(), pg);
        assert_eq!(resolve_workload_ref("web", ids).unwrap(), nginx_container);
        assert_eq!(resolve_workload_ref("nginx", ids).unwrap(), nginx);
        let two_hosts = [nginx, "exe:/opt/nginx/sbin/nginx"];
        let error = resolve_workload_ref("nginx", two_hosts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("several"), "{error}");
        assert_eq!(resolve_workload_ref("missing", ids).unwrap(), "missing");
    }

    /// 이 테스트가 지키는 것: 사용자와 DB 기본값이 컨테이너 설정에서 오고, 비밀번호는 오지 않는 것.
    #[test]
    fn connection_defaults_come_from_the_container_without_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let id = "e".repeat(64);
        std::fs::create_dir_all(dir.path().join(&id)).unwrap();
        std::fs::write(
            dir.path().join(&id).join("config.v2.json"),
            r#"{"Config":{"Env":["POSTGRES_USER=dnx","POSTGRES_PASSWORD=secret"]},
               "NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}]}}}"#,
        )
        .unwrap();
        let mut candidate = WorkloadCandidate {
            id: "container:docker:dnx:exe:/usr/local/bin/postgres".into(),
            fingerprint: "f".into(),
            selector: Some(WorkloadSelector::Executable {
                path: "/usr/local/bin/postgres".into(),
            }),
            adapter: WorkloadAdapter::PostgreSql,
            driver_mode: None,
            bindings: Vec::new(),
            ambiguity: Vec::new(),
            container: Some(WorkloadContainer {
                runtime: "docker".into(),
                id,
                name: Some("dnx".into()),
                image: None,
            }),
        };
        let defaults = suggest_connection_in(&candidate, dir.path());
        assert_eq!(
            defaults,
            ConnectionDefaults {
                endpoint: Some("tcp://127.0.0.1:5432".into()),
                username: Some("dnx".into()),
                database: Some("dnx".into()),
            }
        );
        assert!(!format!("{defaults:?}").contains("secret"));
        candidate.container = None;
        let host = suggest_connection_in(&candidate, dir.path());
        assert_eq!(host.username.as_deref(), Some("postgres"));
        assert_eq!(host.database.as_deref(), Some("postgres"));
    }

    #[test]
    fn proposals_render_as_shell_commands() {
        let report = discover_rows(vec![
            row(10, 1, "nginx", Some("/opt/my nginx/sbin/nginx"), &[]),
            row(20, 1, "redis-server", Some("/usr/bin/redis-server"), &[]),
        ]);
        let all = proposals(&report);
        let command = |id: &str, kind: ProposalKind| {
            let candidate = report.candidates.iter().find(|c| c.id == id).unwrap();
            let proposal = all
                .iter()
                .find(|p| p.candidate_id == id && p.kind == kind)
                .unwrap();
            shell_command(proposal, candidate)
        };
        let nginx = "exe:/opt/my nginx/sbin/nginx";
        assert_eq!(
            command(nginx, ProposalKind::Inspect).unwrap(),
            "aic workload inspect 'exe:/opt/my nginx/sbin/nginx'"
        );
        let enable = command(nginx, ProposalKind::Enable).unwrap();
        assert!(
            enable.starts_with("aic workload enable 'exe:/opt/my nginx/sbin/nginx' --fingerprint ")
        );
        assert!(
            enable.ends_with(" --endpoint <tcp://HOST:PORT>"),
            "{enable}"
        );
        let redis = command("exe:/usr/bin/redis-server", ProposalKind::Enable).unwrap();
        assert!(!redis.contains("--endpoint"), "{redis}");
        assert_eq!(command(nginx, ProposalKind::DriverInspect), None);
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
    fn rabbitmq_processes_with_one_systemd_unit_collapse() {
        let mut server = row(
            1,
            1,
            "rabbitmq-server",
            Some("/usr/sbin/rabbitmq-server"),
            &[],
        );
        server.systemd_unit = Some("rabbitmq-server.service".into());
        let mut beam = row(
            2,
            1,
            "beam.smp",
            Some("/usr/lib/erlang/beam.smp"),
            &["rabbitmq"],
        );
        beam.systemd_unit = Some("rabbitmq-server.service".into());
        let report = discover_rows(vec![server, beam]);
        let candidates = report
            .candidates
            .iter()
            .filter(|candidate| candidate.adapter == WorkloadAdapter::RabbitMq)
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].bindings.len(), 2);
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
    fn container_marker_from_cgroup_recognizes_supported_runtimes() {
        let id = "0123456789abcdef0123456789abcdef";
        for (text, runtime) in [
            (
                format!("0::/system.slice/docker-{id}.scope"),
                ContainerRuntime::Docker,
            ),
            (format!("0::/docker/{id}"), ContainerRuntime::Docker),
            (
                format!("0::/kubepods.slice/cri-containerd-{id}.scope"),
                ContainerRuntime::Containerd,
            ),
            (
                format!("0::/machine.slice/libpod-{id}.scope"),
                ContainerRuntime::Podman,
            ),
            (
                format!("0::/kubepods.slice/{id}"),
                ContainerRuntime::Containerd,
            ),
        ] {
            let evidence = container_marker_from_cgroup(&text).unwrap();
            assert_eq!(evidence.runtime, runtime);
            assert_eq!(evidence.key, id);
        }
        let lxc = container_marker_from_cgroup("0::/lxc/web1").unwrap();
        assert_eq!(lxc.runtime, ContainerRuntime::Lxc);
        assert_eq!(lxc.key, "web1");
    }

    #[test]
    fn container_marker_ignores_runtime_daemon_units() {
        for text in [
            "0::/system.slice/docker.service",
            "0::/system.slice/containerd.service",
            "0::/system.slice/podman.service",
            "0::/system.slice/nginx.service",
            "0::/system.slice/docker-012345.scope",
        ] {
            assert!(container_marker_from_cgroup(text).is_none());
        }
    }

    #[test]
    fn container_evidence_prefers_cgroup_then_pid_namespace() {
        let marker = ContainerEvidence {
            runtime: ContainerRuntime::Docker,
            key: "marker".to_string(),
        };
        let own = NamespaceIds {
            pid: Some(1),
            mnt: Some(2),
            root: Some(FileIdentity {
                device: 1,
                inode: 1,
            }),
        };
        let process = NamespaceIds {
            pid: Some(3),
            mnt: Some(4),
            root: Some(FileIdentity {
                device: 2,
                inode: 2,
            }),
        };
        let evidence = container_evidence(Some(marker), own, process).unwrap();
        assert_eq!(evidence.runtime.label(), "docker");
        assert_eq!(evidence.key, "marker");
        let evidence = container_evidence(None, own, process).unwrap();
        assert_eq!(evidence.runtime.label(), "pidns");
        assert_eq!(evidence.key, "3-4");
    }

    #[test]
    fn mount_namespace_difference_alone_keeps_host_classification() {
        assert!(container_evidence(
            None,
            NamespaceIds {
                pid: Some(1),
                mnt: Some(2),
                root: Some(FileIdentity {
                    device: 1,
                    inode: 1,
                }),
            },
            NamespaceIds {
                pid: Some(1),
                mnt: Some(3),
                root: Some(FileIdentity {
                    device: 1,
                    inode: 1,
                }),
            },
        )
        .is_none());
    }

    #[test]
    fn argv0_replaces_an_unreadable_executable_only_when_it_resolves() {
        let existing = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(
            executable_from_argv0(std::slice::from_ref(&existing)),
            Some(existing.clone())
        );
        assert_eq!(executable_from_argv0(&[]), None);
        assert_eq!(executable_from_argv0(&["redis-server".to_string()]), None);
        assert_eq!(
            executable_from_argv0(&["/nonexistent/redis-server".to_string()]),
            None
        );
        let directory = std::path::Path::new(&existing)
            .parent()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(executable_from_argv0(&[directory]), None);
    }

    #[test]
    fn unreadable_namespaces_leave_the_cgroup_verdict_intact() {
        // 비루트는 다른 사용자 프로세스의 /proc/<pid>/ns/*와 /proc/<pid>/root를 읽지 못한다.
        let own = NamespaceIds {
            pid: Some(1),
            mnt: Some(2),
            root: Some(FileIdentity {
                device: 1,
                inode: 1,
            }),
        };
        let unreadable = NamespaceIds::default();
        assert!(container_evidence(None, own, unreadable).is_none());
        let id = "0123456789abcdef0123456789abcdef";
        let marker = container_marker_from_cgroup(&format!("0::/system.slice/docker-{id}.scope"));
        let evidence = container_evidence(marker, own, unreadable).unwrap();
        assert_eq!(evidence.runtime, ContainerRuntime::Docker);
        assert_eq!(evidence.key, id);
    }

    #[test]
    fn rootfs_difference_detects_host_pid_namespace_containers() {
        let evidence = container_evidence(
            None,
            NamespaceIds {
                pid: Some(1),
                mnt: Some(2),
                root: Some(FileIdentity {
                    device: 10,
                    inode: 20,
                }),
            },
            NamespaceIds {
                pid: Some(1),
                mnt: Some(3),
                root: Some(FileIdentity {
                    device: 11,
                    inode: 21,
                }),
            },
        )
        .unwrap();
        assert_eq!(evidence.runtime, ContainerRuntime::RootFs);
        assert_eq!(evidence.key, "11-21");
    }

    #[test]
    fn unreadable_rootfs_with_mount_isolation_stays_fail_closed() {
        let evidence = container_evidence(
            None,
            NamespaceIds {
                pid: Some(1),
                mnt: Some(2),
                root: Some(FileIdentity {
                    device: 10,
                    inode: 20,
                }),
            },
            NamespaceIds {
                pid: Some(1),
                mnt: Some(3),
                root: None,
            },
        )
        .unwrap();
        assert_eq!(evidence.runtime, ContainerRuntime::Isolated);
        assert_eq!(evidence.key, "3");
    }

    #[test]
    fn namespace_inode_parses_proc_namespace_links() {
        assert_eq!(namespace_inode("pid:[4026531836]"), Some(4_026_531_836));
        assert_eq!(namespace_inode("mnt:[4026531840]"), Some(4_026_531_840));
        assert_eq!(namespace_inode("invalid"), None);
    }

    #[test]
    fn containerized_postgres_is_separated_from_host_with_same_executable() {
        let executable = "/usr/lib/postgresql/16/bin/postgres";
        let report = discover_rows(vec![
            row(1, 1, "postgres", Some(executable), &[]),
            container_row(
                2,
                1,
                "postgres",
                Some(executable),
                &[],
                ContainerRuntime::Docker,
                "0123456789abcdef0123456789abcdef",
            ),
        ]);
        let host_id = format!("exe:{executable}");
        assert_eq!(
            report
                .candidates
                .iter()
                .filter(|candidate| candidate.adapter == WorkloadAdapter::PostgreSql)
                .count(),
            2
        );
        assert!(report
            .candidates
            .iter()
            .any(|candidate| candidate.id == host_id));
        let container = report
            .candidates
            .iter()
            .find(|candidate| {
                candidate
                    .id
                    .starts_with("container:docker:0123456789abcdef0123456789abcdef:")
            })
            .unwrap();
        assert!(container.ambiguity.is_empty(), "{:?}", container.ambiguity);
        assert_eq!(
            container.container.as_ref().map(|c| c.runtime.as_str()),
            Some("docker")
        );
        assert_eq!(container.driver_mode, Some(WorkloadDriverMode::DetectOnly));
        let all = proposals(&report);
        let enabled = all
            .iter()
            .filter(|proposal| proposal.kind == ProposalKind::Enable)
            .map(|proposal| proposal.candidate_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(enabled, vec![host_id, container.id.clone()]);
        let enable = all
            .iter()
            .find(|p| p.kind == ProposalKind::Enable && p.candidate_id == container.id)
            .unwrap();
        assert!(shell_command(enable, container)
            .unwrap()
            .ends_with(" --endpoint <tcp://HOST:PORT>"));
    }

    /// 이 테스트가 지키는 것: 네임스페이스 차이로만 추정한 격리는 무엇인지 모르므로 등록을
    /// 막는 것. snap(multipass 등)도 마운트 네임스페이스가 달라 이 경로로 잡힌다.
    #[test]
    fn an_unidentified_isolation_stays_ambiguous() {
        let report = discover_rows(vec![container_row(
            2,
            1,
            "postgres",
            Some("/usr/lib/postgresql/16/bin/postgres"),
            &[],
            ContainerRuntime::PidNamespace,
            "4026532001",
        )]);
        let candidate = &report.candidates[0];
        assert!(candidate
            .ambiguity
            .iter()
            .any(|ambiguity| ambiguity == CONTAINERIZED_WORKLOAD_AMBIGUITY));
        assert!(proposals(&report)
            .iter()
            .all(|proposal| proposal.kind != ProposalKind::Enable));
    }

    /// 이 테스트가 지키는 것: docker 후보 id가 컨테이너 이름을 쓰는 것. Compose가 컨테이너를
    /// 다시 만들면 id는 바뀌고 이름은 남는다. 메타데이터를 못 읽으면 id로 남는다.
    #[test]
    fn a_docker_candidate_is_named_after_its_container() {
        let named = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let unreadable = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(named)).unwrap();
        std::fs::write(
            dir.path().join(named).join("config.v2.json"),
            r#"{"Name":"/dnx-postgres-1","Config":{"Image":"postgres:17.6-alpine"}}"#,
        )
        .unwrap();
        let executable = "/usr/local/bin/postgres";
        let mut rows = vec![
            container_row(
                2,
                1,
                "postgres",
                Some(executable),
                &[],
                ContainerRuntime::Docker,
                named,
            ),
            container_row(
                3,
                1,
                "postgres",
                Some(executable),
                &[],
                ContainerRuntime::Docker,
                unreadable,
            ),
        ];
        attach_docker_meta(&mut rows, dir.path());
        let report = discover_rows(rows);
        let ids = report
            .candidates
            .iter()
            .map(|candidate| candidate.id.as_str())
            .collect::<Vec<_>>();
        assert!(
            ids.contains(&"container:docker:dnx-postgres-1:exe:/usr/local/bin/postgres"),
            "{ids:?}"
        );
        assert!(
            ids.contains(
                &format!("container:docker:{unreadable}:exe:/usr/local/bin/postgres").as_str()
            ),
            "{ids:?}"
        );
        let named_candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.id.contains("dnx-postgres-1"))
            .unwrap();
        let container = named_candidate.container.as_ref().unwrap();
        assert_eq!(container.id, named);
        assert_eq!(container.image.as_deref(), Some("postgres:17.6-alpine"));
        assert!(render_discover(&report, false).contains(
            "container=dnx-postgres-1 runtime=docker id=aaaaaaaaaaaa image=postgres:17.6-alpine"
        ));
    }

    #[test]
    fn containers_and_host_keep_separate_stable_candidates() {
        let executable = "/usr/lib/postgresql/16/bin/postgres";
        let first_id = "0123456789abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second_id = "0123456789abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let host = discover_rows(vec![row(1, 1, "postgres", Some(executable), &[])]);
        let report = discover_rows(vec![
            row(1, 1, "postgres", Some(executable), &[]),
            container_row(
                2,
                1,
                "postgres",
                Some(executable),
                &[],
                ContainerRuntime::Docker,
                first_id,
            ),
            container_row(
                3,
                1,
                "postgres",
                Some(executable),
                &[],
                ContainerRuntime::Docker,
                second_id,
            ),
        ]);
        assert_eq!(report.candidates.len(), 3);
        assert_eq!(report.candidates[0].id, host.candidates[0].id);
        assert_eq!(
            report.candidates[0].fingerprint,
            host.candidates[0].fingerprint
        );
        assert!(report.candidates[1]
            .id
            .starts_with(&format!("container:docker:{first_id}:")));
        assert!(report.candidates[2]
            .id
            .starts_with(&format!("container:docker:{second_id}:")));
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
            container: None,
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
                container: None,
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

    fn redis_candidate(id: &str, ambiguity: &[&str]) -> WorkloadCandidate {
        WorkloadCandidate {
            container: None,
            id: id.into(),
            fingerprint: format!("fingerprint:{id}"),
            selector: Some(WorkloadSelector::Executable {
                path: format!("/usr/bin/{id}"),
            }),
            adapter: WorkloadAdapter::Redis,
            driver_mode: Some(WorkloadDriverMode::DetectOnly),
            bindings: Vec::new(),
            ambiguity: ambiguity.iter().map(|item| (*item).to_string()).collect(),
        }
    }

    fn redis_report(candidates: Vec<WorkloadCandidate>) -> DiscoveryReport {
        DiscoveryReport {
            schema_version: WORKLOAD_SCHEMA_VERSION,
            evidence_coverage: "test".into(),
            candidates,
        }
    }

    #[test]
    fn monitor_selects_the_single_matching_unambiguous_candidate() {
        let report = redis_report(vec![redis_candidate("redis-a", &[])]);
        let selected = select_monitor_candidate(&report, "redis-a", false).unwrap();
        assert_eq!(selected.id, "redis-a");
    }

    /// 이 테스트가 지키는 것: 연결이 저장된 후보는 같은 어댑터의 다른 후보와 함께 있어도
    /// 점검할 수 있는 것. 호스트와 컨테이너에 같은 서비스가 함께 있는 경우다.
    #[test]
    fn a_candidate_with_a_saved_connection_is_monitored_among_others() {
        let report = redis_report(vec![
            redis_candidate("redis-a", &[]),
            redis_candidate("redis-b", &[]),
        ]);
        assert!(select_monitor_candidate(&report, "redis-a", false).is_err());
        let selected = select_monitor_candidate(&report, "redis-a", true).unwrap();
        assert_eq!(selected.id, "redis-a");
        assert!(select_monitor_candidate(&report, "redis-c", true).is_err());
        let ambiguous = redis_report(vec![redis_candidate(
            "redis-a",
            &["executable_unavailable"],
        )]);
        assert!(select_monitor_candidate(&ambiguous, "redis-a", true).is_err());
    }

    #[test]
    fn monitor_fails_closed_for_zero_multiple_mismatched_or_ambiguous_candidates() {
        let cases = [
            (redis_report(Vec::new()), "redis-a"),
            (
                redis_report(vec![
                    redis_candidate("redis-a", &[]),
                    redis_candidate("redis-b", &[]),
                ]),
                "redis-a",
            ),
            (
                redis_report(vec![redis_candidate("redis-a", &[])]),
                "redis-b",
            ),
            (
                redis_report(vec![redis_candidate(
                    "redis-a",
                    &["executable_unavailable"],
                )]),
                "redis-a",
            ),
        ];
        for (report, candidate_id) in cases {
            assert!(select_monitor_candidate(&report, candidate_id, false).is_err());
        }
    }

    #[test]
    fn jvm_kafka_and_consul_are_discovery_only() {
        for adapter in [
            WorkloadAdapter::Jvm,
            WorkloadAdapter::Kafka,
            WorkloadAdapter::Consul,
        ] {
            assert!(!is_monitor_adapter(adapter));
            let definition = WorkloadDefinition {
                id: format!("{adapter:?}"),
                selector: WorkloadSelector::Executable {
                    path: "/usr/bin/service".into(),
                },
                adapter,
                driver_mode: WorkloadDriverMode::DetectOnly,
                connection: None,
            };
            assert_eq!(
                derive_status(&[definition], &[], Utc::now())[0].state,
                CollectionState::NotCollected
            );
        }
    }

    #[test]
    fn monitor_errors_do_not_expose_probe_details() {
        let error = safe_monitor_error(
            WorkloadAdapter::Memcached,
            WorkloadProbeError::Rejected("CLIENT_ERROR token=secret".into()),
        );
        assert_eq!(
            error.to_string(),
            "Memcached monitor probe failed: rejected the monitor request"
        );
    }

    #[test]
    fn postgresql_enable_requires_an_explicit_connection() {
        assert!(validate_enable_connection(WorkloadAdapter::PostgreSql, None).is_err());
        assert!(validate_enable_connection(WorkloadAdapter::MySql, None).is_err());
        assert!(validate_enable_connection(WorkloadAdapter::MongoDb, None).is_err());
        assert!(validate_enable_connection(WorkloadAdapter::Redis, None).is_ok());
    }

    fn sample(workload_id: &str, captured_at: DateTime<Utc>) -> WorkloadSample {
        sample_for_adapter(workload_id, WorkloadAdapter::Redis, captured_at)
    }

    fn sample_for_adapter(
        workload_id: &str,
        adapter: WorkloadAdapter,
        captured_at: DateTime<Utc>,
    ) -> WorkloadSample {
        WorkloadSample {
            schema_version: aic_common::workload::WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: workload_id.into(),
            captured_at,
            adapter,
            outcome: aic_common::workload::WorkloadSampleOutcome::Failed {
                reason: aic_common::workload::WorkloadSampleFailure::Unreachable,
                detail: "unavailable".into(),
            },
        }
    }

    fn redis_definition(id: &str) -> WorkloadDefinition {
        WorkloadDefinition {
            id: id.into(),
            selector: WorkloadSelector::Executable {
                path: format!("/usr/bin/{id}"),
            },
            adapter: WorkloadAdapter::Redis,
            driver_mode: WorkloadDriverMode::MonitorReady,
            connection: None,
        }
    }

    fn memcached_definition(id: &str) -> WorkloadDefinition {
        WorkloadDefinition {
            id: id.into(),
            selector: WorkloadSelector::Executable {
                path: format!("/usr/bin/{id}"),
            },
            adapter: WorkloadAdapter::Memcached,
            driver_mode: WorkloadDriverMode::MonitorReady,
            connection: None,
        }
    }

    #[test]
    fn derive_status_covers_fresh_stale_missing_and_ambiguous() {
        let now = Utc::now();
        let definition = redis_definition("redis");
        assert_eq!(
            derive_status(
                std::slice::from_ref(&definition),
                &[sample("redis", now)],
                now
            )[0]
            .state,
            CollectionState::Fresh
        );
        assert_eq!(
            derive_status(
                std::slice::from_ref(&definition),
                &[sample(
                    "redis",
                    now - chrono::Duration::seconds(STALE_AFTER.as_secs() as i64 + 1)
                )],
                now
            )[0]
            .state,
            CollectionState::Stale
        );
        assert_eq!(
            derive_status(std::slice::from_ref(&definition), &[], now)[0].state,
            CollectionState::NoSamples
        );
        assert_eq!(
            derive_status(
                &[definition.clone(), redis_definition("redis-two")],
                &[],
                now
            )[0]
            .state,
            CollectionState::AmbiguousDefinitions
        );
        let memcached = memcached_definition("memcached");
        let states = derive_status(
            &[
                definition.clone(),
                redis_definition("redis-two"),
                memcached.clone(),
            ],
            &[sample_for_adapter(
                "memcached",
                WorkloadAdapter::Memcached,
                now,
            )],
            now,
        );
        assert_eq!(states[0].state, CollectionState::AmbiguousDefinitions);
        assert_eq!(states[2].state, CollectionState::Fresh);

        let connected = |id: &str, endpoint: &str| WorkloadDefinition {
            connection: Some(WorkloadConnectionConfig {
                endpoint: endpoint.to_string(),
                username: None,
                secret_ref: None,
                database: None,
                auth_source: None,
            }),
            ..redis_definition(id)
        };
        let states = derive_status(
            &[
                connected("redis", "tcp://127.0.0.1:6379"),
                connected(
                    "container:docker:cache:exe:/usr/local/bin/redis-server",
                    "tcp://127.0.0.1:16379",
                ),
            ],
            &[sample("redis", now)],
            now,
        );
        assert_eq!(states[0].state, CollectionState::Fresh);
        assert_eq!(states[1].state, CollectionState::NoSamples);
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
