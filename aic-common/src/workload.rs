//! Workload discovery contracts shared by the CLI and chat paths.

use crate::paths;
use anyhow::Result;
use chrono::{DateTime, Utc};
use mongodb::bson::{doc, Bson, Document};
use mongodb::options::{ClientOptions, Credential, ServerAddress, Tls, TlsOptions};
use mongodb::Client as MongoDbClient;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn as MySqlConnection, OptsBuilder as MySqlOptsBuilder, SslOpts};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Config as PostgreSqlConfig, NoTls, Row};
use tokio_postgres_rustls::MakeRustlsConnect;

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
    /// Missing records keep the fixed local endpoint defaults.
    #[serde(default)]
    pub connection: Option<WorkloadConnectionConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkloadConnectionConfig {
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadEndpoint {
    Unix(PathBuf),
    Tcp { host: String, port: u16 },
    Tls { host: String, port: u16 },
}

impl WorkloadConnectionConfig {
    pub fn validate_for(&self, adapter: WorkloadAdapter) -> Result<()> {
        self.endpoint()?;
        if self.username.as_deref().is_some_and(str::is_empty) {
            anyhow::bail!("workload username must not be empty");
        }
        if self.database.as_deref().is_some_and(str::is_empty) {
            anyhow::bail!("workload database must not be empty");
        }
        if self.auth_source.as_deref().is_some_and(str::is_empty) {
            anyhow::bail!("workload auth_source must not be empty");
        }
        if let Some(secret_ref) = &self.secret_ref {
            crate::secret::parse_secret_reference(secret_ref).map_err(anyhow::Error::msg)?;
        }
        if !matches!(
            adapter,
            WorkloadAdapter::PostgreSql | WorkloadAdapter::MySql
        ) && self.username.is_some()
            && self.secret_ref.is_none()
        {
            anyhow::bail!("workload username requires secret_ref");
        }
        match adapter {
            WorkloadAdapter::PostgreSql => {
                if self.username.is_none() || self.database.is_none() {
                    anyhow::bail!("PostgreSQL workload connections require username and database");
                }
                if matches!(self.endpoint()?, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("PostgreSQL workload connections require a TCP or TLS endpoint");
                }
            }
            WorkloadAdapter::MySql => {
                if self.username.is_none() {
                    anyhow::bail!("MySQL workload connections require username");
                }
                if matches!(self.endpoint()?, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("MySQL workload connections require a TCP or TLS endpoint");
                }
            }
            WorkloadAdapter::MongoDb => {
                if matches!(self.endpoint()?, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("MongoDB workload connections require a TCP or TLS endpoint");
                }
                if self.database.is_some() {
                    anyhow::bail!("MongoDB workload connections do not support database");
                }
                if self.username.is_some() != self.secret_ref.is_some() {
                    anyhow::bail!("MongoDB username and secret_ref must be provided together");
                }
                if self.auth_source.is_some() && self.username.is_none() {
                    anyhow::bail!("MongoDB auth_source requires credentials");
                }
            }
            WorkloadAdapter::Prometheus => {
                if matches!(self.endpoint()?, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("Prometheus workload connections require a TCP or TLS endpoint");
                }
                if self.username.is_some()
                    || self.secret_ref.is_some()
                    || self.database.is_some()
                    || self.auth_source.is_some()
                {
                    anyhow::bail!("Prometheus workload connections do not support authentication or database fields");
                }
            }
            WorkloadAdapter::ClickHouse => {
                let endpoint = self.endpoint()?;
                if matches!(endpoint, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("ClickHouse workload connections require a TCP or TLS endpoint");
                }
                if self.username.is_some() != self.secret_ref.is_some() {
                    anyhow::bail!("ClickHouse username and secret_ref must be provided together");
                }
                if self.database.is_some() || self.auth_source.is_some() {
                    anyhow::bail!("ClickHouse workload connections do not support database fields");
                }
                if self.secret_ref.is_some() && !matches!(endpoint, WorkloadEndpoint::Tls { .. }) {
                    anyhow::bail!("ClickHouse authentication requires a TLS endpoint");
                }
            }
            WorkloadAdapter::Etcd => {
                if matches!(self.endpoint()?, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("etcd workload connections require a TCP or TLS endpoint");
                }
                if self.username.is_some()
                    || self.secret_ref.is_some()
                    || self.database.is_some()
                    || self.auth_source.is_some()
                {
                    anyhow::bail!("etcd workload connections do not support configuration fields");
                }
            }
            WorkloadAdapter::Elasticsearch | WorkloadAdapter::OpenSearch => {
                let endpoint = self.endpoint()?;
                if matches!(endpoint, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("search workload connections require a TCP or TLS endpoint");
                }
                if self.username.is_some() != self.secret_ref.is_some() {
                    anyhow::bail!("search username and secret_ref must be provided together");
                }
                if self.database.is_some() || self.auth_source.is_some() {
                    anyhow::bail!("search workload connections do not support database fields");
                }
                if self.secret_ref.is_some() && !matches!(endpoint, WorkloadEndpoint::Tls { .. }) {
                    anyhow::bail!("search authentication requires a TLS endpoint");
                }
            }
            WorkloadAdapter::RabbitMq => {
                let endpoint = self.endpoint()?;
                if matches!(endpoint, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("RabbitMQ workload connections require a TCP or TLS endpoint");
                }
                if self.username.is_some() != self.secret_ref.is_some() {
                    anyhow::bail!("RabbitMQ username and secret_ref must be provided together");
                }
                if self.database.is_some() || self.auth_source.is_some() {
                    anyhow::bail!("RabbitMQ workload connections do not support database fields");
                }
                if self.secret_ref.is_some() && !matches!(endpoint, WorkloadEndpoint::Tls { .. }) {
                    anyhow::bail!("RabbitMQ authentication requires a TLS endpoint");
                }
            }
            WorkloadAdapter::Nginx => {
                let endpoint = self.endpoint()?;
                if matches!(endpoint, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("Nginx workload connections require a TCP or TLS endpoint");
                }
                if self.username.is_some() != self.secret_ref.is_some() {
                    anyhow::bail!("Nginx username and secret_ref must be provided together");
                }
                if self.database.is_some() || self.auth_source.is_some() {
                    anyhow::bail!("Nginx workload connections do not support database fields");
                }
                if self.secret_ref.is_some() && !matches!(endpoint, WorkloadEndpoint::Tls { .. }) {
                    anyhow::bail!("Nginx authentication requires a TLS endpoint");
                }
            }
            WorkloadAdapter::HaProxy => {
                if !matches!(self.endpoint()?, WorkloadEndpoint::Unix(_)) {
                    anyhow::bail!("HAProxy workload connections require a Unix endpoint");
                }
                if self.username.is_some()
                    || self.secret_ref.is_some()
                    || self.database.is_some()
                    || self.auth_source.is_some()
                {
                    anyhow::bail!(
                        "HAProxy workload connections do not support configuration fields"
                    );
                }
            }
            WorkloadAdapter::Redis | WorkloadAdapter::Memcached if self.database.is_some() => {
                anyhow::bail!("Redis and Memcached workload connections do not support database");
            }
            _ => {}
        }
        if adapter == WorkloadAdapter::Memcached
            && (self.username.is_some() || self.secret_ref.is_some())
        {
            anyhow::bail!("Memcached workload connections do not support username or secret_ref");
        }
        Ok(())
    }

    pub fn endpoint(&self) -> Result<WorkloadEndpoint> {
        if self.endpoint.is_empty()
            || self.endpoint.contains('@')
            || self.endpoint.contains('?')
            || self.endpoint.contains('#')
            || self.endpoint.chars().any(char::is_whitespace)
        {
            anyhow::bail!("workload endpoint is invalid");
        }
        let (scheme, target) = self.endpoint.split_once("://").ok_or_else(|| {
            anyhow::anyhow!("workload endpoint must use unix://, tcp://, or tls://")
        })?;
        match scheme {
            "unix" => {
                let path = PathBuf::from(target);
                if !path.is_absolute() || target.is_empty() {
                    anyhow::bail!("unix workload endpoint must have an absolute path");
                }
                Ok(WorkloadEndpoint::Unix(path))
            }
            "tcp" | "tls" => {
                let (host, port) = parse_host_port(target)?;
                if scheme == "tcp" {
                    Ok(WorkloadEndpoint::Tcp { host, port })
                } else {
                    ServerName::try_from(host.clone())
                        .map_err(|_| anyhow::anyhow!("TLS workload endpoint host is invalid"))?;
                    Ok(WorkloadEndpoint::Tls { host, port })
                }
            }
            _ => anyhow::bail!("workload endpoint must use unix://, tcp://, or tls://"),
        }
    }
}

impl<'de> Deserialize<'de> for WorkloadConnectionConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            endpoint: String,
            #[serde(default)]
            username: Option<String>,
            #[serde(default)]
            secret_ref: Option<String>,
            #[serde(default)]
            database: Option<String>,
            #[serde(default)]
            auth_source: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let config = Self {
            endpoint: wire.endpoint,
            username: wire.username,
            secret_ref: wire.secret_ref,
            database: wire.database,
            auth_source: wire.auth_source,
        };
        config.endpoint().map_err(serde::de::Error::custom)?;
        if config.username.as_deref().is_some_and(str::is_empty) {
            return Err(serde::de::Error::custom(
                "workload username must not be empty",
            ));
        }
        if config.database.as_deref().is_some_and(str::is_empty) {
            return Err(serde::de::Error::custom(
                "workload database must not be empty",
            ));
        }
        if config.auth_source.as_deref().is_some_and(str::is_empty) {
            return Err(serde::de::Error::custom(
                "workload auth_source must not be empty",
            ));
        }
        if let Some(secret_ref) = &config.secret_ref {
            crate::secret::parse_secret_reference(secret_ref).map_err(serde::de::Error::custom)?;
        }
        Ok(config)
    }
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("IPv6 workload endpoint must use [address]:port"))?;
        if host.is_empty() || host.parse::<std::net::Ipv6Addr>().is_err() {
            anyhow::bail!("TCP workload endpoint host is invalid");
        }
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("TCP workload endpoint must include host and port"))?;
        if host.is_empty() || host.contains('/') || host.contains(':') {
            anyhow::bail!("TCP workload endpoint host is invalid");
        }
        (host, port)
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("TCP workload endpoint port is invalid"))?;
    if port == 0 {
        anyhow::bail!("TCP workload endpoint port is invalid");
    }
    Ok((host.to_string(), port))
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
#[serde(deny_unknown_fields)]
pub struct RedisMetrics {
    pub connected_clients: u64,
    pub used_memory: u64,
    pub total_commands_processed: u64,
    pub instantaneous_ops_per_sec: u64,
    pub keyspace_hits: u64,
    pub keyspace_misses: u64,
}

/// Numeric metrics returned by one bounded Memcached `stats` probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemcachedMetrics {
    pub curr_connections: u64,
    pub bytes: u64,
    pub cmd_get: u64,
    pub cmd_set: u64,
    pub get_hits: u64,
    pub get_misses: u64,
    pub evictions: u64,
}

/// Numeric metrics returned by one bounded PostgreSQL `pg_stat_database` probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgreSqlMetrics {
    pub numbackends: u64,
    pub xact_commit: u64,
    pub xact_rollback: u64,
    pub blks_read: u64,
    pub blks_hit: u64,
    pub tup_returned: u64,
    pub tup_fetched: u64,
    pub tup_inserted: u64,
    pub tup_updated: u64,
    pub tup_deleted: u64,
    pub conflicts: u64,
    pub temp_files: u64,
    pub temp_bytes: u64,
    pub deadlocks: u64,
}

/// Numeric metrics returned by one bounded MySQL `SHOW GLOBAL STATUS` probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MySqlMetrics {
    pub threads_connected: u64,
    pub threads_running: u64,
    pub connections: u64,
    pub aborted_connects: u64,
    pub questions: u64,
    pub slow_queries: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

/// Numeric metrics returned by one bounded MongoDB `serverStatus` probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MongoDbMetrics {
    pub connections_current: u64,
    pub connections_available: u64,
    pub connections_total_created: u64,
    pub opcounters_query: u64,
    pub opcounters_get_more: u64,
    pub opcounters_command: u64,
    pub network_bytes_in: u64,
    pub network_bytes_out: u64,
    pub network_num_requests: u64,
    pub uptime_seconds: u64,
}

/// Numeric metrics returned by one bounded Prometheus `/metrics` scrape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrometheusMetrics {
    pub config_last_reload_successful: u64,
    pub tsdb_head_series: u64,
    pub tsdb_head_chunks: u64,
    pub tsdb_head_samples_appended_total: u64,
    pub engine_queries: u64,
    pub process_resident_memory_bytes: u64,
    pub process_virtual_memory_bytes: u64,
    pub go_goroutines: u64,
}

/// Numeric metrics returned by one fixed ClickHouse system query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickHouseMetrics {
    pub queries: u64,
    pub merges: u64,
    pub part_mutations: u64,
    pub replicated_fetches: u64,
    pub replicated_sends: u64,
    pub tcp_connections: u64,
    pub http_connections: u64,
    pub memory_tracking_bytes: u64,
    pub uptime_seconds: u64,
    pub memory_resident_bytes: u64,
}

/// Numeric metrics returned by one bounded etcd `/metrics` scrape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtcdMetrics {
    pub server_has_leader: u64,
    pub server_is_leader: u64,
    pub leader_changes_seen_total: u64,
    pub proposals_applied_total: u64,
    pub proposals_committed_total: u64,
    pub proposals_failed_total: u64,
    pub proposals_pending: u64,
    pub mvcc_db_total_size_bytes: u64,
    pub mvcc_db_total_size_in_use_bytes: u64,
    pub process_resident_memory_bytes: u64,
}

macro_rules! search_metrics {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub nodes_total: u64,
            pub indices_count: u64,
            pub shards_total: u64,
            pub shards_primaries: u64,
            pub docs_count: u64,
            pub docs_deleted: u64,
            pub store_size_bytes: u64,
            pub fs_total_bytes: u64,
            pub fs_available_bytes: u64,
        }
    };
}
search_metrics!(ElasticsearchMetrics);
search_metrics!(OpenSearchMetrics);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RabbitMqMetrics {
    pub messages: u64,
    pub messages_ready: u64,
    pub messages_unacknowledged: u64,
    pub queues: u64,
    pub connections: u64,
    pub channels: u64,
    pub consumers: u64,
    pub exchanges: u64,
    pub message_stats_publish_total: u64,
    pub message_stats_deliver_get_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NginxMetrics {
    pub active_connections: u64,
    pub accepts_total: u64,
    pub handled_total: u64,
    pub requests_total: u64,
    pub reading: u64,
    pub writing: u64,
    pub waiting: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaProxyMetrics {
    pub current_sessions: u64,
    pub sessions_total: u64,
    pub bytes_in_total: u64,
    pub bytes_out_total: u64,
    pub denied_requests_total: u64,
    pub denied_responses_total: u64,
    pub failed_connections_total: u64,
    pub retry_warnings_total: u64,
    pub servers_down: u64,
}

/// Adapter-specific metrics in a common workload sample.
///
/// The untagged representation preserves the Redis metric JSON written by the first monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkloadMetrics {
    Redis(RedisMetrics),
    Memcached(MemcachedMetrics),
    PostgreSql(PostgreSqlMetrics),
    MySql(MySqlMetrics),
    MongoDb(MongoDbMetrics),
    Prometheus(PrometheusMetrics),
    ClickHouse(ClickHouseMetrics),
    Etcd(EtcdMetrics),
    Elasticsearch(ElasticsearchMetrics),
    OpenSearch(OpenSearchMetrics),
    RabbitMq(RabbitMqMetrics),
    Nginx(NginxMetrics),
    HaProxy(HaProxyMetrics),
}

/// Backward-compatible result of a one-shot Redis monitor probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisMonitorReport {
    pub candidate_id: String,
    pub monitor_ready: bool,
    pub metrics: RedisMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemcachedMonitorReport {
    pub candidate_id: String,
    pub adapter: WorkloadAdapter,
    pub monitor_ready: bool,
    pub metrics: MemcachedMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgreSqlMonitorReport {
    pub candidate_id: String,
    pub adapter: WorkloadAdapter,
    pub monitor_ready: bool,
    pub metrics: PostgreSqlMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MySqlMonitorReport {
    pub candidate_id: String,
    pub adapter: WorkloadAdapter,
    pub monitor_ready: bool,
    pub metrics: MySqlMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MongoDbMonitorReport {
    pub candidate_id: String,
    pub adapter: WorkloadAdapter,
    pub monitor_ready: bool,
    pub metrics: MongoDbMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrometheusMonitorReport {
    pub candidate_id: String,
    pub adapter: WorkloadAdapter,
    pub monitor_ready: bool,
    pub metrics: PrometheusMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickHouseMonitorReport {
    pub candidate_id: String,
    pub adapter: WorkloadAdapter,
    pub monitor_ready: bool,
    pub metrics: ClickHouseMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtcdMonitorReport {
    pub candidate_id: String,
    pub adapter: WorkloadAdapter,
    pub monitor_ready: bool,
    pub metrics: EtcdMetrics,
}

macro_rules! search_report {
    ($name:ident, $metrics:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name {
            pub candidate_id: String,
            pub adapter: WorkloadAdapter,
            pub monitor_ready: bool,
            pub metrics: $metrics,
        }
    };
}
search_report!(ElasticsearchMonitorReport, ElasticsearchMetrics);
search_report!(OpenSearchMonitorReport, OpenSearchMetrics);
search_report!(RabbitMqMonitorReport, RabbitMqMetrics);
search_report!(NginxMonitorReport, NginxMetrics);
search_report!(HaProxyMonitorReport, HaProxyMetrics);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkloadMonitorReport {
    Redis(RedisMonitorReport),
    Memcached(MemcachedMonitorReport),
    PostgreSql(PostgreSqlMonitorReport),
    MySql(MySqlMonitorReport),
    MongoDb(MongoDbMonitorReport),
    Prometheus(PrometheusMonitorReport),
    ClickHouse(ClickHouseMonitorReport),
    Etcd(EtcdMonitorReport),
    Elasticsearch(ElasticsearchMonitorReport),
    OpenSearch(OpenSearchMonitorReport),
    RabbitMq(RabbitMqMonitorReport),
    Nginx(NginxMonitorReport),
    HaProxy(HaProxyMonitorReport),
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
pub const MEMCACHED_STATS_REQUEST: &[u8] = b"stats\r\n";
pub const MEMCACHED_LOOPBACK_ENDPOINT: &str = "127.0.0.1:11211";
pub const POSTGRESQL_METRICS_QUERY: &str = "SELECT numbackends::bigint, xact_commit::bigint, xact_rollback::bigint, blks_read::bigint, blks_hit::bigint, tup_returned::bigint, tup_fetched::bigint, tup_inserted::bigint, tup_updated::bigint, tup_deleted::bigint, conflicts::bigint, temp_files::bigint, temp_bytes::bigint, deadlocks::bigint FROM pg_stat_database WHERE datname = current_database()";
pub const MYSQL_METRICS_QUERY: &str = "SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Threads_running','Connections','Aborted_connects','Questions','Slow_queries','Bytes_received','Bytes_sent')";
pub const MONGODB_RESPONSE_BYTES: usize = 64 * 1024;
pub const PROMETHEUS_LOOPBACK_ENDPOINT: &str = "127.0.0.1:9090";
pub const PROMETHEUS_RESPONSE_BYTES: usize = 1024 * 1024;
pub const CLICKHOUSE_LOOPBACK_ENDPOINT: &str = "127.0.0.1:8123";
pub const CLICKHOUSE_RESPONSE_BYTES: usize = 64 * 1024;
pub const CLICKHOUSE_METRICS_QUERY: &str = "SELECT metric, value FROM system.metrics WHERE metric IN ('Query','Merge','PartMutation','ReplicatedFetch','ReplicatedSend','TCPConnection','HTTPConnection','MemoryTracking') UNION ALL SELECT metric, value FROM system.asynchronous_metrics WHERE metric IN ('Uptime','MemoryResident') ORDER BY metric FORMAT TabSeparatedRaw";
pub const ETCD_LOOPBACK_ENDPOINT: &str = "127.0.0.1:2379";
pub const ETCD_RESPONSE_BYTES: usize = 64 * 1024;
pub const SEARCH_LOOPBACK_ENDPOINT: &str = "127.0.0.1:9200";
pub const SEARCH_RESPONSE_BYTES: usize = 64 * 1024;
pub const RABBITMQ_LOOPBACK_ENDPOINT: &str = "127.0.0.1:15672";
pub const RABBITMQ_RESPONSE_BYTES: usize = 64 * 1024;
pub const NGINX_RESPONSE_BYTES: usize = 16 * 1024;
pub const HAPROXY_RESPONSE_BYTES: usize = 256 * 1024;
pub const HAPROXY_STATS_COMMAND: &[u8] = b"show stat\n";
pub const DRIVER_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
pub const POSTGRESQL_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MYSQL_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MONGODB_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const PROMETHEUS_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const CLICKHOUSE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const ETCD_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const SEARCH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const RABBITMQ_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const NGINX_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const HAPROXY_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const REDIS_RESPONSE_BYTES: usize = 64 * 1024;
pub const MEMCACHED_RESPONSE_BYTES: usize = 64 * 1024;
pub const WORKLOAD_SAMPLE_SCHEMA_VERSION: u32 = 1;
pub const WORKLOAD_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
pub const REDIS_SAMPLE_INTERVAL: Duration = WORKLOAD_SAMPLE_INTERVAL;
pub const MAX_WORKLOAD_HISTORY_SAMPLES: usize = 1440;
pub const WORKLOAD_HISTORY_FILE: &str = "workload-history.jsonl";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadProbeError {
    Unreachable(String),
    Rejected(String),
    Malformed(String),
}

impl fmt::Display for WorkloadProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(detail) => write!(f, "workload endpoint is unavailable: {detail}"),
            Self::Rejected(detail) => write!(f, "workload rejected request: {detail}"),
            Self::Malformed(detail) => write!(f, "workload returned an invalid response: {detail}"),
        }
    }
}

impl std::error::Error for WorkloadProbeError {}

pub type RedisProbeError = WorkloadProbeError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadStore {
    #[serde(default)]
    pub workloads: Vec<WorkloadDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkloadSample {
    pub schema_version: u32,
    pub workload_id: String,
    pub captured_at: DateTime<Utc>,
    /// Missing in Stage 0 Redis samples. Those samples always describe Redis.
    #[serde(default = "default_redis_adapter")]
    pub adapter: WorkloadAdapter,
    #[serde(flatten)]
    pub outcome: WorkloadSampleOutcome,
}

fn default_redis_adapter() -> WorkloadAdapter {
    WorkloadAdapter::Redis
}

impl<'de> Deserialize<'de> for WorkloadSample {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireSample {
            schema_version: u32,
            workload_id: String,
            captured_at: DateTime<Utc>,
            #[serde(default = "default_redis_adapter")]
            adapter: WorkloadAdapter,
            #[serde(flatten)]
            outcome: WorkloadSampleOutcome,
        }

        let mut wire = WireSample::deserialize(deserializer)?;
        if let WorkloadSampleOutcome::Collected { metrics, .. } = &mut wire.outcome {
            if wire.adapter == WorkloadAdapter::OpenSearch {
                if let WorkloadMetrics::Elasticsearch(value) = metrics {
                    *metrics = WorkloadMetrics::OpenSearch(OpenSearchMetrics {
                        nodes_total: value.nodes_total,
                        indices_count: value.indices_count,
                        shards_total: value.shards_total,
                        shards_primaries: value.shards_primaries,
                        docs_count: value.docs_count,
                        docs_deleted: value.docs_deleted,
                        store_size_bytes: value.store_size_bytes,
                        fs_total_bytes: value.fs_total_bytes,
                        fs_available_bytes: value.fs_available_bytes,
                    });
                }
            }
            let matches = matches!(
                (wire.adapter, &*metrics),
                (WorkloadAdapter::Redis, WorkloadMetrics::Redis(_))
                    | (WorkloadAdapter::Memcached, WorkloadMetrics::Memcached(_))
                    | (WorkloadAdapter::PostgreSql, WorkloadMetrics::PostgreSql(_))
                    | (WorkloadAdapter::MySql, WorkloadMetrics::MySql(_))
                    | (WorkloadAdapter::MongoDb, WorkloadMetrics::MongoDb(_))
                    | (WorkloadAdapter::Prometheus, WorkloadMetrics::Prometheus(_))
                    | (WorkloadAdapter::ClickHouse, WorkloadMetrics::ClickHouse(_))
                    | (WorkloadAdapter::Etcd, WorkloadMetrics::Etcd(_))
                    | (
                        WorkloadAdapter::Elasticsearch,
                        WorkloadMetrics::Elasticsearch(_)
                    )
                    | (WorkloadAdapter::OpenSearch, WorkloadMetrics::OpenSearch(_))
                    | (WorkloadAdapter::RabbitMq, WorkloadMetrics::RabbitMq(_))
                    | (WorkloadAdapter::Nginx, WorkloadMetrics::Nginx(_))
                    | (WorkloadAdapter::HaProxy, WorkloadMetrics::HaProxy(_))
            );
            if !matches {
                return Err(serde::de::Error::custom(
                    "workload adapter does not match metric type",
                ));
            }
        }
        Ok(Self {
            schema_version: wire.schema_version,
            workload_id: wire.workload_id,
            captured_at: wire.captured_at,
            adapter: wire.adapter,
            outcome: wire.outcome,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WorkloadSampleOutcome {
    Collected {
        endpoint: String,
        metrics: WorkloadMetrics,
    },
    Failed {
        reason: WorkloadSampleFailure,
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadSampleFailure {
    Unreachable,
    Rejected,
    Malformed,
}

pub type RedisWorkloadSample = WorkloadSample;
pub type RedisSampleOutcome = WorkloadSampleOutcome;
pub type RedisSampleFailure = WorkloadSampleFailure;

pub fn workloads_file_path() -> PathBuf {
    paths::config_file_path().with_file_name("workloads.toml")
}

pub fn workload_history_path() -> PathBuf {
    paths::state_dir().join(WORKLOAD_HISTORY_FILE)
}

pub fn load_workload_history(path: &Path) -> Result<Vec<WorkloadSample>> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut samples = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect::<Vec<WorkloadSample>>();
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

/// Collect Redis metrics from an optional explicit connection. A missing connection preserves the
/// fixed local endpoint selection used by older workload records.
pub fn monitor_redis_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, RedisMetrics), RedisProbeError> {
    let Some(connection) = connection else {
        return monitor_redis();
    };
    connection
        .validate_for(WorkloadAdapter::Redis)
        .map_err(|_| {
            RedisProbeError::Malformed("Redis connection configuration is invalid".into())
        })?;
    let secret = resolve_connection_secret(connection)?;
    match connection
        .endpoint()
        .map_err(|_| RedisProbeError::Malformed("Redis endpoint is invalid".into()))?
    {
        #[cfg(unix)]
        WorkloadEndpoint::Unix(path) => {
            let mut stream = UnixStream::connect(&path).map_err(unreachable)?;
            set_timeouts(&stream)?;
            monitor_redis_authenticated_stream(
                &mut stream,
                connection.username.as_deref(),
                secret.as_deref(),
            )
            .map(|metrics| (connection.endpoint.clone(), metrics))
        }
        #[cfg(not(unix))]
        WorkloadEndpoint::Unix(_) => Err(RedisProbeError::Unreachable(
            "Unix sockets are unavailable".into(),
        )),
        WorkloadEndpoint::Tcp { host, port } => {
            let mut stream = connect_tcp(&host, port)?;
            monitor_redis_authenticated_stream(
                &mut stream,
                connection.username.as_deref(),
                secret.as_deref(),
            )
            .map(|metrics| (connection.endpoint.clone(), metrics))
        }
        WorkloadEndpoint::Tls { host, port } => {
            let stream = connect_tcp(&host, port)?;
            let mut stream = tls_stream(stream, &host)?;
            monitor_redis_authenticated_stream(
                &mut stream,
                connection.username.as_deref(),
                secret.as_deref(),
            )
            .map(|metrics| (connection.endpoint.clone(), metrics))
        }
    }
}

/// Run a Redis custom connection through an injected connector.
///
/// This keeps endpoint selection testable without opening a network connection.
pub fn monitor_redis_with_connector<S>(
    connection: &WorkloadConnectionConfig,
    connector: impl FnOnce(&WorkloadEndpoint) -> std::result::Result<S, WorkloadProbeError>,
) -> std::result::Result<RedisMetrics, RedisProbeError>
where
    S: Read + Write,
{
    connection
        .validate_for(WorkloadAdapter::Redis)
        .map_err(|_| {
            RedisProbeError::Malformed("Redis connection configuration is invalid".into())
        })?;
    let endpoint = connection
        .endpoint()
        .map_err(|_| RedisProbeError::Malformed("Redis endpoint is invalid".into()))?;
    let secret = resolve_connection_secret(connection)?;
    let mut stream = connector(&endpoint)?;
    monitor_redis_authenticated_stream(
        &mut stream,
        connection.username.as_deref(),
        secret.as_deref(),
    )
}

/// Collect one bounded Memcached `stats` response from the fixed loopback endpoint.
pub fn monitor_memcached() -> std::result::Result<(String, MemcachedMetrics), WorkloadProbeError> {
    let endpoint: SocketAddr = MEMCACHED_LOOPBACK_ENDPOINT
        .parse()
        .expect("valid Memcached endpoint");
    monitor_memcached_tcp(endpoint)
        .map(|metrics| (MEMCACHED_LOOPBACK_ENDPOINT.to_string(), metrics))
}

/// Collect Memcached metrics from an optional explicit connection. Memcached connections reject
/// authentication fields during validation.
pub fn monitor_memcached_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, MemcachedMetrics), WorkloadProbeError> {
    let Some(connection) = connection else {
        return monitor_memcached();
    };
    connection
        .validate_for(WorkloadAdapter::Memcached)
        .map_err(|_| {
            WorkloadProbeError::Malformed("Memcached connection configuration is invalid".into())
        })?;
    match connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("Memcached endpoint is invalid".into()))?
    {
        #[cfg(unix)]
        WorkloadEndpoint::Unix(path) => {
            let mut stream = UnixStream::connect(&path).map_err(unreachable)?;
            set_timeouts(&stream)?;
            monitor_memcached_stream(&mut stream)
                .map(|metrics| (connection.endpoint.clone(), metrics))
        }
        #[cfg(not(unix))]
        WorkloadEndpoint::Unix(_) => Err(WorkloadProbeError::Unreachable(
            "Unix sockets are unavailable".into(),
        )),
        WorkloadEndpoint::Tcp { host, port } => {
            let mut stream = connect_tcp(&host, port)?;
            monitor_memcached_stream(&mut stream)
                .map(|metrics| (connection.endpoint.clone(), metrics))
        }
        WorkloadEndpoint::Tls { host, port } => {
            let stream = connect_tcp(&host, port)?;
            let mut stream = tls_stream(stream, &host)?;
            monitor_memcached_stream(&mut stream)
                .map(|metrics| (connection.endpoint.clone(), metrics))
        }
    }
}

/// Collect one bounded `pg_stat_database` row from an explicit PostgreSQL connection.
pub fn monitor_postgresql_with_connection(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<(String, PostgreSqlMetrics), WorkloadProbeError> {
    connection
        .validate_for(WorkloadAdapter::PostgreSql)
        .map_err(|_| {
            WorkloadProbeError::Malformed("PostgreSQL connection configuration is invalid".into())
        })?;
    let endpoint = connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("PostgreSQL endpoint is invalid".into()))?;
    let secret = resolve_connection_secret(connection).map_err(|_| {
        WorkloadProbeError::Rejected("PostgreSQL authentication secret is unavailable".into())
    })?;
    let username = connection
        .username
        .as_deref()
        .ok_or_else(|| WorkloadProbeError::Malformed("PostgreSQL username is missing".into()))?;
    let database = connection
        .database
        .as_deref()
        .ok_or_else(|| WorkloadProbeError::Malformed("PostgreSQL database is missing".into()))?;
    let (host, port, use_tls) = match endpoint {
        WorkloadEndpoint::Tcp { host, port } => (host, port, false),
        WorkloadEndpoint::Tls { host, port } => (host, port, true),
        WorkloadEndpoint::Unix(_) => {
            return Err(WorkloadProbeError::Malformed(
                "PostgreSQL endpoint must use TCP or TLS".into(),
            ));
        }
    };

    let username = username.to_owned();
    let database = database.to_owned();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("PostgreSQL probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(
                POSTGRESQL_PROBE_TIMEOUT,
                monitor_postgresql_async(
                    &host,
                    port,
                    use_tls,
                    &username,
                    &database,
                    secret.as_deref(),
                ),
            )
            .await
            .map_err(|_| WorkloadProbeError::Unreachable("PostgreSQL probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("PostgreSQL probe runtime failed".into()))??;
    Ok((connection.endpoint.clone(), metrics))
}

async fn monitor_postgresql_async(
    host: &str,
    port: u16,
    use_tls: bool,
    username: &str,
    database: &str,
    password: Option<&str>,
) -> std::result::Result<PostgreSqlMetrics, WorkloadProbeError> {
    let mut config = PostgreSqlConfig::new();
    config
        .host(host)
        .port(port)
        .user(username)
        .dbname(database)
        .application_name("aic-workload-monitor")
        .connect_timeout(DRIVER_CONNECT_TIMEOUT)
        .options(
            "-c default_transaction_read_only=on -c statement_timeout=1000 -c lock_timeout=200",
        );
    if let Some(password) = password {
        config.password(password);
    }

    let client = if use_tls {
        config.ssl_mode(SslMode::Require);
        let connector = MakeRustlsConnect::new(tls_client_config()?);
        let (client, connection) = config
            .connect(connector)
            .await
            .map_err(map_postgresql_connect_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    } else {
        config.ssl_mode(SslMode::Disable);
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(map_postgresql_connect_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    };
    let rows = client
        .query(POSTGRESQL_METRICS_QUERY, &[])
        .await
        .map_err(|_| WorkloadProbeError::Rejected("PostgreSQL rejected metrics query".into()))?;
    postgresql_metrics_from_rows(&rows)
}

fn map_postgresql_connect_error(error: tokio_postgres::Error) -> WorkloadProbeError {
    if error.as_db_error().is_some() {
        WorkloadProbeError::Rejected("PostgreSQL rejected connection".into())
    } else {
        WorkloadProbeError::Unreachable("PostgreSQL endpoint is unavailable".into())
    }
}

/// Collect one bounded, fixed `SHOW GLOBAL STATUS` result from an explicit MySQL connection.
pub fn monitor_mysql_with_connection(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<(String, MySqlMetrics), WorkloadProbeError> {
    connection
        .validate_for(WorkloadAdapter::MySql)
        .map_err(|_| {
            WorkloadProbeError::Malformed("MySQL connection configuration is invalid".into())
        })?;
    let endpoint = connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("MySQL endpoint is invalid".into()))?;
    let secret = resolve_connection_secret(connection).map_err(|_| {
        WorkloadProbeError::Rejected("MySQL authentication secret is unavailable".into())
    })?;
    let username = connection
        .username
        .as_deref()
        .ok_or_else(|| WorkloadProbeError::Malformed("MySQL username is missing".into()))?;
    let (host, port, use_tls) = match endpoint {
        WorkloadEndpoint::Tcp { host, port } => (host, port, false),
        WorkloadEndpoint::Tls { host, port } => (host, port, true),
        WorkloadEndpoint::Unix(_) => {
            return Err(WorkloadProbeError::Malformed(
                "MySQL endpoint must use TCP or TLS".into(),
            ));
        }
    };

    let username = username.to_owned();
    let database = connection.database.clone();
    let endpoint_text = connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("MySQL probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(
                MYSQL_PROBE_TIMEOUT,
                monitor_mysql_async(
                    &host,
                    port,
                    use_tls,
                    &username,
                    secret.as_deref(),
                    database.as_deref(),
                ),
            )
            .await
            .map_err(|_| WorkloadProbeError::Unreachable("MySQL probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("MySQL probe runtime failed".into()))??;
    Ok((endpoint_text, metrics))
}

async fn monitor_mysql_async(
    host: &str,
    port: u16,
    use_tls: bool,
    username: &str,
    password: Option<&str>,
    database: Option<&str>,
) -> std::result::Result<MySqlMetrics, WorkloadProbeError> {
    let options = mysql_connection_options(host, port, use_tls, username, password, database)?;
    let mut connection = MySqlConnection::new(options)
        .await
        .map_err(map_mysql_connect_error)?;
    let rows: Vec<(String, String)> = connection
        .query(MYSQL_METRICS_QUERY)
        .await
        .map_err(|_| WorkloadProbeError::Rejected("MySQL rejected metrics query".into()))?;
    let metrics = mysql_metrics_from_rows(&rows);
    let _ = connection.disconnect().await;
    metrics
}

fn mysql_connection_options(
    host: &str,
    port: u16,
    use_tls: bool,
    username: &str,
    password: Option<&str>,
    database: Option<&str>,
) -> std::result::Result<MySqlOptsBuilder, WorkloadProbeError> {
    let mut options = MySqlOptsBuilder::default()
        .ip_or_hostname(host)
        .tcp_port(port)
        .user(Some(username))
        .pass(password)
        .db_name(database)
        .prefer_socket(false)
        .stmt_cache_size(0);
    if use_tls {
        options = options.ssl_opts(Some(mysql_ssl_options()?));
    }
    Ok(options)
}

fn mysql_ssl_options() -> std::result::Result<SslOpts, WorkloadProbeError> {
    let certificates = rustls_native_certs::load_native_certs();
    if !certificates.errors.is_empty() {
        tracing::debug!(
            invalid_native_roots = certificates.errors.len(),
            "some native TLS roots could not be loaded for MySQL"
        );
    }
    if certificates.certs.is_empty() {
        return Err(WorkloadProbeError::Unreachable(
            "native TLS roots are unavailable".into(),
        ));
    }
    Ok(SslOpts::default()
        .with_root_certs(
            certificates
                .certs
                .into_iter()
                .map(|certificate| certificate.as_ref().to_vec().into())
                .collect(),
        )
        .with_disable_built_in_roots(true))
}

fn map_mysql_connect_error(error: mysql_async::Error) -> WorkloadProbeError {
    if matches!(error, mysql_async::Error::Server(_)) {
        WorkloadProbeError::Rejected("MySQL rejected connection".into())
    } else {
        WorkloadProbeError::Unreachable("MySQL endpoint is unavailable".into())
    }
}

fn mysql_metrics_from_rows(
    rows: &[(String, String)],
) -> std::result::Result<MySqlMetrics, WorkloadProbeError> {
    const KEYS: [&str; 8] = [
        "Threads_connected",
        "Threads_running",
        "Connections",
        "Aborted_connects",
        "Questions",
        "Slow_queries",
        "Bytes_received",
        "Bytes_sent",
    ];
    if rows.len() != KEYS.len() {
        return Err(WorkloadProbeError::Malformed(
            "MySQL metrics have an invalid row count".into(),
        ));
    }
    let mut values = BTreeMap::new();
    for (key, value) in rows {
        if !KEYS.contains(&key.as_str()) || values.insert(key.as_str(), value.as_str()).is_some() {
            return Err(WorkloadProbeError::Malformed(
                "MySQL metrics contain an unknown or duplicate metric".into(),
            ));
        }
    }
    let metric = |key| {
        values
            .get(key)
            .ok_or_else(|| {
                WorkloadProbeError::Malformed(format!("MySQL metrics are missing {key}"))
            })?
            .parse::<u64>()
            .map_err(|_| WorkloadProbeError::Malformed(format!("MySQL metric is not a u64: {key}")))
    };
    Ok(MySqlMetrics {
        threads_connected: metric("Threads_connected")?,
        threads_running: metric("Threads_running")?,
        connections: metric("Connections")?,
        aborted_connects: metric("Aborted_connects")?,
        questions: metric("Questions")?,
        slow_queries: metric("Slow_queries")?,
        bytes_received: metric("Bytes_received")?,
        bytes_sent: metric("Bytes_sent")?,
    })
}

/// Collect fixed read-only server metrics from an explicit MongoDB connection.
pub fn monitor_mongodb_with_connection(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<(String, MongoDbMetrics), WorkloadProbeError> {
    connection
        .validate_for(WorkloadAdapter::MongoDb)
        .map_err(|_| {
            WorkloadProbeError::Malformed("MongoDB connection configuration is invalid".into())
        })?;
    let endpoint = connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("MongoDB endpoint is invalid".into()))?;
    let secret = resolve_connection_secret(connection).map_err(|_| {
        WorkloadProbeError::Rejected("MongoDB authentication secret is unavailable".into())
    })?;
    let (host, port, use_tls) = match endpoint {
        WorkloadEndpoint::Tcp { host, port } => (host, port, false),
        WorkloadEndpoint::Tls { host, port } => (host, port, true),
        WorkloadEndpoint::Unix(_) => {
            return Err(WorkloadProbeError::Malformed(
                "MongoDB endpoint must use TCP or TLS".into(),
            ));
        }
    };
    let username = connection.username.clone();
    let auth_source = connection
        .auth_source
        .clone()
        .unwrap_or_else(|| "admin".into());
    let endpoint_text = connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("MongoDB probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(
                MONGODB_PROBE_TIMEOUT,
                monitor_mongodb_async(
                    &host,
                    port,
                    use_tls,
                    username.as_deref(),
                    secret.as_deref(),
                    &auth_source,
                ),
            )
            .await
            .map_err(|_| WorkloadProbeError::Unreachable("MongoDB probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("MongoDB probe runtime failed".into()))??;
    Ok((endpoint_text, metrics))
}

async fn monitor_mongodb_async(
    host: &str,
    port: u16,
    use_tls: bool,
    username: Option<&str>,
    password: Option<&str>,
    auth_source: &str,
) -> std::result::Result<MongoDbMetrics, WorkloadProbeError> {
    let credential = username.map(|username| {
        Credential::builder()
            .username(Some(username.to_owned()))
            .password(password.map(str::to_owned))
            .source(Some(auth_source.to_owned()))
            .build()
    });
    let tls = if use_tls {
        Some(Tls::Enabled(
            TlsOptions::builder()
                .allow_invalid_certificates(Some(false))
                .allow_invalid_hostnames(Some(false))
                .build(),
        ))
    } else {
        Some(Tls::Disabled)
    };
    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: host.to_owned(),
            port: Some(port),
        }])
        .app_name(Some("aic-workload-monitor".into()))
        .credential(credential)
        .direct_connection(Some(true))
        .connect_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .server_selection_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .min_pool_size(Some(0))
        .max_pool_size(Some(1))
        .max_connecting(Some(1))
        .retry_reads(Some(false))
        .retry_writes(Some(false))
        .tls(tls)
        .build();
    let client = MongoDbClient::with_options(options).map_err(map_mongodb_connect_error)?;
    let response = client
        .database("admin")
        .run_command(doc! {
            "serverStatus": 1,
            "repl": 0,
            "metrics": 0,
            "locks": 0,
            "wiredTiger": 0,
            "tcmalloc": 0,
        })
        .await
        .map_err(|_| WorkloadProbeError::Rejected("MongoDB rejected metrics query".into()))?;
    let metrics = mongodb_metrics_from_document(&response);
    client.shutdown().immediate(true).await;
    metrics
}

fn map_mongodb_connect_error(_: mongodb::error::Error) -> WorkloadProbeError {
    WorkloadProbeError::Unreachable("MongoDB endpoint is unavailable".into())
}

fn mongodb_metrics_from_document(
    response: &Document,
) -> std::result::Result<MongoDbMetrics, WorkloadProbeError> {
    let encoded = mongodb::bson::to_vec(response).map_err(|_| {
        WorkloadProbeError::Malformed("MongoDB response could not be encoded".into())
    })?;
    if encoded.len() > MONGODB_RESPONSE_BYTES {
        return Err(WorkloadProbeError::Malformed(
            "MongoDB response exceeds the size limit".into(),
        ));
    }
    let section = |name| {
        response.get_document(name).map_err(|_| {
            WorkloadProbeError::Malformed(format!("MongoDB response is missing {name}"))
        })
    };
    let metric = |document: &Document, key: &str| {
        let value = match document.get(key) {
            Some(Bson::Int32(value)) if *value >= 0 => *value as u64,
            Some(Bson::Int64(value)) if *value >= 0 => *value as u64,
            _ => {
                return Err(WorkloadProbeError::Malformed(format!(
                    "MongoDB metric is missing, negative, or not an integer: {key}"
                )))
            }
        };
        Ok(value)
    };
    let connections = section("connections")?;
    let opcounters = section("opcounters")?;
    let network = section("network")?;
    Ok(MongoDbMetrics {
        connections_current: metric(connections, "current")?,
        connections_available: metric(connections, "available")?,
        connections_total_created: metric(connections, "totalCreated")?,
        opcounters_query: metric(opcounters, "query")?,
        opcounters_get_more: metric(opcounters, "getmore")?,
        opcounters_command: metric(opcounters, "command")?,
        network_bytes_in: metric(network, "bytesIn")?,
        network_bytes_out: metric(network, "bytesOut")?,
        network_num_requests: metric(network, "numRequests")?,
        uptime_seconds: metric(response, "uptime")?,
    })
}

/// Scrape one bounded Prometheus `/metrics` endpoint.
pub fn monitor_prometheus_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, PrometheusMetrics), WorkloadProbeError> {
    let owned_connection = connection.cloned().unwrap_or(WorkloadConnectionConfig {
        endpoint: format!("tcp://{PROMETHEUS_LOOPBACK_ENDPOINT}"),
        username: None,
        secret_ref: None,
        database: None,
        auth_source: None,
    });
    owned_connection
        .validate_for(WorkloadAdapter::Prometheus)
        .map_err(|_| {
            WorkloadProbeError::Malformed("Prometheus connection configuration is invalid".into())
        })?;
    let url = prometheus_metrics_url(&owned_connection)?;
    let endpoint = owned_connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("Prometheus probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(PROMETHEUS_PROBE_TIMEOUT, monitor_prometheus_async(&url))
                .await
                .map_err(|_| WorkloadProbeError::Unreachable("Prometheus probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("Prometheus probe runtime failed".into()))??;
    Ok((endpoint, metrics))
}

fn prometheus_metrics_url(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<String, WorkloadProbeError> {
    match connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("Prometheus endpoint is invalid".into()))?
    {
        WorkloadEndpoint::Tcp { host, port } => {
            Ok(format!("http://{}:{port}/metrics", url_host(&host)))
        }
        WorkloadEndpoint::Tls { host, port } => {
            Ok(format!("https://{}:{port}/metrics", url_host(&host)))
        }
        WorkloadEndpoint::Unix(_) => Err(WorkloadProbeError::Malformed(
            "Prometheus endpoint must use TCP or TLS".into(),
        )),
    }
}

fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

async fn monitor_prometheus_async(
    url: &str,
) -> std::result::Result<PrometheusMetrics, WorkloadProbeError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(DRIVER_CONNECT_TIMEOUT)
        .timeout(PROMETHEUS_PROBE_TIMEOUT)
        .build()
        .map_err(|_| {
            WorkloadProbeError::Unreachable("Prometheus HTTP client is unavailable".into())
        })?;
    let mut response = client.get(url).send().await.map_err(|_| {
        WorkloadProbeError::Unreachable("Prometheus endpoint is unavailable".into())
    })?;
    if !response.status().is_success() {
        return Err(WorkloadProbeError::Rejected(
            "Prometheus rejected metrics request".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > PROMETHEUS_RESPONSE_BYTES as u64)
    {
        return Err(WorkloadProbeError::Malformed(
            "Prometheus response exceeds the size limit".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        WorkloadProbeError::Unreachable("Prometheus response could not be read".into())
    })? {
        if body.len().saturating_add(chunk.len()) > PROMETHEUS_RESPONSE_BYTES {
            return Err(WorkloadProbeError::Malformed(
                "Prometheus response exceeds the size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| WorkloadProbeError::Malformed("Prometheus response is not UTF-8".into()))?;
    parse_prometheus_metrics(body)
}

fn parse_prometheus_metrics(
    body: &str,
) -> std::result::Result<PrometheusMetrics, WorkloadProbeError> {
    const REQUIRED: [&str; 8] = [
        "prometheus_config_last_reload_successful",
        "prometheus_tsdb_head_series",
        "prometheus_tsdb_head_chunks",
        "prometheus_tsdb_head_samples_appended_total",
        "prometheus_engine_queries",
        "process_resident_memory_bytes",
        "process_virtual_memory_bytes",
        "go_goroutines",
    ];
    let mut values = BTreeMap::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name_end = line
            .find(|character: char| character == '{' || character.is_ascii_whitespace())
            .unwrap_or(line.len());
        let name = &line[..name_end];
        if !REQUIRED.contains(&name) {
            continue;
        }
        if line[name_end..].starts_with('{') {
            return Err(WorkloadProbeError::Malformed(format!(
                "Prometheus required metric contains labels: {name}"
            )));
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 || values.contains_key(name) {
            return Err(WorkloadProbeError::Malformed(format!(
                "Prometheus required metric is duplicate or malformed: {name}"
            )));
        }
        let value = parse_prometheus_u64(fields[1], name)?;
        values.insert(name, value);
    }
    let mut take = |name| {
        values.remove(name).ok_or_else(|| {
            WorkloadProbeError::Malformed(format!("Prometheus response is missing {name}"))
        })
    };
    Ok(PrometheusMetrics {
        config_last_reload_successful: take("prometheus_config_last_reload_successful")?,
        tsdb_head_series: take("prometheus_tsdb_head_series")?,
        tsdb_head_chunks: take("prometheus_tsdb_head_chunks")?,
        tsdb_head_samples_appended_total: take("prometheus_tsdb_head_samples_appended_total")?,
        engine_queries: take("prometheus_engine_queries")?,
        process_resident_memory_bytes: take("process_resident_memory_bytes")?,
        process_virtual_memory_bytes: take("process_virtual_memory_bytes")?,
        go_goroutines: take("go_goroutines")?,
    })
}

fn parse_prometheus_u64(value: &str, name: &str) -> std::result::Result<u64, WorkloadProbeError> {
    parse_exposition_u64(value).map_err(|_| {
        WorkloadProbeError::Malformed(format!("Prometheus metric is not a u64: {name}"))
    })
}

/// Run one fixed read-only ClickHouse system query over HTTP.
pub fn monitor_clickhouse_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, ClickHouseMetrics), WorkloadProbeError> {
    let owned_connection = connection.cloned().unwrap_or(WorkloadConnectionConfig {
        endpoint: format!("tcp://{CLICKHOUSE_LOOPBACK_ENDPOINT}"),
        username: None,
        secret_ref: None,
        database: None,
        auth_source: None,
    });
    owned_connection
        .validate_for(WorkloadAdapter::ClickHouse)
        .map_err(|_| {
            WorkloadProbeError::Malformed("ClickHouse connection configuration is invalid".into())
        })?;
    let url = clickhouse_http_url(&owned_connection)?;
    let secret = resolve_connection_secret(&owned_connection).map_err(|_| {
        WorkloadProbeError::Rejected("ClickHouse authentication secret is unavailable".into())
    })?;
    let username = owned_connection.username.clone();
    let endpoint = owned_connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("ClickHouse probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(
                CLICKHOUSE_PROBE_TIMEOUT,
                monitor_clickhouse_async(&url, username.as_deref(), secret.as_deref()),
            )
            .await
            .map_err(|_| WorkloadProbeError::Unreachable("ClickHouse probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("ClickHouse probe runtime failed".into()))??;
    Ok((endpoint, metrics))
}

fn clickhouse_http_url(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<String, WorkloadProbeError> {
    match connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("ClickHouse endpoint is invalid".into()))?
    {
        WorkloadEndpoint::Tcp { host, port } => Ok(format!("http://{}:{port}/", url_host(&host))),
        WorkloadEndpoint::Tls { host, port } => Ok(format!("https://{}:{port}/", url_host(&host))),
        WorkloadEndpoint::Unix(_) => Err(WorkloadProbeError::Malformed(
            "ClickHouse endpoint must use TCP or TLS".into(),
        )),
    }
}

async fn monitor_clickhouse_async(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> std::result::Result<ClickHouseMetrics, WorkloadProbeError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(DRIVER_CONNECT_TIMEOUT)
        .timeout(CLICKHOUSE_PROBE_TIMEOUT)
        .build()
        .map_err(|_| {
            WorkloadProbeError::Unreachable("ClickHouse HTTP client is unavailable".into())
        })?;
    let mut request = client.post(url).body(CLICKHOUSE_METRICS_QUERY);
    if let Some(username) = username {
        request = request.basic_auth(username, password);
    }
    let mut response = request.send().await.map_err(|_| {
        WorkloadProbeError::Unreachable("ClickHouse endpoint is unavailable".into())
    })?;
    if !response.status().is_success() {
        return Err(WorkloadProbeError::Rejected(
            "ClickHouse rejected metrics query".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > CLICKHOUSE_RESPONSE_BYTES as u64)
    {
        return Err(WorkloadProbeError::Malformed(
            "ClickHouse response exceeds the size limit".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        WorkloadProbeError::Unreachable("ClickHouse response could not be read".into())
    })? {
        if body.len().saturating_add(chunk.len()) > CLICKHOUSE_RESPONSE_BYTES {
            return Err(WorkloadProbeError::Malformed(
                "ClickHouse response exceeds the size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| WorkloadProbeError::Malformed("ClickHouse response is not UTF-8".into()))?;
    parse_clickhouse_metrics(body)
}

fn parse_clickhouse_metrics(
    body: &str,
) -> std::result::Result<ClickHouseMetrics, WorkloadProbeError> {
    const REQUIRED: [&str; 10] = [
        "Query",
        "Merge",
        "PartMutation",
        "ReplicatedFetch",
        "ReplicatedSend",
        "TCPConnection",
        "HTTPConnection",
        "MemoryTracking",
        "Uptime",
        "MemoryResident",
    ];
    let mut values = BTreeMap::new();
    for line in body.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let name = fields.next().unwrap_or_default();
        let value = fields.next().ok_or_else(|| {
            WorkloadProbeError::Malformed("ClickHouse metrics row is malformed".into())
        })?;
        if fields.next().is_some()
            || !REQUIRED.contains(&name)
            || values
                .insert(name, parse_clickhouse_u64(value, name)?)
                .is_some()
        {
            return Err(WorkloadProbeError::Malformed(
                "ClickHouse metrics contain an unknown, duplicate, or malformed row".into(),
            ));
        }
    }
    if values.len() != REQUIRED.len() {
        return Err(WorkloadProbeError::Malformed(
            "ClickHouse metrics are incomplete".into(),
        ));
    }
    let mut take = |name| {
        values.remove(name).ok_or_else(|| {
            WorkloadProbeError::Malformed(format!("ClickHouse response is missing {name}"))
        })
    };
    Ok(ClickHouseMetrics {
        queries: take("Query")?,
        merges: take("Merge")?,
        part_mutations: take("PartMutation")?,
        replicated_fetches: take("ReplicatedFetch")?,
        replicated_sends: take("ReplicatedSend")?,
        tcp_connections: take("TCPConnection")?,
        http_connections: take("HTTPConnection")?,
        memory_tracking_bytes: take("MemoryTracking")?,
        uptime_seconds: take("Uptime")?,
        memory_resident_bytes: take("MemoryResident")?,
    })
}

fn parse_clickhouse_u64(value: &str, name: &str) -> std::result::Result<u64, WorkloadProbeError> {
    value.parse::<u64>().map_err(|_| {
        WorkloadProbeError::Malformed(format!("ClickHouse metric is not a u64: {name}"))
    })
}

/// Scrape one bounded etcd `/metrics` endpoint.
pub fn monitor_etcd_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, EtcdMetrics), WorkloadProbeError> {
    let owned_connection = connection.cloned().unwrap_or(WorkloadConnectionConfig {
        endpoint: format!("tcp://{ETCD_LOOPBACK_ENDPOINT}"),
        username: None,
        secret_ref: None,
        database: None,
        auth_source: None,
    });
    owned_connection
        .validate_for(WorkloadAdapter::Etcd)
        .map_err(|_| {
            WorkloadProbeError::Malformed("etcd connection configuration is invalid".into())
        })?;
    let url = etcd_metrics_url(&owned_connection)?;
    let endpoint = owned_connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("etcd probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(ETCD_PROBE_TIMEOUT, monitor_etcd_async(&url))
                .await
                .map_err(|_| WorkloadProbeError::Unreachable("etcd probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("etcd probe runtime failed".into()))??;
    Ok((endpoint, metrics))
}

fn etcd_metrics_url(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<String, WorkloadProbeError> {
    match connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("etcd endpoint is invalid".into()))?
    {
        WorkloadEndpoint::Tcp { host, port } => {
            Ok(format!("http://{}:{port}/metrics", url_host(&host)))
        }
        WorkloadEndpoint::Tls { host, port } => {
            Ok(format!("https://{}:{port}/metrics", url_host(&host)))
        }
        WorkloadEndpoint::Unix(_) => Err(WorkloadProbeError::Malformed(
            "etcd endpoint must use TCP or TLS".into(),
        )),
    }
}

async fn monitor_etcd_async(url: &str) -> std::result::Result<EtcdMetrics, WorkloadProbeError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(DRIVER_CONNECT_TIMEOUT)
        .timeout(ETCD_PROBE_TIMEOUT)
        .build()
        .map_err(|_| WorkloadProbeError::Unreachable("etcd HTTP client is unavailable".into()))?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| WorkloadProbeError::Unreachable("etcd endpoint is unavailable".into()))?;
    if !response.status().is_success() {
        return Err(WorkloadProbeError::Rejected(
            "etcd rejected metrics request".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > ETCD_RESPONSE_BYTES as u64)
    {
        return Err(WorkloadProbeError::Malformed(
            "etcd response exceeds the size limit".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| WorkloadProbeError::Unreachable("etcd response could not be read".into()))?
    {
        if body.len().saturating_add(chunk.len()) > ETCD_RESPONSE_BYTES {
            return Err(WorkloadProbeError::Malformed(
                "etcd response exceeds the size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| WorkloadProbeError::Malformed("etcd response is not UTF-8".into()))?;
    parse_etcd_metrics(body)
}

fn parse_etcd_metrics(body: &str) -> std::result::Result<EtcdMetrics, WorkloadProbeError> {
    const REQUIRED: [&str; 10] = [
        "etcd_server_has_leader",
        "etcd_server_is_leader",
        "etcd_server_leader_changes_seen_total",
        "etcd_server_proposals_applied_total",
        "etcd_server_proposals_committed_total",
        "etcd_server_proposals_failed_total",
        "etcd_server_proposals_pending",
        "etcd_mvcc_db_total_size_in_bytes",
        "etcd_mvcc_db_total_size_in_use_in_bytes",
        "process_resident_memory_bytes",
    ];
    let mut values = BTreeMap::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name_end = line
            .find(|character: char| character == '{' || character.is_ascii_whitespace())
            .unwrap_or(line.len());
        let name = &line[..name_end];
        if !REQUIRED.contains(&name) {
            continue;
        }
        if line[name_end..].starts_with('{') {
            return Err(WorkloadProbeError::Malformed(format!(
                "etcd required metric contains labels: {name}"
            )));
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 || values.contains_key(name) {
            return Err(WorkloadProbeError::Malformed(format!(
                "etcd required metric is duplicate or malformed: {name}"
            )));
        }
        let value = parse_exposition_u64(fields[1]).map_err(|_| {
            WorkloadProbeError::Malformed(format!("etcd metric is not a u64: {name}"))
        })?;
        if matches!(name, "etcd_server_has_leader" | "etcd_server_is_leader") && value > 1 {
            return Err(WorkloadProbeError::Malformed(format!(
                "etcd leader gauge is not 0 or 1: {name}"
            )));
        }
        values.insert(name, value);
    }
    let mut take = |name| {
        values.remove(name).ok_or_else(|| {
            WorkloadProbeError::Malformed(format!("etcd response is missing {name}"))
        })
    };
    Ok(EtcdMetrics {
        server_has_leader: take("etcd_server_has_leader")?,
        server_is_leader: take("etcd_server_is_leader")?,
        leader_changes_seen_total: take("etcd_server_leader_changes_seen_total")?,
        proposals_applied_total: take("etcd_server_proposals_applied_total")?,
        proposals_committed_total: take("etcd_server_proposals_committed_total")?,
        proposals_failed_total: take("etcd_server_proposals_failed_total")?,
        proposals_pending: take("etcd_server_proposals_pending")?,
        mvcc_db_total_size_bytes: take("etcd_mvcc_db_total_size_in_bytes")?,
        mvcc_db_total_size_in_use_bytes: take("etcd_mvcc_db_total_size_in_use_in_bytes")?,
        process_resident_memory_bytes: take("process_resident_memory_bytes")?,
    })
}

pub fn monitor_elasticsearch_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, ElasticsearchMetrics), WorkloadProbeError> {
    let (endpoint, metrics) =
        monitor_search_with_connection(WorkloadAdapter::Elasticsearch, connection)?;
    Ok((endpoint, ElasticsearchMetrics::from(metrics)))
}

pub fn monitor_opensearch_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, OpenSearchMetrics), WorkloadProbeError> {
    let (endpoint, metrics) =
        monitor_search_with_connection(WorkloadAdapter::OpenSearch, connection)?;
    Ok((endpoint, OpenSearchMetrics::from(metrics)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchMetrics {
    nodes_total: u64,
    indices_count: u64,
    shards_total: u64,
    shards_primaries: u64,
    docs_count: u64,
    docs_deleted: u64,
    store_size_bytes: u64,
    fs_total_bytes: u64,
    fs_available_bytes: u64,
}

macro_rules! search_metrics_conversion {
    ($name:ident) => {
        impl From<SearchMetrics> for $name {
            fn from(metrics: SearchMetrics) -> Self {
                Self {
                    nodes_total: metrics.nodes_total,
                    indices_count: metrics.indices_count,
                    shards_total: metrics.shards_total,
                    shards_primaries: metrics.shards_primaries,
                    docs_count: metrics.docs_count,
                    docs_deleted: metrics.docs_deleted,
                    store_size_bytes: metrics.store_size_bytes,
                    fs_total_bytes: metrics.fs_total_bytes,
                    fs_available_bytes: metrics.fs_available_bytes,
                }
            }
        }
    };
}
search_metrics_conversion!(ElasticsearchMetrics);
search_metrics_conversion!(OpenSearchMetrics);

fn monitor_search_with_connection(
    adapter: WorkloadAdapter,
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, SearchMetrics), WorkloadProbeError> {
    let owned_connection = connection.cloned().unwrap_or(WorkloadConnectionConfig {
        endpoint: format!("tcp://{SEARCH_LOOPBACK_ENDPOINT}"),
        username: None,
        secret_ref: None,
        database: None,
        auth_source: None,
    });
    owned_connection.validate_for(adapter).map_err(|_| {
        WorkloadProbeError::Malformed("search connection configuration is invalid".into())
    })?;
    let url = search_cluster_stats_url(&owned_connection)?;
    let secret = resolve_connection_secret(&owned_connection).map_err(|_| {
        WorkloadProbeError::Rejected("search authentication secret is unavailable".into())
    })?;
    let username = owned_connection.username.clone();
    let endpoint = owned_connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("search probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(
                SEARCH_PROBE_TIMEOUT,
                monitor_search_async(&url, username.as_deref(), secret.as_deref()),
            )
            .await
            .map_err(|_| WorkloadProbeError::Unreachable("search probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("search probe runtime failed".into()))??;
    Ok((endpoint, metrics))
}

fn search_cluster_stats_url(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<String, WorkloadProbeError> {
    match connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("search endpoint is invalid".into()))?
    {
        WorkloadEndpoint::Tcp { host, port } => Ok(format!(
            "http://{}:{port}/_cluster/stats?timeout=2s",
            url_host(&host)
        )),
        WorkloadEndpoint::Tls { host, port } => Ok(format!(
            "https://{}:{port}/_cluster/stats?timeout=2s",
            url_host(&host)
        )),
        WorkloadEndpoint::Unix(_) => Err(WorkloadProbeError::Malformed(
            "search endpoint must use TCP or TLS".into(),
        )),
    }
}

async fn monitor_search_async(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> std::result::Result<SearchMetrics, WorkloadProbeError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(DRIVER_CONNECT_TIMEOUT)
        .timeout(SEARCH_PROBE_TIMEOUT)
        .build()
        .map_err(|_| WorkloadProbeError::Unreachable("search HTTP client is unavailable".into()))?;
    let mut request = client.get(url);
    if let Some(username) = username {
        request = request.basic_auth(username, password);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| WorkloadProbeError::Unreachable("search endpoint is unavailable".into()))?;
    if !response.status().is_success() {
        return Err(WorkloadProbeError::Rejected(
            "search rejected stats request".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > SEARCH_RESPONSE_BYTES as u64)
    {
        return Err(WorkloadProbeError::Malformed(
            "search response exceeds the size limit".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| WorkloadProbeError::Unreachable("search response could not be read".into()))?
    {
        if body.len().saturating_add(chunk.len()) > SEARCH_RESPONSE_BYTES {
            return Err(WorkloadProbeError::Malformed(
                "search response exceeds the size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| WorkloadProbeError::Malformed("search response is not UTF-8".into()))?;
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| WorkloadProbeError::Malformed("search response is not valid JSON".into()))?;
    parse_search_metrics(&value)
}

fn parse_search_metrics(
    value: &serde_json::Value,
) -> std::result::Result<SearchMetrics, WorkloadProbeError> {
    let metric = |path: &[&str]| {
        let mut current = value;
        for segment in path {
            current = current.get(*segment).ok_or_else(|| {
                WorkloadProbeError::Malformed(format!(
                    "search response is missing {}",
                    path.join(".")
                ))
            })?;
        }
        current.as_u64().ok_or_else(|| {
            WorkloadProbeError::Malformed(format!("search metric is not a u64: {}", path.join(".")))
        })
    };
    let nodes_total = metric(&["nodes", "count", "total"])?;
    let node_total = metric(&["_nodes", "total"])?;
    let successful = metric(&["_nodes", "successful"])?;
    let failed = metric(&["_nodes", "failed"])?;
    let metrics = SearchMetrics {
        nodes_total,
        indices_count: metric(&["indices", "count"])?,
        shards_total: metric(&["indices", "shards", "total"])?,
        shards_primaries: metric(&["indices", "shards", "primaries"])?,
        docs_count: metric(&["indices", "docs", "count"])?,
        docs_deleted: metric(&["indices", "docs", "deleted"])?,
        store_size_bytes: metric(&["indices", "store", "size_in_bytes"])?,
        fs_total_bytes: metric(&["nodes", "fs", "total_in_bytes"])?,
        fs_available_bytes: metric(&["nodes", "fs", "available_in_bytes"])?,
    };
    if failed != 0
        || successful.checked_add(failed) != Some(node_total)
        || nodes_total != successful
        || metrics.shards_primaries > metrics.shards_total
        || metrics.fs_available_bytes > metrics.fs_total_bytes
    {
        return Err(WorkloadProbeError::Malformed(
            "search response invariants failed".into(),
        ));
    }
    Ok(metrics)
}

pub fn monitor_rabbitmq_with_connection(
    connection: Option<&WorkloadConnectionConfig>,
) -> std::result::Result<(String, RabbitMqMetrics), WorkloadProbeError> {
    let owned_connection = connection.cloned().unwrap_or(WorkloadConnectionConfig {
        endpoint: format!("tcp://{RABBITMQ_LOOPBACK_ENDPOINT}"),
        username: None,
        secret_ref: None,
        database: None,
        auth_source: None,
    });
    owned_connection
        .validate_for(WorkloadAdapter::RabbitMq)
        .map_err(|_| {
            WorkloadProbeError::Malformed("RabbitMQ connection configuration is invalid".into())
        })?;
    let url = rabbitmq_overview_url(&owned_connection)?;
    let secret = resolve_connection_secret(&owned_connection).map_err(|_| {
        WorkloadProbeError::Rejected("RabbitMQ authentication secret is unavailable".into())
    })?;
    let username = owned_connection.username.clone();
    let endpoint = owned_connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("RabbitMQ probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(
                RABBITMQ_PROBE_TIMEOUT,
                monitor_rabbitmq_async(&url, username.as_deref(), secret.as_deref()),
            )
            .await
            .map_err(|_| WorkloadProbeError::Unreachable("RabbitMQ probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("RabbitMQ probe runtime failed".into()))??;
    Ok((endpoint, metrics))
}

fn rabbitmq_overview_url(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<String, WorkloadProbeError> {
    match connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("RabbitMQ endpoint is invalid".into()))?
    {
        WorkloadEndpoint::Tcp { host, port } => {
            Ok(format!("http://{}:{port}/api/overview", url_host(&host)))
        }
        WorkloadEndpoint::Tls { host, port } => {
            Ok(format!("https://{}:{port}/api/overview", url_host(&host)))
        }
        WorkloadEndpoint::Unix(_) => Err(WorkloadProbeError::Malformed(
            "RabbitMQ endpoint must use TCP or TLS".into(),
        )),
    }
}

async fn monitor_rabbitmq_async(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> std::result::Result<RabbitMqMetrics, WorkloadProbeError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(DRIVER_CONNECT_TIMEOUT)
        .timeout(RABBITMQ_PROBE_TIMEOUT)
        .build()
        .map_err(|_| {
            WorkloadProbeError::Unreachable("RabbitMQ HTTP client is unavailable".into())
        })?;
    let mut request = client.get(url);
    if let Some(username) = username {
        request = request.basic_auth(username, password);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| WorkloadProbeError::Unreachable("RabbitMQ endpoint is unavailable".into()))?;
    if !response.status().is_success() {
        return Err(WorkloadProbeError::Rejected(
            "RabbitMQ rejected overview request".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > RABBITMQ_RESPONSE_BYTES as u64)
    {
        return Err(WorkloadProbeError::Malformed(
            "RabbitMQ response exceeds the size limit".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        WorkloadProbeError::Unreachable("RabbitMQ response could not be read".into())
    })? {
        if body.len().saturating_add(chunk.len()) > RABBITMQ_RESPONSE_BYTES {
            return Err(WorkloadProbeError::Malformed(
                "RabbitMQ response exceeds the size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| WorkloadProbeError::Malformed("RabbitMQ response is not UTF-8".into()))?;
    let value = serde_json::from_str(body)
        .map_err(|_| WorkloadProbeError::Malformed("RabbitMQ response is not valid JSON".into()))?;
    parse_rabbitmq_metrics(&value)
}

fn parse_rabbitmq_metrics(
    value: &serde_json::Value,
) -> std::result::Result<RabbitMqMetrics, WorkloadProbeError> {
    let metric = |path: &[&str]| {
        let mut current = value;
        for segment in path {
            current = current.get(*segment).ok_or_else(|| {
                WorkloadProbeError::Malformed(format!(
                    "RabbitMQ response is missing {}",
                    path.join(".")
                ))
            })?;
        }
        current.as_u64().ok_or_else(|| {
            WorkloadProbeError::Malformed(format!(
                "RabbitMQ metric is not a u64: {}",
                path.join(".")
            ))
        })
    };
    let optional_message_metric = |key| match value.get("message_stats") {
        None => Ok(0),
        Some(serde_json::Value::Object(stats)) => match stats.get(key) {
            None => Ok(0),
            Some(metric) => metric.as_u64().ok_or_else(|| {
                WorkloadProbeError::Malformed(format!(
                    "RabbitMQ message_stats metric is not a u64: {key}"
                ))
            }),
        },
        Some(_) => Err(WorkloadProbeError::Malformed(
            "RabbitMQ message_stats is not an object".into(),
        )),
    };
    Ok(RabbitMqMetrics {
        messages: metric(&["queue_totals", "messages"])?,
        messages_ready: metric(&["queue_totals", "messages_ready"])?,
        messages_unacknowledged: metric(&["queue_totals", "messages_unacknowledged"])?,
        queues: metric(&["object_totals", "queues"])?,
        connections: metric(&["object_totals", "connections"])?,
        channels: metric(&["object_totals", "channels"])?,
        consumers: metric(&["object_totals", "consumers"])?,
        exchanges: metric(&["object_totals", "exchanges"])?,
        message_stats_publish_total: optional_message_metric("publish")?,
        message_stats_deliver_get_total: optional_message_metric("deliver_get")?,
    })
}

pub fn monitor_nginx_with_connection(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<(String, NginxMetrics), WorkloadProbeError> {
    connection
        .validate_for(WorkloadAdapter::Nginx)
        .map_err(|_| {
            WorkloadProbeError::Malformed("Nginx connection configuration is invalid".into())
        })?;
    let url = nginx_stub_status_url(connection)?;
    let secret = resolve_connection_secret(connection).map_err(|_| {
        WorkloadProbeError::Rejected("Nginx authentication secret is unavailable".into())
    })?;
    let username = connection.username.clone();
    let endpoint = connection.endpoint.clone();
    let metrics = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                WorkloadProbeError::Unreachable("Nginx probe runtime is unavailable".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(
                NGINX_PROBE_TIMEOUT,
                monitor_nginx_async(&url, username.as_deref(), secret.as_deref()),
            )
            .await
            .map_err(|_| WorkloadProbeError::Unreachable("Nginx probe timed out".into()))?
        })
    })
    .join()
    .map_err(|_| WorkloadProbeError::Unreachable("Nginx probe runtime failed".into()))??;
    Ok((endpoint, metrics))
}

fn nginx_stub_status_url(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<String, WorkloadProbeError> {
    match connection
        .endpoint()
        .map_err(|_| WorkloadProbeError::Malformed("Nginx endpoint is invalid".into()))?
    {
        WorkloadEndpoint::Tcp { host, port } => {
            Ok(format!("http://{}:{port}/stub_status", url_host(&host)))
        }
        WorkloadEndpoint::Tls { host, port } => {
            Ok(format!("https://{}:{port}/stub_status", url_host(&host)))
        }
        WorkloadEndpoint::Unix(_) => Err(WorkloadProbeError::Malformed(
            "Nginx endpoint must use TCP or TLS".into(),
        )),
    }
}

async fn monitor_nginx_async(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> std::result::Result<NginxMetrics, WorkloadProbeError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(DRIVER_CONNECT_TIMEOUT)
        .timeout(NGINX_PROBE_TIMEOUT)
        .build()
        .map_err(|_| WorkloadProbeError::Unreachable("Nginx HTTP client is unavailable".into()))?;
    let mut request = client.get(url);
    if let Some(username) = username {
        request = request.basic_auth(username, password);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| WorkloadProbeError::Unreachable("Nginx endpoint is unavailable".into()))?;
    if !response.status().is_success() {
        return Err(WorkloadProbeError::Rejected(
            "Nginx rejected status request".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > NGINX_RESPONSE_BYTES as u64)
    {
        return Err(WorkloadProbeError::Malformed(
            "Nginx response exceeds the size limit".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| WorkloadProbeError::Unreachable("Nginx response could not be read".into()))?
    {
        if body.len().saturating_add(chunk.len()) > NGINX_RESPONSE_BYTES {
            return Err(WorkloadProbeError::Malformed(
                "Nginx response exceeds the size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| WorkloadProbeError::Malformed("Nginx response is not UTF-8".into()))?;
    parse_nginx_stub_status(body)
}

fn parse_nginx_stub_status(body: &str) -> std::result::Result<NginxMetrics, WorkloadProbeError> {
    let lines = body.lines().collect::<Vec<_>>();
    if lines.len() != 4 {
        return Err(WorkloadProbeError::Malformed(
            "Nginx stub status must contain four lines".into(),
        ));
    }
    let active_connections = lines[0]
        .strip_prefix("Active connections: ")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .ok_or_else(|| {
            WorkloadProbeError::Malformed("Nginx active connections is invalid".into())
        })?;
    if lines[1].trim() != "server accepts handled requests" {
        return Err(WorkloadProbeError::Malformed(
            "Nginx stub status header is invalid".into(),
        ));
    }
    let totals = lines[2]
        .split_ascii_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| WorkloadProbeError::Malformed("Nginx totals are invalid".into()))?;
    if totals.len() != 3 {
        return Err(WorkloadProbeError::Malformed(
            "Nginx totals field count is invalid".into(),
        ));
    }
    let fields = lines[3].split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 6
        || fields[0] != "Reading:"
        || fields[2] != "Writing:"
        || fields[4] != "Waiting:"
    {
        return Err(WorkloadProbeError::Malformed(
            "Nginx connection states are invalid".into(),
        ));
    }
    let reading = fields[1].parse::<u64>();
    let writing = fields[3].parse::<u64>();
    let waiting = fields[5].parse::<u64>();
    let (reading, writing, waiting) = match (reading, writing, waiting) {
        (Ok(r), Ok(w), Ok(i)) => (r, w, i),
        _ => {
            return Err(WorkloadProbeError::Malformed(
                "Nginx connection state value is invalid".into(),
            ))
        }
    };
    let state_total = reading
        .checked_add(writing)
        .and_then(|value| value.checked_add(waiting));
    if totals[1] > totals[0] || state_total != Some(active_connections) {
        return Err(WorkloadProbeError::Malformed(
            "Nginx stub status invariants failed".into(),
        ));
    }
    Ok(NginxMetrics {
        active_connections,
        accepts_total: totals[0],
        handled_total: totals[1],
        requests_total: totals[2],
        reading,
        writing,
        waiting,
    })
}

pub fn monitor_haproxy_with_connection(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<(String, HaProxyMetrics), WorkloadProbeError> {
    connection
        .validate_for(WorkloadAdapter::HaProxy)
        .map_err(|_| {
            WorkloadProbeError::Malformed("HAProxy connection configuration is invalid".into())
        })?;
    #[cfg(unix)]
    {
        let WorkloadEndpoint::Unix(path) = connection
            .endpoint()
            .map_err(|_| WorkloadProbeError::Malformed("HAProxy endpoint is invalid".into()))?
        else {
            unreachable!()
        };
        let metrics = std::thread::spawn(move || {
            let mut stream = connect_unix_with_timeout(&path, DRIVER_CONNECT_TIMEOUT)?;
            stream
                .set_read_timeout(Some(HAPROXY_PROBE_TIMEOUT))
                .map_err(unreachable)?;
            stream
                .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
                .map_err(unreachable)?;
            monitor_haproxy_stream(&mut stream)
        })
        .join()
        .map_err(|_| WorkloadProbeError::Unreachable("HAProxy probe runtime failed".into()))??;
        Ok(("local-unix-socket".into(), metrics))
    }
    #[cfg(not(unix))]
    {
        let _ = connection;
        Err(WorkloadProbeError::Unreachable(
            "Unix sockets are unavailable".into(),
        ))
    }
}

#[cfg(unix)]
fn connect_unix_with_timeout(
    path: &Path,
    timeout: Duration,
) -> std::result::Result<UnixStream, WorkloadProbeError> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() {
        return Err(WorkloadProbeError::Malformed(
            "Unix socket path is invalid".into(),
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    let fd = create_cloexec_unix_socket()?;
    if fd < 0 {
        return Err(unreachable(std::io::Error::last_os_error()));
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let address_len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sun_len = address_len as u8;
    }
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            address_len as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN
        ) {
            return Err(unreachable(error));
        }
        let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if ready <= 0 {
            return Err(WorkloadProbeError::Unreachable(
                "Unix socket connection timed out".into(),
            ));
        }
        let mut socket_error = 0_i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut i32).cast(),
                &mut length,
            )
        } != 0
            || socket_error != 0
        {
            return Err(unreachable(if socket_error != 0 {
                std::io::Error::from_raw_os_error(socket_error)
            } else {
                std::io::Error::last_os_error()
            }));
        }
    }
    stream.set_nonblocking(false).map_err(unreachable)?;
    Ok(stream)
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn create_cloexec_unix_socket() -> std::result::Result<i32, WorkloadProbeError> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        Err(unreachable(std::io::Error::last_os_error()))
    } else {
        Ok(fd)
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))
))]
fn create_cloexec_unix_socket() -> std::result::Result<i32, WorkloadProbeError> {
    Err(WorkloadProbeError::Unreachable(
        "atomic close-on-exec Unix sockets are unavailable on this platform".into(),
    ))
}

fn monitor_haproxy_stream(
    stream: &mut (impl Read + Write),
) -> std::result::Result<HaProxyMetrics, WorkloadProbeError> {
    stream
        .write_all(HAPROXY_STATS_COMMAND)
        .map_err(unreachable)?;
    stream.flush().map_err(unreachable)?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => {
                if bytes.len().saturating_add(size) > HAPROXY_RESPONSE_BYTES {
                    return Err(WorkloadProbeError::Malformed(
                        "HAProxy response exceeds the size limit".into(),
                    ));
                }
                bytes.extend_from_slice(&chunk[..size]);
                if bytes.ends_with(b"\n\n") || bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(error) => return Err(unreachable(error)),
        }
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| WorkloadProbeError::Malformed("HAProxy response is not UTF-8".into()))?;
    parse_haproxy_stats(text)
}

fn parse_haproxy_stats(text: &str) -> std::result::Result<HaProxyMetrics, WorkloadProbeError> {
    let text = text.trim_end_matches(['\r', '\n']);
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| WorkloadProbeError::Malformed("HAProxy CSV header is invalid".into()))?
        .clone();
    const REQUIRED: [&str; 11] = [
        "pxname", "svname", "scur", "stot", "bin", "bout", "dreq", "dresp", "econ", "wretr",
        "status",
    ];
    let mut indices = BTreeMap::new();
    for name in REQUIRED {
        let matches = headers
            .iter()
            .enumerate()
            .filter(|(index, value)| {
                if *index == 0 {
                    value.trim_start_matches('#').trim() == name
                } else {
                    *value == name
                }
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(WorkloadProbeError::Malformed(
                "HAProxy CSV required header is missing or duplicate".into(),
            ));
        }
        indices.insert(name, matches[0]);
    }
    let mut metrics = HaProxyMetrics {
        current_sessions: 0,
        sessions_total: 0,
        bytes_in_total: 0,
        bytes_out_total: 0,
        denied_requests_total: 0,
        denied_responses_total: 0,
        failed_connections_total: 0,
        retry_warnings_total: 0,
        servers_down: 0,
    };
    let mut aggregates = 0_u64;
    for record in reader.records() {
        let record = record
            .map_err(|_| WorkloadProbeError::Malformed("HAProxy CSV record is invalid".into()))?;
        let get = |name| {
            record.get(indices[name]).ok_or_else(|| {
                WorkloadProbeError::Malformed("HAProxy CSV record is incomplete".into())
            })
        };
        let svname = get("svname")?;
        let status = get("status")?;
        let number = |name| {
            let value = get(name)?;
            if value.is_empty() {
                Ok(0)
            } else {
                value.parse::<u64>().map_err(|_| {
                    WorkloadProbeError::Malformed(format!("HAProxy metric is not a u64: {name}"))
                })
            }
        };
        let add = |target: &mut u64, value: u64| {
            *target = target.checked_add(value).ok_or_else(|| {
                WorkloadProbeError::Malformed("HAProxy metric sum overflowed".into())
            })?;
            Ok::<(), WorkloadProbeError>(())
        };
        match svname {
            "FRONTEND" => {
                aggregates += 1;
                add(&mut metrics.current_sessions, number("scur")?)?;
                add(&mut metrics.sessions_total, number("stot")?)?;
                add(&mut metrics.bytes_in_total, number("bin")?)?;
                add(&mut metrics.bytes_out_total, number("bout")?)?;
                add(&mut metrics.denied_requests_total, number("dreq")?)?;
            }
            "BACKEND" => {
                aggregates += 1;
                add(&mut metrics.denied_responses_total, number("dresp")?)?;
                add(&mut metrics.failed_connections_total, number("econ")?)?;
                add(&mut metrics.retry_warnings_total, number("wretr")?)?;
            }
            _ if matches!(status, "DOWN" | "MAINT") => add(&mut metrics.servers_down, 1)?,
            _ => {}
        }
    }
    if aggregates == 0 {
        return Err(WorkloadProbeError::Malformed(
            "HAProxy CSV has no aggregate rows".into(),
        ));
    }
    Ok(metrics)
}

fn parse_exposition_u64(value: &str) -> std::result::Result<u64, ()> {
    let value = value.strip_prefix('+').unwrap_or(value);
    if value.is_empty() || value.starts_with('-') {
        return Err(());
    }
    let (mantissa, exponent) = match value.find(['e', 'E']) {
        Some(index) => {
            let exponent = value[index + 1..].parse::<i32>().map_err(|_| ())?;
            (&value[..index], exponent)
        }
        None => (value, 0),
    };
    let mut digits = String::with_capacity(mantissa.len());
    let mut fractional_digits = 0_i32;
    let mut seen_decimal = false;
    for character in mantissa.chars() {
        match character {
            '0'..='9' => {
                digits.push(character);
                if seen_decimal {
                    fractional_digits = fractional_digits.checked_add(1).ok_or(())?;
                }
            }
            '.' if !seen_decimal => seen_decimal = true,
            _ => return Err(()),
        }
    }
    if digits.is_empty() {
        return Err(());
    }
    if digits.bytes().all(|byte| byte == b'0') {
        return Ok(0);
    }
    let scale = exponent.checked_sub(fractional_digits).ok_or(())?;
    if scale < 0 {
        let remove = usize::try_from(scale.checked_neg().ok_or(())?).map_err(|_| ())?;
        if remove > digits.len()
            || !digits[digits.len() - remove..]
                .bytes()
                .all(|byte| byte == b'0')
        {
            return Err(());
        }
        digits.truncate(digits.len() - remove);
    }
    let mut result = if digits.is_empty() {
        0
    } else {
        digits.parse::<u64>().map_err(|_| ())?
    };
    if scale > 0 {
        let scale = u32::try_from(scale).map_err(|_| ())?;
        if scale > 19 || digits.trim_start_matches('0').len() + scale as usize > 20 {
            return Err(());
        }
        result = result
            .checked_mul(10_u64.checked_pow(scale).ok_or(())?)
            .ok_or(())?;
    }
    Ok(result)
}

fn postgresql_metrics_from_rows(
    rows: &[Row],
) -> std::result::Result<PostgreSqlMetrics, WorkloadProbeError> {
    if rows.len() != 1 {
        return Err(WorkloadProbeError::Malformed(
            "PostgreSQL metrics query must return exactly one row".into(),
        ));
    }
    let row = &rows[0];
    let values = (0..14)
        .map(|index| row.try_get::<_, Option<i64>>(index))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| {
            WorkloadProbeError::Malformed("PostgreSQL metrics have invalid types".into())
        })?;
    postgresql_metrics_from_values(&values)
}

fn postgresql_metrics_from_values(
    values: &[Option<i64>],
) -> std::result::Result<PostgreSqlMetrics, WorkloadProbeError> {
    if values.len() != 14 {
        return Err(WorkloadProbeError::Malformed(
            "PostgreSQL metrics have an invalid field count".into(),
        ));
    }
    let mut values = values.iter().map(|value| {
        value
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| {
                WorkloadProbeError::Malformed(
                    "PostgreSQL metrics contain a null or negative value".into(),
                )
            })
    });
    Ok(PostgreSqlMetrics {
        numbackends: values.next().expect("validated metric count")?,
        xact_commit: values.next().expect("validated metric count")?,
        xact_rollback: values.next().expect("validated metric count")?,
        blks_read: values.next().expect("validated metric count")?,
        blks_hit: values.next().expect("validated metric count")?,
        tup_returned: values.next().expect("validated metric count")?,
        tup_fetched: values.next().expect("validated metric count")?,
        tup_inserted: values.next().expect("validated metric count")?,
        tup_updated: values.next().expect("validated metric count")?,
        tup_deleted: values.next().expect("validated metric count")?,
        conflicts: values.next().expect("validated metric count")?,
        temp_files: values.next().expect("validated metric count")?,
        temp_bytes: values.next().expect("validated metric count")?,
        deadlocks: values.next().expect("validated metric count")?,
    })
}

fn resolve_connection_secret(
    connection: &WorkloadConnectionConfig,
) -> std::result::Result<Option<String>, WorkloadProbeError> {
    connection
        .secret_ref
        .as_deref()
        .map(crate::secret::resolve_secret_reference)
        .transpose()
        .map_err(|_| {
            WorkloadProbeError::Rejected("Redis authentication secret is unavailable".into())
        })
}

fn connect_tcp(host: &str, port: u16) -> std::result::Result<TcpStream, WorkloadProbeError> {
    let addresses = (host, port).to_socket_addrs().map_err(unreachable)?;
    let address = addresses.into_iter().next().ok_or_else(|| {
        WorkloadProbeError::Unreachable("workload endpoint did not resolve".into())
    })?;
    let stream =
        TcpStream::connect_timeout(&address, DRIVER_CONNECT_TIMEOUT).map_err(unreachable)?;
    set_timeouts(&stream)?;
    Ok(stream)
}

fn set_timeouts(stream: &impl TimeoutStream) -> std::result::Result<(), WorkloadProbeError> {
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)
}

trait TimeoutStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl TimeoutStream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

#[cfg(unix)]
impl TimeoutStream for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

fn tls_stream(
    stream: TcpStream,
    host: &str,
) -> std::result::Result<StreamOwned<ClientConnection, TcpStream>, WorkloadProbeError> {
    let config = tls_client_config()?;
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| {
        WorkloadProbeError::Malformed("TLS workload endpoint host is invalid".into())
    })?;
    let connection = ClientConnection::new(Arc::new(config), server_name).map_err(|_| {
        WorkloadProbeError::Malformed("TLS workload endpoint host is invalid".into())
    })?;
    Ok(StreamOwned::new(connection, stream))
}

pub fn tls_client_config() -> std::result::Result<ClientConfig, WorkloadProbeError> {
    let mut roots = RootCertStore::empty();
    let certificates = rustls_native_certs::load_native_certs();
    if !certificates.errors.is_empty() {
        tracing::debug!(
            invalid_native_roots = certificates.errors.len(),
            "some native TLS roots could not be loaded"
        );
    }
    for certificate in certificates.certs {
        if roots.add(certificate).is_err() {
            tracing::debug!("native TLS root could not be parsed");
        }
    }
    if roots.is_empty() {
        return Err(WorkloadProbeError::Unreachable(
            "native TLS roots are unavailable".into(),
        ));
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub fn probe_memcached_server() -> std::result::Result<(), WorkloadProbeError> {
    let endpoint: SocketAddr = MEMCACHED_LOOPBACK_ENDPOINT
        .parse()
        .expect("valid Memcached endpoint");
    monitor_memcached_tcp(endpoint).map(|_| ())
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

pub fn monitor_redis_authenticated_stream(
    stream: &mut (impl Read + Write),
    username: Option<&str>,
    password: Option<&str>,
) -> std::result::Result<RedisMetrics, RedisProbeError> {
    if let Some(password) = password {
        write_redis_auth(stream, username, password)?;
    }
    monitor_redis_stream(stream)
}

fn write_redis_auth(
    stream: &mut (impl Read + Write),
    username: Option<&str>,
    password: &str,
) -> std::result::Result<(), RedisProbeError> {
    let arguments = username.map_or_else(
        || vec!["AUTH", password],
        |username| vec!["AUTH", username, password],
    );
    let mut request = format!("*{}\r\n", arguments.len()).into_bytes();
    for argument in arguments {
        request.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
        request.extend_from_slice(argument.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    stream.write_all(&request).map_err(unreachable)?;
    stream.flush().map_err(unreachable)?;
    let mut prefix = [0_u8; 1];
    stream.read_exact(&mut prefix).map_err(unreachable)?;
    let mut consumed = 1;
    match prefix[0] {
        b'+' => {
            let _ = read_resp_line(stream, REDIS_RESPONSE_BYTES, &mut consumed)?;
            Ok(())
        }
        b'-' => {
            let _ = read_resp_line(stream, REDIS_RESPONSE_BYTES, &mut consumed)?;
            Err(RedisProbeError::Rejected(
                "Redis authentication failed".into(),
            ))
        }
        _ => Err(RedisProbeError::Malformed(
            "Redis AUTH returned malformed RESP".into(),
        )),
    }
}

pub fn read_redis_info_response(
    stream: &mut impl Read,
    response_cap: usize,
) -> std::result::Result<String, RedisProbeError> {
    let mut consumed = 1;
    let mut prefix = [0_u8; 1];
    stream.read_exact(&mut prefix).map_err(unreachable)?;
    if prefix[0] == b'-' {
        let _ = read_resp_line(stream, response_cap, &mut consumed)?;
        return Err(RedisProbeError::Rejected("Redis rejected request".into()));
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

pub fn monitor_memcached_stream(
    stream: &mut (impl Read + Write),
) -> std::result::Result<MemcachedMetrics, WorkloadProbeError> {
    stream
        .write_all(MEMCACHED_STATS_REQUEST)
        .map_err(unreachable)?;
    stream.flush().map_err(unreachable)?;
    let response = read_memcached_stats_response(stream, MEMCACHED_RESPONSE_BYTES)?;
    parse_memcached_stats(&response)
}

pub fn read_memcached_stats_response(
    stream: &mut impl Read,
    response_cap: usize,
) -> std::result::Result<String, WorkloadProbeError> {
    let mut response = Vec::new();
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while response.len() < response_cap {
        match stream.read_exact(&mut byte) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(WorkloadProbeError::Malformed(
                    "Memcached stats response omitted END".into(),
                ));
            }
            Err(error) => return Err(unreachable(error)),
        }
        response.push(byte[0]);
        line.push(byte[0]);
        if !line.ends_with(b"\r\n") {
            continue;
        }
        let text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| WorkloadProbeError::Malformed("Memcached stats is not UTF-8".into()))?;
        if matches!(text, "ERROR" | "CLIENT_ERROR" | "SERVER_ERROR")
            || text.starts_with("CLIENT_ERROR ")
            || text.starts_with("SERVER_ERROR ")
        {
            return Err(WorkloadProbeError::Rejected(
                "Memcached rejected stats".into(),
            ));
        }
        if text == "END" {
            response.truncate(response.len() - line.len());
            return String::from_utf8(response)
                .map_err(|_| WorkloadProbeError::Malformed("Memcached stats is not UTF-8".into()));
        }
        line.clear();
    }
    Err(WorkloadProbeError::Malformed(
        "Memcached stats response exceeded the byte cap or omitted END".into(),
    ))
}

pub fn parse_memcached_stats(
    response: &str,
) -> std::result::Result<MemcachedMetrics, WorkloadProbeError> {
    let mut values = std::collections::BTreeMap::new();
    for line in response.split("\r\n").filter(|line| !line.is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("STAT") {
            return Err(WorkloadProbeError::Malformed(
                "Memcached stats contains a malformed line".into(),
            ));
        }
        let key = fields.next().ok_or_else(|| {
            WorkloadProbeError::Malformed("Memcached stats contains a malformed line".into())
        })?;
        let value = fields.next().ok_or_else(|| {
            WorkloadProbeError::Malformed("Memcached stats contains a malformed line".into())
        })?;
        if fields.next().is_some() || values.insert(key, value).is_some() {
            return Err(WorkloadProbeError::Malformed(
                "Memcached stats contains a duplicate or malformed metric".into(),
            ));
        }
    }
    let metric = |key| {
        values
            .get(key)
            .ok_or_else(|| {
                WorkloadProbeError::Malformed(format!("Memcached stats is missing {key}"))
            })
            .and_then(|value| {
                value.parse::<u64>().map_err(|_| {
                    WorkloadProbeError::Malformed(format!(
                        "Memcached stats metric is not a u64: {key}"
                    ))
                })
            })
    };
    Ok(MemcachedMetrics {
        curr_connections: metric("curr_connections")?,
        bytes: metric("bytes")?,
        cmd_get: metric("cmd_get")?,
        cmd_set: metric("cmd_set")?,
        get_hits: metric("get_hits")?,
        get_misses: metric("get_misses")?,
        evictions: metric("evictions")?,
    })
}

fn monitor_memcached_tcp(
    endpoint: SocketAddr,
) -> std::result::Result<MemcachedMetrics, WorkloadProbeError> {
    let mut stream =
        TcpStream::connect_timeout(&endpoint, DRIVER_CONNECT_TIMEOUT).map_err(unreachable)?;
    stream
        .set_read_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    stream
        .set_write_timeout(Some(DRIVER_CONNECT_TIMEOUT))
        .map_err(unreachable)?;
    monitor_memcached_stream(&mut stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Result as IoResult};

    struct TestStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl TestStream {
        fn response(response: &str) -> Self {
            Self {
                input: Cursor::new(response.as_bytes().to_vec()),
                output: Vec::new(),
            }
        }
    }

    impl Read for TestStream {
        fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for TestStream {
        fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

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
            connection: None,
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
        assert_eq!(definition.connection, None);
    }

    #[test]
    fn legacy_workloads_toml_parses_without_a_connection() {
        let store: WorkloadStore = toml::from_str(
            r#"[[workloads]]
id = "redis"
adapter = "redis"

[workloads.selector.executable]
path = "/usr/bin/redis-server"
"#,
        )
        .unwrap();
        assert_eq!(store.workloads[0].connection, None);
    }

    #[test]
    fn legacy_connection_defaults_database_to_none() {
        let connection: WorkloadConnectionConfig =
            toml::from_str(r#"endpoint = "tcp://127.0.0.1:6379""#).unwrap();
        assert_eq!(connection.database, None);
    }

    #[test]
    fn postgresql_connection_requires_endpoint_username_and_database() {
        let valid = WorkloadConnectionConfig {
            endpoint: "tls://postgres.example:5432".into(),
            username: Some("monitor".into()),
            secret_ref: None,
            database: Some("app".into()),
            auth_source: None,
        };
        valid.validate_for(WorkloadAdapter::PostgreSql).unwrap();

        for invalid in [
            WorkloadConnectionConfig {
                username: None,
                ..valid.clone()
            },
            WorkloadConnectionConfig {
                database: None,
                ..valid.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/postgresql/.s.PGSQL.5432".into(),
                ..valid.clone()
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::PostgreSql).is_err());
        }
        assert!(WorkloadConnectionConfig {
            database: Some("app".into()),
            endpoint: "tcp://127.0.0.1:6379".into(),
            username: None,
            secret_ref: None,
            auth_source: None,
        }
        .validate_for(WorkloadAdapter::Redis)
        .is_err());
    }

    #[test]
    fn postgresql_metrics_reject_null_negative_and_wrong_field_count() {
        let values = (1_i64..=14).map(Some).collect::<Vec<_>>();
        let metrics = postgresql_metrics_from_values(&values).unwrap();
        assert_eq!(metrics.numbackends, 1);
        assert_eq!(metrics.deadlocks, 14);

        for invalid in [
            vec![Some(1); 13],
            {
                let mut values = vec![Some(1); 14];
                values[4] = None;
                values
            },
            {
                let mut values = vec![Some(1); 14];
                values[9] = Some(-1);
                values
            },
        ] {
            assert!(matches!(
                postgresql_metrics_from_values(&invalid),
                Err(WorkloadProbeError::Malformed(_))
            ));
        }
    }

    #[test]
    fn postgresql_metric_variant_matches_only_postgresql_samples() {
        let metrics = PostgreSqlMetrics {
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
        };
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "postgres".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::PostgreSql,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:5432".into(),
                metrics: WorkloadMetrics::PostgreSql(metrics),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("redis".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    #[test]
    fn mysql_connection_requires_tcp_or_tls_and_username() {
        let valid = WorkloadConnectionConfig {
            endpoint: "tls://mysql.example:3306".into(),
            username: Some("monitor".into()),
            secret_ref: None,
            database: Some("metrics".into()),
            auth_source: None,
        };
        valid.validate_for(WorkloadAdapter::MySql).unwrap();
        assert!(WorkloadConnectionConfig {
            username: None,
            ..valid.clone()
        }
        .validate_for(WorkloadAdapter::MySql)
        .is_err());
        assert!(WorkloadConnectionConfig {
            endpoint: "unix:///run/mysqld/mysqld.sock".into(),
            ..valid
        }
        .validate_for(WorkloadAdapter::MySql)
        .is_err());
        let options = mysql_async::Opts::from(
            mysql_connection_options("127.0.0.1", 3306, false, "monitor", None, Some("metrics"))
                .unwrap(),
        );
        assert_eq!(options.db_name(), Some("metrics"));
    }

    #[test]
    fn mysql_metrics_require_exact_allowlisted_u64_rows() {
        let rows = [
            ("Threads_connected", "1"),
            ("Threads_running", "2"),
            ("Connections", "3"),
            ("Aborted_connects", "4"),
            ("Questions", "5"),
            ("Slow_queries", "6"),
            ("Bytes_received", "7"),
            ("Bytes_sent", "8"),
        ];
        let owned = rows
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<Vec<_>>();
        assert_eq!(mysql_metrics_from_rows(&owned).unwrap().bytes_sent, 8);

        let invalid = [
            owned[..7].to_vec(),
            {
                let mut rows = owned.clone();
                rows[7] = ("Unknown".into(), "8".into());
                rows
            },
            {
                let mut rows = owned.clone();
                rows[7] = rows[0].clone();
                rows
            },
            {
                let mut rows = owned.clone();
                rows[3].1 = "-1".into();
                rows
            },
        ];
        for rows in invalid {
            assert!(matches!(
                mysql_metrics_from_rows(&rows),
                Err(WorkloadProbeError::Malformed(_))
            ));
        }
    }

    #[test]
    fn mysql_metric_variant_matches_only_mysql_samples() {
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "mysql".into(),
            captured_at: Utc::now(),
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
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("postgres_sql".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    fn mongodb_response() -> Document {
        doc! {
            "connections": { "current": 1_i32, "available": 2_i64, "totalCreated": 3_i64 },
            "opcounters": { "query": 4_i32, "getmore": 5_i64, "command": 6_i64 },
            "network": { "bytesIn": 7_i64, "bytesOut": 8_i64, "numRequests": 9_i64 },
            "uptime": 10_i64,
        }
    }

    #[test]
    fn mongodb_connection_requires_safe_auth_pair_and_rejects_database() {
        let anonymous = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:27017".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        anonymous.validate_for(WorkloadAdapter::MongoDb).unwrap();
        let authenticated = WorkloadConnectionConfig {
            endpoint: "tls://mongo.example:27017".into(),
            username: Some("monitor".into()),
            secret_ref: Some("env:MONGODB_PASSWORD".into()),
            database: None,
            auth_source: Some("admin".into()),
        };
        authenticated
            .validate_for(WorkloadAdapter::MongoDb)
            .unwrap();
        for adapter in [WorkloadAdapter::Elasticsearch, WorkloadAdapter::OpenSearch] {
            assert!(WorkloadConnectionConfig {
                endpoint: "tcp://search.example:9200".into(),
                ..authenticated.clone()
            }
            .validate_for(adapter)
            .is_err());
        }
        assert!(WorkloadConnectionConfig {
            endpoint: "tcp://clickhouse.example:8123".into(),
            ..authenticated.clone()
        }
        .validate_for(WorkloadAdapter::ClickHouse)
        .is_err());
        for invalid in [
            WorkloadConnectionConfig {
                secret_ref: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                username: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                database: Some("admin".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/mongodb/mongodb.sock".into(),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..anonymous
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::MongoDb).is_err());
        }
    }

    #[test]
    fn mongodb_metrics_require_nested_nonnegative_integers() {
        let metrics = mongodb_metrics_from_document(&mongodb_response()).unwrap();
        assert_eq!(metrics.connections_total_created, 3);
        assert_eq!(metrics.uptime_seconds, 10);

        for invalid in [
            {
                let mut response = mongodb_response();
                response
                    .get_document_mut("network")
                    .unwrap()
                    .remove("bytesIn");
                response
            },
            {
                let mut response = mongodb_response();
                response
                    .get_document_mut("opcounters")
                    .unwrap()
                    .insert("query", Bson::Double(1.0));
                response
            },
            {
                let mut response = mongodb_response();
                response.insert("uptime", -1_i64);
                response
            },
        ] {
            assert!(matches!(
                mongodb_metrics_from_document(&invalid),
                Err(WorkloadProbeError::Malformed(_))
            ));
        }
    }

    #[test]
    fn mongodb_metrics_reject_oversized_response() {
        let mut response = mongodb_response();
        response.insert("padding", "x".repeat(MONGODB_RESPONSE_BYTES));
        assert!(matches!(
            mongodb_metrics_from_document(&response),
            Err(WorkloadProbeError::Malformed(_))
        ));
    }

    #[test]
    fn mongodb_metric_variant_matches_only_mongodb_samples() {
        let metrics = mongodb_metrics_from_document(&mongodb_response()).unwrap();
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "mongodb".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::MongoDb,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:27017".into(),
                metrics: WorkloadMetrics::MongoDb(metrics),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("my_sql".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    fn prometheus_response() -> String {
        [
            "# HELP ignored comment",
            "unknown_metric 99",
            "prometheus_config_last_reload_successful 1",
            "prometheus_tsdb_head_series 2",
            "prometheus_tsdb_head_chunks 3",
            "prometheus_tsdb_head_samples_appended_total 4",
            "prometheus_engine_queries 5",
            "process_resident_memory_bytes 6",
            "process_virtual_memory_bytes 7",
            "go_goroutines 8",
        ]
        .join("\n")
    }

    #[test]
    fn prometheus_endpoint_maps_to_fixed_metrics_url_and_rejects_configuration_fields() {
        let tcp = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:9090".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        tcp.validate_for(WorkloadAdapter::Prometheus).unwrap();
        assert_eq!(
            prometheus_metrics_url(&tcp).unwrap(),
            "http://127.0.0.1:9090/metrics"
        );
        let tls = WorkloadConnectionConfig {
            endpoint: "tls://[::1]:9090".into(),
            ..tcp.clone()
        };
        assert_eq!(
            prometheus_metrics_url(&tls).unwrap(),
            "https://[::1]:9090/metrics"
        );
        for invalid in [
            WorkloadConnectionConfig {
                username: Some("monitor".into()),
                secret_ref: Some("env:PROM_PASSWORD".into()),
                ..tcp.clone()
            },
            WorkloadConnectionConfig {
                database: Some("metrics".into()),
                ..tcp.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..tcp.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/prometheus.sock".into(),
                ..tcp
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::Prometheus).is_err());
        }
    }

    #[test]
    fn prometheus_parser_requires_exact_label_free_u64_metrics() {
        let metrics = parse_prometheus_metrics(&prometheus_response()).unwrap();
        assert_eq!(metrics.tsdb_head_samples_appended_total, 4);
        assert_eq!(metrics.go_goroutines, 8);
        for replacement in [
            "prometheus_engine_queries{slice=\"inner_eval\"} 5",
            "prometheus_engine_queries NaN",
            "prometheus_engine_queries +Inf",
            "prometheus_engine_queries -1",
            "prometheus_engine_queries 1.5",
            "prometheus_engine_queries 18446744073709551616",
            "prometheus_engine_queries 1.5e0",
            "prometheus_engine_queries 1e2147483647",
            "prometheus_engine_queries 1e-2147483648",
        ] {
            let response =
                prometheus_response().replace("prometheus_engine_queries 5", replacement);
            assert!(matches!(
                parse_prometheus_metrics(&response),
                Err(WorkloadProbeError::Malformed(_))
            ));
        }
        let missing = prometheus_response().replace("go_goroutines 8", "");
        assert!(parse_prometheus_metrics(&missing).is_err());
        let duplicate = format!("{}\ngo_goroutines 9", prometheus_response());
        assert!(parse_prometheus_metrics(&duplicate).is_err());
        let scientific = prometheus_response()
            .replace(
                "prometheus_tsdb_head_samples_appended_total 4",
                "prometheus_tsdb_head_samples_appended_total 1.234e+06",
            )
            .replace(
                "prometheus_engine_queries 5",
                "prometheus_engine_queries 5.0e0",
            );
        let metrics = parse_prometheus_metrics(&scientific).unwrap();
        assert_eq!(metrics.tsdb_head_samples_appended_total, 1_234_000);
        assert_eq!(metrics.engine_queries, 5);
    }

    #[test]
    fn prometheus_metric_variant_matches_only_prometheus_samples() {
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "prometheus".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::Prometheus,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:9090".into(),
                metrics: WorkloadMetrics::Prometheus(
                    parse_prometheus_metrics(&prometheus_response()).unwrap(),
                ),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("redis".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    fn clickhouse_response() -> String {
        [
            "Query\t1",
            "Merge\t2",
            "PartMutation\t3",
            "ReplicatedFetch\t4",
            "ReplicatedSend\t5",
            "TCPConnection\t6",
            "HTTPConnection\t7",
            "MemoryTracking\t8",
            "Uptime\t9",
            "MemoryResident\t10",
        ]
        .join("\n")
    }

    #[test]
    fn clickhouse_endpoint_and_auth_contract_are_strict() {
        let anonymous = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:8123".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        anonymous.validate_for(WorkloadAdapter::ClickHouse).unwrap();
        assert_eq!(
            clickhouse_http_url(&anonymous).unwrap(),
            "http://127.0.0.1:8123/"
        );
        let authenticated = WorkloadConnectionConfig {
            endpoint: "tls://[::1]:8443".into(),
            username: Some("monitor".into()),
            secret_ref: Some("env:CLICKHOUSE_PASSWORD".into()),
            database: None,
            auth_source: None,
        };
        authenticated
            .validate_for(WorkloadAdapter::ClickHouse)
            .unwrap();
        assert_eq!(
            clickhouse_http_url(&authenticated).unwrap(),
            "https://[::1]:8443/"
        );
        for invalid in [
            WorkloadConnectionConfig {
                secret_ref: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                username: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                database: Some("system".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/clickhouse.sock".into(),
                ..authenticated
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::ClickHouse).is_err());
        }
    }

    #[test]
    fn clickhouse_parser_requires_exact_allowlisted_u64_rows() {
        let metrics = parse_clickhouse_metrics(&clickhouse_response()).unwrap();
        assert_eq!(metrics.queries, 1);
        assert_eq!(metrics.memory_resident_bytes, 10);
        for invalid in [
            clickhouse_response().replace("Uptime\t9", ""),
            format!("{}\nQuery\t11", clickhouse_response()),
            clickhouse_response().replace("Query\t1", "Unknown\t1"),
            clickhouse_response().replace("Query\t1", "Query\t1\textra"),
            clickhouse_response().replace("Query\t1", "Query\t-1"),
            clickhouse_response().replace("Query\t1", "Query\t1.5"),
            clickhouse_response().replace("Query\t1", "Query\t18446744073709551616"),
        ] {
            assert!(matches!(
                parse_clickhouse_metrics(&invalid),
                Err(WorkloadProbeError::Malformed(_))
            ));
        }
    }

    #[test]
    fn clickhouse_metric_variant_matches_only_clickhouse_samples() {
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "clickhouse".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::ClickHouse,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:8123".into(),
                metrics: WorkloadMetrics::ClickHouse(
                    parse_clickhouse_metrics(&clickhouse_response()).unwrap(),
                ),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("prometheus".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    fn etcd_response() -> String {
        [
            "# HELP ignored comment",
            "unknown_metric 99",
            "etcd_server_has_leader 1",
            "etcd_server_is_leader 0",
            "etcd_server_leader_changes_seen_total 2",
            "etcd_server_proposals_applied_total 3",
            "etcd_server_proposals_committed_total 4",
            "etcd_server_proposals_failed_total 5",
            "etcd_server_proposals_pending 6",
            "etcd_mvcc_db_total_size_in_bytes 7",
            "etcd_mvcc_db_total_size_in_use_in_bytes 8",
            "process_resident_memory_bytes 9",
        ]
        .join("\n")
    }

    #[test]
    fn etcd_endpoint_maps_to_metrics_and_rejects_configuration_fields() {
        let tcp = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:2379".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        tcp.validate_for(WorkloadAdapter::Etcd).unwrap();
        assert_eq!(
            etcd_metrics_url(&tcp).unwrap(),
            "http://127.0.0.1:2379/metrics"
        );
        let tls = WorkloadConnectionConfig {
            endpoint: "tls://[::1]:2379".into(),
            ..tcp.clone()
        };
        assert_eq!(
            etcd_metrics_url(&tls).unwrap(),
            "https://[::1]:2379/metrics"
        );
        for invalid in [
            WorkloadConnectionConfig {
                username: Some("monitor".into()),
                ..tcp.clone()
            },
            WorkloadConnectionConfig {
                secret_ref: Some("env:ETCD_PASSWORD".into()),
                ..tcp.clone()
            },
            WorkloadConnectionConfig {
                database: Some("metrics".into()),
                ..tcp.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..tcp.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/etcd.sock".into(),
                ..tcp
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::Etcd).is_err());
        }
    }

    #[test]
    fn etcd_parser_requires_exact_label_free_u64_metrics_and_boolean_gauges() {
        let metrics = parse_etcd_metrics(&etcd_response()).unwrap();
        assert_eq!(metrics.server_has_leader, 1);
        assert_eq!(metrics.process_resident_memory_bytes, 9);
        for invalid in [
            etcd_response().replace("etcd_server_has_leader 1", ""),
            format!("{}\netcd_server_has_leader 1", etcd_response()),
            etcd_response().replace(
                "etcd_server_has_leader 1",
                "etcd_server_has_leader{instance=\"local\"} 1",
            ),
            etcd_response().replace("etcd_server_has_leader 1", "etcd_server_has_leader 2"),
            etcd_response().replace("etcd_server_is_leader 0", "etcd_server_is_leader -1"),
            etcd_response().replace(
                "etcd_server_proposals_pending 6",
                "etcd_server_proposals_pending 1.5",
            ),
            etcd_response().replace(
                "process_resident_memory_bytes 9",
                "process_resident_memory_bytes 18446744073709551616",
            ),
            etcd_response().replace(
                "etcd_server_proposals_pending 6",
                "etcd_server_proposals_pending 1e2147483647",
            ),
        ] {
            assert!(matches!(
                parse_etcd_metrics(&invalid),
                Err(WorkloadProbeError::Malformed(_))
            ));
        }
        let scientific = etcd_response().replace(
            "etcd_server_proposals_applied_total 3",
            "etcd_server_proposals_applied_total 1.234e+06",
        );
        assert_eq!(
            parse_etcd_metrics(&scientific)
                .unwrap()
                .proposals_applied_total,
            1_234_000
        );
    }

    #[test]
    fn etcd_metric_variant_matches_only_etcd_samples() {
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "etcd".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::Etcd,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:2379".into(),
                metrics: WorkloadMetrics::Etcd(parse_etcd_metrics(&etcd_response()).unwrap()),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("click_house".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    fn search_response() -> serde_json::Value {
        serde_json::json!({
            "_nodes": { "total": 3, "successful": 3, "failed": 0 },
            "indices": {
                "count": 4,
                "shards": { "total": 5, "primaries": 2 },
                "docs": { "count": 6, "deleted": 7 },
                "store": { "size_in_bytes": 8 }
            },
            "nodes": {
                "count": { "total": 3 },
                "fs": { "total_in_bytes": 10, "available_in_bytes": 9 }
            },
            "unknown": true
        })
    }

    #[test]
    fn search_endpoint_and_auth_contract_are_strict() {
        let anonymous = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:9200".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        for adapter in [WorkloadAdapter::Elasticsearch, WorkloadAdapter::OpenSearch] {
            anonymous.validate_for(adapter).unwrap();
        }
        assert_eq!(
            search_cluster_stats_url(&anonymous).unwrap(),
            "http://127.0.0.1:9200/_cluster/stats?timeout=2s"
        );
        let authenticated = WorkloadConnectionConfig {
            endpoint: "tls://[::1]:9200".into(),
            username: Some("monitor".into()),
            secret_ref: Some("env:SEARCH_PASSWORD".into()),
            ..anonymous.clone()
        };
        authenticated
            .validate_for(WorkloadAdapter::Elasticsearch)
            .unwrap();
        assert_eq!(
            search_cluster_stats_url(&authenticated).unwrap(),
            "https://[::1]:9200/_cluster/stats?timeout=2s"
        );
        for invalid in [
            WorkloadConnectionConfig {
                secret_ref: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                username: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                database: Some("index".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/search.sock".into(),
                ..authenticated
            },
        ] {
            assert!(invalid
                .validate_for(WorkloadAdapter::Elasticsearch)
                .is_err());
            assert!(invalid.validate_for(WorkloadAdapter::OpenSearch).is_err());
        }
    }

    #[test]
    fn search_parser_requires_exact_u64_paths_and_invariants() {
        let metrics = parse_search_metrics(&search_response()).unwrap();
        assert_eq!(metrics.nodes_total, 3);
        assert_eq!(metrics.fs_available_bytes, 9);
        let mut invalid = search_response();
        invalid["indices"]["shards"]["primaries"] = serde_json::json!(6);
        assert!(parse_search_metrics(&invalid).is_err());
        let mut invalid = search_response();
        invalid["nodes"]["fs"]["available_in_bytes"] = serde_json::json!(11);
        assert!(parse_search_metrics(&invalid).is_err());
        let mut invalid = search_response();
        invalid["_nodes"]["failed"] = serde_json::json!(1);
        assert!(parse_search_metrics(&invalid).is_err());
        let mut invalid = search_response();
        invalid["indices"]["docs"]["count"] = serde_json::json!(-1);
        assert!(parse_search_metrics(&invalid).is_err());
        let mut invalid = search_response();
        invalid["indices"]["docs"]
            .as_object_mut()
            .unwrap()
            .remove("count");
        assert!(parse_search_metrics(&invalid).is_err());
    }

    #[test]
    fn search_metric_variants_are_adapter_specific() {
        let metrics = parse_search_metrics(&search_response()).unwrap();
        let samples = [
            WorkloadSample {
                schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
                workload_id: "elasticsearch".into(),
                captured_at: Utc::now(),
                adapter: WorkloadAdapter::Elasticsearch,
                outcome: WorkloadSampleOutcome::Collected {
                    endpoint: "tcp://127.0.0.1:9200".into(),
                    metrics: WorkloadMetrics::Elasticsearch(metrics.clone().into()),
                },
            },
            WorkloadSample {
                schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
                workload_id: "opensearch".into(),
                captured_at: Utc::now(),
                adapter: WorkloadAdapter::OpenSearch,
                outcome: WorkloadSampleOutcome::Collected {
                    endpoint: "tcp://127.0.0.1:9200".into(),
                    metrics: WorkloadMetrics::OpenSearch(metrics.into()),
                },
            },
        ];
        for sample in samples {
            let json = serde_json::to_string(&sample).unwrap();
            assert_eq!(
                serde_json::from_str::<WorkloadSample>(&json).unwrap(),
                sample
            );
            let mut mismatched = serde_json::to_value(&sample).unwrap();
            mismatched["adapter"] = serde_json::Value::String("redis".into());
            assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
        }
    }

    fn rabbitmq_response() -> serde_json::Value {
        serde_json::json!({
            "queue_totals": { "messages": 1, "messages_ready": 2, "messages_unacknowledged": 3 },
            "object_totals": { "queues": 4, "connections": 5, "channels": 6, "consumers": 7, "exchanges": 8 },
            "message_stats": { "publish": 9, "deliver_get": 10 },
            "rabbitmq_version": "secret-metadata"
        })
    }

    #[test]
    fn rabbitmq_endpoint_and_auth_contract_are_strict() {
        let anonymous = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:15672".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        anonymous.validate_for(WorkloadAdapter::RabbitMq).unwrap();
        assert_eq!(
            rabbitmq_overview_url(&anonymous).unwrap(),
            "http://127.0.0.1:15672/api/overview"
        );
        let authenticated = WorkloadConnectionConfig {
            endpoint: "tls://[::1]:15672".into(),
            username: Some("monitor".into()),
            secret_ref: Some("env:RABBITMQ_PASSWORD".into()),
            ..anonymous.clone()
        };
        authenticated
            .validate_for(WorkloadAdapter::RabbitMq)
            .unwrap();
        assert_eq!(
            rabbitmq_overview_url(&authenticated).unwrap(),
            "https://[::1]:15672/api/overview"
        );
        assert!(WorkloadConnectionConfig {
            endpoint: "tcp://rabbitmq.example:15672".into(),
            ..authenticated.clone()
        }
        .validate_for(WorkloadAdapter::RabbitMq)
        .is_err());
        for invalid in [
            WorkloadConnectionConfig {
                secret_ref: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                username: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                database: Some("vhost".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/rabbitmq.sock".into(),
                ..authenticated
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::RabbitMq).is_err());
        }
    }

    #[test]
    fn rabbitmq_parser_requires_core_u64_and_defaults_only_missing_message_stats() {
        let metrics = parse_rabbitmq_metrics(&rabbitmq_response()).unwrap();
        assert_eq!(metrics.queues, 4);
        assert_eq!(metrics.message_stats_deliver_get_total, 10);
        let mut missing = rabbitmq_response();
        missing.as_object_mut().unwrap().remove("message_stats");
        let metrics = parse_rabbitmq_metrics(&missing).unwrap();
        assert_eq!(metrics.message_stats_publish_total, 0);
        let mut missing_key = rabbitmq_response();
        missing_key["message_stats"]
            .as_object_mut()
            .unwrap()
            .remove("publish");
        assert_eq!(
            parse_rabbitmq_metrics(&missing_key)
                .unwrap()
                .message_stats_publish_total,
            0
        );
        let mut wrong = rabbitmq_response();
        wrong["message_stats"]["publish"] = serde_json::json!("9");
        assert!(parse_rabbitmq_metrics(&wrong).is_err());
        let mut missing_core = rabbitmq_response();
        missing_core["queue_totals"]
            .as_object_mut()
            .unwrap()
            .remove("messages");
        assert!(parse_rabbitmq_metrics(&missing_core).is_err());
        let mut negative = rabbitmq_response();
        negative["object_totals"]["queues"] = serde_json::json!(-1);
        assert!(parse_rabbitmq_metrics(&negative).is_err());
    }

    #[test]
    fn rabbitmq_metric_variant_matches_only_rabbitmq_samples() {
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "rabbitmq".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::RabbitMq,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:15672".into(),
                metrics: WorkloadMetrics::RabbitMq(
                    parse_rabbitmq_metrics(&rabbitmq_response()).unwrap(),
                ),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("redis".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    #[test]
    fn nginx_endpoint_and_auth_contract_are_strict() {
        let anonymous = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:8080".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        anonymous.validate_for(WorkloadAdapter::Nginx).unwrap();
        assert_eq!(
            nginx_stub_status_url(&anonymous).unwrap(),
            "http://127.0.0.1:8080/stub_status"
        );
        let authenticated = WorkloadConnectionConfig {
            endpoint: "tls://[::1]:8443".into(),
            username: Some("monitor".into()),
            secret_ref: Some("env:NGINX_PASSWORD".into()),
            ..anonymous.clone()
        };
        authenticated.validate_for(WorkloadAdapter::Nginx).unwrap();
        assert_eq!(
            nginx_stub_status_url(&authenticated).unwrap(),
            "https://[::1]:8443/stub_status"
        );
        assert!(WorkloadConnectionConfig {
            endpoint: "tcp://nginx.example:8080".into(),
            ..authenticated.clone()
        }
        .validate_for(WorkloadAdapter::Nginx)
        .is_err());
        for invalid in [
            WorkloadConnectionConfig {
                secret_ref: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                username: None,
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                database: Some("status".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..authenticated.clone()
            },
            WorkloadConnectionConfig {
                endpoint: "unix:///run/nginx.sock".into(),
                ..authenticated
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::Nginx).is_err());
        }
    }

    #[test]
    fn nginx_parser_requires_official_four_line_format_and_invariants() {
        let valid = "Active connections: 291\nserver accepts handled requests\n 16630948 16630948 31070465\nReading: 6 Writing: 179 Waiting: 106\n";
        let metrics = parse_nginx_stub_status(valid).unwrap();
        assert_eq!(metrics.active_connections, 291);
        assert_eq!(metrics.requests_total, 31_070_465);
        for invalid in [
            "Active connections: 1\nserver accepts handled requests\n1 1 1\nReading: 0 Writing: 0 Waiting: 0\nextra\n",
            "Active connections: 1\nserver accepts handled requests\n1 2 3\nReading: 0 Writing: 0 Waiting: 0\n",
            "Active connections: 1\nserver accepts handled requests\n1 1 3\nReading: 1 Writing: 1 Waiting: 0\n",
            "Active connections: 2\nserver accepts handled requests\n1 1 3\nReading: 1 Writing: 0 Waiting: 0\n",
            "Active connections: 1\nserver accepts handled requests\n1 1 3\nReading: 18446744073709551615 Writing: 1 Waiting: 0\n",
            "Active connections: x\nserver accepts handled requests\n1 1 3\nReading: 0 Writing: 0 Waiting: 0\n",
        ] { assert!(matches!(parse_nginx_stub_status(invalid), Err(WorkloadProbeError::Malformed(_)))); }
    }

    #[test]
    fn nginx_metric_variant_matches_only_nginx_samples() {
        let metrics = parse_nginx_stub_status("Active connections: 3\nserver accepts handled requests\n4 4 5\nReading: 1 Writing: 1 Waiting: 1\n").unwrap();
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "nginx".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::Nginx,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:8080".into(),
                metrics: WorkloadMetrics::Nginx(metrics),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
        let mut mismatched = serde_json::to_value(&sample).unwrap();
        mismatched["adapter"] = serde_json::Value::String("redis".into());
        assert!(serde_json::from_value::<WorkloadSample>(mismatched).is_err());
    }

    fn haproxy_csv() -> &'static str {
        "# pxname,svname,scur,stot,bin,bout,dreq,dresp,econ,wretr,status\n\"front,end\",FRONTEND,2,3,4,5,6,,,,OPEN\nbackend,BACKEND,,,,,,7,8,9,UP\nbackend,server1,,,,,,,,,DOWN\nbackend,server2,,,,,,,,,MAINT\n\n"
    }

    #[test]
    fn haproxy_requires_an_explicit_unix_endpoint_without_other_fields() {
        let valid = WorkloadConnectionConfig {
            endpoint: "unix:///run/haproxy/admin.sock".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        valid.validate_for(WorkloadAdapter::HaProxy).unwrap();
        for invalid in [
            WorkloadConnectionConfig {
                endpoint: "tcp://127.0.0.1:8404".into(),
                ..valid.clone()
            },
            WorkloadConnectionConfig {
                username: Some("monitor".into()),
                ..valid.clone()
            },
            WorkloadConnectionConfig {
                secret_ref: Some("env:HAPROXY_PASSWORD".into()),
                ..valid.clone()
            },
            WorkloadConnectionConfig {
                database: Some("stats".into()),
                ..valid.clone()
            },
            WorkloadConnectionConfig {
                auth_source: Some("admin".into()),
                ..valid
            },
        ] {
            assert!(invalid.validate_for(WorkloadAdapter::HaProxy).is_err());
        }
    }

    #[test]
    fn haproxy_csv_parser_handles_quotes_aggregates_and_down_servers() {
        let metrics = parse_haproxy_stats(haproxy_csv()).unwrap();
        assert_eq!(metrics.current_sessions, 2);
        assert_eq!(metrics.sessions_total, 3);
        assert_eq!(metrics.denied_responses_total, 7);
        assert_eq!(metrics.retry_warnings_total, 9);
        assert_eq!(metrics.servers_down, 2);
        let reordered = "status,wretr,econ,dresp,dreq,bout,bin,stot,scur,svname,pxname\r\nOPEN,,,,6,5,4,3,2,FRONTEND,front\r\nUP,9,8,7,,,,,,BACKEND,back\r\n";
        assert_eq!(
            parse_haproxy_stats(reordered)
                .unwrap()
                .failed_connections_total,
            8
        );
        for invalid in [
            "# pxname,svname,scur,stot,bin,bout,dreq,dresp,econ,wretr,status\n",
            "# pxname,svname,scur,stot,bin,bout,dreq,dresp,econ,wretr,status\na,FRONTEND,no,1,1,1,1,,,,OPEN\n",
            "# pxname,svname,scur,stot,bin,bout,dreq,dresp,econ,wretr\na,FRONTEND,1,1,1,1,1,,,\n",
        ] { assert!(parse_haproxy_stats(invalid).is_err()); }
    }

    #[cfg(unix)]
    #[test]
    fn haproxy_stream_sends_fixed_command() {
        let mut stream = TestStream::response(haproxy_csv());
        assert_eq!(monitor_haproxy_stream(&mut stream).unwrap().servers_down, 2);
        assert_eq!(stream.output, HAPROXY_STATS_COMMAND);
    }

    #[cfg(unix)]
    #[test]
    fn unix_connect_timeout_rejects_invalid_and_missing_paths() {
        let too_long = PathBuf::from(format!("/tmp/{}", "x".repeat(200)));
        assert!(matches!(
            connect_unix_with_timeout(&too_long, Duration::from_millis(10)),
            Err(WorkloadProbeError::Malformed(_))
        ));
        assert!(matches!(
            connect_unix_with_timeout(
                Path::new("/tmp/aic-definitely-missing-haproxy.sock"),
                Duration::from_millis(10)
            ),
            Err(WorkloadProbeError::Unreachable(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_connect_timeout_sets_close_on_exec() {
        use std::os::fd::AsRawFd;

        let temp = std::env::temp_dir().join(format!(
            "aic-haproxy-connect-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir(&temp).unwrap();
        let path = temp.join("stats.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let stream = connect_unix_with_timeout(&path, Duration::from_millis(100)).unwrap();
        let accepted = listener.accept().unwrap().0;
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        drop(accepted);
        drop(listener);
        fs::remove_file(path).unwrap();
        fs::remove_dir(temp).unwrap();
    }

    #[test]
    fn haproxy_metric_variant_round_trips_without_socket_path() {
        let sample = WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: "haproxy".into(),
            captured_at: Utc::now(),
            adapter: WorkloadAdapter::HaProxy,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "local-unix-socket".into(),
                metrics: WorkloadMetrics::HaProxy(parse_haproxy_stats(haproxy_csv()).unwrap()),
            },
        };
        let json = serde_json::to_string(&sample).unwrap();
        assert!(!json.contains("/run/haproxy"));
        assert_eq!(
            serde_json::from_str::<WorkloadSample>(&json).unwrap(),
            sample
        );
    }

    #[test]
    fn workload_connection_accepts_only_safe_endpoint_and_secret_reference_shapes() {
        let valid = WorkloadConnectionConfig {
            endpoint: "tls://redis.example:6380".into(),
            username: Some("monitor".into()),
            secret_ref: Some("env:REDIS_PASSWORD".into()),
            database: None,
            auth_source: None,
        };
        valid.validate_for(WorkloadAdapter::Redis).unwrap();
        assert!(matches!(
            valid.endpoint().unwrap(),
            WorkloadEndpoint::Tls { .. }
        ));
        for endpoint in [
            "tcp://host",
            "tcp://user@host:6379",
            "tcp://host:6379/?x",
            "unix://relative",
        ] {
            assert!(WorkloadConnectionConfig {
                endpoint: endpoint.into(),
                username: None,
                secret_ref: None,
                database: None,
                auth_source: None,
            }
            .endpoint()
            .is_err());
        }
        assert!(WorkloadConnectionConfig {
            endpoint: "tcp://host:6379".into(),
            username: None,
            secret_ref: Some("plaintext".into()),
            database: None,
            auth_source: None,
        }
        .validate_for(WorkloadAdapter::Redis)
        .is_err());
        assert_eq!(
            WorkloadConnectionConfig {
                endpoint: "tcp://[::1]:6379".into(),
                username: None,
                secret_ref: None,
                database: None,
                auth_source: None,
            }
            .endpoint()
            .unwrap(),
            WorkloadEndpoint::Tcp {
                host: "::1".into(),
                port: 6379,
            }
        );
    }

    #[test]
    fn memcached_connection_rejects_authentication() {
        let config = WorkloadConnectionConfig {
            endpoint: "tcp://127.0.0.1:11211".into(),
            username: None,
            secret_ref: Some("env:MEMCACHED_PASSWORD".into()),
            database: None,
            auth_source: None,
        };
        assert!(config.validate_for(WorkloadAdapter::Memcached).is_err());
    }

    #[test]
    fn redis_auth_framing_does_not_return_secret_in_error() {
        let mut stream = TestStream::response("-ERR invalid password secret-value\r\n");
        let error =
            monitor_redis_authenticated_stream(&mut stream, Some("monitor"), Some("secret-value"))
                .unwrap_err();
        assert!(matches!(error, RedisProbeError::Rejected(_)));
        assert!(!error.to_string().contains("secret-value"));
        assert_eq!(
            stream.output,
            b"*3\r\n$4\r\nAUTH\r\n$7\r\nmonitor\r\n$12\r\nsecret-value\r\n"
        );
    }

    #[test]
    fn redis_custom_connection_passes_the_validated_endpoint_to_connector() {
        let body = concat!(
            "connected_clients:1\r\nused_memory:2\r\n",
            "total_commands_processed:3\r\ninstantaneous_ops_per_sec:4\r\n",
            "keyspace_hits:5\r\nkeyspace_misses:6\r\n"
        );
        let response = format!("${}\r\n{}\r\n", body.len(), body);
        let connection = WorkloadConnectionConfig {
            endpoint: "tcp://redis.internal:6379".into(),
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        };
        let metrics = monitor_redis_with_connector(&connection, |endpoint| {
            assert_eq!(
                endpoint,
                &WorkloadEndpoint::Tcp {
                    host: "redis.internal".into(),
                    port: 6379
                }
            );
            Ok(TestStream::response(&response))
        })
        .unwrap();
        assert_eq!(metrics.connected_clients, 1);
    }

    #[test]
    fn tls_config_uses_native_roots_without_a_network_connection() {
        let result = tls_client_config();
        assert!(
            result.is_ok(),
            "native TLS roots must construct a client config"
        );
        assert!(ServerName::try_from("redis.example".to_string()).is_ok());
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
        assert!(json.get("adapter").is_none());
        assert_eq!(
            serde_json::from_value::<RedisMonitorReport>(json).unwrap(),
            report
        );
    }

    #[test]
    fn redis_probe_rejects_noauth_and_malformed_responses() {
        assert!(matches!(
            read_redis_info_response(&mut Cursor::new(b"-NOAUTH Authentication required.\r\n"), 128),
            Err(RedisProbeError::Rejected(detail)) if detail == "Redis rejected request"
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
            adapter: WorkloadAdapter::Redis,
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
                adapter: WorkloadAdapter::Redis,
                outcome: RedisSampleOutcome::Collected {
                    endpoint: REDIS_LOOPBACK_ENDPOINT.into(),
                    metrics: WorkloadMetrics::Redis(RedisMetrics {
                        connected_clients: 1,
                        used_memory: 2,
                        total_commands_processed: 3,
                        instantaneous_ops_per_sec: 4,
                        keyspace_hits: 5,
                        keyspace_misses: 6,
                    }),
                },
            },
            RedisWorkloadSample {
                schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
                workload_id: "redis".into(),
                captured_at,
                adapter: WorkloadAdapter::Redis,
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

    #[test]
    fn old_redis_sample_json_loads_as_a_generic_sample() {
        let old = r#"{
            "schema_version":1,
            "workload_id":"redis",
            "captured_at":"2026-09-14T00:00:00Z",
            "outcome":"collected",
            "endpoint":"127.0.0.1:6379",
            "metrics":{"connected_clients":1,"used_memory":2,"total_commands_processed":3,"instantaneous_ops_per_sec":4,"keyspace_hits":5,"keyspace_misses":6}
        }"#;
        let sample: WorkloadSample = serde_json::from_str(old).unwrap();
        assert_eq!(sample.adapter, WorkloadAdapter::Redis);
        assert!(matches!(
            sample.outcome,
            WorkloadSampleOutcome::Collected {
                metrics: WorkloadMetrics::Redis(_),
                ..
            }
        ));
        let mismatched = r#"{
            "schema_version":1,
            "workload_id":"memcached",
            "captured_at":"2026-09-14T00:00:00Z",
            "adapter":"memcached",
            "outcome":"collected",
            "endpoint":"127.0.0.1:11211",
            "metrics":{"connected_clients":1,"used_memory":2,"total_commands_processed":3,"instantaneous_ops_per_sec":4,"keyspace_hits":5,"keyspace_misses":6}
        }"#;
        assert!(serde_json::from_str::<WorkloadSample>(mismatched).is_err());
    }

    #[test]
    fn memcached_stream_requires_complete_valid_stats() {
        let response = concat!(
            "STAT curr_connections 1\r\nSTAT bytes 2\r\nSTAT cmd_get 3\r\n",
            "STAT cmd_set 4\r\nSTAT get_hits 5\r\nSTAT get_misses 6\r\n",
            "STAT evictions 7\r\nEND\r\n"
        );
        let mut stream = TestStream::response(response);
        let metrics = monitor_memcached_stream(&mut stream).unwrap();
        assert_eq!(stream.output, MEMCACHED_STATS_REQUEST);
        assert_eq!(metrics.curr_connections, 1);
        assert_eq!(metrics.evictions, 7);

        for invalid in [
            "STAT curr_connections 1\r\n",
            "STAT curr_connections 1\r\nSTAT curr_connections 2\r\nEND\r\n",
            "STAT curr_connections 18446744073709551616\r\nEND\r\n",
        ] {
            let mut stream = TestStream::response(invalid);
            assert!(monitor_memcached_stream(&mut stream).is_err());
        }
    }
}
