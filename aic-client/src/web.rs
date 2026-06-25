//! `aic web` — 로컬 자원 모니터 + read-only 공유 대시보드 (MVP).
//!
//! `aic chat`의 agentic 실행면(run_command·LLM chat)은 **노출하지 않는다**. 핵심은 aic가 이미
//! 수집하는 **로컬 호스트 자원 텔레메트리**(status bar의 `SysSampler`)를 시계열 차트로 보여주는 것
//! — 외부 관측 백엔드가 없어도 바로 동작한다. 엔드포인트:
//! - `GET  /`                        — 자체완결 대시보드(외부 CDN 없음 — VPN/오프라인 대응)
//! - `GET  /web/local`               — 로컬 자원 시계열(CPU/mem/load/disk·net I/O) — **무설정 동작**
//! - `GET  /web/snapshots`           — 스냅샷 store(`~/.aic/snapshots/`) JSON
//! - `GET  /web/incidents`           — RCA 인시던트 목록 JSON(redacted, path 제외)
//! - `GET  /web/incidents/{id}/report` — RCA report.md(redaction 재적용) markdown
//! - `GET  /web/audit`               — aicd 감사 로그(`audit.log`) tail(redacted)
//! - `GET  /web/history`             — aicd CommandRecordStore 최근 세션 명령(없으면 available:false)
//! - `GET  /web/webhooks`            — webhook alert ingestion 이벤트 tail(redacted, 없으면 빈 목록)
//! - `GET  /web/config`              — 현재 config 요약(토큰/secret 미노출)
//! - `GET  /web/backends`            — 등록된 Prometheus/Loki 백엔드 이름(없으면 빈 목록)
//! - `POST /web/metrics`·`/web/logs` — (선택) 등록된 Prometheus/Loki 질의. 백엔드 없으면 503.
//!
//! 노출은 **on-demand**(`aic web --bind`, 기본 미기동) + **토큰 필수**. 데이터 엔드포인트(`/web/*`)는
//! Bearer 토큰을 요구하고, 대시보드 셸(`/`, `/web/health`)만 면제한다(민감 데이터 없음 — 사용자가
//! 페이지에서 토큰 입력 → JS가 이후 fetch에 Bearer로 싣는다).

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{Path, Request, State},
    http::{
        header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS},
        StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::agent::obs_tools::ObsClient;
use crate::agent::sys_sampler::SysSampler;
use crate::config::ConfigManager;
use crate::history::resolve_session_id;
use crate::uds_client::UdsClient;
use crate::{audit, rca, redaction, snapshot_store, snapshot_timer};
use sysinfo::{Disks, Networks, ProcessRefreshKind, ProcessesToUpdate, System};

/// 대시보드 셸(자체완결 HTML+JS, 외부 의존 없음).
const DASHBOARD: &str = include_str!("web_dashboard.html");

/// 로컬 자원 샘플링 주기(status bar와 동일 감각). disk/net bps는 연속 sample 간 delta라 일정 주기가 필요.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
/// ring buffer 상한 — 2s × 300 = 10분 history.
const RING_CAP: usize = 300;
/// 각 store 조회 시 반환할 tail 상한(대시보드 표시용 — 전량 직렬화 방지).
const AUDIT_TAIL: usize = 200;
const WEBHOOK_TAIL: usize = 100;
const HISTORY_TAIL: usize = 50;
/// runtime health는 audit verify 등 파일 IO를 포함하므로 resource 샘플보다 느슨하게 갱신한다.
const RUNTIME_HEALTH_INTERVAL: Duration = Duration::from_secs(10);
/// resource 탭 top process 목록 길이. 너무 길면 2초 샘플마다 JSON payload와 UI scan 비용이 커진다.
const TOP_PROCESS_LIMIT: usize = 5;
/// resource 이벤트 timeline 상한. 상태 전환만 남겨 payload와 시각 noise를 제한한다.
const RESOURCE_EVENT_LIMIT: usize = 50;

const STATUS_OK: &str = "ok";
const STATUS_WARN: &str = "warn";
const STATUS_CRIT: &str = "crit";
const STATUS_UNAVAILABLE: &str = "unavailable";

/// resource 탭에 표시할 프로세스 요약. command line/env/cwd는 노출하지 않는다.
#[derive(Serialize, Clone)]
struct ProcessSample {
    name: String,
    pid: String,
    cpu_pct: f32,
    memory: u64,
}

#[derive(Serialize, Clone)]
struct HostIdentity {
    hostname: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    kernel_version: Option<String>,
    arch: &'static str,
    uptime_secs: u64,
    boot_time_secs: u64,
    aic_version: &'static str,
}

#[derive(Serialize, Clone)]
struct DiskSample {
    name: String,
    file_system: String,
    mount_point: String,
    total: u64,
    available: u64,
    used: u64,
    used_pct: f64,
    read_only: bool,
}

#[derive(Serialize, Clone)]
struct NetworkSample {
    name: String,
    rx_bps: u64,
    tx_bps: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    mac: String,
    loopback: bool,
}

#[derive(Serialize, Clone)]
struct ProcessPressure {
    process_count: usize,
    thread_count: Option<usize>,
    fd_open: Option<u64>,
    fd_limit: Option<u64>,
    fd_pct: Option<f64>,
    fd_status: &'static str,
    fd_scope: &'static str,
    fd_error: Option<String>,
}

#[derive(Serialize, Clone)]
struct ResourceEvent {
    /// unix epoch milliseconds.
    ts: i64,
    severity: &'static str,
    resource: String,
    value: String,
}

#[derive(Clone)]
struct WebResourceSample {
    top_cpu_procs: Vec<ProcessSample>,
    top_mem_procs: Vec<ProcessSample>,
    host: HostIdentity,
    disks: Vec<DiskSample>,
    networks: Vec<NetworkSample>,
    process_pressure: ProcessPressure,
    events: Vec<ResourceEvent>,
}

/// 한 시점 로컬 자원 스냅샷(차트용 직렬화 DTO). 프로세스 요약은 name/pid와 수치만 담는다.
#[derive(Serialize, Clone)]
struct LocalPoint {
    /// unix epoch milliseconds.
    ts: i64,
    cpu_pct: f32,
    load1: f64,
    cores: usize,
    mem_used: u64,
    mem_total: u64,
    swap_used: u64,
    swap_total: u64,
    disk_avail: u64,
    disk_total: u64,
    disk_read_bps: u64,
    disk_write_bps: u64,
    net_rx_bps: u64,
    net_tx_bps: u64,
    top_cpu_proc: Option<ProcessSample>,
    top_mem_proc: Option<ProcessSample>,
    top_cpu_procs: Vec<ProcessSample>,
    top_mem_procs: Vec<ProcessSample>,
    host: HostIdentity,
    disks: Vec<DiskSample>,
    networks: Vec<NetworkSample>,
    process_pressure: ProcessPressure,
    events: Vec<ResourceEvent>,
}

/// web 서버 구성. `token`은 빈 문자열이 아니어야 한다(호출부 `handle_web`에서 보장).
/// `obs_config`는 선택 — 등록 백엔드(Prometheus/Loki)가 있으면 외부 metrics/logs 탭이 활성화된다.
pub struct WebConfig {
    pub bind: String,
    pub token: String,
    pub obs_config: aic_common::ObservabilityConfig,
}

struct WebState {
    token: String,
    /// 로컬 자원 시계열 ring buffer(백그라운드 샘플러가 채운다). 무설정 동작의 핵심.
    local: Arc<Mutex<VecDeque<LocalPoint>>>,
    /// aic runtime 상태(aicd/session/snapshot/audit). 별도 주기로 갱신해 `/web/local`에 합친다.
    runtime: Arc<Mutex<Value>>,
    /// 등록 관측 백엔드가 있을 때만 Some. 없으면 외부 metrics/logs는 503.
    obs: Option<ObsClient>,
}

/// 대시보드를 `cfg.bind`에 바인드하고 Ctrl+C까지 서빙한다. 동시에 로컬 자원 샘플러를 백그라운드로 돌린다.
pub async fn serve(cfg: WebConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    let obs = ObsClient::new(&cfg.obs_config)
        .ok()
        .filter(|c| !c.is_empty());
    let local: Arc<Mutex<VecDeque<LocalPoint>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(RING_CAP)));
    spawn_local_sampler(local.clone());
    let runtime = Arc::new(Mutex::new(json!({
        "ts": chrono::Utc::now().timestamp_millis(),
        "status": "warming",
    })));
    spawn_runtime_health_sampler(runtime.clone());

    let state = Arc::new(WebState {
        token: cfg.token,
        local,
        runtime,
        obs,
    });

    let app = Router::new()
        .route("/web/health", get(|| async { "ok" }))
        .route("/", get(dashboard))
        .route("/web/local", get(local_metrics))
        .route("/web/snapshots", get(snapshots))
        .route("/web/incidents", get(incidents))
        .route("/web/incidents/{id}/report", get(incident_report))
        .route("/web/audit", get(audit_log))
        .route("/web/history", get(history))
        .route("/web/webhooks", get(webhooks))
        .route("/web/config", get(config_view))
        .route("/web/backends", get(backends))
        .route("/web/metrics", post(metrics))
        .route("/web/logs", post(logs))
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// 백그라운드 로컬 자원 샘플러 — [`SAMPLE_INTERVAL`]마다 호스트 자원을 측정해 ring buffer에 쌓는다.
/// disk/net bps는 연속 sample 간 delta이므로 일정 주기 샘플링이 정확도의 전제다(status bar와 동일).
fn spawn_local_sampler(buf: Arc<Mutex<VecDeque<LocalPoint>>>) {
    tokio::spawn(async move {
        let mut sampler = SysSampler::new();
        let mut proc_sampler = WebProcessSampler::new();
        let mut tick = tokio::time::interval(SAMPLE_INTERVAL);
        loop {
            tick.tick().await;
            let m = sampler.sample();
            let resources = proc_sampler.sample(&m);
            let top_cpu_proc = resources.top_cpu_procs.first().cloned();
            let top_mem_proc = resources.top_mem_procs.first().cloned();
            let point = LocalPoint {
                ts: chrono::Utc::now().timestamp_millis(),
                cpu_pct: m.cpu_pct,
                load1: m.load1,
                cores: m.cores,
                mem_used: m.mem_used,
                mem_total: m.mem_total,
                swap_used: m.swap_used,
                swap_total: m.swap_total,
                disk_avail: m.disk_avail,
                disk_total: m.disk_total,
                disk_read_bps: m.disk_read_bps,
                disk_write_bps: m.disk_write_bps,
                net_rx_bps: m.net_rx_bps,
                net_tx_bps: m.net_tx_bps,
                top_cpu_proc,
                top_mem_proc,
                top_cpu_procs: resources.top_cpu_procs,
                top_mem_procs: resources.top_mem_procs,
                host: resources.host,
                disks: resources.disks,
                networks: resources.networks,
                process_pressure: resources.process_pressure,
                events: resources.events,
            };
            // lock은 push 동안만 잡고 즉시 해제(.await를 가로지르지 않는다).
            if let Ok(mut b) = buf.lock() {
                if b.len() >= RING_CAP {
                    b.pop_front();
                }
                b.push_back(point);
            }
        }
    });
}

/// web resource 전용 프로세스 sampler. CPU 사용률은 연속 refresh delta라 sampler를 재사용한다.
struct WebProcessSampler {
    sys: System,
    disks: Disks,
    networks: Networks,
    events: VecDeque<ResourceEvent>,
    last_levels: HashMap<String, &'static str>,
}

impl WebProcessSampler {
    fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            events: VecDeque::with_capacity(RESOURCE_EVENT_LIMIT),
            last_levels: HashMap::new(),
        }
    }

    fn sample(&mut self, metrics: &crate::agent::sys_sampler::SysMetrics) -> WebResourceSample {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        self.disks.refresh(true);
        self.networks.refresh(true);

        let mut processes: Vec<ProcessSample> = self
            .sys
            .processes()
            .values()
            .filter(|p| p.cpu_usage().is_finite())
            .map(process_sample)
            .collect();
        processes.sort_by(|a, b| {
            b.cpu_pct
                .partial_cmp(&a.cpu_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let top_cpu = processes.iter().take(TOP_PROCESS_LIMIT).cloned().collect();
        processes.sort_by_key(|p| std::cmp::Reverse(p.memory));
        let top_mem = processes.into_iter().take(TOP_PROCESS_LIMIT).collect();
        let disks = disk_samples(&self.disks);
        let networks = network_samples(&self.networks);
        let process_pressure = process_pressure(&self.sys);
        self.record_resource_events(metrics, &disks, &process_pressure);

        WebResourceSample {
            top_cpu_procs: top_cpu,
            top_mem_procs: top_mem,
            host: host_identity(),
            disks,
            networks,
            process_pressure,
            events: self.events.iter().cloned().collect(),
        }
    }

    fn record_resource_events(
        &mut self,
        metrics: &crate::agent::sys_sampler::SysMetrics,
        disks: &[DiskSample],
        process_pressure: &ProcessPressure,
    ) {
        self.record_level(
            "CPU",
            threshold(metrics.cpu_pct as f64, 70.0, 90.0),
            format!("{:.1}%", metrics.cpu_pct),
        );
        let load_ratio = if metrics.cores > 0 {
            metrics.load1 / metrics.cores as f64
        } else {
            metrics.load1
        };
        self.record_level(
            "load",
            threshold(load_ratio, 1.0, 2.0),
            format!("x{load_ratio:.2} per core"),
        );
        self.record_level(
            "memory",
            threshold(percent(metrics.mem_used, metrics.mem_total), 75.0, 90.0),
            format!("{:.0}%", percent(metrics.mem_used, metrics.mem_total)),
        );
        self.record_level(
            "swap",
            threshold(percent(metrics.swap_used, metrics.swap_total), 25.0, 60.0),
            format!("{:.0}%", percent(metrics.swap_used, metrics.swap_total)),
        );
        self.record_level(
            "disk total",
            threshold(
                percent(
                    metrics.disk_total.saturating_sub(metrics.disk_avail),
                    metrics.disk_total,
                ),
                80.0,
                92.0,
            ),
            format!(
                "{:.0}%",
                percent(
                    metrics.disk_total.saturating_sub(metrics.disk_avail),
                    metrics.disk_total,
                )
            ),
        );
        for disk in disks.iter().filter(|d| d.total > 0) {
            self.record_level(
                &format!("disk {}", disk.mount_point),
                threshold(disk.used_pct, 80.0, 92.0),
                format!("{:.0}% used", disk.used_pct),
            );
        }
        let fd_level = match process_pressure.fd_status {
            STATUS_WARN | STATUS_CRIT | STATUS_OK => process_pressure.fd_status,
            _ => STATUS_UNAVAILABLE,
        };
        let fd_value = match (process_pressure.fd_open, process_pressure.fd_limit) {
            (Some(open), Some(limit)) => format!("{open}/{limit} fd"),
            (Some(open), None) => format!("{open} fd open"),
            _ => process_pressure
                .fd_error
                .clone()
                .unwrap_or_else(|| "fd unavailable".to_string()),
        };
        self.record_level("fd pressure", fd_level, fd_value);
    }

    fn record_level(&mut self, resource: &str, level: &'static str, value: String) {
        let key = resource.to_string();
        let prev = self.last_levels.insert(key.clone(), level);
        if prev == Some(level) {
            return;
        }
        if prev.is_none() && level == STATUS_OK {
            return;
        }
        self.events.push_back(ResourceEvent {
            ts: chrono::Utc::now().timestamp_millis(),
            severity: level,
            resource: key,
            value,
        });
        while self.events.len() > RESOURCE_EVENT_LIMIT {
            self.events.pop_front();
        }
    }
}

fn process_sample(p: &sysinfo::Process) -> ProcessSample {
    ProcessSample {
        name: p.name().to_string_lossy().into_owned(),
        pid: p.pid().to_string(),
        cpu_pct: p.cpu_usage(),
        memory: p.memory(),
    }
}

fn host_identity() -> HostIdentity {
    HostIdentity {
        hostname: System::host_name(),
        os: System::name(),
        os_version: System::long_os_version().or_else(System::os_version),
        kernel_version: System::kernel_version(),
        arch: std::env::consts::ARCH,
        uptime_secs: System::uptime(),
        boot_time_secs: System::boot_time(),
        aic_version: option_env!("AIC_BUILD_INFO").unwrap_or(env!("CARGO_PKG_VERSION")),
    }
}

fn disk_samples(disks: &Disks) -> Vec<DiskSample> {
    let mut out: Vec<DiskSample> = disks
        .list()
        .iter()
        .map(|d| {
            let total = d.total_space();
            let available = d.available_space();
            let used = total.saturating_sub(available);
            DiskSample {
                name: d.name().to_string_lossy().into_owned(),
                file_system: d.file_system().to_string_lossy().into_owned(),
                mount_point: d.mount_point().display().to_string(),
                total,
                available,
                used,
                used_pct: percent(used, total),
                read_only: d.is_read_only(),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.used_pct
            .partial_cmp(&a.used_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn network_samples(networks: &Networks) -> Vec<NetworkSample> {
    let mut out: Vec<NetworkSample> = networks
        .iter()
        .map(|(name, n)| NetworkSample {
            name: name.clone(),
            rx_bps: n.received() / SAMPLE_INTERVAL.as_secs().max(1),
            tx_bps: n.transmitted() / SAMPLE_INTERVAL.as_secs().max(1),
            rx_packets: n.packets_received(),
            tx_packets: n.packets_transmitted(),
            rx_errors: n.errors_on_received(),
            tx_errors: n.errors_on_transmitted(),
            mac: n.mac_address().to_string(),
            loopback: is_loopback_interface(name),
        })
        .collect();
    out.sort_by_key(|n| std::cmp::Reverse(n.rx_bps.saturating_add(n.tx_bps)));
    out
}

fn is_loopback_interface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "lo" || n.starts_with("lo") || n.starts_with("loopback")
}

fn process_pressure(sys: &System) -> ProcessPressure {
    let (fd_open, fd_limit, fd_scope, fd_error) = fd_pressure();
    let fd_pct = match (fd_open, fd_limit) {
        (Some(open), Some(limit)) if limit > 0 => Some(open as f64 / limit as f64 * 100.0),
        _ => None,
    };
    ProcessPressure {
        process_count: sys.processes().len(),
        thread_count: thread_count(sys),
        fd_open,
        fd_limit,
        fd_pct,
        fd_status: fd_pct
            .map(|v| threshold(v, 70.0, 90.0))
            .unwrap_or(STATUS_UNAVAILABLE),
        fd_scope,
        fd_error,
    }
}

fn thread_count(sys: &System) -> Option<usize> {
    let mut saw_tasks = false;
    let total = sys
        .processes()
        .values()
        .filter_map(|p| {
            p.tasks().map(|tasks| {
                saw_tasks = true;
                tasks.len().max(1)
            })
        })
        .sum::<usize>();
    saw_tasks.then_some(total)
}

#[cfg(target_os = "linux")]
fn fd_pressure() -> (Option<u64>, Option<u64>, &'static str, Option<String>) {
    match fs::read_to_string("/proc/sys/fs/file-nr") {
        Ok(s) => {
            let parts: Vec<u64> = s
                .split_whitespace()
                .filter_map(|p| p.parse::<u64>().ok())
                .collect();
            if parts.len() >= 3 {
                let open = parts[0].saturating_sub(parts[1]);
                (Some(open), Some(parts[2]), "system", None)
            } else {
                (
                    None,
                    None,
                    "system",
                    Some("invalid /proc/sys/fs/file-nr".to_string()),
                )
            }
        }
        Err(e) => (None, None, "system", Some(e.to_string())),
    }
}

#[cfg(not(target_os = "linux"))]
fn fd_pressure() -> (Option<u64>, Option<u64>, &'static str, Option<String>) {
    let open = count_open_fds();
    let limit = fd_soft_limit();
    let error = if open.is_none() && limit.is_none() {
        Some("fd pressure unavailable".to_string())
    } else {
        None
    };
    (open, limit, "process", error)
}

#[cfg(not(target_os = "linux"))]
fn count_open_fds() -> Option<u64> {
    fs::read_dir("/dev/fd")
        .ok()
        .map(|entries| entries.filter_map(Result::ok).count() as u64)
}

#[cfg(not(target_os = "linux"))]
fn fd_soft_limit() -> Option<u64> {
    let mut lim = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, lim.as_mut_ptr()) == 0 };
    if !ok {
        return None;
    }
    let lim = unsafe { lim.assume_init() };
    if lim.rlim_cur == libc::RLIM_INFINITY {
        None
    } else {
        Some(lim.rlim_cur as u64)
    }
}

fn percent(used: u64, total: u64) -> f64 {
    if total > 0 {
        used as f64 / total as f64 * 100.0
    } else {
        0.0
    }
}

fn threshold(value: f64, warn: f64, crit: f64) -> &'static str {
    if !value.is_finite() {
        STATUS_UNAVAILABLE
    } else if value >= crit {
        STATUS_CRIT
    } else if value >= warn {
        STATUS_WARN
    } else {
        STATUS_OK
    }
}

fn spawn_runtime_health_sampler(slot: Arc<Mutex<Value>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RUNTIME_HEALTH_INTERVAL);
        loop {
            let health = collect_runtime_health().await;
            if let Ok(mut dst) = slot.lock() {
                *dst = health;
            }
            tick.tick().await;
        }
    });
}

async fn collect_runtime_health() -> Value {
    let client = UdsClient::new(aic_common::aicd_socket_path());
    let aicd_online = matches!(client.ping().await, Ok(true));

    let (aicd, sessions) = if aicd_online {
        let metrics = match client.get_metrics().await {
            Ok(m) => json!({
                "ok": true,
                "status": "online",
                "pid": m.pid,
                "uptime_secs": m.uptime_secs,
                "ipc_request_count": m.ipc_request_count,
                "central_store_push_total": m.central_store_push_total,
                "attach_connections": m.attach_connections,
                "attach_open_total": m.attach_open_total,
                "dropped_bytes": m.dropped_bytes,
                "attach_reconnect_total": m.attach_reconnect_total,
            }),
            Err(e) => json!({
                "ok": false,
                "status": "degraded",
                "error": e.to_string(),
            }),
        };
        let sessions = match client.list_sessions().await {
            Ok(list) => {
                let attached = list
                    .iter()
                    .filter(|s| matches!(s.state, aic_common::SessionState::Attached))
                    .count();
                let detached = list
                    .iter()
                    .filter(|s| matches!(s.state, aic_common::SessionState::Detached))
                    .count();
                let active = list
                    .iter()
                    .filter(|s| {
                        !matches!(
                            s.state,
                            aic_common::SessionState::Stopped | aic_common::SessionState::Failed
                        )
                    })
                    .count();
                json!({
                    "ok": true,
                    "total": list.len(),
                    "active": active,
                    "attached": attached,
                    "detached": detached,
                })
            }
            Err(e) => json!({
                "ok": false,
                "total": 0,
                "active": 0,
                "attached": 0,
                "detached": 0,
                "error": e.to_string(),
            }),
        };
        (metrics, sessions)
    } else {
        (
            json!({
                "ok": false,
                "status": "offline",
            }),
            json!({
                "ok": false,
                "total": 0,
                "active": 0,
                "attached": 0,
                "detached": 0,
                "error": "aicd offline",
            }),
        )
    };

    let snapshots = tokio::task::spawn_blocking(snapshot_health)
        .await
        .unwrap_or_else(|e| json!({ "ok": false, "error": e.to_string() }));
    let audit = tokio::task::spawn_blocking(audit_health)
        .await
        .unwrap_or_else(|e| json!({ "ok": false, "status": "error", "error": e.to_string() }));

    json!({
        "ts": chrono::Utc::now().timestamp_millis(),
        "aicd": aicd,
        "sessions": sessions,
        "snapshots": snapshots,
        "audit": audit,
    })
}

fn snapshot_health() -> Value {
    let timer = snapshot_timer::status();
    let loaded = snapshot_store::load_snapshots();
    let (count, latest, store_error) = match loaded {
        Ok(snaps) => {
            let latest = snaps.last().map(|s| {
                json!({
                    "captured_at": s.captured_at,
                    "kind": s.kind,
                })
            });
            (snaps.len(), latest, None::<String>)
        }
        Err(e) => (0, None, Some(e.to_string())),
    };
    json!({
        "ok": store_error.is_none(),
        "timer_installed": timer.installed,
        "platform": format!("{:?}", timer.platform),
        "interval_secs": timer.interval_secs,
        "record_env": snapshot_store::record_enabled(),
        "count": count,
        "latest": latest,
        "error": store_error,
    })
}

fn audit_health() -> Value {
    match audit::verify() {
        Ok(r) => json!({
            "ok": r.valid,
            "status": if r.valid { "valid" } else { "broken" },
            "lines": r.lines,
            "broken_at": r.broken_at,
        }),
        Err(e) => json!({
            "ok": false,
            "status": "unavailable",
            "lines": 0,
            "broken_at": null,
            "error": e.to_string(),
        }),
    }
}

/// 인증 면제 경로 — 대시보드 셸과 헬스 체크(민감 데이터 없음). 나머지 `/web/*`는 Bearer 토큰 필수.
fn auth_exempt(path: &str) -> bool {
    path == "/" || path == "/web/health"
}

/// Bearer 토큰 인증 미들웨어. [`auth_exempt`] 경로만 면제하고, 나머지는
/// `Authorization: Bearer <token>` 상수시간 일치를 요구한다.
async fn require_token(State(state): State<Arc<WebState>>, req: Request, next: Next) -> Response {
    if auth_exempt(req.uri().path()) {
        return next.run(req).await;
    }
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    if bearer_ok(header, &state.token) {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
    }
}

/// `Authorization` 헤더 값이 `Bearer <token>`이고 토큰이 상수시간 일치하면 true.
fn bearer_ok(header: Option<&str>, token: &str) -> bool {
    let Some(value) = header else {
        return false;
    };
    let Some(provided) = value.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(provided.trim().as_bytes(), token.as_bytes())
}

/// 타이밍 공격 방지 상수시간 비교(webhook_server와 동일 정책).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 500으로 매핑하되 내부 에러 본문은 노출하지 않는다(메시지 누출 방지).
fn internal(_e: anyhow::Error) -> (StatusCode, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
}

/// 대시보드 셸(자체완결 HTML). clickjacking/MIME-sniffing 방어 헤더를 함께 싣는다.
async fn dashboard() -> Response {
    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (X_FRAME_OPTIONS, "DENY"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        DASHBOARD,
    )
        .into_response()
}

/// 로컬 자원 시계열 — 무설정 동작의 핵심. ring buffer 전체를 JSON으로 낸다(수치만, 식별정보 없음).
async fn local_metrics(State(state): State<Arc<WebState>>) -> Json<Value> {
    let points: Vec<LocalPoint> = state
        .local
        .lock()
        .map(|b| b.iter().cloned().collect())
        .unwrap_or_default();
    let runtime = state
        .runtime
        .lock()
        .map(|v| v.clone())
        .unwrap_or_else(|_| json!({ "status": "unavailable" }));
    Json(json!({ "points": points, "runtime": runtime }))
}

async fn snapshots() -> Result<Json<Vec<snapshot_store::SnapshotRecord>>, (StatusCode, &'static str)>
{
    let snaps = snapshot_store::load_snapshots().map_err(internal)?;
    Ok(Json(snaps))
}

/// aicd 감사 로그(`~/.local/state/aic/audit.log`) tail. 저장은 평문(보안 원본 보존)이므로 노출 직전
/// `data` 필드에 redaction을 적용한다(secret 유출 방어). seq/ts/kind/host는 비민감.
async fn audit_log() -> Result<Json<Vec<Value>>, (StatusCode, &'static str)> {
    let recs = audit::tail_events(AUDIT_TAIL).map_err(|e| internal(e.into()))?;
    let out = recs
        .iter()
        .map(|r| {
            // `raw`는 AuditEvent.data Value 자체(read_local_records가 ts/kind는 별도 필드로 분리).
            // JSON 구조는 유지하고 string leaf에만 redaction을 적용해 dashboard가 table로 펼칠 수 있게 한다.
            let data = redacted_json_value(&r.raw);
            json!({
                "ts": r.ts,
                "kind": r.kind,
                "host": r.host,
                "data": data,
            })
        })
        .collect();
    Ok(Json(out))
}

fn redacted_json_value(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redaction::redact(s).0),
        Value::Array(items) => Value::Array(items.iter().map(redacted_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redacted_json_value(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// 세션 command 기록 — snapshots와 달리 **aicd CommandRecordStore**(Control_UDS)를 조회한다(파일 아님).
/// aicd 미기동/세션 부재는 에러가 아니라 `available:false`로 안내한다(무설정 동작 철학). command/output은
/// redaction을 적용한다.
async fn history() -> Json<Value> {
    let client = UdsClient::new(aic_common::aicd_socket_path());
    if !matches!(client.ping().await, Ok(true)) {
        return Json(json!({
            "available": false,
            "reason": "aicd가 실행 중이지 않습니다 — aic daemon start 후 aic-session 실행",
            "records": [],
        }));
    }
    let session = match resolve_session_id(&client, None).await {
        Ok(id) => id,
        Err(reason) => return Json(json!({ "available": false, "reason": reason, "records": [] })),
    };
    let recs = client
        .get_recent_commands_for_session(&session, HISTORY_TAIL)
        .await
        .unwrap_or_default();
    let records: Vec<Value> = recs
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "command": r.command.as_ref().map(|c| redaction::redact(c).0),
                "exit_code": r.exit_code,
                "timestamp": r.timestamp,
                "output": redaction::redact(&r.output_lines.join("\n")).0,
            })
        })
        .collect();
    Json(json!({ "available": true, "session": session, "records": records }))
}

/// aicd webhook alert ingestion 이벤트(`webhook-events.jsonl`) tail. 파일 부재는 빈 목록(에러 아님).
/// 자유 텍스트 필드(action/source/alert)에 redaction을 적용한다.
async fn webhooks() -> Json<Vec<Value>> {
    let path = aic_common::paths::webhook_events_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut evs: Vec<Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect();
    if evs.len() > WEBHOOK_TAIL {
        evs = evs.split_off(evs.len() - WEBHOOK_TAIL);
    }
    let red = |v: &Value, k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| redaction::redact(s).0)
    };
    let out = evs
        .iter()
        .map(|e| {
            json!({
                "ts": e.get("ts"),
                "action": red(e, "action"),
                "source": red(e, "source"),
                "alert": red(e, "alert"),
                "severity": e.get("severity"),
            })
        })
        .collect();
    Json(out)
}

/// 현재 config 요약 — **토큰/secret은 절대 노출하지 않는다**. 백엔드 `auth`는 존재 여부(bool)만, URL은
/// redaction 통과, provider/MCP 서버는 이름만. 가시성에 필요한 비민감 필드만 선별해 직렬화한다.
async fn config_view() -> Json<Value> {
    let cfg = match ConfigManager::load() {
        Ok(c) => c,
        Err(e) => return Json(json!({ "error": format!("config 로드 실패: {e}") })),
    };
    let backends: Vec<Value> = cfg
        .observability
        .backends
        .iter()
        .map(|(name, b)| {
            json!({
                "name": name,
                "type": format!("{:?}", b.backend_type),
                "url": redaction::redact(&b.url).0,
                "auth": b.auth.is_some(),
            })
        })
        .collect();
    Json(json!({
        "llm": {
            "default_provider": cfg.llm.default_provider,
            "lang": cfg.llm.lang,
            "providers": cfg.llm.providers.keys().collect::<Vec<_>>(),
        },
        "server": {
            "max_buffer_lines": cfg.server.max_buffer_lines,
            "boundary_strategy": cfg.server.boundary_strategy.method,
        },
        "observability_backends": backends,
        "aicd_webhook_enabled": cfg.aicd.webhook.enabled,
        "mcp_servers": cfg.mcp.servers.keys().collect::<Vec<_>>(),
    }))
}

/// RCA 인시던트 목록. `IncidentSummary`를 그대로 직렬화하면 `path`(서버 홈 절대경로)가 노출되고
/// `title`/`symptom`/`cwd`는 redaction 미적용이다. 여기서 `path`를 제외하고 입력 필드에 redaction을 적용한다.
async fn incidents() -> Result<Json<Vec<Value>>, (StatusCode, &'static str)> {
    let list = rca::list_incidents().map_err(internal)?;
    let out: Vec<Value> = list
        .into_iter()
        .map(|i| {
            json!({
                "id": i.id,
                "title": redaction::redact(&i.title).0,
                "status": i.status,
                "symptom": i.symptom.map(|s| redaction::redact(&s).0),
                "cwd": i.cwd.map(|s| redaction::redact(&s).0),
                "created_at": i.created_at,
                "updated_at": i.updated_at,
                "evidence_count": i.evidence_count,
            })
        })
        .collect();
    Ok(Json(out))
}

/// 인시던트 id는 생성 시 timestamp + slug(`[A-Za-z0-9_-]`)만 쓴다. 데이터 디렉터리에 닿기 전에
/// allowlist로 검증해 path traversal을 차단한다 — axum `Path`는 `%2F`를 `/`로 percent-decode하고
/// `PathBuf::join`은 절대경로 인자로 base를 통째로 치환하므로, `/`·`\`·`.`(따라서 `..`)를 모두 거른다.
fn is_safe_incident_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// RCA report.md를 markdown으로 서빙한다. `render_report`는 redaction 미적용이므로 서빙 직전
/// `redaction::redact`를 한 번 더 통과시켜 secret 유출을 방어한다.
async fn incident_report(Path(id): Path<String>) -> Result<Response, (StatusCode, &'static str)> {
    if !is_safe_incident_id(&id) {
        return Err((StatusCode::BAD_REQUEST, "invalid incident id\n"));
    }
    let meta = rca::load_meta(&id).map_err(internal)?;
    let events = rca::load_events(&id).map_err(internal)?;
    let report = rca::render_report(&meta, &events);
    let (redacted, _) = redaction::redact(&report);
    Ok(([(CONTENT_TYPE, "text/markdown; charset=utf-8")], redacted).into_response())
}

/// 등록된 관측 백엔드 이름(타입별). 외부 metrics/logs 탭 활성화 판단 + 드롭다운용. 없으면 빈 목록.
async fn backends(State(state): State<Arc<WebState>>) -> Json<Value> {
    use aic_common::BackendType;
    let (prom, loki) = match &state.obs {
        Some(o) => (
            o.backend_names_of(BackendType::Prometheus),
            o.backend_names_of(BackendType::Loki),
        ),
        None => (Vec::new(), Vec::new()),
    };
    Json(json!({ "prometheus": prom, "loki": loki }))
}

/// (선택) PromQL 질의 — 등록 백엔드가 있을 때만. ObsClient 출력(redacted·bounded)을 그대로 서빙.
async fn metrics(State(state): State<Arc<WebState>>, Json(args): Json<Value>) -> Response {
    obs_query(&state, "prometheus_query", &args).await
}

/// (선택) LogQL 질의 — 등록 백엔드가 있을 때만.
async fn logs(State(state): State<Arc<WebState>>, Json(args): Json<Value>) -> Response {
    obs_query(&state, "loki_query", &args).await
}

/// 관측 질의 공통 — ObsClient.run의 출력(이미 redact·bounded)을 application/json으로 서빙한다.
/// 백엔드 allowlist·URL 검증·결과 bound는 모두 ObsClient가 담당한다(web은 얇은 어댑터).
async fn obs_query(state: &WebState, tool: &str, args: &Value) -> Response {
    let Some(obs) = &state.obs else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "관측 백엔드가 등록되지 않았습니다 ([observability.backends.*])\n",
        )
            .into_response();
    };
    match obs.run(tool, args).await {
        Ok(body) => ([(CONTENT_TYPE, "application/json")], body).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn bearer_ok_accepts_matching_token() {
        assert!(bearer_ok(Some("Bearer s3cret"), "s3cret"));
        assert!(bearer_ok(Some("Bearer  s3cret "), "s3cret"));
    }

    #[test]
    fn bearer_ok_rejects_mismatch_missing_and_wrong_scheme() {
        assert!(!bearer_ok(Some("Bearer wrong"), "s3cret"));
        assert!(!bearer_ok(None, "s3cret"));
        assert!(!bearer_ok(Some("Basic s3cret"), "s3cret"));
        assert!(!bearer_ok(Some("s3cret"), "s3cret"));
    }

    #[test]
    fn is_safe_incident_id_rejects_traversal() {
        assert!(is_safe_incident_id("20260623-031042-web-demo"));
        assert!(is_safe_incident_id("abc_123-XY"));
        assert!(!is_safe_incident_id("../../etc"));
        assert!(!is_safe_incident_id("/etc"));
        assert!(!is_safe_incident_id(".."));
        assert!(!is_safe_incident_id("a/b"));
        assert!(!is_safe_incident_id("a\\b"));
        assert!(!is_safe_incident_id(""));
        assert!(!is_safe_incident_id(&"x".repeat(200)));
    }

    #[test]
    fn auth_exempt_only_shell_and_health() {
        assert!(auth_exempt("/"));
        assert!(auth_exempt("/web/health"));
        assert!(!auth_exempt("/web/local"));
        assert!(!auth_exempt("/web/snapshots"));
        assert!(!auth_exempt("/web/incidents"));
        assert!(!auth_exempt("/web/metrics"));
        // 새 데이터 엔드포인트도 토큰 필수(감사/명령기록/webhook/config 모두 민감).
        assert!(!auth_exempt("/web/audit"));
        assert!(!auth_exempt("/web/history"));
        assert!(!auth_exempt("/web/webhooks"));
        assert!(!auth_exempt("/web/config"));
    }

    #[test]
    fn local_point_serializes_bounded_resource_summary() {
        // resource point는 command/env/cwd 없이 수치 + 최소 프로세스 요약만 직렬화한다.
        let p = LocalPoint {
            ts: 1,
            cpu_pct: 12.5,
            load1: 1.0,
            cores: 8,
            mem_used: 100,
            mem_total: 200,
            swap_used: 0,
            swap_total: 0,
            disk_avail: 10,
            disk_total: 20,
            disk_read_bps: 0,
            disk_write_bps: 0,
            net_rx_bps: 0,
            net_tx_bps: 0,
            top_cpu_proc: Some(ProcessSample {
                name: "cargo".to_string(),
                pid: "123".to_string(),
                cpu_pct: 4.0,
                memory: 1024,
            }),
            top_mem_proc: None,
            top_cpu_procs: vec![ProcessSample {
                name: "cargo".to_string(),
                pid: "123".to_string(),
                cpu_pct: 4.0,
                memory: 1024,
            }],
            top_mem_procs: vec![],
            host: HostIdentity {
                hostname: Some("dev-host".to_string()),
                os: Some("Darwin".to_string()),
                os_version: Some("macOS 15".to_string()),
                kernel_version: Some("24.0.0".to_string()),
                arch: "aarch64",
                uptime_secs: 100,
                boot_time_secs: 1,
                aic_version: "test",
            },
            disks: vec![DiskSample {
                name: "disk0".to_string(),
                file_system: "apfs".to_string(),
                mount_point: "/".to_string(),
                total: 200,
                available: 50,
                used: 150,
                used_pct: 75.0,
                read_only: false,
            }],
            networks: vec![NetworkSample {
                name: "lo0".to_string(),
                rx_bps: 10,
                tx_bps: 20,
                rx_packets: 1,
                tx_packets: 2,
                rx_errors: 0,
                tx_errors: 0,
                mac: "00:00:00:00:00:00".to_string(),
                loopback: true,
            }],
            process_pressure: ProcessPressure {
                process_count: 42,
                thread_count: Some(84),
                fd_open: Some(12),
                fd_limit: Some(256),
                fd_pct: Some(4.6875),
                fd_status: STATUS_OK,
                fd_scope: "process",
                fd_error: None,
            },
            events: vec![ResourceEvent {
                ts: 1,
                severity: STATUS_WARN,
                resource: "memory".to_string(),
                value: "75%".to_string(),
            }],
        };
        let v = serde_json::to_value(&p).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("cpu_pct") && obj.contains_key("ts"));
        assert_eq!(obj["cores"], 8);
        assert_eq!(obj["top_cpu_proc"]["name"], "cargo");
        assert_eq!(obj["top_cpu_proc"]["pid"], "123");
        assert_eq!(obj["top_cpu_procs"][0]["name"], "cargo");
        assert_eq!(obj["host"]["hostname"], "dev-host");
        assert_eq!(obj["disks"][0]["mount_point"], "/");
        assert_eq!(obj["networks"][0]["name"], "lo0");
        assert_eq!(obj["process_pressure"]["process_count"], 42);
        assert_eq!(obj["events"][0]["resource"], "memory");
        // command/env/cwd 등 고위험 process detail은 없어야 한다.
        assert!(!obj.contains_key("cmd") && !obj.contains_key("env") && !obj.contains_key("cwd"));
    }

    #[test]
    fn audit_data_redaction_preserves_json_shape() {
        let input = json!({
            "provider": "openai",
            "token": "Bearer abcDEF123ghiJKL456mnoPQR789",
            "count": 3,
            "nested": {
                "email": "user@example.com",
                "ok": true
            }
        });
        let out = redacted_json_value(&input);
        assert_eq!(out["provider"], "openai");
        assert_eq!(out["count"], 3);
        assert_eq!(out["nested"]["ok"], true);
        assert_eq!(out["token"], "[REDACTED:bearer_token]");
        assert_eq!(out["nested"]["email"], "[REDACTED:email]");
    }

    #[test]
    fn dashboard_html_is_self_contained() {
        assert!(!DASHBOARD.contains("http://"));
        assert!(!DASHBOARD.contains("https://"));
        assert!(!DASHBOARD.contains("src=\"//"));
        // 로컬 자원이 중심 — /web/local을 호출한다.
        assert!(DASHBOARD.contains("/web/local"));
        assert!(DASHBOARD.contains("Bearer "));
    }
}
