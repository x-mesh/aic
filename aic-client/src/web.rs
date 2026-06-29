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
//! - `GET  /web/chat[/{session}]`    — aic chat 세션/명령/audit 관측 timeline(read-only)
//! - `GET  /web/webhooks`            — webhook alert ingestion 이벤트 tail(redacted, 없으면 빈 목록)
//! - `GET  /web/config`              — 현재 config 요약(토큰/secret 미노출)
//! - `GET  /web/backends`            — 등록된 Prometheus/Loki 백엔드 이름(없으면 빈 목록)
//! - `POST /web/metrics`·`/web/logs` — (선택) 등록된 Prometheus/Loki 질의. 백엔드 없으면 503.
//!
//! 노출은 **on-demand**(`aic web --bind`, 기본 미기동) + **토큰 필수**. 데이터 엔드포인트(`/web/*`)는
//! Bearer 토큰을 요구하고, 대시보드 셸(`/`, `/web/health`)만 면제한다(민감 데이터 없음 — 사용자가
//! 페이지에서 토큰 입력 → JS가 이후 fetch에 Bearer로 싣는다).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
            X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
        },
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
use sysinfo::{Disks, Networks, Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

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
const CHAT_SESSION_LIMIT: usize = 20;
const CHAT_RECORD_TAIL: usize = 30;
const CHAT_AUDIT_TAIL: usize = 80;
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

/// `/web/metrics`·`/web/logs` 요청 본문 상한. PromQL/LogQL 질의 + args JSON은 작으므로 64KB면 충분하다 —
/// axum 기본(2MB)을 좁혀 비정상 대용량 본문을 413으로 거른다.
const OBS_BODY_LIMIT: usize = 64 * 1024;
/// 프로세스 상세의 network 연결 sample 상한(redacted). 너무 길면 payload·UI noise가 커진다.
const PROCESS_NET_SAMPLE: usize = 50;
/// Linux kernel-stack raw 출력 문자 상한(payload bound). macOS는 구조화 파싱이라 미사용.
#[cfg(target_os = "linux")]
const SAMPLE_CAP: usize = 12000;
/// 스택 샘플 윈도(초). macOS `sample`/Linux `perf record` 둘 다 이 시간 동안 샘플링한다.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const SAMPLE_SECS: u64 = 2;
/// Linux `perf record` 샘플링 주파수(Hz). 99는 timer interrupt와 lock-step되는 100Hz를 피하는 관행.
#[cfg(target_os = "linux")]
const PERF_HZ: &str = "99";
/// 구조화 샘플에서 노출할 hot frame(self-time 상위) 개수.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
const HOT_FRAMES: usize = 25;
/// web 접근 감사 이벤트 kind — 누가/언제/어디서 대시보드를 봤는지 audit log(HMAC chain)에 남긴다.
const WEB_ACCESS_KIND: &str = "web_access";
const WEB_AUTH_DENIED_KIND: &str = "web_auth_denied";

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
    /// (opt-in) 프로세스 스택 샘플 허용. 기본 false면 `/web/process/{pid}/sample`은 403.
    pub allow_stack_sample: bool,
}

struct WebState {
    token: String,
    /// 로컬 자원 시계열 ring buffer(백그라운드 샘플러가 채운다). 무설정 동작의 핵심.
    local: Arc<Mutex<VecDeque<LocalPoint>>>,
    /// aic runtime 상태(aicd/session/snapshot/audit). 별도 주기로 갱신해 `/web/local`에 합친다.
    runtime: Arc<Mutex<Value>>,
    /// 등록 관측 백엔드가 있을 때만 Some. 없으면 외부 metrics/logs는 503.
    obs: Option<ObsClient>,
    /// 스택 샘플 활성(기본 ON; `--no-stack-sample`로 off). false면 sample 엔드포인트 403.
    allow_stack_sample: bool,
    /// 진행 중인 sample pid 집합(single-flight) — 같은 pid 동시 샘플/연타 폭주를 막는다.
    sampling: Arc<Mutex<HashSet<u32>>>,
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
        allow_stack_sample: cfg.allow_stack_sample,
        sampling: Arc::new(Mutex::new(HashSet::new())),
    });

    let app = Router::new()
        .route("/web/health", get(|| async { "ok" }))
        .route("/", get(dashboard))
        .route("/web/local", get(local_metrics))
        .route("/web/process/{pid}", get(process_detail))
        .route("/web/process/{pid}/sample", get(process_stack_sample))
        .route("/web/snapshots", get(snapshots))
        .route("/web/incidents", get(incidents))
        .route("/web/incidents/{id}/report", get(incident_report))
        .route("/web/audit", get(audit_log))
        .route("/web/history", get(history))
        .route("/web/chat", get(chat_observability))
        .route("/web/chat/{session}", get(chat_observability_for_session))
        .route("/web/webhooks", get(webhooks))
        .route("/web/config", get(config_view))
        .route("/web/backends", get(backends))
        .route(
            "/web/metrics",
            post(metrics).route_layer(DefaultBodyLimit::max(OBS_BODY_LIMIT)),
        )
        .route(
            "/web/logs",
            post(logs).route_layer(DefaultBodyLimit::max(OBS_BODY_LIMIT)),
        )
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state);

    // ConnectInfo<SocketAddr>로 peer 주소를 추출 — require_token이 접근 감사에 source IP를 남긴다.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
            mac: mask_mac(&n.mac_address().to_string()),
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

/// MAC은 장치 고유 식별자라 공유 대시보드 노출 전 host-specific 하위 3옥텟을 마스킹한다. 벤더 OUI(상위
/// 3옥텟)만 남겨 인터페이스 식별 가치는 유지한다. 표준 6옥텟 형식이 아니면(빈 값 포함) 통째로 마스킹한다.
fn mask_mac(mac: &str) -> String {
    let octets: Vec<&str> = mac.split(':').collect();
    if octets.len() == 6
        && octets
            .iter()
            .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        format!("{}:{}:{}:**:**:**", octets[0], octets[1], octets[2])
    } else if mac.is_empty() {
        String::new()
    } else {
        "**".to_string()
    }
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
        Some(lim.rlim_cur)
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

/// `/web/local`은 2초 주기 폴링이라 매 요청 감사 시 audit log가 폭주한다 — exempt/health/resource-poll을
/// 제외한 민감 read 엔드포인트(audit·incidents·history·chat·config·webhooks·snapshots·metrics·logs)만 감사한다.
fn web_access_is_audited(path: &str) -> bool {
    !auth_exempt(path) && path != "/web/local"
}

/// Bearer 토큰 인증 미들웨어. [`auth_exempt`] 경로만 면제하고, 나머지는
/// `Authorization: Bearer <token>` 상수시간 일치를 요구한다. 대시보드가 audit log를 노출하면서도
/// "누가 봤는지"는 못 남기던 공백을 메우기 위해, 인증 실패(항상)와 민감 엔드포인트 성공 접근을 감사한다.
async fn require_token(State(state): State<Arc<WebState>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if auth_exempt(&path) {
        return next.run(req).await;
    }
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());
    let method = req.method().as_str().to_string();
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    if bearer_ok(header, &state.token) {
        if web_access_is_audited(&path) {
            audit_web_access(WEB_ACCESS_KIND, &method, &path, peer.as_deref());
        }
        next.run(req).await
    } else {
        // 인증 실패는 빈도와 무관하게 항상 감사 — probing/brute-force의 1차 신호.
        audit_web_access(WEB_AUTH_DENIED_KIND, &method, &path, peer.as_deref());
        (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
    }
}

/// web 접근을 audit log에 best-effort로 남긴다. `audit::append`는 동기 파일 IO(HMAC chain)이므로
/// async 워커를 막지 않도록 blocking 풀로 보낸다. 실패해도 요청 처리에는 영향을 주지 않는다.
fn audit_web_access(kind: &'static str, method: &str, path: &str, peer: Option<&str>) {
    let data = json!({
        "method": method,
        "path": path,
        "peer": peer,
    });
    tokio::task::spawn_blocking(move || {
        let _ = audit::append(kind, data);
    });
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

/// 대시보드는 자체완결(인라인 script/style, 외부 자원 0)이므로 CSP의 `default-src 'self'` + inline 허용으로
/// 충분하다. 핵심은 `connect-src 'self'`·`script-src 'self'`: 설령 DOM-XSS가 주입돼도 client가 보관한 Bearer
/// 토큰을 외부 origin으로 유출하지 못하게 막는 심층방어(esc() 렌더 이스케이프 위의 2차 방어선).
const DASHBOARD_CSP: &str = "default-src 'self'; \
script-src 'self' 'unsafe-inline'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; \
connect-src 'self'; \
base-uri 'none'; \
form-action 'none'; \
frame-ancestors 'none'";

/// 대시보드 셸(자체완결 HTML). clickjacking/MIME-sniffing 방어 + CSP/Referrer/Cache 정책 헤더를 함께 싣는다.
/// 토큰 입력형 SPA이므로 referrer 미전송·캐시 금지로 토큰/세션 흔적 노출을 줄인다.
async fn dashboard() -> Response {
    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (X_FRAME_OPTIONS, "DENY"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (CONTENT_SECURITY_POLICY, DASHBOARD_CSP),
            (REFERRER_POLICY, "no-referrer"),
            (CACHE_CONTROL, "no-store"),
        ],
        DASHBOARD,
    )
        .into_response()
}

/// `/web/local` 증분 폴링 파라미터. `since`(unix epoch ms) 이후 포인트만 돌려준다.
#[derive(serde::Deserialize)]
struct LocalQuery {
    since: Option<i64>,
}

/// 로컬 자원 시계열 — 무설정 동작의 핵심. 수치만 담고 식별정보는 없다. 대시보드가 매 2초 폴링하므로,
/// `?since=<ts_ms>`로 마지막 수신 이후 신규 포인트만 반환한다(steady-state에서 ~300 → ~1 포인트). `since`
/// 미지정/0은 ring buffer 전량(최초 로드·재연결)을 그대로 내보내 하위호환을 유지한다.
async fn local_metrics(
    State(state): State<Arc<WebState>>,
    Query(q): Query<LocalQuery>,
) -> Json<Value> {
    let since = q.since.unwrap_or(0);
    let points: Vec<LocalPoint> = state
        .local
        .lock()
        .map(|b| b.iter().filter(|p| p.ts > since).cloned().collect())
        .unwrap_or_default();
    let runtime = state
        .runtime
        .lock()
        .map(|v| v.clone())
        .unwrap_or_else(|_| json!({ "status": "unavailable" }));
    Json(json!({ "points": points, "runtime": runtime }))
}

/// 단일 프로세스 상세(top cpu/mem 행 클릭 시). "이 데몬이 뭘 하는지"를 read-only로 답한다:
/// cmdline/exe/cwd(모두 `redaction` 통과 — secret만 마스킹), status/parent/threads/start·run time, mem/IO.
/// **env는 노출하지 않고** 네트워크/tracing도 포함하지 않는다(공유 대시보드 안전 경계). sysinfo refresh는
/// blocking이라 [`spawn_blocking`]으로 보낸다.
async fn process_detail(State(state): State<Arc<WebState>>, Path(pid): Path<u32>) -> Json<Value> {
    let detail = tokio::task::spawn_blocking(move || collect_process_detail(pid))
        .await
        .ok()
        .flatten();
    let mut out = detail.unwrap_or_else(|| {
        json!({
            "available": false,
            "pid": pid,
            "reason": "프로세스를 찾을 수 없습니다(이미 종료됐거나 접근 권한이 없습니다).",
        })
    });
    // 프론트가 "스택 샘플" 버튼 노출 여부를 정하도록 opt-in 상태를 함께 알린다.
    if let Some(map) = out.as_object_mut() {
        map.insert("sample_allowed".into(), json!(state.allow_stack_sample));
    }
    Json(out)
}

/// single-flight guard — 핸들러 종료(성공·에러·panic) 시 sampling set에서 pid를 제거한다.
struct SamplingGuard {
    set: Arc<Mutex<HashSet<u32>>>,
    pid: u32,
}

impl Drop for SamplingGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.set.lock() {
            s.remove(&self.pid);
        }
    }
}

/// pid가 최신 샘플의 top CPU/mem 프로세스 목록에 있는지 — 임의 pid 샘플을 막는 authz(UI 클릭 대상과 동일).
fn pid_in_top_list(state: &WebState, pid: u32) -> bool {
    let p = pid.to_string();
    state
        .local
        .lock()
        .ok()
        .and_then(|b| {
            b.back().map(|pt| {
                pt.top_cpu_procs
                    .iter()
                    .chain(pt.top_mem_procs.iter())
                    .any(|ps| ps.pid == p)
            })
        })
        .unwrap_or(false)
}

/// 프로세스 CPU 스택 샘플(기본 ON; `--no-stack-sample`로 off). 비침습 — ptrace 첨부가 아니라 stack을
/// 샘플링할 뿐이다. 안전장치: ① 비활성 시 403, ② **표시된 top 프로세스 pid만** 허용(임의 pid 차단),
/// ③ 같은 pid single-flight(429), ④ sample 서브프로세스 timeout. macOS `sample`, Linux는 kernel stack.
async fn process_stack_sample(
    State(state): State<Arc<WebState>>,
    Path(pid): Path<u32>,
) -> Response {
    if !state.allow_stack_sample {
        return (
            StatusCode::FORBIDDEN,
            "스택 샘플이 비활성화됨(`--no-stack-sample`).\n",
        )
            .into_response();
    }
    // 임의 pid 차단 — 대시보드가 현재 보여주는 top CPU/mem 프로세스만 샘플 가능(UI 클릭 대상과 동일).
    if !pid_in_top_list(&state, pid) {
        return (
            StatusCode::FORBIDDEN,
            "표시된 top 프로세스만 샘플할 수 있습니다.\n",
        )
            .into_response();
    }
    // single-flight: 같은 pid가 이미 샘플 중이면 거절(연타·동시요청 폭주 방지). guard가 종료 시 해제.
    {
        let mut s = state.sampling.lock().unwrap_or_else(|e| e.into_inner());
        if !s.insert(pid) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "이미 이 프로세스를 샘플링 중입니다.\n",
            )
                .into_response();
        }
    }
    let _guard = SamplingGuard {
        set: state.sampling.clone(),
        pid,
    };
    let sampled = tokio::task::spawn_blocking(move || run_stack_sample(pid))
        .await
        .ok()
        .flatten();
    match sampled {
        Some(v) => Json(v).into_response(),
        None => Json(json!({
            "available": false,
            "reason": "스택 샘플 수집 실패(미지원 플랫폼·권한 부족·프로세스 종료).",
        }))
        .into_response(),
    }
}

/// 스택 샘플 본체(blocking) — **구조화** 결과를 돌려준다. macOS는 `sample`의 집계 call-tree를 파싱해
/// self-time 상위 hot frame과 thread별 sample 수로, Linux는 kernel stack 스냅샷(userspace 프로파일은 perf
/// 필요 — 별도)으로. 구조화 덕에 path-heavy 헤더(`Path:`/`Binary Images`)는 자연히 빠진다.
fn run_stack_sample(pid: u32) -> Option<Value> {
    #[cfg(target_os = "macos")]
    {
        let mut cmd = std::process::Command::new("sample");
        cmd.args([pid.to_string(), SAMPLE_SECS.to_string()]);
        // `sample`은 SAMPLE_SECS 후 자체 종료하지만, wedge 대비 hard deadline으로 강제 kill한다.
        let out = output_with_timeout(cmd, SAMPLE_SECS + 5)?;
        let text = String::from_utf8_lossy(&out.stdout);
        if text.trim().is_empty() {
            return None;
        }
        Some(parse_macos_sample(&text))
    }
    #[cfg(target_os = "linux")]
    {
        // 우선 perf로 userspace CPU 프로파일을 시도하고, 미설치/권한 실패 시 kernel stack 스냅샷으로 강등.
        if let Some(v) = run_perf_sample(pid) {
            return Some(v);
        }
        let stack = std::fs::read_to_string(format!("/proc/{pid}/stack")).ok()?;
        if stack.trim().is_empty() {
            return None;
        }
        Some(json!({
            "available": true,
            "platform": "linux",
            "kind": "kernel_stack",
            "hot_frames": [],
            "threads": [],
            "total_samples": 0,
            "note": "perf 사용 불가(미설치 또는 perf_event_paranoid 권한) — kernel wait-channel 스택만 표시. \
                     userspace 프로파일은 perf_event_paranoid<=1 또는 root 필요.",
            "raw": redaction::redact(&truncate_chars(&stack, SAMPLE_CAP)).0,
        }))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// 서브프로세스를 실행하되 `secs`초 후 강제 종료한다(wedge 방지). stdout만 capture, stderr는 버린다.
#[cfg(target_os = "macos")]
fn output_with_timeout(mut cmd: std::process::Command, secs: u64) -> Option<std::process::Output> {
    use std::process::Stdio;
    use std::time::Instant;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                return None;
            }
        }
    }
    child.wait_with_output().ok()
}

/// macOS `sample` 출력을 구조화한다(순수 함수 — fixture로 테스트). "Sort by top of stack" 섹션을 self-time
/// hot frame 랭킹으로, "Call graph"의 thread 헤더를 thread별 sample 수로 뽑는다. symbol/binary는 redact.
#[cfg(any(target_os = "macos", test))]
fn parse_macos_sample(text: &str) -> Value {
    let mut threads: Vec<Value> = Vec::new();
    let mut hot: Vec<Value> = Vec::new();
    let mut total: u64 = 0;
    let mut section = "";
    for line in text.lines() {
        if line.starts_with("Call graph:") {
            section = "callgraph";
            continue;
        }
        if line.starts_with("Sort by top of stack") {
            section = "topstack";
            continue;
        }
        if line.starts_with("Binary Images:") || line.starts_with("Total number in stack") {
            section = "";
            continue;
        }
        let t = line.trim_start();
        match section {
            // thread 헤더: "<count> Thread_<id>  <desc>" (frame 줄은 count 뒤가 Thread_가 아니라 제외됨).
            "callgraph" => {
                if let Some((cnt, rest)) = split_count_prefix(t) {
                    if let Some(after) = rest.strip_prefix("Thread_") {
                        total += cnt;
                        let mut parts = after.splitn(2, char::is_whitespace);
                        let tid = parts.next().unwrap_or("");
                        let desc = parts.next().unwrap_or("").trim();
                        threads.push(json!({
                            "thread": format!("Thread_{tid}"),
                            "samples": cnt,
                            "desc": redaction::redact(desc).0,
                        }));
                    }
                }
            }
            // "<symbol>  (in <binary>)        <count>"
            "topstack" if hot.len() < HOT_FRAMES => {
                if let Some((sym, bin, cnt)) = parse_top_frame(t) {
                    hot.push(json!({
                        "symbol": redaction::redact(sym).0,
                        "binary": redaction::redact(bin).0,
                        "count": cnt,
                    }));
                }
            }
            _ => {}
        }
    }
    json!({
        "available": true,
        "platform": "macos",
        "kind": "cpu",
        "total_samples": total,
        "threads": threads,
        "hot_frames": hot,
    })
}

/// "<count> <rest>"에서 선두 정수와 나머지를 분리. 정수가 아니면 None(`+`/`!` 마커 줄 등은 걸러진다).
#[cfg(any(target_os = "macos", test))]
fn split_count_prefix(s: &str) -> Option<(u64, &str)> {
    let (num, rest) = s.split_once(char::is_whitespace)?;
    Some((num.parse().ok()?, rest.trim_start()))
}

/// "Sort by top of stack" 한 줄 파싱: "<symbol>  (in <binary>)  <count>".
#[cfg(any(target_os = "macos", test))]
fn parse_top_frame(s: &str) -> Option<(&str, &str, u64)> {
    let open = s.find("(in ")?;
    let symbol = s[..open].trim_end();
    if symbol.is_empty() {
        return None;
    }
    let after = &s[open + 4..];
    let close = after.find(')')?;
    let binary = after[..close].trim();
    let count: u64 = after[close + 1..].split_whitespace().next()?.parse().ok()?;
    Some((symbol, binary, count))
}

/// Linux userspace CPU 프로파일 — `perf record -F 99 -g -p <pid> -- sleep <secs>` → `perf script` 파싱.
/// 미설치/권한(perf_event_paranoid) 실패는 None(호출부가 /proc kernel-stack으로 강등). perf.data는 temp에
/// 쓰고 즉시 삭제한다.
#[cfg(target_os = "linux")]
fn run_perf_sample(pid: u32) -> Option<Value> {
    use std::process::Command;
    let tmp = std::env::temp_dir().join(format!("aic-perf-{}-{pid}.data", std::process::id()));
    let tmp_s = tmp.to_str()?;
    let rec = Command::new("perf")
        .args([
            "record",
            "-F",
            PERF_HZ,
            "-g",
            "-o",
            tmp_s,
            "-p",
            &pid.to_string(),
            "--",
            "sleep",
            &SAMPLE_SECS.to_string(),
        ])
        .output()
        .ok()?;
    if !rec.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return None; // 미설치/권한 → fallback
    }
    let script = Command::new("perf").args(["script", "-i", tmp_s]).output();
    let _ = std::fs::remove_file(&tmp);
    let script = script.ok()?;
    if !script.status.success() {
        return None;
    }
    Some(parse_perf_script(&String::from_utf8_lossy(&script.stdout)))
}

/// `perf script` 출력을 self-time hot frame으로 집계(순수 함수 — fixture로 테스트). 각 sample은 헤더 줄 +
/// 들여쓴 frame 줄들로 구성되고, **첫 frame(leaf) = CPU가 있던 곳**이다. leaf symbol을 세어 랭킹한다.
#[cfg(any(target_os = "linux", test))]
fn parse_perf_script(text: &str) -> Value {
    let mut counts: HashMap<String, (String, u64)> = HashMap::new();
    let mut total = 0u64;
    let mut expecting_leaf = false;
    for line in text.lines() {
        let indented = line.starts_with('\t') || line.starts_with("    ");
        if !indented {
            // 비들여쓰기 + 비공백 = sample 헤더 → 다음 들여쓴 줄이 leaf.
            expecting_leaf = !line.trim().is_empty();
            continue;
        }
        if expecting_leaf {
            expecting_leaf = false;
            total += 1;
            if let Some((sym, module)) = parse_perf_frame(line.trim()) {
                let e = counts.entry(sym).or_insert((module, 0));
                e.1 += 1;
            }
        }
    }
    let mut hot: Vec<(String, (String, u64))> = counts.into_iter().collect();
    hot.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then_with(|| a.0.cmp(&b.0)));
    hot.truncate(HOT_FRAMES);
    let hot_frames: Vec<Value> = hot
        .into_iter()
        .map(|(sym, (module, cnt))| {
            json!({
                "symbol": redaction::redact(&sym).0,
                "binary": redaction::redact(&module).0,
                "count": cnt,
            })
        })
        .collect();
    json!({
        "available": true,
        "platform": "linux",
        "kind": "cpu",
        "total_samples": total,
        "threads": [],
        "hot_frames": hot_frames,
    })
}

/// `perf script` frame 한 줄 파싱: "<addr> <symbol>+<offset> (<module>)" → (symbol, module).
#[cfg(any(target_os = "linux", test))]
fn parse_perf_frame(s: &str) -> Option<(String, String)> {
    let after_addr = s.splitn(2, char::is_whitespace).nth(1)?;
    let (symoff, module) = match after_addr.rsplit_once('(') {
        Some((sym, m)) => (sym.trim(), m.trim_end_matches(')').trim()),
        None => (after_addr.trim(), ""),
    };
    let symbol = symoff.split('+').next().unwrap_or(symoff).trim();
    if symbol.is_empty() {
        return None;
    }
    // module은 full path일 수 있으므로 basename만 — path/deploy 구조 노출 방지(macOS dylib basename과 일관).
    let module = module.rsplit('/').next().unwrap_or(module);
    Some((symbol.to_string(), module.to_string()))
}

/// `process_detail`의 blocking 본체. cpu%는 연속 refresh 간 delta라 짧게 두 번 샘플링한다.
fn collect_process_detail(pid: u32) -> Option<Value> {
    let spid = Pid::from_u32(pid);
    let mut sys = System::new();
    let kind = ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_disk_usage()
        .with_cmd(UpdateKind::Always)
        .with_cwd(UpdateKind::Always)
        .with_exe(UpdateKind::Always);
    sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[spid]), true, kind);
    // cpu%는 두 샘플 사이 delta — 최소 간격 후 한 번 더 refresh.
    std::thread::sleep(Duration::from_millis(200));
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[spid]),
        true,
        ProcessRefreshKind::nothing().with_cpu(),
    );
    let p = sys.process(spid)?;
    let cmd = p
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let du = p.disk_usage();
    Some(json!({
        "available": true,
        "pid": pid,
        "name": p.name().to_string_lossy(),
        "status": p.status().to_string(),
        "parent": p.parent().map(|pp| pp.as_u32()),
        "cmd": redaction::redact(cmd.trim()).0,
        "exe": p.exe().map(|e| redaction::redact(&e.display().to_string()).0),
        "cwd": p.cwd().map(|c| redaction::redact(&c.display().to_string()).0),
        "start_time": p.start_time(),
        "run_time": p.run_time(),
        "threads": p.tasks().map(|t| t.len()),
        "cpu_pct": p.cpu_usage(),
        "memory": p.memory(),
        "virtual_memory": p.virtual_memory(),
        "disk_read_total": du.total_read_bytes,
        "disk_written_total": du.total_written_bytes,
        "network": collect_process_network(pid),
        "runtime_state": collect_process_runtime_state(pid),
    }))
}

/// Tier A tracing — **read-only** 프로세스 상태. ptrace 첨부·정지·메모리 읽기가 전혀 없어 공유 대시보드에
/// 안전하다. Linux는 `/proc/<pid>/{status,wchan}`로 state·blocked-in 심볼·threads·context-switch(=contention
/// 신호)를, macOS는 `ps` fallback(state/wchan)을 준다. 종료/권한 부족은 available:false.
fn collect_process_runtime_state(pid: u32) -> Value {
    #[cfg(target_os = "linux")]
    {
        let base = format!("/proc/{pid}");
        let status = std::fs::read_to_string(format!("{base}/status")).unwrap_or_default();
        if status.is_empty() {
            json!({ "available": false, "platform": "linux", "reason": "/proc 읽기 실패(종료됐거나 권한 없음)" })
        } else {
            let wchan = std::fs::read_to_string(format!("{base}/wchan")).ok();
            parse_proc_status(&status, wchan.as_deref())
        }
    }
    #[cfg(target_os = "macos")]
    {
        runtime_state_macos(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        json!({ "available": false, "platform": "other", "reason": "지원하지 않는 플랫폼" })
    }
}

/// `/proc/<pid>/status` 텍스트(+wchan)에서 read-only 상태 필드를 뽑는 순수 함수. Linux에서만 호출되지만
/// 순수 함수라 macOS에서도 test로 검증한다(그래서 cfg에 test 포함).
#[cfg(any(target_os = "linux", test))]
fn parse_proc_status(status: &str, wchan: Option<&str>) -> Value {
    let field = |key: &str| -> Option<String> {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    };
    let num = |key: &str| {
        field(key)
            .and_then(|v| v.split_whitespace().next().map(str::to_string))
            .and_then(|v| v.parse::<u64>().ok())
    };
    // wchan은 block된 kernel 심볼. 실행 중이면 "0"이라 의미 없어 거른다.
    let wchan = wchan
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "0");
    json!({
        "available": true,
        "platform": "linux",
        "state": field("State:"),
        "threads": num("Threads:"),
        "voluntary_ctxt_switches": num("voluntary_ctxt_switches:"),
        "nonvoluntary_ctxt_switches": num("nonvoluntary_ctxt_switches:"),
        "wchan": wchan,
    })
}

/// macOS는 `/proc`이 없다. `ps`로 state/wchan만 best-effort(ptrace 첨부 없음). threads·ctx-switch는 Linux 전용.
#[cfg(target_os = "macos")]
fn runtime_state_macos(pid: u32) -> Value {
    let output = std::process::Command::new("ps")
        .args(["-o", "state=,wchan=", "-p", &pid.to_string()])
        .output();
    let Ok(output) = output else {
        return json!({ "available": false, "platform": "macos", "reason": "ps 실행 실패" });
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next().unwrap_or("").trim();
    let mut it = line.split_whitespace();
    let state = it.next().map(str::to_string);
    let wchan = it.next().map(str::to_string).filter(|s| s != "-");
    match state {
        None => {
            json!({ "available": false, "platform": "macos", "reason": "프로세스를 찾을 수 없습니다" })
        }
        Some(state) => json!({
            "available": true,
            "platform": "macos",
            "state": state,
            "wchan": wchan,
            "note": "macOS는 /proc 미지원 — state/wchan만(threads·ctx-switch는 Linux 전용).",
        }),
    }
}

/// pid의 네트워크 소켓을 `lsof -nP -p <pid> -i`로 수집한다(probes.rs와 동일 패턴). args는 고정이고 pid는
/// u32라 injection 여지가 없다. 주소는 `redaction`으로 IP를 마스킹해 포트·state·proto만 남긴다(공유
/// 대시보드 정책 일관 — "사용 여부/규모"는 보이되 peer는 가린다). lsof 미설치/실패는 available:false.
fn collect_process_network(pid: u32) -> Value {
    // `-a`로 선택조건을 AND(pid AND internet)로 묶는다 — 없으면 lsof가 OR로 해석해 시스템 전체
    // 소켓을 반환한다(해당 pid가 아님).
    let output = std::process::Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-i"])
        .output();
    let Ok(output) = output else {
        return json!({ "available": false, "reason": "lsof 미설치 또는 실행 실패" });
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut listening: Vec<String> = Vec::new();
    let mut sample: Vec<String> = Vec::new();
    let mut connections = 0usize;
    // 첫 줄은 헤더(COMMAND PID …). NODE(TCP/UDP) 토큰을 찾아 그 뒤를 주소+state로 본다.
    for line in text.lines().skip(1) {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(ni) = toks.iter().position(|t| *t == "TCP" || *t == "UDP") else {
            continue;
        };
        let proto = toks[ni];
        let rest = toks[ni + 1..].join(" ");
        let state = rest
            .rsplit_once('(')
            .and_then(|(_, s)| s.strip_suffix(')'))
            .unwrap_or("");
        let addr = rest.split(" (").next().unwrap_or(rest.as_str());
        let red = redaction::redact(addr).0;
        if state == "LISTEN" {
            listening.push(format!("{proto} {red}"));
        } else {
            connections += 1;
            if sample.len() < PROCESS_NET_SAMPLE {
                let st = if state.is_empty() {
                    String::new()
                } else {
                    format!(" ({state})")
                };
                sample.push(format!("{proto} {red}{st}"));
            }
        }
    }
    json!({
        "available": true,
        "listening": listening,
        "connections": connections,
        "sample": sample,
    })
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

/// `aic chat` 관측 view. 실행 권한은 노출하지 않고, aicd registry/session command store와 audit tail을
/// 결합해 "어떤 세션에서 어떤 명령/이벤트가 있었는지"를 탐색 가능하게 만든다.
async fn chat_observability() -> Json<Value> {
    chat_observability_inner(None).await
}

async fn chat_observability_for_session(Path(session): Path<String>) -> Json<Value> {
    chat_observability_inner(Some(session)).await
}

async fn chat_observability_inner(selected_arg: Option<String>) -> Json<Value> {
    let client = UdsClient::new(aic_common::aicd_socket_path());
    // chat run 수집(mark_stale + process fallback)은 전체 프로세스 스캔(sysinfo refresh)을 돈다 —
    // async 워커를 막지 않도록 통째로 blocking 풀로 보낸다.
    let chat_runs = tokio::task::spawn_blocking(|| {
        let mut chat_runs =
            crate::chat_registry::list_recent(CHAT_SESSION_LIMIT).unwrap_or_default();
        mark_stale_chat_runs(&mut chat_runs);
        let history_fallback = chat_history_fallback();
        if !chat_runs.iter().any(|r| r.status == "active") {
            let known_pids: Vec<u32> = chat_runs.iter().map(|r| r.pid).collect();
            chat_runs.extend(chat_process_fallback(
                history_fallback.as_ref(),
                &known_pids,
            ));
            chat_runs.sort_by_key(|r| std::cmp::Reverse(r.updated_at));
            chat_runs.truncate(CHAT_SESSION_LIMIT);
        }
        if chat_runs.is_empty() {
            if let Some(history) = history_fallback {
                chat_runs.push(history);
            }
        }
        chat_runs
    })
    .await
    .unwrap_or_default();
    let aicd_online = matches!(client.ping().await, Ok(true));
    if !aicd_online && chat_runs.is_empty() {
        return Json(json!({
            "available": false,
            "reason": "aicd와 aic chat registry가 비어 있습니다 — aic chat 또는 aic-session을 실행하세요.",
            "sessions": [],
            "timeline": [],
            "stats": {
                "session_count": 0,
                "command_count": 0,
                "failed_count": 0,
                "audit_count": 0,
            }
        }));
    }

    let mut sessions = if aicd_online {
        match client.list_sessions().await {
            Ok(s) => s,
            Err(e) if chat_runs.is_empty() => {
                return Json(json!({
                    "available": false,
                    "reason": format!("aicd 세션 목록 조회 실패: {e}"),
                    "sessions": [],
                    "timeline": [],
                }))
            }
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };
    sessions.sort_by_key(|b| std::cmp::Reverse(session_sort_millis(b)));

    let selected = selected_arg
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| sessions.first().map(|s| s.id.clone()))
        .or_else(|| chat_runs.first().map(|r| chat_session_id(&r.run_id)));

    let selected_chat_run = selected
        .as_deref()
        .and_then(|id| id.strip_prefix("chat:"))
        .and_then(|run_id| chat_runs.iter().find(|r| r.run_id == run_id).cloned());

    let mut session_rows = Vec::new();
    let mut selected_records = Vec::new();
    let mut command_count = 0usize;
    let mut failed_count = 0usize;

    // 세션별 command 조회는 UDS 왕복이라 순차로 돌리면 최대 CHAT_SESSION_LIMIT번 N+1 직렬 대기가 된다.
    // 각 호출이 독립 연결을 열므로 join_all로 동시에 돌린다(요청당 wall-clock을 1왕복 수준으로 단축).
    let session_slice: Vec<&aic_common::SessionInfo> =
        sessions.iter().take(CHAT_SESSION_LIMIT).collect();
    let session_records: Vec<Vec<_>> = futures::future::join_all(
        session_slice
            .iter()
            .map(|s| client.get_recent_commands_for_session(&s.id, CHAT_RECORD_TAIL)),
    )
    .await
    .into_iter()
    .map(|r| r.unwrap_or_default())
    .collect();

    for (s, records) in session_slice.iter().zip(session_records) {
        command_count += records.len();
        failed_count += records.iter().filter(|r| r.exit_code != 0).count();
        if selected.as_deref() == Some(s.id.as_str()) {
            selected_records = records.clone();
        }
        let last = records.last();
        session_rows.push(json!({
            "id": s.id,
            "kind": "aicd",
            "label": s.label,
            "state": format!("{:?}", s.state),
            "pid": s.pid,
            "created_at": s.created_at,
            "last_seen_at": s.last_seen_at,
            "last_command_at": s.last_command_at,
            "attached_tty": s.attached_tty.as_ref().map(|v| redaction::redact(v).0),
            "shell": s.shell.as_ref().map(|v| redaction::redact(v).0),
            "cwd": s.cwd.as_ref().map(|p| redaction::redact(&p.display().to_string()).0),
            "record_count": records.len(),
            "failed_count": records.iter().filter(|r| r.exit_code != 0).count(),
            "last_exit_code": last.map(|r| r.exit_code),
            "last_command": last.and_then(|r| r.command.as_ref()).map(|c| truncate_chars(&redaction::redact(c).0, 120)),
        }));
    }

    for r in chat_runs.iter().take(CHAT_SESSION_LIMIT) {
        session_rows.push(json!({
            "id": chat_session_id(&r.run_id),
            "kind": "chat",
            "label": format!("aic chat {}", r.run_id),
            "state": r.status,
            "pid": r.pid,
            "created_at": r.started_at,
            "last_seen_at": r.updated_at,
            "last_command_at": Value::Null,
            "attached_tty": Value::Null,
            "shell": Value::Null,
            "cwd": r.cwd.as_ref().map(|v| redaction::redact(v).0),
            "record_count": r.turn_count,
            "failed_count": 0,
            "last_exit_code": Value::Null,
            "last_command": r.last_input,
        }));
    }

    if selected_records.is_empty() && selected_chat_run.is_none() {
        if let Some(id) = selected.as_deref() {
            selected_records = client
                .get_recent_commands_for_session(id, CHAT_RECORD_TAIL)
                .await
                .unwrap_or_default();
        }
    }

    let audit_records = audit::tail_events(CHAT_AUDIT_TAIL).unwrap_or_default();
    let mut timeline = Vec::new();

    if let Some(run) = &selected_chat_run {
        timeline.push(json!({
            "ts": run.updated_at,
            "ts_ms": run.updated_at.timestamp_millis(),
            "kind": "chat",
            "status": run.status,
            "title": format!("aic chat {}", run.run_id),
            "summary": format!("{} turns · pid {}", run.turn_count, run.pid),
            "detail": {
                "run_id": run.run_id,
                "pid": run.pid,
                "status": run.status,
                "started_at": run.started_at,
                "updated_at": run.updated_at,
                "ended_at": run.ended_at,
                "cwd": run.cwd,
                "provider": run.provider,
                "model": run.model,
                "allow_run_command": run.allow_run_command,
                "llm_available": run.llm_available,
                "turn_count": run.turn_count,
                "last_input": run.last_input,
            }
        }));
    }

    for r in &selected_records {
        let command = r
            .command
            .as_ref()
            .map(|c| redaction::redact(c).0)
            .unwrap_or_else(|| "(no command)".to_string());
        let output = redaction::redact(&r.output_lines.join("\n")).0;
        timeline.push(json!({
            "ts": r.timestamp,
            "ts_ms": r.timestamp.timestamp_millis(),
            "kind": "command",
            "status": if r.exit_code == 0 { "ok" } else { "error" },
            "title": truncate_chars(&command, 160),
            "summary": format!("exit {} · {} output lines", r.exit_code, r.output_lines.len()),
            "detail": {
                "id": r.id,
                "command": command,
                "exit_code": r.exit_code,
                "capture_mode": format!("{:?}", r.capture_mode),
                "capture_quality": format!("{:?}", r.capture_quality),
                "output_preview": truncate_chars(&output, 4000),
                "output_metadata": r.output_metadata.clone(),
            }
        }));
    }

    for r in &audit_records {
        if let Some(run) = &selected_chat_run {
            if !r.raw.to_string().contains(&run.run_id) {
                continue;
            }
        }
        let data = redacted_json_value(&r.raw);
        let ts_ms = r.ts.map(|ts| ts.timestamp_millis()).unwrap_or(0);
        timeline.push(json!({
            "ts": r.ts,
            "ts_ms": ts_ms,
            "kind": "audit",
            "status": audit_status(&r.kind),
            "title": r.kind,
            "summary": r.host.as_deref().unwrap_or("local"),
            "detail": data,
        }));
    }
    timeline.sort_by(|a, b| {
        b.get("ts_ms")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .cmp(&a.get("ts_ms").and_then(Value::as_i64).unwrap_or(0))
    });

    Json(json!({
        "available": true,
        "selected_session": selected,
        "sessions": session_rows,
        "timeline": timeline,
        "stats": {
            "session_count": sessions.len() + chat_runs.len(),
            "shown_session_count": session_rows.len(),
            "chat_run_count": chat_runs.len(),
            "command_count": command_count,
            "failed_count": failed_count,
            "audit_count": audit_records.len(),
        }
    }))
}

fn session_sort_millis(s: &aic_common::SessionInfo) -> i64 {
    s.last_seen_at
        .or(s.last_command_at)
        .unwrap_or(s.created_at)
        .timestamp_millis()
}

fn chat_session_id(run_id: &str) -> String {
    format!("chat:{run_id}")
}

fn chat_history_fallback() -> Option<crate::chat_registry::ChatRunRecord> {
    let history = crate::repl::load_chat_history();
    let last_input = history
        .last()
        .map(|s| truncate_chars(&redaction::redact(s).0, 180))?;
    let updated_at = fs::metadata(crate::repl::chat_history_path())
        .and_then(|m| m.modified())
        .map(chrono::DateTime::<chrono::Utc>::from)
        .unwrap_or_else(|_| chrono::Utc::now());
    Some(crate::chat_registry::ChatRunRecord {
        run_id: "history".to_string(),
        pid: 0,
        status: "history".to_string(),
        started_at: updated_at,
        updated_at,
        ended_at: None,
        cwd: None,
        provider: None,
        model: None,
        allow_run_command: false,
        llm_available: false,
        turn_count: history.len() as u64,
        last_input: Some(last_input),
    })
}

fn mark_stale_chat_runs(runs: &mut [crate::chat_registry::ChatRunRecord]) {
    if !runs.iter().any(|r| r.status == "active" && r.pid != 0) {
        return;
    }
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    for run in runs {
        if run.status == "active" && run.pid != 0 && sys.process(Pid::from_u32(run.pid)).is_none() {
            run.status = "stale".to_string();
            run.ended_at = Some(run.updated_at);
        }
    }
}

fn chat_process_fallback(
    history: Option<&crate::chat_registry::ChatRunRecord>,
    known_pids: &[u32],
) -> Vec<crate::chat_registry::ChatRunRecord> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_cwd(UpdateKind::OnlyIfNotSet),
    );
    let now = chrono::Utc::now();
    let mut out = Vec::new();
    for process in sys.processes().values() {
        let pid = process.pid().as_u32();
        if known_pids.contains(&pid) {
            continue;
        }
        let cmd: Vec<String> = process
            .cmd()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        if !looks_like_aic_chat_cmd(&cmd) {
            continue;
        }
        let started_at =
            chrono::DateTime::<chrono::Utc>::from_timestamp(process.start_time() as i64, 0)
                .unwrap_or(now);
        out.push(crate::chat_registry::ChatRunRecord {
            run_id: format!("process{:x}", pid),
            pid,
            status: "process".to_string(),
            started_at,
            updated_at: now,
            ended_at: None,
            cwd: process.cwd().map(|p| p.display().to_string()),
            provider: None,
            model: None,
            allow_run_command: false,
            llm_available: false,
            turn_count: history.map(|h| h.turn_count).unwrap_or(0),
            last_input: history.and_then(|h| h.last_input.clone()),
        });
    }
    out
}

fn looks_like_aic_chat_cmd(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "chat")
        && args.iter().any(|arg| {
            std::path::Path::new(arg)
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name == "aic" || name == "aic-client")
                .unwrap_or(false)
        })
}

fn audit_status(kind: &str) -> &'static str {
    let k = kind.to_ascii_lowercase();
    if k.contains("blocked") || k.contains("denied") || k.contains("error") || k.contains("fail") {
        "error"
    } else if k.contains("warn") || k.contains("degrade") || k.contains("timeout") {
        "warn"
    } else {
        "event"
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// append-only 로그의 마지막 `n`개 비어있지 않은 라인을 끝에서부터 읽는다(역방향 청크 스캔).
/// 파일 전체를 메모리에 올리지 않으므로, 회전 없이 증가하는 `webhook-events.jsonl` 같은 파일도
/// 요청당 비용이 `n`에 바운드된다. 파일 부재/읽기 실패는 빈 Vec(에러 아님).
fn tail_lines(path: &std::path::Path, n: usize) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};
    const CHUNK: u64 = 64 * 1024;
    if n == 0 {
        return Vec::new();
    }
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut pos = match file.seek(SeekFrom::End(0)) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let mut buf: Vec<u8> = Vec::new();
    // 끝에서부터 청크를 역방향으로 읽어 buf 앞쪽에 prepend. 개행 n개 초과 확보 또는 파일 시작
    // 도달 시 중단(맨 앞 partial 라인은 마지막 n개만 take하므로 자동 폐기된다).
    while pos > 0 {
        let read = CHUNK.min(pos);
        pos -= read;
        if file.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        let mut chunk = vec![0u8; read as usize];
        if file.read_exact(&mut chunk).is_err() {
            break;
        }
        chunk.extend_from_slice(&buf);
        buf = chunk;
        if buf.iter().filter(|&&b| b == b'\n').count() > n {
            break;
        }
    }
    let mut lines: Vec<String> = String::from_utf8_lossy(&buf)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    if lines.len() > n {
        lines = lines.split_off(lines.len() - n);
    }
    lines
}

/// aicd webhook alert ingestion 이벤트(`webhook-events.jsonl`) tail. 파일 부재는 빈 목록(에러 아님).
/// 자유 텍스트 필드(action/source/alert)에 redaction을 적용한다.
async fn webhooks() -> Json<Vec<Value>> {
    let path = aic_common::paths::webhook_events_path();
    let evs: Vec<Value> = tail_lines(&path, WEBHOOK_TAIL)
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect();
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
        // 내부 에러 본문은 노출하지 않는다(`internal()`과 동일 정책) — 경로/파싱 detail 누출 방지.
        Err(_e) => return Json(json!({ "error": "config 로드 실패" })),
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
    let hypotheses = rca::load_hypotheses(&id).unwrap_or_default();
    let report = rca::render_report(&meta, &events, &hypotheses);
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
        // 백엔드 에러 Display는 URL/응답 본문을 담을 수 있어 그대로 노출하지 않는다(`internal()` 정책).
        Err(_e) => (
            StatusCode::BAD_REQUEST,
            "관측 질의 실패 (쿼리 또는 백엔드 응답 오류)\n",
        )
            .into_response(),
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
    fn tail_lines_returns_last_n_across_chunks() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        // 64KB CHUNK를 넘기도록 충분히 많은 라인(역방향 다중 청크 경계 검증).
        for i in 0..8000 {
            writeln!(f, "{{\"n\":{i}}}").unwrap();
        }
        writeln!(f).unwrap(); // 끝에 빈 줄: skip 되어야 함.
        drop(f);
        let lines = tail_lines(&path, 100);
        assert_eq!(lines.len(), 100);
        assert_eq!(lines.first().unwrap(), "{\"n\":7900}");
        assert_eq!(lines.last().unwrap(), "{\"n\":7999}");
    }

    #[test]
    fn tail_lines_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(tail_lines(&dir.path().join("nope.jsonl"), 100).is_empty());
    }

    #[test]
    fn tail_lines_fewer_than_n_returns_all_in_order() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "a").unwrap();
        writeln!(f, "b").unwrap();
        drop(f);
        assert_eq!(tail_lines(&path, 100), vec!["a".to_string(), "b".to_string()]);
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
        assert!(!auth_exempt("/web/chat"));
        assert!(!auth_exempt("/web/webhooks"));
        assert!(!auth_exempt("/web/config"));
    }

    #[test]
    fn web_access_audits_sensitive_reads_but_not_resource_poll() {
        // 2초 폴링 엔드포인트와 exempt 경로는 감사 제외(로그 폭주 방지).
        assert!(!web_access_is_audited("/web/local"));
        assert!(!web_access_is_audited("/"));
        assert!(!web_access_is_audited("/web/health"));
        // 민감 read는 감사.
        assert!(web_access_is_audited("/web/audit"));
        assert!(web_access_is_audited("/web/incidents/x/report"));
        assert!(web_access_is_audited("/web/config"));
        assert!(web_access_is_audited("/web/chat"));
    }

    #[test]
    fn parse_macos_sample_extracts_hot_frames_and_threads() {
        let fixture = "Analysis of sampling python3 (pid 100) every 1 millisecond\n\
Process:         python3.13 [100]\n\
Path:            /Users/someone/venv/python3.13\n\
Call graph:\n\
    846 Thread_111   DispatchQueue_1: com.apple.main-thread  (serial)\n\
      846 start  (in dyld) + 6992  [0x18e]\n\
        846 Py_BytesMain  (in libpython3.13.dylib) + 44  [0x103]\n\
    12 Thread_222\n\
      12 _pthread_start  (in libsystem_pthread.dylib) + 99\n\
Total number in stack (recursive counted multiple, when >=5):\n\
Sort by top of stack, same collapsed (when >= 5):\n\
        _PyEval_EvalFrameDefault  (in libpython3.13.dylib)        143\n\
        _PyLong_FromSTwoDigits  (in libpython3.13.dylib)        121\n\
        _Py_dict_lookup  (in libpython3.13.dylib)        82\n\
Binary Images:\n\
        0x100000000 - 0x100ffffff  python3.13\n";
        let v = parse_macos_sample(fixture);
        assert_eq!(v["available"], true);
        assert_eq!(v["total_samples"], 858); // 846 + 12
        assert_eq!(v["threads"].as_array().unwrap().len(), 2);
        assert_eq!(v["threads"][0]["samples"], 846);
        assert_eq!(v["threads"][0]["thread"], "Thread_111");
        let hot = v["hot_frames"].as_array().unwrap();
        assert_eq!(hot.len(), 3);
        assert_eq!(hot[0]["symbol"], "_PyEval_EvalFrameDefault");
        assert_eq!(hot[0]["binary"], "libpython3.13.dylib");
        assert_eq!(hot[0]["count"], 143);
        // Binary Images / Path 등 path-heavy 줄은 구조화 결과에 포함되지 않는다.
        assert!(!v.to_string().contains("/Users/someone"));
    }

    #[test]
    fn parse_perf_script_counts_leaf_self_time() {
        let fixture = "myapp  1234 [001] 1000.1: cycles:\n\
\t7f01 hot_func+0x12 (/usr/lib/libfoo.so)\n\
\t7f02 caller+0x4 (/usr/lib/libfoo.so)\n\
\n\
myapp  1234 [001] 1000.2: cycles:\n\
\t7f01 hot_func+0x20 (/usr/lib/libfoo.so)\n\
\t7f03 other+0x8 (/usr/lib/libbar.so)\n\
\n\
myapp  1234 [001] 1000.3: cycles:\n\
\t7f04 idle+0x0 ([kernel.kallsyms])\n";
        let v = parse_perf_script(fixture);
        assert_eq!(v["available"], true);
        assert_eq!(v["kind"], "cpu");
        assert_eq!(v["total_samples"], 3);
        let hot = v["hot_frames"].as_array().unwrap();
        assert_eq!(hot[0]["symbol"], "hot_func"); // leaf 2회 → 1위
        assert_eq!(hot[0]["binary"], "libfoo.so"); // path가 아니라 basename
        assert_eq!(hot[0]["count"], 2);
        assert!(hot.iter().any(|f| f["symbol"] == "idle" && f["count"] == 1));
        // 절대경로는 노출되지 않는다.
        assert!(!v.to_string().contains("/usr/lib"));
    }

    #[test]
    fn parse_perf_frame_extracts_symbol_and_basename() {
        assert_eq!(
            parse_perf_frame("7f01 hot_func+0x12 (/usr/lib/libfoo.so)"),
            Some(("hot_func".to_string(), "libfoo.so".to_string()))
        );
        assert_eq!(
            parse_perf_frame("ffffff native_halt+0x0 ([kernel.kallsyms])"),
            Some(("native_halt".to_string(), "[kernel.kallsyms]".to_string()))
        );
    }

    #[test]
    fn parse_top_frame_handles_symbol_binary_count() {
        let (s, b, c) =
            parse_top_frame("_Py_dict_lookup  (in libpython3.13.dylib)        82").unwrap();
        assert_eq!((s, b, c), ("_Py_dict_lookup", "libpython3.13.dylib", 82));
        assert!(parse_top_frame("no binary here 5").is_none());
    }

    #[test]
    fn parse_proc_status_extracts_state_and_contention() {
        let fixture = "Name:\tpostgres\nState:\tS (sleeping)\nThreads:\t12\n\
                       voluntary_ctxt_switches:\t34567\nnonvoluntary_ctxt_switches:\t89\n";
        let v = parse_proc_status(fixture, Some("futex_wait_queue_me\n"));
        assert_eq!(v["available"], true);
        assert_eq!(v["state"], "S (sleeping)");
        assert_eq!(v["threads"], 12);
        assert_eq!(v["voluntary_ctxt_switches"], 34567);
        assert_eq!(v["nonvoluntary_ctxt_switches"], 89);
        assert_eq!(v["wchan"], "futex_wait_queue_me");
        // 실행 중(wchan "0")은 의미 없어 거른다.
        let running = parse_proc_status("State:\tR (running)\nThreads:\t1\n", Some("0\n"));
        assert!(running["wchan"].is_null());
        assert_eq!(running["state"], "R (running)");
    }

    #[test]
    fn mask_mac_keeps_oui_and_masks_device_suffix() {
        assert_eq!(mask_mac("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:**:**:**");
        assert_eq!(mask_mac("00:1A:2B:3C:4D:5E"), "00:1A:2B:**:**:**");
        // 빈 값(불명)·비표준 형식은 통째로 마스킹.
        assert_eq!(mask_mac(""), "");
        assert_eq!(mask_mac("not-a-mac"), "**");
        assert_eq!(mask_mac("aa:bb:cc"), "**");
        assert_eq!(mask_mac("aa:bb:cc:dd:ee:gg"), "**"); // 비-hex
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
    fn chat_process_matcher_requires_aic_chat() {
        assert!(looks_like_aic_chat_cmd(&[
            "/tmp/aic".to_string(),
            "chat".to_string()
        ]));
        assert!(looks_like_aic_chat_cmd(&[
            "/tmp/aic-client".to_string(),
            "--flag".to_string(),
            "chat".to_string()
        ]));
        assert!(!looks_like_aic_chat_cmd(&[
            "/tmp/aic".to_string(),
            "web".to_string()
        ]));
        assert!(!looks_like_aic_chat_cmd(&[
            "/tmp/other".to_string(),
            "chat".to_string()
        ]));
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
