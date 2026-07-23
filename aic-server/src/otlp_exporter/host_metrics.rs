//! aicd OTLP exporter용 host metrics 수집기 (SRE t6).
//!
//! aic-client의 `agent::sys_sampler`는 status bar 전용 `pub(crate)`라 재사용할 수 없고, aic-client에
//! 의존성을 추가하지 않기로 했다(설계 지침). 그래서 여기에 exporter 전용 **최소** 샘플러를 새로 둔다.
//! sys_sampler와 동일한 원칙을 따른다: disk/net i/o는 누적 카운터의 delta라 `Disks`/`Networks`
//! 인스턴스를 세션 내내 **재사용**해야 정확하다(매번 새로 만들면 0). 따라서 샘플러는 상태를 든다.
//!
//! 수집 항목은 cpu(사용률·load 1/5/15m·코어 수), memory(usage/limit/available/utilization),
//! swap(usage/limit/utilization), filesystem(usage/available/limit/utilization), disk i/o,
//! network(bytes·packets·errors), process 수, top 프로세스 RSS, uptime이다. 모든 지표를
//! 순간값(Gauge)으로 낸다 — 우리가 계산하는 i/o·packets·errors rate도 이미 "직전 sample 이후
//! 초당"이라 순간값 의미가 맞다.
//!
//! # top 프로세스 RSS의 가시 범위 (실측 결과 — 재조사하지 말 것)
//!
//! `aic.system.memory.top_process.usage`는 **aicd가 RSS를 읽을 수 있는 프로세스 중** 최대값이다.
//! "시스템 전체의 최대"가 아니다. aicd는 사용자 권한(비루트)으로 도는데, 플랫폼별로 이렇게 갈린다:
//!
//! - **Linux: 제약 없음.** `/proc/<pid>/statm`이 world-readable이라 비루트도 다른 uid(root 포함)
//!   프로세스의 RSS를 전부 읽는다. 실측(jw-server): root로 돌렸을 때와 `nobody`(uid 65534)로
//!   돌렸을 때의 최대 프로세스가 동일했다(uid 0 소유 python, 1.92 GiB). zero-RSS 207개는 권한
//!   문제가 아니라 **커널 스레드**(RSS가 실제로 0)다 — root로 돌려도 똑같이 207개다.
//! - **macOS: 다른 uid 프로세스가 안 보인다.** RSS를 주는 `proc_pidinfo(PROC_PIDTASKINFO)`가
//!   same-uid 또는 root를 요구해서, 실패하면 sysinfo가 **0으로 보고**한다. 실측(이 머신, 비루트):
//!   프로세스 1085개 중 **329개(30%)가 RSS 0**이었고, 그 329개는 `user_id()`조차 못 읽는
//!   집합과 정확히 일치했다(= 권한 실패지 진짜 0이 아니다). `ps`가 다른 uid의 RSS를 보여주는
//!   것은 `/bin/ps`가 **setuid root**이기 때문이다(`-rwsr-xr-x root wheel`) — 비루트 바이너리에는
//!   같은 경로가 없으므로 root 없이 정확한 전체 최대를 얻을 방법은 없다.
//!
//! 그래서 macOS에서는 시스템 소유(root/`_windowserver` 등) 프로세스가 진짜 최대일 경우 과소
//! 집계된다. 이 사실을 조용히 두지 않으려고 두 가지를 한다: (1) 비루트 macOS면 시작 시 warn 로그를
//! 한 번 남긴다, (2) 읽을 수 있는 최대가 0이면(=전부 읽기 실패) point 자체를 **생략**한다 —
//! 0을 내보내면 "아무도 메모리를 안 쓴다"는 거짓 신호가 되기 때문이다.
//! (참고: 이 머신에서 못 보는 것 중 가장 큰 프로세스는 `mds_stores` 375 MiB로, 보이는 최대인
//! `OrbStack Helper` 8.6 GiB에 한참 못 미친다 — 지금은 값이 맞지만 그건 이 머신 상태의 우연이다.)

use std::time::Instant;

// fd 조회는 aic-client의 `/local` probe와 **같은 구현을 공유**한다 — 두 크레이트가 각자 세면 같은
// 프로세스에 다른 숫자를 보고하게 되고, 그러면 어느 쪽이 맞는지 판단할 근거가 사라진다.
use aic_common::proc::process_fd_count;

use sysinfo::{Disks, Networks, ProcessRefreshKind, ProcessesToUpdate, System};

/// 한 metric data point — 이름·단위·값. OTLP Gauge 하나로 인코딩된다.
pub struct MetricPoint {
    /// OTel semconv를 느슨히 따른 metric 이름(예: `system.cpu.utilization`).
    pub name: &'static str,
    /// 단위(UCUM): `1`(비율), `By`(바이트), `By/s`(초당 바이트).
    pub unit: &'static str,
    pub value: MetricValue,
}

/// gauge 값 — 실수(비율/부동) 또는 정수(바이트). OTLP `as_double`/`as_int`로 매핑된다.
pub enum MetricValue {
    Double(f64),
    Int(i64),
}

/// resource 식별 속성 — 어느 호스트가 보냈는지. 문자열은 인코딩 시 redact된다.
pub struct ResourceAttrs {
    pub host_name: String,
    pub host_id: String,
    pub os_type: String,
    /// OTel resource semconv `host.arch` — `aarch64`, `x86_64`.
    pub arch: String,
    /// OTel resource semconv `os.description` — "macOS 15.1", "Ubuntu 22.04".
    /// 커널/배포판을 못 읽으면 빈 문자열(수신측이 기존 값을 보존한다).
    pub os_desc: String,
}

/// 프로세스별 리소스 top-N 샘플 하나 — `logs_proto::encode_process_samples`로 인코딩된다.
/// host metrics와 달리 이름/PID 차원을 담으므로 metrics(무차원 Gauge)가 아니라 OTLP Logs로
/// 나간다(logs_proto의 `ProcessEntry` doc 참고).
pub struct ProcessSample {
    pub name: String,
    pub pid: i64,
    /// 직전 tick 이후 CPU 사용률(%). 코어 합산이라 100%를 넘을 수 있다.
    pub cpu_pct: f64,
    pub rss_bytes: u64,
    /// 직전 tick 이후 읽은/쓴 디스크 바이트(delta). 미지원 플랫폼/첫 tick은 0.
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    /// 프로세스 시작 시각(unix epoch 초). `(pid, start_time)` 안정 식별자. rest 버킷은 0.
    pub start_time: u64,
    /// 소유자 실제 uid. top-N만 `/proc/<pid>/status`에서 채운다(Linux). 그 외/미측정은 `None`.
    pub uid: Option<u32>,
    /// 컨테이너 id. top-N만 `/proc/<pid>/cgroup`에서 파싱(Linux). 없으면 `None`.
    pub container_id: Option<String>,
    /// 이 프로세스가 열고 있는 fd 수. **전체 프로세스에 채운다**([`process_fd_count`]) — top-N
    /// 선정의 랭킹 축이라 선정 전에 있어야 하기 때문이다. 권한 부족/프로세스 소멸/미지원
    /// 플랫폼은 `None` → attr 생략. **호스트 전역 `aic.system.file_descriptor.count`와 다른
    /// 축이다**: 전역 합계는 머신 전체가 수천~수만이라 데몬 하나의 fd 누수가 노이즈에 묻힌다.
    /// rest 버킷에서는 "읽을 수 있었던 프로세스들의 합"을 뜻한다.
    pub fd_count: Option<u32>,
}

/// 전체 프로세스 인벤토리 항목 하나 — `aic.process.inventory` CDC용 **경량** 식별 레코드.
///
/// [`ProcessSample`](top_processes)와 달리 **전수**이며 정적 속성만 담는다(cpu/rss/io 같은 게이지
/// 없음) — 이 스트림은 "무엇이 떴다/죽었나"(생성/소멸/변경)를 추적하지 리소스 사용량을 재지
/// 않는다. 게이지는 top-N `aic.process`가 이미 담당한다. `(pid, start_time)`이 안정 식별자다.
///
/// uid/container_id를 여기 담지 않는 이유: 그건 프로세스당 `/proc` 파일 읽기라 비싸므로, CDC
/// 추적기가 **새로 등장한 프로세스(add)에만** enrich한다([`enrich_process_owner`]) — 정적 속성이라
/// 살아 있는 동안 재조회할 필요가 없다. 여기서는 무비용 필드(pid/ppid/start_time/name)만 전수로 낸다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInv {
    pub pid: i64,
    /// 부모 pid(프로세스 트리/토폴로지 조인용). 없으면 0.
    pub ppid: i64,
    /// 시작 시각(unix epoch 초). `(pid, start_time)` 안정 식별자.
    pub start_time: u64,
    pub name: String,
}

/// 매 tick 실을 프로세스 수 — CPU 상위 N + 메모리 상위 N + 디스크 IO 상위 N + **fd 상위 N**
/// (합집합, pid dedupe)이라 최대 4N개. 시계열 키가 (host, pid, name)이라 이 값이 곧 프로세스
/// 신호의 호스트당 카디널리티 상한을 정한다. fd 축을 더하며 상한이 3N→4N으로 늘었지만, 축이
/// 겹치는 프로세스는 dedupe되므로 실측 레코드 수는 그보다 적다.
const TOP_PROCESS_COUNT: usize = 10;

/// rest 버킷(top-N 밖 프로세스 합계)의 센티넬 프로세스명. pid=0과 함께 "이건 집계지 프로세스가
/// 아니다"를 수신측이 구분하는 표식이다.
const REST_BUCKET_NAME: &str = "__rest__";

/// 한 번 수집한 host metrics 스냅샷(resource + gauge point 목록 + top-N 프로세스).
pub struct HostSample {
    pub resource: ResourceAttrs,
    pub points: Vec<MetricPoint>,
    /// CPU/메모리 상위 소비자(scope=`aic.process`). `process_enabled=false`거나 프로세스를 하나도
    /// 못 읽으면 비어 있고, 그러면 호출부(`serve`)가 process logs push를 건너뛴다.
    pub top_processes: Vec<ProcessSample>,
    /// 전체 프로세스 인벤토리(전수, 경량). CDC exporter(`aic.process.inventory`)가 이전 tick과
    /// diff해 add/remove/change만 방출한다. 수집 비용이 미미해(무비용 필드만) `process_enabled`/
    /// `process_inventory_enabled`와 무관하게 항상 채운다 — 사용 여부는 호출부(`serve`)가 판단한다.
    pub process_inventory: Vec<ProcInv>,
}

/// stateful host metrics 샘플러. i/o delta 계산을 위해 `Disks`/`Networks`/직전 시각을 보존한다.
pub struct HostSampler {
    sys: System,
    disks: Disks,
    networks: Networks,
    last: Instant,
    host_name: String,
    host_id: String,
    os_type: String,
    arch: String,
    os_desc: String,
    // t8: host_extra(memory compressor/pressure/fd, t5)의 decompression_rate delta 상태.
    extra: super::host_extra::HostExtraState,
}

impl HostSampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        // 가시 범위가 좁다는 사실을 조용히 두지 않는다(모듈 doc 참고). 샘플러는 프로세스당 한 번만
        // 생성되므로 이 warn도 한 번만 나간다 — 60초마다 로그를 더럽히지 않는다.
        if rss_scope_is_partial() {
            tracing::warn!(
                "aicd가 비루트라 다른 uid 소유 프로세스의 RSS를 읽을 수 없다(macOS) — \
                 aic.system.memory.top_process.usage는 읽을 수 있는 프로세스 중 최대값이며 \
                 시스템 소유 프로세스가 진짜 최대이면 과소 집계된다"
            );
        }
        let host_name = System::host_name().unwrap_or_else(|| "unknown".to_string());
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            last: Instant::now(),
            host_id: host_id(&host_name),
            os_type: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            os_desc: System::long_os_version().unwrap_or_default(),
            host_name,
            extra: super::host_extra::HostExtraState::new(),
        }
    }

    /// 현재 host metrics를 수집한다. disk/net i/o는 직전 sample 이후 delta를 경과시간으로 나눠 bytes/s.
    pub fn sample(&mut self) -> HostSample {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        // 프로세스 수 + top RSS 계산에 memory()가, top-N 프로세스(scope=`aic.process`)의 CPU·disk
        // IO에 cpu_usage()·disk_usage()가 필요해 `.with_cpu().with_memory().with_disk_usage()`를
        // 켠다. disk_usage도 proc_pidinfo(macOS)/`/proc/<pid>/io`(Linux)에서 같은 열거로 얻으므로
        // 순증 비용이 작다. 이 머신(프로세스 ~990개) 실측:
        // nothing() 8.1~15.4ms vs with_memory() 14.1~20.8ms — 차이가 프로세스당 syscall 1회
        // (`proc_pidinfo(PROC_PIDTASKINFO)`) 추가분이고 회차 노이즈에 묻힌다. with_cpu()는
        // proc_pidinfo(PROC_PIDTASKINFO)의 CPU tick을 같은 호출에서 얻으므로 순증 비용이 작다.
        // 프로세스 열거(`proc_listpids`) 자체가 이미 지배적 비용이라 60초 주기에서 유의미한 부담이
        // 아니다. **CPU 사용률은 직전 refresh 이후 delta**라, refresh를 안 하는 `new()` 직후 첫
        // tick에선 프로세스 cpu가 0으로 나오고 두 번째 tick(=60초 후)부터 정상 값이 된다 — top-N도
        // 첫 tick은 메모리 기준으로만 유효하고 그 다음부터 CPU가 채워진다(용인되는 초기 과도구간).
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_disk_usage(),
        );
        self.disks.refresh(false);
        self.networks.refresh(false);
        // 0으로 나누기 방지(연속 호출 간 간격이 아주 짧을 수 있음).
        let elapsed = self.last.elapsed().as_secs_f64().max(0.001);

        let (read, write) = self.disks.list().iter().fold((0u64, 0u64), |acc, d| {
            let u = d.usage();
            (acc.0 + u.read_bytes, acc.1 + u.written_bytes)
        });
        // received()/packets_received()/errors_on_received()는 모두 직전 refresh 이후의 delta다
        // (누적값은 total_* 계열). 그래서 elapsed로 나누면 그대로 초당 rate가 된다.
        let (rx, tx) = self.networks.iter().fold((0u64, 0u64), |acc, (_, data)| {
            (acc.0 + data.received(), acc.1 + data.transmitted())
        });
        let (rx_pkts, tx_pkts) = self.networks.iter().fold((0u64, 0u64), |acc, (_, d)| {
            (
                acc.0 + d.packets_received(),
                acc.1 + d.packets_transmitted(),
            )
        });
        let (rx_errs, tx_errs) = self.networks.iter().fold((0u64, 0u64), |acc, (_, d)| {
            (
                acc.0 + d.errors_on_received(),
                acc.1 + d.errors_on_transmitted(),
            )
        });
        // root fs("/") 기준 용량 — 디스크 full을 가장 직접적으로 드러낸다. 못 찾으면 첫 디스크로 폴백.
        let root = self
            .disks
            .list()
            .iter()
            .find(|d| d.mount_point() == std::path::Path::new("/"))
            .or_else(|| self.disks.list().first());
        let (disk_total, disk_avail) = root
            .map(|d| (d.total_space(), d.available_space()))
            .unwrap_or((0, 0));

        let cpu_pct = self.sys.global_cpu_usage() as f64;
        let cpu_count = self.sys.cpus().len();
        let mem_used = self.sys.used_memory();
        let mem_total = self.sys.total_memory();
        let mem_avail = self.sys.available_memory();
        let swap_used = self.sys.used_swap();
        let swap_total = self.sys.total_swap();
        let load = System::load_average();
        // 스레드는 세지 않는다 — Linux의 `processes()`가 task까지 돌려주므로 그대로 세면 프로세스
        // 수가 스레드 수만큼 부풀어 다른 호스트/시점과 비교할 수 없게 된다([`real_processes`]).
        let proc_count = real_processes(&self.sys).count();
        // 최대 RSS 프로세스의 값만 낸다. 이름/PID는 attr로 넣지 않는다 — 이 머신 고유 프로세스명이
        // 623종이라 cardinality 폭탄이고, 수신측(rca-server) 읽기 경로가 전부 `WHERE host=? AND
        // metric=?` + `avg(value)`라 attrs 필터/GROUP BY가 없어 차원을 넣으면 평균으로 뭉개진다.
        // "범인이 누구인가"는 changes exporter의 rss_spike가 이미 다룬다.
        // 가시 범위(비루트 macOS는 same-uid만)는 모듈 doc 참고.
        let top_rss = top_process_rss(real_processes(&self.sys).map(|p| p.memory()));
        // 프로세스별 top-N(CPU/메모리 상위 소비자). 이미 refresh한 목록을 재사용하므로 추가 열거
        // 비용이 없다. host_metrics의 무차원 Gauge와 달리 이름/PID를 담아 OTLP Logs로 나간다.
        let top_processes = collect_top_processes(&self.sys, TOP_PROCESS_COUNT);
        // 전체 프로세스 인벤토리(전수, 경량). 같은 refresh 목록을 재사용하며 무비용 필드만 읽으므로
        // top-N 수집과 별개의 추가 열거·syscall이 없다(uid/container는 CDC 추적기가 add에만 붙인다).
        let process_inventory = collect_process_inventory(&self.sys);
        let uptime = System::uptime();
        // filesystem은 available/limit만으로도 used를 유도할 수 있지만, 대시보드가 매번
        // 빼기를 하지 않도록 usage/utilization을 직접 낸다(디스크 full이 가장 흔한 사고 원인).
        let disk_used = disk_total.saturating_sub(disk_avail);

        self.last = Instant::now();

        // 전부 순간값 Gauge. i/o는 이미 초당으로 환산했다. total==0(측정 실패)인 utilization은 0으로 둔다.
        let mut points = vec![
            MetricPoint {
                name: "system.cpu.utilization",
                unit: "1",
                value: MetricValue::Double((cpu_pct / 100.0).clamp(0.0, 1.0)),
            },
            MetricPoint {
                name: "system.cpu.load_average.1m",
                unit: "1",
                value: MetricValue::Double(load.one),
            },
            // 5m/15m은 1m과 함께 봐야 "치솟는 중"과 "계속 높음"이 구분된다.
            MetricPoint {
                name: "system.cpu.load_average.5m",
                unit: "1",
                value: MetricValue::Double(load.five),
            },
            MetricPoint {
                name: "system.cpu.load_average.15m",
                unit: "1",
                value: MetricValue::Double(load.fifteen),
            },
            // load를 코어 수로 정규화해야 다른 호스트와 비교할 수 있다.
            MetricPoint {
                name: "system.cpu.logical.count",
                unit: "{cpu}",
                value: MetricValue::Int(cpu_count as i64),
            },
            MetricPoint {
                name: "system.memory.usage",
                unit: "By",
                value: MetricValue::Int(mem_used as i64),
            },
            // available은 used와 다르다 — 캐시/버퍼는 회수 가능하므로, OOM 여유를 보려면 이 값이다.
            MetricPoint {
                name: "system.memory.available",
                unit: "By",
                value: MetricValue::Int(mem_avail as i64),
            },
            MetricPoint {
                name: "system.memory.limit",
                unit: "By",
                value: MetricValue::Int(mem_total as i64),
            },
            MetricPoint {
                name: "system.memory.utilization",
                unit: "1",
                value: MetricValue::Double(ratio(mem_used, mem_total)),
            },
            MetricPoint {
                name: "system.swap.usage",
                unit: "By",
                value: MetricValue::Int(swap_used as i64),
            },
            MetricPoint {
                name: "system.swap.limit",
                unit: "By",
                value: MetricValue::Int(swap_total as i64),
            },
            // swap이 차기 시작하면 메모리 압박의 직접 신호다 — 비율로 봐야 임계치를 걸 수 있다.
            MetricPoint {
                name: "system.swap.utilization",
                unit: "1",
                value: MetricValue::Double(ratio(swap_used, swap_total)),
            },
            MetricPoint {
                name: "system.filesystem.available",
                unit: "By",
                value: MetricValue::Int(disk_avail as i64),
            },
            MetricPoint {
                name: "system.filesystem.limit",
                unit: "By",
                value: MetricValue::Int(disk_total as i64),
            },
            MetricPoint {
                name: "system.filesystem.usage",
                unit: "By",
                value: MetricValue::Int(disk_used as i64),
            },
            MetricPoint {
                name: "system.filesystem.utilization",
                unit: "1",
                value: MetricValue::Double(ratio(disk_used, disk_total)),
            },
            MetricPoint {
                name: "system.disk.io.read",
                unit: "By/s",
                value: MetricValue::Int((read as f64 / elapsed) as i64),
            },
            MetricPoint {
                name: "system.disk.io.write",
                unit: "By/s",
                value: MetricValue::Int((write as f64 / elapsed) as i64),
            },
            MetricPoint {
                name: "system.network.io.receive",
                unit: "By/s",
                value: MetricValue::Int((rx as f64 / elapsed) as i64),
            },
            MetricPoint {
                name: "system.network.io.transmit",
                unit: "By/s",
                value: MetricValue::Int((tx as f64 / elapsed) as i64),
            },
            // bytes만으로는 "작은 패킷 폭주"(SYN flood, retransmit storm)가 안 보인다.
            MetricPoint {
                name: "system.network.packets.receive",
                unit: "{packets}/s",
                value: MetricValue::Int((rx_pkts as f64 / elapsed) as i64),
            },
            MetricPoint {
                name: "system.network.packets.transmit",
                unit: "{packets}/s",
                value: MetricValue::Int((tx_pkts as f64 / elapsed) as i64),
            },
            // errors는 평소 0이라, 0이 아니게 되는 순간 자체가 신호다(NIC/케이블/드라이버).
            MetricPoint {
                name: "system.network.errors.receive",
                unit: "{errors}/s",
                value: MetricValue::Int((rx_errs as f64 / elapsed) as i64),
            },
            MetricPoint {
                name: "system.network.errors.transmit",
                unit: "{errors}/s",
                value: MetricValue::Int((tx_errs as f64 / elapsed) as i64),
            },
            // 프로세스 폭증(fork bomb, 좀비 누적)과 재부팅 여부는 RCA의 기본 질문이다.
            MetricPoint {
                name: "system.process.count",
                unit: "{processes}",
                value: MetricValue::Int(proc_count as i64),
            },
            MetricPoint {
                name: "system.uptime",
                unit: "s",
                value: MetricValue::Int(uptime as i64),
            },
        ];

        // 무차원 스칼라 1개만 낸다(불변식: 이름/PID attr 금지). 프로세스 목록이 비거나 읽을 수 있는
        // 최대가 0이면(=전부 읽기 실패) 생략한다.
        if let Some(rss) = top_rss {
            points.push(MetricPoint {
                name: "aic.system.memory.top_process.usage",
                unit: "By",
                value: MetricValue::Int(rss as i64),
            });
        }

        // t7: 로컬 커널 clock discipline(adjtimex, Linux 전용)에서 얻을 수 있을 때만 추가한다.
        // 네트워크로 NTP 서버에 질의하지 않는다(과설계 금지 — sntp round-trip 없음). 측정
        // 불가(비Linux, 커널이 unsync 보고 등)면 그냥 생략한다 — 이 metric만 없을 뿐 host metrics
        // 나머지는 그대로 나간다.
        if let Some(offset_ms) = super::ntp::ntp_offset_ms() {
            points.push(MetricPoint {
                name: "aic.agent.ntp_offset_ms",
                unit: "ms",
                value: MetricValue::Double(offset_ms),
            });
        }

        // t8: host_extra(memory compressor/pressure/fd, t5) 배선. 실패는 개별 point 생략으로
        // 처리되므로(host_extra.rs 모듈 doc) 여기서 추가로 방어할 게 없다.
        points.extend(super::host_extra::collect(&mut self.extra));

        HostSample {
            resource: ResourceAttrs {
                host_name: self.host_name.clone(),
                host_id: self.host_id.clone(),
                os_type: self.os_type.clone(),
                arch: self.arch.clone(),
                os_desc: self.os_desc.clone(),
            },
            points,
            top_processes,
            process_inventory,
        }
    }
}

/// 프로세스 RSS 목록에서 `top_process.usage`로 낼 값. 순수 함수로 분리해 sysinfo 없이 픽스처로
/// 결정적 검증을 한다.
///
/// `None`을 반환하는 두 경우 모두 호출부는 point를 **생략**해야 한다(`unwrap()` 금지, 불변식):
/// 1. 프로세스 목록이 비었다.
/// 2. 최댓값이 0이다 — 읽을 수 있는 프로세스가 하나도 없다는 뜻이다(모듈 doc의 macOS 권한 제약).
///    0을 그대로 내보내면 "아무도 메모리를 안 쓴다"는 **거짓 신호**가 된다. 읽기 실패한 프로세스는
///    0으로 보고되므로 max에서 자연히 무시된다 — 0이 최대라는 건 전부 실패했다는 것뿐이다.
fn top_process_rss(memories: impl IntoIterator<Item = u64>) -> Option<u64> {
    memories.into_iter().max().filter(|&v| v > 0)
}

/// 이미 refresh된 `sys`의 프로세스 목록에서 top-N을 뽑는다(추가 열거 없음). sysinfo 경계에서
/// 소유 [`ProcessSample`]로 복사한 뒤 순수 함수 [`select_top_processes`]에 위임한다 — 그래야 선택
/// 로직을 sysinfo 없이 결정적으로 테스트할 수 있다.
///
/// # 플랫폼별 가시성 (F — 조용히 두지 않는다)
/// - **macOS 비루트**: 타 uid 프로세스의 RSS/CPU/디스크가 `proc_pidinfo` 권한 부족으로 0으로
///   보고된다(모듈 상단 doc의 RSS 실측 참고 — cpu·disk도 같은 syscall 계열이라 동일하게 막힌다).
///   그래서 top-N이 **same-uid 프로세스로 편향**된다. 또한 uid/container 귀속은 `/proc`에 의존하는
///   Linux 전용이라 macOS에선 항상 `None`이다([`enrich_process_owner`]). aicd의 실제 배포 대상은
///   Linux 서버라 이 편향은 로컬 macOS 개발 관측에만 영향을 준다.
/// - **Linux**: `/proc/<pid>/*`가 world-readable이라 비루트도 전량 읽힌다(uid/container 포함).
fn collect_top_processes(sys: &System, n: usize) -> Vec<ProcessSample> {
    let all: Vec<ProcessSample> = real_processes(sys)
        .map(|p| {
            let io = p.disk_usage();
            ProcessSample {
                name: p.name().to_string_lossy().into_owned(),
                pid: i64::from(p.pid().as_u32()),
                cpu_pct: f64::from(p.cpu_usage()),
                rss_bytes: p.memory(),
                // read_bytes/written_bytes는 직전 refresh 이후 delta(total_*가 누적) — "이 창에서
                // 누가 디스크를 때렸나"라 delta가 맞다.
                disk_read_bytes: io.read_bytes,
                disk_write_bytes: io.written_bytes,
                // start_time은 sysinfo가 이미 준다(무비용, 전 플랫폼). uid/container는 비싸므로
                // (프로세스당 /proc 파일 읽기) 여기서 채우지 않고 select 후 top-N만 enrich한다.
                start_time: p.start_time(),
                uid: None,
                container_id: None,
                // fd는 **전수**로 채운다 — [`select_top_processes`]의 랭킹 축이라 선정 *전에*
                // 있어야 한다. top-N을 뽑은 뒤 채우면 fd만 새고 cpu·rss·disk는 조용한 프로세스가
                // 애초에 후보에 못 들어 영원히 관측되지 않는다(= 누수 탐지가 노리는 바로 그 대상).
                //
                // 비용은 실측으로 확인했다 — 이 머신(1233 프로세스, 총 fd 33366개) 기준 전수
                // 수집 **1.5~1.8ms**(프로세스당 ~1.3µs). 같은 tick의 sysinfo 프로세스 열거가
                // 이미 8~20ms라 순증이 그 10~20%고, tick 주기는 60초다.
                fd_count: process_fd_count(i64::from(p.pid().as_u32())),
            }
        })
        .collect();
    let mut top = select_top_processes(all, n);
    // uid/container는 top-N(+rest)에만 필요하니 여기서만 /proc 파일을 읽는다 — fd와 달리 랭킹
    // 축이 아니라 귀속 정보일 뿐이라 전수로 읽을 이유가 없다. rest 버킷(pid=0)은 건너뛴다.
    for s in top.iter_mut().filter(|s| s.pid > 0) {
        let (uid, container) = enrich_process_owner(s.pid);
        s.uid = uid;
        s.container_id = container;
    }
    top
}

/// 전체 프로세스를 [`ProcInv`] 경량 인벤토리로 수집한다(전수). `sys`는 호출부(`sample`)가 이미
/// `refresh_processes_specifics(All, ..)`한 상태라, 여기서는 무비용 필드(pid/ppid/start_time/name)만
/// 읽는다 — 추가 열거나 `/proc` 파일 읽기가 없다. uid/container는 비싸므로(프로세스당 `/proc` 읽기)
/// 여기서 채우지 않고 CDC 추적기가 새로 등장한 프로세스(add)에만 붙인다([`enrich_process_owner`]).
fn collect_process_inventory(sys: &System) -> Vec<ProcInv> {
    real_processes(sys)
        .map(|p| ProcInv {
            pid: i64::from(p.pid().as_u32()),
            ppid: p.parent().map_or(0, |pp| i64::from(pp.as_u32())),
            start_time: p.start_time(),
            name: p.name().to_string_lossy().into_owned(),
        })
        .collect()
}

/// 스레드를 제외한 **진짜 프로세스**만 훑는다.
///
/// **Linux의 `sys.processes()`는 스레드(task)까지 함께 돌려준다.** 실측(jw-server): 1시간 동안
/// `tokio-rt-worker`가 고유 pid 812개로 잡혔고, 그 안에는 aicd **자신의** tokio 워커 스레드도
/// 있었다(`/proc/<tid>/status`에서 `Tgid != Pid`). 걸러내지 않으면 세 가지가 동시에 망가진다:
/// (1) top-N 자리를 스레드가 차지해 진짜 자원 소비 프로세스가 밀려나고(실측: ClickHouse 호스트의
/// 상위가 `MergeMutate`·`BgSchPool` 같은 내부 스레드로 채워짐), (2) 프로세스 수 메트릭과 인벤토리
/// 볼륨이 부풀며, (3) `aic.process.inventory`에 프로세스가 아닌 것이 섞여 "무엇이 떴다 죽었나"가
/// 스레드 생성/소멸에 묻힌다.
///
/// [`Process::thread_kind`](sysinfo::Process::thread_kind)는 **Linux 외 플랫폼에서 항상 `None`**을
/// 돌려주므로, macOS에서는 이 필터가 no-op이다(그래서 이 버그는 Linux 배포 후에야 드러났다).
fn real_processes(sys: &System) -> impl Iterator<Item = &sysinfo::Process> {
    sys.processes()
        .values()
        .filter(|p| p.thread_kind().is_none())
}

/// top-N 프로세스에만 붙이는 소유자/컨테이너 귀속. **Linux 전용** — `/proc/<pid>/status`의 실제
/// uid와 `/proc/<pid>/cgroup`의 컨테이너 id를 읽는다. 비-Linux(macOS 등)는 `(None, None)`이다
/// (proc 파일이 없다 — sysinfo `with_user`는 프로세스당 비용이 있어 쓰지 않는다). 읽기 실패도
/// `None`으로 흡수한다(권한/레이스로 프로세스가 사라졌어도 신호 전체를 깨지 않는다).
#[cfg(target_os = "linux")]
pub(super) fn enrich_process_owner(pid: i64) -> (Option<u32>, Option<String>) {
    let uid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| parse_status_uid(&s));
    let container = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|s| extract_container_id(&s));
    (uid, container)
}

/// Linux가 아니면 proc 파일이 없다 — 귀속은 생략한다(RSS/CPU 등 나머지는 그대로 나간다).
#[cfg(not(target_os = "linux"))]
pub(super) fn enrich_process_owner(_pid: i64) -> (Option<u32>, Option<String>) {
    (None, None)
}

/// `/proc/<pid>/status`의 `Uid:` 줄에서 **실제 uid**(첫 필드)를 뽑는다. 순수 함수로 분리해 검증한다.
/// 형식: `Uid:\t<real>\t<effective>\t<saved>\t<fs>`. 호출부([`enrich_process_owner`])는 Linux
/// 전용이지만 파싱은 플랫폼 무관이라 어디서든 테스트한다 — 그래서 비-Linux 빌드의 미사용 lint만 끈다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_status_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

/// `/proc/<pid>/cgroup`에서 컨테이너 id(docker/containerd/crio의 64-hex)를 뽑는다. 순수 함수.
/// cgroup 경로 어딘가에 64자 hex 세그먼트가 있으면 그게 컨테이너 id다
/// (예: `0::/system.slice/docker-<64hex>.scope`, `.../kubepods/.../<64hex>`). 없으면 `None`.
/// [`parse_status_uid`]와 같은 이유로 비-Linux 빌드의 미사용 lint만 끈다(파싱은 플랫폼 무관).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn extract_container_id(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .flat_map(|l| l.split(['/', '-', '.', ':', '_']))
        .find(|seg| seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
}

/// CPU 상위 N + 메모리 상위 N + 디스크 IO 상위 N을 골라 pid로 중복 제거한다. 순수 함수로 분리해
/// sysinfo 없이 픽스처로 결정적 검증을 한다([`top_process_rss`]와 동일 취지).
///
/// - CPU 랭킹은 `cpu > 0`, 메모리 랭킹은 `rss > 0`, 디스크 랭킹은 `read+write > 0`, fd 랭킹은
///   `fd > 0` 프로세스만 후보로 본다 — idle/커널 스레드(지표가 모두 0)가 동률로 상위에 끼어
///   노이즈를 만드는 걸 막는다.
/// - 네 랭킹의 **합집합**을 pid로 dedupe → 한 프로세스가 여러 축에서 상위여도 한 번만 실린다.
///   각 레코드는 cpu·rss·disk·fd를 모두 담으므로 어느 축으로 뽑혔든 네 지표가 함께 나간다.
///   디스크 전용 소비자(백업/로그 flush 등, CPU·mem은 낮음)를 놓치지 않으려 디스크를 별도 축으로
///   두고, 같은 이유로 **fd 전용 누수**(cpu·rss·disk는 조용한 채 fd만 늘어나는 형태)를 놓치지
///   않으려 fd를 네 번째 축으로 둔다.
/// - 결과는 cpu 내림차순, 동률이면 pid 오름차순으로 정렬해 결정적이다(tie로 순서가 흔들리지 않게).
fn select_top_processes(all: Vec<ProcessSample>, n: usize) -> Vec<ProcessSample> {
    if n == 0 {
        return Vec::new();
    }
    let cpu_desc_pid_asc = |a: &usize, b: &usize, all: &[ProcessSample]| {
        all[*b]
            .cpu_pct
            .partial_cmp(&all[*a].cpu_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(all[*a].pid.cmp(&all[*b].pid))
    };
    let disk_io = |p: &ProcessSample| p.disk_read_bytes.saturating_add(p.disk_write_bytes);

    let mut by_cpu: Vec<usize> = (0..all.len()).filter(|&i| all[i].cpu_pct > 0.0).collect();
    by_cpu.sort_by(|&a, &b| cpu_desc_pid_asc(&a, &b, &all));
    let mut keep: std::collections::HashSet<usize> = by_cpu.into_iter().take(n).collect();

    let mut by_mem: Vec<usize> = (0..all.len()).filter(|&i| all[i].rss_bytes > 0).collect();
    by_mem.sort_by(|&a, &b| {
        all[b]
            .rss_bytes
            .cmp(&all[a].rss_bytes)
            .then(all[a].pid.cmp(&all[b].pid))
    });
    keep.extend(by_mem.into_iter().take(n));

    let mut by_disk: Vec<usize> = (0..all.len()).filter(|&i| disk_io(&all[i]) > 0).collect();
    by_disk.sort_by(|&a, &b| {
        disk_io(&all[b])
            .cmp(&disk_io(&all[a]))
            .then(all[a].pid.cmp(&all[b].pid))
    });
    keep.extend(by_disk.into_iter().take(n));

    // fd 축 — cpu·rss·disk 어디에도 안 걸리는 **fd 전용 누수**를 잡는 유일한 경로다. 읽기 실패
    // (`None`, 타 uid 권한)는 0으로 접어 후보에서 빠진다: "모른다"를 상위로 올리면 정작 아는
    // 프로세스를 밀어낸다. 이 축이 있어야 fd 상위가 매 tick 안정적으로 실려 수신측이 기울기를
    // 낼 수 있다(멤버십이 흔들리면 시계열에 구멍이 생겨 누수 판정 자체가 불가능하다).
    let fd_of = |p: &ProcessSample| p.fd_count.unwrap_or(0);
    let mut by_fd: Vec<usize> = (0..all.len()).filter(|&i| fd_of(&all[i]) > 0).collect();
    by_fd.sort_by(|&a, &b| {
        fd_of(&all[b])
            .cmp(&fd_of(&all[a]))
            .then(all[a].pid.cmp(&all[b].pid))
    });
    keep.extend(by_fd.into_iter().take(n));

    // top-N에 든 것은 그대로 싣고, 나머지는 **합계 하나(rest 버킷)**로 접는다 — top-N만 보면
    // "많은 작은 프로세스의 합"(fork bomb, N+1 프로세스 폭증, 로그 flush 떼)을 놓친다. rest가
    // top 소비자보다 크면 문제의 성격이 다르다는 신호다. rest는 pid=0·name="__rest__" 센티넬로
    // 표시하고 start_time/uid/container는 두지 않는다(집계라 프로세스 정체성이 없다).
    // fd_count는 **합산한다** — fd를 전수로 수집하게 되면서 rest에 드는 프로세스도 측정값을
    // 갖기 때문이다. 이 합계가 "top-N 밖 어딘가에서 fd가 늘고 있다"(워커 떼가 조금씩 새는 형태,
    // 어느 하나도 단독으로는 상위에 못 드는 경우)를 드러낸다. 단 읽기 실패(`None`)는 합계에서
    // 빠지므로 rest fd는 **읽을 수 있었던 것들의 합**이고, 하나도 못 읽었으면 `None`이 유지된다
    // (0으로 접으면 "아무도 안 열었다"는 거짓 신호가 된다).
    let mut result = Vec::with_capacity(keep.len() + 1);
    let mut rest = ProcessSample {
        name: REST_BUCKET_NAME.to_string(),
        pid: 0,
        cpu_pct: 0.0,
        rss_bytes: 0,
        disk_read_bytes: 0,
        disk_write_bytes: 0,
        start_time: 0,
        uid: None,
        container_id: None,
        fd_count: None,
    };
    for (i, p) in all.into_iter().enumerate() {
        if keep.contains(&i) {
            result.push(p);
        } else {
            rest.cpu_pct += p.cpu_pct;
            rest.rss_bytes = rest.rss_bytes.saturating_add(p.rss_bytes);
            rest.disk_read_bytes = rest.disk_read_bytes.saturating_add(p.disk_read_bytes);
            rest.disk_write_bytes = rest.disk_write_bytes.saturating_add(p.disk_write_bytes);
            if let Some(fd) = p.fd_count {
                rest.fd_count = Some(rest.fd_count.unwrap_or(0).saturating_add(fd));
            }
        }
    }
    result.sort_by(|a, b| {
        b.cpu_pct
            .partial_cmp(&a.cpu_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.pid.cmp(&b.pid))
    });
    // rest는 정렬 뒤 **맨 끝에** 붙인다(cpu 합이 커도 top 소비자로 오해되지 않게). 네 축 모두 0이면
    // 생략한다 — 접을 게 없는데 빈 버킷을 보내면 노이즈다.
    //
    // fd를 이 조건에 넣는 게 중요하다: cpu·rss·disk가 전부 0인데 fd만 쥐고 있는 idle 워커 떼가
    // 정확히 fd 누수 탐지의 대상인데, fd를 빼면 그 rest 버킷이 통째로 버려진다.
    if rest.cpu_pct > 0.0 || rest.rss_bytes > 0 || disk_io(&rest) > 0 || fd_of(&rest) > 0 {
        result.push(rest);
    }
    result
}

/// aicd가 일부 프로세스의 RSS를 못 읽는 상태인가(= `top_process.usage`가 과소 집계될 수 있는가).
///
/// macOS에서 RSS를 주는 `proc_pidinfo(PROC_PIDTASKINFO)`는 same-uid 또는 root를 요구한다 —
/// 비루트면 다른 uid 프로세스가 전부 0으로 보고된다(실측 근거는 모듈 doc). Linux는 `/proc/<pid>/statm`이
/// world-readable이라 비루트도 전량 읽히므로 항상 `false`다.
#[cfg(target_os = "macos")]
fn rss_scope_is_partial() -> bool {
    // SAFETY: `geteuid`는 실패하지 않고 부작용도 없다(POSIX).
    unsafe { libc::geteuid() != 0 }
}

/// Linux 등: 권한에 의한 RSS 사각지대가 없다(모듈 doc의 jw-server 실측).
#[cfg(not(target_os = "macos"))]
fn rss_scope_is_partial() -> bool {
    false
}

/// used/total 비율(0..1). total==0(측정 실패)이면 0.
fn ratio(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (used as f64 / total as f64).clamp(0.0, 1.0)
    }
}

/// 안정적 host.id — Linux는 machine-id 파일, 그 외(macOS 등)는 hostname 폴백. best-effort다.
/// (값 자체는 인코딩 시 redact를 거친다.)
///
/// t7: events/connections exporter도 동일한 host.id를 resource attr로 붙여야 해서 `pub(super)`로
/// 열었다 — otlp_exporter 내 형제 모듈(`events`/`connections`)에서 `super::host_metrics::host_id`로
/// 재사용한다(host_name/host_id 계산 로직을 두 번 만들지 않기 위함).
pub(super) fn host_id(fallback: &str) -> String {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let id = s.trim();
            if !id.is_empty() {
                return id.to_string();
            }
        }
    }
    fallback.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampler_produces_expected_metric_set() {
        // 실제 시스템 호출 — 패닉 없이 host metrics 목록을 반환하는지 확인(값은 환경 의존).
        let mut s = HostSampler::new();
        let sample = s.sample();
        assert!(!sample.resource.host_name.is_empty());
        assert!(!sample.resource.os_type.is_empty());
        // host metrics 26종(cpu 5 + mem 4 + swap 3 + fs 4 + disk io 2 + net io/packets/errors 6 +
        // process 1 + uptime 1)이 항상 나가고, top_process.usage(프로세스 목록 비었을 때만 생략)와
        // ntp_offset_ms(Linux + 커널 sync 상태일 때만)가 각각 선택적으로 붙는다(26~28).
        // t8: host_extra(t5) 배선분이 여기에 더해진다 — macOS는 compressor(0~3) + pressure.level(0~1)
        // + fd count/limit(0~2)로 최대 6종, Linux는 pressure.some/full(0~2) + fd count/limit(0~2)로
        // 최대 4종, 둘 다 최소 0종(sysctl/procfs 읽기 실패 시 전부 생략 가능). 그래서 상한을
        // 28+6=34까지 넉넉히 잡는다 — 특정 머신의 우연한 상태(어떤 point가 정확히 몇 개 나오는지)를
        // 요구하지 않는다(3번째 반복 사고 규칙).
        assert!(
            (26..=34).contains(&sample.points.len()),
            "host metrics 점수는 26~34여야 함, got {}",
            sample.points.len()
        );
        // utilization 계열은 항상 0..1 범위.
        for p in &sample.points {
            if p.name.ends_with(".utilization") {
                if let MetricValue::Double(v) = p.value {
                    assert!((0.0..=1.0).contains(&v), "{} out of range: {v}", p.name);
                }
            }
        }
    }

    #[test]
    fn sample_includes_host_extra_metrics() {
        // 배선 회귀 방지(t8): `host_extra::collect`가 이 머신에서 낼 수 있는 이름들이 `sample()`
        // 출력에도 나타나야 한다 — `points.extend(host_extra::collect(...))` 줄이 빠지면 이 테스트가
        // FAILED한다(mutation check로 실제 확인함). 두 호출은 같은 순간이 아니므로 **값**은 비교하지
        // 않고 **이름 집합**만 비교한다(decompression_rate처럼 1회차엔 없는 값도 있어 완전 일치는
        // 요구하지 않는다).
        //
        // 이 환경(sysctl/procfs 전부 실패)에서 host_extra가 아무것도 못 내면 비교할 것이 없으므로
        // skip한다 — "이 머신의 현재 상태"를 요구하지 않는다(repo 반복 사고 규칙 3번).
        let mut extra_state = super::super::host_extra::HostExtraState::new();
        let direct = super::super::host_extra::collect(&mut extra_state);
        if direct.is_empty() {
            return;
        }

        let mut s = HostSampler::new();
        let sample = s.sample();
        let names: std::collections::HashSet<&str> = sample.points.iter().map(|p| p.name).collect();
        for p in &direct {
            assert!(
                names.contains(p.name),
                "host_extra 배선 누락: {} 이 HostSampler::sample()에 없다",
                p.name
            );
        }
    }

    #[test]
    fn metric_names_are_unique() {
        // 이름이 겹치면 collector에서 서로를 덮어쓴다 — 항목을 늘릴 때 가장 쉬운 실수라 고정한다.
        let mut s = HostSampler::new();
        let sample = s.sample();
        let mut names: Vec<&str> = sample.points.iter().map(|p| p.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "metric 이름 중복: {names:?}");
    }

    #[test]
    fn newly_added_metrics_are_present() {
        let mut s = HostSampler::new();
        let sample = s.sample();
        let names: Vec<&str> = sample.points.iter().map(|p| p.name).collect();
        for expected in [
            "system.cpu.load_average.5m",
            "system.cpu.load_average.15m",
            "system.cpu.logical.count",
            "system.memory.available",
            "system.swap.utilization",
            "system.filesystem.usage",
            "system.filesystem.utilization",
            "system.network.packets.receive",
            "system.network.packets.transmit",
            "system.network.errors.receive",
            "system.network.errors.transmit",
            "system.process.count",
            "system.uptime",
        ] {
            assert!(names.contains(&expected), "{expected} 누락");
        }
    }

    #[test]
    fn process_count_and_uptime_are_plausible() {
        // 자기 자신이 돌고 있으므로 프로세스는 최소 1개, uptime은 0보다 크다.
        let mut s = HostSampler::new();
        let sample = s.sample();
        for p in &sample.points {
            match (p.name, &p.value) {
                ("system.process.count", MetricValue::Int(v)) => {
                    assert!(*v >= 1, "process count가 0: {v}")
                }
                ("system.uptime", MetricValue::Int(v)) => assert!(*v > 0, "uptime이 0: {v}"),
                _ => {}
            }
        }
    }

    #[test]
    fn top_process_usage_is_positive_and_dimensionless() {
        // 자기 자신이 돌고 있으므로 프로세스 목록은 항상 비어있지 않다 — process_count_and_uptime_are_plausible
        // 과 동일 전제. AC3: top_process.usage는 0보다 크고, By 단위 스칼라 하나여야 한다(이름/PID
        // attr 없음 — MetricPoint 자체가 attrs 필드를 두지 않으므로 구조적으로 보장됨, encode.rs 참고).
        let mut s = HostSampler::new();
        let sample = s.sample();
        let found = sample
            .points
            .iter()
            .find(|p| p.name == "aic.system.memory.top_process.usage");
        let p = found.expect("프로세스 목록이 비어있지 않으므로 top_process point가 있어야 함");
        assert_eq!(p.unit, "By");
        match p.value {
            MetricValue::Int(v) => assert!(v > 0, "top_process.usage가 0 이하: {v}"),
            MetricValue::Double(_) => panic!("top_process.usage는 Int(By)여야 함"),
        }
    }

    #[test]
    fn top_process_rss_picks_maximum_not_average() {
        // 순수 함수 불변식: 평균이 아니라 최댓값을 골라야 한다(수신측 avg(value)와 혼동 방지).
        assert_eq!(top_process_rss([100u64, 300, 200]), Some(300));
        assert_eq!(top_process_rss([50u64]), Some(50));
    }

    #[test]
    fn top_process_rss_of_empty_process_list_is_none() {
        // 불변식 1: 프로세스 목록이 비면 None — 호출부가 unwrap 없이 point를 생략할 수 있어야 한다.
        assert_eq!(top_process_rss(std::iter::empty()), None);
    }

    #[test]
    fn top_process_rss_ignores_unreadable_zero_processes() {
        // macOS 비루트에서 읽기 실패한 프로세스는 0으로 보고된다(모듈 doc). 0들이 섞여 있어도
        // 최댓값은 읽을 수 있었던 프로세스에서 나와야 한다 — 0이 결과를 오염시키면 안 된다.
        assert_eq!(top_process_rss([0u64, 0, 4096, 0, 2048]), Some(4096));
    }

    #[test]
    fn top_process_rss_is_none_when_every_process_is_unreadable() {
        // 전부 읽기 실패(모두 0)면 "최대 RSS가 0"이 아니라 "아는 게 없다"이다 — 0을 내보내면
        // "아무도 메모리를 안 쓴다"는 거짓 신호가 되므로 point를 생략해야 한다.
        assert_eq!(top_process_rss([0u64, 0, 0]), None);
        assert_eq!(top_process_rss([0u64]), None);
    }


    fn proc(name: &str, pid: i64, cpu_pct: f64, rss_bytes: u64) -> ProcessSample {
        ProcessSample {
            name: name.to_string(),
            pid,
            cpu_pct,
            rss_bytes,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            start_time: 0,
            uid: None,
            container_id: None,
            fd_count: None,
        }
    }

    /// cpu·rss·disk는 전부 0이고 **fd만** 높은 프로세스 — fd 전용 누수의 픽스처.
    fn proc_fd(name: &str, pid: i64, fd_count: u32) -> ProcessSample {
        ProcessSample {
            name: name.to_string(),
            pid,
            cpu_pct: 0.0,
            rss_bytes: 0,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            start_time: 0,
            uid: None,
            container_id: None,
            fd_count: Some(fd_count),
        }
    }

    fn proc_io(name: &str, pid: i64, disk_read_bytes: u64, disk_write_bytes: u64) -> ProcessSample {
        ProcessSample {
            name: name.to_string(),
            pid,
            cpu_pct: 0.0,
            rss_bytes: 0,
            disk_read_bytes,
            disk_write_bytes,
            start_time: 0,
            uid: None,
            container_id: None,
            fd_count: None,
        }
    }

    /// fd만 높고 cpu·rss·disk는 조용한 프로세스가 top-N에 실려야 한다. 이 축이 없으면 fd 전용
    /// 누수 프로세스는 후보에조차 못 들어 **영원히** 관측되지 않는다 — 정확히 누수 탐지가 노리는
    /// 대상이 사라지는 것이라, fd 축의 존재 이유가 이 테스트다.
    #[test]
    fn select_top_processes_includes_fd_only_leaker() {
        let all = vec![
            proc("cpu-hog", 1, 95.0, 0),
            proc("mem-hog", 2, 0.0, 8_000_000_000),
            proc_fd("fd-leaker", 3, 9000),
            proc("idle", 4, 0.0, 0),
        ];
        let top = select_top_processes(all, 1);
        let pids: Vec<i64> = top.iter().map(|p| p.pid).collect();
        assert!(
            pids.contains(&3),
            "fd 전용 누수 프로세스가 top-N에 없다: {pids:?}"
        );
        assert!(
            !pids.contains(&4),
            "네 지표가 모두 0인 idle은 실리면 안 된다: {pids:?}"
        );
    }

    /// top-N 밖 프로세스의 fd는 rest 버킷에 합산된다 — "어느 하나도 상위는 아니지만 떼로 새는"
    /// 형태를 보려는 것이다. 반대로 전부 읽기 실패면 `None`이어야 한다: 0으로 접으면 "아무도 fd를
    /// 안 열었다"는 거짓 신호가 되고, 인코딩에서 attr을 생략할 근거가 사라진다.
    #[test]
    fn rest_bucket_sums_readable_fd_only() {
        let all = vec![
            proc("top", 1, 99.0, 0),
            proc_fd("small-a", 2, 100),
            proc_fd("small-b", 3, 50),
        ];
        let top = select_top_processes(all, 1);
        let rest = top.iter().find(|p| p.pid == 0).expect("rest 버킷이 있어야 한다");
        // fd 축도 n=1이라 small-a(100)만 뽑히고 small-b(50)가 rest로 접힌다.
        assert_eq!(rest.fd_count, Some(50));

        // fd_count가 전부 None(권한 부족)이면 rest도 None을 유지한다.
        let all = vec![
            proc("top", 1, 99.0, 0),
            proc("x", 2, 0.0, 10),
            proc("y", 3, 0.0, 5),
        ];
        let top = select_top_processes(all, 1);
        let rest = top.iter().find(|p| p.pid == 0).expect("rest 버킷이 있어야 한다");
        assert_eq!(rest.fd_count, None);
    }

    /// cpu·rss·disk가 전부 0이어도 **fd 합계만 있으면** rest 버킷을 내보내야 한다. fd를 push
    /// 조건에서 빼면 idle 워커 떼의 fd 누수 신호가 통째로 버려진다.
    #[test]
    fn rest_bucket_survives_on_fd_alone() {
        let all = vec![
            proc_fd("selected", 1, 500),
            proc_fd("folded-a", 2, 40),
            proc_fd("folded-b", 3, 30),
        ];
        let top = select_top_processes(all, 1);
        let rest = top
            .iter()
            .find(|p| p.pid == 0)
            .expect("fd만 있어도 rest 버킷이 남아야 한다");
        assert_eq!(rest.fd_count, Some(70));
        assert_eq!(rest.cpu_pct, 0.0);
        assert_eq!(rest.rss_bytes, 0);
    }

    #[test]
    fn select_top_processes_unions_cpu_and_memory_leaders() {
        // CPU 1등(rss 작음)과 메모리 1등(cpu 0)이 둘 다 뽑혀야 한다 — 한 축만 보면 반대 축의
        // 범인을 놓친다. dedupe라 양쪽 상위인 프로세스는 한 번만.
        let all = vec![
            proc("cpu-hog", 1, 95.0, 1024),
            proc("mem-hog", 2, 0.0, 8 * 1024 * 1024 * 1024),
            proc("both", 3, 80.0, 4 * 1024 * 1024 * 1024),
            proc("idle", 4, 0.0, 0), // cpu·rss 둘 다 0 → 후보 아님
        ];
        let top = select_top_processes(all, 2);
        let pids: Vec<i64> = top.iter().map(|p| p.pid).collect();
        // top2 cpu = {1,3}, top2 mem = {2,3} → 합집합 {1,2,3}, idle(4)은 제외.
        assert!(pids.contains(&1) && pids.contains(&2) && pids.contains(&3));
        assert!(!pids.contains(&4), "cpu·rss 둘 다 0인 idle은 실리면 안 된다");
        assert_eq!(top.len(), 3);
        // cpu 내림차순 정렬: cpu-hog(95) > both(80) > mem-hog(0).
        assert_eq!(top[0].pid, 1);
        assert_eq!(top[1].pid, 3);
        assert_eq!(top[2].pid, 2);
    }

    #[test]
    fn select_top_processes_dedupes_process_in_both_rankings() {
        // 한 프로세스가 CPU·메모리 양쪽 최상위여도 한 번만 실린다(중복 시계열 금지).
        let all = vec![
            proc("heavy", 1, 99.0, 16 * 1024 * 1024 * 1024),
            proc("light", 2, 1.0, 1024),
        ];
        let top = select_top_processes(all, 5);
        assert_eq!(top.iter().filter(|p| p.pid == 1).count(), 1);
    }

    #[test]
    fn select_top_processes_excludes_zero_cpu_zero_rss_noise() {
        // 커널 스레드/idle(cpu=0 & rss=0)이 tie로 상위에 끼면 안 된다 — 후보 자체에서 배제.
        let all = vec![
            proc("real", 1, 5.0, 512 * 1024 * 1024),
            proc("k0", 2, 0.0, 0),
            proc("k1", 3, 0.0, 0),
            proc("k2", 4, 0.0, 0),
        ];
        let top = select_top_processes(all, 3);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].pid, 1);
    }

    #[test]
    fn select_top_processes_captures_disk_only_consumer() {
        // 디스크 전용 소비자(cpu·rss 낮음, IO 큼 — 백업/로그 flush)가 CPU·메모리 축에는 안 걸려도
        // 디스크 축으로 뽑혀야 한다. 디스크를 별도 축으로 두는 이유가 이것이다.
        let all = vec![
            proc("cpu-hog", 1, 90.0, 1024),
            proc("mem-hog", 2, 0.0, 8 * 1024 * 1024 * 1024),
            proc_io("backup", 3, 0, 2 * 1024 * 1024 * 1024), // disk write만 큼
        ];
        let top = select_top_processes(all, 1);
        let pids: Vec<i64> = top.iter().map(|p| p.pid).collect();
        // top1 cpu={1}, top1 mem={2}, top1 disk={3} → 합집합 {1,2,3}.
        assert!(
            pids.contains(&3),
            "디스크 전용 소비자가 top-N에 없다: {pids:?}"
        );
        assert_eq!(top.len(), 3);
    }

    #[test]
    fn select_top_processes_folds_long_tail_into_rest_bucket() {
        // top-N 밖 프로세스들의 자원은 rest 버킷(pid=0, name=__rest__) 하나로 접혀 맨 끝에 붙는다.
        let all = vec![
            proc("big", 1, 90.0, 8 * 1024 * 1024 * 1024),
            proc("small1", 2, 5.0, 1024 * 1024),
            proc("small2", 3, 3.0, 2 * 1024 * 1024),
        ];
        let top = select_top_processes(all, 1);
        // cpu/mem top1 = {big}, disk none → keep={1}. small1/small2는 rest로 접힘.
        assert_eq!(top.len(), 2, "top1 + rest 버킷");
        assert_eq!(top[0].pid, 1, "실제 top은 앞에");
        let rest = top.last().unwrap();
        assert_eq!(rest.pid, 0);
        assert_eq!(rest.name, REST_BUCKET_NAME);
        assert!((rest.cpu_pct - 8.0).abs() < 1e-9, "cpu 합 5+3");
        assert_eq!(rest.rss_bytes, 3 * 1024 * 1024, "rss 합 1M+2M");
    }

    #[test]
    fn select_top_processes_omits_empty_rest_bucket() {
        // 모든 프로세스가 top-N에 들면 접을 게 없으니 rest 버킷을 붙이지 않는다.
        let all = vec![proc("a", 1, 10.0, 1024), proc("b", 2, 5.0, 2048)];
        let top = select_top_processes(all, 5);
        assert!(top.iter().all(|p| p.pid != 0), "빈 rest 버킷은 없어야 한다");
    }

    #[test]
    fn parse_status_uid_extracts_real_uid() {
        let status = "Name:\tnginx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_uid(status), Some(1000));
        // root
        assert_eq!(parse_status_uid("Uid:\t0\t0\t0\t0\n"), Some(0));
        // Uid 줄 없음
        assert_eq!(parse_status_uid("Name:\tx\n"), None);
    }

    #[test]
    fn extract_container_id_finds_64hex_segment() {
        let id = "abc123def456abc123def456abc123def456abc123def456abc123def4560000";
        assert_eq!(
            extract_container_id(&format!("0::/system.slice/docker-{id}.scope")),
            Some(id.to_string())
        );
        assert_eq!(
            extract_container_id(&format!("12:cpu,cpuacct:/kubepods/burstable/pod-x/{id}")),
            Some(id.to_string())
        );
        // 컨테이너 밖(호스트 프로세스) — 64-hex 세그먼트가 없다.
        assert_eq!(extract_container_id("0::/init.scope"), None);
        assert_eq!(extract_container_id("0::/user.slice/user-1000.slice"), None);
    }

    #[test]
    fn select_top_processes_empty_when_n_is_zero() {
        let all = vec![proc("a", 1, 10.0, 1024)];
        assert!(select_top_processes(all, 0).is_empty());
    }

    #[test]
    fn collect_top_processes_from_live_system_are_readable() {
        // 실제 시스템: 자기 자신이 돌고 있으므로 최소 1개는 뽑히고(비어 있지 않고), 뽑힌 것은
        // cpu>0 또는 rss>0 중 하나는 만족해야 한다(idle 노이즈 배제 회귀 가드).
        let mut s = HostSampler::new();
        // cpu delta가 채워지도록 두 번 sample한다(첫 tick은 프로세스 cpu가 0).
        let _ = s.sample();
        let sample = s.sample();
        for p in &sample.top_processes {
            assert!(
                p.cpu_pct > 0.0 || p.rss_bytes > 0 || p.disk_read_bytes > 0 || p.disk_write_bytes > 0,
                "cpu·rss·disk 모두 0인 프로세스가 top-N에 실렸다: {} pid={}",
                p.name,
                p.pid
            );
        }
        assert!(
            sample.top_processes.len() <= 3 * TOP_PROCESS_COUNT + 1,
            "top-N 상한(3N: cpu+mem+disk, +1 rest 버킷) 초과: {}",
            sample.top_processes.len()
        );
    }

    #[test]
    fn ratio_handles_zero_total() {
        assert_eq!(ratio(0, 0), 0.0);
        assert_eq!(ratio(5, 10), 0.5);
        // used > total(측정 순간 불일치)이어도 1.0으로 clamp.
        assert_eq!(ratio(20, 10), 1.0);
    }
}
