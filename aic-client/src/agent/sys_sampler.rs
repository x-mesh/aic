//! `aic chat` status bar용 시스템 지표 샘플러 — sysinfo crate로 in-process 수집.
//!
//! load average와 memory는 순간값이지만 **disk i/o는 누적 카운터의 delta**다. sysinfo의
//! `DiskUsage::read_bytes`/`written_bytes`가 마지막 refresh 이후 delta를 자동 계산하므로,
//! `Disks` 인스턴스를 세션 내내 **재사용**해야 정확하다(매번 새로 만들면 0). 따라서 샘플러는
//! 상태를 들고 다닌다. SRE 진단 probe catalog(`agent::probes`)와는 별개 경로다(그쪽은 one-shot 명령).

use std::time::{Duration, Instant};
use sysinfo::{Disks, Networks, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// load/cpu/memory/disk-i/o/net-i/o를 들고 있는 stateful 샘플러. status bar 전용.
pub(crate) struct SysSampler {
    sys: System,
    disks: Disks,
    networks: Networks,
    last: Instant,
}

/// status bar 지표의 임계 단계 — 정상(dim) → 경고(주황) → 위험(빨강). status bar 컬러링용.
/// 변형 선언 순서(Normal < Warn < Crit)가 곧 심각도 순서다 — `Ord`로 `overall_severity`가
/// 여러 지표 중 최댓값을 그대로 고른다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Severity {
    Normal,
    Warn,
    Crit,
}

// status bar 임계값(named const). macOS dev 호스트 오탐을 줄이려 보수적으로 둔다.
// cpu/mem/swap는 %, load는 코어수 배수, disk는 **신뢰 가능한 free bytes 절대값**(APFS % 부정확 회피).
const CPU_WARN_PCT: f32 = 85.0;
const CPU_CRIT_PCT: f32 = 95.0;
const MEM_WARN_PCT: f64 = 90.0;
const MEM_CRIT_PCT: f64 = 97.0;
const SWAP_WARN_PCT: f64 = 50.0;
const SWAP_CRIT_PCT: f64 = 90.0;
/// load1/코어수 배수 — 1.0(코어수와 같음)=warn, 2.0(2배)=crit.
const LOAD_WARN_RATIO: f64 = 1.0;
const LOAD_CRIT_RATIO: f64 = 2.0;
/// root fs 여유 용량 절대 임계(GiB). 사용률 %는 macOS APFS에서 부정확해 free bytes로 판정.
const DISK_WARN_FREE: u64 = 5 * 1024 * 1024 * 1024;
const DISK_CRIT_FREE: u64 = 1024 * 1024 * 1024;

// 적응형 샘플링 주기(초). 전부 Normal이면 느슨하게(노트북에서 2초마다 CPU를 깨우지 않아 배터리 절약),
// Warn/Crit이면 촘촘하게 해상도를 확보한다. C4 council 합의: idle/Normal 5s, Warn/Crit 2s.
const CADENCE_NORMAL_SECS: u64 = 5;
const CADENCE_ALERT_SECS: u64 = 2;

// edge-triggered alert의 자원별 재발화 cooldown. 동일 자원이 악화 전이를 반복해도 이 주기 안엔 다시
// 발화하지 않는다(alert fatigue 방지 + "idle ≤1건/10분" 예산의 실제 rate limiter). Crit이 Warn보다
// 짧다 — 위험은 빨리 다시 알린다. C1 council 합의(§3).
const WARN_COOLDOWN: Duration = Duration::from_secs(300);
const CRIT_COOLDOWN: Duration = Duration::from_secs(120);

/// alert 대상 자원 수(임계가 있는 load/cpu/mem/swap/disk — io 제외). `AlertTracker` 배열의 키 범위.
const ALERT_RESOURCES: usize = 5;

// disk 소진 ETA(C2) 게이트 — Round 3 deep-dive에서 확정한 수치. transient(cargo build/docker pull)·
// sawtooth가 가짜 "~N분 후 full"을 절대 못 내게 다중 게이트를 쌓는다. disk_avail만 대상이며(swap→v1.1,
// mem→sparkline only), disk_sev∈{Warn,Crit}일 때만 arm한다(20GB transient는 non-full 디스크에만 착지
// =Normal=disarm이라 구조적으로 차단). 순수 게이트는 `disk_eta_candidate`, 상태는 `DiskEtaTracker`.
const ETA_WINDOW: Duration = Duration::from_secs(300);
/// 적합에 필요한 최소 표본 수 + 최소 시간 span(둘 다 충족해야 함 — 비균일 cadence를 시간으로 묶는다).
const ETA_MIN_SAMPLES: usize = 10;
const ETA_MIN_SPAN: Duration = Duration::from_secs(300);
/// 비증가 run 최소 길이(상승 지터 `ETA_UP_JITTER`까지는 run 유지) + 감소 step 비율 최소.
const ETA_MONOTONIC_RUN_MIN: usize = 6;
const ETA_DECLINE_FRACTION_MIN: f64 = 0.75;
const ETA_UP_JITTER: u64 = 16 * 1024 * 1024;
/// 최소 기울기(bytes/s) = 5 MiB/min — 이보다 완만하면 FS 지터에 묻혀 ETA가 무의미.
const ETA_MIN_SLOPE_BPS: f64 = 5.0 * 1024.0 * 1024.0 / 60.0;
/// 선형 적합 품질 하한 — transient의 V자/톱니는 직선 R²가 낮아 여기서 걸린다.
const ETA_R2_MIN: f64 = 0.90;
/// 표시 horizon 밴드(초). 너무 짧으면(정적 crit 색이 소유) / 너무 멀면(actionable 아님) 숫자를 숨긴다.
const ETA_MIN_HORIZON_SECS: f64 = 60.0;
const ETA_MAX_HORIZON_SECS: f64 = 7200.0;
/// 이만큼(256 MiB) 여유가 한 번에 늘면 = 공간 회수(build 종료 등) → 즉시 ETA 철회.
const ETA_REFILL_BYTES: u64 = 256 * 1024 * 1024;

/// 한 번 sample한 지표 스냅샷. watch 채널로 publish하려면 `Clone`. `Default`(전부 0/None)는 테스트
/// 리터럴 작성을 단순화하고 "지표 없음" 초기 상태로도 의미가 있다.
#[derive(Clone, Default)]
pub(crate) struct SysMetrics {
    pub load1: f64,
    pub cpu_pct: f32,
    /// 논리 코어 수(load1 정규화용). 최소 1.
    pub cores: usize,
    pub mem_used: u64,
    pub mem_total: u64,
    /// swap 사용량/총량(메모리 압박·OOM 조기 신호). total==0이면 swap 비활성.
    pub swap_used: u64,
    pub swap_total: u64,
    /// root fs("/") 여유 용량(디스크 full 감지). total==0이면 읽기 실패(n/a).
    /// macOS APFS는 컨테이너 공유라 `total - avail` 기반 사용률 %가 무의미(df 21% vs 계산 93%).
    /// `available_space()`만 플랫폼 무관하게 신뢰 가능하므로 여유 용량(free)을 1차 지표로 쓴다.
    pub disk_avail: u64,
    pub disk_total: u64,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    /// 전체 인터페이스 합산 수신/송신 bytes/s (loopback 포함).
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    /// mem가 Warn 이상일 때만 채워지는 "가장 무거운(최대 RSS) 프로세스" — alert가 범인을 지목하는 데
    /// 쓴다(이름, RSS bytes). Normal이면 None(process 열거 비용 0). §C4 actionability.
    pub top_mem_proc: Option<(String, u64)>,
    /// disk 소진 ETA(C2) — sampler task의 `TrendTracker`가 채운다(`sample()`은 항상 None으로 두고
    /// task가 덮어쓴다). status bar disk 세그먼트에 dim 접미로 표시. 비-task 경로(spinner 등)는 None.
    pub disk_eta: Option<DiskEta>,
    /// metric sparkline(C2) — `(status_segments 세그먼트 인덱스, " ▁▂▇↑" 접미)`. task의 `TrendTracker`가
    /// 가장 심각한 metric(cpu/mem/disk)에 대해 채운다. status_segments가 해당 세그먼트에 붙인다.
    pub trend_spark: Option<(usize, String)>,
}

/// disk 여유 소진 예측(C2) — CRIT(1GiB)까지 남은 시간의 버킷 라벨. status bar disk 세그먼트에 dim
/// 접미(`· ~8m→crit`)로 붙어 disk 단계 색을 상속한다(standalone 무색 표시 없음).
#[derive(Clone)]
pub(crate) struct DiskEta {
    /// 버킷 라벨(`~2m`/`~5m`/`~15m`/`~1h`/`~2h`) — tick마다 흔들리지 않게 양자화.
    pub bucket: &'static str,
}

impl SysSampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            last: Instant::now(),
        }
    }

    /// 현재 지표를 샘플한다. disk/net i/o는 직전 sample 이후 delta를 경과시간으로 나눠 bytes/s로 환산.
    pub fn sample(&mut self) -> SysMetrics {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(false);
        self.networks.refresh(false);
        // 0으로 나누기 방지(연속 호출 간 간격이 아주 짧을 수 있음).
        let elapsed = self.last.elapsed().as_secs_f64().max(0.001);
        let (read, write) = self.disks.list().iter().fold((0u64, 0u64), |acc, d| {
            let u = d.usage();
            (acc.0 + u.read_bytes, acc.1 + u.written_bytes)
        });
        // networks.refresh() 이후 received()/transmitted()는 마지막 refresh 이후 delta.
        let (rx, tx) = self.networks.iter().fold((0u64, 0u64), |acc, (_, data)| {
            (acc.0 + data.received(), acc.1 + data.transmitted())
        });
        // 용량은 root fs("/") 기준 — 디스크 full을 가장 직접적으로 드러낸다. macOS APFS는 볼륨
        // 그룹이 "/"에 공유 표시되고, Linux는 "/"가 명확하다. 못 찾으면(컨테이너 등) 첫 디스크로 폴백.
        let root = self
            .disks
            .list()
            .iter()
            .find(|d| d.mount_point() == std::path::Path::new("/"))
            .or_else(|| self.disks.list().first());
        let (disk_total, disk_avail) = root
            .map(|d| (d.total_space(), d.available_space()))
            .unwrap_or((0, 0));
        self.last = Instant::now();
        let mut m = SysMetrics {
            load1: System::load_average().one,
            cpu_pct: self.sys.global_cpu_usage(),
            // 논리 코어 수 — sysinfo refresh 상태와 무관한 std API로 안정 측정(load 정규화 기준).
            cores: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            mem_used: self.sys.used_memory(),
            mem_total: self.sys.total_memory(),
            swap_used: self.sys.used_swap(),
            swap_total: self.sys.total_swap(),
            disk_avail,
            disk_total,
            disk_read_bps: (read as f64 / elapsed) as u64,
            disk_write_bps: (write as f64 / elapsed) as u64,
            net_rx_bps: (rx as f64 / elapsed) as u64,
            net_tx_bps: (tx as f64 / elapsed) as u64,
            top_mem_proc: None,
            // sample()은 ETA·sparkline을 모른다(상태가 필요) — sampler task의 TrendTracker가 publish
            // 직전 덮어쓴다.
            disk_eta: None,
            trend_spark: None,
        };
        // proc-enrich(§C4): mem가 Warn 이상일 때만 process 목록을 in-process로 refresh해 최대 RSS
        // 프로세스(범인)를 지목한다. Normal 경로는 process 열거를 전혀 하지 않아 sub-ms 비용을 유지하고
        // (probe fork도 아님), 이 호출은 sampler task의 spawn_blocking에서 도므로 UI를 막지 않는다.
        // RSS는 단일 refresh로 정확하다(cpu%는 delta가 필요해 별도 — 미구현).
        if m.mem_sev() >= Severity::Warn {
            // **memory만** refresh한다 — cmd/env/cwd/disk까지 가져오는 full refresh는 macOS 첫 호출에서
            // 수 초가 걸린다. 우리는 (이름, RSS)만 필요하므로 ProcessRefreshKind::nothing().with_memory()로
            // 비용을 최소화한다(이름은 기본 정보라 항상 포함).
            self.sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing().with_memory(),
            );
            m.top_mem_proc = self
                .sys
                .processes()
                .values()
                .max_by_key(|p| p.memory())
                .map(|p| (p.name().to_string_lossy().into_owned(), p.memory()));
        }
        m
    }
}

impl SysMetrics {
    /// status bar 한 줄(ANSI 없음 — 출력 시 paint). 순수 함수(테스트 가능).
    pub fn status_line(&self) -> String {
        let mem_pct = if self.mem_total > 0 {
            self.mem_used as f64 * 100.0 / self.mem_total as f64
        } else {
            0.0
        };
        // swap: 활성(total>0)이면 사용률 %, 아니면 off.
        let swap = if self.swap_total > 0 {
            format!("swap {:.0}%", self.swap_used as f64 * 100.0 / self.swap_total as f64)
        } else {
            "swap off".to_string()
        };
        let disk = self.disk_label();
        let clock = chrono::Local::now().format("%H:%M:%S").to_string();
        format!(
            "{} · load {:.2} · cpu {:.0}% · mem {:.0}% ({}/{}) · {} · {} · io r{}/s w{}/s · net ↑{}/s ↓{}/s",
            clock,
            self.load1,
            self.cpu_pct,
            mem_pct,
            human_bytes(self.mem_used),
            human_bytes(self.mem_total),
            swap,
            disk,
            human_bytes(self.disk_read_bps),
            human_bytes(self.disk_write_bps),
            human_bytes(self.net_tx_bps),
            human_bytes(self.net_rx_bps),
        )
    }

    fn mem_pct(&self) -> f64 {
        if self.mem_total > 0 {
            self.mem_used as f64 * 100.0 / self.mem_total as f64
        } else {
            0.0
        }
    }

    /// disk 세그먼트 텍스트 — 여유 용량 + (있으면) 소진 ETA 접미. status_line·status_segments 공용이라
    /// 둘이 항상 같은 토큰을 보여준다(divergence 방지). 사용률 %는 macOS APFS 부정확이라 free만 쓴다.
    fn disk_label(&self) -> String {
        if self.disk_total == 0 {
            return "disk n/a".to_string();
        }
        let mut s = format!("disk {} free", human_bytes(self.disk_avail));
        if let Some(eta) = &self.disk_eta {
            s.push_str(&format!(" · {}→crit", eta.bucket));
        }
        s
    }

    fn load_sev(&self) -> Severity {
        let ratio = self.load1 / self.cores.max(1) as f64;
        sev_high(ratio, LOAD_WARN_RATIO, LOAD_CRIT_RATIO)
    }
    fn cpu_sev(&self) -> Severity {
        sev_high(self.cpu_pct as f64, CPU_WARN_PCT as f64, CPU_CRIT_PCT as f64)
    }
    fn mem_sev(&self) -> Severity {
        sev_high(self.mem_pct(), MEM_WARN_PCT, MEM_CRIT_PCT)
    }
    fn swap_sev(&self) -> Severity {
        // swap 비활성이면 정상. macOS는 평시에도 swap을 쓰므로 임계가 보수적(50/90%).
        if self.swap_total == 0 {
            return Severity::Normal;
        }
        let pct = self.swap_used as f64 * 100.0 / self.swap_total as f64;
        sev_high(pct, SWAP_WARN_PCT, SWAP_CRIT_PCT)
    }
    fn disk_sev(&self) -> Severity {
        // 읽기 실패(n/a)면 정상 취급. 사용률 %는 APFS 부정확이라 free bytes 절대값으로 판정(낮을수록 위험).
        if self.disk_total == 0 {
            return Severity::Normal;
        }
        sev_low(self.disk_avail, DISK_WARN_FREE, DISK_CRIT_FREE)
    }

    /// status bar를 (라벨, 단계) 세그먼트로 분해한다(컬러링용, 순수). 텍스트는 `status_line`과 동일 포맷.
    /// io 세그먼트는 처리량이라 임계 없음(항상 Normal). chat_tui가 단계별 색을 입혀 렌더한다.
    pub fn status_segments(&self) -> Vec<(String, Severity)> {
        let swap = if self.swap_total > 0 {
            format!("swap {:.0}%", self.swap_used as f64 * 100.0 / self.swap_total as f64)
        } else {
            "swap off".to_string()
        };
        let disk = self.disk_label();
        let mut segs = vec![
            (format!("load {:.2}", self.load1), self.load_sev()),
            (format!("cpu {:.0}%", self.cpu_pct), self.cpu_sev()),
            (
                format!(
                    "mem {:.0}% ({}/{})",
                    self.mem_pct(),
                    human_bytes(self.mem_used),
                    human_bytes(self.mem_total)
                ),
                self.mem_sev(),
            ),
            (swap, self.swap_sev()),
            (disk, self.disk_sev()),
            (
                format!(
                    "io r{}/s w{}/s",
                    human_bytes(self.disk_read_bps),
                    human_bytes(self.disk_write_bps)
                ),
                Severity::Normal,
            ),
        ];
        // sparkline(C2)을 대상 세그먼트에 접미 — 그 세그먼트 단계 색을 상속한다(standalone 무색 없음).
        if let Some((idx, suffix)) = &self.trend_spark {
            if let Some(seg) = segs.get_mut(*idx) {
                seg.0.push_str(suffix);
            }
        }
        segs
    }

    /// 임계가 있는 지표(load/cpu/mem/swap/disk) 중 가장 높은 단계. 적응형 샘플링 주기 결정용 —
    /// 전부 Normal이면 느슨하게, 하나라도 Warn/Crit이면 촘촘하게 샘플한다. io는 임계가 없어 제외
    /// (status_segments와 동일 집합). `Severity`의 `Ord`로 최댓값을 그대로 고른다.
    pub(crate) fn overall_severity(&self) -> Severity {
        [
            self.load_sev(),
            self.cpu_sev(),
            self.mem_sev(),
            self.swap_sev(),
            self.disk_sev(),
        ]
        .into_iter()
        .max()
        .unwrap_or(Severity::Normal)
    }

    /// alert 대상 자원의 (이름, 심각도, 사람이 읽는 현재값) 고정 순서 목록 — `AlertTracker`가 전이
    /// 감지·메시지 작성에 쓴다. 임계가 있는 자원만(io 제외), 라벨은 status bar와 동일 토큰이라
    /// 사용자가 색·alert·텍스트를 1:1로 대응시킬 수 있다.
    fn alert_states(&self) -> [(&'static str, Severity, String); ALERT_RESOURCES] {
        [
            ("load", self.load_sev(), format!("load {:.2}", self.load1)),
            ("cpu", self.cpu_sev(), format!("cpu {:.0}%", self.cpu_pct)),
            ("mem", self.mem_sev(), {
                let mut s = format!(
                    "mem {:.0}% ({}/{})",
                    self.mem_pct(),
                    human_bytes(self.mem_used),
                    human_bytes(self.mem_total)
                );
                // 범인 프로세스(최대 RSS) — mem가 Warn 이상으로 채워졌을 때만 덧붙는다.
                if let Some((name, rss)) = &self.top_mem_proc {
                    s.push_str(&format!(" — top: {name} {}", human_bytes(*rss)));
                }
                s
            }),
            (
                "swap",
                self.swap_sev(),
                if self.swap_total > 0 {
                    format!("swap {:.0}%", self.swap_used as f64 * 100.0 / self.swap_total as f64)
                } else {
                    "swap off".to_string()
                },
            ),
            (
                "disk",
                self.disk_sev(),
                format!("disk {} free", human_bytes(self.disk_avail)),
            ),
        ]
    }
}

/// 한 건의 proactive alert — chat 로그에 ambient Note로 표시한다(LLM 컨텍스트엔 안 들어감).
pub(crate) struct Alert {
    /// 새로 진입한 단계(Warn 또는 Crit). bell·렌더 판단용.
    pub severity: Severity,
    /// 표시할 한 줄(예: `⚠ mem 97% (15.5G/16G) 위험(crit) — /diagnose 권장`).
    pub message: String,
}

/// 자원별 직전 심각도와 마지막 발화 이력을 들고, 새 sample마다 **악화 전이**만 골라 alert를 낸다
/// (edge-triggered). status bar와 동일한 임계(`*_sev`)를 재사용하므로 색과 alert가 어긋날 수 없다.
/// 상태는 세션 로컬(프로세스와 함께 소멸) — 영속/cross-session 없음, stateless-pull 경계 안.
pub(crate) struct AlertTracker {
    /// 자원별 직전 심각도(전이 감지 기준). 인덱스는 `SysMetrics::alert_states` 순서.
    prev: [Severity; ALERT_RESOURCES],
    /// 자원별 마지막 발화 시각(cooldown·decay 판정). None이면 최근 발화 없음.
    last_fired: [Option<Instant>; ALERT_RESOURCES],
    /// 자원별 마지막으로 알린 단계(escalation 판정 기준). cooldown 경과 시 Normal로 decay.
    last_fired_sev: [Severity; ALERT_RESOURCES],
}

impl AlertTracker {
    pub fn new() -> Self {
        Self {
            prev: [Severity::Normal; ALERT_RESOURCES],
            last_fired: [None; ALERT_RESOURCES],
            last_fired_sev: [Severity::Normal; ALERT_RESOURCES],
        }
    }

    /// 새 sample을 관찰해 발화할 alert를 반환한다.
    ///
    /// 규칙: (1) **악화 전이**(직전보다 심각도 상승)에서만 후보 — 같은 단계 유지·하강은 발화 안 함.
    /// (2) 직전 발화보다 높은 단계로의 **escalation**(예: Warn→Crit)은 cooldown을 무시하고 즉시 알린다
    /// (악화는 놓치면 안 됨). (3) 같은/낮은 단계 재진입만 자원별 **cooldown**(Crit `CRIT_COOLDOWN` < Warn
    /// `WARN_COOLDOWN`)으로 묶어 깜빡임 스팸을 막는다 — 이게 "idle ≤1건/10분" 예산의 실제 rate limiter다.
    /// (4) cooldown(긴 쪽)만큼 잠잠하면 발화 이력을 **decay**시켜, 한참 뒤 재발한 자원이 새 사건으로
    /// 다시 알림되게 한다. 타이머가 turn을 시작하거나 토큰을 주입하는 일은 없다(§C1).
    pub fn observe(&mut self, m: &SysMetrics, now: Instant) -> Vec<Alert> {
        let states = m.alert_states();
        let mut out = Vec::new();
        for (i, (_name, sev, value)) in states.iter().enumerate() {
            let sev = *sev;
            // 이력 decay: 오래 잠잠했으면(긴 cooldown 경과) 발화 이력을 초기화해 다음 악화를 새 사건으로.
            if self.last_fired[i].is_some_and(|t| now.duration_since(t) >= WARN_COOLDOWN) {
                self.last_fired[i] = None;
                self.last_fired_sev[i] = Severity::Normal;
            }
            if sev > self.prev[i] {
                let escalation = sev > self.last_fired_sev[i];
                let cooldown = if sev == Severity::Crit {
                    CRIT_COOLDOWN
                } else {
                    WARN_COOLDOWN
                };
                let cooled = self.last_fired[i].is_none_or(|t| now.duration_since(t) >= cooldown);
                if escalation || cooled {
                    let (level, hint) = if sev == Severity::Crit {
                        ("위험(crit)", " — /diagnose 권장")
                    } else {
                        ("경고(warn)", "")
                    };
                    out.push(Alert {
                        severity: sev,
                        message: format!("⚠ {value} {level}{hint}"),
                    });
                    self.last_fired[i] = Some(now);
                    self.last_fired_sev[i] = sev;
                }
            }
            self.prev[i] = sev;
        }
        out
    }
}

/// status bar 지표를 **전용 tokio task**에서 샘플해 watch 채널(latest-wins)로 publish한다.
///
/// 핵심: blocking refresh(`disks.refresh`의 statvfs 등)를 `spawn_blocking`에서 돌려 호출자 task(=chat
/// TUI 루프)를 막지 않는다. hung NFS/SMB mount에서 statfs가 멈춰도 UI는 얼지 않는다. 또한 sampler를
/// blocking 클로저로 넘겼다 돌려받는 구조라 **직전 sample이 끝나기 전엔 다음 sample을 시작하지 않는다**
/// (single-flight) — hung mount여도 blocking thread는 항상 ≤1개이고, sleep이 sample 완료 *후*에
/// 걸리므로 밀린 tick이 몰아치지도 않는다.
///
/// 주기는 직전 sample의 `overall_severity`에 따라 적응형(Normal 5s / Warn·Crit 2s)이다.
/// 초기값은 `None`(첫 sample 전, 호출자는 placeholder를 보여줄 수 있다), 이후 매 sample마다 `Some`.
/// 반환된 `Receiver`가 모두 drop되면(채팅 종료) task는 다음 publish에서 스스로 끝난다. 호출자는
/// 즉시 종료를 위해 반환된 `JoinHandle`을 `abort()`해도 된다.
pub(crate) fn spawn_sampler() -> (watch::Receiver<Option<SysMetrics>>, JoinHandle<()>) {
    let (tx, rx) = watch::channel(None);
    let handle = tokio::spawn(async move {
        let mut sampler = SysSampler::new();
        // trend ring + disk ETA 상태는 task 내부에 산다(§C4: ring은 sampler task가 소유). ETA 계산은
        // 순수 CPU(블로킹 없음)라 spawn_blocking 밖, async task에서 직접 돈다.
        let mut trend = TrendTracker::new();
        loop {
            // sampler를 blocking thread로 넘겼다 돌려받는다(i/o delta 계산을 위해 상태를 보존해야 함).
            // 이 await가 끝나기 전엔 절대 다음 sample을 시작하지 않으므로 blocking thread는 ≤1개다.
            let (returned, mut metrics) = match tokio::task::spawn_blocking(move || {
                let m = sampler.sample();
                (sampler, m)
            })
            .await
            {
                Ok(pair) => pair,
                // blocking 클로저 panic — 더는 못 돈다. task 종료.
                Err(_) => break,
            };
            sampler = returned;
            // 추세(C2): ring에 표본을 넣고 disk 소진 ETA와 metric sparkline을 함께 채운다.
            let (disk_eta, trend_spark) = trend.observe(Instant::now(), &metrics);
            metrics.disk_eta = disk_eta;
            metrics.trend_spark = trend_spark;
            let cadence = if metrics.overall_severity() == Severity::Normal {
                Duration::from_secs(CADENCE_NORMAL_SECS)
            } else {
                Duration::from_secs(CADENCE_ALERT_SECS)
            };
            // 수신자가 모두 사라졌으면(채팅 종료) 종료.
            if tx.send(Some(metrics)).is_err() {
                break;
            }
            tokio::time::sleep(cadence).await;
        }
    });
    (rx, handle)
}

/// status_segments 세그먼트 인덱스(load/cpu/mem/swap/disk/io 순) — sparkline을 붙일 위치 지정용.
const SEG_CPU: usize = 1;
const SEG_MEM: usize = 2;
const SEG_DISK: usize = 4;
/// sparkline에 쓰는 ring 꼬리 표본 수(가독성·폭 예산). 2s cadence면 ~24s, 5s면 ~60s 창.
const SPARK_TAIL: usize = 12;
/// disk sparkline·화살표 공통 변동 임계 — 창 동안 이만큼(64MiB) 미만 변하면 평평으로 본다. disk는
/// 창 min..max로 정규화하므로, 이 floor가 없으면 KB 단위 FS 잡음이 풀-진폭 막대로 증폭돼 화살표(→)와
/// 어긋난다(리뷰 지적). 막대·화살표가 같은 임계를 써 일치시킨다. cpu/mem는 0..100 고정이라 불필요.
const DISK_TREND_DELTA: f64 = 64.0 * 1024.0 * 1024.0;

/// trend ring 표본 — 시각 + sparkline/ETA가 쓰는 지표. 합의(§C4)의 "timestamp + disk_avail + cpu/mem"
/// 단일 ring을 구현한다(load/swap은 sparkline 대상이 아니라 제외).
#[derive(Clone, Copy)]
struct TrendSample {
    t: Instant,
    cpu_pct: f32,
    mem_pct: f64,
    disk_avail: u64,
}

/// 추세 상태 머신(sampler task 내부) — 단일 ring에서 disk 소진 ETA(C2a)와 metric sparkline(C2b)을
/// 함께 낸다. ring은 `ETA_WINDOW`만큼 보존하고, sparkline은 그 꼬리 `SPARK_TAIL`개를 쓴다. 상태는
/// 세션 로컬(stateless-pull). disk ETA 디바운스/리트랙션 규칙은 C2a와 동일.
pub(crate) struct TrendTracker {
    /// 추세 ring — `ETA_WINDOW`보다 오래된 표본은 버린다. armed가 아니어도 계속 쌓아, disk가 Warn으로
    /// 넘어오는 순간 이미 충분한 이력이 있게 한다.
    ring: Vec<TrendSample>,
    /// 현재 표시 중인 ETA(초). 값 갱신·grace 판단용.
    shown: Option<f64>,
    /// 등장 디바운스 — 연속 in-gate 후보 수가 2 이상이어야 표시(깜빡임 방지).
    appear: u8,
    /// 소멸 grace — 표시 중 연속 gate-miss가 2 이상이면 숨긴다(refill/Normal은 즉시).
    miss: u8,
    /// refill 감지용 직전 여유 바이트.
    last_avail: Option<u64>,
}

impl TrendTracker {
    pub fn new() -> Self {
        Self {
            ring: Vec::new(),
            shown: None,
            appear: 0,
            miss: 0,
            last_avail: None,
        }
    }

    /// 새 표본을 관찰해 (disk 소진 ETA, sparkline 접미)를 반환한다. sparkline은 `(세그먼트 인덱스,
    /// " {스파크}{화살표}")` — 호출자가 해당 status 세그먼트에 붙이면 그 단계 색을 상속한다.
    pub fn observe(&mut self, now: Instant, m: &SysMetrics) -> (Option<DiskEta>, Option<(usize, String)>) {
        let avail = m.disk_avail;
        // refill 감지(직전보다 256MiB 이상 증가) = 공간 회수 → 즉시 철회.
        let refilled = self
            .last_avail
            .is_some_and(|prev| avail > prev.saturating_add(ETA_REFILL_BYTES));
        self.last_avail = Some(avail);

        // ring push + window trim(시간 기준). armed 여부와 무관하게 쌓아 이력을 확보한다.
        self.ring.push(TrendSample {
            t: now,
            cpu_pct: m.cpu_pct,
            mem_pct: m.mem_pct(),
            disk_avail: avail,
        });
        while self
            .ring
            .first()
            .is_some_and(|s| now.duration_since(s.t) > ETA_WINDOW)
        {
            self.ring.remove(0);
        }

        let eta = self.disk_eta(avail, m.disk_sev(), refilled);
        let spark = self.sparkline(m);
        (eta, spark)
    }

    /// disk 소진 ETA — 게이트 + 등장/소멸 디바운스(C2a). arm은 `disk_sev∈{Warn,Crit}`; Normal·refill이면
    /// 즉시 철회(20GB transient는 non-full=Normal 디스크에만 착지하므로 ETA 경로에 못 들어온다).
    fn disk_eta(&mut self, avail: u64, disk_sev: Severity, refilled: bool) -> Option<DiskEta> {
        if disk_sev == Severity::Normal || refilled {
            self.shown = None;
            self.appear = 0;
            self.miss = 0;
            return None;
        }
        let t0 = self.ring.first().map(|s| s.t);
        let candidate = t0.and_then(|t0| {
            let points: Vec<(f64, f64)> = self
                .ring
                .iter()
                .map(|s| (s.t.duration_since(t0).as_secs_f64(), s.disk_avail as f64))
                .collect();
            disk_eta_candidate(&points, avail as f64)
        });
        match candidate {
            Some(secs) => {
                self.miss = 0;
                if self.shown.is_some() {
                    self.shown = Some(secs); // 값 갱신.
                } else {
                    self.appear = self.appear.saturating_add(1);
                    if self.appear >= 2 {
                        self.shown = Some(secs);
                    }
                }
            }
            None => {
                self.appear = 0;
                if self.shown.is_some() {
                    self.miss = self.miss.saturating_add(1);
                    if self.miss >= 2 {
                        self.shown = None;
                        self.miss = 0;
                    }
                }
            }
        }
        self.shown.map(|secs| DiskEta {
            bucket: bucket_label(secs),
        })
    }

    /// 가장 심각한 metric(cpu/mem/disk 중; 동률·전부 Normal이면 cpu)의 sparkline+화살표를 만든다.
    /// 반환 `(세그먼트 인덱스, " ▁▂▇↑")`. 표본이 3개 미만이면 None. cpu/mem는 0..100, disk는 창 min..max로
    /// 정규화한다(disk는 낮을수록 위험 — 하강이 바로 보인다). load/swap은 ring 미보유라 대상 아님.
    fn sparkline(&self, m: &SysMetrics) -> Option<(usize, String)> {
        if self.ring.len() < 3 {
            return None;
        }
        let tail = &self.ring[self.ring.len().saturating_sub(SPARK_TAIL)..];
        // cpu 기본, mem/disk가 더 심각하면 그쪽으로(동률은 cpu 유지).
        let mut chosen = (SEG_CPU, m.cpu_sev());
        for &(idx, sev) in &[(SEG_MEM, m.mem_sev()), (SEG_DISK, m.disk_sev())] {
            if sev > chosen.1 {
                chosen = (idx, sev);
            }
        }
        let vals: Vec<f64> = match chosen.0 {
            SEG_MEM => tail.iter().map(|s| s.mem_pct).collect(),
            SEG_DISK => tail.iter().map(|s| s.disk_avail as f64).collect(),
            _ => tail.iter().map(|s| s.cpu_pct as f64).collect(),
        };
        let (lo, hi, arrow_thr, flat_below) = match chosen.0 {
            SEG_DISK => {
                let lo = vals.iter().copied().fold(f64::INFINITY, f64::min);
                let hi = vals.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                // disk: 막대·화살표 모두 64MiB 미만 변동은 평평으로(미세 잡음 증폭 방지).
                (lo, hi, DISK_TREND_DELTA, DISK_TREND_DELTA)
            }
            _ => (0.0, 100.0, 3.0, 0.0), // cpu/mem %: 0..100 고정, 3%p 화살표 임계
        };
        let spark = sparkline(&vals, lo, hi, flat_below);
        let arrow = trend_arrow(*vals.first()?, *vals.last()?, arrow_thr);
        Some((chosen.0, format!(" {spark}{arrow}")))
    }
}

/// 순수 게이트 — (경과초, 여유바이트) 점열에서 CRIT(1GiB)까지 ETA(초) 후보를 낸다. 어떤 게이트든
/// 못 넘으면 None. cargo-build/docker-pull(V자)·sawtooth 같은 transient는 여기서 반드시 None이어야
/// 한다(replay-vector 테스트가 강제). 상태 없음 — 디바운스·리트랙션은 `TrendTracker`가 감싼다.
fn disk_eta_candidate(points: &[(f64, f64)], avail_now: f64) -> Option<f64> {
    if points.len() < ETA_MIN_SAMPLES {
        return None;
    }
    let span = points.last()?.0 - points.first()?.0;
    if span < ETA_MIN_SPAN.as_secs_f64() {
        return None;
    }
    // 단조성: 비증가 run(상승 지터 허용) 최장 길이 + 감소 step 비율.
    let total_steps = points.len() - 1;
    let mut longest_run = 0usize;
    let mut cur_run = 0usize;
    let mut declines = 0usize;
    for w in points.windows(2) {
        let delta = w[1].1 - w[0].1; // 바이트 변화(음수면 감소)
        if delta < 0.0 {
            declines += 1;
        }
        if delta <= ETA_UP_JITTER as f64 {
            cur_run += 1;
            longest_run = longest_run.max(cur_run);
        } else {
            cur_run = 0;
        }
    }
    if longest_run < ETA_MONOTONIC_RUN_MIN {
        return None;
    }
    if (declines as f64) < ETA_DECLINE_FRACTION_MIN * total_steps as f64 {
        return None;
    }
    // 최소제곱 선형 적합 avail ~ a + b·t.
    let (slope, r2) = linear_fit(points)?;
    if slope >= 0.0 {
        return None; // 감소(채워지는) 추세만.
    }
    if -slope < ETA_MIN_SLOPE_BPS {
        return None; // 너무 완만 — FS 지터에 묻힘.
    }
    if r2 < ETA_R2_MIN {
        return None; // 직선성 부족(V자/톱니).
    }
    // ETA = (현재 여유 - CRIT) / 감소율. 이미 CRIT 이하면 정적 색이 소유하므로 숫자 숨김.
    let crit = DISK_CRIT_FREE as f64;
    if avail_now <= crit {
        return None;
    }
    let secs = (avail_now - crit) / (-slope);
    if !(ETA_MIN_HORIZON_SECS..=ETA_MAX_HORIZON_SECS).contains(&secs) {
        return None;
    }
    Some(secs)
}

/// 최소제곱 선형 적합 → (기울기 bytes/s, R²). 점이 2개 미만이거나 x가 모두 같으면 None.
fn linear_fit(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    let n = points.len() as f64;
    if n < 2.0 {
        return None;
    }
    let (mut sx, mut sy, mut sxx, mut sxy, mut syy) = (0.0, 0.0, 0.0, 0.0, 0.0);
    for &(x, y) in points {
        sx += x;
        sy += y;
        sxx += x * x;
        sxy += x * y;
        syy += y * y;
    }
    let denom = n * sxx - sx * sx;
    if denom.abs() < f64::EPSILON {
        return None;
    }
    let slope = (n * sxy - sx * sy) / denom;
    let num = (n * sxy - sx * sy).powi(2);
    let den = denom * (n * syy - sy * sy);
    let r2 = if den.abs() < f64::EPSILON { 0.0 } else { num / den };
    Some((slope, r2))
}

/// 값 시퀀스를 unicode 블록(▁▂▃▄▅▆▇█)으로 그린다. lo..hi로 정규화하며, 범위가 `flat_below` 이하면
/// (= 의미 없는 미세 변동) 가운데(▄)로 평탄화해 잡음을 풀-진폭 막대로 증폭하지 않는다(화살표와 일치).
fn sparkline(values: &[f64], lo: f64, hi: f64, flat_below: f64) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let range = hi - lo;
    if range <= flat_below.max(f64::EPSILON) {
        return BARS[3].to_string().repeat(values.len());
    }
    values
        .iter()
        .map(|&v| {
            let frac = ((v - lo) / range).clamp(0.0, 1.0);
            let n = (frac * (BARS.len() - 1) as f64).round() as usize;
            BARS[n.min(BARS.len() - 1)]
        })
        .collect()
}

/// 최근 변화 방향 화살표 — 상승(↑)/하강(↓)/정체(→). 임계 이하 변화는 →로 둬 떨림을 막는다.
fn trend_arrow(first: f64, last: f64, threshold: f64) -> char {
    if last - first > threshold {
        '↑'
    } else if first - last > threshold {
        '↓'
    } else {
        '→'
    }
}

/// ETA(초)를 흔들리지 않는 버킷 라벨로 양자화 — tick마다 숫자가 떨리는 것을 막는다.
fn bucket_label(secs: f64) -> &'static str {
    if secs < 120.0 {
        "~2m"
    } else if secs < 300.0 {
        "~5m"
    } else if secs < 900.0 {
        "~15m"
    } else if secs < 3600.0 {
        "~1h"
    } else {
        "~2h"
    }
}

/// 값이 높을수록 위험한 지표(cpu/mem/swap/load)의 단계 판정.
fn sev_high(v: f64, warn: f64, crit: f64) -> Severity {
    if v >= crit {
        Severity::Crit
    } else if v >= warn {
        Severity::Warn
    } else {
        Severity::Normal
    }
}

/// 값이 낮을수록 위험한 지표(disk free)의 단계 판정.
fn sev_low(v: u64, warn: u64, crit: u64) -> Severity {
    if v <= crit {
        Severity::Crit
    } else if v <= warn {
        Severity::Warn
    } else {
        Severity::Normal
    }
}

/// bytes를 사람이 읽는 단위로(B/K/M/G/T). 순수 함수.
fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b}{}", UNITS[0])
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(1024), "1.0K");
        assert_eq!(human_bytes(1536), "1.5K");
        assert_eq!(human_bytes(1024 * 1024), "1.0M");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0G");
    }

    #[test]
    fn status_line_format() {
        let m = SysMetrics {
            load1: 1.23,
            cpu_pct: 45.6,
            cores: 8,
            mem_used: 8 * 1024 * 1024 * 1024,
            mem_total: 16 * 1024 * 1024 * 1024,
            swap_used: 1024 * 1024 * 1024,
            swap_total: 4 * 1024 * 1024 * 1024,
            disk_avail: 70 * 1024 * 1024 * 1024,
            disk_total: 280 * 1024 * 1024 * 1024,
            disk_read_bps: 2 * 1024 * 1024,
            disk_write_bps: 512 * 1024,
            net_rx_bps: 3 * 1024 * 1024,
            net_tx_bps: 256 * 1024,
            ..Default::default()
        };
        let line = m.status_line();
        assert!(line.contains("load 1.23"), "{line}");
        assert!(line.contains("cpu 46%"), "{line}");
        assert!(line.contains("mem 50%"), "{line}");
        assert!(line.contains("swap 25%"), "{line}");
        // disk는 신뢰 가능한 free만(사용률 %는 macOS APFS에서 부정확).
        assert!(line.contains("disk 70.0G free"), "{line}");
        assert!(line.contains("io r2.0M/s w512.0K/s"), "{line}");
        assert!(line.contains("net ↑256.0K/s ↓3.0M/s"), "{line}");
        // clock: HH:MM:SS 형식 검증(값은 실행 시점 의존이므로 패턴만).
        assert!(line.contains(':'), "{line}");
    }

    #[test]
    fn status_line_handles_no_swap_and_no_disk() {
        let m = SysMetrics {
            load1: 0.0,
            cpu_pct: 0.0,
            cores: 4,
            mem_used: 1024,
            mem_total: 2048,
            swap_used: 0,
            swap_total: 0,
            disk_avail: 0,
            disk_total: 0,
            disk_read_bps: 0,
            disk_write_bps: 0,
            net_rx_bps: 0,
            net_tx_bps: 0,
            ..Default::default()
        };
        let line = m.status_line();
        assert!(line.contains("swap off"), "{line}");
        assert!(line.contains("disk n/a"), "{line}");
    }

    fn metric(load1: f64, cpu: f32, cores: usize, mem_used: u64, mem_total: u64,
              swap_used: u64, swap_total: u64, disk_avail: u64, disk_total: u64) -> SysMetrics {
        SysMetrics {
            load1, cpu_pct: cpu, cores, mem_used, mem_total, swap_used, swap_total,
            disk_avail, disk_total, ..Default::default()
        }
    }

    #[test]
    fn severity_thresholds_normal_warn_crit() {
        let g = 1024 * 1024 * 1024;
        // 정상: 모든 지표 임계 미달 → 전부 Normal.
        let ok = metric(1.0, 10.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        for s in [ok.load_sev(), ok.cpu_sev(), ok.mem_sev(), ok.swap_sev(), ok.disk_sev()] {
            assert_eq!(s, Severity::Normal);
        }
        // cpu warn(85~95), mem crit(>=97).
        let m = metric(1.0, 88.0, 8, 159 * g / 10, 16 * g, 0, 0, 50 * g, 200 * g); // mem 99%
        assert_eq!(m.cpu_sev(), Severity::Warn);
        assert_eq!(m.mem_sev(), Severity::Crit);
        // load: ratio>=2.0 → Crit (16 load / 8 cores = 2.0).
        assert_eq!(metric(16.0, 0.0, 8, 0, 1, 0, 0, 50 * g, 200 * g).load_sev(), Severity::Crit);
        assert_eq!(metric(8.0, 0.0, 8, 0, 1, 0, 0, 50 * g, 200 * g).load_sev(), Severity::Warn);
        // disk: free bytes 절대 임계(<=1G crit, <=5G warn). %가 아니라 free라 macOS APFS 무관.
        assert_eq!(metric(0.0, 0.0, 8, 0, 1, 0, 0, 512 * 1024 * 1024, 999 * g).disk_sev(), Severity::Crit);
        assert_eq!(metric(0.0, 0.0, 8, 0, 1, 0, 0, 3 * g, 999 * g).disk_sev(), Severity::Warn);
        assert_eq!(metric(0.0, 0.0, 8, 0, 1, 0, 0, 50 * g, 999 * g).disk_sev(), Severity::Normal);
        // disk/swap n/a(total 0)는 Normal(오탐 방지).
        assert_eq!(metric(0.0, 0.0, 8, 0, 1, 0, 0, 0, 0).disk_sev(), Severity::Normal);
        assert_eq!(metric(0.0, 0.0, 8, 0, 1, 0, 0, 50 * g, 200 * g).swap_sev(), Severity::Normal);
    }

    #[test]
    fn status_segments_labels_and_severity_align() {
        let g = 1024 * 1024 * 1024;
        let m = metric(1.0, 99.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        let segs = m.status_segments();
        // 세그먼트 6개(load/cpu/mem/swap/disk/io), 텍스트는 status_line과 동일 토큰.
        assert_eq!(segs.len(), 6);
        assert!(segs[1].0.starts_with("cpu "));
        assert_eq!(segs[1].1, Severity::Crit); // cpu 99% >= 95
        assert_eq!(segs[5].1, Severity::Normal); // io는 임계 없음
    }

    #[test]
    fn sampler_runs_without_panic() {
        // 실제 시스템 호출 — 패닉 없이 수치를 반환하는지만 확인(값 범위는 환경 의존).
        let mut s = SysSampler::new();
        let m = s.sample();
        assert!(m.mem_total > 0, "mem_total should be positive on a real host");
    }

    #[test]
    fn overall_severity_picks_highest() {
        let g = 1024 * 1024 * 1024;
        // 전부 정상 → Normal.
        assert_eq!(
            metric(1.0, 10.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g).overall_severity(),
            Severity::Normal
        );
        // mem crit(99%) 하나라도 있으면 전체 Crit(최댓값).
        assert_eq!(
            metric(1.0, 10.0, 8, 159 * g / 10, 16 * g, 0, 0, 50 * g, 200 * g).overall_severity(),
            Severity::Crit
        );
        // 최고가 cpu warn(88%)뿐이면 Warn.
        assert_eq!(
            metric(1.0, 88.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g).overall_severity(),
            Severity::Warn
        );
    }

    #[test]
    fn alert_tracker_fires_on_worsening_edges_only() {
        let g = 1024 * 1024 * 1024;
        let t0 = Instant::now();
        let mut tr = AlertTracker::new();
        // 정상 → 발화 없음.
        let ok = metric(1.0, 10.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        assert!(tr.observe(&ok, t0).is_empty());
        // Normal→cpu warn(88%): 1건 발화(warn).
        let cpu_warn = metric(1.0, 88.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        let a = tr.observe(&cpu_warn, t0);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Warn);
        assert!(a[0].message.contains("cpu 88%"), "{}", a[0].message);
        // 같은 warn 유지 → 발화 없음(전이 아님).
        assert!(tr.observe(&cpu_warn, t0).is_empty());
        // cpu warn→crit(96%)은 악화 전이라 cooldown 무관하게 즉시 발화(crit).
        let cpu_crit = metric(1.0, 96.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        let a = tr.observe(&cpu_crit, t0);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Crit);
        assert!(a[0].message.contains("/diagnose"), "crit should hint /diagnose: {}", a[0].message);
    }

    // (경과초, 여유 GiB-단위 바이트) 점열 빌더 — replay-vector 가독성용.
    fn pts(samples: &[(f64, f64)]) -> Vec<(f64, f64)> {
        let g = 1024.0 * 1024.0 * 1024.0;
        samples.iter().map(|&(t, gib)| (t, gib * g)).collect()
    }

    #[test]
    fn disk_eta_fires_on_clean_linear_decline() {
        let g = 1024.0 * 1024.0 * 1024.0;
        // 6GiB→4GiB로 300s에 걸쳐 일정하게 감소(20s 간격 16표본). rate≈410MiB/min, R²≈1.
        let samples: Vec<(f64, f64)> = (0..=15)
            .map(|i| {
                let t = i as f64 * 20.0;
                (t, 6.0 - 2.0 * t / 300.0)
            })
            .collect();
        let p = pts(&samples);
        let avail_now = p.last().unwrap().1;
        let secs = disk_eta_candidate(&p, avail_now).expect("clean linear decline should yield ETA");
        // (avail_now-1GiB)/rate. avail_now≈4GiB → (3GiB)/(2GiB/300s)=450s 근방.
        assert!(secs > 60.0 && secs < 7200.0, "secs={secs}");
        let _ = g;
    }

    #[test]
    fn disk_eta_suppresses_transient_v_shape() {
        // cargo build/docker pull: 6→2GiB로 썼다(150s) 다시 6GiB로 회수(150s). V자 → 단조 run·R² 붕괴.
        let mut samples = Vec::new();
        for i in 0..=7 {
            let t = i as f64 * 20.0;
            samples.push((t, 6.0 - 4.0 * t / 140.0)); // 하강
        }
        for i in 1..=8 {
            let t = 140.0 + i as f64 * 20.0;
            samples.push((t, 2.0 + 4.0 * (i as f64 * 20.0) / 160.0)); // 회수
        }
        let p = pts(&samples);
        let avail_now = p.last().unwrap().1;
        assert!(
            disk_eta_candidate(&p, avail_now).is_none(),
            "V-shape transient must not yield an ETA"
        );
    }

    #[test]
    fn disk_eta_suppresses_sawtooth_and_flat_and_short() {
        let g = 1024.0 * 1024.0 * 1024.0;
        // 톱니: 4GiB 중심 ±500MiB 진동 → 감소비/R² 미달.
        let saw: Vec<(f64, f64)> = (0..=15)
            .map(|i| {
                let t = i as f64 * 20.0;
                let osc = if i % 2 == 0 { 0.5 } else { -0.5 };
                (t, (4.0 + osc) * g)
            })
            .collect();
        assert!(disk_eta_candidate(&saw, saw.last().unwrap().1).is_none(), "sawtooth");
        // 평평: 일정 4GiB → slope≈0.
        let flat: Vec<(f64, f64)> = (0..=15).map(|i| (i as f64 * 20.0, 4.0 * g)).collect();
        assert!(disk_eta_candidate(&flat, flat.last().unwrap().1).is_none(), "flat");
        // 짧은 윈도: span<300s & n<10 → None(깨끗한 하강이어도).
        let short: Vec<(f64, f64)> = (0..5).map(|i| (i as f64 * 20.0, (5.0 - 0.2 * i as f64) * g)).collect();
        assert!(disk_eta_candidate(&short, short.last().unwrap().1).is_none(), "short window");
    }

    #[test]
    fn trend_tracker_disk_eta_debounce_arm_and_retract() {
        let t0 = Instant::now();
        let g = 1024 * 1024 * 1024;
        let mut tr = TrendTracker::new();
        // armed(disk_sev Warn, 즉 ≤5GiB) 상태로 깨끗한 하강을 한 표본씩 흘려보낸다.
        // 5GiB에서 시작해 300s 동안 4GiB까지(1GiB/300s≈3.5MiB/s≈210MiB/min≥5). 20s 간격.
        let mut shown_at = None;
        for i in 0..=20 {
            let t = t0 + Duration::from_secs(i * 20);
            let avail = ((5.0 - 1.0 * (i as f64 * 20.0) / 400.0) * g as f64) as u64; // ≤5GiB → Warn arm
            let m = metric(1.0, 10.0, 8, 4 * g, 16 * g, 0, 0, avail, 200 * g);
            let (eta, _spark) = tr.observe(t, &m);
            if eta.is_some() && shown_at.is_none() {
                shown_at = Some(i);
            }
        }
        assert!(shown_at.is_some(), "ETA should appear once enough clean-decline history accrues");
        // 디바운스: 첫 in-gate 표본 즉시가 아니라 충분한 span(≥300s=15표본) 이후 + 2연속이라야 등장.
        assert!(shown_at.unwrap() >= 15, "appeared too early: {:?}", shown_at);
        // refill(>256MiB 급증) → 즉시 철회(여전히 Warn=5GiB이지만 회수 신호).
        let later = t0 + Duration::from_secs(500);
        let m_refill = metric(1.0, 10.0, 8, 4 * g, 16 * g, 0, 0, 5 * g, 200 * g);
        assert!(tr.observe(later, &m_refill).0.is_none(), "refill must instantly retract the ETA");
        // Normal 복귀 → 계속 None.
        let m_norm = metric(1.0, 10.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        assert!(tr.observe(later + Duration::from_secs(20), &m_norm).0.is_none());
    }

    #[test]
    fn sparkline_maps_values_to_bars() {
        // 단조 증가 → 첫 칸은 최저(▁), 마지막은 최고(█).
        let s = sparkline(&[0.0, 25.0, 50.0, 75.0, 100.0], 0.0, 100.0, 0.0);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.first(), Some(&'▁'));
        assert_eq!(chars.last(), Some(&'█'));
        assert_eq!(chars.len(), 5);
        // 평평(범위 0) → 전부 가운데(▄).
        assert_eq!(sparkline(&[42.0, 42.0, 42.0], 42.0, 42.0, 0.0), "▄▄▄");
        // 미세 변동이 flat_below(여기선 64MiB) 이하면 평탄화 — 잡음 증폭 방지(리뷰 지적).
        let mib = 1024.0 * 1024.0;
        let lo = 4.0 * 1024.0 * mib;
        let hi = lo + 1.0 * mib; // 1MiB 변동 < 64MiB
        assert_eq!(sparkline(&[lo, hi, lo], lo, hi, DISK_TREND_DELTA), "▄▄▄");
    }

    #[test]
    fn trend_arrow_thresholds() {
        assert_eq!(trend_arrow(10.0, 20.0, 3.0), '↑');
        assert_eq!(trend_arrow(20.0, 10.0, 3.0), '↓');
        assert_eq!(trend_arrow(10.0, 11.0, 3.0), '→'); // 임계 이하 변화는 정체.
    }

    #[test]
    fn trend_tracker_sparkline_picks_metric_by_severity() {
        let t0 = Instant::now();
        let g = 1024 * 1024 * 1024;
        // 전부 Normal → cpu 기본 선택.
        let mut tr = TrendTracker::new();
        let mut spark = None;
        for i in 0..5u64 {
            let m = metric(1.0, 50.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
            spark = tr.observe(t0 + Duration::from_secs(i * 2), &m).1;
        }
        let (idx, s) = spark.expect("sparkline after >=3 samples");
        assert_eq!(idx, SEG_CPU, "all-Normal should spark cpu by default");
        assert!(s.contains('→') || s.contains('↑') || s.contains('↓'), "spark has an arrow: {s}");
        // mem crit(99%) → mem 세그먼트 선택.
        let mut tr = TrendTracker::new();
        let mut spark = None;
        for i in 0..5u64 {
            let m = metric(1.0, 10.0, 8, 159 * g / 10, 16 * g, 0, 0, 50 * g, 200 * g); // mem 99%
            spark = tr.observe(t0 + Duration::from_secs(i * 2), &m).1;
        }
        assert_eq!(spark.expect("spark").0, SEG_MEM, "mem crit should spark the mem segment");
    }

    #[test]
    fn alert_message_includes_mem_culprit_when_present() {
        let g = 1024 * 1024 * 1024;
        let t0 = Instant::now();
        let mut tr = AlertTracker::new();
        // mem crit(99%) + 범인 프로세스 채워짐 → alert 메시지에 "top: node 12.0G" 포함.
        let mut m = metric(1.0, 10.0, 8, 159 * g / 10, 16 * g, 0, 0, 50 * g, 200 * g);
        m.top_mem_proc = Some(("node".to_string(), 12 * g));
        let a = tr.observe(&m, t0);
        assert_eq!(a.len(), 1);
        assert!(a[0].message.contains("top: node 12.0G"), "{}", a[0].message);
        assert!(a[0].message.contains("위험(crit)"), "{}", a[0].message);
    }

    #[test]
    fn alert_tracker_cooldown_suppresses_reentry() {
        let g = 1024 * 1024 * 1024;
        let t0 = Instant::now();
        let mut tr = AlertTracker::new();
        let ok = metric(1.0, 10.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        let cpu_warn = metric(1.0, 88.0, 8, 4 * g, 16 * g, 0, 0, 50 * g, 200 * g);
        // 첫 Normal→Warn 발화.
        assert_eq!(tr.observe(&cpu_warn, t0).len(), 1);
        // Normal로 내려갔다(전이 하강, 발화 없음) 다시 Warn으로 — cooldown(5분) 안이면 억제.
        assert!(tr.observe(&ok, t0).is_empty());
        let within = t0 + Duration::from_secs(60);
        assert!(
            tr.observe(&cpu_warn, within).is_empty(),
            "warn re-entry within cooldown must be suppressed (rate budget)"
        );
        // cooldown 경과 후 다시 Warn이면 발화.
        let after = t0 + WARN_COOLDOWN + Duration::from_secs(1);
        assert!(tr.observe(&ok, after).is_empty()); // Normal 경유(전이 하강)
        assert_eq!(
            tr.observe(&cpu_warn, after + Duration::from_secs(1)).len(),
            1,
            "warn should fire again once cooldown elapsed"
        );
    }

    #[tokio::test]
    async fn spawn_sampler_publishes_metrics_off_thread() {
        // 전용 task가 watch 채널로 첫 지표를 publish하는지 확인. blocking refresh가 spawn_blocking에서
        // 돌므로 이 테스트(=호출자) task는 막히지 않는다. 타임아웃으로 무한 대기 방지.
        let (mut rx, handle) = spawn_sampler();
        // 초기값은 None(첫 sample 전).
        assert!(rx.borrow().is_none(), "initial watch value should be None before first sample");
        let got = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if rx.changed().await.is_err() {
                    return None;
                }
                if let Some(m) = rx.borrow_and_update().clone() {
                    return Some(m);
                }
            }
        })
        .await
        .expect("sampler should publish within 10s");
        let m = got.expect("first publish should carry Some(metrics)");
        assert!(m.mem_total > 0, "published metrics should have a real mem_total");
        // task 정리(수신자 drop만으로도 다음 cycle에 종료하나, 즉시 abort).
        handle.abort();
    }
}
