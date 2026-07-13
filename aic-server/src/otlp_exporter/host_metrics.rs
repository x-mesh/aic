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

/// 한 번 수집한 host metrics 스냅샷(resource + gauge point 목록).
pub struct HostSample {
    pub resource: ResourceAttrs,
    pub points: Vec<MetricPoint>,
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
        }
    }

    /// 현재 host metrics를 수집한다. disk/net i/o는 직전 sample 이후 delta를 경과시간으로 나눠 bytes/s.
    pub fn sample(&mut self) -> HostSample {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        // 프로세스 수 + top RSS 계산에 memory()가 필요해 `.with_memory()`를 켠다. 이 머신(프로세스
        // ~990개) 실측으로는 nothing() 8.1~15.4ms vs with_memory() 14.1~20.8ms — 차이가 프로세스당
        // syscall 1회(`proc_pidinfo(PROC_PIDTASKINFO)`) 추가분이고, 재측정하면 순서가 뒤바뀔 만큼
        // 회차 간 노이즈에 묻힌다. 프로세스 열거(`proc_listpids`) 자체가 이미 지배적 비용이라
        // 60초 주기에서 유의미한 부담이 아니다.
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_memory(),
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
        let proc_count = self.sys.processes().len();
        // 최대 RSS 프로세스의 값만 낸다. 이름/PID는 attr로 넣지 않는다 — 이 머신 고유 프로세스명이
        // 623종이라 cardinality 폭탄이고, 수신측(rca-server) 읽기 경로가 전부 `WHERE host=? AND
        // metric=?` + `avg(value)`라 attrs 필터/GROUP BY가 없어 차원을 넣으면 평균으로 뭉개진다.
        // "범인이 누구인가"는 changes exporter의 rss_spike가 이미 다룬다.
        // 가시 범위(비루트 macOS는 same-uid만)는 모듈 doc 참고.
        let top_rss = top_process_rss(self.sys.processes().values().map(|p| p.memory()));
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

        HostSample {
            resource: ResourceAttrs {
                host_name: self.host_name.clone(),
                host_id: self.host_id.clone(),
                os_type: self.os_type.clone(),
                arch: self.arch.clone(),
                os_desc: self.os_desc.clone(),
            },
            points,
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
        // ntp_offset_ms(Linux + 커널 sync 상태일 때만)가 각각 선택적으로 붙는다 — 26~28 모두 유효.
        assert!(
            (26..=28).contains(&sample.points.len()),
            "host metrics 점수는 26~28이어야 함, got {}",
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

    #[test]
    fn ratio_handles_zero_total() {
        assert_eq!(ratio(0, 0), 0.0);
        assert_eq!(ratio(5, 10), 0.5);
        // used > total(측정 순간 불일치)이어도 1.0으로 clamp.
        assert_eq!(ratio(20, 10), 1.0);
    }
}
