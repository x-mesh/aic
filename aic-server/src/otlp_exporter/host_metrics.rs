//! aicd OTLP exporter용 host metrics 수집기 (SRE t6).
//!
//! aic-client의 `agent::sys_sampler`는 status bar 전용 `pub(crate)`라 재사용할 수 없고, aic-client에
//! 의존성을 추가하지 않기로 했다(설계 지침). 그래서 여기에 exporter 전용 **최소** 샘플러를 새로 둔다.
//! sys_sampler와 동일한 원칙을 따른다: disk/net i/o는 누적 카운터의 delta라 `Disks`/`Networks`
//! 인스턴스를 세션 내내 **재사용**해야 정확하다(매번 새로 만들면 0). 따라서 샘플러는 상태를 든다.
//!
//! 수집 항목은 cpu(사용률·load 1/5/15m·코어 수), memory(usage/limit/available/utilization),
//! swap(usage/limit/utilization), filesystem(usage/available/limit/utilization), disk i/o,
//! network(bytes·packets·errors), process 수, uptime이다. 모든 지표를 순간값(Gauge)으로 낸다 —
//! 우리가 계산하는 i/o·packets·errors rate도 이미 "직전 sample 이후 초당"이라 순간값 의미가 맞다.

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
}

impl HostSampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        let host_name = System::host_name().unwrap_or_else(|| "unknown".to_string());
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            last: Instant::now(),
            host_id: host_id(&host_name),
            os_type: std::env::consts::OS.to_string(),
            host_name,
        }
    }

    /// 현재 host metrics를 수집한다. disk/net i/o는 직전 sample 이후 delta를 경과시간으로 나눠 bytes/s.
    pub fn sample(&mut self) -> HostSample {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        // 프로세스 수만 필요하므로 `ProcessRefreshKind::nothing()`으로 목록만 갱신한다 —
        // cpu/메모리까지 프로세스별로 채우면 60초 주기라도 불필요하게 비싸다.
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
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
            (acc.0 + d.packets_received(), acc.1 + d.packets_transmitted())
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
            },
            points,
        }
    }
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
        // process 1 + uptime 1). ntp_offset_ms는 측정 가능할 때만 27번째로 붙는다(Linux + 커널이
        // sync 상태 보고할 때만 — 26/27 둘 다 유효하다).
        assert!(
            sample.points.len() == 26 || sample.points.len() == 27,
            "host metrics 점수는 26(ntp 미측정) 또는 27(ntp 측정됨)여야 함, got {}",
            sample.points.len()
        );
        if sample.points.len() == 27 {
            assert_eq!(sample.points[26].name, "aic.agent.ntp_offset_ms");
        }
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
    fn ratio_handles_zero_total() {
        assert_eq!(ratio(0, 0), 0.0);
        assert_eq!(ratio(5, 10), 0.5);
        // used > total(측정 순간 불일치)이어도 1.0으로 clamp.
        assert_eq!(ratio(20, 10), 1.0);
    }
}
