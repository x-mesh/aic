//! aicd OTLP exporter용 host metrics 수집기 (SRE t6).
//!
//! aic-client의 `agent::sys_sampler`는 status bar 전용 `pub(crate)`라 재사용할 수 없고, aic-client에
//! 의존성을 추가하지 않기로 했다(설계 지침). 그래서 여기에 exporter 전용 **최소** 샘플러를 새로 둔다.
//! sys_sampler와 동일한 원칙을 따른다: disk/net i/o는 누적 카운터의 delta라 `Disks`/`Networks`
//! 인스턴스를 세션 내내 **재사용**해야 정확하다(매번 새로 만들면 0). 따라서 샘플러는 상태를 든다.
//!
//! 이번 범위는 host metrics(cpu/load/mem/swap/disk/net)뿐이다. events tap/connections(t7),
//! cumulative Sum 온도계·spool/backoff(t8)는 후속. 그래서 모든 지표를 순간값(Gauge)으로 낸다 —
//! 우리가 계산하는 i/o rate도 이미 "직전 sample 이후 bytes/s"라 순간값 의미가 맞다.

use std::time::Instant;

use sysinfo::{Disks, Networks, System};

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
        self.disks.refresh(false);
        self.networks.refresh(false);
        // 0으로 나누기 방지(연속 호출 간 간격이 아주 짧을 수 있음).
        let elapsed = self.last.elapsed().as_secs_f64().max(0.001);

        let (read, write) = self.disks.list().iter().fold((0u64, 0u64), |acc, d| {
            let u = d.usage();
            (acc.0 + u.read_bytes, acc.1 + u.written_bytes)
        });
        let (rx, tx) = self.networks.iter().fold((0u64, 0u64), |acc, (_, data)| {
            (acc.0 + data.received(), acc.1 + data.transmitted())
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
        let mem_used = self.sys.used_memory();
        let mem_total = self.sys.total_memory();
        let swap_used = self.sys.used_swap();
        let swap_total = self.sys.total_swap();
        let load1 = System::load_average().one;

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
                value: MetricValue::Double(load1),
            },
            MetricPoint {
                name: "system.memory.usage",
                unit: "By",
                value: MetricValue::Int(mem_used as i64),
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
        // host metrics 13종(cpu 2 + mem 3 + swap 2 + fs 2 + disk io 2 + net io 2) + t7 ntp_offset_ms는
        // 측정 가능할 때만 14번째로 붙는다(Linux + 커널이 sync 상태 보고할 때만 — 이 머신/CI 환경에
        // 따라 13 또는 14 둘 다 유효하다. 값 자체를 강제하지 않는다).
        assert!(
            sample.points.len() == 13 || sample.points.len() == 14,
            "host metrics 점수는 13(ntp 미측정) 또는 14(ntp 측정됨)여야 함, got {}",
            sample.points.len()
        );
        if sample.points.len() == 14 {
            assert_eq!(sample.points[13].name, "aic.agent.ntp_offset_ms");
        }
        // utilization은 항상 0..1 범위.
        for p in &sample.points {
            if p.name == "system.cpu.utilization" || p.name == "system.memory.utilization" {
                if let MetricValue::Double(v) = p.value {
                    assert!((0.0..=1.0).contains(&v), "{} out of range: {v}", p.name);
                }
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
