//! `aic chat` status bar용 시스템 지표 샘플러 — sysinfo crate로 in-process 수집.
//!
//! load average와 memory는 순간값이지만 **disk i/o는 누적 카운터의 delta**다. sysinfo의
//! `DiskUsage::read_bytes`/`written_bytes`가 마지막 refresh 이후 delta를 자동 계산하므로,
//! `Disks` 인스턴스를 세션 내내 **재사용**해야 정확하다(매번 새로 만들면 0). 따라서 샘플러는
//! 상태를 들고 다닌다. SRE 진단 probe catalog(`agent::probes`)와는 별개 경로다(그쪽은 one-shot 명령).

use std::time::Instant;
use sysinfo::{Disks, System};

/// load/cpu/memory/disk-i/o를 들고 있는 stateful 샘플러. status bar 전용.
pub(crate) struct SysSampler {
    sys: System,
    disks: Disks,
    last: Instant,
}

/// 한 번 sample한 지표 스냅샷.
pub(crate) struct SysMetrics {
    pub load1: f64,
    pub cpu_pct: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
}

impl SysSampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            last: Instant::now(),
        }
    }

    /// 현재 지표를 샘플한다. disk i/o는 직전 sample 이후 delta를 경과시간으로 나눠 bytes/s로 환산.
    pub fn sample(&mut self) -> SysMetrics {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(false);
        // 0으로 나누기 방지(연속 호출 간 간격이 아주 짧을 수 있음).
        let elapsed = self.last.elapsed().as_secs_f64().max(0.001);
        let (read, write) = self.disks.list().iter().fold((0u64, 0u64), |acc, d| {
            let u = d.usage();
            (acc.0 + u.read_bytes, acc.1 + u.written_bytes)
        });
        self.last = Instant::now();
        SysMetrics {
            load1: System::load_average().one,
            cpu_pct: self.sys.global_cpu_usage(),
            mem_used: self.sys.used_memory(),
            mem_total: self.sys.total_memory(),
            disk_read_bps: (read as f64 / elapsed) as u64,
            disk_write_bps: (write as f64 / elapsed) as u64,
        }
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
        format!(
            "load {:.2} · cpu {:.0}% · mem {:.0}% ({}/{}) · io r{}/s w{}/s",
            self.load1,
            self.cpu_pct,
            mem_pct,
            human_bytes(self.mem_used),
            human_bytes(self.mem_total),
            human_bytes(self.disk_read_bps),
            human_bytes(self.disk_write_bps),
        )
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
            mem_used: 8 * 1024 * 1024 * 1024,
            mem_total: 16 * 1024 * 1024 * 1024,
            disk_read_bps: 2 * 1024 * 1024,
            disk_write_bps: 512 * 1024,
        };
        let line = m.status_line();
        assert!(line.contains("load 1.23"), "{line}");
        assert!(line.contains("cpu 46%"), "{line}");
        assert!(line.contains("mem 50%"), "{line}");
        assert!(line.contains("io r2.0M/s w512.0K/s"), "{line}");
    }

    #[test]
    fn sampler_runs_without_panic() {
        // 실제 시스템 호출 — 패닉 없이 수치를 반환하는지만 확인(값 범위는 환경 의존).
        let mut s = SysSampler::new();
        let m = s.sample();
        assert!(m.mem_total > 0, "mem_total should be positive on a real host");
    }
}
