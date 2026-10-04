use std::collections::{HashMap, HashSet};
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoStatus {
    Measured,
    Baseline,
    PermissionDenied,
    Unavailable,
    Unsupported,
    Partial,
}

impl IoStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Baseline => "baseline",
            Self::PermissionDenied => "permission_denied",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::Partial => "partial",
        }
    }
}

#[derive(Default)]
pub struct ProcessIoTracker {
    previous: HashMap<(i64, u64), (u64, u64)>,
    seen: HashSet<(i64, u64)>,
    denied: usize,
    diagnostic_sent: bool,
}

impl ProcessIoTracker {
    pub fn begin(&mut self) {
        self.seen.clear();
        self.denied = 0;
    }

    pub fn finish(&mut self) {
        self.previous.retain(|key, _| self.seen.contains(key));
    }

    pub fn take_permission_diagnostic(&mut self) -> Option<usize> {
        if self.denied == 0 || self.diagnostic_sent {
            return None;
        }
        self.diagnostic_sent = true;
        Some(self.denied)
    }

    pub fn sample(&mut self, pid: i64, start_time: u64) -> (u64, u64, IoStatus) {
        #[cfg(target_os = "linux")]
        let counters = std::fs::read_to_string(format!("/proc/{pid}/io"))
            .and_then(|text| parse_counters(&text));
        #[cfg(not(target_os = "linux"))]
        let counters = Err(io::Error::from(io::ErrorKind::Unsupported));
        self.observe((pid, start_time), counters)
    }

    fn observe(
        &mut self,
        key: (i64, u64),
        counters: io::Result<(u64, u64)>,
    ) -> (u64, u64, IoStatus) {
        self.seen.insert(key);
        match counters {
            Ok(now) => {
                let before = self.previous.insert(key, now);
                match before {
                    Some(before) if now.0 >= before.0 && now.1 >= before.1 => {
                        (now.0 - before.0, now.1 - before.1, IoStatus::Measured)
                    }
                    _ => (0, 0, IoStatus::Baseline),
                }
            }
            Err(error) => {
                // A failed poll breaks the interval, so recovery must establish a new baseline.
                self.previous.remove(&key);
                let status = match error.kind() {
                    io::ErrorKind::PermissionDenied => {
                        self.denied += 1;
                        IoStatus::PermissionDenied
                    }
                    io::ErrorKind::Unsupported => IoStatus::Unsupported,
                    _ => IoStatus::Unavailable,
                };
                (0, 0, status)
            }
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_counters(text: &str) -> io::Result<(u64, u64)> {
    let value = |name| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse().ok())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
    };
    Ok((value("read_bytes:")?, value("write_bytes:")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_live_linux_proc_io() {
        let mut tracker = ProcessIoTracker::default();
        let pid = i64::from(std::process::id());
        assert_eq!(tracker.sample(pid, 1).2, IoStatus::Baseline);
        assert_eq!(tracker.sample(pid, 1).2, IoStatus::Measured);
    }

    #[test]
    fn zero_is_measured_only_after_baseline_and_pid_reuse_resets() {
        let mut tracker = ProcessIoTracker::default();
        assert_eq!(tracker.observe((7, 1), Ok((30, 40))).2, IoStatus::Baseline);
        assert_eq!(
            tracker.observe((7, 1), Ok((30, 40))),
            (0, 0, IoStatus::Measured)
        );
        assert_eq!(
            tracker.observe((7, 1), Ok((35, 49))),
            (5, 9, IoStatus::Measured)
        );
        assert_eq!(tracker.observe((7, 2), Ok((50, 60))).2, IoStatus::Baseline);
        assert_eq!(tracker.observe((7, 2), Ok((1, 2))).2, IoStatus::Baseline);
    }

    #[test]
    fn failures_clear_baseline_and_permission_diagnostic_is_once() {
        let mut tracker = ProcessIoTracker::default();
        tracker.observe((7, 1), Ok((30, 40)));
        assert_eq!(
            tracker
                .observe((7, 1), Err(io::ErrorKind::PermissionDenied.into()))
                .2,
            IoStatus::PermissionDenied
        );
        assert_eq!(tracker.take_permission_diagnostic(), Some(1));
        assert_eq!(tracker.take_permission_diagnostic(), None);
        assert_eq!(tracker.observe((7, 1), Ok((35, 49))).2, IoStatus::Baseline);
        assert_eq!(
            tracker
                .observe((8, 1), Err(io::ErrorKind::NotFound.into()))
                .2,
            IoStatus::Unavailable
        );
        assert_eq!(
            tracker
                .observe((9, 1), Err(io::ErrorKind::Unsupported.into()))
                .2,
            IoStatus::Unsupported
        );
    }

    #[test]
    fn process_exit_removes_counters() {
        let mut tracker = ProcessIoTracker::default();
        tracker.begin();
        tracker.observe((7, 1), Ok((30, 40)));
        tracker.finish();
        tracker.begin();
        tracker.finish();
        assert!(tracker.previous.is_empty());
    }

    #[test]
    fn proc_io_parser_requires_both_counters() {
        assert_eq!(
            parse_counters("rchar: 90\nread_bytes: 0\nwrite_bytes: 15\n").unwrap(),
            (0, 15)
        );
        assert!(parse_counters("read_bytes: 0\n").is_err());
        assert!(parse_counters("read_bytes: no\nwrite_bytes: 0\n").is_err());
    }
}
