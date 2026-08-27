//! Device-keyed disk I/O counter deltas shared by host metric samplers.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::hash::Hash;
use std::path::Path;

/// Disk I/O accumulated between two samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskIoDelta {
    pub read_bytes: u64,
    pub written_bytes: u64,
}

/// Tracks cumulative disk counters by device identity.
///
/// A sample can contain the same backing device more than once (for example, when Linux exposes
/// multiple mounts backed by one `/proc/diskstats` entry). Duplicate identities are collapsed by
/// taking the maximum cumulative value for each counter, making the result independent of input
/// order.
#[derive(Debug)]
pub struct DiskIoTracker<K> {
    previous: HashMap<K, DiskIoDelta>,
    initialized: bool,
}

impl<K> Default for DiskIoTracker<K> {
    fn default() -> Self {
        Self {
            previous: HashMap::new(),
            initialized: false,
        }
    }
}

impl<K> DiskIoTracker<K>
where
    K: Eq + Hash,
{
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one sample of cumulative counters and returns its delta from the previous sample.
    ///
    /// The first sample establishes a baseline and returns `None`. Devices absent from the previous
    /// sample contribute zero, and reset/decreased counters are clamped to zero.
    pub fn sample<I>(&mut self, counters: I) -> Option<DiskIoDelta>
    where
        I: IntoIterator<Item = (K, u64, u64)>,
    {
        let mut current: HashMap<K, DiskIoDelta> = HashMap::new();
        for (device, read_bytes, written_bytes) in counters {
            let entry = current.entry(device).or_default();
            entry.read_bytes = entry.read_bytes.max(read_bytes);
            entry.written_bytes = entry.written_bytes.max(written_bytes);
        }

        let delta = self.initialized.then(|| {
            current
                .iter()
                .fold(DiskIoDelta::default(), |mut total, (device, now)| {
                    if let Some(before) = self.previous.get(device) {
                        total.read_bytes = total
                            .read_bytes
                            .saturating_add(now.read_bytes.saturating_sub(before.read_bytes));
                        total.written_bytes = total
                            .written_bytes
                            .saturating_add(now.written_bytes.saturating_sub(before.written_bytes));
                    }
                    total
                })
        });

        self.previous = current;
        self.initialized = true;
        delta
    }
}

/// Returns a stable device identity, resolving symlinked device paths when possible.
pub fn canonical_device_identity(name: &OsStr) -> OsString {
    std::fs::canonicalize(Path::new(name))
        .map(|path| path.into_os_string())
        .unwrap_or_else(|_| name.to_os_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_io_first_sample_returns_none_and_second_returns_exact_delta() {
        let mut tracker = DiskIoTracker::new();
        assert_eq!(tracker.sample([("sda", 1_000, 2_000)]), None);
        assert_eq!(
            tracker.sample([("sda", 1_125, 2_250)]),
            Some(DiskIoDelta {
                read_bytes: 125,
                written_bytes: 250,
            })
        );
    }

    #[test]
    fn disk_io_duplicate_device_identities_count_once() {
        let mut tracker = DiskIoTracker::new();
        assert_eq!(
            tracker.sample([("sda", 1_000, 2_000), ("sda", 900, 2_100)]),
            None
        );
        assert_eq!(
            tracker.sample([("sda", 1_300, 2_400), ("sda", 1_200, 2_350)]),
            Some(DiskIoDelta {
                read_bytes: 300,
                written_bytes: 300,
            })
        );
    }

    #[test]
    fn disk_io_new_device_does_not_inject_lifetime_total() {
        let mut tracker = DiskIoTracker::new();
        assert_eq!(tracker.sample([("sda", 100, 200)]), None);
        assert_eq!(
            tracker.sample([("sda", 110, 220), ("sdb", 50_000, 80_000)]),
            Some(DiskIoDelta {
                read_bytes: 10,
                written_bytes: 20,
            })
        );
    }

    #[test]
    fn disk_io_decreased_counter_contributes_zero() {
        let mut tracker = DiskIoTracker::new();
        assert_eq!(tracker.sample([("sda", 1_000, 2_000)]), None);
        assert_eq!(
            tracker.sample([("sda", 10, 20)]),
            Some(DiskIoDelta::default())
        );
    }

    #[test]
    fn linux_diskstats_fixture_deduplicates_devices_and_computes_second_sample_delta() {
        const SECTOR_SIZE: u64 = 512;
        const FIRST: &str = "
8 0 sda 10 0 100 0 20 0 200 0 0 0 0 0
8 0 sda 10 0 100 0 20 0 200 0 0 0 0 0
8 16 sdb 5 0 50 0 8 0 80 0 0 0 0 0
";
        const SECOND: &str = "
8 0 sda 11 0 104 0 21 0 207 0 0 0 0 0
8 0 sda 11 0 104 0 21 0 207 0 0 0 0 0
8 16 sdb 6 0 53 0 9 0 85 0 0 0 0 0
";

        fn parse_fixture(input: &str) -> Vec<(String, u64, u64)> {
            input
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    let sectors_read = fields[5].parse::<u64>().unwrap();
                    let sectors_written = fields[9].parse::<u64>().unwrap();
                    (
                        format!("/dev/{}", fields[2]),
                        sectors_read.saturating_mul(SECTOR_SIZE),
                        sectors_written.saturating_mul(SECTOR_SIZE),
                    )
                })
                .collect()
        }

        let mut tracker = DiskIoTracker::new();
        assert_eq!(tracker.sample(parse_fixture(FIRST)), None);
        assert_eq!(
            tracker.sample(parse_fixture(SECOND)),
            Some(DiskIoDelta {
                read_bytes: 7 * SECTOR_SIZE,
                written_bytes: 12 * SECTOR_SIZE,
            })
        );
    }
}
