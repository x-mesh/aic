use aic_common::jvm_perfdata::parse;
use proptest::prelude::*;

const MAGIC: u32 = 0xcafec0c0;
const PROLOGUE_SIZE: usize = 32;
const ENTRY_HEADER_SIZE: usize = 20;
const COUNTER_NAMES: [&str; 8] = [
    "java.threads.started",
    "java.threads.live",
    "java.threads.livePeak",
    "java.threads.daemon",
    "java.cls.loadedClasses",
    "java.cls.sharedLoadedClasses",
    "java.cls.unloadedClasses",
    "java.cls.sharedUnloadedClasses",
];

fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn write_i32(buffer: &mut [u8], offset: usize, value: i32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(buffer: &mut [u8], offset: usize, value: i64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn serialize(values: [i64; 8], timestamp: i64) -> Vec<u8> {
    let mut bytes = vec![0_u8; PROLOGUE_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    bytes[4] = 1;
    bytes[5] = 2;
    bytes[6] = 0;
    bytes[7] = 1;
    write_i64(&mut bytes, 16, timestamp);
    write_i32(&mut bytes, 24, PROLOGUE_SIZE as i32);
    write_i32(&mut bytes, 28, COUNTER_NAMES.len() as i32);

    for (index, (name, value)) in COUNTER_NAMES.iter().zip(values).enumerate() {
        let entry_start = bytes.len();
        let name_offset = ENTRY_HEADER_SIZE;
        let data_offset = align_up(name_offset + name.len() + 1, 8);
        let entry_length = align_up(data_offset + size_of::<i64>(), 8);
        bytes.resize(entry_start + entry_length, 0);
        write_i32(&mut bytes, entry_start, entry_length as i32);
        write_i32(&mut bytes, entry_start + 4, name_offset as i32);
        write_i32(&mut bytes, entry_start + 8, 0);
        bytes[entry_start + 12] = b'J';
        bytes[entry_start + 13] = 1;
        bytes[entry_start + 14] = if (1..=3).contains(&index) { 1 } else { 4 };
        bytes[entry_start + 15] = if (1..=3).contains(&index) { 3 } else { 2 };
        write_i32(&mut bytes, entry_start + 16, data_offset as i32);
        bytes[entry_start + name_offset..entry_start + name_offset + name.len()]
            .copy_from_slice(name.as_bytes());
        write_i64(&mut bytes, entry_start + data_offset, value);
    }

    let used = bytes.len() as i32;
    write_i32(&mut bytes, 8, used);
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bytes_never_panic_and_are_deterministic(
        input in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let first = parse(&input);
        let second = parse(&input);
        prop_assert_eq!(first, second);
    }

    #[test]
    fn serialized_required_counters_round_trip(
        started in 0_i64..=1_000_000,
        live in 0_i64..=1_000,
        peak_extra in 0_i64..=1_000,
        daemon_seed in 0_i64..=1_000,
        loaded in 0_i64..=1_000_000,
        shared_loaded in 0_i64..=100_000,
        unloaded in 0_i64..=100_000,
        shared_unloaded in 0_i64..=10_000,
    ) {
        let daemon = daemon_seed.min(live);
        let peak = live + peak_extra;
        let loaded_floor = unloaded + shared_unloaded;
        let loaded = loaded.max(loaded_floor);
        let fixture = serialize(
            [started, live, peak, daemon, loaded, shared_loaded, unloaded, shared_unloaded],
            1234,
        );
        let metrics = parse(&fixture).unwrap();
        prop_assert_eq!(metrics.threads_started_total, started as u64);
        prop_assert_eq!(metrics.threads_live, live as u64);
        prop_assert_eq!(metrics.threads_peak, peak as u64);
        prop_assert_eq!(metrics.threads_daemon, daemon as u64);
        prop_assert_eq!(
            metrics.classes_loaded,
            (loaded + shared_loaded - unloaded - shared_unloaded) as u64
        );
        prop_assert_eq!(
            metrics.classes_unloaded_total,
            (unloaded + shared_unloaded) as u64
        );
    }
}
