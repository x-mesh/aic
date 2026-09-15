use aic_common::jvm_perfdata::{parse, JvmPerfDataMetrics};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const REQUIRED_NAMES: [&str; 8] = [
    "java.threads.started",
    "java.threads.live",
    "java.threads.livePeak",
    "java.threads.daemon",
    "java.cls.loadedClasses",
    "java.cls.sharedLoadedClasses",
    "java.cls.unloadedClasses",
    "java.cls.sharedUnloadedClasses",
];

#[derive(Deserialize)]
struct Manifest {
    schema_version: u32,
    generator_sha256: String,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    filename: String,
    sha256: String,
    kind: String,
    vendor: String,
    build: String,
    gc: String,
    byte_order: String,
    format: String,
    source_image_digest: String,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    threads_started_total: u64,
    threads_live: u64,
    threads_peak: u64,
    threads_daemon: u64,
    classes_loaded: u64,
    classes_unloaded_total: u64,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/jvm_perfdata")
}

fn manifest() -> Manifest {
    serde_json::from_slice(&fs::read(root().join("manifest.json")).unwrap()).unwrap()
}

fn sha256(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (current, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *current = current.wrapping_add(value);
        }
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

fn entry_names(bytes: &[u8]) -> Vec<String> {
    assert_eq!(&bytes[..4], &[0xca, 0xfe, 0xc0, 0xc0]);
    assert_eq!(bytes[4], 1);
    assert_eq!(&bytes[5..8], &[2, 0, 1]);
    let read_i32 =
        |offset: usize| i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    let used = read_i32(8);
    let mut cursor = read_i32(24);
    let count = read_i32(28);
    let mut names = Vec::new();
    for _ in 0..count {
        let entry_len = read_i32(cursor);
        let name_start = cursor + read_i32(cursor + 4);
        let name_end = bytes[name_start..cursor + entry_len]
            .iter()
            .position(|byte| *byte == 0)
            .map(|length| name_start + length)
            .unwrap();
        names.push(
            std::str::from_utf8(&bytes[name_start..name_end])
                .unwrap()
                .to_owned(),
        );
        cursor += entry_len;
    }
    assert_eq!(cursor, used);
    names
}

#[test]
fn synthetic_fixture_matrix_matches_golden_metrics() {
    let manifest = manifest();
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.fixtures.len(), 6);
    let generator = fs::read(root().join("generate.py")).unwrap();
    assert_eq!(sha256(&generator), manifest.generator_sha256);
    let expected_pairs: BTreeSet<_> = [
        ("17.0.20", "G1"),
        ("17.0.20", "ZGC"),
        ("21.0.12", "G1"),
        ("21.0.12", "ZGC"),
        ("25.0.4", "G1"),
        ("25.0.4", "ZGC"),
    ]
    .into_iter()
    .collect();
    let actual_pairs: BTreeSet<_> = manifest
        .fixtures
        .iter()
        .map(|fixture| (fixture.build.as_str(), fixture.gc.as_str()))
        .collect();
    assert_eq!(actual_pairs, expected_pairs);

    for fixture in manifest.fixtures {
        assert_eq!(fixture.kind, "sanitized_capture");
        assert_eq!(fixture.vendor, "Eclipse Temurin");
        assert_eq!(fixture.byte_order, "little-endian");
        assert_eq!(fixture.format, "2.0");
        assert!(
            fixture.sha256.len() == 64
                && fixture.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(fixture.source_image_digest.len(), 71);
        assert!(fixture.source_image_digest.starts_with("sha256:"));
        assert!(fixture.source_image_digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        let fixture_bytes = fs::read(root().join(&fixture.filename)).unwrap();
        assert_eq!(sha256(&fixture_bytes), fixture.sha256);
        let metrics = parse(&fixture_bytes).unwrap();
        assert_eq!(
            metrics,
            JvmPerfDataMetrics {
                threads_started_total: fixture.expected.threads_started_total,
                threads_live: fixture.expected.threads_live,
                threads_peak: fixture.expected.threads_peak,
                threads_daemon: fixture.expected.threads_daemon,
                classes_loaded: fixture.expected.classes_loaded,
                classes_unloaded_total: fixture.expected.classes_unloaded_total,
            },
            "{}",
            fixture.filename
        );
    }
}

#[test]
fn fixtures_contain_only_the_required_counter_names() {
    let required: BTreeSet<_> = REQUIRED_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    for fixture in manifest().fixtures {
        let bytes = fs::read(root().join(&fixture.filename)).unwrap();
        assert_eq!(bytes.len(), 480, "{}", fixture.filename);
        assert_eq!(
            entry_names(&bytes).into_iter().collect::<BTreeSet<_>>(),
            required
        );
        let printable_runs: Vec<_> = bytes
            .split(|byte| !byte.is_ascii_graphic())
            .filter(|value| value.len() >= 4)
            .map(|value| std::str::from_utf8(value).unwrap())
            .collect();
        assert_eq!(printable_runs, REQUIRED_NAMES, "{}", fixture.filename);
        for forbidden in [
            b"/tmp".as_slice(),
            b"-XX:".as_slice(),
            b"user.name".as_slice(),
        ] {
            assert!(!bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
    }
}
