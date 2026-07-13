//! macOS memory compressor + 양 플랫폼 memory pressure/file descriptor 수집 (SRE t5).
//!
//! **왜 필요한가**: 이 머신에서 실측된 사고 — `system.memory.utilization=0.574`,
//! `system.swap.utilization=0.0` 둘 다 초록불인데, 실제로는 24 GiB의 anonymous memory를
//! 10 GiB RAM에 압축해 우겨넣고(compression_ratio 2.38) 버티는 중이었다. swap이 0이라 어떤
//! 임계에도 안 걸리고, `memory.compressed`가 애초에 수집 항목에 없어서 서버에 그 사실이
//! 존재조차 하지 않았다 — 임계를 낮춰도 안 남는다, 문제는 수집 범위였다. 그래서 여기서
//! (1) macOS memory compressor 3종, (2) 플랫폼 무관 memory pressure(임계를 하나로 걸 수 있는
//! 유일한 축), (3) file descriptor count/limit을 추가로 수집한다.
//!
//! host_metrics.rs와 같은 파일에 두지 않고 별도 모듈로 격리했다 — 여러 t-task가 동시에
//! host_metrics.rs를 건드리면 충돌면이 생기므로, 이 파일은 t5 전용이고 host_metrics.rs 쪽
//! 배선(1줄)은 t8이 담당한다. `collect()`는 아직 어디서도 호출되지 않으므로(`mod.rs`는 모듈
//! 등록만 한다) 이 스냅샷 시점의 `cargo clippy` 기준으로는 도달 불가능한 API다 — t8이 배선하면
//! 이 `allow`는 제거되어야 한다.
#![allow(dead_code)]
//!
//! [`MetricPoint`]는 host_metrics.rs의 기존 타입을 그대로 재사용한다(attrs 없는 무차원 scalar
//! metric만 만든다 — 수신측 rca의 metric 읽기 경로에 attrs 필터가 0건이라 차원 있는 metric은
//! 평균으로 뭉개진다).
//!
//! 실패 처리 원칙(ntp_offset_ms 선례를 따른다 — host_metrics.rs 참고): 한 metric의 실패가 다른
//! metric을 막지 않는다, 모르는 값을 0으로 보내지 않는다(측정 불가는 point 생략), 패닉하지 않는다.

#[cfg(target_os = "macos")]
use std::time::Instant;

use super::host_metrics::{MetricPoint, MetricValue};

/// host_extra 수집 상태. `decompression_rate`는 누적 카운터(`decompressions`)의 delta라 직전
/// 값과 시각을 보존해야 한다(host_metrics.rs의 disk/net i/o delta와 동일 패턴). 첫 sample은
/// baseline만 잡고 rate를 생략한다(직전 값이 없어 delta를 낼 수 없음).
#[derive(Default)]
pub(super) struct HostExtraState {
    #[cfg(target_os = "macos")]
    last_decompressions: Option<(u64, Instant)>,
}

impl HostExtraState {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

/// host_extra metric들을 수집한다. 개별 metric 실패는 해당 point만 생략하고 나머지는 계속
/// 수집한다 — 어떤 경로로도 패닉하지 않는다.
pub(super) fn collect(state: &mut HostExtraState) -> Vec<MetricPoint> {
    let mut points = Vec::new();
    collect_compressor(state, &mut points);
    collect_pressure(&mut points);
    collect_fd(&mut points);
    points
}

// ---------------------------------------------------------------------------------------------
// macOS: memory compressor (host_statistics64/HOST_VM_INFO64)
// ---------------------------------------------------------------------------------------------

/// `host_statistics64(HOST_VM_INFO64)`에서 뽑아 쓰는 필드만 담은 최소 구조체.
#[cfg(target_os = "macos")]
struct VmCompressorStats {
    /// 압축기(compressor) 안에 있는 페이지 수.
    compressor_page_count: u64,
    /// 압축기 안 페이지들을 압축 전(원본) 크기로 환산한 페이지 수 — `compressor_page_count`와의
    /// 비율이 compression_ratio다.
    total_uncompressed_pages_in_compressor: u64,
    /// 부팅 이후 누적 decompression 횟수(카운터) — 초당 rate로 환산하려면 delta가 필요하다.
    decompressions: u64,
}

/// `host_statistics64(HOST_VM_INFO64)` 호출 — 실측 466ns. 실패(비-macOS 커널 이상/권한)면
/// `None`이라 compressor 3종 전체를 생략한다(부분적으로 신뢰 못 할 구조체를 쓰는 것보다 안전).
// `libc::mach_host_self`가 deprecated(대안: `mach2` crate) 표시돼 있지만, 새 의존성을 추가하지
// 말라는 지침(이미 있는 libc만 쓴다) 때문에 의도적으로 그대로 쓴다 — 바인딩 자체는 여전히 유효.
#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn vm_compressor_stats() -> Option<VmCompressorStats> {
    // `modes`류 부작용 없는 순수 조회 — mach_host_self()는 특별 권한이 필요 없는 host 포트다.
    let mut stats: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let rc = unsafe {
        libc::host_statistics64(
            libc::mach_host_self(),
            libc::HOST_VM_INFO64,
            &mut stats as *mut libc::vm_statistics64 as libc::host_info64_t,
            &mut count,
        )
    };
    if rc != libc::KERN_SUCCESS {
        return None;
    }
    Some(VmCompressorStats {
        compressor_page_count: stats.compressor_page_count as u64,
        total_uncompressed_pages_in_compressor: stats.total_uncompressed_pages_in_compressor,
        decompressions: stats.decompressions,
    })
}

#[cfg(target_os = "macos")]
fn collect_compressor(state: &mut HostExtraState, points: &mut Vec<MetricPoint>) {
    let Some(stats) = vm_compressor_stats() else {
        return; // host_statistics64 실패 — compressor 3종 생략, 나머지 metric은 정상 수집.
    };
    let Some(page_size) = sysctl_u64("hw.pagesize") else {
        return; // page size 없이는 페이지 수를 바이트로 환산할 수 없다.
    };

    points.push(MetricPoint {
        name: "aic.system.memory.compressed",
        unit: "By",
        value: MetricValue::Int((stats.compressor_page_count * page_size) as i64),
    });

    // 0으로 나누기 방지 — compressor가 비어 있으면(압축된 게 없으면) ratio 자체가 무의미하다.
    if stats.compressor_page_count > 0 {
        let ratio = stats.total_uncompressed_pages_in_compressor as f64
            / stats.compressor_page_count as f64;
        points.push(MetricPoint {
            name: "aic.system.memory.compression_ratio",
            unit: "1",
            value: MetricValue::Double(ratio),
        });
    }

    // decompressions는 누적 카운터라 직전 sample과의 delta/elapsed로 초당 환산해야 의미가 있다.
    // 첫 sample(state가 비어 있음)은 baseline만 잡고 rate point를 생략한다.
    let now = Instant::now();
    if let Some((last_count, last_at)) = state.last_decompressions {
        let elapsed = now.duration_since(last_at).as_secs_f64().max(0.001);
        let delta = stats.decompressions.saturating_sub(last_count);
        points.push(MetricPoint {
            name: "aic.system.memory.decompression_rate",
            unit: "{page}/s",
            value: MetricValue::Double(delta as f64 / elapsed),
        });
    }
    state.last_decompressions = Some((stats.decompressions, now));
}

#[cfg(not(target_os = "macos"))]
fn collect_compressor(_state: &mut HostExtraState, _points: &mut Vec<MetricPoint>) {
    // memory compressor는 macOS 전용 개념 — 다른 플랫폼은 의도적으로 아무것도 내지 않는다.
}

// ---------------------------------------------------------------------------------------------
// memory pressure — 플랫폼 무관하게 임계를 하나로 걸 수 있는 유일한 축.
// ---------------------------------------------------------------------------------------------

/// macOS: `kern.memorystatus_vm_pressure_level` — 1(normal)/2(warn)/4(critical) 단일 값이라
/// `.some`/`.full` 구분이 없다. 그래서 macOS에서는 `aic.system.memory.pressure` 하나만 낸다.
#[cfg(target_os = "macos")]
fn collect_pressure(points: &mut Vec<MetricPoint>) {
    if let Some(level) = sysctl_u64("kern.memorystatus_vm_pressure_level") {
        points.push(MetricPoint {
            name: "aic.system.memory.pressure",
            unit: "1",
            value: MetricValue::Int(level as i64),
        });
    }
}

/// Linux: `/proc/pressure/memory`(PSI)의 `some`/`full` 라인에서 avg10을 읽어 0..1 비율로 낸다
/// (다른 utilization류 metric과 단위를 맞춘다 — avg10 자체는 최근 10초간 정체된 시간의 %).
/// 파일이 없거나(`CONFIG_PSI` 비활성, 커널 <4.20, `psi=0` 부팅) 읽기 실패면 두 point 다 생략한다.
#[cfg(target_os = "linux")]
fn collect_pressure(points: &mut Vec<MetricPoint>) {
    let Ok(text) = std::fs::read_to_string("/proc/pressure/memory") else {
        return;
    };
    if let Some(some) = parse_psi_avg10(&text, "some") {
        points.push(MetricPoint {
            name: "aic.system.memory.pressure.some",
            unit: "1",
            value: MetricValue::Double((some / 100.0).clamp(0.0, 1.0)),
        });
    }
    if let Some(full) = parse_psi_avg10(&text, "full") {
        points.push(MetricPoint {
            name: "aic.system.memory.pressure.full",
            unit: "1",
            value: MetricValue::Double((full / 100.0).clamp(0.0, 1.0)),
        });
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn collect_pressure(_points: &mut Vec<MetricPoint>) {
    // 지원 플랫폼(macOS/Linux) 밖에서는 pressure 신호를 얻을 안전한 방법이 없다.
}

/// `/proc/pressure/memory` 한 줄(`some avg10=0.00 avg60=... avg300=... total=...`)에서 avg10만
/// 뽑는다. 순수 함수라 실제 `/proc` 파일 없이도(macOS 개발 환경 포함) 테스트할 수 있다. Linux
/// 빌드에서만 실사용되므로 다른 플랫폼 빌드에서는 dead_code 경고를 막아준다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_psi_avg10(text: &str, prefix: &str) -> Option<f64> {
    let line = text.lines().find(|l| l.starts_with(prefix))?;
    let field = line
        .split_whitespace()
        .find(|tok| tok.starts_with("avg10="))?;
    field.strip_prefix("avg10=")?.parse().ok()
}

// ---------------------------------------------------------------------------------------------
// file descriptor — utilization은 절대 내지 않는다(아래 parse_file_nr 주석 참고).
// ---------------------------------------------------------------------------------------------

/// macOS: `kern.num_files`/`kern.maxfiles` — 각각 독립적으로 실패할 수 있어 개별 sysctl 실패가
/// 서로를 막지 않게 따로 조회한다.
#[cfg(target_os = "macos")]
fn collect_fd(points: &mut Vec<MetricPoint>) {
    if let Some(count) = sysctl_u64("kern.num_files") {
        points.push(MetricPoint {
            name: "aic.system.file_descriptor.count",
            unit: "{fd}",
            value: MetricValue::Int(count as i64),
        });
    }
    if let Some(limit) = sysctl_u64("kern.maxfiles") {
        points.push(MetricPoint {
            name: "aic.system.file_descriptor.limit",
            unit: "{fd}",
            value: MetricValue::Int(limit as i64),
        });
    }
}

/// Linux: `/proc/sys/fs/file-nr`(`allocated unused max`, 공백 구분) — count=allocated,
/// limit=max. **utilization은 계산하지 않는다**: jw-server 실측으로 `2057 0 9223372036854775807`
/// (max가 2^63-1)인 커널이 실존해, 비율이 2e-16이 되어 임계를 어떻게 잡아도 영원히 안 걸린다.
/// count/limit raw만 보내고 비율 판단은 수신측(rca)에 맡긴다.
#[cfg(target_os = "linux")]
fn collect_fd(points: &mut Vec<MetricPoint>) {
    let Ok(text) = std::fs::read_to_string("/proc/sys/fs/file-nr") else {
        return;
    };
    if let Some((allocated, max)) = parse_file_nr(&text) {
        points.push(MetricPoint {
            name: "aic.system.file_descriptor.count",
            unit: "{fd}",
            value: MetricValue::Int(allocated as i64),
        });
        points.push(MetricPoint {
            name: "aic.system.file_descriptor.limit",
            unit: "{fd}",
            value: MetricValue::Int(max as i64),
        });
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn collect_fd(_points: &mut Vec<MetricPoint>) {
    // 지원 플랫폼 밖에서는 fd count/limit을 읽을 이식 가능한 방법이 없다.
}

/// `/proc/sys/fs/file-nr`의 3필드(`allocated unused max`)를 파싱한다. `unused`는 쓰지 않는다
/// (allocated가 이미 in-use + free-in-cache를 포함한 커널 관점의 "할당된" 값). 순수 함수라
/// macOS 개발 환경에서도 테스트 가능하다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_file_nr(text: &str) -> Option<(u64, u64)> {
    let mut it = text.split_whitespace();
    let allocated: u64 = it.next()?.parse().ok()?;
    let _unused: u64 = it.next()?.parse().ok()?;
    let max: u64 = it.next()?.parse().ok()?;
    Some((allocated, max))
}

// ---------------------------------------------------------------------------------------------
// macOS sysctlbyname 공용 helper
// ---------------------------------------------------------------------------------------------

/// `sysctlbyname`으로 정수 OID 하나를 읽는다. 존재하지 않는 OID/권한 실패면 `None`.
///
/// macOS sysctl은 OID 타입에 따라 4바이트(`c_int`)나 8바이트(`u64`/`int64_t`)를 쓴다. 버퍼를
/// 8바이트로 잡고 미리 0으로 채워 두면(`buf: u64 = 0`), 커널이 4바이트만 채우는 OID라도(리틀
/// 엔디안에서) 상위 4바이트가 0으로 남아 그대로 올바른 값이 된다 — 그래서 실제로 채워진
/// 길이(`len`)는 4/8만 유효로 보고 나머지는 방어적으로 실패 처리한다.
#[cfg(target_os = "macos")]
fn sysctl_u64(name: &str) -> Option<u64> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            &mut buf as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    match len {
        4 | 8 => Some(buf),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_does_not_panic_and_names_are_unique() {
        // 실제 시스템 호출 — 어느 플랫폼에서든 패닉 없이 끝나야 한다. 측정 불가한 point는
        // 그냥 빠질 뿐(개수는 환경 의존이라 assert하지 않는다).
        let mut state = HostExtraState::new();
        let points = collect(&mut state);
        let mut names: Vec<&str> = points.iter().map(|p| p.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "metric 이름 중복: {names:?}");
    }

    #[test]
    fn second_sample_adds_decompression_rate_when_baseline_exists() {
        // 첫 호출은 baseline만 잡고 rate를 생략, 두 번째 호출부터 rate가 붙을 "수" 있다(macOS
        // 전용 — 다른 플랫폼은 애초에 compressor point 자체가 없다).
        let mut state = HostExtraState::new();
        let first = collect(&mut state);
        let second = collect(&mut state);
        let first_has_rate = first
            .iter()
            .any(|p| p.name == "aic.system.memory.decompression_rate");
        assert!(
            !first_has_rate,
            "첫 sample엔 decompression_rate가 없어야 함"
        );
        if cfg!(target_os = "macos")
            && first
                .iter()
                .any(|p| p.name == "aic.system.memory.compressed")
        {
            let second_has_rate = second
                .iter()
                .any(|p| p.name == "aic.system.memory.decompression_rate");
            assert!(
                second_has_rate,
                "compressor 측정 가능한 macOS는 2번째 sample부터 rate가 있어야 함"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_compressed_is_positive_and_ratio_at_least_one() {
        // Done Criteria AC1: compressed > 0, compression_ratio >= 1.0(정의상 압축 후 페이지 수
        // <= 압축 전 페이지 수 환산이므로 비율은 항상 1.0 이상이어야 한다).
        let mut state = HostExtraState::new();
        let points = collect(&mut state);
        let compressed = points
            .iter()
            .find(|p| p.name == "aic.system.memory.compressed")
            .unwrap_or_else(|| {
                panic!(
                    "compressed point 없음: {:?}",
                    points.iter().map(|p| p.name).collect::<Vec<_>>()
                )
            });
        match compressed.value {
            MetricValue::Int(v) => assert!(v > 0, "compressed가 0 이하: {v}"),
            _ => panic!("compressed는 Int여야 함"),
        }
        if let Some(ratio) = points
            .iter()
            .find(|p| p.name == "aic.system.memory.compression_ratio")
        {
            match ratio.value {
                MetricValue::Double(v) => assert!(v >= 1.0, "compression_ratio가 1.0 미만: {v}"),
                _ => panic!("compression_ratio는 Double이어야 함"),
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_fd_count_matches_sysctl() {
        // Done Criteria AC2: file_descriptor.count == sysctl kern.num_files 실측값.
        let mut state = HostExtraState::new();
        let points = collect(&mut state);
        let count = points
            .iter()
            .find(|p| p.name == "aic.system.file_descriptor.count")
            .unwrap_or_else(|| panic!("file_descriptor.count point 없음"));
        let expected = sysctl_u64("kern.num_files").expect("kern.num_files sysctl 실패");
        match count.value {
            MetricValue::Int(v) => assert_eq!(v as u64, expected),
            _ => panic!("file_descriptor.count는 Int여야 함"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pressure_level_is_one_of_known_values() {
        let mut state = HostExtraState::new();
        let points = collect(&mut state);
        if let Some(p) = points
            .iter()
            .find(|p| p.name == "aic.system.memory.pressure")
        {
            match p.value {
                MetricValue::Int(v) => assert!(
                    v == 1 || v == 2 || v == 4,
                    "알려지지 않은 pressure level: {v}"
                ),
                _ => panic!("pressure는 Int여야 함"),
            }
        }
    }

    #[test]
    fn parse_psi_avg10_extracts_some_and_full() {
        // jw-server 커널 6.17 실측 포맷.
        let text = "some avg10=0.00 avg60=0.00 avg300=0.00 total=464183\n\
full avg10=0.00 avg60=0.00 avg300=0.00 total=461924\n";
        assert_eq!(parse_psi_avg10(text, "some"), Some(0.0));
        assert_eq!(parse_psi_avg10(text, "full"), Some(0.0));

        let loaded = "some avg10=12.34 avg60=5.00 avg300=1.00 total=1\n\
full avg10=3.21 avg60=1.00 avg300=0.50 total=1\n";
        assert_eq!(parse_psi_avg10(loaded, "some"), Some(12.34));
        assert_eq!(parse_psi_avg10(loaded, "full"), Some(3.21));
    }

    #[test]
    fn parse_psi_avg10_missing_prefix_is_none() {
        assert_eq!(parse_psi_avg10("full avg10=1.0\n", "some"), None);
        assert_eq!(parse_psi_avg10("", "some"), None);
    }

    #[test]
    fn parse_file_nr_reads_allocated_and_max() {
        // 정상 macOS류(현실적인 max).
        assert_eq!(
            parse_file_nr("2057 0 9223372036854775807\n"),
            Some((2057, 9223372036854775807))
        );
        assert_eq!(parse_file_nr("900 100 4000\n"), Some((900, 4000)));
    }

    #[test]
    fn parse_file_nr_malformed_is_none() {
        assert_eq!(parse_file_nr(""), None);
        assert_eq!(parse_file_nr("not a number\n"), None);
        assert_eq!(parse_file_nr("1 2\n"), None); // 3필드 미만.
    }
}
