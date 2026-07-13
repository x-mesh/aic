//! macOS memory compressor + 양 플랫폼 memory pressure/file descriptor 수집 (SRE t5).
//!
//! **왜 필요한가**: 이 머신에서 실측된 사고 — `system.memory.utilization=0.574`,
//! `system.swap.utilization=0.0` 둘 다 초록불인데, 실제로는 24 GiB의 anonymous memory를
//! 10 GiB RAM에 압축해 우겨넣고(compression_ratio 2.38) 버티는 중이었다. swap이 0이라 어떤
//! 임계에도 안 걸리고, `memory.compressed`가 애초에 수집 항목에 없어서 서버에 그 사실이
//! 존재조차 하지 않았다 — 임계를 낮춰도 안 남는다, 문제는 수집 범위였다. 그래서 여기서
//! (1) macOS memory compressor 3종, (2) memory pressure, (3) file descriptor count/limit을
//! 추가로 수집한다.
//!
//! memory pressure는 **플랫폼별로 이름을 분리**한다(macOS `.level` 이산값 vs Linux `.some`/`.full`
//! 연속 비율). 초기 설계의 "플랫폼 무관 단일 임계" 전제는 사실이 아니어서 철회했다 — 자세한 이유는
//! 아래 memory pressure 섹션 주석에 있다.
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

/// `host_statistics64(HOST_VM_INFO64)`에서 뽑아 쓰는 필드 + 그 페이지 수를 바이트로 환산할 때
/// 쓸 페이지 크기. **page_size를 같은 구조체에 담는 게 핵심이다** — 아래 `vm_compressor_stats`가
/// 통계와 페이지 크기를 **같은 host port**에서 한꺼번에 얻어 단위 불일치를 구조적으로 차단한다
/// (자세한 근거는 [`HostPort::page_size`] doc 참고).
#[cfg(target_os = "macos")]
struct VmCompressorStats {
    /// 압축기(compressor) 안에 있는 페이지 수. **커널 페이지** 단위다.
    compressor_page_count: u64,
    /// 압축기 안 페이지들을 압축 전(원본) 크기로 환산한 페이지 수 — `compressor_page_count`와의
    /// 비율이 compression_ratio다.
    total_uncompressed_pages_in_compressor: u64,
    /// 부팅 이후 누적 decompression 횟수(카운터) — 초당 rate로 환산하려면 delta가 필요하다.
    decompressions: u64,
    /// 위 페이지 수들과 **같은 host port**에서 얻은 커널 페이지 크기. [`KernelPageSize`] 타입이라
    /// sysctl 등 다른 출처의 `u64`는 여기 들어올 수 없다(컴파일 에러).
    page_size: KernelPageSize,
}

#[cfg(target_os = "macos")]
use mach_host::{HostPort, KernelPageSize};

/// mach host port와 커널 페이지 크기를 감싸는 **비공개 모듈**.
///
/// 별도 모듈로 가둔 이유는 [`KernelPageSize`]의 내부 필드를 이 모듈 밖에서 **구성할 수 없게**
/// 만들기 위해서다. 그 결과 "환산 계수는 host port에서만 나온다"가 주석의 약속이 아니라 **컴파일러가
/// 강제하는 규칙**이 된다 — `sysctl_u64("hw.pagesize")`가 돌려주는 `u64`는 `KernelPageSize`가
/// 아니므로 환산 계수 자리에 넣으면 타입 에러다(자세한 사고 경위는 [`HostPort::page_size`] 참고).
#[cfg(target_os = "macos")]
mod mach_host {
    // libc는 `mach_port_deallocate`/`host_page_size` 바인딩을 노출하지 않는다(0.2.186 기준 — mach
    // 계열은 `mach2` crate로 옮겨졌다). 새 의존성을 추가하지 말라는 지침이 있으므로 직접 선언한다.
    // 두 심볼 모두 libSystem에 있어 macOS에서 항상 링크되므로 추가 링크 플래그가 필요 없다.
    extern "C" {
        fn mach_port_deallocate(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
        ) -> libc::kern_return_t;

        /// `<mach/mach_init.h>`: `kern_return_t host_page_size(host_t, vm_size_t *)`.
        fn host_page_size(
            host: libc::host_t,
            out_page_size: *mut libc::vm_size_t,
        ) -> libc::kern_return_t;
    }

    /// 커널 페이지 크기(바이트). **생성자가 이 모듈 안에만 있다** — 유일한 생산자는
    /// [`HostPort::page_size`]이므로, 다른 출처(sysctl 등)의 숫자가 환산 계수로 흘러드는 것을
    /// 타입 시스템이 막는다. 값은 [`KernelPageSize::get`]으로만 꺼낼 수 있다.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct KernelPageSize(u64);

    impl KernelPageSize {
        pub(super) fn get(self) -> u64 {
            self.0
        }
    }

    /// `mach_host_self()`가 반환한 host port send right의 RAII 소유권.
    ///
    /// **왜 필요한가(누수 버그)**: `mach_host_self()`는 호출할 때마다 send right의 user reference를
    /// 하나 올린다 — 이름(포트 번호)은 같지만 uref가 계속 증가한다. aicd는 상주 데몬이고 이 코드는
    /// 60초마다 호출되므로, 반납하지 않으면 프로세스 수명 내내 uref가 단조 증가한다(하루 1440회).
    /// 참고로 `sysinfo`는 `System::new()`에서 **딱 한 번** 얻어 들고 있어 누수가 없다 — 우리는 주기
    /// 호출이라 그 전략을 쓸 수 없고, 대신 매번 반납해야 한다.
    ///
    /// **누수가 없다는 보장**: 획득은 [`HostPort::acquire`] 한 곳에서만 일어나고, 반납은 [`Drop`]에
    /// 있다. Rust는 스코프를 벗어나는 **모든** 경로(정상 반환, `?`/early return, 패닉 unwind)에서
    /// `drop`을 호출하므로, `vm_compressor_stats`의 `rc != KERN_SUCCESS` early return에서도 반드시
    /// 반납된다. 필드를 밖으로 꺼내 쓰지 못하게 raw 값은 `as_raw()`로만 빌려준다(가드가 살아 있는
    /// 동안만 유효). 이 불변식은 `host_port_send_right_is_not_leaked` 테스트가 `mach_port_get_refs`로
    /// uref를 직접 읽어 회귀 검증한다.
    pub(super) struct HostPort(libc::mach_port_t);

    impl HostPort {
        /// `libc::mach_host_self`가 deprecated(대안 `mach2` crate) 표시지만, 새 의존성 금지 지침에
        /// 따라 의도적으로 계속 쓴다 — 바인딩 자체는 유효하다.
        #[allow(deprecated)]
        pub(super) fn acquire() -> Self {
            // 특별 권한이 필요 없는 host name port — 부작용 없는 순수 조회용이다.
            Self(unsafe { libc::mach_host_self() })
        }

        pub(super) fn as_raw(&self) -> libc::mach_port_t {
            self.0
        }

        /// 이 host port가 보고하는 **커널 페이지 크기**. 실패하면 `None`.
        ///
        /// **`sysctlbyname("hw.pagesize")`를 쓰면 안 된다(실제 버그였다).** `host_statistics64`가
        /// 세는 `compressor_page_count`는 **커널 페이지** 단위인데, `hw.pagesize`는 **호출하는
        /// 프로세스의** 페이지 크기를 보고한다. 평소엔 같지만 Rosetta 하의 x86_64 프로세스에서
        /// 갈라진다 — 이 머신(Apple Silicon)에서 같은 C 프로그램을 두 아키텍처로 빌드해 실측했다:
        ///
        /// ```text
        ///                        native arm64   x86_64 (Rosetta)
        ///   hw.pagesize              16384          4096     ← 갈라진다
        ///   vm_page_size             16384          4096     ← 갈라진다 (프로세스 페이지)
        ///   host_page_size()         16384         16384     ← 불변 (커널 페이지)
        ///   vm_kernel_page_size      16384         16384     ← 불변
        ///   compressed 환산          17.88 GiB   4.49(hw) / 17.96(host) GiB
        /// ```
        ///
        /// 즉 `hw.pagesize`로 환산하면 Rosetta에서 실제의 **1/4로 과소보고**된다(17.9 → 4.5 GiB).
        /// 이 모듈의 존재 이유가 "압축 메모리를 서버에 정확히 보이게 하는 것"이라, 환산 계수가
        /// 틀리면 지표가 거짓이 되고 임계에 안 걸려 우리가 고치려던 사고를 그대로 다시 놓친다.
        ///
        /// **단위 일치의 근거**: `host_page_size`는 `host_statistics64`와 **같은 host port**(`self.0`)
        /// 에 질의한다. 페이지 수를 센 주체와 페이지 크기를 보고하는 주체가 동일한 커널 객체이므로
        /// 단위가 어긋날 수 없다 — 실측이 아니라 구조에서 나오는 보장이다.
        ///
        /// **되돌림 방지**: 네이티브 arm64에서는 `hw.pagesize`도 16384라 *어떤 단위 테스트도* 두
        /// 출처를 구분하지 못한다(Rosetta에서만 갈라지므로). 그래서 테스트 대신 **타입**으로 막았다 —
        /// [`KernelPageSize`]는 이 모듈 안에서만 만들 수 있고 그 유일한 생산자가 이 함수다. sysctl로
        /// 되돌리려면 `u64`를 환산 계수 자리에 넣어야 하는데 그건 컴파일되지 않는다.
        pub(super) fn page_size(&self) -> Option<KernelPageSize> {
            let mut size: libc::vm_size_t = 0;
            let rc = unsafe { host_page_size(self.0, &mut size) };
            (rc == libc::KERN_SUCCESS && size > 0).then_some(KernelPageSize(size as u64))
        }
    }

    impl Drop for HostPort {
        #[allow(deprecated)]
        fn drop(&mut self) {
            // 반납 실패는 복구할 방법도, 의미 있는 대응도 없다(이미 유효하지 않은 포트라는 뜻).
            // 패닉 금지 원칙에 따라 무시한다 — Drop에서 패닉하면 unwind 중 abort로 이어질 수 있다.
            unsafe {
                let _ = mach_port_deallocate(libc::mach_task_self(), self.0);
            }
        }
    }
}

/// `host_statistics64(HOST_VM_INFO64)` 호출 — 실측 466ns. 실패(권한/커널 이상)면 `None`이라
/// compressor 3종 전체를 생략한다(부분적으로 신뢰 못 할 구조체를 쓰는 것보다 안전).
///
/// 통계와 페이지 크기를 **하나의 host port에서 함께** 얻는다 — 이게 단위 불일치를 막는 구조적
/// 장치다([`HostPort::page_size`] doc의 Rosetta 실측 참고). 페이지 크기를 별도 sysctl에서 가져오면
/// 두 값의 출처가 갈라져 Rosetta에서 1/4로 과소보고된다.
#[cfg(target_os = "macos")]
fn vm_compressor_stats() -> Option<VmCompressorStats> {
    // 가드가 스코프 끝(성공/실패 무관)에서 send right를 반납한다 — HostPort doc의 누수 보장 참고.
    let host = HostPort::acquire();

    let mut stats: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let rc = unsafe {
        libc::host_statistics64(
            host.as_raw(),
            libc::HOST_VM_INFO64,
            &mut stats as *mut libc::vm_statistics64 as libc::host_info64_t,
            &mut count,
        )
    };
    if rc != libc::KERN_SUCCESS {
        return None; // 여기서도 `host`의 Drop이 돌아 반납된다.
    }
    // 페이지 수를 센 그 포트에 페이지 크기를 묻는다. 못 얻으면 환산이 불가능하므로 compressor
    // 전체를 생략한다 — 틀린 계수로 거짓 값을 내느니 point를 빼는 게 낫다(모듈 doc의 실패 원칙).
    let page_size = host.page_size()?;

    Some(VmCompressorStats {
        compressor_page_count: stats.compressor_page_count as u64,
        total_uncompressed_pages_in_compressor: stats.total_uncompressed_pages_in_compressor,
        decompressions: stats.decompressions,
        page_size,
    })
}

#[cfg(target_os = "macos")]
fn collect_compressor(state: &mut HostExtraState, points: &mut Vec<MetricPoint>) {
    let Some(stats) = vm_compressor_stats() else {
        // host_statistics64 또는 host_page_size 실패 — compressor 3종 생략, 나머지는 정상 수집.
        return;
    };

    // decompressions는 누적 카운터라 직전 sample과의 delta/elapsed로 초당 환산해야 의미가 있다.
    // 첫 sample(state가 비어 있음)은 baseline만 잡고 rate를 생략한다(None).
    let now = Instant::now();
    let rate = state.last_decompressions.map(|(last_count, last_at)| {
        // 0으로 나누기 방지(연속 호출 간 간격이 아주 짧을 수 있음 — host_metrics.rs와 같은 방어).
        let elapsed = now.duration_since(last_at).as_secs_f64().max(0.001);
        stats.decompressions.saturating_sub(last_count) as f64 / elapsed
    });
    state.last_decompressions = Some((stats.decompressions, now));

    points.extend(compressor_points(
        stats.compressor_page_count,
        stats.total_uncompressed_pages_in_compressor,
        stats.page_size.get(),
        rate,
    ));
}

/// 원시 compressor 수치 → metric points (순수 함수). syscall과 분리해 둔 이유: `compressor_page_count
/// == 0`(압축 미사용 = 방금 부팅했거나 메모리가 넉넉한 건강한 머신, CI 컨테이너)은 **정상 상태**인데,
/// 개발 머신에서는 재현할 수 없어 테스트가 그 분기를 못 밟는다. 순수 함수로 빼면 환경과 무관하게
/// 픽스처로 0-압축 경로를 검증할 수 있다.
///
/// 불변식: `compressed`는 0이어도 항상 낸다(0은 "측정했더니 0"이라는 유효한 값이다). `ratio`는
/// `compressor_page_count > 0`일 때만 낸다 — 0으로 나누지 않기 위함이고, 압축된 게 없을 때의
/// 압축률은 정의 자체가 무의미하다.
///
/// 플랫폼 무관하게 컴파일된다(macOS 전용 syscall에 의존하지 않음) — Linux 빌드에서는 호출부가
/// 없어 쓰이지 않지만, 모듈 상단의 `allow(dead_code)`가 이를 덮는다.
fn compressor_points(
    compressor_pages: u64,
    uncompressed_pages: u64,
    page_size: u64,
    decompression_rate: Option<f64>,
) -> Vec<MetricPoint> {
    let mut points = vec![MetricPoint {
        name: "aic.system.memory.compressed",
        unit: "By",
        value: MetricValue::Int(compressor_pages.saturating_mul(page_size) as i64),
    }];

    if compressor_pages > 0 {
        points.push(MetricPoint {
            name: "aic.system.memory.compression_ratio",
            unit: "1",
            value: MetricValue::Double(uncompressed_pages as f64 / compressor_pages as f64),
        });
    }

    if let Some(rate) = decompression_rate {
        points.push(MetricPoint {
            name: "aic.system.memory.decompression_rate",
            unit: "{page}/s",
            value: MetricValue::Double(rate),
        });
    }

    points
}

#[cfg(not(target_os = "macos"))]
fn collect_compressor(_state: &mut HostExtraState, _points: &mut Vec<MetricPoint>) {
    // memory compressor는 macOS 전용 개념 — 다른 플랫폼은 의도적으로 아무것도 내지 않는다.
}

// ---------------------------------------------------------------------------------------------
// memory pressure — 플랫폼별로 **이름을 명시적으로 분리한다**.
//
// 처음 설계는 "pressure가 플랫폼 무관하게 임계를 하나로 걸 수 있는 유일한 축"이라고 봤으나,
// 그건 사실이 아니어서 철회했다. 두 플랫폼이 측정하는 대상이 근본적으로 다르다:
//
//   macOS: aic.system.memory.pressure.level  = 1 | 2 | 4     이산 레벨 (커널의 판정)
//   Linux: aic.system.memory.pressure.some   = 0.0 ~ 1.0     연속 비율 (정체된 시간의 몫)
//          aic.system.memory.pressure.full   = 0.0 ~ 1.0
//
// 이름·타입·스케일이 전부 다르므로 같은 임계를 걸 수 없다. macOS의 "warn"(2)과 Linux의 "10초 중
// 50% 정체"를 같은 0~1 축으로 매핑하면 서로 다른 두 현상을 같다고 주장하는 셈이라 **거짓**이다.
// 그래서 억지 통일 대신 정직하게 분리했다 — 임계는 수신측(rca)이 `host.os.type`으로 분기해 건다.
//
// ⚠ 다음 사람에게: "이름이 왜 다르지, 통일하자"고 되돌리지 마라. 위 이유 때문에 **의도적**이다.
// 통일하려면 두 지표를 같은 의미로 만들 방법부터 찾아야 하는데, 커널의 이산 판정과 정체 시간의
// 연속 비율 사이에는 그런 변환이 존재하지 않는다.
// ---------------------------------------------------------------------------------------------

/// macOS: `kern.memorystatus_vm_pressure_level` — 1(normal)/2(warn)/4(critical)의 이산 레벨이다.
/// 커널이 이미 판정을 내려 준 값이라 Linux PSI 같은 `.some`/`.full`(정체 시간 비율) 구분이 없다.
/// 그래서 이름을 `.level`로 명시해 Linux의 연속 비율 지표와 **혼동되지 않게** 한다(위 섹션 주석).
#[cfg(target_os = "macos")]
fn collect_pressure(points: &mut Vec<MetricPoint>) {
    if let Some(level) = sysctl_u64("kern.memorystatus_vm_pressure_level") {
        points.push(MetricPoint {
            name: "aic.system.memory.pressure.level",
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
    fn decompression_rate_is_omitted_until_a_baseline_exists() {
        // 누적 카운터라 첫 sample에는 delta를 낼 직전 값이 없다 → rate 생략. 두 번째부터 나온다.
        // 이 관계는 환경과 무관하게 코드가 보장한다: rate는 `state.last_decompressions`가 Some일
        // 때만 push되고, 그 baseline은 compressed point를 push하는 것과 **동일한 조건**(수집 성공)
        // 에서 기록된다. 그래서 "1회차에 compressed가 있었다 ⇒ 2회차엔 rate가 있다"가 성립한다.
        let mut state = HostExtraState::new();
        let first = collect(&mut state);
        let second = collect(&mut state);

        assert!(
            double_of(&first, "aic.system.memory.decompression_rate").is_none(),
            "첫 sample엔 decompression_rate가 없어야 함"
        );

        let collected = int_of(&first, "aic.system.memory.compressed").is_some();
        let rate = double_of(&second, "aic.system.memory.decompression_rate");
        if collected {
            let r = rate.expect("1회차 수집이 성공했으면 2회차엔 rate가 있어야 함");
            // 카운터는 단조 증가(saturating_sub)라 rate는 음수가 될 수 없다.
            assert!(r >= 0.0, "decompression_rate가 음수: {r}");
        } else {
            // 수집 자체가 불가능한 플랫폼/환경(비-macOS 등)에서는 2회차에도 rate가 없다.
            assert!(rate.is_none(), "수집 불가 환경인데 rate가 나왔다: {rate:?}");
        }
    }

    /// 테스트 헬퍼 — 이름으로 point를 찾아 Int 값을 꺼낸다(없으면 None). 타입이 다르면 패닉:
    /// 값의 크기는 환경에 달렸지만 **어떤 타입으로 내보내는가**는 코드가 정하는 불변식이다.
    fn int_of(points: &[MetricPoint], name: &str) -> Option<i64> {
        points
            .iter()
            .find(|p| p.name == name)
            .map(|p| match p.value {
                MetricValue::Int(v) => v,
                MetricValue::Double(_) => panic!("{name}은 Int여야 함"),
            })
    }

    /// 테스트 헬퍼 — 이름으로 point를 찾아 Double 값을 꺼낸다(없으면 None).
    fn double_of(points: &[MetricPoint], name: &str) -> Option<f64> {
        points
            .iter()
            .find(|p| p.name == name)
            .map(|p| match p.value {
                MetricValue::Double(v) => v,
                MetricValue::Int(_) => panic!("{name}은 Double이어야 함"),
            })
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_compressor_points_hold_their_invariants() {
        // 이 테스트는 **이 머신이 지금 압축을 쓰고 있는지**를 묻지 않는다 — `compressed == 0`은
        // 완전히 정상이다(막 부팅했거나 메모리가 넉넉한 머신, CI 컨테이너). 특정 머신의 우연한
        // 상태를 요구하면 테스트가 flaky해진다. 대신 코드가 **항상** 지켜야 하는 불변식만 본다.
        let mut state = HostExtraState::new();
        let points = collect(&mut state);

        // (1) macOS에서 host_statistics64가 성공하면 compressed point는 값과 무관하게 존재한다
        //     (0도 "측정했더니 0"이라는 유효한 값이므로 생략하지 않는다).
        let Some(compressed) = int_of(&points, "aic.system.memory.compressed") else {
            // host_statistics64/hw.pagesize 실패(권한 등) — 그 경우 compressor 3종 전체가 생략되며
            // 그것 또한 명세된 동작이다. 그러면 ratio/rate도 함께 없어야 한다.
            assert!(
                double_of(&points, "aic.system.memory.compression_ratio").is_none(),
                "compressed 없이 ratio만 있을 수 없다"
            );
            return;
        };
        assert!(compressed >= 0, "compressed가 음수: {compressed}");

        // (2) ratio는 compressed > 0일 때만 존재한다(compressor_page_count == 0이면 0으로 나누지
        //     않고 생략). 존재한다면 >= 1.0 — 압축 전 논리 크기가 압축 후 물리 크기보다 작을 수 없다.
        let ratio = double_of(&points, "aic.system.memory.compression_ratio");
        if compressed > 0 {
            let r = ratio.expect("compressed > 0이면 ratio가 있어야 함");
            assert!(r >= 1.0, "compression_ratio가 1.0 미만: {r}");
        } else {
            assert!(
                ratio.is_none(),
                "compressed == 0이면 ratio를 생략해야 함(0으로 나누기 방지): {ratio:?}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_fd_points_hold_their_invariants() {
        // `kern.num_files`는 매 순간 변하는 동적 값이라, 별도 sysctl 호출과 정확 비교하면 두 호출
        // 사이에 fd가 열리고 닫히며 race로 깨진다. 그래서 count는 불변식(0 < count <= limit)만
        // 검증하고, 안정적인 limit(`kern.maxfiles`)만 정확 비교한다.
        let mut state = HostExtraState::new();
        let points = collect(&mut state);

        let Some(count) = int_of(&points, "aic.system.file_descriptor.count") else {
            return; // sysctl 실패 — point 생략이 명세된 동작.
        };
        // 테스트 바이너리 자신이 fd를 열고 있으므로 최소 1개는 항상 있다.
        assert!(count > 0, "fd count가 0 이하: {count}");

        if let Some(limit) = int_of(&points, "aic.system.file_descriptor.limit") {
            assert!(limit > 0, "fd limit이 0 이하: {limit}");
            assert!(count <= limit, "fd count({count})가 limit({limit})을 초과");
            // limit(kern.maxfiles)은 부팅 후 사실상 고정이라 정확 비교가 안전하다.
            let expected = sysctl_u64("kern.maxfiles").expect("kern.maxfiles sysctl 실패");
            assert_eq!(limit as u64, expected, "limit이 kern.maxfiles와 불일치");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pressure_level_is_read_as_a_positive_int() {
        // 알려진 레벨은 1(normal)/2(warn)/4(critical)이지만, **화이트리스트로 단언하지 않는다**:
        // 그건 우리 코드가 아니라 커널의 사실을 단언하는 것이라, 커널이 레벨을 추가하면 코드가
        // 멀쩡한데도 테스트가 깨진다(테스트 실패는 "코드가 틀렸다"여야 한다). 수집 코드도 같은
        // 이유로 모르는 값을 뭉개거나 버리지 않고 그대로 통과시킨다 — 해석은 수신측 몫이다.
        //
        // 대신 우리 코드의 불변식을 본다: (a) Int로 낸다(int_of가 타입 위반 시 패닉),
        // (b) 값이 양수다 — sysctl_u64의 8바이트 버퍼로 4바이트 OID를 읽는 트릭이 깨지면
        // 0이나 쓰레기값이 나오므로, 이건 실제로 우리 코드를 검증한다.
        let mut state = HostExtraState::new();
        let points = collect(&mut state);
        if let Some(v) = int_of(&points, "aic.system.memory.pressure.level") {
            assert!(
                v > 0,
                "pressure level이 양수가 아니다(sysctl 읽기 오류 의심): {v}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pressure_metric_is_named_level_not_bare_pressure() {
        // 이름 회귀 방지: Linux의 `.some`/`.full`(연속 비율)과 혼동되지 않도록 macOS는 `.level`
        // (이산값)로 명시한다. 통일 시도가 되돌아오면 여기서 잡힌다(모듈 상단 주석의 근거 참고).
        let mut state = HostExtraState::new();
        let points = collect(&mut state);
        let names: Vec<&str> = points.iter().map(|p| p.name).collect();
        assert!(
            !names.contains(&"aic.system.memory.pressure"),
            "`.level` 접미사 없는 이름을 내면 안 된다(Linux 연속 비율과 혼동): {names:?}"
        );
        // Linux 전용 이름이 macOS에서 새어 나오지 않는지도 함께 고정한다.
        assert!(!names.contains(&"aic.system.memory.pressure.some"));
        assert!(!names.contains(&"aic.system.memory.pressure.full"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn compressor_page_size_comes_from_the_host_port() {
        // 환산 계수는 `host_statistics64`와 **같은 host port**에서 와야 한다(Rosetta에서 hw.pagesize는
        // 4096, 커널 페이지는 16384라 compressed가 1/4로 과소보고된다 — HostPort::page_size의 실측표).
        //
        // ⚠ 이 테스트가 **증명하지 못하는 것**: 네이티브 arm64에서는 hw.pagesize도 16384라, 출처를
        // 바꿔치기해도 값이 같아 어떤 단언으로도 구분되지 않는다(실제로 mutation을 넣어 확인했다 —
        // 통과해 버린다). Rosetta를 단위 테스트에서 재현하는 건 flaky한 환경 테스트가 되므로 하지
        // 않는다. 그래서 되돌림 방지는 **타입**이 맡는다: KernelPageSize는 mach_host 모듈 안에서만
        // 생성 가능하고 유일한 생산자가 HostPort::page_size라, sysctl로 되돌리면 **컴파일이 깨진다**.
        // 이 테스트는 그 타입 규칙 위에서 값이 온전한지(양수·2의 거듭제곱)만 확인하는 보조 장치다.
        let Some(stats) = vm_compressor_stats() else {
            return; // 수집 불가 환경 — 검증할 것이 없다.
        };
        let from_port = HostPort::acquire()
            .page_size()
            .expect("host port가 page size를 줘야 함");
        assert_eq!(
            stats.page_size, from_port,
            "환산 계수가 host port 값과 다르다"
        );
        // 페이지 크기는 2의 거듭제곱이어야 한다(4096/16384 등).
        assert!(
            stats.page_size.get().is_power_of_two(),
            "page size가 2의 거듭제곱이 아니다: {}",
            stats.page_size.get()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_port_send_right_is_not_leaked() {
        // 회귀 방지(high): `mach_host_self()`는 호출마다 send right의 user reference를 올린다.
        // RAII 가드(HostPort)가 Drop에서 반납하지 않으면 uref가 호출 횟수만큼 단조 증가하고,
        // 60초 주기의 상주 데몬(aicd)에서 무한히 샌다. uref를 직접 읽어 그 불변식을 검증한다.
        extern "C" {
            fn mach_port_get_refs(
                task: libc::mach_port_t,
                name: libc::mach_port_t,
                right: u32,
                refs: *mut u32,
            ) -> libc::kern_return_t;
        }
        const MACH_PORT_RIGHT_SEND: u32 = 0;

        #[allow(deprecated)]
        fn send_refs() -> Option<u32> {
            // 측정 자체를 위해 얻은 포트도 가드로 감싸 즉시 반납한다(측정이 측정을 오염시키지 않게).
            let port = HostPort::acquire();
            let mut refs: u32 = 0;
            let rc = unsafe {
                mach_port_get_refs(
                    libc::mach_task_self(),
                    port.as_raw(),
                    MACH_PORT_RIGHT_SEND,
                    &mut refs,
                )
            };
            (rc == libc::KERN_SUCCESS).then_some(refs)
        }

        let Some(before) = send_refs() else {
            return; // uref를 읽을 수 없는 환경 — 검증 불가이므로 조용히 통과(패닉 금지).
        };

        // 누수가 있으면 uref가 호출 횟수(N)만큼 늘어난다. N을 크게 잡아 "호출 수에 비례해 증가"를
        // 노이즈와 확실히 구분한다.
        const N: usize = 200;
        for _ in 0..N {
            let _ = vm_compressor_stats();
        }

        let Some(after) = send_refs() else { return };

        // 정확 일치를 요구하지 않는 이유: 이 테스트 바이너리의 다른 테스트가 **병렬 스레드**에서
        // sysinfo `System::new()`를 만들면 host port uref가 영구적으로 +1씩 늘어난다(sysinfo는
        // 한 번 얻어 들고 있는 설계라 정상 동작이다). 그 노이즈는 많아야 수 개인 반면, 누수는
        // +200이므로 넉넉한 허용치로도 확실히 갈린다. 검증하는 불변식은 "uref 증가가 호출 횟수에
        // 비례하지 않는다"이다.
        const TOLERANCE: u32 = 20;
        let grew = after.saturating_sub(before);
        assert!(
            grew <= TOLERANCE,
            "host port send right 누수: {N}회 호출에 uref가 {before} → {after} (+{grew})로 증가. \
             HostPort의 Drop(mach_port_deallocate)이 빠졌는지 확인해라."
        );
    }

    #[test]
    fn compressor_points_omits_ratio_when_nothing_is_compressed() {
        // 압축 미사용(compressor_page_count == 0)은 **정상 상태**다 — 방금 부팅했거나 메모리가
        // 넉넉한 머신, CI 컨테이너가 여기 해당한다. 개발 머신에서는 재현할 수 없어 픽스처로 검증한다.
        let points = compressor_points(0, 0, 16384, None);
        // compressed는 0이어도 낸다 — 0은 "측정했더니 0"이라는 유효한 값이다(생략은 "모른다"는 뜻).
        assert_eq!(int_of(&points, "aic.system.memory.compressed"), Some(0));
        // ratio는 생략한다 — 0으로 나누지 않고, 압축된 게 없을 때의 압축률은 무의미하다.
        assert_eq!(
            double_of(&points, "aic.system.memory.compression_ratio"),
            None,
            "compressed == 0이면 ratio를 생략해야 함"
        );
    }

    #[test]
    fn compressor_points_computes_bytes_and_ratio() {
        // 압축 활성: 2 페이지가 압축돼 있고, 압축 전 논리 크기로는 5 페이지였다 → ratio 2.5.
        // 16 KiB 페이지 × 2 = 32768 By.
        let points = compressor_points(2, 5, 16384, Some(12.5));
        assert_eq!(int_of(&points, "aic.system.memory.compressed"), Some(32768));
        assert_eq!(
            double_of(&points, "aic.system.memory.compression_ratio"),
            Some(2.5)
        );
        assert_eq!(
            double_of(&points, "aic.system.memory.decompression_rate"),
            Some(12.5)
        );
    }

    #[test]
    fn compressor_points_ratio_is_at_least_one_by_definition() {
        // 압축 후 물리 페이지 수 <= 압축 전 논리 페이지 수이므로 ratio는 항상 1.0 이상이다.
        // (1.0 = 전혀 압축되지 않은 페이지들 — 압축이 이득을 못 본 경우로, 유효한 값이다.)
        let points = compressor_points(4, 4, 16384, None);
        assert_eq!(
            double_of(&points, "aic.system.memory.compression_ratio"),
            Some(1.0)
        );
    }

    #[test]
    fn compressor_points_omits_rate_without_baseline() {
        // 첫 sample: 직전 값이 없어 delta를 못 내므로 rate를 생략한다(0으로 보내지 않는다 —
        // 0은 "decompression이 실제로 0회"라는 뜻이어야 한다).
        let points = compressor_points(2, 5, 16384, None);
        assert_eq!(
            double_of(&points, "aic.system.memory.decompression_rate"),
            None
        );
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
        // `/proc/sys/fs/file-nr`은 **Linux 전용**이다(macOS는 sysctl kern.num_files를 쓴다).
        // 첫 픽스처는 jw-server 실측값 — max가 2^63-1(사실상 무제한)이라 utilization을 내면
        // 비율이 2e-16이 되어 임계에 영원히 안 걸린다. 이게 count/limit raw만 보내는 이유다
        // (collect_fd doc 참고). 두 번째는 max가 현실적인 값으로 설정된 커널.
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
