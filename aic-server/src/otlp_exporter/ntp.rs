//! 로컬 커널 clock discipline에서 NTP offset을 읽는다 (SRE t7).
//!
//! **네트워크로 NTP 서버에 질의하지 않는다.** Linux 커널은 `adjtimex(2)`(glibc `ntp_adjtime`)
//! syscall로, 로컬에서 이미 돌고 있는 NTP 클라이언트(chronyd/systemd-timesyncd/ntpd)가 커널
//! PLL(phase-locked loop)에 적용해 둔 clock offset 추정치를 그대로 보고한다. 이건 우리가 직접
//! 패킷을 보내는 게 아니라 커널이 이미 알고 있는 값을 읽기만 하는 것이라 "sntp 질의"에 해당하지
//! 않는다(`node_exporter`의 `ntp` collector 등 여러 모니터링 에이전트가 쓰는 표준 기법과 동일).
//!
//! macOS를 포함한 비-Linux 플랫폼에는 이만큼 간단하고 안전한 no-network local API가 없어
//! **의도적으로 생략**한다(과설계 금지) — `ntp_offset_ms()`가 `None`을 반환하면 host metrics에서
//! 해당 point 자체가 빠질 뿐, 나머지 host metrics 전송에는 영향이 없다.
//!
//! syscall 자체(Linux 전용)는 이 저장소가 개발되는 macOS 환경에서 컴파일 타겟이 아니라 여기서
//! 직접 컴파일 검증할 수 없다 — 실제 Linux CI에서 한 번 더 확인이 필요하다. 대신 상태 해석
//! 로직(`interpret`)은 순수 함수로 분리해 플랫폼 무관하게 단위 테스트한다.

/// `ntp_adjtime`/`adjtimex`가 kernel time state로 보고하는 status 코드. 값은 `<sys/timex.h>`와
/// 동일하다: `TIME_ERROR`(5)는 커널이 clock을 아직 sync 못 했다고 보는 상태(리턴값이 -1일 때와
/// 별개로, 정상 syscall 리턴이어도 이 상태면 offset을 신뢰할 수 없다).
///
/// non-Linux 빌드에서는 실제 호출부(`ntp_offset_ms`)가 스텁이라 이 상수/아래 `interpret`가 테스트
/// 밖에서 안 쓰인다 — 그래서 `dead_code`를 이 플랫폼에서만 허용한다(Linux 빌드는 실제로 쓰이므로
/// 경고가 그대로 살아있어 진짜 dead code는 계속 잡힌다).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const TIME_ERROR: i32 = 5;

/// syscall이 성공(ret >= 0)했을 때의 상태값과 raw offset(마이크로초)을 해석해 신뢰 가능한 offset을
/// 밀리초로 변환한다. `ret < 0`(syscall 실패, 보통 권한/미지원)이거나 `ret == TIME_ERROR`(커널이
/// unsync로 보고)면 신뢰할 수 없으므로 `None`. 순수 함수라 실제 syscall 없이 테스트 가능하다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn interpret(ret: i32, offset_usec: i64) -> Option<f64> {
    if ret < 0 || ret == TIME_ERROR {
        return None;
    }
    Some(offset_usec as f64 / 1000.0)
}

/// 현재 커널이 보고하는 NTP offset(ms). 측정 불가(비-Linux, syscall 실패, 커널 unsync)면 `None` —
/// 호출부(host_metrics)는 `None`이면 해당 metric point를 그냥 생략한다.
#[cfg(target_os = "linux")]
pub(super) fn ntp_offset_ms() -> Option<f64> {
    // `modes = 0`(전체 구조체를 0으로 초기화)이면 adjtimex는 커널 clock 파라미터를 **변경하지
    // 않고 조회만** 한다 — 이 함수가 부작용 없는 순수 read임을 보장하는 핵심 불변식이다.
    let mut buf: libc::timex = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ntp_adjtime(&mut buf) };
    interpret(ret, buf.offset as i64)
}

/// macOS 등 비-Linux는 안전한 no-network local API가 없어 생략한다(모듈 doc 참조).
#[cfg(not(target_os = "linux"))]
pub(super) fn ntp_offset_ms() -> Option<f64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpret_returns_none_on_syscall_failure() {
        assert_eq!(interpret(-1, 1234), None);
    }

    #[test]
    fn interpret_returns_none_when_kernel_reports_unsynced() {
        assert_eq!(interpret(TIME_ERROR, 1234), None);
    }

    #[test]
    fn interpret_converts_microseconds_to_milliseconds_when_synced() {
        // TIME_OK == 0.
        assert_eq!(interpret(0, 2_500), Some(2.5));
        // 다른 정상 상태 코드(TIME_INS==1 등)도 TIME_ERROR가 아니면 신뢰한다.
        assert_eq!(interpret(1, -1_000), Some(-1.0));
    }

    #[test]
    fn interpret_handles_zero_offset() {
        assert_eq!(interpret(0, 0), Some(0.0));
    }

    // 실제 syscall 스모크 테스트는 target_os="linux"에서만 의미가 있다 — 이 값은 CI 실행
    // 커널 상태에 따라 Some/None 둘 다 유효하므로 값 자체를 assert하지 않고 패닉만 확인한다.
    #[cfg(target_os = "linux")]
    #[test]
    fn ntp_offset_ms_does_not_panic_on_linux() {
        let _ = ntp_offset_ms();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn ntp_offset_ms_is_none_on_non_linux() {
        assert_eq!(ntp_offset_ms(), None);
    }
}
