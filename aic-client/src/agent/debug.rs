//! agent 모드 전용 debug 출력 — 기존 `AIC_DEBUG` 환경변수를 재사용한다.
//!
//! `main.rs`의 `debug_log!`는 바이너리 crate에만 있어 lib(agent)에서 못 쓰므로,
//! 동일한 `[debug +X.XXXs]` 스타일을 따르는 최소 helper를 여기 둔다.
//!
//! 원칙:
//! - 기본 실행(AIC_DEBUG 미설정)에서는 아무것도 출력하지 않는다.
//! - 출력은 stderr만 사용한다.
//! - 명령/파일 **본문이나 secret-like 값은 찍지 않는다.** 이름·길이·count만 기록한다.

use std::sync::OnceLock;
use std::time::Instant;

/// `AIC_DEBUG=1|true` 여부 (`main.rs::is_debug_mode`와 동일 규칙).
pub(crate) fn enabled() -> bool {
    std::env::var("AIC_DEBUG")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// 첫 호출 시점부터의 누적 경과 시간(초). `main.rs::debug_elapsed_secs`와 같은 패턴.
fn elapsed_secs() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// `AIC_DEBUG`일 때만 stderr에 `[debug +X.XXXs] agent: ...`를 출력한다.
/// 색상(dim)은 UI 색상 정책(NO_COLOR 미설정 && stderr TTY)을 따른다.
pub(crate) fn log(args: std::fmt::Arguments<'_>) {
    if enabled() {
        let body = format!("[debug +{:.3}s] agent: {}", elapsed_secs(), args);
        if super::ui::color_enabled() {
            eprintln!("\x1b[90m{body}\x1b[0m");
        } else {
            eprintln!("{body}");
        }
    }
}

/// `adbg!(...)` — `format!`과 동일한 인자로 agent debug 라인을 출력한다.
macro_rules! adbg {
    ($($arg:tt)*) => {
        $crate::agent::debug::log(format_args!($($arg)*))
    };
}
pub(crate) use adbg;
