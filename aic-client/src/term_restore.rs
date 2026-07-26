//! 전면 TUI(alternate screen + raw mode) 진입 프로그램이 **비정상 종료**될 때 터미널을 되돌리는
//! 공용 가드. `chat_tui`(전면 채팅 TUI)와 `top`(라이브 metric 모니터)이 공유한다.
//!
//! 정상 종료는 각 TUI의 teardown이, 패닉은 여기 설치한 패닉 훅이, 외부 시그널
//! (SIGINT/SIGTERM/SIGHUP/SIGQUIT)은 시그널 핸들러가 책임진다. 세 경로 중 하나라도 비면
//! 터미널이 raw인 채 셸로 돌아간다.
//!
//! # raw mode를 반드시 되돌려야 하는 이유
//!
//! crossterm의 `enable_raw_mode()`는 `cfmakeraw()`와 같은 세트를 적용하는데, 여기엔 **`OPOST`
//! 해제**가 들어 있다. `OPOST`가 꺼지면 커널의 출력 후처리가 통째로 멈춰 `\n`에 CR이 붙지 않는다
//! (`ONLCR` 비트가 켜져 있어도 `OPOST`가 없으면 무시된다). 그 상태로 프로세스가 죽으면 termios는
//! 커널이 원복해 주지 않고 그대로 남아, 이후 실행하는 **모든** 명령의 출력이 줄마다 오른쪽으로
//! 밀리는 계단 모양이 된다:
//!
//! ```text
//! line one
//!          line two
//!                   line three
//! ```
//!
//! 셸이 알아서 고쳐 주리라 기대할 수 없다. zsh는 line editor(ZLE) 진입 시점의 termios를 저장해
//! 두었다가 외부 명령을 실행하기 직전에 그 값을 되씌운다 — 오염된 상태에서 프롬프트가 떴다면
//! 오염된 값이 저장되고, 그 뒤 모든 명령이 그 값을 물려받는다. 프롬프트와 입력만 멀쩡해 보여서
//! 원인을 찾기도 어렵다. 그러니 죽는 쪽이 나가면서 직접 되돌려야 한다.

use std::io;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Once;

use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};

/// raw mode 진입 **이전** 의 termios. 시그널 핸들러가 async-signal-safe하게 읽어 그대로 되쓴다.
/// `Box::into_raw`로 누출시킨 포인터라 핸들러 안에서 할당/해제가 일어나지 않는다(프로세스 수명
/// 내내 한 번만 채워지므로 누수도 상수 크기다).
static ORIG_TERMIOS: AtomicPtr<libc::termios> = AtomicPtr::new(std::ptr::null_mut());

/// 패닉 훅 + 시그널 핸들러 + 원본 termios 스냅샷을 1회 설치한다.
///
/// **반드시 `enable_raw_mode()` 호출 이전에** 부를 것 — 스냅샷이 raw 적용 후에 찍히면 핸들러가
/// 복원하는 값 자체가 raw라 아무 의미가 없다.
pub fn install() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        snapshot_termios();
        install_panic_hook();
        install_signal_handler();
    });
}

/// raw mode 진입 이전의 termios를 떠 둔다. 비-TTY(파이프/CI)면 `tcgetattr`가 실패하고 포인터는
/// null로 남는다 — 그 경우 핸들러는 termios 복원을 건너뛴다(되돌릴 상태가 애초에 없다).
fn snapshot_termios() {
    // SAFETY: zero 초기화한 termios를 tcgetattr로 채운다. termios는 POD라 zeroed가 유효한
    // 초기값이고, 성공(0) 했을 때만 값을 쓴다.
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) == 0 {
            ORIG_TERMIOS.store(Box::into_raw(Box::new(orig)), Ordering::Release);
        }
    }
}

/// 패닉이 나도 터미널을 복원하도록 패닉 훅을 설치한다. LeaveAlternateScreen + disable_raw_mode로
/// 원래 화면을 되돌린 뒤 기존 훅을 호출한다(panic 메시지·backtrace 유지).
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(
            io::stdout(),
            crossterm::event::DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = disable_raw_mode();
        prev(info);
    }));
}

/// 외부 SIGINT/SIGTERM/SIGHUP/SIGQUIT로 **비정상 종료**될 때도 터미널을 복원하도록 시그널
/// 핸들러를 설치한다. 패닉 훅(정상 panic)·teardown(정상 종료)은 이 경로를 못 거치므로 — 셸은
/// "terminated"만 찍고 마우스 모드/alternate screen/raw termios가 그대로 살아남는다.
///
/// raw mode에선 `ISIG`가 꺼져 Ctrl+C가 키 이벤트로 들어오므로(이 핸들러로 안 옴) 외부 kill·pane
/// close·SIGHUP에 반응한다. 반대로 raw 진입 전후의 짧은 창이나 cooked로 새어 들어온 신호에서는
/// 시퀀스가 no-op이고 termios 복원도 같은 값을 되쓰는 것이라 무해하다.
fn install_signal_handler() {
    // SAFETY: 핸들러는 async-signal-safe한 write/tcsetattr/signal/raise만 호출하고 힙 할당을
    // 하지 않는다.
    unsafe {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            libc::signal(
                sig,
                restore_terminal_on_signal as *const () as libc::sighandler_t,
            );
        }
    }
}

/// async-signal-safe 시그널 핸들러: 마우스 모드(노멀/버튼/모션/urxvt/SGR) 끄기 + 커서 표시 +
/// alternate screen 떠나기 시퀀스를 fd 1에 직접 write하고, raw 진입 이전 termios를 되쓴 뒤,
/// 디폴트 처분으로 신호를 재발생시킨다(셸 job control의 "terminated" 표기 유지).
///
/// escape 시퀀스는 상수 슬라이스만 쓰고(crossterm/alloc 미사용), `tcsetattr`는 POSIX가 보장하는
/// async-signal-safe 함수다.
extern "C" fn restore_terminal_on_signal(sig: libc::c_int) {
    const RESTORE: &[u8] =
        b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1015l\x1b[?1006l\x1b[?25h\x1b[?1049l";
    // SAFETY: 상수 바이트 슬라이스의 직접 write + 미리 떠 둔 termios의 tcsetattr — 모두
    // async-signal-safe. 반환값은 무시한다(핸들러 안에서 에러 처리 수단이 없다).
    unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            RESTORE.as_ptr() as *const libc::c_void,
            RESTORE.len(),
        );
        // termios 복원 — 모듈 문서의 "raw mode를 반드시 되돌려야 하는 이유" 참고. 이걸 빼면
        // 셸로 돌아간 뒤 모든 명령의 출력이 계단식으로 밀린다.
        let orig = ORIG_TERMIOS.load(Ordering::Acquire);
        if !orig.is_null() {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
        }
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 스냅샷이 성공하면(=TTY) 포인터가 채워지고, 실패하면(=비-TTY, 테스트 환경) null로 남아
    /// 핸들러가 termios 복원을 건너뛴다. 어느 쪽이든 install()은 패닉 없이 끝나야 한다.
    #[test]
    fn install_is_idempotent_and_safe_without_tty() {
        install();
        install();
        let p = ORIG_TERMIOS.load(Ordering::Acquire);
        // 비-TTY면 null(되돌릴 상태가 없어 스킵), TTY면 유효 포인터 — 둘 다 정상.
        if !p.is_null() {
            // SAFETY: install()이 Box::into_raw로 누출시킨 유효 포인터이고 해제되지 않는다.
            let orig = unsafe { &*p };
            // 스냅샷은 raw 진입 *이전* 이어야 뜻이 있다. raw는 OPOST를 끄므로, 켜져 있다는 건
            // 아직 오염되지 않은 상태를 떴다는 뜻이다.
            assert!(
                orig.c_oflag & libc::OPOST != 0,
                "raw가 이미 적용된 뒤 스냅샷을 떴다 — 복원해도 계단식 출력이 그대로 남는다"
            );
        }
    }

    /// 핸들러가 쓰는 복원 시퀀스는 마우스 3종·확장 2종 해제 + 커서 표시 + alternate screen
    /// 이탈을 모두 담아야 한다. 하나라도 빠지면 그 상태가 셸에 새어 나간다.
    #[test]
    fn restore_sequence_covers_every_mode_the_tui_enters() {
        const RESTORE: &[u8] =
            b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1015l\x1b[?1006l\x1b[?25h\x1b[?1049l";
        let s = std::str::from_utf8(RESTORE).unwrap();
        for seq in [
            "\x1b[?1000l", // 노멀 마우스 트래킹
            "\x1b[?1002l", // 버튼 이벤트 트래킹
            "\x1b[?1003l", // 모든 모션 트래킹
            "\x1b[?1015l", // urxvt 확장 좌표
            "\x1b[?1006l", // SGR 확장 좌표
            "\x1b[?25h",   // 커서 표시
            "\x1b[?1049l", // alternate screen 이탈
        ] {
            assert!(s.contains(seq), "복원 시퀀스에 {seq:?}가 빠졌다");
        }
    }
}
