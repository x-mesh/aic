//! PTY spawn 및 I/O relay 통합 테스트
//!
//! PtyManager로 셸 실행 → 명령어 입력 → 출력 캡처 검증
//!
//! Requirements: 1.1, 1.2, 1.3
//!
//! NOTE: PTY 테스트는 실제 터미널이 필요하므로 CI에서 불안정할 수 있다.
//! `#[ignore]` 속성을 사용하여 기본 테스트에서 제외한다.

use aic_server::pty_manager::PtyManager;
use std::io::Read;

#[test]
#[ignore]
fn pty_spawn_shell_and_echo() {
    // 셸을 PTY로 실행
    let mut pty = PtyManager::spawn_shell(24, 80, "test0001").expect("PTY 셸 실행 실패");
    let mut reader = pty.take_reader().expect("PTY reader 획득 실패");

    // "echo hello" 명령어 전송 후 exit
    pty.write_input(b"echo hello\n").expect("PTY 입력 실패");
    pty.write_input(b"exit\n").expect("PTY exit 입력 실패");

    // 출력 읽기 (타임아웃 방지를 위해 제한된 크기만 읽음)
    let mut output = vec![0u8; 4096];
    let mut total_read = 0;

    // 최대 2초 동안 출력 수집
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(2) {
        match reader.read(&mut output[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => break,
        }
        if total_read >= output.len() {
            break;
        }
    }

    let output_str = String::from_utf8_lossy(&output[..total_read]);
    assert!(
        output_str.contains("hello"),
        "출력에 'hello'가 포함되어야 합니다. 실제 출력: {}",
        output_str
    );
}

#[test]
#[ignore]
fn pty_resize_does_not_panic() {
    let pty = PtyManager::spawn_shell(24, 80, "test0002").expect("PTY 셸 실행 실패");

    // 크기 변경이 에러 없이 완료되어야 함
    pty.resize(40, 120).expect("PTY 크기 변경 실패");
    pty.resize(24, 80).expect("PTY 크기 복원 실패");
}

#[test]
#[ignore]
fn pty_wait_for_exit_returns_status() {
    let mut pty = PtyManager::spawn_shell(24, 80, "test0003").expect("PTY 셸 실행 실패");

    // 즉시 종료하는 명령어 전송
    pty.write_input(b"exit 0\n").expect("PTY exit 입력 실패");

    let status = pty.wait_for_exit().expect("종료 대기 실패");
    assert!(status.is_some(), "ExitStatus가 반환되어야 합니다");
}
