//! Stale 세션 정리 통합 테스트
//!
//! 가짜 소켓/PID 파일을 생성한 뒤 `cleanup_stale_sessions()`를 호출하여
//! stale 파일이 올바르게 삭제되는지 검증한다.
//!
//! Requirements: 6.3, 6.4

use std::fs;
use std::path::PathBuf;

/// 테스트 전용 가짜 파일을 session_dir에 생성하고,
/// 테스트 종료(또는 panic) 시 자동으로 정리하는 guard.
struct TestFileGuard {
    paths: Vec<PathBuf>,
}

impl TestFileGuard {
    fn new() -> Self {
        Self { paths: Vec::new() }
    }

    fn track(&mut self, path: PathBuf) {
        self.paths.push(path);
    }
}

impl Drop for TestFileGuard {
    fn drop(&mut self) {
        for p in &self.paths {
            let _ = fs::remove_file(p);
        }
    }
}

/// 가짜 .sock 파일(일반 파일)을 생성하면 UnixStream::connect가 실패하므로
/// cleanup_stale_sessions()가 stale로 판정하여 삭제해야 한다.
/// Requirements: 6.4
#[test]
fn cleanup_removes_stale_sock_files() {
    let dir = aic_common::session_dir();
    fs::create_dir_all(&dir).expect("session_dir 생성 실패");

    let mut guard = TestFileGuard::new();

    // 테스트 전용 가짜 소켓 파일 생성 (일반 파일 — connect 실패)
    let sock_path = dir.join("session-deadbeef.sock");
    fs::write(&sock_path, "fake-socket").expect("가짜 소켓 파일 생성 실패");
    guard.track(sock_path.clone());

    assert!(sock_path.exists(), "가짜 소켓 파일이 존재해야 합니다");

    // stale 정리 실행
    aic_server::lock::cleanup_stale_sessions();

    // 가짜 소켓은 connect 실패 → 삭제되어야 함
    assert!(
        !sock_path.exists(),
        "stale 소켓 파일이 삭제되어야 합니다: {}",
        sock_path.display()
    );
}

/// 가짜 .sock + 대응하는 .pid 파일(존재하지 않는 PID)을 생성하면
/// cleanup_stale_sessions()가 둘 다 삭제해야 한다.
/// Requirements: 6.3, 6.4
#[test]
fn cleanup_removes_stale_sock_and_pid_files() {
    let dir = aic_common::session_dir();
    fs::create_dir_all(&dir).expect("session_dir 생성 실패");

    let mut guard = TestFileGuard::new();

    let sock_path = dir.join("session-fade0001.sock");
    let pid_path = dir.join("session-fade0001.pid");

    // 가짜 소켓 파일 (일반 파일)
    fs::write(&sock_path, "fake-socket").expect("가짜 소켓 파일 생성 실패");
    guard.track(sock_path.clone());

    // 가짜 PID 파일 — 존재하지 않는 PID 기록
    fs::write(&pid_path, "2147483646\n").expect("가짜 PID 파일 생성 실패");
    guard.track(pid_path.clone());

    assert!(sock_path.exists());
    assert!(pid_path.exists());

    aic_server::lock::cleanup_stale_sessions();

    assert!(!sock_path.exists(), "stale 소켓 파일이 삭제되어야 합니다");
    assert!(!pid_path.exists(), "stale PID 파일이 삭제되어야 합니다");
}

/// session-*.sock 패턴이 아닌 파일은 cleanup 대상이 아니므로 유지되어야 한다.
/// Requirements: 6.4
#[test]
fn cleanup_ignores_non_session_files() {
    let dir = aic_common::session_dir();
    fs::create_dir_all(&dir).expect("session_dir 생성 실패");

    let mut guard = TestFileGuard::new();

    // session- prefix가 없는 파일
    let other_file = dir.join("random-file.sock");
    fs::write(&other_file, "not-a-session").expect("기타 파일 생성 실패");
    guard.track(other_file.clone());

    // .sock 확장자가 아닌 파일
    let txt_file = dir.join("session-abcd1234.txt");
    fs::write(&txt_file, "not-a-socket").expect("txt 파일 생성 실패");
    guard.track(txt_file.clone());

    aic_server::lock::cleanup_stale_sessions();

    assert!(
        other_file.exists(),
        "session- prefix가 없는 파일은 유지되어야 합니다"
    );
    assert!(
        txt_file.exists(),
        ".sock 확장자가 아닌 파일은 유지되어야 합니다"
    );
}

/// 여러 stale 소켓 파일을 한꺼번에 정리할 수 있는지 검증한다.
/// Requirements: 6.3, 6.4
#[test]
fn cleanup_removes_multiple_stale_sessions() {
    let dir = aic_common::session_dir();
    fs::create_dir_all(&dir).expect("session_dir 생성 실패");

    let mut guard = TestFileGuard::new();

    let ids = ["fade0010", "fade0020", "fade0030"];
    let mut sock_paths = Vec::new();
    let mut pid_paths = Vec::new();

    for id in &ids {
        let sock = dir.join(format!("session-{}.sock", id));
        let pid = dir.join(format!("session-{}.pid", id));

        fs::write(&sock, "fake").unwrap();
        fs::write(&pid, "2147483646\n").unwrap();

        guard.track(sock.clone());
        guard.track(pid.clone());

        sock_paths.push(sock);
        pid_paths.push(pid);
    }

    aic_server::lock::cleanup_stale_sessions();

    for (i, sock) in sock_paths.iter().enumerate() {
        assert!(
            !sock.exists(),
            "stale 소켓 [{}] 이 삭제되어야 합니다: {}",
            ids[i],
            sock.display()
        );
    }
    for (i, pid) in pid_paths.iter().enumerate() {
        assert!(
            !pid.exists(),
            "stale PID [{}] 가 삭제되어야 합니다: {}",
            ids[i],
            pid.display()
        );
    }
}
