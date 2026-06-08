//! 데몬 단일 인스턴스 보장.
//!
//! `fcntl(F_SETLK)` advisory write lock + PID file 패턴을 사용한다.
//! 이미 lock을 잡은 프로세스가 살아있으면 즉시 실패하고, stale PID file은 자동 정리한다.
//!
//! 디자인:
//! - lock 파일에 PID + start_time을 기록
//! - `Drop` 시 자동으로 lock 해제 + 파일 unlink
//! - macOS/Linux 모두 동작 (POSIX fcntl)

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// 데몬 PID lock 핸들. drop 시 자동으로 lock 해제 + 파일 제거.
pub struct DaemonLock {
    file: File,
    path: PathBuf,
}

impl DaemonLock {
    /// PID lock 파일을 생성하고 advisory write lock을 획득한다.
    ///
    /// 동작:
    /// 1. 부모 디렉토리 자동 생성
    /// 2. lock 파일을 open (없으면 create)
    /// 3. `fcntl(F_SETLK)`로 write lock 시도
    /// 4. 실패 시 기존 PID 읽어 살아있는지 확인 (`kill -0`)
    ///    - 살아있으면 에러 반환
    ///    - 죽은(stale) 프로세스이면 lock 파일 삭제 후 재시도 (1회)
    /// 5. lock 획득 성공 시 PID를 파일에 기록
    pub fn acquire(path: impl Into<PathBuf>) -> Result<Self> {
        Self::acquire_inner(path.into(), 1)
    }

    fn acquire_inner(path: PathBuf, retries_left: u32) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("락 디렉토리 생성 실패: {}", parent.display()))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("PID lock 파일 열기 실패: {}", path.display()))?;

        match try_write_lock(&file) {
            Ok(()) => {
                // lock 획득 — PID + exe path 기록
                write_pid_and_path(&file, std::process::id())
                    .with_context(|| format!("PID 파일 쓰기 실패: {}", path.display()))?;
                Ok(Self { file, path })
            }
            Err(_) => {
                // 다른 프로세스가 lock을 잡고 있음 — stale 여부 검사
                let mut content = String::new();
                let _ = (&file).read_to_string(&mut content);
                let (pid, recorded_path) = parse_pid_and_path(&content);

                drop(file);

                match pid {
                    Some(pid) if is_pid_alive(pid, recorded_path.as_deref()) => {
                        bail!(
                            "이미 실행 중인 aic-session이 있습니다 (PID {pid}). \
                             단일 인스턴스만 허용됩니다."
                        );
                    }
                    _ => {
                        if retries_left == 0 {
                            bail!(
                                "PID 락이 잠겨있지만 stale 정리 후에도 락을 획득할 수 없습니다: {}",
                                path.display()
                            );
                        }
                        // stale — 파일 삭제 후 재시도
                        let _ = std::fs::remove_file(&path);
                        Self::acquire_inner(path, retries_left - 1)
                    }
                }
            }
        }
    }

    /// 잠긴 lock 파일의 경로.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        // lock은 파일 close 시 자동 해제되지만 명시적 unlock으로 race 줄임
        let _ = unlock(&self.file);
        // C1 fix: unlink는 의도적으로 생략한다.
        // 시퀀스 race — A unlock → B acquire(새 파일 inode) → A unlink가 B의 파일을
        // 지워 단일 인스턴스 보장이 깨질 수 있음. stale 파일은 다음 acquire 시
        // `kill(pid, 0) == ESRCH` 검사로 자동 정리되므로 안전하다.
    }
}

// ── 내부 ────────────────────────────────────────────────────────

fn try_write_lock(file: &File) -> std::io::Result<()> {
    let fd = file.as_raw_fd();
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = 0;
    fl.l_len = 0; // whole file
    let r = unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn unlock(file: &File) -> std::io::Result<()> {
    let fd = file.as_raw_fd();
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_UNLCK as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = 0;
    fl.l_len = 0;
    let r = unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_pid_and_path(file: &File, pid: u32) -> std::io::Result<()> {
    let path = current_exe_path().unwrap_or_default();
    let bytes = format!("{pid}\n{path}\n").into_bytes();
    let fd = file.as_raw_fd();
    // 기존 내용 truncate
    let r = unsafe { libc::ftruncate(fd, 0) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    file.write_all_at(&bytes, 0)?;
    Ok(())
}

fn parse_pid_and_path(content: &str) -> (Option<u32>, Option<String>) {
    let mut lines = content.lines();
    let pid = lines.next().and_then(|s| s.trim().parse::<u32>().ok());
    let path = lines
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    (pid, path)
}

/// PID가 살아있고 (path 정보가 있으면) 같은 exe 인지 확인.
/// path mismatch면 PID recycling으로 간주 stale 처리.
fn is_pid_alive(pid: u32, expected_path: Option<&str>) -> bool {
    if pid == 0 {
        return false;
    }
    let r = unsafe { libc::kill(pid as i32, 0) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        return err.raw_os_error() != Some(libc::ESRCH);
    }
    // PID 살아있음 — exe path 비교 (PID recycling 방어)
    if let Some(expected) = expected_path {
        if let Some(actual) = process_exe_path(pid) {
            if !exe_path_matches(expected, &actual) {
                return false; // PID recycling — stale
            }
        }
    }
    true
}

/// 기록된 exe 경로(`expected`)와 실제 `/proc/<pid>/exe` 경로(`actual`)가 같은 바이너리를
/// 가리키는지 판정한다.
///
/// Linux 에서 데몬 실행 중에 바이너리를 in-place 로 교체(업그레이드)하면 `/proc/<pid>/exe`
/// 의 readlink 결과가 `"<path> (deleted)"` 가 된다. 같은 데몬이 그대로 살아있는 것이므로
/// 이 suffix 를 떼고 비교한다 — 안 그러면 살아있는 aicd 를 stale(PID recycling)로 오판해
/// 단일 인스턴스 보장이 깨지고, 업그레이드할 때마다 중복 aicd 가 떠 버린다. (PID 가 정말로
/// 재활용돼 다른 바이너리가 들어선 경우는 경로 자체가 달라 여전히 mismatch 로 걸린다.)
fn exe_path_matches(expected: &str, actual: &str) -> bool {
    let actual = actual.strip_suffix(" (deleted)").unwrap_or(actual);
    actual == expected
}

fn current_exe_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

#[cfg(target_os = "macos")]
pub(crate) fn process_exe_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let r = unsafe {
        libc::proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if r > 0 {
        buf.truncate(r as usize);
        String::from_utf8(buf).ok()
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn process_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn process_exe_path(_pid: u32) -> Option<String> {
    None
}

// ── Stale 세션 정리 ─────────────────────────────────────────────

/// Session_Dir 내의 stale 소켓/PID 파일을 정리한다.
///
/// 동작:
/// 1. `session_dir()` 내 `session-*.sock` 파일을 스캔
/// 2. 각 소켓에 `UnixStream::connect` 시도 → 실패 시 소켓 파일 삭제
/// 3. 대응하는 `session-*.pid` 파일이 있으면 PID를 읽어 프로세스 존재 여부 확인 후 삭제
/// 4. 권한 오류 시 경고 로그 후 계속 진행
///
/// Requirements: 6.3, 6.4
pub fn cleanup_stale_sessions() {
    cleanup_stale_sessions_in(&aic_common::session_dir());
}

/// `cleanup_stale_sessions()`의 디렉토리 주입 가능 변형. 테스트에서 tempdir 격리에 사용.
pub fn cleanup_stale_sessions_in(dir: &Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(path = %dir.display(), error = %e, "세션 디렉토리 읽기 실패, stale 정리 건너뜀");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // session-*.sock 파일만 대상
        if !file_name.starts_with("session-") || !file_name.ends_with(".sock") {
            continue;
        }

        // 소켓에 connect 시도 — 성공하면 활성 세션 (즉시 정상 종료하여 early eof 방지)
        if let Ok(stream) = std::os::unix::net::UnixStream::connect(&path) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            continue;
        }

        // connect 실패 → stale 소켓 삭제
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!(path = %path.display(), "stale 소켓 파일 삭제"),
            Err(e) if is_permission_error(&e) => {
                tracing::warn!(path = %path.display(), error = %e, "stale 소켓 삭제 권한 오류, 건너뜀");
                continue;
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "stale 소켓 삭제 실패");
            }
        }

        // 대응하는 .pid 파일 정리
        let pid_path = path.with_extension("pid");
        cleanup_stale_pid_file(&pid_path);
    }
}

/// PID 파일을 읽어 프로세스가 살아있지 않으면 삭제한다.
fn cleanup_stale_pid_file(pid_path: &Path) {
    if !pid_path.exists() {
        return;
    }

    let content = match std::fs::read_to_string(pid_path) {
        Ok(c) => c,
        Err(e) if is_permission_error(&e) => {
            tracing::warn!(path = %pid_path.display(), error = %e, "stale PID 파일 읽기 권한 오류, 건너뜀");
            return;
        }
        Err(_) => {
            // 읽기 실패 — 삭제 시도
            remove_file_with_warn(pid_path);
            return;
        }
    };

    let (pid, recorded_path) = parse_pid_and_path(&content);

    // PID가 살아있으면 건드리지 않음
    if let Some(pid) = pid {
        if is_pid_alive(pid, recorded_path.as_deref()) {
            return;
        }
    }

    remove_file_with_warn(pid_path);
}

fn remove_file_with_warn(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!(path = %path.display(), "stale PID 파일 삭제"),
        Err(e) if is_permission_error(&e) => {
            tracing::warn!(path = %path.display(), error = %e, "stale PID 파일 삭제 권한 오류, 건너뜀");
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "stale PID 파일 삭제 실패");
        }
    }
}

fn is_permission_error(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_creates_lock_file_with_pid_and_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        let _lock = DaemonLock::acquire(&path).expect("acquire 실패");
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        let (pid, exe_path) = parse_pid_and_path(&content);
        assert_eq!(pid, Some(std::process::id()));
        // exe path가 기록되었는지 (현재 process의 exe)
        assert!(exe_path.is_some(), "exe path가 기록되어야 함");
    }

    #[test]
    fn drop_keeps_lock_file_to_avoid_race() {
        // C1 fix: drop은 의도적으로 unlink하지 않는다 (다른 프로세스의 새 lock 파일을
        // 지우는 race 회피). stale 파일은 다음 acquire 시 PID 검사로 정리된다.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        {
            let _lock = DaemonLock::acquire(&path).unwrap();
            assert!(path.exists());
        }
        // drop 후에도 file 존재 — race 방지가 의도
        assert!(path.exists());
    }

    #[test]
    fn acquire_creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/sub/test.pid");
        let _lock = DaemonLock::acquire(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn parse_pid_and_path_handles_various_formats() {
        assert_eq!(parse_pid_and_path("12345"), (Some(12345), None));
        assert_eq!(parse_pid_and_path("12345\n"), (Some(12345), None));
        assert_eq!(parse_pid_and_path("  9999  \n"), (Some(9999), None));
        assert_eq!(
            parse_pid_and_path("12345\n/usr/local/bin/aic-session\n"),
            (Some(12345), Some("/usr/local/bin/aic-session".to_string()))
        );
        assert_eq!(parse_pid_and_path(""), (None, None));
        assert_eq!(parse_pid_and_path("invalid"), (None, None));
    }

    #[test]
    fn is_pid_alive_self_returns_true() {
        let pid = std::process::id();
        // path None: kill(pid, 0)만으로 alive 판정
        assert!(is_pid_alive(pid, None));
    }

    #[test]
    fn is_pid_alive_zero_returns_false() {
        assert!(!is_pid_alive(0, None));
    }

    #[test]
    fn is_pid_alive_unlikely_pid_returns_false() {
        // PID_MAX 근처는 거의 사용 불가. 죽은 PID로 간주.
        assert!(!is_pid_alive(0x7FFF_FFFE, None));
    }

    #[test]
    fn is_pid_alive_with_wrong_path_returns_false() {
        // PID는 살아있지만 exe path가 다르면 PID recycling으로 간주 → stale
        let pid = std::process::id();
        assert!(!is_pid_alive(pid, Some("/totally/wrong/path/binary")));
    }

    #[test]
    fn exe_path_matches_handles_in_place_upgrade() {
        // 동일 경로 → 일치
        assert!(exe_path_matches("/usr/local/bin/aicd", "/usr/local/bin/aicd"));
        // Linux in-place 업그레이드: /proc/<pid>/exe 가 "(deleted)" suffix 를 단다.
        // 같은 데몬이므로 일치로 봐야 한다 (이게 핵심 — 중복 aicd 방지).
        assert!(exe_path_matches(
            "/usr/local/bin/aicd",
            "/usr/local/bin/aicd (deleted)"
        ));
        // 진짜 PID recycling: 다른 바이너리는 suffix 유무와 무관하게 mismatch.
        assert!(!exe_path_matches("/usr/local/bin/aicd", "/usr/bin/python3"));
        assert!(!exe_path_matches(
            "/usr/local/bin/aicd",
            "/usr/bin/python3 (deleted)"
        ));
    }

    #[test]
    fn stale_lock_file_is_recovered() {
        // 죽은 PID(자기 자신은 아니지만 프로세스가 없는 PID) 시뮬레이션:
        // 파일에 0x7FFF_FFFE를 PID로 적어두면 stale로 인식되어 정리되어야 함.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");

        std::fs::write(&path, "2147483646\n").unwrap();
        // 락 파일은 있지만 lock이 잠긴 상태는 아님
        // 새로 acquire 호출 시 try_lock이 즉시 성공해 PID + path 덮어쓰기
        let _lock = DaemonLock::acquire(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let (pid, _) = parse_pid_and_path(&content);
        assert_eq!(pid, Some(std::process::id()));
    }

    // ── cleanup_stale_pid_file tests ───────────────────────────

    #[test]
    fn cleanup_stale_pid_file_removes_dead_pid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("session-abc123.pid");
        // 존재하지 않는 PID 기록
        std::fs::write(&pid_path, "2147483646\n").unwrap();
        assert!(pid_path.exists());

        cleanup_stale_pid_file(&pid_path);
        assert!(!pid_path.exists(), "죽은 PID의 파일은 삭제되어야 함");
    }

    #[test]
    fn cleanup_stale_pid_file_keeps_alive_pid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("session-abc123.pid");
        // 현재 프로세스 PID 기록 (살아있음)
        std::fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();
        assert!(pid_path.exists());

        cleanup_stale_pid_file(&pid_path);
        assert!(pid_path.exists(), "살아있는 PID의 파일은 유지되어야 함");
    }

    #[test]
    fn cleanup_stale_pid_file_noop_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("nonexistent.pid");
        // 존재하지 않는 파일 — panic 없이 정상 반환
        cleanup_stale_pid_file(&pid_path);
    }

    #[test]
    fn cleanup_stale_pid_file_removes_empty_content() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("session-empty.pid");
        std::fs::write(&pid_path, "").unwrap();

        cleanup_stale_pid_file(&pid_path);
        assert!(!pid_path.exists(), "빈 PID 파일은 삭제되어야 함");
    }

    #[test]
    fn is_permission_error_detects_correctly() {
        let perm_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test");
        assert!(is_permission_error(&perm_err));

        let other_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        assert!(!is_permission_error(&other_err));
    }
}
