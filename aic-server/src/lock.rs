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
#[derive(Debug)]
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
            // 0700 보장 + 소유자·symlink 검사. 남이 선점한 디렉토리에 lock을 잡으면 위조
            // PID 파일 하나로 기동이 영구 차단될 수 있다.
            aic_common::ensure_runtime_dir(parent)
                .with_context(|| format!("락 디렉토리 준비 실패: {}", parent.display()))?;
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
                        // 이 lock은 aicd와 aic-session이 함께 쓴다 — 어느 쪽인지 단정하지
                        // 않는다. 종전 문구("aic-session이 있습니다")는 aicd 기동 실패에도
                        // 그대로 나와 엉뚱한 프로세스를 찾게 만들었다.
                        bail!(
                            "이미 lock을 쥔 프로세스가 있습니다 (PID {pid}, lock {}). \
                             단일 인스턴스만 허용됩니다.",
                            path.display()
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

/// 후보 경로 **전체**에 대한 aicd 단일 인스턴스 lock 묶음.
///
/// 왜 묶음인가: `XDG_RUNTIME_DIR` 유무가 갈리는 두 프로세스는 정규 lock 경로가 서로 달라
/// (`/run/user/{uid}/aic/aicd.pid` vs `/tmp/aic-{uid}/aicd.pid`) 각자 acquire에 성공한다.
/// "다른 후보에 살아 있는 데몬이 있는지 먼저 읽어 본다"는 사전 조회는 **검사와 획득 사이가
/// 원자적이지 않아** 동시 기동을 막지 못한다 — 두 프로세스가 나란히 조회를 통과한 뒤 각자
/// 다른 lock을 잡으면 exporter·registry가 이중으로 돈다.
///
/// 그래서 후보를 하나라도 남기지 않고 **전부** 잡는다. 획득 순서는 경로 문자열 정렬로
/// 고정한다 — 모든 프로세스가 같은 순서로 진입하므로 서로 다른 후보를 엇갈려 잡는 교착이
/// 생기지 않고, 먼저 도착한 쪽이 첫 후보에서 이긴다. 잡은 lock은 프로세스 수명 동안 들고
/// 있다가 drop에서 함께 풀린다.
#[derive(Debug)]
pub struct DaemonLockSet {
    /// 정렬 순서대로 획득한 lock들. drop 순서는 역순이 아니어도 무방하다(모두 advisory).
    locks: Vec<DaemonLock>,
    canonical: PathBuf,
}

impl DaemonLockSet {
    /// 정규 경로와 대체 후보 전체를 고정 순서로 획득한다.
    ///
    /// - 정규 경로는 반드시 획득해야 한다. 실패하면 그대로 에러.
    /// - 대체 후보는 **부모 디렉토리를 만들 수 없으면** 건너뛴다(예: 다른 사용자 소유의
    ///   `/run/user/{uid}`). 그 경로에는 이 프로세스가 데몬을 띄울 수도 없으므로 경합 대상이
    ///   아니다. 반대로 잡을 수 있는 후보에서 lock이 이미 잡혀 있으면 중복 기동으로 판정한다.
    pub fn acquire_all(canonical: &Path, candidates: &[PathBuf]) -> Result<Self> {
        let mut ordered: Vec<PathBuf> = candidates.to_vec();
        ordered.push(canonical.to_path_buf());
        ordered.sort();
        ordered.dedup();

        let mut locks = Vec::with_capacity(ordered.len());
        for path in ordered {
            let is_canonical = path == canonical;
            if !is_canonical && !parent_dir_is_usable(&path) {
                tracing::debug!(
                    path = %path.display(),
                    "대체 lock 후보의 디렉토리를 쓸 수 없어 건너뜀"
                );
                continue;
            }
            match DaemonLock::acquire(&path) {
                Ok(lock) => locks.push(lock),
                Err(e) if is_canonical => return Err(e),
                Err(e) => {
                    // 대체 후보가 잡혀 있다 = 이미 다른 aicd가 산다.
                    //
                    // **경로가 갈렸다고 단정하지 않는다.** 살아 있는 aicd는 후보 lock을 전부
                    // 쥐고 있으므로, 환경이 똑같은 평범한 중복 기동도 정렬상 첫 후보(대체
                    // 경로)에서 먼저 걸린다. 그 상황에 "XDG_RUNTIME_DIR이 갈렸다"고 적으면
                    // 멀쩡한 환경을 의심하게 만든다 — 실측에서 실제로 그렇게 나왔다.
                    // 갈림은 두 경로의 **디렉토리가 다를 때만** 가능성으로 덧붙인다.
                    let holder = read_lock_holder_pid(&path);
                    // **경로 갈림 판정은 부모 디렉토리 비교로는 안 된다.** 환경이 같아도
                    // 정렬상 첫 후보는 대체 경로라, 평범한 중복 기동도 "다른 디렉토리"에서
                    // 걸린다(실측). 진짜 구분점은 **우리 정규 경로도 같은 데몬이 쥐고 있는가**
                    // 다 — 쥐고 있으면 그냥 같은 환경의 중복 기동이고, 비어 있으면 그쪽
                    // 데몬은 다른 런타임 디렉토리에 산다.
                    let same_daemon_holds_canonical =
                        match (holder, read_lock_holder_pid(canonical)) {
                            (Some(a), Some(b)) => a == b,
                            _ => false,
                        };
                    let holder_label = holder
                        .map(|pid| format!("PID {pid}"))
                        .unwrap_or_else(|| "PID 불명".to_string());
                    if same_daemon_holds_canonical {
                        bail!(
                            "이미 실행 중인 aicd가 있습니다 ({holder_label}, lock {}). \
                             단일 인스턴스만 허용됩니다 — 새로 띄우려면 먼저 종료하세요: \
                             aic daemon stop",
                            canonical.display()
                        );
                    }
                    bail!(
                        "이미 실행 중인 aicd가 있습니다 ({holder_label}, lock {}). 이 \
                         프로세스는 {}에 lock을 잡으려 했습니다 — XDG_RUNTIME_DIR이 서로 \
                         달라 런타임 경로가 갈린 것으로 보입니다.\n기존 데몬을 쓰려면 그대로 \
                         두고, 새로 띄우려면 먼저 종료하세요: aic daemon stop\n(원인: {e})",
                        path.display(),
                        canonical.display()
                    );
                }
            }
        }

        Ok(Self {
            locks,
            canonical: canonical.to_path_buf(),
        })
    }

    /// 실제로 잡은 lock 경로들 (정렬 순서).
    #[allow(dead_code)]
    pub fn paths(&self) -> Vec<&Path> {
        self.locks.iter().map(|l| l.path()).collect()
    }

    /// 정규 lock 경로.
    #[allow(dead_code)]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical
    }
}

/// lock 파일에 기록된 PID — **살아 있을 때만**. 에러 메시지에 "누가 쥐고 있는지"를 넣으려고
/// 쓴다. 잔해에서 읽은 죽은 PID를 보여 주면 엉뚱한 프로세스를 찾게 되므로 생존 확인을 거친다.
fn read_lock_holder_pid(path: &Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    let (pid, recorded_path) = parse_pid_and_path(&content);
    let pid = pid?;
    is_pid_alive(pid, recorded_path.as_deref()).then_some(pid)
}

/// lock 후보의 부모 디렉토리를 이 프로세스가 안전하게 만들거나 쓸 수 있는지.
/// 남이 선점한 디렉토리(다른 소유자·0700 아님·symlink)도 여기서 걸러 후보에서 빠진다.
fn parent_dir_is_usable(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    aic_common::ensure_runtime_dir(parent).is_ok()
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

/// 정규 경로 **밖의** 후보에서 살아 있는 aicd를 찾는다. 있으면 `(lock 경로, PID)`.
///
/// lock은 정규 경로 한 곳에만 잡는다(`aicd_lock_path_for_bind`). 그래서 `XDG_RUNTIME_DIR`
/// 유무가 갈리는 두 프로세스는 서로의 lock 파일을 아예 보지 못하고, `DaemonLock::acquire`가
/// 각자 성공해 aicd가 둘 뜬다. 두 데몬이 같은 세션·spool·exporter를 두고 경합하는데
/// 어느 쪽도 에러를 내지 않아 알아채기 어렵다. 그래서 기동 전에 후보를 훑는다.
///
/// flock을 잡아 보지 않고 파일 내용만 읽는다 — 살아 있는 데몬은 이미 lock을 쥐고 있어
/// 시도해 봐야 실패하고, PID·exe 경로만으로 판정이 충분하다(`is_pid_alive`가 PID 재활용도
/// 걸러낸다). stale 파일은 무시한다.
pub fn find_live_daemon_outside(
    canonical: &Path,
    candidates: &[PathBuf],
) -> Option<(PathBuf, u32)> {
    candidates
        .iter()
        .filter(|path| path.as_path() != canonical)
        .find_map(|path| {
            let content = std::fs::read_to_string(path).ok()?;
            let (pid, recorded_path) = parse_pid_and_path(&content);
            let pid = pid?;
            is_pid_alive(pid, recorded_path.as_deref()).then(|| (path.clone(), pid))
        })
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

    // ── find_live_daemon_outside ─────────────────────────────
    //
    // 살아 있는 PID로는 이 테스트 프로세스 자신을 쓴다. lock 파일 형식은
    // `write_pid_and_path`와 같은 "PID\n exe 경로" 두 줄이다.

    fn write_lock_file(path: &Path, pid: u32, exe: Option<&str>) {
        let body = match exe {
            Some(e) => format!("{pid}\n{e}\n"),
            None => format!("{pid}\n"),
        };
        std::fs::write(path, body).unwrap();
    }

    /// 죽은 PID = 잔해. 이걸 살아있다고 오판하면 정상 기동을 영영 막는다.
    #[test]
    fn find_live_daemon_outside_ignores_stale_lock() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("canonical.pid");
        let alt = dir.path().join("alt.pid");
        write_lock_file(&alt, 4_294_967_290, None); // 존재할 수 없는 PID
        assert_eq!(
            find_live_daemon_outside(&canonical, &[canonical.clone(), alt]),
            None
        );
    }

    /// 이 테스트가 지키는 것: XDG가 갈려 다른 경로에 뜬 데몬을 찾아내는 동작.
    /// 깨지면 aicd가 중복 기동한다.
    #[test]
    fn find_live_daemon_outside_finds_live_lock_in_alt_dir() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("canonical.pid");
        let alt = dir.path().join("alt.pid");
        let me = std::process::id();
        write_lock_file(&alt, me, current_exe_path().as_deref());
        assert_eq!(
            find_live_daemon_outside(&canonical, &[canonical.clone(), alt.clone()]),
            Some((alt, me))
        );
    }

    /// 정규 경로는 건너뛴다 — 그건 `DaemonLock::acquire`가 flock으로 판정할 몫이고,
    /// 여기서 걸면 자기 자신의 잔해에 막혀 기동이 안 된다.
    #[test]
    fn find_live_daemon_outside_skips_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("canonical.pid");
        write_lock_file(
            &canonical,
            std::process::id(),
            current_exe_path().as_deref(),
        );
        assert_eq!(
            find_live_daemon_outside(&canonical, std::slice::from_ref(&canonical)),
            None
        );
    }

    // ── DaemonLockSet (동시 기동 차단) ────────────────────────
    //
    // fcntl(F_SETLK) lock은 **프로세스** 단위라, 같은 프로세스의 스레드 둘로는 배제가
    // 검증되지 않는다(둘 다 성공한다). 그래서 진짜 하위 프로세스를 띄워 "먼저 뜬 aicd"를
    // 만든다 — 테스트 바이너리 자신을 `--ignored` 헬퍼 테스트로 재실행하는 방식이다.

    /// 부모 테스트가 하위 프로세스로 실행하는 헬퍼. `AIC_TEST_HOLD_LOCK` 경로에 lock을 잡고
    /// `LOCKED`를 찍은 뒤, stdin이 닫힐 때까지(= 부모가 끝날 때까지) 들고 있는다.
    #[test]
    #[ignore = "부모 테스트가 하위 프로세스로 실행하는 헬퍼"]
    fn hold_lock_helper() {
        let Ok(paths) = std::env::var("AIC_TEST_HOLD_LOCK") else {
            return;
        };
        // `:`로 여러 경로를 받는다 — 실제 aicd는 후보 lock을 **전부** 쥐므로, 그 상황을
        // 재현해야 "정규 경로도 같은 데몬이 쥐었나" 판정을 검증할 수 있다.
        let _locks: Vec<DaemonLock> = paths
            .split(':')
            .map(|p| DaemonLock::acquire(PathBuf::from(p)).expect("헬퍼 lock 획득 실패"))
            .collect();
        println!("LOCKED");
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
    }

    /// lock을 쥔 하위 프로세스 핸들. stdout 파이프를 함께 들고 있어야 자식이 나중에 쓰는
    /// 하네스 출력이 `Broken pipe`로 깨지지 않는다.
    struct LockHolder {
        child: std::process::Child,
        _stdout: std::io::BufReader<std::process::ChildStdout>,
    }

    /// `paths` 전부에 lock을 쥔 하위 프로세스를 띄우고, 실제로 잡을 때까지 기다린다.
    ///
    /// 정상 경로의 회수는 `stop_lock_holder`가 한다. 여기서 panic하면(=테스트 실패) 자식이
    /// 남지만, 부모가 죽으면 stdin이 닫혀 헬퍼도 곧 빠져나온다.
    #[allow(clippy::zombie_processes)]
    fn spawn_lock_holder(path: &Path) -> LockHolder {
        spawn_lock_holder_multi(&[path])
    }

    fn spawn_lock_holder_multi(paths: &[&Path]) -> LockHolder {
        let joined = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(":");
        spawn_lock_holder_raw(&joined)
    }

    #[allow(clippy::zombie_processes)]
    fn spawn_lock_holder_raw(paths: &str) -> LockHolder {
        use std::io::BufRead;
        let exe = std::env::current_exe().expect("테스트 바이너리 경로");
        let mut child = std::process::Command::new(exe)
            // `--nocapture`가 없으면 libtest가 헬퍼의 stdout을 삼켜 `LOCKED`가 파이프로
            // 나오지 않는다 — 부모는 읽기에서, 자식은 stdin에서 서로를 기다리며 교착한다.
            .args([
                "--exact",
                "lock::tests::hold_lock_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("AIC_TEST_HOLD_LOCK", paths)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("lock holder 기동 실패");

        let stdout = child.stdout.take().expect("holder stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .expect("holder stdout 읽기 실패");
            assert!(n > 0, "holder가 lock을 잡지 못하고 종료했다");
            if line.trim() == "LOCKED" {
                return LockHolder {
                    child,
                    _stdout: reader,
                };
            }
        }
    }

    fn stop_lock_holder(mut holder: LockHolder) {
        drop(holder.child.stdin.take()); // stdin 닫힘 → 헬퍼 종료
        let _ = holder.child.wait();
    }

    /// 이 테스트가 지키는 것: 후보 lock을 **전부** 잡는 동작. 하나라도 빠지면 그 경로를
    /// 정규 경로로 삼은 다른 프로세스가 나란히 기동한다.
    #[test]
    fn acquire_all_holds_every_candidate_lock() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("run-user/aicd.pid");
        let alt = dir.path().join("tmp/aicd.pid");

        let set = DaemonLockSet::acquire_all(&canonical, &[canonical.clone(), alt.clone()])
            .expect("acquire_all 실패");

        let held = set.paths();
        assert_eq!(held.len(), 2, "후보 lock을 전부 잡아야 한다: {held:?}");
        assert!(held.contains(&canonical.as_path()));
        assert!(held.contains(&alt.as_path()));
        assert!(canonical.exists() && alt.exists());
    }

    /// 이 테스트가 지키는 것: XDG_RUNTIME_DIR이 갈린 두 프로세스의 **동시** 기동 차단.
    /// 사전 조회만 하던 종전 구현은 검사-획득 사이가 원자적이지 않아 여기서 통과해 버렸다.
    /// 정규 경로가 정렬상 앞이든 뒤든 모두 막아야 한다.
    #[test]
    fn acquire_all_blocks_start_when_other_runtime_dir_is_locked() {
        for (canonical_rel, alt_rel) in [
            ("run-user/aicd.pid", "tmp/aicd.pid"),
            ("tmp/aicd.pid", "run-user/aicd.pid"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let canonical = dir.path().join(canonical_rel);
            let alt = dir.path().join(alt_rel);
            std::fs::create_dir_all(alt.parent().unwrap()).unwrap();

            // 먼저 뜬 aicd — alt를 자기 정규 경로로 삼은 다른 프로세스.
            let holder = spawn_lock_holder(&alt);

            let err = DaemonLockSet::acquire_all(&canonical, &[canonical.clone(), alt.clone()])
                .expect_err("다른 런타임 디렉토리의 aicd를 막지 못했다");
            let msg = err.to_string();
            assert!(
                msg.contains(&alt.display().to_string()),
                "에러가 충돌한 lock 경로를 알려야 한다: {msg}"
            );

            stop_lock_holder(holder);
        }
    }

    /// 이 테스트가 지키는 것: 평범한 중복 기동을 **경로 갈림으로 오진하지 않는 것**.
    /// 살아 있는 aicd는 후보 lock을 전부 쥐므로 환경이 같아도 정렬상 첫 후보(대체 경로)에서
    /// 걸린다 — 부모 디렉토리 비교로는 구분되지 않는다. 판정 기준은 "정규 경로도 같은
    /// 데몬이 쥐고 있는가"다.
    #[test]
    fn acquire_all_error_does_not_blame_xdg_for_plain_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("run-user/aicd.pid");
        let alt = dir.path().join("tmp/aicd.pid");

        // 실제 aicd처럼 후보 lock을 전부 쥔 홀더.
        let holder = spawn_lock_holder_multi(&[&canonical, &alt]);

        let err = DaemonLockSet::acquire_all(&canonical, &[canonical.clone(), alt.clone()])
            .expect_err("잡힌 후보가 있으면 실패해야 한다");
        let msg = err.to_string();

        assert!(msg.contains("PID "), "홀더 PID가 있어야 한다: {msg}");
        assert!(
            !msg.contains("XDG_RUNTIME_DIR"),
            "정규 경로까지 같은 데몬이 쥐고 있으면 경로 갈림이 아니다: {msg}"
        );
        stop_lock_holder(holder);
    }

    /// 반대 경우 — 정규 경로는 비어 있고 대체 후보만 잡혀 있다. 진짜로 다른 런타임
    /// 디렉토리에 데몬이 산다는 뜻이므로 그렇게 안내해야 한다.
    #[test]
    fn acquire_all_error_reports_split_when_canonical_is_free() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("run-user/aicd.pid");
        let alt = dir.path().join("tmp/aicd.pid");
        let holder = spawn_lock_holder(&alt);

        let err = DaemonLockSet::acquire_all(&canonical, &[canonical.clone(), alt.clone()])
            .expect_err("잡힌 후보가 있으면 실패해야 한다");
        let msg = err.to_string();

        assert!(
            msg.contains("XDG_RUNTIME_DIR"),
            "다른 런타임 디렉토리의 데몬이면 그 사실을 알려야 한다: {msg}"
        );
        assert!(msg.contains(&alt.display().to_string()));
        stop_lock_holder(holder);
    }

    /// 만들 수 없는 후보 디렉토리(다른 사용자 소유의 `/run/user/{uid}` 등)는 건너뛴다 —
    /// 거기엔 이 프로세스가 데몬을 띄울 수도 없으므로 경합 대상이 아니다.
    #[test]
    fn acquire_all_skips_unusable_candidate_dir() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("run-user/aicd.pid");
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file, not a directory").unwrap();
        let alt = blocker.join("aicd.pid"); // 부모가 파일 → create_dir_all 실패

        let set = DaemonLockSet::acquire_all(&canonical, &[canonical.clone(), alt])
            .expect("쓸 수 없는 후보 때문에 기동이 막히면 안 된다");
        assert_eq!(set.paths(), vec![canonical.as_path()]);
        assert_eq!(set.canonical_path(), canonical.as_path());
    }

    #[test]
    fn find_live_daemon_outside_tolerates_missing_and_garbage_files() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("canonical.pid");
        let missing = dir.path().join("absent.pid");
        let garbage = dir.path().join("garbage.pid");
        std::fs::write(&garbage, "not-a-pid\n").unwrap();
        assert_eq!(
            find_live_daemon_outside(&canonical, &[canonical.clone(), missing, garbage]),
            None
        );
    }

    #[test]
    fn exe_path_matches_handles_in_place_upgrade() {
        // 동일 경로 → 일치
        assert!(exe_path_matches(
            "/usr/local/bin/aicd",
            "/usr/local/bin/aicd"
        ));
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
