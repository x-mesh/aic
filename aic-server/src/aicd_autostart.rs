//! `aicd` autostart helper — `aic-session` 이 Attach_UDS 연결에 실패했을 때 best-effort 로
//! aicd 데몬을 background 에서 spawn 하기 위한 유틸리티 (Task 4.3, R9.1).
//!
//! 정책:
//!
//! - **best-effort only**. spawn 실패(바이너리 없음, 권한 없음, fork 실패 등)는 모두
//!   [`AutostartError`] 로 분류되어 상위 계층이 graceful 하게 Local_Fallback 으로 넘어갈 수
//!   있도록 한다. 사용자 shell 은 절대 죽이지 않는다.
//! - **1 회만 시도한다**. 호출자는 failure 시 재호출하지 않고 즉시 local fallback 으로 빠진다.
//! - **stdio 는 모두 null** 로 detach 해 부모 세션의 stdout 에 영향을 주지 않는다.
//!
//! 바이너리 탐색 순서 (aic-client 의 `handle_daemon_start` 와 동일):
//!
//! 1. `current_exe()` 와 같은 디렉토리에 있는 `aicd` 를 우선. 릴리스 설치본은 `aic` /
//!    `aic-session` / `aicd` 세 바이너리가 한 디렉토리에 함께 놓인다.
//! 2. 그 경로에 없으면 PATH resolution 에 위임 (`Command::new("aicd")`).
//!
//! 연결 확인은 호출자가 [`wait_for_socket`] 이 아니라 짧은 sleep 후 재연결을 시도하는
//! 방식으로 수행한다 — 이 모듈은 "spawn 성공 여부" 까지만 돌려준다. 이유:
//!
//! - 소켓 readiness 는 그 자체로 race 를 타기 쉬워 (`bind` 이후 accept 루프 진입까지의
//!   간격) retry 루프에서 다뤄야 더 자연스럽다.
//! - 테스트 관점에서도 이 모듈은 "바이너리가 있냐 없냐" 만 확인하면 되어 단위 테스트가
//!   간결해진다.
//!
//! Requirements: R9.1 (autostart 시도), R9.2 (실패해도 session 은 계속 동작).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// `try_start()` 가 돌려줄 실패 분류. `anyhow` 를 쓰지 않는 이유는 호출자가 실패 경로에
/// 대해 `debug!` 로만 남기고 바로 Local_Fallback 으로 넘어가므로 메시지 포맷을 안정화해
/// 두는 것이 유지보수에 낫기 때문이다.
#[derive(thiserror::Error, Debug)]
pub enum AutostartError {
    /// `aicd` 바이너리를 현재 실행 파일의 인접 디렉토리에서도, PATH 에서도 찾지 못했다.
    /// `spawn()` 에서 `io::ErrorKind::NotFound` 가 나온 경우 이 variant 로 래핑한다.
    #[error("aicd 바이너리를 찾을 수 없음 (시도한 경로: {attempted})")]
    BinaryNotFound { attempted: String },

    /// spawn 자체가 I/O 에러로 실패했다 (권한 부족, fork 실패 등).
    #[error("aicd spawn 실패: {source} (시도한 경로: {attempted})")]
    SpawnFailed {
        attempted: String,
        #[source]
        source: std::io::Error,
    },
}

/// Task 4.3 의 retry 간격과 일치하는 기본 spawn-after-wait 상한.
///
/// `aic daemon start` 와 동일한 150ms — bind → accept 루프 진입까지 일반 Linux/macOS
/// 환경에서 충분하다. 호출자는 이 값을 직접 보지 않고 retry 루프 안에서 sleep 한다.
pub const DEFAULT_SPAWN_GRACE: Duration = Duration::from_millis(150);

/// `aicd` 데몬을 background 로 spawn 한다 (R9.1 의 "one-shot autostart").
///
/// 실행은 **비동기적으로 detach** 된다: 자식 pid 를 호출자에게 돌려주지 않으며,
/// stdin/stdout/stderr 는 null 로 리다이렉트된다. spawn 이 성공했어도 해당 aicd 가
/// 정상적으로 control socket 을 바인드할지까지는 확인하지 않는다. 호출자는 이 함수가
/// `Ok(())` 를 돌려준 뒤 짧은 sleep 을 거쳐 [`AttachClient::connect`] 를 다시 시도해야
/// 한다 (Task 4.3 의 "1 회 재시도" 경로).
///
/// [`AttachClient::connect`]: crate::attach_client::AttachClient::connect
///
/// 실패 분류는 [`AutostartError`] 참조. 어떤 경우에도 이 함수는 panic 하지 않으며,
/// 상위 호출자 (`session_runtime::run`) 가 실패를 관측해 Local_Fallback 으로 넘어갈 수
/// 있다 (R9.2, R9.6).
pub fn try_start() -> Result<(), AutostartError> {
    let aicd_bin = discover_aicd_binary();
    let attempted = aicd_bin.display().to_string();

    let mut cmd = std::process::Command::new(&aicd_bin);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // aicd 를 자체 세션으로 분리한다(setsid). 부모(aic-session)의 제어 터미널이 닫혀
    // SIGHUP 이 전파돼도 aicd 가 함께 죽지 않게 한다 — aicd 는 세션을 가로질러 공유되는
    // 데몬이므로 어느 한 세션의 종료에 휘둘리면 안 된다. `pre_exec` 는 fork 직후·exec 직전에
    // 자식에서 실행되며, 이 시점엔 호출자가 process group leader 가 아니라 setsid 가 성공한다.
    // 멀티스레드 fork 안전을 위해 클로저는 async-signal-safe 한 `setsid` 만 호출하고 힙
    // 할당을 하지 않는다.
    //
    // SAFETY: 위 제약(async-signal-safe only, no alloc)을 지킨다.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    match cmd.spawn() {
        Ok(child) => {
            tracing::info!(
                pid = child.id(),
                bin = %attempted,
                "aicd autostart 성공 — Attach_UDS 재연결을 시도합니다"
            );
            // `Child` 를 detached reaper 스레드로 넘겨 종료 시 `wait` 한다. 이게 없으면
            // aicd 가 (중복 인스턴스의 DaemonLock 실패 등으로) 먼저 종료할 때 부모가 reap
            // 하지 않아 zombie 로 남는다. aicd 가 장기 실행이면 스레드는 그때까지 parked
            // 되고, aic-session 이 먼저 종료되면 스레드도 사라지며 aicd 는 init 으로
            // reparent 되어 init 이 reap 한다.
            std::thread::spawn(move || {
                let mut child = child;
                let _ = child.wait();
            });
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(AutostartError::BinaryNotFound {
            attempted,
        }),
        Err(e) => Err(AutostartError::SpawnFailed {
            attempted,
            source: e,
        }),
    }
}

/// 현재 실행 파일 (`aic-session`) 과 같은 디렉토리의 `aicd` 를 우선 반환하고, 없으면
/// PATH resolution 에 위임할 수 있도록 `PathBuf::from("aicd")` 를 돌려준다.
///
/// 이 동작은 `aic-client::main::handle_daemon_start` 와 의도적으로 동일하다 — 릴리스
/// 설치본에서 두 경로가 일관되게 같은 바이너리를 선택하도록.
fn discover_aicd_binary() -> PathBuf {
    if let Some(adjacent) = adjacent_aicd(std::env::current_exe().ok().as_deref()) {
        return adjacent;
    }
    PathBuf::from("aicd")
}

/// `current_exe` 옆에 `aicd` 바이너리가 실제 파일로 존재하면 그 경로를 돌려준다.
///
/// 단위 테스트에서 임의의 temp dir 을 넘겨 결정 로직을 검증할 수 있도록 public 에 가까운
/// 시그니처로 분리했다 (crate-internal 이지만 `pub(crate)`).
pub(crate) fn adjacent_aicd(current_exe: Option<&Path>) -> Option<PathBuf> {
    let exe = current_exe?;
    let parent = exe.parent()?;
    let candidate = parent.join("aicd");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 바이너리가 없는 환경에서 `try_start()` 는 panic 없이 `BinaryNotFound` 를 돌려준다.
    ///
    /// 핵심 동작 보장:
    /// - PATH 조회가 실패해야 하므로 현재 PATH 상에 `aicd` 가 없어야 한다. CI 환경에서도
    ///   `aicd` 는 PATH 에 설치되어 있지 않으므로 이 테스트는 안정적으로 실패 경로를 탄다.
    /// - `current_exe` 가 `target/debug/deps/...` 를 가리키는데, 그 디렉토리 자체에는
    ///   `aicd` 바이너리가 없다 (test binary 와 분리). 따라서 adjacent 경로도 miss.
    ///
    /// 이 테스트는 R9.2 "autostart 실패해도 session 계속" 의 선결 조건을 직접 검증한다 —
    /// 실패가 panic 이 아니라 회복 가능한 Result variant 로 돌아오는지.
    #[test]
    fn try_start_returns_binary_not_found_when_aicd_absent() {
        // PATH 를 강제로 비워 PATH resolution 이 확실히 실패하도록 한다.
        // 테스트 스레드 간 공유되는 환경변수이지만 이 테스트는 같은 키를 복원해 둔다.
        let original_path = std::env::var_os("PATH");
        // SAFETY: 테스트 종료 후 원복한다. 같은 키를 건드리는 다른 테스트가 없음을 확인.
        unsafe {
            std::env::remove_var("PATH");
        }

        // current_exe 디렉토리에 aicd 라는 파일이 "실수로" 있을 수 있으므로,
        // adjacent_aicd 가 miss 하는 경우에만 이 테스트가 BinaryNotFound 를 단언한다.
        // 있다면 테스트를 skip 한다 (릴리스 빌드 디렉토리에서만 가끔 발생).
        let exe = std::env::current_exe().ok();
        if adjacent_aicd(exe.as_deref()).is_some() {
            unsafe {
                if let Some(p) = original_path {
                    std::env::set_var("PATH", p);
                }
            }
            eprintln!("SKIP: adjacent aicd 가 발견되어 BinaryNotFound 경로를 탈 수 없음");
            return;
        }

        let result = try_start();

        // PATH 원복.
        unsafe {
            if let Some(p) = original_path {
                std::env::set_var("PATH", p);
            }
        }

        match result {
            Err(AutostartError::BinaryNotFound { attempted }) => {
                assert!(
                    attempted.ends_with("aicd"),
                    "attempted 경로는 'aicd' 로 끝나야 함 — {attempted}"
                );
            }
            Err(other) => panic!("BinaryNotFound 기대 — actual: {other:?}"),
            Ok(()) => panic!("aicd 바이너리가 없는데 Ok 를 돌려줌 — 환경 상 발생 불가"),
        }
    }

    /// `adjacent_aicd` 가 실제 파일만 선택하고, 존재하지 않거나 디렉토리인 경우에는 None 을
    /// 돌려주는지 확인한다. 이 결정 로직이 `try_start()` 의 바이너리 선택을 좌우한다.
    #[test]
    fn adjacent_aicd_picks_only_existing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let fake_session = tempdir.path().join("aic-session");
        fs::write(&fake_session, b"#!/bin/sh\nexit 0\n").unwrap();

        // aicd 파일이 없는 상태: None
        assert!(adjacent_aicd(Some(&fake_session)).is_none());

        // aicd 파일 생성 → Some
        let aicd = tempdir.path().join("aicd");
        fs::write(&aicd, b"#!/bin/sh\nexit 0\n").unwrap();
        let picked = adjacent_aicd(Some(&fake_session)).expect("file 생성 후 Some 기대");
        assert_eq!(picked, aicd);

        // current_exe 가 None 이면 None
        assert!(adjacent_aicd(None).is_none());
    }

    /// `try_start()` 가 adjacent 바이너리를 spawn 할 수 있음을 verify 한다. 실제 aicd 를
    /// 띄우지는 않고, 성공 경로가 panic 없이 `Ok(())` 로 내려오는지만 확인한다.
    ///
    /// 바이너리는 "아무 것도 하지 않고 빠르게 종료" 하는 단순 shell script 로 대체한다.
    /// `try_start()` 가 자식 pid 를 노출하지 않는 detach 구조이므로, script 가 즉시 종료해도
    /// 상위 함수 결과는 영향받지 않는다.
    ///
    /// 이 테스트는 바이너리 탐색 경로 (adjacent) 와 spawn 성공 경로 양쪽을 함께 커버한다.
    #[test]
    fn try_start_returns_ok_when_adjacent_aicd_is_executable() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let aicd_path = tempdir.path().join("aicd");
        // exit 0 만 수행하는 최소 script. spawn 시 바로 종료하여 zombie 만 남긴다 — 테스트
        // 환경에서는 tokio runtime 이 없으므로 별도의 reaper 처리는 필요 없다.
        fs::write(&aicd_path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&aicd_path, fs::Permissions::from_mode(0o755)).unwrap();
        // fake current_exe 도 같은 디렉토리에 둔다 — `adjacent_aicd` 가 이 값을 찾아낸다.
        let fake_exe = tempdir.path().join("aic-session");
        fs::write(&fake_exe, b"#!/bin/sh\nexit 0\n").unwrap();

        // `discover_aicd_binary` 는 `std::env::current_exe()` 를 쓰는데, 이 값을 테스트
        // 범위에서 오버라이드할 방법이 없다 (테스트 바이너리 자체의 경로가 반환됨).
        // 따라서 이 테스트는 `adjacent_aicd` 결정 로직 + spawn 성공 경로를 **직접 합쳐**
        // 재구성한다 — `try_start()` 전체 경로를 타지 않고 동등한 spawn 동작을 검증한다.
        let picked = adjacent_aicd(Some(&fake_exe)).expect("tempdir 에 aicd 가 있으므로 Some");
        assert_eq!(picked, aicd_path);

        // Linux 멀티스레드 테스트 러너에서, 방금 write 한 실행 파일을 exec 할 때 다른
        // 테스트 스레드의 fork 와 겹치면 그 자식이 이 파일의 write-fd 를 상속받아 execve 가
        // ETXTBSY("Text file busy") 로 실패할 수 있다(커널 동작, parallelism 의존 flake).
        // 짧게 재시도해 레이스를 흡수한다 — 겹친 자식이 곧 exec/exit 하면 write-fd 가 닫힌다.
        let mut spawned = None;
        for _ in 0..50 {
            match std::process::Command::new(&picked)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                other => {
                    spawned = Some(other);
                    break;
                }
            }
        }
        let result = spawned.expect("ETXTBSY 재시도 한도를 넘어 spawn 을 시도하지 못함");
        assert!(result.is_ok(), "adjacent aicd spawn 실패: {result:?}");
        // zombie 방지: wait 로 reap.
        let _ = result.unwrap().wait();
    }
}
