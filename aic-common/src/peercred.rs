//! UDS 상대편 uid 검증.
//!
//! **왜 파일 권한만으로는 부족한가**: 런타임 디렉토리 검사(`paths::runtime_dir_is_trusted`)는
//! "남이 선점한 디렉토리를 쓰지 않는다"까지만 보장한다. 검사와 실제 연결 사이에는 언제나
//! 틈(TOCTOU)이 있고, 탐색 후보가 전부 걸러진 폴백 상황에서는 클라이언트가 결국 정규 경로로
//! 연결을 시도한다. 경로·권한은 **힌트**이고, 상대가 정말 나인지는 커널만 답할 수 있다.
//!
//! 그래서 연결이 붙은 **뒤에** 소켓에서 상대 uid를 직접 받아 대조한다. 이건 파일시스템 상태와
//! 무관하게 성립하는 유일한 판정이다 — 공격자가 소켓을 심어 두었어도 그 소켓을 서비스하는
//! 프로세스의 uid는 위조할 수 없다.
//!
//! 서버(accept)와 클라이언트(connect) **양쪽**에서 본다. 서버만 보면 공격자 소켓에 붙은
//! 클라이언트가 명령과 응답을 그대로 노출하고, 클라이언트만 보면 남의 프로세스가 control
//! 소켓으로 명령을 밀어 넣을 수 있다.

use std::os::fd::{AsRawFd, RawFd};

/// 소켓 상대편의 uid. 플랫폼별 구현(Linux `SO_PEERCRED`, macOS/BSD `getpeereid`)을 감춘다.
///
/// `aic-server`의 attach 서버가 쓰는 tokio `peer_cred()`와 같은 판정이지만, 여기서는 std·tokio
/// 어느 소켓이든 fd 하나로 처리할 수 있게 libc를 직접 부른다 — `aic-common`은 tokio의 `net`
/// feature를 의도적으로 켜지 않는다(lean 유지, `Cargo.toml` 주석 참고).
#[cfg(target_os = "linux")]
pub fn peer_uid(fd: RawFd) -> std::io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// macOS/BSD는 `SO_PEERCRED`가 없어 `getpeereid`를 쓴다.
#[cfg(not(target_os = "linux"))]
pub fn peer_uid(fd: RawFd) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let r = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

/// 상대편이 **나와 같은 uid**인지 확인한다. 아니면 `PermissionDenied`.
///
/// 조회 자체가 실패해도 거부한다 — "모르겠다"를 통과시키면 검사가 있으나 마나다.
pub fn ensure_peer_is_self(sock: &impl AsRawFd) -> std::io::Result<()> {
    let my_uid = unsafe { libc::geteuid() };
    let peer = peer_uid(sock.as_raw_fd())?;
    if peer != my_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "소켓 상대편 uid가 다릅니다 (peer {peer}, self {my_uid}) — \
                 다른 사용자가 선점한 소켓일 수 있습니다."
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    fn temp_sock_path(tag: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("aic-peercred-{tag}-{pid}-{nanos}.sock"))
    }

    /// 같은 프로세스끼리 연결하면 양쪽 모두 자기 uid를 본다 — 정상 경로가 막히면 안 된다.
    #[test]
    fn ensure_peer_is_self_accepts_same_uid() {
        let path = temp_sock_path("same-uid");
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();

        ensure_peer_is_self(&client).expect("클라이언트 쪽 검증 실패");
        ensure_peer_is_self(&server).expect("서버 쪽 검증 실패");

        let _ = std::fs::remove_file(&path);
    }

    /// uid 조회 자체가 불가능한 fd는 통과시키지 않는다("모르겠다" = 거부).
    #[test]
    fn ensure_peer_is_self_rejects_non_socket() {
        let path = temp_sock_path("not-a-socket");
        let file = std::fs::File::create(&path).unwrap();
        let err = ensure_peer_is_self(&file).expect_err("소켓이 아닌 fd를 통과시키면 안 된다");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
            ) || err.raw_os_error().is_some(),
            "예상 밖 에러: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
