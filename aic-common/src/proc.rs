//! 프로세스 단위 OS 조회 — aic-server(OTLP exporter)와 aic-client(`/local` probe)가 **같은 구현을
//! 공유**하기 위해 여기 둔다. 두 크레이트가 각자 fd를 세면 같은 프로세스에 다른 숫자를 보고하게
//! 되고, 그러면 어느 쪽이 맞는지 판단할 근거가 사라진다.

/// 이 프로세스가 열고 있는 파일 디스크립터 수. 읽을 수 없으면 `None`.
///
/// **fd 누수는 spike가 아니라 느린 선형 증가**라, 호스트 전역 fd 수(머신 전체 수천~수만)로는
/// 데몬 하나가 수백 개 새도 노이즈에 묻힌다. 프로세스 축으로 봐야 `(host, pid, name)` 시계열의
/// 기울기가 드러난다.
///
/// # 권한 — 호출자의 uid에 따라 가시 범위가 갈린다
/// **`/proc/<pid>/fd`는 소유자 전용(0500)**이고 macOS `proc_pidinfo`도 타 uid 프로세스엔 EPERM이다.
/// (Linux에서 `/proc/<pid>/status`·`cgroup`이 world-readable인 것과 다르다.) 그래서 두 플랫폼 모두
/// **비루트 프로세스는 자기 uid 소유 프로세스의 fd만** 볼 수 있다. 읽기 실패는 `None`이며,
/// **0으로 접지 않는다** — "fd를 하나도 안 열었다"는 거짓 신호가 되기 때문이다(모든 프로세스는
/// 최소 stdio를 연다).
#[cfg(target_os = "linux")]
pub fn process_fd_count(pid: i64) -> Option<u32> {
    // read_dir 자체가 fd를 하나 쓰므로 `pid`가 호출자 자신이면 결과가 1 크다. 누수 탐지는 기울기를
    // 보는 것이라 상수 편향 1은 무해해서 보정하지 않는다.
    let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    u32::try_from(entries.filter(|e| e.is_ok()).count()).ok()
}

/// macOS: `proc_pidinfo(PROC_PIDLISTFDS)`로 fd 목록을 받아 개수를 센다.
///
/// **크기 조회(buffer=NULL)만으로 세면 안 된다.** 그 호출이 돌려주는 건 "지금 열린 fd 수"가 아니라
/// 프로세스 fd 테이블에 **할당된 슬롯 수** 기준의 상한이다 — term-meshd(pid 1183) 실측에서 실제
/// 32개인데 560바이트(=70개분)를 돌려줬다. 그 값을 그대로 쓰면 2배 넘게 과대 집계되고, 하필
/// 누수 탐지가 보는 축이 부풀어 오탐이 된다. 그래서 두 번 부른다: 상한으로 버퍼를 잡고, **실제
/// 채워진 바이트**로 개수를 낸다.
///
/// # 절삭(truncation) 방어 — 여유 없이 잡으면 누수 프로세스만 골라 틀린다
/// 크기 조회와 실제 조회는 별개 호출이라 그 사이에 fd가 늘 수 있다. 커널은 넘긴 버퍼 크기까지만
/// 채우고 **"잘렸다"고 알려주지 않으므로**, 채워진 길이가 버퍼를 꽉 채웠으면 잘렸다고 보고 더 큰
/// 버퍼로 재시도한다.
///
/// 조회 결과 크기 그대로 버퍼를 잡으면 **fd가 늘고 있는 프로세스만 골라 과소 계수**하는데, 그게
/// 정확히 누수 탐지가 잡아야 할 대상이라 치명적이다. "한 tick의 절삭은 다음 tick에 보정된다"는
/// 초기 판단은 틀렸다 — 계속 누수 중이면 다음 tick에도 같은 이유로 잘려 영원히 보정되지 않는다.
#[cfg(target_os = "macos")]
pub fn process_fd_count(pid: i64) -> Option<u32> {
    /// 재조회 버퍼에 얹는 여유 엔트리 수 — 두 호출 사이에 새로 열린 fd를 흡수한다.
    const FD_LIST_HEADROOM_ENTRIES: i32 = 32;
    /// 버퍼가 계속 꽉 차는(= 조회보다 빠르게 늘어나는) 프로세스에서 무한 재시도를 막는 상한.
    const FD_LIST_MAX_ATTEMPTS: usize = 3;

    let pid = i32::try_from(pid).ok()?;
    let entry_size = i32::try_from(std::mem::size_of::<libc::proc_fdinfo>()).ok()?;
    // SAFETY: buffer=NULL·buffersize=0은 "크기만 조회" 규약이라 커널이 메모리를 쓰지 않는다.
    let probe =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    // -1은 EPERM(타 uid)·ESRCH(그 사이 종료). 0은 fd가 0개라는 뜻이 될 수 없고(모든 프로세스가
    // 최소 stdio를 연다) 실패와 구분도 안 되므로 둘 다 "모른다"로 접는다.
    if probe <= 0 {
        return None;
    }

    // 구조체 배열이 아니라 바이트 버퍼로 잡는다 — `proc_fdinfo`의 Clone 파생 여부에 기대지 않고,
    // 커널이 채운 길이를 바이트 단위로 그대로 해석하려는 것이다.
    let mut bytes = probe.saturating_add(FD_LIST_HEADROOM_ENTRIES.saturating_mul(entry_size));
    let mut last_filled = 0;
    for _ in 0..FD_LIST_MAX_ATTEMPTS {
        let mut buf = vec![0u8; usize::try_from(bytes).ok()?];
        // SAFETY: buf는 bytes만큼 소유하고, 커널에 넘기는 길이도 정확히 bytes다.
        let filled = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast(), bytes)
        };
        if filled <= 0 {
            return None;
        }
        last_filled = filled;
        if filled < bytes {
            // 여유가 남았다 = 커널이 목록을 다 담았다.
            return u32::try_from(filled / entry_size).ok();
        }
        bytes = bytes.saturating_mul(2);
    }
    // 상한까지 계속 꽉 찼다 = fd가 조회보다 빠르게 늘고 있다. 여기서 `None`으로 접으면 **폭증
    // 중인 프로세스만 관측에서 사라진다** — 가장 봐야 할 대상이 사라지는 셈이라, 과소값이나마
    // 하한으로 내보낸다. 절대치는 낮아도 "늘고 있다"는 기울기는 남는다.
    u32::try_from(last_filled / entry_size).ok()
}

/// 그 외 플랫폼은 프로세스별 fd를 읽을 이식 가능한 방법이 없다.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_fd_count(_pid: i64) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fd 카운트는 syscall/`/proc` 의존이라 픽스처로 못 만든다 — **자기 자신**을 재료로 쓴다.
    /// 어떤 프로세스든 최소 stdio 3개는 열고 있으므로 하한은 확정적이고, 자기 프로세스는 권한
    /// 문제도 없다(uid가 같다). 상한은 두지 않는다 — 테스트 러너가 몇 개를 열지는 우리 소관이 아니다.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn process_fd_count_reads_own_process() {
        let me = i64::from(std::process::id());
        let n = process_fd_count(me).expect("자기 프로세스의 fd는 항상 읽을 수 있어야 한다");
        assert!(n >= 3, "stdio 3개도 못 센다: {n}");
    }

    /// 없는 프로세스는 0이 아니라 `None`이다 — 0으로 접으면 "fd를 안 열었다"는 거짓 신호가 되고,
    /// 호출자가 값의 부재를 표현할 근거가 사라진다. `i32::MAX`는 두 플랫폼 모두 pid 상한
    /// (Linux 기본 4194304, macOS 99999)을 넘어 실재할 수 없다.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn process_fd_count_is_none_for_nonexistent_pid() {
        assert_eq!(process_fd_count(i64::from(i32::MAX)), None);
    }

    /// 새로 연 fd가 결과에 반영돼야 한다 — macOS 절삭 방어의 **간접** 검증이다. 크기 조회 결과
    /// 그대로 버퍼를 잡으면 조회 이후 열린 fd가 잘려 증가가 과소 보고된다. TOCTOU 자체는 두
    /// `proc_pidinfo` 호출 사이에 정확히 끼어들어야 해 결정적 재현이 안 되므로, "여러 개를 새로
    /// 열면 증가가 보인다"는 관측 가능한 성질로 회귀를 막는다.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn process_fd_count_reflects_newly_opened_fds() {
        /// 테스트가 새로 여는 fd 수.
        const OPEN_COUNT: usize = 64;
        /// 단언에 쓰는 최소 증가폭 — 테스트는 같은 프로세스에서 병렬로 돌아 다른 테스트가 그 사이
        /// fd를 닫을 수 있으므로 정확한 증가량(OPEN_COUNT)을 요구하지 않는다.
        const MIN_DELTA: u32 = 32;

        let me = i64::from(std::process::id());
        let before = process_fd_count(me).expect("자기 프로세스의 fd는 읽을 수 있어야 한다");
        let opened: Vec<std::fs::File> = (0..OPEN_COUNT)
            .map(|_| std::fs::File::open("/dev/null").expect("/dev/null을 열 수 있어야 한다"))
            .collect();
        let after = process_fd_count(me).expect("자기 프로세스의 fd는 읽을 수 있어야 한다");
        drop(opened);

        assert!(
            after >= before + MIN_DELTA,
            "fd {OPEN_COUNT}개를 새로 열었는데 증가가 반영되지 않았다: {before} → {after}"
        );
    }
}
