//! `/local`의 `proc_fd_top` 섹션 — 프로세스별 열린 fd 상위 N.
//!
//! # 왜 shell probe가 아니라 Rust인가
//! `/local`의 다른 섹션은 전부 shell 한 줄이지만, 프로세스별 fd만은 그렇게 못 한다. probe는
//! **파이프만 허용**(`;` `&` `$` 등 금지)이라 `awk '{print $1}'` 같은 집계가 불가능하고, Linux에서
//! `/proc/*/fd`를 프로세스별로 세려면 루프가 필요하다. lsof에 기대면 미설치 호스트에서 섹션이
//! 통째로 비는데, aicd의 주 배포 대상이 Linux 서버다. 그래서 계산은 Rust로 하고 probe는 이
//! 서브커맨드를 부르기만 한다.
//!
//! fd 계산 자체는 [`aic_common::proc::process_fd_count`]로, **aicd의 OTLP exporter와 같은 구현**을
//! 쓴다 — 같은 프로세스에 두 도구가 다른 숫자를 보고하면 어느 쪽이 맞는지 판단할 근거가 사라진다.

use aic_common::proc::process_fd_count;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

/// 출력할 프로세스 수. `mem_top_proc`(15줄)과 눈높이를 맞춘다 — `/local`은 사람이 훑는 화면이라
/// 섹션 하나가 화면을 잡아먹으면 안 된다.
const TOP_N: usize = 15;

/// 한도 줄의 접두사. [`crate::agent::diagnose`]의 스캐너가 이 문자열로 파싱하므로 **양쪽을 함께
/// 바꿔야 한다**.
pub(crate) const LIMIT_PREFIX: &str = "per-proc limit:";

/// 프로세스별 fd 상위 N을 사람이 읽을 수 있는 표로 만든다. 첫 줄은 프로세스당 fd 상한(알 수 있을 때).
///
/// 읽을 수 없는 프로세스(타 uid, 그 사이 종료)는 조용히 빠진다 — 0으로 채우면 "fd를 안 열었다"는
/// 거짓 신호가 되기 때문이다. 비루트로 돌면 자기 uid 소유 프로세스만 보이므로, 이 표는 **볼 수
/// 있는 범위 안의** 상위라는 점을 감안해 읽어야 한다.
pub fn render() -> String {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());

    let mut rows: Vec<(u32, i64, String)> = sys
        .processes()
        .iter()
        // 스레드는 제외한다. Linux의 `processes()`는 task까지 돌려주는데, 스레드의 `/proc/<tid>/fd`는
        // 소속 프로세스의 fd 테이블을 그대로 비추므로 같은 fd가 스레드 수만큼 중복 집계돼 상위가
        // 스레드로 도배된다(aicd 쪽 `real_processes` doc의 실측 참고). 비-Linux는 항상 `None`이라 no-op.
        .filter(|(_, p)| p.thread_kind().is_none())
        .filter_map(|(pid, p)| {
            let id = i64::from(pid.as_u32());
            process_fd_count(id).map(|fd| (fd, id, p.name().to_string_lossy().into_owned()))
        })
        .collect();
    // fd 내림차순, 동률이면 pid 오름차순 — tie로 출력 순서가 흔들리지 않게(결정적).
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    let mut out = String::new();
    if let Some(limit) = per_process_fd_limit() {
        out.push_str(&format!("{LIMIT_PREFIX} {limit}\n"));
    }
    out.push_str(&format!("{:>7} {:>7} {}\n", "FD", "PID", "COMMAND"));
    for (fd, pid, name) in rows.iter().take(TOP_N) {
        out.push_str(&format!("{fd:>7} {pid:>7} {name}\n"));
    }
    if rows.is_empty() {
        out.push_str("(읽을 수 있는 프로세스 없음 — 권한 부족)\n");
    }
    out
}

/// 프로세스 하나가 열 수 있는 fd 상한. **호스트 전역 상한이 아니다** — 전역은 이미 `fd` 섹션이
/// 보여주고, 여기서 필요한 건 "이 프로세스가 자기 한도의 어디쯤인가"의 분모다.
///
/// macOS는 `kern.maxfilesperproc`(커널 강제 상한)을 sysctl로 읽는다. 프로세스별 `getrlimit`은
/// 자기 자신에게만 되므로 타 프로세스에는 쓸 수 없고, 이 값이 전 프로세스에 공통으로 걸리는
/// 실질 천장이라 분모로 적절하다.
#[cfg(target_os = "macos")]
fn per_process_fd_limit() -> Option<u64> {
    let name = std::ffi::CString::new("kern.maxfilesperproc").ok()?;
    let mut value: i32 = 0;
    let mut len = std::mem::size_of::<i32>();
    // SAFETY: name은 nul 종단 CString, value/len은 유효한 지역 변수를 가리킨다.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::addr_of_mut!(value).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    u64::try_from(value).ok()
}

/// Linux는 `/proc/sys/fs/nr_open`(프로세스당 fd 상한). 프로세스마다 `/proc/<pid>/limits`로 더
/// 정확한 soft limit을 볼 수도 있지만, 그건 프로세스 수만큼 파일을 더 읽어야 해서 여기서는 공통
/// 천장 하나로 갈음한다.
#[cfg(target_os = "linux")]
fn per_process_fd_limit() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn per_process_fd_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 살아있는 시스템에서 표가 만들어지고 자기 자신이 보여야 한다 — 자기 프로세스는 uid가 같아
    /// 권한 문제가 없으므로 최소 한 줄은 확정적으로 나온다.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn render_lists_at_least_this_process() {
        let out = render();
        assert!(out.contains("FD"), "헤더가 없다:\n{out}");
        assert!(
            out.lines().count() >= 2,
            "헤더 말고 아무 프로세스도 못 읽었다:\n{out}"
        );
    }

    /// 표의 컬럼 순서는 `diagnose::scan_proc_fd`와의 **문자열 계약**이다 — 스캐너가 앞 두 토큰을
    /// fd·pid 정수로 읽는다. 한쪽만 바뀌면 파싱이 조용히 실패해 자동 발견이 영원히 침묵하므로,
    /// 여기서 형태를 고정한다.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn render_rows_start_with_fd_then_pid() {
        let out = render();
        let rows: Vec<&str> = out
            .lines()
            .filter(|l| !l.starts_with(LIMIT_PREFIX))
            .skip(1) // 헤더(FD PID COMMAND)
            .filter(|l| !l.starts_with('('))
            .collect();
        for row in rows.iter().take(3) {
            let mut it = row.split_whitespace();
            assert!(
                it.next().and_then(|t| t.parse::<u64>().ok()).is_some(),
                "첫 토큰이 fd 정수가 아니다: {row}"
            );
            assert!(
                it.next().and_then(|t| t.parse::<u64>().ok()).is_some(),
                "둘째 토큰이 pid 정수가 아니다: {row}"
            );
        }
    }

    /// 한도 줄은 스캐너([`crate::agent::diagnose`])와의 계약이라 접두사가 정확해야 한다.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn render_includes_parsable_limit_line() {
        let out = render();
        let Some(line) = out.lines().find(|l| l.starts_with(LIMIT_PREFIX)) else {
            // 한도를 못 읽는 환경이면 줄 자체가 없는 게 정상이다(0을 지어내지 않는다).
            return;
        };
        let value = line
            .trim_start_matches(LIMIT_PREFIX)
            .trim()
            .parse::<u64>()
            .expect("한도 줄은 정수로 파싱돼야 한다");
        assert!(value > 0, "한도가 0이면 분모로 쓸 수 없다: {line}");
    }
}
