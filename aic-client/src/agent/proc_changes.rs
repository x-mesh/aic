//! `/local`의 `proc_changes` 섹션과 `/procs` 커맨드 — 최근 프로세스 생성/소멸/변경.
//!
//! # 왜 shell probe가 아니라 Rust인가
//! [`proc_fd`](super::proc_fd)와 같은 이유에 하나가 더 붙는다. 이 데이터는 **셸로 얻을 수 없다** —
//! `ps`는 "지금 살아 있는 프로세스"만 보여주지 "방금 죽은 프로세스"를 못 보여준다. 변화(생성/소멸)를
//! 알려면 이전 스냅샷과 비교한 이력이 있어야 하고, 그 이력을 들고 있는 건 aicd다. 그래서 여기서는
//! 계산을 하지 않고 **aicd에 IPC로 물어보기만** 한다.
//!
//! # 한계 — 폴링이라 못 보는 것이 있다
//! aicd는 host metrics tick(기본 60초)마다 전수 프로세스를 diff한다. 그래서 **tick 사이에 떴다
//! 사라진 단명 프로세스는 아예 안 보인다**. 이건 구현 부족이 아니라 유저스페이스 폴링의 구조적
//! 한계이고, 나중에 eBPF(fork/exit tracepoint)가 메꾸는 부분이다. 사용자가 "왜 내 스크립트가 안
//! 보이지"를 오해하지 않도록 섹션 안내 문구에 이 사실을 남긴다.

use crate::agent_event;

/// `/local` 섹션에 실을 최근 변화 수. `proc_fd_top`(15줄)과 눈높이를 맞춘다 — `/local`은 사람이
/// 훑는 화면이라 섹션 하나가 화면을 잡아먹으면 안 된다.
const SECTION_N: usize = 15;

/// aicd에 못 물어봤을 때의 문구 접두사. 테스트가 이 문자열을 계약으로 쓴다.
pub(crate) const UNAVAILABLE_PREFIX: &str = "(aicd에 물어보지 못함";

/// 물어봤으나 변화가 없을 때의 문구 접두사.
pub(crate) const EMPTY_PREFIX: &str = "(최근 프로세스 변화 없음";

/// `/local`의 `proc_changes` 섹션 본문. 인자를 받지 않는다 — 이 함수를 부르는 `aic proc-changes`가
/// risk_guard에서 **exact argv**로만 Safe 판정되기 때문이다(`proc_fd_top`과 같은 제약).
pub fn render() -> String {
    render_n(SECTION_N, false)
}

/// `/procs` 커맨드 본문 — 섹션판보다 많이, 관측 시각까지 보여준다. 이쪽은 사람이 명시적으로 부르는
/// 경로라 probe의 exact-argv 제약을 받지 않아 `count`를 받는다.
pub fn render_detailed(count: usize) -> String {
    render_n(count, true)
}

fn render_n(count: usize, with_time: bool) -> String {
    match agent_event::recent_process_changes(count) {
        // 물어보지 못함 — aicd가 안 떴거나 이 요청을 모르는 구버전이다. "변화 없음"과 절대 뭉치지
        // 않는다(조용한 것과 고장난 것은 사용자에게 전혀 다른 상태다).
        None => format!("{UNAVAILABLE_PREFIX} — aicd 미실행이거나 구버전)\n"),
        Some(changes) if changes.is_empty() => format!(
            "{EMPTY_PREFIX} — exporter가 꺼져 있으면 수집 자체를 안 한다: `aic status`로 확인)\n"
        ),
        Some(changes) => render_table(&changes, with_time),
    }
}

/// 표 렌더링만 하는 순수 함수 — IPC 없이 형태를 검증할 수 있게 분리한다([`proc_fd`]와 같은 취지).
fn render_table(changes: &[aic_common::ipc::ProcessChange], with_time: bool) -> String {
    let mut out = String::new();
    if with_time {
        out.push_str(&format!(
            "{:<7} {:>7} {:>7} {:<19} {}\n",
            "OP", "PID", "PPID", "OBSERVED", "COMMAND"
        ));
    } else {
        out.push_str(&format!(
            "{:<7} {:>7} {:>7} {}\n",
            "OP", "PID", "PPID", "COMMAND"
        ));
    }
    for c in changes {
        if with_time {
            out.push_str(&format!(
                "{:<7} {:>7} {:>7} {:<19} {}\n",
                c.op,
                c.pid,
                c.ppid,
                format_observed(c.observed_at),
                c.name
            ));
        } else {
            out.push_str(&format!(
                "{:<7} {:>7} {:>7} {}\n",
                c.op, c.pid, c.ppid, c.name
            ));
        }
    }
    out
}

/// unix 초를 로컬 시각 문자열로. 변환 불가(0/범위 밖)면 `-`를 낸다 — 0을 1970년으로 찍어 사용자를
/// 헷갈리게 하지 않는다.
fn format_observed(unix_secs: u64) -> String {
    let Ok(secs) = i64::try_from(unix_secs) else {
        return "-".to_string();
    };
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(dt) if secs > 0 => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        _ => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::ipc::ProcessChange;

    fn change(op: &str, pid: i64, name: &str, observed_at: u64) -> ProcessChange {
        ProcessChange {
            op: op.to_string(),
            pid,
            ppid: 1,
            start_time: 1_700_000_000,
            name: name.to_string(),
            uid: None,
            container_id: None,
            observed_at,
        }
    }

    #[test]
    fn table_has_header_and_one_row_per_change() {
        let out = render_table(
            &[change("add", 10, "postgres", 1_700_000_100), change("remove", 20, "gone", 1_700_000_200)],
            false,
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "헤더 + 2행이어야 한다:\n{out}");
        assert!(lines[0].starts_with("OP"));
        assert!(lines[1].contains("add") && lines[1].contains("postgres"));
        assert!(lines[2].contains("remove") && lines[2].contains("gone"));
    }

    #[test]
    fn detailed_table_adds_observed_column() {
        let out = render_table(&[change("add", 10, "x", 1_700_000_100)], true);
        assert!(out.lines().next().unwrap().contains("OBSERVED"));
        // 시각이 실제로 렌더된다(에폭 0이 아니므로 `-`가 아니어야 한다).
        assert!(!out.lines().nth(1).unwrap().contains(" - "));
    }

    /// 0은 "모름"이지 1970년이 아니다 — 그대로 찍으면 사용자가 실제 관측 시각으로 오해한다.
    #[test]
    fn unknown_observed_time_renders_dash_not_epoch() {
        assert_eq!(format_observed(0), "-");
        assert!(!format_observed(0).contains("1970"));
    }

    #[test]
    fn known_observed_time_renders_datetime() {
        let s = format_observed(1_700_000_000);
        assert!(s.starts_with("2023-"), "예상 밖 포맷: {s}");
    }

    /// 빈 목록과 조회 실패는 **다른 문구**여야 한다 — 사용자가 "조용한 것"과 "고장난 것"을 구분해야
    /// 한다. 두 접두사가 겹치면 그 구분이 사라지므로 여기서 고정한다.
    #[test]
    fn empty_and_unavailable_messages_are_distinct() {
        assert_ne!(UNAVAILABLE_PREFIX, EMPTY_PREFIX);
        assert!(!EMPTY_PREFIX.starts_with(UNAVAILABLE_PREFIX));
    }
}
