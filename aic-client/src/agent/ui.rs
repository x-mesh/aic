//! `aic chat` 대화형 UI — ASCII art banner + status line + 색상/폭 처리.
//!
//! line-based 출력만 사용한다(ratatui 같은 fullscreen TUI 미사용).
//! UI/provenance는 stderr로 보내고, LLM 답변은 stdout으로 둔다(스트림 분리).
//! 색상은 `NO_COLOR` 미설정 + TTY일 때만 적용하고, non-TTY는 큰 배너 대신 plain
//! 1줄로 fallback한다. 폭이 좁으면 compact status로 줄인다.

use std::io::IsTerminal;

/// status를 compact로 줄이는 폭 임계값(컬럼).
const COMPACT_WIDTH: usize = 64;

/// stderr가 TTY인지 — 배너/상태/색상 판단 기준(UI는 stderr 출력).
pub(crate) fn is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// 색상 사용 가능 여부 — `NO_COLOR` 미설정 && TTY.
pub(crate) fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && is_tty()
}

/// 순수 결정 로직(테스트용): 둘 중 하나라도 켜지면 배너 생략.
fn banner_suppressed_from(no_banner: bool, quiet: bool) -> bool {
    no_banner || quiet
}

/// chat 시작 배너/status를 끌지 — `AIC_NO_BANNER` 또는 `AIC_QUIET`가 `1|true`면 true.
/// 배너는 debug 로그와 무관하지만, 조용한 실행을 원하는 사용자를 위한 opt-out.
pub(crate) fn banner_suppressed() -> bool {
    banner_suppressed_from(
        super::debug::env_truthy("AIC_NO_BANNER"),
        super::debug::env_truthy("AIC_QUIET"),
    )
}

/// 터미널 폭(컬럼). 알 수 없으면 80.
pub(crate) fn term_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
}

/// markdown 렌더 wrap 폭 — 터미널 폭을 [40, 100]으로 clamp(가독성).
pub(crate) fn render_width() -> usize {
    term_width().clamp(40, 100)
}

/// ANSI 코드로 감싼다(`color=false`면 원문 그대로).
fn paint_if(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// 색상 정책(`color_enabled`)에 따라 ANSI로 감싸거나 plain을 반환한다.
/// NO_COLOR/non-TTY면 escape 없이 원문 — 다른 모듈(run_command/session)에서 직접 ANSI를
/// 쓰지 않고 이 헬퍼를 재사용한다.
pub(crate) fn paint(s: &str, code: &str) -> String {
    paint_if(s, code, color_enabled())
}

/// run_command 노출 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunState {
    On,
    ReadOnly,
}

/// 상태줄에 표시할 정보.
pub(crate) struct StatusInfo {
    pub run_state: RunState,
    pub cwd: String,
    pub provider: Option<String>,
    pub model: Option<String>,
}

/// 폭이 좁아 compact status를 써야 하는지.
fn is_compact(width: usize) -> bool {
    width < COMPACT_WIDTH
}

/// 실시간 status bar(시스템 지표)를 끌지 — `AIC_NO_STATUSBAR`가 `1|true`면 true.
/// 배너 opt-out(`AIC_NO_BANNER`/`AIC_QUIET`)과 별개로, bar만 끄고 싶을 때.
pub(crate) fn statusbar_suppressed() -> bool {
    super::debug::env_truthy("AIC_NO_STATUSBAR")
}

/// 시스템 지표 status bar를 켤지 — TTY이고, 배너/statusbar opt-out이 모두 꺼져 있을 때만.
/// (non-TTY/파이프/CI에서는 자동 비활성 — spinner.rs와 동일 정책.)
pub(crate) fn statusbar_enabled() -> bool {
    is_tty() && !statusbar_suppressed() && !banner_suppressed()
}

/// 시스템 지표 한 줄을 stderr에 dim으로 출력한다. 입력 프롬프트 **직전**에만 호출해야
/// reedline raw mode와 충돌하지 않는다(read_line 진입 전 = 화면 소유자 없음).
/// 활성 여부는 호출 측이 `statusbar_enabled()`로 판단(샘플링 비용 회피).
pub(crate) fn print_status_bar(line: &str) {
    eprintln!("{}", paint(&format!("· {line}"), "2")); // 2 = dim
}

/// banner 라인들. rich면 ASCII art, 아니면 plain 1줄. 순수 함수(테스트 가능).
pub(crate) fn banner_lines(rich: bool) -> Vec<String> {
    if rich {
        // figlet 'aic' + 옆에 미니 봇 마스코트(머리/눈/턱). chat 라벨은 눈 줄에 둔다.
        vec![
            r"   __ _ (_)  ___      ▗▄▖".to_string(),
            format!(
                r"  / _` || | / __|     ▌◉ ◉▌   chat v{}",
                env!("CARGO_PKG_VERSION")
            ),
            r" | (_| || || (__      ▝▀▀▘".to_string(),
            r"  \__,_||_| \___|".to_string(),
        ]
    } else {
        vec![format!(
            "aic chat v{} — agentic SRE assistant",
            env!("CARGO_PKG_VERSION")
        )]
    }
}

/// 상태줄 라인들(ANSI 없음 — prefix/색상은 출력 시 부착). 순수 함수(테스트 가능).
pub(crate) fn status_lines(info: &StatusInfo, width: usize) -> Vec<String> {
    let (tools_full, tool_count) = match info.run_state {
        RunState::On => ("read_file list_dir grep glob run_command", 5),
        RunState::ReadOnly => ("read_file list_dir grep glob", 4),
    };

    if is_compact(width) {
        let mode = match info.run_state {
            RunState::On => "SRE · run_command on",
            RunState::ReadOnly => "read-only · run_command off",
        };
        let toggle = match info.run_state {
            RunState::On => "off: --no-run",
            RunState::ReadOnly => "on: drop --no-run + unset AIC_AGENT_NO_RUN",
        };
        return vec![
            format!("aic chat · {mode} · tools={tool_count}"),
            toggle.to_string(),
        ];
    }

    let mut lines = Vec::new();
    match info.run_state {
        RunState::On => {
            lines.push("aic chat · SRE mode (run_command on)".to_string());
            lines.push(format!("tools: {tools_full}"));
            lines.push(
                "policy: Safe→auto · NeedsConfirm→confirm(y/N) · Dangerous/Unknown→block"
                    .to_string(),
            );
        }
        RunState::ReadOnly => {
            lines.push("aic chat · read-only mode (run_command off)".to_string());
            lines.push(format!("tools: {tools_full}"));
        }
    }

    // cwd는 단축(~/…/마지막2), provider/model은 한 줄로 합쳐 dim 메타 한 줄에 담는다.
    let mut meta = shorten_path(&info.cwd);
    match (&info.provider, &info.model) {
        (Some(p), Some(m)) => meta.push_str(&format!(" · {p}/{m}")),
        (Some(p), None) => meta.push_str(&format!(" · {p}")),
        (None, Some(m)) => meta.push_str(&format!(" · {m}")),
        (None, None) => {}
    }
    lines.push(meta);

    lines.push(match info.run_state {
        RunState::On => "off: aic chat --no-run  (or AIC_AGENT_NO_RUN=1)".to_string(),
        RunState::ReadOnly => {
            "on: run `aic chat` without --no-run/--read-only and unset AIC_AGENT_NO_RUN".to_string()
        }
    });
    lines
}

/// cwd를 status 메타용으로 짧게: home은 `~`로, 4단계보다 깊으면 `~/…/마지막2`로 줄인다.
/// 순수 함수(테스트 가능). home 판정 실패 시 원문 유지.
fn shorten_path(path: &str) -> String {
    let p = match dirs::home_dir() {
        Some(h) => {
            let h = h.display().to_string();
            path.strip_prefix(&h)
                .map(|r| format!("~{r}"))
                .unwrap_or_else(|| path.to_string())
        }
        None => path.to_string(),
    };
    let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() > 3 {
        let lead = if p.starts_with('~') { "~" } else { "" };
        format!(
            "{lead}/…/{}/{}",
            parts[parts.len() - 2],
            parts[parts.len() - 1]
        )
    } else {
        p
    }
}

/// 대화형 입력 프롬프트 라벨.
///
/// 라인 에디터(reedline)가 실제로 활성화되는 조건(stdin && stdout 모두 interactive)과 **동일하게**
/// 판정해야 한다. 그렇지 않으면 비대화형 fallback 경로(stdout으로 prompt 출력)에서
/// Unicode 라벨이 stdout에 섞여 stdout-stderr 분리가 깨진다.
/// interactive가 아니면 단순 ASCII(`you> `)로 fallback한다.
pub(crate) fn prompt_label() -> &'static str {
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        "◇ you ❯ "
    } else {
        "you> "
    }
}

/// banner + status를 stderr로 출력한다(TTY/색상/폭 자동 처리).
pub(crate) fn print_banner_and_status(info: &StatusInfo) {
    eprint!("{}", format_banner_and_status(info));
}

/// banner + status를 ANSI 문자열로 만든다(각 줄 끝 `\n`). 전면 TUI(alternate screen)는 시작 배너가
/// 화면에 안 보이므로, 이 문자열을 대화 로그에 넣어 표시한다(RFC-004 step 8 후속). 색은 동일 정책.
pub(crate) fn format_banner_and_status(info: &StatusInfo) -> String {
    let rich = is_tty();
    let color = color_enabled();
    let mut out = String::new();
    for l in banner_lines(rich) {
        out.push_str(&paint_if(&l, "36;1", color)); // cyan bold
        out.push('\n');
    }
    // rich 배너에는 tagline 한 줄(dim). plain 배너는 한 줄 안에 이미 tagline을 포함한다.
    if rich {
        out.push_str(&paint_if("  agentic SRE assistant", "2", color));
        out.push('\n');
    }
    // status: 첫 줄(mode)은 cyan으로 강조해 위계를 주고, 나머지(tools/meta/toggle)는 dim.
    let bar = paint_if("▌", "2", color);
    for (i, l) in status_lines(info, term_width()).into_iter().enumerate() {
        let code = if i == 0 { "36" } else { "2" };
        out.push_str(&format!("{bar} {}\n", paint_if(&l, code, color)));
    }
    out
}

/// 런타임 상태 변경(예: provider degrade)을 status 줄 스타일로 stderr에 출력한다.
pub(crate) fn print_status_note(note: &str) {
    let color = color_enabled();
    let bar = paint_if("▌", "33", color); // yellow bar
    eprintln!("{bar} {}", paint_if(note, "33", color));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(run_state: RunState) -> StatusInfo {
        StatusInfo {
            run_state,
            cwd: "/tmp/proj".to_string(),
            provider: Some("ai-mesh".to_string()),
            model: Some("claude-haiku".to_string()),
        }
    }

    #[test]
    fn banner_rich_is_multiline_plain_is_one_line() {
        assert!(banner_lines(true).len() >= 3);
        let plain = banner_lines(false);
        assert_eq!(plain.len(), 1);
        assert!(plain[0].contains("aic chat"));
    }

    #[test]
    fn paint_respects_color_flag() {
        assert_eq!(paint_if("x", "1", false), "x");
        assert_eq!(paint_if("x", "1", true), "\x1b[1mx\x1b[0m");
    }

    #[test]
    fn banner_suppressed_when_either_flag_on() {
        assert!(!banner_suppressed_from(false, false), "기본은 배너 표시");
        assert!(banner_suppressed_from(true, false), "AIC_NO_BANNER → 생략");
        assert!(banner_suppressed_from(false, true), "AIC_QUIET → 생략");
        assert!(banner_suppressed_from(true, true));
    }

    #[test]
    fn compact_threshold() {
        assert!(is_compact(40));
        assert!(is_compact(63));
        assert!(!is_compact(64));
        assert!(!is_compact(120));
    }

    #[test]
    fn status_full_on_lists_run_command_and_policy() {
        let lines = status_lines(&info(RunState::On), 120);
        let joined = lines.join("\n");
        assert!(joined.contains("run_command on"));
        assert!(joined.contains("run_command")); // tools 목록
        assert!(joined.contains("policy:"));
        // meta: cwd 단축(여기선 짧아 원문) + provider/model 합침("ai-mesh/claude-haiku").
        assert!(joined.contains("/tmp/proj"));
        assert!(joined.contains("ai-mesh/claude-haiku"));
        assert!(joined.contains("--no-run"));
    }

    #[test]
    fn status_full_readonly_omits_run_command() {
        let lines = status_lines(&info(RunState::ReadOnly), 120);
        let joined = lines.join("\n");
        assert!(joined.contains("read-only"));
        assert!(joined.contains("run_command off"));
        // tools 목록에 run_command가 없어야 한다.
        let tools_line = lines.iter().find(|l| l.starts_with("tools:")).unwrap();
        assert!(!tools_line.contains("run_command"));
        // 다시 켜는 안내(env unset 포함).
        assert!(joined.contains("AIC_AGENT_NO_RUN"));
    }

    #[test]
    fn status_compact_is_two_lines_with_tool_count() {
        let on = status_lines(&info(RunState::On), 40);
        assert_eq!(on.len(), 2);
        assert!(on[0].contains("tools=5"));
        let ro = status_lines(&info(RunState::ReadOnly), 40);
        assert!(ro[0].contains("tools=4"));
    }

    #[test]
    fn prompt_label_nonempty() {
        // TTY 여부와 무관하게 비어있지 않은 라벨.
        assert!(!prompt_label().is_empty());
    }

    #[test]
    fn prompt_label_is_ascii_fallback_when_not_interactive() {
        // cargo test 환경은 stdin/stdout이 비-TTY이므로 ASCII fallback이어야 한다.
        // (stdout으로 Unicode 프롬프트가 새는 것을 방지 — finding 1.)
        let label = prompt_label();
        assert_eq!(label, "you> ");
        assert!(label.is_ascii(), "non-interactive 프롬프트는 ASCII여야 함");
    }
}
