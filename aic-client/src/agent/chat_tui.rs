//! RFC-004 ratatui chat TUI (단계 2 골격) — Inline viewport + 하단 고정 status bar + tui-textarea 입력.
//!
//! reedline 라인 모드의 **TTY 대체**. 동기 `event::poll` 루프(top.rs 패턴)라 crossterm event-stream
//! feature가 불필요하고, status bar는 poll 주기로 갱신되어 **타이핑 중에도 흐른다**(0.9.0의 입력경계/
//! spinner-구간 갱신 한계 해소). Viewport::Inline이라 대화 로그는 `insert_before`로 scrollback에 보존된다.
//!
//! 단계 2 범위: 입력 1줄 받기(`read_line_tui`) + status bar 렌더. LLM 호출/로그 insert_before/slash
//! popup/history는 단계 3~6에서 session과 통합한다. non-TTY는 호출 측이 기존 `repl::LineReader`로 fallback.

use std::io::{self};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Stylize;
use ratatui::widgets::Paragraph;
use ratatui::{backend::CrosstermBackend, Frame, Terminal, TerminalOptions, Viewport};
use tui_textarea::TextArea;

use super::sys_sampler::SysSampler;

/// 한 입력의 결과(reedline `ReadLine` 대응).
pub(crate) enum ChatLine {
    Line(String),
    Eof,
}

/// Inline viewport(2줄)에 status bar(위) + 입력(아래)을 그린다. 순수 함수(TestBackend로 테스트).
pub(crate) fn draw_viewport(f: &mut Frame, status: &str, textarea: &TextArea, prompt: &str) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(f.area());
    f.render_widget(Paragraph::new(status.to_string()).dim(), rows[0]);
    // 입력 줄: prompt + textarea를 가로로.
    let input_cols =
        Layout::horizontal([Constraint::Length(prompt.len() as u16), Constraint::Min(0)])
            .split(rows[1]);
    f.render_widget(Paragraph::new(prompt.to_string()), input_cols[0]);
    f.render_widget(textarea, input_cols[1]);
}

/// status bar가 흐르는 한 줄 입력. TTY 전용(호출 측이 TTY 확인 후 사용).
/// `sampler`가 Some이면 2초마다 지표 갱신. Enter=제출, Ctrl+D/Ctrl+C=EOF.
pub(crate) fn read_line_tui(
    prompt: &str,
    sampler: &mut Option<SysSampler>,
) -> io::Result<ChatLine> {
    enable_raw_mode()?;
    let mut terminal = Terminal::with_options(
        CrosstermBackend::new(io::stdout()),
        TerminalOptions {
            viewport: Viewport::Inline(2),
        },
    )?;
    let mut textarea = TextArea::default();
    let mut status = String::from("· (collecting metrics…)");
    let mut last = Instant::now();

    let outcome = loop {
        if let Some(s) = sampler.as_mut() {
            if last.elapsed().as_secs() >= 2 || status.starts_with("· (") {
                status = format!("· {}", s.sample().status_line());
                last = Instant::now();
            }
        }
        if terminal
            .draw(|f| draw_viewport(f, &status, &textarea, prompt))
            .is_err()
        {
            break ChatLine::Eof;
        }
        // 입력 없으면 200ms 후 다시 그려 status가 흐르게 한다.
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                match (k.code, k.modifiers) {
                    (KeyCode::Char('d') | KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        break ChatLine::Eof
                    }
                    (KeyCode::Enter, _) => break ChatLine::Line(textarea.lines().join("\n")),
                    _ => {
                        textarea.input(k);
                    }
                }
            }
        }
    };

    // viewport 정리 + raw mode 해제. (입력 echo·로그 insert_before는 단계 4에서 session과 통합)
    let _ = terminal.clear();
    disable_raw_mode()?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn draw_viewport_renders_status_and_prompt() {
        let mut ta = TextArea::default();
        ta.insert_str("hello");
        let mut term = Terminal::new(TestBackend::new(40, 2)).unwrap();
        term.draw(|f| draw_viewport(f, "· load 1.0 cpu 5%", &ta, "you ❯ "))
            .unwrap();
        let buf = term.backend().buffer();
        let row0: String = (0..40).map(|x| buf[(x, 0)].symbol()).collect();
        let row1: String = (0..40).map(|x| buf[(x, 1)].symbol()).collect();
        assert!(row0.contains("load 1.0"), "status row: {row0:?}");
        assert!(row1.contains("you"), "input row: {row1:?}");
        assert!(row1.contains("hello"), "input row: {row1:?}");
    }
}
