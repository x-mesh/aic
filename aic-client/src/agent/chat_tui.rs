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

use ansi_to_tui::IntoText;
use ratatui::backend::Backend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Stylize;
use ratatui::text::Text;
use ratatui::widgets::{Paragraph, Widget, Wrap};
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

// ─── 단계 4a: ANSI 출력 → insert_before (height 단일 계산) ──────────────────────
//
// LLM 답변·tool 카드는 ANSI escape(색)가 섞인 문자열이다. ratatui `insert_before`는 `Buffer`에
// 그리므로 ANSI를 직접 못 받는다 → `ansi-to-tui`로 `Text`(스타일 보존)로 변환한다. 또한
// `insert_before(height, …)`는 비워둘 **줄 수**를 미리 줘야 하므로, **실제 렌더와 같은 wrap**으로
// 줄 수를 세는 게 핵심이다(어긋나면 viewport와 겹치거나 잘림). 그래서 answer/note/echo가 모두
// 이 한 함수를 통과하게 강제한다(RFC-004 §height 계산, critic M1).

/// ANSI 문자열을 ratatui `Paragraph`(스타일 보존)로 변환하고, `width`로 wrap한 **줄 수**를 함께
/// 돌려준다. 줄 수는 ratatui가 실제 렌더에 쓰는 `Paragraph::line_count`(unstable-rendered-line-info)로
/// 계산해 `insert_before`가 비워둘 영역과 정확히 일치시킨다. ANSI 파싱 실패(드묾)는 plain 텍스트로
/// 폴백한다(escape가 그대로 보일 수 있으나 패닉/누락은 없음). height·width는 최소 1로 clamp한다.
fn ansi_to_paragraph(ansi: &str, width: u16) -> (Paragraph<'static>, u16) {
    let text: Text<'static> = ansi
        .into_text()
        .unwrap_or_else(|_| Text::raw(ansi.to_string()));
    let para = Paragraph::new(text).wrap(Wrap { trim: false });
    let height = para.line_count(width.max(1)).max(1) as u16;
    (para, height)
}

/// ANSI 출력 한 블록을 viewport **위쪽 scrollback**에 삽입한다(터미널이 보존·스크롤하므로 자체 로그
/// 위젯 불필요). height는 [`ansi_to_paragraph`]가 wrap 줄 수로 계산해 viewport와 겹치지 않는다.
/// 단계 4b의 `ChatLoop`가 `OutMsg::Answer`/`Note`·입력 echo 처리에서 호출한다.
pub(crate) fn insert_before_ansi<B: Backend>(
    terminal: &mut Terminal<B>,
    ansi: &str,
    width: u16,
) -> io::Result<()> {
    let (para, height) = ansi_to_paragraph(ansi, width);
    terminal.insert_before(height, |buf| {
        let area = buf.area;
        para.render(area, buf);
    })
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

    // ─── 단계 4a: ansi_to_paragraph height 계산(insert_before 정확도) ──────────
    // height 오차 = viewport 겹침/잘림. ratatui line_count가 실제 렌더 wrap과 1:1이어야 한다.

    fn h(ansi: &str, width: u16) -> u16 {
        super::ansi_to_paragraph(ansi, width).1
    }

    #[test]
    fn height_ascii_wrap_boundaries() {
        assert_eq!(h("hello", 80), 1, "짧은 한 줄");
        assert_eq!(h(&"a".repeat(80), 80), 1, "정확히 폭만큼 = 1줄");
        assert_eq!(h(&"a".repeat(81), 80), 2, "폭+1 = 2줄");
        assert_eq!(h(&"a".repeat(100), 80), 2, "100자/폭80 = 2줄");
    }

    #[test]
    fn height_cjk_uses_cell_width() {
        // '가'=display width 2. wrap은 cell 폭 기준이어야 한다(byte/char 아님).
        assert_eq!(h(&"가".repeat(40), 80), 1, "80 cells = 1줄");
        assert_eq!(h(&"가".repeat(41), 80), 2, "82 cells/폭80 = 2줄");
        assert_eq!(h(&"가".repeat(50), 80), 2, "100 cells = 2줄");
    }

    #[test]
    fn height_blank_lines_and_trailing_newline() {
        assert_eq!(h("a\n\nb", 80), 3, "빈 줄 보존 = 3줄");
        // trailing newline off-by-one 함정: ratatui line_count는 마지막 빈 줄을 세지 않는다.
        assert_eq!(h("a\n", 80), 1, "trailing nl은 추가 줄로 세지 않음");
        assert_eq!(h("a\nb", 80), 2);
    }

    #[test]
    fn height_tab_and_control_do_not_panic() {
        assert!(h("a\tb\tc", 80) >= 1, "tab 포함 패닉 없음");
        assert!(h("\x1b[Kresidual", 80) >= 1, "잔존 제어 시퀀스 패닉 없음");
        assert!(h("", 80) >= 1, "빈 입력도 최소 1줄");
        assert!(h("x", 0) >= 1, "width 0도 패닉 없이 최소 1");
    }

    #[test]
    fn ansi_color_is_parsed_to_style() {
        // \x1b[34m(파랑)이 Text span style로 보존되어야 insert_before에 색이 남는다.
        let t = "\x1b[34mblue\x1b[0m".into_text().unwrap();
        let span = &t.lines[0].spans[0];
        assert_eq!(span.content, "blue");
        assert_eq!(span.style.fg, Some(ratatui::style::Color::Blue));
    }

    #[test]
    fn insert_before_ansi_renders_into_scrollback() {
        // TestBackend로 insert_before가 패닉 없이 동작하고 내용이 backend에 남는지 확인.
        let mut term = Terminal::with_options(
            TestBackend::new(20, 3),
            TerminalOptions {
                viewport: Viewport::Inline(1),
            },
        )
        .unwrap();
        super::insert_before_ansi(&mut term, "\x1b[34mhi\x1b[0m", 20).unwrap();
        // 패닉 없이 완료되면 통과(실제 scrollback 픽셀 검증은 4b 실터미널).
    }
}
