//! RFC-004 ratatui chat TUI (단계 8) — alternate screen 전면 TUI + 대화 로그 스크롤 버퍼.
//!
//! reedline 라인 모드의 **TTY 대체**. `chat_loop`는 EnterAlternateScreen + raw mode로 전체 화면을
//! 단독 소유하고, 대화 로그를 자체 스크롤 버퍼(`log: Vec<String>` 원본 ANSI)로 관리한다.
//! `EventStream` + `tokio::select!`(키 / status·spinner tick / out_rx)로 입력·지표·답변을 처리한다.
//! status bar는 tick으로 갱신되어 타이핑 중에도 흐른다. 종료 시 alternate screen을 떠나고 로그를 stdout에
//! dump해 터미널 scrollback에 보존한다(8e, 원본 ANSI라 색 그대로).
//!
//! 단계 2~7의 Inline viewport + `insert_before` 모델(`read_line_tui`/`insert_before_ansi`/`draw_chat`/
//! `draw_viewport`/`draw_viewport_popup`/`ansi_to_paragraph`/`draw_thinking`)은 전면 TUI 전환 후
//! 미사용이나, height 계산·테스트 자산으로 보존한다(모듈 `#[allow(dead_code)]`). non-TTY는 호출
//! 측(session)이 `ChatOut::Direct`(reedline/stdin)로 fallback한다.

use std::io::{self};
use std::time::{Duration, Instant};

use ansi_to_tui::IntoText;
use crossterm::event::EventStream;
use futures::StreamExt;
use ratatui::backend::Backend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Widget, Wrap};
use ratatui::{backend::CrosstermBackend, Frame, Terminal, TerminalOptions, Viewport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tui_textarea::TextArea;
use unicode_width::UnicodeWidthStr;

use super::sys_sampler::SysSampler;

/// 한 입력의 결과(reedline `ReadLine` 대응).
pub(crate) enum ChatLine {
    Line(String),
    Eof,
}

/// Inline viewport(2줄)에 입력(위) + status bar(아래)를 그린다. 순수 함수(TestBackend로 테스트).
/// claude CLI 스타일: 입력창 바로 아래에 상태바를 둬 화면 맨 아래에 고정한다.
pub(crate) fn draw_viewport(f: &mut Frame, status: &str, textarea: &TextArea, prompt: &str) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(f.area());
    // 입력 줄(위): prompt + textarea를 가로로. prompt 폭은 byte가 아닌 **display width**로 잡는다
    // (◇/❯는 3바이트 1~2셀 — byte로 잡으면 입력이 과도하게 밀린다).
    let prompt_w = UnicodeWidthStr::width(prompt) as u16;
    let input_cols =
        Layout::horizontal([Constraint::Length(prompt_w), Constraint::Min(0)]).split(rows[0]);
    f.render_widget(Paragraph::new(prompt.to_string()), input_cols[0]);
    f.render_widget(textarea, input_cols[1]);
    // status bar(아래, 화면 맨 아래 고정).
    f.render_widget(Paragraph::new(status.to_string()).dim(), rows[1]);
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

// ─── 단계 4b: ChatLoop — terminal 단독 소유 task + EventStream select! 루프 ─────
//
// terminal을 만지는 주체를 이 task 하나로 한정한다(Arc/Mutex/Rc 없음 → Send 위반·데드락 구조적
// 제거, RFC-004 critic B1/B2). session은 채널 핸들(Send)만 들고: 입력은 line_rx로 받고, 답변/카드/
// spinner 토글은 out_tx로 보낸다. status bar tick은 이 루프가 독립적으로 돌려 LLM await 중에도 흐른다.

/// session → ChatLoop 메시지.
pub(crate) enum OutMsg {
    /// LLM 답변 블록(ANSI 포함) → viewport 위 scrollback에 insert_before.
    Answer(String),
    /// UI/tool 카드/슬래시 출력(ANSI 포함) → insert_before(answer와 동일 경로, 의미 구분만).
    Note(String),
    /// thinking 표시 시작(라벨). viewport 입력 줄을 spinner 줄로 대체한다.
    SpinStart(String),
    /// thinking 표시 종료 → 입력 줄 복귀.
    SpinStop,
    /// 컨텍스트 토큰 추정치(history 문자 수/4) → status bar 끝에 ` · ctx ~Nk` 표시.
    Ctx(usize),
    /// NeedsConfirm 명령 확인 요청. prompt(예: `⚠ … 실행? [y/N]`)를 입력 줄에 띄우고,
    /// y/Y면 true·그 외 키(n/N/Esc/Enter/…)면 false를 oneshot으로 회신한다(기본 거부).
    Confirm(String, tokio::sync::oneshot::Sender<bool>),
    /// 루프 종료 — raw mode 복원 후 task 종료.
    Shutdown,
}

/// session이 ChatLoop와 통신하는 핸들. terminal은 task가 소유하므로 여기엔 채널만 있다.
pub(crate) struct ChatHandle {
    line_rx: mpsc::Receiver<ChatLine>,
    out_tx: mpsc::Sender<OutMsg>,
    join: JoinHandle<()>,
}

impl ChatHandle {
    /// 입력 한 줄을 받는다(ChatLoop가 Enter로 보냄). 채널이 닫히면 EOF로 본다.
    pub(crate) async fn recv_line(&mut self) -> ChatLine {
        self.line_rx.recv().await.unwrap_or(ChatLine::Eof)
    }

    /// 출력/스핀 메시지를 보낸다(채널이 닫혔으면 무시 — 종료 중).
    pub(crate) async fn send(&self, msg: OutMsg) {
        let _ = self.out_tx.send(msg).await;
    }

    /// 출력 송신단을 복제한다 — session의 `ChatOut::Tui`가 답변/spin을 직접 보내게 한다.
    pub(crate) fn out_sender(&self) -> mpsc::Sender<OutMsg> {
        self.out_tx.clone()
    }

    /// 종료: Shutdown 후 task join으로 raw mode 복원을 보장한다.
    pub(crate) async fn shutdown(self) {
        let _ = self.out_tx.send(OutMsg::Shutdown).await;
        let _ = self.join.await;
    }
}

/// 전면 TUI(alternate screen) + raw mode에서 패닉이 나도 터미널을 복원하도록 패닉 훅을 1회 설치한다
/// (m5). LeaveAlternateScreen + disable_raw_mode로 원래 화면을 되돌린 뒤 기존 훅을 호출한다(panic
/// 메시지·backtrace 유지).
fn install_panic_hook() {
    use std::sync::Once;
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            let _ = disable_raw_mode();
            prev(info);
        }));
    });
}

/// ChatLoop task를 띄우고 핸들을 돌려준다. TTY 전용(호출 측이 확인). `with_statusbar`면 2초마다
/// 시스템 지표를 status bar에 갱신한다(non-TTY/opt-out은 호출 측에서 Direct 경로로 우회).
pub(crate) fn start_chat_loop(prompt: String, with_statusbar: bool) -> ChatHandle {
    install_panic_hook();
    let (line_tx, line_rx) = mpsc::channel::<ChatLine>(8);
    let (out_tx, out_rx) = mpsc::channel::<OutMsg>(32);
    let join = tokio::spawn(chat_loop(line_tx, out_rx, prompt, with_statusbar));
    ChatHandle {
        line_rx,
        out_tx,
        join,
    }
}

const SPIN_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// thinking 표시 상태(spinner 애니메이션 프레임 + 경과).
struct SpinState {
    label: String,
    frame: usize,
    started: Instant,
}

/// 주어진 내용으로 새 `TextArea`를 만든다(커서는 끝). history(↑↓) 탐색 시 입력 줄 교체용.
fn textarea_with(content: &str) -> TextArea<'static> {
    let mut ta = TextArea::default();
    ta.insert_str(content);
    ta
}

/// 단계 6: 입력이 `/명령`(공백 전, 첫 토큰)이면 매칭되는 slash 후보를 돌려준다(자동완성 popup용).
/// `/`가 아니거나 인자 입력 중(공백 포함)이면 빈 vec → popup 미표시.
fn slash_candidates(input: &str) -> Vec<&'static str> {
    let Some(rest) = input.strip_prefix('/') else {
        return Vec::new();
    };
    if rest.contains(char::is_whitespace) {
        return Vec::new();
    }
    super::tool_record::SLASH_COMMANDS
        .iter()
        .filter(|c| c.starts_with(rest))
        .copied()
        .collect()
}

/// slash 명령 카테고리별 표시 색(popup 가시성, 과하지 않게 4색).
/// Diagnostics=노랑 · System=cyan · Evidence=초록 · Meta=회색.
fn slash_category_color(name: &str) -> Color {
    match super::tool_record::slash_category(name) {
        "Diagnostics" => Color::Yellow,
        "System" => Color::Cyan,
        "Evidence" => Color::Green,
        _ => Color::Gray, // Meta(help 등)
    }
}

/// popup(slash 후보) 활성 시 viewport: 입력 줄(위) + 후보 1줄(아래, status 자리). 선택은 reverse,
/// 나머지는 dim. ratatui Inline은 동적 높이가 없어 status를 잠시 후보로 대체한다(`/` 입력 중에만).
fn draw_viewport_popup(
    f: &mut Frame,
    popup: &[&str],
    sel: usize,
    textarea: &TextArea,
    prompt: &str,
) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(f.area());
    // 입력 줄(위) — draw_viewport와 동일.
    let prompt_w = UnicodeWidthStr::width(prompt) as u16;
    let input_cols =
        Layout::horizontal([Constraint::Length(prompt_w), Constraint::Min(0)]).split(rows[0]);
    f.render_widget(Paragraph::new(prompt.to_string()), input_cols[0]);
    f.render_widget(textarea, input_cols[1]);
    // 후보 줄(아래): "▸ /local /diagnose …" — sel은 reverse, 나머지 dim.
    let mut spans = vec![Span::raw("▸ ")];
    for (i, c) in popup.iter().enumerate() {
        let style = if i == sel {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        };
        spans.push(Span::styled(format!("/{c}"), style));
        spans.push(Span::raw("  "));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), rows[1]);
}

/// slash popup ↑↓ 순환 범위 상한(표시는 1줄에 선택 항목만).
const MAX_POPUP: usize = 16;

/// chat viewport(3줄 고정)를 그린다. 위→아래: 입력/thinking · (구분선 또는 slash popup) · status.
/// claude CLI 스타일(입력 위, status 맨 아래). popup 활성 시 가운데 줄을 "▸ /명령  설명  (n/m)"으로
/// 토글한다(↑↓로 후보 순환). 동적 높이를 안 써 잔상이 없다(ratatui Inline 한계 회피).
fn draw_chat(
    f: &mut Frame,
    status: &str,
    textarea: &TextArea,
    prompt: &str,
    popup: &[&str],
    popup_sel: usize,
    spin: Option<&SpinState>,
) {
    let rows = Layout::vertical([
        Constraint::Length(1), // 입력/thinking
        Constraint::Length(1), // 구분선 또는 popup
        Constraint::Length(1), // status(맨 아래)
    ])
    .split(f.area());

    // 입력 줄 or thinking(맨 위).
    match spin {
        Some(sp) => {
            let frame = SPIN_FRAMES[sp.frame % SPIN_FRAMES.len()];
            let secs = sp.started.elapsed().as_secs_f32();
            f.render_widget(
                Paragraph::new(format!("{frame} {} ({secs:.1}s)", sp.label)).dim(),
                rows[0],
            );
        }
        None => {
            let prompt_w = UnicodeWidthStr::width(prompt) as u16;
            let cols = Layout::horizontal([Constraint::Length(prompt_w), Constraint::Min(0)])
                .split(rows[0]);
            f.render_widget(Paragraph::new(prompt.to_string()), cols[0]);
            f.render_widget(textarea, cols[1]);
        }
    }

    // 가운데 줄: popup 활성(입력 중)이면 선택 후보+설명, 아니면 구분선.
    if spin.is_none() && !popup.is_empty() {
        let sel = popup[popup_sel];
        let desc = super::tool_record::slash_description(sel);
        let counter = if popup.len() > 1 {
            format!("  ({}/{} ↑↓)", popup_sel + 1, popup.len())
        } else {
            String::new()
        };
        let line = Line::from(vec![
            Span::raw("▸ "),
            Span::styled(format!("/{sel}"), Style::default().add_modifier(Modifier::REVERSED)),
            Span::raw(format!("  {desc}")),
            Span::styled(counter, Style::default().add_modifier(Modifier::DIM)),
        ]);
        f.render_widget(Paragraph::new(line), rows[1]);
    } else {
        let sep = "─".repeat(f.area().width as usize);
        f.render_widget(Paragraph::new(sep).dim(), rows[1]);
    }

    // status(맨 아래).
    f.render_widget(Paragraph::new(status.to_string()).dim(), rows[2]);
}

// ─── 단계 8: 전면 TUI(alternate screen) — 대화 로그 스크롤 버퍼 + 동적 세로 popup ───────

/// 로그 Paragraph의 wrap 후 총 화면 줄 수 기준 scroll 최대값(= total - height, 음수면 0).
/// `Paragraph::scroll`은 wrap 후 화면 줄 기준이므로 이 값으로 scroll을 clamp하면 정합한다(critic B1).
fn log_scroll_max(log_text: &Text, width: u16, height: u16) -> u16 {
    let total = Paragraph::new(log_text.clone())
        .wrap(Wrap { trim: false })
        .line_count(width.max(1)) as u16;
    total.saturating_sub(height)
}

/// 전면 TUI 한 프레임(순수 함수, TestBackend로 검증). 위→아래:
/// 대화 로그(스크롤) · slash popup(세로, 입력 위 조건부) · 입력/thinking · 구분선 · status.
/// 로그는 `Paragraph.wrap.scroll`로 그려 wrap/offset이 자동 정합(critic B1). popup 높이는
/// 가용 공간으로 clamp(작은 터미널 붕괴 방지, critic M3). 로그 영역 Min은 1 이상 보장.
#[allow(clippy::too_many_arguments)]
fn draw_full(
    f: &mut Frame,
    log_text: &Text,
    scroll: u16,
    status: &str,
    textarea: &TextArea,
    prompt: &str,
    popup: &[&str],
    popup_sel: usize,
    spin: Option<&SpinState>,
    confirm: Option<&str>,
) {
    let area = f.area();
    // popup 높이: spin/confirm 중엔 0, 아니면 후보 수를 (가용 높이 - 입력1·구분선1·status1·로그1=4)로 clamp.
    let pop_n = if spin.is_some() || confirm.is_some() {
        0
    } else {
        popup.len().min(area.height.saturating_sub(4) as usize)
    };
    let rows = Layout::vertical([
        Constraint::Min(1),               // 대화 로그(스크롤)
        Constraint::Length(pop_n as u16), // slash popup(세로, 0이면 없음)
        Constraint::Length(1),            // 입력/thinking
        Constraint::Length(1),            // 구분선
        Constraint::Length(1),            // status
    ])
    .split(area);

    // 대화 로그: 내용이 영역보다 짧으면 **하단 정렬**(claude CLI식 — 입력 바로 위에 붙음), 길면 scroll.
    let log_area = rows[0];
    let para = Paragraph::new(log_text.clone()).wrap(Wrap { trim: false });
    let total = para.line_count(log_area.width.max(1)) as u16;
    if total < log_area.height {
        let bottom = Rect {
            x: log_area.x,
            y: log_area.y + (log_area.height - total),
            width: log_area.width,
            height: total,
        };
        f.render_widget(para, bottom);
    } else {
        f.render_widget(para.scroll((scroll, 0)), log_area);
    }

    // slash popup(세로 select box, 입력 위): "/명령(카테고리 색 bold)  설명(회색)", sel은 reverse.
    if pop_n > 0 {
        let items: Vec<ListItem> = popup
            .iter()
            .take(pop_n)
            .map(|c| {
                let desc = super::tool_record::slash_description(c);
                ListItem::new(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        format!("/{c:<13}"),
                        Style::default()
                            .fg(slash_category_color(c))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(desc.to_string(), Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();
        let list = List::new(items)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD));
        let mut state = ListState::default();
        state.select(Some(popup_sel.min(pop_n.saturating_sub(1))));
        f.render_stateful_widget(list, rows[1], &mut state);
    }

    // 입력 줄: confirm(확인 프롬프트, 노랑) > thinking(spinner) > 일반 입력 순.
    match (confirm, spin) {
        // 확인 대기: 입력 줄 전체를 노란색 prompt로 대체(가시성↑). textarea는 그리지 않는다.
        (Some(c), _) => {
            f.render_widget(
                Paragraph::new(c.to_string()).style(Style::default().fg(Color::Yellow)),
                rows[2],
            );
        }
        (None, Some(sp)) => {
            let frame = SPIN_FRAMES[sp.frame % SPIN_FRAMES.len()];
            let secs = sp.started.elapsed().as_secs_f32();
            f.render_widget(
                Paragraph::new(format!("{frame} {} ({secs:.1}s)", sp.label)).dim(),
                rows[2],
            );
        }
        (None, None) => {
            let prompt_w = UnicodeWidthStr::width(prompt) as u16;
            let cols = Layout::horizontal([Constraint::Length(prompt_w), Constraint::Min(0)])
                .split(rows[2]);
            f.render_widget(Paragraph::new(prompt.to_string()), cols[0]);
            f.render_widget(textarea, cols[1]);
        }
    }

    // 구분선 + status.
    let sep = "─".repeat(area.width as usize);
    f.render_widget(Paragraph::new(sep).dim(), rows[3]);
    f.render_widget(Paragraph::new(status.to_string()).dim(), rows[4]);
}

/// thinking 표시: spinner 줄(위) + status 줄(아래). `draw_viewport`의 입력 줄을 대체한다.
/// 레이아웃은 draw_viewport와 동일하게 status를 맨 아래에 둔다(claude CLI 스타일).
fn draw_thinking(f: &mut Frame, status: &str, spin: &SpinState) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(f.area());
    let frame = SPIN_FRAMES[spin.frame % SPIN_FRAMES.len()];
    let secs = spin.started.elapsed().as_secs_f32();
    f.render_widget(
        Paragraph::new(format!("{frame} {} ({secs:.1}s)", spin.label)).dim(),
        rows[0],
    );
    f.render_widget(Paragraph::new(status.to_string()).dim(), rows[1]);
}

/// 대화 로그 ring 상한(줄 수). 초과 시 앞에서 폐기하고 scroll을 보정한다(critic M2). LLM 답변은
/// 보통 수십 줄이라 수천 줄이면 긴 세션도 충분하면서 메모리 폭주는 막는다.
const LOG_CAP: usize = 2000;

/// `log`(원본 ANSI 줄 벡터)를 `Text`로 재구성한다(m3 캐시 갱신용). ANSI 파싱 실패 시 plain 폴백
/// (escape가 보일 수 있으나 패닉/누락 없음). 빈 로그는 빈 Text.
fn rebuild_log_text(log: &[String]) -> Text<'static> {
    let joined = log.join("\n");
    joined.into_text().unwrap_or_else(|_| Text::raw(joined))
}

/// draw_full 레이아웃과 동일한 공식으로 로그 영역 높이를 구한다(scroll clamp·follow를 draw와 정합
/// 시키기 위해 단일 소스). 전체 높이 - popup_n - 입력1 - 구분선1 - status1, 최소 1.
fn log_area_height(total_height: u16, popup_n: u16) -> u16 {
    total_height.saturating_sub(popup_n + 3).max(1)
}

/// status 문자열 끝에 컨텍스트 토큰 추정치를 ` · ctx ~Nk`로 덧붙인다(0이면 생략). 순수 함수.
/// N = tokens/1000(1000 단위 k 절삭). `~`로 추정 표기(provider usage가 아닌 문자수/4 추정).
fn status_with_ctx(status: &str, ctx_tokens: usize) -> String {
    if ctx_tokens == 0 {
        return status.to_string();
    }
    // 1000 미만은 `~512`처럼 정확한 수로(과거 `~0k`로 떠 '값 없음'처럼 보이던 문제), 이상은 `~12k`.
    let ctx = if ctx_tokens >= 1000 {
        format!("~{}k", ctx_tokens / 1000)
    } else {
        format!("~{ctx_tokens}")
    };
    format!("{status} · ctx {ctx}")
}

/// 검색 모드 search bar 텍스트(입력 줄 대체). `/{query}  (idx/total)`. hit가 없으면 `(0/0)`.
/// idx는 1-based로 표시(hit가 있을 때만). 순수 함수.
fn search_bar(query: &str, idx: usize, total: usize) -> String {
    let counter = if total == 0 {
        "(0/0)".to_string()
    } else {
        format!("({}/{})", idx + 1, total)
    };
    format!("/{query}  {counter}")
}

/// 검색 쿼리로 매칭되는 log 인덱스를 모은다(부분 문자열 포함). 빈 쿼리는 빈 vec. 순수 함수.
fn search_hits_for(log: &[String], query: &str) -> Vec<usize> {
    if query.is_empty() {
        return Vec::new();
    }
    log.iter()
        .enumerate()
        .filter(|(_, l)| l.contains(query))
        .map(|(i, _)| i)
        .collect()
}

/// ChatLoop 본체 — terminal 단독 소유. EnterAlternateScreen + enable_raw_mode로 전면 TUI에 진입하고,
/// 대화 로그를 자체 스크롤 버퍼(`log`)로 관리한다. `tokio::select!`로 (키 입력 / status·spinner tick /
/// 출력 메시지)를 한 곳에서 처리한다. 종료(Shutdown/stream EOF/draw 실패) 시 alternate screen을 떠나고
/// raw mode를 복원한 뒤, 대화 버퍼를 stdout에 dump해 터미널 scrollback에 보존한다(8e).
async fn chat_loop(
    line_tx: mpsc::Sender<ChatLine>,
    mut out_rx: mpsc::Receiver<OutMsg>,
    prompt: String,
    with_statusbar: bool,
) {
    if enable_raw_mode().is_err() {
        return;
    }
    if execute!(io::stdout(), EnterAlternateScreen).is_err() {
        let _ = disable_raw_mode();
        return;
    }
    let mut terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
        Ok(t) => t,
        Err(_) => {
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return;
        }
    };
    let mut textarea = TextArea::default();
    let mut events = EventStream::new();
    let mut sampler = with_statusbar.then(SysSampler::new);
    let mut status = String::from("· (collecting metrics…)");
    let mut last_sample = Instant::now();
    let mut spin: Option<SpinState> = None;
    // 대화 로그: 원본 ANSI 줄(dump용·색 보존, M1) + Text 캐시(m3, log 변경 시만 재구성).
    let mut log: Vec<String> = Vec::new();
    let mut log_text: Text<'static> = Text::default();
    // scroll=화면 줄 offset(wrap 후 기준). follow=true면 새 답변 도착 시 자동 최하단(m1).
    let mut scroll: u16 = 0;
    let mut follow = true;
    // 입력 history(reedline과 동일 파일 공유). hist_idx=탐색 위치, draft=탐색 전 편집 내용 보존.
    let mut history = crate::repl::load_chat_history();
    let mut hist_idx: Option<usize> = None;
    let mut draft = String::new();
    // slash 자동완성 popup 선택 인덱스(후보는 매 루프 입력에서 재계산).
    let mut popup_sel: usize = 0;
    // 컨텍스트 토큰 추정치(session이 OutMsg::Ctx로 push). status bar 끝에 ` · ctx ~Nk`로 표시.
    let mut ctx_tokens: usize = 0;
    // 로그 검색 모드(Ctrl+F): Some=검색 중(쿼리), hits=매칭 log 인덱스, idx=현재 hit.
    let mut search: Option<String> = None;
    let mut search_hits: Vec<usize> = Vec::new();
    let mut search_idx: usize = 0;
    // NeedsConfirm 확인 모드: Some(tx)면 확인 대기 중(입력 줄을 confirm_prompt로 대체, 키는 y/n 전용).
    let mut confirm_pending: Option<tokio::sync::oneshot::Sender<bool>> = None;
    let mut confirm_prompt = String::new();

    loop {
        // status 갱신(2초 주기 또는 최초). spinner 유무와 무관하게 흐른다.
        if let Some(s) = sampler.as_mut() {
            if last_sample.elapsed().as_secs() >= 2 || status.starts_with("· (") {
                status = format!("· {}", s.sample().status_line());
                last_sample = Instant::now();
            }
        }
        // slash 후보 popup 계산(입력이 `/명령` 첫 토큰일 때만). MAX_POPUP로 제한, sel 보정.
        let mut popup = slash_candidates(&textarea.lines().join("\n"));
        popup.truncate(MAX_POPUP);
        // 화면에 실제로 표시 가능한 수(pop_n)로 제한 — 작은 터미널에서 보이는 후보와 제출되는 후보가
        // 어긋나는 것을 막는다(codex P2: take(pop_n) 표시 vs popup[popup_sel] 제출 불일치).
        let area = terminal.get_frame().area();
        // 검색/확인 모드에선 slash popup을 막는다(우선순위: 확인>검색>popup, 입력 줄을 대체).
        let pop_n = if spin.is_some() || search.is_some() || confirm_pending.is_some() {
            0
        } else {
            popup.len().min(area.height.saturating_sub(4) as usize)
        };
        popup.truncate(pop_n);
        if popup.is_empty() {
            popup_sel = 0;
        } else if popup_sel >= popup.len() {
            popup_sel = popup.len() - 1;
        }

        // draw: 전면 레이아웃(로그·popup·입력·구분선·status). scroll clamp/follow를 draw_full
        // 내부 레이아웃과 동일 공식으로 계산해 정합시킨다(로그 높이 = 전체 - popup_n - 3).
        let spin_ref = spin.as_ref();
        let pop_n = pop_n as u16;
        let log_h = log_area_height(area.height, pop_n);
        let max = log_scroll_max(&log_text, area.width, log_h);
        if follow {
            scroll = max;
        } else {
            scroll = scroll.min(max);
        }
        let draw_scroll = scroll;
        // status 끝에 컨텍스트 토큰 추정치를 덧붙인다(0이면 생략).
        let status_line = status_with_ctx(&status, ctx_tokens);
        // 검색 모드면 입력 줄 대신 search bar(`/{query}  (idx/total)`)를 그린다(prompt는 빈 문자열로
        // 둬 textarea가 search bar 전체를 차지하게). popup은 위에서 막았고, spin도 검색 중엔 없다.
        let search_ta;
        let (draw_ta, draw_prompt): (&TextArea, &str) = match &search {
            Some(q) => {
                search_ta = textarea_with(&search_bar(q, search_idx, search_hits.len()));
                (&search_ta, "")
            }
            None => (&textarea, prompt.as_str()),
        };
        // 확인 모드면 draw_full이 입력 줄을 노란 prompt로 대체한다(spin/popup/search보다 우선).
        let confirm_ref = confirm_pending.as_ref().map(|_| confirm_prompt.as_str());
        let draw_ok = terminal
            .draw(|f| {
                draw_full(
                    f, &log_text, draw_scroll, &status_line, draw_ta, draw_prompt, &popup,
                    popup_sel, spin_ref, confirm_ref,
                )
            })
            .is_ok();
        if !draw_ok {
            break;
        }

        // tick: spinner 애니메이션 100ms(처리 중, 부드러운 회전), 평상시 status 흐름 1초.
        // status 숫자는 어차피 2초마다 갱신(sample)이고 키 입력은 이벤트 기반(즉시)이라, 평상시
        // redraw를 1초로 둬도 반응성·흐름에 영향 없이 아이들 wake를 줄인다.
        let tick = Duration::from_millis(if spin.is_some() { 100 } else { 1000 });
        // PageUp/Down 점프 폭(로그 높이의 절반, 최소 1).
        let page = (log_h / 2).max(1);

        tokio::select! {
            maybe_ev = events.next() => {
                match maybe_ev {
                    // NeedsConfirm 확인 모드(최우선): y/Y면 승인(true), 그 외 모든 키(n/N/Esc/Enter/…)는
                    // 거부(false). 입력 줄은 confirm_prompt로 대체되어 있고, textarea/slash/history/search는
                    // 전부 비활성이다. Ctrl+C/D도 확인을 거부(false)로 닫아 안전 기본값을 유지한다.
                    Some(Ok(Event::Key(k))) if confirm_pending.is_some() => {
                        let approved = matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y'));
                        if let Some(tx) = confirm_pending.take() {
                            let _ = tx.send(approved);
                        }
                        confirm_prompt.clear();
                    }
                    // 검색 모드(Ctrl+F): 입력 줄을 search bar로 대체하고 키를 검색에 전용한다.
                    // textarea 편집·slash popup·history ↑↓는 비활성(검색 우선). Ctrl+C/D는 항상 EOF.
                    Some(Ok(Event::Key(k))) if search.is_some() => {
                        let query = search.take().unwrap();
                        match (k.code, k.modifiers) {
                            (KeyCode::Char('c') | KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                                let _ = line_tx.send(ChatLine::Eof).await;
                                search = Some(query);
                            }
                            // Esc: 검색 종료(follow 복귀).
                            (KeyCode::Esc, _) => {
                                search = None;
                                search_hits.clear();
                                search_idx = 0;
                            }
                            // Enter/n: 다음 hit, N: 이전 hit. hit로 scroll 이동(follow 해제).
                            (KeyCode::Enter, _) | (KeyCode::Char('n'), _) => {
                                if !search_hits.is_empty() {
                                    search_idx = (search_idx + 1) % search_hits.len();
                                    follow = false;
                                    scroll = (search_hits[search_idx] as u16).min(max);
                                }
                                search = Some(query);
                            }
                            (KeyCode::Char('N'), _) => {
                                if !search_hits.is_empty() {
                                    search_idx = if search_idx == 0 {
                                        search_hits.len() - 1
                                    } else {
                                        search_idx - 1
                                    };
                                    follow = false;
                                    scroll = (search_hits[search_idx] as u16).min(max);
                                }
                                search = Some(query);
                            }
                            // Backspace: 쿼리 한 글자 삭제 → hits 재계산.
                            (KeyCode::Backspace, _) => {
                                let mut q = query;
                                q.pop();
                                search_hits = search_hits_for(&log, &q);
                                search_idx = 0;
                                if !search_hits.is_empty() {
                                    follow = false;
                                    scroll = (search_hits[0] as u16).min(max);
                                }
                                search = Some(q);
                            }
                            // 일반 문자: 쿼리에 append → hits 재계산, 첫 hit로 이동.
                            (KeyCode::Char(c), m)
                                if !m.contains(KeyModifiers::CONTROL)
                                    && !m.contains(KeyModifiers::ALT) =>
                            {
                                let mut q = query;
                                q.push(c);
                                search_hits = search_hits_for(&log, &q);
                                search_idx = 0;
                                if !search_hits.is_empty() {
                                    follow = false;
                                    scroll = (search_hits[0] as u16).min(max);
                                }
                                search = Some(q);
                            }
                            _ => {
                                search = Some(query);
                            }
                        }
                    }
                    Some(Ok(Event::Key(k))) => {
                        match (k.code, k.modifiers) {
                            (KeyCode::Char('c') | KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                                let _ = line_tx.send(ChatLine::Eof).await;
                            }
                            // Ctrl+F: 로그 검색 모드 진입(spin 없을 때만). 빈 쿼리로 시작.
                            (KeyCode::Char('f'), KeyModifiers::CONTROL) if spin.is_none() => {
                                search = Some(String::new());
                                search_hits.clear();
                                search_idx = 0;
                            }
                            // PageUp/Down: 로그 스크롤(popup 활성과 무관하게 동작 — ↑↓는 popup 우선,
                            // PageUp/Down은 항상 로그). PageUp이면 follow 해제, PageDown으로 최하단
                            // 도달 시 follow 재개(m1 불변식: scroll==max면 follow).
                            (KeyCode::PageUp, _) => {
                                follow = false;
                                scroll = scroll.saturating_sub(page);
                            }
                            (KeyCode::PageDown, _) => {
                                scroll = (scroll + page).min(max);
                                if scroll >= max {
                                    follow = true;
                                }
                            }
                            // slash popup 활성: Tab=선택 후보 완성(공백 추가→popup 닫힘, 인자 입력),
                            // ↑↓=후보 이동(아래 history ↑↓보다 우선).
                            (KeyCode::Tab, _) if spin.is_none() && !popup.is_empty() => {
                                textarea = textarea_with(&format!("/{} ", popup[popup_sel]));
                            }
                            (KeyCode::Up, _) if spin.is_none() && !popup.is_empty() => {
                                popup_sel = if popup_sel == 0 {
                                    popup.len() - 1
                                } else {
                                    popup_sel - 1
                                };
                            }
                            (KeyCode::Down, _) if spin.is_none() && !popup.is_empty() => {
                                popup_sel = (popup_sel + 1) % popup.len();
                            }
                            // 편집·제출은 thinking 중이 아닐 때만(LLM 처리 중 입력 차단).
                            (KeyCode::Enter, _) if spin.is_none() => {
                                // popup 활성이면 선택 후보를 제출, 아니면 입력 그대로.
                                let line = if popup.is_empty() {
                                    textarea.lines().join("\n")
                                } else {
                                    format!("/{}", popup[popup_sel])
                                };
                                // 입력 echo를 대화 로그에 남긴다(prompt + 입력). insert_before 대체.
                                log.push(format!("{prompt}{line}"));
                                log_text = rebuild_log_text(&log);
                                follow = true;
                                textarea = TextArea::default();
                                // history 기록(메모리 + 파일, reedline과 동일 파일) 후 탐색/popup 리셋.
                                if crate::repl::should_record_history(&line) {
                                    crate::repl::append_chat_history(&line);
                                    history.push(line.clone());
                                }
                                hist_idx = None;
                                draft.clear();
                                popup_sel = 0;
                                let _ = line_tx.send(ChatLine::Line(line)).await;
                            }
                            // ↑: 이전 history. 첫 ↑는 편집 중이던 입력을 draft에 보존.
                            (KeyCode::Up, _) if spin.is_none() && !history.is_empty() => {
                                let idx = match hist_idx {
                                    None => {
                                        draft = textarea.lines().join("\n");
                                        history.len() - 1
                                    }
                                    Some(0) => 0,
                                    Some(i) => i - 1,
                                };
                                hist_idx = Some(idx);
                                textarea = textarea_with(&history[idx]);
                            }
                            // ↓: 다음 history. 최근 아래로 내려오면 draft(편집 중이던 입력) 복원.
                            (KeyCode::Down, _) if spin.is_none() => {
                                if let Some(i) = hist_idx {
                                    if i + 1 < history.len() {
                                        hist_idx = Some(i + 1);
                                        textarea = textarea_with(&history[i + 1]);
                                    } else {
                                        hist_idx = None;
                                        textarea = textarea_with(&draft);
                                    }
                                }
                            }
                            _ if spin.is_none() => {
                                // 일반 편집 — history 탐색 종료(현재 내용이 새 입력).
                                hist_idx = None;
                                textarea.input(k);
                            }
                            _ => {}
                        }
                    }
                    // Key 외 이벤트(Resize/Mouse/Focus/Paste)는 무시 — Resize는 다음 루프 draw가
                    // 새 크기로 자동 반영(best-effort).
                    Some(Ok(_)) => {}
                    // 일시 입력 오류는 무시(다음 tick에 재시도).
                    Some(Err(_)) => {}
                    // stream 종료 = EOF.
                    None => {
                        let _ = line_tx.send(ChatLine::Eof).await;
                    }
                }
            }
            _ = tokio::time::sleep(tick) => {
                if let Some(sp) = spin.as_mut() {
                    sp.frame = sp.frame.wrapping_add(1);
                }
            }
            msg = out_rx.recv() => {
                match msg {
                    Some(OutMsg::Answer(s)) | Some(OutMsg::Note(s)) => {
                        // 답변/note를 대화 로그에 추가(insert_before 대체). 여러 줄이면 줄 단위로 넣어
                        // ring 상한·dump가 줄 단위로 동작하게 한다(원본 ANSI 보존, M1).
                        for l in s.lines() {
                            log.push(l.to_string());
                        }
                        // ring 상한 초과 시 앞에서 폐기 + scroll 보정(폐기한 만큼 위로, critic M2).
                        if log.len() > LOG_CAP {
                            let drop = log.len() - LOG_CAP;
                            log.drain(0..drop);
                            scroll = scroll.saturating_sub(drop as u16);
                        }
                        log_text = rebuild_log_text(&log);
                        // follow면 새 답변 도착 시 자동 최하단(scroll은 다음 draw에서 max로 재계산됨).
                        if follow {
                            // 다음 draw의 clamp/follow가 max로 맞춰주지만, 의도를 명시.
                            scroll = u16::MAX;
                        }
                    }
                    Some(OutMsg::SpinStart(label)) => {
                        spin = Some(SpinState { label, frame: 0, started: Instant::now() });
                    }
                    Some(OutMsg::SpinStop) => {
                        spin = None;
                    }
                    Some(OutMsg::Ctx(n)) => {
                        ctx_tokens = n;
                    }
                    Some(OutMsg::Confirm(prompt, tx)) => {
                        // 확인 모드 진입 — 입력 줄을 prompt로 대체하고 다음 키 입력을 y/n으로 소비한다.
                        confirm_prompt = prompt;
                        confirm_pending = Some(tx);
                    }
                    Some(OutMsg::Shutdown) | None => break,
                }
            }
        }
    }

    // alternate screen 떠나고 raw mode 복원(원래 화면 복귀).
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    let _ = disable_raw_mode();
    // 8e: 대화 버퍼를 stdout에 dump해 터미널 scrollback에 보존(원본 ANSI라 색 그대로).
    for line in &log {
        println!("{line}");
    }
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
        // 입력은 위(row0), status bar는 아래(row1) — claude CLI 스타일.
        assert!(row0.contains("you"), "input row(위): {row0:?}");
        assert!(row0.contains("hello"), "input row(위): {row0:?}");
        assert!(row1.contains("load 1.0"), "status row(아래): {row1:?}");
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
    fn textarea_with_sets_content() {
        // 단계 5: history(↑↓) 탐색 시 입력 줄을 history 항목으로 교체. CJK 포함 내용 보존.
        let ta = super::textarea_with("가나다 hello");
        assert_eq!(ta.lines().join("\n"), "가나다 hello");
        let empty = super::textarea_with("");
        assert_eq!(empty.lines().join("\n"), "");
    }

    #[test]
    fn slash_candidates_filters_by_prefix() {
        // 단계 6: `/명령` 첫 토큰 prefix 매칭. / 아님·인자(공백) 입력 중엔 빈 vec(popup 닫힘).
        assert!(super::slash_candidates("/lo").contains(&"local"));
        assert!(super::slash_candidates("/d").contains(&"diagnose"));
        assert!(super::slash_candidates("/d").contains(&"doctor"));
        assert_eq!(super::slash_candidates("/help"), vec!["help"]);
        assert!(super::slash_candidates("hello").is_empty(), "/ 아님");
        assert!(super::slash_candidates("/local ").is_empty(), "공백=인자 입력→닫힘");
        assert!(super::slash_candidates("/").len() >= 10, "/ 단독은 전체 후보");
    }

    #[test]
    fn draw_viewport_popup_shows_input_and_candidates() {
        let ta = super::textarea_with("/lo");
        let mut term = Terminal::new(TestBackend::new(60, 2)).unwrap();
        term.draw(|f| super::draw_viewport_popup(f, &["local", "last"], 0, &ta, "you ❯ "))
            .unwrap();
        let buf = term.backend().buffer();
        let row0: String = (0..60).map(|x| buf[(x, 0)].symbol()).collect();
        let row1: String = (0..60).map(|x| buf[(x, 1)].symbol()).collect();
        assert!(row0.contains("lo"), "입력 줄(위): {row0:?}");
        assert!(row1.contains("local"), "후보 줄(아래): {row1:?}");
        assert!(row1.contains("last"), "후보 줄(아래): {row1:?}");
    }

    #[test]
    fn log_scroll_max_clamps_to_total_minus_height() {
        // 단계 8: scroll 최대값 = wrap 후 총 화면 줄 - height(음수면 0).
        let log = Text::from("a\nb\nc\nd\ne"); // 5줄, width 큼=wrap 없음
        assert_eq!(super::log_scroll_max(&log, 80, 3), 2, "5-3=2");
        assert_eq!(super::log_scroll_max(&log, 80, 10), 0, "height≥total");
    }

    #[test]
    fn rebuild_log_text_preserves_lines_and_color() {
        // 8e/M1: log(원본 ANSI 줄)을 Text로 재구성 — 줄 수·색 보존.
        let log = vec![
            "plain".to_string(),
            "\x1b[34mblue\x1b[0m".to_string(),
            "".to_string(),
            "tail".to_string(),
        ];
        let text = super::rebuild_log_text(&log);
        assert_eq!(text.lines.len(), 4, "줄 수 보존(빈 줄 포함)");
        // 두 번째 줄의 첫 span이 파랑이어야 색이 보존된 것.
        let blue_span = &text.lines[1].spans[0];
        assert_eq!(blue_span.content, "blue");
        assert_eq!(blue_span.style.fg, Some(ratatui::style::Color::Blue));
        // 빈 로그는 빈 Text(패닉 없음).
        assert_eq!(super::rebuild_log_text(&[]).lines.len(), 1);
    }

    #[test]
    fn log_area_height_matches_draw_full_formula() {
        // draw_full 레이아웃과 동일: 전체 - popup_n - 3(입력1·구분선1·status1), 최소 1.
        assert_eq!(super::log_area_height(20, 0), 17, "20-0-3");
        assert_eq!(super::log_area_height(20, 5), 12, "20-5-3");
        assert_eq!(super::log_area_height(4, 0), 1, "최소 1(붕괴 방지)");
        assert_eq!(super::log_area_height(3, 0), 1, "전체<3이어도 최소 1");
    }

    #[test]
    fn draw_full_layout_log_input_sep_status() {
        // 전면 TUI: 로그(위) / 입력 / 구분선 / status(맨 아래). popup 없음.
        let log = Text::from("L0\nL1\nL2");
        let ta = super::textarea_with("hi");
        let mut term = Terminal::new(TestBackend::new(40, 8)).unwrap();
        term.draw(|f| super::draw_full(f, &log, 0, "· load", &ta, "you ❯ ", &[], 0, None, None))
            .unwrap();
        let buf = term.backend().buffer();
        let row = |y: u16| (0..40).map(|x| buf[(x, y)].symbol()).collect::<String>();
        // 로그(3줄)는 영역(8-3=5줄)보다 짧아 하단 정렬 → L2가 로그 영역 맨 아래(row 4).
        assert!(row(4).contains("L2"), "로그 하단 정렬: {:?}", row(4));
        assert!(row(5).contains("hi"), "입력: {:?}", row(5));
        assert!(row(6).contains("─"), "구분선: {:?}", row(6));
        assert!(row(7).contains("load"), "status(맨아래): {:?}", row(7));
    }

    #[test]
    fn draw_full_confirm_replaces_input_with_prompt() {
        // 기능 A: 확인 모드면 입력 줄(prompt+textarea) 대신 confirm_prompt를 그린다.
        // popup 후보를 줘도 confirm이 우선이라 popup은 그려지지 않는다.
        let log = Text::from("x");
        let ta = super::textarea_with("/d");
        let prompt = "⚠ systemctl restart nginx 실행? [y/N]";
        let mut term = Terminal::new(TestBackend::new(60, 8)).unwrap();
        term.draw(|f| {
            super::draw_full(
                f,
                &log,
                0,
                "· load",
                &ta,
                "you ❯ ",
                &["diagnose", "doctor"],
                0,
                None,
                Some(prompt),
            )
        })
        .unwrap();
        let buf = term.backend().buffer();
        let all: String = (0..8)
            .map(|y| (0..60).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("|");
        // 입력 줄(row 5 = height-3)에 confirm prompt가 보인다.
        let row5: String = (0..60).map(|x| buf[(x, 5)].symbol()).collect();
        assert!(row5.contains("[y/N]"), "confirm prompt(입력 줄): {row5:?}");
        // confirm 우선 → popup 후보(diagnose/doctor)는 화면에 없다.
        assert!(!all.contains("diagnose"), "confirm 중 popup 미표시: {all:?}");
    }

    #[test]
    fn draw_full_popup_vertical_with_desc() {
        // popup 활성: 입력 위에 세로 목록(명령+설명).
        let log = Text::from("x");
        let ta = super::textarea_with("/d");
        let mut term = Terminal::new(TestBackend::new(70, 10)).unwrap();
        term.draw(|f| {
            super::draw_full(
                f, &log, 0, "· load", &ta, "you ❯ ", &["diagnose", "doctor"], 1, None, None,
            )
        })
        .unwrap();
        let buf = term.backend().buffer();
        let all: String = (0..10)
            .map(|y| (0..70).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("|");
        assert!(all.contains("diagnose"), "popup 세로 후보+설명: {all:?}");
        assert!(all.contains("doctor"), "popup 세로 후보: {all:?}");
    }

    #[test]
    fn draw_chat_popup_shows_selected_with_desc() {
        // popup 활성: 입력(row0) / 선택 후보+설명+카운터(row1) / status(row2). viewport 3줄 고정.
        let ta = super::textarea_with("/d");
        let mut term = Terminal::new(TestBackend::new(80, 3)).unwrap();
        term.draw(|f| {
            super::draw_chat(f, "· load", &ta, "you ❯ ", &["diagnose", "doctor"], 0, None)
        })
        .unwrap();
        let buf = term.backend().buffer();
        let row = |y: u16| (0..80).map(|x| buf[(x, y)].symbol()).collect::<String>();
        assert!(row(0).contains("/d"), "입력(row0): {:?}", row(0));
        assert!(row(1).contains("diagnose"), "popup 선택+설명(row1): {:?}", row(1));
        assert!(row(1).contains("/2"), "카운터(row1): {:?}", row(1));
        assert!(row(2).contains("load"), "status(row2): {:?}", row(2));
    }

    #[test]
    fn draw_chat_no_popup_shows_separator() {
        // popup 비활성: 입력(row0) / 구분선(row1) / status(row2).
        let ta = super::textarea_with("hi");
        let mut term = Terminal::new(TestBackend::new(40, 3)).unwrap();
        term.draw(|f| super::draw_chat(f, "· load", &ta, "you ❯ ", &[], 0, None))
            .unwrap();
        let buf = term.backend().buffer();
        let row = |y: u16| (0..40).map(|x| buf[(x, y)].symbol()).collect::<String>();
        assert!(row(0).contains("hi"), "입력(row0): {:?}", row(0));
        assert!(row(1).contains("─"), "구분선(row1): {:?}", row(1));
        assert!(row(2).contains("load"), "status(row2): {:?}", row(2));
    }

    #[test]
    fn draw_thinking_renders_status_and_spinner_label() {
        // thinking 표시는 spinner+라벨 줄(위 row0) + status 줄(아래 row1, claude CLI 스타일).
        let spin = super::SpinState {
            label: "thinking".into(),
            frame: 0,
            started: Instant::now(),
        };
        let mut term = Terminal::new(TestBackend::new(40, 2)).unwrap();
        term.draw(|f| super::draw_thinking(f, "· load 1.0", &spin))
            .unwrap();
        let buf = term.backend().buffer();
        let row0: String = (0..40).map(|x| buf[(x, 0)].symbol()).collect();
        let row1: String = (0..40).map(|x| buf[(x, 1)].symbol()).collect();
        assert!(row0.contains("thinking"), "spinner row(위): {row0:?}");
        assert!(row1.contains("load 1.0"), "status row(아래): {row1:?}");
    }

    #[test]
    fn status_with_ctx_appends_token_estimate() {
        // 0이면 status 그대로(표시 생략), >0이면 ` · ctx ~Nk`(1000 단위 절삭).
        assert_eq!(super::status_with_ctx("· load 1.0", 0), "· load 1.0");
        assert_eq!(super::status_with_ctx("· load", 12_345), "· load · ctx ~12k");
        // 1000 미만은 정확한 수(~512), 1000 이상은 ~Nk.
        assert_eq!(super::status_with_ctx("s", 999), "s · ctx ~999");
        assert_eq!(super::status_with_ctx("s", 1000), "s · ctx ~1k");
    }

    #[test]
    fn search_bar_formats_query_and_counter() {
        // hit 없으면 (0/0), 있으면 1-based (idx+1/total).
        assert_eq!(super::search_bar("err", 0, 0), "/err  (0/0)");
        assert_eq!(super::search_bar("err", 0, 3), "/err  (1/3)");
        assert_eq!(super::search_bar("err", 2, 3), "/err  (3/3)");
        assert_eq!(super::search_bar("", 0, 0), "/  (0/0)");
    }

    #[test]
    fn search_hits_for_filters_matching_lines() {
        let log = vec![
            "first error".to_string(),
            "ok".to_string(),
            "another error here".to_string(),
            "done".to_string(),
        ];
        assert_eq!(super::search_hits_for(&log, "error"), vec![0, 2]);
        assert_eq!(super::search_hits_for(&log, "ok"), vec![1]);
        assert!(super::search_hits_for(&log, "zzz").is_empty(), "매칭 없음");
        // 빈 쿼리는 hit 없음(검색 시작 직후 전체 매칭 방지).
        assert!(super::search_hits_for(&log, "").is_empty(), "빈 쿼리");
    }

    #[test]
    fn draw_full_renders_search_bar_as_input_line() {
        // 검색 모드 표현 검증: search bar 텍스트를 입력 줄(prompt="")로 그리면 그대로 보인다.
        let log = Text::from("L0\nfound it\nL2");
        let bar = super::search_bar("found", 0, 1);
        let ta = super::textarea_with(&bar);
        let mut term = Terminal::new(TestBackend::new(40, 8)).unwrap();
        term.draw(|f| super::draw_full(f, &log, 0, "· load", &ta, "", &[], 0, None, None))
            .unwrap();
        let buf = term.backend().buffer();
        let row = |y: u16| (0..40).map(|x| buf[(x, y)].symbol()).collect::<String>();
        assert!(row(5).contains("/found"), "search bar(입력 줄): {:?}", row(5));
        assert!(row(5).contains("(1/1)"), "카운터: {:?}", row(5));
    }

    #[test]
    fn draw_full_status_shows_ctx_tokens() {
        // status 끝에 ctx 토큰이 합쳐져 그려지는지(status_line 합성 후 draw_full로).
        let log = Text::from("x");
        let ta = super::textarea_with("hi");
        let status = super::status_with_ctx("· load", 12_000);
        let mut term = Terminal::new(TestBackend::new(40, 6)).unwrap();
        term.draw(|f| super::draw_full(f, &log, 0, &status, &ta, "you ❯ ", &[], 0, None, None))
            .unwrap();
        let buf = term.backend().buffer();
        let row5: String = (0..40).map(|x| buf[(x, 5)].symbol()).collect();
        assert!(row5.contains("ctx ~12k"), "status에 ctx: {row5:?}");
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
