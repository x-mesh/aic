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
use crossterm::event::EventStream;
use futures::StreamExt;
use ratatui::backend::Backend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Widget, Wrap};
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

/// raw mode에서 패닉이 나도 터미널을 복원하도록 패닉 훅을 1회 설치한다(m5). 기존 훅은 보존해
/// 호출한다(panic 메시지·backtrace 유지).
fn install_panic_hook() {
    use std::sync::Once;
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
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

/// ChatLoop 본체 — terminal 단독 소유. enable_raw_mode + Inline(2) viewport로 진입하고,
/// `tokio::select!`로 (키 입력 / status·spinner tick / 출력 메시지)를 한 곳에서 처리한다.
/// 종료(Shutdown/stream EOF/draw 실패) 시 viewport를 정리하고 raw mode를 복원한다.
async fn chat_loop(
    line_tx: mpsc::Sender<ChatLine>,
    mut out_rx: mpsc::Receiver<OutMsg>,
    prompt: String,
    with_statusbar: bool,
) {
    if enable_raw_mode().is_err() {
        return;
    }
    let mut terminal = match Terminal::with_options(
        CrosstermBackend::new(io::stdout()),
        TerminalOptions {
            viewport: Viewport::Inline(2),
        },
    ) {
        Ok(t) => t,
        Err(_) => {
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
    // 입력 history(reedline과 동일 파일 공유). hist_idx=탐색 위치, draft=탐색 전 편집 내용 보존.
    let mut history = crate::repl::load_chat_history();
    let mut hist_idx: Option<usize> = None;
    let mut draft = String::new();
    // slash 자동완성 popup 선택 인덱스(후보는 매 루프 입력에서 재계산).
    let mut popup_sel: usize = 0;

    loop {
        // status 갱신(2초 주기 또는 최초). spinner 유무와 무관하게 흐른다.
        if let Some(s) = sampler.as_mut() {
            if last_sample.elapsed().as_secs() >= 2 || status.starts_with("· (") {
                status = format!("· {}", s.sample().status_line());
                last_sample = Instant::now();
            }
        }
        // slash 후보 popup 계산(입력이 `/명령` 첫 토큰일 때만). sel은 후보 수에 맞게 보정.
        let popup = slash_candidates(&textarea.lines().join("\n"));
        if popup.is_empty() {
            popup_sel = 0;
        } else if popup_sel >= popup.len() {
            popup_sel = popup.len() - 1;
        }
        // draw: spinner→thinking, popup 활성→후보 줄, 아니면 입력+status. 실패 시 종료.
        let draw_ok = terminal
            .draw(|f| match &spin {
                Some(sp) => draw_thinking(f, &status, sp),
                None if !popup.is_empty() => {
                    draw_viewport_popup(f, &popup, popup_sel, &textarea, &prompt)
                }
                None => draw_viewport(f, &status, &textarea, &prompt),
            })
            .is_ok();
        if !draw_ok {
            break;
        }

        // tick: spinner 애니메이션 100ms, 평상시 status 흐름 200ms. width는 answer wrap과 동일 소스.
        let tick = Duration::from_millis(if spin.is_some() { 100 } else { 200 });
        let width = super::ui::render_width() as u16;

        tokio::select! {
            maybe_ev = events.next() => {
                match maybe_ev {
                    Some(Ok(Event::Key(k))) => {
                        match (k.code, k.modifiers) {
                            (KeyCode::Char('c') | KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                                let _ = line_tx.send(ChatLine::Eof).await;
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
                                // 입력 echo를 scrollback에 남긴다(prompt + 입력, plain).
                                let _ = insert_before_ansi(
                                    &mut terminal,
                                    &format!("{prompt}{line}"),
                                    width,
                                );
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
                    // 새 크기로 자동 반영(ratatui #2086 best-effort).
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
                        let _ = insert_before_ansi(&mut terminal, &s, width);
                    }
                    Some(OutMsg::SpinStart(label)) => {
                        spin = Some(SpinState { label, frame: 0, started: Instant::now() });
                    }
                    Some(OutMsg::SpinStop) => {
                        spin = None;
                    }
                    Some(OutMsg::Shutdown) | None => break,
                }
            }
        }
    }

    let _ = terminal.clear();
    let _ = disable_raw_mode();
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
