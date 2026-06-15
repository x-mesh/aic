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
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEventKind,
};
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

use super::sys_sampler::{spawn_sampler, Severity, SysMetrics, SysSampler};

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
    let mut hangul = HangulComposer::default();
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
                if !is_key_press(k) {
                    continue;
                }
                match (k.code, k.modifiers) {
                    (KeyCode::Char('d') | KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        break ChatLine::Eof
                    }
                    (KeyCode::Enter, _) => break ChatLine::Line(textarea.lines().join("\n")),
                    _ => {
                        if !hangul.input(&mut textarea, k) {
                            textarea.input(k);
                        }
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
    /// 작업(turn/slash 처리) 중 Ctrl+C 취소 신호. ChatLoop가 보내고 run_loop_tui가 select!로
    /// `run_turn` future와 race한다 — cancel arm이 이기면 future가 drop되어 reqwest/도구 await가
    /// 취소된다(앱은 유지, 입력 프롬프트로 복귀).
    cancel_rx: mpsc::Receiver<()>,
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

    /// 작업 중 Ctrl+C 취소 신호를 기다린다(`run_turn`/`handle_slash`와 select!). 채널이 닫히면
    /// (ChatLoop 종료 = 앱 종료 중) 다시는 신호가 안 오므로 영원히 pending되어, select!의 다른 arm
    /// (정상 완료)이 처리하도록 둔다 — 닫힌 채널의 즉시-None이 거짓 취소로 잡히는 것을 막는다.
    pub(crate) async fn recv_cancel(&mut self) {
        if self.cancel_rx.recv().await.is_none() {
            std::future::pending::<()>().await;
        }
    }

    /// 새 작업 시작 직전 잔여 취소 신호를 비운다 — 직전 turn 종료와 거의 동시에 눌린 Ctrl+C가
    /// 채널에 남아 다음 turn을 즉시 취소하는 race를 막는다.
    pub(crate) fn drain_cancel(&mut self) {
        while self.cancel_rx.try_recv().is_ok() {}
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
            let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
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
    // 취소 채널: 용량 1이면 충분(중복 Ctrl+C는 try_send 실패로 자연 병합). turn마다 drain_cancel로 비운다.
    let (cancel_tx, cancel_rx) = mpsc::channel::<()>(1);
    let join = tokio::spawn(chat_loop(
        line_tx,
        out_rx,
        cancel_tx,
        prompt,
        with_statusbar,
    ));
    ChatHandle {
        line_rx,
        out_tx,
        cancel_rx,
        join,
    }
}

const SPIN_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn is_key_press(k: KeyEvent) -> bool {
    matches!(k.kind, KeyEventKind::Press | KeyEventKind::Repeat)
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HangulState {
    L { l: u8 },
    Lv { l: u8, v: u8 },
    Lvt { l: u8, v: u8, t: u8 },
}

#[derive(Default)]
struct HangulComposer {
    state: Option<HangulState>,
    cursor_after: Option<(usize, usize)>,
}

impl HangulComposer {
    fn reset(&mut self) {
        self.state = None;
        self.cursor_after = None;
    }

    /// 한글 IME 조합이 진행 중인가(미완성 preedit jamo가 있나). 조합 중에 status 영역을 자발적으로
    /// redraw하면 자모가 분리·이동될 수 있어, metrics tick으로 인한 redraw를 건너뛰는 판단에 쓴다.
    fn is_composing(&self) -> bool {
        self.state.is_some()
    }

    fn input(&mut self, textarea: &mut TextArea<'static>, k: KeyEvent) -> bool {
        let KeyCode::Char(c) = k.code else {
            self.reset();
            return false;
        };
        if k.modifiers.contains(KeyModifiers::CONTROL) || k.modifiers.contains(KeyModifiers::ALT) {
            self.reset();
            return false;
        }
        let Some(jamo) = Jamo::from_char(c) else {
            self.reset();
            return false;
        };
        if self.state.is_some() && self.cursor_after != Some(textarea.cursor()) {
            self.reset();
        }
        self.apply_jamo(textarea, c, jamo);
        true
    }

    fn apply_jamo(&mut self, textarea: &mut TextArea<'static>, raw: char, jamo: Jamo) {
        match (self.state, jamo) {
            (None, Jamo::Consonant { l: Some(l), .. }) => {
                self.insert_fresh(textarea, &raw.to_string(), Some(HangulState::L { l }));
            }
            (None, _) => {
                self.insert_fresh(textarea, &raw.to_string(), None);
            }
            (Some(HangulState::L { l }), Jamo::Vowel(v)) => {
                let s = compose_hangul(l, v, 0).to_string();
                self.replace_active(textarea, &s, Some(HangulState::Lv { l, v }));
            }
            (Some(HangulState::L { .. }), Jamo::Consonant { l: Some(next), .. }) => {
                self.insert_fresh(textarea, &raw.to_string(), Some(HangulState::L { l: next }));
            }
            (Some(HangulState::L { .. }), _) => {
                self.insert_fresh(textarea, &raw.to_string(), None);
            }
            (Some(HangulState::Lv { l, v }), Jamo::Vowel(next_v)) => {
                if let Some(v) = combine_vowel(v, next_v) {
                    let s = compose_hangul(l, v, 0).to_string();
                    self.replace_active(textarea, &s, Some(HangulState::Lv { l, v }));
                } else {
                    self.insert_fresh(textarea, &raw.to_string(), None);
                }
            }
            (Some(HangulState::Lv { l, v }), Jamo::Consonant { t: Some(t), .. }) => {
                let s = compose_hangul(l, v, t).to_string();
                self.replace_active(textarea, &s, Some(HangulState::Lvt { l, v, t }));
            }
            (Some(HangulState::Lv { .. }), Jamo::Consonant { l: Some(next), .. }) => {
                self.insert_fresh(textarea, &raw.to_string(), Some(HangulState::L { l: next }));
            }
            (Some(HangulState::Lv { .. }), _) => {
                self.insert_fresh(textarea, &raw.to_string(), None);
            }
            (Some(HangulState::Lvt { l, v, t }), Jamo::Vowel(next_v)) => {
                if let Some((keep_t, next_l)) = split_final(t) {
                    let prev = compose_hangul(l, v, keep_t.unwrap_or(0));
                    let next = compose_hangul(next_l, next_v, 0);
                    let s = format!("{prev}{next}");
                    self.replace_active(
                        textarea,
                        &s,
                        Some(HangulState::Lv {
                            l: next_l,
                            v: next_v,
                        }),
                    );
                } else {
                    self.insert_fresh(textarea, &raw.to_string(), None);
                }
            }
            (
                Some(HangulState::Lvt { l, v, t }),
                Jamo::Consonant {
                    t: Some(next_t), ..
                },
            ) => {
                if let Some(t) = combine_final(t, next_t) {
                    let s = compose_hangul(l, v, t).to_string();
                    self.replace_active(textarea, &s, Some(HangulState::Lvt { l, v, t }));
                } else if let Jamo::Consonant { l: Some(next), .. } = jamo {
                    self.insert_fresh(textarea, &raw.to_string(), Some(HangulState::L { l: next }));
                } else {
                    self.insert_fresh(textarea, &raw.to_string(), None);
                }
            }
            (Some(HangulState::Lvt { .. }), Jamo::Consonant { l: Some(next), .. }) => {
                self.insert_fresh(textarea, &raw.to_string(), Some(HangulState::L { l: next }));
            }
            (Some(HangulState::Lvt { .. }), _) => {
                self.insert_fresh(textarea, &raw.to_string(), None);
            }
        }
    }

    fn insert_fresh(
        &mut self,
        textarea: &mut TextArea<'static>,
        s: &str,
        state: Option<HangulState>,
    ) {
        textarea.insert_str(s);
        self.state = state;
        self.cursor_after = state.map(|_| textarea.cursor());
    }

    fn replace_active(
        &mut self,
        textarea: &mut TextArea<'static>,
        s: &str,
        state: Option<HangulState>,
    ) {
        if self.cursor_after == Some(textarea.cursor()) {
            textarea.delete_char();
        }
        textarea.insert_str(s);
        self.state = state;
        self.cursor_after = state.map(|_| textarea.cursor());
    }
}

#[derive(Clone, Copy)]
enum Jamo {
    Consonant { l: Option<u8>, t: Option<u8> },
    Vowel(u8),
}

impl Jamo {
    fn from_char(c: char) -> Option<Self> {
        let j = match c {
            'ㄱ' => Self::Consonant {
                l: Some(0),
                t: Some(1),
            },
            'ㄲ' => Self::Consonant {
                l: Some(1),
                t: Some(2),
            },
            'ㄴ' => Self::Consonant {
                l: Some(2),
                t: Some(4),
            },
            'ㄷ' => Self::Consonant {
                l: Some(3),
                t: Some(7),
            },
            'ㄸ' => Self::Consonant {
                l: Some(4),
                t: None,
            },
            'ㄹ' => Self::Consonant {
                l: Some(5),
                t: Some(8),
            },
            'ㅁ' => Self::Consonant {
                l: Some(6),
                t: Some(16),
            },
            'ㅂ' => Self::Consonant {
                l: Some(7),
                t: Some(17),
            },
            'ㅃ' => Self::Consonant {
                l: Some(8),
                t: None,
            },
            'ㅅ' => Self::Consonant {
                l: Some(9),
                t: Some(19),
            },
            'ㅆ' => Self::Consonant {
                l: Some(10),
                t: Some(20),
            },
            'ㅇ' => Self::Consonant {
                l: Some(11),
                t: Some(21),
            },
            'ㅈ' => Self::Consonant {
                l: Some(12),
                t: Some(22),
            },
            'ㅉ' => Self::Consonant {
                l: Some(13),
                t: None,
            },
            'ㅊ' => Self::Consonant {
                l: Some(14),
                t: Some(23),
            },
            'ㅋ' => Self::Consonant {
                l: Some(15),
                t: Some(24),
            },
            'ㅌ' => Self::Consonant {
                l: Some(16),
                t: Some(25),
            },
            'ㅍ' => Self::Consonant {
                l: Some(17),
                t: Some(26),
            },
            'ㅎ' => Self::Consonant {
                l: Some(18),
                t: Some(27),
            },
            'ㅏ' => Self::Vowel(0),
            'ㅐ' => Self::Vowel(1),
            'ㅑ' => Self::Vowel(2),
            'ㅒ' => Self::Vowel(3),
            'ㅓ' => Self::Vowel(4),
            'ㅔ' => Self::Vowel(5),
            'ㅕ' => Self::Vowel(6),
            'ㅖ' => Self::Vowel(7),
            'ㅗ' => Self::Vowel(8),
            'ㅘ' => Self::Vowel(9),
            'ㅙ' => Self::Vowel(10),
            'ㅚ' => Self::Vowel(11),
            'ㅛ' => Self::Vowel(12),
            'ㅜ' => Self::Vowel(13),
            'ㅝ' => Self::Vowel(14),
            'ㅞ' => Self::Vowel(15),
            'ㅟ' => Self::Vowel(16),
            'ㅠ' => Self::Vowel(17),
            'ㅡ' => Self::Vowel(18),
            'ㅢ' => Self::Vowel(19),
            'ㅣ' => Self::Vowel(20),
            _ => return None,
        };
        Some(j)
    }
}

fn compose_hangul(l: u8, v: u8, t: u8) -> char {
    char::from_u32(0xAC00 + (((l as u32 * 21) + v as u32) * 28) + t as u32).unwrap_or('\u{FFFD}')
}

fn combine_vowel(v: u8, next: u8) -> Option<u8> {
    match (v, next) {
        (8, 0) => Some(9),    // ㅗ + ㅏ = ㅘ
        (8, 1) => Some(10),   // ㅗ + ㅐ = ㅙ
        (8, 20) => Some(11),  // ㅗ + ㅣ = ㅚ
        (13, 4) => Some(14),  // ㅜ + ㅓ = ㅝ
        (13, 5) => Some(15),  // ㅜ + ㅔ = ㅞ
        (13, 20) => Some(16), // ㅜ + ㅣ = ㅟ
        (18, 20) => Some(19), // ㅡ + ㅣ = ㅢ
        _ => None,
    }
}

fn combine_final(t: u8, next: u8) -> Option<u8> {
    match (t, next) {
        (1, 19) => Some(3),   // ㄱ + ㅅ = ㄳ
        (4, 22) => Some(5),   // ㄴ + ㅈ = ㄵ
        (4, 27) => Some(6),   // ㄴ + ㅎ = ㄶ
        (8, 1) => Some(9),    // ㄹ + ㄱ = ㄺ
        (8, 16) => Some(10),  // ㄹ + ㅁ = ㄻ
        (8, 17) => Some(11),  // ㄹ + ㅂ = ㄼ
        (8, 19) => Some(12),  // ㄹ + ㅅ = ㄽ
        (8, 25) => Some(13),  // ㄹ + ㅌ = ㄾ
        (8, 26) => Some(14),  // ㄹ + ㅍ = ㄿ
        (8, 27) => Some(15),  // ㄹ + ㅎ = ㅀ
        (17, 19) => Some(18), // ㅂ + ㅅ = ㅄ
        _ => None,
    }
}

fn split_final(t: u8) -> Option<(Option<u8>, u8)> {
    match t {
        1 => Some((None, 0)),
        2 => Some((None, 1)),
        3 => Some((Some(1), 9)),
        4 => Some((None, 2)),
        5 => Some((Some(4), 12)),
        6 => Some((Some(4), 18)),
        7 => Some((None, 3)),
        8 => Some((None, 5)),
        9 => Some((Some(8), 0)),
        10 => Some((Some(8), 6)),
        11 => Some((Some(8), 7)),
        12 => Some((Some(8), 9)),
        13 => Some((Some(8), 16)),
        14 => Some((Some(8), 17)),
        15 => Some((Some(8), 18)),
        16 => Some((None, 6)),
        17 => Some((None, 7)),
        18 => Some((Some(17), 9)),
        19 => Some((None, 9)),
        20 => Some((None, 10)),
        21 => Some((None, 11)),
        22 => Some((None, 12)),
        23 => Some((None, 14)),
        24 => Some((None, 15)),
        25 => Some((None, 16)),
        26 => Some((None, 17)),
        27 => Some((None, 18)),
        _ => None,
    }
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
            Span::styled(
                format!("/{sel}"),
                Style::default().add_modifier(Modifier::REVERSED),
            ),
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

/// textarea 입력 위치로 **하드웨어 커서**를 옮긴다. ratatui는 `set_cursor_position`을 부르지 않으면
/// 커서를 마지막 렌더 셀(여기선 status bar 끝)에 둔 채 두고, tui-textarea는 커서를 셀 스타일로만
/// 표시한다 → 한글 IME 조합 글자(preedit)가 터미널의 하드웨어 커서 위치(status bar 끝)에 새는 버그가
/// 생긴다. cursor(row,col)를 display width로 화면 좌표 변환해 하드웨어 커서를 입력 줄에 정렬한다.
fn place_textarea_cursor(f: &mut Frame, textarea: &TextArea, area: Rect) {
    let (row, col) = textarea.cursor();
    let line = textarea.lines().get(row).map(String::as_str).unwrap_or("");
    let before: String = line.chars().take(col).collect();
    let x = area
        .x
        .saturating_add(UnicodeWidthStr::width(before.as_str()) as u16)
        .min(area.x + area.width.saturating_sub(1));
    let y = area
        .y
        .saturating_add(row as u16)
        .min(area.y + area.height.saturating_sub(1));
    f.set_cursor_position((x, y));
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
    status: Line<'static>,
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
            // 작업 중임을 알리는 spinner + 경과 시간. 끝에 Ctrl+C 중단 힌트를 붙여 기능을 노출한다.
            f.render_widget(
                Paragraph::new(format!("{frame} {} ({secs:.1}s)  · Ctrl+C 중단", sp.label)).dim(),
                rows[2],
            );
        }
        (None, None) => {
            let prompt_w = UnicodeWidthStr::width(prompt) as u16;
            let cols = Layout::horizontal([Constraint::Length(prompt_w), Constraint::Min(0)])
                .split(rows[2]);
            f.render_widget(Paragraph::new(prompt.to_string()), cols[0]);
            f.render_widget(textarea, cols[1]);
            place_textarea_cursor(f, textarea, cols[1]);
        }
    }

    // 구분선 + status(세그먼트별 색은 status Line이 직접 들고 있다 — 여기서 .dim() 강제 금지).
    let sep = "─".repeat(area.width as usize);
    f.render_widget(Paragraph::new(sep).dim(), rows[3]);
    f.render_widget(Paragraph::new(status), rows[4]);
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

/// 마우스 휠 한 틱당 스크롤할 로그 줄 수.
const WHEEL_STEP: u16 = 3;

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

/// 로그 각 줄의 wrap 후 표시 높이(줄 수). draw_full과 동일한 `Wrap{trim:false}` 공식. 순수 함수.
fn wrapped_line_heights(text: &Text, width: u16) -> Vec<u16> {
    text.lines
        .iter()
        .map(|l| {
            Paragraph::new(l.clone())
                .wrap(Wrap { trim: false })
                .line_count(width.max(1)) as u16
        })
        .collect()
}

/// wrap 후 절대 표시 행 → 로그 줄 인덱스(누적 높이 워크). 범위 밖이면 마지막 줄로 clamp. 순수 함수.
fn display_row_to_line(heights: &[u16], row: u16) -> usize {
    let mut acc = 0u32;
    for (i, h) in heights.iter().enumerate() {
        acc += u32::from(*h);
        if u32::from(row) < acc {
            return i;
        }
    }
    heights.len().saturating_sub(1)
}

/// 마우스 y(화면 좌표) → 로그의 절대 표시 행. draw_full의 하단 정렬(내용 < 영역이면 아래 붙음)과
/// scroll 오프셋을 동일하게 반영한다. 로그 영역 밖/하단 정렬 패딩 위면 None. 순수 함수.
fn mouse_log_row(my: u16, log_top: u16, log_h: u16, total: u16, scroll: u16) -> Option<u16> {
    if my < log_top || my >= log_top.saturating_add(log_h) {
        return None;
    }
    let rel = my - log_top;
    if total < log_h {
        let pad = log_h - total;
        if rel < pad {
            return None;
        }
        Some(rel - pad)
    } else {
        Some(scroll.saturating_add(rel))
    }
}

/// 선택 구간 [a,b](로그 줄 인덱스, 순서 무관)를 REVERSED로 강조한 Text 사본. 드래그 선택의
/// 시각 피드백. 줄 스타일만으로는 부족하다 — ANSI reset(`\x1b[0m`)에서 온 span이
/// `sub_modifier`로 REVERSED를 지워버리므로(셀 적용 순서: add → sub), 각 span 스타일에
/// 직접 add를 넣고 sub에서 빼서 어떤 색/reset이 섞여 있어도 강조가 살아남게 한다. 순수 함수.
fn highlight_log_lines(text: &Text<'static>, a: usize, b: usize) -> Text<'static> {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut t = text.clone();
    for line in t.lines.iter_mut().skip(lo).take(hi - lo + 1) {
        line.style = line.style.add_modifier(Modifier::REVERSED);
        for span in line.spans.iter_mut() {
            span.style.add_modifier.insert(Modifier::REVERSED);
            span.style.sub_modifier.remove(Modifier::REVERSED);
        }
    }
    t
}

/// status 문자열 끝에 컨텍스트 토큰 추정치를 ` · ctx ~Nk`로 덧붙인다(0이면 생략). 순수 함수.
/// N = tokens/1000(1000 단위 k 절삭). `~`로 추정 표기(provider usage가 아닌 문자수/4 추정).
fn status_with_ctx(status: &str, ctx_tokens: usize) -> String {
    match ctx_label(ctx_tokens) {
        None => status.to_string(),
        Some(ctx) => format!("{status} · ctx {ctx}"),
    }
}

/// ctx 토큰 추정치 라벨(`~Nk`/`~N`). 0이면 None. 1000 미만은 정확한 수, 이상은 k 절삭.
/// `status_with_ctx`(plain)와 `build_status_line`(colored)이 공유한다.
fn ctx_label(ctx_tokens: usize) -> Option<String> {
    if ctx_tokens == 0 {
        return None;
    }
    Some(if ctx_tokens >= 1000 {
        format!("~{}k", ctx_tokens / 1000)
    } else {
        format!("~{ctx_tokens}")
    })
}

/// status bar 색: 정상=dim · warn=주황 · crit=빨강(굵게). 단일 출처(named).
fn sev_style(sev: Severity) -> Style {
    match sev {
        Severity::Normal => Style::default().add_modifier(Modifier::DIM),
        Severity::Warn => Style::default().fg(Color::Rgb(255, 165, 0)),
        Severity::Crit => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

/// 시스템 지표 세그먼트를 단계별 색(정상 dim/warn 주황/crit 빨강)으로 칠한 status bar 한 줄을 만든다.
/// 구분선(` · `)·선두 `· `·ctx 접미는 dim. 순수 함수(TestBackend로 테스트). 임계 위반 자원만 눈에 띈다.
fn build_status_line(segs: &[(String, Severity)], ctx_tokens: usize) -> Line<'static> {
    let dim = sev_style(Severity::Normal);
    let mut spans: Vec<Span<'static>> = vec![Span::styled("· ", dim)];
    for (i, (text, sev)) in segs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", dim));
        }
        spans.push(Span::styled(text.clone(), sev_style(*sev)));
    }
    if let Some(ctx) = ctx_label(ctx_tokens) {
        spans.push(Span::styled(format!(" · ctx {ctx}"), dim));
    }
    Line::from(spans)
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

/// 클립보드 복사 — OSC 52(원격 ssh 포함 1차 경로)와 시스템 도구(pbcopy 등, 로컬 fallback)를
/// 병행한다. 터미널이 OSC 52 를 막아도 로컬 도구가 있으면 복사된다(둘 다 best-effort).
fn copy_to_clipboard(text: &str) {
    osc52_copy(text);
    system_clipboard_copy(text);
}

/// 시스템 클립보드 CLI(macOS `pbcopy` → wayland `wl-copy` → X11 `xclip` 순)로 복사한다.
/// 미설치/실패는 조용히 무시 — OSC 52 가 1차 경로고 이건 로컬 보강이다.
fn system_clipboard_copy(text: &str) {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    for (cmd, args) in [
        ("pbcopy", &[][..]),
        ("wl-copy", &[][..]),
        ("xclip", &["-selection", "clipboard"][..]),
    ] {
        let Ok(mut child) = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(text.as_bytes());
        }
        let _ = child.wait();
        return; // spawn 에 성공한 첫 도구만 사용.
    }
}

/// 텍스트를 OSC 52 escape 로 터미널 클립보드에 복사한다. SSH 로 원격 접속해도 터미널
/// 에뮬레이터가 로컬 클립보드에 써 주므로 시스템 클립보드 crate 없이 동작한다. 터미널이
/// OSC 52 를 지원하지 않으면(또는 클립보드 쓰기를 막아두면) 조용히 무시된다(best-effort).
fn osc52_copy(text: &str) {
    use std::io::Write;
    let b64 = base64_encode(text.as_bytes());
    // `\x1b]52;c;<base64>\x07` — c = CLIPBOARD selection, BEL 종료.
    let mut out = io::stdout();
    let _ = write!(out, "\x1b]52;c;{b64}\x07");
    let _ = out.flush();
}

/// 최소 base64 인코더(표준 알파벳). OSC 52 payload 전용 — 외부 crate 의존을 피한다.
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// ANSI escape(주로 SGR 색상 `\x1b[…m`, OSC 등)를 제거해 clipboard 용 평문을 만든다.
/// CSI(`\x1b[` … 최종 바이트 0x40–0x7E)와 OSC(`\x1b]` … BEL/ST)를 건너뛴다.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('[') => {
                chars.next();
                for c2 in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c2) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                while let Some(c2) = chars.next() {
                    if c2 == '\x07' {
                        break;
                    }
                    if c2 == '\x1b' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            _ => {
                chars.next();
            }
        }
    }
    out
}

/// metrics watch 채널 폴링 결과 — chat_loop의 select! arm이 채널 상태를 분기하는 데 쓴다.
enum MetricsPoll {
    /// 새 지표 도착(첫 sample 이후엔 항상 이 변형).
    New(SysMetrics),
    /// 채널이 변경됐으나 값이 아직 None(이론상 첫 sample 전 — 무시).
    Empty,
    /// 채널이 닫힘(sampler task 종료) — arm을 비활성화해 busy-loop를 막는다.
    Closed,
}

/// ChatLoop 본체 — terminal 단독 소유. EnterAlternateScreen + enable_raw_mode로 전면 TUI에 진입하고,
/// 대화 로그를 자체 스크롤 버퍼(`log`)로 관리한다. `tokio::select!`로 (키 입력 / status·spinner tick /
/// 출력 메시지)를 한 곳에서 처리한다. 종료(Shutdown/stream EOF/draw 실패) 시 alternate screen을 떠나고
/// raw mode를 복원한 뒤, 대화 버퍼를 stdout에 dump해 터미널 scrollback에 보존한다(8e).
async fn chat_loop(
    line_tx: mpsc::Sender<ChatLine>,
    mut out_rx: mpsc::Receiver<OutMsg>,
    cancel_tx: mpsc::Sender<()>,
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
    // 마우스 휠을 캡처해 로그 viewport 스크롤로 라우팅한다. 캡처하지 않으면 alternate screen에서
    // 터미널이 휠을 ↑↓ 키로 변환해 보내, 사용자가 스크롤하려다 입력 history가 바뀌는 문제가 생긴다.
    // best-effort — 미지원 터미널이어도 TUI 자체는 진입한다.
    let _ = execute!(io::stdout(), EnableMouseCapture);
    // 마우스 캡처 상태 — Ctrl+T 로 토글한다. OFF 면 터미널 네이티브 드래그 선택(복사)이
    // 살아나고, ON 이면 휠이 로그 스크롤로 동작한다.
    let mut mouse_captured = true;
    let mut terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
        Ok(t) => t,
        Err(_) => {
            let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return;
        }
    };
    // alternate screen은 진입 직후 셀이 미정의(터미널마다 검정/잔상)다. 물리적으로 `clear`해 화면 전체를
    // 터미널 기본 배경으로 칠한다. 안 하면 draw가 안 그리는 빈 상단 영역만 검정으로 남아, 로그·입력 줄이
    // 그려지는 영역(기본 배경)과 배경색이 달라 보인다(사용자 보고: "배경색이 다름").
    let _ = terminal.clear();
    let mut textarea = TextArea::default();
    let mut hangul = HangulComposer::default();
    let mut events = EventStream::new();
    // status bar 지표는 전용 task(spawn_sampler)가 blocking refresh(statfs 등)를 spawn_blocking에서
    // 돌려 watch 채널로 publish한다. UI 루프는 채널만 읽으므로 (1) hung mount에서 statfs가 멈춰도
    // 얼지 않고, (2) 채널 갱신이 select!를 깨워 idle에서도 status가 흐른다(이전엔 tick이 spin 중에만
    // 돌아 idle에서 status가 멈췄다).
    let (mut metrics_rx, sampler_task) = if with_statusbar {
        let (rx, handle) = spawn_sampler();
        (Some(rx), Some(handle))
    } else {
        (None, None)
    };
    let mut status = String::from("· 드래그=선택 복사 · Ctrl+Y 전체 복사 · Ctrl+T 마우스 · (metrics…)");
    // 임계 단계 컬러링용 지표 세그먼트(없으면 위 help 텍스트를 plain dim으로). 첫 sample 후 Some.
    let mut status_segs: Option<Vec<(String, Severity)>> = None;
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
    // 드래그 선택(로그 줄 단위 복사): Some((anchor 줄, 현재 줄, drag 발생 여부)). 마우스 캡처 중에도
    // 터미널 네이티브 선택 없이 드래그→복사가 되도록 TUI가 직접 선택을 구현한다(라인 단위).
    // MouseUp에서 drag가 있었으면 선택 줄들을 클립보드에 복사하고 해제한다. 클릭만은 no-op.
    let mut select: Option<(usize, usize, bool)> = None;
    // 이번 루프 반복에서 terminal.draw()를 호출할지. 기본 true이며, IME 조합 중 metrics tick이
    // 오면 그 반복만 false로 두어 자모 분리를 막는다(상태는 갱신하고 redraw만 건너뜀).
    let mut should_draw = true;

    loop {
        // status 지표는 전용 sampler task가 watch 채널로 밀어넣는다(아래 select! metrics arm에서 수신).
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
        // 지표가 있으면 단계별 색(주황/빨강) Line, 없으면(첫 sample 전) help 텍스트를 plain dim으로.
        let status_line: Line = match &status_segs {
            Some(segs) => build_status_line(segs, ctx_tokens),
            None => Line::from(Span::styled(
                status_with_ctx(&status, ctx_tokens),
                sev_style(Severity::Normal),
            )),
        };
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
        // 드래그 선택 중이면 선택 줄을 REVERSED로 강조한 사본을 그린다(log_text 원본 불변,
        // wrap 높이는 스타일과 무관해 scroll 계산은 그대로 정합).
        let highlighted;
        let draw_text: &Text = match select {
            Some((a, b, _)) => {
                highlighted = highlight_log_lines(&log_text, a, b);
                &highlighted
            }
            None => &log_text,
        };
        // IME 조합 중 metrics tick이 오면 should_draw=false로 이 redraw만 건너뛴다(자모 분리 방지).
        // status 상태는 이미 갱신돼 있어, 다음 안전한 이벤트(키 등)의 redraw가 새 status로 칠한다.
        if should_draw {
            let draw_ok = terminal
                .draw(|f| {
                    draw_full(
                        f,
                        draw_text,
                        draw_scroll,
                        status_line,
                        draw_ta,
                        draw_prompt,
                        &popup,
                        popup_sel,
                        spin_ref,
                        confirm_ref,
                    )
                })
                .is_ok();
            if !draw_ok {
                break;
            }
        }
        // 다음 반복은 기본적으로 그린다(metrics arm만 조건부로 false로 되돌린다).
        should_draw = true;

        // 입력 대기 중에는 자발적인 redraw를 하지 않는다. macOS/iTerm/Terminal의 한글 IME
        // 조합창은 앱이 커서 줄을 다시 그리면 자모가 분리되거나 옆으로 밀릴 수 있다. spinner처럼
        // 입력을 막는 상태에서만 100ms tick으로 애니메이션을 갱신한다.
        let tick = Duration::from_millis(100);
        // PageUp/Down 점프 폭(로그 높이의 절반, 최소 1).
        let page = (log_h / 2).max(1);

        tokio::select! {
            maybe_ev = events.next() => {
                match maybe_ev {
                    Some(Ok(Event::Key(k))) if !is_key_press(k) => {}
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
                            // Ctrl+C: 상황별로 동작이 갈린다(claude CLI 스타일).
                            //   작업 중(spin)      → 현재 turn만 취소(cancel 신호), 앱은 유지.
                            //   idle + 입력 있음   → 입력 줄 비우기(오타 입력 취소).
                            //   idle + 빈 입력     → EOF(세션 종료).
                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                if spin.is_some() {
                                    // 용량 1 채널이 차 있으면(이미 보냄) 무시 — 중복 Ctrl+C 자연 병합.
                                    let _ = cancel_tx.try_send(());
                                } else if !textarea.lines().join("\n").is_empty() {
                                    textarea = TextArea::default();
                                    hangul.reset();
                                    hist_idx = None;
                                    draft.clear();
                                } else {
                                    let _ = line_tx.send(ChatLine::Eof).await;
                                }
                            }
                            // Ctrl+D: 전통적 EOF(항상 세션 종료).
                            (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                                let _ = line_tx.send(ChatLine::Eof).await;
                            }
                            // Ctrl+F: 로그 검색 모드 진입(spin 없을 때만). 빈 쿼리로 시작.
                            (KeyCode::Char('f'), KeyModifiers::CONTROL) if spin.is_none() => {
                                search = Some(String::new());
                                search_hits.clear();
                                search_idx = 0;
                            }
                            // Ctrl+Y: 대화 전체를 클립보드에 복사(ANSI 제거). 부분 복사는 드래그
                            // 선택으로, 전체는 키 하나로. SSH 원격은 OSC 52 경로가 담당한다.
                            (KeyCode::Char('y'), KeyModifiers::CONTROL) => {
                                let text = log
                                    .iter()
                                    .map(|l| strip_ansi(l))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                copy_to_clipboard(&text);
                                status =
                                    format!("· 대화 {}줄을 클립보드에 복사했습니다 (Ctrl+Y)", log.len());
                            }
                            // Ctrl+T: 마우스 캡처 토글. OFF 면 터미널 네이티브 드래그 선택/복사가
                            // 가능해지고, ON 이면 휠 스크롤이 로그 viewport 로 동작한다.
                            (KeyCode::Char('t'), KeyModifiers::CONTROL) => {
                                mouse_captured = !mouse_captured;
                                if mouse_captured {
                                    let _ = execute!(io::stdout(), EnableMouseCapture);
                                    status = String::from("· 마우스 캡처 ON — 휠 스크롤");
                                } else {
                                    let _ = execute!(io::stdout(), DisableMouseCapture);
                                    status = String::from(
                                        "· 마우스 캡처 OFF — 드래그 선택/복사 가능 (Ctrl+T 복귀)",
                                    );
                                }
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
                                hangul.reset();
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
                                hangul.reset();
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
                                hangul.reset();
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
                                    hangul.reset();
                                }
                            }
                            _ if spin.is_none() => {
                                // 일반 편집 — history 탐색 종료(현재 내용이 새 입력).
                                hist_idx = None;
                                if !hangul.input(&mut textarea, k) {
                                    textarea.input(k);
                                }
                            }
                            _ => {}
                        }
                    }
                    // 마우스 휠: 로그 viewport 스크롤(↑↓ 입력 history 대신). PageUp/Down과 동일한
                    // follow 규칙 — 위로 굴리면 follow 해제, 아래로 굴려 최하단 도달 시 follow 재개.
                    // 검색/확인 모드와 무관하게 스크롤만 한다(입력 상태는 건드리지 않음).
                    // 좌클릭 드래그: 로그 줄 선택(REVERSED 강조) → 놓으면 클립보드 복사.
                    Some(Ok(Event::Mouse(m))) => match m.kind {
                        MouseEventKind::ScrollUp => {
                            follow = false;
                            scroll = scroll.saturating_sub(WHEEL_STEP);
                        }
                        MouseEventKind::ScrollDown => {
                            scroll = (scroll + WHEEL_STEP).min(max);
                            if scroll >= max {
                                follow = true;
                            }
                        }
                        MouseEventKind::Down(MouseButton::Left) => {
                            select = None;
                            if !log.is_empty() {
                                let heights = wrapped_line_heights(&log_text, area.width);
                                let total = heights.iter().map(|h| u32::from(*h)).sum::<u32>()
                                    .min(u32::from(u16::MAX)) as u16;
                                if let Some(row) =
                                    mouse_log_row(m.row, area.y, log_h, total, scroll)
                                {
                                    let li = display_row_to_line(&heights, row);
                                    select = Some((li, li, false));
                                }
                            }
                        }
                        MouseEventKind::Drag(MouseButton::Left) => {
                            if let Some((anchor, cur, moved)) = select.as_mut() {
                                *moved = true;
                                let heights = wrapped_line_heights(&log_text, area.width);
                                let total = heights.iter().map(|h| u32::from(*h)).sum::<u32>()
                                    .min(u32::from(u16::MAX)) as u16;
                                if let Some(row) =
                                    mouse_log_row(m.row, area.y, log_h, total, scroll)
                                {
                                    *cur = display_row_to_line(&heights, row);
                                }
                                // 선택 범위를 status로 실시간 안내(강조와 함께 영역을 알 수 있게).
                                let n = anchor.abs_diff(*cur) + 1;
                                status = format!("· {n}줄 선택 중 — 놓으면 복사");
                            }
                        }
                        MouseEventKind::Up(MouseButton::Left) => {
                            if let Some((a, b, moved)) = select.take() {
                                // 클릭만(드래그 없음)은 선택 해제만 — 복사하지 않는다.
                                // ring 폐기로 로그가 줄었을 수 있어 인덱스를 현재 길이로 clamp.
                                if moved && !log.is_empty() {
                                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                                    let hi = hi.min(log.len() - 1);
                                    let lo = lo.min(hi);
                                    let text = strip_ansi(&log[lo..=hi].join("\n"));
                                    copy_to_clipboard(&text);
                                    status = format!(
                                        "· {}줄을 클립보드에 복사했습니다 (드래그)",
                                        hi - lo + 1
                                    );
                                }
                            }
                        }
                        _ => {}
                    },
                    // 그 외 이벤트(Resize/Focus/Paste)는 무시 — Resize는 다음 루프 draw가
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
            _ = tokio::time::sleep(tick), if spin.is_some() => {
                if let Some(sp) = spin.as_mut() {
                    sp.frame = sp.frame.wrapping_add(1);
                }
            }
            // 전용 sampler task가 새 지표를 publish하면 status/segs를 갱신한다. 채널이 없으면(statusbar
            // 비활성) 영원히 pending이라 이 arm은 비활성이다. 닫히면(task 종료) arm을 끈다(busy-loop 방지).
            poll = async {
                match metrics_rx.as_mut() {
                    Some(rx) => match rx.changed().await {
                        Ok(()) => match rx.borrow_and_update().clone() {
                            Some(m) => MetricsPoll::New(m),
                            None => MetricsPoll::Empty,
                        },
                        Err(_) => MetricsPoll::Closed,
                    },
                    None => std::future::pending().await,
                }
            } => {
                match poll {
                    MetricsPoll::New(m) => {
                        status = format!("· {}", m.status_line());
                        status_segs = Some(m.status_segments());
                        // 조합 중이면 이 redraw만 건너뛴다(상태는 갱신됨, 다음 키 입력이 칠한다).
                        if hangul.is_composing() {
                            should_draw = false;
                        }
                    }
                    MetricsPoll::Empty => {}
                    MetricsPoll::Closed => {
                        metrics_rx = None;
                    }
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

    // 전용 sampler task 중단(수신자 drop만으로도 다음 cycle에 끝나지만 즉시 정리).
    if let Some(handle) = sampler_task {
        handle.abort();
    }
    // 마우스 캡처 해제 + alternate screen 떠나고 raw mode 복원(원래 화면 복귀).
    let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
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
    fn base64_encode_matches_known_vectors() {
        // RFC 4648 테스트 벡터 + padding 경계.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // 멀티바이트(UTF-8) — 한글.
        assert_eq!(base64_encode("안녕".as_bytes()), "7JWI64WV");
    }

    #[test]
    fn strip_ansi_removes_color_and_keeps_text() {
        // SGR 색상.
        assert_eq!(strip_ansi("\x1b[31m빨강\x1b[0m"), "빨강");
        // 복합 CSI.
        assert_eq!(strip_ansi("\x1b[1;38;5;204mbold\x1b[0m text"), "bold text");
        // OSC(BEL 종료).
        assert_eq!(strip_ansi("a\x1b]0;title\x07b"), "ab");
        // escape 없는 평문은 그대로.
        assert_eq!(strip_ansi("plain"), "plain");
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty())
    }

    fn type_chars(chars: &[char]) -> String {
        let mut ta = TextArea::default();
        let mut hangul = HangulComposer::default();
        for &c in chars {
            let k = key(c);
            if !hangul.input(&mut ta, k) {
                ta.input(k);
            }
        }
        ta.lines().join("\n")
    }

    #[test]
    fn hangul_composer_combines_compat_jamo() {
        assert_eq!(type_chars(&['ㅎ', 'ㅏ', 'ㄴ', 'ㄱ', 'ㅡ', 'ㄹ']), "한글");
    }

    #[test]
    fn hangul_composer_splits_final_before_vowel() {
        assert_eq!(type_chars(&['ㄴ', 'ㅏ', 'ㄴ', 'ㅏ']), "나나");
    }

    #[test]
    fn hangul_composer_combines_vowels_and_final_clusters() {
        assert_eq!(type_chars(&['ㄱ', 'ㅗ', 'ㅏ']), "과");
        assert_eq!(type_chars(&['ㅇ', 'ㅓ', 'ㅂ', 'ㅅ']), "없");
    }

    #[test]
    fn hangul_composer_leaves_native_syllables_alone() {
        assert_eq!(type_chars(&['한', '글']), "한글");
        assert_eq!(type_chars(&['ㄱ', 'a']), "ㄱa");
    }

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
        assert!(
            super::slash_candidates("/local ").is_empty(),
            "공백=인자 입력→닫힘"
        );
        assert!(
            super::slash_candidates("/").len() >= 10,
            "/ 단독은 전체 후보"
        );
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
    fn wrapped_heights_and_display_row_mapping() {
        // 25자 줄은 width 10에서 3행으로 wrap → 누적 높이로 행→줄 매핑.
        let text = Text::from(vec![
            Line::raw("short"),
            Line::raw("x".repeat(25)),
            Line::raw("tail"),
        ]);
        let h = super::wrapped_line_heights(&text, 10);
        assert_eq!(h, vec![1, 3, 1]);
        assert_eq!(super::display_row_to_line(&h, 0), 0);
        assert_eq!(super::display_row_to_line(&h, 1), 1);
        assert_eq!(super::display_row_to_line(&h, 3), 1);
        assert_eq!(super::display_row_to_line(&h, 4), 2);
        // 범위 밖은 마지막 줄로 clamp.
        assert_eq!(super::display_row_to_line(&h, 99), 2);
    }

    #[test]
    fn mouse_log_row_bottom_align_and_scroll() {
        // 내용(3) < 영역(10): 하단 정렬 — 위 7행은 패딩(None), 8행째가 첫 내용.
        assert_eq!(super::mouse_log_row(6, 0, 10, 3, 0), None);
        assert_eq!(super::mouse_log_row(7, 0, 10, 3, 0), Some(0));
        assert_eq!(super::mouse_log_row(9, 0, 10, 3, 0), Some(2));
        // 내용(20) > 영역(10): scroll 오프셋 가산.
        assert_eq!(super::mouse_log_row(0, 0, 10, 20, 5), Some(5));
        assert_eq!(super::mouse_log_row(9, 0, 10, 20, 5), Some(14));
        // 로그 영역 밖(입력/status 줄)은 None.
        assert_eq!(super::mouse_log_row(10, 0, 10, 20, 5), None);
        // log_top 오프셋 반영.
        assert_eq!(super::mouse_log_row(1, 2, 10, 20, 0), None);
        assert_eq!(super::mouse_log_row(2, 2, 10, 20, 0), Some(0));
    }

    #[test]
    fn highlight_survives_ansi_spans_repro() {
        // ANSI 색+reset이 섞인 줄(실제 로그와 동일 경로: rebuild_log_text)에 highlight를 적용해
        // 렌더된 buffer 셀에 REVERSED가 남는지 확인한다.
        let log = vec!["\x1b[34mblue\x1b[0m tail".to_string(), "plain".to_string()];
        let text = super::rebuild_log_text(&log);
        let t = super::highlight_log_lines(&text, 0, 1);
        let backend = ratatui::backend::TestBackend::new(20, 2);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            f.render_widget(Paragraph::new(t.clone()).wrap(Wrap { trim: false }), f.area());
        })
        .unwrap();
        let buf = term.backend().buffer();
        for (x, y, what) in [(0u16, 0u16, "blue 첫 글자"), (5, 0, "tail"), (0, 1, "plain")] {
            assert!(
                buf[(x, y)].modifier.contains(Modifier::REVERSED),
                "{what} 셀에 REVERSED 없음: {:?}",
                buf[(x, y)]
            );
        }
    }

    #[test]
    fn highlight_log_lines_reverses_range_only() {
        let text = Text::from(vec![Line::raw("a"), Line::raw("b"), Line::raw("c")]);
        // 순서 무관(2,1) → [1,2]만 REVERSED, 0은 그대로.
        let t = super::highlight_log_lines(&text, 2, 1);
        assert!(!t.lines[0].style.add_modifier.contains(Modifier::REVERSED));
        assert!(t.lines[1].style.add_modifier.contains(Modifier::REVERSED));
        assert!(t.lines[2].style.add_modifier.contains(Modifier::REVERSED));
        // 범위가 로그 길이를 넘어도 패닉 없음.
        let t2 = super::highlight_log_lines(&text, 1, 99);
        assert!(t2.lines[1].style.add_modifier.contains(Modifier::REVERSED));
        assert!(t2.lines[2].style.add_modifier.contains(Modifier::REVERSED));
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
        term.draw(|f| super::draw_full(f, &log, 0, super::Line::from("· load"), &ta, "you ❯ ", &[], 0, None, None))
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
                super::Line::from("· load"),
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
        assert!(
            !all.contains("diagnose"),
            "confirm 중 popup 미표시: {all:?}"
        );
    }

    #[test]
    fn draw_full_popup_vertical_with_desc() {
        // popup 활성: 입력 위에 세로 목록(명령+설명).
        let log = Text::from("x");
        let ta = super::textarea_with("/d");
        let mut term = Terminal::new(TestBackend::new(70, 10)).unwrap();
        term.draw(|f| {
            super::draw_full(
                f,
                &log,
                0,
                super::Line::from("· load"),
                &ta,
                "you ❯ ",
                &["diagnose", "doctor"],
                1,
                None,
                None,
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
        assert!(
            row(1).contains("diagnose"),
            "popup 선택+설명(row1): {:?}",
            row(1)
        );
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
        assert_eq!(
            super::status_with_ctx("· load", 12_345),
            "· load · ctx ~12k"
        );
        // 1000 미만은 정확한 수(~512), 1000 이상은 ~Nk.
        assert_eq!(super::status_with_ctx("s", 999), "s · ctx ~999");
        assert_eq!(super::status_with_ctx("s", 1000), "s · ctx ~1k");
    }

    #[test]
    fn build_status_line_colors_by_severity() {
        use super::Severity::{Crit, Normal, Warn};
        let segs = vec![
            ("load 1.0".to_string(), Normal),
            ("cpu 88%".to_string(), Warn),
            ("mem 99%".to_string(), Crit),
        ];
        let line = super::build_status_line(&segs, 1500);
        // 텍스트는 status_line과 동일 토큰 + ctx 접미.
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("load 1.0") && text.contains("cpu 88%") && text.contains("mem 99%"));
        assert!(text.contains("ctx ~1k"), "ctx 접미: {text}");
        // 위반 세그먼트가 정확한 색을 들고 있다: warn=주황, crit=빨강, 정상=색 없음(dim).
        let span = |needle: &str| {
            line.spans
                .iter()
                .find(|s| s.content.contains(needle))
                .unwrap_or_else(|| panic!("span 없음: {needle}"))
                .style
        };
        assert_eq!(span("cpu 88%").fg, Some(ratatui::style::Color::Rgb(255, 165, 0)));
        assert_eq!(span("mem 99%").fg, Some(ratatui::style::Color::Red));
        assert_eq!(span("load 1.0").fg, None); // 정상은 색 미지정(dim modifier만)
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
        term.draw(|f| super::draw_full(f, &log, 0, super::Line::from("· load"), &ta, "", &[], 0, None, None))
            .unwrap();
        let buf = term.backend().buffer();
        let row = |y: u16| (0..40).map(|x| buf[(x, y)].symbol()).collect::<String>();
        assert!(
            row(5).contains("/found"),
            "search bar(입력 줄): {:?}",
            row(5)
        );
        assert!(row(5).contains("(1/1)"), "카운터: {:?}", row(5));
    }

    #[test]
    fn draw_full_status_shows_ctx_tokens() {
        // status 끝에 ctx 토큰이 합쳐져 그려지는지(status_line 합성 후 draw_full로).
        let log = Text::from("x");
        let ta = super::textarea_with("hi");
        let status = super::status_with_ctx("· load", 12_000);
        let mut term = Terminal::new(TestBackend::new(40, 6)).unwrap();
        term.draw(|f| {
            super::draw_full(f, &log, 0, super::Line::from(status.clone()), &ta, "you ❯ ", &[], 0, None, None)
        })
        .unwrap();
        let buf = term.backend().buffer();
        let row5: String = (0..40).map(|x| buf[(x, 5)].symbol()).collect();
        assert!(row5.contains("ctx ~12k"), "status에 ctx: {row5:?}");
    }

    #[test]
    fn draw_full_status_row_paints_crit_red() {
        // 엔드투엔드: crit 세그먼트가 status 행 셀에 실제 빨강(fg=Red)으로 그려지는지(렌더 파이프라인).
        use super::Severity::{Crit, Normal};
        let log = Text::from("x");
        let ta = super::textarea_with("hi");
        let segs = vec![("load 1.0".to_string(), Normal), ("mem 99%".to_string(), Crit)];
        let status = super::build_status_line(&segs, 0);
        let mut term = Terminal::new(TestBackend::new(60, 6)).unwrap();
        term.draw(|f| super::draw_full(f, &log, 0, status, &ta, "you ❯ ", &[], 0, None, None))
            .unwrap();
        let buf = term.backend().buffer();
        // status 행(맨 아래 = height-1 = 5)에서 'mem' 글자가 있는 셀이 빨강인지 확인.
        let row = 5u16;
        let red = (0..60).any(|x| {
            let cell = &buf[(x, row)];
            cell.symbol() == "m" && cell.style().fg == Some(ratatui::style::Color::Red)
        });
        assert!(red, "crit 세그먼트가 빨강으로 렌더되지 않음");
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
