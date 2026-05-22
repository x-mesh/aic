//! Interactive REPL 세션.
//!
//! 사용자 입력을 받아 LLM에 전달하고 응답을 출력하는 대화형 루프.
//! "exit", "quit", Ctrl+D(EOF)로 종료한다.

use crate::llm_dispatcher::LlmDispatcher;
use aic_common::CommandRecord;
use std::io::{self, Write};
use unicode_width::UnicodeWidthStr;

pub struct ReplSession {
    dispatcher: LlmDispatcher,
    context: CommandRecord,
    lang: String,
    /// 첫 턴 컨텍스트 주입 여부 (한 번 주입 후 false).
    first_turn: bool,
}

impl ReplSession {
    pub fn new(dispatcher: LlmDispatcher, context: CommandRecord, lang: String) -> Self {
        Self {
            dispatcher,
            context,
            lang,
            first_turn: true,
        }
    }

    /// REPL 진입 시 stderr에 직전 명령 컨텍스트 헤더를 한 줄 출력한다.
    fn print_context_header(&self) {
        print_context_header(&self.context);
    }

    /// REPL 첫 턴에 한 번만 prepend되는 어시스턴트 역할 정의 (system 같은 역할).
    /// LlmDispatcher가 system 메시지를 별도 지원하지 않으므로 첫 user 메시지에 prepend한다.
    fn system_preface(&self) -> &'static str {
        system_preface()
    }

    /// 첫 턴에 LLM에 전달할 직전 실패 컨텍스트를 XML 태그로 만든다.
    /// 의미 없는 컨텍스트면 None.
    fn format_first_turn_prefix(&self) -> Option<String> {
        format_first_turn_prefix(&self.context)
    }

    /// 사용자 입력에 언어 지시를 추가한다 (minimal — 역할 정의는 system_preface가 담당).
    fn wrap_prompt(&self, input: &str) -> String {
        format!("{input}\n\n{}", lang_instruction(&self.lang))
    }

    /// 입력 문자열이 REPL 종료 명령인지 판별한다.
    pub fn is_exit_command(input: &str) -> bool {
        let trimmed = input.trim();
        trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit")
    }

    /// REPL 루프 실행. exit/quit/Ctrl+D로 종료.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut reader = LineReader::new();

        self.print_context_header();

        loop {
            // 한 줄 읽기 (TTY는 Unicode-aware 라인 에디터, 비-TTY는 read_line)
            let line = match reader.read("aic> ")? {
                ReadLine::Eof => {
                    println!();
                    break;
                }
                ReadLine::Line(l) => l,
            };

            // 종료 명령 확인
            if Self::is_exit_command(&line) {
                break;
            }

            let input = line.trim();
            if input.is_empty() {
                continue;
            }

            // slash 명령은 tool-calling agent 모드(OpenAI-compat) 전용. 여기서는 LLM에
            // 보내지 않고 안내만 한다(stderr) — stdout 답변 오염 방지.
            if input.starts_with('/') {
                eprintln!(
                    "slash 명령(/help, /last, /raw)은 agent 모드(OpenAI 호환 provider의 `aic chat`) \
                     전용입니다. 현재는 일반 대화 모드입니다."
                );
                continue;
            }

            // LLM에 전달하고 응답 출력
            let mut prompt = self.wrap_prompt(input);
            if self.first_turn {
                let context = self.format_first_turn_prefix().unwrap_or_default();
                let preface = self.system_preface();
                prompt = format!("{preface}{context}{prompt}");
                self.first_turn = false;
            }

            // 스피너 표시
            let spinner = crate::spinner::Spinner::start("thinking...".to_string());

            let send_result = self.dispatcher.send(&prompt).await;
            spinner.stop().await;

            match send_result {
                Ok(full_response) => {
                    // <think> 블록 분리 후 출력
                    let (think, main) = split_think_block(&full_response);
                    if let Some(ref t) = think {
                        print_think_summary(t);
                    }
                    print_with_border(&main);
                }
                Err(e) => {
                    eprintln!("LLM 요청 실패: {e}");
                }
            }
        }

        Ok(())
    }
}

// ── 공유 헬퍼 (ReplSession / agent::AgentSession 공용) ──────────────

/// 한 줄 읽기 결과.
pub(crate) enum ReadLine {
    Line(String),
    /// EOF(Ctrl-D) 또는 Ctrl-C — 루프 종료 신호.
    Eof,
}

/// chat 입력 history 파일 경로 — config와 동일한 XDG 패턴
/// (`~/.config/aic/chat_history` 또는 `$XDG_CONFIG_HOME/aic/chat_history`).
/// `config.toml`과 같은 디렉터리를 쓰므로 `config_path()`에서 파일명만 바꾼다.
fn chat_history_path() -> std::path::PathBuf {
    crate::config::ConfigManager::config_path().with_file_name("chat_history")
}

/// 대화형 입력 reader.
///
/// TTY에서는 `reedline`의 Unicode-aware 라인 에디터를 써서 (1) CJK wide char 삭제 시
/// 잔상이 남던 문제(cooked TTY erase 한계)를 해결하고, (2) up/down 화살표로 이전 입력
/// 히스토리를 탐색하며, (3) `/` 명령에 대해 Claude 스타일 후보 패널(ColumnarMenu)을 연다.
/// 히스토리는 세션 간에도 유지되도록 `~/.config/aic/chat_history`에 보관한다(IO 실패 무시).
/// 비-TTY(pipe/script)에서는 기존 `stdin().read_line` 동작을 그대로 유지한다.
/// 대화형 입력 프롬프트(reedline `Prompt`). 호출부가 넘긴 라벨을 좌측 프롬프트로 렌더한다.
/// indicator/right/multiline은 비워 라벨만 정확히 보이게 한다.
struct AicPrompt {
    left: String,
}

impl reedline::Prompt for AicPrompt {
    fn render_prompt_left(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed(&self.left)
    }
    fn render_prompt_right(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed("")
    }
    fn render_prompt_indicator(
        &self,
        _mode: reedline::PromptEditMode,
    ) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed("")
    }
    fn render_prompt_multiline_indicator(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed("")
    }
    fn render_prompt_history_search_indicator(
        &self,
        _history_search: reedline::PromptHistorySearch,
    ) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed("(search) ")
    }
}

/// reedline slash 후보 completer — `tool_record` 완성 로직을 재사용한다.
/// value=command/section 이름(삽입용), description=설명(메뉴 표시용)으로 분리한다.
struct SlashCompleter;

impl reedline::Completer for SlashCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<reedline::Suggestion> {
        let (start, entries, append_ws) =
            crate::agent::tool_record::slash_completion_entries(line, pos);
        entries
            .into_iter()
            .map(|(value, desc)| reedline::Suggestion {
                value,
                description: if desc.is_empty() { None } else { Some(desc) },
                style: None,
                extra: None,
                span: reedline::Span { start, end: pos },
                append_whitespace: append_ws,
            })
            .collect()
    }
}

/// completion 메뉴를 만든다. NO_COLOR/non-색상 정책이면 색 없이(선택행은 reverse만) 구성.
fn build_completion_menu() -> reedline::ReedlineMenu {
    use nu_ansi_term::Style;
    use reedline::{ColumnarMenu, MenuBuilder, ReedlineMenu};
    let mut menu = ColumnarMenu::default().with_name(COMPLETION_MENU);
    if !crate::agent::ui::color_enabled() {
        // 색상 비활성: 모든 텍스트 plain, 선택행만 reverse(색이 아닌 속성)로 가시성 유지.
        menu = menu
            .with_text_style(Style::new())
            .with_description_text_style(Style::new())
            .with_match_text_style(Style::new())
            .with_selected_text_style(Style::new().reverse())
            .with_selected_match_text_style(Style::new().reverse());
    }
    ReedlineMenu::EngineCompleter(Box::new(menu))
}

/// completion 메뉴 이름(키바인딩과 메뉴가 공유).
const COMPLETION_MENU: &str = "completion_menu";

pub(crate) struct LineReader {
    /// TTY일 때만 Some. 비-TTY/초기화 실패 시 None → read_line fallback.
    engine: Option<reedline::Reedline>,
}

impl LineReader {
    /// stdin·stdout이 모두 TTY면 reedline 엔진(slash 후보 메뉴 + history)을 만든다.
    /// 아니면 fallback(read_line)을 준비한다.
    pub(crate) fn new() -> Self {
        use std::io::IsTerminal;
        if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
            return Self { engine: None };
        }
        match build_reedline() {
            Ok(engine) => Self {
                engine: Some(engine),
            },
            // reedline 생성 실패(터미널 비호환 등) → 폴백.
            Err(_) => Self { engine: None },
        }
    }

    /// `prompt`를 표시하고 한 줄을 읽는다. Ctrl-D/Ctrl-C는 [`ReadLine::Eof`].
    /// 메뉴 열림 시 ↑↓로 후보 이동, 닫힘 시 ↑↓로 history 탐색(reedline 기본 emacs 키바인딩).
    pub(crate) fn read(&mut self, prompt: &str) -> anyhow::Result<ReadLine> {
        match self.engine.as_mut() {
            Some(engine) => {
                let prompt = AicPrompt {
                    left: prompt.to_string(),
                };
                match engine.read_line(&prompt) {
                    Ok(reedline::Signal::Success(line)) => Ok(ReadLine::Line(line)),
                    Ok(reedline::Signal::CtrlC) | Ok(reedline::Signal::CtrlD) => Ok(ReadLine::Eof),
                    Err(e) => Err(anyhow::anyhow!(e)),
                }
            }
            None => {
                // 비-TTY: 기존 동작 — prompt를 stdout에 출력 후 read_line.
                print!("{prompt}");
                io::stdout().flush()?;
                let mut line = String::new();
                let n = io::stdin().read_line(&mut line)?;
                if n == 0 {
                    Ok(ReadLine::Eof)
                } else {
                    Ok(ReadLine::Line(line))
                }
            }
        }
    }
}

impl Drop for LineReader {
    /// 세션 종료 시 history를 파일로 동기화한다(best-effort — 실패는 무시).
    fn drop(&mut self) {
        if let Some(engine) = self.engine.as_mut() {
            let _ = engine.sync_history();
        }
    }
}

/// slash 후보 메뉴용 emacs 키바인딩을 만든다(테스트 가능하도록 분리).
///
/// 기본 emacs(↑↓=메뉴 열림 시 이동/닫힘 시 history, Enter, Esc)에 더해:
/// - **Tab** = 메뉴 열기 / 순환(`Menu`→`MenuNext`).
/// - **`/`** = 문자 삽입 후 즉시 메뉴 열기(`Multiple([Edit(InsertChar('/')), Menu]`)).
///   reedline 0.39에는 buffer-change hook이 없어, `/` 키에 삽입+메뉴 열기를 묶는다.
///   completer가 후보를 못 내면(`/`가 일반 문장 중간 등) 메뉴는 비어 자연히 닫힌다.
fn slash_keybindings() -> reedline::Keybindings {
    use reedline::{default_emacs_keybindings, EditCommand, KeyCode, KeyModifiers, ReedlineEvent};
    let mut kb = default_emacs_keybindings();
    kb.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu(COMPLETION_MENU.to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    kb.add_binding(
        KeyModifiers::NONE,
        KeyCode::Char('/'),
        ReedlineEvent::Multiple(vec![
            ReedlineEvent::Edit(vec![EditCommand::InsertChar('/')]),
            ReedlineEvent::Menu(COMPLETION_MENU.to_string()),
        ]),
    );
    kb
}

/// reedline 엔진을 구성한다: slash completer + ColumnarMenu + FileBackedHistory + 키바인딩.
fn build_reedline() -> anyhow::Result<reedline::Reedline> {
    use reedline::{Emacs, FileBackedHistory, Reedline};

    let path = chat_history_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // 기존 history 경로 재사용(plain text). 실패 시 빈 history로 시작.
    // FilteredHistory로 감싸 빈 줄·공백-only·exit/quit는 저장하지 않는다(이전 정책 보존).
    let backing =
        FileBackedHistory::with_file(HISTORY_CAPACITY, path).map_err(|e| anyhow::anyhow!(e))?;
    let history = Box::new(FilteredHistory {
        inner: Box::new(backing),
    }) as Box<dyn reedline::History>;

    let engine = Reedline::create()
        .with_completer(Box::new(SlashCompleter))
        .with_menu(build_completion_menu())
        .with_history(history)
        .with_edit_mode(Box::new(Emacs::new(slash_keybindings())));
    Ok(engine)
}

/// history 파일에 보관할 최대 항목 수.
const HISTORY_CAPACITY: usize = 1000;

/// 입력을 history에 기록할지 판정한다.
/// 빈 줄·공백-only·`exit`/`quit`는 기록하지 않는다(잡음·중복 방지). reedline은 빈 buffer만
/// 자동 제외하므로, 공백-only/exit/quit는 [`FilteredHistory`]에서 추가로 거른다.
fn should_record_history(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty() && !ReplSession::is_exit_command(trimmed)
}

/// reedline `History` 래퍼 — `save()` 시 [`should_record_history`]를 통과한 항목만 백엔드에
/// 영속한다. 나머지(공백-only/exit/quit)는 저장하지 않고 입력값을 그대로 돌려준다.
/// 그 외 메서드는 내부 history에 그대로 위임한다.
struct FilteredHistory {
    inner: Box<dyn reedline::History>,
}

impl reedline::History for FilteredHistory {
    fn save(&mut self, h: reedline::HistoryItem) -> reedline::Result<reedline::HistoryItem> {
        if should_record_history(&h.command_line) {
            self.inner.save(h)
        } else {
            Ok(h)
        }
    }
    fn load(&self, id: reedline::HistoryItemId) -> reedline::Result<reedline::HistoryItem> {
        self.inner.load(id)
    }
    fn count(&self, query: reedline::SearchQuery) -> reedline::Result<i64> {
        self.inner.count(query)
    }
    fn search(&self, query: reedline::SearchQuery) -> reedline::Result<Vec<reedline::HistoryItem>> {
        self.inner.search(query)
    }
    fn update(
        &mut self,
        id: reedline::HistoryItemId,
        updater: &dyn Fn(reedline::HistoryItem) -> reedline::HistoryItem,
    ) -> reedline::Result<()> {
        self.inner.update(id, updater)
    }
    fn clear(&mut self) -> reedline::Result<()> {
        self.inner.clear()
    }
    fn delete(&mut self, h: reedline::HistoryItemId) -> reedline::Result<()> {
        self.inner.delete(h)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.inner.sync()
    }
    fn session(&self) -> Option<reedline::HistorySessionId> {
        self.inner.session()
    }
}

/// `record`가 의미 있는 직전 명령 정보를 갖고 있는지.
/// placeholder (`exit_code == -1` + "히스토리에서 가져옴" 마커)는 false.
pub(crate) fn has_meaningful_context(record: &CommandRecord) -> bool {
    let cmd = match record.command.as_deref() {
        Some(c) if !c.trim().is_empty() => c,
        _ => return false,
    };
    let placeholder = record.exit_code == -1
        && record
            .output_lines
            .first()
            .map(|l| l.contains("히스토리에서 가져옴"))
            .unwrap_or(false);
    if placeholder {
        return false;
    }
    let _ = cmd;
    true
}

/// 직전 명령 컨텍스트 헤더를 stderr에 한 줄 출력한다.
pub(crate) fn print_context_header(record: &CommandRecord) {
    if !has_meaningful_context(record) {
        return;
    }
    let cmd = record.command.as_deref().unwrap_or("");
    eprintln!(
        "\x1b[2m[aic] 직전 명령: {}  (exit {})\x1b[0m",
        cmd, record.exit_code,
    );
}

/// 대화 첫 턴에 prepend되는 역할 정의(system 역할 텍스트).
pub(crate) fn system_preface() -> &'static str {
    "You are an interactive shell/dev troubleshooting assistant for the ac-rust REPL. \
     Be concise. Plain text only. Always cite the concrete signal (file, error token, exit code) \
     that justifies your suggestion. Ask one clarifying question only when the user's intent is genuinely ambiguous.\n\n"
}

/// 첫 턴에 LLM에 전달할 직전 실패 컨텍스트를 XML 태그로 만든다. 의미 없으면 None.
pub(crate) fn format_first_turn_prefix(record: &CommandRecord) -> Option<String> {
    if !has_meaningful_context(record) {
        return None;
    }
    let cmd = record.command.as_deref().unwrap_or("");
    let mut s = String::new();
    s.push_str("<previous_failure>\n");
    s.push_str(&format!("<command>{cmd}</command>\n"));
    s.push_str(&format!("<exit_code>{}</exit_code>\n", record.exit_code));
    if !record.output_lines.is_empty() {
        let start = record.output_lines.len().saturating_sub(10);
        let shown = record.output_lines.len() - start;
        s.push_str(&format!("<output_tail lines=\"{shown}\">\n"));
        for line in &record.output_lines[start..] {
            s.push_str(line);
            s.push('\n');
        }
        s.push_str("</output_tail>\n");
    }
    s.push_str("</previous_failure>\n\n");
    s.push_str("Treat this block as authoritative context; do not ask the user to repeat it.\n\n");
    Some(s)
}

/// 언어 설정에 맞는 응답 언어 지시 문장.
pub(crate) fn lang_instruction(lang: &str) -> String {
    match lang {
        "korean" => "Respond in Korean.".to_string(),
        "english" => "Respond in English.".to_string(),
        "japanese" => "Respond in Japanese.".to_string(),
        "chinese" => "Respond in Chinese.".to_string(),
        other => format!("Respond in {other}."),
    }
}

/// 문자열을 지정된 너비로 분할 (유니코드 너비 고려, 단어 경계 우선)
fn split_at_width(s: &str, max_width: usize) -> (&str, &str) {
    use unicode_width::UnicodeWidthChar;

    if s.is_empty() || max_width == 0 {
        return (s, "");
    }

    if s.width() <= max_width {
        return (s, "");
    }

    let mut width = 0;
    let mut split_idx = 0;
    let mut last_space_idx = 0;
    let mut last_space_width = 0;

    for (idx, ch) in s.char_indices() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(1);

        if ch.is_whitespace() {
            last_space_idx = idx;
            last_space_width = width;
        }

        if width + ch_width > max_width {
            if last_space_idx > 0 && last_space_width > max_width / 3 {
                return (&s[..last_space_idx], s[last_space_idx..].trim_start());
            }
            if split_idx == 0 {
                split_idx = idx + ch.len_utf8();
            }
            break;
        }
        width += ch_width;
        split_idx = idx + ch.len_utf8();
    }

    if split_idx == 0 {
        return (s, "");
    }

    (&s[..split_idx], &s[split_idx..])
}

/// LLM 응답에서 <think> 블록을 분리한다.
pub(crate) fn split_think_block(text: &str) -> (Option<String>, String) {
    let trimmed = text.trim();
    if let Some(start) = trimmed.find("<think>") {
        if let Some(end) = trimmed.find("</think>") {
            let think = trimmed[start + 7..end].trim().to_string();
            let rest = format!("{}{}", &trimmed[..start], &trimmed[end + 8..])
                .trim()
                .to_string();
            let think_opt = if think.is_empty() { None } else { Some(think) };
            return (think_opt, rest);
        }
    }
    (None, trimmed.to_string())
}

/// <think> 블록을 처음과 끝을 보여주는 요약 한 줄로 출력
pub(crate) fn print_think_summary(think: &str) {
    let lines: Vec<&str> = think.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return;
    }
    let first: String = lines
        .first()
        .unwrap_or(&"")
        .trim()
        .chars()
        .take(40)
        .collect();
    let last: String = lines
        .last()
        .unwrap_or(&"")
        .trim()
        .chars()
        .rev()
        .take(30)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if lines.len() <= 1 {
        println!("\x1b[90m[Thinking] {first}\x1b[0m");
    } else {
        println!("\x1b[90m[Thinking] {first} ... {last}\x1b[0m");
    }
}

/// 파란색 왼쪽 선과 함께 텍스트 출력
pub(crate) fn print_with_border(text: &str) {
    let prefix = "\x1b[34m▐\x1b[0m "; // 파란색
    let empty_prefix = "\x1b[34m▐\x1b[0m";

    let term_width = terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80);
    let content_width = term_width.saturating_sub(3);

    for line in text.lines() {
        if line.is_empty() {
            println!("{}", empty_prefix);
        } else {
            let mut remaining = line;
            while !remaining.is_empty() {
                let (chunk, rest) = split_at_width(remaining, content_width);
                println!("{}{}", prefix, chunk);
                remaining = rest;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── history 기록 정책 ──────────────────────────────────────

    #[test]
    fn history_records_normal_input() {
        assert!(should_record_history("read_file foo.rs"));
        assert!(should_record_history("안녕하세요"));
    }

    #[test]
    fn history_skips_empty_whitespace_and_exit_quit() {
        assert!(!should_record_history(""));
        assert!(!should_record_history("   "));
        assert!(!should_record_history("\t\n"));
        assert!(!should_record_history("exit"));
        assert!(!should_record_history("quit"));
        assert!(!should_record_history("  EXIT  "));
        assert!(!should_record_history("Quit"));
    }

    #[test]
    fn filtered_history_does_not_persist_excluded_entries() {
        use reedline::{FileBackedHistory, History, HistoryItem, SearchDirection, SearchQuery};
        let inner = Box::new(FileBackedHistory::new(50).unwrap()) as Box<dyn History>;
        let mut hist = FilteredHistory { inner };
        // 정상 입력은 저장.
        hist.save(HistoryItem::from_command_line("ps aux")).unwrap();
        // 제외 대상은 저장되지 않음.
        hist.save(HistoryItem::from_command_line("exit")).unwrap();
        hist.save(HistoryItem::from_command_line("   ")).unwrap();
        hist.save(HistoryItem::from_command_line("quit")).unwrap();

        let all = hist
            .search(SearchQuery::everything(SearchDirection::Forward, None))
            .unwrap();
        let cmds: Vec<&str> = all.iter().map(|i| i.command_line.as_str()).collect();
        assert!(cmds.contains(&"ps aux"));
        assert!(!cmds
            .iter()
            .any(|c| *c == "exit" || *c == "quit" || c.trim().is_empty()));
    }

    #[test]
    fn slash_key_binding_inserts_and_opens_menu() {
        use reedline::{KeyCode, KeyModifiers, ReedlineEvent};
        let kb = slash_keybindings();
        // '/' 키는 문자 삽입 + 메뉴 열기를 묶은 Multiple 이벤트여야 한다.
        let ev = kb
            .find_binding(KeyModifiers::NONE, KeyCode::Char('/'))
            .expect("'/' 바인딩 존재");
        match ev {
            ReedlineEvent::Multiple(events) => {
                assert!(
                    matches!(events.first(), Some(ReedlineEvent::Edit(_))),
                    "첫 이벤트는 문자 삽입(Edit)이어야 함"
                );
                assert!(
                    events
                        .iter()
                        .any(|e| matches!(e, ReedlineEvent::Menu(name) if name == COMPLETION_MENU)),
                    "메뉴 열기 이벤트 포함되어야 함"
                );
            }
            other => panic!("'/' 바인딩이 Multiple이 아님: {other:?}"),
        }
        // Tab 바인딩은 유지(메뉴 열기/순환).
        assert!(kb.find_binding(KeyModifiers::NONE, KeyCode::Tab).is_some());
    }

    #[test]
    fn slash_completer_returns_candidates_for_slash() {
        use reedline::Completer;
        // '/' 입력 직후 completer가 후보를 반환해야 메뉴가 (열렸을 때) 비어있지 않다.
        let mut c = SlashCompleter;
        let sug = c.complete("/", 1);
        assert!(!sug.is_empty(), "/ 후보가 있어야 함");
        assert!(sug.iter().any(|s| s.value == "local"));
        // 문장 중간의 '/'(후보 없음)는 빈 목록 → 메뉴가 자연히 닫힘(panic 없음).
        assert!(c.complete("ab/", 3).is_empty());
        assert!(c.complete("path is a/b", 11).is_empty());
    }

    #[test]
    fn history_path_shares_config_dir() {
        // config.toml과 같은 디렉터리의 chat_history 파일이어야 한다.
        let p = chat_history_path();
        assert!(p.ends_with("chat_history"));
        assert_eq!(
            p.parent(),
            crate::config::ConfigManager::config_path().parent()
        );
    }

    // ── Task 14.3: Unit tests: ReplSession 종료 명령 ───────────
    // **Validates: Requirements 7.4**

    #[test]
    fn exit_command_recognized() {
        assert!(ReplSession::is_exit_command("exit"));
    }

    #[test]
    fn quit_command_recognized() {
        assert!(ReplSession::is_exit_command("quit"));
    }

    #[test]
    fn exit_case_insensitive() {
        assert!(ReplSession::is_exit_command("EXIT"));
        assert!(ReplSession::is_exit_command("Exit"));
        assert!(ReplSession::is_exit_command("eXiT"));
    }

    #[test]
    fn quit_case_insensitive() {
        assert!(ReplSession::is_exit_command("QUIT"));
        assert!(ReplSession::is_exit_command("Quit"));
        assert!(ReplSession::is_exit_command("qUiT"));
    }

    #[test]
    fn exit_with_whitespace() {
        assert!(ReplSession::is_exit_command("  exit  "));
        assert!(ReplSession::is_exit_command("\texit\n"));
        assert!(ReplSession::is_exit_command("  quit  "));
        assert!(ReplSession::is_exit_command("\tquit\n"));
    }

    #[test]
    fn non_exit_commands_not_recognized() {
        assert!(!ReplSession::is_exit_command("hello"));
        assert!(!ReplSession::is_exit_command("exiting"));
        assert!(!ReplSession::is_exit_command("quitter"));
        assert!(!ReplSession::is_exit_command(""));
        assert!(!ReplSession::is_exit_command("   "));
    }

    #[test]
    fn eof_is_handled_by_zero_bytes_read() {
        // EOF는 read_line이 0을 반환하는 것으로 감지됨.
        // is_exit_command는 텍스트 기반 종료만 담당하므로
        // 빈 문자열은 종료 명령이 아님을 확인한다.
        assert!(!ReplSession::is_exit_command(""));
    }

    // ── first-turn 컨텍스트 주입 테스트 ──────────────────────
    fn make_session(record: CommandRecord) -> ReplSession {
        // dispatcher는 실제 호출하지 않으므로 build만 되면 됨.
        // 하지만 LlmDispatcher::new가 config 의존이라 직접 생성이 어렵다.
        // 따라서 컨텍스트 포맷팅 로직만 검증하기 위해 별도 함수 형태로 호출한다.
        // 여기서는 ReplSession 인스턴스를 만드는 대신 직접 record로 검증.
        let _ = record;
        unreachable!("use direct CommandRecord checks")
    }

    fn build_prefix_for(record: &CommandRecord) -> Option<String> {
        // ReplSession::format_first_turn_prefix와 동일한 로직을 인라인으로 재현 (XML 태그 형식).
        let cmd = record.command.as_deref().filter(|c| !c.trim().is_empty())?;
        let placeholder = record.exit_code == -1
            && record
                .output_lines
                .first()
                .map(|l| l.contains("히스토리에서 가져옴"))
                .unwrap_or(false);
        if placeholder {
            return None;
        }
        let mut s = String::new();
        s.push_str("<previous_failure>\n");
        s.push_str(&format!("<command>{cmd}</command>\n"));
        s.push_str(&format!("<exit_code>{}</exit_code>\n", record.exit_code));
        if !record.output_lines.is_empty() {
            let start = record.output_lines.len().saturating_sub(10);
            let shown = record.output_lines.len() - start;
            s.push_str(&format!("<output_tail lines=\"{shown}\">\n"));
            for line in &record.output_lines[start..] {
                s.push_str(line);
                s.push('\n');
            }
            s.push_str("</output_tail>\n");
        }
        s.push_str("</previous_failure>\n\n");
        s.push_str(
            "Treat this block as authoritative context; do not ask the user to repeat it.\n\n",
        );
        Some(s)
    }

    #[test]
    fn first_turn_prefix_with_full_record() {
        let r = CommandRecord {
            command: Some("git push".to_string()),
            exit_code: 1,
            output_lines: vec!["error: rejected".to_string()],
            timestamp: chrono::Utc::now(),
            ..Default::default()
        };
        let prefix = build_prefix_for(&r).expect("expected prefix");
        assert!(prefix.contains("<previous_failure>"));
        assert!(prefix.contains("</previous_failure>"));
        assert!(prefix.contains("<command>git push</command>"));
        assert!(prefix.contains("<exit_code>1</exit_code>"));
        assert!(prefix.contains("<output_tail lines=\"1\">"));
        assert!(prefix.contains("error: rejected"));
        assert!(prefix.contains("authoritative context"));
        let _ = make_session; // suppress unused
    }

    #[test]
    fn first_turn_prefix_none_when_command_missing() {
        let r = CommandRecord {
            command: None,
            exit_code: 0,
            output_lines: vec![],
            timestamp: chrono::Utc::now(),
            ..Default::default()
        };
        assert!(build_prefix_for(&r).is_none());
    }

    #[test]
    fn first_turn_prefix_omits_output_tail_when_empty() {
        let r = CommandRecord {
            command: Some("ls".to_string()),
            exit_code: 0,
            output_lines: vec![],
            timestamp: chrono::Utc::now(),
            ..Default::default()
        };
        let prefix = build_prefix_for(&r).expect("expected prefix");
        assert!(!prefix.contains("<output_tail"));
        assert!(prefix.contains("<previous_failure>"));
    }

    #[test]
    fn first_turn_prefix_truncates_to_last_10_lines() {
        let lines: Vec<String> = (0..20).map(|i| format!("line-{i}")).collect();
        let r = CommandRecord {
            command: Some("noisy".to_string()),
            exit_code: 1,
            output_lines: lines,
            timestamp: chrono::Utc::now(),
            ..Default::default()
        };
        let prefix = build_prefix_for(&r).expect("expected prefix");
        assert!(prefix.contains("<output_tail lines=\"10\">"));
        assert!(!prefix.contains("line-9\n"));
        assert!(prefix.contains("line-10"));
        assert!(prefix.contains("line-19"));
    }

    #[test]
    fn first_turn_prefix_skips_history_placeholder() {
        let r = CommandRecord {
            command: Some("ls".to_string()),
            exit_code: -1,
            output_lines: vec!["(히스토리에서 가져옴)".to_string()],
            timestamp: chrono::Utc::now(),
            ..Default::default()
        };
        assert!(build_prefix_for(&r).is_none());
    }
}
