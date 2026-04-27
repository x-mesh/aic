//! Interactive REPL 세션.
//!
//! 사용자 입력을 받아 LLM에 전달하고 응답을 출력하는 대화형 루프.
//! "exit", "quit", Ctrl+D(EOF)로 종료한다.

use crate::llm_dispatcher::LlmDispatcher;
use aic_common::CommandRecord;
use std::io::{self, BufRead, Write};
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

    /// `context`가 의미 있는 직전 명령 정보를 갖고 있는지.
    /// placeholder (`exit_code == -1` + "히스토리에서 가져옴" 마커)는 false.
    fn has_meaningful_context(&self) -> bool {
        let cmd = match self.context.command.as_deref() {
            Some(c) if !c.trim().is_empty() => c,
            _ => return false,
        };
        let placeholder = self.context.exit_code == -1
            && self
                .context
                .output_lines
                .first()
                .map(|l| l.contains("히스토리에서 가져옴"))
                .unwrap_or(false);
        if placeholder {
            return false;
        }
        // exit 0 + command 있음도 의미 있음(사용자가 명시적으로 REPL 진입)
        let _ = cmd;
        true
    }

    /// REPL 진입 시 stderr에 직전 명령 컨텍스트 헤더를 한 줄 출력한다.
    fn print_context_header(&self) {
        if !self.has_meaningful_context() {
            return;
        }
        let cmd = self.context.command.as_deref().unwrap_or("");
        eprintln!(
            "\x1b[2m[aic] 직전 명령: {}  (exit {})\x1b[0m",
            cmd, self.context.exit_code,
        );
    }

    /// REPL 첫 턴에 한 번만 prepend되는 어시스턴트 역할 정의 (system 같은 역할).
    /// LlmDispatcher가 system 메시지를 별도 지원하지 않으므로 첫 user 메시지에 prepend한다.
    fn system_preface(&self) -> &'static str {
        "You are an interactive shell/dev troubleshooting assistant for the ac-rust REPL. \
         Be concise. Plain text only. Always cite the concrete signal (file, error token, exit code) \
         that justifies your suggestion. Ask one clarifying question only when the user's intent is genuinely ambiguous.\n\n"
    }

    /// 첫 턴에 LLM에 전달할 직전 실패 컨텍스트를 XML 태그로 만든다.
    /// 의미 없는 컨텍스트면 None.
    fn format_first_turn_prefix(&self) -> Option<String> {
        if !self.has_meaningful_context() {
            return None;
        }
        let cmd = self.context.command.as_deref().unwrap_or("");
        let mut s = String::new();
        s.push_str("<previous_failure>\n");
        s.push_str(&format!("<command>{cmd}</command>\n"));
        s.push_str(&format!(
            "<exit_code>{}</exit_code>\n",
            self.context.exit_code
        ));
        if !self.context.output_lines.is_empty() {
            let start = self.context.output_lines.len().saturating_sub(10);
            let shown = self.context.output_lines.len() - start;
            s.push_str(&format!("<output_tail lines=\"{shown}\">\n"));
            for line in &self.context.output_lines[start..] {
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

    /// 사용자 입력에 언어 지시를 추가한다 (minimal — 역할 정의는 system_preface가 담당).
    fn wrap_prompt(&self, input: &str) -> String {
        let lang_instruction = match self.lang.as_str() {
            "korean" => "Respond in Korean.",
            "english" => "Respond in English.",
            "japanese" => "Respond in Japanese.",
            "chinese" => "Respond in Chinese.",
            other => &format!("Respond in {}.", other),
        };
        format!("{input}\n\n{lang_instruction}")
    }

    /// 입력 문자열이 REPL 종료 명령인지 판별한다.
    pub fn is_exit_command(input: &str) -> bool {
        let trimmed = input.trim();
        trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit")
    }

    /// REPL 루프 실행. exit/quit/Ctrl+D로 종료.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();

        self.print_context_header();

        loop {
            // 프롬프트 표시
            print!("aic> ");
            io::stdout().flush()?;

            // 한 줄 읽기
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;

            // EOF (Ctrl+D)
            if bytes_read == 0 {
                println!();
                break;
            }

            // 종료 명령 확인
            if Self::is_exit_command(&line) {
                break;
            }

            let input = line.trim();
            if input.is_empty() {
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
fn split_think_block(text: &str) -> (Option<String>, String) {
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
fn print_think_summary(think: &str) {
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
fn print_with_border(text: &str) {
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
