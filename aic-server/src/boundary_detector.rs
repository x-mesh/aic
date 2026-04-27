//! PTY 출력 스트림에서 명령어 경계(Command Boundary)를 식별한다.
//!
//! 두 가지 전략을 지원한다:
//! - PromptMarker: 셸 precmd/preexec 훅이 출력하는 OSC 133 시퀀스를 감지
//! - TimingHeuristic: 출력 간 idle 시간 기반 폴백
//!
//! Requirements: 4.1, 4.2, 4.3

use aic_common::CommandRecord;
use std::time::{Duration, Instant};

// ── OSC 133 마커 패턴 ──────────────────────────────────────────

/// OSC 133;A — 프롬프트 시작
const OSC_PROMPT_START: &str = "\x1b]133;A\x07";
/// OSC 133;B — 명령어 시작 (사용자 입력 시작)
const OSC_COMMAND_START: &str = "\x1b]133;B\x07";
/// OSC 133;C — 명령어 출력 시작
const OSC_OUTPUT_START: &str = "\x1b]133;C\x07";
/// OSC 133;C;cmd={hex} — AIC 확장: 실행 명령어 텍스트
const OSC_COMMAND_WITH_TEXT_PREFIX: &str = "\x1b]133;C;cmd=";
/// OSC 133;D — 명령어 완료 (exit code 포함)
/// 실제 형식: \x1b]133;D;{exit_code}\x07
const OSC_COMPLETION_PREFIX: &str = "\x1b]133;D;";
const OSC_COMPLETION_SUFFIX: char = '\x07';
/// 명령 문자열은 4KiB까지만 보존한다.
const MAX_COMMAND_HEX_LEN: usize = 8192;

// ── 전략 enum ──────────────────────────────────────────────────

pub enum BoundaryStrategy {
    /// 셸 precmd/preexec 훅을 통한 OSC 133 마커 감지
    PromptMarker { marker_sequence: String },
    /// 출력 타이밍 기반 휴리스틱 (폴백)
    TimingHeuristic { idle_threshold: Duration },
}

// ── CommandBoundaryDetector ────────────────────────────────────

pub struct CommandBoundaryDetector {
    strategy: BoundaryStrategy,
    current_output: Vec<String>,
    current_command: Option<String>,
    last_exit_code: Option<i32>,
    /// TimingHeuristic 전략에서 마지막 라인 수신 시각
    last_line_time: Option<Instant>,
    /// 출력이 축적된 상태인지 (prompt start 이후 출력이 있었는지)
    has_output: bool,
}

impl CommandBoundaryDetector {
    pub fn new(strategy: BoundaryStrategy) -> Self {
        Self {
            strategy,
            current_output: Vec::new(),
            current_command: None,
            last_exit_code: None,
            last_line_time: None,
            has_output: false,
        }
    }

    /// clean text 라인을 입력받아 Command Boundary 감지 시 CommandRecord를 반환한다.
    pub fn feed_line(&mut self, line: &str) -> Option<CommandRecord> {
        match &self.strategy {
            BoundaryStrategy::PromptMarker { .. } => self.feed_line_prompt_marker(line),
            BoundaryStrategy::TimingHeuristic { idle_threshold } => {
                let threshold = *idle_threshold;
                self.feed_line_timing(line, threshold)
            }
        }
    }

    /// exit code 업데이트 (셸 훅 또는 외부에서 전달)
    pub fn set_exit_code(&mut self, code: i32) {
        self.last_exit_code = Some(code);
    }

    // ── PromptMarker 전략 ──────────────────────────────────────

    fn feed_line_prompt_marker(&mut self, line: &str) -> Option<CommandRecord> {
        // 1) 명령어 완료 마커 (D;exit_code) 감지
        if let Some(exit_code) = parse_completion_marker(line) {
            return self.finalize_record(exit_code);
        }

        // 2) 프롬프트 시작 마커 (A) 감지 — 이전 명령어 출력이 있으면 finalize
        if line.contains(OSC_PROMPT_START) {
            if self.has_output {
                let exit_code = self.last_exit_code.unwrap_or(0);
                return self.finalize_record(exit_code);
            }
            // 출력 없이 프롬프트만 반복되는 경우 — 무시
            return None;
        }

        // 3) 출력 시작(C) 마커는 명령어 텍스트를 포함할 수 있다.
        if let Some(command) = parse_command_marker(line) {
            if let Some(command) = command {
                self.current_command = Some(command);
            }
            return None;
        }

        // 4) 명령어 시작(B) 마커는 상태 전환만
        if line.contains(OSC_COMMAND_START) {
            return None;
        }

        // 5) 일반 출력 라인 축적
        self.current_output.push(line.to_string());
        self.has_output = true;
        None
    }

    // ── TimingHeuristic 전략 ───────────────────────────────────

    fn feed_line_timing(&mut self, line: &str, idle_threshold: Duration) -> Option<CommandRecord> {
        let now = Instant::now();
        let mut result = None;

        // idle_threshold 초과 시 이전 명령어 경계로 판단
        if let Some(last_time) = self.last_line_time {
            if now.duration_since(last_time) >= idle_threshold && self.has_output {
                let exit_code = self.last_exit_code.unwrap_or(0);
                result = self.finalize_record(exit_code);
            }
        }

        // 새 라인 축적
        self.current_output.push(line.to_string());
        self.has_output = true;
        self.last_line_time = Some(now);

        result
    }

    // ── 공통: 레코드 생성 ──────────────────────────────────────

    fn finalize_record(&mut self, exit_code: i32) -> Option<CommandRecord> {
        if self.current_output.is_empty() && (self.current_command.is_none() || exit_code == 0) {
            // 출력이 없으면 레코드를 생성하지 않음
            self.reset_state();
            return None;
        }

        let record = CommandRecord {
            command: self.current_command.take(),
            exit_code,
            output_lines: std::mem::take(&mut self.current_output),
            timestamp: chrono::Utc::now(),
            ..Default::default()
        };

        self.reset_state();
        Some(record)
    }

    fn reset_state(&mut self) {
        self.current_output.clear();
        self.current_command = None;
        self.last_exit_code = None;
        self.has_output = false;
    }
}

// ── OSC 133 파싱 유틸리티 ──────────────────────────────────────

/// `\x1b]133;D;{exit_code}\x07` 형식에서 exit_code를 추출한다.
fn parse_completion_marker(line: &str) -> Option<i32> {
    let start = line.find(OSC_COMPLETION_PREFIX)?;
    let after_prefix = start + OSC_COMPLETION_PREFIX.len();
    let rest = &line[after_prefix..];
    let end = rest.find(OSC_COMPLETION_SUFFIX)?;
    rest[..end].parse::<i32>().ok()
}

/// `\x1b]133;C\x07` 또는 `\x1b]133;C;cmd={hex}\x07` 형식의 command marker를 파싱한다.
///
/// 반환값:
/// - `None`: command marker가 아님
/// - `Some(None)`: command marker지만 명령 텍스트가 없거나 디코딩 불가
/// - `Some(Some(cmd))`: 명령 텍스트 디코딩 성공
fn parse_command_marker(line: &str) -> Option<Option<String>> {
    if let Some(start) = line.find(OSC_COMMAND_WITH_TEXT_PREFIX) {
        let after_prefix = start + OSC_COMMAND_WITH_TEXT_PREFIX.len();
        let rest = &line[after_prefix..];
        let end = rest.find(OSC_COMPLETION_SUFFIX)?;
        return Some(decode_hex_command(&rest[..end]));
    }

    if line.contains(OSC_OUTPUT_START) {
        return Some(None);
    }

    None
}

fn decode_hex_command(hex: &str) -> Option<String> {
    let hex = hex.trim();
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }

    let hex = &hex[..hex.len().min(MAX_COMMAND_HEX_LEN)];
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }

    let command = String::from_utf8(bytes).ok()?;
    let command = command.trim();
    if command.is_empty() {
        None
    } else {
        Some(command.to_string())
    }
}

// ── 셸 훅 주입 유틸리티 ────────────────────────────────────────

/// 지정된 셸에 대한 OSC 133 마커 출력 훅 스크립트를 생성한다.
///
/// zsh: precmd/preexec 함수 정의
/// bash: PROMPT_COMMAND 설정
pub fn generate_shell_hooks(shell: &str) -> String {
    match shell {
        "zsh" => ZSH_HOOKS.to_string(),
        "bash" => BASH_HOOKS.to_string(),
        _ => String::new(),
    }
}

const ZSH_HOOKS: &str = r#"
# AIC OSC 133 shell integration (zsh)
# precmd 훅 목록의 맨 앞에 등록하여 $?가 다른 훅에 의해 덮어쓰이기 전에 캡처
_aic_save_exit_code() {
    _aic_last_exit=$?
}
_aic_hex() {
    printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}
_aic_preexec() {
    local _aic_cmd_hex
    _aic_cmd_hex="$(_aic_hex "$1")"
    printf '\x1b]133;C;cmd=%s\x07' "${_aic_cmd_hex[1,8192]}"
}
_aic_precmd() {
    printf '\x1b]133;D;%d\x07' "$_aic_last_exit"
    printf '\x1b]133;A\x07'
    printf '\x1b]133;B\x07'
}
autoload -Uz add-zsh-hook
# save_exit_code를 맨 먼저 실행하여 $? 보존
add-zsh-hook precmd _aic_save_exit_code
add-zsh-hook precmd _aic_precmd
add-zsh-hook preexec _aic_preexec
"#;

const BASH_HOOKS: &str = r#"
# AIC OSC 133 shell integration (bash)
_aic_hex() {
    printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}
_aic_debug_trap() {
    _aic_last_exit=$?
    case "$BASH_COMMAND" in
        _aic_prompt_command*|_aic_debug_trap*|trap\ *) return ;;
    esac
    local _aic_cmd_hex
    _aic_cmd_hex="$(_aic_hex "$BASH_COMMAND")"
    printf '\x1b]133;C;cmd=%s\x07' "${_aic_cmd_hex:0:8192}"
}
_aic_prompt_command() {
    local exit_code=${_aic_last_exit:-$?}
    printf '\x1b]133;D;%d\x07' "$exit_code"
    printf '\x1b]133;A\x07'
    printf '\x1b]133;B\x07'
}
# trap DEBUG로 명령어 실행 직후 exit code를 즉시 캡처
trap '_aic_debug_trap' DEBUG
PROMPT_COMMAND="_aic_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
"#;

// ── 테스트 ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn make_prompt_marker_detector() -> CommandBoundaryDetector {
        CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
            marker_sequence: "osc133".to_string(),
        })
    }

    // --- OSC 133 completion marker 파싱 ---

    #[test]
    fn parse_completion_marker_extracts_exit_code() {
        assert_eq!(parse_completion_marker("\x1b]133;D;0\x07"), Some(0));
        assert_eq!(parse_completion_marker("\x1b]133;D;1\x07"), Some(1));
        assert_eq!(parse_completion_marker("\x1b]133;D;127\x07"), Some(127));
        assert_eq!(parse_completion_marker("\x1b]133;D;-1\x07"), Some(-1));
    }

    #[test]
    fn parse_completion_marker_returns_none_for_invalid() {
        assert_eq!(parse_completion_marker("no marker here"), None);
        assert_eq!(parse_completion_marker("\x1b]133;D;abc\x07"), None);
        assert_eq!(parse_completion_marker("\x1b]133;D;\x07"), None);
    }

    #[test]
    fn parse_command_marker_extracts_hex_command() {
        let marker = "\x1b]133;C;cmd=636172676f206275696c64\x07";
        assert_eq!(
            parse_command_marker(marker),
            Some(Some("cargo build".to_string()))
        );
    }

    #[test]
    fn parse_command_marker_accepts_legacy_marker() {
        assert_eq!(parse_command_marker("\x1b]133;C\x07"), Some(None));
    }

    #[test]
    fn parse_command_marker_invalid_hex_is_marker_without_command() {
        assert_eq!(parse_command_marker("\x1b]133;C;cmd=zz\x07"), Some(None));
    }

    // --- PromptMarker 전략: 기본 흐름 ---

    #[test]
    fn prompt_marker_basic_flow() {
        let mut det = make_prompt_marker_detector();

        // 출력 라인 축적
        assert!(det.feed_line("line 1").is_none());
        assert!(det.feed_line("line 2").is_none());

        // 완료 마커 → 레코드 생성
        let record = det.feed_line("\x1b]133;D;0\x07").unwrap();
        assert_eq!(record.exit_code, 0);
        assert_eq!(record.output_lines, vec!["line 1", "line 2"]);
        assert_eq!(record.command, None);
    }

    #[test]
    fn prompt_marker_with_nonzero_exit_code() {
        let mut det = make_prompt_marker_detector();

        det.feed_line("\x1b]133;C;cmd=6d616b65\x07");
        det.feed_line("error: file not found");
        let record = det.feed_line("\x1b]133;D;1\x07").unwrap();
        assert_eq!(record.exit_code, 1);
        assert_eq!(record.command.as_deref(), Some("make"));
        assert_eq!(record.output_lines, vec!["error: file not found"]);
    }

    #[test]
    fn prompt_marker_records_command_without_output_when_failed() {
        let mut det = make_prompt_marker_detector();

        det.feed_line("\x1b]133;C;cmd=66616c7365\x07");
        let record = det.feed_line("\x1b]133;D;1\x07").unwrap();

        assert_eq!(record.exit_code, 1);
        assert_eq!(record.command.as_deref(), Some("false"));
        assert!(record.output_lines.is_empty());
    }

    #[test]
    fn prompt_marker_ignores_command_without_output_when_successful() {
        let mut det = make_prompt_marker_detector();

        det.feed_line("\x1b]133;C;cmd=74727565\x07");

        assert!(det.feed_line("\x1b]133;D;0\x07").is_none());
    }

    #[test]
    fn prompt_start_finalizes_previous_command() {
        let mut det = make_prompt_marker_detector();

        det.feed_line("output from cmd1");
        // set_exit_code로 exit code 설정 후 prompt start(A) 마커
        det.set_exit_code(2);
        let record = det.feed_line("\x1b]133;A\x07").unwrap();
        assert_eq!(record.exit_code, 2);
        assert_eq!(record.output_lines, vec!["output from cmd1"]);
    }

    #[test]
    fn prompt_start_without_output_does_not_create_record() {
        let mut det = make_prompt_marker_detector();

        // 출력 없이 프롬프트 시작 → 레코드 없음
        assert!(det.feed_line("\x1b]133;A\x07").is_none());
    }

    #[test]
    fn command_start_and_output_start_markers_are_ignored() {
        let mut det = make_prompt_marker_detector();

        assert!(det.feed_line("\x1b]133;B\x07").is_none());
        assert!(det.feed_line("\x1b]133;C\x07").is_none());
    }

    #[test]
    fn multiple_commands_produce_separate_records() {
        let mut det = make_prompt_marker_detector();

        // 첫 번째 명령어
        det.feed_line("output A");
        let r1 = det.feed_line("\x1b]133;D;0\x07").unwrap();
        assert_eq!(r1.output_lines, vec!["output A"]);

        // 두 번째 명령어
        det.feed_line("output B1");
        det.feed_line("output B2");
        let r2 = det.feed_line("\x1b]133;D;42\x07").unwrap();
        assert_eq!(r2.exit_code, 42);
        assert_eq!(r2.output_lines, vec!["output B1", "output B2"]);
    }

    // --- set_exit_code ---

    #[test]
    fn set_exit_code_updates_state() {
        let mut det = make_prompt_marker_detector();
        det.set_exit_code(5);
        assert_eq!(det.last_exit_code, Some(5));
    }

    // --- TimingHeuristic 전략 ---

    #[test]
    fn timing_heuristic_no_boundary_within_threshold() {
        let mut det = CommandBoundaryDetector::new(BoundaryStrategy::TimingHeuristic {
            idle_threshold: Duration::from_secs(10), // 매우 긴 threshold
        });

        // 빠르게 연속 입력 → 경계 감지 안 됨
        assert!(det.feed_line("line 1").is_none());
        assert!(det.feed_line("line 2").is_none());
        assert!(det.feed_line("line 3").is_none());
    }

    #[test]
    fn timing_heuristic_boundary_after_threshold() {
        let mut det = CommandBoundaryDetector::new(BoundaryStrategy::TimingHeuristic {
            idle_threshold: Duration::from_millis(0), // 즉시 경계 감지
        });

        det.feed_line("first command output");
        // last_line_time이 설정된 상태에서 다음 feed_line 호출 시
        // duration >= 0ms 이므로 경계 감지
        det.set_exit_code(1);

        // 약간의 시간 경과 보장 (0ms threshold이므로 거의 항상 통과)
        std::thread::sleep(Duration::from_millis(1));

        let record = det.feed_line("second command output").unwrap();
        assert_eq!(record.exit_code, 1);
        assert_eq!(record.output_lines, vec!["first command output"]);

        // 두 번째 명령어의 출력은 새 축적 시작
        assert_eq!(det.current_output, vec!["second command output"]);
    }

    // --- TimingHeuristic: 추가 edge cases ---

    #[test]
    fn timing_heuristic_multiple_boundaries_in_sequence() {
        let mut det = CommandBoundaryDetector::new(BoundaryStrategy::TimingHeuristic {
            idle_threshold: Duration::from_millis(0),
        });

        // 첫 번째 명령어 출력
        det.feed_line("cmd1 output");
        std::thread::sleep(Duration::from_millis(1));

        // 두 번째 명령어 출력 → 첫 번째 경계 감지
        det.set_exit_code(0);
        let r1 = det.feed_line("cmd2 output").unwrap();
        assert_eq!(r1.exit_code, 0);
        assert_eq!(r1.output_lines, vec!["cmd1 output"]);

        std::thread::sleep(Duration::from_millis(1));

        // 세 번째 명령어 출력 → 두 번째 경계 감지
        det.set_exit_code(42);
        let r2 = det.feed_line("cmd3 output").unwrap();
        assert_eq!(r2.exit_code, 42);
        assert_eq!(r2.output_lines, vec!["cmd2 output"]);
    }

    #[test]
    fn timing_heuristic_exit_code_defaults_to_zero() {
        let mut det = CommandBoundaryDetector::new(BoundaryStrategy::TimingHeuristic {
            idle_threshold: Duration::from_millis(0),
        });

        det.feed_line("some output");
        std::thread::sleep(Duration::from_millis(1));

        // set_exit_code 호출 없이 경계 감지 → 기본값 0
        let record = det.feed_line("next output").unwrap();
        assert_eq!(record.exit_code, 0);
        assert_eq!(record.output_lines, vec!["some output"]);
    }

    // --- Completion marker: embedded in longer line ---

    #[test]
    fn completion_marker_embedded_in_longer_line() {
        let mut det = make_prompt_marker_detector();

        det.feed_line("output line");
        // 마커가 다른 텍스트에 둘러싸인 경우에도 감지
        let record = det.feed_line("prefix\x1b]133;D;3\x07suffix").unwrap();
        assert_eq!(record.exit_code, 3);
        assert_eq!(record.output_lines, vec!["output line"]);
    }

    // --- 셸 훅 생성 ---

    #[test]
    fn generate_zsh_hooks_contains_osc_markers() {
        let hooks = generate_shell_hooks("zsh");
        assert!(hooks.contains("precmd"));
        assert!(hooks.contains("preexec"));
        assert!(hooks.contains("133;D"));
        assert!(hooks.contains("133;C;cmd="));
        assert!(hooks.contains("133;A"));
    }

    #[test]
    fn generate_bash_hooks_contains_prompt_command() {
        let hooks = generate_shell_hooks("bash");
        assert!(hooks.contains("PROMPT_COMMAND"));
        assert!(hooks.contains("133;D"));
        assert!(hooks.contains("133;C;cmd="));
        assert!(hooks.contains("133;A"));
    }

    #[test]
    fn generate_hooks_unknown_shell_returns_empty() {
        assert!(generate_shell_hooks("fish").is_empty());
        assert!(generate_shell_hooks("").is_empty());
    }

    // --- Property-Based Tests ---

    /// 출력 라인에 OSC 133 마커 문자가 포함되지 않는 안전한 텍스트 전략
    fn safe_output_line() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 _.:/@#\\-]{1,80}".prop_filter("no BEL char", |s| {
            !s.contains('\x07') && !s.contains('\x1b')
        })
    }

    // Feature: ac-cli-tool, Property 4: Command Boundary Detection Produces Correct Records
    // **Validates: Requirements 4.1, 4.2**
    proptest! {
        #[test]
        fn command_boundary_detection_produces_correct_records(
            // N개의 명령어 블록 생성 (1..=5)
            blocks in prop::collection::vec(
                (
                    // 각 블록: 1..=5개의 출력 라인
                    prop::collection::vec(safe_output_line(), 1..=5),
                    // 각 블록의 exit code (0..=255)
                    0i32..=255,
                ),
                1..=5,
            )
        ) {
            let mut det = make_prompt_marker_detector();
            let mut records: Vec<CommandRecord> = Vec::new();

            for (lines, exit_code) in &blocks {
                // 출력 라인 feed
                for line in lines {
                    let result = det.feed_line(line);
                    prop_assert!(result.is_none(), "출력 라인에서 레코드가 생성되면 안 됨");
                }

                // completion marker feed → 레코드 생성
                let marker = format!("\x1b]133;D;{}\x07", exit_code);
                let record = det.feed_line(&marker);
                prop_assert!(record.is_some(), "completion marker 후 레코드가 생성되어야 함");
                records.push(record.unwrap());
            }

            // 검증 1: 정확히 N개의 CommandRecord 생성
            prop_assert_eq!(records.len(), blocks.len());

            // 검증 2 & 3: 각 레코드의 output_lines와 exit_code가 해당 블록과 일치
            for (record, (expected_lines, expected_exit_code)) in records.iter().zip(blocks.iter()) {
                prop_assert_eq!(&record.output_lines, expected_lines);
                prop_assert_eq!(record.exit_code, *expected_exit_code);
            }
        }
    }
}
