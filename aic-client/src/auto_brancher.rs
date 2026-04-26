//! Exit Code 기반 자동 분기 모듈.
//!
//! `CommandRecord`의 `exit_code`를 기반으로 에러 분석 모드 또는
//! Interactive REPL 모드로 분기한다.

use aic_common::CommandRecord;

/// 실행 모드. Exit Code에 따라 결정된다.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionMode {
    /// exit_code != 0: LLM 에러 분석 모드
    ErrorAnalysis(CommandRecord),
    /// exit_code == 0: Interactive REPL 모드
    InteractiveRepl(CommandRecord),
}

pub struct AutoBrancher;

impl AutoBrancher {
    /// `CommandRecord`의 `exit_code`를 기반으로 실행 모드를 결정한다.
    ///
    /// - `exit_code != 0` → `ExecutionMode::ErrorAnalysis`
    /// - `exit_code == 0` → `ExecutionMode::InteractiveRepl`
    pub fn determine_mode(record: &CommandRecord) -> ExecutionMode {
        if record.exit_code != 0 {
            ExecutionMode::ErrorAnalysis(record.clone())
        } else {
            ExecutionMode::InteractiveRepl(record.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_record(exit_code: i32) -> CommandRecord {
        CommandRecord {
            command: Some("test-cmd".to_string()),
            exit_code,
            output_lines: vec!["output".to_string()],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn nonzero_exit_code_returns_error_analysis() {
        let record = make_record(1);
        let mode = AutoBrancher::determine_mode(&record);
        assert!(matches!(mode, ExecutionMode::ErrorAnalysis(_)));
    }

    #[test]
    fn zero_exit_code_returns_interactive_repl() {
        let record = make_record(0);
        let mode = AutoBrancher::determine_mode(&record);
        assert!(matches!(mode, ExecutionMode::InteractiveRepl(_)));
    }

    #[test]
    fn negative_exit_code_returns_error_analysis() {
        let record = make_record(-1);
        let mode = AutoBrancher::determine_mode(&record);
        assert!(matches!(mode, ExecutionMode::ErrorAnalysis(_)));
    }

    #[test]
    fn preserves_record_in_error_analysis() {
        let record = make_record(127);
        if let ExecutionMode::ErrorAnalysis(r) = AutoBrancher::determine_mode(&record) {
            assert_eq!(r.exit_code, 127);
            assert_eq!(r.command, Some("test-cmd".to_string()));
        } else {
            panic!("ErrorAnalysis를 기대했습니다");
        }
    }

    #[test]
    fn preserves_record_in_interactive_repl() {
        let record = make_record(0);
        if let ExecutionMode::InteractiveRepl(r) = AutoBrancher::determine_mode(&record) {
            assert_eq!(r.exit_code, 0);
            assert_eq!(r.command, Some("test-cmd".to_string()));
        } else {
            panic!("InteractiveRepl을 기대했습니다");
        }
    }

    // ── Property-Based Tests ───────────────────────────────────
    // Feature: ac-cli-tool, Property 5: Exit Code Determines Execution Mode
    // **Validates: Requirements 5.2, 5.3**

    use proptest::prelude::*;

    fn arb_command_record() -> impl Strategy<Value = CommandRecord> {
        (
            proptest::option::of(any::<String>()),
            any::<i32>(),
            proptest::collection::vec(any::<String>(), 0..8),
            0i64..4_102_444_800_000i64,
        )
            .prop_map(|(command, exit_code, output_lines, ts_millis)| {
                let timestamp =
                    chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default();
                CommandRecord {
                    command,
                    exit_code,
                    output_lines,
                    timestamp,
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_exit_code_determines_execution_mode(record in arb_command_record()) {
            let mode = AutoBrancher::determine_mode(&record);
            if record.exit_code != 0 {
                prop_assert!(
                    matches!(mode, ExecutionMode::ErrorAnalysis(ref r) if r.exit_code == record.exit_code),
                    "exit_code != 0 ({}) 이면 ErrorAnalysis여야 합니다", record.exit_code
                );
            } else {
                prop_assert!(
                    matches!(mode, ExecutionMode::InteractiveRepl(ref r) if r.exit_code == 0),
                    "exit_code == 0 이면 InteractiveRepl이어야 합니다"
                );
            }
        }
    }
}
