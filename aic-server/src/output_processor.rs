//! PTY 출력 스트림에서 ANSI Escape Sequence를 제거하고,
//! Alternate Screen Buffer 상태를 추적한다.
//!
//! Requirements: 2.1, 10.2, 10.3, 10.4

/// ANSI 제거된 텍스트와 원본 passthrough 바이트를 함께 반환하는 구조체.
pub struct ProcessedOutput {
    /// ANSI 제거된 순수 텍스트 (Alternate Screen 중에는 None)
    pub clean_text: Option<String>,
    /// 사용자 터미널로 전달할 원본 바이트 (항상 존재)
    pub passthrough: Vec<u8>,
    /// OSC 133 마커들 (boundary detection용, ANSI strip 전에 추출)
    pub osc133_markers: Vec<String>,
}

pub struct OutputProcessor {
    in_alternate_screen: bool,
}

/// Alternate Screen Buffer 진입 시퀀스 (ESC = 0x1B)
const ALT_SCREEN_ENTER: &[&[u8]] = &[b"\x1b[?1049h", b"\x1b[?47h", b"\x1b[?1047h"];

/// Alternate Screen Buffer 복귀 시퀀스
const ALT_SCREEN_EXIT: &[&[u8]] = &[b"\x1b[?1049l", b"\x1b[?47l", b"\x1b[?1047l"];

fn contains_sequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// raw bytes에서 OSC 133 마커를 추출한다.
/// 형식: \x1b]133;X\x07 또는 \x1b]133;X;...\x07
fn extract_osc133_markers(raw: &[u8]) -> Vec<String> {
    let mut markers = Vec::new();
    let osc_start = b"\x1b]133;";
    let mut i = 0;

    while i < raw.len() {
        // OSC 133 시작 위치 찾기
        if let Some(pos) = raw[i..]
            .windows(osc_start.len())
            .position(|w| w == osc_start)
        {
            let start = i + pos;
            // BEL(0x07) 또는 ST(\x1b\\) 종료 찾기
            if let Some(end_offset) = raw[start..].iter().position(|&b| b == 0x07) {
                let end = start + end_offset + 1;
                if let Ok(marker) = std::str::from_utf8(&raw[start..end]) {
                    markers.push(marker.to_string());
                }
                i = end;
            } else {
                i = start + 1;
            }
        } else {
            break;
        }
    }

    markers
}

impl Default for OutputProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputProcessor {
    pub fn new() -> Self {
        Self {
            in_alternate_screen: false,
        }
    }

    /// raw bytes를 처리하여 ProcessedOutput을 반환한다.
    ///
    /// 1. passthrough는 항상 원본 raw bytes
    /// 2. OSC 133 마커를 먼저 추출 (boundary detection용)
    /// 3. Alternate Screen 진입/복귀 시퀀스를 스캔하여 상태 전환
    /// 4. Alternate Screen 활성 시 clean_text = None
    /// 5. Normal Screen 시 ANSI 제거 후 clean_text = Some(stripped)
    pub fn process(&mut self, raw: &[u8]) -> ProcessedOutput {
        // OSC 133 마커 추출 (ANSI strip 전에)
        let osc133_markers = extract_osc133_markers(raw);

        // 진입/복귀 시퀀스 감지 (ANSI strip 전에 raw bytes에서 스캔)
        for seq in ALT_SCREEN_ENTER {
            if contains_sequence(raw, seq) {
                self.in_alternate_screen = true;
            }
        }
        for seq in ALT_SCREEN_EXIT {
            if contains_sequence(raw, seq) {
                self.in_alternate_screen = false;
            }
        }

        let clean_text = if self.in_alternate_screen {
            None
        } else {
            let stripped_bytes = strip_ansi_escapes::strip(raw);
            Some(String::from_utf8_lossy(&stripped_bytes).into_owned())
        };

        ProcessedOutput {
            clean_text,
            passthrough: raw.to_vec(),
            osc133_markers,
        }
    }

    /// 현재 Alternate Screen Buffer 활성 여부
    pub fn is_alternate_screen(&self) -> bool {
        self.in_alternate_screen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// ANSI escape sequence를 생성하는 전략.
    /// 일반적인 SGR(색상/스타일), 커서 이동, 화면 지우기 등을 포함한다.
    fn ansi_sequence_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // SGR: 색상, bold, reset 등
            (0u8..=107).prop_map(|n| format!("\x1b[{}m", n)),
            // 복합 SGR: e.g. \x1b[1;32m
            (0u8..=9, 30u8..=37).prop_map(|(a, b)| format!("\x1b[{};{}m", a, b)),
            // 커서 이동
            (1u16..=100).prop_map(|n| format!("\x1b[{}A", n)),
            (1u16..=100).prop_map(|n| format!("\x1b[{}B", n)),
            (1u16..=100).prop_map(|n| format!("\x1b[{}C", n)),
            (1u16..=100).prop_map(|n| format!("\x1b[{}D", n)),
            // 화면/라인 지우기
            Just("\x1b[K".to_string()),
            Just("\x1b[2J".to_string()),
            Just("\x1b[0m".to_string()),
            Just("\x1b[1m".to_string()),
        ]
    }

    /// ESC(0x1B)를 포함하지 않는 printable ASCII 텍스트 전략.
    fn pure_text_strategy() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            // printable ASCII 중 ESC(0x1B) 제외: 0x20..=0x7E
            (0x20u8..=0x7Eu8).prop_map(|b| b as char),
            0..=80,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>())
    }

    /// 순수 텍스트 세그먼트와 ANSI 시퀀스를 interleave하여 조합하는 전략.
    /// (결합된 바이트열, 순수 텍스트 세그먼트 목록)을 반환한다.
    fn text_with_ansi_strategy() -> impl Strategy<Value = (Vec<u8>, Vec<String>)> {
        proptest::collection::vec(
            (
                pure_text_strategy(),
                proptest::option::of(ansi_sequence_strategy()),
            ),
            1..=8,
        )
        .prop_map(|segments| {
            let mut combined = Vec::new();
            let mut text_parts = Vec::new();
            for (text, maybe_ansi) in segments {
                if let Some(ansi) = maybe_ansi {
                    combined.extend_from_slice(ansi.as_bytes());
                }
                combined.extend_from_slice(text.as_bytes());
                text_parts.push(text);
            }
            (combined, text_parts)
        })
    }

    /// Alternate Screen 진입/복귀 시퀀스 쌍을 선택하는 전략.
    /// (enter_sequence, exit_sequence) 튜플을 반환한다.
    fn alt_screen_pair_strategy() -> impl Strategy<Value = (&'static [u8], &'static [u8])> {
        prop_oneof![
            Just((&b"\x1b[?1049h"[..], &b"\x1b[?1049l"[..])),
            Just((&b"\x1b[?47h"[..], &b"\x1b[?47l"[..])),
            Just((&b"\x1b[?1047h"[..], &b"\x1b[?1047l"[..])),
        ]
    }

    // Feature: ac-cli-tool, Property 1: ANSI Stripping Preserves Text Content
    proptest! {
        /// **Validates: Requirements 2.1**
        ///
        /// 임의의 순수 텍스트 + ANSI 시퀀스 조합에 대해:
        /// (1) 결과의 clean_text에 ANSI escape sequence가 포함되지 않음
        /// (2) 원본 순수 텍스트 콘텐츠가 clean_text에 보존됨
        #[test]
        fn ansi_stripping_preserves_text_content(
            (raw, text_parts) in text_with_ansi_strategy()
        ) {
            let mut processor = OutputProcessor::new();
            let output = processor.process(&raw);

            let clean = output.clean_text
                .expect("normal screen mode에서 clean_text는 Some이어야 함");

            // (1) clean_text에 ESC 바이트(0x1B)가 없어야 한다
            prop_assert!(
                !clean.contains('\x1b'),
                "clean_text에 ESC(0x1B)가 포함됨: {:?}", clean
            );

            // (2) 모든 순수 텍스트 세그먼트가 clean_text에 보존되어야 한다
            for part in &text_parts {
                prop_assert!(
                    clean.contains(part.as_str()),
                    "순수 텍스트 '{}'가 clean_text에서 누락됨. clean_text: {:?}",
                    part, clean
                );
            }
        }
    }

    // Feature: ac-cli-tool, Property 8: Alternate Screen Buffer Detection and Round-Trip
    proptest! {
        /// **Validates: Requirements 10.2, 10.3, 10.4**
        ///
        /// 임의의 Alternate Screen 진입/복귀 시퀀스 쌍과 텍스트에 대해:
        /// (1) 진입 시퀀스 처리 후 is_alternate_screen() == true, clean_text == None
        /// (2) 복귀 시퀀스 처리 후 is_alternate_screen() == false, clean_text == Some(...)
        #[test]
        fn alternate_screen_detection_and_round_trip(
            (enter_seq, exit_seq) in alt_screen_pair_strategy(),
            prefix in pure_text_strategy(),
            suffix in pure_text_strategy(),
        ) {
            let mut processor = OutputProcessor::new();

            // 초기 상태: normal mode
            prop_assert!(!processor.is_alternate_screen(), "초기 상태는 normal mode여야 함");

            // 진입 시퀀스가 포함된 청크 처리
            let mut enter_chunk = Vec::new();
            enter_chunk.extend_from_slice(prefix.as_bytes());
            enter_chunk.extend_from_slice(enter_seq);
            enter_chunk.extend_from_slice(suffix.as_bytes());

            let enter_output = processor.process(&enter_chunk);

            prop_assert!(
                processor.is_alternate_screen(),
                "진입 시퀀스 처리 후 alternate screen 상태여야 함"
            );
            prop_assert!(
                enter_output.clean_text.is_none(),
                "alternate screen 중 clean_text는 None이어야 함, got: {:?}",
                enter_output.clean_text
            );

            // 복귀 시퀀스가 포함된 청크 처리
            let mut exit_chunk = Vec::new();
            exit_chunk.extend_from_slice(prefix.as_bytes());
            exit_chunk.extend_from_slice(exit_seq);
            exit_chunk.extend_from_slice(suffix.as_bytes());

            let exit_output = processor.process(&exit_chunk);

            prop_assert!(
                !processor.is_alternate_screen(),
                "복귀 시퀀스 처리 후 normal mode로 돌아와야 함"
            );
            prop_assert!(
                exit_output.clean_text.is_some(),
                "normal mode 복귀 후 clean_text는 Some이어야 함"
            );
        }
    }

    // --- Unit tests: OutputProcessor edge cases (Task 5.4) ---
    // **Validates: Requirements 2.1**

    #[test]
    fn empty_input_returns_empty_clean_text() {
        let mut processor = OutputProcessor::new();
        let output = processor.process(b"");

        assert_eq!(output.clean_text, Some("".to_string()));
        assert!(output.passthrough.is_empty());
    }

    #[test]
    fn ansi_only_input_returns_empty_clean_text() {
        let mut processor = OutputProcessor::new();
        let output = processor.process(b"\x1b[31m\x1b[0m");

        // ANSI 시퀀스만 있으므로 strip 후 visible text 없음
        assert_eq!(output.clean_text, Some("".to_string()));
    }

    #[test]
    fn broken_ansi_sequence_does_not_crash() {
        let mut processor = OutputProcessor::new();
        // 불완전한 ANSI 시퀀스: ESC[ 만 있고 종결 문자 없음
        let output = processor.process(b"\x1b[");

        // crash 없이 처리되어야 하며, clean_text는 Some
        assert!(output.clean_text.is_some());
        // clean_text에 ESC(0x1B)가 남아있지 않아야 함 (strip 라이브러리가 제거)
        let clean = output.clean_text.unwrap();
        assert!(!clean.contains('\x1b'));
    }

    #[test]
    fn osc133_command_marker_is_extracted_before_stripping() {
        let mut processor = OutputProcessor::new();
        let raw = b"\x1b]133;C;cmd=6d616b65\x07";
        let output = processor.process(raw);

        assert_eq!(
            output.osc133_markers,
            vec!["\x1b]133;C;cmd=6d616b65\x07".to_string()]
        );
        assert_eq!(output.passthrough, raw.to_vec());
    }

    #[test]
    fn passthrough_always_contains_raw_bytes() {
        let mut processor = OutputProcessor::new();

        // Normal mode: passthrough == raw bytes
        let raw_normal = b"hello \x1b[31mworld\x1b[0m";
        let output_normal = processor.process(raw_normal);
        assert_eq!(output_normal.passthrough, raw_normal.to_vec());

        // Alternate screen mode: passthrough도 여전히 raw bytes
        let raw_alt = b"\x1b[?1049hsome TUI output";
        let output_alt = processor.process(raw_alt);
        assert_eq!(output_alt.passthrough, raw_alt.to_vec());
        assert!(output_alt.clean_text.is_none()); // alternate screen이므로 None
    }
}
