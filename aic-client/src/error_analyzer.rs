//! 에러 분석 모듈.
//!
//! `CommandRecord`의 에러 컨텍스트를 LLM 프롬프트로 구성하고,
//! LLM 응답을 `AnalysisResult`로 파싱한다.

use aic_common::{AnalysisResult, CommandRecord};

pub struct ErrorAnalyzer;

/// 출력에서 보존할 최대 라인 수.
const MAX_OUTPUT_LINES: usize = 50;

/// 진단 깊이를 안내하는 few-shot 예시.
/// 도메인을 의도적으로 다양화: (1) Makefile 빌드 실패(파싱 레이어) (2) 히스토리 폴백 hypothesis form.
const FEWSHOT: &str = "\n# Examples (style only — do not copy literally)\n\
                       \n\
                       Example A — output available:\n\
                       Input: COMMAND `make`, EXIT_CODE 2, OUTPUT contains \"Makefile:3: *** missing separator. Stop.\"\n\
                       EXPLANATION: Makefile 3행의 명령 라인이 탭이 아닌 스페이스로 시작해서 *** missing separator가 발생했습니다.\n\
                       COMMAND: sed -i '' $'s/^    /\\t/' Makefile\n\
                       INFO: cat -A Makefile | head 으로 ^I(탭) 대신 스페이스로 시작한 라인을 확인하세요.\n\
                       \n\
                       Example B — history fallback (no output):\n\
                       Input: COMMAND `chmod 755 deploy.sh`, EXIT_CODE UNKNOWN, OUTPUT none.\n\
                       EXPLANATION: 출력이 없어 단정할 수 없으나, 권한 변경 실패의 가장 흔한 원인은 deploy.sh가 현재 디렉토리에 없거나 소유자가 다른 사용자일 가능성이 큽니다.\n\
                       COMMAND:\n\
                       INFO: ls -l deploy.sh 로 파일 존재 여부와 소유자를 먼저 확인하세요.\n";

/// 출력 라인에서 분석에 무의미한 노이즈를 제거한다.
///
/// 다음을 노이즈로 간주하여 제거한다:
/// - 빈 라인 (trim 후)
/// - 셸 프롬프트만 있는 라인 (`%`, `$`, `>`, `#`)
/// - 길이 ≤ 2자인 짧은 라인 (오타 입력 후 백스페이스 흔적 등)
/// - `command`가 주어진 경우, 그 명령어가 그대로 에코된 라인
///
/// 모든 라인이 노이즈로 판정되어 결과가 비면 원본을 유지(trim_end만 적용)해서
/// 정보 손실을 방지한다.
pub fn clean_output_lines(lines: &[String], command: Option<&str>) -> Vec<String> {
    let cmd_trim = command.map(str::trim).filter(|s| !s.is_empty());

    let cleaned: Vec<String> = lines
        .iter()
        .map(|s| s.trim_end().to_string())
        .filter(|s| {
            let t = s.trim();
            if t.is_empty() {
                return false;
            }
            if matches!(t, "%" | "$" | ">" | "#") {
                return false;
            }
            if t.chars().count() <= 2 {
                return false;
            }
            if let Some(c) = cmd_trim {
                if t == c {
                    return false;
                }
            }
            true
        })
        .collect();

    if cleaned.is_empty() {
        // 모두 노이즈라면 정보 손실을 막기 위해 원본 lines 사용 (trim만 적용)
        lines.iter().map(|s| s.trim_end().to_string()).collect()
    } else {
        cleaned
    }
}

impl ErrorAnalyzer {
    /// LLM을 호출하지 않아도 확정적으로 처리할 수 있는 케이스.
    ///
    /// exit 130은 POSIX 셸에서 SIGINT/Ctrl-C로 중단된 경우가 대부분이다.
    /// 이 상황에서 LLM에 맡기면 출력에 섞인 이전 AIC 분석문을 실제 실패 원인으로
    /// 오해해 임의의 재실행 명령을 제안할 수 있으므로 로컬에서 막는다.
    pub fn deterministic_result(record: &CommandRecord, lang: &str) -> Option<AnalysisResult> {
        if record.exit_code != 130 {
            return deterministic_known_error(record, lang);
        }

        let command_known = record
            .command
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        let aic_transcript = output_looks_like_aic_transcript(&record.output_lines);

        let explanation = match lang {
            "english" => {
                if aic_transcript {
                    "The captured failure is AIC or its prompt being interrupted by SIGINT, not the original command's error.".to_string()
                } else if command_known {
                    "The command exited with 130, which means it was interrupted by SIGINT/Ctrl-C rather than failing with a diagnostic error.".to_string()
                } else {
                    "The captured process exited with 130, so the reliable signal is SIGINT/Ctrl-C interruption, not a concrete command failure.".to_string()
                }
            }
            "japanese" => {
                if aic_transcript {
                    "取得された失敗は元のコマンドではなく、AICまたは確認プロンプトがSIGINTで中断されたものです。".to_string()
                } else if command_known {
                    "終了コード130はSIGINT/Ctrl-Cによる中断を示し、診断可能なエラー終了ではありません。".to_string()
                } else {
                    "取得できた確実な情報は終了コード130、つまりSIGINT/Ctrl-Cによる中断だけです。"
                        .to_string()
                }
            }
            "chinese" => {
                if aic_transcript {
                    "捕获到的是 AIC 或确认提示被 SIGINT 中断，不是原始命令的错误。".to_string()
                } else if command_known {
                    "退出码 130 表示命令被 SIGINT/Ctrl-C 中断，而不是带有诊断信息的失败。"
                        .to_string()
                } else {
                    "可靠信号只有退出码 130，即 SIGINT/Ctrl-C 中断，不能据此判断具体命令故障。"
                        .to_string()
                }
            }
            _ => {
                if aic_transcript {
                    "캡처된 실패는 원래 명령의 에러가 아니라 AIC 또는 실행 확인 프롬프트가 SIGINT/Ctrl-C로 중단된 상황입니다.".to_string()
                } else if command_known {
                    "종료 코드 130은 명령이 진단 가능한 에러로 실패한 것이 아니라 SIGINT/Ctrl-C로 중단됐다는 뜻입니다.".to_string()
                } else {
                    "신뢰할 수 있는 신호는 종료 코드 130, 즉 SIGINT/Ctrl-C 중단뿐이라 구체적인 명령 실패로 단정할 수 없습니다.".to_string()
                }
            }
        };

        let additional_info = match lang {
            "english" => {
                if aic_transcript || !command_known {
                    "Run the intended command again and invoke aic after it fails normally."
                        .to_string()
                } else {
                    "If this was accidental, rerun the same command without interrupting it."
                        .to_string()
                }
            }
            "japanese" => {
                if aic_transcript || !command_known {
                    "対象コマンドを再実行し、通常の失敗ログが出てからaicを起動してください。"
                        .to_string()
                } else {
                    "意図しない中断なら、同じコマンドを中断せずに再実行してください。".to_string()
                }
            }
            "chinese" => {
                if aic_transcript || !command_known {
                    "重新运行目标命令，等它正常失败并输出日志后再运行 aic。".to_string()
                } else {
                    "如果是误中断，请不要按 Ctrl-C，重新运行同一命令。".to_string()
                }
            }
            _ => {
                if aic_transcript || !command_known {
                    "분석하려던 원래 명령을 다시 실행하고, 정상 실패 로그가 나온 뒤 aic를 실행하세요.".to_string()
                } else {
                    "실수로 중단했다면 같은 명령을 Ctrl-C 없이 다시 실행하세요.".to_string()
                }
            }
        };

        Some(AnalysisResult {
            explanation,
            suggested_command: None,
            additional_info: Some(additional_info),
        })
    }

    /// `CommandRecord`에서 에러 분석용 LLM 프롬프트를 생성한다.
    ///
    /// 프롬프트는 영어 라벨(`EXPLANATION:`/`COMMAND:`/`INFO:`)을 강제하고,
    /// 본문 언어는 `lang`에 맞춘다. 동어반복·일반론·placeholder 응답을 금지한다.
    pub fn build_prompt(record: &CommandRecord, lang: &str) -> String {
        let command_text = record.command.as_deref().unwrap_or("(unknown command)");

        // 노이즈(빈 줄, 셸 프롬프트, 짧은 garbage, 명령어 에코) 제거 후 LLM에 전달
        let cleaned = clean_output_lines(&record.output_lines, record.command.as_deref());

        // exit_code=-1은 히스토리 폴백 (실제 exit code 불명)
        let exit_info = if record.exit_code == -1 {
            "UNKNOWN (retrieved from shell history — actual exit code not available)".to_string()
        } else {
            record.exit_code.to_string()
        };

        // 출력이 히스토리 폴백 placeholder인지 확인
        let is_history_fallback = record.output_lines.len() == 1
            && record.output_lines[0].contains("히스토리에서 가져옴");

        let output_section = if is_history_fallback {
            "(no terminal output captured — command retrieved from shell history only)".to_string()
        } else if cleaned.is_empty() {
            "(no output)".to_string()
        } else if cleaned.len() > MAX_OUTPUT_LINES {
            let skip = cleaned.len() - MAX_OUTPUT_LINES;
            let tail = cleaned[skip..].join("\n");
            format!("... ({skip} earlier lines truncated)\n{tail}")
        } else {
            cleaned.join("\n")
        };

        let lang_name = match lang {
            "english" => "English",
            "japanese" => "Japanese",
            "chinese" => "Chinese",
            "korean" => "Korean",
            other => other,
        };

        // 명령어 자체를 캡처하지 못한 케이스 (cmd=∅) — OUTPUT은 있지만 COMMAND가 unknown.
        // history fallback과 다르고, LLM이 cmd 이름을 환각으로 만들어내는 것을 막아야 한다.
        let cmd_unknown = record
            .command
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty();

        let history_note = if record.exit_code == -1 || is_history_fallback {
            "\n# Important context\n\
             OUTPUT and EXIT_CODE are unavailable (retrieved from shell history). \
             EXPLANATION must be in HYPOTHESIS form: \"Likely X because the command shape Y typically fails when Z.\" \
             Do NOT state facts you cannot verify. Do NOT invent error tokens.\n"
        } else if cmd_unknown {
            "\n# Important context\n\
             COMMAND is unknown — only EXIT_CODE and OUTPUT are reliable. \
             Do NOT invent or guess the command name (no \"`make` 가...\", no \"`git` 명령이...\"). \
             Reason from OUTPUT and EXIT_CODE alone. \
             EXPLANATION must be in HYPOTHESIS form starting with phrases like \
             \"Likely the failing process...\" or \"OUTPUT 으로부터 추정컨대...\".\n"
        } else {
            ""
        };

        let interrupt_note = if record.exit_code == 130 {
            "\n# Important context\n\
             EXIT_CODE 130 means the observed process was interrupted by SIGINT/Ctrl-C. \
             Do NOT propose rerunning or fixing a guessed command unless OUTPUT also contains a separate, concrete error token. \
             If COMMAND is unknown, COMMAND must be empty and INFO should explain how to recapture the intended command.\n"
        } else {
            ""
        };

        let transcript_note = if output_looks_like_aic_transcript(&record.output_lines) {
            "\n# Important context\n\
             OUTPUT appears to include AIC's own UI/debug output or a previous assistant analysis. \
             Treat those lines as wrapper transcript, not as the original program failure. \
             Do NOT copy commands from labels such as \"Try this\", \"다음 시도\", \"Run\", or \"실행\". \
             If COMMAND is unknown, COMMAND must be empty.\n"
        } else {
            ""
        };

        format!(
            "You diagnose POSIX shell command failures. You read exit codes and stderr the way a kernel \
             engineer reads dmesg: every token is a clue. You never recommend an action without naming the \
             signal that justifies it.\n\
             {FEWSHOT}\
             \n\
             # Failed command\n\
             COMMAND: {command_text}\n\
             EXIT_CODE: {exit_info}\n\
             OUTPUT:\n\
             {output_section}\n\
             {history_note}\
             {interrupt_note}\
             {transcript_note}\
             \n\
             # Internal reasoning (DO NOT print)\n\
             Before writing EXPLANATION, silently identify:\n\
             1. Which layer failed — shell parsing / binary lookup / runtime / network / permission / state.\n\
             2. Which concrete token in OUTPUT proves it (filename, error code, syscall, line number).\n\
             3. What the next action lets the user observe.\n\
             Then verify: does EXPLANATION cite that token? If not, rewrite before emitting.\n\
             \n\
             # Required output format\n\
             Emit EXACTLY three lines, in this order, with these EXACT English labels:\n\
             \n\
             EXPLANATION: <≤35 words; name the MECHANISM, not the symptom. \
             Bad: \"Makefile에 문제가 있습니다.\" \
             Good: \"`make`가 'target: prereq' 라인에서 탭 대신 스페이스를 받아 *** missing separator 를 던졌습니다.\">\n\
             COMMAND: <one runnable shell command, single line, no quotes around it. \
             Empty after the colon ONLY if no concrete fix is possible — and then INFO MUST give a diagnostic command.>\n\
             INFO: <≤25 words; non-redundant supplement OR diagnostic command when COMMAND is empty. \
             Diagnostic example: \"cat -A Makefile | head\", \"echo $PATH\", \"ls -l <file>\". Empty INFO is forbidden when COMMAND is empty.>\n\
             \n\
             # Rules\n\
             - Labels EXPLANATION / COMMAND / INFO stay in English exactly.\n\
             - Body in {lang_name}.\n\
             - PLAIN TEXT only. No markdown, no code fences, no backticks, no bullets, no numbering.\n\
             - Do NOT repeat the explanation inside INFO.\n\
             - Banned vague phrases (rewrite as specific): \"확인하세요\" / \"확인해 보세요\" / \"확인 후\" / \
             \"검토\" / \"점검\" / \"환경을 확인\" / \"경로를 확인\" / \"check your environment\" / \
             \"verify the path\" / \"please review\" / \"examine your\". \
             Replace with the concrete signal, e.g. \"PATH에 /usr/local/bin 없음\" / \"node_modules 미설치\". \
             If you would otherwise write \"~를 확인/검토/점검하세요\", instead emit a single shell command that \
             actually performs the check (e.g. \"ls -l <file>\", \"cat -A Makefile | head\", \"echo \\$PATH\").\n\
             - Total response under ~80 words.\n",
        )
    }

    /// LLM 응답 텍스트를 `AnalysisResult`로 파싱한다.
    ///
    /// 영어/한국어/일본어/중국어의 다양한 라벨 형태를 인식하고,
    /// placeholder 명령어는 `None`으로 정규화한다.
    /// 라벨이 전혀 없으면 전체 텍스트를 explanation으로 사용한다.
    pub fn parse_response(raw: &str) -> AnalysisResult {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return AnalysisResult {
                explanation: "(no response from LLM)".to_string(),
                suggested_command: None,
                additional_info: None,
            };
        }

        // <think> 블록 제거 후 파싱 (think 내용은 출력 시 별도 처리)
        let content = strip_think_block(trimmed);
        let content = content.trim();
        if content.is_empty() {
            return AnalysisResult {
                explanation: trimmed.to_string(),
                suggested_command: None,
                additional_info: None,
            };
        }

        let sections = parse_sections(content);

        let explanation = sections.explanation;
        let raw_command = sections.command;
        let info = sections.info;

        // 라벨이 하나도 매칭되지 않은 경우: 전체를 explanation에 그대로 사용
        if explanation.is_none() && raw_command.is_none() && info.is_none() {
            return AnalysisResult {
                explanation: content.to_string(),
                suggested_command: None,
                additional_info: None,
            };
        }

        AnalysisResult {
            explanation: explanation.unwrap_or_else(|| content.to_string()),
            suggested_command: raw_command.and_then(normalize_command),
            additional_info: info.filter(|s| !s.trim().is_empty()),
        }
    }

    /// 레코드 컨텍스트를 반영해 LLM 응답을 파싱한다.
    ///
    /// 기본 파서는 응답 형식만 다루고, 이 함수는 "명령어 미캡처 + AIC 자체 출력"
    /// 같은 컨텍스트에서 환각성 실행 제안을 제거한다.
    pub fn parse_response_for_record(
        raw: &str,
        record: &CommandRecord,
        lang: &str,
    ) -> AnalysisResult {
        let mut result = Self::parse_response(raw);
        let command_unknown = record
            .command
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty);

        if command_unknown && output_looks_like_aic_transcript(&record.output_lines) {
            result.suggested_command = None;
            if result
                .additional_info
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            {
                result.additional_info = Some(match lang {
                    "english" => "Original command was not captured; rerun it and invoke aic after the real failure output.".to_string(),
                    "japanese" => "元のコマンドが取得されていません。再実行して実際の失敗出力後にaicを起動してください。".to_string(),
                    "chinese" => "未捕获原始命令；请重新运行它，并在真实失败输出后再运行 aic。".to_string(),
                    _ => "원래 명령이 캡처되지 않았습니다. 다시 실행해 실제 실패 출력이 나온 뒤 aic를 실행하세요.".to_string(),
                });
            }
        }

        result
    }
}

// ── 파서 내부 ─────────────────────────────────────────────────

/// <think>...</think> 블록을 제거하고 나머지 텍스트를 반환한다.
fn strip_think_block(text: &str) -> String {
    if let Some(start) = text.find("<think>") {
        if let Some(end) = text.find("</think>") {
            return format!("{}{}", &text[..start], &text[end + 8..]);
        }
    }
    text.to_string()
}

#[derive(Debug, Default)]
struct ParsedSections {
    explanation: Option<String>,
    command: Option<String>,
    info: Option<String>,
}

/// 알려진 라벨 → 의미(SectionKind) 매핑.
/// 소문자 + 공백 정규화된 형태로 비교한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    Explanation,
    Command,
    Info,
}

/// 라벨 패턴 테이블. 가장 구체적인 라벨이 먼저 와야 한다.
/// (예: "suggested command"가 "command"보다 먼저)
const LABEL_TABLE: &[(&str, SectionKind)] = &[
    // 영어 — 구체적인 것 먼저
    ("suggested command", SectionKind::Command),
    ("fix command", SectionKind::Command),
    ("additional info", SectionKind::Info),
    ("explanation", SectionKind::Explanation),
    ("cause", SectionKind::Explanation),
    ("reason", SectionKind::Explanation),
    ("analysis", SectionKind::Explanation),
    ("command", SectionKind::Command),
    ("fix", SectionKind::Command),
    ("solution", SectionKind::Command),
    ("info", SectionKind::Info),
    ("note", SectionKind::Info),
    ("tip", SectionKind::Info),
    ("hint", SectionKind::Info),
    // 한국어
    ("수정 명령어", SectionKind::Command),
    ("제안 명령어", SectionKind::Command),
    ("추가 정보", SectionKind::Info),
    ("원인", SectionKind::Explanation),
    ("설명", SectionKind::Explanation),
    ("분석", SectionKind::Explanation),
    ("이유", SectionKind::Explanation),
    ("명령어", SectionKind::Command),
    ("제안", SectionKind::Command),
    ("해결", SectionKind::Command),
    ("참고", SectionKind::Info),
    ("팁", SectionKind::Info),
    ("비고", SectionKind::Info),
    // 일본어
    ("説明", SectionKind::Explanation),
    ("原因", SectionKind::Explanation),
    ("コマンド", SectionKind::Command),
    ("修正コマンド", SectionKind::Command),
    ("補足", SectionKind::Info),
    ("メモ", SectionKind::Info),
    // 중국어
    ("说明", SectionKind::Explanation),
    ("命令", SectionKind::Command),
    ("修复命令", SectionKind::Command),
    ("补充", SectionKind::Info),
    ("提示", SectionKind::Info),
];

/// 응답 텍스트를 라인 단위로 순회하며 라벨 섹션을 추출한다.
fn parse_sections(text: &str) -> ParsedSections {
    let mut sections = ParsedSections::default();
    let mut current: Option<(SectionKind, String)> = None;

    for line in text.lines() {
        if let Some((kind, body_start)) = match_label(line) {
            // 이전 섹션을 flush
            if let Some((k, body)) = current.take() {
                assign_section(&mut sections, k, body);
            }
            current = Some((kind, body_start.to_string()));
        } else if let Some((_, ref mut body)) = current {
            // 현재 섹션의 본문에 라인 추가
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(line);
        }
        // 라벨도 아니고 진행 중인 섹션도 없으면 무시 (헤더 위 빈 줄 등)
    }

    // 마지막 섹션 flush
    if let Some((k, body)) = current.take() {
        assign_section(&mut sections, k, body);
    }

    sections
}

/// 라인에서 라벨을 찾고, 라벨 종류와 콜론 뒤 본문 시작을 반환한다.
///
/// 지원 패턴:
/// - `LABEL: body`
/// - `**LABEL:** body` (마크다운 누수 대응)
/// - `1. LABEL: body` / `1) LABEL: body`
/// - `- LABEL: body`
///
/// 대소문자 무시, label 양쪽 공백 무시.
fn match_label(line: &str) -> Option<(SectionKind, &str)> {
    let stripped = strip_leading_decorations(line);
    let lower = stripped.to_lowercase();

    // 콜론(ASCII ':' 또는 전각 '：') 위치 — 첫 번째 콜론을 라벨/본문 경계로 본다
    let colon_idx = stripped.find([':', '\u{FF1A}'])?;
    let (label_raw, after) = stripped.split_at(colon_idx);
    // 콜론을 건너뛰고, 콜론 직후의 마크다운 마커(`**`, `*`, `_`, 백틱)를 제거
    let body = after
        .chars()
        .next()
        .map(|c| &after[c.len_utf8()..])
        .unwrap_or("")
        .trim_start_matches(['*', '_', '`'])
        .trim_start();

    let label_normalized = normalize_label(label_raw);
    if label_normalized.is_empty() {
        return None;
    }

    // 1. 정확히 매칭
    for (pat, kind) in LABEL_TABLE {
        if label_normalized == *pat {
            return Some((*kind, body));
        }
    }

    // 2. 라벨이 더 길어도 알려진 라벨로 시작/끝나는 경우 허용
    //    (예: "EXPLANATION (root cause)", "1. EXPLANATION")
    for (pat, kind) in LABEL_TABLE {
        if label_normalized.contains(pat) {
            return Some((*kind, body));
        }
    }

    // 3. 마크다운 강조가 lower 버전에 남았을 수 있으니 한 번 더
    let lower_label = lower[..colon_idx].trim_matches(|c: char| {
        c.is_whitespace() || c == '*' || c == '#' || c == '-' || c == '_' || c == '`'
    });
    for (pat, kind) in LABEL_TABLE {
        if lower_label == *pat {
            return Some((*kind, body));
        }
    }

    None
}

/// 라인 앞쪽의 마크다운/리스트 장식을 제거한다.
/// 예: `- `, `* `, `1. `, `1) `, `**`, `# ` 등.
fn strip_leading_decorations(line: &str) -> &str {
    let mut s = line.trim_start();
    // 마크다운 헤더 (#, ##, ...)
    while s.starts_with('#') {
        s = &s[1..];
    }
    s = s.trim_start();
    // 리스트 마커
    let bytes = s.as_bytes();
    if bytes
        .first()
        .map(|b| *b == b'-' || *b == b'*')
        .unwrap_or(false)
    {
        s = s[1..].trim_start();
    }
    // 번호 마커: "1.", "1)", "12.", "12)"
    let mut digits = 0;
    for b in s.bytes() {
        if b.is_ascii_digit() {
            digits += 1;
        } else {
            break;
        }
    }
    if digits > 0 && digits < s.len() {
        let after = &s[digits..];
        if after.starts_with('.') || after.starts_with(')') {
            s = after[1..].trim_start();
        }
    }
    s
}

/// 라벨 텍스트를 정규화한다 (소문자 + 마크다운 제거 + 공백 압축).
fn normalize_label(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(*c, '*' | '_' | '`' | '#'))
        .collect();
    let lower = cleaned.to_lowercase();
    // 연속 공백을 단일 공백으로 압축
    let mut out = String::with_capacity(lower.len());
    let mut prev_space = true;
    for ch in lower.trim().chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

fn assign_section(sections: &mut ParsedSections, kind: SectionKind, body: String) {
    let trimmed = body.trim().to_string();
    let target = match kind {
        SectionKind::Explanation => &mut sections.explanation,
        SectionKind::Command => &mut sections.command,
        SectionKind::Info => &mut sections.info,
    };
    // 같은 섹션이 두 번 등장하면 첫 번째만 유지 (LLM이 중복 응답해도 안정적)
    if target.is_none() {
        if !trimmed.is_empty() {
            *target = Some(trimmed);
        } else {
            // 빈 라벨도 "명시적으로 비어있음"이므로 None을 유지하되 매칭되었음을 기록할 필요는 없다
            *target = None;
        }
    }
}

fn deterministic_known_error(record: &CommandRecord, lang: &str) -> Option<AnalysisResult> {
    let output = record.output_lines.join("\n");
    let output_lower = output.to_lowercase();
    let command = record.command.as_deref().unwrap_or("").trim();
    let command_lower = command.to_lowercase();

    if record.exit_code == 127
        || output_lower.contains("command not found")
        || output_lower.contains("not recognized as an internal or external")
    {
        return Some(rule_result(
            lang,
            "shell.command_not_found",
            "명령을 찾을 수 없습니다. 실행 파일이 설치되어 있지 않거나 PATH에 없거나 명령 이름에 오타가 있을 가능성이 큽니다.",
            "Command was not found. It is likely not installed, not on PATH, or misspelled.",
            None,
            "설치 여부와 PATH를 먼저 확인하세요. 예: `which <command>` 또는 package manager 설치 상태를 확인합니다.",
            "Check whether the executable exists and is on PATH. For example, run `which <command>` or inspect the package manager install state.",
        ));
    }

    if record.exit_code == 126
        || output_lower.contains("permission denied")
        || output_lower.contains("operation not permitted")
    {
        let suggested =
            executable_path_from_command(command).map(|path| format!("chmod +x {path}"));
        return Some(rule_result(
            lang,
            "shell.permission_denied",
            "명령을 실행할 권한이 없습니다. 파일 실행 비트가 없거나 현재 사용자가 해당 파일/디렉토리에 접근할 권한이 없을 수 있습니다.",
            "The command could not be executed because permission was denied. The file may lack execute permission or the current user may not have access.",
            suggested,
            "파일이면 `ls -l`로 권한과 소유자를 확인하세요. 디렉토리/시스템 경로라면 소유자와 권한 정책을 먼저 확인해야 합니다.",
            "Check permissions and ownership with `ls -l`. For system paths, confirm ownership and access policy before changing permissions.",
        ));
    }

    if output_lower.contains("eaddrinuse")
        || output_lower.contains("address already in use")
        || output_lower.contains("port is already allocated")
    {
        return Some(rule_result(
            lang,
            "network.port_in_use",
            "사용하려는 포트가 이미 다른 프로세스에 의해 점유되어 있습니다.",
            "The port is already in use by another process.",
            None,
            "점유 프로세스를 확인한 뒤 종료하거나 다른 포트를 지정하세요. macOS/Linux 예: `lsof -nP -iTCP:<port> -sTCP:LISTEN`.",
            "Find the owning process and stop it or choose another port. On macOS/Linux: `lsof -nP -iTCP:<port> -sTCP:LISTEN`.",
        ));
    }

    if command_lower.starts_with("git ")
        && (output_lower.contains("non-fast-forward")
            || output_lower.contains("fetch first")
            || output_lower.contains("failed to push some refs"))
    {
        return Some(rule_result(
            lang,
            "git.non_fast_forward",
            "원격 브랜치에 로컬에 없는 커밋이 있어 push가 거부되었습니다.",
            "The push was rejected because the remote branch contains commits that are not in your local branch.",
            Some("git pull --rebase".to_string()),
            "rebase 후 충돌을 해결하고 테스트한 뒤 다시 push하세요. 공유 브랜치에서 force push는 피하세요.",
            "Rebase, resolve conflicts, run the relevant checks, then push again. Avoid force-pushing shared branches.",
        ));
    }

    if command_lower.starts_with("docker ")
        && output_lower.contains("cannot connect to the docker daemon")
    {
        return Some(rule_result(
            lang,
            "docker.daemon_not_running",
            "Docker daemon에 연결할 수 없습니다. Docker Desktop 또는 docker service가 실행 중이지 않을 가능성이 큽니다.",
            "The Docker daemon is not reachable. Docker Desktop or the docker service is likely not running.",
            None,
            "Docker Desktop/service를 시작한 뒤 `docker info`로 연결 상태를 확인하세요.",
            "Start Docker Desktop or the docker service, then verify with `docker info`.",
        ));
    }

    None
}

fn rule_result(
    lang: &str,
    rule_id: &str,
    explanation_ko: &str,
    explanation_en: &str,
    suggested_command: Option<String>,
    info_ko: &str,
    info_en: &str,
) -> AnalysisResult {
    let english = lang == "english";
    let info = if english { info_en } else { info_ko };
    AnalysisResult {
        explanation: if english {
            explanation_en.to_string()
        } else {
            explanation_ko.to_string()
        },
        suggested_command,
        additional_info: Some(format!("{info} [rule: {rule_id}]")),
    }
}

fn executable_path_from_command(command: &str) -> Option<String> {
    let first = command.split_whitespace().next()?.trim();
    if first.starts_with("./") || first.starts_with('/') {
        Some(first.to_string())
    } else {
        None
    }
}

fn output_looks_like_aic_transcript(lines: &[String]) -> bool {
    let joined = lines.join("\n").to_lowercase();
    let markers = [
        "[debug",
        "mode     error-analysis",
        "mode     repl",
        "aic>",
        "▸ 원인",
        "▸ 다음 시도",
        "? 실행:",
        "cache    ",
        "llm      ",
    ];
    markers
        .iter()
        .filter(|marker| joined.contains(**marker))
        .count()
        >= 2
}

/// LLM이 내놓은 명령어 문자열을 정규화한다.
/// - 코드펜스/백틱/양끝 따옴표 제거
/// - 첫 번째 라인만 사용
/// - placeholder ("없음", "(none)" 등)는 `None`
fn normalize_command(raw: String) -> Option<String> {
    let mut s = raw.trim().to_string();

    // 펜스드 코드블록 제거: ```lang\n...\n```
    if s.starts_with("```") {
        if let Some(rest) = s.strip_prefix("```") {
            // 첫 줄(언어 식별자) 버리기
            let after_lang = rest.split_once('\n').map(|(_, t)| t).unwrap_or(rest);
            s = after_lang.to_string();
        }
        if let Some(end) = s.rfind("```") {
            s.truncate(end);
        }
        s = s.trim().to_string();
    }

    // 단일 라인만 채택
    if let Some(first_line) = s.lines().next() {
        s = first_line.to_string();
    }

    // 인라인 백틱 제거: `cmd` → cmd
    if s.starts_with('`') && s.ends_with('`') && s.len() >= 2 {
        s = s[1..s.len() - 1].to_string();
    }

    // 양끝 따옴표 제거 (LLM이 가끔 감싸는 경우)
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            s = s[1..s.len() - 1].to_string();
        }
    }

    // 흔한 prefix 제거: "$ cmd" / "> cmd"
    if let Some(rest) = s.strip_prefix("$ ") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("> ") {
        s = rest.to_string();
    }

    let s = s.trim().to_string();
    if s.is_empty() {
        return None;
    }

    // placeholder 감지 (소문자 정규화 후 비교)
    let lower = s.to_lowercase();
    let placeholders = [
        "(none)",
        "none",
        "n/a",
        "na",
        "-",
        "—",
        "–",
        "없음",
        "해당 없음",
        "없습니다",
        "(없음)",
        "なし",
        "無し",
        "无",
        "无命令",
        "no fix",
        "no command",
        "not applicable",
        "(empty)",
        "(no command)",
    ];
    if placeholders.iter().any(|p| lower == *p) {
        return None;
    }

    Some(s)
}

// ── 테스트 ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use proptest::prelude::*;

    fn make_record(command: Option<&str>, exit_code: i32, lines: Vec<&str>) -> CommandRecord {
        CommandRecord {
            command: command.map(|s| s.to_string()),
            exit_code,
            output_lines: lines.into_iter().map(|s| s.to_string()).collect(),
            timestamp: Utc::now(),
            ..Default::default()
        }
    }

    // ── Property test ──────────────────────────────────────────

    proptest! {
        #[test]
        fn prompt_includes_all_context_fields(
            cmd in "[a-zA-Z0-9 _/\\-\\.]{1,80}",
            exit_code in prop::num::i32::ANY,
            lines in prop::collection::vec("[a-zA-Z0-9 :_/\\-\\.]{0,120}", 1..10),
        ) {
            let record = CommandRecord {
                command: Some(cmd.clone()),
                exit_code,
                output_lines: lines.clone(),
                timestamp: Utc::now(),
                ..Default::default()
            };

            let prompt = ErrorAnalyzer::build_prompt(&record, "korean");

            prop_assert!(
                prompt.contains(&cmd),
                "prompt에 command '{}' 가 포함되지 않음", cmd
            );

            let exit_str = exit_code.to_string();
            prop_assert!(
                prompt.contains(&exit_str),
                "prompt에 exit_code '{}' 가 포함되지 않음", exit_str
            );

            // 노이즈 제거 후 살아남은 라인은 모두 prompt에 포함된다.
            // (10줄 이하라 truncation은 발생하지 않음.)
            let cleaned = clean_output_lines(&lines, Some(&cmd));
            for line in &cleaned {
                if !line.is_empty() {
                    prop_assert!(
                        prompt.contains(line.as_str()),
                        "prompt에 cleaned line '{}' 가 포함되지 않음", line
                    );
                }
            }
        }
    }

    // ── clean_output_lines ─────────────────────────────────────

    #[test]
    fn clean_output_lines_drops_blank_short_and_prompt_lines() {
        let lines = vec![
            "".to_string(),
            "  ".to_string(),
            "d".to_string(),
            "sd".to_string(),
            "%".to_string(),
            "$".to_string(),
            "zsh: command not found: foo".to_string(),
        ];
        let out = clean_output_lines(&lines, None);
        assert_eq!(out, vec!["zsh: command not found: foo".to_string()]);
    }

    #[test]
    fn clean_output_lines_drops_command_echo() {
        let lines = vec![
            "ls /nope".to_string(),
            "ls: cannot access '/nope': No such file or directory".to_string(),
        ];
        let out = clean_output_lines(&lines, Some("ls /nope"));
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("No such file"));
    }

    #[test]
    fn clean_output_lines_preserves_when_all_noise() {
        // 모두 노이즈면 정보 손실 방지로 원본을 유지
        let lines = vec!["%".to_string(), "$".to_string(), "".to_string()];
        let out = clean_output_lines(&lines, None);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn clean_output_lines_keeps_meaningful_lines() {
        let lines = vec![
            "Permission denied".to_string(),
            "Operation not permitted".to_string(),
        ];
        let out = clean_output_lines(&lines, None);
        assert_eq!(out, lines);
    }

    #[test]
    fn clean_output_lines_strips_trailing_whitespace() {
        let lines = vec!["error message   \t".to_string()];
        let out = clean_output_lines(&lines, None);
        assert_eq!(out, vec!["error message".to_string()]);
    }

    #[test]
    fn clean_output_lines_with_none_command_skips_echo_check() {
        let lines = vec!["ls /nope".to_string(), "error msg".to_string()];
        let out = clean_output_lines(&lines, None);
        assert_eq!(out.len(), 2);
    }

    // ── build_prompt ───────────────────────────────────────────

    #[test]
    fn build_prompt_with_none_command() {
        let record = make_record(None, 127, vec!["command not found"]);
        let prompt = ErrorAnalyzer::build_prompt(&record, "korean");

        assert!(prompt.contains("(unknown command)"));
        assert!(prompt.contains("127"));
        assert!(prompt.contains("command not found"));
    }

    #[test]
    fn build_prompt_with_empty_output() {
        let record = make_record(Some("false"), 1, vec![]);
        let prompt = ErrorAnalyzer::build_prompt(&record, "korean");

        assert!(prompt.contains("false"));
        assert!(prompt.contains("(no output)"));
    }

    #[test]
    fn build_prompt_truncates_long_output_keeping_tail() {
        // 60줄 → 마지막 50줄만 보존, 앞 10줄은 truncate 표시
        let lines: Vec<String> = (0..60).map(|i| format!("line_{i}")).collect();
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let record = make_record(Some("cmd"), 1, line_refs);
        let prompt = ErrorAnalyzer::build_prompt(&record, "korean");

        assert!(prompt.contains("10 earlier lines truncated"));
        assert!(prompt.contains("line_59")); // 마지막은 보존
        assert!(prompt.contains("line_10")); // 50줄 윈도우 시작
        assert!(!prompt.contains("line_0\n")); // 가장 앞 라인은 잘림
    }

    #[test]
    fn build_prompt_specifies_language_name() {
        for (lang, expected) in [
            ("korean", "Korean"),
            ("english", "English"),
            ("japanese", "Japanese"),
            ("chinese", "Chinese"),
        ] {
            let record = make_record(Some("ls"), 1, vec!["x"]);
            let prompt = ErrorAnalyzer::build_prompt(&record, lang);
            assert!(
                prompt.contains(expected),
                "lang '{lang}' should include '{expected}'"
            );
        }
    }

    #[test]
    fn build_prompt_enforces_english_labels() {
        let record = make_record(Some("ls"), 1, vec!["x"]);
        let prompt = ErrorAnalyzer::build_prompt(&record, "korean");
        assert!(prompt.contains("EXPLANATION:"));
        assert!(prompt.contains("COMMAND:"));
        assert!(prompt.contains("INFO:"));
    }

    #[test]
    fn build_prompt_exit_130_warns_against_guessing() {
        let record = make_record(None, 130, vec!["▸ 다음 시도", "$ make", "? 실행: `make` ?"]);
        let prompt = ErrorAnalyzer::build_prompt(&record, "korean");

        assert!(prompt.contains("EXIT_CODE 130 means"));
        assert!(prompt.contains("COMMAND must be empty"));
        assert!(prompt.contains("Do NOT copy commands"));
    }

    #[test]
    fn deterministic_result_exit_130_has_no_command() {
        let record = make_record(Some("make"), 130, vec!["^C"]);
        let result = ErrorAnalyzer::deterministic_result(&record, "korean").unwrap();

        assert!(result.explanation.contains("SIGINT"));
        assert!(result.suggested_command.is_none());
        assert!(result.additional_info.is_some());
    }

    #[test]
    fn deterministic_result_exit_130_aic_transcript_mentions_wrapper() {
        let record = make_record(
            None,
            130,
            vec![
                "[debug +0.001s] mode     error-analysis",
                "▸ 다음 시도",
                "$ make",
                "? 실행: `make` ?",
            ],
        );
        let result = ErrorAnalyzer::deterministic_result(&record, "korean").unwrap();

        assert!(result.explanation.contains("AIC"));
        assert!(result.suggested_command.is_none());
        assert!(result.additional_info.unwrap().contains("원래 명령"));
    }

    #[test]
    fn deterministic_result_command_not_found() {
        let record = make_record(
            Some("frobnicate"),
            127,
            vec!["zsh: command not found: frobnicate"],
        );
        let result = ErrorAnalyzer::deterministic_result(&record, "korean").unwrap();

        assert!(result.explanation.contains("명령을 찾을 수 없습니다"));
        assert!(result.suggested_command.is_none());
        assert!(result
            .additional_info
            .unwrap()
            .contains("shell.command_not_found"));
    }

    #[test]
    fn deterministic_result_permission_denied_suggests_chmod_for_local_path() {
        let record = make_record(Some("./deploy.sh"), 126, vec!["permission denied"]);
        let result = ErrorAnalyzer::deterministic_result(&record, "english").unwrap();

        assert!(result.explanation.contains("permission was denied"));
        assert_eq!(
            result.suggested_command.as_deref(),
            Some("chmod +x ./deploy.sh")
        );
        assert!(result
            .additional_info
            .unwrap()
            .contains("shell.permission_denied"));
    }

    #[test]
    fn deterministic_result_port_in_use() {
        let record = make_record(
            Some("npm run dev"),
            1,
            vec!["Error: listen EADDRINUSE: address already in use :::3000"],
        );
        let result = ErrorAnalyzer::deterministic_result(&record, "korean").unwrap();

        assert!(result.explanation.contains("포트"));
        assert!(result
            .additional_info
            .unwrap()
            .contains("network.port_in_use"));
    }

    #[test]
    fn deterministic_result_git_non_fast_forward() {
        let record = make_record(
            Some("git push"),
            1,
            vec!["! [rejected] main -> main (non-fast-forward)"],
        );
        let result = ErrorAnalyzer::deterministic_result(&record, "english").unwrap();

        assert_eq!(
            result.suggested_command.as_deref(),
            Some("git pull --rebase")
        );
        assert!(result.explanation.contains("remote branch"));
        assert!(result
            .additional_info
            .unwrap()
            .contains("git.non_fast_forward"));
    }

    // ── parse_response: 영어 라벨 ──────────────────────────────

    #[test]
    fn parse_response_english_canonical() {
        let raw = "\
EXPLANATION: The file does not exist.
COMMAND: ls /correct/path
INFO: Check your working directory.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "The file does not exist.");
        assert_eq!(
            result.suggested_command.as_deref(),
            Some("ls /correct/path")
        );
        assert_eq!(
            result.additional_info.as_deref(),
            Some("Check your working directory.")
        );
    }

    // ── parse_response: 한국어 라벨 (실제 LLM이 자주 내는 형태) ──

    #[test]
    fn parse_response_korean_numbered_labels() {
        let raw = "\
1. 설명: 이 명령어는 파일을 찾을 수 없습니다.
2. 수정 명령어: python3 /Users/jinwoo/script.py
3. 추가 정보: 절대 경로를 사용하세요.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert!(result.explanation.contains("파일을 찾을 수 없"));
        assert_eq!(
            result.suggested_command.as_deref(),
            Some("python3 /Users/jinwoo/script.py")
        );
        assert!(result
            .additional_info
            .as_deref()
            .unwrap()
            .contains("절대 경로"));
    }

    #[test]
    fn parse_response_korean_short_labels() {
        let raw = "\
원인: 파일이 없습니다.
명령어: ls
참고: pwd로 현재 위치 확인.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "파일이 없습니다.");
        assert_eq!(result.suggested_command.as_deref(), Some("ls"));
        assert_eq!(
            result.additional_info.as_deref(),
            Some("pwd로 현재 위치 확인.")
        );
    }

    #[test]
    fn parse_response_japanese_labels() {
        let raw = "\
説明: ファイルが見つかりません。
コマンド: ls /tmp
補足: パスを確認してください。";
        let result = ErrorAnalyzer::parse_response(raw);
        assert!(result.explanation.contains("ファイル"));
        assert_eq!(result.suggested_command.as_deref(), Some("ls /tmp"));
        assert!(result.additional_info.is_some());
    }

    // ── parse_response: 명령어 정규화 ──────────────────────────

    #[test]
    fn parse_response_strips_code_fence() {
        let raw = "\
EXPLANATION: x.
COMMAND: ```bash
ls -la
```
INFO: y.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.suggested_command.as_deref(), Some("ls -la"));
    }

    #[test]
    fn parse_response_strips_inline_backticks() {
        let raw = "EXPLANATION: x.\nCOMMAND: `ls -la`\nINFO: y.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.suggested_command.as_deref(), Some("ls -la"));
    }

    #[test]
    fn parse_response_strips_dollar_prefix() {
        let raw = "EXPLANATION: x.\nCOMMAND: $ ls -la\nINFO: y.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.suggested_command.as_deref(), Some("ls -la"));
    }

    #[test]
    fn parse_response_strips_surrounding_quotes() {
        let raw = "EXPLANATION: x.\nCOMMAND: \"ls -la\"\nINFO: y.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.suggested_command.as_deref(), Some("ls -la"));
    }

    #[test]
    fn parse_response_command_placeholder_becomes_none() {
        for placeholder in &[
            "EXPLANATION: x.\nCOMMAND: 없음\nINFO: y.",
            "EXPLANATION: x.\nCOMMAND: (none)\nINFO: y.",
            "EXPLANATION: x.\nCOMMAND: N/A\nINFO: y.",
            "EXPLANATION: x.\nCOMMAND: -\nINFO: y.",
            "EXPLANATION: x.\nCOMMAND: \nINFO: y.",
        ] {
            let result = ErrorAnalyzer::parse_response(placeholder);
            assert!(
                result.suggested_command.is_none(),
                "placeholder '{placeholder}'은 None이어야 함"
            );
        }
    }

    // ── parse_response: 마크다운 누수 ──────────────────────────

    #[test]
    fn parse_response_handles_markdown_bold() {
        let raw = "**EXPLANATION:** test.\n**COMMAND:** ls\n**INFO:** ok.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "test.");
        assert_eq!(result.suggested_command.as_deref(), Some("ls"));
    }

    #[test]
    fn parse_response_handles_dash_prefix() {
        let raw = "- EXPLANATION: x.\n- COMMAND: ls\n- INFO: ok.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "x.");
        assert_eq!(result.suggested_command.as_deref(), Some("ls"));
    }

    // ── parse_response: 다중 라인 본문 ─────────────────────────

    #[test]
    fn parse_response_multiline_explanation() {
        let raw = "\
EXPLANATION: First sentence.
Second sentence on next line.
COMMAND: ls
INFO: tip.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert!(result.explanation.contains("First sentence"));
        assert!(result.explanation.contains("Second sentence"));
        assert_eq!(result.suggested_command.as_deref(), Some("ls"));
    }

    // ── parse_response: 빈 / fallback / 부분 매칭 ──────────────

    #[test]
    fn parse_response_unstructured_fallback() {
        let raw = "Something went wrong, try again later.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, raw);
        assert!(result.suggested_command.is_none());
        assert!(result.additional_info.is_none());
    }

    #[test]
    fn parse_response_empty_input() {
        let result = ErrorAnalyzer::parse_response("");
        assert_eq!(result.explanation, "(no response from LLM)");
        assert!(result.suggested_command.is_none());
        assert!(result.additional_info.is_none());
    }

    #[test]
    fn parse_response_whitespace_only() {
        let result = ErrorAnalyzer::parse_response("   \n\t  ");
        assert_eq!(result.explanation, "(no response from LLM)");
    }

    #[test]
    fn parse_response_only_explanation() {
        let raw = "EXPLANATION: Permission denied.";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "Permission denied.");
        assert!(result.suggested_command.is_none());
        assert!(result.additional_info.is_none());
    }

    #[test]
    fn parse_response_case_insensitive_labels() {
        let raw = "explanation: lowercase works\ncommand: echo hello";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "lowercase works");
        assert_eq!(result.suggested_command.as_deref(), Some("echo hello"));
    }

    #[test]
    fn parse_response_full_width_colon() {
        // 일부 LLM이 한국어 응답에서 전각 콜론(U+FF1A)을 사용하는 경우
        let raw = "원인\u{FF1A}파일 없음\n명령어\u{FF1A}ls /tmp";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "파일 없음");
        assert_eq!(result.suggested_command.as_deref(), Some("ls /tmp"));
    }

    #[test]
    fn parse_response_duplicate_section_keeps_first() {
        let raw = "\
EXPLANATION: first
COMMAND: ls
EXPLANATION: second
INFO: ok";
        let result = ErrorAnalyzer::parse_response(raw);
        assert_eq!(result.explanation, "first");
        assert_eq!(result.suggested_command.as_deref(), Some("ls"));
        assert_eq!(result.additional_info.as_deref(), Some("ok"));
    }

    #[test]
    fn parse_response_for_record_drops_aic_transcript_command_guess() {
        let record = make_record(
            None,
            1,
            vec![
                "[debug +0.001s] mode     error-analysis",
                "▸ 다음 시도",
                "$ make",
                "aic>",
            ],
        );
        let raw = "원인: 이전 출력입니다.\n다음 시도: make\n참고: 로그를 다시 보세요.";
        let result = ErrorAnalyzer::parse_response_for_record(raw, &record, "korean");

        assert!(result.suggested_command.is_none());
        assert!(result.additional_info.is_some());
    }

    #[test]
    #[ignore] // 임시 dump용 — `cargo test ... -- --ignored --nocapture`로 출력만 확인
    fn dump_actual_prompt() {
        let r = CommandRecord {
            command: Some("cat sd".to_string()),
            exit_code: 1,
            output_lines: vec!["cat: sd: No such file or directory".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let p = ErrorAnalyzer::build_prompt(&r, "korean");
        println!("\n===== ACTUAL PROMPT BEGIN =====");
        println!("{p}");
        println!("===== ACTUAL PROMPT END ({} chars) =====\n", p.len());
    }
}
