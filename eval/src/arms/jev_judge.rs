//! TypeSafe Jev의 Choice로 evidence 섹션 하나의 상태(정상·경고·위험)를 고른다.
//!
//! `jev.rs`(probe **선택**)와 API·재시도 정책은 같지만 질문 계약이 다르다 — 여기서는 probe별
//! 임계를 담지 않는 단일 질문을 쓴다(`docs/PRD-JEV-PROBE-JUDGMENT.md` 3절). state 조립과 응답
//! 파싱은 HTTP와 분리한 순수 함수로 두어 `TYPESAFE_API_KEY` 없이도 테스트한다(R8).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;

const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
const QUESTION_ID: &str = "severity";
/// 보조 Noul 질문. T5가 라이브 1회로 wire 형식을 확인했다(`docs/PRD-JEV-PROBE-JUDGMENT.md` 9절:
/// 응답은 `{"type":"noul","noul":<0..1>}` 하나뿐이고 별도 confidence가 없다). 같은 state에 붙여
/// 보내되, 주 지표는 그대로 `severity`(Choice)로만 계산한다 — Noul은 임계를 바꿔가며 정밀도·재현율
/// 곡선을 그리는 보조 분석 전용이다.
const NOUL_QUESTION_ID: &str = "abnormal";

/// 질문 버전. `instructions`나 `criteria`를 고치면 올린다(jev.rs의 관례).
/// v2: 개발 45섹션 1회 실행 후 명시적 한도가 없는 수치(예: proc_fd_top의 절대량 축)를 모델이
/// 과소평가하는 사례가 보여 일반 원칙 한 문장을 추가했다(RESULTS.md 참고). probe별 수치 임계는
/// 여전히 넣지 않는다.
pub const QUESTION_VERSION: &str = "v3";

/// 429(속도 제한)와 529(과부하)만 재시도한다. 401·422는 다시 보내도 같은 답이다(jev.rs와 동일 정책).
const MAX_ATTEMPTS: u32 = 4;
const BASE_BACKOFF_MS: u64 = 500;

/// state 토큰 추정에 쓰는 바이트/토큰 비율. 실제 비율보다 낮게(=보수적으로) 잡아야 추정이 실측보다
/// 작아서 예산을 넘겨 보내는 사고를 막는다. T6에서 usage.input_tokens와 대조해 검증한다.
pub const CONSERVATIVE_BYTES_PER_TOKEN: f64 = 2.0;

/// 요청 하나에 허용하는 state 토큰 상한. Jev의 요청당 컨텍스트는 state와 가장 긴 질문 합계 32k
/// 토큰이다(PRD-JEV-PROBE-SELECTION.md 9절). 질문 쪽 여유를 넉넉히 남기려고 절반만 state에 쓴다.
pub const STATE_TOKEN_BUDGET: u64 = 16_000;

/// 판정 결과. `success`도 `failure`도 아닌 `oversize`가 있다 — 예산을 넘은 섹션은 보내지 않고
/// 여기서 바로 반환하므로 API 실패(계약 위반)와 섞어 세면 안 된다(R5).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct JudgeOutcome {
    /// "none" | "warn" | "crit". 실패(oversize 포함)면 `None`.
    pub label: Option<String>,
    /// 선택지 밖 값을 받았을 때 그 원문. 무엇을 만들어냈는지 기록해야 한계를 보고할 수 있다.
    pub raw_label: Option<String>,
    pub confidence: Option<f64>,
    pub probabilities: Option<BTreeMap<String, f64>>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// 보조 Noul 응답(0..1, "이상 신호가 있는가"의 확률). 계약 위반이어도 실패로 세지 않는다 —
    /// 주 지표는 `label`(Choice)뿐이고 이 값은 judge-score(T7)의 보조 곡선에만 쓴다.
    pub noul: Option<f64>,
    /// 재시도를 포함한 총 시도 수. oversize면 전송 자체가 없으므로 0이다.
    pub attempts: u32,
    pub latency_ms: u64,
    pub error: Option<String>,
    /// state 토큰 추정치가 [`STATE_TOKEN_BUDGET`]을 넘어 **전송하지 않은** 사례. 잘라 보내는
    /// 폴백은 두지 않는다 — 잘림과 모델의 누락을 구분할 수 없게 되기 때문이다(R5).
    pub oversize: bool,
}

impl JudgeOutcome {
    fn failed(error: impl Into<String>, attempts: u32, latency_ms: u64) -> Self {
        Self {
            attempts,
            latency_ms,
            error: Some(error.into()),
            ..Default::default()
        }
    }

    fn oversize() -> Self {
        Self {
            oversize: true,
            ..Default::default()
        }
    }

    /// 성공도 oversize도 아니면 실패다. oversize는 별도 열로 보고하므로 여기서 실패로 세지 않는다.
    /// judge-score(T7, `docs/PRD-JEV-PROBE-JUDGMENT.md` 7절)가 실패율 집계에 쓴다 — 아직
    /// 배선 전이라 프로덕션 경로에서는 미사용이다.
    #[allow(dead_code)]
    pub fn is_failure(&self) -> bool {
        self.label.is_none() && !self.oversize
    }
}

/// 범주 설명. Choice의 `criteria`로 들어간다. probe 이름이나 수치 임계는 넣지 않는다 — 넣으면
/// 사실상 스캐너를 프롬프트로 재구현하는 것이고, 2단계가 같은 질문을 재사용할 수 없다.
fn criteria() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("none", "정상이다. 수치나 상태가 임계를 넘지 않고 즉시 조치가 필요하지 않다."),
        (
            "warn",
            "경고다. 자원 사용량이나 오류가 임계에 근접했거나 넘어서 주의가 필요하지만 아직 서비스 중단은 아니다.",
        ),
        (
            "crit",
            "위험이다. 이미 서비스 중단·강제 종료 등 심각한 사건이 벌어졌다.",
        ),
    ])
}

/// v2까지는 임계를 주지 않고 "상식적인 기준"에만 맡겼고, 그래서 실패가 전부 임계 판단에 몰렸다
/// (정밀도 0.750, disk 0.571 · inodes 0.444 · swap_usage 0.571). v3는 자원 유형별 임계를 준다.
///
/// 임계값은 `aic-client/src/agent/diagnose.rs`의 스캐너 상수를 그대로 옮긴 것이다. 평가 데이터의
/// 실패 사례를 보고 정한 값이 아니다 — 그랬다면 같은 데이터로 재측정할 수 없다.
///
/// probe 이름 대신 **자원 유형**으로 쓴다. 스캐너가 없는 50개 probe로 확장할 때 같은 문장을
/// 재사용할 수 있어야 하기 때문이다. probe마다 임계를 나열하면 질문이 probe 수만큼 늘어난다.
fn instructions() -> String {
    "호스트에서 수집한 진단 probe 출력 섹션 하나다. 이 섹션이 나타내는 상태를 정상·경고·위험 중 \
     하나로 고른다.\n\n\
     수치가 있으면 다음 임계를 기준으로 본다.\n\
     - 디스크 용량과 inode 사용률: 90% 이상이면 경고\n\
     - 파일 디스크립터와 swap 사용률: 80% 이상이면 경고\n\
     - 프로세스 하나가 자기 한도에서 차지하는 비율: 50% 이상이면 경고\n\
     - 좀비 프로세스: 10개 이상이면 경고\n\n\
     사건 로그는 수치가 아니라 존재 자체로 판단한다. OOM으로 인한 강제 종료, 유닛 시작 실패, \
     데몬 오류는 한 건이라도 있으면 경고 이상이며, 서비스가 이미 멈춘 정황이 있으면 위험이다.\n\n\
     위 목록에 없는 자원이라도 한도 대비 비율을 알 수 있으면 같은 기준(80~90%)을 적용한다. \
     한도를 알 수 없고 절대량만 있으면 그 수치가 상식적으로 비정상인지 본다. \
     판단할 근거가 부족하면 정상을 고른다."
        .to_string()
}

/// Noul(보조) 질문의 criteria. `severity`(Choice)와 같은 판단 기준을 이진으로 다시 묻는다 —
/// 별도 기준을 쓰면 두 질문이 서로 다른 것을 재게 된다.
fn noul_criteria() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "true",
            "수치가 임계를 넘었거나 심각한 사건이 이미 발생했다.",
        ),
        ("false", "수치와 상태가 정상 범위 안에 있다."),
    ])
}

fn noul_instructions() -> String {
    "이 진단 probe 출력 섹션이 정상 범위를 벗어난 이상 신호를 담고 있는가?".to_string()
}

const KNOWN_LABELS: [&str; 3] = ["none", "warn", "crit"];

/// evidence 섹션에서 Jev에 보낼 state를 만든다(순수). `## <probe_id>` 줄, `command:` 줄,
/// `exit_code=` 줄, stdout 본문까지만 남기고 stderr는 뺀다 — 9개 스캐너 전부 stdout만 보므로
/// stderr까지 주면 모델이 스캐너보다 더 많은 정보를 갖게 돼 "재현" 질문이 어긋난다(PRD 3절).
/// 이 결정의 한계: stderr에만 있는 신호(예: 명령 자체의 실패)는 이 실험이 놓친다.
///
/// 송신 직전 `aic_common::redaction::redact`를 적용한다 — 합성 fixture만 보낸다는 전제의
/// 방어선이지 실제 출력 전송의 허가 근거가 아니다(R4).
pub fn build_state(section: &str) -> String {
    let before_stderr = section
        .split_once("\n--- stderr ---")
        .map_or(section, |(before, _)| before);
    aic_common::redaction::redact(before_stderr).0
}

/// state의 추정 토큰 수. [`CONSERVATIVE_BYTES_PER_TOKEN`]보다 실측 비율이 높으면(=한 토큰이 더
/// 많은 바이트를 차지하면) 추정이 실제보다 커져 안전한 쪽으로 틀린다. T6이 usage.input_tokens와
/// 대조해 이 상수의 보수성을 실측으로 확인한다.
pub fn estimated_tokens(state: &str) -> u64 {
    (state.len() as f64 / CONSERVATIVE_BYTES_PER_TOKEN).ceil() as u64
}

/// state가 [`STATE_TOKEN_BUDGET`]을 넘는지(순수).
pub fn is_oversize(state: &str) -> bool {
    estimated_tokens(state) > STATE_TOKEN_BUDGET
}

pub struct JudgeClient {
    http: reqwest::Client,
    api_key: String,
    model: String,
}

impl JudgeClient {
    /// `TYPESAFE_API_KEY`에서 키를 읽는다. 네트워크 진입점은 이 생성자를 실제로 부르는
    /// `judge-run` 서브커맨드 하나뿐이다 — 단위 테스트는 호출하지 않는다(R8).
    pub fn from_env(model: &str) -> Result<Self> {
        let api_key = std::env::var("TYPESAFE_API_KEY").context(
            "TYPESAFE_API_KEY가 설정돼 있지 않습니다 — judge 비교군을 실행할 수 없습니다",
        )?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("HTTP 클라이언트 생성 실패")?;
        Ok(Self {
            http,
            api_key,
            model: model.to_string(),
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// evidence 섹션 하나를 판정한다. 예산을 넘으면 전송 없이 [`JudgeOutcome::oversize`]를 낸다.
    pub async fn judge(&self, section: &str) -> JudgeOutcome {
        let state = build_state(section);
        if is_oversize(&state) {
            return JudgeOutcome::oversize();
        }

        let started = Instant::now();
        let body = json!({
            "state": state,
            "model": self.model,
            "questions": {
                QUESTION_ID: {
                    "type": "choice",
                    "instructions": instructions(),
                    "criteria": criteria(),
                },
                NOUL_QUESTION_ID: {
                    "type": "noul",
                    "instructions": noul_instructions(),
                    "criteria": noul_criteria(),
                }
            }
        });

        let mut attempts = 0;
        let mut last_error = String::new();
        while attempts < MAX_ATTEMPTS {
            attempts += 1;
            match self.send_once(&body).await {
                Ok(json) => {
                    return parse_answer(&json, attempts, started.elapsed().as_millis() as u64)
                }
                Err(SendError::Retryable(msg)) => {
                    last_error = msg;
                    let backoff = BASE_BACKOFF_MS * 2u64.pow(attempts - 1);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
                Err(SendError::Permanent(msg)) => {
                    return JudgeOutcome::failed(
                        msg,
                        attempts,
                        started.elapsed().as_millis() as u64,
                    )
                }
            }
        }
        JudgeOutcome::failed(
            format!("{MAX_ATTEMPTS}회 재시도 후 실패: {last_error}"),
            attempts,
            started.elapsed().as_millis() as u64,
        )
    }

    async fn send_once(&self, body: &serde_json::Value) -> Result<serde_json::Value, SendError> {
        let resp = self
            .http
            .post(ENDPOINT)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| SendError::Retryable(format!("요청 실패: {e}")))?;

        let status = resp.status().as_u16();
        if status == 429 || status == 529 {
            return Err(SendError::Retryable(format!("HTTP {status}")));
        }
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            let head: String = text.chars().take(200).collect();
            return Err(SendError::Permanent(format!("HTTP {status}: {head}")));
        }
        resp.json()
            .await
            .map_err(|e| SendError::Permanent(format!("응답 파싱 실패: {e}")))
    }
}

enum SendError {
    Retryable(String),
    Permanent(String),
}

/// 응답에서 라벨과 부수 정보를 꺼낸다(순수). 목록 밖 값·`answers` 누락은 실패로 세고 원문은
/// 남긴다 — 조용히 대체하면 측정 대상인 계약 위반율 자체가 사라진다(R6, jev.rs의
/// `an_unknown_choice_counts_as_failure_but_keeps_the_raw_value`와 같은 형태).
fn parse_answer(json: &serde_json::Value, attempts: u32, latency_ms: u64) -> JudgeOutcome {
    let Some(answer) = json.pointer(&format!("/answers/{QUESTION_ID}")) else {
        return JudgeOutcome::failed("응답에 answers가 없습니다", attempts, latency_ms);
    };
    let raw = answer
        .get("choice")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let probabilities = answer
        .get("probabilities")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_f64().map(|f| (k.clone(), f)))
                .collect::<BTreeMap<String, f64>>()
        });
    let input_tokens = json
        .pointer("/usage/input_tokens")
        .and_then(serde_json::Value::as_u64);
    let output_tokens = json
        .pointer("/usage/output_tokens")
        .and_then(serde_json::Value::as_u64);
    // Noul은 보조 신호다 — 없거나 형식이 어긋나도 주 판정(label)의 실패로 세지 않는다.
    let noul = json
        .pointer(&format!("/answers/{NOUL_QUESTION_ID}/noul"))
        .and_then(serde_json::Value::as_f64);
    let label = raw
        .as_deref()
        .filter(|c| KNOWN_LABELS.contains(c))
        .map(str::to_string);
    let error = if label.is_none() {
        Some(match &raw {
            Some(r) => format!("목록 밖 라벨: {r}"),
            None => "응답에 choice가 없습니다".to_string(),
        })
    } else {
        None
    };

    JudgeOutcome {
        label,
        raw_label: raw,
        confidence: answer.get("confidence").and_then(serde_json::Value::as_f64),
        probabilities,
        input_tokens,
        output_tokens,
        noul,
        attempts,
        latency_ms,
        error,
        oversize: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn criteria_cover_exactly_the_three_labels() {
        let c = criteria();
        assert_eq!(c.len(), KNOWN_LABELS.len());
        for label in KNOWN_LABELS {
            assert!(c.contains_key(label), "criteria에 {label}이 없습니다");
        }
    }

    #[test]
    fn build_state_drops_stderr_and_keeps_the_header_and_stdout() {
        let section = "## disk\ncommand: df -h\nexit_code=0 duration_ms=1 truncated=false cwd=.\n\
--- stdout ---\n/dev/sda1 100G 95G 5G 95% /\n\n--- stderr ---\nsome noise on stderr\n";
        let state = build_state(section);
        assert!(state.contains("## disk"));
        assert!(state.contains("command: df -h"));
        assert!(state.contains("--- stdout ---"));
        assert!(state.contains("/dev/sda1 100G 95G 5G 95% /"));
        assert!(
            !state.contains("some noise on stderr"),
            "stderr가 state에 남았다: {state}"
        );
    }

    #[test]
    fn build_state_redacts_secrets_before_sending() {
        // 심어둔 가짜 API 키가 전송 본문(state)에 그대로 남지 않아야 한다. entropy 게이트를
        // 통과하도록 aic-common의 redaction 테스트와 같은 다양한 문자 구성을 쓴다.
        let fake_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";
        let section = format!(
            "## journal_daemon_errors\ncommand: journalctl\nexit_code=0\n\
--- stdout ---\ntoken={fake_key}\n\n--- stderr ---\n"
        );
        let state = build_state(&section);
        assert!(!state.contains(fake_key), "redact 미적용: {state}");
    }

    #[test]
    fn a_64kib_section_is_rejected_as_oversize_without_a_network_call() {
        let huge = "x".repeat(64 * 1024);
        let section = format!(
            "## disk\ncommand: df -h\nexit_code=0\n--- stdout ---\n{huge}\n\n--- stderr ---\n"
        );
        let state = build_state(&section);
        assert!(
            is_oversize(&state),
            "64 KiB 섹션이 oversize로 거부되지 않았다"
        );
    }

    #[test]
    fn a_small_section_is_not_oversize() {
        let section = "## disk\ncommand: df -h\nexit_code=0\n--- stdout ---\n\
/dev/sda1 100G 95G 5G 95% /\n\n--- stderr ---\n";
        let state = build_state(section);
        assert!(!is_oversize(&state));
    }

    #[test]
    fn a_known_choice_is_accepted() {
        let json = json!({
            "answers": { "severity": {
                "type": "choice",
                "choice": "warn",
                "probabilities": { "warn": 0.7, "none": 0.2, "crit": 0.1 },
                "confidence": 0.6
            }},
            "usage": { "input_tokens": 210, "output_tokens": 0 }
        });
        let out = parse_answer(&json, 1, 80);
        assert_eq!(out.label.as_deref(), Some("warn"));
        assert_eq!(out.confidence, Some(0.6));
        assert_eq!(out.input_tokens, Some(210));
        assert!(out.error.is_none());
        assert!(!out.is_failure());
        assert_eq!(
            out.noul, None,
            "abnormal 질문이 없으면 noul은 None이어야 한다"
        );
    }

    #[test]
    fn a_noul_answer_in_the_same_response_is_parsed() {
        // 2026-09-22 라이브 확인(T5, docs/PRD-JEV-PROBE-JUDGMENT.md 9절)에서 받은 실제 형태.
        let json = json!({
            "model": "jev-1.13.0",
            "answers": {
                "severity": {
                    "type": "choice",
                    "choice": "warn",
                    "confidence": 0.91,
                    "probabilities": { "warn": 0.94, "none": 0.01, "crit": 0.05 }
                },
                "abnormal": { "type": "noul", "noul": 0.84 }
            },
            "usage": { "input_tokens": 636, "output_tokens": 57 }
        });
        let out = parse_answer(&json, 1, 120);
        assert_eq!(out.label.as_deref(), Some("warn"));
        assert_eq!(out.noul, Some(0.84));
        assert!(!out.is_failure());
    }

    #[test]
    fn an_unknown_choice_counts_as_failure_but_keeps_the_raw_value() {
        // 목록 밖 값을 조용히 none으로 바꾸면, 모델이 계약을 어긴 사실이 지표에서 사라진다.
        let json = json!({ "answers": { "severity": { "choice": "info" } } });
        let out = parse_answer(&json, 1, 90);
        assert!(out.is_failure());
        assert_eq!(out.raw_label.as_deref(), Some("info"));
        assert!(out.error.unwrap().contains("info"));
    }

    #[test]
    fn a_missing_answer_is_a_failure() {
        let out = parse_answer(&json!({ "usage": {} }), 2, 300);
        assert!(out.is_failure());
        assert_eq!(out.attempts, 2);
        assert_eq!(out.latency_ms, 300);
    }
}
