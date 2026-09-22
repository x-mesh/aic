//! TypeSafe Jev의 Choice로 범주를 고른다.
//!
//! Rust SDK가 없어 HTTP를 직접 친다. 요청·응답 형식은 공식 API 문서(2026-09-22 확인)를 따른다.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use aic_client::agent::diagnose::DIAGNOSE_CATEGORIES;
use anyhow::{Context, Result};
use serde_json::json;

use super::ArmOutcome;

const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// 질문 하나짜리 요청이라 id는 고정이다.
const QUESTION_ID: &str = "category";

/// 질문 버전. `instructions`나 `criteria`를 고치면 올린다. 원시 결과에 함께 실어야 어떤 질문으로
/// 얻은 수치인지 나중에 가릴 수 있다.
pub const QUESTION_VERSION: &str = "v1";

/// 429(속도 제한)와 529(과부하)만 재시도한다. 401·422는 다시 보내도 같은 답이다.
const MAX_ATTEMPTS: u32 = 4;
const BASE_BACKOFF_MS: u64 = 500;

/// 범주 설명. Choice의 `criteria`로 들어간다.
///
/// 설명은 **증상이 가리키는 대상**을 기준으로 쓴다. 어떤 probe가 붙는지는 적지 않는다 —
/// 모델에게 probe를 고르게 하면 목록 밖 항목을 만들어낼 여지가 생기고, 그건 불변 조건 위반이다.
fn criteria() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("cpu", "처리 능력이 문제다. 부하가 높거나, 클럭이 제한되거나, 연산이 밀려 느리다."),
        ("memory", "메모리가 문제다. 사용량이 많거나, 누수가 의심되거나, OOM이 발생했거나, swap을 쓴다."),
        ("disk", "저장 장치가 문제다. 공간이나 inode가 부족하거나, 읽기·쓰기가 느리거나, 파일시스템이 이상하다."),
        ("network", "네트워크가 문제다. 연결이 되지 않거나, 포트·DNS·지연·패킷 손실이 의심된다."),
        ("process", "특정 프로세스나 서비스가 문제다. 죽었거나, 재시작을 반복하거나, 응답하지 않는다."),
        ("docker", "Docker 자체나 컨테이너가 문제다."),
        ("k8s", "Kubernetes 클러스터, 노드, 파드가 문제다."),
        ("generic", "증상만으로는 어느 대상이 문제인지 좁힐 수 없다."),
    ])
}

fn instructions() -> String {
    "운영자가 호스트에서 관측한 증상이다. 어느 대상을 먼저 조사해야 하는지 고른다. \
     증상이 여러 대상을 암시하면 가장 직접적으로 지목된 대상을 고른다. \
     어느 대상도 좁혀지지 않으면 generic을 고른다."
        .to_string()
}

pub struct JevClient {
    http: reqwest::Client,
    api_key: String,
    model: String,
}

impl JevClient {
    /// `TYPESAFE_API_KEY`에서 키를 읽는다. 없으면 이 비교군을 실행할 수 없다.
    pub fn from_env(model: &str) -> Result<Self> {
        let api_key = std::env::var("TYPESAFE_API_KEY")
            .context("TYPESAFE_API_KEY가 설정돼 있지 않습니다 — jev 비교군을 실행할 수 없습니다")?;
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

    pub async fn categorize(&self, symptom: &str) -> ArmOutcome {
        let started = Instant::now();
        let body = json!({
            "state": symptom,
            "model": self.model,
            "questions": {
                QUESTION_ID: {
                    "type": "choice",
                    "instructions": instructions(),
                    "criteria": criteria(),
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
                    // 재시도해도 시도 수와 지연은 합산한다 — 실패를 싸게 보이게 하지 않는다.
                    let backoff = BASE_BACKOFF_MS * 2u64.pow(attempts - 1);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
                Err(SendError::Permanent(msg)) => {
                    return ArmOutcome::failed(msg, attempts, started.elapsed().as_millis() as u64)
                }
            }
        }
        ArmOutcome::failed(
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
    /// 다시 보내면 달라질 수 있다 — 속도 제한, 과부하, 전송 오류.
    Retryable(String),
    /// 다시 보내도 같다 — 키 오류, 요청 검증 실패.
    Permanent(String),
}

/// 응답에서 범주와 부수 정보를 꺼낸다.
///
/// 목록 밖 값은 실패로 센다. 원문은 버리지 않고 남긴다 — 무엇을 만들어냈는지가 곧 한계 보고다.
fn parse_answer(json: &serde_json::Value, attempts: u32, latency_ms: u64) -> ArmOutcome {
    let Some(answer) = json.pointer(&format!("/answers/{QUESTION_ID}")) else {
        return ArmOutcome::failed("응답에 answers가 없습니다", attempts, latency_ms);
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
    let category = raw
        .as_deref()
        .filter(|c| DIAGNOSE_CATEGORIES.contains(c))
        .map(str::to_string);
    let error = if category.is_none() {
        Some(match &raw {
            Some(r) => format!("목록 밖 범주: {r}"),
            None => "응답에 choice가 없습니다".to_string(),
        })
    } else {
        None
    };

    ArmOutcome {
        category,
        raw_category: raw,
        confidence: answer.get("confidence").and_then(serde_json::Value::as_f64),
        probabilities,
        input_tokens,
        output_tokens,
        attempts,
        latency_ms,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn criteria_cover_exactly_the_known_categories() {
        // 범주 하나가 빠지면 모델은 그 답을 낼 수 없고, 그 범주의 사례는 구조적으로 전부 틀린다.
        let c = criteria();
        assert_eq!(c.len(), DIAGNOSE_CATEGORIES.len());
        for cat in DIAGNOSE_CATEGORIES {
            assert!(c.contains_key(cat), "criteria에 {cat}이 없습니다");
        }
    }

    #[test]
    fn a_known_choice_is_accepted() {
        let json = json!({
            "answers": { "category": {
                "type": "choice",
                "choice": "network",
                "probabilities": { "network": 0.8, "cpu": 0.2 },
                "confidence": 0.74
            }},
            "usage": { "input_tokens": 412, "output_tokens": 0 }
        });
        let out = parse_answer(&json, 1, 120);
        assert_eq!(out.category.as_deref(), Some("network"));
        assert_eq!(out.confidence, Some(0.74));
        assert_eq!(out.input_tokens, Some(412));
        assert!(out.error.is_none());
    }

    #[test]
    fn an_unknown_choice_counts_as_failure_but_keeps_the_raw_value() {
        // 목록 밖 값을 조용히 generic으로 바꾸면, 모델이 계약을 어긴 사실이 지표에서 사라진다.
        let json = json!({ "answers": { "category": { "choice": "gpu" } } });
        let out = parse_answer(&json, 1, 90);
        assert!(out.is_failure());
        assert_eq!(out.raw_category.as_deref(), Some("gpu"));
        assert!(out.error.unwrap().contains("gpu"));
    }

    #[test]
    fn a_missing_answer_is_a_failure() {
        let out = parse_answer(&json!({ "usage": {} }), 2, 300);
        assert!(out.is_failure());
        assert_eq!(out.attempts, 2);
        assert_eq!(out.latency_ms, 300);
    }
}
