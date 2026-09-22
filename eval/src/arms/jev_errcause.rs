//! Jev로 명령 실패의 원인 범주를 고른다.
//!
//! 질문은 하나다: 10개 범주 중 하나를 고르는 Choice. follow-up 실험과 달리 인자 질문이 없다 —
//! 여기서 필요한 것은 범주뿐이고, 그 범주가 곧 다음 조치를 정한다.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

const QUESTION: &str = "cause";
pub const QUESTION_VERSION: &str = "errcause-v1";
const MAX_ATTEMPTS: u32 = 4;
const BASE_BACKOFF_MS: u64 = 500;
/// 컨텍스트 한계 안에 보수적으로 두는 예산. 실패 출력 하나는 이보다 훨씬 작다.
const STATE_TOKEN_BUDGET: u64 = 24_000;
const CONSERVATIVE_BYTES_PER_TOKEN: f64 = 2.0;

const INSTRUCTIONS: &str = "터미널에서 실행한 명령이 실패했다. 명령과 종료 코드와 출력을 보고 \
실패의 **원인 계열**을 하나 고른다. 기준은 표면에 나온 낱말이 아니라 **다음에 해야 할 조치**다 — \
같은 낱말이라도 조치가 다르면 다른 범주다.";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CauseOutcome {
    pub category: Option<String>,
    /// 선택지 밖 값을 받았을 때의 원문. 무엇을 만들어냈는지 남겨야 한계를 보고할 수 있다.
    pub raw_category: Option<String>,
    pub confidence: Option<f64>,
    pub probabilities: Option<BTreeMap<String, f64>>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub resolved_model: Option<String>,
    pub attempts: u32,
    pub latency_ms: u64,
    pub oversize: bool,
    pub error: Option<String>,
}

impl CauseOutcome {
    fn failed(msg: impl Into<String>, attempts: u32, latency_ms: u64) -> Self {
        Self {
            attempts,
            latency_ms,
            error: Some(msg.into()),
            ..Default::default()
        }
    }

    /// 확률 상위 `n`개. 1등이 틀렸을 때 정답이 몇 번째에 있었는지 보려고 쓴다.
    pub fn top_n(&self, n: usize) -> Vec<String> {
        let Some(p) = &self.probabilities else {
            return self.category.iter().cloned().collect();
        };
        let mut ranked: Vec<(&String, &f64)> = p.iter().collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked.into_iter().take(n).map(|(k, _)| k.clone()).collect()
    }
}

pub fn build_questions(categories: &BTreeMap<String, String>) -> Value {
    let criteria: serde_json::Map<String, Value> = categories
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    json!({
        QUESTION: {
            "type": "choice",
            "instructions": INSTRUCTIONS,
            "criteria": criteria,
        }
    })
}

pub fn parse_answer(
    json: &Value,
    categories: &BTreeMap<String, String>,
    attempts: u32,
    latency_ms: u64,
) -> CauseOutcome {
    let Some(answers) = json.get("answers").and_then(Value::as_object) else {
        return CauseOutcome::failed("응답에 answers가 없습니다", attempts, latency_ms);
    };
    let Some(a) = answers.get(QUESTION) else {
        return CauseOutcome::failed("cause 답이 없습니다", attempts, latency_ms);
    };
    let raw = a.get("choice").and_then(Value::as_str).map(str::to_string);
    let mut out = CauseOutcome {
        raw_category: raw.clone(),
        confidence: a.get("confidence").and_then(Value::as_f64),
        probabilities: a.get("probabilities").and_then(Value::as_object).map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_f64().map(|f| (k.clone(), f)))
                .collect()
        }),
        input_tokens: json.pointer("/usage/input_tokens").and_then(Value::as_u64),
        output_tokens: json.pointer("/usage/output_tokens").and_then(Value::as_u64),
        resolved_model: json
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        attempts,
        latency_ms,
        ..Default::default()
    };
    match raw {
        Some(c) if categories.contains_key(&c) => out.category = Some(c),
        Some(c) => out.error = Some(format!("목록 밖 범주: {c}")),
        None => out.error = Some("choice가 없습니다".into()),
    }
    out
}

pub struct CauseClient {
    http: reqwest::Client,
    endpoint: String,
    api_key: String,
    model: String,
}

enum SendError {
    Retryable(String),
    Permanent(String),
}

impl CauseClient {
    pub fn from_env(model: &str) -> Result<Self> {
        let (endpoint, api_key) = crate::arms::jev_env("errcause")?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("HTTP 클라이언트 생성 실패")?;
        Ok(Self {
            http,
            endpoint,
            api_key,
            model: model.to_string(),
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn endpoint_host(&self) -> String {
        crate::arms::endpoint_host(&self.endpoint)
    }

    pub async fn classify(
        &self,
        input: &str,
        categories: &BTreeMap<String, String>,
    ) -> CauseOutcome {
        if (input.len() as f64 / CONSERVATIVE_BYTES_PER_TOKEN).ceil() as u64 > STATE_TOKEN_BUDGET {
            return CauseOutcome {
                oversize: true,
                error: Some("state가 토큰 예산을 넘어 보내지 않음".into()),
                ..Default::default()
            };
        }
        let started = Instant::now();
        let body = json!({
            "state": input,
            "model": self.model,
            "questions": build_questions(categories),
        });
        let mut attempts = 0;
        let mut last = String::new();
        while attempts < MAX_ATTEMPTS {
            attempts += 1;
            match self.send_once(&body).await {
                Ok(v) => {
                    return parse_answer(
                        &v,
                        categories,
                        attempts,
                        started.elapsed().as_millis() as u64,
                    )
                }
                Err(SendError::Retryable(m)) => {
                    last = m;
                    tokio::time::sleep(Duration::from_millis(
                        BASE_BACKOFF_MS * 2u64.pow(attempts - 1),
                    ))
                    .await;
                }
                Err(SendError::Permanent(m)) => {
                    return CauseOutcome::failed(m, attempts, started.elapsed().as_millis() as u64)
                }
            }
        }
        CauseOutcome::failed(
            format!("{MAX_ATTEMPTS}회 재시도 후 실패: {last}"),
            attempts,
            started.elapsed().as_millis() as u64,
        )
    }

    async fn send_once(&self, body: &Value) -> Result<Value, SendError> {
        let resp = self
            .http
            .post(&self.endpoint)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cats() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("network".to_string(), "연결 실패".to_string()),
            ("usage".to_string(), "사용법 오류".to_string()),
        ])
    }

    #[test]
    fn every_category_becomes_a_choice_option() {
        let q = build_questions(&cats());
        let c = q["cause"]["criteria"].as_object().unwrap();
        assert_eq!(c.len(), 2);
        assert!(c.contains_key("network") && c.contains_key("usage"));
    }

    #[test]
    fn an_answer_outside_the_list_is_a_failure_that_keeps_the_raw_value() {
        let v = json!({"answers": {"cause": {"choice": "vibes"}}});
        let o = parse_answer(&v, &cats(), 1, 10);
        assert!(o.error.is_some());
        assert_eq!(o.raw_category.as_deref(), Some("vibes"));
        assert!(o.category.is_none());
    }

    #[test]
    fn probabilities_rank_the_alternatives() {
        let v = json!({"answers": {"cause": {"choice": "network", "confidence": 0.7,
            "probabilities": {"network": 0.7, "usage": 0.3}}},
            "usage": {"input_tokens": 200, "output_tokens": 5}});
        let o = parse_answer(&v, &cats(), 1, 10);
        assert_eq!(o.category.as_deref(), Some("network"));
        assert_eq!(o.top_n(2), vec!["network", "usage"]);
        assert_eq!(o.input_tokens, Some(200));
    }
}
