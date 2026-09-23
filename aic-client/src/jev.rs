//! 분류 전용 모델(TypeSafe Jev) 클라이언트 — 닫힌 선택지에서 하나를 고른다.
//!
//! 생성형 LLM과 쓰임이 다르다. 문장을 만들지 않고 주어진 선택지 중 하나를 돌려주므로, 목록 밖 값이
//! 나올 수 없고 같은 입력에 같은 답을 낸다. 명령 실패의 원인 계열을 가리는 데 이 성질이 맞는다 —
//! 필요한 것은 설명이 아니라 "어느 계열인가" 하나이고, 그 답이 곧 다음 조치를 정한다.
//!
//! 도입 근거는 `docs/ERROR-CAUSE-EVALUATION.md`의 측정이다. 출력을 보지 않고 라벨한 64건에서
//! 키워드 규칙 0.672, Jev 0.906, LLM 0.922였고(Jev와 LLM의 차이는 유의하지 않다) Jev는 p50 246ms,
//! 호출당 약 960 토큰이었다.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};

use crate::agent::debug::adbg;

/// 응답 파싱 결과. 목록 밖 값이나 오류는 `None`이며, 호출자는 분류 없이 진행한다.
#[derive(Debug, Clone, PartialEq)]
pub struct Choice {
    pub value: String,
    pub confidence: Option<f64>,
}

pub fn log_criteria() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "connectivity_or_dependency",
            "네트워크 연결 또는 외부 의존성 문제",
        ),
        ("service_crash", "서비스 또는 프로세스 충돌 및 종료"),
        ("resource_pressure", "CPU, 메모리 또는 기타 자원 부족"),
        ("storage_or_io", "저장 장치 또는 입출력 문제"),
        ("permission_or_auth", "권한 또는 인증 문제"),
        ("configuration_or_input", "설정 또는 입력 문제"),
        ("no_clear_cause", "명확한 원인 없음"),
    ])
}

pub async fn choose_log(cfg: &aic_common::JevConfig, excerpt: &str) -> Option<Choice> {
    let criteria = log_criteria();
    choose(
        cfg,
        excerpt,
        "Choose the one dominant cause category for this bounded log excerpt.",
        &criteria,
    )
    .await
}

/// 요청 본문. 순수 함수라 네트워크 없이 테스트한다.
pub fn build_body(
    model: &str,
    state: &str,
    question: &str,
    criteria: &BTreeMap<&str, &str>,
) -> Value {
    let map: serde_json::Map<String, Value> = criteria
        .iter()
        .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
        .collect();
    json!({
        "state": state,
        "model": model,
        "questions": { "q": { "type": "choice", "instructions": question, "criteria": map } },
    })
}

/// 응답에서 선택지를 꺼낸다. **선택지 목록 안의 값만** 통과시킨다 — 목록 밖 값을 그대로 받으면
/// 호출자가 존재하지 않는 범주로 분기한다.
pub fn parse_choice(json: &Value, allowed: &BTreeMap<&str, &str>) -> Option<Choice> {
    let a = json.pointer("/answers/q")?;
    let value = a.get("choice")?.as_str()?.to_string();
    allowed.contains_key(value.as_str()).then(|| Choice {
        value,
        confidence: a.get("confidence").and_then(Value::as_f64),
    })
}

/// 설정에서 (endpoint, api_key)를 푼다. 키는 config의 평문/`keychain:` 참조가 우선이고, 없으면
/// `JEV_API_KEY` 환경변수를 본다. 키가 없으면 `None` — 호출자는 분류를 건너뛴다.
fn credentials(cfg: &aic_common::JevConfig) -> Option<(String, String)> {
    let key = match cfg
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => crate::keychain::resolve(raw).ok()?,
        None => std::env::var("JEV_API_KEY").ok()?,
    };
    (!key.trim().is_empty()).then(|| (cfg.endpoint.clone(), key))
}

/// 선택지 중 하나를 고른다. 실패·시간 초과·미설정은 전부 `None`이다.
///
/// 오류를 삼키는 이유: 분류는 부가 정보이지 분석의 전제가 아니다. 외부 서비스가 느리거나 죽었다고
/// 로컬 에러 분석까지 막으면 사용자는 아무 답도 받지 못한다. 분류가 붙지 않은 것은 호출자가
/// 반환값으로 알 수 있고, 사유는 `AIC_DEBUG` 로그에 남는다.
pub async fn choose(
    cfg: &aic_common::JevConfig,
    state: &str,
    question: &str,
    criteria: &BTreeMap<&str, &str>,
) -> Option<Choice> {
    if !cfg.enabled {
        return None;
    }
    let (endpoint, api_key) = credentials(cfg)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs.max(1)))
        .build()
        .ok()?;
    let body = build_body(&cfg.model, state, question, criteria);
    let resp = match client
        .post(&endpoint)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            adbg!("jev 요청 실패 · {e}");
            return None;
        }
    };
    if !resp.status().is_success() {
        adbg!("jev HTTP {}", resp.status().as_u16());
        return None;
    }
    let value: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            adbg!("jev 응답 파싱 실패 · {e}");
            return None;
        }
    };
    let picked = parse_choice(&value, criteria);
    if picked.is_none() {
        adbg!("jev 선택지 밖 응답");
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn criteria() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([("network", "연결 실패"), ("usage", "사용법 오류")])
    }

    #[test]
    fn the_body_carries_every_option_and_the_state() {
        let b = build_body("jev-latest", "$ curl x\nexit=7", "고르시오", &criteria());
        assert_eq!(b["model"], "jev-latest");
        assert_eq!(b["state"], "$ curl x\nexit=7");
        let c = b["questions"]["q"]["criteria"].as_object().unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c["network"], "연결 실패");
    }

    #[test]
    fn an_answer_outside_the_options_is_rejected() {
        // 목록 밖 값을 통과시키면 호출자가 없는 범주로 분기한다.
        let v = json!({"answers": {"q": {"choice": "vibes", "confidence": 0.9}}});
        assert!(parse_choice(&v, &criteria()).is_none());
    }

    #[test]
    fn a_valid_choice_keeps_its_confidence() {
        let v = json!({"answers": {"q": {"choice": "network", "confidence": 0.82}}});
        let c = parse_choice(&v, &criteria()).expect("선택됨");
        assert_eq!(c.value, "network");
        assert_eq!(c.confidence, Some(0.82));
    }

    #[test]
    fn a_malformed_response_is_none_not_a_panic() {
        assert!(parse_choice(&json!({}), &criteria()).is_none());
        assert!(parse_choice(&json!({"answers": {"q": {}}}), &criteria()).is_none());
    }

    #[tokio::test]
    async fn a_disabled_config_never_calls_out() {
        // 기본이 비활성이다. 켜지 않은 사용자의 명령 출력이 밖으로 나가면 안 된다.
        let cfg = aic_common::JevConfig::default();
        assert!(!cfg.enabled);
        assert!(choose(&cfg, "state", "q", &criteria()).await.is_none());
    }

    #[tokio::test]
    async fn an_enabled_config_without_a_key_is_skipped() {
        let cfg = aic_common::JevConfig {
            enabled: true,
            api_key: Some("   ".to_string()),
            ..Default::default()
        };
        assert!(choose(&cfg, "state", "q", &criteria()).await.is_none());
    }

    #[test]
    fn log_taxonomy_is_closed_and_has_no_severity_or_action() {
        let criteria = log_criteria();
        assert_eq!(criteria.len(), 7);
        assert!(criteria.contains_key("connectivity_or_dependency"));
        assert!(criteria.contains_key("service_crash"));
        assert!(criteria.contains_key("resource_pressure"));
        assert!(criteria.contains_key("storage_or_io"));
        assert!(criteria.contains_key("permission_or_auth"));
        assert!(criteria.contains_key("configuration_or_input"));
        assert!(criteria.contains_key("no_clear_cause"));
        assert!(!criteria.keys().any(|key| key.contains("severity")));
        assert!(!criteria.keys().any(|key| key.contains("command")));
    }

    #[test]
    fn log_choice_keeps_confidence_and_rejects_outside_taxonomy() {
        let criteria = log_criteria();
        let valid = json!({
            "answers": {"q": {"choice": "resource_pressure", "confidence": 0.73}}
        });
        let choice = parse_choice(&valid, &criteria).expect("고정 로그 taxonomy 선택");
        assert_eq!(choice.value, "resource_pressure");
        assert_eq!(choice.confidence, Some(0.73));
        let outside = json!({"answers": {"q": {"choice": "critical"}}});
        assert!(parse_choice(&outside, &criteria).is_none());
    }

    #[tokio::test]
    async fn disabled_log_classification_is_unavailable_without_network() {
        let cfg = aic_common::JevConfig::default();
        assert!(choose_log(&cfg, "redacted log").await.is_none());
    }
}
