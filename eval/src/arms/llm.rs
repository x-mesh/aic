//! 설정된 LLM provider에게 같은 선택지를 주고 범주를 받는다.
//!
//! 저장소에 JSON schema를 강제하는 경로가 없어 tool calling을 쓴다. 범주를 `enum`으로 제한한
//! tool 하나만 노출하므로, 모델이 고를 수 있는 값의 집합이 Jev의 Choice와 같다.
//!
//! 프롬프트로 JSON을 요청하고 파싱 실패 시 폴백하는 방식은 쓰지 않는다. 그 폴백이 곧 측정
//! 대상인 오류율을 가린다.

use std::time::Instant;

use aic_client::agent::diagnose::DIAGNOSE_CATEGORIES;
use aic_client::agent::types::{ChatMessage, ChatResponse, ToolSpec};
use aic_client::config::ConfigManager;
use aic_client::llm_dispatcher::LlmDispatcher;
use anyhow::{Context, Result};
use serde_json::json;

use super::ArmOutcome;

/// 질문 버전. system 지시나 tool 설명을 고치면 올린다.
pub const QUESTION_VERSION: &str = "v1";

const SYSTEM: &str = "당신은 호스트 진단을 돕는다. 운영자가 관측한 증상을 읽고, \
어느 대상을 먼저 조사해야 하는지 하나 고른다. 반드시 select_diagnosis_category 도구를 호출한다. \
증상이 여러 대상을 암시하면 가장 직접적으로 지목된 대상을 고른다. \
어느 대상도 좁혀지지 않으면 generic을 고른다.";

fn tool_spec() -> ToolSpec {
    ToolSpec {
        name: "select_diagnosis_category",
        description: "증상이 가리키는 조사 대상을 하나 고른다.",
        parameters: json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": DIAGNOSE_CATEGORIES,
                    "description": "cpu=처리 능력, memory=메모리, disk=저장 장치, \
                                    network=네트워크, process=특정 프로세스·서비스, \
                                    docker=Docker와 컨테이너, k8s=Kubernetes, \
                                    generic=좁힐 수 없음"
                }
            },
            "required": ["category"],
            "additionalProperties": false
        }),
    }
}

pub struct LlmArm {
    dispatcher: LlmDispatcher,
    provider: String,
    model: String,
}

impl LlmArm {
    /// 사용자의 `config.toml`에 설정된 provider를 쓰되 **모델 ID를 고정한다**.
    ///
    /// provider 기본 모델에 맡기면 그 값이 언제 바뀌었는지 결과만 보고는 알 수 없다. PRD가
    /// 평가 시작 전에 정확한 모델 ID를 고정하라고 요구하는 이유다. config에도 `--llm-model`에도
    /// 없으면 실행하지 않는다.
    pub fn from_config(model_override: Option<&str>) -> Result<Self> {
        let mut llm = ConfigManager::load()
            .context("config.toml을 읽지 못했습니다")?
            .llm;
        let provider = llm.default_provider.clone();
        let entry = llm
            .providers
            .get_mut(&provider)
            .with_context(|| format!("config.toml에 provider {provider}가 없습니다"))?;
        if let Some(m) = model_override {
            entry.model = Some(m.to_string());
        }
        let model = entry.model.clone().context(
            "모델 ID가 고정되지 않았습니다 — config.toml의 provider에 model을 적거나 \
             --llm-model로 지정하세요",
        )?;
        Ok(Self {
            dispatcher: LlmDispatcher::from_config(llm),
            provider,
            model,
        })
    }

    /// 결과에 기록할 식별자. provider와 모델을 함께 남긴다.
    pub fn identity(&self) -> String {
        format!("{}/{}", self.provider, self.model)
    }

    pub async fn categorize(&self, symptom: &str) -> ArmOutcome {
        let started = Instant::now();
        let messages = [
            ChatMessage::System(SYSTEM.to_string()),
            ChatMessage::User(symptom.to_string()),
        ];
        let tools = [tool_spec()];

        // 재시도는 dispatcher가 내부에서 하지 않는다(tool-calling 경로). 여기서도 하지 않는다 —
        // 실패율 자체가 측정 대상이고, 감추면 비교가 흐려진다.
        let result = self.dispatcher.send_messages(&messages, &tools).await;
        let latency_ms = started.elapsed().as_millis() as u64;
        let usage = self.dispatcher.last_usage();

        let mut outcome = match result {
            Ok(response) => parse_response(&response, 1, latency_ms),
            Err(e) => ArmOutcome::failed(e.to_string(), 1, latency_ms),
        };
        outcome.input_tokens = usage.map(|u| u.input_tokens);
        outcome.output_tokens = usage.map(|u| u.output_tokens);
        outcome
    }
}

fn parse_response(response: &ChatResponse, attempts: u32, latency_ms: u64) -> ArmOutcome {
    let calls = match response {
        ChatResponse::ToolCalls(calls) => calls,
        // 도구를 쓰지 않았다 = 계약 위반. 텍스트에서 범주를 긁어내면 다른 비교군보다 관대해진다.
        ChatResponse::Text(t) => {
            let head: String = t.chars().take(200).collect();
            return ArmOutcome {
                raw_category: Some(head.clone()),
                error: Some(format!("도구를 호출하지 않고 텍스트로 답했습니다: {head}")),
                attempts,
                latency_ms,
                ..Default::default()
            };
        }
    };
    let Some(call) = calls.first() else {
        return ArmOutcome::failed("tool_calls가 비어 있습니다", attempts, latency_ms);
    };
    let raw = serde_json::from_str::<serde_json::Value>(&call.arguments)
        .ok()
        .and_then(|v| {
            v.get("category")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
    let category = raw
        .as_deref()
        .filter(|c| DIAGNOSE_CATEGORIES.contains(c))
        .map(str::to_string);
    let error = if category.is_none() {
        Some(match &raw {
            Some(r) => format!("목록 밖 범주: {r}"),
            None => format!(
                "arguments에서 category를 찾지 못했습니다: {}",
                call.arguments
            ),
        })
    } else {
        None
    };
    ArmOutcome {
        category,
        raw_category: raw,
        attempts,
        latency_ms,
        error,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_client::agent::types::ToolCall;

    fn call(arguments: &str) -> ChatResponse {
        ChatResponse::ToolCalls(vec![ToolCall {
            id: "c1".into(),
            name: "select_diagnosis_category".into(),
            arguments: arguments.into(),
        }])
    }

    #[test]
    fn the_tool_enum_matches_the_known_categories() {
        // enum이 실제 목록과 갈리면 모델은 고를 수 없는 값을 제안받거나, 목록 밖 값을 합법적으로
        // 돌려준다. 둘 다 불변 조건을 깬다.
        let spec = tool_spec();
        let values = spec.parameters["properties"]["category"]["enum"]
            .as_array()
            .expect("enum 배열");
        let names: Vec<&str> = values.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(names, DIAGNOSE_CATEGORIES.to_vec());
    }

    #[test]
    fn a_known_category_is_accepted() {
        let out = parse_response(&call(r#"{"category":"network"}"#), 1, 200);
        assert_eq!(out.category.as_deref(), Some("network"));
        assert!(out.error.is_none());
    }

    #[test]
    fn an_unknown_category_counts_as_failure() {
        let out = parse_response(&call(r#"{"category":"gpu"}"#), 1, 200);
        assert!(out.is_failure());
        assert_eq!(out.raw_category.as_deref(), Some("gpu"));
    }

    #[test]
    fn malformed_arguments_are_a_failure() {
        let out = parse_response(&call("not json"), 1, 200);
        assert!(out.is_failure());
        assert!(out.error.unwrap().contains("category"));
    }

    #[test]
    fn a_text_answer_is_a_failure_not_a_salvage() {
        // 텍스트에서 "network"를 주워 담으면 이 비교군만 두 번 기회를 갖는다.
        let out = parse_response(
            &ChatResponse::Text("network 문제로 보입니다".into()),
            1,
            200,
        );
        assert!(out.is_failure());
        assert!(out.error.unwrap().contains("도구를 호출하지 않고"));
    }
}
