//! LLM 비교군 — Jev와 **같은 입력·같은 선택지**로 원인 범주를 묻는다.
//!
//! production에는 이 분류 단계가 없어서(실패는 결정적 테이블을 거쳐 바로 설명 생성으로 간다) 가져다
//! 쓸 프롬프트가 없다. 그래서 Jev 질문과 같은 지시문·같은 범주 설명을 그대로 프롬프트로 만든다.
//! 비교의 목적이 "같은 문제를 누가 더 싸고 빠르게 푸는가"이므로 정보량을 맞춰야 한다.

use std::collections::BTreeMap;
use std::time::Instant;

use aic_client::config::ConfigManager;
use aic_client::llm_dispatcher::LlmDispatcher;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LlmCauseOutcome {
    pub category: Option<String>,
    /// 목록 밖 값을 냈을 때의 원문(앞부분). 형식 준수 실패를 실패로 세기 위해 남긴다.
    pub raw_response: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

/// Jev 질문과 같은 내용을 텍스트 프롬프트로 편다. 순수 함수라 네트워크 없이 테스트한다.
pub fn build_prompt(input: &str, categories: &BTreeMap<String, String>) -> String {
    let list = categories
        .iter()
        .map(|(k, v)| format!("- {k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "터미널에서 실행한 명령이 실패했다. 명령과 종료 코드와 출력을 보고 실패의 **원인 계열**을 \
하나 고른다. 기준은 표면에 나온 낱말이 아니라 **다음에 해야 할 조치**다 — 같은 낱말이라도 조치가 \
다르면 다른 범주다.\n\n\
# 범주\n{list}\n\n\
# 실패\n{input}\n\n\
# 형식\n범주 id 하나만 출력한다. 설명·따옴표·문장부호를 붙이지 않는다."
    )
}

/// 응답에서 범주를 꺼낸다. 모델이 설명을 덧붙이는 일이 흔하므로 목록의 id가 토큰으로 등장하는지
/// 본다. 여러 개가 나오면 첫 번째를 쓴다 — "골라라"에 여러 개를 낸 것은 형식 위반이지만 첫 답을
/// 고른 것으로 보는 편이 실패로 버리는 것보다 모델에 유리하고, 그래야 비교가 보수적이다.
pub fn parse_response(text: &str, categories: &BTreeMap<String, String>) -> Option<String> {
    let low = text.to_lowercase();
    let mut best: Option<(usize, &String)> = None;
    for id in categories.keys() {
        if let Some(pos) = low.find(id.as_str()) {
            if best.is_none_or(|(p, _)| pos < p) {
                best = Some((pos, id));
            }
        }
    }
    best.map(|(_, id)| id.clone())
}

pub struct LlmCauseArm {
    dispatcher: LlmDispatcher,
    identity: String,
}

impl LlmCauseArm {
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
        let model = entry
            .model
            .clone()
            .context("모델 ID가 고정되지 않았습니다 — --llm-model로 지정하세요")?;
        Ok(Self {
            dispatcher: LlmDispatcher::from_config(llm),
            identity: format!("{provider}/{model}"),
        })
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub async fn classify(
        &self,
        input: &str,
        categories: &BTreeMap<String, String>,
    ) -> LlmCauseOutcome {
        let prompt = build_prompt(input, categories);
        let started = Instant::now();
        let result = self.dispatcher.send(&prompt).await;
        let latency_ms = started.elapsed().as_millis() as u64;
        let usage = self.dispatcher.last_usage();
        let mut out = LlmCauseOutcome {
            input_tokens: usage.map(|u| u.input_tokens),
            output_tokens: usage.map(|u| u.output_tokens),
            latency_ms,
            ..Default::default()
        };
        match result {
            Ok(text) => {
                out.category = parse_response(&text, categories);
                if out.category.is_none() {
                    out.raw_response = Some(text.chars().take(200).collect());
                    out.error = Some("응답에서 목록 안의 범주를 찾지 못했습니다".into());
                }
            }
            Err(e) => out.error = Some(e.to_string()),
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cats() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("network".to_string(), "연결 실패".to_string()),
            ("not_found".to_string(), "대상 없음".to_string()),
        ])
    }

    #[test]
    fn the_prompt_lists_every_category_and_the_failure() {
        let p = build_prompt("$ curl x\nexit_code=7", &cats());
        assert!(p.contains("- network: 연결 실패"));
        assert!(p.contains("- not_found: 대상 없음"));
        assert!(p.contains("exit_code=7"));
    }

    #[test]
    fn a_bare_id_and_a_chatty_answer_both_parse() {
        assert_eq!(
            parse_response("network", &cats()).as_deref(),
            Some("network")
        );
        assert_eq!(
            parse_response("이 실패는 network 계열로 보입니다.", &cats()).as_deref(),
            Some("network")
        );
    }

    #[test]
    fn when_several_ids_appear_the_first_one_wins() {
        // "골라라"에 둘을 낸 것은 형식 위반이지만, 첫 답으로 세는 편이 모델에 유리하고 비교가
        // 보수적이 된다.
        assert_eq!(
            parse_response("not_found 또는 network", &cats()).as_deref(),
            Some("not_found")
        );
    }

    #[test]
    fn an_answer_with_no_known_id_is_none() {
        assert!(parse_response("잘 모르겠습니다", &cats()).is_none());
    }
}
