//! 현재 production 경로 그대로: LLM에게 `aic-followup` 블록을 요청하고 파싱한다.
//!
//! Jev 비교군과 같은 증거·같은 게이트를 쓴다. 프롬프트는 production의
//! `build_diagnose_prompt_followup`을 그대로 부르므로 "지금 사용자가 겪는 동작"을 잰다.

use std::time::Instant;

use aic_client::agent::diagnose::{
    build_diagnose_prompt_followup, extract_followup_block, resolve_followup_line,
};
use aic_client::config::ConfigManager;
use aic_client::llm_dispatcher::LlmDispatcher;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LlmFollowupOutcome {
    /// 블록에서 뽑은 줄 전부(게이트 전). 블록이 없으면 빈 벡터 = "follow-up 불필요"로 본다.
    pub lines: Vec<String>,
    /// 게이트를 통과한 줄.
    pub accepted_lines: Vec<String>,
    /// 게이트가 거부한 줄과 사유.
    pub rejected: Vec<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

pub struct LlmFollowupArm {
    dispatcher: LlmDispatcher,
    identity: String,
}

impl LlmFollowupArm {
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

    pub async fn choose(&self, symptom: Option<&str>, evidence: &str) -> LlmFollowupOutcome {
        let prompt = build_diagnose_prompt_followup(symptom, evidence);
        let started = Instant::now();
        let result = self.dispatcher.send(&prompt).await;
        let latency_ms = started.elapsed().as_millis() as u64;
        let usage = self.dispatcher.last_usage();
        let mut out = LlmFollowupOutcome {
            input_tokens: usage.map(|u| u.input_tokens),
            output_tokens: usage.map(|u| u.output_tokens),
            latency_ms,
            ..Default::default()
        };
        let text = match result {
            Ok(t) => t,
            Err(e) => {
                out.error = Some(e.to_string());
                return out;
            }
        };
        out.lines = extract_followup_block(&text).unwrap_or_default();
        for line in &out.lines {
            match resolve_followup_line(line, evidence) {
                Ok(_) => out.accepted_lines.push(line.clone()),
                Err(reason) => out.rejected.push(format!("{line} — {reason}")),
            }
        }
        out
    }
}
