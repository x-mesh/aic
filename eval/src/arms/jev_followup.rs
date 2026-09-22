//! Jev로 follow-up probe를 고른다.
//!
//! 한 요청에 질문을 여러 개 싣는다. `template`은 어느 템플릿을 돌릴지(또는 불필요)의 Choice이고,
//! `arg:<template>`은 그 템플릿의 인자를 후보 중에서 고르는 Choice다. Jev는 한 forward pass로
//! 전부 답하므로 왕복은 한 번이다. 후보는 증거의 공백 토큰에서 결정적으로 뽑았으므로 무엇을 고르든
//! 게이트를 통과한다 — Jev는 생성하지 않고 고르기만 한다.
//!
//! v3(2라운드): 후보가 있는 템플릿만 메뉴에 올린다. 후보는 문제가 드러난 행으로 좁혀져 있으므로
//! (`followup::candidates`), Jev의 몫은 "어느 템플릿을(또는 none을) 고르는가"다. 수치를 한도와 견주는
//! 판단은 스캐너가 이미 했다.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use aic_client::agent::probes::{followup_templates, probe_descriptions, probe_exists};
use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::followup::{candidates, template_ids};

const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
const TEMPLATE_QUESTION: &str = "template";
/// "follow-up이 필요 없다" 선택지. 템플릿 id와 겹치지 않는 이름이어야 한다.
pub const NONE_CHOICE: &str = "none";
/// 인자 질문의 "이 중 대상이 없다" 선택지. 후보가 하나뿐일 때도 Choice가 두 선택지를 갖게 한다.
const NO_TARGET: &str = "__none__";
pub const QUESTION_VERSION: &str = "v3";
const MAX_ATTEMPTS: u32 = 4;
const BASE_BACKOFF_MS: u64 = 500;
/// 컨텍스트 한계(state + 가장 긴 질문 32k) 안에 보수적으로 두는 예산.
const STATE_TOKEN_BUDGET: u64 = 24_000;
const CONSERVATIVE_BYTES_PER_TOKEN: f64 = 2.0;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FollowupOutcome {
    /// 조합한 follow-up 줄(`<template> <arg>`). `None`이면 "불필요"거나 실패다 — `error`로 구분한다.
    pub line: Option<String>,
    pub template: Option<String>,
    pub raw_template: Option<String>,
    pub arg: Option<String>,
    pub template_confidence: Option<f64>,
    pub template_probabilities: Option<BTreeMap<String, f64>>,
    pub arg_confidence: Option<f64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub attempts: u32,
    pub latency_ms: u64,
    pub oversize: bool,
    pub error: Option<String>,
}

impl FollowupOutcome {
    fn failed(msg: impl Into<String>, attempts: u32, latency_ms: u64) -> Self {
        Self {
            attempts,
            latency_ms,
            error: Some(msg.into()),
            ..Default::default()
        }
    }

    pub fn is_failure(&self) -> bool {
        self.error.is_some()
    }
}

/// 상위 N개 템플릿(확률 순). LLM이 최대 3줄을 내므로 같은 폭으로 비교하기 위해 쓴다.
pub fn top_templates(outcome: &FollowupOutcome, n: usize) -> Vec<String> {
    let Some(p) = &outcome.template_probabilities else {
        return outcome.template.iter().cloned().collect();
    };
    let mut ranked: Vec<(&String, &f64)> = p.iter().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.into_iter().take(n).map(|(k, _)| k.clone()).collect()
}

pub fn build_state(evidence: &str) -> String {
    aic_common::redaction::redact(evidence).0
}

fn is_oversize(state: &str) -> bool {
    (state.len() as f64 / CONSERVATIVE_BYTES_PER_TOKEN).ceil() as u64 > STATE_TOKEN_BUDGET
}

/// 요청 본문. 순수 함수라 네트워크 없이 테스트한다.
pub fn build_questions(evidence: &str) -> Value {
    let mut template_criteria: BTreeMap<String, String> = BTreeMap::new();
    template_criteria.insert(
        NONE_CHOICE.to_string(),
        "추가로 돌릴 probe가 없다. 1차 증거만으로 충분하거나, 아래 어느 템플릿도 지금 증거가 가리키는 대상에 맞지 않는다.".to_string(),
    );
    // catalog probe 59개는 인자가 없으니 늘 올린다 — 템플릿만 주면 Jev는 "넓은 probe를 하나 더
    // 돌린다"는 선택을 할 수 없어 LLM과 비교가 기울어진다. 인자형 템플릿은 후보가 있는 것만 올린다:
    // 후보 없는 템플릿은 골라도 실행할 수 없고, 1라운드에서 그 자리를 정상 행으로 채우는 오답이 나왔다.
    let cands = candidates(evidence);
    for (id, desc) in followup_templates() {
        if cands.contains_key(id) {
            template_criteria.insert(id.to_string(), format!("[인자 필요] {desc}"));
        }
    }
    for (id, desc) in probe_descriptions() {
        template_criteria.insert(id.to_string(), desc.to_string());
    }
    let mut questions = serde_json::Map::new();
    questions.insert(
        TEMPLATE_QUESTION.to_string(),
        json!({
            "type": "choice",
            "instructions": "호스트 1차 진단 증거다. 원인을 좁히기 위해 다음에 돌릴 read-only follow-up probe를 하나 고른다. 증거에 문제가 드러난 대상(실패한 unit, fd를 많이 쓰는 PID, 재시작하는 컨테이너, NotReady pod 등)이 있으면 그 대상을 더 깊이 보는 템플릿을 고르고, 그런 대상이 없으면 none을 고른다.",
            "criteria": template_criteria,
        }),
    );
    for (tmpl, cands) in cands {
        let mut criteria: BTreeMap<String, String> = BTreeMap::new();
        criteria.insert(NO_TARGET.to_string(), "이 중에는 대상이 없다".to_string());
        for c in &cands {
            criteria.insert(c.clone(), c.clone());
        }
        questions.insert(
            format!("arg:{tmpl}"),
            json!({
                "type": "choice",
                "instructions": format!("{tmpl}을 돌린다면 증거에서 가장 문제가 드러난 대상은 어느 것인가."),
                "criteria": criteria,
            }),
        );
    }
    Value::Object(questions)
}

/// 응답에서 템플릿과 인자를 조합한다. 목록 밖 값은 실패로 세고 원문을 남긴다.
pub fn parse_answer(
    json: &Value,
    evidence: &str,
    attempts: u32,
    latency_ms: u64,
) -> FollowupOutcome {
    let Some(answers) = json.get("answers").and_then(Value::as_object) else {
        return FollowupOutcome::failed("응답에 answers가 없습니다", attempts, latency_ms);
    };
    let Some(t) = answers.get(TEMPLATE_QUESTION) else {
        return FollowupOutcome::failed("template 답이 없습니다", attempts, latency_ms);
    };
    let raw = t.get("choice").and_then(Value::as_str).map(str::to_string);
    let probs = t.get("probabilities").and_then(Value::as_object).map(|m| {
        m.iter()
            .filter_map(|(k, v)| v.as_f64().map(|f| (k.clone(), f)))
            .collect::<BTreeMap<String, f64>>()
    });
    let mut out = FollowupOutcome {
        raw_template: raw.clone(),
        template_confidence: t.get("confidence").and_then(Value::as_f64),
        template_probabilities: probs,
        input_tokens: json.pointer("/usage/input_tokens").and_then(Value::as_u64),
        output_tokens: json.pointer("/usage/output_tokens").and_then(Value::as_u64),
        attempts,
        latency_ms,
        ..Default::default()
    };
    let Some(raw) = raw else {
        out.error = Some("template choice가 없습니다".into());
        return out;
    };
    if raw == NONE_CHOICE {
        out.template = Some(NONE_CHOICE.to_string());
        return out;
    }
    // catalog probe는 인자가 없다 — 그 자체가 실행 줄이다.
    if probe_exists(&raw) {
        out.template = Some(raw.clone());
        out.line = Some(raw);
        return out;
    }
    if !template_ids().contains(&raw.as_str()) {
        out.error = Some(format!("목록 밖 템플릿: {raw}"));
        return out;
    }
    out.template = Some(raw.clone());
    // 인자: 해당 arg 질문의 답. 질문이 없었다면(후보 0개) 템플릿을 골라도 실행할 수 없다.
    let cands = candidates(evidence);
    let key = format!("arg:{raw}");
    let picked = answers
        .get(&key)
        .and_then(|a| a.get("choice"))
        .and_then(Value::as_str)
        .map(str::to_string);
    out.arg_confidence = answers
        .get(&key)
        .and_then(|a| a.get("confidence"))
        .and_then(Value::as_f64);
    match picked {
        Some(a) if a != NO_TARGET && cands.get(raw.as_str()).is_some_and(|v| v.contains(&a)) => {
            out.line = Some(format!("{raw} {a}"));
            out.arg = Some(a);
        }
        Some(a) if a == NO_TARGET => {
            out.error = Some(format!("{raw}를 골랐으나 대상이 없다고 답함"));
        }
        Some(a) => {
            out.error = Some(format!("{raw}의 인자가 후보 밖: {a}"));
        }
        None => {
            out.error = Some(format!("{raw}를 골랐으나 인자 후보가 없어 실행 불가"));
        }
    }
    out
}

pub struct FollowupClient {
    http: reqwest::Client,
    api_key: String,
    model: String,
}

enum SendError {
    Retryable(String),
    Permanent(String),
}

impl FollowupClient {
    pub fn from_env(model: &str) -> Result<Self> {
        let api_key = std::env::var("TYPESAFE_API_KEY").context(
            "TYPESAFE_API_KEY가 설정돼 있지 않습니다 — jev follow-up 비교군을 실행할 수 없습니다",
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

    pub async fn choose(&self, evidence: &str) -> FollowupOutcome {
        let state = build_state(evidence);
        if is_oversize(&state) {
            return FollowupOutcome {
                oversize: true,
                error: Some("state가 토큰 예산을 넘어 보내지 않음".into()),
                ..Default::default()
            };
        }
        let started = Instant::now();
        let body = json!({
            "state": state,
            "model": self.model,
            "questions": build_questions(evidence),
        });
        let mut attempts = 0;
        let mut last_error = String::new();
        while attempts < MAX_ATTEMPTS {
            attempts += 1;
            match self.send_once(&body).await {
                Ok(json) => {
                    return parse_answer(
                        &json,
                        evidence,
                        attempts,
                        started.elapsed().as_millis() as u64,
                    )
                }
                Err(SendError::Retryable(msg)) => {
                    last_error = msg;
                    tokio::time::sleep(Duration::from_millis(
                        BASE_BACKOFF_MS * 2u64.pow(attempts - 1),
                    ))
                    .await;
                }
                Err(SendError::Permanent(msg)) => {
                    return FollowupOutcome::failed(
                        msg,
                        attempts,
                        started.elapsed().as_millis() as u64,
                    )
                }
            }
        }
        FollowupOutcome::failed(
            format!("{MAX_ATTEMPTS}회 재시도 후 실패: {last_error}"),
            attempts,
            started.elapsed().as_millis() as u64,
        )
    }

    async fn send_once(&self, body: &Value) -> Result<Value, SendError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const EV: &str = "## failed_units\ncommand: x\nexit_code=0\n--- stdout ---\n\
● nginx.service loaded failed failed Web\nredis.service loaded failed failed KV\n\n--- stderr ---\n";

    #[test]
    fn questions_include_one_arg_question_per_template_with_candidates() {
        let q = build_questions(EV);
        let obj = q.as_object().unwrap();
        assert!(obj.contains_key("template"));
        assert!(obj.contains_key("arg:journal_unit"));
        // 후보가 없는 템플릿에는 질문을 만들지 않는다 — 고를 수 없는 것을 묻지 않는다.
        assert!(!obj.contains_key("arg:proc_fd"));
        let crit = obj["arg:journal_unit"]["criteria"].as_object().unwrap();
        assert!(crit.contains_key("nginx.service") && crit.contains_key(NO_TARGET));
    }

    #[test]
    fn template_menu_is_catalog_plus_templates_with_candidates_plus_none() {
        // catalog 59 + 후보가 있는 템플릿(journal_unit) + none. 후보 없는 템플릿은 골라도 실행할 수
        // 없어 올리지 않는다.
        let q = build_questions(EV);
        let crit = q["template"]["criteria"].as_object().unwrap();
        assert_eq!(crit.len(), probe_descriptions().len() + 2);
        assert!(crit.contains_key(NONE_CHOICE));
        assert!(crit.contains_key("journal_errors"));
        assert!(crit.contains_key("journal_unit"));
        assert!(!crit.contains_key("proc_fd"));
    }

    #[test]
    fn a_catalog_probe_is_its_own_line_and_needs_no_arg() {
        let json = json!({"answers": {"template": {"choice": "journal_errors"}}});
        let out = parse_answer(&json, EV, 1, 100);
        assert_eq!(out.line.as_deref(), Some("journal_errors"));
        assert!(!out.is_failure());
        assert!(aic_client::agent::diagnose::resolve_followup_line("journal_errors", EV).is_ok());
    }

    #[test]
    fn a_valid_template_and_arg_compose_a_gate_passing_line() {
        let json = json!({
            "answers": {
                "template": {"choice": "journal_unit", "confidence": 0.9,
                             "probabilities": {"journal_unit": 0.9, "none": 0.1}},
                "arg:journal_unit": {"choice": "nginx.service", "confidence": 0.8}
            },
            "usage": {"input_tokens": 300, "output_tokens": 0}
        });
        let out = parse_answer(&json, EV, 1, 100);
        assert_eq!(out.line.as_deref(), Some("journal_unit nginx.service"));
        assert!(!out.is_failure());
        assert!(
            aic_client::agent::diagnose::resolve_followup_line(out.line.as_ref().unwrap(), EV)
                .is_ok()
        );
    }

    #[test]
    fn none_is_a_valid_answer_not_a_failure() {
        let json = json!({"answers": {"template": {"choice": "none"}}});
        let out = parse_answer(&json, EV, 1, 100);
        assert_eq!(out.template.as_deref(), Some("none"));
        assert!(out.line.is_none() && !out.is_failure());
    }

    #[test]
    fn an_unknown_template_is_a_failure_that_keeps_the_raw_value() {
        let json = json!({"answers": {"template": {"choice": "docker_exec"}}});
        let out = parse_answer(&json, EV, 1, 100);
        assert!(out.is_failure());
        assert_eq!(out.raw_template.as_deref(), Some("docker_exec"));
    }

    #[test]
    fn an_arg_outside_the_candidates_is_a_failure() {
        // 후보 밖 인자를 조용히 받으면 게이트에서 거부되는 줄을 "골랐다"고 세게 된다.
        let json = json!({"answers": {
            "template": {"choice": "journal_unit"},
            "arg:journal_unit": {"choice": "mysqld.service"}
        }});
        let out = parse_answer(&json, EV, 1, 100);
        assert!(out.is_failure() && out.line.is_none());
    }

    #[test]
    fn top_templates_ranks_by_probability() {
        let o = FollowupOutcome {
            template_probabilities: Some(BTreeMap::from([
                ("none".into(), 0.1),
                ("journal_unit".into(), 0.6),
                ("proc_fd".into(), 0.3),
            ])),
            ..Default::default()
        };
        assert_eq!(top_templates(&o, 2), vec!["journal_unit", "proc_fd"]);
    }
}
