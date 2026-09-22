//! follow-up 선택 실험의 원시 기록과 채점.
//!
//! 정답은 `accepted` 줄 집합이다. 비어 있으면 "불필요"가 정답이고, Jev의 `none`과 LLM의 빈 블록이
//! 그것을 맞힌 것이다. 실패(API 오류, 목록 밖, 인자 후보 없음)는 오답으로 센다 — 실패를 빼면
//! 실패가 잦은 비교군이 좋아 보인다.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::arms::jev_followup::{top_templates, FollowupOutcome, NONE_CHOICE};
use crate::arms::llm_followup::LlmFollowupOutcome;
use crate::followup::Split;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowupRecord {
    pub bundle_id: String,
    pub split: Split,
    pub arm: String,
    pub repeat: u32,
    pub model: Option<String>,
    pub question_version: Option<String>,
    pub input_sha256: String,
    pub accepted: Vec<String>,
    /// 번들의 trait(신호 계열, 함정 종류). 계열별 표를 만들 때 쓴다. 1라운드 기록에는 없다.
    #[serde(default)]
    pub traits: Vec<String>,
    /// Jev 또는 규칙 비교군의 결과. 규칙 비교군은 Jev와 같은 형태로 기록한다(`arm`으로 구분).
    pub jev: Option<FollowupOutcome>,
    pub llm: Option<LlmFollowupOutcome>,
}

#[derive(Debug, Default)]
pub struct ArmSummary {
    pub arm: String,
    pub n: usize,
    /// 신호가 있는 사례에서 첫 선택이 정답 집합에 든 비율.
    pub top1_correct: f64,
    /// 신호가 있는 사례에서 상위 3개(Jev는 확률 순, LLM은 블록 순) 중 하나라도 든 비율.
    pub top3_correct: f64,
    /// 신호 없는 사례에서 "불필요"를 맞힌 비율.
    pub none_correct: f64,
    pub signal_n: usize,
    pub none_n: usize,
    /// 실패(API/계약/후보 없음) 비율. Jev만 의미 있다 — LLM은 게이트 거부로 드러난다.
    pub failure_rate: f64,
    /// LLM: 블록 줄 중 게이트가 거부한 비율.
    pub gate_reject_rate: Option<f64>,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub total_input_tokens: u64,
}

fn template_of(line: &str) -> &str {
    line.split_once(' ').map_or(line, |(t, _)| t)
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

/// 첫 선택의 정오. 신호 없는 번들은 "불필요"를 맞혔는지로, 실패는 오답으로 본다.
pub fn first_pick_ok(r: &FollowupRecord) -> bool {
    let is_none = r.accepted.is_empty();
    match (&r.jev, &r.llm) {
        (Some(j), _) => {
            if j.is_failure() {
                return false;
            }
            if is_none {
                j.template.as_deref() == Some(NONE_CHOICE)
            } else {
                j.line.as_ref().is_some_and(|l| r.accepted.contains(l))
            }
        }
        (_, Some(l)) => {
            if l.error.is_some() {
                return false;
            }
            if is_none {
                l.lines.is_empty()
            } else {
                l.accepted_lines
                    .first()
                    .is_some_and(|f| r.accepted.contains(f))
            }
        }
        _ => false,
    }
}

pub fn summarize(arm: &str, records: &[FollowupRecord]) -> ArmSummary {
    let mine: Vec<&FollowupRecord> = records
        .iter()
        .filter(|r| r.arm == arm && r.repeat == 1)
        .collect();
    let mut s = ArmSummary {
        arm: arm.to_string(),
        n: mine.len(),
        ..Default::default()
    };
    let mut top1 = 0usize;
    let mut top3 = 0usize;
    let mut none_ok = 0usize;
    let mut failures = 0usize;
    let mut lines_total = 0usize;
    let mut lines_rejected = 0usize;
    let mut lat: Vec<u64> = Vec::new();
    for r in &mine {
        let accepted_templates: Vec<&str> = r.accepted.iter().map(|l| template_of(l)).collect();
        let is_none = r.accepted.is_empty();
        if is_none {
            s.none_n += 1;
        } else {
            s.signal_n += 1;
        }
        let ok = first_pick_ok(r);
        if is_none {
            if ok {
                none_ok += 1;
            }
        } else if ok {
            top1 += 1;
        }
        if let Some(j) = &r.jev {
            lat.push(j.latency_ms);
            s.total_input_tokens += j.input_tokens.unwrap_or(0);
            if j.is_failure() {
                failures += 1;
                continue;
            }
            if !is_none
                && top_templates(j, 3)
                    .iter()
                    .any(|t| accepted_templates.contains(&t.as_str()))
            {
                top3 += 1;
            }
        } else if let Some(l) = &r.llm {
            lat.push(l.latency_ms);
            s.total_input_tokens += l.input_tokens.unwrap_or(0);
            lines_total += l.lines.len();
            lines_rejected += l.rejected.len();
            if l.error.is_some() {
                failures += 1;
                continue;
            }
            if !is_none
                && l.accepted_lines
                    .iter()
                    .take(3)
                    .any(|f| r.accepted.contains(f))
            {
                top3 += 1;
            }
        }
    }
    lat.sort_unstable();
    s.top1_correct = if s.signal_n == 0 {
        0.0
    } else {
        top1 as f64 / s.signal_n as f64
    };
    s.top3_correct = if s.signal_n == 0 {
        0.0
    } else {
        top3 as f64 / s.signal_n as f64
    };
    s.none_correct = if s.none_n == 0 {
        0.0
    } else {
        none_ok as f64 / s.none_n as f64
    };
    s.failure_rate = if mine.is_empty() {
        0.0
    } else {
        failures as f64 / mine.len() as f64
    };
    s.gate_reject_rate = (lines_total > 0).then(|| lines_rejected as f64 / lines_total as f64);
    s.latency_p50_ms = percentile(&lat, 0.50);
    s.latency_p95_ms = percentile(&lat, 0.95);
    s
}

/// `(trait, 정답 수, n)` 행들.
pub type TraitRows = Vec<(String, usize, usize)>;

/// trait별 첫 선택 정답 수(1회차), trait 이름순. 어느 계열·함정에서 갈리는지 본다.
pub fn by_trait(arm: &str, records: &[FollowupRecord]) -> TraitRows {
    let mut acc: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in records.iter().filter(|r| r.arm == arm && r.repeat == 1) {
        let ok = first_pick_ok(r);
        for t in &r.traits {
            let e = acc.entry(t.clone()).or_default();
            e.1 += 1;
            if ok {
                e.0 += 1;
            }
        }
    }
    acc.into_iter().map(|(t, (c, n))| (t, c, n)).collect()
}

/// 같은 번들을 여러 번 물었을 때 첫 선택이 같은 비율. `(일치 비율, 반복이 있는 번들 수)`.
///
/// Jev는 비생성형이라 거의 결정적이고 LLM은 그렇지 않다 — 운영에서 같은 증거에 매번 다른 follow-up이
/// 나오면 사용자는 결과를 믿지 못한다. 이 수치가 그 차이를 잰다.
pub fn repeat_agreement(arm: &str, records: &[FollowupRecord]) -> Option<(f64, usize)> {
    let mut ids: Vec<&str> = records
        .iter()
        .filter(|r| r.arm == arm)
        .map(|r| r.bundle_id.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let first_pick = |r: &FollowupRecord| -> String {
        match (&r.jev, &r.llm) {
            (Some(j), _) => j
                .line
                .clone()
                .or_else(|| j.template.clone())
                .unwrap_or_default(),
            (_, Some(l)) => l.accepted_lines.first().cloned().unwrap_or_default(),
            _ => String::new(),
        }
    };
    let mut agreed = 0usize;
    let mut counted = 0usize;
    for id in ids {
        let picks: Vec<String> = records
            .iter()
            .filter(|r| r.arm == arm && r.bundle_id == id)
            .map(first_pick)
            .collect();
        if picks.len() < 2 {
            continue;
        }
        counted += 1;
        if picks.iter().all(|p| *p == picks[0]) {
            agreed += 1;
        }
    }
    (counted > 0).then(|| (agreed as f64 / counted as f64, counted))
}
