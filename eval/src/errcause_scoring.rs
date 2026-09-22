//! 원인 범주 분류의 원시 기록과 채점.
//!
//! 정답은 `accepted` 집합이다. 여러 범주가 타당한 사례가 있으므로 하나라도 맞으면 정탐이다.
//! 실패(API 오류, 목록 밖 값, 규칙의 `unknown`)는 오답으로 센다 — 빼면 자주 기권하는 비교군이
//! 좋아 보인다.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::arms::jev_errcause::CauseOutcome;
use crate::arms::llm_errcause::LlmCauseOutcome;
use crate::errcause::Split;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CauseRecord {
    pub case_id: String,
    pub split: Split,
    pub arm: String,
    pub repeat: u32,
    pub model: Option<String>,
    pub question_version: Option<String>,
    pub input_sha256: String,
    pub accepted: Vec<String>,
    pub traits: Vec<String>,
    /// Jev 또는 규칙 비교군(규칙은 Jev와 같은 형태로 적는다). `arm`으로 구분한다.
    pub jev: Option<CauseOutcome>,
    pub llm: Option<LlmCauseOutcome>,
}

impl CauseRecord {
    /// 이 비교군이 고른 범주. 실패면 `None`.
    pub fn picked(&self) -> Option<&str> {
        match (&self.jev, &self.llm) {
            (Some(j), _) => j.category.as_deref(),
            (_, Some(l)) => l.category.as_deref(),
            _ => None,
        }
    }

    pub fn correct(&self) -> bool {
        self.picked()
            .is_some_and(|c| self.accepted.iter().any(|a| a == c))
    }
}

#[derive(Debug, Default)]
pub struct CauseSummary {
    pub arm: String,
    pub n: usize,
    pub accuracy: f64,
    /// 상위 3개 안에 정답이 있는 비율. Jev만 분포를 주므로 다른 비교군은 1등과 같다.
    pub top3: f64,
    /// 답을 내지 못한 비율(규칙의 `unknown`, 목록 밖 값, API 오류). 오답에도 포함된다.
    pub abstain_rate: f64,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub total_input_tokens: u64,
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

pub fn summarize(arm: &str, records: &[CauseRecord]) -> CauseSummary {
    let mine: Vec<&CauseRecord> = records
        .iter()
        .filter(|r| r.arm == arm && r.repeat == 1)
        .collect();
    let mut s = CauseSummary {
        arm: arm.to_string(),
        n: mine.len(),
        ..Default::default()
    };
    if mine.is_empty() {
        return s;
    }
    let mut hit = 0usize;
    let mut top3 = 0usize;
    let mut abstain = 0usize;
    let mut lat: Vec<u64> = Vec::new();
    for r in &mine {
        if r.correct() {
            hit += 1;
        }
        if r.picked().is_none() {
            abstain += 1;
        }
        match (&r.jev, &r.llm) {
            (Some(j), _) => {
                lat.push(j.latency_ms);
                s.total_input_tokens += j.input_tokens.unwrap_or(0);
                if j.top_n(3).iter().any(|c| r.accepted.contains(c)) {
                    top3 += 1;
                }
            }
            (_, Some(l)) => {
                lat.push(l.latency_ms);
                s.total_input_tokens += l.input_tokens.unwrap_or(0);
                if r.correct() {
                    top3 += 1;
                }
            }
            _ => {}
        }
    }
    lat.sort_unstable();
    s.accuracy = hit as f64 / mine.len() as f64;
    s.top3 = top3 as f64 / mine.len() as f64;
    s.abstain_rate = abstain as f64 / mine.len() as f64;
    s.latency_p50_ms = percentile(&lat, 0.50);
    s.latency_p95_ms = percentile(&lat, 0.95);
    s
}

/// `(범주, 정답 수, n)` — 정답 집합의 첫 범주 기준으로 묶는다.
pub type GroupRows = Vec<(String, usize, usize)>;

pub fn by_category(arm: &str, records: &[CauseRecord]) -> GroupRows {
    group(arm, records, |r| {
        vec![r.accepted.first().cloned().unwrap_or_default()]
    })
}

pub fn by_trait(arm: &str, records: &[CauseRecord]) -> GroupRows {
    group(arm, records, |r| r.traits.clone())
}

fn group(
    arm: &str,
    records: &[CauseRecord],
    keys: impl Fn(&CauseRecord) -> Vec<String>,
) -> GroupRows {
    let mut acc: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in records.iter().filter(|r| r.arm == arm && r.repeat == 1) {
        let ok = r.correct();
        for k in keys(r) {
            if k.is_empty() {
                continue;
            }
            let e = acc.entry(k).or_default();
            e.1 += 1;
            if ok {
                e.0 += 1;
            }
        }
    }
    acc.into_iter().map(|(k, (c, n))| (k, c, n)).collect()
}

/// 같은 사례를 여러 번 물었을 때 답이 같은 비율. `(일치 비율, 반복이 있는 사례 수)`.
pub fn repeat_agreement(arm: &str, records: &[CauseRecord]) -> Option<(f64, usize)> {
    let mut ids: Vec<&str> = records
        .iter()
        .filter(|r| r.arm == arm)
        .map(|r| r.case_id.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut agreed = 0usize;
    let mut counted = 0usize;
    for id in ids {
        let picks: Vec<String> = records
            .iter()
            .filter(|r| r.arm == arm && r.case_id == id)
            .map(|r| r.picked().unwrap_or_default().to_string())
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

/// 두 비교군이 **같은 사례에서** 어떻게 갈렸는지. `(a만 맞음, b만 맞음, 둘 다 맞음, 둘 다 틀림)`.
///
/// 정확도 차이만 보면 "누가 높은가"는 알아도 "어디서 갈리는가"를 모른다. 짝지은 비교가 있어야
/// 한쪽을 채택할 근거가 된다.
pub fn paired(a: &str, b: &str, records: &[CauseRecord]) -> (usize, usize, usize, usize) {
    let pick = |arm: &str, id: &str| {
        records
            .iter()
            .find(|r| r.arm == arm && r.case_id == id && r.repeat == 1)
            .map(CauseRecord::correct)
    };
    let mut ids: Vec<&str> = records.iter().map(|r| r.case_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    let (mut only_a, mut only_b, mut both, mut neither) = (0, 0, 0, 0);
    for id in ids {
        match (pick(a, id), pick(b, id)) {
            (Some(true), Some(true)) => both += 1,
            (Some(true), Some(false)) => only_a += 1,
            (Some(false), Some(true)) => only_b += 1,
            (Some(false), Some(false)) => neither += 1,
            _ => {}
        }
    }
    (only_a, only_b, both, neither)
}
