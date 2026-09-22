//! 지표 계산과 집계.
//!
//! 측정 대상은 범주가 아니라 **증거 확보**다. 범주는 수단이므로 정확도를 보조 지표로만 둔다.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::arms::ArmOutcome;
use crate::scenario::{Lang, Scenario, Split};

/// 실행 한 번의 원시 기록. 사례·분할·비교군·반복을 모두 식별한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub scenario_id: String,
    pub split: Split,
    pub lang: Lang,
    pub arm: String,
    pub repeat: u32,
    /// 구현 기준 revision(git). 같은 데이터라도 코드가 바뀌면 다른 결과다.
    pub revision: String,
    /// Jev는 모델 ID, LLM은 provider 이름. 규칙 비교군은 `None`.
    pub model: Option<String>,
    pub question_version: Option<String>,
    /// 실제로 보낸 입력의 해시. 같은 입력을 썼는지 나중에 대조한다.
    pub input_sha256: String,
    pub outcome: ArmOutcome,
    pub selected_probes: Vec<String>,
    /// 모호한 사례(필수 집합이 빔)는 `None`이다. 확보율 평균에서 제외한다.
    pub score: Option<CaseScore>,
}

/// 사례 하나의 점수.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CaseScore {
    pub required_total: usize,
    pub required_hit: usize,
    /// 필수 probe 확보율. 실패(범주 없음)면 0이다.
    pub coverage: f64,
    /// 필수를 하나라도 빠뜨렸는가.
    pub missed_any: bool,
    /// 필수도 유용도 아닌 선택 수.
    pub unnecessary: usize,
    pub category_allowed: bool,
    pub total_selected: usize,
}

/// 사례 하나를 채점한다. 필수 집합이 비었으면 `None`.
///
/// 실패(API 오류·목록 밖 범주)는 확보율 0으로 센다. 실패 때문에 불필요 probe가 0이 되어
/// 그 지표가 좋아 보이는 착시는 집계 쪽에서 막는다([`ArmSummary::unnecessary_paired`]).
pub fn score_case(
    scenario: &Scenario,
    outcome: &ArmOutcome,
    selected: &[String],
) -> Option<CaseScore> {
    if scenario.is_ambiguous() {
        return None;
    }
    let required: BTreeSet<&str> = scenario
        .required_probes
        .iter()
        .map(String::as_str)
        .collect();
    let useful = scenario.useful();
    let chosen: BTreeSet<&str> = selected.iter().map(String::as_str).collect();

    let hit = required.intersection(&chosen).count();
    let unnecessary = chosen
        .iter()
        .filter(|id| !required.contains(*id) && !useful.contains(**id))
        .count();
    let category_allowed = outcome
        .category
        .as_deref()
        .is_some_and(|c| scenario.allowed_categories.iter().any(|a| a == c));

    Some(CaseScore {
        required_total: required.len(),
        required_hit: hit,
        coverage: hit as f64 / required.len() as f64,
        missed_any: hit < required.len(),
        unnecessary,
        category_allowed,
        total_selected: chosen.len(),
    })
}

/// 비교군 하나의 집계.
#[derive(Debug, Clone, Serialize)]
pub struct ArmSummary {
    pub arm: String,
    /// 채점에 들어간 사례 수(모호한 사례 제외).
    pub scored_cases: usize,
    pub mean_coverage: f64,
    pub missed_case_rate: f64,
    pub mean_unnecessary: f64,
    pub category_accuracy: f64,
    pub mean_total_selected: f64,
    /// API 실패와 목록 밖 응답을 합친 비율. 규칙 비교군은 0이다.
    pub failure_rate: f64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    /// 모호한 사례에서 generic을 고른 비율. 별도 집계다.
    pub ambiguous_generic_rate: Option<f64>,
}

pub fn summarize(arm: &str, records: &[CaseRecord]) -> ArmSummary {
    let mine: Vec<&CaseRecord> = records.iter().filter(|r| r.arm == arm).collect();
    let scored: Vec<&CaseRecord> = mine.iter().copied().filter(|r| r.score.is_some()).collect();
    let n = scored.len().max(1) as f64;

    let mean = |f: &dyn Fn(&CaseScore) -> f64| -> f64 {
        scored
            .iter()
            .filter_map(|r| r.score.as_ref().map(f))
            .sum::<f64>()
            / n
    };

    let mut latencies: Vec<u64> = mine.iter().map(|r| r.outcome.latency_ms).collect();
    latencies.sort_unstable();

    let ambiguous: Vec<&CaseRecord> = mine.iter().copied().filter(|r| r.score.is_none()).collect();
    let ambiguous_generic_rate = (!ambiguous.is_empty()).then(|| {
        ambiguous
            .iter()
            .filter(|r| r.outcome.category.as_deref() == Some("generic"))
            .count() as f64
            / ambiguous.len() as f64
    });

    ArmSummary {
        arm: arm.to_string(),
        scored_cases: scored.len(),
        mean_coverage: mean(&|s| s.coverage),
        missed_case_rate: mean(&|s| if s.missed_any { 1.0 } else { 0.0 }),
        mean_unnecessary: mean(&|s| s.unnecessary as f64),
        category_accuracy: mean(&|s| if s.category_allowed { 1.0 } else { 0.0 }),
        mean_total_selected: mean(&|s| s.total_selected as f64),
        failure_rate: if mine.is_empty() {
            0.0
        } else {
            mine.iter().filter(|r| r.outcome.is_failure()).count() as f64 / mine.len() as f64
        },
        total_input_tokens: mine.iter().filter_map(|r| r.outcome.input_tokens).sum(),
        total_output_tokens: mine.iter().filter_map(|r| r.outcome.output_tokens).sum(),
        latency_p50_ms: percentile(&latencies, 0.50),
        latency_p95_ms: percentile(&latencies, 0.95),
        ambiguous_generic_rate,
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

/// 두 비교군이 **모두 정상 반환한** 사례만 골라 불필요 probe 평균을 비교한다.
///
/// 실패는 probe를 하나도 고르지 않으므로 불필요 수가 0이 된다. 그대로 평균 내면 많이 실패한
/// 쪽이 이 지표에서 유리해 보인다. 비교 대상 사례 수를 함께 돌려줘 보고에 싣는다.
pub fn unnecessary_paired(records: &[CaseRecord], arm_a: &str, arm_b: &str) -> (f64, f64, usize) {
    let pairs = paired_scores(records, arm_a, arm_b, &|s| s.unnecessary as f64);
    let n = pairs.len();
    if n == 0 {
        return (0.0, 0.0, 0);
    }
    let a = pairs.iter().map(|(x, _)| x).sum::<f64>() / n as f64;
    let b = pairs.iter().map(|(_, y)| y).sum::<f64>() / n as f64;
    (a, b, n)
}

/// 같은 (시나리오, 언어, 반복)에서 두 비교군이 모두 정상 반환한 값 쌍.
pub fn paired_scores(
    records: &[CaseRecord],
    arm_a: &str,
    arm_b: &str,
    pick: &dyn Fn(&CaseScore) -> f64,
) -> Vec<(f64, f64)> {
    let key = |r: &CaseRecord| (r.scenario_id.clone(), r.lang, r.repeat);
    let mut out = Vec::new();
    for ra in records.iter().filter(|r| r.arm == arm_a) {
        if ra.outcome.is_failure() {
            continue;
        }
        let Some(sa) = ra.score.as_ref() else {
            continue;
        };
        let Some(rb) = records
            .iter()
            .find(|r| r.arm == arm_b && key(r) == key(ra) && !r.outcome.is_failure())
        else {
            continue;
        };
        let Some(sb) = rb.score.as_ref() else {
            continue;
        };
        out.push((pick(sa), pick(sb)));
    }
    out
}

/// 짝지은 차이(a − b)의 bootstrap 신뢰구간.
///
/// 재표집 단위는 **기본 시나리오**다. 같은 시나리오의 번역과 반복 실행은 독립 표본이 아니므로
/// 각각을 하나로 세면 구간이 실제보다 좁아진다. 난수는 고정 시드 LCG라 같은 입력에 같은 구간이
/// 나온다 — 보고 수치가 실행마다 흔들리면 비교가 어렵다.
pub fn paired_bootstrap_ci(
    grouped: &[Vec<(f64, f64)>],
    iterations: usize,
    seed: u64,
) -> (f64, f64) {
    if grouped.is_empty() {
        return (0.0, 0.0);
    }
    let mut state = seed | 1;
    let mut next = || {
        // Numerical Recipes LCG. 통계용으로 충분하고 외부 의존성이 없다.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let mut diffs = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut sum = 0.0;
        let mut count = 0usize;
        for _ in 0..grouped.len() {
            let g = &grouped[next() % grouped.len()];
            for (a, b) in g {
                sum += a - b;
                count += 1;
            }
        }
        if count > 0 {
            diffs.push(sum / count as f64);
        }
    }
    if diffs.is_empty() {
        return (0.0, 0.0);
    }
    diffs.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    let lo = diffs[((diffs.len() as f64) * 0.025) as usize];
    let hi = diffs[(((diffs.len() as f64) * 0.975) as usize).min(diffs.len() - 1)];
    (lo, hi)
}

/// 입력 문자열의 sha256. 같은 입력을 썼는지 나중에 대조한다.
pub fn input_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Texts;

    fn scenario(required: &[&str], useful: &[&str], allowed: &[&str]) -> Scenario {
        Scenario {
            id: "t-001".into(),
            split: Split::Dev,
            primary_category: "network".into(),
            docker_available: false,
            text: Texts {
                ko: "네트워크가 느려요".into(),
                en: "the network is slow".into(),
            },
            allowed_categories: allowed.iter().map(|s| (*s).to_string()).collect(),
            required_probes: required.iter().map(|s| (*s).to_string()).collect(),
            useful_probes: useful.iter().map(|s| (*s).to_string()).collect(),
            traits: vec![],
            source: "synthetic".into(),
        }
    }

    fn outcome(category: Option<&str>) -> ArmOutcome {
        ArmOutcome {
            category: category.map(str::to_string),
            attempts: 1,
            latency_ms: 10,
            ..Default::default()
        }
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn full_coverage_scores_one() {
        let sc = scenario(&["ip", "route"], &["date"], &["network"]);
        let s = score_case(
            &sc,
            &outcome(Some("network")),
            &ids(&["ip", "route", "date"]),
        )
        .expect("채점");
        assert_eq!(s.coverage, 1.0);
        assert!(!s.missed_any);
        assert_eq!(s.unnecessary, 0);
        assert!(s.category_allowed);
    }

    #[test]
    fn a_partial_hit_is_counted_as_a_miss() {
        let sc = scenario(&["ip", "route"], &[], &["network"]);
        let s = score_case(&sc, &outcome(Some("network")), &ids(&["ip"])).expect("채점");
        assert_eq!(s.coverage, 0.5);
        assert!(s.missed_any);
    }

    #[test]
    fn probes_outside_both_sets_count_as_unnecessary() {
        let sc = scenario(&["ip"], &["date"], &["network"]);
        let s = score_case(
            &sc,
            &outcome(Some("network")),
            &ids(&["ip", "date", "cpu_throttle"]),
        )
        .expect("채점");
        assert_eq!(s.unnecessary, 1);
    }

    #[test]
    fn a_wrong_but_allowed_category_still_passes() {
        // 서로 다른 범주가 같은 필수 집합에 도달하면 둘 다 허용한다.
        let sc = scenario(&["ip"], &[], &["network", "generic"]);
        let s = score_case(&sc, &outcome(Some("generic")), &ids(&["ip"])).expect("채점");
        assert!(s.category_allowed);
    }

    #[test]
    fn an_ambiguous_case_is_excluded_from_scoring() {
        let sc = scenario(&[], &["date"], &["generic"]);
        assert!(score_case(&sc, &outcome(Some("generic")), &ids(&["date"])).is_none());
    }

    #[test]
    fn a_failure_scores_zero_coverage() {
        let sc = scenario(&["ip"], &[], &["network"]);
        let s = score_case(&sc, &outcome(None), &[]).expect("채점");
        assert_eq!(s.coverage, 0.0);
        assert!(s.missed_any);
        assert!(!s.category_allowed);
    }

    #[test]
    fn the_bootstrap_is_deterministic_for_a_fixed_seed() {
        // 실행마다 구간이 흔들리면 두 보고를 비교할 수 없다.
        let grouped = vec![vec![(0.9, 0.5)], vec![(1.0, 0.4)], vec![(0.7, 0.7)]];
        let a = paired_bootstrap_ci(&grouped, 200, 42);
        let b = paired_bootstrap_ci(&grouped, 200, 42);
        assert_eq!(a, b);
        assert!(a.0 <= a.1);
    }

    #[test]
    fn identical_arms_give_a_ci_containing_zero() {
        let grouped = vec![vec![(0.8, 0.8)], vec![(0.5, 0.5)]];
        let (lo, hi) = paired_bootstrap_ci(&grouped, 200, 7);
        assert!(lo <= 0.0 && hi >= 0.0, "({lo}, {hi})");
    }

    #[test]
    fn the_same_text_always_hashes_the_same() {
        assert_eq!(
            input_hash("네트워크가 느려요"),
            input_hash("네트워크가 느려요")
        );
        assert_ne!(input_hash("a"), input_hash("b"));
    }
}
