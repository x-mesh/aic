//! confidence를 라우팅 신호로 쓸 수 있는지 분석한다.
//!
//! PRD 5절은 첫 평가에서 confidence로 선택을 바꾸지 말라고 했다. 그 평가가 끝났으므로 이제
//! 기록된 값으로 "언제 믿고 언제 폴백할지"를 재본다. 새 API 호출은 필요하지 않다.
//!
//! confidence는 확률 분포의 분산에서 계산한 통계이고 정답률이 아니다(공식 문서). 그래서 여기서
//! 하는 일은 confidence를 정답률로 읽는 것이 아니라, **구간별로 실제 정확도가 어떻게 갈리는지**를
//! 관측하는 것이다.

use std::collections::BTreeSet;

use crate::scenario::Dataset;
use crate::scoring::CaseRecord;

/// 구간 경계. 낮은 쪽을 촘촘히 둔다 — 폴백 임계값이 그 근처에 놓일 것이기 때문이다.
const BUCKETS: [(f64, f64); 5] = [
    (0.0, 0.5),
    (0.5, 0.7),
    (0.7, 0.9),
    (0.9, 0.99),
    (0.99, 1.01),
];

/// 폴백 임계값 후보.
const THRESHOLDS: [f64; 6] = [0.0, 0.4, 0.5, 0.6, 0.7, 0.9];

pub fn report(records: &[CaseRecord], ds: &Dataset, arm: &str) {
    let primary: Vec<&CaseRecord> = records
        .iter()
        .filter(|r| r.arm == arm && r.repeat == 1 && r.outcome.confidence.is_some())
        .collect();
    if primary.is_empty() {
        println!("{arm}: confidence를 기록한 결과가 없습니다");
        return;
    }

    println!("## {arm} — confidence 구간별 실제 정확도");
    println!();
    println!(
        "  {:<14} {:>5} {:>9} {:>9} {:>9}",
        "구간", "n", "범주정확", "확보율", "불필요"
    );
    for (lo, hi) in BUCKETS {
        let subset: Vec<&&CaseRecord> = primary
            .iter()
            .filter(|r| {
                let c = r.outcome.confidence.unwrap_or(0.0);
                c >= lo && c < hi
            })
            .collect();
        if subset.is_empty() {
            continue;
        }
        let scored: Vec<&&&CaseRecord> = subset.iter().filter(|r| r.score.is_some()).collect();
        let n = subset.len();
        let cat = mean(&subset, |r| {
            r.score
                .map_or(0.0, |s| if s.category_allowed { 1.0 } else { 0.0 })
        });
        let cov = if scored.is_empty() {
            f64::NAN
        } else {
            scored
                .iter()
                .filter_map(|r| r.score.map(|s| s.coverage))
                .sum::<f64>()
                / scored.len() as f64
        };
        let unn = if scored.is_empty() {
            f64::NAN
        } else {
            scored
                .iter()
                .filter_map(|r| r.score.map(|s| s.unnecessary as f64))
                .sum::<f64>()
                / scored.len() as f64
        };
        println!("  [{lo:.2}, {hi:.2})  {n:>5} {cat:>9.3} {cov:>9.3} {unn:>9.2}");
    }

    // 낮은 confidence에 모호·적대 입력이 모이는지. 모인다면 confidence는 "이상한 입력 감지"로도
    // 쓸 수 있다.
    let odd: BTreeSet<&str> = ds
        .scenarios
        .iter()
        .filter(|s| {
            s.traits
                .iter()
                .any(|t| t == "ambiguous" || t == "adversarial")
        })
        .map(|s| s.id.as_str())
        .collect();
    let low: Vec<&&CaseRecord> = primary
        .iter()
        .filter(|r| r.outcome.confidence.unwrap_or(1.0) < 0.7)
        .collect();
    if !low.is_empty() {
        let hit = low
            .iter()
            .filter(|r| odd.contains(r.scenario_id.as_str()))
            .count();
        println!();
        println!(
            "  confidence < 0.70 인 {}건 중 모호·적대 입력이 {}건 ({:.0}%)",
            low.len(),
            hit,
            hit as f64 / low.len() as f64 * 100.0
        );
        let total_odd = primary
            .iter()
            .filter(|r| odd.contains(r.scenario_id.as_str()))
            .count();
        if total_odd > 0 {
            println!(
                "  모호·적대 입력 {total_odd}건 중 {hit}건이 이 구간에 들어옴 ({:.0}% 포착)",
                hit as f64 / total_odd as f64 * 100.0
            );
        }
    }

    println!();
    println!("## {arm} — 임계값 미만을 generic으로 폴백할 때");
    println!();
    println!(
        "  {:<8} {:>7} {:>9} {:>9} {:>9}",
        "임계값", "폴백건", "확보율", "누락율", "불필요"
    );
    for t in THRESHOLDS {
        let mut cov_sum = 0.0;
        let mut miss = 0usize;
        let mut unn_sum = 0.0;
        let mut n = 0usize;
        let mut fallbacks = 0usize;
        for r in &primary {
            let Some(sc) = ds.scenarios.iter().find(|s| s.id == r.scenario_id) else {
                continue;
            };
            if sc.is_ambiguous() {
                continue;
            }
            let conf = r.outcome.confidence.unwrap_or(0.0);
            // 임계값 미만이면 generic이 고르는 probe로 대체한다. generic은 범주를 좁히지 않고
            // 넓게 훑으므로, 확보율은 오르고 불필요도 오르는 쪽으로 움직여야 한다.
            let (category, fell_back) = if conf < t {
                fallbacks += 1;
                ("generic", true)
            } else {
                (r.outcome.category.as_deref().unwrap_or("generic"), false)
            };
            let _ = fell_back;
            let ids = crate::arms::probes_for(category, sc.docker_available);
            let selected: Vec<String> = ids.into_iter().map(str::to_string).collect();
            let Some(s) = crate::scoring::score_case(sc, &r.outcome, &selected) else {
                continue;
            };
            // 폴백한 경우 원래 outcome의 범주 판정은 의미가 없으므로 확보율·불필요만 쓴다.
            cov_sum += s.coverage;
            unn_sum += s.unnecessary as f64;
            if s.missed_any {
                miss += 1;
            }
            n += 1;
        }
        if n == 0 {
            continue;
        }
        println!(
            "  {t:<8.2} {fallbacks:>7} {:>9.3} {:>9.3} {:>9.2}",
            cov_sum / n as f64,
            miss as f64 / n as f64,
            unn_sum / n as f64
        );
    }
}

fn mean(records: &[&&CaseRecord], pick: impl Fn(&CaseRecord) -> f64) -> f64 {
    if records.is_empty() {
        return f64::NAN;
    }
    records.iter().map(|r| pick(r)).sum::<f64>() / records.len() as f64
}

/// 상위 N개 범주의 probe 합집합을 쓰면 어떻게 되는가.
///
/// generic 폴백이 거의 도움이 안 된 이유는 generic이 그 사례의 필수 probe를 담지 못해서다.
/// Choice는 전체 확률 분포를 주므로 "2등까지 조사한다"를 새 호출 없이 시뮬레이션할 수 있다.
/// 범주 하나로 복합 증상을 담지 못한다는 한계(PRD 3절)에 값이 붙는지 여기서 본다.
pub fn top_n_report(records: &[CaseRecord], ds: &Dataset, arm: &str) {
    let primary: Vec<&CaseRecord> = records
        .iter()
        .filter(|r| r.arm == arm && r.repeat == 1 && r.outcome.probabilities.is_some())
        .collect();
    if primary.is_empty() {
        println!("{arm}: 확률 분포를 기록한 결과가 없습니다");
        return;
    }

    println!();
    println!("## {arm} — 상위 N개 범주의 probe 합집합");
    println!();
    println!(
        "  {:<4} {:>9} {:>9} {:>9} {:>11}",
        "N", "확보율", "누락율", "불필요", "선택probe"
    );
    for n in 1..=3usize {
        let mut cov = 0.0;
        let mut miss = 0usize;
        let mut unn = 0.0;
        let mut total = 0.0;
        let mut counted = 0usize;
        for r in &primary {
            let Some(sc) = ds.scenarios.iter().find(|s| s.id == r.scenario_id) else {
                continue;
            };
            if sc.is_ambiguous() {
                continue;
            }
            let Some(probs) = r.outcome.probabilities.as_ref() else {
                continue;
            };
            let mut ranked: Vec<(&String, &f64)> = probs.iter().collect();
            ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
            let mut selected: BTreeSet<String> = BTreeSet::new();
            for (cat, _) in ranked.iter().take(n) {
                for id in crate::arms::probes_for(cat, sc.docker_available) {
                    selected.insert(id.to_string());
                }
            }
            let ids: Vec<String> = selected.into_iter().collect();
            let Some(s) = crate::scoring::score_case(sc, &r.outcome, &ids) else {
                continue;
            };
            cov += s.coverage;
            unn += s.unnecessary as f64;
            total += s.total_selected as f64;
            if s.missed_any {
                miss += 1;
            }
            counted += 1;
        }
        if counted == 0 {
            continue;
        }
        let c = counted as f64;
        println!(
            "  {n:<4} {:>9.3} {:>9.3} {:>9.2} {:>11.1}",
            cov / c,
            miss as f64 / c,
            unn / c,
            total / c
        );
    }
}

/// confidence가 낮을 때만 2등까지 조사하는 적응형 정책.
///
/// 상위 2개 합집합은 확보율을 크게 올리지만 불필요 probe도 함께 올린다. confidence가 실제
/// 정확도와 단조 관계를 보였으므로, **확신할 때는 1등만 믿고 애매할 때만 넓히는** 중간 지점이
/// 있는지 본다. 임계값 0은 항상 1등, 1.01은 항상 2등까지다.
pub fn adaptive_report(records: &[CaseRecord], ds: &Dataset, arm: &str) {
    let primary: Vec<&CaseRecord> = records
        .iter()
        .filter(|r| r.arm == arm && r.repeat == 1 && r.outcome.probabilities.is_some())
        .collect();
    if primary.is_empty() {
        return;
    }

    println!();
    println!("## {arm} — confidence < 임계값일 때만 2등까지 합치기");
    println!();
    println!(
        "  {:<8} {:>7} {:>9} {:>9} {:>9} {:>11}",
        "임계값", "확장건", "확보율", "누락율", "불필요", "선택probe"
    );
    for t in [0.0, 0.7, 0.9, 0.99, 1.01] {
        let mut cov = 0.0;
        let mut miss = 0usize;
        let mut unn = 0.0;
        let mut total = 0.0;
        let mut counted = 0usize;
        let mut widened = 0usize;
        for r in &primary {
            let Some(sc) = ds.scenarios.iter().find(|s| s.id == r.scenario_id) else {
                continue;
            };
            if sc.is_ambiguous() {
                continue;
            }
            let Some(probs) = r.outcome.probabilities.as_ref() else {
                continue;
            };
            let take = if r.outcome.confidence.unwrap_or(1.0) < t {
                widened += 1;
                2
            } else {
                1
            };
            let mut ranked: Vec<(&String, &f64)> = probs.iter().collect();
            ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
            let mut selected: BTreeSet<String> = BTreeSet::new();
            for (cat, _) in ranked.iter().take(take) {
                for id in crate::arms::probes_for(cat, sc.docker_available) {
                    selected.insert(id.to_string());
                }
            }
            let ids: Vec<String> = selected.into_iter().collect();
            let Some(s) = crate::scoring::score_case(sc, &r.outcome, &ids) else {
                continue;
            };
            cov += s.coverage;
            unn += s.unnecessary as f64;
            total += s.total_selected as f64;
            if s.missed_any {
                miss += 1;
            }
            counted += 1;
        }
        if counted == 0 {
            continue;
        }
        let c = counted as f64;
        println!(
            "  {t:<8.2} {widened:>7} {:>9.3} {:>9.3} {:>9.2} {:>11.1}",
            cov / c,
            miss as f64 / c,
            unn / c,
            total / c
        );
    }
}
