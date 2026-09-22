//! `docs/PRD-JEV-PROBE-JUDGMENT.md` 7절 — judge-run 원시 결과를 혼동행렬과 신뢰구간으로 채점한다.
//!
//! `scoring.rs`(probe **선택** 평가)는 두 비교군을 짝지어 차이를 잰다. 여기는 비교할 두 번째
//! 비교군이 없다 — 스캐너 자체가 정답이므로 Jev 하나의 절대 재현율·정밀도만 잰다. 그래서
//! `paired_bootstrap_ci`(차이의 신뢰구간)를 그대로 쓰지 않고, 같은 재표집 방식(사례 단위, 고정
//! 시드 LCG)을 단일 비율에 맞게 다시 쓴다.

use std::collections::BTreeMap;

use crate::judgment::{Expected, JudgmentDataset, Split};
use crate::JudgeRecord;

/// judge-score 전용 bootstrap 반복 수·시드. `main.rs`의 probe-선택 평가와 같은 값을 써서
/// "고정 시드라 재현 가능하다"는 관례를 유지한다.
pub const BOOTSTRAP_ITERATIONS: usize = 2000;
pub const BOOTSTRAP_SEED: u64 = 20260922;

/// 이진 판정 하나. "정상"이 아니면(경고·위험) 이상으로 본다 — 심각도 등급(warn/crit) 자체의
/// 일치는 별도 지표(심각도 일치율)로 센다.
fn is_abnormal_expected(e: Expected) -> bool {
    e != Expected::None
}

fn is_abnormal_label(label: Option<&str>) -> bool {
    matches!(label, Some("warn") | Some("crit"))
}

/// 사례 하나의 채점 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseOutcome {
    /// 성공 응답. 이진 정답(TP/FP/FN/TN)과, 둘 다 이상으로 본 경우의 등급 일치 여부를 담는다.
    Scored {
        expected_abnormal: bool,
        got_abnormal: bool,
        severity_match: Option<bool>,
    },
    Oversize,
    Failure,
}

fn classify(record: &JudgeRecord) -> CaseOutcome {
    if record.outcome.oversize {
        return CaseOutcome::Oversize;
    }
    let Some(label) = record.outcome.label.as_deref() else {
        return CaseOutcome::Failure;
    };
    let expected_abnormal = is_abnormal_expected(record.expected);
    let got_abnormal = is_abnormal_label(Some(label));
    let severity_match =
        (expected_abnormal && got_abnormal).then(|| record.expected.as_str() == label);
    CaseOutcome::Scored {
        expected_abnormal,
        got_abnormal,
        severity_match,
    }
}

/// 혼동행렬(2x2, 이상 대 정상) + 파생 지표.
#[derive(Debug, Clone, Copy, Default)]
struct ConfusionCounts {
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
    oversize: usize,
    failure: usize,
    severity_hit: usize,
    severity_total: usize,
}

impl ConfusionCounts {
    fn add(&mut self, outcome: CaseOutcome) {
        match outcome {
            CaseOutcome::Oversize => self.oversize += 1,
            CaseOutcome::Failure => self.failure += 1,
            CaseOutcome::Scored {
                expected_abnormal,
                got_abnormal,
                severity_match,
            } => {
                match (expected_abnormal, got_abnormal) {
                    (true, true) => self.tp += 1,
                    (true, false) => self.fn_ += 1,
                    (false, true) => self.fp += 1,
                    (false, false) => self.tn += 1,
                }
                if let Some(hit) = severity_match {
                    self.severity_total += 1;
                    if hit {
                        self.severity_hit += 1;
                    }
                }
            }
        }
    }

    fn scored_total(&self) -> usize {
        self.tp + self.fp + self.fn_ + self.tn
    }

    /// 스캐너 재현율 = TP / (TP + FN). 분모가 0이면 계산 불가(NaN)로 남긴다 — 0으로 채우면
    /// "재현율 0"과 "측정 불가"가 구분되지 않는다.
    fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            f64::NAN
        } else {
            self.tp as f64 / denom as f64
        }
    }

    /// 스캐너 대비 정밀도 = TP / (TP + FP).
    fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            f64::NAN
        } else {
            self.tp as f64 / denom as f64
        }
    }

    fn severity_agreement(&self) -> f64 {
        if self.severity_total == 0 {
            f64::NAN
        } else {
            self.severity_hit as f64 / self.severity_total as f64
        }
    }
}

/// `values[i]`가 true인 비율의 percentile bootstrap 95% CI. 재표집 단위는 호출부가 넘기는
/// `values`의 각 원소(사례 하나) — `scoring::paired_bootstrap_ci`와 같은 LCG·시드 관례를 쓴다.
fn bootstrap_ci_rate(values: &[bool], iterations: usize, seed: u64) -> (f64, f64) {
    if values.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let mut state = seed | 1;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let mut rates = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let hit = (0..values.len())
            .filter(|_| values[next() % values.len()])
            .count();
        rates.push(hit as f64 / values.len() as f64);
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let lo = rates[((rates.len() as f64) * 0.025) as usize];
    let hi = rates[(((rates.len() as f64) * 0.975) as usize).min(rates.len() - 1)];
    (lo, hi)
}

/// 사례 하나가 TP인지(재현율 분모: expected_abnormal 중 got_abnormal도 true) — recall 신뢰구간용.
fn recall_hits(records: &[&JudgeRecord]) -> Vec<bool> {
    records
        .iter()
        .filter_map(|r| match classify(r) {
            CaseOutcome::Scored {
                expected_abnormal: true,
                got_abnormal,
                ..
            } => Some(got_abnormal),
            _ => None,
        })
        .collect()
}

/// 사례 하나가 TP인지(정밀도 분모: got_abnormal 중 expected_abnormal도 true) — precision 신뢰구간용.
fn precision_hits(records: &[&JudgeRecord]) -> Vec<bool> {
    records
        .iter()
        .filter_map(|r| match classify(r) {
            CaseOutcome::Scored {
                expected_abnormal,
                got_abnormal: true,
                ..
            } => Some(expected_abnormal),
            _ => None,
        })
        .collect()
}

/// 최종 분할 1회차만 주 게이트로 쓴다(PRD 6절). 반복 3회 중 좋은 쪽을 고르지 않는다.
pub fn report(records: &[JudgeRecord], ds: &JudgmentDataset) {
    let primary: Vec<&JudgeRecord> = records
        .iter()
        .filter(|r| r.split == Split::Final && r.repeat == 1)
        .collect();
    if primary.is_empty() {
        println!("최종 분할 1회차 결과가 없습니다");
        return;
    }

    let mut overall = ConfusionCounts::default();
    let mut per_probe: BTreeMap<&str, ConfusionCounts> = BTreeMap::new();
    for r in &primary {
        let outcome = classify(r);
        overall.add(outcome);
        per_probe
            .entry(r.probe_id.as_str())
            .or_default()
            .add(outcome);
    }

    println!("## 최종 분할(1회차) — 전체");
    println!();
    println!(
        "  사례 {}  oversize {}  실패 {}  채점 {}",
        primary.len(),
        overall.oversize,
        overall.failure,
        overall.scored_total()
    );
    println!(
        "  TP {}  FP {}  FN {}  TN {}",
        overall.tp, overall.fp, overall.fn_, overall.tn
    );
    println!("  스캐너 재현율   = {:.3}", overall.recall());
    println!("  스캐너 대비 정밀도 = {:.3}", overall.precision());
    println!(
        "  심각도 일치율(warn 대 crit, n={}) = {:.3}",
        overall.severity_total,
        overall.severity_agreement()
    );

    let recall_ci = bootstrap_ci_rate(&recall_hits(&primary), BOOTSTRAP_ITERATIONS, BOOTSTRAP_SEED);
    let precision_ci = bootstrap_ci_rate(
        &precision_hits(&primary),
        BOOTSTRAP_ITERATIONS,
        BOOTSTRAP_SEED,
    );
    println!(
        "  재현율 95% CI [{:.3}, {:.3}]  정밀도 95% CI [{:.3}, {:.3}]  (bootstrap, n_iter={BOOTSTRAP_ITERATIONS})",
        recall_ci.0, recall_ci.1, precision_ci.0, precision_ci.1
    );

    println!();
    println!("## probe별");
    println!();
    println!(
        "  {:<24} {:>4} {:>4} {:>9} {:>9} {:>9} {:>5} {:>5}",
        "probe", "n", "채점", "재현율", "정밀도", "등급일치", "over", "실패"
    );
    for (probe, c) in &per_probe {
        println!(
            "  {:<24} {:>4} {:>4} {:>9.3} {:>9.3} {:>9.3} {:>5} {:>5}",
            probe,
            c.oversize + c.failure + c.scored_total(),
            c.scored_total(),
            c.recall(),
            c.precision(),
            c.severity_agreement(),
            c.oversize,
            c.failure
        );
    }

    // 반복 일치율: 최종 분할 3회 중 같은 입력이 같은 라벨을 냈는가.
    let mut by_case: BTreeMap<&str, Vec<Option<&str>>> = BTreeMap::new();
    for r in records.iter().filter(|r| r.split == Split::Final) {
        by_case
            .entry(r.case_id.as_str())
            .or_default()
            .push(r.outcome.label.as_deref());
    }
    let mut agreed = 0usize;
    let mut counted = 0usize;
    for labels in by_case.values() {
        if labels.len() < 2 {
            continue;
        }
        counted += 1;
        if labels.iter().all(|l| *l == labels[0]) {
            agreed += 1;
        }
    }
    if counted > 0 {
        println!();
        println!(
            "## 반복 일치율 — 최종 분할 3회 중 같은 라벨 {agreed}/{counted} ({:.3})",
            agreed as f64 / counted as f64
        );
    }

    confidence_buckets(records);
    noul_threshold_curve(&primary);
    let _ = ds; // trait별 세분 보고는 T8의 삼분 표에서 원문과 함께 다룬다.
}

/// confidence 구간별 정확도. **개발 분할에서만** 계산한다 — 2단계 게이트 후보 임계를 최종
/// 분할로 고르면 그 수치는 과적합이다(PRD 6절).
const CONFIDENCE_BUCKETS: [(f64, f64); 5] = [
    (0.0, 0.5),
    (0.5, 0.7),
    (0.7, 0.9),
    (0.9, 0.99),
    (0.99, 1.01),
];

fn confidence_buckets(records: &[JudgeRecord]) {
    let dev: Vec<&JudgeRecord> = records
        .iter()
        .filter(|r| r.split == Split::Dev && r.outcome.confidence.is_some())
        .collect();
    if dev.is_empty() {
        return;
    }
    println!();
    println!("## confidence 구간별 정확도 — 개발 분할 전용(2단계 임계 후보는 여기서만 고른다)");
    println!();
    println!("  {:<14} {:>5} {:>9}", "구간", "n", "정확도");
    for (lo, hi) in CONFIDENCE_BUCKETS {
        let subset: Vec<&&JudgeRecord> = dev
            .iter()
            .filter(|r| {
                let c = r.outcome.confidence.unwrap_or(0.0);
                c >= lo && c < hi
            })
            .collect();
        if subset.is_empty() {
            continue;
        }
        let hit = subset
            .iter()
            .filter(|r| r.outcome.label.as_deref() == Some(r.expected.as_str()))
            .count();
        println!(
            "  [{lo:.2}, {hi:.2})  {:>5} {:>9.3}",
            subset.len(),
            hit as f64 / subset.len() as f64
        );
    }
}

/// Noul 보조 신호의 임계값별 정밀도·재현율. **주 지표는 아니다** — Choice(`label`)만 게이트를
/// 결정한다. 여기는 2단계에서 Noul을 배선할 가치가 있는지 보는 참고 자료다.
fn noul_threshold_curve(primary: &[&JudgeRecord]) {
    let with_noul: Vec<&&JudgeRecord> = primary
        .iter()
        .filter(|r| r.outcome.noul.is_some() && !r.outcome.oversize)
        .collect();
    if with_noul.is_empty() {
        return;
    }
    println!();
    println!("## Noul 보조 신호 — 임계값별 정밀도·재현율(참고, 게이트에 미반영)");
    println!();
    println!(
        "  {:<8} {:>5} {:>5} {:>5} {:>5} {:>9} {:>9}",
        "임계값", "TP", "FP", "FN", "TN", "재현율", "정밀도"
    );
    for t in [0.1, 0.3, 0.5, 0.7, 0.9] {
        let (mut tp, mut fp, mut fn_, mut tn) = (0usize, 0usize, 0usize, 0usize);
        for r in &with_noul {
            let expected_abnormal = is_abnormal_expected(r.expected);
            let got_abnormal = r.outcome.noul.unwrap_or(0.0) >= t;
            match (expected_abnormal, got_abnormal) {
                (true, true) => tp += 1,
                (true, false) => fn_ += 1,
                (false, true) => fp += 1,
                (false, false) => tn += 1,
            }
        }
        let recall = if tp + fn_ == 0 {
            f64::NAN
        } else {
            tp as f64 / (tp + fn_) as f64
        };
        let precision = if tp + fp == 0 {
            f64::NAN
        } else {
            tp as f64 / (tp + fp) as f64
        };
        println!("  {t:<8.2} {tp:>5} {fp:>5} {fn_:>5} {tn:>5} {recall:>9.3} {precision:>9.3}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arms::jev_judge::JudgeOutcome;

    fn rec(
        split: Split,
        repeat: u32,
        probe: &str,
        expected: Expected,
        label: Option<&str>,
    ) -> JudgeRecord {
        JudgeRecord {
            case_id: format!("{probe}-{repeat}"),
            split,
            probe_id: probe.to_string(),
            repeat,
            model: "jev-1.13.0".to_string(),
            question_version: "v2".to_string(),
            input_sha256: "deadbeef".to_string(),
            expected,
            outcome: JudgeOutcome {
                label: label.map(str::to_string),
                ..Default::default()
            },
        }
    }

    #[test]
    fn a_true_positive_counts_toward_recall_and_precision() {
        let records = [rec(Split::Final, 1, "disk", Expected::Warn, Some("warn"))];
        let primary: Vec<&JudgeRecord> = records.iter().collect();
        let mut c = ConfusionCounts::default();
        for r in &primary {
            c.add(classify(r));
        }
        assert_eq!(c.tp, 1);
        assert_eq!(c.recall(), 1.0);
        assert_eq!(c.precision(), 1.0);
    }

    #[test]
    fn oversize_and_failure_are_excluded_from_the_confusion_matrix() {
        let mut failed = rec(Split::Final, 1, "disk", Expected::Warn, None);
        failed.outcome.error = Some("응답에 choice가 없습니다".to_string());
        let mut oversized = rec(Split::Final, 1, "disk", Expected::Warn, None);
        oversized.outcome.oversize = true;
        let mut c = ConfusionCounts::default();
        c.add(classify(&failed));
        c.add(classify(&oversized));
        assert_eq!(c.failure, 1);
        assert_eq!(c.oversize, 1);
        assert_eq!(
            c.scored_total(),
            0,
            "실패·oversize는 주 지표에서 빠져야 한다"
        );
    }

    #[test]
    fn a_severity_mismatch_within_abnormal_still_counts_as_a_binary_true_positive() {
        // warn을 crit으로 잘못 짚어도 "정상 대 이상" 이진 재현율에서는 맞힌 것이다.
        // 등급 자체의 일치는 severity_agreement가 별도로 잰다.
        let r = rec(
            Split::Final,
            1,
            "failed_units",
            Expected::Warn,
            Some("crit"),
        );
        let outcome = classify(&r);
        match outcome {
            CaseOutcome::Scored {
                expected_abnormal,
                got_abnormal,
                severity_match,
            } => {
                assert!(expected_abnormal && got_abnormal);
                assert_eq!(severity_match, Some(false));
            }
            other => panic!("expected Scored, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_ci_is_deterministic_for_a_fixed_seed() {
        let values = vec![true, true, false, true, false, true, true, false];
        let a = bootstrap_ci_rate(&values, 500, 7);
        let b = bootstrap_ci_rate(&values, 500, 7);
        assert_eq!(a, b);
        assert!(a.0 <= a.1);
    }
}
