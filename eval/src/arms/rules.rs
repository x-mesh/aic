//! 규칙 기반 비교군.
//!
//! 검증 결과 규칙이 채택되어 `aic-client`의 `symptom_rules`로 옮겨졌다. 여기서는 그것을 호출한다
//! — 어휘 테이블을 두 벌 두면 실험이 운영과 다른 것을 재기 시작한다.
//!
//! 다음 라운드에서 새 규칙을 시험할 때는 `improved`를 다시 자체 구현으로 두고 `current`와
//! 비교한다. 지금은 둘이 같은 코드를 부르므로 결과도 같다.

use aic_client::agent::diagnose::diagnose_category;
use aic_client::agent::symptom_rules;

/// 규칙 버전. production 규칙을 고치면 올린다. 원시 결과에 버전이 없으면 어느 규칙으로 얻은
/// 수치인지 나중에 가릴 수 없다.
pub const RULES_VERSION: &str = "v3-production";

/// 현재 production의 범주 판정.
pub fn current(symptom: &str) -> &'static str {
    diagnose_category(Some(symptom))
}

/// 개선 규칙. 지금은 production과 같은 코드다.
pub fn improved(symptom: &str) -> &'static str {
    symptom_rules::categorize(symptom)
}

/// 규칙의 점수를 Jev의 Choice와 같은 모양으로 만든다.
///
/// 적응형 확장 로직(`probes_adaptive`)을 모델과 규칙이 공유하려면 확률 분포와 confidence가 같은
/// 자리에 있어야 한다. confidence는 `1등 / (1등 + 2등)`이며 production의
/// `CATEGORY_WIDEN_THRESHOLD` 판정과 같은 값이다.
pub fn improved_outcome(symptom: &str) -> crate::arms::ArmOutcome {
    let scores = symptom_rules::scored(symptom);
    let total: i32 = scores.iter().map(|(_, s)| *s).sum();
    let probabilities: std::collections::BTreeMap<String, f64> = if total > 0 {
        scores
            .iter()
            .map(|(cat, s)| ((*cat).to_string(), *s as f64 / total as f64))
            .collect()
    } else {
        std::collections::BTreeMap::from([("generic".to_string(), 1.0)])
    };
    let top = scores.first().map_or(0, |(_, s)| *s);
    let second = scores.get(1).map_or(0, |(_, s)| *s);
    let confidence = if top == 0 {
        1.0
    } else {
        top as f64 / (top + second) as f64
    };
    crate::arms::ArmOutcome {
        category: Some(scores.first().map_or("generic", |(c, _)| *c).to_string()),
        raw_category: None,
        confidence: Some(confidence),
        probabilities: Some(probabilities),
        attempts: 1,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_client::agent::diagnose::DIAGNOSE_CATEGORIES;

    #[test]
    fn improved_prefers_the_subject_over_the_modifier() {
        // 현행이 무너지는 자리. 대상이 수식어를 이겨야 한다.
        assert_eq!(improved("네트워크가 느려요"), "network");
        assert_eq!(improved("the network is slow"), "network");
        assert_eq!(improved("메모리 사용량이 높아"), "memory");
        assert_eq!(improved("디스크가 느려요"), "disk");
    }

    #[test]
    fn current_and_improved_now_agree() {
        // 규칙이 채택되어 production으로 옮겨졌다. 둘이 갈리면 이식이 어긋난 것이다 —
        // 다음 라운드에서 improved를 자체 구현으로 되돌리면 이 테스트를 지운다.
        for symptom in [
            "네트워크가 느려요",
            "메모리 사용량이 높아",
            "df에서 사용률이 95%로 나옵니다",
            "CPU는 정상인데 서비스가 응답하지 않습니다",
            "뭔가 이상합니다",
        ] {
            assert_eq!(current(symptom), improved(symptom), "증상: {symptom}");
        }
    }

    #[test]
    fn improved_keeps_single_symptom_answers() {
        // 개선이 쉬운 사례를 망가뜨리면 순이득이 없다.
        assert_eq!(improved("cpu 높음"), "cpu");
        assert_eq!(improved("메모리 누수"), "memory");
        assert_eq!(improved("디스크 공간 부족"), "disk");
        assert_eq!(improved("포트 연결 안 됨"), "network");
        assert_eq!(improved("프로세스가 죽음"), "process");
        assert_eq!(improved("docker 컨테이너 문제"), "docker");
        assert_eq!(improved("pod CrashLoopBackOff"), "k8s");
    }

    #[test]
    fn a_negated_subject_does_not_win() {
        assert_eq!(
            improved("CPU는 정상인데 서비스가 응답하지 않는다"),
            "process"
        );
        assert_eq!(improved("cpu is normal but the service is down"), "process");
    }

    #[test]
    fn ties_follow_the_current_branch_order() {
        // 대상 둘이 같은 점수면 현행과 같은 답을 낸다. 근거 없이 갈라지지 않게 한다.
        assert_eq!(improved("pod 네트워크 문제"), "k8s");
        assert_eq!(current("pod 네트워크 문제"), "k8s");
    }

    #[test]
    fn an_unmatched_symptom_falls_back_to_generic() {
        assert_eq!(improved("뭔가 이상합니다"), "generic");
        assert_eq!(improved(""), "generic");
    }

    #[test]
    fn token_start_matching_avoids_substring_traps() {
        // 현행은 "실행"의 `행`을 cpu로 읽는다. 어절 시작 일치는 그러지 않는다.
        assert_eq!(improved("배치 실행 결과를 모르겠다"), "generic");
        // 붙여 쓴 대상은 여전히 잡는다 — 대상 키워드는 길어 substring이 안전하다.
        assert_eq!(improved("네트워크느림"), "network");
    }

    #[test]
    fn both_rules_only_return_known_categories() {
        for symptom in [
            "네트워크가 느려요",
            "뭔가 이상합니다",
            "pod 네트워크 문제",
            "",
        ] {
            assert!(
                DIAGNOSE_CATEGORIES.contains(&current(symptom)),
                "current: {symptom}"
            );
            assert!(
                DIAGNOSE_CATEGORIES.contains(&improved(symptom)),
                "improved: {symptom}"
            );
        }
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;

    #[test]
    fn a_clear_symptom_gets_high_confidence() {
        let o = improved_outcome("메모리 누수가 의심됩니다");
        assert_eq!(o.category.as_deref(), Some("memory"));
        assert!(o.confidence.unwrap() > 0.9, "{:?}", o.confidence);
    }

    #[test]
    fn a_split_judgement_gets_low_confidence() {
        // 대상 둘이 같은 점수면 판단이 갈린 것이다. 이때 2등까지 조사할 근거가 된다.
        let o = improved_outcome("pod 네트워크 문제");
        assert_eq!(o.category.as_deref(), Some("k8s"));
        let c = o.confidence.unwrap();
        assert!((c - 0.5).abs() < 0.01, "동점이면 0.5여야 한다: {c}");
    }

    #[test]
    fn an_unmatched_symptom_reports_generic_with_full_confidence() {
        // 후보가 하나뿐이면 갈릴 것이 없다 — 넓혀도 얻는 게 없으므로 확장하지 않는다.
        let o = improved_outcome("뭔가 이상합니다");
        assert_eq!(o.category.as_deref(), Some("generic"));
        assert_eq!(o.confidence, Some(1.0));
    }

    #[test]
    fn the_outcome_category_matches_the_plain_rule() {
        for symptom in [
            "네트워크가 느려요",
            "메모리 사용량이 높아",
            "pod CrashLoopBackOff",
            "df에서 사용률이 95%로 나옵니다",
            "스레드 하나가 데드락으로 보입니다",
        ] {
            assert_eq!(
                improved_outcome(symptom).category.as_deref(),
                Some(improved(symptom)),
                "증상: {symptom}"
            );
        }
    }

    #[test]
    fn probabilities_rank_the_same_way_as_scores() {
        let o = improved_outcome("컨테이너 하나가 CPU를 다 쓰고 있습니다");
        let probs = o.probabilities.unwrap();
        let top = o.category.unwrap();
        let best = probs
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .unwrap();
        assert_eq!(*best.0, top);
    }
}
