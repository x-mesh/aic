//! 규칙 비교군: 결정적 후보에서 고정 우선순위로 첫 후보를 고른다.
//!
//! 후보가 문제 행으로 좁혀져 있으면 "무엇을 고를까"는 거의 남지 않는다. 이 비교군이 Jev와 같은 점수를
//! 내면 follow-up 선택에 모델이 필요 없다는 뜻이고(1단계와 같은 물음), Jev만 맞히는 사례가 있다면
//! 그것이 모델의 몫이다. 네트워크 없음.

use crate::arms::jev_followup::{FollowupOutcome, NONE_CHOICE};
use crate::followup::candidates;

pub const RULES_VERSION: &str = "rules-v1";

/// 우선순위: 가장 구체적인 계열부터. 여러 계열에 후보가 있으면 앞쪽이 이긴다.
const PRIORITY: &[&str] = &[
    "journal_unit",
    "proc_fd",
    "docker_logs",
    "k8s_pod_describe",
    "k8s_node_describe",
];

/// Jev와 같은 형태로 돌려준다 — 채점기가 두 비교군을 같은 코드로 읽는다.
pub fn choose(evidence: &str) -> FollowupOutcome {
    let started = std::time::Instant::now();
    let cands = candidates(evidence);
    let pick = PRIORITY.iter().find_map(|t| {
        cands
            .get(t)
            .and_then(|v| v.first())
            .map(|a| (*t, a.clone()))
    });
    let latency_ms = started.elapsed().as_millis() as u64;
    match pick {
        Some((t, a)) => FollowupOutcome {
            line: Some(format!("{t} {a}")),
            template: Some(t.to_string()),
            raw_template: Some(t.to_string()),
            arg: Some(a),
            attempts: 1,
            latency_ms,
            ..Default::default()
        },
        None => FollowupOutcome {
            template: Some(NONE_CHOICE.to_string()),
            raw_template: Some(NONE_CHOICE.to_string()),
            attempts: 1,
            latency_ms,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_first_candidate_of_the_highest_priority_template() {
        let ev = "## failed_units\ncommand: x\nexit_code=0\n--- stdout ---\n\
● nginx.service loaded failed failed Web\nredis.service loaded failed failed KV\n\n--- stderr ---\n";
        let o = choose(ev);
        assert_eq!(o.line.as_deref(), Some("journal_unit nginx.service"));
        assert!(!o.is_failure());
    }

    #[test]
    fn no_candidates_means_none() {
        let o = choose("## disk\ncommand: df\nexit_code=0\n--- stdout ---\n/dev/sda1 100G 5G 95G 5% /\n\n--- stderr ---\n");
        assert_eq!(o.template.as_deref(), Some(NONE_CHOICE));
        assert!(o.line.is_none() && !o.is_failure());
    }
}
