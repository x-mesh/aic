//! 범주를 고르는 네 가지 방식.
//!
//! 네 비교군의 차이는 **범주 판정 하나**뿐이다. 고른 범주를 probe 목록으로 바꾸는 일은
//! `aic-client`의 [`select_probes_for_category`]가 전담한다. 목록을 여기서 복제하면 두 벌이
//! 갈라지고, 그 시점부터 이 실험은 운영과 다른 것을 재게 된다.

pub mod jev;
pub mod llm;
pub mod rules;

use std::collections::BTreeMap;

use aic_client::agent::diagnose::select_probes_for_category;

/// 비교군 한 번의 판정 결과.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ArmOutcome {
    /// 고른 범주. `None`이면 실패(API 오류 또는 목록 밖 응답)이며 확보율을 0으로 센다.
    pub category: Option<String>,
    /// 목록 밖 값을 받았을 때 그 원문. 무엇을 만들어냈는지 기록해야 한계를 보고할 수 있다.
    pub raw_category: Option<String>,
    pub confidence: Option<f64>,
    pub probabilities: Option<BTreeMap<String, f64>>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// 재시도를 포함한 총 시도 수. 지연과 비용을 합산할 때 쓴다.
    pub attempts: u32,
    /// 첫 요청부터 결과 또는 실패 확정까지.
    pub latency_ms: u64,
    pub error: Option<String>,
}

impl ArmOutcome {
    pub fn failed(error: impl Into<String>, attempts: u32, latency_ms: u64) -> Self {
        Self {
            attempts,
            latency_ms,
            error: Some(error.into()),
            ..Default::default()
        }
    }

    pub fn is_failure(&self) -> bool {
        self.category.is_none()
    }
}

/// 고른 범주로 probe ID 목록을 만든다.
///
/// `full_sweep`은 항상 false다 — 평가 입력에는 언제나 증상 문자열이 있고, 증상 없는 전체 점검은
/// 모델을 거치지 않는다(PRD 불변 조건).
pub fn probes_for(category: &str, docker_available: bool) -> Vec<&'static str> {
    select_probes_for_category(category, false, docker_available)
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_client::agent::diagnose::{select_probes, DIAGNOSE_CATEGORIES};
    use aic_client::agent::probes::probe_exists;

    #[test]
    fn every_category_maps_to_catalog_probes() {
        // 모델이 목록 안의 범주를 돌려주는 한, 나오는 probe도 전부 실재해야 한다. 이게 깨지면
        // "모델은 명령을 만들어내지 않는다"는 불변 조건이 성립하지 않는다.
        for cat in DIAGNOSE_CATEGORIES {
            for docker in [false, true] {
                let ids = probes_for(cat, docker);
                assert!(!ids.is_empty(), "{cat}: probe가 비었다");
                for id in ids {
                    assert!(probe_exists(id), "{cat}: CATALOG에 없는 {id}");
                }
            }
        }
    }

    #[test]
    fn the_current_arm_matches_the_production_path() {
        // 현행 비교군이 운영과 다른 것을 고르면 baseline 자체가 틀린다.
        for symptom in ["cpu 높음", "네트워크가 느려요", "pod CrashLoopBackOff"] {
            for docker in [false, true] {
                let production: Vec<&str> = select_probes(Some(symptom), docker)
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect();
                let via_category = probes_for(rules::current(symptom), docker);
                assert_eq!(production, via_category, "증상: {symptom}, docker={docker}");
            }
        }
    }
}
