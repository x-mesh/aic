//! 평가 데이터 스키마와 라벨 검증.
//!
//! 라벨은 모델을 돌리기 전에 확정하고, 결과를 본 뒤에는 고치지 않는다. 그 규칙을 지키려면
//! 데이터 자체가 검증을 통과해야 한다 — 겹치는 집합이나 존재하지 않는 probe ID가 섞이면
//! 확보율이 조용히 틀린 값을 낸다.

use std::collections::BTreeSet;

use aic_client::agent::diagnose::{select_probes_for_category, DIAGNOSE_CATEGORIES};
use aic_client::agent::probes::probe_exists;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// 데이터 파일 전체.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Dataset {
    pub schema_version: u32,
    /// 데이터를 확정한 날짜. 결과 보고에 함께 싣는다.
    pub generated: String,
    pub scenarios: Vec<Scenario>,
}

/// 기본 시나리오 하나. 한국어·영어 표현을 함께 갖는다.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Scenario {
    pub id: String,
    pub split: Split,
    /// 이 시나리오를 만든 기준 범주. 정답이 아니라 데이터 배분을 위한 축이다 —
    /// 정답은 `allowed_categories`다.
    pub primary_category: String,
    /// 평가 시점에 docker가 설치돼 있다고 볼지. `select_probes`의 인자로 그대로 들어간다.
    pub docker_available: bool,
    pub text: Texts,
    /// 허용 범주. 서로 다른 범주가 같은 필수 probe에 도달하면 둘 다 허용한다 —
    /// 범주는 수단이고 측정 대상은 증거 확보다.
    pub allowed_categories: Vec<String>,
    /// 증상 문장이 정당화하는 1차 증거. 비어 있으면 확보율 계산에서 제외한다.
    pub required_probes: Vec<String>,
    /// 있으면 유용하지만 없어도 감점하지 않는 항목. 기본 공통 probe가 여기 들어간다.
    ///
    /// 비워 두면 [`Scenario::useful`]이 허용 범주가 고르는 목록에서 필수를 뺀 나머지로 채운다.
    /// 손으로 적으면 범주별 목록이 바뀔 때마다 데이터를 따라 고쳐야 하고, 그 동기화 실패가
    /// 조용히 점수를 흔든다.
    #[serde(default)]
    pub useful_probes: Vec<String>,
    /// 이 사례가 무엇을 시험하는지. 하위 집합별 보고에 쓴다.
    pub traits: Vec<String>,
    pub source: String,
}

/// 개발용과 최종 평가용. 같은 시나리오의 번역·변형은 이 경계를 넘지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Dev,
    Final,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Texts {
    pub ko: String,
    pub en: String,
}

/// 평가 입력 하나 = 시나리오 × 언어.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Ko,
    En,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::Ko, Lang::En];

    pub fn as_str(self) -> &'static str {
        match self {
            Lang::Ko => "ko",
            Lang::En => "en",
        }
    }
}

impl Scenario {
    pub fn text(&self, lang: Lang) -> &str {
        match lang {
            Lang::Ko => &self.text.ko,
            Lang::En => &self.text.en,
        }
    }

    /// 필수 집합이 비어 있는 사례. 확보율 평균에서 빼고 범주 처리만 따로 집계한다.
    pub fn is_ambiguous(&self) -> bool {
        self.required_probes.is_empty()
    }

    /// 채점에 쓸 유용 집합.
    ///
    /// 명시하지 않았으면 **허용 범주들이 고르는 probe에서 필수를 뺀 나머지**다. 정답 범주를 고른
    /// 비교군의 "불필요"가 0이 되는 기준선이며, 틀린 범주를 고르면 그쪽 probe가 불필요로 잡힌다.
    pub fn useful(&self) -> BTreeSet<String> {
        if !self.useful_probes.is_empty() {
            return self.useful_probes.iter().cloned().collect();
        }
        let required: BTreeSet<&str> =
            self.required_probes.iter().map(String::as_str).collect();
        self.allowed_categories
            .iter()
            .flat_map(|cat| {
                select_probes_for_category(cat, false, self.docker_available)
                    .into_iter()
                    .map(|(id, _)| id.to_string())
            })
            .filter(|id| !required.contains(id.as_str()))
            .collect()
    }
}

impl Dataset {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("데이터 파일을 읽지 못했습니다: {}", path.display()))?;
        let ds: Dataset = serde_json::from_str(&raw)
            .with_context(|| format!("데이터 파싱 실패: {}", path.display()))?;
        ds.validate()?;
        Ok(ds)
    }

    /// 라벨이 규칙을 지키는지 확인한다. 하나라도 어기면 평가를 시작하지 않는다.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("지원하지 않는 schema_version: {}", self.schema_version);
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for sc in &self.scenarios {
            if !seen.insert(sc.id.as_str()) {
                bail!("중복 id: {}", sc.id);
            }
            if sc.text.ko.trim().is_empty() || sc.text.en.trim().is_empty() {
                bail!("{}: 한국어와 영어 표현이 둘 다 있어야 합니다", sc.id);
            }
            if !DIAGNOSE_CATEGORIES.contains(&sc.primary_category.as_str()) {
                bail!(
                    "{}: 알 수 없는 primary_category {}",
                    sc.id,
                    sc.primary_category
                );
            }
            if sc.allowed_categories.is_empty() {
                bail!("{}: allowed_categories가 비어 있습니다", sc.id);
            }
            for cat in &sc.allowed_categories {
                if !DIAGNOSE_CATEGORIES.contains(&cat.as_str()) {
                    bail!("{}: 알 수 없는 allowed_category {cat}", sc.id);
                }
            }
            for id in sc.required_probes.iter().chain(&sc.useful_probes) {
                if !probe_exists(id) {
                    bail!("{}: CATALOG에 없는 probe {id}", sc.id);
                }
            }
            let required: BTreeSet<&str> = sc.required_probes.iter().map(String::as_str).collect();
            let useful: BTreeSet<&str> = sc.useful_probes.iter().map(String::as_str).collect();
            if required.len() != sc.required_probes.len() {
                bail!("{}: required_probes에 중복이 있습니다", sc.id);
            }
            if useful.len() != sc.useful_probes.len() {
                bail!("{}: useful_probes에 중복이 있습니다", sc.id);
            }
            let overlap: Vec<&&str> = required.intersection(&useful).collect();
            if !overlap.is_empty() {
                bail!("{}: 필수와 유용이 겹칩니다: {overlap:?}", sc.id);
            }
            // 어떤 허용 범주로도 못 얻는 필수 probe가 있으면 그 사례는 아무도 만점을 못 낸다.
            // 의도한 사례(복합 증상)일 수 있으므로 막지 않고, 표시를 강제한다.
            let reachable: BTreeSet<String> = sc
                .allowed_categories
                .iter()
                .flat_map(|cat| {
                    select_probes_for_category(cat, false, sc.docker_available)
                        .into_iter()
                        .map(|(id, _)| id.to_string())
                })
                .collect();
            let unreachable: Vec<&str> = sc
                .required_probes
                .iter()
                .map(String::as_str)
                .filter(|id| !reachable.contains(*id))
                .collect();
            if !unreachable.is_empty() && !sc.traits.iter().any(|t| t == "unreachable-required") {
                bail!(
                    "{}: 허용 범주로 얻을 수 없는 필수 probe {unreachable:?} — \
                     의도한 복합 증상이면 traits에 \"unreachable-required\"를 넣으세요",
                    sc.id
                );
            }
        }
        Ok(())
    }

    /// 범주별·분할별 개수. 배분이 의도대로인지 확인할 때 쓴다.
    pub fn counts(&self) -> Vec<(String, usize, usize)> {
        DIAGNOSE_CATEGORIES
            .iter()
            .map(|cat| {
                let dev = self
                    .scenarios
                    .iter()
                    .filter(|s| s.primary_category == *cat && s.split == Split::Dev)
                    .count();
                let fin = self
                    .scenarios
                    .iter()
                    .filter(|s| s.primary_category == *cat && s.split == Split::Final)
                    .count();
                ((*cat).to_string(), dev, fin)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(required: &[&str], useful: &[&str]) -> Scenario {
        Scenario {
            id: "t-001".into(),
            split: Split::Dev,
            primary_category: "cpu".into(),
            docker_available: false,
            text: Texts {
                ko: "CPU가 높습니다".into(),
                en: "CPU is high".into(),
            },
            allowed_categories: vec!["cpu".into()],
            required_probes: required.iter().map(|s| (*s).to_string()).collect(),
            useful_probes: useful.iter().map(|s| (*s).to_string()).collect(),
            traits: vec!["single-symptom".into()],
            source: "synthetic".into(),
        }
    }

    fn dataset(scenarios: Vec<Scenario>) -> Dataset {
        Dataset {
            schema_version: 1,
            generated: "2026-09-22".into(),
            scenarios,
        }
    }

    #[test]
    fn a_valid_scenario_passes() {
        dataset(vec![scenario(&["cpu_throttle"], &["date", "host"])])
            .validate()
            .expect("검증 통과");
    }

    #[test]
    fn overlapping_required_and_useful_is_rejected() {
        // 겹치면 같은 probe가 확보율과 "불필요 아님" 양쪽에 계산돼 지표가 서로를 가린다.
        let err = dataset(vec![scenario(&["cpu_throttle"], &["cpu_throttle"])])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("겹칩니다"), "{err}");
    }

    #[test]
    fn an_unknown_probe_id_is_rejected() {
        // 오타 하나면 그 항목은 영원히 확보되지 않아 확보율이 구조적으로 1 미만이 된다.
        let err = dataset(vec![scenario(&["cpu_throttl"], &[])])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("CATALOG에 없는"), "{err}");
    }

    #[test]
    fn an_unknown_category_is_rejected() {
        let mut sc = scenario(&["cpu_throttle"], &[]);
        sc.allowed_categories = vec!["cpu".into(), "gpu".into()];
        let err = dataset(vec![sc]).validate().unwrap_err();
        assert!(err.to_string().contains("allowed_category"), "{err}");
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let err = dataset(vec![
            scenario(&["cpu_throttle"], &[]),
            scenario(&["vmstat_iowait"], &[]),
        ])
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("중복 id"), "{err}");
    }

    #[test]
    fn a_missing_translation_is_rejected() {
        // 언어별 보고가 성립하려면 두 표현이 같은 시나리오에서 나와야 한다.
        let mut sc = scenario(&["cpu_throttle"], &[]);
        sc.text.en = "  ".into();
        let err = dataset(vec![sc]).validate().unwrap_err();
        assert!(err.to_string().contains("영어"), "{err}");
    }

    #[test]
    fn an_empty_required_set_marks_the_case_ambiguous() {
        // 모호한 입력은 확보율 평균에서 빼야 한다. 0으로 세면 모든 비교군이 똑같이 끌려 내려간다.
        let sc = scenario(&[], &["date"]);
        assert!(sc.is_ambiguous());
        dataset(vec![sc])
            .validate()
            .expect("모호한 사례도 유효하다");
    }
}
