//! `docs/PRD-JEV-PROBE-JUDGMENT.md`의 평가 데이터 스키마와 라벨 검증.
//!
//! `scenario.rs`(probe **선택** 평가)와 계약이 다르다 — 여기서는 정답 라벨을 사람이 정하지 않고
//! `scanned_severities`(스캐너의 실제 판정)에서 파생한다. 선언 라벨이 실제 판정과 어긋나면 fixture
//! 자체가 결함이므로, 데이터를 확정하기 전에 검증이 거부해야 한다.

use std::collections::BTreeSet;

use aic_client::agent::diagnose::scanned_severities;
use aic_client::agent::probes::probe_exists;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// `scan_findings`가 판정하는 9개 probe. `docs/PRD-JEV-PROBE-JUDGMENT.md` 2절이 근거를 남긴다 —
/// `journal_errors`는 다른 섹션(`journal_daemon_errors`의 구조화 파싱 성공 여부)에 의존해 발화하므로
/// 섹션 하나를 독립 fixture로 다루는 이 실험에서 뺐다.
pub const JUDGED_PROBES: [&str; 9] = [
    "disk",
    "inodes",
    "dmesg_oom",
    "journal_daemon_errors",
    "proc_states",
    "failed_units",
    "fd",
    "proc_fd_top",
    "swap_usage",
];

/// 데이터 파일 전체.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JudgmentDataset {
    pub schema_version: u32,
    /// 데이터를 확정한 날짜.
    pub generated: String,
    pub cases: Vec<JudgmentCase>,
}

/// 사례 하나 = 섹션 하나.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JudgmentCase {
    pub id: String,
    pub split: Split,
    pub probe_id: String,
    /// 전체 섹션 텍스트: `## <probe_id>` 줄 + `command:`/`exit_code=` 줄 + stdout(+ stderr) 본문.
    /// `judge_judge`의 state 조립이 여기서 stderr를 뺀 나머지를 그대로 옮긴다.
    pub section: String,
    pub expected: Expected,
    /// 근거: 기존 스캐너 단위 테스트에서 파생했는지, `probes.rs`의 명령 문자열이 규정하는 출력
    /// 형태에서 새로 작성했는지. 비면 검증이 거부한다 — 실제 호스트 출력이 섞이는 것을 막는
    /// 유일한 데이터 단계 방어선이다.
    pub source: String,
    /// 이 사례가 무엇을 시험하는지(obvious-positive/boundary-positive/boundary-negative/
    /// clean-negative/format-variant). 하위 집합별 보고에 쓴다.
    pub traits: Vec<String>,
}

/// 개발용과 최종 평가용. 같은 fixture의 변형은 이 경계를 넘지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Dev,
    Final,
}

/// 스캐너가 매기는 정답 라벨. `Severity`(crate 내부 타입)를 그대로 쓰지 않고 evaluation 쪽에
/// 독립된 표현을 둔다 — 이 파일은 `scanned_severities`의 문자열 계약(`"warn"`/`"crit"`)에만
/// 의존해야 하고, `aic-client`의 내부 enum 표현에 결합되면 안 된다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Expected {
    None,
    Warn,
    Crit,
}

impl Expected {
    pub fn as_str(self) -> &'static str {
        match self {
            Expected::None => "none",
            Expected::Warn => "warn",
            Expected::Crit => "crit",
        }
    }

    fn from_scanner_label(label: Option<&str>) -> Result<Self> {
        match label {
            None => Ok(Expected::None),
            Some("warn") => Ok(Expected::Warn),
            Some("crit") => Ok(Expected::Crit),
            Some(other) => bail!("scanned_severities가 알 수 없는 라벨을 냈습니다: {other}"),
        }
    }
}

impl JudgmentDataset {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("데이터 파일을 읽지 못했습니다: {}", path.display()))?;
        let ds: JudgmentDataset = serde_json::from_str(&raw)
            .with_context(|| format!("데이터 파싱 실패: {}", path.display()))?;
        ds.validate()?;
        Ok(ds)
    }

    /// 라벨이 규칙을 지키는지 확인한다. 하나라도 어기면 평가를 시작하지 않는다. 네트워크를 쓰지
    /// 않는다 — `scanned_severities`는 순수 함수다.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("지원하지 않는 schema_version: {}", self.schema_version);
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut section_by_split: std::collections::BTreeMap<Split, BTreeSet<&str>> =
            std::collections::BTreeMap::new();
        let mut label_errors: Vec<String> = Vec::new();

        for c in &self.cases {
            if !seen.insert(c.id.as_str()) {
                bail!("중복 id: {}", c.id);
            }
            if !JUDGED_PROBES.contains(&c.probe_id.as_str()) {
                bail!(
                    "{}: scan_findings가 판정하지 않는 probe {} (판정 대상: {JUDGED_PROBES:?})",
                    c.id,
                    c.probe_id
                );
            }
            if !probe_exists(&c.probe_id) {
                bail!("{}: CATALOG에 없는 probe {}", c.id, c.probe_id);
            }
            if c.source.trim().is_empty() {
                bail!(
                    "{}: source가 비어 있습니다 — 실제 호스트 출력을 섞지 않았다는 근거가 없습니다",
                    c.id
                );
            }
            let expected_header = format!("## {}", c.probe_id);
            if !c.section.trim_start().starts_with(&expected_header) {
                bail!(
                    "{}: section이 '{expected_header}'로 시작하지 않습니다",
                    c.id
                );
            }

            section_by_split
                .entry(c.split)
                .or_default()
                .insert(c.section.as_str());

            // 정답 라벨 대조: 실제 스캐너가 판정하는 라벨과 선언 라벨이 어긋나면 fixture 결함이다.
            let actual = scanned_severities(&c.section);
            for (probe_id, _) in &actual {
                if probe_id != &c.probe_id {
                    bail!(
                        "{}: section 헤더는 {}인데 스캐너가 다른 probe {probe_id}에서 발견을 냈습니다 \
                         — 섹션 하나에 여러 '## ' 헤더가 섞였을 수 있습니다",
                        c.id,
                        c.probe_id
                    );
                }
            }
            let actual_label = actual
                .iter()
                .find(|(probe_id, _)| probe_id == &c.probe_id)
                .map(|(_, label)| *label);
            let actual_expected = Expected::from_scanner_label(actual_label)
                .with_context(|| format!("{}: 스캐너 라벨 해석 실패", c.id))?;
            if actual_expected != c.expected {
                label_errors.push(format!(
                    "{}: 선언 라벨 {} != 스캐너 판정 {} (probe {})",
                    c.id,
                    c.expected.as_str(),
                    actual_expected.as_str(),
                    c.probe_id
                ));
            }
        }

        if !label_errors.is_empty() {
            bail!(
                "선언 라벨과 스캐너 판정이 어긋나는 사례 {}건:\n{}",
                label_errors.len(),
                label_errors.join("\n")
            );
        }

        // dev/final 분할이 겹치면 최종 평가가 개발 단계에서 이미 본 입력을 재는 것이 된다.
        if let (Some(dev), Some(fin)) = (
            section_by_split.get(&Split::Dev),
            section_by_split.get(&Split::Final),
        ) {
            let overlap: Vec<&&str> = dev.intersection(fin).collect();
            if !overlap.is_empty() {
                bail!(
                    "dev와 final 분할에 동일한 section이 {}건 겹칩니다",
                    overlap.len()
                );
            }
        }

        Ok(())
    }

    /// probe별·분할별 개수. 배분이 의도대로인지 확인할 때 쓴다.
    pub fn counts(&self) -> Vec<(String, usize, usize)> {
        JUDGED_PROBES
            .iter()
            .map(|probe| {
                let dev = self
                    .cases
                    .iter()
                    .filter(|c| c.probe_id == *probe && c.split == Split::Dev)
                    .count();
                let fin = self
                    .cases
                    .iter()
                    .filter(|c| c.probe_id == *probe && c.split == Split::Final)
                    .count();
                ((*probe).to_string(), dev, fin)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(
        id: &str,
        split: Split,
        probe_id: &str,
        section: &str,
        expected: Expected,
    ) -> JudgmentCase {
        JudgmentCase {
            id: id.to_string(),
            split,
            probe_id: probe_id.to_string(),
            section: section.to_string(),
            expected,
            source: "synthetic".to_string(),
            traits: vec!["clean-negative".to_string()],
        }
    }

    fn dataset(cases: Vec<JudgmentCase>) -> JudgmentDataset {
        JudgmentDataset {
            schema_version: 1,
            generated: "2026-09-22".to_string(),
            cases,
        }
    }

    #[test]
    fn a_valid_negative_case_passes() {
        let sec = "## disk\ncommand: df -h\nexit_code=0 duration_ms=1 truncated=false cwd=/\n\
--- stdout ---\n/dev/sda1 100G 10G 90G 10% /\n--- stderr ---\n\n";
        dataset(vec![case("d-001", Split::Dev, "disk", sec, Expected::None)])
            .validate()
            .expect("검증 통과");
    }

    #[test]
    fn a_mismatched_label_is_rejected() {
        let sec = "## disk\ncommand: df -h\nexit_code=0 duration_ms=1 truncated=false cwd=/\n\
--- stdout ---\n/dev/sda1 100G 95G 5G 95% /\n--- stderr ---\n\n";
        // 실제로는 warn인데 none으로 잘못 선언했다.
        let err = dataset(vec![case("d-002", Split::Dev, "disk", sec, Expected::None)])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("어긋나는"), "{err}");
    }

    #[test]
    fn an_empty_source_is_rejected() {
        let sec = "## disk\n--- stdout ---\n/dev/sda1 100G 10G 90G 10% /\n--- stderr ---\n\n";
        let mut c = case("d-003", Split::Dev, "disk", sec, Expected::None);
        c.source = "  ".to_string();
        let err = dataset(vec![c]).validate().unwrap_err();
        assert!(err.to_string().contains("source가 비어"), "{err}");
    }

    #[test]
    fn a_probe_outside_the_judged_nine_is_rejected() {
        let sec = "## uptime\n--- stdout ---\nload average: 0.1\n--- stderr ---\n\n";
        let err = dataset(vec![case(
            "d-004",
            Split::Dev,
            "uptime",
            sec,
            Expected::None,
        )])
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("판정하지 않는 probe"), "{err}");
    }

    #[test]
    fn overlapping_sections_across_splits_are_rejected() {
        let sec = "## disk\n--- stdout ---\n/dev/sda1 100G 10G 90G 10% /\n--- stderr ---\n\n";
        let err = dataset(vec![
            case("d-005", Split::Dev, "disk", sec, Expected::None),
            case("d-006", Split::Final, "disk", sec, Expected::None),
        ])
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("겹칩니다"), "{err}");
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let sec = "## disk\n--- stdout ---\n/dev/sda1 100G 10G 90G 10% /\n--- stderr ---\n\n";
        let err = dataset(vec![
            case("d-007", Split::Dev, "disk", sec, Expected::None),
            case("d-007", Split::Dev, "disk", sec, Expected::None),
        ])
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("중복 id"), "{err}");
    }
}
