//! 명령 실패의 원인 범주 분류 실험 — 데이터셋.
//!
//! 앞선 세 실험(증상→범주, probe 판정, follow-up 선택)은 전부 **형식이 안정적인 표**를 입력으로
//! 줬다. `failed_units`·`docker ps`·`kubectl get pods`·`proc_fd_top`은 파싱하면 답이 나오므로
//! 결정적 규칙이 이기는 것이 당연했고, 실제로 세 번 다 그랬다. 이 실험은 그 편향을 뺀다: 입력은
//! 형식이 없는 명령 실패 출력이고, 정답은 구성상 만들 수 없어 사람이 라벨을 매긴다.
//!
//! 대상은 `error_analyzer::deterministic_known_error`가 **못 잡는** 실패다. 잡는 것(command not
//! found, permission denied, 포트 점유, git non-fast-forward, docker daemon)은 이미 LLM을 거치지
//! 않으므로 물어볼 이유가 없다.
//!
//! 분할 규약: 개발 분할은 출력을 전부 읽고 규칙·질문·프롬프트를 맞추는 데 쓴다. 최종 분할은 명령을
//! 고를 때 **의도한 범주**로만 라벨을 달고 출력은 읽지 않았다 — 규칙을 쓴 사람이 새 데이터도 쓰면,
//! 새 데이터가 규칙 어휘를 닮아 규칙이 부풀려질 수 있어서다.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrCauseDataset {
    pub schema_version: u32,
    pub generated: String,
    /// 범주 id → 설명. 설명은 **다음 조치**를 말한다 — 표면 어휘가 아니라 조치가 범주를 가른다.
    pub categories: BTreeMap<String, String>,
    pub cases: Vec<ErrCase>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrCase {
    pub id: String,
    pub split: Split,
    pub command: String,
    pub exit_code: i64,
    /// 실제로 실행해 받은 stdout+stderr. 개인 경로만 일반화했고 형식은 그대로다.
    pub output: String,
    /// 타당한 범주들. 둘이면 출력만으로는 가릴 수 없는 사례다(예: docker pull 실패가 이름 오류인지
    /// 로그인 부재인지). 버리지 않는 이유는 운영에서 그런 출력이 흔해서다.
    pub accepted: Vec<String>,
    pub traits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Dev,
    Final,
}

/// 모델·규칙에 보여줄 입력. 명령과 종료 코드와 출력이 전부다.
///
/// 출력은 실제 호스트에서 받은 것이므로 전송 전에 production과 같은 redaction을 거친다.
pub fn render_input(case: &ErrCase) -> String {
    let body = aic_common::redaction::redact(&case.output).0;
    format!(
        "$ {}\nexit_code={}\n--- output ---\n{}",
        case.command, case.exit_code, body
    )
}

impl ErrCauseDataset {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("데이터 파일을 읽지 못했습니다: {}", path.display()))?;
        let ds: Self = serde_json::from_str(&raw)
            .with_context(|| format!("데이터 파싱 실패: {}", path.display()))?;
        ds.validate()?;
        Ok(ds)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("지원하지 않는 schema_version: {}", self.schema_version);
        }
        if self.categories.len() < 2 {
            bail!("범주가 2개 미만입니다");
        }
        let mut seen = std::collections::BTreeSet::new();
        for c in &self.cases {
            if !seen.insert(c.id.as_str()) {
                bail!("중복 id: {}", c.id);
            }
            if c.accepted.is_empty() {
                bail!("{}: accepted가 비었습니다", c.id);
            }
            for a in &c.accepted {
                if !self.categories.contains_key(a) {
                    bail!("{}: 목록 밖 범주 {a}", c.id);
                }
            }
            if c.output.trim().is_empty() {
                bail!(
                    "{}: 출력이 비었습니다 — 그런 실패는 production이 종료 코드만으로 설명한다",
                    c.id
                );
            }
            // 정답이 하나뿐인데 그 실패를 production이 이미 결정적으로 잡는다면 물어볼 이유가 없다.
            let low = c.output.to_lowercase();
            if c.exit_code == 127
                || c.exit_code == 126
                || low.contains("command not found")
                || low.contains("permission denied")
                || low.contains("operation not permitted")
            {
                bail!(
                    "{}: production의 결정적 테이블이 이미 잡는 실패입니다 — 시험 대상이 아닙니다",
                    c.id
                );
            }
        }
        Ok(())
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let dev = self.cases.iter().filter(|c| c.split == Split::Dev).count();
        let multi = self.cases.iter().filter(|c| c.accepted.len() > 1).count();
        (dev, self.cases.len() - dev, multi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(output: &str, exit: i64, accepted: &[&str]) -> ErrCase {
        ErrCase {
            id: "c1".into(),
            split: Split::Dev,
            command: "x".into(),
            exit_code: exit,
            output: output.into(),
            accepted: accepted.iter().map(|s| s.to_string()).collect(),
            traits: vec![],
        }
    }

    fn ds(cases: Vec<ErrCase>) -> ErrCauseDataset {
        ErrCauseDataset {
            schema_version: 1,
            generated: "t".into(),
            categories: BTreeMap::from([
                ("network".to_string(), "연결 실패".to_string()),
                ("usage".to_string(), "사용법 오류".to_string()),
            ]),
            cases,
        }
    }

    #[test]
    fn a_failure_the_deterministic_table_already_handles_is_rejected() {
        // 그런 실패는 LLM을 거치지 않으므로 이 실험의 모수가 아니다. 섞이면 규칙 비교군이
        // production 테이블을 베껴 점수를 올린다.
        let err = ds(vec![case("bash: foo: command not found", 127, &["usage"])])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("결정적 테이블"), "{err}");
        let err = ds(vec![case("cat: x: Permission denied", 1, &["usage"])])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("결정적 테이블"), "{err}");
    }

    #[test]
    fn an_answer_outside_the_category_list_is_rejected() {
        let err = ds(vec![case("boom", 1, &["nope"])])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("목록 밖 범주"), "{err}");
    }

    #[test]
    fn the_rendered_input_is_redacted() {
        // 실제 호스트 출력이라 전송 전에 production과 같은 단계를 거쳐야 한다.
        let c = case("connect to 10.1.2.3 failed", 1, &["network"]);
        let s = render_input(&c);
        assert!(!s.contains("10.1.2.3"), "{s}");
        assert!(s.contains("exit_code=1"));
    }
}
