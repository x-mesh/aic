//! `aic chat` 메시지 의도 라우팅 실험 — 데이터셋.
//!
//! 슬래시 없이 쓴 채팅 입력은 도구 호출 루프로 간다. 그 루프는 LLM이 셸 명령을 지어내고 반복마다
//! history를 다시 보낸다. 같은 요청이 진단이면 `/diagnose`가 probe 카탈로그로 모으고 LLM을 한 번만
//! 부른다. 입력을 네 경로(`diagnose`·`local`·`explain_last`·`agent`) 중 하나로 가르면 진단성 요청을
//! 싼 경로로 보낼 수 있다 — 이 실험은 그 판정을 규칙·Jev·LLM 중 누가 해야 하는지 잰다.
//!
//! 분할 규약: 개발 분할은 규칙을 쓴 사람이 직접 썼다. 최종 분할은 **LLM 비교군과 다른 모델**이 의도별로
//! 생성했고 사람은 읽지 않는다. 규칙 작성자가 평가 문장도 쓰면 문장이 규칙 어휘를 닮고, 분류할 모델이
//! 직접 쓴 문장을 채점하면 그 모델이 유리해진다 — 두 경로를 모두 막는다.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub use crate::errcause::Split;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntentDataset {
    pub schema_version: u32,
    pub generated: String,
    /// Jev 질문과 LLM 프롬프트의 지시문. 두 비교군이 같은 문장을 받아야 비교가 공정하다.
    pub instructions: String,
    pub categories: BTreeMap<String, String>,
    pub cases: Vec<IntentCase>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntentCase {
    pub id: String,
    pub split: Split,
    pub text: String,
    /// 타당한 경로들. 둘이면 문장만으로 가를 수 없는 경계 사례다.
    pub accepted: Vec<String>,
    pub traits: Vec<String>,
    /// `author:dev` 또는 `generated:<model>`. 최종 분할이 사람 손을 타지 않았음을 기록으로 남긴다.
    pub source: String,
}

impl IntentDataset {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("데이터 파일을 읽지 못했습니다: {}", path.display()))?;
        let ds: Self = serde_json::from_str(&raw)
            .with_context(|| format!("데이터 파싱 실패: {}", path.display()))?;
        ds.validate()?;
        Ok(ds)
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        self.validate()?;
        std::fs::write(path, serde_json::to_string_pretty(self)? + "\n")
            .with_context(|| format!("저장 실패: {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("지원하지 않는 schema_version: {}", self.schema_version);
        }
        if self.instructions.trim().is_empty() {
            bail!("instructions가 비었습니다");
        }
        let mut seen_id = std::collections::BTreeSet::new();
        let mut seen_text = std::collections::BTreeSet::new();
        for c in &self.cases {
            if !seen_id.insert(c.id.as_str()) {
                bail!("중복 id: {}", c.id);
            }
            // 같은 문장이 두 분할에 있으면 최종 분할이 개발 분할을 새어 받는다.
            if !seen_text.insert(normalize(&c.text)) {
                bail!("{}: 같은 문장이 이미 있습니다", c.id);
            }
            if c.text.trim().is_empty() {
                bail!("{}: 문장이 비었습니다", c.id);
            }
            if c.accepted.is_empty() {
                bail!("{}: accepted가 비었습니다", c.id);
            }
            for a in &c.accepted {
                if !self.categories.contains_key(a) {
                    bail!("{}: 목록 밖 경로 {a}", c.id);
                }
            }
            if c.split == Split::Final && !c.source.starts_with("generated:") {
                bail!(
                    "{}: 최종 분할은 생성 모델이 만든 문장만 받는다(source={})",
                    c.id,
                    c.source
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

/// 중복 판정용 정규화. 대소문자·공백·끝 문장부호 차이만으로 다른 문장이 되지 않게 한다.
pub fn normalize(text: &str) -> String {
    text.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(['?', '!', '.', '~'])
        .to_string()
}

/// 생성 모델에 주는 요청. 이 문장 하나로 최종 분할의 라벨이 정해지므로, 의도 정의를 그대로 싣는다.
pub fn generation_prompt(intent: &str, definition: &str, others: &str, n: usize) -> String {
    format!(
        "터미널 도우미(`aic chat`)에 사용자가 입력할 법한 메시지를 {n}개 만든다.\n\n\
# 만들 의도: {intent}\n{definition}\n\n\
# 다른 의도(이쪽에 속하는 문장은 만들지 않는다)\n{others}\n\n\
# 조건\n\
- 한국어 약 70%, 영어 약 30%.\n\
- 문체를 섞는다: 반말·존댓말, 아주 짧은 말, 긴 설명, 오타, 이모티콘, 명령조.\n\
- 실제 운영자가 쓸 법한 도구와 대상(nginx, postgres, k8s, docker, systemd, redis 등)을 다양하게 쓴다.\n\
- 다른 의도와 헷갈릴 만한 낱말이 들어가도 되지만, 요청 자체는 분명히 이 의도여야 한다.\n\
- 서로 비슷한 문장을 반복하지 않는다.\n\n\
# 형식\nJSON 문자열 배열 하나만 출력한다. 설명이나 코드 블록 표시를 붙이지 않는다."
    )
}

/// 생성 응답에서 문장 배열을 꺼낸다. 모델이 코드 블록으로 감싸는 일이 흔해 첫 `[`부터 마지막 `]`까지
/// 잘라 읽는다.
pub fn parse_generated(text: &str) -> Result<Vec<String>> {
    let start = text.find('[').context("응답에 JSON 배열이 없습니다")?;
    let end = text.rfind(']').context("응답에 JSON 배열이 없습니다")?;
    let arr: Vec<String> = serde_json::from_str(&text[start..=end]).context("배열 파싱 실패")?;
    Ok(arr
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ds(cases: Vec<IntentCase>) -> IntentDataset {
        IntentDataset {
            schema_version: 1,
            generated: "t".into(),
            instructions: "고른다".into(),
            categories: BTreeMap::from([
                ("diagnose".to_string(), "문제".to_string()),
                ("agent".to_string(), "그 외".to_string()),
            ]),
            cases,
        }
    }

    fn case(id: &str, split: Split, text: &str, source: &str) -> IntentCase {
        IntentCase {
            id: id.into(),
            split,
            text: text.into(),
            accepted: vec!["agent".into()],
            traits: vec![],
            source: source.into(),
        }
    }

    #[test]
    fn a_final_case_written_by_a_person_is_rejected() {
        // 최종 분할에 규칙 작성자의 문장이 섞이면 이 실험이 막으려던 편향이 그대로 들어온다.
        let err = ds(vec![case("a", Split::Final, "안녕", "author:dev")])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("생성 모델"), "{err}");
    }

    #[test]
    fn the_same_sentence_in_two_splits_is_rejected() {
        let err = ds(vec![
            case("a", Split::Dev, "메모리 보여줘", "author:dev"),
            case("b", Split::Final, "메모리  보여줘?", "generated:m"),
        ])
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("같은 문장"), "{err}");
    }

    #[test]
    fn a_fenced_json_array_is_parsed() {
        let got = parse_generated("```json\n[\"a\", \" b \", \"\"]\n```").unwrap();
        assert_eq!(got, vec!["a", "b"]);
    }
}
