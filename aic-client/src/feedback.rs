//! 분석 결과 피드백 로그 (P3 'Solution Feedback').
//!
//! `aic feedback worked|not-worked|irrelevant`로 사용자가 분석 결과의 품질을
//! 피드백한다. 데이터는 local-only로 `~/.local/share/aic/feedback.json`에
//! append되며, prompt/response 본문은 저장하지 않고 fingerprint와 verdict만 남긴다
//! (privacy 정책 준수).
//!
//! 활용:
//! - `Worked`는 `recipes::upsert`로 자동 승격되어 다음 동일 fingerprint 발생 시
//!   LLM 호출을 건너뛴다.
//! - `NotWorked`는 기존 recipe를 삭제 (있다면) — 잘못 학습된 recipe를 잡아낸다.
//! - `Irrelevant`는 deterministic rule 또는 prompt template 개선 후보로
//!   debug bundle에 포함될 수 있다.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Worked,
    NotWorked,
    Irrelevant,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Worked => "worked",
            Verdict::NotWorked => "not-worked",
            Verdict::Irrelevant => "irrelevant",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub fingerprint: String,
    pub verdict: Verdict,
    pub note: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedbackLog {
    #[serde(default)]
    pub entries: Vec<FeedbackEntry>,
}

const ENTRY_CAP: usize = 1_000;

pub fn log_path() -> PathBuf {
    if let Some(d) = dirs::data_local_dir() {
        return d.join("aic").join("feedback.json");
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".local")
        .join("share")
        .join("aic")
        .join("feedback.json")
}

pub fn load() -> FeedbackLog {
    load_from(&log_path())
}

pub fn load_from(path: &Path) -> FeedbackLog {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => FeedbackLog::default(),
    }
}

pub fn save(log: &FeedbackLog) -> io::Result<()> {
    save_to(&log_path(), log)
}

pub fn save_to(path: &Path, log: &FeedbackLog) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(log)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// 새 entry를 append한다. ENTRY_CAP을 초과하면 가장 오래된 것부터 제거.
pub fn append(entry: FeedbackEntry) -> io::Result<()> {
    let mut log = load();
    log.entries.push(entry);
    while log.entries.len() > ENTRY_CAP {
        log.entries.remove(0);
    }
    save(&log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_serializes_and_deserializes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("feedback.json");
        let log = FeedbackLog {
            entries: vec![FeedbackEntry {
                fingerprint: "deadbeefcafef00d".to_string(),
                verdict: Verdict::Worked,
                note: Some("clean fix".to_string()),
                at: Utc::now(),
            }],
        };
        save_to(&path, &log).unwrap();
        assert_eq!(log, load_from(&path));
    }

    #[test]
    fn missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.json");
        assert!(load_from(&path).entries.is_empty());
    }

    #[test]
    fn verdict_labels_are_kebab_case() {
        assert_eq!(Verdict::Worked.label(), "worked");
        assert_eq!(Verdict::NotWorked.label(), "not-worked");
        assert_eq!(Verdict::Irrelevant.label(), "irrelevant");
    }
}
