//! 분석 결과 캐시 — 같은 명령어/exit/output 조합은 24h TTL로 재사용.
//!
//! 키: 64-bit hash of (command + exit_code + last 4KB of output).
//! 저장 위치: `~/.cache/aic/analyses/<key>.json`.
//! TTL이 지난 entry는 load 시 자동 삭제.

use aic_common::AnalysisResult;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

const TTL_HOURS: i64 = 24;
const TAIL_BYTES: usize = 4096;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CachedAnalysis {
    pub key: String,
    pub cached_at: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub result: AnalysisResult,
}

/// 캐시 디렉토리 (`~/.cache/aic/analyses`).
pub fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    cache_dir_in(&PathBuf::from(home))
}

fn cache_dir_in(home: &Path) -> PathBuf {
    home.join(".cache").join("aic").join("analyses")
}

/// 결정론적 캐시 키 (16자 hex). 같은 입력 → 같은 키.
pub fn cache_key(cmd: &str, exit: i32, output_lines: &[String]) -> String {
    let mut hasher = DefaultHasher::new();
    cmd.hash(&mut hasher);
    exit.hash(&mut hasher);
    let joined: String = output_lines.join("\n");
    let tail = if joined.len() > TAIL_BYTES {
        let start = joined.len() - TAIL_BYTES;
        let mut idx = start;
        while idx < joined.len() && !joined.is_char_boundary(idx) {
            idx += 1;
        }
        &joined[idx..]
    } else {
        &joined
    };
    tail.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// 캐시에서 결과 로드. TTL 지난 entry는 자동 삭제 후 None 반환.
pub fn load(key: &str) -> Option<CachedAnalysis> {
    load_from(&cache_dir(), key)
}

pub fn load_from(dir: &Path, key: &str) -> Option<CachedAnalysis> {
    let path = dir.join(format!("{key}.json"));
    let content = std::fs::read_to_string(&path).ok()?;
    let cached: CachedAnalysis = serde_json::from_str(&content).ok()?;
    let age = Utc::now() - cached.cached_at;
    if age > Duration::hours(TTL_HOURS) {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    Some(cached)
}

/// 결과를 캐시에 저장.
pub fn save(cached: &CachedAnalysis) -> std::io::Result<()> {
    save_to(&cache_dir(), cached)
}

pub fn save_to(dir: &Path, cached: &CachedAnalysis) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", cached.key));
    let content = serde_json::to_string_pretty(cached).map_err(std::io::Error::other)?;
    std::fs::write(&path, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result() -> AnalysisResult {
        AnalysisResult {
            explanation: "test".into(),
            suggested_command: Some("ls".into()),
            additional_info: None,
        }
    }

    #[test]
    fn cache_key_is_deterministic() {
        let lines = vec!["error: x".to_string()];
        let k1 = cache_key("ls /nope", 1, &lines);
        let k2 = cache_key("ls /nope", 1, &lines);
        assert_eq!(k1, k2);
    }

    #[test]
    fn cache_key_changes_with_command() {
        let lines = vec!["error".to_string()];
        let k1 = cache_key("ls", 1, &lines);
        let k2 = cache_key("ls /tmp", 1, &lines);
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_changes_with_exit_code() {
        let lines = vec!["error".to_string()];
        let k1 = cache_key("ls", 1, &lines);
        let k2 = cache_key("ls", 2, &lines);
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_uses_tail_only_for_long_output() {
        // last TAIL_BYTES만 비교 — 그 앞부분이 달라도 tail이 같으면 같은 key
        let common_tail = "Z".repeat(TAIL_BYTES);
        let lines_a = vec![format!("{}{}", "X".repeat(8000), common_tail)];
        let lines_b = vec![format!("{}{}", "Y".repeat(8000), common_tail)];
        let lines_c = vec![format!("{}{}", "X".repeat(8000), "W".repeat(TAIL_BYTES))];

        let k_a = cache_key("cmd", 1, &lines_a);
        let k_b = cache_key("cmd", 1, &lines_b);
        let k_c = cache_key("cmd", 1, &lines_c);

        assert_eq!(k_a, k_b, "head는 다르지만 tail이 같으니 같은 key");
        assert_ne!(k_a, k_c, "tail이 다르면 다른 key");
    }

    #[test]
    fn load_from_returns_none_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        assert!(load_from(temp.path(), "nonexistent").is_none());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let cached = CachedAnalysis {
            key: "roundtrip_test".into(),
            cached_at: Utc::now(),
            provider: "test".into(),
            model: "test-model".into(),
            result: make_result(),
        };
        save_to(temp.path(), &cached).unwrap();
        let loaded = load_from(temp.path(), &cached.key).unwrap();
        assert_eq!(loaded.key, cached.key);
        assert_eq!(loaded.result, cached.result);
    }

    #[test]
    fn ttl_expired_entry_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let cached = CachedAnalysis {
            key: "expired_test".into(),
            cached_at: Utc::now() - Duration::hours(25),
            provider: "x".into(),
            model: "y".into(),
            result: make_result(),
        };
        save_to(temp.path(), &cached).unwrap();
        let path = temp.path().join(format!("{}.json", cached.key));
        assert!(path.exists());

        let loaded = load_from(temp.path(), &cached.key);
        assert!(loaded.is_none());
        assert!(!path.exists()); // 자동 삭제 확인
    }
}
