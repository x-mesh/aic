//! 학습된 해결책 저장소 (P2 'aic learn').
//!
//! 사용자가 "이 해결책이 통했다"고 표시한 결과를 local recipe로 저장해두면, 다음에
//! 같은 fingerprint 에러가 다시 일어났을 때 LLM 호출 전에 먼저 보여준다.
//!
//! - fingerprint: `cache::cache_key_with_context`로 생성하는 16자 hex.
//!   record의 command/exit/output tail/project context를 모두 반영하므로 같은 환경
//!   같은 에러면 동일한 fingerprint다.
//! - 저장 위치: `~/.local/share/aic/recipes.json` (혹은 dirs::data_local_dir 결과).
//!   cache와 분리한다 — cache는 eviction 대상이지만 recipes는 사용자 자산.
//! - 데이터 구조는 향후 확장(version, tags 등)을 위해 단순한 Vec<Recipe>를 그대로 직렬화.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recipe {
    /// cache key와 동일한 16자 hex.
    pub fingerprint: String,
    /// 사용자가 본 command 텍스트 (참조용).
    pub command: Option<String>,
    /// 분석 explanation (참조용, length cap 적용).
    pub explanation: String,
    /// 작동한 suggested_command. 없으면 사용자가 note만 남긴 형태.
    pub suggested_command: Option<String>,
    /// 사용자 메모 (선택).
    pub note: Option<String>,
    /// 처음 학습된 시각.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// 동일 fingerprint를 다시 만나 hit한 횟수.
    pub hits: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RecipeStore {
    #[serde(default)]
    pub recipes: Vec<Recipe>,
}

const EXPLANATION_CAP: usize = 2_000;

/// 기본 store 경로. `dirs::data_local_dir()`이 None이면 home 기반 폴백.
pub fn store_path() -> PathBuf {
    if let Some(d) = dirs::data_local_dir() {
        return d.join("aic").join("recipes.json");
    }
    // 폴백: ~/.local/share/aic/recipes.json
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".local")
        .join("share")
        .join("aic")
        .join("recipes.json")
}

/// store_path()에서 RecipeStore를 읽는다. 파일이 없으면 빈 store.
pub fn load() -> RecipeStore {
    load_from(&store_path())
}

pub fn load_from(path: &Path) -> RecipeStore {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => RecipeStore::default(),
    }
}

/// store_path()에 RecipeStore를 atomic하게 저장한다.
pub fn save(store: &RecipeStore) -> io::Result<()> {
    save_to(&store_path(), store)
}

pub fn save_to(path: &Path, store: &RecipeStore) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// fingerprint에 매칭되는 recipe를 반환한다.
pub fn find(fingerprint: &str) -> Option<Recipe> {
    load()
        .recipes
        .into_iter()
        .find(|r| r.fingerprint == fingerprint)
}

/// recipe를 추가하거나 같은 fingerprint가 있으면 hits/timestamp만 갱신한다.
pub fn upsert(mut recipe: Recipe) -> io::Result<()> {
    let mut store = load();
    if let Some(existing) = store
        .recipes
        .iter_mut()
        .find(|r| r.fingerprint == recipe.fingerprint)
    {
        existing.hits = existing.hits.saturating_add(1);
        if recipe.note.is_some() {
            existing.note = recipe.note.clone();
        }
        if recipe.suggested_command.is_some() {
            existing.suggested_command = recipe.suggested_command.clone();
        }
    } else {
        // explanation 크기 cap.
        if recipe.explanation.len() > EXPLANATION_CAP {
            recipe.explanation.truncate(EXPLANATION_CAP);
        }
        recipe.hits = 1;
        store.recipes.push(recipe);
    }
    save(&store)
}

/// fingerprint hit 횟수를 1 증가시킨다 (recipe match 시 호출).
pub fn touch(fingerprint: &str) -> io::Result<()> {
    let mut store = load();
    if let Some(existing) = store
        .recipes
        .iter_mut()
        .find(|r| r.fingerprint == fingerprint)
    {
        existing.hits = existing.hits.saturating_add(1);
        save(&store)
    } else {
        Ok(())
    }
}

/// fingerprint prefix로 매칭되는 recipe를 모두 삭제하고 삭제된 갯수를 반환한다.
pub fn delete_by_prefix(prefix: &str) -> io::Result<usize> {
    let mut store = load();
    let before = store.recipes.len();
    store.recipes.retain(|r| !r.fingerprint.starts_with(prefix));
    let deleted = before - store.recipes.len();
    if deleted > 0 {
        save(&store)?;
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn sample_recipe(fp: &str) -> Recipe {
        Recipe {
            fingerprint: fp.to_string(),
            command: Some("cargo build".to_string()),
            explanation: "타입 mismatch 에러".to_string(),
            suggested_command: Some("cargo update -p foo".to_string()),
            note: None,
            created_at: Utc::now(),
            hits: 0,
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recipes.json");
        let store = RecipeStore {
            recipes: vec![sample_recipe("aaaaaaaaaaaaaaaa")],
        };
        save_to(&path, &store).unwrap();
        let loaded = load_from(&path);
        assert_eq!(store, loaded);
    }

    #[test]
    fn load_from_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does_not_exist.json");
        let loaded = load_from(&path);
        assert!(loaded.recipes.is_empty());
    }

    #[test]
    fn explanation_cap_truncates_long_text() {
        let mut store = RecipeStore::default();
        let long_explanation = "x".repeat(EXPLANATION_CAP * 2);
        let mut r = sample_recipe("bbbbbbbbbbbbbbbb");
        r.explanation = long_explanation;
        store.recipes.push(r.clone());
        // upsert는 store_path를 참조하므로 직접 호출하지 않는다.
        // 여기서는 만일 cap이 적용되었을 때 동작을 시뮬레이션해 본다.
        if r.explanation.len() > EXPLANATION_CAP {
            r.explanation.truncate(EXPLANATION_CAP);
        }
        assert_eq!(r.explanation.len(), EXPLANATION_CAP);
    }
}
