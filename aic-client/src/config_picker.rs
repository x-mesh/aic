//! 설정 경로 하나를 골라 값 하나를 바꾸는 편집기(`aic config set` 인자 없이)와 경로 목록
//! (`aic config list`).
//!
//! 작업 단위로 여러 값을 함께 맞추는 `aic config` 마법사와 나눈다. LLM 연결처럼 provider
//! 종류·endpoint·키·모델이 서로 맞아야 하는 값은 하나씩 바꾸면 중간에 어긋난 상태가 남으므로
//! 마법사에 둔다.
//!
//! 목록은 `aic config set`이 받는 경로를 설정 구조에서 그대로 뽑는다. 따로 적어 둔 목록은
//! 설정이 늘 때마다 낡는다.

use aic_common::AppConfig;
use serde::Serialize;
use serde_json::Value;

/// 바꿀 수 있는 설정 한 칸.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct SettablePath {
    pub path: String,
    /// 현재 값. 비어 있으면 `None`, 비밀이면 가린 값.
    pub value: Option<String>,
    pub kind: ValueKind,
    /// aicd가 재시작 없이 다시 읽는가.
    pub live: bool,
    pub secret: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ValueKind {
    Bool,
    Number,
    Text,
    /// 비어 있는 `Option`이라 타입을 알 수 없다. 넣는 값에 맞춰 해석된다.
    Empty,
}

/// `aic config set`이 받는 모든 경로. 배열과 테이블은 단일 값으로 바꿀 수 없어 뺀다.
pub(crate) fn settable_paths(config: &AppConfig) -> anyhow::Result<Vec<SettablePath>> {
    let json = serde_json::to_value(config)?;
    let mut out = Vec::new();
    collect(&json, "", &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn collect(node: &Value, prefix: &str, out: &mut Vec<SettablePath>) {
    let Value::Object(map) = node else {
        return;
    };
    for (key, child) in map {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let kind = match child {
            Value::Object(_) => {
                collect(child, &path, out);
                continue;
            }
            Value::Array(_) => continue,
            Value::Bool(_) => ValueKind::Bool,
            Value::Number(_) => ValueKind::Number,
            Value::String(_) => ValueKind::Text,
            Value::Null => ValueKind::Empty,
        };
        let secret = super::is_secret_config_path(&path);
        let value = match child {
            Value::Null => None,
            Value::String(s) if secret => Some(super::mask_api_key(s)),
            Value::String(s) => Some(s.clone()),
            other => Some(other.to_string()),
        };
        out.push(SettablePath {
            live: aic_common::is_live_reloadable(&path),
            path,
            value,
            kind,
            secret,
        });
    }
}

fn shown_value(item: &SettablePath) -> &str {
    item.value.as_deref().unwrap_or("(비어 있음)")
}

fn reload_label(item: &SettablePath) -> &'static str {
    if item.live {
        "즉시"
    } else {
        "재시작"
    }
}

fn picker_label(item: &SettablePath) -> String {
    format!(
        "[{}] {} = {}",
        reload_label(item),
        item.path,
        shown_value(item)
    )
}

/// `aic config list [--live] [--json]`
pub(crate) fn print_list(config: &AppConfig, live_only: bool, json: bool) -> anyhow::Result<()> {
    let items: Vec<SettablePath> = settable_paths(config)?
        .into_iter()
        .filter(|i| !live_only || i.live)
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    println!(
        "{}개 · [즉시] aicd가 {}초 안에 다시 읽음 · [재시작] aic daemon restart 후 반영",
        items.len(),
        aic_common::CONFIG_RELOAD_INTERVAL_SECS
    );
    for item in &items {
        let color = if item.live {
            super::COL_GREEN
        } else {
            super::COL_DIM
        };
        println!(
            "  {color}[{}]{} {} = {}",
            reload_label(item),
            super::COL_RESET,
            item.path,
            shown_value(item)
        );
    }
    Ok(())
}

/// 고른 설정에 넣을 값을 받는다. 바꾸지 않기로 했으면 `None`.
fn prompt_value(
    theme: &dialoguer::theme::ColorfulTheme,
    item: &SettablePath,
) -> anyhow::Result<Option<String>> {
    use dialoguer::{Input, Password, Select};

    if item.secret {
        // 비밀은 화면과 스크롤백에 남기지 않는다. 빈 입력은 그대로 두겠다는 뜻으로 읽는다.
        let raw = Password::with_theme(theme)
            .with_prompt(format!("{} 새 값 (비우면 유지)", item.path))
            .allow_empty_password(true)
            .interact()?;
        return Ok(Some(raw).filter(|v| !v.is_empty()));
    }
    if item.kind == ValueKind::Bool {
        let current_true = item.value.as_deref() == Some("true");
        let idx = Select::with_theme(theme)
            .with_prompt(item.path.as_str())
            .items(["true", "false"])
            .default(if current_true { 0 } else { 1 })
            .interact_opt()?;
        return Ok(idx.map(|i| if i == 0 { "true" } else { "false" }.to_string()));
    }
    // 현재 값을 입력칸에 미리 채우지 않는다. 채운 값을 고치는 모드에서는 Backspace(DEL)가 첫
    // 번째 것만 먹었다(pty 실측) — 기본값으로 보여 주고 Enter면 유지한다.
    let mut input = Input::<String>::with_theme(theme)
        .with_prompt(format!("{} (Enter면 유지 · unset이면 비움)", item.path))
        .allow_empty(true);
    if let Some(current) = &item.value {
        input = input.default(current.clone());
    }
    let raw = input.interact_text()?;
    let raw = raw.trim();
    if raw.is_empty() || Some(raw) == item.value.as_deref() {
        return Ok(None);
    }
    Ok(Some(raw.to_string()))
}

/// `aic config set`을 인자 없이 실행했을 때: 경로를 검색해 고르고 값 하나를 바꾼다.
pub(crate) fn run_set_picker() -> anyhow::Result<()> {
    use dialoguer::FuzzySelect;
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "인자 없는 `aic config set`은 터미널에서 설정을 골라 바꾸는 화면입니다 — \
             스크립트에서는 `aic config set <경로> <값>`을 쓰세요"
        );
    }
    let mut config = aic_client::config::ConfigManager::load()?;
    let items = settable_paths(&config)?;
    let labels: Vec<String> = items.iter().map(picker_label).collect();
    let theme = dialoguer::theme::ColorfulTheme::default();

    let Some(idx) = FuzzySelect::with_theme(&theme)
        .with_prompt("바꿀 설정 (입력해 검색 · Esc 취소)")
        .items(&labels)
        .default(0)
        .max_length(15)
        .interact_opt()?
    else {
        return Ok(());
    };
    let item = &items[idx];
    let Some(value) = prompt_value(&theme, item)? else {
        println!("변경 없음");
        return Ok(());
    };
    super::apply_config_set(&mut config, &item.path, &value)?;
    super::save_config(&config)?;
    super::report_config_set(&config, &item.path, &value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<SettablePath> {
        settable_paths(&crate::default_config()).unwrap()
    }

    /// 이 테스트가 지키는 것: 목록이 `aic config set`이 받는 경로와 같은 것.
    /// 목록에 있는데 set이 거부하면 고른 뒤에야 실패한다.
    #[test]
    fn every_listed_path_is_accepted_by_set() {
        let mut config = crate::default_config();
        for item in items() {
            let value = match (&item.value, item.secret) {
                (None, _) | (_, true) => "unset".to_string(),
                (Some(v), false) => v.clone(),
            };
            crate::apply_config_set(&mut config, &item.path, &value)
                .unwrap_or_else(|e| panic!("{}: {e}", item.path));
        }
    }

    #[test]
    fn tables_and_arrays_are_not_listed() {
        let paths: Vec<String> = items().into_iter().map(|i| i.path).collect();
        assert!(!paths.iter().any(|p| p == "aicd.exporter"));
        assert!(!paths.iter().any(|p| p == "aicd.logs.files"));
        assert!(paths.iter().any(|p| p == "aicd.logs.journald.enabled"));
    }

    /// 이 테스트가 지키는 것: [즉시] 표시가 aicd가 실제로 다시 읽는 목록과 같은 것.
    /// 갈리면 반영되지 않은 값을 반영됐다고 믿거나, 필요 없는 재시작을 한다.
    #[test]
    fn live_marks_match_the_daemon_reload_list() {
        let mut live: Vec<String> = items()
            .into_iter()
            .filter(|i| i.live)
            .map(|i| i.path)
            .collect();
        live.sort();
        let mut expected: Vec<String> = aic_common::LIVE_RELOADABLE_CONFIG_PATHS
            .iter()
            .map(|p| p.to_string())
            .collect();
        expected.sort();
        assert_eq!(live, expected);
    }

    #[test]
    fn a_secret_is_listed_masked() {
        let mut config = crate::default_config();
        crate::apply_config_set(
            &mut config,
            "aicd.exporter.token",
            "rca-ingest-0123456789abcdef",
        )
        .unwrap();
        let token = settable_paths(&config)
            .unwrap()
            .into_iter()
            .find(|i| i.path == "aicd.exporter.token")
            .unwrap();
        assert!(token.secret);
        let shown = token.value.unwrap();
        assert!(!shown.contains("0123456789abcdef"), "{shown}");
    }

    #[test]
    fn an_empty_option_is_listed_without_a_type() {
        let item = items()
            .into_iter()
            .find(|i| i.path == "aicd.exporter.spool_max_age_secs")
            .unwrap();
        assert_eq!(item.value, None);
        assert_eq!(item.kind, ValueKind::Empty);
    }
}
