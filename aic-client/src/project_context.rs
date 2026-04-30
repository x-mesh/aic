//! Small project context pack for error analysis prompts.

use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_STATUS_LINES: usize = 20;

pub fn build_context_pack() -> Option<String> {
    if std::env::var("AIC_CONTEXT")
        .map(|v| v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
    {
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    build_context_pack_for_dir(&cwd)
}

fn build_context_pack_for_dir(cwd: &Path) -> Option<String> {
    let root = git_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    let mut lines = Vec::new();
    lines.push(format!("cwd: {}", cwd.display()));
    if root != cwd {
        lines.push(format!("repo_root: {}", root.display()));
    }

    if let Some(branch) = git_output(&root, &["branch", "--show-current"]) {
        if !branch.trim().is_empty() {
            lines.push(format!("git_branch: {}", branch.trim()));
        }
    }

    if let Some(status) = git_output(&root, &["status", "--short"]) {
        let status_lines = status
            .lines()
            .take(MAX_STATUS_LINES)
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        if !status_lines.is_empty() {
            lines.push("git_status:".to_string());
            lines.extend(status_lines.into_iter().map(|line| format!("  {line}")));
        }
    }

    let manifests = detect_manifests(&root);
    if !manifests.is_empty() {
        lines.push(format!("manifests: {}", manifests.join(", ")));
    }

    if lines.len() <= 1 && manifests.is_empty() {
        return None;
    }

    let raw = lines.join("\n");
    let (redacted, _) = crate::redaction::redact(&raw);
    Some(redacted)
}

fn git_root(cwd: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(cwd)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    if out.status.success() {
        String::from_utf8(out.stdout).ok()
    } else {
        None
    }
}

fn detect_manifests(root: &Path) -> Vec<&'static str> {
    [
        ("Cargo.toml", "rust:cargo"),
        ("package.json", "node:package-json"),
        ("pnpm-lock.yaml", "node:pnpm"),
        ("yarn.lock", "node:yarn"),
        ("package-lock.json", "node:npm"),
        ("pyproject.toml", "python:pyproject"),
        ("requirements.txt", "python:requirements"),
        ("go.mod", "go:modules"),
        ("Makefile", "make"),
    ]
    .into_iter()
    .filter_map(|(file, label)| root.join(file).exists().then_some(label))
    .collect()
}

pub fn append_to_prompt(prompt: String, context: Option<&str>) -> String {
    match context.map(str::trim).filter(|s| !s.is_empty()) {
        Some(context) => format!(
            "{prompt}\n\n# Project Context\n\
             Use this context only when it is directly relevant. Do not assume unstated file contents.\n\
             ```text\n{context}\n```"
        ),
        None => prompt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_manifest_context_without_git() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname='x'\n").unwrap();

        let context = build_context_pack_for_dir(dir.path()).unwrap();

        assert!(context.contains("cwd:"));
        assert!(context.contains("rust:cargo"));
    }

    #[test]
    fn append_to_prompt_adds_context_block() {
        let prompt = append_to_prompt("base".to_string(), Some("cwd: /tmp/project"));
        assert!(prompt.contains("# Project Context"));
        assert!(prompt.contains("cwd: /tmp/project"));
    }
}
