//! 읽기 전용 agent 도구 — `read_file` / `list_dir` / `grep` / `glob`.
//!
//! 모든 경로는 [`Sandbox::resolve`]를 통과한다(샌드박스 밖·symlink 탈출 거부).
//! 안전 규칙:
//! - secrets 파일(`.env`, `*.pem`, `id_rsa*` 등)은 read 차단.
//! - hidden(`.`)·`.git/`은 traversal에서 제외.
//! - large file은 truncate, binary file은 메타데이터만 반환(LLM에 덤프 금지).
//!
//! **읽기 전용 불변식**: 쓰기/실행 도구는 registry에 등록하지 않는다(Phase 2까지).

use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::sandbox::Sandbox;
use super::types::ToolSpec;

/// 도구 실행 실패. panic 대신 LLM에 tool 메시지로 회신된다.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolError {
    pub message: String,
}

impl ToolError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ToolError {}

// ── 한도 상수 ──────────────────────────────────────────────
/// read_file 기본 최대 바이트.
const DEFAULT_READ_MAX_BYTES: usize = 64 * 1024;
/// read_file 하드 상한(요청 max_bytes가 더 커도 이 값을 넘지 않음).
const HARD_READ_MAX_BYTES: usize = 1024 * 1024;
/// list_dir 최대 엔트리 수.
const MAX_DIR_ENTRIES: usize = 500;
/// grep 최대 매치 수.
const MAX_GREP_MATCHES: usize = 200;
/// grep 라인 표시 최대 길이(char 기준).
const MAX_GREP_LINE_LEN: usize = 500;
/// glob 최대 결과 수.
const MAX_GLOB_RESULTS: usize = 500;
/// traversal 최대 깊이.
const MAX_WALK_DEPTH: usize = 20;
/// traversal 전역 파일 수 안전 상한.
const MAX_WALK_FILES: usize = 20_000;
/// binary 판정용 선두 스캔 바이트.
const BINARY_SCAN_BYTES: usize = 8192;

/// secrets로 간주해 read를 차단할 파일명인지 판정한다(대소문자 무시).
pub fn is_secret_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    if lower == ".env" || lower.starts_with(".env.") {
        return true;
    }
    if matches!(
        lower.as_str(),
        "credentials" | ".netrc" | ".npmrc" | ".pgpass" | ".htpasswd"
    ) {
        return true;
    }
    if lower.starts_with("id_rsa")
        || lower.starts_with("id_ed25519")
        || lower.starts_with("id_dsa")
        || lower.starts_with("id_ecdsa")
    {
        return true;
    }
    const SECRET_EXT: [&str; 6] = [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"];
    SECRET_EXT.iter().any(|e| lower.ends_with(e))
}

/// traversal에서 제외할 hidden/VCS 엔트리인지 판정한다(이름 기준 — `.git` 포함).
pub fn is_hidden_or_vcs(name: &str) -> bool {
    name.starts_with('.')
}

/// 경로 컴포넌트에 `.git`이 있으면 true(read_file의 .git 차단용).
fn has_git_component(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == ".git")
}

/// char 경계를 지키며 문자열을 최대 길이로 자른다.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, ToolError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::new(format!("필수 인자 '{key}'가 없거나 문자열이 아님")))
}

// ── 도구 구현 ──────────────────────────────────────────────

/// `read_file` — 단일 파일 내용 반환. secrets·binary·large 규칙 적용.
pub fn read_file(args: &Value, sb: &Sandbox) -> Result<String, ToolError> {
    let path_arg = arg_str(args, "path")?;
    let path = sb.resolve(path_arg)?;
    if has_git_component(&path) {
        return Err(ToolError::new(".git 내부는 접근할 수 없습니다"));
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if is_secret_file(name) {
        return Err(ToolError::new(format!("secrets 파일 접근 거부: {name}")));
    }
    if sb.is_ignored(&path, false) {
        return Err(ToolError::new(format!(
            "gitignore된 경로 접근 거부: {name}"
        )));
    }
    let meta =
        std::fs::metadata(&path).map_err(|e| ToolError::new(format!("metadata 조회 실패: {e}")))?;
    if !meta.is_file() {
        return Err(ToolError::new("파일이 아닙니다(디렉터리?)"));
    }
    let size = meta.len() as usize;
    let max_bytes = args
        .get("max_bytes")
        .and_then(|v| v.as_u64())
        .map(|v| (v as usize).min(HARD_READ_MAX_BYTES))
        .unwrap_or(DEFAULT_READ_MAX_BYTES);

    let bytes = std::fs::read(&path).map_err(|e| ToolError::new(format!("파일 읽기 실패: {e}")))?;

    // binary 감지: 선두 스캔 구간에 NUL이 있으면 메타데이터만 반환.
    let scan = bytes.len().min(BINARY_SCAN_BYTES);
    if bytes[..scan].contains(&0) {
        return Ok(format!("[binary file: {size} bytes — 내용 생략]"));
    }

    let truncated = bytes.len() > max_bytes;
    let slice = &bytes[..bytes.len().min(max_bytes)];
    let mut content = String::from_utf8_lossy(slice).into_owned();
    if truncated {
        content.push_str(&format!(
            "\n…[truncated: 전체 {size} bytes 중 {max_bytes} bytes 표시]"
        ));
    }
    Ok(content)
}

/// `list_dir` — 디렉터리 엔트리 목록(hidden 제외, 정렬). 기본 path는 `.`.
pub fn list_dir(args: &Value, sb: &Sandbox) -> Result<String, ToolError> {
    let path_arg = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let dir = sb.resolve(path_arg)?;
    let meta =
        std::fs::metadata(&dir).map_err(|e| ToolError::new(format!("metadata 조회 실패: {e}")))?;
    if !meta.is_dir() {
        return Err(ToolError::new("디렉터리가 아닙니다"));
    }

    let rd =
        std::fs::read_dir(&dir).map_err(|e| ToolError::new(format!("디렉터리 읽기 실패: {e}")))?;
    let mut rows: Vec<String> = Vec::new();
    let mut hidden_skipped = 0usize;
    let mut ignored_skipped = 0usize;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if is_hidden_or_vcs(&name) {
            hidden_skipped += 1;
            continue;
        }
        let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if sb.is_ignored(&ent.path(), is_dir) {
            ignored_skipped += 1;
            continue;
        }
        let marker = match ent.file_type() {
            Ok(t) if t.is_dir() => "/",
            Ok(t) if t.is_symlink() => "@",
            _ => "",
        };
        rows.push(format!("{name}{marker}"));
    }
    rows.sort();

    let mut capped = false;
    if rows.len() > MAX_DIR_ENTRIES {
        rows.truncate(MAX_DIR_ENTRIES);
        capped = true;
    }

    let mut out = if rows.is_empty() {
        "(표시할 엔트리 없음)".to_string()
    } else {
        rows.join("\n")
    };
    if capped {
        out.push_str(&format!("\n…[{MAX_DIR_ENTRIES} 엔트리 상한 도달]"));
    }
    if hidden_skipped > 0 {
        out.push_str(&format!("\n[hidden {hidden_skipped}개 제외]"));
    }
    if ignored_skipped > 0 {
        out.push_str(&format!("\n[gitignore {ignored_skipped}개 제외]"));
    }
    Ok(out)
}

/// `grep` — 정규식으로 라인 검색. base가 디렉터리면 재귀(hidden/`.git`/symlink 제외).
pub fn grep(args: &Value, sb: &Sandbox) -> Result<String, ToolError> {
    let pattern = arg_str(args, "pattern")?;
    let re = regex::Regex::new(pattern).map_err(|e| ToolError::new(format!("정규식 오류: {e}")))?;
    let base_arg = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let base = sb.resolve(base_arg)?;
    let max_matches = args
        .get("max_matches")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(MAX_GREP_MATCHES)
        .min(MAX_GREP_MATCHES);

    let mut files: Vec<PathBuf> = Vec::new();
    if base.is_file() {
        files.push(base.clone());
    } else {
        collect_files(&base, sb, 0, &mut files);
    }

    let mut out: Vec<String> = Vec::new();
    'outer: for f in files {
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if is_secret_file(name) {
            continue;
        }
        let bytes = match std::fs::read(&f) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let scan = bytes.len().min(BINARY_SCAN_BYTES);
        if bytes[..scan].contains(&0) {
            continue; // binary skip
        }
        let text = String::from_utf8_lossy(&bytes);
        let rel = f.strip_prefix(sb.root()).unwrap_or(&f).to_string_lossy();
        for (idx, line) in text.lines().enumerate() {
            if re.is_match(line) {
                let shown = truncate_chars(line, MAX_GREP_LINE_LEN);
                out.push(format!("{rel}:{}:{shown}", idx + 1));
                if out.len() >= max_matches {
                    out.push(format!("…[{max_matches} 매치 상한 도달]"));
                    break 'outer;
                }
            }
        }
    }

    if out.is_empty() {
        Ok("(매치 없음)".to_string())
    } else {
        Ok(out.join("\n"))
    }
}

/// `glob` — 와일드카드 패턴으로 root 기준 상대 경로 매칭(`*`,`**`,`?`).
pub fn glob(args: &Value, sb: &Sandbox) -> Result<String, ToolError> {
    let pattern = arg_str(args, "pattern")?;
    let re = regex::Regex::new(&glob_to_regex(pattern))
        .map_err(|e| ToolError::new(format!("glob 패턴 오류: {e}")))?;

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(sb.root(), sb, 0, &mut files);

    let mut out: Vec<String> = Vec::new();
    for f in files {
        let rel = match f.strip_prefix(sb.root()) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if re.is_match(&rel) {
            out.push(rel);
            if out.len() >= MAX_GLOB_RESULTS {
                out.sort();
                out.push(format!("…[{MAX_GLOB_RESULTS} 결과 상한 도달]"));
                return Ok(out.join("\n"));
            }
        }
    }
    out.sort();
    if out.is_empty() {
        Ok("(매치 없음)".to_string())
    } else {
        Ok(out.join("\n"))
    }
}

/// glob 패턴을 정규식으로 변환한다. `**`=임의 디렉터리, `*`=`/` 제외 임의, `?`=`/` 제외 1자.
fn glob_to_regex(pattern: &str) -> String {
    let mut re = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    if chars.peek() == Some(&'/') {
                        chars.next();
                        re.push_str("(?:.*/)?"); // `**/` → 0개 이상 디렉터리
                    } else {
                        re.push_str(".*"); // 후행 `**`
                    }
                } else {
                    re.push_str("[^/]*");
                }
            }
            '?' => re.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    re.push('$');
    re
}

/// root 하위를 재귀로 walk하며 파일 경로를 모은다.
/// hidden/`.git`/symlink는 따라가지 않고(샌드박스 탈출 차단), gitignore된
/// 디렉터리/파일도 제외한다(디렉터리 제외 시 하위로 재귀하지 않음).
fn collect_files(dir: &Path, sb: &Sandbox, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_WALK_DEPTH || out.len() >= MAX_WALK_FILES {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if is_hidden_or_vcs(&name) {
            continue;
        }
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue; // symlink는 따라가지 않음(탈출 가드)
        }
        let p = ent.path();
        if sb.is_ignored(&p, ft.is_dir()) {
            continue; // gitignore 제외
        }
        if ft.is_dir() {
            collect_files(&p, sb, depth + 1, out);
        } else if ft.is_file() {
            out.push(p);
            if out.len() >= MAX_WALK_FILES {
                return;
            }
        }
    }
}

// ── registry ──────────────────────────────────────────────

/// 등록된 읽기 전용 도구 스펙(LLM 노출용). 쓰기/실행 도구는 의도적으로 미등록.
pub fn read_only_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "read_file",
            description: "샌드박스(cwd) 내 단일 파일의 텍스트 내용을 읽는다. secrets/바이너리는 거부/요약된다.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "cwd 기준 상대 경로" },
                    "max_bytes": { "type": "integer", "description": "최대 읽기 바이트(선택)" }
                },
                "required": ["path"]
            }),
        },
        ToolSpec {
            name: "list_dir",
            description: "디렉터리의 엔트리 목록을 반환한다(hidden 제외). path 생략 시 cwd.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "cwd 기준 상대 경로(기본 '.')" }
                }
            }),
        },
        ToolSpec {
            name: "grep",
            description: "정규식으로 파일 내 라인을 검색한다. path가 디렉터리면 재귀 검색.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Rust regex 패턴" },
                    "path": { "type": "string", "description": "검색 시작 경로(기본 '.')" },
                    "max_matches": { "type": "integer", "description": "최대 매치 수(선택)" }
                },
                "required": ["pattern"]
            }),
        },
        ToolSpec {
            name: "glob",
            description: "와일드카드(*, **, ?)로 cwd 하위 파일 경로를 찾는다.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "예: src/**/*.rs" }
                },
                "required": ["pattern"]
            }),
        },
    ]
}

/// 도구 이름으로 dispatch한다. 미지원 이름은 tool 에러로 회신(loop 지속).
pub fn execute(name: &str, args: &Value, sb: &Sandbox) -> Result<String, ToolError> {
    match name {
        "read_file" => read_file(args, sb),
        "list_dir" => list_dir(args, sb),
        "grep" => grep(args, sb),
        "glob" => glob(args, sb),
        other => Err(ToolError::new(format!("미지원 도구: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sandbox_with_files() -> (tempfile::TempDir, Sandbox) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("hello.txt"), "hello world\nsecond line").unwrap();
        fs::write(root.join(".env"), "API_KEY=secret123").unwrap();
        fs::write(root.join(".hidden"), "hidden content").unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src").join("main.rs"), "fn main() { let x = 1; }").unwrap();
        fs::write(root.join("src").join("util.rs"), "pub fn util() {}").unwrap();
        // binary file (NUL 포함)
        fs::write(root.join("blob.bin"), [0u8, 1, 2, 3, 0, 5]).unwrap();
        let sb = Sandbox::new(root).unwrap();
        (dir, sb)
    }

    #[test]
    fn read_file_normal() {
        let (_d, sb) = sandbox_with_files();
        let out = read_file(&json!({ "path": "hello.txt" }), &sb).unwrap();
        assert!(out.contains("hello world"));
        assert!(out.contains("second line"));
    }

    #[test]
    fn read_file_secret_rejected() {
        let (_d, sb) = sandbox_with_files();
        let err = read_file(&json!({ "path": ".env" }), &sb).unwrap_err();
        assert!(err.message.contains("secrets"));
    }

    #[test]
    fn read_file_binary_returns_metadata_only() {
        let (_d, sb) = sandbox_with_files();
        let out = read_file(&json!({ "path": "blob.bin" }), &sb).unwrap();
        assert!(out.contains("binary file"));
        assert!(!out.contains('\u{1}'));
    }

    #[test]
    fn read_file_large_truncated() {
        let (dir, sb) = sandbox_with_files();
        let big = "a".repeat(2048);
        fs::write(dir.path().join("big.txt"), &big).unwrap();
        let out = read_file(&json!({ "path": "big.txt", "max_bytes": 100 }), &sb).unwrap();
        assert!(out.contains("truncated"));
        // 표시 본문(notice 이전)은 정확히 100 bytes로 제한된다.
        let body = out.split("\n…[truncated").next().unwrap();
        assert_eq!(body.matches('a').count(), 100);
    }

    #[test]
    fn read_file_missing_path_arg_errors() {
        let (_d, sb) = sandbox_with_files();
        assert!(read_file(&json!({}), &sb).is_err());
    }

    #[test]
    fn list_dir_skips_hidden() {
        let (_d, sb) = sandbox_with_files();
        let out = list_dir(&json!({ "path": "." }), &sb).unwrap();
        assert!(out.contains("hello.txt"));
        assert!(out.contains("src/"));
        assert!(!out.contains(".env"));
        assert!(!out.contains(".hidden"));
        assert!(out.contains("hidden") && out.contains("제외"));
    }

    #[test]
    fn grep_finds_matches() {
        let (_d, sb) = sandbox_with_files();
        let out = grep(&json!({ "pattern": "fn ", "path": "src" }), &sb).unwrap();
        assert!(out.contains("main.rs"));
        assert!(out.contains("util.rs"));
    }

    #[test]
    fn grep_skips_secret_and_binary() {
        let (_d, sb) = sandbox_with_files();
        // secret 값과 binary는 검색 대상에서 제외.
        let out = grep(&json!({ "pattern": "secret123" }), &sb).unwrap();
        assert_eq!(out, "(매치 없음)");
    }

    #[test]
    fn glob_matches_pattern() {
        let (_d, sb) = sandbox_with_files();
        let out = glob(&json!({ "pattern": "src/**/*.rs" }), &sb).unwrap();
        assert!(out.contains("src/main.rs"));
        assert!(out.contains("src/util.rs"));
        assert!(!out.contains("hello.txt"));
    }

    /// gitignore된 non-dot 파일/디렉터리가 모든 읽기 도구에서 제외/거부되는지.
    fn sandbox_with_gitignore() -> (tempfile::TempDir, Sandbox) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join(".gitignore"), "ignored.txt\nbuild/\n*.log\n").unwrap();
        fs::write(root.join("ignored.txt"), "TOPSECRET_TOKEN").unwrap();
        fs::write(root.join("keep.txt"), "keep me").unwrap();
        fs::write(root.join("app.log"), "log line").unwrap();
        fs::create_dir(root.join("build")).unwrap();
        fs::write(root.join("build").join("out.bin.txt"), "artifact").unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src").join("main.rs"), "fn main() {}").unwrap();
        // Sandbox::new가 .gitignore를 로드한다.
        let sb = Sandbox::new(root).unwrap();
        (dir, sb)
    }

    #[test]
    fn read_file_gitignored_nondot_file_rejected() {
        let (_d, sb) = sandbox_with_gitignore();
        let err = read_file(&json!({ "path": "ignored.txt" }), &sb).unwrap_err();
        assert!(err.message.contains("gitignore"));
        // ignore 안 된 파일은 정상.
        assert!(read_file(&json!({ "path": "keep.txt" }), &sb).is_ok());
    }

    #[test]
    fn read_file_inside_gitignored_dir_rejected() {
        let (_d, sb) = sandbox_with_gitignore();
        let err = read_file(&json!({ "path": "build/out.bin.txt" }), &sb).unwrap_err();
        assert!(err.message.contains("gitignore"));
    }

    #[test]
    fn list_dir_skips_gitignored() {
        let (_d, sb) = sandbox_with_gitignore();
        let out = list_dir(&json!({ "path": "." }), &sb).unwrap();
        assert!(out.contains("keep.txt"));
        assert!(out.contains("src/"));
        assert!(!out.contains("ignored.txt"));
        assert!(!out.contains("build"));
        assert!(!out.contains("app.log"));
        assert!(out.contains("gitignore") && out.contains("제외"));
    }

    #[test]
    fn glob_skips_gitignored() {
        let (_d, sb) = sandbox_with_gitignore();
        let out = glob(&json!({ "pattern": "**/*" }), &sb).unwrap();
        assert!(out.contains("keep.txt"));
        assert!(out.contains("src/main.rs"));
        assert!(!out.contains("ignored.txt"));
        assert!(!out.contains("build/"));
        assert!(!out.contains("app.log"));
    }

    #[test]
    fn grep_skips_gitignored() {
        let (_d, sb) = sandbox_with_gitignore();
        // ignored.txt의 내용은 검색되지 않아야 한다.
        let out = grep(&json!({ "pattern": "TOPSECRET_TOKEN" }), &sb).unwrap();
        assert_eq!(out, "(매치 없음)");
    }

    #[test]
    fn glob_to_regex_basics() {
        assert_eq!(glob_to_regex("*.rs"), "^[^/]*\\.rs$");
        assert_eq!(glob_to_regex("src/**/*.rs"), "^src/(?:.*/)?[^/]*\\.rs$");
        assert_eq!(glob_to_regex("a?b"), "^a[^/]b$");
    }

    #[test]
    fn execute_unknown_tool_errors() {
        let (_d, sb) = sandbox_with_files();
        let err = execute("write_file", &json!({}), &sb).unwrap_err();
        assert!(err.message.contains("미지원 도구"));
    }

    #[test]
    fn execute_dispatches_read_file() {
        let (_d, sb) = sandbox_with_files();
        let out = execute("read_file", &json!({ "path": "hello.txt" }), &sb).unwrap();
        assert!(out.contains("hello world"));
    }

    #[test]
    fn read_only_specs_contains_no_write_tools() {
        let names: Vec<&str> = read_only_specs().iter().map(|s| s.name).collect();
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"list_dir"));
        assert!(names.contains(&"grep"));
        assert!(names.contains(&"glob"));
        // 읽기 전용 불변식: 쓰기/실행 도구 미등록.
        assert!(!names.contains(&"write_file"));
        assert!(!names.contains(&"edit_file"));
        assert!(!names.contains(&"run_command"));
    }

    #[test]
    fn is_secret_file_detects_common_secrets() {
        assert!(is_secret_file(".env"));
        assert!(is_secret_file(".env.local"));
        assert!(is_secret_file("server.pem"));
        assert!(is_secret_file("id_rsa"));
        assert!(is_secret_file("backup.key"));
        assert!(!is_secret_file("main.rs"));
        assert!(!is_secret_file("README.md"));
    }
}
