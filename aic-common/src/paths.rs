//! Cross-platform 소켓 경로 및 설정 경로 결정
//!
//! - macOS: `/tmp/aic-{uid}/session.sock`
//! - Linux: `$XDG_RUNTIME_DIR/aic/session.sock` (설정 시), 아니면 `/tmp/aic-{uid}/session.sock`
//!
//! Requirements: 2.1, 7.1, 7.3, 11.1, 11.2, 11.4

use std::path::{Path, PathBuf};

/// UDS 소켓 경로를 결정한다.
/// 현재 OS를 자동 감지하여 플랫폼 관례에 따른 경로를 반환한다.
pub fn default_socket_path() -> PathBuf {
    resolve_socket_path(std::env::consts::OS)
}

/// 지정된 OS 문자열에 따라 소켓 경로를 결정한다.
/// 테스트에서 OS를 주입할 수 있도록 분리.
pub fn resolve_socket_path(os: &str) -> PathBuf {
    session_dir_for_os(os).join("session.sock")
}

// ── 세션별 경로 함수 ──────────────────────────────────────────

/// 플랫폼별 세션 디렉토리를 반환한다.
/// macOS: `/tmp/aic-{uid}/`
/// Linux: `$XDG_RUNTIME_DIR/aic/` (설정 시) 또는 `/tmp/aic-{uid}/`
pub fn session_dir() -> PathBuf {
    session_dir_for_os(std::env::consts::OS)
}

/// OS 문자열을 주입받아 세션 디렉토리를 결정한다 (테스트용).
fn session_dir_for_os(os: &str) -> PathBuf {
    match os {
        "linux" => {
            if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                PathBuf::from(runtime_dir).join("aic")
            } else {
                tmp_session_dir()
            }
        }
        _ => tmp_session_dir(),
    }
}

/// `/tmp/aic-{uid}/` 경로 생성
fn tmp_session_dir() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/aic-{}", uid))
}

/// Session_ID를 인자로 받아 세션별 소켓 경로를 반환한다.
/// 예: `/tmp/aic-{uid}/session-a1b2c3d4.sock`
pub fn session_socket_path(session_id: &str) -> PathBuf {
    session_dir().join(format!("session-{}.sock", session_id))
}

/// `aicd` supervisor daemon의 control UDS 소켓 경로.
/// 사용자당 하나만 존재한다.
pub fn aicd_socket_path() -> PathBuf {
    session_dir().join("aicd.sock")
}

/// `aicd` supervisor daemon의 PID lock 파일 경로.
pub fn aicd_lock_path() -> PathBuf {
    session_dir().join("aicd.pid")
}

/// `aicd` supervisor daemon의 registry snapshot 경로.
///
/// 런타임 세션 복구용이므로 control socket/lock과 같은 session_dir 아래에 둔다.
pub fn aicd_registry_path() -> PathBuf {
    session_dir().join("aicd-registry.json")
}

/// daemonless mode에서 `aic`가 읽는 마지막 command record 경로.
pub fn local_command_record_path() -> PathBuf {
    session_dir().join("last-command.json")
}

/// shell hook start/end 사이의 임시 metadata 경로.
pub fn local_hook_pending_path(session_id: &str, command_id: &str) -> PathBuf {
    let safe_session = sanitize_path_token(session_id);
    let safe_command = sanitize_path_token(command_id);
    session_dir().join(format!("hook-pending-{safe_session}-{safe_command}.json"))
}

fn sanitize_path_token(value: &str) -> String {
    let out: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(64)
        .collect();
    if out.is_empty() {
        "none".to_string()
    } else {
        out
    }
}

/// 소켓 경로에서 Session_ID를 추출한다.
/// `session-{id}.sock` 형식의 파일명에서 `{id}` 부분을 반환한다.
/// 형식이 맞지 않으면 `None`을 반환한다.
pub fn extract_session_id(socket_path: &Path) -> Option<String> {
    let file_name = socket_path.file_name()?.to_str()?;
    let id = file_name.strip_prefix("session-")?.strip_suffix(".sock")?;
    if id.is_empty() {
        return None;
    }
    Some(id.to_string())
}

/// `session_dir()` 안의 모든 `session-*.sock` 파일을 mtime 내림차순(최신 우선)으로 반환.
pub fn list_session_sockets() -> Vec<PathBuf> {
    list_session_sockets_in(&session_dir())
}

/// 테스트 가능한 inner helper — 임의 디렉토리에서 `session-*.sock` 파일 enumerate.
pub fn list_session_sockets_in(dir: &Path) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut paths: Vec<(PathBuf, std::time::SystemTime)> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_str()?;
            if !name.starts_with("session-") || !name.ends_with(".sock") {
                return None;
            }
            let mtime = e.metadata().ok().and_then(|m| m.modified().ok())?;
            Some((p, mtime))
        })
        .collect();
    // mtime 내림차순(최신 우선). clippy::unnecessary_sort_by 회피용 sort_by_key + Reverse.
    paths.sort_by_key(|p| std::cmp::Reverse(p.1));
    paths.into_iter().map(|(p, _)| p).collect()
}

/// 활성 세션 소켓 경로를 우선순위에 따라 결정한다.
/// 우선순위: explicit_id > $AIC_SESSION_ID env > 가장 최근 session-*.sock > legacy default_socket_path.
pub fn resolve_active_socket(explicit_id: Option<&str>) -> PathBuf {
    if let Some(id) = explicit_id.map(str::trim).filter(|s| !s.is_empty()) {
        return session_socket_path(id);
    }
    if let Ok(env_id) = std::env::var("AIC_SESSION_ID") {
        let trimmed = env_id.trim();
        if !trimmed.is_empty() {
            return session_socket_path(trimmed);
        }
    }
    list_session_sockets()
        .into_iter()
        .next()
        .unwrap_or_else(default_socket_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_is_absolute() {
        let path = default_socket_path();
        assert!(path.is_absolute());
    }

    #[test]
    fn default_socket_path_ends_with_session_sock() {
        let path = default_socket_path();
        assert!(path.ends_with("session.sock"));
    }

    #[test]
    fn resolve_linux_with_xdg_runtime() {
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let path = resolve_socket_path("linux");
        assert_eq!(path, PathBuf::from("/run/user/1000/aic/session.sock"));
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn resolve_linux_without_xdg_runtime() {
        std::env::remove_var("XDG_RUNTIME_DIR");
        let path = resolve_socket_path("linux");
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/aic-{}/session.sock", uid))
        );
    }

    #[test]
    fn resolve_macos() {
        let path = resolve_socket_path("macos");
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/aic-{}/session.sock", uid))
        );
    }

    // ── session_dir tests ──────────────────────────────────────

    #[test]
    fn session_dir_is_absolute() {
        assert!(session_dir().is_absolute());
    }

    // ── session_socket_path tests ──────────────────────────────

    #[test]
    fn session_socket_path_format() {
        let path = session_socket_path("a1b2c3d4");
        assert!(path.is_absolute());
        assert!(path.ends_with("session-a1b2c3d4.sock"));
    }

    #[test]
    fn session_socket_path_under_session_dir() {
        let path = session_socket_path("deadbeef");
        assert_eq!(path.parent().unwrap(), session_dir());
    }

    #[test]
    fn aicd_registry_path_under_session_dir() {
        let path = aicd_registry_path();
        assert_eq!(path.parent().unwrap(), session_dir());
        assert!(path.ends_with("aicd-registry.json"));
    }

    #[test]
    fn local_command_record_path_under_session_dir() {
        let path = local_command_record_path();
        assert_eq!(path.parent().unwrap(), session_dir());
        assert!(path.ends_with("last-command.json"));
    }

    #[test]
    fn local_hook_pending_path_sanitizes_tokens() {
        let path = local_hook_pending_path("../bad", "cmd/123!");
        let name = path.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "hook-pending-bad-cmd123.json");
    }

    // ── extract_session_id tests ───────────────────────────────

    #[test]
    fn extract_session_id_roundtrip() {
        let id = "a1b2c3d4";
        let path = session_socket_path(id);
        assert_eq!(extract_session_id(&path), Some(id.to_string()));
    }

    #[test]
    fn extract_session_id_invalid_paths() {
        // 잘못된 prefix
        assert_eq!(
            extract_session_id(Path::new("/tmp/aic-501/other-abc.sock")),
            None
        );
        // 잘못된 suffix
        assert_eq!(
            extract_session_id(Path::new("/tmp/aic-501/session-abc.pid")),
            None
        );
        // 빈 ID
        assert_eq!(
            extract_session_id(Path::new("/tmp/aic-501/session-.sock")),
            None
        );
        // 디렉토리만
        assert_eq!(extract_session_id(Path::new("/tmp/aic-501/")), None);
    }

    // ── list_session_sockets_in ──────────────────────────────
    use std::fs;
    use std::time::Duration;

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("aic-paths-test-{tag}-{pid}-{nanos}"));
        fs::create_dir_all(&dir).expect("create_dir_all");
        dir
    }

    #[test]
    fn list_session_sockets_empty_dir() {
        let dir = unique_temp_dir("empty");
        let paths = list_session_sockets_in(&dir);
        assert!(paths.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_session_sockets_filters_non_session_files() {
        let dir = unique_temp_dir("filter");
        fs::write(dir.join("session-abc.sock"), b"").unwrap();
        fs::write(dir.join("session.sock"), b"").unwrap(); // legacy 형식 → 제외
        fs::write(dir.join("not-a-session.sock"), b"").unwrap(); // prefix 불일치 → 제외
        fs::write(dir.join("session-def.pid"), b"").unwrap(); // suffix 불일치 → 제외
        let paths = list_session_sockets_in(&dir);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].to_string_lossy().ends_with("session-abc.sock"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_session_sockets_orders_by_mtime_desc() {
        let dir = unique_temp_dir("order");
        let old = dir.join("session-old.sock");
        let mid = dir.join("session-mid.sock");
        let new = dir.join("session-new.sock");
        fs::write(&old, b"").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&mid, b"").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&new, b"").unwrap();
        let paths = list_session_sockets_in(&dir);
        assert_eq!(paths.len(), 3);
        assert!(paths[0].to_string_lossy().ends_with("session-new.sock"));
        assert!(paths[1].to_string_lossy().ends_with("session-mid.sock"));
        assert!(paths[2].to_string_lossy().ends_with("session-old.sock"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_session_sockets_missing_dir_returns_empty() {
        let dir = std::env::temp_dir().join("aic-paths-test-nonexistent-xyz123");
        let _ = fs::remove_dir_all(&dir); // ensure missing
        let paths = list_session_sockets_in(&dir);
        assert!(paths.is_empty());
    }
}
