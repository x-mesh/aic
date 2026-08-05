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

/// systemd `--user` 세션의 표준 런타임 디렉토리 아래 aic 디렉토리 (`/run/user/{uid}/aic`).
/// `XDG_RUNTIME_DIR`이 비어 있을 때의 대체 후보로만 쓴다.
fn run_user_session_dir() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{}/aic", uid))
}

// ── aicd 경로: 만드는 쪽과 찾는 쪽의 분리 ────────────────────────
//
// `session_dir()`는 **현재 프로세스의 환경**만 보고 한 곳을 정하는데, 그 환경이 데몬의
// 환경과 다를 수 있다. systemd `--user`로 뜬 aicd에는 `XDG_RUNTIME_DIR`이 있어 소켓이
// `/run/user/{uid}/aic`에 생기지만, 로그인 셸이 아닌 곳(`make`, cron, 에이전트 셸)에는
// 그 변수가 없어 `session_dir()`가 `/tmp/aic-{uid}`로 갈린다. 그러면 클라이언트는 멀쩡히
// 도는 데몬을 "실행 중이 아님"으로 본다 — `aic daemon restart --if-running`이 조용히
// skip돼 `make install`/`aic update` 뒤에도 구버전 데몬이 계속 도는 사고가 여기서 났다.
//
// 그래서 **찾을 때만**(`aicd_*_path`) 두 관례를 순서대로 훑어 실제 소켓이 있는 쪽을 쓴다.
// 만드는 쪽(`aicd_*_path_for_bind`)은 `session_dir()` 한 곳으로 고정한다 — 파일 잔해에
// 따라 데몬이 매번 다른 곳에 bind하면 그게 더 찾기 어려운 문제가 된다.

const AICD_SOCKET_FILE: &str = "aicd.sock";
const AICD_LOCK_FILE: &str = "aicd.pid";
const AICD_ATTACH_SOCKET_FILE: &str = "aicd-attach.sock";
const AICD_REGISTRY_FILE: &str = "aicd-registry.json";

/// aicd를 찾을 때 훑을 세션 디렉토리 후보. 0번이 정규 경로(`session_dir()`)다.
fn session_dir_candidates_for_os(os: &str) -> Vec<PathBuf> {
    let canonical = session_dir_for_os(os);
    if os != "linux" {
        return vec![canonical];
    }
    // linux의 두 관례를 서로의 대체 후보로 둔다. XDG가 **설정돼 있으면** `/run/user/{uid}`는
    // 후보에 넣지 않는다 — 격리 환경(테스트/컨테이너)이 의도적으로 다른 런타임 디렉토리를
    // 가리킨 상황이라, 거기서 시스템 데몬으로 새는 편이 못 찾는 것보다 나쁘다.
    let alt = if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        tmp_session_dir()
    } else {
        run_user_session_dir()
    };
    if alt == canonical {
        vec![canonical]
    } else {
        vec![canonical, alt]
    }
}

/// 후보 중 실제 `aicd.sock`이 있는 첫 디렉토리. 아무 데도 없으면 정규 경로(= 종전 동작).
///
/// 소켓 하나를 기준점으로 삼아 lock·registry·attach까지 같은 디렉토리에서 뽑는다 —
/// 파일마다 따로 탐색하면 `aic daemon status`가 한쪽의 socket과 다른 쪽의 pid를 섞어
/// 보여줄 수 있다.
fn resolve_aicd_dir(candidates: &[PathBuf]) -> PathBuf {
    candidates
        .iter()
        .find(|dir| dir.join(AICD_SOCKET_FILE).exists())
        .or_else(|| candidates.first())
        .cloned()
        .unwrap_or_else(session_dir)
}

fn aicd_dir() -> PathBuf {
    resolve_aicd_dir(&session_dir_candidates_for_os(std::env::consts::OS))
}

/// Session_ID를 인자로 받아 세션별 소켓 경로를 반환한다.
/// 예: `/tmp/aic-{uid}/session-a1b2c3d4.sock`
pub fn session_socket_path(session_id: &str) -> PathBuf {
    session_dir().join(format!("session-{}.sock", session_id))
}

/// `aicd` supervisor daemon의 control UDS 소켓 경로 (탐색).
/// 사용자당 하나만 존재한다.
pub fn aicd_socket_path() -> PathBuf {
    aicd_dir().join(AICD_SOCKET_FILE)
}

/// `aicd` supervisor daemon의 PID lock 파일 경로 (탐색).
pub fn aicd_lock_path() -> PathBuf {
    aicd_dir().join(AICD_LOCK_FILE)
}

/// `aicd` supervisor daemon의 Attach_UDS 소켓 경로 (Phase 3.3, 탐색).
///
/// `aic-session` 이 PTY raw byte stream 을 `aicd` 로 보낼 때 사용한다.
/// Control_UDS(`aicd.sock`) 와 같은 부모 디렉토리(0700) 아래에 두며,
/// 소켓 파일 자체 권한은 0600 (R15.3).
pub fn aicd_attach_socket_path() -> PathBuf {
    aicd_dir().join(AICD_ATTACH_SOCKET_FILE)
}

/// `aicd` supervisor daemon의 registry snapshot 경로 (탐색).
///
/// 런타임 세션 복구용이므로 control socket/lock과 같은 디렉토리 아래에 둔다.
pub fn aicd_registry_path() -> PathBuf {
    aicd_dir().join(AICD_REGISTRY_FILE)
}

/// aicd가 control UDS를 **만들** 때 쓰는 정규 경로. 탐색과 달리 파일 존재 여부를 보지 않는다.
pub fn aicd_socket_path_for_bind() -> PathBuf {
    session_dir().join(AICD_SOCKET_FILE)
}

/// aicd가 PID lock을 **만들** 때 쓰는 정규 경로.
pub fn aicd_lock_path_for_bind() -> PathBuf {
    session_dir().join(AICD_LOCK_FILE)
}

/// aicd가 Attach_UDS를 **만들** 때 쓰는 정규 경로.
pub fn aicd_attach_socket_path_for_bind() -> PathBuf {
    session_dir().join(AICD_ATTACH_SOCKET_FILE)
}

/// aicd가 registry snapshot을 **쓸** 때의 정규 경로.
pub fn aicd_registry_path_for_bind() -> PathBuf {
    session_dir().join(AICD_REGISTRY_FILE)
}

/// daemonless mode에서 `aic`가 읽는 마지막 command record 경로.
pub fn local_command_record_path() -> PathBuf {
    session_dir().join("last-command.json")
}

/// 영속 상태 디렉터리 (XDG State). `$XDG_STATE_HOME/aic` 또는 `~/.local/state/aic`.
/// session_dir(runtime, ephemeral)과 달리 재부팅을 넘어 보존되는 로그/이벤트용.
pub fn state_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(xdg).join("aic")
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~"));
        home.join(".local").join("state").join("aic")
    }
}

/// aicd webhook 수신·처리 이벤트 로그(JSONL) 경로 (SRE R2). `aic webhook list`가 읽는다.
pub fn webhook_events_path() -> PathBuf {
    state_dir().join("webhook-events.jsonl")
}

/// `config.toml` 경로 (XDG Base Directory). aic-client(ConfigManager)와 aicd(aic-server)가
/// 동일 경로를 읽도록 단일 출처로 둔다. `$XDG_CONFIG_HOME/aic/config.toml` 또는 `~/.config/aic/config.toml`.
pub fn config_file_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("aic").join("config.toml")
    } else {
        // aic-common은 lean하게 유지(dirs 미사용) — HOME에서 직접 결정.
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~"));
        home.join(".config").join("aic").join("config.toml")
    }
}

/// aicd OTLP exporter 오프라인 spool 디렉토리 (SRE t8). `~/.aic/otlp-spool/`.
///
/// 다른 aic 경로들과 달리 XDG 관례(`state_dir`/`config_file_path`) 대신 고정 `~/.aic` 하위를
/// 쓴다 — t8 interface contract가 이 경로를 명시했고, spool은 세션 runtime도 XDG state도
/// 아닌 "collector 다운 동안 버티는 로컬 디스크 버퍼"라는 별도 범주라 구분해 두는 편이 찾기
/// 쉽다. 디렉토리는 `Spool::open`이 0700 권한으로 생성한다(다른 로컬 사용자가 spool된 —
/// 이미 redact된 — protobuf payload를 못 읽게).
pub fn otlp_spool_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    home.join(".aic").join("otlp-spool")
}

/// aicd 로그 수집기(journald/file/container) 체크포인트 디렉토리 (RFC-006). `~/.aic/log-checkpoints/`.
///
/// `otlp_spool_dir`과 동일한 이유로 XDG 관례 대신 고정 `~/.aic` 하위를 쓴다 — 이 디렉토리는
/// 세션 runtime도 XDG state도 아닌 "재시작 후 이어 읽기 위한 로컬 커서 저장소"라는 별도
/// 범주다. 디렉토리는 `CheckpointStore::open`이 0700 권한으로 생성한다.
pub fn log_checkpoint_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    home.join(".aic").join("log-checkpoints")
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

    // XDG_RUNTIME_DIR은 프로세스 전역이라, 이를 set/remove하는 테스트들이 병렬 실행되면
    // 한 테스트가 assert 하기 전에 다른 테스트가 값을 바꿔 간헐적으로 깨진다(env-race).
    // 아래 락으로 직렬화하고, 각 테스트는 원래 값을 저장했다가 복원한다.
    static XDG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_linux_with_xdg_runtime() {
        let _guard = XDG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let path = resolve_socket_path("linux");
        assert_eq!(path, PathBuf::from("/run/user/1000/aic/session.sock"));
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn resolve_linux_without_xdg_runtime() {
        let _guard = XDG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let path = resolve_socket_path("linux");
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/aic-{}/session.sock", uid))
        );
        if let Some(v) = prev {
            std::env::set_var("XDG_RUNTIME_DIR", v);
        }
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

    // ── aicd 경로: bind(정규) vs 탐색 ──────────────────────────

    /// 만드는 쪽은 환경만 보고 `session_dir()` 한 곳으로 고정돼야 한다.
    #[test]
    fn aicd_bind_paths_are_pinned_to_session_dir() {
        for (path, name) in [
            (aicd_socket_path_for_bind(), "aicd.sock"),
            (aicd_lock_path_for_bind(), "aicd.pid"),
            (aicd_attach_socket_path_for_bind(), "aicd-attach.sock"),
            (aicd_registry_path_for_bind(), "aicd-registry.json"),
        ] {
            assert_eq!(path.parent().unwrap(), session_dir(), "{name}");
            assert!(path.ends_with(name));
        }
    }

    /// 탐색 결과는 네 경로가 **같은** 디렉토리에서 나와야 한다 — socket은 이쪽,
    /// pid는 저쪽으로 갈리면 `aic daemon status`가 섞인 정보를 보여준다.
    #[test]
    fn aicd_discovered_paths_share_one_dir() {
        let dir = aicd_socket_path().parent().unwrap().to_path_buf();
        assert_eq!(aicd_lock_path().parent().unwrap(), dir);
        assert_eq!(aicd_attach_socket_path().parent().unwrap(), dir);
        assert_eq!(aicd_registry_path().parent().unwrap(), dir);
    }

    #[test]
    fn resolve_aicd_dir_prefers_canonical_when_socket_is_there() {
        let canonical = unique_temp_dir("aicd-canonical");
        let alt = unique_temp_dir("aicd-alt");
        fs::write(canonical.join(AICD_SOCKET_FILE), b"").unwrap();
        fs::write(alt.join(AICD_SOCKET_FILE), b"").unwrap();
        assert_eq!(
            resolve_aicd_dir(&[canonical.clone(), alt.clone()]),
            canonical
        );
        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    /// 이 테스트가 지키는 것: systemd로 뜬 aicd(대체 후보)를 XDG 없는 셸(정규=/tmp)에서
    /// 찾아내는 동작. 깨지면 `make install` 후 재시작이 조용히 skip된다.
    #[test]
    fn resolve_aicd_dir_falls_back_to_alt_when_canonical_is_empty() {
        let canonical = unique_temp_dir("aicd-empty");
        let alt = unique_temp_dir("aicd-live");
        fs::write(alt.join(AICD_SOCKET_FILE), b"").unwrap();
        assert_eq!(resolve_aicd_dir(&[canonical.clone(), alt.clone()]), alt);
        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    /// 어디에도 소켓이 없으면 종전대로 정규 경로 — 데몬 미실행 시 표시할 경로가 필요하다.
    #[test]
    fn resolve_aicd_dir_defaults_to_canonical_when_nothing_found() {
        let canonical = unique_temp_dir("aicd-none-a");
        let alt = unique_temp_dir("aicd-none-b");
        assert_eq!(
            resolve_aicd_dir(&[canonical.clone(), alt.clone()]),
            canonical
        );
        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    #[test]
    fn session_dir_candidates_without_xdg_include_run_user() {
        let _guard = XDG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let candidates = session_dir_candidates_for_os("linux");
        assert_eq!(candidates[0], tmp_session_dir(), "0번은 정규 경로");
        assert_eq!(
            candidates[1],
            run_user_session_dir(),
            "systemd --user 쪽 대체"
        );
        if let Some(v) = prev {
            std::env::set_var("XDG_RUNTIME_DIR", v);
        }
    }

    /// XDG가 잡혀 있으면 `/run/user/{uid}`는 후보가 아니다 — 격리 환경이 의도적으로
    /// 다른 런타임 디렉토리를 가리킨 것이라, 시스템 데몬으로 새면 안 된다.
    #[test]
    fn session_dir_candidates_with_xdg_do_not_leak_to_run_user() {
        let _guard = XDG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", "/tmp/isolated-runtime");
        let candidates = session_dir_candidates_for_os("linux");
        assert_eq!(candidates[0], PathBuf::from("/tmp/isolated-runtime/aic"));
        assert_eq!(candidates[1], tmp_session_dir());
        assert!(!candidates.contains(&run_user_session_dir()));
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn session_dir_candidates_on_macos_has_only_tmp() {
        assert_eq!(
            session_dir_candidates_for_os("macos"),
            vec![tmp_session_dir()]
        );
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
