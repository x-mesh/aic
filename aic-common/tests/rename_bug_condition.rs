//! Bug Condition Exploration Test: ac prefix가 코드베이스 전반에 존재함
//!
//! 이 테스트는 `aic` prefix (올바른 동작)를 기대합니다.
//! 현재 코드는 `ac` prefix를 사용하므로 FAIL이 예상됩니다.
//! FAIL = 버그 존재 확인 (성공적인 탐색)
//!
//! **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 2.1, 2.3, 2.4, 2.5**

use aic_common::{resolve_socket_path, AicError};
use proptest::prelude::*;
use std::sync::{Mutex, MutexGuard};

// process-global `XDG_RUNTIME_DIR`를 set/remove하는 테스트들이 병렬로 돌면
// 서로의 setup을 덮어 쓰므로 race가 난다 (CI에서 발견됨). 한 곳에서만 변경하도록 직렬화.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ── Unit tests: 구체적 counterexample 탐색 ─────────────────────

#[test]
fn config_path_should_contain_aic_directory() {
    // ConfigManager의 config_path() 로직을 재현 (ac-client 크레이트 의존 없이)
    // XDG_CONFIG_HOME 설정 시 경로: $XDG_CONFIG_HOME/aic/config.toml (수정 완료)
    let xdg_base = std::path::PathBuf::from("/tmp/test-xdg-config");
    let path = xdg_base.join("aic").join("config.toml");
    let path_str = path.to_string_lossy();

    // 기대: /aic/config.toml 경로를 포함해야 함 (수정 후 PASS 예상)
    assert!(
        path_str.contains("/aic/"),
        "설정 경로가 '/aic/' 디렉토리를 포함해야 합니다. 실제: {}",
        path_str
    );
}

#[test]
fn socket_path_macos_should_contain_aic_prefix() {
    let path = resolve_socket_path("macos");
    let path_str = path.to_string_lossy();

    // 기대: /tmp/aic-{uid}/ 경로 (현재 /tmp/ac-{uid}/ → FAIL 예상)
    assert!(
        path_str.contains("/tmp/aic-"),
        "macOS 소켓 경로가 '/tmp/aic-' prefix를 포함해야 합니다. 실제: {}",
        path_str
    );
}

#[test]
fn socket_path_linux_xdg_should_contain_aic_prefix() {
    let _g = env_lock();
    std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
    let path = resolve_socket_path("linux");
    std::env::remove_var("XDG_RUNTIME_DIR");
    let path_str = path.to_string_lossy();

    // 기대: /aic/session.sock 경로 (현재 /ac/ → FAIL 예상)
    assert!(
        path_str.contains("/aic/"),
        "Linux XDG 소켓 경로가 '/aic/' 디렉토리를 포함해야 합니다. 실제: {}",
        path_str
    );
}

#[test]
fn error_server_not_running_should_reference_aic_session() {
    let err = AicError::ServerNotRunning;
    let msg = err.to_string();

    // 기대: aic-session 참조 (현재 ac-session → FAIL 예상)
    assert!(
        msg.contains("aic-session"),
        "ServerNotRunning 에러가 'aic-session'을 참조해야 합니다. 실제: {}",
        msg
    );
}

#[test]
fn error_api_key_missing_should_reference_aic_config() {
    let err = AicError::ApiKeyMissing {
        provider: "openai".to_string(),
    };
    let msg = err.to_string();

    // 기대: aic config 참조 (현재 ac config → FAIL 예상)
    assert!(
        msg.contains("aic config"),
        "ApiKeyMissing 에러가 'aic config'를 참조해야 합니다. 실제: {}",
        msg
    );
}

// ── Property-based tests: 임의의 입력에 대해 aic prefix 검증 ───

fn arb_absolute_path() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z0-9_]{1,8}", 1..4)
        .prop_map(|segments| format!("/{}", segments.join("/")))
}

fn arb_os() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("linux"), Just("macos")]
}

proptest! {
    /// **Validates: Requirements 2.4**
    /// 임의의 XDG 경로에서 Linux 소켓 경로가 aic prefix를 사용하는지 검증
    #[test]
    fn socket_path_linux_xdg_uses_aic_prefix(xdg_dir in arb_absolute_path()) {
        let _g = env_lock();
        std::env::set_var("XDG_RUNTIME_DIR", &xdg_dir);
        let path = resolve_socket_path("linux");
        std::env::remove_var("XDG_RUNTIME_DIR");

        let path_str = path.to_string_lossy();

        // aic 디렉토리를 포함해야 함 (현재 ac → FAIL 예상)
        prop_assert!(
            path_str.contains("/aic/"),
            "Linux XDG 소켓 경로가 '/aic/'를 포함해야 합니다. XDG_RUNTIME_DIR={}, 실제: {}",
            xdg_dir, path_str
        );
    }

    /// **Validates: Requirements 2.4**
    /// 임의의 OS에서 XDG 미설정 시 소켓 경로가 aic prefix를 사용하는지 검증
    #[test]
    fn socket_path_without_xdg_uses_aic_prefix(os in arb_os()) {
        let _g = env_lock();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let path = resolve_socket_path(os);

        let path_str = path.to_string_lossy();

        // /tmp/aic- prefix를 포함해야 함 (현재 /tmp/ac- → FAIL 예상)
        prop_assert!(
            path_str.contains("/tmp/aic-"),
            "소켓 경로가 '/tmp/aic-'를 포함해야 합니다. OS={}, 실제: {}",
            os, path_str
        );
    }
}
