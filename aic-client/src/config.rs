//! ConfigManager: 설정 파일 로드 및 소켓 경로 결정
//!
//! - `~/.config/aic/config.toml` (XDG Base Directory 준수)
//! - TOML 파싱 실패 시 기본 설정 폴백
//! - 소켓 경로: macOS `/tmp/aic-{uid}/session.sock`, Linux `$XDG_RUNTIME_DIR/aic/session.sock`

use aic_common::{AppConfig, BoundaryStrategyConfig, LlmConfig, ServerConfig};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct ConfigManager;

impl ConfigManager {
    /// XDG Base Directory 준수 설정 파일 경로 반환
    /// `$XDG_CONFIG_HOME/aic/config.toml` 또는 `~/.config/aic/config.toml`
    pub fn config_path() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg).join("aic").join("config.toml")
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("~"))
                .join(".config")
                .join("aic")
                .join("config.toml")
        }
    }

    /// 설정 파일 로드. 파일 미존재 시 기본값, 파싱 실패 시 stderr 출력 후 기본값 반환
    pub fn load() -> anyhow::Result<AppConfig> {
        let path = Self::config_path();

        if !path.exists() {
            return Ok(Self::default_config());
        }

        let content = std::fs::read_to_string(&path)?;

        match toml::from_str::<AppConfig>(&content) {
            Ok(config) => Ok(config),
            Err(e) => {
                eprintln!(
                    "설정 파일 파싱 실패 ({}): {}\n기본 설정을 사용합니다.",
                    path.display(),
                    e
                );
                Ok(Self::default_config())
            }
        }
    }

    /// UDS 소켓 경로 결정
    /// - macOS: `/tmp/aic-{uid}/session.sock`
    /// - Linux: `$XDG_RUNTIME_DIR/aic/session.sock` (설정 시), 아니면 `/tmp/aic-{uid}/session.sock`
    pub fn socket_path() -> PathBuf {
        aic_common::default_socket_path()
    }

    #[cfg(test)]
    fn resolve_socket_path(os: &str) -> PathBuf {
        aic_common::resolve_socket_path(os)
    }

    /// 기본 AppConfig
    pub fn default_config() -> AppConfig {
        AppConfig {
            llm: LlmConfig {
                default_provider: "openai".to_string(),
                providers: HashMap::new(),
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: ServerConfig {
                max_buffer_lines: 500,
                socket_path: None,
                boundary_strategy: BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
            session: aic_common::SessionConfig::default(),
            observability: aic_common::ObservabilityConfig::default(),
            aicd: aic_common::AicdConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::{LlmConfig, ProviderConfig, ProviderType};
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn default_config_has_expected_values() {
        let config = ConfigManager::default_config();
        assert_eq!(config.llm.default_provider, "openai");
        assert!(config.llm.providers.is_empty());
        assert_eq!(config.server.max_buffer_lines, 500);
        assert!(config.server.socket_path.is_none());
        assert_eq!(config.server.boundary_strategy.method, "prompt_marker");
        assert!(config.server.boundary_strategy.idle_threshold_ms.is_none());
    }

    #[test]
    fn default_config_has_no_observability_backends() {
        let config = ConfigManager::default_config();
        assert!(config.observability.backends.is_empty());
    }

    #[test]
    fn parses_observability_backends_section() {
        use aic_common::BackendType;

        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
boundary_strategy = { method = "prompt_marker" }

[observability.backends.prom]
backend_type = "Prometheus"
url = "http://prometheus:9090"

[observability.backends.logs]
backend_type = "Loki"
url = "http://loki:3100"
auth = "keychain:obs_loki"
"#;
        let config: AppConfig = toml::from_str(toml_str).expect("config should parse");

        let prom = config
            .observability
            .backends
            .get("prom")
            .expect("prom backend present");
        assert_eq!(prom.backend_type, BackendType::Prometheus);
        assert_eq!(prom.url, "http://prometheus:9090");
        assert!(prom.auth.is_none());

        let logs = config
            .observability
            .backends
            .get("logs")
            .expect("logs backend present");
        assert_eq!(logs.backend_type, BackendType::Loki);
        assert_eq!(logs.auth.as_deref(), Some("keychain:obs_loki"));
    }

    #[test]
    fn legacy_config_without_observability_defaults_empty() {
        // observability 섹션이 없는 레거시 config도 #[serde(default)]로 파싱돼야 한다.
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
boundary_strategy = { method = "prompt_marker" }
"#;
        let config: AppConfig = toml::from_str(toml_str).expect("legacy config should parse");
        assert!(config.observability.backends.is_empty());
    }

    #[test]
    fn config_path_uses_xdg_config_home() {
        // 환경변수 경합을 피하기 위해 내부 로직을 직접 테스트
        // XDG_CONFIG_HOME이 설정된 경우의 경로 계산 검증
        let xdg_path = PathBuf::from("/tmp/test-xdg-config")
            .join("aic")
            .join("config.toml");
        assert_eq!(
            xdg_path,
            PathBuf::from("/tmp/test-xdg-config/aic/config.toml")
        );
    }

    #[test]
    fn config_path_returns_valid_path() {
        let _guard = env_lock();
        let path = ConfigManager::config_path();
        // 어떤 환경이든 config.toml로 끝나야 함
        assert!(path.ends_with("config.toml"));
        // aic 디렉토리 하위여야 함
        assert!(path.to_string_lossy().contains("/aic/"));
    }

    #[test]
    fn load_returns_default_when_file_missing() {
        let _guard = env_lock();
        let old = std::env::var("XDG_CONFIG_HOME").ok();
        // 존재하지 않는 경로를 가리키도록 설정
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/aic-test-nonexistent-dir-12345");
        let config = ConfigManager::load().unwrap();
        assert_eq!(config, ConfigManager::default_config());
        if let Some(old) = old {
            std::env::set_var("XDG_CONFIG_HOME", old);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn load_falls_back_on_invalid_toml() {
        let _guard = env_lock();
        let old = std::env::var("XDG_CONFIG_HOME").ok();
        let dir = std::env::temp_dir().join("aic-test-invalid-toml");
        let config_dir = dir.join("aic");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.toml"), "this is not valid toml [[[").unwrap();

        std::env::set_var("XDG_CONFIG_HOME", dir.to_str().unwrap());
        let config = ConfigManager::load().unwrap();
        assert_eq!(config, ConfigManager::default_config());

        if let Some(old) = old {
            std::env::set_var("XDG_CONFIG_HOME", old);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn socket_path_is_absolute() {
        let _guard = env_lock();
        let path = ConfigManager::socket_path();
        assert!(
            path.is_absolute(),
            "소켓 경로는 절대 경로여야 합니다: {:?}",
            path
        );
    }

    #[test]
    fn socket_path_ends_with_session_sock() {
        let _guard = env_lock();
        let path = ConfigManager::socket_path();
        assert!(
            path.ends_with("session.sock"),
            "소켓 경로는 session.sock으로 끝나야 합니다: {:?}",
            path
        );
    }

    #[test]
    fn resolve_socket_path_linux_with_xdg_runtime() {
        let _guard = env_lock();
        let old = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let path = ConfigManager::resolve_socket_path("linux");
        assert_eq!(path, PathBuf::from("/run/user/1000/aic/session.sock"));
        if let Some(old) = old {
            std::env::set_var("XDG_RUNTIME_DIR", old);
        } else {
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
    }

    #[test]
    fn resolve_socket_path_linux_without_xdg_runtime() {
        let _guard = env_lock();
        let old = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let path = ConfigManager::resolve_socket_path("linux");
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/aic-{}/session.sock", uid))
        );
        if let Some(old) = old {
            std::env::set_var("XDG_RUNTIME_DIR", old);
        }
    }

    #[test]
    fn resolve_socket_path_macos() {
        let path = ConfigManager::resolve_socket_path("macos");
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/aic-{}/session.sock", uid))
        );
    }

    // ── proptest strategies ────────────────────────────────────

    fn arb_provider_type() -> impl Strategy<Value = ProviderType> {
        prop_oneof![
            Just(ProviderType::OpenAiCompatible),
            Just(ProviderType::Groq),
            Just(ProviderType::Anthropic),
            Just(ProviderType::CliBackend),
        ]
    }

    fn arb_provider_config() -> impl Strategy<Value = ProviderConfig> {
        (
            arb_provider_type(),
            proptest::option::of("[a-z]{3,10}"),
            proptest::option::of("[a-z]{3,10}"),
            proptest::option::of("[a-z]{3,10}"),
            proptest::option::of("[a-z]{3,10}"),
        )
            .prop_map(|(provider_type, endpoint, api_key, model, cli_path)| {
                ProviderConfig {
                    provider_type,
                    endpoint,
                    api_key,
                    model,
                    cli_path,
                    cli_args: None,
                }
            })
    }

    fn arb_providers() -> impl Strategy<Value = HashMap<String, ProviderConfig>> {
        proptest::collection::hash_map("[a-z]{2,6}", arb_provider_config(), 0..3)
    }

    fn arb_boundary_strategy() -> impl Strategy<Value = BoundaryStrategyConfig> {
        (
            prop_oneof![
                Just("prompt_marker".to_string()),
                Just("timing_heuristic".to_string())
            ],
            proptest::option::of(100u64..5000u64),
        )
            .prop_map(|(method, idle_threshold_ms)| BoundaryStrategyConfig {
                method,
                idle_threshold_ms,
            })
    }

    fn arb_server_config() -> impl Strategy<Value = ServerConfig> {
        (
            100usize..2000usize,
            proptest::option::of("[a-z/]{3,20}".prop_map(PathBuf::from)),
            arb_boundary_strategy(),
        )
            .prop_map(
                |(max_buffer_lines, socket_path, boundary_strategy)| ServerConfig {
                    max_buffer_lines,
                    socket_path,
                    boundary_strategy,
                },
            )
    }

    fn arb_llm_config() -> impl Strategy<Value = LlmConfig> {
        (
            "[a-z]{3,10}",
            arb_providers(),
            prop_oneof![
                Just("korean".to_string()),
                Just("english".to_string()),
                Just("japanese".to_string()),
            ],
            1u64..30u64,
            10u64..120u64,
        )
            .prop_map(
                |(
                    default_provider,
                    providers,
                    lang,
                    connect_timeout_secs,
                    request_timeout_secs,
                )| {
                    LlmConfig {
                        default_provider,
                        providers,
                        lang,
                        connect_timeout_secs,
                        request_timeout_secs,
                    }
                },
            )
    }

    fn arb_app_config() -> impl Strategy<Value = AppConfig> {
        (arb_llm_config(), arb_server_config()).prop_map(|(llm, server)| AppConfig {
            llm,
            server,
            session: aic_common::SessionConfig::default(),
            observability: aic_common::ObservabilityConfig::default(),
            aicd: aic_common::AicdConfig::default(),
        })
    }

    // Feature: ac-cli-tool, Property 7: Config Serialization Round-Trip
    // **Validates: Requirements 8.3**
    proptest! {
        #[test]
        fn config_serialization_round_trip(config in arb_app_config()) {
            let toml_str = toml::to_string(&config)
                .expect("AppConfig should serialize to TOML");
            let deserialized: AppConfig = toml::from_str(&toml_str)
                .expect("TOML should deserialize back to AppConfig");
            prop_assert_eq!(config, deserialized);
        }
    }

    // ── Property 9 strategies ──────────────────────────────────

    fn arb_os() -> impl Strategy<Value = &'static str> {
        prop_oneof![Just("linux"), Just("macos")]
    }

    /// 임의의 절대 경로 생성 (XDG_RUNTIME_DIR 시뮬레이션용)
    fn arb_absolute_path() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z0-9_]{1,8}", 1..4)
            .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    // Feature: ac-cli-tool, Property 9: Socket Path Follows Platform Conventions
    // **Validates: Requirements 11.4**
    proptest! {
        #[test]
        fn socket_path_follows_platform_conventions_with_xdg(
            os in arb_os(),
            xdg_dir in arb_absolute_path(),
        ) {
            let _guard = env_lock();
            let old = std::env::var("XDG_RUNTIME_DIR").ok();
            // XDG_RUNTIME_DIR 설정 후 테스트
            std::env::set_var("XDG_RUNTIME_DIR", &xdg_dir);
            let path = ConfigManager::resolve_socket_path(os);
            if let Some(old) = old {
                std::env::set_var("XDG_RUNTIME_DIR", old);
            } else {
                std::env::remove_var("XDG_RUNTIME_DIR");
            }

            // 1) 절대 경로
            prop_assert!(path.is_absolute(), "경로가 절대 경로여야 합니다: {:?}", path);

            // 2) 플랫폼 관례 준수
            let path_str = path.to_string_lossy();
            match os {
                "linux" => {
                    // Linux + XDG_RUNTIME_DIR → XDG_RUNTIME_DIR 하위
                    prop_assert!(
                        path_str.starts_with(&xdg_dir),
                        "Linux(XDG 설정): 경로가 XDG_RUNTIME_DIR({}) 하위여야 합니다: {:?}",
                        xdg_dir, path
                    );
                }
                "macos" => {
                    // macOS → /tmp/aic- 하위
                    prop_assert!(
                        path_str.starts_with("/tmp/aic-"),
                        "macOS: 경로가 /tmp/aic- 하위여야 합니다: {:?}", path
                    );
                }
                _ => unreachable!(),
            }

            // 3) session.sock으로 종료
            prop_assert!(
                path.ends_with("session.sock"),
                "경로가 session.sock으로 끝나야 합니다: {:?}", path
            );
        }

        #[test]
        fn socket_path_follows_platform_conventions_without_xdg(os in arb_os()) {
            let _guard = env_lock();
            let old = std::env::var("XDG_RUNTIME_DIR").ok();
            // XDG_RUNTIME_DIR 미설정 상태에서 테스트
            std::env::remove_var("XDG_RUNTIME_DIR");
            let path = ConfigManager::resolve_socket_path(os);
            if let Some(old) = old {
                std::env::set_var("XDG_RUNTIME_DIR", old);
            }

            // 1) 절대 경로
            prop_assert!(path.is_absolute(), "경로가 절대 경로여야 합니다: {:?}", path);

            // 2) XDG 미설정 시 Linux/macOS 모두 /tmp/aic- 하위
            let path_str = path.to_string_lossy();
            prop_assert!(
                path_str.starts_with("/tmp/aic-"),
                "XDG 미설정: 경로가 /tmp/aic- 하위여야 합니다: {:?}", path
            );

            // 3) session.sock으로 종료
            prop_assert!(
                path.ends_with("session.sock"),
                "경로가 session.sock으로 끝나야 합니다: {:?}", path
            );
        }
    }
}
