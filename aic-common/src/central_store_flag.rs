//! Central_Store_Flag 평가 모듈.
//!
//! 본 기능을 끄고 켜는 단일 스위치를 관리한다. 우선순위는
//! `env (AIC_CENTRAL_STORE) > config ([daemon] central_store) > Phase default` 이다.
//!
//! 평가된 값은 `resolve_central_store_flag`를 처음 호출한 프로세스의 runtime 동안
//! `OnceLock`에 캐시되며, 이후 호출은 동일 값을 반환한다(R2.7).
//!
//! ## Phase 표
//!
//! | Phase | 기본값 |
//! |-------|--------|
//! | 3.1 ~ 3.3 | `false` |
//! | 3.4 ~ 3.5 | `true`  |
//!
//! Phase는 Cargo feature `phase-3_N` 로 빌드 시점에 결정되며, 런타임 전환은 없다.
//!
//! ## `[daemon]` 섹션의 위치
//!
//! 사용자가 `config.toml`에 `[daemon]` 섹션이 없거나 `central_store` 키가 없더라도
//! 기존 설정은 그대로 로드돼야 한다 (R2.6, R12.2). 본 모듈의 `DaemonConfig`는
//! `#[serde(default)]` 이고 `AppConfigWithDaemon` 래퍼 역시 `daemon` 필드 전체가
//! `#[serde(default)]` 이다.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::AppConfig;

/// 빌드된 `aic-common` 이 속한 Phase. `current_phase()` 가 반환한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    P31,
    P32,
    P33,
    P34,
    P35,
}

impl Phase {
    /// Central_Store_Flag 의 Phase-별 기본값 (R8.1, R8.2).
    pub fn default_central_store_flag(self) -> bool {
        match self {
            Phase::P31 | Phase::P32 | Phase::P33 => false,
            Phase::P34 | Phase::P35 => true,
        }
    }

    /// Phase 를 사람이 읽기 좋은 문자열 라벨로 변환.
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::P31 => "phase-3_1",
            Phase::P32 => "phase-3_2",
            Phase::P33 => "phase-3_3",
            Phase::P34 => "phase-3_4",
            Phase::P35 => "phase-3_5",
        }
    }
}

/// 현재 빌드에서 활성화된 Phase 를 반환한다.
///
/// Cargo `phase-3_N` feature 로 단일 값이 고정되며, `build.rs` 에서 정확히 하나만
/// 활성임을 assert 한다. 따라서 여러 `#[cfg(...)]` 분기 중 실제로는 하나만 컴파일된다.
#[cfg(feature = "phase-3_1")]
pub fn current_phase() -> Phase {
    Phase::P31
}

#[cfg(feature = "phase-3_2")]
pub fn current_phase() -> Phase {
    Phase::P32
}

#[cfg(feature = "phase-3_3")]
pub fn current_phase() -> Phase {
    Phase::P33
}

#[cfg(feature = "phase-3_4")]
pub fn current_phase() -> Phase {
    Phase::P34
}

#[cfg(feature = "phase-3_5")]
pub fn current_phase() -> Phase {
    Phase::P35
}

// 방어적 fallback: build.rs assert 가 올바르게 동작하면 도달하지 않는다.
// cfg 매크로가 컴파일 타임에 유일한 current_phase 정의를 남기므로
// 이 블록은 어떤 feature 조합에서도 컴파일되지 않아야 한다. 혹시라도
// 빌드 설정이 깨지면 build.rs 가 먼저 실패할 것이다.
#[cfg(not(any(
    feature = "phase-3_1",
    feature = "phase-3_2",
    feature = "phase-3_3",
    feature = "phase-3_4",
    feature = "phase-3_5"
)))]
compile_error!(
    "aic-common: phase-3_N feature 가 하나도 활성화되어 있지 않습니다. \
     Cargo.toml 의 default feature 설정을 확인하세요."
);

/// `[daemon]` 섹션. 기존 config 호환을 위해 모든 필드가 optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// `true` / `false`. 비워 두면 env / Phase default 로 폴백한다.
    #[serde(default)]
    pub central_store: Option<bool>,
}

/// `AppConfig` + `[daemon]` 섹션 을 포괄하는 얇은 래퍼.
///
/// 기존 `AppConfig` 는 그대로 두고, `[daemon]` 을 옵션으로 추가하기 위한 구조체다.
/// `flatten` 을 이용해 `toml::from_str::<AppConfigWithDaemon>(...)` 한 번에 읽는다.
/// `[daemon]` 섹션이 없거나 key 가 빠져도 `default` 로 채워진다(R2.6, R12.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppConfigWithDaemon {
    #[serde(flatten)]
    pub app: AppConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

/// bool-like 문자열을 해석 (R2.2, R2.3).
///
/// - `"1" | "true" | "on" | "yes"` (대소문자 무관) → `Some(true)`
/// - `"0" | "false" | "off" | "no"` (대소문자 무관) → `Some(false)`
/// - 그 외 → `None`
pub fn parse_bool_like(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

/// `Central_Store_Flag` 가 어느 소스에서 유래했는지 표시한다.
///
/// `aic doctor` 의 Central Store 섹션 (R14.6) 이 "왜 이 값인지" 를 사용자에게
/// 보여 주기 위해 쓰인다. 우선순위는 `Env > Config > PhaseDefault` 이다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagSource {
    /// 환경변수 `AIC_CENTRAL_STORE` 가 유효 bool-like 값으로 해석되어 적용됐다.
    Env,
    /// config `[daemon] central_store` 로부터 값이 왔다 (env 가 없거나 해석 실패).
    Config,
    /// env / config 모두 값을 제공하지 않아 Phase 기본값이 적용됐다.
    PhaseDefault,
}

impl FlagSource {
    /// Doctor 출력 / 로그에 사용하는 안정 라벨.
    pub fn as_str(self) -> &'static str {
        match self {
            FlagSource::Env => "env",
            FlagSource::Config => "config",
            FlagSource::PhaseDefault => "phase-default",
        }
    }
}

/// Runtime 동안 한 번 평가된 flag 를 보관하는 캐시 (R2.7).
///
/// 테스트에서는 `resolve_central_store_flag_uncached` 를 사용해 캐시를 우회한다.
static RESOLVED: OnceLock<bool> = OnceLock::new();

/// Central_Store_Flag 를 평가한다.
///
/// 우선순위:
/// 1. env `AIC_CENTRAL_STORE` 가 유효한 bool-like 값이면 그대로 (R2.4).
/// 2. env 값이 해석 불가능하면 `tracing::warn!` 후 다음 단계로 폴백.
/// 3. config `[daemon] central_store` 가 `Some(_)` 이면 그 값 (R2.1, R2.4).
/// 4. Phase default (R2.5, R8).
///
/// 최초 호출 시점에 결정된 값은 `OnceLock` 에 캐시되므로 이후 호출은 동일 값을 반환한다
/// (R2.7). 테스트 등에서 서로 다른 입력으로 반복 평가하려면
/// [`resolve_central_store_flag_uncached`] 를 사용한다.
pub fn resolve_central_store_flag(
    env: &HashMap<String, String>,
    config: Option<&DaemonConfig>,
) -> bool {
    if let Some(&v) = RESOLVED.get() {
        return v;
    }
    let v = resolve_central_store_flag_uncached(env, config);
    // 경합이 있어도 한 번만 set 된다. 이미 set 되어 있다면 무시해도 안전.
    let _ = RESOLVED.set(v);
    v
}

/// 캐시를 우회해 매번 입력에 따라 평가한다. 테스트 전용.
pub fn resolve_central_store_flag_uncached(
    env: &HashMap<String, String>,
    config: Option<&DaemonConfig>,
) -> bool {
    resolve_central_store_flag_with_source_uncached(env, config).0
}

/// 캐시를 우회하고 flag 값 + 결정 소스를 함께 반환한다.
///
/// `aic doctor` 의 Central Store 섹션 (R14.6) 에서 사용한다. Runtime 동안 단일 값을
/// 고정해야 하는 일반 read-path (R2.7) 에서는 `resolve_central_store_flag` 를 쓰고,
/// doctor 는 "현재 환경을 다시 관측" 하는 용도라 의도적으로 캐시를 거치지 않는다.
pub fn resolve_central_store_flag_with_source_uncached(
    env: &HashMap<String, String>,
    config: Option<&DaemonConfig>,
) -> (bool, FlagSource) {
    if let Some(raw) = env.get("AIC_CENTRAL_STORE") {
        match parse_bool_like(raw) {
            Some(v) => return (v, FlagSource::Env),
            None => {
                tracing::warn!(
                    value = %raw,
                    "AIC_CENTRAL_STORE 값을 해석할 수 없어 무시합니다 (config/phase default 로 폴백)"
                );
            }
        }
    }
    if let Some(cfg) = config {
        if let Some(v) = cfg.central_store {
            return (v, FlagSource::Config);
        }
    }
    (
        current_phase().default_central_store_flag(),
        FlagSource::PhaseDefault,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    // ── parse_bool_like ─────────────────────────────────────────

    #[test]
    fn parse_bool_like_accepts_true_tokens() {
        for raw in ["1", "true", "TRUE", "On", "yes", "  YES  "] {
            assert_eq!(parse_bool_like(raw), Some(true), "raw={raw:?}");
        }
    }

    #[test]
    fn parse_bool_like_accepts_false_tokens() {
        for raw in ["0", "false", "FALSE", "Off", "no", "NO"] {
            assert_eq!(parse_bool_like(raw), Some(false), "raw={raw:?}");
        }
    }

    #[test]
    fn parse_bool_like_rejects_invalid() {
        for raw in ["", " ", "maybe", "2", "enable", "ja"] {
            assert_eq!(parse_bool_like(raw), None, "raw={raw:?}");
        }
    }

    // ── resolve_central_store_flag_uncached ────────────────────

    #[test]
    fn env_true_beats_config_false() {
        // R2.4: env 가 config 를 덮어써야 한다.
        let env = env_with(&[("AIC_CENTRAL_STORE", "1")]);
        let cfg = DaemonConfig {
            central_store: Some(false),
        };
        assert!(resolve_central_store_flag_uncached(&env, Some(&cfg)));
    }

    #[test]
    fn env_false_beats_config_true() {
        let env = env_with(&[("AIC_CENTRAL_STORE", "off")]);
        let cfg = DaemonConfig {
            central_store: Some(true),
        };
        assert!(!resolve_central_store_flag_uncached(&env, Some(&cfg)));
    }

    #[test]
    fn env_invalid_falls_back_to_config() {
        // R2 의 "해석 불가능한 값은 무시": env 의 쓰레기값을 무시하고 config 사용.
        let env = env_with(&[("AIC_CENTRAL_STORE", "banana")]);
        let cfg = DaemonConfig {
            central_store: Some(true),
        };
        assert!(resolve_central_store_flag_uncached(&env, Some(&cfg)));
    }

    #[test]
    fn env_invalid_and_no_config_uses_phase_default() {
        // R2.5: env 해석 불가 + config 없음 → Phase default.
        let env = env_with(&[("AIC_CENTRAL_STORE", "banana")]);
        let expected = current_phase().default_central_store_flag();
        assert_eq!(
            resolve_central_store_flag_uncached(&env, None),
            expected,
            "phase={:?}",
            current_phase()
        );
    }

    #[test]
    fn config_used_when_env_unset() {
        // R2.1: config 채널이 두 번째 우선순위.
        let env = HashMap::new();
        let cfg = DaemonConfig {
            central_store: Some(true),
        };
        assert!(resolve_central_store_flag_uncached(&env, Some(&cfg)));

        let cfg_false = DaemonConfig {
            central_store: Some(false),
        };
        assert!(!resolve_central_store_flag_uncached(&env, Some(&cfg_false)));
    }

    #[test]
    fn phase_default_used_when_env_and_config_empty() {
        // R2.5 / R8: 둘 다 비면 Phase default.
        let env = HashMap::new();
        let cfg = DaemonConfig::default(); // central_store = None
        let expected = current_phase().default_central_store_flag();
        assert_eq!(
            resolve_central_store_flag_uncached(&env, Some(&cfg)),
            expected
        );
        assert_eq!(resolve_central_store_flag_uncached(&env, None), expected);
    }

    // ── Phase default 표 커버 ──────────────────────────────────

    #[test]
    fn phase_default_matrix_matches_requirements() {
        // R8.1 / R8.2: Phase 3.1~3.3 false, 3.4~3.5 true.
        assert!(!Phase::P31.default_central_store_flag());
        assert!(!Phase::P32.default_central_store_flag());
        assert!(!Phase::P33.default_central_store_flag());
        assert!(Phase::P34.default_central_store_flag());
        assert!(Phase::P35.default_central_store_flag());
    }

    #[test]
    fn current_phase_matches_active_feature() {
        // Phase 정의의 sanity check. 어떤 빌드든 정확히 하나여야 한다
        // (build.rs 가 강제).
        let p = current_phase();
        // 라벨이 phase-3_N 형식이어야 한다.
        assert!(p.as_str().starts_with("phase-3_"));
    }

    // ── 레거시 config 호환 (R2.6, R12.2) ───────────────────────

    #[test]
    fn legacy_config_without_daemon_section_parses() {
        // 기존 config.toml 에 [daemon] 섹션이 아예 없더라도 정상 로드되어야 한다.
        let toml_str = r#"
[llm]
default_provider = "openai"
lang = "korean"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"
"#;
        let cfg: AppConfigWithDaemon = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.daemon.central_store, None);
        assert_eq!(cfg.app.llm.default_provider, "openai");
    }

    #[test]
    fn config_with_daemon_section_but_no_central_store_parses() {
        // [daemon] 섹션은 있지만 central_store 키가 빠진 경우.
        let toml_str = r#"
[llm]
default_provider = "openai"
lang = "korean"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"

[daemon]
"#;
        let cfg: AppConfigWithDaemon = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.daemon.central_store, None);
    }

    #[test]
    fn config_with_daemon_central_store_true_parses() {
        let toml_str = r#"
[llm]
default_provider = "openai"
lang = "korean"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"

[daemon]
central_store = true
"#;
        let cfg: AppConfigWithDaemon = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.daemon.central_store, Some(true));
    }

    #[test]
    fn legacy_config_resolves_to_phase_default() {
        // 레거시 config (daemon 섹션 없음) + env 없음 → Phase default.
        let toml_str = r#"
[llm]
default_provider = "openai"
lang = "korean"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"
"#;
        let cfg: AppConfigWithDaemon = toml::from_str(toml_str).unwrap();
        let env = HashMap::new();
        let expected = current_phase().default_central_store_flag();
        assert_eq!(
            resolve_central_store_flag_uncached(&env, Some(&cfg.daemon)),
            expected
        );
    }

    // ── Priority composition: env > config > phase default ────

    #[test]
    fn full_priority_chain_env_wins() {
        let env = env_with(&[("AIC_CENTRAL_STORE", "no")]);
        let cfg = DaemonConfig {
            central_store: Some(true),
        };
        // env=false → false, config=true, phase default 무관.
        assert!(!resolve_central_store_flag_uncached(&env, Some(&cfg)));
    }

    #[test]
    fn full_priority_chain_config_wins_when_env_absent() {
        let env = HashMap::new();
        let cfg = DaemonConfig {
            central_store: Some(false),
        };
        // env 없음 → config=false 가 우선.
        assert!(!resolve_central_store_flag_uncached(&env, Some(&cfg)));
    }

    #[test]
    fn full_priority_chain_phase_default_when_both_absent() {
        let env = HashMap::new();
        let cfg = DaemonConfig::default();
        assert_eq!(
            resolve_central_store_flag_uncached(&env, Some(&cfg)),
            current_phase().default_central_store_flag()
        );
    }

    // ── 대소문자 무관 (R2.2, R2.3) ────────────────────────────

    #[test]
    fn env_key_is_case_sensitive_but_value_is_not() {
        // 환경변수 key 는 대소문자 민감이 맞지만, 값은 대소문자 무관.
        for token in ["TRUE", "True", "tRuE", "ON"] {
            let env = env_with(&[("AIC_CENTRAL_STORE", token)]);
            assert!(
                resolve_central_store_flag_uncached(&env, None),
                "token={token:?} 이 true 로 해석되어야 한다"
            );
        }
        for token in ["OFF", "No", "FaLsE"] {
            let env = env_with(&[("AIC_CENTRAL_STORE", token)]);
            assert!(
                !resolve_central_store_flag_uncached(&env, None),
                "token={token:?} 이 false 로 해석되어야 한다"
            );
        }
    }

    // ── FlagSource (R14.6 의 doctor 출력용) ───────────────────

    #[test]
    fn flag_source_env_wins_over_config() {
        // 우선순위 1: env 가 유효하면 FlagSource::Env.
        let env = env_with(&[("AIC_CENTRAL_STORE", "1")]);
        let cfg = DaemonConfig {
            central_store: Some(false),
        };
        let (v, src) = resolve_central_store_flag_with_source_uncached(&env, Some(&cfg));
        assert!(v);
        assert_eq!(src, FlagSource::Env);
    }

    #[test]
    fn flag_source_config_when_env_absent() {
        // 우선순위 2: env 없고 config 가 Some 이면 FlagSource::Config.
        let env = HashMap::new();
        let cfg = DaemonConfig {
            central_store: Some(true),
        };
        let (v, src) = resolve_central_store_flag_with_source_uncached(&env, Some(&cfg));
        assert!(v);
        assert_eq!(src, FlagSource::Config);
    }

    #[test]
    fn flag_source_phase_default_when_both_absent() {
        // 우선순위 3: env / config 모두 값이 없으면 FlagSource::PhaseDefault.
        let env = HashMap::new();
        let cfg = DaemonConfig::default();
        let (v, src) = resolve_central_store_flag_with_source_uncached(&env, Some(&cfg));
        assert_eq!(v, current_phase().default_central_store_flag());
        assert_eq!(src, FlagSource::PhaseDefault);

        // config 가 아예 None 이어도 동일.
        let (v2, src2) = resolve_central_store_flag_with_source_uncached(&env, None);
        assert_eq!(v2, current_phase().default_central_store_flag());
        assert_eq!(src2, FlagSource::PhaseDefault);
    }

    #[test]
    fn flag_source_env_invalid_falls_back_to_config_source() {
        // env 값이 해석 불가 → config 가 Some 이면 FlagSource::Config.
        let env = env_with(&[("AIC_CENTRAL_STORE", "banana")]);
        let cfg = DaemonConfig {
            central_store: Some(true),
        };
        let (v, src) = resolve_central_store_flag_with_source_uncached(&env, Some(&cfg));
        assert!(v);
        assert_eq!(src, FlagSource::Config);
    }

    #[test]
    fn flag_source_env_invalid_and_no_config_uses_phase_default() {
        // env 해석 불가 + config 없음 → FlagSource::PhaseDefault.
        let env = env_with(&[("AIC_CENTRAL_STORE", "banana")]);
        let (v, src) = resolve_central_store_flag_with_source_uncached(&env, None);
        assert_eq!(v, current_phase().default_central_store_flag());
        assert_eq!(src, FlagSource::PhaseDefault);
    }

    #[test]
    fn flag_source_label_strings_are_stable() {
        // R14.6 doctor 출력에서 사용하는 문자열 라벨. 변경 시 doctor 스냅샷 테스트가
        // 같이 깨져야 한다.
        assert_eq!(FlagSource::Env.as_str(), "env");
        assert_eq!(FlagSource::Config.as_str(), "config");
        assert_eq!(FlagSource::PhaseDefault.as_str(), "phase-default");
    }

    #[test]
    fn uncached_and_with_source_agree_on_bool() {
        // 두 API 가 항상 같은 bool 을 반환해야 한다 (하나는 source 를 덧붙일 뿐).
        for (env_val, cfg_val) in [
            (Some("1"), None),
            (Some("0"), Some(true)),
            (None, Some(true)),
            (None, None),
            (Some("banana"), Some(false)),
        ] {
            let env = match env_val {
                Some(v) => env_with(&[("AIC_CENTRAL_STORE", v)]),
                None => HashMap::new(),
            };
            let cfg = cfg_val.map(|v| DaemonConfig {
                central_store: Some(v),
            });
            let a = resolve_central_store_flag_uncached(&env, cfg.as_ref());
            let (b, _) = resolve_central_store_flag_with_source_uncached(&env, cfg.as_ref());
            assert_eq!(a, b, "env={env_val:?} cfg={cfg_val:?}");
        }
    }
}
