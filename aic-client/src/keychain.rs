//! OS keychain 통합 — API key를 평문 `config.toml` 대신 OS 자격 증명 저장소에 저장.
//!
//! - macOS: Keychain Access (apple-native)
//! - Linux: Secret Service / libsecret (linux-native)
//! - Windows: Credential Manager (windows-native)
//!
//! config.toml에서는 `api_key = "keychain:<provider-name>"` 형태로 reference하고,
//! 실제 키는 service `"aic"` + account `<provider-name>` entry에 저장한다.
//!
//! Linux headless 환경 등 keychain 사용 불가 시 호출자는 환경 변수로 fallback 가능.

/// `keychain:<name>` 참조 문자열인지 확인하고, 그렇다면 실제 키를 keychain에서 로드한다.
/// 일반 평문이면 그대로 반환.
pub fn resolve(value: &str) -> Result<String, String> {
    if aic_common::secret::is_keychain_reference(value) {
        aic_common::secret::resolve_secret_reference(value)
    } else {
        Ok(value.to_string())
    }
}

/// keychain entry에 API key를 저장.
pub fn store(account: &str, secret: &str) -> Result<(), String> {
    aic_common::secret::store_keychain(account, secret)
}

/// keychain entry에서 API key를 로드.
pub fn load(account: &str) -> Result<String, String> {
    aic_common::secret::load_keychain(account)
}

/// keychain entry 삭제.
#[allow(dead_code)]
pub fn delete(account: &str) -> Result<(), String> {
    aic_common::secret::delete_keychain(account)
}

/// 평문 API key를 keychain reference 형식(`keychain:<name>`)으로 변환.
pub fn make_reference(name: &str) -> String {
    aic_common::secret::make_keychain_reference(name)
}

/// 값이 keychain reference인지 검사.
pub fn is_reference(value: &str) -> bool {
    aic_common::secret::is_keychain_reference(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_format() {
        assert_eq!(make_reference("openai"), "keychain:openai");
        assert!(is_reference("keychain:openai"));
        assert!(!is_reference("sk-actual-secret"));
        assert!(!is_reference(""));
    }

    #[test]
    fn resolve_passes_through_plain_value() {
        let result = resolve("sk-plain-key").unwrap();
        assert_eq!(result, "sk-plain-key");
    }

    #[test]
    fn resolve_keychain_prefix_attempts_load() {
        // 존재하지 않는 entry → 에러 (keychain 자체는 OS-dependent라 mock 불가)
        let result = resolve("keychain:nonexistent_entry_xyz_aic_test");
        assert!(result.is_err());
    }
}
