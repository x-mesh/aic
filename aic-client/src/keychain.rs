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

const SERVICE: &str = "aic";
const KEYCHAIN_PREFIX: &str = "keychain:";

/// `keychain:<name>` 참조 문자열인지 확인하고, 그렇다면 실제 키를 keychain에서 로드한다.
/// 일반 평문이면 그대로 반환.
pub fn resolve(value: &str) -> Result<String, String> {
    if let Some(name) = value.strip_prefix(KEYCHAIN_PREFIX) {
        load(name)
    } else {
        Ok(value.to_string())
    }
}

/// keychain entry에 API key를 저장.
pub fn store(account: &str, secret: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, account)
        .map_err(|e| format!("keychain entry 생성 실패: {e}"))?;
    entry
        .set_password(secret)
        .map_err(|e| format!("keychain 저장 실패: {e}"))
}

/// keychain entry에서 API key를 로드.
pub fn load(account: &str) -> Result<String, String> {
    let entry = keyring::Entry::new(SERVICE, account)
        .map_err(|e| format!("keychain entry 생성 실패: {e}"))?;
    entry
        .get_password()
        .map_err(|e| format!("keychain 로드 실패 (account={account}): {e}"))
}

/// keychain entry 삭제.
#[allow(dead_code)]
pub fn delete(account: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, account)
        .map_err(|e| format!("keychain entry 생성 실패: {e}"))?;
    entry
        .delete_credential()
        .map_err(|e| format!("keychain 삭제 실패: {e}"))
}

/// 평문 API key를 keychain reference 형식(`keychain:<name>`)으로 변환.
pub fn make_reference(name: &str) -> String {
    format!("{KEYCHAIN_PREFIX}{name}")
}

/// 값이 keychain reference인지 검사.
pub fn is_reference(value: &str) -> bool {
    value.starts_with(KEYCHAIN_PREFIX)
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
