//! Shared secret-reference validation and resolution.

const SERVICE: &str = "aic";
const ENV_PREFIX: &str = "env:";
const KEYCHAIN_PREFIX: &str = "keychain:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretReference<'a> {
    Env(&'a str),
    Keychain(&'a str),
}

pub fn parse_secret_reference(value: &str) -> Result<SecretReference<'_>, String> {
    if let Some(name) = value.strip_prefix(ENV_PREFIX) {
        if is_env_name(name) {
            return Ok(SecretReference::Env(name));
        }
        return Err("env secret reference has an invalid name".to_string());
    }
    if let Some(account) = value.strip_prefix(KEYCHAIN_PREFIX) {
        if !account.is_empty() && !account.chars().any(char::is_whitespace) {
            return Ok(SecretReference::Keychain(account));
        }
        return Err("keychain secret reference has an invalid account".to_string());
    }
    Err("secret_ref must use env:NAME or keychain:ACCOUNT".to_string())
}

pub fn resolve_secret_reference(value: &str) -> Result<String, String> {
    match parse_secret_reference(value)? {
        SecretReference::Env(name) => {
            std::env::var(name).map_err(|_| format!("environment secret is unavailable: {name}"))
        }
        SecretReference::Keychain(account) => load_keychain(account),
    }
}

pub fn store_keychain(account: &str, secret: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, account)
        .map_err(|error| format!("keychain entry 생성 실패: {error}"))?
        .set_password(secret)
        .map_err(|error| format!("keychain 저장 실패: {error}"))
}

pub fn load_keychain(account: &str) -> Result<String, String> {
    keyring::Entry::new(SERVICE, account)
        .map_err(|error| format!("keychain entry 생성 실패: {error}"))?
        .get_password()
        .map_err(|error| format!("keychain 로드 실패 (account={account}): {error}"))
}

pub fn delete_keychain(account: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, account)
        .map_err(|error| format!("keychain entry 생성 실패: {error}"))?
        .delete_credential()
        .map_err(|error| format!("keychain 삭제 실패: {error}"))
}

pub fn is_keychain_reference(value: &str) -> bool {
    value.starts_with(KEYCHAIN_PREFIX)
}

pub fn make_keychain_reference(account: &str) -> String {
    format!("{KEYCHAIN_PREFIX}{account}")
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('A'..='Z' | 'a'..='z' | '_'))
        && chars.all(|character| matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolves_env_reference_without_persisting_a_secret() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AIC_SECRET_TEST", "test-secret");
        }
        assert_eq!(
            resolve_secret_reference("env:AIC_SECRET_TEST").unwrap(),
            "test-secret"
        );
        unsafe {
            std::env::remove_var("AIC_SECRET_TEST");
        }
    }

    #[test]
    fn validates_keychain_reference_without_accessing_keychain() {
        assert_eq!(
            parse_secret_reference("keychain:redis-monitor").unwrap(),
            SecretReference::Keychain("redis-monitor")
        );
        assert!(parse_secret_reference("plaintext-secret").is_err());
        assert!(parse_secret_reference("env:1BAD").is_err());
    }
}
