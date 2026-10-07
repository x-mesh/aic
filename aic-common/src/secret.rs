//! Shared secret-reference validation and resolution.

const SERVICE: &str = "aic";
const ENV_PREFIX: &str = "env:";
const KEYCHAIN_PREFIX: &str = "keychain:";
const FILE_PREFIX: &str = "file:";
const MAX_FILE_SECRET_NAME: usize = 64;
#[cfg(unix)]
const SECRET_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretReference<'a> {
    Env(&'a str),
    Keychain(&'a str),
    /// A file under [`file_secret_dir`]. aicd reads it no matter how it was started; the
    /// environment of a systemd unit and the Linux kernel keyring of a login shell do not reach it.
    File(&'a str),
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
    if let Some(name) = value.strip_prefix(FILE_PREFIX) {
        if is_file_secret_name(name) {
            return Ok(SecretReference::File(name));
        }
        return Err("file secret reference has an invalid name".to_string());
    }
    Err("secret_ref must use env:NAME, keychain:ACCOUNT, or file:NAME".to_string())
}

pub fn resolve_secret_reference(value: &str) -> Result<String, String> {
    match parse_secret_reference(value)? {
        SecretReference::Env(name) => {
            std::env::var(name).map_err(|_| format!("environment secret is unavailable: {name}"))
        }
        SecretReference::Keychain(account) => load_keychain(account),
        SecretReference::File(name) => load_file_secret(name),
    }
}

/// `file:NAME` 비밀이 있는 디렉토리. `workloads.toml`과 같은 설정 디렉토리라 aicd와 CLI가 같은
/// 위치를 본다.
pub fn file_secret_dir() -> std::path::PathBuf {
    crate::paths::config_file_path().with_file_name("secrets")
}

pub fn make_file_reference(name: &str) -> String {
    format!("{FILE_PREFIX}{name}")
}

/// 비밀을 `file_secret_dir()/NAME`에 소유자만 읽을 수 있게 저장하고 `file:NAME` 참조를 돌려준다.
pub fn store_file_secret(name: &str, secret: &str) -> Result<String, String> {
    store_file_secret_in(&file_secret_dir(), name, secret)?;
    Ok(make_file_reference(name))
}

pub fn delete_file_secret(name: &str) -> Result<(), String> {
    if !is_file_secret_name(name) {
        return Err("file secret name is invalid".to_string());
    }
    match std::fs::remove_file(file_secret_dir().join(name)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("file secret 삭제 실패: {error}")),
    }
}

fn load_file_secret(name: &str) -> Result<String, String> {
    load_file_secret_in(&file_secret_dir(), name)
}

fn store_file_secret_in(dir: &std::path::Path, name: &str, secret: &str) -> Result<(), String> {
    use std::io::Write;
    if !is_file_secret_name(name) {
        return Err("file secret name is invalid".to_string());
    }
    std::fs::create_dir_all(dir).map_err(|error| format!("secret 디렉토리 생성 실패: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(SECRET_DIR_MODE))
            .map_err(|error| format!("secret 디렉토리 권한 설정 실패: {error}"))?;
    }
    let temporary = dir.join(format!(".{name}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(SECRET_FILE_MODE);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("file secret 쓰기 실패: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(SECRET_FILE_MODE))
            .map_err(|error| format!("file secret 권한 설정 실패: {error}"))?;
    }
    file.write_all(secret.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("file secret 쓰기 실패: {error}"))?;
    std::fs::rename(&temporary, dir.join(name))
        .map_err(|error| format!("file secret 저장 실패: {error}"))
}

fn load_file_secret_in(dir: &std::path::Path, name: &str) -> Result<String, String> {
    if !is_file_secret_name(name) {
        return Err("file secret name is invalid".to_string());
    }
    let path = dir.join(name);
    let metadata =
        std::fs::metadata(&path).map_err(|_| format!("file secret is unavailable: {name}"))?;
    // 다른 사용자가 읽을 수 있는 비밀은 이미 새었을 수 있다. 조용히 쓰지 않고 거부해 고치게 한다.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "file secret must be readable only by its owner (chmod 600): {name}"
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let secret = std::fs::read_to_string(&path)
        .map_err(|_| format!("file secret is unavailable: {name}"))?;
    Ok(secret.trim_end_matches(['\n', '\r']).to_string())
}

fn is_file_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_SECRET_NAME
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
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

    #[test]
    fn a_file_secret_round_trips_and_stays_owner_only() {
        let root = std::env::temp_dir().join(format!(
            "aic-file-secret-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let secrets = root.join("secrets");
        store_file_secret_in(&secrets, "pg-db", "s3cret\n").unwrap();
        assert_eq!(load_file_secret_in(&secrets, "pg-db").unwrap(), "s3cret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&secrets), 0o700);
            assert_eq!(mode(&secrets.join("pg-db")), 0o600);
            std::fs::set_permissions(
                secrets.join("pg-db"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            let error = load_file_secret_in(&secrets, "pg-db").unwrap_err();
            assert!(error.contains("chmod 600"), "{error}");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_secret_name_cannot_leave_the_secret_directory() {
        for name in ["", "../x", "a/b", ".hidden", "a b", &"x".repeat(65)] {
            assert!(
                parse_secret_reference(&format!("file:{name}")).is_err(),
                "{name:?}"
            );
        }
        assert_eq!(
            parse_secret_reference("file:pg-dnx_postgres.1").unwrap(),
            SecretReference::File("pg-dnx_postgres.1")
        );
    }

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
