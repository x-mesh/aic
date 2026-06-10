//! 인시던트 증거 번들 작성 (SRE R0/R2).
//!
//! `/bundle` slash(대화형)와 `aic diagnose --bundle`·webhook 자동 진단(비대화)에서 공유한다.
//! redacted 증거 markdown을 `~/.aic/bundles/<label>-<ts>.md`에 0600/0700 권한으로 저장.

use std::path::PathBuf;

use super::tool_record;

/// 증거 markdown을 `~/.aic/bundles/`에 저장하고 경로를 반환한다.
///
/// 비대화 컨텍스트(webhook/CLI)에서도 호출 가능 — TTY/세션 상태에 의존하지 않는다.
pub fn write_bundle(name: Option<&str>, evidence: &str) -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("홈 디렉터리를 찾을 수 없습니다"))?;
    let dir = home.join(".aic").join("bundles");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let label = tool_record::sanitize_bundle_name(name.unwrap_or(""));
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("{label}-{ts}.md"));
    let body = format!(
        "# aic incident bundle: {label}\n생성: {ts}\n\n{evidence}\n",
        label = name.unwrap_or("(unnamed)"),
    );
    std::fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_bundle_creates_redacted_markdown_file() {
        // HOME을 임시 디렉터리로 돌려 실제 파일 생성 경로를 검증한다.
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        // SAFETY: 단일 스레드 테스트 — 직후 복원.
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }

        let path = write_bundle(Some("api-latency"), "## ps\nproc list\n").unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("aic incident bundle: api-latency"));
        assert!(content.contains("proc list"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}
