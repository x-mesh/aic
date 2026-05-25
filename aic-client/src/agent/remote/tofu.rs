//! TOFU(Trust On First Use) 4-step (RFC-005 §4.1, BatchMode↔TOFU 양립 해소).
//!
//! `BatchMode=yes` + `StrictHostKeyChecking=yes` 조합은 known_hosts에 없는 호스트에 대해
//! ssh가 즉시 exit 255로 종료한다. TOFU prompt UI 없이는 신규 호스트 등록 불가하다.
//! 이 모듈은 다음 4-step의 핵심 함수만 제공한다 — wiring(ssh_process 자동 재시도, chat TUI
//! confirm UI, mpsc 직렬화)은 호출자 책임.
//!
//! 1. ssh 시도 → exit 255 (host key 미일치) ← `ssh_process::SshProcessExecutor` 책임
//! 2. **`scan_host(hostname, port, timeout)`** — `ssh-keyscan`으로 fingerprint 수집
//! 3. **TUI/stdin confirm**(호출자) — fingerprint를 사용자에게 노출
//! 4. **`append_known_hosts(path, host_keys)`** — `~/.ssh/known_hosts`에 append
//!
//! 보안 주의: `ssh-keyscan` 자체가 MITM 노출 위험이 있다(공격자가 자기 키 반환). 호출자는
//! confirm UI에서 fingerprint를 외부 채널로 검증할 것을 사용자에게 안내해야 한다.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

/// `ssh-keyscan` 실행 결과 — host key 라인 모음.
#[derive(Debug, Clone)]
pub struct KeyScan {
    pub host_keys: Vec<HostKey>,
}

/// 한 줄의 host key (`<hostname> <key_type> <base64_blob>` 형태).
#[derive(Debug, Clone)]
pub struct HostKey {
    pub key_type: String,
    /// known_hosts에 그대로 append할 수 있는 통째 라인.
    pub known_hosts_line: String,
}

/// `ssh-keyscan -T {timeout} -p {port} {hostname}`을 실행해 호스트 키를 수집한다.
/// 미설치/네트워크 실패는 `Err`. 결과가 비어 있어도 `Err`(MITM 의심 또는 알고리즘 호환 X).
pub async fn scan_host(hostname: &str, port: u16, timeout_secs: u32) -> Result<KeyScan> {
    let out = tokio::process::Command::new("ssh-keyscan")
        .args([
            "-T",
            &timeout_secs.to_string(),
            "-p",
            &port.to_string(),
            hostname,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .context("ssh-keyscan invocation failed (not installed?)")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let host_keys = parse_keyscan_lines(&stdout);
    if host_keys.is_empty() {
        return Err(anyhow!(
            "ssh-keyscan returned no host keys (stderr: {})",
            stderr.trim()
        ));
    }
    Ok(KeyScan { host_keys })
}

/// `ssh-keyscan` 출력에서 host key 라인 파싱(주석/빈 줄 무시, malformed 무시).
pub(crate) fn parse_keyscan_lines(stdout: &str) -> Vec<HostKey> {
    stdout
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|line| {
            let mut parts = line.splitn(3, ' ');
            let _host = parts.next()?;
            let key_type = parts.next()?;
            let _key_data = parts.next()?;
            Some(HostKey {
                key_type: key_type.to_string(),
                known_hosts_line: line.to_string(),
            })
        })
        .collect()
}

/// 사용자가 승인한 호스트 키를 `~/.ssh/known_hosts`에 append한다.
///
/// `O_APPEND` mode는 단일 `write()`를 OS 레벨 atomic하게 처리하므로(<PIPE_BUF=512), 라인 길이가
/// ~100B인 known_hosts entry에는 advisory lock 없이도 partial line 위험이 무시할 수준이다.
/// 다만 동시에 여러 aic 인스턴스가 같은 호스트를 등록하면 라인 순서·중복은 비결정.
pub fn append_known_hosts(known_hosts: &Path, host_keys: &[HostKey]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    if let Some(parent) = known_hosts.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(known_hosts)
        .with_context(|| format!("open {} for append", known_hosts.display()))?;
    for key in host_keys {
        writeln!(file, "{}", key.known_hosts_line).with_context(|| "write known_hosts entry")?;
    }
    Ok(())
}

/// `ssh-keygen -l -f /dev/stdin`을 호출해 SHA256 fingerprint를 받는다 — confirm UI 노출용.
///
/// 결과 형식 예: `256 SHA256:abc...= host (ED25519)`. 두 번째 필드(SHA256:...)를 반환한다.
/// `ssh-keygen` 미설치/실패는 `Err`.
pub async fn fingerprint_sha256(known_hosts_line: &str) -> Result<String> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("ssh-keygen")
        .args(["-l", "-f", "/dev/stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("ssh-keygen invocation failed (not installed?)")?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(known_hosts_line.as_bytes())
            .await
            .context("write key to ssh-keygen stdin")?;
        stdin.write_all(b"\n").await.ok();
    }
    let out = child
        .wait_with_output()
        .await
        .context("ssh-keygen wait failed")?;
    if !out.status.success() {
        return Err(anyhow!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let fp = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("ssh-keygen output unexpected: {line}"))?
        .to_string();
    Ok(fp)
}

// ── 테스트 ──────────────────────────────────────────────────────────
// ssh-keyscan/ssh-keygen 외부 호출이 필요한 부분은 #[ignore] 또는 통합 테스트로.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_keyscan_lines_skips_comments_and_empty() {
        let stdout = "\
# 10.0.1.10:22 SSH-2.0-OpenSSH_9.6
10.0.1.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
10.0.1.10 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHA...
# end
";
        let keys = parse_keyscan_lines(stdout);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[1].key_type, "ecdsa-sha2-nistp256");
        assert!(keys[0].known_hosts_line.starts_with("10.0.1.10"));
    }

    #[test]
    fn parse_keyscan_lines_ignores_malformed() {
        let stdout = "10.0.1.10 just-a-key-no-data\n10.0.1.11 ssh-rsa BLOB\n\n";
        let keys = parse_keyscan_lines(stdout);
        assert_eq!(keys.len(), 1, "두 토큰 라인은 무시, 세 토큰 라인만 유지");
        assert_eq!(keys[0].key_type, "ssh-rsa");
    }

    #[test]
    fn append_known_hosts_creates_file_and_appends_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("subdir").join("known_hosts");
        let keys = vec![
            HostKey {
                key_type: "ssh-ed25519".into(),
                known_hosts_line: "10.0.1.10 ssh-ed25519 AAAA...".into(),
            },
            HostKey {
                key_type: "ssh-rsa".into(),
                known_hosts_line: "10.0.1.10 ssh-rsa AAAA...".into(),
            },
        ];
        append_known_hosts(&path, &keys).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("ssh-ed25519"));
        assert!(body.contains("ssh-rsa"));

        // 두 번째 호출은 누적(append).
        append_known_hosts(&path, &keys[..1]).unwrap();
        let body2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body2.lines().count(), 3);
    }

    /// 통합 테스트: 실제 ssh-keygen이 설치된 환경에서만 실행.
    #[tokio::test]
    #[ignore]
    async fn fingerprint_sha256_with_real_ssh_keygen() {
        // RFC 5208 ed25519 sample — 실제 ssh-keygen이 SHA256 fingerprint를 반환해야 함.
        let line = "test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINq6n8j7gqzL+M+1aB0pUe8jKqzbxA6IsBKZ3W0jW5Xv";
        let fp = fingerprint_sha256(line).await.unwrap();
        assert!(fp.starts_with("SHA256:"), "fingerprint: {fp}");
    }
}
