//! Audit log — JSONL append-only, HMAC-SHA256 line chain.
//!
//! 각 라인은 이전 라인의 hash를 참조해 chain을 형성한다. 변조 시 verify가 실패.
//! 6 이벤트 종류: secret_detected, redact_bypassed, circuit_opened, timeout,
//! redaction_applied, llm_request_sent.
//!
//! 위치: `~/.local/state/aic/audit.log` (file 0600, dir 0700).
//! HMAC 키: `~/.config/aic/audit.key` (0600, 부재 시 자동 생성).

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ROTATE_MAX_BYTES: u64 = 100 * 1024 * 1024;
const ROTATE_KEEP: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// C3 fix: 단조 증가하는 sequence 번호. 누락/swap/replay 검출용.
    /// 기존 로그(seq 필드 없음)는 0으로 default deserialize.
    #[serde(default)]
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub data: serde_json::Value,
    pub prev_hash: String,
    pub line_hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReport {
    pub lines: usize,
    pub valid: bool,
    /// chain이 깨진 라인 번호 (1-indexed). valid이면 None.
    pub broken_at: Option<usize>,
}

// ── 공개 API (default 위치 사용) ───────────────────────────────

/// 이벤트를 audit log에 append. best-effort — 실패해도 호출자에게 panic 없이 에러만 전달.
pub fn append(kind: &str, data: serde_json::Value) -> std::io::Result<()> {
    append_to(&audit_path(), &key_path(), kind, data)
}

/// audit log 무결성 검증.
pub fn verify() -> std::io::Result<VerifyReport> {
    verify_at(&audit_path(), &key_path())
}

// ── 내부 (path inject 가능) ────────────────────────────────────

fn append_to(
    log_path: &Path,
    key_path: &Path,
    kind: &str,
    data: serde_json::Value,
) -> std::io::Result<()> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
        apply_perm(parent, 0o700);
    }
    rotate_if_needed(log_path)?;

    let key = load_or_create_key(key_path)?;
    let last = last_event(log_path)?;
    let prev_hash = last
        .as_ref()
        .map(|e| e.line_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let next_seq = last.as_ref().map(|e| e.seq + 1).unwrap_or(0);

    let ts = Utc::now();
    let line_hash = compute_hash(&key, next_seq, &ts, kind, &data, &prev_hash)?;
    let event = AuditEvent {
        seq: next_seq,
        ts,
        kind: kind.to_string(),
        data,
        prev_hash,
        line_hash,
    };

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    apply_perm(log_path, 0o600);
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    Ok(())
}

fn verify_at(log_path: &Path, key_path: &Path) -> std::io::Result<VerifyReport> {
    if !log_path.exists() {
        return Ok(VerifyReport {
            lines: 0,
            valid: true,
            broken_at: None,
        });
    }
    let key = load_or_create_key(key_path)?;
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut prev = GENESIS_HASH.to_string();
    let mut expected_seq = 0u64;
    let mut count = 0usize;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: AuditEvent = serde_json::from_str(&line)
            .map_err(|e| std::io::Error::other(format!("parse line {}: {}", i + 1, e)))?;
        // C3 fix: seq 검증 — 누락/swap/replay 검출
        if event.seq != expected_seq {
            return Ok(VerifyReport {
                lines: count,
                valid: false,
                broken_at: Some(i + 1),
            });
        }
        if event.prev_hash != prev {
            return Ok(VerifyReport {
                lines: count,
                valid: false,
                broken_at: Some(i + 1),
            });
        }
        let expected = compute_hash(
            &key,
            event.seq,
            &event.ts,
            &event.kind,
            &event.data,
            &event.prev_hash,
        )?;
        if expected != event.line_hash {
            return Ok(VerifyReport {
                lines: count,
                valid: false,
                broken_at: Some(i + 1),
            });
        }
        prev = event.line_hash;
        expected_seq = event.seq + 1;
        count += 1;
    }
    Ok(VerifyReport {
        lines: count,
        valid: true,
        broken_at: None,
    })
}

fn compute_hash(
    key: &[u8],
    seq: u64,
    ts: &DateTime<Utc>,
    kind: &str,
    data: &serde_json::Value,
    prev_hash: &str,
) -> std::io::Result<String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(std::io::Error::other)?;
    mac.update(seq.to_string().as_bytes());
    mac.update(b"|");
    mac.update(ts.to_rfc3339().as_bytes());
    mac.update(b"|");
    mac.update(kind.as_bytes());
    mac.update(b"|");
    mac.update(serde_json::to_string(data)?.as_bytes());
    mac.update(b"|");
    mac.update(prev_hash.as_bytes());
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

/// 마지막 valid event를 반환 (seq + line_hash 추출용).
fn last_event(path: &Path) -> std::io::Result<Option<AuditEvent>> {
    if !path.exists() {
        return Ok(None);
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut last = None;
    for line in reader.lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<AuditEvent>(&line) {
            last = Some(event);
        }
    }
    Ok(last)
}

/// C2 fix: HMAC 키는 OS keychain 우선, file은 fallback (headless Linux 등).
/// 평문 file 키 발견 시 keychain로 마이그레이션 시도 (best-effort).
const KEYCHAIN_ACCOUNT: &str = "audit_hmac";

fn load_or_create_key(path: &Path) -> std::io::Result<Vec<u8>> {
    load_or_create_key_inner(path, !is_keychain_disabled())
}

fn is_keychain_disabled() -> bool {
    // 단위 테스트는 file fallback 경로를 검증하므로 keychain 우회
    if cfg!(test) {
        return true;
    }
    std::env::var("AIC_NO_KEYCHAIN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn load_or_create_key_inner(path: &Path, use_keychain: bool) -> std::io::Result<Vec<u8>> {
    // 1) keychain 우선
    if use_keychain {
        if let Ok(hex) = crate::keychain::load(KEYCHAIN_ACCOUNT) {
            if let Some(bytes) = decode_hex(&hex) {
                if bytes.len() >= 32 {
                    return Ok(bytes);
                }
            }
        }
    }

    // 2) 기존 file 키 (이전 버전 호환) — keychain 사용 시 마이그레이션 best-effort
    if let Ok(content) = std::fs::read(path) {
        if content.len() >= 32 {
            if use_keychain {
                let _ = crate::keychain::store(KEYCHAIN_ACCOUNT, &hex_encode(&content));
            }
            return Ok(content);
        }
    }

    // 3) 새 키 생성
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        apply_perm(parent, 0o700);
    }
    let mut key = vec![0u8; 32];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;

    // 4) keychain 저장 시도 — 성공 시 file에 저장 안 함
    if use_keychain && crate::keychain::store(KEYCHAIN_ACCOUNT, &hex_encode(&key)).is_ok() {
        return Ok(key);
    }

    // 5) keychain 비활성 또는 저장 실패 시 file fallback
    std::fs::write(path, &key)?;
    apply_perm(path, 0o600);
    Ok(key)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn rotate_if_needed(path: &Path) -> std::io::Result<()> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if metadata.len() < ROTATE_MAX_BYTES {
        return Ok(());
    }
    // 가장 오래된 .ROTATE_KEEP 삭제 후 N..1 이동
    let _ = std::fs::remove_file(path.with_extension(format!("log.{ROTATE_KEEP}")));
    for i in (1..ROTATE_KEEP).rev() {
        let from = path.with_extension(format!("log.{i}"));
        let to = path.with_extension(format!("log.{}", i + 1));
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    let _ = std::fs::rename(path, path.with_extension("log.1"));
    Ok(())
}

fn apply_perm(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn audit_path() -> PathBuf {
    home()
        .join(".local")
        .join("state")
        .join("aic")
        .join("audit.log")
}

fn key_path() -> PathBuf {
    home().join(".config").join("aic").join("audit.key")
}

fn home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let key = dir.path().join("audit.key");
        (dir, log, key)
    }

    #[test]
    fn empty_log_verifies_as_valid() {
        let (_dir, log, key) = setup();
        let report = verify_at(&log, &key).unwrap();
        assert_eq!(report.lines, 0);
        assert!(report.valid);
    }

    #[test]
    fn append_and_verify_single_event() {
        let (_dir, log, key) = setup();
        append_to(
            &log,
            &key,
            "secret_detected",
            serde_json::json!({"kind": "aws_key"}),
        )
        .unwrap();
        let report = verify_at(&log, &key).unwrap();
        assert_eq!(report.lines, 1);
        assert!(report.valid);
    }

    #[test]
    fn append_and_verify_chain_of_six() {
        let (_dir, log, key) = setup();
        for kind in [
            "secret_detected",
            "redact_bypassed",
            "circuit_opened",
            "timeout",
            "redaction_applied",
            "llm_request_sent",
        ] {
            append_to(&log, &key, kind, serde_json::json!({"k": kind})).unwrap();
        }
        let report = verify_at(&log, &key).unwrap();
        assert_eq!(report.lines, 6);
        assert!(report.valid);
    }

    #[test]
    fn tampered_data_fails_verify() {
        let (_dir, log, key) = setup();
        append_to(
            &log,
            &key,
            "circuit_opened",
            serde_json::json!({"endpoint": "x"}),
        )
        .unwrap();
        append_to(&log, &key, "timeout", serde_json::json!({"secs": 30})).unwrap();

        // 1번 라인의 data를 변조
        let content = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let tampered = lines[0].replace("\"x\"", "\"injected\"");
        let owned = [tampered, lines[1].to_string()];
        let _ = lines;
        std::fs::write(&log, owned.join("\n") + "\n").unwrap();

        let report = verify_at(&log, &key).unwrap();
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(1));
    }

    #[test]
    fn key_file_persists_across_calls() {
        let (_dir, log, key) = setup();
        append_to(&log, &key, "timeout", serde_json::json!({})).unwrap();
        let key_content_1 = std::fs::read(&key).unwrap();
        append_to(&log, &key, "timeout", serde_json::json!({})).unwrap();
        let key_content_2 = std::fs::read(&key).unwrap();
        assert_eq!(key_content_1, key_content_2);
    }

    #[test]
    fn log_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, log, key) = setup();
        append_to(&log, &key, "timeout", serde_json::json!({})).unwrap();
        let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn key_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, log, key) = setup();
        append_to(&log, &key, "timeout", serde_json::json!({})).unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn hex_encode_roundtrip_known_value() {
        let key = vec![0u8; 32];
        let prev = GENESIS_HASH.to_string();
        let ts = Utc::now();
        let h1 = compute_hash(&key, 0, &ts, "k", &serde_json::Value::Null, &prev).unwrap();
        let h2 = compute_hash(&key, 0, &ts, "k", &serde_json::Value::Null, &prev).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 32 bytes hex
                                  // seq가 다르면 hash도 달라야 함
        let h3 = compute_hash(&key, 1, &ts, "k", &serde_json::Value::Null, &prev).unwrap();
        assert_ne!(h1, h3);
    }

    // C3 fix: 새 시나리오 — line swap / deletion / key rotation

    #[test]
    fn line_swap_fails_verify() {
        let (_dir, log, key) = setup();
        append_to(&log, &key, "first", serde_json::json!({"i": 1})).unwrap();
        append_to(&log, &key, "second", serde_json::json!({"i": 2})).unwrap();
        append_to(&log, &key, "third", serde_json::json!({"i": 3})).unwrap();

        // 1번과 2번 라인 swap
        let content = std::fs::read_to_string(&log).unwrap();
        let mut lines: Vec<&str> = content.lines().collect();
        lines.swap(0, 1);
        std::fs::write(&log, lines.join("\n") + "\n").unwrap();

        let report = verify_at(&log, &key).unwrap();
        assert!(!report.valid, "swap된 라인은 verify 실패해야 함");
        assert_eq!(report.broken_at, Some(1));
    }

    #[test]
    fn middle_line_deletion_fails_verify() {
        let (_dir, log, key) = setup();
        append_to(&log, &key, "a", serde_json::json!({"i": 1})).unwrap();
        append_to(&log, &key, "b", serde_json::json!({"i": 2})).unwrap();
        append_to(&log, &key, "c", serde_json::json!({"i": 3})).unwrap();

        // 중간 라인 삭제 (seq 0, 2만 남김 — gap)
        let content = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let kept = [lines[0], lines[2]];
        std::fs::write(&log, kept.join("\n") + "\n").unwrap();

        let report = verify_at(&log, &key).unwrap();
        assert!(!report.valid, "중간 라인 삭제는 seq gap으로 검출되어야 함");
    }

    #[test]
    fn key_change_fails_verify() {
        let (_dir, log, key) = setup();
        append_to(&log, &key, "evt", serde_json::json!({})).unwrap();

        // 키를 다른 값으로 교체
        std::fs::write(&key, vec![0xFFu8; 32]).unwrap();

        let report = verify_at(&log, &key).unwrap();
        assert!(
            !report.valid,
            "키 교체 후 verify는 line_hash mismatch로 실패"
        );
        assert_eq!(report.broken_at, Some(1));
    }

    #[test]
    fn first_line_seq_is_zero() {
        let (_dir, log, key) = setup();
        append_to(&log, &key, "first", serde_json::json!({})).unwrap();
        let content = std::fs::read_to_string(&log).unwrap();
        assert!(content.contains("\"seq\":0"));
    }

    #[test]
    fn second_line_seq_is_one() {
        let (_dir, log, key) = setup();
        append_to(&log, &key, "first", serde_json::json!({})).unwrap();
        append_to(&log, &key, "second", serde_json::json!({})).unwrap();
        let content = std::fs::read_to_string(&log).unwrap();
        assert!(content.contains("\"seq\":0"));
        assert!(content.contains("\"seq\":1"));
    }
}
