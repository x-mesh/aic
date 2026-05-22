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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

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

    // 기존 chain 보호: log에 이미 내용이 있으면(=keychain-only chain일 수 있음) keychain/file에서
    // 키를 **얻어야만** append한다. 키를 못 얻는데 새 fallback 키로 이어 쓰면 chain이 깨지므로
    // 새 키 생성은 log가 비었거나 없을 때(allow_new)만 허용한다.
    let last = last_event(log_path)?;
    let allow_new = last.is_none();
    let key = match load_or_create_key(key_path, allow_new) {
        Ok(k) => k,
        Err(e) => {
            // chain 보호를 위해 append를 skip(새 키로 이어 쓰지 않음). 일반 출력은 조용히.
            keychain_chain_skip_hint();
            return Err(e);
        }
    };
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
    // verify는 읽기 전용 — 새 키를 생성하지 않는다(allow_new=false).
    let key = load_or_create_key(key_path, false)?;
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

/// audit HMAC 키 backend: **기본 file**, `AIC_AUDIT_KEYCHAIN=1`일 때만 OS keychain opt-in.
/// `AIC_NO_KEYCHAIN=1`은 최우선 off. keychain opt-in 시 평문 file 키는 keychain으로 마이그레이션 시도.
const KEYCHAIN_ACCOUNT: &str = "audit_hmac";
/// keychain 접근(load/store) 1회 timeout. nested-PTY/headless(Aqua 세션 밖)에서 Security
/// framework Mach IPC가 무한 block하는 것을 막는다. 초과 시 file fallback으로 degrade.
const KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// keychain이 한 번이라도 timeout/실패하면 이후 접근을 건너뛴다(blocking thread 누적 방지).
static KEYCHAIN_BLOCKED: AtomicBool = AtomicBool::new(false);

/// audit HMAC 키를 로드/생성한다. **keychain opt-in(`AIC_AUDIT_KEYCHAIN=1`) 시 프로세스 내 1회만**
/// keychain에 접근하고 이후엔 캐시된 키를 쓴다(매 append마다 Mach IPC 호출 → hang 방지). 기본/테스트·
/// `AIC_NO_KEYCHAIN`은 캐시 없이 file 경로를 그대로 사용한다(키 파일 변경 즉시 반영).
fn load_or_create_key(path: &Path, allow_new: bool) -> std::io::Result<Vec<u8>> {
    if !keychain_enabled() {
        return load_or_create_key_inner(path, false, allow_new);
    }
    static CACHE: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    key_with_cache(cache, || load_or_create_key_inner(path, true, allow_new))
}

/// 캐시에 키가 있으면 그대로, 없으면 `load`를 **락을 보유한 채** 1회 호출해 채운다.
/// 동시 cache miss여도 load는 한 번만 실행되어 keychain load thread가 누적되지 않는다
/// (단일 초기화 semantics). 프로세스 수명 동안 동일 키 → HMAC chain 정합 유지.
/// 락 poison은 무시(키는 불변이므로 안전).
fn key_with_cache(
    cache: &Mutex<Option<Vec<u8>>>,
    load: impl FnOnce() -> std::io::Result<Vec<u8>>,
) -> std::io::Result<Vec<u8>> {
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(k) = guard.as_ref() {
        return Ok(k.clone());
    }
    // 락을 잡은 채 load → 동시 호출은 여기서 대기하다 위 캐시 hit으로 빠진다.
    let key = load()?;
    *guard = Some(key.clone());
    Ok(key)
}

/// 기존 chain이 있는데 키를 못 얻어 append를 skip할 때의 힌트(일반 출력은 조용히, AIC_DEBUG=1|true만).
fn keychain_chain_skip_hint() {
    if env_true("AIC_DEBUG") {
        eprintln!(
            "[audit] 기존 audit chain의 키를 얻지 못해(키체인 불가·file 키 없음) append를 건너뜀 \
             — 새 키로 chain을 깨지 않도록 보호"
        );
    }
}

/// 클로저를 별도 스레드에서 실행하고 `dur` 내 완료를 기다린다. 초과 시 `None`(스레드는
/// detach — keychain Mach 호출이 무한 block해도 호출자는 막히지 않는다).
fn run_with_timeout<T: Send + 'static>(
    dur: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(dur).ok()
}

/// timeout을 적용한 keychain load. 이전에 block된 적 있으면 즉시 skip.
fn keychain_load_timed(account: &str) -> Result<String, String> {
    if KEYCHAIN_BLOCKED.load(Ordering::SeqCst) {
        return Err("keychain disabled (prior timeout)".into());
    }
    let acct = account.to_string();
    match run_with_timeout(KEYCHAIN_TIMEOUT, move || crate::keychain::load(&acct)) {
        Some(r) => r,
        None => {
            KEYCHAIN_BLOCKED.store(true, Ordering::SeqCst);
            keychain_timeout_hint("load");
            Err("keychain load timed out".into())
        }
    }
}

/// timeout을 적용한 keychain store(best-effort). block되면 file fallback에 맡긴다.
fn keychain_store_timed(account: &str, secret: &str) -> Result<(), String> {
    if KEYCHAIN_BLOCKED.load(Ordering::SeqCst) {
        return Err("keychain disabled (prior timeout)".into());
    }
    let acct = account.to_string();
    let sec = secret.to_string();
    match run_with_timeout(KEYCHAIN_TIMEOUT, move || {
        crate::keychain::store(&acct, &sec)
    }) {
        Some(r) => r,
        None => {
            KEYCHAIN_BLOCKED.store(true, Ordering::SeqCst);
            keychain_timeout_hint("store");
            Err("keychain store timed out".into())
        }
    }
}

/// keychain timeout 힌트는 일반 출력을 시끄럽게 하지 않도록 `AIC_DEBUG=1|true`일 때만 stderr로.
fn keychain_timeout_hint(op: &str) {
    if env_true("AIC_DEBUG") {
        eprintln!("[audit] keychain {op} timed out — audit HMAC 키를 file fallback으로 사용");
    }
}

/// env 값이 `1`/`true`(대소문자 무시)면 true.
fn env_true(name: &str) -> bool {
    // 공통 semantics: trim + case-insensitive로 `1`/`true`만 ON(`agent::debug::truthy`와 동일).
    std::env::var(name)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// 순수 결정 로직(테스트용): keychain 사용 여부. 우선순위 test → NO_KEYCHAIN → opt-in.
fn keychain_enabled_from(is_test: bool, no_keychain: bool, opt_in: bool) -> bool {
    if is_test {
        return false; // 단위 테스트는 항상 file
    }
    if no_keychain {
        return false; // 최우선 차단
    }
    opt_in // opt-in(AIC_AUDIT_KEYCHAIN)일 때만 사용
}

/// audit HMAC 키 backend로 keychain을 쓸지. **기본은 file(off)**, `AIC_AUDIT_KEYCHAIN=1`일 때만
/// opt-in. `AIC_NO_KEYCHAIN=1`은 최우선으로 off. 단위 테스트는 항상 file.
fn keychain_enabled() -> bool {
    keychain_enabled_from(
        cfg!(test),
        env_true("AIC_NO_KEYCHAIN"),
        env_true("AIC_AUDIT_KEYCHAIN"),
    )
}

/// 순수 결정 로직(테스트용): backend 라벨. 우선순위 NO_KEYCHAIN > opt-in > 기본(file).
fn audit_key_backend_for(no_keychain: bool, opt_in: bool) -> &'static str {
    if no_keychain {
        "file (keychain off: AIC_NO_KEYCHAIN)"
    } else if opt_in {
        "keychain (opt-in: AIC_AUDIT_KEYCHAIN)"
    } else {
        "file (default)"
    }
}

/// `/doctor`·문서용 audit key backend 라벨.
pub fn audit_key_backend() -> &'static str {
    audit_key_backend_for(env_true("AIC_NO_KEYCHAIN"), env_true("AIC_AUDIT_KEYCHAIN"))
}

fn load_or_create_key_inner(
    path: &Path,
    use_keychain: bool,
    allow_new: bool,
) -> std::io::Result<Vec<u8>> {
    // 1) keychain 우선 (timeout 적용 — block 시 file로 degrade)
    if use_keychain {
        if let Ok(hex) = keychain_load_timed(KEYCHAIN_ACCOUNT) {
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
                let _ = keychain_store_timed(KEYCHAIN_ACCOUNT, &hex_encode(&content));
            }
            return Ok(content);
        }
    }

    // 2.5) chain 보호: 기존 chain이 있는데(allow_new=false) keychain·file 모두에서 키를 못 얻으면
    // **새 키를 만들지 않는다**. 새 키로 append하면 기존 keychain-only chain이 깨지기 때문.
    if !allow_new {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "audit 키를 얻을 수 없고(keychain 불가·file 키 없음) 기존 chain이 있어 새 키 생성을 건너뜀",
        ));
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
    if use_keychain && keychain_store_timed(KEYCHAIN_ACCOUNT, &hex_encode(&key)).is_ok() {
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

    // ── keychain block 수정: timeout + cache ──────────────────

    #[test]
    fn run_with_timeout_returns_value_when_fast() {
        let r = run_with_timeout(Duration::from_secs(2), || 42);
        assert_eq!(r, Some(42));
    }

    #[test]
    fn run_with_timeout_gives_up_when_slow() {
        // 느린 클로저(5s)는 짧은 timeout(100ms)에 None으로 포기 → 호출자 비차단.
        let start = std::time::Instant::now();
        let r = run_with_timeout(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_secs(5));
            7
        });
        assert_eq!(r, None);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timeout이 빠르게 반환해야 함: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn key_with_cache_loads_once_then_caches() {
        use std::cell::Cell;
        let cache = Mutex::new(None);
        let calls = Cell::new(0);
        let key1 = key_with_cache(&cache, || {
            calls.set(calls.get() + 1);
            Ok(vec![9u8; 32])
        })
        .unwrap();
        let key2 = key_with_cache(&cache, || {
            calls.set(calls.get() + 1);
            Ok(vec![1u8; 32]) // 두 번째 load는 호출되면 안 됨(캐시 hit).
        })
        .unwrap();
        assert_eq!(calls.get(), 1, "load는 1회만 호출되어야 함(이후 캐시)");
        assert_eq!(key1, vec![9u8; 32]);
        assert_eq!(key2, key1, "캐시된 동일 키를 반환해야 함(HMAC chain 정합)");
    }

    #[test]
    fn key_change_still_detected_without_cache_in_test_mode() {
        // cfg(test)에서는 keychain 비활성 → load_or_create_key가 캐시를 거치지 않고 file을
        // 매번 읽는다(키 파일 변경 즉시 반영). key_change_fails_verify와 동일 불변식 재확인.
        let (_dir, log, key) = setup();
        append_to(&log, &key, "evt", serde_json::json!({})).unwrap();
        std::fs::write(&key, vec![0xAAu8; 32]).unwrap();
        let report = verify_at(&log, &key).unwrap();
        assert!(
            !report.valid,
            "test 모드는 캐시 없이 file 키를 재읽어 변경을 검출해야 함"
        );
    }

    // ── 리뷰 finding: chain 보호 + 단일 key load ──────────────

    #[test]
    fn no_new_key_when_chain_exists_and_no_file_key() {
        // allow_new=false인데 keychain 불가·file 키 없음 → 새 키 생성 거부(Err), 파일 미생성.
        let (_dir, _log, key) = setup();
        let r = load_or_create_key_inner(&key, false, false);
        assert!(r.is_err(), "기존 chain 보호: 새 키 생성 거부");
        assert!(!key.exists(), "키 파일을 만들지 않아야 함");
    }

    #[test]
    fn append_skips_when_key_missing_and_chain_exists() {
        // 기존 chain(첫 append로 생성)에서 키 파일이 사라지면(keychain-only인데 keychain 불가
        // 상황 시뮬레이션) 두 번째 append는 새 키로 이어 쓰지 않고 skip(Err)해야 한다. chain 불변.
        let (_dir, log, key) = setup();
        append_to(&log, &key, "evt1", serde_json::json!({})).unwrap();
        std::fs::remove_file(&key).unwrap();
        let before = std::fs::read_to_string(&log).unwrap();
        let r = append_to(&log, &key, "evt2", serde_json::json!({}));
        assert!(r.is_err(), "키를 못 얻으면 append를 skip(chain 보호)");
        let after = std::fs::read_to_string(&log).unwrap();
        assert_eq!(before, after, "log에 새 line이 추가되면 안 됨");
        assert!(!key.exists(), "새 키 파일을 만들면 안 됨");
    }

    #[test]
    fn first_append_allows_new_key_when_log_empty() {
        // log가 비어 있으면 allow_new=true → file fallback 키 생성 + append 성공(기존 동작 유지).
        let (_dir, log, key) = setup();
        append_to(&log, &key, "evt", serde_json::json!({})).unwrap();
        assert!(key.exists(), "첫 append는 키를 생성해야 함");
        assert!(verify_at(&log, &key).unwrap().valid);
    }

    #[test]
    fn keychain_backend_precedence() {
        // 기본(opt-in 없음) → file.
        assert!(
            !keychain_enabled_from(false, false, false),
            "기본은 file(off)"
        );
        // opt-in만 → keychain.
        assert!(
            keychain_enabled_from(false, false, true),
            "AIC_AUDIT_KEYCHAIN=on → keychain"
        );
        // NO_KEYCHAIN은 opt-in보다 우선 → off.
        assert!(
            !keychain_enabled_from(false, true, true),
            "AIC_NO_KEYCHAIN이 opt-in보다 우선(off)"
        );
        // 테스트 모드는 항상 off.
        assert!(
            !keychain_enabled_from(true, false, true),
            "cfg(test)는 항상 file"
        );
    }

    #[test]
    fn audit_key_backend_labels() {
        assert_eq!(audit_key_backend_for(false, false), "file (default)");
        assert_eq!(
            audit_key_backend_for(false, true),
            "keychain (opt-in: AIC_AUDIT_KEYCHAIN)"
        );
        // NO_KEYCHAIN 우선.
        assert_eq!(
            audit_key_backend_for(true, true),
            "file (keychain off: AIC_NO_KEYCHAIN)"
        );
        assert_eq!(
            audit_key_backend_for(true, false),
            "file (keychain off: AIC_NO_KEYCHAIN)"
        );
    }

    #[test]
    fn concurrent_key_load_calls_loader_once() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        let cache = Arc::new(Mutex::new(None));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = Arc::clone(&cache);
            let n = Arc::clone(&calls);
            handles.push(std::thread::spawn(move || {
                key_with_cache(&c, || {
                    n.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50));
                    Ok(vec![5u8; 32])
                })
                .unwrap()
            }));
        }
        let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "동시 cache miss여도 loader는 1회만 호출되어야 함"
        );
        assert!(keys.iter().all(|k| *k == vec![5u8; 32]), "모두 동일 키");
    }
}
