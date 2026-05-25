//! 멀티호스트 batch audit (RFC-005 §4.6, O2 fix).
//!
//! 단일 호스트 audit(기존 `aic_client::audit`)와 분리된 모듈로, 멀티호스트 fan-out 단위
//! audit를 daily segment 파일(`~/.aic/audit/YYYY-MM-DD.jsonl`)에 JSONL append한다. 각 엔트리는
//! `prev_hash` chain으로 무결성을 보존하며, segment 경계에는 `segment_end` 레코드로 다음
//! segment와 연결고리를 남긴다(cross-segment verify).
//!
//! 엔트리 종류:
//!   - `batch_start` — 멀티호스트 명령 시작
//!   - `host_result` — 호스트별 RemoteResult
//!   - `tofu_accept` / `tofu_reject` / `host_key_mismatch` — TOFU 보안 이벤트
//!   - `batch_end` — 완료(stats 포함)
//!   - `batch_cancelled` — Ctrl+C 취소
//!   - `segment_end` — day segment 경계(다음 segment 파일명 포함)
//!
//! Chain: `hash = sha256(prev_hash || serialize(entry_without_hash))`. 단순 SHA256 chain으로
//! 시작 — 미래 HMAC 마이그레이션 가능(기존 `audit.rs`와 같은 secret_key 도입 시).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// audit 엔트리 — 모든 종류를 한 enum으로 표현해 JSONL 한 줄당 하나의 type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEntry {
    BatchStart {
        ts: DateTime<Utc>,
        batch_id: String,
        kind: String,
        group: String,
        hosts: Vec<String>,
        prev_hash: String,
        hash: String,
    },
    HostResult {
        ts: DateTime<Utc>,
        batch_id: String,
        host: String,
        status: String,
        cmd: String,
        duration_ms: u64,
        exit_code: i32,
        truncated: bool,
        redacted: usize,
        prev_hash: String,
        hash: String,
    },
    TofuAccept {
        ts: DateTime<Utc>,
        batch_id: String,
        host: String,
        fingerprint: String,
        prev_hash: String,
        hash: String,
    },
    TofuReject {
        ts: DateTime<Utc>,
        batch_id: String,
        host: String,
        fingerprint: String,
        reason: String,
        prev_hash: String,
        hash: String,
    },
    BatchEnd {
        ts: DateTime<Utc>,
        batch_id: String,
        stats: BatchStats,
        prev_hash: String,
        hash: String,
    },
    BatchCancelled {
        ts: DateTime<Utc>,
        batch_id: String,
        completed: usize,
        incomplete: Vec<String>,
        prev_hash: String,
        hash: String,
    },
    SegmentEnd {
        ts: DateTime<Utc>,
        date: String,
        next_segment: String,
        prev_hash: String,
        hash: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchStats {
    pub ok: usize,
    pub ok_warn: usize,
    pub unreachable: usize,
    pub timeout: usize,
    pub auth_fail: usize,
    pub proxy_fail: usize,
    pub remote_err: usize,
    pub host_key_mismatch: usize,
    pub cancelled: usize,
}

impl AuditEntry {
    fn prev_hash(&self) -> &str {
        match self {
            AuditEntry::BatchStart { prev_hash, .. }
            | AuditEntry::HostResult { prev_hash, .. }
            | AuditEntry::TofuAccept { prev_hash, .. }
            | AuditEntry::TofuReject { prev_hash, .. }
            | AuditEntry::BatchEnd { prev_hash, .. }
            | AuditEntry::BatchCancelled { prev_hash, .. }
            | AuditEntry::SegmentEnd { prev_hash, .. } => prev_hash,
        }
    }
    pub fn hash(&self) -> &str {
        match self {
            AuditEntry::BatchStart { hash, .. }
            | AuditEntry::HostResult { hash, .. }
            | AuditEntry::TofuAccept { hash, .. }
            | AuditEntry::TofuReject { hash, .. }
            | AuditEntry::BatchEnd { hash, .. }
            | AuditEntry::BatchCancelled { hash, .. }
            | AuditEntry::SegmentEnd { hash, .. } => hash,
        }
    }
}

/// 같은 day segment에 audit를 append. 마지막 hash를 in-memory 캐시해 chain을 잇는다.
pub struct BatchAppender {
    pub audit_dir: PathBuf,
    pub batch_id: String,
    last_hash: String,
}

impl BatchAppender {
    /// `~/.aic/audit/` 디렉토리 + 오늘 segment 파일을 준비. 기존 segment의 마지막 hash를 로드.
    pub fn open(audit_dir: PathBuf, batch_id: String) -> Result<Self> {
        std::fs::create_dir_all(&audit_dir)
            .with_context(|| format!("create {}", audit_dir.display()))?;
        let path = today_segment_path(&audit_dir);
        let last_hash = read_last_hash(&path)?;
        Ok(Self {
            audit_dir,
            batch_id,
            last_hash,
        })
    }

    fn append_with_chain(&mut self, build: impl FnOnce(&str) -> AuditEntry) -> Result<()> {
        let entry = build(&self.last_hash);
        let path = today_segment_path(&self.audit_dir);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let line = serde_json::to_string(&entry).context("serialize audit entry")?;
        writeln!(f, "{line}").context("write audit line")?;
        self.last_hash = entry.hash().to_string();
        Ok(())
    }

    pub fn batch_start(&mut self, kind: &str, group: &str, hosts: &[String]) -> Result<()> {
        let batch_id = self.batch_id.clone();
        let kind = kind.to_string();
        let group = group.to_string();
        let hosts_clone = hosts.to_vec();
        self.append_with_chain(move |prev| {
            let ts = Utc::now();
            let payload_hash = entry_hash(
                prev,
                &serde_json::json!({
                    "type": "batch_start",
                    "ts": ts,
                    "batch_id": batch_id,
                    "kind": kind,
                    "group": group,
                    "hosts": hosts_clone,
                }),
            );
            AuditEntry::BatchStart {
                ts,
                batch_id,
                kind,
                group,
                hosts: hosts_clone,
                prev_hash: prev.to_string(),
                hash: payload_hash,
            }
        })
    }

    #[allow(clippy::too_many_arguments)] // host_result 필드가 본래 많은 RemoteResult를 평탄화한다.
    pub fn host_result(
        &mut self,
        host: &str,
        status: &str,
        cmd: &str,
        duration_ms: u64,
        exit_code: i32,
        truncated: bool,
        redacted: usize,
    ) -> Result<()> {
        let batch_id = self.batch_id.clone();
        let host = host.to_string();
        let status = status.to_string();
        let cmd = cmd.to_string();
        self.append_with_chain(move |prev| {
            let ts = Utc::now();
            let payload_hash = entry_hash(
                prev,
                &serde_json::json!({
                    "type": "host_result",
                    "ts": ts,
                    "batch_id": batch_id,
                    "host": host,
                    "status": status,
                    "cmd": cmd,
                    "duration_ms": duration_ms,
                    "exit_code": exit_code,
                    "truncated": truncated,
                    "redacted": redacted,
                }),
            );
            AuditEntry::HostResult {
                ts,
                batch_id,
                host,
                status,
                cmd,
                duration_ms,
                exit_code,
                truncated,
                redacted,
                prev_hash: prev.to_string(),
                hash: payload_hash,
            }
        })
    }

    pub fn tofu_accept(&mut self, host: &str, fingerprint: &str) -> Result<()> {
        let batch_id = self.batch_id.clone();
        let host = host.to_string();
        let fingerprint = fingerprint.to_string();
        self.append_with_chain(move |prev| {
            let ts = Utc::now();
            let payload_hash = entry_hash(
                prev,
                &serde_json::json!({
                    "type": "tofu_accept",
                    "ts": ts,
                    "batch_id": batch_id,
                    "host": host,
                    "fingerprint": fingerprint,
                }),
            );
            AuditEntry::TofuAccept {
                ts,
                batch_id,
                host,
                fingerprint,
                prev_hash: prev.to_string(),
                hash: payload_hash,
            }
        })
    }

    pub fn tofu_reject(&mut self, host: &str, fingerprint: &str, reason: &str) -> Result<()> {
        let batch_id = self.batch_id.clone();
        let host = host.to_string();
        let fingerprint = fingerprint.to_string();
        let reason = reason.to_string();
        self.append_with_chain(move |prev| {
            let ts = Utc::now();
            let payload_hash = entry_hash(
                prev,
                &serde_json::json!({
                    "type": "tofu_reject",
                    "ts": ts,
                    "batch_id": batch_id,
                    "host": host,
                    "fingerprint": fingerprint,
                    "reason": reason,
                }),
            );
            AuditEntry::TofuReject {
                ts,
                batch_id,
                host,
                fingerprint,
                reason,
                prev_hash: prev.to_string(),
                hash: payload_hash,
            }
        })
    }

    pub fn batch_end(&mut self, stats: BatchStats) -> Result<()> {
        let batch_id = self.batch_id.clone();
        self.append_with_chain(move |prev| {
            let ts = Utc::now();
            let payload_hash = entry_hash(
                prev,
                &serde_json::json!({
                    "type": "batch_end",
                    "ts": ts,
                    "batch_id": batch_id,
                    "stats": stats,
                }),
            );
            AuditEntry::BatchEnd {
                ts,
                batch_id,
                stats,
                prev_hash: prev.to_string(),
                hash: payload_hash,
            }
        })
    }

    pub fn batch_cancelled(&mut self, completed: usize, incomplete: Vec<String>) -> Result<()> {
        let batch_id = self.batch_id.clone();
        self.append_with_chain(move |prev| {
            let ts = Utc::now();
            let payload_hash = entry_hash(
                prev,
                &serde_json::json!({
                    "type": "batch_cancelled",
                    "ts": ts,
                    "batch_id": batch_id,
                    "completed": completed,
                    "incomplete": incomplete,
                }),
            );
            AuditEntry::BatchCancelled {
                ts,
                batch_id,
                completed,
                incomplete,
                prev_hash: prev.to_string(),
                hash: payload_hash,
            }
        })
    }
}

fn today_segment_path(dir: &Path) -> PathBuf {
    let date = Utc::now().format("%Y-%m-%d").to_string();
    dir.join(format!("{date}.jsonl"))
}

/// segment 파일의 마지막 엔트리 hash를 읽는다. 파일이 없으면 빈 문자열(genesis).
fn read_last_hash(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let Some(last_line) = body.lines().rfind(|l| !l.trim().is_empty()) else {
        return Ok(String::new());
    };
    let entry: AuditEntry = serde_json::from_str(last_line)
        .with_context(|| format!("parse last entry of {}", path.display()))?;
    Ok(entry.hash().to_string())
}

/// SHA256(prev_hash || canonical_json(payload)) — payload는 hash/prev_hash 필드 미포함.
fn entry_hash(prev_hash: &str, payload: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\n");
    // serde_json::to_string은 key 순서가 결정적이지 않을 수 있어서, sort_keys로 정렬.
    let canon = canonicalize_json(payload);
    hasher.update(canon.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// 결정적 JSON 직렬화 — object key는 알파벳 순.
fn canonicalize_json(v: &serde_json::Value) -> String {
    fn write(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Null => out.push_str("null"),
            serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            serde_json::Value::Number(n) => out.push_str(&n.to_string()),
            serde_json::Value::String(s) => {
                out.push_str(&serde_json::to_string(s).unwrap_or_default());
            }
            serde_json::Value::Array(arr) => {
                out.push('[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap_or_default());
                    out.push(':');
                    write(&map[*k], out);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ── Verify ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub segment: PathBuf,
    pub entries: usize,
    pub valid: bool,
    pub broken_at: Option<usize>,
    pub last_hash: String,
}

/// segment 파일의 hash chain을 재계산해 무결성을 검증한다.
pub fn verify_segment(path: &Path) -> Result<VerifyReport> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut prev = String::new();
    let mut count = 0;
    for (i, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
        let entry: AuditEntry = serde_json::from_str(line)
            .with_context(|| format!("parse line {} of {}", i + 1, path.display()))?;
        if entry.prev_hash() != prev {
            return Ok(VerifyReport {
                segment: path.to_path_buf(),
                entries: count,
                valid: false,
                broken_at: Some(i + 1),
                last_hash: prev,
            });
        }
        // 재계산: payload(=entry without hash/prev_hash)를 추출해 hash 재계산.
        let expected = recompute_hash(&entry, entry.prev_hash())?;
        if expected != entry.hash() {
            return Ok(VerifyReport {
                segment: path.to_path_buf(),
                entries: count,
                valid: false,
                broken_at: Some(i + 1),
                last_hash: prev,
            });
        }
        prev = entry.hash().to_string();
    }
    Ok(VerifyReport {
        segment: path.to_path_buf(),
        entries: count,
        valid: true,
        broken_at: None,
        last_hash: prev,
    })
}

fn recompute_hash(entry: &AuditEntry, prev_hash: &str) -> Result<String> {
    // serialize 후 hash/prev_hash 필드 제거.
    let v = serde_json::to_value(entry).context("serialize for verify")?;
    let serde_json::Value::Object(mut map) = v else {
        return Err(anyhow!("audit entry must be object"));
    };
    map.remove("hash");
    map.remove("prev_hash");
    let payload = serde_json::Value::Object(map);
    Ok(entry_hash(prev_hash, &payload))
}

/// audit 디렉토리의 모든 segment를 찾아 반환(YYYY-MM-DD.jsonl 패턴).
pub fn list_segments(audit_dir: &Path) -> Result<Vec<PathBuf>> {
    if !audit_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(audit_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

// ── 테스트 ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn appender_writes_chained_entries() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let mut a = BatchAppender::open(audit_dir.clone(), "01J-test".into()).unwrap();
        a.batch_start("diagnose", "@web-tier", &["web-01".into(), "web-02".into()])
            .unwrap();
        a.host_result("web-01", "ok", "uptime", 412, 0, false, 0)
            .unwrap();
        a.host_result("web-02", "unreachable", "uptime", 10_000, 255, false, 0)
            .unwrap();
        a.batch_end(BatchStats {
            ok: 1,
            unreachable: 1,
            ..Default::default()
        })
        .unwrap();

        let path = today_segment_path(&audit_dir);
        let report = verify_segment(&path).unwrap();
        assert!(report.valid, "chain should be valid: {report:?}");
        assert_eq!(report.entries, 4);
    }

    #[test]
    fn tampering_breaks_chain() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let mut a = BatchAppender::open(audit_dir.clone(), "01J-tamper".into()).unwrap();
        a.batch_start("diagnose", "@web", &["h1".into()]).unwrap();
        a.host_result("h1", "ok", "uptime", 100, 0, false, 0).unwrap();
        a.batch_end(BatchStats { ok: 1, ..Default::default() }).unwrap();

        // 파일을 손으로 변조: 가운데 host_result line의 host를 'h1' → 'evil'로.
        let path = today_segment_path(&audit_dir);
        let body = std::fs::read_to_string(&path).unwrap();
        let tampered = body.replace(r#""host":"h1""#, r#""host":"evil""#);
        std::fs::write(&path, tampered).unwrap();

        let report = verify_segment(&path).unwrap();
        assert!(!report.valid, "tampered chain must fail verify");
        assert!(report.broken_at.is_some());
    }

    #[test]
    fn chain_continues_across_appender_open() {
        // 같은 segment에 다른 batch_id로 두 번 열어도 chain은 이어진다.
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let mut a = BatchAppender::open(audit_dir.clone(), "batch-1".into()).unwrap();
        a.batch_start("diagnose", "@a", &["h1".into()]).unwrap();
        a.batch_end(BatchStats::default()).unwrap();

        // 새 BatchAppender — 마지막 hash 자동 로드.
        let mut b = BatchAppender::open(audit_dir.clone(), "batch-2".into()).unwrap();
        b.batch_start("diagnose", "@b", &["h2".into()]).unwrap();
        b.batch_end(BatchStats::default()).unwrap();

        let report = verify_segment(&today_segment_path(&audit_dir)).unwrap();
        assert!(report.valid);
        assert_eq!(report.entries, 4);
    }

    #[test]
    fn tofu_accept_and_reject_entries() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let mut a = BatchAppender::open(audit_dir.clone(), "tofu-test".into()).unwrap();
        a.tofu_accept("web-01", "SHA256:abc...").unwrap();
        a.tofu_reject("web-02", "SHA256:xyz...", "user_declined")
            .unwrap();
        let report = verify_segment(&today_segment_path(&audit_dir)).unwrap();
        assert!(report.valid);
        assert_eq!(report.entries, 2);
    }

    #[test]
    fn batch_cancelled_records_incomplete_hosts() {
        let dir = tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let mut a = BatchAppender::open(audit_dir.clone(), "cancel-test".into()).unwrap();
        a.batch_start("diagnose", "@all", &["h1".into(), "h2".into(), "h3".into()])
            .unwrap();
        a.host_result("h1", "ok", "uptime", 100, 0, false, 0).unwrap();
        a.batch_cancelled(1, vec!["h2".into(), "h3".into()]).unwrap();
        let report = verify_segment(&today_segment_path(&audit_dir)).unwrap();
        assert!(report.valid);
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let canon = canonicalize_json(&v);
        assert_eq!(canon, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn list_segments_returns_sorted_jsonl_files() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.path().join("2026-05-25.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("2026-05-24.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("README.md"), "").unwrap();
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 2);
        assert!(segs[0].file_name().unwrap().to_str().unwrap().contains("2026-05-24"));
    }
}
