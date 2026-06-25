//! Lightweight read-only registry for live `aic chat` agent sessions.
//!
//! `aicd`의 `SessionInfo` registry는 shell hook / aic-session 계층을 나타낸다. `aic chat`
//! 자체의 `AgentSession`은 별도 run_id만 가지므로 web 관측 화면이 볼 수 있는 작은 heartbeat
//! 파일을 남긴다. 실행 권한이나 대화 전문은 저장하지 않고, 세션 식별/상태/마지막 입력 preview만 저장한다.

use std::fs;
use std::io;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const CHAT_RUN_DIR: &str = "chat-runs";
const PREVIEW_LIMIT: usize = 180;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRunRecord {
    pub run_id: String,
    pub pid: u32,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub cwd: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub allow_run_command: bool,
    pub llm_available: bool,
    pub turn_count: u64,
    pub last_input: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChatRunStart {
    pub run_id: String,
    pub cwd: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub allow_run_command: bool,
    pub llm_available: bool,
}

pub fn start(meta: ChatRunStart) -> io::Result<()> {
    let now = Utc::now();
    write_record(&ChatRunRecord {
        run_id: safe_run_id(&meta.run_id),
        pid: std::process::id(),
        status: "active".to_string(),
        started_at: now,
        updated_at: now,
        ended_at: None,
        cwd: meta.cwd,
        provider: meta.provider,
        model: meta.model,
        allow_run_command: meta.allow_run_command,
        llm_available: meta.llm_available,
        turn_count: 0,
        last_input: None,
    })
}

pub fn touch_input(run_id: &str, input: &str) -> io::Result<()> {
    let safe = safe_run_id(run_id);
    let mut rec = read_record(&safe)?.unwrap_or_else(|| {
        let now = Utc::now();
        ChatRunRecord {
            run_id: safe.clone(),
            pid: std::process::id(),
            status: "active".to_string(),
            started_at: now,
            updated_at: now,
            ended_at: None,
            cwd: None,
            provider: None,
            model: None,
            allow_run_command: false,
            llm_available: false,
            turn_count: 0,
            last_input: None,
        }
    });
    rec.status = "active".to_string();
    rec.updated_at = Utc::now();
    rec.turn_count = rec.turn_count.saturating_add(1);
    rec.last_input = Some(truncate_preview(input));
    write_record(&rec)
}

pub fn finish(run_id: &str) -> io::Result<()> {
    let safe = safe_run_id(run_id);
    let Some(mut rec) = read_record(&safe)? else {
        return Ok(());
    };
    let now = Utc::now();
    rec.status = "ended".to_string();
    rec.updated_at = now;
    rec.ended_at = Some(now);
    write_record(&rec)
}

pub fn list_recent(limit: usize) -> io::Result<Vec<ChatRunRecord>> {
    let dir = registry_dir();
    let mut out = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = fs::read(entry.path()) {
            if let Ok(rec) = serde_json::from_slice::<ChatRunRecord>(&bytes) {
                out.push(rec);
            }
        }
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    out.truncate(limit);
    Ok(out)
}

fn write_record(rec: &ChatRunRecord) -> io::Result<()> {
    let dir = registry_dir();
    fs::create_dir_all(&dir)?;
    let path = record_path(&rec.run_id);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(rec).map_err(io::Error::other)?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

fn read_record(run_id: &str) -> io::Result<Option<ChatRunRecord>> {
    let path = record_path(run_id);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn record_path(run_id: &str) -> PathBuf {
    registry_dir().join(format!("{}.json", safe_run_id(run_id)))
}

fn registry_dir() -> PathBuf {
    aic_common::paths::state_dir().join(CHAT_RUN_DIR)
}

fn safe_run_id(value: &str) -> String {
    let safe: String = value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    if safe.is_empty() {
        "unknown".to_string()
    } else {
        safe
    }
}

fn truncate_preview(value: &str) -> String {
    let redacted = crate::redaction::redact(value).0.replace('\n', " ");
    if redacted.chars().count() <= PREVIEW_LIMIT {
        return redacted;
    }
    let mut out: String = redacted
        .chars()
        .take(PREVIEW_LIMIT.saturating_sub(1))
        .collect();
    out.push('…');
    out
}
