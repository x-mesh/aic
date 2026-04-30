use aic_common::{CaptureMode, CaptureQuality, CommandRecord, OutputMetadata};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingHookRecord {
    session_id: String,
    command_id: String,
    command: String,
    cwd: Option<PathBuf>,
    shell: Option<String>,
    pid: u32,
    started_at: chrono::DateTime<chrono::Utc>,
}

pub fn load_last() -> Option<CommandRecord> {
    let content = std::fs::read_to_string(aic_common::local_command_record_path()).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn save_last(record: &CommandRecord) -> anyhow::Result<()> {
    let path = aic_common::local_command_record_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(record)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

pub fn save_hook_start(
    session_id: String,
    command_id: String,
    command: String,
    cwd: Option<PathBuf>,
    shell: Option<String>,
    pid: u32,
    started_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    let pending = PendingHookRecord {
        session_id: session_id.clone(),
        command_id: command_id.clone(),
        command,
        cwd,
        shell,
        pid,
        started_at,
    };
    let path = aic_common::local_hook_pending_path(&session_id, &command_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec(&pending)?)?;
    Ok(())
}

pub fn finish_hook(
    session_id: &str,
    command_id: &str,
    exit_code: i32,
    finished_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Option<CommandRecord>> {
    let path = aic_common::local_hook_pending_path(session_id, command_id);
    let pending = match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str::<PendingHookRecord>(&content)?,
        Err(_) => return Ok(None),
    };
    let _ = std::fs::remove_file(&path);

    let record = CommandRecord {
        id: aic_common::generate_record_id(),
        command: Some(pending.command),
        exit_code,
        output_lines: Vec::new(),
        timestamp: finished_at,
        capture_mode: CaptureMode::Hook,
        capture_quality: CaptureQuality::MetadataOnly,
        output_metadata: Some(OutputMetadata {
            original_bytes: Some(0),
            stored_bytes: 0,
            stored_lines: 0,
            truncated: false,
            binary: false,
            sha256: None,
        }),
    };
    save_last(&record)?;
    Ok(Some(record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_missing_hook_returns_none() {
        let result = finish_hook("missing", "missing", 1, chrono::Utc::now()).unwrap();
        assert!(result.is_none());
    }
}
