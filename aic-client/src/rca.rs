//! Persistent RCA incident workspace.
//!
//! The workspace is intentionally file-based and append-friendly:
//! `~/.aic/incidents/<id>/meta.json` stores incident metadata and
//! `evidence.jsonl` stores timestamped evidence events. This keeps P0 usable
//! from headless CLI/webhook flows without introducing a database.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const INDEX_FILE: &str = "index.json";
const META_FILE: &str = "meta.json";
const EVIDENCE_FILE: &str = "evidence.jsonl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentMeta {
    pub id: String,
    pub title: String,
    pub status: IncidentStatus,
    pub symptom: Option<String>,
    pub cwd: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Mitigated,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEvent {
    pub id: String,
    pub at: DateTime<Utc>,
    pub kind: EvidenceKind,
    pub title: String,
    pub source: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Lifecycle,
    Diagnosis,
    Timeline,
    Analysis,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub id: String,
    pub title: String,
    pub status: IncidentStatus,
    pub symptom: Option<String>,
    pub cwd: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub evidence_count: usize,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct Index {
    #[serde(default)]
    incidents: Vec<String>,
}

pub fn incidents_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".aic").join("incidents")
}

pub fn incident_dir(id: &str) -> PathBuf {
    incidents_dir().join(id)
}

pub fn create_incident(
    title: &str,
    symptom: Option<&str>,
    cwd: Option<&Path>,
) -> anyhow::Result<IncidentMeta> {
    let now = Utc::now();
    let id = make_incident_id(title, now);
    let dir = incident_dir(&id);
    fs::create_dir_all(&dir)?;
    secure_dir(&dir);

    let mut meta = IncidentMeta {
        id,
        title: title.trim().to_string(),
        status: IncidentStatus::Open,
        symptom: symptom
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        cwd: cwd.map(|p| p.display().to_string()),
        created_at: now,
        updated_at: now,
        evidence_count: 0,
    };
    save_meta(&meta)?;

    let lifecycle_body = format!(
        "title: {}\nsymptom: {}\ncwd: {}",
        meta.title,
        meta.symptom.as_deref().unwrap_or("(none)"),
        meta.cwd.as_deref().unwrap_or("(unknown)")
    );
    append_evidence(
        &mut meta,
        EvidenceKind::Lifecycle,
        "incident opened",
        "aic rca start",
        &lifecycle_body,
        &["lifecycle"],
    )?;

    update_index(&meta.id)?;
    Ok(meta)
}

pub fn append_evidence(
    meta: &mut IncidentMeta,
    kind: EvidenceKind,
    title: &str,
    source: &str,
    body: &str,
    tags: &[&str],
) -> anyhow::Result<EvidenceEvent> {
    let id = format!("E{}", meta.evidence_count + 1);
    let event = EvidenceEvent {
        id,
        at: Utc::now(),
        kind,
        title: title.trim().to_string(),
        source: source.trim().to_string(),
        body: crate::redaction::redact(body).0,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    };

    let dir = incident_dir(&meta.id);
    fs::create_dir_all(&dir)?;
    secure_dir(&dir);
    let path = dir.join(EVIDENCE_FILE);
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let line = serde_json::to_string(&event)?;
    writeln!(f, "{line}")?;
    secure_file(&path);

    meta.evidence_count += 1;
    meta.updated_at = event.at;
    save_meta(meta)?;
    Ok(event)
}

pub fn load_meta(id: &str) -> anyhow::Result<IncidentMeta> {
    let path = incident_dir(id).join(META_FILE);
    let s = fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("RCA incident를 찾을 수 없습니다: {id} ({e})"))?;
    Ok(serde_json::from_str(&s)?)
}

pub fn load_events(id: &str) -> anyhow::Result<Vec<EvidenceEvent>> {
    let path = incident_dir(id).join(EVIDENCE_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        out.push(serde_json::from_str(line)?);
    }
    out.sort_by_key(|e: &EvidenceEvent| e.at);
    Ok(out)
}

pub fn list_incidents() -> anyhow::Result<Vec<IncidentSummary>> {
    let mut ids = load_index()?.incidents;
    ids.retain(|id| incident_dir(id).join(META_FILE).exists());
    let mut out = Vec::new();
    for id in ids {
        if let Ok(meta) = load_meta(&id) {
            out.push(summary(meta));
        }
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
    Ok(out)
}

pub fn latest_incident_id() -> anyhow::Result<Option<String>> {
    Ok(list_incidents()?.into_iter().next().map(|i| i.id))
}

pub fn resolve_id(id: Option<&str>) -> anyhow::Result<String> {
    if let Some(id) = id {
        let matches: Vec<_> = list_incidents()?
            .into_iter()
            .filter(|i| i.id == id || i.id.starts_with(id))
            .collect();
        return match matches.as_slice() {
            [one] => Ok(one.id.clone()),
            [] => Err(anyhow::anyhow!("RCA incident를 찾을 수 없습니다: {id}")),
            _ => Err(anyhow::anyhow!("RCA incident prefix가 모호합니다: {id}")),
        };
    }
    latest_incident_id()?.ok_or_else(|| {
        anyhow::anyhow!("RCA incident가 없습니다. 먼저 `aic rca start`를 실행하세요.")
    })
}

pub fn render_status(meta: &IncidentMeta) -> String {
    format!(
        "RCA {}\n상태: {:?}\n제목: {}\n증상: {}\n생성: {}\n갱신: {}\n증거: {}개\n경로: {}",
        meta.id,
        meta.status,
        meta.title,
        meta.symptom.as_deref().unwrap_or("(none)"),
        meta.created_at.to_rfc3339(),
        meta.updated_at.to_rfc3339(),
        meta.evidence_count,
        incident_dir(&meta.id).display()
    )
}

pub fn render_timeline(meta: &IncidentMeta, events: &[EvidenceEvent]) -> String {
    let mut lines = vec![format!("# RCA timeline: {}", meta.title)];
    if events.is_empty() {
        lines.push("(evidence 없음)".to_string());
        return lines.join("\n");
    }
    for ev in events {
        lines.push(format!(
            "- {} [{}] {:?}: {} ({})",
            ev.at.to_rfc3339(),
            ev.id,
            ev.kind,
            ev.title,
            ev.source
        ));
    }
    lines.join("\n")
}

pub fn render_report(meta: &IncidentMeta, events: &[EvidenceEvent]) -> String {
    let mut md = String::new();
    md.push_str(&format!("# RCA Report: {}\n\n", meta.title));
    md.push_str("## Summary\n\n");
    md.push_str(&format!(
        "- Incident ID: `{}`\n- Status: `{:?}`\n- Symptom: {}\n- Created: {}\n- Updated: {}\n\n",
        meta.id,
        meta.status,
        meta.symptom.as_deref().unwrap_or("(none)"),
        meta.created_at.to_rfc3339(),
        meta.updated_at.to_rfc3339()
    ));

    md.push_str("## Timeline\n\n");
    for ev in events {
        md.push_str(&format!(
            "- {} [{}] {} — {}\n",
            ev.at.to_rfc3339(),
            ev.id,
            ev.title,
            ev.source
        ));
    }
    if events.is_empty() {
        md.push_str("- (no evidence)\n");
    }

    md.push_str("\n## Findings\n\n");
    let analyses: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.kind, EvidenceKind::Analysis | EvidenceKind::Diagnosis))
        .collect();
    if analyses.is_empty() {
        md.push_str("- 아직 분석 evidence가 없습니다. `aic rca start --diagnose ...`로 초동 증거를 붙이세요.\n");
    } else {
        for ev in analyses {
            md.push_str(&format!(
                "- [{}] {}\n",
                ev.id,
                first_nonempty_line(&ev.body)
            ));
        }
    }

    md.push_str("\n## Evidence Appendix\n\n");
    for ev in events {
        md.push_str(&format!(
            "### [{}] {} ({:?})\n\nsource: `{}`\n\n```text\n{}\n```\n\n",
            ev.id, ev.title, ev.kind, ev.source, ev.body
        ));
    }
    md
}

pub fn write_report(meta: &IncidentMeta, report: &str) -> anyhow::Result<PathBuf> {
    let path = incident_dir(&meta.id).join("report.md");
    fs::write(&path, report)?;
    secure_file(&path);
    Ok(path)
}

fn summary(meta: IncidentMeta) -> IncidentSummary {
    IncidentSummary {
        path: incident_dir(&meta.id),
        id: meta.id,
        title: meta.title,
        status: meta.status,
        symptom: meta.symptom,
        cwd: meta.cwd,
        created_at: meta.created_at,
        updated_at: meta.updated_at,
        evidence_count: meta.evidence_count,
    }
}

fn save_meta(meta: &IncidentMeta) -> anyhow::Result<()> {
    let path = incident_dir(&meta.id).join(META_FILE);
    let json = serde_json::to_string_pretty(meta)?;
    fs::write(&path, json)?;
    secure_file(&path);
    Ok(())
}

fn load_index() -> anyhow::Result<Index> {
    let path = incidents_dir().join(INDEX_FILE);
    match fs::read_to_string(&path) {
        Ok(s) => Ok(serde_json::from_str(&s).unwrap_or_default()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Index::default()),
        Err(e) => Err(e.into()),
    }
}

fn update_index(id: &str) -> anyhow::Result<()> {
    let dir = incidents_dir();
    fs::create_dir_all(&dir)?;
    secure_dir(&dir);
    let mut index = load_index()?;
    index.incidents.retain(|existing| existing != id);
    index.incidents.insert(0, id.to_string());
    let path = dir.join(INDEX_FILE);
    fs::write(&path, serde_json::to_string_pretty(&index)?)?;
    secure_file(&path);
    Ok(())
}

fn make_incident_id(title: &str, at: DateTime<Utc>) -> String {
    let slug = slugify(title);
    format!("{}-{slug}", at.format("%Y%m%d-%H%M%S"))
}

fn slugify(title: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in title.chars().flat_map(|c| c.to_lowercase()) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
        if out.len() >= 48 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "incident".to_string()
    } else {
        out
    }
}

fn first_nonempty_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("(empty analysis)")
        .chars()
        .take(180)
        .collect()
}

fn secure_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

fn secure_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use tempfile::TempDir;

    struct HomeGuard {
        prev: Option<std::ffi::OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    impl HomeGuard {
        fn set(path: &Path) -> Self {
            static HOME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = HOME_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let prev = std::env::var_os("HOME");
            unsafe {
                std::env::set_var("HOME", path);
            }
            Self { prev, _lock: lock }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    #[test]
    fn create_append_and_render_report() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let mut meta = create_incident(
            "API Latency!",
            Some("p99 high"),
            Some(Path::new("/srv/api")),
        )
        .unwrap();
        assert!(meta.id.ends_with("api-latency"));
        assert_eq!(meta.evidence_count, 1);

        append_evidence(
            &mut meta,
            EvidenceKind::Diagnosis,
            "initial diagnosis",
            "test",
            "## analysis\nroot cause likely deploy",
            &["diagnosis"],
        )
        .unwrap();

        let loaded = load_meta(&meta.id).unwrap();
        assert_eq!(loaded.evidence_count, 2);
        let events = load_events(&meta.id).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].id, "E2");

        let report = render_report(&loaded, &events);
        assert!(report.contains("[E2]"));
        assert!(report.contains("Evidence Appendix"));
    }

    #[test]
    fn resolve_latest_and_prefix() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let meta = create_incident("disk full", None, None).unwrap();
        assert_eq!(resolve_id(None).unwrap(), meta.id);
        let prefix = &meta.id[..8];
        assert_eq!(resolve_id(Some(prefix)).unwrap(), meta.id);
    }
}
