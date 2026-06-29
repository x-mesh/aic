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
    /// 최초 Mitigated 전이 시각(TTM = mitigated_at − created_at). 미전이면 None.
    /// `#[serde(default)]`로 이 필드가 없는 기존 meta.json도 호환 로드된다.
    #[serde(default)]
    pub mitigated_at: Option<DateTime<Utc>>,
    /// Closed 전이 시각(MTTR = closed_at − created_at). reopen 시 None으로 되돌린다.
    #[serde(default)]
    pub closed_at: Option<DateTime<Utc>>,
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
    /// incident 시간창으로 질의한 관측 백엔드(Prometheus/Loki) 결과 — probe 증거를 메트릭/로그로 뒷받침한다.
    Observability,
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
    // 저장 전에 redaction — title/symptom/cwd의 secret이 디렉터리 이름(slug)·meta·report로 새지 않게 한다.
    let title = crate::redaction::redact(title.trim()).0;
    let symptom = symptom
        .map(|s| crate::redaction::redact(s.trim()).0)
        .filter(|s| !s.is_empty());
    let cwd = cwd.map(|p| crate::redaction::redact(&p.display().to_string()).0);

    // 동초·동제목 충돌과 두 프로세스 동시 생성의 TOCTOU를 mkdir 기반으로 원자 확보(조용한 덮어쓰기 방지).
    let base = make_incident_id(&title, now);
    let (id, dir) = claim_incident_dir(&base)?;
    secure_dir(&dir);

    let mut meta = IncidentMeta {
        id,
        title,
        status: IncidentStatus::Open,
        symptom,
        cwd,
        created_at: now,
        updated_at: now,
        evidence_count: 0,
        mitigated_at: None,
        closed_at: None,
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
    let dir = incident_dir(&meta.id);
    fs::create_dir_all(&dir)?;
    secure_dir(&dir);

    // 동시 append를 직렬화한다(cross-process). 락 안에서 파일의 실제 줄 수로 E-id/count를 산출해
    // stale meta.evidence_count로 인한 중복 E-id·count 드리프트(lost-update)를 막는다.
    let _lock = IncidentLock::acquire(&dir)?;
    let path = dir.join(EVIDENCE_FILE);
    let seq = count_evidence_lines(&path) + 1;

    // title/source/body 모두 저장 시점에 redaction한다 — web 재-redaction 밖의 소비자(직접 파일 읽기,
    // bundle, report)에서도 secret이 새지 않게 한다.
    let event = EvidenceEvent {
        id: format!("E{seq}"),
        at: Utc::now(),
        kind,
        title: crate::redaction::redact(title.trim()).0,
        source: crate::redaction::redact(source.trim()).0,
        body: crate::redaction::redact(body).0,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    };

    // content+개행을 한 번의 write_all로 — writeln!의 분할 쓰기가 동시 append 시 interleave 되는 것을
    // 피한다(O_APPEND + flock로 한 줄이 원자적으로 EOF에 붙는다). sync_all로 내구성 확보.
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let mut line = serde_json::to_string(&event)?;
    line.push('\n');
    f.write_all(line.as_bytes())?;
    f.sync_all()?;
    secure_file(&path);

    meta.evidence_count = seq;
    meta.updated_at = event.at;
    save_meta(meta)?;
    Ok(event)
}

/// incident 상태를 전이하고 그 사실을 lifecycle evidence로 timeline에 남긴다. Mitigated/Closed 전이 시각을
/// 기록해 MTTR(Closed−created)·TTM(Mitigated−created)을 도출 가능하게 한다. Closed는 Mitigated를 함의하고
/// (mitigated_at 미설정 시 함께 채움), Open으로의 재개방(reopen)은 closed_at을 해제한다. 임의 전이를 막지
/// 않되 모든 전이를 evidence로 남겨 상태 히스토리를 보존한다. append_evidence가 atomic save까지 수행한다.
pub fn set_status(meta: &mut IncidentMeta, new: IncidentStatus) -> anyhow::Result<EvidenceEvent> {
    let now = Utc::now();
    let prev = meta.status;
    match new {
        IncidentStatus::Mitigated => {
            if meta.mitigated_at.is_none() {
                meta.mitigated_at = Some(now);
            }
        }
        IncidentStatus::Closed => {
            if meta.mitigated_at.is_none() {
                meta.mitigated_at = Some(now); // closed implies mitigated
            }
            meta.closed_at = Some(now);
        }
        IncidentStatus::Open => {
            meta.closed_at = None; // reopen
        }
    }
    meta.status = new;
    let body = format!("status: {prev:?} -> {new:?}");
    append_evidence(
        meta,
        EvidenceKind::Lifecycle,
        &format!("status -> {new:?}"),
        "aic rca status",
        &body,
        &["lifecycle", "transition"],
    )
}

pub fn load_meta(id: &str) -> anyhow::Result<IncidentMeta> {
    if !is_safe_id(id) {
        anyhow::bail!("RCA incident id가 유효하지 않습니다: {id}");
    }
    let path = incident_dir(id).join(META_FILE);
    let s = fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("RCA incident를 찾을 수 없습니다: {id} ({e})"))?;
    Ok(serde_json::from_str(&s)?)
}

/// evidence를 시간순(보조키 E-id)으로 로드한다. 손상된 한 줄이 incident 전체(status/timeline/report/web)를
/// 죽이지 않도록, 파싱 실패한 줄은 **건너뛰고** 카운트만 stderr로 알린다(부분 손상 graceful).
pub fn load_events(id: &str) -> anyhow::Result<Vec<EvidenceEvent>> {
    if !is_safe_id(id) {
        anyhow::bail!("RCA incident id가 유효하지 않습니다: {id}");
    }
    let path = incident_dir(id).join(EVIDENCE_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<EvidenceEvent>(line) {
            Ok(ev) => out.push(ev),
            Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        eprintln!("rca: incident {id}: evidence.jsonl에서 손상된 {skipped}줄을 건너뜀");
    }
    // timestamp 1차, E-id 시퀀스 2차 — 동일 시각/NTP 역보정 시에도 삽입 순서로 안정 정렬.
    out.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then_with(|| evidence_seq(&a.id).cmp(&evidence_seq(&b.id)))
    });
    Ok(out)
}

/// **디렉터리 스캔을 권위로** incident를 나열한다(index.json은 캐시일 뿐 신뢰하지 않는다). corrupt/누락
/// index가 incident를 통째로 숨기거나, index에만 있는 유령 엔트리가 끼는 정합성 문제를 제거한다.
/// `meta.json`이 있는 모든 하위 디렉터리를 incident로 인식하고, updated_at 내림차순으로 정렬한다.
pub fn list_incidents() -> anyhow::Result<Vec<IncidentSummary>> {
    let dir = incidents_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || !path.join(META_FILE).exists() {
            continue;
        }
        let Some(id) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Ok(meta) = load_meta(id) {
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
    let mut s = format!(
        "RCA {}\n상태: {:?}\n제목: {}\n증상: {}\n생성: {}\n갱신: {}\n증거: {}개\n경로: {}",
        meta.id,
        meta.status,
        meta.title,
        meta.symptom.as_deref().unwrap_or("(none)"),
        meta.created_at.to_rfc3339(),
        meta.updated_at.to_rfc3339(),
        meta.evidence_count,
        incident_dir(&meta.id).display()
    );
    if let Some(m) = meta.mitigated_at {
        s.push_str(&format!(
            "\n완화까지(TTM): {}",
            humanize_duration(m - meta.created_at)
        ));
    }
    if let Some(c) = meta.closed_at {
        s.push_str(&format!(
            "\nMTTR: {}",
            humanize_duration(c - meta.created_at)
        ));
    }
    s
}

/// 사람이 읽는 기간 포맷(MTTR/TTM 표시). 음수(시계 역전)는 0으로 클램프.
fn humanize_duration(d: chrono::Duration) -> String {
    let secs = d.num_seconds().max(0);
    let (days, hours, mins, s) = (
        secs / 86400,
        (secs % 86400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
    );
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
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

    // Resolution & Postmortem — 완화/종료된 incident에만 MTTR/TTM을 싣는다(미해결 incident엔 노이즈 안 됨).
    if meta.mitigated_at.is_some() || meta.closed_at.is_some() {
        md.push_str("## Resolution\n\n");
        if let Some(m) = meta.mitigated_at {
            md.push_str(&format!(
                "- Time to mitigate (TTM): {} (opened {} → mitigated {})\n",
                humanize_duration(m - meta.created_at),
                meta.created_at.to_rfc3339(),
                m.to_rfc3339()
            ));
        }
        if let Some(c) = meta.closed_at {
            md.push_str(&format!(
                "- MTTR (time to resolve): {} (opened {} → closed {})\n",
                humanize_duration(c - meta.created_at),
                meta.created_at.to_rfc3339(),
                c.to_rfc3339()
            ));
        }
        md.push('\n');
    }

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
        // body 내 ``` 가 펜스를 탈출해 report.md 렌더에 markdown을 주입하지 못하도록 펜스 길이를 동적 산정.
        let fence = code_fence_for(&ev.body);
        md.push_str(&format!(
            "### [{}] {} ({:?})\n\nsource: `{}`\n\n{fence}text\n{}\n{fence}\n\n",
            ev.id, ev.title, ev.kind, ev.source, ev.body
        ));
    }
    md
}

pub fn write_report(meta: &IncidentMeta, report: &str) -> anyhow::Result<PathBuf> {
    let path = incident_dir(&meta.id).join("report.md");
    atomic_write(&path, report.as_bytes())?;
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
    atomic_write(&path, json.as_bytes())?;
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

/// index.json은 이제 **write-through 캐시/순서 힌트**일 뿐 권위가 아니다 — list_incidents가 디렉터리
/// 스캔을 권위로 삼으므로(아래) corrupt/누락 index가 incident를 숨기지 못한다. 그래도 외부 reader 호환을
/// 위해 atomic하게 유지한다.
fn update_index(id: &str) -> anyhow::Result<()> {
    let dir = incidents_dir();
    fs::create_dir_all(&dir)?;
    secure_dir(&dir);
    let mut index = load_index()?;
    index.incidents.retain(|existing| existing != id);
    index.incidents.insert(0, id.to_string());
    let path = dir.join(INDEX_FILE);
    atomic_write(&path, serde_json::to_string_pretty(&index)?.as_bytes())?;
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

/// incident id allowlist — 생성 시 timestamp + slug(`[A-Za-z0-9_-]`)만 쓰므로, 파일시스템에 닿는
/// read 경로(load_meta/load_events)에서 이 검증으로 path traversal(`..`·`/`·`\`)을 선제 차단한다.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// 원자적·내구적 파일 쓰기 — 같은 디렉터리의 임시 파일에 쓰고 fsync 후 rename으로 교체한다.
/// `fs::write`(truncate-then-write)와 달리 크래시/시그널/동시 read 중에도 target이 잘리지 않는다
/// (rename은 동일 filesystem에서 POSIX atomic). 0600 권한은 rename 전 temp에 적용해 그대로 승계한다.
fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("f");
    let tmp = dir.join(format!(".{name}.tmp.{}", tmp_suffix()));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    secure_file(&tmp);
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // 디렉터리 엔트리(rename) 내구성 — best-effort 부모 fsync.
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// temp 파일 충돌 회피용 접미사(pid + 나노초). 같은 dir에서 여러 writer가 동시에 atomic_write 해도
/// temp 이름이 겹치지 않게 한다.
fn tmp_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}.{nanos}", std::process::id())
}

/// incident별 advisory 파일 락(`.lock`). append_evidence의 count read-modify-write와 evidence.jsonl
/// 쓰기를 **프로세스·스레드 간** 직렬화한다(webhook 동시 발화/CLI·session 병행 대비). flock은 advisory라
/// 모든 writer가 같은 락을 잡아야 의미가 있는데, append_evidence가 유일한 evidence writer 경로다.
#[cfg(unix)]
struct IncidentLock {
    _file: fs::File,
}

#[cfg(unix)]
impl IncidentLock {
    fn acquire(dir: &Path) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let path = dir.join(".lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        secure_file(&path);
        let fd = file.as_raw_fd();
        loop {
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue; // EINTR — 재시도
            }
            return Err(err);
        }
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
impl Drop for IncidentLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // close도 락을 풀지만 명시적으로 해제한다.
        let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
struct IncidentLock;

#[cfg(not(unix))]
impl IncidentLock {
    fn acquire(_dir: &Path) -> io::Result<Self> {
        Ok(Self)
    }
}

/// evidence.jsonl의 실제 비어있지 않은 줄 수 — append 시 E-id/count의 **진실 소스**. stale
/// meta.evidence_count 대신 파일을 세어 동시 append의 lost-update(중복 E-id·count 드리프트)를 막는다.
fn count_evidence_lines(path: &Path) -> usize {
    match fs::read_to_string(path) {
        Ok(c) => c.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

/// 충돌하지 않는 incident 디렉터리를 원자적으로 확보한다. `fs::create_dir`(=mkdir)는 이미 있으면
/// AlreadyExists로 실패하므로, 그 신호로 suffix(`-1`,`-2`,…)를 올려 재시도한다 — 동초·동제목 incident가
/// 같은 id로 서로를 조용히 덮어쓰던 버그와 두 프로세스 동시 생성의 TOCTOU를 함께 막는다.
fn claim_incident_dir(base: &str) -> io::Result<(String, PathBuf)> {
    let parent = incidents_dir();
    fs::create_dir_all(&parent)?;
    secure_dir(&parent);
    for n in 0..10_000 {
        let id = if n == 0 {
            base.to_string()
        } else {
            format!("{base}-{n}")
        };
        let dir = parent.join(&id);
        match fs::create_dir(&dir) {
            Ok(()) => return Ok((id, dir)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "incident id 공간이 고갈되었습니다",
    ))
}

/// evidence body를 감쌀 코드 펜스 — body 내 최장 백틱 런보다 1 긴 백틱으로 만들어, body 안의 ``` 가
/// 펜스를 탈출해 대시보드 report.md 렌더에 markdown을 주입하는 것을 막는다(최소 3개).
fn code_fence_for(body: &str) -> String {
    let max_run = body
        .bytes()
        .fold((0usize, 0usize), |(max, cur), b| {
            if b == b'`' {
                (max.max(cur + 1), cur + 1)
            } else {
                (max, 0)
            }
        })
        .0;
    "`".repeat(max_run.max(2) + 1)
}

/// E-id(`E{n}`)의 수치 시퀀스 — load_events의 보조 정렬키. 동일 timestamp나 NTP 역보정 시
/// 삽입 순서(E-id)로 안정 정렬한다.
fn evidence_seq(id: &str) -> u64 {
    id.strip_prefix('E')
        .and_then(|n| n.parse().ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;
    use tempfile::TempDir;

    struct HomeGuard {
        prev: Option<std::ffi::OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    impl HomeGuard {
        fn set(path: &Path) -> Self {
            // 크레이트 전역 HOME 테스트 락 공유(auto_rca 등 incidents_dir에 쓰는 다른 모듈과의 레이스 방지).
            let lock = crate::snapshot_store::home_test_lock()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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

    // P1-5: 동일 제목을 연속 생성해도 서로 다른 id로 확보돼 조용한 덮어쓰기가 없다.
    #[test]
    fn same_title_creates_distinct_incidents_no_overwrite() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let a = create_incident("disk full", None, None).unwrap();
        let b = create_incident("disk full", None, None).unwrap();
        assert_ne!(a.id, b.id, "동초·동제목이라도 id가 충돌하면 안 된다");
        let listed = list_incidents().unwrap();
        assert!(
            listed.iter().any(|i| i.id == a.id) && listed.iter().any(|i| i.id == b.id),
            "두 incident가 모두 살아 있어야 한다(덮어쓰기 없음)"
        );
    }

    // P0-2: index.json이 깨져도 디렉터리 스캔으로 incident가 보인다.
    #[test]
    fn list_survives_corrupt_index() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let meta = create_incident("db slow", None, None).unwrap();
        // index를 의도적으로 손상.
        let idx = incidents_dir().join(INDEX_FILE);
        fs::write(&idx, "{ this is not valid json").unwrap();
        let listed = list_incidents().unwrap();
        assert!(
            listed.iter().any(|i| i.id == meta.id),
            "corrupt index가 incident를 숨기면 안 된다"
        );
    }

    // P1-3: evidence.jsonl의 손상된 한 줄이 incident 전체 로드를 죽이지 않는다.
    #[test]
    fn load_events_skips_malformed_line() {
        use std::io::Write;
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let mut meta = create_incident("oom", None, None).unwrap(); // E1 lifecycle
        append_evidence(&mut meta, EvidenceKind::Note, "n", "test", "body", &[]).unwrap(); // E2
        let path = incident_dir(&meta.id).join(EVIDENCE_FILE);
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "GARBAGE NOT JSON {{").unwrap();
        drop(f);
        let events = load_events(&meta.id).unwrap();
        assert_eq!(events.len(), 2, "손상 줄은 건너뛰고 유효 evidence만 로드");
    }

    // P2-8: read 경로가 path traversal id를 거부한다.
    #[test]
    fn load_rejects_unsafe_id() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());
        assert!(load_meta("../etc").is_err());
        assert!(load_meta("a/b").is_err());
        assert!(load_events("..").is_err());
        assert!(!is_safe_id("../x") && !is_safe_id("a/b") && !is_safe_id(""));
        assert!(is_safe_id("20260629-120000-disk-full"));
    }

    // P1-6: title/source/body가 저장 시점에 redaction된다.
    #[test]
    fn append_redacts_title_source_body() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let mut meta = create_incident("incident", None, None).unwrap();
        let secret = "Bearer abcDEF123ghiJKL456mnoPQR789";
        let ev =
            append_evidence(&mut meta, EvidenceKind::Note, secret, secret, secret, &[]).unwrap();
        assert!(
            ev.title.contains("[REDACTED"),
            "title redacted: {}",
            ev.title
        );
        assert!(
            ev.source.contains("[REDACTED"),
            "source redacted: {}",
            ev.source
        );
        assert!(ev.body.contains("[REDACTED"), "body redacted: {}", ev.body);
    }

    // P2-7: body의 ``` 가 report 코드펜스를 탈출하지 못한다(더 긴 펜스로 감싼다).
    #[test]
    fn report_fence_outlasts_backticks_in_body() {
        assert_eq!(code_fence_for("no backticks"), "```");
        assert_eq!(code_fence_for("a ``` b"), "````");
        assert_eq!(code_fence_for("```` x"), "`````");

        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());
        let mut meta = create_incident("fence", None, None).unwrap();
        append_evidence(
            &mut meta,
            EvidenceKind::Note,
            "t",
            "s",
            "line1\n```\n## injected heading\n",
            &[],
        )
        .unwrap();
        let events = load_events(&meta.id).unwrap();
        let report = render_report(&meta, &events);
        // 주입된 body가 4-backtick 펜스로 감싸여 3-backtick으로 펜스를 못 닫는다.
        assert!(report.contains("````text"), "더 긴 펜스로 감싸야 한다");
    }

    // P2-9: 동일 timestamp evidence는 E-id 시퀀스로 안정 정렬된다.
    #[test]
    fn evidence_seq_breaks_timestamp_ties() {
        assert!(evidence_seq("E2") < evidence_seq("E10"));
        assert_eq!(evidence_seq("Exx"), u64::MAX);
        let same = Utc::now();
        let mk = |id: &str| EvidenceEvent {
            id: id.to_string(),
            at: same,
            kind: EvidenceKind::Note,
            title: String::new(),
            source: String::new(),
            body: String::new(),
            tags: vec![],
        };
        let mut v = vec![mk("E3"), mk("E1"), mk("E2")];
        v.sort_by(|a, b| {
            a.at.cmp(&b.at)
                .then_with(|| evidence_seq(&a.id).cmp(&evidence_seq(&b.id)))
        });
        assert_eq!(
            v.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            vec!["E1", "E2", "E3"]
        );
    }

    // P1-4: 동시 append(여러 writer)에도 flock 직렬화로 E-id 중복/유실이 없다.
    #[test]
    fn concurrent_appends_have_no_duplicate_eids() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let base = create_incident("concurrent", None, None).unwrap(); // E1 lifecycle
        let id = base.id.clone();
        let n = 8usize;
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let id = id.clone();
                std::thread::spawn(move || {
                    // 각 스레드가 자기 meta를 로드해 append — 별개 writer를 모사.
                    let mut m = load_meta(&id).unwrap();
                    append_evidence(&mut m, EvidenceKind::Note, &format!("t{i}"), "s", "b", &[])
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let events = load_events(&id).unwrap();
        assert_eq!(events.len(), n + 1, "lifecycle E1 + {n}개 append");
        let ids: std::collections::HashSet<_> = events.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids.len(), events.len(), "E-id 중복이 없어야 한다");
    }

    // P1-4: meta.evidence_count가 stale해도 E-id는 파일 진실에서 산출된다(lost-update 방지).
    #[test]
    fn append_derives_seq_from_file_not_stale_meta() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let mut meta = create_incident("race", None, None).unwrap(); // E1, count=1
        append_evidence(&mut meta, EvidenceKind::Note, "n2", "s", "b", &[]).unwrap(); // E2, count=2
                                                                                      // meta를 인위적으로 stale하게 되돌린다(다른 writer가 이미 추가한 상황 모사).
        meta.evidence_count = 0;
        let ev = append_evidence(&mut meta, EvidenceKind::Note, "n3", "s", "b", &[]).unwrap();
        assert_eq!(ev.id, "E3", "stale count가 아니라 파일 줄 수로 E-id 산출");
        assert_eq!(meta.evidence_count, 3);
    }

    // (B) lifecycle: 전이가 타임스탬프·evidence·MTTR로 기록되고 영속된다.
    #[test]
    fn set_status_records_lifecycle_mttr_and_persists() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());

        let mut meta = create_incident("svc down", None, None).unwrap();
        assert_eq!(meta.status, IncidentStatus::Open);
        assert!(meta.mitigated_at.is_none() && meta.closed_at.is_none());

        set_status(&mut meta, IncidentStatus::Mitigated).unwrap();
        assert_eq!(meta.status, IncidentStatus::Mitigated);
        assert!(meta.mitigated_at.is_some());

        set_status(&mut meta, IncidentStatus::Closed).unwrap();
        assert_eq!(meta.status, IncidentStatus::Closed);
        assert!(meta.closed_at.is_some());

        // 영속성 + report Resolution(MTTR) 섹션 + 전이 evidence.
        let loaded = load_meta(&meta.id).unwrap();
        assert_eq!(loaded.status, IncidentStatus::Closed);
        assert!(loaded.mitigated_at.is_some() && loaded.closed_at.is_some());
        let events = load_events(&meta.id).unwrap();
        let report = render_report(&loaded, &events);
        assert!(report.contains("## Resolution") && report.contains("MTTR"));
        assert!(events
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "transition")));

        // reopen → closed_at 해제.
        set_status(&mut meta, IncidentStatus::Open).unwrap();
        assert!(meta.closed_at.is_none());
        assert_eq!(meta.status, IncidentStatus::Open);
    }

    // Closed는 Mitigated를 함의한다(중간 단계 생략 시 mitigated_at도 채움).
    #[test]
    fn closed_implies_mitigated() {
        let tmp = TempDir::new().unwrap();
        let _home = HomeGuard::set(tmp.path());
        let mut meta = create_incident("direct close", None, None).unwrap();
        set_status(&mut meta, IncidentStatus::Closed).unwrap();
        assert!(meta.mitigated_at.is_some() && meta.closed_at.is_some());
    }

    #[test]
    fn humanize_duration_formats() {
        use chrono::Duration;
        assert_eq!(humanize_duration(Duration::seconds(45)), "45s");
        assert_eq!(humanize_duration(Duration::seconds(125)), "2m 5s");
        assert_eq!(humanize_duration(Duration::seconds(3700)), "1h 1m");
        assert_eq!(humanize_duration(Duration::seconds(90061)), "1d 1h 1m");
        assert_eq!(humanize_duration(Duration::seconds(-5)), "0s");
    }

    // 기존(lifecycle 필드 없는) meta.json도 호환 로드된다.
    #[test]
    fn meta_without_lifecycle_fields_deserializes() {
        let old = r#"{"id":"x","title":"t","status":"open","symptom":null,"cwd":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","evidence_count":0}"#;
        let m: IncidentMeta = serde_json::from_str(old).unwrap();
        assert!(m.mitigated_at.is_none() && m.closed_at.is_none());
    }
}
