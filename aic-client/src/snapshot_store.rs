//! 진단 스냅샷 영구 시계열 store (`~/.aic/snapshots/snapshots.jsonl`) — 스냅샷 레코더 L0 토대.
//!
//! RCA workspace(incident 단위, `rca.rs`)와 **별개의 silo**: 일반 /local·/compare·이상-트리거 스냅샷을
//! 시간순 append-only JSONL에 쌓아 baseline diff·추세·"장애 순간의 전체 상태" 증거에 쓴다. rca.rs의 파일
//! primitive(home dir·0o600/0o700·redaction·RFC3339)를 미러하되, RCA에 없는 **retention cap**(head-trim)을
//! 더하고 `captured_at`을 **호출자 주입**으로 받아 순서·trim 테스트를 결정적으로 만든다.
//!
//! 영구 기록은 opt-in(`AIC_SNAPSHOT_RECORD`, 기본 off — 디스크에 redacted 스냅샷을 쓰므로). 연속/이상-트리거
//! 기록(L1+)과 /compare 영구화가 이 게이트를 공유한다.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// 스냅샷 레코드 스키마 버전. 필드 추가는 v1 유지(`#[serde(default)]`), rename/제거 시 상향.
const SCHEMA_VERSION: u32 = 1;
/// 보관할 최대 스냅샷 수(append 시 head-trim). RCA엔 retention이 없어 무한 증가 — store는 /compare·이상
/// 트리거가 자동으로 먹이므로 상한이 필수.
const MAX_SNAPSHOTS: usize = 200;
const SNAPSHOTS_FILE: &str = "snapshots.jsonl";

/// 한 시점 전체 스냅샷의 시계열 단위. `body`는 redacted 텍스트(`## name\n<out>` 모음).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    #[serde(default)]
    pub schema_version: u32,
    pub captured_at: DateTime<Utc>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// 스냅샷 출처: "local" | "compare" | "diagnose" | "alert" 등.
    pub kind: String,
    /// 포함된 probe 섹션 id(`## name` 키) 목록 — 빠른 인덱싱/diff용.
    #[serde(default)]
    pub sections: Vec<String>,
    /// redacted 스냅샷 본문.
    pub body: String,
}

impl SnapshotRecord {
    /// 새 레코드. `body`는 저장 직전 redaction을 한 번 더 적용(idempotent·방어적). `now`(captured_at)는
    /// 호출자가 주입한다 — 내부에서 `Utc::now()`를 부르지 않아 순서/trim 테스트가 결정적(프로덕션은 Utc::now()).
    pub fn new(
        kind: &str,
        body: &str,
        host: Option<String>,
        cwd: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        // body뿐 아니라 host/cwd도 저장 직전 redact — 경로/호스트명에 든 민감 토큰(IP/이메일/secret 패턴)이
        // 평문으로 at-rest 저장돼 미래 reader(bundle/diff/LLM)로 새는 것을 막는다(body와 동일 보장).
        let body = crate::redaction::redact(body).0;
        let host = host.map(|h| crate::redaction::redact(&h).0);
        let cwd = cwd.map(|c| crate::redaction::redact(&c).0);
        let sections = body
            .lines()
            .filter_map(|l| l.strip_prefix("## ").map(|n| n.trim().to_string()))
            .collect();
        Self {
            schema_version: SCHEMA_VERSION,
            captured_at: now,
            host,
            cwd,
            kind: kind.to_string(),
            sections,
            body,
        }
    }
}

/// 영구 스냅샷 기록 opt-in. 기본 off. `AIC_SNAPSHOT_RECORD`를 trim·소문자화 후 falsy 집합(""/0/false/no/off)이
/// 아니면 on — 사용자가 `False`/`off`/공백을 끄려고 입력했는데 켜지는 footgun 방지.
pub fn record_enabled() -> bool {
    match std::env::var("AIC_SNAPSHOT_RECORD") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        ),
        Err(_) => false,
    }
}

/// `~/.aic/snapshots` 디렉터리(rca `incidents_dir`와 동형).
pub fn snapshots_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".aic").join("snapshots")
}

/// 레코드 한 건을 JSONL로 append하고 `MAX_SNAPSHOTS`로 head-trim한다(0o700/0o600 권한). 반환=파일 경로.
pub fn append_snapshot(record: &SnapshotRecord) -> anyhow::Result<PathBuf> {
    let dir = snapshots_dir();
    fs::create_dir_all(&dir)?;
    secure_dir(&dir);
    let path = dir.join(SNAPSHOTS_FILE);
    // torn-tail 방어: 직전 append가 디스크full 등으로 개행 없이 끊겼으면, 새 레코드가 그 fragment에 붙어
    // 둘 다 파싱 불가로 유실된다. 쓰기 전 마지막 바이트를 보고 개행이 아니면 선행 개행으로 fragment를 격리한다.
    let leading = needs_leading_newline(&path)?;
    {
        let mut f = open_secure(fs::OpenOptions::new().create(true).append(true), &path)?;
        if leading {
            f.write_all(b"\n")?;
        }
        writeln!(f, "{}", serde_json::to_string(record)?)?;
    }
    secure_file(&path);
    trim_to_max(&path)?;
    Ok(path)
}

/// 파일이 비어있지 않고 마지막 바이트가 개행이 아니면 true(직전 torn-tail). 없는 파일/빈 파일은 false.
fn needs_leading_newline(path: &Path) -> std::io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if f.metadata()?.len() == 0 {
        return Ok(false);
    }
    f.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last)?;
    Ok(last[0] != b'\n')
}

/// OpenOptions에 unix면 0600 mode를 적용해 연다(create 시 world-readable 윈도 제거). non-unix는 그대로.
fn open_secure(opts: &mut fs::OpenOptions, path: &Path) -> std::io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// 저장된 스냅샷을 `captured_at` 오름차순으로 로드. 파일 없으면 빈 Vec. 깨진 라인은 건너뛴다(append 중
/// 단절 내성).
pub fn load_snapshots() -> anyhow::Result<Vec<SnapshotRecord>> {
    let path = snapshots_dir().join(SNAPSHOTS_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out: Vec<SnapshotRecord> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    out.sort_by_key(|r| r.captured_at);
    Ok(out)
}

/// 라인 수가 `MAX_SNAPSHOTS`를 넘으면 마지막 N개만 남기고 atomic(tmp+rename) 재작성한다(append-only JSONL은
/// 제자리 trim 불가). 경계 내면 무동작.
fn trim_to_max(path: &Path) -> anyhow::Result<()> {
    let content = fs::read_to_string(path)?;
    let nonempty = content.lines().filter(|l| !l.trim().is_empty()).count();
    if nonempty <= MAX_SNAPSHOTS {
        return Ok(()); // 경계 내 → 무동작(빠른 경로). 깨진 라인이 있어도 load가 건너뛰므로 무해.
    }
    // 초과: **유효 레코드만** 추려 마지막 MAX개 유지 — retention이 '유효 레코드 수' 기준이 되고, 깨진/torn
    // 라인은 이 재작성에서 self-heal로 제거된다(깨진 라인이 budget을 잠식하지 않음).
    let valid: Vec<&str> = content
        .lines()
        .filter(|l| serde_json::from_str::<SnapshotRecord>(l).is_ok())
        .collect();
    let keep = if valid.len() > MAX_SNAPSHOTS {
        &valid[valid.len() - MAX_SNAPSHOTS..]
    } else {
        &valid[..]
    };
    let tmp = path.with_extension("jsonl.tmp");
    {
        let mut f = open_secure(
            fs::OpenOptions::new().create(true).write(true).truncate(true),
            &tmp,
        )?;
        for l in keep {
            writeln!(f, "{l}")?;
        }
    }
    fs::rename(&tmp, path)?;
    secure_file(path);
    Ok(())
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

    /// HOME을 임시 디렉터리로 바꿔 store를 격리하고, env 경합을 직렬화한다(rca.rs 패턴).
    struct HomeGuard {
        prev: Option<std::ffi::OsString>,
        _lock: MutexGuard<'static, ()>,
        _dir: TempDir,
    }
    impl HomeGuard {
        fn set() -> Self {
            static HOME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = HOME_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let dir = TempDir::new().unwrap();
            let prev = std::env::var_os("HOME");
            unsafe {
                std::env::set_var("HOME", dir.path());
            }
            Self {
                prev,
                _lock: lock,
                _dir: dir,
            }
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

    fn rec(kind: &str, body: &str, secs: i64) -> SnapshotRecord {
        let now = DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap();
        SnapshotRecord::new(kind, body, None, Some("/tmp/x".into()), now)
    }

    #[test]
    fn append_load_roundtrip_and_sections() {
        let _h = HomeGuard::set();
        append_snapshot(&rec("local", "## host\nmyhost\n## disk\n/dev/sda1 90% /\n", 0)).unwrap();
        let loaded = load_snapshots().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].kind, "local");
        assert_eq!(loaded[0].schema_version, 1);
        assert_eq!(
            loaded[0].sections,
            vec!["host".to_string(), "disk".to_string()]
        );
        assert!(loaded[0].body.contains("90%"));
    }

    #[test]
    fn loads_in_captured_at_order_regardless_of_append_order() {
        let _h = HomeGuard::set();
        append_snapshot(&rec("a", "## x\n1\n", 20)).unwrap();
        append_snapshot(&rec("b", "## x\n2\n", 5)).unwrap();
        append_snapshot(&rec("c", "## x\n3\n", 10)).unwrap();
        let kinds: Vec<String> = load_snapshots()
            .unwrap()
            .into_iter()
            .map(|r| r.kind)
            .collect();
        assert_eq!(kinds, vec!["b", "c", "a"]); // captured_at 5,10,20 순서
    }

    #[test]
    fn retention_head_trims_to_max() {
        let _h = HomeGuard::set();
        for i in 0..(MAX_SNAPSHOTS as i64 + 5) {
            append_snapshot(&rec("k", "## x\nv\n", i)).unwrap();
        }
        let loaded = load_snapshots().unwrap();
        assert_eq!(loaded.len(), MAX_SNAPSHOTS, "MAX 초과분 head-trim");
        // 가장 오래된 5개(captured_at 0..5)는 제거 — 남은 최소 captured_at은 5.
        assert_eq!(
            loaded.first().unwrap().captured_at,
            DateTime::from_timestamp(1_700_000_000 + 5, 0).unwrap()
        );
    }

    #[test]
    fn body_redaction_masks_secrets() {
        let _h = HomeGuard::set();
        append_snapshot(&rec("local", "## net\nbind 10.1.2.3:8080\n", 0)).unwrap();
        let body = &load_snapshots().unwrap()[0].body;
        assert!(!body.contains("10.1.2.3"), "IPv4 미마스킹: {body}");
    }

    #[cfg(unix)]
    #[test]
    fn stored_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _h = HomeGuard::set();
        append_snapshot(&rec("local", "## x\n1\n", 0)).unwrap();
        let path = snapshots_dir().join(SNAPSHOTS_FILE);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "perms={mode:o}");
    }

    #[test]
    fn record_enabled_opt_in_default_off() {
        let _h = HomeGuard::set(); // HOME_LOCK으로 env 경합 직렬화
        unsafe {
            std::env::remove_var("AIC_SNAPSHOT_RECORD");
        }
        assert!(!record_enabled());
        unsafe {
            std::env::set_var("AIC_SNAPSHOT_RECORD", "1");
        }
        assert!(record_enabled());
        unsafe {
            std::env::set_var("AIC_SNAPSHOT_RECORD", "0");
        }
        assert!(!record_enabled());
        // footgun 방지: 끄려는 의도의 입력은 off로(정규화).
        for off in ["false", "False", "OFF", "no", "  off  "] {
            unsafe {
                std::env::set_var("AIC_SNAPSHOT_RECORD", off);
            }
            assert!(!record_enabled(), "off로 인식돼야: {off:?}");
        }
        unsafe {
            std::env::remove_var("AIC_SNAPSHOT_RECORD");
        }
    }

    #[test]
    fn torn_tail_does_not_eat_next_record() {
        let _h = HomeGuard::set();
        // 직전 append가 개행 없이 끊긴 상황 모사: 깨진 fragment를 직접 쓴다.
        fs::create_dir_all(snapshots_dir()).unwrap();
        let path = snapshots_dir().join(SNAPSHOTS_FILE);
        fs::write(&path, "{\"kind\":\"torn\",\"capt").unwrap();
        append_snapshot(&rec("after", "## x\n1\n", 0)).unwrap();
        // 새 레코드가 fragment에 안 붙고 살아남는다(torn은 자체 라인으로 격리돼 load가 건너뜀).
        let loaded = load_snapshots().unwrap();
        assert_eq!(loaded.len(), 1, "{loaded:?}");
        assert_eq!(loaded[0].kind, "after");
    }

    #[test]
    fn trim_self_heals_corruption_keeping_valid_records() {
        let _h = HomeGuard::set();
        fs::create_dir_all(snapshots_dir()).unwrap();
        let path = snapshots_dir().join(SNAPSHOTS_FILE);
        // 깨진 라인을 MAX개 미리 심어 budget을 잠식시킨다.
        fs::write(&path, "GARBAGE\n".repeat(MAX_SNAPSHOTS)).unwrap();
        // 유효 레코드를 MAX+5개 append → trim이 유효만 마지막 MAX개 유지(깨진 라인 self-heal 제거).
        for i in 0..(MAX_SNAPSHOTS as i64 + 5) {
            append_snapshot(&rec("k", "## x\nv\n", i)).unwrap();
        }
        let loaded = load_snapshots().unwrap();
        assert_eq!(loaded.len(), MAX_SNAPSHOTS, "유효 레코드만 MAX개여야: {}", loaded.len());
        assert_eq!(
            loaded.first().unwrap().captured_at,
            DateTime::from_timestamp(1_700_000_000 + 5, 0).unwrap()
        );
    }

    #[test]
    fn cwd_and_host_redacted_at_write() {
        let _h = HomeGuard::set();
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        // host/cwd에 redaction이 잡는 패턴(IPv4) → 저장된 값이 마스킹돼야(body와 동일 보장).
        let r = SnapshotRecord::new(
            "local",
            "## x\n1\n",
            Some("host-10.0.0.9".into()),
            Some("/srv/10.0.0.9/app".into()),
            now,
        );
        append_snapshot(&r).unwrap();
        let l = &load_snapshots().unwrap()[0];
        assert!(!l.cwd.as_ref().unwrap().contains("10.0.0.9"), "cwd 미마스킹: {:?}", l.cwd);
        assert!(!l.host.as_ref().unwrap().contains("10.0.0.9"), "host 미마스킹: {:?}", l.host);
    }
}

