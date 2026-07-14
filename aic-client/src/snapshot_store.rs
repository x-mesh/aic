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
/// 다중 프로세스 append 직렬화용 lockfile(데이터 파일과 분리). [`cross_process_guard`] 참조.
const LOCKFILE: &str = ".lock";

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
    /// 사람이 남긴 관찰 메모(`/record now <메모>`, `aic snapshot record --memo`). 없으면 `None`.
    ///
    /// **왜 로컬에 저장하는가**: 이 기능의 본질은 **메모**다 — 임계 스캔이 원리상 못 잡는 "지금 이게
    /// 이상하다"를 사람이 직접 남기는 경로다. 그런데 메모가 OTLP 이벤트로**만** 나가면, aicd가 꺼져
    /// 있을 때(우리 문서상 **정상 상태**다) 그 관찰이 통째로 사라진다. 스냅샷은 저장되는데 정작
    /// 사람이 남긴 말은 어디에도 없는 것이다. 원격은 부가이지 본체가 아니므로, 메모는 로컬 레코드에
    /// 함께 남긴다.
    ///
    /// 하위 호환: 기존 레코드엔 이 필드가 없다 → `#[serde(default)]`로 `None`이 된다.
    #[serde(default)]
    pub memo: Option<String>,
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
        Self::with_memo(kind, body, host, cwd, now, None)
    }

    /// [`Self::new`] + 사람이 남긴 메모(`/record now <메모>`). memo도 body/host/cwd와 **동일하게
    /// redact**한다 — 사람이 메모에 secret을 적어 넣을 수 있고(F14), at-rest 평문으로 남으면 미래
    /// reader(bundle/diff/LLM)로 그대로 샌다.
    pub fn with_memo(
        kind: &str,
        body: &str,
        host: Option<String>,
        cwd: Option<String>,
        now: DateTime<Utc>,
        memo: Option<&str>,
    ) -> Self {
        // body뿐 아니라 host/cwd도 저장 직전 redact — 경로/호스트명에 든 민감 토큰(IP/이메일/secret 패턴)이
        // 평문으로 at-rest 저장돼 미래 reader(bundle/diff/LLM)로 새는 것을 막는다(body와 동일 보장).
        let body = crate::redaction::redact(body).0;
        let host = host.map(|h| crate::redaction::redact(&h).0);
        let cwd = cwd.map(|c| crate::redaction::redact(&c).0);
        let memo = memo
            .map(|m| crate::redaction::redact(m).0)
            .filter(|m| !m.trim().is_empty());
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
            memo,
        }
    }

    /// `aic snapshot list`의 사람이 보는 한 줄. **순수 함수**(store를 읽지 않으므로 격리 없이 테스트
    /// 가능). 저장한 메모를 **다시 볼 경로**를 여기서 만든다 — 저장만 하고 표시하지 않으면
    /// "메모는 로컬에 저장됐습니다"라는 안내가 빈 약속이 된다(사용자가 확인할 방법이 없다).
    pub fn list_line(&self) -> String {
        let mut s = format!(
            "- {} · {} · sections={} ({})",
            self.captured_at.to_rfc3339(),
            self.kind,
            self.sections.len(),
            self.sections.join(",")
        );
        if let Some(memo) = &self.memo {
            s.push_str(&format!(
                " · memo: {}",
                memo_preview(memo, MEMO_PREVIEW_CHARS)
            ));
        }
        s
    }
}

/// list 한 줄에 보여줄 메모 미리보기 최대 글자수(바이트 아님). 목록이 한 줄로 읽히게 짧게 자른다 —
/// 전체 메모는 `snapshot compare`/bundle 등 본문 경로에서 본다.
const MEMO_PREVIEW_CHARS: usize = 60;

/// 메모를 **한 줄 미리보기**로 만든다(순수). 개행·탭(sanitize가 남긴 정상 문자)을 공백으로 접어
/// 목록이 여러 줄로 깨지지 않게 하고, `max_chars`(글자 기준, UTF-8 경계 안전)를 넘으면 `…`로 자른다.
fn memo_preview(memo: &str, max_chars: usize) -> String {
    // 개행·탭 → 공백, 연속 공백은 하나로. (제어문자 자체는 sanitize 단계에서 이미 제거됨.)
    let collapsed: String = memo
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .collect();
    let collapsed = collapsed.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = collapsed.chars().take(max_chars).collect();
    if collapsed.chars().count() > max_chars {
        out.push('…');
    }
    out
}

/// opt-in **값 파서**(순수). 기본 off. 값을 trim·소문자화 후 falsy 집합(""/0/false/no/off)이 아니면
/// on — 사용자가 `False`/`off`/공백을 끄려고 입력했는데 켜지는 footgun 방지.
///
/// **값을 주입받는다**(env를 읽지 않는다) — 그래서 계약을 격리 없이, 프로세스 전역 env를 만지지
/// 않고 테스트할 수 있다. `set_var`는 Rust 2024에서 unsafe(다른 스레드가 env를 읽는 동안 쓰면
/// data race)라, 값 열거를 env로 하면 병렬 테스트의 간헐 실패 씨앗이 된다 — 순수 코어를 분리해 피한다.
pub fn enabled_from_value(value: Option<&str>) -> bool {
    match value {
        Some(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        ),
        None => false,
    }
}

/// opt-in env 공통 파서 — [`enabled_from_value`]에 env 값을 주입한다. AIC_SNAPSHOT_RECORD(L0-L2)·
/// AIC_AUTO_RCA(L3 auto_rca)가 공유한다.
pub fn env_enabled(var: &str) -> bool {
    enabled_from_value(std::env::var(var).ok().as_deref())
}

/// 영구 스냅샷 기록 opt-in(`AIC_SNAPSHOT_RECORD`). 기본 off.
///
/// 테스트는 env 대신 [`test_store`]의 주입값을 쓴다(2024 UB 회피 — [`snapshots_dir`] 참고).
pub fn record_enabled() -> bool {
    #[cfg(test)]
    if let Some(v) = test_store::override_recording() {
        return v;
    }
    env_enabled("AIC_SNAPSHOT_RECORD")
}

/// `~/.aic/snapshots` 디렉터리(rca `incidents_dir`와 동형).
///
/// **테스트에서는 env(`HOME`)를 만지지 않고 [`test_store`]의 주입값을 쓴다** — `set_var("HOME")`은
/// Rust 2024에서 unsafe(다른 스레드가 env를 읽는 동안 쓰면 data race)라, HOME을 바꿔 store를
/// 격리하던 방식은 UB의 씨앗이었다. 주입은 프로세스 전역 상태(env) 대신 내부 값을 쓰므로 그 race가
/// 없다. 프로덕션(`cfg(not(test))`)에는 이 분기가 아예 컴파일되지 않아 비용 0이다.
pub fn snapshots_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(dir) = test_store::override_dir() {
        return dir;
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".aic").join("snapshots")
}

/// 테스트가 store를 **주입으로 격리**하는 하네스 — env를 만지지 않는다(2024 UB 회피).
///
/// snapshots dir과 opt-in 플래그(`AIC_SNAPSHOT_RECORD` 대체) 두 축을 프로세스 전역 값으로 들고,
/// [`snapshots_dir`]/[`record_enabled`]가 프로덕션 경로 대신 이 값을 참조한다. **thread-local이 아니라
/// 전역인 이유**: chat `/record now`의 캡처는 `spawn_blocking`으로 다른 스레드에서 도는데, 그 스레드도
/// 같은 override를 봐야 하기 때문이다(thread-local이면 못 본다). 전역이라 병렬 테스트끼리는 겹치므로
/// [`home_test_lock`]으로 직렬화한다 — 예전 HomeGuard와 같은 직렬화이되, **공유하는 게 env가 아니라
/// 내부 PathBuf/bool이라 data race가 없다**.
#[cfg(test)]
pub(crate) mod test_store {
    use super::PathBuf;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Override {
        dir: Option<PathBuf>,
        /// `Some(v)`면 `record_enabled()`가 env 대신 `v`를 쓴다. `None`이면 기본(off).
        recording: Option<bool>,
    }
    static OVERRIDE: Mutex<Override> = Mutex::new(Override {
        dir: None,
        recording: None,
    });

    fn lock() -> std::sync::MutexGuard<'static, Override> {
        OVERRIDE.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn override_dir() -> Option<PathBuf> {
        lock().dir.clone()
    }
    pub(crate) fn override_recording() -> Option<bool> {
        lock().recording
    }
    pub(crate) fn set_dir(dir: Option<PathBuf>) {
        lock().dir = dir;
    }
    pub(crate) fn set_recording(v: Option<bool>) {
        lock().recording = v;
    }
}

/// append 임계구역 직렬화용 프로세스 전역 락. L1 이상-트리거 캡처는 `spawn_blocking` 스레드에서, /compare·
/// baseline append는 세션 task에서 — **같은 프로세스의 서로 다른 실행 컨텍스트**가 동시에 append할 수 있다.
/// read-tail + append + `trim_to_max`(read-all→rename)는 비원자적이라, 한 쪽 append가 다른 쪽 trim의
/// read-all과 rename 사이에 끼면 atomic rename이 그 쓰기를 덮어 **잃은 쓰기**가 된다. 임계구역 전체를
/// 직렬화해 막는다. (다중 aic 프로세스 — 두 세션·L2 타이머 — 간 경쟁은 이 in-process 락으론 못 막으며,
/// [`cross_process_guard`]의 lockfile flock이 그 층을 담당한다.)
fn append_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// **다중 프로세스** append 직렬화 게이트(L2). L1의 in-process [`append_lock`] Mutex는 같은 프로세스의 두
/// 실행 컨텍스트만 직렬화한다 — 하지만 L2 타이머는 **별개의 `aic snapshot capture` 프로세스**라, 인터랙티브
/// 세션의 /compare·alert append와 정말 동시에 trim(read-all→rename)을 돌려 잃은 쓰기가 난다. 별도 lockfile
/// `~/.aic/snapshots/.lock`에 `File::lock`(LOCK_EX, blocking)을 걸어 프로세스 간 직렬화한다.
///
/// **왜 데이터 파일이 아니라 별도 lockfile인가:** flock은 inode(OFD)에 붙는데 `trim_to_max`의 rename이 데이터
/// 파일을 새 inode로 교체하므로, 데이터 파일을 직접 flock하면 trim 전후 writer가 서로 다른 inode를 잠가
/// 상호배제가 깨진다. lockfile은 절대 rename되지 않아 모든 writer가 항상 같은 inode를 잠근다.
///
/// 매 append마다 fresh open(핸들 캐시 금지 — std는 "이미 락 든 핸들의 재-lock은 unspecified"로 규정). 반환된
/// 가드를 잡고 있는 동안 락 유지(drop=close 시 OFD 락 자동 해제 → stale 락 없음, 프로세스 죽어도 동일).
/// 락 획득 실패(권한·IO·non-unix 차이)는 **best-effort**로 무시: 락 없이 진행한다(同프로세스는 Mutex가 여전히
/// 보호하고, opt-in으로 켠 기록을 드문 cross-process 경합 때문에 버리지 않는다).
///
/// `lock()`은 **무한 blocking**(try_lock+timeout 아님): 임계구역이 순수 로컬 파일 IO(read-tail→append→가끔
/// trim)로 µs급이고, 캡처는 이미 detached(spawn_blocking / 별도 타이머 프로세스)라 대기가 UI를 막지 않으므로
/// 정당하다. 네트워크 FS(~/.aic가 NFS 등)에서 flock이 hang하면 그 캡처 한 건만 지연된다 — 이론적 한계.
fn cross_process_guard(dir: &Path) -> Option<fs::File> {
    let lock_path = dir.join(LOCKFILE);
    let file = open_secure(fs::OpenOptions::new().create(true).write(true), &lock_path).ok()?;
    file.lock().ok()?; // blocking LOCK_EX. 실패(non-unix 차이 등)면 None → 락 없이 진행.
    Some(file)
}

/// 레코드 한 건을 JSONL로 append하고 `MAX_SNAPSHOTS`로 head-trim한다(0o700/0o600 권한). 반환=파일 경로.
pub fn append_snapshot(record: &SnapshotRecord) -> anyhow::Result<PathBuf> {
    // 동시 writer 직렬화(위 [`append_lock`] 설명 참조). poison된 락은 회복해 best-effort store를 막지 않는다.
    let _guard = append_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = snapshots_dir();
    fs::create_dir_all(&dir)?;
    secure_dir(&dir);
    // cross-process 락은 Mutex **안쪽**에 중첩(同프로세스는 한 스레드만 여기 도달 → flock 무경합). 함수 끝까지
    // 가드를 유지해 append+trim 임계구역 전체를 다른 프로세스로부터 보호한다.
    let _xguard = cross_process_guard(&dir);
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

/// (D-time) 두 스냅샷 body의 변화를 사람이 읽는 리포트로 만든다 — chat `/compare`와 **동일 로직**을
/// 재사용한다(volatile 메타 정규화 + 섹션별 추가/삭제/변경 + 라인 diff). `aic snapshot compare`와 web
/// Snapshots diff 뷰가 공유한다. body는 이미 redacted 스냅샷 텍스트다.
pub fn compare(old_body: &str, new_body: &str) -> String {
    crate::agent::tool_record::compare_report(old_body, new_body)
}

/// (D-time) `records`(captured_at 오름차순)에서 `newest` 이전이며 `target` 시각 이하인 **가장 최근**
/// 스냅샷 인덱스를 고른다(= "N분 전"에 가장 가까운 과거). 해당하는 게 없으면 가장 오래된 것(0). records가
/// 2개 미만이면 None. pure — 단위 테스트 대상.
pub fn index_at_or_before(records: &[SnapshotRecord], target: DateTime<Utc>) -> Option<usize> {
    if records.len() < 2 {
        return None;
    }
    let newest = records.len() - 1;
    // newest 제외하고 뒤에서부터 target 이하 첫 매칭.
    for i in (0..newest).rev() {
        if records[i].captured_at <= target {
            return Some(i);
        }
    }
    Some(0) // target보다 이른 게 없으면 가장 오래된 스냅샷과 비교
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
            fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true),
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

/// store를 주입으로 격리하는 테스트들(snapshot_store + snapshot_capture + session)이 공유하는
/// **프로세스 전역** 직렬화 락. override(dir/recording)가 전역이라 병렬 테스트끼리 겹치므로 하나의
/// 락으로 직렬화한다(모듈별 별도 락이면 서로의 override를 덮어 오염된다).
#[cfg(test)]
pub(crate) fn home_test_lock() -> &'static std::sync::Mutex<()> {
    static STORE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    STORE_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// **env를 만지지 않고** store를 tempdir로 격리하는 RAII 가드 — 예전 `HomeGuard`(HOME set_var)를
/// 대체한다. 락을 잡아 병렬 테스트를 직렬화하고, [`test_store`] override를 세팅하며, drop 시 되돌린다.
/// snapshot_store·snapshot_capture·session 테스트가 공유한다(한 곳에 두어 세 모듈이 같은 격리를 쓴다).
#[cfg(test)]
pub(crate) struct TestStore {
    _lock: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
}

#[cfg(test)]
impl TestStore {
    /// 격리를 연다(기록 opt-in은 기본 off — `record_enabled()`가 false). 락은 이 가드 수명 동안 유지.
    pub(crate) fn new() -> Self {
        // poison 회복: 직전 테스트가 락 든 채 패닉해도 다음 테스트가 진행되게.
        let lock = home_test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        test_store::set_dir(Some(dir.path().to_path_buf()));
        // **`None`이 아니라 `Some(false)`** — None이면 `record_enabled()`가 실 env(AIC_SNAPSHOT_RECORD)로
        // 떨어져 테스트가 개발 머신/CI의 ambient env에 의존한다. 기본을 명시적 off로 못 박는다.
        test_store::set_recording(Some(false));
        Self {
            _lock: lock,
            _dir: dir,
        }
    }

    /// 이 테스트 동안 `AIC_SNAPSHOT_RECORD` opt-in을 켜고/끈다(env 대신 주입). 예전엔 여기서
    /// `set_var("AIC_SNAPSHOT_RECORD", ...)`를 했다.
    pub(crate) fn set_recording(&self, on: bool) {
        test_store::set_recording(Some(on));
    }
}

#[cfg(test)]
impl Drop for TestStore {
    fn drop(&mut self) {
        // 전역 override를 원상복구(다음 테스트가 프로덕션 기본을 보게).
        test_store::set_dir(None);
        test_store::set_recording(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 격리는 이제 `TestStore`(env 미접촉)가 담당한다 — 예전 HomeGuard(HOME set_var)를 대체했다.

    fn rec(kind: &str, body: &str, secs: i64) -> SnapshotRecord {
        let now = DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap();
        SnapshotRecord::new(kind, body, None, Some("/tmp/x".into()), now)
    }

    #[test]
    fn index_at_or_before_picks_closest_past() {
        // captured_at: 0s, 10s, 20s, 30s(newest). 15s 전 target(=30-15=15s 시점) → 10s(idx1)이 최근 과거.
        let recs = vec![
            rec("a", "## x\n1\n", 0),
            rec("b", "## x\n2\n", 10),
            rec("c", "## x\n3\n", 20),
            rec("d", "## x\n4\n", 30),
        ];
        let newest = recs.last().unwrap().captured_at;
        assert_eq!(
            index_at_or_before(&recs, newest - chrono::Duration::seconds(15)),
            Some(1)
        );
        // 아주 먼 과거 target → 가장 오래된 것(0).
        assert_eq!(
            index_at_or_before(&recs, newest - chrono::Duration::seconds(9999)),
            Some(0)
        );
        // 2개 미만 → None.
        assert_eq!(index_at_or_before(&recs[..1], newest), None);
    }

    #[test]
    fn compare_surfaces_changed_section() {
        let old = "## disk\n/dev/sda1 80% /\n## ports\n:22\n";
        let new = "## disk\n/dev/sda1 95% /\n## ports\n:22\n";
        let report = compare(old, new);
        assert!(report.contains("disk"), "변경 섹션에 disk: {report}");
        // 동일 입력은 변화 없음.
        assert!(compare(old, old).contains("변화 없음"));
    }

    #[test]
    fn append_load_roundtrip_and_sections() {
        let _h = TestStore::new();
        append_snapshot(&rec(
            "local",
            "## host\nmyhost\n## disk\n/dev/sda1 90% /\n",
            0,
        ))
        .unwrap();
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
        let _h = TestStore::new();
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
        let _h = TestStore::new();
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
    fn concurrent_appends_during_trim_lose_no_records() {
        // L1 회귀: 캡처(spawn_blocking)와 /compare(세션 task)가 같은 프로세스에서 동시에 append할 수 있다.
        // 파일이 MAX를 넘은 상태의 동시 append는 각자 trim(read-all→rename)을 돌려, 직렬화가 없으면 한 쪽
        // 쓰기가 다른 쪽 rename에 덮여 유실된다. append_lock이 이를 막는지(모든 동시 쓰기 보존) 검증한다.
        let _h = TestStore::new();
        for i in 0..(MAX_SNAPSHOTS as i64) {
            // 파일을 MAX로 채워 이후 append마다 trim이 발생하게 한다(rename 경쟁 윈도우 노출).
            append_snapshot(&rec("seed", "## x\nv\n", i)).unwrap();
        }
        let n: i64 = 40;
        let handles: Vec<_> = (0..n)
            .map(|i| {
                std::thread::spawn(move || {
                    // seed보다 큰 captured_at → trim 유지 윈도우(마지막 MAX)에 반드시 포함.
                    append_snapshot(&rec("hot", "## x\nv\n", MAX_SNAPSHOTS as i64 + i)).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let loaded = load_snapshots().unwrap();
        assert_eq!(loaded.len(), MAX_SNAPSHOTS, "trim 후 정확히 MAX");
        let hot = loaded.iter().filter(|r| r.kind == "hot").count();
        assert_eq!(hot, n as usize, "동시 append 유실 없음(40건 모두 보존)");
    }

    #[cfg(unix)]
    #[test]
    fn cross_process_lockfile_created_0600_and_isolated() {
        // L2: append가 cross-process lockfile(.lock)을 만들고, 그 파일이 store 데이터(load/trim)에 섞이지
        // 않으며, 락이 있어도 후속 append가 정상 동작(재진입 가능)함을 확인한다.
        use std::os::unix::fs::PermissionsExt;
        let _h = TestStore::new();
        append_snapshot(&rec("a", "## x\n1\n", 0)).unwrap();
        let lock_path = snapshots_dir().join(LOCKFILE);
        assert!(lock_path.exists(), "lockfile 미생성");
        let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "lockfile 권한 0600 아님: {mode:o}");
        // 두 번째 append도 정상(같은 lockfile fresh open→lock→unlock).
        append_snapshot(&rec("b", "## x\n2\n", 1)).unwrap();
        let loaded = load_snapshots().unwrap();
        // .lock은 snapshots.jsonl만 읽는 load에 절대 섞이지 않는다 — 레코드는 정확히 2건.
        assert_eq!(loaded.len(), 2, "lockfile이 데이터에 섞였거나 append 유실");
        assert_eq!(
            loaded.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn cross_process_guard_serializes_via_flock() {
        // L2 핵심 불변식에 teeth: .lock flock이 정말 cross-OFD(=cross-process) append를 직렬화하는지. 메인이
        // 락을 직접 잡으면 다른 OFD로 들어오는 append가 flock에서 막혀야 한다(flock이 no-op/조기 drop이면 즉시
        // 완료 → 테스트 실패). unix flock은 cross-OFD를 同프로세스에서도 상호배제한다.
        use std::sync::mpsc;
        use std::time::Duration;
        let _h = TestStore::new();
        let dir = snapshots_dir();
        fs::create_dir_all(&dir).unwrap();
        // append_snapshot의 cross_process_guard와 동일한 .lock을 **별도 OFD**로 미리 잡는다.
        let held = open_secure(
            fs::OpenOptions::new().create(true).write(true),
            &dir.join(LOCKFILE),
        )
        .unwrap();
        held.lock().unwrap();
        let (tx, rx) = mpsc::channel();
        let t = std::thread::spawn(move || {
            // in-process Mutex(무경합) 통과 후 flock에서 블록된다.
            append_snapshot(&rec("blocked", "## x\n1\n", 0)).unwrap();
            let _ = tx.send(());
        });
        // 락을 든 동안 append는 완료될 수 없다(flock 차단). µs급 임계구역이라 300ms 음성 마진은 넉넉.
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "flock이 cross-process append를 막지 못함(즉시 완료)"
        );
        held.unlock().unwrap();
        drop(held);
        // 해제 후 append 완료.
        rx.recv_timeout(Duration::from_secs(5))
            .expect("락 해제 후에도 append 미완료");
        t.join().unwrap();
        assert_eq!(load_snapshots().unwrap().len(), 1);
    }

    #[test]
    fn old_records_without_memo_field_still_load() {
        // 하위 호환: 기존 레코드엔 `memo` 필드가 없다. 그 줄이 파싱 실패로 통째 유실되면(load가
        // 깨진 라인을 건너뛰므로) 과거 스냅샷이 조용히 사라진다 — `#[serde(default)]`로 None이 된다.
        let _h = TestStore::new();
        fs::create_dir_all(snapshots_dir()).unwrap();
        let path = snapshots_dir().join(SNAPSHOTS_FILE);
        // 구버전 aic가 쓴 레코드 — `memo` 키가 **아예 없다**(있는데 null인 것과 다르다).
        let old_line = serde_json::json!({
            "schema_version": 1,
            "captured_at": "2023-11-14T22:13:20Z",
            "host": null,
            "cwd": "/tmp/x",
            "kind": "local",
            "sections": ["host"],
            "body": "## host\nh\n",
        })
        .to_string();
        assert!(
            !old_line.contains("memo"),
            "픽스처에 memo 키가 있으면 안 된다"
        );
        fs::write(&path, format!("{old_line}\n")).unwrap();

        let loaded = load_snapshots().unwrap();
        assert_eq!(loaded.len(), 1, "구버전 레코드가 유실됐다");
        assert_eq!(loaded[0].kind, "local");
        assert_eq!(loaded[0].memo, None, "필드 없는 구버전은 메모 없음이어야");
    }

    // ── list 표시: 저장한 메모를 다시 볼 경로(순수 포맷, store 미접촉) ────────────

    #[test]
    fn list_line_shows_memo_when_present_and_omits_when_absent() {
        // 저장만 하고 표시 안 하면 "메모는 로컬에 저장됐습니다"가 빈 약속이 된다 — list가 보여준다.
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let with = SnapshotRecord::with_memo(
            "manual",
            "## host\nh\n",
            None,
            None,
            now,
            Some("디스크가 이상하다"),
        );
        let line = with.list_line();
        assert!(
            line.contains("memo: 디스크가 이상하다"),
            "메모가 안 보인다: {line}"
        );

        // 메모 없는 레코드(alert 캡처 등)엔 memo 조각이 없다 — 없는 걸 있는 척하지 않는다.
        let without = SnapshotRecord::new("alert", "## host\nh\n", None, None, now);
        assert!(
            !without.list_line().contains("memo:"),
            "메모 없는데 memo: 표시"
        );
    }

    #[test]
    fn memo_preview_collapses_newlines_and_truncates_on_char_boundary() {
        // 목록 한 줄이 여러 줄로 깨지지 않게 개행·탭을 접고, 길면 …로 자른다(UTF-8 경계 안전).
        assert_eq!(memo_preview("한 줄\n둘째 줄\t셋", 40), "한 줄 둘째 줄 셋");

        // 멀티바이트로 상한 초과 → 글자 기준 절단 + 말줄임(패닉하면 바이트 경계를 깬 것).
        let long = "가".repeat(100);
        let out = memo_preview(&long, 60);
        assert_eq!(out.chars().count(), 61, "60글자 + …"); // 잘림 표시 포함
        assert!(out.ends_with('…'));
        assert!(out.chars().take(60).all(|c| c == '가'));

        // 상한 이하면 말줄임 없음.
        assert_eq!(memo_preview("짧다", 60), "짧다");
    }

    #[test]
    fn body_redaction_masks_secrets() {
        let _h = TestStore::new();
        append_snapshot(&rec("local", "## net\nbind 10.1.2.3:8080\n", 0)).unwrap();
        let body = &load_snapshots().unwrap()[0].body;
        assert!(!body.contains("10.1.2.3"), "IPv4 미마스킹: {body}");
    }

    #[cfg(unix)]
    #[test]
    fn stored_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _h = TestStore::new();
        append_snapshot(&rec("local", "## x\n1\n", 0)).unwrap();
        let path = snapshots_dir().join(SNAPSHOTS_FILE);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "perms={mode:o}");
    }

    #[test]
    fn enabled_value_parser_contract() {
        // 공유 파서 계약 — **값을 주입**해 검증한다(env 미접촉 → 격리·직렬화 불필요, 2024 UB 없음).
        // 미설정(None)과 falsy 문자열은 off, 그 외는 on. footgun: 끄려는 의도의 입력은 off로 정규화.
        assert!(!enabled_from_value(None), "미설정은 off");
        for off in ["", "0", "false", "False", "OFF", "no", "  off  "] {
            assert!(!enabled_from_value(Some(off)), "off로 인식돼야: {off:?}");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            assert!(enabled_from_value(Some(on)), "on으로 인식돼야: {on:?}");
        }
    }

    #[test]
    fn record_enabled_defaults_off_and_follows_injection() {
        // opt-in 게이트를 **env 없이** 검증한다(2024 UB 회피). 값 파싱 계약은 순수
        // `enabled_value_parser_contract`가, env 배선(어느 var를 읽는지)은 프로덕션 경로가 담당하고
        // `record_enabled`/`env_enabled` doc에 못 박혀 있다 — 여기선 게이트 동작만 결정적으로 본다.
        let h = TestStore::new();
        assert!(
            !record_enabled(),
            "TestStore 기본은 off(실 env에 의존하지 않는다)"
        );
        h.set_recording(true);
        assert!(record_enabled(), "주입 on이면 record_enabled도 on");
        h.set_recording(false);
        assert!(!record_enabled(), "주입 off면 off");
    }

    #[test]
    fn torn_tail_does_not_eat_next_record() {
        let _h = TestStore::new();
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
        let _h = TestStore::new();
        fs::create_dir_all(snapshots_dir()).unwrap();
        let path = snapshots_dir().join(SNAPSHOTS_FILE);
        // 깨진 라인을 MAX개 미리 심어 budget을 잠식시킨다.
        fs::write(&path, "GARBAGE\n".repeat(MAX_SNAPSHOTS)).unwrap();
        // 유효 레코드를 MAX+5개 append → trim이 유효만 마지막 MAX개 유지(깨진 라인 self-heal 제거).
        for i in 0..(MAX_SNAPSHOTS as i64 + 5) {
            append_snapshot(&rec("k", "## x\nv\n", i)).unwrap();
        }
        let loaded = load_snapshots().unwrap();
        assert_eq!(
            loaded.len(),
            MAX_SNAPSHOTS,
            "유효 레코드만 MAX개여야: {}",
            loaded.len()
        );
        assert_eq!(
            loaded.first().unwrap().captured_at,
            DateTime::from_timestamp(1_700_000_000 + 5, 0).unwrap()
        );
    }

    #[test]
    fn cwd_and_host_redacted_at_write() {
        let _h = TestStore::new();
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
        assert!(
            !l.cwd.as_ref().unwrap().contains("10.0.0.9"),
            "cwd 미마스킹: {:?}",
            l.cwd
        );
        assert!(
            !l.host.as_ref().unwrap().contains("10.0.0.9"),
            "host 미마스킹: {:?}",
            l.host
        );
    }
}
