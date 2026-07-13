//! 로그 수집기 체크포인트 — ordered ack + 소스별 자연키 `record_id` (RFC-006 t4).
//!
//! 세 가지를 묶는다:
//!   1. [`record_id`] — 재전송해도 불변인 멱등키. 수신측 ReplacingMergeTree가 이 키로 중복을
//!      접는다.
//!   2. [`AckTracker`] — in-flight 배치의 완료 순서가 뒤집혀도(#2가 #1보다 먼저 durable) 체크포인트가
//!      **연속 prefix**만큼만 전진하도록 보장한다. 안 그러면 #1이 영원히 유실된다(Vector가
//!      `OrderedFinalizer`를 쓰는 이유와 동일).
//!   3. [`CheckpointStore`] — 소스별 커서(`journald` cursor, `file` offset 등)를 디스크에 원자적으로
//!      저장한다. [`super::super::spool`]의 tmp → `sync_all()` → `rename` 패턴을 그대로 쓴다 —
//!      Vector의 journald checkpointer는 이걸 안 해서 크래시 시 커서가 찢어진다.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::PathBuf;

use aic_common::LogLine;

/// 멱등키. 재전송해도 **불변**이어야 수신측 ReplacingMergeTree가 중복을 접는다.
///
/// 소스별 자연키를 우선한다:
///   - journald : `__CURSOR` (그 자체가 안정적 자연키)
///   - file / container : `fingerprint:offset` (재전송해도 안 변한다)
///   - aic self : 자연키가 없다 → 내용 해시로 폴백
///
/// 내용 해시로 폴백하면 "같은 ms에 완전히 동일한 라인"이 하나로 접힌다(재시도 루프의 반복 WARN
/// 등). 자연키가 있는 2/4 소스에서는 이 문제가 사라진다.
#[allow(dead_code)] // t5/t8/t9가 배선하면 제거
pub fn record_id(natural_key: Option<&str>, host: &str, line: &LogLine) -> String {
    if let Some(key) = natural_key {
        return format!("log:{key}");
    }

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    host.hash(&mut h);
    line.source.hash(&mut h);
    line.service.hash(&mut h);
    line.ts.timestamp_millis().hash(&mut h);
    line.message.hash(&mut h);
    format!("log:{:016x}", h.finish())
}

/// in-flight 배치의 완료 순서 뒤집힘을 흡수하는 ordered ack tracker.
///
/// 배치가 durable해지는 순서는 발행 순서와 다를 수 있다(재시도, 네트워크 지연 등). 완료된 배치
/// 중 **연속 prefix의 최댓값까지만** [`committed`](Self::committed)가 전진한다 — 구멍이 있으면 그
/// 앞에서 멈춰, 아직 완료되지 않은 더 이전 배치를 체크포인트가 건너뛰어 유실시키지 않는다.
#[allow(dead_code)] // t5/t8/t9가 배선하면 제거
#[derive(Debug, Default)]
pub struct AckTracker {
    /// 다음에 발급할 seq.
    next_seq: u64,
    /// 아직 committed에 편입되지 않은, seq 순서상 다음으로 기다리는 값.
    next_expected: u64,
    /// `next_expected`보다 앞서 완료된(구멍 뒤에서 도착한) seq들.
    completed: BTreeSet<u64>,
}

impl AckTracker {
    /// 새 tracker. seq는 1부터 발급한다(0은 "아직 아무것도 committed되지 않음"을 뜻하도록 비워
    /// 둔다).
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            next_expected: 1,
            completed: BTreeSet::new(),
        }
    }

    /// 배치 seq를 발급한다(단조 증가).
    pub fn issue(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// 그 배치가 durable해졌음을 알린다. push 성공, 또는 spool `append()`(fsync 완료) 성공 둘 다
    /// 여기로 보고한다 — 둘 다 durable이다.
    pub fn complete(&mut self, seq: u64) {
        if seq < self.next_expected {
            // 이미 committed된 seq의 재보고(중복 알림 등) — 무시.
            return;
        }
        self.completed.insert(seq);
        while self.completed.remove(&self.next_expected) {
            self.next_expected += 1;
        }
    }

    /// 연속 prefix의 최댓값. 구멍이 있으면 그 앞에서 멈춘다.
    ///
    /// 예: 2, 3을 complete하고 1은 아직 → `committed() == 0`. 이후 1이 오면 → `committed() == 3`
    /// 으로 점프.
    pub fn committed(&self) -> u64 {
        self.next_expected - 1
    }
}

/// 체크포인트 파일 확장자.
const CHECKPOINT_EXT: &str = "checkpoint";
/// 원자적 교체를 위한 임시 파일 확장자. spool.rs의 `TMP_EXT`와 동일한 관례.
const TMP_EXT: &str = "tmp";

/// 소스별 체크포인트(로그 수집 커서)를 디스크에 원자적으로 저장/로드한다.
///
/// `key`는 `"journald"` / `"file/<label>"` / `"container/<id>"` 형태 — 파일 경로에 그대로 쓰면
/// path traversal이 되므로 [`sanitize_key`]로 영숫자/`-`/`_`만 남긴다.
#[allow(dead_code)] // t5/t8/t9가 배선하면 제거
#[derive(Debug)]
pub struct CheckpointStore {
    dir: PathBuf,
}

impl CheckpointStore {
    /// `dir`을 0700 권한으로 열거나 생성한다.
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    /// 저장된 체크포인트 값을 읽는다. 파일이 없거나, 손상/파싱 실패(UTF-8이 아니거나 빈 값)면
    /// `None` — 호출부가 `--since=now` 등으로 폴백한다. **panic하지 않는다.**
    pub fn load(&self, key: &str) -> Option<String> {
        let path = self.checkpoint_path(key);
        let raw = std::fs::read(&path).ok()?;
        let text = String::from_utf8(raw).ok()?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(trimmed.to_string())
    }

    /// 체크포인트 값을 원자적으로 저장한다. tmp → `sync_all()` → `rename`
    /// ([`super::super::spool`]의 `append()`와 동일 패턴) — 중간에 프로세스가 죽어도 절반만
    /// 쓰인 최종 파일이 생기지 않는다(있어도 `.tmp`로만 남아 `load()`가 무시한다).
    pub fn save(&self, key: &str, value: &str) -> io::Result<()> {
        let safe = sanitize_key(key);
        let final_path = self.dir.join(format!("{safe}.{CHECKPOINT_EXT}"));
        let tmp_path = self.dir.join(format!("{safe}.{TMP_EXT}"));

        {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(value.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    fn checkpoint_path(&self, key: &str) -> PathBuf {
        self.dir
            .join(format!("{}.{CHECKPOINT_EXT}", sanitize_key(key)))
    }
}

/// 체크포인트 `key`를 파일명으로 안전하게 만든다. 영숫자/`-`/`_`가 아닌 문자(`/`, `.` 포함)는
/// 전부 `_`로 치환한다 — 슬래시나 `..`가 남지 않으므로 `key`가 무엇이든 `dir` 밖으로 escape할
/// 수 없다. 결과가 비면(전부 치환 대상이었던 경우) 고정 문자열로 대체한다.
fn sanitize_key(key: &str) -> String {
    let mapped: String = key
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = mapped.trim_matches('_');
    let truncated: String = trimmed.chars().take(128).collect();
    if truncated.is_empty() {
        "key".to_string()
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample_line(source: &str, service: &str, ts_millis: i64, message: &str) -> LogLine {
        LogLine {
            source: source.to_string(),
            service: service.to_string(),
            severity: "INFO".to_string(),
            message: message.to_string(),
            attrs: BTreeMap::new(),
            ts: chrono::DateTime::from_timestamp_millis(ts_millis).unwrap(),
            record_id: String::new(),
        }
    }

    #[test]
    fn ordered_ack_stops_at_gap() {
        let mut tracker = AckTracker::new();
        let a = tracker.issue();
        let b = tracker.issue();
        let c = tracker.issue();
        assert_eq!((a, b, c), (1, 2, 3));

        tracker.complete(2);
        tracker.complete(3);
        assert_eq!(
            tracker.committed(),
            0,
            "1이 아직 안 왔으니 committed는 0에 머물러야 함"
        );

        tracker.complete(1);
        assert_eq!(
            tracker.committed(),
            3,
            "구멍이 메워지면 연속 prefix 끝까지 점프해야 함"
        );
    }

    #[test]
    fn ordered_ack_advances_in_order() {
        let mut tracker = AckTracker::new();
        tracker.issue();
        tracker.issue();
        tracker.issue();

        tracker.complete(1);
        assert_eq!(tracker.committed(), 1);
        tracker.complete(2);
        assert_eq!(tracker.committed(), 2);
        tracker.complete(3);
        assert_eq!(tracker.committed(), 3);
    }

    #[test]
    fn record_id_is_stable_across_resend() {
        let line = sample_line("file", "nginx", 1_000, "hello");
        let id1 = record_id(Some("abcd1234:4096"), "host-a", &line);
        let id2 = record_id(Some("abcd1234:4096"), "host-a", &line);
        assert_eq!(id1, id2);
        assert_eq!(id1, "log:abcd1234:4096");
    }

    #[test]
    fn record_id_falls_back_to_content_hash_without_natural_key() {
        let line = sample_line("aic", "aicd", 1_000, "same content");
        let id1 = record_id(None, "host-a", &line);
        let id2 = record_id(None, "host-a", &line);
        assert_eq!(id1, id2, "동일 내용은 동일 id로 접혀야 함");

        let other = sample_line("aic", "aicd", 1_000, "different content");
        let id3 = record_id(None, "host-a", &other);
        assert_ne!(id1, id3, "다른 내용은 다른 id여야 함");
    }

    #[test]
    fn checkpoint_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(dir.path().to_path_buf()).unwrap();

        assert_eq!(store.load("journald"), None);

        store.save("journald", "s=abc123;i=456").unwrap();
        assert_eq!(store.load("journald"), Some("s=abc123;i=456".to_string()));

        store.save("journald", "s=abc123;i=789").unwrap();
        assert_eq!(store.load("journald"), Some("s=abc123;i=789".to_string()));
    }

    #[test]
    fn checkpoint_survives_crash() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(dir.path().to_path_buf()).unwrap();

        store.save("file/nginx", "fp:100").unwrap();

        // 다음 save가 tmp까지 쓰고 rename 전에 죽었다고 가정 — 찢어진 tmp가 남는다.
        let tmp_path = dir
            .path()
            .join(format!("{}.{TMP_EXT}", sanitize_key("file/nginx")));
        std::fs::write(&tmp_path, b"garbage-half-written").unwrap();

        assert_eq!(
            store.load("file/nginx"),
            Some("fp:100".to_string()),
            "찢어진 tmp가 아니라 마지막으로 rename된 값을 읽어야 함"
        );
    }

    #[test]
    fn corrupt_checkpoint_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(dir.path().to_path_buf()).unwrap();

        let path = dir
            .path()
            .join(format!("{}.{CHECKPOINT_EXT}", sanitize_key("journald")));
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0xff]).unwrap(); // 유효하지 않은 UTF-8

        assert_eq!(
            store.load("journald"),
            None,
            "손상된 파일은 panic 없이 None"
        );
    }

    #[test]
    fn checkpoint_key_is_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(dir.path().to_path_buf()).unwrap();

        let malicious = "file//../../etc/passwd";
        store.save(malicious, "should-not-escape").unwrap();

        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let parent = entry.path().parent().unwrap().to_path_buf();
            assert_eq!(
                parent,
                dir.path(),
                "체크포인트 파일이 dir 밖으로 나가면 안 됨"
            );
        }

        assert_eq!(store.load(malicious), Some("should-not-escape".to_string()));

        // 상위 디렉토리에 이 malicious key로 만들어질 법한 실제 경로가 없어야 한다.
        assert!(!dir.path().join("..").join("etc").join("passwd").exists());
    }
}
