//! `aicd` command record store (Phase 3.x 이후 중앙 저장소).
//!
//! `HookEventStore`에서 승격된 모듈이다. 기존 hook event 수신 버퍼 역할을
//! 그대로 유지하면서, Phase 3.1 ~ 3.5에서 PTY record(`capture_mode=Pty`)와
//! explicit capture record(`capture_mode=ExplicitCapture`)까지 같은 ring에
//! 수용하도록 확장된다.
//!
//! Phase 3.1 — Task 1.1 변경사항:
//! - `push_pty` / `push_explicit` / `recent` / `find_by_prefix` 신규 async API 추가.
//! - 내부 `push_inner` 헬퍼로 id auto-assign / 보존 및 ring 상한 관리 로직을 통일.
//! - 기존 `on_started` / `on_finished` / `last` / `len` 의 public 시그니처는 유지.
//!
//! 디자인:
//! - per-session bounded ring (기본 64). 메모리 누적 방지.
//! - command_id로 start/finish 매칭. start 후 timeout 안에 finish 없으면 Abandoned.
//! - 본 모듈은 PTY ring buffer와 분리되어 있다 — capture_quality가 다르기 때문.

use aic_common::{CaptureMode, CaptureQuality, CommandRecord};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// 각 세션이 보유하는 ring 크기 (record 단위).
const PER_SESSION_CAPACITY: usize = 64;

/// 미완료 start record를 식별하기 위한 (session_id, command_id) → start info 임시 표.
#[derive(Debug, Clone)]
struct PendingStart {
    command: String,
    cwd: Option<std::path::PathBuf>,
    /// finish 매칭 시 duration 보정/Abandoned timeout 정리에 사용 — 현재는 finish 이벤트에
    /// 포함된 duration_ms를 그대로 쓰지만 이 필드는 향후 timeout/cleanup 경로에서 필요하다.
    #[allow(dead_code)]
    started_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Default)]
struct Inner {
    /// session_id → 완료된 CommandRecord ring.
    finished: HashMap<String, VecDeque<CommandRecord>>,
    /// (session_id, command_id) → 미완료 start info.
    pending: HashMap<(String, String), PendingStart>,
}

/// 공유 가능한 command record store.
///
/// 기존 `HookEventStore`를 승격한 이름으로, public API 시그니처와 동작은
/// 동일하게 유지된다.
#[derive(Clone, Default)]
pub struct CommandRecordStore {
    inner: Arc<RwLock<Inner>>,
}

impl CommandRecordStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 새 command 시작 이벤트를 기록한다. pending에 보관해 두고 finish를 기다린다.
    pub async fn on_started(
        &self,
        session_id: &str,
        command_id: &str,
        command: String,
        cwd: Option<std::path::PathBuf>,
        started_at: chrono::DateTime<chrono::Utc>,
    ) {
        let mut g = self.inner.write().await;
        g.pending.insert(
            (session_id.to_string(), command_id.to_string()),
            PendingStart {
                command,
                cwd,
                started_at,
            },
        );
    }

    /// 완료 이벤트를 기록한다. 매칭되는 start가 있으면 합쳐서 record를 만든다.
    /// 매칭되는 start가 없으면 partial record(`command = None`)로 저장한다.
    pub async fn on_finished(
        &self,
        session_id: &str,
        command_id: &str,
        exit_code: i32,
        finished_at: chrono::DateTime<chrono::Utc>,
        duration_ms: u64,
    ) {
        let mut g = self.inner.write().await;
        let pending = g
            .pending
            .remove(&(session_id.to_string(), command_id.to_string()));

        let (command, cwd) = match pending {
            Some(p) => (Some(p.command), p.cwd),
            None => (None, None),
        };

        let record = CommandRecord {
            id: String::new(), // push_inner가 auto-assign
            command,
            exit_code,
            output_lines: Vec::new(),
            timestamp: finished_at,
            capture_mode: CaptureMode::Hook,
            capture_quality: CaptureQuality::MetadataOnly,
            output_metadata: None,
            cwd: cwd.map(|p| p.to_string_lossy().into_owned()),
            duration_ms: (duration_ms > 0).then_some(duration_ms),
        };

        let ring = g
            .finished
            .entry(session_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(PER_SESSION_CAPACITY));
        push_inner(ring, record);
    }

    /// 특정 세션의 마지막 record를 반환한다.
    pub async fn last(&self, session_id: &str) -> Option<CommandRecord> {
        let g = self.inner.read().await;
        g.finished.get(session_id).and_then(|r| r.back().cloned())
    }

    /// 특정 세션의 모든 record 수.
    pub async fn len(&self, session_id: &str) -> usize {
        self.inner
            .read()
            .await
            .finished
            .get(session_id)
            .map(|r| r.len())
            .unwrap_or(0)
    }

    // ── Phase 3.1 신규 API (R1.2 ~ R1.5) ───────────────────────────────

    /// PTY 경로(OutputProcessor + BoundaryDetector)가 만든 record를 push한다.
    /// `record.capture_mode`는 반드시 `CaptureMode::Pty`이어야 한다.
    ///
    /// R1.2, R1.6, R1.7, R1.8: id 비어 있으면 auto-assign, 이미 있으면 보존.
    /// ring 상한 도달 시 `pop_front`.
    pub async fn push_pty(&self, session_id: &str, record: CommandRecord) {
        debug_assert!(
            matches!(record.capture_mode, CaptureMode::Pty),
            "push_pty expects CaptureMode::Pty, got {:?}",
            record.capture_mode
        );
        let mut g = self.inner.write().await;
        let ring = g
            .finished
            .entry(session_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(PER_SESSION_CAPACITY));
        push_inner(ring, record);
    }

    /// `aic run -- <cmd>` 처럼 명시 wrapper가 만든 record를 push한다.
    /// `record.capture_mode`는 반드시 `CaptureMode::ExplicitCapture`이어야 한다.
    pub async fn push_explicit(&self, session_id: &str, record: CommandRecord) {
        debug_assert!(
            matches!(record.capture_mode, CaptureMode::ExplicitCapture),
            "push_explicit expects CaptureMode::ExplicitCapture, got {:?}",
            record.capture_mode
        );
        let mut g = self.inner.write().await;
        let ring = g
            .finished
            .entry(session_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(PER_SESSION_CAPACITY));
        push_inner(ring, record);
    }

    /// 세션의 최근 `count`개 record를 시간순(oldest → newest)으로 반환한다.
    ///
    /// R1.4: VecDeque의 `iter().rev().take(count).rev()` 패턴.
    /// `count == 0` 또는 ring이 비어 있으면 빈 Vec를 반환한다.
    pub async fn recent(&self, session_id: &str, count: usize) -> Vec<CommandRecord> {
        if count == 0 {
            return Vec::new();
        }
        let g = self.inner.read().await;
        match g.finished.get(session_id) {
            Some(ring) => ring
                .iter()
                .rev()
                .take(count)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            None => Vec::new(),
        }
    }

    /// session 내 record id prefix 매칭 결과를 시간순으로 반환한다.
    ///
    /// R1.5: `prefix`가 빈 문자열이면 빈 Vec를 반환한다 (전체 덤프 금지).
    pub async fn find_by_prefix(
        &self,
        session_id: &str,
        prefix: &str,
    ) -> Vec<CommandRecord> {
        if prefix.is_empty() {
            return Vec::new();
        }
        let g = self.inner.read().await;
        match g.finished.get(session_id) {
            Some(ring) => ring
                .iter()
                .filter(|r| r.id.starts_with(prefix))
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }
}

/// session ring에 record를 push하면서 id auto-assign / 보존과 상한 관리를 통일한다.
///
/// - R1.6: `record.id`가 비어 있으면 `aic_common::generate_record_id()`로 16-hex 부여.
/// - R1.7: 비어 있지 않으면 그대로 보존.
/// - R1.8: ring 상한 도달 시 `pop_front`로 가장 오래된 record를 제거.
/// - R9.5 (task 4.4): **id 기반 dedup** — 같은 `record.id` 가 이미 ring 에 존재하면
///   새 record 로 덮어쓰지 않고 skip 한다. 이 보호는 [`BoundaryOwnershipGate`] 의
///   `Transferring` 상태 동안 local replay 와 central pool 이 동시에 같은 record 를
///   push 할 때 발생하는 "이중 저장" 을 근본적으로 차단하기 위함이다 (R9.5 "단 한
///   경로에서만 기록"). 첫 번째로 들어온 record 가 "정답" 으로 유지된다.
///
/// dedup 은 `record.id` 가 **비어 있지 않은** 경우에만 수행한다. 빈 id 로 들어오는
/// record 는 이 호출 시점에 새 16-hex id 를 부여받으므로 기존 record 와 충돌할 일이
/// 통계적으로 없다 (R1.6). 지역적인 O(N) 선형 탐색이지만 N ≤ 64 (PER_SESSION_CAPACITY)
/// 이므로 worst-case 비용도 무시 가능하다.
///
/// [`BoundaryOwnershipGate`]: crate::boundary_ownership_gate::BoundaryOwnershipGate
fn push_inner(ring: &mut VecDeque<CommandRecord>, mut record: CommandRecord) {
    if record.id.is_empty() {
        record.id = aic_common::generate_record_id();
    } else if ring.iter().any(|existing| existing.id == record.id) {
        // 같은 id 가 이미 있으면 기존 record 를 유지하고 새 push 는 drop 한다 (R9.5).
        tracing::trace!(
            id = %record.id,
            "CommandRecordStore dedup: 이미 존재하는 id 로 push — skip (R9.5)"
        );
        return;
    }
    if ring.len() == PER_SESSION_CAPACITY {
        ring.pop_front();
    }
    ring.push_back(record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn pty_record(id: &str, command: &str) -> CommandRecord {
        CommandRecord {
            id: id.to_string(),
            command: Some(command.to_string()),
            exit_code: 0,
            output_lines: vec![format!("out-{command}")],
            timestamp: Utc::now(),
            capture_mode: CaptureMode::Pty,
            capture_quality: CaptureQuality::FullOutput,
            output_metadata: None,
            cwd: None,
            duration_ms: None,
        }
    }

    fn explicit_record(id: &str, command: &str) -> CommandRecord {
        CommandRecord {
            id: id.to_string(),
            command: Some(command.to_string()),
            exit_code: 0,
            output_lines: vec![format!("out-{command}")],
            timestamp: Utc::now(),
            capture_mode: CaptureMode::ExplicitCapture,
            capture_quality: CaptureQuality::FullOutput,
            output_metadata: None,
            cwd: None,
            duration_ms: None,
        }
    }

    #[tokio::test]
    async fn paired_start_finish_produces_full_metadata() {
        let s = CommandRecordStore::new();
        s.on_started("s1", "c1", "ls -la".into(), Some("/tmp".into()), Utc::now())
            .await;
        s.on_finished("s1", "c1", 0, Utc::now(), 5).await;
        let rec = s.last("s1").await.unwrap();
        assert_eq!(rec.command.as_deref(), Some("ls -la"));
        assert_eq!(rec.exit_code, 0);
        assert_eq!(rec.capture_mode, CaptureMode::Hook);
        assert_eq!(rec.capture_quality, CaptureQuality::MetadataOnly);
        // start 이벤트의 cwd와 finish 이벤트의 duration이 record로 옮겨진다.
        assert_eq!(rec.cwd.as_deref(), Some("/tmp"));
        assert_eq!(rec.duration_ms, Some(5));
        // Hook record 역시 push_inner를 통해 16-hex id를 받는다.
        assert_eq!(rec.id.len(), 16);
    }

    #[tokio::test]
    async fn finish_without_start_stores_partial_record() {
        let s = CommandRecordStore::new();
        s.on_finished("s1", "missing", 1, Utc::now(), 0).await;
        let rec = s.last("s1").await.unwrap();
        assert_eq!(rec.command, None);
        assert_eq!(rec.exit_code, 1);
        assert_eq!(rec.capture_quality, CaptureQuality::MetadataOnly);
    }

    #[tokio::test]
    async fn ring_evicts_oldest_at_capacity() {
        let s = CommandRecordStore::new();
        for i in 0..(PER_SESSION_CAPACITY + 5) {
            s.on_started("s1", &format!("c{i}"), format!("cmd{i}"), None, Utc::now())
                .await;
            s.on_finished("s1", &format!("c{i}"), 0, Utc::now(), 0)
                .await;
        }
        assert_eq!(s.len("s1").await, PER_SESSION_CAPACITY);
        let last = s.last("s1").await.unwrap();
        assert_eq!(
            last.command.as_deref(),
            Some(format!("cmd{}", PER_SESSION_CAPACITY + 4).as_str())
        );
    }

    #[tokio::test]
    async fn separate_sessions_do_not_collide() {
        let s = CommandRecordStore::new();
        s.on_started("a", "c1", "in-a".into(), None, Utc::now())
            .await;
        s.on_finished("a", "c1", 0, Utc::now(), 0).await;
        s.on_started("b", "c1", "in-b".into(), None, Utc::now())
            .await;
        s.on_finished("b", "c1", 0, Utc::now(), 0).await;
        assert_eq!(s.last("a").await.unwrap().command.as_deref(), Some("in-a"));
        assert_eq!(s.last("b").await.unwrap().command.as_deref(), Some("in-b"));
    }

    // ── Phase 3.1 Task 1.1 신규 테스트 ──────────────────────────────────

    /// id가 비어 있으면 push_pty/push_explicit 모두 16-hex id를 auto-assign (R1.6).
    #[tokio::test]
    async fn push_auto_assigns_id_when_empty() {
        let s = CommandRecordStore::new();
        s.push_pty("s1", pty_record("", "ls")).await;
        s.push_explicit("s1", explicit_record("", "grep")).await;
        let recs = s.recent("s1", 10).await;
        assert_eq!(recs.len(), 2);
        for r in &recs {
            assert_eq!(r.id.len(), 16, "auto-assigned id must be 16 hex chars");
            assert!(
                r.id.chars().all(|c| c.is_ascii_hexdigit()),
                "auto-assigned id must be lowercase hex, got {}",
                r.id
            );
        }
        // 서로 다른 id이어야 한다.
        assert_ne!(recs[0].id, recs[1].id);
    }

    /// 입력 id가 비어 있지 않으면 그대로 보존 (R1.7).
    #[tokio::test]
    async fn push_preserves_non_empty_id() {
        let s = CommandRecordStore::new();
        let explicit_id = "deadbeefcafef00d".to_string();
        s.push_pty("s1", pty_record(&explicit_id, "ls")).await;

        let custom_id = "my-custom-id-42".to_string();
        s.push_explicit("s1", explicit_record(&custom_id, "grep"))
            .await;

        let recs = s.recent("s1", 10).await;
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].id, explicit_id);
        assert_eq!(recs[1].id, custom_id);
    }

    /// recent은 oldest → newest 순서여야 한다 (R1.4).
    #[tokio::test]
    async fn recent_returns_oldest_to_newest_order() {
        let s = CommandRecordStore::new();
        for i in 0..5 {
            s.push_pty("s1", pty_record(&format!("id{i:02}"), &format!("cmd{i}")))
                .await;
        }
        let all = s.recent("s1", 10).await;
        assert_eq!(all.len(), 5);
        for (i, r) in all.iter().enumerate() {
            assert_eq!(r.command.as_deref(), Some(format!("cmd{i}").as_str()));
        }

        // count가 ring 크기보다 작으면 tail만 반환하며 순서는 유지된다.
        let tail = s.recent("s1", 3).await;
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].command.as_deref(), Some("cmd2"));
        assert_eq!(tail[1].command.as_deref(), Some("cmd3"));
        assert_eq!(tail[2].command.as_deref(), Some("cmd4"));

        // count 0 → 빈 Vec.
        assert!(s.recent("s1", 0).await.is_empty());
        // 존재하지 않는 세션 → 빈 Vec.
        assert!(s.recent("missing", 10).await.is_empty());
    }

    /// recent은 ring 상한 도달 시 가장 오래된 record가 제거되어도 tail 순서를 보존해야 한다 (R1.4, R1.8).
    #[tokio::test]
    async fn recent_after_ring_eviction_preserves_order() {
        let s = CommandRecordStore::new();
        let total = PER_SESSION_CAPACITY + 10;
        for i in 0..total {
            s.push_pty(
                "s1",
                pty_record(&format!("id{i:03}"), &format!("cmd{i}")),
            )
            .await;
        }
        assert_eq!(s.len("s1").await, PER_SESSION_CAPACITY);
        let recs = s.recent("s1", PER_SESSION_CAPACITY).await;
        assert_eq!(recs.len(), PER_SESSION_CAPACITY);
        // 가장 오래된 record는 총 개수 - 용량 만큼 앞의 것이 제거된 뒤의 것이다.
        let oldest_surviving = total - PER_SESSION_CAPACITY;
        assert_eq!(
            recs[0].command.as_deref(),
            Some(format!("cmd{oldest_surviving}").as_str())
        );
        assert_eq!(
            recs.last().unwrap().command.as_deref(),
            Some(format!("cmd{}", total - 1).as_str())
        );
    }

    /// find_by_prefix: 빈 prefix → 빈 Vec / 매칭 / no-match 세 경우 (R1.5).
    #[tokio::test]
    async fn find_by_prefix_empty_match_and_no_match() {
        let s = CommandRecordStore::new();
        s.push_pty("s1", pty_record("abcd1234aaaa0000", "ls")).await;
        s.push_pty("s1", pty_record("abcd1234bbbb1111", "grep")).await;
        s.push_pty("s1", pty_record("ffff0000deadbeef", "cat")).await;

        // 빈 prefix → 빈 Vec.
        assert!(s.find_by_prefix("s1", "").await.is_empty());

        // prefix 매칭 → 시간순 유지.
        let matches = s.find_by_prefix("s1", "abcd1234").await;
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].command.as_deref(), Some("ls"));
        assert_eq!(matches[1].command.as_deref(), Some("grep"));

        // 더 긴 prefix로 단일 record.
        let one = s.find_by_prefix("s1", "abcd1234bbbb").await;
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].command.as_deref(), Some("grep"));

        // no-match → 빈 Vec.
        assert!(s.find_by_prefix("s1", "zzzz").await.is_empty());

        // 존재하지 않는 세션 → 빈 Vec.
        assert!(s.find_by_prefix("other", "abcd").await.is_empty());
    }

    /// 서로 다른 session 간 격리: 한 세션의 recent/find_by_prefix가 다른 세션 record를 포함하지 않는다 (R1.9).
    #[tokio::test]
    async fn push_isolation_across_sessions() {
        let s = CommandRecordStore::new();
        // interleave push across sessions.
        s.push_pty("a", pty_record("aaaa000000000001", "a-first"))
            .await;
        s.push_explicit("b", explicit_record("bbbb000000000001", "b-first"))
            .await;
        s.push_pty("a", pty_record("aaaa000000000002", "a-second"))
            .await;
        s.push_explicit("b", explicit_record("bbbb000000000002", "b-second"))
            .await;

        let a_recs = s.recent("a", 10).await;
        let b_recs = s.recent("b", 10).await;
        assert_eq!(a_recs.len(), 2);
        assert_eq!(b_recs.len(), 2);
        for r in &a_recs {
            assert!(r.command.as_deref().unwrap().starts_with("a-"));
            assert!(r.id.starts_with("aaaa"));
        }
        for r in &b_recs {
            assert!(r.command.as_deref().unwrap().starts_with("b-"));
            assert!(r.id.starts_with("bbbb"));
        }

        // find_by_prefix도 세션 경계를 넘지 않는다.
        let a_matches = s.find_by_prefix("a", "aaaa").await;
        let b_matches = s.find_by_prefix("b", "aaaa").await;
        assert_eq!(a_matches.len(), 2);
        assert!(b_matches.is_empty());

        // last도 세션별로 독립이다.
        assert_eq!(s.last("a").await.unwrap().id, "aaaa000000000002");
        assert_eq!(s.last("b").await.unwrap().id, "bbbb000000000002");
    }

    // ── Task 4.4: id 기반 dedup (R9.5) ─────────────────────────────────

    /// 같은 id 로 두 번 push 하면 두 번째 push 는 무시되고, 첫 번째 record 가 그대로
    /// 유지되어야 한다 (R9.5 "단 한 경로에서만 기록").
    #[tokio::test]
    async fn dedup_by_id_keeps_first_push_and_drops_duplicate() {
        let s = CommandRecordStore::new();
        let id = "deadbeef00000001".to_string();

        // 첫 push: command="ls", output_lines=["first"].
        let mut first = pty_record(&id, "ls");
        first.output_lines = vec!["first".to_string()];
        s.push_pty("s1", first).await;

        // 두 번째 push: 같은 id 지만 다른 command/output.
        let mut second = pty_record(&id, "rm -rf /");
        second.output_lines = vec!["should-not-appear".to_string()];
        s.push_pty("s1", second).await;

        // ring 에는 1 개만 있어야 하고, 그것은 첫 번째 record 여야 한다.
        assert_eq!(s.len("s1").await, 1, "dedup 이 적용되지 않아 2 개가 저장됨");
        let recs = s.recent("s1", 10).await;
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, id);
        assert_eq!(
            recs[0].command.as_deref(),
            Some("ls"),
            "dedup 이 두 번째 push 로 덮어쓴 것으로 보임 — 첫 번째가 유지되어야 함"
        );
        assert_eq!(recs[0].output_lines, vec!["first".to_string()]);
    }

    /// dedup 은 explicit capture mode 에도 동일하게 적용된다.
    #[tokio::test]
    async fn dedup_by_id_applies_to_explicit_push() {
        let s = CommandRecordStore::new();
        let id = "cafef00dcafef00d".to_string();

        s.push_explicit("s1", explicit_record(&id, "echo first")).await;
        s.push_explicit("s1", explicit_record(&id, "echo second")).await;

        assert_eq!(s.len("s1").await, 1);
        assert_eq!(
            s.last("s1").await.unwrap().command.as_deref(),
            Some("echo first")
        );
    }

    /// dedup 은 동일 id 가 다른 capture_mode 로 들어와도 적용된다 — 같은 record 를
    /// Transferring 구간에서 local (Pty) 과 central (Pty) 양쪽이 replay 할 때의 보호.
    #[tokio::test]
    async fn dedup_by_id_crosses_push_api_boundary() {
        let s = CommandRecordStore::new();
        let id = "ffff000011112222".to_string();

        s.push_pty("s1", pty_record(&id, "pty-first")).await;
        // 가상의 replay 경로가 같은 id 로 다시 push (예: local 이 record 를 마무리 후
        // aicd 에 RegisterRecordForSession 으로 올려 다시 push 되는 경로). dedup 이
        // 두 번째를 drop 해야 한다.
        s.push_pty("s1", pty_record(&id, "pty-replay")).await;

        assert_eq!(s.len("s1").await, 1);
        assert_eq!(
            s.last("s1").await.unwrap().command.as_deref(),
            Some("pty-first")
        );
    }

    /// dedup 은 세션별 ring 에서만 동작한다 — 같은 id 가 다른 세션에 있으면 서로 다른
    /// ring 이므로 저장되어야 한다 (격리 유지).
    #[tokio::test]
    async fn dedup_is_scoped_per_session() {
        let s = CommandRecordStore::new();
        let id = "11112222aaaabbbb".to_string();

        s.push_pty("session-a", pty_record(&id, "a-cmd")).await;
        s.push_pty("session-b", pty_record(&id, "b-cmd")).await;

        // 두 세션 모두 각각 1 개씩 가져야 한다.
        assert_eq!(s.len("session-a").await, 1);
        assert_eq!(s.len("session-b").await, 1);
        assert_eq!(
            s.last("session-a").await.unwrap().command.as_deref(),
            Some("a-cmd")
        );
        assert_eq!(
            s.last("session-b").await.unwrap().command.as_deref(),
            Some("b-cmd")
        );
    }

    /// 빈 id 로 연속 push 하면 각각 새 16-hex id 를 부여받아 저장된다 — 빈 id 는
    /// dedup 대상이 아니다.
    #[tokio::test]
    async fn empty_id_push_is_not_deduped() {
        let s = CommandRecordStore::new();
        for i in 0..5 {
            s.push_pty("s1", pty_record("", &format!("cmd{i}"))).await;
        }
        let recs = s.recent("s1", 10).await;
        assert_eq!(recs.len(), 5, "빈 id 는 dedup 대상이 아니므로 5 개 모두 저장");
        // 부여된 id 들은 모두 서로 달라야 한다.
        let mut ids: Vec<&str> = recs.iter().map(|r| r.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 5, "자동 부여된 id 집합에 중복이 있음");
    }
}
