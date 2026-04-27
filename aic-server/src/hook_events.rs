//! `aicd` hook-event 수신 버퍼 (Phase 3).
//!
//! shell hook이 보낸 `CommandStarted`/`CommandFinished` 이벤트를 session_id별로
//! 보관한다. 분석 시 client는 이 버퍼에서 마지막 metadata-only record를 읽는다.
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

/// 공유 가능한 hook event store.
#[derive(Clone, Default)]
pub struct HookEventStore {
    inner: Arc<RwLock<Inner>>,
}

impl HookEventStore {
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

        // cwd는 현재 CommandRecord에 직접 저장할 필드가 없어 trace 로그로만 흘린다.
        // 향후 CommandRecord에 cwd/duration_ms 필드 추가 시 함께 저장.
        let (command, cwd) = match pending {
            Some(p) => (Some(p.command), p.cwd),
            None => (None, None),
        };
        if cwd.is_some() || duration_ms > 0 {
            tracing::debug!(session_id, command_id, ?cwd, duration_ms, "hook finish");
        }

        let record = CommandRecord {
            command,
            exit_code,
            output_lines: Vec::new(),
            timestamp: finished_at,
            capture_mode: CaptureMode::Hook,
            capture_quality: CaptureQuality::MetadataOnly,
            output_metadata: None,
        };

        let ring = g
            .finished
            .entry(session_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(PER_SESSION_CAPACITY));
        if ring.len() == PER_SESSION_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(record);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn paired_start_finish_produces_full_metadata() {
        let s = HookEventStore::new();
        s.on_started("s1", "c1", "ls -la".into(), Some("/tmp".into()), Utc::now())
            .await;
        s.on_finished("s1", "c1", 0, Utc::now(), 5).await;
        let rec = s.last("s1").await.unwrap();
        assert_eq!(rec.command.as_deref(), Some("ls -la"));
        assert_eq!(rec.exit_code, 0);
        assert_eq!(rec.capture_mode, CaptureMode::Hook);
        assert_eq!(rec.capture_quality, CaptureQuality::MetadataOnly);
    }

    #[tokio::test]
    async fn finish_without_start_stores_partial_record() {
        let s = HookEventStore::new();
        s.on_finished("s1", "missing", 1, Utc::now(), 0).await;
        let rec = s.last("s1").await.unwrap();
        assert_eq!(rec.command, None);
        assert_eq!(rec.exit_code, 1);
        assert_eq!(rec.capture_quality, CaptureQuality::MetadataOnly);
    }

    #[tokio::test]
    async fn ring_evicts_oldest_at_capacity() {
        let s = HookEventStore::new();
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
        let s = HookEventStore::new();
        s.on_started("a", "c1", "in-a".into(), None, Utc::now())
            .await;
        s.on_finished("a", "c1", 0, Utc::now(), 0).await;
        s.on_started("b", "c1", "in-b".into(), None, Utc::now())
            .await;
        s.on_finished("b", "c1", 0, Utc::now(), 0).await;
        assert_eq!(s.last("a").await.unwrap().command.as_deref(), Some("in-a"));
        assert_eq!(s.last("b").await.unwrap().command.as_deref(), Some("in-b"));
    }
}
