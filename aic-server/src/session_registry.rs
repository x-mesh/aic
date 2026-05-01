//! `aicd` in-memory 세션 registry (Phase 1.3 server-side).
//!
//! 디자인:
//! - 동시성: `tokio::sync::RwLock<HashMap<String, SessionInfo>>`. read-heavy
//!   (`ListSessions`)이고 write는 register/unregister/state 변경뿐이라 RwLock이
//!   적합하다.
//! - 영속성 없음: 현재는 in-memory. PRD R2에서 언급된 파일 기반 복구는
//!   별도 sub-step에서 추가한다.
//! - 이 모듈은 client wiring(`aic-session`이 register를 부르는 부분)에는
//!   관여하지 않는다 — Phase 1.4에서 wiring한다.

use aic_common::{SessionInfo, SessionState};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

const SNAPSHOT_MAX_AGE: Duration = Duration::hours(24);

/// 공유 가능한 registry handle. clone은 cheap (Arc).
#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<RwLock<HashMap<String, SessionInfo>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_sessions(sessions: Vec<SessionInfo>) -> Self {
        let map = sessions
            .into_iter()
            .map(|info| (info.id.clone(), info))
            .collect();
        Self {
            inner: Arc::new(RwLock::new(map)),
        }
    }

    /// 새 세션을 등록한다. 같은 id가 이미 있으면 덮어쓴다 (re-attach 시나리오).
    pub async fn register(&self, info: SessionInfo) {
        let mut guard = self.inner.write().await;
        guard.insert(info.id.clone(), info);
    }

    /// 세션을 제거한다. 없는 id는 no-op.
    pub async fn unregister(&self, id: &str) -> bool {
        let mut guard = self.inner.write().await;
        guard.remove(id).is_some()
    }

    /// 세션 상태를 갱신한다. id가 없으면 false 반환.
    pub async fn set_state(&self, id: &str, state: SessionState) -> bool {
        let mut guard = self.inner.write().await;
        if let Some(info) = guard.get_mut(id) {
            info.state = state;
            true
        } else {
            false
        }
    }

    /// heartbeat 수신 시 last_seen_at/cwd/state를 갱신한다.
    pub async fn heartbeat(
        &self,
        id: &str,
        seen_at: DateTime<Utc>,
        cwd: Option<std::path::PathBuf>,
    ) -> bool {
        let mut guard = self.inner.write().await;
        if let Some(info) = guard.get_mut(id) {
            info.last_seen_at = Some(seen_at);
            if cwd.is_some() {
                info.cwd = cwd;
            }
            if matches!(info.state, SessionState::Detached | SessionState::Failed) {
                info.state = SessionState::Attached;
            }
            true
        } else {
            false
        }
    }

    /// hook-only 세션은 `aic-session` register가 없으므로 command start에서 upsert한다.
    pub async fn upsert_hook_session(
        &self,
        id: &str,
        pid: u32,
        shell: Option<String>,
        cwd: Option<std::path::PathBuf>,
        at: DateTime<Utc>,
    ) {
        let mut guard = self.inner.write().await;
        guard
            .entry(id.to_string())
            .and_modify(|info| {
                info.pid = pid;
                info.state = SessionState::Attached;
                info.last_seen_at = Some(at);
                info.last_command_at = Some(at);
                if shell.is_some() {
                    info.shell = shell.clone();
                }
                if cwd.is_some() {
                    info.cwd = cwd.clone();
                }
            })
            .or_insert_with(|| SessionInfo {
                id: id.to_string(),
                pid,
                state: SessionState::Attached,
                created_at: at,
                last_seen_at: Some(at),
                last_command_at: Some(at),
                attached_tty: None,
                shell,
                cwd,
                label: None,
            });
    }

    /// 세션 label을 설정 또는 제거한다 (None으로 untag).
    /// 존재하지 않는 id면 false를 반환.
    pub async fn set_label(&self, id: &str, label: Option<String>) -> bool {
        let mut guard = self.inner.write().await;
        if let Some(info) = guard.get_mut(id) {
            info.label = label.filter(|s| !s.is_empty());
            true
        } else {
            false
        }
    }

    /// command finish처럼 시작 정보가 없는 이벤트에서도 liveness를 갱신한다.
    pub async fn touch_seen(&self, id: &str, seen_at: DateTime<Utc>) -> bool {
        let mut guard = self.inner.write().await;
        if let Some(info) = guard.get_mut(id) {
            info.last_seen_at = Some(seen_at);
            true
        } else {
            false
        }
    }

    /// 등록된 세션 정보를 created_at 오름차순으로 반환한다.
    pub async fn list(&self) -> Vec<SessionInfo> {
        let guard = self.inner.read().await;
        let mut out: Vec<SessionInfo> = guard.values().cloned().collect();
        out.sort_by_key(|s| s.created_at);
        out
    }

    /// 등록된 세션 수.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// 등록된 세션이 없는지 확인. clippy `len_without_is_empty` 보강.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }

    /// heartbeat가 오래 끊긴 active 세션을 Detached로 낮춘다.
    pub async fn mark_stale_active_detached(
        &self,
        now: DateTime<Utc>,
        stale_after: Duration,
    ) -> usize {
        let mut guard = self.inner.write().await;
        let mut changed = 0usize;
        for info in guard.values_mut() {
            if !matches!(info.state, SessionState::Attached | SessionState::Creating) {
                continue;
            }
            let last_seen = info.last_seen_at.unwrap_or(info.created_at);
            if now.signed_duration_since(last_seen) > stale_after {
                info.state = SessionState::Detached;
                info.attached_tty = None;
                changed += 1;
            }
        }
        changed
    }

    /// 오래된 inactive 세션을 제거한다.
    ///
    /// Attached/Creating은 살아 있는 세션일 수 있으므로 제거하지 않는다.
    pub async fn prune_inactive_older_than(
        &self,
        now: DateTime<Utc>,
        older_than: Duration,
    ) -> usize {
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, info| {
            if matches!(info.state, SessionState::Attached | SessionState::Creating) {
                return true;
            }
            let last_seen = info.last_seen_at.unwrap_or(info.created_at);
            now.signed_duration_since(last_seen) <= older_than
        });
        before.saturating_sub(guard.len())
    }

    /// registry snapshot을 JSON으로 저장한다.
    pub async fn save_snapshot(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let sessions = self.list().await;
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(&sessions)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// JSON snapshot을 읽어 registry를 복구한다.
    ///
    /// 재시작 직후에는 attach 상태를 신뢰할 수 없으므로 살아 있던 세션은 Detached로 낮춘다.
    /// 너무 오래된 항목은 버려 snapshot이 무한히 커지지 않게 한다.
    pub fn load_snapshot(path: &Path, now: DateTime<Utc>) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = std::fs::read_to_string(path)?;
        let mut sessions: Vec<SessionInfo> = serde_json::from_str(&content)?;
        sessions.retain(|info| {
            let last_seen = info.last_seen_at.unwrap_or(info.created_at);
            now.signed_duration_since(last_seen) <= SNAPSHOT_MAX_AGE
        });
        for info in &mut sessions {
            if matches!(info.state, SessionState::Attached | SessionState::Creating) {
                info.state = SessionState::Detached;
                info.attached_tty = None;
            }
        }
        Ok(Self::from_sessions(sessions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn info(id: &str, ts_offset_secs: i64) -> SessionInfo {
        let created_at = Utc::now() + chrono::Duration::seconds(ts_offset_secs);
        SessionInfo {
            id: id.to_string(),
            pid: 12345,
            state: SessionState::Attached,
            created_at,
            last_seen_at: Some(created_at),
            last_command_at: None,
            attached_tty: Some("/dev/ttys001".to_string()),
            shell: Some("/bin/zsh".to_string()),
            cwd: Some(PathBuf::from("/tmp")),
            label: None,
        }
    }

    #[tokio::test]
    async fn register_and_list_returns_inserted() {
        let r = SessionRegistry::new();
        r.register(info("aaaaaaaa", 0)).await;
        let list = r.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "aaaaaaaa");
    }

    #[tokio::test]
    async fn list_is_sorted_by_created_at_asc() {
        let r = SessionRegistry::new();
        r.register(info("newer", 10)).await;
        r.register(info("older", -10)).await;
        let list = r.list().await;
        assert_eq!(
            list.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["older", "newer"]
        );
    }

    #[tokio::test]
    async fn unregister_removes_entry() {
        let r = SessionRegistry::new();
        r.register(info("aaaaaaaa", 0)).await;
        assert!(r.unregister("aaaaaaaa").await);
        assert_eq!(r.len().await, 0);
    }

    #[tokio::test]
    async fn unregister_unknown_returns_false() {
        let r = SessionRegistry::new();
        assert!(!r.unregister("missing").await);
    }

    #[tokio::test]
    async fn re_register_same_id_overwrites() {
        let r = SessionRegistry::new();
        let mut first = info("aaaaaaaa", 0);
        first.attached_tty = Some("/dev/ttys001".to_string());
        r.register(first).await;

        let mut second = info("aaaaaaaa", 0);
        second.attached_tty = Some("/dev/ttys999".to_string());
        r.register(second).await;

        let list = r.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].attached_tty.as_deref(), Some("/dev/ttys999"));
    }

    #[tokio::test]
    async fn set_state_updates_existing_session() {
        let r = SessionRegistry::new();
        r.register(info("aaaaaaaa", 0)).await;
        assert!(r.set_state("aaaaaaaa", SessionState::Detached).await);
        let list = r.list().await;
        assert_eq!(list[0].state, SessionState::Detached);
    }

    #[tokio::test]
    async fn set_state_unknown_returns_false() {
        let r = SessionRegistry::new();
        assert!(!r.set_state("missing", SessionState::Stopped).await);
    }

    #[tokio::test]
    async fn heartbeat_updates_seen_and_cwd() {
        let r = SessionRegistry::new();
        r.register(info("aaaaaaaa", 0)).await;
        let seen = Utc::now();
        assert!(
            r.heartbeat("aaaaaaaa", seen, Some(PathBuf::from("/work")))
                .await
        );

        let list = r.list().await;
        assert_eq!(list[0].last_seen_at, Some(seen));
        assert_eq!(list[0].cwd.as_deref(), Some(std::path::Path::new("/work")));
    }

    #[tokio::test]
    async fn heartbeat_without_cwd_preserves_existing_cwd() {
        let r = SessionRegistry::new();
        r.register(info("aaaaaaaa", 0)).await;
        let before = r.list().await[0].cwd.clone();
        let seen = Utc::now();

        assert!(r.heartbeat("aaaaaaaa", seen, None).await);

        let list = r.list().await;
        assert_eq!(list[0].last_seen_at, Some(seen));
        assert_eq!(list[0].cwd, before);
    }

    #[tokio::test]
    async fn upsert_hook_session_creates_missing_entry() {
        let r = SessionRegistry::new();
        let at = Utc::now();
        r.upsert_hook_session(
            "aaaaaaaa",
            999,
            Some("zsh".to_string()),
            Some(PathBuf::from("/tmp")),
            at,
        )
        .await;

        let list = r.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "aaaaaaaa");
        assert_eq!(list[0].pid, 999);
        assert_eq!(list[0].created_at, at);
        assert_eq!(list[0].last_seen_at, Some(at));
        assert_eq!(list[0].last_command_at, Some(at));
    }

    #[tokio::test]
    async fn snapshot_roundtrip_restores_detached_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let r = SessionRegistry::new();
        r.register(info("aaaaaaaa", 0)).await;
        r.save_snapshot(&path).await.unwrap();

        let restored = SessionRegistry::load_snapshot(&path, Utc::now()).unwrap();
        let list = restored.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "aaaaaaaa");
        assert_eq!(list[0].state, SessionState::Detached);
        assert_eq!(list[0].attached_tty, None);
    }

    #[tokio::test]
    async fn snapshot_load_drops_old_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let old = Utc::now() - chrono::Duration::hours(48);
        let r = SessionRegistry::from_sessions(vec![SessionInfo {
            id: "aaaaaaaa".to_string(),
            pid: 12345,
            state: SessionState::Attached,
            created_at: old,
            last_seen_at: Some(old),
            last_command_at: None,
            attached_tty: Some("/dev/ttys001".to_string()),
            shell: Some("/bin/zsh".to_string()),
            cwd: Some(PathBuf::from("/tmp")),
            label: None,
        }]);
        r.save_snapshot(&path).await.unwrap();

        let restored = SessionRegistry::load_snapshot(&path, Utc::now()).unwrap();
        assert!(restored.is_empty().await);
    }

    #[tokio::test]
    async fn prune_removes_only_old_inactive_entries() {
        let now = Utc::now();
        let old = now - chrono::Duration::hours(3);
        let r = SessionRegistry::from_sessions(vec![
            SessionInfo {
                id: "olddead".to_string(),
                pid: 1,
                state: SessionState::Detached,
                created_at: old,
                last_seen_at: Some(old),
                last_command_at: None,
                attached_tty: None,
                shell: None,
                cwd: None,
                label: None,
            },
            SessionInfo {
                id: "oldlive".to_string(),
                pid: 2,
                state: SessionState::Attached,
                created_at: old,
                last_seen_at: Some(old),
                last_command_at: None,
                attached_tty: Some("/dev/ttys001".to_string()),
                shell: None,
                cwd: None,
                label: None,
            },
            SessionInfo {
                id: "newdead".to_string(),
                pid: 3,
                state: SessionState::Detached,
                created_at: now,
                last_seen_at: Some(now),
                last_command_at: None,
                attached_tty: None,
                shell: None,
                cwd: None,
                label: None,
            },
        ]);

        let count = r
            .prune_inactive_older_than(now, chrono::Duration::hours(1))
            .await;
        assert_eq!(count, 1);

        let ids = r.list().await.into_iter().map(|s| s.id).collect::<Vec<_>>();
        assert_eq!(ids, vec!["oldlive", "newdead"]);
    }

    #[tokio::test]
    async fn mark_stale_active_detached_updates_only_old_active_entries() {
        let now = Utc::now();
        let old = now - chrono::Duration::minutes(2);
        let r = SessionRegistry::from_sessions(vec![
            SessionInfo {
                id: "oldlive".to_string(),
                pid: 1,
                state: SessionState::Attached,
                created_at: old,
                last_seen_at: Some(old),
                last_command_at: None,
                attached_tty: Some("/dev/ttys001".to_string()),
                shell: None,
                cwd: None,
                label: None,
            },
            SessionInfo {
                id: "newlive".to_string(),
                pid: 2,
                state: SessionState::Attached,
                created_at: now,
                last_seen_at: Some(now),
                last_command_at: None,
                attached_tty: Some("/dev/ttys002".to_string()),
                shell: None,
                cwd: None,
                label: None,
            },
            SessionInfo {
                id: "olddead".to_string(),
                pid: 3,
                state: SessionState::Stopped,
                created_at: old,
                last_seen_at: Some(old),
                last_command_at: None,
                attached_tty: None,
                shell: None,
                cwd: None,
                label: None,
            },
        ]);

        let count = r
            .mark_stale_active_detached(now, chrono::Duration::seconds(30))
            .await;
        assert_eq!(count, 1);

        let sessions = r.list().await;
        let old_live = sessions.iter().find(|s| s.id == "oldlive").unwrap();
        let new_live = sessions.iter().find(|s| s.id == "newlive").unwrap();
        assert_eq!(old_live.state, SessionState::Detached);
        assert_eq!(old_live.attached_tty, None);
        assert_eq!(new_live.state, SessionState::Attached);
    }
}
