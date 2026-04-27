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
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 공유 가능한 registry handle. clone은 cheap (Arc).
#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<RwLock<HashMap<String, SessionInfo>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
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

    /// 등록된 세션 정보를 created_at 오름차순으로 반환한다.
    pub async fn list(&self) -> Vec<SessionInfo> {
        let guard = self.inner.read().await;
        let mut out: Vec<SessionInfo> = guard.values().cloned().collect();
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        out
    }

    /// 등록된 세션 수.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn info(id: &str, ts_offset_secs: i64) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            pid: 12345,
            state: SessionState::Attached,
            created_at: Utc::now() + chrono::Duration::seconds(ts_offset_secs),
            attached_tty: Some("/dev/ttys001".to_string()),
            shell: Some("/bin/zsh".to_string()),
            cwd: Some(PathBuf::from("/tmp")),
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
        assert_eq!(list.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec!["older", "newer"]);
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
}
