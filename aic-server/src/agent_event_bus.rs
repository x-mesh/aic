//! chat/agent 행위 tap — `AgentEvent`를 OTLP exporter로 fan-out하는 broadcast 채널.
//!
//! chat은 단명하는 `aic-client` 프로세스라 collector 연결·spool·backoff를 직접 들 수 없다.
//! 그래서 행위를 IPC(`IpcRequest::AgentEvent`)로 aicd에 넘기고, 상주 데몬이 무유실 전송을
//! 책임진다 — shell hook이 command를 넘기는 것과 같은 구조다.
//!
//! [`CommandRecordStore`](crate::command_record_store::CommandRecordStore)의 tap과 분리한 이유:
//! 그쪽은 **ring에 적재된 command record**를 fan-out하는 store의 부산물이라, 구독자가 없어도
//! record는 보존된다. 반면 agent 행위는 저장하지 않고 흘려보내기만 한다(로컬 조회 대상이 아니고
//! audit/tool_record가 이미 각자 기록한다). 저장 책임이 없는 것을 store에 얹으면 "ring에는 왜
//! 안 남지?"라는 혼선만 생긴다.
//!
//! **lossy tap**: 구독자(exporter)가 못 따라가면 초과분은 `RecvError::Lagged`로 유실된다.
//! 구독자가 아예 없으면(exporter 비활성) publish는 조용히 버려진다 — chat 쪽이 exporter 설정을
//! 알 필요가 없도록 하기 위함이다.

use aic_common::AgentEvent;
use tokio::sync::broadcast;

/// tap 채널 용량. command tap(`EVENTS_TAP_CAPACITY` = 256)보다 작게 잡는다 — agent 행위는
/// 사람의 chat 속도에 묶여 있어 command만큼 몰아치지 않는다.
const AGENT_TAP_CAPACITY: usize = 64;

/// agent 행위 broadcast. clone해도 같은 채널을 가리킨다.
#[derive(Clone)]
pub struct AgentEventBus {
    tx: broadcast::Sender<AgentEvent>,
}

impl AgentEventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(AGENT_TAP_CAPACITY);
        Self { tx }
    }

    /// exporter task가 구독한다. late subscribe 이전 이벤트는 받지 못한다(replay 없음).
    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.tx.subscribe()
    }

    /// 행위를 fan-out한다. 구독자가 없으면(exporter 비활성) 조용히 버린다 — 이건 정상 경로다.
    pub fn publish(&self, ev: AgentEvent) {
        let _ = self.tx.send(ev);
    }

    /// 현재 구독자 수. exporter가 붙었는지 확인하는 테스트용.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for AgentEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ev(kind: &str) -> AgentEvent {
        AgentEvent {
            kind: kind.to_string(),
            summary: "s".to_string(),
            severity: "INFO".to_string(),
            attrs: BTreeMap::new(),
            ts: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn subscriber_receives_published_event() {
        let bus = AgentEventBus::new();
        let mut rx = bus.subscribe();
        bus.publish(ev("tool.run_command"));
        let got = rx.recv().await.expect("이벤트 수신");
        assert_eq!(got.kind, "tool.run_command");
    }

    #[tokio::test]
    async fn publish_without_subscriber_is_silently_dropped() {
        // exporter가 비활성이면 구독자가 없다 — chat 쪽이 그걸 알 필요 없이 그냥 publish한다.
        let bus = AgentEventBus::new();
        assert_eq!(bus.receiver_count(), 0);
        bus.publish(ev("risk.denied")); // 패닉/에러 없이 버려져야 한다.
    }

    #[tokio::test]
    async fn every_subscriber_gets_every_event() {
        let bus = AgentEventBus::new();
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        bus.publish(ev("finding.created"));
        assert_eq!(a.recv().await.unwrap().kind, "finding.created");
        assert_eq!(b.recv().await.unwrap().kind, "finding.created");
    }
}
