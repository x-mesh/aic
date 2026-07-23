//! 최근 프로세스 인벤토리 변화의 링 버퍼 + broadcast tap.
//!
//! **왜 있나**: OTLP exporter(`aic.process.inventory`)는 변화를 collector로 *내보내기만* 한다.
//! chat이 "방금 뭐가 떴다 죽었나"를 보려면 로컬에도 남아 있어야 하고, 그건 collector 설정과
//! 무관해야 한다 — OTLP를 안 켰다고 로컬 관측이 사라지면 곤란하기 때문이다. 그래서 tick이
//! 계산한 변화분을 여기에 먼저 쌓고, OTLP 전송은 그중 하나의 소비자로 둔다.
//!
//! **구조**: [`CommandRecordStore`](crate::command_record_store)와 같은 모양이다 — 유한 링
//! (`VecDeque`, [`CAPACITY`]) + `broadcast` tap. 링은 폴링(chat의 IPC 조회)이 읽고, tap은
//! 실시간 구독자가 읽는다. 둘을 함께 두는 이유: 폴링만 두면 tick 사이에 들어온 변화를 늦게
//! 보고, tap만 두면 **구독 이전** 변화를 영영 못 본다(broadcast는 late subscriber에게 과거를
//! 주지 않는다). 링이 "최근 이력", tap이 "지금부터"를 담당한다.
//!
//! **나중 확장**: RCA-eBPF(팀원의 eBPF 수집기) UDS 스트림도 결국 이 store에 **producer로**
//! 꽂힌다 — 그때 소비자(chat/OTLP)는 그대로 두고 생산자만 하나 늘리면 된다.

use std::collections::VecDeque;

use aic_common::ipc::ProcessChange;
use tokio::sync::{broadcast, RwLock};

/// 링에 보관할 최근 변화 수. 프로세스 기동이 몰리는 순간(부팅 직후·배포)에 한 tick이 수백 건을
/// 낼 수 있어, 한 tick 분이 통째로 밀려나지 않을 정도로 잡는다. 넘치면 오래된 것부터 버린다.
const CAPACITY: usize = 1024;

/// 실시간 tap 채널 용량. 구독자가 느려 밀리면 tokio broadcast가 그 구독자에게 `Lagged`를
/// 돌려주고 건너뛴다 — 링(폴링 경로)이 이력을 들고 있으므로 여기서의 유실은 치명적이지 않다.
const TAP_CAPACITY: usize = 256;

/// 최근 프로세스 인벤토리 변화를 들고 있는 공유 store.
#[derive(Debug)]
pub struct ProcessInventoryStore {
    ring: RwLock<VecDeque<ProcessChange>>,
    tap_tx: broadcast::Sender<ProcessChange>,
}

impl Default for ProcessInventoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessInventoryStore {
    pub fn new() -> Self {
        let (tap_tx, _rx) = broadcast::channel(TAP_CAPACITY);
        Self {
            ring: RwLock::new(VecDeque::with_capacity(CAPACITY)),
            tap_tx,
        }
    }

    /// 실시간 구독자를 붙인다. 구독 **이전**에 push된 변화는 오지 않는다(broadcast 의미론) —
    /// 과거가 필요하면 [`recent`](Self::recent)로 링을 읽는다.
    pub fn subscribe(&self) -> broadcast::Receiver<ProcessChange> {
        self.tap_tx.subscribe()
    }

    /// 한 tick 분 변화를 링에 넣고 tap으로 fan-out한다. 링이 가득 차면 오래된 것부터 버린다.
    ///
    /// tap send 실패(구독자 없음)는 **정상**이라 무시한다 — 아무도 안 보고 있을 뿐이다.
    pub async fn push_many(&self, changes: Vec<ProcessChange>) {
        if changes.is_empty() {
            return;
        }
        let mut ring = self.ring.write().await;
        for c in changes {
            if ring.len() == CAPACITY {
                ring.pop_front();
            }
            let _ = self.tap_tx.send(c.clone());
            ring.push_back(c);
        }
    }

    /// 최근 변화를 **최신순**으로 `count`개까지 돌려준다. 링은 오래된 것이 앞이라 뒤에서 훑는다.
    pub async fn recent(&self, count: usize) -> Vec<ProcessChange> {
        let ring = self.ring.read().await;
        ring.iter().rev().take(count).cloned().collect()
    }

    /// 현재 링에 쌓인 변화 수(테스트/진단용).
    pub async fn len(&self) -> usize {
        self.ring.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(pid: i64, op: &str) -> ProcessChange {
        ProcessChange {
            op: op.to_string(),
            pid,
            ppid: 1,
            start_time: 100,
            name: format!("p{pid}"),
            uid: None,
            container_id: None,
            observed_at: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn recent_returns_newest_first() {
        let s = ProcessInventoryStore::new();
        s.push_many(vec![change(1, "add"), change(2, "add"), change(3, "remove")])
            .await;
        let got = s.recent(2).await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].pid, 3, "가장 최근이 먼저");
        assert_eq!(got[1].pid, 2);
    }

    #[tokio::test]
    async fn ring_evicts_oldest_beyond_capacity() {
        let s = ProcessInventoryStore::new();
        let batch: Vec<_> = (0..(CAPACITY as i64 + 10)).map(|i| change(i, "add")).collect();
        s.push_many(batch).await;
        assert_eq!(s.len().await, CAPACITY);
        // 가장 오래된 10개가 밀려났으므로 남은 최솟값 pid는 10이다.
        let all = s.recent(CAPACITY).await;
        let min_pid = all.iter().map(|c| c.pid).min().unwrap();
        assert_eq!(min_pid, 10);
    }

    #[tokio::test]
    async fn subscriber_receives_pushed_changes() {
        let s = ProcessInventoryStore::new();
        let mut rx = s.subscribe();
        s.push_many(vec![change(7, "add")]).await;
        let got = rx.try_recv().expect("구독자에게 fan-out");
        assert_eq!(got.pid, 7);
        assert_eq!(got.op, "add");
    }

    #[tokio::test]
    async fn push_without_subscribers_is_fine_and_still_rings() {
        let s = ProcessInventoryStore::new();
        s.push_many(vec![change(1, "add")]).await;
        assert_eq!(s.len().await, 1);
    }

    #[tokio::test]
    async fn empty_push_is_noop() {
        let s = ProcessInventoryStore::new();
        s.push_many(Vec::new()).await;
        assert!(s.is_empty().await);
    }
}
