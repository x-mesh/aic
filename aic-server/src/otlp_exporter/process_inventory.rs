//! 전체 프로세스 인벤토리 CDC(change-data-capture) 추적기 — `aic.process.inventory` scope.
//!
//! **무엇을/왜**: host metrics tick마다 sampler가 전수 프로세스 인벤토리([`ProcInv`])를 준다. 매
//! tick 전체를 다시 보내면 (프로세스 ~1000개 × 60초) 낭비이자 수신측 부담이다. 그래서 이 추적기가
//! **이전 tick과 diff**해 실제로 바뀐 것(생성 add / 소멸 remove / 속성 변경 change)만 방출한다.
//! 게이지(cpu/rss/io)는 여기서 다루지 않는다 — 그건 매 tick 변하는 값이라 delta로 압축되지 않고,
//! top-N `aic.process` 스냅샷이 이미 담당한다(상태=CDC / 메트릭=주기 스냅샷 분리).
//!
//! **식별자**: `(pid, start_time)`. pid는 재사용되므로 단독으로는 짧게 죽고 재사용된 프로세스가 한
//! 시계열에 섞인다 — start_time을 함께 키로 써 안정화한다([`ProcInv`] doc 참고).
//!
//! **재동기화(resync)**: delta 스트림은 한 프레임만 유실돼도(재접속·드롭) 소비자 상태가 틀어진다.
//! 그래서 (1) 매 batch에 단조 증가 `sequence`를 실어 소비자가 갭을 감지하고, (2) 주기적으로
//! **keyframe**(현재 전체 인벤토리 = 재동기화 기준점)을 낸다. 영상의 I-frame과 같은 개념이다.
//! 첫 tick은 항상 keyframe이다(소비자의 초기 상태).
//!
//! **비용 경계**: uid/container_id는 프로세스당 `/proc` 파일 읽기라 비싸다. 정적 속성이므로 살아
//! 있는 동안 재조회할 필요가 없어, **새로 등장한 프로세스(add)에만** enrich한다 — keyframe에서도
//! 이미 아는 프로세스는 저장된 값을 재사용하고 신규만 읽는다. 그래서 enrich 호출 수는 매 tick의
//! "새 프로세스 수"로 묶인다(보통 소수).

use std::collections::HashMap;

use super::host_metrics::ProcInv;

/// 프로세스 하나의 변화 종류. 와이어에는 [`ChangeOp::as_str`]로 실린다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOp {
    /// 이전 tick에 없던 프로세스가 등장.
    Added,
    /// 이전 tick에 있던 프로세스가 사라짐.
    Removed,
    /// 같은 `(pid, start_time)`인데 정적 속성(name/ppid)이 바뀜(exec 등, 드묾).
    Changed,
}

impl ChangeOp {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeOp::Added => "add",
            ChangeOp::Removed => "remove",
            ChangeOp::Changed => "change",
        }
    }
}

/// 방출할 인벤토리 변화 레코드 하나 — 변화 종류 + 식별 속성 + (add에 채운) 소유자/컨테이너.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvRecord {
    pub op: ChangeOp,
    pub pid: i64,
    pub ppid: i64,
    pub start_time: u64,
    pub name: String,
    pub uid: Option<u32>,
    pub container_id: Option<String>,
}

/// 한 tick diff 결과. `emit`이 false면 보낼 게 없다(delta인데 변화 0) — 호출부는 push를 건너뛰고
/// **sequence를 소비하지 않는다**(빈 프레임을 안 보내면서도 소비자의 갭 감지가 오작동하지 않게).
pub struct ChangeSet {
    /// 이 batch의 단조 증가 시퀀스(방출되는 batch에만 부여). 소비자가 갭을 감지한다.
    pub sequence: u64,
    /// 이 batch가 전체 스냅샷(재동기화 기준점)인지.
    pub keyframe: bool,
    /// 방출할 게 있는지(keyframe이거나 변화 레코드가 하나 이상).
    pub emit: bool,
    pub records: Vec<InvRecord>,
}

/// `(pid, start_time)`별로 마지막으로 관측한 정적 속성. uid/container는 add 때 한 번 채워 재사용한다.
#[derive(Clone)]
struct Stored {
    ppid: i64,
    name: String,
    uid: Option<u32>,
    container_id: Option<String>,
}

/// 이전 인벤토리 상태를 들고 tick마다 diff하는 CDC 추적기.
pub struct InventoryTracker {
    prev: HashMap<(i64, u64), Stored>,
    /// 지금까지 방출한 batch 수 = 마지막으로 부여한 sequence. 0이면 아직 아무것도 안 보냄(첫 diff는
    /// 무조건 keyframe).
    sequence: u64,
    /// 마지막 keyframe 이후 지난 tick 수(방출 여부와 무관하게 벽시계 tick을 센다).
    ticks_since_keyframe: u32,
    /// keyframe 주기(tick). 0이면 첫 tick 외에는 keyframe을 내지 않는다.
    keyframe_every: u32,
}

impl InventoryTracker {
    pub fn new(keyframe_every: u32) -> Self {
        Self {
            prev: HashMap::new(),
            sequence: 0,
            ticks_since_keyframe: 0,
            keyframe_every,
        }
    }

    /// 현재 인벤토리를 이전 상태와 diff한다. `enrich`는 새 프로세스의 (uid, container_id)를
    /// 구하는 함수다(Linux `/proc` 읽기 — 비-Linux는 `(None, None)`). add에만 호출된다.
    pub fn diff<F>(&mut self, current: &[ProcInv], enrich: F) -> ChangeSet
    where
        F: Fn(i64) -> (Option<u32>, Option<String>),
    {
        let keyframe = self.sequence == 0
            || (self.keyframe_every > 0 && self.ticks_since_keyframe >= self.keyframe_every);

        let mut records = Vec::new();

        if keyframe {
            // 전체 스냅샷. 이미 아는 프로세스는 저장된 uid/container 재사용, 신규만 enrich한다.
            let mut new_prev = HashMap::with_capacity(current.len());
            for p in current {
                let key = (p.pid, p.start_time);
                let (uid, container_id) = match self.prev.get(&key) {
                    Some(s) => (s.uid, s.container_id.clone()),
                    None => enrich(p.pid),
                };
                records.push(InvRecord {
                    op: ChangeOp::Added,
                    pid: p.pid,
                    ppid: p.ppid,
                    start_time: p.start_time,
                    name: p.name.clone(),
                    uid,
                    container_id: container_id.clone(),
                });
                new_prev.insert(
                    key,
                    Stored {
                        ppid: p.ppid,
                        name: p.name.clone(),
                        uid,
                        container_id,
                    },
                );
            }
            self.prev = new_prev;
            self.ticks_since_keyframe = 0;
        } else {
            // added / changed — current를 훑는다.
            for p in current {
                let key = (p.pid, p.start_time);
                match self.prev.get(&key) {
                    None => {
                        let (uid, container_id) = enrich(p.pid);
                        records.push(InvRecord {
                            op: ChangeOp::Added,
                            pid: p.pid,
                            ppid: p.ppid,
                            start_time: p.start_time,
                            name: p.name.clone(),
                            uid,
                            container_id: container_id.clone(),
                        });
                        self.prev.insert(
                            key,
                            Stored {
                                ppid: p.ppid,
                                name: p.name.clone(),
                                uid,
                                container_id,
                            },
                        );
                    }
                    Some(s) if s.ppid != p.ppid || s.name != p.name => {
                        // 정적 속성 변경(드묾) — uid/container는 그대로 재사용한다.
                        records.push(InvRecord {
                            op: ChangeOp::Changed,
                            pid: p.pid,
                            ppid: p.ppid,
                            start_time: p.start_time,
                            name: p.name.clone(),
                            uid: s.uid,
                            container_id: s.container_id.clone(),
                        });
                        let s = self.prev.get_mut(&key).expect("방금 조회한 키");
                        s.ppid = p.ppid;
                        s.name = p.name.clone();
                    }
                    Some(_) => {} // 변화 없음.
                }
            }
            // removed — prev에 있으나 current에 없는 키.
            let cur_keys: std::collections::HashSet<(i64, u64)> =
                current.iter().map(|p| (p.pid, p.start_time)).collect();
            let removed_keys: Vec<(i64, u64)> = self
                .prev
                .keys()
                .filter(|k| !cur_keys.contains(*k))
                .copied()
                .collect();
            for key in removed_keys {
                let s = self.prev.remove(&key).expect("방금 열거한 키");
                records.push(InvRecord {
                    op: ChangeOp::Removed,
                    pid: key.0,
                    ppid: s.ppid,
                    start_time: key.1,
                    name: s.name,
                    uid: s.uid,
                    container_id: s.container_id,
                });
            }
            self.ticks_since_keyframe += 1;
        }

        // sequence는 **방출하는 batch에만** 부여한다 — 빈 delta tick이 번호를 소비해 소비자에게
        // 가짜 갭으로 보이지 않게 한다.
        let emit = keyframe || !records.is_empty();
        if emit {
            self.sequence += 1;
        }
        ChangeSet {
            sequence: self.sequence,
            keyframe,
            emit,
            records,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn inv(pid: i64, start: u64, name: &str) -> ProcInv {
        ProcInv {
            pid,
            ppid: 1,
            start_time: start,
            name: name.to_string(),
        }
    }

    /// enrich를 세지 않는 기본 스텁(uid/container 없음).
    fn no_enrich(_pid: i64) -> (Option<u32>, Option<String>) {
        (None, None)
    }

    #[test]
    fn first_tick_is_keyframe_with_all_processes() {
        let mut t = InventoryTracker::new(0);
        let cur = vec![inv(10, 100, "a"), inv(20, 200, "b")];
        let cs = t.diff(&cur, no_enrich);
        assert!(cs.keyframe);
        assert!(cs.emit);
        assert_eq!(cs.sequence, 1);
        assert_eq!(cs.records.len(), 2);
        assert!(cs.records.iter().all(|r| r.op == ChangeOp::Added));
    }

    #[test]
    fn added_and_removed_are_emitted_as_delta() {
        let mut t = InventoryTracker::new(0);
        t.diff(&[inv(10, 100, "a"), inv(20, 200, "b")], no_enrich); // seq 1 keyframe
        // b가 죽고 c가 태어남.
        let cs = t.diff(&[inv(10, 100, "a"), inv(30, 300, "c")], no_enrich);
        assert!(!cs.keyframe);
        assert!(cs.emit);
        assert_eq!(cs.sequence, 2);
        let mut ops: Vec<_> = cs
            .records
            .iter()
            .map(|r| (r.op, r.pid))
            .collect();
        ops.sort_by_key(|(_, pid)| *pid);
        assert_eq!(ops, vec![(ChangeOp::Removed, 20), (ChangeOp::Added, 30)]);
    }

    #[test]
    fn unchanged_tick_does_not_emit_or_consume_sequence() {
        let mut t = InventoryTracker::new(0);
        let cur = vec![inv(10, 100, "a")];
        t.diff(&cur, no_enrich); // seq 1 keyframe
        let cs = t.diff(&cur, no_enrich); // 변화 없음
        assert!(!cs.emit);
        assert!(cs.records.is_empty());
        // 방출 안 했으니 sequence는 그대로 1 — 다음 실제 변화가 2를 받아 갭이 안 생긴다.
        let cs2 = t.diff(&[inv(10, 100, "a"), inv(11, 110, "z")], no_enrich);
        assert!(cs2.emit);
        assert_eq!(cs2.sequence, 2);
    }

    #[test]
    fn keyframe_recurs_on_cadence_and_reuses_known_enrichment() {
        let enrich_calls = Cell::new(0);
        let counting = |pid: i64| {
            enrich_calls.set(enrich_calls.get() + 1);
            (Some(pid as u32), None)
        };
        let mut t = InventoryTracker::new(2); // 2 tick마다 keyframe
        let cur = vec![inv(10, 100, "a")];
        let cs1 = t.diff(&cur, counting); // seq1 keyframe, enrich 1회(신규 a)
        assert!(cs1.keyframe);
        assert_eq!(enrich_calls.get(), 1);
        // tick2: 변화 없음 → emit 안 함, ticks_since_keyframe=1
        let cs2 = t.diff(&cur, counting);
        assert!(!cs2.emit);
        // tick3: ticks_since_keyframe(1) < 2라 아직 keyframe 아님, 변화도 없음
        let cs3 = t.diff(&cur, counting);
        assert!(!cs3.emit);
        // tick4: ticks_since_keyframe가 2에 도달 → keyframe. a는 이미 알아서 enrich 재호출 없음.
        let before = enrich_calls.get();
        let cs4 = t.diff(&cur, counting);
        assert!(cs4.keyframe);
        assert!(cs4.emit);
        assert_eq!(cs4.sequence, 2, "방출된 batch는 keyframe1, keyframe4 두 번뿐");
        assert_eq!(enrich_calls.get(), before, "keyframe이라도 아는 프로세스는 재-enrich 안 함");
    }

    #[test]
    fn add_enriches_only_new_process() {
        let enrich_calls = Cell::new(0);
        let counting = |pid: i64| {
            enrich_calls.set(enrich_calls.get() + 1);
            (Some(7), Some(format!("c{pid}")))
        };
        let mut t = InventoryTracker::new(0);
        t.diff(&[inv(10, 100, "a")], counting); // keyframe, enrich a (1회)
        assert_eq!(enrich_calls.get(), 1);
        let cs = t.diff(&[inv(10, 100, "a"), inv(20, 200, "b")], counting);
        assert_eq!(enrich_calls.get(), 2, "기존 a는 재-enrich 없이 신규 b만");
        let b = cs.records.iter().find(|r| r.pid == 20).unwrap();
        assert_eq!(b.uid, Some(7));
        assert_eq!(b.container_id.as_deref(), Some("c20"));
    }

    #[test]
    fn same_pid_reused_after_exit_is_add_not_change() {
        let mut t = InventoryTracker::new(0);
        t.diff(&[inv(10, 100, "old")], no_enrich); // keyframe
        // pid 10이 죽고 같은 pid가 새 start_time으로 재사용됨 → (pid,start) 키가 달라 remove+add.
        let cs = t.diff(&[inv(10, 555, "new")], no_enrich);
        let mut ops: Vec<_> = cs.records.iter().map(|r| (r.op, r.start_time)).collect();
        ops.sort_by_key(|(_, st)| *st);
        assert_eq!(ops, vec![(ChangeOp::Removed, 100), (ChangeOp::Added, 555)]);
    }

    #[test]
    fn changed_name_same_identity_is_change_op() {
        let mut t = InventoryTracker::new(0);
        t.diff(&[inv(10, 100, "before")], no_enrich); // keyframe
        let cs = t.diff(&[inv(10, 100, "after")], no_enrich);
        assert_eq!(cs.records.len(), 1);
        assert_eq!(cs.records[0].op, ChangeOp::Changed);
        assert_eq!(cs.records[0].name, "after");
    }
}
