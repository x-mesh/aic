//! `BoundaryOwnershipGate` — record 생성 경로 (local vs central) 단일 경계 보장 (task 4.4).
//!
//! # 배경
//!
//! Phase 3.4 Local_Fallback 경로(R9.3, R9.5)에서 aic-session 은 attach 연결이 끊기면
//! local `OutputProcessor` / `CommandBoundaryDetector` 로 돌아가고, 재연결이 성공하면
//! 다시 aicd central path 로 이관한다. 이 이관 구간에서 **같은 명령에 대한 record 가
//! local 과 central 양쪽에서 각각 생성되어 중복 저장되는 것**을 막아야 한다 (R9.5
//! "단 한 경로에서만 기록").
//!
//! `BoundaryOwnershipGate` 는 이 규칙을 세 가지 상태로 표현하는 atomic state machine
//! 이다:
//!
//! | owner      | local 이 record 를 emit? | central 이 record 를 emit? |
//! |------------|--------------------------|-----------------------------|
//! | Local      | yes                      | no (연결 없음)              |
//! | Central    | no (반환값 무시)         | yes                         |
//! | Transferring | yes (진행 중인 record 만 — replay) | yes (신규 bytes) |
//!
//! 이관 시 dedup 은 `CommandRecordStore::push_inner` 의 id 기반 중복 검사가 담당한다
//! (같은 task 에서 추가됨). local 이 replay 로 올린 record 와 central 이 자체 boundary
//! 로 만든 record 의 **id 가 동일**하므로 두 번째 push 는 자동으로 skip 된다.
//!
//! # API
//!
//! 본 task 의 핵심 API (task 설명 R9.3/R9.5/R14.5):
//!
//! - [`BoundaryOwnershipGate::local_should_emit`] — local `feed_line` 반환 record 를
//!   저장해도 되는지. `Central` 에서는 false 를 돌려주어 호출자가 반환값을 버리게 한다.
//! - [`BoundaryOwnershipGate::central_should_emit`] — central attach pool 이 확정한
//!   record 를 aicd store 에 push 해도 되는지. `Local` 에서는 false.
//! - [`BoundaryOwnershipGate::transfer_to_central`] — 재연결 성공 후 호출. `Local` 또는
//!   `Transferring` 에서 `Central` 로 이관한다.
//! - [`BoundaryOwnershipGate::transfer_to_local`] — attach 끊김 감지 후 호출. `Central`
//!   또는 `Transferring` 에서 `Local` 로 이관한다.
//! - [`BoundaryOwnershipGate::mark_transferring`] — 재연결 직후 replay 윈도우를 여는
//!   중간 상태. 호출자가 `local` 이 in-flight record 를 마무리해 aicd 로 replay 할 수
//!   있는 시간을 확보하기 위한 opt-in. 이후 `transfer_to_central` 로 닫는다.
//! - [`BoundaryOwnershipGate::owner`] — 현재 상태 스냅샷 getter.
//!
//! # Backoff schedule
//!
//! [`next_backoff`] 와 상수 [`INITIAL_BACKOFF`] / [`MAX_BACKOFF`] 은 재연결 루프가
//! 사용하는 지수 backoff 를 구현한다. 스케줄은 정확히 1s → 2s → 4s → 8s → 16s → 30s →
//! 30s (cap) 로 고정되어야 하며 (R9.3), 이 순서가 단위 테스트로 보장된다.
//!
//! # Scope
//!
//! 본 task 에서는 gate/backoff 의 핵심 상태 머신과 helper 만 제공한다. 실제 runtime
//! 의 "reconnect on signal → retry with backoff → transfer_to_central" 파이프라인은
//! [`crate::session_runtime`] 쪽에서 task 4.4 완료 후 attach_client.reconnect_signal 과
//! 묶이게 된다 (추후 통합 단계). [`reconnect_with_backoff`] 는 테스트 가능한 형태로
//! 재연결 루프의 골격을 구현해, 향후 통합 시 그대로 이식할 수 있다.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::metrics::AttachMetrics;

// ── 상수 ────────────────────────────────────────────────────────

/// 재연결 backoff 의 초기 대기 시간 (R9.3).
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// 재연결 backoff 의 상한 (R9.3). 지수 증가가 이 값에서 멈춘다.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

// ── Owner 상태 ─────────────────────────────────────────────────

/// Gate 가 관리하는 세 가지 상태. AtomicU8 payload 와 1:1 매핑된다.
///
/// - [`Local`]: attach 가 끊긴 상태. local path 가 단독으로 record 를 만든다.
/// - [`Central`]: attach 가 살아 있는 기본 상태. aicd 쪽 pool 만 record 를 만든다.
///   local feed_line 은 호출될 수 있으나 반환값을 **무시**한다 (R9.5).
/// - [`Transferring`]: 이관 진행 중. local 이 in-flight record 를 마무리해 aicd 에
///   replay 하고, 신규 PTY bytes 는 central 로 이동한다. 두 경로가 잠시 동시에 active 이
///   지만, 같은 record 의 경우 [`CommandRecordStore::push_inner`] 의 id dedup 이
///   중복 저장을 막는다.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoundaryOwner {
    Local = 0,
    Central = 1,
    Transferring = 2,
}

impl BoundaryOwner {
    /// raw atomic payload 로부터 안전하게 복원한다. 알 수 없는 값은 `Local` 로 매핑해
    /// fail-safe 를 유지한다 (local path 가 항상 존재하는 것이 덜 위험하다 — R9.2).
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Central,
            2 => Self::Transferring,
            _ => Self::Local,
        }
    }
}

// ── Gate ───────────────────────────────────────────────────────

/// 경계 소유권 게이트. 내부적으로 `AtomicU8` 하나만 들고 있어 cheap clone 가능하다.
///
/// 단일 aic-session runtime 이 하나의 인스턴스를 `Arc` 로 공유한다. writer loop,
/// reconnect task, local boundary detector 가 모두 같은 인스턴스를 참조한다.
#[derive(Debug)]
pub struct BoundaryOwnershipGate {
    owner: AtomicU8,
}

impl BoundaryOwnershipGate {
    /// 초기 상태를 지정해 gate 를 생성한다.
    ///
    /// - `Local` 은 attach 연결이 아직 없거나 실패한 Local_Fallback 진입 경로.
    /// - `Central` 은 attach 가 handshake 된 정상 경로.
    pub fn new(initial: BoundaryOwner) -> Self {
        Self {
            owner: AtomicU8::new(initial as u8),
        }
    }

    /// `Local` 로 시작하는 단축 생성자. attach 실패 시 호출 경로에서 사용한다.
    pub fn new_local() -> Self {
        Self::new(BoundaryOwner::Local)
    }

    /// `Central` 로 시작하는 단축 생성자. attach 가 성공한 경로에서 사용한다.
    pub fn new_central() -> Self {
        Self::new(BoundaryOwner::Central)
    }

    /// 현재 owner 값 스냅샷.
    ///
    /// `SeqCst` 가 아닌 `Acquire` 를 쓰는 이유: gate 상태 전환과 얽힌 external side
    /// effect (e.g. replay push) 가 이 load 이전에 완료되었음을 보장해야 하므로
    /// acquire-release 순서로 충분하다. transfer_to_* 는 대응해 `Release` 로 저장한다.
    pub fn owner(&self) -> BoundaryOwner {
        BoundaryOwner::from_u8(self.owner.load(Ordering::Acquire))
    }

    /// local path 가 record 를 저장소에 밀어넣어도 되는지.
    ///
    /// - `Local`, `Transferring` → true (local 이 active)
    /// - `Central` → false (local feed_line 반환값은 무시되어야 함, R9.5)
    pub fn local_should_emit(&self) -> bool {
        matches!(
            self.owner(),
            BoundaryOwner::Local | BoundaryOwner::Transferring
        )
    }

    /// central path (aicd pool) 가 record 를 aicd store 에 push 해도 되는지.
    ///
    /// - `Central`, `Transferring` → true
    /// - `Local` → false (attach 가 없어 central path 가 inactive)
    pub fn central_should_emit(&self) -> bool {
        matches!(
            self.owner(),
            BoundaryOwner::Central | BoundaryOwner::Transferring
        )
    }

    /// 재연결 직후 호출. gate 를 `Transferring` 으로 옮겨 replay 윈도우를 연다.
    ///
    /// 이 상태에서는:
    /// - local 이 in-flight record 를 마무리할 때 `local_should_emit() == true` 이므로
    ///   local store 에 push 하고, 호출자는 같은 record 를 aicd 에도 replay 한다.
    /// - central pool 은 신규 PTY bytes 로 새 record 를 만들어 push 한다 — local 의
    ///   replay 와 id 가 같은 경우 `CommandRecordStore::push_inner` 의 dedup 에 걸려
    ///   두 번째 push 가 skip 된다 (R9.5).
    ///
    /// `transfer_to_central` 과 분리되어 있는 이유는 호출자가 replay 동작을 수행할 수
    /// 있는 명시적 윈도우를 열어 주기 위함이다. 호출자가 Transferring 를 거칠 필요가
    /// 없다면 바로 `transfer_to_central` 을 호출해도 동일한 최종 상태가 된다.
    pub fn mark_transferring(&self) {
        self.owner
            .store(BoundaryOwner::Transferring as u8, Ordering::Release);
    }

    /// `Local` 또는 `Transferring` 에서 `Central` 로 이관한다 (R9.3, R9.5).
    ///
    /// 재연결 task 가 `AttachClient::connect` 를 성공시킨 직후 호출한다. 호출 이후:
    /// - local `feed_line` 반환 record 는 무시된다 (`local_should_emit() == false`).
    /// - 신규 PTY bytes 는 central path 가 단독 처리한다.
    ///
    /// 이미 `Central` 상태이면 no-op 이다. `Local` → `Central` 직접 이동도 허용되지만,
    /// 그 경우 in-flight record replay 를 수행할 수 없으므로 호출자는 replay 가 필요
    /// 없는 경우 (e.g. 맨 처음 attach 성공) 에만 이 short-cut 을 사용해야 한다.
    pub fn transfer_to_central(&self) {
        self.owner
            .store(BoundaryOwner::Central as u8, Ordering::Release);
    }

    /// `Central` 또는 `Transferring` 에서 `Local` 로 이관한다 (R9.3).
    ///
    /// attach 가 끊긴 것을 writer loop 가 감지했을 때 호출된다. 이후 local path 가
    /// 단독으로 record 를 만들어 Local_Fallback 을 제공한다 (R9.6).
    pub fn transfer_to_local(&self) {
        self.owner
            .store(BoundaryOwner::Local as u8, Ordering::Release);
    }
}

impl Default for BoundaryOwnershipGate {
    /// Default 는 `Local` — attach 가 아직 없는 보수적 시작점.
    fn default() -> Self {
        Self::new_local()
    }
}

// ── Backoff schedule ───────────────────────────────────────────

/// 직전 backoff 로부터 다음 backoff 를 계산한다 (R9.3, R14.5).
///
/// 규칙:
/// 1. `prev < INITIAL_BACKOFF` 이면 `INITIAL_BACKOFF` (= 1s) 로 시작.
/// 2. 그 외에는 `prev * 2`.
/// 3. 결과가 `MAX_BACKOFF` (= 30s) 을 넘으면 `MAX_BACKOFF` 로 cap.
///
/// 정확한 시퀀스: 1s → 2s → 4s → 8s → 16s → 30s → 30s → … (cap 유지). 단위 테스트
/// `backoff_schedule_is_exact` 가 이 시퀀스를 직접 검증한다.
///
/// `saturating_mul` 로 overflow 를 막고, `Duration::min` 으로 cap 을 적용한다.
pub fn next_backoff(prev: Duration) -> Duration {
    if prev < INITIAL_BACKOFF {
        return INITIAL_BACKOFF;
    }
    let doubled = prev.saturating_mul(2);
    if doubled > MAX_BACKOFF {
        MAX_BACKOFF
    } else {
        doubled
    }
}

// ── Reconnect loop (재사용 가능한 helper) ──────────────────────

/// 재연결 루프의 한 단일 attempt 결과. 테스트/통합 모두에서 재사용된다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectOutcome {
    /// 재연결 성공. 호출자는 `gate.transfer_to_central()` 을 호출하고 새 client 를
    /// 적용한다. `attempts` 는 성공까지 걸린 시도 횟수 (1-based) 이다.
    Connected { attempts: u32 },
    /// 상위 shutdown 신호에 의해 루프가 중단되었다.
    Cancelled,
}

/// 재연결 시도를 지수 backoff 로 반복한다 (R9.3, R14.5). 성공 시 gate 를 Central 로
/// 이관한다.
///
/// # 파라미터
/// - `connect`: 각 시도에서 호출되는 async closure. `Ok(())` 이면 성공으로 간주하고
///   루프를 탈출한다. `Err(_)` 이면 `attach_reconnect_total` 을 +1 하고 다음 backoff
///   만큼 sleep 한 뒤 재시도한다.
/// - `sleep`: 테스트에서 시간을 조작할 수 있도록 sleep 구현을 주입한다. production 에서는
///   `tokio::time::sleep` 을 그대로 넘긴다.
/// - `cancel`: 상위 shutdown 신호. true 를 반환하면 루프가 즉시 종료된다.
///
/// # 동작
/// 1. attempt=1 부터 시작, backoff=`INITIAL_BACKOFF` (1s).
/// 2. `connect()` 호출.
///    - `Ok(())` 이면 `gate.transfer_to_central()` 호출 후 `Connected { attempts }` 반환.
///    - `Err(_)` 이면 `metrics.inc_attach_reconnect()` 호출, `sleep(backoff)`, backoff =
///      `next_backoff(backoff)` 로 업데이트.
/// 3. 각 반복 전 `cancel()` 이 true 면 `Cancelled` 반환.
///
/// 본 helper 는 session_runtime 통합 이전에도 단위 테스트로 backoff 시퀀스와
/// reconnect_total 동작을 검증할 수 있게 해 준다.
#[allow(dead_code)] // session_runtime 통합은 후속 PR.
pub async fn reconnect_with_backoff<F, Fut, E, S, SF, C>(
    gate: &BoundaryOwnershipGate,
    metrics: Arc<AttachMetrics>,
    mut connect: F,
    mut sleep: S,
    mut cancel: C,
) -> ReconnectOutcome
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
    S: FnMut(Duration) -> SF,
    SF: std::future::Future<Output = ()>,
    C: FnMut() -> bool,
{
    let mut backoff = INITIAL_BACKOFF;
    let mut attempts: u32 = 0;

    loop {
        if cancel() {
            return ReconnectOutcome::Cancelled;
        }
        attempts = attempts.saturating_add(1);
        match connect(attempts).await {
            Ok(()) => {
                gate.transfer_to_central();
                return ReconnectOutcome::Connected { attempts };
            }
            Err(_e) => {
                metrics.inc_attach_reconnect();
                sleep(backoff).await;
                backoff = next_backoff(backoff);
            }
        }
    }
}

// ── Unit tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Gate transitions ───────────────────────────────────────

    /// Default 와 `new_local` 은 모두 `Local` 로 시작해야 한다.
    #[test]
    fn initial_state_is_local() {
        let g = BoundaryOwnershipGate::default();
        assert_eq!(g.owner(), BoundaryOwner::Local);
        assert!(g.local_should_emit());
        assert!(!g.central_should_emit());

        let g2 = BoundaryOwnershipGate::new_local();
        assert_eq!(g2.owner(), BoundaryOwner::Local);
    }

    /// `new_central` 은 `Central` 로 시작하고 local path 는 방출하지 않아야 한다.
    #[test]
    fn new_central_starts_in_central() {
        let g = BoundaryOwnershipGate::new_central();
        assert_eq!(g.owner(), BoundaryOwner::Central);
        assert!(!g.local_should_emit());
        assert!(g.central_should_emit());
    }

    /// 핵심 전환 시퀀스: Local → transfer_to_central → Central.
    #[test]
    fn local_to_central_via_transfer() {
        let g = BoundaryOwnershipGate::new_local();
        assert_eq!(g.owner(), BoundaryOwner::Local);
        g.transfer_to_central();
        assert_eq!(g.owner(), BoundaryOwner::Central);
        assert!(!g.local_should_emit());
        assert!(g.central_should_emit());
    }

    /// 핵심 전환 시퀀스: Central → transfer_to_local → Local.
    #[test]
    fn central_to_local_via_transfer() {
        let g = BoundaryOwnershipGate::new_central();
        g.transfer_to_local();
        assert_eq!(g.owner(), BoundaryOwner::Local);
        assert!(g.local_should_emit());
        assert!(!g.central_should_emit());
    }

    /// Transferring 상태에서는 양쪽 경로 모두 emit 할 수 있어야 한다 (R9.5 replay 윈도우).
    #[test]
    fn transferring_state_allows_both_paths() {
        let g = BoundaryOwnershipGate::new_local();
        g.mark_transferring();
        assert_eq!(g.owner(), BoundaryOwner::Transferring);
        // 이관 윈도우에서는 local (in-flight replay) 과 central (신규 bytes) 가 모두 active.
        assert!(g.local_should_emit());
        assert!(g.central_should_emit());
    }

    /// 전체 이관 사이클: Local → Transferring → Central → Transferring → Local.
    /// "transitions through Transferring state" 를 정면으로 검증한다.
    #[test]
    fn full_transition_cycle_goes_through_transferring() {
        let g = BoundaryOwnershipGate::new_local();
        assert_eq!(g.owner(), BoundaryOwner::Local);

        // 재연결 직후 replay 윈도우 오픈.
        g.mark_transferring();
        assert_eq!(g.owner(), BoundaryOwner::Transferring);
        assert!(g.local_should_emit() && g.central_should_emit());

        // replay 완료 → Central 커밋.
        g.transfer_to_central();
        assert_eq!(g.owner(), BoundaryOwner::Central);
        assert!(!g.local_should_emit() && g.central_should_emit());

        // 나중에 attach 끊김 → 역방향으로 다시 Transferring 을 거친다.
        g.mark_transferring();
        assert_eq!(g.owner(), BoundaryOwner::Transferring);

        g.transfer_to_local();
        assert_eq!(g.owner(), BoundaryOwner::Local);
        assert!(g.local_should_emit() && !g.central_should_emit());
    }

    /// 동일 상태 재호출은 no-op 이어야 한다 (idempotency).
    #[test]
    fn transfer_calls_are_idempotent() {
        let g = BoundaryOwnershipGate::new_central();
        g.transfer_to_central();
        g.transfer_to_central();
        assert_eq!(g.owner(), BoundaryOwner::Central);

        g.transfer_to_local();
        g.transfer_to_local();
        assert_eq!(g.owner(), BoundaryOwner::Local);
    }

    /// `BoundaryOwner::from_u8` 는 알려진 값 그대로 매핑하고 나머지는 `Local` 로
    /// 매핑해야 한다 — fail-safe 기본값.
    #[test]
    fn owner_from_u8_handles_known_and_unknown() {
        assert_eq!(BoundaryOwner::from_u8(0), BoundaryOwner::Local);
        assert_eq!(BoundaryOwner::from_u8(1), BoundaryOwner::Central);
        assert_eq!(BoundaryOwner::from_u8(2), BoundaryOwner::Transferring);
        // 비정상 payload 는 Local 로 매핑되어야 함.
        assert_eq!(BoundaryOwner::from_u8(3), BoundaryOwner::Local);
        assert_eq!(BoundaryOwner::from_u8(255), BoundaryOwner::Local);
    }

    // ── Backoff schedule ───────────────────────────────────────

    /// 스케줄은 1s → 2s → 4s → 8s → 16s → 30s → 30s (cap) 로 고정되어야 한다 (R9.3).
    #[test]
    fn backoff_schedule_is_exact() {
        // 첫 호출: "아직 시도 안 함" 에서 1s 로 진입.
        let mut d = next_backoff(Duration::from_secs(0));
        assert_eq!(d, Duration::from_secs(1), "1차 backoff 는 1s 이어야 함");

        // 1s → 2s → 4s → 8s → 16s → 30s → 30s → 30s …
        let expected = [
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
        ];
        for (i, exp) in expected.iter().enumerate() {
            d = next_backoff(d);
            assert_eq!(
                d, *exp,
                "스텝 {}: 기대 {:?}, 실제 {:?}",
                i + 1,
                exp,
                d
            );
        }
    }

    /// cap 근방에서 정확히 멈추는지 — 16s 의 double 은 32s 이지만 30s 로 clamp.
    #[test]
    fn backoff_caps_at_thirty_seconds() {
        // 16s 의 다음은 2배인 32s 가 아니라 30s 여야 한다.
        let next = next_backoff(Duration::from_secs(16));
        assert_eq!(next, Duration::from_secs(30));

        // 이미 30s 이면 그대로 30s.
        let stable = next_backoff(Duration::from_secs(30));
        assert_eq!(stable, Duration::from_secs(30));

        // cap 을 넘는 비정상 입력이 들어와도 30s 로 clamp — defensive.
        let clamped = next_backoff(Duration::from_secs(120));
        assert_eq!(clamped, Duration::from_secs(30));
    }

    /// overflow 안전성 — 엄청나게 큰 Duration 이 들어와도 패닉 없이 cap 으로 수렴.
    #[test]
    fn backoff_is_overflow_safe() {
        let huge = Duration::from_secs(u64::MAX / 2);
        let clamped = next_backoff(huge);
        assert_eq!(clamped, MAX_BACKOFF);
    }

    // ── reconnect_with_backoff ─────────────────────────────────

    /// 첫 시도에서 성공하면 gate 가 즉시 Central 로 이관되고 reconnect 카운터는 0 이다.
    #[tokio::test]
    async fn reconnect_succeeds_on_first_attempt() {
        let gate = BoundaryOwnershipGate::new_local();
        let metrics = Arc::new(AttachMetrics::new());
        let slept: std::sync::Arc<std::sync::Mutex<Vec<Duration>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let slept_capture = std::sync::Arc::clone(&slept);
        let outcome = reconnect_with_backoff(
            &gate,
            Arc::clone(&metrics),
            |_attempt| async { Ok::<(), &'static str>(()) },
            move |d| {
                let slept_capture = std::sync::Arc::clone(&slept_capture);
                async move {
                    slept_capture.lock().unwrap().push(d);
                }
            },
            || false,
        )
        .await;

        assert_eq!(outcome, ReconnectOutcome::Connected { attempts: 1 });
        assert_eq!(gate.owner(), BoundaryOwner::Central);
        assert_eq!(metrics.attach_reconnect_total(), 0);
        assert!(
            slept.lock().unwrap().is_empty(),
            "성공 시 sleep 은 일어나지 않아야 함"
        );
    }

    /// 실패 → 실패 → 성공 시나리오. sleep 값이 backoff schedule 과 일치하고
    /// `attach_reconnect_total` 이 실패 횟수만큼 증가해야 한다 (R14.5).
    #[tokio::test]
    async fn reconnect_applies_backoff_and_increments_metrics() {
        let gate = BoundaryOwnershipGate::new_local();
        let metrics = Arc::new(AttachMetrics::new());
        let slept: std::sync::Arc<std::sync::Mutex<Vec<Duration>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        // 처음 3 번 실패, 4 번째 성공.
        let attempt_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempt_count_c = std::sync::Arc::clone(&attempt_count);

        let slept_capture = std::sync::Arc::clone(&slept);
        let outcome = reconnect_with_backoff(
            &gate,
            Arc::clone(&metrics),
            move |_attempt| {
                let attempt_count_c = std::sync::Arc::clone(&attempt_count_c);
                async move {
                    let n = attempt_count_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if n < 3 {
                        Err("fake-io-error")
                    } else {
                        Ok::<(), &'static str>(())
                    }
                }
            },
            move |d| {
                let slept_capture = std::sync::Arc::clone(&slept_capture);
                async move {
                    slept_capture.lock().unwrap().push(d);
                }
            },
            || false,
        )
        .await;

        assert_eq!(outcome, ReconnectOutcome::Connected { attempts: 4 });
        assert_eq!(gate.owner(), BoundaryOwner::Central);
        // 3 번 실패했으므로 reconnect 카운터는 3.
        assert_eq!(metrics.attach_reconnect_total(), 3);
        // sleep 스케줄은 1s → 2s → 4s (세 번 실패 후 네 번째 시도가 성공하므로
        // sleep 은 실패 직후에만 적용).
        assert_eq!(
            *slept.lock().unwrap(),
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
            ]
        );
    }

    /// cancel 신호가 떨어지면 connect 를 시도하지 않고 즉시 Cancelled 를 반환한다.
    #[tokio::test]
    async fn reconnect_respects_cancel_signal() {
        let gate = BoundaryOwnershipGate::new_local();
        let metrics = Arc::new(AttachMetrics::new());

        let connect_calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = std::sync::Arc::clone(&connect_calls);

        let outcome = reconnect_with_backoff(
            &gate,
            Arc::clone(&metrics),
            move |_attempt| {
                let cc = std::sync::Arc::clone(&cc);
                async move {
                    cc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err("should not be called")
                }
            },
            |_d| async {},
            || true, // 즉시 cancel.
        )
        .await;

        assert_eq!(outcome, ReconnectOutcome::Cancelled);
        assert_eq!(gate.owner(), BoundaryOwner::Local);
        assert_eq!(
            connect_calls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "cancel 신호 하에서는 connect 를 호출하지 않아야 함"
        );
        assert_eq!(metrics.attach_reconnect_total(), 0);
    }
}
