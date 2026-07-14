//! 연속 실패용 exponential backoff (SRE t8).
//!
//! collector가 다운된 동안 매 tick/이벤트마다 그대로 두들기지 않기 위한 재시도 간격 계산기.
//! 1s → 2s → 4s → ... → 60s(cap) + jitter로 늘어나고, 성공 한 번으로 즉시 리셋된다. "실패
//! 상태에선 드레인/송신 시도 자체를 backoff 간격으로만" 하라는 t8 interface contract를
//! 그대로 구현한다 — [`Backoff::ready`]가 false면 호출부는 네트워크 시도를 아예 건너뛰고
//! (새 데이터는 spool에만 쌓는다) 다음 tick으로 넘어가야 한다.

use std::time::Duration;

use rand::Rng;

/// 첫 실패 후 재시도 간격.
const BASE: Duration = Duration::from_secs(1);
/// 재시도 간격 상한.
const CAP: Duration = Duration::from_secs(60);

pub struct Backoff {
    consecutive_failures: u32,
    next_allowed: tokio::time::Instant,
}

impl Backoff {
    pub fn new() -> Self {
        Self {
            consecutive_failures: 0,
            // 초기 상태는 즉시 시도 가능해야 한다(첫 tick부터 backoff에 걸리면 안 됨).
            next_allowed: tokio::time::Instant::now(),
        }
    }

    /// 지금 드레인/송신을 시도해도 되는지. backoff 윈도 안이면 false — 호출부는 네트워크 시도를
    /// 건너뛰고 새 데이터를 spool에만 적재해야 한다.
    pub fn ready(&self) -> bool {
        tokio::time::Instant::now() >= self.next_allowed
    }

    /// 성공 — 연속 실패 카운트를 리셋하고 다음 시도를 즉시 허용한다.
    pub fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_allowed = tokio::time::Instant::now();
    }

    /// 실패 — 연속 실패 카운트를 올리고 다음 허용 시각을 `delay_for(n) + jitter`만큼 뒤로 민다.
    pub fn on_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let delay = Self::delay_for(self.consecutive_failures);
        // additive jitter: delay의 최대 20%(최소 50ms)를 더해 여러 aicd 인스턴스가 동시에
        // 재시도를 몰아치는 thundering herd를 완화한다. full jitter(0..delay) 대신 additive를
        // 쓰는 이유는 최소 지연 보장(=요청 폭주 억제 효과)을 유지하기 위해서다.
        let jitter_max_ms = ((delay.as_millis() as u64) / 5).max(50);
        let jitter_ms = rand::thread_rng().gen_range(0..=jitter_max_ms);
        self.next_allowed = tokio::time::Instant::now() + delay + Duration::from_millis(jitter_ms);
    }

    /// n번째 연속 실패(1-indexed)에 대응하는 jitter 없는 기본 지연 — 1,2,4,8,16,32,60(cap),60,...
    fn delay_for(consecutive_failures: u32) -> Duration {
        let shift = consecutive_failures.saturating_sub(1).min(6); // 2^6=64s > CAP라 6에서 멈춰도 충분
        let base = BASE.saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX));
        base.min(CAP)
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_escalates_exponentially_then_caps() {
        assert_eq!(Backoff::delay_for(1), Duration::from_secs(1));
        assert_eq!(Backoff::delay_for(2), Duration::from_secs(2));
        assert_eq!(Backoff::delay_for(3), Duration::from_secs(4));
        assert_eq!(Backoff::delay_for(4), Duration::from_secs(8));
        assert_eq!(Backoff::delay_for(5), Duration::from_secs(16));
        assert_eq!(Backoff::delay_for(6), Duration::from_secs(32));
        assert_eq!(
            Backoff::delay_for(7),
            Duration::from_secs(60),
            "60s에서 cap"
        );
        assert_eq!(
            Backoff::delay_for(20),
            Duration::from_secs(60),
            "cap 이후로도 60s 유지"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ready_initially_true() {
        let backoff = Backoff::new();
        assert!(backoff.ready(), "첫 시도는 backoff 없이 즉시 가능해야 함");
    }

    #[tokio::test(start_paused = true)]
    async fn on_failure_blocks_until_delay_elapses() {
        let mut backoff = Backoff::new();
        backoff.on_failure();
        assert!(!backoff.ready(), "실패 직후엔 backoff 윈도 안이어야 함");

        // base delay(1s) + 최대 jitter(20%=200ms)보다 넉넉히 지나면 반드시 ready여야 한다.
        tokio::time::advance(Duration::from_millis(1300)).await;
        assert!(backoff.ready(), "1.3s 후엔 ready여야 함(1s+jitter<=1.2s)");
    }

    #[tokio::test(start_paused = true)]
    async fn on_success_resets_and_unblocks_immediately() {
        let mut backoff = Backoff::new();
        backoff.on_failure();
        backoff.on_failure();
        backoff.on_failure();
        assert!(!backoff.ready());

        backoff.on_success();
        assert!(backoff.ready(), "성공하면 즉시 재시도 가능해야 함");

        // 리셋 후 다시 실패하면 다시 1s부터 시작해야 한다(연속 실패 누적이 아니라).
        backoff.on_failure();
        tokio::time::advance(Duration::from_millis(1300)).await;
        assert!(backoff.ready(), "리셋 후 1회 실패는 1s대 지연이어야 함");
    }

    #[tokio::test(start_paused = true)]
    async fn on_failure_never_produces_shorter_than_base_delay() {
        // jitter는 항상 추가만 되어야 한다(음수 방향 없음) — 200ms 후엔 아직 ready면 안 됨.
        let mut backoff = Backoff::new();
        backoff.on_failure();
        tokio::time::advance(Duration::from_millis(200)).await;
        assert!(
            !backoff.ready(),
            "base delay(1s)보다 먼저 ready가 되면 안 됨"
        );
    }
}
