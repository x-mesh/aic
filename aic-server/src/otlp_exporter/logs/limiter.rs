//! 서비스당 token-bucket rate limit (RFC-006 t6 — 볼륨 안전장치 2/2, severity 필터 다음 단계).
//!
//! **고정 윈도우는 쓰지 않는다** — 윈도우 경계에서 `rate`만큼(윈도우 끝) + `rate`만큼(다음
//! 윈도우 시작)이 거의 동시에 통과해 순간 2배 버스트가 그대로 새 나간다. token bucket은
//! `capacity = burst`(기본 `rate`와 동일)에서 시작해 경과 시간에 비례해서만 채우므로 이 버스트를
//! 만들지 않는다.
//!
//! **카디널리티 방어(필수).** 서비스 이름이 매 라인 다르면(로그에서 드물지 않다) 버킷 맵이
//! 무한 성장해 OOM으로 이어진다. `max_services`를 넘으면 가장 최근에 쓰이지 않은(LRU) 버킷부터
//! evict한다. 새 crate를 추가하지 않고 `last_access` 타임스탬프를 들고 있다가 필요할 때만
//! 선형 스캔한다 — eviction은 맵이 상한에 닿았을 때만 일어나므로(그 이후로는 상한에 머문다)
//! 비용이 무한정 누적되지 않는다.

use std::collections::HashMap;

use tokio::time::Instant;

/// 서비스 하나의 token bucket 상태.
struct Bucket {
    /// 현재 보유 토큰 수(소수 — 부분 refill을 표현하기 위해 f64로 둔다).
    tokens: f64,
    /// 마지막으로 refill을 계산한 시각.
    last_refill: Instant,
    /// 마지막으로 `try_acquire`가 호출된 시각 — LRU eviction 기준.
    last_access: Instant,
}

impl Bucket {
    fn new(now: Instant, burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
            last_access: now,
        }
    }

    /// 경과 시간에 비례해 토큰을 채운다(상한 `burst`). 고정 윈도우가 아니라 연속 시간 기준이라
    /// 윈도우 경계 버스트가 없다.
    fn refill(&mut self, now: Instant, rate_per_sec: f64, burst: f64) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * rate_per_sec).min(burst);
            self.last_refill = now;
        }
    }
}

/// 서비스당 rate limit. 기본 1000 lines/s(호출부가 `AicdLogsConfig::max_lines_per_sec`을 넘긴다).
pub struct Limiter {
    buckets: HashMap<String, Bucket>,
    rate_per_sec: f64,
    burst: f64,
    max_services: usize,
}

impl Limiter {
    /// `rate_per_sec`이 0이면 1로 올림(0으로 두면 모든 라인이 영구히 막혀 사실상 "로그 전체
    /// drop" 설정이 되는데, 그건 `enabled=false`로 표현해야지 rate=0으로 표현할 값은 아니다).
    /// `max_services`도 최소 1 — 0이면 버킷을 하나도 못 만들어 매 서비스가 매번 evict되며
    /// 무한 루프처럼 동작한다.
    pub fn new(rate_per_sec: u32, max_services: usize) -> Self {
        let rate = rate_per_sec.max(1) as f64;
        Self {
            buckets: HashMap::new(),
            rate_per_sec: rate,
            burst: rate,
            max_services: max_services.max(1),
        }
    }

    /// 토큰이 있으면 소비하고 `true`, 없으면 `false`(호출부가 `DropCounters::by_rate_limit`을
    /// 올려야 한다 — 여기선 카운터를 건드리지 않는다, 관심사 분리).
    pub fn try_acquire(&mut self, service: &str) -> bool {
        let now = Instant::now();
        let rate = self.rate_per_sec;
        let burst = self.burst;

        if !self.buckets.contains_key(service) {
            self.evict_if_at_capacity();
            self.buckets
                .insert(service.to_string(), Bucket::new(now, burst));
        }

        // 방금 insert했거나 기존에 있었으므로 항상 존재한다.
        let bucket = self.buckets.get_mut(service).expect("bucket just ensured");
        bucket.refill(now, rate, burst);
        bucket.last_access = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// 맵이 이미 `max_services`에 도달했으면 가장 오래전에 접근된 버킷을 하나 지운다.
    /// eviction은 새 서비스가 등장할 때만(맵이 상한에 있을 때만) 일어나므로, 정상 상태에서는
    /// 맵 크기가 절대 `max_services`를 넘지 않는다.
    fn evict_if_at_capacity(&mut self) {
        if self.buckets.len() < self.max_services {
            return;
        }
        if let Some(lru_key) = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.last_access)
            .map(|(k, _)| k.clone())
        {
            self.buckets.remove(&lru_key);
        }
    }

    /// 현재 추적 중인 서비스(버킷) 수 — 관측/테스트용.
    pub fn service_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn rate_limit_drops_and_counts() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let mut limiter = Limiter::new(1000, 200);
        let dropped = AtomicU64::new(0);
        let mut passed = 0u64;

        // 10,000 lines/s 폭주 — 동일 시점(paused clock, advance 없음)에 10,000줄을 한 서비스로
        // 밀어 넣는다.
        for _ in 0..10_000 {
            if limiter.try_acquire("nginx") {
                passed += 1;
            } else {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
        }

        // burst == rate(1000)라 통과 수는 정확히 1000(근사가 아니라 이 순간엔 등호) — 나머지
        // 9000은 전부 드롭.
        assert_eq!(passed, 1000, "통과 수가 rate(1000/s)에 근사해야 함");
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            10_000 - passed,
            "드롭 수는 정확히 by_rate_limit 카운터 값과 일치해야 함"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn token_bucket_no_boundary_burst() {
        let mut limiter = Limiter::new(100, 200);

        // "윈도우 끝" 버스트 — rate만큼 즉시 소비.
        let mut first_batch_passed = 0;
        for _ in 0..100 {
            if limiter.try_acquire("svc") {
                first_batch_passed += 1;
            }
        }
        assert_eq!(first_batch_passed, 100);

        // 고정 윈도우였다면 "다음 윈도우 시작"에 다시 rate만큼(100) 통과해 순간 2배(200)가
        // 새 나갔을 시나리오 — 시간을 거의 흘리지 않은 채(고정 윈도우 경계를 흉내) 곧바로 재시도.
        let mut second_batch_passed = 0;
        for _ in 0..100 {
            if limiter.try_acquire("svc") {
                second_batch_passed += 1;
            }
        }
        assert_eq!(
            second_batch_passed, 0,
            "token bucket은 실시간이 안 지났으면 추가 토큰을 주지 않아야 함(2배 버스트 방지)"
        );

        // 정확히 1초가 지나야 rate만큼만 새로 채워진다(2배가 아니라 1배).
        tokio::time::advance(Duration::from_secs(1)).await;
        let mut third_batch_passed = 0;
        for _ in 0..200 {
            if limiter.try_acquire("svc") {
                third_batch_passed += 1;
            }
        }
        assert_eq!(
            third_batch_passed, 100,
            "1초 경과 후엔 rate(100)만큼만 리필되어야 함 — 2배(200)는 절대 통과하면 안 됨"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn service_bucket_map_is_bounded() {
        let max_services = 50;
        let mut limiter = Limiter::new(1000, max_services);

        for i in 0..10_000 {
            limiter.try_acquire(&format!("service-{i}"));
            assert!(
                limiter.service_count() <= max_services,
                "버킷 맵이 max_services를 넘으면 안 됨(OOM 방지)"
            );
        }

        assert_eq!(
            limiter.service_count(),
            max_services,
            "고유 서비스가 충분히 많으면 맵이 max_services에서 멈춰야 함"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn distinct_services_get_independent_buckets() {
        let mut limiter = Limiter::new(1, 200);
        assert!(limiter.try_acquire("a"));
        // "a"는 토큰을 소진했어도 "b"는 별개 버킷이라 영향받지 않는다.
        assert!(limiter.try_acquire("b"));
        assert!(!limiter.try_acquire("a"));
    }
}
