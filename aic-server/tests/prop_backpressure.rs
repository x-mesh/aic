//! Property test — Phase 3.3 P6 backpressure non-interference (Task 3.7).
//!
//! **Property 6: Backpressure non-interference** — 임의의 PTY byte stream 이
//! [`BoundedByteChannel`] 의 capacity 를 초과하도록 유입되는 시나리오에서,
//!
//!   (a) **stdout passthrough 의 byte-exact 출력** 이 chunk drop 여부와 무관하게
//!       입력 전체와 일치해야 하며,
//!   (b) **`metrics.dropped_bytes` 의 최종 값** 이 실제로 drop 된 byte 수 합과
//!       정확히 일치해야 한다.
//!
//! 본 property 는 `aic-server::session_runtime::fan_out_chunk` 가 구현하는 팬아웃
//! 순서 — `stdout.write_all(chunk)` → `attach_client.try_send(chunk)` — 의 불변식을
//! 더 낮은 계층(`BoundedByteChannel` + mock stdout) 에서 직접 검증한다. 즉 attach
//! tee 의 drop 이 발생해도 passthrough 는 무영향이라는 R10.4 계약을 property 로
//! 고정한다 (R10.3 은 byte 보존, R10.5 는 metric 가시성).
//!
//! **실제 `fan_out_chunk` 와의 대응 관계**
//!
//!   1. 사용자의 PTY read() 가 `chunk` 를 돌려준다 →
//!      [`BackpressureHarness::feed`] 의 인자.
//!   2. `stdout.write_all(&chunk)` → harness 는 `Arc<Mutex<Vec<u8>>>` 에 extend.
//!      이 순서가 `try_send` 보다 **먼저** 실행된다는 불변식이 property 의 절반.
//!   3. `attach_client.try_send(Bytes::copy_from_slice(chunk))` → harness 는
//!      `BoundedByteChannel::try_send` 를 직접 호출하고 결과에 따라 attempted/
//!      dropped 를 로컬 집계한다.
//!   4. 별도 consumer task 가 느린 스케줄로 `recv` 하면서 일부러 cap 을 overflow 시킨다.
//!
//! **전략**
//!
//!   `(arb_byte_chunks, slow_consumer_delay_schedule)` 의 쌍.
//!   - `arb_byte_chunks`: 0..=80 개 chunk, chunk 당 1..=2048 byte, 내용은 임의.
//!   - `slow_consumer_delay_schedule`: 0..=16 개의 yield point 인덱스.
//!     producer loop 가 해당 인덱스에 도달할 때 `tokio::task::yield_now()` 로
//!     consumer 에게 스위칭할 기회를 준다. 전혀 yield 하지 않으면 consumer 가
//!     실행될 틈이 없어 cap 에 빠르게 도달하고, 반대로 너무 자주 yield 하면
//!     drop 이 거의 발생하지 않는다. 두 극단을 모두 cover 하기 위해 스케줄은
//!     기본 "sparse random" 이다.
//!
//! **검증**
//!
//!   (1) `mock_stdout.bytes() == input_concatenated` — 입력 전체가 원형 그대로
//!       stdout buffer 에 누적되어 있어야 한다 (byte-exact passthrough).
//!   (2) `metrics.dropped_bytes == Σ dropped chunk lens` — drop 된 chunk 의
//!       byte 합이 metric 과 정확히 일치해야 한다.
//!   (3) 부수 불변 — `dropped_bytes + consumed_bytes == attempted_bytes`
//!       (byte 보존). receiver 가 drain 을 마친 시점에 모든 byte 의 거취가
//!       설명되어야 한다.
//!
//! **Validates: Requirements R10.3, R10.4, R10.5**

use aic_common::bounded_byte_channel::{BoundedByteChannel, SendOutcome};
use aic_server::metrics::AttachMetrics;
use bytes::Bytes;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

// ── 상수 ──────────────────────────────────────────────────────
//
// Cap 을 "충분히 작게" 두어 256 cases 중 대다수가 실제로 drop 을 경험하도록 한다.
// 4 MiB 의 실제 aic-session cap 을 그대로 쓰면 이 테스트 입력 규모에서는 cap 초과가
// 거의 일어나지 않아 property 의 조건문이 vacuous 해진다.

/// 채널 cap — 의도적으로 작게 잡아 drop 발생률을 높인다.
const CHANNEL_CAP_BYTES: usize = 1024;

/// chunk 개수 상한. 너무 크면 256 cases × slow consumer 로 테스트가 느려진다.
const MAX_CHUNKS: usize = 80;

/// chunk 당 byte 길이 상한. cap 보다 큰 chunk 도 허용해 "단일 chunk 로 cap 초과" 경로도
/// 커버한다 (chunk.len() > cap 이면 queued=0 상태여도 try_send 가 즉시 drop 한다).
const MAX_CHUNK_LEN: usize = 2048;

/// yield 스케줄 길이 상한.
const MAX_YIELDS: usize = 16;

// ── 전략 ──────────────────────────────────────────────────────

/// 임의의 byte chunk 시퀀스.
///
/// 각 chunk 는 `[u8]` 의 임의 값을 가진다. chunk 길이는 0 까지 허용해 "빈 chunk"
/// 도 passthrough 와 metric 에 영향을 주지 않는지 함께 검증한다.
fn arb_byte_chunks() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(
        prop::collection::vec(any::<u8>(), 0..=MAX_CHUNK_LEN),
        0..=MAX_CHUNKS,
    )
}

/// producer loop 에서 `yield_now()` 를 호출할 chunk 인덱스 집합 (sorted & unique).
///
/// 각 원소는 `[0, MAX_CHUNKS)` 에 있는 chunk 인덱스. producer 가 해당 index 의
/// chunk 를 보낸 직후 `yield_now()` 를 부른다. 실제 chunk 수보다 큰 인덱스는 무시된다.
fn arb_yield_schedule() -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(0..MAX_CHUNKS, 0..=MAX_YIELDS)
        .prop_map(|mut v| {
            v.sort_unstable();
            v.dedup();
            v
        })
}

// ── Harness ────────────────────────────────────────────────────

/// `fan_out_chunk` 의 (stdout → attach try_send) 팬아웃 순서를 더 낮은 계층에서
/// 재현하는 harness.
///
/// stdout 은 `Arc<Mutex<Vec<u8>>>` 로 모사하고, attach 경로는 실제
/// `BoundedByteChannel` + `AttachMetrics` 를 그대로 사용한다. consumer task 는
/// feed loop 와는 별도 tokio task 로 돌며 `yield_schedule` 에 따라 주어진 여유만큼만
/// progress 한다.
struct BackpressureHarness {
    stdout: Arc<Mutex<Vec<u8>>>,
    channel: BoundedByteChannel,
    metrics: Arc<AttachMetrics>,
    /// 송신 시도된 chunk 각각의 길이와 `SendOutcome` 을 순서대로 기록.
    /// (len, outcome). len 은 원본 chunk 의 길이로, drop 된 chunk 의 byte 합을
    /// 독립적으로 재계산하는 데 쓰인다 (property (b) 검증용).
    send_log: Vec<(usize, SendOutcome)>,
}

impl BackpressureHarness {
    fn new(cap_bytes: usize) -> (Self, BackpressureReceiverTask) {
        let metrics = Arc::new(AttachMetrics::new());
        // metrics.dropped_bytes 와 channel.dropped 를 동일한 AtomicU64 로 공유.
        // 실제 AttachClient 의 구성(task 3.4)을 그대로 따른다. 이 덕분에 channel
        // 내부에서 dropped_bytes 카운터가 증가하면 metrics.dropped_bytes() 가
        // 별도 mirror 없이 반영된다 — property (b) 의 관측 지점.
        let dropped_handle = metrics.dropped_bytes_handle();
        let (tx, rx) = BoundedByteChannel::new_with_dropped_counter(cap_bytes, dropped_handle);

        let harness = Self {
            stdout: Arc::new(Mutex::new(Vec::new())),
            channel: tx,
            metrics,
            send_log: Vec::new(),
        };
        let receiver_task = BackpressureReceiverTask {
            rx,
            consumed_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        (harness, receiver_task)
    }

    /// `fan_out_chunk` 의 앞 두 단계를 그대로 시뮬레이션한다.
    ///
    ///   (1) stdout passthrough 를 먼저 수행 (byte-exact).
    ///   (2) attach try_send 를 수행. drop 되더라도 stdout 에는 이미 write 됨.
    ///
    /// 반환값은 `SendOutcome` — 테스트에서 별도 집계가 필요하면 사용할 수 있다.
    fn feed(&mut self, chunk: &[u8]) -> SendOutcome {
        // (1) stdout passthrough — drop 여부와 무관하게 **항상** 먼저.
        {
            let mut guard = self
                .stdout
                .lock()
                .expect("mock stdout mutex 는 poison 될 일이 없다");
            guard.extend_from_slice(chunk);
        }
        // (2) attach tee.
        let outcome = self
            .channel
            .try_send(Bytes::copy_from_slice(chunk));
        self.send_log.push((chunk.len(), outcome));
        outcome
    }
}

/// slow consumer task. producer 가 `yield_now()` 를 호출할 때마다 1 chunk 씩만
/// 꺼내는 식으로 의도적으로 느리게 동작해 cap 을 overflow 시킨다.
struct BackpressureReceiverTask {
    rx: aic_common::bounded_byte_channel::BoundedByteReceiver,
    consumed_bytes: Arc<std::sync::atomic::AtomicUsize>,
}

// ── Property body ─────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Validates: Requirements R10.3, R10.4, R10.5**
    ///
    /// 임의의 byte chunk 시퀀스와 slow-consumer yield schedule 에 대해,
    /// harness 의 `feed` 를 순서대로 호출한 뒤 다음을 단언한다:
    ///
    ///   1. `stdout.bytes() == input_concatenated` — passthrough byte-exact.
    ///   2. `metrics.dropped_bytes == send_log 의 drop 합` — metric 정확성.
    ///   3. drain 이후 `dropped + consumed == attempted` — byte 보존.
    #[test]
    fn prop_backpressure_non_interference(
        chunks in arb_byte_chunks(),
        yield_schedule in arb_yield_schedule(),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread tokio runtime");

        let outcome: Result<(), TestCaseError> = rt.block_on(async move {
            let (mut harness, mut receiver_task) =
                BackpressureHarness::new(CHANNEL_CAP_BYTES);

            // 기대되는 stdout 출력 — feed 전에 미리 concat 해두면 feed 중
            // harness.stdout 이 항상 이 prefix 를 extend 해야 한다.
            let input_concatenated: Vec<u8> =
                chunks.iter().flat_map(|c| c.iter().copied()).collect();
            let attempted_bytes: usize = chunks.iter().map(|c| c.len()).sum();

            // yield_schedule 은 chunks.len() 보다 큰 인덱스를 포함할 수 있으므로
            // 실제 존재하는 인덱스만 set 으로 정리.
            let yield_set: std::collections::BTreeSet<usize> = yield_schedule
                .into_iter()
                .filter(|&i| i < chunks.len())
                .collect();

            // consumer 는 background task 로 돌리되, producer 가 yield 할 때만
            // 진행할 기회를 가진다. current_thread runtime 을 쓰므로
            // `yield_now().await` 가 task 스위치를 유도한다.
            let stdout_handle = Arc::clone(&harness.stdout);
            let consumed_counter = Arc::clone(&receiver_task.consumed_bytes);
            let consumed_counter_for_task = Arc::clone(&consumed_counter);

            let consumer = tokio::spawn(async move {
                // producer 가 channel 을 drop 할 때까지 drain. 각 recv 직후
                // 다시 한 번 yield 해서 producer 에게 제어권을 돌려준다 —
                // current_thread runtime 에서 starvation 을 피하기 위함.
                while let Some(bytes) = receiver_task.rx.recv().await {
                    consumed_counter_for_task
                        .fetch_add(bytes.len(), Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });

            // ── producer loop ────────────────────────────────
            // chunks.len() 만큼 feed 하고, yield_set 에 포함된 인덱스에서
            // consumer 에게 실행 기회를 양보한다.
            for (i, chunk) in chunks.iter().enumerate() {
                let _outcome = harness.feed(chunk);
                if yield_set.contains(&i) {
                    tokio::task::yield_now().await;
                }
            }

            // channel 을 drop 해 consumer 가 자연 종료되도록 한다. harness 를
            // 그대로 두면 tx 가 살아있어 consumer 가 hang.
            //
            // NOTE: channel 을 멤버에서 꺼내기 위해 harness 의 channel 만 drop
            // 하는 helper 를 쓰지 않고, send_log / stdout 만 이후에 쓴다.
            let BackpressureHarness {
                channel,
                metrics,
                send_log,
                stdout: _stdout,
            } = harness;
            drop(channel);

            // consumer 종료 대기. invariant 파손 시 hang 을 피하기 위해 timeout.
            tokio::time::timeout(std::time::Duration::from_secs(5), consumer)
                .await
                .map_err(|_| TestCaseError::fail("consumer task did not finish in time"))?
                .map_err(|e| TestCaseError::fail(format!("consumer task panicked: {e:?}")))?;

            // ── (1) Passthrough byte-exact (R10.4) ─────────────
            let stdout_bytes = stdout_handle
                .lock()
                .expect("stdout mutex")
                .clone();
            prop_assert_eq!(
                stdout_bytes,
                input_concatenated,
                "passthrough stdout 은 입력 전체를 byte-exact 로 받아야 한다 \
                 (drop 발생 여부와 무관)"
            );

            // ── (2) metrics.dropped_bytes 정확성 (R10.3, R10.5) ──
            //
            // send_log 를 기준으로 재계산한 drop 합이 metrics 카운터 값과 일치해야
            // 한다. channel 의 dropped 카운터가 metrics.dropped_bytes 와 동일
            // AtomicU64 를 공유하므로, try_send 가 drop 을 관측할 때마다 metric
            // 에 자동 반영된 상태여야 한다.
            let dropped_from_log: u64 = send_log
                .iter()
                .filter_map(|(len, outcome)| match outcome {
                    SendOutcome::Dropped => Some(*len as u64),
                    SendOutcome::Sent => None,
                })
                .sum();
            let dropped_from_metric = metrics.dropped_bytes();
            prop_assert_eq!(
                dropped_from_metric,
                dropped_from_log,
                "metrics.dropped_bytes 는 실제 drop 된 chunk 의 byte 합과 정확히 일치해야 한다"
            );

            // ── (3) byte 보존 (부수 불변) ──────────────────────
            //
            // drain 이후에는 channel 에 남은 bytes 가 없다. 따라서
            //   attempted == consumed + dropped.
            let consumed_bytes = receiver_task_consumed(&consumed_counter);
            prop_assert_eq!(
                consumed_bytes + dropped_from_metric as usize,
                attempted_bytes,
                "byte 보존 위반: attempted != consumed + dropped"
            );

            Ok(())
        });
        outcome?;
    }
}

/// `consumed_bytes` counter 의 현재 값 읽기 helper — 클로저 안에서 `move` 된
/// Arc 와 별개로 바깥 scope 에서 관측할 수 있도록 별도 clone 을 쓴다.
fn receiver_task_consumed(counter: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
    counter.load(Ordering::Relaxed)
}
