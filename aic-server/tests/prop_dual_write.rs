//! Property test — Phase 3.1 Dual-Write equivalence (Task 1.7).
//!
//! **Property 2: Dual-write equivalence** — 임의의 `CommandRecord` 시퀀스가
//! Phase 3.1 Dual_Write 모드로 aic-session 에 의해 수신된 것으로 시뮬레이션될 때,
//! local `RingBuffer.recent_records(N)` 과 aicd `CommandRecordStore.recent(session_id, N)`
//! 은 `(id, command, exit_code, output_lines, capture_mode)` 5-튜플 기준으로
//! 동일해야 한다.
//!
//! 시뮬레이션은 `session_runtime::dispatch_record` 의 핵심 동작을 재현한다 —
//! 단, IPC 는 호출하지 않고 양쪽 store 에 직접 push 한다 (실제 dual-write 경로와
//! 관측 가능한 상태 변화는 같다):
//!
//!   1. 입력 record 의 `id` 가 비어 있으면 `generate_record_id()` 로 부여한다
//!      (local push **이전**에 부여해야 두 store 가 동일 id 를 갖는다 — P2 전제).
//!   2. 먼저 local `RingBuffer::push` 로 push 한다.
//!   3. 이어서 `capture_mode` 에 따라 `CommandRecordStore::push_pty` /
//!      `push_explicit` 로 push 한다.
//!
//! 크기 경계:
//! - `CommandRecordStore` 는 세션당 64 record ring 이고 `RingBuffer` 는 500 line
//!   용량이다. 두 eviction 정책이 다르므로 eviction 이 일어나면 두 store 의
//!   tail 이 달라질 수 있다. 아래 전략에서 record 수를 64 이하로, 그리고 record 당
//!   output_lines 개수를 `MAX_OUTPUT_LINES_PER_RECORD` 이하로 묶어 두 eviction
//!   모두 트리거되지 않도록 한다 (64 * 5 = 320 < 500).
//!
//! **Validates: Requirements R3.1, R3.4, R17.1, R17.2, R17.3**

use aic_common::{generate_record_id, CaptureMode, CaptureQuality, CommandRecord};
use aic_server::command_record_store::CommandRecordStore;
use aic_server::ring_buffer::RingBuffer;
use chrono::Utc;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use std::sync::Arc;
use tokio::sync::RwLock;

/// `CommandRecordStore` 의 per-session ring capacity 와 일치해야 한다.
/// record 수가 이 값을 초과하면 중앙 ring 이 front 부터 eviction 해 local 과
/// 달라질 수 있다.
const PER_SESSION_RECORD_CAPACITY: usize = 64;

/// local `RingBuffer` 용량 (총 output_lines 기준).
/// 실제 `session_runtime` 이 쓰는 값과 동일하다.
const RING_BUFFER_LINE_CAPACITY: usize = 500;

/// record 당 output_lines 최대 개수. `PER_SESSION_RECORD_CAPACITY * this`
/// 가 `RING_BUFFER_LINE_CAPACITY` 를 넘지 않아야 line-based eviction 이
/// 트리거되지 않는다 (64 * 5 = 320 ≤ 500).
const MAX_OUTPUT_LINES_PER_RECORD: usize = 5;

/// 여러 case 에서 session id 를 흔들어 ring 이 session 으로 격리되는지도
/// 간접적으로 확인한다. 생성 패턴은 store 쪽 다른 property test 와 정렬.
fn arb_session_id() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,12}".prop_map(String::from)
}

/// push API 가 받아들이는 capture_mode (Pty / ExplicitCapture) 만 생성.
/// `Hook` 은 `on_started`/`on_finished` 전용 경로이고 `push_pty`/`push_explicit`
/// 의 debug_assert 에 의해 거절되므로 본 property 의 대상이 아니다.
fn arb_pushable_capture_mode() -> impl Strategy<Value = CaptureMode> {
    prop_oneof![Just(CaptureMode::Pty), Just(CaptureMode::ExplicitCapture)]
}

/// 빈 `id` 를 가진 임의 `CommandRecord` 를 만든다 — `simulate_dual_write` 가
/// push 직전에 `generate_record_id()` 로 채운다 (dispatch_record 의 실제 동작).
fn arb_command_record() -> impl Strategy<Value = CommandRecord> {
    (
        proptest::option::of("[a-zA-Z0-9 _\\-]{0,30}"),
        any::<i32>(),
        prop::collection::vec(
            "[a-zA-Z0-9 ]{0,30}",
            0..=MAX_OUTPUT_LINES_PER_RECORD,
        ),
        arb_pushable_capture_mode(),
    )
        .prop_map(
            |(command, exit_code, output_lines, capture_mode)| CommandRecord {
                id: String::new(),
                command,
                exit_code,
                output_lines,
                timestamp: Utc::now(),
                capture_mode,
                capture_quality: CaptureQuality::FullOutput,
                output_metadata: None,
                cwd: None,
                duration_ms: None,
            },
        )
}

/// 비교에 사용하는 projection. `timestamp` 는 local/central 양쪽에서 같은
/// 복사본이 들어가지만 (simulate_dual_write 가 복제해서 넣음) 본 property
/// 는 디자인 문서의 5-튜플 기준을 정확히 따르므로 의도적으로 제외한다.
type DualWriteKey = (String, Option<String>, i32, Vec<String>, CaptureMode);

fn project(record: &CommandRecord) -> DualWriteKey {
    (
        record.id.clone(),
        record.command.clone(),
        record.exit_code,
        record.output_lines.clone(),
        record.capture_mode,
    )
}

/// `session_runtime::dispatch_record` 의 핵심 동작을 IPC 없이 재현한다.
///
/// - 입력 record 의 `id` 가 비어 있으면 `generate_record_id()` 로 부여.
/// - local push → central push 순서.
/// - `capture_mode` 에 따라 `push_pty` / `push_explicit` 분기.
///
/// 반환값은 id 가 부여된 record 시퀀스 (테스트가 필요에 따라 활용).
async fn simulate_dual_write(
    session_id: &str,
    records: Vec<CommandRecord>,
    ring_buffer: &Arc<RwLock<RingBuffer>>,
    store: &CommandRecordStore,
) -> Vec<CommandRecord> {
    let mut assigned = Vec::with_capacity(records.len());
    for mut record in records {
        // P2 전제: 양쪽 store 가 동일 id 를 관찰하도록 push 이전에 부여한다.
        if record.id.is_empty() {
            record.id = generate_record_id();
        }

        // 1) local RingBuffer 먼저 — 실제 dispatch_record 와 동일한 순서.
        {
            let mut guard = ring_buffer.write().await;
            guard.push(record.clone());
        }

        // 2) central CommandRecordStore.
        match record.capture_mode {
            CaptureMode::Pty => store.push_pty(session_id, record.clone()).await,
            CaptureMode::ExplicitCapture => {
                store.push_explicit(session_id, record.clone()).await
            }
            CaptureMode::Hook => unreachable!(
                "arb_pushable_capture_mode generates only Pty / ExplicitCapture"
            ),
        }

        assigned.push(record);
    }
    assigned
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Validates: Requirements R3.1, R3.4, R17.1, R17.2, R17.3**
    ///
    /// 임의의 session_id 와 record 시퀀스에 대해 `simulate_dual_write` 이후
    /// `RingBuffer::recent_records(N)` 과 `CommandRecordStore::recent(session_id, N)`
    /// 의 projection (id, command, exit_code, output_lines, capture_mode) 이
    /// 동일해야 한다.
    ///
    /// 전략:
    /// - 시퀀스 길이는 `0..=PER_SESSION_RECORD_CAPACITY` (64) 로 묶어 중앙
    ///   ring 의 record-수 eviction 을 회피한다.
    /// - record 당 output_lines 는 `0..=MAX_OUTPUT_LINES_PER_RECORD` (5) 로
    ///   묶어 local RingBuffer 의 500-line eviction 을 회피한다.
    /// 두 eviction 이 모두 트리거되지 않으므로 두 store 의 tail 은 push 순서
    /// 그대로 완전 일치해야 한다.
    #[test]
    fn prop_dual_write_equivalence(
        session_id in arb_session_id(),
        records in prop::collection::vec(
            arb_command_record(),
            0..=PER_SESSION_RECORD_CAPACITY,
        ),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime");

        let outcome: Result<(), TestCaseError> = rt.block_on(async {
            let ring_buffer = Arc::new(RwLock::new(RingBuffer::new(RING_BUFFER_LINE_CAPACITY)));
            let store = CommandRecordStore::new();

            let n = records.len();
            let _assigned = simulate_dual_write(
                &session_id,
                records,
                &ring_buffer,
                &store,
            )
            .await;

            // N 은 시퀀스 길이 — 두 store 모두 eviction 이 없다고 가정하므로
            // recent(N) 이 전체 시퀀스를 시간순으로 돌려줄 것이다.
            let local_recent: Vec<CommandRecord> = {
                let guard = ring_buffer.read().await;
                guard.recent_records(n)
            };
            let central_recent: Vec<CommandRecord> = store.recent(&session_id, n).await;

            prop_assert_eq!(
                local_recent.len(),
                n,
                "local RingBuffer lost records (size-only eviction unexpectedly triggered)"
            );
            prop_assert_eq!(
                central_recent.len(),
                n,
                "central CommandRecordStore lost records (ring eviction unexpectedly triggered)"
            );

            let local_keys: Vec<DualWriteKey> = local_recent.iter().map(project).collect();
            let central_keys: Vec<DualWriteKey> = central_recent.iter().map(project).collect();

            prop_assert_eq!(
                local_keys,
                central_keys,
                "dual-write projection mismatch between local and central stores"
            );

            Ok(())
        });
        outcome?;
    }
}
