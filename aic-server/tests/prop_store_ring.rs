//! Property test for `CommandRecordStore` ring bound.
//!
//! **Validates: Requirements R1.8**
//!
//! Property 4 (Ring bound):
//! - 임의 session_id 에 임의 개수의 record 를 `push_pty` 한 뒤,
//!   `store.len(session_id) <= 64` 이 성립한다.
//! - 64 개 초과 push 시 `store.recent(session_id, 64)` 가 정확히 마지막 64개
//!   push 와 같아야 한다 (순서 보존).
//!
//! 전략:
//! - `prop::collection::vec(arb_command_record(), 0..200)` 로 임의 크기의 record
//!   시퀀스를 생성한다.
//! - push 직전 각 record 의 `command` 를 `"cmd-<index>"` 로 덮어써, tail-64
//!   비교가 자동 부여된 id 가 아닌 안정적인 `command` 필드 기준으로
//!   가능하도록 한다.

use aic_common::{CaptureMode, CaptureQuality, CommandRecord};
use aic_server::command_record_store::CommandRecordStore;
use proptest::prelude::*;

/// `CommandRecordStore` 내부 상수와 동일해야 한다. 공개 API 로 노출되지
/// 않으므로 여기서도 같은 값으로 하드코딩한다.
const PER_SESSION_CAPACITY: usize = 64;

/// PTY capture_mode 로 채워진 임의 `CommandRecord` 를 생성한다.
/// `id` 는 빈 문자열로 두어 store 가 16-hex id 를 자동 부여하게 한다.
/// `command` 는 push 직전 index 기반으로 덮어쓸 것이므로 여기서는 None 으로 둔다.
fn arb_command_record() -> impl Strategy<Value = CommandRecord> {
    (
        any::<i32>(),
        prop::collection::vec("[a-zA-Z0-9 ]{0,30}", 0..4),
        0i64..4_102_444_800_000i64,
        prop_oneof![
            Just(CaptureQuality::FullOutput),
            Just(CaptureQuality::TruncatedOutput),
            Just(CaptureQuality::Unknown),
        ],
    )
        .prop_map(
            |(exit_code, output_lines, ts_millis, capture_quality)| {
                let timestamp =
                    chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default();
                CommandRecord {
                    id: String::new(),
                    command: None,
                    exit_code,
                    output_lines,
                    timestamp,
                    capture_mode: CaptureMode::Pty,
                    capture_quality,
                    output_metadata: None,
                    cwd: None,
                    duration_ms: None,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Validates: Requirements R1.8**
    ///
    /// 임의 개수(0..200)의 PTY record 를 동일 session_id 에 push 하면:
    ///  (1) `store.len(session_id) <= PER_SESSION_CAPACITY (64)` 이 항상 성립.
    ///  (2) push 횟수가 64 초과이면 `recent(64)` 는 정확히 꼬리 64 개 push 와
    ///      같아야 하며(순서 보존), 64 이하이면 전체 push 가 oldest→newest
    ///      순으로 반환된다.
    #[test]
    fn ring_bound_holds_for_any_push_sequence(
        records in prop::collection::vec(arb_command_record(), 0..200),
        session_id in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime");

        let result: Result<(), TestCaseError> = rt.block_on(async {
            let store = CommandRecordStore::new();
            let n = records.len();

            for (i, mut record) in records.into_iter().enumerate() {
                // tail-64 비교를 안정적으로 하기 위해 distinctive command 를 심는다.
                // id 는 여전히 빈 문자열이라 store 가 auto-assign 한다.
                record.command = Some(format!("cmd-{i}"));
                store.push_pty(&session_id, record).await;
            }

            // (1) ring capacity bound 는 전 push 개수와 무관하게 항상 성립.
            let len = store.len(&session_id).await;
            prop_assert!(
                len <= PER_SESSION_CAPACITY,
                "len({}) > PER_SESSION_CAPACITY({}) after {} pushes",
                len,
                PER_SESSION_CAPACITY,
                n,
            );

            // recent() 가 반환하는 record 수는 min(n, 64).
            let expected_len = n.min(PER_SESSION_CAPACITY);
            let recent = store.recent(&session_id, PER_SESSION_CAPACITY).await;
            prop_assert_eq!(
                recent.len(),
                expected_len,
                "recent length mismatch: got {}, expected {} (after {} pushes)",
                recent.len(),
                expected_len,
                n,
            );

            // (2) recent 의 command 시퀀스가 꼬리 64 개 push 의 command 와 동일.
            //     64 이하면 0..n 전체, 초과면 (n-64)..n 가 기대값이다.
            let expected_start = n.saturating_sub(PER_SESSION_CAPACITY);
            for (offset, rec) in recent.iter().enumerate() {
                let expected_cmd = format!("cmd-{}", expected_start + offset);
                prop_assert_eq!(
                    rec.command.as_deref(),
                    Some(expected_cmd.as_str()),
                    "recent[{}] command mismatch after {} pushes",
                    offset,
                    n,
                );
            }

            // len 과 recent.len 은 항상 일치해야 한다 (R1.4 보강).
            prop_assert_eq!(
                len,
                recent.len(),
                "len({}) disagrees with recent.len({})",
                len,
                recent.len(),
            );

            Ok(())
        });
        result?;
    }
}
