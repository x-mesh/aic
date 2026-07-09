//! Property test — `CommandRecordStore` id uniqueness & stability (Phase 3.1 Task 1.2).
//!
//! Phase 3.1 Property 3: 서로 다른 `session_id`를 섞은 임의 push 시퀀스에서
//!
//!   (a) push_pty에 빈 id로 투입된 record에 자동 부여되는 id 집합에 충돌이 없고,
//!   (b) push_explicit에 비어 있지 않은 id로 투입된 record의 id는 그대로 보존된다.
//!
//! **Validates: Requirements R1.6, R1.7**

use aic_common::{CaptureMode, CaptureQuality, CommandRecord};
use aic_server::command_record_store::CommandRecordStore;
use chrono::Utc;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use std::collections::{HashMap, HashSet};
use tokio::runtime::Runtime;

/// 명시적 explicit id와 auto-assign id를 구분하기 위한 distinctive prefix.
///
/// auto-assign id는 `generate_record_id`가 돌려주는 16자 lowercase hex이므로
/// 절대 `X-`로 시작할 수 없다 — 이 prefix를 관찰값의 필터로 쓴다.
const EXPLICIT_PREFIX: &str = "X-";

/// 한 push 이벤트의 스펙.
///
/// - `Auto`: push_pty에 빈 id record를 넣어 자동 부여를 유도.
/// - `Explicit`: push_explicit에 `X-…` 형식의 id record를 그대로 보존.
#[derive(Debug, Clone)]
enum PushOp {
    Auto { session: String },
    Explicit { session: String, id: String },
}

fn arb_session_id() -> impl Strategy<Value = String> {
    // interleaving 커버리지를 위해 2~5개 세션을 섞는다.
    prop_oneof![
        Just("sess-a".to_string()),
        Just("sess-b".to_string()),
        Just("sess-c".to_string()),
        Just("sess-d".to_string()),
        Just("sess-e".to_string()),
    ]
}

/// distinctive `X-` prefix를 가진 explicit id. auto-assign 16-hex와 충돌하지 않는다.
fn arb_explicit_id() -> impl Strategy<Value = String> {
    "X-[A-Za-z0-9]{1,16}".prop_map(|s| s)
}

fn arb_push_op() -> impl Strategy<Value = PushOp> {
    prop_oneof![
        arb_session_id().prop_map(|session| PushOp::Auto { session }),
        (arb_session_id(), arb_explicit_id())
            .prop_map(|(session, id)| PushOp::Explicit { session, id }),
    ]
}

fn pty_record_with_id(id: &str, tag: &str) -> CommandRecord {
    CommandRecord {
        id: id.to_string(),
        command: Some(tag.to_string()),
        exit_code: 0,
        output_lines: Vec::new(),
        timestamp: Utc::now(),
        capture_mode: CaptureMode::Pty,
        capture_quality: CaptureQuality::FullOutput,
        output_metadata: None,
        cwd: None,
        duration_ms: None,
    }
}

fn explicit_record_with_id(id: &str, tag: &str) -> CommandRecord {
    CommandRecord {
        id: id.to_string(),
        command: Some(tag.to_string()),
        exit_code: 0,
        output_lines: Vec::new(),
        timestamp: Utc::now(),
        capture_mode: CaptureMode::ExplicitCapture,
        capture_quality: CaptureQuality::FullOutput,
        output_metadata: None,
        cwd: None,
        duration_ms: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Property 3: Store id uniqueness & stability**
    ///
    /// **Validates: Requirements R1.6, R1.7**
    ///
    /// - (a) `push_pty`에 빈 id로 투입된 auto record의 id 집합은 중복이 없어야 한다 (R1.6).
    /// - (b) `push_explicit`에 비어 있지 않은 id로 투입된 record의 id는 `recent()` 결과에
    ///   그대로 보존되어야 한다 (R1.7).
    ///
    /// 총 ops 수는 `PER_SESSION_CAPACITY = 64` 미만으로 제한해 ring eviction에 의한
    /// 관찰 누락을 배제한다 (R1.8은 별도 태스크 1.3에서 검증).
    #[test]
    fn prop_store_id_uniqueness_and_stability(
        ops in proptest::collection::vec(arb_push_op(), 0..60usize)
    ) {
        // Per test-case Tokio runtime. `CommandRecordStore`는 `tokio::sync::RwLock`을
        // 쓰므로 async context가 필요하다. current-thread runtime으로 충분하다.
        let rt = Runtime::new().expect("failed to build tokio runtime");
        let outcome: Result<(), TestCaseError> = rt.block_on(async {
            let store = CommandRecordStore::new();

            let mut auto_count_total: usize = 0;
            let mut explicit_expected: Vec<(String, String)> = Vec::new();
            let mut sessions_seen: HashSet<String> = HashSet::new();

            for (i, op) in ops.iter().enumerate() {
                match op {
                    PushOp::Auto { session } => {
                        let rec = pty_record_with_id("", &format!("auto-{i}"));
                        store.push_pty(session, rec).await;
                        auto_count_total += 1;
                        sessions_seen.insert(session.clone());
                    }
                    PushOp::Explicit { session, id } => {
                        let rec = explicit_record_with_id(id, &format!("explicit-{i}"));
                        store.push_explicit(session, rec).await;
                        explicit_expected.push((session.clone(), id.clone()));
                        sessions_seen.insert(session.clone());
                    }
                }
            }

            // 세션별로 전체 ring을 덤프한다. 총 op 수 ≤ 60 < 64이므로 eviction은 발생하지 않는다.
            let mut recent_by_session: HashMap<String, Vec<CommandRecord>> = HashMap::new();
            for s in &sessions_seen {
                recent_by_session.insert(s.clone(), store.recent(s, 64).await);
            }

            // (a) auto id 집합이 모든 세션을 가로질러 유일해야 한다.
            //     - auto id는 lowercase 16-hex (generate_record_id) 이므로 EXPLICIT_PREFIX 로
            //       시작할 수 없다. 따라서 prefix 부재로 auto id를 식별한다.
            //     - 전체 auto id 개수는 auto 연산 수와 정확히 같아야 한다.
            let mut auto_ids: HashSet<String> = HashSet::new();
            let mut total_auto_observed: usize = 0;
            for records in recent_by_session.values() {
                for r in records {
                    if !r.id.starts_with(EXPLICIT_PREFIX) {
                        total_auto_observed += 1;
                        prop_assert!(
                            auto_ids.insert(r.id.clone()),
                            "duplicate auto-assigned id observed: {}",
                            r.id
                        );
                        // auto id는 정확히 16-hex 이어야 한다는 부가 조건.
                        prop_assert_eq!(r.id.len(), 16);
                        prop_assert!(
                            r.id.chars().all(|c| c.is_ascii_hexdigit()),
                            "auto id is not lowercase hex: {}",
                            r.id
                        );
                    }
                }
            }
            prop_assert_eq!(
                total_auto_observed,
                auto_count_total,
                "auto id observation count must equal number of auto push ops"
            );

            // (b) explicit id는 해당 세션의 recent() 결과에 그대로 존재해야 한다.
            for (session, id) in &explicit_expected {
                let recs = recent_by_session
                    .get(session)
                    .expect("session seen in ops must be present in recent map");
                prop_assert!(
                    recs.iter().any(|r| r.id == *id),
                    "explicit id {} not preserved in session {}",
                    id,
                    session
                );
            }

            Ok(())
        });
        outcome?;
    }
}
