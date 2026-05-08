//! `CommandRecordStore` session 격리 property test (Phase 3.1, Task 1.4).
//!
//! **Property 5: Session isolation** — 두 개 이상의 서로 다른 `session_id` 에
//! interleave 된 push 시퀀스에서, 한 세션의 `last` / `recent` / `find_by_prefix`
//! 결과는 다른 세션에 push 된 record 를 포함하지 않아야 한다.
//!
//! 검증 전략:
//! - 세션 "a" 에 push 되는 모든 record 는 id 가 "aaaa" 로 시작한다.
//! - 세션 "b" 에 push 되는 모든 record 는 id 가 "bbbb" 로 시작한다.
//! - 따라서 한 세션에서 반환된 record 의 id prefix 를 확인하면 cross-session
//!   leak 이 있는지 결정할 수 있다.
//! - `find_by_prefix` 에는 빈 문자열, 자기/타세션 prefix, 임의 hex, 무관한
//!   문자열을 섞어 질의한다 — isolation invariant 는 질의 모양과 무관하다.
//!
//! **Validates: Requirements R1.9, R5.9, R11.4**

use aic_common::{CaptureMode, CaptureQuality, CommandRecord};
use aic_server::command_record_store::CommandRecordStore;
use chrono::Utc;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// 테스트 상에서 사용하는 두 세션 선택지.
#[derive(Debug, Clone, Copy)]
enum SessionChoice {
    A,
    B,
}

impl SessionChoice {
    fn id(self) -> &'static str {
        match self {
            SessionChoice::A => "a",
            SessionChoice::B => "b",
        }
    }

    /// 이 세션에 push 되는 모든 record id 가 공통으로 갖는 4 자 hex prefix.
    /// 다른 세션의 prefix 와 서로소이므로, id 만 보면 출처 세션을 알 수 있다.
    fn id_prefix(self) -> &'static str {
        match self {
            SessionChoice::A => "aaaa",
            SessionChoice::B => "bbbb",
        }
    }

    fn other(self) -> SessionChoice {
        match self {
            SessionChoice::A => SessionChoice::B,
            SessionChoice::B => SessionChoice::A,
        }
    }
}

fn arb_session_choice() -> impl Strategy<Value = SessionChoice> {
    prop_oneof![Just(SessionChoice::A), Just(SessionChoice::B)]
}

/// push API 가 받아들이는 capture_mode (Pty / ExplicitCapture) 만 생성.
/// Hook 은 별도 경로(`on_started`/`on_finished`) 이므로 본 property 에서는 제외.
fn arb_pushable_capture_mode() -> impl Strategy<Value = CaptureMode> {
    prop_oneof![Just(CaptureMode::Pty), Just(CaptureMode::ExplicitCapture)]
}

/// 세션 prefix 를 강제로 붙인 16 자 lowercase hex id.
/// prefix 4 자 + suffix 12 자 = 16 자 (store 의 id 길이 관례와 일치).
fn arb_session_scoped_id(session: SessionChoice) -> impl Strategy<Value = String> {
    "[0-9a-f]{12}".prop_map(move |suffix| format!("{}{}", session.id_prefix(), suffix))
}

/// 한 번의 push 연산을 기술하는 (session, record) 튜플.
fn arb_push_op() -> impl Strategy<Value = (SessionChoice, CommandRecord)> {
    arb_session_choice().prop_flat_map(|session| {
        (
            Just(session),
            arb_session_scoped_id(session),
            arb_pushable_capture_mode(),
            proptest::option::of("[a-z0-9 _\\-]{0,20}"),
            -128i32..128i32,
            prop::collection::vec("[a-zA-Z0-9 ]{0,30}", 0..=5),
        )
            .prop_map(
                |(session, id, capture_mode, command, exit_code, output_lines)| {
                    let record = CommandRecord {
                        id,
                        command,
                        exit_code,
                        output_lines,
                        timestamp: Utc::now(),
                        capture_mode,
                        capture_quality: CaptureQuality::FullOutput,
                        output_metadata: None,
                    };
                    (session, record)
                },
            )
    })
}

/// `find_by_prefix` 에 사용할 임의 prefix. 매치/미매치/경계값을 고르게 섞는다.
fn arb_prefix_query() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),           // 빈 prefix → 빈 결과 (R1.5)
        Just("a".to_string()),         // 두 세션의 id 접두와 부분 겹침
        Just("b".to_string()),
        Just("aaaa".to_string()),      // 세션 a 전용 prefix
        Just("bbbb".to_string()),      // 세션 b 전용 prefix
        Just("aaab".to_string()),      // a prefix 직후 변이 — 아무것도 매치 안 됨
        "[0-9a-f]{1,16}".prop_map(String::from),
        "[a-z]{1,8}".prop_map(String::from),
    ]
}

/// 테스트 본체. `TestCaseError` 로 prop_assert! 결과를 바깥으로 전달한다.
fn run_isolation_case(
    ops: Vec<(SessionChoice, CommandRecord)>,
    prefix: String,
) -> Result<(), TestCaseError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| TestCaseError::fail(format!("runtime build failed: {e}")))?;

    rt.block_on(async move {
        let store = CommandRecordStore::new();

        // 1. 임의 interleave 순서로 push.
        for (session, record) in &ops {
            match record.capture_mode {
                CaptureMode::Pty => store.push_pty(session.id(), record.clone()).await,
                CaptureMode::ExplicitCapture => {
                    store.push_explicit(session.id(), record.clone()).await
                }
                CaptureMode::Hook => unreachable!("arb_pushable_capture_mode only emits Pty/Explicit"),
            }
        }

        // 2. 각 세션에 대해 격리 invariant 를 검증.
        for session in [SessionChoice::A, SessionChoice::B] {
            let sid = session.id();
            let own_prefix = session.id_prefix();
            let other_prefix = session.other().id_prefix();

            // (a) last(sid) 는 None 이거나 반드시 own_prefix 로 시작한다.
            if let Some(last) = store.last(sid).await {
                prop_assert!(
                    last.id.starts_with(own_prefix),
                    "last({sid}) leaked cross-session record id={} (expected prefix {own_prefix})",
                    last.id
                );
                prop_assert!(
                    !last.id.starts_with(other_prefix),
                    "last({sid}) returned record with foreign prefix {other_prefix}: id={}",
                    last.id
                );
            }

            // (b) recent(sid, ∞) 의 모든 record 는 own_prefix 로 시작해야 한다.
            //     usize::MAX 는 ring cap 에 관계없이 전체를 요청한다는 의미.
            let recent = store.recent(sid, usize::MAX).await;
            for rec in &recent {
                prop_assert!(
                    rec.id.starts_with(own_prefix),
                    "recent({sid}) leaked cross-session record id={} (expected prefix {own_prefix})",
                    rec.id
                );
                prop_assert!(
                    !rec.id.starts_with(other_prefix),
                    "recent({sid}) contained foreign-prefixed id={}",
                    rec.id
                );
            }

            // (c) find_by_prefix(sid, prefix) 의 모든 record 도 own_prefix 로 시작.
            //     prefix 가 own_prefix 와 서로소(예: "bbbb") 여도 세션 경계를
            //     타 세션 record 로 채우면 안 된다.
            let matches = store.find_by_prefix(sid, &prefix).await;
            for rec in &matches {
                prop_assert!(
                    rec.id.starts_with(own_prefix),
                    "find_by_prefix({sid}, {prefix:?}) leaked cross-session record id={}",
                    rec.id
                );
            }

            // (d) 타 세션 prefix 로 질의하면 항상 빈 Vec.
            //     — 가장 엄격한 cross-session leak 체크.
            let cross = store.find_by_prefix(sid, other_prefix).await;
            prop_assert!(
                cross.is_empty(),
                "find_by_prefix({sid}, {other_prefix:?}) returned {} records but session-scoped ids \
                 should keep this empty",
                cross.len()
            );

            // (e) 빈 prefix 는 항상 빈 Vec — 전체 덤프 금지 (R1.5) 가 세션 간 유출
            //     방지에도 기여함을 교차 확인.
            let empty_query = store.find_by_prefix(sid, "").await;
            prop_assert!(
                empty_query.is_empty(),
                "find_by_prefix({sid}, \"\") must return empty, got {} records",
                empty_query.len()
            );
        }

        Ok::<(), TestCaseError>(())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Validates: Requirements R1.9, R5.9, R11.4**
    ///
    /// 임의로 interleave 된 push 시퀀스와 임의 prefix 질의에 대해 세션 격리가
    /// 유지되는지 확인한다.
    #[test]
    fn command_record_store_session_isolation(
        ops in prop::collection::vec(arb_push_op(), 0..80),
        prefix in arb_prefix_query(),
    ) {
        run_isolation_case(ops, prefix)?;
    }
}
