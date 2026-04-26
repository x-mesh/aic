//! Property Test: Session_ID 형식 불변량
//!
//! `generate_session_id()` 호출 결과가 항상 8자 이하이고
//! 모든 문자가 `[0-9a-f]`에 속하는지 검증한다.
//!
//! Feature: multi-session, Property 1: Session_ID 형식 불변량
//! **Validates: Requirements 1.2**

use aic_common::session::generate_session_id;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: multi-session, Property 1: Session_ID 형식 불변량
    ///
    /// 임의의 호출에서 `generate_session_id()`가 반환하는 문자열은:
    /// 1. 길이가 8자 이하여야 한다
    /// 2. 모든 문자가 `[0-9a-f]`에 속해야 한다
    ///
    /// **Validates: Requirements 1.2**
    #[test]
    fn session_id_format_invariant(_seed in any::<u64>()) {
        let id = generate_session_id();

        prop_assert!(
            id.len() <= 8,
            "Session_ID 길이가 8자 이하여야 합니다. 실제 길이: {}, 값: {}",
            id.len(), id
        );

        prop_assert!(
            id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "Session_ID의 모든 문자가 [0-9a-f]에 속해야 합니다. 실제: {}",
            id
        );
    }
}
