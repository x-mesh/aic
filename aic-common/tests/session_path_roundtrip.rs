//! Property Test: 소켓 경로 round-trip
//!
//! 임의의 유효한 Session_ID에 대해 `session_socket_path(id)`로 생성한 경로에서
//! `extract_session_id(path)`를 호출하면 원래 Session_ID와 동일한 값을 반환하는지 검증한다.
//!
//! Feature: multi-session, Property 2: 소켓 경로 round-trip
//! **Validates: Requirements 7.2**

use aic_common::paths::{extract_session_id, session_socket_path};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: multi-session, Property 2: 소켓 경로 round-trip
    ///
    /// 임의의 유효한 Session_ID(1~8자, `[0-9a-f]`)에 대해
    /// `session_socket_path(id)` → `extract_session_id(path)` 결과가
    /// 원래 ID와 동일해야 한다.
    ///
    /// **Validates: Requirements 7.2**
    #[test]
    fn socket_path_roundtrip(id in "[0-9a-f]{1,8}") {
        let path = session_socket_path(&id);
        let extracted = extract_session_id(&path);

        prop_assert_eq!(
            extracted.as_deref(),
            Some(id.as_str()),
            "round-trip 실패: session_socket_path({:?}) = {:?}, extract_session_id 결과 = {:?}",
            id, path, extracted
        );
    }
}
