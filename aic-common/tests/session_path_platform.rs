//! Property Test: 세션 소켓 경로 플랫폼 규칙 준수
//!
//! 임의의 유효한 Session_ID에 대해:
//! (1) `session_socket_path(id)`는 절대 경로여야 한다
//! (2) `session-{id}.sock`으로 끝나야 한다
//! (3) parent 디렉토리가 `session_dir()`과 동일해야 한다
//!
//! Feature: multi-session, Property 3: 세션 소켓 경로 플랫폼 규칙 준수
//! **Validates: Requirements 2.1, 7.1, 7.3**

use aic_common::paths::{session_dir, session_socket_path};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: multi-session, Property 3: 세션 소켓 경로 플랫폼 규칙 준수
    ///
    /// 임의의 유효한 Session_ID(1~8자, `[0-9a-f]`)에 대해:
    /// 1. 절대 경로여야 한다
    /// 2. `session-{id}.sock`으로 끝나야 한다
    /// 3. parent 디렉토리가 `session_dir()`과 동일해야 한다
    ///
    /// **Validates: Requirements 2.1, 7.1, 7.3**
    #[test]
    fn socket_path_follows_platform_rules(id in "[0-9a-f]{1,8}") {
        let path = session_socket_path(&id);
        let expected_dir = session_dir();

        // (1) 절대 경로 검증
        prop_assert!(
            path.is_absolute(),
            "소켓 경로가 절대 경로가 아닙니다: {:?}",
            path
        );

        // (2) session-{id}.sock 파일명 검증
        let expected_filename = format!("session-{}.sock", id);
        let actual_filename = path.file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("");
        prop_assert_eq!(
            actual_filename,
            expected_filename.as_str(),
            "파일명이 예상과 다릅니다: 경로={:?}",
            path
        );

        // (3) parent 디렉토리가 session_dir()과 동일한지 검증
        let parent = path.parent().expect("소켓 경로에 parent가 없습니다");
        prop_assert_eq!(
            parent,
            expected_dir.as_path(),
            "parent 디렉토리가 session_dir()과 다릅니다: parent={:?}, session_dir={:?}",
            parent,
            expected_dir
        );
    }
}
