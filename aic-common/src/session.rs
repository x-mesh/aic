//! Session_ID 생성 및 검증
//!
//! 8자 lowercase hex 문자열로 세션을 고유하게 식별한다.
//! Requirements: 1.1, 1.2

use rand::Rng;

/// 8자 lowercase hex Session_ID를 생성한다.
///
/// `rand::thread_rng()`로 u32 난수를 생성한 뒤 hex 인코딩한다.
/// 결과는 정확히 8자의 `[0-9a-f]` 문자열이다.
pub fn generate_session_id() -> String {
    let value: u32 = rand::thread_rng().gen();
    format!("{:08x}", value)
}

/// 현재 session artifact와 충돌하지 않는 Session_ID를 생성한다.
///
/// `session-{id}.sock` 또는 `session-{id}.pid`가 이미 있으면 live/stale 판정은
/// 호출자가 수행한 cleanup 결과를 신뢰하고 다른 id를 시도한다.
pub fn generate_unused_session_id(max_attempts: usize) -> Option<String> {
    for _ in 0..max_attempts {
        let id = generate_session_id();
        let socket_path = crate::paths::session_socket_path(&id);
        let lock_path = socket_path.with_extension("pid");
        if !socket_path.exists() && !lock_path.exists() {
            return Some(id);
        }
    }
    None
}

/// Session_ID가 유효한지 검증한다.
///
/// 유효 조건: 1~8자, 모든 문자가 `[0-9a-f]`에 속해야 한다.
pub fn is_valid_session_id(id: &str) -> bool {
    let len = id.len();
    (1..=8).contains(&len)
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_id_is_valid() {
        let id = generate_session_id();
        assert!(
            is_valid_session_id(&id),
            "generated id should be valid: {id}"
        );
    }

    #[test]
    fn generated_id_is_exactly_8_chars() {
        let id = generate_session_id();
        assert_eq!(id.len(), 8);
    }

    #[test]
    fn valid_ids() {
        assert!(is_valid_session_id("a1b2c3d4"));
        assert!(is_valid_session_id("00000000"));
        assert!(is_valid_session_id("abcdef01"));
        assert!(is_valid_session_id("a")); // 1자도 유효
    }

    #[test]
    fn invalid_ids() {
        assert!(!is_valid_session_id("")); // 빈 문자열
        assert!(!is_valid_session_id("123456789")); // 9자 초과
        assert!(!is_valid_session_id("ABCDEF01")); // 대문자
        assert!(!is_valid_session_id("a1b2c3g4")); // 'g'는 hex 아님
        assert!(!is_valid_session_id("hello!!!")); // 특수문자
    }

    #[test]
    fn generated_ids_are_unique() {
        let ids: std::collections::HashSet<String> =
            (0..10).map(|_| generate_session_id()).collect();
        assert_eq!(ids.len(), 10, "10회 생성된 Session_ID에 중복이 있음");
    }

    #[test]
    fn unused_session_id_generation_honors_attempt_limit() {
        assert_eq!(generate_unused_session_id(0), None);
        let id = generate_unused_session_id(1).expect("one attempt should usually produce an id");
        assert!(is_valid_session_id(&id));
    }
}
