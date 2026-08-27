//! 테스트 전용 헬퍼.
//!
//! 환경변수는 **프로세스 전역** 상태이고 `cargo test`는 한 바이너리 안에서 테스트를 여러
//! 스레드로 돌린다. 그래서 `XDG_RUNTIME_DIR`을 지우는 테스트와 `AIC_RUNTIME_DIR`을 세우는
//! 테스트가 각자 다른 Mutex로 직렬화하면 서로를 전혀 막지 못한다 — 한쪽이 세운 값이 다른
//! 쪽의 관측에 그대로 새어 들어간다. 런타임 디렉토리 결정에 두 변수가 함께 관여하므로,
//! **환경변수를 만지는 테스트는 모두 이 하나의 lock을 공유해야 한다.**

use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// 프로세스 전역 환경변수를 만지는 테스트의 공용 직렬화 지점.
///
/// lock이 poison되어도 계속 쓴다 — 앞선 테스트의 panic이 뒤따르는 테스트를 연쇄로
/// 실패시키면 진짜 원인이 묻힌다.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
