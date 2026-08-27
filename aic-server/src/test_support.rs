//! 테스트 전용 헬퍼.
//!
//! `tempfile::tempdir()`는 umask를 따라 디렉토리를 만들기 때문에 보통 0755가 된다. 런타임
//! 디렉토리(소켓·lock의 부모)는 `aic_common::paths::ensure_runtime_dir`이 0700만 신뢰하므로,
//! tempdir을 그대로 런타임 디렉토리로 쓰는 테스트는 "선점된 디렉토리"로 판정되어 실패한다.
//! 검사를 느슨하게 하는 것은 `/tmp` 선점 방어를 무너뜨리므로, 테스트 쪽이 실제 런타임
//! 디렉토리와 같은 권한을 갖추는 것이 옳다.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// 런타임 디렉토리 권한 — `aic_common::paths`의 `RUNTIME_DIR_MODE`와 같은 값이다.
const RUNTIME_DIR_MODE: u32 = 0o700;

/// 런타임 디렉토리로 바로 쓸 수 있는 0700 tempdir.
pub(crate) fn runtime_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    chmod_runtime_dir(dir.path());
    dir
}

/// `path`와 그 조상 중 tempdir 안에 새로 만들어진 것을 0700으로 맞춘다.
///
/// 테스트가 런타임 디렉토리를 미리 만들어 둘 때 쓴다 — `create_dir_all`은 umask를 따르므로
/// 그대로 두면 신뢰성 검사에서 걸린다.
pub(crate) fn create_runtime_dir_all(path: &Path) {
    std::fs::create_dir_all(path).expect("런타임 디렉토리 생성");
    chmod_runtime_dir(path);
}

fn chmod_runtime_dir(path: &Path) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(RUNTIME_DIR_MODE))
        .expect("런타임 디렉토리 권한 설정");
}
