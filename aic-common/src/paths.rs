//! Cross-platform 소켓 경로 및 설정 경로 결정
//!
//! - macOS: `/tmp/aic-{uid}/session.sock`
//! - Linux: `$XDG_RUNTIME_DIR/aic/session.sock` (설정 시), 아니면 `/tmp/aic-{uid}/session.sock`
//!
//! Requirements: 2.1, 7.1, 7.3, 11.1, 11.2, 11.4

use std::path::{Path, PathBuf};

/// legacy 단일 UDS 소켓(`session.sock`)을 **찾을** 때의 경로.
/// 정규 경로에 없고 대체 후보에 있으면 그쪽을 쓴다 (`session_dir_candidates_for_os` 참고).
pub fn default_socket_path() -> PathBuf {
    discover_file(LEGACY_SOCKET_FILE)
}

/// 지정된 OS 문자열에 따라 **정규** 소켓 경로를 결정한다 (탐색 없음).
/// 테스트에서 OS를 주입할 수 있도록 분리.
pub fn resolve_socket_path(os: &str) -> PathBuf {
    session_dir_for_os(os).join(LEGACY_SOCKET_FILE)
}

const LEGACY_SOCKET_FILE: &str = "session.sock";

// ── 세션별 경로 함수 ──────────────────────────────────────────

/// 명시적 런타임 디렉토리 지정 환경변수.
///
/// **왜 필요한가**: 자동 후보 탐색은 "XDG 유무가 갈린 같은 사용자의 두 셸"을 이어 주려는
/// 휴리스틱이라, `/tmp/aic-{uid}`를 모든 후보 집합의 공통 원소로 둔다. 그 덕에 중복 기동을
/// 막을 수 있지만, `/tmp`와 uid를 공유하는 **다른 컨테이너**끼리도 서로를 막게 된다 —
/// 의도적으로 격리한 인스턴스가 남의 lock에 걸려 못 뜨는 것은 오탐이다(PID namespace 때문에
/// `is_pid_alive` 판정도 신뢰할 수 없다).
///
/// 이 변수가 설정되면 **자동 탐색을 끄고** 지정된 디렉토리 하나만 쓴다. "여기가 내 런타임
/// 디렉토리다"라는 명시 계약이므로, 다른 관례를 훑어 남의 인스턴스를 찾을 이유가 없다.
const RUNTIME_DIR_ENV: &str = "AIC_RUNTIME_DIR";

/// `AIC_RUNTIME_DIR`이 지정한 디렉토리. 빈 값과 **상대 경로**는 미설정으로 본다.
///
/// 상대 경로를 받아들이면 cwd가 다른 프로세스마다 다른 곳을 가리킨다 — 셸에서 띄운 aicd와
/// 다른 디렉토리에서 실행한 `aic`가 조용히 갈려, 이 변수가 막으려던 바로 그 상황(서로를 못
/// 찾는 두 인스턴스)을 만든다. 절대 경로만 계약으로 인정한다.
fn explicit_runtime_dir() -> Option<PathBuf> {
    let dir = std::env::var_os(RUNTIME_DIR_ENV)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())?;
    if !dir.is_absolute() {
        tracing::debug!(
            path = %dir.display(),
            "{RUNTIME_DIR_ENV}가 상대 경로라 무시한다 — 절대 경로만 인정한다"
        );
        return None;
    }
    Some(dir)
}

/// 플랫폼별 세션 디렉토리를 반환한다.
/// - `AIC_RUNTIME_DIR` 설정 시: 그 경로 (탐색 없음)
/// - macOS: `/tmp/aic-{uid}/`
/// - Linux: `$XDG_RUNTIME_DIR/aic/` (설정 시) 또는 `/tmp/aic-{uid}/`
pub fn session_dir() -> PathBuf {
    session_dir_for_os(std::env::consts::OS)
}

/// OS 문자열을 주입받아 세션 디렉토리를 결정한다 (테스트용).
fn session_dir_for_os(os: &str) -> PathBuf {
    if let Some(dir) = explicit_runtime_dir() {
        return dir;
    }
    match os {
        "linux" => {
            if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                PathBuf::from(runtime_dir).join("aic")
            } else {
                tmp_session_dir()
            }
        }
        _ => tmp_session_dir(),
    }
}

/// `/tmp/aic-{uid}/` 경로 생성
fn tmp_session_dir() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/aic-{}", uid))
}

/// systemd `--user` 세션의 표준 런타임 디렉토리 아래 aic 디렉토리 (`/run/user/{uid}/aic`).
/// `XDG_RUNTIME_DIR`이 비어 있을 때의 대체 후보로만 쓴다.
fn run_user_session_dir() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{}/aic", uid))
}

// ── 런타임 디렉토리 신뢰성 검사 ────────────────────────────────
//
// `/tmp/aic-{uid}`는 sticky 비트가 붙은 공용 `/tmp` 아래에 있어 **누구나 먼저 만들 수 있다**.
// 다른 로컬 사용자가 `aic-0/`을 선점해 `aicd.sock`·`session-*.sock`을 심어 두면, 그 경로를
// 후보로 훑는 root의 `aic`가 공격자 소켓에 연결한다(명령 노출·위조 응답). 위조 `aicd.pid`에
// 남의 살아 있는 PID를 적어 두면 `is_pid_alive`가 alive로 읽어 aicd 기동을 영구 차단할 수도
// 있다. 그래서 후보를 **쓰기 전에** 소유자·권한·symlink를 확인하고, 만들 때는 0700으로
// 고정한다.

/// 런타임 디렉토리 권한 — 소유자만 접근(0700). 새로 만들 때와 이어받을 때의 목표값이다.
const RUNTIME_DIR_MODE: u32 = 0o700;

/// **다른 사용자에게 쓰기를 허용하는 비트**(group/other write).
///
/// 신뢰 판정의 기준이 왜 "0700인가"가 아니라 "남이 쓸 수 있었는가"인지: 공격은 남이 그
/// 디렉토리에 `aicd.sock`·`aicd.pid`를 **심는** 것이고, 그러려면 디렉토리 쓰기 권한이
/// 필요하다. group/other에 읽기·실행만 열린 디렉토리(0755)는 목록이 보일 뿐 내용을 심을
/// 수 없으므로, 소유자가 나 자신이라면 그 안의 소켓은 내가 만든 것이 확실하다.
///
/// 이 구분이 실제로 중요한 이유: v0.35.0 이하는 런타임 디렉토리를 umask대로 만들어 보통
/// 0755였다. 판정을 0700 일치로 두면 업그레이드한 사용자의 멀쩡한 디렉토리가 전부
/// "선점됨"으로 거부되어 aicd가 뜨지 못한다(v0.36.0 실측).
const FOREIGN_WRITE_BITS: u32 = 0o022;

/// **다른 사용자의 디렉토리 진입(search)을 허용하는 비트**(group/other execute).
///
/// 디렉토리 안에 무언가를 심으려면 그 디렉토리의 쓰기 권한만으로는 부족하고, 부모를
/// 통과(`x`)해서 도달할 수 있어야 한다. 부모가 소유자에게만 진입을 허용하면 그 아래는
/// 남이 닿을 수 없다.
const FOREIGN_SEARCH_BITS: u32 = 0o011;

/// `dir`의 부모가 다른 사용자의 진입을 막고 있는지 — 막고 있으면 `dir` 자신의 group/other
/// write 비트가 열려 있어도 그 안의 내용은 내가 만든 것이 확실하다.
///
/// 왜 이 예외가 필요한가: `FOREIGN_WRITE_BITS`만 보는 판정은 구버전 디렉토리가 0755라고
/// 가정한다. 그런데 Ubuntu의 기본 umask는 `0002`라 실제로는 **0775**로 만들어진다. 이때
/// group write가 걸려 `/run/user/{uid}`(0700) 아래의 멀쩡한 디렉토리까지 "선점됨"으로
/// 거부되고, aicd가 재시작 루프에 갇혀 영구히 뜨지 못한다(v0.36.1 실측).
///
/// 부모를 경로 문자열로 `lstat`하지 않고 열린 fd로 `fstat`하는 이유는 `adopt_runtime_dir`과
/// 같다 — 검사와 사용 사이에 부모가 바뀌면 검사가 무의미해진다. `O_NOFOLLOW`가 symlink
/// 부모를, `O_DIRECTORY`가 디렉토리가 아닌 부모를 열기 단계에서 막는다. 열지 못하면
/// "막고 있다고 볼 근거 없음"으로 보아 엄격한 판정으로 되돌아간다.
fn parent_blocks_foreign_entry(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let Some(parent) = dir.parent() else {
        return false;
    };
    let Ok(handle) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(parent)
    else {
        return false;
    };
    let Ok(meta) = handle.metadata() else {
        return false;
    };
    if meta.uid() != unsafe { libc::getuid() } {
        return false;
    }
    meta.permissions().mode() & FOREIGN_SEARCH_BITS == 0
}

/// `dir`이 이 사용자 소유의, 남이 쓸 수 없는 실제 디렉토리인지. 없는 경로는 "아직 안전"으로
/// 본다 (만들 때 `ensure_runtime_dir`이 0700으로 만든다).
///
/// `symlink_metadata`(lstat)로 본다 — `metadata`는 symlink를 따라가므로, 공격자가 심어 둔
/// symlink가 자기 소유 디렉토리를 가리키면 검사를 통과해 버린다.
pub fn runtime_dir_is_trusted(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return false;
    }
    if meta.uid() != unsafe { libc::getuid() } {
        return false;
    }
    if meta.permissions().mode() & FOREIGN_WRITE_BITS == 0 {
        return true;
    }
    parent_blocks_foreign_entry(dir)
}

fn untrusted_runtime_dir_err(dir: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "런타임 디렉토리를 신뢰할 수 없습니다: {} — 다른 사용자 소유이거나 \
             symlink이거나 다른 사용자가 쓸 수 있는 권한입니다. 선점된 디렉토리일 수 \
             있으니 확인 후 제거하세요.",
            dir.display()
        ),
    )
}

/// 이미 있는 런타임 디렉토리를 이어받는다 — 필요하면 0700으로 조인다.
///
/// 구버전이 umask대로 만든 디렉토리(umask 022면 0755, Ubuntu 기본 umask 002면 0775)를
/// 그대로 쓰기 위한 마이그레이션이다. **남이 쓸 수 있었던 디렉토리는 조이지 않고
/// 거부한다** — 그 시점에 이미 무언가 심겼을 수 있어, 권한만 조여 봐야 내용의 출처를
/// 되돌릴 수 없기 때문이다. 다만 부모가 남의 진입을 막고 있었다면 group/other write가
/// 열려 있어도 남이 닿을 수 없었으므로 이어받는다(`parent_blocks_foreign_entry`).
///
/// 검사와 `chmod` 사이에 경로가 바뀌는 것(TOCTOU)을 막으려고 **열린 fd를 고정해** 그 fd로
/// 검사(`fstat`)하고 그 fd에 적용(`fchmod`)한다. `O_NOFOLLOW`는 마지막 요소가 symlink면,
/// `O_DIRECTORY`는 디렉토리가 아니면 열기 자체를 실패시킨다.
fn adopt_runtime_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;

    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|_| untrusted_runtime_dir_err(dir))?;

    let meta = handle.metadata()?;
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(untrusted_runtime_dir_err(dir));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & FOREIGN_WRITE_BITS != 0 && !parent_blocks_foreign_entry(dir) {
        return Err(untrusted_runtime_dir_err(dir));
    }
    if mode == RUNTIME_DIR_MODE {
        return Ok(());
    }
    if unsafe { libc::fchmod(handle.as_raw_fd(), RUNTIME_DIR_MODE as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 런타임 디렉토리를 0700으로 보장한다. 이미 있으면 소유자·권한·symlink를 검사하고,
/// 내 소유이면서 남이 쓸 수 없던 디렉토리는 0700으로 조여 이어받는다.
///
/// 소켓·lock을 만들기 **전에** 부르는 쪽에서 쓴다. 검사에 실패하면 만들지 않고 에러 —
/// 남이 선점한 디렉토리에 데몬을 띄우면 그 자체가 사고다.
pub fn ensure_runtime_dir(dir: &Path) -> std::io::Result<()> {
    ensure_runtime_dir_inner(dir, 1)
}

/// `retries_left`는 생성 경합(`AlreadyExists`) 재확인 횟수의 상한이다. 무한 재귀를 막는다 —
/// 누가 계속 만들었다 지우면 상한 없이 도는 코드가 된다.
fn ensure_runtime_dir_inner(dir: &Path, retries_left: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;

    if !runtime_dir_is_trusted(dir) {
        return Err(untrusted_runtime_dir_err(dir));
    }
    if dir.exists() {
        return adopt_runtime_dir(dir);
    }
    // 부모까지는 관례대로 만들고(`/run/user/{uid}` 등 이미 있는 게 보통), 마지막 요소만
    // 0700으로 만든다. mode는 umask의 영향을 받으므로 생성 후 명시적으로 다시 설정한다.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::DirBuilder::new()
        .mode(RUNTIME_DIR_MODE)
        .create(dir)
    {
        Ok(()) => {}
        // 경합으로 누가 먼저 만들었으면 그게 우리 것인지 다시 본다.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && retries_left > 0 => {
            return ensure_runtime_dir_inner(dir, retries_left - 1);
        }
        Err(e) => return Err(e),
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(RUNTIME_DIR_MODE))?;
    Ok(())
}

// ── aicd 경로: 만드는 쪽과 찾는 쪽의 분리 ────────────────────────
//
// `session_dir()`는 **현재 프로세스의 환경**만 보고 한 곳을 정하는데, 그 환경이 데몬의
// 환경과 다를 수 있다. systemd `--user`로 뜬 aicd에는 `XDG_RUNTIME_DIR`이 있어 소켓이
// `/run/user/{uid}/aic`에 생기지만, 로그인 셸이 아닌 곳(`make`, cron, 에이전트 셸)에는
// 그 변수가 없어 `session_dir()`가 `/tmp/aic-{uid}`로 갈린다. 그러면 클라이언트는 멀쩡히
// 도는 데몬을 "실행 중이 아님"으로 본다 — `aic daemon restart --if-running`이 조용히
// skip돼 `make install`/`aic update` 뒤에도 구버전 데몬이 계속 도는 사고가 여기서 났다.
//
// 그래서 **찾을 때만**(`aicd_*_path`) 두 관례를 순서대로 훑어 실제 소켓이 있는 쪽을 쓴다.
// 만드는 쪽(`aicd_*_path_for_bind`)은 `session_dir()` 한 곳으로 고정한다 — 파일 잔해에
// 따라 데몬이 매번 다른 곳에 bind하면 그게 더 찾기 어려운 문제가 된다.

const AICD_SOCKET_FILE: &str = "aicd.sock";
const AICD_LOCK_FILE: &str = "aicd.pid";
const AICD_ATTACH_SOCKET_FILE: &str = "aicd-attach.sock";
const AICD_REGISTRY_FILE: &str = "aicd-registry.json";

/// aicd를 찾을 때 훑을 세션 디렉토리 후보. 0번이 정규 경로(`session_dir()`)다.
fn session_dir_candidates_for_os(os: &str) -> Vec<PathBuf> {
    let canonical = session_dir_for_os(os);
    // 명시 계약이 있으면 자동 탐색을 하지 않는다 — 격리하겠다고 선언한 인스턴스가 관례 경로를
    // 훑어 남의 데몬을 찾아내면 격리가 아니다(`RUNTIME_DIR_ENV` 주석 참고).
    if explicit_runtime_dir().is_some() {
        return vec![canonical];
    }
    if os != "linux" {
        return vec![canonical];
    }
    // linux의 두 관례를 서로의 대체 후보로 둔다. XDG가 **설정돼 있으면** `/run/user/{uid}`는
    // 후보에 넣지 않는다 — 격리 환경(테스트/컨테이너)이 의도적으로 다른 런타임 디렉토리를
    // 가리킨 상황이라, 거기서 시스템 데몬으로 새는 편이 못 찾는 것보다 나쁘다.
    let alt = if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        tmp_session_dir()
    } else {
        run_user_session_dir()
    };
    if alt == canonical {
        vec![canonical]
    } else {
        vec![canonical, alt]
    }
}

/// 탐색에 실제로 쓸 후보 — 관례 후보에서 **남이 선점한 디렉토리를 뺀 것**.
///
/// 관례 계산(`session_dir_candidates_for_os`)은 환경변수만 보는 순수 함수로 두고, 파일시스템
/// 상태를 보는 필터는 여기서만 건다. 섞어 두면 같은 입력이 머신 상태에 따라 다른 값을 내
/// 테스트가 흔들린다.
///
/// **이 필터는 방어의 전부가 아니다.** 검사와 연결 사이의 틈(TOCTOU)은 닫지 못하고, 후보가
/// 전부 걸러진 폴백에서는 정규 경로를 그대로 남긴다 — 경로를 아예 못 만들면 "데몬 없음"조차
/// 보고할 수 없기 때문이다. 실제로 남의 소켓에 붙는 것을 막는 것은 연결 후의 uid 검사
/// (`peercred::ensure_peer_is_self`)이고, 이 필터는 거기 도달하기 전에 명백한 선점을 걸러내는
/// 1차 방어다.
fn trusted_candidates(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let trusted: Vec<PathBuf> = candidates
        .iter()
        .filter(|dir| runtime_dir_is_trusted(dir))
        .cloned()
        .collect();
    if trusted.is_empty() {
        candidates.into_iter().take(1).collect()
    } else {
        trusted
    }
}

/// 이 프로세스가 탐색에 쓸 후보 목록 (관례 + 신뢰성 필터).
fn discovery_candidates() -> Vec<PathBuf> {
    trusted_candidates(session_dir_candidates_for_os(std::env::consts::OS))
}

/// 후보 중 실제 `aicd.sock`이 있는 첫 디렉토리. 아무 데도 없으면 정규 경로(= 종전 동작).
///
/// 소켓 하나를 기준점으로 삼아 lock·registry·attach까지 같은 디렉토리에서 뽑는다 —
/// 파일마다 따로 탐색하면 `aic daemon status`가 한쪽의 socket과 다른 쪽의 pid를 섞어
/// 보여줄 수 있다.
fn resolve_aicd_dir(candidates: &[PathBuf]) -> PathBuf {
    candidates
        .iter()
        .find(|dir| dir.join(AICD_SOCKET_FILE).exists())
        .or_else(|| candidates.first())
        .cloned()
        .unwrap_or_else(session_dir)
}

fn aicd_dir() -> PathBuf {
    resolve_aicd_dir(&discovery_candidates())
}

/// 후보를 순서대로 훑어 `file`이 실제로 있는 첫 경로. 없으면 정규 경로(= 종전 동작).
///
/// aicd는 `aicd.sock` 하나를 디렉토리 기준점으로 삼지만(`resolve_aicd_dir`), 세션 소켓은
/// 파일마다 주인이 달라 기준점으로 쓸 단일 파일이 없다. 그래서 파일 단위로 훑는다.
fn resolve_file_in(candidates: &[PathBuf], file: &str) -> PathBuf {
    let canonical = candidates.first().cloned().unwrap_or_else(session_dir);
    candidates
        .iter()
        .map(|dir| dir.join(file))
        .find(|path| path.exists())
        .unwrap_or_else(|| canonical.join(file))
}

fn discover_file(file: &str) -> PathBuf {
    resolve_file_in(&discovery_candidates(), file)
}

fn session_socket_file(session_id: &str) -> String {
    format!("session-{}.sock", session_id)
}

/// Session_ID의 세션 소켓을 **찾을** 때의 경로.
/// 예: `/tmp/aic-{uid}/session-a1b2c3d4.sock`
///
/// aicd와 같은 이유로 두 후보를 훑는다 — 로그인 셸에서 띄운 세션(XDG 있음 → `/run/user`)을
/// XDG 없는 셸의 `aic`가 못 찾으면 `aic history` 같은 명령이 조용히 빈손이 된다.
pub fn session_socket_path(session_id: &str) -> PathBuf {
    discover_file(&session_socket_file(session_id))
}

/// 세션 소켓을 **만들** 때의 정규 경로. 탐색과 달리 파일 존재 여부를 보지 않는다.
pub fn session_socket_path_for_bind(session_id: &str) -> PathBuf {
    session_dir().join(session_socket_file(session_id))
}

/// Session_ID가 후보 디렉토리 어디에서든 이미 쓰이고 있는지.
///
/// 소켓과 PID lock을 모두 본다 — 비정상 종료로 lock만 남은 id를 재사용하면
/// `DaemonLock::acquire`가 뒤늦게 실패한다. 정규 경로만 보면 다른 런타임 디렉토리에
/// 살아 있는 세션과 같은 id를 뽑아, 탐색이 남의 세션을 가리키게 된다.
pub fn session_id_in_use(session_id: &str) -> bool {
    let socket = session_socket_file(session_id);
    let lock = format!("session-{}.pid", session_id);
    discovery_candidates()
        .iter()
        .any(|dir| dir.join(&socket).exists() || dir.join(&lock).exists())
}

/// `aicd` supervisor daemon의 control UDS 소켓 경로 (탐색).
/// 사용자당 하나만 존재한다.
pub fn aicd_socket_path() -> PathBuf {
    aicd_dir().join(AICD_SOCKET_FILE)
}

/// `aicd` supervisor daemon의 PID lock 파일 경로 (탐색).
pub fn aicd_lock_path() -> PathBuf {
    aicd_dir().join(AICD_LOCK_FILE)
}

/// `aicd` supervisor daemon의 Attach_UDS 소켓 경로 (Phase 3.3, 탐색).
///
/// `aic-session` 이 PTY raw byte stream 을 `aicd` 로 보낼 때 사용한다.
/// Control_UDS(`aicd.sock`) 와 같은 부모 디렉토리(0700) 아래에 두며,
/// 소켓 파일 자체 권한은 0600 (R15.3).
pub fn aicd_attach_socket_path() -> PathBuf {
    aicd_dir().join(AICD_ATTACH_SOCKET_FILE)
}

/// `aicd` supervisor daemon의 registry snapshot 경로 (탐색).
///
/// 런타임 세션 복구용이므로 control socket/lock과 같은 디렉토리 아래에 둔다.
pub fn aicd_registry_path() -> PathBuf {
    aicd_dir().join(AICD_REGISTRY_FILE)
}

/// aicd가 control UDS를 **만들** 때 쓰는 정규 경로. 탐색과 달리 파일 존재 여부를 보지 않는다.
pub fn aicd_socket_path_for_bind() -> PathBuf {
    session_dir().join(AICD_SOCKET_FILE)
}

/// aicd가 PID lock을 **만들** 때 쓰는 정규 경로.
pub fn aicd_lock_path_for_bind() -> PathBuf {
    session_dir().join(AICD_LOCK_FILE)
}

/// aicd PID lock의 후보 경로 전체 (0번이 정규 경로).
///
/// 중복 기동 검사용이다. lock은 정규 경로 한 곳에만 잡으므로, XDG 유무가 갈리는 두
/// 프로세스는 서로의 lock을 못 보고 각자 데몬을 띄운다. 기동 전에 이 목록을 훑어
/// 살아 있는 aicd가 있는지 본다.
pub fn aicd_lock_path_candidates() -> Vec<PathBuf> {
    discovery_candidates()
        .into_iter()
        .map(|dir| dir.join(AICD_LOCK_FILE))
        .collect()
}

/// aicd가 Attach_UDS를 **만들** 때 쓰는 정규 경로.
pub fn aicd_attach_socket_path_for_bind() -> PathBuf {
    session_dir().join(AICD_ATTACH_SOCKET_FILE)
}

/// aicd가 registry snapshot을 **쓸** 때의 정규 경로.
pub fn aicd_registry_path_for_bind() -> PathBuf {
    session_dir().join(AICD_REGISTRY_FILE)
}

/// daemonless mode에서 `aic`가 읽는 마지막 command record 경로.
pub fn local_command_record_path() -> PathBuf {
    session_dir().join("last-command.json")
}

/// 영속 상태 디렉터리 (XDG State). `$XDG_STATE_HOME/aic` 또는 `~/.local/state/aic`.
/// session_dir(runtime, ephemeral)과 달리 재부팅을 넘어 보존되는 로그/이벤트용.
pub fn state_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(xdg).join("aic")
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~"));
        home.join(".local").join("state").join("aic")
    }
}

/// aicd webhook 수신·처리 이벤트 로그(JSONL) 경로 (SRE R2). `aic webhook list`가 읽는다.
pub fn webhook_events_path() -> PathBuf {
    state_dir().join("webhook-events.jsonl")
}

/// `config.toml` 경로 (XDG Base Directory). aic-client(ConfigManager)와 aicd(aic-server)가
/// 동일 경로를 읽도록 단일 출처로 둔다. `$XDG_CONFIG_HOME/aic/config.toml` 또는 `~/.config/aic/config.toml`.
pub fn config_file_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("aic").join("config.toml")
    } else {
        // aic-common은 lean하게 유지(dirs 미사용) — HOME에서 직접 결정.
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~"));
        home.join(".config").join("aic").join("config.toml")
    }
}

/// aicd OTLP exporter 오프라인 spool 디렉토리 (SRE t8). `~/.aic/otlp-spool/`.
///
/// 다른 aic 경로들과 달리 XDG 관례(`state_dir`/`config_file_path`) 대신 고정 `~/.aic` 하위를
/// 쓴다 — t8 interface contract가 이 경로를 명시했고, spool은 세션 runtime도 XDG state도
/// 아닌 "collector 다운 동안 버티는 로컬 디스크 버퍼"라는 별도 범주라 구분해 두는 편이 찾기
/// 쉽다. 디렉토리는 `Spool::open`이 0700 권한으로 생성한다(다른 로컬 사용자가 spool된 —
/// 이미 redact된 — protobuf payload를 못 읽게).
pub fn otlp_spool_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    home.join(".aic").join("otlp-spool")
}

/// aicd 로그 수집기(journald/file/container) 체크포인트 디렉토리 (RFC-006). `~/.aic/log-checkpoints/`.
///
/// `otlp_spool_dir`과 동일한 이유로 XDG 관례 대신 고정 `~/.aic` 하위를 쓴다 — 이 디렉토리는
/// 세션 runtime도 XDG state도 아닌 "재시작 후 이어 읽기 위한 로컬 커서 저장소"라는 별도
/// 범주다. 디렉토리는 `CheckpointStore::open`이 0700 권한으로 생성한다.
pub fn log_checkpoint_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    home.join(".aic").join("log-checkpoints")
}

/// shell hook start/end 사이의 임시 metadata 경로.
pub fn local_hook_pending_path(session_id: &str, command_id: &str) -> PathBuf {
    let safe_session = sanitize_path_token(session_id);
    let safe_command = sanitize_path_token(command_id);
    session_dir().join(format!("hook-pending-{safe_session}-{safe_command}.json"))
}

fn sanitize_path_token(value: &str) -> String {
    let out: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(64)
        .collect();
    if out.is_empty() {
        "none".to_string()
    } else {
        out
    }
}

/// 소켓 경로에서 Session_ID를 추출한다.
/// `session-{id}.sock` 형식의 파일명에서 `{id}` 부분을 반환한다.
/// 형식이 맞지 않으면 `None`을 반환한다.
pub fn extract_session_id(socket_path: &Path) -> Option<String> {
    let file_name = socket_path.file_name()?.to_str()?;
    let id = file_name.strip_prefix("session-")?.strip_suffix(".sock")?;
    if id.is_empty() {
        return None;
    }
    Some(id.to_string())
}

/// 후보 디렉토리 전체의 `session-*.sock`을 mtime 내림차순(최신 우선)으로 반환.
///
/// 한 디렉토리만 보면 XDG 유무가 갈리는 셸에서 세션 목록이 통째로 비어 보인다.
pub fn list_session_sockets() -> Vec<PathBuf> {
    list_session_sockets_in_all(&discovery_candidates())
}

/// 여러 디렉토리를 합쳐 최신 우선으로 정렬한다. 같은 파일명이 두 곳에 있으면 최신 것만 남긴다
/// (같은 Session_ID가 양쪽에 있는 건 비정상이라, 오래된 잔해가 최신 세션을 가리는 걸 막는다).
///
/// 디렉토리별로 정렬한 결과를 이어 붙이면 안 된다 — 뒤 디렉토리의 최신 세션이 앞 디렉토리의
/// 오래된 세션 뒤로 밀려, `resolve_active_socket`이 엉뚱한 세션을 고른다.
pub fn list_session_sockets_in_all(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut all: Vec<(PathBuf, std::time::SystemTime)> = dirs
        .iter()
        .flat_map(|dir| stat_session_sockets(dir))
        .collect();
    all.sort_by_key(|p| std::cmp::Reverse(p.1));
    let mut seen = std::collections::HashSet::new();
    all.into_iter()
        .filter_map(|(path, _)| {
            let name = path.file_name()?.to_owned();
            seen.insert(name).then_some(path)
        })
        .collect()
}

/// 테스트 가능한 inner helper — 임의 디렉토리에서 `session-*.sock` 파일 enumerate.
pub fn list_session_sockets_in(dir: &Path) -> Vec<PathBuf> {
    let mut paths = stat_session_sockets(dir);
    // mtime 내림차순(최신 우선). clippy::unnecessary_sort_by 회피용 sort_by_key + Reverse.
    paths.sort_by_key(|p| std::cmp::Reverse(p.1));
    paths.into_iter().map(|(p, _)| p).collect()
}

/// `session-*.sock`을 mtime과 함께 수집한다(정렬 없음). 여러 디렉토리를 합칠 때
/// 전역 정렬을 하려면 mtime이 살아 있어야 해서 분리했다.
fn stat_session_sockets(dir: &Path) -> Vec<(PathBuf, std::time::SystemTime)> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_str()?;
            if !name.starts_with("session-") || !name.ends_with(".sock") {
                return None;
            }
            let mtime = e.metadata().ok().and_then(|m| m.modified().ok())?;
            Some((p, mtime))
        })
        .collect()
}

/// 활성 세션 소켓 경로를 우선순위에 따라 결정한다.
/// 우선순위: explicit_id > $AIC_SESSION_ID env > 가장 최근 session-*.sock > legacy default_socket_path.
pub fn resolve_active_socket(explicit_id: Option<&str>) -> PathBuf {
    if let Some(id) = explicit_id.map(str::trim).filter(|s| !s.is_empty()) {
        return session_socket_path(id);
    }
    if let Ok(env_id) = std::env::var("AIC_SESSION_ID") {
        let trimmed = env_id.trim();
        if !trimmed.is_empty() {
            return session_socket_path(trimmed);
        }
    }
    list_session_sockets()
        .into_iter()
        .next()
        .unwrap_or_else(default_socket_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_is_absolute() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = default_socket_path();
        assert!(path.is_absolute());
    }

    // ── 런타임 디렉토리 신뢰성 ────────────────────────────────

    /// 이 테스트가 지키는 것: 공용 `/tmp` 아래 후보를 남이 선점했을 때 거부하는 동작.
    /// 깨지면 다른 로컬 사용자가 심어 둔 `aicd.sock`으로 연결이 새어 나간다.
    ///
    /// 기준은 "0700인가"가 아니라 **"남이 쓸 수 있는가"**다 — 소켓을 심으려면 디렉토리
    /// 쓰기 권한이 있어야 하므로, group/other write가 판정선이다.
    #[test]
    fn runtime_dir_is_trusted_rejects_foreign_writable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("trust-perm");
        // 부모가 남의 진입을 허용해야 "남이 쓸 수 있는가"가 실제 판정선이 된다. 개발자
        // umask에 따라 `unique_temp_dir`이 0700을 만들면 부모 예외가 걸려 이 테스트의
        // 전제가 사라지므로 명시적으로 고정한다.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = tmp.join("aic-0");
        std::fs::create_dir(&dir).unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(runtime_dir_is_trusted(&dir));

        for writable in [0o770, 0o707, 0o777, 0o720, 0o702] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(writable)).unwrap();
            assert!(
                !runtime_dir_is_trusted(&dir),
                "0{writable:o}는 남이 파일을 심을 수 있어 신뢰할 수 없다"
            );
        }
    }

    /// 이 테스트가 지키는 것: **업그레이드 경로**. v0.35.0 이하는 런타임 디렉토리를 umask대로
    /// 만들어 보통 0755였다. 이를 "선점됨"으로 거부하면 업그레이드한 사용자의 aicd가 뜨지
    /// 못한다(v0.36.0 실측). 남이 쓸 수 없는 권한이면 내 것이 확실하므로 신뢰해야 한다.
    #[test]
    fn runtime_dir_is_trusted_accepts_legacy_readable_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("trust-legacy");
        let dir = tmp.join("aic-0");
        std::fs::create_dir(&dir).unwrap();

        for legacy in [0o755, 0o750, 0o705, 0o711] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(legacy)).unwrap();
            assert!(
                runtime_dir_is_trusted(&dir),
                "0{legacy:o}는 남이 쓸 수 없으므로 내 디렉토리가 확실하다"
            );
        }
    }

    /// 이 테스트가 지키는 것: **Ubuntu 기본 umask(0002) 업그레이드 경로**. 구버전이 남긴
    /// 런타임 디렉토리는 0755가 아니라 0775이고, group write만 보고 거부하면
    /// `/run/user/{uid}`(0700) 아래의 멀쩡한 디렉토리까지 막혀 aicd가 재시작 루프에
    /// 갇힌다(okrd-rca-central에서 3일 반 다운, v0.36.1 실측).
    ///
    /// 부모가 진입을 막고 있으면 남이 애초에 닿을 수 없었으므로 신뢰해야 한다.
    #[test]
    fn runtime_dir_is_trusted_accepts_group_writable_under_closed_parent() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("trust-closed-parent");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.join("aic");
        std::fs::create_dir(&dir).unwrap();

        for umask002 in [0o775, 0o770, 0o777] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(umask002)).unwrap();
            assert!(
                runtime_dir_is_trusted(&dir),
                "0{umask002:o}라도 부모가 0700이면 남이 도달할 수 없다"
            );
        }
    }

    /// 부모 예외는 **부모가 진입을 막을 때만** 열린다. `/tmp/aic-{uid}`처럼 누구나 통과할
    /// 수 있는 부모 아래에서는 group/other write가 그대로 거부 사유다 — 이게 깨지면
    /// `/tmp` 선점 방어가 무너진다.
    #[test]
    fn runtime_dir_is_trusted_rejects_group_writable_under_open_parent() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("trust-open-parent");
        let dir = tmp.join("aic-0");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();

        for parent in [0o755, 0o751, 0o711, 0o777] {
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(parent)).unwrap();
            assert!(
                !runtime_dir_is_trusted(&dir),
                "부모 0{parent:o}는 남의 진입을 허용하므로 0775를 신뢰하면 안 된다"
            );
        }
        // 다음 테스트/정리가 지울 수 있도록 되돌린다.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// 부모가 막고 있는 0775 디렉토리는 이어받으면서 0700으로 조이고 내용은 보존한다 —
    /// 살아 있는 세션 소켓과 registry snapshot을 지우면 안 된다.
    #[test]
    fn ensure_runtime_dir_tightens_umask002_dir_under_closed_parent() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("ensure-umask002");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.join("aic");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();

        let marker = dir.join("aicd-registry.json");
        std::fs::write(&marker, b"{}\n").unwrap();

        ensure_runtime_dir(&dir).expect("부모가 0700이면 0775도 이어받아야 한다");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "이어받으면서 0700으로 조여야 한다");
        assert!(marker.exists(), "디렉토리 내용은 그대로 두어야 한다");

        // 재호출은 멱등.
        ensure_runtime_dir(&dir).expect("재호출 실패");
    }

    /// 구버전이 남긴 0755 디렉토리를 이어받으며 0700으로 조인다 — 사용자가 손으로
    /// `chmod 700`을 하지 않아도 업그레이드가 이어져야 한다.
    #[test]
    fn ensure_runtime_dir_tightens_legacy_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("ensure-legacy");
        let dir = tmp.join("aic-0");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 디렉토리 안의 내용은 보존된다 — 살아 있는 세션 소켓을 지우면 안 된다.
        let marker = dir.join("aicd.pid");
        std::fs::write(&marker, b"1234\n").unwrap();

        ensure_runtime_dir(&dir).expect("내 소유 0755는 이어받아야 한다");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "이어받으면서 0700으로 조여야 한다");
        assert!(marker.exists(), "디렉토리 내용은 그대로 두어야 한다");

        // 재호출은 멱등.
        ensure_runtime_dir(&dir).expect("재호출 실패");
    }

    /// symlink는 이어받기 경로에서도 거부해야 한다 — `O_NOFOLLOW`가 그것을 보장한다.
    /// 검사만 lstat으로 하고 chmod를 경로로 하면 그 사이에 링크로 바꿔치기할 수 있다.
    #[test]
    fn ensure_runtime_dir_refuses_symlink_even_when_target_is_ours() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("ensure-link");
        let real = tmp.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = tmp.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = ensure_runtime_dir(&link).expect_err("symlink는 거부해야 한다");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "거부했으면 대상 권한도 건드리지 않아야 한다");
    }

    /// symlink는 lstat으로 걸러야 한다 — 따라가서 검사하면 공격자가 자기 소유 디렉토리를
    /// 가리키는 링크를 심어 검사를 통과시킬 수 있다.
    #[test]
    fn runtime_dir_is_trusted_rejects_symlink_and_non_dir() {
        let tmp = unique_temp_dir("trust-link");
        let real = tmp.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(!runtime_dir_is_trusted(&link));

        let file = tmp.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(!runtime_dir_is_trusted(&file));
    }

    /// 없는 경로는 "아직 안전" — `ensure_runtime_dir`이 0700으로 만든다.
    #[test]
    fn ensure_runtime_dir_creates_with_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("ensure-create");
        let dir = tmp.join("nested/aic");
        assert!(runtime_dir_is_trusted(&dir), "없는 경로는 통과");

        ensure_runtime_dir(&dir).expect("생성 실패");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "umask와 무관하게 0700이어야 한다");

        // 재호출은 멱등.
        ensure_runtime_dir(&dir).expect("재호출 실패");
    }

    /// 선점된 디렉토리에는 만들지도, 쓰지도 않는다.
    #[test]
    fn ensure_runtime_dir_refuses_untrusted_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("ensure-untrusted");
        // 부모 예외(`parent_blocks_foreign_entry`)가 걸리지 않도록 진입을 열어 둔다.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = tmp.join("aic-0");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = ensure_runtime_dir(&dir).expect_err("0777 디렉토리를 받아들이면 안 된다");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn default_socket_path_ends_with_session_sock() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = default_socket_path();
        assert!(path.ends_with("session.sock"));
    }

    // `XDG_RUNTIME_DIR`/`AIC_RUNTIME_DIR`은 프로세스 전역이라, 이를 set/remove하는 테스트가
    // 병렬 실행되면 한 테스트가 assert 하기 전에 다른 테스트가 값을 바꿔 간헐적으로
    // 깨진다(env-race). 아래 락으로 직렬화하고, 각 테스트는 원래 값을 저장했다가 복원한다.
    //
    // **읽기만 하는 테스트도 이 락을 잡아야 한다.** `session_dir()`의 결과가 곧 환경변수의
    // 함수라, 값을 바꾸지 않아도 남이 바꾼 창에 관측하면 똑같이 깨진다.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_linux_with_xdg_runtime() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let path = resolve_socket_path("linux");
        assert_eq!(path, PathBuf::from("/run/user/1000/aic/session.sock"));
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn resolve_linux_without_xdg_runtime() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let path = resolve_socket_path("linux");
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/aic-{}/session.sock", uid))
        );
        if let Some(v) = prev {
            std::env::set_var("XDG_RUNTIME_DIR", v);
        }
    }

    #[test]
    fn resolve_macos() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = resolve_socket_path("macos");
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/aic-{}/session.sock", uid))
        );
    }

    // ── session_dir tests ──────────────────────────────────────

    #[test]
    fn session_dir_is_absolute() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(session_dir().is_absolute());
    }

    // ── session_socket_path tests ──────────────────────────────

    #[test]
    fn session_socket_path_format() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = session_socket_path("a1b2c3d4");
        assert!(path.is_absolute());
        assert!(path.ends_with("session-a1b2c3d4.sock"));
    }

    /// 탐색은 "어느 후보에도 없으면 정규 경로"가 계약이다. 실재하지 않는 id를 써서
    /// 대체 후보의 우연한 파일에 결과가 흔들리지 않게 한다.
    #[test]
    fn session_socket_path_defaults_to_session_dir_when_absent() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = session_socket_path("ffffffff");
        assert!(!path.exists(), "테스트 전제: 이 id의 소켓은 없어야 한다");
        assert_eq!(path.parent().unwrap(), session_dir());
    }

    // ── aicd 경로: bind(정규) vs 탐색 ──────────────────────────

    /// 만드는 쪽은 환경만 보고 `session_dir()` 한 곳으로 고정돼야 한다.
    #[test]
    fn aicd_bind_paths_are_pinned_to_session_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (path, name) in [
            (aicd_socket_path_for_bind(), "aicd.sock"),
            (aicd_lock_path_for_bind(), "aicd.pid"),
            (aicd_attach_socket_path_for_bind(), "aicd-attach.sock"),
            (aicd_registry_path_for_bind(), "aicd-registry.json"),
        ] {
            assert_eq!(path.parent().unwrap(), session_dir(), "{name}");
            assert!(path.ends_with(name));
        }
    }

    /// 탐색 결과는 네 경로가 **같은** 디렉토리에서 나와야 한다 — socket은 이쪽,
    /// pid는 저쪽으로 갈리면 `aic daemon status`가 섞인 정보를 보여준다.
    #[test]
    fn aicd_discovered_paths_share_one_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = aicd_socket_path().parent().unwrap().to_path_buf();
        assert_eq!(aicd_lock_path().parent().unwrap(), dir);
        assert_eq!(aicd_attach_socket_path().parent().unwrap(), dir);
        assert_eq!(aicd_registry_path().parent().unwrap(), dir);
    }

    #[test]
    fn resolve_aicd_dir_prefers_canonical_when_socket_is_there() {
        let canonical = unique_temp_dir("aicd-canonical");
        let alt = unique_temp_dir("aicd-alt");
        fs::write(canonical.join(AICD_SOCKET_FILE), b"").unwrap();
        fs::write(alt.join(AICD_SOCKET_FILE), b"").unwrap();
        assert_eq!(
            resolve_aicd_dir(&[canonical.clone(), alt.clone()]),
            canonical
        );
        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    /// 이 테스트가 지키는 것: systemd로 뜬 aicd(대체 후보)를 XDG 없는 셸(정규=/tmp)에서
    /// 찾아내는 동작. 깨지면 `make install` 후 재시작이 조용히 skip된다.
    #[test]
    fn resolve_aicd_dir_falls_back_to_alt_when_canonical_is_empty() {
        let canonical = unique_temp_dir("aicd-empty");
        let alt = unique_temp_dir("aicd-live");
        fs::write(alt.join(AICD_SOCKET_FILE), b"").unwrap();
        assert_eq!(resolve_aicd_dir(&[canonical.clone(), alt.clone()]), alt);
        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    /// 어디에도 소켓이 없으면 종전대로 정규 경로 — 데몬 미실행 시 표시할 경로가 필요하다.
    #[test]
    fn resolve_aicd_dir_defaults_to_canonical_when_nothing_found() {
        let canonical = unique_temp_dir("aicd-none-a");
        let alt = unique_temp_dir("aicd-none-b");
        assert_eq!(
            resolve_aicd_dir(&[canonical.clone(), alt.clone()]),
            canonical
        );
        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    #[test]
    fn session_dir_candidates_without_xdg_include_run_user() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let candidates = session_dir_candidates_for_os("linux");
        assert_eq!(candidates[0], tmp_session_dir(), "0번은 정규 경로");
        assert_eq!(
            candidates[1],
            run_user_session_dir(),
            "systemd --user 쪽 대체"
        );
        if let Some(v) = prev {
            std::env::set_var("XDG_RUNTIME_DIR", v);
        }
    }

    /// XDG가 잡혀 있으면 `/run/user/{uid}`는 후보가 아니다 — 격리 환경이 의도적으로
    /// 다른 런타임 디렉토리를 가리킨 것이라, 시스템 데몬으로 새면 안 된다.
    #[test]
    fn session_dir_candidates_with_xdg_do_not_leak_to_run_user() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", "/tmp/isolated-runtime");
        let candidates = session_dir_candidates_for_os("linux");
        assert_eq!(candidates[0], PathBuf::from("/tmp/isolated-runtime/aic"));
        assert_eq!(candidates[1], tmp_session_dir());
        assert!(!candidates.contains(&run_user_session_dir()));
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    /// 이 테스트가 지키는 것: `AIC_RUNTIME_DIR`의 격리 계약. 깨지면 `/tmp`를 공유하는
    /// 다른 컨테이너의 lock·소켓에 걸려, 격리하겠다고 선언한 인스턴스가 못 뜬다.
    #[test]
    fn explicit_runtime_dir_disables_candidate_discovery() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        let prev_explicit = std::env::var(RUNTIME_DIR_ENV).ok();

        // XDG가 잡혀 있어도 명시 지정이 이긴다.
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        std::env::set_var(RUNTIME_DIR_ENV, "/srv/aic-isolated");

        assert_eq!(
            session_dir_for_os("linux"),
            PathBuf::from("/srv/aic-isolated")
        );
        assert_eq!(
            session_dir_candidates_for_os("linux"),
            vec![PathBuf::from("/srv/aic-isolated")],
            "명시 계약이 있으면 관례 경로를 훑지 않는다"
        );
        assert_eq!(
            session_dir_candidates_for_os("macos"),
            vec![PathBuf::from("/srv/aic-isolated")]
        );

        // 빈 값은 미설정으로 본다 — 스크립트가 빈 변수를 export 하는 흔한 사고 방어.
        std::env::set_var(RUNTIME_DIR_ENV, "");
        assert_eq!(
            session_dir_for_os("linux"),
            PathBuf::from("/run/user/1000/aic")
        );

        // 상대 경로도 무시한다 — cwd에 따라 프로세스마다 다른 곳을 가리키면 계약이 아니다.
        std::env::set_var(RUNTIME_DIR_ENV, "runtime/aic");
        assert_eq!(
            session_dir_for_os("linux"),
            PathBuf::from("/run/user/1000/aic"),
            "상대 경로는 관례 경로로 되돌아가야 한다"
        );

        match prev_explicit {
            Some(v) => std::env::set_var(RUNTIME_DIR_ENV, v),
            None => std::env::remove_var(RUNTIME_DIR_ENV),
        }
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    /// 신뢰 필터는 주입된 목록만 보는 순수 함수 — 머신의 `/tmp` 상태에 흔들리지 않는다.
    #[test]
    fn trusted_candidates_drops_hijacked_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = unique_temp_dir("trusted-filter");
        let good = tmp.join("good");
        let hijacked = tmp.join("hijacked");
        fs::create_dir(&good).unwrap();
        fs::create_dir(&hijacked).unwrap();
        fs::set_permissions(&good, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&hijacked, fs::Permissions::from_mode(0o777)).unwrap();

        assert_eq!(
            trusted_candidates(vec![good.clone(), hijacked.clone()]),
            vec![good.clone()]
        );

        // 정규 경로가 선점당하고 대체 후보가 멀쩡하면 대체 쪽으로 탐색이 넘어간다.
        assert_eq!(
            trusted_candidates(vec![hijacked.clone(), good.clone()]),
            vec![good]
        );

        // 전부 걸러졌을 때만 정규 경로(0번)를 남긴다 — 경로를 못 만들면 "데몬 없음"조차
        // 말할 수 없다. 실제 차단은 연결 후 uid 검사가 한다.
        let hijacked2 = tmp.join("hijacked2");
        fs::create_dir(&hijacked2).unwrap();
        fs::set_permissions(&hijacked2, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            trusted_candidates(vec![hijacked.clone(), hijacked2]),
            vec![hijacked],
            "폴백은 정규 경로 하나만 남긴다"
        );
    }

    #[test]
    fn session_dir_candidates_on_macos_has_only_tmp() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            session_dir_candidates_for_os("macos"),
            vec![tmp_session_dir()]
        );
    }

    #[test]
    fn local_command_record_path_under_session_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = local_command_record_path();
        assert_eq!(path.parent().unwrap(), session_dir());
        assert!(path.ends_with("last-command.json"));
    }

    #[test]
    fn local_hook_pending_path_sanitizes_tokens() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = local_hook_pending_path("../bad", "cmd/123!");
        let name = path.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "hook-pending-bad-cmd123.json");
    }

    // ── extract_session_id tests ───────────────────────────────

    #[test]
    fn extract_session_id_roundtrip() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let id = "a1b2c3d4";
        let path = session_socket_path(id);
        assert_eq!(extract_session_id(&path), Some(id.to_string()));
    }

    #[test]
    fn extract_session_id_invalid_paths() {
        // 잘못된 prefix
        assert_eq!(
            extract_session_id(Path::new("/tmp/aic-501/other-abc.sock")),
            None
        );
        // 잘못된 suffix
        assert_eq!(
            extract_session_id(Path::new("/tmp/aic-501/session-abc.pid")),
            None
        );
        // 빈 ID
        assert_eq!(
            extract_session_id(Path::new("/tmp/aic-501/session-.sock")),
            None
        );
        // 디렉토리만
        assert_eq!(extract_session_id(Path::new("/tmp/aic-501/")), None);
    }

    // ── list_session_sockets_in ──────────────────────────────
    use std::fs;
    use std::time::Duration;

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("aic-paths-test-{tag}-{pid}-{nanos}"));
        fs::create_dir_all(&dir).expect("create_dir_all");
        dir
    }

    #[test]
    fn list_session_sockets_empty_dir() {
        let dir = unique_temp_dir("empty");
        let paths = list_session_sockets_in(&dir);
        assert!(paths.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_session_sockets_filters_non_session_files() {
        let dir = unique_temp_dir("filter");
        fs::write(dir.join("session-abc.sock"), b"").unwrap();
        fs::write(dir.join("session.sock"), b"").unwrap(); // legacy 형식 → 제외
        fs::write(dir.join("not-a-session.sock"), b"").unwrap(); // prefix 불일치 → 제외
        fs::write(dir.join("session-def.pid"), b"").unwrap(); // suffix 불일치 → 제외
        let paths = list_session_sockets_in(&dir);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].to_string_lossy().ends_with("session-abc.sock"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_session_sockets_orders_by_mtime_desc() {
        let dir = unique_temp_dir("order");
        let old = dir.join("session-old.sock");
        let mid = dir.join("session-mid.sock");
        let new = dir.join("session-new.sock");
        fs::write(&old, b"").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&mid, b"").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&new, b"").unwrap();
        let paths = list_session_sockets_in(&dir);
        assert_eq!(paths.len(), 3);
        assert!(paths[0].to_string_lossy().ends_with("session-new.sock"));
        assert!(paths[1].to_string_lossy().ends_with("session-mid.sock"));
        assert!(paths[2].to_string_lossy().ends_with("session-old.sock"));
        let _ = fs::remove_dir_all(&dir);
    }

    // ── 세션 소켓: bind(정규) vs 탐색 ──────────────────────────

    #[test]
    fn session_socket_bind_path_is_pinned_to_session_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = session_socket_path_for_bind("deadbeef");
        assert_eq!(path.parent().unwrap(), session_dir());
        assert!(path.ends_with("session-deadbeef.sock"));
    }

    #[test]
    fn resolve_file_in_falls_back_to_alt_then_canonical() {
        let canonical = unique_temp_dir("sess-canon");
        let alt = unique_temp_dir("sess-alt");
        let dirs = [canonical.clone(), alt.clone()];
        let file = "session-abc.sock";

        // 어디에도 없으면 정규 경로
        assert_eq!(resolve_file_in(&dirs, file), canonical.join(file));

        // 대체 후보에만 있으면 그쪽 — 이게 XDG 없는 셸에서 세션을 찾아내는 동작이다
        fs::write(alt.join(file), b"").unwrap();
        assert_eq!(resolve_file_in(&dirs, file), alt.join(file));

        // 양쪽에 있으면 정규 경로가 이긴다
        fs::write(canonical.join(file), b"").unwrap();
        assert_eq!(resolve_file_in(&dirs, file), canonical.join(file));

        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    /// 디렉토리별로 정렬한 뒤 이어 붙이면 깨지는 케이스: 대체 후보의 최신 세션이
    /// 정규 경로의 오래된 세션보다 앞에 와야 한다.
    #[test]
    fn list_session_sockets_in_all_sorts_across_dirs() {
        let canonical = unique_temp_dir("all-canon");
        let alt = unique_temp_dir("all-alt");
        fs::write(canonical.join("session-old.sock"), b"").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        fs::write(alt.join("session-new.sock"), b"").unwrap();

        let paths = list_session_sockets_in_all(&[canonical.clone(), alt.clone()]);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with("session-new.sock"), "{paths:?}");
        assert!(paths[1].ends_with("session-old.sock"), "{paths:?}");

        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    #[test]
    fn list_session_sockets_in_all_dedupes_by_name_keeping_newest() {
        let canonical = unique_temp_dir("dup-canon");
        let alt = unique_temp_dir("dup-alt");
        fs::write(canonical.join("session-dup.sock"), b"").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        fs::write(alt.join("session-dup.sock"), b"").unwrap();

        let paths = list_session_sockets_in_all(&[canonical.clone(), alt.clone()]);
        assert_eq!(paths.len(), 1);
        assert!(
            paths[0].starts_with(&alt),
            "최신 쪽이 남아야 한다: {paths:?}"
        );

        let _ = fs::remove_dir_all(&canonical);
        let _ = fs::remove_dir_all(&alt);
    }

    #[test]
    fn list_session_sockets_in_all_skips_missing_dirs() {
        let live = unique_temp_dir("skip-live");
        let missing = std::env::temp_dir().join("aic-paths-test-absent-98765");
        let _ = fs::remove_dir_all(&missing);
        fs::write(live.join("session-x.sock"), b"").unwrap();

        let paths = list_session_sockets_in_all(&[missing, live.clone()]);
        assert_eq!(paths.len(), 1);

        let _ = fs::remove_dir_all(&live);
    }

    #[test]
    fn list_session_sockets_missing_dir_returns_empty() {
        let dir = std::env::temp_dir().join("aic-paths-test-nonexistent-xyz123");
        let _ = fs::remove_dir_all(&dir); // ensure missing
        let paths = list_session_sockets_in(&dir);
        assert!(paths.is_empty());
    }
}
