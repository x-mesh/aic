//! aicd OTLP docker 디스크 사용량 exporter (SRE t7: A3).
//!
//! opt-in(config `[aicd.exporter]`의 `docker_enabled`, **기본 false** — 아래 "왜 기본 false인가"
//! 참고)으로, aicd가 주기적으로 `docker system df --format json`을 spawn해 이미지/컨테이너/볼륨/
//! 빌드 캐시가 차지한 디스크 크기와 회수 가능량을 얻은 뒤 OTLP Metrics(scope=`aicd`)로 인코딩해
//! `{endpoint}/v1/metrics`로 push한다. `docker stats`는 쓰지 않는다 — CPU% 샘플링 창 때문에
//! 실측 2.05초가 걸리는데(API 소켓으로 쳐도 동일), `docker system df`는 0.19초다. 이 task의
//! 목적은 디스크지 CPU가 아니다.
//!
//! **패턴은 [`connections`](super::connections)를 따른다**: spawn 실패/timeout/non-zero exit/
//! 출력 상한 초과 4중 방어 + 실패 시 push/spool/backoff와 무관하게 다음 주기까지 조용히 skip.
//! host metrics tick(60초, in-process sysinfo)을 외부 프로세스 spawn이 막지 않도록 독립 tokio
//! task로 뜬다(aicd_main.rs). 4중 방어는 두 exporter가 공유하는 [`super::proc::run_capped`]에
//! 모여 있다 — orphan 프로세스 방지와 스트리밍 출력 상한이 거기서 보장된다.
//!
//! **파싱만은 다르다**: `docker system df --format json`의 출력은 JSON 배열이 아니라
//! **NDJSON**(줄당 객체 하나)이다. `connections.rs`처럼 `serde_json::from_slice(전체)`를 쓰면
//! 최상위가 배열이 아니라서 100% 실패한다 — 반드시 줄 단위로 파싱한다. 값도 전부 사람이 읽는
//! 문자열(`"82.64GB"`, `"39.93GB (48%)"`)이라 [`parse_docker_size`]로 바이트로 바꾼다.
//!
//! **metric은 무차원 스칼라, 컨테이너별 차원 없음**: `Type`(Images/Containers/Local Volumes/
//! Build Cache)을 attribute가 아니라 **metric 이름으로 펼친다**. 컨테이너 단위 attr을 넣지 않는
//! 이유 — 수신측(rca) metric 읽기 경로에 attrs 필터가 없어 여러 값이 평균으로 뭉개진다.
//!
//! 내보내는 metric은 **네 카테고리 × (`Size`, `Reclaimable`) = 8개**이며 전부 `By`다:
//! `aic.docker.{image,container,volume,build_cache}.disk.{usage,reclaimable}`. 컨테이너도
//! 예외가 아니다 — `docker system df`는 컨테이너에도 `Reclaimable`을 보낸다(자세한 경위는
//! [`build_metric_points`] 참고).
//!
//! **왜 기본 false인가**: 이 exporter 하나만 Docker라는 외부 CLI 존재에 의존한다(events/
//! connections/changes/agent는 모두 `aic` 자체 spawn 또는 in-process sysinfo/tap이라 항상
//! 가용). Docker가 없는 호스트에서 `enabled=true`로 부모 게이트만 켜면 이 task가 매 tick마다
//! spawn 실패를 겪고 WARN 로그만 쌓는다 — 실질적 이득 없이 노이즈다. 그래서 부모 게이트와 별개로
//! `docker_enabled` 자체를 opt-in(기본 false)으로 둔다(events/connections/changes/agent의
//! "부모 게이트 true면 기본 true" 관례에서 의도적으로 벗어난 유일한 플래그).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::watch;

use super::backoff::Backoff;
use super::encode;
use super::host_metrics::{HostSample, MetricPoint, MetricValue, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// PATH에 없을 때 순서대로 뒤질 docker 설치 위치.
///
/// **왜 PATH만으로는 안 되나**: aicd는 launchd(macOS)/systemd(Linux)로 뜨고, 그 환경의 PATH는
/// **셸의 PATH가 아니라 서비스 매니저 기본값**이다. 실측 — launchd로 뜬 aicd의 PATH는
/// `/usr/bin:/bin:/usr/sbin:/sbin`뿐이라, `/usr/local/bin/docker`(Docker Desktop·OrbStack이
/// 심볼릭 링크를 두는 자리)를 **못 찾는다**. 그래서 `docker_bin`을 그냥 `"docker"`로 두고 PATH
/// 탐색에 맡겼더니 실환경에서 매 tick `ENOENT`만 났다.
///
/// "docker는 aic 배포물이 아니라 시스템에 이미 설치돼 있으니 PATH가 유일하게 맞는 탐색 위치"라는
/// 판단이 틀렸다 — 그건 **셸에서 실행할 때만 참**이고, 데몬은 셸을 거치지 않는다.
///
/// **이 목록의 일부는 쓰기 가능한 디렉토리다** — 왜 그래도 괜찮은지는
/// [`resolve_docker_bin_with`]의 "쓰기 가능 경로와 root" 절 참고.
const FALLBACK_DOCKER_DIRS: &[&str] = &[
    // Docker Desktop·OrbStack이 심볼릭 링크를 두는 자리(macOS/Linux 공통). 이 머신도 여기다.
    "/usr/local/bin",
    // Apple Silicon Homebrew.
    "/opt/homebrew/bin",
    // Linux 배포판 패키지(docker.io, docker-ce).
    "/usr/bin",
    // Ubuntu snap.
    "/snap/bin",
    // Docker Desktop을 앱 번들에서 직접 쓰는 경우(macOS).
    "/Applications/Docker.app/Contents/Resources/bin",
];

/// `$HOME` 밑의 docker 설치 위치(OrbStack이 사용자 홈에도 둔다). 홈은 런타임에만 알 수 있어
/// [`FALLBACK_DOCKER_DIRS`]와 분리한다.
const HOME_RELATIVE_DOCKER_PATH: &str = ".orbstack/bin/docker";
/// `docker system df --format json` stdout 상한. 정상 출력은 카테고리 4줄뿐이라 이 한도를 훨씬
/// 밑돈다 — 초과분은 신뢰할 수 없는 출력으로 간주해 이번 주기를 스킵한다.
///
/// 상한은 [`super::proc::run_capped`]가 **스트리밍으로 읽으면서** 강제하므로 실제로 메모리를
/// 묶는다(출력을 전부 버퍼링한 뒤 길이를 재는 건 방어가 아니라 사후 확인이다 — 그렇게 짜면 무한
/// 출력이 검사에 도달하기 전에 이미 메모리를 먹는다).
const MAX_DF_OUTPUT_BYTES: usize = 256 * 1024;

/// docker 실행 파일의 **절대경로**를 찾는다. 못 찾으면 `None`(호출부는 exporter를 비활성한다).
///
/// 탐색 순서: `configured`(config `[aicd.exporter].docker_bin`) → `PATH` → [`FALLBACK_DOCKER_DIRS`]
/// → `$HOME/.orbstack/bin/docker`. 서비스 매니저의 빈약한 PATH를 폴백이 메워 준다(위 상수 doc 참고).
pub fn resolve_docker_bin(configured: Option<&Path>) -> Option<PathBuf> {
    resolve_docker_bin_with(
        configured,
        std::env::var_os("PATH"),
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
        // SAFETY: geteuid는 실패하지 않고 부작용이 없다(POSIX). aic 안에서도 이미 쓰는 패턴.
        unsafe { libc::geteuid() } == 0,
        &is_executable_file,
        &is_root_controlled_path,
    )
}

/// [`resolve_docker_bin`]의 순수 코어 — 환경(PATH/HOME/euid)과 실행 가능 판정을 주입받아 테스트가
/// **이 머신의 docker 설치 상태에 의존하지 않게** 한다(CI에는 docker가 없을 수 있다).
///
/// # 반환값은 반드시 절대경로다
///
/// aicd는 데몬이라 **cwd가 무엇인지 보장되지 않는다**(launchd는 `/`, systemd는 unit이 정하는 대로).
/// 상대경로를 spawn하면 그 시점의 cwd 기준으로 해석되므로 "환경에 따라 조용히 다른 바이너리를
/// 실행"할 수 있다 — 이 모듈이 없애려던 부류의 버그 그 자체다. 그래서 후보 채택을 아래 `accept`
/// **한 곳**으로 모으고, 거기서 `is_absolute()`를 강제한다. 탐색 단계가 늘어도 절대경로 불변식이
/// 새 코드 경로로 새지 않는다.
///
/// 두 군데가 특히 상대경로를 만든다:
/// - **PATH의 빈 항목**: POSIX에서 `PATH`의 빈 항목(`/usr/bin::/bin`, 선행/후행 `:`)은 **cwd**를
///   뜻한다. 그대로 join하면 후보가 `docker`(상대경로)가 된다 → 건너뛴다(탐색은 계속한다).
/// - **상대경로 config**: `docker_bin = "bin/docker"` 같은 값 → **거부한다**(폴백하지 않는다).
///   오타·상대경로를 조용히 덮고 엉뚱한 docker를 쓰는 것보다, 없다고 말해 주는 편이 덜 헷갈린다.
///
/// # 쓰기 가능 경로와 root
///
/// 폴백 목록에는 쓰기 가능한 디렉토리가 섞여 있다 — `$HOME/.orbstack/bin`(사용자 소유),
/// `/usr/local/bin`(macOS에선 admin 그룹 쓰기 가능). 그럼에도 폴백을 두는 근거:
///
/// aicd는 **사용자 단위 서비스**로만 설치된다 — `~/Library/LaunchAgents/com.x-mesh.aicd.plist`
/// (LaunchAgents, `UserName` 키 없음)와 `systemctl --user`(`aic-client/src/daemon_install.rs`).
/// 둘 다 설치한 사용자의 권한으로 돈다. 그 사용자가 자기 `$HOME`에 docker를 심어 aicd에게
/// 실행시키는 건 **권한 상승이 아니다** — 애초에 그 사용자는 plist 자체를 고쳐 아무 바이너리나
/// 실행시킬 수 있다(plist가 있는 `~/Library/LaunchAgents`가 사용자 쓰기 가능하다).
///
/// 위험한 건 **root로 뜬 aicd**뿐이다(`sudo aicd` — 지원 설치 경로는 아니지만 막을 수는 없다).
/// 그때는 사용자 쓰기 가능 경로의 바이너리를 실행해 주는 것이 곧 root 하이재킹 통로다.
///
/// 그래서 **euid가 0이면 후보를 경로 속성으로 가려낸다** — 후보와 그 모든 상위 디렉토리가 root
/// 소유이고 non-root 쓰기 불가여야 채택한다([`is_root_controlled_path`]). 판정을 **탐색 단계가
/// 아니라 후보 자체에** 걸어야 하는 이유가 있다: 단계로 막으면(예: "폴백만 끊는다") 안 막은 단계로
/// 그대로 우회된다. 실제로 그랬다 — root의 PATH에 `/usr/local/bin`이 있으면(macOS에선 admin 그룹
/// 쓰기 가능, `sudo`가 `env_keep`으로 PATH를 물려주는 설정도 흔하다) 폴백을 아무리 끊어도 PATH에서
/// 그대로 집어 왔다. `accept` 한 곳에 불변식을 모으는 지금 구조가 그 구멍을 구조적으로 막는다.
///
/// 이 방식은 **과잉 방어도 함께 푼다**: `/usr/bin`·`/snap/bin`처럼 root 통제 하의 폴백은 root로
/// 떠도 그대로 통과하므로, root 운영자의 정상 설치를 이유 없이 깨뜨리지 않는다. 막히는 건 딱
/// 위험한 것(`$HOME/.orbstack/bin`, group-writable `/usr/local/bin`)뿐이다. 못 찾으면 WARN이
/// `docker_bin`으로 못을 박으라고 알려 준다.
///
/// # TOCTOU는 굳이 막지 않는다
///
/// 판정(기동 시 1회)과 spawn(60초마다, 데몬 수명 내내) 사이에 경로를 갈아끼울 창은 분명히 있다.
/// 그래도 **막지 않는다**: 그 창을 쓸 수 있는 주체는 (a) aicd와 같은 사용자 — 위에서 봤듯 이미
/// plist로 임의 실행이 가능하니 얻는 게 없고, (b) root — 그때는 신뢰 판정이 애초에 사용자 쓰기
/// 가능 경로를 걸러 낸다. 즉 이 TOCTOU를 막아서 실제로 닫히는 공격은 **하나도 없다**.
/// fd 고정(`fexecve`)은 순수 비용이라 넣지 않는다.
///
/// (앞선 판에서 "소유자를 stat하는 것 자체가 또 하나의 TOCTOU"라며 root일 때 폴백을 통째로 끊었는데,
/// 그 논리는 틀렸다. 신뢰 판정은 **경로가 누구 통제 하에 있는가**라는 정책 질문이지 경합하는 상태가
/// 아니다 — `/usr/bin`의 소유자가 tick 사이에 바뀌지 않는다. 게다가 그 판이 PATH는 그대로 열어 둬서
/// root의 PATH에 `/usr/local/bin`이 있으면 가드가 통째로 우회됐다.)
fn resolve_docker_bin_with(
    configured: Option<&Path>,
    path_var: Option<OsString>,
    home: Option<&Path>,
    running_as_root: bool,
    is_exec: &dyn Fn(&Path) -> bool,
    is_root_controlled: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    // 후보를 채택하는 **유일한** 관문. 불변식(절대경로 + 실행 가능 + root일 때 신뢰 가능)이 여기 한
    // 곳에만 있어야 탐색 단계가 늘어도 새 경로로 새지 않는다. 특히 신뢰 판정을 **후보 단위**로 두는
    // 게 핵심이다 — "어느 단계에서 왔는가"(config/PATH/폴백)로 막으면 단계 하나만 빠뜨려도 가드가
    // 통째로 우회된다(실제로 그렇게 새어서 이 판에서 고쳤다).
    let accept = |cand: PathBuf| -> Option<PathBuf> {
        if !cand.is_absolute() || !is_exec(&cand) {
            return None;
        }
        if running_as_root && !is_root_controlled(&cand) {
            tracing::warn!(
                candidate = %cand.display(),
                "root로 실행 중 — root 통제 밖(비-root 소유이거나 non-root 쓰기 가능) 경로의 docker는 \
                 채택하지 않는다. 쓰려면 [aicd.exporter].docker_bin에 root 통제 하의 절대경로를 지정할 것"
            );
            return None;
        }
        Some(cand)
    };

    // 1. config가 명시했으면 그것만 본다 — 비표준 위치에 설치한 사람의 명시적 의사다.
    //    실행 파일이 아니거나 상대경로면 **폴백하지 않고 실패**한다.
    //    config도 예외가 아니다: root면 신뢰 판정을 똑같이 받는다. "명시했으니 믿는다"고 열어 두면
    //    config 파일 자체가 사용자 쓰기 가능한 경우(root aicd가 사용자 홈의 config를 읽는 경우)
    //    가드가 다시 우회된다.
    if let Some(p) = configured {
        if !p.is_absolute() {
            tracing::warn!(
                docker_bin = %p.display(),
                "[aicd.exporter].docker_bin이 상대경로 — 데몬은 cwd가 보장되지 않아 거부한다(절대경로로 지정할 것)"
            );
        }
        return accept(p.to_path_buf());
    }

    // 2. PATH — 셸에서 띄운 aicd나 PATH가 제대로 잡힌 서비스라면 여기서 끝난다.
    //    빈 항목(= cwd)이 만드는 상대경로 후보는 accept가 걸러 내고, 탐색은 다음 항목으로 계속된다.
    if let Some(paths) = path_var {
        for dir in std::env::split_paths(&paths) {
            if let Some(found) = accept(dir.join("docker")) {
                return Some(found);
            }
        }
    }

    // 3. 서비스 매니저 PATH에는 없지만 docker가 실제로 설치되는 표준 위치들. root라도 `/usr/bin`처럼
    //    root 통제 하의 위치는 그대로 통과한다 — accept가 후보별로 가려낸다.
    for dir in FALLBACK_DOCKER_DIRS {
        if let Some(found) = accept(Path::new(dir).join("docker")) {
            return Some(found);
        }
    }
    if let Some(h) = home {
        if let Some(found) = accept(h.join(HOME_RELATIVE_DOCKER_PATH)) {
            return Some(found);
        }
    }

    None
}

/// 후보 경로가 **root 통제 하**에 있는가 — euid가 0일 때만 쓴다([`resolve_docker_bin_with`]의
/// "쓰기 가능 경로와 root" 참고).
///
/// 심볼릭 링크를 먼저 해소한 뒤(`canonicalize`) 최종 경로와 **모든 상위 디렉토리**를 훑어, 각각이
/// [`is_root_controlled_meta`]를 만족하는지 본다. 링크를 해소하는 이유: root 소유 심볼릭 링크라도
/// 그 **대상**이 사용자 쓰기 가능한 곳(`/Applications/OrbStack.app/...`)이면 하이재킹 통로다.
/// 해소 후에는 경로에 링크가 남지 않으므로 각 성분의 mode 검사가 의미를 가진다.
fn is_root_controlled_path(p: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let Ok(real) = std::fs::canonicalize(p) else {
        return false;
    };
    let mut cur: Option<&Path> = Some(real.as_path());
    while let Some(c) = cur {
        let Ok(md) = std::fs::symlink_metadata(c) else {
            return false;
        };
        if !is_root_controlled_meta(md.uid(), md.permissions().mode()) {
            return false;
        }
        cur = c.parent();
    }
    true
}

/// [`is_root_controlled_path`]의 순수 판정 — 한 경로 성분의 `(uid, mode)`가 root 통제 하인가.
///
/// **root 소유**(`uid == 0`)이고 **group/other 쓰기 불가**(`mode & 0o022 == 0`)여야 한다. 둘 다
/// 필요하다: 소유자만 보면 `/usr/local/bin`(macOS에서 root:admin **0775**)이 통과해 admin 그룹
/// 아무나 하이재킹할 수 있고, 쓰기 비트만 보면 사용자 소유 0755 디렉토리가 통과한다.
///
/// 파일시스템을 건드리지 않는 순수 함수로 떼어 낸 이유는 테스트다 — root 소유 디렉토리는 root가
/// 아니면 만들 수 없어서, FS를 통째로 쓰면 "이 머신이 root인가"에 결과가 끌려간다.
fn is_root_controlled_meta(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// **이 프로세스가 실제로 spawn할 수 있는** 실행 파일인가.
///
/// 두 검사를 모두 해야 한다:
/// 1. **정규 파일인가** — `faccessat(X_OK)`는 *탐색 가능한 디렉토리*에도 성공하므로 이것만으론
///    디렉토리를 docker로 오인한다. `metadata`는 심볼릭 링크를 따라가므로
///    `/usr/local/bin/docker → /Applications/OrbStack.app/...`처럼 링크로 설치된 경우도 통과한다
///    (이 머신이 실제로 그렇다).
/// 2. **실효 권한으로 실행 가능한가** — 예전엔 `mode() & 0o111 != 0`을 봤는데, 이건 **"누군가는
///    실행 가능"**만 본다. 소유자만 x 비트가 있고 aicd가 다른 사용자면 판정은 통과하는데 spawn은
///    `EACCES`로 죽는다 — 이 커밋이 없애려던 "매 tick 실패"가 그대로 남는 것이다. 그래서
///    `faccessat(..., X_OK, AT_EACCESS)`로 **실효 uid/gid** 기준 판정을 커널에 맡긴다
///    (`access(2)`는 real uid를 보므로 setuid 상황에서 틀린 답을 낸다).
///
/// # `AT_EACCESS`를 테스트로 못 박는 방법과 그 한계
///
/// `AT_EACCESS`의 **동작 차이**는 실제 uid와 실효 uid가 갈릴 때만 드러난다(setuid 바이너리, 또는
/// `setresuid`로 갈라 놓은 프로세스). 그런 상태는 in-process 단위 테스트로 만들 수 없다 — uid를
/// 가르려면 애초에 특권이 필요하고, CI는 그런 특권으로 돌지 않는다. 그래서 "플래그를 빼도 테스트가
/// 통과"하는 공허함이 생기기 쉽다.
///
/// 대신 **두 겹**으로 못 박는다:
/// 1. 호출을 [`faccess_x_ok`]로 얇게 감싸고, 테스트 빌드에서 **실제로 넘어간 flags를 기록**한다 →
///    `is_executable_file`이 `AT_EACCESS`를 넘기는지 단언한다(`AT_EACCESS`를 지우면 테스트가 깨진다).
/// 2. 엉터리 플래그를 주면 커널이 `EINVAL`을 내는지 확인한다 → 이 플랫폼이 flags를 **실제로 검증**
///    한다(무시하지 않는다)는 뜻이므로, 1이 확인한 `AT_EACCESS`가 실효를 갖는다.
///
/// 두 겹을 합쳐도 "실효 uid ≠ 실제 uid에서 판정이 달라진다"를 **직접** 재현하지는 못한다. 그건
/// 특권 없이는 불가능하다 — 이 사실을 코드에 남겨 두는 것이, 없는 테스트를 있는 척하는 것보다 낫다.
fn is_executable_file(p: &Path) -> bool {
    if !std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false) {
        return false;
    }
    faccess_x_ok(p, libc::AT_EACCESS)
}

// 테스트 빌드에서 `faccess_x_ok`에 마지막으로 넘어간 flags. 호출부가 `AT_EACCESS`를 실제로
// 넘기는지 단언하기 위한 것 — 프로덕션 빌드에는 존재하지 않는다.
#[cfg(test)]
thread_local! {
    static LAST_FACCESSAT_FLAGS: std::cell::Cell<libc::c_int> =
        const { std::cell::Cell::new(i32::MIN) };
}

/// `faccessat(AT_FDCWD, p, X_OK, flags)`의 얇은 래퍼. `flags`를 인자로 빼 둔 이유는 오직 테스트가
/// **호출부가 무엇을 넘기는지** 관찰하고, 엉터리 플래그에 커널이 `EINVAL`을 내는지 확인하기 위함이다
/// ([`is_executable_file`]의 doc 참고). 프로덕션 호출부는 언제나 `AT_EACCESS`를 넘긴다.
fn faccess_x_ok(p: &Path, flags: libc::c_int) -> bool {
    use std::os::unix::ffi::OsStrExt;

    #[cfg(test)]
    LAST_FACCESSAT_FLAGS.with(|f| f.set(flags));

    // 경로에 NUL이 있으면 애초에 exec할 수 없다.
    let Ok(c_path) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: c_path는 살아 있는 NUL 종료 C 문자열이고, faccessat은 그것을 읽기만 한다.
    unsafe { libc::faccessat(libc::AT_FDCWD, c_path.as_ptr(), libc::X_OK, flags) == 0 }
}

/// docker exporter 실행 설정.
#[derive(Debug, Clone)]
pub struct DockerConfig {
    /// OTLP collector base URL. `/v1/metrics`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 캡처 주기.
    pub interval: Duration,
    /// spawn할 `docker` 실행 파일의 **절대경로**. 호출부가 [`resolve_docker_bin`]으로 기동 시 찾아
    /// 넘긴다 — `"docker"` 같은 상대 이름을 넣어 PATH 탐색에 맡기면 launchd/systemd의 빈약한
    /// PATH에서 못 찾는다(상수 [`FALLBACK_DOCKER_DIRS`] doc 참고).
    ///
    /// **`None`이면 기동 시엔 못 찾았다는 뜻**이고, task는 그래도 뜬다 — 매 tick 재탐색하다가
    /// 찾으면 그때부터 캡처를 시작한다([`serve_docker`]의 "나중에 설치된 docker" 참고).
    pub docker_bin: Option<PathBuf>,
    /// config `[aicd.exporter].docker_bin` 원본. 재탐색할 때 같은 우선순위를 다시 적용하려면
    /// 기동 때 쓴 입력이 그대로 있어야 한다.
    pub configured_bin: Option<PathBuf>,
    /// `docker system df` 프로세스 타임아웃(hung 방어).
    pub timeout: Duration,
    /// 오프라인 spool(SRE t8). 다른 exporter task와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 다른 exporter task와 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<super::ExporterHealth>,
}

/// docker exporter를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
///
/// # 나중에 설치된 docker
///
/// `cfg.docker_bin`이 `None`이면 기동 시엔 docker를 못 찾았다는 뜻이다. 그래도 task는 뜨고, **매
/// tick 재탐색**하다가 찾으면 그때부터 캡처를 시작한다.
///
/// 왜 그냥 비활성하지 않는가: 기동 시 1회만 판정하면 aicd가 뜬 뒤 docker를 설치한 사람은 재시작
/// 전까지 exporter가 **영구 비활성**이 된다. 이건 실제 회귀다 — 예전엔 `docker_bin`이 그냥
/// `"docker"`라 매 tick PATH를 다시 탐색했고, 셸에서 띄운 aicd(PATH가 멀쩡한 경우)는 저절로
/// 살아났다. launchd/systemd로 뜬 경우엔 애초에 작동하지 않았으니 그쪽은 회귀가 아니지만,
/// 셸로 띄우는 경로는 실재한다.
///
/// 비용은 무시할 만하다 — 못 찾은 동안 60초마다 stat 몇 번이 전부고, 찾은 뒤에는 재탐색하지 않는다.
/// WARN 폭주(이 커밋이 없애려던 것)도 없다: 기동 시 1회만 WARN이고, 이후 미탐색 tick은 `debug`다.
pub async fn serve_docker(
    cfg: DockerConfig,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    serve_docker_with(cfg, shutdown, &resolve_docker_bin).await
}

/// [`serve_docker`]의 코어 — 재탐색기를 주입받는다.
///
/// 주입하는 이유는 테스트다. 진짜 [`resolve_docker_bin`]은 이 프로세스의 euid와 실제 파일시스템
/// 소유권(`is_root_controlled_path`)을 보므로, 테스트가 임시 디렉토리에 가짜 docker를 놓으면
/// **머신 상태에 결과가 끌려간다** — 예컨대 root로 도는 CI에서 `/tmp`가 world-writable이면 신뢰
/// 판정이 (옳게) 거부해서, 코드가 멀쩡한데도 테스트가 깨진다. 재탐색 **루프 자체**를 검증하려면
/// 탐색 결과를 결정적으로 줄 수 있어야 한다.
async fn serve_docker_with(
    cfg: DockerConfig,
    mut shutdown: watch::Receiver<bool>,
    resolve: &(dyn Fn(Option<&Path>) -> Option<PathBuf> + Sync),
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = super::metrics_url(&cfg.endpoint);
    // 기동 시 못 찾았어도 task는 뜬다 — 아래 루프가 매 tick 재탐색한다.
    let mut docker_bin = cfg.docker_bin.clone();
    tracing::info!(
        url = %url,
        interval_secs = cfg.interval.as_secs(),
        docker_bin = ?docker_bin.as_ref().map(|p| p.display().to_string()),
        "OTLP docker exporter 시작"
    );

    // host_metrics와 동일 방식으로 얻어야 같은 host.id로 다른 signal들과 상관관계를 지을 수 있다.
    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let os_desc = sysinfo::System::long_os_version().unwrap_or_default();

    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut backoff = Backoff::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                // 아직 못 찾았으면 이번 tick에 다시 찾아본다(위 doc "나중에 설치된 docker").
                let bin = match &docker_bin {
                    Some(b) => b.clone(),
                    None => match resolve(cfg.configured_bin.as_deref()) {
                        Some(found) => {
                            tracing::info!(
                                docker_bin = %found.display(),
                                "docker 실행 파일을 찾았다 — docker exporter 캡처 시작"
                            );
                            docker_bin = Some(found.clone());
                            found
                        }
                        None => {
                            // 기동 시 이미 WARN을 한 번 남겼다 — 매 tick 반복하지 않는다.
                            tracing::debug!("docker 실행 파일을 아직 찾지 못했다 — 이번 주기 skip");
                            continue;
                        }
                    },
                };
                match capture_docker_df(&bin, cfg.timeout).await {
                    Ok(lines) => {
                        let points = build_metric_points(&lines);
                        if points.is_empty() {
                            continue;
                        }
                        let sample = HostSample {
                            resource: ResourceAttrs {
                                host_name: host_name.clone(),
                                host_id: host_id.clone(),
                                os_type: os_type.clone(),
                                arch: arch.clone(),
                                os_desc: os_desc.clone(),
                            },
                            points,
                        };
                        let body = encode::encode_metrics(
                            &sample,
                            &cfg.service_version,
                            super::unix_nanos_now(),
                            // docker task는 로그 드롭을 모른다 — 게이지를 싣지 않는다(중복 발행 방지).
                            None,
                        );

                        if !backoff.ready() {
                            if let Err(e) = cfg.spool.append(SignalKind::Metrics, &body) {
                                tracing::warn!(error = %e, "OTLP docker spool append 실패 — 이 샘플 유실");
                            }
                            continue;
                        }

                        match super::push(&client, &url, cfg.token.as_deref(), body.clone()).await {
                            Ok(()) => {
                                backoff.on_success();
                                cfg.health.record_ok();
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "OTLP docker push 실패 — spool에 적재");
                                if let Err(e2) = cfg.spool.append(SignalKind::Metrics, &body) {
                                    tracing::warn!(error = %e2, "OTLP docker spool append 실패 — 이 샘플 유실");
                                }
                                backoff.on_failure();
                                cfg.health.record_fail();
                            }
                        }
                    }
                    Err(e) => {
                        // 캡처 자체의 문제(미설치/데몬 다운/권한 없음/hang)라 push/spool/backoff와
                        // 무관하게 다음 주기까지 skip한다 — connections.rs와 동일 원칙. health를
                        // 건드리지 않는다: health는 "push가 성공/실패했나"만 추적하고, 캡처 실패는
                        // 애초에 push를 시도조차 하지 않았기 때문이다.
                        tracing::warn!(error = %e, "docker system df 캡처/파싱 실패 — 다음 주기까지 skip");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("OTLP docker exporter 종료");
    Ok(())
}

/// `docker_bin system df --format json`을 spawn해 stdout을 NDJSON 라인 단위로 파싱한다.
///
/// spawn 실패(미설치)/timeout(hang)/non-zero exit(데몬 다운·권한 없음 모두 동일 경로)/출력 상한
/// 초과 4중 방어는 [`super::proc::run_capped`]가 담당한다 — orphan 프로세스 방지(`kill_on_drop` +
/// 명시적 kill)와 **스트리밍 상한**(버퍼링 후 사후 확인이 아니라 읽는 도중 차단)이 거기 있다.
///
/// 데몬 다운과 권한 없음은 **제어 흐름상** 같은 경로(non-zero exit)지만, `run_capped`가 stderr를
/// 캡처해 에러에 실어 주므로 **로그에서는 구분된다**(`"failed to connect to the docker API at ..."`
/// vs 권한 거부 메시지). exit status만 남기면 운영 중에 원인을 못 가린다.
///
/// 개별 라인의 JSON 파싱 실패는 [`parse_ndjson_lines`]가 그 라인만 건너뛴다 — 전부 실패하면
/// 여기서 `Err`로 승격해 이번 주기를 skip한다.
async fn capture_docker_df(
    docker_bin: &std::path::Path,
    timeout: Duration,
) -> anyhow::Result<Vec<DfLine>> {
    let mut cmd = tokio::process::Command::new(docker_bin);
    cmd.args(["system", "df", "--format", "json"]);

    let stdout =
        super::proc::run_capped(cmd, timeout, MAX_DF_OUTPUT_BYTES, "docker system df").await?;

    let lines = parse_ndjson_lines(&stdout);
    if lines.is_empty() {
        anyhow::bail!("docker system df 출력에서 파싱 가능한 라인이 하나도 없음");
    }
    Ok(lines)
}

/// `docker system df --format json`의 NDJSON(줄당 JSON 객체 1개) 출력을 순수 함수로 파싱한다.
/// **주의**: 최상위가 배열이 아니다 — `serde_json::from_slice(전체)`를 쓰면 100% 실패한다
/// (connections.rs의 `InventorySnapshot` 파싱을 그대로 복사하면 걸리는 함정, 모듈 doc 참고).
/// 한 줄의 파싱 실패는 그 줄만 버리고 나머지는 살린다 — Docker 버전에 따라 필드가 늘거나 알 수
/// 없는 줄이 섞여도 다른 카테고리의 metric은 여전히 나가야 한다.
fn parse_ndjson_lines(stdout: &[u8]) -> Vec<DfLine> {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|line| match serde_json::from_str::<DfLine>(line) {
            Ok(entry) => Some(entry),
            Err(e) => {
                tracing::debug!(error = %e, line, "docker system df 라인 파싱 실패 — 이 라인만 skip");
                None
            }
        })
        .collect()
}

/// `docker system df --format json`이 내는 사람이 읽는 크기 문자열을 바이트로 바꾼다. docker는
/// go-units `HumanSize`(10진 SI, 1000배수)로 포맷한다 — 1024가 아니라 1000 기준이다.
///
/// 처리해야 하는 실제 형태 셋:
/// - `"82.64GB"` — `Size` 필드, 퍼센트 없음.
/// - `"39.93GB (48%)"` — `Reclaimable` 필드, `"<크기> (<퍼센트>)"`.
/// - `"21.66GB"` — Build Cache의 `Reclaimable`은 퍼센트가 없다(둘 다 처리해야 함).
///
/// 인식 못 하는 형식은 `None` — 호출부가 그 metric point만 생략한다(0으로 채우지 않는다: 측정
/// 불가는 point 생략이지, "측정했더니 0"이 아니다).
fn parse_docker_size(raw: &str) -> Option<u64> {
    // "39.93GB (48%)"의 뒷부분(퍼센트 괄호)을 버린다 — 앞 토큰만 크기다.
    let head = raw.split_whitespace().next()?;
    let split_at = head.find(|c: char| c.is_ascii_alphabetic())?;
    let (num_part, unit_part) = head.split_at(split_at);
    let num: f64 = num_part.parse().ok()?;
    if !num.is_finite() || num < 0.0 {
        return None;
    }
    let multiplier: f64 = match unit_part {
        "B" => 1.0,
        "kB" => 1_000.0,
        "MB" => 1_000_000.0,
        "GB" => 1_000_000_000.0,
        "TB" => 1_000_000_000_000.0,
        "PB" => 1_000_000_000_000_000.0,
        _ => return None,
    };
    Some((num * multiplier).round() as u64)
}

/// 파싱된 df 라인들을 OTLP metric point로 펼친다. `Type`을 attribute가 아니라 metric 이름으로
/// 펼치는 이유는 모듈 doc 참고(수신측 attrs 필터 부재로 평균에 뭉개지는 것을 막기 위함).
///
/// **네 카테고리 모두 `Size`와 `Reclaimable`을 둘 다 낸다 — 총 8개.** 한때 컨테이너의
/// `Reclaimable`을 "스펙상 없다"며 버렸는데 **사실이 아니었다**: `docker system df`는 컨테이너에도
/// `Reclaimable`을 보낸다(이 파일의 [`REAL_DF_OUTPUT`] 픽스처에 `"224.5kB (0%)"`로 실재한다).
/// docker가 안 보낸 게 아니라 우리가 버리고 있었다. 카테고리별로 필드 유무를 다르게 취급하지
/// 않는 지금 구조가 그 실수를 구조적으로 막는다 — 값이 오면 보내고, 못 읽으면 그 point만 생략한다.
///
/// 바이트 파싱에 실패한 개별 값은 그 point만 생략한다 — 한 카테고리의 값 하나가 이상해도 나머지
/// 카테고리/필드는 그대로 나간다.
fn build_metric_points(lines: &[DfLine]) -> Vec<MetricPoint> {
    let mut points = Vec::new();
    for line in lines {
        let (usage_name, reclaimable_name): (&'static str, &'static str) = match line.kind.as_str()
        {
            "Images" => (
                "aic.docker.image.disk.usage",
                "aic.docker.image.disk.reclaimable",
            ),
            "Containers" => (
                "aic.docker.container.disk.usage",
                "aic.docker.container.disk.reclaimable",
            ),
            "Local Volumes" => (
                "aic.docker.volume.disk.usage",
                "aic.docker.volume.disk.reclaimable",
            ),
            "Build Cache" => (
                "aic.docker.build_cache.disk.usage",
                "aic.docker.build_cache.disk.reclaimable",
            ),
            other => {
                // 알 수 없는 Type(신규 Docker 버전이 카테고리를 추가한 경우 등) — 이 라인만
                // 건너뛰고 나머지는 그대로 처리한다.
                tracing::debug!(kind = other, "docker system df의 알 수 없는 Type — skip");
                continue;
            }
        };

        if let Some(bytes) = parse_docker_size(&line.size) {
            points.push(MetricPoint {
                name: usage_name,
                unit: "By",
                value: MetricValue::Int(bytes as i64),
            });
        }

        // Reclaimable 필드가 아예 없는 버전 skew에서만 None이다 — 그때는 이 point만 생략한다
        // (0으로 채우지 않는다: 측정 불가는 생략이지 "측정했더니 0"이 아니다).
        if let Some(bytes) = line.reclaimable.as_deref().and_then(parse_docker_size) {
            points.push(MetricPoint {
                name: reclaimable_name,
                unit: "By",
                value: MetricValue::Int(bytes as i64),
            });
        }
    }
    points
}

// ── NDJSON wire contract (`docker system df --format json`의 실제 줄 형태) ────────────────

#[derive(Debug, Deserialize)]
struct DfLine {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Size")]
    size: String,
    /// Build Cache는 퍼센트 없이(`"21.66GB"`), 나머지는 퍼센트를 붙여(`"39.93GB (48%)"`) 온다.
    /// 필드 자체가 없는 버전 skew도 있을 수 있어 `Option` + `default`로 방어한다.
    #[serde(rename = "Reclaimable", default)]
    reclaimable: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    // ── docker 바이너리 탐색 ────────────────────────────────────────────────
    //
    // 전부 순수 함수 테스트다 — 존재 판정을 주입하므로 **이 머신에 docker가 깔려 있든 말든**
    // 결과가 같다(CI에는 docker가 없을 수 있다).

    /// 주어진 경로 집합만 "실행 가능한 파일"로 치는 가짜 판정기(경로를 소유하므로 입력을 빌리지
    /// 않는다).
    ///
    /// **정확 경로 매칭이다** — 그래서 상대경로 후보(`docker`)도 목록에 넣으면 "있다"고 답한다.
    /// 아래 절대경로 테스트들이 바로 그 성질을 이용해, resolve가 상대경로 후보를 채택하려 들면
    /// 잡아낸다(예전엔 이 픽스처가 절대경로만 쥐여 줘서 그 버그를 구조적으로 못 봤다).
    fn only(existing: &[&str]) -> impl Fn(&Path) -> bool {
        let set: Vec<PathBuf> = existing.iter().map(PathBuf::from).collect();
        move |p: &Path| set.iter().any(|e| e == p)
    }

    /// **모든 resolve 테스트가 통과하는 관문.** 개별 테스트는 `resolve_docker_bin_with`를 직접
    /// 부르지 않고 반드시 이걸 거친다 — 어떤 입력을 주든 반환값이 절대경로임을 여기서 단언하므로,
    /// 개별 테스트가 그 단언을 잊어도 불변식은 구조적으로 지켜진다.
    fn resolve(
        configured: Option<&Path>,
        path_var: Option<OsString>,
        home: Option<&Path>,
        is_exec: &dyn Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        // 비-root에서는 신뢰 판정을 **아예 하지 않아야** 한다(불필요한 stat). 호출되면 터진다.
        let never = |p: &Path| -> bool {
            panic!("비-root인데 신뢰 판정을 호출했다: {}", p.display());
        };
        resolve_as(configured, path_var, home, false, is_exec, &never)
    }

    /// [`resolve`]의 root 포함 버전 — 절대경로 단언은 동일하다.
    fn resolve_as(
        configured: Option<&Path>,
        path_var: Option<OsString>,
        home: Option<&Path>,
        running_as_root: bool,
        is_exec: &dyn Fn(&Path) -> bool,
        is_root_controlled: &dyn Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        let got = resolve_docker_bin_with(
            configured,
            path_var,
            home,
            running_as_root,
            is_exec,
            is_root_controlled,
        );
        if let Some(p) = &got {
            assert!(
                p.is_absolute(),
                "resolve가 상대경로를 반환했다 — aicd는 데몬이라 cwd가 보장되지 않는다: {}",
                p.display()
            );
        }
        got
    }

    /// root 신뢰 판정 픽스처 — 주어진 경로 집합만 "root 통제 하"로 친다.
    fn trusted(paths: &[&str]) -> impl Fn(&Path) -> bool {
        let set: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        move |p: &Path| set.iter().any(|e| e == p)
    }

    /// **회귀 가드**: launchd로 뜬 aicd의 PATH는 `/usr/bin:/bin:/usr/sbin:/sbin`뿐이고 docker는
    /// `/usr/local/bin/docker`에 있다(이 머신 실측). 예전처럼 PATH 탐색에만 맡기면 여기서 못 찾아
    /// 매 tick ENOENT가 났다 — 폴백이 이 상황을 건져야 한다.
    #[test]
    fn finds_docker_outside_the_launchd_path() {
        let launchd_path = Some(OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"));
        let got = resolve(None, launchd_path, None, &only(&["/usr/local/bin/docker"]));
        assert_eq!(got, Some(PathBuf::from("/usr/local/bin/docker")));
    }

    #[test]
    fn prefers_path_over_the_fallback_dirs() {
        // PATH에 있으면 굳이 폴백을 뒤지지 않는다(사용자 PATH가 우선).
        let got = resolve(
            None,
            Some(OsString::from("/opt/custom/bin:/usr/bin")),
            None,
            &only(&["/opt/custom/bin/docker", "/usr/local/bin/docker"]),
        );
        assert_eq!(got, Some(PathBuf::from("/opt/custom/bin/docker")));
    }

    #[test]
    fn configured_path_wins_over_everything() {
        let got = resolve(
            Some(Path::new("/custom/docker")),
            Some(OsString::from("/usr/bin")),
            None,
            &only(&["/custom/docker", "/usr/bin/docker"]),
        );
        assert_eq!(got, Some(PathBuf::from("/custom/docker")));
    }

    /// config가 가리킨 경로가 실행 파일이 아니면 **폴백하지 않고 실패**한다 — 오타를 조용히 덮고
    /// 엉뚱한 docker를 쓰면 더 헷갈린다.
    #[test]
    fn a_bad_configured_path_does_not_silently_fall_back() {
        let got = resolve(
            Some(Path::new("/typo/dcoker")),
            Some(OsString::from("/usr/bin")),
            None,
            &only(&["/usr/bin/docker"]), // PATH엔 멀쩡한 docker가 있다.
        );
        assert_eq!(
            got, None,
            "지정한 경로가 틀렸으면 조용히 다른 걸 쓰면 안 된다"
        );
    }

    #[test]
    fn falls_back_to_home_orbstack_path() {
        let got = resolve(
            None,
            Some(OsString::from("/usr/bin")),
            Some(Path::new("/Users/someone")),
            &only(&["/Users/someone/.orbstack/bin/docker"]),
        );
        assert_eq!(
            got,
            Some(PathBuf::from("/Users/someone/.orbstack/bin/docker"))
        );
    }

    /// Linux 배포판 패키지 위치(`/usr/bin/docker`)도 커버해야 한다.
    #[test]
    fn finds_the_linux_distro_package_path() {
        let got = resolve(None, None, None, &only(&["/usr/bin/docker"]));
        assert_eq!(got, Some(PathBuf::from("/usr/bin/docker")));
    }

    /// docker가 아예 없으면 `None` — 호출부가 exporter를 비활성한다(매 tick WARN 대신 기동 시 1회).
    #[test]
    fn returns_none_when_docker_is_absent_everywhere() {
        let got = resolve(
            None,
            Some(OsString::from("/usr/bin:/bin")),
            Some(Path::new("/home/nobody")),
            &only(&[]),
        );
        assert_eq!(got, None);
    }

    // ── 절대경로 불변식: 상대경로 후보를 만드는 세 입력 ────────────────────────
    //
    // aicd는 데몬이라 cwd가 보장되지 않는다(launchd는 `/`, systemd는 unit이 정하는 대로). 상대경로를
    // 채택하면 "cwd 기준 탐색"이 되어, 이 커밋이 없애려던 "환경에 따라 조용히 다른 걸 실행"이 그대로
    // 돌아온다. 아래 셋은 판정기가 상대경로 후보에 "있다"고 답하도록 일부러 꾸며 놓았다.

    /// **POSIX: `PATH`의 빈 항목은 cwd를 뜻한다.** `/nowhere::/also/nowhere`의 가운데 빈 항목이
    /// 후보 `docker`(상대경로)를 만든다 — cwd에 악의적 `docker`가 놓인 상황 그대로다.
    #[test]
    fn an_empty_path_entry_never_yields_a_relative_candidate() {
        let got = resolve(
            None,
            Some(OsString::from("/nowhere::/also/nowhere")),
            None,
            &only(&["docker"]),
        );
        assert_eq!(
            got, None,
            "PATH의 빈 항목(cwd)이 만든 상대경로 후보를 채택했다 — 데몬의 cwd는 보장되지 않는다"
        );
    }

    /// 빈 항목은 **건너뛸 뿐, 탐색을 중단시키지 않는다** — 선행 `:`(= cwd가 맨 앞) 뒤의 정상
    /// 디렉토리에서 계속 찾아야 한다. cwd의 `docker`가 `/usr/bin/docker`를 선점하면 안 된다.
    #[test]
    fn a_leading_empty_path_entry_is_skipped_not_preferred() {
        let got = resolve(
            None,
            Some(OsString::from(":/usr/bin")),
            None,
            &only(&["docker", "/usr/bin/docker"]),
        );
        assert_eq!(
            got,
            Some(PathBuf::from("/usr/bin/docker")),
            "cwd(빈 항목)의 docker를 절대경로보다 먼저 채택했다"
        );
    }

    /// PATH에 들어 있는 **상대경로 디렉토리**도 같은 함정이다 — 건너뛰고 계속 찾는다.
    #[test]
    fn a_relative_path_dir_is_skipped() {
        let got = resolve(
            None,
            Some(OsString::from("bin:./tools:/usr/bin")),
            None,
            &only(&["bin/docker", "./tools/docker", "/usr/bin/docker"]),
        );
        assert_eq!(
            got,
            Some(PathBuf::from("/usr/bin/docker")),
            "PATH의 상대경로 디렉토리를 채택했다"
        );
    }

    /// **상대경로 config는 거부한다**(폴백하지 않는다). 데몬의 cwd에 의존하는 설정은 조용히 받아
    /// 주는 것보다 "없다"고 말해 주는 편이 맞다 — 무엇을 실행할지 애초에 예측할 수 없다.
    #[test]
    fn a_relative_configured_path_is_rejected() {
        for rel in ["docker", "bin/docker", "./docker", "../bin/docker"] {
            let got = resolve(
                Some(Path::new(rel)),
                Some(OsString::from("/usr/bin")),
                None,
                // 상대경로도 폴백도 전부 "있다"고 답한다 — 그래도 채택하면 안 된다.
                &only(&[rel, "/usr/bin/docker", "/usr/local/bin/docker"]),
            );
            assert_eq!(
                got, None,
                "상대경로 config({rel})를 채택했다 — 데몬의 cwd는 보장되지 않는다"
            );
        }
    }

    // ── root 가드 ─────────────────────────────────────────────────────────────

    /// **회귀 가드 — 이전 판의 블로킹 버그.** 가드를 "폴백 단계"에 걸었더니 PATH 탐색이 그보다
    /// **먼저** 돌아 통째로 우회됐다. root의 PATH에 `/usr/local/bin`이 있으면(macOS에선 admin 그룹
    /// 쓰기 가능, `sudo`의 `env_keep`으로 사용자 PATH가 넘어오는 설정도 흔하다) 폴백을 아무리
    /// 끊어도 여기서 집어 왔다. 이제 신뢰 판정이 **후보 단위**라 PATH도 똑같이 걸러진다.
    #[test]
    fn as_root_an_untrusted_path_entry_is_rejected() {
        let got = resolve_as(
            None,
            // root의 PATH에 사용자/admin 쓰기 가능 디렉토리가 섞여 있다.
            Some(OsString::from("/usr/local/bin:/usr/sbin")),
            None,
            true,
            &only(&["/usr/local/bin/docker"]),
            &trusted(&[]), // 어느 것도 root 통제 하가 아니다.
        );
        assert_eq!(
            got, None,
            "root인데 PATH의 쓰기 가능 디렉토리에서 docker를 집어 왔다 — 가드가 PATH를 못 덮는다"
        );
    }

    /// root라도 **root 통제 하의 PATH 항목**은 그대로 채택한다.
    #[test]
    fn as_root_a_trusted_path_entry_is_accepted() {
        let got = resolve_as(
            None,
            Some(OsString::from("/usr/local/bin:/usr/bin")),
            None,
            true,
            &only(&["/usr/local/bin/docker", "/usr/bin/docker"]),
            // /usr/local/bin은 신뢰 못 하지만 /usr/bin은 신뢰한다 — 앞의 것을 건너뛰고 뒤를 잡아야 한다.
            &trusted(&["/usr/bin/docker"]),
        );
        assert_eq!(
            got,
            Some(PathBuf::from("/usr/bin/docker")),
            "신뢰 못 할 PATH 항목에서 멈추지 말고 신뢰 가능한 다음 항목을 계속 찾아야 한다"
        );
    }

    /// root일 때 사용자 쓰기 가능 **폴백**(`$HOME/.orbstack/bin`, group-writable `/usr/local/bin`)도
    /// 당연히 막힌다.
    #[test]
    fn as_root_untrusted_fallback_dirs_are_rejected() {
        let got = resolve_as(
            None,
            Some(OsString::from("/usr/sbin:/sbin")), // PATH엔 docker가 없다.
            Some(Path::new("/Users/victim")),
            true,
            &only(&[
                "/usr/local/bin/docker",
                "/Users/victim/.orbstack/bin/docker",
            ]),
            &trusted(&[]),
        );
        assert_eq!(
            got, None,
            "root인데 쓰기 가능 폴백 경로의 docker를 채택했다 — 권한 상승 통로"
        );
    }

    /// **과잉 방어 회귀 가드**: 이전 판은 root면 폴백을 통째로 끊어, `/usr/bin`처럼 root 통제 하의
    /// 정상 설치까지 이유 없이 깨뜨렸다. 이제는 root라도 신뢰 가능한 폴백이면 채택한다.
    #[test]
    fn as_root_a_trusted_fallback_dir_is_still_accepted() {
        let got = resolve_as(
            None,
            Some(OsString::from("/usr/sbin:/sbin")), // PATH엔 없다 — 폴백으로 내려간다.
            None,
            true,
            &only(&["/usr/bin/docker"]),
            &trusted(&["/usr/bin/docker"]),
        );
        assert_eq!(
            got,
            Some(PathBuf::from("/usr/bin/docker")),
            "root라도 root 통제 하의 폴백(/usr/bin)은 정상 설치다 — 막으면 과잉 방어"
        );
    }

    /// 같은 입력을 **비-root로** 주면 찾아야 한다 — 위 테스트들이 "root라서 막혔다"를 증명하려면
    /// "root가 아니면 찾는다"가 함께 참이어야 한다(공허 통과 방지).
    #[test]
    fn as_non_root_the_same_writable_dirs_are_searched() {
        let got = resolve(
            None,
            Some(OsString::from("/usr/sbin:/sbin")),
            Some(Path::new("/Users/victim")),
            &only(&[
                "/usr/local/bin/docker",
                "/Users/victim/.orbstack/bin/docker",
            ]),
        );
        assert_eq!(got, Some(PathBuf::from("/usr/local/bin/docker")));
    }

    /// **config도 신뢰 판정을 피해 가지 못한다.** root aicd가 사용자 쓰기 가능한 config를 읽는 경우
    /// "명시했으니 믿는다"고 열어 두면 가드가 config로 우회된다.
    #[test]
    fn as_root_an_untrusted_configured_path_is_rejected() {
        let got = resolve_as(
            Some(Path::new("/Users/victim/evil/docker")),
            None,
            None,
            true,
            &only(&["/Users/victim/evil/docker"]),
            &trusted(&[]),
        );
        assert_eq!(got, None, "root인데 신뢰 못 할 config 경로를 채택했다");
    }

    /// root라도 root 통제 하의 config 경로는 그대로 존중한다 — WARN이 안내하는 탈출구가 실제로
    /// 동작해야 한다.
    #[test]
    fn as_root_a_trusted_configured_path_is_accepted() {
        let got = resolve_as(
            Some(Path::new("/opt/docker/bin/docker")),
            None,
            None,
            true,
            &only(&["/opt/docker/bin/docker"]),
            &trusted(&["/opt/docker/bin/docker"]),
        );
        assert_eq!(got, Some(PathBuf::from("/opt/docker/bin/docker")));
    }

    // ── root 신뢰 판정(순수) ──────────────────────────────────────────────────

    /// `is_root_controlled_meta`는 **두 조건이 모두** 필요하다. 어느 하나만 봐도 뚫린다:
    /// - 소유자만 보면 macOS의 `/usr/local/bin`(root:admin **0775**)이 통과해 admin 그룹 아무나
    ///   하이재킹한다.
    /// - 쓰기 비트만 보면 사용자 소유 0755 디렉토리가 통과한다.
    #[test]
    fn is_root_controlled_meta_requires_root_owner_and_no_group_or_other_write() {
        assert!(is_root_controlled_meta(0, 0o755), "root:root 0755 — 정상");
        assert!(is_root_controlled_meta(0, 0o700), "root 전용 — 정상");

        assert!(
            !is_root_controlled_meta(0, 0o775),
            "root 소유라도 group 쓰기 가능하면 안 된다 — macOS /usr/local/bin이 정확히 이거다"
        );
        assert!(
            !is_root_controlled_meta(0, 0o777),
            "other 쓰기 가능하면 안 된다"
        );
        assert!(
            !is_root_controlled_meta(501, 0o755),
            "사용자 소유면 mode가 아무리 빡빡해도 안 된다"
        );
        assert!(
            !is_root_controlled_meta(501, 0o700),
            "사용자 소유 — 안 된다"
        );
    }

    /// 경로 walk 쪽(FS를 실제로 만지는 부분)의 결정적 케이스: 없는 경로는 신뢰하지 않는다.
    /// (긍정 케이스는 root 소유 디렉토리 체인이 필요해 비-root 테스트로는 만들 수 없다 — 그래서
    /// 판정 본체를 위 순수 함수로 떼어 냈다.)
    #[test]
    fn is_root_controlled_path_rejects_a_missing_path() {
        assert!(!is_root_controlled_path(Path::new(
            "/definitely/does/not/exist/docker"
        )));
    }

    // ── 실행 가능 판정 ────────────────────────────────────────────────────────

    /// 실제 파일시스템 판정기 — 디렉토리나 비실행 파일을 docker로 오인하지 않는다.
    #[test]
    fn is_executable_file_rejects_dirs_and_non_executables() {
        let dir = tempfile::tempdir().unwrap();
        // 디렉토리는 x 비트(= 탐색 권한)가 서 있어 `faccessat(X_OK)`가 **성공한다** —
        // is_file() 검사가 없으면 디렉토리를 docker로 오인한다.
        assert!(
            !is_executable_file(dir.path()),
            "디렉토리는 실행 파일이 아니다"
        );

        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(&plain), "실행 비트가 없으면 아니다");

        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable_file(&plain), "실행 비트가 있으면 맞다");

        assert!(!is_executable_file(&dir.path().join("nope")), "없는 경로");
    }

    /// 심볼릭 링크로 설치된 docker(이 머신의 `/usr/local/bin/docker → OrbStack.app/...`)도 잡아야
    /// 한다 — `metadata`가 링크를 따라가는지 확인한다.
    #[test]
    fn is_executable_file_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-docker");
        std::fs::write(&real, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();

        let link = dir.path().join("docker");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(is_executable_file(&link), "심볼릭 링크를 따라가야 한다");
    }

    /// **`mode() & 0o111 != 0`으로는 못 잡는 케이스**: 소유자에게만 x 비트가 **없는** 파일
    /// (mode `0o011` — group/other만 실행 가능). "누군가는 실행 가능"만 보는 낡은 판정은 여기서
    /// true를 내지만, aicd(= 이 파일의 소유자)가 실제로 spawn하면 `EACCES`로 죽는다 — 이 커밋이
    /// 없애려던 "매 tick 실패"가 그대로 남는 것이다. 실효 권한(`faccessat` + `AT_EACCESS`)이라야
    /// false다.
    #[test]
    fn is_executable_file_rejects_a_file_this_process_cannot_execute() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("owner-cannot-exec");
        std::fs::write(&f, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o011)).unwrap();

        // 픽스처 전제를 못박는다 — 낡은 판정이라면 이 파일을 "실행 가능"으로 본다. 이게 깨지면
        // 이 테스트는 아무것도 증명하지 못하므로 조용히 통과시키지 않고 여기서 터뜨린다.
        let mode = std::fs::metadata(&f).unwrap().permissions().mode();
        assert_ne!(
            mode & 0o111,
            0,
            "픽스처 전제 붕괴: 낡은 판정(mode & 0o111)이 이 파일을 실행 불가로 본다면 대조가 성립하지 않는다"
        );

        // root는 x 비트가 하나라도 서 있으면 실제로 실행할 수 있으니 그때는 true가 정답이다.
        // 요점은 "우리 판정 == 커널의 실효 권한 판정"이고, 그건 양쪽 다에서 참이어야 한다.
        // (mutation 검증은 비-root에서 한다 — 아래 assert가 false를 요구한다.)
        let is_root = unsafe { libc::geteuid() } == 0;
        assert_eq!(
            is_executable_file(&f),
            is_root,
            "실효 권한으로 판정해야 한다 — 소유자에게 x가 없으면 소유자는 실행할 수 없다 (euid==0: {is_root})"
        );
    }

    /// **호출부가 실제로 `AT_EACCESS`를 넘기는지** 못박는다. 플래그를 지우거나 `libc::access`
    /// (real uid 기준)로 갈아치우면 여기서 깨진다 — 그게 없으면 "실효 권한으로 본다"는 주장이
    /// 테스트로는 공허해진다(왜 동작 자체는 단위 테스트로 못 만드는지는 `is_executable_file` doc 참고).
    #[test]
    fn is_executable_file_passes_at_eaccess_to_the_kernel() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("exec");
        std::fs::write(&f, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();

        LAST_FACCESSAT_FLAGS.with(|c| c.set(i32::MIN));
        assert!(is_executable_file(&f));
        let flags = LAST_FACCESSAT_FLAGS.with(|c| c.get());
        assert_eq!(
            flags,
            libc::AT_EACCESS,
            "faccessat에 AT_EACCESS가 넘어가지 않았다 — 실효 uid가 아니라 real uid로 판정하게 된다"
        );
    }

    /// 이 플랫폼이 `faccessat`의 flags를 **실제로 검증**한다는 확인 — 엉터리 플래그엔 `EINVAL`을
    /// 낸다. flags를 무시하는 플랫폼이라면 위 테스트가 `AT_EACCESS`를 확인해도 의미가 없으므로,
    /// 그 전제를 여기서 못박는다(macOS/Linux 둘 다 검증한다).
    #[test]
    fn the_platform_actually_validates_faccessat_flags() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("exec");
        std::fs::write(&f, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(faccess_x_ok(&f, libc::AT_EACCESS), "정상 플래그는 통과");
        assert!(
            !faccess_x_ok(&f, 0x4000),
            "엉터리 플래그가 통과했다 — 이 플랫폼은 flags를 무시한다(그렇다면 AT_EACCESS도 무의미하다)"
        );
    }

    /// 실제 `docker system df --format json` 출력(TASK-CONTEXT.md 픽스처) — 4개 카테고리 NDJSON.
    const REAL_DF_OUTPUT: &str = concat!(
        r#"{"Active":"3","Reclaimable":"39.93GB (48%)","Size":"82.64GB","TotalCount":"179","Type":"Images"}"#,
        "\n",
        r#"{"Active":"2","Reclaimable":"224.5kB (0%)","Size":"222.6MB","TotalCount":"3","Type":"Containers"}"#,
        "\n",
        r#"{"Active":"2","Reclaimable":"7.824GB (94%)","Size":"8.3GB","TotalCount":"30","Type":"Local Volumes"}"#,
        "\n",
        r#"{"Active":"0","Reclaimable":"21.66GB","Size":"42.6GB","TotalCount":"344","Type":"Build Cache"}"#,
        "\n",
    );

    /// stdout에 고정 텍스트를 출력하는 실행 가능한 shell 스크립트를 만든다(실제 `docker` 바이너리
    /// 없이 spawn+timeout+parse 파이프라인 전체를 결정적으로 검증하기 위한 test double).
    fn fake_docker_bin(dir: &tempfile::TempDir, script: &str) -> std::path::PathBuf {
        let path = dir.path().join("fake-docker");
        fake_docker_bin_at(&path, script);
        path
    }

    /// [`fake_docker_bin`]의 경로 지정 버전 — "나중에 docker를 설치한다"를 재현할 때 쓴다.
    fn fake_docker_bin_at(path: &Path, script: &str) {
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "#!/bin/sh\n{script}").unwrap();
        drop(f);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // ── 바이트 파서 ─────────────────────────────────────────────────────────

    #[test]
    fn parse_docker_size_handles_plain_size() {
        assert_eq!(parse_docker_size("82.64GB"), Some(82_640_000_000));
    }

    #[test]
    fn parse_docker_size_strips_trailing_percentage() {
        assert_eq!(parse_docker_size("39.93GB (48%)"), Some(39_930_000_000));
    }

    #[test]
    fn parse_docker_size_handles_size_without_percentage() {
        // Build Cache의 Reclaimable은 퍼센트가 없다 — 있는 경우와 별도 경로로 다뤄야 한다.
        assert_eq!(parse_docker_size("21.66GB"), Some(21_660_000_000));
    }

    #[test]
    fn parse_docker_size_handles_kilobytes() {
        assert_eq!(parse_docker_size("224.5kB"), Some(224_500));
    }

    #[test]
    fn parse_docker_size_handles_bytes_and_zero() {
        assert_eq!(parse_docker_size("0B"), Some(0));
        assert_eq!(parse_docker_size("512B"), Some(512));
    }

    #[test]
    fn parse_docker_size_rejects_unrecognized_input() {
        assert_eq!(parse_docker_size(""), None);
        assert_eq!(parse_docker_size("N/A"), None);
        assert_eq!(
            parse_docker_size("12.3XB"),
            None,
            "모르는 단위는 None이어야 한다"
        );
    }

    // ── NDJSON 파싱 ─────────────────────────────────────────────────────────

    #[test]
    fn parse_ndjson_lines_parses_all_four_categories() {
        let lines = parse_ndjson_lines(REAL_DF_OUTPUT.as_bytes());
        assert_eq!(lines.len(), 4);
        let kinds: Vec<&str> = lines.iter().map(|l| l.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["Images", "Containers", "Local Volumes", "Build Cache"]
        );
    }

    #[test]
    fn parse_ndjson_lines_skips_only_the_malformed_line() {
        let mixed = format!(
            "{}\nnot even json\n{}",
            r#"{"Active":"3","Reclaimable":"39.93GB (48%)","Size":"82.64GB","TotalCount":"179","Type":"Images"}"#,
            r#"{"Active":"0","Reclaimable":"21.66GB","Size":"42.6GB","TotalCount":"344","Type":"Build Cache"}"#,
        );
        let lines = parse_ndjson_lines(mixed.as_bytes());
        assert_eq!(lines.len(), 2, "망가진 한 줄만 빠지고 나머지는 살아야 한다");
        assert_eq!(lines[0].kind, "Images");
        assert_eq!(lines[1].kind, "Build Cache");
    }

    #[test]
    fn parse_ndjson_lines_on_whole_blob_json_array_would_fail_but_line_by_line_succeeds() {
        // connections.rs 패턴(serde_json::from_slice(전체))을 그대로 썼다면 최상위가 배열이 아니라
        // 여기서 즉시 실패한다 — 그 회귀를 잡기 위한 대조 테스트.
        assert!(serde_json::from_slice::<Vec<DfLine>>(REAL_DF_OUTPUT.as_bytes()).is_err());
        assert_eq!(parse_ndjson_lines(REAL_DF_OUTPUT.as_bytes()).len(), 4);
    }

    // ── metric point 구성 ───────────────────────────────────────────────────

    /// 픽스처에 있는 값은 **하나도 버리지 않는다** — 4 카테고리 × (Size, Reclaimable) = 8개.
    ///
    /// 회귀 이력: 한때 컨테이너의 `Reclaimable`을 "스펙상 없다"며 버렸는데, 바로 이 픽스처에
    /// `"224.5kB (0%)"`로 실재했다. 그래서 이 테스트는 개별 metric을 확인하는 데 그치지 않고
    /// **픽스처의 모든 (카테고리, 필드) 조합이 빠짐없이 나갔는지**를 대조한다.
    #[test]
    fn build_metric_points_emits_all_eight_scalars_with_correct_bytes() {
        let lines = parse_ndjson_lines(REAL_DF_OUTPUT.as_bytes());
        let points = build_metric_points(&lines);

        let get = |name: &str| {
            points
                .iter()
                .find(|p| p.name == name)
                .map(|p| match p.value {
                    MetricValue::Int(v) => v,
                    MetricValue::Double(_) => panic!("docker metric은 항상 Int(바이트)여야 함"),
                })
        };

        // 픽스처의 8개 값을 그대로 대조한다(Size 4 + Reclaimable 4).
        let expected: [(&str, i64); 8] = [
            ("aic.docker.image.disk.usage", 82_640_000_000),
            ("aic.docker.image.disk.reclaimable", 39_930_000_000),
            ("aic.docker.container.disk.usage", 222_600_000),
            // 이 값이 픽스처의 "224.5kB (0%)"다 — 버려서는 안 된다.
            ("aic.docker.container.disk.reclaimable", 224_500),
            ("aic.docker.volume.disk.usage", 8_300_000_000),
            ("aic.docker.volume.disk.reclaimable", 7_824_000_000),
            ("aic.docker.build_cache.disk.usage", 42_600_000_000),
            ("aic.docker.build_cache.disk.reclaimable", 21_660_000_000),
        ];
        for (name, want) in expected {
            assert_eq!(get(name), Some(want), "{name} 누락 또는 값 불일치");
        }

        assert_eq!(
            points.len(),
            8,
            "4 카테고리 × (Size, Reclaimable) = 8개가 전부 나가야 한다 — 버리는 값이 없다"
        );
        for p in &points {
            assert_eq!(p.unit, "By", "모든 docker metric은 무차원 바이트");
        }
    }

    /// 위 테스트가 이름을 하드코딩하므로, 픽스처의 **줄 수**가 늘면(도커가 카테고리를 추가하면)
    /// 조용히 놓치지 않도록 카테고리 수와 point 수의 관계를 따로 못박는다.
    ///
    /// **이름의 유일성까지 본다**: 개수만 세면 한 카테고리가 같은 이름을 두 번 내도 통과한다
    /// (실제로 mutation 검증에서 이 구멍에 걸렸다 — 컨테이너의 reclaimable 이름을 usage로
    /// 되돌렸는데 개수는 그대로 8이라 잡히지 않았다). metric 이름이 겹치면 수신측에서 서로를
    /// 덮어쓰므로 유일성은 그 자체로 중요한 invariant다.
    #[test]
    fn every_parsed_category_contributes_a_distinct_size_and_reclaimable_point() {
        let lines = parse_ndjson_lines(REAL_DF_OUTPUT.as_bytes());
        let points = build_metric_points(&lines);
        assert_eq!(
            points.len(),
            lines.len() * 2,
            "카테고리마다 usage/reclaimable 두 개씩 — 어느 한쪽이라도 버리면 여기서 걸린다"
        );

        let mut names: Vec<&str> = points.iter().map(|p| p.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "metric 이름이 중복됐다 — 수신측에서 서로를 덮어쓴다: {names:?}"
        );
    }

    #[test]
    fn build_metric_points_skips_only_the_unparseable_value() {
        let lines = vec![
            DfLine {
                kind: "Images".to_string(),
                size: "not a size".to_string(),
                reclaimable: Some("39.93GB (48%)".to_string()),
            },
            DfLine {
                kind: "Build Cache".to_string(),
                size: "42.6GB".to_string(),
                reclaimable: Some("21.66GB".to_string()),
            },
        ];
        let points = build_metric_points(&lines);
        // Images.usage는 파싱 실패해 생략되지만 Images.reclaimable과 Build Cache 둘 다는 살아야 한다
        // — "모르는 값은 0이 아니라 생략"의 핵심 invariant.
        assert!(points
            .iter()
            .all(|p| p.name != "aic.docker.image.disk.usage"));
        assert!(points
            .iter()
            .any(|p| p.name == "aic.docker.image.disk.reclaimable"));
        assert!(points
            .iter()
            .any(|p| p.name == "aic.docker.build_cache.disk.usage"));
        assert!(points
            .iter()
            .any(|p| p.name == "aic.docker.build_cache.disk.reclaimable"));
    }

    #[test]
    fn build_metric_points_ignores_unknown_type_without_panicking() {
        let lines = vec![DfLine {
            kind: "Some Future Category".to_string(),
            size: "1GB".to_string(),
            reclaimable: None,
        }];
        assert!(build_metric_points(&lines).is_empty());
    }

    // ── capture_docker_df: spawn/timeout/exit/파싱 4중 방어 ────────────────────

    use super::super::proc::testutil::{is_text_file_busy, retry_busy};

    #[tokio::test]
    async fn capture_docker_df_parses_real_ndjson_output_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(&dir, &format!("cat <<'EOF'\n{REAL_DF_OUTPUT}EOF"));

        let lines = retry_busy(|| capture_docker_df(&bin, Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].kind, "Images");
        assert_eq!(lines[0].size, "82.64GB");
    }

    #[tokio::test]
    async fn capture_docker_df_errors_on_nonzero_exit() {
        // 데몬 다운/권한 없음 둘 다 non-zero exit라 제어 흐름은 같다 — 다만 stderr가 에러에 실려
        // 로그에서는 둘을 구분할 수 있어야 한다(exit status만 남기면 운영 중에 원인을 못 가린다).
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(
            &dir,
            "echo 'failed to connect to the docker API at unix:///var/run/docker.sock' >&2; exit 1",
        );
        let err = retry_busy(|| capture_docker_df(&bin, Duration::from_secs(5)))
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("종료"), "err={msg}");
        assert!(
            msg.contains("failed to connect to the docker API"),
            "데몬 다운 원인(stderr)이 에러에 실려야 한다: {msg}"
        );
    }

    #[tokio::test]
    async fn capture_docker_df_times_out_on_hung_process() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(&dir, "sleep 30");
        let err = retry_busy(|| capture_docker_df(&bin, Duration::from_millis(100)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("끝나지 않음"), "err={err}");
    }

    #[tokio::test]
    async fn capture_docker_df_errors_on_spawn_failure_when_docker_not_installed() {
        let missing = std::path::PathBuf::from("/definitely/does/not/exist/docker");
        assert!(capture_docker_df(&missing, Duration::from_secs(5))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn capture_docker_df_errors_when_every_line_fails_to_parse() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(&dir, "echo 'not json at all'");
        assert!(
            retry_busy(|| capture_docker_df(&bin, Duration::from_secs(5)))
                .await
                .is_err()
        );
    }

    /// **회귀 가드**: timeout 시 spawn된 `docker`가 실제로 죽어야 한다. `tokio::time::timeout`은
    /// future만 drop할 뿐 자식 프로세스를 죽이지 않는다 — aicd는 상주 데몬이고 이 task는 60초마다
    /// 도니, docker가 hang하는 환경이면 orphan이 매 tick 쌓인다. 플래그가 켜졌는지가 아니라
    /// **프로세스가 사라졌는지**를 확인한다(재시도 전략은 `super::proc::testutil` 참고).
    #[tokio::test]
    async fn capture_docker_df_timeout_kills_the_child_process() {
        use super::super::proc::testutil::{alive, hang_script, read_pid, GRACES};

        for grace in GRACES {
            let dir = tempfile::tempdir().unwrap();
            let pidfile = dir.path().join("pid");
            let bin = fake_docker_bin(&dir, &hang_script(&pidfile));

            let err = capture_docker_df(&bin, grace).await.unwrap_err();
            // 스크립트 exec race(ETXTBSY) — 자식이 아예 안 떴다. 다시 시도한다.
            if is_text_file_busy(&err) {
                continue;
            }
            assert!(err.to_string().contains("끝나지 않음"), "err={err}");

            // pid가 없으면 자식이 기동 전이었다 — 죽일 자식이 없었으니 단정하지 않는다(공허 통과 방지).
            let Some(pid) = read_pid(&pidfile) else {
                continue;
            };
            assert!(
                !alive(pid),
                "timeout 후에도 docker(pid={pid})가 살아 있다 — orphan 누수"
            );
            return;
        }
        panic!("자식이 한 번도 기동하지 못해 orphan 여부를 검증하지 못했다");
    }

    /// **회귀 가드**: 무한 출력은 전부 버퍼링되기 전에 스트리밍 도중 끊긴다. 사후 확인 방식
    /// (`wait_with_output()` 후 길이 검사)이라면 이 테스트는 끝나지 않거나 OOM으로 죽는다.
    #[tokio::test]
    async fn capture_docker_df_cuts_off_unbounded_output_mid_stream() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_docker_bin(
            &dir,
            "while :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done",
        );

        // 바깥 timeout을 안쪽보다 넉넉히 줘야 "상한 때문에 끊겼다"와 "timeout이라 끊겼다"가 구분된다.
        let err = tokio::time::timeout(
            Duration::from_secs(20),
            retry_busy(|| capture_docker_df(&bin, Duration::from_secs(15))),
        )
        .await
        .expect("상한이 스트리밍으로 강제되지 않아 무한 출력에 매달렸다")
        .unwrap_err();

        assert!(err.to_string().contains("상한"), "err={err}");
    }

    // ── serve_docker: 캡처 실패가 task를 죽이지 않고, 다른 signal이 공유하는 health/spool도 오염하지 않는다 ──

    #[tokio::test]
    async fn serve_docker_survives_missing_binary_without_touching_shared_health_or_spool() {
        let dir = tempfile::tempdir().unwrap();
        let quotas = aic_common::SpoolQuotas {
            metrics: 1024 * 1024,
            logs: 1024 * 1024,
            app_logs: 1024 * 1024,
        };
        let spool = Arc::new(Spool::open(dir.path().to_path_buf(), quotas).unwrap());
        let health = Arc::new(super::super::ExporterHealth::new(
            "http://127.0.0.1:1".to_string(),
            spool.clone(),
        ));

        let cfg = DockerConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            interval: Duration::from_millis(15),
            docker_bin: Some(std::path::PathBuf::from(
                "/definitely/does/not/exist/docker",
            )),
            configured_bin: None,
            timeout: Duration::from_secs(5),
            spool: spool.clone(),
            health: health.clone(),
        };

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_docker(cfg, rx));
        // interval(15ms)보다 훨씬 긴 유예를 둬 여러 tick이 반드시 발생하게 한다.
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send_replace(true);
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve_docker가 shutdown 후 hang됨")
            .expect("serve_docker task가 panic함");
        assert!(
            result.is_ok(),
            "캡처 반복 실패가 task 자체를 죽이면 안 됨: {result:?}"
        );

        // 캡처 실패는 push를 시도조차 하지 않으므로, 다른 exporter task와 공유하는 health/spool은
        // 전혀 건드리지 않는다 — docker 미설치가 events/connections/changes/agent의 건강 카운터를
        // 오염시키지 않는다는 증거.
        let snap = health.snapshot();
        assert_eq!(snap.push_ok_total, 0);
        assert_eq!(snap.push_fail_total, 0);
        assert_eq!(
            spool.batch_count(),
            0,
            "캡처 실패는 spool에 아무것도 남기지 않는다"
        );
    }

    /// **회귀 가드**: aicd가 뜬 뒤에 docker를 설치해도 재시작 없이 살아나야 한다. 기동 시 1회만
    /// 판정하고 못 찾으면 task를 안 띄우던 앞 판에서는 exporter가 **영구 비활성**이었다
    /// (`serve_docker`의 "나중에 설치된 docker" 참고).
    ///
    /// 캡처 성공 여부는 spool로 관찰한다 — endpoint가 죽어 있으니 캡처가 되면 push가 실패하고
    /// 샘플이 spool에 쌓인다. 캡처 자체가 안 되면 spool은 그대로 0이다(바로 위 테스트가 그 성질을
    /// 못박는다). 즉 `0 -> 0 초과`가 곧 "없던 docker를 찾아 캡처를 시작했다"는 증거다.
    #[tokio::test]
    async fn serve_docker_starts_capturing_when_docker_appears_after_startup() {
        let dir = tempfile::tempdir().unwrap();
        let quotas = aic_common::SpoolQuotas {
            metrics: 1024 * 1024,
            logs: 1024 * 1024,
            app_logs: 1024 * 1024,
        };
        let spool_dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(Spool::open(spool_dir.path().to_path_buf(), quotas).unwrap());
        let health = Arc::new(super::super::ExporterHealth::new(
            "http://127.0.0.1:1".to_string(),
            spool.clone(),
        ));

        // 아직 존재하지 않는 경로 — 나중에 여기에 "docker를 설치"한다.
        let bin_path = dir.path().join("fake-docker");

        let cfg = DockerConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            interval: Duration::from_millis(15),
            docker_bin: None, // 기동 시 못 찾았다.
            configured_bin: Some(bin_path.clone()),
            timeout: Duration::from_secs(5),
            spool: spool.clone(),
            health: health.clone(),
        };

        // 재탐색기: 파일이 실제로 생겨야 찾았다고 답한다(진짜 resolve의 euid/소유권 의존을 피한다).
        let probe = bin_path.clone();
        let resolver =
            move |_: Option<&Path>| -> Option<PathBuf> { probe.exists().then(|| probe.clone()) };

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { serve_docker_with(cfg, rx, &resolver).await });

        // 아직 docker가 없다 — 여러 tick이 지나도 캡처는 없다.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            spool.batch_count(),
            0,
            "docker가 없는데 캡처가 됐다 — 테스트 전제가 무너졌다"
        );

        // 여기서 docker를 "설치"한다.
        fake_docker_bin_at(&bin_path, &format!("cat <<'EOF'\n{REAL_DF_OUTPUT}EOF"));

        // 재시작 없이 저절로 캡처가 시작돼야 한다.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if spool.batch_count() > 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "docker를 설치했는데도 캡처가 시작되지 않았다 — 재탐색이 동작하지 않는다"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve_docker가 shutdown 후 hang됨")
            .expect("serve_docker task가 panic함")
            .expect("serve_docker가 에러로 끝남");
    }
}
