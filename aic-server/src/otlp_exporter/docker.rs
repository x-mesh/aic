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

/// `$HOME` 밑의 docker 설치 위치들. 홈은 런타임에만 알 수 있어 [`FALLBACK_DOCKER_DIRS`]와 분리한다.
///
/// - `.orbstack/bin/docker` — OrbStack이 사용자 홈에도 둔다.
/// - `.docker/bin/docker` — Docker Desktop을 **user 설치**(Advanced settings → System/User)로 고르면
///   여기 심볼릭 링크를 만든다. system 설치는 `/usr/local/bin`([`FALLBACK_DOCKER_DIRS`])이다.
///
/// 둘 다 사용자 쓰기 가능 경로라 **root aicd일 땐 walk가 자동으로 거부**한다([`resolve_docker_bin_with`]의
/// "쓰기 가능 경로와 root" 참고) — 즉 이 폴백들은 비-root aicd에서만 유효하고, 그게 옳은 동작이다.
const HOME_RELATIVE_DOCKER_PATHS: &[&str] = &[".orbstack/bin/docker", ".docker/bin/docker"];
/// `docker system df --format json` stdout 상한. 정상 출력은 카테고리 4줄뿐이라 이 한도를 훨씬
/// 밑돈다 — 초과분은 신뢰할 수 없는 출력으로 간주해 이번 주기를 스킵한다.
///
/// 상한은 [`super::proc::run_capped`]가 **스트리밍으로 읽으면서** 강제하므로 실제로 메모리를
/// 묶는다(출력을 전부 버퍼링한 뒤 길이를 재는 건 방어가 아니라 사후 확인이다 — 그렇게 짜면 무한
/// 출력이 검사에 도달하기 전에 이미 메모리를 먹는다).
const MAX_DF_OUTPUT_BYTES: usize = 256 * 1024;

/// docker 실행 파일의 **절대경로**를 찾는다. 못 찾으면 `None`.
///
/// `None`이라고 exporter를 영영 포기하지는 않는다: [`serve_docker`] task는 그래도 뜨고, 기동 시
/// 한 번 WARN을 남긴 뒤 **매 tick 이 함수를 다시 부른다** — docker가 나중에 설치되면 그때부터 캡처를
/// 시작한다(자세한 건 [`serve_docker`]의 "나중에 설치된 docker" 참고). 즉 이 함수의 `None`은 "지금은
/// 없다"이지 "비활성"이 아니다.
///
/// 탐색 순서: `configured`(config `[aicd.exporter].docker_bin`) → `PATH` → [`FALLBACK_DOCKER_DIRS`]
/// → [`HOME_RELATIVE_DOCKER_PATHS`](`$HOME/.orbstack/bin/docker`, `$HOME/.docker/bin/docker`).
/// 서비스 매니저의 빈약한 PATH를 폴백이 메워 준다(위 상수 doc 참고).
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
/// 폴백 목록에는 쓰기 가능한 디렉토리가 섞여 있다 — `$HOME/.orbstack/bin`·`$HOME/.docker/bin`
/// (사용자 소유), `/usr/local/bin`(macOS에선 admin 그룹 쓰기 가능). 그럼에도 폴백을 두는 근거:
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
            // **debug다** — 이 함수는 매 tick 재탐색에서 다시 불린다(`serve_docker`). 여기서 WARN을
            // 내면 "60초마다 WARN을 쏟지 않는다"는 이 모듈의 보장이 그대로 깨진다. 상태가 바뀔 때만
            // (찾음/잃음) 시끄러워야 하고, 그 판단은 상태를 아는 호출부가 한다.
            tracing::debug!(
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
            // 여기도 debug다 — 위 accept와 같은 이유(매 tick 재탐색에서 다시 불린다).
            tracing::debug!(
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
        for rel in HOME_RELATIVE_DOCKER_PATHS {
            if let Some(found) = accept(h.join(rel)) {
                return Some(found);
            }
        }
    }

    None
}

/// 후보 경로가 **root 통제 하**에 있는가 — euid가 0일 때만 쓴다([`resolve_docker_bin_with`]의
/// "쓰기 가능 경로와 root" 참고).
///
/// # 검사 대상은 "실제로 실행될 전 구간"이다 (canonicalize만으로는 절반이다)
///
/// 커널이 `execve(cand)`를 처리할 때 경로를 **한 성분씩** 내려가며 심볼릭 링크를 따라간다. 이때
/// 실제로 실행될 바이너리를 바꿀 수 있는 지점은 셋이다:
/// 1. 경로 위의 **모든 디렉토리** — 비-root가 쓸 수 있으면 성분을 rename/replace해 딴 데로 돌린다.
/// 2. 경로 위의 **모든 심볼릭 링크** — 대상을 바꾸면 실행 파일이 바뀐다. 링크는 제자리 수정이 안 되고
///    **자기가 놓인 디렉토리**를 통해서만 교체되므로, 링크의 부모 디렉토리가 곧 통제점이다(→ 1).
/// 3. **최종 실행 파일** — 비-root가 쓸 수 있으면 내용을 갈아친다.
///
/// 그래서 **원칙은 "실행될 경로를 구성하는 어떤 성분도 비-root가 바꿀 수 없어야 한다"**이다. 이걸
/// 커널과 똑같이 성분 단위로 내려가며 검사한다 — 디렉토리를 만나면 그 디렉토리를, 링크를 만나면
/// (부모는 이미 검사했으니) 링크를 따라 대상 경로로 갈아타 계속, 최종 파일에서 파일 자신을 검사한다.
///
/// 예전 판은 `canonicalize(cand)`의 성분만 검사했다 — 이건 **대상**만 본다. 정작 spawn되는 건
/// `cand`(예: `/usr/local/bin/docker`)인데, 그 링크가 놓인 `/usr/local/bin`을 아무도 검사하지
/// 않았다. `/usr/local/bin`이 group-writable(Homebrew 기본 `0775 root:admin`)이면 admin 그룹이
/// 링크를 스왑해 root aicd가 임의 바이너리를 실행하게 만든다 — 우리가 3라운드 전에 막은 것의
/// **정확한 대칭**(그때는 root 링크 → 사용자 대상, 이번엔 사용자 디렉토리의 링크 → root 대상)이다.
///
/// **심볼릭 링크 자신의 mode는 보지 않는다**: 링크는 언제나 `0777 lrwxrwxrwx`라 mode 검사가 무의미
/// 하다. 링크의 무결성은 순전히 부모 디렉토리(교체 가능 여부)가 좌우하고, 그 부모는 내려오는 길에
/// 이미 검사했다.
///
/// **상대 링크 대상은 해소한다(거부하지 않는다)**: Homebrew가 정확히 상대 링크를 쓴다 —
/// `/opt/homebrew/bin/docker -> ../Cellar/docker/<ver>/bin/docker`. `..`는 "위험"이 아니라 그냥
/// "부모로 올라감"이라 거부가 아니라 접어야 한다. 링크가 놓인 디렉토리 기준으로 절대화한 뒤 다시
/// 성분 단위로 walk하므로, `../Cellar/...`의 각 성분이 root 통제 하면 정상 통과한다(그렇지 않으면
/// 그 성분에서 거부). `..`를 렉시컬하게 접는 게 안전한 근거는 아래 walk 본문의 `ParentDir` 주석 참고.
///
/// stat 실패나 파일 종류가 이상하면(디바이스 등) **거부**한다(fail-closed). 심볼릭 루프 방어로
/// 따라가는 링크 수에 상한을 둔다.
fn is_root_controlled_path(p: &Path) -> bool {
    is_root_controlled_walk(p, 0, &|path| {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        match std::fs::symlink_metadata(path) {
            Ok(md) => {
                is_root_controlled_meta(md.uid(), md.permissions().mode(), has_extended_acl(path))
            }
            Err(_) => false,
        }
    })
}

/// 심볼릭 링크를 따라가며 실행 경로의 **모든 성분**을 검사하는 순수 코어. 성분의 신뢰 판정을
/// 주입받는다 — 실제 판정(소유권/mode/ACL)은 root 소유 파일이 필요해 비-root 테스트로는 못 만들지만,
/// **"어느 성분을 검사하는가"**(링크가 놓인 디렉토리를 빠뜨리지 않는지)는 이 주입점으로 결정적으로
/// 검증할 수 있다. FS 구조(링크/디렉토리)는 tempdir에 실제로 만들어 traversal은 진짜로 돈다.
fn is_root_controlled_walk(p: &Path, depth: u32, trusted: &dyn Fn(&Path) -> bool) -> bool {
    use std::path::Component;

    /// ELOOP 방어 — 커널 기본(`MAXSYMLINKS`)과 같은 40.
    const MAX_SYMLINK_DEPTH: u32 = 40;
    if depth > MAX_SYMLINK_DEPTH || !p.is_absolute() {
        return false;
    }

    let mut current = PathBuf::from("/");
    // 루트(`/`)부터 검사한다 — 루트가 신뢰 밖이면 그 아래 전부 의미 없다.
    if !trusted(&current) {
        return false;
    }

    let comps: Vec<Component> = p.components().collect();
    for (idx, comp) in comps.iter().enumerate() {
        let name = match comp {
            Component::RootDir => continue,
            // `.` — 무시한다(현재 위치 유지).
            Component::CurDir => continue,
            // `..` — 부모로 접는다. **이게 안전한 이유**: 이 walk는 심볼릭 링크를 만나면 즉시 대상
            // 경로로 restart하므로(아래 `is_symlink` 가지), 여기까지 쌓인 `current`에는 링크가 하나도
            // 없다(전부 실제 디렉토리). 링크 없는 경로에서 `..`를 렉시컬하게 pop하는 건 커널의 해소와
            // 정확히 같다 — canonicalize가 필요한 "링크를 건너뛰며 접는" 위험이 여기엔 없다.
            // (`/`에서 pop은 no-op이라 루트 위로는 못 올라간다.)
            Component::ParentDir => {
                current.pop();
                continue;
            }
            Component::Normal(n) => n,
            Component::Prefix(_) => return false,
        };
        current.push(name);

        let Ok(md) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        let ft = md.file_type();
        let is_last = idx == comps.len() - 1;

        if ft.is_symlink() {
            // 부모 디렉토리는 이미 신뢰됨을 확인했다 → 이 링크는 비-root가 스왑할 수 없다.
            // 링크 자신의 mode는 보지 않고(0777이라 무의미), 대상 경로로 갈아타 계속 검사한다.
            let Ok(target) = std::fs::read_link(&current) else {
                return false;
            };
            // **상대 링크 대상은 거부가 아니라 해소한다.** Homebrew가 정확히 상대 링크를 쓴다:
            // `/opt/homebrew/bin/docker -> ../Cellar/docker/<ver>/bin/docker`. 링크가 놓인 디렉토리
            // (`current.parent()`) 기준으로 절대화한 뒤, 남은 성분(`..`/`.` 포함)을 그대로 이어 붙여
            // **다시 성분 단위로** walk한다 — restart하는 walk가 그 안의 링크를 또 성분별로 따라가고,
            // `..`는 위에서 렉시컬하게 접힌다. `../Cellar/...`의 각 성분이 root 통제 하면 통과한다.
            let base = match current.parent() {
                Some(b) => b.to_path_buf(),
                None => return false,
            };
            let mut next = if target.is_absolute() {
                target
            } else {
                base.join(target)
            };
            // 남은 성분을 있는 그대로(`..`/`.` 포함) 이어 붙인다 — 정규화는 restart된 walk가 한다.
            for rest in &comps[idx + 1..] {
                match rest {
                    Component::Normal(n) => next.push(n),
                    Component::CurDir => {}
                    Component::ParentDir => next.push(".."),
                    Component::RootDir | Component::Prefix(_) => return false,
                }
            }
            return is_root_controlled_walk(&next, depth + 1, trusted);
        } else if ft.is_dir() {
            if !trusted(&current) {
                return false;
            }
        } else if ft.is_file() {
            // 실행 파일은 경로의 **끝**이어야 한다. 중간에 파일이 나오면 잘못된 경로다.
            if !is_last {
                return false;
            }
            return trusted(&current);
        } else {
            // 소켓·디바이스 등 — docker 실행 파일이 아니다.
            return false;
        }
    }
    // 모든 성분을 소진했는데 끝이 디렉토리였다 — 실행 **파일**이 아니다.
    false
}

/// [`is_root_controlled_path`]의 순수 판정 — 한 경로 성분이 root 통제 하인가.
///
/// 셋 **모두** 필요하다:
/// - **root 소유**(`uid == 0`) — 아니면 소유자가 언제든 갈아치운다.
/// - **group/other 쓰기 불가**(`mode & 0o022 == 0`) — 소유자만 보면 `/usr/local/bin`(macOS에서
///   root:admin **0775**)이 통과해 admin 그룹 아무나 하이재킹한다.
/// - **확장 ACL 없음** — mode 비트가 깨끗해도 ACL로 쓰기 권한이 붙어 있을 수 있다. 아래 참고.
///
/// # 왜 ACL까지 보는가 (그리고 왜 "해석"하지 않는가)
///
/// macOS의 확장 ACL은 **mode 비트와 완전히 독립**이다. `chmod +a "someone allow write"`를 걸어도
/// `ls -l`은 그대로 `0755 root:wheel`로 보인다 — 즉 `mode & 0o022`만 보는 판정은 **fail-open**이다.
/// 겉보기 root 소유인데 실제로는 사용자가 쓸 수 있는 것, canonicalize로 막은 것과 정확히 같은
/// 종류의 우회다. **fail-open인 방어 장치는 없느니만 못하다** — 있다고 믿게 만들기 때문이다.
///
/// ACL을 파싱해 "안전한 ACL인가"를 판정하지는 **않는다**. 그건 복잡하고 그 자체가 새 버그 표면이다.
/// **확장 ACL이 존재하면 신뢰하지 않는다**로 끝낸다(fail-closed). 정상적인 시스템 경로(`/usr/bin`,
/// `/usr`, `/`)엔 확장 ACL이 없으니 과잉 거부가 아니다.
///
/// Linux의 POSIX ACL은 사정이 다르다 — 명명된 사용자에게 쓰기를 주면 그 권한은 **ACL mask**를
/// 거치고, mask는 곧 **group mode 비트로 드러난다**. 그래서 Linux에서는 `mode & 0o022`가 이미
/// 잡는다(실효 쓰기 권한이 mode에 안 보이게 숨을 수 없다). 그럼에도 Linux에서도 ACL 존재를 함께
/// 보는 이유는 방어 심층화이고 비용이 거의 없어서다.
///
/// 파일시스템을 건드리지 않는 순수 함수로 떼어 낸 이유는 테스트다 — root 소유 디렉토리는 root가
/// 아니면 만들 수 없어서, FS를 통째로 쓰면 "이 머신이 root인가"에 결과가 끌려간다.
fn is_root_controlled_meta(uid: u32, mode: u32, has_extended_acl: bool) -> bool {
    uid == 0 && mode & 0o022 == 0 && !has_extended_acl
}

/// 이 경로에 **확장 ACL**이 붙어 있는가. 판단이 불가능하면 **`true`(신뢰 못 함)를 반환한다** —
/// 이 함수의 소비자는 보안 게이트라 모르는 것은 위험한 것으로 친다(fail-closed).
///
/// **호출자([`is_root_controlled_walk`])는 심볼릭 링크 성분엔 이 함수를 부르지 않는다** — 링크는
/// 검사하지 않고 대상으로 따라가므로(무결성은 링크의 부모 디렉토리가 좌우), 여기 들어오는 건 언제나
/// 실제 디렉토리이거나 최종 실행 **파일**이다(링크가 아니다). 그래서 링크-추종 여부는 실질적으로
/// 무의미하지만, 아래 두 API 모두 **링크를 따라가지 않는 변종**(`_link_np` / `lgetxattr`)을 쓴다 —
/// 설령 링크가 들어와도 대상이 아니라 그 경로 성분 자신의 ACL을 보는 보수적(fail-safe) 선택이다.
/// (예전 doc은 "canonicalize한 뒤라 링크가 없다"고 했는데, walk 재작성으로 더는 canonicalize를 안
/// 쓴다 — 링크가 없는 이유가 "canonicalize"가 아니라 "walk가 링크 성분을 검사 대상에서 제외"로 바뀌었다.)
///
/// - **macOS**: `acl_get_link_np(path, ACL_TYPE_EXTENDED)`가 non-NULL이면 ACL이 있다. 없으면 NULL +
///   `ENOENT`.
/// - **Linux**: `system.posix_acl_access` xattr이 있으면 ACL이 있다. 없으면 `ENODATA`. 파일시스템이
///   ACL을 아예 지원하지 않으면(`ENOTSUP`) ACL로 권한을 줄 수도 없으므로 "없음"으로 친다.
///   디렉토리의 *default* ACL(`system.posix_acl_default`)은 보지 않는다 — 상속 템플릿일 뿐,
///   그 디렉토리 자체에 쓰기 권한을 주지 않는다.
fn has_extended_acl(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let Ok(c_path) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return true; // 경로에 NUL — 판단 불가.
    };

    #[cfg(target_os = "macos")]
    {
        // macOS `sys/acl.h`: `ACL_TYPE_EXTENDED = 0x00000100`. libc 크레이트가 ACL API를 노출하지
        // 않아 직접 선언한다.
        const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
        extern "C" {
            fn acl_get_link_np(
                path: *const libc::c_char,
                acl_type: libc::c_int,
            ) -> *mut libc::c_void;
            fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
        }

        // SAFETY: c_path는 살아 있는 NUL 종료 C 문자열이고, acl_get_link_np는 그것을 읽기만 한다.
        // 반환된 non-NULL 핸들은 acl_free로 즉시 해제한다(누수 방지).
        let acl = unsafe { acl_get_link_np(c_path.as_ptr(), ACL_TYPE_EXTENDED) };
        if !acl.is_null() {
            // SAFETY: 방금 acl_get_link_np가 돌려준 유효한 핸들이다.
            unsafe { acl_free(acl) };
            return true;
        }
        // NULL이면 errno로 "없다"와 "모르겠다"를 가른다.
        let err = std::io::Error::last_os_error();
        !matches!(err.raw_os_error(), Some(libc::ENOENT))
    }

    #[cfg(target_os = "linux")]
    {
        const ACL_XATTR: &[u8] = b"system.posix_acl_access\0";
        // SAFETY: 두 포인터 모두 살아 있는 NUL 종료 C 문자열이고, 크기 0으로 물어보므로 값 버퍼에
        // 쓰지 않는다(존재 여부만 확인).
        let rc = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                ACL_XATTR.as_ptr() as *const libc::c_char,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc >= 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // ACL 없음 / 이 FS는 ACL을 지원하지 않음(=> ACL로 권한을 줄 수도 없다).
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => false,
            // 그 밖의 실패는 모른다는 뜻 — 보안 게이트라 위험한 쪽으로 친다.
            _ => true,
        }
    }

    // aicd는 macOS/Linux만 지원한다(`daemon_install.rs`의 `detect_platform`). 그 밖의 unix에서는 ACL을
    // 확인할 방법이 없으므로 **fail-closed로 `true`(신뢰 못 함)**를 반환한다 — 이 함수는 보안 게이트라
    // 모르는 건 위험한 것으로 친다. 영향은 "지원 밖 OS에서 **root로** 뜬 aicd"뿐이고(비-root는 신뢰
    // 판정 자체를 안 탄다), 그 조합에서 docker exporter가 안 뜨는 건 안전한 실패다. 이 분기가 없으면
    // 다른 unix에서 **컴파일 에러**가 나므로(반환값 없음), 명시적으로 처리한다.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = &c_path;
        true
    }
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
/// 반대 방향도 대칭으로 처리한다: 찾은 뒤에 docker가 **사라지면**(경로가 지워지거나 바뀌어 spawn이
/// `ENOENT`) 다음 tick부터 다시 재탐색한다. 한쪽만 재탐색하면 "없다가 생기면 살아나지만, 있다가
/// 없어지면 영원히 ENOENT만 찍는" 비대칭이 된다.
///
/// # 로그는 상태 변화에만
///
/// **같은 상태를 반복해서 알리는 로그는 정보가 아니라 소음이다.** 이 모듈이 없애려던 게 정확히
/// 그것("60초마다 WARN을 쏟는 대신 기동 시 한 번만")이라, 재탐색을 넣으면서 그 보장을 되살리는 게
/// 중요하다. 그래서 [`BinState`]로 상태를 들고, **전이할 때만** WARN/INFO를 낸다:
/// - 못 찾은 상태가 지속되는 동안 → 조용하다(`debug`).
/// - 없다가 찾았다 → `INFO` 한 번.
/// - 있다가 사라졌다 → `WARN` 한 번.
///
/// 후보를 거절하는 개별 사유(상대경로·신뢰 못 할 경로 등)도 [`resolve_docker_bin_with`] 안에서
/// `debug`다 — 매 tick 재탐색에서 다시 불리기 때문이다.
///
/// # 비용: 왜 `spawn_blocking`을 쓰지 않는가
///
/// 재탐색은 동기 FS 호출(`metadata`/`symlink_metadata`/`faccessat`, 그리고 root면 실행 경로 성분별
/// `symlink_metadata` + ACL 조회)을 런타임 스레드에서 직접 부른다. NFS/FUSE 같은 느린 FS라면
/// 이론상 런타임 스레드를 블록할 수 있다. 그래도 `spawn_blocking`으로 옮기지 않는다:
/// - **비용이 작다**: 재탐색은 **못 찾은 동안에만** 돌고(찾으면 멈춘다), 한 번에 stat 십수 회다.
///   주기는 60초다. 게다가 이 task는 어차피 매 tick 외부 프로세스를 spawn하는데(`docker system df`),
///   그 spawn 자체가 실행 파일을 읽는 FS 작업이다 — 재탐색이 더하는 몫은 그 옆에서 미미하다.
/// - **`spawn_blocking`이 공짜가 아니다**: 이 프로젝트에서 이미 겪었듯 `timeout`으로 감싸도 클로저는
///   계속 돌아, 진짜로 매달린 FS 호출은 blocking-pool 스레드를 **영구히** 묶는다. 느린 FS를 상정한
///   방어가 오히려 스레드 누수로 갚아지는 셈이라, 지금 규모에서는 손해다.
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
    let mut state = BinState::from_initial(cfg.docker_bin.clone(), cfg.configured_bin.as_deref());
    tracing::info!(
        url = %url,
        interval_secs = cfg.interval.as_secs(),
        docker_bin = ?state.path().map(|p| p.display().to_string()),
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
                let Some((bin, _announced)) = state.ensure(resolve, cfg.configured_bin.as_deref()) else {
                    continue;
                };
                match capture_docker_df(&bin, cfg.timeout).await {
                    Ok(lines) => {
                        // 캡처가 됐다 = 이 경로는 지금 멀쩡하다. 다음 장애를 새로 알릴 수 있게 기록을 지운다.
                        state.mark_ok();
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
                            // docker task는 프로세스를 수집하지 않는다 — encode_metrics는 points만
                            // 쓰므로 비워 둔다(process logs는 host metrics tick만 낸다).
                            top_processes: Vec::new(),
                            process_inventory: Vec::new(),
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
                        if is_binary_unusable(&e) {
                            // 찾아 뒀던 docker를 더는 못 쓴다(사라짐 ENOENT / 실행 불가 EACCES). 상태를
                            // 되돌려 다음 tick부터 재탐색한다 — WARN은 이 전이에서 한 번뿐이고, 못 찾는
                            // 동안은 조용하다(위 doc "로그는 상태 변화에만").
                            let _announced = state.mark_gone(&bin);
                        } else if state.mark_capture_failed() {
                            // docker는 있는데 명령이 실패했다(데몬 down/권한/timeout). 데몬 down은 흔한
                            // 정상 상태라 **이 전이에서 한 번만** WARN하고, 지속되는 동안은 아래 debug다
                            // (item 3). ENOENT(사라짐)와 달리 재탐색하지 않는다 — 실행 파일은 멀쩡하다.
                            tracing::warn!(error = %e, "docker system df 캡처 실패(데몬 down/권한/timeout) — 다음 주기까지 skip");
                        } else {
                            tracing::debug!(error = %e, "docker system df 캡처 실패 지속 — 이번 주기 skip");
                        }
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

/// docker 실행 파일의 탐색 상태. **로그를 상태 변화에만 남기기 위해** 존재한다
/// ([`serve_docker`]의 "로그는 상태 변화에만" 참고) — 상태를 안 들고 있으면 같은 사실("못 찾았다",
/// "이 경로가 계속 실패한다")을 매 tick 다시 외치게 되고, 그게 이 모듈이 없애려던 WARN 폭주다.
///
/// 두 가지를 들고 있어야 한다:
/// - `current`: 이번 tick에 쓸 실행 파일. `None`이면 재탐색해야 한다.
/// - `announced_bad`: 마지막으로 "이 경로/부재가 나쁘다"고 알린 대상. 같은 대상이 같은 이유로 계속
///   실패할 때 WARN/INFO를 반복하지 않기 위한 것이다. **왜 필요한가**: resolve는 성공하는데 exec만
///   `ENOENT`로 실패하는 경우(예: 잘못된 shebang 인터프리터)를 생각하면, 재탐색이 매번 **같은 경로**를
///   다시 찾아 `current`를 채우고 exec가 또 실패한다 — `announced_bad`가 없으면 tick마다
///   `찾음(INFO) → 사라짐(WARN)`이 진동한다. 직전에 이미 이 경로를 나쁘다고 알렸으면 조용히 넘어간다.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BinState {
    current: Option<PathBuf>,
    announced_bad: Announced,
}

/// [`BinState`]가 마지막으로 알린 나쁜 소식. `PartialEq`로 "같은 걸 또 알리려는가"를 판정한다.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Announced {
    /// 아직 아무 나쁜 소식도 알리지 않았다(정상 동작 중이거나 기동 직후).
    Nothing,
    /// "아무 데서도 docker를 못 찾는다"를 알렸다.
    Missing,
    /// 이 **특정 경로**가 실패한다(exec ENOENT/사라짐)를 알렸다.
    Bad(PathBuf),
    /// docker는 있는데 **명령이 실패한다**(데몬 down/권한/timeout — non-zero exit)를 알렸다.
    /// `Bad`와 다르다: 실행 파일은 멀쩡하므로 `current`를 비우지 않고(재탐색 무의미) 같은 경로를
    /// 계속 시도한다. docker 데몬이 꺼져 있는 건 흔한 정상 상태라, 전이에만 알리고 지속되는 동안은
    /// 조용해야 한다(매 tick WARN은 소음이다).
    CaptureFailing,
}

impl BinState {
    /// 기동 시 상태를 만든다. resolve 결과와 config 값을 함께 받아, 못 찾았으면 **여기서 딱 한 번**
    /// WARN을 낸다. config가 지정됐는데 못 찾은 경우(오타·상대경로·root 신뢰 실패, 또는 아직 미설치)는
    /// **재탐색해도 안 바뀌는 영구 오설정일 수 있으므로** config를 짚어 주는 별도 문구로 알린다 —
    /// 이 신호가 없으면 "오타를 조용히 덮지 않는다"는 원래 설계 목표가 기본 로그 레벨에서 실현되지
    /// 않는다(거절의 유일한 신호가 재탐색 경로의 `debug`뿐이라 안 보인다).
    fn from_initial(resolved: Option<PathBuf>, configured: Option<&Path>) -> Self {
        match resolved {
            Some(p) => BinState {
                current: Some(p),
                announced_bad: Announced::Nothing,
            },
            None => {
                if let Some(c) = configured {
                    tracing::warn!(
                        docker_bin = %c.display(),
                        "[aicd.exporter].docker_bin을 지금은 쓸 수 없다(없거나·상대경로거나·root 신뢰 판정 실패) \
                         — 절대경로로 지정했는지 확인할 것. 설치되면 자동으로 잡는다"
                    );
                } else {
                    tracing::warn!(
                        "docker 실행 파일을 찾지 못했다 — 설치되면 자동으로 캡처를 시작한다 \
                         ([aicd.exporter].docker_bin으로 절대경로를 지정할 수 있다)"
                    );
                }
                BinState {
                    current: None,
                    announced_bad: Announced::Missing,
                }
            }
        }
    }

    fn path(&self) -> Option<&Path> {
        self.current.as_deref()
    }

    /// 이번 tick에 쓸 실행 파일을 확보한다. 이미 있으면 그대로 쓰고, 아니면 재탐색한다.
    ///
    /// 반환값의 `bool`은 **이번 호출에서 "새로 찾았다"고 INFO를 냈는가**이다(테스트가 전이 억제를
    /// 관찰하기 위한 것 — 로그로만 드러나는 성질이라 값으로 내주지 않으면 공허해진다). INFO는
    /// **정말 새 소식일 때만** 낸다: 직전에 바로 이 경로가 나쁘다고 알린 상태(`Bad(같은 경로)`)에서
    /// 재탐색이 같은 경로를 도로 물어온 것은 새 소식이 아니므로 조용하다.
    fn ensure(
        &mut self,
        resolve: &dyn Fn(Option<&Path>) -> Option<PathBuf>,
        configured: Option<&Path>,
    ) -> Option<(PathBuf, bool)> {
        if let Some(p) = &self.current {
            return Some((p.clone(), false));
        }
        match resolve(configured) {
            Some(found) => {
                // 직전에 바로 이 경로를 나쁘다고 알렸는가? 그렇다면 도로 물어온 것은 새 정보가 아니다.
                let already_known_bad = self.announced_bad == Announced::Bad(found.clone());
                let announced = if already_known_bad {
                    tracing::debug!(
                        docker_bin = %found.display(),
                        "재탐색이 직전에 실패한 그 경로를 다시 찾음 — 조용히 재시도한다"
                    );
                    false
                } else {
                    tracing::info!(
                        docker_bin = %found.display(),
                        "docker 실행 파일을 찾았다 — docker exporter 캡처 시작"
                    );
                    // 새 경로를 찾았으니 "나쁘다"던 기록은 지운다(이 경로의 실패는 새로 알려야 한다).
                    self.announced_bad = Announced::Nothing;
                    true
                };
                self.current = Some(found.clone());
                Some((found, announced))
            }
            None => {
                // 이미 Missing이라고 알렸으면 조용히, 아니면(직전이 Bad/Nothing) 이번에 Missing 전이를
                // 알린다 — 다만 대개 사라짐 WARN을 mark_gone이 이미 냈으므로 여기서는 debug로 족하다.
                if self.announced_bad != Announced::Missing {
                    self.announced_bad = Announced::Missing;
                }
                tracing::debug!("docker 실행 파일을 아직 찾지 못했다 — 이번 주기 skip");
                None
            }
        }
    }

    /// 캡처가 성공했다 — 이 경로는 지금 멀쩡하다. "나쁘다"던 기록을 지워, **다음 번 장애는 새로
    /// 알리도록** 한다(안 지우면 P가 한 번 실패한 뒤로는 P의 어떤 장애도 영원히 억제된다). 직전에
    /// 실제 장애(`Bad`/`CaptureFailing`)를 알렸던 상태에서 회복했다면 **복구 INFO를 한 번** 낸다.
    fn mark_ok(&mut self) {
        match self.announced_bad {
            Announced::Nothing | Announced::Missing => {}
            Announced::Bad(_) | Announced::CaptureFailing => {
                tracing::info!("docker exporter 캡처가 정상으로 돌아왔다");
            }
        }
        self.announced_bad = Announced::Nothing;
    }

    /// 쓰던 실행 파일을 exec 시점에 더는 못 쓴다(`ENOENT` 사라짐 / `EACCES` 실행 불가). 재탐색하도록
    /// `current`를 비우고, **직전에 이 경로를 이미 나쁘다고 알리지 않았을 때만** WARN을 낸다.
    ///
    /// **알렸으면 `true`**를 돌려준다(테스트가 억제를 관찰하기 위함 — 상태만 보면 두 경우가 구분되지
    /// 않는다). 이 반환값 + `announced_bad` 덕에 "같은 경로가 계속 실패"해도 WARN은 한 번뿐이다.
    fn mark_gone(&mut self, bin: &Path) -> bool {
        self.current = None;
        if self.announced_bad == Announced::Bad(bin.to_path_buf()) {
            return false;
        }
        tracing::warn!(
            docker_bin = %bin.display(),
            "docker 실행 파일을 더는 쓸 수 없다(사라졌거나 실행 불가) — 다시 탐색한다(복구되면 자동으로 캡처를 재개한다)"
        );
        self.announced_bad = Announced::Bad(bin.to_path_buf());
        true
    }

    /// docker는 실행됐는데 **명령(`docker system df`)이 실패**했다(데몬 down/권한/timeout — non-zero
    /// exit, 미설치 아님). `current`는 그대로 둔다 — 실행 파일은 멀쩡하니 재탐색은 무의미하다.
    ///
    /// **처음 이 상태로 들어갈 때만 `true`**(=WARN)를 돌려주고, 지속되는 동안은 `false`(=조용히)다.
    /// docker 데몬이 꺼져 있는 건 흔한 정상 상태라, 매 tick WARN을 쏟으면 소음이다(item 3).
    fn mark_capture_failed(&mut self) -> bool {
        if self.announced_bad == Announced::CaptureFailing {
            return false;
        }
        self.announced_bad = Announced::CaptureFailing;
        true
    }
}

/// 캡처 실패가 **이 실행 파일을 더는 쓸 수 없어서**인가 — spawn이 `ENOENT`(사라짐) 또는
/// `EACCES`(실행 비트가 사라짐/권한 회수)로 실패한 경우. 둘 다 "이 경로는 끝났다"는 신호라
/// **재탐색 대상**이다: 재탐색의 [`is_executable_file`] 검사가 실행 불가가 된 경로를 자연스럽게
/// 걸러 내(다른 위치의 docker로 옮겨 가거나, 권한이 복구되면 같은 경로를 다시 잡는다). 재탐색이
/// 같은 경로를 도로 물어와도 상태 기계가 조용히 유지하므로 무한 로그는 없다.
///
/// 데몬 down(non-zero exit)/timeout/파싱 실패와는 갈라진다 — 그것들은 실행 파일이 멀쩡하므로
/// 재탐색이 무의미하고, `CaptureFailing`으로 전이-알림만 한다.
///
/// `run_capped`의 `cmd.spawn()?`가 `std::io::Error`를 그대로 anyhow에 실어 주므로 downcast로 본다.
fn is_binary_unusable(e: &anyhow::Error) -> bool {
    use std::io::ErrorKind;
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| matches!(io.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied))
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

    /// Docker Desktop **user 설치**의 `$HOME/.docker/bin/docker`도 커버해야 한다 — HOME 상대 폴백이
    /// 이제 둘(`.orbstack`, `.docker`)이니 순회가 둘 다 도는지 확인한다.
    #[test]
    fn falls_back_to_home_docker_desktop_user_path() {
        let got = resolve(
            None,
            Some(OsString::from("/usr/bin")),
            Some(Path::new("/Users/someone")),
            // .orbstack은 없고 .docker만 있다 — 순회가 첫 항목에서 멈추지 않아야 잡힌다.
            &only(&["/Users/someone/.docker/bin/docker"]),
        );
        assert_eq!(
            got,
            Some(PathBuf::from("/Users/someone/.docker/bin/docker"))
        );
    }

    /// **root/비-root 대칭**: `$HOME/.docker/bin`은 사용자 쓰기 가능이라, root aicd일 땐 walk(신뢰
    /// 판정)가 거부하고 비-root에선 채택해야 한다 — 이 폴백 추가가 root 거부를 실제로 타는지 못박는다.
    #[test]
    fn home_docker_desktop_path_is_rejected_as_root_but_accepted_as_non_root() {
        let home = Path::new("/Users/victim");
        let cand = "/Users/victim/.docker/bin/docker";

        // 비-root: 신뢰 판정 없이 채택.
        let as_non_root = resolve(None, None, Some(home), &only(&[cand]));
        assert_eq!(as_non_root, Some(PathBuf::from(cand)));

        // root: 사용자 쓰기 가능이라 신뢰 밖 → 거부.
        let as_root = resolve_as(
            None,
            None,
            Some(home),
            true,
            &only(&[cand]),
            &trusted(&[]), // 이 경로는 root 통제 밖.
        );
        assert_eq!(
            as_root, None,
            "root인데 사용자 쓰기 가능한 $HOME/.docker/bin의 docker를 채택했다"
        );
    }

    /// **실측(주입 아님)**: 사용자 쓰기 가능한 `$HOME/.docker/bin/docker` 형태가 **진짜**
    /// `is_root_controlled_path`(root일 때만 호출되는 그 가드)에서 거부되는지 확인한다. 위 두 테스트는
    /// 신뢰 판정을 주입하지만, 이건 실제 판정을 실제 FS 구조에 돌려 "root 거부를 정말 탄다"를 못박는다.
    /// `bin`을 0777로 둬 base 소유와 무관하게 거부되게 한다(root 머신에서도 유효).
    #[test]
    fn a_user_writable_home_docker_path_is_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(tmp.path()).unwrap();
        let bin = home.join(".docker").join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let docker = bin.join("docker");
        std::fs::write(&docker, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        // 사용자 쓰기 가능 시뮬레이트: 이 성분 하나만으로도 walk가 거부해야 한다(base 소유 무관).
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o777)).unwrap();

        assert!(
            !is_root_controlled_path(&docker),
            "사용자 쓰기 가능한 $HOME/.docker/bin의 docker가 root 신뢰 판정을 통과했다"
        );
    }

    /// Linux 배포판 패키지 위치(`/usr/bin/docker`)도 커버해야 한다.
    #[test]
    fn finds_the_linux_distro_package_path() {
        let got = resolve(None, None, None, &only(&["/usr/bin/docker"]));
        assert_eq!(got, Some(PathBuf::from("/usr/bin/docker")));
    }

    /// docker가 아예 없으면 `None` — 호출부(`serve_docker`)는 task를 유지한 채 매 tick 재탐색하고,
    /// WARN은 기동 시 1회만 낸다("지금은 없다"이지 "비활성"이 아니다 — `resolve_docker_bin` doc 참고).
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
        assert!(
            is_root_controlled_meta(0, 0o755, false),
            "root:root 0755 — 정상"
        );
        assert!(is_root_controlled_meta(0, 0o700, false), "root 전용 — 정상");

        assert!(
            !is_root_controlled_meta(0, 0o775, false),
            "root 소유라도 group 쓰기 가능하면 안 된다 — macOS /usr/local/bin이 정확히 이거다"
        );
        assert!(
            !is_root_controlled_meta(0, 0o777, false),
            "other 쓰기 가능하면 안 된다"
        );
        assert!(
            !is_root_controlled_meta(501, 0o755, false),
            "사용자 소유면 mode가 아무리 빡빡해도 안 된다"
        );
        assert!(
            !is_root_controlled_meta(501, 0o700, false),
            "사용자 소유 — 안 된다"
        );
    }

    /// **fail-open 회귀 가드**: mode 비트가 완벽해 보여도(`0o755 root:wheel`) 확장 ACL로 쓰기 권한이
    /// 붙어 있으면 신뢰하면 안 된다. macOS의 확장 ACL은 mode에 **전혀 드러나지 않는다** —
    /// canonicalize로 막은 것과 같은 종류의 우회(겉보기 root 소유, 실제로는 사용자 쓰기 가능)다.
    #[test]
    fn is_root_controlled_meta_rejects_a_path_with_an_extended_acl() {
        assert!(
            !is_root_controlled_meta(0, 0o755, true),
            "mode가 깨끗해도 확장 ACL이 있으면 신뢰하면 안 된다 — 방어가 fail-open이 된다"
        );
        assert!(
            !is_root_controlled_meta(0, 0o700, true),
            "root 전용 mode라도 ACL이 있으면 안 된다"
        );
    }

    /// 경로 walk 쪽(FS를 실제로 만지는 부분)의 결정적 케이스: 없는 경로는 신뢰하지 않는다.
    /// (소유권 긍정 케이스는 root 소유 디렉토리 체인이 필요해 비-root 테스트로는 못 만든다 — 그래서
    /// 소유권 판정은 순수 함수로, **"어느 성분을 검사하는가"**는 아래 주입점으로 나눠 검증한다.)
    #[test]
    fn is_root_controlled_path_rejects_a_missing_path() {
        assert!(!is_root_controlled_path(Path::new(
            "/definitely/does/not/exist/docker"
        )));
    }

    /// **회귀 가드 — item 1(블로킹).** 예전 판은 `canonicalize(cand)`의 성분만 검사해서, 정작
    /// 실행되는 **링크 경로**가 놓인 디렉토리를 아무도 안 봤다. 사용자 쓰기 가능 디렉토리에 놓인
    /// 링크가 (그 자체로는 안전해 보이는) 대상을 가리키면, 공격자가 링크를 스왑해 root aicd에게
    /// 임의 바이너리를 실행시킬 수 있다.
    ///
    /// FS 구조(링크·디렉토리)는 tempdir에 실제로 만들어 traversal이 진짜로 돌게 하고, 소유권 판정만
    /// 주입한다("unsafe 디렉토리만 신뢰 안 함"). walk가 링크의 **부모 디렉토리**를 검사 대상에 넣으면
    /// 거부되고, 빠뜨리면(=예전 버그) 대상까지 따라가 통과한다 — 그 차이를 잡는다.
    #[test]
    fn is_root_controlled_walk_checks_the_directory_that_holds_the_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        // canonicalize로 /var -> /private/var 류의 링크를 미리 해소해 둔다(경로 동일성 안정화).
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        let safe = root.join("safe");
        let unsafe_dir = root.join("unsafe");
        std::fs::create_dir(&safe).unwrap();
        std::fs::create_dir(&unsafe_dir).unwrap();

        // 대상 파일은 "안전한" safe/ 안에 둔다.
        let target = safe.join("docker-real");
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 실행되는 경로: unsafe/docker -> (절대경로) safe/docker-real. 절대 대상을 쓴다 — 이 테스트의
        // 관심은 "링크 디렉토리를 검사하는가"이고, 상대 대상 해소는 아래 relative 테스트가 따로 본다.
        let link = unsafe_dir.join("docker");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // 주입 판정: unsafe 디렉토리 하나만 신뢰 밖, 나머지(루트~safe, 대상 파일)는 전부 신뢰.
        let unsafe_canon = unsafe_dir.clone();
        let trusted = move |p: &Path| p != unsafe_canon.as_path();

        assert!(
            !is_root_controlled_walk(&link, 0, &trusted),
            "링크가 놓인 사용자 쓰기 가능 디렉토리를 검사하지 않았다 — 스왑 하이재킹이 뚫린다"
        );

        // 대조(공허 방지): unsafe까지 신뢰하면 링크를 따라가 대상을 채택한다 — walk가 실제로 링크를
        // 해소해 끝까지 도달함을 증명한다(위 거부가 "walk가 그냥 다 막아서"가 아님).
        let all_trusted = |_: &Path| true;
        assert!(
            is_root_controlled_walk(&link, 0, &all_trusted),
            "전부 신뢰인데 거부했다 — walk가 링크를 못 따라가거나 과잉 거부한다"
        );
    }

    /// **배선 가드 — item 1.** 위 주입 테스트는 `is_root_controlled_walk`를 직접 부르므로, 프로덕션
    /// 진입점 `is_root_controlled_path`가 그 walk로 배선돼 있는지(예전 canonicalize 방식으로
    /// 되돌아가지 않았는지)는 확인하지 못한다. 그 차이를 잡는다:
    /// - walk: 실행 경로(`tempdir/.../docker`) 성분 중 **비-root 통제 디렉토리**(tempdir 자체가 사용자
    ///   소유이거나, root면 0777 `unsafe`)를 만나 **거부**.
    /// - canonicalize(예전 버그): 링크의 **대상**과 그 상위만 보는데, 대상을 **시스템 실행 파일**
    ///   (`/bin/true` 등, root 소유)로 두면 그 상위(`/bin`, `/`)가 전부 root라 **통과**한다.
    ///
    /// **핵심 — base 무관**: 대상을 tempdir 안이 아니라 **시스템 경로**로 두는 게 이 판의 요점이다.
    /// canonicalize가 tempdir을 벗어나 시스템 경로로 해소되므로, 판별력이 `/tmp`(또는 `TMPDIR`)의
    /// 소유·권한에 **의존하지 않는다**. 예전 판은 대상을 tempdir 안에 둬서, base가 root 통제가 아니면
    /// canonicalize도 거부해 walk와 구분이 흐려졌다(패널 지적).
    ///
    /// 그래서 root도 필요 없다 — 비-root에선 walk가 사용자 소유 tempdir base에서 거부하고,
    /// canonicalize는 시스템 대상을 통과시키므로, 어느 권한에서든 둘이 갈린다. 시스템에 root 통제 하의
    /// 실행 파일이 없으면(비정상 환경) 판별 전제가 없으니 skip한다.
    ///
    /// **순환 전제 금지(패널 지적)**: 전제("시스템 대상이 root 통제 하")를 **검증 대상 함수로 고르면**
    /// (`find(is_root_controlled_path)`), 그 함수가 `return false`로 망가질 때 전제 선택도 같이 눈이 멀어
    /// 테스트가 실패가 아니라 **skip으로 도망친다**(실측으로 확인함). 그래서 전제는 **독립적인 직접
    /// stat**([`independently_root_controlled`])으로 세우고, 나아가 **양방향으로** 단언한다:
    /// - **positive**: 시스템 대상 자신은 root 통제 하이므로 `is_root_controlled_path`가 **채택**해야 한다
    ///   → `return false`(전면 거부, exporter 사망) 회귀를 잡는다.
    /// - **negative**: 사용자 쓰기 가능 경로의 링크는 **거부**해야 한다 → `return true`(전면 채택)와
    ///   canonicalize-revert(대상만 보기) 회귀를 잡는다.
    #[test]
    fn is_root_controlled_path_rejects_a_link_in_a_writable_dir_even_when_target_is_root_safe() {
        // 전제 확립은 **검증 대상과 독립적인** 직접 stat으로 한다(순환 금지).
        let sys_target = ["/bin/true", "/usr/bin/true", "/bin/sh", "/usr/bin/env"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| independently_root_controlled(p));
        let Some(sys_target) = sys_target else {
            eprintln!("skip: (독립 stat 기준) root 통제 하의 시스템 실행 파일을 찾지 못함");
            return;
        };

        // positive: root 통제 하 시스템 대상은 채택되어야 한다 — `return false` 회귀를 여기서 잡는다.
        assert!(
            is_root_controlled_path(&sys_target),
            "root 통제 하 시스템 실행 파일({})을 거부했다 — 전면 거부 회귀(exporter 사망)",
            sys_target.display()
        );

        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();

        // 사용자 쓰기 가능 링크 디렉토리(root로 돌 때도 0777이라 root 통제 밖). 비-root면 base 자체가
        // 사용자 소유라 walk는 거기서 이미 거부한다 — 어느 쪽이든 walk는 실행 경로에서 막는다.
        let unsafe_dir = base.join("unsafe");
        std::fs::create_dir(&unsafe_dir).unwrap();
        std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let link = unsafe_dir.join("docker");
        std::os::unix::fs::symlink(&sys_target, &link).unwrap();

        // negative: 실행 경로는 tempdir 안의 link이므로 walk는 사용자 쓰기 가능 성분을 보고 거부해야
        // 한다. canonicalize로 되돌아가면 대상(시스템 root 실행 파일)의 상위만 봐 통과해 버린다.
        assert!(
            !is_root_controlled_path(&link),
            "is_root_controlled_path가 링크 경로 성분을 안 봤다 — canonicalize 방식으로 되돌아갔다(스왑 하이재킹)"
        );
    }

    /// [`is_root_controlled_path`]와 **독립적인** root-통제 판정(직접 stat). 회귀 가드 테스트가 자기
    /// 검증 대상으로 전제를 고르는 순환을 피하려고 쓴다 — canonicalize된 경로와 모든 상위가 root
    /// 소유(`uid==0`)이고 non-root 쓰기 불가(`mode & 0o022 == 0`)인지 본다. 시스템 경로엔 확장 ACL이
    /// 없으므로 여기선 ACL을 보지 않는다(전제 확립용 최소 판정).
    fn independently_root_controlled(p: &Path) -> bool {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Ok(real) = std::fs::canonicalize(p) else {
            return false;
        };
        let mut cur: Option<&Path> = Some(real.as_path());
        while let Some(c) = cur {
            let Ok(md) = std::fs::symlink_metadata(c) else {
                return false;
            };
            if md.uid() != 0 || md.permissions().mode() & 0o022 != 0 {
                return false;
            }
            cur = c.parent();
        }
        true
    }

    /// walk는 **실행 파일(경로의 끝)**에 도달해야 한다 — 디렉토리로 끝나면 거부한다.
    #[test]
    fn is_root_controlled_walk_rejects_a_directory_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let d = root.join("adir");
        std::fs::create_dir(&d).unwrap();
        let all_trusted = |_: &Path| true;
        assert!(
            !is_root_controlled_walk(&d, 0, &all_trusted),
            "디렉토리는 실행 파일이 아니다"
        );
    }

    /// **회귀 가드 — 최종 실행 파일 자신도 검사한다.** 부모 디렉토리가 전부 root 통제여도 **파일이
    /// 0777이면** 사용자가 내용을 갈아치울 수 있다(디렉토리 무결성과 별개). 예전엔 이 검사를 깨는
    /// mutation이 어떤 테스트도 안 깨뜨렸다(공허) — 파일 성분만 신뢰 밖으로 두고 거부되는지 본다.
    #[test]
    fn is_root_controlled_walk_checks_the_executable_file_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let f = root.join("docker");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 부모(루트~root)는 전부 신뢰, **파일 자신만** 신뢰 밖(예: 0777 실행 파일).
        let fp = f.clone();
        let untrusted_file = move |p: &Path| p != fp.as_path();
        assert!(
            !is_root_controlled_walk(&f, 0, &untrusted_file),
            "실행 파일 자신이 신뢰 밖(사용자 쓰기 가능)인데 통과 — 파일 성분 검사가 빠졌다"
        );

        // 대조(공허 방지): 파일까지 신뢰하면 통과 — walk가 끝까지 도달함을 증명.
        let all_trusted = |_: &Path| true;
        assert!(is_root_controlled_walk(&f, 0, &all_trusted));
    }

    // ── fail-closed 형제 분기들 (item 3): 각 거부를 fail-open으로 뒤집는 mutation이 잡히도록 ──
    //
    // "파일 성분 검사가 공허했다"를 실측으로 배운 뒤, 나머지 fail-closed 분기(중간 성분이 정규 파일/
    // 비정규 파일/심링크 depth 초과)도 같은 눈으로 각각 mutation으로 검증한다.

    /// **회귀 가드**: 디렉토리여야 할 중간 성분이 **정규 파일**이면 거부한다(경로가 잘못됐다).
    /// 이 거부(`is_file && !is_last -> return false`)를 빼면 그 파일에서 `trusted`를 반환해 조기 통과
    /// 하므로(all_trusted 하에) 이 테스트가 잡는다.
    #[test]
    fn is_root_controlled_walk_rejects_a_regular_file_mid_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let midfile = root.join("notadir");
        std::fs::write(&midfile, b"x").unwrap();
        // 디렉토리가 와야 할 자리에 파일이 있다: root/notadir/docker
        let path = midfile.join("docker");
        let all_trusted = |_: &Path| true;
        assert!(
            !is_root_controlled_walk(&path, 0, &all_trusted),
            "중간 성분이 정규 파일인데 통과 — 잘못된 경로를 받아들였다"
        );
    }

    /// **회귀 가드**: 최종 성분이 **비정규 파일**(소켓 등 — 디렉토리도 정규 파일도 심링크도 아님)이면
    /// 거부한다. 이 `else -> return false` 분기를 fail-open으로 바꾸면 소켓을 실행 파일로 오인한다.
    #[test]
    fn is_root_controlled_walk_rejects_a_non_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let sock_path = root.join("docker");
        // UnixListener::bind가 소켓 파일을 만든다(mknod 권한 없이도 됨).
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        assert!(
            sock_path.exists() && !sock_path.is_file() && !sock_path.is_dir(),
            "전제: 소켓은 정규 파일도 디렉토리도 아니다"
        );
        let all_trusted = |_: &Path| true;
        assert!(
            !is_root_controlled_walk(&sock_path, 0, &all_trusted),
            "비정규 파일(소켓)을 실행 파일로 받아들였다"
        );
    }

    /// **회귀 가드**: 심링크 체인이 `MAX_SYMLINK_DEPTH`(40)를 넘으면 거부한다(ELOOP 방어). depth
    /// 상한을 없애거나 크게 키우는 mutation은 이 41+단계 체인에서 잡힌다.
    #[test]
    fn is_root_controlled_walk_rejects_a_too_deep_symlink_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // 실제 파일 + link_0 -> link_1 -> ... -> link_44 -> real. 45단계라 depth 40을 확실히 넘는다.
        let real = root.join("real");
        std::fs::write(&real, b"x").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut prev = real.clone();
        for i in 0..45u32 {
            let link = root.join(format!("link_{i}"));
            std::os::unix::fs::symlink(&prev, &link).unwrap();
            prev = link;
        }
        // prev = link_44 (체인의 머리). walk가 45번 따라가면 depth가 40을 넘어 거부해야 한다.
        let all_trusted = |_: &Path| true;
        assert!(
            !is_root_controlled_walk(&prev, 0, &all_trusted),
            "심링크 체인이 depth 상한을 넘었는데 통과 — ELOOP 방어가 없다"
        );

        // 대조(공허 방지): 짧은 체인(상한 이내)은 통과 — 상한 자체가 정상 링크를 막지 않음을 확인.
        let short = root.join("short_link");
        std::os::unix::fs::symlink(&real, &short).unwrap();
        assert!(is_root_controlled_walk(&short, 0, &all_trusted));
    }

    /// `..`는 거부가 아니라 **접는다**(부모로 올라감). 링크 없는 실경로에서의 `..` 폴딩은 커널 해소와
    /// 같다 — `root/sub/../docker`는 `root/docker`로 접혀 통과해야 한다.
    #[test]
    fn is_root_controlled_walk_folds_dot_dot_instead_of_rejecting() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        let f = root.join("docker");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let all_trusted = |_: &Path| true;

        let with_dotdot = root.join("sub").join("..").join("docker");
        assert!(
            is_root_controlled_walk(&with_dotdot, 0, &all_trusted),
            "root/sub/../docker는 root/docker로 접혀 통과해야 한다 — `..`를 거부하면 상대 링크가 깨진다"
        );
    }

    /// **회귀 가드 — item 1(블로킹): Homebrew 상대 링크.** Homebrew는
    /// `.../bin/docker -> ../Cellar/docker/<ver>/bin/docker`처럼 **상대 링크**를 쓴다. 예전 walk는
    /// `..`를 fail-closed로 거부해 이 정상 설치의 exporter를 조용히 비활성시켰다. 이제는 링크가 놓인
    /// 디렉토리 기준으로 해소해, 각 성분이 root 통제 하면 통과해야 한다.
    ///
    /// 소유권은 주입한다("전부 신뢰"). 링크와 디렉토리는 tempdir에 실제 상대 링크로 만들어 해소가
    /// 진짜로 돈다.
    #[test]
    fn is_root_controlled_walk_resolves_a_relative_homebrew_style_link() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Homebrew 레이아웃: root/bin/docker -> ../Cellar/docker/1.0/bin/docker
        let bindir = root.join("bin");
        std::fs::create_dir(&bindir).unwrap();
        let cellar_bin = root.join("Cellar").join("docker").join("1.0").join("bin");
        std::fs::create_dir_all(&cellar_bin).unwrap();
        let target = cellar_bin.join("docker");
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

        let link = bindir.join("docker");
        std::os::unix::fs::symlink("../Cellar/docker/1.0/bin/docker", &link).unwrap();

        let all_trusted = |_: &Path| true;
        assert!(
            is_root_controlled_walk(&link, 0, &all_trusted),
            "상대 링크가 전부 root 통제 하인데 거부됐다 — Homebrew 정상 설치가 깨진다"
        );
    }

    /// 상대 링크라도 **지나는 디렉토리 하나라도 신뢰 밖이면 거부**한다 — 링크가 놓인 디렉토리 쪽이든
    /// (item 1의 핵심), 대상 쪽 중간 디렉토리든 둘 다.
    #[test]
    fn is_root_controlled_walk_rejects_a_relative_link_through_an_untrusted_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let bindir = root.join("bin");
        std::fs::create_dir(&bindir).unwrap();
        let cellar_mid = root.join("Cellar").join("docker");
        let cellar_bin = cellar_mid.join("1.0").join("bin");
        std::fs::create_dir_all(&cellar_bin).unwrap();
        let target = cellar_bin.join("docker");
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = bindir.join("docker");
        std::os::unix::fs::symlink("../Cellar/docker/1.0/bin/docker", &link).unwrap();

        // (a) 링크가 놓인 디렉토리가 신뢰 밖 — 스왑 하이재킹 경로.
        let bd = bindir.clone();
        let untrusted_linkdir = move |p: &Path| p != bd.as_path();
        assert!(
            !is_root_controlled_walk(&link, 0, &untrusted_linkdir),
            "상대 링크가 놓인 사용자 쓰기 가능 디렉토리를 통과시켰다"
        );

        // (b) 대상 쪽 중간 디렉토리가 신뢰 밖.
        let cm = cellar_mid.clone();
        let untrusted_target_mid = move |p: &Path| p != cm.as_path();
        assert!(
            !is_root_controlled_walk(&link, 0, &untrusted_target_mid),
            "상대 링크 대상 경로의 사용자 쓰기 가능 중간 디렉토리를 통과시켰다"
        );
    }

    /// ACL이 없는 평범한 파일에는 `has_extended_acl`이 false여야 한다 — 여기서 true가 나오면 정상적인
    /// 시스템 경로(`/usr/bin`, `/`)를 전부 거부해 root aicd가 docker를 영영 못 쓴다(과잉 거부).
    ///
    /// **macOS/Linux 전용**: 그 밖의 unix에선 `has_extended_acl`이 fail-closed로 `true`를 반환하는 게
    /// **옳은 정책**이라("모르면 신뢰 안 함") plain file도 `true`가 정답이다 — false를 기대하는 이
    /// 테스트는 그 플랫폼에서 의미가 없다. 프로덕션 fallback과 같은 지원 정책으로 gate한다.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn has_extended_acl_is_false_for_a_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("plain");
        std::fs::write(&f, b"x").unwrap();
        assert!(
            !has_extended_acl(&f),
            "ACL을 걸지 않은 파일을 ACL 있음으로 봤다 — 정상 경로를 전부 거부하게 된다"
        );
    }

    /// **탐지 자체**를 못박는다: 실제로 확장 ACL을 건 파일을 `has_extended_acl`이 잡아야 한다.
    ///
    /// ACL을 담지 못하는 파일시스템이라면 ACL로 하이재킹할 수도 없으므로 탐지할 대상 자체가 없다 —
    /// 그때도 조용히 넘어가지 않고 "ACL 없음"을 단언한다.
    ///
    /// **item 4 — 이 테스트가 조용히 공허해지는 걸 막는다**: 예전엔 손으로 만든 xattr blob이 잘못돼
    /// `EINVAL`이 나도 "이 FS는 ACL 미지원"으로 처리해 테스트가 통과했다. 이제 [`acl_unsupported`]는
    /// **오직 `ENOTSUP`(=진짜 미지원)만** 미지원으로 치므로, blob이 틀리면(`EINVAL`) 아래 `panic`
    /// 가지로 떨어져 시끄럽게 실패한다. set이 `Ok`라는 것 자체가 커널이 blob을 유효한 ACL로 받아
    /// 저장했다는 뜻이고(malformed면 커널이 SET에서 EINVAL), 그 위에서 탐지를 시험하므로 순환이 없다.
    ///
    /// **지원 정책 일관성**: 이 테스트와 그 헬퍼(`set_extended_acl_for_test`)는 ACL을 실제로 거는
    /// 방법이 OS별이라 macOS/Linux에만 있다. 프로덕션 `has_extended_acl`이 그 밖의 unix를 fail-closed
    /// 폴백으로 처리해 **컴파일은 되는** 것과 맞춰, 이 테스트도 지원 대상에서만 컴파일되게 gate한다
    /// (다른 unix에서 테스트 바이너리가 깨지지 않는다). 분류 정책(ACL 있으면 신뢰 안 함)은
    /// `is_root_controlled_meta_rejects_a_path_with_an_extended_acl`가 어느 플랫폼에서든 못박는다.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn has_extended_acl_detects_a_real_extended_acl() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("acl-target");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!has_extended_acl(&f), "전제: 아직 ACL이 없다");

        match set_extended_acl_for_test(&f) {
            Ok(()) => assert!(
                has_extended_acl(&f),
                "확장 ACL을 실제로 걸었는데 탐지하지 못했다 — 가드가 fail-open이다"
            ),
            Err(e) if acl_unsupported(&e) => {
                assert!(
                    !has_extended_acl(&f),
                    "ACL을 담지 못하는 FS인데 ACL이 있다고 답했다"
                );
            }
            Err(e) => panic!(
                "ACL 설정이 예상 밖의 이유로 실패했다(blob 오류일 수 있다 — 조용히 넘기지 않는다): {e}"
            ),
        }
    }

    /// 이 파일시스템이 ACL을 담지 못한다는 **진짜** 신호(`ENOTSUP`)인가. `EINVAL`(blob 오류)이나
    /// `EPERM`(권한)은 여기 포함하지 않는다 — 그것들을 "미지원"으로 흡수하면 테스트 버그가 조용히
    /// 통과한다(item 4). `EOPNOTSUPP`는 Linux에서 `ENOTSUP`과 같은 값이다.
    fn acl_unsupported(e: &std::io::Error) -> bool {
        e.raw_os_error() == Some(libc::ENOTSUP)
    }

    /// **item 4 회귀 가드(순수·크로스플랫폼).** `acl_unsupported`가 `EINVAL`/`EPERM`을 "미지원"으로
    /// 흡수하면, `has_extended_acl_detects_a_real_extended_acl`이 malformed blob(→EINVAL)에서도 조용히
    /// skip돼 공허해진다. 분류 자체를 여기서 못박아, 흡수하는 mutation을 잡는다.
    #[test]
    fn acl_unsupported_accepts_only_enotsup_not_blob_or_perm_errors() {
        use std::io::Error;
        assert!(acl_unsupported(&Error::from_raw_os_error(libc::ENOTSUP)));
        assert!(
            !acl_unsupported(&Error::from_raw_os_error(libc::EINVAL)),
            "blob 오류(EINVAL)를 '미지원'으로 흡수하면 테스트가 조용히 공허해진다"
        );
        assert!(
            !acl_unsupported(&Error::from_raw_os_error(libc::EPERM)),
            "권한 오류(EPERM)도 '미지원'이 아니다"
        );
    }

    /// 테스트용으로 파일에 **확장 ACL**을 건다. 외부 CLI(`setfacl`)에 의존하지 않는다 — 없는 CI가
    /// 있어서다. POSIX ACL xattr(`system.posix_acl_access`)을 직접 쓴다: 헤더(version=2) 뒤에
    /// `{u16 tag, u16 perm, u32 id}` 엔트리들이 온다. 명명된 USER 엔트리를 넣으려면 MASK도 있어야
    /// 커널이 받아 준다.
    #[cfg(target_os = "linux")]
    fn set_extended_acl_for_test(p: &Path) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt;

        const ACL_USER_OBJ: u16 = 0x01;
        const ACL_USER: u16 = 0x02;
        const ACL_GROUP_OBJ: u16 = 0x04;
        const ACL_MASK: u16 = 0x10;
        const ACL_OTHER: u16 = 0x20;
        const UNDEFINED_ID: u32 = 0xffff_ffff;

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&2u32.to_ne_bytes()); // POSIX_ACL_XATTR_VERSION
        let entry = |blob: &mut Vec<u8>, tag: u16, perm: u16, id: u32| {
            blob.extend_from_slice(&tag.to_ne_bytes());
            blob.extend_from_slice(&perm.to_ne_bytes());
            blob.extend_from_slice(&id.to_ne_bytes());
        };
        entry(&mut blob, ACL_USER_OBJ, 7, UNDEFINED_ID);
        // 명명된 사용자에게 쓰기 부여 — 이 엔트리가 ACL을 "확장"으로 만든다.
        entry(&mut blob, ACL_USER, 2, 12345);
        entry(&mut blob, ACL_GROUP_OBJ, 5, UNDEFINED_ID);
        entry(&mut blob, ACL_MASK, 7, UNDEFINED_ID);
        entry(&mut blob, ACL_OTHER, 5, UNDEFINED_ID);

        let c_path = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        let name = b"system.posix_acl_access\0";
        // SAFETY: 경로/이름은 살아 있는 NUL 종료 C 문자열이고, blob은 len 바이트만큼 유효하다.
        let rc = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                name.as_ptr() as *const libc::c_char,
                blob.as_ptr() as *const libc::c_void,
                blob.len(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// macOS: `chmod +a`로 확장 ACL을 건다. `chmod`는 base OS라 항상 있고 APFS/HFS+는 ACL을
    /// 지원하므로, 이 경로는 개발기·CI 양쪽에서 실제로 돈다(스킵되지 않는다).
    #[cfg(target_os = "macos")]
    fn set_extended_acl_for_test(p: &Path) -> std::io::Result<()> {
        // chmod는 숫자 uid를 UUID로 번역하지 못한다("Unable to translate '501' to a UUID") — 이름이
        // 필요하다.
        let who = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()?;
        if !who.status.success() {
            return Err(std::io::Error::other("id -un 실패"));
        }
        let user = String::from_utf8_lossy(&who.stdout).trim().to_string();

        let out = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(format!("user:{user} allow write"))
            .arg(p)
            .output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "chmod +a 실패: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
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

        // 재탐색기를 고정한다 — 진짜 resolve를 쓰면 "이 머신에 docker가 깔려 있나"에 결과가 끌려간다
        // (실행 파일이 사라지면 재탐색이 돌므로, 개발기에선 진짜 docker를 찾아 캡처에 성공해 버린다).
        let missing = std::path::PathBuf::from("/definitely/does/not/exist/docker");
        let resolver = move |_: Option<&Path>| -> Option<PathBuf> { Some(missing.clone()) };

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { serve_docker_with(cfg, rx, &resolver).await });
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

    // ── BinState: 로그는 상태 변화에만 ────────────────────────────────────────

    fn missing() -> BinState {
        BinState {
            current: None,
            announced_bad: Announced::Missing,
        }
    }
    fn found(p: &str) -> BinState {
        BinState {
            current: Some(PathBuf::from(p)),
            announced_bad: Announced::Nothing,
        }
    }

    // ── 로그 캡처 (병렬-안전) ─────────────────────────────────────────────────
    //
    // **왜 `with_default`가 아니라 영구 전역 구독자인가**: tracing의 callsite interest 캐시는 프로세스
    // 전역 원자값이다. `with_default`(스레드-로컬 구독자)로 캡처하면, 캡처 밖의 기본 구독자가
    // `NoSubscriber`(interest=never)라, 어떤 callsite가 캡처 밖에서 처음 등록되면 "never"로 캐시돼
    // 이후 캡처 안에서의 emit까지 통째로 억제된다 → WARN이 간헐적으로 0으로 잡히는 flaky(실측: 풀 모듈
    // 병렬에서 4/10 실패). 락으로 직렬화해도 캐시가 캡처 밖에서 오염되므로 안 낫는다.
    //
    // 해법: **영구 전역 구독자를 한 번 설치**한다. 그러면 callsite는 항상 이 구독자 아래 등록돼
    // "sometimes"로 캐시되고(never로 굳지 않음), 매 이벤트마다 `enabled`가 호출된다. 실제 수집은
    // **스레드-로컬 sink**로 라우팅한다 — 캡처 중인 테스트는 자기 스레드 sink를 켜고, 병렬 테스트는
    // 각자 자기 스레드 sink(또는 없음)라 서로 섞이지 않는다. 통합 테스트의 serve 루프는 current-thread
    // 런타임의 block_on 스레드(=테스트 스레드)에서 폴링되므로 같은 sink에 잡힌다.

    thread_local! {
        static CAPTURE_SINK: std::cell::RefCell<Option<Vec<(tracing::Level, String)>>> =
            const { std::cell::RefCell::new(None) };
    }

    struct GlobalCapture;
    impl tracing::Subscriber for GlobalCapture {
        fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
            // "sometimes" — callsite를 never로 굳히지 않고 매번 enabled()를 부르게 한다.
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(&self, md: &tracing::Metadata<'_>) -> bool {
            // 이 crate 이벤트만(reqwest/hyper/tokio 노이즈 제외), 그리고 sink가 켜져 있을 때만.
            md.target().starts_with("aic_server") && CAPTURE_SINK.with(|s| s.borrow().is_some())
        }
        fn event(&self, event: &tracing::Event<'_>) {
            CAPTURE_SINK.with(|s| {
                if let Some(v) = s.borrow_mut().as_mut() {
                    struct MsgVisitor(String);
                    impl tracing::field::Visit for MsgVisitor {
                        fn record_debug(
                            &mut self,
                            field: &tracing::field::Field,
                            value: &dyn std::fmt::Debug,
                        ) {
                            if field.name() == "message" {
                                self.0 = format!("{value:?}");
                            }
                        }
                    }
                    let mut mv = MsgVisitor(String::new());
                    event.record(&mut mv);
                    v.push((*event.metadata().level(), mv.0));
                }
            });
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn install_global_capture() {
        use std::sync::OnceLock;
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            // **실패를 삼키지 않는다.** 전역 구독자는 프로세스당 한 번만 설치되고, 이 `OnceLock`이
            // 그 유일한 설치 지점이다 — 그러니 정상적으로는 반드시 성공한다. 만약 이 crate의 다른
            // 코드가 먼저 전역 구독자를 설치했다면 여기서 실패하는데, 그걸 무시하면 **로그 캡처가
            // "누가 먼저 돌았나"에 의존**하게 된다(순서/스케줄 의존 = 이번 라운드가 없애려던 flaky의
            // 동종). `expect`로 그 위반을 **모든 실행에서 결정적으로** 드러낸다 — 통계로 넘어가는 게
            // 아니라 구조로 못박는다. (실측: 이 바이너리엔 다른 전역 구독자가 없어 항상 성공한다.)
            tracing::subscriber::set_global_default(GlobalCapture).expect(
                "전역 캡처 구독자 설치 실패 — 다른 곳에서 이미 전역 tracing 구독자를 세웠다",
            );
        });
    }

    /// 클로저를 도는 동안 이 스레드에서 방출된 `(레벨, message)`를 수집한다. 병렬 테스트와 섞이지
    /// 않는다(스레드-로컬 sink). 위 "로그 캡처" 주석 참고.
    fn capture_events<F: FnOnce()>(f: F) -> Vec<(tracing::Level, String)> {
        install_global_capture();
        CAPTURE_SINK.with(|s| *s.borrow_mut() = Some(Vec::new()));
        // sink는 panic 시에도 반드시 비운다(다음 테스트에 새지 않게).
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                CAPTURE_SINK.with(|s| *s.borrow_mut() = None);
            }
        }
        let _clear = Clear;
        f();
        CAPTURE_SINK.with(|s| s.borrow_mut().take().unwrap_or_default())
    }

    /// [`capture_events`]의 레벨만 보는 버전.
    fn capture_levels<F: FnOnce()>(f: F) -> Vec<tracing::Level> {
        capture_events(f).into_iter().map(|(l, _)| l).collect()
    }

    fn count(levels: &[tracing::Level], want: tracing::Level) -> usize {
        levels.iter().filter(|l| **l == want).count()
    }

    fn count_msg(events: &[(tracing::Level, String)], lvl: tracing::Level, needle: &str) -> usize {
        events
            .iter()
            .filter(|(l, m)| *l == lvl && m.contains(needle))
            .count()
    }

    /// **회귀 가드 — item 1: 로그 캡처가 순서/스레드에 무관하다.** 전역 구독자 + 스레드-로컬 sink
    /// 구조가 "누가 먼저 돌았나"에 의존하지 않음을 못박는다. idempotent 설치(순차 두 번), 캡처 간
    /// 격리(첫 캡처가 둘째로 안 샘), 스레드 격리(새 스레드에서도 자기 sink만), 누수 없음(캡처 밖
    /// 로그는 어느 sink에도 안 들어감)을 모두 확인한다.
    #[test]
    fn capture_is_order_and_thread_independent() {
        let e1 = capture_events(|| tracing::warn!("aic-cap-marker-one"));
        assert_eq!(
            count_msg(&e1, tracing::Level::WARN, "aic-cap-marker-one"),
            1
        );

        let e2 = capture_events(|| tracing::warn!("aic-cap-marker-two"));
        assert_eq!(
            count_msg(&e2, tracing::Level::WARN, "aic-cap-marker-two"),
            1
        );
        assert_eq!(
            count_msg(&e2, tracing::Level::WARN, "marker-one"),
            0,
            "이전 캡처가 다음 캡처로 샜다"
        );

        let et = std::thread::spawn(|| capture_events(|| tracing::warn!("aic-cap-marker-thread")))
            .join()
            .unwrap();
        assert_eq!(
            count_msg(&et, tracing::Level::WARN, "marker-thread"),
            1,
            "새 스레드에서 캡처가 동작하지 않았다 — 스레드-로컬 sink 라우팅 실패"
        );

        // 캡처 밖에서 낸 로그는 어느 sink에도 안 들어간다(누수 없음).
        tracing::warn!("aic-cap-marker-outside");
        let e3 = capture_events(|| {});
        assert_eq!(count_msg(&e3, tracing::Level::WARN, "marker-outside"), 0);
    }

    /// **회귀 가드 — WARN 폭주(로그 레벨로 직접 검증).** 못 찾은 상태가 지속되는 동안 재탐색은 계속
    /// 돌아야 하지만(매 tick resolve 호출) **WARN은 단 한 번도 나오면 안 된다** — 못 찾음의 유일한
    /// WARN은 기동 시 `from_initial`이 낸다.
    #[test]
    fn bin_state_is_silent_at_warn_while_docker_stays_absent() {
        let counter = std::cell::Cell::new(0);
        let resolver = |_: Option<&Path>| -> Option<PathBuf> {
            counter.set(counter.get() + 1);
            None
        };

        let mut state = missing();
        let levels = capture_levels(|| {
            for _ in 0..5 {
                assert!(state.ensure(&resolver, None).is_none());
            }
        });

        assert_eq!(
            count(&levels, tracing::Level::WARN),
            0,
            "못 찾은 상태가 지속되는데 재탐색이 WARN을 쏟았다 — 폭주"
        );
        assert_eq!(
            counter.get(),
            5,
            "재탐색은 매 tick 계속 돌아야 한다(조용히 도는 것과 안 도는 것은 다르다)"
        );
    }

    /// 없다가 찾으면 INFO 한 번(전이)이고, 그 뒤로는 **재탐색하지 않는다**(찾은 뒤엔 비용 0).
    #[test]
    fn bin_state_transitions_to_found_and_then_stops_resolving() {
        let counter = std::cell::Cell::new(0);
        let resolver = |_: Option<&Path>| -> Option<PathBuf> {
            counter.set(counter.get() + 1);
            Some(PathBuf::from("/usr/bin/docker"))
        };

        let mut state = missing();
        let levels = capture_levels(|| {
            let (bin, announced) = state.ensure(&resolver, None).unwrap();
            assert_eq!(bin, PathBuf::from("/usr/bin/docker"));
            assert!(announced, "없다가 찾은 것은 새 소식 — INFO를 내야 한다");

            for _ in 0..3 {
                let (bin, announced) = state.ensure(&resolver, None).unwrap();
                assert_eq!(bin, PathBuf::from("/usr/bin/docker"));
                assert!(!announced, "이미 찾은 뒤엔 다시 알리지 않는다");
            }
        });
        assert_eq!(
            count(&levels, tracing::Level::INFO),
            1,
            "찾음 전이는 INFO 정확히 한 번"
        );
        assert_eq!(
            counter.get(),
            1,
            "이미 찾았는데 재탐색을 계속 돌렸다 — 매 tick 불필요한 stat이다"
        );
    }

    /// **회귀 가드 — 비대칭**: 찾은 뒤 docker가 사라지면 재탐색이 다시 돌아야 한다. 안 그러면
    /// "있다가 없어지면 영원히 ENOENT만 찍는" 한쪽만 자가 치유되는 상태가 된다.
    #[test]
    fn bin_state_re_resolves_after_the_binary_disappears() {
        let mut state = found("/usr/bin/docker");
        assert!(
            state.mark_gone(Path::new("/usr/bin/docker")),
            "Found -> 사라짐 전이는 알려야 한다"
        );
        assert_eq!(
            state.path(),
            None,
            "사라졌으면 재탐색하도록 current를 비운다"
        );

        let counter = std::cell::Cell::new(0);
        let resolver = |_: Option<&Path>| -> Option<PathBuf> {
            counter.set(counter.get() + 1);
            Some(PathBuf::from("/opt/docker"))
        };
        assert_eq!(
            state.ensure(&resolver, None),
            Some((PathBuf::from("/opt/docker"), true))
        );
        assert_eq!(counter.get(), 1, "사라진 뒤 재탐색이 돌지 않았다");
    }

    /// **회귀 가드 — 진동(item 2).** resolve는 늘 성공하는데 exec만 매번 `ENOENT`(잘못된 shebang 등)면,
    /// 순진한 상태 기계는 tick마다 `찾음(INFO) → 사라짐(WARN)`을 반복한다. 같은 경로가 같은 이유로
    /// 계속 실패하는 건 새 정보가 아니므로, **WARN도 INFO도 딱 한 번씩**이어야 한다.
    #[test]
    fn bin_state_suppresses_oscillation_when_a_resolved_path_keeps_failing_exec() {
        let bad = PathBuf::from("/opt/bad/docker");
        let b = bad.clone();
        let resolver = move |_: Option<&Path>| Some(b.clone());

        let mut state = missing();
        let bad_for_loop = bad.clone();
        let levels = capture_levels(|| {
            for _ in 0..6 {
                let (bin, _) = state
                    .ensure(&resolver, None)
                    .expect("resolve가 늘 경로를 준다");
                assert_eq!(bin, bad_for_loop);
                // 캡처가 ENOENT로 실패했다고 가정한다.
                state.mark_gone(&bad_for_loop);
            }
        });

        assert_eq!(
            count(&levels, tracing::Level::WARN),
            1,
            "같은 경로가 계속 ENOENT인데 매 tick WARN을 냈다 — 진동/폭주"
        );
        assert_eq!(
            count(&levels, tracing::Level::INFO),
            1,
            "같은 경로를 도로 찾은 것은 새 소식이 아닌데 매번 INFO를 냈다 — 진동"
        );
    }

    /// **회귀 가드 — mark_ok가 기록을 지운다.** 경로가 한 번 실패한 뒤 복구되어 캡처에 성공하면,
    /// 그 뒤에 오는 **독립적인 새 장애는 다시 알려야 한다**. `mark_ok`가 "나쁨" 기록을 안 지우면
    /// 첫 실패 이후 그 경로의 모든 장애가 영원히 억제된다.
    #[test]
    fn bin_state_re_announces_a_fresh_failure_after_a_successful_capture() {
        let p = PathBuf::from("/usr/bin/docker");
        let mut state = found("/usr/bin/docker");

        assert!(state.mark_gone(&p), "첫 장애는 알려야 한다");

        // 재탐색으로 같은 경로를 도로 찾고(조용히), 캡처에 성공한다.
        let pp = p.clone();
        let resolver = move |_: Option<&Path>| Some(pp.clone());
        state.ensure(&resolver, None).unwrap();
        state.mark_ok();

        assert!(
            state.mark_gone(&p),
            "성공 뒤의 새 장애를 억제하면 안 된다 — mark_ok가 나쁨 기록을 지워야 한다"
        );
    }

    /// **회귀 가드 — item 3: 데몬 down WARN 폭주.** docker는 있는데 `docker system df`가 non-zero
    /// exit(데몬 꺼짐 — 흔한 정상 상태)면, 예전엔 매 tick WARN이 나왔다. 이제는 **전이에만** WARN하고
    /// 지속되는 동안은 조용해야 한다. mark_capture_failed는 첫 진입에서만 true(=WARN 사유)를 준다.
    #[test]
    fn bin_state_capture_failure_warns_once_then_stays_quiet() {
        let mut state = found("/usr/bin/docker");
        assert!(
            state.mark_capture_failed(),
            "첫 캡처 실패(데몬 down)는 알려야 한다"
        );
        for _ in 0..5 {
            assert!(
                !state.mark_capture_failed(),
                "데몬 down이 지속되는데 또 알렸다 — 매 tick WARN 폭주"
            );
        }
        // current는 그대로여야 한다 — 실행 파일은 멀쩡하니 재탐색하지 않는다(ENOENT와 다르다).
        assert_eq!(state.path(), Some(Path::new("/usr/bin/docker")));
    }

    /// 데몬이 다시 뜨면(캡처 성공) **복구 INFO 한 번**을 내고, 이후 성공은 조용하다. 그리고 다음
    /// 독립 장애는 다시 WARN해야 한다(mark_ok가 CaptureFailing 기록을 지운다).
    #[test]
    fn bin_state_capture_recovery_logs_info_once_and_rearms() {
        let mut state = found("/usr/bin/docker");

        let levels = capture_levels(|| {
            assert!(state.mark_capture_failed(), "첫 실패 WARN");
            state.mark_ok(); // 데몬 복귀
            state.mark_ok(); // 이후 성공은 조용
        });
        assert_eq!(
            count(&levels, tracing::Level::INFO),
            1,
            "복구는 INFO 정확히 한 번(이후 성공은 조용)"
        );

        assert!(
            state.mark_capture_failed(),
            "복구 뒤의 새 장애는 다시 알려야 한다 — mark_ok가 CaptureFailing을 지워야 한다"
        );
    }

    /// ENOENT(사라짐)와 데몬 down은 **구분**된다: 전자는 재탐색하도록 `current`를 비우고, 후자는
    /// 같은 경로를 계속 시도한다.
    #[test]
    fn bin_state_distinguishes_missing_binary_from_daemon_down() {
        let p = Path::new("/usr/bin/docker");

        let mut gone = found("/usr/bin/docker");
        gone.mark_gone(p);
        assert_eq!(gone.path(), None, "ENOENT는 재탐색하도록 current를 비운다");

        let mut down = found("/usr/bin/docker");
        down.mark_capture_failed();
        assert_eq!(
            down.path(),
            Some(p),
            "데몬 down은 실행 파일이 멀쩡하니 같은 경로를 유지한다"
        );
    }

    /// **item 3 — config 오타는 기동 시 WARN으로 보여야 한다.** config가 지정됐는데 resolve가
    /// 실패하면(오타·상대경로·root 신뢰 실패, 또는 아직 미설치), 유일한 신호가 재탐색 경로의 debug라면
    /// 기본 로그 레벨에서 안 보인다. `from_initial`이 기동 시 WARN을 내는지 **레벨로** 확인한다.
    #[test]
    fn from_initial_warns_at_startup_when_a_configured_path_is_rejected() {
        let levels = capture_levels(|| {
            let st = BinState::from_initial(None, Some(Path::new("/typo/docker")));
            assert_eq!(st.path(), None);
            assert_eq!(st.announced_bad, Announced::Missing);
        });
        assert_eq!(
            count(&levels, tracing::Level::WARN),
            1,
            "config가 거부됐는데 기동 WARN이 없다 — 오타가 기본 레벨에서 안 보인다"
        );
    }

    /// config가 없을 때의 "못 찾음"도 기동 시 WARN 한 번(단, 문구가 config를 짚지 않는다).
    #[test]
    fn from_initial_warns_once_when_docker_is_absent_and_no_config() {
        let levels = capture_levels(|| {
            let st = BinState::from_initial(None, None);
            assert_eq!(st.path(), None);
        });
        assert_eq!(count(&levels, tracing::Level::WARN), 1);
    }

    /// 기동 시 이미 찾은 경우엔 기동 경고가 없다.
    #[test]
    fn from_initial_is_quiet_when_docker_is_already_found() {
        let levels = capture_levels(|| {
            let st = BinState::from_initial(Some(PathBuf::from("/usr/bin/docker")), None);
            assert_eq!(st.path(), Some(Path::new("/usr/bin/docker")));
        });
        assert_eq!(count(&levels, tracing::Level::WARN), 0);
    }

    /// **회귀 가드 — 비대칭(루프 배선)**: 위 `bin_state_*` 테스트들은 상태 기계만 본다. 그 기계가
    /// `serve_docker`의 캡처 실패 경로에 **실제로 연결돼 있는지**는 별개 문제라, ENOENT를
    /// `mark_gone`으로 잇는 배선을 빼도 상태 기계 테스트는 전부 통과한다(실제로 mutation에서 그
    /// 구멍에 걸렸다). 그래서 여기서는 루프 전체를 돌린다.
    ///
    /// 시나리오: A에 docker가 있어 캡처가 돌던 중 A가 사라지고 B에 나타난다. 재탐색이 배선돼 있으면
    /// B로 옮겨 가 캡처가 재개된다(spool이 다시 늘어난다). 배선이 없으면 A에 대고 영원히 ENOENT만
    /// 내므로 spool이 얼어붙는다.
    #[tokio::test]
    async fn serve_docker_recovers_when_the_running_binary_disappears() {
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

        let path_a = dir.path().join("docker-a");
        let path_b = dir.path().join("docker-b");
        let script = format!("cat <<'EOF'\n{REAL_DF_OUTPUT}EOF");
        fake_docker_bin_at(&path_a, &script);

        let cfg = DockerConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            interval: Duration::from_millis(15),
            docker_bin: Some(path_a.clone()),
            configured_bin: None,
            timeout: Duration::from_secs(5),
            spool: spool.clone(),
            health: health.clone(),
        };

        // 재탐색기: 지금 실제로 존재하는 쪽을 답한다(진짜 resolve의 머신 의존을 피한다).
        let (a, b) = (path_a.clone(), path_b.clone());
        let resolver = move |_: Option<&Path>| -> Option<PathBuf> {
            if a.exists() {
                Some(a.clone())
            } else if b.exists() {
                Some(b.clone())
            } else {
                None
            }
        };

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { serve_docker_with(cfg, rx, &resolver).await });

        // A로 캡처가 돌기 시작할 때까지 기다린다.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while spool.batch_count() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "A에 docker가 있는데 캡처가 시작되지 않았다 — 테스트 전제가 무너졌다"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // docker가 A에서 사라지고 B로 옮겨 간다(삭제 후 다른 경로에 재설치).
        std::fs::remove_file(&path_a).unwrap();
        fake_docker_bin_at(&path_b, &script);
        let baseline = spool.batch_count();

        // 재탐색이 배선돼 있으면 B를 찾아 캡처를 재개한다 — spool이 다시 늘어난다.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while spool.batch_count() <= baseline + 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "실행 파일이 사라졌는데 재탐색이 돌지 않았다 — 사라진 경로에 대고 영원히 ENOENT만 낸다"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve_docker가 shutdown 후 hang됨")
            .expect("serve_docker task가 panic함")
            .expect("serve_docker가 에러로 끝남");
    }

    /// spawn 실패가 **이 경로를 더는 못 써서**(ENOENT 사라짐 / EACCES 실행 불가)인지, 아니면 데몬
    /// down/timeout(실행 파일은 멀쩡)인지 갈라내야 재탐색 여부를 정할 수 있다.
    #[tokio::test]
    async fn is_binary_unusable_distinguishes_gone_and_noexec_from_daemon_down() {
        // 없는 실행 파일 → ENOENT → 재탐색 대상.
        let missing = capture_docker_df(
            Path::new("/definitely/does/not/exist/docker"),
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(
            is_binary_unusable(&missing),
            "미설치 spawn 실패를 재탐색 대상으로 인식하지 못했다: {missing}"
        );

        // 실행 비트가 없는 파일 → EACCES → 이것도 재탐색 대상(item 4 — 예전엔 CaptureFailing에 갇혔다).
        let dir = tempfile::tempdir().unwrap();
        let noexec = dir.path().join("docker");
        std::fs::write(&noexec, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o644)).unwrap();
        let eacces = capture_docker_df(&noexec, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            is_binary_unusable(&eacces),
            "실행 비트 없는 파일의 EACCES를 재탐색 대상으로 보지 않았다 — CaptureFailing에 갇힌다: {eacces}"
        );

        // 데몬 다운(non-zero exit)은 실행 파일이 멀쩡 — 재탐색 대상이 아니다(CaptureFailing).
        let bin = fake_docker_bin(&dir, "echo 'cannot connect' >&2; exit 1");
        let down = retry_busy(|| capture_docker_df(&bin, Duration::from_secs(5)))
            .await
            .unwrap_err();
        assert!(
            !is_binary_unusable(&down),
            "데몬 다운을 '실행 파일 못 씀'으로 오인했다 — 애먼 재탐색을 돈다: {down}"
        );
    }

    /// **회귀 가드 — item 2: CaptureFailing 루프 배선.** 상태 기계 단위 테스트는 있지만, 그게
    /// `serve_docker` 루프에 **실제로 배선됐는지**는 별개다(4차의 ENOENT 통합 테스트와 대칭). docker가
    /// 계속 non-zero exit(데몬 down)일 때 **데몬-down WARN이 첫 tick 1회만** 나오고, 복구되면 INFO
    /// 한 번이 나오는지를 루프를 실제로 돌려 확인한다.
    ///
    /// 로그 캡처(`capture_events`)는 **스레드-로컬 sink**로 라우팅하므로, serve 루프를 `tokio::spawn`
    /// (워커 스레드로 이동)하면 그 스레드엔 sink가 없어 이벤트가 안 잡힌다. 그래서 current-thread
    /// 런타임 + block_on으로 **테스트 스레드에서** 폴링해 같은 sink에 잡히게 한다(위 "로그 캡처" 주석
    /// 참고). fake docker는 호출 횟수를 세서 처음 2번은 exit 1(데몬 down), 그 뒤엔 성공(복구)한다.
    #[test]
    fn serve_docker_warns_once_on_daemon_down_and_logs_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let count_file = dir.path().join("count");
        // 처음 2회 exit 1(데몬 down), 그 뒤 정상 NDJSON(복구). 복구를 mid-run 개입 없이 스크립트가
        // 호출 횟수로 스스로 만든다. down이 **2틱** 이상이라야 "always-WARN" 배선 회귀(M25)가
        // down_warns=2로 잡힌다(1틱만 down이면 정상이든 회귀든 1이라 구분 못 한다).
        let script = format!(
            "n=$(cat '{cf}' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{cf}'; \
             if [ \"$n\" -le 2 ]; then echo 'cannot connect to the docker daemon' >&2; exit 1; fi; \
             cat <<'NDJSON'\n{out}NDJSON",
            cf = count_file.display(),
            out = REAL_DF_OUTPUT
        );
        let bin = fake_docker_bin(&dir, &script);

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
        let cfg = DockerConfig {
            endpoint: "http://127.0.0.1:1".to_string(), // 죽은 endpoint — push는 실패하지만 캡처와 무관.
            token: None,
            service_version: "0.0.0-test".to_string(),
            interval: Duration::from_millis(5),
            docker_bin: Some(bin.clone()),
            configured_bin: None,
            timeout: Duration::from_secs(5),
            spool: spool.clone(),
            health,
        };
        // current 가 항상 Some(bin)이라 resolver는 불리지 않는다(데몬 down은 재탐색 안 함) — 더미.
        let resolver = |_: Option<&Path>| -> Option<PathBuf> { None };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let events = capture_events(|| {
            rt.block_on(async {
                let (tx, rx) = watch::channel(false);
                let serve = serve_docker_with(cfg, rx, &resolver);
                tokio::pin!(serve);
                // **시계가 아니라 관찰로** 끝낸다: 복구(캡처 성공→spool 적재)가 실제로 일어날 때까지
                // 기다렸다가 shutdown한다. 시간 기반이면 부하가 큰 병렬 실행에서 tick 수가 모자라
                // flaky해진다(실측: 3s 고정이 풀 스위트 병렬에서 간헐 실패). 안전 상한만 넉넉히 둔다.
                let _ = tokio::time::timeout(Duration::from_secs(20), async {
                    loop {
                        tokio::select! {
                            _ = &mut serve => break,
                            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                                if spool.batch_count() > 0 {
                                    // 캡처가 성공해 spool에 쌓였다 = 복구가 일어났고 그 INFO도 이미 났다.
                                    tx.send_replace(true);
                                    let _ = (&mut serve).await;
                                    break;
                                }
                            }
                        }
                    }
                })
                .await;
            });
        });

        // 데몬-down WARN은 push-실패 WARN 등과 메시지로 구분해 센다.
        let down_warns = count_msg(&events, tracing::Level::WARN, "캡처 실패(데몬 down");
        assert_eq!(
            down_warns, 1,
            "데몬 down이 지속되는데 캡처 WARN이 {down_warns}번 — 전이-알림 배선이 끊겼다(매 tick 폭주)"
        );
        let recovery = count_msg(&events, tracing::Level::INFO, "정상으로 돌아왔다");
        assert_eq!(
            recovery, 1,
            "복구 INFO가 {recovery}번 — 데몬이 다시 뜬 전이를 한 번 알려야 한다"
        );
    }
}
