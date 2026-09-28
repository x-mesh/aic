//! `aic update` — 설치 출처를 감지해 적절한 셀프업데이트 경로를 선택한다.
//!
//! - **Manual**(install.sh, /usr/local/bin, ~/.local/bin): GitHub release archive를
//!   직접 받아 sha256 검증 후 세 binary(`aic`, `aic-session`, `aicd`)를 atomic
//!   rename으로 교체. 디렉토리 권한이 없으면 `sudo install`로 fallback하고, 교체 중
//!   하나라도 실패하면 이미 교체한 binary를 되돌린다.
//! - **Brew**(`/opt/homebrew`, `/usr/local/Cellar`, `linuxbrew`): `brew upgrade
//!   x-mesh/tap/aic`로 위임.
//! - **Cargo**(`~/.cargo/bin`): 자동 교체 거부 — `cargo install` 재실행 안내.
//!
//! 디자인은 `x-mesh/gk`의 update 모듈을 거의 그대로 옮긴 것으로, 같은 release
//! 자산 layout(`{name}_{version}_{os}_{arch}.tar.gz` + `checksums.txt`)을 가정한다.

use anyhow::{anyhow, bail, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

/// 소스이자 release 자산(tag/archive/checksums)이 올라가는 repo. public이라 미인증
/// redirect·직링크가 그대로 동작한다 — 별도 미러가 필요 없다.
const REPO: &str = "x-mesh/aic";
/// release.yml이 매 릴리스마다 Formula를 갱신하는 tap — `brew upgrade` 위임 대상.
const BREW_TAP: &str = "x-mesh/tap/aic";
/// release archive에 포함된 모든 binary. `aic-session`/`aicd`는 나란히 갱신된다.
const BINARIES: &[&str] = &["aic", "aic-session", "aicd"];

/// 4 MiB가 넘는 checksums.txt는 받아들이지 않는다 — 정상 파일은 수백 바이트 수준.
const MAX_CHECKSUMS_BYTES: usize = 64 * 1024;
/// 단일 archive 64 MiB 상한 — 우리 release는 ~10 MiB이므로 충분.
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

/// 현재 실행 중인 `aic` binary의 버전. `Cargo.toml`의 `[package].version`과 일치.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ── 설치 출처 감지 ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Manual,
    Brew,
    Cargo,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Manual => "manual",
            Source::Brew => "brew",
            Source::Cargo => "cargo",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Install {
    pub source: Source,
    pub binary_path: PathBuf,
    pub dir: PathBuf,
    pub os: &'static str,
    pub arch: &'static str,
}

impl Install {
    /// release archive 이름. `name_template`이 `{Project}_{Version}_{Os}_{Arch}`이므로
    /// 호출 시 tag을 받아 조립한다.
    pub fn asset_name(&self, tag: &str) -> String {
        let version = tag.strip_prefix('v').unwrap_or(tag);
        format!("aic_{version}_{}_{}.tar.gz", self.os, self.arch)
    }
}

const BREW_PREFIXES: &[&str] = &[
    "/opt/homebrew/",
    "/usr/local/Cellar/",
    "/usr/local/Homebrew/",
    "/home/linuxbrew/.linuxbrew/",
];

pub fn detect_install() -> Result<Install> {
    let exe = std::env::current_exe().context("실행 binary 경로 조회 실패")?;
    let resolved = std::fs::canonicalize(&exe).unwrap_or(exe);

    let os =
        goreleaser_os().ok_or_else(|| anyhow!("지원하지 않는 OS: {}", std::env::consts::OS))?;
    let arch = goreleaser_arch()
        .ok_or_else(|| anyhow!("지원하지 않는 아키텍처: {}", std::env::consts::ARCH))?;

    let dir = resolved
        .parent()
        .ok_or_else(|| anyhow!("부모 디렉토리 없음: {}", resolved.display()))?
        .to_path_buf();

    let source = classify(&resolved);
    Ok(Install {
        source,
        binary_path: resolved,
        dir,
        os,
        arch,
    })
}

fn classify(path: &Path) -> Source {
    let s = path.to_string_lossy();
    for p in BREW_PREFIXES {
        if s.starts_with(p) {
            return Source::Brew;
        }
    }
    if is_cargo_install_path(path) {
        return Source::Cargo;
    }
    Source::Manual
}

fn is_cargo_install_path(path: &Path) -> bool {
    if let Some(home) = dirs::home_dir() {
        let cargo_bin = home.join(".cargo").join("bin");
        if path.starts_with(&cargo_bin) {
            return true;
        }
    }
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let bin = PathBuf::from(cargo_home).join("bin");
        if path.starts_with(&bin) {
            return true;
        }
    }
    false
}

fn goreleaser_os() -> Option<&'static str> {
    match std::env::consts::OS {
        "linux" => Some("linux"),
        "macos" => Some("darwin"),
        _ => None,
    }
}

fn goreleaser_arch() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

// ── 버전 비교 ─────────────────────────────────────────────────

/// `a < b` → -1, 같으면 0, 크면 1. `v` prefix와 `-rc1` 류 suffix는 무시한다.
/// 비-숫자 segment(예: dev)는 "항상 더 낮은 버전"으로 간주해 항상 update 가능 표시.
/// 버전 비교. 구현은 `aic_common::semver`에 있다 — aicd의 셀프업데이트가 같은
/// 판정을 써야 하고, 두 벌이 되면 CLI와 데몬이 다른 답을 낼 수 있다.
pub fn compare_semver(a: &str, b: &str) -> i32 {
    aic_common::semver::compare(a, b)
}

pub fn format_plan(current: &str, next: &str) -> String {
    format!(
        "{} → {}",
        current.trim_start_matches('v'),
        next.trim_start_matches('v')
    )
}

// ── GitHub 호출 ───────────────────────────────────────────────

/// 최신 release 태그를 가져온다. `api.github.com`(미인증 60 req/h — 쉽게 소진되어 403) 대신
/// `github.com/.../releases/latest`의 302 `Location`(`.../releases/tag/<tag>`)에서 태그를 추출한다.
/// 웹 redirect는 API rate limit·토큰과 무관하다.
pub async fn fetch_latest_tag() -> Result<String> {
    let url = format!("https://github.com/{REPO}/releases/latest");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("aic/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none()) // 따라가지 않고 Location 헤더만 읽는다
        .build()?;
    let resp = client
        .get(&url)
        .send()
        .await
        .context("최신 release 조회 실패")?;
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            anyhow!(
                "최신 release redirect 없음 (status {}) — release가 없거나 네트워크 문제",
                resp.status()
            )
        })?;
    tag_from_location(location)
        .ok_or_else(|| anyhow!("redirect Location에서 태그 추출 실패: {location}"))
}

/// `github.com/.../releases/tag/<tag>` 형태 Location에서 `<tag>`를 추출한다(순수 함수).
/// `/tag/`가 없으면(release 없어 releases 페이지로 redirect 등) None.
fn tag_from_location(location: &str) -> Option<String> {
    let (_, tag) = location.rsplit_once("/tag/")?;
    let tag = tag.trim().trim_end_matches('/');
    (!tag.is_empty()).then(|| tag.to_string())
}

fn asset_url(tag: &str, asset: &str) -> String {
    format!("https://github.com/{REPO}/releases/download/{tag}/{asset}")
}

// ── 다운로드 + 검증 + 추출 ─────────────────────────────────────

/// archive를 받아 sha256을 검증하고 staging 디렉토리에 binary들을 풀어 둔다.
/// 반환값은 (binary 이름 → 추출된 파일 절대 경로) 매핑.
pub async fn download_verified(
    tag: &str,
    asset: &str,
    staging: &Path,
) -> Result<std::collections::HashMap<String, PathBuf>> {
    let expected = fetch_expected_sum(tag, asset).await?;
    let archive_bytes = download_to_bytes(&asset_url(tag, asset)).await?;
    verify_sha256(&archive_bytes, &expected)?;
    extract_binaries(&archive_bytes, staging)
}

async fn fetch_expected_sum(tag: &str, asset: &str) -> Result<String> {
    let url = asset_url(tag, "checksums.txt");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("aic/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client
        .get(&url)
        .send()
        .await
        .context("checksums.txt 다운로드 실패")?;
    if !resp.status().is_success() {
        bail!("checksums.txt 응답 {}", resp.status());
    }
    let bytes = resp.bytes().await.context("checksums.txt body 읽기 실패")?;
    if bytes.len() > MAX_CHECKSUMS_BYTES {
        bail!("checksums.txt가 비정상적으로 큼 ({} bytes)", bytes.len());
    }
    let text = std::str::from_utf8(&bytes).context("checksums.txt가 UTF-8이 아님")?;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let sum = it.next();
        let name = it.next();
        if let (Some(sum), Some(name)) = (sum, name) {
            if name == asset {
                return Ok(sum.to_lowercase());
            }
        }
    }
    bail!("checksums.txt에 {asset} 항목이 없음");
}

async fn download_to_bytes(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .user_agent(concat!("aic/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("download 실패: {url}"))?;
    if !resp.status().is_success() {
        bail!("download {url} 응답 {}", resp.status());
    }
    let mut out = Vec::with_capacity(8 * 1024 * 1024);
    let mut stream = resp.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("스트리밍 read 실패")?;
        if (out.len() as u64) + (chunk.len() as u64) > MAX_ARCHIVE_BYTES {
            bail!("archive가 한계({MAX_ARCHIVE_BYTES} bytes)를 초과");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn verify_sha256(bytes: &[u8], expected: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let actual = hex_lower(&h.finalize());
    if actual != expected.to_lowercase() {
        bail!("sha256 불일치 (expected {expected}, got {actual})");
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// archive에서 `BINARIES`만 골라 `staging/<name>.new`로 추출. 절대/상대 경로
/// 탈출 시도(`..`)와 알 수 없는 항목은 무시한다.
fn extract_binaries(
    archive: &[u8],
    staging: &Path,
) -> Result<std::collections::HashMap<String, PathBuf>> {
    use flate2::read::GzDecoder;
    let gz = GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);
    let mut out = std::collections::HashMap::new();

    for entry in tar.entries().context("tar 헤더 read 실패")? {
        let mut entry = entry.context("tar entry read 실패")?;
        let path = entry.path().context("tar path read 실패")?.into_owned();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !BINARIES.contains(&name.as_str()) {
            continue;
        }
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        }) {
            continue;
        }

        let dst = staging.join(format!("{name}.new"));
        let mut data = Vec::with_capacity(8 * 1024 * 1024);
        entry.read_to_end(&mut data).context("tar 내용 read 실패")?;
        std::fs::write(&dst, &data).with_context(|| format!("쓰기 실패: {}", dst.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&dst, perms)
                .with_context(|| format!("chmod 실패: {}", dst.display()))?;
        }
        out.insert(name, dst);
    }

    if out.is_empty() {
        bail!("archive에서 binary를 찾지 못함 (대상: {BINARIES:?})");
    }
    Ok(out)
}

// ── atomic 교체 ───────────────────────────────────────────────

/// 설치 디렉토리에 binary를 쓰는 방법. 다운로드 **전에** 한 번 정한다 — 쓸 수 없는 위치라면
/// 수십 MB를 받은 뒤가 아니라 시작하자마자 원인과 함께 멈춰야 한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteAccess {
    /// 현재 사용자로 직접 쓴다. staging도 설치 디렉토리에 두어 같은 FS에서 rename한다.
    Direct,
    /// 권한이 없어 `sudo`로 쓴다. staging은 시스템 tmpdir이고 `sudo install`이 copy한다.
    Sudo,
}

fn install_dir_access(dir: &Path) -> Result<WriteAccess> {
    match probe_write(dir) {
        Ok(()) => Ok(WriteAccess::Direct),
        Err(e) => access_after_probe_failure(
            dir,
            &e,
            unsafe { libc::geteuid() } == 0,
            which("sudo").is_some(),
        ),
    }
}

/// probe 실패의 **종류**로 다음 수단을 정한다. sudo는 권한 부족만 해결한다 — 읽기 전용
/// 마운트(컨테이너·샌드박스의 `/usr` 등)나 root가 막힌 경우에 sudo로 넘기면 같은 이유로 다시
/// 실패하고, 사용자에게는 원인과 무관한 "sudo install 실패"만 남는다.
fn access_after_probe_failure(
    dir: &Path,
    err: &std::io::Error,
    is_root: bool,
    has_sudo: bool,
) -> Result<WriteAccess> {
    if err.kind() == std::io::ErrorKind::ReadOnlyFilesystem {
        bail!(
            "{}이(가) 읽기 전용 파일시스템에 있어 binary를 교체할 수 없습니다 — 컨테이너나 \
             샌드박스 안이라면 호스트 셸에서 다시 실행하세요 ({err})",
            dir.display()
        );
    }
    if err.kind() != std::io::ErrorKind::PermissionDenied || is_root {
        bail!("{}에 쓸 수 없습니다: {err}", dir.display());
    }
    if !has_sudo {
        bail!(
            "{}에 쓰기 권한이 없고 sudo도 없음 — 권한 있는 사용자로 다시 실행하거나 \
             user-writable 위치로 binary를 옮기세요",
            dir.display()
        );
    }
    Ok(WriteAccess::Sudo)
}

/// 이번 실행에서 교체한 binary 하나. 되돌릴 때 이 기록만 쓴다 — 디렉토리의 `.bak`을 전부
/// 믿으면 아직 교체하지 않은 binary까지 **이전 업데이트의** 백업으로 내려 버린다.
struct Replaced {
    target: PathBuf,
    /// 교체 전 binary의 백업. 원래 없던 binary(첫 설치)면 `None` — 되돌릴 때 지운다.
    backup: Option<PathBuf>,
}

/// staged binary들을 차례로 설치하고, 하나라도 실패하면 **이미 교체한 것을 모두** 되돌린다.
/// 일부만 새 버전이 되면 `aic`와 `aicd`의 IPC 계약이 깨진다.
fn install_all(access: WriteAccess, plan: &[(PathBuf, PathBuf)]) -> Result<()> {
    let mut done: Vec<Replaced> = Vec::new();
    for (staged, target) in plan {
        println!("  installing {} → {}", file_label(target), target.display());
        match replace_binary(access, staged, target) {
            Ok(replaced) => done.push(replaced),
            Err(e) => {
                for (staged, _) in plan {
                    let _ = std::fs::remove_file(staged);
                }
                return Err(match roll_back(access, &done) {
                    Ok(()) => e.context("설치를 중단하고 이미 교체한 binary를 되돌렸습니다"),
                    Err(re) => e.context(format!(
                        "되돌리기도 실패했습니다 — binary 버전이 섞였을 수 있으니 {}를 확인하세요: {re:#}",
                        done.iter()
                            .map(|r| r.target.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                });
            }
        }
    }
    Ok(())
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn replace_binary(access: WriteAccess, staged: &Path, target: &Path) -> Result<Replaced> {
    if !staged.exists() {
        bail!("staged binary 없음: {}", staged.display());
    }
    let bak = target.with_extension("bak");
    let backup = target.exists().then(|| bak.clone());
    match access {
        WriteAccess::Direct => {
            let _ = std::fs::remove_file(&bak);
            if backup.is_some() {
                std::fs::copy(target, &bak)
                    .with_context(|| format!("백업 실패: {}", bak.display()))?;
            }
            std::fs::rename(staged, target)
                .with_context(|| format!("rename 실패: {}", target.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o755);
                std::fs::set_permissions(target, perms)
                    .with_context(|| format!("chmod 실패: {}", target.display()))?;
            }
        }
        WriteAccess::Sudo => {
            // Direct와 같은 `.bak`을 남겨야 교체 중 실패와 재시작 후 롤백(`restore_from_backup`)이
            // 모두 가능하다.
            if backup.is_some() {
                run_sudo(&[
                    "cp".as_ref(),
                    "-p".as_ref(),
                    target.as_os_str(),
                    bak.as_os_str(),
                ])
                .with_context(|| format!("백업 실패: {}", bak.display()))?;
            }
            run_sudo(&[
                "install".as_ref(),
                "-m".as_ref(),
                "0755".as_ref(),
                staged.as_os_str(),
                target.as_os_str(),
            ])?;
            let _ = std::fs::remove_file(staged);
        }
    }
    Ok(Replaced {
        target: target.to_path_buf(),
        backup,
    })
}

fn roll_back(access: WriteAccess, done: &[Replaced]) -> Result<()> {
    for r in done.iter().rev() {
        match (access, &r.backup) {
            (WriteAccess::Direct, Some(bak)) => std::fs::rename(bak, &r.target)
                .with_context(|| format!("복구 실패: {}", r.target.display()))?,
            (WriteAccess::Direct, None) => std::fs::remove_file(&r.target)
                .with_context(|| format!("삭제 실패: {}", r.target.display()))?,
            (WriteAccess::Sudo, Some(bak)) => run_sudo(&[
                "mv".as_ref(),
                "-f".as_ref(),
                bak.as_os_str(),
                r.target.as_os_str(),
            ])?,
            (WriteAccess::Sudo, None) => {
                run_sudo(&["rm".as_ref(), "-f".as_ref(), r.target.as_os_str()])?
            }
        }
    }
    Ok(())
}

fn run_sudo(args: &[&std::ffi::OsStr]) -> Result<()> {
    let cmd = args
        .first()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    let status = std::process::Command::new("sudo")
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .with_context(|| format!("sudo {cmd} 실행 실패"))?;
    if !status.success() {
        bail!("sudo {cmd} 실패 (exit {:?})", status.code());
    }
    Ok(())
}

/// `dir`에 임시 파일을 만들어 본다. ACL/group·마운트 옵션까지 반영되므로 mode bit 검사보다
/// 정확하다. 실패 종류(권한/읽기 전용)는 호출부가 다음 수단을 고르는 데 쓴다.
fn probe_write(dir: &Path) -> std::io::Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let probe = dir.join(format!(
        ".aic-update-probe-{}-{}",
        std::process::id(),
        nanos
    ));
    let f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)?;
    drop(f);
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

fn which(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path) {
        let candidate = p.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ── 진입점 ────────────────────────────────────────────────────

pub struct UpdateOptions {
    pub check: bool,
    pub force: bool,
    pub pinned: Option<String>,
}

/// update가 디스크의 binary를 실제로 건드렸는지.
///
/// 호출부는 이걸로 "aicd를 재시작해야 하는가"를 판단한다 — binary만 갈아끼우면
/// 이미 떠 있는 데몬은 옛 코드로 계속 돌기 때문이다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// binary가 교체되었다(Manual), 또는 외부 매니저가 교체했을 수 있다(Brew).
    ///
    /// `tag`은 **설치된 쪽**의 버전이다. 호출부가 `CARGO_PKG_VERSION`으로 대신 쓰면 안 된다 —
    /// 그 값은 지금 도는 프로세스의 컴파일 시점 버전이라, 교체 결과와 다를 수 있다(핀 설치나
    /// 다운그레이드에서 실제로 어긋난다). Brew는 외부 매니저가 정하므로 `None`이다.
    Replaced { tag: Option<String> },
    /// binary는 그대로다 — `--check`, 이미 최신, cargo 설치(자동 교체 거부).
    Unchanged,
}

pub async fn run(opts: UpdateOptions) -> Result<Outcome> {
    let install = detect_install()?;
    let current = current_version();

    // 최신 태그: Manual은 다운로드 URL 구성에 **필수**라 실패 시 중단한다.
    // Brew/Cargo는 `brew upgrade`/cargo가 최신을 알아서 가져오므로 태그는 출력·--check 용 best-effort —
    // 조회가 실패해도(네트워크 등) 업그레이드를 막지 않는다. 조회는 github.com redirect라 rate limit 무관.
    let target: Option<String> = match opts.pinned.clone() {
        Some(t) => Some(t),
        None => match install.source {
            Source::Manual => Some(fetch_latest_tag().await?),
            _ => fetch_latest_tag().await.ok(),
        },
    };

    if opts.check {
        return match target.as_deref() {
            Some(t) if compare_semver(current, t) >= 0 => {
                println!(
                    "up-to-date: v{current} (latest {t}, source {})",
                    install.source.label()
                );
                Ok(Outcome::Unchanged)
            }
            Some(t) => {
                println!("update available: {}", format_plan(current, t));
                std::process::exit(1);
            }
            None => {
                let hint = match install.source {
                    Source::Brew => "brew outdated",
                    _ => "잠시 후 재시도",
                };
                println!(
                    "최신 버전 확인 실패 (네트워크) — source {}, `{hint}`로 확인하세요.",
                    install.source.label()
                );
                Ok(Outcome::Unchanged)
            }
        };
    }

    match target.as_deref() {
        Some(t) => println!(
            "current: v{current}\nlatest:  {t}\nsource:  {} ({})",
            install.source.label(),
            install.binary_path.display()
        ),
        None => println!(
            "current: v{current}\nsource:  {} ({}) — 최신 태그 확인은 건너뜀",
            install.source.label(),
            install.binary_path.display()
        ),
    }

    let up_to_date =
        matches!(target.as_deref(), Some(t) if compare_semver(current, t) >= 0) && !opts.force;
    if up_to_date {
        println!("이미 최신입니다 — 강제 재설치는 --force.");
        return Ok(Outcome::Unchanged);
    }

    match install.source {
        Source::Brew => run_brew_upgrade().map(|()| Outcome::Replaced { tag: None }),
        Source::Cargo => print_cargo_hint().map(|()| Outcome::Unchanged),
        // Manual은 위에서 target이 Some임이 보장된다(None이면 fetch_latest_tag가 이미 중단).
        Source::Manual => {
            let tag = target.as_deref().unwrap().to_string();
            run_manual_upgrade(&install, &tag)
                .await
                .map(|()| Outcome::Replaced { tag: Some(tag) })
        }
    }
}

fn run_brew_upgrade() -> Result<()> {
    if which("brew").is_none() {
        bail!("PATH에 brew가 없습니다. install.sh로 재설치하거나 brew를 직접 실행하세요.");
    }
    println!("→ brew upgrade {BREW_TAP}");
    let status = std::process::Command::new("brew")
        .arg("upgrade")
        .arg(BREW_TAP)
        .status()
        .context("brew upgrade 실행 실패")?;
    if !status.success() {
        bail!("brew upgrade 실패 (exit {:?})", status.code());
    }
    Ok(())
}

fn print_cargo_hint() -> Result<()> {
    println!(
        "cargo로 설치된 binary는 자동 교체하지 않습니다. 다음 명령으로 갱신하세요:\n\
         \n  cargo install --git https://github.com/{REPO} --bins\n"
    );
    Ok(())
}

async fn run_manual_upgrade(install: &Install, tag: &str) -> Result<()> {
    let access = install_dir_access(&install.dir)?;
    let staging = match access {
        WriteAccess::Direct => install.dir.clone(),
        WriteAccess::Sudo => std::env::temp_dir(),
    };
    let asset = install.asset_name(tag);
    println!("downloading {asset} ({tag}) → {}", staging.display());

    let staged = download_verified(tag, &asset, &staging).await?;

    // aic / aic-session / aicd가 같은 디렉토리에 있다고 가정. 다른 위치에 있다면
    // 이 흐름은 aic의 위치만 갱신하고 나머지는 사용자 안내로 둔다.
    let mut plan = Vec::new();
    for bin in BINARIES {
        let Some(src) = staged.get(*bin) else {
            eprintln!("⚠ archive에 {bin}이 없어 건너뜀");
            continue;
        };
        let target = install.dir.join(bin);
        if !target.exists() && *bin != "aic" {
            // 사이드카 binary가 같은 위치에 없으면 무리해서 새로 깔지 않는다.
            eprintln!(
                "  {bin}: {} 에 기존 binary 없음 — 건너뜀 (별도 위치에 설치된 것으로 보임)",
                target.display()
            );
            let _ = std::fs::remove_file(src);
            continue;
        }
        plan.push((src.clone(), target));
    }
    install_all(access, &plan)?;

    println!("updated to {tag}");
    // 재시작은 호출부가 Outcome::Replaced를 보고 자동으로 수행한다 — 안내만 하면
    // 사용자가 빠뜨렸을 때 구버전 aicd가 조용히 계속 돈다.
    Ok(())
}

// ── 업데이트 이력과 롤백 ──────────────────────────────────────

/// 업데이트 한 건의 결과. `aic status`가 마지막 한 건을 읽어 보여준다.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateRecord {
    pub at: chrono::DateTime<chrono::Utc>,
    pub from: String,
    pub to: String,
    /// `ok` | `rolled_back` | `restart_skipped`
    pub result: String,
    /// 롤백했다면 그 이유.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// 이력 한 줄을 append한다. 실패해도 업데이트 자체를 실패로 만들지 않는다 — 기록은 부가
/// 정보이고, 여기서 에러를 올리면 이미 끝난 교체를 되돌릴 수도 없으면서 명령만 실패로 보인다.
pub fn record_update(record: &UpdateRecord) {
    let path = aic_common::paths::update_history_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut line) = serde_json::to_string(record) else {
        return;
    };
    line.push('\n');
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// 마지막 업데이트 이력 한 건. 파일이 없거나 비어 있으면 `None`.
pub fn last_update_record() -> Option<UpdateRecord> {
    let text = std::fs::read_to_string(aic_common::paths::update_history_path()).ok()?;
    text.lines()
        .rev()
        .find_map(|line| serde_json::from_str::<UpdateRecord>(line).ok())
}

/// `replace_binary`가 남긴 `.bak`으로 세 binary를 되돌린다.
///
/// **세 개를 함께 되돌린다.** 일부만 되돌리면 `aic`와 `aicd`의 버전이 어긋나 IPC 계약이 깨진다.
/// 하나라도 `.bak`이 없으면 되돌릴 수 없는 상태이므로 시도하지 않고 그 사실을 알린다.
pub fn restore_from_backup(dir: &Path) -> Result<()> {
    let pairs: Vec<(PathBuf, PathBuf)> = BINARIES
        .iter()
        .map(|bin| (dir.join(bin), dir.join(format!("{bin}.bak"))))
        .filter(|(target, _)| target.exists())
        .collect();
    if pairs.is_empty() {
        bail!("되돌릴 binary가 없습니다: {}", dir.display());
    }
    if let Some((target, bak)) = pairs.iter().find(|(_, bak)| !bak.exists()) {
        bail!(
            "{}의 백업이 없어 되돌릴 수 없습니다 (target: {})",
            bak.display(),
            target.display()
        );
    }
    for (target, bak) in &pairs {
        std::fs::copy(bak, target)
            .with_context(|| format!("복구 실패: {} ← {}", target.display(), bak.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755));
        }
    }
    Ok(())
}

/// 설치 디렉토리(롤백 대상 경로)를 알려 준다.
pub fn install_dir() -> Result<PathBuf> {
    Ok(detect_install()?.dir)
}

// ── 테스트 ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_refuses_a_partial_backup_set() {
        // 일부만 되돌리면 aic와 aicd의 버전이 어긋나 IPC 계약이 깨진다. 되돌릴 수 없는
        // 상태라면 손대지 않고 그 사실을 알려야 한다.
        let dir = tempfile::tempdir().unwrap();
        for bin in BINARIES {
            std::fs::write(dir.path().join(bin), b"new").unwrap();
        }
        // aic만 백업이 있고 나머지는 없다.
        std::fs::write(dir.path().join("aic.bak"), b"old").unwrap();

        let err = restore_from_backup(dir.path()).unwrap_err().to_string();
        assert!(err.contains("백업이 없어"), "{err}");
        // 실패했으면 아무것도 건드리지 않았어야 한다.
        assert_eq!(std::fs::read(dir.path().join("aic")).unwrap(), b"new");
    }

    #[test]
    fn rollback_restores_every_binary_together() {
        let dir = tempfile::tempdir().unwrap();
        for bin in BINARIES {
            std::fs::write(dir.path().join(bin), b"new").unwrap();
            std::fs::write(dir.path().join(format!("{bin}.bak")), b"old").unwrap();
        }
        restore_from_backup(dir.path()).unwrap();
        for bin in BINARIES {
            assert_eq!(
                std::fs::read(dir.path().join(bin)).unwrap(),
                b"old",
                "{bin}"
            );
        }
    }

    #[test]
    fn rollback_skips_binaries_that_were_never_installed() {
        // 사이드카가 다른 위치에 설치된 호스트는 교체 때도 건너뛴다. 없는 것을 되돌리라고
        // 요구하면 멀쩡한 롤백이 실패한다.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("aic"), b"new").unwrap();
        std::fs::write(dir.path().join("aic.bak"), b"old").unwrap();
        restore_from_backup(dir.path()).unwrap();
        assert_eq!(std::fs::read(dir.path().join("aic")).unwrap(), b"old");
    }

    #[test]
    fn an_update_record_roundtrips_through_jsonl() {
        let rec = UpdateRecord {
            at: chrono::Utc::now(),
            from: "0.41.8".to_string(),
            to: "0.41.9".to_string(),
            result: "rolled_back".to_string(),
            reason: Some("재시작 후 15초 동안 aicd가 응답하지 않음".to_string()),
        };
        let line = serde_json::to_string(&rec).unwrap();
        let back: UpdateRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back.from, "0.41.8");
        assert_eq!(back.result, "rolled_back");
        assert!(back.reason.is_some_and(|r| r.contains("응답하지 않음")));
        // 성공 기록에는 reason 키 자체가 없어야 한다(읽는 쪽이 빈 사유를 표시하지 않도록).
        let ok = UpdateRecord {
            reason: None,
            ..rec
        };
        assert!(!serde_json::to_string(&ok).unwrap().contains("reason"));
    }

    #[test]
    fn semver_compares_basic() {
        assert_eq!(compare_semver("0.2.0", "0.3.0"), -1);
        assert_eq!(compare_semver("v0.3.0", "0.3.0"), 0);
        assert_eq!(compare_semver("0.3.1", "v0.3.0"), 1);
        assert_eq!(compare_semver("1.0.0", "0.99.99"), 1);
    }

    #[test]
    fn semver_strips_prerelease_suffix() {
        assert_eq!(compare_semver("0.3.0-rc1", "0.3.0"), 0);
        assert_eq!(compare_semver("0.3.0+build.1", "0.3.0"), 0);
    }

    #[test]
    fn semver_dev_is_always_lower() {
        // 비-숫자 segment는 dirty로 간주 — 항상 update 가능 표시가 의도.
        assert_eq!(compare_semver("dev", "0.3.0"), -1);
        assert_eq!(compare_semver("0.3.0", "dev"), 1);
    }

    #[test]
    fn tag_from_location_extracts_tag() {
        assert_eq!(
            tag_from_location("https://github.com/x-mesh/aic/releases/tag/v0.8.0").as_deref(),
            Some("v0.8.0")
        );
        // trailing slash 허용.
        assert_eq!(
            tag_from_location("https://github.com/x-mesh/aic/releases/tag/v1.2.3/").as_deref(),
            Some("v1.2.3")
        );
        // `/tag/`가 없으면(release 없어 releases 페이지로 redirect 등) None.
        assert_eq!(
            tag_from_location("https://github.com/x-mesh/aic/releases"),
            None
        );
        assert_eq!(
            tag_from_location("https://github.com/x-mesh/aic/releases/tag/"),
            None
        );
    }

    #[test]
    fn classify_brew_paths() {
        assert_eq!(classify(Path::new("/opt/homebrew/bin/aic")), Source::Brew);
        assert_eq!(
            classify(Path::new("/usr/local/Cellar/aic/0.3.0/bin/aic")),
            Source::Brew
        );
        assert_eq!(
            classify(Path::new("/home/linuxbrew/.linuxbrew/bin/aic")),
            Source::Brew
        );
    }

    #[test]
    fn classify_manual_paths() {
        assert_eq!(classify(Path::new("/usr/local/bin/aic")), Source::Manual);
        assert_eq!(
            classify(Path::new("/home/user/.local/bin/aic")),
            Source::Manual
        );
    }

    #[test]
    fn asset_name_template_matches_goreleaser() {
        let install = Install {
            source: Source::Manual,
            binary_path: PathBuf::from("/tmp/aic"),
            dir: PathBuf::from("/tmp"),
            os: "darwin",
            arch: "arm64",
        };
        assert_eq!(
            install.asset_name("v0.3.0"),
            "aic_0.3.0_darwin_arm64.tar.gz"
        );
        assert_eq!(install.asset_name("0.3.0"), "aic_0.3.0_darwin_arm64.tar.gz");
    }

    #[test]
    fn format_plan_strips_v_prefix() {
        assert_eq!(format_plan("v0.2.0", "v0.3.0"), "0.2.0 → 0.3.0");
        assert_eq!(format_plan("0.2.0", "0.3.0"), "0.2.0 → 0.3.0");
    }

    #[test]
    fn extract_binaries_picks_only_known_names() {
        // tar.gz를 inline으로 만들어 aic/aic-session/aicd 외 entry가 무시되는지 검증.
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut gz_buf = Vec::new();
        {
            let enc = GzEncoder::new(&mut gz_buf, Compression::fast());
            let mut builder = tar::Builder::new(enc);
            for (name, content) in [
                ("aic", b"aic-binary".to_vec()),
                ("aic-session", b"session-binary".to_vec()),
                ("aicd", b"daemon-binary".to_vec()),
                ("README.md", b"# readme".to_vec()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                builder.append(&header, content.as_slice()).unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let extracted = extract_binaries(&gz_buf, dir.path()).unwrap();
        assert_eq!(extracted.len(), 3);
        assert!(extracted.contains_key("aic"));
        assert!(extracted.contains_key("aic-session"));
        assert!(extracted.contains_key("aicd"));
        // README는 BINARIES에 없어 추출되지 않음.
        assert!(!dir.path().join("README.md").exists());
    }

    #[test]
    fn writable_detects_user_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(install_dir_access(dir.path()).unwrap(), WriteAccess::Direct);
    }

    #[test]
    fn read_only_filesystem_is_reported_instead_of_escalating_to_sudo() {
        // sudo도 같은 EROFS로 실패한다. 예전에는 "sudo install 실패"만 남아 원인이 가려졌다.
        let err = std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem);
        let msg = access_after_probe_failure(Path::new("/usr/local/bin"), &err, false, true)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("읽기 전용"), "{msg}");
    }

    #[test]
    fn root_permission_denied_does_not_escalate_to_sudo() {
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(access_after_probe_failure(Path::new("/opt/aic"), &err, true, true).is_err());
    }

    #[test]
    fn non_root_permission_denied_uses_sudo_only_when_available() {
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let dir = Path::new("/usr/local/bin");
        assert_eq!(
            access_after_probe_failure(dir, &err, false, true).unwrap(),
            WriteAccess::Sudo
        );
        assert!(access_after_probe_failure(dir, &err, false, false).is_err());
    }

    fn stage_release(dir: &Path) -> Vec<(PathBuf, PathBuf)> {
        BINARIES
            .iter()
            .map(|bin| {
                let src = dir.join(format!("{bin}.new"));
                std::fs::write(&src, b"new").unwrap();
                (src, dir.join(bin))
            })
            .collect()
    }

    #[test]
    fn failed_replacement_rolls_back_binaries_already_replaced() {
        // aic만 새 버전이 되고 aicd는 옛 버전으로 남으면 IPC 계약이 깨진다.
        let dir = tempfile::tempdir().unwrap();
        for bin in ["aic", "aic-session"] {
            std::fs::write(dir.path().join(bin), b"old").unwrap();
        }
        // 마지막 대상(aicd)을 디렉토리로 만들어 백업 단계에서 실패시킨다.
        std::fs::create_dir(dir.path().join("aicd")).unwrap();
        std::fs::write(dir.path().join("aicd").join("keep"), b"x").unwrap();
        let plan = stage_release(dir.path());

        let msg = install_all(WriteAccess::Direct, &plan)
            .unwrap_err()
            .to_string();

        assert!(msg.contains("되돌렸습니다"), "{msg}");
        for bin in ["aic", "aic-session"] {
            assert_eq!(
                std::fs::read(dir.path().join(bin)).unwrap(),
                b"old",
                "{bin}"
            );
        }
        for (src, _) in &plan {
            assert!(!src.exists(), "staged 파일이 남음: {}", src.display());
        }
    }

    #[test]
    fn rollback_removes_a_binary_that_did_not_exist_before() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("aic-session"), b"old").unwrap();
        std::fs::create_dir(dir.path().join("aicd")).unwrap();
        std::fs::write(dir.path().join("aicd").join("keep"), b"x").unwrap();
        let plan = stage_release(dir.path());

        install_all(WriteAccess::Direct, &plan).unwrap_err();

        assert!(!dir.path().join("aic").exists());
        assert_eq!(
            std::fs::read(dir.path().join("aic-session")).unwrap(),
            b"old"
        );
    }

    #[test]
    fn successful_install_replaces_every_binary_and_keeps_backups() {
        let dir = tempfile::tempdir().unwrap();
        for bin in BINARIES {
            std::fs::write(dir.path().join(bin), b"old").unwrap();
        }
        let plan = stage_release(dir.path());

        install_all(WriteAccess::Direct, &plan).unwrap();

        for bin in BINARIES {
            assert_eq!(
                std::fs::read(dir.path().join(bin)).unwrap(),
                b"new",
                "{bin}"
            );
            let bak = dir.path().join(format!("{bin}.bak"));
            assert_eq!(std::fs::read(bak).unwrap(), b"old", "{bin}");
        }
    }
}
