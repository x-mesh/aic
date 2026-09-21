//! `aic daemon install` / `uninstall` — OS-native auto-start unit 관리.
//!
//! 한 명령으로 양 OS 모두 부팅 시 `aicd` auto-start를 설정한다:
//! - macOS: `~/Library/LaunchAgents/com.x-mesh.aicd.plist` (launchctl)
//! - Linux: `~/.config/systemd/user/aicd.service` (systemctl --user)
//!
//! `brew services`는 macOS launchd만 잘 통합하고 Linux brew에선 stub이라
//! 이 모듈이 두 경로를 직접 처리한다. 사용자 단위(--user / LaunchAgents)라서
//! root 권한 불필요.
//!
//! 모든 함수는 멱등 — 같은 파일을 여러 번 install해도 안전. uninstall도 부분
//! 상태(파일은 있는데 unload 됐거나)에서도 잘 동작한다.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// macOS launchd plist의 Label / unit 이름.
pub const LAUNCHD_LABEL: &str = "com.x-mesh.aicd";
/// Linux systemd user service 파일명.
pub const SYSTEMD_UNIT: &str = "aicd.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Linux,
    Unsupported,
}

pub fn detect_platform() -> Platform {
    match std::env::consts::OS {
        "macos" => Platform::Macos,
        "linux" => Platform::Linux,
        _ => Platform::Unsupported,
    }
}

/// systemd linger 처리 결과.
///
/// linger가 없으면 `systemctl --user enable`은 **부팅 자동 시작을 보장하지 않는다** —
/// 마지막 로그인 세션이 닫히는 순간 user manager가 내려가고 user 유닛도 같이 죽는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Linger {
    /// 원래 켜져 있었다 — 건드리지 않았다.
    AlreadyOn,
    /// 이번에 켰다.
    Enabled,
    /// 켜지 못했다. 사유를 그대로 보여 줘 다음 조치를 판단하게 한다.
    Failed(String),
    /// linger 개념이 없다(macOS launchd) 또는 unit을 load하지 않은 설치(`--no-load`).
    NotApplicable,
}

/// 설치 결과 요약 — 호출자가 사용자에게 한 줄로 보여줄 수 있게.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub platform: Platform,
    pub unit_path: PathBuf,
    pub aicd_path: PathBuf,
    pub log_dir: PathBuf,
    /// load/enable까지 수행했는지(`--no-load`면 false).
    pub loaded: bool,
    /// 로그아웃 후에도 유닛이 살아 있게 하는 linger 처리 결과.
    pub linger: Linger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    pub platform: Platform,
    pub unit_path: PathBuf,
    /// 파일이 존재해서 실제로 제거했는지.
    pub removed: bool,
}

// ── 경로 결정 ──────────────────────────────────────────────────

// snapshot_timer(L2)가 같은 HOME 해석을 공유하도록 pub(crate).
pub(crate) fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("HOME 환경 변수가 설정되지 않았습니다"))
}

/// macOS plist 설치 경로.
pub fn macos_plist_path() -> Result<PathBuf> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

/// system 유닛에 박을 `aicd` 경로.
///
/// 기본 해석([`resolve_aicd_path`])은 `current_exe()` 옆을 먼저 본다. 그래서
/// `sudo ~/.local/bin/aic daemon install --system`으로 설치하면 유닛이 **특정 사용자의 홈 아래**
/// binary를 가리킨다. 그 홈이 사라지거나 마운트가 풀리면 부팅 시 서비스가 뜨지 못한다.
/// system 서비스는 공용 경로의 binary를 써야 한다.
fn resolve_system_aicd_path() -> Result<PathBuf> {
    for dir in ["/usr/local/bin", "/usr/bin"] {
        let candidate = PathBuf::from(dir).join("aicd");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    let fallback = resolve_aicd_path()?;
    if is_under_home(&fallback) {
        return Err(anyhow!(
            "system 유닛이 사용자 홈 아래 binary({})를 가리키게 됩니다. \
             /usr/local/bin에 설치한 뒤 다시 실행하세요: sudo install -m 0755 {} /usr/local/bin/aicd",
            fallback.display(),
            fallback.display()
        ));
    }
    Ok(fallback)
}

/// 경로가 사용자 홈 아래인가. system 서비스가 의존하면 안 되는 위치를 걸러낸다.
fn is_under_home(path: &Path) -> bool {
    path.starts_with("/home") || path.starts_with("/root") || path.starts_with("/Users")
}

/// systemd 유닛이 user·system 두 스코프에 동시에 존재할 때의 충돌 상태.
///
/// **왜 root에서만 겹치는가**: 런타임 디렉토리는 `is_system_service()`(= euid 0)로 갈린다.
/// root의 사용자 단위로 뜬 aicd도 euid가 0이라 system 유닛과 같은 `/run/aic`를 쓰고, 같은
/// lock을 두고 다툰다. 먼저 잡은 쪽이 이기고 진 쪽은 `RestartSec=2`로 영원히 재시도한다.
/// 일반 사용자의 사용자 단위는 uid가 달라 경로가 갈리므로 이 진단에 걸리지 않는다.
#[derive(Debug, Clone)]
pub struct UnitConflict {
    /// 지금 설치·재시작하려는 스코프. `true`면 system.
    target_system: bool,
    /// 반대 스코프에 남아 있는 유닛 파일.
    other_unit: Option<PathBuf>,
    /// 그 유닛이 지금 활성인가.
    other_active: bool,
    /// 런타임 lock을 쥐고 살아 있는 프로세스.
    holder: Option<i32>,
    /// lock 보유자가 뜬 스코프. `/proc`에서 읽지 못하면 `None`.
    holder_system: Option<bool>,
}

impl UnitConflict {
    /// 반대 스코프의 이름. 안내 문구가 가리키는 대상이다.
    fn other_label(&self) -> &'static str {
        if self.target_system {
            "사용자 단위"
        } else {
            "system 단위"
        }
    }

    /// 반대 스코프를 다루는 `systemctl` 호출 형태.
    fn systemctl_prefix(&self) -> &'static str {
        if self.target_system {
            "systemctl --user"
        } else {
            "systemctl"
        }
    }

    /// `aic status`에 한 줄로 얹을 요약.
    pub fn summary(&self) -> String {
        let mut s = format!("{} aicd가 함께 설치되어 있습니다", self.other_label());
        if let (Some(pid), Some(system)) = (self.holder, self.holder_system) {
            let scope = if system {
                "system 단위"
            } else {
                "사용자 단위"
            };
            s.push_str(&format!(" — 지금 lock을 쥔 쪽은 {scope}(PID {pid})입니다"));
        }
        s
    }

    /// lock을 쥔 쪽이 실제로 길을 막고 있는가. 판정은 `detect_unit_conflict`와 같은 함수를 쓴다 —
    /// 여기서 갈라지면 충돌 요인으로 치지도 않은 데몬을 멈추라고 안내하게 된다.
    fn holder_blocks(&self) -> bool {
        holder_blocks_scope(self.target_system, self.holder, self.holder_system)
    }

    /// 충돌을 푸는 명령을 순서대로 돌려준다.
    ///
    /// 유닛 파일 삭제가 들어가는 이유: `systemctl disable`은 파일을 지우지 않으므로, 비활성인
    /// 채 남은 유닛을 무언가 `start`하면 옛 binary가 되살아나 lock을 다시 가져간다.
    pub fn cleanup_commands(&self) -> Vec<String> {
        let mut cmds = Vec::new();
        if self.holder_blocks() {
            cmds.push("aic daemon stop".to_string());
        }
        if self.other_active {
            cmds.push(format!("{} disable --now aicd", self.systemctl_prefix()));
        }
        if let Some(path) = &self.other_unit {
            cmds.push(format!("rm -f {}", path.display()));
            cmds.push(format!("{} daemon-reload", self.systemctl_prefix()));
        }
        cmds
    }

    /// 설치·재시작을 멈추면서 보여 줄 사유와 정리 절차.
    pub fn remediation(&self, action: &str) -> String {
        let mut lines = vec![format!(
            "{} aicd가 남아 있어 {action}{} 중단합니다.",
            self.other_label(),
            object_particle(action)
        )];
        if let Some(pid) = self.holder {
            let scope = match self.holder_system {
                Some(true) => " (system 단위)",
                Some(false) => " (사용자 단위)",
                None => "",
            };
            lines.push(format!(
                "  실행 중: PID {pid}{scope} — lock {}",
                aic_common::aicd_lock_path().display()
            ));
        }
        if self.other_active {
            lines.push(format!(
                "  활성 유닛: {} {SYSTEMD_UNIT}",
                self.systemctl_prefix()
            ));
        } else if let Some(path) = &self.other_unit {
            lines.push(format!("  남은 유닛 파일: {}", path.display()));
        }
        lines.push("  먼저 정리하세요:".to_string());
        for cmd in self.cleanup_commands() {
            lines.push(format!("    {cmd}"));
        }
        lines.join("\n")
    }
}

/// lock 보유자가 지금 하려는 일을 막고 있는가.
///
/// 같은 스코프의 데몬이라면 막고 있는 것이 아니다 — 그때 충돌의 원인은 잔존 유닛 파일이지
/// 돌고 있는 데몬이 아니다. 스코프를 못 읽었을 때는 system 쪽에서만 보수적으로 막는다:
/// 전역 유닛이 조용히 재시작 루프에 빠지는 쪽이, 사용자 설치가 한 번 막히는 것보다 비싸다.
fn holder_blocks_scope(
    target_system: bool,
    holder: Option<i32>,
    holder_system: Option<bool>,
) -> bool {
    match (holder, holder_system) {
        (None, _) => false,
        (Some(_), Some(system)) => system != target_system,
        (Some(_), None) => target_system,
    }
}

/// 한글 낱말 뒤에 붙일 목적격 조사. 받침이 있으면 `을`, 없으면 `를`이다.
fn object_particle(word: &str) -> &'static str {
    match word.chars().next_back() {
        // 한글 음절은 0xAC00부터 종성 28개 단위로 늘어선다 — 나누어떨어지면 받침이 없다.
        Some(c) if ('가'..='힣').contains(&c) && (c as u32 - 0xAC00).is_multiple_of(28) => "를",
        _ => "을",
    }
}

/// 지금 설치·재시작하려는 스코프와 다투는 aicd가 있으면 그 상태를 돌려준다.
///
/// 확인 대상은 셋이다: 반대 스코프의 유닛 파일, 그 유닛의 활성 여부, 그리고 지금 런타임
/// lock을 쥔 프로세스. **파일이 남아 있기만 해도 충돌로 본다** — 이번 사고의 실제 경로였다.
pub fn detect_unit_conflict(target_system: bool) -> Option<UnitConflict> {
    if detect_platform() != Platform::Linux {
        return None;
    }
    // 반대 스코프가 system인데 지금이 root가 아니면 런타임 디렉토리가 uid로 갈려 애초에 같은
    // lock을 두고 다투지 않는다. 멀쩡한 사용자 설치를 막지 않는다.
    if !target_system && unsafe { libc::geteuid() } != 0 {
        return None;
    }

    let (other_unit, other_active) = if target_system {
        let active = systemctl_user_command()
            .args(["is-active", "--quiet", SYSTEMD_UNIT])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        (linux_unit_path().ok().filter(|p| p.exists()), active)
    } else {
        let active = Command::new("systemctl")
            .args(["is-active", "--quiet", SYSTEMD_UNIT])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        (
            Some(linux_system_unit_path()).filter(|p| p.exists()),
            active,
        )
    };

    let lock = aic_common::aicd_lock_path();
    let holder = std::fs::read_to_string(&lock)
        .ok()
        .and_then(|t| t.trim().lines().next()?.trim().parse::<i32>().ok())
        .filter(|pid| unsafe { libc::kill(*pid, 0) } == 0);
    let holder_system = holder.and_then(process_unit_scope);

    let holder_conflicts = holder_blocks_scope(target_system, holder, holder_system);

    if other_unit.is_none() && !other_active && !holder_conflicts {
        return None;
    }
    Some(UnitConflict {
        target_system,
        other_unit,
        other_active,
        holder,
        holder_system,
    })
}

/// 프로세스를 띄운 systemd 스코프. `true`면 system 유닛, `false`면 사용자 단위.
fn process_unit_scope(pid: i32) -> Option<bool> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    scope_from_cgroup(&raw)
}

/// `/proc/<pid>/cgroup` 본문에서 스코프를 읽는다.
///
/// 사용자 단위는 `user@<uid>.service` 아래에, system 단위는 `system.slice` 아래에 놓인다.
/// 사용자 쪽을 먼저 보는 이유: 사용자 세션 경로에도 `.slice`가 여러 겹 쌓여 있어, system만
/// 찾으면 사용자 단위를 system으로 오판할 수 있다.
///
/// `user.slice`까지 보는 이유: `aic daemon start`로 직접 띄운 데몬은 유닛이 아니라 로그인
/// 세션에 붙어 `/user.slice/user-0.slice/session-N.scope`에 놓인다. `user@`만 찾으면 그 데몬이
/// 스코프 불명으로 떨어져, 사용자 단위가 하나도 없는 호스트에서 system 설치와 재시작이
/// "사용자 단위가 남아 있다"며 막힌다.
fn scope_from_cgroup(cgroup: &str) -> Option<bool> {
    if cgroup.contains("user@") || cgroup.contains("user.slice") {
        return Some(false);
    }
    if cgroup.contains("system.slice") {
        return Some(true);
    }
    None
}

/// Linux systemd **system** unit 경로. root로 설치할 때 쓴다.
pub fn linux_system_unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system").join(SYSTEMD_UNIT)
}

/// Linux systemd user unit 경로. `XDG_CONFIG_HOME`이 있으면 우선 사용.
pub fn linux_unit_path() -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".config")
        });
    Ok(base.join("systemd").join("user").join(SYSTEMD_UNIT))
}

/// stdout/stderr가 redirect될 로그 디렉토리.
///
/// aicd의 `telemetry`와 **같은 해석**을 써야 `server.log`와 `aicd.err.log`가 한 디렉토리에
/// 모인다. 예전에는 여기서 HOME을 직접 조립해 `XDG_STATE_HOME`을 무시했다.
pub fn log_dir() -> Result<PathBuf> {
    Ok(aic_common::paths::log_dir())
}

/// `current_exe()`(보통 `aic`) 옆에 있는 `aicd` 절대경로를 반환한다.
/// 없으면 PATH에서 찾고, 그것도 없으면 에러.
pub fn resolve_aicd_path() -> Result<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("aicd");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    which_in_path("aicd").ok_or_else(|| {
        anyhow!(
            "aicd 실행 파일을 찾을 수 없습니다. \
             aic와 같은 디렉토리에 aicd가 설치되어 있는지 확인하세요."
        )
    })
}

// snapshot_timer(L2)의 resolve_aic_path 폴백이 공유.
pub(crate) fn which_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

// ── Unit 파일 렌더링 ──────────────────────────────────────────

/// macOS launchd plist (XML). `RunAtLoad` + `KeepAlive` + log redirect.
pub fn render_macos_plist(aicd_path: &Path, log_dir: &Path) -> String {
    let aicd = aicd_path.display();
    let stdout = log_dir.join("aicd.out.log");
    let stderr = log_dir.join("aicd.err.log");
    // systemd unit과 같은 이유로 명시 계약을 plist에 굳혀 넣는다
    // (`render_linux_service` 주석 참고).
    let runtime_dir_env = match effective_runtime_dir_env() {
        Some(dir) => {
            format!("\n        <key>AIC_RUNTIME_DIR</key>\n        <string>{dir}</string>")
        }
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{aicd}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AIC_LOG</key>
        <string>info</string>{runtime_dir_env}
    </dict>
</dict>
</plist>
"#,
        stdout = stdout.display(),
        stderr = stderr.display(),
    )
}

/// Linux systemd user unit (INI). `Restart=on-failure`로 keep-alive.
///
/// **`AIC_RUNTIME_DIR`을 설치 시점에 굳혀 넣는다.** 이 변수는 "런타임 디렉토리는 여기"라는
/// 명시 계약이라 자동 후보 탐색을 끈다 — unit에 옮겨 적지 않으면 systemd가 띄운 aicd는
/// 관례 경로(`$XDG_RUNTIME_DIR/aic`)에 bind하는데 셸의 `aic`는 지정 경로만 보고 "데몬 없음"
/// 으로 판단해 **두 번째 aicd를 띄운다**. 서로 다른 디렉토리라 lock도 겹치지 않아 아무도
/// 에러를 내지 않는다 — 정확히 중복 기동 방지가 막으려던 그 상황이다.
pub fn render_linux_service(aicd_path: &Path, log_dir: &Path) -> String {
    render_linux_service_for(aicd_path, log_dir, false)
}

/// `system`이면 system 유닛(root로 기동, `multi-user.target`)을, 아니면 기존 user 유닛을 만든다.
///
/// system 유닛에 `User=`를 넣지 않는 것은 의도다 — SRE 도구로서 다른 사용자 소유 프로세스의
/// `/proc/<pid>/exe`를 읽어야 워크로드 탐지가 정확해지고, 그 읽기는 root만 가능하다.
pub fn render_linux_service_for(aicd_path: &Path, log_dir: &Path, system: bool) -> String {
    let aicd = aicd_path.display();
    let stdout = log_dir.join("aicd.out.log");
    let stderr = log_dir.join("aicd.err.log");
    let runtime_dir_env = match effective_runtime_dir_env() {
        Some(dir) => format!("\nEnvironment=AIC_RUNTIME_DIR={dir}"),
        None => String::new(),
    };
    // systemd는 `User=`가 없는 system 유닛에 HOME을 넣지 않는다. 그러면 aicd가 config·state
    // 경로를 홈 기준으로 풀지 못해 설정을 하나도 못 읽은 채 뜬다(실서버에서 그랬다).
    // `HOME` 대신 passwd를 읽는 이유: `sudo aic daemon install --system`에서 `HOME`은 sudo를
    // 부른 사람의 홈일 수 있는데, 유닛이 가리켜야 하는 것은 데몬이 실제로 돌 root의 홈이다.
    // 사용자 단위는 systemd user manager가 HOME을 물려주므로 건드리지 않는다.
    let home_env = match (system, aic_common::paths::passwd_home()) {
        (true, Some(home)) => match home.to_str() {
            // systemd는 `Environment=`를 공백으로 쪼갠다. 감싸지 않으면 공백이 든 홈 경로가
            // 잘려 들어가, 이 줄이 고치려던 "설정을 못 읽는" 상태가 형태만 바꿔 재현된다.
            // 개행·복귀문자는 INI 자체를 깨뜨리므로 거른다(`effective_runtime_dir_env`와 같은 이유).
            Some(h) if !h.trim().is_empty() && !h.contains(['\n', '\r']) => {
                format!("\nEnvironment=\"HOME={h}\"")
            }
            _ => String::new(),
        },
        _ => String::new(),
    };
    let target = if system {
        "multi-user.target"
    } else {
        "default.target"
    };
    format!(
        r#"[Unit]
Description=aic supervisor daemon (aicd)
Documentation=https://github.com/x-mesh/aic
After={target}

[Service]
Type=simple
ExecStart={aicd}
Restart=on-failure
RestartSec=2
Environment=AIC_LOG=info{runtime_dir_env}{home_env}
StandardOutput=append:{stdout}
StandardError=append:{stderr}

[Install]
WantedBy={target}
"#,
        stdout = stdout.display(),
        stderr = stderr.display(),
    )
}

/// 설치 시점의 `AIC_RUNTIME_DIR` 값. 미설정이거나 빈 값이면 `None`.
///
/// unit 파일에 그대로 들어가므로 개행이 섞인 값은 거른다 — INI/plist를 깨뜨리거나 다른
/// 지시자를 주입할 수 있다.
fn effective_runtime_dir_env() -> Option<String> {
    let raw = std::env::var("AIC_RUNTIME_DIR").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains(['\n', '\r']) {
        return None;
    }
    Some(trimmed.to_string())
}

// ── install / uninstall ────────────────────────────────────────

/// auto-start unit을 설치한다. `no_load`가 true면 파일만 쓰고 load/enable은 안 한다.
pub fn install(no_load: bool) -> Result<InstallReport> {
    install_with_scope(no_load, aic_common::paths::is_system_service())
}

/// `system`이면 `/etc/systemd/system`에 유닛을 깔고 `systemctl`을 system 모드로 부른다.
///
/// 호출부가 명시하는 이유: root로 무언가를 설치하러 온 사람이 의도치 않게 전역 서비스를 만들면
/// 안 된다. `aic daemon install --system`이 유일한 진입점이고, 기본값은 지금까지의 사용자 설치다.
pub fn install_with_scope(no_load: bool, system: bool) -> Result<InstallReport> {
    let platform = detect_platform();
    if system && platform != Platform::Linux {
        return Err(anyhow!(
            "--system 설치는 Linux에서만 지원합니다 (현재: {})",
            std::env::consts::OS
        ));
    }
    if system && unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!(
            "--system 설치는 root 권한이 필요합니다 (sudo aic daemon install --system)"
        ));
    }
    // system 유닛과 사용자 단위가 같이 떠 있으면 먼저 잡은 쪽이 lock을 쥐고 다른 쪽은
    // 영원히 실패한다. systemd가 재시작을 반복해 로그만 쌓이므로, 설치 단계에서 막는다.
    // 어느 쪽을 깔든 반대쪽을 본다 — 한 방향만 막으면 반대 순서로 같은 사고가 난다.
    if let Some(conflict) = detect_unit_conflict(system) {
        let action = if system {
            "system 설치"
        } else {
            "사용자 단위 설치"
        };
        return Err(anyhow!("{}", conflict.remediation(action)));
    }
    if platform == Platform::Unsupported {
        return Err(anyhow!(
            "지원하지 않는 OS: {} (macOS / Linux만 지원)",
            std::env::consts::OS
        ));
    }

    let aicd = if system {
        resolve_system_aicd_path()?
    } else {
        resolve_aicd_path()?
    };
    let logs = log_dir()?;
    std::fs::create_dir_all(&logs)
        .with_context(|| format!("로그 디렉토리 생성 실패: {}", logs.display()))?;
    // 로그에는 실행한 명령과 경로가 들어간다. `/var/log` 아래는 기본 umask로 만들면 755가 되어
    // 같은 호스트의 다른 사용자에게 읽힌다. aicd의 telemetry가 쓰는 권한과 같게 맞춘다.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o700));
    }

    let unit_path = match platform {
        Platform::Macos => macos_plist_path()?,
        Platform::Linux if system => linux_system_unit_path(),
        Platform::Linux => linux_unit_path()?,
        Platform::Unsupported => unreachable!(),
    };
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("unit 디렉토리 생성 실패: {}", parent.display()))?;
    }

    let body = match platform {
        Platform::Macos => render_macos_plist(&aicd, &logs),
        Platform::Linux => render_linux_service_for(&aicd, &logs, system),
        Platform::Unsupported => unreachable!(),
    };

    // 멱등: 같은 내용이면 write도 skip해서 mtime 보존.
    let needs_write = match std::fs::read_to_string(&unit_path) {
        Ok(existing) => existing != body,
        Err(_) => true,
    };
    if needs_write {
        std::fs::write(&unit_path, &body)
            .with_context(|| format!("unit 파일 쓰기 실패: {}", unit_path.display()))?;
    }

    let loaded = if no_load {
        false
    } else {
        match platform {
            Platform::Macos => launchctl_load(&unit_path)?,
            Platform::Linux if system => systemctl_system_enable_now()?,
            Platform::Linux => systemctl_user_enable_now()?,
            Platform::Unsupported => unreachable!(),
        }
    };

    // enable만으로는 로그아웃 후 생존이 보장되지 않는다(위 ensure_linger 주석 참고).
    // launchd에는 linger 개념이 없고, --no-load는 매니저를 건드리지 않겠다는 뜻이라 둘 다 제외.
    let linger = if no_load || platform != Platform::Linux {
        Linger::NotApplicable
    } else {
        ensure_linger()
    };

    Ok(InstallReport {
        platform,
        unit_path,
        aicd_path: aicd,
        log_dir: logs,
        loaded,
        linger,
    })
}

/// auto-start unit을 제거한다. 파일과 load/enable 상태 모두 정리.
pub fn uninstall() -> Result<UninstallReport> {
    let platform = detect_platform();
    if platform == Platform::Unsupported {
        return Err(anyhow!(
            "지원하지 않는 OS: {} (macOS / Linux만 지원)",
            std::env::consts::OS
        ));
    }
    // 지금 이 호스트를 관리하는 유닛을 지운다. system으로 설치한 호스트에서 user 경로만
    // 지우면 `/etc/systemd/system`의 유닛이 남아 계속 데몬을 띄운다.
    let (unit_path, system) = current_unit().unwrap_or_else(|| {
        let fallback = match platform {
            Platform::Macos => macos_plist_path().unwrap_or_default(),
            _ => linux_unit_path().unwrap_or_default(),
        };
        (fallback, false)
    });

    // load/enable 해제는 파일 존재 여부와 무관하게 시도 — best-effort.
    match platform {
        Platform::Macos => {
            let _ = launchctl_unload(&unit_path);
        }
        Platform::Linux if system => {
            let _ = Command::new("systemctl")
                .args(["disable", "--now", SYSTEMD_UNIT])
                .output();
        }
        Platform::Linux => {
            let _ = systemctl_user_disable_now();
        }
        Platform::Unsupported => unreachable!(),
    }

    let removed = if unit_path.exists() {
        std::fs::remove_file(&unit_path)
            .with_context(|| format!("unit 파일 삭제 실패: {}", unit_path.display()))?;
        true
    } else {
        false
    };

    // 파일만 지우고 reload하지 않으면 systemd가 유닛을 계속 기억한다 — 다음 `start`가 사라진
    // 유닛으로 성공하거나, 남은 상태가 다음 설치와 엉킨다.
    if removed && platform == Platform::Linux {
        if system {
            let _ = Command::new("systemctl").arg("daemon-reload").output();
        } else {
            let _ = systemctl_user_command().arg("daemon-reload").output();
        }
    }

    Ok(UninstallReport {
        platform,
        unit_path,
        removed,
    })
}

// ── OS 호출 ────────────────────────────────────────────────────

fn launchctl_load(plist: &Path) -> Result<bool> {
    // Modern: `launchctl bootstrap gui/$UID <plist>`. fallback: `load`.
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    let bootstrap = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(plist)
        .output();
    match bootstrap {
        Ok(out) if out.status.success() => Ok(true),
        Ok(out) => {
            // 이미 load 되어 있으면 bootstrap이 실패한다 (exit 37 등). 이 경우는 OK.
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("already") || stderr.contains("Service") {
                return Ok(true);
            }
            // legacy fallback
            let legacy = Command::new("launchctl")
                .arg("load")
                .arg(plist)
                .output()
                .with_context(|| "launchctl load 실패")?;
            if legacy.status.success() {
                Ok(true)
            } else {
                Err(anyhow!(
                    "launchctl bootstrap/load 모두 실패: bootstrap stderr={stderr}, load stderr={}",
                    String::from_utf8_lossy(&legacy.stderr)
                ))
            }
        }
        Err(e) => Err(anyhow!("launchctl 실행 실패: {e}")),
    }
}

fn launchctl_unload(plist: &Path) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let domain_target = format!("gui/{uid}/{LAUNCHD_LABEL}");
    let _ = Command::new("launchctl")
        .args(["bootout", &domain_target])
        .output();
    // legacy도 시도 — bootstrap만 됐든 load만 됐든 모두 떼낸다.
    let _ = Command::new("launchctl").arg("unload").arg(plist).output();
    Ok(())
}

/// `systemctl --user` 실행용 Command. 자식 프로세스의 `XDG_RUNTIME_DIR`를 보정한다.
///
/// 로그인 셸 밖(`curl … | sh` 설치 스크립트, cron, ssh 단발 명령)에서는 `/run/user/<uid>`가
/// 실제로 존재해도 이 변수가 비어 있어 systemd user bus에 붙지 못하고
/// "Failed to connect to bus: No medium found"로 죽는다. 디렉터리가 실재할 때만 채운다 —
/// 없는 경로를 가리키면 더 알아보기 힘든 실패가 되기 때문이다.
pub(crate) fn systemctl_user_command() -> Command {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user");
    let unset = match std::env::var_os("XDG_RUNTIME_DIR") {
        None => true,
        Some(v) => v.is_empty(),
    };
    if unset {
        let uid = unsafe { libc::getuid() };
        let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
        if runtime_dir.is_dir() {
            cmd.env("XDG_RUNTIME_DIR", &runtime_dir);
        }
    }
    cmd
}

/// user bus 연결 실패는 원인이 환경(로그인 세션/linger)이라 raw D-Bus 문구만 보여 주면
/// 다음에 뭘 해야 할지 알 수 없다. 그 경우에만 실행 가능한 안내를 덧붙인다.
pub(crate) fn with_user_bus_hint(stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.contains("Failed to connect to bus") {
        format!(
            "{stderr}\n  → systemd user 세션에 연결하지 못했습니다. \
             `XDG_RUNTIME_DIR=/run/user/$(id -u)`를 설정한 뒤 다시 실행하거나, \
             `loginctl enable-linger $(id -un)`으로 user 세션을 상주시키세요."
        )
    } else {
        stderr.to_string()
    }
}

/// 현재 uid의 linger 상태. `loginctl`이 없거나 출력을 못 읽으면 `None`(= 알 수 없음).
///
/// uid로 조회한다 — 이름 조회가 한 단계 더 실패할 수 있고, `loginctl`은 둘 다 받는다.
fn linger_is_enabled(uid: u32) -> Option<bool> {
    let out = Command::new("loginctl")
        .args(["show-user", &uid.to_string(), "--property=Linger"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_linger_property(&String::from_utf8_lossy(&out.stdout))
}

/// `loginctl show-user --property=Linger` 출력을 판독한다.
///
/// 형식이 예상과 다르면 `None` — "yes가 아니다"와 "못 읽었다"를 뭉뚱그리면, 조회가 깨졌을 때
/// linger를 껐다고 오해해 매번 enable을 재시도하거나 반대로 실패를 성공으로 읽는다.
fn parse_linger_property(stdout: &str) -> Option<bool> {
    let value = stdout.trim().strip_prefix("Linger=")?;
    match value.trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// 로그아웃 뒤에도 user 유닛이 살아 있도록 linger를 켠다.
///
/// **왜 필요한가**: `systemctl --user enable --now`만으로는 부족하다. linger가 꺼져 있으면
/// 마지막 로그인 세션이 닫힐 때 user manager(`user@<uid>.service`)가 내려가고 `aicd`도 함께
/// 죽는다. 그러면 cron 같은 짧은 로그인이 user manager를 잠깐 살리는 동안에만 배치가 나가서,
/// 원격에서는 호스트가 계속 죽어 있는 것처럼 보인다(설치 로그에는 아무 경고도 남지 않는다).
///
/// 실패해도 `Err`를 반환하지 않는다 — 유닛 설치 자체는 이미 성공했고, 되돌릴 수 없는 단계
/// 뒤의 보정 하나로 명령 전체를 실패시키면 운영자가 멀쩡한 설치를 실패로 읽는다. 대신 사유를
/// `Linger::Failed`로 돌려주고 호출부가 **반드시** 경고를 출력한다 — 조용히 넘기면 이 버그가
/// 그대로 재발한다.
pub fn ensure_linger() -> Linger {
    let uid = unsafe { libc::getuid() };

    // 이미 켜져 있으면 건드리지 않는다 — 멱등하고, 정상 상태에 잡음을 만들지 않는다.
    if linger_is_enabled(uid) == Some(true) {
        return Linger::AlreadyOn;
    }

    let out = match Command::new("loginctl")
        .args(["enable-linger", &uid.to_string()])
        .output()
    {
        Ok(out) => out,
        Err(e) => return Linger::Failed(format!("loginctl 실행 실패: {e}")),
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stderr = stderr.trim();
        let detail = if stderr.is_empty() {
            format!("exit {}", out.status)
        } else {
            stderr.to_string()
        };
        return Linger::Failed(format!("loginctl enable-linger {uid} 실패: {detail}"));
    }

    // 성공 코드만 믿지 않고 실제 상태를 다시 읽는다 — polkit이 거부해도 0을 돌려주는 경로가
    // 있고, 그 경우 "켰다"고 보고하면 이 버그를 다시 못 잡는다.
    match linger_is_enabled(uid) {
        Some(true) => Linger::Enabled,
        Some(false) => Linger::Failed(
            "loginctl enable-linger가 성공했지만 Linger=no 그대로입니다 (권한 거부 가능성)".into(),
        ),
        None => Linger::Failed("linger 상태를 확인할 수 없습니다 (loginctl 조회 실패)".into()),
    }
}

/// system 유닛을 등록하고 즉시 기동한다. `--user`가 없다는 점 외에 흐름은 같다.
fn systemctl_system_enable_now() -> Result<bool> {
    let reload = Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .with_context(|| "systemctl daemon-reload 실행 실패 (systemd가 있는지 확인)")?;
    if !reload.status.success() {
        return Err(anyhow!(
            "systemctl daemon-reload 실패: {}",
            String::from_utf8_lossy(&reload.stderr).trim()
        ));
    }
    let enable = Command::new("systemctl")
        .args(["enable", "--now", SYSTEMD_UNIT])
        .output()
        .with_context(|| "systemctl enable --now 실행 실패")?;
    if !enable.status.success() {
        return Err(anyhow!(
            "systemctl enable --now 실패: {}",
            String::from_utf8_lossy(&enable.stderr).trim()
        ));
    }
    Ok(true)
}

fn systemctl_user_enable_now() -> Result<bool> {
    let reload = systemctl_user_command()
        .arg("daemon-reload")
        .output()
        .with_context(|| "systemctl --user daemon-reload 실행 실패 (systemd가 있는지 확인)")?;
    if !reload.status.success() {
        return Err(anyhow!(
            "systemctl --user daemon-reload 실패: {}",
            with_user_bus_hint(&String::from_utf8_lossy(&reload.stderr))
        ));
    }
    let enable = systemctl_user_command()
        .args(["enable", "--now", SYSTEMD_UNIT])
        .output()
        .with_context(|| "systemctl --user enable --now 실행 실패")?;
    if !enable.status.success() {
        return Err(anyhow!(
            "systemctl --user enable --now {SYSTEMD_UNIT} 실패: {}",
            with_user_bus_hint(&String::from_utf8_lossy(&enable.stderr))
        ));
    }
    Ok(true)
}

fn systemctl_user_disable_now() -> Result<()> {
    let _ = systemctl_user_command()
        .args(["disable", "--now", SYSTEMD_UNIT])
        .output();
    let _ = systemctl_user_command().arg("daemon-reload").output();
    Ok(())
}

/// 자동 시작 unit이 설치되어 있으면 그 매니저(launchd/systemd)에게 재시작을 맡긴다.
///
/// unit이 없으면 `Ok(false)` — 호출부가 직접 shutdown → start를 해야 한다는 뜻이다.
///
/// **왜 매니저를 거치는가**: unit에는 `KeepAlive`(launchd) / `Restart=on-failure`
/// (systemd)가 걸려 있다. 우리가 데몬을 죽이면 매니저가 곧바로 자기 판단으로 다시
/// 띄우기 때문에, 그 사이에 CLI가 직접 `aicd`를 spawn하면 두 기동이 경쟁하고 진 쪽이
/// singleton PID lock에 걸려 실패한다. 매니저에게 재시작을 시키면 죽이고 띄우는 일이
/// 한 주체 안에서 순서대로 일어난다.
pub fn restart_via_unit() -> Result<bool> {
    let Some((unit, system)) = current_unit() else {
        return Ok(false);
    };
    if !unit.exists() {
        return Ok(false);
    }
    // 반대 스코프의 aicd가 lock을 쥐고 있으면 `systemctl restart`는 성공 코드를 돌려주면서도
    // 유닛은 기동 실패를 반복한다. 그대로 두면 업데이트가 끝났다고 보고하면서 옛 데몬이 계속
    // 도는 상태가 되므로, 재시작을 시작하기 전에 멈춘다.
    if let Some(conflict) = detect_unit_conflict(system) {
        return Err(anyhow!("{}", conflict.remediation("재시작")));
    }
    match detect_platform() {
        Platform::Macos => {
            let uid = unsafe { libc::getuid() };
            let target = format!("gui/{uid}/{LAUNCHD_LABEL}");
            // `kickstart -k`: 돌고 있으면 죽이고 다시 띄운다. 안 돌고 있으면 그냥 띄운다.
            let out = Command::new("launchctl")
                .args(["kickstart", "-k", &target])
                .output()
                .with_context(|| "launchctl kickstart 실행 실패")?;
            if !out.status.success() {
                return Err(anyhow!(
                    "launchctl kickstart -k {target} 실패: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            Ok(true)
        }
        Platform::Linux => {
            let out = if system {
                Command::new("systemctl")
                    .args(["restart", SYSTEMD_UNIT])
                    .output()
                    .with_context(|| "systemctl restart 실행 실패")?
            } else {
                systemctl_user_command()
                    .args(["restart", SYSTEMD_UNIT])
                    .output()
                    .with_context(|| "systemctl --user restart 실행 실패")?
            };
            if !out.status.success() {
                return Err(anyhow!(
                    "systemctl --user restart {SYSTEMD_UNIT} 실패: {}",
                    with_user_bus_hint(&String::from_utf8_lossy(&out.stderr))
                ));
            }
            Ok(true)
        }
        Platform::Unsupported => Ok(false),
    }
}

/// 현재 설치 상태(파일 존재 여부)만 빠르게 확인한다. `aic daemon status`에서 사용.
pub fn current_unit_path() -> Option<PathBuf> {
    current_unit().map(|(path, _)| path)
}

/// 지금 이 호스트에서 aicd를 관리하는 유닛과 그 스코프(`true`면 system).
///
/// **존재만으로 판단하면 오진한다.** `systemctl --user disable`은 유닛 파일을 지우지 않으므로,
/// system으로 전환한 호스트에도 user 유닛 파일이 남는다. 그 파일을 보고 `systemctl --user
/// restart`를 부르면 성공 코드가 돌아오는데 실제 system 유닛은 그대로다 — 업데이트가 끝났다고
/// 보고하면서 옛 데몬이 계속 도는 상태가 된다(실서버에서 그렇게 됐다).
pub fn current_unit() -> Option<(PathBuf, bool)> {
    match detect_platform() {
        Platform::Macos => macos_plist_path()
            .ok()
            .filter(|p| p.exists())
            .map(|p| (p, false)),
        Platform::Linux => {
            let system = linux_system_unit_path();
            if aic_common::paths::is_system_service() && system.exists() {
                return Some((system, true));
            }
            linux_unit_path()
                .ok()
                .filter(|p| p.exists())
                .map(|p| (p, false))
        }
        Platform::Unsupported => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::test_support::env_lock;

    /// 이 테스트가 지키는 것: 명시 런타임 디렉토리가 unit 파일로 넘어가는 것.
    /// 깨지면 systemd가 띄운 aicd와 셸의 `aic`가 서로 다른 디렉토리를 봐, 아무 에러 없이
    /// aicd가 둘 뜬다(중복 기동 방지가 lock으로는 못 잡는 경로다).
    #[test]
    fn unit_files_carry_explicit_runtime_dir() {
        let _guard = env_lock();
        let prev = std::env::var("AIC_RUNTIME_DIR").ok();

        std::env::set_var("AIC_RUNTIME_DIR", "/srv/aic-isolated");
        let unit =
            render_linux_service(Path::new("/usr/local/bin/aicd"), Path::new("/var/log/aic"));
        assert!(
            unit.contains("Environment=AIC_RUNTIME_DIR=/srv/aic-isolated"),
            "unit에 런타임 디렉토리가 빠졌다:\n{unit}"
        );
        let plist = render_macos_plist(Path::new("/opt/bin/aicd"), Path::new("/var/log/aic"));
        assert!(plist.contains("<key>AIC_RUNTIME_DIR</key>"));
        assert!(plist.contains("<string>/srv/aic-isolated</string>"));

        // 미설정이면 아무것도 넣지 않는다 — 기본 동작(관례 탐색)은 그대로.
        std::env::remove_var("AIC_RUNTIME_DIR");
        let unit =
            render_linux_service(Path::new("/usr/local/bin/aicd"), Path::new("/var/log/aic"));
        assert!(!unit.contains("AIC_RUNTIME_DIR"));
        assert!(unit.contains("Environment=AIC_LOG=info"));
        let plist = render_macos_plist(Path::new("/opt/bin/aicd"), Path::new("/var/log/aic"));
        assert!(!plist.contains("AIC_RUNTIME_DIR"));

        // 개행이 섞인 값은 unit 문법을 깨뜨리므로 무시한다(지시자 주입 방어).
        std::env::set_var("AIC_RUNTIME_DIR", "/srv/x\nExecStart=/bin/sh");
        let unit =
            render_linux_service(Path::new("/usr/local/bin/aicd"), Path::new("/var/log/aic"));
        assert!(
            !unit.contains("/bin/sh"),
            "개행 주입이 unit에 들어갔다:\n{unit}"
        );

        match prev {
            Some(v) => std::env::set_var("AIC_RUNTIME_DIR", v),
            None => std::env::remove_var("AIC_RUNTIME_DIR"),
        }
    }

    #[test]
    fn macos_plist_contains_label_and_paths() {
        let p = render_macos_plist(Path::new("/opt/bin/aicd"), Path::new("/var/log/aic"));
        assert!(p.contains("<key>Label</key>"));
        assert!(p.contains(LAUNCHD_LABEL));
        assert!(p.contains("<string>/opt/bin/aicd</string>"));
        assert!(p.contains("RunAtLoad"));
        assert!(p.contains("KeepAlive"));
        assert!(p.contains("/var/log/aic/aicd.out.log"));
        assert!(p.contains("/var/log/aic/aicd.err.log"));
        // valid XML 시작
        assert!(p.starts_with("<?xml"));
    }

    #[test]
    fn a_leftover_user_unit_does_not_hijack_the_system_scope() {
        // `systemctl --user disable`은 유닛 파일을 지우지 않는다. 그 파일만 보고 user 스코프로
        // 판단하면 `systemctl --user restart`가 성공 코드를 돌려주는데 정작 system 유닛은
        // 그대로다 — 업데이트를 끝냈다고 보고하면서 옛 데몬이 계속 돈다(실서버에서 그랬다).
        //
        // 이 테스트는 판정 규칙만 고정한다: system 스코프에서는 `/etc/systemd/system` 쪽이
        // 우선이고, 그 경로는 user 유닛 경로와 절대 같지 않다.
        let system = linux_system_unit_path();
        assert_eq!(system, Path::new("/etc/systemd/system/aicd.service"));
        if let Ok(user) = linux_unit_path() {
            assert_ne!(system, user);
        }
    }

    #[test]
    fn system_unit_targets_multi_user_and_lives_under_etc() {
        // user 유닛은 로그인 세션에 묶인다. SRE 도구로 서버에 놓을 때는 부팅과 함께 떠야 하고,
        // 로그도 사람과 수집기가 보는 자리에 있어야 한다.
        let s = render_linux_service_for(
            Path::new("/usr/local/bin/aicd"),
            Path::new("/var/log/aic"),
            true,
        );
        assert!(s.contains("WantedBy=multi-user.target"));
        assert!(s.contains("After=multi-user.target"));
        assert!(s.contains("StandardError=append:/var/log/aic/aicd.err.log"));
        // User=를 넣지 않는 것은 의도다 — root여야 다른 사용자 프로세스의 exe를 읽는다.
        assert!(!s.contains("User="));
        assert_eq!(
            linux_system_unit_path(),
            Path::new("/etc/systemd/system/aicd.service")
        );
    }

    #[test]
    fn user_unit_keeps_the_session_target() {
        // 기본값은 지금까지의 사용자 설치다. 회귀가 나면 로그인 세션에 묶이던 동작이 바뀐다.
        let s = render_linux_service_for(
            Path::new("/home/u/.local/bin/aicd"),
            Path::new("/home/u/.local/state/aic"),
            false,
        );
        assert!(s.contains("WantedBy=default.target"));
        assert!(!s.contains("multi-user.target"));
    }

    #[test]
    fn linux_service_contains_required_sections() {
        let s = render_linux_service(Path::new("/usr/local/bin/aicd"), Path::new("/var/log/aic"));
        assert!(s.contains("[Unit]"));
        assert!(s.contains("[Service]"));
        assert!(s.contains("[Install]"));
        assert!(s.contains("ExecStart=/usr/local/bin/aicd"));
        assert!(s.contains("Restart=on-failure"));
        assert!(s.contains("WantedBy=default.target"));
        assert!(s.contains("append:/var/log/aic/aicd.out.log"));
    }

    #[test]
    fn detect_platform_matches_env_consts_os() {
        let p = detect_platform();
        match std::env::consts::OS {
            "macos" => assert_eq!(p, Platform::Macos),
            "linux" => assert_eq!(p, Platform::Linux),
            _ => assert_eq!(p, Platform::Unsupported),
        }
    }

    #[test]
    fn linux_unit_path_respects_xdg_config_home() {
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/aic-test-xdg");
        let p = linux_unit_path().unwrap();
        assert_eq!(
            p,
            PathBuf::from("/tmp/aic-test-xdg/systemd/user/aicd.service")
        );
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn macos_plist_path_under_library_launchagents() {
        // HOME이 설정되어 있어야 pass — 일반 테스트 환경은 OK
        if std::env::var("HOME").is_err() {
            return;
        }
        let p = macos_plist_path().unwrap();
        let s = p.to_string_lossy();
        assert!(s.ends_with("Library/LaunchAgents/com.x-mesh.aicd.plist"));
    }

    #[test]
    fn user_bus_hint_only_augments_bus_failures() {
        // D-Bus 연결 실패에는 다음 행동이 붙는다.
        let hinted = with_user_bus_hint("Failed to connect to bus: No medium found");
        assert!(hinted.contains("XDG_RUNTIME_DIR"));
        assert!(hinted.contains("loginctl enable-linger"));
        // 그 외 오류는 원문 그대로 — 무관한 안내로 원인을 흐리지 않는다.
        let plain = with_user_bus_hint("Unit aicd.service not found.");
        assert_eq!(plain, "Unit aicd.service not found.");
    }

    /// 이 테스트가 지키는 것: linger 판독이 "켜짐"/"꺼짐"/"못 읽음"을 구분하는 것.
    /// 셋을 뭉뚱그리면 조회가 깨진 호스트에서 linger를 켰다고 오해하고, 이 버그(로그아웃 시
    /// aicd 종료)가 경고 없이 그대로 재발한다.
    #[test]
    fn linger_property_distinguishes_unknown_from_disabled() {
        assert_eq!(parse_linger_property("Linger=yes"), Some(true));
        assert_eq!(parse_linger_property("Linger=yes\n"), Some(true));
        assert_eq!(parse_linger_property("Linger=no"), Some(false));
        // 판독 불가는 "꺼짐"이 아니라 "모름"이다.
        assert_eq!(parse_linger_property(""), None);
        assert_eq!(parse_linger_property("Linger="), None);
        assert_eq!(
            parse_linger_property("Failed to get user: No such user"),
            None
        );
        assert_eq!(parse_linger_property("Docked=no"), None);
    }

    /// 이 테스트가 지키는 것: linger 실패가 **실행 가능한 조치**를 들고 오는 것.
    /// 원래 버그는 안내가 `Failed to connect to bus` 오류 경로에만 있어서, 로그인 세션이 있는
    /// 정상 설치는 경고를 영영 못 봤다는 것이었다.
    #[test]
    fn linger_failure_carries_actionable_reason() {
        let failed = Linger::Failed("loginctl enable-linger 0 실패: Access denied".into());
        let Linger::Failed(reason) = failed else {
            panic!("Failed variant여야 함");
        };
        assert!(reason.contains("enable-linger"));
        assert!(!reason.is_empty());
    }

    #[test]
    fn systemctl_user_command_targets_user_manager() {
        let cmd = systemctl_user_command();
        assert_eq!(cmd.get_program(), "systemctl");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, vec!["--user"]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn systemctl_user_command_fills_runtime_dir_when_unset() {
        // 로그인 셸 밖(`curl | sh`)에서는 XDG_RUNTIME_DIR가 비어 user bus 연결이 깨진다.
        // 런타임 디렉터리가 실재하면 채워 주고, 없으면 손대지 않아야 한다.
        let uid = unsafe { libc::getuid() };
        let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
        let prev = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::remove_var("XDG_RUNTIME_DIR");

        let cmd = systemctl_user_command();
        let injected = cmd
            .get_envs()
            .find(|(k, _)| *k == std::ffi::OsStr::new("XDG_RUNTIME_DIR"))
            .map(|(_, v)| v.map(|v| v.to_os_string()));

        if runtime_dir.is_dir() {
            assert_eq!(injected, Some(Some(runtime_dir.into_os_string())));
        } else {
            assert!(injected.is_none(), "없는 경로를 주입하면 안 된다");
        }

        if let Some(prev) = prev {
            std::env::set_var("XDG_RUNTIME_DIR", prev);
        }
    }

    /// 이 테스트가 지키는 것: lock 보유자가 어느 스코프에서 떴는지 구분하는 것.
    /// 깨지면 두 유닛이 같이 설치된 호스트에서 "누가 lock을 쥐었나"를 못 읽어,
    /// 안내가 엉뚱한 쪽을 정리하라고 시킨다.
    #[test]
    fn cgroup_tells_a_user_unit_from_a_system_unit() {
        // 실서버(okrr-intranet-2)에서 그대로 읽은 두 형태.
        assert_eq!(
            scope_from_cgroup(
                "0::/user.slice/user-0.slice/user@0.service/app.slice/aicd.service\n"
            ),
            Some(false)
        );
        assert_eq!(
            scope_from_cgroup("0::/system.slice/aicd.service\n"),
            Some(true)
        );
        assert_eq!(scope_from_cgroup("0::/\n"), None);
    }

    /// 이 테스트가 지키는 것: 안내가 **반대 스코프**를 가리키는 것.
    /// 깨지면 사용자 단위를 깔다 막힌 사람에게 사용자 단위를 지우라고 안내한다.
    #[test]
    fn a_user_scope_install_is_told_to_clean_the_system_unit() {
        let conflict = UnitConflict {
            target_system: false,
            other_unit: Some(PathBuf::from("/etc/systemd/system/aicd.service")),
            other_active: true,
            holder: Some(4242),
            holder_system: Some(true),
        };
        let text = conflict.remediation("사용자 단위 설치");
        assert!(text.contains("/etc/systemd/system/aicd.service"), "{text}");
        assert!(text.contains("systemctl disable --now aicd"), "{text}");
        assert!(
            !text.contains("--user"),
            "반대 스코프를 가리켜야 한다: {text}"
        );
        assert!(text.contains("aic daemon stop"), "{text}");
    }

    /// 이 테스트가 지키는 것: system 설치 쪽 안내가 예전 그대로 사용자 단위를 겨냥하는 것.
    /// 파일 삭제와 daemon-reload가 빠지면 disable해도 유닛이 되살아난다.
    #[test]
    fn a_system_install_is_told_to_clean_the_user_unit() {
        let conflict = UnitConflict {
            target_system: true,
            other_unit: Some(PathBuf::from("/root/.config/systemd/user/aicd.service")),
            other_active: false,
            holder: None,
            holder_system: None,
        };
        let text = conflict.remediation("system 설치");
        assert!(
            text.contains("rm -f /root/.config/systemd/user/aicd.service"),
            "{text}"
        );
        assert!(text.contains("systemctl --user daemon-reload"), "{text}");
        // 죽은 데몬이 없으면 stop을 시키지 않는다.
        assert!(!text.contains("aic daemon stop"), "{text}");
    }

    /// 이 테스트가 지키는 것: 요약이 lock을 쥔 쪽을 이름으로 밝히는 것.
    /// `aic status`에서 이 한 줄이 없으면 운영자는 재시작 루프의 원인을 못 찾는다.
    #[test]
    fn the_summary_names_the_scope_holding_the_lock() {
        let conflict = UnitConflict {
            target_system: true,
            other_unit: Some(PathBuf::from("/root/.config/systemd/user/aicd.service")),
            other_active: true,
            holder: Some(1813286),
            holder_system: Some(false),
        };
        let summary = conflict.summary();
        assert!(summary.contains("사용자 단위"), "{summary}");
        assert!(summary.contains("1813286"), "{summary}");
    }

    /// 이 테스트가 지키는 것: system 유닛이 HOME을 들고 가는 것.
    /// 깨지면 systemd가 HOME 없이 aicd를 띄우고, aicd는 config를 못 읽은 채 exporter와
    /// 셀프업데이트를 전부 off로 올린다 — 에러 하나 없이.
    #[test]
    fn a_system_unit_carries_home_so_config_resolves() {
        let body = render_linux_service_for(
            Path::new("/usr/local/bin/aicd"),
            Path::new("/var/log/aic"),
            true,
        );
        if aic_common::paths::passwd_home().is_some() {
            assert!(body.contains("Environment=\"HOME="), "{body}");
        }
    }

    /// 이 테스트가 지키는 것: 사용자 단위는 HOME을 박지 않는 것.
    /// user manager가 물려주는 값이 정답이라, 설치 시점 값을 굳히면 홈이 바뀐 계정에서 어긋난다.
    #[test]
    fn a_user_unit_leaves_home_to_the_session_manager() {
        let body = render_linux_service_for(
            Path::new("/usr/local/bin/aicd"),
            Path::new("/var/log/aic"),
            false,
        );
        assert!(!body.contains("Environment=\"HOME="), "{body}");
    }

    /// 이 테스트가 지키는 것: 같은 스코프의 데몬에는 중지를 권하지 않는 것.
    /// 잔존 유닛 파일이 원인일 때 멀쩡히 돌고 있는 데몬을 멈추라고 하면 텔레메트리만 끊긴다.
    #[test]
    fn a_daemon_in_the_same_scope_is_not_asked_to_stop() {
        let conflict = UnitConflict {
            target_system: true,
            other_unit: Some(PathBuf::from("/root/.config/systemd/user/aicd.service")),
            other_active: false,
            holder: Some(1828830),
            holder_system: Some(true),
        };
        let cmds = conflict.cleanup_commands();
        assert!(!cmds.iter().any(|c| c.contains("daemon stop")), "{cmds:?}");
        assert!(cmds.iter().any(|c| c.starts_with("rm -f")), "{cmds:?}");
    }

    /// 이 테스트가 지키는 것: 목적격 조사가 받침을 따르는 것.
    /// 실서버 출력에 "설치을 중단합니다"가 그대로 찍혔다.
    #[test]
    fn the_particle_follows_the_final_consonant() {
        assert_eq!(object_particle("사용자 단위 설치"), "를");
        assert_eq!(object_particle("system 설치"), "를");
        assert_eq!(object_particle("재시작"), "을");
    }
}
