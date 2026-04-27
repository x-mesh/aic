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

/// 설치 결과 요약 — 호출자가 사용자에게 한 줄로 보여줄 수 있게.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub platform: Platform,
    pub unit_path: PathBuf,
    pub aicd_path: PathBuf,
    pub log_dir: PathBuf,
    /// load/enable까지 수행했는지(`--no-load`면 false).
    pub loaded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    pub platform: Platform,
    pub unit_path: PathBuf,
    /// 파일이 존재해서 실제로 제거했는지.
    pub removed: bool,
}

// ── 경로 결정 ──────────────────────────────────────────────────

fn home_dir() -> Result<PathBuf> {
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

/// Linux systemd user unit 경로. `XDG_CONFIG_HOME`이 있으면 우선 사용.
pub fn linux_unit_path() -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().unwrap_or_else(|_| PathBuf::from(".")).join(".config"));
    Ok(base.join("systemd").join("user").join(SYSTEMD_UNIT))
}

/// stdout/stderr가 redirect될 로그 디렉토리. `~/.local/state/aic`로 통일 —
/// telemetry 모듈이 쓰는 디렉토리와 동일.
pub fn log_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".local").join("state").join("aic"))
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

fn which_in_path(name: &str) -> Option<PathBuf> {
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
        <string>info</string>
    </dict>
</dict>
</plist>
"#,
        stdout = stdout.display(),
        stderr = stderr.display(),
    )
}

/// Linux systemd user unit (INI). `Restart=on-failure`로 keep-alive.
pub fn render_linux_service(aicd_path: &Path, log_dir: &Path) -> String {
    let aicd = aicd_path.display();
    let stdout = log_dir.join("aicd.out.log");
    let stderr = log_dir.join("aicd.err.log");
    format!(
        r#"[Unit]
Description=aic supervisor daemon (aicd)
Documentation=https://github.com/x-mesh/aic
After=default.target

[Service]
Type=simple
ExecStart={aicd}
Restart=on-failure
RestartSec=2
Environment=AIC_LOG=info
StandardOutput=append:{stdout}
StandardError=append:{stderr}

[Install]
WantedBy=default.target
"#,
        stdout = stdout.display(),
        stderr = stderr.display(),
    )
}

// ── install / uninstall ────────────────────────────────────────

/// auto-start unit을 설치한다. `no_load`가 true면 파일만 쓰고 load/enable은 안 한다.
pub fn install(no_load: bool) -> Result<InstallReport> {
    let platform = detect_platform();
    if platform == Platform::Unsupported {
        return Err(anyhow!(
            "지원하지 않는 OS: {} (macOS / Linux만 지원)",
            std::env::consts::OS
        ));
    }

    let aicd = resolve_aicd_path()?;
    let logs = log_dir()?;
    std::fs::create_dir_all(&logs)
        .with_context(|| format!("로그 디렉토리 생성 실패: {}", logs.display()))?;

    let unit_path = match platform {
        Platform::Macos => macos_plist_path()?,
        Platform::Linux => linux_unit_path()?,
        Platform::Unsupported => unreachable!(),
    };
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("unit 디렉토리 생성 실패: {}", parent.display()))?;
    }

    let body = match platform {
        Platform::Macos => render_macos_plist(&aicd, &logs),
        Platform::Linux => render_linux_service(&aicd, &logs),
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
            Platform::Linux => systemctl_user_enable_now()?,
            Platform::Unsupported => unreachable!(),
        }
    };

    Ok(InstallReport {
        platform,
        unit_path,
        aicd_path: aicd,
        log_dir: logs,
        loaded,
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
    let unit_path = match platform {
        Platform::Macos => macos_plist_path()?,
        Platform::Linux => linux_unit_path()?,
        Platform::Unsupported => unreachable!(),
    };

    // load/enable 해제는 파일 존재 여부와 무관하게 시도 — best-effort.
    match platform {
        Platform::Macos => {
            let _ = launchctl_unload(&unit_path);
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

fn systemctl_user_enable_now() -> Result<bool> {
    let reload = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output()
        .with_context(|| "systemctl --user daemon-reload 실행 실패 (systemd가 있는지 확인)")?;
    if !reload.status.success() {
        return Err(anyhow!(
            "systemctl --user daemon-reload 실패: {}",
            String::from_utf8_lossy(&reload.stderr)
        ));
    }
    let enable = Command::new("systemctl")
        .args(["--user", "enable", "--now", SYSTEMD_UNIT])
        .output()
        .with_context(|| "systemctl --user enable --now 실행 실패")?;
    if !enable.status.success() {
        return Err(anyhow!(
            "systemctl --user enable --now {SYSTEMD_UNIT} 실패: {}",
            String::from_utf8_lossy(&enable.stderr)
        ));
    }
    Ok(true)
}

fn systemctl_user_disable_now() -> Result<()> {
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", SYSTEMD_UNIT])
        .output();
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    Ok(())
}

/// 현재 설치 상태(파일 존재 여부)만 빠르게 확인한다. `aic daemon status`에서 사용.
pub fn current_unit_path() -> Option<PathBuf> {
    match detect_platform() {
        Platform::Macos => macos_plist_path().ok(),
        Platform::Linux => linux_unit_path().ok(),
        Platform::Unsupported => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
        assert_eq!(p, PathBuf::from("/tmp/aic-test-xdg/systemd/user/aicd.service"));
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
}
