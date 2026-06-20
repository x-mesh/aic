//! `aic snapshot install/uninstall/status` — 주기 캡처 타이머 unit 관리 (스냅샷 레코더 L2).
//!
//! [`crate::daemon_install`]의 aicd **supervisor**(장기 실행, RunAtLoad+KeepAlive / Restart=on-failure)와 달리
//! 이건 **one-shot 타이머**: N초마다 `aic snapshot capture`를 띄워 캡처 후 종료한다.
//! - macOS: `~/Library/LaunchAgents/com.x-mesh.aic-snapshot.plist` (launchd `StartInterval`, KeepAlive 없음)
//! - Linux: `~/.config/systemd/user/aic-snapshot.{timer,service}` (systemd `.timer` + `Type=oneshot` `.service`)
//!
//! 공용 OS plumbing(detect_platform/home_dir/log_dir/which_in_path)은 daemon_install에서 재사용한다. unit 본문·
//! 라벨·lifecycle만 supervisor와 다르다.
//!
//! **opt-in 경계:** 타이머 unit이 env로 `AIC_SNAPSHOT_RECORD=1`을 주입하므로 **타이머 설치 = 기록 동의**.
//! launchd agent와 systemd --user service는 사용자 셸 env를 상속하지 않아, 주입이 없으면 매 발화가
//! `record_enabled()` off로 silent no-op이 된다(설치는 성공하는데 아무것도 안 쌓이는 최악의 버그). capture는
//! 여전히 게이트를 따르고, 그 게이트를 unit env가 켜 준다.

use crate::daemon_install::{detect_platform, home_dir, log_dir, which_in_path, Platform};
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// macOS launchd Label / Linux unit basename 접두.
pub const LAUNCHD_LABEL: &str = "com.x-mesh.aic-snapshot";
/// Linux systemd `.timer` 파일명.
pub const TIMER_UNIT: &str = "aic-snapshot.timer";
/// Linux systemd `.service` 파일명(타이머가 발화시키는 oneshot).
pub const SERVICE_UNIT: &str = "aic-snapshot.service";
/// `--interval` 생략 시 기본 캡처 간격(초). store 보관 200개 × 300초 ≈ 16.6시간 증거 윈도우.
pub const SNAPSHOT_INTERVAL_DEFAULT_SECS: u64 = 300;
/// 최소 간격(초). 1초 같은 병적 간격이 probe fork를 폭주시키고 store ring을 수분에 회전시키는 걸 막는다.
pub const SNAPSHOT_INTERVAL_MIN_SECS: u64 = 60;

/// `SNAPSHOT_INTERVAL_MIN_SECS` 하한으로 clamp.
pub fn clamp_interval(secs: u64) -> u64 {
    secs.max(SNAPSHOT_INTERVAL_MIN_SECS)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerInstallReport {
    pub platform: Platform,
    /// 주 unit 경로(macOS plist / Linux .timer).
    pub unit_path: PathBuf,
    pub aic_path: PathBuf,
    pub log_dir: PathBuf,
    pub interval_secs: u64,
    /// load/enable까지 수행했는지(`--no-load`면 false).
    pub loaded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerUninstallReport {
    pub platform: Platform,
    pub unit_path: PathBuf,
    /// 주 unit 파일이 존재해서 실제 제거했는지.
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerStatus {
    pub platform: Platform,
    pub installed: bool,
    pub unit_path: Option<PathBuf>,
    /// 설치된 unit 파일에서 역파싱한 간격(초). 손편집/파싱 실패면 None.
    pub interval_secs: Option<u64>,
}

// ── 경로 결정 ──────────────────────────────────────────────────

fn macos_plist_path() -> Result<PathBuf> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

fn systemd_user_dir() -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".config")
        });
    Ok(base.join("systemd").join("user"))
}

fn linux_timer_path() -> Result<PathBuf> {
    Ok(systemd_user_dir()?.join(TIMER_UNIT))
}

fn linux_service_path() -> Result<PathBuf> {
    Ok(systemd_user_dir()?.join(SERVICE_UNIT))
}

/// 타이머가 실행할 `aic` **자기 자신** 절대경로. daemon_install::resolve_aicd_path(sibling `aicd`)와 달리
/// current_exe(=현재 실행 중인 aic)를 쓴다 — aicd엔 `snapshot capture` 서브커맨드가 없으므로 반드시 aic여야 함.
pub fn resolve_aic_path() -> Result<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        // symlink(brew 등) 추적. canonicalize 실패하면 원경로 사용.
        let exe = exe.canonicalize().unwrap_or(exe);
        if exe.exists() {
            return Ok(exe);
        }
    }
    which_in_path("aic")
        .ok_or_else(|| anyhow!("aic 실행 파일을 찾을 수 없습니다 (current_exe/PATH 모두 실패)"))
}

// ── Unit 파일 렌더링 ──────────────────────────────────────────

/// macOS launchd plist — one-shot 주기 캡처. `StartInterval`로 N초마다 재실행, KeepAlive 없음(짧은 종료를
/// crash로 오인해 tight-loop 재spawn하는 걸 방지). RunAtLoad로 설치 즉시 1회 캡처. AIC_SNAPSHOT_RECORD=1 주입.
pub fn render_macos_plist(aic_path: &Path, log_dir: &Path, interval_secs: u64) -> String {
    let aic = aic_path.display();
    let stdout = log_dir.join("aic-snapshot.out.log");
    let stderr = log_dir.join("aic-snapshot.err.log");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{aic}</string>
        <string>snapshot</string>
        <string>capture</string>
    </array>
    <key>StartInterval</key>
    <integer>{interval_secs}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AIC_SNAPSHOT_RECORD</key>
        <string>1</string>
    </dict>
</dict>
</plist>
"#,
        stdout = stdout.display(),
        stderr = stderr.display(),
    )
}

/// Linux systemd `.service` — `Type=oneshot`, 타이머가 발화시킨다. AIC_SNAPSHOT_RECORD=1 주입.
pub fn render_linux_service(aic_path: &Path, log_dir: &Path) -> String {
    let aic = aic_path.display();
    let stdout = log_dir.join("aic-snapshot.out.log");
    let stderr = log_dir.join("aic-snapshot.err.log");
    format!(
        r#"[Unit]
Description=aic periodic snapshot capture (oneshot)
Documentation=https://github.com/x-mesh/aic

[Service]
Type=oneshot
ExecStart={aic} snapshot capture
Environment=AIC_SNAPSHOT_RECORD=1
StandardOutput=append:{stdout}
StandardError=append:{stderr}
"#,
        stdout = stdout.display(),
        stderr = stderr.display(),
    )
}

/// Linux systemd `.timer` — `OnUnitActiveSec`로 직전 실행 종료 후 N초 간격. 첫 발화는 `OnActiveSec=0`으로 타이머
/// **활성화(enable --now) 즉시** 한다(macOS `RunAtLoad` 대응). `OnBootSec`은 user-manager 시작(로그인) 기준이라
/// 활성화 시각과 무관 — 로그인 직후 설치하면 첫 캡처가 interval만큼 늦으므로 쓰지 않는다. `WantedBy=timers.target`
/// 이라 `systemctl --user list-timers`에 보인다.
pub fn render_linux_timer(interval_secs: u64) -> String {
    format!(
        r#"[Unit]
Description=aic periodic snapshot capture timer
Documentation=https://github.com/x-mesh/aic

[Timer]
OnActiveSec=0
OnUnitActiveSec={interval_secs}
Unit={SERVICE_UNIT}

[Install]
WantedBy=timers.target
"#
    )
}

// ── install / uninstall / status ───────────────────────────────

fn write_if_changed(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("unit 디렉토리 생성 실패: {}", parent.display()))?;
    }
    // 멱등: 같은 내용이면 write skip(mtime 보존 → 불필요한 systemd reload 회피).
    let needs_write = match std::fs::read_to_string(path) {
        Ok(existing) => existing != body,
        Err(_) => true,
    };
    if needs_write {
        std::fs::write(path, body)
            .with_context(|| format!("unit 파일 쓰기 실패: {}", path.display()))?;
    }
    Ok(())
}

/// 주기 캡처 타이머를 설치한다. `no_load`면 파일만 쓰고 launchctl/systemctl load는 안 한다.
pub fn install(interval_secs: u64, no_load: bool) -> Result<TimerInstallReport> {
    let platform = detect_platform();
    if platform == Platform::Unsupported {
        return Err(anyhow!(
            "지원하지 않는 OS: {} (macOS / Linux만 지원)",
            std::env::consts::OS
        ));
    }
    let interval = clamp_interval(interval_secs);
    let aic = resolve_aic_path()?;
    let logs = log_dir()?;
    std::fs::create_dir_all(&logs)
        .with_context(|| format!("로그 디렉토리 생성 실패: {}", logs.display()))?;

    let (unit_path, loaded) = match platform {
        Platform::Macos => {
            let plist = macos_plist_path()?;
            write_if_changed(&plist, &render_macos_plist(&aic, &logs, interval))?;
            let loaded = if no_load {
                false
            } else {
                launchctl_load(&plist)?
            };
            (plist, loaded)
        }
        Platform::Linux => {
            let timer = linux_timer_path()?;
            let service = linux_service_path()?;
            write_if_changed(&service, &render_linux_service(&aic, &logs))?;
            write_if_changed(&timer, &render_linux_timer(interval))?;
            let loaded = if no_load {
                false
            } else {
                systemctl_enable_now()?
            };
            (timer, loaded)
        }
        Platform::Unsupported => unreachable!(),
    };

    Ok(TimerInstallReport {
        platform,
        unit_path,
        aic_path: aic,
        log_dir: logs,
        interval_secs: interval,
        loaded,
    })
}

/// 타이머를 제거한다. Linux는 .timer와 .service **둘 다** unload+삭제(orphan .service 방지).
pub fn uninstall() -> Result<TimerUninstallReport> {
    let platform = detect_platform();
    if platform == Platform::Unsupported {
        return Err(anyhow!(
            "지원하지 않는 OS: {} (macOS / Linux만 지원)",
            std::env::consts::OS
        ));
    }
    match platform {
        Platform::Macos => {
            let plist = macos_plist_path()?;
            let _ = launchctl_unload(&plist);
            let removed = remove_if_exists(&plist)?;
            Ok(TimerUninstallReport {
                platform,
                unit_path: plist,
                removed,
            })
        }
        Platform::Linux => {
            let timer = linux_timer_path()?;
            let service = linux_service_path()?;
            let _ = systemctl_disable_now();
            // 두 파일 다 제거 — .service만 남기면 dangling unit이 된다. removed는 주 unit(.timer) 기준.
            let removed = remove_if_exists(&timer)?;
            let _ = remove_if_exists(&service);
            let _ = systemctl_daemon_reload();
            Ok(TimerUninstallReport {
                platform,
                unit_path: timer,
                removed,
            })
        }
        Platform::Unsupported => unreachable!(),
    }
}

/// 현재 타이머 설치 상태(파일 존재 + 역파싱한 간격)를 반환한다.
pub fn status() -> TimerStatus {
    let platform = detect_platform();
    let unit_path = match platform {
        Platform::Macos => macos_plist_path().ok(),
        Platform::Linux => linux_timer_path().ok(),
        Platform::Unsupported => None,
    };
    let installed = unit_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    let interval_secs = if installed {
        unit_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|body| parse_interval(platform, &body))
    } else {
        None
    };
    TimerStatus {
        platform,
        installed,
        unit_path,
        interval_secs,
    }
}

/// 설치된 unit 파일에서 간격을 역파싱한다(macOS `StartInterval`, Linux `OnUnitActiveSec`).
fn parse_interval(platform: Platform, body: &str) -> Option<u64> {
    match platform {
        Platform::Macos => {
            // <key>StartInterval</key> 다음 줄의 <integer>N</integer>.
            let lines: Vec<&str> = body.lines().collect();
            for (i, l) in lines.iter().enumerate() {
                if l.contains("<key>StartInterval</key>") {
                    let next = lines.get(i + 1)?.trim();
                    let inner = next
                        .strip_prefix("<integer>")?
                        .strip_suffix("</integer>")?;
                    return inner.trim().parse().ok();
                }
            }
            None
        }
        Platform::Linux => body.lines().find_map(|l| {
            l.trim()
                .strip_prefix("OnUnitActiveSec=")
                .and_then(|v| v.trim().parse().ok())
        }),
        Platform::Unsupported => None,
    }
}

fn remove_if_exists(path: &Path) -> Result<bool> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("unit 파일 삭제 실패: {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ── OS 호출 (daemon_install의 supervisor 경로와 같은 패턴, unit 이름만 다름) ──

fn launchctl_load(plist: &Path) -> Result<bool> {
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    let bootstrap = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(plist)
        .output();
    match bootstrap {
        Ok(out) if out.status.success() => Ok(true),
        Ok(out) => {
            // 이미 load 되어 있으면 bootstrap이 실패한다(exit 37 등) — 그 경우는 OK.
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("already") || stderr.contains("Service") {
                return Ok(true);
            }
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
    let _ = Command::new("launchctl").arg("unload").arg(plist).output();
    Ok(())
}

fn systemctl_enable_now() -> Result<bool> {
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
    // 타이머만 enable --now (서비스는 발화 때마다 끌려온다).
    let enable = Command::new("systemctl")
        .args(["--user", "enable", "--now", TIMER_UNIT])
        .output()
        .with_context(|| "systemctl --user enable --now 실행 실패")?;
    if !enable.status.success() {
        return Err(anyhow!(
            "systemctl --user enable --now {TIMER_UNIT} 실패: {}",
            String::from_utf8_lossy(&enable.stderr)
        ));
    }
    Ok(true)
}

fn systemctl_disable_now() -> Result<()> {
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", TIMER_UNIT])
        .output();
    Ok(())
}

fn systemctl_daemon_reload() -> Result<()> {
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_plist_is_oneshot_timer_running_aic_snapshot_capture() {
        let p = render_macos_plist(Path::new("/opt/bin/aic"), Path::new("/var/log/aic"), 300);
        assert!(p.starts_with("<?xml"));
        assert!(p.contains(LAUNCHD_LABEL));
        // one-shot 타이머: StartInterval 있고 KeepAlive 없음(있으면 tight-loop 재spawn).
        assert!(p.contains("<key>StartInterval</key>"));
        assert!(p.contains("<integer>300</integer>"));
        assert!(!p.contains("KeepAlive"), "타이머에 KeepAlive가 있으면 안 됨");
        // aic(자기 자신) + snapshot capture 서브커맨드.
        assert!(p.contains("<string>/opt/bin/aic</string>"));
        assert!(p.contains("<string>snapshot</string>"));
        assert!(p.contains("<string>capture</string>"));
        // opt-in env 주입(없으면 매 발화 no-op).
        assert!(p.contains("AIC_SNAPSHOT_RECORD"));
        assert!(p.contains("/var/log/aic/aic-snapshot.out.log"));
    }

    #[test]
    fn linux_timer_and_service_shape() {
        let svc = render_linux_service(Path::new("/usr/local/bin/aic"), Path::new("/var/log/aic"));
        assert!(svc.contains("Type=oneshot"));
        assert!(svc.contains("ExecStart=/usr/local/bin/aic snapshot capture"));
        assert!(svc.contains("Environment=AIC_SNAPSHOT_RECORD=1"));
        assert!(svc.contains("append:/var/log/aic/aic-snapshot.out.log"));

        let timer = render_linux_timer(300);
        assert!(timer.contains("[Timer]"));
        assert!(timer.contains("OnUnitActiveSec=300"));
        // 첫 발화는 활성화 즉시(OnActiveSec=0) — 로그인 기준 OnBootSec은 쓰지 않는다.
        assert!(timer.contains("OnActiveSec=0"));
        assert!(!timer.contains("OnBootSec"), "OnBootSec은 로그인 기준이라 쓰면 안 됨");
        assert!(timer.contains(&format!("Unit={SERVICE_UNIT}")));
        assert!(timer.contains("WantedBy=timers.target"));
    }

    #[test]
    fn interval_is_clamped_to_min() {
        assert_eq!(clamp_interval(1), SNAPSHOT_INTERVAL_MIN_SECS);
        assert_eq!(clamp_interval(0), SNAPSHOT_INTERVAL_MIN_SECS);
        assert_eq!(clamp_interval(300), 300);
        assert_eq!(clamp_interval(SNAPSHOT_INTERVAL_MIN_SECS), SNAPSHOT_INTERVAL_MIN_SECS);
    }

    #[test]
    fn parse_interval_roundtrips_render() {
        // render → parse_interval로 간격을 그대로 복원(status 역파싱 정확성).
        let mac = render_macos_plist(Path::new("/x/aic"), Path::new("/l"), 420);
        assert_eq!(parse_interval(Platform::Macos, &mac), Some(420));
        let timer = render_linux_timer(540);
        assert_eq!(parse_interval(Platform::Linux, &timer), Some(540));
        // 손편집/누락 → None.
        assert_eq!(parse_interval(Platform::Macos, "<plist></plist>"), None);
        assert_eq!(parse_interval(Platform::Linux, "[Timer]\n"), None);
    }
}
