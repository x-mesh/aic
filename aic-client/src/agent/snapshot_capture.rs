//! 이상-트리거 전체 /local 스냅샷 캡처 (스냅샷 레코더 L1).
//!
//! status bar 샘플러의 Severity 전이(Warn/Crit Onset) 시 "장애 순간의 전체 상태"를 캡처해 영구 store에
//! 남긴다. 핵심: `AgentSession::collect_local_snapshot`은 `&mut self`+sandbox가 필요해 백그라운드/alert
//! 컨텍스트에서 못 부른다 → 여기 **standalone capture**는 자체 `Sandbox::from_cwd()`로 probe를 직접 돌려
//! AgentSession 없이 동일한 redacted 스냅샷을 만든다.
//!
//! opt-in(`AIC_SNAPSHOT_RECORD`, 기본 off) · best-effort · read-only Safe probe만. probe 다수×timeout이라
//! 호출부(chat_tui onset 분기)는 `spawn_blocking`으로 detached 실행해 UI/응답을 막지 않는다.

use super::sys_sampler::{Alert, AlertKind, Severity};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::time::Duration;

/// 캡처 storm 방지용 cooldown. AlertTracker 자체 cooldown(120s/300s)은 escalation(Warn→Crit)에서 우회되므로
/// 캡처에는 별도 한도를 둔다 — 같은 장애 구간에 전체 probe를 반복 fork하지 않게.
pub(crate) const CAPTURE_COOLDOWN: Duration = Duration::from_secs(120);

/// 이 alert 배치가 캡처 트리거인지 — **Onset이고 Warn 이상**일 때만. 회복(Recovered, Severity::Normal)은
/// 장애 순간이 아니므로 제외한다. 순수 함수(테스트 가능).
pub(crate) fn alert_triggers_capture(alerts: &[Alert]) -> bool {
    alerts
        .iter()
        .any(|a| a.kind == AlertKind::Onset && a.severity >= Severity::Warn)
}

/// 전체 /local 스냅샷을 자체 Sandbox로 수집해 store에 append한다(opt-in·best-effort). off면 probe도 안 돈다.
pub(crate) fn capture(kind: &str) -> anyhow::Result<()> {
    if !crate::snapshot_store::record_enabled() {
        return Ok(()); // opt-in off → probe fork 전 early-out(오버헤드 0).
    }
    let body = collect_local_body()?;
    store_if_enabled(kind, &body, Utc::now())?;
    Ok(())
}

/// local probe들을 자체 sandbox로 실행해 `## name\n<redacted out>` 본문을 만든다(AgentSession 불요).
fn collect_local_body() -> anyhow::Result<String> {
    let sandbox = super::sandbox::Sandbox::from_cwd().map_err(|e| anyhow::anyhow!("sandbox: {e}"))?;
    let mut body = String::new();
    for (idx, (name, cmd)) in super::sysinfo::local_probes().into_iter().enumerate() {
        let corr = format!("snap.{idx}");
        let args = serde_json::json!({ "command": cmd });
        // Safe 명령이라 confirm 미호출이지만 비대화 안전을 위해 거부 클로저 전달(NeedsConfirm 자동 실행 안 됨).
        let out = super::run_command::execute_with_corr(&args, &sandbox, &corr, |_, _, _| false)
            .unwrap_or_else(|e| format!("[tool error] {e}"));
        body.push_str(&format!("## {name}\n{out}\n\n"));
    }
    Ok(body)
}

/// opt-in이면 body를 store에 append한다(`now` 주입 → 테스트 결정성, probe 미실행). off면 `Ok(None)`.
fn store_if_enabled(kind: &str, body: &str, now: DateTime<Utc>) -> anyhow::Result<Option<PathBuf>> {
    if !crate::snapshot_store::record_enabled() {
        return Ok(None);
    }
    let cwd = std::env::current_dir().ok().map(|p| p.display().to_string());
    let rec = crate::snapshot_store::SnapshotRecord::new(kind, body, None, cwd, now);
    Ok(Some(crate::snapshot_store::append_snapshot(&rec)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use tempfile::TempDir;

    fn alert(kind: AlertKind, severity: Severity) -> Alert {
        Alert {
            severity,
            kind,
            message: "x".to_string(),
        }
    }

    #[test]
    fn capture_predicate_onset_warn_or_above_only() {
        // Onset·Warn 이상만 트리거. 회복/Normal/빈 배치는 트리거 아님.
        assert!(alert_triggers_capture(&[alert(AlertKind::Onset, Severity::Warn)]));
        assert!(alert_triggers_capture(&[alert(AlertKind::Onset, Severity::Crit)]));
        assert!(!alert_triggers_capture(&[alert(AlertKind::Onset, Severity::Normal)]));
        assert!(!alert_triggers_capture(&[alert(AlertKind::Recovered, Severity::Crit)]));
        assert!(!alert_triggers_capture(&[]));
        // 여러 개 중 하나라도 Onset·Warn↑면 트리거.
        assert!(alert_triggers_capture(&[
            alert(AlertKind::Recovered, Severity::Normal),
            alert(AlertKind::Onset, Severity::Warn),
        ]));
    }

    // HOME 격리 + env 직렬화(snapshot_store 테스트와 동일 패턴).
    struct HomeGuard {
        prev: Option<std::ffi::OsString>,
        _lock: MutexGuard<'static, ()>,
        _dir: TempDir,
    }
    impl HomeGuard {
        fn set() -> Self {
            static HOME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = HOME_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let dir = TempDir::new().unwrap();
            let prev = std::env::var_os("HOME");
            unsafe {
                std::env::set_var("HOME", dir.path());
            }
            Self {
                prev,
                _lock: lock,
                _dir: dir,
            }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    #[test]
    fn store_if_enabled_respects_opt_in() {
        let _h = HomeGuard::set();
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        // off(기본): 아무것도 안 쓴다.
        unsafe {
            std::env::remove_var("AIC_SNAPSHOT_RECORD");
        }
        assert!(store_if_enabled("alert", "## x\n1\n", now).unwrap().is_none());
        assert!(crate::snapshot_store::load_snapshots().unwrap().is_empty());
        // on: kind=alert 레코드 1건 저장(probe 미실행 — 결정적).
        unsafe {
            std::env::set_var("AIC_SNAPSHOT_RECORD", "1");
        }
        assert!(store_if_enabled("alert", "## host\nh\n## disk\nd\n", now)
            .unwrap()
            .is_some());
        let loaded = crate::snapshot_store::load_snapshots().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].kind, "alert");
        assert_eq!(loaded[0].sections, vec!["host".to_string(), "disk".to_string()]);
        unsafe {
            std::env::remove_var("AIC_SNAPSHOT_RECORD");
        }
    }
}
