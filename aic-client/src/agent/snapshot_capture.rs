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
/// 반환=append된 레코드 경로(게이트 off로 no-op이면 `None`). L1 alert 경로(chat_tui)가 이 게이트형을 쓴다.
pub fn capture(kind: &str) -> anyhow::Result<Option<PathBuf>> {
    capture_opts(kind, false, None)
}

/// 게이트(`AIC_SNAPSHOT_RECORD`)를 **우회**해 무조건 캡처한다 — `aic snapshot capture --force` 수동 1회용.
/// passive 경로(/compare·L1)는 여전히 게이트를 따르므로 opt-in 불변식은 유지된다(명시적 force만 예외).
pub fn capture_forced(kind: &str) -> anyhow::Result<Option<PathBuf>> {
    capture_opts(kind, true, None)
}

/// [`capture_forced`] + **사람이 남긴 메모를 레코드에 함께 저장**한다(`/record now <메모>`).
///
/// 메모를 로컬에 남기는 게 이 기능의 본체다 — OTLP는 부가 경로이고, aicd 미실행은 정상 상태라
/// 원격에만 의존하면 사람이 "지금 이게 중요하다"고 남긴 관찰이 통째로 사라진다
/// (`SnapshotRecord::memo` 문서 참고).
pub fn capture_forced_with_memo(kind: &str, memo: Option<&str>) -> anyhow::Result<Option<PathBuf>> {
    capture_opts(kind, true, memo)
}

/// `force`면 게이트 무시, 아니면 opt-in 준수(off면 probe 전 early-out). 게이트는 여기와 [`store`] 두 곳에
/// 있어 force가 양쪽을 모두 통과해야 한다(early-out 우회만으론 store에서 다시 막힘).
fn capture_opts(kind: &str, force: bool, memo: Option<&str>) -> anyhow::Result<Option<PathBuf>> {
    if !force && !crate::snapshot_store::record_enabled() {
        return Ok(None); // opt-in off → probe fork 전 early-out(오버헤드 0).
    }
    let body = collect_local_body()?;
    store(kind, &body, Utc::now(), force, memo)
}

/// local probe들을 자체 sandbox로 실행해 `## name\n<redacted out>` 본문을 만든다(AgentSession 불요).
fn collect_local_body() -> anyhow::Result<String> {
    let sandbox =
        super::sandbox::Sandbox::from_cwd().map_err(|e| anyhow::anyhow!("sandbox: {e}"))?;
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

/// body를 store에 append한다(`now` 주입 → 테스트 결정성, probe 미실행). `force`가 아니면 opt-in 게이트를
/// 재확인해 off면 `Ok(None)`(capture의 early-out과 별개의 2차 게이트).
fn store(
    kind: &str,
    body: &str,
    now: DateTime<Utc>,
    force: bool,
    memo: Option<&str>,
) -> anyhow::Result<Option<PathBuf>> {
    if !force && !crate::snapshot_store::record_enabled() {
        return Ok(None);
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let rec = crate::snapshot_store::SnapshotRecord::with_memo(kind, body, None, cwd, now, memo);
    Ok(Some(crate::snapshot_store::append_snapshot(&rec)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_store::TestStore;

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
        assert!(alert_triggers_capture(&[alert(
            AlertKind::Onset,
            Severity::Warn
        )]));
        assert!(alert_triggers_capture(&[alert(
            AlertKind::Onset,
            Severity::Crit
        )]));
        assert!(!alert_triggers_capture(&[alert(
            AlertKind::Onset,
            Severity::Normal
        )]));
        assert!(!alert_triggers_capture(&[alert(
            AlertKind::Recovered,
            Severity::Crit
        )]));
        assert!(!alert_triggers_capture(&[]));
        // 여러 개 중 하나라도 Onset·Warn↑면 트리거.
        assert!(alert_triggers_capture(&[
            alert(AlertKind::Recovered, Severity::Normal),
            alert(AlertKind::Onset, Severity::Warn),
        ]));
    }

    // 격리는 `TestStore`(snapshot_store, env 미접촉)가 담당한다 — 예전 HomeGuard(HOME set_var) 대체.

    #[test]
    fn store_respects_opt_in() {
        let h = TestStore::new();
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        // off(기본): 아무것도 안 쓴다. (opt-in은 env 대신 주입 — TestStore 기본 off.)
        h.set_recording(false);
        assert!(store("alert", "## x\n1\n", now, false, None)
            .unwrap()
            .is_none());
        assert!(crate::snapshot_store::load_snapshots().unwrap().is_empty());
        // on: kind=alert 레코드 1건 저장(probe 미실행 — 결정적).
        h.set_recording(true);
        assert!(store("alert", "## host\nh\n## disk\nd\n", now, false, None)
            .unwrap()
            .is_some());
        let loaded = crate::snapshot_store::load_snapshots().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].kind, "alert");
        assert_eq!(
            loaded[0].sections,
            vec!["host".to_string(), "disk".to_string()]
        );
    }

    #[test]
    fn force_bypasses_opt_in_gate() {
        // force=true는 opt-in이 off여도 store에 쓴다(--force 수동 캡처 경로). 게이트가 2곳이라 store가
        // 직접 force를 받아 둘 다 통과하는지 확인한다.
        let _h = TestStore::new(); // 기본 off
        let now = DateTime::from_timestamp(1_700_000_100, 0).unwrap();
        assert!(
            store("manual", "## host\nh\n", now, true, None)
                .unwrap()
                .is_some(),
            "force인데 게이트에 막힘"
        );
        let loaded = crate::snapshot_store::load_snapshots().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].kind, "manual");
    }

    #[test]
    fn memo_survives_locally_even_with_no_daemon() {
        // **제품 구멍의 회귀 테스트**: `/record now <메모>`의 본질은 메모다. 예전엔 메모가 OTLP
        // 이벤트로**만** 나가서, aicd가 꺼져 있으면(문서상 **정상 상태**다) 사람이 "지금 이게
        // 중요하다"고 남긴 관찰이 통째로 사라졌다 — 스냅샷은 저장되는데 정작 메모는 어디에도 없었다.
        //
        // 이 테스트는 **네트워크를 전혀 쓰지 않는다**(store만 호출) — 즉 aicd가 없는 상황 그 자체다.
        // 그 조건에서 메모가 로컬 레코드에 남아야 한다.
        let _h = TestStore::new(); // force=true 경로라 opt-in과 무관(기본 off로 충분)
        let now = DateTime::from_timestamp(1_700_000_200, 0).unwrap();
        store(
            "manual",
            "## host\nh\n",
            now,
            true,
            Some("디스크가 이상하다"),
        )
        .unwrap();

        let loaded = crate::snapshot_store::load_snapshots().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].memo.as_deref(),
            Some("디스크가 이상하다"),
            "aicd 없이도 메모가 로컬에 남아야 한다 — 이게 이 기능의 본체다"
        );
    }

    #[test]
    fn memo_is_redacted_and_empty_memo_stays_none() {
        // 메모에도 secret이 들어올 수 있다(F14) — body/host/cwd와 동일하게 at-rest redact.
        let _h = TestStore::new();
        let now = DateTime::from_timestamp(1_700_000_300, 0).unwrap();
        store(
            "manual",
            "## host\nh\n",
            now,
            true,
            Some("bind 10.1.2.3:8080 확인"),
        )
        .unwrap();
        let memo = crate::snapshot_store::load_snapshots().unwrap()[0]
            .memo
            .clone()
            .expect("메모가 있어야");
        assert!(!memo.contains("10.1.2.3"), "메모 미마스킹: {memo}");

        // 메모 없는 캡처(기존 /record now, alert 캡처 등)는 None 그대로 — 회귀 방지.
        let now2 = DateTime::from_timestamp(1_700_000_400, 0).unwrap();
        store("alert", "## host\nh\n", now2, true, None).unwrap();
        let all = crate::snapshot_store::load_snapshots().unwrap();
        assert_eq!(all[1].memo, None, "메모 없는 캡처에 메모가 생겼다");
    }
}
