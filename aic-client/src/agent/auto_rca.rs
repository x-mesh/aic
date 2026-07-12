//! Crit 이상-트리거 자동 RCA 인시던트 생성 (스냅샷 레코더 L3).
//!
//! status bar 샘플러가 **Crit Onset** 전이를 감지하면(L1 캡처의 Warn↑보다 엄격) "장애 순간"의 진단 증거를
//! 모아 RCA workspace(`rca.rs`)에 인시던트를 자동 생성한다. L1 `snapshot_capture`와 같은 standalone 패턴 —
//! `AgentSession`(&mut self) 없이 자체 `Sandbox::from_cwd()`로 Safe probe를 직접 돌린다.
//!
//! **LLM 호출 0**: `diagnose::collect_probe_evidence`(select_probes 기반)로 raw 증거를 모으고 결정적
//! `scan_findings`만 적용한다. 사용자는 나중에 `aic rca report <id>`로 LLM 분석을 붙인다.
//!
//! 증거원으로 L1 `collect_local_body`(LOCAL_SECTIONS)가 아니라 `collect_probe_evidence`(select_probes)를 쓰는
//! 이유: scan_findings가 키로 삼는 dmesg_oom·swap_usage·proc_states·failed_units·inodes가 LOCAL_SECTIONS엔
//! 없어, OOM(=Crit의 유일 신호)을 놓친다.
//!
//! 자원 증거에 더해 aicd가 살아 있으면 onset 직전 window의 터미널 명령([`terminal_evidence`])을
//! Timeline 증거로 붙인다 — "무엇이 방금 실행됐나"는 스냅샷이 답 못 하는 RCA 1순위 질문.
//!
//! [`terminal_evidence`]: super::terminal_evidence
//!
//! opt-in(`AIC_AUTO_RCA`, 기본 off, L0-L2의 AIC_SNAPSHOT_RECORD와 **독립**) · best-effort · read-only Safe.
//! 인시던트 dir 생성은 스냅샷 append보다 무거우므로 호출부(chat_tui onset)는 `spawn_blocking` detached로 돌려
//! UI를 막지 않고, 전용 `AUTO_RCA_COOLDOWN`으로 Crit flap 시 인시던트 양산을 막는다.

use super::sys_sampler::{Alert, AlertKind, Severity};
use std::time::Duration;

/// 인시던트 양산 방지 cooldown. L1 캡처(120s)의 5배 — 인시던트는 사람이 `aic rca report`로 읽는 무거운
/// 산출물이라 한 장애 구간(disk fill·OOM 스파이크)에 하나만 만든다. AlertTracker 자체 cooldown은
/// escalation(Warn→Crit)에서 우회되므로 RCA storm 방지엔 의존할 수 없어 별도로 둔다.
pub(crate) const AUTO_RCA_COOLDOWN: Duration = Duration::from_secs(600);

/// 이 alert 배치가 auto-RCA 트리거인지 — **Onset이고 Crit**일 때만(L1 캡처의 Warn↑보다 엄격). 순수 함수.
pub(crate) fn alerts_trigger_rca(alerts: &[Alert]) -> bool {
    alerts
        .iter()
        .any(|a| a.kind == AlertKind::Onset && a.severity == Severity::Crit)
}

/// auto-RCA opt-in(`AIC_AUTO_RCA`, 기본 off). AIC_SNAPSHOT_RECORD와 독립.
pub(crate) fn auto_rca_enabled() -> bool {
    crate::snapshot_store::env_enabled("AIC_AUTO_RCA")
}

/// Crit onset 시 진단 증거를 모아 RCA 인시던트를 만든다(opt-in·best-effort). off면 probe도 안 돈다.
/// 반환=생성된 incident id(off로 no-op이면 `None`). `crit_msgs`=Crit Onset 메시지들(title/symptom 소스).
pub(crate) fn capture_incident(crit_msgs: &[String]) -> anyhow::Result<Option<String>> {
    if !auto_rca_enabled() {
        return Ok(None); // opt-in off → probe fork·incident dir 생성 전 early-out(회귀 0).
    }
    let sandbox =
        super::sandbox::Sandbox::from_cwd().map_err(|e| anyhow::anyhow!("sandbox: {e}"))?;
    // Crit 메시지는 인시던트 title/symptom 텍스트로만 쓴다(증거 수집은 자원-무관 포괄 집합으로). 증상별
    // select_probes는 단일 카테고리로 좁혀 cpu/load Crit이나 복합 장애에서 scan 키를 놓치므로, RCA는
    // collect_comprehensive_evidence로 모든 scan_findings 키 섹션을 항상 수집한다.
    let symptom = (!crit_msgs.is_empty()).then(|| crit_msgs.join(" | "));
    let evidence = super::diagnose::collect_comprehensive_evidence(&sandbox, "auto-rca");
    let findings = super::diagnose::scan_findings(&evidence);
    let block = super::diagnose::render_findings_block_with(&findings, "auto-detected findings (Crit onset)");

    let title = crit_msgs
        .first()
        .map(|m| format!("auto-RCA: {}", truncate_chars(m, 60)))
        .unwrap_or_else(|| "auto-RCA: critical resource alert".to_string());
    let cwd = std::env::current_dir().ok();

    let mut meta = crate::rca::create_incident(&title, symptom.as_deref(), cwd.as_deref())?;
    // (a) Diagnosis = 결정적 findings 블록 — render_report의 Findings 섹션(kind∈{Analysis,Diagnosis})에 노출.
    let findings_body = if block.trim().is_empty() {
        "결정적 임계 스캔에서 매칭 신호 없음 — 아래 raw 진단 증거(Note) 참조.".to_string()
    } else {
        block
    };
    crate::rca::append_evidence(
        &mut meta,
        crate::rca::EvidenceKind::Diagnosis,
        "auto-detected findings",
        "aic auto-rca",
        &findings_body,
        &["auto-rca", "findings"],
    )?;
    // (b) Note = 전체 진단 증거(appendix) — Findings 섹션 필터 밖이라 본문이 Findings를 오염시키지 않는다.
    crate::rca::append_evidence(
        &mut meta,
        crate::rca::EvidenceKind::Note,
        "full diagnostic snapshot",
        "aic auto-rca",
        &evidence,
        &["auto-rca", "snapshot"],
    )?;
    // (c) Timeline = onset 직전 window의 터미널 명령(aicd 전 세션) — 자원 스냅샷이 답하지 못하는
    // "무엇이 방금 실행됐나"를 채운다. aicd 미실행/기록 없음이면 조용히 생략(best-effort).
    if let Some(body) = super::terminal_evidence::collect(chrono::Utc::now()) {
        crate::rca::append_evidence(
            &mut meta,
            crate::rca::EvidenceKind::Timeline,
            "terminal commands before onset",
            "aicd command store",
            &body,
            &["auto-rca", "terminal"],
        )?;
    }
    // (d) Diagnosis = baseline 대비 프로세스 rss 성장 리더보드(결정적, LLM 0) — "어느 프로세스가
    // 자랐나"로 범인 후보를 좁힌다. baseline은 L0 store의 onset 120s+ 이전 최신 mem_top_proc
    // 스냅샷(같은 순간의 alert 캡처는 이미 부푼 상태라 부적격). store 미기록·섹션 부재·성장 0이면 생략.
    let snapshots = crate::snapshot_store::load_snapshots().unwrap_or_default();
    if let Some(body) =
        super::proc_delta::growth_evidence(&snapshots, &evidence, chrono::Utc::now())
    {
        crate::rca::append_evidence(
            &mut meta,
            crate::rca::EvidenceKind::Diagnosis,
            "process rss growth since baseline",
            "aic auto-rca",
            &body,
            &["auto-rca", "proc-delta"],
        )?;
    }
    Ok(Some(meta.id))
}

/// char 경계 안전 truncation(멀티바이트 분할 방지). 초과 시 말줄임표.
/// terminal_evidence의 명령 한 줄 truncation도 이 헬퍼를 공유한다.
pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;
    use tempfile::TempDir;

    fn alert(kind: AlertKind, severity: Severity, msg: &str) -> Alert {
        Alert {
            severity,
            kind,
            message: msg.to_string(),
        }
    }

    #[test]
    fn trigger_predicate_crit_onset_only() {
        // Crit Onset만 트리거(L1보다 엄격). Warn Onset·Crit Recovered·빈 배치는 아님.
        assert!(alerts_trigger_rca(&[alert(AlertKind::Onset, Severity::Crit, "x")]));
        assert!(!alerts_trigger_rca(&[alert(AlertKind::Onset, Severity::Warn, "x")]));
        assert!(!alerts_trigger_rca(&[alert(AlertKind::Recovered, Severity::Crit, "x")]));
        assert!(!alerts_trigger_rca(&[]));
        // 여러 개 중 하나라도 Crit Onset이면 트리거.
        assert!(alerts_trigger_rca(&[
            alert(AlertKind::Onset, Severity::Warn, "w"),
            alert(AlertKind::Onset, Severity::Crit, "c"),
        ]));
    }

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate_chars("  hi  ", 60), "hi");
        let long = "가".repeat(80);
        let t = truncate_chars(&long, 60);
        assert_eq!(t.chars().count(), 61); // 60 + '…'
        assert!(t.ends_with('…'));
    }

    // HOME 격리 + env 직렬화(snapshot_store와 동일한 프로세스 전역 락 공유).
    // AIC_AICD_SOCKET도 격리한다 — aicd 소켓은 `/tmp/aic-{uid}` 아래라 HOME 격리로는
    // 안 가려져, 개발 머신에서 실제 aicd가 돌고 있으면 terminal 증거가 끼어들어
    // evidence_count 단정이 비결정적이 된다. 기본은 tempdir 내 미존재 경로(= aicd 없음).
    struct HomeGuard {
        prev_home: Option<std::ffi::OsString>,
        prev_rca: Option<std::ffi::OsString>,
        prev_sock: Option<std::ffi::OsString>,
        _lock: MutexGuard<'static, ()>,
        dir: TempDir,
    }
    impl HomeGuard {
        fn set() -> Self {
            let lock = crate::snapshot_store::home_test_lock()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = TempDir::new().unwrap();
            let prev_home = std::env::var_os("HOME");
            let prev_rca = std::env::var_os("AIC_AUTO_RCA");
            let prev_sock = std::env::var_os("AIC_AICD_SOCKET");
            unsafe {
                std::env::set_var("HOME", dir.path());
                std::env::set_var("AIC_AICD_SOCKET", dir.path().join("no-aicd.sock"));
            }
            Self {
                prev_home,
                prev_rca,
                prev_sock,
                _lock: lock,
                dir,
            }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev_home.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
                match self.prev_rca.take() {
                    Some(v) => std::env::set_var("AIC_AUTO_RCA", v),
                    None => std::env::remove_var("AIC_AUTO_RCA"),
                }
                match self.prev_sock.take() {
                    Some(v) => std::env::set_var("AIC_AICD_SOCKET", v),
                    None => std::env::remove_var("AIC_AICD_SOCKET"),
                }
            }
        }
    }

    #[test]
    fn gated_off_is_noop() {
        // off(기본): probe도 안 돌고 인시던트도 안 만든다.
        let _h = HomeGuard::set();
        unsafe {
            std::env::remove_var("AIC_AUTO_RCA");
        }
        assert!(capture_incident(&["cpu 99%".to_string()]).unwrap().is_none());
        assert!(crate::rca::list_incidents().unwrap().is_empty());
    }

    #[test]
    fn on_creates_incident_with_findings_and_snapshot() {
        // on: 실제 Safe probe를 돌려 인시던트 1건 생성 — lifecycle(create) + Diagnosis(findings) +
        // Note(snapshot) = evidence 3건. probe 출력은 비결정적이지만 인시던트 구조는 결정적.
        let _h = HomeGuard::set();
        unsafe {
            std::env::set_var("AIC_AUTO_RCA", "1");
        }
        let id = capture_incident(&["memory 98% critical".to_string()])
            .unwrap()
            .expect("on인데 인시던트 미생성");
        let list = crate::rca::list_incidents().unwrap();
        assert_eq!(list.len(), 1);
        let meta = crate::rca::load_meta(&id).unwrap();
        assert_eq!(meta.evidence_count, 3, "lifecycle+findings+snapshot = 3건");
        assert!(meta.title.starts_with("auto-RCA:"));
        assert_eq!(meta.symptom.as_deref(), Some("memory 98% critical"));
        // Note 증거에 raw 진단 본문(## 섹션)이 들어갔는지.
        let events = crate::rca::load_events(&id).unwrap();
        assert!(events.iter().any(|e| e.kind == crate::rca::EvidenceKind::Note
            && e.tags.iter().any(|t| t == "snapshot")));
    }

    #[test]
    fn on_appends_terminal_timeline_when_aicd_reachable() {
        // aicd(mock)가 살아 있고 window 내 명령이 있으면 Timeline 증거가 4번째로 붙는다.
        let h = HomeGuard::set();
        let sock = h.dir.path().join("mock-aicd.sock");
        let mut records = std::collections::HashMap::new();
        records.insert(
            "aaaa0001".to_string(),
            vec![aic_common::CommandRecord {
                command: Some("docker build -t big-image .".to_string()),
                exit_code: 0,
                timestamp: chrono::Utc::now() - chrono::Duration::seconds(60),
                ..Default::default()
            }],
        );
        let _mock = super::super::terminal_evidence::spawn_mock_aicd(
            &sock,
            vec![aic_common::SessionInfo {
                id: "aaaa0001".to_string(),
                pid: 1,
                state: aic_common::SessionState::Attached,
                created_at: chrono::Utc::now(),
                last_seen_at: None,
                last_command_at: None,
                attached_tty: None,
                shell: None,
                cwd: None,
                label: None,
            }],
            records,
        );
        unsafe {
            std::env::set_var("AIC_AUTO_RCA", "1");
            std::env::set_var("AIC_AICD_SOCKET", &sock);
        }
        let id = capture_incident(&["memory 98% critical".to_string()])
            .unwrap()
            .expect("on인데 인시던트 미생성");
        let meta = crate::rca::load_meta(&id).unwrap();
        assert_eq!(
            meta.evidence_count, 4,
            "lifecycle+findings+snapshot+terminal = 4건"
        );
        let events = crate::rca::load_events(&id).unwrap();
        let timeline = events
            .iter()
            .find(|e| e.kind == crate::rca::EvidenceKind::Timeline)
            .expect("terminal Timeline 증거");
        assert!(timeline.tags.iter().any(|t| t == "terminal"));
        assert!(timeline.body.contains("docker build -t big-image ."));
    }

    #[test]
    fn on_appends_proc_delta_when_baseline_exists() {
        // L0 store에 onset 이전 baseline이 있으면 프로세스 rss 성장 리더보드가 Diagnosis로 붙는다.
        // baseline pid는 가짜라 현재 프로세스가 전부 (new)로 잡혀 리더보드가 반드시 생긴다.
        let _h = HomeGuard::set();
        let baseline = crate::snapshot_store::SnapshotRecord::new(
            "periodic",
            "## mem_top_proc\n  PID COMM RSS\n  999999 fake-proc 1024\n",
            None,
            None,
            chrono::Utc::now() - chrono::Duration::minutes(10),
        );
        crate::snapshot_store::append_snapshot(&baseline).unwrap();
        unsafe {
            std::env::set_var("AIC_AUTO_RCA", "1");
        }
        let id = capture_incident(&["memory 98% critical".to_string()])
            .unwrap()
            .expect("on인데 인시던트 미생성");
        let meta = crate::rca::load_meta(&id).unwrap();
        assert_eq!(
            meta.evidence_count, 4,
            "lifecycle+findings+snapshot+proc-delta = 4건"
        );
        let events = crate::rca::load_events(&id).unwrap();
        let delta = events
            .iter()
            .find(|e| e.tags.iter().any(|t| t == "proc-delta"))
            .expect("proc-delta Diagnosis 증거");
        assert_eq!(delta.kind, crate::rca::EvidenceKind::Diagnosis);
        assert!(delta.body.contains("(new)"), "가짜 baseline 대비 전부 new");
    }
}
