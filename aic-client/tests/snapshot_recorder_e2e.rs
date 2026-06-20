//! 스냅샷 레코더(L0-L3) e2e 테스트 — 실제 `aic` 바이너리를 격리된 HOME에서 subprocess로 돌려
//! 유닛 테스트가 못 잡는 경계를 고정한다:
//! - opt-in 게이트 off일 때 디스크 산출물 0(회귀 0)
//! - `aic snapshot capture --force`의 실제 캡처→store append(L0/L1 머신리)
//! - `aic snapshot list/status --json` 봉투(본문 미유출)
//! - 주기 타이머 unit install/status(역파싱)/uninstall(L2)
//! - **진짜 다중 프로세스** 동시 캡처의 잃은 쓰기 0 — cross-process flock(L2). 유닛 테스트는
//!   in-process(Mutex)만 검증하므로 이 시나리오가 별도 프로세스 flock을 직접 친다.
//! - `aic rca start --diagnose --no-analyze`의 인시던트+증거 생성(L3 auto-RCA가 쓰는 머신리)
//!
//! 외부 LLM/네트워크 없이 동작(--no-analyze / probe만).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// HOME/XDG를 임시 격리한 aic 명령(실제 홈 오염 방지 + keychain 우회). e2e_headless.rs와 동형.
fn aic_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aic"));
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("cfg"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("AIC_NO_KEYCHAIN", "1")
        .env("NO_COLOR", "1")
        // 부모 환경의 레코더 게이트가 새지 않도록 명시적으로 제거(테스트별로 켠다).
        .env_remove("AIC_SNAPSHOT_RECORD")
        .env_remove("AIC_AUTO_RCA")
        .stdin(std::process::Stdio::null());
    cmd
}

fn snapshots_file(home: &Path) -> PathBuf {
    home.join(".aic").join("snapshots").join("snapshots.jsonl")
}

/// JSONL을 레코드 줄 단위로 읽는다(빈 줄·깨진 줄 제외 후 파싱).
fn load_records(home: &Path) -> Vec<serde_json::Value> {
    let path = snapshots_file(home);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect()
}

// ── L0/L1: gate off = 회귀 0 ───────────────────────────────────

#[test]
fn capture_without_gate_or_force_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    // 게이트 off(env 미설정) + --force 없음 → 아무것도 안 쓰고 exit 0.
    let out = aic_cmd(tmp.path())
        .args(["snapshot", "capture"])
        .output()
        .expect("aic snapshot capture 실행 실패");
    assert!(out.status.success(), "exit 비정상: {:?}", out.status);
    assert!(
        !snapshots_file(tmp.path()).exists(),
        "게이트 off인데 store 파일이 생성됨"
    );
}

// ── L0/L1: --force 실제 캡처 → store append + list/status ───────

#[test]
fn force_capture_writes_record_and_list_status_reflect_it() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aic_cmd(tmp.path())
        .args(["snapshot", "capture", "--force", "--kind", "e2e"])
        .output()
        .expect("capture --force 실행 실패");
    assert!(out.status.success(), "capture --force exit: {:?}", out.status);

    // 레코드 1건, kind=e2e, sections 비어있지 않음, 본문 존재.
    let recs = load_records(tmp.path());
    assert_eq!(recs.len(), 1, "레코드 1건이어야: {recs:?}");
    assert_eq!(recs[0]["kind"], "e2e");
    assert!(
        recs[0]["sections"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "sections가 비어있음: {}",
        recs[0]
    );
    assert!(recs[0]["body"].as_str().map(|b| b.contains("## ")).unwrap_or(false));

    // list --json: schema_version 봉투, 메타만(본문 필드 미유출).
    let list = aic_cmd(tmp.path())
        .args(["snapshot", "list", "--json"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let lv: serde_json::Value = serde_json::from_slice(&list.stdout).expect("list --json은 JSON");
    assert_eq!(lv["schema_version"], 1);
    assert_eq!(lv["total"], 1);
    let snaps = lv["snapshots"].as_array().expect("snapshots 배열");
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0]["kind"], "e2e");
    assert!(snaps[0].get("body").is_none(), "list --json에 본문이 유출됨: {}", snaps[0]);

    // status --json: store + 게이트(record_enabled=false, --force는 게이트를 안 켠다) + 타이머 미설치.
    let status = aic_cmd(tmp.path())
        .args(["snapshot", "status", "--json"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let sv: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status --json은 JSON");
    assert_eq!(sv["record_count"], 1);
    assert_eq!(sv["record_enabled"], false, "--force는 게이트를 켜지 않는다");
    assert_eq!(sv["timer"]["installed"], false);
}

// ── L2: 주기 타이머 install → status 역파싱 → uninstall ─────────

#[test]
fn timer_install_status_uninstall_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();

    // --no-load: launchctl/systemctl 호출 없이 unit 파일만 쓴다(시스템 미오염).
    let install = aic_cmd(tmp.path())
        .args(["snapshot", "install", "--interval", "123", "--no-load"])
        .output()
        .expect("snapshot install 실행 실패");
    assert!(install.status.success(), "install exit: {:?}\n{}", install.status, String::from_utf8_lossy(&install.stderr));

    // 플랫폼별 unit 경로 + 공통 불변식(opt-in env 주입·snapshot capture 실행·interval 반영).
    #[cfg(target_os = "macos")]
    let unit = tmp.path().join("Library/LaunchAgents/com.x-mesh.aic-snapshot.plist");
    #[cfg(target_os = "linux")]
    let unit = tmp.path().join("cfg/systemd/user/aic-snapshot.timer");

    assert!(unit.exists(), "타이머 unit 파일 미생성: {}", unit.display());
    #[cfg(target_os = "macos")]
    {
        let body = std::fs::read_to_string(&unit).unwrap();
        assert!(body.contains("<key>StartInterval</key>"));
        assert!(body.contains("<integer>123</integer>"));
        assert!(!body.contains("KeepAlive"), "one-shot 타이머에 KeepAlive 금지");
        assert!(body.contains("AIC_SNAPSHOT_RECORD"));
        assert!(body.contains("<string>snapshot</string>") && body.contains("<string>capture</string>"));
    }
    #[cfg(target_os = "linux")]
    {
        let timer = std::fs::read_to_string(&unit).unwrap();
        assert!(timer.contains("OnActiveSec=0"), "활성화 즉시 첫 발화");
        assert!(timer.contains("OnUnitActiveSec=123"));
        assert!(!timer.contains("OnBootSec"), "로그인 기준 OnBootSec 금지");
        let service = std::fs::read_to_string(
            tmp.path().join("cfg/systemd/user/aic-snapshot.service"),
        )
        .expect(".service 미생성");
        assert!(service.contains("Type=oneshot"));
        assert!(service.contains("Environment=AIC_SNAPSHOT_RECORD=1"));
        assert!(service.contains("snapshot capture"));
    }

    // status --json: 설치됨 + 간격 역파싱(123).
    let status = aic_cmd(tmp.path())
        .args(["snapshot", "status", "--json"])
        .output()
        .unwrap();
    let sv: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status --json은 JSON");
    assert_eq!(sv["timer"]["installed"], true);
    assert_eq!(sv["timer"]["interval_secs"], 123, "간격 역파싱 실패: {}", sv["timer"]);

    // uninstall → 파일 제거(launchctl/systemctl 미로드 상태에서도 best-effort).
    let uninstall = aic_cmd(tmp.path())
        .args(["snapshot", "uninstall"])
        .output()
        .expect("snapshot uninstall 실행 실패");
    assert!(uninstall.status.success(), "uninstall exit: {:?}", uninstall.status);
    assert!(!unit.exists(), "uninstall 후에도 unit 파일 잔존");
}

// ── L2: 진짜 다중 프로세스 동시 캡처 — cross-process flock 잃은 쓰기 0 ──

#[test]
fn concurrent_processes_capture_without_lost_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".aic").join("snapshots");
    std::fs::create_dir_all(&dir).unwrap();

    // 파일을 MAX(200) 근처까지 직접 시드해, 이후 동시 append마다 trim(read-all→rename)이 돌게 한다 —
    // cross-process 잃은 쓰기는 그 rename 윈도우에서 발생하므로 teeth를 주려면 trim이 필요하다.
    // SnapshotRecord JSON(schema v1) 직접 작성(host/cwd는 #[serde(default)]라 생략 가능).
    const SEED: usize = 197;
    const PROCS: usize = 6;
    let mut seed = String::new();
    for i in 0..SEED {
        // 2020년대 타임스탬프(동시 캡처의 now=2026보다 과거 → trim 시 manual이 살아남는 newest에 든다).
        let ts = format!("2020-01-01T00:{:02}:{:02}+00:00", i / 60, i % 60);
        seed.push_str(&format!(
            "{{\"schema_version\":1,\"captured_at\":\"{ts}\",\"kind\":\"seed\",\"sections\":[],\"body\":\"## x\\nv\\n\"}}\n"
        ));
    }
    std::fs::write(dir.join("snapshots.jsonl"), seed).unwrap();

    // PROCS개의 별도 `aic snapshot capture --force` 프로세스를 동시에 띄운다.
    let mut children: Vec<std::process::Child> = (0..PROCS)
        .map(|_| {
            aic_cmd(tmp.path())
                .args(["snapshot", "capture", "--force", "--kind", "manual"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("동시 capture spawn 실패")
        })
        .collect();
    for c in &mut children {
        let st = c.wait().expect("capture 프로세스 wait 실패");
        assert!(st.success(), "동시 capture 프로세스 exit 비정상: {st:?}");
    }

    // trim 후 정확히 MAX, 그리고 동시 추가한 manual 6건이 **모두** 보존(잃은 쓰기 0).
    let recs = load_records(tmp.path());
    assert_eq!(recs.len(), 200, "trim 후 정확히 MAX(200)여야: {}", recs.len());
    let manual = recs.iter().filter(|r| r["kind"] == "manual").count();
    assert_eq!(
        manual, PROCS,
        "동시 다중 프로세스 캡처 {PROCS}건 중 일부 유실(cross-process flock 실패): 보존 {manual}건"
    );
}

// ── L3: auto-RCA가 쓰는 인시던트+증거 머신리(aic rca start --diagnose --no-analyze) ──

#[test]
fn rca_start_with_diagnose_creates_incident_with_evidence() {
    let tmp = tempfile::tempdir().unwrap();

    // create_incident + headless diagnose 증거 첨부(LLM 없음). L3 auto_rca::capture_incident와 동형 머신리.
    let start = aic_cmd(tmp.path())
        .args(["rca", "start", "disk pressure", "--diagnose", "--no-analyze"])
        .output()
        .expect("rca start 실행 실패");
    assert!(start.status.success(), "rca start exit: {:?}\n{}", start.status, String::from_utf8_lossy(&start.stderr));

    // status --json(id 생략 → 목록): incident 1건 + evidence ≥ 2(lifecycle + diagnosis).
    let status = aic_cmd(tmp.path())
        .args(["rca", "status", "--json"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let sv: serde_json::Value = serde_json::from_slice(&status.stdout).expect("rca status --json은 JSON");
    let list = sv.as_array().expect("rca status --json(목록)은 배열");
    assert_eq!(list.len(), 1, "incident 1건이어야: {sv}");
    let evidence_count = list[0]["evidence_count"].as_u64().unwrap_or(0);
    assert!(
        evidence_count >= 2,
        "lifecycle+diagnosis로 evidence ≥ 2여야: {evidence_count}"
    );

    // report 렌더가 동작(Findings/Evidence 섹션 포함).
    let report = aic_cmd(tmp.path())
        .args(["rca", "report"])
        .output()
        .unwrap();
    assert!(report.status.success());
    let rtext = String::from_utf8_lossy(&report.stdout);
    assert!(rtext.contains("disk pressure"), "report에 제목 누락: {rtext}");
}
