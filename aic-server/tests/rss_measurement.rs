//! RSS measurement harness — centralized-record-store spec, Task 4.5.
//!
//! 이 파일은 Phase 3.4 의 R6.5 / R6.6 기준을 **수동으로 검증**하기 위한
//! bash 스크립트 [`scripts/measure-rss-phase34.sh`](../../../scripts/measure-rss-phase34.sh)
//! 와 [`scripts/measure-rss-phase30.sh`](../../../scripts/measure-rss-phase30.sh)
//! 이 호스트 환경에서 정상 실행 가능한지 확인하는 스모크 테스트를 담는다.
//!
//! - 실제 RSS 측정은 `aic-session` / `aicd` 프로세스가 이미 기동돼 있어야
//!   의미를 갖기 때문에 CI 에서는 기본적으로 **실행하지 않는다**
//!   (`#[ignore]`).
//! - 수동 실행:
//!   ```bash
//!   cargo test -p aic-server --test rss_measurement -- --ignored
//!   ```
//! - 실행 단계는 모두 `std::process::Command` 기반이며 테스트는 다음을
//!   검증한다:
//!     1. 두 스크립트가 `bash -n` 으로 파싱 가능하다.
//!     2. `--wait 0 --processes 0` 으로 no-op 실행 시 성공 종료(exit 0)한다.
//!     3. 생성된 JSON 이 유효한 `serde_json::Value` 로 파싱되고 주요 키를
//!        포함한다.
//!
//! 주의:
//! - Linux/macOS 가 아닌 환경(예: Windows) 에서는 bash 가 없을 수 있으므로
//!   스크립트 실행 단계는 `bash` 탐색이 실패하면 스킵된다.
//! - R6.5/R6.6 의 수치 PASS/FAIL 은 자동화된 테스트로는 판정할 수 없다.
//!   수동 절차는 [`scripts/README.md`](../../../scripts/README.md) 참고.

use std::path::{Path, PathBuf};
use std::process::Command;

/// 이 테스트 파일이 속한 crate (`aic-server`) 의 부모(워크스페이스 루트) 를
/// 반환한다. `CARGO_MANIFEST_DIR` 는 `aic-server` 이므로 한 단계 올라간다.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().expect("aic-server has a parent").to_path_buf()
}

fn script(name: &str) -> PathBuf {
    workspace_root().join("scripts").join(name)
}

fn bash_available() -> bool {
    Command::new("bash")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn assert_script_exists(path: &Path) {
    assert!(
        path.exists(),
        "script missing: {} — did Task 4.5 add it?",
        path.display()
    );
}

#[test]
#[ignore = "manual RSS measurement — run with `--ignored`"]
fn scripts_are_syntactically_valid_bash() {
    let phase34 = script("measure-rss-phase34.sh");
    let phase30 = script("measure-rss-phase30.sh");
    assert_script_exists(&phase34);
    assert_script_exists(&phase30);

    if !bash_available() {
        eprintln!("bash not available on PATH; skipping syntax check");
        return;
    }

    for path in [&phase34, &phase30] {
        let out = Command::new("bash")
            .arg("-n")
            .arg(path)
            .output()
            .expect("failed to spawn bash -n");
        assert!(
            out.status.success(),
            "bash -n failed for {}: stderr={}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
#[ignore = "manual RSS measurement — run with `--ignored`"]
fn phase34_script_produces_valid_json_for_empty_run() {
    // processes=0 + wait=0 은 실제 프로세스를 기대하지 않으므로 어떤 호스트
    // 에서도 실행 가능하다. 스크립트가 JSON 리포트를 생성하는지만 확인한다.
    let path = script("measure-rss-phase34.sh");
    assert_script_exists(&path);

    if !bash_available() {
        eprintln!("bash not available on PATH; skipping invocation");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let output = tmpdir.path().join("phase-3_4-rss.json");

    let status = Command::new("bash")
        .arg(&path)
        .args([
            "--phase",
            "3_4",
            "--wait",
            "0",
            "--processes",
            "0",
            "--output",
        ])
        .arg(&output)
        .status()
        .expect("failed to spawn measure-rss-phase34.sh");
    assert!(status.success(), "script exited non-zero: {status}");

    let raw = std::fs::read_to_string(&output).expect("read output JSON");
    let value: serde_json::Value =
        serde_json::from_str(&raw).expect("output is not valid JSON");

    // 필수 키 확인 — scripts/README.md 스키마와 맞춰야 한다.
    for key in [
        "phase",
        "mode",
        "timestamp",
        "actual_sessions",
        "actual_aicd",
        "total_rss_kb",
        "interpretation",
    ] {
        assert!(
            value.get(key).is_some(),
            "missing key `{key}` in JSON output"
        );
    }
    assert_eq!(value["phase"], "3_4");
    assert_eq!(value["mode"], "multi");
}

#[test]
#[ignore = "manual RSS measurement — run with `--ignored`"]
fn phase30_wrapper_forwards_phase_label() {
    // Phase 3.0 baseline wrapper 도 동일하게 동작해야 한다.
    let path = script("measure-rss-phase30.sh");
    assert_script_exists(&path);

    if !bash_available() {
        eprintln!("bash not available on PATH; skipping invocation");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let output = tmpdir.path().join("phase-3_0-rss.json");

    let status = Command::new("bash")
        .arg(&path)
        .args(["--wait", "0", "--processes", "0", "--output"])
        .arg(&output)
        .status()
        .expect("failed to spawn measure-rss-phase30.sh");
    assert!(status.success(), "script exited non-zero: {status}");

    let value: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(&output).expect("open json"))
            .expect("valid JSON");
    assert_eq!(value["phase"], "3_0");
}
