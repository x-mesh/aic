//! SRE R6: headless(비대화·TTY 없음) e2e 테스트.
//!
//! SRE는 aic를 서버(cron/systemd/webhook spawn)에서 TTY 없이 돌린다. 이 테스트는
//! `aic` 바이너리를 stdin 닫힌 subprocess로 실행해 headless 경로가 동작하고 **상태 변경
//! 명령이 자동 실행되지 않음**(보안 속성)을 고정한다. 외부 LLM/네트워크 없이 동작.

#![cfg(unix)]

use std::process::Command;

/// HOME/XDG를 임시로 격리한 aic 명령을 만든다(실제 홈 오염 방지 + keychain 우회).
fn aic_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aic"));
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("cfg"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("AIC_NO_KEYCHAIN", "1")
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null()); // TTY 없음(비대화)
    cmd
}

#[test]
fn diagnose_headless_produces_evidence_without_tty() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aic_cmd(tmp.path())
        .args(["diagnose", "--no-analyze", "generic"])
        .output()
        .expect("aic diagnose 실행 실패");
    assert!(out.status.success(), "exit 비정상: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("# diagnose"), "stdout={stdout}");
    assert!(stdout.contains("## evidence"), "stdout={stdout}");
    // 최소 한 개 probe 결과(date/host/os 등)가 수집되어야 한다.
    assert!(stdout.contains("## "), "probe 섹션 없음: {stdout}");
}

#[test]
fn audit_subcommands_run_headless() {
    let tmp = tempfile::tempdir().unwrap();
    // diagnose가 audit 이벤트를 남긴다.
    aic_cmd(tmp.path())
        .args(["diagnose", "--no-analyze", "cpu"])
        .output()
        .unwrap();

    // verify: 빈/유효 로그 → exit 0.
    let verify = aic_cmd(tmp.path()).args(["audit", "verify"]).output().unwrap();
    assert!(verify.status.success(), "audit verify exit: {:?}", verify.status);

    // tail --json: 유효한 JSON 배열.
    let tail = aic_cmd(tmp.path())
        .args(["audit", "tail", "-n", "10", "--json"])
        .output()
        .unwrap();
    assert!(tail.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&tail.stdout).expect("tail --json은 JSON");
    assert!(parsed.is_array(), "tail --json은 배열: {parsed}");

    // search --kind: headless 동작.
    let search = aic_cmd(tmp.path())
        .args(["audit", "search", "--kind", "headless_diagnose", "--json"])
        .output()
        .unwrap();
    assert!(search.status.success());
    let s: serde_json::Value = serde_json::from_slice(&search.stdout).expect("search --json은 JSON");
    assert!(s.is_array());
}

#[test]
fn webhook_list_runs_headless() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aic_cmd(tmp.path())
        .args(["webhook", "list", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("webhook list --json은 JSON");
    assert!(parsed.is_array());
}

#[test]
fn config_get_runs_headless() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aic_cmd(tmp.path())
        .args(["config", "get", "llm.default_provider"])
        .output()
        .unwrap();
    // 설정 파일이 없으면 default("openai")가 나오거나 path-not-found(비-0)일 수 있다.
    // 핵심은 hang 없이 종료하는 것.
    let _ = out.status;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("openai") || stderr.contains("not found") || out.status.success(),
        "stdout={stdout} stderr={stderr}"
    );
}

/// 보안 속성: 비대화(TTY 없음)에서 NeedsConfirm 명령은 자동 실행되지 않는다.
/// webhook/cron이 spawn한 진단이 상태 변경 명령을 자동 실행하면 안 되는 핵심 불변식.
#[test]
fn needs_confirm_command_is_rejected_when_non_interactive() {
    use aic_client::agent::run_command::execute_with_corr;
    use aic_client::agent::Sandbox;

    let sandbox = Sandbox::from_cwd().expect("sandbox");
    // systemctl restart = NeedsConfirm(상태 변경). 비대화 confirm 클로저는 항상 false.
    let args = serde_json::json!({ "command": "systemctl restart nginx" });
    let result = execute_with_corr(&args, &sandbox, "test-corr", |_, _, _| false).unwrap();
    assert!(
        result.contains("[denied]"),
        "NeedsConfirm은 비대화에서 거부되어야 함: {result}"
    );
    // 명령이 실제로 실행된 흔적(stdout)이 없어야 한다.
    assert!(!result.contains("Active:"), "명령이 실행됨: {result}");
}
