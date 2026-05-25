//! SSH 멀티호스트 실행 레이어 (RFC-005 Phase 2).
//!
//! [`RemoteExecutor`] trait + 외부 `ssh` 프로세스 구현([`ssh_process::SshProcessExecutor`]).
//! 인벤토리([`super::hosts::Inventory`])는 Phase 1, fan-out + 카드 렌더는 Phase 3.
//!
//! 안전 원칙 (red-team 12 Critical fix 반영):
//! - 셸 해석 배제: `RemoteCommand { program, args }`만 노출, 외부 `ssh -- {program} {args}`로
//!   호출하며 args는 [`shell_escape`]로 quote (S1).
//! - `BatchMode=yes` + `ForwardAgent=no`(host overlay 시 opt-in) + `ControlMaster=auto`로
//!   비밀번호/MFA 차단 + agent socket 탈취 차단 + 핸드셰이크 overhead 완화.
//! - stdout/stderr 상한 64 KiB 저장 / 8 MiB 드레인 (R2).
//! - 분기 명확: 8종 [`HostStatus`] + [`classify_ssh_result`] (U2).

pub mod fanout;
pub mod path_guard;
pub mod secret_filter;
pub mod ssh_process;

use serde::Serialize;

pub use fanout::{run_fanout, FanoutResult, StatusCounts};
pub use path_guard::{check_path, lexical_canonicalize, PathCheck};
pub use ssh_process::SshProcessExecutor;

/// 원격 호스트에서 실행할 명령. 셸 해석 배제를 위해 program/args를 분리한다.
#[derive(Debug, Clone)]
pub struct RemoteCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl RemoteCommand {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(items.into_iter().map(Into::into));
        self
    }
}

/// 원격 호스트 결과 — 카드 1장에 직접 대응(Phase 3 렌더).
#[derive(Debug, Clone, Serialize)]
pub struct RemoteResult {
    pub host: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub status: HostStatus,
    /// stdout 또는 stderr가 64KiB 저장 한계를 넘었는지(나머지는 드레인 후 버림).
    pub truncated: bool,
    /// pre-render secret 필터가 redact한 매치 수(stdout+stderr 합산). 0이어도 미일치
    /// secret이 있을 수 있음 → audit 측에서 "원격 결과는 secret 포함 가능" 경고 첨부.
    #[serde(default)]
    pub redacted: usize,
}

/// 8종 상태 태그(RFC-005 §4.4 U2). Phase 3의 카드 헤더에 표시.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    /// exit 0 + stderr 무해.
    Ok,
    /// exit 0이지만 stderr에 `WARNING`/`NOTICE` 패턴 — 카드에 본문 노출.
    OkWithWarn,
    /// ConnectTimeout 초과 또는 ssh exit 255 + duration ≤ ConnectTimeout.
    Unreachable,
    /// 명령 실행 단계 timeout (per-host cmd timeout).
    Timeout,
    /// BatchMode 차단 — `Permission denied`/`publickey`/`gssapi` 패턴.
    AuthFail,
    /// ProxyJump 경로 실패 — `jump host`/`bastion` 패턴(공통 원인 집계용).
    ProxyFail,
    /// 원격 셸/명령 실패 — exit ≠ 0, channel-open 실패 포함. 패턴 미일치 시 fallback.
    RemoteErr,
    /// known_hosts fingerprint 불일치 — 즉시 차단 + audit critical.
    HostKeyMismatch,
}

impl HostStatus {
    /// 카드 헤더에 표시할 짧은 태그(예: `[ok]`, `[unreachable]`).
    pub fn label(self) -> &'static str {
        match self {
            HostStatus::Ok => "ok",
            HostStatus::OkWithWarn => "ok_warn",
            HostStatus::Unreachable => "unreachable",
            HostStatus::Timeout => "timeout",
            HostStatus::AuthFail => "auth_fail",
            HostStatus::ProxyFail => "proxy_fail",
            HostStatus::RemoteErr => "remote_err",
            HostStatus::HostKeyMismatch => "host_key_mismatch",
        }
    }

    /// severity 정렬용(Phase 4): 큰 값이 더 심각.
    /// host_key_mismatch > auth_fail > proxy_fail > timeout > unreachable > remote_err > ok_warn > ok
    pub fn severity(self) -> u8 {
        match self {
            HostStatus::HostKeyMismatch => 90,
            HostStatus::AuthFail => 70,
            HostStatus::ProxyFail => 60,
            HostStatus::Timeout => 50,
            HostStatus::Unreachable => 40,
            HostStatus::RemoteErr => 30,
            HostStatus::OkWithWarn => 10,
            HostStatus::Ok => 0,
        }
    }
}

/// 외부 ssh의 exit code + stderr + duration → [`HostStatus`].
///
/// RFC-005 §4.5 분류 규칙:
/// - exit 0: stderr WARNING 패턴이면 [`OkWithWarn`], 아니면 [`Ok`].
/// - exit 255 + duration ≤ ConnectTimeout(여유 500ms): `jump host`/`bastion`면 [`ProxyFail`],
///   아니면 [`Unreachable`].
/// - exit 255 + duration > ConnectTimeout: stderr 패턴별 분기 — `permission denied`/`publickey`/
///   `gssapi`는 [`AuthFail`], `host key`+`changed`는 [`HostKeyMismatch`], `channel`/`open failed`는
///   [`RemoteErr`], 미일치 fallback [`RemoteErr`].
/// - exit ≠ 0/255: [`RemoteErr`].
pub fn classify_ssh_result(
    exit_code: i32,
    stderr: &str,
    duration_ms: u64,
    connect_timeout_ms: u64,
) -> HostStatus {
    if exit_code == 0 {
        return if stderr_has_warning(stderr) {
            HostStatus::OkWithWarn
        } else {
            HostStatus::Ok
        };
    }
    let lower = stderr.to_lowercase();
    if exit_code == 255 {
        // ssh exit 255는 connect/auth/원격 셸 등 모든 단계의 실패를 한 코드로 보고한다.
        // duration만으로 분기하면 빠른 auth_fail(localhost ~90ms)도 unreachable로 오분류된다
        // (실측 회귀). 따라서 stderr 패턴을 우선 검사하고, 패턴 미일치 + connect 단계로
        // 추정되는 duration일 때만 unreachable로 결론낸다.

        // 1) host key 불일치(critical) — 항상 최우선
        if lower.contains("host key") && (lower.contains("changed") || lower.contains("verification failed")) {
            return HostStatus::HostKeyMismatch;
        }
        // 2) ProxyJump 경로 실패
        if lower.contains("jump host") || lower.contains("bastion") {
            return HostStatus::ProxyFail;
        }
        // 3) 인증 실패 (BatchMode 차단)
        if lower.contains("permission denied") || lower.contains("publickey")
            || lower.contains("gssapi") || lower.contains("kerberos")
            || lower.contains("keyboard-interactive")
            || lower.contains("too many authentication failures")
        {
            return HostStatus::AuthFail;
        }
        // 4) channel open 실패 (auth는 됐지만 원격 셸 거부)
        if lower.contains("channel") || lower.contains("open failed") {
            return HostStatus::RemoteErr;
        }
        // 5) 명시적 timeout 메시지
        if lower.contains("operation timed out") || lower.contains("connection timed out") {
            return HostStatus::Unreachable;
        }
        // 6) connect 단계 일반 실패
        if lower.contains("connect to host") || lower.contains("connection refused")
            || lower.contains("no route to host") || lower.contains("network is unreachable")
            || lower.contains("name or service not known")
        {
            return HostStatus::Unreachable;
        }
        // 7) duration fallback: connect_timeout 안에 exit이면 unreachable로 추정
        if duration_ms <= connect_timeout_ms.saturating_add(500) {
            return HostStatus::Unreachable;
        }
    }
    HostStatus::RemoteErr
}

fn stderr_has_warning(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("warning") || lower.contains("warn:") || lower.contains("notice:")
}

/// POSIX sh-safe quoting(RFC-005 §4.2 S1).
/// `'...'`로 래핑 + 내부 `'`는 `'\''`로 이스케이프. sh/bash/zsh 모두 안전.
/// fish/csh은 호스트별 `$SHELL` 감지 시 `sh -c` 래핑(Phase 후속) — 잔존 위험은 §7 Risk.
pub fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// 원격 실행 추상화. MVP 구현은 [`SshProcessExecutor`] 단일.
///
/// `RemoteExecutor` trait를 유지하는 이유는 미래 전환(러스시/`ssh2`) 보험이며,
/// 트리거는 RFC-005 §5.2 — (a) connection latency UX 병목, (b) OpenSSH 미설치 환경.
#[allow(async_fn_in_trait)] // MVP는 dyn 사용 안 함. 1.1에서 dyn 필요해지면 async-trait 도입.
pub trait RemoteExecutor: Send + Sync {
    async fn exec(
        &self,
        host: &super::hosts::HostEntry,
        cmd: &RemoteCommand,
    ) -> RemoteResult;
}

// ── 단위 테스트 (실제 ssh 호출 없이 검증 가능한 순수 함수만) ─────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape_wraps_with_single_quotes() {
        assert_eq!(shell_escape("hello"), "'hello'");
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn shell_escape_handles_internal_single_quote() {
        // it's → 'it'\''s'
        assert_eq!(shell_escape("it's"), r#"'it'\''s'"#);
    }

    #[test]
    fn shell_escape_neutralizes_metachars() {
        // shell 메타문자 안에 들어가도 single-quote 안이라 모두 리터럴.
        let s = shell_escape("; rm -rf / $(whoami)");
        assert_eq!(s, "'; rm -rf / $(whoami)'");
    }

    #[test]
    fn shell_escape_handles_history_expansion_char() {
        // csh `!` history는 single-quote 내부에선 비활성(non-interactive sh 호환).
        // 사용자는 비-sh 셸 호스트에 대해 remote_shell_wrap=true 옵션을 쓴다.
        assert_eq!(shell_escape("find / -name '!secret'"), r#"'find / -name '\''!secret'\'''"#);
    }

    #[test]
    fn classify_exit_zero_ok() {
        assert_eq!(classify_ssh_result(0, "", 100, 10_000), HostStatus::Ok);
    }

    #[test]
    fn classify_exit_zero_with_warning_stderr() {
        assert_eq!(
            classify_ssh_result(0, "WARNING: disk usage 92%", 100, 10_000),
            HostStatus::OkWithWarn
        );
        assert_eq!(
            classify_ssh_result(0, "notice: cron job slow", 100, 10_000),
            HostStatus::OkWithWarn
        );
    }

    #[test]
    fn classify_connect_timeout_unreachable() {
        // duration ≤ connect_timeout(+500ms) 범위에서 exit 255 → Unreachable
        assert_eq!(
            classify_ssh_result(255, "ssh: connect to host 10.0.0.1 port 22: Connection refused", 9_800, 10_000),
            HostStatus::Unreachable
        );
    }

    #[test]
    fn classify_proxy_jump_failure() {
        assert_eq!(
            classify_ssh_result(255, "ssh: Could not resolve jump host bastion-main", 9_500, 10_000),
            HostStatus::ProxyFail
        );
    }

    #[test]
    fn classify_auth_fail_permission_denied() {
        assert_eq!(
            classify_ssh_result(
                255,
                "Permission denied (publickey,gssapi-keyex,gssapi-with-mic).",
                12_000,
                10_000
            ),
            HostStatus::AuthFail
        );
    }

    #[test]
    fn classify_auth_fail_kerberos() {
        assert_eq!(
            classify_ssh_result(255, "GSSAPI Error: No credentials", 12_000, 10_000),
            HostStatus::AuthFail
        );
    }

    #[test]
    fn classify_host_key_changed() {
        // host key changed는 connect duration 무관하게 최우선
        let stderr = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                      @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                      The ECDSA host key for 10.0.1.10 has changed.";
        assert_eq!(
            classify_ssh_result(255, stderr, 11_000, 10_000),
            HostStatus::HostKeyMismatch
        );
    }

    #[test]
    fn classify_channel_open_failure() {
        assert_eq!(
            classify_ssh_result(255, "channel 0: open failed: administratively prohibited", 15_000, 10_000),
            HostStatus::RemoteErr
        );
    }

    #[test]
    fn classify_auth_fail_with_short_duration_does_not_become_unreachable() {
        // 실측 회귀: localhost 인증 실패는 매우 빠르게(~90ms) exit 255를 반환한다.
        // 이전 로직은 duration ≤ connect_timeout이면 무조건 Unreachable로 잡았는데,
        // stderr 패턴 우선으로 바뀌어 AuthFail로 정확 분류되어야 한다.
        let stderr = "nonexistent_user@127.0.0.1: Permission denied (publickey,password,keyboard-interactive).";
        assert_eq!(
            classify_ssh_result(255, stderr, 92, 3_000),
            HostStatus::AuthFail
        );
    }

    #[test]
    fn classify_explicit_timeout_message_is_unreachable() {
        // ConnectTimeout 도달 시 ssh가 출력하는 메시지.
        assert_eq!(
            classify_ssh_result(
                255,
                "ssh: connect to host 192.0.2.1 port 22: Operation timed out",
                3_013,
                3_000
            ),
            HostStatus::Unreachable
        );
    }

    #[test]
    fn classify_unknown_exit_code_falls_back_to_remote_err() {
        // remote 명령 자체가 exit ≠ 0, 255 (예: `df` exit 1)
        assert_eq!(
            classify_ssh_result(1, "df: invalid option", 200, 10_000),
            HostStatus::RemoteErr
        );
    }

    #[test]
    fn host_status_severity_orders_correctly() {
        let mut statuses = vec![
            HostStatus::Ok,
            HostStatus::AuthFail,
            HostStatus::OkWithWarn,
            HostStatus::HostKeyMismatch,
            HostStatus::Timeout,
            HostStatus::Unreachable,
        ];
        statuses.sort_by_key(|s| std::cmp::Reverse(s.severity()));
        assert_eq!(
            statuses,
            vec![
                HostStatus::HostKeyMismatch,
                HostStatus::AuthFail,
                HostStatus::Timeout,
                HostStatus::Unreachable,
                HostStatus::OkWithWarn,
                HostStatus::Ok,
            ]
        );
    }

    #[test]
    fn remote_command_builder_chains() {
        let c = RemoteCommand::new("ps").arg("aux").args(["-o", "pid"]);
        assert_eq!(c.program, "ps");
        assert_eq!(c.args, vec!["aux", "-o", "pid"]);
    }
}
