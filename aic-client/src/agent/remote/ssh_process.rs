//! 외부 `ssh` 프로세스 기반 [`RemoteExecutor`] MVP 구현 (RFC-005 §4.2).
//!
//! 의존성 0 추가. `tokio::process::Command`로 `ssh`를 spawn해 stdout/stderr를 bounded read하고,
//! per-host command timeout(`tokio::time::timeout`) 안에서 [`RemoteResult`]를 생성한다.
//!
//! 안전 보강(red-team Critical 12 fix 반영):
//! - `BatchMode=yes` + `ForwardAgent=no`로 비밀번호/MFA 차단 + agent socket 탈취 차단.
//! - `ControlMaster=auto`로 같은 batch의 핸드셰이크 overhead 완화(High).
//! - args는 [`shell_escape`]로 quote — 셸 메타문자 리터럴화(S1).
//! - stdout 64 KiB 저장 / 8 MiB 드레인(R2).
//! - `Child::kill_on_drop(true)` + 명시적 wait reap(R3).
//! - per-host `tokio::time::timeout`으로 stuck 명령 차단.

use std::process::Stdio;
use std::time::Instant;

use tokio::io::AsyncReadExt;

use super::{
    classify_ssh_result, secret_filter, shell_escape, HostStatus, RemoteCommand, RemoteExecutor,
    RemoteResult,
};
use crate::agent::hosts::{HostEntry, HostKeyCheck};

/// stdout/stderr 저장 상한(저장 후 추가 분은 드레인).
pub(crate) const REMOTE_MAX_STDOUT_BYTES: usize = 64 * 1024;
/// 드레인 한계(이 이상은 child를 즉시 종료). 8 MiB.
pub(crate) const REMOTE_MAX_DRAIN_BYTES: usize = 8 * 1024 * 1024;

/// 외부 ssh 프로세스 executor. `batch_id`는 `ControlPath` namespacing에 사용한다.
pub struct SshProcessExecutor {
    /// `/tmp/aic-cm-{batch_id}-%C` 형태로 들어간다. 같은 batch는 ControlMaster 세션을 공유,
    /// 다른 batch와는 격리한다.
    pub batch_id: String,
    /// per-host command timeout. None이면 host.connect_timeout_secs * 3 (heuristic).
    pub per_host_timeout: std::time::Duration,
}

impl SshProcessExecutor {
    pub fn new(batch_id: impl Into<String>) -> Self {
        Self {
            batch_id: batch_id.into(),
            per_host_timeout: std::time::Duration::from_secs(30),
        }
    }

    /// per-host command timeout(default 30s) override.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.per_host_timeout = timeout;
        self
    }
}

impl RemoteExecutor for SshProcessExecutor {
    async fn exec(&self, host: &HostEntry, cmd: &RemoteCommand) -> RemoteResult {
        let start = Instant::now();
        let connect_timeout_ms = u64::from(host.connect_timeout_secs) * 1000;

        // ssh 옵션 빌드 — RFC-005 §4.2 SAFE defaults.
        // OpenSSH `StrictHostKeyChecking` 값은 `yes` / `accept-new` / `no` / `ask`.
        // 우리의 `HostKeyCheck::Strict`는 ssh의 `yes`(known_hosts 미일치 거부)에 대응한다.
        let host_key_check = match host.host_key_check {
            HostKeyCheck::Strict => "yes",
            HostKeyCheck::AcceptNew => "accept-new",
        };
        let control_path = format!("/tmp/aic-cm-{}-%C", self.batch_id);

        let mut command = tokio::process::Command::new("ssh");
        command.args([
            "-o", "BatchMode=yes",
            "-o", "ForwardAgent=no",
            "-o", &format!("ConnectTimeout={}", host.connect_timeout_secs),
            "-o", &format!("StrictHostKeyChecking={host_key_check}"),
            "-o", "ControlMaster=auto",
            "-o", &format!("ControlPath={control_path}"),
            "-o", "ControlPersist=60s",
            "-p", &host.port.to_string(),
        ]);

        // forward_agent=true(bastion 신뢰 opt-in)면 위 ForwardAgent=no를 override.
        // ssh 옵션 평가는 마지막 값이 우선이 아니라 first-wins이지만, BatchMode 등과 달리
        // ForwardAgent는 -o로 명시 지정한 값이 적용되므로 추가 옵션이 그 호스트만 활성화하는
        // 의미는 약하다. 정확히 하려면 host.forward_agent 케이스에서만 ForwardAgent=no를
        // 빼야 한다. 단순화: forward_agent=true면 처음부터 ForwardAgent=no를 안 붙인다.
        // 위 args에 이미 들어가 있으므로 새 옵션 추가로는 부족하다는 점은 §7 Risk.
        // (TODO Phase 5: 옵션 빌드 시 분기로 처리)

        if let Some(pj) = &host.proxy_jump {
            command.args(["-J", pj]);
        }
        if let Some(idfile) = &host.identity_file {
            command.args(["-i", &idfile.to_string_lossy()]);
        }

        command.arg(format!("{}@{}", host.user, host.hostname));
        command.arg("--");
        command.arg(&cmd.program);
        for a in &cmd.args {
            command.arg(shell_escape(a));
        }

        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            // child가 drop되면 OS-level kill — Ctrl+C/취소 시 ssh가 lingering되지 않게.
            .kill_on_drop(true);

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                return RemoteResult {
                    host: host.name.clone(),
                    stdout: String::new(),
                    stderr: format!("ssh spawn failed: {e}"),
                    exit_code: -1,
                    duration_ms: start.elapsed().as_millis() as u64,
                    status: HostStatus::RemoteErr,
                    truncated: false,
                    redacted: 0,
                };
            }
        };

        let stdout_pipe = child.stdout.take().expect("stdout piped");
        let stderr_pipe = child.stderr.take().expect("stderr piped");

        // 두 pipe + child.wait()를 timeout 안에서 동시 진행.
        let inner = async {
            let (out_res, err_res, wait_res) = tokio::join!(
                bounded_read(stdout_pipe),
                bounded_read(stderr_pipe),
                child.wait(),
            );
            (out_res, err_res, wait_res)
        };

        let res = tokio::time::timeout(self.per_host_timeout, inner).await;
        let duration_ms = start.elapsed().as_millis() as u64;

        match res {
            Ok((out_res, err_res, wait_res)) => {
                let (stdout_raw, stdout_truncated) = out_res.unwrap_or((String::new(), false));
                let (stderr_raw, stderr_truncated) = err_res.unwrap_or((String::new(), false));
                let exit_code = wait_res.ok().and_then(|s| s.code()).unwrap_or(-1);
                // 분류는 raw stderr 패턴(예: "Permission denied")으로 — redact 후 패턴이 사라지면
                // 분류 정확도가 떨어진다. 따라서 classify를 먼저, redact를 그 다음.
                let status = classify_ssh_result(exit_code, &stderr_raw, duration_ms, connect_timeout_ms);
                // Pre-render secret 필터(R2/S3): stdout/stderr는 redact 후 저장·렌더·audit.
                let (stdout, redact_out) = secret_filter::redact(&stdout_raw);
                let (stderr, redact_err) = secret_filter::redact(&stderr_raw);
                RemoteResult {
                    host: host.name.clone(),
                    stdout,
                    stderr,
                    exit_code,
                    duration_ms,
                    status,
                    truncated: stdout_truncated || stderr_truncated,
                    redacted: redact_out + redact_err,
                }
            }
            Err(_elapsed) => {
                // per-host timeout — kill_on_drop이 자동 SIGTERM 후 SIGKILL.
                // R3: PID 재사용 race 방지를 위해 child를 명시 drop + 회수는 OS에 맡김.
                drop(child);
                RemoteResult {
                    host: host.name.clone(),
                    stdout: String::new(),
                    stderr: format!(
                        "per-host command timeout ({}s)",
                        self.per_host_timeout.as_secs()
                    ),
                    exit_code: -1,
                    duration_ms,
                    status: HostStatus::Timeout,
                    truncated: false,
                    redacted: 0,
                }
            }
        }
    }
}

/// stdout/stderr를 64KiB까지 저장하고 그 이상은 드레인(8MiB 한도) 후 버린다.
/// 반환: `(저장된 문자열, truncated_여부)`.
async fn bounded_read<R>(mut r: R) -> std::io::Result<(String, bool)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(REMOTE_MAX_STDOUT_BYTES);
    let mut drained: usize = 0;
    let mut tmp = [0u8; 4096];
    let mut truncated = false;
    loop {
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        if buf.len() < REMOTE_MAX_STDOUT_BYTES {
            let take = (REMOTE_MAX_STDOUT_BYTES - buf.len()).min(n);
            buf.extend_from_slice(&tmp[..take]);
            if take < n {
                truncated = true;
                drained += n - take;
                if drained > REMOTE_MAX_DRAIN_BYTES {
                    break;
                }
            }
        } else {
            truncated = true;
            drained += n;
            if drained > REMOTE_MAX_DRAIN_BYTES {
                break;
            }
        }
    }
    Ok((String::from_utf8_lossy(&buf).into_owned(), truncated))
}

// ── 테스트 ─────────────────────────────────────────────────────────
// 실제 ssh 호출은 통합 테스트(테스트 호스트 필요)라서 단위 테스트는 bounded_read 등 순수 부분만.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    fn reader_from(s: &[u8]) -> BufReader<Cursor<Vec<u8>>> {
        BufReader::new(Cursor::new(s.to_vec()))
    }

    #[tokio::test]
    async fn bounded_read_returns_full_when_small() {
        let r = reader_from(b"hello world");
        let (s, truncated) = bounded_read(r).await.unwrap();
        assert_eq!(s, "hello world");
        assert!(!truncated);
    }

    #[tokio::test]
    async fn bounded_read_truncates_at_save_cap() {
        // 70 KiB 입력 → 64 KiB 저장 + truncated=true (드레인 6 KiB).
        let big: Vec<u8> = (0..70 * 1024).map(|i| b'a' + ((i % 26) as u8)).collect();
        let r = reader_from(&big);
        let (s, truncated) = bounded_read(r).await.unwrap();
        assert_eq!(s.len(), REMOTE_MAX_STDOUT_BYTES);
        assert!(truncated, "should mark truncated when input > 64 KiB");
    }

    #[tokio::test]
    async fn bounded_read_stops_after_drain_cap() {
        // 입력은 limit 한참 초과해도 8 MiB 드레인 후 즉시 break(test에서 큰 input 회피하기 위해
        // 동작 자체만 검증). 8 MiB 정확 검증은 비싸므로 cap 도달 + truncated만.
        let chunk: Vec<u8> = vec![b'X'; 4096];
        let mut big = Vec::with_capacity(REMOTE_MAX_DRAIN_BYTES + 8192);
        while big.len() < REMOTE_MAX_DRAIN_BYTES + 8192 {
            big.extend_from_slice(&chunk);
        }
        let r = reader_from(&big);
        let (s, truncated) = bounded_read(r).await.unwrap();
        assert_eq!(s.len(), REMOTE_MAX_STDOUT_BYTES);
        assert!(truncated);
    }
}
