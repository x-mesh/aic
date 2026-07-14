//! exporter task가 외부 프로세스를 spawn할 때 쓰는 공용 안전 래퍼.
//!
//! connections(`aic snapshot inventory`)와 docker(`docker system df`) 두 exporter가 외부 CLI를
//! 주기적으로 spawn한다. aicd는 **상주 데몬**이라 주기 tick에서 새는 자원은 시간이 지나며 반드시
//! 쌓인다 — 그래서 spawn 경로를 한 곳으로 모으고 아래 두 가지를 구조적으로 보장한다.
//!
//! **1. orphan 프로세스를 남기지 않는다.** `tokio::time::timeout`이 만료되면 **future만 drop될 뿐
//! 이미 spawn된 자식 프로세스는 그대로 살아 있다**. 60초마다 도는 task에서 외부 CLI가 hang하면
//! orphan이 매 tick 누적된다(실제로 이 버그가 있었다). 그래서 `kill_on_drop(true)`로 `Child` drop
//! 시 kill을 보장하고, timeout/상한 초과 경로에서는 **명시적으로 `kill().await`까지** 한다
//! (`kill_on_drop`은 tokio 런타임이 살아 있어야 동작하므로, 확실한 경로에서는 직접 죽여 reap까지
//! 끝낸다 — 좀비도 남기지 않는다).
//!
//! **2. 출력 상한이 진짜 방어다.** `wait_with_output()`으로 전부 버퍼링한 **뒤에** 길이를 재면
//! 그건 방어가 아니라 사후 확인이다 — 무한 출력을 뱉는 프로세스는 그 검사에 도달하기 전에 이미
//! 메모리를 다 먹는다. 여기서는 **스트리밍으로 읽으면서** 상한을 넘는 순간 즉시 중단하고 자식을
//! kill한다. 그래서 최대 메모리는 항상 `max_bytes + 청크 크기`로 묶인다.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// 스트리밍 read 청크 크기. 최대 메모리는 `max_bytes + CHUNK`로 묶인다.
const CHUNK: usize = 8 * 1024;

/// stderr 보존 상한. 진단 문구는 보통 한두 줄이라 이 정도면 넘치고, 초과분은 **버리되 계속 읽어
/// 비운다**(읽기를 멈추면 파이프가 차서 자식이 write에서 블록된다 — 그건 우리가 만든 hang이다).
const MAX_STDERR_BYTES: usize = 16 * 1024;

/// 실패 로그에 붙일 stderr 줄 수. 원인은 보통 마지막 줄에 있다.
const STDERR_HINT_LINES: usize = 3;

/// `cmd`를 spawn해 stdout을 **상한을 지키며** 수집하고, 종료 상태까지 확인해 stdout bytes를
/// 돌려준다. stdin은 null, stdout/stderr는 pipe로 강제한다(호출부가 잊지 못하게).
///
/// `what`은 에러 메시지에 쓰이는 사람이 읽을 명령 이름(예: `"docker system df"`).
///
/// **stderr는 왜 캡처하나**: 예전엔 null로 버렸는데, 그러면 non-zero exit 시 `exit status: 1`만
/// 남아 **"데몬이 안 떴다"/"권한이 없다"/"소켓 경로가 틀렸다"를 구분할 수 없다**. 운영 중에 이걸
/// 디버깅하는 사람에게는 그 한 줄이 전부다. 그래서 stderr를 [`MAX_STDERR_BYTES`] 상한으로 받아
/// 실패 메시지에 붙인다. 단, **redaction을 거친다** — stderr에는 경로·호스트명·토큰이 섞일 수
/// 있고, aicd 로그는 진단 번들에 실려 나갈 수 있다(송신 문자열을 전부 redact하는 repo 규약을
/// 로그에도 동일하게 적용한다).
///
/// `Err`가 되는 경우 — 호출부는 전부 "이번 주기 skip"으로 동일 취급한다:
/// - spawn 실패(미설치 → ENOENT)
/// - `timeout` 초과(hang) — 자식을 kill하고 reap한다
/// - stdout이 `max_bytes`를 초과(비정상/무한 출력) — 읽는 도중 즉시 끊고 자식을 kill한다
/// - non-zero exit(데몬 다운·권한 없음 등이 모두 여기로 온다 — 구분은 stderr가 해 준다)
pub(super) async fn run_capped(
    mut cmd: Command,
    timeout: Duration,
    max_bytes: usize,
    what: &str,
) -> anyhow::Result<Vec<u8>> {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // 핵심: 이게 없으면 아래 timeout이 만료돼 future가 drop될 때 자식이 살아남아 orphan이 된다.
        .kill_on_drop(true);

    let mut child = cmd.spawn()?;

    let collected = tokio::time::timeout(timeout, async {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("{what}의 stdout을 잡지 못함"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("{what}의 stderr를 잡지 못함"))?;

        // 두 파이프를 **동시에** 읽어야 한다. stdout만 읽으면 자식이 stderr를 많이 뱉을 때 파이프가
        // 가득 차 write에서 블록되고, 우리는 오지 않을 stdout EOF를 기다리며 서로 멈춘다(고전적
        // deadlock). `try_join!`은 한쪽이 Err(= stdout 상한 초과)면 즉시 단축해 다른 쪽 future를
        // drop하므로, 무한 출력에 매달리지 않고 곧바로 kill 경로로 간다.
        let (out, err) = tokio::try_join!(
            read_capped(&mut stdout, max_bytes, what),
            read_lossy_capped(&mut stderr, MAX_STDERR_BYTES),
        )?;
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>((status, out, err))
    })
    .await;

    match collected {
        // hang — 자식이 살아 있다. 명시적으로 죽이고 reap한다(orphan/좀비 둘 다 방지).
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("{what}가 {}초 내에 끝나지 않음", timeout.as_secs())
        }
        // 상한 초과/IO 에러 — 자식이 아직 출력을 뱉고 있을 수 있으므로 즉시 죽인다.
        Ok(Err(e)) => {
            let _ = child.kill().await;
            Err(e)
        }
        Ok(Ok((status, out, err))) => {
            if !status.success() {
                // stderr가 곧 원인이다 — 없으면 예전처럼 status만 남는다.
                let hint = stderr_hint(&err);
                if hint.is_empty() {
                    anyhow::bail!("{what}가 {status} 로 종료 (stderr 없음)");
                }
                anyhow::bail!("{what}가 {status} 로 종료: {hint}");
            }
            Ok(out)
        }
    }
}

/// stdout을 청크 단위로 읽되 누적이 `max_bytes`를 넘는 순간 즉시 `Err`. 전부 읽고 나서 재는 것이
/// 아니라 **읽는 도중에** 끊는 것이 핵심이다 — 그래야 무한 출력이 메모리를 먹기 전에 막힌다.
async fn read_capped<R>(reader: &mut R, max_bytes: usize, what: &str) -> anyhow::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; CHUNK];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(buf);
        }
        if buf.len() + n > max_bytes {
            anyhow::bail!(
                "{what} 출력이 상한({max_bytes} bytes)을 초과함 — 신뢰할 수 없는 출력으로 간주"
            );
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// stderr용 — 상한까지만 **보존**하고 초과분은 버리되 EOF까지 계속 읽어 파이프를 비운다.
///
/// stdout과 달리 상한 초과를 에러로 올리지 않는다: stderr는 진단 보조일 뿐이라, 수다스럽다는
/// 이유로 수집 전체를 실패시키면 본말이 전도된다. 읽기를 아예 멈추지도 않는다 — 파이프가 차면
/// 자식이 write에서 블록돼 우리가 hang을 만든다. 메모리는 `max_bytes`로 묶이고, 무한히 뱉는
/// 병적인 경우는 바깥 timeout이 받아낸다.
async fn read_lossy_capped<R>(reader: &mut R, max_bytes: usize) -> anyhow::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; CHUNK];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(buf);
        }
        let room = max_bytes.saturating_sub(buf.len());
        if room > 0 {
            buf.extend_from_slice(&chunk[..n.min(room)]);
        }
    }
}

/// 실패 로그에 붙일 stderr 요약 — 마지막 [`STDERR_HINT_LINES`]줄을 redact해 한 줄로 합친다.
/// 원인은 보통 끝줄에 있고(앞은 진행 로그), 로그 한 줄이 화면을 도배하지 않게 줄 수를 묶는다.
fn stderr_hint(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let tail: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if tail.is_empty() {
        return String::new();
    }
    let start = tail.len().saturating_sub(STDERR_HINT_LINES);
    let joined = tail[start..].join(" | ");
    // repo 규약: 밖으로 나가는 문자열은 예외 없이 redaction을 통과한다(로그도 진단 번들에 실린다).
    aic_common::redaction::redact(&joined).0
}

/// orphan 회귀 가드를 세 모듈(proc/docker/connections)이 공유하기 위한 테스트 유틸.
///
/// **왜 단순 고정 timeout이 아닌가**: timeout이 자식의 fork/exec보다 먼저 터지면 죽일 자식이 애초에
/// 없어서 "orphan 없음"이 **공허하게** 통과한다(150ms로 잡았다가 실제로 이 함정에 걸렸다). 반대로
/// 고정값을 넉넉히 키우면 부하가 큰 CI에서 여전히 흔들린다. 그래서 **pid 파일이 존재할 때만 단정**
/// 하고(= 자식이 실제로 살아 있었다는 증거), 자식이 기동 전이었으면 더 긴 grace로 재시도한다.
/// 공허 통과와 flake를 동시에 막는다.
#[cfg(test)]
pub(super) mod testutil {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::Duration;

    /// grace 후보 — 첫 시도로 대부분 끝나고, 부하가 크면 점증한다.
    pub(crate) const GRACES: [Duration; 3] = [
        Duration::from_secs(3),
        Duration::from_secs(8),
        Duration::from_secs(20),
    ];

    /// `$$`를 pidfile에 남기고 `exec sleep`으로 매달리는 스크립트 본문. `exec`로 sh를 sleep으로
    /// 치환해야 기록한 pid가 곧 실제로 매달린 프로세스의 pid가 된다(직계 자식 = 죽일 대상).
    pub(crate) fn hang_script(pidfile: &Path) -> String {
        format!("echo $$ > {}\nexec sleep 60", pidfile.display())
    }

    /// 실행 가능한 `/bin/sh` 스크립트를 만든다.
    pub(crate) fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "#!/bin/sh\n{body}").unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// 프로세스가 살아 있는지 — signal 0은 존재 확인만 한다(죽이지 않는다).
    pub(crate) fn alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// 자식이 남긴 pid. 파일이 없으면 자식이 기동 전에 죽은 것 → `None`(단정하지 않고 재시도).
    pub(crate) fn read_pid(pidfile: &Path) -> Option<i32> {
        std::fs::read_to_string(pidfile).ok()?.trim().parse().ok()
    }

    /// Linux `ETXTBSY`("Text file busy")인가.
    ///
    /// **테스트 전용 문제다.** 병렬 테스트에서 한 스레드가 방금 만든 스크립트에 쓰기 fd를 아직
    /// 들고 있는 동안 다른 스레드가 fork하면, 그 자식이 fd를 물려받은 채 같은 파일을 `execve`해
    /// 커널이 ETXTBSY를 돌려준다(`O_CLOEXEC`이어도 fork~exec 사이에는 열려 있어 못 막는 알려진
    /// race). 프로덕션 aicd는 실행 파일을 쓰지 않으므로 이 경로가 없다 — 그래서 `run_capped`가
    /// 아니라 테스트 쪽에서 재시도로 흡수한다(프로덕션 코드에 테스트 사정을 넣지 않는다).
    pub(crate) fn is_text_file_busy(e: &anyhow::Error) -> bool {
        e.to_string().contains("Text file busy")
    }

    /// 생성한 스크립트를 exec하는 테스트를 감싼다 — ETXTBSY만 재시도하고, 다른 결과는 그대로 통과.
    pub(crate) async fn retry_busy<T, F, Fut>(mut f: F) -> anyhow::Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        let mut last = None;
        for _ in 0..12 {
            match f().await {
                Err(e) if is_text_file_busy(&e) => {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    last = Some(e);
                }
                other => return other,
            }
        }
        Err(last.expect("ETXTBSY 재시도를 다 썼는데 마지막 에러가 없다"))
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{
        alive, hang_script, is_text_file_busy, read_pid, retry_busy, script, GRACES,
    };
    use super::*;

    fn script_in(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
        script(dir.path(), name, body)
    }

    #[tokio::test]
    async fn captures_stdout_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let bin = script_in(&dir, "ok", "echo hello");
        let out =
            retry_busy(|| run_capped(Command::new(&bin), Duration::from_secs(5), 4096, "test"))
                .await
                .unwrap();
        assert_eq!(String::from_utf8_lossy(&out).trim(), "hello");
    }

    #[tokio::test]
    async fn nonzero_exit_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let bin = script_in(&dir, "fail", "exit 1");
        let err =
            retry_busy(|| run_capped(Command::new(&bin), Duration::from_secs(5), 4096, "test"))
                .await
                .unwrap_err();
        assert!(err.to_string().contains("종료"), "err={err}");
    }

    /// 실패 원인이 로그에 남아야 한다. 예전엔 stderr를 null로 버려 `exit status: 1`만 남았고,
    /// "데몬이 안 떴다"인지 "권한이 없다"인지 구분할 수 없었다.
    #[tokio::test]
    async fn nonzero_exit_error_carries_the_stderr_reason() {
        let dir = tempfile::tempdir().unwrap();
        let bin = script_in(
            &dir,
            "daemon-down",
            "echo 'failed to connect to the docker API at unix:///var/run/docker.sock; \
             check if the daemon is running' >&2\nexit 1",
        );
        let err =
            retry_busy(|| run_capped(Command::new(&bin), Duration::from_secs(5), 4096, "test"))
                .await
                .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("종료"), "err={msg}");
        assert!(
            msg.contains("check if the daemon is running"),
            "실패 원인(stderr)이 에러에 실려야 한다: {msg}"
        );
    }

    /// stderr가 비어 있으면 그렇다고 명시한다 — 조용한 실패와 "원인을 못 읽었다"를 섞지 않는다.
    #[tokio::test]
    async fn nonzero_exit_without_stderr_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let bin = script_in(&dir, "silent-fail", "exit 3");
        let err =
            retry_busy(|| run_capped(Command::new(&bin), Duration::from_secs(5), 4096, "test"))
                .await
                .unwrap_err();
        assert!(err.to_string().contains("stderr 없음"), "err={err}");
    }

    /// stderr에 섞인 secret은 로그로 새지 않는다(aicd 로그는 진단 번들에 실려 나갈 수 있다).
    #[tokio::test]
    async fn stderr_in_the_error_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let bin = script_in(
            &dir,
            "leaky",
            "echo 'auth failed for AKIAIOSFODNN7EXAMPLE' >&2\nexit 1",
        );
        let err =
            retry_busy(|| run_capped(Command::new(&bin), Duration::from_secs(5), 4096, "test"))
                .await
                .unwrap_err();

        let msg = err.to_string();
        assert!(
            !msg.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret이 에러 메시지로 유출됨: {msg}"
        );
        assert!(msg.contains("[REDACTED:"), "redaction 표식이 없음: {msg}");
    }

    /// 수다스러운 stderr가 수집 자체를 실패시키면 안 된다(진단 보조일 뿐이다). 상한을 넘겨도
    /// stdout은 정상적으로 돌아오고, 자식은 파이프가 차서 블록되지 않는다(계속 비워 준다).
    #[tokio::test]
    async fn a_noisy_stderr_neither_fails_the_run_nor_deadlocks_the_child() {
        let dir = tempfile::tempdir().unwrap();
        // stderr로 상한(16KiB)을 훌쩍 넘겨 뱉은 뒤, stdout에 정상 결과를 낸다.
        let bin = script_in(
            &dir,
            "noisy",
            "i=0\nwhile [ $i -lt 4000 ]; do echo 'noise noise noise noise noise' >&2; i=$((i+1)); done\n\
             echo ok",
        );

        let out = tokio::time::timeout(
            Duration::from_secs(20),
            retry_busy(|| run_capped(Command::new(&bin), Duration::from_secs(15), 4096, "test")),
        )
        .await
        .expect("stderr를 비우지 않아 자식이 파이프에서 블록됐다(deadlock)")
        .unwrap();

        assert_eq!(String::from_utf8_lossy(&out).trim(), "ok");
    }

    #[test]
    fn stderr_hint_keeps_the_last_lines_and_redacts() {
        let raw = b"progress 1\nprogress 2\nfatal: permission denied\n";
        let hint = stderr_hint(raw);
        assert!(hint.contains("fatal: permission denied"), "hint={hint}");

        // 줄 수 상한을 넘으면 마지막 줄들만 남는다 — 원인은 끝에 있다.
        let many = (1..=10)
            .map(|i| format!("line{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let hint = stderr_hint(many.as_bytes());
        assert!(hint.contains("line10"), "마지막 줄이 남아야 함: {hint}");
        assert!(!hint.contains("line1\n"), "앞줄은 버려야 함: {hint}");
        assert!(
            !hint.contains("line7"),
            "STDERR_HINT_LINES(3)만 남아야 함: {hint}"
        );

        assert_eq!(stderr_hint(b"   \n  \n"), "", "공백뿐이면 빈 문자열");
    }

    #[tokio::test]
    async fn spawn_failure_is_an_error() {
        let missing = std::path::PathBuf::from("/definitely/does/not/exist/nope");
        assert!(
            run_capped(Command::new(missing), Duration::from_secs(5), 4096, "test")
                .await
                .is_err()
        );
    }

    /// **회귀 가드**: timeout 시 자식 프로세스가 실제로 죽어야 한다. `kill_on_drop` 없이 그냥
    /// `tokio::time::timeout`만 걸면 future만 drop되고 자식은 살아남아, 60초마다 도는 exporter
    /// task에서 orphan이 매 tick 누적된다. 플래그가 켜졌는지가 아니라 **프로세스가 사라졌는지**를
    /// 직접 확인한다(재시도 전략은 [`testutil`] 참고 — pid가 잡힐 때만 단정한다).
    #[tokio::test]
    async fn timeout_actually_kills_the_child_process() {
        for grace in GRACES {
            let dir = tempfile::tempdir().unwrap();
            let pidfile = dir.path().join("pid");
            let bin = script_in(&dir, "hang", &hang_script(&pidfile));

            let err = run_capped(Command::new(&bin), grace, 4096, "test")
                .await
                .unwrap_err();
            // 스크립트 exec race(ETXTBSY) — 자식이 아예 안 떴다. 다시 시도한다.
            if is_text_file_busy(&err) {
                continue;
            }
            assert!(err.to_string().contains("끝나지 않음"), "err={err}");

            // pid가 없으면 자식이 기동 전에 죽은 것 — 죽일 자식이 없었으니 단정하지 않는다
            // (여기서 통과시키면 공허한 테스트가 된다). 더 긴 grace로 재시도.
            let Some(pid) = read_pid(&pidfile) else {
                continue;
            };
            assert!(
                !alive(pid),
                "timeout 후에도 자식(pid={pid})이 살아 있다 — orphan 누수"
            );
            return;
        }
        panic!("자식이 한 번도 기동하지 못해 orphan 여부를 검증하지 못했다");
    }

    /// **회귀 가드**: 무한 출력이 메모리를 먹기 전에 끊긴다. 전부 버퍼링한 뒤 길이를 재는 구현
    /// (`wait_with_output()` 후 검사)이라면 이 테스트는 영원히 끝나지 않거나 OOM으로 죽는다.
    #[tokio::test]
    async fn unbounded_output_is_cut_off_mid_stream_and_the_child_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let bin = script_in(
            &dir,
            "flood",
            &format!(
                "echo $$ > {}\nwhile :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done",
                pidfile.display()
            ),
        );

        // 넉넉한 timeout을 준다 — 그래야 "상한 때문에 끊겼다"와 "timeout이라 끊겼다"가 구분된다.
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            run_capped(
                Command::new(&bin),
                Duration::from_secs(9),
                64 * 1024,
                "test",
            ),
        )
        .await
        .expect("상한이 동작하지 않아 무한 출력에 매달렸다")
        .unwrap_err();

        assert!(err.to_string().contains("상한"), "err={err}");

        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            !alive(pid),
            "상한 초과로 끊은 뒤에도 자식(pid={pid})이 계속 출력을 뱉고 있다"
        );
    }

    /// 상한 경계 — 정확히 상한만큼의 출력은 통과한다(off-by-one으로 정상 출력을 버리지 않는다).
    #[tokio::test]
    async fn output_exactly_at_the_cap_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        // printf로 개행 없이 정확히 100바이트.
        let bin = script_in(&dir, "exact", "printf 'a%.0s' $(seq 1 100)");
        let out =
            retry_busy(|| run_capped(Command::new(&bin), Duration::from_secs(5), 100, "test"))
                .await
                .unwrap();
        assert_eq!(out.len(), 100);
    }
}
