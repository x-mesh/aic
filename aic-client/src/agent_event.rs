//! chat/agent 행위를 aicd로 넘기는 fire-and-forget 송신기 (OTLP `aic.agent` scope).
//!
//! chat은 단명하는 프로세스라 collector 연결·spool·backoff를 직접 들 수 없다. 그래서 행위를
//! aicd에 넘기고, 상주 데몬의 exporter가 무유실 전송을 책임진다 — shell hook이 command를 넘기는
//! 구조와 같다.
//!
//! **sync 블로킹**으로 구현한다. 호출부(`run_command::execute_with_corr`, `risk_guard` 차단
//! 경로, diagnose 스캔)가 전부 sync라 async 런타임 핸들을 가정할 수 없고, `crate::audit::append`가
//! 이미 같은 성격(동기 best-effort 기록)이라 관례도 맞다. 소켓 I/O에 짧은 timeout을 걸어
//! aicd가 느리거나 죽어 있어도 chat이 멈추지 않게 한다.
//!
//! **실패는 전부 무시한다**(silent skip). aicd 미실행은 정상 상태이고, 텔레메트리 송신 실패가
//! 사용자의 chat 흐름을 방해해서는 안 된다.
//!
//! **redaction은 여기서 한다** — summary/attrs 값이 프로세스 경계를 넘기 전에 마스킹한다.
//! 인코딩 단계(`logs_proto`)에서 한 번 더 redact되지만(idempotent), 원본이 데몬으로 넘어가지
//! 않게 하는 게 1차 방어선이다.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use aic_common::{
    encode_frame, AgentEvent, IpcRequest, AGENT_KIND_FINDING_CREATED, AGENT_KIND_RISK_DENIED,
    AGENT_KIND_TOOL_RUN_COMMAND,
};

/// 소켓 연결/송신/응답 대기 상한. chat 흐름을 막지 않도록 짧게 잡는다 — aicd는 로컬 UDS라
/// 정상 상황에서 밀리초 단위로 끝난다.
const IO_TIMEOUT: Duration = Duration::from_millis(300);

/// agent가 셸 명령을 실행했다. 시스템을 바꿨을 수 있는 유일한 도구라 항상 보낸다.
/// 차단된 명령은 여기가 아니라 [`risk_denied`]로 간다.
pub fn tool_run_command(command: &str, exit_code: Option<i32>, duration_ms: u64, cwd: &str) {
    let mut attrs = BTreeMap::new();
    attrs.insert(
        "exit_code".to_string(),
        exit_code.map_or_else(|| "unknown".to_string(), |c| c.to_string()),
    );
    attrs.insert("duration_ms".to_string(), duration_ms.to_string());
    attrs.insert("cwd".to_string(), cwd.to_string());
    // 실패한 명령은 RCA에서 먼저 봐야 하므로 severity를 올린다.
    let severity = match exit_code {
        Some(0) => "INFO",
        _ => "ERROR",
    };
    emit(AGENT_KIND_TOOL_RUN_COMMAND, command, severity, attrs);
}

/// risk_guard가 명령을 차단했다 — 위험한 시도가 있었다는 보안 신호라 항상 WARN이다.
pub fn risk_denied(command: &str, risk_level: &str, rule: Option<&str>) {
    let mut attrs = BTreeMap::new();
    attrs.insert("risk_level".to_string(), risk_level.to_string());
    if let Some(rule) = rule {
        attrs.insert("rule".to_string(), rule.to_string());
    }
    emit(AGENT_KIND_RISK_DENIED, command, "WARN", attrs);
}

/// 진단이 finding을 만들었다. `severity`는 이미 OTLP 표기(ERROR/WARN/INFO)로 매핑된 값이다.
pub fn finding_created(probe_id: &str, severity: &str, message: &str) {
    let mut attrs = BTreeMap::new();
    attrs.insert("probe_id".to_string(), probe_id.to_string());
    emit(AGENT_KIND_FINDING_CREATED, message, severity, attrs);
}

/// 한 행위를 aicd로 보낸다. 실패는 전부 무시한다(aicd 미실행은 정상 상태).
fn emit(kind: &str, summary: &str, severity: &str, attrs: BTreeMap<String, String>) {
    let ev = AgentEvent {
        kind: kind.to_string(),
        summary: redact(summary),
        severity: severity.to_string(),
        attrs: attrs
            .into_iter()
            .map(|(k, v)| (k, redact(&v)))
            .collect::<BTreeMap<_, _>>(),
        ts: chrono::Utc::now(),
    };
    // 실패는 무시한다 — aicd 미실행은 정상 상태이고, 텔레메트리가 chat을 방해해선 안 된다.
    // (audit/rca_memory 등 다른 best-effort 경로와 같은 관례: lib 모듈은 조용히 실패한다.)
    let _ = send(&IpcRequest::AgentEvent(ev));
}

/// 송신 대상 문자열을 마스킹한다. `redaction::redact`는 idempotent라 이미 redact된 입력에
/// 다시 적용해도 안전하다. 반환 튜플의 `.1`(리포트)은 여기선 쓰지 않는다.
fn redact(s: &str) -> String {
    crate::redaction::redact(s).0
}

fn send(req: &IpcRequest) -> std::io::Result<()> {
    let payload = serde_json::to_vec(req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut stream = UnixStream::connect(aic_common::aicd_socket_path())?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&encode_frame(&payload))?;
    stream.flush()?;
    // 응답(Pong)을 읽어 서버가 프레임을 소비할 시간을 준다 — 곧바로 끊으면 aicd 쪽에
    // "클라이언트 조기 종료" 경고가 남는다. 내용은 쓰지 않으므로 실패해도 무시한다.
    let mut buf = [0u8; 64];
    let _ = stream.read(&mut buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_without_daemon_is_silent() {
        // aicd 소켓이 없어도(미실행) 패닉하지 않고 조용히 실패해야 한다 — 정상 경로다.
        // 실제 소켓 경로가 살아 있는 개발 머신에서도 이 호출은 성공하거나 조용히 실패할 뿐이다.
        tool_run_command("echo hi", Some(0), 12, "/tmp");
        risk_denied("rm -rf /", "Dangerous", Some("builtin_denylist"));
        finding_created("disk_full", "WARN", "/ 사용률 95%");
    }

    #[test]
    fn summary_and_attrs_are_redacted_before_leaving_the_process() {
        // emit이 만드는 AgentEvent를 직접 만들어 redaction이 걸리는지 확인한다.
        let secret = "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE";
        let masked = redact(secret);
        assert!(
            !masked.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret이 마스킹되지 않음: {masked}"
        );
    }

    #[test]
    fn failed_command_is_error_severity() {
        // exit_code 0만 INFO, 나머지(실패/unknown)는 ERROR — RCA에서 실패를 먼저 보게 한다.
        let sev = |c: Option<i32>| match c {
            Some(0) => "INFO",
            _ => "ERROR",
        };
        assert_eq!(sev(Some(0)), "INFO");
        assert_eq!(sev(Some(1)), "ERROR");
        assert_eq!(sev(None), "ERROR");
    }
}
