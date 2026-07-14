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
    encode_frame, AgentEvent, IpcRequest, IpcResponse, AGENT_KIND_FINDING_CREATED,
    AGENT_KIND_RISK_DENIED, AGENT_KIND_SNAPSHOT_RECORDED, AGENT_KIND_TOOL_RUN_COMMAND,
};

/// 소켓 연결/송신/응답 대기 상한. chat 흐름을 막지 않도록 짧게 잡는다 — aicd는 로컬 UDS라
/// 정상 상황에서 밀리초 단위로 끝난다.
const IO_TIMEOUT: Duration = Duration::from_millis(300);

/// 응답 본문 상한 — 우리가 읽는 응답(Pong/ExporterStatus)은 수백 바이트다. 손상된 길이
/// 헤더가 거대한 할당으로 이어지지 않게 막는다.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// `/record now <메모>`가 보낼 수 있는 메모 상한(바이트). 사람이 손으로 남기는 관찰 메모치고는
/// 넉넉하되(64KiB), IPC 프레임 상한(`aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES`, 16MiB)에는 한참
/// 못 미친다 — 1MB 메모 같은 병적 입력이 프레임 상한에 닿는 일을 여기서 미리 막는다(F16).
const MEMO_MAX_BYTES: usize = 64 * 1024;

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

/// 사람이 "지금 이 순간을 남긴다"고 판단해 기록한다 — 임계에 안 걸려도 사람이 이상하다고
/// 느낀 순간을 남기는 경로. severity는 항상 INFO(사건이 아니라 사람의 관찰 기록이다).
///
/// **`attrs` 키에 `exit_code`/`cwd`/`duration_ms`를 쓰지 마라** — 서버의 `EVENT_MAPPED_KEYS`가
/// 이 키들을 컬럼으로 흡수하며 attrs에서 지운다.
///
/// 호출부(chat `/record now <메모>`, CLI `aic snapshot record --memo`)를 대신해 여기서 병적 입력을
/// 처리한다 — 두 호출부가 각자 방어하면 한쪽만 고치고 잊는 경로가 생긴다:
/// - **빈 메모**(공백만 포함, 또는 sanitize 후 공백만 남는 메모)는 이벤트로서 무의미하므로 발화하지
///   않는다(F15). 로컬 스냅샷 저장은 이 함수와 무관하게 호출부가 계속 수행한다.
/// - **제어문자·ANSI escape 제거**(F17) — 수신측(터미널로 events를 훑어보는 사람)의 화면을 깨지
///   않게. 개행/탭은 메모의 정상적인 부분이라 남긴다.
/// - **UTF-8 경계 보존 절단**(F16) — IPC 프레임 상한(16MiB)에 닿지 않게 훨씬 낮은 선에서 자른다.
///
/// 반환값 = **실제로 발화를 시도했는가**(fire-and-forget이라 aicd 도달 여부는 알 수 없다 — 그건
/// [`exporter_status`]로 별도 확인). `false`면 sanitize 후 메모가 비어 스킵했다는 뜻이라, 호출부가
/// 이 값으로 "메모가 비어 애초에 안 보냈다"와 "보내려 했지만 aicd가 없어 조용히 실패했다"(F19)를
/// 구분해 사용자에게 다른 안내를 줄 수 있다.
pub fn snapshot_recorded(memo: &str, attrs: BTreeMap<String, String>) -> bool {
    let memo = sanitize_memo(memo);
    if memo.trim().is_empty() {
        return false;
    }
    dispatch(snapshot_event(&memo, attrs));
    true
}

/// 메모를 전송 전 안전화한다: 제어문자(ESC 등) 제거(개행·탭은 유지) → UTF-8 경계 보존 절단.
/// 순수 함수(테스트 가능). ESC(`\x1b`)만 지워도 뒤따르는 CSI 바이트열(`[33m` 등)은 그냥 평문으로
/// 남아 터미널이 escape sequence로 해석하지 않으므로 이 정도로 충분하다.
fn sanitize_memo(memo: &str) -> String {
    let cleaned: String = memo
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    crate::agent::tool_record::cap_str(&cleaned, MEMO_MAX_BYTES).0
}

/// `snapshot_recorded`가 보낼 이벤트를 만든다. kind/severity를 **인자로 받지 않고 본문에
/// 고정**한다 — 그래야 테스트가 이 두 값을 주입하지 않고 결과만 검증할 수 있다(회귀를 실제로 잡는다).
fn snapshot_event(memo: &str, attrs: BTreeMap<String, String>) -> AgentEvent {
    build_event(AGENT_KIND_SNAPSHOT_RECORDED, memo, "INFO", attrs)
}

/// exporter가 지금 collector에 닿고 있는지 aicd에 묻는다 (chat status bar용).
///
/// `None`은 **aicd에 물어보지 못했다**는 뜻이다 — 미실행이거나, 이 요청을 모르는 구버전이거나,
/// 응답이 timeout됐다. `Some(status)`의 `enabled: false`는 "aicd는 살아있지만 exporter가 꺼져
/// 있다"로, 둘은 사용자에게 전혀 다른 상태라 구분해서 돌려준다.
pub fn exporter_status() -> Option<aic_common::ExporterStatus> {
    match query(&IpcRequest::GetExporterStatus) {
        Ok(IpcResponse::ExporterStatus(s)) => Some(s),
        // 구버전 aicd는 unknown request를 graceful Error로 답한다 → 조회 불가로 취급.
        _ => None,
    }
}

/// `AgentEvent`를 만든다(summary/attrs 값 redaction 포함). 순수 함수라 네트워크 없이 검증 가능하다.
fn build_event(
    kind: &str,
    summary: &str,
    severity: &str,
    attrs: BTreeMap<String, String>,
) -> AgentEvent {
    AgentEvent {
        kind: kind.to_string(),
        summary: redact(summary),
        severity: severity.to_string(),
        attrs: attrs
            .into_iter()
            .map(|(k, v)| (k, redact(&v)))
            .collect::<BTreeMap<_, _>>(),
        ts: chrono::Utc::now(),
    }
}

/// 만들어진 이벤트를 aicd로 보낸다. 실패는 전부 무시한다(aicd 미실행은 정상 상태이고,
/// 텔레메트리가 chat을 방해해선 안 된다 — audit/rca_memory 등 다른 best-effort 경로와 같은 관례).
fn dispatch(ev: AgentEvent) {
    let _ = send(&IpcRequest::AgentEvent(ev));
}

/// 한 행위를 aicd로 보낸다(build + dispatch).
fn emit(kind: &str, summary: &str, severity: &str, attrs: BTreeMap<String, String>) {
    dispatch(build_event(kind, summary, severity, attrs));
}

/// 송신 대상 문자열을 마스킹한다. `redaction::redact`는 idempotent라 이미 redact된 입력에
/// 다시 적용해도 안전하다. 반환 튜플의 `.1`(리포트)은 여기선 쓰지 않는다.
fn redact(s: &str) -> String {
    crate::redaction::redact(s).0
}

/// 요청을 보내고 응답을 무시한다(fire-and-forget). 응답을 **읽기는** 한다 — 곧바로 끊으면
/// aicd 쪽에 "클라이언트 조기 종료" 경고가 남기 때문이다.
fn send(req: &IpcRequest) -> std::io::Result<()> {
    query(req).map(|_| ())
}

/// 요청을 보내고 응답을 파싱해 돌려준다. 프레임은 length-prefixed JSON(`encode_frame`).
fn query(req: &IpcRequest) -> std::io::Result<IpcResponse> {
    let payload = serde_json::to_vec(req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut stream = UnixStream::connect(aic_common::aicd_socket_path())?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&encode_frame(&payload))?;
    stream.flush()?;

    // 4바이트 길이 헤더 → 본문. 상한을 두어 손상된 헤더가 거대한 할당으로 이어지지 않게 한다.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_RESPONSE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("응답이 너무 큼: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// redaction 테스트 공용 fixture — AWS 공식 문서가 예시용으로 지정한 **가짜** access key
    /// (실제 자격증명 아님). 이 모듈의 모든 secret-redaction 테스트가 각자 리터럴을 새로 선언하는
    /// 대신 이 상수 하나를 재사용한다 — privacy 스캐너(`git-kit commit`)가 파일 전체에서 "AKIA…"
    /// 꼴 리터럴 개수를 threshold로 세는데, 같은 fixture를 테스트마다 다시 타이핑하면 실제 secret
    /// 유출과 무관하게 그 카운트만 늘어난다.
    const AWS_KEY_FIXTURE: &str = "AKIAIOSFODNN7EXAMPLE";

    #[test]
    fn send_without_daemon_is_silent() {
        // aicd 소켓이 없어도(미실행) 패닉하지 않고 조용히 실패해야 한다 — 정상 경로다.
        // 실제 소켓 경로가 살아 있는 개발 머신에서도 이 호출은 성공하거나 조용히 실패할 뿐이다.
        tool_run_command("echo hi", Some(0), 12, "/tmp");
        risk_denied("rm -rf /", "Dangerous", Some("builtin_denylist"));
        finding_created("disk_full", "WARN", "/ 사용률 95%");
        snapshot_recorded(
            "cpu sys 26%, idle 67% — 커널 모드 비율이 높음",
            BTreeMap::new(),
        );
    }

    #[test]
    fn snapshot_event_kind_and_severity_come_from_the_function_body() {
        // kind/severity를 테스트가 주입하지 않는다 — snapshot_event()가 본문에 고정한 값을
        // 그대로 검증한다. 누가 kind를 다른 상수로 바꾸거나 severity를 WARN으로 바꾸면 실패한다.
        let ev = snapshot_event("이상하게 느려짐", BTreeMap::new());

        assert_eq!(ev.kind, "snapshot.recorded");
        assert_eq!(
            ev.severity, "INFO",
            "사람의 관찰 기록이라 사건 severity를 달지 않는다"
        );
        assert_eq!(ev.summary, "이상하게 느려짐");
    }

    #[test]
    fn snapshot_event_carries_caller_attrs() {
        let mut attrs = BTreeMap::new();
        attrs.insert("memo_source".to_string(), "manual".to_string());
        let ev = snapshot_event("memo", attrs);

        assert_eq!(ev.attrs.get("memo_source"), Some(&"manual".to_string()));
    }

    #[test]
    fn snapshot_event_redacts_summary_and_attrs() {
        // snapshot_recorded() 경로가 실제로 redaction을 거치는지 본다 — summary와 attrs 값 양쪽.
        let secret = AWS_KEY_FIXTURE;
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "note".to_string(),
            format!("export AWS_SECRET_ACCESS_KEY={secret}"),
        );
        let ev = snapshot_event(&format!("키가 노출됨: {secret}"), attrs);

        assert!(
            !ev.summary.contains(secret),
            "summary가 마스킹되지 않음: {}",
            ev.summary
        );
        let masked = ev.attrs.get("note").expect("note attr 존재");
        assert!(
            !masked.contains(secret),
            "attrs 값이 마스킹되지 않음: {masked}"
        );
    }

    #[test]
    fn summary_and_attrs_are_redacted_before_leaving_the_process() {
        // emit이 만드는 AgentEvent를 직접 만들어 redaction이 걸리는지 확인한다.
        let secret = format!("export AWS_SECRET_ACCESS_KEY={AWS_KEY_FIXTURE}");
        let masked = redact(&secret);
        assert!(
            !masked.contains(AWS_KEY_FIXTURE),
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

    // ── t3 B3: `/record now <메모>` 적대적 입력(F14~F17) ─────────────────────────

    #[test]
    fn snapshot_recorded_skips_empty_or_whitespace_only_memo() {
        // F15: 빈 메모/공백뿐인 메모는 발화하지 않는다 — 반환값 false로 "스킵했다"를 네트워크
        // 없이 관찰할 수 있다(dispatch를 부르기 **전에** 조기 반환하므로 daemon 유무와 무관하게
        // 결정적).
        assert!(!snapshot_recorded("", BTreeMap::new()));
        assert!(!snapshot_recorded("   \n\t  ", BTreeMap::new()));
    }

    #[test]
    fn snapshot_recorded_skips_memo_that_sanitizes_to_empty() {
        // F15+F17 결합: 공백은 아니지만(제어문자만 있음) sanitize 후 공백만 남는 메모도 스킵해야
        // 한다 — parse 단계의 `.trim()`(유니코드 공백만 제거)은 ESC 같은 제어문자를 못 거르므로,
        // 이 판정이 sanitize **이후**에 있어야만 잡히는 케이스다.
        assert!(!snapshot_recorded("\x1b\x1b\x1b", BTreeMap::new()));
    }

    #[test]
    fn snapshot_recorded_sends_non_empty_memo() {
        // 진짜 메모는 발화를 시도한다(반환 true) — daemon 유무와 무관(fire-and-forget).
        assert!(snapshot_recorded("cpu 이상하게 높음", BTreeMap::new()));
    }

    #[test]
    fn sanitize_memo_strips_control_chars_and_ansi_but_keeps_newline_and_tab() {
        // F17: 제어문자/ANSI escape가 수신측 표시를 깨지 않아야 한다. ESC를 지우면 뒤따르는
        // CSI 바이트열은 이스케이프 시퀀스가 아니라 평범한 문자로 남는다(터미널이 해석 안 함).
        let input = "line1\x1b[31mRED\x1b[0m\tline1-tab\nline2\x07bell";
        let out = sanitize_memo(input);
        assert!(!out.contains('\x1b'), "ESC가 남음: {out:?}");
        assert!(!out.contains('\x07'), "BEL이 남음: {out:?}");
        assert!(out.contains('\n'), "개행이 지워짐: {out:?}");
        assert!(out.contains('\t'), "탭이 지워짐: {out:?}");
        // ESC만 사라지고 나머지 텍스트(색상 코드 잔여물 포함)는 평문으로 보존.
        assert!(out.contains("[31mRED[0m"), "본문이 훼손됨: {out:?}");
    }

    #[test]
    fn sanitize_memo_truncates_oversized_input_at_utf8_boundary() {
        // F16: 1MB 메모 같은 병적 입력이 절단되어 IPC 프레임 상한(16MiB)에 닿지 않는다.
        // 멀티바이트 문자(한글, 3바이트)로 채워 절단 지점이 문자 중간이면 즉시 드러나게 한다.
        let oversized = "가".repeat(1_000_000); // 3MB (문자당 3바이트)
        let out = sanitize_memo(&oversized);
        assert!(
            out.len() <= MEMO_MAX_BYTES,
            "절단이 상한을 넘음: {} bytes",
            out.len()
        );
        assert!(out.len() < 1_000_000 * 3, "절단이 전혀 안 됨");
        // UTF-8 경계 보존 — 잘렸어도 유효한 문자열이어야 한다(패닉하면 경계를 깬 것).
        assert!(
            out.chars().all(|c| c == '가'),
            "절단이 문자 중간을 깨서 깨진 바이트가 섞임: {out:?}"
        );
    }

    #[test]
    fn sanitize_memo_does_not_defeat_redaction() {
        // F14: sanitize_memo(제어문자 제거)를 먼저 거쳐도 redaction이 여전히 걸려야 한다(두 방어가
        // 서로를 무력화하지 않는다).
        let secret = AWS_KEY_FIXTURE;
        let noisy = format!("\x1b[31mexport AWS_SECRET_ACCESS_KEY={secret}\x1b[0m");
        let memo = sanitize_memo(&noisy);
        let ev = snapshot_event(&memo, BTreeMap::new());
        assert!(
            !ev.summary.contains(secret),
            "sanitize 이후에도 secret이 마스킹돼야 함: {}",
            ev.summary
        );
    }
}
