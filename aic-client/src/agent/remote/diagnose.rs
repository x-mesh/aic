//! 원격 aic diagnose --no-analyze --json 결과의 버전드 집계 계약.
//!
//! SSH 전송 상태와 원격 진단 payload 상태를 분리한다. SSH가 성공해도 오래되거나 손상된 JSON이면
//! invalid_payload이며 정상 진단으로 승격하지 않는다.

use serde::Serialize;
use serde_json::Value;

use super::{FanoutResult, HostStatus, RemoteCommand};

pub const REMOTE_DIAGNOSE_SCHEMA_VERSION: u32 = 1;
const MAX_REMOTE_SYMPTOM_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteDiagnosisState {
    Success,
    TransportError,
    InvalidPayload,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteDiagnosisHost {
    pub host: String,
    pub state: RemoteDiagnosisState,
    pub transport_status: Option<HostStatus>,
    pub duration_ms: Option<u64>,
    pub truncated: bool,
    pub redacted: usize,
    pub diagnosis: Option<Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteDiagnosisReport {
    pub schema_version: u32,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub target: String,
    pub symptom: Option<String>,
    pub wall_timed_out: bool,
    pub summary: RemoteDiagnosisSummary,
    pub hosts: Vec<RemoteDiagnosisHost>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteDiagnosisSummary {
    pub success: usize,
    pub transport_error: usize,
    pub invalid_payload: usize,
    pub incomplete: usize,
    pub total: usize,
}

impl RemoteDiagnosisSummary {
    fn from_hosts(hosts: &[RemoteDiagnosisHost]) -> Self {
        Self {
            success: count_state(hosts, RemoteDiagnosisState::Success),
            transport_error: count_state(hosts, RemoteDiagnosisState::TransportError),
            invalid_payload: count_state(hosts, RemoteDiagnosisState::InvalidPayload),
            incomplete: count_state(hosts, RemoteDiagnosisState::Incomplete),
            total: hosts.len(),
        }
    }
}

impl RemoteDiagnosisReport {
    pub fn from_fanout(target: String, symptom: Option<String>, result: FanoutResult) -> Self {
        let mut hosts: Vec<RemoteDiagnosisHost> = result
            .results
            .into_iter()
            .map(|remote| {
                let transport_ok = matches!(remote.status, HostStatus::Ok | HostStatus::OkWithWarn);
                if !transport_ok {
                    let error = first_nonempty(&remote.stderr, &remote.stdout)
                        .unwrap_or("원격 명령 실행 실패")
                        .to_string();
                    return RemoteDiagnosisHost {
                        host: remote.host,
                        state: RemoteDiagnosisState::TransportError,
                        transport_status: Some(remote.status),
                        duration_ms: Some(remote.duration_ms),
                        truncated: remote.truncated,
                        redacted: remote.redacted,
                        diagnosis: None,
                        error: Some(error),
                    };
                }

                if remote.truncated {
                    return RemoteDiagnosisHost {
                        host: remote.host,
                        state: RemoteDiagnosisState::InvalidPayload,
                        transport_status: Some(remote.status),
                        duration_ms: Some(remote.duration_ms),
                        truncated: true,
                        redacted: remote.redacted,
                        diagnosis: None,
                        error: Some("원격 diagnosis 출력이 저장 상한을 넘어 잘림".to_string()),
                    };
                }

                match parse_diagnosis_envelope(&remote.stdout) {
                    Ok(diagnosis) => RemoteDiagnosisHost {
                        host: remote.host,
                        state: RemoteDiagnosisState::Success,
                        transport_status: Some(remote.status),
                        duration_ms: Some(remote.duration_ms),
                        truncated: remote.truncated,
                        redacted: remote.redacted,
                        diagnosis: Some(diagnosis),
                        error: None,
                    },
                    Err(error) => RemoteDiagnosisHost {
                        host: remote.host,
                        state: RemoteDiagnosisState::InvalidPayload,
                        transport_status: Some(remote.status),
                        duration_ms: Some(remote.duration_ms),
                        truncated: remote.truncated,
                        redacted: remote.redacted,
                        diagnosis: None,
                        error: Some(error),
                    },
                }
            })
            .collect();

        hosts.extend(
            result
                .incomplete
                .into_iter()
                .map(|host| RemoteDiagnosisHost {
                    host,
                    state: RemoteDiagnosisState::Incomplete,
                    transport_status: None,
                    duration_ms: None,
                    truncated: false,
                    redacted: 0,
                    diagnosis: None,
                    error: Some("wall-clock timeout 전에 완료되지 않음".to_string()),
                }),
        );
        hosts.sort_by(|a, b| a.host.cmp(&b.host));

        let summary = RemoteDiagnosisSummary::from_hosts(&hosts);
        Self {
            schema_version: REMOTE_DIAGNOSE_SCHEMA_VERSION,
            observed_at: chrono::Utc::now(),
            target,
            symptom,
            wall_timed_out: result.wall_timed_out,
            summary,
            hosts,
        }
    }

    pub fn all_succeeded(&self) -> bool {
        !self.wall_timed_out
            && !self.hosts.is_empty()
            && self
                .hosts
                .iter()
                .all(|host| host.state == RemoteDiagnosisState::Success)
    }

    pub fn render_text(&self) -> String {
        let mut out = format!(
            "remote diagnose: {} · {}/{} success\n",
            self.target, self.summary.success, self.summary.total,
        );
        for host in &self.hosts {
            out.push_str(&format!("\n{} [{}]", host.host, state_label(host.state)));
            if let Some(duration_ms) = host.duration_ms {
                out.push_str(&format!(" · {duration_ms}ms"));
            }
            out.push('\n');

            if let Some(diagnosis) = &host.diagnosis {
                let findings = diagnosis
                    .get("auto_findings")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if findings.is_empty() {
                    out.push_str("  결정적 발견 없음\n");
                } else {
                    for finding in findings {
                        let message = finding
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("(message 없음)");
                        out.push_str(&format!("  - {message}\n"));
                    }
                }
            }
            if let Some(error) = &host.error {
                out.push_str(&format!("  error: {}\n", one_line(error)));
            }
        }
        if self.wall_timed_out {
            out.push_str("\nwall-clock timeout: 일부 호스트 결과가 미완료입니다.\n");
        }
        out
    }
}

pub fn command(symptom: &[String]) -> Result<RemoteCommand, String> {
    let symptom_bytes = symptom.iter().map(String::len).sum::<usize>();
    if symptom_bytes > MAX_REMOTE_SYMPTOM_BYTES {
        return Err(format!(
            "원격 진단 증상은 {MAX_REMOTE_SYMPTOM_BYTES} bytes 이하여야 합니다"
        ));
    }
    if let Some(token) = symptom
        .iter()
        .find(|token| token.starts_with('-') || token.chars().any(char::is_control))
    {
        return Err(format!("원격 진단 증상에 허용되지 않는 토큰: {token:?}"));
    }
    let mut args = vec!["diagnose".to_string()];
    args.extend(symptom.iter().cloned());
    args.push("--no-analyze".to_string());
    args.push("--json".to_string());
    Ok(RemoteCommand::new("aic").args(args))
}

fn parse_diagnosis_envelope(stdout: &str) -> Result<Value, String> {
    let envelope: Value = serde_json::from_str(stdout.trim())
        .map_err(|error| format!("원격 diagnosis JSON 파싱 실패: {error}"))?;
    if envelope.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("지원하지 않는 원격 diagnosis schema_version".to_string());
    }
    envelope
        .get("diagnosis")
        .filter(|diagnosis| diagnosis.is_object())
        .cloned()
        .ok_or_else(|| "원격 diagnosis payload 누락".to_string())
}

fn first_nonempty<'a>(first: &'a str, second: &'a str) -> Option<&'a str> {
    [first, second]
        .into_iter()
        .map(str::trim)
        .find(|s| !s.is_empty())
}

fn one_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn state_label(state: RemoteDiagnosisState) -> &'static str {
    match state {
        RemoteDiagnosisState::Success => "success",
        RemoteDiagnosisState::TransportError => "transport_error",
        RemoteDiagnosisState::InvalidPayload => "invalid_payload",
        RemoteDiagnosisState::Incomplete => "incomplete",
    }
}

fn count_state(hosts: &[RemoteDiagnosisHost], state: RemoteDiagnosisState) -> usize {
    hosts.iter().filter(|host| host.state == state).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::remote::RemoteResult;

    fn remote(host: &str, status: HostStatus, stdout: &str) -> RemoteResult {
        RemoteResult {
            host: host.to_string(),
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: if matches!(status, HostStatus::Ok | HostStatus::OkWithWarn) {
                0
            } else {
                1
            },
            duration_ms: 12,
            status,
            truncated: false,
            redacted: 0,
        }
    }

    #[test]
    fn remote_diagnose_command_is_fixed_read_only_json() {
        let cmd = command(&["disk".to_string(), "full".to_string()]).unwrap();
        assert_eq!(cmd.program, "aic");
        assert_eq!(
            cmd.args,
            ["diagnose", "disk", "full", "--no-analyze", "--json"]
        );
    }

    #[test]
    fn remote_diagnose_rejects_flag_injection() {
        let error = command(&["--kernel".to_string()]).unwrap_err();
        assert!(error.contains("허용되지 않는 토큰"));
    }

    #[test]
    fn remote_diagnose_separates_transport_and_payload_failures() {
        let report = RemoteDiagnosisReport::from_fanout(
            "@web".to_string(),
            Some("disk full".to_string()),
            FanoutResult {
                results: vec![
                    remote(
                        "ok",
                        HostStatus::Ok,
                        r#"{"schema_version":1,"diagnosis":{"auto_findings":[]}}"#,
                    ),
                    remote("bad-json", HostStatus::Ok, "not json"),
                    remote("offline", HostStatus::Unreachable, ""),
                ],
                wall_timed_out: true,
                incomplete: vec!["slow".to_string()],
            },
        );

        assert_eq!(report.hosts[0].host, "bad-json");
        assert_eq!(report.hosts[0].state, RemoteDiagnosisState::InvalidPayload);
        assert_eq!(report.hosts[1].state, RemoteDiagnosisState::TransportError);
        assert_eq!(report.hosts[2].state, RemoteDiagnosisState::Success);
        assert_eq!(report.hosts[3].state, RemoteDiagnosisState::Incomplete);
        assert_eq!(report.summary.success, 1);
        assert_eq!(report.summary.transport_error, 1);
        assert_eq!(report.summary.invalid_payload, 1);
        assert_eq!(report.summary.incomplete, 1);
        assert_eq!(report.summary.total, 4);
        assert!(!report.all_succeeded());
    }

    /// 상한은 토큰 길이의 **바이트 합**이다 — 구분자는 세지 않는다. 한국어 증상은 글자당
    /// 3바이트라 훨씬 적은 글자 수에서 걸리므로, 경계를 못 박아 둔다.
    #[test]
    fn remote_diagnose_symptom_cap_is_measured_in_bytes() {
        let at_cap = "a".repeat(MAX_REMOTE_SYMPTOM_BYTES);
        assert!(
            command(&[at_cap]).is_ok(),
            "상한과 같은 크기는 통과해야 한다"
        );

        let over_cap = "a".repeat(MAX_REMOTE_SYMPTOM_BYTES + 1);
        let error = command(&[over_cap]).unwrap_err();
        assert!(error.contains("bytes 이하"));

        // 토큰이 나뉘어도 합산 기준은 같다 — 구분자 공백은 상한에 포함되지 않는다.
        let half = "a".repeat(MAX_REMOTE_SYMPTOM_BYTES / 2);
        assert!(command(&[half.clone(), half]).is_ok());

        // 한글은 글자당 3바이트 — 171자면 513바이트라 상한을 넘는다.
        let korean = "디".repeat(MAX_REMOTE_SYMPTOM_BYTES / 3 + 1);
        assert!(
            command(&[korean]).is_err(),
            "글자 수가 아니라 바이트로 재야 한다"
        );
    }

    /// 사람이 보는 기본 출력. 호스트마다 상태 라벨이 붙고, 성공했지만 발견이 없는 호스트와
    /// 실패한 호스트가 서로 다른 줄로 구분되어야 "일부만 확인됐다"가 눈에 남는다.
    #[test]
    fn remote_diagnose_text_keeps_per_host_state_visible() {
        let report = RemoteDiagnosisReport::from_fanout(
            "@web".to_string(),
            None,
            FanoutResult {
                results: vec![
                    remote(
                        "clean",
                        HostStatus::Ok,
                        r#"{"schema_version":1,"diagnosis":{"auto_findings":[]}}"#,
                    ),
                    remote(
                        "busy",
                        HostStatus::Ok,
                        r#"{"schema_version":1,"diagnosis":{"auto_findings":[{"message":"disk 94%"}]}}"#,
                    ),
                    remote("offline", HostStatus::Unreachable, ""),
                ],
                wall_timed_out: true,
                incomplete: vec!["slow".to_string()],
            },
        );

        let text = report.render_text();
        assert!(text.starts_with("remote diagnose: @web · 2/4 success\n"));
        assert!(text.contains("busy [success]"));
        assert!(text.contains("  - disk 94%"));
        assert!(text.contains("clean [success]"));
        assert!(text.contains("  결정적 발견 없음"));
        assert!(text.contains("offline [transport_error]"));
        assert!(text.contains("slow [incomplete]"));
        assert!(
            text.contains("wall-clock timeout: 일부 호스트 결과가 미완료입니다."),
            "미완료가 있었다는 사실이 출력에서 사라지면 안 된다"
        );
    }

    #[test]
    fn remote_diagnose_rejects_unknown_schema() {
        let error =
            parse_diagnosis_envelope(r#"{"schema_version":2,"diagnosis":{"auto_findings":[]}}"#)
                .unwrap_err();
        assert!(error.contains("schema_version"));
    }

    #[test]
    fn remote_diagnose_never_accepts_truncated_payload() {
        let mut result = remote(
            "truncated",
            HostStatus::Ok,
            r#"{"schema_version":1,"diagnosis":{"auto_findings":[]}}"#,
        );
        result.truncated = true;
        let report = RemoteDiagnosisReport::from_fanout(
            "truncated".to_string(),
            None,
            FanoutResult {
                results: vec![result],
                wall_timed_out: false,
                incomplete: vec![],
            },
        );
        assert_eq!(report.hosts[0].state, RemoteDiagnosisState::InvalidPayload);
        assert!(!report.all_succeeded());
    }
}
