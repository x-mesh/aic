//! OTLP Logs protobuf 최소 subset (SRE t7: events/connections가 공유).
//!
//! `encode.rs`(t6, metrics 전용)와 같은 설계 원칙을 따른다 — opentelemetry-proto crate 대신 prost
//! 직접 + 손수 정의한 최소 message subset이며, 각 `tag`는 opentelemetry-proto v1 `.proto`의 필드
//! 번호와 1:1로 맞춘다. `KeyValue`/`AnyValue`/`Resource`/`InstrumentationScope`는 `encode.rs`와
//! 구조가 동일하지만 **의도적으로 별도 정의**한다 — encode.rs는 이미 테스트된 t6 코드라 공유
//! 리팩터링으로 손대는 대신, logs 신호(events + connections)가 이 파일 하나만 보면 무엇을
//! 보내는지 알 수 있게 self-contained로 둔다.
//!
//! **redaction invariant(+예외 1건)**: encode.rs와 동일하게, 원칙적으로 모든 문자열 필드는
//! [`redact_str`]를 통과한다(command text·hostname처럼 "우연히 섞여든" secret/PII를 막기 위함).
//! **단, `network.local.address`/`network.peer.address`/`host.ip` 값은 redact하지 않는다.**
//! redaction 패턴에 IPv4가 포함돼 있어(`aic_common::redaction`) 그대로 적용하면 모든 연결이
//! `[REDACTED:ipv4]`로 뭉개져 connections exporter 자체가 무의미해진다 — 이 필드들은 "실수로
//! 섞여든 PII"가 아니라 **exporter의 목적 그 자체인 payload**다(자기 소유 서버의 연결 토폴로지
//! 관측, Datadog agent류 네트워크 모니터링과 동일 성격). key는 고정 상수라 redact해도 no-op이지만
//! 경로 통일을 위해 key는 계속 [`redact_str`]를 거친다 — value만 예외([`attr_addr`] 참고).
//! 숫자 필드(exit_code/port 등)는 애초에 secret이 아니므로 redaction 대상이 아니다.

use prost::Message as _;

/// 송신 직전 secret/PII 마스킹. 문자열 필드가 이 함수를 거친다(주소류 예외는 [`attr_addr`] 참고).
fn redact_str(s: &str) -> String {
    aic_common::redaction::redact(s).0
}

/// resource `service.name` — 중앙 collector가 aic 데몬이 보낸 텔레메트리임을 구분하는 키.
const SERVICE_NAME: &str = "aicd";

/// OTLP SeverityNumber(logs.proto) — 우리가 쓰는 세 값만 상수화한다.
const SEVERITY_INFO: i32 = 9;
const SEVERITY_WARN: i32 = 13;
const SEVERITY_ERROR: i32 = 17;

/// command 종료 이벤트 하나 — `aic.events` scope LogRecord로 인코딩할 입력.
pub struct CommandEvent<'a> {
    pub id: &'a str,
    pub command: Option<&'a str>,
    pub exit_code: i32,
    /// `CaptureQuality`의 `Debug` 표현(예: `"FullOutput"`) — 별도 enum 매핑 없이 그대로 문자열 attr.
    pub capture_quality: &'a str,
}

/// listen/established 소켓 하나 — `aic.connections` scope LogRecord로 인코딩할 입력.
pub struct ConnectionEntry<'a> {
    pub protocol: &'a str,
    pub state: &'a str,
    pub local_addr: &'a str,
    pub local_port: u16,
    pub peer_addr: Option<&'a str>,
    pub peer_port: Option<u16>,
}

/// resource attrs 공통 부분(host.name/id/os.type/service.*) — events/connections가 공유.
/// connections만 `host_ip`를 추가로 붙인다(hosts 메타 갱신, DoD 요구사항).
pub struct ResourceAttrs<'a> {
    pub host_name: &'a str,
    pub host_id: &'a str,
    pub os_type: &'a str,
    pub host_ip: Option<&'a str>,
}

/// 하나의 chat/agent 행위를 `ExportLogsServiceRequest`로 인코딩한다(scope=`aic.agent`).
///
/// 셸 명령(`aic.events`)과 **다른 scope**로 보낸다 — 수신 측이 "사람이 친 명령"과 "agent가 한
/// 행위"를 테이블/쿼리 단계에서 구분할 수 있어야 하기 때문이다. 같은 scope에 섞으면 attrs를
/// 일일이 뒤져야 구분된다.
///
/// `severity`는 문자열로 받아 OTLP SeverityNumber로 매핑한다. 미지의 값은 INFO로 떨어뜨린다 —
/// 알 수 없는 심각도 때문에 이벤트 자체를 버리는 것보다, 낮게 보고 흘리는 편이 낫다.
pub fn encode_agent_event(
    ev: &aic_common::AgentEvent,
    resource: &ResourceAttrs<'_>,
    service_version: &str,
    time_unix_nano: u64,
) -> Vec<u8> {
    let (severity_number, severity_text) = match ev.severity.to_ascii_uppercase().as_str() {
        "ERROR" => (SEVERITY_ERROR, "ERROR"),
        "WARN" | "WARNING" => (SEVERITY_WARN, "WARN"),
        _ => (SEVERITY_INFO, "INFO"),
    };

    let mut attributes = vec![attr_str("aic.agent.kind", &ev.kind)];
    // 부가 속성은 `aic.agent.*` 아래로 모아, 수신 측이 prefix 하나로 agent 속성을 걸러낼 수 있게 한다.
    for (k, v) in &ev.attrs {
        attributes.push(attr_str(&format!("aic.agent.{k}"), v));
    }

    let log_record = LogRecord {
        time_unix_nano,
        observed_time_unix_nano: time_unix_nano,
        severity_number,
        severity_text: redact_str(severity_text),
        body: Some(string_value(&ev.summary)),
        attributes,
        dropped_attributes_count: 0,
        flags: 0,
    };
    build_request(resource, "aic.agent", service_version, vec![log_record])
}

/// 하나의 `CommandEvent`를 `ExportLogsServiceRequest` protobuf 바이트로 인코딩한다(scope=`aic.events`).
pub fn encode_command_event(
    ev: &CommandEvent<'_>,
    resource: &ResourceAttrs<'_>,
    service_version: &str,
    time_unix_nano: u64,
) -> Vec<u8> {
    let command_text = ev.command.unwrap_or("");
    let (severity_number, severity_text) = if ev.exit_code != 0 {
        (SEVERITY_ERROR, "ERROR")
    } else {
        (SEVERITY_INFO, "INFO")
    };
    let attributes = vec![
        attr_str("aic.record.id", ev.id),
        attr_str("aic.command.text", command_text),
        attr_int("aic.command.exit_code", ev.exit_code as i64),
        attr_str("aic.command.capture_quality", ev.capture_quality),
    ];
    let log_record = LogRecord {
        time_unix_nano,
        observed_time_unix_nano: time_unix_nano,
        severity_number,
        severity_text: redact_str(severity_text),
        body: Some(string_value(command_text)),
        attributes,
        dropped_attributes_count: 0,
        flags: 0,
    };
    build_request(resource, "aic.events", service_version, vec![log_record])
}

/// `entries`를 한 번의 `ExportLogsServiceRequest`(LogRecord 여러 개, scope=`aic.connections`)로
/// 배치 인코딩한다. 빈 slice면 빈 log_records를 담은 유효 요청을 만든다(호출부가 empty check로
/// 건너뛰는 걸 선호하지만, 인코딩 자체는 항상 유효해야 한다).
pub fn encode_connections(
    entries: &[ConnectionEntry<'_>],
    resource: &ResourceAttrs<'_>,
    service_version: &str,
    time_unix_nano: u64,
) -> Vec<u8> {
    let log_records = entries
        .iter()
        .map(|c| {
            let mut attributes = vec![
                attr_str("network.transport", c.protocol),
                attr_str("aic.connection.state", c.state),
                attr_addr("network.local.address", c.local_addr),
                attr_int("network.local.port", c.local_port as i64),
            ];
            if let Some(pa) = c.peer_addr {
                attributes.push(attr_addr("network.peer.address", pa));
            }
            if let Some(pp) = c.peer_port {
                attributes.push(attr_int("network.peer.port", pp as i64));
            }
            let body_text = format!("{} {}", c.protocol, c.state);
            LogRecord {
                time_unix_nano,
                observed_time_unix_nano: time_unix_nano,
                severity_number: SEVERITY_INFO,
                severity_text: redact_str("INFO"),
                body: Some(string_value(&body_text)),
                attributes,
                dropped_attributes_count: 0,
                flags: 0,
            }
        })
        .collect();
    build_request(resource, "aic.connections", service_version, log_records)
}

/// 공통 조립 — resource(+host.ip 선택) + scope + log_records → protobuf bytes.
fn build_request(
    resource: &ResourceAttrs<'_>,
    scope_name: &str,
    service_version: &str,
    log_records: Vec<LogRecord>,
) -> Vec<u8> {
    let mut resource_attrs = vec![
        attr_str("host.name", resource.host_name),
        attr_str("host.id", resource.host_id),
        attr_str("os.type", resource.os_type),
        attr_str("service.name", SERVICE_NAME),
        attr_str("service.version", service_version),
    ];
    if let Some(ip) = resource.host_ip {
        resource_attrs.push(attr_addr("host.ip", ip));
    }

    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: resource_attrs,
                dropped_attributes_count: 0,
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: redact_str(scope_name),
                    version: redact_str(service_version),
                    attributes: Vec::new(),
                    dropped_attributes_count: 0,
                }),
                log_records,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };
    request.encode_to_vec()
}

fn attr_str(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: redact_str(key),
        value: Some(string_value(value)),
    }
}

fn attr_int(key: &str, value: i64) -> KeyValue {
    KeyValue {
        key: redact_str(key),
        value: Some(AnyValue {
            value: Some(AnyValueOneof::IntValue(value)),
        }),
    }
}

/// network address 전용 — value는 redact **하지 않는다**(모듈 doc 최상단 "redaction invariant
/// 예외" 참고). key만 [`redact_str`]를 거친다(고정 상수라 no-op이지만 경로는 통일해 둔다).
fn attr_addr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: redact_str(key),
        value: Some(AnyValue {
            value: Some(AnyValueOneof::StringValue(value.to_string())),
        }),
    }
}

fn string_value(s: &str) -> AnyValue {
    AnyValue {
        value: Some(AnyValueOneof::StringValue(redact_str(s))),
    }
}

// ── OTLP protobuf message subset (prost) — logs.proto v1 필드 번호와 1:1 ─────────────

/// collector/logs/v1/logs_service.proto — `ExportLogsServiceRequest`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportLogsServiceRequest {
    #[prost(message, repeated, tag = "1")]
    pub resource_logs: Vec<ResourceLogs>,
}

/// logs/v1/logs.proto — `ResourceLogs`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResourceLogs {
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    #[prost(message, repeated, tag = "2")]
    pub scope_logs: Vec<ScopeLogs>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

/// logs/v1/logs.proto — `ScopeLogs`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScopeLogs {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<InstrumentationScope>,
    #[prost(message, repeated, tag = "2")]
    pub log_records: Vec<LogRecord>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

/// logs/v1/logs.proto — `LogRecord`. trace_id/span_id(9/10)는 우리가 안 쓰므로 생략(prost는
/// 미정의 필드를 인코딩하지 않으므로 wire는 유효하다).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogRecord {
    #[prost(fixed64, tag = "1")]
    pub time_unix_nano: u64,
    #[prost(fixed64, tag = "11")]
    pub observed_time_unix_nano: u64,
    #[prost(int32, tag = "2")]
    pub severity_number: i32,
    #[prost(string, tag = "3")]
    pub severity_text: String,
    #[prost(message, optional, tag = "5")]
    pub body: Option<AnyValue>,
    #[prost(message, repeated, tag = "6")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "7")]
    pub dropped_attributes_count: u32,
    #[prost(uint32, tag = "8")]
    pub flags: u32,
}

/// resource/v1/resource.proto — `Resource`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Resource {
    #[prost(message, repeated, tag = "1")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "2")]
    pub dropped_attributes_count: u32,
}

/// common/v1/common.proto — `InstrumentationScope`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstrumentationScope {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub version: String,
    #[prost(message, repeated, tag = "3")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "4")]
    pub dropped_attributes_count: u32,
}

/// common/v1/common.proto — `KeyValue`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(message, optional, tag = "2")]
    pub value: Option<AnyValue>,
}

/// common/v1/common.proto — `AnyValue`. 우리는 string/int만 쓴다(bool/double 미사용이지만 wire
/// 호환을 위해 oneof 태그는 스펙과 동일하게 4개 다 정의한다).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AnyValue {
    #[prost(oneof = "AnyValueOneof", tags = "1, 2, 3, 4")]
    pub value: Option<AnyValueOneof>,
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
pub enum AnyValueOneof {
    #[prost(string, tag = "1")]
    StringValue(String),
    #[prost(bool, tag = "2")]
    BoolValue(bool),
    #[prost(int64, tag = "3")]
    IntValue(i64),
    #[prost(double, tag = "4")]
    DoubleValue(f64),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource<'a>(host_ip: Option<&'a str>) -> ResourceAttrs<'a> {
        ResourceAttrs {
            host_name: "web-1",
            host_id: "id-abc",
            os_type: "linux",
            host_ip,
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn command_event_roundtrips_and_maps_severity_by_exit_code() {
        let ok = CommandEvent {
            id: "deadbeefcafef00d",
            command: Some("ls -la"),
            exit_code: 0,
            capture_quality: "FullOutput",
        };
        let bytes = encode_command_event(&ok, &resource(None), "0.24.0", 42);
        let req = ExportLogsServiceRequest::decode(bytes.as_slice()).expect("valid protobuf");
        let lr = &req.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(lr.severity_number, SEVERITY_INFO);
        assert_eq!(lr.severity_text, "INFO");
        assert_eq!(lr.time_unix_nano, 42);
        assert_eq!(req.resource_logs[0].scope_logs[0].scope.as_ref().unwrap().name, "aic.events");

        let failing = CommandEvent {
            id: "aaaa1111bbbb2222",
            command: Some("false"),
            exit_code: 1,
            capture_quality: "MetadataOnly",
        };
        let bytes2 = encode_command_event(&failing, &resource(None), "0.24.0", 43);
        let req2 = ExportLogsServiceRequest::decode(bytes2.as_slice()).unwrap();
        let lr2 = &req2.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(lr2.severity_number, SEVERITY_ERROR);
        assert_eq!(lr2.severity_text, "ERROR");
    }

    #[test]
    fn command_event_attributes_carry_id_command_exit_code_and_quality() {
        let ev = CommandEvent {
            id: "1234567890abcdef",
            command: Some("cargo test"),
            exit_code: 2,
            capture_quality: "TruncatedOutput",
        };
        let bytes = encode_command_event(&ev, &resource(None), "9.9.9", 1);
        let req = ExportLogsServiceRequest::decode(bytes.as_slice()).unwrap();
        let attrs = &req.resource_logs[0].scope_logs[0].log_records[0].attributes;
        let get = |k: &str| {
            attrs
                .iter()
                .find(|kv| kv.key == k)
                .and_then(|kv| kv.value.clone())
                .and_then(|v| v.value)
        };
        assert!(matches!(get("aic.record.id"), Some(AnyValueOneof::StringValue(v)) if v == "1234567890abcdef"));
        assert!(matches!(get("aic.command.text"), Some(AnyValueOneof::StringValue(v)) if v == "cargo test"));
        assert!(matches!(get("aic.command.exit_code"), Some(AnyValueOneof::IntValue(2))));
        assert!(matches!(get("aic.command.capture_quality"), Some(AnyValueOneof::StringValue(v)) if v == "TruncatedOutput"));
    }

    /// invariant: command text에 섞인 secret은 wire에 원문으로 남지 않는다.
    #[test]
    fn command_event_redacts_secrets_in_command_text() {
        let ev = CommandEvent {
            id: "0000000000000001",
            command: Some("curl -H 'Authorization: Bearer abcDEF123ghiJKL456mnoPQR789' https://x"),
            exit_code: 0,
            capture_quality: "FullOutput",
        };
        let bytes = encode_command_event(&ev, &resource(None), "0.24.0", 1);
        assert!(
            !contains(&bytes, b"abcDEF123ghiJKL456mnoPQR789"),
            "command text의 secret이 유출됨"
        );
        assert!(contains(&bytes, b"[REDACTED:"), "redaction 표식이 없음");
    }

    #[test]
    fn connections_batch_roundtrips_with_listen_and_established() {
        let entries = vec![
            ConnectionEntry {
                protocol: "tcp",
                state: "LISTEN",
                local_addr: "0.0.0.0",
                local_port: 22,
                peer_addr: None,
                peer_port: None,
            },
            ConnectionEntry {
                protocol: "tcp",
                state: "ESTABLISHED",
                local_addr: "192.168.1.5",
                local_port: 22,
                peer_addr: Some("192.168.1.10"),
                peer_port: Some(54321),
            },
        ];
        let bytes = encode_connections(&entries, &resource(Some("192.168.1.5")), "0.24.0", 100);
        let req = ExportLogsServiceRequest::decode(bytes.as_slice()).expect("valid protobuf");
        let scope_logs = &req.resource_logs[0].scope_logs[0];
        assert_eq!(scope_logs.scope.as_ref().unwrap().name, "aic.connections");
        assert_eq!(scope_logs.log_records.len(), 2);

        // resource에 host.ip가 붙어야 한다(hosts 메타 갱신).
        let resource_attrs = &req.resource_logs[0].resource.as_ref().unwrap().attributes;
        let host_ip = resource_attrs.iter().find(|kv| kv.key == "host.ip");
        assert!(host_ip.is_some(), "connections resource에 host.ip가 없음");

        // LISTEN 항목은 peer attrs가 없어야 한다.
        let listen_attrs = &scope_logs.log_records[0].attributes;
        assert!(!listen_attrs.iter().any(|kv| kv.key == "network.peer.address"));
        // ESTABLISHED 항목은 peer attrs가 있어야 한다.
        let estab_attrs = &scope_logs.log_records[1].attributes;
        assert!(estab_attrs.iter().any(|kv| kv.key == "network.peer.address"));
        assert!(estab_attrs.iter().any(|kv| kv.key == "network.peer.port"));
    }

    #[test]
    fn connections_batch_handles_empty_entries() {
        let bytes = encode_connections(&[], &resource(None), "0.24.0", 1);
        let req = ExportLogsServiceRequest::decode(bytes.as_slice()).expect("valid protobuf even when empty");
        assert!(req.resource_logs[0].scope_logs[0].log_records.is_empty());
    }

    /// redaction invariant의 **예외**: network address 값은 redact되지 않고 그대로 나가야 한다
    /// — redact하면 IPv4 패턴에 걸려 모든 연결이 `[REDACTED:ipv4]`로 뭉개져 exporter가 무의미해진다
    /// (모듈 doc 참고). key는 계속 redact_str를 거치지만(no-op) value는 원문 그대로여야 한다.
    #[test]
    fn connections_does_not_redact_network_addresses() {
        let entries = vec![ConnectionEntry {
            protocol: "tcp",
            state: "ESTABLISHED",
            local_addr: "10.0.0.5",
            local_port: 8080,
            peer_addr: Some("203.0.113.7"),
            peer_port: Some(443),
        }];
        let bytes = encode_connections(&entries, &resource(Some("192.168.1.5")), "0.24.0", 1);
        assert!(
            contains(&bytes, b"10.0.0.5"),
            "local_addr가 redact되어 실제 IP가 유출되지 않음 — 이 exporter의 목적을 무의미하게 만듦"
        );
        assert!(
            contains(&bytes, b"203.0.113.7"),
            "peer_addr가 redact됨 — connections exporter는 실제 토폴로지를 그대로 보내야 함"
        );
        assert!(contains(&bytes, b"192.168.1.5"), "host.ip가 redact됨");
        assert!(
            !contains(&bytes, b"[REDACTED:ipv4]"),
            "network address 필드에 IPv4 redaction이 잘못 적용됨"
        );
    }
}
