//! OTLP metrics를 protobuf로 인코딩한다 (SRE t6).
//!
//! `opentelemetry-proto` 대신 **prost 직접 + 손수 정의한 최소 메시지 subset**을 쓴다(Cargo.toml
//! 근거 참조). 우리가 보내는 것은 `ExportMetricsServiceRequest` → `ResourceMetrics` →
//! `ScopeMetrics` → `Metric`(Gauge only) → `NumberDataPoint`뿐이라, 아래 구조체는 OTLP proto의
//! 해당 message들과 **필드 번호까지 1:1**로 맞춘 subset이다. 각 `tag`는 원본 .proto 파일의 field
//! number이며, 주석으로 출처 message를 남긴다(스펙 변경 시 대조용).
//!
//! **redaction invariant**: 인코딩되는 모든 문자열 필드는 예외 없이 [`redact_str`]를 통과한다
//! (metric name/unit 같은 상수 포함 — 상수는 no-op이지만 경로를 단일화해 "누락"을 구조적으로 막는다).
//! hostname 등 동적 값에 섞인 secret/PII가 collector로 새어나가지 않음을 보장한다.

use prost::Message as _;

use super::host_metrics::{HostSample, MetricValue};

/// InstrumentationScope name — 이 metric을 낸 주체. resource `service.name`과 동일하게 aicd.
const SCOPE_NAME: &str = "aicd";
/// resource `service.name` — 중앙 collector가 aic 데몬이 보낸 텔레메트리임을 구분하는 키.
const SERVICE_NAME: &str = "aicd";

/// 송신 직전 secret/PII 마스킹. 모든 문자열 필드가 이 함수를 거친다(invariant).
fn redact_str(s: &str) -> String {
    aic_common::redaction::redact(s).0
}

/// `HostSample`을 OTLP `ExportMetricsServiceRequest` protobuf 바이트로 인코딩한다.
///
/// `now_unix_nano`는 각 data point의 `time_unix_nano`로 쓰인다(호출부에서 sample 시각을 넘겨
/// 테스트가 결정적이게 한다). 모든 문자열은 `redact_str`를 통과한 뒤 인코딩된다.
pub fn encode_metrics(sample: &HostSample, service_version: &str, now_unix_nano: u64) -> Vec<u8> {
    let resource_attrs = vec![
        attr("host.name", &sample.resource.host_name),
        attr("host.id", &sample.resource.host_id),
        attr("os.type", &sample.resource.os_type),
        attr("service.name", SERVICE_NAME),
        attr("service.version", service_version),
    ];

    let data_points = sample
        .points
        .iter()
        .map(|p| NumberDataPoint {
            attributes: Vec::new(),
            start_time_unix_nano: 0,
            time_unix_nano: now_unix_nano,
            value: Some(match p.value {
                MetricValue::Double(v) => NumberValue::AsDouble(v),
                MetricValue::Int(v) => NumberValue::AsInt(v),
            }),
            flags: 0,
        })
        .collect::<Vec<_>>();

    // metric 하나당 gauge data point 하나. name/unit은 상수지만 redact를 거쳐 경로를 단일화한다.
    let metrics = sample
        .points
        .iter()
        .zip(data_points)
        .map(|(p, dp)| Metric {
            name: redact_str(p.name),
            description: String::new(),
            unit: redact_str(p.unit),
            data: Some(MetricData::Gauge(Gauge {
                data_points: vec![dp],
            })),
        })
        .collect();

    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: resource_attrs,
                dropped_attributes_count: 0,
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: redact_str(SCOPE_NAME),
                    version: redact_str(service_version),
                    attributes: Vec::new(),
                    dropped_attributes_count: 0,
                }),
                metrics,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };

    request.encode_to_vec()
}

/// string-valued `KeyValue` 하나(키·값 모두 redact). resource attribute 구성 전용 helper.
fn attr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: redact_str(key),
        value: Some(AnyValue {
            value: Some(AnyValueOneof::StringValue(redact_str(value))),
        }),
    }
}

// ── OTLP protobuf message subset (prost) ───────────────────────────
// 필드 번호는 opentelemetry-proto v1.x .proto 파일과 동일하다. 우리가 실제로 채우는 필드만 정의하고,
// 나머지(exemplars, histogram 등)는 생략한다 — prost는 미정의 필드를 인코딩하지 않으므로 wire는 유효하다.

/// collector/metrics/v1/metrics_service.proto — `ExportMetricsServiceRequest`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportMetricsServiceRequest {
    #[prost(message, repeated, tag = "1")]
    pub resource_metrics: Vec<ResourceMetrics>,
}

/// metrics/v1/metrics.proto — `ResourceMetrics`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResourceMetrics {
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    #[prost(message, repeated, tag = "2")]
    pub scope_metrics: Vec<ScopeMetrics>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

/// resource/v1/resource.proto — `Resource`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Resource {
    #[prost(message, repeated, tag = "1")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "2")]
    pub dropped_attributes_count: u32,
}

/// metrics/v1/metrics.proto — `ScopeMetrics`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScopeMetrics {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<InstrumentationScope>,
    #[prost(message, repeated, tag = "2")]
    pub metrics: Vec<Metric>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
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

/// metrics/v1/metrics.proto — `Metric`. data oneof에서 gauge(tag 5)만 쓴다.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Metric {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub description: String,
    #[prost(string, tag = "3")]
    pub unit: String,
    #[prost(oneof = "MetricData", tags = "5")]
    pub data: Option<MetricData>,
}

/// `Metric.data` oneof — 이번 범위는 gauge만(sum/histogram은 후속).
#[derive(Clone, PartialEq, ::prost::Oneof)]
pub enum MetricData {
    #[prost(message, tag = "5")]
    Gauge(Gauge),
}

/// metrics/v1/metrics.proto — `Gauge`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gauge {
    #[prost(message, repeated, tag = "1")]
    pub data_points: Vec<NumberDataPoint>,
}

/// metrics/v1/metrics.proto — `NumberDataPoint`. attributes=7, time=3, value oneof(as_double=4/as_int=6).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NumberDataPoint {
    #[prost(message, repeated, tag = "7")]
    pub attributes: Vec<KeyValue>,
    #[prost(fixed64, tag = "2")]
    pub start_time_unix_nano: u64,
    #[prost(fixed64, tag = "3")]
    pub time_unix_nano: u64,
    #[prost(uint32, tag = "8")]
    pub flags: u32,
    #[prost(oneof = "NumberValue", tags = "4, 6")]
    pub value: Option<NumberValue>,
}

/// `NumberDataPoint.value` oneof. as_int은 스펙상 sfixed64.
#[derive(Clone, PartialEq, ::prost::Oneof)]
pub enum NumberValue {
    #[prost(double, tag = "4")]
    AsDouble(f64),
    #[prost(sfixed64, tag = "6")]
    AsInt(i64),
}

/// common/v1/common.proto — `KeyValue`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(message, optional, tag = "2")]
    pub value: Option<AnyValue>,
}

/// common/v1/common.proto — `AnyValue`. 우리는 string/bool/int/double만 쓴다.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AnyValue {
    #[prost(oneof = "AnyValueOneof", tags = "1, 2, 3, 4")]
    pub value: Option<AnyValueOneof>,
}

/// `AnyValue.value` oneof. 변형명은 OTLP `AnyValue`의 oneof 필드명(`string_value` 등)을 그대로
/// 따른 것이라 공통 `Value` 접미가 의도적이다(스펙 대조 용이).
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
    use crate::otlp_exporter::host_metrics::{MetricPoint, ResourceAttrs};

    fn sample_with_resource(host_name: &str, host_id: &str, os_type: &str) -> HostSample {
        HostSample {
            resource: ResourceAttrs {
                host_name: host_name.to_string(),
                host_id: host_id.to_string(),
                os_type: os_type.to_string(),
            },
            points: vec![
                MetricPoint {
                    name: "system.cpu.utilization",
                    unit: "1",
                    value: MetricValue::Double(0.42),
                },
                MetricPoint {
                    name: "system.memory.usage",
                    unit: "By",
                    value: MetricValue::Int(8 * 1024 * 1024 * 1024),
                },
            ],
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// invariant: 문자열 필드에 섞인 secret/PII는 인코딩 결과에 원문으로 남지 않는다.
    #[test]
    fn all_string_fields_are_redacted_before_encoding() {
        // hostname=AWS key, host_id=email, os_type=bearer token 을 각각 심는다.
        let secrets: &[&str] = &[
            "AKIAIOSFODNN7EXAMPLE",
            "admin@corp.internal",
            "Bearer abcDEF123ghiJKL456mnoPQR789",
        ];
        let sample = sample_with_resource(
            &format!("host-{}", secrets[0]),
            secrets[1],
            secrets[2],
        );
        let bytes = encode_metrics(&sample, "0.24.0", 1_700_000_000_000_000_000);

        // 원문 secret은 wire에 절대 남지 않는다.
        for s in secrets {
            assert!(
                !contains(&bytes, s.as_bytes()),
                "secret이 인코딩 결과에 유출됨: {s}"
            );
        }
        // 마스킹 표식은 존재한다(redaction이 실제로 동작).
        assert!(contains(&bytes, b"[REDACTED:"), "redaction 표식이 없음");
    }

    /// invariant는 개별 secret 종류마다 성립해야 한다(hostname 위치에 각기 다른 종류를 넣어 검증).
    #[test]
    fn redaction_holds_for_each_secret_kind_in_hostname() {
        let cases: &[&str] = &[
            "AKIAIOSFODNN7EXAMPLE",                          // aws_key
            "ghp_AbC123XyZ789DeF456GhI012JkL345MnO678",      // github_token
            "user@example.com",                              // email
            "010-1234-5678",                                 // kr_phone
            "192.168.10.20",                                 // ipv4
            "postgres://app:s3cr3tPass@db:5432/orders",      // conn_string
        ];
        for secret in cases {
            let sample = sample_with_resource(secret, "id", "linux");
            let bytes = encode_metrics(&sample, "0.24.0", 1);
            assert!(
                !contains(&bytes, secret.as_bytes()),
                "'{secret}' 종류가 redact되지 않고 유출됨"
            );
        }
    }

    /// wire가 유효한 OTLP인지 — 같은 스키마로 디코드해 구조·값을 되짚는다(encode/decode 대칭).
    #[test]
    fn encodes_valid_otlp_request_roundtrip() {
        let sample = sample_with_resource("web-1", "id-abc", "linux");
        let bytes = encode_metrics(&sample, "9.9.9", 42);
        let req = ExportMetricsServiceRequest::decode(bytes.as_slice()).expect("valid protobuf");

        assert_eq!(req.resource_metrics.len(), 1);
        let rm = &req.resource_metrics[0];
        let resource = rm.resource.as_ref().unwrap();
        // resource attribute 5종이 모두 존재(host.name/host.id/os.type/service.name/service.version).
        let keys: Vec<&str> = resource.attributes.iter().map(|kv| kv.key.as_str()).collect();
        for expected in [
            "host.name",
            "host.id",
            "os.type",
            "service.name",
            "service.version",
        ] {
            assert!(keys.contains(&expected), "resource attr 누락: {expected}");
        }

        let sm = &rm.scope_metrics[0];
        assert_eq!(sm.scope.as_ref().unwrap().name, "aicd");
        assert_eq!(sm.metrics.len(), 2);
        assert_eq!(sm.metrics[0].name, "system.cpu.utilization");

        // 첫 metric의 gauge double 값 0.42가 왕복 후에도 보존된다.
        let MetricData::Gauge(g) = sm.metrics[0].data.as_ref().unwrap();
        assert_eq!(g.data_points.len(), 1);
        assert_eq!(g.data_points[0].time_unix_nano, 42);
        match g.data_points[0].value.as_ref().unwrap() {
            NumberValue::AsDouble(v) => assert!((v - 0.42).abs() < 1e-9),
            other => panic!("expected double, got {other:?}"),
        }
        // 둘째 metric은 int 값.
        let MetricData::Gauge(g2) = sm.metrics[1].data.as_ref().unwrap();
        match g2.data_points[0].value.as_ref().unwrap() {
            NumberValue::AsInt(v) => assert_eq!(*v, 8 * 1024 * 1024 * 1024),
            other => panic!("expected int, got {other:?}"),
        }
    }

    /// AnyValue의 string 값도 왕복 후 redact된 형태로 보존된다(디코드로 값 확인).
    #[test]
    fn resource_attr_value_is_redacted_and_readable() {
        let sample = sample_with_resource("clean-host", "AKIAIOSFODNN7EXAMPLE", "linux");
        let bytes = encode_metrics(&sample, "0.24.0", 1);
        let req = ExportMetricsServiceRequest::decode(bytes.as_slice()).unwrap();
        let attrs = &req.resource_metrics[0].resource.as_ref().unwrap().attributes;
        let host_id = attrs.iter().find(|kv| kv.key == "host.id").unwrap();
        let Some(AnyValueOneof::StringValue(v)) = &host_id.value.as_ref().unwrap().value else {
            panic!("host.id는 string value여야 함");
        };
        assert!(v.contains("[REDACTED:aws_key]"), "host.id가 redact되지 않음: {v}");
    }
}
