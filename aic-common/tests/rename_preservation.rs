//! Preservation Property Tests: 기능 동작 보존 검증
//!
//! 리네이밍 전 코드에서 PASS해야 한다.
//! 리네이밍 후에도 동일하게 PASS해야 한다 (회귀 방지).
//!
//! **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8**

use aic_common::*;
use proptest::prelude::*;
use std::path::PathBuf;

// ── Arbitrary strategies ───────────────────────────────────────

fn arb_provider_type() -> impl Strategy<Value = ProviderType> {
    prop_oneof![
        Just(ProviderType::OpenAiCompatible),
        Just(ProviderType::Anthropic),
        Just(ProviderType::CliBackend),
    ]
}

fn arb_provider_config() -> impl Strategy<Value = ProviderConfig> {
    (
        arb_provider_type(),
        proptest::option::of("[a-z]{3,10}"),
        proptest::option::of("[a-z]{3,10}"),
        proptest::option::of("[a-z]{3,10}"),
        proptest::option::of("[a-z]{3,10}"),
    )
        .prop_map(
            |(provider_type, endpoint, api_key, model, cli_path)| ProviderConfig {
                provider_type,
                endpoint,
                api_key,
                model,
                cli_path,
            },
        )
}

fn arb_boundary_strategy() -> impl Strategy<Value = BoundaryStrategyConfig> {
    (
        prop_oneof![
            Just("prompt_marker".to_string()),
            Just("timing_heuristic".to_string()),
        ],
        proptest::option::of(100u64..5000u64),
    )
        .prop_map(|(method, idle_threshold_ms)| BoundaryStrategyConfig {
            method,
            idle_threshold_ms,
        })
}

fn arb_app_config() -> impl Strategy<Value = AppConfig> {
    (
        "[a-z]{3,10}",
        proptest::collection::hash_map("[a-z]{2,6}", arb_provider_config(), 0..3),
        100usize..2000usize,
        proptest::option::of("[a-z/]{3,20}".prop_map(PathBuf::from)),
        arb_boundary_strategy(),
    )
        .prop_map(
            |(default_provider, providers, max_buffer_lines, socket_path, boundary_strategy)| {
                AppConfig {
                    llm: LlmConfig {
                        default_provider,
                        providers,
                        lang: "korean".to_string(),
                        connect_timeout_secs: 5,
                        request_timeout_secs: 30,
                    },
                    server: ServerConfig {
                        max_buffer_lines,
                        socket_path,
                        boundary_strategy,
                    },
                }
            },
        )
}

fn arb_command_record() -> impl Strategy<Value = CommandRecord> {
    (
        proptest::option::of(any::<String>()),
        any::<i32>(),
        proptest::collection::vec(any::<String>(), 0..8),
        0i64..4_102_444_800_000i64,
    )
        .prop_map(|(command, exit_code, output_lines, ts_millis)| {
            let timestamp = chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default();
            CommandRecord {
                command,
                exit_code,
                output_lines,
                timestamp,
            }
        })
}

fn arb_ipc_request() -> impl Strategy<Value = IpcRequest> {
    prop_oneof![
        Just(IpcRequest::GetLastCommand),
        any::<usize>().prop_map(|count| IpcRequest::GetRecentLines { count }),
        Just(IpcRequest::Ping),
    ]
}

fn arb_ipc_response() -> impl Strategy<Value = IpcResponse> {
    prop_oneof![
        arb_command_record().prop_map(IpcResponse::CommandData),
        proptest::collection::vec(any::<String>(), 0..8).prop_map(IpcResponse::Lines),
        Just(IpcResponse::Pong),
        any::<String>().prop_map(|message| IpcResponse::Error { message }),
    ]
}

// ── Property-based tests ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Validates: Requirements 3.4**
    /// 임의의 AppConfig에 대해 TOML serialize → deserialize round-trip 보존
    #[test]
    fn prop_app_config_toml_roundtrip(config in arb_app_config()) {
        let toml_str = toml::to_string(&config)
            .expect("AppConfig should serialize to TOML");
        let deserialized: AppConfig = toml::from_str(&toml_str)
            .expect("TOML should deserialize back to AppConfig");
        prop_assert_eq!(config, deserialized);
    }

    /// **Validates: Requirements 3.1**
    /// 임의의 IpcRequest에 대해 JSON serialize → deserialize round-trip 보존
    #[test]
    fn prop_ipc_request_json_roundtrip(req in arb_ipc_request()) {
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&req, &deserialized);
    }

    /// **Validates: Requirements 3.1**
    /// 임의의 IpcResponse에 대해 JSON serialize → deserialize round-trip 보존
    #[test]
    fn prop_ipc_response_json_roundtrip(resp in arb_ipc_response()) {
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&resp, &deserialized);
    }

    /// **Validates: Requirements 3.1**
    /// 임의의 바이트 페이로드에 대해 encode_frame → decode_frame round-trip 보존
    #[test]
    fn prop_frame_roundtrip(payload in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let frame = encode_frame(&payload);

        // 프레임 크기 = 4 (header) + payload 길이
        prop_assert_eq!(frame.len(), 4 + payload.len());

        let (total_size, decoded) = decode_frame(&frame).unwrap();
        prop_assert_eq!(total_size, frame.len());
        prop_assert_eq!(decoded, payload.as_slice());
    }
}

// ── 에러 variant 의미론 보존 ───────────────────────────────────

#[test]
fn error_server_not_running_display_pattern() {
    // **Validates: Requirements 3.6**
    let err = AicError::ServerNotRunning;
    let msg = err.to_string();
    // 에러 메시지가 서버 실행 안내를 포함해야 함
    assert!(
        msg.contains("실행 중이지 않습니다"),
        "ServerNotRunning 에러 메시지 패턴 불일치: {}",
        msg
    );
}

#[test]
fn error_api_key_missing_display_pattern() {
    // **Validates: Requirements 3.6**
    let err = AicError::ApiKeyMissing {
        provider: "openai".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("API key가 설정되지 않았습니다"),
        "ApiKeyMissing 에러 메시지 패턴 불일치: {}",
        msg
    );
}

#[test]
fn error_cli_not_found_display_pattern() {
    // **Validates: Requirements 3.6**
    let err = AicError::CliNotFound {
        cli_name: "test-cli".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("test-cli") && msg.contains("찾을 수 없습니다"),
        "CliNotFound 에러 메시지 패턴 불일치: {}",
        msg
    );
}

#[test]
fn error_llm_api_error_display_pattern() {
    // **Validates: Requirements 3.6**
    let err = AicError::LlmApiError {
        status: 500,
        message: "Internal Server Error".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("LLM API 호출 실패") && msg.contains("Internal Server Error"),
        "LlmApiError 에러 메시지 패턴 불일치: {}",
        msg
    );
}

#[test]
fn error_pty_error_display_pattern() {
    // **Validates: Requirements 3.6**
    let err = AicError::PtyError("spawn failed".to_string());
    let msg = err.to_string();
    assert!(
        msg.contains("PTY 생성 실패") && msg.contains("spawn failed"),
        "PtyError 에러 메시지 패턴 불일치: {}",
        msg
    );
}

#[test]
fn error_ipc_error_from_io_preserves_semantics() {
    // **Validates: Requirements 3.6**
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let err: AicError = io_err.into();
    let msg = err.to_string();
    assert!(
        msg.contains("IPC 통신 오류") && msg.contains("refused"),
        "IpcError 에러 메시지 패턴 불일치: {}",
        msg
    );
}

#[test]
fn error_config_error_display_pattern() {
    // **Validates: Requirements 3.6**
    let err = AicError::ConfigError("invalid TOML".to_string());
    let msg = err.to_string();
    assert!(
        msg.contains("설정 파일 오류") && msg.contains("invalid TOML"),
        "ConfigError 에러 메시지 패턴 불일치: {}",
        msg
    );
}

#[test]
fn error_from_anyhow_preserves_semantics() {
    // **Validates: Requirements 3.6**
    let anyhow_err = anyhow::anyhow!("PTY device not available");
    let err: AicError = anyhow_err.into();
    let msg = err.to_string();
    // anyhow::Error → AicError는 PtyError variant로 변환됨
    assert!(
        msg.contains("PTY 생성 실패") && msg.contains("PTY device not available"),
        "From<anyhow::Error> 변환 의미론 불일치: {}",
        msg
    );
}
