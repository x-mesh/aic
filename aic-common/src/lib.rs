//! aic-common: 공유 데이터 모델, IPC 프로토콜, 에러 타입

pub mod error;
pub mod ipc;
pub mod paths;
pub mod session;

pub use error::AicError;
pub use ipc::{decode_frame, encode_frame, IpcRequest, IpcResponse, MetricsSnapshot};
pub use paths::{
    aicd_lock_path, aicd_socket_path, default_socket_path, extract_session_id,
    list_session_sockets, resolve_active_socket, resolve_socket_path, session_dir,
    session_socket_path,
};
pub use session::{generate_session_id, is_valid_session_id};

// CaptureMode/CaptureQuality/OutputMetadata는 같은 모듈 내 정의이므로 별도 re-export 불필요.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ── CommandRecord ──────────────────────────────────────────────

/// 레코드를 만든 캡처 경로.
///
/// `Pty`는 PTY wrapper 기반 정확 캡처, `Hook`은 shell hook 기반 metadata-only,
/// `ExplicitCapture`는 `aic run -- <cmd>` 같은 명시적 wrapper 캡처.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CaptureMode {
    #[default]
    Pty,
    Hook,
    ExplicitCapture,
}

/// 레코드 출력의 품질 등급. 분석 prompt와 cache key가 신뢰도를 인식하기 위해 사용.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CaptureQuality {
    /// PTY 또는 explicit capture로 stdout/stderr tail이 있음
    FullOutput,
    /// command/cwd/exit/duration만 있음
    MetadataOnly,
    /// 출력이 있었지만 policy에 따라 일부 제거됨
    RedactedOutput,
    /// binary/non-UTF8 출력이 감지되어 본문 생략됨
    BinaryOmitted,
    /// line/byte cap으로 일부만 저장됨
    TruncatedOutput,
    /// legacy record 또는 품질 판단 불가
    #[default]
    Unknown,
}

/// 출력 본문에 대한 메타데이터. 본문이 일부/전부 잘렸거나 해시만 남는 경우에 채운다.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OutputMetadata {
    /// 잘리기 전 원본 byte 크기 (알 수 있는 경우)
    pub original_bytes: Option<u64>,
    /// 실제 저장된 byte 크기
    pub stored_bytes: u64,
    /// 실제 저장된 라인 수
    pub stored_lines: usize,
    /// truncation 여부
    pub truncated: bool,
    /// binary/non-UTF8 감지 여부
    pub binary: bool,
    /// 본문 hash (생략된 binary 출력의 식별용)
    pub sha256: Option<String>,
}

/// 하나의 명령어 실행에 대한 레코드.
///
/// `capture_mode`/`capture_quality`/`output_metadata`는 레거시 JSON 호환을 위해
/// `#[serde(default)]`로 채워진다. 새 코드는 가능하면 명시적으로 채운다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandRecord {
    /// 실행된 명령어 텍스트 (가능한 경우)
    pub command: Option<String>,
    /// 프로세스 종료 코드
    pub exit_code: i32,
    /// ANSI 제거된 출력 라인들
    pub output_lines: Vec<String>,
    /// 명령어 완료 시각
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// 캡처 경로 (Phase 0). 레거시 JSON에선 `Pty`로 기본화.
    #[serde(default)]
    pub capture_mode: CaptureMode,
    /// 출력 품질 등급. 레거시 JSON에선 `Unknown`으로 기본화.
    #[serde(default)]
    pub capture_quality: CaptureQuality,
    /// 출력 본문 메타데이터. 본문 cap/redaction/binary 시에만 채운다.
    #[serde(default)]
    pub output_metadata: Option<OutputMetadata>,
}

impl Default for CommandRecord {
    fn default() -> Self {
        Self {
            command: None,
            exit_code: 0,
            output_lines: Vec::new(),
            timestamp: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0)
                .expect("UNIX epoch is a valid timestamp"),
            capture_mode: CaptureMode::default(),
            capture_quality: CaptureQuality::default(),
            output_metadata: None,
        }
    }
}

// ── AppConfig / ServerConfig ───────────────────────────────────

/// 애플리케이션 설정.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    pub llm: LlmConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Ring Buffer 최대 라인 수 (기본: 500)
    pub max_buffer_lines: usize,
    /// UDS 소켓 경로 (기본: XDG_RUNTIME_DIR/aic/session.sock)
    pub socket_path: Option<PathBuf>,
    /// Command Boundary 감지 전략
    pub boundary_strategy: BoundaryStrategyConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundaryStrategyConfig {
    /// "prompt_marker" 또는 "timing_heuristic"
    pub method: String,
    /// Timing Heuristic 사용 시 idle threshold (ms)
    pub idle_threshold_ms: Option<u64>,
}

// ── LlmConfig / ProviderConfig / ProviderType ──────────────────

/// LLM Provider 설정.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmConfig {
    /// 기본 Provider 이름 ("openai", "nvidia", "anthropic", "kiro-cli", "claude-cli")
    pub default_provider: String,
    /// Provider별 설정. config.toml에 누락되면 빈 맵으로 처리 (런타임에 resolve_provider가 ConfigError 반환).
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    /// 응답 언어 설정 (기본: "korean")
    #[serde(default = "default_lang")]
    pub lang: String,
    /// TCP 연결 타임아웃(초) — endpoint reachability 확인용. 기본 5초.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// 요청 전체 타임아웃(초) — connect + LLM 응답 대기 포함. 기본 30초.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

fn default_lang() -> String {
    "korean".to_string()
}

/// `lang = "auto"`인 경우 환경 변수($LC_ALL, $LANG)에서 언어를 추론한다.
/// 추론 실패 시 "english"로 폴백한다. config에 명시적 언어가 있으면 그대로 반환.
pub fn resolve_lang(configured: &str) -> String {
    if configured != "auto" {
        return configured.to_string();
    }

    let raw = std::env::var("LC_ALL")
        .ok()
        .or_else(|| std::env::var("LANG").ok())
        .unwrap_or_default()
        .to_lowercase();

    // ko_KR.UTF-8 → "ko", ja_JP → "ja" 등 prefix 추출
    let prefix = raw.split(['_', '.']).next().unwrap_or("");

    match prefix {
        "ko" => "korean".to_string(),
        "ja" => "japanese".to_string(),
        "zh" => "chinese".to_string(),
        "en" => "english".to_string(),
        _ => "english".to_string(),
    }
}

fn default_connect_timeout_secs() -> u64 {
    5
}

fn default_request_timeout_secs() -> u64 {
    30
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Provider 유형
    pub provider_type: ProviderType,
    /// API endpoint URL (REST API 타입만)
    pub endpoint: Option<String>,
    /// API key (REST API 타입만)
    pub api_key: Option<String>,
    /// 모델 이름
    pub model: Option<String>,
    /// CLI 실행 파일 경로 (CLI Backend 타입만)
    pub cli_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProviderType {
    /// OpenAI 호환 API (OpenAI, NVIDIA)
    OpenAiCompatible,
    /// Anthropic 전용 API
    Anthropic,
    /// 로컬 CLI 실행 (kiro-cli, claude-cli)
    CliBackend,
}

// ── AnalysisResult ─────────────────────────────────────────────

/// LLM 에러 분석 결과.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// 에러 원인 설명
    pub explanation: String,
    /// 수정된 명령어 제안 (있는 경우)
    pub suggested_command: Option<String>,
    /// 추가 참고 정보
    pub additional_info: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn command_record_serialize_roundtrip() {
        let record = CommandRecord {
            command: Some("ls -la".to_string()),
            exit_code: 1,
            output_lines: vec!["error: not found".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: CommandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn command_record_with_none_command() {
        let record = CommandRecord {
            command: None,
            exit_code: 0,
            output_lines: vec![],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: CommandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn legacy_command_record_json_deserializes_with_defaults() {
        // capture_mode/capture_quality/output_metadata 필드 없는 옛 JSON.
        // 기본값(Pty/Unknown/None)으로 채워져야 한다.
        let legacy = r#"{
            "command": "cargo build",
            "exit_code": 1,
            "output_lines": ["error[E0308]"],
            "timestamp": "2026-01-01T00:00:00Z"
        }"#;
        let record: CommandRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(record.command.as_deref(), Some("cargo build"));
        assert_eq!(record.exit_code, 1);
        assert_eq!(record.capture_mode, CaptureMode::Pty);
        assert_eq!(record.capture_quality, CaptureQuality::Unknown);
        assert!(record.output_metadata.is_none());
    }

    #[test]
    fn command_record_with_capture_metadata_roundtrip() {
        let record = CommandRecord {
            command: Some("vim README.md".to_string()),
            exit_code: 0,
            output_lines: vec![],
            timestamp: Utc::now(),
            capture_mode: CaptureMode::Hook,
            capture_quality: CaptureQuality::MetadataOnly,
            output_metadata: Some(OutputMetadata {
                original_bytes: Some(0),
                stored_bytes: 0,
                stored_lines: 0,
                truncated: false,
                binary: false,
                sha256: None,
            }),
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: CommandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn capture_mode_default_is_pty() {
        assert_eq!(CaptureMode::default(), CaptureMode::Pty);
    }

    #[test]
    fn capture_quality_default_is_unknown() {
        assert_eq!(CaptureQuality::default(), CaptureQuality::Unknown);
    }

    #[test]
    fn app_config_serialize_roundtrip() {
        let config = AppConfig {
            llm: LlmConfig {
                default_provider: "openai".to_string(),
                providers: HashMap::from([(
                    "openai".to_string(),
                    ProviderConfig {
                        provider_type: ProviderType::OpenAiCompatible,
                        endpoint: Some("https://api.openai.com/v1/chat/completions".to_string()),
                        api_key: Some("sk-test".to_string()),
                        model: Some("gpt-4o".to_string()),
                        cli_path: None,
                    },
                )]),
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: ServerConfig {
                max_buffer_lines: 500,
                socket_path: None,
                boundary_strategy: BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn provider_type_variants_serialize() {
        for (variant, expected) in [
            (ProviderType::OpenAiCompatible, "\"OpenAiCompatible\""),
            (ProviderType::Anthropic, "\"Anthropic\""),
            (ProviderType::CliBackend, "\"CliBackend\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn analysis_result_serialize_roundtrip() {
        let result = AnalysisResult {
            explanation: "파일을 찾을 수 없습니다".to_string(),
            suggested_command: Some("ls /correct/path".to_string()),
            additional_info: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
