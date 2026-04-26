//! aic-common: 공유 데이터 모델, IPC 프로토콜, 에러 타입

pub mod error;
pub mod ipc;
pub mod paths;
pub mod session;

pub use error::AicError;
pub use ipc::{decode_frame, encode_frame, IpcRequest, IpcResponse, MetricsSnapshot};
pub use paths::{
    default_socket_path, extract_session_id, list_session_sockets, resolve_active_socket,
    resolve_socket_path, session_dir, session_socket_path,
};
pub use session::{generate_session_id, is_valid_session_id};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ── CommandRecord ──────────────────────────────────────────────

/// 하나의 명령어 실행에 대한 레코드.
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
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: CommandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
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
