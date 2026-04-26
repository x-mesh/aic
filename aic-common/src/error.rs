//! aic 에러 타입 정의

/// aic 도구의 통합 에러 타입.
///
/// 각 variant는 한국어 에러 메시지를 포함하며,
/// AIC_Server와 AIC_Client 양쪽에서 공통으로 사용한다.
#[derive(thiserror::Error, Debug)]
pub enum AicError {
    #[error("AIC_Server가 실행 중이지 않습니다. 'aic-session'을 먼저 시작하세요.")]
    ServerNotRunning,

    #[error("API key가 설정되지 않았습니다. 'aic config' 명령어로 설정하세요.")]
    ApiKeyMissing { provider: String },

    #[error("{cli_name}을 찾을 수 없습니다. 설치 여부를 확인하세요.")]
    CliNotFound { cli_name: String },

    #[error("LLM API 호출 실패: {message}")]
    LlmApiError { status: u16, message: String },

    #[error("PTY 생성 실패: {0}")]
    PtyError(String),

    #[error("IPC 통신 오류: {0}")]
    IpcError(#[from] std::io::Error),

    #[error("설정 파일 오류: {0}")]
    ConfigError(String),

    /// 사용자에게 직접 보여줄 메시지 (prefix 없이 그대로 출력)
    #[error("{0}")]
    UserMessage(String),
}

impl From<anyhow::Error> for AicError {
    fn from(err: anyhow::Error) -> Self {
        AicError::PtyError(err.to_string())
    }
}

impl AicError {
    /// 사용자에게 보여줄 한 줄짜리 친화적 메시지.
    /// `Display`(=raw `to_string()`)와 다르게 status 코드별 안내를 포함한다.
    pub fn user_message(&self) -> String {
        match self {
            AicError::ServerNotRunning => self.to_string(),
            AicError::ApiKeyMissing { provider } => {
                format!("'{provider}' provider의 API 키가 설정되지 않았습니다. `aic config` 명령으로 설정하세요.")
            }
            AicError::CliNotFound { cli_name } => {
                format!("CLI 도구 '{cli_name}'을(를) 찾을 수 없습니다. 설치 후 PATH를 확인하세요.")
            }
            AicError::LlmApiError { status, message } => match *status {
                0 => format!("네트워크 연결에 실패했습니다. 인터넷 연결을 확인하세요. ({message})"),
                401 => "API 키가 거부되었습니다. `aic config`에서 키를 다시 설정하세요.".into(),
                403 => "API 접근 권한이 없습니다. 키 권한을 확인하세요.".into(),
                404 => "LLM API endpoint를 찾을 수 없습니다 (HTTP 404). 설정의 endpoint URL을 확인하세요.".into(),
                429 => "API 요청 한도를 초과했습니다 (HTTP 429). 잠시 후 다시 시도하세요.".into(),
                500..=599 => format!("LLM 서버 오류 (HTTP {status}). 잠시 후 다시 시도하세요."),
                _ => format!("LLM API 오류 (HTTP {status}): {message}"),
            },
            AicError::PtyError(msg) => format!("PTY 오류: {msg}"),
            AicError::IpcError(e) => format!("IPC 오류: {e}"),
            AicError::ConfigError(msg) => format!("설정 오류: {msg}"),
            AicError::UserMessage(msg) => msg.clone(),
        }
    }

    /// 일시적(transient) 에러인지 — 재시도가 의미 있는지 판단.
    /// HTTP 5xx, 429(rate limit), 네트워크 오류(status=0)는 재시도 가능.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AicError::LlmApiError { status, .. }
                if *status == 0 || *status == 429 || (*status >= 500 && *status < 600)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_not_running_message() {
        let err = AicError::ServerNotRunning;
        assert_eq!(
            err.to_string(),
            "AIC_Server가 실행 중이지 않습니다. 'aic-session'을 먼저 시작하세요."
        );
    }

    #[test]
    fn api_key_missing_message() {
        let err = AicError::ApiKeyMissing {
            provider: "openai".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "API key가 설정되지 않았습니다. 'aic config' 명령어로 설정하세요."
        );
    }

    #[test]
    fn cli_not_found_message() {
        let err = AicError::CliNotFound {
            cli_name: "kiro-cli".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "kiro-cli을 찾을 수 없습니다. 설치 여부를 확인하세요."
        );
    }

    #[test]
    fn llm_api_error_message() {
        let err = AicError::LlmApiError {
            status: 429,
            message: "Rate limit exceeded".to_string(),
        };
        assert_eq!(err.to_string(), "LLM API 호출 실패: Rate limit exceeded");
    }

    #[test]
    fn pty_error_message() {
        let err = AicError::PtyError("spawn failed".to_string());
        assert_eq!(err.to_string(), "PTY 생성 실패: spawn failed");
    }

    #[test]
    fn pty_error_from_anyhow() {
        let anyhow_err = anyhow::anyhow!("PTY device not available");
        let err: AicError = anyhow_err.into();
        assert_eq!(err.to_string(), "PTY 생성 실패: PTY device not available");
    }

    #[test]
    fn ipc_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err: AicError = io_err.into();
        assert_eq!(err.to_string(), "IPC 통신 오류: refused");
    }

    #[test]
    fn config_error_message() {
        let err = AicError::ConfigError("invalid TOML".to_string());
        assert_eq!(err.to_string(), "설정 파일 오류: invalid TOML");
    }

    // ── user_message ────────────────────────────────────────────

    #[test]
    fn user_message_for_each_http_status() {
        let cases: &[(u16, &str)] = &[
            (0, "네트워크"),
            (401, "API 키"),
            (403, "권한"),
            (404, "endpoint"),
            (429, "한도"),
            (500, "서버 오류"),
            (502, "서버 오류"),
            (503, "서버 오류"),
            (599, "서버 오류"),
        ];
        for (status, expected_substring) in cases {
            let err = AicError::LlmApiError {
                status: *status,
                message: "raw msg".into(),
            };
            let msg = err.user_message();
            assert!(
                msg.contains(expected_substring),
                "status {status}: '{msg}' should contain '{expected_substring}'"
            );
        }
    }

    #[test]
    fn user_message_api_key_missing_includes_provider() {
        let err = AicError::ApiKeyMissing {
            provider: "nvidia".into(),
        };
        let msg = err.user_message();
        assert!(msg.contains("nvidia"));
        assert!(msg.contains("aic config"));
    }

    #[test]
    fn user_message_cli_not_found_includes_name() {
        let err = AicError::CliNotFound {
            cli_name: "kiro".into(),
        };
        let msg = err.user_message();
        assert!(msg.contains("kiro"));
        assert!(msg.contains("PATH"));
    }

    // ── is_retryable ────────────────────────────────────────────

    #[test]
    fn is_retryable_5xx_and_429_and_network() {
        for status in [0, 429, 500, 502, 503, 504, 599] {
            let err = AicError::LlmApiError {
                status,
                message: "x".into(),
            };
            assert!(err.is_retryable(), "status {status} should be retryable");
        }
    }

    #[test]
    fn is_retryable_4xx_not_retryable() {
        for status in [400, 401, 403, 404, 422] {
            let err = AicError::LlmApiError {
                status,
                message: "x".into(),
            };
            assert!(
                !err.is_retryable(),
                "status {status} should NOT be retryable"
            );
        }
    }

    #[test]
    fn is_retryable_2xx_3xx_not_retryable() {
        // 정상 응답이 retryable로 잡히면 안 됨 (실수 방지)
        for status in [200, 201, 301, 302] {
            let err = AicError::LlmApiError {
                status,
                message: "x".into(),
            };
            assert!(!err.is_retryable());
        }
    }

    #[test]
    fn is_retryable_non_llm_errors_not_retryable() {
        assert!(!AicError::ServerNotRunning.is_retryable());
        assert!(!AicError::ApiKeyMissing {
            provider: "x".into()
        }
        .is_retryable());
        assert!(!AicError::CliNotFound {
            cli_name: "x".into()
        }
        .is_retryable());
        assert!(!AicError::ConfigError("x".into()).is_retryable());
    }
}
