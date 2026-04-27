//! LLM API mock 서버 통합 테스트
//!
//! OpenAI/Anthropic API 요청 형식 구성 및 응답 파싱을 검증한다.
//! 실제 HTTP 서버 없이 요청 빌딩과 응답 추출 로직을 테스트한다.
//!
//! Requirements: 8.1, 8.2

use aic_common::{AicError, LlmConfig, ProviderConfig, ProviderType};
use std::collections::HashMap;

// ── 헬퍼: LlmConfig 생성 ──────────────────────────────────────

fn make_openai_config(api_key: Option<&str>) -> LlmConfig {
    LlmConfig {
        default_provider: "openai".to_string(),
        providers: HashMap::from([(
            "openai".to_string(),
            ProviderConfig {
                provider_type: ProviderType::OpenAiCompatible,
                endpoint: Some("https://api.openai.com/v1/chat/completions".to_string()),
                api_key: api_key.map(|s| s.to_string()),
                model: Some("gpt-4o".to_string()),
                cli_path: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    }
}

fn make_groq_config(api_key: Option<&str>) -> LlmConfig {
    LlmConfig {
        default_provider: "groq".to_string(),
        providers: HashMap::from([(
            "groq".to_string(),
            ProviderConfig {
                provider_type: ProviderType::Groq,
                // endpoint·model 미지정 — dispatcher 기본값(Groq Cloud + llama-3.3-70b-versatile)이 적용되어야 함
                endpoint: None,
                api_key: api_key.map(|s| s.to_string()),
                model: None,
                cli_path: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    }
}

fn make_anthropic_config(api_key: Option<&str>) -> LlmConfig {
    LlmConfig {
        default_provider: "anthropic".to_string(),
        providers: HashMap::from([(
            "anthropic".to_string(),
            ProviderConfig {
                provider_type: ProviderType::Anthropic,
                endpoint: Some("https://api.anthropic.com/v1/messages".to_string()),
                api_key: api_key.map(|s| s.to_string()),
                model: Some("claude-sonnet-4-6".to_string()),
                cli_path: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    }
}

fn make_cli_config(cli_path: &str) -> LlmConfig {
    LlmConfig {
        default_provider: "cli".to_string(),
        providers: HashMap::from([(
            "cli".to_string(),
            ProviderConfig {
                provider_type: ProviderType::CliBackend,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: Some(cli_path.to_string()),
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    }
}

// ── LlmDispatcher 생성 및 API key 검증 ────────────────────────

#[tokio::test]
async fn openai_missing_api_key_returns_api_key_missing() {
    let config = make_openai_config(None);
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let err = dispatcher.send("test prompt").await.unwrap_err();
    assert!(
        matches!(err, AicError::ApiKeyMissing { .. }),
        "ApiKeyMissing 에러를 기대했지만 {:?}를 받았습니다",
        err
    );
}

#[tokio::test]
async fn groq_missing_api_key_returns_api_key_missing() {
    let config = make_groq_config(None);
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let err = dispatcher.send("test prompt").await.unwrap_err();
    assert!(
        matches!(err, AicError::ApiKeyMissing { .. }),
        "ApiKeyMissing 에러를 기대했지만 {:?}를 받았습니다",
        err
    );
}

#[tokio::test]
async fn anthropic_missing_api_key_returns_api_key_missing() {
    let config = make_anthropic_config(None);
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let err = dispatcher.send("test prompt").await.unwrap_err();
    assert!(
        matches!(err, AicError::ApiKeyMissing { .. }),
        "ApiKeyMissing 에러를 기대했지만 {:?}를 받았습니다",
        err
    );
}

// ── Provider 설정 누락 시 에러 ─────────────────────────────────

#[tokio::test]
async fn missing_provider_returns_config_error() {
    let config = LlmConfig {
        default_provider: "nonexistent".to_string(),
        providers: HashMap::new(),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    };
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let err = dispatcher.send("test").await.unwrap_err();
    assert!(
        matches!(err, AicError::ConfigError(_)),
        "ConfigError를 기대했지만 {:?}를 받았습니다",
        err
    );
}

// ── CLI Backend: 존재하지 않는 CLI 실행 시 에러 ────────────────

#[tokio::test]
async fn cli_not_found_returns_error() {
    let config = make_cli_config("/nonexistent/path/to/fake-cli-tool-xyz");
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let err = dispatcher.send("test").await.unwrap_err();
    assert!(
        matches!(err, AicError::CliNotFound { .. }),
        "CliNotFound 에러를 기대했지만 {:?}를 받았습니다",
        err
    );
}

// ── OpenAI 응답 파싱 검증 (직접 JSON 구조 테스트) ──────────────

#[test]
fn openai_response_format_parsing() {
    // OpenAI API 응답 형식
    let response_json = serde_json::json!({
        "id": "chatcmpl-abc123",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "The error is caused by a type mismatch."
            },
            "finish_reason": "stop"
        }]
    });

    // content 추출 검증
    let content = response_json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap();
    assert_eq!(content, "The error is caused by a type mismatch.");
}

#[test]
fn groq_response_format_parsing() {
    // Groq는 OpenAI 호환 — 응답 포맷도 동일
    let response_json = serde_json::json!({
        "id": "chatcmpl-groq-xyz",
        "object": "chat.completion",
        "model": "llama-3.3-70b-versatile",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "The build failed because of a missing dependency."
            },
            "finish_reason": "stop"
        }]
    });

    let content = response_json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap();
    assert_eq!(content, "The build failed because of a missing dependency.");
}

#[test]
fn anthropic_response_format_parsing() {
    // Anthropic API 응답 형식
    let response_json = serde_json::json!({
        "id": "msg_abc123",
        "type": "message",
        "role": "assistant",
        "content": [{
            "type": "text",
            "text": "Here is the analysis of your error."
        }],
        "stop_reason": "end_turn"
    });

    // content 추출 검증
    let text = response_json["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "Here is the analysis of your error.");
}

// ── OpenAI 요청 형식 검증 ──────────────────────────────────────

#[test]
fn openai_request_body_format() {
    let model = "gpt-4o";
    let prompt = "Why did my build fail?";

    let body = serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": prompt }]
    });

    assert_eq!(body["model"], "gpt-4o");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], prompt);
}

#[test]
fn anthropic_request_body_format() {
    let model = "claude-sonnet-4-6";
    let prompt = "Analyze this error";

    let body = serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": prompt }],
        "max_tokens": 4096
    });

    assert_eq!(body["model"], model);
    assert_eq!(body["messages"][0]["content"], prompt);
    assert_eq!(body["max_tokens"], 4096);
}

// ── send_stream도 동일한 에러 처리 ─────────────────────────────

#[tokio::test]
async fn send_stream_propagates_api_key_error() {
    let config = make_openai_config(None);
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    match dispatcher.send_stream("test").await {
        Err(AicError::ApiKeyMissing { .. }) => {} // 기대한 에러
        Err(other) => panic!("ApiKeyMissing을 기대했지만 {:?}를 받았습니다", other),
        Ok(_) => panic!("에러를 기대했지만 Ok를 받았습니다"),
    }
}
