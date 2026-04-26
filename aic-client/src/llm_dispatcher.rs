//! LLM Provider 및 CLI Backend 디스패처
//!
//! 설정된 LLM Provider(OpenAI 호환, Anthropic) 또는
//! CLI Backend(kiro-cli, claude-cli)로 요청을 라우팅한다.

use aic_common::{AicError, LlmConfig, ProviderConfig, ProviderType};
use futures::stream;
use futures::Stream;
use reqwest::Client;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 모델 이름에서 응답 시간을 추정해 request timeout을 결정한다.
/// `base` (사용자 config의 request_timeout_secs)는 floor 역할 — 사용자가 명시적으로
/// 큰 값을 설정했으면 그대로 사용, 작은 base에 대해서만 모델별 minimum을 적용한다.
pub fn estimate_request_timeout(model: &str, base_secs: u64) -> Duration {
    let m = model.to_lowercase();
    let secs = if m.contains("deepseek-v")
        || m.contains("deepseek-r")
        || m.contains("405b")
        || m.contains("opus")
        || m.contains("o1")
    {
        base_secs.max(180)
    } else if m.contains("70b") || m.contains("sonnet") || m.contains("nemotron") {
        base_secs.max(90)
    } else if m.contains("32b") || m.contains("haiku") || m.contains("gpt-4o") {
        base_secs.max(45)
    } else {
        base_secs
    };
    Duration::from_secs(secs)
}

/// 단순 circuit breaker — 60초 window 안에 N회 실패하면 30초 동안 fail-fast.
#[derive(Debug)]
struct CircuitBreaker {
    window: Mutex<VecDeque<Instant>>,
    open_until: Mutex<Option<Instant>>,
    threshold: usize,
    window_duration: Duration,
    open_duration: Duration,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            window: Mutex::new(VecDeque::new()),
            open_until: Mutex::new(None),
            threshold: 5,
            window_duration: Duration::from_secs(60),
            open_duration: Duration::from_secs(30),
        }
    }

    /// circuit이 열려 있으면 즉시 에러 반환. 만료된 open 상태는 자동 닫힌다.
    fn check(&self) -> Result<(), AicError> {
        let mut open = self.open_until.lock().unwrap();
        if let Some(until) = *open {
            let now = Instant::now();
            if now < until {
                let secs = until.saturating_duration_since(now).as_secs();
                return Err(AicError::LlmApiError {
                    status: 0,
                    message: format!(
                        "최근 연속 실패가 많아 circuit breaker가 열렸습니다. 약 {secs}초 후 자동 재개"
                    ),
                });
            }
            *open = None;
        }
        Ok(())
    }

    fn record_failure(&self) {
        let now = Instant::now();
        let mut win = self.window.lock().unwrap();
        win.push_back(now);
        while let Some(&front) = win.front() {
            if now.duration_since(front) > self.window_duration {
                win.pop_front();
            } else {
                break;
            }
        }
        if win.len() >= self.threshold {
            *self.open_until.lock().unwrap() = Some(now + self.open_duration);
            win.clear();
            // P4: audit log — circuit open
            let _ = crate::audit::append(
                "circuit_opened",
                serde_json::json!({
                    "threshold": self.threshold,
                    "window_secs": self.window_duration.as_secs(),
                    "open_secs": self.open_duration.as_secs(),
                }),
            );
        }
    }

    fn record_success(&self) {
        self.window.lock().unwrap().clear();
    }
}

/// LLM 요청 디스패처.
///
/// `LlmConfig`의 `default_provider`에 해당하는 provider를 찾아
/// 요청을 라우팅한다.
pub struct LlmDispatcher {
    config: LlmConfig,
    http_client: Client,
    circuit: Arc<CircuitBreaker>,
}

impl Clone for LlmDispatcher {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            http_client: self.http_client.clone(),
            circuit: Arc::clone(&self.circuit),
        }
    }
}

impl LlmDispatcher {
    /// LlmConfig로부터 디스패처를 생성한다.
    ///
    /// `connect_timeout`(TCP 연결까지)과 `timeout`(요청 전체 — LLM 응답 대기 포함)을
    /// 분리해서 적용한다. connect는 짧게(기본 5s) 잡아 unreachable endpoint를 빠르게 감지하고,
    /// 전체 timeout은 LLM 응답 대기 시간을 포함하므로 더 길게(기본 30s) 잡는다.
    pub fn from_config(config: LlmConfig) -> Self {
        let http_client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(config.connect_timeout_secs))
            .timeout(std::time::Duration::from_secs(config.request_timeout_secs))
            .build()
            .unwrap_or_default();
        Self {
            config,
            http_client,
            circuit: Arc::new(CircuitBreaker::new()),
        }
    }

    /// 프롬프트를 설정된 백엔드로 전송하고 응답을 반환한다.
    ///
    /// 일시적 에러(HTTP 5xx, 429, 네트워크 오류)에 대해 최대 5회까지 재시도한다.
    /// 재시도 사이에는 0.5s → 1s → 2s → 4s exponential backoff을 둔다 (총 backoff 약 7.5s).
    /// CLI Backend는 재시도하지 않는다 (대부분 영구적 에러).
    pub async fn send(&self, prompt: &str) -> Result<String, AicError> {
        let provider = self.resolve_provider()?;

        // CLI는 재시도/circuit breaker/redaction 의미 약함 (로컬 실행)
        if matches!(provider.provider_type, ProviderType::CliBackend) {
            return self.send_cli(provider, prompt);
        }

        // P2: secret/PII redaction (LLM 송신 직전 단일 stage)
        // AIC_REDACT=off 환경 변수로 비활성 가능 (escape hatch)
        let redact_enabled = std::env::var("AIC_REDACT")
            .map(|v| v.to_lowercase() != "off")
            .unwrap_or(true);
        let prompt_owned;
        let prompt: &str = if redact_enabled {
            let (redacted, report) = crate::redaction::redact(prompt);
            if !report.is_empty() {
                let summary: String = report
                    .counts
                    .iter()
                    .map(|(k, c)| format!(" {k}×{c}"))
                    .collect();
                eprintln!(
                    "\x1b[33m⚠ {} redaction applied:{}\x1b[0m",
                    report.total(),
                    summary
                );
                // P4: audit log append (best-effort)
                let _ = crate::audit::append(
                    "redaction_applied",
                    serde_json::json!({"counts": report.counts, "total": report.total()}),
                );
            }
            prompt_owned = redacted;
            &prompt_owned
        } else {
            eprintln!("\x1b[33m⚠ AIC_REDACT=off — secret/PII이 LLM에 그대로 전송됩니다\x1b[0m");
            let _ = crate::audit::append("redact_bypassed", serde_json::json!({}));
            prompt
        };

        // circuit이 열려있으면 즉시 fail-fast (60s window 5회 실패 → 30s open)
        self.circuit.check()?;

        const MAX_ATTEMPTS: u32 = 5;
        const BASE_DELAY_MS: u64 = 500;

        let mut last_err: Option<AicError> = None;
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                let delay_ms = BASE_DELAY_MS * (1u64 << (attempt - 1));
                eprintln!(
                    "\x1b[90m  ... 재시도 {}/{} ({}ms 대기){}\x1b[0m",
                    attempt + 1,
                    MAX_ATTEMPTS,
                    delay_ms,
                    last_err
                        .as_ref()
                        .map(|e| format!(" — {}", e.user_message()))
                        .unwrap_or_default()
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let result = match provider.provider_type {
                ProviderType::OpenAiCompatible => self.send_openai(provider, prompt).await,
                ProviderType::Anthropic => self.send_anthropic(provider, prompt).await,
                ProviderType::CliBackend => unreachable!("filtered above"),
            };

            match result {
                Ok(response) => {
                    self.circuit.record_success();
                    return Ok(response);
                }
                Err(e) if e.is_retryable() && attempt + 1 < MAX_ATTEMPTS => {
                    last_err = Some(e);
                    continue;
                }
                Err(e) => {
                    // 최종 실패 → circuit breaker에 기록
                    self.circuit.record_failure();
                    return Err(e);
                }
            }
        }

        let err = last_err.expect("loop ran at least once");
        self.circuit.record_failure();
        Err(err)
    }

    /// 스트리밍 응답 (REPL 모드용).
    ///
    /// 현재는 `send()`를 호출하고 결과를 단일 청크로 래핑한다.
    /// 추후 실제 SSE 스트리밍으로 교체 가능.
    pub async fn send_stream(
        &self,
        prompt: &str,
    ) -> Result<impl Stream<Item = Result<String, AicError>>, AicError> {
        let response = self.send(prompt).await?;
        Ok(stream::once(async move { Ok(response) }))
    }

    /// OpenAI-compatible streaming 응답. 첫 토큰부터 callback으로 incremental 전달.
    /// 다른 provider type은 단발 `send()`로 fallback (callback에 전체 응답 1회 전달).
    pub async fn send_streaming<F>(&self, prompt: &str, mut on_chunk: F) -> Result<String, AicError>
    where
        F: FnMut(&str),
    {
        let provider = self.resolve_provider()?;

        // CliBackend는 streaming 미지원 — fallback
        if matches!(provider.provider_type, ProviderType::CliBackend) {
            let resp = self.send(prompt).await?;
            on_chunk(&resp);
            return Ok(resp);
        }

        self.circuit.check()?;

        // redaction (send와 동일 정책)
        let redact_enabled = std::env::var("AIC_REDACT")
            .map(|v| v.to_lowercase() != "off")
            .unwrap_or(true);
        let prompt_owned;
        let prompt_to_send: &str = if redact_enabled {
            let (redacted, report) = crate::redaction::redact(prompt);
            if !report.is_empty() {
                let summary: String = report
                    .counts
                    .iter()
                    .map(|(k, c)| format!(" {k}×{c}"))
                    .collect();
                eprintln!(
                    "\x1b[33m⚠ {} redaction applied:{}\x1b[0m",
                    report.total(),
                    summary
                );
                let _ = crate::audit::append(
                    "redaction_applied",
                    serde_json::json!({"counts": report.counts, "total": report.total()}),
                );
            }
            prompt_owned = redacted;
            &prompt_owned
        } else {
            eprintln!("\x1b[33m⚠ AIC_REDACT=off — secret/PII이 LLM에 그대로 전송됩니다\x1b[0m");
            let _ = crate::audit::append("redact_bypassed", serde_json::json!({}));
            prompt
        };

        let raw = provider
            .api_key
            .as_deref()
            .ok_or_else(|| AicError::ApiKeyMissing {
                provider: self.config.default_provider.clone(),
            })?;
        let resolved = crate::keychain::resolve(raw).map_err(|e| AicError::ApiKeyMissing {
            provider: format!("{} ({e})", self.config.default_provider),
        })?;

        let result = match provider.provider_type {
            ProviderType::OpenAiCompatible => {
                let endpoint = provider
                    .endpoint
                    .as_deref()
                    .unwrap_or("https://api.openai.com/v1/chat/completions");
                let model = provider.model.as_deref().unwrap_or("gpt-4o");
                let timeout = estimate_request_timeout(model, self.config.request_timeout_secs);
                crate::streaming::stream_openai_compat(
                    &self.http_client,
                    endpoint,
                    &resolved,
                    model,
                    prompt_to_send,
                    timeout,
                    |chunk| on_chunk(chunk),
                )
                .await
            }
            ProviderType::Anthropic => {
                let endpoint = provider
                    .endpoint
                    .as_deref()
                    .unwrap_or("https://api.anthropic.com/v1/messages");
                let model = provider
                    .model
                    .as_deref()
                    .unwrap_or("claude-sonnet-4-20250514");
                let timeout = estimate_request_timeout(model, self.config.request_timeout_secs);
                crate::streaming::stream_anthropic(
                    &self.http_client,
                    endpoint,
                    &resolved,
                    model,
                    prompt_to_send,
                    timeout,
                    |chunk| on_chunk(chunk),
                )
                .await
            }
            ProviderType::CliBackend => unreachable!("filtered above"),
        };

        match &result {
            Ok(_) => self.circuit.record_success(),
            Err(_) => self.circuit.record_failure(),
        }

        result
    }

    // ── 내부 헬퍼 ──────────────────────────────────────────────

    /// default_provider에 해당하는 ProviderConfig를 찾는다.
    fn resolve_provider(&self) -> Result<&ProviderConfig, AicError> {
        self.config
            .providers
            .get(&self.config.default_provider)
            .ok_or_else(|| {
                AicError::ConfigError(format!(
                    "Provider '{}' 설정을 찾을 수 없습니다",
                    self.config.default_provider
                ))
            })
    }

    /// OpenAI 호환 API 요청 (OpenAI, NVIDIA 등).
    async fn send_openai(
        &self,
        provider: &ProviderConfig,
        prompt: &str,
    ) -> Result<String, AicError> {
        let endpoint = provider
            .endpoint
            .as_deref()
            .unwrap_or("https://api.openai.com/v1/chat/completions");
        let raw = provider
            .api_key
            .as_deref()
            .ok_or_else(|| AicError::ApiKeyMissing {
                provider: self.config.default_provider.clone(),
            })?;
        // keychain reference (`keychain:<name>`) 자동 해석, 평문은 그대로
        let resolved = crate::keychain::resolve(raw).map_err(|e| AicError::ApiKeyMissing {
            provider: format!("{} ({e})", self.config.default_provider),
        })?;
        let api_key = resolved.as_str();
        let model = provider.model.as_deref().unwrap_or("gpt-4o");

        let body = json!({
            "model": model,
            "messages": [{ "role": "user", "content": prompt }]
        });

        // 모델별 동적 timeout: 큰 모델(deepseek/405b/opus)은 base가 작아도 최소 180s 적용
        let timeout = estimate_request_timeout(model, self.config.request_timeout_secs);

        let resp = self
            .http_client
            .post(endpoint)
            .header("Authorization", format!("Bearer {api_key}"))
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| AicError::LlmApiError {
                status: 0,
                message: e.to_string(),
            })?;

        handle_http_status(&resp)?;

        // Rate limit 헤더 로깅 (Groq, OpenAI 등)
        log_rate_limit_headers(&resp);

        let bytes = resp.bytes().await.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: format!("응답 수신 실패: {e}"),
        })?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AicError::LlmApiError {
                status: 0,
                message: format!("응답 파싱 실패: {e}"),
            })?;

        extract_openai_content(&json)
    }

    /// Anthropic 전용 API 요청.
    async fn send_anthropic(
        &self,
        provider: &ProviderConfig,
        prompt: &str,
    ) -> Result<String, AicError> {
        let endpoint = provider
            .endpoint
            .as_deref()
            .unwrap_or("https://api.anthropic.com/v1/messages");
        let raw = provider
            .api_key
            .as_deref()
            .ok_or_else(|| AicError::ApiKeyMissing {
                provider: self.config.default_provider.clone(),
            })?;
        let resolved = crate::keychain::resolve(raw).map_err(|e| AicError::ApiKeyMissing {
            provider: format!("{} ({e})", self.config.default_provider),
        })?;
        let api_key = resolved.as_str();
        let model = provider
            .model
            .as_deref()
            .unwrap_or("claude-sonnet-4-20250514");

        let body = json!({
            "model": model,
            "messages": [{ "role": "user", "content": prompt }],
            "max_tokens": 4096
        });

        // 모델별 동적 timeout (opus는 180s, sonnet 90s, haiku 45s)
        let timeout = estimate_request_timeout(model, self.config.request_timeout_secs);

        let resp = self
            .http_client
            .post(endpoint)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| AicError::LlmApiError {
                status: 0,
                message: e.to_string(),
            })?;

        handle_http_status(&resp)?;

        let bytes = resp.bytes().await.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: format!("응답 수신 실패: {e}"),
        })?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AicError::LlmApiError {
                status: 0,
                message: format!("응답 파싱 실패: {e}"),
            })?;

        extract_anthropic_content(&json)
    }

    /// CLI Backend 실행 (kiro-cli, claude-cli).
    fn send_cli(&self, provider: &ProviderConfig, prompt: &str) -> Result<String, AicError> {
        let cli_path = provider
            .cli_path
            .as_deref()
            .unwrap_or(&self.config.default_provider);

        let output = std::process::Command::new(cli_path)
            .arg(prompt)
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    AicError::CliNotFound {
                        cli_name: cli_path.to_string(),
                    }
                } else {
                    AicError::LlmApiError {
                        status: 0,
                        message: format!("CLI 실행 실패: {e}"),
                    }
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AicError::LlmApiError {
                status: output.status.code().unwrap_or(1) as u16,
                message: format!("CLI 프로세스 에러: {stderr}"),
            });
        }

        String::from_utf8(output.stdout).map_err(|e| AicError::LlmApiError {
            status: 0,
            message: format!("CLI 출력 디코딩 실패: {e}"),
        })
    }
}

// ── 유틸리티 함수 ──────────────────────────────────────────────

/// Rate limit 관련 응답 헤더를 디버그 로그로 출력한다.
/// Groq, OpenAI 등 x-ratelimit-* 헤더를 지원한다.
fn log_rate_limit_headers(resp: &reqwest::Response) {
    if std::env::var("AIC_DEBUG")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        let headers = resp.headers();
        let remaining_req = headers
            .get("x-ratelimit-remaining-requests")
            .and_then(|v| v.to_str().ok());
        let remaining_tok = headers
            .get("x-ratelimit-remaining-tokens")
            .and_then(|v| v.to_str().ok());
        let reset_req = headers
            .get("x-ratelimit-reset-requests")
            .and_then(|v| v.to_str().ok());
        let reset_tok = headers
            .get("x-ratelimit-reset-tokens")
            .and_then(|v| v.to_str().ok());

        if remaining_req.is_some() || remaining_tok.is_some() {
            eprintln!(
                "\x1b[90m[DEBUG] Rate limit: req_remaining={}, tok_remaining={}, req_reset={}, tok_reset={}\x1b[0m",
                remaining_req.unwrap_or("-"),
                remaining_tok.unwrap_or("-"),
                reset_req.unwrap_or("-"),
                reset_tok.unwrap_or("-"),
            );
        }
    }
}

/// HTTP 응답 상태 코드를 검사하여 에러를 반환한다.
fn handle_http_status(resp: &reqwest::Response) -> Result<(), AicError> {
    let status = resp.status().as_u16();
    match status {
        200..=299 => Ok(()),
        401 => Err(AicError::LlmApiError {
            status,
            message: "API 인증 실패".to_string(),
        }),
        429 => Err(AicError::LlmApiError {
            status,
            message: "API 요청 한도 초과".to_string(),
        }),
        _ => Err(AicError::LlmApiError {
            status,
            message: format!("HTTP {status} 에러"),
        }),
    }
}

/// OpenAI 호환 응답에서 content를 추출한다.
fn extract_openai_content(json: &serde_json::Value) -> Result<String, AicError> {
    json["choices"]
        .get(0)
        .and_then(|c| c["message"]["content"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AicError::LlmApiError {
            status: 0,
            message: "OpenAI 응답에서 content를 추출할 수 없습니다".to_string(),
        })
}

/// Anthropic 응답에서 content를 추출한다.
fn extract_anthropic_content(json: &serde_json::Value) -> Result<String, AicError> {
    json["content"]
        .get(0)
        .and_then(|c| c["text"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AicError::LlmApiError {
            status: 0,
            message: "Anthropic 응답에서 content를 추출할 수 없습니다".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::{LlmConfig, ProviderConfig, ProviderType};
    use std::collections::HashMap;

    fn make_config(
        provider_type: ProviderType,
        api_key: Option<&str>,
        cli_path: Option<&str>,
    ) -> LlmConfig {
        let name = match provider_type {
            ProviderType::OpenAiCompatible => "openai",
            ProviderType::Anthropic => "anthropic",
            ProviderType::CliBackend => "cli",
        };
        LlmConfig {
            default_provider: name.to_string(),
            providers: HashMap::from([(
                name.to_string(),
                ProviderConfig {
                    provider_type,
                    endpoint: Some("http://localhost:9999/v1/chat".to_string()),
                    api_key: api_key.map(|s| s.to_string()),
                    model: Some("test-model".to_string()),
                    cli_path: cli_path.map(|s| s.to_string()),
                },
            )]),
            lang: "korean".to_string(),
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        }
    }

    // ── from_config ────────────────────────────────────────────

    #[test]
    fn from_config_stores_config() {
        let config = make_config(ProviderType::OpenAiCompatible, Some("sk-test"), None);
        let dispatcher = LlmDispatcher::from_config(config.clone());
        assert_eq!(dispatcher.config.default_provider, "openai");
    }

    // ── resolve_provider ───────────────────────────────────────

    #[test]
    fn resolve_provider_missing_returns_config_error() {
        let config = LlmConfig {
            default_provider: "nonexistent".to_string(),
            providers: HashMap::new(),
            lang: "korean".to_string(),
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        };
        let dispatcher = LlmDispatcher::from_config(config);
        let err = dispatcher.resolve_provider().unwrap_err();
        assert!(matches!(err, AicError::ConfigError(_)));
    }

    // ── API key missing ────────────────────────────────────────

    #[tokio::test]
    async fn openai_missing_api_key_returns_error() {
        let config = make_config(ProviderType::OpenAiCompatible, None, None);
        let dispatcher = LlmDispatcher::from_config(config);
        let err = dispatcher.send("hello").await.unwrap_err();
        assert!(matches!(err, AicError::ApiKeyMissing { .. }));
    }

    #[tokio::test]
    async fn anthropic_missing_api_key_returns_error() {
        let config = make_config(ProviderType::Anthropic, None, None);
        let dispatcher = LlmDispatcher::from_config(config);
        let err = dispatcher.send("hello").await.unwrap_err();
        assert!(matches!(err, AicError::ApiKeyMissing { .. }));
    }

    // ── CLI not found ──────────────────────────────────────────

    #[tokio::test]
    async fn cli_not_found_returns_error() {
        let config = make_config(
            ProviderType::CliBackend,
            None,
            Some("/nonexistent/path/to/cli-tool-xyz"),
        );
        let dispatcher = LlmDispatcher::from_config(config);
        let err = dispatcher.send("hello").await.unwrap_err();
        assert!(matches!(err, AicError::CliNotFound { .. }));
    }

    // ── HTTP status handling ───────────────────────────────────

    #[test]
    fn handle_http_status_401() {
        let resp = http::Response::builder().status(401).body("").unwrap();
        let reqwest_resp = reqwest::Response::from(resp);
        let err = handle_http_status(&reqwest_resp).unwrap_err();
        match err {
            AicError::LlmApiError { status, message } => {
                assert_eq!(status, 401);
                assert_eq!(message, "API 인증 실패");
            }
            _ => panic!("expected LlmApiError"),
        }
    }

    #[test]
    fn handle_http_status_429() {
        let resp = http::Response::builder().status(429).body("").unwrap();
        let reqwest_resp = reqwest::Response::from(resp);
        let err = handle_http_status(&reqwest_resp).unwrap_err();
        match err {
            AicError::LlmApiError { status, message } => {
                assert_eq!(status, 429);
                assert_eq!(message, "API 요청 한도 초과");
            }
            _ => panic!("expected LlmApiError"),
        }
    }

    #[test]
    fn handle_http_status_500() {
        let resp = http::Response::builder().status(500).body("").unwrap();
        let reqwest_resp = reqwest::Response::from(resp);
        let err = handle_http_status(&reqwest_resp).unwrap_err();
        match err {
            AicError::LlmApiError { status, .. } => assert_eq!(status, 500),
            _ => panic!("expected LlmApiError"),
        }
    }

    #[test]
    fn handle_http_status_200_ok() {
        let resp = http::Response::builder().status(200).body("").unwrap();
        let reqwest_resp = reqwest::Response::from(resp);
        assert!(handle_http_status(&reqwest_resp).is_ok());
    }

    // ── Response extraction ────────────────────────────────────

    #[test]
    fn extract_openai_content_valid() {
        let json = json!({
            "choices": [{ "message": { "content": "Hello world" } }]
        });
        assert_eq!(extract_openai_content(&json).unwrap(), "Hello world");
    }

    #[test]
    fn extract_openai_content_empty_choices() {
        let json = json!({ "choices": [] });
        assert!(extract_openai_content(&json).is_err());
    }

    #[test]
    fn extract_anthropic_content_valid() {
        let json = json!({
            "content": [{ "type": "text", "text": "Bonjour" }]
        });
        assert_eq!(extract_anthropic_content(&json).unwrap(), "Bonjour");
    }

    #[test]
    fn extract_anthropic_content_empty() {
        let json = json!({ "content": [] });
        assert!(extract_anthropic_content(&json).is_err());
    }

    // ── estimate_request_timeout ──────────────────────────────

    #[test]
    fn estimate_timeout_for_deepseek_uses_180s_floor() {
        // base가 작아도 deepseek은 최소 180s
        let t = estimate_request_timeout("deepseek-ai/deepseek-v4-pro", 30);
        assert_eq!(t, std::time::Duration::from_secs(180));
    }

    #[test]
    fn estimate_timeout_for_405b_uses_180s_floor() {
        let t = estimate_request_timeout("meta/llama-3.1-405b-instruct", 30);
        assert_eq!(t, std::time::Duration::from_secs(180));
    }

    #[test]
    fn estimate_timeout_for_opus_uses_180s_floor() {
        let t = estimate_request_timeout("claude-3-opus-20240229", 30);
        assert_eq!(t, std::time::Duration::from_secs(180));
    }

    #[test]
    fn estimate_timeout_for_70b_uses_90s_floor() {
        let t = estimate_request_timeout("meta/llama-3.1-70b-instruct", 30);
        assert_eq!(t, std::time::Duration::from_secs(90));
    }

    #[test]
    fn estimate_timeout_for_sonnet_uses_90s_floor() {
        let t = estimate_request_timeout("claude-sonnet-4-20250514", 30);
        assert_eq!(t, std::time::Duration::from_secs(90));
    }

    #[test]
    fn estimate_timeout_for_haiku_uses_45s_floor() {
        let t = estimate_request_timeout("claude-3-5-haiku-20241022", 30);
        assert_eq!(t, std::time::Duration::from_secs(45));
    }

    #[test]
    fn estimate_timeout_for_small_model_uses_base() {
        // 8b 같은 작은 모델은 base 그대로
        let t = estimate_request_timeout("meta/llama-3.1-8b-instruct", 30);
        assert_eq!(t, std::time::Duration::from_secs(30));
    }

    #[test]
    fn estimate_timeout_user_base_overrides_floor() {
        // 사용자가 명시적으로 큰 base 설정한 경우 그대로 사용 (max로 보존)
        let t = estimate_request_timeout("meta/llama-3.1-8b-instruct", 600);
        assert_eq!(t, std::time::Duration::from_secs(600));
        let t2 = estimate_request_timeout("deepseek-ai/deepseek-v4", 600);
        assert_eq!(t2, std::time::Duration::from_secs(600));
    }

    // ── CircuitBreaker ─────────────────────────────────────────

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        let cb = CircuitBreaker::new();
        for _ in 0..5 {
            cb.record_failure();
        }
        let err = cb.check().unwrap_err();
        match err {
            AicError::LlmApiError { message, .. } => {
                assert!(message.contains("circuit breaker"));
            }
            _ => panic!("expected LlmApiError"),
        }
    }

    #[test]
    fn circuit_breaker_passes_below_threshold() {
        let cb = CircuitBreaker::new();
        for _ in 0..4 {
            cb.record_failure();
        }
        assert!(cb.check().is_ok());
    }

    #[test]
    fn circuit_breaker_resets_on_success() {
        let cb = CircuitBreaker::new();
        for _ in 0..4 {
            cb.record_failure();
        }
        cb.record_success();
        // 성공 후 window 클리어 — 다시 4번 실패해도 still 4 < 5
        for _ in 0..4 {
            cb.record_failure();
        }
        assert!(cb.check().is_ok());
    }

    // ── send_stream wraps send ─────────────────────────────────

    #[tokio::test]
    async fn send_stream_returns_error_on_missing_key() {
        let config = make_config(ProviderType::OpenAiCompatible, None, None);
        let dispatcher = LlmDispatcher::from_config(config);
        match dispatcher.send_stream("hello").await {
            Err(AicError::ApiKeyMissing { .. }) => {}
            Err(other) => panic!("expected ApiKeyMissing, got: {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
