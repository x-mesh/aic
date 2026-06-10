//! LLM Provider 및 CLI Backend 디스패처
//!
//! 설정된 LLM Provider(OpenAI 호환, Groq, Anthropic) 또는
//! CLI Backend(kiro-cli, claude-cli)로 요청을 라우팅한다.

use aic_common::{AicError, LlmConfig, ProviderConfig, ProviderType};
use futures::stream;
use futures::Stream;
use reqwest::Client;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// OpenAI 호환 provider의 기본 endpoint·모델 결정.
/// 사용자가 ProviderConfig에 endpoint·model을 비워둬도 즉시 동작하도록
/// `ProviderType`에 따른 합리적 기본값을 돌려준다.
pub(crate) fn openai_compat_defaults(ptype: &ProviderType) -> (&'static str, &'static str) {
    match ptype {
        ProviderType::Groq => (
            "https://api.groq.com/openai/v1/chat/completions",
            "llama-3.3-70b-versatile",
        ),
        // OpenAI / NVIDIA 등 일반 OpenAI-compat — OpenAI 기본값
        _ => ("https://api.openai.com/v1/chat/completions", "gpt-4o"),
    }
}

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
                ProviderType::OpenAiCompatible | ProviderType::Groq => {
                    self.send_openai(provider, prompt).await
                }
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
            ProviderType::OpenAiCompatible | ProviderType::Groq => {
                let (default_endpoint, default_model) =
                    openai_compat_defaults(&provider.provider_type);
                let endpoint = provider.endpoint.as_deref().unwrap_or(default_endpoint);
                let model = provider.model.as_deref().unwrap_or(default_model);
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
                let model = provider.model.as_deref().unwrap_or("claude-sonnet-4-6");
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

    /// 현재 provider가 tool-calling(`send_messages`)을 지원하는지.
    ///
    /// OpenAI-compat(OpenAiCompatible / Groq)과 Anthropic(SRE R4) 경로가 true.
    /// 호출부는 false일 때 기존 단발 `send` 경로(ReplSession)로 폴백한다.
    pub fn supports_tool_calling(&self) -> bool {
        self.resolve_provider()
            .map(|p| {
                matches!(
                    p.provider_type,
                    ProviderType::OpenAiCompatible | ProviderType::Groq | ProviderType::Anthropic
                )
            })
            .unwrap_or(false)
    }

    /// multi-turn messages + tool-calling 요청 (OpenAI-compatible 경로 전용).
    ///
    /// 기존 `send`/`send_streaming`/`extract_openai_content`는 영향받지 않는다.
    /// provider가 OpenAI-compat이 아니면 즉시 에러를 반환해 호출부가 폴백하게 한다.
    /// redaction은 송신 직전 단일 stage로 각 메시지 content에 적용한다(`send`와 동일 정책).
    pub async fn send_messages(
        &self,
        messages: &[crate::agent::types::ChatMessage],
        tools: &[crate::agent::types::ToolSpec],
    ) -> Result<crate::agent::types::ChatResponse, AicError> {
        let provider = self.resolve_provider()?;
        // Anthropic은 wire format이 달라 전용 경로로 분기(SRE R4).
        if matches!(provider.provider_type, ProviderType::Anthropic) {
            return self.send_messages_anthropic(provider, messages, tools).await;
        }
        if !matches!(
            provider.provider_type,
            ProviderType::OpenAiCompatible | ProviderType::Groq
        ) {
            return Err(AicError::ConfigError(
                "send_messages는 OpenAI 호환 또는 Anthropic provider에서만 지원됩니다".to_string(),
            ));
        }

        self.circuit.check()?;

        let (default_endpoint, default_model) = openai_compat_defaults(&provider.provider_type);
        let endpoint = provider.endpoint.as_deref().unwrap_or(default_endpoint);
        let model = provider.model.as_deref().unwrap_or(default_model);

        let raw = provider
            .api_key
            .as_deref()
            .ok_or_else(|| AicError::ApiKeyMissing {
                provider: self.config.default_provider.clone(),
            })?;
        let resolved = crate::keychain::resolve(raw).map_err(|e| AicError::ApiKeyMissing {
            provider: format!("{} ({e})", self.config.default_provider),
        })?;

        // redaction: 송신 직전 각 메시지 content에 적용 (AIC_REDACT=off로 비활성).
        let redact_enabled = std::env::var("AIC_REDACT")
            .map(|v| v.to_lowercase() != "off")
            .unwrap_or(true);
        let wire_messages: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                let mut j = m.to_openai_json();
                if redact_enabled {
                    if let Some(c) = j.get("content").and_then(|v| v.as_str()) {
                        let (red, _report) = crate::redaction::redact(c);
                        j["content"] = serde_json::Value::String(red);
                    }
                }
                j
            })
            .collect();

        let mut body = json!({
            "model": model,
            "messages": wire_messages,
        });
        if !tools.is_empty() {
            body["tools"] =
                serde_json::Value::Array(tools.iter().map(|t| t.to_openai_json()).collect());
            body["tool_choice"] = json!("auto");
        }

        let timeout = estimate_request_timeout(model, self.config.request_timeout_secs);

        let resp = self
            .http_client
            .post(endpoint)
            .header("Authorization", format!("Bearer {}", resolved.as_str()))
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| AicError::LlmApiError {
                status: 0,
                message: e.to_string(),
            });

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                self.circuit.record_failure();
                return Err(e);
            }
        };

        if let Err(e) = handle_http_status(&resp) {
            self.circuit.record_failure();
            return Err(e);
        }

        let bytes = resp.bytes().await.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: format!("응답 수신 실패: {e}"),
        })?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AicError::LlmApiError {
                status: 0,
                message: format!("응답 파싱 실패: {e}"),
            })?;

        match crate::agent::types::parse_openai_response(&json) {
            Some(r) => {
                self.circuit.record_success();
                Ok(r)
            }
            None => {
                self.circuit.record_failure();
                Err(AicError::LlmApiError {
                    status: 0,
                    message: "응답에서 메시지를 추출할 수 없습니다".to_string(),
                })
            }
        }
    }

    /// Anthropic Messages API tool-calling 경로 (SRE R4). `send_messages`에서 분기 호출된다.
    ///
    /// OpenAI와의 차이: system은 top-level 필드, tools는 `input_schema`, tool 결과는 user
    /// content의 `tool_result` 블록, 응답은 `content[].tool_use` 블록. 변환은
    /// `agent::types::{to_anthropic_request, parse_anthropic_response}`가 단일 출처로 담당한다.
    async fn send_messages_anthropic(
        &self,
        provider: &ProviderConfig,
        messages: &[crate::agent::types::ChatMessage],
        tools: &[crate::agent::types::ToolSpec],
    ) -> Result<crate::agent::types::ChatResponse, AicError> {
        self.circuit.check()?;

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
        let model = provider.model.as_deref().unwrap_or("claude-sonnet-4-6");

        let redact_enabled = std::env::var("AIC_REDACT")
            .map(|v| v.to_lowercase() != "off")
            .unwrap_or(true);

        let (system, mut wire_messages) = crate::agent::types::to_anthropic_request(messages);
        if redact_enabled {
            for m in &mut wire_messages {
                redact_anthropic_content(m);
            }
        }

        let mut body = json!({
            "model": model,
            "max_tokens": 4096,
            "messages": wire_messages,
        });
        if let Some(sys) = system {
            let sys = if redact_enabled {
                crate::redaction::redact(&sys).0
            } else {
                sys
            };
            body["system"] = json!(sys);
        }
        if !tools.is_empty() {
            body["tools"] =
                serde_json::Value::Array(tools.iter().map(|t| t.to_anthropic_json()).collect());
        }

        let timeout = estimate_request_timeout(model, self.config.request_timeout_secs);
        let resp = self
            .http_client
            .post(endpoint)
            .header("x-api-key", resolved.as_str())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| AicError::LlmApiError {
                status: 0,
                message: e.to_string(),
            });

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                self.circuit.record_failure();
                return Err(e);
            }
        };
        if let Err(e) = handle_http_status(&resp) {
            self.circuit.record_failure();
            return Err(e);
        }

        let bytes = resp.bytes().await.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: format!("응답 수신 실패: {e}"),
        })?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AicError::LlmApiError {
                status: 0,
                message: format!("응답 파싱 실패: {e}"),
            })?;

        match crate::agent::types::parse_anthropic_response(&json) {
            Some(r) => {
                self.circuit.record_success();
                Ok(r)
            }
            None => {
                self.circuit.record_failure();
                Err(AicError::LlmApiError {
                    status: 0,
                    message: "Anthropic 응답에서 메시지를 추출할 수 없습니다".to_string(),
                })
            }
        }
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

    /// OpenAI 호환 API 요청 (OpenAI, NVIDIA, Groq 등).
    /// endpoint·model이 비어 있으면 `provider_type`에 따라 기본값을 적용한다.
    async fn send_openai(
        &self,
        provider: &ProviderConfig,
        prompt: &str,
    ) -> Result<String, AicError> {
        let (default_endpoint, default_model) = openai_compat_defaults(&provider.provider_type);
        let endpoint = provider.endpoint.as_deref().unwrap_or(default_endpoint);
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
        let model = provider.model.as_deref().unwrap_or(default_model);

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
        let model = provider.model.as_deref().unwrap_or("claude-sonnet-4-6");

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
    ///
    /// 호출 형식:
    /// - `cli_args`가 명시되어 있으면: `<cli_path> <cli_args...> <prompt>`
    /// - 비어 있으면 `cli_path` basename으로 자동 분기:
    ///   - `kiro-cli` / `kiro` → `chat <prompt>` (kiro-cli는 첫 인자를
    ///     subcommand로 해석하므로 `chat`이 필수)
    ///   - `claude` / `claude-cli` → `-p <prompt>` (non-interactive print)
    ///   - 그 외 → `<prompt>` (legacy 동작)
    fn send_cli(&self, provider: &ProviderConfig, prompt: &str) -> Result<String, AicError> {
        let cli_path = provider
            .cli_path
            .as_deref()
            .unwrap_or(&self.config.default_provider);
        let args = resolve_cli_args(cli_path, provider.cli_args.as_deref());

        let mut cmd = std::process::Command::new(cli_path);
        for a in &args {
            cmd.arg(a);
        }
        cmd.arg(prompt);
        let output = cmd.output().map_err(|e| {
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

/// CLI Backend 호출 시 prompt 앞에 prepend할 인자를 결정한다.
///
/// 결정 규칙:
/// 1. 사용자가 `cli_args`를 명시했으면 그대로 사용한다 (override).
/// 2. 안 했으면 `cli_path` basename에서 자동 추론:
///    - `kiro-cli`, `kiro` → `["chat"]` (chat subcommand 필수)
///    - `claude`, `claude-cli` → `["-p"]` (non-interactive print 모드)
///    - 그 외 → `[]` (legacy: prompt만 그대로 전달)
pub(crate) fn resolve_cli_args(cli_path: &str, override_args: Option<&[String]>) -> Vec<String> {
    if let Some(args) = override_args {
        return args.to_vec();
    }
    let basename = std::path::Path::new(cli_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cli_path);
    match basename {
        "kiro-cli" | "kiro" => vec!["chat".to_string()],
        "claude" | "claude-cli" => vec!["-p".to_string()],
        _ => Vec::new(),
    }
}

// ── 유틸리티 함수 ──────────────────────────────────────────────

/// Rate limit 관련 응답 헤더를 디버그 로그로 출력한다.
/// Groq, OpenAI 등 x-ratelimit-* 헤더를 지원한다.
fn log_rate_limit_headers(resp: &reqwest::Response) {
    // 공통 truthy 판정(1|true, trim+case-insensitive) 재사용 — AIC_DEBUG=" true "도 ON.
    if crate::agent::debug::env_truthy("AIC_DEBUG") {
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

/// Anthropic wire 메시지의 content 블록 내 텍스트(`text`/tool_result `content`)에 redaction을
/// 적용한다(송신 직전 단일 stage — OpenAI 경로의 string content redaction과 동일 정책). SRE R4.
fn redact_anthropic_content(message: &mut serde_json::Value) {
    let Some(blocks) = message.get_mut("content").and_then(|c| c.as_array_mut()) else {
        return;
    };
    for block in blocks {
        for key in ["text", "content"] {
            if let Some(s) = block.get(key).and_then(|v| v.as_str()) {
                let (red, _r) = crate::redaction::redact(s);
                block[key] = serde_json::Value::String(red);
            }
        }
    }
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
            ProviderType::Groq => "groq",
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
                    cli_args: None,
                },
            )]),
            lang: "korean".to_string(),
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        }
    }

    // ── openai_compat_defaults ─────────────────────────────────

    #[test]
    fn openai_compat_defaults_groq_returns_groq_endpoint() {
        let (endpoint, model) = openai_compat_defaults(&ProviderType::Groq);
        assert_eq!(endpoint, "https://api.groq.com/openai/v1/chat/completions");
        assert_eq!(model, "llama-3.3-70b-versatile");
    }

    #[test]
    fn openai_compat_defaults_openai_returns_openai_endpoint() {
        let (endpoint, model) = openai_compat_defaults(&ProviderType::OpenAiCompatible);
        assert_eq!(endpoint, "https://api.openai.com/v1/chat/completions");
        assert_eq!(model, "gpt-4o");
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

    // ── resolve_cli_args ───────────────────────────────────────

    #[test]
    fn resolve_cli_args_kiro_uses_chat_subcommand() {
        // kiro-cli/kiro는 첫 인자를 subcommand로 해석하므로 chat이 필수.
        assert_eq!(resolve_cli_args("kiro-cli", None), vec!["chat".to_string()]);
        assert_eq!(resolve_cli_args("kiro", None), vec!["chat".to_string()]);
        // 절대경로도 basename으로 매칭.
        assert_eq!(
            resolve_cli_args("/usr/local/bin/kiro-cli", None),
            vec!["chat".to_string()]
        );
    }

    #[test]
    fn resolve_cli_args_claude_uses_print_flag() {
        // claude는 기본이 interactive — -p로 non-interactive print 필요.
        assert_eq!(resolve_cli_args("claude", None), vec!["-p".to_string()]);
        assert_eq!(resolve_cli_args("claude-cli", None), vec!["-p".to_string()]);
    }

    #[test]
    fn resolve_cli_args_unknown_cli_no_args() {
        assert!(resolve_cli_args("my-custom-llm", None).is_empty());
        assert!(resolve_cli_args("/opt/foo/bar-cli", None).is_empty());
    }

    #[test]
    fn resolve_cli_args_user_override_wins() {
        // 사용자가 cli_args를 명시했으면 cli basename 자동 추론을 무시한다.
        let custom = vec!["chat".to_string(), "--no-color".to_string()];
        assert_eq!(
            resolve_cli_args("kiro-cli", Some(&custom)),
            vec!["chat".to_string(), "--no-color".to_string()]
        );
        // 빈 vec override는 명시적 "no extra args" — basename 추론보다 우선.
        let empty: Vec<String> = vec![];
        assert!(resolve_cli_args("kiro-cli", Some(&empty)).is_empty());
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
        let t = estimate_request_timeout("claude-sonnet-4-6", 30);
        assert_eq!(t, std::time::Duration::from_secs(90));
    }

    #[test]
    fn estimate_timeout_for_haiku_uses_45s_floor() {
        let t = estimate_request_timeout("claude-haiku-4-5-20251001", 30);
        assert_eq!(t, std::time::Duration::from_secs(45));
    }

    #[test]
    fn estimate_timeout_for_opus_4x_uses_180s_floor() {
        // 새 ID 명명(`claude-opus-4-7`)도 substring "opus" 매칭으로 잡혀야 한다.
        let t = estimate_request_timeout("claude-opus-4-7", 30);
        assert_eq!(t, std::time::Duration::from_secs(180));
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

    // ── send_messages / tool-calling capability ────────────────

    #[test]
    fn supports_tool_calling_true_for_openai_groq_anthropic() {
        let openai = LlmDispatcher::from_config(make_config(
            ProviderType::OpenAiCompatible,
            Some("sk-x"),
            None,
        ));
        assert!(openai.supports_tool_calling());
        let groq = LlmDispatcher::from_config(make_config(ProviderType::Groq, Some("gsk-x"), None));
        assert!(groq.supports_tool_calling());
        // SRE R4: Anthropic도 네이티브 tool-calling 지원(read-only 강등 제거).
        let anthropic =
            LlmDispatcher::from_config(make_config(ProviderType::Anthropic, Some("sk-ant"), None));
        assert!(anthropic.supports_tool_calling());
    }

    #[test]
    fn supports_tool_calling_false_for_cli() {
        let cli = LlmDispatcher::from_config(make_config(
            ProviderType::CliBackend,
            None,
            Some("/bin/echo"),
        ));
        assert!(!cli.supports_tool_calling());
    }

    #[test]
    fn redact_anthropic_content_masks_text_and_tool_result() {
        let mut msg = json!({
            "role": "user",
            "content": [
                { "type": "text", "text": "key sk-ant-abcdefghijklmnopqrstuvwxyz0123456789ABCD" },
                { "type": "tool_result", "tool_use_id": "t1", "content": "token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ" }
            ]
        });
        redact_anthropic_content(&mut msg);
        let text = msg["content"][0]["text"].as_str().unwrap();
        let tr = msg["content"][1]["content"].as_str().unwrap();
        assert!(text.contains("[REDACTED:"), "text not redacted: {text}");
        assert!(tr.contains("[REDACTED:"), "tool_result not redacted: {tr}");
    }

    #[tokio::test]
    async fn send_messages_unsupported_provider_errors() {
        use crate::agent::types::ChatMessage;
        // CliBackend는 tool-calling 미지원 — send_messages가 ConfigError로 폴백 유도.
        // (Anthropic은 R4부터 전용 경로로 지원되므로 더 이상 unsupported가 아니다.)
        let config = make_config(ProviderType::CliBackend, None, Some("/bin/echo"));
        let dispatcher = LlmDispatcher::from_config(config);
        let msgs = vec![ChatMessage::User("hi".to_string())];
        let err = dispatcher.send_messages(&msgs, &[]).await.unwrap_err();
        assert!(matches!(err, AicError::ConfigError(_)));
    }

    #[tokio::test]
    async fn send_messages_missing_api_key_errors() {
        use crate::agent::types::ChatMessage;
        let config = make_config(ProviderType::OpenAiCompatible, None, None);
        let dispatcher = LlmDispatcher::from_config(config);
        let msgs = vec![ChatMessage::User("hi".to_string())];
        let err = dispatcher.send_messages(&msgs, &[]).await.unwrap_err();
        assert!(matches!(err, AicError::ApiKeyMissing { .. }));
    }
}
