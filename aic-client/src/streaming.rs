//! OpenAI-compatible SSE streaming 파서.
//!
//! `data: {...}` 형식의 SSE event를 라인 단위로 파싱하고,
//! `choices[0].delta.content`를 추출하여 callback으로 전달한다.
//! `data: [DONE]` 수신 시 정상 종료, 그 외에는 partial 응답 그대로 반환.

use aic_common::AicError;
use futures::StreamExt;
use std::time::Duration;

/// OpenAI-compatible streaming endpoint를 호출하고 청크 단위로 callback 호출.
///
/// 반환값: 누적된 전체 응답 텍스트.
pub async fn stream_openai_compat<F>(
    client: &reqwest::Client,
    endpoint: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
    timeout: Duration,
    mut on_chunk: F,
) -> Result<String, AicError>
where
    F: FnMut(&str),
{
    let body = serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": prompt }],
        "stream": true,
    });

    let resp = client
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

    let status = resp.status().as_u16();
    if !(200..=299).contains(&status) {
        return Err(AicError::LlmApiError {
            status,
            message: format!("HTTP {status}"),
        });
    }

    let mut stream = resp.bytes_stream();
    let mut buffer = Vec::<u8>::new();
    let mut full = String::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: e.to_string(),
        })?;
        buffer.extend_from_slice(&chunk);

        while let Some((pos, advance)) = find_event_boundary(&buffer) {
            let event_bytes: Vec<u8> = buffer.drain(..pos + advance).collect();
            if let Some(result) = process_openai_event(&event_bytes, &mut on_chunk, &mut full) {
                return result;
            }
        }
    }

    // C4 fix: stream 종료 후 buffer 잔존 처리 (boundary 없이 끝난 마지막 event)
    if !buffer.is_empty() {
        if let Some(result) = process_openai_event(&buffer, &mut on_chunk, &mut full) {
            return result;
        }
    }

    Ok(full)
}

fn process_openai_event<F: FnMut(&str)>(
    event_bytes: &[u8],
    on_chunk: &mut F,
    full: &mut String,
) -> Option<Result<String, AicError>> {
    for line in event_bytes.split(|&b| b == b'\n') {
        let line = trim_trailing_cr(line);
        if let Some(data) = strip_data_prefix(line) {
            if data.is_empty() {
                continue;
            }
            if data == b"[DONE]" {
                return Some(Ok(full.clone()));
            }
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
                // C4 fix: API error mid-stream 처리
                if let Some(err_obj) = json.get("error") {
                    let msg = err_obj
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    return Some(Err(AicError::LlmApiError {
                        status: 0,
                        message: format!("API error: {msg}"),
                    }));
                }
                if let Some(content) = json["choices"][0]["delta"]["content"].as_str() {
                    on_chunk(content);
                    full.push_str(content);
                }
            }
        }
    }
    None
}

/// Anthropic streaming endpoint (`/v1/messages` with `stream: true`).
///
/// SSE event types:
/// - `content_block_delta` — `delta.text` 추출
/// - `message_stop` — 정상 종료
pub async fn stream_anthropic<F>(
    client: &reqwest::Client,
    endpoint: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
    timeout: Duration,
    mut on_chunk: F,
) -> Result<String, AicError>
where
    F: FnMut(&str),
{
    let body = serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": prompt }],
        "max_tokens": 4096,
        "stream": true,
    });

    let resp = client
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

    let status = resp.status().as_u16();
    if !(200..=299).contains(&status) {
        return Err(AicError::LlmApiError {
            status,
            message: format!("HTTP {status}"),
        });
    }

    let mut stream = resp.bytes_stream();
    let mut buffer = Vec::<u8>::new();
    let mut full = String::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: e.to_string(),
        })?;
        buffer.extend_from_slice(&chunk);

        while let Some((pos, advance)) = find_event_boundary(&buffer) {
            let event_bytes: Vec<u8> = buffer.drain(..pos + advance).collect();
            if let Some(result) = process_anthropic_event(&event_bytes, &mut on_chunk, &mut full) {
                return result;
            }
        }
    }

    // C4 fix: stream 종료 후 buffer 잔존 처리
    if !buffer.is_empty() {
        if let Some(result) = process_anthropic_event(&buffer, &mut on_chunk, &mut full) {
            return result;
        }
    }

    Ok(full)
}

fn process_anthropic_event<F: FnMut(&str)>(
    event_bytes: &[u8],
    on_chunk: &mut F,
    full: &mut String,
) -> Option<Result<String, AicError>> {
    for line in event_bytes.split(|&b| b == b'\n') {
        let line = trim_trailing_cr(line);
        if let Some(data) = strip_data_prefix(line) {
            if data.is_empty() {
                continue;
            }
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
                let event_type = json["type"].as_str().unwrap_or("");
                if event_type == "content_block_delta" {
                    if let Some(text) = json["delta"]["text"].as_str() {
                        on_chunk(text);
                        full.push_str(text);
                    }
                } else if event_type == "message_stop" {
                    return Some(Ok(full.clone()));
                } else if event_type == "error" {
                    // C4 fix: error event 명시적 처리
                    let msg = json["error"]["message"]
                        .as_str()
                        .unwrap_or("unknown anthropic error");
                    return Some(Err(AicError::LlmApiError {
                        status: 0,
                        message: format!("Anthropic API error: {msg}"),
                    }));
                }
            }
        }
    }
    None
}

/// SSE event boundary 위치를 찾는다. `\r\n\r\n` (CRLF), `\n\n` (LF), `\r\r` (legacy CR) 모두 지원.
/// 반환값: (event 끝 위치, drain할 총 바이트 수)
fn find_event_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((p, 4));
    }
    if let Some(p) = buf.windows(2).position(|w| w == b"\n\n" || w == b"\r\r") {
        return Some((p, 2));
    }
    None
}

fn trim_trailing_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn strip_data_prefix(line: &[u8]) -> Option<&[u8]> {
    line.strip_prefix(b"data: ")
        .or_else(|| line.strip_prefix(b"data:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_lf_event_boundary() {
        assert_eq!(find_event_boundary(b"abc\n\ndef"), Some((3, 2)));
        assert_eq!(find_event_boundary(b"abc\ndef"), None);
        assert_eq!(find_event_boundary(b"\n\n"), Some((0, 2)));
    }

    #[test]
    fn finds_crlf_event_boundary() {
        // C4 fix: CRLF proxy 환경 (CloudFlare 등) 지원
        assert_eq!(find_event_boundary(b"abc\r\n\r\ndef"), Some((3, 4)));
        assert_eq!(find_event_boundary(b"\r\n\r\n"), Some((0, 4)));
    }

    #[test]
    fn finds_legacy_cr_event_boundary() {
        assert_eq!(find_event_boundary(b"abc\r\rdef"), Some((3, 2)));
    }

    #[test]
    fn strips_data_prefix_with_space() {
        assert_eq!(strip_data_prefix(b"data: hello"), Some(b"hello".as_ref()));
    }

    #[test]
    fn strips_data_prefix_without_space() {
        assert_eq!(strip_data_prefix(b"data:hello"), Some(b"hello".as_ref()));
    }

    #[test]
    fn strip_data_prefix_returns_none_for_other() {
        assert_eq!(strip_data_prefix(b"event: ping"), None);
        assert_eq!(strip_data_prefix(b""), None);
    }

    #[test]
    fn trim_trailing_cr_removes_carriage_return() {
        assert_eq!(trim_trailing_cr(b"hello\r"), b"hello");
        assert_eq!(trim_trailing_cr(b"hello"), b"hello");
        assert_eq!(trim_trailing_cr(b""), b"");
    }

    #[test]
    fn process_openai_event_returns_done() {
        let mut full = String::new();
        let mut on_chunk = |_: &str| {};
        let result = process_openai_event(b"data: [DONE]\n", &mut on_chunk, &mut full);
        assert!(matches!(result, Some(Ok(_))));
    }

    #[test]
    fn process_openai_event_returns_error_on_api_error() {
        let mut full = String::new();
        let mut on_chunk = |_: &str| {};
        let event = br#"data: {"error":{"message":"rate limit"}}"#;
        let result = process_openai_event(event, &mut on_chunk, &mut full);
        match result {
            Some(Err(AicError::LlmApiError { message, .. })) => {
                assert!(message.contains("rate limit"));
            }
            other => panic!("expected LlmApiError, got {other:?}"),
        }
    }

    #[test]
    fn process_anthropic_event_handles_error_type() {
        let mut full = String::new();
        let mut on_chunk = |_: &str| {};
        let event = br#"data: {"type":"error","error":{"message":"overloaded"}}"#;
        let result = process_anthropic_event(event, &mut on_chunk, &mut full);
        match result {
            Some(Err(AicError::LlmApiError { message, .. })) => {
                assert!(message.contains("overloaded"));
            }
            other => panic!("expected LlmApiError, got {other:?}"),
        }
    }

    #[test]
    fn process_openai_event_extracts_content_with_crlf() {
        let mut full = String::new();
        let mut chunks = Vec::new();
        let mut on_chunk = |c: &str| chunks.push(c.to_string());
        let event = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\r";
        process_openai_event(event, &mut on_chunk, &mut full);
        assert_eq!(chunks, vec!["Hi"]);
        assert_eq!(full, "Hi");
    }
}
