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

// ── agent 루프용 streaming (messages + tools) ─────────────────────────────
//
// REPL용 stream_openai_compat/stream_anthropic은 단일 prompt·텍스트만 다룬다. agent chat은 (1) 메시지
// 히스토리+tools 요청이고 (2) tool_calls를 SSE delta에서 재조립해야 한다. 요청 빌드(auth·redaction·
// body)는 dispatcher가 하고, 여기서는 이미 보낸 응답의 byte stream을 받아 텍스트는 on_chunk로 라이브
// 전달하며 tool_calls를 누적해 `ChatResponse`로 끝맺는다.

use crate::agent::types::{ChatResponse, ToolCall};
use std::collections::BTreeMap;

/// 스트리밍 중 조립되는 tool call(인자는 fragment로 도착해 이어붙인다).
#[derive(Default)]
struct ToolCallBuilder {
    id: String,
    name: String,
    args: String,
}

/// 누적 텍스트 + 조립된 tool_calls를 최종 `ChatResponse`로. tool_calls가 하나라도 있으면 ToolCalls,
/// 아니면 Text. 인자가 빈 tool은 `{}`로 채워 파서가 깨지지 않게 한다.
fn finish_response(text: String, tools: Vec<ToolCallBuilder>) -> ChatResponse {
    let calls: Vec<ToolCall> = tools
        .into_iter()
        .filter(|t| !t.name.is_empty())
        .map(|t| ToolCall {
            id: t.id,
            name: t.name,
            arguments: if t.args.trim().is_empty() {
                "{}".to_string()
            } else {
                t.args
            },
        })
        .collect();
    if calls.is_empty() {
        ChatResponse::Text(text)
    } else {
        ChatResponse::ToolCalls(calls)
    }
}

/// OpenAI-compatible streaming 응답을 누적한다. 텍스트 delta는 on_chunk로 라이브 전달하고,
/// `delta.tool_calls[]`를 index별로 재조립한다(id·name은 첫 fragment, arguments는 이어붙임).
pub async fn accumulate_openai_stream<F>(
    resp: reqwest::Response,
    mut on_chunk: F,
) -> Result<ChatResponse, AicError>
where
    F: FnMut(&str),
{
    let mut stream = resp.bytes_stream();
    let mut buffer = Vec::<u8>::new();
    let mut text = String::new();
    let mut tools: Vec<ToolCallBuilder> = Vec::new();
    let mut done = false;
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: e.to_string(),
        })?;
        buffer.extend_from_slice(&chunk);
        while let Some((pos, advance)) = find_event_boundary(&buffer) {
            let event_bytes: Vec<u8> = buffer.drain(..pos + advance).collect();
            if process_openai_stream_event(&event_bytes, &mut on_chunk, &mut text, &mut tools)? {
                done = true;
                break;
            }
        }
        if done {
            break;
        }
    }
    if !done && !buffer.is_empty() {
        process_openai_stream_event(&buffer, &mut on_chunk, &mut text, &mut tools)?;
    }
    Ok(finish_response(text, tools))
}

/// 한 SSE event를 처리한다. `[DONE]`이면 Ok(true)(종료), 오류면 Err.
fn process_openai_stream_event<F: FnMut(&str)>(
    event_bytes: &[u8],
    on_chunk: &mut F,
    text: &mut String,
    tools: &mut Vec<ToolCallBuilder>,
) -> Result<bool, AicError> {
    for line in event_bytes.split(|&b| b == b'\n') {
        let line = trim_trailing_cr(line);
        let Some(data) = strip_data_prefix(line) else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        if data == b"[DONE]" {
            return Ok(true);
        }
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            continue;
        };
        if let Some(err) = json.get("error") {
            let msg = err.get("message").and_then(|v| v.as_str()).unwrap_or("unknown");
            return Err(AicError::LlmApiError {
                status: 0,
                message: format!("API error: {msg}"),
            });
        }
        let delta = &json["choices"][0]["delta"];
        if let Some(content) = delta["content"].as_str() {
            if !content.is_empty() {
                on_chunk(content);
                text.push_str(content);
            }
        }
        if let Some(tcs) = delta["tool_calls"].as_array() {
            for tc in tcs {
                let idx = tc["index"].as_u64().unwrap_or(0) as usize;
                while tools.len() <= idx {
                    tools.push(ToolCallBuilder::default());
                }
                let b = &mut tools[idx];
                if let Some(id) = tc["id"].as_str() {
                    if !id.is_empty() {
                        b.id = id.to_string();
                    }
                }
                if let Some(name) = tc["function"]["name"].as_str() {
                    if !name.is_empty() {
                        b.name = name.to_string();
                    }
                }
                if let Some(args) = tc["function"]["arguments"].as_str() {
                    b.args.push_str(args);
                }
            }
        }
    }
    Ok(false)
}

/// Anthropic streaming 응답을 누적한다. `text_delta`는 라이브 전달, `tool_use` 블록은
/// content_block_start(id·name) + input_json_delta(partial_json)로 재조립한다.
pub async fn accumulate_anthropic_stream<F>(
    resp: reqwest::Response,
    mut on_chunk: F,
) -> Result<ChatResponse, AicError>
where
    F: FnMut(&str),
{
    let mut stream = resp.bytes_stream();
    let mut buffer = Vec::<u8>::new();
    let mut text = String::new();
    // content block index → tool builder(tool_use 블록만). 순서 보존 위해 BTreeMap.
    let mut tools: BTreeMap<usize, ToolCallBuilder> = BTreeMap::new();
    let mut done = false;
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| AicError::LlmApiError {
            status: 0,
            message: e.to_string(),
        })?;
        buffer.extend_from_slice(&chunk);
        while let Some((pos, advance)) = find_event_boundary(&buffer) {
            let event_bytes: Vec<u8> = buffer.drain(..pos + advance).collect();
            if process_anthropic_stream_event(&event_bytes, &mut on_chunk, &mut text, &mut tools)? {
                done = true;
                break;
            }
        }
        if done {
            break;
        }
    }
    if !done && !buffer.is_empty() {
        process_anthropic_stream_event(&buffer, &mut on_chunk, &mut text, &mut tools)?;
    }
    Ok(finish_response(text, tools.into_values().collect()))
}

fn process_anthropic_stream_event<F: FnMut(&str)>(
    event_bytes: &[u8],
    on_chunk: &mut F,
    text: &mut String,
    tools: &mut BTreeMap<usize, ToolCallBuilder>,
) -> Result<bool, AicError> {
    for line in event_bytes.split(|&b| b == b'\n') {
        let line = trim_trailing_cr(line);
        let Some(data) = strip_data_prefix(line) else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            continue;
        };
        match json["type"].as_str().unwrap_or("") {
            "content_block_start" => {
                let idx = json["index"].as_u64().unwrap_or(0) as usize;
                let cb = &json["content_block"];
                if cb["type"].as_str() == Some("tool_use") {
                    tools.insert(
                        idx,
                        ToolCallBuilder {
                            id: cb["id"].as_str().unwrap_or("").to_string(),
                            name: cb["name"].as_str().unwrap_or("").to_string(),
                            args: String::new(),
                        },
                    );
                }
            }
            "content_block_delta" => {
                let d = &json["delta"];
                match d["type"].as_str().unwrap_or("") {
                    "text_delta" => {
                        if let Some(t) = d["text"].as_str() {
                            if !t.is_empty() {
                                on_chunk(t);
                                text.push_str(t);
                            }
                        }
                    }
                    "input_json_delta" => {
                        let idx = json["index"].as_u64().unwrap_or(0) as usize;
                        if let Some(p) = d["partial_json"].as_str() {
                            tools.entry(idx).or_default().args.push_str(p);
                        }
                    }
                    _ => {}
                }
            }
            "message_stop" => return Ok(true),
            "error" => {
                let msg = json["error"]["message"]
                    .as_str()
                    .unwrap_or("unknown anthropic error");
                return Err(AicError::LlmApiError {
                    status: 0,
                    message: format!("Anthropic API error: {msg}"),
                });
            }
            _ => {}
        }
    }
    Ok(false)
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

    // ── agent-loop streaming (messages+tools) 재조립 테스트 ────────────────

    #[test]
    fn openai_stream_reassembles_tool_call() {
        let mut text = String::new();
        let mut tools = Vec::new();
        let mut on_chunk = |_: &str| {};
        // index 0: id·name + arguments 시작 fragment.
        process_openai_stream_event(
            br#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read_file","arguments":"{\"path\":"}}]}}]}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        // arguments 이어붙임 fragment(id·name 생략).
        process_openai_stream_event(
            br#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a.txt\"}"}}]}}]}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        assert!(process_openai_stream_event(b"data: [DONE]", &mut on_chunk, &mut text, &mut tools).unwrap());
        match finish_response(text, tools) {
            ChatResponse::ToolCalls(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].id, "call_1");
                assert_eq!(c[0].name, "read_file");
                assert_eq!(c[0].arguments, r#"{"path":"a.txt"}"#);
            }
            other => panic!("expected ToolCalls, got {other:?}"),
        }
    }

    #[test]
    fn openai_stream_text_only_streams_live() {
        let mut text = String::new();
        let mut tools = Vec::new();
        let mut chunks = Vec::new();
        let mut on_chunk = |c: &str| chunks.push(c.to_string());
        process_openai_stream_event(
            br#"data: {"choices":[{"delta":{"content":"Hel"}}]}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        process_openai_stream_event(
            br#"data: {"choices":[{"delta":{"content":"lo"}}]}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        assert_eq!(chunks, vec!["Hel", "lo"]);
        assert_eq!(finish_response(text, tools), ChatResponse::Text("Hello".to_string()));
    }

    #[test]
    fn anthropic_stream_reassembles_tool_use() {
        let mut text = String::new();
        let mut tools = BTreeMap::new();
        let mut on_chunk = |_: &str| {};
        process_anthropic_stream_event(
            br#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"grep"}}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        process_anthropic_stream_event(
            br#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"q\":"}}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        process_anthropic_stream_event(
            br#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"x\"}"}}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        assert!(process_anthropic_stream_event(br#"data: {"type":"message_stop"}"#, &mut on_chunk, &mut text, &mut tools).unwrap());
        match finish_response(text, tools.into_values().collect()) {
            ChatResponse::ToolCalls(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].id, "toolu_1");
                assert_eq!(c[0].name, "grep");
                assert_eq!(c[0].arguments, r#"{"q":"x"}"#);
            }
            other => panic!("expected ToolCalls, got {other:?}"),
        }
    }

    #[test]
    fn anthropic_stream_text_delta_live() {
        let mut text = String::new();
        let mut tools = BTreeMap::new();
        let mut chunks = Vec::new();
        let mut on_chunk = |c: &str| chunks.push(c.to_string());
        process_anthropic_stream_event(
            br#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi "}}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        process_anthropic_stream_event(
            br#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"there"}}"#,
            &mut on_chunk, &mut text, &mut tools).unwrap();
        assert_eq!(chunks, vec!["Hi ", "there"]);
        assert_eq!(finish_response(text, tools.into_values().collect()), ChatResponse::Text("Hi there".to_string()));
    }

    #[test]
    fn finish_response_empty_args_becomes_braces() {
        let tools = vec![ToolCallBuilder { id: "c".into(), name: "noargs".into(), args: String::new() }];
        match finish_response(String::new(), tools) {
            ChatResponse::ToolCalls(c) => assert_eq!(c[0].arguments, "{}"),
            other => panic!("expected ToolCalls, got {other:?}"),
        }
    }
}
