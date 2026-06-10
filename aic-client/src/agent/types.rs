//! agent 메시지/도구 타입 + OpenAI function-calling wire 직렬화.
//!
//! 이 모듈은 순수 데이터/직렬화만 담당한다(I/O·네트워크 없음). OpenAI
//! chat-completions 규약에 1:1로 대응하며, 단위 테스트로 라운드트립을 검증한다.

use serde_json::{json, Value};

/// multi-turn 대화 메시지. OpenAI chat-completions role 모델에 대응한다.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatMessage {
    /// system role — 역할/행동 지시.
    System(String),
    /// user role — 사용자 입력.
    User(String),
    /// assistant role — 모델 응답. tool_calls만 있을 때 content는 None(null).
    Assistant {
        content: Option<String>,
        tool_calls: Vec<ToolCall>,
    },
    /// tool role — 도구 실행 결과를 `tool_call_id`로 회신.
    Tool { call_id: String, content: String },
}

/// LLM이 요청한 도구 호출. `arguments`는 OpenAI 규약대로 JSON "문자열"이며,
/// 실제 파싱은 도구 실행 직전에 한다(잘못된 JSON도 tool 에러로 흡수하기 위함).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// LLM에 노출할 도구 스펙. `parameters`는 JSON Schema.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters: Value,
}

/// `send_messages` 응답: 텍스트 종료 또는 도구 호출 요청.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatResponse {
    Text(String),
    ToolCalls(Vec<ToolCall>),
}

impl ChatMessage {
    /// OpenAI chat-completions message wire format으로 직렬화한다.
    pub fn to_openai_json(&self) -> Value {
        match self {
            ChatMessage::System(c) => json!({ "role": "system", "content": c }),
            ChatMessage::User(c) => json!({ "role": "user", "content": c }),
            ChatMessage::Assistant {
                content,
                tool_calls,
            } => {
                let mut m = json!({ "role": "assistant" });
                // tool_calls만 있는 경우 content는 null로 직렬화한다.
                m["content"] = match content {
                    Some(c) => json!(c),
                    None => Value::Null,
                };
                if !tool_calls.is_empty() {
                    m["tool_calls"] =
                        Value::Array(tool_calls.iter().map(ToolCall::to_openai_json).collect());
                }
                m
            }
            ChatMessage::Tool { call_id, content } => {
                json!({ "role": "tool", "tool_call_id": call_id, "content": content })
            }
        }
    }
}

impl ToolCall {
    /// assistant 메시지의 `tool_calls[]` 항목으로 직렬화한다.
    pub fn to_openai_json(&self) -> Value {
        json!({
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": self.arguments,
            }
        })
    }
}

impl ToolSpec {
    /// 요청 body의 `tools[]` 항목으로 직렬화한다.
    pub fn to_openai_json(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters.clone(),
            }
        })
    }

    /// Anthropic Messages API `tools[]` 항목으로 직렬화한다(SRE R4).
    /// OpenAI의 `function.parameters`와 달리 `input_schema`를 쓴다. JSON Schema는 동일.
    pub fn to_anthropic_json(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters.clone(),
        })
    }
}

/// ChatMessage 목록을 Anthropic Messages API 요청용 `(system, messages)`로 변환한다(SRE R4).
///
/// OpenAI와의 차이를 흡수한다:
/// - System은 메시지가 아니라 top-level `system` 필드다(여러 개면 join).
/// - tool 결과는 `tool` role이 아니라 **user role의 `tool_result` content 블록**이다.
/// - assistant의 tool 호출은 `tool_use` content 블록이며 `input`은 (문자열이 아닌) 객체다.
/// - 연속된 user 성격(User 텍스트 + Tool 결과)은 하나의 user 메시지로 병합한다(role 교차 규칙).
pub fn to_anthropic_request(messages: &[ChatMessage]) -> (Option<String>, Vec<Value>) {
    let mut system_parts: Vec<String> = Vec::new();
    let mut out: Vec<Value> = Vec::new();
    let mut pending_user: Vec<Value> = Vec::new();

    fn flush_user(pending: &mut Vec<Value>, out: &mut Vec<Value>) {
        if !pending.is_empty() {
            out.push(json!({ "role": "user", "content": std::mem::take(pending) }));
        }
    }

    for m in messages {
        match m {
            ChatMessage::System(c) => system_parts.push(c.clone()),
            ChatMessage::User(c) => {
                pending_user.push(json!({ "type": "text", "text": c }));
            }
            ChatMessage::Tool { call_id, content } => {
                pending_user.push(json!({
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": content,
                }));
            }
            ChatMessage::Assistant {
                content,
                tool_calls,
            } => {
                flush_user(&mut pending_user, &mut out);
                let mut blocks: Vec<Value> = Vec::new();
                if let Some(c) = content {
                    if !c.is_empty() {
                        blocks.push(json!({ "type": "text", "text": c }));
                    }
                }
                for tc in tool_calls {
                    // arguments(JSON 문자열) → input(객체). 파싱 실패 시 빈 객체.
                    let input: Value = serde_json::from_str(&tc.arguments).unwrap_or(json!({}));
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": input,
                    }));
                }
                out.push(json!({ "role": "assistant", "content": blocks }));
            }
        }
    }
    flush_user(&mut pending_user, &mut out);
    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    (system, out)
}

/// Anthropic Messages API 응답에서 `ChatResponse`를 파싱한다(SRE R4).
///
/// `content[]`에 `tool_use` 블록이 있으면 [`ChatResponse::ToolCalls`](각 `input` 객체를
/// OpenAI 호환 arguments JSON 문자열로 변환), 없으면 `text` 블록을 합쳐 [`ChatResponse::Text`].
pub fn parse_anthropic_response(json: &Value) -> Option<ChatResponse> {
    let content = json.get("content")?.as_array()?;
    let mut calls: Vec<ToolCall> = Vec::new();
    let mut text = String::new();
    for block in content {
        match block.get("type").and_then(|v| v.as_str()) {
            Some("tool_use") => {
                let id = block
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = block.get("name").and_then(|v| v.as_str())?.to_string();
                let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
                let arguments = serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string());
                calls.push(ToolCall {
                    id,
                    name,
                    arguments,
                });
            }
            Some("text") => {
                if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                    text.push_str(t);
                }
            }
            _ => {}
        }
    }
    if !calls.is_empty() {
        return Some(ChatResponse::ToolCalls(calls));
    }
    Some(ChatResponse::Text(text))
}

/// OpenAI chat-completions 응답에서 `ChatResponse`를 파싱한다.
///
/// `choices[0].message`에 `tool_calls`가 있으면 [`ChatResponse::ToolCalls`],
/// 없으면 `content` 텍스트를 [`ChatResponse::Text`]로 돌려준다.
/// 구조가 예상과 다르면 `None`.
pub fn parse_openai_response(json: &Value) -> Option<ChatResponse> {
    let message = json.get("choices")?.get(0)?.get("message")?;

    if let Some(arr) = message.get("tool_calls").and_then(|v| v.as_array()) {
        let calls: Vec<ToolCall> = arr.iter().filter_map(parse_tool_call).collect();
        if !calls.is_empty() {
            return Some(ChatResponse::ToolCalls(calls));
        }
    }

    let content = message
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some(ChatResponse::Text(content))
}

/// 응답의 단일 `tool_calls[]` 항목을 [`ToolCall`]로 파싱한다.
fn parse_tool_call(v: &Value) -> Option<ToolCall> {
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let func = v.get("function")?;
    let name = func.get("name").and_then(|x| x.as_str())?.to_string();
    // arguments 누락 시 빈 객체로 — 실행 직전 파싱 단계에서 처리.
    let arguments = func
        .get("arguments")
        .and_then(|x| x.as_str())
        .unwrap_or("{}")
        .to_string();
    Some(ToolCall {
        id,
        name,
        arguments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_message_serializes_role_and_content() {
        let m = ChatMessage::System("be nice".to_string());
        let j = m.to_openai_json();
        assert_eq!(j["role"], "system");
        assert_eq!(j["content"], "be nice");
    }

    #[test]
    fn user_message_serializes() {
        let m = ChatMessage::User("hello".to_string());
        let j = m.to_openai_json();
        assert_eq!(j["role"], "user");
        assert_eq!(j["content"], "hello");
    }

    #[test]
    fn assistant_with_tool_calls_has_null_content_and_tool_calls() {
        let m = ChatMessage::Assistant {
            content: None,
            tool_calls: vec![ToolCall {
                id: "call_1".to_string(),
                name: "read_file".to_string(),
                arguments: "{\"path\":\"a.txt\"}".to_string(),
            }],
        };
        let j = m.to_openai_json();
        assert_eq!(j["role"], "assistant");
        assert!(j["content"].is_null());
        assert_eq!(j["tool_calls"][0]["id"], "call_1");
        assert_eq!(j["tool_calls"][0]["type"], "function");
        assert_eq!(j["tool_calls"][0]["function"]["name"], "read_file");
        assert_eq!(
            j["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"a.txt\"}"
        );
    }

    #[test]
    fn assistant_text_only_has_no_tool_calls_field() {
        let m = ChatMessage::Assistant {
            content: Some("done".to_string()),
            tool_calls: vec![],
        };
        let j = m.to_openai_json();
        assert_eq!(j["content"], "done");
        assert!(j.get("tool_calls").is_none());
    }

    #[test]
    fn tool_message_uses_tool_call_id() {
        let m = ChatMessage::Tool {
            call_id: "call_9".to_string(),
            content: "result".to_string(),
        };
        let j = m.to_openai_json();
        assert_eq!(j["role"], "tool");
        assert_eq!(j["tool_call_id"], "call_9");
        assert_eq!(j["content"], "result");
    }

    #[test]
    fn tool_spec_serializes_as_function() {
        let spec = ToolSpec {
            name: "grep",
            description: "search",
            parameters: json!({"type": "object"}),
        };
        let j = spec.to_openai_json();
        assert_eq!(j["type"], "function");
        assert_eq!(j["function"]["name"], "grep");
        assert_eq!(j["function"]["description"], "search");
        assert_eq!(j["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn parse_response_text() {
        let j = json!({
            "choices": [{ "message": { "role": "assistant", "content": "hi there" } }]
        });
        assert_eq!(
            parse_openai_response(&j),
            Some(ChatResponse::Text("hi there".to_string()))
        );
    }

    #[test]
    fn parse_response_tool_calls() {
        let j = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "read_file", "arguments": "{\"path\":\"x\"}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        match parse_openai_response(&j) {
            Some(ChatResponse::ToolCalls(calls)) => {
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].id, "call_1");
                assert_eq!(calls[0].name, "read_file");
                assert_eq!(calls[0].arguments, "{\"path\":\"x\"}");
            }
            other => panic!("expected ToolCalls, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_empty_tool_calls_falls_back_to_text() {
        let j = json!({
            "choices": [{ "message": { "content": "fallback", "tool_calls": [] } }]
        });
        assert_eq!(
            parse_openai_response(&j),
            Some(ChatResponse::Text("fallback".to_string()))
        );
    }

    #[test]
    fn parse_response_missing_choices_is_none() {
        let j = json!({ "error": "boom" });
        assert_eq!(parse_openai_response(&j), None);
    }

    // ── Anthropic wire (SRE R4) ───────────────────────────────

    #[test]
    fn tool_spec_anthropic_uses_input_schema() {
        let spec = ToolSpec {
            name: "grep",
            description: "search",
            parameters: json!({ "type": "object", "properties": {} }),
        };
        let j = spec.to_anthropic_json();
        assert_eq!(j["name"], "grep");
        assert_eq!(j["description"], "search");
        assert_eq!(j["input_schema"]["type"], "object");
        assert!(j.get("function").is_none(), "Anthropic은 function 래퍼 없음");
    }

    #[test]
    fn anthropic_request_extracts_system_and_builds_messages() {
        let msgs = vec![
            ChatMessage::System("be terse".to_string()),
            ChatMessage::User("hi".to_string()),
        ];
        let (system, messages) = to_anthropic_request(&msgs);
        assert_eq!(system.as_deref(), Some("be terse"));
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"][0]["type"], "text");
        assert_eq!(messages[0]["content"][0]["text"], "hi");
    }

    #[test]
    fn anthropic_request_tool_use_and_result_blocks() {
        // assistant tool_use → user tool_result. arguments(문자열)는 input(객체)로.
        let msgs = vec![
            ChatMessage::User("check disk".to_string()),
            ChatMessage::Assistant {
                content: None,
                tool_calls: vec![ToolCall {
                    id: "tu_1".to_string(),
                    name: "run_command".to_string(),
                    arguments: "{\"command\":\"df -h\"}".to_string(),
                }],
            },
            ChatMessage::Tool {
                call_id: "tu_1".to_string(),
                content: "Filesystem 50%".to_string(),
            },
        ];
        let (_system, messages) = to_anthropic_request(&msgs);
        assert_eq!(messages.len(), 3);
        // assistant tool_use
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"][0]["type"], "tool_use");
        assert_eq!(messages[1]["content"][0]["id"], "tu_1");
        assert_eq!(messages[1]["content"][0]["input"]["command"], "df -h");
        // user tool_result
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(messages[2]["content"][0]["type"], "tool_result");
        assert_eq!(messages[2]["content"][0]["tool_use_id"], "tu_1");
        assert_eq!(messages[2]["content"][0]["content"], "Filesystem 50%");
    }

    #[test]
    fn anthropic_request_merges_consecutive_user_blocks() {
        // 병렬 tool 결과 2개는 하나의 user 메시지로 병합(role 교차 규칙).
        let msgs = vec![
            ChatMessage::Tool {
                call_id: "a".to_string(),
                content: "ra".to_string(),
            },
            ChatMessage::Tool {
                call_id: "b".to_string(),
                content: "rb".to_string(),
            },
        ];
        let (_s, messages) = to_anthropic_request(&msgs);
        assert_eq!(messages.len(), 1, "연속 user는 1개로 병합");
        assert_eq!(messages[0]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn parse_anthropic_text_response() {
        let j = json!({
            "type": "message",
            "content": [{ "type": "text", "text": "hello" }]
        });
        assert_eq!(
            parse_anthropic_response(&j),
            Some(ChatResponse::Text("hello".to_string()))
        );
    }

    #[test]
    fn parse_anthropic_tool_use_response() {
        let j = json!({
            "type": "message",
            "stop_reason": "tool_use",
            "content": [
                { "type": "text", "text": "checking" },
                { "type": "tool_use", "id": "tu_9", "name": "run_command", "input": { "command": "ps aux" } }
            ]
        });
        match parse_anthropic_response(&j) {
            Some(ChatResponse::ToolCalls(calls)) => {
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].id, "tu_9");
                assert_eq!(calls[0].name, "run_command");
                // input 객체 → arguments JSON 문자열.
                let args: Value = serde_json::from_str(&calls[0].arguments).unwrap();
                assert_eq!(args["command"], "ps aux");
            }
            other => panic!("expected ToolCalls, got {other:?}"),
        }
    }

    #[test]
    fn anthropic_round_trip_tool_call() {
        // 응답 tool_use → ToolCall → 다음 요청 assistant tool_use 블록 동일 input.
        let resp = json!({
            "content": [{ "type": "tool_use", "id": "x", "name": "grep", "input": { "pattern": "err" } }]
        });
        let ChatResponse::ToolCalls(calls) = parse_anthropic_response(&resp).unwrap() else {
            panic!("expected ToolCalls");
        };
        let msg = ChatMessage::Assistant {
            content: None,
            tool_calls: calls,
        };
        let (_s, messages) = to_anthropic_request(&[msg]);
        assert_eq!(messages[0]["content"][0]["input"]["pattern"], "err");
    }

    #[test]
    fn tool_call_round_trip_through_json() {
        // ToolCall → wire JSON → re-parse 동일성(메시지 1건 응답으로 재구성).
        let original = ToolCall {
            id: "call_rt".to_string(),
            name: "list_dir".to_string(),
            arguments: "{\"path\":\".\"}".to_string(),
        };
        let wire = json!({
            "choices": [{
                "message": { "content": null, "tool_calls": [original.to_openai_json()] }
            }]
        });
        match parse_openai_response(&wire) {
            Some(ChatResponse::ToolCalls(calls)) => assert_eq!(calls[0], original),
            other => panic!("expected ToolCalls, got {other:?}"),
        }
    }
}
