//! MCP(Model Context Protocol) 클라이언트 — config에 등록된 MCP 서버의 tool을 `aic chat`에 노출한다.
//!
//! 현재 transport는 **Streamable HTTP**(JSON-RPC를 POST, 응답은 `application/json` 또는 SSE)만 지원한다.
//! mem-mesh·sre-agent 같은 MCP 서버를 config `[mcp.servers.<name>]`로 등록하면, 세션 시작 시 핸드셰이크
//! (`initialize` → `notifications/initialized` → `tools/list`)로 tool을 발견해 LLM tool 목록에 합류시킨다.
//!
//! 보안 불변식(obs_tools와 동일 정책 재사용):
//! - **endpoint allowlist + SSRF 방어** — `ensure_safe_url`(http(s)만, link-local/metadata IP 차단).
//! - **bounded** — 응답 본문/출력을 cap으로 제한(`read_bounded`/`finalize`).
//! - **redaction** — tool 결과를 LLM에 넘기기 전 `finalize`로 secret/PII 마스킹 + 길이 cap.
//! - **변경 도구 confirm** — `auto_approve`에 없는 tool은 실행 전 사용자 확인(호출부 session에서 게이팅).
//! - **graceful degrade** — 연결/호출 실패는 해당 서버/도구만 비활성화하고 turn은 진행(절대 블로킹 안 함).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use super::obs_tools::{ensure_safe_url, finalize, read_bounded, truncate};
use super::tools::ToolError;
use super::types::ToolSpec;
use aic_common::McpConfig;

const CONNECT_TIMEOUT_SECS: u64 = 5;
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// 핸드셰이크(initialize/initialized/tools_list) 요청별 타임아웃 — tool 호출(30s)보다 짧게 둬, 응답이
/// 느린 서버가 chat startup을 길게 잡지 않게 한다.
const HANDSHAKE_TIMEOUT_SECS: u64 = 8;
/// 서버 1대 연결(핸드셰이크 전체)의 상한. 느린/무응답 서버가 startup을 묶지 않도록 connect를 wrap한다.
const CONNECT_OVERALL_SECS: u64 = 10;
/// tools/list 페이지네이션 안전 상한(무한 cursor 루프 방지).
const MAX_TOOL_PAGES: usize = 50;
/// 클라이언트가 제안하는 MCP 프로토콜 버전. 서버가 initialize 응답에서 다른 버전을 주면 그 값을 이후
/// 요청의 `MCP-Protocol-Version` 헤더로 echo한다(2025-06-18 streamable HTTP MUST).
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// 발견된 단일 MCP tool.
struct McpToolDef {
    /// 서버에서의 원래 이름(예: `search`). tools/call에 그대로 보낸다.
    name: String,
    /// LLM에 노출하는 namespaced 이름(예: `mem-mesh__search`). 내장 tool과 충돌을 막는다.
    /// `ToolSpec`이 `&'static str`을 요구해 연결 시 1회 leak한다(tool 수만큼, 프로세스 수명).
    full_name: &'static str,
    /// LLM용 설명(leak, 위와 동일 이유).
    description: &'static str,
    /// JSON Schema(`inputSchema`). ToolSpec.parameters로 그대로 쓴다.
    input_schema: Value,
}

/// 등록된 단일 MCP 서버(연결 상태 포함).
struct McpServer {
    name: String,
    url: String,
    auth: Option<String>,
    /// 확인 없이 자동 실행할 tool 원래 이름들. 그 외는 호출 전 confirm.
    auto_approve: HashSet<String>,
    /// initialize 응답의 `Mcp-Session-Id`(있으면 이후 요청에 echo).
    session_id: Option<String>,
    /// 협상된 프로토콜 버전(initialize 응답의 protocolVersion, 없으면 제안 버전). post-init 요청의
    /// `MCP-Protocol-Version` 헤더로 echo한다. None이면(=init 전) 헤더 미전송.
    protocol_version: Option<String>,
    /// JSON-RPC id 카운터(요청-응답 매칭용).
    next_id: AtomicU64,
    /// tools/list로 발견한 tool들(연결 실패 시 빈 채로 둔다 = degrade).
    tools: Vec<McpToolDef>,
}

/// config의 MCP 서버들을 묶은 클라이언트. read-only 도구는 자동, 변경 도구는 confirm 후 실행한다.
pub struct McpClient {
    http: reqwest::Client,
    servers: Vec<McpServer>,
}

impl McpClient {
    /// config `[mcp]`에서 클라이언트를 만든다. enabled 서버가 하나도 없으면 None(노출 0).
    /// URL은 obs와 동일한 SSRF 방어를 통과해야 등록된다(부적합 URL은 경고 후 skip).
    pub fn new(cfg: &McpConfig) -> Option<Self> {
        let mut servers = Vec::new();
        for (name, sc) in &cfg.servers {
            if !sc.enabled {
                continue;
            }
            if let Err(e) = ensure_safe_url(&sc.url) {
                eprintln!("\x1b[33m⚠ MCP 서버 '{name}' URL 거부: {}\x1b[0m", e.message);
                continue;
            }
            servers.push(McpServer {
                name: name.clone(),
                url: sc.url.clone(),
                auth: sc.auth.clone(),
                auto_approve: sc.auto_approve.iter().cloned().collect(),
                session_id: None,
                protocol_version: None,
                next_id: AtomicU64::new(1),
                tools: Vec::new(),
            });
        }
        if servers.is_empty() {
            return None;
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .ok()?;
        Some(Self { http, servers })
    }

    /// 모든 서버에 핸드셰이크해 tool을 발견한다. 서버별로 독립 — 한 곳이 실패해도 나머지는 진행한다.
    /// 사용자에게 보여줄 요약 라인들을 반환한다(예: "mem-mesh: 12 tools", "x: 연결 실패 …").
    pub async fn connect(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        for server in &mut self.servers {
            // 서버 1대 핸드셰이크 전체를 CONNECT_OVERALL_SECS로 묶는다 — 무응답 서버가 startup을
            // 길게 잡지 못하게(요청별 타임아웃과 별개의 상한).
            let outcome = tokio::time::timeout(
                Duration::from_secs(CONNECT_OVERALL_SECS),
                connect_server(&self.http, server),
            )
            .await;
            match outcome {
                Ok(Ok(())) => {
                    notes.push(format!("MCP {}: {} tools", server.name, server.tools.len()))
                }
                Ok(Err(e)) => notes.push(format!("MCP {}: 연결 실패 — {}", server.name, e.message)),
                Err(_) => notes.push(format!(
                    "MCP {}: 연결 시간 초과({CONNECT_OVERALL_SECS}s) — 건너뜀",
                    server.name
                )),
            }
        }
        notes
    }

    /// LLM에 노출할 ToolSpec 목록(모든 서버의 발견된 tool).
    pub fn specs(&self) -> Vec<ToolSpec> {
        self.servers
            .iter()
            .flat_map(|s| {
                s.tools.iter().map(|t| ToolSpec {
                    name: t.full_name,
                    description: t.description,
                    parameters: t.input_schema.clone(),
                })
            })
            .collect()
    }

    /// 발견된 MCP tool 이름인가(namespaced full_name 기준).
    pub fn is_tool(&self, full_name: &str) -> bool {
        self.find(full_name).is_some()
    }

    /// 실행 전 사용자 확인이 필요한가. auto_approve에 있는 read-only tool은 false(자동), 그 외 true.
    /// 미등록 이름은 안전하게 true(확인 요구).
    pub fn needs_confirm(&self, full_name: &str) -> bool {
        match self.find(full_name) {
            Some((server, tool)) => !server.auto_approve.contains(&tool.name),
            None => true,
        }
    }

    /// tool을 호출한다(tools/call). 결과 content를 텍스트로 합쳐 redact + cap해서 반환한다.
    /// 서버가 isError를 표시하면 `[tool error] …`로 감싼다(turn은 계속 진행).
    pub async fn call(&self, full_name: &str, args: &Value) -> Result<String, ToolError> {
        let (server, tool) = self
            .find(full_name)
            .ok_or_else(|| ToolError::new(format!("미등록 MCP 도구: {full_name}")))?;
        // MCP tools/call의 arguments는 object여야 한다. 모델이 null/스칼라를 보내면 {}로 정규화한다.
        let arguments = if args.is_object() {
            args.clone()
        } else {
            json!({})
        };
        let params = json!({ "name": tool.name, "arguments": arguments });
        let result = post_rpc(&self.http, server, "tools/call", params, REQUEST_TIMEOUT_SECS).await?;
        let is_error = result.get("isError").and_then(Value::as_bool).unwrap_or(false);
        let text = finalize(&extract_content_text(&result));
        if is_error {
            Ok(format!("[tool error] {text}"))
        } else {
            Ok(text)
        }
    }

    fn find(&self, full_name: &str) -> Option<(&McpServer, &McpToolDef)> {
        self.servers.iter().find_map(|s| {
            s.tools
                .iter()
                .find(|t| t.full_name == full_name)
                .map(|t| (s, t))
        })
    }
}

// ── 서버 핸드셰이크 + JSON-RPC 전송(자유 함수 — self 借用 충돌 회피) ──────────

async fn connect_server(http: &reqwest::Client, server: &mut McpServer) -> Result<(), ToolError> {
    // initialize — 응답 헤더의 Mcp-Session-Id를 잡아 이후 요청에 echo.
    let init_params = json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": { "name": "aic", "version": env!("CARGO_PKG_VERSION") }
    });
    let (init, session_id) =
        post_rpc_with_session(http, server, "initialize", init_params, HANDSHAKE_TIMEOUT_SECS)
            .await?;
    server.session_id = session_id;
    // 협상된 프로토콜 버전을 잡아 이후 요청 헤더로 echo한다(서버가 안 주면 우리가 제안한 버전).
    server.protocol_version = Some(
        init.get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(MCP_PROTOCOL_VERSION)
            .to_string(),
    );
    // initialized 통지(best-effort — 일부 서버는 필요).
    let _ = post_notification(http, server, "notifications/initialized").await;
    // tools/list → tool 발견. nextCursor가 있으면 모든 페이지를 모은다(MAX_TOOL_PAGES 안전 상한).
    let mut tools: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_TOOL_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let result = post_rpc(http, server, "tools/list", params, HANDSHAKE_TIMEOUT_SECS).await?;
        if let Some(arr) = result.get("tools").and_then(Value::as_array) {
            tools.extend(arr.iter().cloned());
        }
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(c) if !c.is_empty() => cursor = Some(c.to_string()),
            _ => break,
        }
    }
    server.tools = tools
        .iter()
        .filter_map(|t| {
            let name = t.get("name")?.as_str()?.to_string();
            let desc = t
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let schema = t
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object" }));
            let full = format!("{}__{}", server.name, name);
            Some(McpToolDef {
                full_name: Box::leak(full.into_boxed_str()),
                description: Box::leak(desc.into_boxed_str()),
                name,
                input_schema: schema,
            })
        })
        .collect();
    Ok(())
}

/// auth/세션/프로토콜 헤더를 붙인 POST RequestBuilder를 만든다. timeout은 요청 종류별로 다르다
/// (핸드셰이크는 짧게, tool 호출은 길게).
fn build_req(
    http: &reqwest::Client,
    server: &McpServer,
    body: &Value,
    timeout_secs: u64,
) -> Result<reqwest::RequestBuilder, ToolError> {
    let mut req = http
        .post(&server.url)
        .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
        .timeout(Duration::from_secs(timeout_secs))
        .json(body);
    if let Some(sid) = &server.session_id {
        req = req.header("Mcp-Session-Id", sid.as_str());
    }
    // 2025-06-18 streamable HTTP: init 이후 모든 요청에 협상 버전을 보낸다(init 전엔 None → 미전송).
    if let Some(pv) = &server.protocol_version {
        req = req.header("MCP-Protocol-Version", pv.as_str());
    }
    if let Some(auth) = &server.auth {
        let tok = crate::keychain::resolve(auth)
            .map_err(|e| ToolError::new(format!("MCP auth 토큰 resolve 실패: {e}")))?;
        req = req.bearer_auth(tok);
    }
    Ok(req)
}

/// 요청-응답 JSON-RPC. 결과 Value와 (있으면) 응답 Mcp-Session-Id를 돌려준다.
async fn post_rpc_with_session(
    http: &reqwest::Client,
    server: &McpServer,
    method: &str,
    params: Value,
    timeout_secs: u64,
) -> Result<(Value, Option<String>), ToolError> {
    let id = server.next_id.fetch_add(1, Ordering::Relaxed);
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let resp = build_req(http, server, &body, timeout_secs)?
        .send()
        .await
        .map_err(|e| ToolError::new(format!("MCP 요청 실패: {e}")))?;
    let status = resp.status();
    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = read_bounded(resp).await?;
    let text = String::from_utf8_lossy(&bytes);
    if !status.is_success() {
        // 에러 본문도 LLM에 전달되므로 redact + cap한다(secret/PII 누출 방지).
        let safe = crate::redaction::redact(&text).0;
        return Err(ToolError::new(format!(
            "MCP HTTP {status}: {}",
            truncate(&safe, 1000)
        )));
    }
    let msg = extract_rpc_message(&text, &content_type)?;
    if let Some(err) = msg.get("error") {
        let m = err.get("message").and_then(Value::as_str).unwrap_or("unknown");
        let safe = crate::redaction::redact(m).0;
        return Err(ToolError::new(format!("MCP error: {safe}")));
    }
    Ok((msg.get("result").cloned().unwrap_or(Value::Null), session_id))
}

async fn post_rpc(
    http: &reqwest::Client,
    server: &McpServer,
    method: &str,
    params: Value,
    timeout_secs: u64,
) -> Result<Value, ToolError> {
    post_rpc_with_session(http, server, method, params, timeout_secs)
        .await
        .map(|(result, _)| result)
}

/// 통지(id 없음, 응답 무시). best-effort.
async fn post_notification(
    http: &reqwest::Client,
    server: &McpServer,
    method: &str,
) -> Result<(), ToolError> {
    let body = json!({ "jsonrpc": "2.0", "method": method, "params": {} });
    let _ = build_req(http, server, &body, HANDSHAKE_TIMEOUT_SECS)?
        .send()
        .await
        .map_err(|e| ToolError::new(format!("MCP 통지 실패: {e}")))?;
    Ok(())
}

/// 응답 본문에서 JSON-RPC 메시지를 추출한다. `application/json`이면 그대로 파싱, `text/event-stream`이면
/// `data:` 라인을 훑어 result/error를 가진 메시지를 고른다(순수 함수 — 테스트 가능).
fn extract_rpc_message(text: &str, content_type: &str) -> Result<Value, ToolError> {
    let is_sse = content_type.contains("text/event-stream")
        || (!text.trim_start().starts_with('{') && text.contains("data:"));
    if is_sse {
        let mut last: Option<Value> = None;
        for line in text.lines() {
            let Some(data) = line.trim_start().strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(data) {
                if v.get("result").is_some() || v.get("error").is_some() {
                    return Ok(v);
                }
                last = Some(v);
            }
        }
        last.ok_or_else(|| ToolError::new("MCP SSE 응답에서 JSON-RPC 메시지를 찾지 못함".to_string()))
    } else {
        serde_json::from_str::<Value>(text.trim())
            .map_err(|e| ToolError::new(format!("MCP 응답 파싱 실패: {e}")))
    }
}

/// tools/call 결과의 `content[]`를 텍스트로 합친다. text 블록은 그대로, 그 외(resource 등)는 raw JSON.
/// content가 없으면 result 전체를 직렬화(structuredContent 등 폴백).
fn extract_content_text(result: &Value) -> String {
    if let Some(arr) = result.get("content").and_then(Value::as_array) {
        let parts: Vec<String> = arr
            .iter()
            .map(|c| {
                c.get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| c.to_string())
            })
            .collect();
        if !parts.is_empty() {
            return parts.join("\n");
        }
    }
    result.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_returns_none_without_enabled_servers() {
        let cfg = McpConfig::default();
        assert!(McpClient::new(&cfg).is_none());
    }

    #[test]
    fn new_rejects_unsafe_url_and_disabled() {
        use aic_common::McpServerConfig;
        let mut servers = std::collections::HashMap::new();
        // disabled → skip.
        servers.insert(
            "off".to_string(),
            McpServerConfig {
                url: "http://127.0.0.1:8787/mcp".to_string(),
                enabled: false,
                auth: None,
                auto_approve: vec![],
            },
        );
        // link-local(metadata SSRF) → skip.
        servers.insert(
            "evil".to_string(),
            McpServerConfig {
                url: "http://169.254.169.254/mcp".to_string(),
                enabled: true,
                auth: None,
                auto_approve: vec![],
            },
        );
        let cfg = McpConfig { servers };
        assert!(McpClient::new(&cfg).is_none(), "no valid enabled server → None");
    }

    #[test]
    fn extract_rpc_message_parses_plain_json() {
        let msg = extract_rpc_message(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#, "application/json")
            .unwrap();
        assert_eq!(msg["result"]["ok"], json!(true));
    }

    #[test]
    fn extract_rpc_message_parses_sse() {
        // SSE: ping/notification 다음에 실제 result 메시지.
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"x\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n";
        let msg = extract_rpc_message(body, "text/event-stream").unwrap();
        assert!(msg.get("result").is_some(), "{msg}");
        assert_eq!(msg["result"]["tools"], json!([]));
    }

    #[test]
    fn extract_rpc_message_errors_on_garbage() {
        assert!(extract_rpc_message("not json", "application/json").is_err());
    }

    #[test]
    fn extract_content_text_joins_text_blocks() {
        let result = json!({
            "content": [
                { "type": "text", "text": "line1" },
                { "type": "text", "text": "line2" }
            ]
        });
        assert_eq!(extract_content_text(&result), "line1\nline2");
    }

    #[test]
    fn extract_content_text_falls_back_to_raw() {
        let result = json!({ "structuredContent": { "x": 1 } });
        let s = extract_content_text(&result);
        assert!(s.contains("structuredContent"), "{s}");
    }
}
