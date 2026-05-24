//! 읽기 전용 agentic 어시스턴트 (RFC-002 Phase 1).
//!
//! 구성:
//! - [`types`] — ChatMessage / ToolCall / ToolSpec / ChatResponse + OpenAI wire 직렬화.
//! - [`sandbox`] — cwd 기반 파일 접근 샌드박스(경로 탈출 차단).
//! - [`tools`] — 읽기 전용 도구(read_file/list_dir/grep/glob) + registry.
//! - [`session`] — tool-calling agent loop(`AgentSession`).
//!
//! 안전 원칙: 읽기 전용. 쓰기/실행 도구는 registry에 등록하지 않는다(Phase 2).
//! provider는 OpenAI-compat 경로에서만 tool-calling을 지원하며, 미지원 시
//! 호출부가 기존 `ReplSession`(단발 send)으로 폴백한다.

// RFC-004 단계 2 골격(ratatui chat TUI). 단계 4에서 session 연결 시 allow 제거.
#[allow(dead_code)]
pub(crate) mod chat_tui;
pub(crate) mod debug;
pub(crate) mod diagnose;
pub mod gitignore;
pub(crate) mod markdown;
pub(crate) mod probes;
pub mod run_command;
pub mod sandbox;
pub mod session;
pub(crate) mod sys_sampler;
pub(crate) mod sysinfo;
pub(crate) mod tool_record;
pub mod tools;
pub mod types;
pub(crate) mod ui;

pub use sandbox::Sandbox;
pub use session::AgentSession;
pub use tools::ToolError;
pub use types::{ChatMessage, ChatResponse, ToolCall, ToolSpec};
