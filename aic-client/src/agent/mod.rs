//! 읽기 전용 agentic 어시스턴트 (RFC-002 Phase 1).
//!
//! 구성:
//! - [`types`] — ChatMessage / ToolCall / ToolSpec / ChatResponse + OpenAI wire 직렬화.
//! - [`sandbox`] — cwd 기반 파일 접근 샌드박스(경로 탈출 차단).
//! - [`tools`] — 읽기 전용 도구(read_file/list_dir/grep/glob) + registry.
//! - [`session`] — tool-calling agent loop(`AgentSession`).
//!
//! 안전 원칙: 읽기 전용. 쓰기/실행 도구는 registry에 등록하지 않는다(Phase 2).
//! provider는 OpenAI-compat과 Anthropic(SRE R4) 경로에서 tool-calling을 지원하며,
//! 미지원(CLI backend 등) 시 호출부가 기존 `ReplSession`(단발 send)으로 폴백한다.

// RFC-004 단계 2 골격(ratatui chat TUI). 단계 4에서 session 연결 시 allow 제거.
#[allow(dead_code)]
pub(crate) mod chat_tui;
pub(crate) mod debug;
// SRE R2: headless 진단(run_headless_diagnose)을 바이너리(diagnose CLI/webhook spawn)에서 쓰므로 pub.
pub mod diagnose;
pub mod gitignore;
// RFC-005 Phase 1: SSH 멀티호스트 인벤토리(hosts.toml + ssh_config import + overlay).
pub mod hosts;
// RFC-005 Phase 2: RemoteExecutor trait + 외부 ssh 프로세스 구현. fan-out은 Phase 3.
pub mod remote;
// RFC-005 Phase 5 후반: 멀티호스트 batch audit + daily segment + SHA256 chain (O2).
pub mod audit_batch;
// RFC-005 Phase 6: 사용자 확장 가능한 tokenizer 화이트리스트(builtin + ~/.aic/whitelist.toml) (O3).
pub mod whitelist;
// SRE R0/R2: 인시던트 증거 번들 작성(대화형 /bundle + 비대화 webhook/CLI 공유).
pub mod bundle;
pub(crate) mod markdown;
// MCP(Model Context Protocol) 클라이언트 — config 등록 서버(mem-mesh 등)의 tool을 chat에 노출(HTTP).
pub(crate) mod mcp;
// SRE R1: 관측 백엔드(Prometheus/Loki/Elasticsearch) read-only HTTP 질의 도구.
pub mod obs_tools;
pub(crate) mod probes;
// `/local`의 proc_changes 섹션 + `/procs` — 최근 프로세스 생성/소멸. probe가 `aic proc-changes`로
// 호출하므로 proc_fd와 같은 이유로 pub.
pub mod proc_changes;
// `/local`의 proc_fd_top 섹션 — 프로세스별 fd 상위 N. probe가 `aic proc-fd-top`으로 호출하므로
// main.rs(외부 크레이트 경로)에서 접근 가능해야 해 pub.
pub mod proc_fd;
// RCA 강화 ③: baseline 스냅샷 대비 프로세스 rss 성장 리더보드(결정적 범인 후보 좁히기).
pub(crate) mod proc_delta;
pub mod run_command;
pub mod sandbox;
pub mod session;
// 스냅샷 레코더 L1: 이상-트리거 전체 /local 스냅샷 캡처(standalone, AgentSession 불요).
// L2: `aic snapshot capture`(main.rs, 외부 크레이트 경로)가 capture/capture_forced를 호출하므로 pub.
pub mod snapshot_capture;
// 스냅샷 레코더 L3: Crit 이상-트리거 자동 RCA 인시던트 생성(standalone). chat_tui onset에서만 호출.
pub(crate) mod auto_rca;
pub(crate) mod sys_sampler;
pub(crate) mod sysinfo;
// RCA 강화 ②: Crit onset 직전 window의 터미널 명령(aicd 전 세션)을 인시던트 Timeline 증거로.
pub(crate) mod terminal_evidence;
// SRE t7: connections/inventory JSON 스냅샷("aic snapshot inventory --json" hidden leaf) — aicd
// OTLP connections exporter가 주기 spawn한다. main.rs(외부 크레이트 경로)가 capture()를 호출하므로 pub.
pub mod net_inventory;
pub(crate) mod tool_record;
pub mod tools;
pub mod types;
pub(crate) mod ui;
pub(crate) mod webhook_watch;

pub use sandbox::Sandbox;
pub use session::AgentSession;
pub use tools::ToolError;
pub use types::{ChatMessage, ChatResponse, ToolCall, ToolSpec};
