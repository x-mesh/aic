//! aic-common: 공유 데이터 모델, IPC 프로토콜, 에러 타입

pub mod attach;
pub mod bounded_byte_channel;
pub mod central_store_flag;
pub mod error;
pub mod ipc;
pub mod paths;
// LLM/텔레메트리 송신 직전 secret·PII 마스킹. aic-client(LLM prompt)와 aic-server
// (OTLP exporter, SRE t6) 양쪽이 공유하므로 lean한 aic-common으로 옮겨 단일 원천으로 둔다.
pub mod redaction;
pub mod session;
pub mod shell_hooks;

pub use error::AicError;
pub use ipc::{
    decode_frame, encode_frame, AgentEvent, DaemonVersion, ExporterStatus, IpcRequest, IpcResponse,
    MetricsSnapshot, AGENT_KIND_FINDING_CREATED, AGENT_KIND_RISK_DENIED,
    AGENT_KIND_SNAPSHOT_RECORDED, AGENT_KIND_TOOL_RUN_COMMAND,
};
pub use paths::{
    aicd_attach_socket_path, aicd_lock_path, aicd_registry_path, aicd_socket_path,
    default_socket_path, extract_session_id, list_session_sockets, local_command_record_path,
    local_hook_pending_path, resolve_active_socket, resolve_socket_path, session_dir,
    session_socket_path,
};
pub use session::{
    generate_record_id, generate_session_id, generate_unused_session_id, is_valid_record_id,
    is_valid_session_id,
};
pub use shell_hooks::generate_shell_hooks;

// CaptureMode/CaptureQuality/OutputMetadata는 같은 모듈 내 정의이므로 별도 re-export 불필요.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ── CommandRecord ──────────────────────────────────────────────

/// 레코드를 만든 캡처 경로.
///
/// `Pty`는 PTY wrapper 기반 정확 캡처, `Hook`은 shell hook 기반 metadata-only,
/// `ExplicitCapture`는 `aic run -- <cmd>` 같은 명시적 wrapper 캡처.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CaptureMode {
    #[default]
    Pty,
    Hook,
    ExplicitCapture,
}

/// 레코드 출력의 품질 등급. 분석 prompt와 cache key가 신뢰도를 인식하기 위해 사용.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CaptureQuality {
    /// PTY 또는 explicit capture로 stdout/stderr tail이 있음
    FullOutput,
    /// command/cwd/exit/duration만 있음
    MetadataOnly,
    /// 출력이 있었지만 policy에 따라 일부 제거됨
    RedactedOutput,
    /// binary/non-UTF8 출력이 감지되어 본문 생략됨
    BinaryOmitted,
    /// line/byte cap으로 일부만 저장됨
    TruncatedOutput,
    /// legacy record 또는 품질 판단 불가
    #[default]
    Unknown,
}

impl CaptureMode {
    /// history/last 등 목록 UI용 짧은 소스 라벨.
    pub fn short_label(self) -> &'static str {
        match self {
            CaptureMode::Pty => "pty",
            CaptureMode::Hook => "hook",
            CaptureMode::ExplicitCapture => "run",
        }
    }
}

impl CaptureQuality {
    /// history/last 등 목록 UI용 짧은 품질 라벨.
    pub fn short_label(self) -> &'static str {
        match self {
            CaptureQuality::FullOutput => "full",
            CaptureQuality::MetadataOnly => "meta",
            CaptureQuality::RedactedOutput => "redact",
            CaptureQuality::BinaryOmitted => "bin",
            CaptureQuality::TruncatedOutput => "trunc",
            CaptureQuality::Unknown => "?",
        }
    }
}

/// 목록 UI용 duration 포맷: `512ms`, `1.3s`, `2m03s`.
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

/// 출력 본문에 대한 메타데이터. 본문이 일부/전부 잘렸거나 해시만 남는 경우에 채운다.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OutputMetadata {
    /// 잘리기 전 원본 byte 크기 (알 수 있는 경우)
    pub original_bytes: Option<u64>,
    /// 실제 저장된 byte 크기
    pub stored_bytes: u64,
    /// 실제 저장된 라인 수
    pub stored_lines: usize,
    /// truncation 여부
    pub truncated: bool,
    /// binary/non-UTF8 감지 여부
    pub binary: bool,
    /// 본문 hash (생략된 binary 출력의 식별용)
    pub sha256: Option<String>,
    /// 재실행 승격(`aic capture-last`) 시 승격 전 원본 레코드의 exit code.
    /// 새 레코드의 `exit_code`는 재실행 결과이므로, 원래 실패 코드를 여기 보존한다.
    #[serde(default)]
    pub original_exit_code: Option<i32>,
}

/// 하나의 명령어 실행에 대한 레코드.
///
/// `capture_mode`/`capture_quality`/`output_metadata`는 레거시 JSON 호환을 위해
/// `#[serde(default)]`로 채워진다. 새 코드는 가능하면 명시적으로 채운다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandRecord {
    /// Stable record id (16자 lowercase hex). `aic history`, `aic analyze --record`,
    /// `aic fix --record`의 공통 키이다. 레거시 JSON 호환을 위해 `#[serde(default)]`로
    /// 빈 문자열을 허용하며, ring buffer push 시 비어 있으면 자동 부여한다.
    #[serde(default)]
    pub id: String,
    /// 실행된 명령어 텍스트 (가능한 경우)
    pub command: Option<String>,
    /// 프로세스 종료 코드
    pub exit_code: i32,
    /// ANSI 제거된 출력 라인들
    pub output_lines: Vec<String>,
    /// 명령어 완료 시각
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// 캡처 경로 (Phase 0). 레거시 JSON에선 `Pty`로 기본화.
    #[serde(default)]
    pub capture_mode: CaptureMode,
    /// 출력 품질 등급. 레거시 JSON에선 `Unknown`으로 기본화.
    #[serde(default)]
    pub capture_quality: CaptureQuality,
    /// 출력 본문 메타데이터. 본문 cap/redaction/binary 시에만 채운다.
    #[serde(default)]
    pub output_metadata: Option<OutputMetadata>,
    /// 명령이 실행된 shell cwd (알 수 있는 경우). hook event 또는 explicit capture에서 채운다.
    #[serde(default)]
    pub cwd: Option<String>,
    /// 명령 실행 시간 (ms). hook event 또는 explicit capture에서 채운다.
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

impl Default for CommandRecord {
    fn default() -> Self {
        Self {
            id: String::new(),
            command: None,
            exit_code: 0,
            output_lines: Vec::new(),
            timestamp: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0)
                .expect("UNIX epoch is a valid timestamp"),
            capture_mode: CaptureMode::default(),
            capture_quality: CaptureQuality::default(),
            output_metadata: None,
            cwd: None,
            duration_ms: None,
        }
    }
}

/// 분석 직전에 사용자에게 capture quality를 안내하는 hint 메시지 (Phase 4).
///
/// 의도:
/// - PTY wrapper의 FullOutput 결과는 hint를 내지 않는다(noise).
/// - hook mode 등에서 MetadataOnly이면 분석 신뢰도가 떨어진다는 사실과
///   `aic capture-last` / `aic run --` 옵션을 알린다.
/// - TruncatedOutput/BinaryOmitted는 사실만 짧게 알린다.
///
/// `mode`는 사용자의 SessionCaptureMode — Hybrid에서는 hook→hint 흐름이 product 기본
/// 동작이므로 메시지를 좀 더 actionable하게 표현한다.
pub fn capture_quality_hint(record: &CommandRecord, mode: SessionCaptureMode) -> Option<String> {
    match record.capture_quality {
        CaptureQuality::FullOutput | CaptureQuality::Unknown => None,
        CaptureQuality::MetadataOnly => {
            let cmd = record.command.as_deref().unwrap_or("(이전 명령)");
            let suggest = match mode {
                SessionCaptureMode::Hybrid => format!(
                    "정확한 분석을 위해 `aic run -- {cmd}`로 다시 실행하거나 \
                     `aic capture-last`로 capture 모드 재실행하세요."
                ),
                _ => format!(
                    "출력 없이 metadata만 있어 분석 신뢰도가 낮습니다. \
                     `aic run -- {cmd}` 또는 PTY 세션(`aic-session`)에서 다시 실행해 보세요."
                ),
            };
            Some(format!("이 기록은 metadata-only 입니다 — {suggest}"))
        }
        CaptureQuality::TruncatedOutput => Some(
            "출력이 cap을 초과해 일부만 저장되었습니다. 전체 분석에는 일부 누락이 있을 수 있습니다."
                .to_string(),
        ),
        CaptureQuality::BinaryOmitted => Some(
            "binary/non-UTF8 출력이라 본문이 생략되었습니다. metadata 기반 분석으로만 진행됩니다."
                .to_string(),
        ),
        CaptureQuality::RedactedOutput => Some(
            "출력이 redaction 정책에 의해 일부 제거되었습니다 — 분석 결과가 보수적일 수 있습니다."
                .to_string(),
        ),
    }
}

// ── Session registry types ─────────────────────────────────────

/// 세션 lifecycle 상태. PRD-AICD-SUPERVISOR §10.2와 일치한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Creating,
    Attached,
    Detached,
    Stopping,
    Stopped,
    Failed,
}

/// `aicd` registry의 세션 한 건.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session_ID (8자 lowercase hex). `session::generate_session_id` 참조.
    pub id: String,
    /// 세션 owner 프로세스 PID (현재는 `aic-session` PID, 향후 PTY child PID).
    pub pid: u32,
    /// 현재 lifecycle 상태.
    pub state: SessionState,
    /// 세션이 처음 등록된 시각.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// 마지막 heartbeat 또는 hook event 수신 시각.
    #[serde(default)]
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    /// 마지막 command start 시각.
    #[serde(default)]
    pub last_command_at: Option<chrono::DateTime<chrono::Utc>>,
    /// 현재 attach된 TTY 경로 (예: `/dev/ttys003`). attach가 없으면 `None`.
    pub attached_tty: Option<String>,
    /// 셸 실행 파일 경로 (예: `/bin/zsh`). 알 수 없으면 `None`.
    pub shell: Option<String>,
    /// 세션 cwd. 셸 시작 시점 또는 마지막 보고 시점 기준.
    pub cwd: Option<std::path::PathBuf>,
    /// 사용자가 부여한 label (예: "main", "test-runner"). 기본은 None — 레거시 JSON
    /// 호환을 위해 `#[serde(default)]`. session id는 그대로 두고 별도 메타로만 쓴다.
    #[serde(default)]
    pub label: Option<String>,
}

// ── Session capture mode (Phase 4) ─────────────────────────────

/// 사용자가 config로 선택하는 capture 동작.
///
/// `CaptureMode`(record-level)와는 구분된다. `SessionCaptureMode`는 "어떤 mode로
/// 캡처할 것인가"를 표현하고, `CaptureMode`는 "이 record가 실제로 어떻게 만들어졌는가"를
/// 표현한다. Hybrid는 record-level enum에는 없다(record는 항상 둘 중 하나로 만들어진다).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionCaptureMode {
    /// 기존 PTY wrapper. 출력 정확도 높음.
    Pty,
    /// shell hook 기반 metadata-only.
    Hook,
    /// 평소 metadata-only, 분석 시 capture suggestion 자동 노출.
    #[default]
    Hybrid,
}

/// 세션 동작 관련 사용자 설정.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionConfig {
    /// 어느 capture mode를 쓸지. 기본 "hybrid".
    #[serde(default)]
    pub capture_mode: SessionCaptureMode,
}

// ── AppConfig / ServerConfig ───────────────────────────────────

/// 애플리케이션 설정.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    pub llm: LlmConfig,
    pub server: ServerConfig,
    /// 세션 capture 모드 설정 (Phase 4). 레거시 config 호환을 위해 default.
    #[serde(default)]
    pub session: SessionConfig,
    /// 관측 백엔드(Prometheus/Loki/Elasticsearch) 설정 (SRE R1).
    /// 레거시 config 호환을 위해 default — 미설정 시 등록 백엔드 없음.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// aicd 데몬 설정 (SRE R2: webhook alert ingestion). 레거시 호환 default.
    #[serde(default)]
    pub aicd: AicdConfig,
    /// MCP 서버 설정 — 등록 서버의 tool을 chat에 노출한다. 레거시 호환 default(미설정 시 서버 없음).
    #[serde(default)]
    pub mcp: McpConfig,
    /// RCA 워크플로 설정. 레거시 호환 default — 미설정 시 모든 기능 opt-in 유지.
    #[serde(default)]
    pub rca: RcaConfig,
    /// 외부 전송(팀 공유) 설정 (Phase 2 O3). 레거시 호환 default — 미설정 시 등록 목적지 없음.
    #[serde(default)]
    pub outbound: OutboundConfig,
}

/// RCA 워크플로 설정 (SRE).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RcaConfig {
    /// `aic rca close` 시 `--remember` 없이도 sre-agent incident-memory에 자동 기록한다(best-effort handoff).
    /// 기본 false — incident-memory 배선은 명시적 opt-in을 유지한다.
    #[serde(default)]
    pub auto_remember: bool,
}

/// 외부 전송 설정 (Phase 2 O3). 목적지 이름 → 설정. 미설정 시 빈 맵(전송 불가 — deny-by-default).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OutboundConfig {
    /// 전송 목적지들(`[outbound.targets.<name>]`). 이름이 곧 allowlist 키다.
    #[serde(default)]
    pub targets: HashMap<String, OutboundTarget>,
}

/// 한 전송 목적지. `kind`로 어댑터를 고른다("file" | "webhook"). webhook은 `enabled=true`여야 실제 전송.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboundTarget {
    /// "file"(로컬 디렉터리 기록, 기본 활성) 또는 "webhook"(HTTP POST, 기본 비활성).
    pub kind: String,
    /// webhook 목적지의 활성 여부. 기본 false — 명시적으로 켜야 전송(file은 항상 활성).
    #[serde(default)]
    pub enabled: bool,
    /// file 목적지의 기록 디렉터리(없으면 `~/.aic/outbound`).
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// webhook 목적지의 POST URL(http/https).
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Ring Buffer 최대 라인 수 (기본: 500)
    pub max_buffer_lines: usize,
    /// UDS 소켓 경로 (기본: XDG_RUNTIME_DIR/aic/session.sock)
    pub socket_path: Option<PathBuf>,
    /// Command Boundary 감지 전략
    pub boundary_strategy: BoundaryStrategyConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundaryStrategyConfig {
    /// "prompt_marker" 또는 "timing_heuristic"
    pub method: String,
    /// Timing Heuristic 사용 시 idle threshold (ms)
    pub idle_threshold_ms: Option<u64>,
}

// ── LlmConfig / ProviderConfig / ProviderType ──────────────────

/// LLM Provider 설정.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmConfig {
    /// 기본 Provider 이름 ("openai", "nvidia", "groq", "anthropic", "kiro-cli", "claude-cli")
    pub default_provider: String,
    /// Provider별 설정. config.toml에 누락되면 빈 맵으로 처리 (런타임에 resolve_provider가 ConfigError 반환).
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    /// 응답 언어 설정 (기본: "korean")
    #[serde(default = "default_lang")]
    pub lang: String,
    /// TCP 연결 타임아웃(초) — endpoint reachability 확인용. 기본 5초.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// 요청 전체 타임아웃(초) — connect + LLM 응답 대기 포함. 기본 30초.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

fn default_lang() -> String {
    "korean".to_string()
}

/// `lang = "auto"`인 경우 환경 변수($LC_ALL, $LANG)에서 언어를 추론한다.
/// 추론 실패 시 "english"로 폴백한다. config에 명시적 언어가 있으면 그대로 반환.
pub fn resolve_lang(configured: &str) -> String {
    if configured != "auto" {
        return configured.to_string();
    }

    let raw = std::env::var("LC_ALL")
        .ok()
        .or_else(|| std::env::var("LANG").ok())
        .unwrap_or_default()
        .to_lowercase();

    // ko_KR.UTF-8 → "ko", ja_JP → "ja" 등 prefix 추출
    let prefix = raw.split(['_', '.']).next().unwrap_or("");

    match prefix {
        "ko" => "korean".to_string(),
        "ja" => "japanese".to_string(),
        "zh" => "chinese".to_string(),
        "en" => "english".to_string(),
        _ => "english".to_string(),
    }
}

fn default_connect_timeout_secs() -> u64 {
    5
}

fn default_request_timeout_secs() -> u64 {
    30
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Provider 유형
    pub provider_type: ProviderType,
    /// API endpoint URL (REST API 타입만)
    pub endpoint: Option<String>,
    /// API key (REST API 타입만)
    pub api_key: Option<String>,
    /// 모델 이름
    pub model: Option<String>,
    /// CLI 실행 파일 경로 (CLI Backend 타입만)
    pub cli_path: Option<String>,
    /// CLI 호출 시 prompt 앞에 prepend되는 인자 (CLI Backend 타입만).
    ///
    /// 예: kiro-cli는 `chat` subcommand가 필요하므로 `["chat"]`,
    /// claude-cli는 `["-p"]` (non-interactive print). 비워두면 cli_path basename으로
    /// 합리적 default를 자동 선택한다(`kiro-cli/kiro` → `["chat"]`,
    /// `claude/claude-cli` → `["-p"]`, 그 외 → `[]`).
    ///
    /// 레거시 config 호환을 위해 `#[serde(default)]`. None은 "auto"와 동치.
    #[serde(default)]
    pub cli_args: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProviderType {
    /// OpenAI 호환 API (OpenAI, NVIDIA 등 — endpoint/model을 직접 지정)
    OpenAiCompatible,
    /// Groq Cloud API (OpenAI 호환 — endpoint/model 미지정 시 Groq 기본값 적용)
    Groq,
    /// Anthropic 전용 API
    Anthropic,
    /// 로컬 CLI 실행 (kiro-cli, claude-cli)
    CliBackend,
}

// ── ObservabilityConfig / BackendConfig / BackendType (SRE R1) ──

/// 관측 백엔드 통합 설정. config.toml `[observability]` 섹션.
///
/// 등록된 백엔드만 obs 질의 도구(prometheus_query/loki_query/es_query)의
/// endpoint allowlist에 들어간다. 미등록 URL 질의는 도구 레벨에서 거부되어
/// SSRF / 내부망 탐색을 차단한다 (R1.6).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// 백엔드 이름 → 설정. config.toml `[observability.backends.<name>]`.
    #[serde(default)]
    pub backends: HashMap<String, BackendConfig>,
}

/// 단일 관측 백엔드 설정.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendConfig {
    /// 백엔드 유형. (VictoriaMetrics는 PromQL 호환이므로 `Prometheus`로 등록)
    pub backend_type: BackendType,
    /// base URL (예: `http://prometheus:9090`). 질의 시 allowlist의 단일 출처.
    pub url: String,
    /// 인증 토큰. 평문 또는 `keychain:<account>` 참조. 미지정 시 무인증.
    #[serde(default)]
    pub auth: Option<String>,
}

/// 관측 백엔드 유형.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendType {
    /// Prometheus PromQL (VictoriaMetrics 포함 — PromQL/HTTP API 호환)
    Prometheus,
    /// Loki LogQL
    Loki,
    /// Elasticsearch / OpenSearch 검색 API
    Elasticsearch,
}

// ── McpConfig / McpServerConfig (MCP client) ───────────────

/// MCP 서버 통합 설정. config.toml `[mcp]` 섹션. 등록된 서버의 tool을 chat tool-calling에 노출한다.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct McpConfig {
    /// 서버 이름 → 설정. config.toml `[mcp.servers.<name>]`.
    #[serde(default)]
    pub servers: HashMap<String, McpServerConfig>,
}

/// 단일 MCP 서버 설정. 현재 transport는 Streamable HTTP(POST + 선택적 SSE 응답)만 지원한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// MCP endpoint URL (예: `http://127.0.0.1:8787/mcp`). obs 백엔드와 동일한 SSRF 방어를 적용한다.
    pub url: String,
    /// 비활성 시 연결·노출하지 않는다. 기본 true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 인증 토큰(`Authorization: Bearer`). 평문 또는 `keychain:<account>`. 미지정 시 무인증.
    #[serde(default)]
    pub auth: Option<String>,
    /// 확인 없이 자동 실행할 (read-only) tool 이름 목록. 그 외 tool은 실행 전 사용자 확인을 받는다.
    #[serde(default)]
    pub auto_approve: Vec<String>,
}

// ── AicdConfig / AicdWebhookConfig (SRE R2) ────────────────

/// aicd 데몬 설정.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AicdConfig {
    /// webhook alert ingestion 설정.
    #[serde(default)]
    pub webhook: AicdWebhookConfig,
    /// OTLP host-metrics exporter 설정 (SRE t6). 기본 비활성(opt-in).
    #[serde(default)]
    pub exporter: AicdExporterConfig,
}

/// aicd OTLP exporter 설정 (SRE t6: host metrics push / t7: events+connections push).
///
/// 기본 **비활성**이다. 활성화하면 aicd가 주기적으로 sysinfo 기반 host metrics(cpu/load/mem/
/// swap/disk/net)를 수집해 OTLP protobuf로 인코딩한 뒤 `{endpoint}/v1/metrics`로 push한다.
/// `events_enabled`/`connections_enabled`는 `enabled=true`일 때만 의미가 있으며(부모 게이트),
/// 각각 command 종료 이벤트(OTLP Logs, `/v1/logs`)와 주기 connections/inventory 스냅샷(OTLP Logs,
/// `/v1/logs`)을 독립적으로 껐다 켤 수 있다. 모든 송신 문자열 필드는 redaction을 거친다. token은
/// 평문 또는 환경변수 `AIC_EXPORTER_TOKEN`로 주입한다(aicd는 keychain을 resolve하지 않는다 —
/// webhook secret과 동일 관례).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AicdExporterConfig {
    /// exporter 활성화 여부. 기본 false(opt-in). false면 코드 경로 완전 비활성(하위 플래그 무관).
    #[serde(default)]
    pub enabled: bool,
    /// OTLP HTTP collector base URL(예: `http://127.0.0.1:4318`). `/v1/metrics`·`/v1/logs`가
    /// 각각 append된다. 미설정(빈 문자열)이면 enabled여도 exporter를 띄우지 않는다.
    #[serde(default)]
    pub endpoint: String,
    /// `Authorization: Bearer <token>`용 토큰. 환경변수 `AIC_EXPORTER_TOKEN`가 우선한다.
    /// 미설정 시 Authorization 헤더 없이 전송(localhost collector 등).
    #[serde(default)]
    pub token: Option<String>,
    /// 수집·push 주기(초). host metrics 전용. 기본 60초. 다른 config가 units 없는 `interval`을
    /// 쓰지 않도록 repo 관례(`dedup_ttl_secs`/`connect_timeout_secs`)를 따라 `_secs` suffix로
    /// 단위를 명시한다.
    #[serde(default = "default_exporter_interval")]
    pub interval_secs: u64,
    /// command 종료 이벤트(CommandRecordStore tap → OTLP Logs) push 활성화 여부. 기본 true
    /// (`enabled=true`로 껐다 켤 때 기본 동작 — host metrics만 원하면 명시적으로 false).
    #[serde(default = "default_true")]
    pub events_enabled: bool,
    /// connections/inventory 주기 스냅샷(OTLP Logs) push 활성화 여부. 기본 true.
    #[serde(default = "default_true")]
    pub connections_enabled: bool,
    /// chat/agent 행위(OTLP Logs, scope=`aic.agent`) push 활성화 여부. 기본 true.
    ///
    /// 보내는 것은 시스템을 **바꾼** 행위와 **위험 신호**뿐이다(`tool.run_command`,
    /// `risk.denied`, `finding.created`). chat 대화 내용·LLM prompt/response는 보내지 않는다 —
    /// 그건 애초에 aicd로 넘어오지도 않는다.
    #[serde(default = "default_true")]
    pub agent_enabled: bool,
    /// connections/inventory 스냅샷 캡처 주기(초). host metrics `interval_secs`와 별개 — 스냅샷은
    /// `aic` 바이너리를 spawn하는 비용이 있어 기본을 더 길게(60초) 둔다.
    #[serde(default = "default_connections_interval")]
    pub connections_interval_secs: u64,
    /// 오프라인 spool(`~/.aic/otlp-spool/`, SRE t8) 총 용량 상한(bytes). collector가 다운된 동안
    /// push 실패분을 여기 쌓아 두고 복구 후 드레인한다. 상한을 넘으면 가장 오래된 배치부터
    /// 삭제(oldest drop)하며 카운터를 올린다(무한정 디스크를 먹지 않게). 기본 256MiB.
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,
    /// spool 드레인 시 한 번(host metrics tick)에 재전송을 시도할 최대 배치 수(SRE t8). 배치당
    /// HTTP 요청 1개라 이 값이 곧 "collector 복구 직후 한 번에 몇 요청을 쏠지"의 속도 제한이다.
    /// 기본 20 — 밀린 배치가 더 있으면 다음 tick에 이어서 드레인한다.
    #[serde(default = "default_spool_drain_batch_limit")]
    pub spool_drain_batch_limit: usize,
    /// 프로세스 생명주기 변경 이벤트(start/exit/rss 급증)를 scope=`aic.changes`로 보낼지.
    /// 부모 게이트(`enabled`)가 꺼져 있으면 이 값과 무관하게 task 자체가 뜨지 않는다.
    #[serde(default = "default_true")]
    pub changes_enabled: bool,
    /// 프로세스 스냅샷 tick 주기. 이 간격 안에 떴다 사라진 프로세스는 놓친다 —
    /// connections(60초)보다 짧게 잡는 이유가 그것이다.
    #[serde(default = "default_changes_interval")]
    pub changes_interval_secs: u64,
}

impl Default for AicdExporterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            token: None,
            interval_secs: default_exporter_interval(),
            events_enabled: true,
            connections_enabled: true,
            agent_enabled: true,
            connections_interval_secs: default_connections_interval(),
            spool_max_bytes: default_spool_max_bytes(),
            spool_drain_batch_limit: default_spool_drain_batch_limit(),
            changes_enabled: true,
            changes_interval_secs: default_changes_interval(),
        }
    }
}

fn default_exporter_interval() -> u64 {
    60
}

fn default_connections_interval() -> u64 {
    60
}

fn default_changes_interval() -> u64 {
    30
}

fn default_spool_max_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_spool_drain_batch_limit() -> usize {
    20
}

/// aicd webhook 리스너 설정 (Alertmanager/Grafana/PagerDuty/generic JSON 수신).
///
/// 기본 **비활성**이며, 활성화해도 **127.0.0.1 바인드**가 기본이다(외부 노출 방지).
/// 인증 secret은 HMAC-SHA256(secret, body) 검증에 쓰인다 — 평문 또는 환경변수
/// `AIC_WEBHOOK_SECRET`로 주입(aicd는 keychain을 resolve하지 않는다).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AicdWebhookConfig {
    /// webhook 리스너 활성화 여부. 기본 false(opt-in).
    #[serde(default)]
    pub enabled: bool,
    /// 바인드 주소. 기본 `127.0.0.1:9099`(localhost 전용).
    #[serde(default = "default_webhook_listen")]
    pub listen_addr: String,
    /// HMAC 공유 secret(평문). 환경변수 `AIC_WEBHOOK_SECRET`가 우선한다.
    /// 미설정 시 인증 없음(localhost 바인드 + opt-in이라 허용하되 경고).
    #[serde(default)]
    pub secret: Option<String>,
    /// 분당 최대 LLM 진단 횟수(token-bucket). alert storm 비용 폭주 방지. 기본 10.
    #[serde(default = "default_webhook_rate_limit")]
    pub rate_limit_per_min: u32,
    /// 동일 fingerprint(alertname+labels) 재진단 차단 TTL(초). 기본 300(5분).
    #[serde(default = "default_webhook_dedup_ttl")]
    pub dedup_ttl_secs: u64,
    /// alert 수신 시 `aic diagnose`를 자동 spawn할지. 기본 true.
    /// false면 수신·기록만 하고 자동 진단은 하지 않는다.
    #[serde(default = "default_true")]
    pub auto_diagnose: bool,
    /// 자동 진단에 `--follow-up`(LLM 제안 probe 1라운드 자동 실행+재분석)을 붙일지.
    /// 헤드리스(사람 부재) 경로라 기본 false(opt-in) — 진단당 LLM 2회 호출 비용도 고려.
    #[serde(default)]
    pub follow_up: bool,
}

impl Default for AicdWebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_webhook_listen(),
            secret: None,
            rate_limit_per_min: default_webhook_rate_limit(),
            dedup_ttl_secs: default_webhook_dedup_ttl(),
            auto_diagnose: true,
            follow_up: false,
        }
    }
}

fn default_webhook_listen() -> String {
    "127.0.0.1:9099".to_string()
}

fn default_webhook_rate_limit() -> u32 {
    10
}

fn default_webhook_dedup_ttl() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

// ── AnalysisResult ─────────────────────────────────────────────

/// LLM 에러 분석 결과.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// 에러 원인 설명
    pub explanation: String,
    /// 수정된 명령어 제안 (있는 경우)
    pub suggested_command: Option<String>,
    /// 추가 참고 정보
    pub additional_info: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn command_record_serialize_roundtrip() {
        let record = CommandRecord {
            command: Some("ls -la".to_string()),
            exit_code: 1,
            output_lines: vec!["error: not found".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: CommandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn command_record_with_none_command() {
        let record = CommandRecord {
            command: None,
            exit_code: 0,
            output_lines: vec![],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: CommandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn legacy_command_record_json_deserializes_with_defaults() {
        // capture_mode/capture_quality/output_metadata 필드 없는 옛 JSON.
        // 기본값(Pty/Unknown/None)으로 채워져야 한다.
        let legacy = r#"{
            "command": "cargo build",
            "exit_code": 1,
            "output_lines": ["error[E0308]"],
            "timestamp": "2026-01-01T00:00:00Z"
        }"#;
        let record: CommandRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(record.command.as_deref(), Some("cargo build"));
        assert_eq!(record.exit_code, 1);
        assert_eq!(record.capture_mode, CaptureMode::Pty);
        assert_eq!(record.capture_quality, CaptureQuality::Unknown);
        assert!(record.output_metadata.is_none());
    }

    #[test]
    fn command_record_with_capture_metadata_roundtrip() {
        let record = CommandRecord {
            id: "deadbeefcafef00d".to_string(),
            command: Some("vim README.md".to_string()),
            exit_code: 0,
            output_lines: vec![],
            timestamp: Utc::now(),
            capture_mode: CaptureMode::Hook,
            capture_quality: CaptureQuality::MetadataOnly,
            output_metadata: Some(OutputMetadata {
                original_bytes: Some(0),
                stored_bytes: 0,
                stored_lines: 0,
                truncated: false,
                binary: false,
                sha256: None,
                original_exit_code: None,
            }),
            cwd: Some("/tmp".to_string()),
            duration_ms: Some(42),
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: CommandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn capture_mode_default_is_pty() {
        assert_eq!(CaptureMode::default(), CaptureMode::Pty);
    }

    #[test]
    fn capture_quality_default_is_unknown() {
        assert_eq!(CaptureQuality::default(), CaptureQuality::Unknown);
    }

    #[test]
    fn app_config_serialize_roundtrip() {
        let config = AppConfig {
            llm: LlmConfig {
                default_provider: "openai".to_string(),
                providers: HashMap::from([(
                    "openai".to_string(),
                    ProviderConfig {
                        provider_type: ProviderType::OpenAiCompatible,
                        endpoint: Some("https://api.openai.com/v1/chat/completions".to_string()),
                        api_key: Some("sk-test".to_string()),
                        model: Some("gpt-4o".to_string()),
                        cli_path: None,
                        cli_args: None,
                    },
                )]),
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: ServerConfig {
                max_buffer_lines: 500,
                socket_path: None,
                boundary_strategy: BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
            session: SessionConfig::default(),
            observability: ObservabilityConfig::default(),
            aicd: AicdConfig::default(),
            mcp: McpConfig::default(),
            rca: RcaConfig::default(),
            outbound: OutboundConfig::default(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn legacy_app_config_without_session_section_deserializes() {
        // Phase 4: 기존 config.toml에 [session] 섹션이 없어도 default(Hybrid)로 채워져야 한다.
        let toml_str = r#"
[llm]
default_provider = "openai"
lang = "korean"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.session.capture_mode, SessionCaptureMode::Hybrid);
    }

    #[test]
    fn aicd_webhook_config_defaults_are_safe() {
        // SRE R2: webhook은 기본 비활성 + localhost 바인드 + 보수적 한도.
        let w = AicdWebhookConfig::default();
        assert!(!w.enabled, "webhook은 기본 비활성(opt-in)");
        assert_eq!(w.listen_addr, "127.0.0.1:9099", "기본 바인드는 localhost");
        assert!(w.secret.is_none());
        assert_eq!(w.rate_limit_per_min, 10);
        assert_eq!(w.dedup_ttl_secs, 300);
        assert!(w.auto_diagnose);
    }

    #[test]
    fn legacy_config_without_aicd_section_defaults_disabled() {
        // [aicd] 섹션이 없는 레거시 config도 default(비활성)로 채워져야 한다.
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.aicd.webhook.enabled);
        assert_eq!(cfg.aicd.webhook.listen_addr, "127.0.0.1:9099");
    }

    #[test]
    fn aicd_webhook_section_parses() {
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"

[aicd.webhook]
enabled = true
listen_addr = "127.0.0.1:9200"
secret = "s3cr3t"
rate_limit_per_min = 30
dedup_ttl_secs = 600
auto_diagnose = false
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.aicd.webhook.enabled);
        assert_eq!(cfg.aicd.webhook.listen_addr, "127.0.0.1:9200");
        assert_eq!(cfg.aicd.webhook.secret.as_deref(), Some("s3cr3t"));
        assert_eq!(cfg.aicd.webhook.rate_limit_per_min, 30);
        assert_eq!(cfg.aicd.webhook.dedup_ttl_secs, 600);
        assert!(!cfg.aicd.webhook.auto_diagnose);
    }

    #[test]
    fn aicd_exporter_defaults_disabled_when_absent() {
        // [aicd.exporter] 섹션이 없으면 exporter는 비활성 default여야 한다(회귀 0).
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.aicd.exporter.enabled);
        assert_eq!(cfg.aicd.exporter.interval_secs, 60);
        assert!(cfg.aicd.exporter.endpoint.is_empty());
        assert!(cfg.aicd.exporter.token.is_none());
        // t7: events/connections 하위 플래그도 [aicd.exporter] 섹션 부재 시 안전한 기본값이어야 한다.
        assert!(cfg.aicd.exporter.events_enabled, "events는 기본 활성(부모 게이트가 실제 gate)");
        assert!(cfg.aicd.exporter.connections_enabled, "connections도 기본 활성(부모 게이트가 실제 gate)");
        assert_eq!(cfg.aicd.exporter.connections_interval_secs, 60);
        // t8: spool 기본값도 섹션 부재 시 안전한 기본으로 채워져야 한다.
        assert_eq!(cfg.aicd.exporter.spool_max_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.aicd.exporter.spool_drain_batch_limit, 20);
        // changes: 프로세스 생명주기 전이. 부모 게이트가 실제 gate이므로 기본 활성.
        assert!(cfg.aicd.exporter.changes_enabled, "changes도 기본 활성(부모 게이트가 실제 gate)");
        assert_eq!(
            cfg.aicd.exporter.changes_interval_secs, 30,
            "connections(60s)보다 짧아야 짧게 살다 간 프로세스를 덜 놓친다"
        );
    }

    #[test]
    fn aicd_exporter_events_connections_flags_default_true_when_absent_from_partial_section() {
        // [aicd.exporter]는 있지만 events_enabled/connections_enabled/connections_interval_secs가
        // 없는 레거시(t6 시점) config — 새 필드는 #[serde(default)]로 안전하게 채워져야 한다.
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"

[aicd.exporter]
enabled = true
endpoint = "http://127.0.0.1:4318"
interval_secs = 15
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.aicd.exporter.enabled);
        assert_eq!(cfg.aicd.exporter.interval_secs, 15);
        assert!(cfg.aicd.exporter.events_enabled);
        assert!(cfg.aicd.exporter.connections_enabled);
        assert_eq!(cfg.aicd.exporter.connections_interval_secs, 60);
    }

    #[test]
    fn aicd_exporter_events_connections_flags_can_be_disabled_individually() {
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"

[aicd.exporter]
enabled = true
endpoint = "http://127.0.0.1:4318"
events_enabled = false
connections_enabled = false
connections_interval_secs = 120
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.aicd.exporter.events_enabled);
        assert!(!cfg.aicd.exporter.connections_enabled);
        assert_eq!(cfg.aicd.exporter.connections_interval_secs, 120);
    }

    #[test]
    fn aicd_exporter_section_parses() {
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"

[aicd.exporter]
enabled = true
endpoint = "http://127.0.0.1:4318"
token = "otlp-token"
interval_secs = 15
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.aicd.exporter.enabled);
        assert_eq!(cfg.aicd.exporter.endpoint, "http://127.0.0.1:4318");
        assert_eq!(cfg.aicd.exporter.token.as_deref(), Some("otlp-token"));
        assert_eq!(cfg.aicd.exporter.interval_secs, 15);
    }

    #[test]
    fn aicd_exporter_spool_fields_can_be_overridden() {
        // t8: spool_max_bytes/spool_drain_batch_limit도 다른 exporter 필드와 동일하게 명시적으로
        // 오버라이드 가능해야 한다.
        let toml_str = r#"
[llm]
default_provider = "openai"

[server]
max_buffer_lines = 500
[server.boundary_strategy]
method = "prompt_marker"

[aicd.exporter]
enabled = true
endpoint = "http://127.0.0.1:4318"
spool_max_bytes = 1048576
spool_drain_batch_limit = 5
"#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.aicd.exporter.spool_max_bytes, 1_048_576);
        assert_eq!(cfg.aicd.exporter.spool_drain_batch_limit, 5);
    }

    #[test]
    fn capture_quality_hint_silent_for_full_output() {
        let rec = CommandRecord {
            command: Some("ls".into()),
            capture_quality: CaptureQuality::FullOutput,
            ..Default::default()
        };
        assert!(capture_quality_hint(&rec, SessionCaptureMode::Pty).is_none());
    }

    #[test]
    fn capture_quality_hint_metadata_only_suggests_run() {
        let rec = CommandRecord {
            command: Some("cargo build".into()),
            capture_quality: CaptureQuality::MetadataOnly,
            ..Default::default()
        };
        let msg = capture_quality_hint(&rec, SessionCaptureMode::Hook).unwrap();
        assert!(msg.contains("metadata-only"));
        assert!(msg.contains("aic run"));
    }

    #[test]
    fn capture_quality_hint_hybrid_mode_message_differs() {
        let rec = CommandRecord {
            command: Some("cargo build".into()),
            capture_quality: CaptureQuality::MetadataOnly,
            ..Default::default()
        };
        let hybrid = capture_quality_hint(&rec, SessionCaptureMode::Hybrid).unwrap();
        let hook = capture_quality_hint(&rec, SessionCaptureMode::Hook).unwrap();
        assert_ne!(hybrid, hook, "hybrid 메시지는 hook 메시지와 달라야 한다");
    }

    #[test]
    fn capture_quality_hint_truncated_and_binary() {
        let trunc = CommandRecord {
            capture_quality: CaptureQuality::TruncatedOutput,
            ..Default::default()
        };
        let msg = capture_quality_hint(&trunc, SessionCaptureMode::Pty).unwrap();
        assert!(msg.contains("일부만 저장"), "truncated hint: {msg}");

        let bin = CommandRecord {
            capture_quality: CaptureQuality::BinaryOmitted,
            ..Default::default()
        };
        let msg = capture_quality_hint(&bin, SessionCaptureMode::Pty).unwrap();
        assert!(msg.contains("binary"), "binary hint: {msg}");
    }

    #[test]
    fn short_labels_are_stable() {
        assert_eq!(CaptureMode::Pty.short_label(), "pty");
        assert_eq!(CaptureMode::Hook.short_label(), "hook");
        assert_eq!(CaptureMode::ExplicitCapture.short_label(), "run");
        assert_eq!(CaptureQuality::FullOutput.short_label(), "full");
        assert_eq!(CaptureQuality::MetadataOnly.short_label(), "meta");
        assert_eq!(CaptureQuality::TruncatedOutput.short_label(), "trunc");
        assert_eq!(CaptureQuality::BinaryOmitted.short_label(), "bin");
    }

    #[test]
    fn format_duration_ms_ranges() {
        assert_eq!(format_duration_ms(0), "0ms");
        assert_eq!(format_duration_ms(999), "999ms");
        assert_eq!(format_duration_ms(1_300), "1.3s");
        assert_eq!(format_duration_ms(59_949), "59.9s");
        assert_eq!(format_duration_ms(123_000), "2m03s");
    }

    #[test]
    fn command_record_legacy_json_defaults_new_fields() {
        let legacy = r#"{
            "command": "cargo build",
            "exit_code": 1,
            "output_lines": [],
            "timestamp": "2026-01-01T00:00:00Z"
        }"#;
        let record: CommandRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(record.cwd, None);
        assert_eq!(record.duration_ms, None);
    }

    #[test]
    fn provider_type_variants_serialize() {
        for (variant, expected) in [
            (ProviderType::OpenAiCompatible, "\"OpenAiCompatible\""),
            (ProviderType::Groq, "\"Groq\""),
            (ProviderType::Anthropic, "\"Anthropic\""),
            (ProviderType::CliBackend, "\"CliBackend\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn analysis_result_serialize_roundtrip() {
        let result = AnalysisResult {
            explanation: "파일을 찾을 수 없습니다".to_string(),
            suggested_command: Some("ls /correct/path".to_string()),
            additional_info: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
