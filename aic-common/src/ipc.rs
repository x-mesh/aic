//! IPC 프로토콜 타입 및 Length-prefixed framing 유틸리티

use crate::{CommandRecord, LogLine, SessionInfo};
use serde::{Deserialize, Serialize};

// ── IPC Request / Response ─────────────────────────────────────

/// IPC 프레임 payload의 최대 허용 크기. 4-byte length prefix 디코딩 직후 buffer를
/// 할당하기 전에 이 값을 초과하면 거절해 OOM/DoS를 방지한다. 16 MiB는 가장 큰 record
/// (FullOutput byte cap 256 KiB + JSON overhead)도 충분히 수용할 수 있다.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// 클라이언트 → 데몬 요청 메시지 (externally tagged JSON).
///
/// `Ping`/`GetMetrics`는 양 데몬(`aic-session`, `aicd`) 모두에서 의미를 가진다.
/// `GetLastCommand`/`GetRecentLines`는 세션 단위 데이터라 `aicd`에서는 거부된다.
/// `ListSessions`/`Shutdown`은 `aicd` control plane 전용이며, 세션 데몬은
/// graceful Error로 응답한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcRequest {
    GetLastCommand,
    GetRecentLines {
        count: usize,
    },
    GetRecentCommands {
        count: usize,
    },
    /// 세션 ring buffer에서 record id prefix로 일치하는 record를 모두 반환한다.
    /// `aic --record <prefix>`/`aic fix --record`/`aic learn --record`가 200개를
    /// 폴링해 client-side filter하던 비효율을 제거한다.
    FindRecordByPrefix {
        prefix: String,
    },
    /// 세션에 사용자 label을 붙이거나 제거한다 (label=None이면 untag).
    /// `aic session tag <id> <label>` / `aic session untag <id>`가 사용한다.
    TagSession {
        id: String,
        label: Option<String>,
    },
    /// 외부에서 만든 CommandRecord를 세션 ring buffer에 등록한다.
    /// `aic run -- ...`가 만든 ExplicitCapture record를 history/--record/fix
    /// 흐름에 통합하기 위한 entry point. record.id가 비어 있으면 ring buffer
    /// push 시 자동으로 부여된다.
    ///
    /// 이 variant는 **세션 local socket** 경로 전용이다 (aic-session의 `UdsServer`가
    /// 자기 session_id를 이미 알고 있으므로 record만 보낸다). `aicd` Control_UDS에서는
    /// session_id 라우팅이 필요해 [`IpcRequest::RegisterRecordForSession`]을 사용한다
    /// (R12.5 backwards-compat을 위해 본 variant는 유지).
    RegisterRecord(CommandRecord),
    /// `aicd` CommandRecordStore에 세션별로 record를 등록한다 (Phase 3.1 Dual-Write).
    ///
    /// `record.capture_mode`에 따라 `push_pty` 또는 `push_explicit`으로 라우팅되며,
    /// `Hook` 모드는 `CommandStarted`/`CommandFinished` 경로를 사용해야 하므로 거부된다.
    RegisterRecordForSession {
        session_id: String,
        record: CommandRecord,
    },
    /// `aicd` hook event store에서 특정 세션의 마지막 metadata-only command를 조회한다.
    GetLastCommandForSession {
        id: String,
    },
    /// `aicd` CommandRecordStore에서 특정 세션의 최근 `count`개 record를 조회한다 (R13.1).
    ///
    /// Phase 3.1의 `aic history` 및 Phase 3.2 client default read path에서 사용된다.
    /// 응답은 시간순(oldest→newest) `CommandRecords`. 해당 session_id에 record가
    /// 하나도 없으면 빈 Vec를 포함하는 `CommandRecords`로 응답한다 — client가
    /// "no records found" UI를 직접 결정할 수 있도록.
    GetRecentCommandsForSession {
        id: String,
        count: usize,
    },
    /// `aicd` CommandRecordStore에서 특정 세션의 최근 record들을 시간순(oldest→newest)
    /// 으로 나열하고 `output_lines`를 flatten한 뒤 마지막 `count` 라인만 `Lines`로
    /// 반환한다 (R13.1, R4.4).
    ///
    /// Phase 3.2 client default read path가 `GetRecentLines { count }`를 aicd로
    /// 라우팅할 때 사용된다. 세션에 record가 없거나 `output_lines`가 모두 비어 있으면
    /// 빈 Vec를 `Lines`로 반환한다 — list-op 성격에 맞춘다.
    GetRecentLinesForSession {
        id: String,
        count: usize,
    },
    /// `aicd` CommandRecordStore에서 특정 세션의 record id prefix 검색 결과를
    /// 시간순으로 반환한다 (R13.1, R4.4).
    ///
    /// 세션이 없거나 매칭이 없으면 빈 `CommandRecords`를 반환한다.
    FindRecordByPrefixForSession {
        id: String,
        prefix: String,
    },
    Ping,
    GetMetrics,
    /// 실행 중인 데몬 바이너리의 빌드 identity를 요청한다.
    ///
    /// `make install`/`aic update`는 디스크의 binary만 교체하므로, 재시작 전까지는
    /// **구버전 aicd가 그대로 돈다**. 디스크를 stat해서는 이걸 알 수 없어(경로가 같다)
    /// 실행 중인 프로세스에 직접 묻는다. 이 variant를 모르는 구버전 데몬은
    /// `Error { message: "unknown request: ..." }`로 graceful 응답하므로, 그 응답
    /// 자체가 "GetVersion 이전 빌드가 돌고 있다"는 신호가 된다.
    GetVersion,
    /// `aicd`에 등록된 세션 목록을 요청한다 (Phase 1.2~1.3).
    ListSessions,
    /// 오래된 inactive(detached/stopping/stopped/failed) 세션을 registry에서 제거한다.
    PruneSessions {
        older_than_secs: u64,
    },
    /// `aicd`를 graceful 종료 시킨다 (active sessions 정리는 향후 sub-step).
    Shutdown,
    /// 세션을 `aicd` registry에 등록한다 (Phase 1.3).
    /// `aic-session`이 시작 직후 보낸다. 같은 id가 이미 있으면 덮어쓴다.
    RegisterSession(SessionInfo),
    /// 세션을 `aicd` registry에서 제거한다 (Phase 1.3).
    /// `aic-session`이 정상 종료 직전에 보낸다.
    UnregisterSession {
        id: String,
    },
    /// 실행 중인 세션이 아직 살아 있음을 `aicd` registry에 알린다.
    HeartbeatSession {
        id: String,
        seen_at: chrono::DateTime<chrono::Utc>,
        cwd: Option<std::path::PathBuf>,
    },
    /// 특정 세션에 graceful 종료 신호를 보낸다 (Phase 2.1).
    ///
    /// 현재 구현: `aicd`가 registry에서 PID를 찾아 `SIGTERM`을 보낸다.
    /// 향후 PTY ownership을 `aicd`가 가져오면 `aicd`가 직접 child를 종료한다.
    StopSession {
        id: String,
    },
    /// shell hook이 보내는 command-start 이벤트 (Phase 3).
    ///
    /// hook mode에서 `preexec`/`DEBUG trap`이 발화하며, 출력은 캡처하지 않고
    /// metadata만 등록한다. `aicd` 미실행 시 hook은 silent skip.
    CommandStarted {
        session_id: String,
        command_id: String,
        command: String,
        cwd: Option<std::path::PathBuf>,
        shell: Option<String>,
        pid: u32,
        started_at: chrono::DateTime<chrono::Utc>,
    },
    /// shell hook이 보내는 command-finish 이벤트 (Phase 3).
    CommandFinished {
        session_id: String,
        command_id: String,
        exit_code: i32,
        finished_at: chrono::DateTime<chrono::Utc>,
        duration_ms: u64,
    },
    /// chat/agent에서 일어난 **주목할 만한 행위**를 aicd로 보낸다 (OTLP `aic.agent` scope).
    ///
    /// chat은 단명하는 `aic-client` 프로세스라 collector 연결·spool·backoff를 직접 들 수 없다.
    /// 그래서 `_hook-event`가 command를 aicd로 넘기는 것과 같은 구조로, 행위를 aicd에 넘기고
    /// 상주 데몬의 exporter가 무유실 전송을 책임진다.
    ///
    /// 모든 행위를 보내지 않는다 — 시스템을 **바꾼** 행위(`tool.run_command`)와 **위험 신호**
    /// (`risk.denied`, `finding.created`)만 보낸다. 읽기 도구(read_file/grep/glob)까지 실으면
    /// 노이즈만 커지고 RCA에 쓸모가 없다.
    AgentEvent(AgentEvent),
    /// OTLP exporter가 실제로 collector에 닿고 있는지 묻는다.
    ///
    /// exporter는 aicd 안에서 조용히 돌기 때문에, chat을 쓰는 사람은 자기 행위가 서버로 나가는지
    /// 확인할 방법이 없다 — push가 계속 실패해도 aicd 로그에만 남는다. chat status bar가 이걸
    /// 주기적으로 물어 "지금 나가고 있다/밀리고 있다"를 눈에 보이게 한다.
    GetExporterStatus,
    /// spool에 밀린 배치를 **지금 즉시** 전량 드레인하라고 요청한다(chat `/flush`). 평소 드레인은
    /// tick당 `spool_drain_batch_limit`(기본 20)로 속도 제한돼, 큰 백로그는 collector 복구 후에도
    /// 몇 시간에 걸쳐 빠진다 — 사용자가 "지금 밀어 넣어도 된다"고 판단하면 이 요청으로 rate-limit을
    /// 한 번 우회한다. exporter가 꺼져 있으면 `Error`가 온다.
    FlushSpool,
    /// `aic-client`(chat 등)의 자체 tracing 로그를 aicd로 흘려보낸다 (RFC-006 t11).
    ///
    /// `aic-client`는 `AgentEvent`와 같은 이유로 단명 프로세스라 OTLP exporter를 직접 들 수
    /// 없다 — 그래서 주기(2s) 또는 종료 시점(`libc::atexit`)에 버퍼를 모아 aicd로 넘기고,
    /// 상주 데몬의 exporter가 무유실 전송을 책임진다. `aicd` control plane 전용이라
    /// `aic-session`은 이 variant를 거부한다.
    PushLogLines {
        lines: Vec<LogLine>,
    },
    /// 최근 프로세스 인벤토리 변화(생성/소멸/변경)를 **최신순**으로 `count`개까지 돌려준다.
    ///
    /// aicd가 host metrics tick마다 전수 프로세스를 이전 tick과 diff해 링에 쌓아 둔 것을 읽는다
    /// — chat이 "방금 뭐가 떴다 죽었나"를 폴링으로 확인하는 경로다. OTLP 전송
    /// (`aic.process.inventory`)과 **같은 관측이지만 게이트가 다르다**: 이쪽은 collector 설정과
    /// 무관하게 채워지므로 `process_inventory_enabled=false`여도 조회된다.
    GetRecentProcessChanges {
        count: usize,
    },
}

/// chat/agent의 한 행위. `kind`가 문자열이라 새 행위를 추가해도 IPC 스키마가 바뀌지 않는다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    /// 행위 종류 — [`AGENT_KIND_TOOL_RUN_COMMAND`] 등. OTLP attr `aic.agent.kind`가 된다.
    pub kind: String,
    /// 사람이 읽을 요약. LogRecord body가 된다 (예: 실행한 명령, 차단 사유, finding 제목).
    /// **호출부가 redaction을 마친 문자열을 넘긴다** — 인코딩 단계에서 한 번 더 redact되지만
    /// (idempotent), 원본이 데몬 경계를 넘지 않게 하는 게 1차 방어선이다.
    pub summary: String,
    /// ERROR / WARN / INFO. 미지의 값은 인코딩 시 INFO로 떨어진다.
    pub severity: String,
    /// 부가 속성 — `aic.agent.*` prefix로 OTLP attr에 실린다 (예: exit_code, tool, rule).
    #[serde(default)]
    pub attrs: std::collections::BTreeMap<String, String>,
    /// 행위 발생 시각.
    pub ts: chrono::DateTime<chrono::Utc>,
}

/// agent가 셸 명령을 실행했다 — 시스템을 바꿨을 수 있는 유일한 도구라 항상 보낸다.
pub const AGENT_KIND_TOOL_RUN_COMMAND: &str = "tool.run_command";
/// risk_guard가 명령을 차단했다 — 위험한 시도가 있었다는 보안 신호.
pub const AGENT_KIND_RISK_DENIED: &str = "risk.denied";
/// 진단이 finding을 만들었다 — severity를 가진 사건의 시작점.
pub const AGENT_KIND_FINDING_CREATED: &str = "finding.created";
/// 사람이 "지금 이 순간을 남긴다"고 판단해 기록했다 — 임계가 못 잡는 것을 사람이 잡는 경로.
pub const AGENT_KIND_SNAPSHOT_RECORDED: &str = "snapshot.recorded";

/// 데몬 → 클라이언트 응답 메시지 (externally tagged JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcResponse {
    CommandData(CommandRecord),
    CommandRecords(Vec<CommandRecord>),
    Lines(Vec<String>),
    Pong,
    Metrics(MetricsSnapshot),
    /// `ListSessions` 응답 — `aicd` registry 기준 세션 목록.
    Sessions(Vec<SessionInfo>),
    /// `PruneSessions` 응답 — 제거된 세션 수.
    PrunedSessions {
        count: usize,
    },
    /// `GetVersion` 응답 — 응답한 데몬 **프로세스**의 빌드 identity.
    Version(DaemonVersion),
    /// `GetExporterStatus` 응답. exporter가 꺼져 있으면 `enabled: false`인 기본값이 온다 —
    /// "꺼짐"과 "켜졌는데 실패 중"은 사용자에게 전혀 다른 상태라 응답 자체를 생략하지 않는다.
    ExporterStatus(ExporterStatus),
    /// `FlushSpool` 응답 — 즉시 드레인 결과.
    SpoolFlushed(SpoolFlushResult),
    /// `GetRecentProcessChanges` 응답 — 최신순 프로세스 변화 목록. exporter task가 안 떠서 링
    /// 자체가 없으면 빈 목록이 온다("변화 없음"과 "수집 안 함"을 여기서 구분하지 않는다 — 구분이
    /// 필요하면 `GetExporterStatus`가 답한다).
    ProcessChanges(Vec<ProcessChange>),
    Error {
        message: String,
    },
}

/// 프로세스 인벤토리 변화 하나 — aicd가 최근분을 링에 들고 chat이 IPC로 읽어 간다.
///
/// OTLP `aic.process.inventory` scope로 나가는 것과 **같은 관측**이지만, 이쪽은 로컬 실시간
/// 확인용이라 collector 설정과 무관하게 채워진다. `(pid, start_time)`이 안정 식별자다 — pid는
/// 재사용되므로 단독으로는 짧게 죽고 재사용된 프로세스가 섞인다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessChange {
    /// `"add"` | `"remove"` | `"change"`.
    pub op: String,
    pub pid: i64,
    /// 부모 pid(프로세스 트리). 미상이면 0.
    pub ppid: i64,
    /// 시작 시각(unix epoch 초). 미상이면 0.
    pub start_time: u64,
    /// 실행 파일명(comm) — argv가 아니라 secret 유입 위험이 없다.
    pub name: String,
    /// 소유자 uid. Linux에서 add 때만 채운다.
    pub uid: Option<u32>,
    /// 컨테이너 id. Linux에서 add 때만 채운다.
    pub container_id: Option<String>,
    /// aicd가 이 변화를 **관측한** 시각(unix epoch 초). 프로세스 시작 시각이 아니라 tick 시각이라,
    /// 최대 tick 주기만큼 늦을 수 있다(폴링의 구조적 한계 — 그 사이 떴다 죽은 건 아예 안 보인다).
    pub observed_at: u64,
}

/// `/flush` 즉시 드레인 결과. `remaining`이 0이 아니면(collector가 도중에 실패) 남은 배치는 다음
/// 주기 드레인으로 넘어간다.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SpoolFlushResult {
    /// 이번에 성공적으로 재전송+삭제한 배치 수.
    pub drained: u64,
    /// collector가 영구 거부(4xx)해 버린 배치 수.
    pub rejected: u64,
    /// 드레인 후 spool에 남은 배치 수(0이면 완전히 비었다).
    pub remaining: u64,
}

/// OTLP exporter의 전송 건강 상태.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ExporterStatus {
    /// exporter task가 떠 있는지. false면 나머지 필드는 의미 없다(config off 또는 endpoint 미설정).
    ///
    /// **이건 부모 게이트(`[aicd.exporter] enabled`)일 뿐이다.** 하위 signal별 게이트
    /// (`agent_enabled` 등)는 이 값에 반영되지 않으므로, agent 이벤트가 실제로 나가는지는
    /// [`Self::agent_enabled`]를 봐야 한다.
    pub enabled: bool,
    /// **agent exporter task가 실제로 떠 있는지**(`aic.agent` scope — chat `/record now` 등).
    ///
    /// 왜 별도 필드인가: `enabled`(부모 게이트)가 true여도 `[aicd.exporter] agent_enabled = false`면
    /// `serve_agent` task가 spawn되지 않고, `AgentEventBus`에 **구독자가 없어 publish가 조용히
    /// 버려진다**. 그 상태를 chat이 IPC로 알 방법이 없으면 `/record now`는 "기록됨"이라고 말하면서
    /// 사람이 남긴 순간을 잃는다 — 가장 나쁜 종류의 유실이다.
    ///
    /// `None` = **모름**(이 필드를 모르는 구버전 aicd). "확실히 꺼짐"(`Some(false)`)과 구분해야
    /// 하므로 bool로 뭉개지 않는다 — 모름을 "꺼짐"으로 읽으면 멀쩡한 구버전에 헛경고를 내고,
    /// "켜짐"으로 읽으면 진짜 유실을 놓친다. 호출부가 둘을 나눠 판단하게 둔다.
    #[serde(default)]
    pub agent_enabled: Option<bool>,
    /// **config에서 agent exporter를 켜 두었는가**(`[aicd.exporter] agent_enabled`).
    ///
    /// [`Self::agent_enabled`](=실제로 살아있는가)와 **다른 축이다**. 둘을 합쳐야 사용자에게 맞는
    /// 조치를 안내할 수 있다:
    /// - `configured=false` → "설정이 꺼져 있다" → `agent_enabled = true`로 켜라.
    /// - `configured=true` + `live=false` → "설정은 켰는데 **뜨지 못했다**"(endpoint 오류·spool 실패·
    ///   task 사망) → **aicd 로그를 봐라**. 이때 "설정을 켜라"고 안내하면 이미 켜 둔 사용자가
    ///   시키는 대로 해도 안 고쳐진다(오진).
    ///
    /// `None` = 모름(이 필드를 모르는 구버전 aicd).
    #[serde(default)]
    pub agent_configured: Option<bool>,
    /// collector base URL(표시용).
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub push_ok_total: u64,
    #[serde(default)]
    pub push_fail_total: u64,
    /// 마지막 push 성공 후 경과 초. `None`이면 **한 번도 성공한 적 없음** — "방금 성공(0초)"과
    /// 구분되어야 하므로 0으로 뭉개지 않는다.
    #[serde(default)]
    pub last_ok_secs_ago: Option<u64>,
    /// 전송 못 하고 spool에 밀려 있는 배치 수. 0이 아니면 collector에 못 닿고 있다는 뜻이다.
    #[serde(default)]
    pub spool_batches: u64,
    /// spool 용량 상한을 넘겨 **버린** 배치 수. 0이 아니면 데이터가 실제로 유실됐다.
    #[serde(default)]
    pub spool_dropped: u64,
}

/// 실행 중인 데몬 바이너리의 빌드 identity (`GetVersion` 응답).
///
/// 세 필드 모두 데몬이 자기 build.rs가 주입한 값을 그대로 싣는다 — 디스크의 binary가
/// 아니라 **지금 메모리에서 도는 코드**의 정체다. client는 이걸 자기 값과 비교해
/// 설치 후 재시작을 빠뜨린 skew를 잡아낸다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonVersion {
    /// `CARGO_PKG_VERSION`.
    pub version: String,
    /// `AIC_BUILD_COMMIT` — short hash(`*` suffix=dirty). git 밖 빌드(릴리스 tarball,
    /// crates.io)는 빈 문자열이라, 비교 시 이 경우는 version만으로 판정해야 한다.
    #[serde(default)]
    pub commit: String,
    /// `AIC_BUILD_INFO` — `--version`이 출력하는 완성 문자열(빌드 시각 포함).
    /// 표시 전용 — 빌드 시각이 섞여 있어 동일성 판정에는 쓰지 않는다.
    #[serde(default)]
    pub build_info: String,
}

/// 데몬 metric 스냅샷 (`aic top`/`aic-session metrics` 응답용).
///
/// Phase 3 centralized-record-store 도입 이후 `aicd` 측 metric(`central_store_push_total`,
/// `attach_connections`, `attach_open_total`)과 `aic-session` 측 metric(`dropped_bytes`,
/// `attach_reconnect_total`)이 같은 snapshot에 합쳐진다. 구 버전 데몬이 내려 주는 JSON에는
/// 해당 필드가 없을 수 있어 모두 `#[serde(default)]`로 backwards-compatible 하게 유지한다.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// 데몬 시작 이후 경과 시간(초)
    pub uptime_secs: u64,
    /// 데몬 PID
    pub pid: u32,
    /// 누적 IPC 요청 수
    pub ipc_request_count: u64,
    /// Ring Buffer 현재 사용 라인 수
    pub rb_used: usize,
    /// Ring Buffer 최대 라인 수
    pub rb_capacity: usize,
    /// 마지막 명령어 종료 후 경과 초 (없으면 None)
    pub last_command_secs_ago: Option<u64>,
    /// `aicd` CommandRecordStore에 push된 record 누적 수 (R14.1).
    #[serde(default)]
    pub central_store_push_total: u64,
    /// `aicd` Attach_UDS의 현재 활성 연결 수 (R14.2, gauge).
    #[serde(default)]
    pub attach_connections: u64,
    /// `aicd`가 수신한 `AttachOpen` 프레임 누적 수 (R14.3).
    #[serde(default)]
    pub attach_open_total: u64,
    /// `aic-session`에서 backpressure로 drop된 byte 누적 수 (R14.4).
    #[serde(default)]
    pub dropped_bytes: u64,
    /// `aic-session`의 Attach_UDS 재연결 시도 누적 수 (R14.5).
    #[serde(default)]
    pub attach_reconnect_total: u64,
}

// ── Length-prefixed framing ────────────────────────────────────

/// payload 앞에 4-byte u32 big-endian 길이 prefix를 붙여 반환한다.
pub fn encode_frame(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

/// 4-byte u32 big-endian 길이 prefix를 파싱하여 (전체 프레임 크기, payload 슬라이스)를 반환한다.
///
/// - `data`가 4바이트 미만이면 에러
/// - prefix가 가리키는 payload가 `data`에 충분히 없으면 에러
pub fn decode_frame(data: &[u8]) -> anyhow::Result<(usize, &[u8])> {
    if data.len() < 4 {
        anyhow::bail!(
            "프레임 헤더가 부족합니다: 최소 4바이트 필요, {}바이트 수신",
            data.len()
        );
    }

    let payload_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let total_frame_size = 4 + payload_len;

    if data.len() < total_frame_size {
        anyhow::bail!(
            "프레임 데이터가 부족합니다: {}바이트 필요, {}바이트 수신",
            total_frame_size,
            data.len()
        );
    }

    Ok((total_frame_size, &data[4..total_frame_size]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // ── ExporterStatus 와이어 호환 ─────────────────────────────

    #[test]
    fn exporter_status_from_old_daemon_has_unknown_agent_flag() {
        // 구버전 aicd는 `agent_enabled`를 모른다 — 그 응답에는 필드가 아예 없다. 이때 `None`(모름)이
        // 나와야 한다. 만약 이걸 `false`(꺼짐)로 역직렬화하면, 멀쩡히 동작하는 구버전 사용자에게
        // `/record now`가 매번 "agent exporter가 꺼져 있다"고 헛경고를 낸다.
        let old_wire = r#"{"enabled":true,"endpoint":"http://x:4318","push_ok_total":3,
            "push_fail_total":0,"last_ok_secs_ago":1,"spool_batches":0,"spool_dropped":0}"#;
        let s: ExporterStatus = serde_json::from_str(old_wire).unwrap();
        assert!(s.enabled);
        assert_eq!(
            s.agent_enabled, None,
            "필드 없는 구버전 응답은 '모름'이어야 한다(꺼짐이 아니다)"
        );
        assert_eq!(
            s.agent_configured, None,
            "구버전은 config 축도 모른다 — 모름이어야 한다"
        );
    }

    #[test]
    fn exporter_status_separates_configured_from_live() {
        // 두 축은 독립이다: "설정은 켰는데 뜨지 못했다"(configured=true, live=false)를 표현할 수
        // 있어야 클라이언트가 "설정을 켜라"는 오진 대신 "aicd 로그를 보라"고 안내한다.
        let s = ExporterStatus {
            enabled: true,
            agent_enabled: Some(false),
            agent_configured: Some(true),
            ..Default::default()
        };
        let back: ExporterStatus =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.agent_enabled, Some(false));
        assert_eq!(back.agent_configured, Some(true));
        assert_eq!(back, s);
    }

    #[test]
    fn exporter_status_roundtrips_agent_flag() {
        // 신버전끼리는 값이 그대로 왕복한다 — Some(false)(확실히 꺼짐)가 None(모름)으로 뭉개지면
        // 진짜 유실을 보고하지 못한다.
        for flag in [Some(true), Some(false), None] {
            let s = ExporterStatus {
                enabled: true,
                agent_enabled: flag,
                ..Default::default()
            };
            let json = serde_json::to_string(&s).unwrap();
            let back: ExporterStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back.agent_enabled, flag);
            assert_eq!(back, s);
        }
    }

    // ── IpcRequest 직렬화 ──────────────────────────────────────

    #[test]
    fn ipc_request_get_last_command_roundtrip() {
        let req = IpcRequest::GetLastCommand;
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_get_recent_lines_roundtrip() {
        let req = IpcRequest::GetRecentLines { count: 42 };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_ping_roundtrip() {
        let req = IpcRequest::Ping;
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_get_last_command_for_session_roundtrip() {
        let req = IpcRequest::GetLastCommandForSession {
            id: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_get_recent_commands_for_session_roundtrip() {
        let req = IpcRequest::GetRecentCommandsForSession {
            id: "deadbeef".to_string(),
            count: 20,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_get_recent_lines_for_session_roundtrip() {
        let req = IpcRequest::GetRecentLinesForSession {
            id: "deadbeef".to_string(),
            count: 200,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_find_record_by_prefix_for_session_roundtrip() {
        let req = IpcRequest::FindRecordByPrefixForSession {
            id: "deadbeef".to_string(),
            prefix: "ab12".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_push_log_lines_roundtrip() {
        let line = LogLine {
            source: "aic".to_string(),
            service: "aic-client".to_string(),
            severity: "INFO".to_string(),
            message: "hello".to_string(),
            attrs: std::collections::BTreeMap::new(),
            ts: Utc::now(),
            record_id: "log:deadbeef".to_string(),
        };
        let req = IpcRequest::PushLogLines { lines: vec![line] };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    // ── IpcResponse 직렬화 ─────────────────────────────────────

    #[test]
    fn ipc_response_command_data_roundtrip() {
        let record = CommandRecord {
            command: Some("cargo build".to_string()),
            exit_code: 1,
            output_lines: vec!["error[E0308]: mismatched types".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let resp = IpcResponse::CommandData(record);
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn ipc_response_lines_roundtrip() {
        let resp = IpcResponse::Lines(vec!["line1".into(), "line2".into()]);
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn ipc_response_pong_roundtrip() {
        let resp = IpcResponse::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn ipc_response_error_roundtrip() {
        let resp = IpcResponse::Error {
            message: "서버 내부 오류".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    // ── Metrics backwards-compatibility ────────────────────────

    #[test]
    fn metrics_snapshot_default_is_zero() {
        let snap = MetricsSnapshot::default();
        assert_eq!(snap.uptime_secs, 0);
        assert_eq!(snap.pid, 0);
        assert_eq!(snap.ipc_request_count, 0);
        assert_eq!(snap.rb_used, 0);
        assert_eq!(snap.rb_capacity, 0);
        assert_eq!(snap.last_command_secs_ago, None);
        assert_eq!(snap.central_store_push_total, 0);
        assert_eq!(snap.attach_connections, 0);
        assert_eq!(snap.attach_open_total, 0);
        assert_eq!(snap.dropped_bytes, 0);
        assert_eq!(snap.attach_reconnect_total, 0);
    }

    #[test]
    fn metrics_snapshot_deserializes_legacy_payload_without_new_fields() {
        // Phase 3 이전 데몬이 내려주던 payload 형태 (central_store/attach 필드 없음).
        // serde(default) 덕분에 여전히 deserialize 되어야 한다 (R14 backwards-compat).
        let legacy = r#"{
            "uptime_secs": 42,
            "pid": 12345,
            "ipc_request_count": 7,
            "rb_used": 3,
            "rb_capacity": 100,
            "last_command_secs_ago": 8
        }"#;
        let snap: MetricsSnapshot = serde_json::from_str(legacy).unwrap();
        assert_eq!(snap.uptime_secs, 42);
        assert_eq!(snap.pid, 12345);
        assert_eq!(snap.ipc_request_count, 7);
        assert_eq!(snap.rb_used, 3);
        assert_eq!(snap.rb_capacity, 100);
        assert_eq!(snap.last_command_secs_ago, Some(8));
        // 신규 필드는 기본값 0
        assert_eq!(snap.central_store_push_total, 0);
        assert_eq!(snap.attach_connections, 0);
        assert_eq!(snap.attach_open_total, 0);
        assert_eq!(snap.dropped_bytes, 0);
        assert_eq!(snap.attach_reconnect_total, 0);
    }

    #[test]
    fn metrics_snapshot_roundtrip_with_new_fields() {
        let snap = MetricsSnapshot {
            uptime_secs: 10,
            pid: 9,
            ipc_request_count: 3,
            rb_used: 1,
            rb_capacity: 64,
            last_command_secs_ago: Some(2),
            central_store_push_total: 11,
            attach_connections: 2,
            attach_open_total: 5,
            dropped_bytes: 4096,
            attach_reconnect_total: 1,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // ── Framing ────────────────────────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello, world!";
        let frame = encode_frame(payload);

        assert_eq!(frame.len(), 4 + payload.len());

        let (total_size, decoded) = decode_frame(&frame).unwrap();
        assert_eq!(total_size, frame.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_empty_payload() {
        let frame = encode_frame(b"");
        assert_eq!(frame, vec![0, 0, 0, 0]);

        let (total_size, decoded) = decode_frame(&frame).unwrap();
        assert_eq!(total_size, 4);
        assert_eq!(decoded, b"");
    }

    #[test]
    fn decode_insufficient_header() {
        let result = decode_frame(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_insufficient_payload() {
        // header가 10바이트 payload를 가리키지만 실제로는 2바이트만 존재
        let data = [0, 0, 0, 10, 0xAA, 0xBB];
        let result = decode_frame(&data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_with_trailing_data() {
        let payload = b"test";
        let mut data = encode_frame(payload);
        data.extend_from_slice(b"trailing");

        let (total_size, decoded) = decode_frame(&data).unwrap();
        assert_eq!(total_size, 4 + payload.len());
        assert_eq!(decoded, payload);
    }

    // ── JSON + Framing 통합 ────────────────────────────────────

    #[test]
    fn json_over_frame_roundtrip() {
        let req = IpcRequest::GetRecentLines { count: 100 };
        let json_bytes = serde_json::to_vec(&req).unwrap();
        let frame = encode_frame(&json_bytes);

        let (_total, payload) = decode_frame(&frame).unwrap();
        let decoded: IpcRequest = serde_json::from_slice(payload).unwrap();
        assert_eq!(req, decoded);
    }

    // ── Property-Based Tests ───────────────────────────────────
    // Feature: ac-cli-tool, Property 3: IPC Message Serialization Round-Trip
    // **Validates: Requirements 3.2**

    use proptest::prelude::*;

    /// CommandRecord 전략: 임의의 timestamp를 밀리초 단위 i64에서 생성
    fn arb_command_record() -> impl Strategy<Value = CommandRecord> {
        (
            proptest::option::of(any::<String>()),
            any::<i32>(),
            proptest::collection::vec(any::<String>(), 0..8),
            // 밀리초 범위: 0 ~ 4102444800000 (약 2100년)
            0i64..4_102_444_800_000i64,
        )
            .prop_map(|(command, exit_code, output_lines, ts_millis)| {
                let timestamp =
                    chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default();
                CommandRecord {
                    command,
                    exit_code,
                    output_lines,
                    timestamp,
                    ..Default::default()
                }
            })
    }

    /// `PushLogLines` proptest 전략. `record_id`/`message`는 임의 문자열이고
    /// `attrs`는 빈 map으로 고정한다(BTreeMap 임의 생성은 roundtrip 검증에 필요하지 않음).
    fn arb_log_line() -> impl Strategy<Value = LogLine> {
        (
            "[a-z]{1,16}",
            "[a-z-]{1,16}",
            "(ERROR|WARN|INFO|DEBUG)",
            "[a-zA-Z0-9 ]{0,64}",
            0i64..4_102_444_800_000i64,
            "[a-z0-9:]{1,32}",
        )
            .prop_map(
                |(source, service, severity, message, ts_millis, record_id)| LogLine {
                    source,
                    service,
                    severity,
                    message,
                    attrs: std::collections::BTreeMap::new(),
                    ts: chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default(),
                    record_id,
                },
            )
    }

    fn arb_ipc_request() -> impl Strategy<Value = IpcRequest> {
        prop_oneof![
            Just(IpcRequest::GetLastCommand),
            any::<usize>().prop_map(|count| IpcRequest::GetRecentLines { count }),
            any::<usize>().prop_map(|count| IpcRequest::GetRecentCommands { count }),
            "[0-9a-f]{1,16}".prop_map(|prefix| IpcRequest::FindRecordByPrefix { prefix }),
            Just(IpcRequest::Ping),
            Just(IpcRequest::GetMetrics),
            Just(IpcRequest::ListSessions),
            any::<u64>().prop_map(|older_than_secs| IpcRequest::PruneSessions { older_than_secs }),
            Just(IpcRequest::Shutdown),
            arb_session_info().prop_map(IpcRequest::RegisterSession),
            "[0-9a-f]{1,8}".prop_map(|id| IpcRequest::UnregisterSession { id }),
            (
                "[0-9a-f]{1,8}",
                0i64..4_102_444_800_000i64,
                proptest::option::of("[a-zA-Z0-9/_-]{1,64}".prop_map(std::path::PathBuf::from)),
            )
                .prop_map(|(id, ts, cwd)| IpcRequest::HeartbeatSession {
                    id,
                    seen_at: chrono::DateTime::from_timestamp_millis(ts).unwrap_or_default(),
                    cwd,
                }),
            "[0-9a-f]{1,8}".prop_map(|id| IpcRequest::GetLastCommandForSession { id }),
            ("[0-9a-f]{1,8}", any::<usize>())
                .prop_map(|(id, count)| IpcRequest::GetRecentCommandsForSession { id, count }),
            ("[0-9a-f]{1,8}", any::<usize>())
                .prop_map(|(id, count)| IpcRequest::GetRecentLinesForSession { id, count }),
            ("[0-9a-f]{1,8}", "[0-9a-f]{1,16}").prop_map(|(id, prefix)| {
                IpcRequest::FindRecordByPrefixForSession { id, prefix }
            }),
            "[0-9a-f]{1,8}".prop_map(|id| IpcRequest::StopSession { id }),
            ("[0-9a-f]{1,8}", proptest::option::of("[a-zA-Z0-9_-]{1,32}"),)
                .prop_map(|(id, label)| IpcRequest::TagSession { id, label }),
            arb_command_record().prop_map(IpcRequest::RegisterRecord),
            ("[0-9a-f]{1,8}", arb_command_record()).prop_map(|(session_id, record)| {
                IpcRequest::RegisterRecordForSession { session_id, record }
            }),
            (
                "[0-9a-f]{1,8}",
                "[0-9a-f]{1,16}",
                "[a-z ]{1,40}",
                proptest::option::of("[a-zA-Z0-9/_-]{1,32}".prop_map(std::path::PathBuf::from)),
                proptest::option::of("[a-zA-Z0-9/_-]{1,32}"),
                any::<u32>(),
                0i64..4_102_444_800_000i64,
            )
                .prop_map(|(session_id, command_id, command, cwd, shell, pid, ts)| {
                    IpcRequest::CommandStarted {
                        session_id,
                        command_id,
                        command,
                        cwd,
                        shell,
                        pid,
                        started_at: chrono::DateTime::from_timestamp_millis(ts).unwrap_or_default(),
                    }
                }),
            (
                "[0-9a-f]{1,8}",
                "[0-9a-f]{1,16}",
                any::<i32>(),
                0i64..4_102_444_800_000i64,
                any::<u64>(),
            )
                .prop_map(|(session_id, command_id, exit_code, ts, dur)| {
                    IpcRequest::CommandFinished {
                        session_id,
                        command_id,
                        exit_code,
                        finished_at: chrono::DateTime::from_timestamp_millis(ts)
                            .unwrap_or_default(),
                        duration_ms: dur,
                    }
                }),
            proptest::collection::vec(arb_log_line(), 0..8)
                .prop_map(|lines| IpcRequest::PushLogLines { lines }),
        ]
    }

    fn arb_session_state() -> impl Strategy<Value = crate::SessionState> {
        use crate::SessionState::*;
        prop_oneof![
            Just(Creating),
            Just(Attached),
            Just(Detached),
            Just(Stopping),
            Just(Stopped),
            Just(Failed),
        ]
    }

    fn arb_session_info() -> impl Strategy<Value = crate::SessionInfo> {
        (
            "[0-9a-f]{1,8}",
            any::<u32>(),
            arb_session_state(),
            0i64..4_102_444_800_000i64,
            proptest::option::of(0i64..4_102_444_800_000i64),
            proptest::option::of(0i64..4_102_444_800_000i64),
            proptest::option::of("[a-zA-Z0-9/_]{1,32}"),
            proptest::option::of("[a-zA-Z0-9/_-]{1,32}"),
            proptest::option::of("[a-zA-Z0-9/_-]{1,64}".prop_map(std::path::PathBuf::from)),
        )
            .prop_map(
                |(
                    id,
                    pid,
                    state,
                    ts_millis,
                    seen_millis,
                    command_millis,
                    attached_tty,
                    shell,
                    cwd,
                )| {
                    let created_at =
                        chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default();
                    let last_seen_at =
                        seen_millis.and_then(chrono::DateTime::from_timestamp_millis);
                    let last_command_at =
                        command_millis.and_then(chrono::DateTime::from_timestamp_millis);
                    crate::SessionInfo {
                        id,
                        pid,
                        state,
                        created_at,
                        last_seen_at,
                        last_command_at,
                        attached_tty,
                        shell,
                        cwd,
                        label: None,
                    }
                },
            )
    }

    fn arb_ipc_response() -> impl Strategy<Value = IpcResponse> {
        prop_oneof![
            arb_command_record().prop_map(IpcResponse::CommandData),
            proptest::collection::vec(arb_command_record(), 0..8)
                .prop_map(IpcResponse::CommandRecords),
            proptest::collection::vec(any::<String>(), 0..8).prop_map(IpcResponse::Lines),
            Just(IpcResponse::Pong),
            proptest::collection::vec(arb_session_info(), 0..8).prop_map(IpcResponse::Sessions),
            any::<usize>().prop_map(|count| IpcResponse::PrunedSessions { count }),
            any::<String>().prop_map(|message| IpcResponse::Error { message }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_ipc_request_json_roundtrip(req in arb_ipc_request()) {
            let json = serde_json::to_string(&req).unwrap();
            let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&req, &deserialized);
        }

        #[test]
        fn prop_ipc_response_json_roundtrip(resp in arb_ipc_response()) {
            let json = serde_json::to_string(&resp).unwrap();
            let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&resp, &deserialized);
        }

        #[test]
        fn prop_ipc_request_frame_roundtrip(req in arb_ipc_request()) {
            let json_bytes = serde_json::to_vec(&req).unwrap();
            let frame = encode_frame(&json_bytes);
            let (_total, payload) = decode_frame(&frame).unwrap();
            let decoded: IpcRequest = serde_json::from_slice(payload).unwrap();
            prop_assert_eq!(&req, &decoded);
        }

        #[test]
        fn prop_ipc_response_frame_roundtrip(resp in arb_ipc_response()) {
            let json_bytes = serde_json::to_vec(&resp).unwrap();
            let frame = encode_frame(&json_bytes);
            let (_total, payload) = decode_frame(&frame).unwrap();
            let decoded: IpcResponse = serde_json::from_slice(payload).unwrap();
            prop_assert_eq!(&resp, &decoded);
        }
    }
}
