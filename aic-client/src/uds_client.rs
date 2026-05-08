//! Unix Domain Socket 클라이언트.
//!
//! AIC_Server에 UDS로 연결하여 IPC 요청을 전송하고 응답을 수신한다.
//! Length-prefixed JSON 프레이밍(`aic_common::encode_frame`)을 사용한다.

use aic_common::{encode_frame, AicError, CommandRecord, IpcRequest, IpcResponse, SessionInfo};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub struct UdsClient {
    socket_path: PathBuf,
}

impl UdsClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// AIC_Server에 연결하여 직전 명령어 데이터를 요청한다.
    pub async fn get_last_command(&self) -> Result<CommandRecord, AicError> {
        let response = self.send_request(IpcRequest::GetLastCommand).await?;

        match response {
            IpcResponse::CommandData(record) => Ok(record),
            IpcResponse::Error { message } => {
                // 서버 응답 에러는 사용자 친화적 메시지로 변환
                if message.contains("저장된 명령어가 없습니다") {
                    Err(AicError::UserMessage(
                        "아직 분석할 명령어가 없습니다. aic-session 안에서 명령어를 실행한 후 다시 시도하세요.".to_string(),
                    ))
                } else {
                    Err(AicError::UserMessage(message))
                }
            }
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {:?}", other),
            ))),
        }
    }

    /// 세션 ring buffer의 최근 N개 CommandRecord를 시간순(오래된→최신)으로 조회한다.
    ///
    /// session-level 요청이므로 session socket에 연결한 UdsClient에서만 의미가 있다.
    /// `aicd` control socket에 보내면 Error 응답이 돌아온다.
    pub async fn get_recent_commands(&self, count: usize) -> Result<Vec<CommandRecord>, AicError> {
        match self
            .send_request(IpcRequest::GetRecentCommands { count })
            .await?
        {
            IpcResponse::CommandRecords(records) => Ok(records),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// 외부에서 만든 CommandRecord를 세션 ring buffer에 등록한다.
    /// `aic run`이 만든 ExplicitCapture record를 history/--record/fix 흐름과
    /// 통합하기 위해 사용. session socket이 없으면 `ServerNotRunning`을 돌려준다 —
    /// 호출자는 best-effort로 무시할 수 있다.
    pub async fn register_record(&self, record: CommandRecord) -> Result<(), AicError> {
        match self
            .send_request(IpcRequest::RegisterRecord(record))
            .await?
        {
            IpcResponse::Pong => Ok(()),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// 세션 ring buffer에서 record id prefix로 시작하는 record를 모두 조회한다.
    /// `aic --record <prefix>`/`aic fix --record`/`aic learn --record`가 사용한다 —
    /// client가 200개를 가져와 필터링하던 비효율을 server-side filter로 대체한다.
    pub async fn find_record_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<CommandRecord>, AicError> {
        match self
            .send_request(IpcRequest::FindRecordByPrefix {
                prefix: prefix.to_string(),
            })
            .await?
        {
            IpcResponse::CommandRecords(records) => Ok(records),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// `aicd` hook-event store에서 특정 세션의 마지막 metadata-only command를 조회한다.
    pub async fn get_last_command_for_session(&self, id: &str) -> Result<CommandRecord, AicError> {
        let response = self
            .send_request(IpcRequest::GetLastCommandForSession { id: id.to_string() })
            .await?;

        match response {
            IpcResponse::CommandData(record) => Ok(record),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {:?}", other),
            ))),
        }
    }

    /// `aicd` CommandRecordStore에서 특정 세션의 최근 N개 record를 조회한다.
    ///
    /// Phase 3.1 `aic history`/Phase 3.2 read path에서 aicd만을 조회할 때 사용한다.
    /// 해당 session에 record가 없으면 빈 Vec를 반환한다.
    pub async fn get_recent_commands_for_session(
        &self,
        id: &str,
        count: usize,
    ) -> Result<Vec<CommandRecord>, AicError> {
        match self
            .send_request(IpcRequest::GetRecentCommandsForSession {
                id: id.to_string(),
                count,
            })
            .await?
        {
            IpcResponse::CommandRecords(records) => Ok(records),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {:?}", other),
            ))),
        }
    }

    /// `aicd` CommandRecordStore에서 특정 세션의 최근 output line tail N개를 조회한다.
    ///
    /// Phase 3.2 read path에서 aicd의 `GetRecentLinesForSession`로 라우팅할 때 사용한다.
    /// 세션에 record가 없거나 `output_lines`가 모두 비어 있으면 빈 Vec를 반환한다.
    pub async fn get_recent_lines_for_session(
        &self,
        id: &str,
        count: usize,
    ) -> Result<Vec<String>, AicError> {
        match self
            .send_request(IpcRequest::GetRecentLinesForSession {
                id: id.to_string(),
                count,
            })
            .await?
        {
            IpcResponse::Lines(lines) => Ok(lines),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {:?}", other),
            ))),
        }
    }

    /// `aicd` CommandRecordStore에서 특정 세션 scope로 record id prefix 매칭을 수행한다.
    ///
    /// Phase 3.2 read path에서 aicd의 `FindRecordByPrefixForSession`으로 라우팅할 때 사용한다.
    /// 세션이 없거나 매칭이 없으면 빈 Vec를 반환한다.
    pub async fn find_record_by_prefix_for_session(
        &self,
        id: &str,
        prefix: &str,
    ) -> Result<Vec<CommandRecord>, AicError> {
        match self
            .send_request(IpcRequest::FindRecordByPrefixForSession {
                id: id.to_string(),
                prefix: prefix.to_string(),
            })
            .await?
        {
            IpcResponse::CommandRecords(records) => Ok(records),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {:?}", other),
            ))),
        }
    }

    /// 연결 가능 여부를 확인한다 (health check).
    pub async fn ping(&self) -> Result<bool, AicError> {
        match self.send_request(IpcRequest::Ping).await {
            Ok(IpcResponse::Pong) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// 데몬 metric snapshot 조회.
    pub async fn get_metrics(&self) -> Result<aic_common::MetricsSnapshot, AicError> {
        match self.send_request(IpcRequest::GetMetrics).await? {
            IpcResponse::Metrics(snap) => Ok(snap),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// `aicd` registry의 세션 목록 조회. control plane 전용.
    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>, AicError> {
        match self.send_request(IpcRequest::ListSessions).await? {
            IpcResponse::Sessions(list) => Ok(list),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// `aicd` registry에서 오래된 inactive 세션을 제거한다.
    pub async fn prune_sessions(&self, older_than_secs: u64) -> Result<usize, AicError> {
        match self
            .send_request(IpcRequest::PruneSessions { older_than_secs })
            .await?
        {
            IpcResponse::PrunedSessions { count } => Ok(count),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// `aicd`에 graceful Shutdown을 요청한다. 응답으로 Pong을 받으면 daemon이 종료 중.
    pub async fn shutdown(&self) -> Result<(), AicError> {
        match self.send_request(IpcRequest::Shutdown).await? {
            IpcResponse::Pong => Ok(()),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// fire-and-forget 송신용 generic wrapper. 응답을 그대로 돌려준다.
    /// hook event 같은 best-effort 호출에서 사용한다.
    pub async fn send_raw(&self, request: IpcRequest) -> Result<IpcResponse, AicError> {
        self.send_request(request).await
    }

    /// `aicd`에 세션 label을 설정/제거 요청한다 (label=None이면 untag).
    pub async fn tag_session(&self, id: &str, label: Option<String>) -> Result<(), AicError> {
        match self
            .send_request(IpcRequest::TagSession {
                id: id.to_string(),
                label,
            })
            .await?
        {
            IpcResponse::Pong => Ok(()),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// `aicd`에 특정 세션을 graceful 종료시키도록 요청한다 (Phase 2.1).
    pub async fn stop_session(&self, id: &str) -> Result<(), AicError> {
        match self
            .send_request(IpcRequest::StopSession { id: id.to_string() })
            .await?
        {
            IpcResponse::Pong => Ok(()),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// IPC 요청을 전송하고 응답을 수신하는 공통 메서드.
    ///
    /// UDS는 local IPC라 응답 시간은 ms 단위가 정상이다. 데몬이 hang된 경우 빠르게
    /// 감지해 폴백(셸 히스토리)으로 넘어갈 수 있도록 짧은 timeout을 사용한다.
    async fn send_request(&self, request: IpcRequest) -> Result<IpcResponse, AicError> {
        use tokio::time::{timeout, Duration};

        // local UDS 응답은 ms 단위가 정상. hang 감지를 빨리 하도록 짧게.
        let connect_timeout = Duration::from_secs(1);
        let read_timeout = Duration::from_secs(3);

        let mut stream = timeout(connect_timeout, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| {
                AicError::IpcError(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("서버 연결 타임아웃 ({}초)", connect_timeout.as_secs()),
                ))
            })?
            .map_err(|_| AicError::ServerNotRunning)?;

        // 요청 직렬화 + length-prefixed 프레임 전송
        let request_json = serde_json::to_vec(&request)
            .map_err(|e| AicError::ConfigError(format!("요청 직렬화 실패: {e}")))?;
        let frame = encode_frame(&request_json);
        stream.write_all(&frame).await?;

        // 응답 프레임 헤더(4바이트) 수신 (타임아웃 적용)
        let mut len_buf = [0u8; 4];
        timeout(read_timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                AicError::IpcError(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "서버 응답 타임아웃 ({}초) — aic-session이 hang 상태일 수 있음",
                        read_timeout.as_secs()
                    ),
                ))
            })??;
        let payload_len = u32::from_be_bytes(len_buf) as usize;
        if payload_len > aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES {
            return Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "응답 payload 크기({payload_len})가 허용 한계({})를 초과",
                    aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES
                ),
            )));
        }

        // 응답 payload 수신
        let mut payload_buf = vec![0u8; payload_len];
        timeout(read_timeout, stream.read_exact(&mut payload_buf))
            .await
            .map_err(|_| {
                AicError::IpcError(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("서버 응답 payload 타임아웃 ({}초)", read_timeout.as_secs()),
                ))
            })??;

        // JSON 역직렬화
        let response: IpcResponse = serde_json::from_slice(&payload_buf)
            .map_err(|e| AicError::ConfigError(format!("응답 역직렬화 실패: {e}")))?;

        Ok(response)
    }
}

/// Phase 3.2 read path cascade — aicd → session socket (→ 상위 레이어의 shell history fallback).
///
/// `Central_Store_Flag` 가 `true` 면 (1) aicd control UDS 를 먼저 조회하고,
/// 실패 시 (2) 세션 local UDS 로 폴백한다. flag 가 `false` 면 Phase 3.1 이전과 동일하게
/// (2) 만 사용한다 (R4.5).
///
/// **Phase 3.5 차이** (R7.1): `phase-3_5` feature 가 활성이면 (2) 세션 local socket
/// fallback 브랜치가 **컴파일 단계에서 제거된다**. aicd 가 실패하거나 flag=false 여도
/// 세션 소켓을 시도하지 않고 바로 `Ok(None)` / 빈 Vec 를 반환해 상위 레이어의 shell
/// history fallback 으로 넘어간다. flag=false 인 경우에는 진입 시점에 한 번
/// `tracing::warn!("이 빌드는 세션 로컬 소켓 fallback을 지원하지 않습니다")` 를 남긴다.
///
/// "shell history fallback" 은 `get_last_command` 시나리오에만 존재하며, 이는 main.rs
/// 계층에서 `None` 을 받은 뒤 독립적으로 호출한다 — 이 레이어는 IPC 수준의 cascade 만
/// 책임진다 (`uds_client` 에 셸 히스토리 파싱 로직을 넣지 않는다).
///
/// **반환 규약**
/// - `get_last_command_cascade`: `Ok(Some(record))` = IPC 경로로 record 획득,
///   `Ok(None)` = 모든 IPC 경로가 "record 없음" 으로 응답, `Err(_)` = 진짜 고장.
/// - `get_recent_commands_cascade` / `get_recent_lines_cascade` /
///   `find_record_by_prefix_cascade`: 빈 Vec 는 aicd 의 성공 응답(list-op 성격)이므로
///   **cascade 하지 않는다** (R4.3 은 에러 시에만 cascade). 진짜 에러 시에만 session socket
///   으로 폴백하며, 양쪽 다 에러면 `Err(_)` 를 돌려준다. Phase 3.5 빌드에서는 session
///   socket 폴백이 없으므로 aicd 가 에러면 그대로 `Err(_)` 가 전파된다.
pub struct ReadCascade {
    session_id: String,
    central_store_flag: bool,
    aicd_sock: PathBuf,
    // Phase 3.5 빌드에서는 세션 로컬 socket 경로 자체를 사용하지 않으므로
    // 필드 존재가 dead code 가 되지 않도록 cfg 로 감춘다. `with_paths` 생성자는
    // 테스트 호환을 위해 시그니처를 유지하되, phase-3_5 에서는 입력을 버린다.
    #[cfg(not(feature = "phase-3_5"))]
    session_sock: PathBuf,
}

impl ReadCascade {
    /// 기본 경로(`aicd_socket_path()` / `session_socket_path(&session_id)`) 로 초기화한다.
    ///
    /// Phase 3.5 빌드에서는 session socket 경로를 저장하지 않지만, public 시그니처는
    /// 기존과 동일하게 유지한다 (호출자는 session_id 만 알면 된다).
    pub fn new(session_id: impl Into<String>, central_store_flag: bool) -> Self {
        let session_id = session_id.into();
        let aicd_sock = aic_common::aicd_socket_path();
        #[cfg(not(feature = "phase-3_5"))]
        let session_sock = aic_common::session_socket_path(&session_id);
        #[cfg(feature = "phase-3_5")]
        {
            // Phase 3.5: session_socket_path 는 여전히 "session-{id}.sock" 경로 자체는
            // 생성해 두되 (hook CLI 의 RegisterRecord 경로 등 다른 용도가 있음),
            // read cascade 는 그 경로를 사용하지 않는다. 지역 변수만 discard 한다.
            let _ = aic_common::session_socket_path(&session_id);
        }
        Self {
            session_id,
            central_store_flag,
            aicd_sock,
            #[cfg(not(feature = "phase-3_5"))]
            session_sock,
        }
    }

    /// 소켓 경로를 명시적으로 override 한다 (테스트 전용; 일반 호출은 `new` 를 사용).
    ///
    /// Phase 3.5 빌드에서는 `session_sock` 인자가 무시된다. 테스트 호환을 위해
    /// 시그니처는 유지한다.
    pub fn with_paths(
        session_id: impl Into<String>,
        central_store_flag: bool,
        aicd_sock: PathBuf,
        session_sock: PathBuf,
    ) -> Self {
        #[cfg(feature = "phase-3_5")]
        let _ = session_sock; // 사용하지 않음을 명시.
        Self {
            session_id: session_id.into(),
            central_store_flag,
            aicd_sock,
            #[cfg(not(feature = "phase-3_5"))]
            session_sock,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn central_store_flag(&self) -> bool {
        self.central_store_flag
    }

    /// 직전 command record 한 건을 cascade 로 조회한다 (R4.1~R4.3).
    ///
    /// - flag=true: (1) aicd `GetLastCommandForSession { id }` → (2) session `GetLastCommand`.
    /// - flag=false: (2) 만 시도.
    /// - 두 경로 모두 "record 없음" 이면 `Ok(None)` (→ 상위 레이어가 shell history 로 폴백).
    /// - (1) 실패 시 `tracing::warn!` 만 남기고 (2) 를 시도 (R4.3).
    ///
    /// **Phase 3.5 차이 (R7.1)**: session socket fallback 이 제거된다. flag=true 에서
    /// aicd 가 실패하면 바로 `Ok(None)` 을 반환해 상위 레이어의 shell history 로 넘긴다.
    /// flag=false 에서는 session socket 이 없으므로 warning 로그를 남기고 `Ok(None)` 을
    /// 반환한다.
    #[cfg(not(feature = "phase-3_5"))]
    pub async fn get_last_command(&self) -> Result<Option<CommandRecord>, AicError> {
        if self.central_store_flag {
            let aicd = UdsClient::new(self.aicd_sock.clone());
            match aicd.get_last_command_for_session(&self.session_id).await {
                Ok(record) => return Ok(Some(record)),
                Err(e) => {
                    tracing::warn!(
                        session_id = %self.session_id,
                        error = %e,
                        "aicd GetLastCommandForSession 실패 — session socket 으로 폴백"
                    );
                }
            }
        }

        // (2) session socket fallback.
        let session = UdsClient::new(self.session_sock.clone());
        match session.get_last_command().await {
            Ok(record) => Ok(Some(record)),
            Err(AicError::UserMessage(_)) => {
                // session socket 도 "record 없음" 으로 응답 — 상위 레이어가 history 로 폴백.
                Ok(None)
            }
            Err(AicError::ServerNotRunning) => {
                // session socket 자체가 없는 케이스. shell history 로 폴백하게 하려면 None.
                Ok(None)
            }
            Err(other) => Err(other),
        }
    }

    /// Phase 3.5 변형: session local socket fallback 이 제거되었다 (R7.1).
    ///
    /// flag=true 이면 aicd 만 시도하고, 실패 / 없음 시 `Ok(None)` 으로 떨어져
    /// 상위 레이어가 shell history 로 폴백하도록 한다. flag=false 는 Phase 3.5
    /// 빌드에서 "세션 로컬 소켓 경로" 가 지원되지 않으므로 warning 을 남기고
    /// `Ok(None)` 을 돌려준다 (R12.3, R12.4 의 graceful 응답 유지).
    #[cfg(feature = "phase-3_5")]
    pub async fn get_last_command(&self) -> Result<Option<CommandRecord>, AicError> {
        if !self.central_store_flag {
            tracing::warn!(
                session_id = %self.session_id,
                "이 빌드는 세션 로컬 소켓 fallback을 지원하지 않습니다"
            );
            return Ok(None);
        }
        let aicd = UdsClient::new(self.aicd_sock.clone());
        match aicd.get_last_command_for_session(&self.session_id).await {
            Ok(record) => Ok(Some(record)),
            Err(AicError::UserMessage(_)) => {
                // aicd 가 "record 없음" 으로 graceful Error 응답 — history 로 폴백.
                Ok(None)
            }
            Err(AicError::ServerNotRunning) => {
                // aicd 자체가 없는 경우. Phase 3.5 에는 session socket fallback 이 없으므로
                // shell history 로 폴백하도록 None 을 돌려준다.
                Ok(None)
            }
            Err(other) => Err(other),
        }
    }

    /// 최근 N 개 command record 를 cascade 로 조회한다.
    ///
    /// 빈 Vec 는 aicd 의 성공 응답이므로 cascade 하지 않는다 (spec 의 "cascade only on Error").
    /// (1) 이 진짜 에러를 돌려주면 (2) 로 폴백하고, 양쪽 다 에러면 `Err` 를 돌려준다.
    ///
    /// **Phase 3.5 차이 (R7.1)**: session socket fallback 제거. flag=true 에서
    /// aicd 가 에러면 `Err` 그대로 전파된다.
    #[cfg(not(feature = "phase-3_5"))]
    pub async fn get_recent_commands(
        &self,
        count: usize,
    ) -> Result<Vec<CommandRecord>, AicError> {
        if self.central_store_flag {
            let aicd = UdsClient::new(self.aicd_sock.clone());
            match aicd
                .get_recent_commands_for_session(&self.session_id, count)
                .await
            {
                Ok(records) => return Ok(records),
                Err(e) => {
                    tracing::warn!(
                        session_id = %self.session_id,
                        error = %e,
                        "aicd GetRecentCommandsForSession 실패 — session socket 으로 폴백"
                    );
                }
            }
        }

        let session = UdsClient::new(self.session_sock.clone());
        session.get_recent_commands(count).await
    }

    /// Phase 3.5 변형: session local socket fallback 이 제거되었다 (R7.1).
    ///
    /// flag=true 이면 aicd 를 시도하고 결과를 그대로 돌려준다 (에러 시 Err 전파).
    /// flag=false 이면 세션 로컬 소켓이 지원되지 않으므로 warning 을 남기고 빈 Vec 를
    /// 반환한다.
    #[cfg(feature = "phase-3_5")]
    pub async fn get_recent_commands(
        &self,
        count: usize,
    ) -> Result<Vec<CommandRecord>, AicError> {
        if !self.central_store_flag {
            tracing::warn!(
                session_id = %self.session_id,
                "이 빌드는 세션 로컬 소켓 fallback을 지원하지 않습니다"
            );
            return Ok(Vec::new());
        }
        let aicd = UdsClient::new(self.aicd_sock.clone());
        aicd.get_recent_commands_for_session(&self.session_id, count)
            .await
    }

    /// 최근 N 라인을 cascade 로 조회한다 (output_lines flatten tail).
    ///
    /// session socket 에는 `GetRecentLines` 만 존재하고 session-scoped 변형은 없다 —
    /// session socket 은 단일 세션만 호스팅하므로 이게 정확한 대응이다.
    ///
    /// **Phase 3.5 차이 (R7.1)**: session socket fallback 제거.
    #[cfg(not(feature = "phase-3_5"))]
    pub async fn get_recent_lines(&self, count: usize) -> Result<Vec<String>, AicError> {
        if self.central_store_flag {
            let aicd = UdsClient::new(self.aicd_sock.clone());
            match aicd
                .get_recent_lines_for_session(&self.session_id, count)
                .await
            {
                Ok(lines) => return Ok(lines),
                Err(e) => {
                    tracing::warn!(
                        session_id = %self.session_id,
                        error = %e,
                        "aicd GetRecentLinesForSession 실패 — session socket 으로 폴백"
                    );
                }
            }
        }

        // session socket 의 GetRecentLines 래퍼는 UdsClient 에 없으므로 raw request 를 보낸다.
        let session = UdsClient::new(self.session_sock.clone());
        match session.send_raw(IpcRequest::GetRecentLines { count }).await? {
            IpcResponse::Lines(lines) => Ok(lines),
            IpcResponse::Error { message } => Err(AicError::UserMessage(message)),
            other => Err(AicError::IpcError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("예상치 못한 응답: {other:?}"),
            ))),
        }
    }

    /// Phase 3.5 변형: session local socket fallback 이 제거되었다 (R7.1).
    #[cfg(feature = "phase-3_5")]
    pub async fn get_recent_lines(&self, count: usize) -> Result<Vec<String>, AicError> {
        if !self.central_store_flag {
            tracing::warn!(
                session_id = %self.session_id,
                "이 빌드는 세션 로컬 소켓 fallback을 지원하지 않습니다"
            );
            return Ok(Vec::new());
        }
        let aicd = UdsClient::new(self.aicd_sock.clone());
        aicd.get_recent_lines_for_session(&self.session_id, count)
            .await
    }

    /// record id prefix 매칭을 cascade 로 수행한다.
    ///
    /// 빈 Vec 는 "매칭 0 건" 의 성공 응답이므로 cascade 하지 않는다.
    ///
    /// **Phase 3.5 차이 (R7.1)**: session socket fallback 제거.
    #[cfg(not(feature = "phase-3_5"))]
    pub async fn find_record_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<CommandRecord>, AicError> {
        if self.central_store_flag {
            let aicd = UdsClient::new(self.aicd_sock.clone());
            match aicd
                .find_record_by_prefix_for_session(&self.session_id, prefix)
                .await
            {
                Ok(records) => return Ok(records),
                Err(e) => {
                    tracing::warn!(
                        session_id = %self.session_id,
                        error = %e,
                        "aicd FindRecordByPrefixForSession 실패 — session socket 으로 폴백"
                    );
                }
            }
        }

        let session = UdsClient::new(self.session_sock.clone());
        session.find_record_by_prefix(prefix).await
    }

    /// Phase 3.5 변형: session local socket fallback 이 제거되었다 (R7.1).
    #[cfg(feature = "phase-3_5")]
    pub async fn find_record_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<CommandRecord>, AicError> {
        if !self.central_store_flag {
            tracing::warn!(
                session_id = %self.session_id,
                "이 빌드는 세션 로컬 소켓 fallback을 지원하지 않습니다"
            );
            return Ok(Vec::new());
        }
        let aicd = UdsClient::new(self.aicd_sock.clone());
        aicd.find_record_by_prefix_for_session(&self.session_id, prefix)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::{encode_frame, IpcRequest, IpcResponse};
    use chrono::Utc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// 단일 요청을 처리하는 간이 mock 서버를 시작하고 소켓 경로를 반환한다.
    async fn start_mock_server(
        response: IpcResponse,
    ) -> (
        PathBuf,
        tokio::task::JoinHandle<IpcRequest>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let path = sock_path.clone();

        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // 요청 프레임 수신
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let payload_len = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).await.unwrap();
            let request: IpcRequest = serde_json::from_slice(&payload).unwrap();

            // 응답 프레임 전송
            let resp_json = serde_json::to_vec(&response).unwrap();
            let frame = encode_frame(&resp_json);
            stream.write_all(&frame).await.unwrap();

            request
        });

        (path, handle, dir)
    }

    #[tokio::test]
    async fn ping_returns_true_on_pong() {
        let (sock_path, server, _dir) = start_mock_server(IpcResponse::Pong).await;
        let client = UdsClient::new(sock_path);

        let result = client.ping().await.unwrap();
        assert!(result);

        let req = server.await.unwrap();
        assert_eq!(req, IpcRequest::Ping);
    }

    #[tokio::test]
    async fn ping_returns_false_on_no_server() {
        let client = UdsClient::new(PathBuf::from("/tmp/nonexistent_ac_test.sock"));
        let result = client.ping().await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn get_last_command_returns_record() {
        let record = CommandRecord {
            command: Some("cargo build".to_string()),
            exit_code: 1,
            output_lines: vec!["error[E0308]".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let (sock_path, server, _dir) =
            start_mock_server(IpcResponse::CommandData(record.clone())).await;
        let client = UdsClient::new(sock_path);

        let result = client.get_last_command().await.unwrap();
        assert_eq!(result.command, Some("cargo build".to_string()));
        assert_eq!(result.exit_code, 1);

        let req = server.await.unwrap();
        assert_eq!(req, IpcRequest::GetLastCommand);
    }

    #[tokio::test]
    async fn get_last_command_server_error_response() {
        let (sock_path, _server, _dir) = start_mock_server(IpcResponse::Error {
            message: "저장된 명령어가 없습니다".to_string(),
        })
        .await;
        let client = UdsClient::new(sock_path);

        let err = client.get_last_command().await.unwrap_err();
        // 사용자 친화적 메시지로 변환되었는지 확인 (UserMessage variant 사용)
        match err {
            AicError::UserMessage(msg) => {
                assert!(msg.contains("아직 분석할 명령어가 없습니다"));
            }
            other => panic!("UserMessage를 기대했지만 {:?}를 받았습니다", other),
        }
    }

    #[tokio::test]
    async fn get_last_command_connection_failure() {
        let client = UdsClient::new(PathBuf::from("/tmp/nonexistent_ac_test.sock"));
        let err = client.get_last_command().await.unwrap_err();
        match err {
            AicError::ServerNotRunning => {} // 기대한 에러
            other => panic!("ServerNotRunning을 기대했지만 {:?}를 받았습니다", other),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // ReadCascade — Phase 3.2 Task 2.2 cascade 조합 테스트.
    //
    // 각 cascade 메서드에 대해 4가지 조합을 검증한다:
    //   · flag=true  + aicd-success              → aicd 결과, session 미호출
    //   · flag=true  + aicd-error + session-success → session 결과 (R4.3 폴백)
    //   · flag=true  + aicd-down(연결 실패) + session-success → session 결과
    //   · flag=false + session-success           → session 결과 (R4.5)
    // 이로 8가지 실패/성공 조합을 get_last_command / get_recent_commands /
    // get_recent_lines / find_record_by_prefix 네 계열에 대해 커버한다.
    //
    // mock_server 는 가벼운 UnixListener 를 띄워 지정된 response 목록을
    // **accept 순서대로** 돌려준다. 하나의 ReadCascade 호출이 한 연결 = 한 response
    // 이므로, cascade 가 aicd 를 skip 했다면 aicd mock 은 연결을 받지 못하고
    // 조용히 남아 있는다. 반대로 fallback 이 일어났다면 session mock 쪽에서도
    // 연결 하나가 소비된다.
    // ═══════════════════════════════════════════════════════════════════

    /// 지정된 응답을 순서대로 돌려주는 간이 mock server. drop 시 listener 를 닫는다.
    /// `connections` 는 실제로 accept 된 횟수(= cascade 가 해당 소켓을 시도한 횟수).
    async fn start_multi_mock(
        responses: Vec<IpcResponse>,
    ) -> (PathBuf, tempfile::TempDir, std::sync::Arc<tokio::sync::Mutex<usize>>) {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("mock.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let counter = std::sync::Arc::new(tokio::sync::Mutex::new(0usize));
        let counter_clone = counter.clone();
        tokio::spawn(async move {
            for resp in responses {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                {
                    let mut c = counter_clone.lock().await;
                    *c += 1;
                }
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    continue;
                }
                let payload_len = u32::from_be_bytes(len_buf) as usize;
                let mut payload = vec![0u8; payload_len];
                if stream.read_exact(&mut payload).await.is_err() {
                    continue;
                }
                let _req: IpcRequest = match serde_json::from_slice(&payload) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let body = serde_json::to_vec(&resp).unwrap();
                let frame = encode_frame(&body);
                let _ = stream.write_all(&frame).await;
            }
            // 이후 accept 는 consumer 가 없으므로 block — listener 가 drop 되면 에러로 빠진다.
        });
        (sock_path, dir, counter)
    }

    fn sample_record(id: &str, command: &str, exit_code: i32) -> CommandRecord {
        CommandRecord {
            id: id.to_string(),
            command: Some(command.to_string()),
            exit_code,
            output_lines: vec![format!("out-{command}")],
            timestamp: Utc::now(),
            ..Default::default()
        }
    }

    fn nonexistent_sock() -> PathBuf {
        // 임의의 존재하지 않는 경로 — connection 실패를 강제한다.
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("nope.sock");
        // TempDir 를 drop 하면 디렉토리가 사라져 소켓 경로도 무효해진다 — 의도한 바.
        drop(dir);
        p
    }

    // ── get_last_command cascade ────────────────────────────────────
    //
    // 아래 cascade 테스트들은 session socket fallback 을 상정한 시나리오이므로
    // `phase-3_5` feature 에서는 컴파일에서 배제한다 (R7.1). Phase 3.5 전용 동작은
    // `phase_3_5_cascade_tests` 서브 모듈에 별도로 둔다.
    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_last_command_flag_true_aicd_success_skips_session() {
        // flag=true + (1) aicd 성공 → session mock 은 사용되지 않아야 한다.
        let expected = sample_record("1111", "ls", 0);
        let (aicd_sock, _aicd_dir, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(expected.clone())]).await;
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(sample_record(
                "2222", "should-not-be-used", 99,
            ))])
            .await;

        let cascade = ReadCascade::with_paths("sess01", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap().expect("Some");
        assert_eq!(got.command.as_deref(), Some("ls"));
        assert_eq!(*aicd_hits.lock().await, 1, "aicd 가 1회 호출되어야 한다");
        assert_eq!(
            *session_hits.lock().await,
            0,
            "aicd 성공 시 session 은 호출되지 말아야 한다"
        );
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_last_command_flag_true_aicd_error_falls_back_to_session() {
        // flag=true + (1) aicd 가 Error 응답 → (2) session 으로 폴백.
        let (aicd_sock, _aicd_dir, aicd_hits) = start_multi_mock(vec![IpcResponse::Error {
            message: "hook metadata record를 찾을 수 없습니다".to_string(),
        }])
        .await;
        let expected = sample_record("2222", "echo hi", 0);
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(expected.clone())]).await;

        let cascade = ReadCascade::with_paths("sess02", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap().expect("Some");
        assert_eq!(got.command.as_deref(), Some("echo hi"));
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 1, "session 으로 폴백");
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_last_command_flag_true_aicd_down_falls_back_to_session() {
        // flag=true + (1) aicd 연결 불가 → (2) session 으로 폴백.
        let aicd_sock = nonexistent_sock();
        let expected = sample_record("3333", "cat", 0);
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(expected.clone())]).await;

        let cascade = ReadCascade::with_paths("sess03", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap().expect("Some");
        assert_eq!(got.command.as_deref(), Some("cat"));
        assert_eq!(*session_hits.lock().await, 1);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_last_command_flag_false_uses_only_session() {
        // flag=false: aicd 는 건드리지 않고 session 만 사용 (R4.5).
        let (aicd_sock, _aicd_dir, aicd_hits) = start_multi_mock(vec![IpcResponse::CommandData(
            sample_record("1111", "aicd-should-be-skipped", 0),
        )])
        .await;
        let expected = sample_record("4444", "rm -rf tmp", 0);
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(expected.clone())]).await;

        let cascade = ReadCascade::with_paths("sess04", false, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap().expect("Some");
        assert_eq!(got.command.as_deref(), Some("rm -rf tmp"));
        assert_eq!(
            *aicd_hits.lock().await,
            0,
            "flag=false 에서는 aicd 를 호출하지 말아야 한다"
        );
        assert_eq!(*session_hits.lock().await, 1);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_last_command_both_missing_returns_none() {
        // 두 IPC 경로 모두 "record 없음" → 상위 레이어의 history fallback 을 위해 Ok(None).
        let (aicd_sock, _aicd_dir, _) = start_multi_mock(vec![IpcResponse::Error {
            message: "hook metadata record를 찾을 수 없습니다".to_string(),
        }])
        .await;
        let (session_sock, _sess_dir, _) = start_multi_mock(vec![IpcResponse::Error {
            message: "저장된 명령어가 없습니다".to_string(),
        }])
        .await;

        let cascade = ReadCascade::with_paths("sess05", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap();
        assert!(
            got.is_none(),
            "두 경로 모두 record 없음이면 Ok(None) 이어야 history fallback 이 트리거된다"
        );
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_last_command_both_down_returns_none() {
        // aicd down + session down → 마지막으로 Ok(None) 으로 떨어져야 shell history 폴백이 동작.
        let aicd_sock = nonexistent_sock();
        let session_sock = nonexistent_sock();
        let cascade = ReadCascade::with_paths("sess06", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap();
        assert!(got.is_none(), "양쪽 모두 연결 실패 시 Ok(None) 으로 떨어진다");
    }

    // ── get_recent_commands cascade ─────────────────────────────────

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_recent_commands_flag_true_aicd_success_skips_session() {
        let records = vec![
            sample_record("aaaa", "ls", 0),
            sample_record("bbbb", "pwd", 0),
        ];
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![])]).await;

        let cascade = ReadCascade::with_paths("sess10", true, aicd_sock, session_sock);
        let got = cascade.get_recent_commands(10).await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_recent_commands_flag_true_aicd_down_falls_back_to_session() {
        let aicd_sock = nonexistent_sock();
        let records = vec![sample_record("cccc", "grep", 1)];
        let (session_sock, _d, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;

        let cascade = ReadCascade::with_paths("sess11", true, aicd_sock, session_sock);
        let got = cascade.get_recent_commands(10).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].command.as_deref(), Some("grep"));
        assert_eq!(*session_hits.lock().await, 1);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_recent_commands_flag_false_uses_only_session() {
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "zzzz", "should-skip", 0,
            )])])
            .await;
        let records = vec![sample_record("dddd", "make", 2)];
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;

        let cascade = ReadCascade::with_paths("sess12", false, aicd_sock, session_sock);
        let got = cascade.get_recent_commands(5).await.unwrap();
        assert_eq!(got[0].command.as_deref(), Some("make"));
        assert_eq!(*aicd_hits.lock().await, 0);
        assert_eq!(*session_hits.lock().await, 1);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_recent_commands_aicd_empty_does_not_cascade() {
        // aicd 가 빈 Vec 로 성공 응답 → cascade 하지 않음 (R4.3 "cascade only on Error").
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![])]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "xxxx", "session-wins", 0,
            )])])
            .await;

        let cascade = ReadCascade::with_paths("sess13", true, aicd_sock, session_sock);
        let got = cascade.get_recent_commands(5).await.unwrap();
        assert_eq!(got.len(), 0, "aicd 빈 Vec 는 성공이므로 cascade 하지 않는다");
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(
            *session_hits.lock().await,
            0,
            "session 까지 내려가면 안 된다"
        );
    }

    // ── get_recent_lines cascade ────────────────────────────────────

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_recent_lines_flag_true_aicd_success_skips_session() {
        let lines = vec!["line-a".to_string(), "line-b".to_string()];
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::Lines(lines.clone())]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::Lines(vec![])]).await;

        let cascade = ReadCascade::with_paths("sess20", true, aicd_sock, session_sock);
        let got = cascade.get_recent_lines(10).await.unwrap();
        assert_eq!(got, lines);
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_recent_lines_flag_true_aicd_down_falls_back_to_session() {
        let aicd_sock = nonexistent_sock();
        let lines = vec!["fallback-line".to_string()];
        let (session_sock, _d, session_hits) =
            start_multi_mock(vec![IpcResponse::Lines(lines.clone())]).await;

        let cascade = ReadCascade::with_paths("sess21", true, aicd_sock, session_sock);
        let got = cascade.get_recent_lines(10).await.unwrap();
        assert_eq!(got, lines);
        assert_eq!(*session_hits.lock().await, 1);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_recent_lines_flag_false_uses_only_session() {
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::Lines(vec!["aicd-skip".to_string()])]).await;
        let lines = vec!["legacy".to_string(), "route".to_string()];
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::Lines(lines.clone())]).await;

        let cascade = ReadCascade::with_paths("sess22", false, aicd_sock, session_sock);
        let got = cascade.get_recent_lines(10).await.unwrap();
        assert_eq!(got, lines);
        assert_eq!(*aicd_hits.lock().await, 0);
        assert_eq!(*session_hits.lock().await, 1);
    }

    // ── find_record_by_prefix cascade ───────────────────────────────

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_find_by_prefix_flag_true_aicd_success_skips_session() {
        let records = vec![sample_record("abcd1234", "target", 0)];
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![])]).await;

        let cascade = ReadCascade::with_paths("sess30", true, aicd_sock, session_sock);
        let got = cascade.find_record_by_prefix("abcd").await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_find_by_prefix_flag_true_aicd_down_falls_back_to_session() {
        let aicd_sock = nonexistent_sock();
        let records = vec![sample_record("abcd5678", "session-target", 0)];
        let (session_sock, _d, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;

        let cascade = ReadCascade::with_paths("sess31", true, aicd_sock, session_sock);
        let got = cascade.find_record_by_prefix("abcd").await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].command.as_deref(), Some("session-target"));
        assert_eq!(*session_hits.lock().await, 1);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_find_by_prefix_flag_false_uses_only_session() {
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "aicd1111", "skip", 0,
            )])])
            .await;
        let records = vec![sample_record("sess2222", "legacy-prefix-match", 0)];
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;

        let cascade = ReadCascade::with_paths("sess32", false, aicd_sock, session_sock);
        let got = cascade.find_record_by_prefix("sess").await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].command.as_deref(), Some("legacy-prefix-match"));
        assert_eq!(*aicd_hits.lock().await, 0);
        assert_eq!(*session_hits.lock().await, 1);
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn cascade_find_by_prefix_aicd_empty_does_not_cascade() {
        // aicd 가 "매칭 0 건" 성공 응답 → cascade 하지 않음.
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![])]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "sess3333", "should-not-reach", 0,
            )])])
            .await;

        let cascade = ReadCascade::with_paths("sess33", true, aicd_sock, session_sock);
        let got = cascade.find_record_by_prefix("sess").await.unwrap();
        assert!(got.is_empty());
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 3.5 전용 cascade 테스트 (R7.1)
    //
    // Phase 3.5 빌드에서는 session local socket fallback 이 제거된다. 따라서:
    //   · flag=true  + aicd 성공         → aicd 결과, session 경로 미사용
    //   · flag=true  + aicd Error 응답    → Ok(None) / 빈 Vec 로 떨어져 상위
    //                                       레이어가 shell history 로 폴백
    //   · flag=true  + aicd down          → 동일
    //   · flag=false                      → warning 로그 + Ok(None) / 빈 Vec
    //
    // session socket mock 은 테스트 하네스 호환을 위해 인자로만 넣고 실제로는
    // 절대 호출되면 안 된다 — session_hits 가 0 인지로 검증한다.
    // ═══════════════════════════════════════════════════════════════════

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_last_command_flag_true_aicd_success() {
        let expected = sample_record("abcd1234", "ls -la", 0);
        let (aicd_sock, _aicd_dir, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(expected.clone())]).await;
        // session mock 은 호출되지 말아야 한다.
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(sample_record(
                "should-not", "used", 99,
            ))])
            .await;

        let cascade = ReadCascade::with_paths("sess_p35_a", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap().expect("Some");
        assert_eq!(got.command.as_deref(), Some("ls -la"));
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(
            *session_hits.lock().await,
            0,
            "Phase 3.5 에서는 session socket 으로 내려가선 안 된다"
        );
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_last_command_flag_true_aicd_missing_returns_none() {
        // aicd 가 "record 없음" 으로 graceful Error → Phase 3.5 는 session fallback 이
        // 없으므로 Ok(None) 으로 떨어져 상위 레이어가 shell history 로 폴백한다.
        let (aicd_sock, _aicd_dir, aicd_hits) = start_multi_mock(vec![IpcResponse::Error {
            message: "해당 세션의 record를 찾을 수 없습니다".to_string(),
        }])
        .await;
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(sample_record(
                "should-not", "used", 99,
            ))])
            .await;

        let cascade = ReadCascade::with_paths("sess_p35_b", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap();
        assert!(got.is_none(), "Phase 3.5 에서는 aicd record 없음 → Ok(None)");
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_last_command_flag_true_aicd_down_returns_none() {
        let aicd_sock = nonexistent_sock();
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(sample_record(
                "should-not", "used", 99,
            ))])
            .await;

        let cascade = ReadCascade::with_paths("sess_p35_c", true, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap();
        assert!(
            got.is_none(),
            "aicd 연결 실패 시에도 Phase 3.5 는 session fallback 없이 Ok(None)"
        );
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_last_command_flag_false_returns_none() {
        // flag=false 는 Phase 3.5 에서 지원되지 않으므로 warning 을 남기고 Ok(None).
        let (aicd_sock, _aicd_dir, aicd_hits) = start_multi_mock(vec![IpcResponse::CommandData(
            sample_record("shouldskip", "aicd-skip", 0),
        )])
        .await;
        let (session_sock, _sess_dir, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandData(sample_record(
                "shouldskip", "session-skip", 0,
            ))])
            .await;

        let cascade = ReadCascade::with_paths("sess_p35_d", false, aicd_sock, session_sock);
        let got = cascade.get_last_command().await.unwrap();
        assert!(got.is_none(), "flag=false + Phase 3.5 → Ok(None)");
        assert_eq!(*aicd_hits.lock().await, 0, "aicd 는 호출되지 말아야 한다");
        assert_eq!(*session_hits.lock().await, 0, "session 도 호출되지 말아야 한다");
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_recent_commands_flag_true_aicd_success() {
        let records = vec![
            sample_record("a1", "ls", 0),
            sample_record("a2", "pwd", 0),
        ];
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![])]).await;

        let cascade = ReadCascade::with_paths("sess_p35_e", true, aicd_sock, session_sock);
        let got = cascade.get_recent_commands(10).await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_recent_commands_flag_true_aicd_error_propagates() {
        // aicd 가 진짜 에러 (UserMessage 가 아닌 것) 를 돌려주는 시나리오는 mock 으로
        // 만들기 번거로우니 "UserMessage" 케이스를 이용해 빈 Vec 가 아닌 Err 가
        // 전파되는지 대신 확인한다.
        let (aicd_sock, _d1, aicd_hits) = start_multi_mock(vec![IpcResponse::Error {
            message: "내부 에러".to_string(),
        }])
        .await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "should-not", "used", 0,
            )])])
            .await;

        let cascade = ReadCascade::with_paths("sess_p35_f", true, aicd_sock, session_sock);
        let err = cascade.get_recent_commands(5).await.unwrap_err();
        match err {
            AicError::UserMessage(msg) => assert!(msg.contains("내부 에러")),
            other => panic!("UserMessage 를 기대했지만 {other:?}"),
        }
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(
            *session_hits.lock().await,
            0,
            "Phase 3.5 에서는 session socket fallback 이 없어야 한다"
        );
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_recent_commands_flag_false_returns_empty() {
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "aa", "skip", 0,
            )])])
            .await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "bb", "skip", 0,
            )])])
            .await;

        let cascade = ReadCascade::with_paths("sess_p35_g", false, aicd_sock, session_sock);
        let got = cascade.get_recent_commands(5).await.unwrap();
        assert!(got.is_empty());
        assert_eq!(*aicd_hits.lock().await, 0);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_recent_lines_flag_true_aicd_success() {
        let lines = vec!["L1".to_string(), "L2".to_string()];
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::Lines(lines.clone())]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::Lines(vec![])]).await;

        let cascade = ReadCascade::with_paths("sess_p35_h", true, aicd_sock, session_sock);
        let got = cascade.get_recent_lines(10).await.unwrap();
        assert_eq!(got, lines);
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_recent_lines_flag_false_returns_empty() {
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::Lines(vec!["skip".to_string()])]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::Lines(vec!["skip".to_string()])]).await;

        let cascade = ReadCascade::with_paths("sess_p35_i", false, aicd_sock, session_sock);
        let got = cascade.get_recent_lines(10).await.unwrap();
        assert!(got.is_empty());
        assert_eq!(*aicd_hits.lock().await, 0);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_find_by_prefix_flag_true_aicd_success() {
        let records = vec![sample_record("abcd1234", "target", 0)];
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(records.clone())]).await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![])]).await;

        let cascade = ReadCascade::with_paths("sess_p35_j", true, aicd_sock, session_sock);
        let got = cascade.find_record_by_prefix("abcd").await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(*aicd_hits.lock().await, 1);
        assert_eq!(*session_hits.lock().await, 0);
    }

    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase35_find_by_prefix_flag_false_returns_empty() {
        let (aicd_sock, _d1, aicd_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "skip", "aicd", 0,
            )])])
            .await;
        let (session_sock, _d2, session_hits) =
            start_multi_mock(vec![IpcResponse::CommandRecords(vec![sample_record(
                "skip", "session", 0,
            )])])
            .await;

        let cascade = ReadCascade::with_paths("sess_p35_k", false, aicd_sock, session_sock);
        let got = cascade.find_record_by_prefix("skip").await.unwrap();
        assert!(got.is_empty());
        assert_eq!(*aicd_hits.lock().await, 0);
        assert_eq!(*session_hits.lock().await, 0);
    }
}
