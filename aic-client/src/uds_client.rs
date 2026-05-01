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
}
