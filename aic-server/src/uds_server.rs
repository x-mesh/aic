//! Unix Domain Socket 서버.
//!
//! AIC_Client의 IPC 요청을 수신하고 RingBuffer 데이터로 응답한다.
//! Length-prefixed JSON 프레이밍(`aic_common::encode_frame` / `decode_frame`)을 사용한다.

use crate::ring_buffer::RingBuffer;
use aic_common::{encode_frame, IpcRequest, IpcResponse};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

pub struct UdsServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl UdsServer {
    /// UDS 엔드포인트 생성. 기존 소켓 파일이 있으면 삭제 후 재바인딩.
    pub async fn bind(socket_path: &Path) -> anyhow::Result<Self> {
        // 기존 소켓 파일 삭제 (존재하지 않아도 무시)
        let _ = std::fs::remove_file(socket_path);

        // 부모 디렉토리가 없으면 생성
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path)?;

        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// 클라이언트 연결을 수락하고 IPC 요청을 처리하는 루프.
    pub async fn serve(&self, buffer: Arc<RwLock<RingBuffer>>) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    let buf = Arc::clone(&buffer);
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, buf).await {
                            let msg = e.to_string();
                            // connect만 하고 끊는 경우 (health check, stale 체크) — 정상 패턴
                            if msg.contains("early eof") || msg.contains("unexpected eof") {
                                tracing::debug!(error = %e, "UDS 클라이언트 조기 종료 (health check)");
                            } else {
                                tracing::warn!(error = %e, "UDS 클라이언트 처리 실패");
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "UDS 연결 수락 실패");
                }
            }
        }
    }

    /// 소켓 파일 삭제.
    pub fn cleanup(&self) -> anyhow::Result<()> {
        std::fs::remove_file(&self.socket_path)?;
        Ok(())
    }
}

impl Drop for UdsServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

// ── 클라이언트 핸들러 ──────────────────────────────────────────

/// 단일 클라이언트 연결을 처리한다.
/// Length-prefixed JSON 프레임을 읽고, 요청을 처리한 뒤 응답을 전송한다.
async fn handle_client(
    mut stream: UnixStream,
    buffer: Arc<RwLock<RingBuffer>>,
) -> anyhow::Result<()> {
    // 프레임 헤더(4바이트) 읽기
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    // payload 읽기
    let mut payload_buf = vec![0u8; payload_len];
    stream.read_exact(&mut payload_buf).await?;

    // JSON 역직렬화 — unknown variant 등은 client에 graceful Error 응답
    let response = match serde_json::from_slice::<IpcRequest>(&payload_buf) {
        Ok(request) => process_request(request, &buffer).await,
        Err(e) => {
            tracing::debug!(error = %e, "IpcRequest 역직렬화 실패");
            IpcResponse::Error {
                message: format!("unknown request: {e}"),
            }
        }
    };

    // 응답 직렬화 + length-prefixed 프레임 전송
    let response_json = serde_json::to_vec(&response)?;
    let frame = encode_frame(&response_json);
    stream.write_all(&frame).await?;

    Ok(())
}

/// IpcRequest를 처리하여 IpcResponse를 반환한다.
async fn process_request(request: IpcRequest, buffer: &Arc<RwLock<RingBuffer>>) -> IpcResponse {
    crate::metrics::record_ipc_request();
    match request {
        IpcRequest::GetLastCommand => {
            let buf = buffer.read().await;
            match buf.last() {
                Some(record) => IpcResponse::CommandData(record.clone()),
                None => IpcResponse::Error {
                    message: "저장된 명령어가 없습니다".to_string(),
                },
            }
        }
        IpcRequest::GetRecentLines { count } => {
            let buf = buffer.read().await;
            let lines = buf.recent_lines(count);
            IpcResponse::Lines(lines.into_iter().map(String::from).collect())
        }
        IpcRequest::Ping => IpcResponse::Pong,
        IpcRequest::ListSessions
        | IpcRequest::Shutdown
        | IpcRequest::RegisterSession(_)
        | IpcRequest::UnregisterSession { .. }
        | IpcRequest::StopSession { .. } => IpcResponse::Error {
            message: format!(
                "{request:?}는 aicd control plane 요청입니다 — aicd 소켓에 연결하세요"
            ),
        },
        IpcRequest::GetMetrics => {
            let buf = buffer.read().await;
            let last_command_secs_ago = buf.last().map(|rec| {
                let elapsed = chrono::Utc::now() - rec.timestamp;
                elapsed.num_seconds().max(0) as u64
            });
            IpcResponse::Metrics(aic_common::MetricsSnapshot {
                uptime_secs: crate::metrics::uptime_secs(),
                pid: std::process::id(),
                ipc_request_count: crate::metrics::ipc_request_count(),
                rb_used: buf.total_lines(),
                rb_capacity: buf.capacity(),
                last_command_secs_ago,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::CommandRecord;
    use chrono::Utc;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn make_buffer_with_record() -> Arc<RwLock<RingBuffer>> {
        let mut buf = RingBuffer::new(100);
        buf.push(CommandRecord {
            command: Some("cargo test".to_string()),
            exit_code: 1,
            output_lines: vec!["error[E0308]".to_string(), "help: try".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        });
        Arc::new(RwLock::new(buf))
    }

    #[tokio::test]
    async fn process_ping_returns_pong() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(100)));
        let resp = process_request(IpcRequest::Ping, &buffer).await;
        assert_eq!(resp, IpcResponse::Pong);
    }

    #[tokio::test]
    async fn process_get_last_command_empty_buffer() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(100)));
        let resp = process_request(IpcRequest::GetLastCommand, &buffer).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(message.contains("저장된 명령어가 없습니다"));
            }
            _ => panic!("빈 버퍼에서 Error 응답을 기대했습니다"),
        }
    }

    #[tokio::test]
    async fn process_get_last_command_with_record() {
        let buffer = make_buffer_with_record();
        let resp = process_request(IpcRequest::GetLastCommand, &buffer).await;
        match resp {
            IpcResponse::CommandData(record) => {
                assert_eq!(record.command, Some("cargo test".to_string()));
                assert_eq!(record.exit_code, 1);
            }
            _ => panic!("CommandData 응답을 기대했습니다"),
        }
    }

    #[tokio::test]
    async fn process_get_recent_lines() {
        let buffer = make_buffer_with_record();
        let resp = process_request(IpcRequest::GetRecentLines { count: 1 }, &buffer).await;
        match resp {
            IpcResponse::Lines(lines) => {
                assert_eq!(lines, vec!["help: try"]);
            }
            _ => panic!("Lines 응답을 기대했습니다"),
        }
    }

    #[tokio::test]
    async fn uds_server_bind_and_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server = UdsServer::bind(&sock_path).await.unwrap();
        assert!(sock_path.exists());

        let buffer = make_buffer_with_record();
        let buf_clone = Arc::clone(&buffer);

        // 서버를 백그라운드에서 실행
        let serve_handle = tokio::spawn(async move {
            server.serve(buf_clone).await;
        });

        // 클라이언트 연결 및 Ping 전송
        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

        let req = IpcRequest::Ping;
        let req_json = serde_json::to_vec(&req).unwrap();
        let frame = encode_frame(&req_json);
        client.write_all(&frame).await.unwrap();

        // 응답 수신
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();

        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        assert_eq!(resp, IpcResponse::Pong);

        serve_handle.abort();
    }

    #[tokio::test]
    async fn uds_server_get_last_command_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test2.sock");

        let server = UdsServer::bind(&sock_path).await.unwrap();
        let buffer = make_buffer_with_record();
        let buf_clone = Arc::clone(&buffer);

        let serve_handle = tokio::spawn(async move {
            server.serve(buf_clone).await;
        });

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

        // GetLastCommand 요청
        let req = IpcRequest::GetLastCommand;
        let req_json = serde_json::to_vec(&req).unwrap();
        let frame = encode_frame(&req_json);
        client.write_all(&frame).await.unwrap();

        // 응답 수신
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();

        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        match resp {
            IpcResponse::CommandData(record) => {
                assert_eq!(record.command, Some("cargo test".to_string()));
                assert_eq!(record.exit_code, 1);
                assert_eq!(record.output_lines.len(), 2);
            }
            _ => panic!("CommandData 응답을 기대했습니다"),
        }

        serve_handle.abort();
    }

    #[tokio::test]
    async fn uds_server_cleanup_removes_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("cleanup.sock");

        let server = UdsServer::bind(&sock_path).await.unwrap();
        assert!(sock_path.exists());

        server.cleanup().unwrap();
        assert!(!sock_path.exists());
    }

    #[tokio::test]
    async fn uds_server_rebind_existing_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("rebind.sock");

        // 첫 번째 바인딩
        let _server1 = UdsServer::bind(&sock_path).await.unwrap();
        assert!(sock_path.exists());

        // 두 번째 바인딩 — 기존 소켓 파일을 삭제하고 재바인딩
        let _server2 = UdsServer::bind(&sock_path).await.unwrap();
        assert!(sock_path.exists());
    }
}
