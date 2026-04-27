//! aicd supervisor의 control UDS 서버.
//!
//! `uds_server`와 다르게 RingBuffer에 결합되지 않는다. aicd는 control plane
//! (세션 registry, daemon health, lifecycle command)만 다루고, 출력 캡처는
//! 각 `aic-session`(또는 향후 attach relay)이 보유한다.
//!
//! Phase 1 sub-step 1: 최소 동작 — `Ping → Pong`만 처리한다. 이후 sub-step에서
//! `ListSessions`, `GetMetrics`, `Shutdown` 등을 단계적으로 추가한다.

use aic_common::{encode_frame, IpcRequest, IpcResponse};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

/// aicd control UDS 엔드포인트.
pub struct ControlServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl ControlServer {
    /// control 소켓을 바인드한다. 기존 소켓 파일은 정리 후 재생성한다.
    pub async fn bind(socket_path: &Path) -> anyhow::Result<Self> {
        let _ = std::fs::remove_file(socket_path);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(socket_path)?;
        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// `shutdown` notify가 신호를 받을 때까지 accept 루프를 돈다.
    /// 신호를 받으면 즉시 루프를 빠져나오며, in-flight 핸들러는 detach된 채 종료된다.
    pub async fn serve(&self, shutdown: Arc<Notify>) {
        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream).await {
                                    let msg = e.to_string();
                                    if msg.contains("early eof") || msg.contains("unexpected eof") {
                                        tracing::debug!(error = %e, "control client 조기 종료");
                                    } else {
                                        tracing::warn!(error = %e, "control client 처리 실패");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "control 연결 수락 실패");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    tracing::info!("control server shutdown 신호 수신");
                    break;
                }
            }
        }
    }

    /// 바인드된 소켓 경로.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn handle_client(mut stream: UnixStream) -> anyhow::Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    let mut payload_buf = vec![0u8; payload_len];
    stream.read_exact(&mut payload_buf).await?;

    let response = match serde_json::from_slice::<IpcRequest>(&payload_buf) {
        Ok(request) => process_control_request(request).await,
        Err(e) => {
            tracing::debug!(error = %e, "control IpcRequest 역직렬화 실패");
            IpcResponse::Error {
                message: format!("unknown request: {e}"),
            }
        }
    };

    let response_json = serde_json::to_vec(&response)?;
    let frame = encode_frame(&response_json);
    stream.write_all(&frame).await?;
    Ok(())
}

/// aicd가 처리하는 control request. 미지원 variant는 graceful Error를 반환한다.
async fn process_control_request(request: IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::Ping => IpcResponse::Pong,
        // session-level request는 현재 sub-step에서는 거부한다.
        // 다음 sub-step에서 ListSessions/GetMetrics/Shutdown을 추가한다.
        other => IpcResponse::Error {
            message: format!("aicd가 아직 지원하지 않는 요청: {other:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn ping_returns_pong() {
        assert_eq!(
            process_control_request(IpcRequest::Ping).await,
            IpcResponse::Pong
        );
    }

    #[tokio::test]
    async fn unsupported_request_returns_error() {
        let resp = process_control_request(IpcRequest::GetLastCommand).await;
        match resp {
            IpcResponse::Error { message } => assert!(message.contains("아직 지원하지 않는")),
            other => panic!("Error 응답을 기대했지만 {other:?}"),
        }
    }

    #[tokio::test]
    async fn bind_and_ping_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aicd.sock");
        let server = ControlServer::bind(&sock_path).await.unwrap();
        assert!(sock_path.exists());

        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let serve_handle = tokio::spawn(async move { server.serve(shutdown_clone).await });

        // 클라이언트 ping
        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let req_json = serde_json::to_vec(&IpcRequest::Ping).unwrap();
        let frame = encode_frame(&req_json);
        client.write_all(&frame).await.unwrap();

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        assert_eq!(resp, IpcResponse::Pong);

        // shutdown
        shutdown.notify_one();
        // serve 루프가 빠져나갈 때까지 잠깐 대기 (테스트 안정성)
        let _ = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
    }
}
