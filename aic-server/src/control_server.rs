//! aicd supervisor의 control UDS 서버.
//!
//! `uds_server`와 다르게 RingBuffer에 결합되지 않는다. aicd는 control plane
//! (세션 registry, daemon health, lifecycle command)만 다루고, 출력 캡처는
//! 각 `aic-session`(또는 향후 attach relay)이 보유한다.
//!
//! Phase 1 sub-step 1: 최소 동작 — `Ping → Pong`만 처리한다. 이후 sub-step에서
//! `ListSessions`, `GetMetrics`, `Shutdown` 등을 단계적으로 추가한다.

use crate::session_registry::SessionRegistry;
use aic_common::{encode_frame, IpcRequest, IpcResponse};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

/// Daemon 측에서 control_server가 외부 상태를 변경할 때 사용하는 핸들.
/// shutdown trigger와 session registry를 보유한다.
#[derive(Clone)]
pub struct ControlContext {
    pub shutdown: Arc<Notify>,
    pub registry: SessionRegistry,
}

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

    /// `ctx.shutdown`이 신호를 받을 때까지 accept 루프를 돈다.
    /// 신호를 받으면 즉시 루프를 빠져나오며, in-flight 핸들러는 detach된 채 종료된다.
    pub async fn serve(&self, ctx: ControlContext) {
        let shutdown = Arc::clone(&ctx.shutdown);
        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let ctx = ctx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, ctx).await {
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

async fn handle_client(mut stream: UnixStream, ctx: ControlContext) -> anyhow::Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    let mut payload_buf = vec![0u8; payload_len];
    stream.read_exact(&mut payload_buf).await?;

    let response = match serde_json::from_slice::<IpcRequest>(&payload_buf) {
        Ok(request) => process_control_request(request, &ctx).await,
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
async fn process_control_request(request: IpcRequest, ctx: &ControlContext) -> IpcResponse {
    match request {
        IpcRequest::Ping => IpcResponse::Pong,
        IpcRequest::ListSessions => IpcResponse::Sessions(ctx.registry.list().await),
        IpcRequest::RegisterSession(info) => {
            tracing::info!(session_id = %info.id, pid = info.pid, "세션 등록");
            ctx.registry.register(info).await;
            IpcResponse::Pong
        }
        IpcRequest::UnregisterSession { id } => {
            let removed = ctx.registry.unregister(&id).await;
            tracing::info!(session_id = %id, removed, "세션 등록 해제");
            IpcResponse::Pong
        }
        IpcRequest::Shutdown => {
            tracing::info!("control Shutdown 요청 수신");
            // 응답을 보낸 뒤 serve 루프가 빠져나가도록 notify.
            // notify_one()은 수신자가 없으면 next notified()까지 latch되므로
            // 응답 write 이후 select가 즉시 종료된다.
            ctx.shutdown.notify_one();
            IpcResponse::Pong
        }
        // session-level request는 aicd의 책임이 아니다.
        IpcRequest::GetLastCommand
        | IpcRequest::GetRecentLines { .. }
        | IpcRequest::GetMetrics => IpcResponse::Error {
            message: format!("aicd는 세션 데이터 요청을 직접 처리하지 않습니다: {request:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ctx() -> ControlContext {
        ControlContext {
            shutdown: Arc::new(Notify::new()),
            registry: SessionRegistry::new(),
        }
    }

    fn sample_info(id: &str) -> aic_common::SessionInfo {
        aic_common::SessionInfo {
            id: id.to_string(),
            pid: 4242,
            state: aic_common::SessionState::Attached,
            created_at: chrono::Utc::now(),
            attached_tty: Some("/dev/ttys001".to_string()),
            shell: Some("/bin/zsh".to_string()),
            cwd: Some(std::path::PathBuf::from("/tmp")),
        }
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        assert_eq!(
            process_control_request(IpcRequest::Ping, &ctx()).await,
            IpcResponse::Pong
        );
    }

    #[tokio::test]
    async fn list_sessions_empty_when_registry_empty() {
        let resp = process_control_request(IpcRequest::ListSessions, &ctx()).await;
        match resp {
            IpcResponse::Sessions(list) => assert!(list.is_empty()),
            other => panic!("Sessions 응답을 기대했지만 {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_then_list_returns_session() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::RegisterSession(sample_info("aaaaaaaa")),
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);

        let list_resp = process_control_request(IpcRequest::ListSessions, &c).await;
        match list_resp {
            IpcResponse::Sessions(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].id, "aaaaaaaa");
            }
            other => panic!("Sessions 응답을 기대했지만 {other:?}"),
        }
    }

    #[tokio::test]
    async fn unregister_removes_session() {
        let c = ctx();
        process_control_request(IpcRequest::RegisterSession(sample_info("aaaaaaaa")), &c).await;
        let resp = process_control_request(
            IpcRequest::UnregisterSession {
                id: "aaaaaaaa".to_string(),
            },
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);
        assert_eq!(c.registry.len().await, 0);
    }

    #[tokio::test]
    async fn unregister_unknown_id_still_returns_pong() {
        // best-effort 호출이라 unknown id는 silent OK여야 한다 — client crash 후
        // aicd가 stale cleanup을 한 뒤에 client retry가 도착하는 흐름.
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::UnregisterSession {
                id: "missing".to_string(),
            },
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);
    }

    #[tokio::test]
    async fn shutdown_notifies_and_acks() {
        let c = ctx();
        let resp = process_control_request(IpcRequest::Shutdown, &c).await;
        assert_eq!(resp, IpcResponse::Pong);
        // Shutdown 처리 후 notified()가 즉시 떨어져야 한다.
        let waited = tokio::time::timeout(Duration::from_millis(100), c.shutdown.notified()).await;
        assert!(waited.is_ok(), "shutdown notify가 발화되지 않음");
    }

    #[tokio::test]
    async fn session_data_request_rejected_with_error() {
        let resp = process_control_request(IpcRequest::GetLastCommand, &ctx()).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(message.contains("aicd는 세션 데이터"), "actual: {message}");
            }
            other => panic!("Error 응답을 기대했지만 {other:?}"),
        }
    }

    async fn ping_through_socket(sock_path: &Path) -> IpcResponse {
        let mut client = tokio::net::UnixStream::connect(sock_path).await.unwrap();
        let req_json = serde_json::to_vec(&IpcRequest::Ping).unwrap();
        let frame = encode_frame(&req_json);
        client.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        serde_json::from_slice(&resp_buf).unwrap()
    }

    #[tokio::test]
    async fn bind_and_ping_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aicd.sock");
        let server = ControlServer::bind(&sock_path).await.unwrap();
        assert!(sock_path.exists());

        let c = ctx();
        let shutdown = Arc::clone(&c.shutdown);
        let serve_handle = tokio::spawn(async move { server.serve(c).await });

        assert_eq!(ping_through_socket(&sock_path).await, IpcResponse::Pong);

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
    }

    #[tokio::test]
    async fn shutdown_request_terminates_server() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aicd.sock");
        let server = ControlServer::bind(&sock_path).await.unwrap();
        let c = ctx();
        let serve_handle = tokio::spawn(async move { server.serve(c).await });

        // Shutdown 요청을 보내면 응답으로 Pong을 받고 serve 루프가 종료된다.
        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let req_json = serde_json::to_vec(&IpcRequest::Shutdown).unwrap();
        client.write_all(&encode_frame(&req_json)).await.unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        assert_eq!(resp, IpcResponse::Pong);

        // serve가 종료되어야 한다 — 2초 안에 join 가능.
        let joined = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
        assert!(joined.is_ok(), "Shutdown 후 serve 루프가 종료되지 않음");
    }
}
