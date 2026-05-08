//! `aic-session` → `aicd` best-effort client (Phase 1.4).
//!
//! 정책:
//! - 모든 호출은 `aicd`가 떠 있지 않거나 응답이 안 오면 **silent skip** 한다.
//!   `aic-session`은 단독으로도 정상 동작해야 하므로 register/unregister 실패가
//!   사용자 셸을 망가뜨리면 안 된다.
//! - 짧은 connect/write/read timeout만 사용. 사용자 prompt latency를 방해하면
//!   안 되므로 100ms 안에 끝낸다.
//!
//! 자동 spawn은 의도적으로 하지 않는다 (Phase 1.5에서 `aic daemon start` 또는
//! `aic doctor --fix`로 명시 시작).

use aic_common::{
    aicd_socket_path, encode_frame, CommandRecord, IpcRequest, IpcResponse, SessionInfo,
};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// `aicd` 호출에 사용할 짧은 timeout.
const AICD_RPC_TIMEOUT: Duration = Duration::from_millis(100);

/// 새 세션을 `aicd`에 등록한다 (best-effort).
///
/// 실패 시 trace 로그만 남기고 Ok(())를 반환한다 — 호출자는 결과를 무시해도 된다.
pub async fn register_session(info: SessionInfo) {
    if let Err(e) = send(&aicd_socket_path(), IpcRequest::RegisterSession(info)).await {
        tracing::debug!(error = %e, "aicd register 실패 (무시) — aicd가 미실행이거나 응답 없음");
    }
}

/// 세션을 `aicd` registry에서 제거한다 (best-effort).
pub async fn unregister_session(id: &str) {
    if let Err(e) = send(
        &aicd_socket_path(),
        IpcRequest::UnregisterSession { id: id.to_string() },
    )
    .await
    {
        tracing::debug!(error = %e, "aicd unregister 실패 (무시)");
    }
}

/// 세션 heartbeat를 `aicd`에 보낸다 (best-effort).
pub async fn heartbeat_session(id: &str, cwd: Option<std::path::PathBuf>) {
    if let Err(e) = send(
        &aicd_socket_path(),
        IpcRequest::HeartbeatSession {
            id: id.to_string(),
            seen_at: chrono::Utc::now(),
            cwd,
        },
    )
    .await
    {
        tracing::debug!(error = %e, "aicd heartbeat 실패 (무시)");
    }
}

/// Phase 3.1 Dual-Write: `aic-session`이 만든 `CommandRecord`를 `aicd`의
/// [`CommandRecordStore`](crate::command_record_store::CommandRecordStore) 로
/// 세션 라우팅해 전송한다 (best-effort).
///
/// 본 함수는 연결/쓰기/응답 전체를 [`AICD_RPC_TIMEOUT`] (100ms) 이내로 제한한다.
/// timeout / connection error / 역직렬화 오류 모두 `tracing::debug!`로만 기록하고
/// silent skip 한다 (R3.3) — 호출 결과를 무시해도 안전하다.
///
/// # 인자
/// - `session_id`: aicd 측 `CommandRecordStore`의 key 가 될 세션 식별자.
/// - `record`: 이미 id 가 부여된 `CommandRecord`. 빈 id 여도 aicd 측에서 auto-assign 하지만,
///   local store 와 id를 일치시키려면 호출 전에 id를 확정해 두는 것을 권장한다 (P2 전제).
pub async fn register_record(session_id: &str, record: CommandRecord) {
    if let Err(e) = send(
        &aicd_socket_path(),
        IpcRequest::RegisterRecordForSession {
            session_id: session_id.to_string(),
            record,
        },
    )
    .await
    {
        tracing::debug!(
            session_id,
            error = %e,
            "aicd register_record 실패 (무시) — aicd 미실행 또는 timeout"
        );
    }
}

/// 단발성 IPC: connect → write request → read response → close. 타임아웃 안에 끝낸다.
async fn send(socket_path: &Path, request: IpcRequest) -> anyhow::Result<IpcResponse> {
    let fut = async {
        let mut stream = UnixStream::connect(socket_path).await?;
        let req_json = serde_json::to_vec(&request)?;
        let frame = encode_frame(&req_json);
        stream.write_all(&frame).await?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;
        let response: IpcResponse = serde_json::from_slice(&resp_buf)?;
        Ok::<_, anyhow::Error>(response)
    };

    match tokio::time::timeout(AICD_RPC_TIMEOUT, fut).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("aicd 응답 timeout ({}ms)", AICD_RPC_TIMEOUT.as_millis()),
    }
}

/// 현재 stdin이 가리키는 TTY 경로. TTY가 아니거나 알 수 없으면 None.
pub fn current_tty() -> Option<String> {
    use std::os::fd::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    let ptr = unsafe { libc::ttyname(fd) };
    if ptr.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    cstr.to_str().ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_to_missing_socket_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let result = send(&missing, IpcRequest::Ping).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn register_session_silent_when_aicd_down() {
        // aicd가 없는 상태에서도 panic 없이 반환해야 한다.
        let now = chrono::Utc::now();
        let info = SessionInfo {
            id: "deadbeef".to_string(),
            pid: std::process::id(),
            state: aic_common::SessionState::Attached,
            created_at: now,
            last_seen_at: Some(now),
            last_command_at: None,
            attached_tty: None,
            shell: None,
            cwd: None,
            label: None,
        };
        // socket path가 사용자 환경의 실제 aicd_socket_path()를 가리킬 수 있지만,
        // CI에서 aicd가 떠 있지 않다고 가정하면 silent skip 확인 가능.
        register_session(info).await;
    }

    #[tokio::test]
    async fn unregister_session_silent_when_aicd_down() {
        unregister_session("missing").await;
    }

    #[tokio::test]
    async fn register_record_silent_when_aicd_down() {
        // aicd 미실행 상태에서도 panic 없이 반환해야 한다 (R3.3).
        let record = aic_common::CommandRecord {
            command: Some("ls".to_string()),
            capture_mode: aic_common::CaptureMode::Pty,
            ..Default::default()
        };
        register_record("deadbeef", record).await;
    }

    #[tokio::test]
    async fn register_record_completes_within_timeout() {
        // aicd 소켓이 없는 환경에서 register_record 전체가 100ms 안에 끝나는지 확인한다.
        // AICD_RPC_TIMEOUT(100ms)이 상한이므로 여유를 둔 500ms 안에 반드시 완료되어야 한다.
        let record = aic_common::CommandRecord {
            command: Some("cargo build".to_string()),
            capture_mode: aic_common::CaptureMode::Pty,
            ..Default::default()
        };
        let completed = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            register_record("abcd1234", record),
        )
        .await;
        assert!(
            completed.is_ok(),
            "register_record가 500ms 안에 끝나지 않음 — AICD_RPC_TIMEOUT 상한 가드가 깨졌을 수 있음"
        );
    }

    #[tokio::test]
    async fn end_to_end_register_then_list_via_socket() {
        // ControlServer를 한 번 띄우고 register → list가 통하는지 검증한다.
        use crate::control_server::{ControlContext, ControlServer};
        use crate::session_registry::SessionRegistry;
        use std::sync::Arc;
        use tokio::sync::Notify;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aicd.sock");
        let server = ControlServer::bind(&sock_path).await.unwrap();
        let registry = SessionRegistry::new();
        let ctx = ControlContext {
            shutdown: Arc::new(Notify::new()),
            registry: registry.clone(),
            record_store: crate::command_record_store::CommandRecordStore::new(),
            registry_path: None,
            metrics: Arc::new(crate::metrics::AicdMetrics::new()),
        };
        let serve_handle = tokio::spawn(async move { server.serve(ctx).await });

        let now = chrono::Utc::now();
        let info = SessionInfo {
            id: "abcd1234".to_string(),
            pid: 9999,
            state: aic_common::SessionState::Attached,
            created_at: now,
            last_seen_at: Some(now),
            last_command_at: None,
            attached_tty: Some("/dev/ttys001".to_string()),
            shell: Some("/bin/zsh".to_string()),
            cwd: Some(std::path::PathBuf::from("/tmp")),
            label: None,
        };
        let resp = send(&sock_path, IpcRequest::RegisterSession(info))
            .await
            .unwrap();
        assert_eq!(resp, IpcResponse::Pong);

        let list_resp = send(&sock_path, IpcRequest::ListSessions).await.unwrap();
        match list_resp {
            IpcResponse::Sessions(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].id, "abcd1234");
            }
            other => panic!("Sessions 응답을 기대 — actual: {other:?}"),
        }

        let unreg = send(
            &sock_path,
            IpcRequest::UnregisterSession {
                id: "abcd1234".to_string(),
            },
        )
        .await
        .unwrap();
        assert_eq!(unreg, IpcResponse::Pong);

        serve_handle.abort();
    }
}
