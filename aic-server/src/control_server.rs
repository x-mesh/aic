//! aicd supervisor의 control UDS 서버.
//!
//! `uds_server`와 다르게 RingBuffer에 결합되지 않는다. aicd는 control plane
//! (세션 registry, daemon health, lifecycle command)만 다루고, 출력 캡처는
//! 각 `aic-session`(또는 향후 attach relay)이 보유한다.
//!
//! Phase 1 sub-step 1: 최소 동작 — `Ping → Pong`만 처리한다. 이후 sub-step에서
//! `ListSessions`, `GetMetrics`, `Shutdown` 등을 단계적으로 추가한다.

use crate::hook_events::HookEventStore;
use crate::session_registry::SessionRegistry;
use aic_common::{encode_frame, IpcRequest, IpcResponse};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

const STALE_ACTIVE_AFTER: chrono::Duration = chrono::Duration::seconds(30);

/// Daemon 측에서 control_server가 외부 상태를 변경할 때 사용하는 핸들.
/// shutdown trigger, session registry, hook event buffer를 보유한다.
#[derive(Clone)]
pub struct ControlContext {
    pub shutdown: Arc<Notify>,
    pub registry: SessionRegistry,
    pub hook_events: HookEventStore,
    pub registry_path: Option<PathBuf>,
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
    if payload_len > aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES {
        anyhow::bail!(
            "control IPC payload 크기({payload_len})가 허용 한계({})를 초과",
            aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES
        );
    }

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
        IpcRequest::ListSessions => {
            reconcile_stale_sessions(ctx).await;
            IpcResponse::Sessions(ctx.registry.list().await)
        }
        IpcRequest::PruneSessions { older_than_secs } => {
            reconcile_stale_sessions(ctx).await;
            let older_than_secs = older_than_secs.min(i64::MAX as u64) as i64;
            let count = ctx
                .registry
                .prune_inactive_older_than(
                    chrono::Utc::now(),
                    chrono::Duration::seconds(older_than_secs),
                )
                .await;
            if count > 0 {
                persist_registry(ctx).await;
            }
            IpcResponse::PrunedSessions { count }
        }
        IpcRequest::RegisterSession(info) => {
            tracing::info!(session_id = %info.id, pid = info.pid, "세션 등록");
            ctx.registry.register(info).await;
            persist_registry(ctx).await;
            IpcResponse::Pong
        }
        IpcRequest::UnregisterSession { id } => {
            let removed = ctx.registry.unregister(&id).await;
            tracing::info!(session_id = %id, removed, "세션 등록 해제");
            persist_registry(ctx).await;
            IpcResponse::Pong
        }
        IpcRequest::HeartbeatSession { id, seen_at, cwd } => {
            let updated = ctx.registry.heartbeat(&id, seen_at, cwd).await;
            tracing::debug!(session_id = %id, updated, "세션 heartbeat");
            if updated {
                persist_registry(ctx).await;
            }
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
        IpcRequest::StopSession { id } => stop_session(ctx, &id).await,
        IpcRequest::TagSession { id, label } => {
            let updated = ctx.registry.set_label(&id, label.clone()).await;
            if updated {
                persist_registry(ctx).await;
                tracing::info!(session_id = %id, ?label, "세션 label 갱신");
                IpcResponse::Pong
            } else {
                IpcResponse::Error {
                    message: format!("세션을 찾을 수 없습니다: {id}"),
                }
            }
        }
        IpcRequest::GetLastCommandForSession { id } => match ctx.hook_events.last(&id).await {
            Some(record) => IpcResponse::CommandData(record),
            None => IpcResponse::Error {
                message: format!("hook metadata record를 찾을 수 없습니다: {id}"),
            },
        },
        IpcRequest::CommandStarted {
            session_id,
            command_id,
            command,
            cwd,
            shell,
            pid,
            started_at,
        } => {
            ctx.registry
                .upsert_hook_session(&session_id, pid, shell, cwd.clone(), started_at)
                .await;
            persist_registry(ctx).await;
            ctx.hook_events
                .on_started(&session_id, &command_id, command, cwd, started_at)
                .await;
            IpcResponse::Pong
        }
        IpcRequest::CommandFinished {
            session_id,
            command_id,
            exit_code,
            finished_at,
            duration_ms,
        } => {
            if ctx.registry.touch_seen(&session_id, finished_at).await {
                persist_registry(ctx).await;
            }
            ctx.hook_events
                .on_finished(
                    &session_id,
                    &command_id,
                    exit_code,
                    finished_at,
                    duration_ms,
                )
                .await;
            IpcResponse::Pong
        }
        // hook mode에서 마지막 metadata-only record를 조회한다.
        // 일반 GetLastCommand는 aic-session ring buffer 전용이지만, AIC_SESSION_ID가
        // 있고 aicd hook_events에 record가 있으면 hook record를 반환한다.
        IpcRequest::GetLastCommand => {
            // Phase 3.x: 정확한 session 라우팅이 필요해 일단 graceful Error.
            // 사용자가 aic --session <id> 형태로 호출하면 client가 적절히 routing.
            IpcResponse::Error {
                message: "aicd hook GetLastCommand는 세션 ID 라우팅을 거쳐야 합니다 \
                    (--session 인자 사용)"
                    .to_string(),
            }
        }
        // 그 외 session-level request는 aicd의 책임이 아니다.
        IpcRequest::GetRecentLines { .. }
        | IpcRequest::GetRecentCommands { .. }
        | IpcRequest::FindRecordByPrefix { .. }
        | IpcRequest::RegisterRecord(_)
        | IpcRequest::GetMetrics => IpcResponse::Error {
            message: format!("aicd는 세션 데이터 요청을 직접 처리하지 않습니다: {request:?}"),
        },
    }
}

async fn reconcile_stale_sessions(ctx: &ControlContext) {
    let count = ctx
        .registry
        .mark_stale_active_detached(chrono::Utc::now(), STALE_ACTIVE_AFTER)
        .await;
    if count > 0 {
        tracing::info!(count, "stale active 세션을 detached로 전환");
        persist_registry(ctx).await;
    }
}

async fn persist_registry(ctx: &ControlContext) {
    let Some(path) = ctx.registry_path.as_ref() else {
        return;
    };
    if let Err(e) = ctx.registry.save_snapshot(path).await {
        tracing::warn!(path = %path.display(), error = %e, "registry snapshot 저장 실패");
    }
}

/// `aicd`가 owning하지 않는 PTY child를 종료하는 임시 구현 (Phase 2.1).
///
/// 진짜 PTY ownership 이동(Phase 2 본 구현)이 들어오기 전까지의 bridge:
/// - registry에서 PID 조회
/// - 해당 PID에 SIGTERM 전송 (kill -TERM)
/// - registry에서 제거
///
/// 한계:
/// - PTY child가 아니라 `aic-session` 프로세스에 신호가 간다. 그 프로세스의
///   shutdown 핸들러가 PTY child를 정리한다(이미 잘 동작).
/// - PID race(이미 죽었거나 recycling) 가능 — best-effort.
async fn stop_session(ctx: &ControlContext, id: &str) -> IpcResponse {
    let entry = ctx.registry.list().await.into_iter().find(|s| s.id == id);
    let Some(info) = entry else {
        return IpcResponse::Error {
            message: format!("세션을 찾을 수 없습니다: {id}"),
        };
    };

    let pid = info.pid as i32;
    if pid <= 1 {
        return IpcResponse::Error {
            message: format!("유효하지 않은 PID: {pid}"),
        };
    }
    if !pid_looks_like_aic_session(pid as u32) {
        tracing::warn!(
            session_id = %id,
            pid,
            "stop: PID가 aic-session 프로세스로 보이지 않아 SIGTERM 거부"
        );
        ctx.registry
            .set_state(id, aic_common::SessionState::Failed)
            .await;
        persist_registry(ctx).await;
        return IpcResponse::Error {
            message: format!("PID {pid}가 aic-session 프로세스로 보이지 않아 종료를 거부했습니다"),
        };
    }
    let r = unsafe { libc::kill(pid, libc::SIGTERM) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            tracing::info!(session_id = %id, pid, "stop: 프로세스 이미 없음 — registry만 정리");
            ctx.registry.unregister(id).await;
            return IpcResponse::Pong;
        }
        return IpcResponse::Error {
            message: format!("kill({pid}, SIGTERM) 실패: {err}"),
        };
    }
    tracing::info!(session_id = %id, pid, "SIGTERM 전송");
    // unregister는 호출하지 않는다 — 세션이 자체 shutdown path에서
    // UnregisterSession을 보낸다. 이중 unregister는 best-effort라 OK지만
    // race 줄이려고 호출자 쪽에 맡긴다.
    IpcResponse::Pong
}

fn pid_looks_like_aic_session(pid: u32) -> bool {
    match crate::lock::process_exe_path(pid) {
        Some(path) => path_matches_aic_session(&path),
        // Unsupported or inaccessible platforms keep the old best-effort behavior.
        None => true,
    }
}

fn path_matches_aic_session(path: &str) -> bool {
    std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        == Some("aic-session")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ctx() -> ControlContext {
        ControlContext {
            shutdown: Arc::new(Notify::new()),
            registry: SessionRegistry::new(),
            hook_events: HookEventStore::new(),
            registry_path: None,
        }
    }

    fn sample_info(id: &str) -> aic_common::SessionInfo {
        let now = chrono::Utc::now();
        aic_common::SessionInfo {
            id: id.to_string(),
            pid: 4242,
            state: aic_common::SessionState::Attached,
            created_at: now,
            last_seen_at: Some(now),
            last_command_at: None,
            attached_tty: Some("/dev/ttys001".to_string()),
            shell: Some("/bin/zsh".to_string()),
            cwd: Some(std::path::PathBuf::from("/tmp")),
            label: None,
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
        let resp =
            process_control_request(IpcRequest::RegisterSession(sample_info("aaaaaaaa")), &c).await;
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
    async fn list_sessions_marks_stale_active_detached() {
        let c = ctx();
        let mut stale = sample_info("aaaaaaaa");
        stale.last_seen_at = Some(chrono::Utc::now() - chrono::Duration::minutes(2));
        stale.attached_tty = Some("/dev/ttys001".to_string());
        c.registry.register(stale).await;

        let resp = process_control_request(IpcRequest::ListSessions, &c).await;

        match resp {
            IpcResponse::Sessions(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].state, aic_common::SessionState::Detached);
                assert_eq!(list[0].attached_tty, None);
            }
            other => panic!("expected Sessions, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn prune_sessions_removes_old_detached_entries() {
        let c = ctx();
        let mut old = sample_info("aaaaaaaa");
        old.state = aic_common::SessionState::Detached;
        old.last_seen_at = Some(chrono::Utc::now() - chrono::Duration::hours(2));
        c.registry.register(old).await;

        let resp = process_control_request(
            IpcRequest::PruneSessions {
                older_than_secs: 3600,
            },
            &c,
        )
        .await;

        assert_eq!(resp, IpcResponse::PrunedSessions { count: 1 });
        assert!(c.registry.is_empty().await);
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
    async fn heartbeat_updates_registered_session() {
        let c = ctx();
        process_control_request(IpcRequest::RegisterSession(sample_info("aaaaaaaa")), &c).await;
        let seen_at = chrono::Utc::now();
        let resp = process_control_request(
            IpcRequest::HeartbeatSession {
                id: "aaaaaaaa".to_string(),
                seen_at,
                cwd: Some(std::path::PathBuf::from("/work")),
            },
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);

        let sessions = c.registry.list().await;
        assert_eq!(sessions[0].last_seen_at, Some(seen_at));
        assert_eq!(
            sessions[0].cwd.as_deref(),
            Some(std::path::Path::new("/work"))
        );
    }

    #[tokio::test]
    async fn get_last_command_for_session_returns_hook_record() {
        let c = ctx();
        let started_at = chrono::Utc::now();
        process_control_request(
            IpcRequest::CommandStarted {
                session_id: "aaaaaaaa".to_string(),
                command_id: "cmd1".to_string(),
                command: "cargo build".to_string(),
                cwd: Some(std::path::PathBuf::from("/tmp")),
                shell: Some("zsh".to_string()),
                pid: 1234,
                started_at,
            },
            &c,
        )
        .await;
        process_control_request(
            IpcRequest::CommandFinished {
                session_id: "aaaaaaaa".to_string(),
                command_id: "cmd1".to_string(),
                exit_code: 1,
                finished_at: chrono::Utc::now(),
                duration_ms: 12,
            },
            &c,
        )
        .await;

        let resp = process_control_request(
            IpcRequest::GetLastCommandForSession {
                id: "aaaaaaaa".to_string(),
            },
            &c,
        )
        .await;

        match resp {
            IpcResponse::CommandData(record) => {
                assert_eq!(record.command.as_deref(), Some("cargo build"));
                assert_eq!(record.exit_code, 1);
                assert_eq!(record.capture_mode, aic_common::CaptureMode::Hook);
                assert_eq!(
                    record.capture_quality,
                    aic_common::CaptureQuality::MetadataOnly
                );
            }
            other => panic!("CommandData 응답을 기대 — actual: {other:?}"),
        }

        let sessions = c.registry.list().await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "aaaaaaaa");
        assert_eq!(sessions[0].last_command_at, Some(started_at));
    }

    #[tokio::test]
    async fn get_last_command_for_session_missing_returns_error() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::GetLastCommandForSession {
                id: "missing".to_string(),
            },
            &c,
        )
        .await;

        match resp {
            IpcResponse::Error { message } => {
                assert!(message.contains("찾을 수 없습니다"), "actual: {message}");
            }
            other => panic!("Error 응답을 기대 — actual: {other:?}"),
        }
    }

    #[tokio::test]
    async fn stop_session_unknown_id_returns_error() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::StopSession {
                id: "missing".to_string(),
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(message.contains("찾을 수 없습니다"), "actual: {message}");
            }
            other => panic!("Error 응답을 기대 — actual: {other:?}"),
        }
    }

    #[tokio::test]
    async fn stop_session_self_pid_sends_signal_path() {
        // 자기 자신 PID로 등록한 뒤 StopSession을 호출하면 kill 결과를 검증할 수 있다.
        // SIGTERM은 테스트 프로세스에 영향을 줄 수 있으므로 PID를 init(1)로 두고
        // permission denied 또는 ESRCH 한쪽이 나오는지 확인한다 — kill(1, SIGTERM)은
        // 일반 사용자가 EPERM을 받는다.
        let c = ctx();
        let now = chrono::Utc::now();
        let info = aic_common::SessionInfo {
            id: "abcd1234".to_string(),
            pid: 1,
            state: aic_common::SessionState::Attached,
            created_at: now,
            last_seen_at: Some(now),
            last_command_at: None,
            attached_tty: None,
            shell: None,
            cwd: None,
            label: None,
        };
        c.registry.register(info).await;
        let resp = process_control_request(
            IpcRequest::StopSession {
                id: "abcd1234".to_string(),
            },
            &c,
        )
        .await;
        // EPERM/EACCES가 나면 Error, 운이 좋아 (운영 안 좋은) ESRCH면 Pong.
        // 핵심은 panic 안 하고 graceful 응답이라는 것.
        assert!(matches!(
            resp,
            IpcResponse::Error { .. } | IpcResponse::Pong
        ));
    }

    #[test]
    fn stop_session_pid_path_must_look_like_aic_session() {
        assert!(path_matches_aic_session("/tmp/bin/aic-session"));
        assert!(path_matches_aic_session("aic-session"));
        assert!(!path_matches_aic_session("/bin/sh"));
        assert!(!path_matches_aic_session("/usr/bin/aicd"));
        assert!(!path_matches_aic_session(""));
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
        // Phase 3 이후 GetLastCommand는 hook routing 안내 에러를, 나머지 세션-데이터 요청은
        // 기존 "aicd는 세션 데이터" 에러를 반환한다.
        let resp = process_control_request(IpcRequest::GetMetrics, &ctx()).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(message.contains("aicd는 세션 데이터"), "actual: {message}");
            }
            other => panic!("Error 응답을 기대했지만 {other:?}"),
        }

        let last = process_control_request(IpcRequest::GetLastCommand, &ctx()).await;
        match last {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("세션 ID 라우팅"),
                    "GetLastCommand 라우팅 안내 기대 — actual: {message}"
                );
            }
            other => panic!("Error 응답을 기대했지만 {other:?}"),
        }
    }

    #[tokio::test]
    async fn hook_event_pair_lands_in_store() {
        let c = ctx();
        let now = chrono::Utc::now();
        let start = process_control_request(
            IpcRequest::CommandStarted {
                session_id: "abcd1234".to_string(),
                command_id: "c1".to_string(),
                command: "ls -la".to_string(),
                cwd: Some(std::path::PathBuf::from("/tmp")),
                shell: Some("/bin/zsh".to_string()),
                pid: 9999,
                started_at: now,
            },
            &c,
        )
        .await;
        assert_eq!(start, IpcResponse::Pong);

        let end = process_control_request(
            IpcRequest::CommandFinished {
                session_id: "abcd1234".to_string(),
                command_id: "c1".to_string(),
                exit_code: 7,
                finished_at: now,
                duration_ms: 12,
            },
            &c,
        )
        .await;
        assert_eq!(end, IpcResponse::Pong);

        let rec = c.hook_events.last("abcd1234").await.unwrap();
        assert_eq!(rec.command.as_deref(), Some("ls -la"));
        assert_eq!(rec.exit_code, 7);
        assert_eq!(rec.capture_mode, aic_common::CaptureMode::Hook);
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
