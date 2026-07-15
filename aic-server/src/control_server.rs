//! aicd supervisor의 control UDS 서버.
//!
//! `uds_server`와 다르게 RingBuffer에 결합되지 않는다. aicd는 control plane
//! (세션 registry, daemon health, lifecycle command)만 다루고, 출력 캡처는
//! 각 `aic-session`(또는 향후 attach relay)이 보유한다.
//!
//! Phase 1 sub-step 1: 최소 동작 — `Ping → Pong`만 처리한다. 이후 sub-step에서
//! `ListSessions`, `GetMetrics`, `Shutdown` 등을 단계적으로 추가한다.

use crate::agent_event_bus::AgentEventBus;
use crate::command_record_store::CommandRecordStore;
use crate::metrics::AicdMetrics;
use crate::session_registry::SessionRegistry;
use aic_common::{encode_frame, CaptureMode, CommandRecord, IpcRequest, IpcResponse, LogLine};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};

const STALE_ACTIVE_AFTER: chrono::Duration = chrono::Duration::seconds(30);

/// 백그라운드 reconcile 루프 주기. `STALE_ACTIVE_AFTER`와 같은 값을 써서
/// active → detached 전환이 한 주기 안에 잡히도록 한다.
const RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Daemon 측에서 control_server가 외부 상태를 변경할 때 사용하는 핸들.
/// shutdown trigger, session registry, hook event buffer, aicd metric 카운터를 보유한다.
#[derive(Clone)]
pub struct ControlContext {
    /// daemon 종료 신호. `watch`는 level-triggered라 한 번 `send(true)`하면
    /// control/attach serve 루프의 모든 구독자가 신호를 놓치지 않고 깨어난다.
    /// (`Notify::notify_one`은 단일 waiter만 깨워 다중 루프에서 한쪽이 hang 됐다.)
    pub shutdown: watch::Sender<bool>,
    pub registry: SessionRegistry,
    pub record_store: CommandRecordStore,
    pub registry_path: Option<PathBuf>,
    /// Phase 3.1: `RegisterRecordForSession` 등 central store 경로 metric을 증가시킨다.
    /// `Arc`로 공유해 이후 `AttachServer`/`SessionProcessorPool`과 동일 counter를 참조한다.
    pub metrics: Arc<AicdMetrics>,
    /// chat/agent 행위를 OTLP agent exporter로 fan-out하는 tap. exporter가 비활성이면
    /// 구독자가 없어 publish는 조용히 버려진다 — chat 쪽은 그걸 알 필요가 없다.
    pub agent_bus: AgentEventBus,
    /// OTLP exporter 전송 건강. exporter가 비활성이면 `None` — `GetExporterStatus`는 그때
    /// `enabled: false`를 돌려준다("꺼짐"과 "켜졌는데 실패 중"은 다른 상태다).
    pub exporter_health: Option<Arc<crate::otlp_exporter::ExporterHealth>>,
    /// `aic-client`가 `PushLogLines`로 넘긴 자체 로그를 흘려보낼 채널(RFC-006 t11).
    ///
    /// logs exporter(`otlp_exporter::logs::serve_logs`)가 아직 `aicd_main`에 배선되지
    /// 않아(t12가 배선 예정) 지금은 `None`이다 — 그래도 IPC 수신 경로 자체는 여기서 갖춰
    /// 두어, 채널이 준비되는 순간 바로 흐르게 한다. `Some`이 되면 `try_send`로 넣는다
    /// (가득 차면 조용히 drop — self_layer.rs의 재귀 방지 원칙과 동일하게 여기서도
    /// `tracing::` 매크로를 호출해 실패를 로깅하지 않는다).
    pub logs_tx: Option<mpsc::Sender<LogLine>>,
    /// chat `/flush` 요청을 OTLP exporter task(`serve`)로 보내는 채널. exporter가 비활성이면
    /// `None` — 그때 `FlushSpool`은 `Error`로 답한다. `Some`이면 요청 + oneshot reply를 보내고
    /// 드레인 결과를 받아 IPC 응답으로 돌려준다.
    pub flush_tx: Option<mpsc::Sender<crate::otlp_exporter::FlushRequest>>,
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
        let mut shutdown_rx = ctx.shutdown.subscribe();
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
                _ = shutdown_rx.changed() => {
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
        IpcRequest::GetVersion => IpcResponse::Version(aic_common::DaemonVersion {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: env!("AIC_BUILD_COMMIT").to_string(),
            build_info: env!("AIC_BUILD_INFO").to_string(),
        }),
        IpcRequest::GetExporterStatus => IpcResponse::ExporterStatus(
            ctx.exporter_health
                .as_ref()
                .map(|h| h.snapshot())
                // exporter 비활성 — 기본값(enabled: false). 응답을 생략하지 않는 이유는
                // 호출부가 "꺼짐"을 "조회 실패"와 구분해야 하기 때문이다.
                .unwrap_or_default(),
        ),
        IpcRequest::FlushSpool => match &ctx.flush_tx {
            None => IpcResponse::Error {
                message: "OTLP exporter가 꺼져 있어 flush할 spool이 없습니다".to_string(),
            },
            Some(tx) => {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let req = crate::otlp_exporter::FlushRequest { reply: reply_tx };
                // exporter task가 죽었으면 send가 실패한다 — "성공"을 단언하지 않고 정직하게 에러.
                if tx.send(req).await.is_err() {
                    return IpcResponse::Error {
                        message: "OTLP exporter task에 flush 요청을 전달하지 못했습니다(종료됨?)"
                            .to_string(),
                    };
                }
                // 드레인이 큰 백로그를 로컬로 밀 수 있으니 여유 timeout. drain은 첫 일시 실패에서
                // 멈추므로 collector가 죽어 있어도 오래 걸리지 않는다.
                match tokio::time::timeout(std::time::Duration::from_secs(30), reply_rx).await {
                    Ok(Ok(result)) => IpcResponse::SpoolFlushed(result),
                    // reply drop(task가 응답 전에 죽음) 또는 timeout — 결과를 모른다. 단언 대신 에러.
                    _ => IpcResponse::Error {
                        message:
                            "flush 결과를 확인하지 못했습니다(exporter가 응답 전에 종료했거나 \
                                  30초 내 완료하지 못함)"
                                .to_string(),
                    },
                }
            }
        },
        IpcRequest::AgentEvent(ev) => {
            // 저장하지 않고 tap으로 흘리기만 한다 — 로컬 기록은 chat 쪽 audit/tool_record가
            // 이미 담당한다. exporter가 꺼져 있으면 구독자가 없어 조용히 버려진다.
            tracing::debug!(kind = %ev.kind, severity = %ev.severity, "agent event 수신");
            ctx.agent_bus.publish(ev);
            IpcResponse::Pong
        }
        IpcRequest::PushLogLines { lines } => {
            if let Some(tx) = &ctx.logs_tx {
                for line in lines {
                    // 채널이 가득 차면 조용히 버린다 — self_layer.rs와 같은 이유로 여기서
                    // `tracing::` 매크로를 호출해 실패를 로깅하지 않는다(폭주 중 로그를 더
                    // 만들면 상황이 악화된다). t12가 exporter를 배선하기 전까지는
                    // `logs_tx`가 `None`이라 이 루프 자체가 아예 돌지 않는다.
                    let _ = tx.try_send(line);
                }
            }
            // aic-client의 flush는 fire-and-forget이라 실패해도 재시도하지 않는다 —
            // 채널 유무와 무관하게 항상 성공으로 응답한다.
            IpcResponse::Pong
        }
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
            // watch=level-triggered: send_replace로 값을 true로 latch하고 control/
            // attach serve 루프의 모든 구독자를 동시에 깨운다. send()와 달리 구독자가
            // 아직 없어도 값이 설정되므로, 이후 subscribe하는 루프도 신호를 본다.
            ctx.shutdown.send_replace(true);
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
        IpcRequest::GetLastCommandForSession { id } => match ctx.record_store.last(&id).await {
            Some(record) => IpcResponse::CommandData(record),
            None => IpcResponse::Error {
                message: format!("hook metadata record를 찾을 수 없습니다: {id}"),
            },
        },
        // Phase 3.1 Task 1.8 / Phase 3.2 Task 2.1: `aic history` 및 Phase 3.2 read path가 사용한다.
        // list-op 성격(recent / find_by_prefix / recent_lines)이므로 해당 세션에 record가
        // 없어도 빈 Vec로 응답한다 — client가 "no records" UI를 직접 결정할 수 있도록.
        IpcRequest::GetRecentCommandsForSession { id, count } => {
            IpcResponse::CommandRecords(ctx.record_store.recent(&id, count).await)
        }
        IpcRequest::GetRecentLinesForSession { id, count } => {
            // oldest→newest 순서로 record들을 가져온 뒤 output_lines를 flatten,
            // 마지막 `count` 라인만 tail로 잘라낸다. `ring_buffer::recent_lines`와 동일 의미.
            let records = ctx.record_store.recent(&id, usize::MAX).await;
            let lines = tail_flatten_output_lines(&records, count);
            IpcResponse::Lines(lines)
        }
        IpcRequest::FindRecordByPrefixForSession { id, prefix } => {
            IpcResponse::CommandRecords(ctx.record_store.find_by_prefix(&id, &prefix).await)
        }
        IpcRequest::RegisterRecordForSession { session_id, record } => {
            // Phase 3.1 Dual-Write: aic-session이 보낸 PTY/Explicit record를
            // aicd CommandRecordStore에 라우팅한다 (R3.4, R14.1).
            match record.capture_mode {
                CaptureMode::Pty => {
                    ctx.record_store.push_pty(&session_id, record).await;
                    ctx.metrics.inc_central_store_push();
                    IpcResponse::Pong
                }
                CaptureMode::ExplicitCapture => {
                    ctx.record_store.push_explicit(&session_id, record).await;
                    ctx.metrics.inc_central_store_push();
                    IpcResponse::Pong
                }
                CaptureMode::Hook => IpcResponse::Error {
                    message: "Hook capture_mode record는 RegisterRecordForSession 대신 \
                        CommandStarted/CommandFinished 경로를 사용해야 합니다"
                        .to_string(),
                },
            }
        }
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
            ctx.record_store
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
            ctx.record_store
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
        // 있고 aicd record_store에 record가 있으면 hook record를 반환한다.
        IpcRequest::GetLastCommand => {
            // Phase 3.x: 정확한 session 라우팅이 필요해 일단 graceful Error.
            // 사용자가 aic --session <id> 형태로 호출하면 client가 적절히 routing.
            IpcResponse::Error {
                message: "aicd hook GetLastCommand는 세션 ID 라우팅을 거쳐야 합니다 \
                    (--session 인자 사용)"
                    .to_string(),
            }
        }
        // Task 6.3: aicd의 central store / attach metric snapshot을 내려준다 (R14.1~R14.5).
        //
        // `AicdMetrics::snapshot()` 은 `central_store_push_total` / `attach_connections` /
        // `attach_open_total` 을 채운 `MetricsSnapshot` 을 빌드한다. uptime/pid/ipc_request_count
        // 같은 기본 필드도 함께 채워지므로 `aic top` 같은 구 버전 consumer 도 그대로 동작한다.
        // aic-session 쪽의 `dropped_bytes` / `attach_reconnect_total` 은 aicd 에는 존재하지
        // 않으므로 snapshot 기본값(0) 이 그대로 유지된다. client 는 세션 GetMetrics 를 별도로
        // 조회해 합쳐 본다.
        IpcRequest::GetMetrics => IpcResponse::Metrics(ctx.metrics.snapshot()),
        // 그 외 session-level request는 aicd의 책임이 아니다.
        IpcRequest::GetRecentLines { .. }
        | IpcRequest::GetRecentCommands { .. }
        | IpcRequest::FindRecordByPrefix { .. }
        | IpcRequest::RegisterRecord(_) => IpcResponse::Error {
            message: format!("aicd는 세션 데이터 요청을 직접 처리하지 않습니다: {request:?}"),
        },
    }
}

/// oldest→newest 순서의 record 슬라이스에서 `output_lines`를 flatten한 뒤
/// 마지막 `count` 라인만 tail로 잘라낸다.
///
/// `aic-server/src/ring_buffer.rs::recent_lines`와 동일 시맨틱:
/// - `count == 0` → 빈 Vec.
/// - `output_lines` 전체 길이가 `count`보다 작으면 전체를 그대로 반환.
/// - 그 이상이면 뒤에서부터 `count` 라인만 시간순으로 반환.
fn tail_flatten_output_lines(records: &[CommandRecord], count: usize) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }
    // 뒤에서부터 필요한 만큼 수집한 뒤 뒤집어서 시간순으로 반환.
    let mut collected: Vec<String> = Vec::with_capacity(count);
    let mut remaining = count;
    for record in records.iter().rev() {
        let lines = &record.output_lines;
        if lines.len() <= remaining {
            for line in lines.iter().rev() {
                collected.push(line.clone());
            }
            remaining -= lines.len();
        } else {
            for line in lines[lines.len() - remaining..].iter().rev() {
                collected.push(line.clone());
            }
            remaining = 0;
        }
        if remaining == 0 {
            break;
        }
    }
    collected.reverse();
    collected
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

/// `RECONCILE_INTERVAL` 주기로 `reconcile_stale_sessions`를 호출하는 백그라운드
/// 태스크를 spawn한다. 호출자는 종료 시 반환된 핸들을 `abort()`해야 한다.
pub fn spawn_reconcile_loop(ctx: ControlContext) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RECONCILE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // 첫 즉시 tick은 건너뛰고 한 주기 뒤부터 reconcile 시작.
        tick.tick().await;
        loop {
            tick.tick().await;
            reconcile_stale_sessions(&ctx).await;
        }
    })
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
    use crate::metrics::AicdMetrics;
    use std::time::Duration;

    fn ctx() -> ControlContext {
        ControlContext {
            shutdown: watch::channel(false).0,
            registry: SessionRegistry::new(),
            record_store: CommandRecordStore::new(),
            registry_path: None,
            metrics: Arc::new(AicdMetrics::new()),
            agent_bus: AgentEventBus::new(),
            // exporter 미구성 — GetExporterStatus는 `enabled: false`를 돌려준다.
            exporter_health: None,
            // 아직 배선 전(t12) — PushLogLines 핸들러가 no-op으로 Pong만 응답하는지 검증.
            logs_tx: None,
            flush_tx: None,
        }
    }

    fn agent_event(kind: &str) -> aic_common::AgentEvent {
        aic_common::AgentEvent {
            kind: kind.to_string(),
            summary: "rm -rf /tmp/x".to_string(),
            severity: "INFO".to_string(),
            attrs: std::collections::BTreeMap::new(),
            ts: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn agent_event_is_fanned_out_to_tap() {
        let c = ctx();
        let mut rx = c.agent_bus.subscribe();
        let resp = process_control_request(
            IpcRequest::AgentEvent(agent_event(aic_common::AGENT_KIND_TOOL_RUN_COMMAND)),
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);
        let got = rx.try_recv().expect("tap으로 fan-out되어야 함");
        assert_eq!(got.kind, aic_common::AGENT_KIND_TOOL_RUN_COMMAND);
        assert_eq!(got.summary, "rm -rf /tmp/x");
    }

    #[tokio::test]
    async fn agent_event_without_subscriber_still_succeeds() {
        // exporter 비활성(구독자 0) — chat 쪽이 그걸 모른 채 보내도 정상 응답해야 한다.
        let c = ctx();
        assert_eq!(c.agent_bus.receiver_count(), 0);
        let resp = process_control_request(
            IpcRequest::AgentEvent(agent_event(aic_common::AGENT_KIND_RISK_DENIED)),
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);
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
        // Shutdown 처리 후 watch 값이 true로 설정돼야 한다.
        assert!(*c.shutdown.borrow(), "shutdown 신호가 설정되지 않음");
    }

    #[tokio::test]
    async fn session_data_request_rejected_with_error() {
        // Phase 3 이후 GetLastCommand는 hook routing 안내 에러를, session data 조회 request들은
        // 기존 "aicd는 세션 데이터" 에러를 반환한다. GetMetrics는 aicd metric 스냅샷이라 별도
        // 경로(아래 `get_metrics_returns_aicd_snapshot` 참조)로 처리된다.
        let resp = process_control_request(IpcRequest::GetRecentLines { count: 10 }, &ctx()).await;
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

    /// Task 6.3: aicd Control_UDS의 `GetMetrics`는 `AicdMetrics::snapshot()`을 그대로
    /// 내려준다. central_store_push_total/attach_connections/attach_open_total이 실제
    /// 카운터 값을 반영하는지, aic-session 쪽 필드(dropped_bytes/attach_reconnect_total)는
    /// 기본값 0 으로 유지되는지 함께 확인한다 (R14.1~R14.5).
    #[tokio::test]
    async fn get_metrics_returns_aicd_snapshot() {
        // metric init 은 process-global latch 라 테스트마다 호출해도 무해하다.
        crate::metrics::init();
        let c = ctx();

        // 카운터 몇 번 올린 뒤 snapshot 을 GetMetrics 로 조회한다. 직접 inc_* 를 호출해
        // 다른 경로(store push 등) 부작용 없이 snapshot 빌더만 검증한다.
        c.metrics.inc_central_store_push();
        c.metrics.inc_central_store_push();
        c.metrics.inc_central_store_push();
        c.metrics.inc_attach_open();
        c.metrics.inc_attach_connection();
        c.metrics.inc_attach_connection();

        let resp = process_control_request(IpcRequest::GetMetrics, &c).await;
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.central_store_push_total, 3, "R14.1");
                assert_eq!(snap.attach_open_total, 1, "R14.3");
                assert_eq!(snap.attach_connections, 2, "R14.2 (gauge)");
                // aic-session 전용 필드는 aicd snapshot 에서는 기본값 유지.
                assert_eq!(snap.dropped_bytes, 0, "R14.4 — aicd에서는 0");
                assert_eq!(snap.attach_reconnect_total, 0, "R14.5 — aicd에서는 0");
                // 기본 필드도 채워져 있어야 `aic top` 같은 구 버전 consumer 가 동작한다.
                assert_eq!(snap.pid, std::process::id());
            }
            other => panic!("Metrics 응답을 기대 — actual: {other:?}"),
        }
    }

    /// `RegisterRecordForSession` 으로 push 가 성공하면 snapshot 의
    /// `central_store_push_total` 이 함께 증가한다 — Task 1.5 의 metric wiring 이
    /// GetMetrics 경로에서 실제로 관측되는지 end-to-end 로 검증한다 (R14.1).
    #[tokio::test]
    async fn get_metrics_reflects_register_record_push() {
        crate::metrics::init();
        let c = ctx();
        // Pty record 2개 + Explicit record 1개 push.
        for _ in 0..2 {
            let _ = process_control_request(
                IpcRequest::RegisterRecordForSession {
                    session_id: "s1".to_string(),
                    record: make_record(aic_common::CaptureMode::Pty, "ls"),
                },
                &c,
            )
            .await;
        }
        let _ = process_control_request(
            IpcRequest::RegisterRecordForSession {
                session_id: "s1".to_string(),
                record: make_record(aic_common::CaptureMode::ExplicitCapture, "aic run ls"),
            },
            &c,
        )
        .await;

        let resp = process_control_request(IpcRequest::GetMetrics, &c).await;
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.central_store_push_total, 3);
            }
            other => panic!("Metrics 기대 — {other:?}"),
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

        let rec = c.record_store.last("abcd1234").await.unwrap();
        assert_eq!(rec.command.as_deref(), Some("ls -la"));
        assert_eq!(rec.exit_code, 7);
        assert_eq!(rec.capture_mode, aic_common::CaptureMode::Hook);
    }

    // ── Phase 3.1 Task 1.5: RegisterRecordForSession 라우팅 ───────────────

    fn make_record(
        capture_mode: aic_common::CaptureMode,
        command: &str,
    ) -> aic_common::CommandRecord {
        aic_common::CommandRecord {
            id: String::new(),
            command: Some(command.to_string()),
            exit_code: 0,
            output_lines: vec![format!("out-{command}")],
            timestamp: chrono::Utc::now(),
            capture_mode,
            capture_quality: aic_common::CaptureQuality::FullOutput,
            output_metadata: None,
            cwd: None,
            duration_ms: None,
        }
    }

    /// PTY record는 `push_pty` 경로로 들어가고 metric이 증가한다 (R3.4, R14.1).
    #[tokio::test]
    async fn register_record_for_session_routes_pty_to_store() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::RegisterRecordForSession {
                session_id: "sess-pty".to_string(),
                record: make_record(aic_common::CaptureMode::Pty, "ls"),
            },
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);

        let recs = c.record_store.recent("sess-pty", 10).await;
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].command.as_deref(), Some("ls"));
        assert_eq!(recs[0].capture_mode, aic_common::CaptureMode::Pty);
        // id가 비어 있던 record는 store에서 16-hex id를 부여받는다.
        assert_eq!(recs[0].id.len(), 16);
        assert_eq!(c.metrics.central_store_push_total(), 1);
    }

    /// ExplicitCapture record는 `push_explicit` 경로로 들어간다 (R3.4, R14.1).
    #[tokio::test]
    async fn register_record_for_session_routes_explicit_to_store() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::RegisterRecordForSession {
                session_id: "sess-exp".to_string(),
                record: make_record(aic_common::CaptureMode::ExplicitCapture, "aic run ls"),
            },
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);

        let recs = c.record_store.recent("sess-exp", 10).await;
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].capture_mode,
            aic_common::CaptureMode::ExplicitCapture
        );
        assert_eq!(recs[0].command.as_deref(), Some("aic run ls"));
        assert_eq!(c.metrics.central_store_push_total(), 1);
    }

    /// Hook capture_mode는 CommandStarted/CommandFinished 경로 전용이라 Error로 거부된다.
    #[tokio::test]
    async fn register_record_for_session_rejects_hook_mode() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::RegisterRecordForSession {
                session_id: "sess-hook".to_string(),
                record: make_record(aic_common::CaptureMode::Hook, "hook-cmd"),
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("CommandStarted"),
                    "expected Hook rejection message, got: {message}"
                );
            }
            other => panic!("Error 응답을 기대 — actual: {other:?}"),
        }
        // store에 push되지 않았고 metric도 증가하지 않아야 한다.
        assert_eq!(c.record_store.len("sess-hook").await, 0);
        assert_eq!(c.metrics.central_store_push_total(), 0);
    }

    /// 알려지지 않은 session_id라도 push는 성공해야 한다 (session_id는 store에서 새 ring을 연다).
    #[tokio::test]
    async fn register_record_for_session_accepts_unknown_session() {
        let c = ctx();
        // registry에 미등록 + record_store에도 처음 보는 session_id.
        assert_eq!(c.record_store.len("never-seen").await, 0);

        let resp = process_control_request(
            IpcRequest::RegisterRecordForSession {
                session_id: "never-seen".to_string(),
                record: make_record(aic_common::CaptureMode::Pty, "echo hi"),
            },
            &c,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);
        assert_eq!(c.record_store.len("never-seen").await, 1);
        assert_eq!(c.metrics.central_store_push_total(), 1);
    }

    /// 여러 세션에 번갈아 push해도 metric은 누적되고 세션 간 record는 섞이지 않는다.
    #[tokio::test]
    async fn register_record_for_session_isolates_sessions_and_counts() {
        let c = ctx();
        for _ in 0..3 {
            process_control_request(
                IpcRequest::RegisterRecordForSession {
                    session_id: "sa".to_string(),
                    record: make_record(aic_common::CaptureMode::Pty, "cmd-a"),
                },
                &c,
            )
            .await;
        }
        for _ in 0..2 {
            process_control_request(
                IpcRequest::RegisterRecordForSession {
                    session_id: "sb".to_string(),
                    record: make_record(aic_common::CaptureMode::ExplicitCapture, "cmd-b"),
                },
                &c,
            )
            .await;
        }

        assert_eq!(c.record_store.len("sa").await, 3);
        assert_eq!(c.record_store.len("sb").await, 2);
        assert_eq!(c.metrics.central_store_push_total(), 5);

        // 각 세션의 recent에는 해당 세션 command만.
        for r in c.record_store.recent("sa", 10).await {
            assert_eq!(r.command.as_deref(), Some("cmd-a"));
        }
        for r in c.record_store.recent("sb", 10).await {
            assert_eq!(r.command.as_deref(), Some("cmd-b"));
        }
    }

    /// legacy `RegisterRecord(CommandRecord)` variant는 session socket 경로 전용이므로
    /// aicd에서는 여전히 graceful Error로 거부된다 (R12.5 backwards-compat).
    #[tokio::test]
    async fn legacy_register_record_variant_still_rejected() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::RegisterRecord(make_record(aic_common::CaptureMode::Pty, "legacy")),
            &c,
        )
        .await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("aicd는 세션 데이터"),
                    "expected session-data rejection, got: {message}"
                );
            }
            other => panic!("Error 응답을 기대 — actual: {other:?}"),
        }
        assert_eq!(c.metrics.central_store_push_total(), 0);
    }

    // ── Phase 3.2 Task 2.1: 세션-라우팅 read variants ────────────────────

    /// GetRecentCommandsForSession: 세션의 recent를 시간순(oldest→newest) Vec로 반환한다.
    /// 세션이 비어 있으면 빈 Vec (list-op 성격, R4.4).
    #[tokio::test]
    async fn get_recent_commands_for_session_returns_oldest_to_newest() {
        let c = ctx();
        for i in 0..3 {
            process_control_request(
                IpcRequest::RegisterRecordForSession {
                    session_id: "sess".to_string(),
                    record: make_record(aic_common::CaptureMode::Pty, &format!("cmd{i}")),
                },
                &c,
            )
            .await;
        }
        let resp = process_control_request(
            IpcRequest::GetRecentCommandsForSession {
                id: "sess".to_string(),
                count: 10,
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::CommandRecords(recs) => {
                assert_eq!(recs.len(), 3);
                for (i, r) in recs.iter().enumerate() {
                    assert_eq!(r.command.as_deref(), Some(format!("cmd{i}").as_str()));
                }
            }
            other => panic!("CommandRecords 기대 — {other:?}"),
        }
    }

    /// 세션에 record가 없으면 `GetRecentCommandsForSession`는 빈 Vec를 반환한다 (list-op).
    #[tokio::test]
    async fn get_recent_commands_for_session_empty_on_missing_session() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::GetRecentCommandsForSession {
                id: "never".to_string(),
                count: 5,
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::CommandRecords(recs) => assert!(recs.is_empty()),
            other => panic!("CommandRecords 기대 — {other:?}"),
        }
    }

    /// GetRecentLinesForSession: 해당 세션의 record들의 `output_lines`를 flatten하고
    /// 마지막 `count` 라인만 시간순으로 반환한다 (R4.4).
    #[tokio::test]
    async fn get_recent_lines_for_session_tails_flattened_output() {
        let c = ctx();
        // record 2개: ["a","b"] + ["c","d","e"] → 총 5 라인.
        let mut r1 = make_record(aic_common::CaptureMode::Pty, "first");
        r1.output_lines = vec!["a".into(), "b".into()];
        let mut r2 = make_record(aic_common::CaptureMode::Pty, "second");
        r2.output_lines = vec!["c".into(), "d".into(), "e".into()];
        process_control_request(
            IpcRequest::RegisterRecordForSession {
                session_id: "sess".to_string(),
                record: r1,
            },
            &c,
        )
        .await;
        process_control_request(
            IpcRequest::RegisterRecordForSession {
                session_id: "sess".to_string(),
                record: r2,
            },
            &c,
        )
        .await;

        // tail 3: record 경계를 넘겨서도 순서 유지.
        let resp = process_control_request(
            IpcRequest::GetRecentLinesForSession {
                id: "sess".to_string(),
                count: 3,
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::Lines(lines) => assert_eq!(lines, vec!["c", "d", "e"]),
            other => panic!("Lines 기대 — {other:?}"),
        }

        // tail 4: 첫 record의 마지막 라인 + 두 번째 record 전체.
        let resp = process_control_request(
            IpcRequest::GetRecentLinesForSession {
                id: "sess".to_string(),
                count: 4,
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::Lines(lines) => assert_eq!(lines, vec!["b", "c", "d", "e"]),
            other => panic!("Lines 기대 — {other:?}"),
        }

        // count=0 → 빈 Vec.
        let resp = process_control_request(
            IpcRequest::GetRecentLinesForSession {
                id: "sess".to_string(),
                count: 0,
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::Lines(lines) => assert!(lines.is_empty()),
            other => panic!("Lines 기대 — {other:?}"),
        }
    }

    /// 없는 세션에 대한 GetRecentLinesForSession은 빈 Lines를 반환한다.
    #[tokio::test]
    async fn get_recent_lines_for_session_empty_on_missing_session() {
        let c = ctx();
        let resp = process_control_request(
            IpcRequest::GetRecentLinesForSession {
                id: "never".to_string(),
                count: 10,
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::Lines(lines) => assert!(lines.is_empty()),
            other => panic!("Lines 기대 — {other:?}"),
        }
    }

    /// FindRecordByPrefixForSession: 세션 scope 내에서만 prefix 매칭.
    #[tokio::test]
    async fn find_record_by_prefix_for_session_scopes_to_session() {
        let c = ctx();
        // 세션 "a"에는 id가 "aaaa..."인 record만, "b"에는 "bbbb..."인 것만.
        let mut ra1 = make_record(aic_common::CaptureMode::Pty, "a-one");
        ra1.id = "aaaa000000000001".into();
        let mut ra2 = make_record(aic_common::CaptureMode::Pty, "a-two");
        ra2.id = "aaaa000000000002".into();
        let mut rb1 = make_record(aic_common::CaptureMode::Pty, "b-one");
        rb1.id = "bbbb000000000001".into();
        for (sess, rec) in [("a", ra1), ("a", ra2), ("b", rb1)] {
            process_control_request(
                IpcRequest::RegisterRecordForSession {
                    session_id: sess.to_string(),
                    record: rec,
                },
                &c,
            )
            .await;
        }

        // "a" scope에서 aaaa 매칭 → 2개.
        let resp = process_control_request(
            IpcRequest::FindRecordByPrefixForSession {
                id: "a".to_string(),
                prefix: "aaaa".to_string(),
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::CommandRecords(recs) => {
                assert_eq!(recs.len(), 2);
                assert!(recs.iter().all(|r| r.id.starts_with("aaaa")));
            }
            other => panic!("CommandRecords 기대 — {other:?}"),
        }

        // "b" scope에서 aaaa 매칭 → 0개.
        let resp = process_control_request(
            IpcRequest::FindRecordByPrefixForSession {
                id: "b".to_string(),
                prefix: "aaaa".to_string(),
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::CommandRecords(recs) => assert!(recs.is_empty()),
            other => panic!("CommandRecords 기대 — {other:?}"),
        }

        // 빈 prefix → find_by_prefix는 빈 Vec를 반환 (store 계약, R1.5).
        let resp = process_control_request(
            IpcRequest::FindRecordByPrefixForSession {
                id: "a".to_string(),
                prefix: "".to_string(),
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::CommandRecords(recs) => assert!(recs.is_empty()),
            other => panic!("CommandRecords 기대 — {other:?}"),
        }

        // 없는 session → 빈 Vec.
        let resp = process_control_request(
            IpcRequest::FindRecordByPrefixForSession {
                id: "missing".to_string(),
                prefix: "aaaa".to_string(),
            },
            &c,
        )
        .await;
        match resp {
            IpcResponse::CommandRecords(recs) => assert!(recs.is_empty()),
            other => panic!("CommandRecords 기대 — {other:?}"),
        }
    }

    /// `GetLastCommand` (session_id 없음)는 aicd에서 graceful Error 유지 (R7.3, R12.3).
    #[tokio::test]
    async fn get_last_command_without_session_returns_graceful_error() {
        let c = ctx();
        let resp = process_control_request(IpcRequest::GetLastCommand, &c).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("세션 ID 라우팅"),
                    "expected routing hint, got: {message}"
                );
            }
            other => panic!("Error 기대 — {other:?}"),
        }
    }

    /// `tail_flatten_output_lines` 헬퍼 직접 검증 — record 경계를 넘는 flatten.
    #[test]
    fn tail_flatten_output_lines_mirrors_ring_buffer_semantics() {
        let rec = |lines: &[&str]| CommandRecord {
            id: String::new(),
            command: None,
            exit_code: 0,
            output_lines: lines.iter().map(|s| (*s).to_string()).collect(),
            timestamp: chrono::Utc::now(),
            capture_mode: CaptureMode::Pty,
            capture_quality: aic_common::CaptureQuality::FullOutput,
            output_metadata: None,
            cwd: None,
            duration_ms: None,
        };
        let records = vec![rec(&["a", "b"]), rec(&["c", "d", "e"])];

        assert_eq!(tail_flatten_output_lines(&records, 0), Vec::<String>::new());
        assert_eq!(tail_flatten_output_lines(&records, 3), vec!["c", "d", "e"]);
        assert_eq!(
            tail_flatten_output_lines(&records, 4),
            vec!["b", "c", "d", "e"]
        );
        assert_eq!(
            tail_flatten_output_lines(&records, 5),
            vec!["a", "b", "c", "d", "e"]
        );
        // n > total → 모든 라인을 시간순으로.
        assert_eq!(
            tail_flatten_output_lines(&records, 10),
            vec!["a", "b", "c", "d", "e"]
        );
        // 빈 입력.
        assert_eq!(tail_flatten_output_lines(&[], 5), Vec::<String>::new());
    }

    /// R12.4: IPC 역직렬화에 실패하면 handle_client가 graceful Error 응답을 돌려준다.
    /// 이 테스트는 socket 레벨에서 raw JSON 문자열을 frame하여 불량 payload를 전송하고
    /// 서버가 연결을 끊거나 panic 하지 않음을 확인한다.
    #[tokio::test]
    async fn malformed_ipc_request_returns_graceful_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aicd.sock");
        let server = ControlServer::bind(&sock_path).await.unwrap();
        let c = ctx();
        let shutdown = c.shutdown.clone();
        let serve_handle = tokio::spawn(async move { server.serve(c).await });

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        // IpcRequest로 역직렬화되지 않는 JSON (미지 variant 이름).
        let garbage = br#"{"UnknownVariantXyz":{"foo":42}}"#;
        let frame = encode_frame(garbage);
        client.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.starts_with("unknown request"),
                    "expected 'unknown request' prefix, got: {message}"
                );
            }
            other => panic!("Error 기대 — {other:?}"),
        }

        shutdown.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
    }

    // ── 기존 socket smoke tests ─────────────────────────────────────────

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
        let shutdown = c.shutdown.clone();
        let serve_handle = tokio::spawn(async move { server.serve(c).await });

        assert_eq!(ping_through_socket(&sock_path).await, IpcResponse::Pong);

        shutdown.send_replace(true);
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
