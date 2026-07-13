//! Unix Domain Socket 서버.
//!
//! AIC_Client의 IPC 요청을 수신하고 RingBuffer 데이터로 응답한다.
//! Length-prefixed JSON 프레이밍(`aic_common::encode_frame` / `decode_frame`)을 사용한다.
//!
//! ## 운영 모드 (Task 4.2, R6.3, R6.4)
//!
//! `UdsServer`는 두 가지 모드로 동작한다 — [`UdsServerMode`] 참조. 모드는
//! `Arc<AtomicU8>`로 표현되어 runtime에 무중단으로 전환 가능하다.
//!
//! - **`FullLocal`** — 기존 Phase ≤ 3.3 동작. 모든 request variant를 local
//!   `RingBuffer` 기준으로 처리한다. 하위 호환성을 위한 기본값이다.
//! - **`PingOnly`** — Phase 3.4 central_store 모드. `Ping` / `GetMetrics` /
//!   `RegisterRecord`(hook CLI fallback 경로) 세 가지만 처리하고, 그 외의 data
//!   plane 조회(`GetLastCommand`/`GetRecentLines`/`GetRecentCommands`/
//!   `FindRecordByPrefix`)는 즉시 `IpcResponse::Error`로 거절한다. Local
//!   data plane 자체가 생성되어 있지 않거나 비어 있기 때문이다.
//!
//! Task 4.3의 Local_Fallback 경로는 runtime에 `set_mode(FullLocal)`을 호출해
//! 다시 full data plane 응답을 복원할 수 있다.
//!
//! ## Phase 3.5 feature gate (Task 5.2, R7.2, R7.3)
//!
//! Phase 3.5 빌드에서는 세션 로컬 data plane 자체가 제거된다. 모드가 `FullLocal`
//! 이든 `PingOnly` 이든 상관없이 아래 variant만 허용되며, 그 외의 data plane 조회
//! ( `GetLastCommand` / `GetRecentLines` / `GetRecentCommands` /
//! `FindRecordByPrefix` )는 Phase 3.5 전용 안내 에러로 거절된다.
//!
//! - `Ping` — liveness (R7.2)
//! - `RegisterRecord` — hook CLI fallback 경로 (R7.2)
//! - `GetMetrics` — session-level 메트릭 스냅샷

use crate::metrics::AttachMetrics;
use crate::ring_buffer::RingBuffer;
use aic_common::{encode_frame, IpcRequest, IpcResponse};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

/// `aic-session`의 UDS 서버가 data plane 요청에 응답하는 범위.
///
/// R6.3, R6.4: central_store 모드에서는 `Ping` + `RegisterRecord` (hook CLI
/// fallback) + `GetMetrics`만 허용한다. Local_Fallback으로 전환되면 다시
/// `FullLocal`로 돌아가 기존 경로를 복구한다.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdsServerMode {
    /// 모든 data plane 요청을 local `RingBuffer` 기준으로 처리. Phase ≤ 3.3
    /// 기본값이며 Local_Fallback 활성 시에도 사용된다 (R6.4, R9.4).
    FullLocal = 0,
    /// central_store 모드 — Ping/GetMetrics/RegisterRecord만 허용.
    PingOnly = 1,
}

impl UdsServerMode {
    /// u8 표현으로부터 [`UdsServerMode`] 를 복원한다. atomic store 에서 읽은 값을
    /// enum 으로 바꿔 debug 로그/외부 assert 에서 쓰기 위한 helper 이다 — 미지 값은
    /// [`UdsServerMode::FullLocal`] 로 폴백해 안전한 기본 동작을 유지한다.
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => UdsServerMode::PingOnly,
            _ => UdsServerMode::FullLocal,
        }
    }
}

/// `aic-session`이 실행하는 per-session local UDS 서버.
///
/// `mode` 필드는 `Arc<AtomicU8>`로 공유되어 serve 루프와 외부 호출자(Task 4.3
/// Local_Fallback 전환 경로 등)가 lock 없이 모드를 전환할 수 있다.
///
/// `attach_metrics` 필드(옵션)는 Task 6.3 에서 추가되었으며 `GetMetrics` 응답의
/// `dropped_bytes` / `attach_reconnect_total` 필드를 채우기 위해 사용한다
/// (R14.4, R14.5). 호출자가 [`UdsServer::bind_with_attach_metrics`] 로 바인드하면
/// 세션 runtime 의 `AttachMetrics` 인스턴스와 같은 atomic 카운터를 공유한다.
/// 주입되지 않았을 때는 snapshot 의 두 필드가 기본값(0) 으로 내려간다 — 기존 단위
/// 테스트의 회귀를 막기 위한 기본 동작이다.
pub struct UdsServer {
    listener: UnixListener,
    socket_path: PathBuf,
    /// [`UdsServerMode`]의 u8 표현. handler가 [`Ordering::Relaxed`] read로 매번
    /// 읽어 현재 모드를 반영한다 — request 당 한 번의 atomic load만 발생한다.
    mode: Arc<AtomicU8>,
    /// `aic-session` 측 Attach 메트릭. `GetMetrics` 에서 `dropped_bytes` /
    /// `attach_reconnect_total` 필드를 채우는 데 쓰인다 (Task 6.3, R14.4, R14.5).
    attach_metrics: Option<Arc<AttachMetrics>>,
}

impl UdsServer {
    /// UDS 엔드포인트 생성. 기존 소켓 파일이 있으면 삭제 후 재바인딩.
    ///
    /// 초기 모드는 [`UdsServerMode::FullLocal`]이다 — 기존 호출자들이 명시적
    /// 설정 없이도 Phase ≤ 3.3과 동일한 동작을 얻도록 (하위 호환).
    ///
    /// `attach_metrics` 는 주입되지 않는다. 필요하면
    /// [`UdsServer::bind_with_attach_metrics`] 를 사용하라.
    pub async fn bind(socket_path: &Path) -> anyhow::Result<Self> {
        Self::bind_inner(socket_path, None).await
    }

    /// `attach_metrics` 핸들을 함께 주입해 바인드한다. `GetMetrics` 응답에서
    /// `dropped_bytes` / `attach_reconnect_total` 필드가 세션 runtime 과 동일한
    /// 값으로 내려가게 하는 경로다 (Task 6.3, R14.4, R14.5).
    pub async fn bind_with_attach_metrics(
        socket_path: &Path,
        attach_metrics: Arc<AttachMetrics>,
    ) -> anyhow::Result<Self> {
        Self::bind_inner(socket_path, Some(attach_metrics)).await
    }

    async fn bind_inner(
        socket_path: &Path,
        attach_metrics: Option<Arc<AttachMetrics>>,
    ) -> anyhow::Result<Self> {
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
            mode: Arc::new(AtomicU8::new(UdsServerMode::FullLocal as u8)),
            attach_metrics,
        })
    }

    /// 현재 서버 모드를 읽는다. `Ordering::Relaxed`로 가장 최근 저장값을
    /// 반환한다 — 모드 전환은 request 경계에서만 관측되면 충분하다.
    pub fn current_mode(&self) -> UdsServerMode {
        UdsServerMode::from_u8(self.mode.load(Ordering::Relaxed))
    }

    /// 서버 모드를 runtime에 전환한다. 이미 수락된 in-flight request는 이전
    /// 모드로 처리될 수 있으나, 다음 request부터는 즉시 새 모드가 적용된다.
    ///
    /// Task 4.3 Local_Fallback 경로에서 `FullLocal`로 되돌리거나, local data
    /// plane이 생성되지 않았음을 확정한 직후 `PingOnly`로 전환할 때 호출한다.
    pub fn set_mode(&self, mode: UdsServerMode) {
        self.mode.store(mode as u8, Ordering::Relaxed);
    }

    /// 외부에서 모드를 플립할 수 있도록 atomic handle을 공유한다. `serve()`를
    /// `tokio::spawn`에 move한 뒤에도 호출자가 모드 전환을 수행할 수 있게 한다.
    pub fn mode_handle(&self) -> Arc<AtomicU8> {
        Arc::clone(&self.mode)
    }

    /// 클라이언트 연결을 수락하고 IPC 요청을 처리하는 루프.
    pub async fn serve(&self, buffer: Arc<RwLock<RingBuffer>>) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    let buf = Arc::clone(&buffer);
                    let mode = Arc::clone(&self.mode);
                    let metrics = self.attach_metrics.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, buf, mode, metrics).await {
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

/// central_store 모드(`PingOnly`)에서 data plane 조회 요청에 돌려주는 에러 메시지.
/// 사용자가 `aic-session` 소켓 대신 `aicd`를 조회해야 함을 안내한다 (R6.3).
///
/// Phase 3.5 빌드에서는 세션 로컬 data plane 자체가 제거되어 본 상수를 사용하는 경로가
/// 전부 compile out 되므로 `#[cfg(not(feature = "phase-3_5"))]` 로 감싸 dead_code
/// warning 을 방지한다.
#[cfg(not(feature = "phase-3_5"))]
const CENTRAL_STORE_ROUTING_ERROR: &str = "central_store 모드 — aicd를 조회하세요";

/// Phase 3.5 전용 안내 에러 메시지. 세션 로컬 data plane 이 완전히 제거되었음을
/// 안내하고 사용자를 `aicd` 로 유도한다 (R7.2, R7.3).
#[cfg(feature = "phase-3_5")]
const PHASE_3_5_REMOVED_ERROR: &str =
    "Phase 3.5: 세션 로컬 data plane이 제거되었습니다. aicd를 사용하세요.";

/// Phase 3.5 에서 세션 로컬 data plane 조회 요청이 들어왔을 때 돌려줄 Error 응답.
#[cfg(feature = "phase-3_5")]
fn phase_3_5_removed_error() -> IpcResponse {
    IpcResponse::Error {
        message: PHASE_3_5_REMOVED_ERROR.to_string(),
    }
}

/// 단일 클라이언트 연결을 처리한다.
/// Length-prefixed JSON 프레임을 읽고, 요청을 처리한 뒤 응답을 전송한다.
async fn handle_client(
    mut stream: UnixStream,
    buffer: Arc<RwLock<RingBuffer>>,
    mode: Arc<AtomicU8>,
    attach_metrics: Option<Arc<AttachMetrics>>,
) -> anyhow::Result<()> {
    // 프레임 헤더(4바이트) 읽기
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    if payload_len > aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES {
        anyhow::bail!(
            "IPC payload 크기({payload_len})가 허용 한계({})를 초과 — 연결 거절",
            aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES
        );
    }

    // payload 읽기
    let mut payload_buf = vec![0u8; payload_len];
    stream.read_exact(&mut payload_buf).await?;

    // 현재 모드를 한 번만 읽는다 — request 처리 중 모드가 바뀌더라도 이 request는
    // 읽은 시점의 모드 기준으로 일관되게 처리된다.
    let current_mode = UdsServerMode::from_u8(mode.load(Ordering::Relaxed));

    // JSON 역직렬화 — unknown variant 등은 client에 graceful Error 응답
    let response = match serde_json::from_slice::<IpcRequest>(&payload_buf) {
        Ok(request) => {
            process_request(request, &buffer, current_mode, attach_metrics.as_deref()).await
        }
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

/// `PingOnly` 모드에서 data plane 조회 요청에 돌려줄 Error 응답을 생성한다.
///
/// Phase 3.5 빌드에서는 호출 경로가 전부 [`phase_3_5_removed_error`] 로 대체되어
/// 본 함수가 사용되지 않으므로 `#[cfg(not(feature = "phase-3_5"))]` 로 감싸 dead_code
/// warning 을 방지한다.
#[cfg(not(feature = "phase-3_5"))]
fn central_store_routing_error() -> IpcResponse {
    IpcResponse::Error {
        message: CENTRAL_STORE_ROUTING_ERROR.to_string(),
    }
}

/// IpcRequest를 처리하여 IpcResponse를 반환한다.
///
/// `mode`가 [`UdsServerMode::PingOnly`]일 때는 `Ping` / `GetMetrics` /
/// `RegisterRecord` 세 variant 외의 data plane 조회는 즉시
/// [`central_store_routing_error`]를 반환한다 (R6.3).
///
/// Phase 3.5 (Task 5.2, R7.2, R7.3): `phase-3_5` feature 가 활성화되면 모드와
/// 무관하게 세션 로컬 data plane 조회는 모두 [`phase_3_5_removed_error`] 로
/// 거절한다. Phase 3.5 빌드에서는 세션 로컬 ring buffer / OutputProcessor /
/// BoundaryDetector 자체가 존재하지 않으므로 `FullLocal` 모드라도 의미 있는
/// 응답을 내려줄 수 없다.
///
/// Task 6.3 (R14.4, R14.5): `attach_metrics` 가 주입되면 `GetMetrics` 응답의
/// `dropped_bytes` / `attach_reconnect_total` 필드를 세션 runtime 과 동일한
/// 카운터 값으로 채운다. `None` 이면 snapshot 의 두 필드가 기본값 0 으로 내려가
/// 기존 단위 테스트의 회귀가 없다.
async fn process_request(
    request: IpcRequest,
    buffer: &Arc<RwLock<RingBuffer>>,
    mode: UdsServerMode,
    attach_metrics: Option<&AttachMetrics>,
) -> IpcResponse {
    crate::metrics::record_ipc_request();
    match request {
        // ── data plane 조회 — PingOnly 모드에서는 routing error ───────
        IpcRequest::GetLastCommand => {
            #[cfg(feature = "phase-3_5")]
            {
                // Phase 3.5 빌드는 모드와 무관하게 거절 — local data plane 없음 (R7.2, R7.3).
                let _ = mode;
                return phase_3_5_removed_error();
            }
            #[cfg(not(feature = "phase-3_5"))]
            {
                if mode == UdsServerMode::PingOnly {
                    return central_store_routing_error();
                }
                let buf = buffer.read().await;
                match buf.last() {
                    Some(record) => IpcResponse::CommandData(record.clone()),
                    None => IpcResponse::Error {
                        message: "저장된 명령어가 없습니다".to_string(),
                    },
                }
            }
        }
        IpcRequest::GetRecentLines { count } => {
            #[cfg(feature = "phase-3_5")]
            {
                let _ = (mode, count);
                return phase_3_5_removed_error();
            }
            #[cfg(not(feature = "phase-3_5"))]
            {
                if mode == UdsServerMode::PingOnly {
                    return central_store_routing_error();
                }
                let buf = buffer.read().await;
                let lines = buf.recent_lines(count);
                IpcResponse::Lines(lines.into_iter().map(String::from).collect())
            }
        }
        IpcRequest::GetRecentCommands { count } => {
            #[cfg(feature = "phase-3_5")]
            {
                let _ = (mode, count);
                return phase_3_5_removed_error();
            }
            #[cfg(not(feature = "phase-3_5"))]
            {
                if mode == UdsServerMode::PingOnly {
                    return central_store_routing_error();
                }
                let buf = buffer.read().await;
                IpcResponse::CommandRecords(buf.recent_records(count))
            }
        }
        IpcRequest::FindRecordByPrefix { ref prefix } => {
            #[cfg(feature = "phase-3_5")]
            {
                let _ = (mode, prefix);
                return phase_3_5_removed_error();
            }
            #[cfg(not(feature = "phase-3_5"))]
            {
                if mode == UdsServerMode::PingOnly {
                    return central_store_routing_error();
                }
                let buf = buffer.read().await;
                IpcResponse::CommandRecords(buf.find_by_prefix(prefix))
            }
        }
        // ── hook CLI fallback 경로 — PingOnly / Phase 3.5 에서도 허용 (R6.3, R7.2) ──
        //
        // `aic _hook-event start/end` CLI가 aicd 미실행 시 세션 local socket으로
        // fallback해 record를 푸시하는 경로가 유지되어야 한다. PingOnly 모드 / Phase 3.5
        // 에서는 `RingBuffer`가 cap=0 dummy로 주입되어 있으면 push는 무시되지만 response는
        // Pong으로 내려가 client 측 silent skip이 성공 경로와 동일하게 이어진다.
        IpcRequest::RegisterRecord(ref record) => {
            let mut buf = buffer.write().await;
            buf.push(record.clone());
            IpcResponse::Pong
        }
        IpcRequest::Ping => IpcResponse::Pong,
        // Ping과 마찬가지로 양 데몬 모두에서 의미가 있다 — aic-session도 자기 빌드로
        // 답한다(구버전 세션 데몬이 남아 도는 경우를 같은 방식으로 확인할 수 있게).
        IpcRequest::GetVersion => IpcResponse::Version(aic_common::DaemonVersion {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: env!("AIC_BUILD_COMMIT").to_string(),
            build_info: env!("AIC_BUILD_INFO").to_string(),
        }),
        IpcRequest::ListSessions
        | IpcRequest::AgentEvent(_)
        | IpcRequest::GetExporterStatus
        | IpcRequest::PushLogLines { .. }
        | IpcRequest::PruneSessions { .. }
        | IpcRequest::Shutdown
        | IpcRequest::RegisterSession(_)
        | IpcRequest::UnregisterSession { .. }
        | IpcRequest::HeartbeatSession { .. }
        | IpcRequest::StopSession { .. }
        | IpcRequest::GetLastCommandForSession { .. }
        | IpcRequest::GetRecentCommandsForSession { .. }
        | IpcRequest::GetRecentLinesForSession { .. }
        | IpcRequest::FindRecordByPrefixForSession { .. }
        | IpcRequest::RegisterRecordForSession { .. }
        | IpcRequest::TagSession { .. }
        | IpcRequest::CommandStarted { .. }
        | IpcRequest::CommandFinished { .. } => IpcResponse::Error {
            message: format!(
                "{request:?}는 aicd control plane 요청입니다 — aicd 소켓에 연결하세요"
            ),
        },
        // ── GetMetrics — 모드에 관계없이 세션-레벨 스냅샷 반환 (R6.3) ─
        //
        // PingOnly 모드에서는 `RingBuffer`가 cap=0 dummy이므로 `rb_used`/
        // `rb_capacity`는 모두 0으로 내려가고, `last_command_secs_ago`도 None이다.
        // 이는 Task 4.1의 central-only 운영 상태를 그대로 반영한다.
        //
        // Task 6.3 (R14.4, R14.5): `attach_metrics` 가 주입되면 `dropped_bytes` /
        // `attach_reconnect_total` 필드를 세션 runtime 과 동일한 atomic 카운터 값으로
        // 채운다. 주입이 없으면 기본값 0 이 내려가 기존 단위 테스트의 회귀가 없다.
        IpcRequest::GetMetrics => {
            let buf = buffer.read().await;
            let last_command_secs_ago = buf.last().map(|rec| {
                let elapsed = chrono::Utc::now() - rec.timestamp;
                elapsed.num_seconds().max(0) as u64
            });
            let mut snap = aic_common::MetricsSnapshot {
                uptime_secs: crate::metrics::uptime_secs(),
                pid: std::process::id(),
                ipc_request_count: crate::metrics::ipc_request_count(),
                rb_used: buf.total_lines(),
                rb_capacity: buf.capacity(),
                last_command_secs_ago,
                // aicd 전용 필드(central_store_push_total/attach_connections/
                // attach_open_total)는 aic-session 경로에서 관측하지 않는다. client는
                // aicd Control_UDS의 GetMetrics 를 별도로 조회해 합쳐 본다.
                ..aic_common::MetricsSnapshot::default()
            };
            if let Some(m) = attach_metrics {
                m.fill_snapshot(&mut snap);
            }
            IpcResponse::Metrics(snap)
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
        let resp = process_request(IpcRequest::Ping, &buffer, UdsServerMode::FullLocal, None).await;
        assert_eq!(resp, IpcResponse::Pong);
    }

    #[tokio::test]
    async fn process_get_last_command_empty_buffer() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(100)));
        let resp = process_request(
            IpcRequest::GetLastCommand,
            &buffer,
            UdsServerMode::FullLocal,
            None,
        )
        .await;
        match resp {
            IpcResponse::Error { message } => {
                // Phase 3.5: FullLocal 라도 data plane 제거. Phase ≤ 3.4: "저장된 명령어가 없습니다".
                #[cfg(feature = "phase-3_5")]
                assert_eq!(message, PHASE_3_5_REMOVED_ERROR);
                #[cfg(not(feature = "phase-3_5"))]
                assert!(message.contains("저장된 명령어가 없습니다"));
            }
            _ => panic!("빈 버퍼에서 Error 응답을 기대했습니다"),
        }
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn process_get_last_command_with_record() {
        let buffer = make_buffer_with_record();
        let resp = process_request(
            IpcRequest::GetLastCommand,
            &buffer,
            UdsServerMode::FullLocal,
            None,
        )
        .await;
        match resp {
            IpcResponse::CommandData(record) => {
                assert_eq!(record.command, Some("cargo test".to_string()));
                assert_eq!(record.exit_code, 1);
            }
            _ => panic!("CommandData 응답을 기대했습니다"),
        }
    }

    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn process_get_recent_lines() {
        let buffer = make_buffer_with_record();
        let resp = process_request(
            IpcRequest::GetRecentLines { count: 1 },
            &buffer,
            UdsServerMode::FullLocal,
            None,
        )
        .await;
        match resp {
            IpcResponse::Lines(lines) => {
                assert_eq!(lines, vec!["help: try"]);
            }
            _ => panic!("Lines 응답을 기대했습니다"),
        }
    }

    // ── Task 4.2: UdsServerMode 단위 테스트 ──────────────────────────────
    //
    // PingOnly 모드에서 data plane 조회가 routing error로 내려가고, 모드가
    // FullLocal로 전환되면 동일 request가 기존 응답으로 돌아가는지 확인한다.

    /// PingOnly 모드에서 Ping은 여전히 Pong으로 응답해야 한다 (R6.3).
    #[tokio::test]
    async fn process_ping_allowed_in_ping_only_mode() {
        let buffer = make_buffer_with_record();
        let resp = process_request(IpcRequest::Ping, &buffer, UdsServerMode::PingOnly, None).await;
        assert_eq!(resp, IpcResponse::Pong);
    }

    /// PingOnly 모드에서는 RecordStore 조회류 요청이 모두 central_store routing
    /// error로 내려간다 (R6.3). 네 가지 variant를 모두 확인한다.
    ///
    /// Phase 3.5 빌드에서는 FullLocal / PingOnly 모드 구분 없이 모두 거절되고
    /// 메시지가 [`PHASE_3_5_REMOVED_ERROR`] 로 바뀌므로, 본 테스트는 Phase ≤ 3.4
    /// 빌드에서만 유효하다. Phase 3.5 전용 검증은
    /// [`phase_3_5_full_local_mode_rejects_data_plane_reads`] 를 참조한다.
    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn ping_only_mode_rejects_data_plane_reads() {
        let buffer = make_buffer_with_record();
        let cases: Vec<IpcRequest> = vec![
            IpcRequest::GetLastCommand,
            IpcRequest::GetRecentLines { count: 5 },
            IpcRequest::GetRecentCommands { count: 5 },
            IpcRequest::FindRecordByPrefix {
                prefix: "ab".to_string(),
            },
        ];

        for req in cases {
            let dbg = format!("{req:?}");
            let resp = process_request(req, &buffer, UdsServerMode::PingOnly, None).await;
            match resp {
                IpcResponse::Error { message } => {
                    assert_eq!(
                        message, CENTRAL_STORE_ROUTING_ERROR,
                        "PingOnly 모드에서 {dbg} 는 central_store 안내 에러를 내야 한다"
                    );
                }
                other => panic!("PingOnly 모드에서 {dbg} 가 Error 가 아님: {other:?}"),
            }
        }
    }

    /// PingOnly 모드에서도 `RegisterRecord`는 hook CLI fallback 경로를 위해 허용된다
    /// (R6.3). buffer capacity 가 0인 경우에는 push 가 silently drop 되지만 응답은
    /// Pong 으로 내려가야 한다.
    #[tokio::test]
    async fn ping_only_mode_allows_register_record_fallback() {
        // cap=0 dummy ring buffer — Task 4.1 이 central_store 모드에서 생성하는 것과 같다.
        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        let record = CommandRecord {
            command: Some("git status".to_string()),
            exit_code: 0,
            output_lines: vec!["clean".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let resp = process_request(
            IpcRequest::RegisterRecord(record),
            &buffer,
            UdsServerMode::PingOnly,
            None,
        )
        .await;
        assert_eq!(resp, IpcResponse::Pong);
    }

    /// PingOnly 모드에서도 `GetMetrics`는 세션-레벨 스냅샷을 내려준다 (R6.3).
    /// cap=0 dummy buffer 에서는 rb_used/rb_capacity 모두 0 으로 내려가는지 확인한다.
    #[tokio::test]
    async fn ping_only_mode_allows_get_metrics_with_empty_buffer() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        let resp = process_request(
            IpcRequest::GetMetrics,
            &buffer,
            UdsServerMode::PingOnly,
            None,
        )
        .await;
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.rb_used, 0);
                assert_eq!(snap.rb_capacity, 0);
                assert!(snap.last_command_secs_ago.is_none());
            }
            other => panic!("PingOnly GetMetrics 가 Metrics 가 아님: {other:?}"),
        }
    }

    /// Local_Fallback 시나리오 — 처음에 PingOnly 로 시작했다가 FullLocal 로 전환되면
    /// 동일 request 가 routing error → 기존 data plane 응답으로 바뀌어야 한다 (R6.4).
    ///
    /// `mode_handle` 을 공유해 외부에서 전환한 뒤 handler 에 새 모드를 넘겨
    /// "같은 request 가 모드에 따라 다르게 응답한다" 를 직접 확인한다.
    ///
    /// Phase 3.5 빌드에서는 FullLocal 로 전환되어도 data plane 은 제거되어 있으므로
    /// 본 테스트는 Phase ≤ 3.4 빌드에서만 유효하다.
    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn mode_switch_changes_handler_response() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("mode-switch.sock");
        let server = UdsServer::bind(&sock_path).await.unwrap();
        // bind 직후 기본 모드는 FullLocal (하위 호환).
        assert_eq!(server.current_mode(), UdsServerMode::FullLocal);

        // 외부에서 PingOnly 로 전환.
        server.set_mode(UdsServerMode::PingOnly);
        assert_eq!(server.current_mode(), UdsServerMode::PingOnly);

        let buffer = make_buffer_with_record();

        // PingOnly 단계: GetLastCommand 는 routing error.
        let resp_ping_only = process_request(
            IpcRequest::GetLastCommand,
            &buffer,
            server.current_mode(),
            None,
        )
        .await;
        match resp_ping_only {
            IpcResponse::Error { message } => {
                assert_eq!(message, CENTRAL_STORE_ROUTING_ERROR);
            }
            other => panic!("PingOnly 기대 Error, got {other:?}"),
        }

        // Local_Fallback 진입 — FullLocal 로 되돌린다 (R6.4).
        server.set_mode(UdsServerMode::FullLocal);
        assert_eq!(server.current_mode(), UdsServerMode::FullLocal);

        // 같은 request 가 이번엔 CommandData 로 응답.
        let resp_full_local = process_request(
            IpcRequest::GetLastCommand,
            &buffer,
            server.current_mode(),
            None,
        )
        .await;
        match resp_full_local {
            IpcResponse::CommandData(record) => {
                assert_eq!(record.command.as_deref(), Some("cargo test"));
                assert_eq!(record.exit_code, 1);
            }
            other => panic!("FullLocal 기대 CommandData, got {other:?}"),
        }
    }

    /// mode_handle() 이 반환한 Arc 가 서버 내부와 같은 atomic 을 공유하는지 확인한다.
    /// Task 4.3 이 spawn 된 serve task 바깥에서 모드를 플립할 때 사용할 경로이다.
    #[tokio::test]
    async fn mode_handle_shares_atomic_with_server() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("mode-handle.sock");
        let server = UdsServer::bind(&sock_path).await.unwrap();
        let handle = server.mode_handle();

        // 외부 handle 로 전환 → 서버 내부 view 가 바뀐다.
        handle.store(UdsServerMode::PingOnly as u8, Ordering::Relaxed);
        assert_eq!(server.current_mode(), UdsServerMode::PingOnly);

        // 반대 방향: 서버 API 로 전환 → handle 쪽에서도 관측된다.
        server.set_mode(UdsServerMode::FullLocal);
        assert_eq!(
            UdsServerMode::from_u8(handle.load(Ordering::Relaxed)),
            UdsServerMode::FullLocal,
        );
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

    #[cfg(not(feature = "phase-3_5"))]
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

    /// Task 4.2 end-to-end: 외부에서 `set_mode(PingOnly)` 를 호출한 뒤 실제
    /// UDS round-trip 에서 routing error 가 관측되는지 확인한다.
    ///
    /// Phase 3.5 빌드에서는 error message 가 [`PHASE_3_5_REMOVED_ERROR`] 로 바뀌고
    /// FullLocal 전환 후에도 여전히 거절되므로, 별도 테스트
    /// ([`phase_3_5_round_trip_full_local_is_removed_error`]) 에서 검증한다.
    #[cfg(not(feature = "phase-3_5"))]
    #[tokio::test]
    async fn uds_server_round_trip_reflects_ping_only_mode() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("round-trip-ping-only.sock");

        let server = UdsServer::bind(&sock_path).await.unwrap();
        // `serve()` 가 self 를 Arc 없이 소비하므로 handle 을 먼저 확보해 둔다.
        let mode_handle = server.mode_handle();

        let buffer = make_buffer_with_record();
        let buf_clone = Arc::clone(&buffer);
        let serve_handle = tokio::spawn(async move {
            server.serve(buf_clone).await;
        });

        // PingOnly 로 전환 (Task 4.1 + 4.2 의 central_store 기동 경로).
        mode_handle.store(UdsServerMode::PingOnly as u8, Ordering::Relaxed);

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let req = IpcRequest::GetLastCommand;
        let frame = encode_frame(&serde_json::to_vec(&req).unwrap());
        client.write_all(&frame).await.unwrap();

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        match resp {
            IpcResponse::Error { message } => {
                assert_eq!(message, CENTRAL_STORE_ROUTING_ERROR);
            }
            other => panic!("PingOnly round-trip 에서 Error 를 기대: {other:?}"),
        }

        // FullLocal 로 되돌린 뒤 같은 request 가 CommandData 로 내려오는지 확인 (R6.4).
        mode_handle.store(UdsServerMode::FullLocal as u8, Ordering::Relaxed);

        let mut client2 = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let req = IpcRequest::GetLastCommand;
        let frame = encode_frame(&serde_json::to_vec(&req).unwrap());
        client2.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 4];
        client2.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client2.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        match resp {
            IpcResponse::CommandData(record) => {
                assert_eq!(record.command.as_deref(), Some("cargo test"));
            }
            other => panic!("FullLocal round-trip 에서 CommandData 를 기대: {other:?}"),
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

    // ── Task 5.2 (Phase 3.5): legacy data plane 제거 ─────────────────────
    //
    // Phase 3.5 빌드에서는 `UdsServerMode` 와 무관하게 세션 로컬 ring buffer 기반의
    // data plane 조회가 모두 거절되어야 한다 (R7.2, R7.3). 아래 테스트들은
    // `phase-3_5` feature 가 활성화된 빌드에서만 컴파일/실행된다.

    /// Phase 3.5 에서는 FullLocal 모드로 들어온 data plane 조회가 모두
    /// [`PHASE_3_5_REMOVED_ERROR`] 로 거절된다 (R7.2, R7.3).
    ///
    /// record 가 있는 buffer 를 주더라도 응답은 Error 여야 한다 — 이는 "세션 로컬
    /// data plane 자체가 제거되었다" 는 계약을 가장 직접적으로 검증한다.
    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase_3_5_full_local_mode_rejects_data_plane_reads() {
        let buffer = make_buffer_with_record();
        let cases: Vec<IpcRequest> = vec![
            IpcRequest::GetLastCommand,
            IpcRequest::GetRecentLines { count: 5 },
            IpcRequest::GetRecentCommands { count: 5 },
            IpcRequest::FindRecordByPrefix {
                prefix: "ab".to_string(),
            },
        ];

        for req in cases {
            let dbg = format!("{req:?}");
            let resp = process_request(req, &buffer, UdsServerMode::FullLocal, None).await;
            match resp {
                IpcResponse::Error { message } => {
                    assert_eq!(
                        message, PHASE_3_5_REMOVED_ERROR,
                        "Phase 3.5 FullLocal 에서 {dbg} 는 제거 안내 에러를 내야 한다"
                    );
                }
                other => panic!("Phase 3.5 FullLocal 에서 {dbg} 가 Error 가 아님: {other:?}"),
            }
        }
    }

    /// Phase 3.5 PingOnly 모드에서도 같은 메시지로 거절된다 (R7.2, R7.3).
    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase_3_5_ping_only_mode_rejects_data_plane_reads() {
        let buffer = make_buffer_with_record();
        let cases: Vec<IpcRequest> = vec![
            IpcRequest::GetLastCommand,
            IpcRequest::GetRecentLines { count: 5 },
            IpcRequest::GetRecentCommands { count: 5 },
            IpcRequest::FindRecordByPrefix {
                prefix: "ab".to_string(),
            },
        ];

        for req in cases {
            let dbg = format!("{req:?}");
            let resp = process_request(req, &buffer, UdsServerMode::PingOnly, None).await;
            match resp {
                IpcResponse::Error { message } => {
                    assert_eq!(
                        message, PHASE_3_5_REMOVED_ERROR,
                        "Phase 3.5 PingOnly 에서 {dbg} 는 제거 안내 에러를 내야 한다"
                    );
                }
                other => panic!("Phase 3.5 PingOnly 에서 {dbg} 가 Error 가 아님: {other:?}"),
            }
        }
    }

    /// Phase 3.5 에서도 `Ping` 은 모드와 무관하게 `Pong` 으로 응답한다 (liveness, R7.2).
    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase_3_5_ping_allowed_in_both_modes() {
        let buffer = make_buffer_with_record();
        for mode in [UdsServerMode::FullLocal, UdsServerMode::PingOnly] {
            let resp = process_request(IpcRequest::Ping, &buffer, mode, None).await;
            assert_eq!(
                resp,
                IpcResponse::Pong,
                "Phase 3.5 {mode:?} 에서 Ping 은 Pong 으로 응답해야 한다 (liveness)"
            );
        }
    }

    /// Phase 3.5 에서도 `RegisterRecord` 는 hook CLI fallback 경로를 위해 허용된다
    /// (R7.2). buffer 에는 capacity 0 dummy 가 주입되더라도 응답은 Pong 으로 내려가
    /// client 측 silent skip 경로가 성공 case 와 동일하게 이어진다.
    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase_3_5_register_record_allowed_for_hook_cli_fallback() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        let record = CommandRecord {
            command: Some("git status".to_string()),
            exit_code: 0,
            output_lines: vec!["clean".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        for mode in [UdsServerMode::FullLocal, UdsServerMode::PingOnly] {
            let resp = process_request(
                IpcRequest::RegisterRecord(record.clone()),
                &buffer,
                mode,
                None,
            )
            .await;
            assert_eq!(
                resp,
                IpcResponse::Pong,
                "Phase 3.5 {mode:?} 에서 RegisterRecord 는 Pong 으로 응답해야 한다 (hook CLI fallback, R7.2)"
            );
        }
    }

    /// Phase 3.5 에서도 `GetMetrics` 는 세션-레벨 스냅샷을 계속 내려준다. dummy
    /// buffer (cap=0) 에서는 rb_used/rb_capacity 모두 0 이다 — 세션 로컬 data plane 이
    /// 제거되었다는 Phase 3.5 의 계약을 자연스럽게 반영한다.
    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase_3_5_get_metrics_allowed_with_empty_buffer() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        for mode in [UdsServerMode::FullLocal, UdsServerMode::PingOnly] {
            let resp = process_request(IpcRequest::GetMetrics, &buffer, mode, None).await;
            match resp {
                IpcResponse::Metrics(snap) => {
                    assert_eq!(snap.rb_used, 0);
                    assert_eq!(snap.rb_capacity, 0);
                    assert!(snap.last_command_secs_ago.is_none());
                }
                other => panic!("Phase 3.5 {mode:?} GetMetrics 가 Metrics 가 아님: {other:?}"),
            }
        }
    }

    /// Phase 3.5 end-to-end: 실제 UDS round-trip 에서 FullLocal 모드라도 data plane
    /// 조회가 제거 안내 에러로 내려간다 (R7.2, R7.3, R20.3). 세션 소켓은 여전히 bind
    /// 되어 liveness / hook fallback 을 제공하지만, record 조회 경로는 제거되었다.
    #[cfg(feature = "phase-3_5")]
    #[tokio::test]
    async fn phase_3_5_round_trip_full_local_is_removed_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("phase-3_5-round-trip.sock");

        let server = UdsServer::bind(&sock_path).await.unwrap();
        // 기본 모드는 FullLocal — Phase 3.5 에서도 bind 초기값은 동일하다.
        assert_eq!(server.current_mode(), UdsServerMode::FullLocal);

        let buffer = make_buffer_with_record();
        let buf_clone = Arc::clone(&buffer);
        let serve_handle = tokio::spawn(async move {
            server.serve(buf_clone).await;
        });

        // (1) GetLastCommand — Phase 3.5 removed error 로 내려간다.
        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let req = IpcRequest::GetLastCommand;
        let frame = encode_frame(&serde_json::to_vec(&req).unwrap());
        client.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        match resp {
            IpcResponse::Error { message } => {
                assert_eq!(message, PHASE_3_5_REMOVED_ERROR);
            }
            other => panic!("Phase 3.5 round-trip 에서 Error 를 기대: {other:?}"),
        }

        // (2) Ping 은 여전히 Pong.
        let mut client2 = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let req = IpcRequest::Ping;
        let frame = encode_frame(&serde_json::to_vec(&req).unwrap());
        client2.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 4];
        client2.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client2.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        assert_eq!(resp, IpcResponse::Pong);

        serve_handle.abort();
    }

    // ── Task 6.3: GetMetrics 에 AttachMetrics 필드 포함 ──────────────────
    //
    // `attach_metrics` 가 주입된 세션에서는 `GetMetrics` 응답이 `dropped_bytes` /
    // `attach_reconnect_total` 필드를 세션 runtime 의 atomic 카운터와 동일한 값으로
    // 내려준다 (R14.4, R14.5). 주입되지 않은 경우는 기본값(0) 이 그대로 내려가
    // 기존 단위 테스트가 회귀하지 않는다.

    /// attach_metrics 가 주입되지 않은 경우 dropped_bytes / attach_reconnect_total 은
    /// 기본값 0 으로 내려간다 — 기존 경로의 backwards-compat.
    #[tokio::test]
    async fn get_metrics_without_attach_metrics_returns_zero_defaults() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        let resp = process_request(
            IpcRequest::GetMetrics,
            &buffer,
            UdsServerMode::FullLocal,
            None,
        )
        .await;
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.dropped_bytes, 0);
                assert_eq!(snap.attach_reconnect_total, 0);
                // aicd 전용 필드도 기본값 — aic-session 에서는 채우지 않는다.
                assert_eq!(snap.central_store_push_total, 0);
                assert_eq!(snap.attach_connections, 0);
                assert_eq!(snap.attach_open_total, 0);
            }
            other => panic!("Metrics 기대 — {other:?}"),
        }
    }

    /// attach_metrics 카운터를 올린 뒤 GetMetrics 를 호출하면 같은 값이 snapshot 에
    /// 반영된다 (R14.4, R14.5).
    #[tokio::test]
    async fn get_metrics_with_attach_metrics_reflects_counters() {
        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        let attach = Arc::new(AttachMetrics::new());
        attach.add_dropped_bytes(100);
        attach.add_dropped_bytes(250);
        attach.inc_attach_reconnect();
        attach.inc_attach_reconnect();
        attach.inc_attach_reconnect();

        let resp = process_request(
            IpcRequest::GetMetrics,
            &buffer,
            UdsServerMode::FullLocal,
            Some(attach.as_ref()),
        )
        .await;
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.dropped_bytes, 350, "R14.4");
                assert_eq!(snap.attach_reconnect_total, 3, "R14.5");
                // 기존 ring buffer 필드도 정상 반영.
                assert_eq!(snap.rb_used, 0);
                assert_eq!(snap.rb_capacity, 0);
                // aicd 전용 필드는 aic-session 에서 관측하지 않아 기본값.
                assert_eq!(snap.central_store_push_total, 0);
                assert_eq!(snap.attach_connections, 0);
                assert_eq!(snap.attach_open_total, 0);
            }
            other => panic!("Metrics 기대 — {other:?}"),
        }
    }

    /// `AttachMetrics::dropped_bytes_handle()` 이 반환한 Arc 로 직접 올린 값도
    /// 같은 카운터를 공유하므로 snapshot 에 그대로 내려온다. Task 3.4 의
    /// `BoundedByteChannel` 통합 지점이 6.3 GetMetrics 경로에서도 그대로 작동함을
    /// 보여주는 회귀 테스트이다.
    #[tokio::test]
    async fn get_metrics_reflects_dropped_bytes_via_shared_handle() {
        use std::sync::atomic::Ordering as AO;

        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        let attach = Arc::new(AttachMetrics::new());
        let handle = attach.dropped_bytes_handle();
        // BoundedByteChannel 이 drop 을 관측했다는 가정하에 직접 누적.
        handle.fetch_add(4096, AO::Relaxed);
        handle.fetch_add(512, AO::Relaxed);

        let resp = process_request(
            IpcRequest::GetMetrics,
            &buffer,
            UdsServerMode::PingOnly,
            Some(attach.as_ref()),
        )
        .await;
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.dropped_bytes, 4608);
                assert_eq!(snap.attach_reconnect_total, 0);
            }
            other => panic!("Metrics 기대 — {other:?}"),
        }
    }

    /// `bind_with_attach_metrics` 로 바인드한 서버는 실제 UDS round-trip 에서도
    /// attach 카운터를 snapshot 에 내려준다 (R14.4, R14.5).
    #[tokio::test]
    async fn bind_with_attach_metrics_round_trip_includes_counters() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("attach-metrics-round-trip.sock");

        let attach = Arc::new(AttachMetrics::new());
        attach.add_dropped_bytes(777);
        attach.inc_attach_reconnect();

        let server = UdsServer::bind_with_attach_metrics(&sock_path, Arc::clone(&attach))
            .await
            .unwrap();
        let buffer = Arc::new(RwLock::new(RingBuffer::new(0)));
        let buf_clone = Arc::clone(&buffer);
        let serve_handle = tokio::spawn(async move {
            server.serve(buf_clone).await;
        });

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let frame = encode_frame(&serde_json::to_vec(&IpcRequest::GetMetrics).unwrap());
        client.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.dropped_bytes, 777);
                assert_eq!(snap.attach_reconnect_total, 1);
            }
            other => panic!("Metrics 기대 — {other:?}"),
        }

        // round-trip 이후 `attach` 카운터를 계속 올리면 새 연결의 snapshot 에도
        // 반영되는지 확인 — runtime 전체가 같은 atomic 을 공유하는지 확인하는 경로.
        attach.add_dropped_bytes(23);
        attach.inc_attach_reconnect();

        let mut client2 = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let frame = encode_frame(&serde_json::to_vec(&IpcRequest::GetMetrics).unwrap());
        client2.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 4];
        client2.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client2.read_exact(&mut resp_buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
        match resp {
            IpcResponse::Metrics(snap) => {
                assert_eq!(snap.dropped_bytes, 800);
                assert_eq!(snap.attach_reconnect_total, 2);
            }
            other => panic!("Metrics 기대 — {other:?}"),
        }

        serve_handle.abort();
    }

    /// 구 버전 consumer 가 snapshot 의 새 필드를 "무시" 해도 정상 작동함을 회귀로
    /// 확인한다. 실제로는 `MetricsSnapshot` 의 `#[serde(default)]` 가 양방향 호환을
    /// 제공하지만, 여기서는 client 가 legacy field 만 읽어도 panic 없이 값을
    /// 얻을 수 있는지 end-to-end 로 체크한다 (R14 backwards-compat, 6.1 의 수동
    /// 회귀 항목과 동일한 의도).
    #[tokio::test]
    async fn legacy_consumers_only_reading_old_fields_still_work() {
        let buffer = make_buffer_with_record();
        let attach = Arc::new(AttachMetrics::new());
        attach.add_dropped_bytes(1234);
        attach.inc_attach_reconnect();

        let resp = process_request(
            IpcRequest::GetMetrics,
            &buffer,
            UdsServerMode::FullLocal,
            Some(attach.as_ref()),
        )
        .await;
        match resp {
            IpcResponse::Metrics(snap) => {
                // 구 버전 consumer (top.rs, doctor.rs) 가 참조하는 필드만 강제로 읽는다.
                #[cfg(not(feature = "phase-3_5"))]
                {
                    let _ = snap.uptime_secs;
                    let _ = snap.pid;
                    let _ = snap.ipc_request_count;
                    assert!(snap.rb_capacity > 0);
                    assert!(snap.rb_used > 0);
                }
                let _ = snap.last_command_secs_ago;
                // 새 필드는 구 consumer 가 무시해도 panic 없이 접근 가능해야 한다.
                assert_eq!(snap.dropped_bytes, 1234);
                assert_eq!(snap.attach_reconnect_total, 1);
            }
            other => panic!("Metrics 기대 — {other:?}"),
        }
    }
}
