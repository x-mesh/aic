//! `AttachServer` — aicd 측 Attach_UDS 엔드포인트.
//!
//! `aic-session` 의 PTY reader → aicd `SessionProcessorPool` → `CommandRecordStore`
//! 로 이어지는 데이터 스트림을 수용한다. Control_UDS 와 분리된 소켓을 쓰는 이유는
//! stream backpressure 가 control request/response latency 를 오염시키지 않도록
//! 하기 위함이다 (design.md §3).
//!
//! 연결 한 개 = session_id 한 개 = `SessionProcessor` 한 개. 멀티플렉싱은 지원하지
//! 않으며, 같은 session_id 에 대한 두 번째 `AttachOpen` 은 `AttachError` 로 거부된다.
//!
//! Requirements: R5.1, R5.2, R5.7, R5.9, R5.10, R11.4, R13.5, R14.2, R14.3,
//! R15.1, R15.2, R15.3, R15.4.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aic_common::attach::{
    read_attach_frame, write_attach_server_frame, AttachClientFrame, AttachDecodeError,
    AttachFrameKind, AttachServerFrame, ATTACH_PROTOCOL_VERSION,
};
use anyhow::Context;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

use crate::command_record_store::CommandRecordStore;
use crate::metrics::AicdMetrics;
use crate::session_processor_pool::{AttachOpenError, SessionProcessorPool};

/// aicd 의 Attach_UDS 엔드포인트.
///
/// `bind` 로 생성한 뒤 `serve(shutdown)` 을 호출하면 accept 루프가 돌아간다. 연결 하나당
/// [`handle_attach_client`] 가 독립 task 로 spawn 된다.
pub struct AttachServer {
    listener: UnixListener,
    socket_path: PathBuf,
    metrics: Arc<AicdMetrics>,
    pool: Arc<SessionProcessorPool>,
    store: CommandRecordStore,
}

impl AttachServer {
    /// Attach_UDS 소켓을 바인드한다.
    ///
    /// - 부모 디렉토리가 없으면 `0700` 으로 새로 만든다. 이미 있으면 mode 를 확인만 하고
    ///   0700 이 아니면 warn-only 로그 (R15.1). 강제 chmod 는 하지 않는다 — 운영자의
    ///   기존 policy 를 덮어쓰지 않기 위함이다.
    /// - 기존 소켓 파일은 언바인드 후 재생성.
    /// - 소켓 파일 자체 권한은 `0600` (R15.3).
    pub async fn bind(
        socket_path: &Path,
        metrics: Arc<AicdMetrics>,
        pool: Arc<SessionProcessorPool>,
        store: CommandRecordStore,
    ) -> anyhow::Result<Self> {
        if let Some(parent) = socket_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Attach_UDS 부모 디렉토리 생성 실패: {}", parent.display())
                })?;
                // 새로 만들 때에만 0700 으로 설정 — 기존 디렉토리는 건드리지 않는다.
                let perms = std::fs::Permissions::from_mode(0o700);
                let _ = std::fs::set_permissions(parent, perms);
            } else {
                match std::fs::metadata(parent) {
                    Ok(md) => {
                        let mode = md.permissions().mode() & 0o777;
                        if mode != 0o700 {
                            tracing::warn!(
                                path = %parent.display(),
                                actual_mode = format!("{:o}", mode),
                                "Attach_UDS 부모 디렉토리 권한이 0700 이 아닙니다 (R15.1)"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %parent.display(),
                            error = %e,
                            "Attach_UDS 부모 디렉토리 stat 실패"
                        );
                    }
                }
            }
        }

        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("Attach_UDS bind 실패: {}", socket_path.display()))?;

        // R15.3: 소켓 파일 권한 0600.
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(socket_path, perms).with_context(|| {
            format!(
                "Attach_UDS 소켓 권한 0600 설정 실패: {}",
                socket_path.display()
            )
        })?;

        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
            metrics,
            pool,
            store,
        })
    }

    /// `shutdown` 이 notify 될 때까지 accept 루프를 돈다. 각 연결은 별도 task 로 분리되어
    /// 처리되므로 shutdown 이 떨어져도 in-flight 연결은 detach 된 상태로 각자 종료된다.
    pub async fn serve(&self, shutdown: Arc<Notify>) {
        loop {
            tokio::select! {
                accept = self.listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            let metrics = Arc::clone(&self.metrics);
                            let pool = Arc::clone(&self.pool);
                            let store = self.store.clone();
                            tokio::spawn(async move {
                                handle_attach_client(stream, metrics, pool, store).await;
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Attach_UDS accept 실패");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    tracing::info!("AttachServer shutdown 신호 수신");
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

impl Drop for AttachServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// 한 개의 Attach_UDS 연결을 처리한다.
///
/// 1. peer uid 확인 — aicd euid 와 다르면 즉시 close (R15.2).
/// 2. 첫 프레임은 `AttachOpen` 이어야 한다. 아니면 `AttachError` 후 close.
/// 3. `protocol_version != ATTACH_PROTOCOL_VERSION` → `AttachError` 후 close (R13.5).
/// 4. `pool.open(session_id)` 호출. `AlreadyOpen` → `AttachError` 후 close.
/// 5. 성공 시 `AttachAck` 송신 + `metrics.inc_attach_open()` + `inc_attach_connection()`.
/// 6. 루프:
///    - `PtyBytes`: `pool.feed` 결과를 각각 `store.push_pty` +
///      `metrics.inc_central_store_push()`.
///    - `AttachClose` → break.
///    - 두 번째 `AttachOpen` → `AttachError` 후 break (멀티플렉싱 금지).
///    - `PtyBytesTooLarge` / 기타 decode 에러 → `AttachError` 후 break (R15.4).
///    - EOF / read error → break.
/// 7. `pool.close(session_id)` + `metrics.dec_attach_connection()` (R11.4).
async fn handle_attach_client(
    stream: UnixStream,
    metrics: Arc<AicdMetrics>,
    pool: Arc<SessionProcessorPool>,
    store: CommandRecordStore,
) {
    // ── (1) peer uid 검사 (R15.2) ─────────────────────────
    //
    // tokio `UnixStream::peer_cred()` 는 플랫폼별로 Linux=SO_PEERCRED, macOS/BSD=
    // `getpeereid` 를 사용한다. 즉 spec 에서 요구한 `libc::getpeereid` 의 의미를
    // cross-platform 으로 그대로 대리한다. 다른 uid 프로세스가 dial 해 오는
    // mismatch 케이스는 테스트에서 재현이 어려워 코드 경로만 남겨 둔다.
    let my_uid = unsafe { libc::geteuid() };
    match stream.peer_cred() {
        Ok(cred) => {
            if cred.uid() != my_uid {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    my_uid,
                    "Attach_UDS peer uid 불일치 — 연결을 거부 (R15.2)"
                );
                return;
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Attach_UDS peer credential 조회 실패 — 연결을 거부"
            );
            return;
        }
    }

    // read/write half 를 분리해 루프 안에서 각각 독립적으로 소유한다.
    let (mut reader, mut writer) = stream.into_split();

    // ── (2) 첫 프레임: AttachOpen ─────────────────────────
    let (session_id, proto_version) = match read_attach_frame(&mut reader).await {
        Ok(AttachFrameKind::Client(AttachClientFrame::AttachOpen {
            session_id,
            protocol_version,
        })) => (session_id, protocol_version),
        Ok(AttachFrameKind::Client(AttachClientFrame::AttachClose { reason })) => {
            tracing::debug!(
                %reason,
                "Attach_UDS: client 가 AttachOpen 없이 AttachClose"
            );
            return;
        }
        Ok(other) => {
            let msg = "첫 프레임은 AttachOpen 이어야 합니다".to_string();
            let _ = write_attach_server_frame(
                &mut writer,
                &AttachServerFrame::AttachError {
                    message: msg.clone(),
                },
            )
            .await;
            tracing::warn!(?other, "Attach_UDS: 첫 프레임이 AttachOpen 이 아님");
            return;
        }
        Err(e) => {
            tracing::debug!(error = %e, "Attach_UDS: 첫 프레임 읽기 실패");
            return;
        }
    };

    // ── (3) 프로토콜 버전 체크 (R13.5) ─────────────────────
    if proto_version != ATTACH_PROTOCOL_VERSION {
        let msg = format!(
            "지원하지 않는 attach protocol_version={proto_version} \
             (서버 지원={ATTACH_PROTOCOL_VERSION})"
        );
        let _ = write_attach_server_frame(
            &mut writer,
            &AttachServerFrame::AttachError {
                message: msg.clone(),
            },
        )
        .await;
        tracing::warn!(
            proto_version,
            session_id = %session_id,
            "Attach_UDS: 지원하지 않는 protocol_version"
        );
        return;
    }

    // ── (4) pool.open ─────────────────────────────────────
    if let Err(AttachOpenError::AlreadyOpen(id)) = pool.open(&session_id).await {
        let msg = format!("세션 {id} 에 대한 attach 연결이 이미 열려 있습니다");
        let _ = write_attach_server_frame(
            &mut writer,
            &AttachServerFrame::AttachError { message: msg },
        )
        .await;
        tracing::warn!(session_id = %id, "Attach_UDS: 중복 AttachOpen 거부");
        return;
    }

    // ── (5) Ack + metric ─────────────────────────────────
    if let Err(e) = write_attach_server_frame(
        &mut writer,
        &AttachServerFrame::AttachAck {
            protocol_version: ATTACH_PROTOCOL_VERSION,
        },
    )
    .await
    {
        tracing::warn!(error = %e, "Attach_UDS: AttachAck 송신 실패 — cleanup 후 종료");
        pool.close(&session_id).await;
        return;
    }
    metrics.inc_attach_open();
    metrics.inc_attach_connection();

    // ── (6) Stream loop ──────────────────────────────────
    loop {
        match read_attach_frame(&mut reader).await {
            Ok(AttachFrameKind::Client(AttachClientFrame::PtyBytes { bytes })) => {
                let records = pool.feed(&session_id, &bytes).await;
                for record in records {
                    store.push_pty(&session_id, record).await;
                    metrics.inc_central_store_push();
                }
            }
            Ok(AttachFrameKind::Client(AttachClientFrame::AttachClose { reason })) => {
                tracing::debug!(session_id = %session_id, %reason, "Attach_UDS: AttachClose 수신");
                break;
            }
            Ok(AttachFrameKind::Client(AttachClientFrame::AttachOpen { .. })) => {
                let _ = write_attach_server_frame(
                    &mut writer,
                    &AttachServerFrame::AttachError {
                        message: "한 연결에서 추가 AttachOpen 은 허용되지 않습니다 \
                                  (멀티플렉싱 금지)"
                            .to_string(),
                    },
                )
                .await;
                tracing::warn!(session_id = %session_id, "Attach_UDS: 두 번째 AttachOpen 거부");
                break;
            }
            Ok(AttachFrameKind::Server(_)) => {
                // client 경로에 server frame 이 들어오면 protocol violation.
                tracing::warn!(
                    session_id = %session_id,
                    "Attach_UDS: client 경로에 server frame 수신 — 연결 종료"
                );
                break;
            }
            Err(e) => {
                // R15.4: PtyBytesTooLarge 등 디코드 실패는 client 에게 한 번 알린 뒤 종료.
                // EOF/ConnectionReset 은 AttachError 를 돌려줄 필요가 없다.
                let is_eof = matches!(
                    &e,
                    AttachDecodeError::Io(io_err)
                        if io_err.kind() == std::io::ErrorKind::UnexpectedEof
                            || io_err.kind() == std::io::ErrorKind::ConnectionReset
                            || io_err.kind() == std::io::ErrorKind::BrokenPipe
                );
                if !is_eof {
                    let _ = write_attach_server_frame(
                        &mut writer,
                        &AttachServerFrame::AttachError {
                            message: format!("attach frame 디코드 실패: {e}"),
                        },
                    )
                    .await;
                }
                tracing::debug!(
                    session_id = %session_id,
                    error = %e,
                    "Attach_UDS: frame 디코드/읽기 에러 — 연결 종료"
                );
                break;
            }
        }
    }

    // ── (7) cleanup (R11.4) ───────────────────────────────
    pool.close(&session_id).await;
    metrics.dec_attach_connection();
}

// ── Unit tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use aic_common::attach::{
        write_attach_frame, AttachClientFrame, AttachServerFrame, ATTACH_PROTOCOL_VERSION,
        MAX_PTY_BYTES_FRAME, PTY_BYTES_DISCRIMINANT,
    };
    use bytes::Bytes;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 테스트용 bootstrap: tempdir 에 attach 소켓을 바인드하고 serve 태스크를 띄운다.
    struct Harness {
        _tempdir: TempDir,
        socket_path: PathBuf,
        metrics: Arc<AicdMetrics>,
        pool: Arc<SessionProcessorPool>,
        store: CommandRecordStore,
        shutdown: Arc<Notify>,
        serve_handle: tokio::task::JoinHandle<()>,
    }

    impl Harness {
        async fn start() -> Self {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("aicd-attach.sock");
            let metrics = Arc::new(AicdMetrics::new());
            let pool = Arc::new(SessionProcessorPool::new());
            let store = CommandRecordStore::new();
            let server = AttachServer::bind(
                &socket_path,
                Arc::clone(&metrics),
                Arc::clone(&pool),
                store.clone(),
            )
            .await
            .expect("bind");
            let shutdown = Arc::new(Notify::new());
            let shutdown_clone = Arc::clone(&shutdown);
            let serve_handle = tokio::spawn(async move {
                server.serve(shutdown_clone).await;
            });
            Self {
                _tempdir: tempdir,
                socket_path,
                metrics,
                pool,
                store,
                shutdown,
                serve_handle,
            }
        }

        async fn connect(&self) -> UnixStream {
            // tokio 가 bind 에서 반환한 후라도 accept task 가 등록되기 전이면
            // connect 가 ECONNREFUSED 로 튈 수 있어 소량 재시도한다.
            for _ in 0..50 {
                if let Ok(s) = UnixStream::connect(&self.socket_path).await {
                    return s;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("attach 소켓 connect 실패: {}", self.socket_path.display());
        }

        async fn shutdown(self) {
            self.shutdown.notify_one();
            let _ = tokio::time::timeout(Duration::from_millis(500), self.serve_handle).await;
        }
    }

    /// client 가 read half 로 EOF 를 관측할 때까지 기다린다. 관측된 EOF 는 서버 측 cleanup
    /// (pool.close + metrics.dec_attach_connection) 이 완료됐음을 의미한다 — handle_attach_client
    /// 가 return 하면서 `OwnedWriteHalf` 가 drop 되고, 그 시점에 clean-up 은 이미 끝나 있다.
    async fn wait_until_eof<R>(reader: &mut R)
    where
        R: AsyncReadExt + Unpin,
    {
        let mut buf = [0u8; 1024];
        for _ in 0..200 {
            match tokio::time::timeout(Duration::from_millis(50), reader.read(&mut buf)).await {
                Ok(Ok(0)) => return,
                Ok(Ok(_)) => continue, // 남은 bytes 를 버린다
                Ok(Err(_)) => return,  // 연결 오류도 종료로 간주
                Err(_) => continue,    // timeout — 재시도
            }
        }
        panic!("EOF 관측 실패 (서버 cleanup 타임아웃)");
    }

    /// metrics counter 가 `target` 값이 될 때까지 폴링. 테스트 안정성을 위한 busy-wait.
    async fn wait_for_attach_connections(metrics: &AicdMetrics, target: u64) {
        for _ in 0..200 {
            if metrics.attach_connections() == target {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "attach_connections 가 {target} 이 되지 않음 (현재 {})",
            metrics.attach_connections()
        );
    }

    // ── 1. bind_creates_socket_with_0600_mode ──────────────────

    /// R15.3: 소켓 파일 권한은 0600 이어야 한다. 부모 디렉토리 perm 체크는 warn-only 이므로
    /// 여기선 소켓 파일 mode 만 검증한다.
    #[tokio::test]
    async fn bind_creates_socket_with_0600_mode() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("attach.sock");
        let metrics = Arc::new(AicdMetrics::new());
        let pool = Arc::new(SessionProcessorPool::new());
        let store = CommandRecordStore::new();
        let _server = AttachServer::bind(&socket_path, metrics, pool, store)
            .await
            .expect("bind");
        let md = std::fs::metadata(&socket_path).expect("metadata");
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "actual mode = {mode:o}");
    }

    // ── 2. wrong_protocol_version_returns_error ────────────────

    /// R13.5: 지원하지 않는 protocol_version 은 AttachError 후 연결 종료.
    #[tokio::test]
    async fn wrong_protocol_version_returns_error() {
        let h = Harness::start().await;
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        // v999 — 서버가 지원하지 않는 버전.
        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "s-bad-version".to_string(),
                protocol_version: 999,
            },
        )
        .await
        .unwrap();

        let frame = read_attach_frame(&mut reader).await.expect("read error");
        match frame {
            AttachFrameKind::Server(AttachServerFrame::AttachError { message }) => {
                assert!(
                    message.contains("protocol_version"),
                    "message = {message}"
                );
            }
            other => panic!("AttachError 를 기대 — actual: {other:?}"),
        }

        // 서버는 이후 연결을 close — EOF 가 관측되어야 한다.
        wait_until_eof(&mut reader).await;

        // pool 에 세션이 등록되지 않아야 한다 (open 전에 거절되었으므로).
        assert_eq!(h.pool.active_len().await, 0);
        // attach_open_total / attach_connections 는 증가하지 않는다.
        assert_eq!(h.metrics.attach_open_total(), 0);
        assert_eq!(h.metrics.attach_connections(), 0);

        h.shutdown().await;
    }

    // ── 3. successful_open_returns_ack_and_increments_metrics ──

    /// R5.7 + R14.2 + R14.3: 정상 AttachOpen 은 AttachAck 를 돌려주고 metric 을 올린다.
    #[tokio::test]
    async fn successful_open_returns_ack_and_increments_metrics() {
        let h = Harness::start().await;
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "s-ok".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();

        let frame = read_attach_frame(&mut reader).await.unwrap();
        match frame {
            AttachFrameKind::Server(AttachServerFrame::AttachAck { protocol_version }) => {
                assert_eq!(protocol_version, ATTACH_PROTOCOL_VERSION);
            }
            other => panic!("AttachAck 를 기대 — actual: {other:?}"),
        }

        // Ack 이 온 시점이면 inc_attach_open / inc_attach_connection 이 이미 호출된 상태.
        assert_eq!(h.metrics.attach_open_total(), 1);
        wait_for_attach_connections(&h.metrics, 1).await;

        // pool 에 세션이 등록되었다.
        assert_eq!(h.pool.active_len().await, 1);

        // 깨끗한 종료 (다음 테스트가 의존하지 않는 독립 상태 유지).
        drop(writer);
        wait_until_eof(&mut reader).await;
        wait_for_attach_connections(&h.metrics, 0).await;
        h.shutdown().await;
    }

    // ── 4. attach_close_exits_gracefully_and_decrements_metrics ─

    /// R11.4 + R14.2: AttachClose 후 서버는 pool.close + metric 감소.
    #[tokio::test]
    async fn attach_close_exits_gracefully_and_decrements_metrics() {
        let h = Harness::start().await;
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "s-close".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let _ack = read_attach_frame(&mut reader).await.unwrap();
        wait_for_attach_connections(&h.metrics, 1).await;
        assert_eq!(h.pool.active_len().await, 1);

        // graceful close
        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachClose {
                reason: "bye".to_string(),
            },
        )
        .await
        .unwrap();

        wait_until_eof(&mut reader).await;

        // attach_connections 는 0, attach_open_total 은 그대로 1.
        assert_eq!(h.metrics.attach_connections(), 0);
        assert_eq!(h.metrics.attach_open_total(), 1);
        // pool 에서도 제거됨 (R11.4 — ring 은 유지되지만 processor 는 해제).
        assert_eq!(h.pool.active_len().await, 0);

        h.shutdown().await;
    }

    // ── 5. second_attach_open_rejected ─────────────────────────

    /// 한 연결에서 두 번째 AttachOpen 은 거부 (멀티플렉싱 금지).
    #[tokio::test]
    async fn second_attach_open_rejected() {
        let h = Harness::start().await;
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "s-mux".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        // ack 소비.
        match read_attach_frame(&mut reader).await.unwrap() {
            AttachFrameKind::Server(AttachServerFrame::AttachAck { .. }) => {}
            other => panic!("expected Ack, got {other:?}"),
        }
        wait_for_attach_connections(&h.metrics, 1).await;

        // 두 번째 AttachOpen → 서버가 AttachError + close.
        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "s-mux-2".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();

        let frame = read_attach_frame(&mut reader).await.unwrap();
        match frame {
            AttachFrameKind::Server(AttachServerFrame::AttachError { message }) => {
                assert!(
                    message.contains("AttachOpen") || message.contains("멀티플렉싱"),
                    "message = {message}"
                );
            }
            other => panic!("AttachError 를 기대 — actual: {other:?}"),
        }

        wait_until_eof(&mut reader).await;
        // 연결이 닫히며 cleanup 되었으므로 attach_connections = 0.
        assert_eq!(h.metrics.attach_connections(), 0);
        assert_eq!(h.pool.active_len().await, 0);
        h.shutdown().await;
    }

    // ── 6. pty_bytes_feed_produces_records_in_store ────────────

    /// R5.10 + R14.1: PtyBytes frame → pool.feed → store.push_pty.
    /// 테스트 payload 는 OSC 133 한 쌍 (C;cmd=6c73 / D;0) 을 담아 record 1 개를 만들어낸다.
    #[tokio::test]
    async fn pty_bytes_feed_produces_records_in_store() {
        let h = Harness::start().await;
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "s-feed".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        match read_attach_frame(&mut reader).await.unwrap() {
            AttachFrameKind::Server(AttachServerFrame::AttachAck { .. }) => {}
            other => panic!("expected Ack, got {other:?}"),
        }

        // cmd="ls" 의 hex 는 "6c73". 실제 PTY 흐름은 preexec → body → precmd 가
        // 서로 다른 read() 로 분리되어 오므로, 여기서도 3 개의 PtyBytes frame 으로
        // 나눠 보낸다 (`SessionProcessorPool::feed` 가 markers 먼저 → 라인 나중 순
        // 으로 처리하기 때문에 한 청크에 D 마커와 출력이 섞여 있으면 출력이 다음
        // 명령으로 밀려 record 가 나오지 않는다 — 이 순서 가정은 session_runtime 의
        // PTY read 루프와 일치한다).
        for chunk in [
            &b"\x1b]133;C;cmd=6c73\x07"[..],
            &b"output\n"[..],
            &b"\x1b]133;D;0\x07"[..],
        ] {
            write_attach_frame(
                &mut writer,
                &AttachClientFrame::PtyBytes {
                    bytes: Bytes::copy_from_slice(chunk),
                },
            )
            .await
            .unwrap();
        }

        // 서버가 frame 을 처리하고 store 에 push 할 시간을 확보하기 위해 AttachClose
        // 를 보낸 뒤 EOF 로 동기화한다. AttachClose 까지 처리된 시점이면 PtyBytes 결과
        // 도 모두 반영되어 있다 (단일 task 내 순차 처리).
        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachClose {
                reason: "done".to_string(),
            },
        )
        .await
        .unwrap();
        wait_until_eof(&mut reader).await;

        let recs = h.store.recent("s-feed", 10).await;
        assert_eq!(recs.len(), 1, "record 1 개 기대 — got {recs:?}");
        let r = &recs[0];
        assert_eq!(r.command.as_deref(), Some("ls"));
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.output_lines, vec!["output".to_string()]);
        // push_pty 카운터가 정확히 1 증가했다.
        assert_eq!(h.metrics.central_store_push_total(), 1);
        assert_eq!(h.metrics.attach_connections(), 0);

        h.shutdown().await;
    }

    // ── 7. oversize_pty_bytes_closes_connection ────────────────

    /// R15.4: `PtyBytes` length > MAX → 디코더가 에러를 내고 서버는 AttachError + close.
    /// 실제 16 MiB payload 를 보내지 않고 length prefix 만 조작해 안전하게 검증한다.
    #[tokio::test]
    async fn oversize_pty_bytes_closes_connection() {
        let h = Harness::start().await;
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "s-oversize".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        match read_attach_frame(&mut reader).await.unwrap() {
            AttachFrameKind::Server(AttachServerFrame::AttachAck { .. }) => {}
            other => panic!("expected Ack, got {other:?}"),
        }

        // 직접 wire format 을 위조: [0x01][MAX+1 BE][payload 없음].
        // 서버 decoder 는 length 검사 단계에서 PtyBytesTooLarge 를 내므로 payload 는 필요 없다.
        let mut framed: Vec<u8> = Vec::with_capacity(1 + 4);
        framed.push(PTY_BYTES_DISCRIMINANT);
        let bogus_len: u32 = (MAX_PTY_BYTES_FRAME + 1) as u32;
        framed.extend_from_slice(&bogus_len.to_be_bytes());
        writer.write_all(&framed).await.unwrap();
        writer.flush().await.unwrap();

        // 서버는 AttachError 후 연결을 닫는다.
        let frame = read_attach_frame(&mut reader).await.unwrap();
        match frame {
            AttachFrameKind::Server(AttachServerFrame::AttachError { message }) => {
                assert!(
                    message.contains("디코드") || message.contains("PtyBytes"),
                    "message = {message}"
                );
            }
            other => panic!("AttachError 를 기대 — actual: {other:?}"),
        }

        wait_until_eof(&mut reader).await;
        assert_eq!(h.metrics.attach_connections(), 0);
        assert_eq!(h.pool.active_len().await, 0);
        // push 는 없었어야 한다.
        assert_eq!(h.metrics.central_store_push_total(), 0);

        h.shutdown().await;
    }
}
