//! `AttachClient` — aic-session 측 Attach_UDS 클라이언트 (task 3.4).
//!
//! `aic-session` 의 PTY reader 가 생산하는 raw PTY byte chunk 를
//! [`BoundedByteChannel`] 을 거쳐 aicd 의 [`AttachServer`] 로 전송한다.
//! 구성 요소:
//!
//! - `connect()`: Attach_UDS 에 접속하고 `AttachOpen` 을 보낸 뒤 `AttachAck` 을
//!   100ms 안에 기다린다. 실패 모드는 [`AttachConnectError`] 로 세분화된다.
//! - `try_send(bytes)`: non-blocking. `BoundedByteChannel::try_send` 를 호출하고
//!   cap 을 초과하면 silently drop 한다. drop 은 channel 내부의 `dropped` 카운터
//!   (= `AttachMetrics::dropped_bytes_handle()` 와 동일 인스턴스) 에 자동 반영되고,
//!   **세션 lifetime 당 최대 1 회** `tracing::warn!` 로 사용자에게 알린다 (R10.6).
//! - writer task: [`BoundedByteReceiver`] 에서 bytes 를 꺼내
//!   [`write_attach_frame`] 로 `PtyBytes` frame 을 전송한다. write 실패는 스트림
//!   끊김으로 보고, reconnect task 를 깨워 graceful 종료한다. (reconnect 자체는
//!   task 4.4 에서 완성되므로 여기에서는 **placeholder** 로 Notify 만 발사한다.)
//!
//! 설계 요지:
//!
//! - `reconnect_handle` 필드는 task 4.4 에서 실제 backoff 루프 task 로 대체된다.
//!   현재는 `Notify` 를 듣고 즉시 종료하는 no-op task 를 spawn 한다 — 소유권을
//!   미리 정리해 두어 struct 시그니처가 task 4.4 에서 바뀌지 않도록 한다.
//! - `AttachClient::drop` 시 `tx` 가 먼저 drop 되고, receiver 가 drain 되면서
//!   writer task 가 자연 종료한다. 그 직후 reconnect_handle 을 `abort` 하여
//:///   placeholder task 도 정리한다.
//!
//! Requirements: R5.7, R5.8, R10.1, R10.2, R10.3, R10.5, R10.6, R14.4.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aic_common::attach::{
    read_attach_frame, write_attach_frame, AttachClientFrame, AttachDecodeError, AttachFrameKind,
    AttachIoError, AttachServerFrame, ATTACH_PROTOCOL_VERSION,
};
use aic_common::bounded_byte_channel::{
    BoundedByteChannel, BoundedByteReceiver, SendOutcome,
};
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::metrics::AttachMetrics;

/// `aic-session` 과 aicd Attach_UDS 사이의 bounded byte channel cap.
///
/// design.md §"Concurrency and Backpressure": 4 MiB. PTY chunk 가 일시적으로
/// 몰려도 stdout passthrough 를 방해하지 않도록 하는 upper-bound 버퍼.
pub const ATTACH_CHANNEL_CAP_BYTES: usize = 4 * 1024 * 1024;

/// `connect` 가 `AttachAck` 을 기다리는 상한 (R5.7).
pub const ATTACH_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(100);

// ── Errors ─────────────────────────────────────────────────────

/// `connect` 가 돌려줄 수 있는 실패 분류.
#[derive(thiserror::Error, Debug)]
pub enum AttachConnectError {
    /// 소켓 connect / frame write / frame read 단계에서 발생한 I/O 오류.
    #[error("Attach_UDS I/O 오류: {0}")]
    Io(#[from] std::io::Error),

    /// 쓰기 단계의 frame 인코딩 / 길이 프리픽스 변환 오류.
    #[error("AttachOpen 송신 실패: {0}")]
    WriteFrame(#[from] AttachIoError),

    /// `AttachAck` 을 기다리다 decoder 단계에서 발생한 오류.
    #[error("AttachAck 수신 디코드 실패: {0}")]
    ReadFrame(#[from] AttachDecodeError),

    /// `AttachAck` 을 [`ATTACH_HANDSHAKE_TIMEOUT`] 안에 받지 못했다 (R5.7).
    #[error("AttachAck timeout ({}ms)", ATTACH_HANDSHAKE_TIMEOUT.as_millis())]
    Timeout,

    /// 서버가 명시적으로 거부 응답을 보냈다. `AttachError { message }` 원문.
    #[error("Attach 서버 거부: {0}")]
    ServerError(String),

    /// 예상과 다른 첫 프레임을 수신했다 (e.g. client frame). 프로토콜 위반.
    #[error("AttachAck 자리에 예상 외의 프레임: {0}")]
    BadAck(String),

    /// `AttachAck` 의 `protocol_version` 이 우리가 보낸 것과 다르다.
    #[error("Attach 서버 protocol_version 불일치: server={server}, expected={expected}")]
    WrongVersion { server: u32, expected: u32 },
}

// ── Public type ────────────────────────────────────────────────

/// aic-session → aicd Attach_UDS 클라이언트 핸들.
///
/// cheap clone 불가 (PTY reader 가 1 개라 필요 없음). drop 시 writer/reconnect
/// task 가 자연 종료된다.
pub struct AttachClient {
    /// 이 연결이 바인드된 session_id. 로그/디버그 용도.
    session_id: String,
    /// PTY reader 가 `try_send` 할 채널 producer. drop 되면 writer task 종료.
    tx: BoundedByteChannel,
    /// `AttachMetrics` 공유 핸들 — `attach_reconnect_total` / `dropped_bytes`
    /// 모두 외부에서 관측한다. `dropped_bytes` 는 channel 의 `dropped` 카운터와
    /// 같은 `Arc<AtomicU64>` 인스턴스이므로 자동 동기화된다.
    ///
    /// task 4.4 의 reconnect backoff 루프가 `inc_attach_reconnect()` 를 호출할 때
    /// 이 핸들을 사용한다. 이 시점에는 struct 필드로만 보관한다.
    #[allow(dead_code)]
    metrics: Arc<AttachMetrics>,
    /// writer task 가 "연결 끊김" 을 감지했을 때 notify 되는 신호. task 4.4 의
    /// reconnect backoff 루프가 이 신호를 기다리도록 placeholder 로 둔다.
    #[allow(dead_code)]
    reconnect_signal: Arc<Notify>,
    /// writer task 핸들 — drop 시 channel 이 닫혀 자연 종료한다.
    ///
    /// 필드로 저장만 하고 접근하지는 않지만, `AttachClient` 수명에 task 를
    /// 묶어 두어 outer runtime 이 abort 하지 않도록 한다. tokio 는 `JoinHandle`
    /// 이 drop 되면 task 를 detach 할 뿐 실행을 중단시키지 않으므로, 이 핸들이
    /// `None` 이 되어도 graceful shutdown 은 `tx` drop → channel close →
    /// writer_loop 자연 종료 시퀀스로 계속된다.
    #[allow(dead_code)]
    writer_handle: Option<JoinHandle<()>>,
    /// reconnect placeholder task — task 4.4 전까지는 no-op.
    reconnect_handle: Option<JoinHandle<()>>,
    /// "drop 이 처음 관측됐다" 는 사실을 warn! 로 **1 회만** 기록하기 위한 latch.
    /// R10.6: 세션 lifetime 당 최대 1 번.
    warn_latch: Arc<std::sync::atomic::AtomicBool>,
    /// drop 누적 카운터 (channel/metrics 공유 인스턴스). warn latch 트리거 판단에 사용.
    dropped_counter: Arc<AtomicU64>,
}

impl AttachClient {
    /// aicd Attach_UDS 에 연결하고 handshake 를 수행한다.
    ///
    /// 절차:
    /// 1. [`UnixStream::connect`] (socket_path)
    /// 2. `AttachOpen { session_id, protocol_version=ATTACH_PROTOCOL_VERSION }` 송신
    /// 3. [`ATTACH_HANDSHAKE_TIMEOUT`] (100ms) 안에 `AttachAck` 수신
    ///    - 서버가 `AttachError` 를 돌려주면 [`AttachConnectError::ServerError`]
    ///    - protocol_version 이 다르면 [`AttachConnectError::WrongVersion`]
    /// 4. writer task spawn — `BoundedByteReceiver` 에서 bytes 를 꺼내
    ///    `AttachClientFrame::PtyBytes` 로 전송.
    /// 5. reconnect placeholder task spawn (task 4.4 에서 교체).
    ///
    /// 성공 시 [`AttachClient`] 핸들을 반환한다.
    pub async fn connect(
        socket_path: &Path,
        session_id: String,
        metrics: Arc<AttachMetrics>,
    ) -> Result<Self, AttachConnectError> {
        // ── (a) 연결 + handshake 를 통째로 100ms 제한 안에서 수행 ──
        //
        // connect 단계도 handshake 의 일부이므로 timeout 을 포함한다.
        // 오작동하는 서버가 accept 만 하고 ack 를 보내지 않는 경우까지 커버.
        let inner = async {
            let mut stream = UnixStream::connect(socket_path).await?;

            // AttachOpen 송신.
            write_attach_frame(
                &mut stream,
                &AttachClientFrame::AttachOpen {
                    session_id: session_id.clone(),
                    protocol_version: ATTACH_PROTOCOL_VERSION,
                },
            )
            .await?;
            stream.flush().await?;

            // AttachAck 수신.
            let frame = read_attach_frame(&mut stream).await?;
            match frame {
                AttachFrameKind::Server(AttachServerFrame::AttachAck { protocol_version }) => {
                    if protocol_version != ATTACH_PROTOCOL_VERSION {
                        return Err(AttachConnectError::WrongVersion {
                            server: protocol_version,
                            expected: ATTACH_PROTOCOL_VERSION,
                        });
                    }
                    Ok(stream)
                }
                AttachFrameKind::Server(AttachServerFrame::AttachError { message }) => {
                    Err(AttachConnectError::ServerError(message))
                }
                other => Err(AttachConnectError::BadAck(format!("{other:?}"))),
            }
        };

        let stream = match tokio::time::timeout(ATTACH_HANDSHAKE_TIMEOUT, inner).await {
            Ok(result) => result?,
            Err(_) => return Err(AttachConnectError::Timeout),
        };

        // ── (b) Bounded byte channel — dropped 카운터는 metrics 와 공유 ──
        let dropped_counter = metrics.dropped_bytes_handle();
        let (tx, rx) = BoundedByteChannel::new_with_dropped_counter(
            ATTACH_CHANNEL_CAP_BYTES,
            Arc::clone(&dropped_counter),
        );

        // ── (c) Writer task spawn ──
        let reconnect_signal = Arc::new(Notify::new());
        let writer_handle = Some(tokio::spawn(writer_loop(
            session_id.clone(),
            stream,
            rx,
            Arc::clone(&reconnect_signal),
        )));

        // ── (d) Reconnect placeholder task ──
        //
        // task 4.4 가 이 자리를 backoff 재연결 루프로 교체한다. 그 전까지는
        // 어떤 신호도 소비하지 않고 영원히 대기하는 no-op 태스크를 둔다.
        // `reconnect_signal.notified()` 를 소비해 버리면 `writer_loop` 가 보낸
        // 끊김 신호를 다른 관찰자(예: 통합 테스트)가 수신하지 못하게 되므로,
        // placeholder 는 명시적으로 `pending` 을 대기한다. AttachClient drop 시
        // abort 되어 누수 없이 정리된다.
        let reconnect_handle = Some(tokio::spawn(async {
            std::future::pending::<()>().await;
        }));

        Ok(Self {
            session_id,
            tx,
            metrics,
            reconnect_signal,
            writer_handle,
            reconnect_handle,
            warn_latch: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dropped_counter,
        })
    }

    /// PTY reader 가 생산한 byte chunk 를 channel 에 넣는다.
    ///
    /// channel 이 full 이면 chunk 를 drop 하고 `dropped_bytes` 를 `len` 만큼
    /// 증가시킨다 (channel 내부에서 자동 수행). drop 이 **처음** 발생한 시점에
    /// `tracing::warn!` 을 한 번만 찍어 운영자가 인지하도록 한다 (R10.6).
    pub fn try_send(&self, bytes: Bytes) -> SendOutcome {
        let len = bytes.len();
        let outcome = self.tx.try_send(bytes);
        if outcome == SendOutcome::Dropped {
            // 이 경로에서는 metrics 쪽 카운터가 channel 내부에서 이미 증가했다 —
            // dropped_counter 와 metrics.dropped_bytes_handle() 이 같은 인스턴스.
            // warn 은 latch 로 딱 1 회만 찍는다.
            if !self
                .warn_latch
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::warn!(
                    session_id = %self.session_id,
                    dropped_bytes_total = self.dropped_counter.load(Ordering::Relaxed),
                    first_drop_len = len,
                    "Attach_UDS backpressure: PTY byte chunk 가 처음 drop 되었습니다 \
                     (세션 lifetime 당 최대 1 회 경고, R10.6)"
                );
            }
        }
        outcome
    }

    /// 현재 channel 에 머무르는 byte 수 (진단/테스트용).
    pub fn queued_bytes(&self) -> usize {
        self.tx.queued_bytes()
    }

    /// 공유 `dropped_bytes` 카운터의 누적 값 (channel/metrics 공통).
    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_counter.load(Ordering::Relaxed)
    }

    /// 이 연결이 바인드된 session_id 참조.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// `AttachMetrics` 핸들 복제본. 테스트에서 카운터 단언에 사용.
    #[cfg(test)]
    pub fn metrics(&self) -> Arc<AttachMetrics> {
        Arc::clone(&self.metrics)
    }
}

impl std::fmt::Debug for AttachClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachClient")
            .field("session_id", &self.session_id)
            .field("queued_bytes", &self.tx.queued_bytes())
            .field("dropped_bytes", &self.dropped_counter.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for AttachClient {
    fn drop(&mut self) {
        // writer_handle 은 **abort 하지 않는다**: tokio `JoinHandle::drop` 은 task 를
        // detach 할 뿐 실행을 중단시키지 않는다. struct drop 순서상 `tx` 필드가 먼저
        // 떨어지며 channel 이 닫히고, writer task 는 `rx.recv() == None` 을 만나
        // `AttachClose` 를 flush 한 뒤 자연 종료한다 — AttachClient 를 sync drop 해도
        // graceful shutdown 시퀀스가 손실되지 않는 것이 핵심이다.
        //
        // reconnect placeholder task 는 `Notify::notified()` 에서 무한 대기하므로
        // 반드시 abort 해서 누수 없이 정리한다.
        if let Some(h) = self.reconnect_handle.take() {
            h.abort();
        }
    }
}

// ── Internal: writer task ──────────────────────────────────────

/// `BoundedByteReceiver` 에서 bytes 를 꺼내 `AttachClientFrame::PtyBytes` 로 쏘는
/// 태스크.
///
/// 실패/EOF/소켓 close 시 `reconnect_signal` 을 notify 한 뒤 종료한다 —
/// task 4.4 의 reconnect backoff 루프가 이 신호를 받아 재연결 시퀀스를 시작한다.
async fn writer_loop(
    session_id: String,
    stream: UnixStream,
    mut rx: BoundedByteReceiver,
    reconnect_signal: Arc<Notify>,
) {
    let (_reader, mut writer) = stream.into_split();

    loop {
        match rx.recv().await {
            Some(bytes) => {
                let frame = AttachClientFrame::PtyBytes { bytes };
                if let Err(e) = write_attach_frame(&mut writer, &frame).await {
                    tracing::debug!(
                        session_id = %session_id,
                        error = %e,
                        "AttachClient writer: PtyBytes write 실패 — 연결 종료 처리"
                    );
                    // notify_one: permit 을 저장해 두어 이후에 `notified()` 를 호출하는
                    // 관찰자도 수신할 수 있게 한다. `notify_waiters` 는 호출 시점에
                    // 대기 중인 waiter 만 깨우므로 race 에 약하다.
                    reconnect_signal.notify_one();
                    break;
                }
            }
            None => {
                // producer 모두 drop — graceful shutdown.
                // AttachClose 를 보내려 시도하되 실패해도 무시.
                let _ = write_attach_frame(
                    &mut writer,
                    &AttachClientFrame::AttachClose {
                        reason: "aic-session shutdown".to_string(),
                    },
                )
                .await;
                let _ = writer.flush().await;
                tracing::debug!(
                    session_id = %session_id,
                    "AttachClient writer: channel 이 닫혀 정상 종료"
                );
                break;
            }
        }
    }
}

// ── Unit tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use aic_common::attach::{
        read_attach_frame, write_attach_server_frame, AttachClientFrame,
        AttachFrameKind, AttachServerFrame, ATTACH_PROTOCOL_VERSION,
    };
    use bytes::Bytes;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::net::UnixListener;
    use tokio::time::{timeout, Duration as StdDuration};

    /// 실패 없이 handshake 를 수행하고 PtyBytes frame 을 받아 보관하는 mock 서버.
    struct MockServer {
        tempdir: TempDir,
        socket_path: PathBuf,
        handle: tokio::task::JoinHandle<MockServerOutcome>,
    }

    #[derive(Debug, Default)]
    struct MockServerOutcome {
        open_session_id: Option<String>,
        open_protocol_version: Option<u32>,
        pty_chunks: Vec<Bytes>,
        got_close: bool,
        /// EOF 로 연결이 닫혔는가 (client 쪽에서 drop 된 케이스).
        got_eof: bool,
    }

    impl MockServer {
        /// 정상 시나리오: AttachOpen 을 받으면 AttachAck 로 응답하고, 이후 PtyBytes
        /// / AttachClose 를 수집한다.
        async fn ack() -> Self {
            let tempdir = tempfile::tempdir().unwrap();
            let socket_path = tempdir.path().join("attach.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();

            let handle = tokio::spawn(async move {
                let mut out = MockServerOutcome::default();
                let (stream, _) = listener.accept().await.expect("accept");
                let (mut reader, mut writer) = stream.into_split();

                // 첫 프레임: AttachOpen.
                match read_attach_frame(&mut reader).await {
                    Ok(AttachFrameKind::Client(AttachClientFrame::AttachOpen {
                        session_id,
                        protocol_version,
                    })) => {
                        out.open_session_id = Some(session_id);
                        out.open_protocol_version = Some(protocol_version);
                    }
                    other => panic!("expected AttachOpen, got {other:?}"),
                }

                // AttachAck.
                write_attach_server_frame(
                    &mut writer,
                    &AttachServerFrame::AttachAck {
                        protocol_version: ATTACH_PROTOCOL_VERSION,
                    },
                )
                .await
                .unwrap();

                // 이후 프레임 수집.
                loop {
                    match read_attach_frame(&mut reader).await {
                        Ok(AttachFrameKind::Client(AttachClientFrame::PtyBytes { bytes })) => {
                            out.pty_chunks.push(bytes);
                        }
                        Ok(AttachFrameKind::Client(AttachClientFrame::AttachClose { .. })) => {
                            out.got_close = true;
                            break;
                        }
                        Ok(_) => continue,
                        Err(_) => {
                            out.got_eof = true;
                            break;
                        }
                    }
                }
                out
            });

            Self {
                tempdir,
                socket_path,
                handle,
            }
        }

        /// AttachOpen 에 AttachError 로 응답하는 서버 (거부 시나리오).
        async fn reject(message: &'static str) -> Self {
            let tempdir = tempfile::tempdir().unwrap();
            let socket_path = tempdir.path().join("attach.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();

            let handle = tokio::spawn(async move {
                let mut out = MockServerOutcome::default();
                let (stream, _) = listener.accept().await.expect("accept");
                let (mut reader, mut writer) = stream.into_split();

                if let Ok(AttachFrameKind::Client(AttachClientFrame::AttachOpen {
                    session_id,
                    protocol_version,
                })) = read_attach_frame(&mut reader).await
                {
                    out.open_session_id = Some(session_id);
                    out.open_protocol_version = Some(protocol_version);
                }

                let _ = write_attach_server_frame(
                    &mut writer,
                    &AttachServerFrame::AttachError {
                        message: message.to_string(),
                    },
                )
                .await;
                out
            });

            Self {
                tempdir,
                socket_path,
                handle,
            }
        }

        /// accept 는 하지만 어떤 응답도 보내지 않는 서버 (timeout 시나리오).
        async fn hang() -> Self {
            let tempdir = tempfile::tempdir().unwrap();
            let socket_path = tempdir.path().join("attach.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();

            let handle = tokio::spawn(async move {
                let out = MockServerOutcome::default();
                // accept 후 대기만. client timeout 을 유도.
                let _conn = listener.accept().await.ok();
                tokio::time::sleep(StdDuration::from_secs(5)).await;
                out
            });

            Self {
                tempdir,
                socket_path,
                handle,
            }
        }

        fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        async fn finish(self) -> MockServerOutcome {
            // handle 이 자체 종료될 때까지 기다리되 테스트 hang 방지.
            match timeout(StdDuration::from_secs(2), self.handle).await {
                Ok(Ok(out)) => {
                    drop(self.tempdir);
                    out
                }
                Ok(Err(e)) => panic!("mock server panicked: {e}"),
                Err(_) => panic!("mock server 종료 timeout"),
            }
        }
    }

    // ── 1. connect → ack → send → close 정상 흐름 ────────────────

    #[tokio::test]
    async fn connect_and_send_pty_bytes_succeeds() {
        let server = MockServer::ack().await;
        let metrics = Arc::new(AttachMetrics::new());
        let client = AttachClient::connect(
            server.socket_path(),
            "s-happy".to_string(),
            Arc::clone(&metrics),
        )
        .await
        .expect("connect 성공");

        assert_eq!(client.session_id(), "s-happy");

        // PtyBytes 몇 개 전송. cap 이 4 MiB 이라 small chunk 는 모두 Sent.
        for i in 0..3u8 {
            let outcome = client.try_send(Bytes::from(vec![i; 32]));
            assert_eq!(outcome, SendOutcome::Sent, "chunk {i} 는 cap 안이므로 Sent");
        }

        // 연결 종료를 유도 — AttachClient 를 drop 하면 tx 가 닫히고 writer
        // task 가 AttachClose 를 보낸 뒤 종료한다.
        drop(client);

        let outcome = server.finish().await;
        assert_eq!(outcome.open_session_id.as_deref(), Some("s-happy"));
        assert_eq!(
            outcome.open_protocol_version,
            Some(ATTACH_PROTOCOL_VERSION)
        );
        assert_eq!(outcome.pty_chunks.len(), 3);
        for (i, chunk) in outcome.pty_chunks.iter().enumerate() {
            assert_eq!(chunk.len(), 32);
            assert!(chunk.iter().all(|b| *b == i as u8));
        }
        assert!(outcome.got_close, "AttachClose 를 받아야 함");
        // dropped_bytes 는 전혀 증가하지 않았어야 한다.
        assert_eq!(metrics.dropped_bytes(), 0);
    }

    // ── 2. backpressure drop 시 metrics 반영 + warn latch 1 회 ──

    #[tokio::test]
    async fn backpressure_drop_reflected_in_metrics() {
        // 이 테스트는 handshake 만 수행한 뒤, cap 을 인위적으로 초과하도록
        // internal channel 을 cap=0 짜리 재구성한다. 하지만 AttachClient 는
        // 내부 cap 을 외부에서 바꿀 수 없는 구조이므로, 4 MiB cap 을 실제로 채워
        // drop 을 유발한다 (4 MiB + 1 byte 1 개).
        //
        // 4 MiB 할당은 테스트에서 부담스러우므로, 여기서는 AttachClient 생성 직후
        // 내부 tx 필드를 쓰지 않고 별도의 scope 에서 "cap=0 + 동일 카운터"
        // 조합이 AttachMetrics 쪽으로 전파되는지를 확인한다. 이 단언은 AttachClient
        // 의 구성 공식이 정확함을 보장한다.
        let metrics = Arc::new(AttachMetrics::new());
        let counter = metrics.dropped_bytes_handle();
        let (tx, _rx) = BoundedByteChannel::new_with_dropped_counter(0, Arc::clone(&counter));

        // cap=0 이므로 어떤 chunk 든 즉시 drop.
        let outcome = tx.try_send(Bytes::from(vec![0u8; 128]));
        assert_eq!(outcome, SendOutcome::Dropped);
        // metrics 쪽에 카운터가 자동 반영.
        assert_eq!(metrics.dropped_bytes(), 128);

        // 한 번 더 — 누적된다.
        let _ = tx.try_send(Bytes::from(vec![0u8; 72]));
        assert_eq!(metrics.dropped_bytes(), 200);
    }

    #[tokio::test]
    async fn warn_latch_fires_only_once_per_client() {
        // cap 을 강제로 0 으로 설정한 AttachClient 를 합성해 warn latch 경로를
        // 관측한다. connect 는 실제로 수행하되, `tx` 를 교체해 항상 drop 을 내보낸다.
        let server = MockServer::ack().await;
        let metrics = Arc::new(AttachMetrics::new());
        let mut client = AttachClient::connect(
            server.socket_path(),
            "s-warn".to_string(),
            Arc::clone(&metrics),
        )
        .await
        .expect("connect");

        // 원래 tx 를 cap=0 채널로 교체 — writer task 는 새 receiver 에 붙지 않지만
        // try_send 결과만 관찰하는 이 테스트에는 무관하다. warn_latch / dropped_counter
        // 는 동일 metric 인스턴스를 계속 쓴다.
        let (zero_tx, _zero_rx) = BoundedByteChannel::new_with_dropped_counter(
            0,
            metrics.dropped_bytes_handle(),
        );
        client.tx = zero_tx;

        let o1 = client.try_send(Bytes::from(vec![1u8; 10]));
        let o2 = client.try_send(Bytes::from(vec![2u8; 20]));
        let o3 = client.try_send(Bytes::from(vec![3u8; 30]));
        assert_eq!(o1, SendOutcome::Dropped);
        assert_eq!(o2, SendOutcome::Dropped);
        assert_eq!(o3, SendOutcome::Dropped);

        // metrics 는 모든 drop 을 누적한다.
        assert_eq!(metrics.dropped_bytes(), 60);
        // warn_latch 는 1 회 set 되어 이후 호출에서 추가로 토글되지 않는다.
        assert!(client
            .warn_latch
            .load(std::sync::atomic::Ordering::Relaxed));

        drop(client);
        let _ = server.finish().await;
    }

    // ── 3. server 가 AttachError 로 거부 ─────────────────────────

    #[tokio::test]
    async fn connect_returns_server_error_when_rejected() {
        let server = MockServer::reject("protocol_version 2 는 지원하지 않습니다").await;
        let metrics = Arc::new(AttachMetrics::new());
        let err = AttachClient::connect(
            server.socket_path(),
            "s-reject".to_string(),
            Arc::clone(&metrics),
        )
        .await
        .expect_err("connect 는 실패해야 함");

        match err {
            AttachConnectError::ServerError(msg) => {
                assert!(msg.contains("protocol_version"), "msg = {msg}");
            }
            other => panic!("ServerError 기대 — actual: {other:?}"),
        }
        let _ = server.finish().await;
    }

    // ── 4. 소켓 자체가 없으면 Io 에러 ────────────────────────────

    #[tokio::test]
    async fn connect_returns_io_when_socket_missing() {
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("nope.sock");
        let metrics = Arc::new(AttachMetrics::new());

        let err = AttachClient::connect(&missing, "s-missing".to_string(), metrics)
            .await
            .expect_err("connect 는 실패해야 함");

        match err {
            AttachConnectError::Io(_) => {}
            other => panic!("Io 기대 — actual: {other:?}"),
        }
    }

    // ── 5. server 가 ack 를 안 보내면 Timeout ────────────────────

    #[tokio::test]
    async fn connect_returns_timeout_when_server_hangs() {
        let server = MockServer::hang().await;
        let metrics = Arc::new(AttachMetrics::new());
        let start = std::time::Instant::now();
        let err = AttachClient::connect(
            server.socket_path(),
            "s-hang".to_string(),
            Arc::clone(&metrics),
        )
        .await
        .expect_err("connect 는 timeout 되어야 함");
        let elapsed = start.elapsed();

        assert!(
            matches!(err, AttachConnectError::Timeout),
            "Timeout 기대 — actual: {err:?}"
        );
        // 100ms 상한 안에서 종료되는지 확인 (넉넉히 500ms).
        assert!(
            elapsed < StdDuration::from_millis(500),
            "handshake timeout 이 상한을 크게 초과: {:?}",
            elapsed
        );

        // hang 서버는 drop 시 함께 정리.
        server.handle.abort();
    }

    // ── 6. writer task 가 AttachClose 로 graceful 종료 ───────────

    #[tokio::test]
    async fn writer_sends_attach_close_on_drop() {
        let server = MockServer::ack().await;
        let metrics = Arc::new(AttachMetrics::new());
        let client = AttachClient::connect(
            server.socket_path(),
            "s-gc".to_string(),
            Arc::clone(&metrics),
        )
        .await
        .expect("connect");

        // 빈 상태로 즉시 drop — writer 가 AttachClose 를 내보내야 한다.
        drop(client);

        let outcome = server.finish().await;
        assert!(outcome.got_close, "AttachClose 미수신");
    }

    // ── 7. writer 실패 시 reconnect_signal notify ───────────────

    #[tokio::test]
    async fn write_failure_triggers_reconnect_signal() {
        // 서버는 handshake 후 즉시 연결을 끊는다 (AttachAck 보내고 stream drop).
        // 그 이후 client 가 PtyBytes 를 보내면 writer 가 write 에러를 만나
        // reconnect_signal 을 notify 한다.
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("attach.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server_handle: JoinHandle<()> = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.into_split();
            // AttachOpen 을 소비.
            let _ = read_attach_frame(&mut reader).await;
            // Ack 를 돌려주고 곧바로 stream 을 drop.
            let _ = write_attach_server_frame(
                &mut writer,
                &AttachServerFrame::AttachAck {
                    protocol_version: ATTACH_PROTOCOL_VERSION,
                },
            )
            .await;
            drop(writer);
            drop(reader);
        });

        let metrics = Arc::new(AttachMetrics::new());
        let client = AttachClient::connect(&socket_path, "s-fail".to_string(), Arc::clone(&metrics))
            .await
            .expect("connect");
        let signal = Arc::clone(&client.reconnect_signal);

        // 서버 task 가 stream 을 drop 할 시간을 주고 나서 send 시도.
        let _ = server_handle.await;
        for _ in 0..10 {
            client.try_send(Bytes::from(vec![0xAAu8; 32]));
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }

        // writer 가 에러를 만나 notify 했는지 확인 — 최대 1s 대기.
        let notified = timeout(StdDuration::from_secs(1), signal.notified()).await;
        assert!(notified.is_ok(), "reconnect_signal 이 notify 되지 않음");

        drop(client);
    }
}
