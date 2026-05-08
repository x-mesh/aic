//! Phase 3.3 attach stream 파이프라인 통합 테스트 — Task 3.8.
//!
//! Requirements: R5.1, R5.2, R5.7, R5.9, R5.10, R11.4, R13.5, R15.1, R15.2, R15.4.
//!
//! 본 테스트는 실제 [`AttachServer`] 를 tempdir 위의 UDS 에 바인드한 뒤, aic-session
//! 쪽을 raw wire protocol (`write_attach_frame` / `read_attach_frame`) 로 재현해
//! end-to-end 흐름을 검증한다. unit test 들과 달리 실제 서버 accept 루프, 실제
//! [`SessionProcessorPool`], 실제 [`CommandRecordStore`] 그리고 [`AicdMetrics`] 공유
//! 카운터를 통과시켜 Phase 3.3 파이프라인이 "한 덩어리" 로 움직이는지 확인한다.
//!
//! ## 시나리오
//!
//! - A: 정상 open → `PtyBytes` 3 chunk (preexec / body / precmd) → `AttachClose` →
//!   `CommandRecordStore::recent(session_id)` 가 기대 record 를 보유. metric 도 기대치.
//! - B: `protocol_version=999` → 서버가 `AttachError` 응답 후 연결 close. store / pool
//!   에 아무것도 남지 않는다 (R13.5).
//! - C: oversize `PtyBytes` (length prefix = MAX+1) → 서버가 `AttachError` 응답 후 close.
//!   open 까지는 성공했지만 store push 는 0, pool 은 cleanup (R15.4).
//! - D: peer uid mismatch 는 같은 프로세스 안에서 실제로 재현할 수 없으므로, 연결
//!   부트스트랩이 ["server 기동됨 → uid 일치 → graceful close → pool/metric 정리"] 경로
//!   를 통해 graceful 하게 동작한다는 **positive path** 를 관측한다. Task 3.1 의 unit
//!   test 가 peer uid 검사 자체의 logic 경로를 이미 커버하고 있어, 본 integration 은
//!   "uid 검사 path 를 통과하고 server 가 정상 재가동된다" 는 regression 만 지킨다.
//! - E: `AttachClose` 로 한 연결 정리 후, **같은 session_id** 로 두 번째 연결 수립이
//!   가능해야 한다. `pool.close` 가 state 를 drop 하므로 재사용이 성공해야 한다 (R11.4).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aic_common::attach::{
    read_attach_frame, write_attach_frame, AttachClientFrame, AttachFrameKind, AttachServerFrame,
    ATTACH_PROTOCOL_VERSION, MAX_PTY_BYTES_FRAME, PTY_BYTES_DISCRIMINANT,
};
use aic_server::attach_server::AttachServer;
use aic_server::command_record_store::CommandRecordStore;
use aic_server::metrics::AicdMetrics;
use aic_server::session_processor_pool::SessionProcessorPool;
use bytes::Bytes;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

// ─────────────────────────────────────────────────────────────────
// Harness — AttachServer 를 tempdir 위에 기동하고 공유 상태를 보관.
// ─────────────────────────────────────────────────────────────────

/// 공유되는 `CommandRecordStore`/`SessionProcessorPool`/`AicdMetrics` 를 한 묶음으로
/// 들고 있어, 테스트가 server 배후 상태를 직접 관측할 수 있게 한다.
struct Harness {
    _tempdir: TempDir,
    socket_path: PathBuf,
    metrics: Arc<AicdMetrics>,
    pool: Arc<SessionProcessorPool>,
    store: CommandRecordStore,
    shutdown: Arc<Notify>,
    serve_handle: JoinHandle<()>,
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
        .expect("AttachServer::bind");

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
        // bind 직후 listener accept 루프가 뜰 시간을 확보하기 위한 소량 재시도.
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

// ─────────────────────────────────────────────────────────────────
// 공용 utility
// ─────────────────────────────────────────────────────────────────

/// client 가 read half 로 EOF 를 관측할 때까지 기다린다. EOF 는 서버가 connection
/// cleanup (pool.close + metric dec) 을 끝냈음을 의미한다. 남아 있는 바이트는 그냥
/// 버린다.
async fn wait_until_eof<R>(reader: &mut R)
where
    R: AsyncReadExt + Unpin,
{
    let mut buf = [0u8; 1024];
    for _ in 0..200 {
        match tokio::time::timeout(Duration::from_millis(50), reader.read(&mut buf)).await {
            Ok(Ok(0)) => return,
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return,
            Err(_) => continue,
        }
    }
    panic!("EOF 관측 실패 (서버 cleanup 타임아웃)");
}

/// gauge metric 이 `target` 값이 될 때까지 폴링.
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

/// pool.active_len() 이 `target` 값이 될 때까지 폴링.
async fn wait_for_pool_len(pool: &SessionProcessorPool, target: usize) {
    for _ in 0..200 {
        if pool.active_len().await == target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "pool.active_len 이 {target} 이 되지 않음 (현재 {})",
        pool.active_len().await
    );
}

/// AttachAck 를 소비하고 protocol_version 을 검증한다.
async fn expect_ack<R>(reader: &mut R)
where
    R: AsyncReadExt + Unpin,
{
    match read_attach_frame(reader).await.expect("read ack") {
        AttachFrameKind::Server(AttachServerFrame::AttachAck { protocol_version }) => {
            assert_eq!(protocol_version, ATTACH_PROTOCOL_VERSION);
        }
        other => panic!("AttachAck 를 기대 — actual: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 A — full happy-path attach stream.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_a_open_ptybytes_close_produces_records_in_store() {
    let h = Harness::start().await;

    // aic-session 을 흉내: connect → AttachOpen → AttachAck 대기 → PtyBytes 3 frame →
    // AttachClose → EOF. OSC 133 마커는 "make" 명령 (6d 61 6b 65) 의 preexec/precmd.
    let stream = h.connect().await;
    let (mut reader, mut writer) = stream.into_split();

    write_attach_frame(
        &mut writer,
        &AttachClientFrame::AttachOpen {
            session_id: "sess-a".to_string(),
            protocol_version: ATTACH_PROTOCOL_VERSION,
        },
    )
    .await
    .expect("write open");
    expect_ack(&mut reader).await;

    // ack 까지 받은 시점 = server 가 inc_attach_open / inc_attach_connection 을 호출한 뒤.
    wait_for_attach_connections(&h.metrics, 1).await;
    assert_eq!(h.metrics.attach_open_total(), 1);
    assert_eq!(h.pool.active_len().await, 1);

    // (preexec, body, precmd) 를 separate frame 으로 — `SessionProcessorPool::feed`
    // 는 한 chunk 안에 D 마커와 출력이 섞여 있으면 출력이 다음 명령으로 밀리는 특성이
    // 있다 (OSC markers 를 먼저 feed 하므로). 실제 session_runtime 의 PTY 루프도
    // chunk 분리 순서가 preexec → body → precmd 라, 이 테스트가 동일 가정을 따른다.
    for chunk in [
        &b"\x1b]133;C;cmd=6d616b65\x07"[..],
        &b"building...\n"[..],
        &b"\x1b]133;D;0\x07"[..],
    ] {
        write_attach_frame(
            &mut writer,
            &AttachClientFrame::PtyBytes {
                bytes: Bytes::copy_from_slice(chunk),
            },
        )
        .await
        .expect("write PtyBytes");
    }

    // graceful close. AttachClose 처리가 끝나야 cleanup 이 동기적으로 완료된다.
    write_attach_frame(
        &mut writer,
        &AttachClientFrame::AttachClose {
            reason: "done".to_string(),
        },
    )
    .await
    .expect("write close");
    wait_until_eof(&mut reader).await;

    // store 에 1 개의 record 가 남아야 한다. 다른 세션에는 영향 없음.
    let recs = h.store.recent("sess-a", 10).await;
    assert_eq!(recs.len(), 1, "정확히 1 개의 record 를 기대 — got {recs:?}");
    let r = &recs[0];
    assert_eq!(r.command.as_deref(), Some("make"));
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.output_lines, vec!["building...".to_string()]);

    // 다른 session_id 는 비어 있어야 한다 (R5.9 session isolation).
    assert!(h.store.recent("sess-other", 10).await.is_empty());

    // metric: central_store_push 1, attach_open_total 1, attach_connections 0 (close 됨).
    assert_eq!(h.metrics.central_store_push_total(), 1);
    assert_eq!(h.metrics.attach_open_total(), 1);
    assert_eq!(h.metrics.attach_connections(), 0);

    // pool 도 drain.
    assert_eq!(h.pool.active_len().await, 0);

    h.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 B — wrong protocol_version → AttachError + close.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_b_wrong_protocol_version_rejected() {
    let h = Harness::start().await;
    let stream = h.connect().await;
    let (mut reader, mut writer) = stream.into_split();

    // 서버가 지원하지 않는 v999 로 AttachOpen.
    write_attach_frame(
        &mut writer,
        &AttachClientFrame::AttachOpen {
            session_id: "sess-b".to_string(),
            protocol_version: 999,
        },
    )
    .await
    .expect("write open");

    // 서버 응답: AttachError (메시지에 "protocol_version" 키워드 포함).
    match read_attach_frame(&mut reader).await.expect("read error") {
        AttachFrameKind::Server(AttachServerFrame::AttachError { message }) => {
            assert!(
                message.contains("protocol_version"),
                "message = {message}"
            );
        }
        other => panic!("AttachError 를 기대 — actual: {other:?}"),
    }

    // 이후 서버는 즉시 close — EOF 가 관측되어야 한다.
    wait_until_eof(&mut reader).await;

    // store / pool 모두 오염되지 않아야 한다 (open 전에 거절).
    assert!(h.store.recent("sess-b", 10).await.is_empty());
    assert_eq!(h.pool.active_len().await, 0);

    // metric: attach_open_total 과 attach_connections 모두 0 그대로. central_store push 도 0.
    assert_eq!(h.metrics.attach_open_total(), 0);
    assert_eq!(h.metrics.attach_connections(), 0);
    assert_eq!(h.metrics.central_store_push_total(), 0);

    h.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 C — oversize PtyBytes → AttachError + close.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_c_oversize_pty_bytes_rejected() {
    let h = Harness::start().await;
    let stream = h.connect().await;
    let (mut reader, mut writer) = stream.into_split();

    // 정상 open 으로 시작 — 그 뒤에 oversize PtyBytes 를 던져 decoder 단계에서 거부를 유도.
    write_attach_frame(
        &mut writer,
        &AttachClientFrame::AttachOpen {
            session_id: "sess-c".to_string(),
            protocol_version: ATTACH_PROTOCOL_VERSION,
        },
    )
    .await
    .expect("write open");
    expect_ack(&mut reader).await;
    wait_for_attach_connections(&h.metrics, 1).await;
    assert_eq!(h.pool.active_len().await, 1);

    // 실제 16 MiB 를 보내지 않고 wire format 만 위조:
    //   [0x01][ (MAX+1) BE ][payload 없음 ]
    // decoder 는 length 체크 단계에서 PtyBytesTooLarge 를 내므로 payload 를 읽지 않는다.
    let mut framed: Vec<u8> = Vec::with_capacity(1 + 4);
    framed.push(PTY_BYTES_DISCRIMINANT);
    let bogus_len: u32 = (MAX_PTY_BYTES_FRAME + 1) as u32;
    framed.extend_from_slice(&bogus_len.to_be_bytes());
    writer.write_all(&framed).await.expect("write bogus");
    writer.flush().await.expect("flush");

    // 서버는 AttachError 후 연결을 닫는다 (R15.4).
    match read_attach_frame(&mut reader).await.expect("read error") {
        AttachFrameKind::Server(AttachServerFrame::AttachError { message }) => {
            assert!(
                message.contains("디코드") || message.contains("PtyBytes"),
                "message = {message}"
            );
        }
        other => panic!("AttachError 를 기대 — actual: {other:?}"),
    }
    wait_until_eof(&mut reader).await;

    // 오버사이즈 frame 이 먼저 거부되었으므로 어떤 record 도 store 에 들어가지 않는다.
    assert!(h.store.recent("sess-c", 10).await.is_empty());
    // pool 은 cleanup 되어 해당 session 이 남아 있으면 안 된다 (R11.4).
    wait_for_pool_len(&h.pool, 0).await;
    // metric: open 은 카운트되었지만 (정상 handshake 경로), connections 는 dec 되어 0.
    assert_eq!(h.metrics.attach_open_total(), 1);
    assert_eq!(h.metrics.attach_connections(), 0);
    // store push 는 0.
    assert_eq!(h.metrics.central_store_push_total(), 0);

    h.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 D — peer uid mismatch 는 실제 프로세스 간 호출 없이 재현 불가.
//   대신 "uid check path 를 통과하는 정상 부트스트랩" 이 regression 없이
//   동작함을 확인한다 (aic-server 측 `AttachServer::handle_attach_client` 의
//   peer_cred 경로가 접속을 기각하지 않고 pool.open 까지 도달한다는 positive path).
//   peer uid 검증 자체의 negative path 는 Task 3.1 unit test 에서 직접 다룬다.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_d_peer_uid_path_allows_same_uid_connection() {
    let h = Harness::start().await;

    // 같은 프로세스 / 같은 uid 에서 connect — server 의 peer_cred 검사는
    // libc::geteuid() == cred.uid() 로 통과. 이 경로가 regression 없이 동작해야 한다.
    let stream = h.connect().await;
    let (mut reader, mut writer) = stream.into_split();

    write_attach_frame(
        &mut writer,
        &AttachClientFrame::AttachOpen {
            session_id: "sess-d".to_string(),
            protocol_version: ATTACH_PROTOCOL_VERSION,
        },
    )
    .await
    .expect("write open");
    expect_ack(&mut reader).await;
    wait_for_attach_connections(&h.metrics, 1).await;

    // graceful close — 서버가 pool.close + metric dec 을 수행해야 한다.
    write_attach_frame(
        &mut writer,
        &AttachClientFrame::AttachClose {
            reason: "uid path done".to_string(),
        },
    )
    .await
    .expect("write close");
    wait_until_eof(&mut reader).await;

    assert_eq!(h.metrics.attach_connections(), 0);
    assert_eq!(h.metrics.attach_open_total(), 1);
    assert_eq!(h.pool.active_len().await, 0);
    // uid 검사 실패 시에는 이 카운터가 올라가지 않으니, 여기서는 1 이어야 한다.
    // (즉 uid check path 를 통과하지 않으면 handshake 자체가 불가능 → test 가 일찍 실패).
    assert!(
        h.store.recent("sess-d", 10).await.is_empty(),
        "close 만 받은 세션은 record 가 없다"
    );

    h.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 E — AttachClose 후 같은 session_id 로 재접속 가능.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_e_session_id_reusable_after_close() {
    let h = Harness::start().await;

    // (1) 첫 번째 연결: open → 간단한 명령 1건 → close.
    {
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "sess-e".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .expect("write open #1");
        expect_ack(&mut reader).await;
        wait_for_attach_connections(&h.metrics, 1).await;

        // "ls" = 6c 73, exit 0.
        for chunk in [
            &b"\x1b]133;C;cmd=6c73\x07"[..],
            &b"file1\n"[..],
            &b"\x1b]133;D;0\x07"[..],
        ] {
            write_attach_frame(
                &mut writer,
                &AttachClientFrame::PtyBytes {
                    bytes: Bytes::copy_from_slice(chunk),
                },
            )
            .await
            .expect("write PtyBytes #1");
        }
        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachClose {
                reason: "first".to_string(),
            },
        )
        .await
        .expect("write close #1");
        wait_until_eof(&mut reader).await;
    }

    // 첫 연결 cleanup 확인.
    wait_for_attach_connections(&h.metrics, 0).await;
    wait_for_pool_len(&h.pool, 0).await;
    let recs_after_first = h.store.recent("sess-e", 10).await;
    assert_eq!(recs_after_first.len(), 1, "첫 연결에서 record 1건");
    assert_eq!(recs_after_first[0].command.as_deref(), Some("ls"));

    // (2) 동일 session_id 로 두 번째 연결 → pool.open 이 성공해야 한다.
    //     state 가 drop 되었으므로 새 OutputProcessor/BoundaryDetector 로 다시 시작.
    {
        let stream = h.connect().await;
        let (mut reader, mut writer) = stream.into_split();

        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachOpen {
                session_id: "sess-e".to_string(),
                protocol_version: ATTACH_PROTOCOL_VERSION,
            },
        )
        .await
        .expect("write open #2");
        // 같은 session_id 재사용 이 금지되어 있다면 여기서 AttachError 가 와서 panic.
        expect_ack(&mut reader).await;
        wait_for_attach_connections(&h.metrics, 1).await;

        // "pwd" = 70 77 64, exit 0.
        for chunk in [
            &b"\x1b]133;C;cmd=707764\x07"[..],
            &b"/tmp\n"[..],
            &b"\x1b]133;D;0\x07"[..],
        ] {
            write_attach_frame(
                &mut writer,
                &AttachClientFrame::PtyBytes {
                    bytes: Bytes::copy_from_slice(chunk),
                },
            )
            .await
            .expect("write PtyBytes #2");
        }
        write_attach_frame(
            &mut writer,
            &AttachClientFrame::AttachClose {
                reason: "second".to_string(),
            },
        )
        .await
        .expect("write close #2");
        wait_until_eof(&mut reader).await;
    }

    wait_for_attach_connections(&h.metrics, 0).await;
    wait_for_pool_len(&h.pool, 0).await;

    // 같은 session_id 의 ring 에는 두 record 가 시간순으로 누적되어 있어야 한다.
    // ring 은 session 단위라 재open 후에도 store 는 계속된다.
    let recs = h.store.recent("sess-e", 10).await;
    assert_eq!(recs.len(), 2, "두 연결의 record 가 같은 ring 에 누적 — got {recs:?}");
    assert_eq!(recs[0].command.as_deref(), Some("ls"));
    assert_eq!(recs[1].command.as_deref(), Some("pwd"));

    // metric: open 2건, connections 0, push 2건.
    assert_eq!(h.metrics.attach_open_total(), 2);
    assert_eq!(h.metrics.attach_connections(), 0);
    assert_eq!(h.metrics.central_store_push_total(), 2);

    h.shutdown().await;
}
