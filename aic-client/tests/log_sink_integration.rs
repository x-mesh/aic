//! RFC-006 t11 통합테스트 — `aic-client`의 log_sink 종료 flush를 **실제 바이너리를 서브프로세스로
//! 띄워** 검증한다.
//!
//! `AIC_TEST_LOG_SINK_EMIT=1`을 주면 `main()`이 CLI 파싱 이전에 `tracing::warn!` 이벤트 하나를
//! 남기고 `std::process::exit(0)`으로 종료한다(main.rs 참고) — 실제 프로덕션 코드가 흩어진
//! 40여 곳의 `process::exit()` 중 하나를 그대로 흉내낸 것이므로, 여기서 검증하는 atexit 기반
//! flush가 실제 종료 경로에서도 동작함을 보장한다.
//!
//! aicd 소켓 경로는 `AIC_LOG_SINK_AICD_SOCKET`으로 override한다(`log_sink::resolve_aicd_socket`
//! 참고) — 실제 aicd 소켓 경로는 uid당 하나로 고정돼 있어 병렬 테스트/실제 aicd와 충돌하지
//! 않는 격리된 mock 소켓을 쓰려면 이 훅이 필요하다.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::time::{Duration, Instant};

use aic_common::{encode_frame, IpcRequest, IpcResponse};

/// mock aicd — 연결 하나를 accept해 length-prefixed JSON `IpcRequest`를 읽고 `Pong`으로
/// 응답한 뒤, 수신한 요청을 채널로 돌려준다. 실제 aicd와 동일한 프레이밍을 쓴다.
fn spawn_mock_aicd(sock_path: std::path::PathBuf) -> std::sync::mpsc::Receiver<IpcRequest> {
    let listener = UnixListener::bind(&sock_path).expect("mock aicd 소켓 bind 실패");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_err() {
                return;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            if let Ok(req) = serde_json::from_slice::<IpcRequest>(&body) {
                let _ = tx.send(req);
            }
            let resp = serde_json::to_vec(&IpcResponse::Pong).unwrap();
            let _ = stream.write_all(&encode_frame(&resp));
            let _ = stream.flush();
        }
    });
    rx
}

/// 1. `exit_path_flushes_buffer` — `std::process::exit(0)` 경로로 끝나도 atexit 훅이 버퍼를
///    flush하고, mock aicd UDS 소켓이 `PushLogLines`를 실제로 수신하는지 검증한다.
#[test]
fn exit_path_flushes_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mock-aicd.sock");
    let rx = spawn_mock_aicd(sock_path.clone());

    let bin = env!("CARGO_BIN_EXE_aic");
    let output = Command::new(bin)
        .env("AIC_TEST_LOG_SINK_EMIT", "1")
        .env("AIC_LOG_SINK_AICD_SOCKET", &sock_path)
        .output()
        .expect("aic 서브프로세스 실행 실패");

    assert!(
        output.status.success(),
        "std::process::exit(0) 경로는 성공 종료여야 함: {:?}",
        output
    );

    let req = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("mock aicd가 종료 전 PushLogLines를 수신해야 함(atexit flush)");

    match req {
        IpcRequest::PushLogLines { lines } => {
            assert!(!lines.is_empty(), "flush된 라인이 최소 1개는 있어야 함");
            assert!(
                lines
                    .iter()
                    .any(|l| l.message.contains("log_sink 통합테스트 이벤트")),
                "테스트가 남긴 tracing::warn! 이벤트가 flush된 라인에 있어야 함: {lines:?}"
            );
            assert!(lines.iter().all(|l| l.service == "aic-client"));
        }
        other => panic!("PushLogLines를 기대했으나 다른 요청을 받음: {other:?}"),
    }
}

/// 2. `aicd_absent_exits_quietly` — aicd(mock 소켓)조차 없는 상태에서 종료해도 에러 출력
///    없이 조용히 끝나고, 종료 자체가 300ms 근방(IO_TIMEOUT) 안에서 지연 없이 끝나는지 검증한다.
#[test]
fn aicd_absent_exits_quietly() {
    let dir = tempfile::tempdir().unwrap();
    // 존재하지 않는 소켓 경로 — bind도, listen도 하지 않는다.
    let missing_sock = dir.path().join("no-such-aicd.sock");

    let bin = env!("CARGO_BIN_EXE_aic");
    let start = Instant::now();
    let output = Command::new(bin)
        .env("AIC_TEST_LOG_SINK_EMIT", "1")
        .env("AIC_LOG_SINK_AICD_SOCKET", &missing_sock)
        .output()
        .expect("aic 서브프로세스 실행 실패");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "aicd 미실행이어도 프로세스는 정상 종료(exit 0)해야 함: {:?}",
        output
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "aicd 부재 시 종료가 지연되면 안 됨(IO_TIMEOUT 300ms 근방이어야 함): {elapsed:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.to_lowercase().contains("panic"),
        "aicd 미실행이 panic으로 이어지면 안 됨: {stderr}"
    );
}
