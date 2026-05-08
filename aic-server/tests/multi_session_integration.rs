//! 세션별 소켓 독립성 통합 테스트
//!
//! 서로 다른 Session_ID로 두 UdsServer 인스턴스를 동시에 바인딩하고,
//! 각각 독립적으로 Ping 응답 및 RingBuffer 격리를 검증한다.
//!
//! Requirements: 3.1, 3.2, 5.1, 5.2, 5.3
//!
//! ## Phase 3.5 feature gate (Task 5.2 / 5.3)
//!
//! Phase 3.5 빌드에서는 세션 로컬 data plane 이 제거되어 `GetLastCommand` 가
//! 항상 안내 에러로 거절된다. 따라서 data plane 조회에 의존하는 두 테스트
//! (`two_sessions_independent_ring_buffers`, `two_sessions_concurrent_requests`) 는
//! `#[cfg(not(feature = "phase-3_5"))]` 로 gate 하고, Ping-only 검증인
//! `two_sessions_independent_ping` 만 Phase 3.5 에서도 실행한다.

use aic_common::{encode_frame, IpcRequest, IpcResponse};
#[cfg(not(feature = "phase-3_5"))]
use aic_common::CommandRecord;
use aic_server::ring_buffer::RingBuffer;
use aic_server::uds_server::UdsServer;

#[cfg(not(feature = "phase-3_5"))]
use chrono::Utc;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

/// UDS 클라이언트 헬퍼: 요청 전송 → 응답 수신
async fn send_request(sock_path: &std::path::Path, request: IpcRequest) -> IpcResponse {
    let mut stream = tokio::net::UnixStream::connect(sock_path).await.unwrap();

    let req_json = serde_json::to_vec(&request).unwrap();
    let frame = encode_frame(&req_json);
    stream.write_all(&frame).await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    serde_json::from_slice(&resp_buf).unwrap()
}

/// 두 UdsServer 인스턴스가 서로 다른 세션 소켓에 동시 바인딩되고,
/// 각각 독립적으로 Ping/Pong 응답을 반환하는지 검증한다.
/// Requirements: 3.1, 3.2
#[tokio::test]
async fn two_sessions_independent_ping() {
    let dir = tempfile::tempdir().unwrap();

    // 서로 다른 Session_ID로 소켓 경로 생성
    let sock_a = dir.path().join("session-aaaa1111.sock");
    let sock_b = dir.path().join("session-bbbb2222.sock");

    // 두 서버 동시 바인딩
    let server_a = UdsServer::bind(&sock_a).await.unwrap();
    let server_b = UdsServer::bind(&sock_b).await.unwrap();

    assert!(sock_a.exists(), "세션 A 소켓 파일이 존재해야 합니다");
    assert!(sock_b.exists(), "세션 B 소켓 파일이 존재해야 합니다");

    // 각 서버에 독립적인 RingBuffer 할당
    let buffer_a = Arc::new(RwLock::new(RingBuffer::new(100)));
    let buffer_b = Arc::new(RwLock::new(RingBuffer::new(100)));

    let buf_a_clone = Arc::clone(&buffer_a);
    let buf_b_clone = Arc::clone(&buffer_b);

    let handle_a = tokio::spawn(async move { server_a.serve(buf_a_clone).await });
    let handle_b = tokio::spawn(async move { server_b.serve(buf_b_clone).await });

    // 각 서버에 Ping 전송 → 독립적으로 Pong 응답 확인
    let resp_a = send_request(&sock_a, IpcRequest::Ping).await;
    let resp_b = send_request(&sock_b, IpcRequest::Ping).await;

    assert_eq!(resp_a, IpcResponse::Pong, "세션 A가 Pong을 반환해야 합니다");
    assert_eq!(resp_b, IpcResponse::Pong, "세션 B가 Pong을 반환해야 합니다");

    handle_a.abort();
    handle_b.abort();
}

/// 각 세션이 독립적인 RingBuffer를 유지하는지 검증한다.
/// 세션 A에만 데이터를 넣고, 세션 B에서는 빈 상태를 확인한다.
/// Requirements: 5.1, 5.2, 5.3
///
/// Phase 3.5 (Task 5.2 / 5.3): 세션 로컬 data plane 이 제거되어 `GetLastCommand`
/// 는 항상 안내 에러로 거절된다 (R7.2). 본 테스트는 data plane 조회의 격리를
/// 검증하므로 Phase 3.5 빌드에서는 제외된다.
#[cfg(not(feature = "phase-3_5"))]
#[tokio::test]
async fn two_sessions_independent_ring_buffers() {
    let dir = tempfile::tempdir().unwrap();

    let sock_a = dir.path().join("session-cccc3333.sock");
    let sock_b = dir.path().join("session-dddd4444.sock");

    let server_a = UdsServer::bind(&sock_a).await.unwrap();
    let server_b = UdsServer::bind(&sock_b).await.unwrap();

    // 세션 A: 데이터가 있는 RingBuffer
    let mut buf_a = RingBuffer::new(100);
    buf_a.push(CommandRecord {
        command: Some("cargo test".to_string()),
        exit_code: 0,
        output_lines: vec!["ok".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });
    let buffer_a = Arc::new(RwLock::new(buf_a));

    // 세션 B: 빈 RingBuffer
    let buffer_b = Arc::new(RwLock::new(RingBuffer::new(100)));

    let buf_a_clone = Arc::clone(&buffer_a);
    let buf_b_clone = Arc::clone(&buffer_b);

    let handle_a = tokio::spawn(async move { server_a.serve(buf_a_clone).await });
    let handle_b = tokio::spawn(async move { server_b.serve(buf_b_clone).await });

    // 세션 A: GetLastCommand → CommandData 응답
    let resp_a = send_request(&sock_a, IpcRequest::GetLastCommand).await;
    match &resp_a {
        IpcResponse::CommandData(record) => {
            assert_eq!(record.command, Some("cargo test".to_string()));
            assert_eq!(record.exit_code, 0);
        }
        other => panic!(
            "세션 A에서 CommandData를 기대했지만 {:?}를 받았습니다",
            other
        ),
    }

    // 세션 B: GetLastCommand → Error 응답 (빈 버퍼)
    let resp_b = send_request(&sock_b, IpcRequest::GetLastCommand).await;
    match &resp_b {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("저장된 명령어가 없습니다"),
                "세션 B는 빈 버퍼이므로 에러 메시지를 반환해야 합니다"
            );
        }
        other => panic!("세션 B에서 Error를 기대했지만 {:?}를 받았습니다", other),
    }

    handle_a.abort();
    handle_b.abort();
}

/// 두 세션에 동시에 여러 요청을 보내도 서로 간섭하지 않는지 검증한다.
/// Requirements: 3.2, 5.2
///
/// Phase 3.5 (Task 5.2 / 5.3): data plane 조회가 Phase 3.5 전용 에러로 거절되므로
/// 본 테스트는 Phase ≤ 3.4 에서만 유효하다.
#[cfg(not(feature = "phase-3_5"))]
#[tokio::test]
async fn two_sessions_concurrent_requests() {
    let dir = tempfile::tempdir().unwrap();

    let sock_a = dir.path().join("session-eeee5555.sock");
    let sock_b = dir.path().join("session-ffff6666.sock");

    let server_a = UdsServer::bind(&sock_a).await.unwrap();
    let server_b = UdsServer::bind(&sock_b).await.unwrap();

    // 세션 A: "ls" 명령어
    let mut buf_a = RingBuffer::new(100);
    buf_a.push(CommandRecord {
        command: Some("ls -la".to_string()),
        exit_code: 0,
        output_lines: vec!["total 42".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });
    let buffer_a = Arc::new(RwLock::new(buf_a));

    // 세션 B: "pwd" 명령어
    let mut buf_b = RingBuffer::new(100);
    buf_b.push(CommandRecord {
        command: Some("pwd".to_string()),
        exit_code: 0,
        output_lines: vec!["/home/user".to_string()],
        timestamp: Utc::now(),
        ..Default::default()
    });
    let buffer_b = Arc::new(RwLock::new(buf_b));

    let buf_a_clone = Arc::clone(&buffer_a);
    let buf_b_clone = Arc::clone(&buffer_b);

    let handle_a = tokio::spawn(async move { server_a.serve(buf_a_clone).await });
    let handle_b = tokio::spawn(async move { server_b.serve(buf_b_clone).await });

    // 동시에 두 세션에 요청 전송
    let (resp_a, resp_b) = tokio::join!(
        send_request(&sock_a, IpcRequest::GetLastCommand),
        send_request(&sock_b, IpcRequest::GetLastCommand),
    );

    // 세션 A는 "ls -la" 데이터만 반환
    match &resp_a {
        IpcResponse::CommandData(record) => {
            assert_eq!(record.command, Some("ls -la".to_string()));
        }
        other => panic!(
            "세션 A에서 CommandData를 기대했지만 {:?}를 받았습니다",
            other
        ),
    }

    // 세션 B는 "pwd" 데이터만 반환
    match &resp_b {
        IpcResponse::CommandData(record) => {
            assert_eq!(record.command, Some("pwd".to_string()));
        }
        other => panic!(
            "세션 B에서 CommandData를 기대했지만 {:?}를 받았습니다",
            other
        ),
    }

    handle_a.abort();
    handle_b.abort();
}
