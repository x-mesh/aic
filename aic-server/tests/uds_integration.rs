//! UDS server-client round-trip 통합 테스트
//!
//! UdsServer 시작 → UdsClient 연결 → GetLastCommand 요청/응답 검증
//! Ping/Pong 검증
//!
//! Requirements: 3.1, 3.2

use aic_common::{CommandRecord, IpcResponse};
use aic_server::ring_buffer::RingBuffer;
use aic_server::uds_server::UdsServer;

use aic_common::{encode_frame, IpcRequest};
use chrono::Utc;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

fn make_buffer_with_record() -> Arc<RwLock<RingBuffer>> {
    let mut buf = RingBuffer::new(100);
    buf.push(CommandRecord {
        command: Some("cargo build".to_string()),
        exit_code: 1,
        output_lines: vec![
            "error[E0308]: mismatched types".to_string(),
            "help: try using a conversion method".to_string(),
        ],
        timestamp: Utc::now(),
        ..Default::default()
    });
    Arc::new(RwLock::new(buf))
}

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

#[tokio::test]
async fn ping_pong_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("ping.sock");

    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buffer = Arc::new(RwLock::new(RingBuffer::new(100)));
    let buf_clone = Arc::clone(&buffer);

    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    let resp = send_request(&sock_path, IpcRequest::Ping).await;
    assert_eq!(resp, IpcResponse::Pong);

    handle.abort();
}

#[tokio::test]
async fn get_last_command_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("cmd.sock");

    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buffer = make_buffer_with_record();
    let buf_clone = Arc::clone(&buffer);

    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    let resp = send_request(&sock_path, IpcRequest::GetLastCommand).await;
    match resp {
        IpcResponse::CommandData(record) => {
            assert_eq!(record.command, Some("cargo build".to_string()));
            assert_eq!(record.exit_code, 1);
            assert_eq!(record.output_lines.len(), 2);
            assert!(record.output_lines[0].contains("E0308"));
        }
        other => panic!("CommandData 응답을 기대했지만 {:?}를 받았습니다", other),
    }

    handle.abort();
}

#[tokio::test]
async fn get_last_command_empty_buffer_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("empty.sock");

    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buffer = Arc::new(RwLock::new(RingBuffer::new(100)));
    let buf_clone = Arc::clone(&buffer);

    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    let resp = send_request(&sock_path, IpcRequest::GetLastCommand).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(message.contains("저장된 명령어가 없습니다"));
        }
        other => panic!("Error 응답을 기대했지만 {:?}를 받았습니다", other),
    }

    handle.abort();
}

#[tokio::test]
async fn get_recent_lines_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("lines.sock");

    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buffer = make_buffer_with_record();
    let buf_clone = Arc::clone(&buffer);

    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    let resp = send_request(&sock_path, IpcRequest::GetRecentLines { count: 1 }).await;
    match resp {
        IpcResponse::Lines(lines) => {
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains("conversion method"));
        }
        other => panic!("Lines 응답을 기대했지만 {:?}를 받았습니다", other),
    }

    handle.abort();
}

#[tokio::test]
async fn multiple_sequential_requests() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("multi.sock");

    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buffer = make_buffer_with_record();
    let buf_clone = Arc::clone(&buffer);

    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    // 첫 번째 요청: Ping
    let resp1 = send_request(&sock_path, IpcRequest::Ping).await;
    assert_eq!(resp1, IpcResponse::Pong);

    // 두 번째 요청: GetLastCommand
    let resp2 = send_request(&sock_path, IpcRequest::GetLastCommand).await;
    assert!(matches!(resp2, IpcResponse::CommandData(_)));

    // 세 번째 요청: Ping (연결 재사용 확인)
    let resp3 = send_request(&sock_path, IpcRequest::Ping).await;
    assert_eq!(resp3, IpcResponse::Pong);

    handle.abort();
}
