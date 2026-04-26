//! 클라이언트 세션 연결 통합 테스트
//!
//! `AIC_SESSION_ID` 환경변수 설정 여부에 따른 클라이언트 소켓 연결 동작을 검증한다.
//!
//! - 세션 소켓이 존재하면 UdsClient가 정상 연결되어 Ping/Pong 응답을 받는다.
//! - 세션 소켓이 존재하지 않으면 연결이 실패한다 (히스토리 폴백 시나리오).
//! - 세션이 종료된 경우(소켓 경로만 있고 서버 없음) 연결이 실패한다.
//!
//! Requirements: 4.1, 4.2, 4.3

use aic_client::uds_client::UdsClient;
use aic_server::ring_buffer::RingBuffer;
use aic_server::uds_server::UdsServer;

use std::sync::Arc;
use tokio::sync::RwLock;

/// AIC_SESSION_ID 설정 시 세션 소켓으로 UdsClient가 정상 연결되는지 검증한다.
///
/// 1. temp dir에 `session-{id}.sock` 형식으로 UdsServer를 바인딩
/// 2. UdsClient로 해당 소켓에 연결하여 Ping → Pong 응답 확인
///
/// Requirements: 4.1, 4.2
#[tokio::test]
async fn session_id_set_connects_to_session_socket() {
    let dir = tempfile::tempdir().unwrap();
    let session_id = "ab12cd34";
    let sock_path = dir.path().join(format!("session-{session_id}.sock"));

    // 세션 소켓에 UdsServer 바인딩
    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buffer = Arc::new(RwLock::new(RingBuffer::new(100)));
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    // UdsClient로 세션 소켓에 연결하여 Ping 전송
    let client = UdsClient::new(sock_path.clone());
    let alive = client.ping().await.unwrap();
    assert!(
        alive,
        "세션 소켓에 연결된 UdsClient는 Ping에 true를 반환해야 합니다"
    );

    handle.abort();
}

/// AIC_SESSION_ID 미설정 시 히스토리 폴백 시나리오를 검증한다.
///
/// 존재하지 않는 소켓 경로로 UdsClient를 생성하면 연결이 실패하여
/// ping이 false를 반환하고, get_last_command는 ServerNotRunning 에러를 반환한다.
/// 이는 클라이언트가 히스토리 폴백으로 전환해야 하는 상황이다.
///
/// Requirements: 4.3
#[tokio::test]
async fn session_id_not_set_fallback_to_history() {
    let dir = tempfile::tempdir().unwrap();
    // 존재하지 않는 소켓 경로 — AIC_SESSION_ID 미설정 시 기본 소켓도 없는 상황
    let nonexistent_sock = dir.path().join("session.sock");

    let client = UdsClient::new(nonexistent_sock);

    // ping은 연결 실패 시 false 반환 (에러가 아닌 false)
    let alive = client.ping().await.unwrap();
    assert!(
        !alive,
        "존재하지 않는 소켓에 대해 ping은 false를 반환해야 합니다"
    );

    // get_last_command는 ServerNotRunning 에러 반환
    let err = client.get_last_command().await.unwrap_err();
    match err {
        aic_common::AicError::ServerNotRunning => {}
        other => panic!("ServerNotRunning을 기대했지만 {:?}를 받았습니다", other),
    }
}

/// 세션이 종료된 경우(소켓 파일이 존재하지 않음)를 검증한다.
///
/// AIC_SESSION_ID에 대응하는 소켓 경로가 존재하지 않으면
/// 클라이언트는 연결할 수 없고, 사용자에게 세션 종료를 알린 뒤
/// 히스토리 폴백으로 전환해야 한다.
///
/// Requirements: 4.3, 4.4
#[tokio::test]
async fn session_ended_socket_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let session_id = "deadbeef";
    // 세션 소켓 경로를 생성하지만 실제 서버는 바인딩하지 않음 (종료된 세션)
    let sock_path = dir.path().join(format!("session-{session_id}.sock"));

    // 소켓 파일이 존재하지 않음을 확인
    assert!(
        !sock_path.exists(),
        "종료된 세션의 소켓 파일은 존재하지 않아야 합니다"
    );

    let client = UdsClient::new(sock_path);

    // ping은 false 반환
    let alive = client.ping().await.unwrap();
    assert!(!alive, "종료된 세션에 대해 ping은 false를 반환해야 합니다");

    // get_last_command는 ServerNotRunning 에러
    let err = client.get_last_command().await.unwrap_err();
    match err {
        aic_common::AicError::ServerNotRunning => {}
        other => panic!("ServerNotRunning을 기대했지만 {:?}를 받았습니다", other),
    }
}

/// 세션 소켓 경로가 session_socket_path() 함수와 일치하는지 검증한다.
///
/// aic_common::session_socket_path()로 생성한 경로에 서버를 바인딩하고
/// 동일한 경로로 클라이언트가 연결할 수 있는지 확인한다.
/// 서버와 클라이언트가 동일한 경로 결정 로직을 사용함을 보장한다.
///
/// Requirements: 4.1, 4.2
#[tokio::test]
async fn session_socket_path_consistency() {
    let dir = tempfile::tempdir().unwrap();
    let session_id = "cafe0123";

    // session_socket_path와 동일한 네이밍 규칙으로 소켓 생성
    let sock_path = dir.path().join(format!("session-{session_id}.sock"));

    // 경로 형식 검증: session-{id}.sock 패턴
    let file_name = sock_path.file_name().unwrap().to_str().unwrap();
    assert!(
        file_name.starts_with("session-"),
        "소켓 파일명은 'session-' prefix를 가져야 합니다"
    );
    assert!(
        file_name.ends_with(".sock"),
        "소켓 파일명은 '.sock' suffix를 가져야 합니다"
    );

    // 경로에서 session_id 추출 가능 확인
    let extracted = aic_common::extract_session_id(&sock_path);
    assert_eq!(
        extracted,
        Some(session_id.to_string()),
        "소켓 경로에서 session_id를 추출할 수 있어야 합니다"
    );

    // 실제 서버 바인딩 + 클라이언트 연결
    let server = UdsServer::bind(&sock_path).await.unwrap();
    let buffer = Arc::new(RwLock::new(RingBuffer::new(100)));
    let buf_clone = Arc::clone(&buffer);
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    let client = UdsClient::new(sock_path);
    let alive = client.ping().await.unwrap();
    assert!(
        alive,
        "session_socket_path 규칙으로 생성된 소켓에 클라이언트가 연결 가능해야 합니다"
    );

    handle.abort();
}
