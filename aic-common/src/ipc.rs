//! IPC 프로토콜 타입 및 Length-prefixed framing 유틸리티

use crate::{CommandRecord, SessionInfo};
use serde::{Deserialize, Serialize};

// ── IPC Request / Response ─────────────────────────────────────

/// 클라이언트 → 데몬 요청 메시지 (externally tagged JSON).
///
/// `Ping`/`GetMetrics`는 양 데몬(`aic-session`, `aicd`) 모두에서 의미를 가진다.
/// `GetLastCommand`/`GetRecentLines`는 세션 단위 데이터라 `aicd`에서는 거부된다.
/// `ListSessions`/`Shutdown`은 `aicd` control plane 전용이며, 세션 데몬은
/// graceful Error로 응답한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcRequest {
    GetLastCommand,
    GetRecentLines {
        count: usize,
    },
    GetRecentCommands {
        count: usize,
    },
    /// `aicd` hook event store에서 특정 세션의 마지막 metadata-only command를 조회한다.
    GetLastCommandForSession {
        id: String,
    },
    Ping,
    GetMetrics,
    /// `aicd`에 등록된 세션 목록을 요청한다 (Phase 1.2~1.3).
    ListSessions,
    /// 오래된 inactive(detached/stopping/stopped/failed) 세션을 registry에서 제거한다.
    PruneSessions {
        older_than_secs: u64,
    },
    /// `aicd`를 graceful 종료 시킨다 (active sessions 정리는 향후 sub-step).
    Shutdown,
    /// 세션을 `aicd` registry에 등록한다 (Phase 1.3).
    /// `aic-session`이 시작 직후 보낸다. 같은 id가 이미 있으면 덮어쓴다.
    RegisterSession(SessionInfo),
    /// 세션을 `aicd` registry에서 제거한다 (Phase 1.3).
    /// `aic-session`이 정상 종료 직전에 보낸다.
    UnregisterSession {
        id: String,
    },
    /// 실행 중인 세션이 아직 살아 있음을 `aicd` registry에 알린다.
    HeartbeatSession {
        id: String,
        seen_at: chrono::DateTime<chrono::Utc>,
        cwd: Option<std::path::PathBuf>,
    },
    /// 특정 세션에 graceful 종료 신호를 보낸다 (Phase 2.1).
    ///
    /// 현재 구현: `aicd`가 registry에서 PID를 찾아 `SIGTERM`을 보낸다.
    /// 향후 PTY ownership을 `aicd`가 가져오면 `aicd`가 직접 child를 종료한다.
    StopSession {
        id: String,
    },
    /// shell hook이 보내는 command-start 이벤트 (Phase 3).
    ///
    /// hook mode에서 `preexec`/`DEBUG trap`이 발화하며, 출력은 캡처하지 않고
    /// metadata만 등록한다. `aicd` 미실행 시 hook은 silent skip.
    CommandStarted {
        session_id: String,
        command_id: String,
        command: String,
        cwd: Option<std::path::PathBuf>,
        shell: Option<String>,
        pid: u32,
        started_at: chrono::DateTime<chrono::Utc>,
    },
    /// shell hook이 보내는 command-finish 이벤트 (Phase 3).
    CommandFinished {
        session_id: String,
        command_id: String,
        exit_code: i32,
        finished_at: chrono::DateTime<chrono::Utc>,
        duration_ms: u64,
    },
}

/// 데몬 → 클라이언트 응답 메시지 (externally tagged JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcResponse {
    CommandData(CommandRecord),
    CommandRecords(Vec<CommandRecord>),
    Lines(Vec<String>),
    Pong,
    Metrics(MetricsSnapshot),
    /// `ListSessions` 응답 — `aicd` registry 기준 세션 목록.
    Sessions(Vec<SessionInfo>),
    /// `PruneSessions` 응답 — 제거된 세션 수.
    PrunedSessions {
        count: usize,
    },
    Error {
        message: String,
    },
}

/// 데몬 metric 스냅샷 (`aic top`/`aic-session metrics` 응답용).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// 데몬 시작 이후 경과 시간(초)
    pub uptime_secs: u64,
    /// 데몬 PID
    pub pid: u32,
    /// 누적 IPC 요청 수
    pub ipc_request_count: u64,
    /// Ring Buffer 현재 사용 라인 수
    pub rb_used: usize,
    /// Ring Buffer 최대 라인 수
    pub rb_capacity: usize,
    /// 마지막 명령어 종료 후 경과 초 (없으면 None)
    pub last_command_secs_ago: Option<u64>,
}

// ── Length-prefixed framing ────────────────────────────────────

/// payload 앞에 4-byte u32 big-endian 길이 prefix를 붙여 반환한다.
pub fn encode_frame(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

/// 4-byte u32 big-endian 길이 prefix를 파싱하여 (전체 프레임 크기, payload 슬라이스)를 반환한다.
///
/// - `data`가 4바이트 미만이면 에러
/// - prefix가 가리키는 payload가 `data`에 충분히 없으면 에러
pub fn decode_frame(data: &[u8]) -> anyhow::Result<(usize, &[u8])> {
    if data.len() < 4 {
        anyhow::bail!(
            "프레임 헤더가 부족합니다: 최소 4바이트 필요, {}바이트 수신",
            data.len()
        );
    }

    let payload_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let total_frame_size = 4 + payload_len;

    if data.len() < total_frame_size {
        anyhow::bail!(
            "프레임 데이터가 부족합니다: {}바이트 필요, {}바이트 수신",
            total_frame_size,
            data.len()
        );
    }

    Ok((total_frame_size, &data[4..total_frame_size]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // ── IpcRequest 직렬화 ──────────────────────────────────────

    #[test]
    fn ipc_request_get_last_command_roundtrip() {
        let req = IpcRequest::GetLastCommand;
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_get_recent_lines_roundtrip() {
        let req = IpcRequest::GetRecentLines { count: 42 };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_ping_roundtrip() {
        let req = IpcRequest::Ping;
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn ipc_request_get_last_command_for_session_roundtrip() {
        let req = IpcRequest::GetLastCommandForSession {
            id: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    // ── IpcResponse 직렬화 ─────────────────────────────────────

    #[test]
    fn ipc_response_command_data_roundtrip() {
        let record = CommandRecord {
            command: Some("cargo build".to_string()),
            exit_code: 1,
            output_lines: vec!["error[E0308]: mismatched types".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        };
        let resp = IpcResponse::CommandData(record);
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn ipc_response_lines_roundtrip() {
        let resp = IpcResponse::Lines(vec!["line1".into(), "line2".into()]);
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn ipc_response_pong_roundtrip() {
        let resp = IpcResponse::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn ipc_response_error_roundtrip() {
        let resp = IpcResponse::Error {
            message: "서버 내부 오류".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    // ── Framing ────────────────────────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello, world!";
        let frame = encode_frame(payload);

        assert_eq!(frame.len(), 4 + payload.len());

        let (total_size, decoded) = decode_frame(&frame).unwrap();
        assert_eq!(total_size, frame.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_empty_payload() {
        let frame = encode_frame(b"");
        assert_eq!(frame, vec![0, 0, 0, 0]);

        let (total_size, decoded) = decode_frame(&frame).unwrap();
        assert_eq!(total_size, 4);
        assert_eq!(decoded, b"");
    }

    #[test]
    fn decode_insufficient_header() {
        let result = decode_frame(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_insufficient_payload() {
        // header가 10바이트 payload를 가리키지만 실제로는 2바이트만 존재
        let data = [0, 0, 0, 10, 0xAA, 0xBB];
        let result = decode_frame(&data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_with_trailing_data() {
        let payload = b"test";
        let mut data = encode_frame(payload);
        data.extend_from_slice(b"trailing");

        let (total_size, decoded) = decode_frame(&data).unwrap();
        assert_eq!(total_size, 4 + payload.len());
        assert_eq!(decoded, payload);
    }

    // ── JSON + Framing 통합 ────────────────────────────────────

    #[test]
    fn json_over_frame_roundtrip() {
        let req = IpcRequest::GetRecentLines { count: 100 };
        let json_bytes = serde_json::to_vec(&req).unwrap();
        let frame = encode_frame(&json_bytes);

        let (_total, payload) = decode_frame(&frame).unwrap();
        let decoded: IpcRequest = serde_json::from_slice(payload).unwrap();
        assert_eq!(req, decoded);
    }

    // ── Property-Based Tests ───────────────────────────────────
    // Feature: ac-cli-tool, Property 3: IPC Message Serialization Round-Trip
    // **Validates: Requirements 3.2**

    use proptest::prelude::*;

    /// CommandRecord 전략: 임의의 timestamp를 밀리초 단위 i64에서 생성
    fn arb_command_record() -> impl Strategy<Value = CommandRecord> {
        (
            proptest::option::of(any::<String>()),
            any::<i32>(),
            proptest::collection::vec(any::<String>(), 0..8),
            // 밀리초 범위: 0 ~ 4102444800000 (약 2100년)
            0i64..4_102_444_800_000i64,
        )
            .prop_map(|(command, exit_code, output_lines, ts_millis)| {
                let timestamp =
                    chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default();
                CommandRecord {
                    command,
                    exit_code,
                    output_lines,
                    timestamp,
                    ..Default::default()
                }
            })
    }

    fn arb_ipc_request() -> impl Strategy<Value = IpcRequest> {
        prop_oneof![
            Just(IpcRequest::GetLastCommand),
            any::<usize>().prop_map(|count| IpcRequest::GetRecentLines { count }),
            any::<usize>().prop_map(|count| IpcRequest::GetRecentCommands { count }),
            Just(IpcRequest::Ping),
            Just(IpcRequest::GetMetrics),
            Just(IpcRequest::ListSessions),
            any::<u64>().prop_map(|older_than_secs| IpcRequest::PruneSessions { older_than_secs }),
            Just(IpcRequest::Shutdown),
            arb_session_info().prop_map(IpcRequest::RegisterSession),
            "[0-9a-f]{1,8}".prop_map(|id| IpcRequest::UnregisterSession { id }),
            (
                "[0-9a-f]{1,8}",
                0i64..4_102_444_800_000i64,
                proptest::option::of("[a-zA-Z0-9/_-]{1,64}".prop_map(std::path::PathBuf::from)),
            )
                .prop_map(|(id, ts, cwd)| IpcRequest::HeartbeatSession {
                    id,
                    seen_at: chrono::DateTime::from_timestamp_millis(ts).unwrap_or_default(),
                    cwd,
                }),
            "[0-9a-f]{1,8}".prop_map(|id| IpcRequest::GetLastCommandForSession { id }),
            "[0-9a-f]{1,8}".prop_map(|id| IpcRequest::StopSession { id }),
            (
                "[0-9a-f]{1,8}",
                "[0-9a-f]{1,16}",
                "[a-z ]{1,40}",
                proptest::option::of("[a-zA-Z0-9/_-]{1,32}".prop_map(std::path::PathBuf::from)),
                proptest::option::of("[a-zA-Z0-9/_-]{1,32}"),
                any::<u32>(),
                0i64..4_102_444_800_000i64,
            )
                .prop_map(|(session_id, command_id, command, cwd, shell, pid, ts)| {
                    IpcRequest::CommandStarted {
                        session_id,
                        command_id,
                        command,
                        cwd,
                        shell,
                        pid,
                        started_at: chrono::DateTime::from_timestamp_millis(ts).unwrap_or_default(),
                    }
                }),
            (
                "[0-9a-f]{1,8}",
                "[0-9a-f]{1,16}",
                any::<i32>(),
                0i64..4_102_444_800_000i64,
                any::<u64>(),
            )
                .prop_map(|(session_id, command_id, exit_code, ts, dur)| {
                    IpcRequest::CommandFinished {
                        session_id,
                        command_id,
                        exit_code,
                        finished_at: chrono::DateTime::from_timestamp_millis(ts)
                            .unwrap_or_default(),
                        duration_ms: dur,
                    }
                }),
        ]
    }

    fn arb_session_state() -> impl Strategy<Value = crate::SessionState> {
        use crate::SessionState::*;
        prop_oneof![
            Just(Creating),
            Just(Attached),
            Just(Detached),
            Just(Stopping),
            Just(Stopped),
            Just(Failed),
        ]
    }

    fn arb_session_info() -> impl Strategy<Value = crate::SessionInfo> {
        (
            "[0-9a-f]{1,8}",
            any::<u32>(),
            arb_session_state(),
            0i64..4_102_444_800_000i64,
            proptest::option::of(0i64..4_102_444_800_000i64),
            proptest::option::of(0i64..4_102_444_800_000i64),
            proptest::option::of("[a-zA-Z0-9/_]{1,32}"),
            proptest::option::of("[a-zA-Z0-9/_-]{1,32}"),
            proptest::option::of("[a-zA-Z0-9/_-]{1,64}".prop_map(std::path::PathBuf::from)),
        )
            .prop_map(
                |(
                    id,
                    pid,
                    state,
                    ts_millis,
                    seen_millis,
                    command_millis,
                    attached_tty,
                    shell,
                    cwd,
                )| {
                    let created_at =
                        chrono::DateTime::from_timestamp_millis(ts_millis).unwrap_or_default();
                    let last_seen_at =
                        seen_millis.and_then(chrono::DateTime::from_timestamp_millis);
                    let last_command_at =
                        command_millis.and_then(chrono::DateTime::from_timestamp_millis);
                    crate::SessionInfo {
                        id,
                        pid,
                        state,
                        created_at,
                        last_seen_at,
                        last_command_at,
                        attached_tty,
                        shell,
                        cwd,
                    }
                },
            )
    }

    fn arb_ipc_response() -> impl Strategy<Value = IpcResponse> {
        prop_oneof![
            arb_command_record().prop_map(IpcResponse::CommandData),
            proptest::collection::vec(arb_command_record(), 0..8)
                .prop_map(IpcResponse::CommandRecords),
            proptest::collection::vec(any::<String>(), 0..8).prop_map(IpcResponse::Lines),
            Just(IpcResponse::Pong),
            proptest::collection::vec(arb_session_info(), 0..8).prop_map(IpcResponse::Sessions),
            any::<usize>().prop_map(|count| IpcResponse::PrunedSessions { count }),
            any::<String>().prop_map(|message| IpcResponse::Error { message }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_ipc_request_json_roundtrip(req in arb_ipc_request()) {
            let json = serde_json::to_string(&req).unwrap();
            let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&req, &deserialized);
        }

        #[test]
        fn prop_ipc_response_json_roundtrip(resp in arb_ipc_response()) {
            let json = serde_json::to_string(&resp).unwrap();
            let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&resp, &deserialized);
        }

        #[test]
        fn prop_ipc_request_frame_roundtrip(req in arb_ipc_request()) {
            let json_bytes = serde_json::to_vec(&req).unwrap();
            let frame = encode_frame(&json_bytes);
            let (_total, payload) = decode_frame(&frame).unwrap();
            let decoded: IpcRequest = serde_json::from_slice(payload).unwrap();
            prop_assert_eq!(&req, &decoded);
        }

        #[test]
        fn prop_ipc_response_frame_roundtrip(resp in arb_ipc_response()) {
            let json_bytes = serde_json::to_vec(&resp).unwrap();
            let frame = encode_frame(&json_bytes);
            let (_total, payload) = decode_frame(&frame).unwrap();
            let decoded: IpcResponse = serde_json::from_slice(payload).unwrap();
            prop_assert_eq!(&resp, &decoded);
        }
    }
}
