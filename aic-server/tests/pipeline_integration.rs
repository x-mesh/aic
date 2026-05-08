//! Full pipeline 통합 테스트
//!
//! Command execution → OutputProcessor → CommandBoundaryDetector → RingBuffer → UDS response
//! 전체 파이프라인을 시뮬레이션하여 검증한다.
//!
//! Requirements: 2.1, 2.2, 4.1, 4.2, 4.4

use aic_common::{encode_frame, CommandRecord, IpcRequest, IpcResponse};
use aic_server::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use aic_server::output_processor::OutputProcessor;
use aic_server::ring_buffer::RingBuffer;
use aic_server::uds_server::UdsServer;

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

/// OutputProcessor → CommandBoundaryDetector → RingBuffer 파이프라인을
/// 동기적으로 시뮬레이션한다.
///
/// 디자인 문서에 따르면 OSC 133 마커는 ANSI strip 전에 먼저 파싱해야 한다.
/// 따라서 raw bytes에서 마커 라인을 먼저 감지하고, 일반 출력은 ANSI strip 후
/// clean text로 boundary detector에 전달한다.
fn simulate_pipeline(raw_chunks: &[&[u8]], buffer: &mut RingBuffer) -> Vec<CommandRecord> {
    let mut processor = OutputProcessor::new();
    let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
        marker_sequence: "osc133".to_string(),
    });

    let mut records = Vec::new();

    for chunk in raw_chunks {
        // 1) raw bytes를 문자열로 변환하여 OSC 마커 스캔용으로 보관
        let raw_str = String::from_utf8_lossy(chunk);

        // 2) OutputProcessor로 ANSI strip + alternate screen 감지
        let output = processor.process(chunk);

        // 3) 각 raw 라인을 순회하며 마커 감지 또는 clean text 축적
        for raw_line in raw_str.lines() {
            // OSC 133 마커가 포함된 라인은 raw 상태로 detector에 전달 (마커 감지용)
            if raw_line.contains("\x1b]133;") {
                if let Some(record) = detector.feed_line(raw_line) {
                    buffer.push(record.clone());
                    records.push(record);
                }
            } else if output.clean_text.is_some() {
                // alternate screen이 아닌 경우에만 clean text를 축적
                let stripped = strip_ansi_escapes::strip(raw_line.as_bytes());
                let clean_line = String::from_utf8_lossy(&stripped);
                if !clean_line.is_empty() {
                    if let Some(record) = detector.feed_line(&clean_line) {
                        buffer.push(record.clone());
                        records.push(record);
                    }
                }
            }
        }
    }

    records
}

#[test]
fn pipeline_single_command_with_marker() {
    let mut buffer = RingBuffer::new(500);

    // 시뮬레이션: 명령어 출력 + OSC 133 completion marker
    let chunks: Vec<&[u8]> = vec![b"file1.rs\nfile2.rs\n", b"\x1b]133;D;0\x07"];

    let records = simulate_pipeline(&chunks, &mut buffer);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].exit_code, 0);
    assert!(records[0].output_lines.contains(&"file1.rs".to_string()));
    assert!(records[0].output_lines.contains(&"file2.rs".to_string()));

    // RingBuffer에서도 동일한 레코드를 조회할 수 있어야 함
    let last = buffer.last().unwrap();
    assert_eq!(last.exit_code, 0);
    assert_eq!(last.output_lines.len(), 2);
}

#[test]
fn pipeline_error_command_with_nonzero_exit() {
    let mut buffer = RingBuffer::new(500);

    let chunks: Vec<&[u8]> = vec![b"error[E0308]: mismatched types\n", b"\x1b]133;D;1\x07"];

    let records = simulate_pipeline(&chunks, &mut buffer);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].exit_code, 1);
    assert!(records[0].output_lines[0].contains("E0308"));
}

#[test]
fn pipeline_command_marker_populates_command_record() {
    let mut buffer = RingBuffer::new(500);

    let chunks: Vec<&[u8]> = vec![
        b"\x1b]133;C;cmd=636172676f206275696c64\x07",
        b"error[E0308]: mismatched types\n",
        b"\x1b]133;D;101\x07",
    ];

    let records = simulate_pipeline(&chunks, &mut buffer);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].command.as_deref(), Some("cargo build"));
    assert_eq!(records[0].exit_code, 101);

    let last = buffer.last().unwrap();
    assert_eq!(last.command.as_deref(), Some("cargo build"));
}

#[test]
fn pipeline_multiple_commands_sequential() {
    let mut buffer = RingBuffer::new(500);

    let chunks: Vec<&[u8]> = vec![
        b"output from cmd1\n",
        b"\x1b]133;D;0\x07\n",
        b"error from cmd2\n",
        b"\x1b]133;D;2\x07\n",
    ];

    let records = simulate_pipeline(&chunks, &mut buffer);

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].exit_code, 0);
    assert_eq!(records[1].exit_code, 2);

    // RingBuffer의 last()는 마지막 명령어를 반환
    let last = buffer.last().unwrap();
    assert_eq!(last.exit_code, 2);
}

#[test]
fn pipeline_ansi_stripped_before_boundary_detection() {
    let mut buffer = RingBuffer::new(500);

    // ANSI 색상 코드가 포함된 출력
    let chunks: Vec<&[u8]> = vec![
        b"\x1b[31merror: file not found\x1b[0m\n",
        b"\x1b]133;D;1\x07",
    ];

    let records = simulate_pipeline(&chunks, &mut buffer);

    assert_eq!(records.len(), 1);
    // ANSI가 제거된 순수 텍스트만 저장되어야 함
    let line = &records[0].output_lines[0];
    assert!(line.contains("error: file not found"));
    assert!(!line.contains("\x1b["));
}

#[test]
fn pipeline_alternate_screen_skips_buffer() {
    let mut buffer = RingBuffer::new(500);

    let chunks: Vec<&[u8]> = vec![
        b"normal output\n",
        b"\x1b[?1049h",   // alternate screen 진입
        b"TUI content\n", // 이 출력은 버퍼에 저장되지 않아야 함
        b"\x1b[?1049l",   // alternate screen 복귀
        b"back to normal\n",
        b"\x1b]133;D;0\x07",
    ];

    let records = simulate_pipeline(&chunks, &mut buffer);

    // alternate screen 중 출력은 무시되므로 "TUI content"는 레코드에 없어야 함
    assert_eq!(records.len(), 1);
    let all_lines: Vec<&str> = records[0].output_lines.iter().map(|s| s.as_str()).collect();
    assert!(all_lines.contains(&"normal output"));
    assert!(all_lines.contains(&"back to normal"));
    assert!(!all_lines.iter().any(|l| l.contains("TUI content")));
}

/// 전체 파이프라인 + UDS 서버를 통한 end-to-end 테스트.
///
/// Phase 3.5 (Task 5.2 / 5.3): 세션 로컬 data plane 이 제거되어 `GetLastCommand`
/// 가 항상 Phase 3.5 전용 안내 에러로 거절된다 (R7.2). 본 테스트는 local
/// RingBuffer 에 push 된 record 를 session UDS 로 조회하는 플로우를 검증하므로
/// Phase 3.5 에서는 제외한다.
#[cfg(not(feature = "phase-3_5"))]
#[tokio::test]
async fn pipeline_to_uds_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("pipeline.sock");

    // 파이프라인으로 RingBuffer에 데이터 적재
    let mut ring = RingBuffer::new(500);
    let chunks: Vec<&[u8]> = vec![b"build successful\n", b"\x1b]133;D;0\x07"];
    simulate_pipeline(&chunks, &mut ring);

    let buffer = Arc::new(RwLock::new(ring));
    let buf_clone = Arc::clone(&buffer);

    // UDS 서버 시작
    let server = UdsServer::bind(&sock_path).await.unwrap();
    let handle = tokio::spawn(async move { server.serve(buf_clone).await });

    // UDS 클라이언트로 GetLastCommand 요청
    let mut stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

    let req = IpcRequest::GetLastCommand;
    let req_json = serde_json::to_vec(&req).unwrap();
    let frame = encode_frame(&req_json);
    stream.write_all(&frame).await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    let resp: IpcResponse = serde_json::from_slice(&resp_buf).unwrap();
    match resp {
        IpcResponse::CommandData(record) => {
            assert_eq!(record.exit_code, 0);
            assert!(record
                .output_lines
                .iter()
                .any(|l| l.contains("build successful")));
        }
        other => panic!("CommandData를 기대했지만 {:?}를 받았습니다", other),
    }

    handle.abort();
}
