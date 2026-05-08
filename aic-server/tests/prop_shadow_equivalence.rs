//! Property test — Phase 3.3 Task 3.6: P1 Shadow equivalence (local ↔ aicd).
//!
//! **Property 1: Shadow equivalence** — 동일한 PTY byte 시퀀스를 두 경로에 투입할 때,
//! 두 경로가 산출하는 `CommandRecord` 시퀀스는
//! `(command, exit_code, output_lines, capture_mode, capture_quality)` 5-튜플
//! 기준으로 완전히 동일해야 한다.
//!
//!   (A) **local 파이프라인** — `OutputProcessor + CommandBoundaryDetector`
//!       (`session_runtime::output_handle` 의 local 경로와 동일 구성).
//!   (B) **central 파이프라인** — attach stream 을 통해 aicd 의
//!       `SessionProcessorPool` 에 투입 (`SessionProcessorPool::feed` 는 위
//!       local 구성과 동일한 처리기를 내부적으로 사용하며, 반환 record 에
//!       `capture_mode = CaptureMode::Pty` 를 명시 설정한다).
//!
//! ### capture_mode / capture_quality 동등성
//!
//! - local 파이프라인: detector 가 반환하는 `CommandRecord` 는 `capture_mode`
//!   와 `capture_quality` 를 명시 설정하지 않으므로 `Default` 값
//!   (`CaptureMode::Pty`, `CaptureQuality::Unknown`) 을 가진다.
//! - central 파이프라인: `SessionProcessorPool::feed` 가 반환 직전 매
//!   record 에 `capture_mode = CaptureMode::Pty` 를 명시 덮어쓰고,
//!   `capture_quality` 는 손대지 않으므로 `CaptureQuality::Unknown` 이 된다.
//!
//! 두 값 모두 동일하므로 projection 의 5-튜플이 일치해야 한다.
//!
//! ### 생성 전략: `arb_pty_byte_stream`
//!
//! 하나의 "명령 cycle" 을 OSC 133 마커를 기반으로 현실적으로 구성한다:
//!
//! ```text
//! [optional \x1b]133;A\x07]          # prompt start (noise)
//! [optional \x1b]133;B\x07]          # command entry (noise)
//!  \x1b]133;C;cmd=<hex>\x07          # 실행 시작 + command 텍스트
//! <N lines of output, 각 줄에 임의 SGR ANSI 노이즈 선택>
//!  \x1b]133;D;<exit_code>\x07        # 완료 + exit code
//! ```
//!
//! 스트림은 위 cycle 을 1..=5 회 연결한다. detector 의 ring eviction 을
//! 트리거하지 않기 위해 cycle 수를 5 이하로 제한한다. command 텍스트와
//! 출력 라인은 ASCII-only 로 제한해 UTF-8 경계 문제를 배제한다 (shadow
//! 동등성만 확인하는 본 property 의 목적에 맞춤 — UTF-8 경계 처리의
//! 정확성은 OutputProcessor 의 단위 테스트 책임이다).
//!
//! ### chunking
//!
//! 동일한 byte 시퀀스를 두 파이프라인에 "그대로" 한 번에 투입한다.
//! chunk 경계가 다르면 두 파이프라인이 다르게 반응할 수 있는데 (예:
//! multi-byte ANSI 중간에서 chunk 가 잘리는 경우), 본 property 는 경로
//! 간 동등성을 보는 것이지 chunking 내성을 확인하지 않는다. 같은 byte
//! 를 같은 chunk 로 feed 하므로 두 파이프라인의 내부 상태 전이는
//! 동일해야 한다.
//!
//! **Validates: Requirements R5.10, R5.11, R16.1, R16.2, R16.3, R16.4**

use aic_common::{CaptureMode, CaptureQuality, CommandRecord};
use aic_server::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use aic_server::output_processor::OutputProcessor;
use aic_server::session_processor_pool::SessionProcessorPool;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// 한 byte stream 에 포함할 명령 cycle 수 상한 — detector 의 ring / pool 의
/// 내부 버퍼 eviction 을 트리거하지 않도록 넉넉히 여유를 둔다. 출력 라인도
/// cycle 당 5 줄 이하이므로 총 최대 25 줄 + 마커들, 이는 `CommandRecordStore`
/// 의 64-record ring 아래이다.
const MAX_CYCLES: usize = 5;
/// cycle 당 출력 라인 수 상한.
const MAX_LINES_PER_CYCLE: usize = 5;

/// 출력 라인 본문. ESC / BEL / CR / LF / 백슬래시 는 OSC 133 마커 파싱과
/// line split 에 영향을 주므로 배제한다. 일반적인 printable ASCII 중 파싱에
/// 안전한 문자들만 허용한다.
fn arb_safe_output_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 _./:@#\\-]{0,40}".prop_map(String::from)
}

/// 명령 텍스트. OSC 133;C;cmd=<hex> 로 hex-encoding 되어 들어가므로 임의
/// 바이트라도 문제가 없지만, 검증의 간결성을 위해 ASCII-only 로 제한한다.
fn arb_command_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 _\\-]{1,20}".prop_map(String::from)
}

/// 한 줄에 덧씌울 수 있는 SGR ANSI 노이즈. OutputProcessor 가 ANSI strip 을
/// 해주므로 detector 로는 순수 텍스트만 도달한다. 노이즈 포함 여부와 상관
/// 없이 두 파이프라인이 같은 결과를 내야 한다.
fn arb_ansi_sgr() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"\x1b[31m".to_vec()), // red
        Just(b"\x1b[32m".to_vec()), // green
        Just(b"\x1b[1m".to_vec()),  // bold
        Just(b"\x1b[0m".to_vec()),  // reset
        Just(Vec::new()),           // no noise
    ]
}

/// 한 명령 cycle 을 byte 시퀀스로 생성한다.
fn arb_command_cycle() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<bool>(),
        any::<bool>(),
        arb_command_text(),
        prop::collection::vec(
            (arb_safe_output_text(), arb_ansi_sgr(), arb_ansi_sgr()),
            0..=MAX_LINES_PER_CYCLE,
        ),
        // 현실적 exit code 범위 — detector 는 임의 i32 를 파싱할 수 있지만
        // 셸 관습 (0 / 1 / 2 / 127 등) 범위와 edge case (0 / 255) 모두 포함.
        -5i32..=255,
    )
        .prop_map(|(with_a, with_b, cmd_text, lines, exit_code)| {
            let mut bytes: Vec<u8> = Vec::new();

            // (1) optional A marker — 이 시점까지 축적된 출력이 없으면 detector
            //     는 무시하므로 cycle 시작에 두는 것은 안전하다.
            if with_a {
                bytes.extend_from_slice(b"\x1b]133;A\x07");
            }

            // (2) optional B marker — command 입력 시작, detector 는 상태
            //     전이만 하므로 역시 안전하다.
            if with_b {
                bytes.extend_from_slice(b"\x1b]133;B\x07");
            }

            // (3) C;cmd=<hex> — command 실행 시작. hex 인코딩.
            bytes.extend_from_slice(b"\x1b]133;C;cmd=");
            for b in cmd_text.as_bytes() {
                bytes.extend_from_slice(format!("{:02x}", b).as_bytes());
            }
            bytes.push(0x07); // BEL 종결

            // (4) 출력 라인 — 각 줄에 선행/후행 SGR noise 를 선택적으로 붙인다.
            for (text, pre, post) in &lines {
                bytes.extend_from_slice(pre);
                bytes.extend_from_slice(text.as_bytes());
                bytes.extend_from_slice(post);
                bytes.push(b'\n');
            }

            // (5) D;<exit_code> — 완료.
            bytes.extend_from_slice(format!("\x1b]133;D;{}\x07", exit_code).as_bytes());

            bytes
        })
}

/// 1..=MAX_CYCLES 개의 명령 cycle 을 이어 붙인 완전한 PTY byte stream.
fn arb_pty_byte_stream() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(arb_command_cycle(), 1..=MAX_CYCLES).prop_map(|cycles| {
        let mut all = Vec::new();
        for c in cycles {
            all.extend_from_slice(&c);
        }
        all
    })
}

/// (A) local 파이프라인 — `session_runtime::output_handle` 의 local 경로와
/// 정확히 같은 순서/컴포넌트 조합이다. `SessionProcessorPool::feed` 와 달리
/// 반환 record 에 `capture_mode` 를 명시 설정하지 않으므로 `Default`
/// (`CaptureMode::Pty`) 가 유지된다 — central 경로와 일치한다.
fn local_pipeline(bytes: &[u8]) -> Vec<CommandRecord> {
    let mut processor = OutputProcessor::new();
    let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
        marker_sequence: "osc133".to_string(),
    });
    let output = processor.process(bytes);

    let mut records = Vec::new();

    // (1) OSC 133 마커를 먼저 feed.
    for marker in &output.osc133_markers {
        if let Some(r) = detector.feed_line(marker) {
            records.push(r);
        }
    }

    // (2) ANSI-stripped clean_text 의 라인들도 순서대로 feed.
    if let Some(ref text) = output.clean_text {
        for line in text.lines() {
            if let Some(r) = detector.feed_line(line) {
                records.push(r);
            }
        }
    }

    records
}

/// Projection — timestamp 와 id 는 비교에서 제외한다 (R16.3). 남은 필드는
/// `(command, exit_code, output_lines, capture_mode, capture_quality)` 5-튜플.
type ShadowKey = (
    Option<String>,
    i32,
    Vec<String>,
    CaptureMode,
    CaptureQuality,
);

fn project(r: &CommandRecord) -> ShadowKey {
    (
        r.command.clone(),
        r.exit_code,
        r.output_lines.clone(),
        r.capture_mode,
        r.capture_quality,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Validates: Requirements R5.10, R5.11, R16.1, R16.2, R16.3, R16.4**
    ///
    /// 동일한 byte 시퀀스를 두 파이프라인에 투입했을 때 5-튜플 기준 record
    /// 시퀀스가 동일해야 한다.
    #[test]
    fn prop_shadow_equivalence_local_vs_aicd(bytes in arb_pty_byte_stream()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime");

        let outcome: Result<(), TestCaseError> = rt.block_on(async {
            // (A) local 파이프라인.
            let local_records = local_pipeline(&bytes);

            // (B) central 파이프라인 via SessionProcessorPool.
            let pool = SessionProcessorPool::new();
            pool.open("shadow-session")
                .await
                .expect("open session_id once");
            let central_records = pool.feed("shadow-session", &bytes).await;

            // 5-튜플 projection 비교.
            let local_keys: Vec<ShadowKey> = local_records.iter().map(project).collect();
            let central_keys: Vec<ShadowKey> = central_records.iter().map(project).collect();

            prop_assert_eq!(
                local_keys.len(),
                central_keys.len(),
                "shadow: record count mismatch (local={}, central={})",
                local_records.len(),
                central_records.len()
            );

            prop_assert_eq!(
                local_keys,
                central_keys,
                "shadow: 5-tuple projection mismatch between local and central pipelines"
            );

            Ok(())
        });
        outcome?;
    }
}
