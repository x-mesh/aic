//! Property test: Attach wire format round-trip
//!
//! **Boundary Property (보조): Attach frame round-trip** — `write_attach_frame`로
//! 인코드한 후 `read_attach_frame`으로 디코드하면 원본과 같아야 하며,
//! `PtyBytes.bytes.len() > MAX_PTY_BYTES_FRAME` 인 경우 디코드가 에러를 반환해야
//! 한다.
//!
//! 검증 대상:
//! - `write_attach_frame` (binary & JSON path 양쪽)
//! - `read_attach_frame` (binary & JSON path + oversize rejection)
//!
//! **Validates: Requirements R5.5, R5.6, R15.4**

use aic_common::attach::{
    read_attach_frame, write_attach_frame, AttachClientFrame, AttachDecodeError, AttachFrameKind,
    MAX_PTY_BYTES_FRAME, PTY_BYTES_DISCRIMINANT,
};
use bytes::Bytes;
use proptest::prelude::*;
use std::io::Cursor;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

// ── tokio runtime ──────────────────────────────────────────────
//
// proptest 본체는 sync API 이지만 `write_attach_frame` / `read_attach_frame` 는
// async 이므로, case 마다 tokio runtime 을 새로 만들지 않고 프로세스 전역 단일
// 런타임을 공유해 오버헤드를 줄인다. read/write 는 메모리 Vec/Cursor 기반이라
// multi-thread runtime 이 필요하지 않으므로 single-thread 로 충분하다.

fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio current_thread runtime")
    })
}

// ── Arbitrary strategies ───────────────────────────────────────
//
// roundtrip 검증에서 PtyBytes payload 상한은 256 cases × 최대 16 MiB 를 채우면
// 수 GB 할당이 발생한다. 현실적 PTY chunk size 를 감안해 0..=64 KiB 로 축소한다.
// oversize 분기는 payload 를 할당하지 않고 length header 만 조작하는 별도
// property (`prop_pty_bytes_oversize_rejected`) 에서 검증한다.

const ROUNDTRIP_PTY_MAX: usize = 64 * 1024;

fn arb_attach_open() -> impl Strategy<Value = AttachClientFrame> {
    // session_id 는 아이디 포맷 (16자 hex) 보다 넓게 잡아 wire codec 자체의
    // 일반성을 검증한다. protocol_version 도 임의 u32 값을 허용한다 (wire
    // 수준에서는 숫자 필드일 뿐이며 버전 협상은 상위 layer 책임).
    (".*", any::<u32>()).prop_map(|(session_id, protocol_version)| {
        AttachClientFrame::AttachOpen {
            session_id,
            protocol_version,
        }
    })
}

fn arb_pty_bytes() -> impl Strategy<Value = AttachClientFrame> {
    proptest::collection::vec(any::<u8>(), 0..=ROUNDTRIP_PTY_MAX).prop_map(|v| {
        AttachClientFrame::PtyBytes {
            bytes: Bytes::from(v),
        }
    })
}

fn arb_attach_close() -> impl Strategy<Value = AttachClientFrame> {
    any::<String>().prop_map(|reason| AttachClientFrame::AttachClose { reason })
}

fn arb_attach_client_frame() -> impl Strategy<Value = AttachClientFrame> {
    prop_oneof![arb_attach_open(), arb_pty_bytes(), arb_attach_close()]
}

// ── Property tests ─────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Validates: Requirements R5.5, R5.6**
    ///
    /// 임의의 `AttachClientFrame` (AttachOpen | PtyBytes | AttachClose) 을
    /// `write_attach_frame` 으로 메모리에 직렬화한 뒤 `read_attach_frame` 으로
    /// 다시 디코드하면 원본과 정확히 동일해야 한다. 이는 binary path (PtyBytes,
    /// discriminant 0x01) 와 JSON path (그 외, discriminant 0x02) 양쪽의
    /// wire format 불변식을 동시에 커버한다.
    #[test]
    fn prop_attach_client_frame_roundtrip(frame in arb_attach_client_frame()) {
        let mut buf: Vec<u8> = Vec::new();
        rt()
            .block_on(async { write_attach_frame(&mut buf, &frame).await })
            .expect("write_attach_frame must succeed for well-formed frames");

        let mut cursor = Cursor::new(buf);
        let decoded = rt()
            .block_on(async { read_attach_frame(&mut cursor).await })
            .expect("read_attach_frame must succeed for well-formed frames");

        match decoded {
            AttachFrameKind::Client(c) => prop_assert_eq!(c, frame),
            AttachFrameKind::Server(other) => {
                prop_assert!(
                    false,
                    "expected client frame, got server frame: {:?}",
                    other
                );
            }
        }
    }

    /// **Validates: Requirements R15.4**
    ///
    /// `PtyBytes` frame 의 length prefix 가 `MAX_PTY_BYTES_FRAME` (16 MiB) 를
    /// 초과할 때 디코더는 `AttachDecodeError::PtyBytesTooLarge` 로 거부해야 한다.
    ///
    /// 실제 16 MiB 초과 payload 를 proptest case 마다 할당하면 테스트가 비현실적으로
    /// 느려지므로, `[0x01][4B BE len_over_MAX]` 까지만 구성한 malformed byte stream
    /// 을 만들어 읽기 경로의 거부 동작을 검증한다. 이는 `write_attach_frame` 이
    /// 논리적으로 같은 헤더를 생성한다는 사실(쓰기 성공 → 읽기 실패)을 시뮬레이션한
    /// 것이다 (기존 unit test `pty_bytes_oversize_rejected` 와 동일 기법).
    #[test]
    fn prop_pty_bytes_oversize_rejected(
        bogus_len in (MAX_PTY_BYTES_FRAME as u32 + 1)..=u32::MAX,
    ) {
        let mut buf: Vec<u8> = Vec::with_capacity(1 + 4);
        buf.push(PTY_BYTES_DISCRIMINANT);
        buf.extend_from_slice(&bogus_len.to_be_bytes());
        // payload 바이트 자체는 쓰지 않는다 — decoder 가 length 검증 단계에서
        // 곧바로 거부해 raw body 를 읽지 않기 때문.

        let mut cursor = Cursor::new(buf);
        let err = rt()
            .block_on(async { read_attach_frame(&mut cursor).await })
            .expect_err("oversize PtyBytes frame must be rejected");

        match err {
            AttachDecodeError::PtyBytesTooLarge { len, max } => {
                prop_assert_eq!(len, bogus_len as usize);
                prop_assert_eq!(max, MAX_PTY_BYTES_FRAME);
            }
            other => prop_assert!(
                false,
                "expected PtyBytesTooLarge, got {:?}",
                other
            ),
        }
    }
}
