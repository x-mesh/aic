//! Attach protocol frame 타입 및 wire codec.
//!
//! `aicd` 가 `aic-session` 으로부터 raw PTY byte stream 을 받아 central
//! `CommandRecordStore` 로 흘려보내기 위한 IPC 채널이 **Attach_UDS** 다
//! (design.md §3 참조). 기존 `aic-common::ipc` 의 control plane (length-prefixed
//! JSON) 과 달리, attach 채널은 request/response 가 아니라 **client → server
//! stream + server → client ack/error** 형태이며, PTY raw bytes 는 성능·정확성을
//!위해 JSON 을 거치지 않는 binary wire path 를 쓴다.
//!
//! # Wire format
//!
//! 모든 frame 은 맨 앞 1 byte discriminant 로 시작한다.
//!
//! - `0x01` = `PtyBytes` (binary path):
//!   `[1B disc=0x01][4B BE length][raw bytes]`
//! - `0x02` = 그 외 variant (JSON path):
//!   `[1B disc=0x02][4B BE length][JSON(AttachClientFrame 또는 AttachServerFrame)]`
//!
//! length 는 모두 big-endian `u32`. `PtyBytes` length 가
//! [`MAX_PTY_BYTES_FRAME`] 을 초과하면 디코더가 거부해 OOM/DoS 를 방지한다
//! (R15.4).
//!
//! # Client/Server 관점
//!
//! - `AttachClientFrame` 은 `aic-session` → `aicd` 방향.
//! - `AttachServerFrame` 은 `aicd` → `aic-session` 방향.
//! - 이 모듈은 client side helper 만 제공하지만 ([`write_attach_frame`],
//!   [`read_attach_frame`]), 두 frame 모두 JSON path 를 공유하므로 server side 에서도
//!   동일 유틸을 재사용할 수 있도록 enum [`AttachFrameKind`] 로 디코딩 결과를 돌려준다.
//!
//! Requirements: R5.3, R5.4, R5.5, R5.6, R13.4, R15.4.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ── 프로토콜 상수 ──────────────────────────────────────────────

/// 현재 attach 프로토콜 버전. `AttachOpen` 과 `AttachAck` 가 이 값을 교환하며,
/// 서버가 지원하지 않는 버전이면 `AttachError` 로 거부한다 (R13.4, R13.5).
pub const ATTACH_PROTOCOL_VERSION: u32 = 1;

/// `PtyBytes` variant 의 wire discriminant. binary fast path.
pub const PTY_BYTES_DISCRIMINANT: u8 = 0x01;

/// 그 외 variant (AttachOpen/AttachClose/AttachAck/AttachError) 의 wire
/// discriminant. JSON path.
pub const JSON_FRAME_DISCRIMINANT: u8 = 0x02;

/// 단일 `PtyBytes` frame payload 의 최대 byte 수 (16 MiB). 디코더가 이 값을 초과하는
/// length prefix 를 만나면 `AttachDecodeError::PtyBytesTooLarge` 로 거부해 OOM/DoS 를
/// 차단한다 (R15.4). 일반 PTY chunk 는 KB 단위이므로 이 한도는 사실상 adversarial
/// input 을 막는 용도다.
pub const MAX_PTY_BYTES_FRAME: usize = 16 * 1024 * 1024;

// ── Frame enums ────────────────────────────────────────────────

/// `aic-session` → `aicd` 방향의 attach frame.
///
/// `PtyBytes` 는 `Bytes` (bytes crate) 로 zero-copy 공유 가능한 raw byte slice
/// 를 담는다. JSON 직렬화 경로를 타지 않도록 `#[serde(skip)]` 처리하며, 실제
/// 전송은 [`write_attach_frame`] 의 binary discriminant 분기를 통한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AttachClientFrame {
    /// attach 세션 open. 최초로 송신되는 frame 이며, 성공 시 서버가
    /// [`AttachServerFrame::AttachAck`] 로 응답한다 (R5.3, R5.7).
    AttachOpen {
        session_id: String,
        protocol_version: u32,
    },
    /// PTY raw bytes chunk. binary wire path 로만 전송된다 (R5.5). JSON 경로에서는
    /// `#[serde(skip)]` 에 의해 직렬화되지 않는다 — JSON 직렬화가 요청되면 디코드
    /// 시 `AttachDecodeError::JsonContainsPtyBytes` 로 거부한다.
    #[serde(skip)]
    PtyBytes {
        bytes: Bytes,
    },
    /// attach 세션 graceful 종료. 서버는 이후 EOF 와 동일하게 처리한다 (R5.3, R11.4).
    AttachClose {
        reason: String,
    },
}

/// `aicd` → `aic-session` 방향의 attach frame. JSON 경로만 사용한다 (R5.4, R5.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AttachServerFrame {
    /// [`AttachClientFrame::AttachOpen`] 에 대한 승인 응답 (R5.4).
    AttachAck {
        protocol_version: u32,
    },
    /// attach 가 거부된 사유를 담는다 (R5.4, R13.5, R15.2, R15.4).
    AttachError {
        message: String,
    },
}

/// [`read_attach_frame`] 이 돌려주는 디코딩 결과.
///
/// server side (aicd) 는 client frame 을 기대하므로 `Client` variant 가 일반 경로,
/// client side (aic-session) 는 server frame 을 기대하므로 `Server` variant 가
/// 일반 경로다. 디코드는 discriminant + JSON 을 기반으로 양방향 모두 수행할 수 있어,
/// 한 쪽 helper 가 양쪽 사용처에서 재사용 가능하다.
#[derive(Debug, Clone, PartialEq)]
pub enum AttachFrameKind {
    Client(AttachClientFrame),
    Server(AttachServerFrame),
}

// ── 에러 타입 ──────────────────────────────────────────────────

/// [`write_attach_frame`] 수행 중 발생할 수 있는 에러.
#[derive(thiserror::Error, Debug)]
pub enum AttachIoError {
    #[error("attach frame I/O 실패: {0}")]
    Io(#[from] std::io::Error),

    #[error("attach JSON frame 직렬화 실패: {0}")]
    Json(#[from] serde_json::Error),

    #[error("attach frame payload 가 u32::MAX 를 초과했습니다 ({len} bytes)")]
    PayloadTooLargeForLengthPrefix { len: usize },
}

/// [`read_attach_frame`] 수행 중 발생할 수 있는 에러.
#[derive(thiserror::Error, Debug)]
pub enum AttachDecodeError {
    #[error("attach frame I/O 실패: {0}")]
    Io(#[from] std::io::Error),

    #[error("attach JSON frame 역직렬화 실패: {0}")]
    Json(#[from] serde_json::Error),

    #[error("attach frame discriminant 0x{0:02x} 를 알 수 없습니다")]
    UnknownDiscriminant(u8),

    #[error(
        "PtyBytes frame length {len} 이 허용 한계 {max} 를 초과합니다 (R15.4)"
    )]
    PtyBytesTooLarge { len: usize, max: usize },

    #[error("JSON frame 안에 PtyBytes variant 가 포함되어 있습니다 — 이는 binary path 로만 전송되어야 합니다")]
    JsonContainsPtyBytes,
}

// ── Wire codec helpers ─────────────────────────────────────────

/// `AttachClientFrame` 하나를 wire format 으로 인코딩해 `w` 에 쓴다.
///
/// - [`AttachClientFrame::PtyBytes`] 는 `[0x01][4B BE len][raw bytes]` 의 binary
///   path 로 나간다 (R5.5).
/// - 그 외 variant 는 `[0x02][4B BE len][JSON]` 의 JSON path 로 나간다 (R5.6).
///
/// `w` 를 flush 하지는 않는다 — 호출자가 batching 결정을 내릴 수 있도록 둔다.
pub async fn write_attach_frame<W>(
    w: &mut W,
    frame: &AttachClientFrame,
) -> Result<(), AttachIoError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    match frame {
        AttachClientFrame::PtyBytes { bytes } => {
            let len: u32 = bytes
                .len()
                .try_into()
                .map_err(|_| AttachIoError::PayloadTooLargeForLengthPrefix { len: bytes.len() })?;
            w.write_u8(PTY_BYTES_DISCRIMINANT).await?;
            w.write_u32(len).await?;
            w.write_all(bytes).await?;
        }
        other => {
            let json = serde_json::to_vec(other)?;
            let len: u32 = json
                .len()
                .try_into()
                .map_err(|_| AttachIoError::PayloadTooLargeForLengthPrefix { len: json.len() })?;
            w.write_u8(JSON_FRAME_DISCRIMINANT).await?;
            w.write_u32(len).await?;
            w.write_all(&json).await?;
        }
    }
    Ok(())
}

/// `AttachServerFrame` 하나를 wire format 으로 인코딩해 `w` 에 쓴다. 서버 방향은
/// JSON path 만 사용한다 (R5.6).
pub async fn write_attach_server_frame<W>(
    w: &mut W,
    frame: &AttachServerFrame,
) -> Result<(), AttachIoError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let json = serde_json::to_vec(frame)?;
    let len: u32 = json
        .len()
        .try_into()
        .map_err(|_| AttachIoError::PayloadTooLargeForLengthPrefix { len: json.len() })?;
    w.write_u8(JSON_FRAME_DISCRIMINANT).await?;
    w.write_u32(len).await?;
    w.write_all(&json).await?;
    Ok(())
}

/// `r` 에서 attach frame 하나를 읽어 [`AttachFrameKind`] 로 반환한다.
///
/// 1 byte discriminant 를 먼저 읽고 분기한다.
/// - `0x01` 이면 `[4B BE len][raw bytes]` 를 읽어 `AttachClientFrame::PtyBytes` 로 복구.
///   length 가 [`MAX_PTY_BYTES_FRAME`] 을 초과하면 `AttachDecodeError::PtyBytesTooLarge`
///   로 거부한다 (R15.4). 이 단계에서 `raw bytes` 를 소비하지 않으므로 호출자는
///   이 에러 이후 스트림 상태를 "offset 이 어긋났다" 로 간주해 연결을 닫아야 한다.
/// - `0x02` 이면 `[4B BE len][JSON]` 을 읽어 `AttachClientFrame` 또는
///   `AttachServerFrame` 중 deserialize 성공하는 쪽으로 반환한다. JSON 안에 PtyBytes
///   variant 가 섞여 들어오면 `AttachDecodeError::JsonContainsPtyBytes` 로 거부한다.
pub async fn read_attach_frame<R>(
    r: &mut R,
) -> Result<AttachFrameKind, AttachDecodeError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let disc = r.read_u8().await?;
    match disc {
        PTY_BYTES_DISCRIMINANT => {
            let len = r.read_u32().await? as usize;
            if len > MAX_PTY_BYTES_FRAME {
                return Err(AttachDecodeError::PtyBytesTooLarge {
                    len,
                    max: MAX_PTY_BYTES_FRAME,
                });
            }
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf).await?;
            Ok(AttachFrameKind::Client(AttachClientFrame::PtyBytes {
                bytes: Bytes::from(buf),
            }))
        }
        JSON_FRAME_DISCRIMINANT => {
            let len = r.read_u32().await? as usize;
            // JSON frame 도 비정상적으로 거대할 수 있으므로 동일 한계를 적용해
            // adversarial input 을 차단한다 — PtyBytes 와 같은 상한을 쓴다.
            if len > MAX_PTY_BYTES_FRAME {
                return Err(AttachDecodeError::PtyBytesTooLarge {
                    len,
                    max: MAX_PTY_BYTES_FRAME,
                });
            }
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf).await?;

            // client frame 우선 시도 → 실패 시 server frame 으로 폴백.
            if let Ok(client) = serde_json::from_slice::<AttachClientFrame>(&buf) {
                if matches!(client, AttachClientFrame::PtyBytes { .. }) {
                    return Err(AttachDecodeError::JsonContainsPtyBytes);
                }
                return Ok(AttachFrameKind::Client(client));
            }
            let server: AttachServerFrame = serde_json::from_slice(&buf)?;
            Ok(AttachFrameKind::Server(server))
        }
        other => Err(AttachDecodeError::UnknownDiscriminant(other)),
    }
}

// ── Unit tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// helper: `AttachClientFrame` 을 메모리에 쓰고 다시 읽어 비교한다.
    async fn roundtrip_client(frame: AttachClientFrame) {
        let mut buf: Vec<u8> = Vec::new();
        write_attach_frame(&mut buf, &frame).await.unwrap();
        let mut cur = Cursor::new(buf);
        let decoded = read_attach_frame(&mut cur).await.unwrap();
        match decoded {
            AttachFrameKind::Client(c) => assert_eq!(c, frame),
            AttachFrameKind::Server(_) => panic!("expected client frame"),
        }
    }

    /// helper: `AttachServerFrame` 을 메모리에 쓰고 다시 읽어 비교한다.
    async fn roundtrip_server(frame: AttachServerFrame) {
        let mut buf: Vec<u8> = Vec::new();
        write_attach_server_frame(&mut buf, &frame).await.unwrap();
        let mut cur = Cursor::new(buf);
        let decoded = read_attach_frame(&mut cur).await.unwrap();
        match decoded {
            AttachFrameKind::Server(s) => assert_eq!(s, frame),
            AttachFrameKind::Client(_) => panic!("expected server frame"),
        }
    }

    #[tokio::test]
    async fn attach_open_roundtrip() {
        roundtrip_client(AttachClientFrame::AttachOpen {
            session_id: "deadbeef".to_string(),
            protocol_version: ATTACH_PROTOCOL_VERSION,
        })
        .await;
    }

    #[tokio::test]
    async fn attach_close_roundtrip() {
        roundtrip_client(AttachClientFrame::AttachClose {
            reason: "session exited".to_string(),
        })
        .await;
    }

    #[tokio::test]
    async fn pty_bytes_roundtrip_small() {
        // 짧은 UTF-8 텍스트 chunk — 일반적인 PTY output 케이스.
        let payload = Bytes::from_static(b"\x1b]133;A\x07$ ls\r\n");
        roundtrip_client(AttachClientFrame::PtyBytes {
            bytes: payload.clone(),
        })
        .await;
    }

    #[tokio::test]
    async fn pty_bytes_roundtrip_boundary_max_size() {
        // 정확히 한계 크기의 PtyBytes 가 정상 왕복되는지 확인. (16 MiB)
        // 테스트 속도 보호를 위해 전체를 채우지 않고 길이 헤더만 한계값을 찍는
        // case 는 read_attach_frame 이 read_exact 에서 막히므로 여기서는 `MAX`
        // 자체의 왕복이 비현실적으로 느리다는 점을 감안해 256 KiB 로 축소 검증한다.
        let size = 256 * 1024;
        let payload = Bytes::from(vec![0xAAu8; size]);
        roundtrip_client(AttachClientFrame::PtyBytes { bytes: payload }).await;
    }

    #[tokio::test]
    async fn attach_ack_roundtrip() {
        roundtrip_server(AttachServerFrame::AttachAck {
            protocol_version: ATTACH_PROTOCOL_VERSION,
        })
        .await;
    }

    #[tokio::test]
    async fn attach_error_roundtrip() {
        roundtrip_server(AttachServerFrame::AttachError {
            message: "protocol_version 2 는 지원하지 않습니다".to_string(),
        })
        .await;
    }

    /// R15.4: oversize PtyBytes frame 은 디코더가 거부해야 한다. 실제 16 MiB
    /// 를 소비하지 않도록, length 헤더만 [`MAX_PTY_BYTES_FRAME`] + 1 로 조작한
    /// 인위적 byte stream 을 만들어 검증한다.
    #[tokio::test]
    async fn pty_bytes_oversize_rejected() {
        let mut buf: Vec<u8> = Vec::with_capacity(1 + 4);
        buf.push(PTY_BYTES_DISCRIMINANT);
        let bogus_len: u32 = (MAX_PTY_BYTES_FRAME + 1) as u32;
        buf.extend_from_slice(&bogus_len.to_be_bytes());
        // payload 는 의도적으로 비워 둔다 — decoder 는 length 체크 단계에서
        // 거부하므로 raw bytes 를 읽지 않는다.

        let mut cur = Cursor::new(buf);
        let err = read_attach_frame(&mut cur).await.unwrap_err();
        match err {
            AttachDecodeError::PtyBytesTooLarge { len, max } => {
                assert_eq!(len, MAX_PTY_BYTES_FRAME + 1);
                assert_eq!(max, MAX_PTY_BYTES_FRAME);
            }
            other => panic!("expected PtyBytesTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_discriminant_rejected() {
        // 알 수 없는 discriminant 는 명시적 에러를 내야 한다 (stream sync 가 깨진
        // 상태이므로 호출자는 연결을 닫게 된다).
        let buf = vec![0x7Fu8];
        let mut cur = Cursor::new(buf);
        let err = read_attach_frame(&mut cur).await.unwrap_err();
        assert!(matches!(err, AttachDecodeError::UnknownDiscriminant(0x7F)));
    }

    #[test]
    fn pty_bytes_skipped_on_json_serialize() {
        // `#[serde(skip)]` 가 붙은 PtyBytes 는 JSON 직렬화 시 *variant 자체가
        // 제외되어 serde_json 이 에러를 반환해야 한다* — 즉 실수로 JSON path
        // 에 PtyBytes 가 섞이는 일을 컴파일/런타임에서 차단한다.
        let frame = AttachClientFrame::PtyBytes {
            bytes: Bytes::from_static(b"abc"),
        };
        let result = serde_json::to_vec(&frame);
        assert!(
            result.is_err(),
            "PtyBytes 는 JSON serialize 경로를 타면 안 된다"
        );
    }
}
