//! Phase 3.2 read path 통합 테스트 — Task 2.3.
//!
//! Requirements: R4.1, R4.2, R4.3, R4.5
//!
//! 본 테스트는 실제 `ControlServer`(aicd 제어 소켓)와 `UdsServer`(세션 로컬 소켓)를
//! tempdir 위의 UDS 로 기동하고, 그 위에서 Phase 3.2 read path cascade 동작을 검증한다.
//!
//! - 시나리오 A: `Central_Store_Flag=true` + aicd 기동 + 세션 record push →
//!   cascade 의 (1) aicd 경로로 `last / recent / find` 모두 성공.
//! - 시나리오 B: aicd 기동됐지만 aicd store 가 비어 있음 → `last` 는 (1) aicd Error
//!   응답 뒤 (2) session socket 으로 폴백해 record 획득. `recent` / `find` 는 aicd 의
//!   빈 Vec 성공 응답이 우선하므로 폴백하지 않는다 (R4.3 "cascade only on Error").
//! - 시나리오 C: aicd 미기동 + `Central_Store_Flag=true` → aicd 연결 실패 후 (2)
//!   session socket 폴백만 동작. 로그 내용은 검증하지 않고(깨지기 쉬움) behaviour
//!   — 즉 session record 가 반환되는지 — 만 본다.
//! - 시나리오 D: `Central_Store_Flag=false` → aicd 는 건드리지 않고 (2) session
//!   socket 만 사용해 기존 흐름 유지 (R4.5).
//!
//! 주의: 본 테스트는 `aic-client` 의 `ReadCascade` 를 **직접 쓰지 않는다**. Client 쪽
//! cascade 로직을 의존하면 테스트가 implementation coupling 을 재검증할 뿐이라,
//! 여기서는 동일한 wire protocol 흐름을 최소한 로컬로 재구현해 aicd/session UDS
//! 의 end-to-end 행동을 직접 확인한다.
//!
//! ## Phase 3.5 feature gate (Task 5.1 / 5.2 / 5.3)
//!
//! Phase 3.5 에서는 세션 로컬 data plane 과 session socket fallback 이 모두 제거되어
//! 본 시나리오들이 의존하는 "aicd → session socket → shell history" cascade 의 (2)
//! 단계가 사라진다 (R7.1, R7.2). 따라서 본 통합 테스트 파일 전체를
//! `#![cfg(not(feature = "phase-3_5"))]` 로 gate 한다. Phase 3.5 전용 cascade 검증은
//! `aic-client` 의 `uds_client` unit test 에서 별도로 수행한다.
#![cfg(not(feature = "phase-3_5"))]

use aic_common::{
    encode_frame, CaptureMode, CaptureQuality, CommandRecord, IpcRequest, IpcResponse,
};
use aic_server::command_record_store::CommandRecordStore;
use aic_server::control_server::{ControlContext, ControlServer};
use aic_server::metrics::AicdMetrics;
use aic_server::ring_buffer::RingBuffer;
use aic_server::session_registry::SessionRegistry;
use aic_server::uds_server::UdsServer;

use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;

// ─────────────────────────────────────────────────────────────────
// 공용 wire 헬퍼 — length-prefixed JSON frame 한 번 보내고 받는다.
// ─────────────────────────────────────────────────────────────────

/// 단발성 IPC: connect → write → read → close. 연결 실패는 `None` 으로 표현한다.
async fn send_request_opt(sock: &Path, req: &IpcRequest) -> Option<IpcResponse> {
    let mut stream = UnixStream::connect(sock).await.ok()?;
    let body = serde_json::to_vec(req).ok()?;
    let frame = encode_frame(&body);
    stream.write_all(&frame).await.ok()?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.ok()?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.ok()?;
    serde_json::from_slice(&payload).ok()
}

/// 연결이 되어 있어야 하는 경로(서버가 살아 있음 가정)에서 보내는 헬퍼. 실패 시 panic.
async fn send_request(sock: &Path, req: IpcRequest) -> IpcResponse {
    send_request_opt(sock, &req)
        .await
        .expect("IPC wire 실패 — 서버가 기동되어 있어야 한다")
}

// ─────────────────────────────────────────────────────────────────
// 최소한의 read cascade 재구현 — `aic-client` 의 `ReadCascade` 와 같은 규약.
//
// - flag=true: (1) aicd `*ForSession` → (2) session local socket.
// - flag=false: (2) 만 사용 (R4.5).
// - last 는 Error / connection-failure 모두 폴백 (R4.3).
// - recent / find 는 aicd 의 성공 응답(빈 Vec 포함) 이면 폴백하지 않는다.
// ─────────────────────────────────────────────────────────────────

struct LocalCascade {
    session_id: String,
    flag: bool,
    aicd_sock: PathBuf,
    session_sock: PathBuf,
}

impl LocalCascade {
    fn new(session_id: &str, flag: bool, aicd_sock: PathBuf, session_sock: PathBuf) -> Self {
        Self {
            session_id: session_id.to_string(),
            flag,
            aicd_sock,
            session_sock,
        }
    }

    /// 직전 command record 1건. `Some(record)` 또는 `None`(두 경로 모두 record 없음).
    async fn get_last_command(&self) -> Option<CommandRecord> {
        if self.flag {
            let resp = send_request_opt(
                &self.aicd_sock,
                &IpcRequest::GetLastCommandForSession {
                    id: self.session_id.clone(),
                },
            )
            .await;
            // connection 실패(None) 또는 Error/기타 응답 → (2) 로 폴백 (R4.3)
            if let Some(IpcResponse::CommandData(r)) = resp {
                return Some(r);
            }
        }
        let resp = send_request_opt(&self.session_sock, &IpcRequest::GetLastCommand).await;
        match resp {
            Some(IpcResponse::CommandData(r)) => Some(r),
            _ => None,
        }
    }

    /// 최근 N 개 record. aicd 의 성공 응답(빈 Vec 포함) 은 그대로 반환.
    /// aicd 연결/파싱 실패 시 session socket 으로 폴백.
    async fn get_recent_commands(&self, count: usize) -> Vec<CommandRecord> {
        if self.flag {
            let resp = send_request_opt(
                &self.aicd_sock,
                &IpcRequest::GetRecentCommandsForSession {
                    id: self.session_id.clone(),
                    count,
                },
            )
            .await;
            if let Some(IpcResponse::CommandRecords(records)) = resp {
                return records;
            }
            // 연결 실패 또는 Error → 세션 폴백
        }
        match send_request_opt(&self.session_sock, &IpcRequest::GetRecentCommands { count }).await {
            Some(IpcResponse::CommandRecords(records)) => records,
            _ => Vec::new(),
        }
    }

    /// record id prefix 매칭. aicd 의 빈 Vec 성공 응답은 그대로 반환.
    async fn find_record_by_prefix(&self, prefix: &str) -> Vec<CommandRecord> {
        if self.flag {
            let resp = send_request_opt(
                &self.aicd_sock,
                &IpcRequest::FindRecordByPrefixForSession {
                    id: self.session_id.clone(),
                    prefix: prefix.to_string(),
                },
            )
            .await;
            if let Some(IpcResponse::CommandRecords(records)) = resp {
                return records;
            }
        }
        match send_request_opt(
            &self.session_sock,
            &IpcRequest::FindRecordByPrefix {
                prefix: prefix.to_string(),
            },
        )
        .await
        {
            Some(IpcResponse::CommandRecords(records)) => records,
            _ => Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// 서버 기동 헬퍼 — aicd ControlServer + 세션 UdsServer.
// ─────────────────────────────────────────────────────────────────

struct AicdHarness {
    sock_path: PathBuf,
    ctx: ControlContext,
    handle: JoinHandle<()>,
    _dir: TempDir,
}

impl AicdHarness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aicd.sock");
        let server = ControlServer::bind(&sock_path).await.unwrap();
        let ctx = ControlContext {
            shutdown: watch::channel(false).0,
            registry: SessionRegistry::new(),
            record_store: CommandRecordStore::new(),
            registry_path: None,
            metrics: Arc::new(AicdMetrics::new()),
            agent_bus: aic_server::agent_event_bus::AgentEventBus::new(),
            exporter_health: None,
        };
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move { server.serve(ctx_clone).await });
        // accept 루프가 listen 상태로 진입할 수 있도록 한 tick 양보.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        Self {
            sock_path,
            ctx,
            handle,
            _dir: dir,
        }
    }
}

impl Drop for AicdHarness {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

struct SessionHarness {
    sock_path: PathBuf,
    buffer: Arc<RwLock<RingBuffer>>,
    handle: JoinHandle<()>,
    _dir: TempDir,
}

impl SessionHarness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("session.sock");
        let server = UdsServer::bind(&sock_path).await.unwrap();
        let buffer = Arc::new(RwLock::new(RingBuffer::new(200)));
        let buf_clone = Arc::clone(&buffer);
        let handle = tokio::spawn(async move { server.serve(buf_clone).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        Self {
            sock_path,
            buffer,
            handle,
            _dir: dir,
        }
    }

    async fn push(&self, record: CommandRecord) {
        self.buffer.write().await.push(record);
    }
}

impl Drop for SessionHarness {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ─────────────────────────────────────────────────────────────────
// record 빌더
// ─────────────────────────────────────────────────────────────────

fn pty_record(id: &str, command: &str, exit_code: i32) -> CommandRecord {
    CommandRecord {
        id: id.to_string(),
        command: Some(command.to_string()),
        exit_code,
        output_lines: vec![format!("out-{command}")],
        timestamp: Utc::now(),
        capture_mode: CaptureMode::Pty,
        capture_quality: CaptureQuality::FullOutput,
        output_metadata: None,
        cwd: None,
        duration_ms: None,
    }
}

/// aicd CommandRecordStore 에 record 를 직접 push 한다 (wire 를 통해).
/// 실제 aic-session 이 수행하는 경로(`register_record`)와 동일한 protocol.
async fn push_record_to_aicd(aicd_sock: &Path, session_id: &str, record: CommandRecord) {
    let resp = send_request(
        aicd_sock,
        IpcRequest::RegisterRecordForSession {
            session_id: session_id.to_string(),
            record,
        },
    )
    .await;
    assert_eq!(
        resp,
        IpcResponse::Pong,
        "RegisterRecordForSession 가 Pong 을 돌려주지 않음"
    );
}

/// 존재하지 않는 UDS 경로를 만들어 aicd down 상황을 모사한다.
/// TempDir 이 drop 되면 디렉토리 자체가 없어지므로 해당 경로는 확실히 연결 불가.
fn nonexistent_aicd_sock() -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("aicd.sock");
    drop(dir);
    path
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 A — aicd up + flag=true + record in aicd
//   ⇒ cascade 가 aicd 경로로 last / recent / find 성공.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_a_flag_on_aicd_has_record_cascade_uses_aicd() {
    let aicd = AicdHarness::start().await;
    let session = SessionHarness::start().await;

    // aicd store 에는 두 개의 record 를 넣고, session socket 에는 같은 session_id
    // 에 다른 record 를 넣어 두어 cascade 가 실수로 session 을 쓰면 차이가 드러나게 한다.
    push_record_to_aicd(&aicd.sock_path, "sess-a", pty_record("aaaa0001", "ls", 0)).await;
    push_record_to_aicd(&aicd.sock_path, "sess-a", pty_record("aaaa0002", "pwd", 0)).await;

    session
        .push(pty_record("ffff9999", "session-should-not-be-used", 99))
        .await;

    let cascade = LocalCascade::new(
        "sess-a",
        true,
        aicd.sock_path.clone(),
        session.sock_path.clone(),
    );

    // last
    let last = cascade.get_last_command().await.expect("aicd 경로로 Some");
    assert_eq!(last.id, "aaaa0002", "aicd 의 최신 record 가 와야 한다");
    assert_eq!(last.command.as_deref(), Some("pwd"));

    // recent
    let recent = cascade.get_recent_commands(10).await;
    assert_eq!(recent.len(), 2, "aicd 의 record 2건이 와야 한다");
    assert_eq!(recent[0].id, "aaaa0001");
    assert_eq!(recent[1].id, "aaaa0002");

    // find_by_prefix
    let matched = cascade.find_record_by_prefix("aaaa").await;
    assert_eq!(matched.len(), 2, "aicd 에서 prefix 매칭 2건");
    assert!(matched.iter().all(|r| r.id.starts_with("aaaa")));

    // aicd 의 central_store_push_total 이 RegisterRecordForSession 호출 횟수만큼 증가했는지.
    // (push 2건 × 1 = 2) — 다른 경로에서 증가하지 않음을 확인.
    assert_eq!(
        aicd.ctx.metrics.central_store_push_total(),
        2,
        "aicd metric 이 기대치와 다르다 (Task 1.5 라우팅과의 consistency)"
    );
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 B — aicd up + flag=true + aicd store 비어 있음 + session 에 record
//   ⇒ last 는 aicd Error 뒤 session 으로 폴백 (R4.3). recent / find 는 aicd 의
//     빈 Vec 성공 응답이 우선이므로 폴백하지 않는다.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_b_flag_on_aicd_empty_session_fallback_for_last() {
    let aicd = AicdHarness::start().await;
    let session = SessionHarness::start().await;

    // aicd 에는 push 하지 않는다. session 에만 record 를 적재.
    let expected = pty_record("bbbb1111", "echo fallback", 0);
    session.push(expected.clone()).await;

    let cascade = LocalCascade::new(
        "sess-b",
        true,
        aicd.sock_path.clone(),
        session.sock_path.clone(),
    );

    // last: aicd → Error("hook metadata record를 찾을 수 없습니다") → session 폴백 → record 획득
    let last = cascade
        .get_last_command()
        .await
        .expect("session 폴백으로 Some");
    assert_eq!(
        last.command.as_deref(),
        Some("echo fallback"),
        "session socket 의 record 가 와야 한다"
    );

    // recent: aicd 가 빈 Vec 로 성공 응답 → cascade 는 session 까지 내려가지 않는다.
    // 이 동작은 R4.3 의 "cascade only on Error" 시맨틱을 따른다 (ReadCascade 설계).
    let recent = cascade.get_recent_commands(10).await;
    assert!(
        recent.is_empty(),
        "aicd 의 빈 Vec 는 성공 응답이라 session 으로 폴백되지 않아야 한다 — 실제: {}건",
        recent.len()
    );

    // find_by_prefix 도 같은 시맨틱.
    let matched = cascade.find_record_by_prefix("bbbb").await;
    assert!(
        matched.is_empty(),
        "aicd 의 빈 Vec 는 성공 응답이라 session 으로 폴백되지 않아야 한다"
    );
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 C — aicd down + flag=true + session 에 record
//   ⇒ aicd 연결 실패 후 session socket 폴백만 동작.
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_c_flag_on_aicd_down_falls_back_to_session() {
    let aicd_sock = nonexistent_aicd_sock();
    let session = SessionHarness::start().await;

    let expected_last = pty_record("cccc0001", "first", 0);
    let expected_tail = pty_record("cccc0002", "second", 1);
    session.push(expected_last.clone()).await;
    session.push(expected_tail.clone()).await;

    let cascade = LocalCascade::new("sess-c", true, aicd_sock, session.sock_path.clone());

    // last: aicd 연결 실패 → session 폴백 → 가장 마지막 record.
    let last = cascade
        .get_last_command()
        .await
        .expect("session 폴백으로 Some");
    assert_eq!(last.command.as_deref(), Some("second"));

    // recent: aicd 연결 실패 → session 폴백.
    let recent = cascade.get_recent_commands(10).await;
    assert_eq!(recent.len(), 2, "session 의 record 2건");
    assert_eq!(recent[0].command.as_deref(), Some("first"));
    assert_eq!(recent[1].command.as_deref(), Some("second"));

    // find_by_prefix: aicd 연결 실패 → session 폴백.
    let matched = cascade.find_record_by_prefix("cccc").await;
    assert_eq!(matched.len(), 2);
    assert!(matched.iter().all(|r| r.id.starts_with("cccc")));
}

// ─────────────────────────────────────────────────────────────────
// 시나리오 D — flag=false + aicd 에 record + session 에 별도 record
//   ⇒ aicd 는 건드리지 않고 session socket 만 사용 (R4.5).
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scenario_d_flag_off_uses_session_only() {
    let aicd = AicdHarness::start().await;
    let session = SessionHarness::start().await;

    // aicd 에 "잘못 선택하면 드러나는" record 를 넣고, session 에는 기대 record 를 넣는다.
    push_record_to_aicd(
        &aicd.sock_path,
        "sess-d",
        pty_record("aaaa9999", "aicd-should-be-skipped", 77),
    )
    .await;

    let expected = pty_record("dddd0001", "session-wins", 0);
    session.push(expected.clone()).await;

    let cascade = LocalCascade::new(
        "sess-d",
        false, // flag=false → aicd 경로 skip (R4.5)
        aicd.sock_path.clone(),
        session.sock_path.clone(),
    );

    // last: 오직 session 경로만 사용.
    let last = cascade
        .get_last_command()
        .await
        .expect("session 경로로 Some");
    assert_eq!(
        last.command.as_deref(),
        Some("session-wins"),
        "flag=false 에서는 session socket 의 record 가 와야 한다"
    );

    // recent / find 도 session 만.
    let recent = cascade.get_recent_commands(10).await;
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, "dddd0001");

    let matched = cascade.find_record_by_prefix("dddd").await;
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].id, "dddd0001");

    // aicd central store metric 은 push 에 의해 1 이 증가했을 뿐 read 는 없었다는 것을
    // 보장하기 위해, 그 이상의 상승은 관측되지 않아야 한다 (관측 가능한 것은 push 뿐).
    assert_eq!(aicd.ctx.metrics.central_store_push_total(), 1);
}
