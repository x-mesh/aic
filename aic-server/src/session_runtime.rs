//! `aic-session` runtime orchestration.
//!
//! Binary `main.rs` is intentionally kept thin: CLI parsing, environment setup,
//! telemetry, and then this runtime.
//!
//! ## Phase 3.5 feature gate (Task 5.3, R7.1, R7.2, R20.1~20.3)
//!
//! `phase-3_5` feature 가 활성이면 세션 로컬 data plane (`RingBuffer` /
//! `OutputProcessor` / `CommandBoundaryDetector`) 를 **일절 생성하지 않는다**.
//! Local_Fallback on-demand 경로 (R9.6) 도 함께 제거되며, `AttachClient::connect`
//! 가 autostart 재시도까지 실패하면 `aic-session` 은 fatal error 로 즉시 종료한다.
//! 세션 로컬 socket (`session-{id}.sock`) 은 Ping/RegisterRecord(hook fallback)
//! 전용으로 유지된다 (R7.2). PTY relay / raw mode / SIGWINCH / registry heartbeat
//! 은 Phase 3.5 에서도 계속 `aic-session` 이 담당한다 (R20.3).

use crate::attach_client::AttachClient;
#[cfg(not(feature = "phase-3_5"))]
use crate::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use crate::lock::DaemonLock;
use crate::metrics::AttachMetrics;
#[cfg(not(feature = "phase-3_5"))]
use crate::output_processor::OutputProcessor;
use crate::pty_manager::{HookPolicy, PtyManager};
#[cfg(not(feature = "phase-3_5"))]
use crate::ring_buffer::RingBuffer;
#[cfg(not(feature = "phase-3_5"))]
use crate::uds_server::UdsServerMode;
use crate::uds_server::UdsServer;
use aic_common::central_store_flag::resolve_central_store_flag;
use aic_common::aicd_attach_socket_path;
#[cfg(not(feature = "phase-3_5"))]
use aic_common::{generate_record_id, CommandRecord};
use bytes::Bytes;
use std::io::{Read, Write};
use std::sync::Arc;
#[cfg(not(feature = "phase-3_5"))]
use tokio::sync::RwLock;

/// Runtime options derived from the `aic-session` CLI.
#[derive(Debug, Clone, Copy)]
pub struct SessionRuntimeConfig {
    pub hook_policy: HookPolicy,
}

/// `aic-session` runtime 전체에서 공유되는 read-only 상태.
///
/// R2.7: `Central_Store_Flag`는 runtime 시작 시 한 번만 평가되어 여기 고정 저장된다.
/// 이후 어떤 경로에서 참조하든 같은 값을 본다.
#[derive(Debug)]
pub(crate) struct SessionRuntimeState {
    /// Central_Store_Flag 의 runtime 고정값. true 이면 dual-write 활성.
    pub central_store_flag: bool,
    /// Attach_UDS 쪽 metric (dropped_bytes / attach_reconnect_total). runtime 시작 시
    /// 1 번 생성되어 `AttachClient` 및 세션 `UdsServer` 의 `GetMetrics` 핸들러에서
    /// 같은 카운터를 공유한다 (R14.4, R14.5, Task 6.3). attach 연결 여부와 무관하게
    /// 항상 존재한다.
    ///
    /// 본 구조체 자체는 필드를 읽는 경로가 없지만 (카운터는 `Arc` clone 을 통해
    /// 외부 소비자에게 전달된다) runtime state 의 일부로 보관해 라이프타임을
    /// 보장한다. dead_code lint 는 그래서 의도적으로 허용.
    #[allow(dead_code)]
    pub attach_metrics: Arc<AttachMetrics>,
}

/// 현재 터미널 크기(rows, cols)를 반환한다.
fn get_terminal_size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
            && ws.ws_row > 0
            && ws.ws_col > 0
        {
            (ws.ws_row, ws.ws_col)
        } else {
            (24, 80)
        }
    }
}

/// 터미널을 raw mode로 설정하고 이전 termios를 반환한다.
/// UTF-8 입력 처리를 위해 IUTF8 플래그를 유지한다.
fn set_raw_mode() -> anyhow::Result<libc::termios> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
            anyhow::bail!("tcgetattr 실패");
        }

        let mut raw = orig;
        libc::cfmakeraw(&mut raw);

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            raw.c_iflag |= libc::IUTF8;
        }

        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
            anyhow::bail!("tcsetattr 실패");
        }

        Ok(orig)
    }
}

/// 터미널을 원래 모드로 복원한다.
fn restore_terminal(orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
    }
}

/// Phase 3.5 미적용 빌드 (`not(feature = "phase-3_5")`) 에서만 사용되는
/// 로컬 data plane 필터 / dispatch 헬퍼들.
///
/// `phase-3_5` 빌드에서는 세션 로컬 data plane 이 완전히 제거되어 본 헬퍼들의
/// 호출 경로 자체가 compile out 된다. Phase ≤ 3.4 빌드 호환성을 위해 남겨둔다.
#[cfg(not(feature = "phase-3_5"))]
fn should_store_record(record: &CommandRecord) -> bool {
    let Some(command) = record.command.as_deref() else {
        return true;
    };

    let cmd_base = command
        .split_whitespace()
        .next()
        .and_then(|s| s.rsplit('/').next())
        .unwrap_or("");

    !matches!(cmd_base, "aic" | "ac" | "aic-session")
}

/// 확정된 `CommandRecord` 를 local ring buffer 에 push 하고, Central_Store_Flag 가
/// true 이면 aicd 에도 best-effort dual-write 한다.
///
/// `phase-3_5` 빌드에서는 로컬 RingBuffer 가 존재하지 않아 호출 경로가 사라진다.
///
/// 동작 순서 (중요):
/// 1. [`should_store_record`] 필터가 true 인 경우에만 아래 단계를 진행한다.
///    `aic` / `aic-session` 등의 내부 명령은 local/aicd 양쪽 모두에서 기록을 건너뛴다.
/// 2. record.id 가 비어 있으면 [`generate_record_id`] 로 16-hex id 를 부여한다. 이는
///    local RingBuffer 와 aicd CommandRecordStore 양쪽이 **동일한 id** 를 갖도록
///    하기 위한 전제 조건이다 (P2 Dual-Write equivalence 의 핵심).
/// 3. local `RingBuffer::push` 수행. local 경로가 먼저이므로 aicd 가 죽어 있어도
///    사용자 측 동작에는 영향이 없다 (R3.3).
/// 4. `central_store_flag` 가 true 이면 `aicd_client::register_record` 를 호출.
///    해당 호출 자체가 100ms timeout 으로 감싸져 있어 stdout passthrough 지연을
///    만들지 않는다 (R3.2). 실패 시 silent skip (R3.3).
///
/// 본 함수는 `tokio::task::spawn_blocking` 로 실행되는 PTY reader thread 에서
/// 호출되므로, async 부분은 `tokio::runtime::Handle::current().block_on` 으로 감싼다.
#[cfg(not(feature = "phase-3_5"))]
fn dispatch_record(
    mut record: CommandRecord,
    ring_buffer: &Arc<RwLock<RingBuffer>>,
    session_id: &str,
    central_store_flag: bool,
) {
    if !should_store_record(&record) {
        return;
    }
    // P2 전제: local / aicd 양쪽이 같은 id 를 공유하도록 local push 이전에 id 부여.
    if record.id.is_empty() {
        record.id = generate_record_id();
    }

    let rt = tokio::runtime::Handle::current();
    let buf_clone = Arc::clone(ring_buffer);
    let record_for_local = record.clone();
    let session_id_owned = session_id.to_string();

    rt.block_on(async move {
        // (1) local push — 기존 경로. 실패할 수 있는 요소가 없다.
        {
            let mut rb = buf_clone.write().await;
            rb.push(record_for_local);
        }
        // (2) aicd 로 dual-write (R3.1, R3.2, R3.3, R3.7).
        //     flag=false 이면 호출 자체를 건너뛰어 불필요한 connect 시도조차 하지 않는다.
        if central_store_flag {
            crate::aicd_client::register_record(&session_id_owned, record).await;
        }
    });
}

/// Task 4.3 의 분기 결정 — Central_Store_Flag 와 Attach_UDS 연결 결과에 따라
/// aic-session 의 local data plane (`RingBuffer` / `OutputProcessor` /
/// `CommandBoundaryDetector`) 을 생성해야 하는지 여부를 돌려준다.
///
/// R6.2:
/// - flag=true AND attach 성공 → local instance 를 **아예 만들지 않는다** (false 반환).
/// - flag=false 또는 attach 실패 → 기존 경로대로 local instance 를 생성 (true 반환).
///
/// `phase-3_5` 빌드에서는 로컬 data plane 자체가 제거되어 호출자가 없으므로
/// 본 함수는 `#[cfg(not(feature = "phase-3_5"))]` 가드 아래에서만 컴파일된다.
///
/// `run()` 의 큰 runtime 경로와 무관하게 이 결정만 테스트하기 위해 작은 함수로
/// 분리했다. 아래 `tests::local_data_plane_branches` 가 세 조합을 모두 cover 한다.
#[cfg(not(feature = "phase-3_5"))]
fn should_create_local_data_plane(central_store_flag: bool, attach_connected: bool) -> bool {
    !(central_store_flag && attach_connected)
}

/// Task 4.3 R9.1 의 "autostart + 1 회 재시도" 경로.
///
/// 호출 순서:
/// 1. `AttachClient::connect` 를 1 차 시도.
/// 2. 실패하면 [`aicd_autostart::try_start`] 로 aicd 를 best-effort spawn.
/// 3. autostart 가 `Ok(())` 인 경우에만 [`AUTOSTART_GRACE`] 만큼 sleep 한 뒤 재시도.
///    autostart 가 `Err` (바이너리 없음 등) 이면 재시도를 건너뛰고 1 차 실패를 반환한다.
/// 4. 재시도 시점에 `AttachMetrics::attach_reconnect_total` 을 +1 한다 (R14.5).
///    1 차 connect 실패 자체는 "첫 연결" 이므로 카운트하지 않는다 — task 4.3 의 명시 요구.
///
/// Return:
/// - `Ok(client)` — 1 차 또는 2 차 connect 가 성공
/// - `Err(last_err)` — autostart 가 실패했거나 재시도도 실패한 경우의 마지막 에러
///
/// 이 함수는 production 경로 전용 shim 이며, 테스트는 [`attach_with_autostart_retry_inner`]
/// 에 fake starter 를 주입해 verify 한다.
async fn attach_with_autostart_retry(
    socket_path: &std::path::Path,
    session_id: &str,
    metrics: Arc<AttachMetrics>,
) -> Result<AttachClient, crate::attach_client::AttachConnectError> {
    attach_with_autostart_retry_inner(socket_path, session_id, metrics, || {
        crate::aicd_autostart::try_start().map_err(|e| e.to_string())
    })
    .await
}

/// `attach_with_autostart_retry` 의 핵심 로직. `starter` 클로저로 autostart 동작을
/// 주입 가능해 단위 테스트에서 "autostart 성공 후 재시도" 와 "autostart 실패로 바로
/// fallback" 두 경로를 독립적으로 검증할 수 있다.
async fn attach_with_autostart_retry_inner<F>(
    socket_path: &std::path::Path,
    session_id: &str,
    metrics: Arc<AttachMetrics>,
    starter: F,
) -> Result<AttachClient, crate::attach_client::AttachConnectError>
where
    F: FnOnce() -> Result<(), String>,
{
    // ── (1) 첫 시도 ──────────────────────────────────────────────
    match AttachClient::connect(socket_path, session_id.to_string(), Arc::clone(&metrics)).await {
        Ok(client) => Ok(client),
        Err(first_err) => {
            tracing::debug!(
                session_id,
                socket = %socket_path.display(),
                error = %first_err,
                "Attach_UDS 1 차 연결 실패 — aicd autostart 를 시도합니다 (R9.1)"
            );

            // ── (2) autostart 시도 ──────────────────────────────
            //
            // 바이너리가 없거나 spawn 실패이면 재시도는 무의미하므로 1 차 에러를 그대로
            // 돌려준다. 로그는 debug 레벨 — 사용자가 `aicd` 를 설치하지 않은 일반
            // 경로에서도 노이즈를 만들지 않기 위함이다.
            if let Err(auto_err) = starter() {
                tracing::debug!(
                    session_id,
                    error = %auto_err,
                    "aicd autostart 실패 — Local_Fallback 으로 진입합니다 (R9.2)"
                );
                return Err(first_err);
            }

            // ── (3) 재연결 — attach_reconnect_total 증가 (R14.5) ──
            //
            // autostart 가 spawn 에 성공했다고 해서 aicd 가 listener 를 바인드했다는
            // 보장은 없다. 짧은 grace 동안 sleep 한 뒤 재시도한다 —
            // `handle_daemon_start` 와 동일한 150ms.
            tokio::time::sleep(AUTOSTART_GRACE).await;
            metrics.inc_attach_reconnect();

            AttachClient::connect(socket_path, session_id.to_string(), metrics).await
        }
    }
}

/// autostart 이후 재연결 전에 부여하는 grace period. `aic-client::handle_daemon_start`
/// 의 150ms 와 동일 — aicd 가 listener 를 바인드할 정도의 최소 시간이다.
const AUTOSTART_GRACE: std::time::Duration = std::time::Duration::from_millis(150);

/// Task 4.1 에서 local data plane 이 활성화된 경우 `fan_out_chunk` 가 참조하는
/// 세 컴포넌트의 mutable bundle.
///
/// local=None (flag=true + attach 성공) 조합에서는 이 struct 를 만들 필요 없이
/// `fan_out_chunk(..., local=None, ...)` 로 호출해 processor/detector/ring 소비
/// 자체를 skip 한다 (R6.2). `lifetime` 은 `spawn_blocking` 안쪽 스택과 outer
/// `Arc<RwLock<RingBuffer>>` 를 동시에 참조하기 위해 단일 `'a` 로 묶었다.
///
/// Phase 3.5 빌드에서는 세션 로컬 data plane 이 완전히 제거되어 본 struct 도
/// 필요하지 않다 (`#[cfg(not(feature = "phase-3_5"))]` 로 gate).
#[cfg(not(feature = "phase-3_5"))]
struct LocalDataPlaneMut<'a> {
    processor: &'a mut OutputProcessor,
    detector: &'a mut CommandBoundaryDetector,
    ring_buffer: &'a Arc<RwLock<RingBuffer>>,
}

/// PTY reader blocking thread 안에서 한 chunk (`&buf[..n]`) 를 "passthrough → attach tee
/// → local processor" 순서로 팬아웃한다.
///
/// 이 순서는 Task 3.5 의 핵심 요구사항 (R5.7, R5.8, R5.11, R5.12) 을 그대로 따른다:
///
/// 1. **stdout passthrough 가 가장 먼저** 실행되어 사용자 체감 latency 에 attach 전송이
///    끼어들지 않도록 한다. `try_send` 가 full 이어도, OutputProcessor 가 느려도,
///    local `dispatch_record` 가 aicd 와 연결해 100ms 를 잡아먹어도 stdout byte 들은
///    이미 write 된 상태이다 (R5.12, Property 6 의 non-interference).
/// 2. **attach_client.try_send** 가 그 다음. `BoundedByteChannel` 은 non-blocking 이며,
///    cap 을 넘으면 chunk 를 drop 하고 `AttachMetrics.dropped_bytes` 에만 누적된다
///    (R10.3). stdout 은 이미 write 되었기 때문에 drop 이 발생해도 사용자는 출력을
///    놓치지 않는다.
/// 3. **local OutputProcessor + CommandBoundaryDetector** — Task 4.1 부터는
///    `local: Option<LocalDataPlaneMut<'_>>` 로 가드된다. `Some` 이면 기존 경로
///    (Phase 3.3 Dual_Processing, Phase 3.4 Local_Fallback) 대로 동작하고,
///    `None` 이면 (flag=true + attach 성공) 해당 블록을 통째로 skip 한다 (R6.2).
///
/// Phase 3.5 빌드에서는 로컬 data plane 이 제거되어 3 단계 중 "local" 블록 자체가
/// compile out 된다 — [`fan_out_chunk_central_only`] 가 대응 버전이며 본 함수는
/// Phase ≤ 3.4 전용이다.
///
/// 별도 helper 로 분리한 이유는 단위 테스트에서 "동일 chunk 가 local / central 양쪽에
/// 그대로 도달하는가" 를 시뮬레이션하기 위함이다. attach client 대신 mock sink 를
/// 넣어 같은 바이트열을 받는지 확인할 수 있다.
#[cfg(not(feature = "phase-3_5"))]
fn fan_out_chunk<W: Write>(
    chunk: &[u8],
    stdout: &mut W,
    attach_client: Option<&AttachClient>,
    local: Option<LocalDataPlaneMut<'_>>,
    session_id: &str,
    central_store_flag: bool,
) {
    // ── (1) stdout passthrough 가 가장 먼저 (R5.12, R10.4) ────────
    //
    // Write error 는 대부분 shell 종료 시점의 PIPE 이므로 debug 로만 남긴다 —
    // 루프 상위에서 PTY read() == 0 을 만날 때까지 계속 진행한다.
    if let Err(e) = stdout.write_all(chunk) {
        tracing::debug!(error = %e, "stdout passthrough write 실패 (무시)");
    }
    if let Err(e) = stdout.flush() {
        tracing::debug!(error = %e, "stdout passthrough flush 실패 (무시)");
    }

    // ── (2) Attach tee (R5.7, R5.8) ─────────────────────────────
    //
    // attach_client 는 Phase 3.3 에서 `central_store_flag=true` 이고 handshake 가
    // 성공한 경우에만 Some 이다. Local_Fallback 모드(§Phase 3.4 Task 4.3) 나 flag=false
    // 에서는 None 이다. `Bytes::copy_from_slice` 로 Arc 공유 힙에 한 번만 할당한다.
    if let Some(client) = attach_client {
        let _outcome = client.try_send(Bytes::copy_from_slice(chunk));
        // outcome 이 Dropped 여도 여기서는 추가 로깅하지 않는다 — AttachClient 내부가
        // 세션 lifetime 당 최대 1 회 warn! 을 찍고, metric 에도 이미 반영되어 있다.
    }

    // ── (3) Local OutputProcessor + BoundaryDetector (R5.11, R6.2) ────
    //
    // Task 4.1: local 이 None 이면 (flag=true + attach 성공) 이 블록 자체를 skip 해
    // local pipeline 의 CPU / 메모리 비용을 제거한다. `chunk` 는 이미 (1) 에서 stdout
    // 으로, (2) 에서 aicd 로 전달되었으므로 사용자 입장에서는 손실이 없다.
    if let Some(LocalDataPlaneMut {
        processor,
        detector,
        ring_buffer,
    }) = local
    {
        // Phase 3.3 Dual_Processing / Phase 3.4 Local_Fallback: attach 여부와 무관하게
        // local path 가 유지되며, boundary 가 확정되면 dispatch_record 가 local
        // RingBuffer 에 push + (flag=true 면) aicd 로 forward.
        let output = processor.process(chunk);

        for marker in &output.osc133_markers {
            if let Some(record) = detector.feed_line(marker) {
                dispatch_record(record, ring_buffer, session_id, central_store_flag);
            }
        }

        if let Some(ref text) = output.clean_text {
            for line in text.lines() {
                if let Some(record) = detector.feed_line(line) {
                    dispatch_record(record, ring_buffer, session_id, central_store_flag);
                }
            }
        }
    }
}

/// Phase 3.5 전용 팬아웃 — "stdout passthrough → attach tee" 두 단계만 수행한다.
///
/// Phase 3.5 빌드에서는 로컬 `RingBuffer` / `OutputProcessor` / `CommandBoundaryDetector`
/// 가 전부 제거된다 (R20.1~20.3). `run()` 내부에서 `AttachClient::connect` 가
/// 실패하면 곧바로 fatal error 로 프로세스를 종료하므로, 본 함수에 들어오는 시점에는
/// 항상 `attach_client` 가 Some 이다. 그럼에도 stdout passthrough 는 아무 의존성
/// 없이 성공해야 하므로 `Option<&AttachClient>` 시그니처를 그대로 유지해 후속
/// 리팩터링을 단순화한다.
#[cfg(feature = "phase-3_5")]
fn fan_out_chunk_central_only<W: Write>(
    chunk: &[u8],
    stdout: &mut W,
    attach_client: Option<&AttachClient>,
) {
    // stdout passthrough 가 가장 먼저 — attach 상태와 무관하게 byte-exact (R5.12).
    if let Err(e) = stdout.write_all(chunk) {
        tracing::debug!(error = %e, "stdout passthrough write 실패 (무시)");
    }
    if let Err(e) = stdout.flush() {
        tracing::debug!(error = %e, "stdout passthrough flush 실패 (무시)");
    }

    // attach tee — Phase 3.5 에서는 항상 Some 이지만 None 도 허용해 유연성을 유지한다.
    if let Some(client) = attach_client {
        let _ = client.try_send(Bytes::copy_from_slice(chunk));
    }
}

/// Run one foreground `aic-session` until the shell exits, PTY reaches EOF, or
/// the process receives SIGTERM/SIGINT.
pub async fn run(config: SessionRuntimeConfig) -> anyhow::Result<()> {
    // 0. Central_Store_Flag 를 runtime 시작 시점에 한 번만 평가해 고정한다 (R2.7).
    //    - env `AIC_CENTRAL_STORE` 가 최우선.
    //    - 본 경로에서는 config 파일까지 읽지는 않고 env + Phase default 만 본다.
    //      (추후 config 경로 통합 시 `AppConfigWithDaemon` 을 주입한다.)
    //    flag=false 이면 이후 `aicd_client::register_record` 호출 자체를 건너뛴다 (R3.7).
    let env_vars: std::collections::HashMap<String, String> = std::env::vars().collect();
    let attach_metrics = Arc::new(AttachMetrics::new());
    let runtime_state = Arc::new(SessionRuntimeState {
        central_store_flag: resolve_central_store_flag(&env_vars, None),
        attach_metrics: Arc::clone(&attach_metrics),
    });
    tracing::info!(
        central_store_flag = runtime_state.central_store_flag,
        "aic-session runtime flag 결정 완료"
    );

    // Task 5.2 (R19.3): Phase 3.5 빌드에서 `AIC_CENTRAL_STORE=0` 은 사실상 무시된다.
    // Phase 3.5 는 세션 로컬 data plane 자체를 제거했기 때문에 "끈다" 라는 선택지가
    // 의미를 잃는다. 값이 실제로 false 로 평가되었다면 한 번 warn 을 남겨 운영자가
    // 환경변수의 오해를 알아차릴 수 있게 한다. flag 자체는 환경변수가 요청한 대로
    // 그대로 유지되지만 (R2.7), 이후 런타임 경로는 Phase 3.5 feature 가 우선한다.
    #[cfg(feature = "phase-3_5")]
    if !runtime_state.central_store_flag {
        tracing::warn!("Phase 3.5 빌드에서 AIC_CENTRAL_STORE=0은 무시됩니다");
    }

    // 0. Session_ID 생성 및 세션별 소켓/lock 경로 결정
    let session_dir = aic_common::session_dir();
    std::fs::create_dir_all(&session_dir)
        .map_err(|e| anyhow::anyhow!("세션 디렉토리 생성 실패: {} — {e}", session_dir.display()))?;

    // Stale 세션 정리 — 이전 비정상 종료로 남은 소켓/PID 파일 삭제
    crate::lock::cleanup_stale_sessions();

    let session_id = aic_common::generate_unused_session_id(16)
        .ok_or_else(|| anyhow::anyhow!("충돌 없는 Session_ID를 생성하지 못했습니다"))?;
    let sock = aic_common::session_socket_path(&session_id);
    let lock_path = sock.with_extension("pid");

    // 세션별 PID lock 획득 — 동일 Session_ID의 중복 실행만 방지
    let _daemon_lock = match DaemonLock::acquire(&lock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("⚠ {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        session_id = %session_id,
        pid = std::process::id(),
        socket = %sock.display(),
        lock = %lock_path.display(),
        "aic-session 시작 — Session_ID 생성, PID lock 획득"
    );

    let (rows, cols) = get_terminal_size();

    // 1. PTY 셸 실행
    let mut pty =
        PtyManager::spawn_shell_with_hook_policy(rows, cols, &session_id, config.hook_policy)?;
    let hook_status = pty.check_hook_status();
    let shell_name = pty.shell_name().to_string();
    let reader = pty.take_reader()?;
    let mut writer = pty.take_writer()?;

    // 1.5. 훅 설정 확인 및 처리
    match hook_status {
        crate::pty_manager::HookStatus::Configured => {}
        crate::pty_manager::HookStatus::NeedsSetup { fallback_path } => {
            let msg = crate::pty_manager::get_hook_setup_message(&shell_name);
            if !msg.is_empty() {
                eprintln!("{}", msg);
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            let source_cmd = format!("source '{}' 2>/dev/null\n", fallback_path.display());
            writer.write_all(source_cmd.as_bytes())?;
            writer.flush()?;
        }
        crate::pty_manager::HookStatus::Unsupported => {}
        crate::pty_manager::HookStatus::Disabled => {}
    }

    // 2. 터미널 raw mode 설정
    let orig_termios = set_raw_mode()?;

    // 3. UDS 서버 바인딩 — ring_buffer 보다 먼저 binding 을 해 두어도 serve 는
    //    뒤에서 spawn 한다. Local data plane 생성 분기를 정한 뒤에 buffer 참조를
    //    넘기기 위함이다 (R6.2, R6.3).
    //
    //    `attach_metrics` 를 주입해 `GetMetrics` 응답의 `dropped_bytes` /
    //    `attach_reconnect_total` 가 세션 runtime 과 동일한 카운터 값으로 내려가도록 한다
    //    (Task 6.3, R14.4, R14.5).
    let uds_server =
        UdsServer::bind_with_attach_metrics(&sock, Arc::clone(&attach_metrics)).await?;
    tracing::info!(shell = %shell_name, socket = %sock.display(), "PTY 셸 spawn 및 UDS 서버 bind 완료");

    // 4. aicd registry에 best-effort 등록 — aicd가 미실행이면 silent skip한다.
    let now = chrono::Utc::now();
    let session_info_for_register = aic_common::SessionInfo {
        id: session_id.clone(),
        pid: std::process::id(),
        state: aic_common::SessionState::Attached,
        created_at: now,
        last_seen_at: Some(now),
        last_command_at: None,
        attached_tty: crate::aicd_client::current_tty(),
        shell: Some(shell_name.clone()),
        cwd: std::env::current_dir().ok(),
        label: None,
    };
    crate::aicd_client::register_session(session_info_for_register).await;

    let heartbeat_session_id = session_id.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            // The parent aic-session process cwd does not follow `cd` inside the
            // child shell. Keep heartbeat as liveness-only so hook-reported cwd
            // is not overwritten by stale parent cwd.
            crate::aicd_client::heartbeat_session(&heartbeat_session_id, None).await;
        }
    });

    // 5. stdin → PTY 입력 relay (blocking thread)
    let stdin_handle = tokio::task::spawn_blocking(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
                Err(_) => break,
            }
        }
    });

    // 6. Phase 3.3 Attach_UDS connect (R5.7, R5.8) — local data plane 생성 분기보다
    //    **먼저** 수행해야 한다 (Task 4.1/R6.2).
    //
    // Phase ≤ 3.4: Central_Store_Flag=true 이면 runtime 초반에 한 번만
    //   `AttachClient::connect` 를 시도한다. 성공하면 Phase 3.4 central-only 경로 —
    //   local `RingBuffer` / `OutputProcessor` / `CommandBoundaryDetector` 를 아예
    //   만들지 않는다 (R6.2). 실패하면 Task 4.3 의 autostart + 1 회 재시도를 수행하고,
    //   그래도 실패하면 `None` 으로 진행해 Local_Fallback 경로로 간다 (R9.1, R9.2).
    //   flag=false 이면 connect 자체를 시도하지 않아 불필요한 UDS dial 이 없다.
    //
    // Phase 3.5 (Task 5.3, R7.1, R20.1~20.3): 세션 로컬 data plane 이 제거되어
    //   `AttachClient` 연결이 반드시 성공해야만 runtime 을 계속할 수 있다. autostart
    //   재시도까지 실패하면 fatal error 로 즉시 종료한다. Central_Store_Flag 의 runtime
    //   값이 false 여도 무시되며 (이미 시작 시 warn 을 찍었다, R19.3), 항상 attach 시도를
    //   수행한다.

    #[cfg(not(feature = "phase-3_5"))]
    let attach_client: Option<Arc<AttachClient>> = if runtime_state.central_store_flag {
        let attach_socket = aicd_attach_socket_path();
        match attach_with_autostart_retry(
            &attach_socket,
            &session_id,
            Arc::clone(&attach_metrics),
        )
        .await
        {
            Ok(client) => {
                tracing::info!(
                    session_id = %session_id,
                    socket = %attach_socket.display(),
                    "Attach_UDS 연결 성공 — Phase 3.4 central-only 모드 (local data plane 생략)"
                );
                Some(Arc::new(client))
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %session_id,
                    socket = %attach_socket.display(),
                    error = %e,
                    "Attach_UDS 연결 실패 — Local_Fallback 경로로 진행 (local path 사용)"
                );
                None
            }
        }
    } else {
        None
    };

    // Phase 3.5: attach 연결이 반드시 성공해야 한다. 실패 시 fatal error.
    #[cfg(feature = "phase-3_5")]
    let attach_client: Arc<AttachClient> = {
        let attach_socket = aicd_attach_socket_path();
        match attach_with_autostart_retry(
            &attach_socket,
            &session_id,
            Arc::clone(&attach_metrics),
        )
        .await
        {
            Ok(client) => {
                tracing::info!(
                    session_id = %session_id,
                    socket = %attach_socket.display(),
                    "Attach_UDS 연결 성공 — Phase 3.5 central-only 모드"
                );
                Arc::new(client)
            }
            Err(e) => {
                // R7.1, R20.1: Phase 3.5 에서는 Local_Fallback 이 제거되어 attach 가 필수.
                // raw mode 를 복원한 뒤 bail 하여 사용자 터미널을 깨끗한 상태로 돌려준다.
                restore_terminal(&orig_termios);
                let _ = std::fs::remove_file(&sock);
                anyhow::bail!(
                    "Phase 3.5: Attach_UDS 연결 실패 — aicd 가 기동되지 않았거나 응답하지 않습니다 ({}): {e}",
                    attach_socket.display()
                );
            }
        }
    };

    // 7. Local data plane 조건부 생성 (Task 4.1, R6.2, R6.4).
    //
    //    Phase ≤ 3.4: `should_create_local_data_plane` 가 false 이면 (flag=true AND
    //    attach 성공) `RingBuffer` / `OutputProcessor` / `CommandBoundaryDetector` 를
    //    **아예 만들지 않는다**. 생성 자체가 skip 되므로 heap allocation 도 발생하지
    //    않아 Phase 3.4 의 RSS 감소 기준 (R6.5, R6.6) 달성에 기여한다.
    //
    //    Option<Arc<RwLock<RingBuffer>>> 는 uds_server 경로와의 호환성을 위해 존재한다.
    //
    //    Phase 3.5 (Task 5.3): `RingBuffer` / `OutputProcessor` / `CommandBoundaryDetector`
    //    모듈 import 자체가 compile out 되어 있다. 아래 블록도 전체 `cfg` 로 gate.
    #[cfg(not(feature = "phase-3_5"))]
    let local_enabled =
        should_create_local_data_plane(runtime_state.central_store_flag, attach_client.is_some());
    #[cfg(not(feature = "phase-3_5"))]
    let ring_buffer: Option<Arc<RwLock<RingBuffer>>> = if local_enabled {
        Some(Arc::new(RwLock::new(RingBuffer::new(500))))
    } else {
        None
    };
    #[cfg(not(feature = "phase-3_5"))]
    tracing::debug!(
        session_id = %session_id,
        central_store_flag = runtime_state.central_store_flag,
        attach_connected = attach_client.is_some(),
        local_enabled,
        "local data plane 분기 결정"
    );

    // 7.1 UDS 서버 모드 결정 & serve 루프 (Task 4.1 + 4.2 + 4.3, R6.2, R6.3, R6.4, R9.4).
    //
    //     Phase ≤ 3.4:
    //     - `local_enabled=true` (Central_Store_Flag=false, 또는 flag=true 이지만
    //       autostart 재시도까지 실패한 Local_Fallback 경로) — `FullLocal` 유지. session
    //       socket 에서 full data plane 요청을 다시 응답해야 한다 (R9.4).
    //     - `local_enabled=false` (Central_Store_Flag=true AND attach 성공) — 서버를
    //       [`UdsServerMode::PingOnly`] 로 전환해 `GetLastCommand`/`GetRecentLines`/
    //       `GetRecentCommands`/`FindRecordByPrefix` 를 routing error 로 응답한다.
    //
    //     Phase 3.5 (Task 5.2 + 5.3): uds_server 는 legacy socket 파일을 Ping-only /
    //     RegisterRecord(hook fallback) / GetMetrics 만 처리하도록 feature gate 되어
    //     있다. data plane 조회는 모드와 무관하게 Phase 3.5 전용 안내 에러로 거절된다
    //     (R7.2). 따라서 여기서는 모드 전환 자체가 불필요하고 `FullLocal` 기본값을
    //     유지한 채 dummy buffer 를 주입한다.
    //
    //     Task 4.1 스코프에서는 ring_buffer 가 None 이어도 uds_server 는 동작해야 하므로
    //     빈 RingBuffer 를 dummy 로 넘겨 API 호환성을 유지한다 (R20.3).
    #[cfg(not(feature = "phase-3_5"))]
    let uds_mode_handle = uds_server.mode_handle();
    #[cfg(not(feature = "phase-3_5"))]
    if !local_enabled {
        uds_server.set_mode(UdsServerMode::PingOnly);
    }
    // local_enabled=true (Local_Fallback 포함) 에서는 기본값 `FullLocal` 이 유지되어
    // 세션 소켓의 data plane 조회가 정상 응답된다 (R9.4). 명시적으로 set 하지 않는 이유는
    // `UdsServer::bind` 가 이미 `FullLocal` 로 초기화되기 때문이다.
    #[cfg(not(feature = "phase-3_5"))]
    let buf_for_uds = ring_buffer
        .clone()
        .unwrap_or_else(|| Arc::new(RwLock::new(RingBuffer::new(0))));
    // Phase 3.5: ring buffer 모듈 자체가 없어 dummy 만 주입한다. uds_server 내부에서는
    // feature gate 로 data plane 경로가 차단되어 buffer 가 조회되지 않는다.
    #[cfg(feature = "phase-3_5")]
    let buf_for_uds = {
        use crate::ring_buffer::RingBuffer as DummyRingBuffer;
        Arc::new(tokio::sync::RwLock::new(DummyRingBuffer::new(0)))
    };
    let uds_handle = tokio::spawn(async move {
        uds_server.serve(buf_for_uds).await;
    });
    #[cfg(not(feature = "phase-3_5"))]
    {
        tracing::debug!(
            session_id = %session_id,
            uds_mode = ?UdsServerMode::from_u8(uds_mode_handle.load(std::sync::atomic::Ordering::Relaxed)),
            "uds_server 모드 확정"
        );
        // `uds_mode_handle` 은 Task 4.3 Local_Fallback 전환 경로가 `FullLocal` 로 되돌릴
        // 때 사용할 예정이라 drop 하지 않고 유지한다. 현재 shutdown 경로에서는 별도 해제
        // 동작이 없다.
        let _uds_mode_handle = uds_mode_handle;
    }

    // 8. PTY 출력 → stdout passthrough → (attach tee) → (local OutputProcessor → RingBuffer)
    //    팬아웃 순서는 fan_out_chunk 의 문서 참조 (R5.7, R5.8, R5.11, R5.12, R6.2).
    //
    //    Phase ≤ 3.4: local_enabled 가 false 이면 spawn_blocking 안에서 OutputProcessor /
    //    CommandBoundaryDetector 자체를 만들지 않고, fan_out_chunk 에는 `None` 을 전달한다.
    //
    //    Phase 3.5: 로컬 data plane 이 제거되어 [`fan_out_chunk_central_only`] 를 사용하며
    //    stdout passthrough + attach tee 두 단계만 수행한다.
    #[cfg(not(feature = "phase-3_5"))]
    let buf_for_output = ring_buffer.clone();
    #[cfg(not(feature = "phase-3_5"))]
    let output_session_id = session_id.clone();
    #[cfg(not(feature = "phase-3_5"))]
    let output_central_store = runtime_state.central_store_flag;
    #[cfg(not(feature = "phase-3_5"))]
    let attach_for_output = attach_client.clone();
    #[cfg(feature = "phase-3_5")]
    let attach_for_output: Arc<AttachClient> = Arc::clone(&attach_client);

    #[cfg(not(feature = "phase-3_5"))]
    let output_handle = tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        // local data plane 은 조건부 생성 — R6.2 의 핵심이다. `Option` 안쪽 값을
        // 스택에 직접 보유하고, fan_out_chunk 에는 `as_mut` 으로 short-lived reference
        // 를 넘긴다.
        let mut local_state: Option<(OutputProcessor, CommandBoundaryDetector)> =
            if buf_for_output.is_some() {
                Some((
                    OutputProcessor::new(),
                    CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
                        marker_sequence: "osc133".to_string(),
                    }),
                ))
            } else {
                None
            };
        let mut stdout = std::io::stdout().lock();
        let mut buf = [0u8; 4096];

        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buf[..n];
                    // 매 chunk 마다 local reference 를 새로 엮어 fan_out_chunk 의
                    // lifetime 요구를 만족시킨다. buf_for_output 이 None 이면 local 도 None.
                    let local_ref = match (&mut local_state, &buf_for_output) {
                        (Some((processor, detector)), Some(rb)) => Some(LocalDataPlaneMut {
                            processor,
                            detector,
                            ring_buffer: rb,
                        }),
                        _ => None,
                    };
                    fan_out_chunk(
                        chunk,
                        &mut stdout,
                        attach_for_output.as_deref(),
                        local_ref,
                        &output_session_id,
                        output_central_store,
                    );
                }
                Err(_) => break,
            }
        }
    });

    #[cfg(feature = "phase-3_5")]
    let output_handle = tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut stdout = std::io::stdout().lock();
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    fan_out_chunk_central_only(
                        &buf[..n],
                        &mut stdout,
                        Some(attach_for_output.as_ref()),
                    );
                }
                Err(_) => break,
            }
        }
    });

    // 8. SIGWINCH 핸들러
    let pty_master_for_resize = Arc::new(std::sync::Mutex::new(pty));
    let pty_for_sigwinch = Arc::clone(&pty_master_for_resize);
    let sigwinch_handle = tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = match signal(SignalKind::window_change()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("SIGWINCH 핸들러 등록 실패: {e}");
                return;
            }
        };
        while sig.recv().await.is_some() {
            let (rows, cols) = get_terminal_size();
            if let Ok(pty) = pty_for_sigwinch.lock() {
                let _ = pty.resize(rows, cols);
            }
        }
    });

    // 9. 셸 종료 대기
    let mut child_for_wait = pty_master_for_resize
        .lock()
        .ok()
        .and_then(|mut pty| pty.take_child());
    let wait_handle = tokio::task::spawn_blocking(move || {
        if let Some(child) = child_for_wait.as_mut() {
            let _ = child.wait();
        }
    });

    // 9.5 외부 종료 시그널 핸들러 (SIGTERM, SIGINT)
    let shutdown_signal = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        match (sigterm.as_mut(), sigint.as_mut()) {
            (Some(t), Some(i)) => {
                tokio::select! {
                    _ = t.recv() => "SIGTERM",
                    _ = i.recv() => "SIGINT",
                }
            }
            (Some(t), None) => {
                t.recv().await;
                "SIGTERM"
            }
            (None, Some(i)) => {
                i.recv().await;
                "SIGINT"
            }
            (None, None) => std::future::pending().await,
        }
    };

    let trigger = tokio::select! {
        _ = wait_handle => "shell-exit",
        _ = output_handle => "pty-eof",
        sig = shutdown_signal => sig,
    };

    // 10. Graceful 정리
    restore_terminal(&orig_termios);
    // AttachClient 를 먼저 drop 하여 writer task 가 AttachClose 를 flush 한 뒤 자연
    // 종료하도록 한다. `attach_for_output` 이 `Arc` 를 들고 있다면 여기서 drop 해도
    // reference count 가 0 이 아닐 수 있어 원본 `attach_client` 와 spawn_blocking 쪽
    // 복사본을 모두 drop 해 준다 — output_handle 은 이미 select! 로 awaited 되어
    // blocking task 가 종료된 상태이므로 `attach_for_output` 은 이미 소멸했다.
    drop(attach_client);
    crate::aicd_client::unregister_session(&session_id).await;
    uds_handle.abort();
    stdin_handle.abort();
    heartbeat_handle.abort();
    sigwinch_handle.abort();
    let _ = std::fs::remove_file(&sock);

    tracing::info!(
        trigger = trigger,
        session_id = %session_id,
        socket = %sock.display(),
        "aic-session shutdown — 세션 소켓 삭제 완료"
    );

    Ok(())
}

#[cfg(all(test, not(feature = "phase-3_5")))]
mod tests {
    use super::*;
    use chrono::Utc;

    fn record(command: Option<&str>) -> CommandRecord {
        CommandRecord {
            command: command.map(str::to_string),
            exit_code: 1,
            output_lines: vec!["output".to_string()],
            timestamp: Utc::now(),
            ..Default::default()
        }
    }

    #[test]
    fn stores_user_commands() {
        assert!(should_store_record(&record(Some("cargo build"))));
        assert!(should_store_record(&record(Some("/usr/bin/git status"))));
        assert!(should_store_record(&record(None)));
    }

    #[test]
    fn skips_aic_internal_commands() {
        assert!(!should_store_record(&record(Some("aic"))));
        assert!(!should_store_record(&record(Some("aic --help"))));
        assert!(!should_store_record(&record(Some("ac status"))));
        assert!(!should_store_record(&record(Some("/tmp/bin/aic-session"))));
    }

    // ── Phase 3.1 Task 1.6: dispatch_record 단위 테스트 ─────────────────

    /// flag=false 인 상태에서 aicd 가 없어도 local push 는 항상 성공해야 한다 (R3.3, R3.7).
    #[tokio::test]
    async fn dispatch_record_local_push_succeeds_when_flag_off() {
        let rb = Arc::new(RwLock::new(RingBuffer::new(100)));
        let rec = record(Some("echo hi"));

        // block_on 안에서 block_on 을 하면 panic 이 나므로 spawn_blocking 으로 격리한다.
        let rb_clone = Arc::clone(&rb);
        tokio::task::spawn_blocking(move || {
            dispatch_record(rec, &rb_clone, "sess-1", /*central_store_flag=*/ false);
        })
        .await
        .expect("spawn_blocking task failed");

        let guard = rb.read().await;
        assert_eq!(guard.recent_records(10).len(), 1);
        let stored = guard.recent_records(10)[0].clone();
        assert_eq!(stored.command.as_deref(), Some("echo hi"));
        // local push 에서 id auto-assign 이 적용되어 16-hex 가 된다.
        assert_eq!(stored.id.len(), 16);
    }

    /// flag=true 인 상태에서도 aicd 미기동이면 local push 는 성공하고 register_record 는
    /// silent skip 된다. dual-write 호출 전체가 100ms 상한 안에서 끝나야 한다 (R3.2, R3.3).
    #[tokio::test]
    async fn dispatch_record_dual_write_completes_under_timeout_when_aicd_absent() {
        let rb = Arc::new(RwLock::new(RingBuffer::new(100)));
        let rec = record(Some("ls"));

        let rb_clone = Arc::clone(&rb);
        let start = std::time::Instant::now();
        let joined = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::task::spawn_blocking(move || {
                dispatch_record(rec, &rb_clone, "sess-2", /*central_store_flag=*/ true);
            }),
        )
        .await;
        assert!(
            joined.is_ok(),
            "dispatch_record 가 500ms 안에 끝나지 않음 — dual-write timeout 상한이 깨짐"
        );
        joined.unwrap().expect("spawn_blocking task failed");
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "dispatch_record 실 소요 시간이 500ms 를 초과: {elapsed:?}"
        );

        // local 은 여전히 push 되어 있어야 한다 (aicd 는 best-effort).
        let guard = rb.read().await;
        let stored = guard.recent_records(10);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].command.as_deref(), Some("ls"));
    }

    /// `should_store_record` 가 false 인 내부 명령은 local/aicd 양쪽 모두 건너뛴다.
    #[tokio::test]
    async fn dispatch_record_skips_internal_commands() {
        let rb = Arc::new(RwLock::new(RingBuffer::new(100)));
        let rec = record(Some("aic analyze"));

        let rb_clone = Arc::clone(&rb);
        tokio::task::spawn_blocking(move || {
            dispatch_record(rec, &rb_clone, "sess-3", /*central_store_flag=*/ true);
        })
        .await
        .expect("spawn_blocking task failed");

        let guard = rb.read().await;
        assert!(
            guard.recent_records(10).is_empty(),
            "내부 명령 'aic analyze' 는 ring buffer 에 저장되면 안 된다"
        );
    }

    /// 이미 id 가 부여된 record 는 local/aicd 양쪽이 같은 id 를 공유해야 한다 (P2 전제).
    #[tokio::test]
    async fn dispatch_record_preserves_existing_id() {
        let rb = Arc::new(RwLock::new(RingBuffer::new(100)));
        let explicit_id = "deadbeefcafef00d".to_string();
        let mut rec = record(Some("git status"));
        rec.id = explicit_id.clone();

        let rb_clone = Arc::clone(&rb);
        tokio::task::spawn_blocking(move || {
            dispatch_record(rec, &rb_clone, "sess-4", /*central_store_flag=*/ true);
        })
        .await
        .expect("spawn_blocking task failed");

        let guard = rb.read().await;
        let stored = guard.recent_records(10);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, explicit_id);
    }

    /// 실제 `aicd_client::register_record` 호출 경로가 100ms 상한 안에 끝나는지
    /// 확인한다. aicd 는 띄우지 않았으므로 connect 시점에 즉시 실패하거나 timeout
    /// 으로 회수되는데, 어느 쪽이든 silent skip 되어야 한다 (R3.2, R3.3).
    ///
    /// 본 테스트는 전체 dispatch_record 소요시간이 200ms 를 넘으면 실패한다 —
    /// 100ms timeout + OS 스케줄링 여유를 감안해 2배 gap 을 둔다.
    #[tokio::test]
    async fn dispatch_record_dual_write_bounded_by_100ms_timeout() {
        let rb = Arc::new(RwLock::new(RingBuffer::new(100)));
        let rec = record(Some("uname -a"));

        let rb_clone = Arc::clone(&rb);
        let start = std::time::Instant::now();
        tokio::task::spawn_blocking(move || {
            dispatch_record(rec, &rb_clone, "sess-timeout", true);
        })
        .await
        .expect("spawn_blocking task failed");
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "dispatch_record 총 소요 {elapsed:?} 가 100ms timeout 상한을 크게 초과"
        );

        // local push 는 여전히 성공해야 한다.
        let guard = rb.read().await;
        assert_eq!(guard.recent_records(10).len(), 1);
    }

    // ── Task 3.5: fan_out_chunk 단위 테스트 ──────────────────────────────
    //
    // fan_out_chunk 가 stdout passthrough → attach tee → local processor 순서로
    // 동일한 chunk 를 팬아웃하는지 확인한다. 실제 AttachClient 를 사용하되 mock
    // UDS 서버를 띄워 "전송된 PtyBytes 의 payload" 를 관측한다.

    use aic_common::attach::{
        read_attach_frame, write_attach_server_frame, AttachClientFrame, AttachFrameKind,
        AttachServerFrame, ATTACH_PROTOCOL_VERSION,
    };
    use bytes::Bytes;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    /// handshake 후 도착하는 PtyBytes chunk 를 모아 주는 mock server.
    /// session_runtime 테스트 전용이라 attach_client.rs 의 MockServer 와 중복되지만,
    /// 크레이트 간 재사용 부담을 피하기 위해 최소 버전만 복제한다.
    struct LocalMockServer {
        _tempdir: TempDir,
        socket_path: PathBuf,
        handle: tokio::task::JoinHandle<Vec<Bytes>>,
    }

    impl LocalMockServer {
        async fn start() -> Self {
            let tempdir = tempfile::tempdir().unwrap();
            let socket_path = tempdir.path().join("attach.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();

            let handle = tokio::spawn(async move {
                let mut chunks: Vec<Bytes> = Vec::new();
                let (stream, _) = listener.accept().await.expect("accept");
                let (mut reader, mut writer) = stream.into_split();

                // AttachOpen 소비.
                match read_attach_frame(&mut reader).await {
                    Ok(AttachFrameKind::Client(AttachClientFrame::AttachOpen { .. })) => {}
                    other => panic!("expected AttachOpen, got {other:?}"),
                }
                write_attach_server_frame(
                    &mut writer,
                    &AttachServerFrame::AttachAck {
                        protocol_version: ATTACH_PROTOCOL_VERSION,
                    },
                )
                .await
                .unwrap();

                loop {
                    match read_attach_frame(&mut reader).await {
                        Ok(AttachFrameKind::Client(AttachClientFrame::PtyBytes { bytes })) => {
                            chunks.push(bytes);
                        }
                        Ok(AttachFrameKind::Client(AttachClientFrame::AttachClose { .. })) => {
                            break;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                chunks
            });

            Self {
                _tempdir: tempdir,
                socket_path,
                handle,
            }
        }

        fn socket_path(&self) -> &std::path::Path {
            &self.socket_path
        }

        async fn finish(self) -> Vec<Bytes> {
            tokio::time::timeout(std::time::Duration::from_secs(2), self.handle)
                .await
                .expect("mock server timeout")
                .expect("mock server panicked")
        }
    }

    /// attach_client=None 인 경우 stdout 은 여전히 원본을 받고 local ring 에도 record 가
    /// push 된다 (flag=false 레거시 경로 동일). Dual_Processing 이 "attach 없을 때"도
    /// 안전한 동작을 보장함을 확인한다.
    #[tokio::test]
    async fn fan_out_without_attach_client_writes_stdout_and_local_only() {
        let rb = Arc::new(RwLock::new(RingBuffer::new(500)));

        // OSC 133 한 쌍을 단일 청크로 주되 fan_out_chunk 는 stdout/attach/local 에 raw
        // bytes 를 그대로 전달하는 것을 검증하는 테스트이므로 boundary 미성립은 무관.
        let chunk = b"hello world\n";

        let rb_clone = Arc::clone(&rb);
        let fan = move || {
            let mut stdout: Vec<u8> = Vec::new();
            let mut processor = OutputProcessor::new();
            let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
                marker_sequence: "osc133".to_string(),
            });
            fan_out_chunk(
                chunk,
                &mut stdout,
                None,
                Some(LocalDataPlaneMut {
                    processor: &mut processor,
                    detector: &mut detector,
                    ring_buffer: &rb_clone,
                }),
                "sess-noattach",
                false,
            );
            stdout
        };
        let stdout = tokio::task::spawn_blocking(fan)
            .await
            .expect("spawn_blocking");

        // stdout 은 원본 raw bytes 를 byte-exact 로 받는다 (R5.12).
        assert_eq!(stdout, chunk);
        // local ring 은 OSC 133 marker 가 없어 record 가 아직 없다. fan_out 이 silently
        // 완료되는지만 확인.
        let guard = rb.read().await;
        assert!(guard.recent_records(10).is_empty());
    }

    /// attach_client=Some 에서 같은 chunk 가 stdout / attach 서버 / local processor 에
    /// 모두 도달하는지 확인한다. 이 테스트는 Task 3.5 의 핵심 수용 기준 — "local 과
    /// central 경로가 같은 chunk 를 받는지 시뮬레이션" — 에 해당한다.
    #[tokio::test]
    async fn fan_out_with_attach_client_tees_same_bytes_to_stdout_and_server() {
        let server = LocalMockServer::start().await;
        let metrics = Arc::new(AttachMetrics::new());
        let attach = AttachClient::connect(
            server.socket_path(),
            "sess-tee".to_string(),
            Arc::clone(&metrics),
        )
        .await
        .expect("attach connect");
        let attach = Arc::new(attach);

        let rb = Arc::new(RwLock::new(RingBuffer::new(500)));

        // 여러 chunk 를 순차적으로 fan_out — stdout/attach 양쪽이 동일한 byte 시퀀스를
        // 받는지를 관측하기 위함.
        let chunks: Vec<Vec<u8>> = vec![
            b"first-chunk-output\n".to_vec(),
            b"second\x1b[32mcolored\x1b[0m\n".to_vec(),
            b"third\n".to_vec(),
        ];

        let attach_for_task = Arc::clone(&attach);
        let rb_for_task = Arc::clone(&rb);
        let chunks_for_task = chunks.clone();

        let collected_stdout = tokio::task::spawn_blocking(move || {
            let mut stdout: Vec<u8> = Vec::new();
            let mut processor = OutputProcessor::new();
            let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
                marker_sequence: "osc133".to_string(),
            });
            for chunk in &chunks_for_task {
                fan_out_chunk(
                    chunk,
                    &mut stdout,
                    Some(attach_for_task.as_ref()),
                    Some(LocalDataPlaneMut {
                        processor: &mut processor,
                        detector: &mut detector,
                        ring_buffer: &rb_for_task,
                    }),
                    "sess-tee",
                    /*central_store_flag=*/ false, // flag=false 로 두어 aicd 호출은 배제.
                );
            }
            stdout
        })
        .await
        .expect("spawn_blocking");

        // stdout 은 모든 chunk 를 순서대로 byte-exact 로 받는다 (R5.12).
        let expected_stdout: Vec<u8> = chunks.iter().flatten().copied().collect();
        assert_eq!(collected_stdout, expected_stdout);

        // AttachClient 를 drop 하면 writer task 가 AttachClose 를 보낸다 — 그 시점에
        // 서버 쪽이 finish() 로 정리된다.
        //
        // Arc 가 fan_out 안에서 공유되었으므로 여기서 attach 원본 Arc 하나만 drop 해도
        // spawn_blocking 쪽 Arc 가 이미 소멸해 ref count 가 0 이 된다.
        drop(attach);

        let received = server.finish().await;
        assert_eq!(
            received.len(),
            chunks.len(),
            "attach 서버가 받은 chunk 수가 송신한 수와 불일치"
        );
        for (i, (sent, got)) in chunks.iter().zip(received.iter()).enumerate() {
            assert_eq!(
                got.as_ref(),
                sent.as_slice(),
                "chunk {i}: stdout 과 attach tee 가 같은 byte 를 받지 못함"
            );
        }

        // backpressure drop 은 발생하지 않았어야 한다 (작은 chunk + cap 4MiB).
        assert_eq!(metrics.dropped_bytes(), 0);
    }

    /// OSC 133 preexec/precmd 쌍을 넣어 local boundary detector 가 record 를 만들어
    /// ring buffer 에 push 하는지까지 확인한다. Dual_Processing 모드에서 local path
    /// 가 유지됨을 증명하는 end-to-end 유사 단위 테스트 (R5.11).
    #[tokio::test]
    async fn fan_out_with_attach_still_produces_local_records() {
        let server = LocalMockServer::start().await;
        let metrics = Arc::new(AttachMetrics::new());
        let attach = Arc::new(
            AttachClient::connect(
                server.socket_path(),
                "sess-dual".to_string(),
                Arc::clone(&metrics),
            )
            .await
            .expect("attach connect"),
        );
        let rb = Arc::new(RwLock::new(RingBuffer::new(500)));

        // cmd="ls" → hex "6c73". preexec → body → precmd 를 3 개 청크로 나눠 보낸다.
        let chunks: Vec<Vec<u8>> = vec![
            b"\x1b]133;C;cmd=6c73\x07".to_vec(),
            b"first-line\nsecond-line\n".to_vec(),
            b"\x1b]133;D;0\x07".to_vec(),
        ];

        let attach_for_task = Arc::clone(&attach);
        let rb_for_task = Arc::clone(&rb);
        let chunks_for_task = chunks.clone();
        tokio::task::spawn_blocking(move || {
            let mut stdout: Vec<u8> = Vec::new();
            let mut processor = OutputProcessor::new();
            let mut detector = CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
                marker_sequence: "osc133".to_string(),
            });
            for chunk in &chunks_for_task {
                fan_out_chunk(
                    chunk,
                    &mut stdout,
                    Some(attach_for_task.as_ref()),
                    Some(LocalDataPlaneMut {
                        processor: &mut processor,
                        detector: &mut detector,
                        ring_buffer: &rb_for_task,
                    }),
                    "sess-dual",
                    /*central_store_flag=*/ false,
                );
            }
        })
        .await
        .expect("spawn_blocking");

        // local ring 에 record 1 개 (command="ls", exit_code=0).
        let guard = rb.read().await;
        let recs = guard.recent_records(10);
        assert_eq!(recs.len(), 1, "local ring 에 record 1 개 기대 — got {recs:?}");
        assert_eq!(recs[0].command.as_deref(), Some("ls"));
        assert_eq!(recs[0].exit_code, 0);
        drop(guard);

        // attach 서버는 동일한 byte stream 을 받았어야 한다.
        drop(attach);
        let received = server.finish().await;
        let expected_bytes: Vec<u8> = chunks.iter().flatten().copied().collect();
        let received_bytes: Vec<u8> = received
            .iter()
            .flat_map(|b| b.as_ref().iter().copied())
            .collect();
        assert_eq!(received_bytes, expected_bytes);
    }

    // ── Task 4.1: should_create_local_data_plane + fan_out_chunk(local=None) ──
    //
    // "flag+attach=true → local None", "flag=false → local Some",
    // "flag=true but attach fails → local Some as fallback" 세 조합을 커버한다.
    // local path 를 실제로 생성하는 `run()` 전체를 돌리지 않고, 분기 결정 함수
    // 한 점에서만 테스트해 runtime 의 PTY / 터미널 사이드 이펙트를 배제한다.

    #[test]
    fn local_data_plane_skipped_when_central_store_and_attach_connected() {
        // R6.2 의 핵심 조건: flag=true AND attach 성공 → local instance 를 만들지 않는다.
        assert!(
            !should_create_local_data_plane(/*flag=*/ true, /*attach_connected=*/ true),
            "flag=true + attach 성공 조합에서는 local data plane 을 생성하지 않아야 한다 (R6.2)"
        );
    }

    #[test]
    fn local_data_plane_created_when_flag_off() {
        // R19.1: flag=false 이면 phase 와 무관하게 기존 local 경로를 유지한다.
        // attach 상태와 무관하다.
        assert!(
            should_create_local_data_plane(/*flag=*/ false, /*attach_connected=*/ false),
            "flag=false 에서는 local data plane 을 생성해 legacy 경로를 유지해야 한다"
        );
        assert!(
            should_create_local_data_plane(/*flag=*/ false, /*attach_connected=*/ true),
            "flag=false 에서는 attach_connected 값과 무관하게 local 생성"
        );
    }

    #[test]
    fn local_data_plane_created_as_fallback_when_attach_fails() {
        // R9.2 / Task 4.3 의 전제: flag=true 이지만 attach 실패 → Local_Fallback.
        assert!(
            should_create_local_data_plane(/*flag=*/ true, /*attach_connected=*/ false),
            "flag=true 라도 attach 실패 시 Local_Fallback 으로 local 을 생성해야 한다 (R9.2, R19.2)"
        );
    }

    /// fan_out_chunk 가 local=None 에서 stdout 과 attach 에만 bytes 를 흘리고, ring
    /// buffer / processor 를 전혀 건드리지 않는지 확인한다. R6.2 의 "생성하지 않음"
    /// 정책이 호출 경로에서도 준수됨을 보장.
    #[tokio::test]
    async fn fan_out_without_local_skips_processor_and_ring() {
        // 이 테스트는 attach_client 는 None (None + None) 조합을 다룬다. local=None 이면
        // ring_buffer 를 어디에서도 참조하지 않으므로 harness 가 ring_buffer 를 만들지
        // 않는 것 자체가 정책 준수의 증거이다. stdout passthrough 만 byte-exact 로
        // 들어오는지 확인한다.
        let chunk = b"hello\nworld\n";
        let fan = move || {
            let mut stdout: Vec<u8> = Vec::new();
            fan_out_chunk(
                chunk,
                &mut stdout,
                /*attach_client=*/ None,
                /*local=*/ None,
                "sess-no-local",
                /*central_store_flag=*/ true,
            );
            stdout
        };
        let stdout = tokio::task::spawn_blocking(fan)
            .await
            .expect("spawn_blocking");
        assert_eq!(
            stdout, chunk,
            "local=None 이어도 stdout passthrough 는 byte-exact 를 유지해야 한다 (R5.12)"
        );
    }

    /// fan_out_chunk 가 local=None, attach=Some 에서도 raw bytes 를 attach tee 로
    /// 정확히 보내고 local 경로는 전혀 수행하지 않음을 확인한다. 이는 Phase 3.4 의
    /// 기대 동작 — central-only 모드 — 을 최소 단위로 재현한다.
    #[tokio::test]
    async fn fan_out_central_only_tees_bytes_and_skips_local() {
        let server = LocalMockServer::start().await;
        let metrics = Arc::new(AttachMetrics::new());
        let attach = Arc::new(
            AttachClient::connect(
                server.socket_path(),
                "sess-central-only".to_string(),
                Arc::clone(&metrics),
            )
            .await
            .expect("attach connect"),
        );

        // OSC 133 preexec/precmd 쌍을 의도적으로 보냈지만 local=None 이라 record 는
        // 생성되지 않아야 한다. 관찰 가능한 것은 stdout + attach 서버 수신 byte 뿐이다.
        let chunks: Vec<Vec<u8>> = vec![
            b"\x1b]133;C;cmd=6c73\x07".to_vec(),
            b"output-line\n".to_vec(),
            b"\x1b]133;D;0\x07".to_vec(),
        ];

        let attach_for_task = Arc::clone(&attach);
        let chunks_for_task = chunks.clone();
        let collected_stdout = tokio::task::spawn_blocking(move || {
            let mut stdout: Vec<u8> = Vec::new();
            for chunk in &chunks_for_task {
                fan_out_chunk(
                    chunk,
                    &mut stdout,
                    Some(attach_for_task.as_ref()),
                    /*local=*/ None,
                    "sess-central-only",
                    /*central_store_flag=*/ true,
                );
            }
            stdout
        })
        .await
        .expect("spawn_blocking");

        // stdout 은 모든 chunk 를 byte-exact 로 받는다.
        let expected: Vec<u8> = chunks.iter().flatten().copied().collect();
        assert_eq!(collected_stdout, expected);

        // AttachClient drop → AttachClose → 서버 finish.
        drop(attach);
        let received = server.finish().await;
        let received_bytes: Vec<u8> = received
            .iter()
            .flat_map(|b| b.as_ref().iter().copied())
            .collect();
        assert_eq!(received_bytes, expected);
        // local 경로는 어디에서도 실행되지 않았으므로 dropped_bytes 도 0.
        assert_eq!(metrics.dropped_bytes(), 0);
    }

    // ── Task 4.3: Local_Fallback autostart + retry 단위 테스트 ──────────────
    //
    // `attach_with_autostart_retry_inner` 에 주입 가능한 starter 클로저로 다음 세 경로를
    // 각각 검증한다:
    //
    // (A) 첫 connect 성공 → autostart 와 재시도는 시도조차 안 함.
    // (B) 첫 connect 실패 + autostart 실패 → 재시도 skip, 즉시 Local_Fallback 으로
    //     진입하는 경로 (= 가짜 aicd 없는 환경의 대표 경로, R9.2).
    // (C) 첫 connect 실패 + autostart 성공 + 재시도 성공 → `attach_reconnect_total` 이 +1
    //     증가 (R14.5).

    /// (A) 경로: 첫 연결에서 바로 성공하면 starter 가 호출되지 않고 metric 도 건드리지
    /// 않는다. autostart helper 를 아예 타지 않는 정상 경로.
    #[tokio::test]
    async fn autostart_retry_not_invoked_when_first_connect_succeeds() {
        let server = LocalMockServer::start().await;
        let metrics = Arc::new(AttachMetrics::new());

        let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoked_flag = Arc::clone(&invoked);
        let starter = move || {
            invoked_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok::<(), String>(())
        };

        let client = attach_with_autostart_retry_inner(
            server.socket_path(),
            "s-first-ok",
            Arc::clone(&metrics),
            starter,
        )
        .await
        .expect("첫 connect 는 성공해야 함");
        assert_eq!(client.session_id(), "s-first-ok");

        assert!(
            !invoked.load(std::sync::atomic::Ordering::Relaxed),
            "첫 연결이 성공했는데 autostart starter 가 호출됨"
        );
        assert_eq!(
            metrics.attach_reconnect_total(),
            0,
            "첫 연결 성공 경로에서는 attach_reconnect_total 이 0 이어야 함"
        );

        drop(client);
        let _ = server.finish().await;
    }

    /// (B) 경로: 가짜 aicd 가 없는 환경을 시뮬레이션 — 소켓 파일 자체가 없고 autostart 도
    /// 실패한다. 이 조합이 R9.2 Local_Fallback 의 대표 진입 경로이다.
    ///
    /// 단언:
    /// - 결과는 `Err` — 호출자가 `None` 으로 처리해 local data plane 을 만들게 된다.
    /// - starter 는 **정확히 1 회** 호출되었다.
    /// - `attach_reconnect_total` 은 0 — autostart 가 실패해 재시도 자체를 건너뛰었다.
    #[tokio::test]
    async fn autostart_retry_short_circuits_when_starter_fails() {
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("nope.sock");
        let metrics = Arc::new(AttachMetrics::new());

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_flag = Arc::clone(&calls);
        let starter = move || {
            calls_flag.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err("aicd 바이너리를 찾을 수 없음".to_string())
        };

        let err = attach_with_autostart_retry_inner(
            &missing,
            "s-no-aicd",
            Arc::clone(&metrics),
            starter,
        )
        .await
        .expect_err("소켓도 없고 autostart 도 실패하면 Err 기대");
        // 에러 분류는 1 차 connect 실패를 그대로 반환 — Io 분류가 가장 흔하다.
        match err {
            crate::attach_client::AttachConnectError::Io(_) => {}
            other => panic!("첫 connect 실패가 Io 이어야 함 — actual: {other:?}"),
        }

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "starter 는 정확히 한 번만 호출되어야 함"
        );
        assert_eq!(
            metrics.attach_reconnect_total(),
            0,
            "autostart 실패 시 재시도를 건너뛰므로 reconnect 카운터는 0 이어야 함"
        );
    }

    /// (C) 경로: autostart 가 성공한 것처럼 시뮬레이션하면 재시도가 일어나고 그 재시도가
    /// 성공하면 `attach_reconnect_total` 이 1 증가한다 (R14.5).
    ///
    /// harness 는 "첫 연결 실패" 를 강제하기 위해 존재하지 않는 소켓 경로를 잠시 쓰고,
    /// starter 클로저 안에서 실제 mock 서버를 띄운 뒤 sleep 동안 소켓 파일이 존재하도록
    /// 한다. 하지만 `attach_with_autostart_retry_inner` 는 같은 `socket_path` 에만 연결을
    /// 시도하므로, starter 는 해당 path 에 정확히 UDS listener 를 bind 해야 한다.
    ///
    /// 구현: starter 실행 시점에 임시 listener 를 spawn 하고 handshake 를 수행하는
    /// task 를 띄운다 — 첫 connect 실패 → starter 호출 → 150ms grace → 두 번째 connect
    /// 가 이 listener 에 붙는다.
    #[tokio::test]
    async fn autostart_retry_increments_reconnect_on_second_attempt() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("attach.sock");
        let socket_path_for_starter = socket_path.clone();
        let metrics = Arc::new(AttachMetrics::new());

        // starter 가 "한 번" 호출되었는지, 그리고 호출된 시점에 listener 를 bind 하는지를
        // 관측한다.
        let started_at = Arc::new(std::sync::Mutex::new(None::<std::time::Instant>));
        let started_at_flag = Arc::clone(&started_at);
        let server_handle_slot: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let server_handle_flag = Arc::clone(&server_handle_slot);

        let starter = move || {
            *started_at_flag.lock().unwrap() = Some(std::time::Instant::now());
            // mock listener 를 시작. accept 이후 handshake 만 수행하고 close.
            let path = socket_path_for_starter.clone();
            let handle = tokio::spawn(async move {
                let listener = tokio::net::UnixListener::bind(&path).expect("listener bind");
                let (stream, _) = listener.accept().await.expect("accept");
                let (mut reader, mut writer) = stream.into_split();
                // AttachOpen 소비.
                match aic_common::attach::read_attach_frame(&mut reader).await {
                    Ok(aic_common::attach::AttachFrameKind::Client(
                        aic_common::attach::AttachClientFrame::AttachOpen { .. },
                    )) => {}
                    other => panic!("expected AttachOpen, got {other:?}"),
                }
                aic_common::attach::write_attach_server_frame(
                    &mut writer,
                    &aic_common::attach::AttachServerFrame::AttachAck {
                        protocol_version: aic_common::attach::ATTACH_PROTOCOL_VERSION,
                    },
                )
                .await
                .unwrap();
                // handshake 만 수행하고 AttachClose 가 올 때까지 대기.
                loop {
                    match aic_common::attach::read_attach_frame(&mut reader).await {
                        Ok(aic_common::attach::AttachFrameKind::Client(
                            aic_common::attach::AttachClientFrame::AttachClose { .. },
                        )) => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            });
            *server_handle_flag.lock().unwrap() = Some(handle);
            Ok::<(), String>(())
        };

        let client = attach_with_autostart_retry_inner(
            &socket_path,
            "s-retry-ok",
            Arc::clone(&metrics),
            starter,
        )
        .await
        .expect("autostart 이후 재시도는 성공해야 함");
        assert_eq!(client.session_id(), "s-retry-ok");

        // 재시도가 실제로 일어났으므로 reconnect 카운터가 1 증가했다 (R14.5).
        assert_eq!(metrics.attach_reconnect_total(), 1);
        assert!(
            started_at.lock().unwrap().is_some(),
            "starter 는 호출되어야 함"
        );

        drop(client);
        let maybe_handle = server_handle_slot.lock().unwrap().take();
        if let Some(h) = maybe_handle {
            let _ = h.await;
        }
    }

    // ── Task 4.3: R11.1 회귀 — 이미 push 된 aicd record 는 연결 끊김 후에도 유지 ──
    //
    // 요구사항 11.1: "이미 완료된 record 가 CommandRecordStore 에 push 된 상태에서
    // aic-session 프로세스가 crash 할 때, aicd CommandRecordStore 는 해당 record 를
    // 그대로 보존한다."
    //
    // aicd 프로세스는 단위 테스트에서 직접 kill 할 수 없지만, 의미론적으로 중요한 것은
    // "한번 push 된 record 는 subsequent reconnect 나 attach 닫힘에 무관하게 ring 에
    // 남는다" 는 것이다. 이를 CommandRecordStore 의 API 수준에서 직접 증명한다.

    /// 세션 A 에 record 를 push 한 뒤, 해당 세션의 attach 연결이 끊어진 것처럼 시뮬레이션
    /// (API 상으로는 아무것도 하지 않음) 하고도 `last` / `recent` 가 원래 record 를
    /// 그대로 돌려주는지 확인한다. 이는 R11.1 의 핵심 보장이다.
    #[tokio::test]
    async fn aicd_record_preserved_across_simulated_attach_disconnect() {
        use crate::command_record_store::CommandRecordStore;

        let store = CommandRecordStore::new();
        let session_id = "preserve-session-1";

        let mut rec = CommandRecord {
            command: Some("cargo test".to_string()),
            exit_code: 0,
            output_lines: vec!["ok".to_string()],
            timestamp: Utc::now(),
            capture_mode: aic_common::CaptureMode::Pty,
            ..Default::default()
        };
        rec.id = "deadbeef12345678".to_string();
        store.push_pty(session_id, rec.clone()).await;
        assert_eq!(store.len(session_id).await, 1);

        // 여기서 "attach 연결 끊김" 은 본질적으로 아무 API 호출도 하지 않는 것과 같다
        // (store 는 attach 연결 상태를 들고 있지 않다). 그 사이 다른 세션의 push 가
        // interleave 되어도 우리 세션의 record 는 영향받지 않아야 한다.
        store
            .push_pty(
                "other-session",
                CommandRecord {
                    command: Some("noise".to_string()),
                    exit_code: 1,
                    output_lines: vec![],
                    timestamp: Utc::now(),
                    capture_mode: aic_common::CaptureMode::Pty,
                    ..Default::default()
                },
            )
            .await;

        // 원본 세션의 record 는 그대로 남아야 한다.
        let preserved = store.last(session_id).await.expect("record 가 유지되어야 함");
        assert_eq!(preserved.id, "deadbeef12345678");
        assert_eq!(preserved.command.as_deref(), Some("cargo test"));
        assert_eq!(preserved.exit_code, 0);
        assert_eq!(preserved.output_lines, vec!["ok".to_string()]);

        let recent = store.recent(session_id, 10).await;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, "deadbeef12345678");
    }

    /// Local_Fallback 시나리오 시뮬레이션 — flag=true AND attach 실패 후 local path 가
    /// on-demand 로 활성화되었을 때, local push 가 정상 동작하고 store (세션별 ring)
    /// 가 격리를 유지하는지 확인한다. autostart 헬퍼 자체는 테스트 환경에서 호출하지 않고,
    /// `should_create_local_data_plane` 분기로 "local_enabled=true" 경로를 모사한다.
    #[tokio::test]
    async fn local_fallback_push_works_when_attach_missing() {
        // Central_Store_Flag=true + attach 실패 (connected=false) → Local_Fallback.
        assert!(
            should_create_local_data_plane(
                /*central_store_flag=*/ true,
                /*attach_connected=*/ false
            ),
            "flag=true 이지만 attach 실패 시 Local_Fallback 으로 local data plane 을 만들어야 함 (R9.6)"
        );

        // 해당 분기에서 생성되는 local ring buffer 를 직접 시뮬레이션.
        let rb = Arc::new(RwLock::new(RingBuffer::new(100)));
        let rec = record(Some("git log"));

        let rb_clone = Arc::clone(&rb);
        tokio::task::spawn_blocking(move || {
            // flag=true 를 유지한 채 local push 를 수행 — aicd 호출은 silent skip 되므로
            // 소켓 없는 테스트 환경에서도 안전하다.
            dispatch_record(rec, &rb_clone, "fallback-sess", /*flag=*/ true);
        })
        .await
        .expect("spawn_blocking");

        let guard = rb.read().await;
        assert_eq!(
            guard.recent_records(10).len(),
            1,
            "Local_Fallback 에서 local push 가 동작해야 함"
        );
        let stored = &guard.recent_records(10)[0];
        assert_eq!(stored.command.as_deref(), Some("git log"));
        assert!(!stored.id.is_empty(), "local push 는 id 를 자동 부여함");
    }
}

// ── Phase 3.5 전용 테스트 ─────────────────────────────────────────────
//
// Task 5.3 (R7.1, R20.1~20.3): Phase 3.5 에서는 세션 로컬 data plane 이 제거되어
// `dispatch_record` / `should_store_record` / `fan_out_chunk` / `should_create_local_data_plane`
// 관련 테스트는 compile 되지 않는다. 대신 아래 두 항목만 검증한다:
// - `attach_with_autostart_retry_inner` 자체가 Phase 3.5 빌드에서도 동일하게 작동
// - Phase 3.5 전용 `fan_out_chunk_central_only` 가 stdout/attach 양쪽에 byte-exact
#[cfg(all(test, feature = "phase-3_5"))]
mod phase_3_5_tests {
    use super::*;
    use aic_common::attach::{
        read_attach_frame, write_attach_server_frame, AttachClientFrame, AttachFrameKind,
        AttachServerFrame, ATTACH_PROTOCOL_VERSION,
    };
    use bytes::Bytes;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    /// Minimal mock attach server — handshake 후 PtyBytes chunk 를 모아준다.
    struct PhaseFiveMockServer {
        _tempdir: TempDir,
        socket_path: PathBuf,
        handle: tokio::task::JoinHandle<Vec<Bytes>>,
    }

    impl PhaseFiveMockServer {
        async fn start() -> Self {
            let tempdir = tempfile::tempdir().unwrap();
            let socket_path = tempdir.path().join("attach.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let handle = tokio::spawn(async move {
                let mut chunks: Vec<Bytes> = Vec::new();
                let (stream, _) = listener.accept().await.expect("accept");
                let (mut reader, mut writer) = stream.into_split();
                match read_attach_frame(&mut reader).await {
                    Ok(AttachFrameKind::Client(AttachClientFrame::AttachOpen { .. })) => {}
                    other => panic!("expected AttachOpen, got {other:?}"),
                }
                write_attach_server_frame(
                    &mut writer,
                    &AttachServerFrame::AttachAck {
                        protocol_version: ATTACH_PROTOCOL_VERSION,
                    },
                )
                .await
                .unwrap();
                loop {
                    match read_attach_frame(&mut reader).await {
                        Ok(AttachFrameKind::Client(AttachClientFrame::PtyBytes { bytes })) => {
                            chunks.push(bytes);
                        }
                        Ok(AttachFrameKind::Client(AttachClientFrame::AttachClose { .. })) => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                chunks
            });
            Self {
                _tempdir: tempdir,
                socket_path,
                handle,
            }
        }

        fn socket_path(&self) -> &std::path::Path {
            &self.socket_path
        }

        async fn finish(self) -> Vec<Bytes> {
            tokio::time::timeout(std::time::Duration::from_secs(2), self.handle)
                .await
                .expect("mock server timeout")
                .expect("mock server panicked")
        }
    }

    /// Phase 3.5 전용 fan_out_chunk_central_only — stdout passthrough + attach tee.
    /// 로컬 data plane 이 제거되었으므로 ring buffer / processor 경로가 없음을 재확인한다.
    #[tokio::test]
    async fn central_only_fan_out_tees_bytes_to_stdout_and_attach() {
        let server = PhaseFiveMockServer::start().await;
        let metrics = Arc::new(AttachMetrics::new());
        let attach = Arc::new(
            AttachClient::connect(
                server.socket_path(),
                "sess-p35".to_string(),
                Arc::clone(&metrics),
            )
            .await
            .expect("attach connect"),
        );

        let chunks: Vec<Vec<u8>> = vec![
            b"first-chunk\n".to_vec(),
            b"second\x1b[32mcolored\x1b[0m\n".to_vec(),
            b"third\n".to_vec(),
        ];

        let attach_for_task = Arc::clone(&attach);
        let chunks_for_task = chunks.clone();
        let collected = tokio::task::spawn_blocking(move || {
            let mut stdout: Vec<u8> = Vec::new();
            for chunk in &chunks_for_task {
                fan_out_chunk_central_only(
                    chunk,
                    &mut stdout,
                    Some(attach_for_task.as_ref()),
                );
            }
            stdout
        })
        .await
        .expect("spawn_blocking");

        let expected: Vec<u8> = chunks.iter().flatten().copied().collect();
        assert_eq!(collected, expected, "stdout passthrough 가 byte-exact 가 아님");

        drop(attach);
        let received = server.finish().await;
        let received_bytes: Vec<u8> = received
            .iter()
            .flat_map(|b| b.as_ref().iter().copied())
            .collect();
        assert_eq!(received_bytes, expected, "attach tee 가 byte-exact 가 아님");
        assert_eq!(metrics.dropped_bytes(), 0);
    }

    /// Phase 3.5 에서도 `attach_with_autostart_retry_inner` 의 첫 연결 성공 경로는
    /// autostart starter 를 호출하지 않고 reconnect 카운터도 건드리지 않는다.
    #[tokio::test]
    async fn autostart_retry_not_invoked_when_first_connect_succeeds_p35() {
        let server = PhaseFiveMockServer::start().await;
        let metrics = Arc::new(AttachMetrics::new());

        let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoked_flag = Arc::clone(&invoked);
        let starter = move || {
            invoked_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok::<(), String>(())
        };

        let client = attach_with_autostart_retry_inner(
            server.socket_path(),
            "sess-p35-retry",
            Arc::clone(&metrics),
            starter,
        )
        .await
        .expect("첫 connect 는 성공해야 함");
        assert_eq!(client.session_id(), "sess-p35-retry");
        assert!(!invoked.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(metrics.attach_reconnect_total(), 0);

        drop(client);
        let _ = server.finish().await;
    }

    /// Phase 3.5 에서 autostart starter 가 실패하면 즉시 Err 를 돌려주어 호출자(run)
    /// 가 fatal error 로 종료할 수 있도록 한다 (R7.1).
    #[tokio::test]
    async fn autostart_retry_returns_error_for_fatal_exit_p35() {
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("nope.sock");
        let metrics = Arc::new(AttachMetrics::new());

        let starter = || Err::<(), String>("aicd 바이너리 부재".to_string());
        let result =
            attach_with_autostart_retry_inner(&missing, "sess-p35-fail", metrics, starter).await;

        assert!(
            result.is_err(),
            "Phase 3.5 에서 attach 실패 경로는 Err 를 돌려주어 fatal 종료를 유도해야 함"
        );
    }
}
