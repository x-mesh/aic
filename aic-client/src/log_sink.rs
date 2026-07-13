//! `aic-client`(chat 등) 자체 로그를 aicd로 흘려보내는 최초의 tracing subscriber (RFC-006 t11).
//!
//! ★★★ 먼저 알아야 할 사실 두 가지 ★★★
//!
//! **(1) 이전까지 `aic-client`에는 tracing subscriber가 없었다.** `Cargo.toml`이 `tracing`
//! facade만 의존했고 `tracing-subscriber`는 없었으므로, [`init`]을 호출하기 전까지 크레이트 안의
//! 모든 `tracing::` 매크로는 **no-op**이었다. 이 모듈은 "Layer 추가"가 아니라 subscriber의
//! **최초 도입**이다.
//!
//! **(2) `Drop` 가드는 여기서 무용지물이다.** `aic-client/src/main.rs`에는 `std::process::exit()`
//! 호출이 40곳 넘게 흩어져 있다(`grep -c "process::exit" aic-client/src/main.rs`). `Drop`은
//! `std::process::exit()`에서 절대 돌지 않는다 — `tracing_appender`의 `WorkerGuard` 패턴은
//! `aicd`(`main` 정상 반환으로 끝남)에는 맞지만 `aic-client`에는 맞지 않는다. 실측으로 확인한
//! 유일하게 확실한 종료 시점 flush 지점은 **`libc::atexit`**뿐이다 — `std::process::exit`에서도,
//! 정상 return에서도, panic(unwind, 워크스페이스에 `panic = "abort"` 설정 없음)에서도 돈다.
//!
//! ## `debug_log!`(main.rs)와의 관계 — 통합하지 않고 공존시킨다
//!
//! `main.rs`의 `debug_log!`/`debug_step!`은 `AIC_DEBUG` 환경변수로 켜는 사람이 직접 읽는
//! **로컬 stderr 디버그 출력**이다 — subscriber도, 채널도, IPC도 필요 없이 즉시 `eprintln!`한다.
//! 이 모듈이 제공하는 `tracing::` 파이프라인은 반대로 **프로세스 경계를 넘어 aicd → OTLP
//! collector로 나가는 중앙 관측 채널**이다. 목적(로컬 즉석 디버깅 vs 중앙 RCA/관측)과 대상
//! 독자(그 자리의 개발자 vs 사후에 로그를 보는 운영자)가 다르고, `debug_log!`를 `tracing::`으로
//! 옮기면 40여 개 호출부를 건드려야 하는 데 비해 이 태스크가 얻는 이득이 없다. 그래서 **통합하지
//! 않고 공존**시킨다 — `debug_log!`는 그대로 두고, 이 모듈은 `tracing::` 매크로(주로 라이브러리
//! 코드와 향후 추가될 구조적 이벤트)만 aicd로 흘린다.
//!
//! ## 재귀 차단
//!
//! `self_layer.rs`(t7, aicd 쪽)와 같은 함정을 피하기 위해 [`ClientLogLayer::on_event`] 안에서는
//! `tracing::` 매크로를 **절대** 호출하지 않는다 — 실패는 드롭 카운터로만 관측한다
//! (`on_event_never_calls_tracing_macros` 테스트가 구조적으로 이를 grep 가능한 형태로 보증한다).
//!
//! ## 커버하지 못하는 종료 경로
//!
//! `SIGKILL`, `SIGSEGV`, `abort()`, 그리고 기본 처분(default disposition)으로 종료되는
//! `SIGINT`/`SIGTERM`(예: 터미널에서 Ctrl-C를 눌렀을 때 시그널 핸들러가 없으면 커널이 바로
//! 프로세스를 죽인다)은 `atexit`이 돌지 않아 버퍼가 유실된다. `aic chat`처럼 이미 tokio 런타임
//! 안에서 오래 도는 서브커맨드는 `tokio::signal::ctrl_c()`로 SIGINT를 잡아 flush 후 종료하는 게
//! 정공법이지만, 이 태스크(t11) 범위에는 포함하지 않는다 — **TODO(t12 또는 후속 태스크)**.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

use aic_common::{encode_frame, IpcRequest, LogLine};

/// 버퍼 최대 라인 수. 이 이상은 **최신 라인을 버리는(newest-drop)** 정책 — 이미 쌓인 라인은
/// 그대로 두고 넘치는 새 이벤트만 드롭 카운터에 반영한다(FIFO 순서를 어지럽히지 않는다).
const BUFFER_CAP: usize = 256;

/// 주기 flush 간격.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// atexit/주기 flush의 소켓 IO 상한. aicd가 hang이어도 프로세스 종료(또는 flush 한 사이클)를
/// 300ms 이상 붙잡지 않는다 — shell prompt latency 규약.
const IO_TIMEOUT: Duration = Duration::from_millis(300);

/// 응답 본문 상한 — 손상된 길이 헤더가 거대한 할당으로 이어지지 않게 막는다.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// 전역 버퍼(process-wide singleton). `init()`이 채우고, tracing 이벤트가 계속 여기로
/// `push()`되며, 주기/종료 flush가 `drain`한다. 로직 자체는 [`LogBuffer`]로 분리해 유닛
/// 테스트가 이 전역 상태를 거치지 않고 독립적으로 검증할 수 있게 한다.
static BUF: OnceLock<Arc<LogBuffer>> = OnceLock::new();

fn global_buffer() -> Arc<LogBuffer> {
    BUF.get_or_init(|| Arc::new(LogBuffer::new(BUFFER_CAP)))
        .clone()
}

/// 라인 버퍼 + drop 카운터. bounded, newest-drop.
struct LogBuffer {
    lines: Mutex<Vec<LogLine>>,
    dropped: AtomicU64,
    cap: usize,
}

impl LogBuffer {
    fn new(cap: usize) -> Self {
        Self {
            lines: Mutex::new(Vec::with_capacity(cap)),
            dropped: AtomicU64::new(0),
            cap,
        }
    }

    /// 라인 하나를 추가한다. 가득 차 있으면 새 라인을 버리고 카운터만 올린다(newest-drop).
    /// lock이 poisoned이어도(과거에 이 lock을 쥔 채 다른 스레드가 패닉) 패닉 전파 없이
    /// 내용을 그대로 이어서 쓴다 — 이 크리티컬 섹션 자체는 panic 위험이 없는 순수 push라
    /// poison은 사실상 발생하지 않지만, 방어적으로 처리한다.
    fn push(&self, line: LogLine) {
        let mut guard = match self.lines.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() >= self.cap {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            guard.push(line);
        }
    }

    /// 블로킹으로 버퍼를 통째로 비워 반환한다 — 경합 걱정이 없는 경로(주기 flush)에서 쓴다.
    fn drain_blocking(&self) -> Vec<LogLine> {
        match self.lines.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        }
    }

    /// 논블로킹으로 버퍼를 통째로 비워 반환한다. **데드락 회피가 최우선**인 경로(atexit)에서
    /// 쓴다 — `std::process::exit()`를 부른 스레드가 하필 이 lock을 쥔 채로 죽었을 수 있으므로
    /// `try_lock`만 쓰고, 경합이면 즉시 `None`을 반환한다(재시도하지 않는다).
    fn try_drain(&self) -> Option<Vec<LogLine>> {
        let mut guard = self.lines.try_lock().ok()?;
        if guard.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut *guard))
    }

    #[cfg(test)]
    fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// `message` 필드(및 나머지 필드)를 뽑아내는 Visitor.
///
/// **`aic-server/src/otlp_exporter/logs/self_layer.rs`(t7)의 `MessageVisitor`를 그대로
/// 복제한 것이다** — crate 경계(`aic-server` ↔ `aic-client`)를 넘어 재사용할 공개 API가 없어
/// (self_layer 쪽은 aicd 내부 전용 모듈), `aic-common`으로 올리는 대신 이 파일에 복제해 두는
/// 편이 t7 소유 파일을 건드리지 않고도 안전하다고 판단했다.
///
/// `tracing::warn!("텍스트 {x}")`의 `message` 필드는 `fmt::Arguments`로 기록되므로
/// `record_debug`에서 잡힌다(`record_str`가 아니다). `message = "리터럴"`처럼 `&str`/`String`을
/// 직접 넘긴 경우는 `record_str`로 온다 — 둘 다 처리해야 어느 형태든 message를 놓치지 않는다.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    attrs: BTreeMap<String, String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.attrs
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.attrs
                .insert(field.name().to_string(), value.to_string());
        }
    }
}

/// `tracing::Level`을 `LogLine::severity` 문자열로 매핑한다(`self_layer.rs`와 동일 규칙).
fn severity_for_level(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG | Level::TRACE => "DEBUG",
    }
}

/// 멱등키. `aic-server/.../checkpoint.rs`의 `record_id` 내용 해시 폴백과 **동일한 로직의
/// 복제본**이다 — 그 함수는 `aic-server` 내부 전용 모듈(`pub(crate)` 성격)이라 크레이트
/// 경계 너머에서 재사용할 수 없다. `aic` self 소스는 자연키가 없으므로 항상 이 폴백을 탄다.
fn content_hash_record_id(host: &str, line: &LogLine) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    host.hash(&mut h);
    line.source.hash(&mut h);
    line.service.hash(&mut h);
    line.ts.timestamp_millis().hash(&mut h);
    line.message.hash(&mut h);
    format!("log:{:016x}", h.finish())
}

/// `aic-client` 자체 `tracing` 이벤트를 [`LogLine`]으로 정규화해 [`LogBuffer`]에 쌓는 layer.
///
/// `source = "aic"`, `service = "aic-client"` 고정.
struct ClientLogLayer {
    host: String,
    buf: Arc<LogBuffer>,
}

impl<S: Subscriber> Layer<S> for ClientLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let mut attrs = visitor.attrs;
        attrs.insert("target".to_string(), event.metadata().target().to_string());

        // 원본이 프로세스 경계를 넘지 않는 게 1차 방어선 — aicd 인코딩 단계에서 한 번 더
        // redact되지만(idempotent), 여기서 먼저 마스킹한다(self_layer.rs와 동일 관례).
        let (message, _) = aic_common::redaction::redact(&visitor.message);

        let mut line = LogLine {
            source: "aic".to_string(),
            service: "aic-client".to_string(),
            severity: severity_for_level(event.metadata().level()).to_string(),
            message,
            attrs,
            ts: chrono::Utc::now(),
            record_id: String::new(),
        };
        line.record_id = content_hash_record_id(&self.host, &line);

        // on_event는 sync fn이라 .await 불가 — LogBuffer::push는 순수 lock+push라 블로킹
        // 구간이 짧다. 재귀 방지를 위해 여기서는 tracing:: 매크로를 절대 호출하지 않는다
        // (on_event_never_calls_tracing_macros 테스트가 이를 구조적으로 검증한다).
        self.buf.push(line);
    }
}

/// tracing subscriber를 설치하고 종료/주기 flush를 배선한다. `main()` 진입 직후 1회만
/// 호출한다. `#[tokio::main] async fn main()` 본문에서 호출되므로 tokio 런타임 핸들은 항상
/// 존재하지만, 방어적으로 확인한다(런타임 밖에서 호출되는 테스트 등 대비).
pub fn init() {
    let buf = global_buffer();

    let host = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let layer = ClientLogLayer {
        host,
        buf: buf.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    // 이미 전역 subscriber가 설치되어 있으면(예: 테스트 하네스) 조용히 무시한다 — panic 금지.
    let _ = subscriber.try_init();

    // 종료 시점 flush. Drop이 아니라 atexit을 쓴다 — main.rs에 std::process::exit()가 40여
    // 곳 흩어져 있고 Drop을 돌지 않기 때문(모듈 doc 참고).
    // SAFETY: atexit 훅은 시그널 핸들러가 아니라 일반 실행 컨텍스트(exit() 호출 스레드)에서
    // 돌므로 여기서 lock/IO를 쓰는 게 허용된다. 다만 exit()를 부른 스레드가 하필 버퍼 lock을
    // 쥔 채 죽었을 가능성은 있으므로 `flush_at_exit`/`LogBuffer::try_drain`이 try_lock으로
    // 방어한다.
    unsafe {
        libc::atexit(flush_at_exit);
    }

    // 주기 flush(2s) — `aic chat`처럼 오래 도는 서브커맨드에서 종료 전에도 로그가 나가게
    // 한다. init()은 `#[tokio::main] async fn main()` 안에서 호출되므로 핸들은 항상
    // 존재하지만, 유닛 테스트 등 런타임 밖 호출에 대비해 확인한다.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(periodic_flush_loop(buf));
    }
}

/// 2초 주기로 버퍼를 비워 aicd로 보낸다. 기존 async IPC 클라이언트(`UdsClient`)를 재사용한다.
/// 전송 실패(aicd 미실행 등)는 무시한다 — best-effort 텔레메트리다(agent_event.rs와 동일 관례).
/// 실패 시 이미 드레인한 라인은 재시도 없이 유실된다(atexit이 마지막 안전망이 아니라 각
/// 주기가 독립적인 fire-and-forget이라는 뜻) — 이 태스크의 계약대로 종료 시점 유실 방지가
/// 목표이지 전송 신뢰성 자체를 보장하지 않는다.
async fn periodic_flush_loop(buf: Arc<LogBuffer>) {
    loop {
        tokio::time::sleep(FLUSH_INTERVAL).await;
        let lines = buf.drain_blocking();
        if lines.is_empty() {
            continue;
        }
        let client = crate::uds_client::UdsClient::new(resolve_aicd_socket());
        let _ = client.send_raw(IpcRequest::PushLogLines { lines }).await;
    }
}

/// 종료 시점 flush 훅. `libc::atexit`은 인자를 받지 않는 plain fn pointer만 등록할 수 있어
/// 전역 [`BUF`]를 직접 참조한다(클로저 캡처 불가).
extern "C" fn flush_at_exit() {
    let Some(buf) = BUF.get() else { return };
    if let Some(lines) = buf.try_drain() {
        let _ = blocking_push(&resolve_aicd_socket(), lines);
    }
}

/// blocking `UnixStream`으로 `lines`를 한 번에 aicd로 보낸다.
///
/// atexit이 도는 시점에는 tokio 런타임이 이미 없거나 종료 중이라 **런타임에 의존할 수 없다**
/// (`Handle::block_on`은 이 시점에 panic한다) — 그래서 `std::os::unix::net::UnixStream`을
/// 직접 연다. 실패(aicd 미실행, 소켓 아님, 권한 없음, hang)는 전부 조용히 무시한다 —
/// best-effort이고, 종료 경로에서 사용자를 붙잡으면 안 된다(300ms IO_TIMEOUT).
fn blocking_push(socket_path: &Path, lines: Vec<LogLine>) -> std::io::Result<()> {
    let req = IpcRequest::PushLogLines { lines };
    let payload = serde_json::to_vec(&req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut sock = UnixStream::connect(socket_path)?;
    sock.set_write_timeout(Some(IO_TIMEOUT))?;
    sock.set_read_timeout(Some(IO_TIMEOUT))?;
    sock.write_all(&encode_frame(&payload))?;
    sock.flush()?;

    // 응답을 읽어 소비한다(값은 안 쓴다) — 곧바로 끊으면 aicd 쪽에 "클라이언트 조기 종료"
    // 경고가 남는다(agent_event.rs와 동일 관례). read_timeout이 걸려 있으므로 aicd가 응답을
    // 주지 않아도(hung) 여기서 300ms 넘게 블로킹되지 않는다 — 실패해도 무시.
    let mut len_buf = [0u8; 4];
    if sock.read_exact(&mut len_buf).is_ok() {
        let len = u32::from_be_bytes(len_buf) as usize;
        if len <= MAX_RESPONSE_BYTES {
            let mut body = vec![0u8; len];
            let _ = sock.read_exact(&mut body);
        }
    }
    Ok(())
}

/// aicd 소켓 경로. 테스트에서 `AIC_LOG_SINK_AICD_SOCKET`으로 override할 수 있다 — 실제 aicd
/// 소켓 경로(`aic_common::aicd_socket_path()`)는 uid당 하나로 고정돼 있어, 서브프로세스
/// 통합테스트가 격리된 mock 소켓을 쓰려면 이 훅이 필요하다. 프로덕션 코드(다른 모든
/// `aicd_socket_path()` 호출부)는 그대로 두고 이 함수 안에서만 분기한다.
fn resolve_aicd_socket() -> PathBuf {
    std::env::var_os("AIC_LOG_SINK_AICD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(aic_common::aicd_socket_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Instant;

    fn sample_line(msg: &str) -> LogLine {
        LogLine {
            source: "aic".to_string(),
            service: "aic-client".to_string(),
            severity: "INFO".to_string(),
            message: msg.to_string(),
            attrs: BTreeMap::new(),
            ts: chrono::Utc::now(),
            record_id: format!("log:{msg}"),
        }
    }

    // ── LogBuffer 단위 테스트 ──────────────────────────────────────

    #[test]
    fn buffer_saturation_drops_newest_and_counts() {
        let buf = LogBuffer::new(2);
        buf.push(sample_line("a"));
        buf.push(sample_line("b"));
        buf.push(sample_line("c")); // 초과 — 드롭(newest-drop)
        buf.push(sample_line("d")); // 역시 드롭

        let drained = buf.drain_blocking();
        assert_eq!(drained.len(), 2, "cap을 넘는 라인은 버퍼에 들어가면 안 됨");
        assert_eq!(drained[0].message, "a", "먼저 들어온 라인이 보존되어야 함");
        assert_eq!(drained[1].message, "b");
        assert_eq!(buf.dropped_count(), 2, "넘친 2줄만큼 카운터가 올라야 함");
    }

    #[test]
    fn atexit_hook_uses_try_lock_and_returns_on_contention() {
        // flush_at_exit이 실제로 부르는 LogBuffer::try_drain을 직접 검증한다 — lock이 다른
        // 스레드에 쥐어져 있으면(exit()를 부른 스레드가 하필 lock을 쥔 채 죽는 시나리오를
        // 흉내) 즉시 None을 반환해야 한다(데드락 0).
        let buf = Arc::new(LogBuffer::new(8));
        buf.push(sample_line("queued"));

        let held = buf.clone();
        let barrier = Arc::new(Barrier::new(2));
        let barrier2 = barrier.clone();
        let handle = thread::spawn(move || {
            let _guard = held.lines.lock().unwrap();
            barrier2.wait();
            thread::sleep(Duration::from_millis(200));
        });
        barrier.wait(); // 다른 스레드가 lock을 쥔 뒤에만 진행한다.

        let start = Instant::now();
        let result = buf.try_drain();
        let elapsed = start.elapsed();

        assert!(
            result.is_none(),
            "lock 경합 중엔 즉시 None을 반환해야 함(데드락 회피)"
        );
        assert!(
            elapsed < Duration::from_millis(100),
            "try_lock은 즉시 반환해야 함(블로킹 없음): {elapsed:?}"
        );

        handle.join().unwrap();
    }

    // ── blocking_push 단위 테스트 ──────────────────────────────────

    #[test]
    fn blocking_push_times_out_on_hung_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("hung.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        thread::spawn(move || {
            // accept만 하고 아무것도 읽지 않는다 — 응답 없는 hang을 흉내.
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(Duration::from_secs(2));
                drop(stream);
            }
        });

        let lines = vec![sample_line("hung")];
        let start = Instant::now();
        let _ = blocking_push(&sock_path, lines);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(600),
            "IO_TIMEOUT(300ms) 근처에서 반환해야 함(hang에 매몰되면 안 됨): {elapsed:?}"
        );
    }

    #[test]
    fn socket_missing_or_not_a_socket_is_silent() {
        let dir = tempfile::tempdir().unwrap();

        // 1) 소켓 파일 자체가 없음.
        let missing = dir.path().join("missing.sock");
        let result = std::panic::catch_unwind(|| blocking_push(&missing, vec![sample_line("x")]));
        assert!(
            result.is_ok(),
            "존재하지 않는 소켓 경로에서 panic이 나면 안 됨"
        );
        assert!(
            result.unwrap().is_err(),
            "존재하지 않는 소켓은 연결 실패(Err)해야 함"
        );

        // 2) 소켓이 아니라 일반 파일.
        let not_a_socket = dir.path().join("plain.txt");
        std::fs::write(&not_a_socket, b"not a socket").unwrap();
        let result =
            std::panic::catch_unwind(|| blocking_push(&not_a_socket, vec![sample_line("y")]));
        assert!(
            result.is_ok(),
            "일반 파일에 연결 시도해도 panic이 나면 안 됨"
        );
        assert!(result.unwrap().is_err());

        // 3) 권한 없음 — 소유자 권한을 모두 제거한 소켓(root로 도는 CI에서는 무시될 수 있어
        // 반환값 자체는 단언하지 않는다. panic 0만 검증한다).
        let no_perm = dir.path().join("no-perm.sock");
        let listener = std::os::unix::net::UnixListener::bind(&no_perm).unwrap();
        std::fs::set_permissions(&no_perm, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = std::panic::catch_unwind(|| blocking_push(&no_perm, vec![sample_line("z")]));
        drop(listener);
        assert!(
            result.is_ok(),
            "권한 없는 소켓에 연결 시도해도 panic이 나면 안 됨"
        );
    }

    // ── MessageVisitor / redaction / severity ──────────────────────

    /// `f` 실행 동안만 유효한 scoped subscriber를 설치하고, 그 안에서 발생한 이벤트가 쌓인
    /// 버퍼를 돌려준다. 전역 [`BUF`]를 거치지 않는 독립 인스턴스라 병렬 테스트 간 간섭이 없다.
    fn capture_events<F: FnOnce()>(f: F) -> Vec<LogLine> {
        let buf = Arc::new(LogBuffer::new(64));
        let layer = ClientLogLayer {
            host: "test-host".to_string(),
            buf: buf.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        buf.drain_blocking()
    }

    #[test]
    fn message_visitor_extracts_from_record_debug() {
        // warn!("텍스트") — 암시적 message 필드는 fmt::Arguments → record_debug로 잡힌다.
        let lines = capture_events(|| {
            tracing::warn!(target: "aic_client::test", "텍스트 메시지");
        });
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].message, "텍스트 메시지");
        assert_eq!(lines[0].source, "aic");
        assert_eq!(lines[0].service, "aic-client");
        assert_eq!(lines[0].severity, "WARN");
    }

    #[test]
    fn message_visitor_extracts_from_record_str() {
        // message 필드에 &str을 직접(sigil 없이) 넘기면 record_str로 온다.
        let lines = capture_events(|| {
            tracing::warn!(target: "aic_client::test", message = "다이렉트 문자열 메시지");
        });
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].message, "다이렉트 문자열 메시지");
    }

    #[test]
    fn message_is_redacted() {
        let lines = capture_events(|| {
            tracing::warn!(
                target: "aic_client::test",
                "Authorization: Bearer abcdefghijklmnop1234567890 유출됨"
            );
        });
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].message.contains("[REDACTED:bearer_token]"),
            "시크릿이 마스킹되어야 함: {}",
            lines[0].message
        );
        assert!(!lines[0].message.contains("abcdefghijklmnop1234567890"));
    }

    #[test]
    fn level_maps_to_severity() {
        assert_eq!(severity_for_level(&Level::ERROR), "ERROR");
        assert_eq!(severity_for_level(&Level::WARN), "WARN");
        assert_eq!(severity_for_level(&Level::INFO), "INFO");
        assert_eq!(severity_for_level(&Level::DEBUG), "DEBUG");
        assert_eq!(severity_for_level(&Level::TRACE), "DEBUG");
    }

    // ── 재귀 방지 구조적 보증 ────────────────────────────────────────

    /// `on_event` 함수 본문 안에 `tracing::` 매크로 호출이 전혀 없음을 소스 텍스트로 직접
    /// 검증한다 — self_layer.rs(t7)와 동일한 함정(실패가 다시 로그가 되는 무한루프)을
    /// 구조적으로 차단했다는 근거를 grep 가능한 형태로 남긴다.
    #[test]
    fn on_event_never_calls_tracing_macros() {
        let src = include_str!("log_sink.rs");
        let start = src.find("fn on_event(").expect("on_event 정의를 찾아야 함");
        let after_start = &src[start..];
        let open = after_start.find('{').expect("on_event 본문 시작 `{`");

        let mut depth = 0i32;
        let mut end = None;
        for (i, ch) in after_start[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("on_event 본문 끝 `}`를 찾아야 함");
        let body = &after_start[open..=end];

        // `//` 라인 주석을 제거한 뒤 검사한다 — 이 파일의 주석 자체가 설명을 위해
        // "tracing::"이라는 문자열을 언급하므로(예: 이 테스트 바로 위 코드 주석), 주석까지
        // 그대로 검사하면 실제 호출이 없어도 오탐한다. 실제 코드에서 tracing:: 매크로를
        // 호출하는지만 본다.
        let code_only: String = body
            .lines()
            .map(|line| match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !code_only.contains("tracing::"),
            "on_event 안에서 tracing:: 매크로를 호출하면 재귀 위험이 있다(self_layer.rs와 \
             동일한 함정): {code_only}"
        );
    }
}
