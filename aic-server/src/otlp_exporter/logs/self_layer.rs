//! aicd 자체 로그(`tracing::warn!`/`error!` 등)를 OTLP 로그 파이프라인으로 흘리는
//! `tracing_subscriber::Layer` (RFC-006 t7).
//!
//! ★★★ 재귀 위험 ★★★ — 반드시 아래 두 방어를 유지한 채로만 수정할 것.
//!
//! `tracing-core`의 재진입 가드(`dispatcher::get_default`의 `can_enter` 체크)는 **전역
//! subscriber**(`set_global_default`/`.init()`)에서는 우회된다 — `SCOPED_COUNT == 0`이면 가드 없이
//! `get_global()`을 바로 호출하는 fast path를 탄다. `aicd`는 `telemetry.rs`에서 `.init()`을
//! 쓰므로, 만약 이 layer의 `on_event` 안에서 `tracing::` 매크로를 호출하면 그 즉시 무한재귀 →
//! 스택 오버플로다.
//!
//! 게다가 task 경계를 넘는 피드백 루프도 있다(스택이 갈리므로 `can_enter`가 애초에 못 잡는다):
//! exporter task가 push 실패 → `tracing::warn!` → 이 layer가 그 이벤트를 `LogLine`으로 만들어
//! 로그 채널로 `try_send` → `serve_logs`가 그 `LogLine`을 다시 push 시도 → 또 실패 →
//! `tracing::warn!` → ... 무한 루프.
//!
//! 방어 두 겹(둘 다 필수):
//!   1. 이 layer를 등록할 때 반드시 **per-layer** `.with_filter(filter_fn(...))`로
//!      [`is_loop_target`]을 적용해 exporter 자신과 그 HTTP 클라이언트(hyper/h2/reqwest/rustls/
//!      tower)가 만든 이벤트를 원천 차단한다. **전역 `EnvFilter`로 걸면 안 된다** — 그러면
//!      stderr/file 등 다른 layer에서도 그 이벤트가 사라진다(opentelemetry-rust issue #1682와
//!      동일한 함정).
//!   2. [`SelfLogLayer::on_event`] 안에서는 `tracing::` 매크로를 **절대** 호출하지 않는다. 채널이
//!      가득 차면 `dropped` 카운터만 올린다. `try_send`만 쓴다(`blocking_send`는 async
//!      컨텍스트에서 panic하므로 금지 — `on_event`는 tokio worker 스레드에서 불릴 수 있다).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use aic_common::LogLine;

use super::checkpoint::record_id;

/// 이 layer가 만든 로그를 다시 이 layer로 먹이는 경로를 원천 차단하는 target prefix 목록.
///
/// - `aic_server::otlp_exporter` : exporter 자신(push 실패 `warn!`이 곧 새 로그가 되는 경로).
/// - `hyper`/`h2`/`reqwest`/`rustls`/`tower` : exporter의 HTTP 클라이언트 내부 로그. `AIC_LOG=debug`를
///   켜는 순간 push 1건이 수십 라인을 만들어 같은 루프를 돈다.
const LOOP_TARGETS: &[&str] = &[
    "aic_server::otlp_exporter",
    "hyper",
    "h2",
    "reqwest",
    "rustls",
    "tower",
];

/// `target`이 [`LOOP_TARGETS`]에 속하는지(정확히 일치하거나 `prefix::` 하위 모듈인지) 검사한다.
/// `SelfLogLayer`를 등록할 때 반드시 이 함수로 만든 per-layer filter를 붙여야 한다 — 전역
/// `EnvFilter`로 대체하면 다른 layer(stderr/file)까지 같이 죽는다.
pub fn is_loop_target(target: &str) -> bool {
    LOOP_TARGETS
        .iter()
        .any(|p| target == *p || target.starts_with(&format!("{p}::")))
}

/// `message` 필드(및 나머지 필드)를 뽑아내는 Visitor.
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

/// `tracing::Level`을 `LogLine::severity` 문자열로 매핑한다. DEBUG/TRACE는 둘 다 "DEBUG"로 접는다
/// (OTLP severity 스키마가 4단계뿐인 다른 소스와 맞추기 위함).
fn severity_for_level(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG | Level::TRACE => "DEBUG",
    }
}

/// aicd 자체 `tracing` 이벤트를 [`LogLine`]으로 정규화해 로그 채널로 흘리는 layer.
///
/// `source = "aic"`, `service = "aicd"` 고정. `record_id`는 self 소스에 자연키가 없으므로
/// [`checkpoint::record_id`](super::checkpoint::record_id)의 내용 해시 폴백을 그대로 재사용한다.
pub struct SelfLogLayer {
    tx: mpsc::Sender<LogLine>,
    dropped: Arc<AtomicU64>,
    host: String,
}

impl SelfLogLayer {
    /// `tx`로 흘려보낼 layer를 만든다. 호스트명은 생성 시점에 1회만 조회한다(이벤트마다 조회하면
    /// `on_event`가 무거워진다).
    pub fn new(tx: mpsc::Sender<LogLine>) -> Self {
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            host: sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string()),
        }
    }

    /// 채널이 가득 차 드롭된 이벤트 수. `on_event` 안에서 `tracing::`을 호출할 수 없으므로(재귀
    /// 위험) 로그 대신 이 카운터로만 관측한다.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// `dropped` 카운터의 핸들을 복제한다. `.with_filter(..)`로 self를 소비하기 전에 호출해 두면
    /// 이후에도 드롭 수를 관측할 수 있다(테스트/헬스체크 용도).
    pub fn dropped_counter(&self) -> Arc<AtomicU64> {
        self.dropped.clone()
    }
}

impl<S: Subscriber> Layer<S> for SelfLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let mut attrs = visitor.attrs;
        attrs.insert("target".to_string(), event.metadata().target().to_string());

        // 원본이 데몬 경계를 넘지 않는 게 1차 방어선 — 로컬 파일/stderr에는 이미 원문이 남지만,
        // 중앙 collector로 나가는 이 경로는 반드시 redact를 거친다.
        let (message, _) = aic_common::redaction::redact(&visitor.message);

        let mut line = LogLine {
            source: "aic".to_string(),
            service: "aicd".to_string(),
            severity: severity_for_level(event.metadata().level()).to_string(),
            message,
            attrs,
            // self 소스는 발생=수집이라 지연 0.
            ts: chrono::Utc::now(),
            record_id: String::new(),
        };
        line.record_id = record_id(None, &self.host, &line);

        // on_event는 sync fn — .await 불가하므로 try_send만 쓴다. blocking_send는 async
        // 컨텍스트(tokio worker 스레드)에서 panic하므로 절대 금지. 실패해도 tracing:: 매크로를
        // 호출하지 않는다(재귀 방지) — 카운터만 올린다.
        if self.tx.try_send(line).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::SubscriberExt;

    /// `f` 실행 동안만 유효한 scoped subscriber(`SelfLogLayer` + 프로덕션과 동일한 LOOP_TARGETS
    /// per-layer filter)를 설치하고, 그 안에서 발생한 이벤트가 흘러든 채널과 dropped 카운터
    /// 핸들을 돌려준다.
    fn capture_events<F: FnOnce()>(
        capacity: usize,
        f: F,
    ) -> (mpsc::Receiver<LogLine>, Arc<AtomicU64>) {
        let (tx, rx) = mpsc::channel(capacity);
        let layer = SelfLogLayer::new(tx);
        let dropped = layer.dropped_counter();
        let filtered = layer.with_filter(filter_fn(|md| !is_loop_target(md.target())));
        let subscriber = tracing_subscriber::registry().with(filtered);
        tracing::subscriber::with_default(subscriber, f);
        (rx, dropped)
    }

    #[test]
    fn message_visitor_extracts_from_record_debug() {
        // warn!("텍스트") — 암시적 message 필드는 fmt::Arguments → record_debug로 잡힌다.
        // target을 명시하는 이유: 기본 target(호출 모듈 경로)이 이 테스트 자신처럼
        // `aic_server::otlp_exporter::...` 아래일 경우 LOOP_TARGETS에 걸려 필터링되기 때문 —
        // loop-target 필터링 자체는 별도 테스트(loop_targets_are_filtered)가 검증한다.
        let (mut rx, _dropped) = capture_events(8, || {
            tracing::warn!(target: "aic_server::web", "텍스트 메시지");
        });
        let line = rx.try_recv().expect("이벤트가 채널에 들어와야 함");
        assert_eq!(line.message, "텍스트 메시지");
    }

    #[test]
    fn message_visitor_extracts_from_record_str() {
        // message 필드에 &str을 직접(sigil 없이) 넘기면 record_str로 온다.
        let (mut rx, _dropped) = capture_events(8, || {
            tracing::warn!(target: "aic_server::web", message = "다이렉트 문자열 메시지");
        });
        let line = rx.try_recv().expect("이벤트가 채널에 들어와야 함");
        assert_eq!(line.message, "다이렉트 문자열 메시지");
    }

    #[test]
    fn loop_targets_are_filtered() {
        let (mut rx, _dropped) = capture_events(8, || {
            tracing::warn!(target: "aic_server::otlp_exporter::logs", "루프1");
            tracing::warn!(target: "hyper::client", "루프2");
            tracing::warn!(target: "reqwest", "루프3");
            tracing::warn!(target: "aic_server::web", "정상 타겟");
        });

        let mut messages = Vec::new();
        while let Ok(line) = rx.try_recv() {
            messages.push(line.message);
        }
        assert_eq!(
            messages,
            vec!["정상 타겟".to_string()],
            "LOOP_TARGETS는 채널에 안 들어오고, 그 외 target은 들어와야 함"
        );
    }

    #[test]
    fn channel_full_increments_counter_without_logging() {
        // 용량 1 — 첫 이벤트로 채널이 가득 차고, 아무도 드레인하지 않는다.
        let (rx, dropped) = capture_events(1, || {
            tracing::warn!(target: "aic_server::web", "첫 번째");
            tracing::warn!(target: "aic_server::web", "두 번째"); // try_send 실패해야 함
            tracing::warn!(target: "aic_server::web", "세 번째"); // 역시 실패
        });
        drop(rx); // 의도적으로 드레인하지 않은 채로 스코프를 벗어난다 — panic이 없어야 한다.

        assert_eq!(
            dropped.load(Ordering::Relaxed),
            2,
            "채널이 가득 찬 뒤의 이벤트만큼 dropped가 늘어야 함"
        );
    }

    #[test]
    fn level_maps_to_severity() {
        assert_eq!(severity_for_level(&Level::ERROR), "ERROR");
        assert_eq!(severity_for_level(&Level::WARN), "WARN");
        assert_eq!(severity_for_level(&Level::INFO), "INFO");
        assert_eq!(severity_for_level(&Level::DEBUG), "DEBUG");
        assert_eq!(severity_for_level(&Level::TRACE), "DEBUG");
    }

    #[test]
    fn message_is_redacted() {
        // bearer_token 패턴은 entropy 게이트가 없는(is_secret=false) 정형 매칭이라 항상 마스킹된다.
        let (mut rx, _dropped) = capture_events(8, || {
            tracing::warn!(
                target: "aic_server::web",
                "Authorization: Bearer abcdefghijklmnop1234567890 유출됨"
            );
        });
        let line = rx.try_recv().expect("이벤트가 채널에 들어와야 함");
        assert!(
            line.message.contains("[REDACTED:bearer_token]"),
            "시크릿이 마스킹되어야 함: {}",
            line.message
        );
        assert!(
            !line.message.contains("abcdefghijklmnop1234567890"),
            "원본 토큰이 그대로 남아있으면 안 됨"
        );
    }
}
