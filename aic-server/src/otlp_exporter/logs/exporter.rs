//! aicd log collector 배치 exporter (RFC-006 t5).
//!
//! `mpsc::Receiver<LogLine>`을 소비해 라인을 버퍼에 모았다가, **`batch_max_lines`에 도달하거나
//! `batch_max_ms`가 지나면(먼저 도달하는 쪽) 한 번에 flush**한다 — 라인당 HTTP 요청을 하지
//! 않는다. 소스는 아직 없다(t3/journald 등 후속 태스크가 채운다); 이 task는 채널 upstream이
//! 누구든 상관없이 배치+전송만 담당한다.
//!
//! 구조는 [`super::super::events`](super::super::events)(tap 기반 push)의 관례를 그대로 따른다
//! (자체 `Backoff`/`reqwest::Client` 소유, push 실패 시 spool 적재, health 카운터 갱신, shared
//! shutdown watch 구독) — 다만 이벤트마다 즉시 전송하는 events와 달리 여기는 **배치**가 핵심이다.
//! 타이머는 빈 버퍼에서 매 `batch_max_ms`마다 깨어나 아무 일도 안 하는 낭비를 피하기 위해
//! **첫 라인이 버퍼에 들어온 시점부터** 잰다 — 버퍼가 비어 있는 동안은 데드라인 자체가 없다
//! (`tokio::select!`가 `rx.recv()`/`shutdown.changed()`만 겨룬다).
//!
//! ★ 불변식 ★
//!   - **`spool.drain()`을 호출하지 않는다.** 드레인 주체는 host metrics task(`serve`) 하나뿐이다
//!     (`super::super` 모듈 doc 26-29줄 참고) — 이 task는 append-only다.
//!   - `Backoff`는 이 task가 자체 소유한다(공유 금지 — events.rs 관례와 동일).
//!   - `reqwest::Client`도 이 task가 자체 생성한다(`HTTP_TIMEOUT` 10s, 다른 task들과 동일).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use aic_common::{AicdLogsConfig, LogLine};

use super::super::backoff::Backoff;
use super::super::logs_proto::{self, ResourceAttrs};
use super::super::{ExporterHealth, SignalKind, Spool};
use super::{filter, DropCounters, Limiter};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// logs exporter 실행 설정.
#[derive(Clone)]
pub struct LogsExporterConfig {
    /// OTLP collector base URL. `/v1/logs`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 이 줄 수에 도달하면 즉시 flush한다. 권장 기본값 500.
    pub batch_max_lines: usize,
    /// 첫 라인이 버퍼에 들어온 시점부터 이 시간(ms)이 지나면 flush한다. 권장 기본값 2000.
    pub batch_max_ms: u64,
    /// 오프라인 spool(SRE t8). 다른 exporter config와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 다른 exporter task와 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<ExporterHealth>,
    /// `[aicd.logs]` 설정(SRE t6 볼륨 안전장치) — min_severity/서비스 override/rate limit을
    /// 여기서 읽는다. batch_max_lines/batch_max_ms는 위 필드로 이미 분리되어 있어 이 struct와
    /// 중복되지만, filter/limiter는 나머지 필드(min_severity, services, max_lines_per_sec,
    /// max_services)가 필요해 통째로 들고 있는 편이 자연스럽다.
    pub logs_cfg: AicdLogsConfig,
    /// 드롭 사유별 카운터(severity/rate_limit) — `encode.rs`가 `aic.log.dropped`로 노출한다.
    /// 다른 exporter task와 공유해 metrics tick이 최신 값을 읽게 한다.
    pub drop_counters: Arc<DropCounters>,
}

/// 배치 축적 + flush 상태를 묶는다. `serve_logs`의 select 루프에서 참조를 여러 번 흩뿌리는
/// 대신 메서드로 캡슐화해 둔다.
struct LogsFlusher {
    cfg: LogsExporterConfig,
    client: reqwest::Client,
    url: String,
    host_name: String,
    host_id: String,
    os_type: String,
    backoff: Backoff,
    buffer: Vec<LogLine>,
    /// 다음 flush 데드라인. 버퍼가 비어 있는 동안은 `None`(타이머 없음).
    deadline: Option<Instant>,
    /// 서비스당 token-bucket rate limiter(SRE t6). severity 필터를 통과한 라인만 여기를 거친다.
    limiter: Limiter,
}

impl LogsFlusher {
    /// 라인 하나를 볼륨 안전장치(min_severity → rate limit, 이 순서가 비용이 싼 쪽부터)에
    /// 통과시킨다. 드롭되면 `false`를 반환하고 `DropCounters`만 올린다 — **합성 `LogLine`을
    /// 만들어 버퍼에 넣지 않는다**(모듈 doc 불변식).
    fn gate(&mut self, line: &LogLine) -> bool {
        if !filter::passes_severity(line, &self.cfg.logs_cfg) {
            self.cfg
                .drop_counters
                .by_severity
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if !self.limiter.try_acquire(&line.service) {
            self.cfg
                .drop_counters
                .by_rate_limit
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// 라인을 버퍼에 쌓는다. 버퍼가 비어 있다가 채워지는 순간에만 데드라인을 새로 잡는다 —
    /// 이미 대기 중인 배치의 데드라인을 뒤로 미루지 않는다(먼저 들어온 라인 기준으로 고정).
    fn push_line(&mut self, line: LogLine) {
        if self.buffer.is_empty() {
            self.deadline = Some(Instant::now() + Duration::from_millis(self.cfg.batch_max_ms));
        }
        self.buffer.push(line);
    }

    fn should_flush_on_size(&self) -> bool {
        self.buffer.len() >= self.cfg.batch_max_lines
    }

    /// 현재 버퍼를 인코딩해 전송을 시도한다. 빈 버퍼는 no-op(빈 배치를 push/spool 어느 쪽에도
    /// 남기지 않는다).
    async fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.buffer);
        self.deadline = None;

        let resource = ResourceAttrs {
            host_name: &self.host_name,
            host_id: &self.host_id,
            os_type: &self.os_type,
            host_ip: None,
        };
        let body = logs_proto::encode_log_line(&batch, &resource, &self.cfg.service_version);

        if !self.backoff.ready() {
            // backoff 윈도 안 — push 시도 없이 바로 spool(무유실). 드레인은 이 task가 하지
            // 않는다(host metrics task `serve`가 유일한 드레인 주체, 모듈 doc 참고).
            if let Err(e) = self.cfg.spool.append(SignalKind::AppLogs, &body) {
                tracing::warn!(error = %e, batch_lines = batch.len(), "OTLP app logs spool append 실패 — 이 배치 유실");
            }
            return;
        }

        match super::super::push_logs(
            &self.client,
            &self.url,
            self.cfg.token.as_deref(),
            body.clone(),
        )
        .await
        {
            Ok(()) => {
                self.backoff.on_success();
                self.cfg.health.record_ok();
            }
            Err(e) => {
                tracing::warn!(error = %e, batch_lines = batch.len(), "OTLP app logs push 실패 — spool에 적재");
                if let Err(e2) = self.cfg.spool.append(SignalKind::AppLogs, &body) {
                    tracing::warn!(error = %e2, batch_lines = batch.len(), "OTLP app logs spool append 실패 — 이 배치 유실");
                }
                self.backoff.on_failure();
                self.cfg.health.record_fail();
            }
        }
    }
}

/// 데드라인이 있으면 그 시각까지 sleep, 없으면 영원히 대기(pending) — `tokio::select!`에서
/// 버퍼가 빈 동안 타이머 브랜치가 아예 없는 것과 동일하게 동작하게 한다.
async fn wait_for_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// logs exporter를 실행한다. `shutdown`이 true가 되면 남은 배치를 강제 flush한 뒤 graceful하게
/// 종료한다.
pub async fn serve_logs(
    cfg: LogsExporterConfig,
    mut rx: mpsc::Receiver<LogLine>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = super::super::logs_url(&cfg.endpoint);
    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let host_id = super::super::host_metrics::host_id(&host_name);
    let os_type = std::env::consts::OS.to_string();

    tracing::info!(
        url = %url,
        batch_max_lines = cfg.batch_max_lines,
        batch_max_ms = cfg.batch_max_ms,
        "OTLP logs exporter 시작"
    );

    let limiter = Limiter::new(cfg.logs_cfg.max_lines_per_sec, cfg.logs_cfg.max_services);
    let mut flusher = LogsFlusher {
        cfg,
        client,
        url,
        host_name,
        host_id,
        os_type,
        backoff: Backoff::new(),
        buffer: Vec::new(),
        deadline: None,
        limiter,
    };

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Some(line) => {
                        // 볼륨 안전장치(SRE t6) — min_severity 먼저(싸다), 그 다음 rate limit.
                        // 드롭되면 카운터만 올리고 버퍼/배치엔 아예 닿지 않는다.
                        if flusher.gate(&line) {
                            flusher.push_line(line);
                            if flusher.should_flush_on_size() {
                                flusher.flush().await;
                            }
                        }
                    }
                    None => break, // sender 전부 drop — 아래에서 잔여 배치를 최종 flush한다.
                }
            }
            _ = wait_for_deadline(flusher.deadline) => {
                flusher.flush().await;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    // shutdown/채널 종료 — 버퍼에 남은 라인을 유실시키지 않고 강제 flush.
    flusher.flush().await;

    tracing::info!("OTLP logs exporter 종료");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_spool() -> (tempfile::TempDir, Arc<Spool>) {
        let dir = tempfile::tempdir().unwrap();
        let quotas = aic_common::SpoolQuotas {
            metrics: 16 * 1024 * 1024,
            logs: 16 * 1024 * 1024,
            app_logs: 16 * 1024 * 1024,
        };
        let spool = Spool::open(dir.path().join("otlp-spool"), quotas).unwrap();
        (dir, Arc::new(spool))
    }

    fn log_line(msg: &str) -> LogLine {
        LogLine {
            source: "aic".to_string(),
            service: "aicd".to_string(),
            severity: "INFO".to_string(),
            message: msg.to_string(),
            attrs: BTreeMap::new(),
            ts: chrono::Utc::now(),
            record_id: format!("log:{msg}"),
        }
    }

    /// 스케줄러에게 여러 번 제어권을 넘겨, 다른 task(spawn된 exporter)가 이미 큐에 들어온
    /// IO/채널 이벤트를 처리할 기회를 준다. paused clock 환경에서 real IO(닫힌 포트로의 TCP
    /// connect 실패 등)가 완결될 시간을 벌기 위함 — 그 IO 자체는 실시간으로도 사실상 즉시
    /// 완료되므로(ECONNREFUSED), 다수 yield면 충분하다.
    async fn settle() {
        for _ in 0..500 {
            tokio::task::yield_now().await;
        }
    }

    /// 실시간(non-paused) 테스트용 — `pred`가 참이 될 때까지 짧게 폴링한다.
    async fn wait_until(mut pred: impl FnMut() -> bool) {
        for _ in 0..200 {
            if pred() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(pred(), "조건이 시간 내에 충족되지 않음");
    }

    /// 닫힌 포트 — 어떤 push도 즉시 실패한다(연결 거부).
    const CLOSED_PORT_ENDPOINT: &str = "http://127.0.0.1:1";

    #[tokio::test(start_paused = true)]
    async fn flush_at_max_lines() {
        let (_dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(
            CLOSED_PORT_ENDPOINT.to_string(),
            spool.clone(),
        ));
        let cfg = LogsExporterConfig {
            endpoint: CLOSED_PORT_ENDPOINT.to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 500,
            // ms 타이머가 이 테스트에서 절대 끼어들지 않게 충분히 크게 잡는다.
            batch_max_ms: 3_600_000,
            spool: spool.clone(),
            health,
            logs_cfg: aic_common::AicdLogsConfig::default(),
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(1024);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        for i in 0..499 {
            tx.send(log_line(&format!("line-{i}"))).await.unwrap();
        }
        settle().await;
        assert_eq!(
            spool.batch_count(),
            0,
            "499줄에선 아직 flush되면 안 됨(라인/시간 어느 쪽도 임계에 안 닿음)"
        );

        tx.send(log_line("line-499")).await.unwrap();
        settle().await;
        assert_eq!(
            spool.batch_count(),
            1,
            "500번째 라인에서 flush되어야 함(push 실패 → spool 1건)"
        );

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn flush_at_max_ms() {
        let (_dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(
            CLOSED_PORT_ENDPOINT.to_string(),
            spool.clone(),
        ));
        let cfg = LogsExporterConfig {
            endpoint: CLOSED_PORT_ENDPOINT.to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            // 라인 수로는 이 테스트에서 절대 안 걸리게.
            batch_max_lines: 10_000,
            batch_max_ms: 2000,
            spool: spool.clone(),
            health,
            logs_cfg: aic_common::AicdLogsConfig::default(),
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(1024);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        for i in 0..499 {
            tx.send(log_line(&format!("line-{i}"))).await.unwrap();
        }
        settle().await;
        assert_eq!(spool.batch_count(), 0);

        tokio::time::advance(Duration::from_millis(1999)).await;
        settle().await;
        assert_eq!(spool.batch_count(), 0, "1999ms에선 아직 flush되면 안 됨");

        tokio::time::advance(Duration::from_millis(2)).await; // 총 2001ms
        settle().await;
        assert_eq!(
            spool.batch_count(),
            1,
            "2000ms 경과 후엔 499줄이어도 flush되어야 함"
        );

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn push_failure_appends_to_spool_as_applogs() {
        let (dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(
            CLOSED_PORT_ENDPOINT.to_string(),
            spool.clone(),
        ));
        let cfg = LogsExporterConfig {
            endpoint: CLOSED_PORT_ENDPOINT.to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 2,
            batch_max_ms: 60_000,
            spool: spool.clone(),
            health: health.clone(),
            logs_cfg: aic_common::AicdLogsConfig::default(),
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(16);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        tx.send(log_line("a")).await.unwrap();
        tx.send(log_line("b")).await.unwrap(); // batch_max_lines=2 도달 → flush

        wait_until(|| spool.batch_count() == 1).await;

        let mut found_applogs = false;
        for entry in std::fs::read_dir(dir.path().join("otlp-spool")).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().ends_with(".a.batch") {
                found_applogs = true;
            }
        }
        assert!(
            found_applogs,
            "push 실패 배치가 AppLogs(파일명 code=a)로 spool되어야 함"
        );
        assert_eq!(health.snapshot().push_fail_total, 1);

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_flushes_pending_batch() {
        let (_dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(
            CLOSED_PORT_ENDPOINT.to_string(),
            spool.clone(),
        ));
        let cfg = LogsExporterConfig {
            endpoint: CLOSED_PORT_ENDPOINT.to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 500,
            batch_max_ms: 60_000, // 타이머로는 절대 안 나가게.
            spool: spool.clone(),
            health,
            logs_cfg: aic_common::AicdLogsConfig::default(),
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(16);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        tx.send(log_line("pending")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            spool.batch_count(),
            0,
            "shutdown 전엔 아직 버퍼에만 있어야 함"
        );

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        assert_eq!(
            spool.batch_count(),
            1,
            "shutdown 시 남은 배치가 강제 flush되어야 함"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_skips_network_and_spools_directly() {
        use axum::extract::State;
        use axum::http::StatusCode;

        async fn always_fail(State(count): State<Arc<AtomicUsize>>) -> StatusCode {
            count.fetch_add(1, Ordering::SeqCst);
            StatusCode::SERVICE_UNAVAILABLE
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hit_count = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .route("/v1/logs", axum::routing::post(always_fail))
            .with_state(hit_count.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let (_dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(format!("http://{addr}"), spool.clone()));
        let cfg = LogsExporterConfig {
            endpoint: format!("http://{addr}"),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 1, // 매 라인마다 즉시 flush되게.
            batch_max_ms: 60_000,
            spool: spool.clone(),
            health,
            logs_cfg: aic_common::AicdLogsConfig::default(),
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(16);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        tx.send(log_line("first")).await.unwrap(); // flush → 503 → backoff.on_failure()
        settle().await;
        assert_eq!(hit_count.load(Ordering::SeqCst), 1);
        assert_eq!(spool.batch_count(), 1);

        // backoff 윈도 안(가상 시계는 advance하지 않았으므로 여전히 실패 직후) — 네트워크
        // 시도 없이 곧장 spool되어야 한다.
        tx.send(log_line("second")).await.unwrap();
        settle().await;
        assert_eq!(
            hit_count.load(Ordering::SeqCst),
            1,
            "backoff 윈도 안에선 네트워크 시도가 없어야 함"
        );
        assert_eq!(spool.batch_count(), 2);

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_logs_never_drains_spool() {
        let (_dir, spool) = test_spool();
        // 다른 task가 이미 쌓아 둔 배치를 흉내(host metrics task만 이걸 드레인해야 한다).
        spool
            .append(SignalKind::Metrics, b"pre-existing-batch")
            .unwrap();
        assert_eq!(spool.batch_count(), 1);

        let health = Arc::new(ExporterHealth::new(
            CLOSED_PORT_ENDPOINT.to_string(),
            spool.clone(),
        ));
        let cfg = LogsExporterConfig {
            endpoint: CLOSED_PORT_ENDPOINT.to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 500,
            batch_max_ms: 60_000,
            spool: spool.clone(),
            health,
            logs_cfg: aic_common::AicdLogsConfig::default(),
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(16);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        tx.send(log_line("x")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        // serve_logs 자신이 flush한 배치(push 실패 → spool 1건) + 미리 심어둔 배치(1건) = 2건.
        // 드레인했다면 미리 심어둔 배치가 사라져 1건이었을 것이다.
        assert_eq!(
            spool.batch_count(),
            2,
            "serve_logs는 spool을 드레인하면 안 됨 — 기존 배치가 그대로 남아 있어야 함"
        );
    }

    #[tokio::test]
    async fn empty_batch_is_never_pushed() {
        let (_dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(
            CLOSED_PORT_ENDPOINT.to_string(),
            spool.clone(),
        ));
        let cfg = LogsExporterConfig {
            endpoint: CLOSED_PORT_ENDPOINT.to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 500,
            batch_max_ms: 50,
            spool: spool.clone(),
            health: health.clone(),
            logs_cfg: aic_common::AicdLogsConfig::default(),
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (_tx, rx) = mpsc::channel(16);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        // 아무 라인도 보내지 않은 채 ms 타이머 주기를 여러 번 흘려보낸다 — 데드라인 자체가
        // 없으므로(버퍼가 빈 동안 잡히지 않음) flush가 트리거될 일이 없어야 한다.
        tokio::time::sleep(Duration::from_millis(150)).await;

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        assert_eq!(
            spool.batch_count(),
            0,
            "빈 배치는 push/spool 어느 쪽도 건드리면 안 됨"
        );
        assert_eq!(health.snapshot().push_ok_total, 0);
        assert_eq!(health.snapshot().push_fail_total, 0);
    }

    /// SRE t6 DoD 7 — 드롭이 대량 발생해도 배치에 합성 `LogLine`이 섞여 들어가지 않는다.
    /// 3줄이 드롭되는 동안 전송된 배치에는 통과한 2줄만 있어야 한다.
    ///
    /// 드롭 수단으로 **min_severity 필터**를 쓴다(rate limit이 아니다). rate limit은 토큰이
    /// 실시간으로 리필되므로, CPU 경합이 심하면 라인 사이 간격이 벌어져 통과/드롭 개수가
    /// 흔들린다 — 실제로 `cargo test --workspace`(여러 테스트 바이너리 동시 실행)에서
    /// 간헐 실패했다. severity 필터는 순수 함수라 시계와 무관하다. rate limit 드롭 경로는
    /// `limiter::tests::rate_limit_drops_and_counts`가 paused clock으로 이미 결정적으로 검증한다.
    ///
    /// 라인을 **통과분 먼저, 드롭분 나중에** 보낸다. mpsc는 FIFO이므로 `by_severity == 3`이
    /// 관측된 시점엔 앞선 2줄이 이미 버퍼에 들어가 있음이 보장된다(shutdown이 미처리 라인을
    /// 앞질러 빈 버퍼를 flush하는 경합이 구조적으로 불가능).
    ///
    /// `start_paused = true`는 쓸 수 없다 — handler의 `.await`마다 가상 시계가 auto-advance해
    /// reqwest의 `HTTP_TIMEOUT`(10s)이 실제 소켓 I/O보다 먼저 만료된다.
    #[tokio::test]
    async fn no_synthetic_log_line_is_created() {
        use axum::extract::State;
        use prost::Message as _;
        use std::sync::Mutex;

        type Captured = Arc<Mutex<Vec<Vec<u8>>>>;

        // handler에 `.await`를 두지 않는다(위 doc 참고 — 동기 캡처).
        async fn capture(
            State(bodies): State<Captured>,
            body: axum::body::Bytes,
        ) -> axum::http::StatusCode {
            bodies.lock().unwrap().push(body.to_vec());
            axum::http::StatusCode::OK
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bodies: Captured = Arc::new(Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route("/v1/logs", axum::routing::post(capture))
            .with_state(bodies.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let (_dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(format!("http://{addr}"), spool.clone()));
        let logs_cfg = aic_common::AicdLogsConfig {
            min_severity: "WARN".to_string(), // DEBUG 라인은 여기서 걸린다.
            max_lines_per_sec: 10_000,        // rate limit은 이 테스트에서 절대 걸리지 않게.
            max_services: 10,
            ..Default::default()
        };
        let cfg = LogsExporterConfig {
            endpoint: format!("http://{addr}"),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 100, // 라인 수로는 flush 안 걸리게.
            batch_max_ms: 60_000, // 타이머로도 flush 안 걸리게 — flush는 shutdown 때 한 번.
            spool: spool.clone(),
            health,
            logs_cfg,
            drop_counters: Arc::new(DropCounters::new()),
        };
        let drop_counters = cfg.drop_counters.clone();
        let (tx, rx) = mpsc::channel(16);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        // 통과분(ERROR) 2줄 먼저 — FIFO라 드롭분보다 반드시 앞서 처리된다.
        for i in 0..2 {
            let mut line = log_line(&format!("pass-{i}"));
            line.severity = "ERROR".to_string();
            tx.send(line).await.unwrap();
        }
        // 드롭분(DEBUG) 3줄 — min_severity=WARN에 걸린다.
        for i in 0..3 {
            let mut line = log_line(&format!("drop-{i}"));
            line.severity = "DEBUG".to_string();
            tx.send(line).await.unwrap();
        }
        {
            let dc = drop_counters.clone();
            wait_until(move || dc.by_severity.load(Ordering::Relaxed) == 3).await;
        }

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        let captured = bodies.lock().unwrap();
        let spooled = spool.batch_count();

        // 배치는 collector에 도달했거나 spool에 적재됐거나 둘 중 하나여야 한다. 둘 다 0이면
        // 배치가 **조용히 사라진 것**이다(flush의 push 실패 + spool append 실패 경로). 그냥
        // "1개여야 함"으로 단언하면 그 경우를 구분할 수 없으므로 어느 경로였는지 남긴다.
        assert!(
            !(captured.is_empty() && spooled == 0),
            "배치가 유실됐다 — collector 도달 0건, spool 적재 0건. \
             push 실패 후 spool append까지 실패한 경로를 의심하라"
        );
        assert_eq!(
            spooled, 0,
            "mock 서버가 200을 주므로 spool로 새지 않아야 함(배치가 실제로 전송됨)"
        );
        assert_eq!(captured.len(), 1, "배치 한 번만 전송되어야 함");

        let decoded = logs_proto::ExportLogsServiceRequest::decode(captured[0].as_slice())
            .expect("valid OTLP logs protobuf");
        let log_records = &decoded.resource_logs[0].scope_logs[0].log_records;

        assert_eq!(
            log_records.len(),
            2,
            "통과한 2줄만 실려야 한다 — 드롭된 3줄만큼 합성 레코드가 섞이면 안 됨"
        );
        assert_eq!(
            drop_counters.by_severity.load(Ordering::Relaxed),
            3,
            "드롭 수는 정확히 by_severity 카운터와 일치해야 함"
        );
        assert_eq!(
            drop_counters.by_rate_limit.load(Ordering::Relaxed),
            0,
            "rate limit은 10k/s라 이 테스트에서 걸리지 않아야 함"
        );
    }
}
