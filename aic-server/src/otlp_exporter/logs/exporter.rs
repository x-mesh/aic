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
    /// 버퍼의 원문 바이트 합이 이 값을 **넘기기 전에** flush한다. 권장 기본값 4 MiB.
    ///
    /// 라인 수만으로는 배치 크기를 못 묶는다 — 라인 하나가 64 KiB까지 갈 수 있어 500줄이면
    /// 최악 31 MiB이고, 수신 측은 8 MiB에서 413으로 자른다. 그리고 그 413은 재전송해도 영원히
    /// 413이라 spool 큐 머리에 박혀 **다른 시그널의 드레인까지 멈춘다**(RFC-006 §6.6).
    pub batch_max_bytes: usize,
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
    /// `buffer`에 든 라인들의 원문 바이트 합. 매번 다시 세지 않으려고 들고 다닌다.
    buffered_bytes: usize,
    /// 다음 flush 데드라인. 버퍼가 비어 있는 동안은 `None`(타이머 없음).
    deadline: Option<Instant>,
    /// 서비스당 token-bucket rate limiter(SRE t6). severity 필터를 통과한 라인만 여기를 거친다.
    limiter: Limiter,
}

/// 한 라인이 배치 크기에 기여하는 바이트. **인코딩 전 원문 기준**이다.
///
/// 이건 flush 시점을 정하는 **휴리스틱**이지 크기 보장이 아니다 — protobuf 프레이밍,
/// `aic.log.` attr 키 prefix, resource attr이 이 위에 얹히므로 원문 합이 `batch_max_bytes`
/// 아래여도 인코딩 결과는 넘을 수 있다. 실제 보장은 [`LogsFlusher::encode_within_limit`]가
/// **인코딩된 본문을 직접 재서** 한다.
///
/// 라인마다 인코딩해 보고 결정하지 않는 이유는 비용이다 — 여기는 라인당 경로이고, 인코딩은
/// 배치당 한 번이면 된다.
fn line_bytes(line: &LogLine) -> usize {
    line.message.len()
        + line.service.len()
        + line.source.len()
        + line.record_id.len()
        + line
            .attrs
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
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
    ///
    /// **이 라인을 넣으면 `batch_max_bytes`를 넘길 경우, 넣기 *전에* 지금까지의 버퍼를 flush한다.**
    /// 넣고 나서 검사하면 이미 상한을 넘긴 배치를 전송하게 된다 — 그게 정확히 413을 부르는 길이고,
    /// 413은 재전송해도 영원히 413이라 spool 큐를 막는다(RFC-006 §6.6). 버퍼가 비어 있는데도
    /// 한 라인이 상한을 넘는 경우는 그 라인 혼자 배치가 된다 — 나눌 수 없으니 보내는 수밖에 없고,
    /// 라인 자체가 64 KiB로 잘려 있어(§3) 상한을 넘을 수 없다.
    async fn add_line(&mut self, line: LogLine) {
        let bytes = line_bytes(&line);
        if !self.buffer.is_empty() && self.buffered_bytes + bytes > self.cfg.batch_max_bytes {
            self.flush().await;
        }
        if self.buffer.is_empty() {
            self.deadline = Some(Instant::now() + Duration::from_millis(self.cfg.batch_max_ms));
        }
        self.buffered_bytes += bytes;
        self.buffer.push(line);
    }

    fn should_flush_on_size(&self) -> bool {
        self.buffer.len() >= self.cfg.batch_max_lines
            || self.buffered_bytes >= self.cfg.batch_max_bytes
    }

    /// 라인 묶음 하나를 OTLP 본문으로 인코딩한다.
    fn encode(&self, lines: &[LogLine]) -> Vec<u8> {
        let resource = ResourceAttrs {
            host_name: &self.host_name,
            host_id: &self.host_id,
            os_type: &self.os_type,
            host_ip: None,
        };
        logs_proto::encode_log_line(lines, &resource, &self.cfg.service_version)
    }

    /// **인코딩된 본문**이 `batch_max_bytes`를 넘지 않도록 배치를 쪼갠다.
    ///
    /// [`line_bytes`]를 누적해 flush를 트리거하는 건 **휴리스틱**이다 — protobuf 프레이밍,
    /// `aic.log.` attr 키 prefix, resource attr이 원문 바이트 위에 얹히므로 "원문 4 MiB면 인코딩
    /// 후에도 4 MiB 아래"라는 보장이 없다. attr이 많은 라인(journald는 pid/unit/syslog_facility를
    /// 붙인다)이 몰리면 오버헤드 비율이 커진다.
    ///
    /// 그래서 **실제 인코딩 결과를 재고**, 넘으면 반으로 쪼개 다시 잰다. 이게 없으면 초과분이
    /// 수신 측 body-limit에 413으로 걸리고, 그 배치는 재전송해도 영원히 413이라 통째로 유실된다.
    ///
    /// 라인 하나는 `MAX_LOG_LINE_BYTES`(64 KiB)로 이미 잘려 있으므로 분할은 반드시 끝난다.
    /// 그래도 한 줄이 상한을 넘으면(attr이 비정상적으로 큰 경우) 더 쪼갤 수 없으니 그대로 보낸다 —
    /// 413을 받고 영구 실패로 드롭되며 카운터에 잡힌다. 조용히 사라지지는 않는다.
    fn encode_within_limit(&self, batch: Vec<LogLine>) -> Vec<(Vec<u8>, usize)> {
        let limit = self.cfg.batch_max_bytes;
        let mut out = Vec::new();
        // stack에서 pop하는 순서가 곧 전송 순서다 — right를 먼저 push해야 left가 먼저 나간다.
        let mut stack = vec![batch];
        while let Some(chunk) = stack.pop() {
            if chunk.is_empty() {
                continue;
            }
            let body = self.encode(&chunk);
            if body.len() <= limit || chunk.len() == 1 {
                out.push((body, chunk.len()));
                continue;
            }
            let mid = chunk.len() / 2;
            let mut left = chunk;
            let right = left.split_off(mid);
            stack.push(right);
            stack.push(left);
        }
        out
    }

    /// 현재 버퍼를 인코딩해 전송을 시도한다. 빈 버퍼는 no-op(빈 배치를 push/spool 어느 쪽에도
    /// 남기지 않는다). 인코딩 결과가 상한을 넘으면 여러 배치로 나눠 보낸다.
    async fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.buffer);
        self.buffered_bytes = 0;
        self.deadline = None;

        for (body, lines) in self.encode_within_limit(batch) {
            self.send_one(body, lines).await;
        }
    }

    /// 인코딩이 끝난 본문 하나를 push한다(실패 시 spool/드롭 분기 포함).
    async fn send_one(&mut self, body: Vec<u8>, batch_lines: usize) {
        if !self.backoff.ready() {
            // backoff 윈도 안 — push 시도 없이 바로 spool(무유실). 드레인은 이 task가 하지
            // 않는다(host metrics task `serve`가 유일한 드레인 주체, 모듈 doc 참고).
            if let Err(e) = self.cfg.spool.append(SignalKind::AppLogs, &body) {
                tracing::warn!(error = %e, batch_lines, "OTLP app logs spool append 실패 — 이 배치 유실");
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
            // partial_success 폐기 수(Ok(u64))는 여기선 무시한다 — aic.logs는 수신측이 아는 scope라
            // 폐기가 없고, collector_dropped 게이지·전이 로그는 host-metrics 태스크(process)가 담당.
            Ok(_) => {
                self.backoff.on_success();
                self.cfg.health.record_ok();
            }
            // 4xx — 재전송해도 같은 응답이다. **spool에 넣지 않는다**: 넣는 순간 그게 poison
            // batch가 되어 FIFO 머리에 박히고, 모든 kind의 드레인을 멈춘다(RFC-006 §6.6).
            // 버리되 조용히 버리지 않는다 — 카운터가 이 유실을 드러낸다.
            Err(e) if e.is_permanent() => {
                tracing::warn!(
                    error = %e,
                    batch_lines,
                    "collector가 app logs 배치를 영구 거부 — 이 배치 유실(spool에 넣지 않는다)"
                );
                self.cfg
                    .drop_counters
                    .by_rejected
                    .fetch_add(batch_lines as u64, Ordering::Relaxed);
                // backoff는 올리지 않는다 — collector는 살아 있다. 우리 요청이 틀렸을 뿐이고,
                // backoff를 걸면 멀쩡한 다음 배치까지 지연시킨다.
                self.cfg.health.record_ok();
            }
            Err(e) => {
                tracing::warn!(error = %e, batch_lines, "OTLP app logs push 실패 — spool에 적재");
                if let Err(e2) = self.cfg.spool.append(SignalKind::AppLogs, &body) {
                    tracing::warn!(error = %e2, batch_lines, "OTLP app logs spool append 실패 — 이 배치 유실");
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
        batch_max_bytes = cfg.batch_max_bytes,
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
        buffered_bytes: 0,
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
                            flusher.add_line(line).await;
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
            batch_max_bytes: 4 * 1024 * 1024,
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

    /// 큰 라인이 몰리면 `batch_max_lines`만으로는 배치가 수신 측 요청 상한을 넘긴다.
    ///
    /// 라인 하나는 64 KiB까지 허용되므로 500줄이면 최악 31 MiB인데, rca는 8 MiB에서 413을 낸다.
    /// 그리고 413은 재전송해도 영원히 413이라, 그 배치가 spool 큐 머리에 박혀 **다른 시그널의
    /// 드레인까지 멈춘다**(RFC-006 §6.6). 그래서 바이트로도 잘라야 한다.
    ///
    /// 여기서는 64 KiB 라인 500개를 넣고 (a) 배치가 여러 개로 쪼개졌는지, (b) **어느 배치도
    /// 상한을 넘지 않는지**를 spool에 쌓인 실제 인코딩 바이트로 확인한다.
    #[tokio::test(start_paused = true)]
    async fn a_batch_never_exceeds_max_bytes_even_when_lines_are_huge() {
        const LINE_BYTES: usize = 64 * 1024;
        const MAX_BYTES: usize = 512 * 1024; // 테스트를 빨리 끝내려 작게 — 비율은 동일하다.
        const LINES: usize = 500;

        let (dir, spool) = test_spool();
        let spool_dir = dir.path().join("otlp-spool");
        let health = Arc::new(ExporterHealth::new(
            CLOSED_PORT_ENDPOINT.to_string(),
            spool.clone(),
        ));
        let cfg = LogsExporterConfig {
            endpoint: CLOSED_PORT_ENDPOINT.to_string(),
            token: None,
            service_version: "0.0.0-test".to_string(),
            // 라인 수로는 절대 안 걸리게 — 바이트 상한만이 배치를 자를 수 있어야 한다.
            batch_max_lines: 10_000,
            batch_max_bytes: MAX_BYTES,
            batch_max_ms: 3_600_000,
            spool: spool.clone(),
            health,
            logs_cfg: aic_common::AicdLogsConfig {
                // 이 테스트는 배치 크기만 본다 — rate limit이 라인을 삼키면 안 된다.
                max_lines_per_sec: u32::MAX,
                ..Default::default()
            },
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(2048);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        let big = "x".repeat(LINE_BYTES);
        for _ in 0..LINES {
            tx.send(log_line(&big)).await.unwrap();
        }
        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        // 라인 수 상한(10k)에는 한참 못 미치므로, 쪼개진 이유는 바이트 상한뿐이다.
        let batches = spool.batch_count();
        assert!(
            batches > 1,
            "바이트 상한이 배치를 잘라야 한다 — 배치가 {batches}개뿐이면 500 × 64 KiB가 한 덩어리로 나간 것"
        );

        // 상한을 실제로 지켰는지는 spool에 떨어진 인코딩 결과로 확인한다. 원문 바이트로 재는
        // 카운터가 맞아도 인코딩이 부풀면 의미가 없다 — 수신 측이 보는 건 이 바이트다.
        let mut largest = 0usize;
        for entry in std::fs::read_dir(&spool_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "batch") {
                largest = largest.max(std::fs::metadata(&path).unwrap().len() as usize);
            }
        }
        assert!(
            largest > 0,
            "spool에 배치 파일이 있어야 한다(push는 닫힌 포트라 전부 실패한다)"
        );
        // protobuf 프레이밍이 원문 위에 얹히므로 정확히 MAX_BYTES는 아니지만, 배치가 통제 없이
        // 커지지 않았음을 못박는다. 실제 배선(4 MiB 상한 vs 8 MiB 수신 한도)이 이 여유를 준다.
        assert!(
            largest < MAX_BYTES * 2,
            "배치 하나가 {largest} 바이트 — 상한 {MAX_BYTES}의 2배를 넘으면 크기를 통제하지 못한 것"
        );
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
            batch_max_bytes: 4 * 1024 * 1024,
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
            batch_max_bytes: 4 * 1024 * 1024,
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
            batch_max_bytes: 4 * 1024 * 1024,
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
            batch_max_bytes: 4 * 1024 * 1024,
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
            batch_max_bytes: 4 * 1024 * 1024,
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
            batch_max_bytes: 4 * 1024 * 1024,
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
            batch_max_lines: 100,             // 라인 수로는 flush 안 걸리게.
            batch_max_bytes: 4 * 1024 * 1024, // 바이트로도 안 걸리게.
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

    /// 인코딩된 본문이 `batch_max_bytes`를 넘으면 배치를 쪼개 보낸다.
    ///
    /// line_bytes() 누적(= flush 트리거)은 **원문 바이트**만 센다. protobuf 프레이밍과
    /// `aic.log.` attr 키 prefix, resource attr이 그 위에 얹히므로 원문이 상한 아래여도
    /// 인코딩 결과는 넘을 수 있다. 넘긴 채로 보내면 수신 측이 413으로 자르고, 그 배치는
    /// 재전송해도 영원히 413이라 통째로 유실된다.
    ///
    /// 실시간 시계로 돈다 — mock collector가 진짜 body를 받아야 크기를 잴 수 있다.
    #[tokio::test]
    async fn oversized_encoded_batch_is_split_under_the_wire_limit() {
        use axum::extract::State;
        use prost::Message as _;
        use std::sync::Mutex;

        type Captured = Arc<Mutex<Vec<Vec<u8>>>>;

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

        // 상한을 작게 잡아 인코딩 오버헤드만으로도 분할이 강제되게 한다.
        const WIRE_LIMIT: usize = 4096;

        let (_dir, spool) = test_spool();
        let health = Arc::new(ExporterHealth::new(format!("http://{addr}"), spool.clone()));
        let logs_cfg = aic_common::AicdLogsConfig {
            max_lines_per_sec: 100_000, // rate limit이 끼어들지 않게
            ..Default::default()
        };
        let cfg = LogsExporterConfig {
            endpoint: format!("http://{addr}"),
            token: None,
            service_version: "0.0.0-test".to_string(),
            batch_max_lines: 10_000, // 라인 수로는 flush 안 걸리게
            batch_max_bytes: WIRE_LIMIT,
            batch_max_ms: 3_600_000, // 타이머로도 flush 안 걸리게 — flush는 shutdown 때 한 번
            spool: spool.clone(),
            health,
            logs_cfg,
            drop_counters: Arc::new(DropCounters::new()),
        };
        let (tx, rx) = mpsc::channel(1024);
        let (sd_tx, sd_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_logs(cfg, rx, sd_rx));

        const LINES: usize = 60;
        const CHANNEL_CAP: usize = 1024;
        for i in 0..LINES {
            tx.send(log_line(&format!("line-{i:03}-{}", "x".repeat(40))))
                .await
                .unwrap();
        }

        // exporter가 채널을 **비울 때까지** 기다린다. `send().await`는 채널에 넣는 것까지만
        // 보장한다 — 여기서 바로 shutdown을 쏘면 루프가 라인을 꺼내기도 전에 깨져 빈 버퍼를
        // flush하고 끝난다(실제로 그렇게 실패했다). capacity가 전부 돌아오면 recv가 다 됐다는 뜻.
        {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while tx.capacity() < CHANNEL_CAP {
                assert!(
                    std::time::Instant::now() < deadline,
                    "exporter가 10초 안에 채널을 비우지 못했다"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            settle().await; // recv 직후 add_line이 끝날 틈
        }

        sd_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        let captured = bodies.lock().unwrap();
        assert!(
            captured.len() >= 2,
            "상한을 넘는 배치는 쪼개져야 한다 — 요청이 {}개뿐이다",
            captured.len()
        );

        // 핵심 단언: **보낸 본문 중 상한을 넘는 게 하나도 없다.**
        for (i, body) in captured.iter().enumerate() {
            assert!(
                body.len() <= WIRE_LIMIT,
                "{i}번째 본문이 {} bytes로 상한({WIRE_LIMIT})을 넘었다 — 수신 측이 413으로 자른다",
                body.len()
            );
        }

        // 그리고 라인이 하나도 새지 않는다.
        let total: usize = captured
            .iter()
            .map(|b| {
                logs_proto::ExportLogsServiceRequest::decode(b.as_slice())
                    .expect("valid OTLP logs protobuf")
                    .resource_logs[0]
                    .scope_logs[0]
                    .log_records
                    .len()
            })
            .sum();
        assert_eq!(total, LINES, "분할 과정에서 라인이 유실되면 안 된다");

        assert_eq!(
            spool.batch_count(),
            0,
            "mock이 200을 주므로 spool로 새지 않는다"
        );
    }
}
