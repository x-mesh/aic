//! aicd webhook alert ingestion (SRE R2).
//!
//! Alertmanager/Grafana/PagerDuty/generic JSON webhook을 수신해, firing alert마다
//! `aic diagnose --bundle`을 spawn(읽기 전용 진단 + 증거 번들)한다. 온콜이 터미널을
//! 열었을 때 이미 증거가 준비되어 있게 하는 것이 목적이다.
//!
//! 보안(pitfalls 高위험 완화):
//! - **127.0.0.1 바인드 기본**(config) + **opt-in**(기본 비활성).
//! - **인증**: `Authorization: Bearer <secret>` 또는 `X-AIC-Signature: <hex HMAC-SHA256(secret,body)>`.
//!   secret 미설정 시(localhost 전용) 허용하되 경고.
//! - **rate limit**(token-bucket, 기본 10/분): alert storm LLM 비용 폭주 차단.
//! - **dedup**(fingerprint 5분 TTL): 동일 alert 재진단 차단(진단→alert 루프 방지).
//! - 자동 진단은 `aic diagnose`(고정 Safe probe만)라 상태 변경 명령은 실행되지 않는다.
//! - alert payload의 symptom은 sanitize(개행/제어문자 제거 + 길이 cap)해 argv로만 전달.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use tokio::sync::{watch, Mutex};

type HmacSha256 = Hmac<Sha256>;

/// symptom 텍스트 최대 길이(argv 안전 + 로그 bound).
const MAX_SYMPTOM_LEN: usize = 200;
/// webhook-events.jsonl 한 줄 최대 바이트(과도한 라벨 방지).
const MAX_EVENT_BYTES: usize = 8 * 1024;

/// webhook 서버 실행 설정.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub listen_addr: String,
    pub secret: Option<String>,
    pub rate_limit_per_min: u32,
    pub dedup_ttl: Duration,
    pub auto_diagnose: bool,
    /// spawn할 `aic` 실행 파일 경로.
    pub aic_bin: PathBuf,
}

/// 정규화된 수신 alert.
#[derive(Debug, Clone)]
struct IncomingAlert {
    name: String,
    severity: Option<String>,
    summary: Option<String>,
    /// alertname + 정렬된 labels로 만든 dedup 키.
    fingerprint: String,
}

impl IncomingAlert {
    /// 진단에 넘길 symptom 텍스트(name + summary). sanitize 전 raw.
    fn symptom_text(&self) -> String {
        match &self.summary {
            Some(s) if !s.is_empty() => format!("{}: {}", self.name, s),
            _ => self.name.clone(),
        }
    }
}

struct WebhookState {
    secret: Option<String>,
    auto_diagnose: bool,
    aic_bin: PathBuf,
    dedup_ttl: Duration,
    limiter: Mutex<TokenBucket>,
    dedup: Mutex<HashMap<String, Instant>>,
}

/// 간단한 token-bucket rate limiter. capacity = 분당 한도, 60초에 걸쳐 선형 refill.
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(per_min: u32, now: Instant) -> Self {
        let cap = per_min.max(1) as f64;
        Self {
            capacity: cap,
            tokens: cap,
            refill_per_sec: cap / 60.0,
            last: now,
        }
    }

    /// 토큰 1개를 시도 소비. 가능하면 true.
    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// webhook 서버를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
/// bind 실패 시 에러를 반환(호출부는 aicd 전체를 abort하지 않고 경고만 — webhook은 opt-in 부가 기능).
pub async fn serve(cfg: WebhookConfig, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr).await?;
    let bound = listener.local_addr().ok();
    tracing::info!(addr = ?bound, auto_diagnose = cfg.auto_diagnose, "webhook 리스너 바인드");
    if cfg.secret.is_none() {
        tracing::warn!("webhook secret 미설정 — 인증 없이 수신합니다(localhost 바인드 권장).");
    }

    let now = Instant::now();
    let state = Arc::new(WebhookState {
        secret: cfg.secret,
        auto_diagnose: cfg.auto_diagnose,
        aic_bin: cfg.aic_bin,
        dedup_ttl: cfg.dedup_ttl,
        limiter: Mutex::new(TokenBucket::new(cfg.rate_limit_per_min, now)),
        dedup: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/webhook", post(handle_generic))
        .route("/webhook/{source}", post(handle_source))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // 이미 true면 즉시, 아니면 변경을 기다린다.
            if *shutdown.borrow() {
                return;
            }
            while shutdown.changed().await.is_ok() {
                if *shutdown.borrow() {
                    break;
                }
            }
        })
        .await?;
    tracing::info!("webhook 리스너 종료");
    Ok(())
}

async fn handle_generic(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    process(state, "generic", headers, body).await
}

async fn handle_source(
    State(state): State<Arc<WebhookState>>,
    Path(source): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    process(state, &source, headers, body).await
}

async fn process(
    state: Arc<WebhookState>,
    source: &str,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if !authorize(&state, &headers, &body) {
        tracing::warn!(source, "webhook 인증 실패");
        record_event(source, "unauthorized", None, 0);
        return StatusCode::UNAUTHORIZED;
    }
    let json: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(source, error = %e, "webhook JSON 파싱 실패");
            return StatusCode::BAD_REQUEST;
        }
    };
    let alerts = parse_alerts(source, &json);
    if alerts.is_empty() {
        record_event(source, "no_firing_alerts", None, 0);
        return StatusCode::OK;
    }

    for alert in alerts {
        let now = Instant::now();
        // dedup: 동일 fingerprint가 TTL 내면 진단 skip(루프/중복 비용 방지).
        if is_duplicate(&state, &alert.fingerprint, now).await {
            record_event(source, "deduped", Some(&alert), 0);
            continue;
        }
        // rate limit: storm 시 비용 폭주 차단.
        let allowed = { state.limiter.lock().await.try_take(now) };
        if !allowed {
            record_event(source, "rate_limited", Some(&alert), 0);
            tracing::warn!(source, alert = %alert.name, "webhook rate limit 초과 — 진단 skip");
            continue;
        }
        if state.auto_diagnose {
            spawn_diagnose(&state, &alert);
            record_event(source, "diagnosing", Some(&alert), 0);
        } else {
            record_event(source, "received", Some(&alert), 0);
        }
    }
    StatusCode::OK
}

/// dedup 검사 + 등록(갱신). TTL 만료 항목은 정리한다.
async fn is_duplicate(state: &WebhookState, fingerprint: &str, now: Instant) -> bool {
    let mut map = state.dedup.lock().await;
    map.retain(|_, t| now.saturating_duration_since(*t) < state.dedup_ttl);
    if map.contains_key(fingerprint) {
        return true;
    }
    map.insert(fingerprint.to_string(), now);
    false
}

fn spawn_diagnose(state: &WebhookState, alert: &IncomingAlert) {
    let symptom = sanitize_symptom(&alert.symptom_text());
    let label = sanitize_label(&alert.fingerprint);
    let aic_bin = state.aic_bin.clone();
    // child를 await해 좀비를 reap. rate limiter가 spawn 빈도를 bound하므로 task 누적은 없음.
    tokio::spawn(async move {
        let mut cmd = tokio::process::Command::new(&aic_bin);
        cmd.arg("diagnose")
            .arg(&symptom)
            .arg("--bundle")
            .arg("--name")
            .arg(&label)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                let _ = child.wait().await;
            }
            Err(e) => tracing::warn!(error = %e, "aic diagnose spawn 실패"),
        }
    });
}

// ── 인증 ───────────────────────────────────────────────────

fn authorize(state: &WebhookState, headers: &HeaderMap, body: &[u8]) -> bool {
    let Some(secret) = &state.secret else {
        return true; // secret 미설정 → 허용(localhost opt-in). serve()에서 경고함.
    };
    // 1) Authorization: Bearer <secret> (Alertmanager/Grafana가 헤더로 보내기 쉬움)
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(tok) = auth.strip_prefix("Bearer ") {
            if constant_time_eq(tok.trim().as_bytes(), secret.as_bytes()) {
                return true;
            }
        }
    }
    // 2) X-AIC-Signature: <hex HMAC-SHA256(secret, body)> (PagerDuty류/generic)
    if let Some(sig) = headers.get("x-aic-signature").and_then(|v| v.to_str().ok()) {
        let expected = compute_hmac_hex(secret.as_bytes(), body);
        if constant_time_eq(sig.trim().as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    false
}

fn compute_hmac_hex(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC는 임의 키 길이를 허용");
    mac.update(body);
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// 타이밍 공격 방지 상수시간 비교.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── 포맷 파서 ──────────────────────────────────────────────

/// source별 파서 디스패치. 인식 못 하면 generic으로 폴백.
fn parse_alerts(source: &str, json: &Value) -> Vec<IncomingAlert> {
    match source {
        "alertmanager" | "grafana" => parse_alertmanager_style(json),
        "pagerduty" => parse_pagerduty(json),
        _ => parse_generic(json),
    }
}

/// Alertmanager / Grafana unified alerting — `{"alerts":[{labels, annotations, status}]}`.
/// firing(또는 status 미지정) alert만 취한다.
fn parse_alertmanager_style(json: &Value) -> Vec<IncomingAlert> {
    let mut out = Vec::new();
    let Some(alerts) = json.get("alerts").and_then(|v| v.as_array()) else {
        return out;
    };
    for a in alerts {
        let status = a.get("status").and_then(|v| v.as_str()).unwrap_or("firing");
        if status != "firing" {
            continue;
        }
        let labels = a.get("labels");
        let name = labels
            .and_then(|l| l.get("alertname"))
            .and_then(|v| v.as_str())
            .unwrap_or("alert")
            .to_string();
        let severity = labels
            .and_then(|l| l.get("severity"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let summary = a
            .get("annotations")
            .and_then(|an| an.get("summary").or_else(|| an.get("description")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let fingerprint = a
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| fingerprint_from_labels(&name, labels));
        out.push(IncomingAlert {
            name,
            severity,
            summary,
            fingerprint,
        });
    }
    out
}

/// PagerDuty v3 webhook — `{"event":{"data":{"title":..., "id":...}}}`. lenient.
fn parse_pagerduty(json: &Value) -> Vec<IncomingAlert> {
    let Some(data) = json.get("event").and_then(|e| e.get("data")) else {
        return parse_generic(json);
    };
    let name = data
        .get("title")
        .or_else(|| data.get("summary"))
        .and_then(|v| v.as_str())
        .unwrap_or("pagerduty_incident")
        .to_string();
    let severity = data
        .get("priority")
        .and_then(|p| p.get("summary"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let fingerprint = data
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| fingerprint_from_labels(&name, None));
    vec![IncomingAlert {
        name,
        severity,
        summary: None,
        fingerprint,
    }]
}

/// generic JSON — alertname/alert/title + summary를 lenient하게 추출. 없으면 통째로 symptom.
fn parse_generic(json: &Value) -> Vec<IncomingAlert> {
    // alertmanager 형태면 그쪽 파서를 우선 시도.
    if json.get("alerts").is_some() {
        let v = parse_alertmanager_style(json);
        if !v.is_empty() {
            return v;
        }
    }
    let name = json
        .get("alertname")
        .or_else(|| json.get("alert"))
        .or_else(|| json.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or("generic_alert")
        .to_string();
    let summary = json
        .get("summary")
        .or_else(|| json.get("message"))
        .or_else(|| json.get("description"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let fingerprint = fingerprint_from_labels(&name, json.get("labels"));
    vec![IncomingAlert {
        name,
        severity: json
            .get("severity")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        summary,
        fingerprint,
    }]
}

/// alertname + 정렬된 label k=v로 결정적 fingerprint를 만든다.
fn fingerprint_from_labels(name: &str, labels: Option<&Value>) -> String {
    let mut parts = vec![name.to_string()];
    if let Some(obj) = labels.and_then(|l| l.as_object()) {
        let mut kv: Vec<String> = obj
            .iter()
            .filter(|(k, _)| k.as_str() != "alertname")
            .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
            .collect();
        kv.sort();
        parts.extend(kv);
    }
    parts.join(",")
}

// ── sanitize ───────────────────────────────────────────────

/// symptom을 argv 안전하게 정리 — 개행/제어문자 제거 + 길이 cap. 셸을 거치지 않으므로
/// injection은 없지만, 프롬프트/로그 오염을 막는다.
fn sanitize_symptom(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() > MAX_SYMPTOM_LEN {
        trimmed.chars().take(MAX_SYMPTOM_LEN).collect()
    } else {
        trimmed.to_string()
    }
}

/// 번들 라벨용 — 영숫자/-_ 만 남긴다.
fn sanitize_label(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() {
        "alert".to_string()
    } else {
        s
    }
}

// ── 이벤트 로그(JSONL) — t11 pending/audit ─────────────────

#[derive(Serialize)]
struct WebhookEvent<'a> {
    ts: String,
    source: &'a str,
    action: &'a str,
    alert: Option<&'a str>,
    severity: Option<&'a str>,
    fingerprint: Option<&'a str>,
}

/// 수신·처리 이벤트를 webhook-events.jsonl에 append(best-effort). `aic webhook list`가 읽는다.
fn record_event(source: &str, action: &str, alert: Option<&IncomingAlert>, _n: usize) {
    use std::io::Write;
    let path = aic_common::paths::webhook_events_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let ev = WebhookEvent {
        ts: chrono::Utc::now().to_rfc3339(),
        source,
        action,
        alert: alert.map(|a| a.name.as_str()),
        severity: alert.and_then(|a| a.severity.as_deref()),
        fingerprint: alert.map(|a| a.fingerprint.as_str()),
    };
    if let Ok(mut line) = serde_json::to_string(&ev) {
        if line.len() > MAX_EVENT_BYTES {
            line.truncate(MAX_EVENT_BYTES);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_bucket_limits_then_refills() {
        let t0 = Instant::now();
        let mut tb = TokenBucket::new(2, t0);
        assert!(tb.try_take(t0));
        assert!(tb.try_take(t0));
        assert!(!tb.try_take(t0), "capacity 2 소진 후 거부");
        // 30초 뒤 = 2/60*30 = 1 토큰 refill.
        let t1 = t0 + Duration::from_secs(30);
        assert!(tb.try_take(t1));
        assert!(!tb.try_take(t1));
    }

    #[test]
    fn parse_alertmanager_firing_only() {
        let body = json!({
            "alerts": [
                { "status": "firing", "labels": { "alertname": "HighCPU", "severity": "critical", "instance": "web1" },
                  "annotations": { "summary": "CPU 95%" } },
                { "status": "resolved", "labels": { "alertname": "HighCPU" } }
            ]
        });
        let alerts = parse_alertmanager_style(&body);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "HighCPU");
        assert_eq!(alerts[0].severity.as_deref(), Some("critical"));
        assert_eq!(alerts[0].summary.as_deref(), Some("CPU 95%"));
        assert!(alerts[0].fingerprint.contains("HighCPU"));
        assert!(alerts[0].fingerprint.contains("instance=web1"));
    }

    #[test]
    fn parse_pagerduty_event() {
        let body = json!({ "event": { "data": { "title": "DB down", "id": "PXYZ" } } });
        let alerts = parse_pagerduty(&body);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "DB down");
        assert_eq!(alerts[0].fingerprint, "PXYZ");
    }

    #[test]
    fn parse_generic_fallback() {
        let body = json!({ "alertname": "DiskFull", "summary": "/ at 98%", "labels": { "host": "db1" } });
        let alerts = parse_generic(&body);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "DiskFull");
        assert_eq!(alerts[0].summary.as_deref(), Some("/ at 98%"));
    }

    #[test]
    fn fingerprint_is_deterministic_and_label_order_independent() {
        let a = fingerprint_from_labels("X", Some(&json!({ "b": "2", "a": "1" })));
        let b = fingerprint_from_labels("X", Some(&json!({ "a": "1", "b": "2" })));
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_and_constant_time() {
        let sig = compute_hmac_hex(b"secret", b"body");
        // 동일 입력은 동일 출력, 64 hex chars(SHA256).
        assert_eq!(sig.len(), 64);
        assert_eq!(sig, compute_hmac_hex(b"secret", b"body"));
        assert!(constant_time_eq(sig.as_bytes(), sig.as_bytes()));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn sanitize_symptom_strips_control_and_caps() {
        let s = sanitize_symptom("line1\nline2\t\u{0}end");
        assert!(!s.contains('\n'));
        assert!(!s.contains('\u{0}'));
        let long = "x".repeat(500);
        assert!(sanitize_symptom(&long).chars().count() <= MAX_SYMPTOM_LEN);
    }

    #[test]
    fn sanitize_label_keeps_safe_chars() {
        assert_eq!(sanitize_label("HighCPU,instance=web1"), "HighCPU-instance-web1");
        assert_eq!(sanitize_label(""), "alert");
    }
}
