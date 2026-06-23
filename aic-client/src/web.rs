//! `aic web` — 로컬 자원 모니터 + read-only 공유 대시보드 (MVP).
//!
//! `aic chat`의 agentic 실행면(run_command·LLM chat)은 **노출하지 않는다**. 핵심은 aic가 이미
//! 수집하는 **로컬 호스트 자원 텔레메트리**(status bar의 `SysSampler`)를 시계열 차트로 보여주는 것
//! — 외부 관측 백엔드가 없어도 바로 동작한다. 엔드포인트:
//! - `GET  /`                        — 자체완결 대시보드(외부 CDN 없음 — VPN/오프라인 대응)
//! - `GET  /web/local`               — 로컬 자원 시계열(CPU/mem/load/disk·net I/O) — **무설정 동작**
//! - `GET  /web/snapshots`           — 스냅샷 store(`~/.aic/snapshots/`) JSON
//! - `GET  /web/incidents`           — RCA 인시던트 목록 JSON(redacted, path 제외)
//! - `GET  /web/incidents/{id}/report` — RCA report.md(redaction 재적용) markdown
//! - `GET  /web/backends`            — 등록된 Prometheus/Loki 백엔드 이름(없으면 빈 목록)
//! - `POST /web/metrics`·`/web/logs` — (선택) 등록된 Prometheus/Loki 질의. 백엔드 없으면 503.
//!
//! 노출은 **on-demand**(`aic web --bind`, 기본 미기동) + **토큰 필수**. 데이터 엔드포인트(`/web/*`)는
//! Bearer 토큰을 요구하고, 대시보드 셸(`/`, `/web/health`)만 면제한다(민감 데이터 없음 — 사용자가
//! 페이지에서 토큰 입력 → JS가 이후 fetch에 Bearer로 싣는다).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{Path, Request, State},
    http::{
        header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS},
        StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::agent::obs_tools::ObsClient;
use crate::agent::sys_sampler::SysSampler;
use crate::{rca, redaction, snapshot_store};

/// 대시보드 셸(자체완결 HTML+JS, 외부 의존 없음).
const DASHBOARD: &str = include_str!("web_dashboard.html");

/// 로컬 자원 샘플링 주기(status bar와 동일 감각). disk/net bps는 연속 sample 간 delta라 일정 주기가 필요.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
/// ring buffer 상한 — 2s × 300 = 10분 history.
const RING_CAP: usize = 300;

/// 한 시점 로컬 자원 스냅샷(차트용 직렬화 DTO). 프로세스명 등 식별 정보는 담지 않는다(수치만).
#[derive(Serialize, Clone)]
struct LocalPoint {
    /// unix epoch milliseconds.
    ts: i64,
    cpu_pct: f32,
    load1: f64,
    cores: usize,
    mem_used: u64,
    mem_total: u64,
    swap_used: u64,
    swap_total: u64,
    disk_avail: u64,
    disk_total: u64,
    disk_read_bps: u64,
    disk_write_bps: u64,
    net_rx_bps: u64,
    net_tx_bps: u64,
}

/// web 서버 구성. `token`은 빈 문자열이 아니어야 한다(호출부 `handle_web`에서 보장).
/// `obs_config`는 선택 — 등록 백엔드(Prometheus/Loki)가 있으면 외부 metrics/logs 탭이 활성화된다.
pub struct WebConfig {
    pub bind: String,
    pub token: String,
    pub obs_config: aic_common::ObservabilityConfig,
}

struct WebState {
    token: String,
    /// 로컬 자원 시계열 ring buffer(백그라운드 샘플러가 채운다). 무설정 동작의 핵심.
    local: Arc<Mutex<VecDeque<LocalPoint>>>,
    /// 등록 관측 백엔드가 있을 때만 Some. 없으면 외부 metrics/logs는 503.
    obs: Option<ObsClient>,
}

/// 대시보드를 `cfg.bind`에 바인드하고 Ctrl+C까지 서빙한다. 동시에 로컬 자원 샘플러를 백그라운드로 돌린다.
pub async fn serve(cfg: WebConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    let obs = ObsClient::new(&cfg.obs_config)
        .ok()
        .filter(|c| !c.is_empty());
    let local: Arc<Mutex<VecDeque<LocalPoint>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(RING_CAP)));
    spawn_local_sampler(local.clone());

    let state = Arc::new(WebState {
        token: cfg.token,
        local,
        obs,
    });

    let app = Router::new()
        .route("/web/health", get(|| async { "ok" }))
        .route("/", get(dashboard))
        .route("/web/local", get(local_metrics))
        .route("/web/snapshots", get(snapshots))
        .route("/web/incidents", get(incidents))
        .route("/web/incidents/{id}/report", get(incident_report))
        .route("/web/backends", get(backends))
        .route("/web/metrics", post(metrics))
        .route("/web/logs", post(logs))
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// 백그라운드 로컬 자원 샘플러 — [`SAMPLE_INTERVAL`]마다 호스트 자원을 측정해 ring buffer에 쌓는다.
/// disk/net bps는 연속 sample 간 delta이므로 일정 주기 샘플링이 정확도의 전제다(status bar와 동일).
fn spawn_local_sampler(buf: Arc<Mutex<VecDeque<LocalPoint>>>) {
    tokio::spawn(async move {
        let mut sampler = SysSampler::new();
        let mut tick = tokio::time::interval(SAMPLE_INTERVAL);
        loop {
            tick.tick().await;
            let m = sampler.sample();
            let point = LocalPoint {
                ts: chrono::Utc::now().timestamp_millis(),
                cpu_pct: m.cpu_pct,
                load1: m.load1,
                cores: m.cores,
                mem_used: m.mem_used,
                mem_total: m.mem_total,
                swap_used: m.swap_used,
                swap_total: m.swap_total,
                disk_avail: m.disk_avail,
                disk_total: m.disk_total,
                disk_read_bps: m.disk_read_bps,
                disk_write_bps: m.disk_write_bps,
                net_rx_bps: m.net_rx_bps,
                net_tx_bps: m.net_tx_bps,
            };
            // lock은 push 동안만 잡고 즉시 해제(.await를 가로지르지 않는다).
            if let Ok(mut b) = buf.lock() {
                if b.len() >= RING_CAP {
                    b.pop_front();
                }
                b.push_back(point);
            }
        }
    });
}

/// 인증 면제 경로 — 대시보드 셸과 헬스 체크(민감 데이터 없음). 나머지 `/web/*`는 Bearer 토큰 필수.
fn auth_exempt(path: &str) -> bool {
    path == "/" || path == "/web/health"
}

/// Bearer 토큰 인증 미들웨어. [`auth_exempt`] 경로만 면제하고, 나머지는
/// `Authorization: Bearer <token>` 상수시간 일치를 요구한다.
async fn require_token(State(state): State<Arc<WebState>>, req: Request, next: Next) -> Response {
    if auth_exempt(req.uri().path()) {
        return next.run(req).await;
    }
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    if bearer_ok(header, &state.token) {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
    }
}

/// `Authorization` 헤더 값이 `Bearer <token>`이고 토큰이 상수시간 일치하면 true.
fn bearer_ok(header: Option<&str>, token: &str) -> bool {
    let Some(value) = header else {
        return false;
    };
    let Some(provided) = value.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(provided.trim().as_bytes(), token.as_bytes())
}

/// 타이밍 공격 방지 상수시간 비교(webhook_server와 동일 정책).
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

/// 500으로 매핑하되 내부 에러 본문은 노출하지 않는다(메시지 누출 방지).
fn internal(_e: anyhow::Error) -> (StatusCode, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
}

/// 대시보드 셸(자체완결 HTML). clickjacking/MIME-sniffing 방어 헤더를 함께 싣는다.
async fn dashboard() -> Response {
    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (X_FRAME_OPTIONS, "DENY"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        DASHBOARD,
    )
        .into_response()
}

/// 로컬 자원 시계열 — 무설정 동작의 핵심. ring buffer 전체를 JSON으로 낸다(수치만, 식별정보 없음).
async fn local_metrics(State(state): State<Arc<WebState>>) -> Json<Value> {
    let points: Vec<LocalPoint> = state
        .local
        .lock()
        .map(|b| b.iter().cloned().collect())
        .unwrap_or_default();
    Json(json!({ "points": points }))
}

async fn snapshots() -> Result<Json<Vec<snapshot_store::SnapshotRecord>>, (StatusCode, &'static str)>
{
    let snaps = snapshot_store::load_snapshots().map_err(internal)?;
    Ok(Json(snaps))
}

/// RCA 인시던트 목록. `IncidentSummary`를 그대로 직렬화하면 `path`(서버 홈 절대경로)가 노출되고
/// `title`/`symptom`/`cwd`는 redaction 미적용이다. 여기서 `path`를 제외하고 입력 필드에 redaction을 적용한다.
async fn incidents() -> Result<Json<Vec<Value>>, (StatusCode, &'static str)> {
    let list = rca::list_incidents().map_err(internal)?;
    let out: Vec<Value> = list
        .into_iter()
        .map(|i| {
            json!({
                "id": i.id,
                "title": redaction::redact(&i.title).0,
                "status": i.status,
                "symptom": i.symptom.map(|s| redaction::redact(&s).0),
                "cwd": i.cwd.map(|s| redaction::redact(&s).0),
                "created_at": i.created_at,
                "updated_at": i.updated_at,
                "evidence_count": i.evidence_count,
            })
        })
        .collect();
    Ok(Json(out))
}

/// 인시던트 id는 생성 시 timestamp + slug(`[A-Za-z0-9_-]`)만 쓴다. 데이터 디렉터리에 닿기 전에
/// allowlist로 검증해 path traversal을 차단한다 — axum `Path`는 `%2F`를 `/`로 percent-decode하고
/// `PathBuf::join`은 절대경로 인자로 base를 통째로 치환하므로, `/`·`\`·`.`(따라서 `..`)를 모두 거른다.
fn is_safe_incident_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// RCA report.md를 markdown으로 서빙한다. `render_report`는 redaction 미적용이므로 서빙 직전
/// `redaction::redact`를 한 번 더 통과시켜 secret 유출을 방어한다.
async fn incident_report(Path(id): Path<String>) -> Result<Response, (StatusCode, &'static str)> {
    if !is_safe_incident_id(&id) {
        return Err((StatusCode::BAD_REQUEST, "invalid incident id\n"));
    }
    let meta = rca::load_meta(&id).map_err(internal)?;
    let events = rca::load_events(&id).map_err(internal)?;
    let report = rca::render_report(&meta, &events);
    let (redacted, _) = redaction::redact(&report);
    Ok((
        [(CONTENT_TYPE, "text/markdown; charset=utf-8")],
        redacted,
    )
        .into_response())
}

/// 등록된 관측 백엔드 이름(타입별). 외부 metrics/logs 탭 활성화 판단 + 드롭다운용. 없으면 빈 목록.
async fn backends(State(state): State<Arc<WebState>>) -> Json<Value> {
    use aic_common::BackendType;
    let (prom, loki) = match &state.obs {
        Some(o) => (
            o.backend_names_of(BackendType::Prometheus),
            o.backend_names_of(BackendType::Loki),
        ),
        None => (Vec::new(), Vec::new()),
    };
    Json(json!({ "prometheus": prom, "loki": loki }))
}

/// (선택) PromQL 질의 — 등록 백엔드가 있을 때만. ObsClient 출력(redacted·bounded)을 그대로 서빙.
async fn metrics(State(state): State<Arc<WebState>>, Json(args): Json<Value>) -> Response {
    obs_query(&state, "prometheus_query", &args).await
}

/// (선택) LogQL 질의 — 등록 백엔드가 있을 때만.
async fn logs(State(state): State<Arc<WebState>>, Json(args): Json<Value>) -> Response {
    obs_query(&state, "loki_query", &args).await
}

/// 관측 질의 공통 — ObsClient.run의 출력(이미 redact·bounded)을 application/json으로 서빙한다.
/// 백엔드 allowlist·URL 검증·결과 bound는 모두 ObsClient가 담당한다(web은 얇은 어댑터).
async fn obs_query(state: &WebState, tool: &str, args: &Value) -> Response {
    let Some(obs) = &state.obs else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "관측 백엔드가 등록되지 않았습니다 ([observability.backends.*])\n",
        )
            .into_response();
    };
    match obs.run(tool, args).await {
        Ok(body) => ([(CONTENT_TYPE, "application/json")], body).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn bearer_ok_accepts_matching_token() {
        assert!(bearer_ok(Some("Bearer s3cret"), "s3cret"));
        assert!(bearer_ok(Some("Bearer  s3cret "), "s3cret"));
    }

    #[test]
    fn bearer_ok_rejects_mismatch_missing_and_wrong_scheme() {
        assert!(!bearer_ok(Some("Bearer wrong"), "s3cret"));
        assert!(!bearer_ok(None, "s3cret"));
        assert!(!bearer_ok(Some("Basic s3cret"), "s3cret"));
        assert!(!bearer_ok(Some("s3cret"), "s3cret"));
    }

    #[test]
    fn is_safe_incident_id_rejects_traversal() {
        assert!(is_safe_incident_id("20260623-031042-web-demo"));
        assert!(is_safe_incident_id("abc_123-XY"));
        assert!(!is_safe_incident_id("../../etc"));
        assert!(!is_safe_incident_id("/etc"));
        assert!(!is_safe_incident_id(".."));
        assert!(!is_safe_incident_id("a/b"));
        assert!(!is_safe_incident_id("a\\b"));
        assert!(!is_safe_incident_id(""));
        assert!(!is_safe_incident_id(&"x".repeat(200)));
    }

    #[test]
    fn auth_exempt_only_shell_and_health() {
        assert!(auth_exempt("/"));
        assert!(auth_exempt("/web/health"));
        assert!(!auth_exempt("/web/local"));
        assert!(!auth_exempt("/web/snapshots"));
        assert!(!auth_exempt("/web/incidents"));
        assert!(!auth_exempt("/web/metrics"));
    }

    #[test]
    fn local_point_serializes_numeric_only() {
        // 식별정보(프로세스명 등) 없이 수치만 직렬화되는지 — 키 집합 고정 검증.
        let p = LocalPoint {
            ts: 1,
            cpu_pct: 12.5,
            load1: 1.0,
            cores: 8,
            mem_used: 100,
            mem_total: 200,
            swap_used: 0,
            swap_total: 0,
            disk_avail: 10,
            disk_total: 20,
            disk_read_bps: 0,
            disk_write_bps: 0,
            net_rx_bps: 0,
            net_tx_bps: 0,
        };
        let v = serde_json::to_value(&p).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("cpu_pct") && obj.contains_key("ts"));
        assert_eq!(obj["cores"], 8);
        // host/process 등 식별 키가 없어야 한다.
        assert!(!obj.contains_key("host") && !obj.contains_key("proc"));
    }

    #[test]
    fn dashboard_html_is_self_contained() {
        assert!(!DASHBOARD.contains("http://"));
        assert!(!DASHBOARD.contains("https://"));
        assert!(!DASHBOARD.contains("src=\"//"));
        // 로컬 자원이 중심 — /web/local을 호출한다.
        assert!(DASHBOARD.contains("/web/local"));
        assert!(DASHBOARD.contains("Bearer "));
    }
}
