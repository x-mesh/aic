//! `aic web` — 읽기 전용 web 대시보드 (MVP-0).
//!
//! `aic chat`의 agentic 실행면(run_command·LLM chat)은 **노출하지 않는다**. 오직 이미 수집된
//! read-only 자산만 HTTP로 서빙한다:
//! - `GET /web/snapshots`           — 스냅샷 store(`~/.aic/snapshots/`) JSON
//! - `GET /web/incidents`           — RCA 인시던트 목록 JSON
//! - `GET /web/incidents/{id}/report` — RCA report.md(redaction 재적용) markdown
//!
//! 설계 근거(investigate/scaffold): web에 `run_command`를 여는 보안 부담을 피하고, web의 유일한
//! 실강점(시각화·공유)만 취한다. 노출은 **on-demand**(`aic web --bind`, 기본 미기동) + **토큰 필수**
//! (webhook의 secret-미설정 우회 함정을 닫는다 — VPN은 네트워크 경계지 인증이 아니다).

use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::{header::CONTENT_TYPE, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};

use crate::{rca, redaction, snapshot_store};

/// web 서버 구성. `token`은 빈 문자열이 아니어야 한다(호출부 `handle_web`에서 보장).
pub struct WebConfig {
    pub bind: String,
    pub token: String,
}

struct WebState {
    token: String,
}

/// 읽기 전용 대시보드를 `cfg.bind`에 바인드하고 Ctrl+C까지 서빙한다.
pub async fn serve(cfg: WebConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    let state = Arc::new(WebState { token: cfg.token });

    let app = Router::new()
        .route("/web/health", get(|| async { "ok" }))
        .route("/", get(index))
        .route("/web/snapshots", get(snapshots))
        .route("/web/incidents", get(incidents))
        .route("/web/incidents/{id}/report", get(incident_report))
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// Bearer 토큰 인증 미들웨어. `/web/health`만 면제(헬스 체크). 나머지는 `Authorization: Bearer <token>`
/// 상수시간 일치를 요구한다.
async fn require_token(
    State(state): State<Arc<WebState>>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/web/health" {
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

/// 최소 인덱스 — 엔드포인트 안내(프런트엔드 차트는 후속).
async fn index() -> Response {
    let body = "<!doctype html><meta charset=utf-8><title>aic web</title>\
<h1>aic web (read-only)</h1><ul>\
<li><a href=\"/web/snapshots\">/web/snapshots</a></li>\
<li><a href=\"/web/incidents\">/web/incidents</a></li>\
</ul><p>auth: Authorization: Bearer &lt;token&gt;</p>";
    ([(CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

async fn snapshots() -> Result<Json<Vec<snapshot_store::SnapshotRecord>>, (StatusCode, &'static str)> {
    let snaps = snapshot_store::load_snapshots().map_err(internal)?;
    Ok(Json(snaps))
}

async fn incidents() -> Result<Json<Vec<rca::IncidentSummary>>, (StatusCode, &'static str)> {
    let list = rca::list_incidents().map_err(internal)?;
    Ok(Json(list))
}

/// RCA report.md를 markdown으로 서빙한다. `render_report`는 redaction 미적용이므로 서빙 직전
/// `redaction::redact`를 한 번 더 통과시켜 secret 유출을 방어한다.
async fn incident_report(Path(id): Path<String>) -> Result<Response, (StatusCode, &'static str)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        // 길이 불일치는 즉시 false.
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn bearer_ok_accepts_matching_token() {
        assert!(bearer_ok(Some("Bearer s3cret"), "s3cret"));
        // 앞뒤 공백은 trim.
        assert!(bearer_ok(Some("Bearer  s3cret "), "s3cret"));
    }

    #[test]
    fn bearer_ok_rejects_mismatch_missing_and_wrong_scheme() {
        assert!(!bearer_ok(Some("Bearer wrong"), "s3cret"));
        assert!(!bearer_ok(None, "s3cret"));
        // Bearer 스킴이 아니면 거부(Basic 등).
        assert!(!bearer_ok(Some("Basic s3cret"), "s3cret"));
        // 토큰만 있고 스킴 없음.
        assert!(!bearer_ok(Some("s3cret"), "s3cret"));
    }
}
