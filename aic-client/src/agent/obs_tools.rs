//! 관측 백엔드(Prometheus / Loki / Elasticsearch) read-only 질의 도구 (SRE R1).
//!
//! `run_command`(셸 실행)과 분리된 **독립 HTTP 도구**다. PromQL/LogQL/ES REST는
//! 셸 명령이 아니라 HTTP 호출이므로 셸 도구의 메타문자/sandbox 검증과 맞지 않는다.
//!
//! 보안 불변식:
//! - **endpoint allowlist** — config `[observability.backends.*]`에 등록된 백엔드만
//!   질의 가능. LLM은 backend *이름*만 고르고 URL을 직접 줄 수 없다 → SSRF 차단의 핵심.
//! - **redirect 비활성** — reqwest가 3xx를 자동 추적하지 않는다. 등록 endpoint가
//!   클라우드 메타데이터(`169.254.169.254`)로 우회 redirect하는 공격을 막는다 (A1).
//! - **link-local 차단** — 백엔드 host가 IP 리터럴이고 link-local/unspecified면 거부.
//! - **bounded** — 응답 본문/출력 문자열을 cap으로 제한해 context 폭주를 막는다.
//!
//! 응답 redaction 패턴 강화(Bearer/conn-string)는 R1-obs-redaction(t5)에서 추가된다.
//! 여기서는 기존 `redaction::redact`를 출력 직전에 적용한다.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use futures::StreamExt;
use serde_json::{json, Value};

use super::tools::ToolError;
use super::types::ToolSpec;
use aic_common::{BackendConfig, BackendType, ObservabilityConfig};

const CONNECT_TIMEOUT_SECS: u64 = 5;
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// 네트워크 레벨 응답 본문 fetch 상한.
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
/// LLM/출력에 넘기는 최종 문자열 상한.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// Loki/ES 기본 결과 행 수.
const DEFAULT_LIMIT: u64 = 100;
/// 결과 행 수 하드 상한.
const MAX_LIMIT: u64 = 1000;

/// 등록된 관측 백엔드에 대한 read-only HTTP 질의 클라이언트.
pub struct ObsClient {
    http: reqwest::Client,
    backends: HashMap<String, BackendConfig>,
}

impl ObsClient {
    /// config의 `[observability]`에서 클라이언트를 만든다.
    /// redirect 비활성 + 타임아웃 적용.
    pub fn new(cfg: &ObservabilityConfig) -> Result<Self, ToolError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| ToolError::new(format!("HTTP 클라이언트 생성 실패: {e}")))?;
        Ok(Self {
            http,
            backends: cfg.backends.clone(),
        })
    }

    /// 등록된 백엔드 이름 목록(정렬). 도구 description / 에러 메시지용.
    pub fn backend_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.backends.keys().cloned().collect();
        names.sort();
        names
    }

    /// 등록된 백엔드가 하나도 없으면 true.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// 특정 타입의 등록 백엔드 이름 목록(정렬).
    pub fn backend_names_of(&self, t: BackendType) -> Vec<String> {
        let mut v: Vec<String> = self
            .backends
            .iter()
            .filter(|(_, b)| b.backend_type == t)
            .map(|(name, _)| name.clone())
            .collect();
        v.sort();
        v
    }

    /// LLM에 노출할 ToolSpec 목록. 타입별 등록 백엔드가 있을 때만 해당 도구를 포함하고,
    /// `backend` 파라미터의 JSON Schema `enum`에 실제 백엔드 이름을 박아 LLM이 임의 URL을
    /// 만들지 못하게 한다(endpoint allowlist의 스키마 레벨 강제).
    pub fn specs(&self) -> Vec<ToolSpec> {
        let mut specs = Vec::new();
        let prom = self.backend_names_of(BackendType::Prometheus);
        if !prom.is_empty() {
            specs.push(ToolSpec {
                name: "prometheus_query",
                description: "등록된 Prometheus(또는 VictoriaMetrics) 백엔드에 PromQL을 질의한다. \
                              read-only. `start`+`end`(+`step`)를 주면 range query, 없으면 instant query. \
                              결과는 bounded JSON. 임의 URL은 불가 — `backend`는 등록된 이름만 허용.",
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "backend": { "type": "string", "enum": prom, "description": "질의할 Prometheus 백엔드 이름" },
                        "query": { "type": "string", "description": "PromQL 식 (예: up, rate(http_requests_total[5m]))" },
                        "time": { "type": "string", "description": "instant query 평가 시각(RFC3339 또는 unix ts, 선택)" },
                        "start": { "type": "string", "description": "range query 시작(unix ts/RFC3339). end와 함께." },
                        "end": { "type": "string", "description": "range query 끝(unix ts/RFC3339). start와 함께." },
                        "step": { "type": "string", "description": "range query 해상도(예: 30s, 1m. 기본 60s)" }
                    },
                    "required": ["backend", "query"]
                }),
            });
        }
        let loki = self.backend_names_of(BackendType::Loki);
        if !loki.is_empty() {
            specs.push(ToolSpec {
                name: "loki_query",
                description: "등록된 Loki 백엔드에 LogQL을 query_range로 질의한다. read-only. \
                              결과 행 수는 limit로 bound(기본 100, 상한 1000). `backend`는 등록된 이름만 허용.",
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "backend": { "type": "string", "enum": loki, "description": "질의할 Loki 백엔드 이름" },
                        "query": { "type": "string", "description": "LogQL 식 (예: {app=\"api\"} |= \"error\")" },
                        "start": { "type": "string", "description": "시작 시각(unix ns/RFC3339, 선택)" },
                        "end": { "type": "string", "description": "끝 시각(unix ns/RFC3339, 선택)" },
                        "limit": { "type": "integer", "description": "최대 로그 행 수(기본 100, 상한 1000)" }
                    },
                    "required": ["backend", "query"]
                }),
            });
        }
        let es = self.backend_names_of(BackendType::Elasticsearch);
        if !es.is_empty() {
            specs.push(ToolSpec {
                name: "es_search",
                description: "등록된 Elasticsearch/OpenSearch 백엔드에 query_string으로 검색한다. read-only. \
                              결과 수는 size로 bound(기본 100, 상한 1000). `backend`는 등록된 이름만 허용.",
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "backend": { "type": "string", "enum": es, "description": "검색할 Elasticsearch 백엔드 이름" },
                        "index": { "type": "string", "description": "인덱스 패턴 (예: logs-*). 영숫자와 -_.*, 만 허용" },
                        "query": { "type": "string", "description": "Lucene query_string (예: level:ERROR AND service:api)" },
                        "size": { "type": "integer", "description": "최대 hit 수(기본 100, 상한 1000)" }
                    },
                    "required": ["backend", "index", "query"]
                }),
            });
        }
        specs
    }

    /// tool 이름으로 질의를 디스패치한다. (t6 tool registry가 이 진입점을 호출)
    pub async fn run(&self, tool: &str, args: &Value) -> Result<String, ToolError> {
        match tool {
            "prometheus_query" => self.prometheus_query(args).await,
            "loki_query" => self.loki_query(args).await,
            "es_search" => self.es_search(args).await,
            other => Err(ToolError::new(format!("미지원 관측 도구: {other}"))),
        }
    }

    fn resolve_backend(&self, name: &str, expect: BackendType) -> Result<&BackendConfig, ToolError> {
        let b = self.backends.get(name).ok_or_else(|| {
            let known = self.backend_names();
            let hint = if known.is_empty() {
                "등록된 백엔드가 없습니다. config [observability.backends.<name>]에 추가하세요".to_string()
            } else {
                format!("등록된 백엔드: {}", known.join(", "))
            };
            ToolError::new(format!("등록되지 않은 관측 백엔드: '{name}'. {hint}"))
        })?;
        if b.backend_type != expect {
            return Err(ToolError::new(format!(
                "백엔드 '{name}'는 {expect:?} 타입이 아닙니다(실제 {:?})",
                b.backend_type
            )));
        }
        Ok(b)
    }

    // ── 백엔드별 질의 ──────────────────────────────────────

    /// Prometheus PromQL — `start`+`end`가 있으면 range query, 없으면 instant query.
    async fn prometheus_query(&self, args: &Value) -> Result<String, ToolError> {
        let name = arg_str(args, "backend")?;
        let backend = self.resolve_backend(name, BackendType::Prometheus)?;
        let query = arg_str(args, "query")?;

        let (path, params): (&str, Vec<(&str, String)>) = match (
            args.get("start").and_then(value_as_str),
            args.get("end").and_then(value_as_str),
        ) {
            (Some(start), Some(end)) => {
                let step = args
                    .get("step")
                    .and_then(value_as_str)
                    .unwrap_or_else(|| "60s".to_string());
                (
                    "/api/v1/query_range",
                    vec![
                        ("query", query.to_string()),
                        ("start", start),
                        ("end", end),
                        ("step", step),
                    ],
                )
            }
            _ => {
                let mut p = vec![("query", query.to_string())];
                if let Some(time) = args.get("time").and_then(value_as_str) {
                    p.push(("time", time));
                }
                ("/api/v1/query", p)
            }
        };

        let url = build_url(&backend.url, path)?;
        let req = self.http.get(url).query(&params);
        let body = self.send_bounded(req, backend).await?;
        Ok(finalize(&body))
    }

    /// Loki LogQL — `query_range` 기반. `start`/`end`/`limit` 선택.
    async fn loki_query(&self, args: &Value) -> Result<String, ToolError> {
        let name = arg_str(args, "backend")?;
        let backend = self.resolve_backend(name, BackendType::Loki)?;
        let query = arg_str(args, "query")?;
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64));

        let mut params = vec![("query", query.to_string()), ("limit", limit.to_string())];
        if let Some(start) = args.get("start").and_then(value_as_str) {
            params.push(("start", start));
        }
        if let Some(end) = args.get("end").and_then(value_as_str) {
            params.push(("end", end));
        }

        let url = build_url(&backend.url, "/loki/api/v1/query_range")?;
        let req = self.http.get(url).query(&params);
        let body = self.send_bounded(req, backend).await?;
        Ok(finalize(&body))
    }

    /// Elasticsearch / OpenSearch — `index` 패턴 + `query`(query_string) + `size`.
    async fn es_search(&self, args: &Value) -> Result<String, ToolError> {
        let name = arg_str(args, "backend")?;
        let backend = self.resolve_backend(name, BackendType::Elasticsearch)?;
        let index = arg_str(args, "index")?;
        let query = arg_str(args, "query")?;
        let size = clamp_limit(args.get("size").and_then(Value::as_u64));

        // index는 URL path component이므로 안전한 문자만 허용(경로 탈출/injection 차단).
        if !is_safe_index(index) {
            return Err(ToolError::new(format!(
                "안전하지 않은 index 패턴: '{index}' (영숫자, '-_.*,' 만 허용)"
            )));
        }

        let body = json!({
            "size": size,
            "query": { "query_string": { "query": query } }
        });

        let url = build_url(&backend.url, &format!("/{index}/_search"))?;
        let req = self.http.post(url).json(&body);
        let text = self.send_bounded(req, backend).await?;
        Ok(finalize(&text))
    }

    // ── 공통 전송 + bounded read ───────────────────────────

    async fn send_bounded(
        &self,
        mut req: reqwest::RequestBuilder,
        backend: &BackendConfig,
    ) -> Result<String, ToolError> {
        if let Some(auth) = &backend.auth {
            let token = crate::keychain::resolve(auth)
                .map_err(|e| ToolError::new(format!("백엔드 인증 토큰 resolve 실패: {e}")))?;
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ToolError::new(format!("HTTP 요청 실패: {e}")))?;
        let status = resp.status();
        let bytes = read_bounded(resp).await?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !status.is_success() {
            return Err(ToolError::new(format!(
                "백엔드 오류 {status}: {}",
                truncate(&text, 2000)
            )));
        }
        Ok(text)
    }
}

// ── 자유 함수 헬퍼 ─────────────────────────────────────────

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, ToolError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::new(format!("필수 인자 '{key}'가 없거나 문자열이 아님")))
}

/// 숫자 또는 문자열 타임스탬프를 문자열로 받는다(Prometheus는 둘 다 허용).
fn value_as_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn clamp_limit(requested: Option<u64>) -> u64 {
    requested.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// base URL + path를 합쳐 검증된 `Url`을 만든다.
fn build_url(base: &str, path: &str) -> Result<reqwest::Url, ToolError> {
    let trimmed = base.trim_end_matches('/');
    ensure_safe_url(&format!("{trimmed}{path}"))
}

/// scheme/host 안전성 검사. http(s)만, IP 리터럴 host는 link-local/unspecified 거부.
pub(crate) fn ensure_safe_url(raw: &str) -> Result<reqwest::Url, ToolError> {
    let url = reqwest::Url::parse(raw)
        .map_err(|e| ToolError::new(format!("백엔드 URL 파싱 실패: {raw} ({e})")))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(ToolError::new(format!("지원하지 않는 URL scheme: {other}"))),
    }
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_blocked_ip(&ip) {
                return Err(ToolError::new(format!(
                    "차단된 IP 대역(link-local/metadata/unspecified): {host}"
                )));
            }
        }
    }
    Ok(url)
}

/// 클라우드 메타데이터(169.254.169.254 등 link-local) 및 unspecified 주소 차단.
/// loopback/사설 대역은 사내 모니터링이 정상적으로 쓰므로 허용한다.
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// ES index 패턴 허용 문자(경로 탈출/injection 차단).
fn is_safe_index(index: &str) -> bool {
    !index.is_empty()
        && index
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '*' | ','))
}

/// 응답을 MAX_RESPONSE_BYTES까지만 스트리밍으로 읽는다(거대 응답 OOM 방지).
pub(crate) async fn read_bounded(resp: reqwest::Response) -> Result<Vec<u8>, ToolError> {
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ToolError::new(format!("응답 읽기 실패: {e}")))?;
        if buf.len() >= MAX_RESPONSE_BYTES {
            break;
        }
        let remaining = MAX_RESPONSE_BYTES - buf.len();
        if chunk.len() > remaining {
            buf.extend_from_slice(&chunk[..remaining]);
            break;
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// LLM/출력 전 최종 처리: redaction 적용 + 출력 길이 cap.
pub(crate) fn finalize(body: &str) -> String {
    let (redacted, _report) = crate::redaction::redact(body);
    truncate(&redacted, MAX_OUTPUT_BYTES)
}

pub(crate) fn truncate(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…(출력이 {max_bytes} bytes로 잘림)", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::BackendConfig;

    fn cfg_with(name: &str, backend_type: BackendType, url: &str) -> ObservabilityConfig {
        let mut backends = HashMap::new();
        backends.insert(
            name.to_string(),
            BackendConfig {
                backend_type,
                url: url.to_string(),
                auth: None,
            },
        );
        ObservabilityConfig { backends }
    }

    #[test]
    fn unregistered_backend_is_rejected() {
        let cfg = cfg_with("prom", BackendType::Prometheus, "http://localhost:9090");
        let client = ObsClient::new(&cfg).unwrap();
        let err = client
            .resolve_backend("nope", BackendType::Prometheus)
            .unwrap_err();
        assert!(err.message.contains("등록되지 않은"));
    }

    #[test]
    fn wrong_backend_type_is_rejected() {
        let cfg = cfg_with("prom", BackendType::Prometheus, "http://localhost:9090");
        let client = ObsClient::new(&cfg).unwrap();
        let err = client
            .resolve_backend("prom", BackendType::Loki)
            .unwrap_err();
        assert!(err.message.contains("타입이 아닙니다"));
    }

    #[test]
    fn link_local_ip_is_blocked() {
        // 클라우드 메타데이터 SSRF 차단 (A1).
        let err = ensure_safe_url("http://169.254.169.254/latest/meta-data/").unwrap_err();
        assert!(err.message.contains("차단된 IP"));
    }

    #[test]
    fn unspecified_ip_is_blocked() {
        assert!(ensure_safe_url("http://0.0.0.0:9090/api/v1/query").is_err());
    }

    #[test]
    fn private_and_loopback_ips_are_allowed() {
        // 사내 모니터링은 사설/loopback 대역을 정상 사용.
        assert!(ensure_safe_url("http://10.0.0.5:9090/api/v1/query").is_ok());
        assert!(ensure_safe_url("http://192.168.1.10:3100/loki/api/v1/query_range").is_ok());
        assert!(ensure_safe_url("http://127.0.0.1:9090/api/v1/query").is_ok());
    }

    #[test]
    fn non_http_scheme_is_rejected() {
        assert!(ensure_safe_url("file:///etc/passwd").is_err());
        assert!(ensure_safe_url("ftp://example.com/x").is_err());
    }

    #[test]
    fn build_url_trims_trailing_slash() {
        let url = build_url("http://prometheus:9090/", "/api/v1/query").unwrap();
        assert_eq!(url.as_str(), "http://prometheus:9090/api/v1/query");
    }

    #[test]
    fn is_safe_index_rejects_path_traversal() {
        assert!(is_safe_index("logs-*"));
        assert!(is_safe_index("app-2026.06.10"));
        assert!(!is_safe_index("../secrets"));
        assert!(!is_safe_index("a/b"));
        assert!(!is_safe_index(""));
    }

    #[test]
    fn clamp_limit_bounds() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(50)), 50);
        assert_eq!(clamp_limit(Some(99_999)), MAX_LIMIT);
    }

    #[test]
    fn truncate_caps_output() {
        let big = "x".repeat(MAX_OUTPUT_BYTES + 100);
        let out = truncate(&big, MAX_OUTPUT_BYTES);
        assert!(out.len() <= MAX_OUTPUT_BYTES + 64);
        assert!(out.contains("잘림"));
    }
}
