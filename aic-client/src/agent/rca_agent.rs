//! rca-agent(RCA-eBPF) localhost control API pull 클라이언트 (커널 evidence Phase 1).
//!
//! rca-agent는 커널 eBPF 신호를 수집하는 별도 system 데몬이다 — 생명주기는 system
//! systemd가 소유하고, aic는 소비자로서 control API에서 `rca.evidence.v1` evidence
//! bundle을 **pull**만 한다(rca-agent ADR-0048 D2 경계 — 에이전트 쪽 변경 0).
//!
//! 보안 불변식:
//! - **loopback 전용** — evidence bundle은 PID/comm/cgroup entity를 담으므로 호스트 밖
//!   전송은 rca-agent 쪽 opt-in push의 몫이다. aic는 원격 rca-agent URL을 거부한다.
//! - **bounded + redacted** — 응답은 obs_tools와 동일한 cap/redaction(`finalize`)을 거친다.
//! - 도구는 read-only pull이므로 run_command 게이트와 무관하게 노출한다.
//!
//! 해석 주의(도구 description에도 명시): rca-agent는 판정하지 않는 collector다.
//! `findings`는 임계값 없는 관측 delta, `correlation_hint`는 rule 기반 참고 힌트,
//! `baseline.available`은 "이전 저장 이력 있음"일 뿐이다 — 판정은 소비자(aic) 몫.

use std::net::IpAddr;
use std::time::Duration;

use serde_json::{json, Value};

use super::obs_tools::{ensure_safe_url, finalize, read_bounded, truncate};
use super::tools::ToolError;
use super::types::ToolSpec;
use aic_common::RcaAgentConfig;

const CONNECT_TIMEOUT_SECS: u64 = 3;
/// collect는 요청한 window만큼 서버가 블록하므로 요청별 timeout = window + margin.
const COLLECT_MARGIN_SECS: u64 = 15;
/// 수집 window 기본/하한/상한(초). 상한은 rca-agent 쪽 5분 bound와 일치.
const DEFAULT_WINDOW_SECS: u64 = 30;
const MIN_WINDOW_SECS: u64 = 5;
const MAX_WINDOW_SECS: u64 = 300;

/// 로컬 rca-agent control API에 대한 read-only pull 클라이언트.
pub struct RcaAgentClient {
    http: reqwest::Client,
    base: String,
}

impl RcaAgentClient {
    /// config `[rca_agent]`에서 클라이언트를 만든다. 비활성(enabled=false)이면 `Ok(None)`.
    /// URL이 loopback이 아니면 에러 — entity 포함 evidence의 호스트 밖 유출을 차단한다.
    pub fn new(cfg: &RcaAgentConfig) -> Result<Option<Self>, ToolError> {
        if !cfg.enabled {
            return Ok(None);
        }
        let url = ensure_safe_url(cfg.url.trim_end_matches('/'))?;
        ensure_loopback(&url)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .build()
            .map_err(|e| ToolError::new(format!("HTTP 클라이언트 생성 실패: {e}")))?;
        Ok(Some(Self {
            http,
            base: url.as_str().trim_end_matches('/').to_string(),
        }))
    }

    /// control API base URL(에러 메시지/evidence source 표기용).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// LLM에 노출할 ToolSpec 목록.
    pub fn specs(&self) -> Vec<ToolSpec> {
        vec![
            ToolSpec {
                name: "rca_agent_collect",
                description:
                    "로컬 rca-agent(커널 eBPF collector)에서 evidence bundle(rca.evidence.v1)을 \
                     수집한다. 지정한 window(초) 동안 블록한 뒤 신호별 delta·findings·correlation \
                     hint를 JSON으로 반환한다. read-only. 해석 주의: findings는 임계값 없는 관측 \
                     delta이고 correlation_hint는 rule 기반 참고 힌트다 — root cause 판정이 아니며 \
                     baseline.available은 저장 이력 유무일 뿐이다.",
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "duration_secs": {
                            "type": "integer",
                            "description": "수집 window 초(기본 30, 범위 5..300). 이 시간만큼 블록된다."
                        }
                    }
                }),
            },
            ToolSpec {
                name: "rca_agent_features",
                description:
                    "rca-agent의 신호별 BPF attach 상태(enabled/attach flavor/disabled 사유)와 \
                     kernel capability(btf/tracing/ringbuf 등)를 조회한다. read-only, 즉시 반환.",
                parameters: json!({ "type": "object", "properties": {} }),
            },
        ]
    }

    /// tool 이름으로 디스패치한다(session exec_tool 진입점).
    pub async fn run(&self, tool: &str, args: &Value) -> Result<String, ToolError> {
        match tool {
            "rca_agent_collect" => {
                let secs = args
                    .get("duration_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_WINDOW_SECS);
                self.collect(secs).await
            }
            "rca_agent_features" => self.features().await,
            other => Err(ToolError::new(format!("미지원 rca-agent 도구: {other}"))),
        }
    }

    /// `POST /collectz?profile=incident&duration=<w>s` — window만큼 블록 후 evidence bundle 반환.
    pub async fn collect(&self, window_secs: u64) -> Result<String, ToolError> {
        let secs = window_secs.clamp(MIN_WINDOW_SECS, MAX_WINDOW_SECS);
        let url = format!("{}/collectz?profile=incident&duration={secs}s", self.base);
        let req = self
            .http
            .post(&url)
            .timeout(Duration::from_secs(secs + COLLECT_MARGIN_SECS));
        self.send(req).await
    }

    /// `GET /featuresz` — 신호별 attach 상태 + kernel capability.
    pub async fn features(&self) -> Result<String, ToolError> {
        let url = format!("{}/featuresz", self.base);
        let req = self.http.get(&url).timeout(Duration::from_secs(10));
        self.send(req).await
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<String, ToolError> {
        let resp = req.send().await.map_err(|e| {
            ToolError::new(format!(
                "rca-agent 요청 실패: {e}. rca-agent가 실행 중인지 확인하세요 \
                 (systemctl status rca-agent)"
            ))
        })?;
        let status = resp.status();
        let bytes = read_bounded(resp).await?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !status.is_success() {
            return Err(ToolError::new(format!(
                "rca-agent 오류 {status}: {}",
                truncate(&text, 2000)
            )));
        }
        Ok(finalize(&text))
    }
}

/// host가 loopback(127.0.0.0/8, ::1) 또는 `localhost`인지 강제한다.
fn ensure_loopback(url: &reqwest::Url) -> Result<(), ToolError> {
    let host = url.host_str().unwrap_or_default();
    let host_ip = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let is_loopback = host_ip.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !is_loopback {
        return Err(ToolError::new(format!(
            "rca-agent URL은 loopback만 허용됩니다: '{host}'. evidence bundle은 PID/comm 등 \
             entity를 담으므로 원격 전송은 rca-agent 쪽 opt-in push 설정을 사용하세요."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, url: &str) -> RcaAgentConfig {
        RcaAgentConfig {
            enabled,
            url: url.to_string(),
        }
    }

    #[test]
    fn disabled_config_yields_none() {
        assert!(RcaAgentClient::new(&cfg(false, "http://127.0.0.1:9090"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn loopback_urls_are_accepted() {
        for url in [
            "http://127.0.0.1:9090",
            "http://localhost:9090",
            "http://[::1]:9090",
            // trailing slash는 base에서 제거된다.
            "http://127.0.0.1:9090/",
        ] {
            let client = RcaAgentClient::new(&cfg(true, url)).unwrap().unwrap();
            assert!(!client.base().ends_with('/'), "url={url}");
        }
    }

    #[test]
    fn non_loopback_urls_are_rejected() {
        for url in [
            "http://10.0.0.5:9090",
            "http://192.168.1.10:9090",
            "http://rca.example.com:9090",
            "https://[2001:db8::1]:9090",
        ] {
            let err = RcaAgentClient::new(&cfg(true, url)).unwrap_err();
            assert!(err.message.contains("loopback"), "url={url}: {}", err.message);
        }
    }

    #[test]
    fn default_config_url_is_loopback() {
        let mut c = RcaAgentConfig::default();
        assert!(!c.enabled);
        c.enabled = true;
        assert!(RcaAgentClient::new(&c).unwrap().is_some());
    }

    #[test]
    fn specs_expose_two_readonly_tools() {
        let client = RcaAgentClient::new(&cfg(true, "http://127.0.0.1:9090"))
            .unwrap()
            .unwrap();
        let names: Vec<&str> = client.specs().iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["rca_agent_collect", "rca_agent_features"]);
    }
}
