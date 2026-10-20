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
//!   `/collectz` 번들만은 JSON 구조를 지키며 줄인다(`finalize_bundle`).
//! - 도구는 read-only pull이므로 run_command 게이트와 무관하게 노출한다.
//!
//! 해석 주의(도구 description에도 명시): rca-agent는 판정하지 않는 collector다.
//! `findings`는 임계값 없는 관측 delta, `correlation_hint`는 rule 기반 참고 힌트,
//! `baseline.available`은 "이전 저장 이력 있음"일 뿐이다 — 판정은 소비자(aic) 몫.
//!
//! **동시 collect는 서버가 막아 주지 않는다.** rca-agent에는 collect 상호배제 가드가
//! 없어(`internal/control/collector.go`에 mutex 0건) 겹쳐 호출해도 409 같은 거절이
//! 오지 않는다. 지금은 호출이 사용자 주도(도구/CLI 1회)라 문제가 없지만, 주기 수집을
//! 붙이는 쪽에서는 수집 중 tick을 건너뛰는 자체 상호배제를 스스로 넣어야 한다.

use std::net::IpAddr;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::obs_tools::{
    ensure_safe_url, finalize, read_capped, truncate, MAX_OUTPUT_BYTES, MAX_RESPONSE_BYTES,
};
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
/// `/collectz` 번들 읽기 상한. process_tree(노드 1024개)를 켜면 600KB를 넘어 공용 512KB로는
/// JSON 중간이 잘린다. aic-server OTLP exporter의 `MAX_BUNDLE_BYTES`와 같은 값.
const MAX_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
/// 출력 상한 때문에 생략한 `observations.top` 하위 값을 대신하는 표식 키(값은 원래 크기).
const OMITTED_KEY: &str = "aic_omitted_bytes";

/// 로컬 rca-agent control API에 대한 read-only pull 클라이언트.
#[derive(Debug)]
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
                     baseline.available은 저장 이력 유무일 뿐이다. 출력 상한 때문에 \
                     observations.top 하위 값이 {\"aic_omitted_bytes\": N}으로 바뀌어 있으면 \
                     N bytes가 생략된 것이지 데이터가 없다는 뜻이 아니다.",
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
        let (text, truncated) = self.fetch(req, MAX_BUNDLE_BYTES).await?;
        if truncated {
            return Err(ToolError::new(format!(
                "rca-agent 번들이 {MAX_BUNDLE_BYTES} bytes를 넘어 읽기를 중단했습니다. \
                 rca-agent에서 켠 신호(특히 process_tree)를 줄이세요."
            )));
        }
        Ok(finalize_bundle(&text))
    }

    /// `GET /healthz` — 도달성만 확인하는 논블로킹 프로브(doctor 헬스체크용).
    /// collect와 달리 window를 잡지 않으므로 짧은 timeout으로 충분하다.
    pub async fn health(&self) -> Result<String, ToolError> {
        let url = format!("{}/healthz", self.base);
        let req = self.http.get(&url).timeout(Duration::from_secs(2));
        self.send(req).await
    }

    /// `GET /featuresz` — 신호별 attach 상태 + kernel capability.
    pub async fn features(&self) -> Result<String, ToolError> {
        let url = format!("{}/featuresz", self.base);
        let req = self.http.get(&url).timeout(Duration::from_secs(10));
        self.send(req).await
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<String, ToolError> {
        let (text, _) = self.fetch(req, MAX_RESPONSE_BYTES).await?;
        Ok(finalize(&text))
    }

    /// 요청을 보내 `max_bytes`까지 읽는다. 비-2xx는 상태코드·본문 앞부분과 함께 오류로 올린다.
    async fn fetch(
        &self,
        req: reqwest::RequestBuilder,
        max_bytes: usize,
    ) -> Result<(String, bool), ToolError> {
        let resp = req.send().await.map_err(|e| {
            ToolError::new(format!(
                "rca-agent 요청 실패: {e}. rca-agent가 실행 중인지 확인하세요 \
                 (systemctl status rca-agent)"
            ))
        })?;
        let status = resp.status();
        let (bytes, truncated) = read_capped(resp, max_bytes).await?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !status.is_success() {
            return Err(ToolError::new(format!(
                "rca-agent 오류 {status}: {}",
                truncate(&text, 2000)
            )));
        }
        Ok((text, truncated))
    }
}

/// `/collectz` 번들을 redaction하고 LLM 출력 상한에 맞춘다.
///
/// 바이트 단위로 자르면 JSON이 깨져 `kernel_findings` 같은 파싱 소비자가 조용히 빈 결과를
/// 낸다. 그래서 `observations.top`에서 큰 값부터 표식으로 바꿔 유효한 JSON을 유지한다.
/// findings·delta·start/end는 작고 판정의 정본이라 건드리지 않는다.
/// JSON이 아니면 공용 `finalize`로 물러난다.
pub(crate) fn finalize_bundle(body: &str) -> String {
    let Ok(mut bundle) = serde_json::from_str::<Value>(body) else {
        return finalize(body);
    };
    redact_strings(&mut bundle);
    shrink_top(&mut bundle, MAX_OUTPUT_BYTES);
    // 직렬화한 텍스트에 redaction을 다시 돌리면 숫자가 가려져 JSON이 깨지므로 자르기만 한다.
    truncate(&bundle.to_string(), MAX_OUTPUT_BYTES)
}

/// 문자열 값과 키에만 redaction을 적용한다. 원문 텍스트에 돌리면 `kr_rrn`이 따옴표 없는
/// 13자리 숫자를 가리고 `conn_string`이 닫는 따옴표 너머까지 삼켜 JSON이 깨진다.
fn redact_strings(value: &mut Value) {
    match value {
        Value::String(s) => *s = crate::redaction::redact(s).0,
        Value::Array(items) => items.iter_mut().for_each(redact_strings),
        Value::Object(fields) => {
            *fields = std::mem::take(fields)
                .into_iter()
                .map(|(key, mut v)| {
                    redact_strings(&mut v);
                    (crate::redaction::redact(&key).0, v)
                })
                .collect();
        }
        _ => {}
    }
}

/// 직렬화 길이가 `max_bytes` 이하가 될 때까지 `observations.top`의 가장 큰 값을 표식으로 바꾼다.
/// 객체 항목은 자식 배열·객체를 먼저 바꿔 `available`·`loss_in_window` 같은 스칼라 플래그를 남긴다.
fn shrink_top(bundle: &mut Value, max_bytes: usize) {
    while bundle.to_string().len() > max_bytes {
        let Some(top) = bundle
            .pointer_mut("/observations/top")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        let Some((entry, child)) = largest_omittable(top) else {
            return;
        };
        let target = match child {
            Some(child) => &mut top[&entry][&child],
            None => &mut top[&entry],
        };
        let size = target.to_string().len();
        *target = json!({ OMITTED_KEY: size });
    }
}

/// 생략 후보 중 가장 큰 것의 경로(항목 키, 자식 키). 객체 항목은 자식 배열·객체가 후보이고,
/// 객체가 아닌 배열 항목은 항목 자체가 후보다. 이미 표식인 값은 제외한다.
fn largest_omittable(top: &Map<String, Value>) -> Option<(String, Option<String>)> {
    let omittable = |v: &Value| (v.is_array() || v.is_object()) && v.get(OMITTED_KEY).is_none();
    top.iter()
        .flat_map(|(key, entry)| -> Vec<(String, Option<String>, usize)> {
            match entry.as_object() {
                Some(fields) => fields
                    .iter()
                    .filter(|(_, v)| omittable(v))
                    .map(|(child, v)| (key.clone(), Some(child.clone()), v.to_string().len()))
                    .collect(),
                None if omittable(entry) => vec![(key.clone(), None, entry.to_string().len())],
                None => Vec::new(),
            }
        })
        .max_by_key(|(_, _, size)| *size)
        .map(|(key, child, _)| (key, child))
}

/// `/featuresz` JSON에서 활성 신호 수를 센다(pure). `kernel_capabilities`는 신호가 아니라 제외.
/// 파싱 실패나 예상 밖 구조면 `None` — 호출부(진단·요약)를 죽이지 않는다.
///
/// web 신선도 스트립과 chat `/doctor`가 같은 숫자를 보여야 해서 여기 한 곳에 둔다.
pub(crate) fn count_active_signals(body: &str) -> Option<usize> {
    let v: Value = serde_json::from_str(body).ok()?;
    let obj = v.as_object()?;
    Some(
        obj.iter()
            .filter(|(name, e)| {
                *name != "kernel_capabilities"
                    && e.get("enabled").and_then(Value::as_bool) == Some(true)
            })
            .count(),
    )
}

/// host가 loopback(127.0.0.0/8, ::1) 또는 `localhost`인지 강제한다.
fn ensure_loopback(url: &reqwest::Url) -> Result<(), ToolError> {
    let host = url.host_str().unwrap_or_default();
    let host_ip = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let is_loopback = host_ip.eq_ignore_ascii_case("localhost")
        || host_ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
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
            assert!(
                err.message.contains("loopback"),
                "url={url}: {}",
                err.message
            );
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

    fn bundle(top: Value) -> String {
        json!({
            "observations": {
                "findings": [{"signal": "oom", "metric": "kills", "severity": "warning", "value": 1}],
                "top": top
            }
        })
        .to_string()
    }

    #[test]
    fn oversized_bundle_keeps_kernel_findings() {
        let nodes: Vec<Value> = (0..2000)
            .map(|pid| json!({"pid": pid, "comm": "java", "exe": "/usr/lib/jvm/java-21/bin/java"}))
            .collect();
        let body = bundle(json!({"process_tree": {"available": true, "nodes": nodes}}));
        assert!(body.len() > MAX_OUTPUT_BYTES);

        assert!(crate::agent::diagnose::kernel_findings(&finalize(&body)).is_empty());
        let out = finalize_bundle(&body);
        assert!(out.len() <= MAX_OUTPUT_BYTES);
        assert_eq!(crate::agent::diagnose::kernel_findings(&out).len(), 1);
    }

    #[test]
    fn non_object_top_entry_is_omitted_whole() {
        let events: Vec<Value> = (0..8000).map(|seq| json!({"seq": seq})).collect();
        let out = finalize_bundle(&bundle(json!({"ring": events})));
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(
            v["observations"]["top"]["ring"][OMITTED_KEY]
                .as_u64()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn real_bundle_fixture_round_trips() {
        let body = include_str!("../../../aic-server/tests/fixtures/rca-agent/collectz-end.json");
        let out: Value = serde_json::from_str(&finalize_bundle(body)).unwrap();
        assert!(out.get("observations").is_some());
    }

    #[test]
    fn redaction_keeps_bundle_json_valid() {
        let body = bundle(json!({"process_tree": {
            "nodes": [{"pid": 1, "start_boottime_ns": 1_234_561_234_567u64}],
            "note": "redis://user:pass@cache:6379",
            "after": 1
        }}));
        let out = finalize_bundle(&body);
        assert_eq!(crate::agent::diagnose::kernel_findings(&out).len(), 1);
        let v: Value = serde_json::from_str(&out).unwrap();
        let tree = &v["observations"]["top"]["process_tree"];
        assert_eq!(tree["nodes"][0]["start_boottime_ns"], 1_234_561_234_567u64);
        assert_eq!(tree["note"], "[REDACTED:conn_string]");
        assert_eq!(tree["after"], 1);
    }

    #[test]
    fn small_bundle_is_unchanged() {
        let body = bundle(json!({"oom": {"available": true, "events": [{"seq": 1}]}}));
        let out: Value = serde_json::from_str(&finalize_bundle(&body)).unwrap();
        assert_eq!(out, serde_json::from_str::<Value>(&body).unwrap());
    }
}
