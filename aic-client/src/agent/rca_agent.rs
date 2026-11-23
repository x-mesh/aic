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
/// 블랙박스 고정본 읽기 상한. rca-agent 설정 상한이 16 MiB이고, 줄일 대상이 바닥나면 그보다
/// 커질 수 있다(형식 문서 §8).
const MAX_BLACKBOX_BYTES: usize = 32 * 1024 * 1024;
/// 준비된 고정본은 완성된 JSON을 그대로 내주므로 짧게 둔다. 큰 고정본 전송 시간만 감안한다.
const BLACKBOX_TIMEOUT_SECS: u64 = 30;
/// 블랙박스 id 길이(16자리 소문자 hex).
const BLACKBOX_ID_LEN: usize = 16;

fn is_blackbox_id(id: &str) -> bool {
    id.len() == BLACKBOX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

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
                     N bytes가 생략된 것이지 데이터가 없다는 뜻이 아니다. process_tree에 \
                     aic_summary_of_bytes가 있으면 원문 대신 요약이다: exits_in_window(창 안 \
                     종료, kill_sender 원문 포함), reconcile_exits(시각·원인 미상, 개수와 age \
                     범위만), top_nodes(지표별 상위 노드와 조상 사슬, 지표 키가 없으면 측정 안 \
                     함), d_state. 각 목록의 total과 kept가 다르면 일부만 실린 것이다. \
                     container는 cgroup_path에서 aic가 찾은 런타임과 짧은 id(12자)이며, 없으면 \
                     컨테이너 밖이거나 런타임을 알아보지 못한 것이다. \
                     kill_sender.pid는 시그널을 생성한 실행 문맥이지 죽이기로 결정한 주체가 아니다. \
                     process_tree.aic_findings는 aic가 트리 원문에서 만든 판정이다(loss, \
                     crash_loop, signal_exit, d_state). SIGKILL 종료는 OOM이라고 단정하지 않으므로 \
                     oom 신호와 맞춰 본다. process_tree.blackbox_refs에 state가 ready인 id가 있으면 \
                     rca_agent_blackbox로 장애 앞뒤 구간의 고정본을 볼 수 있다.",
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
            ToolSpec {
                name: "rca_agent_blackbox",
                description:
                    "rca-agent 프로세스 트리 블랙박스 고정본(process_tree_blackbox.v1)을 id로 \
                     조회해 요약을 반환한다. id는 rca_agent_collect 결과의 \
                     process_tree.blackbox_refs[].id(16자리 hex)다. read-only, 즉시 반환. 요약: \
                     triggers(crash_loop·fatal_signal·oom_kill·fork_storm·d_state·pressure·manual, \
                     cause 포함), range(트리거 전후 구간), loss(0이 아니면 그 구간의 프레임·종료가 \
                     빠짐), frames(1초 프레임의 live 노드 수 범위, procs_blocked·load1·PSI 최댓값과 \
                     시각, 카운터 합, 종료 그룹 합), exits(최근 종료), exited_summary, \
                     snapshots.at_trigger·at_end(트리거 시점과 끝 시점의 process_tree 요약). \
                     아직 캡처 중이면 오류로 알린다.",
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "blackbox_refs[].id (16자리 소문자 hex)"
                        }
                    },
                    "required": ["id"]
                }),
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
            "rca_agent_blackbox" => {
                let id = args.get("id").and_then(Value::as_str).unwrap_or_default();
                self.blackbox(id).await
            }
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

    /// `GET /blackboxz/<id>` — 블랙박스 고정본을 받아 요약한다.
    ///
    /// id는 경로에 그대로 들어가므로 형식(16자리 소문자 hex)을 먼저 검사한다. 캡처 중이면 409,
    /// 블랙박스가 꺼져 있거나 id가 없으면 404가 온다(형식 문서 §8).
    pub async fn blackbox(&self, id: &str) -> Result<String, ToolError> {
        if !is_blackbox_id(id) {
            return Err(ToolError::new(format!(
                "블랙박스 id 형식이 아닙니다: '{}'. rca_agent_collect 결과의 \
                 process_tree.blackbox_refs[].id(16자리 소문자 hex)를 쓰세요.",
                truncate(id, 64)
            )));
        }
        let url = format!("{}/blackboxz/{id}", self.base);
        let req = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(BLACKBOX_TIMEOUT_SECS));
        let (status, text, truncated) = self.fetch_any_status(req, MAX_BLACKBOX_BYTES).await?;
        match status {
            reqwest::StatusCode::CONFLICT => {
                return Err(ToolError::new(format!(
                "블랙박스 {id}는 아직 캡처 중입니다(state capturing). 트리거 뒤 구간(기본 30초)이 \
                     끝난 뒤 다시 조회하세요."
            )))
            }
            reqwest::StatusCode::NOT_FOUND => {
                return Err(ToolError::new(format!(
                    "블랙박스 {id}를 찾지 못했습니다. 블랙박스가 꺼져 있거나(signals.process_tree.\
                     blackbox) 고정본이 보관 한도로 지워졌을 수 있습니다. ({})",
                    truncate(&text, 500)
                )))
            }
            s if !s.is_success() => return Err(status_error(s, &text)),
            _ => {}
        }
        if truncated {
            return Err(ToolError::new(format!(
                "블랙박스 고정본이 {MAX_BLACKBOX_BYTES} bytes를 넘어 읽기를 중단했습니다."
            )));
        }
        let Ok(mut capture) = serde_json::from_str::<Value>(&text) else {
            return Ok(finalize(&text));
        };
        redact_strings(&mut capture);
        // 요약은 상한 안의 유효한 JSON을 보장하므로 문자열을 자르지 않는다(자르면 JSON이 깨진다).
        match super::rca_blackbox::summarize(&capture, MAX_OUTPUT_BYTES) {
            Some(summary) => Ok(summary.to_string()),
            None => Ok(finalize(&text)),
        }
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
        let (status, text, truncated) = self.fetch_any_status(req, max_bytes).await?;
        if !status.is_success() {
            return Err(status_error(status, &text));
        }
        Ok((text, truncated))
    }

    /// 요청을 보내 상태 코드와 함께 `max_bytes`까지 읽는다. 상태별로 안내를 바꾸는 호출부용이다.
    async fn fetch_any_status(
        &self,
        req: reqwest::RequestBuilder,
        max_bytes: usize,
    ) -> Result<(reqwest::StatusCode, String, bool), ToolError> {
        let resp = req.send().await.map_err(|e| {
            ToolError::new(format!(
                "rca-agent 요청 실패: {e}. rca-agent가 실행 중인지 확인하세요 \
                 (systemctl status rca-agent)"
            ))
        })?;
        let status = resp.status();
        let (bytes, truncated) = read_capped(resp, max_bytes).await?;
        Ok((
            status,
            String::from_utf8_lossy(&bytes).into_owned(),
            truncated,
        ))
    }
}

fn status_error(status: reqwest::StatusCode, body: &str) -> ToolError {
    ToolError::new(format!("rca-agent 오류 {status}: {}", truncate(body, 2000)))
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
    // 판정과 요약은 redaction을 거친 값으로만 만든다(exe·argv_path·cgroup_path가 원문으로 나가지 않게).
    // 판정은 트리 원문이 필요하므로 요약보다 먼저 만든다.
    attach_process_tree_findings(&mut bundle);
    if bundle.to_string().len() > MAX_OUTPUT_BYTES {
        summarize_process_tree(&mut bundle);
    }
    shrink_top(&mut bundle, MAX_OUTPUT_BYTES);
    // 직렬화한 텍스트에 redaction을 다시 돌리면 숫자가 가려져 JSON이 깨지므로 자르기만 한다.
    truncate(&bundle.to_string(), MAX_OUTPUT_BYTES)
}

/// 트리 원문에서 만든 판정을 `process_tree.aic_findings`에 싣는다. 판정이 없으면 키를 넣지 않는다.
fn attach_process_tree_findings(bundle: &mut Value) {
    const TREE: &str = "/observations/top/process_tree";
    let findings = match bundle.pointer(TREE) {
        Some(tree) => super::rca_process_tree::findings(tree),
        None => return,
    };
    if findings.is_empty() {
        return;
    }
    if let Some(tree) = bundle.pointer_mut(TREE).and_then(Value::as_object_mut) {
        tree.insert(
            super::rca_process_tree::FINDINGS_KEY.into(),
            Value::Array(findings),
        );
    }
}

/// 출력 상한을 넘는 번들에서 `observations.top.process_tree` 원문을 판정용 요약으로 바꾼다.
/// 원문은 노드 1024개까지 와서 가장 큰 항목이 되고, 그대로 두면 `shrink_top`이 통째로
/// 생략 표식으로 바꿔 트리를 하나도 볼 수 없게 된다.
fn summarize_process_tree(bundle: &mut Value) {
    let Some(tree) = bundle.pointer_mut("/observations/top/process_tree") else {
        return;
    };
    if let Some(summary) = super::rca_process_tree::summarize(tree) {
        *tree = summary;
    }
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
    fn specs_expose_readonly_tools() {
        let client = RcaAgentClient::new(&cfg(true, "http://127.0.0.1:9090"))
            .unwrap()
            .unwrap();
        let names: Vec<&str> = client.specs().iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec![
                "rca_agent_collect",
                "rca_agent_features",
                "rca_agent_blackbox"
            ]
        );
    }

    /// id는 URL 경로에 들어가므로 형식이 아닌 값은 요청 전에 거부한다.
    #[test]
    fn blackbox_id_must_be_16_lowercase_hex() {
        assert!(is_blackbox_id("0123456789abcdef"));
        for bad in [
            "",
            "0123456789ABCDEF",
            "0123456789abcde",
            "../../healthz00",
            "0123456789abcdefa",
        ] {
            assert!(!is_blackbox_id(bad), "{bad}");
        }
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

    /// #74: 노드 1024개·종료 이력 256개(렌더 상한)인 트리는 생략 표식이 아니라 요약으로 남는다.
    #[test]
    fn full_process_tree_is_summarized_within_output_limit() {
        let nodes: Vec<Value> = (1..=1024u64)
            .map(|pid| {
                json!({
                    "pid": pid, "ppid": pid - 1, "fork_ppid": pid - 1,
                    "start_boottime_ns": 1_000_000_000u64 * pid, "start_precision": "ns",
                    "start_age_seconds": 100.0, "comm": "worker",
                    "exe": "/usr/lib/jvm/java-21/bin/java", "exe_source": "proc_exe",
                    "cgroup_id": 9123,
                    "cgroup_path": "/kubepods.slice/kubepods-burstable.slice/cri-containerd-3f9c.scope",
                    "state": "live", "source": "event", "proc_state": "S", "rss_bytes": pid * 4096,
                    "in_window": {"forked": false, "execed": false, "exited": false},
                    "window": {"cpu_ns": pid * 1000, "runq_wait_us": pid, "block_io_bytes": 0}
                })
            })
            .collect();
        let exited: Vec<Value> = (0..256u64)
            .map(|i| {
                json!({
                    "seq": i, "pid": 5000 + i, "ppid": 1, "fork_ppid": 1,
                    "start_boottime_ns": 7_000_000_000u64 + i, "comm": "sh", "exe": "/bin/sh",
                    "cgroup_path": "/system.slice/cron.service", "in_window": true,
                    "closed_by": "exit_event", "exit_age_seconds": i as f64, "lifetime_ms": 3,
                    "exit_status": 1, "cpu_total_ns": 0, "total": {"runq_wait_us": 1}
                })
            })
            .collect();
        let body = bundle(json!({"process_tree": {
            "available": true, "schema": "process_tree.v1", "loss_in_window": true,
            "loss_keys": ["exited_overwritten"], "nodes_truncated": true,
            "nodes": nodes, "exited": exited
        }}));
        assert!(body.len() > MAX_OUTPUT_BYTES);

        let out = finalize_bundle(&body);
        assert!(out.len() <= MAX_OUTPUT_BYTES, "{}", out.len());
        // 에이전트 finding(oom) 1건에, 원문 트리에서 만든 손실·크래시 루프 판정이 요약을 거쳐 남는다.
        let messages: Vec<String> = crate::agent::diagnose::kernel_findings(&out)
            .into_iter()
            .map(|f| f.message)
            .collect();
        assert_eq!(messages.len(), 3, "{messages:?}");
        assert!(messages[0].starts_with("kernel/oom"));
        assert!(messages[1].starts_with("kernel/process_tree.loss"));
        assert!(messages[2].starts_with("kernel/process_tree.crash_loop"));
        assert!(messages[2].contains("256번"), "{}", messages[2]);
        let v: Value = serde_json::from_str(&out).unwrap();
        let tree = &v["observations"]["top"]["process_tree"];
        assert!(tree.get(OMITTED_KEY).is_none(), "요약이 생략되면 안 된다");
        assert!(
            tree[crate::agent::rca_process_tree::SUMMARY_KEY]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(tree["loss_in_window"], true);
        assert_eq!(tree["exits_in_window"]["total"], 256);
        assert_eq!(tree["top_nodes"]["cpu_ns"]["top"][0]["pid"], 1024);
    }

    /// 컨테이너 id(64자리 hex)는 redaction을 거친 뒤에도 요약에 남아야 한다.
    #[test]
    fn container_id_survives_redaction_into_summary() {
        let hex = "3f9c0a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789ab";
        let path = format!("/kubepods.slice/kubepods-burstable.slice/cri-containerd-{hex}.scope");
        let nodes: Vec<Value> = (1..=1024u64)
            .map(|pid| {
                json!({"pid": pid, "ppid": 0, "comm": "app", "cgroup_path": path,
                       "exe": "/usr/lib/jvm/java-21/bin/java", "window": {"cpu_ns": pid}})
            })
            .collect();
        let body = bundle(json!({"process_tree": {"nodes": nodes}}));
        assert!(body.len() > MAX_OUTPUT_BYTES, "요약 경로를 타야 한다");
        let v: Value = serde_json::from_str(&finalize_bundle(&body)).unwrap();
        let top = &v["observations"]["top"]["process_tree"]["top_nodes"]["cpu_ns"]["top"][0];
        assert_eq!(
            top["container"],
            json!({"runtime": "containerd", "id": &hex[..12]})
        );
    }

    /// 요약은 redaction을 거친 값으로 만든다.
    #[test]
    fn summary_is_built_from_redacted_values() {
        let nodes: Vec<Value> = (1..=1024u64)
            .map(|pid| {
                json!({"pid": pid, "ppid": 0, "comm": "app",
                       "exe": "/usr/lib/jvm/java-21/bin/java", "window": {"cpu_ns": pid}})
            })
            .collect();
        let exited = vec![json!({
            "pid": 9, "comm": "client", "in_window": true, "closed_by": "exit_event",
            "argv_path": "redis://user:pass@cache:6379", "exit_status": 1
        })];
        let body = bundle(json!({"process_tree": {"nodes": nodes, "exited": exited}}));
        assert!(body.len() > MAX_OUTPUT_BYTES, "요약 경로를 타야 한다");
        let out = finalize_bundle(&body);
        assert!(!out.contains("user:pass"), "원문 비밀값이 요약에 남았다");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["observations"]["top"]["process_tree"]["exits_in_window"]["records"][0]["argv_path"],
            "[REDACTED:conn_string]"
        );
    }

    /// 상한 안의 번들은 process_tree 원문을 그대로 둔다.
    #[test]
    fn small_process_tree_is_not_summarized() {
        let body = bundle(json!({"process_tree": {"nodes": [{"pid": 1, "comm": "systemd"}]}}));
        let v: Value = serde_json::from_str(&finalize_bundle(&body)).unwrap();
        assert_eq!(
            v["observations"]["top"]["process_tree"]["nodes"][0]["pid"],
            1
        );
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
