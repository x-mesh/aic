//! aic RCA ↔ sre-agent incident-memory 브리지 (R7 핸드오프).
//!
//! aic는 on-demand 대화형 RCA(pull) 도구이고, 상시 감시·기억(push)은 인접한 sre-agent의 영역이다.
//! 이 모듈은 그 경계를 지키며 둘을 잇는 **best-effort** 다리다:
//! - [`match_incidents`]: 현재 incident와 유사한 과거 incident를 sre-agent 기억에서 찾는다(읽기).
//! - [`record_incident`]: 닫은 incident를 sre-agent 기억에 한 번 기록한다(핸드오프, opt-in).
//!
//! sre-agent MCP가 `[mcp]`에 구성돼 있지 않거나 해당 tool이 없으면 조용히 `None` — RCA 핵심 흐름을
//! 절대 깨지 않는다. tool은 사용자가 붙인 서버명과 무관하게 bare-name suffix(`__match_incidents`)로 찾는다.

use aic_common::McpConfig;
use serde_json::{json, Value};

use crate::agent::mcp::McpClient;
use crate::rca::IncidentMeta;

/// aic RCA incident → sre-agent incident-memory 키 `(sensor, event, severity)`.
/// sensor는 출처를 나타내는 상수 `aic-rca`, event는 증상(없으면 제목), severity는 라벨(없으면 `unknown`).
pub fn sre_keys(meta: &IncidentMeta) -> (String, String, String) {
    let sensor = "aic-rca".to_string();
    let event = meta.symptom.clone().unwrap_or_else(|| meta.title.clone());
    let severity = meta
        .severity
        .map(|s| s.as_label().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    (sensor, event, severity)
}

/// sre-agent MCP tool을 bare-name suffix(`__match_incidents` 등)로 찾아 호출한다(서버명 무관).
/// MCP 미구성/해당 tool 없음/호출 실패면 `None` — 호출부는 이를 "건너뜀"으로 처리한다.
async fn sre_call(mcp: &McpConfig, tool_suffix: &str, args: Value) -> Option<String> {
    let mut client = McpClient::new(mcp)?;
    client.connect().await;
    let full = client
        .specs()
        .into_iter()
        .map(|s| s.name)
        .find(|n| n.ends_with(tool_suffix))?;
    match client.call(full, &args).await {
        Ok(text) => Some(text),
        Err(e) => {
            eprintln!("sre-agent {tool_suffix} 호출 실패: {}", e.message);
            None
        }
    }
}

/// 현재 incident와 유사한 과거 incident를 sre-agent 기억에서 찾는다(읽기 전용 pull).
pub async fn match_incidents(mcp: &McpConfig, meta: &IncidentMeta, limit: u32) -> Option<String> {
    let (sensor, event, severity) = sre_keys(meta);
    let args = json!({ "sensor": sensor, "event": event, "severity": severity, "limit": limit });
    sre_call(mcp, "__match_incidents", args).await
}

/// 닫은 incident를 sre-agent 기억에 기록한다(핸드오프). 성공 시 `Some(응답 텍스트)`.
pub async fn record_incident(mcp: &McpConfig, meta: &IncidentMeta) -> Option<String> {
    let (sensor, event, severity) = sre_keys(meta);
    let args = json!({
        "sensor": sensor,
        "event": event,
        "severity": severity,
        "trigger_data": { "incident": meta.id, "evidence_count": meta.evidence_count },
    });
    sre_call(mcp, "__record_incident", args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rca::{IncidentStatus, Severity};
    use chrono::Utc;

    fn meta(symptom: Option<&str>, severity: Option<Severity>) -> IncidentMeta {
        IncidentMeta {
            id: "20260630-000000-test".to_string(),
            title: "checkout 5xx spike".to_string(),
            status: IncidentStatus::Open,
            symptom: symptom.map(str::to_string),
            cwd: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            evidence_count: 3,
            severity,
            mitigated_at: None,
            closed_at: None,
        }
    }

    #[test]
    fn keys_prefer_symptom_and_severity_label() {
        let (sensor, event, severity) =
            sre_keys(&meta(Some("5xx from checkout"), Some(Severity::Sev2)));
        assert_eq!(sensor, "aic-rca");
        assert_eq!(event, "5xx from checkout");
        assert_eq!(severity, Severity::Sev2.as_label());
    }

    #[test]
    fn keys_fall_back_to_title_and_unknown() {
        let (_, event, severity) = sre_keys(&meta(None, None));
        assert_eq!(event, "checkout 5xx spike"); // symptom 없으면 title
        assert_eq!(severity, "unknown"); // severity 없으면 unknown
    }
}
