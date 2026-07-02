//! (O1) 외부로 내보낼 데이터의 **정규화 스키마 + 안전장치 타입**. 실제 전송 어댑터(O2)와 config·CLi
//! 진입점(O3)은 후속이며, 이 모듈은 그 토대다 — 목적지가 늘어도 변환 코드가 곱으로 늘지 않도록 페이로드를
//! 한 형태로 고정하고, 전송 전에 반드시 지켜야 하는 두 안전장치(redaction·deny-by-default 정책)를
//! **타입으로** 표현한다.
//!
//! 경계(SRE-SCOPE-BOUNDARY 로드맵 4): 외부 전송은 redaction + confirm gate + HMAC audit 3종 + allowlist
//! deny-by-default를 거친다. 이 중 redaction과 정책·audit 스키마를 여기서 고정하고, confirm gate와 실제
//! 네트워크 전송은 O2 어댑터가 맡는다. Phase 2에서 실제로 네트워크 전송이 켜지는 어댑터는 없다.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::rca::IncidentMeta;

pub mod adapter;

/// redaction을 **타입으로 강제**하는 마커. `Redacted`는 오직 [`Redacted::new`]로만 만들어지고, 그 생성자가
/// `redaction::redact`를 통과시킨다. 따라서 `OutboundPayload`의 자유 텍스트 필드에 raw(미-redacted) 문자열이
/// 들어가는 경로가 타입 시스템 상 존재하지 않는다 — redaction 우회 전송이 컴파일 단계에서 불가능하다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)] // 직렬화는 감싼 문자열 그대로(`{"0": ...}` 방지).
pub struct Redacted(String);

impl Redacted {
    /// raw 문자열을 redaction 통과시켜 감싼다 — 유일한 생성 경로.
    pub fn new(raw: &str) -> Self {
        Self(crate::redaction::redact(raw).0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 페이로드의 출처(host/session). host는 식별 가능성이 있어 `Redacted`로 감싼다.
#[derive(Debug, Clone, Serialize)]
pub struct PayloadSource {
    pub host: Redacted,
    pub session: Option<String>,
}

/// 밖으로 보낼 수 있는 것들(incident report·bundle·finding 요약)을 통일한 정규화 페이로드.
/// 모든 자유 텍스트는 `Redacted` — 생성 시점에 redaction이 강제된다. severity/fingerprint/evidence_refs는
/// 비민감 메타(라벨·id)라 평문. 어댑터(O2)는 이 한 구조체만 받으면 되므로 목적지별 변환이 얇아진다.
#[derive(Debug, Clone, Serialize)]
pub struct OutboundPayload {
    pub title: Redacted,
    pub severity: Option<String>,
    pub fingerprint: Option<String>,
    pub body_md: Redacted,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub source: PayloadSource,
}

impl OutboundPayload {
    /// incident meta + 렌더된 report markdown으로 페이로드를 만든다. title/body/host는 여기서 redaction
    /// 통과(Redacted). `evidence_refs`는 호출부가 넘기는 evidence id 목록(비민감).
    pub fn from_incident(meta: &IncidentMeta, report_md: &str, evidence_refs: Vec<String>) -> Self {
        OutboundPayload {
            title: Redacted::new(&meta.title),
            severity: meta.severity.map(|s| s.as_label().to_string()),
            // incident 자체엔 fingerprint가 없다(webhook alert에만 있음) — 없으면 None.
            fingerprint: None,
            body_md: Redacted::new(report_md),
            evidence_refs,
            created_at: meta.created_at,
            source: PayloadSource {
                host: Redacted::new(&current_host()),
                session: None,
            },
        }
    }

    /// 전송/미리보기용 JSON 직렬화(Redacted는 transparent라 평문 문자열로 나온다).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// (O1) 외부 전송 정책 — **deny-by-default**. allowlist에 이름이 등록된 목적지에만 전송을 허용한다.
/// 빈 allowlist면 전부 거부한다(임의 URL·미등록 목적지로 데이터가 나가는 경로를 원천 차단). O2의
/// `WebhookAdapter`가 전송 직전 이 게이트를 통과해야 한다.
#[derive(Debug, Clone, Default)]
pub struct OutboundPolicy {
    allowlist: BTreeSet<String>,
}

impl OutboundPolicy {
    pub fn new(allow: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowlist: allow.into_iter().collect(),
        }
    }

    /// 목적지 이름이 allowlist에 있으면 true. 미등록·빈 allowlist는 false(deny-by-default).
    pub fn is_allowed(&self, target: &str) -> bool {
        self.allowlist.contains(target)
    }
}

/// (O1) 전송 감사 레코드 스키마 — O2 어댑터가 전송 성공/실패를 이 형태로 HMAC audit 로그에 남긴다.
/// 여기서 형태를 고정해 어댑터 구현이 정책·감사보다 먼저 가지 않게 한다. 페이로드 본문은 담지 않고(이미
/// 전송됨) 메타만 남긴다.
#[derive(Debug, Clone, Serialize)]
pub struct DeliveryAudit {
    pub target: String,
    pub ok: bool,
    pub fingerprint: Option<String>,
    pub bytes: usize,
    pub error: Option<String>,
}

/// 현재 호스트명(없으면 "unknown"). 출처 표기용.
fn current_host() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rca::{IncidentStatus, Severity};

    fn meta() -> IncidentMeta {
        IncidentMeta {
            id: "20260702-000000-x".to_string(),
            title: "checkout 5xx from admin@corp.io".to_string(),
            status: IncidentStatus::Open,
            symptom: Some("5xx".to_string()),
            cwd: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            evidence_count: 2,
            severity: Some(Severity::Sev2),
            mitigated_at: None,
            closed_at: None,
        }
    }

    #[test]
    fn redacted_masks_on_construction() {
        let r = Redacted::new("mail to admin@corp.io now");
        assert!(r.as_str().contains("[REDACTED:email]"));
        assert!(!r.as_str().contains("admin@corp.io"));
    }

    #[test]
    fn from_incident_redacts_title_and_body_and_carries_meta() {
        let p = OutboundPayload::from_incident(
            &meta(),
            "root cause: leaked key AKIA... contact admin@corp.io",
            vec!["E1".into(), "E2".into()],
        );
        // 자유 텍스트는 redaction 통과(email이 마스킹됨).
        assert!(p.title.as_str().contains("[REDACTED:email]"));
        assert!(p.body_md.as_str().contains("[REDACTED:email]"));
        // 비민감 메타는 그대로.
        assert_eq!(p.severity.as_deref(), Some("SEV2"));
        assert_eq!(p.evidence_refs, vec!["E1", "E2"]);
        // JSON 직렬화: Redacted는 평문 문자열(transparent)로 나온다.
        let v = p.to_json();
        assert!(v["title"].is_string());
        assert!(v["title"].as_str().unwrap().contains("[REDACTED:email]"));
    }

    #[test]
    fn policy_is_deny_by_default() {
        let empty = OutboundPolicy::default();
        assert!(!empty.is_allowed("slack")); // 빈 allowlist면 전부 거부
        let p = OutboundPolicy::new(["slack".to_string(), "file-local".to_string()]);
        assert!(p.is_allowed("slack"));
        assert!(p.is_allowed("file-local"));
        assert!(!p.is_allowed("evil.example.com")); // 미등록 목적지 거부
    }
}
