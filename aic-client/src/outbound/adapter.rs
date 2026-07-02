//! (O2) 전송 어댑터 — `OutboundAdapter` trait + 두 구현. redaction은 O1의 타입(`OutboundPayload`가
//! `Redacted`만 담음)이 이미 보장하므로 어댑터는 redaction을 다시 걱정하지 않는다.
//!
//! Phase 2 방침: 실제로 네트워크 전송이 켜지는 어댑터는 없다. `FileAdapter`(로컬 파일 기록)만 기본
//! 활성이고, `WebhookAdapter`는 코드·테스트로 완성하되 **기본 비활성 + allowlist 미등록 시 전송 거부**다.
//! 임의 외부 URL로 데이터가 나가는 경로는 Phase 2에서 열리지 않는다. confirm gate와 config·CLI 진입점은
//! 후속(O3)이 담당한다.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use super::{DeliveryAudit, OutboundPayload, OutboundPolicy};

/// 전송 결과 요약. 어댑터가 반환하고 호출부(O3)가 [`DeliveryAudit`]로 HMAC audit 로그에 남긴다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub target: String,
    pub bytes: usize,
    /// 사람이 읽는 결과 detail — 파일 경로 또는 `HTTP 200` 등.
    pub detail: String,
}

impl DeliveryReceipt {
    /// 성공 receipt를 감사 레코드로 변환한다(ok=true).
    pub fn to_audit(&self, fingerprint: Option<String>) -> DeliveryAudit {
        DeliveryAudit {
            target: self.target.clone(),
            ok: true,
            fingerprint,
            bytes: self.bytes,
            error: None,
        }
    }
}

/// 정규화 페이로드를 한 목적지로 내보내는 어댑터. redaction은 페이로드 타입이 보장하므로 여기선 전송만
/// 담당한다. dyn 없이 concrete 타입/enum으로 디스패치한다(O3).
#[allow(async_fn_in_trait)] // dyn 미사용 — Send 경계 불명확 경고 무해.
pub trait OutboundAdapter {
    fn name(&self) -> &str;
    async fn deliver(&self, payload: &OutboundPayload) -> Result<DeliveryReceipt>;
}

/// 파일명·경로에 안전한 토큰만 남긴다([A-Za-z0-9_-] 외는 `_`). fingerprint가 redacted 자유 텍스트라
/// path traversal·이상 문자가 섞일 수 있어 방어한다.
fn sanitize_token(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let t = t.trim_matches('_').to_string();
    if t.is_empty() {
        "incident".to_string()
    } else {
        t.chars().take(48).collect()
    }
}

/// (O2) 로컬 디렉터리에 페이로드를 JSON+MD로 기록하는 어댑터 — **기본 활성**. 외부 의존 없이 전체
/// 파이프라인(정규화→redaction→기록)을 CI에서 검증하는 dry-run 겸 검증용이다. 네트워크를 타지 않는다.
pub struct FileAdapter {
    name: String,
    dir: PathBuf,
}

impl FileAdapter {
    pub fn new(name: impl Into<String>, dir: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            dir: dir.into(),
        }
    }
}

impl OutboundAdapter for FileAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn deliver(&self, payload: &OutboundPayload) -> Result<DeliveryReceipt> {
        std::fs::create_dir_all(&self.dir)?;
        let json = serde_json::to_string_pretty(&payload.to_json())?;
        let stamp = payload.created_at.format("%Y%m%d-%H%M%S");
        let fp = payload
            .fingerprint
            .as_deref()
            .map(sanitize_token)
            .unwrap_or_else(|| "incident".to_string());
        let base = format!("{stamp}-{fp}");
        let json_path = self.dir.join(format!("{base}.json"));
        let md_path = self.dir.join(format!("{base}.md"));
        write_new(&json_path, json.as_bytes())?;
        // body_md는 이미 Redacted(평문 마스킹본).
        write_new(&md_path, payload.body_md.as_str().as_bytes())?;
        Ok(DeliveryReceipt {
            target: self.name.clone(),
            bytes: json.len(),
            detail: json_path.display().to_string(),
        })
    }
}

/// 파일을 쓴다(부모 생성은 호출부). 0600 권한은 상위 dir 정책을 따른다 — 여기선 단순 쓰기.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

/// (O2) generic HTTP POST 어댑터 — **기본 비활성 + allowlist 게이트**. 목적지별 포맷 변환(Slack blocks 등)은
/// 하지 않고 범용 envelope(OutboundPayload JSON)를 그대로 POST한다(목적지 전용 어댑터는 O3/Phase 3).
/// deliver는 (1) 비활성이면 즉시 거부, (2) allowlist 미등록이면 전송 시도조차 안 함(deny-by-default),
/// (3) http(s) URL만 허용한 뒤에야 POST한다.
pub struct WebhookAdapter {
    name: String,
    url: String,
    enabled: bool,
    policy: OutboundPolicy,
}

impl WebhookAdapter {
    pub fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        enabled: bool,
        policy: OutboundPolicy,
    ) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            enabled,
            policy,
        }
    }
}

impl OutboundAdapter for WebhookAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn deliver(&self, payload: &OutboundPayload) -> Result<DeliveryReceipt> {
        // (1) 기본 비활성 — Phase 2에서 실제 전송을 켜지 않는다.
        if !self.enabled {
            return Err(anyhow!(
                "webhook 어댑터 '{}' 비활성 — 실제 전송은 활성화 + allowlist 등록 후에만(Phase 2 기본 비활성)",
                self.name
            ));
        }
        // (2) deny-by-default: allowlist 미등록 목적지는 전송 시도조차 안 한다.
        if !self.policy.is_allowed(&self.name) {
            return Err(anyhow!(
                "목적지 '{}' allowlist 미등록 — 전송 거부(deny-by-default)",
                self.name
            ));
        }
        // (3) http(s) URL만 허용(파일/기타 스킴 차단).
        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            return Err(anyhow!("허용되지 않은 URL 스킴: {}", self.url));
        }
        let body = payload.to_json();
        let bytes = body.to_string().len();
        let client = reqwest::Client::new();
        let resp = client.post(&self.url).json(&body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("전송 실패: HTTP {}", status.as_u16()));
        }
        Ok(DeliveryReceipt {
            target: self.name.clone(),
            bytes,
            detail: format!("HTTP {}", status.as_u16()),
        })
    }
}

/// (O2) dry-run 미리보기 — 실제 전송 없이 "이렇게 나갑니다"를 보여준다. 페이로드가 이미 redacted이므로
/// 그대로 pretty JSON으로 렌더한다. O3의 `--dry-run`이 confirm gate 전에 호출한다.
pub fn render_dry_run(payload: &OutboundPayload) -> String {
    serde_json::to_string_pretty(&payload.to_json()).unwrap_or_else(|_| "(직렬화 실패)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutboundPayload;
    use crate::rca::{IncidentMeta, IncidentStatus, Severity};

    fn payload() -> OutboundPayload {
        let meta = IncidentMeta {
            id: "20260702-000000-x".to_string(),
            title: "checkout 5xx from admin@corp.io".to_string(),
            status: IncidentStatus::Open,
            symptom: Some("5xx".to_string()),
            cwd: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            evidence_count: 1,
            severity: Some(Severity::Sev2),
            mitigated_at: None,
            closed_at: None,
        };
        OutboundPayload::from_incident(&meta, "body with admin@corp.io leak", vec!["E1".into()])
    }

    #[tokio::test]
    async fn file_adapter_round_trip_writes_redacted_json_and_md() {
        let dir = tempfile::tempdir().unwrap();
        let adapter = FileAdapter::new("file-local", dir.path());
        let receipt = adapter.deliver(&payload()).await.unwrap();
        assert_eq!(receipt.target, "file-local");
        assert!(receipt.bytes > 0);
        // 기록된 JSON 파일이 실제로 있고 redaction이 적용돼 있다(raw 이메일 없음).
        let written: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(written.len(), 2); // .json + .md
        let json = std::fs::read_to_string(
            dir.path().join(
                written
                    .iter()
                    .find(|p| p.extension().is_some_and(|x| x == "json"))
                    .unwrap(),
            ),
        )
        .unwrap();
        assert!(json.contains("[REDACTED:email]"));
        assert!(!json.contains("admin@corp.io"));
    }

    #[tokio::test]
    async fn webhook_disabled_by_default_refuses() {
        let a = WebhookAdapter::new(
            "slack",
            "https://hooks.example.com/x",
            false,
            OutboundPolicy::new(["slack".to_string()]),
        );
        let err = a.deliver(&payload()).await.unwrap_err().to_string();
        assert!(err.contains("비활성"), "{err}");
    }

    #[tokio::test]
    async fn webhook_enabled_but_not_allowlisted_refuses_before_send() {
        // 활성이지만 allowlist에 없으면 네트워크 시도 없이 거부(deny-by-default).
        let a = WebhookAdapter::new(
            "slack",
            "https://hooks.example.com/x",
            true,
            OutboundPolicy::default(), // 빈 allowlist
        );
        let err = a.deliver(&payload()).await.unwrap_err().to_string();
        assert!(err.contains("allowlist"), "{err}");
    }

    #[tokio::test]
    async fn webhook_rejects_non_http_scheme() {
        let a = WebhookAdapter::new(
            "evil",
            "file:///etc/passwd",
            true,
            OutboundPolicy::new(["evil".to_string()]),
        );
        let err = a.deliver(&payload()).await.unwrap_err().to_string();
        assert!(err.contains("스킴"), "{err}");
    }

    #[test]
    fn dry_run_renders_redacted_without_sending() {
        let out = render_dry_run(&payload());
        assert!(out.contains("[REDACTED:email]"));
        assert!(!out.contains("admin@corp.io"));
    }

    #[test]
    fn sanitize_token_strips_unsafe_chars() {
        assert_eq!(sanitize_token("fp/../etc"), "fp____etc"); // /../ = 4자 → 4 underscore
        assert_eq!(sanitize_token(""), "incident");
        assert_eq!(sanitize_token("ok-name_1"), "ok-name_1");
    }
}
