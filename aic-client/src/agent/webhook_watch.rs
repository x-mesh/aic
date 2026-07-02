//! C1: webhook alert의 chat 유입 — aicd webhook_server가 `webhook-events.jsonl`에 append하는 alert를
//! **세션 스코프로 tail**해서 열린 chat 세션에 ambient Note로 흘려보낸다.
//!
//! 경계(SRE-SCOPE-BOUNDARY): 이건 상시 감시 데몬이 아니다. chat 세션이 살아 있는 동안에만 파일을
//! tail하고, 세션이 끝나면 watcher task도 스스로 종료한다(receiver drop). baseline을 **세션 시작 시점의
//! 파일 크기**로 잡아 과거 alert가 시작 화면에 쏟아지지 않게 한다(시작 이후 새 alert만). 새 감시 주체를
//! 만드는 게 아니라, aicd가 이미 "받아 진단"한 결과를 마침 열려 있는 사람 세션에 **보여줄 뿐**이다.
//!
//! 소음 억제는 chat 루프의 `NoiseGate`(D5)가 fingerprint 단위로 담당한다.

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// 파일 폴링 주기. status bar 샘플러(2~5s)와 독립. 너무 촘촘하면 idle에서 낭비, 너무 길면 알림 지연.
const POLL_SECS: u64 = 3;
/// 한 폴링에서 읽는 새 구간 최대 바이트(폭주 방어). 초과분은 다음 폴링으로 밀린다.
const MAX_READ_BYTES: u64 = 256 * 1024;
/// 채팅으로 흘려보낼 실제 alert action만 통과시킨다. 관리성 이벤트(unauthorized/deduped 등)는 제외한다.
const ACTIONABLE: &[&str] = &["diagnosing", "received"];

/// chat으로 유입할 webhook alert 한 건(표시 전용 요약). LLM 컨텍스트에 들어가지 않는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebhookAlert {
    pub action: String,
    pub severity: Option<String>,
    pub alert: Option<String>,
    pub fingerprint: String,
}

impl WebhookAlert {
    /// severity가 critical/crit이면 true — chat에서 BEL을 울릴지 판단(그 외는 조용한 ambient 줄).
    pub fn is_critical(&self) -> bool {
        self.severity
            .as_deref()
            .map(|s| {
                let s = s.to_ascii_lowercase();
                s.contains("crit")
            })
            .unwrap_or(false)
    }

    /// dedup 키. fingerprint가 비면 action+alert로 대체해 서로 다른 알림이 한 키로 뭉치지 않게 한다.
    pub fn dedup_key(&self) -> String {
        if self.fingerprint.is_empty() {
            format!("{}:{}", self.action, self.alert.as_deref().unwrap_or(""))
        } else {
            self.fingerprint.clone()
        }
    }
}

/// webhook-events.jsonl 한 줄(JSON)을 chat 유입용 alert로 파싱한다(pure — 단위 테스트 대상).
/// actionable action(diagnosing/received)만 Some. 그 외 action·파싱 실패·비-객체는 None.
pub(crate) fn parse_webhook_alert_line(line: &str) -> Option<WebhookAlert> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let action = v.get("action").and_then(|a| a.as_str())?.to_string();
    if !ACTIONABLE.contains(&action.as_str()) {
        return None;
    }
    Some(WebhookAlert {
        action,
        severity: v
            .get("severity")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
        alert: v
            .get("alert")
            .and_then(|a| a.as_str())
            .map(|s| s.to_string()),
        fingerprint: v
            .get("fingerprint")
            .and_then(|f| f.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// baseline offset 이후로 늘어난 파일 구간만 읽어 actionable alert들을 반환하고, 새 offset을 갱신한다
/// (pure I/O 헬퍼 — 폴링 task가 반복 호출). 파일 부재는 (빈 목록, offset 유지). truncate/rotate로
/// 파일이 offset보다 작아지면 0으로 리셋해 재동기화한다. `MAX_READ_BYTES`로 한 번에 읽는 양을 제한한다.
fn read_new_alerts(path: &std::path::Path, offset: &mut u64) -> Vec<WebhookAlert> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(meta) = std::fs::metadata(path) else {
        return Vec::new();
    };
    let len = meta.len();
    if len < *offset {
        *offset = 0; // rotate/truncate 감지 → 재동기화
    }
    if len == *offset {
        return Vec::new();
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    if f.seek(SeekFrom::Start(*offset)).is_err() {
        return Vec::new();
    }
    let to_read = (len - *offset).min(MAX_READ_BYTES);
    let mut buf = vec![0u8; to_read as usize];
    if f.read_exact(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    // 마지막 줄이 개행으로 안 끝나면(부분 기록) 그 줄은 남기고 offset을 그 앞까지만 전진시킨다.
    let consumed = text.rfind('\n').map(|i| i as u64 + 1).unwrap_or(0);
    *offset += consumed;
    text[..consumed as usize]
        .lines()
        .filter_map(parse_webhook_alert_line)
        .collect()
}

/// `webhook-events.jsonl`을 세션 스코프로 tail하는 task를 띄운다. baseline = 시작 시점 파일 크기라
/// 과거 alert는 무시하고 시작 이후 새 alert만 채널로 보낸다. 반환된 receiver가 drop되면(세션 종료)
/// task는 다음 폴링에서 스스로 끝난다.
pub(crate) fn spawn_webhook_watcher() -> (mpsc::Receiver<WebhookAlert>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(32);
    let handle = tokio::spawn(async move {
        let path = aic_common::paths::webhook_events_path();
        // baseline: 시작 시점 EOF. 파일이 없으면 0(이후 생성되면 처음부터 읽되, 그 시점 이후 것만).
        let mut offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        loop {
            tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
            if tx.is_closed() {
                break;
            }
            // 파일 read는 blocking — 전용 blocking thread로 옮겨 async worker를 막지 않는다(hung fs 방어).
            let p = path.clone();
            let mut off = offset;
            let alerts =
                tokio::task::spawn_blocking(move || (read_new_alerts(&p, &mut off), off)).await;
            let Ok((alerts, new_off)) = alerts else {
                continue;
            };
            offset = new_off;
            for a in alerts {
                if tx.send(a).await.is_err() {
                    return; // receiver dropped
                }
            }
        }
    });
    (rx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_only_actionable_actions() {
        let received = r#"{"ts":"2026-07-02T00:00:00Z","action":"received","severity":"critical","alert":"redis oom","fingerprint":"fp-a"}"#;
        let a = parse_webhook_alert_line(received).unwrap();
        assert_eq!(a.action, "received");
        assert_eq!(a.severity.as_deref(), Some("critical"));
        assert_eq!(a.fingerprint, "fp-a");
        assert!(a.is_critical());
        // 관리성 이벤트는 제외.
        assert!(parse_webhook_alert_line(r#"{"action":"deduped","fingerprint":"fp-a"}"#).is_none());
        assert!(parse_webhook_alert_line(r#"{"action":"rate_limited"}"#).is_none());
        assert!(parse_webhook_alert_line("not json").is_none());
    }

    #[test]
    fn dedup_key_falls_back_when_fingerprint_empty() {
        let a = WebhookAlert {
            action: "received".into(),
            severity: None,
            alert: Some("disk full".into()),
            fingerprint: String::new(),
        };
        assert_eq!(a.dedup_key(), "received:disk full");
        assert!(!a.is_critical()); // severity 없으면 non-crit
    }

    #[test]
    fn read_new_alerts_reads_only_appended_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhook-events.jsonl");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(
                f,
                r#"{{"action":"received","alert":"old","fingerprint":"fp-old"}}"#
            )
            .unwrap();
        }
        // baseline = 현재 EOF → 기존 줄은 무시.
        let mut offset = std::fs::metadata(&path).unwrap().len();
        assert!(read_new_alerts(&path, &mut offset).is_empty());
        // 새 줄 2개 append(하나는 actionable, 하나는 deduped).
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(
                f,
                r#"{{"action":"diagnosing","alert":"new","fingerprint":"fp-new"}}"#
            )
            .unwrap();
            writeln!(f, r#"{{"action":"deduped","fingerprint":"fp-new"}}"#).unwrap();
        }
        let got = read_new_alerts(&path, &mut offset);
        assert_eq!(got.len(), 1); // deduped는 제외
        assert_eq!(got[0].fingerprint, "fp-new");
        // 다시 읽으면 새 줄 없음.
        assert!(read_new_alerts(&path, &mut offset).is_empty());
    }

    #[test]
    fn read_new_alerts_resyncs_on_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhook-events.jsonl");
        std::fs::write(&path, "long previous content long previous content\n").unwrap();
        let mut offset = std::fs::metadata(&path).unwrap().len();
        // rotate: 더 짧은 내용으로 교체.
        std::fs::write(
            &path,
            r#"{"action":"received","fingerprint":"fp-z"}"#.to_string() + "\n",
        )
        .unwrap();
        let got = read_new_alerts(&path, &mut offset);
        assert_eq!(got.len(), 1); // offset 리셋 후 새 파일 처음부터 읽음
        assert_eq!(got[0].fingerprint, "fp-z");
    }
}
