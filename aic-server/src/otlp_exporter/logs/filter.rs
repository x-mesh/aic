//! min_severity 필터 (RFC-006 t6 — 볼륨 안전장치 1/2, `serve_logs` 앞단에서 가장 먼저 돈다).
//!
//! **기본값이 소스에 따라 다르다.** 외부 소스(journald/container/file)는 `WARN` — RFC-006 §6이
//! 명시적으로 경고한 대로("기본을 INFO로 두면 안 된다 — 켜자마자 사고가 난다"). `aic` self
//! 로그만 `INFO`다 — self는 볼륨이 작고, "에이전트가 왜 안 보내나"를 중앙에서 디버깅하려면
//! INFO 레벨 가시성이 필요하다.
//!
//! `AicdLogsConfig::min_severity`(aic-common) 자체의 serde 기본값은 소스 구분이 없는 단일
//! `"INFO"`다. 여기서는 그 값이 **손대지 않은 기본값과 동일할 때만** 소스별 안전 기본을
//! 얹는다 — 사용자가 전역값을 명시적으로 다른 값으로 바꾸면(예: `"ERROR"`) 소스와 무관하게
//! 그 값이 이긴다. 서비스별 `[aicd.logs.services.<name>]` override는 항상 최우선이다.

use aic_common::{AicdLogsConfig, LogLine};

/// `aic-common::default_log_min_severity()`와 동일한 리터럴(그 함수는 private이라 재노출되지
/// 않는다) — 전역 `min_severity`가 이 값 그대로면 "사용자가 안 건드린 기본값"으로 취급한다.
const GLOBAL_DEFAULT_SENTINEL: &str = "INFO";

/// severity 순서: DEBUG < INFO < WARN < ERROR. 알 수 없는 값은 INFO로 취급한다(너무 낙관적으로
/// 버리지도, 너무 보수적으로 다 통과시키지도 않는 중간값).
fn severity_rank(s: &str) -> u8 {
    match s {
        "DEBUG" => 0,
        "WARN" => 2,
        "ERROR" => 3,
        _ => 1,
    }
}

/// 소스별 안전 기본값. `line.source == "aic"`만 INFO, 나머지 전부 WARN.
fn source_default_min_severity(source: &str) -> &'static str {
    if source == "aic" {
        "INFO"
    } else {
        "WARN"
    }
}

/// 이 라인에 적용할 유효 min_severity를 계산한다. 서비스 override > 명시적 전역값 > 소스별
/// 안전 기본 순.
fn effective_min_severity<'a>(line: &LogLine, cfg: &'a AicdLogsConfig) -> &'a str {
    if let Some(over) = cfg
        .services
        .get(&line.service)
        .and_then(|o| o.min_severity.as_deref())
    {
        return over;
    }
    if cfg.min_severity != GLOBAL_DEFAULT_SENTINEL {
        return cfg.min_severity.as_str();
    }
    source_default_min_severity(&line.source)
}

/// `line.severity`가 유효 min_severity 이상이면 `true`(통과), 미만이면 `false`(드롭 대상 —
/// 호출부가 `DropCounters::by_severity`를 올린다).
pub fn passes_severity(line: &LogLine, cfg: &AicdLogsConfig) -> bool {
    severity_rank(&line.severity) >= severity_rank(effective_min_severity(line, cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::AicdLogServiceOverride;
    use std::collections::BTreeMap;

    fn line(source: &str, service: &str, severity: &str) -> LogLine {
        LogLine {
            source: source.to_string(),
            service: service.to_string(),
            severity: severity.to_string(),
            message: "m".to_string(),
            attrs: BTreeMap::new(),
            ts: chrono::Utc::now(),
            record_id: "r".to_string(),
        }
    }

    #[test]
    fn severity_order_is_debug_info_warn_error() {
        assert!(severity_rank("DEBUG") < severity_rank("INFO"));
        assert!(severity_rank("INFO") < severity_rank("WARN"));
        assert!(severity_rank("WARN") < severity_rank("ERROR"));
    }

    #[test]
    fn unknown_severity_is_treated_as_info() {
        assert_eq!(severity_rank("WEIRD"), severity_rank("INFO"));
    }

    #[test]
    fn min_severity_default_warn_for_external_info_for_self() {
        let cfg = AicdLogsConfig::default();

        // 외부 소스(journald/container/file 대표로 journald) — 기본 WARN.
        assert!(!passes_severity(&line("journald", "nginx", "INFO"), &cfg));
        assert!(passes_severity(&line("journald", "nginx", "WARN"), &cfg));
        assert!(passes_severity(&line("journald", "nginx", "ERROR"), &cfg));
        assert!(!passes_severity(&line("container", "web", "INFO"), &cfg));
        assert!(!passes_severity(&line("file", "app.log", "DEBUG"), &cfg));

        // aic self — 기본 INFO.
        assert!(passes_severity(&line("aic", "aicd", "INFO"), &cfg));
        assert!(!passes_severity(&line("aic", "aicd", "DEBUG"), &cfg));
    }

    #[test]
    fn min_severity_service_override_wins() {
        let mut cfg = AicdLogsConfig::default();
        cfg.services.insert(
            "nginx-error".to_string(),
            AicdLogServiceOverride {
                min_severity: Some("INFO".to_string()),
                ..Default::default()
            },
        );

        // 이 서비스만 INFO까지 통과 — 전역(외부 기본 WARN)을 이긴다.
        assert!(passes_severity(
            &line("container", "nginx-error", "INFO"),
            &cfg
        ));
        // override가 없는 다른 서비스는 여전히 WARN 기본.
        assert!(!passes_severity(&line("container", "other", "INFO"), &cfg));
    }

    #[test]
    fn explicit_global_min_severity_wins_over_source_default() {
        let cfg = AicdLogsConfig {
            min_severity: "ERROR".to_string(),
            ..Default::default()
        };

        // 전역을 명시적으로 ERROR로 바꾸면 소스 기본(WARN/INFO)을 무시하고 ERROR가 적용된다.
        assert!(!passes_severity(&line("journald", "nginx", "WARN"), &cfg));
        assert!(passes_severity(&line("journald", "nginx", "ERROR"), &cfg));
        assert!(!passes_severity(&line("aic", "aicd", "WARN"), &cfg));
    }
}
