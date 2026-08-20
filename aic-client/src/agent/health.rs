//! Deterministic, model-free machine health verdict for `aic chat /health`.
//!
//! The report is serializable so the chat UI and a future rca-web handoff can consume the same
//! contract. Missing observations stay `unknown`; absence of a finding is never enough to claim a
//! probe succeeded.

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::diagnose::Finding;
use super::sys_sampler::{HealthResourceState, Severity, SysMetrics};

pub(crate) const HEALTH_PROBE_IDS: &[&str] = &[
    "disk",
    "inodes",
    "fd",
    "proc_states",
    "failed_units",
    "dmesg_oom",
];
pub(crate) const HEALTH_PROBE_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HealthState {
    Healthy,
    Unknown,
    Degraded,
    Critical,
}

impl HealthState {
    fn from_severity(value: Severity) -> Self {
        match value {
            Severity::Normal => Self::Healthy,
            Severity::Warn => Self::Degraded,
            Severity::Crit => Self::Critical,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Unknown => "UNKNOWN",
            Self::Degraded => "DEGRADED",
            Self::Critical => "CRITICAL",
        }
    }

    fn glyph(self) -> &'static str {
        match self {
            Self::Healthy => "🟢",
            Self::Unknown => "⚪",
            Self::Degraded => "🟡",
            Self::Critical => "🔴",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvidenceSource {
    Metric,
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Freshness {
    Fresh,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EvidenceRef {
    pub id: String,
    pub source: EvidenceSource,
    pub source_id: String,
    pub observed_at: DateTime<Utc>,
    pub freshness: Freshness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Coverage {
    pub axis: String,
    pub state: HealthState,
    pub detail: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HealthFinding {
    pub id: String,
    pub state: HealthState,
    pub message: String,
    pub evidence_refs: Vec<String>,
    pub suggested_followup: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HealthReport {
    pub schema_version: u32,
    pub observed_at: DateTime<Utc>,
    pub verdict: HealthState,
    pub coverage_complete: bool,
    pub checked_axes: usize,
    pub total_axes: usize,
    pub coverage: Vec<Coverage>,
    pub findings: Vec<HealthFinding>,
    pub evidence: Vec<EvidenceRef>,
}

const PROBE_AXES: &[(&str, &str)] = &[
    ("disk", "filesystems"),
    ("inodes", "inodes"),
    ("fd", "file_descriptors"),
    ("proc_states", "processes"),
    ("failed_units", "services"),
    ("dmesg_oom", "kernel_oom"),
];

impl HealthReport {
    pub(crate) fn from_observations(metrics: Option<&SysMetrics>, snapshot: &str) -> Self {
        let observed_at = Utc::now();
        let deterministic = super::diagnose::scan_findings(snapshot);
        let mut coverage = Vec::new();
        let mut evidence = Vec::new();
        let mut findings = Vec::new();

        let metric_states = metrics
            .map(SysMetrics::health_resource_states)
            .unwrap_or_else(missing_metric_states);
        for metric in metric_states {
            let evidence_id = format!("M:{}", metric.axis);
            let state = if metric.measured {
                HealthState::from_severity(metric.severity)
            } else {
                HealthState::Unknown
            };
            evidence.push(EvidenceRef {
                id: evidence_id.clone(),
                source: EvidenceSource::Metric,
                source_id: metric.axis.to_string(),
                observed_at,
                freshness: if metric.measured {
                    Freshness::Fresh
                } else {
                    Freshness::Unknown
                },
            });
            if state >= HealthState::Degraded {
                findings.push(HealthFinding {
                    id: format!("F:{}", metric.axis),
                    state,
                    message: metric.detail.clone(),
                    evidence_refs: vec![evidence_id.clone()],
                    suggested_followup: Some(metric_followup(metric.axis).to_string()),
                });
            }
            coverage.push(Coverage {
                axis: metric.axis.to_string(),
                state,
                detail: metric.detail,
                evidence_refs: vec![evidence_id],
            });
        }

        let sections = split_sections(snapshot);
        for &(probe_id, axis) in PROBE_AXES {
            let evidence_id = format!("E:{probe_id}");
            let body = sections
                .iter()
                .find_map(|(id, body)| (*id == probe_id).then_some(body.as_str()));
            let measured = body.is_some_and(probe_succeeded);
            evidence.push(EvidenceRef {
                id: evidence_id.clone(),
                source: EvidenceSource::Probe,
                source_id: probe_id.to_string(),
                observed_at,
                freshness: if measured {
                    Freshness::Fresh
                } else {
                    Freshness::Unknown
                },
            });

            let matched: Vec<&Finding> = deterministic
                .iter()
                .filter(|finding| finding.probe_id == probe_id)
                .collect();
            let state = if !measured {
                HealthState::Unknown
            } else {
                matched
                    .iter()
                    .map(|finding| HealthState::from_severity(finding.severity))
                    .max()
                    .unwrap_or(HealthState::Healthy)
            };
            let detail = if !measured {
                probe_failure_detail(body)
            } else if matched.is_empty() {
                "이상 신호 없음".to_string()
            } else {
                matched
                    .iter()
                    .map(|finding| finding.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            for (index, finding) in matched.into_iter().enumerate() {
                findings.push(HealthFinding {
                    id: format!("F:{probe_id}:{}", index + 1),
                    state: HealthState::from_severity(finding.severity),
                    message: finding.message.clone(),
                    evidence_refs: vec![evidence_id.clone()],
                    suggested_followup: finding.suggested_followup.clone(),
                });
            }
            coverage.push(Coverage {
                axis: axis.to_string(),
                state,
                detail,
                evidence_refs: vec![evidence_id],
            });
        }

        let checked_axes = coverage
            .iter()
            .filter(|c| c.state != HealthState::Unknown)
            .count();
        let total_axes = coverage.len();
        let coverage_complete = checked_axes == total_axes;
        let observed_verdict = coverage
            .iter()
            .filter(|c| c.state != HealthState::Unknown)
            .map(|c| c.state)
            .max()
            .unwrap_or(HealthState::Unknown);
        let verdict = if observed_verdict >= HealthState::Degraded {
            observed_verdict
        } else if coverage_complete {
            HealthState::Healthy
        } else {
            HealthState::Unknown
        };

        Self {
            schema_version: 1,
            observed_at,
            verdict,
            coverage_complete,
            checked_axes,
            total_axes,
            coverage,
            findings,
            evidence,
        }
    }

    pub(crate) fn render(&self) -> String {
        let scope = if self.coverage_complete {
            "complete coverage".to_string()
        } else {
            format!(
                "partial coverage: {}/{} checked",
                self.checked_axes, self.total_axes
            )
        };
        let mut out = format!(
            "Machine health: {} ({scope})\nObserved: {}\n",
            self.verdict.label(),
            self.observed_at.to_rfc3339()
        );
        if !self.findings.is_empty() {
            out.push_str("\nFindings:\n");
            for finding in &self.findings {
                out.push_str(&format!(
                    "{} {}  {}  [{}]\n",
                    finding.state.glyph(),
                    finding.id,
                    finding.message,
                    finding.evidence_refs.join(",")
                ));
                if let Some(next) = &finding.suggested_followup {
                    out.push_str(&format!("   Next: /diagnose {next}\n"));
                }
            }
        }
        out.push_str("\nCoverage:\n");
        for item in &self.coverage {
            out.push_str(&format!(
                "{} {:<18} {}  [{}]\n",
                item.state.glyph(),
                item.axis,
                item.detail,
                item.evidence_refs.join(",")
            ));
        }
        if !self.coverage_complete {
            out.push_str("\nUNKNOWN 항목은 정상으로 판정하지 않았습니다. 권한·플랫폼·수집 상태를 확인하세요.\n");
        }
        out
    }
}

fn missing_metric_states() -> Vec<HealthResourceState> {
    ["load", "cpu", "memory", "swap", "root_disk"]
        .into_iter()
        .map(|axis| HealthResourceState {
            axis,
            severity: Severity::Normal,
            detail: "신선한 status sample 없음".to_string(),
            measured: false,
        })
        .collect()
}

fn metric_followup(axis: &str) -> &'static str {
    match axis {
        "load" | "cpu" => "cpu",
        "memory" | "swap" => "memory",
        "root_disk" => "disk",
        _ => "generic health",
    }
}

fn split_sections(snapshot: &str) -> Vec<(&str, String)> {
    let mut sections = Vec::new();
    for line in snapshot.lines() {
        if let Some(name) = line.strip_prefix("## ") {
            sections.push((name.trim(), String::new()));
        } else if let Some((_, body)) = sections.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    sections
}

fn probe_succeeded(body: &str) -> bool {
    body.lines()
        .any(|line| line.starts_with("exit_code=0 ") || line == "exit_code=0")
}

fn probe_failure_detail(body: Option<&str>) -> String {
    let Some(body) = body else {
        return "probe 결과 없음".to_string();
    };
    if body.contains("[timeout]") || body.contains("exit_code=timeout") {
        return "probe timeout".to_string();
    }
    if let Some(line) = body.lines().find(|line| line.starts_with("exit_code=")) {
        return format!(
            "probe 실패 ({})",
            line.split_whitespace().next().unwrap_or(line)
        );
    }
    if body.contains("[blocked]") {
        return "probe 정책 차단".to_string();
    }
    "probe 실행 결과를 판독할 수 없음".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> SysMetrics {
        SysMetrics {
            load1: 1.0,
            cpu_pct: 10.0,
            cores: 4,
            mem_used: 4 * 1024 * 1024 * 1024,
            mem_total: 16 * 1024 * 1024 * 1024,
            disk_avail: 20 * 1024 * 1024 * 1024,
            disk_total: 100 * 1024 * 1024 * 1024,
            cpu_valid: true,
            ..SysMetrics::default()
        }
    }

    fn healthy_snapshot() -> String {
        HEALTH_PROBE_IDS
            .iter()
            .map(|id| format!("## {id}\ncommand: x\nexit_code=0 duration_ms=1 truncated=false cwd=/tmp\n--- stdout ---\n\n--- stderr ---\n\n"))
            .collect()
    }

    #[test]
    fn complete_clean_observations_are_healthy() {
        let report = HealthReport::from_observations(Some(&metrics()), &healthy_snapshot());
        assert_eq!(report.verdict, HealthState::Healthy);
        assert!(report.coverage_complete);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn critical_finding_wins_and_keeps_evidence_reference() {
        let snapshot = healthy_snapshot().replace(
            "## dmesg_oom\ncommand: x\nexit_code=0 duration_ms=1 truncated=false cwd=/tmp\n--- stdout ---\n",
            "## dmesg_oom\ncommand: x\nexit_code=0 duration_ms=1 truncated=false cwd=/tmp\n--- stdout ---\nOut of memory: Killed process 42\n",
        );
        let report = HealthReport::from_observations(Some(&metrics()), &snapshot);
        assert_eq!(report.verdict, HealthState::Critical);
        let finding = report
            .findings
            .iter()
            .find(|f| f.id.starts_with("F:dmesg_oom"))
            .unwrap();
        assert_eq!(finding.evidence_refs, vec!["E:dmesg_oom"]);
    }

    #[test]
    fn failed_probe_is_unknown_not_healthy() {
        let snapshot = healthy_snapshot().replace(
            "## failed_units\ncommand: x\nexit_code=0",
            "## failed_units\ncommand: x\nexit_code=1",
        );
        let report = HealthReport::from_observations(Some(&metrics()), &snapshot);
        let services = report
            .coverage
            .iter()
            .find(|c| c.axis == "services")
            .unwrap();
        assert_eq!(services.state, HealthState::Unknown);
        assert_eq!(report.verdict, HealthState::Unknown);
        assert!(!report.coverage_complete);
    }

    #[test]
    fn missing_metrics_are_explicit_unknowns_and_serialize() {
        let report = HealthReport::from_observations(None, &healthy_snapshot());
        assert_eq!(report.verdict, HealthState::Unknown);
        assert_eq!(
            report
                .coverage
                .iter()
                .filter(|c| c.state == HealthState::Unknown)
                .count(),
            5
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert!(json["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"] == "M:cpu"));
    }
}
