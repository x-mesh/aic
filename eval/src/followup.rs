//! follow-up probe 선택 실험의 데이터와 인자 후보 추출.
//!
//! follow-up 템플릿 10개는 전부 인자형이고, 인자는 1차 증거에 **공백 분리 토큰**으로 그대로 등장한
//! 값만 게이트를 통과한다(`resolve_followup_line`). Jev는 텍스트를 생성하지 않으므로 인자를 지어낼
//! 수 없다 — 대신 증거에서 후보를 같은 규칙(공백 토큰 + 인자 charset)으로 뽑아 Choice 선택지로
//! 준다. 그러면 무엇을 고르든 게이트를 통과한다는 것이 구성상 보장된다.

use std::collections::BTreeMap;

use aic_client::agent::diagnose::resolve_followup_line;
use aic_client::agent::probes::followup_templates;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FollowupDataset {
    pub schema_version: u32,
    pub generated: String,
    pub bundles: Vec<Bundle>,
}

/// 진단 한 번의 1차 증거와, 그 증거가 구성상 가리키는 정답 follow-up.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Bundle {
    pub id: String,
    pub split: Split,
    pub symptom: Option<String>,
    /// `## <probe_id>` 섹션을 이어 붙인 1차 증거. 실제 호스트 출력은 섞이지 않는다(`source` 필수).
    pub evidence: String,
    /// 정답 follow-up 줄들(`<template_id> <arg>`). 하나라도 맞으면 정탐. 비어 있으면
    /// "follow-up 불필요"가 정답이다.
    pub accepted: Vec<String>,
    pub source: String,
    pub traits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Dev,
    Final,
}

/// 선택지 밖 응답을 실패로 세기 위한 템플릿 목록. production의 단일 출처를 그대로 쓴다.
pub fn template_ids() -> Vec<&'static str> {
    followup_templates().into_iter().map(|(id, _)| id).collect()
}

/// `## <id>` 섹션으로 나눈다. production의 `iter_sections`와 같은 규칙이지만 그 함수는 공개돼 있지
/// 않아 여기서 최소 형태로 다시 둔다.
fn sections(evidence: &str) -> Vec<(&str, String)> {
    let mut out: Vec<(&str, String)> = Vec::new();
    for line in evidence.lines() {
        if let Some(name) = line.strip_prefix("## ") {
            out.push((name.trim(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// `--- stdout ---` 아래의 비어 있지 않은 줄들. 헤더의 `command:` 줄에 든 단어가 후보로 새는 것을
/// 막고, 구분자 직후의 빈 줄이 "첫 줄"로 잡혀 표 헤더 건너뛰기가 어긋나는 것도 막는다.
fn stdout_lines(body: &str) -> Vec<&str> {
    let after = body
        .split_once("--- stdout ---")
        .map_or(body, |(_, rest)| rest);
    let out = after
        .split_once("--- stderr ---")
        .map_or(after, |(out, _)| out);
    out.lines().filter(|l| !l.trim().is_empty()).collect()
}

/// 게이트와 같은 charset 규칙. production의 `FollowupTemplate::arg_valid`는 공개돼 있지 않아 같은
/// 규칙을 여기 둔다 — 갈리면 후보가 게이트에서 거부되므로 `followup_validate`가 그것을 잡는다.
fn arg_charset_ok(arg: &str) -> bool {
    let mut chars = arg.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    arg.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// 후보 수 상한. Choice는 255개까지 받지만 선택지가 많을수록 질문이 길어지고, 실제 진단 출력에서
/// 대상 후보가 이보다 많으면 이미 사람이 읽기 어려운 출력이다.
const MAX_CANDIDATES: usize = 30;

/// 템플릿별 인자 후보. 전부 증거의 공백 토큰이며 charset을 만족한다.
///
/// 규칙은 템플릿이 무엇을 받는지(description)에서 나온다. 섹션 이름으로 범위를 좁혀, 다른 섹션의
/// 숫자가 PID 후보로 새는 것을 막는다.
pub fn candidates(evidence: &str) -> BTreeMap<&'static str, Vec<String>> {
    let secs = sections(evidence);
    let mut out: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    let mut push = |template: &'static str, value: &str| {
        if !arg_charset_ok(value) {
            return;
        }
        let list = out.entry(template).or_default();
        if !list.iter().any(|v| v == value) && list.len() < MAX_CANDIDATES {
            list.push(value.to_string());
        }
    };

    for (name, body) in &secs {
        let lines = stdout_lines(body);
        match *name {
            // failed_units: 첫 토큰이 unit 이름. `●` 같은 마커가 앞에 붙기도 한다.
            "failed_units" => {
                for line in &lines {
                    for tok in line.split_whitespace() {
                        if tok.ends_with(".service")
                            || tok.ends_with(".timer")
                            || tok.ends_with(".socket")
                            || tok.ends_with(".mount")
                        {
                            push("journal_unit", tok);
                            break;
                        }
                    }
                }
            }
            // proc_fd_top / process: 표의 PID 열. 헤더 줄과 한도 줄은 숫자 토큰이 아니거나 문맥이 다르다.
            // `FD PID COMMAND` 표. 첫 열(FD 개수)도 숫자라 PID로 오인하기 쉬우므로 둘째 열만 본다.
            // 한도 줄(`per-proc limit: 1000`)과 헤더는 둘째 열이 숫자가 아니라 자연히 빠진다.
            "proc_fd_top" => {
                for line in &lines {
                    let toks: Vec<&str> = line.split_whitespace().collect();
                    if toks.len() < 3 {
                        continue;
                    }
                    let (fd, pid, cmd) = (toks[0], toks[1], toks[2]);
                    let is_num = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
                    if is_num(fd) && is_num(pid) {
                        push("proc_fd", pid);
                        if cmd.bytes().any(|b| b.is_ascii_alphabetic()) {
                            push("proc_net", cmd);
                        }
                    }
                }
            }
            // docker_ps: 마지막 토큰이 NAMES 열.
            "docker_ps" => {
                for line in lines.iter().skip(1) {
                    if let Some(last) = line.split_whitespace().last() {
                        for t in [
                            "docker_logs",
                            "docker_logs_since",
                            "docker_inspect_container",
                            "docker_health",
                        ] {
                            push(t, last);
                        }
                    }
                }
            }
            // k8s pod 목록: 첫 토큰이 pod 이름.
            "k8s_pods_notready" | "k8s_crashloop_pods" => {
                // `-A`면 첫 열이 NAMESPACE, 아니면 NAME이다. 헤더로 판별한다.
                let name_col = lines
                    .first()
                    .and_then(|h| h.split_whitespace().next())
                    .map_or(0, |h| usize::from(h == "NAMESPACE"));
                for line in lines.iter().skip(1) {
                    if let Some(name) = line.split_whitespace().nth(name_col) {
                        push("k8s_pod_describe", name);
                        push("k8s_pod_logs", name);
                    }
                }
            }
            "k8s_nodes" | "k8s_node_pressure" => {
                for line in lines.iter().skip(1) {
                    if let Some(first) = line.split_whitespace().next() {
                        push("k8s_node_describe", first);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

impl FollowupDataset {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("데이터 파일을 읽지 못했습니다: {}", path.display()))?;
        let ds: Self = serde_json::from_str(&raw)
            .with_context(|| format!("데이터 파싱 실패: {}", path.display()))?;
        ds.validate()?;
        Ok(ds)
    }

    /// 정답 줄이 실제 게이트를 통과하는지까지 확인한다. 통과하지 않는 정답은 어느 비교군도 맞힐 수
    /// 없어 그 사례는 구조적으로 전부 틀린다.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("지원하지 않는 schema_version: {}", self.schema_version);
        }
        let ids = template_ids();
        let mut seen = std::collections::BTreeSet::new();
        for b in &self.bundles {
            if !seen.insert(b.id.as_str()) {
                bail!("중복 id: {}", b.id);
            }
            if b.source.trim().is_empty() {
                bail!(
                    "{}: source가 비어 있습니다 — 실제 호스트 출력이 섞였는지 알 수 없습니다",
                    b.id
                );
            }
            if !b.evidence.contains("## ") {
                bail!("{}: evidence에 섹션이 없습니다", b.id);
            }
            let cands = candidates(&b.evidence);
            for line in &b.accepted {
                let (tmpl, arg) = line
                    .split_once(' ')
                    .with_context(|| format!("{}: 정답 줄 형식 위반: {line:?}", b.id))?;
                if !ids.contains(&tmpl) {
                    bail!("{}: 정답의 템플릿이 목록에 없습니다: {tmpl}", b.id);
                }
                resolve_followup_line(line, &b.evidence).map_err(|e| {
                    anyhow::anyhow!("{}: 정답 {line:?}가 게이트를 통과하지 못함: {e}", b.id)
                })?;
                // 후보 추출이 정답을 포함해야 Jev가 그것을 고를 기회가 있다. 못 뽑으면 추출 규칙의 결함이다.
                let has = cands.get(tmpl).is_some_and(|v| v.iter().any(|c| c == arg));
                if !has {
                    bail!(
                        "{}: 후보 추출이 정답 인자 {arg:?}를 {tmpl}의 후보로 뽑지 못했습니다 \
                         (후보: {:?})",
                        b.id,
                        cands.get(tmpl)
                    );
                }
            }
        }
        Ok(())
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let dev = self
            .bundles
            .iter()
            .filter(|b| b.split == Split::Dev)
            .count();
        let fin = self.bundles.len() - dev;
        let none = self
            .bundles
            .iter()
            .filter(|b| b.accepted.is_empty())
            .count();
        (dev, fin, none)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAILED_UNITS: &str = "## failed_units\ncommand: systemctl --failed\nexit_code=0\n\
--- stdout ---\n● nginx.service loaded failed failed Web\nredis.service loaded failed failed KV\n\n--- stderr ---\n";

    const PROC_FD_TOP: &str = "## proc_fd_top\ncommand: x\nexit_code=0\n--- stdout ---\n\
per-proc limit: 1000\n     FD     PID COMMAND\n    900   4242 leaky\n    120    301 svcd\n\n--- stderr ---\n";

    #[test]
    fn unit_names_come_from_the_first_token_of_each_failed_row() {
        let c = candidates(FAILED_UNITS);
        assert_eq!(
            c.get("journal_unit").cloned().unwrap_or_default(),
            vec!["nginx.service".to_string(), "redis.service".to_string()]
        );
    }

    #[test]
    fn pids_skip_the_limit_line_and_keep_the_command_column() {
        // 한도 줄의 1000이 PID 후보로 새면 Jev가 존재하지 않는 프로세스를 고른다.
        let c = candidates(PROC_FD_TOP);
        assert_eq!(
            c.get("proc_fd").cloned().unwrap_or_default(),
            vec!["4242".to_string(), "301".to_string()]
        );
        assert_eq!(
            c.get("proc_net").cloned().unwrap_or_default(),
            vec!["leaky".to_string(), "svcd".to_string()]
        );
    }

    #[test]
    fn every_candidate_passes_the_production_gate() {
        // 후보 규칙이 게이트와 갈리면 Jev의 답이 거부된다. 둘이 같은 규칙임을 여기서 잠근다.
        let evidence = format!("{FAILED_UNITS}{PROC_FD_TOP}");
        for (tmpl, args) in candidates(&evidence) {
            for a in args {
                let line = format!("{tmpl} {a}");
                assert!(
                    resolve_followup_line(&line, &evidence).is_ok(),
                    "{line} 거부됨"
                );
            }
        }
    }

    #[test]
    fn a_json_journal_line_yields_no_unit_candidate() {
        // 게이트는 공백 토큰만 대조하므로 JSON 안의 unit 이름은 어차피 거부된다. 후보로 뽑지 않아야
        // Jev가 통과 못 할 답을 고르지 않는다.
        let ev = "## journal_daemon_errors\ncommand: j\nexit_code=0\n--- stdout ---\n\
{\"_SYSTEMD_UNIT\":\"cron.service\",\"MESSAGE\":\"x\"}\n\n--- stderr ---\n";
        assert!(!candidates(ev).contains_key("journal_unit"));
    }

    #[test]
    fn validate_rejects_an_answer_the_extractor_cannot_reach() {
        let ds = FollowupDataset {
            schema_version: 1,
            generated: "t".into(),
            bundles: vec![Bundle {
                id: "b1".into(),
                split: Split::Dev,
                symptom: None,
                evidence: FAILED_UNITS.into(),
                // evidence에 없는 unit — 게이트에서 거부된다.
                accepted: vec!["journal_unit mysqld.service".into()],
                source: "synthetic".into(),
                traits: vec![],
            }],
        };
        let err = ds.validate().unwrap_err().to_string();
        assert!(err.contains("게이트"), "{err}");
    }
}
