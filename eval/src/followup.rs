//! follow-up probe 선택 실험의 데이터와 인자 후보 추출.
//!
//! follow-up 템플릿 10개는 전부 인자형이고, 인자는 1차 증거에 **공백 분리 토큰**으로 그대로 등장한
//! 값만 게이트를 통과한다(`resolve_followup_line`). Jev는 텍스트를 생성하지 않으므로 인자를 지어낼
//! 수 없다 — 대신 증거에서 후보를 같은 규칙(공백 토큰 + 인자 charset)으로 뽑아 Choice 선택지로
//! 준다. 그러면 무엇을 고르든 게이트를 통과한다는 것이 구성상 보장된다.
//!
//! 후보는 **문제가 드러난 행**으로 좁힌다(2라운드). 1라운드에서 Jev의 오답은 전부 `proc_fd_top` 표의
//! 정상 행(50/100000, 한도 없는 900)을 대상으로 고른 것이었다 — 수치를 한도와 견주는 판단은 Jev가
//! 못 하고 스캐너가 한다. 그래서 `proc_fd`는 `scan_proc_fd`가 경고한 PID만, docker·k8s는 STATUS 열이
//! 정상이 아닌 행만 후보로 준다. 후보가 없는 템플릿은 메뉴에서 빠지고, 어느 템플릿에도 후보가 없으면
//! Jev는 `none`이나 catalog probe만 고를 수 있다. 정답 집합은 이 후보 집합과 같아야 하며
//! `validate`가 그것을 잠근다 — 정답은 생성기가 아니라 결정적 필터가 정한다.

use std::collections::BTreeMap;

use aic_client::agent::diagnose::{resolve_followup_line, scanned_proc_fd_pids};
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

/// `docker ps -s` 한 줄에서 (컨테이너 이름, 문제 여부). 헤더 줄이거나 형태가 어긋나면 `None`.
///
/// **헤더 오프셋으로 열을 자르지 않는다.** probe 출력은 redaction을 거친 뒤에 파싱되는데,
/// PORTS의 IPv4가 `[REDACTED:ipv4]`로 바뀌면서 셀 길이가 늘어 NAMES·SIZE 열이 행마다 다른 만큼
/// 오른쪽으로 밀린다(실측: 한 행 +16, 다른 행 +8). docker는 원본 폭으로 이미 패딩을 끝냈으므로
/// 헤더 위치는 더 이상 데이터 위치가 아니다. 그래서 양끝의 고정 토큰을 앵커로 쓴다.
///
/// - SIZE는 `<크기> (virtual <크기>)`다. `(virtual` 앞앞 토큰이 NAMES다(없으면 뒤에서 둘째).
/// - STATUS는 `Up`·`Restarting`·`Exited` 같은 고정 낱말로 시작한다. 그 지점부터 NAMES 직전까지가
///   STATUS + PORTS이며, PORTS에는 `(unhealthy)`·`(Paused)`가 섞이지 않는다.
fn docker_ps_row(line: &str) -> Option<(&str, bool)> {
    /// docker가 STATUS 첫 낱말로 쓰는 값. IMAGE·COMMAND 열은 따옴표나 `:` 태그를 달고 있어 겹치지 않는다.
    const STATUS_HEADS: &[&str] = &[
        "Up",
        "Exited",
        "Created",
        "Restarting",
        "Removal",
        "Dead",
        "Paused",
    ];
    let toks: Vec<&str> = line.split_whitespace().collect();
    let names_at = match toks.iter().rposition(|t| *t == "(virtual") {
        Some(i) => i.checked_sub(2)?,
        None => toks.len().checked_sub(2)?,
    };
    let status_at = toks
        .iter()
        .take(names_at)
        .position(|t| STATUS_HEADS.contains(t))?;
    let segment = &toks[status_at..names_at];
    let problem = segment[0] != "Up"
        || segment
            .iter()
            .any(|t| *t == "(unhealthy)" || *t == "(Paused)");
    Some((toks[names_at], problem))
}

/// `kubectl get pods` STATUS. probe가 `grep -v Running`을 거치므로 표에 남는 정상 행은 끝난 Job뿐이다.
fn k8s_pod_status_is_problem(status: &str) -> bool {
    !matches!(status, "Running" | "Completed" | "Succeeded")
}

/// 컨테이너가 한 번이라도 떴어야 로그가 있다. 이미지를 못 받았거나(ImagePullBackOff) 스케줄되지
/// 않은(Pending) pod에 `kubectl logs`는 오류만 돌려준다.
fn k8s_pod_has_logs(status: &str) -> bool {
    matches!(status, "CrashLoopBackOff" | "Error" | "OOMKilled")
}

/// `kubectl get nodes` STATUS. cordon(`Ready,SchedulingDisabled`)은 의도된 상태라 문제가 아니다.
fn k8s_node_status_is_problem(status: &str) -> bool {
    status.starts_with("NotReady") || status == "Unknown"
}

/// 템플릿별 인자 후보. 전부 증거의 공백 토큰이며 charset을 만족하고, 문제가 드러난 행에서만 나온다.
///
/// 규칙은 템플릿이 무엇을 받는지(description)에서 나온다. 섹션 이름으로 범위를 좁혀, 다른 섹션의
/// 숫자가 PID 후보로 새는 것을 막는다.
pub fn candidates(evidence: &str) -> BTreeMap<&'static str, Vec<String>> {
    let secs = sections(evidence);
    let flagged_pids: Vec<String> = scanned_proc_fd_pids(evidence)
        .iter()
        .map(u64::to_string)
        .collect();
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
            // failed_units: 첫 토큰이 unit 이름. `●` 같은 마커가 앞에 붙기도 한다. 표에 있는 행은 전부
            // 실패한 unit이라 따로 거를 것이 없다.
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
            // proc_fd_top: `FD PID COMMAND` 표에서 스캐너가 경고한 PID의 행만. 첫 열(FD 개수)도 숫자라
            // PID로 오인하기 쉬우므로 둘째 열만 본다.
            "proc_fd_top" => {
                for line in &lines {
                    let toks: Vec<&str> = line.split_whitespace().collect();
                    if toks.len() < 3 {
                        continue;
                    }
                    let (pid, cmd) = (toks[1], toks[2]);
                    if !flagged_pids.iter().any(|p| p == pid) {
                        continue;
                    }
                    push("proc_fd", pid);
                    if cmd.bytes().any(|b| b.is_ascii_alphabetic()) {
                        push("proc_net", cmd);
                    }
                }
            }
            // docker_ps(`docker ps -s`): NAMES 뒤에 SIZE 열이 있어 마지막 토큰이 이름이 아니다.
            "docker_ps" => {
                for line in lines.iter().skip(1) {
                    let Some((name, problem)) = docker_ps_row(line) else {
                        continue;
                    };
                    if !problem {
                        continue;
                    }
                    for t in [
                        "docker_logs",
                        "docker_logs_since",
                        "docker_inspect_container",
                        "docker_health",
                    ] {
                        push(t, name);
                    }
                }
            }
            // k8s pod 목록: NAME 열이 pod 이름, 그 두 칸 뒤가 STATUS. RESTARTS는 `14 (2m ago)`처럼
            // 공백을 품을 수 있지만 STATUS 앞이라 영향이 없다.
            "k8s_pods_notready" | "k8s_crashloop_pods" => {
                // `-A`면 첫 열이 NAMESPACE, 아니면 NAME이다. 헤더로 판별한다.
                let name_col = lines
                    .first()
                    .and_then(|h| h.split_whitespace().next())
                    .map_or(0, |h| usize::from(h == "NAMESPACE"));
                for line in lines.iter().skip(1) {
                    let toks: Vec<&str> = line.split_whitespace().collect();
                    let (Some(name), Some(status)) = (toks.get(name_col), toks.get(name_col + 2))
                    else {
                        continue;
                    };
                    if !k8s_pod_status_is_problem(status) {
                        continue;
                    }
                    push("k8s_pod_describe", name);
                    if k8s_pod_has_logs(status) {
                        push("k8s_pod_logs", name);
                    }
                }
            }
            "k8s_nodes" => {
                for line in lines.iter().skip(1) {
                    let toks: Vec<&str> = line.split_whitespace().collect();
                    let (Some(name), Some(status)) = (toks.first(), toks.get(1)) else {
                        continue;
                    };
                    if k8s_node_status_is_problem(status) {
                        push("k8s_node_describe", name);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// 후보를 `<template> <arg>` 줄로 편 정렬된 집합. 정답과 대조할 때 쓴다.
pub fn candidate_lines(evidence: &str) -> Vec<String> {
    let mut out: Vec<String> = candidates(evidence)
        .iter()
        .flat_map(|(t, args)| args.iter().map(move |a| format!("{t} {a}")))
        .collect();
    out.sort();
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

    /// 정답이 결정적 후보 집합과 같고 실제 게이트를 통과하는지 확인한다.
    ///
    /// 같아야 하는 이유: 정답은 생성기의 규칙 복제본이 만들고 후보는 production 스캐너와 이 파일의
    /// 필터가 만든다. 둘이 어긋나면 어느 비교군도 맞힐 수 없는 사례(정답이 후보 밖)나 정답이
    /// 부족한 사례(1라운드 pf-08: 스캐너는 세 PID를 경고했는데 정답은 하나)가 생긴다.
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
            let expected = candidate_lines(&b.evidence);
            let mut accepted = b.accepted.clone();
            accepted.sort();
            if accepted != expected {
                bail!(
                    "{}: 정답이 결정적 후보와 다릅니다 — 정답 {accepted:?}, 후보 {expected:?}",
                    b.id
                );
            }
            for line in &b.accepted {
                let (tmpl, _) = line
                    .split_once(' ')
                    .with_context(|| format!("{}: 정답 줄 형식 위반: {line:?}", b.id))?;
                if !ids.contains(&tmpl) {
                    bail!("{}: 정답의 템플릿이 목록에 없습니다: {tmpl}", b.id);
                }
                resolve_followup_line(line, &b.evidence).map_err(|e| {
                    anyhow::anyhow!("{}: 정답 {line:?}가 게이트를 통과하지 못함: {e}", b.id)
                })?;
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

    /// docker/kubectl처럼 열을 최대 폭 + 3으로 맞춘 표. 마지막 열은 채우지 않는다.
    fn table(rows: &[&[&str]]) -> String {
        let ncol = rows[0].len();
        let widths: Vec<usize> = (0..ncol)
            .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0) + 3)
            .collect();
        rows.iter()
            .map(|r| {
                let mut line = String::new();
                for (i, cell) in r.iter().enumerate() {
                    if i + 1 == ncol {
                        line.push_str(cell);
                    } else {
                        line.push_str(&format!("{cell:<w$}", w = widths[i]));
                    }
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn docker_ps(rows: &[&[&str]]) -> String {
        let mut all: Vec<&[&str]> = vec![&[
            "CONTAINER ID",
            "IMAGE",
            "COMMAND",
            "CREATED",
            "STATUS",
            "PORTS",
            "NAMES",
            "SIZE",
        ]];
        all.extend_from_slice(rows);
        format!(
            "## docker_ps\ncommand: docker ps -s | head -n 30\nexit_code=0\n--- stdout ---\n{}\n\n--- stderr ---\n",
            table(&all)
        )
    }

    #[test]
    fn unit_names_come_from_the_first_token_of_each_failed_row() {
        let c = candidates(FAILED_UNITS);
        assert_eq!(
            c.get("journal_unit").cloned().unwrap_or_default(),
            vec!["nginx.service".to_string(), "redis.service".to_string()]
        );
    }

    #[test]
    fn only_scanner_flagged_pids_are_proc_fd_candidates() {
        // 1라운드 오답 4건의 원인: 정상 행(12%, 한도 없는 900, 50/100000)을 대상으로 골랐다. 후보에서
        // 빼면 고를 수 없다. 한도 줄의 1000이 PID로 새지 않는 것도 여기서 잠근다.
        let c = candidates(PROC_FD_TOP);
        assert_eq!(
            c.get("proc_fd").cloned().unwrap_or_default(),
            vec!["4242".to_string()]
        );
        assert_eq!(
            c.get("proc_net").cloned().unwrap_or_default(),
            vec!["leaky".to_string()]
        );
        let normal = "## proc_fd_top\ncommand: x\nexit_code=0\n--- stdout ---\n\
per-proc limit: 100000\n     FD     PID COMMAND\n     50    904 tiny\n\n--- stderr ---\n\
## proc_fd_top\ncommand: x\nexit_code=0\n--- stdout ---\n     FD     PID COMMAND\n    900    905 mid2\n\n--- stderr ---\n";
        assert!(candidates(normal).is_empty(), "{:?}", candidates(normal));
        // 한도 줄이 없어도 절대량(>= 10000)은 경고다.
        let abs = "## proc_fd_top\ncommand: x\nexit_code=0\n--- stdout ---\n\
     FD     PID COMMAND\n  12000   3101 java\n    300   3102 sshd\n\n--- stderr ---\n";
        assert_eq!(
            candidates(abs).get("proc_fd").cloned().unwrap_or_default(),
            vec!["3101".to_string()]
        );
    }

    #[test]
    fn docker_names_come_from_the_names_column_of_problem_rows_only() {
        let ev = docker_ps(&[
            &[
                "3f9a1c2b7d4e",
                "nginx:1.25",
                "\"/docker-entrypoint.…\"",
                "7 days ago",
                "Up 7 days",
                "0.0.0.0:80->80/tcp",
                "web-1",
                "1.09kB (virtual 187MB)",
            ],
            &[
                "8c1d2e3f4a5b",
                "myapp:2.1",
                "\"python -m app\"",
                "2 hours ago",
                "Restarting (1) 12 seconds ago",
                "",
                "api-2",
                "0B (virtual 412MB)",
            ],
            &[
                "9d2e3f4a5b6c",
                "redis:7",
                "\"docker-entrypoint.s…\"",
                "3 days ago",
                "Up 3 days (healthy)",
                "6379/tcp",
                "cache-1",
                "0B (virtual 117MB)",
            ],
            &[
                "1a2b3c4d5e6f",
                "myapp:2.1",
                "\"python -m worker\"",
                "2 hours ago",
                "Up 2 hours (unhealthy)",
                "",
                "worker-3",
                "12.3kB (virtual 412MB)",
            ],
        ]);
        let c = candidates(&ev);
        // SIZE가 마지막 열이라 "마지막 토큰" 규칙이면 `187MB)`가 이름이 된다. COMMAND의 `…`가 뒤 열을
        // 밀지도 않아야 한다. 정상(Up, healthy) 행은 후보가 아니다.
        assert_eq!(
            c.get("docker_logs").cloned().unwrap_or_default(),
            vec!["api-2".to_string(), "worker-3".to_string()]
        );
        assert_eq!(c.get("docker_health"), c.get("docker_logs"));
        for line in ["docker_logs api-2", "docker_health worker-3"] {
            assert!(resolve_followup_line(line, &ev).is_ok(), "{line}");
        }
        let healthy = docker_ps(&[&[
            "3f9a1c2b7d4e",
            "nginx:1.25",
            "\"/docker-entrypoint.…\"",
            "7 days ago",
            "Up 10 seconds (health: starting)",
            "",
            "web-1",
            "0B (virtual 187MB)",
        ]]);
        assert!(candidates(&healthy).is_empty());
    }

    #[test]
    fn redacted_ports_do_not_shift_the_name_out_of_the_row() {
        // 실측(2026-09-22, macOS+OrbStack): probe 출력은 redaction 뒤에 파싱되는데 PORTS의 IPv4가
        // `[REDACTED:ipv4]`로 늘어나 NAMES가 헤더 위치보다 행마다 다르게(+8·+16) 밀린다. 헤더
        // 오프셋으로 자르면 이름이 잘리고(게이트에서 거부) STATUS 칸이 어긋나 정상 컨테이너가
        // 문제로 잡힌다. 아래 두 줄은 그때 실제로 나온 형태다(이름만 바꿨다).
        let ev = "## docker_ps\ncommand: docker ps -s | head -n 30\nexit_code=0\n--- stdout ---\n\
CONTAINER ID   IMAGE                               COMMAND                   CREATED        STATUS                PORTS                                                                                                NAMES                                  SIZE\n\
7a548a168c8b   acme/nginx:1.13.7                   \"/run.sh\"                 6 days ago     Up 6 days             [REDACTED:ipv4]:80->80/tcp, [::]:80->80/tcp, [REDACTED:ipv4]:443->443/tcp, [::]:443->443/tcp                         web-intranet-v2-nginx-1                6.77kB (virtual 271MB)\n\
7d65febad023   acme/php73:7.3.20                   \"bash -c 'dpkg -i /v…\"   6 days ago     Up 6 days (unhealthy) 80/tcp, 443/tcp, [REDACTED:ipv4]:32769->9000/tcp, [::]:32769->9000/tcp                                       web-intranet-v2-php-1                  16.5MB (virtual 929MB)\n\n--- stderr ---\n";
        let c = candidates(ev);
        // 정상 nginx는 후보가 아니고, unhealthy php만 후보이며 이름이 온전하다.
        assert_eq!(
            c.get("docker_logs").cloned().unwrap_or_default(),
            vec!["web-intranet-v2-php-1".to_string()]
        );
        assert!(resolve_followup_line("docker_logs web-intranet-v2-php-1", ev).is_ok());
    }

    #[test]
    fn a_container_with_no_published_ports_still_parses() {
        // PORTS가 비면 STATUS 바로 뒤가 NAMES다 — 앵커가 토큰 개수에 기대면 여기서 깨진다.
        let ev = "## docker_ps\ncommand: docker ps -s | head -n 30\nexit_code=0\n--- stdout ---\n\
CONTAINER ID   IMAGE       COMMAND       CREATED       STATUS                        PORTS   NAMES     SIZE\n\
1a2b3c4d5e6f   acme:2.1    \"./worker\"    2 hours ago   Restarting (137) 8 seconds ago         worker-3   0B (virtual 412MB)\n\n--- stderr ---\n";
        assert_eq!(
            candidates(ev)
                .get("docker_health")
                .cloned()
                .unwrap_or_default(),
            vec!["worker-3".to_string()]
        );
    }

    #[test]
    fn pods_skip_completed_rows_and_never_started_containers_have_no_logs() {
        let ev = "## k8s_pods_notready\ncommand: kubectl get pods -A | grep -v Running\nexit_code=0\n--- stdout ---\n\
NAMESPACE   NAME                     READY   STATUS             RESTARTS      AGE\n\
prod        payments-7f9c-x1         0/1     CrashLoopBackOff   14 (2m ago)   3d\n\
prod        ingest-5d2a-q9           0/1     ImagePullBackOff   0             25m\n\
prod        backup-28812345-x9k2l    0/1     Completed          0             3h\n\n--- stderr ---\n";
        let c = candidates(ev);
        assert_eq!(
            c.get("k8s_pod_describe").cloned().unwrap_or_default(),
            vec!["payments-7f9c-x1".to_string(), "ingest-5d2a-q9".to_string()]
        );
        assert_eq!(
            c.get("k8s_pod_logs").cloned().unwrap_or_default(),
            vec!["payments-7f9c-x1".to_string()]
        );
        // `-A` 없는 표는 NAME이 첫 열이다.
        let no_ns = "## k8s_pods_notready\ncommand: kubectl get pods | grep -v Running\nexit_code=0\n--- stdout ---\n\
NAME             READY   STATUS   RESTARTS   AGE\n\
api-6c8d-abcde   0/1     Error    3          1h\n\n--- stderr ---\n";
        assert_eq!(
            candidates(no_ns)
                .get("k8s_pod_logs")
                .cloned()
                .unwrap_or_default(),
            vec!["api-6c8d-abcde".to_string()]
        );
    }

    #[test]
    fn nodes_only_not_ready_or_unknown_are_targets() {
        let ev = "## k8s_nodes\ncommand: kubectl get nodes\nexit_code=0\n--- stdout ---\n\
NAME      STATUS                     ROLES           AGE    VERSION\n\
node-a    Ready                      control-plane   300d   v1.28.9\n\
node-b    Ready,SchedulingDisabled   <none>          300d   v1.28.9\n\
node-c    NotReady                   <none>          300d   v1.28.9\n\n--- stderr ---\n";
        assert_eq!(
            candidates(ev)
                .get("k8s_node_describe")
                .cloned()
                .unwrap_or_default(),
            vec!["node-c".to_string()]
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
    fn validate_requires_the_answer_set_to_equal_the_deterministic_candidates() {
        let mk = |accepted: &[&str]| FollowupDataset {
            schema_version: 1,
            generated: "t".into(),
            bundles: vec![Bundle {
                id: "b1".into(),
                split: Split::Dev,
                symptom: None,
                evidence: FAILED_UNITS.into(),
                accepted: accepted.iter().map(|s| s.to_string()).collect(),
                source: "synthetic".into(),
                traits: vec![],
            }],
        };
        // 후보 둘 중 하나만 적은 정답: 필터가 더 많이 잡으니 어긋난다(1라운드 pf-08 결함).
        assert!(mk(&["journal_unit nginx.service"]).validate().is_err());
        // 신호 없음이라고 적었는데 후보가 있다.
        let err = mk(&[]).validate().unwrap_err().to_string();
        assert!(err.contains("정답이 결정적 후보와 다릅니다"), "{err}");
        // 후보 밖 정답은 어느 비교군도 맞힐 수 없다.
        assert!(mk(&["journal_unit mysqld.service"]).validate().is_err());
        assert!(
            mk(&["journal_unit nginx.service", "journal_unit redis.service"])
                .validate()
                .is_ok()
        );
    }
}
