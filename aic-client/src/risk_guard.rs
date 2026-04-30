//! Command risk classifier (P2 'Command Risk Guard').
//!
//! `aic fix`/`aic capture-last`/hook mode 사전 경고 등에서 "이 명령을 실행/재실행해도
//! 안전한가"를 판단하는 공통 모듈이다.
//!
//! 의도:
//! - 정확한 shell 파싱은 목적이 아니다. 위험을 "낮춰 보지 않는다"는 보수적 태도를
//!   기본으로 한다 — 파싱 실패/복잡한 형태는 [`RiskLevel::Unknown`]으로 흐른다.
//! - rule은 builtin denylist 우선, 그 다음 safelist, 마지막으로 Unknown 폴백.
//! - pipeline (`|`), 다중 statement (`;`/`&&`/`||`), subshell (`$()`/`` ` `` `)는
//!   각 segment 중 가장 위험한 결과를 채택하며 subshell은 항상 Unknown.

use std::collections::HashSet;

/// 명령의 위험 등급.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// 읽기 전용 또는 formatting처럼 낮은 위험. `--yes` 자동 진행 허용.
    Safe,
    /// 파일 변경/dependency install/network write — 사용자 확인 필요.
    NeedsConfirm,
    /// destructive/irreversible. `--yes`도 통하지 않아야 한다.
    Dangerous,
    /// 파싱 실패 또는 분류 불가 — 호출자는 보수적으로 처리.
    Unknown,
}

impl RiskLevel {
    /// `--yes`로 자동 진행해도 되는 등급인지.
    pub fn allows_auto_confirm(self) -> bool {
        matches!(self, RiskLevel::Safe)
    }

    /// 두 위험 중 더 높은 쪽을 반환한다.
    pub fn max(self, other: RiskLevel) -> RiskLevel {
        if self.severity() >= other.severity() {
            self
        } else {
            other
        }
    }

    fn severity(self) -> u8 {
        match self {
            RiskLevel::Safe => 0,
            RiskLevel::NeedsConfirm => 1,
            RiskLevel::Unknown => 2,
            RiskLevel::Dangerous => 3,
        }
    }
}

/// 분류 결과. 사용자에게 표시할 사유와 매칭된 rule id를 함께 돌려준다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub reason: Option<String>,
    pub rule: Option<&'static str>,
}

impl RiskAssessment {
    fn dangerous(rule: &'static str, reason: impl Into<String>) -> Self {
        Self {
            level: RiskLevel::Dangerous,
            reason: Some(reason.into()),
            rule: Some(rule),
        }
    }
    fn needs_confirm(rule: &'static str, reason: impl Into<String>) -> Self {
        Self {
            level: RiskLevel::NeedsConfirm,
            reason: Some(reason.into()),
            rule: Some(rule),
        }
    }
    fn safe(rule: &'static str) -> Self {
        Self {
            level: RiskLevel::Safe,
            reason: None,
            rule: Some(rule),
        }
    }
    fn unknown(reason: impl Into<String>) -> Self {
        Self {
            level: RiskLevel::Unknown,
            reason: Some(reason.into()),
            rule: None,
        }
    }
}

/// 명령 텍스트의 위험을 분류한다.
///
/// 동작:
/// 1. multi-statement/pipeline 분리 — `;`, `&&`, `||`, `|` 단위로 segment 나눔.
/// 2. subshell(`$(...)`/backtick), redirect target이 `/etc`/`/dev` 등 시스템 경로면
///    Dangerous 또는 Unknown.
/// 3. 각 segment 분류 → 최댓값 반환.
pub fn classify(command: &str) -> RiskAssessment {
    classify_with_extra_denylist(command, &[])
}

/// `extra_dangerous`에 사용자 config로 확장한 dangerous 명령 prefix(공백 포함)
/// 목록을 넣으면 builtin rule보다 우선해서 매칭한다.
pub fn classify_with_extra_denylist(command: &str, extra_dangerous: &[String]) -> RiskAssessment {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return RiskAssessment::unknown("빈 명령");
    }

    // subshell 또는 backtick은 정확한 분석이 어려워 Unknown로 단호히 떨어뜨린다.
    if contains_unbounded_substitution(trimmed) {
        return RiskAssessment::unknown("subshell/backtick 포함 — 정적 분석 한계");
    }

    let segments = split_top_level(trimmed);
    if segments.is_empty() {
        return RiskAssessment::unknown("파싱 실패");
    }

    let mut worst = RiskAssessment {
        level: RiskLevel::Safe,
        reason: None,
        rule: None,
    };
    for seg in segments {
        let asm = classify_single(seg.trim(), extra_dangerous);
        if asm.level.severity() > worst.level.severity() {
            worst = asm;
        }
    }
    worst
}

fn contains_unbounded_substitution(cmd: &str) -> bool {
    // backtick 사용은 곧 subshell.
    if cmd.contains('`') {
        return true;
    }
    // $(...)는 paren depth로 본다 — 단순한 $( cmd ) 패턴은 잡힌다.
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'(' {
            return true;
        }
        i += 1;
    }
    false
}

/// top-level statement/pipeline separator로 분리 — 따옴표 안의 separator는 무시.
fn split_top_level(cmd: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = cmd.as_bytes();
    let mut start = 0;
    let mut i = 0;
    let mut quote: Option<u8> = None;

    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
                i += 1;
            }
            None => {
                if b == b'\'' || b == b'"' {
                    quote = Some(b);
                    i += 1;
                    continue;
                }
                if b == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if b == b';' || b == b'|' || b == b'&' {
                    // ;, &&, ||, | 모두 분리 — single & (background)도 분리.
                    let cut = i;
                    let next = bytes.get(i + 1).copied();
                    let consume = if (b == b'|' && next == Some(b'|'))
                        || (b == b'&' && next == Some(b'&'))
                    {
                        2
                    } else {
                        1
                    };
                    out.push(&cmd[start..cut]);
                    i += consume;
                    start = i;
                    continue;
                }
                i += 1;
            }
        }
    }
    if start < cmd.len() {
        out.push(&cmd[start..]);
    }
    out.into_iter().filter(|s| !s.trim().is_empty()).collect()
}

fn classify_single(segment: &str, extra_dangerous: &[String]) -> RiskAssessment {
    if segment.is_empty() {
        return RiskAssessment::unknown("빈 segment");
    }

    // redirect target이 시스템 경로면 위험.
    if let Some(asm) = classify_redirect(segment) {
        return asm;
    }

    // env prefix (`FOO=bar cmd ...`) 제거 — A=B 형태가 첫 토큰이면 건너뛴다.
    let stripped = strip_env_prefix(segment);
    let tokens = match tokenize(stripped) {
        Some(t) if !t.is_empty() => t,
        _ => return RiskAssessment::unknown("토큰화 실패"),
    };

    // base name 단위로 매칭 (e.g. /usr/local/bin/git → git).
    let head_full = tokens[0].as_str();
    let head = base_name(head_full);
    let rest: Vec<&str> = tokens.iter().skip(1).map(String::as_str).collect();

    // 사용자 정의 denylist 우선.
    let lowered = stripped.trim_start().to_lowercase();
    for entry in extra_dangerous {
        let needle = entry.trim().to_lowercase();
        if !needle.is_empty() && lowered.starts_with(&needle) {
            return RiskAssessment::dangerous(
                "config.dangerous",
                format!("사용자 정의 dangerous rule과 일치 ('{entry}')"),
            );
        }
    }

    // ── Dangerous rules ────────────────────────────────────────────
    if let Some(asm) = match_dangerous(head, &rest) {
        return asm;
    }
    // ── Safe rules ─────────────────────────────────────────────────
    if let Some(asm) = match_safe(head, &rest) {
        return asm;
    }
    // ── NeedsConfirm rules ─────────────────────────────────────────
    if let Some(asm) = match_needs_confirm(head, &rest) {
        return asm;
    }

    RiskAssessment::unknown(format!("분류 룰에 매칭되지 않음 ('{head}')"))
}

fn classify_redirect(segment: &str) -> Option<RiskAssessment> {
    // 따옴표 밖에서 > 또는 >>가 시스템 경로로 향하면 Dangerous.
    let bytes = segment.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
                i += 1;
            }
            None => {
                if b == b'\'' || b == b'"' {
                    quote = Some(b);
                    i += 1;
                    continue;
                }
                if b == b'>' {
                    let target = segment[i + 1..].trim_start_matches('>').trim_start();
                    let target_first = target.split_whitespace().next().unwrap_or("");
                    if is_system_path(target_first) {
                        return Some(RiskAssessment::dangerous(
                            "redirect.system_path",
                            format!("시스템 경로로의 redirect: '{target_first}'"),
                        ));
                    }
                }
                i += 1;
            }
        }
    }
    None
}

fn is_system_path(s: &str) -> bool {
    let s = s.trim_matches(|c| c == '\'' || c == '"');
    s.starts_with("/etc/")
        || s == "/etc"
        || s.starts_with("/dev/")
        || s == "/dev/sda"
        || s.starts_with("/boot/")
        || s.starts_with("/sys/")
        || s.starts_with("/proc/")
}

fn strip_env_prefix(segment: &str) -> &str {
    let trimmed = segment.trim_start();
    let mut rest = trimmed;
    loop {
        let head = rest.split_whitespace().next().unwrap_or("");
        if head.is_empty() {
            return rest;
        }
        if let Some(eq) = head.find('=') {
            let name = &head[..eq];
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                rest = rest[head.len()..].trim_start();
                continue;
            }
        }
        return rest;
    }
}

fn tokenize(segment: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let bytes = segment.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    let mut in_token = false;

    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' && i + 1 < bytes.len() {
                    cur.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                    i += 1;
                    continue;
                }
                cur.push(b as char);
                i += 1;
            }
            None => {
                if b.is_ascii_whitespace() {
                    if in_token {
                        out.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                    i += 1;
                    continue;
                }
                if b == b'\'' || b == b'"' {
                    quote = Some(b);
                    in_token = true;
                    i += 1;
                    continue;
                }
                if b == b'\\' && i + 1 < bytes.len() {
                    cur.push(bytes[i + 1] as char);
                    in_token = true;
                    i += 2;
                    continue;
                }
                cur.push(b as char);
                in_token = true;
                i += 1;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if in_token {
        out.push(cur);
    }
    Some(out)
}

fn base_name(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

// ── Rule helpers ──────────────────────────────────────────────────

fn has_flag(args: &[&str], flag: &str) -> bool {
    args.iter().any(|a| *a == flag || a.starts_with(&format!("{flag}=")))
}

fn first_subcommand<'a>(args: &[&'a str]) -> Option<&'a str> {
    args.iter().find(|a| !a.starts_with('-')).copied()
}

fn match_dangerous(head: &str, args: &[&str]) -> Option<RiskAssessment> {
    match head {
        "rm" => {
            if has_flag(args, "-rf")
                || (has_flag(args, "-r") && has_flag(args, "-f"))
                || has_flag(args, "--recursive")
                    && (has_flag(args, "--force") || has_flag(args, "-f"))
                || has_flag(args, "-fr")
            {
                return Some(RiskAssessment::dangerous(
                    "rm.recursive_force",
                    "재귀적 강제 삭제는 복구 불가하다 (rm -rf)",
                ));
            }
            // 단순 rm은 NeedsConfirm로 처리(아래 fallthrough에서).
            None
        }
        "git" => match first_subcommand(args) {
            Some("push") => {
                if has_flag(args, "--force")
                    || has_flag(args, "-f")
                    || has_flag(args, "--force-with-lease")
                {
                    Some(RiskAssessment::dangerous(
                        "git.push_force",
                        "force push는 원격 history를 덮어쓴다",
                    ))
                } else {
                    None
                }
            }
            Some("reset") => {
                if has_flag(args, "--hard") {
                    Some(RiskAssessment::dangerous(
                        "git.reset_hard",
                        "git reset --hard는 작업 트리 변경을 모두 버린다",
                    ))
                } else {
                    None
                }
            }
            Some("clean") => {
                if has_flag(args, "-f") || has_flag(args, "--force") || has_flag(args, "-fd") {
                    Some(RiskAssessment::dangerous(
                        "git.clean_force",
                        "git clean -f는 untracked 파일을 영구 삭제한다",
                    ))
                } else {
                    None
                }
            }
            Some("checkout") | Some("restore") => {
                if args.iter().any(|a| *a == "." || *a == "--") {
                    Some(RiskAssessment::dangerous(
                        "git.checkout_dot",
                        "현재 변경을 모두 버리는 형태",
                    ))
                } else {
                    None
                }
            }
            _ => None,
        },
        "kubectl" => match first_subcommand(args) {
            Some("delete") => Some(RiskAssessment::dangerous(
                "kubectl.delete",
                "kubectl delete는 cluster 자원을 제거한다",
            )),
            Some("apply") if has_flag(args, "--prune") => Some(RiskAssessment::dangerous(
                "kubectl.apply_prune",
                "--prune은 매니페스트에 없는 자원을 삭제한다",
            )),
            _ => None,
        },
        "terraform" => match first_subcommand(args) {
            Some("apply") | Some("destroy") => Some(RiskAssessment::dangerous(
                "terraform.mutate",
                "terraform apply/destroy는 infra 상태를 변경한다",
            )),
            _ => None,
        },
        "docker" => match first_subcommand(args) {
            Some("rm") | Some("rmi") | Some("system") if has_flag(args, "-f") => {
                Some(RiskAssessment::dangerous(
                    "docker.force_remove",
                    "docker 강제 제거는 복구 불가",
                ))
            }
            _ => None,
        },
        "npm" | "pnpm" | "yarn" => match first_subcommand(args) {
            Some("publish") => Some(RiskAssessment::dangerous(
                "npm.publish",
                "package publish는 외부에 영구 공개된다",
            )),
            _ => None,
        },
        "dd" => Some(RiskAssessment::dangerous(
            "dd.raw_io",
            "dd는 디스크/디바이스를 직접 덮어쓸 수 있다",
        )),
        "mkfs" | "mkfs.ext4" | "mkfs.xfs" | "mkfs.btrfs" => Some(RiskAssessment::dangerous(
            "mkfs",
            "파일시스템 포맷은 데이터를 모두 지운다",
        )),
        "shutdown" | "reboot" | "halt" | "poweroff" => Some(RiskAssessment::dangerous(
            "system.power",
            "시스템 종료/재시작",
        )),
        _ => None,
    }
}

fn match_needs_confirm(head: &str, args: &[&str]) -> Option<RiskAssessment> {
    let needs_confirm_heads: &[&str] = &[
        "rm", "mv", "cp", "chmod", "chown", "kill", "pkill", "killall", "make", "systemctl",
        "service",
    ];
    if needs_confirm_heads.contains(&head) {
        return Some(RiskAssessment::needs_confirm(
            "fs.mutation",
            format!("파일/프로세스 변경 명령 ({head})"),
        ));
    }
    if matches!(head, "npm" | "pnpm" | "yarn") {
        match first_subcommand(args) {
            Some("install" | "i" | "add" | "remove" | "uninstall" | "update" | "upgrade") => {
                return Some(RiskAssessment::needs_confirm(
                    "npm.mutate",
                    "dependency tree 변경",
                ));
            }
            _ => {}
        }
    }
    if head == "cargo" {
        match first_subcommand(args) {
            Some("install" | "uninstall" | "update" | "publish") => {
                return Some(RiskAssessment::needs_confirm(
                    "cargo.mutate",
                    "cargo 상태 변경",
                ));
            }
            _ => {}
        }
    }
    if head == "git" {
        match first_subcommand(args) {
            Some("commit" | "push" | "pull" | "merge" | "rebase" | "stash" | "tag" | "fetch") => {
                return Some(RiskAssessment::needs_confirm(
                    "git.mutate",
                    "git 상태 변경",
                ));
            }
            _ => {}
        }
    }
    if head == "docker" {
        match first_subcommand(args) {
            Some("run" | "start" | "stop" | "kill" | "restart" | "build" | "pull" | "compose") => {
                return Some(RiskAssessment::needs_confirm(
                    "docker.mutate",
                    "docker 상태 변경",
                ));
            }
            _ => {}
        }
    }
    None
}

fn match_safe(head: &str, args: &[&str]) -> Option<RiskAssessment> {
    let safe_set: HashSet<&str> = [
        "ls", "ll", "la", "cat", "less", "more", "head", "tail", "echo", "pwd", "whoami", "id",
        "date", "uptime", "uname", "hostname", "env", "printenv", "which", "type", "command",
        "history", "tree", "stat", "file", "wc", "grep", "rg", "ag", "find", "fd", "locate",
        "diff", "cmp", "df", "du", "free", "ps", "top", "htop", "lsof", "netstat", "ss", "ip",
        "ifconfig", "route", "ping", "traceroute", "dig", "nslookup", "host", "curl", "wget",
        "jq", "yq", "xxd", "base64",
    ]
    .iter()
    .copied()
    .collect();
    if safe_set.contains(head) {
        return Some(RiskAssessment::safe("safe.readonly"));
    }
    if head == "git" {
        match first_subcommand(args) {
            Some(
                "status" | "log" | "diff" | "show" | "branch" | "tag" | "blame" | "ls-files"
                | "ls-tree" | "config" | "remote" | "rev-parse" | "describe",
            ) => return Some(RiskAssessment::safe("git.read")),
            _ => {}
        }
    }
    if head == "cargo" {
        match first_subcommand(args) {
            Some("fmt" | "check" | "clippy" | "build" | "test" | "tree" | "metadata" | "doc") => {
                return Some(RiskAssessment::safe("cargo.read"))
            }
            _ => {}
        }
    }
    if head == "npm" || head == "pnpm" || head == "yarn" {
        match first_subcommand(args) {
            Some("test" | "run" | "list" | "ls" | "outdated" | "audit") => {
                return Some(RiskAssessment::safe("npm.read"))
            }
            _ => {}
        }
    }
    if head == "kubectl" {
        match first_subcommand(args) {
            Some("get" | "describe" | "logs" | "config" | "version" | "explain") => {
                return Some(RiskAssessment::safe("kubectl.read"))
            }
            _ => {}
        }
    }
    if head == "docker" {
        match first_subcommand(args) {
            Some(
                "ps" | "images" | "logs" | "inspect" | "version" | "info" | "diff" | "history",
            ) => return Some(RiskAssessment::safe("docker.read")),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lvl(cmd: &str) -> RiskLevel {
        classify(cmd).level
    }

    #[test]
    fn empty_command_is_unknown() {
        assert_eq!(lvl(""), RiskLevel::Unknown);
        assert_eq!(lvl("   "), RiskLevel::Unknown);
    }

    #[test]
    fn safe_readonly_commands() {
        for cmd in [
            "ls -la",
            "cat README.md",
            "grep foo bar.txt",
            "git status",
            "git log --oneline",
            "cargo build",
            "cargo check",
            "kubectl get pods",
            "docker ps",
            "/usr/bin/ls /tmp",
        ] {
            assert_eq!(lvl(cmd), RiskLevel::Safe, "expected Safe for '{cmd}'");
        }
    }

    #[test]
    fn dangerous_rm_rf() {
        assert_eq!(lvl("rm -rf /tmp/foo"), RiskLevel::Dangerous);
        assert_eq!(lvl("rm -fr /tmp/foo"), RiskLevel::Dangerous);
        assert_eq!(lvl("rm -r -f x"), RiskLevel::Dangerous);
    }

    #[test]
    fn dangerous_git_force_push() {
        assert_eq!(lvl("git push --force"), RiskLevel::Dangerous);
        assert_eq!(lvl("git push -f origin main"), RiskLevel::Dangerous);
        assert_eq!(
            lvl("git push --force-with-lease origin main"),
            RiskLevel::Dangerous
        );
        // 일반 push는 NeedsConfirm.
        assert_eq!(lvl("git push origin main"), RiskLevel::NeedsConfirm);
    }

    #[test]
    fn dangerous_kubectl_delete_and_terraform() {
        assert_eq!(lvl("kubectl delete pod foo"), RiskLevel::Dangerous);
        assert_eq!(lvl("kubectl apply --prune -f ."), RiskLevel::Dangerous);
        assert_eq!(lvl("terraform apply -auto-approve"), RiskLevel::Dangerous);
        assert_eq!(lvl("terraform destroy"), RiskLevel::Dangerous);
    }

    #[test]
    fn dangerous_publish_dd_mkfs_power() {
        assert_eq!(lvl("npm publish"), RiskLevel::Dangerous);
        assert_eq!(lvl("dd if=/dev/zero of=/dev/sda"), RiskLevel::Dangerous);
        assert_eq!(lvl("mkfs.ext4 /dev/sdb1"), RiskLevel::Dangerous);
        assert_eq!(lvl("shutdown -h now"), RiskLevel::Dangerous);
    }

    #[test]
    fn needs_confirm_mutations() {
        assert_eq!(lvl("npm install"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("cargo update -p foo"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("git commit -m 'msg'"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("docker run -it ubuntu"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("mv a b"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("rm tmpfile"), RiskLevel::NeedsConfirm);
    }

    #[test]
    fn pipeline_takes_max_risk() {
        // git status (Safe) | grep foo (Safe) → Safe.
        assert_eq!(lvl("git status | grep foo"), RiskLevel::Safe);
        // ls (Safe) && rm -rf x (Dangerous) → Dangerous.
        assert_eq!(lvl("ls && rm -rf /tmp/x"), RiskLevel::Dangerous);
        // npm install (NeedsConfirm) ; npm test (Safe) → NeedsConfirm.
        assert_eq!(lvl("npm install ; npm test"), RiskLevel::NeedsConfirm);
    }

    #[test]
    fn subshell_is_unknown() {
        assert_eq!(lvl("echo $(rm -rf /tmp/x)"), RiskLevel::Unknown);
        assert_eq!(lvl("echo `rm -rf /tmp/x`"), RiskLevel::Unknown);
    }

    #[test]
    fn redirect_to_system_path_is_dangerous() {
        assert_eq!(
            lvl("echo broken > /etc/passwd"),
            RiskLevel::Dangerous
        );
        assert_eq!(
            lvl("cat src.txt >> /dev/sda"),
            RiskLevel::Dangerous
        );
        // 사용자 디렉토리로의 redirect는 Safe (echo가 safe head).
        assert_eq!(lvl("echo hello > /tmp/out.txt"), RiskLevel::Safe);
    }

    #[test]
    fn unknown_for_unrecognized_command() {
        assert_eq!(lvl("some_obscure_tool --do-things"), RiskLevel::Unknown);
    }

    #[test]
    fn env_prefix_is_skipped() {
        // FOO=bar git status → safe
        assert_eq!(lvl("FOO=bar git status"), RiskLevel::Safe);
        // PATH=/x:/y rm -rf /tmp/foo → Dangerous
        assert_eq!(lvl("PATH=/x:/y rm -rf /tmp/foo"), RiskLevel::Dangerous);
    }

    #[test]
    fn quoted_separators_do_not_split() {
        // Inside quotes the ; should not be treated as separator.
        // echo (safe) with quoted argument containing ;.
        assert_eq!(lvl("echo 'a;b'"), RiskLevel::Safe);
    }

    #[test]
    fn allows_auto_confirm_only_for_safe() {
        assert!(RiskLevel::Safe.allows_auto_confirm());
        assert!(!RiskLevel::NeedsConfirm.allows_auto_confirm());
        assert!(!RiskLevel::Dangerous.allows_auto_confirm());
        assert!(!RiskLevel::Unknown.allows_auto_confirm());
    }

    #[test]
    fn extra_dangerous_denylist_overrides() {
        // 기본은 Safe (cargo build).
        assert_eq!(lvl("cargo build"), RiskLevel::Safe);
        let extras = vec!["cargo build".to_string()];
        let asm = classify_with_extra_denylist("cargo build --release", &extras);
        assert_eq!(asm.level, RiskLevel::Dangerous);
        assert_eq!(asm.rule, Some("config.dangerous"));
    }

    #[test]
    fn risk_level_max_picks_higher() {
        assert_eq!(
            RiskLevel::Safe.max(RiskLevel::NeedsConfirm),
            RiskLevel::NeedsConfirm
        );
        assert_eq!(
            RiskLevel::NeedsConfirm.max(RiskLevel::Dangerous),
            RiskLevel::Dangerous
        );
        assert_eq!(
            RiskLevel::Unknown.max(RiskLevel::Dangerous),
            RiskLevel::Dangerous
        );
        assert_eq!(
            RiskLevel::Unknown.max(RiskLevel::NeedsConfirm),
            RiskLevel::Unknown
        );
    }

    #[test]
    fn unbalanced_quote_returns_unknown() {
        assert_eq!(lvl("echo 'unterminated"), RiskLevel::Unknown);
    }
}
