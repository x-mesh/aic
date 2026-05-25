//! `run_command` tokenizer 화이트리스트 (RFC-005 §4.3 게이트 1·4, O3 fix).
//!
//! 멀티호스트(또는 단일) 원격 명령 검사 4단:
//!   1. shell 메타문자(`; & | $() <> \` ` redirect) 차단.
//!   2. program이 **builtin allowlist**(ps/df/free/uptime/cat/journalctl/ls/find) 또는
//!      **user whitelist**(`~/.aic/whitelist.toml`)에 있어야 통과.
//!   3. 경로 인자(절대 경로 `/...`)는 [`path_guard::check_path`]로 추가 검사 (S2/S3).
//!   4. user whitelist의 `allowed_args` 규칙(있으면) 매칭.
//!
//! RFC §4.3 R4(red-team A4): 화이트리스트가 'read-only=safe-read'를 보장하지 못함을
//! [`path_guard`]의 procfs/devfs allowlist 반전 + 경로 denylist로 보완.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent::remote::path_guard::{check_path, PathCheck};

/// 내장 허용 program — 모두 read-only 진단 명령. 추가는 user whitelist로.
pub const BUILTIN_PROGRAMS: &[&str] = &[
    "ps", "df", "free", "uptime", "cat", "journalctl", "ls", "find",
];

/// shell 메타문자 — args에 포함되면 즉시 거부(원격 셸 재해석 차단, S1 보강).
const SHELL_METACHARS: &[char] = &[
    ';', '&', '|', '$', '<', '>', '`', '\\', '\n', '\r',
];

/// user whitelist 디스크 표현.
#[derive(Debug, Default, Deserialize)]
struct WhitelistToml {
    #[serde(default, rename = "programs")]
    programs: Vec<UserProgram>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserProgram {
    name: String,
    /// (있으면) 정확한 args 시퀀스 매칭. 없으면 program 매칭만으로 통과.
    #[serde(default)]
    allowed_args: Option<Vec<Vec<String>>>,
}

/// 머지된 화이트리스트(builtin + user).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Whitelist {
    /// program 이름 → user 규칙(있을 때만; builtin은 None).
    pub programs: BTreeMap<String, Option<Vec<Vec<String>>>>,
    pub user_path: Option<PathBuf>,
}

impl Whitelist {
    /// `~/.aic/whitelist.toml`을 로드해 builtin과 머지. 파일 없으면 builtin만.
    pub fn load() -> Result<Self> {
        let home = dirs::home_dir().context("$HOME not set")?;
        let path = home.join(".aic").join("whitelist.toml");
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let mut programs: BTreeMap<String, Option<Vec<Vec<String>>>> = BTreeMap::new();
        for p in BUILTIN_PROGRAMS {
            programs.insert((*p).to_string(), None);
        }
        let mut user_path = None;
        if path.exists() {
            let s = fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            let doc: WhitelistToml = toml::from_str(&s)
                .with_context(|| format!("parse {}", path.display()))?;
            for up in doc.programs {
                programs.insert(up.name, up.allowed_args);
            }
            user_path = Some(path.to_path_buf());
        }
        Ok(Self {
            programs,
            user_path,
        })
    }

    /// `program + args`를 4단 게이트로 검사한다.
    pub fn check(&self, program: &str, args: &[String]) -> CheckResult {
        // 1) shell metachar
        for a in args {
            if let Some(c) = a.chars().find(|c| SHELL_METACHARS.contains(c)) {
                return CheckResult::Blocked {
                    reason: format!("shell metacharacter '{c}' in argument {a:?}"),
                };
            }
        }
        if let Some(c) = program.chars().find(|c| SHELL_METACHARS.contains(c)) {
            return CheckResult::Blocked {
                reason: format!("shell metacharacter '{c}' in program {program:?}"),
            };
        }

        // 2) program allowlist
        let Some(allowed_args) = self.programs.get(program) else {
            return CheckResult::Blocked {
                reason: format!("program {program:?} not in whitelist"),
            };
        };

        // 3) 경로 인자 검사 — 절대 경로(`/`)는 path_guard로 추가 검증
        for a in args {
            if a.starts_with('/') {
                if let PathCheck::Blocked { reason } = check_path(a) {
                    return CheckResult::Blocked {
                        reason: format!("path argument: {reason}"),
                    };
                }
            }
        }

        // 4) user `allowed_args` 규칙(있을 때만)
        if let Some(rules) = allowed_args {
            let arg_strs: Vec<&str> = args.iter().map(String::as_str).collect();
            let matched = rules.iter().any(|rule| args_match(rule, &arg_strs));
            if !matched {
                return CheckResult::Blocked {
                    reason: format!(
                        "args {:?} do not match any allowed_args rule for {program:?}",
                        args
                    ),
                };
            }
        }

        CheckResult::Allowed
    }
}

/// 단일 규칙(예: `["-t", "-l"]`)이 실제 args와 일치하는지. `{path}` 같은 placeholder는
/// MVP에서 미지원 — 단순 시퀀스 일치만. 사용자가 모든 변형을 명시.
fn args_match(rule: &[String], args: &[&str]) -> bool {
    if rule.len() != args.len() {
        return false;
    }
    rule.iter().zip(args.iter()).all(|(r, a)| r == a)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CheckResult {
    Allowed,
    Blocked { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn builtin_programs_pass_without_path_args() {
        let wl = Whitelist::load_from(&PathBuf::from("/nonexistent")).unwrap();
        assert_eq!(wl.check("uptime", &[]), CheckResult::Allowed);
        assert_eq!(wl.check("free", &["-m".into()]), CheckResult::Allowed);
    }

    #[test]
    fn unknown_program_blocked() {
        let wl = Whitelist::load_from(&PathBuf::from("/nonexistent")).unwrap();
        let r = wl.check("rm", &["-rf".into(), "/".into()]);
        assert!(matches!(r, CheckResult::Blocked { .. }));
    }

    #[test]
    fn shell_metachar_in_args_blocked() {
        let wl = Whitelist::load_from(&PathBuf::from("/nonexistent")).unwrap();
        for meta in &[";", "&", "|", "$", "<", ">", "`"] {
            let arg = format!("foo{meta}bar");
            let r = wl.check("ls", &[arg.clone()]);
            assert!(
                matches!(r, CheckResult::Blocked { .. }),
                "metachar '{meta}' must block"
            );
        }
    }

    #[test]
    fn path_argument_runs_path_guard() {
        let wl = Whitelist::load_from(&PathBuf::from("/nonexistent")).unwrap();
        // /etc/shadow는 path_guard에서 차단
        let r = wl.check("cat", &["/etc/shadow".into()]);
        assert!(matches!(r, CheckResult::Blocked { .. }));
        // 정상 경로는 통과
        let r = wl.check("cat", &["/etc/os-release".into()]);
        assert_eq!(r, CheckResult::Allowed);
    }

    #[test]
    fn equivalent_path_uri_blocked_via_canonicalize() {
        let wl = Whitelist::load_from(&PathBuf::from("/nonexistent")).unwrap();
        // /etc/./shadow → /etc/shadow → 차단 (path_guard 정규화)
        let r = wl.check("cat", &["/etc/./shadow".into()]);
        assert!(matches!(r, CheckResult::Blocked { .. }));
        // /proc/self/environ → 차단 (procfs allowlist 반전)
        let r = wl.check("cat", &["/proc/self/environ".into()]);
        assert!(matches!(r, CheckResult::Blocked { .. }));
        // 허용 procfs
        let r = wl.check("cat", &["/proc/loadavg".into()]);
        assert_eq!(r, CheckResult::Allowed);
    }

    #[test]
    fn user_whitelist_adds_program() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("whitelist.toml");
        std::fs::write(
            &path,
            r#"
[[programs]]
name = "ss"
"#,
        )
        .unwrap();
        let wl = Whitelist::load_from(&path).unwrap();
        assert_eq!(wl.check("ss", &["-tlnp".into()]), CheckResult::Allowed);
        assert_eq!(wl.programs.get("ss").cloned(), Some(None));
    }

    #[test]
    fn user_whitelist_with_allowed_args_strict_match() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("whitelist.toml");
        std::fs::write(
            &path,
            r#"
[[programs]]
name = "systemctl"
allowed_args = [["status", "nginx"], ["is-active", "nginx"]]
"#,
        )
        .unwrap();
        let wl = Whitelist::load_from(&path).unwrap();
        assert_eq!(
            wl.check("systemctl", &["status".into(), "nginx".into()]),
            CheckResult::Allowed
        );
        assert_eq!(
            wl.check("systemctl", &["is-active".into(), "nginx".into()]),
            CheckResult::Allowed
        );
        // 미일치 args는 거부
        assert!(matches!(
            wl.check("systemctl", &["restart".into(), "nginx".into()]),
            CheckResult::Blocked { .. }
        ));
        // 다른 unit은 거부 (placeholder MVP 미지원)
        assert!(matches!(
            wl.check("systemctl", &["status".into(), "postgres".into()]),
            CheckResult::Blocked { .. }
        ));
    }

    #[test]
    fn newline_in_arg_blocked() {
        // CRLF injection 회피
        let wl = Whitelist::load_from(&PathBuf::from("/nonexistent")).unwrap();
        let r = wl.check("ls", &["/etc\nrm".into()]);
        assert!(matches!(r, CheckResult::Blocked { .. }));
    }

    #[test]
    fn block_reason_message_helps_debugging() {
        let wl = Whitelist::load_from(&PathBuf::from("/nonexistent")).unwrap();
        match wl.check("ls", &["/etc/shadow".into()]) {
            CheckResult::Blocked { reason } => {
                assert!(reason.contains("path"), "reason={reason}");
            }
            _ => panic!("should block"),
        }
    }
}
