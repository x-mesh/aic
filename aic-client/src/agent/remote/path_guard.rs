//! 원격 명령 인자의 경로 게이트(RFC-005 §4.3 게이트 2·3, S2·S3 fix).
//!
//! 두 단계:
//!   1. **Lexical canonicalization** — `/etc/./shadow`, `/etc/../etc/shadow`, `//etc//shadow`
//!      같은 동등 경로를 같은 정규형으로 변환.
//!   2. **Allowlist 반전 + Denylist** — `/proc/`/`/dev/`/`/sys/firmware/`/`/run/secrets/`는
//!      기본 차단, probe catalog가 실제 쓰는 procfs 경로만 명시 허용. 파일명 패턴 denylist는
//!      `id_rsa`/`.pem`/`.env`/`credentials`/`shadow`/`sudoers` 등.
//!
//! 원격 symlink chain은 클라이언트에서 해소 불가 — RFC-005 §7 trust boundary로 명시. lexical만 처리한다.

/// 경로 검사 결과. 차단 시 `reason`은 audit 메시지·사용자 알림용.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PathCheck {
    Allowed,
    Blocked { reason: String },
}

/// probe catalog가 실제 사용하는 procfs 경로만 명시 허용 (allowlist 반전).
const PROCFS_ALLOWLIST: &[&str] = &[
    "/proc/loadavg",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/vmstat",
    "/proc/diskstats",
    "/proc/net/dev",
    "/proc/uptime",
    "/proc/stat",
];

/// 기본 차단 접두사. `/proc/`는 별도 allowlist 반전 로직, 그 외는 단순 prefix.
const FORBIDDEN_PREFIXES: &[&str] = &[
    "/dev/",
    "/sys/firmware/",
    "/run/secrets/",
];

/// 파일명/경로 substring 기반 secret 패턴(대소문자 무관).
const FORBIDDEN_PATTERNS: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".pem",
    ".key",
    ".env",
    "credentials",
    "shadow",      // /etc/shadow, /etc/gshadow
    "sudoers",
    ".aws/",
    ".kube/",
    "kubeconfig",
];

/// 경로 인자가 허용되는지 검사한다. 동등 경로 우회(`/etc/./shadow` 등)는 canonicalize로 차단.
pub fn check_path(path: &str) -> PathCheck {
    let canon = lexical_canonicalize(path);

    // procfs는 allowlist 반전 — 기본 차단, 명시 허용만 통과.
    if canon.starts_with("/proc/") || canon == "/proc" {
        if PROCFS_ALLOWLIST.iter().any(|p| canon == *p) {
            return PathCheck::Allowed;
        }
        return PathCheck::Blocked {
            reason: format!("procfs path not in allowlist: {canon}"),
        };
    }

    // dev/sysfs/secrets은 기본 차단.
    for prefix in FORBIDDEN_PREFIXES {
        if canon.starts_with(prefix) {
            return PathCheck::Blocked {
                reason: format!("path matches forbidden prefix {prefix}: {canon}"),
            };
        }
    }

    // 파일명 패턴 검사(대소문자 무관). best-effort — audit에 한계 경고 첨부(호출자 책임).
    let lower = canon.to_lowercase();
    for pat in FORBIDDEN_PATTERNS {
        if lower.contains(pat) {
            return PathCheck::Blocked {
                reason: format!("path matches secret pattern '{pat}': {canon}"),
            };
        }
    }

    PathCheck::Allowed
}

/// 경로의 lexical 정규화 — `/./`, `/../`, `//` 만 처리한다(원격 symlink는 해소 못함).
/// 빈 입력은 빈 문자열 반환.
pub fn lexical_canonicalize(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let leading_slash = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {} // 빈 세그먼트(중복 슬래시) + 현재 디렉토리는 스킵
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = if leading_slash {
        String::from("/")
    } else {
        String::new()
    };
    out.push_str(&parts.join("/"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_basic_cases() {
        assert_eq!(lexical_canonicalize("/etc/./shadow"), "/etc/shadow");
        assert_eq!(lexical_canonicalize("/etc/../etc/shadow"), "/etc/shadow");
        assert_eq!(lexical_canonicalize("//etc//shadow"), "/etc/shadow");
        assert_eq!(lexical_canonicalize("/a/b/../c"), "/a/c");
        assert_eq!(lexical_canonicalize("/"), "/");
        assert_eq!(lexical_canonicalize(""), "");
    }

    #[test]
    fn block_etc_shadow_via_equivalent_paths() {
        // S2 회귀: 동등 경로 우회가 모두 차단되어야 함.
        for p in &[
            "/etc/shadow",
            "/etc/./shadow",
            "/etc/../etc/shadow",
            "/etc//shadow",
            "/etc/gshadow",
        ] {
            assert!(
                matches!(check_path(p), PathCheck::Blocked { .. }),
                "{p} should be blocked"
            );
        }
    }

    #[test]
    fn block_proc_self_environ_and_pid_environ() {
        // S3 회귀: /proc/self/environ, /proc/[N]/environ, /proc/net/tcp 모두 차단.
        for p in &[
            "/proc/self/environ",
            "/proc/1/environ",
            "/proc/12345/cmdline",
            "/proc/net/tcp",
            "/proc/bus/usb",
            "/proc/sysvipc/sem",
        ] {
            assert!(
                matches!(check_path(p), PathCheck::Blocked { .. }),
                "{p} should be blocked"
            );
        }
    }

    #[test]
    fn allow_procfs_only_when_in_allowlist() {
        for p in &[
            "/proc/loadavg",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/vmstat",
            "/proc/diskstats",
            "/proc/net/dev",
            "/proc/uptime",
            "/proc/stat",
        ] {
            assert!(
                matches!(check_path(p), PathCheck::Allowed),
                "{p} should be allowed"
            );
        }
    }

    #[test]
    fn block_dev_and_sysfs() {
        for p in &[
            "/dev/urandom",
            "/dev/zero",
            "/dev/mem",
            "/dev/sda",
            "/sys/firmware/dmi",
            "/run/secrets/db_password",
        ] {
            assert!(
                matches!(check_path(p), PathCheck::Blocked { .. }),
                "{p} should be blocked"
            );
        }
    }

    #[test]
    fn block_secret_filename_patterns() {
        for p in &[
            "/home/user/.ssh/id_rsa",
            "/home/user/.ssh/id_ed25519.pub",
            "/home/user/.aws/credentials",
            "/home/user/.kube/config",
            "/home/user/.env.production",
            "/etc/secrets.pem",
            "/tmp/server.key",
        ] {
            assert!(
                matches!(check_path(p), PathCheck::Blocked { .. }),
                "{p} should be blocked"
            );
        }
    }

    #[test]
    fn allow_normal_log_and_config_paths() {
        for p in &[
            "/var/log/syslog",
            "/var/log/nginx/access.log",
            "/etc/os-release",
            "/etc/hostname",
            "/home/user/app.log",
        ] {
            assert!(
                matches!(check_path(p), PathCheck::Allowed),
                "{p} should be allowed"
            );
        }
    }

    #[test]
    fn block_reason_contains_canonical_form() {
        // 동등 경로 우회가 차단됐을 때 reason에 정규화된 경로가 들어가야 디버깅이 쉽다.
        let r = check_path("/etc/./../etc/shadow");
        match r {
            PathCheck::Blocked { reason } => {
                assert!(reason.contains("/etc/shadow"), "reason: {reason}")
            }
            _ => panic!("should be blocked"),
        }
    }
}
