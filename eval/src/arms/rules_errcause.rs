//! 규칙 비교군 — 키워드로 원인 범주를 고른다.
//!
//! **개발 분할(105건)의 출력만 보고 썼다.** 최종 분할은 이 파일을 쓰는 동안 한 번도 읽지 않았다.
//! 2라운드에서 규칙 어휘를 시험 집합에 맞춰 넓힌 뒤 "규칙이 모델을 따라잡았다"고 결론 낸 것이
//! 과적합이었을 수 있어, 이번에는 규칙을 쓰는 데이터와 재는 데이터를 분리한다.
//!
//! 순서가 곧 우선순위다. 위쪽이 더 구체적인 신호이고, 아래로 갈수록 넓다 — 예를 들어 TLS 실패
//! 출력에는 `certificate`와 함께 `error`도 들어 있으므로 TLS를 먼저 본다.

/// `(범주, 이 범주를 가리키는 소문자 키워드)`. 앞에서부터 처음 걸리는 범주를 고른다.
const TABLE: &[(&str, &[&str])] = &[
    // TLS는 네트워크 실패의 하위처럼 보이지만 조치가 다르다(인증서 교체 대 연결 확인).
    (
        "tls",
        &[
            "ssl certificate problem",
            "certificate has expired",
            "self signed certificate",
            "unable to get local issuer",
            "certificate verify failed",
            "no alternative certificate subject",
            "certificate is not trusted",
        ],
    ),
    (
        "auth",
        &[
            "returned error: 401",
            "returned error: 403",
            "returned error: 407",
            "unauthorized",
            "forbidden",
            "authentication required",
            "authentication failed",
            "could not read username",
            "access denied",
            "docker login",
            "bad credentials",
        ],
    ),
    (
        "remote_error",
        &[
            "returned error: 500",
            "returned error: 502",
            "returned error: 503",
            "returned error: 504",
            "returned error: 429",
            "internal server error",
            "bad gateway",
            "service unavailable",
            "too many requests",
            "rate limit",
        ],
    ),
    (
        "resource",
        &[
            "too many open files",
            "cannot allocate memory",
            "memoryerror",
            "file size limit exceeded",
            "filesize limit exceeded",
            "no space left on device",
            "quota exceeded",
            "resource temporarily unavailable",
        ],
    ),
    (
        "dependency",
        &[
            "modulenotfounderror",
            "no module named",
            "cannot find module",
            "importerror",
        ],
    ),
    (
        "network",
        &[
            "could not resolve",
            "cannot resolve",
            "couldn't connect",
            "connection refused",
            "failed to connect",
            "connection timed out",
            "network is unreachable",
            "no route to host",
            "nodename nor servname",
            "unknown host",
            "name or service not known",
            "server api group list",
        ],
    ),
    (
        "state",
        &[
            "not a git repository",
            "저장소가 아닙니다",
            "no rebase in progress",
            "no cherry-pick or revert in progress",
            "no merge to abort",
            "no bisect in progress",
            "스태시 항목이 없습니다",
            "no stash entries",
            "no configured push destination",
            "추적 정보가 없습니다",
            "there is no tracking information",
            "current-context is not set",
            "file exists",
            "already exists",
            "used by worktree",
        ],
    ),
    (
        "not_found",
        &[
            "no such file or directory",
            "no such container",
            "no such object",
            "no such volume",
            "not found",
            "없습니다",
            "did not match any",
            "bad object",
            "bad revision",
            "unknown revision",
            "no rule to make target",
            "does not exist",
            "아닙니다",
            "no available formula",
            "could not find a version",
            "not found in workspace",
        ],
    ),
    (
        "usage",
        &[
            "usage:",
            "unrecognized option",
            "unknown flag",
            "unknown option",
            "invalid option",
            "unknown primary or operator",
            "option requires an argument",
            "requires at least",
            "must specify one of",
            "try 'curl --help'",
            "no objects passed",
            "no valid patches in input",
            "contains this feature",
            "not supported",
        ],
    ),
    (
        "malformed_input",
        &[
            "parse error",
            "syntaxerror",
            "syntax error",
            "문법 오류",
            "unrecognized archive format",
            "not a zipfile",
            "end-of-central-directory",
            "unexpected character",
            "mismatched types",
            "error[e",
            "expected property name",
            "not in gzip format",
        ],
    ),
];

/// 어느 키워드에도 걸리지 않을 때. 가장 흔한 범주를 찍는 것이 아니라 "모름"을 드러낸다 —
/// 찍으면 정확도가 올라가 보이지만 운영에서 틀린 조치를 권하게 된다.
pub const UNKNOWN: &str = "unknown";
pub const RULES_VERSION: &str = "errcause-rules-v1";

/// 명령·종료 코드·출력에서 원인 범주 하나를 고른다. 순수 함수.
pub fn classify(input: &str) -> &'static str {
    let low = input.to_lowercase();
    for (category, keywords) in TABLE {
        if keywords.iter().any(|k| low.contains(k)) {
            return category;
        }
    }
    UNKNOWN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_wins_over_the_generic_network_wording() {
        // 인증서 실패 출력에도 연결 관련 낱말이 섞여 있어 순서가 뒤집히면 network로 샌다.
        let s = "$ curl https://x\nexit_code=60\n--- output ---\ncurl: (60) SSL certificate problem: certificate has expired";
        assert_eq!(classify(s), "tls");
    }

    #[test]
    fn a_korean_git_message_is_recognised() {
        // 같은 실패가 로케일에 따라 다른 문자열로 나온다. 규칙은 로케일마다 어휘를 따로 넣어야 한다.
        let s = "$ git status\nexit_code=128\n--- output ---\nfatal: (현재 폴더 또는 상위 폴더 중 일부가) 깃 저장소가 아닙니다: .git";
        assert_eq!(classify(s), "state");
    }

    #[test]
    fn nothing_matched_is_reported_as_unknown() {
        let s = "$ weird\nexit_code=3\n--- output ---\nsomething entirely unfamiliar happened";
        assert_eq!(classify(s), UNKNOWN);
    }
}
