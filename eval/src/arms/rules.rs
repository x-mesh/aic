//! 규칙 기반 두 비교군.
//!
//! `current`는 운영 코드를 그대로 부른다. `improved`는 여기서만 산다 — 평가 결과가 채택으로
//! 이어지면 그때 운영에 옮긴다(PRD 범위 밖).

use aic_client::agent::diagnose::diagnose_category;

/// 현행 규칙. 운영 코드를 그대로 호출한다.
pub fn current(symptom: &str) -> &'static str {
    diagnose_category(Some(symptom))
}

/// 범주별 키워드. 대상 명사와 증상 수식어를 나눈다.
///
/// 현행 규칙이 무너지는 자리가 바로 이 구분이 없어서다. "네트워크가 느려요"에서 `네트워크`는
/// **무엇이** 문제인지를, `느려`는 **어떻게** 문제인지를 말한다. 첫 일치로 고르면 분기 순서가
/// 앞선 쪽이 이기므로 수식어가 대상을 밀어낸다.
struct Keywords {
    category: &'static str,
    /// 무엇이 문제인지 — 대상.
    subjects: &'static [&'static str],
    /// 어떻게 문제인지 — 증상 표현. 여러 대상에 공통으로 붙는다.
    modifiers: &'static [&'static str],
}

/// 규칙 버전. 어휘나 점수를 고치면 올린다. 원시 결과에 버전이 없으면 어느 규칙으로 얻은
/// 수치인지 나중에 가릴 수 없다.
pub const RULES_VERSION: &str = "v2";

/// 순서는 현행 분기와 같다. 동점일 때 현행과 같은 답을 내기 위함이다.
const TABLE: &[Keywords] = &[
    Keywords {
        category: "k8s",
        subjects: &[
            "k8s",
            "kubernetes",
            "kubectl",
            "kube",
            "쿠버",
            "pod",
            "파드",
            "namespace",
            "네임스페이스",
            "노드",
            "node",
            "hpa",
            "replica",
            "레플리카",
            "resourcequota",
            "quota",
            "쿼터",
            "deployment",
            "디플로이",
            "ingress",
            "kubelet",
            "cluster",
            "클러스터",
            "taint",
            "evict",
        ],
        modifiers: &["crashloop", "oomkilled", "imagepull", "pending", "notready"],
    },
    Keywords {
        category: "docker",
        subjects: &[
            "docker",
            "도커",
            "container",
            "컨테이너",
            "이미지",
            "image",
            "dangling",
            "compose",
            "dockerd",
        ],
        modifiers: &[],
    },
    Keywords {
        category: "cpu",
        subjects: &[
            "cpu",
            "load",
            "부하",
            "코어",
            "core",
            "스레드",
            "thread",
            "클럭",
            "clock",
            "주파수",
            "frequency",
            "throttl",
            "온도",
            "thermal",
            "발열",
            "iowait",
        ],
        modifiers: &[
            "느림", "느려", "slow", "hang", "행", "busy", "높", "high", "포화",
        ],
    },
    Keywords {
        category: "memory",
        subjects: &[
            "memory",
            "mem",
            "메모리",
            "swap",
            "스왑",
            "ram",
            "oom",
            "rss",
            "heap",
            "힙",
        ],
        modifiers: &["leak", "누수", "부족", "exhaust", "소진"],
    },
    Keywords {
        category: "disk",
        subjects: &[
            "disk",
            "디스크",
            "storage",
            "스토리지",
            "inode",
            "공간",
            "space",
            "volume",
            "볼륨",
            "df",
            "파일시스템",
            "filesystem",
            "용량",
            "capacity",
            "mount",
            "마운트",
            "partition",
            "파티션",
            "/tmp",
            "/var",
            "블록",
            "iops",
        ],
        modifiers: &["full", "가득", "readonly", "읽기"],
    },
    Keywords {
        category: "network",
        subjects: &[
            "network",
            "net",
            "네트워크",
            "port",
            "포트",
            "dns",
            "socket",
            "소켓",
            "연결",
            "connection",
            "패킷",
            "packet",
            "ss",
            "netstat",
            "syn",
            "tcp",
            "udp",
            "http",
            "gateway",
            "게이트웨이",
            "라우팅",
            "routing",
            "인터페이스",
            "interface",
            "mtu",
            "conntrack",
            "방화벽",
            "firewall",
            "curl",
            "ping",
            "nslookup",
            "resolver",
            "리졸버",
            "backlog",
            "time_wait",
        ],
        modifiers: &["latency", "지연", "timeout", "타임아웃", "끊"],
    },
    Keywords {
        category: "process",
        subjects: &[
            "process",
            "proc",
            "프로세스",
            "service",
            "서비스",
            "zombie",
            "좀비",
            "daemon",
            "데몬",
            "디스크립터",
            "descriptor",
            "fd",
            "pid",
            "systemd",
            "systemctl",
            "launchd",
            "unit",
            "유닛",
            "워커",
            "worker",
            "defunct",
            "nginx",
        ],
        modifiers: &[
            "crash",
            "죽",
            "down",
            "응답",
            "respond",
            "restart",
            "재시작",
            "사라",
            "failed",
        ],
    },
];

/// 대상이 맞았을 때 점수. 수식어보다 크게 둬 대상이 이기게 한다.
const SUBJECT_TOKEN: i32 = 6;
/// 붙여 쓴 표현을 놓치지 않기 위한 폴백. 어절 경계로 못 잡으면 여기로 떨어진다.
const SUBJECT_SUBSTRING: i32 = 4;
const MODIFIER_TOKEN: i32 = 2;
// 수식어에는 substring 폴백을 두지 않는다. `행`·`높`처럼 한두 글자라, 포함 검사로 열면
// "실행"·"높이" 같은 무관한 말이 범주를 정해 버린다. 대상 키워드는 길어 그 위험이 작다.

/// 이 말이 앞선 대상을 **무효화**한다. "CPU는 정상인데 서비스가 안 뜬다"에서 cpu를 빼기 위함이다.
///
/// `없`이나 `no`는 넣지 않는다. "메모리가 없다", "no space left"는 부정이 아니라 증상이다.
const NEGATIONS: &[&str] = &[
    "정상",
    "문제없",
    "이상없",
    "괜찮",
    "normal",
    "fine",
    "healthy",
    "ok",
    "okay",
];

/// 부정어가 대상을 무효화하는 거리(어절 단위). "CPU는 정상" 같은 바로 뒤 수식을 잡되,
/// 문장을 건너뛰어 엉뚱한 대상을 지우지 않을 만큼 좁게 둔다.
const NEGATION_WINDOW: usize = 2;

/// 개선 규칙. 대상과 수식어를 나눠 점수를 합산하고 최고점을 고른다.
pub fn improved(symptom: &str) -> &'static str {
    let lower = symptom.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.is_empty() {
        return "generic";
    }

    let mut best: Option<(&'static str, i32)> = None;
    for kw in TABLE {
        let score = score_category(kw, &lower, &tokens);
        if score <= 0 {
            continue;
        }
        // 동점이면 먼저 나온 범주가 이긴다 — 현행 분기 순서와 같은 규칙이다.
        if best.is_none_or(|(_, b)| score > b) {
            best = Some((kw.category, score));
        }
    }
    best.map_or("generic", |(cat, _)| cat)
}

fn score_category(kw: &Keywords, lower: &str, tokens: &[&str]) -> i32 {
    let mut score = 0;
    if let Some(idx) = first_token_match(tokens, kw.subjects) {
        if negated_after(tokens, idx) {
            // 대상이 정상이라고 말했으니 이 범주는 후보가 아니다. 수식어 점수도 주지 않는다 —
            // "CPU는 정상인데 느리다"에서 느림은 다른 대상의 증상이다.
            return 0;
        }
        score += SUBJECT_TOKEN;
    } else if kw.subjects.iter().any(|s| lower.contains(s)) {
        score += SUBJECT_SUBSTRING;
    }
    if first_token_match(tokens, kw.modifiers).is_some() {
        score += MODIFIER_TOKEN;
    }
    score
}

/// 어절이 키워드로 **시작**하면 일치로 본다. 한국어 조사("네트워크가")를 흡수하면서도,
/// "실행"이 `행`에 걸리는 substring 오탐은 막는다.
fn first_token_match(tokens: &[&str], keywords: &[&str]) -> Option<usize> {
    tokens.iter().position(|t| {
        let cleaned = t.trim_matches(|c: char| !c.is_alphanumeric());
        keywords.iter().any(|k| cleaned.starts_with(k))
    })
}

fn negated_after(tokens: &[&str], idx: usize) -> bool {
    let end = (idx + NEGATION_WINDOW).min(tokens.len().saturating_sub(1));
    tokens[idx..=end]
        .iter()
        .skip(1)
        .any(|t| NEGATIONS.iter().any(|n| t.starts_with(n)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_client::agent::diagnose::DIAGNOSE_CATEGORIES;

    #[test]
    fn improved_prefers_the_subject_over_the_modifier() {
        // 현행이 무너지는 자리. 대상이 수식어를 이겨야 한다.
        assert_eq!(improved("네트워크가 느려요"), "network");
        assert_eq!(improved("the network is slow"), "network");
        assert_eq!(improved("메모리 사용량이 높아"), "memory");
        assert_eq!(improved("디스크가 느려요"), "disk");
    }

    #[test]
    fn current_still_answers_cpu_for_those() {
        // baseline이 실제로 다르다는 것을 여기서 고정한다. 같아지면 비교 자체가 무의미하다.
        assert_eq!(current("네트워크가 느려요"), "cpu");
        assert_eq!(current("메모리 사용량이 높아"), "cpu");
    }

    #[test]
    fn improved_keeps_single_symptom_answers() {
        // 개선이 쉬운 사례를 망가뜨리면 순이득이 없다.
        assert_eq!(improved("cpu 높음"), "cpu");
        assert_eq!(improved("메모리 누수"), "memory");
        assert_eq!(improved("디스크 공간 부족"), "disk");
        assert_eq!(improved("포트 연결 안 됨"), "network");
        assert_eq!(improved("프로세스가 죽음"), "process");
        assert_eq!(improved("docker 컨테이너 문제"), "docker");
        assert_eq!(improved("pod CrashLoopBackOff"), "k8s");
    }

    #[test]
    fn a_negated_subject_does_not_win() {
        assert_eq!(
            improved("CPU는 정상인데 서비스가 응답하지 않는다"),
            "process"
        );
        assert_eq!(improved("cpu is normal but the service is down"), "process");
    }

    #[test]
    fn ties_follow_the_current_branch_order() {
        // 대상 둘이 같은 점수면 현행과 같은 답을 낸다. 근거 없이 갈라지지 않게 한다.
        assert_eq!(improved("pod 네트워크 문제"), "k8s");
        assert_eq!(current("pod 네트워크 문제"), "k8s");
    }

    #[test]
    fn an_unmatched_symptom_falls_back_to_generic() {
        assert_eq!(improved("뭔가 이상합니다"), "generic");
        assert_eq!(improved(""), "generic");
    }

    #[test]
    fn token_start_matching_avoids_substring_traps() {
        // 현행은 "실행"의 `행`을 cpu로 읽는다. 어절 시작 일치는 그러지 않는다.
        assert_eq!(improved("배치 실행 결과를 모르겠다"), "generic");
        // 붙여 쓴 대상은 여전히 잡는다 — 대상 키워드는 길어 substring이 안전하다.
        assert_eq!(improved("네트워크느림"), "network");
    }

    #[test]
    fn both_rules_only_return_known_categories() {
        for symptom in [
            "네트워크가 느려요",
            "뭔가 이상합니다",
            "pod 네트워크 문제",
            "",
        ] {
            assert!(
                DIAGNOSE_CATEGORIES.contains(&current(symptom)),
                "current: {symptom}"
            );
            assert!(
                DIAGNOSE_CATEGORIES.contains(&improved(symptom)),
                "improved: {symptom}"
            );
        }
    }
}
