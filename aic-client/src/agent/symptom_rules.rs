//! 증상 문자열에서 진단 범주를 고르는 규칙.
//!
//! 이전 구현은 키워드를 부분 문자열로 훑어 **첫 일치**를 택했다. 그래서 분기 순서가 앞선 범주가
//! 이기고, 증상을 수식하는 말이 대상을 밀어냈다 — `"네트워크가 느려요"`는 cpu 분기의 `"느려"`에
//! 먼저 걸려 network probe를 하나도 고르지 않았다.
//!
//! 여기서는 키워드를 **대상**(무엇이 문제인가)과 **수식어**(어떻게 문제인가)로 나누고 대상에 더
//! 큰 점수를 준다. 여러 범주가 맞으면 점수 합이 가장 높은 쪽을 택하고, 동점이면 [`TABLE`] 순서를
//! 지킨다.
//!
//! 이 설계와 어휘는 네 가지 판정 방식을 비교한 검증에서 나왔다. 규칙이 Jev와 LLM과 구별되지
//! 않는다는 결론의 근거는 `docs/PROBE-SELECTION-EVALUATION.md`에 있다.

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
            "rollout",
            "롤아웃",
            "failedscheduling",
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
            "healthcheck",
            "헬스체크",
            "layer",
            "레이어",
            "overlay",
            "prune",
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
        // 사용률·스레드·포화는 대상이 아니라 측정값이다. 대상으로 올리면 "df에서 사용률이 95%"가
        // cpu로 끌려간다 — df가 disk 대상인데 동점에서 cpu가 앞서기 때문이다.
        modifiers: &[
            "느림",
            "느려",
            "slow",
            "hang",
            "행",
            "busy",
            "높",
            "high",
            "포화",
            "saturate",
            "사용률",
            "utilization",
            "스레드",
            "thread",
            "컨텍스트",
            "context",
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
            "tmpfs",
            "available",
            "폴트",
            "fault",
        ],
        modifiers: &["leak", "누수", "부족", "exhaust", "소진", "회수", "reclaim"],
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
            "du",
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
            "snapshot",
            "스냅샷",
            "디렉터리",
            "directory",
            "저널",
            "journal",
            "덤프",
            "dump",
        ],
        modifiers: &["full", "가득", "readonly", "읽기", "쓰기", "write"],
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
            "경로",
            "route",
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
            "close_wait",
            "keepalive",
            "업스트림",
            "upstream",
            "도메인",
            "domain",
            "인바운드",
            "inbound",
            "트래픽",
            "traffic",
        ],
        modifiers: &[
            "latency",
            "지연",
            "timeout",
            "타임아웃",
            "끊",
            "리셋",
            "reset",
            "거부",
            "refuse",
            "손실",
            "loss",
        ],
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
            "핸들",
            "handle",
            "데드락",
            "deadlock",
            "권한",
            "permission",
            "executable",
            "activating",
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
            "회수",
            "reap",
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

/// 부정어가 대상을 무효화하는 거리(어절 단위). "CPU와 디스크는 정상인데"처럼 대상 둘을
/// 한꺼번에 부정하는 문장이 있어 앞쪽 대상에서도 부정어에 닿아야 한다. 문장 전체로 넓히면
/// 뒤 절의 부정이 앞 절의 대상을 지운다.
const NEGATION_WINDOW: usize = 3;

/// 점수가 0보다 큰 범주를 내림차순으로. 동점은 [`TABLE`] 순서를 지킨다.
pub fn scored(symptom: &str) -> Vec<(&'static str, i32)> {
    let lower = symptom.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<(&'static str, i32)> = TABLE
        .iter()
        .filter_map(|kw| {
            let s = score_category(kw, &lower, &tokens);
            (s > 0).then_some((kw.category, s))
        })
        .collect();
    // 안정 정렬이라 동점에서 TABLE 순서가 유지된다.
    out.sort_by_key(|(_, score)| std::cmp::Reverse(*score));
    out
}

/// 증상에서 진단 범주를 고른다. 대상과 수식어를 나눠 점수를 합산하고 최고점을 고른다.
pub fn categorize(symptom: &str) -> &'static str {
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
