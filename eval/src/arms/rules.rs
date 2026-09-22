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
pub const RULES_VERSION: &str = "v3";

/// 순서는 현행 분기와 같다. 동점일 때 현행과 같은 답을 내기 위함이다.
const TABLE: &[Keywords] = &[
    Keywords {
        category: "k8s",
        subjects: &[
            "k8s", "kubernetes", "kubectl", "kube", "쿠버", "pod", "파드", "namespace",
            "네임스페이스", "노드", "node", "hpa", "replica", "레플리카", "resourcequota",
            "quota", "쿼터", "deployment", "디플로이", "ingress", "kubelet", "cluster",
            "클러스터", "taint", "evict", "rollout", "롤아웃", "failedscheduling",
        ],
        modifiers: &["crashloop", "oomkilled", "imagepull", "pending", "notready"],
    },
    Keywords {
        category: "docker",
        subjects: &[
            "docker", "도커", "container", "컨테이너", "이미지", "image", "dangling",
            "compose", "dockerd", "healthcheck", "헬스체크", "layer", "레이어", "overlay",
            "prune",
        ],
        modifiers: &[],
    },
    Keywords {
        category: "cpu",
        subjects: &[
            "cpu", "load", "부하", "코어", "core", "클럭", "clock", "주파수", "frequency",
            "throttl", "온도", "thermal", "발열", "iowait",
        ],
        // 사용률·스레드·포화는 대상이 아니라 측정값이다. 대상으로 올리면 "df에서 사용률이 95%"가
        // cpu로 끌려간다 — df가 disk 대상인데 동점에서 cpu가 앞서기 때문이다.
        modifiers: &[
            "느림", "느려", "slow", "hang", "행", "busy", "높", "high", "포화", "saturate",
            "사용률", "utilization", "스레드", "thread", "컨텍스트", "context",
        ],
    },
    Keywords {
        category: "memory",
        subjects: &[
            "memory", "mem", "메모리", "swap", "스왑", "ram", "oom", "rss", "heap", "힙",
            "tmpfs", "available", "폴트", "fault",
        ],
        modifiers: &["leak", "누수", "부족", "exhaust", "소진", "회수", "reclaim"],
    },
    Keywords {
        category: "disk",
        subjects: &[
            "disk", "디스크", "storage", "스토리지", "inode", "공간", "space", "volume",
            "볼륨", "df", "du", "파일시스템", "filesystem", "용량", "capacity", "mount",
            "마운트", "partition", "파티션", "/tmp", "/var", "블록", "iops", "snapshot",
            "스냅샷", "디렉터리", "directory", "저널", "journal", "덤프", "dump",
        ],
        modifiers: &["full", "가득", "readonly", "읽기", "쓰기", "write"],
    },
    Keywords {
        category: "network",
        subjects: &[
            "network", "net", "네트워크", "port", "포트", "dns", "socket", "소켓", "연결",
            "connection", "패킷", "packet", "ss", "netstat", "syn", "tcp", "udp", "http",
            "gateway", "게이트웨이", "라우팅", "routing", "경로", "route", "인터페이스",
            "interface", "mtu", "conntrack", "방화벽", "firewall", "curl", "ping",
            "nslookup", "resolver", "리졸버", "backlog", "time_wait", "close_wait",
            "keepalive", "업스트림", "upstream", "도메인", "domain", "인바운드", "inbound",
            "트래픽", "traffic",
        ],
        modifiers: &[
            "latency", "지연", "timeout", "타임아웃", "끊", "리셋", "reset", "거부",
            "refuse", "손실", "loss",
        ],
    },
    Keywords {
        category: "process",
        subjects: &[
            "process", "proc", "프로세스", "service", "서비스", "zombie", "좀비", "daemon",
            "데몬", "디스크립터", "descriptor", "fd", "pid", "systemd", "systemctl",
            "launchd", "unit", "유닛", "워커", "worker", "defunct", "nginx", "핸들",
            "handle", "데드락", "deadlock", "권한", "permission", "executable",
            "activating",
        ],
        modifiers: &[
            "crash", "죽", "down", "응답", "respond", "restart", "재시작", "사라", "failed",
            "회수", "reap",
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

/// 개선 규칙의 결과를 Jev의 Choice와 같은 모양으로 만든다.
///
/// 2차 라운드에서 유일하게 유의했던 우위는 `jev-adaptive`였고, 그것은 확률 분포로 2등까지
/// 조사하는 **전략**의 효과였다(단일 선택 Jev는 규칙과 동등했다). 규칙도 범주별 점수를
/// 계산하므로 같은 전략을 쓸 수 있다 — 모델 호출 없이 같은 이득이 나오는지 보기 위함이다.
///
/// `confidence`는 `1등 / (1등 + 2등)`이다. 2등이 붙어 있을수록 낮아져 "판단이 갈린다"를
/// 나타낸다. Jev의 분산 기반 confidence와 값의 의미는 다르지만 방향은 같다.
pub fn improved_outcome(symptom: &str) -> crate::arms::ArmOutcome {
    let scores = scored(symptom);
    let total: i32 = scores.iter().map(|(_, s)| *s).sum();
    let probabilities: std::collections::BTreeMap<String, f64> = if total > 0 {
        scores
            .iter()
            .map(|(cat, s)| ((*cat).to_string(), *s as f64 / total as f64))
            .collect()
    } else {
        // 아무 키워드도 안 맞았다 = generic 하나만 후보다.
        std::collections::BTreeMap::from([("generic".to_string(), 1.0)])
    };
    let top = scores.first().map_or(0, |(_, s)| *s);
    let second = scores.get(1).map_or(0, |(_, s)| *s);
    let confidence = if top == 0 {
        1.0
    } else {
        top as f64 / (top + second) as f64
    };
    crate::arms::ArmOutcome {
        category: Some(scores.first().map_or("generic", |(c, _)| *c).to_string()),
        raw_category: None,
        confidence: Some(confidence),
        probabilities: Some(probabilities),
        attempts: 1,
        ..Default::default()
    }
}

/// 점수가 0보다 큰 범주를 내림차순으로. 동점은 [`TABLE`] 순서를 지킨다.
fn scored(symptom: &str) -> Vec<(&'static str, i32)> {
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
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

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

#[cfg(test)]
mod outcome_tests {
    use super::*;

    #[test]
    fn a_clear_symptom_gets_high_confidence() {
        let o = improved_outcome("메모리 누수가 의심됩니다");
        assert_eq!(o.category.as_deref(), Some("memory"));
        assert!(o.confidence.unwrap() > 0.9, "{:?}", o.confidence);
    }

    #[test]
    fn a_split_judgement_gets_low_confidence() {
        // 대상 둘이 같은 점수면 판단이 갈린 것이다. 이때 2등까지 조사할 근거가 된다.
        let o = improved_outcome("pod 네트워크 문제");
        assert_eq!(o.category.as_deref(), Some("k8s"));
        let c = o.confidence.unwrap();
        assert!((c - 0.5).abs() < 0.01, "동점이면 0.5여야 한다: {c}");
    }

    #[test]
    fn an_unmatched_symptom_reports_generic_with_full_confidence() {
        // 후보가 하나뿐이면 갈릴 것이 없다 — 넓혀도 얻는 게 없으므로 확장하지 않는다.
        let o = improved_outcome("뭔가 이상합니다");
        assert_eq!(o.category.as_deref(), Some("generic"));
        assert_eq!(o.confidence, Some(1.0));
    }

    #[test]
    fn the_outcome_category_matches_the_plain_rule() {
        for symptom in [
            "네트워크가 느려요",
            "메모리 사용량이 높아",
            "pod CrashLoopBackOff",
            "df에서 사용률이 95%로 나옵니다",
            "스레드 하나가 데드락으로 보입니다",
        ] {
            assert_eq!(
                improved_outcome(symptom).category.as_deref(),
                Some(improved(symptom)),
                "증상: {symptom}"
            );
        }
    }

    #[test]
    fn probabilities_rank_the_same_way_as_scores() {
        let o = improved_outcome("컨테이너 하나가 CPU를 다 쓰고 있습니다");
        let probs = o.probabilities.unwrap();
        let top = o.category.unwrap();
        let best = probs
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .unwrap();
        assert_eq!(*best.0, top);
    }
}
