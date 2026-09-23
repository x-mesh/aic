//! 규칙 비교군 — 키워드로 채팅 입력의 처리 경로를 고른다.
//!
//! **개발 분할(107건)만 보고 썼다.** 최종 분할은 생성 모델이 만들었고 이 파일을 쓰는 동안 읽지 않았다.
//!
//! 순서가 곧 우선순위다. "방금"처럼 직전 명령을 가리키는 말이 가장 강한 신호이고, 다음이 작업 요청
//! (만들어·고쳐·설명해), 다음이 증상 호소, 마지막이 상태 조회다. 증상 낱말은 작업 요청 안에도
//! 흔히 나오므로("메모리 누수 잡는 법 알려줘") 작업 요청을 먼저 본다.

pub const RULES_VERSION: &str = "intent-rules-v1";
/// 어느 키워드에도 걸리지 않으면 기존 경로(도구 호출 루프)로 둔다. 모르는 것을 진단으로 보내면
/// 쓸데없이 probe를 돌리지만, 에이전트로 두면 지금과 같은 동작이다.
pub const FALLBACK: &str = "agent";

const TABLE: &[(&str, &[&str])] = &[
    (
        "explain_last",
        &[
            "방금",
            "위 명령",
            "위에 뜬",
            "마지막 명령",
            "마지막 실행",
            "이 에러",
            "이 출력",
            "저 에러",
            "저 permission",
            "왜 실패",
            "왜 안 돼",
            "무슨 뜻",
            "무슨 말",
            "에러 뭐",
            "뜬 거",
            "떴는데",
            "that error",
            "that command",
            "that traceback",
            "last output",
            "last command",
        ],
    ),
    (
        "agent",
        &[
            "만들어",
            "작성",
            "고쳐",
            "리팩터",
            "추가해",
            "바꿔",
            "알려줘",
            "설명해",
            "설명 ",
            "뭐야?",
            "어디 있",
            "찾아줘",
            "도와줘",
            "초안",
            "어떻게",
            "방법",
            "하는 법",
            "이어서",
            "안녕",
            "고마워",
            "write ",
            "how do i",
            "difference",
            "what's the difference",
        ],
    ),
    (
        "diagnose",
        &[
            "느려",
            "느림",
            "slow",
            "죽었",
            "죽여",
            "죽네",
            "죽어",
            "안 돼요",
            "안 돈",
            "멈춰",
            "끊겨",
            "꽉 찼",
            "재시작을 반복",
            "재시작",
            "crashloop",
            "notready",
            "oom",
            "누수",
            "timeout",
            "타임아웃",
            "에러율",
            "502",
            "503",
            "100%",
            "too many open files",
            "원인",
            "왜 그런지",
            "이유가 뭘까",
            "문제인가",
            "문제죠",
            "무슨 일",
            "드랍",
            "eating",
            "높아",
            "넘는데",
            "튀었",
            "어긋나",
        ],
    ),
    (
        "local",
        &[
            "보여줘",
            "보여 줘",
            "목록",
            "확인",
            "알려줘",
            "몇 퍼센트",
            "사용량",
            "훑어",
            "show me",
            "current",
            "snapshot",
            "뭐지",
            "얼마나",
            "구성",
            "정보",
            "상태",
            "uptime",
            "load average",
        ],
    ),
];

/// 채팅 입력 하나에서 경로를 고른다. 순수 함수.
pub fn classify(text: &str) -> &'static str {
    let low = text.to_lowercase();
    for (route, keywords) in TABLE {
        if keywords.iter().any(|k| low.contains(k)) {
            return route;
        }
    }
    FALLBACK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_request_wins_over_a_symptom_word_inside_it() {
        // 증상 낱말이 작업 요청 안에 나오는 경우가 규칙의 대표 함정이다.
        assert_eq!(classify("메모리 누수 잡는 일반적인 방법 알려줘"), "agent");
        assert_eq!(classify("디스크 정리하는 스크립트 만들어줘"), "agent");
    }

    #[test]
    fn a_reference_to_the_last_command_wins() {
        assert_eq!(classify("방금 빌드 실패한 이유"), "explain_last");
    }

    #[test]
    fn unknown_input_stays_on_the_existing_path() {
        assert_eq!(classify("흠"), FALLBACK);
    }
}
