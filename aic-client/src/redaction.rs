//! LLM 송신 직전 prompt redaction — secret/PII를 마스킹.
//!
//! Secret 5종: AWS access key, GitHub token, Anthropic key, OpenAI key, JWT
//! PII 4종: email, 한국 전화번호, 주민등록번호, IPv4 주소
//!
//! 단일 stage. LLM 송신 전 1회 적용. 응답에는 적용 X.
//! Anthropic key를 OpenAI key보다 먼저 매칭한다 (sk-ant- prefix 충돌 방지).

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionReport {
    /// (kind, count) — 종류별 매칭 횟수
    pub counts: Vec<(String, usize)>,
}

impl RedactionReport {
    pub fn total(&self) -> usize {
        self.counts.iter().map(|(_, c)| c).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// secret으로 간주할 최소 Shannon entropy (bits/char). 정형화된 short string의 false positive를 줄인다.
const SECRET_ENTROPY_MIN: f64 = 3.0;

/// 입력 텍스트에서 secret/PII를 `[REDACTED:kind]`로 마스킹하고 보고서를 반환한다.
pub fn redact(text: &str) -> (String, RedactionReport) {
    let mut current = text.to_string();
    let mut counts: Vec<(String, usize)> = Vec::new();

    for (name, regex, is_secret) in patterns().iter() {
        let mut count = 0usize;
        let placeholder = format!("[REDACTED:{name}]");
        current = regex
            .replace_all(&current, |caps: &regex::Captures| {
                let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                // secret은 entropy 보조 검증 — 너무 단조롭면 false positive로 간주, 원본 유지
                if *is_secret && shannon_entropy(matched) < SECRET_ENTROPY_MIN {
                    matched.to_string()
                } else {
                    count += 1;
                    placeholder.clone()
                }
            })
            .into_owned();
        if count > 0 {
            counts.push(((*name).to_string(), count));
        }
    }

    (current, RedactionReport { counts })
}

/// Shannon entropy in bits per character. 0(완전 단조) ~ log2(unique chars).
pub fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count();
    if len == 0 {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len_f = len as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / len_f;
            -p * p.log2()
        })
        .sum()
}

fn patterns() -> &'static Vec<(&'static str, Regex, bool)> {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex, bool)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // (name, regex, is_secret) — secret은 entropy 보조, PII는 정형 매칭만
            // anthropic은 openai보다 먼저 매칭 (sk-ant- prefix 충돌)
            (
                "anthropic_key",
                Regex::new(r"sk-ant-[A-Za-z0-9_-]{32,}").unwrap(),
                true,
            ),
            (
                "openai_key",
                Regex::new(r"sk-[A-Za-z0-9_-]{32,}").unwrap(),
                true,
            ),
            ("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), true),
            (
                "github_token",
                Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
                true,
            ),
            (
                "jwt_token",
                Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
                true,
            ),
            // PII (영향 큰 것부터) — 정형 매칭만, entropy 무관
            (
                "kr_rrn",
                Regex::new(r"\b\d{6}-?[1-4]\d{6}\b").unwrap(),
                false,
            ),
            (
                "email",
                Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
                false,
            ),
            (
                "kr_phone",
                Regex::new(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b").unwrap(),
                false,
            ),
            (
                "ipv4",
                Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
                false,
            ),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Secret 5종 (TP) ───────────────────────────────────────

    #[test]
    fn redacts_aws_key() {
        let (out, r) = redact("key=AKIAIOSFODNN7EXAMPLE rest");
        assert!(out.contains("[REDACTED:aws_key]"));
        assert_eq!(r.total(), 1);
    }

    #[test]
    fn redacts_github_token() {
        let (out, _) = redact("token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
        assert!(out.contains("[REDACTED:github_token]"));
    }

    #[test]
    fn redacts_openai_key() {
        let (out, _) = redact("OPENAI=sk-proj-abcdefghijklmnopqrstuvwxyz123456");
        assert!(out.contains("[REDACTED:openai_key]"));
    }

    #[test]
    fn redacts_anthropic_key_takes_priority_over_openai() {
        let (out, r) = redact("X=sk-ant-api01-abcdefghijklmnopqrstuvwxyz1234567890123");
        assert!(out.contains("[REDACTED:anthropic_key]"));
        assert!(!out.contains("[REDACTED:openai_key]"));
        let kinds: Vec<&str> = r.counts.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds, vec!["anthropic_key"]);
    }

    #[test]
    fn redacts_jwt() {
        let (out, _) =
            redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF");
        assert!(out.contains("[REDACTED:jwt_token]"));
    }

    // ── PII 4종 (TP) ──────────────────────────────────────────

    #[test]
    fn redacts_email() {
        let (out, _) = redact("user@example.com sent");
        assert!(out.contains("[REDACTED:email]"));
    }

    #[test]
    fn redacts_kr_phone_various_formats() {
        for phone in &[
            "010-1234-5678",
            "010 1234 5678",
            "01012345678",
            "01098765432",
        ] {
            let (out, _) = redact(&format!("phone: {phone}"));
            assert!(
                out.contains("[REDACTED:kr_phone]"),
                "phone {phone} not redacted"
            );
        }
    }

    #[test]
    fn redacts_kr_rrn() {
        let (out, _) = redact("주민번호 901101-1234567");
        assert!(out.contains("[REDACTED:kr_rrn]"));
    }

    #[test]
    fn redacts_ipv4() {
        let (out, _) = redact("ip 192.168.1.1");
        assert!(out.contains("[REDACTED:ipv4]"));
    }

    // ── 다중 매칭 ─────────────────────────────────────────────

    #[test]
    fn multiple_redactions_count_correctly() {
        let input = "user1@a.com and user2@b.com both 010-1234-5678";
        let (_out, r) = redact(input);
        assert_eq!(r.total(), 3);
        // email 2 + phone 1
        let counts: std::collections::HashMap<String, usize> = r.counts.into_iter().collect();
        assert_eq!(counts.get("email"), Some(&2));
        assert_eq!(counts.get("kr_phone"), Some(&1));
    }

    // ── False Positive (FP) — 정상 텍스트에 매칭되면 안 됨 ───

    #[test]
    fn does_not_redact_clean_text() {
        let inputs = [
            "hello world this is normal text",
            "Rust 컴파일러는 매우 엄격하다",
            "function add(a, b) { return a + b }",
            "version 1.2.3 release notes",
            "lorem ipsum dolor sit amet",
        ];
        for input in &inputs {
            let (out, r) = redact(input);
            assert_eq!(out, *input, "should not redact: {input}");
            assert!(r.is_empty());
        }
    }

    #[test]
    fn does_not_redact_short_strings_resembling_keys() {
        // 너무 짧은 문자열은 secret으로 인식 안 됨
        let inputs = ["sk-", "AKIA", "ghp_", "eyJ"];
        for input in &inputs {
            let (out, r) = redact(input);
            assert_eq!(out, *input, "should not redact short: {input}");
            assert!(r.is_empty());
        }
    }

    #[test]
    fn does_not_redact_version_numbers_as_ipv4() {
        // 1.2.3은 IPv4가 아닌데 ipv4 패턴은 4-octet만 매칭하므로 OK
        let (out, _) = redact("rust 1.65.0 build");
        assert_eq!(out, "rust 1.65.0 build");
    }

    #[test]
    fn does_not_redact_at_sign_in_code() {
        // 단순 @가 아닌 email 형식만 매칭
        let (out, _) = redact("@derive(Debug) attribute");
        assert_eq!(out, "@derive(Debug) attribute");
    }

    // ── RedactionReport ──────────────────────────────────────

    #[test]
    fn report_is_empty_for_clean_input() {
        let (_, r) = redact("clean");
        assert!(r.is_empty());
        assert_eq!(r.total(), 0);
    }

    // ── Entropy ───────────────────────────────────────────────

    #[test]
    fn shannon_entropy_zero_for_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn shannon_entropy_zero_for_single_char_repeat() {
        // 모두 같은 글자 → entropy = 0
        let h = shannon_entropy("aaaaaaaaaaaaaaaa");
        assert!(h < 0.01, "expected ~0, got {h}");
    }

    #[test]
    fn shannon_entropy_high_for_diverse_string() {
        // 다양한 글자 → entropy > 4
        let h = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(h > 3.0, "expected >3, got {h}");
    }

    // ── Entropy 보조 (false positive 감소) ────────────────────

    #[test]
    fn low_entropy_secret_pattern_is_not_redacted() {
        // GitHub 토큰 형식이지만 모두 같은 글자 — false positive로 간주, 원본 유지
        let input = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (out, r) = redact(input);
        assert_eq!(out, input, "low-entropy 패턴은 redact되지 않아야 함");
        assert!(r.is_empty());
    }

    #[test]
    fn high_entropy_secret_pattern_is_redacted() {
        // 다양한 글자 분포 — 진짜 secret로 간주, redact
        let input = "ghp_AbC123XyZ789DeF456GhI012JkL345MnO678";
        let (out, r) = redact(input);
        assert!(out.contains("[REDACTED:github_token]"));
        assert_eq!(r.total(), 1);
    }

    #[test]
    fn pii_is_redacted_regardless_of_entropy() {
        // PII는 entropy와 무관 — 정형화된 짧은 패턴이 그대로 redact
        let (out, _) = redact("test@a.bc");
        assert!(out.contains("[REDACTED:email]"));
    }
}
