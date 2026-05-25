//! 원격 stdout/stderr에서 secret 패턴을 redact (RFC-005 §4.6 S3, pre-render).
//!
//! 호출 시점: ssh_process가 stdout/stderr를 collect한 **직후**, [`RemoteResult`] 생성 시.
//! render(TUI 카드) + audit 기록은 redact된 문자열로만 진행한다. 패턴 미일치 시 secret이
//! 노출될 수 있다는 한계는 `RemoteResult.redacted` 카운트가 0이어도 보장 못 함 →
//! audit 측에서 "원격 결과는 secret 포함 가능" 경고를 항상 첨부한다(별도 RFC §4.6).
//!
//! 패턴 카테고리:
//!   - 환경변수 형식 secret: `AWS_*=`, `DATABASE_URL=`, `VAULT_TOKEN=`, `*PASSWORD=`,
//!     `*API_KEY=`, `*SECRET=`, `*TOKEN=`.
//!   - JWT prefix(`eyJ`로 시작하는 3-segment dot-separated).
//!   - PEM 헤더/푸터(`-----BEGIN`/`-----END`) — 다중행 PEM 블록 자체는 라인 단위 매칭 한계.

use regex::Regex;
use std::sync::OnceLock;

static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();

fn patterns() -> &'static Vec<Regex> {
    PATTERNS.get_or_init(|| {
        vec![
            // 환경변수 = secret. 키워드를 양쪽 `[A-Z_]*`로 감싸 `MY_PASSWORD=`, `PASSWORD_HASH=`,
            // `GITHUB_TOKEN=` 모두 잡되, `AWS_REGION=`/`AWS_PROFILE=` 같은 non-secret AWS 변수는
            // 정확한 secret AWS 키 이름(ACCESS_KEY_ID/SECRET_ACCESS_KEY/SESSION_TOKEN)만 매치해
            // 거짓 양성 회피.
            Regex::new(
                r"(?i)\b(?:[A-Z_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY)[A-Z_]*|DATABASE_URL|VAULT_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)=\S+",
            )
            .expect("static regex"),
            // JWT: `eyJ` prefix 3-segment dot-separated. segment 길이 최소 4(header는 짧을 수 있음).
            // 너무 엄격하면 실 JWT를 놓쳐 secret이 그대로 노출.
            Regex::new(r"eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=.-]+")
                .expect("static regex"),
            // PEM 헤더/푸터 — 본문(base64) 라인은 라인 단위 매칭 한계 → §7 Risk.
            Regex::new(r"-----BEGIN [A-Z ]+-----").expect("static regex"),
            Regex::new(r"-----END [A-Z ]+-----").expect("static regex"),
        ]
    })
}

/// `text`에서 secret 패턴을 `[REDACTED]`로 치환하고, (치환된 텍스트, 매치 수)를 반환.
pub fn redact(text: &str) -> (String, usize) {
    let mut out = text.to_string();
    let mut hits: usize = 0;
    for re in patterns() {
        let count = re.find_iter(&out).count();
        if count > 0 {
            hits += count;
            out = re.replace_all(&out, "[REDACTED]").into_owned();
        }
    }
    (out, hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_env_var_secrets() {
        let (out, hits) = redact(
            "export AWS_ACCESS_KEY_ID=AKIA1234567890abcdef\n\
             export DATABASE_URL=postgres://u:p@h:5432/db",
        );
        assert_eq!(hits, 2);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("AKIA"));
        assert!(!out.contains("postgres://"));
    }

    #[test]
    fn redact_password_and_token_variants() {
        let (out, hits) = redact("MY_PASSWORD=hunter2\nGITHUB_TOKEN=ghp_abcdef\nMY_SECRET=xyz");
        assert_eq!(hits, 3, "all three should be matched");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("ghp_abcdef"));
    }

    #[test]
    fn redact_jwt() {
        let token =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTcwMDAwMDAwMH0.signature_blob_here";
        let line = format!("Authorization: Bearer {token}");
        let (out, hits) = redact(&line);
        assert_eq!(hits, 1);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("eyJ"));
    }

    #[test]
    fn redact_pem_headers() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                   MIIEpAIBAAKCAQEA...\n\
                   -----END RSA PRIVATE KEY-----";
        let (out, hits) = redact(pem);
        assert!(hits >= 2, "BEGIN + END 헤더 매칭, hits={hits}");
        assert!(!out.contains("BEGIN RSA"));
        assert!(!out.contains("END RSA"));
        // 본문(base64) 라인은 라인 단위 redaction 미지원 — 잔존 위험 명시.
        assert!(out.contains("MIIEpAIBAA"));
    }

    #[test]
    fn no_match_for_clean_output() {
        let s = "load 1.5 cpu 30% · mem 60% · disk 45G free";
        let (out, hits) = redact(s);
        assert_eq!(hits, 0);
        assert_eq!(out, s);
    }

    #[test]
    fn preserves_non_secret_lines() {
        let s = "starting server\nAWS_REGION=us-east-1\nlistening on :8080";
        let (out, hits) = redact(s);
        // AWS_REGION은 SECRET/KEY/TOKEN 패턴 아님(키워드 매치 안 함) → 통과.
        assert_eq!(hits, 0, "AWS_REGION은 패턴이 아님");
        assert_eq!(out, s);
    }

    #[test]
    fn does_not_mangle_words_starting_with_password_substring() {
        // 'PASSWORD_HASH=...'는 password 토큰이 들어가서 매칭됨(보수적). 거짓 양성은 §7 Risk.
        let (_, hits) = redact("PASSWORD_HASH=$2a$10$abc");
        assert_eq!(hits, 1, "보수적 match — 거짓 양성 가능, 운영자가 audit으로 확인");
    }
}
