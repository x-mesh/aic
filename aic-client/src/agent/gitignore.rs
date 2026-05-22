//! 최소 gitignore 매처 (읽기 전용 도구용).
//!
//! 루트의 `.gitignore`와 `.git/info/exclude`를 읽어, 도구가 ignore된 경로를
//! 건너뛰거나 거부하는 데 쓴다. 전체 gitignore 명세가 아니라 흔한 패턴만 다루는
//! **보수적 서브셋**이다:
//! - `#` 주석, 공백 라인 무시.
//! - `!` 부정(negation) — 나중 규칙이 우선(last-match-wins).
//! - 트레일링 `/` → 디렉터리 전용 패턴.
//! - 슬래시를 포함(또는 리딩 `/`)하면 루트 기준 anchored, 아니면 basename 패턴
//!   (임의 깊이의 단일 경로 세그먼트에 매칭).
//! - 와일드카드 `*`(슬래시 제외), `?`(슬래시 제외 1자), `**`(디렉터리 가로지름).
//!
//! 디렉터리가 ignore되면 그 하위도 ignore된다(조상 prefix 검사로 처리).
//! 미지원/모호한 패턴은 매칭하지 않는 쪽(=ignore 안 함)으로 보수적으로 흘린다.

use std::path::Path;

use regex::Regex;

struct Rule {
    regex: Regex,
    negated: bool,
    dir_only: bool,
    /// true면 루트 기준 전체 상대경로에, false면 단일 세그먼트(basename)에 매칭.
    anchored: bool,
}

#[derive(Default)]
pub struct Gitignore {
    rules: Vec<Rule>,
}

impl Gitignore {
    /// 루트의 `.gitignore` + `.git/info/exclude`를 읽어 매처를 만든다.
    /// 파일이 없으면 빈 매처(아무것도 ignore 안 함)를 돌려준다 — 동작 회귀 없음.
    pub fn load(root: &Path) -> Self {
        let mut rules = Vec::new();
        for rel in [".gitignore", ".git/info/exclude"] {
            let p = root.join(rel);
            if let Ok(content) = std::fs::read_to_string(&p) {
                for line in content.lines() {
                    if let Some(rule) = parse_line(line) {
                        rules.push(rule);
                    }
                }
            }
        }
        Self { rules }
    }

    /// 빈 매처(테스트/폴백용).
    pub fn empty() -> Self {
        Self::default()
    }

    /// 단일 경로(prefix)에 대해 규칙을 순서대로 적용한다(last-match-wins).
    fn match_one(&self, acc: &str, seg: &str, is_dir: bool) -> Option<bool> {
        let mut decision: Option<bool> = None;
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            let hit = if rule.anchored {
                rule.regex.is_match(acc)
            } else {
                rule.regex.is_match(seg)
            };
            if hit {
                decision = Some(!rule.negated);
            }
        }
        decision
    }

    /// 루트 기준 상대경로(slash 구분)가 ignore되는지 판정한다.
    /// 경로 자신과 모든 조상 디렉터리 prefix를 검사해, 디렉터리 ignore가
    /// 하위로 전파되도록 한다.
    pub fn is_ignored(&self, rel: &str, is_dir: bool) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        let segs: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return false;
        }
        let mut ignored = false;
        let mut acc = String::new();
        for (i, seg) in segs.iter().enumerate() {
            if i > 0 {
                acc.push('/');
            }
            acc.push_str(seg);
            let seg_is_dir = if i == segs.len() - 1 { is_dir } else { true };
            if let Some(d) = self.match_one(&acc, seg, seg_is_dir) {
                ignored = d;
            }
        }
        ignored
    }
}

/// gitignore 한 줄을 규칙으로 파싱한다. 주석/공백/미지원은 None.
fn parse_line(raw: &str) -> Option<Rule> {
    let line = raw.trim_end();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut pat = line;
    let mut negated = false;
    if let Some(stripped) = pat.strip_prefix('!') {
        negated = true;
        pat = stripped;
    }
    let mut dir_only = false;
    if let Some(stripped) = pat.strip_suffix('/') {
        dir_only = true;
        pat = stripped;
    }
    // 리딩 `/`는 anchored 의미 — 제거하고 anchored 플래그로.
    let leading_slash = pat.starts_with('/');
    if leading_slash {
        pat = &pat[1..];
    }
    if pat.is_empty() {
        return None;
    }
    // 내부 슬래시가 있거나 리딩 슬래시였으면 anchored(루트 기준 전체경로 매칭).
    let anchored = leading_slash || pat.contains('/');
    let regex = Regex::new(&gitignore_to_regex(pat)).ok()?;
    Some(Rule {
        regex,
        negated,
        dir_only,
        anchored,
    })
}

/// gitignore 글롭 패턴을 anchored 정규식(^...$)으로 변환한다.
fn gitignore_to_regex(pattern: &str) -> String {
    let mut re = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    if chars.peek() == Some(&'/') {
                        chars.next();
                        re.push_str("(?:.*/)?"); // `**/` → 0개 이상 디렉터리
                    } else {
                        re.push_str(".*"); // 후행 `**`
                    }
                } else {
                    re.push_str("[^/]*");
                }
            }
            '?' => re.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    re.push('$');
    re
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gi(lines: &[&str]) -> Gitignore {
        let rules = lines.iter().filter_map(|l| parse_line(l)).collect();
        Gitignore { rules }
    }

    #[test]
    fn empty_matcher_ignores_nothing() {
        let g = Gitignore::empty();
        assert!(!g.is_ignored("anything.txt", false));
    }

    #[test]
    fn basename_pattern_matches_any_depth() {
        let g = gi(&["*.log"]);
        assert!(g.is_ignored("app.log", false));
        assert!(g.is_ignored("sub/dir/app.log", false));
        assert!(!g.is_ignored("app.txt", false));
    }

    #[test]
    fn exact_nondot_file_ignored() {
        // 리뷰 요구: ignore된 non-dot 파일.
        let g = gi(&["ignored.txt"]);
        assert!(g.is_ignored("ignored.txt", false));
        assert!(g.is_ignored("nested/ignored.txt", false));
        assert!(!g.is_ignored("keep.txt", false));
    }

    #[test]
    fn anchored_pattern_only_at_root() {
        let g = gi(&["/build"]);
        assert!(g.is_ignored("build", true));
        assert!(g.is_ignored("build/out.txt", false)); // 디렉터리 ignore 전파
        assert!(!g.is_ignored("src/build", true)); // 하위의 build는 anchored라 제외 안 됨
    }

    #[test]
    fn dir_only_pattern_matches_dir_and_contents() {
        let g = gi(&["node_modules/"]);
        assert!(g.is_ignored("node_modules", true));
        assert!(g.is_ignored("node_modules/pkg/index.js", false));
        // 동일 이름의 파일(디렉터리 아님)은 dir_only라 ignore 안 됨.
        assert!(!g.is_ignored("node_modules", false));
    }

    #[test]
    fn negation_unignores() {
        let g = gi(&["*.log", "!keep.log"]);
        assert!(g.is_ignored("a.log", false));
        assert!(!g.is_ignored("keep.log", false));
    }

    #[test]
    fn double_star_path() {
        let g = gi(&["build/**/*.o"]);
        assert!(g.is_ignored("build/a/b/x.o", false));
        assert!(g.is_ignored("build/x.o", false));
        assert!(!g.is_ignored("src/x.o", false));
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let g = gi(&["# comment", "", "  ", "*.tmp"]);
        assert!(g.is_ignored("a.tmp", false));
    }
}
