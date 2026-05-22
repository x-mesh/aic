//! CLI 친화 Markdown subset → 터미널 렌더러 (의존성 없는 순수 함수).
//!
//! `/local` LLM 분석 출력이 raw `##`/`**` 원문처럼 보이지 않게, 제한된 subset만 ANSI 구조로
//! 렌더한다: heading(`#`~`###`), bullet(`- `/`* `/`+ `), 번호 목록, bold(`**`), inline `code`,
//! fenced code block(```` ``` ````), blockquote(`> `). 표/HTML/이미지는 지원하지 않고 평문 처리.
//!
//! - `color=false`(NO_COLOR/non-TTY)면 ANSI 없이 **구조만**(들여쓰기·`•`·`#` 보존) 정리한다.
//! - 줄바꿈은 unicode-width 기반(CJK 2칸)으로 `width`에 맞춰 wrap한다.
//! - 부분/깨진 markdown(미완 fence 등)도 panic 없이 best-effort 렌더.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// opencode 스타일 amber/yellow 강조색(256색). 16색만 지원하는 터미널은 근사 노랑으로 보인다.
/// 강조(heading·bullet 마커·inline code)에만 쓰고 본문 텍스트는 기본 fg를 유지한다(가독성).
pub(crate) const AMBER: &str = "38;5;214";
/// inline code용 살짝 밝은 amber.
pub(crate) const AMBER_LIGHT: &str = "38;5;215";

/// Markdown subset을 터미널용 문자열로 렌더한다. 순수 함수(테스트 가능).
/// `width`는 wrap 폭(컬럼), `color`면 ANSI 스타일 적용(아니면 plain 구조).
pub(crate) fn render_markdown(md: &str, width: usize, color: bool) -> String {
    let width = width.max(4);
    let mut out: Vec<String> = Vec::new();
    let mut in_fence = false;

    for raw in md.lines() {
        let trimmed_start = raw.trim_start();

        // 코드 펜스 토글(```), 마커 줄 자체는 출력하지 않는다.
        if trimmed_start.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            // 코드 블록: 좌측 바 + 내용 그대로(인라인 처리 안 함).
            out.push(format!(
                "{} {}",
                paint("│", "2", color),
                paint(raw, "2", color)
            ));
            continue;
        }

        let line = raw.trim_end();
        if line.trim().is_empty() {
            out.push(String::new());
            continue;
        }

        // heading: #, ##, ###
        if let Some(level) = heading_level(line) {
            let text = line[level..].trim_start();
            let body = style_inline(text, color);
            // 굵게+amber(색). plain이면 본문만(구조는 빈 줄·간격으로 유지).
            out.push(paint(&body, &format!("1;{AMBER}"), color));
            continue;
        }

        // blockquote: > ...
        if let Some(rest) = line.strip_prefix("> ").or_else(|| line.strip_prefix(">")) {
            out.extend(render_block(
                &paint("▏ ", "2", color),
                &paint("▏ ", "2", color),
                rest.trim_start(),
                width,
                color,
            ));
            continue;
        }

        // 번호 목록: "1. ", "2) " ...
        if let Some((marker, rest)) = numbered_item(line) {
            let first = format!("  {marker} ");
            let cont = " ".repeat(display_width(&first));
            out.extend(render_block(&first, &cont, rest, width, color));
            continue;
        }

        // 불릿: "- ", "* ", "+ " (들여쓰기 허용)
        if let Some((indent, rest)) = bullet_item(line) {
            let first = format!("{indent}{} ", paint("•", AMBER, color));
            let cont = " ".repeat(indent.len() + 2);
            out.extend(render_block(&first, &cont, rest, width, color));
            continue;
        }

        // 일반 문단
        out.extend(render_block("", "", line, width, color));
    }

    out.join("\n")
}

/// `#`/`##`/`###`(공백 동반)이면 `#` 개수(=prefix 길이, 공백 포함 전)를 반환.
fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if (1..=6).contains(&hashes) && line[hashes..].starts_with(' ') {
        Some(hashes)
    } else {
        None
    }
}

/// 불릿 마커(`- `/`* `/`+ `)면 (선행 공백, 본문) 반환.
fn bullet_item(line: &str) -> Option<(String, &str)> {
    let indent_len = line.len() - line.trim_start().len();
    let indent = &line[..indent_len];
    let body = &line[indent_len..];
    for m in ["- ", "* ", "+ "] {
        if let Some(rest) = body.strip_prefix(m) {
            return Some((indent.to_string(), rest));
        }
    }
    None
}

/// 번호 목록(`1. ` 또는 `1) `)이면 (정규화 마커 "1.", 본문) 반환.
fn numbered_item(line: &str) -> Option<(String, &str)> {
    let digits: String = line.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let after = &line[digits.len()..];
    let rest = after
        .strip_prefix(". ")
        .or_else(|| after.strip_prefix(") "))?;
    Some((format!("{digits}."), rest))
}

/// prefix(첫 줄)/cont(이어지는 줄) + 폭 wrap + 인라인 스타일을 적용한 줄들을 만든다.
fn render_block(first: &str, cont: &str, text: &str, width: usize, color: bool) -> Vec<String> {
    let avail = width.saturating_sub(display_width(first)).max(4);
    let wrapped = wrap_words(text, avail);
    wrapped
        .into_iter()
        .enumerate()
        .map(|(i, line)| {
            let p = if i == 0 { first } else { cont };
            format!("{p}{}", style_inline(&line, color))
        })
        .collect()
}

/// 단어 단위로 `width`(표시폭, CJK 2칸)에 맞춰 wrap. `width`보다 긴 단어(긴 CJK 런·URL)는
/// 표시폭 기준 char 단위로 쪼갠다. 마커는 plain 텍스트 기준으로 측정.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for word in text.split_whitespace() {
        for chunk in break_word(word, width) {
            let ww = UnicodeWidthStr::width(chunk.as_str());
            if cur.is_empty() {
                cur = chunk;
                cur_w = ww;
            } else if cur_w + 1 + ww <= width {
                cur.push(' ');
                cur.push_str(&chunk);
                cur_w += 1 + ww;
            } else {
                lines.push(std::mem::take(&mut cur));
                cur = chunk;
                cur_w = ww;
            }
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// `width`보다 넓은 단어를 표시폭 기준 char 단위 청크로 쪼갠다(짧으면 그대로).
fn break_word(word: &str, width: usize) -> Vec<String> {
    if UnicodeWidthStr::width(word) <= width {
        return vec![word.to_string()];
    }
    let mut chunks = Vec::new();
    let mut cur = String::new();
    let mut w = 0usize;
    for ch in word.chars() {
        let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
        if w + cw > width && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
            w = 0;
        }
        cur.push(ch);
        w += cw;
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

/// 인라인 스타일: inline `code`(backtick) → 시안, `**bold**` → 굵게. 코드 안의 `**`는 평문.
fn style_inline(s: &str, color: bool) -> String {
    let mut out = String::new();
    // backtick으로 분할 — 홀수 인덱스 세그먼트가 inline code.
    for (i, seg) in s.split('`').enumerate() {
        if i % 2 == 1 {
            out.push_str(&paint(seg, AMBER_LIGHT, color)); // inline code = amber-light
        } else {
            out.push_str(&style_bold(seg, color));
        }
    }
    out
}

/// `**bold**` 쌍을 굵게. 짝이 없으면 마커를 평문으로 둔다.
fn style_bold(s: &str, color: bool) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("**") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find("**") {
            out.push_str(&paint(&after[..end], "1", color));
            rest = &after[end + 2..];
        } else {
            out.push_str("**");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// 표시폭(ANSI 없음 가정 — wrap은 스타일 적용 전 plain에서 수행).
fn display_width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// `color`면 ANSI로 감싸고, 아니면 원문(구조만).
fn paint(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heading_rendered_not_raw_hashes() {
        let r = render_markdown("## Disk usage", 80, true);
        assert!(!r.contains("## "), "raw ## 노출: {r}");
        assert!(r.contains("Disk usage"));
        assert!(r.contains("\x1b["), "색상 ANSI 적용");
        // plain(color=false)이면 ANSI 없이 본문만.
        let p = render_markdown("## Disk usage", 80, false);
        assert!(!p.contains('\x1b'));
        assert!(!p.contains("## "));
        assert!(p.contains("Disk usage"));
    }

    #[test]
    fn amber_palette_for_accents_plain_when_off() {
        // heading/bullet/inline code는 amber(38;5;214/215), 본문은 기본 fg.
        let r = render_markdown("## Title\n- item with `code`", 80, true);
        assert!(r.contains(AMBER), "amber heading/bullet 누락: {r}");
        assert!(r.contains(AMBER_LIGHT), "amber-light inline code 누락: {r}");
        // color=false면 ANSI 전혀 없음.
        let p = render_markdown("## Title\n- item", 80, false);
        assert!(!p.contains('\x1b'));
    }

    #[test]
    fn bold_and_inline_code_styled() {
        let r = render_markdown("use **bold** and `code` here", 80, true);
        assert!(!r.contains("**"), "raw ** 노출: {r}");
        assert!(!r.contains('`'), "raw backtick 노출: {r}");
        assert!(r.contains("bold") && r.contains("code"));
        // plain: 마커 제거, 텍스트 보존.
        let p = render_markdown("use **bold** and `code` here", 80, false);
        assert_eq!(p, "use bold and code here");
    }

    #[test]
    fn bullets_become_dots() {
        let p = render_markdown("- first\n- second", 80, false);
        assert!(p.contains("• first"));
        assert!(p.contains("• second"));
        assert!(!p.contains("- first"));
    }

    #[test]
    fn numbered_list_kept() {
        let p = render_markdown("1. one\n2. two", 80, false);
        assert!(p.contains("1. one"));
        assert!(p.contains("2. two"));
    }

    #[test]
    fn code_fence_block_no_inline_and_no_marker() {
        let p = render_markdown("```\nlet x = **not bold**;\n```", 80, false);
        assert!(!p.contains("```"), "fence 마커 노출: {p}");
        // 코드 블록 안 ** 는 그대로(인라인 스타일 미적용).
        assert!(p.contains("**not bold**"));
        assert!(p.contains("│"));
    }

    #[test]
    fn wraps_long_paragraph_to_width() {
        let text = "alpha beta gamma delta epsilon zeta eta theta";
        let p = render_markdown(text, 16, false);
        for line in p.lines() {
            assert!(display_width(line) <= 16, "초과 줄: '{line}'");
        }
        assert!(p.lines().count() > 1);
    }

    #[test]
    fn cjk_width_wrap() {
        // CJK는 2칸 — width 6이면 3글자에서 줄바꿈.
        let p = render_markdown("가나다라마바", 6, false);
        for line in p.lines() {
            assert!(display_width(line) <= 6, "CJK 초과: '{line}'");
        }
    }

    #[test]
    fn unterminated_fence_is_graceful() {
        // 닫히지 않은 코드펜스도 panic 없이 렌더.
        let p = render_markdown("text\n```\ncode line", 80, false);
        assert!(p.contains("code line"));
        assert!(!p.contains("```"));
    }

    #[test]
    fn blockquote_prefixed() {
        let p = render_markdown("> note here", 80, false);
        assert!(p.contains("▏"));
        assert!(p.contains("note here"));
    }
}
