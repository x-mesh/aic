//! 프로세스 rss 성장 리더보드 (RCA 강화 ③ — "어느 프로세스가 자랐나").
//!
//! Crit onset 시 "memory 98%"까지는 알아도 **범인 프로세스**는 스냅샷 한 장으론 모른다.
//! L0 store의 baseline 스냅샷(onset 이전)과 onset 진단 증거가 둘 다 `## mem_top_proc`
//! 섹션(`ps -eo pid,comm,rss` 계열)을 품으므로, 양쪽을 파싱해 pid별 rss 증가를
//! **결정적으로**(LLM 0) diff한다 — LLM이 오기 전에 범인 후보가 좁혀져 있게.
//!
//! best-effort: store 미기록(opt-in off)·baseline 없음·섹션 부재·성장 0이면 `None` —
//! 인시던트 생성은 계속된다. 파서는 첫 토큰이 숫자가 아닌 줄(헤더·`[command]` wrapper)을
//! 건너뛰어 ps 출력 변형에 관대하다.

use chrono::{DateTime, Utc};

/// diff 대상 섹션 id — probe catalog의 `mem_top_proc`(`ps -eo pid,comm,rss` 정렬 상위).
pub(crate) const SECTION: &str = "mem_top_proc";

/// baseline로 쓸 스냅샷의 최소 나이(초). onset과 같은 순간의 alert 캡처는 이미 부푼
/// 상태라 baseline이 못 된다 — L1 캡처 cooldown(120s)과 같은 값.
pub(crate) const BASELINE_MIN_AGE_SECS: i64 = 120;

/// 리더보드 행 수 상한.
const TOP_N: usize = 10;

/// `ps -eo pid,comm,rss` 한 줄에서 뽑은 샘플. rss는 KiB(리눅스/맥 ps 공통 단위).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcSample {
    pub pid: u32,
    pub comm: String,
    pub rss_kb: u64,
}

/// 리더보드 한 행. `is_new`=baseline에 없던(또는 pid 재사용으로 comm이 바뀐) 프로세스.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeltaRow {
    pub pid: u32,
    pub comm: String,
    pub rss_kb: u64,
    pub delta_kb: i64,
    pub is_new: bool,
}

/// auto-RCA 진입점: store 스냅샷들과 onset 진단 증거 본문에서 성장 리더보드 텍스트를 만든다.
/// baseline 미존재/섹션 부재/성장 0 → `None`.
pub(crate) fn growth_evidence(
    snapshots: &[crate::snapshot_store::SnapshotRecord],
    current_evidence: &str,
    onset: DateTime<Utc>,
) -> Option<String> {
    let baseline = baseline_snapshot(snapshots, onset)?;
    let base_samples = parse_mem_top(extract_section(&baseline.body, SECTION)?);
    let cur_samples = parse_mem_top(extract_section(current_evidence, SECTION)?);
    if base_samples.is_empty() || cur_samples.is_empty() {
        return None;
    }
    let rows = leaderboard(&base_samples, &cur_samples, TOP_N);
    if rows.is_empty() {
        return None;
    }
    Some(render(baseline.captured_at, onset, &rows))
}

/// onset보다 `BASELINE_MIN_AGE_SECS` 이상 오래됐고 `mem_top_proc` 섹션을 가진 최신 스냅샷.
pub(crate) fn baseline_snapshot(
    snapshots: &[crate::snapshot_store::SnapshotRecord],
    onset: DateTime<Utc>,
) -> Option<&crate::snapshot_store::SnapshotRecord> {
    let cutoff = onset - chrono::Duration::seconds(BASELINE_MIN_AGE_SECS);
    snapshots
        .iter()
        .filter(|s| s.captured_at <= cutoff && s.sections.iter().any(|sec| sec == SECTION))
        .max_by_key(|s| s.captured_at)
}

/// `## name\n<out>` 본문(스냅샷 body·진단 evidence 공통 포맷)에서 해당 섹션 텍스트를 뽑는다.
pub(crate) fn extract_section<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let header = format!("## {name}");
    let mut start = None;
    for (offset, line) in body.lines().map(|l| {
        // lines()는 offset을 안 주므로 포인터 연산으로 복원한다.
        let off = l.as_ptr() as usize - body.as_ptr() as usize;
        (off, l)
    }) {
        match start {
            None if line.trim_end() == header => start = Some(offset + line.len()),
            Some(s) if line.starts_with("## ") => {
                return Some(body[s..offset].trim_matches('\n'));
            }
            _ => {}
        }
    }
    start.map(|s| body[s..].trim_matches('\n'))
}

/// ps 출력 파싱: 첫 토큰=pid(숫자 아니면 skip — 헤더/wrapper 내성), 마지막 토큰=rss(KiB),
/// 사이 전부=comm(macOS 앱 경로의 공백 보존).
pub(crate) fn parse_mem_top(section: &str) -> Vec<ProcSample> {
    section
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 3 {
                return None;
            }
            let pid: u32 = tokens[0].parse().ok()?;
            let rss_kb: u64 = tokens[tokens.len() - 1].parse().ok()?;
            Some(ProcSample {
                pid,
                comm: tokens[1..tokens.len() - 1].join(" "),
                rss_kb,
            })
        })
        .collect()
}

/// pid 조인 후 rss 증가(Δ>0)만 내림차순 top-N. pid가 재사용돼 comm이 다르면 새 프로세스로 본다.
pub(crate) fn leaderboard(
    baseline: &[ProcSample],
    current: &[ProcSample],
    top_n: usize,
) -> Vec<DeltaRow> {
    let base: std::collections::HashMap<u32, &ProcSample> =
        baseline.iter().map(|s| (s.pid, s)).collect();
    let mut rows: Vec<DeltaRow> = current
        .iter()
        .filter_map(|cur| {
            let (delta_kb, is_new) = match base.get(&cur.pid) {
                Some(b) if b.comm == cur.comm => (cur.rss_kb as i64 - b.rss_kb as i64, false),
                _ => (cur.rss_kb as i64, true),
            };
            (delta_kb > 0).then_some(DeltaRow {
                pid: cur.pid,
                comm: cur.comm.clone(),
                rss_kb: cur.rss_kb,
                delta_kb,
                is_new,
            })
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.delta_kb));
    rows.truncate(top_n);
    rows
}

/// 리더보드 텍스트 렌더. baseline 나이를 명시해 "얼마나 옛날과의 비교인지"를 증거 자체가 말하게 한다.
fn render(baseline_at: DateTime<Utc>, onset: DateTime<Utc>, rows: &[DeltaRow]) -> String {
    let age_min = (onset - baseline_at).num_minutes();
    let mut out = format!(
        "process rss growth since baseline snapshot ({}, onset {}분 전 캡처). (new)=baseline에 없던 프로세스.\n",
        baseline_at.to_rfc3339(),
        age_min
    );
    for r in rows {
        out.push_str(&format!(
            "+{} → {} pid={} {}{}\n",
            fmt_kb(r.delta_kb as u64),
            fmt_kb(r.rss_kb),
            r.pid,
            r.comm,
            if r.is_new { " (new)" } else { "" }
        ));
    }
    out
}

/// KiB를 사람이 읽는 단위로(소수 1자리). 리더보드는 크기 비교가 목적이라 정밀도보다 가독성.
fn fmt_kb(kb: u64) -> String {
    const MB: f64 = 1024.0;
    const GB: f64 = 1024.0 * 1024.0;
    let kb_f = kb as f64;
    if kb_f >= GB {
        format!("{:.1}GB", kb_f / GB)
    } else if kb_f >= MB {
        format!("{:.1}MB", kb_f / MB)
    } else {
        format!("{kb}KB")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn sample(pid: u32, comm: &str, rss_kb: u64) -> ProcSample {
        ProcSample {
            pid,
            comm: comm.to_string(),
            rss_kb,
        }
    }

    fn snapshot_at(at: &str, body: &str) -> crate::snapshot_store::SnapshotRecord {
        crate::snapshot_store::SnapshotRecord::new("periodic", body, None, None, ts(at))
    }

    const ONSET: &str = "2026-07-10T12:00:00Z";

    #[test]
    fn parse_skips_headers_and_wrappers_keeps_spaced_comm() {
        let section = "\
[command] ps -eo pid,comm,rss -m
  PID COMM              RSS
  123 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome 1048576
  456 node              204800
  bad line here
   12 short 1
";
        let got = parse_mem_top(section);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].pid, 123);
        assert!(got[0].comm.ends_with("Google Chrome"), "공백 comm 보존");
        assert_eq!(got[0].rss_kb, 1_048_576);
        assert_eq!(got[2], sample(12, "short", 1));
    }

    #[test]
    fn extract_section_finds_middle_and_last() {
        let body = "## memory\nfree stuff\n\n## mem_top_proc\n  1 a 10\n  2 b 20\n\n## fd\nxx\n";
        assert_eq!(
            extract_section(body, "mem_top_proc").unwrap(),
            "  1 a 10\n  2 b 20"
        );
        assert_eq!(extract_section(body, "fd").unwrap(), "xx");
        assert!(extract_section(body, "missing").is_none());
    }

    #[test]
    fn leaderboard_growth_only_sorted_new_marked() {
        let base = vec![
            sample(1, "steady", 100),
            sample(2, "grower", 100),
            sample(3, "shrinker", 500),
            sample(4, "reused-pid", 50),
        ];
        let cur = vec![
            sample(1, "steady", 100),     // Δ0 → 제외
            sample(2, "grower", 1100),    // Δ+1000
            sample(3, "shrinker", 100),   // Δ<0 → 제외
            sample(4, "other-comm", 300), // pid 재사용 → new, Δ=rss
            sample(5, "newcomer", 700),   // new
        ];
        let rows = leaderboard(&base, &cur, 10);
        let ids: Vec<(u32, i64, bool)> =
            rows.iter().map(|r| (r.pid, r.delta_kb, r.is_new)).collect();
        assert_eq!(
            ids,
            vec![(2, 1000, false), (5, 700, true), (4, 300, true)],
            "Δ내림차순·성장만·new 마킹"
        );
        // top_n cap.
        assert_eq!(leaderboard(&base, &cur, 1).len(), 1);
    }

    #[test]
    fn baseline_requires_min_age_and_section() {
        let with = "## mem_top_proc\n  1 a 10\n";
        let without = "## memory\nx\n";
        let snaps = vec![
            snapshot_at("2026-07-10T11:00:00Z", with), // 후보(오래됨)
            snapshot_at("2026-07-10T11:50:00Z", with), // 후보 중 최신 ← 정답
            snapshot_at("2026-07-10T11:59:30Z", with), // 120s 미만 → 제외
            snapshot_at("2026-07-10T11:55:00Z", without), // 섹션 없음 → 제외
        ];
        let picked = baseline_snapshot(&snaps, ts(ONSET)).expect("baseline");
        assert_eq!(picked.captured_at, ts("2026-07-10T11:50:00Z"));
        // 후보가 전부 너무 신선하면 None.
        let fresh = vec![snapshot_at("2026-07-10T11:59:00Z", with)];
        assert!(baseline_snapshot(&fresh, ts(ONSET)).is_none());
    }

    #[test]
    fn growth_evidence_end_to_end_and_none_paths() {
        let baseline_body = "## mem_top_proc\n  PID COMM RSS\n  10 worker 102400\n  20 web 51200\n";
        let snaps = vec![snapshot_at("2026-07-10T11:45:00Z", baseline_body)];
        let current = "## memory\nfree\n\n## mem_top_proc\n  PID COMM RSS\n  10 worker 2201600\n  20 web 51200\n";
        let body = growth_evidence(&snaps, current, ts(ONSET)).expect("리더보드 생성");
        assert!(body.contains("onset 15분 전 캡처"));
        assert!(body.contains("pid=10 worker"));
        assert!(body.contains("+2.0GB → 2.1GB"), "{body}");
        assert!(!body.contains("pid=20"), "성장 0은 제외");

        // None 경로: baseline 없음 / current 섹션 없음 / 성장 없음.
        assert!(growth_evidence(&[], current, ts(ONSET)).is_none());
        assert!(growth_evidence(&snaps, "## memory\nx\n", ts(ONSET)).is_none());
        let no_growth = "## mem_top_proc\n  10 worker 102400\n  20 web 51200\n";
        assert!(growth_evidence(&snaps, no_growth, ts(ONSET)).is_none());
    }
}
