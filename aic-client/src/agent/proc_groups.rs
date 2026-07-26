//! 프로세스 **그룹** 집계 — "무엇이 몇 개나 떠서 얼마나 먹고 있나".
//!
//! # 왜 개체가 아니라 그룹인가
//! [`sys_sampler`](super::sys_sampler)는 오래도록 최대 RSS 프로세스 **하나**(`top_mem_proc`)만 지목해
//! 왔다. 그것으로는 답할 수 없는 질문이 있다 — `load 16.68`인 호스트에서 실제 범인이 "claude 21개가
//! 합쳐서 CPU 40%"일 때, 개체 최댓값만 보면 "claude 하나가 3%"로 보여 아무 문제도 없어 보인다.
//! **같은 무리를 21번 봐도 매번 한 마리로 세면 무리가 안 보인다.** 그래서 이름으로 묶어 개수·CPU
//! 합·RSS 합을 낸다.
//!
//! # 사실만 보고하고 판단하지 않는다
//! 이 모듈은 `claude ×21, cpu 40%, rss 4.3G`라는 **사실**만 만든다. "유령이니 정리하라"는 결론은
//! 내지 않는다 — 개수만으로는 폭주와 정상 병렬 작업을 구별할 수 없기 때문이다. 실제로 `ppid==1`이나
//! 개수 같은 단일 축으로 프로세스를 유령이라 단정했다가 살아 있는 세션의 부속 프로세스를 죽일 뻔한
//! 전례가 있고(터미널 탭이 쓰는 gitstatus 데몬), 같은 종류의 과교정이 "실제 173개 중 47개만 보고"
//! 회귀를 만든 적도 있다. 정리 여부를 판정하려면 tty 앵커·부모 생존·유휴 시간 같은 교차 축이 필요하고,
//! 그건 집계기가 곁다리로 낼 결론이 아니다.
//!
//! # 비용
//! 전수 프로세스 열거는 싸지 않다. 호출자(`sys_sampler`)가 **이상 신호가 있을 때만** 부르고, 평시엔
//! 프로세스 목록을 아예 열지 않는다. 진단 도구가 상시로 전수 스캔을 돌면 그 자신이 부하의 일부가 된다.

/// 집계 대상 프로세스인가 — **유저랜드 스레드는 제외**한다.
///
/// Linux의 `processes()`는 task(스레드)까지 돌려준다. 거르지 않으면 스레드 20개짜리 프로세스 하나가
/// `×20`으로 보여 그룹 개수가 통째로 거짓이 된다.
///
/// 반대 방향의 과교정도 실제로 있었다 — `thread_kind().is_none()`으로 걸렀다가 **커널 스레드까지
/// 잘라내** 실제 173개 중 47개만 보고한 회귀(v0.31.0, 같은 날 핫픽스)다. 커널 스레드는 `Tgid == Pid`인
/// 독립 항목이라 남겨야 한다. [`super::proc_fd`]가 같은 판정을 쓴다 — 바꾸려면 양쪽을 함께 봐야 한다.
pub(crate) fn is_countable(p: &sysinfo::Process) -> bool {
    !matches!(p.thread_kind(), Some(sysinfo::ThreadKind::Userland))
}

/// 집계 결과 한 행 — 같은 이름 프로세스 무리.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProcGroup {
    /// 프로세스 이름(`claude`, `node`, …).
    pub name: String,
    /// 그 이름으로 뜬 프로세스 수.
    pub count: usize,
    /// 그룹 RSS 합계(bytes).
    pub rss: u64,
    /// 그룹 CPU 사용률 합계(%). **기준선이 없으면 `None`** — sysinfo의 프로세스 CPU는 직전 refresh
    /// 대비 delta라, 첫 스캔 값은 0이 아니라 "부팅 이후 누적 평균"이라는 그럴싸하게 틀린 수다.
    /// `cpu --%` 폴백과 같은 원칙으로, 믿을 수 없으면 숫자를 만들지 않는다.
    pub cpu_pct: Option<f32>,
}

/// 상위 그룹을 무엇 기준으로 고를지. 부하의 종류에 따라 범인이 다르다 — load/cpu 경보에는 CPU를,
/// mem 경보에는 RSS를 기준으로 봐야 진짜 원인이 위로 온다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupSort {
    Cpu,
    Rss,
}

/// 프로세스 표본을 이름으로 묶어 상위 `top_n` 그룹을 만든다. 순수 함수.
///
/// `samples`는 `(이름, cpu%, rss)` 튜플의 순회자다 — sysinfo 타입을 여기까지 끌고 오지 않아 테스트가
/// 실제 프로세스 없이 돌아간다. `cpu_valid=false`면 모든 그룹의 `cpu_pct`가 `None`이 되고, 그때
/// `GroupSort::Cpu`는 의미가 없으므로 RSS 정렬로 자동 폴백한다(없는 기준으로 순위를 매기지 않는다).
pub(crate) fn top_groups<I>(
    samples: I,
    top_n: usize,
    sort: GroupSort,
    cpu_valid: bool,
) -> Vec<ProcGroup>
where
    I: IntoIterator<Item = (String, f32, u64)>,
{
    use std::collections::HashMap;
    let mut acc: HashMap<String, (usize, f32, u64)> = HashMap::new();
    for (name, cpu, rss) in samples {
        let e = acc.entry(name).or_insert((0, 0.0, 0));
        e.0 += 1;
        e.1 += cpu;
        e.2 = e.2.saturating_add(rss);
    }
    let mut groups: Vec<ProcGroup> = acc
        .into_iter()
        .map(|(name, (count, cpu, rss))| ProcGroup {
            name,
            count,
            rss,
            cpu_pct: cpu_valid.then_some(cpu),
        })
        .collect();

    // cpu 기준이 요청됐어도 값이 없으면 rss로 — 기준 없는 순위는 무작위와 같다.
    let effective = match (sort, cpu_valid) {
        (GroupSort::Cpu, true) => GroupSort::Cpu,
        _ => GroupSort::Rss,
    };
    match effective {
        GroupSort::Cpu => groups.sort_by(|a, b| {
            b.cpu_pct
                .partial_cmp(&a.cpu_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
                // 동률이면 RSS, 그다음 이름 — 순서가 tick마다 흔들리면 읽는 사람이 변화를 오해한다.
                .then(b.rss.cmp(&a.rss))
                .then(a.name.cmp(&b.name))
        }),
        GroupSort::Rss => groups.sort_by(|a, b| {
            b.rss
                .cmp(&a.rss)
                .then(b.count.cmp(&a.count))
                .then(a.name.cmp(&b.name))
        }),
    }
    groups.truncate(top_n);
    groups
}

/// `/local`의 `proc_groups` 섹션에 실을 행 수. `proc_fd_top`(15줄)과 눈높이를 맞춘다 — 섹션 하나가
/// 화면을 잡아먹으면 안 되고, 범인이 2~3위에 숨는 경우가 있어 1~2행으로는 모자란다.
const RENDER_TOP_N: usize = 10;

/// 이름별 프로세스 그룹 상위 N을 사람이 읽는 표로 만든다(probe `proc_groups` / `aic proc-groups`).
///
/// # 왜 **세 번** refresh하는가 (두 번으로는 전부 0이 나온다)
/// 프로세스 cpu%는 직전 refresh와의 델타인데, sysinfo가 그 델타를 내놓기까지 세 단계를 거친다.
///
/// 1. **1회차** — 프로세스 객체를 만든다(`create_new_process`). 이전 값이 없어 `old_stime`이 비어 있다.
/// 2. **2회차** — `total_existing_time == 0`이라 계산 조건에 걸려 `cpu_usage = 0`으로 두고, 대신
///    `old_stime`/`old_utime`을 채운다. **여기까지가 흔히 쓰는 "두 번 refresh" 패턴이고, 값은 0이다.**
/// 3. **3회차** — 비로소 `old`가 있어 실제 델타가 나온다.
///
/// 실측(이 머신, `/bin/sh` 3개가 각 98% 소모 중):
/// ```text
/// refresh 2회 → 합계   0.0%   ← sysinfo 문서의 예제 패턴. 조용히 전부 0
/// refresh 3회 → 합계 743.0%   (최상위 rustc 250%)
/// new_all() + 1회 → 합계 0.0%
/// ```
/// `ProcessRefreshKind::everything()`으로 바꿔도 2회차까지는 0이다 — refresh **종류**가 아니라
/// **횟수** 문제라, 이걸 모르면 "sysinfo가 macOS에서 프로세스 cpu를 못 준다"고 오진하기 쉽다.
///
/// 비루트로 돌면 자기 uid 소유 프로세스만 보이므로, 이 표는 **볼 수 있는 범위 안의** 집계다.
pub fn render() -> String {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let kind = ProcessRefreshKind::nothing().with_memory().with_cpu();
    let mut sys = System::new();
    // 1회차: 프로세스 객체 생성.
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    // 2회차: old_stime/old_utime 기준선 확보(값은 아직 0).
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    // 이 구간이 곧 cpu%의 분모다. sysinfo 내부 시계도 이 간격을 넘겨야 갱신된다.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    // 3회차: 실제 델타.
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);

    let groups = top_groups(
        sys.processes()
            .values()
            .filter(|p| is_countable(p))
            .map(|p| {
                (
                    p.name().to_string_lossy().into_owned(),
                    p.cpu_usage(),
                    p.memory(),
                )
            }),
        RENDER_TOP_N,
        GroupSort::Cpu,
        true,
    );

    let mut out = format!("{:>5} {:>7} {:>8}  {}\n", "COUNT", "CPU%", "RSS", "NAME");
    for g in &groups {
        let cpu = match g.cpu_pct {
            Some(c) => format!("{c:.1}"),
            None => "--".to_string(),
        };
        out.push_str(&format!(
            "{:>5} {:>7} {:>8}  {}\n",
            g.count,
            cpu,
            human_rss(g.rss),
            g.name
        ));
    }
    if groups.is_empty() {
        out.push_str("(읽을 수 있는 프로세스 없음 — 권한 부족)\n");
    }
    out
}

/// RSS를 표 폭에 맞는 짧은 단위로. `sys_sampler::human_bytes`와 같은 규칙이지만 그쪽은 private이라
/// 여기서 최소한만 구현한다(이 표 말고 쓰이지 않는다).
fn human_rss(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str, cpu: f32, rss_mb: u64) -> (String, f32, u64) {
        (name.to_string(), cpu, rss_mb * 1024 * 1024)
    }

    /// 같은 이름 프로세스가 하나의 행으로 묶이고 개수·합계가 맞는다.
    ///
    /// 이 테스트가 곧 이 모듈의 존재 이유다 — 개체 최댓값만 보면 claude는 `3%`짜리 잔챙이지만,
    /// 묶으면 `21개 · 40%`로 목록 맨 위에 온다.
    #[test]
    fn groups_by_name_and_sums_count_cpu_rss() {
        let samples: Vec<_> = (0..21)
            .map(|_| s("claude", 1.9, 210))
            .chain(std::iter::once(s("swift-frontend", 3.0, 900)))
            .collect();
        let groups = top_groups(samples, 5, GroupSort::Cpu, true);

        assert_eq!(groups[0].name, "claude");
        assert_eq!(groups[0].count, 21);
        assert_eq!(groups[0].rss, 21 * 210 * 1024 * 1024);
        let cpu = groups[0].cpu_pct.expect("cpu 유효");
        assert!((cpu - 39.9).abs() < 0.1, "cpu 합계: {cpu}");
        // 개체 하나로는 swift-frontend(3.0%)가 claude 개체(1.9%)보다 크지만, 그룹으로는 뒤진다.
        assert_eq!(groups[1].name, "swift-frontend");
    }

    /// 기준선이 없으면 cpu를 만들어내지 않고, 정렬도 rss로 폴백한다.
    #[test]
    fn without_cpu_baseline_no_numbers_and_rss_fallback() {
        let samples = vec![s("hog", 90.0, 100), s("fat", 1.0, 8000)];
        let groups = top_groups(samples, 5, GroupSort::Cpu, false);
        assert!(groups.iter().all(|g| g.cpu_pct.is_none()));
        // cpu를 요청했지만 기준이 없으므로 rss 순 — 없는 기준으로 순위를 매기지 않는다.
        assert_eq!(groups[0].name, "fat");
    }

    #[test]
    fn rss_sort_and_top_n_truncation() {
        let samples = vec![s("a", 0.0, 30), s("b", 0.0, 50), s("c", 0.0, 10)];
        let groups = top_groups(samples, 2, GroupSort::Rss, true);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "b");
        assert_eq!(groups[1].name, "a");
    }

    /// 동률이 tick마다 순서를 바꾸면 읽는 사람이 없는 변화를 본다 — 이름까지 내려가 결정적으로 정한다.
    #[test]
    fn ties_break_deterministically() {
        let samples = vec![s("zzz", 5.0, 100), s("aaa", 5.0, 100)];
        let first = top_groups(samples.clone(), 5, GroupSort::Cpu, true);
        let second = top_groups(samples, 5, GroupSort::Cpu, true);
        assert_eq!(first, second);
        assert_eq!(first[0].name, "aaa");
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert!(top_groups(Vec::new(), 5, GroupSort::Cpu, true).is_empty());
    }

    /// 실제 시스템 호출 — 헤더가 있고 패닉 없이 돈다(값은 환경 의존이라 형식만 본다).
    ///
    /// **cpu가 전부 0이면 실패시킨다.** refresh 횟수가 모자라면 sysinfo는 오류 없이 조용히 0을
    /// 돌려주므로(`render` doc의 실측 참고), 그 회귀를 잡을 방법은 이 확인뿐이다. 테스트 러너 자신이
    /// cpu를 쓰고 있으므로 합계가 0일 수는 없다.
    #[test]
    fn render_produces_table_with_live_cpu() {
        let out = render();
        assert!(out.starts_with("COUNT"), "헤더: {out}");
        let rows: Vec<&str> = out.lines().skip(1).collect();
        assert!(!rows.is_empty(), "행이 없다: {out}");

        let total: f32 = rows
            .iter()
            .filter_map(|l| l.split_whitespace().nth(1))
            .filter_map(|c| c.parse::<f32>().ok())
            .sum();
        assert!(
            total > 0.0,
            "cpu가 전부 0 — refresh 횟수 회귀 의심(3회 필요):\n{out}"
        );
    }
}
