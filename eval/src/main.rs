//! `docs/PRD-JEV-PROBE-SELECTION.md`의 비교 실험 러너.
//!
//! probe를 **고르기만** 한다. 고른 명령을 호스트에서 실행하지 않는다.

mod arms;
mod scenario;
mod scoring;

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use arms::{jev::JevClient, llm::LlmArm, rules, ArmOutcome};
use scenario::{Dataset, Lang, Scenario, Split};
use scoring::CaseRecord;

const DEFAULT_DATA: &str = "data/scenarios.json";
const DEFAULT_RESULTS: &str = "target/results.jsonl";
/// bootstrap 반복 수. 고정 시드와 함께 쓰므로 실행마다 같은 구간이 나온다.
const BOOTSTRAP_ITERATIONS: usize = 2000;
const BOOTSTRAP_SEED: u64 = 20260922;

#[derive(Parser)]
#[command(name = "aic-eval", about = "증상별 진단 항목 선택 비교 실험")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 데이터 라벨이 규칙을 지키는지 확인한다. 네트워크를 쓰지 않는다.
    Validate {
        #[arg(long, default_value = DEFAULT_DATA)]
        data: PathBuf,
    },
    /// 비교군을 실행해 원시 결과를 남긴다.
    Run {
        #[arg(long, default_value = DEFAULT_DATA)]
        data: PathBuf,
        /// current | improved | jev | llm. 여러 번 줄 수 있다.
        #[arg(long = "arm", required = true)]
        arms: Vec<String>,
        /// dev | final. 생략하면 전부.
        #[arg(long)]
        split: Option<String>,
        /// 같은 입력을 몇 번 반복할지. 모델의 결정론 여부를 볼 때 올린다.
        #[arg(long, default_value_t = 1)]
        repeats: u32,
        #[arg(long, default_value = DEFAULT_RESULTS)]
        out: PathBuf,
        #[arg(long, default_value = "jev-1.13.0")]
        jev_model: String,
    },
    /// 범주별로 어떤 probe가 붙는지 보여준다. 필수 집합을 정할 때 쓴다.
    Probes {
        /// 생략하면 전부.
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        docker: bool,
    },
    /// 원시 결과를 집계해 보고한다.
    Score {
        #[arg(long, default_value = DEFAULT_RESULTS)]
        results: PathBuf,
        /// 비교의 기준이 될 비교군. 차이의 신뢰구간을 이 비교군 대비로 낸다.
        #[arg(long, default_value = "improved")]
        baseline: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Validate { data } => validate(&data),
        Command::Run {
            data,
            arms,
            split,
            repeats,
            out,
            jev_model,
        } => run(&data, &arms, split.as_deref(), repeats, &out, &jev_model).await,
        Command::Probes { category, docker } => {
            show_probes(category.as_deref(), docker)
        }
        Command::Score { results, baseline } => score(&results, &baseline),
    }
}

fn show_probes(category: Option<&str>, docker: bool) -> Result<()> {
    use aic_client::agent::diagnose::DIAGNOSE_CATEGORIES;
    let wanted: Vec<&str> = match category {
        Some(c) => {
            if !DIAGNOSE_CATEGORIES.contains(&c) {
                bail!("알 수 없는 범주: {c}");
            }
            vec![c]
        }
        None => DIAGNOSE_CATEGORIES.to_vec(),
    };
    for cat in wanted {
        let ids = arms::probes_for(cat, docker);
        println!("{cat} ({}개)", ids.len());
        println!("  {}", ids.join(" "));
    }
    Ok(())
}

fn validate(data: &std::path::Path) -> Result<()> {
    let ds = Dataset::load(data)?;
    println!(
        "✔ {} 시나리오, schema_version {}",
        ds.scenarios.len(),
        ds.schema_version
    );
    println!("  확정일: {}", ds.generated);
    println!();
    println!("  {:<10} {:>5} {:>6}", "범주", "dev", "final");
    for (cat, dev, fin) in ds.counts() {
        println!("  {cat:<10} {dev:>5} {fin:>6}");
    }
    let ambiguous = ds.scenarios.iter().filter(|s| s.is_ambiguous()).count();
    println!();
    println!("  모호한 사례(확보율 제외): {ambiguous}");
    Ok(())
}

/// 하나의 비교군이 범주를 고르는 방법. 모델 비교군만 네트워크를 쓴다.
enum Runner {
    Current,
    Improved,
    Jev(Box<JevClient>),
    Llm(Box<LlmArm>),
}

impl Runner {
    fn build(name: &str, jev_model: &str) -> Result<Self> {
        Ok(match name {
            "current" => Runner::Current,
            "improved" => Runner::Improved,
            "jev" => Runner::Jev(Box::new(JevClient::from_env(jev_model)?)),
            "llm" => Runner::Llm(Box::new(LlmArm::from_config()?)),
            other => bail!("알 수 없는 비교군: {other}"),
        })
    }

    /// 결과에 함께 기록할 모델·provider 식별자.
    fn model(&self) -> Option<String> {
        match self {
            Runner::Current | Runner::Improved => None,
            Runner::Jev(c) => Some(c.model().to_string()),
            Runner::Llm(a) => Some(a.provider().to_string()),
        }
    }

    fn question_version(&self) -> Option<String> {
        match self {
            Runner::Current | Runner::Improved => None,
            Runner::Jev(_) => Some(arms::jev::QUESTION_VERSION.to_string()),
            Runner::Llm(_) => Some(arms::llm::QUESTION_VERSION.to_string()),
        }
    }

    async fn categorize(&self, symptom: &str) -> ArmOutcome {
        match self {
            Runner::Current => local(rules::current(symptom)),
            Runner::Improved => local(rules::improved(symptom)),
            Runner::Jev(c) => c.categorize(symptom).await,
            Runner::Llm(a) => a.categorize(symptom).await,
        }
    }
}

/// 규칙 비교군은 네트워크를 쓰지 않으므로 지연·토큰이 0이다. 실패도 없다.
fn local(category: &str) -> ArmOutcome {
    ArmOutcome {
        category: Some(category.to_string()),
        raw_category: Some(category.to_string()),
        attempts: 1,
        ..Default::default()
    }
}

async fn run(
    data: &std::path::Path,
    arm_names: &[String],
    split: Option<&str>,
    repeats: u32,
    out: &std::path::Path,
    jev_model: &str,
) -> Result<()> {
    let ds = Dataset::load(data)?;
    let split = match split {
        None => None,
        Some("dev") => Some(Split::Dev),
        Some("final") => Some(Split::Final),
        Some(other) => bail!("알 수 없는 split: {other}"),
    };
    let scenarios: Vec<&Scenario> = ds
        .scenarios
        .iter()
        .filter(|s| split.is_none_or(|want| s.split == want))
        .collect();
    if scenarios.is_empty() {
        bail!("실행할 시나리오가 없습니다");
    }

    let revision = git_revision();
    let mut runners = Vec::new();
    for name in arm_names {
        runners.push((name.clone(), Runner::build(name, jev_model)?));
    }

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = std::fs::File::create(out)
        .with_context(|| format!("결과 파일을 만들지 못했습니다: {}", out.display()))?;

    let total = scenarios.len() * Lang::ALL.len() * runners.len() * repeats as usize;
    let mut done = 0usize;
    for (name, runner) in &runners {
        for repeat in 1..=repeats {
            for sc in &scenarios {
                for lang in Lang::ALL {
                    let symptom = sc.text(lang);
                    let outcome = runner.categorize(symptom).await;
                    let selected: Vec<String> = outcome
                        .category
                        .as_deref()
                        .map(|cat| {
                            arms::probes_for(cat, sc.docker_available)
                                .into_iter()
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    let score = scoring::score_case(sc, &outcome, &selected);
                    let record = CaseRecord {
                        scenario_id: sc.id.clone(),
                        split: sc.split,
                        lang,
                        arm: name.clone(),
                        repeat,
                        revision: revision.clone(),
                        model: runner.model(),
                        question_version: runner.question_version(),
                        input_sha256: scoring::input_hash(symptom),
                        outcome,
                        selected_probes: selected,
                        score,
                    };
                    writeln!(file, "{}", serde_json::to_string(&record)?)?;
                    done += 1;
                    if done.is_multiple_of(20) || done == total {
                        eprintln!("  {done}/{total}");
                    }
                }
            }
        }
    }
    println!("✔ {done}건을 {}에 기록했습니다", out.display());
    Ok(())
}

fn score(results: &std::path::Path, baseline: &str) -> Result<()> {
    let raw = std::fs::read_to_string(results)
        .with_context(|| format!("결과를 읽지 못했습니다: {}", results.display()))?;
    let records: Vec<CaseRecord> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .context("결과 파싱 실패")?;
    if records.is_empty() {
        bail!("결과가 비어 있습니다");
    }

    let mut arm_names: Vec<String> = records.iter().map(|r| r.arm.clone()).collect();
    arm_names.sort();
    arm_names.dedup();

    println!(
        "{:<10} {:>6} {:>9} {:>9} {:>9} {:>8} {:>8} {:>9} {:>9}",
        "비교군", "사례", "확보율", "누락율", "불필요", "범주", "실패율", "p50(ms)", "p95(ms)"
    );
    let mut summaries = Vec::new();
    for arm in &arm_names {
        let s = scoring::summarize(arm, &records);
        println!(
            "{:<10} {:>6} {:>9.3} {:>9.3} {:>9.2} {:>8.3} {:>8.3} {:>9} {:>9}",
            s.arm,
            s.scored_cases,
            s.mean_coverage,
            s.missed_case_rate,
            s.mean_unnecessary,
            s.category_accuracy,
            s.failure_rate,
            s.latency_p50_ms,
            s.latency_p95_ms
        );
        summaries.push(s);
    }

    if !arm_names.iter().any(|a| a == baseline) {
        println!();
        println!("(기준 비교군 {baseline}의 결과가 없어 차이를 내지 않습니다)");
        return Ok(());
    }

    println!();
    println!("{baseline} 대비 확보율 차이 (짝지은 bootstrap 95% CI, 시나리오 단위 재표집)");
    for arm in arm_names.iter().filter(|a| *a != baseline) {
        let grouped = group_by_scenario(&records, arm, baseline, &|s| s.coverage);
        let pairs: usize = grouped.iter().map(Vec::len).sum();
        if pairs == 0 {
            println!("  {arm:<10} 비교 가능한 사례 없음");
            continue;
        }
        let point = grouped.iter().flatten().map(|(a, b)| a - b).sum::<f64>() / pairs as f64;
        let (lo, hi) = scoring::paired_bootstrap_ci(&grouped, BOOTSTRAP_ITERATIONS, BOOTSTRAP_SEED);
        println!("  {arm:<10} {point:+.3}  [{lo:+.3}, {hi:+.3}]  (n={pairs})");
    }

    println!();
    println!("불필요 probe (두 비교군이 모두 정상 반환한 사례에서만)");
    for arm in arm_names.iter().filter(|a| *a != baseline) {
        let (a, b, n) = scoring::unnecessary_paired(&records, arm, baseline);
        println!("  {arm:<10} {a:.2} vs {baseline} {b:.2}  (n={n})");
    }

    println!();
    println!("언어별 확보율");
    for arm in &arm_names {
        for lang in Lang::ALL {
            let subset: Vec<CaseRecord> =
                records.iter().filter(|r| r.lang == lang).cloned().collect();
            let s = scoring::summarize(arm, &subset);
            println!(
                "  {:<10} {:<3} {:.3} (n={})",
                arm,
                lang.as_str(),
                s.mean_coverage,
                s.scored_cases
            );
        }
    }

    let repeats = records.iter().map(|r| r.repeat).max().unwrap_or(1);
    if repeats > 1 {
        println!();
        println!("반복 일치율 (같은 입력을 {repeats}번 물었을 때 같은 범주가 나온 비율)");
        for arm in &arm_names {
            match repeat_agreement(&records, arm) {
                Some((rate, n)) => println!("  {arm:<10} {rate:.3} (입력 {n}개)"),
                None => println!("  {arm:<10} 반복 없음"),
            }
        }
    }

    for s in &summaries {
        if let Some(rate) = s.ambiguous_generic_rate {
            println!();
            println!("  {}: 모호한 사례에서 generic 선택 {:.3}", s.arm, rate);
        }
    }
    Ok(())
}

/// 같은 입력을 여러 번 물었을 때 같은 답이 나온 비율.
///
/// PRD가 반복 3회를 요구한 근거는 생성 모델의 변동이다. Jev는 비생성형이라 실제로 변동이
/// 있는지 먼저 봐야 한다 — 결정적이면 반복은 비용만 쓰고 아무것도 알려주지 않는다.
fn repeat_agreement(records: &[CaseRecord], arm: &str) -> Option<(f64, usize)> {
    let mut keys: Vec<(&str, Lang)> = records
        .iter()
        .filter(|r| r.arm == arm)
        .map(|r| (r.scenario_id.as_str(), r.lang))
        .collect();
    keys.sort_unstable();
    keys.dedup();

    let mut agreed = 0usize;
    let mut counted = 0usize;
    for (id, lang) in keys {
        let answers: Vec<Option<&str>> = records
            .iter()
            .filter(|r| r.arm == arm && r.scenario_id == id && r.lang == lang)
            .map(|r| r.outcome.category.as_deref())
            .collect();
        if answers.len() < 2 {
            continue;
        }
        counted += 1;
        if answers.iter().all(|a| *a == answers[0]) {
            agreed += 1;
        }
    }
    (counted > 0).then(|| (agreed as f64 / counted as f64, counted))
}

/// 짝지은 값을 시나리오별로 묶는다. bootstrap 재표집 단위가 시나리오이기 때문이다.
fn group_by_scenario(
    records: &[CaseRecord],
    arm_a: &str,
    arm_b: &str,
    pick: &dyn Fn(&scoring::CaseScore) -> f64,
) -> Vec<Vec<(f64, f64)>> {
    let mut ids: Vec<&str> = records.iter().map(|r| r.scenario_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    ids.into_iter()
        .map(|id| {
            let subset: Vec<CaseRecord> = records
                .iter()
                .filter(|r| r.scenario_id == id)
                .cloned()
                .collect();
            scoring::paired_scores(&subset, arm_a, arm_b, pick)
        })
        .filter(|v| !v.is_empty())
        .collect()
}

/// 결과에 기록할 구현 기준. git이 없으면 unknown.
fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
