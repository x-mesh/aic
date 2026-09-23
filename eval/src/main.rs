//! `docs/PRD-JEV-PROBE-SELECTION.md`의 비교 실험 러너.
//!
//! probe를 **고르기만** 한다. 고른 명령을 호스트에서 실행하지 않는다.

mod arms;
mod confidence;
mod errcause;
mod errcause_scoring;
mod followup;
mod followup_scoring;
mod intent;
mod judge_scoring;
mod judgment;
mod scenario;
mod scoring;

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use arms::{jev::JevClient, jev_judge::JudgeClient, llm::LlmArm, rules, ArmOutcome};
use judgment::JudgmentDataset;
use scenario::{Dataset, Lang, Scenario, Split};
use scoring::CaseRecord;

const DEFAULT_DATA: &str = "data/scenarios.json";
const DEFAULT_JUDGMENT_DATA: &str = "data/probe-judgments.json";
const DEFAULT_RESULTS: &str = "target/results.jsonl";
const DEFAULT_JUDGE_RESULTS: &str = "target/judge-results.jsonl";
/// 벤치마크의 LLM 비교군 모델. provider 기본값에 맡기지 않는 이유는 `LlmArm::from_config`
/// doc 참고 — 언제 바뀌었는지 결과만 보고는 알 수 없다.
const DEFAULT_LLM_MODEL: &str = "kiro/gpt-5.6-luna";
/// `jev-adaptive`의 기본 임계값. 개발 데이터에서 정한다 — 근거는 RESULTS.md 참고.
const DEFAULT_ADAPTIVE_THRESHOLD: f64 = 0.70;
/// bootstrap 반복 수. 고정 시드와 함께 쓰므로 실행마다 같은 구간이 나온다.
const BOOTSTRAP_ITERATIONS: usize = 2000;
const BOOTSTRAP_SEED: u64 = 20260922;
/// Jev의 공개 단가(2026-09-22 확인): 입력 100만 토큰당 0.042 USD, 출력은 무료.
const JEV_INPUT_USD_PER_TOKEN: f64 = 0.042 / 1_000_000.0;

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
        /// LLM 비교군의 모델 ID. config.toml의 provider 설정을 덮어쓴다.
        #[arg(long, default_value = DEFAULT_LLM_MODEL)]
        llm_model: String,
        /// jev-adaptive의 confidence 임계값. 미만이면 2등 범주까지 합친다.
        #[arg(long, default_value_t = DEFAULT_ADAPTIVE_THRESHOLD)]
        adaptive_threshold: f64,
    },
    /// confidence를 라우팅 신호로 쓸 수 있는지 분석한다. 새 API 호출이 없다.
    Confidence {
        #[arg(long, default_value = DEFAULT_RESULTS)]
        results: PathBuf,
        #[arg(long, default_value = DEFAULT_DATA)]
        data: PathBuf,
        #[arg(long, default_value = "jev")]
        arm: String,
    },
    /// follow-up 번들의 정답 줄이 게이트를 통과하고 후보 추출이 정답을 포함하는지 확인한다. 네트워크 없음.
    FollowupValidate {
        #[arg(long, default_value = "data/followup-bundles.json")]
        data: PathBuf,
    },
    /// follow-up 선택을 Jev와 LLM으로 돌려 원시 결과를 남긴다.
    FollowupRun {
        #[arg(long, default_value = "data/followup-bundles.json")]
        data: PathBuf,
        /// jev | llm | rules. 여러 번 줄 수 있다. rules는 결정적 후보의 첫 항목을 고르는 비교군(네트워크 없음).
        #[arg(long = "arm", required = true)]
        arms: Vec<String>,
        #[arg(long)]
        split: Option<String>,
        #[arg(long, default_value_t = 1)]
        repeats: u32,
        #[arg(long, default_value = "target/followup.jsonl")]
        out: PathBuf,
        #[arg(long, default_value = "jev-1.13.0")]
        jev_model: String,
        #[arg(long, default_value = DEFAULT_LLM_MODEL)]
        llm_model: String,
    },
    /// 원인 범주 데이터셋이 규약을 지키는지 확인한다. 네트워크 없음.
    ErrcauseValidate {
        #[arg(long, default_value = "data/errcause-cases.json")]
        data: PathBuf,
    },
    /// 명령 실패의 원인 범주를 규칙·Jev·LLM으로 분류해 원시 결과를 남긴다.
    ErrcauseRun {
        #[arg(long, default_value = "data/errcause-cases.json")]
        data: PathBuf,
        /// rules | jev | llm. 여러 번 줄 수 있다. rules는 네트워크를 쓰지 않는다.
        #[arg(long = "arm", required = true)]
        arms: Vec<String>,
        #[arg(long)]
        split: Option<String>,
        #[arg(long, default_value_t = 1)]
        repeats: u32,
        #[arg(long, default_value = "target/errcause.jsonl")]
        out: PathBuf,
        #[arg(long, default_value = "jev-latest")]
        jev_model: String,
        #[arg(long, default_value = DEFAULT_LLM_MODEL)]
        llm_model: String,
    },
    /// 원인 범주 원시 결과를 집계한다. 네트워크 없음.
    ErrcauseScore {
        #[arg(long, default_value = "target/errcause.jsonl")]
        results: PathBuf,
    },
    /// 의도 라우팅 데이터셋이 규약을 지키는지 확인한다. 네트워크 없음.
    IntentValidate {
        #[arg(long, default_value = "data/intent-cases.json")]
        data: PathBuf,
    },
    /// 최종 분할을 생성 모델로 만든다. 문장은 출력하지 않는다 — 사람이 읽으면 블라인드가 깨진다.
    IntentGenerate {
        #[arg(long, default_value = "data/intent-cases.json")]
        data: PathBuf,
        #[arg(long, default_value_t = 30)]
        per_intent: usize,
        /// LLM 비교군과 다른 모델이어야 한다. 같은 모델이면 자기가 쓴 문장을 채점한다.
        #[arg(long, default_value = "kiro/claude-sonnet-5")]
        model: String,
    },
    /// 채팅 입력의 처리 경로를 규칙·Jev·LLM으로 분류해 원시 결과를 남긴다.
    IntentRun {
        #[arg(long, default_value = "data/intent-cases.json")]
        data: PathBuf,
        #[arg(long = "arm", required = true)]
        arms: Vec<String>,
        #[arg(long)]
        split: Option<String>,
        #[arg(long, default_value_t = 1)]
        repeats: u32,
        #[arg(long, default_value = "target/intent.jsonl")]
        out: PathBuf,
        #[arg(long, default_value = "jev-latest")]
        jev_model: String,
        #[arg(long, default_value = DEFAULT_LLM_MODEL)]
        llm_model: String,
    },
    /// 실제 `aic diagnose --json`(또는 raw evidence) 파일에서 결정적 follow-up 후보를 뽑아 보여준다.
    /// 합성 데이터가 아닌 진짜 출력에 추출 규칙이 도는지 확인할 때 쓴다. 네트워크 없음.
    FollowupCandidates {
        /// `aic diagnose --json` 출력 파일 또는 `## section` 형식의 raw evidence. 여러 번 줄 수 있다.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// follow-up 원시 결과를 집계한다. 네트워크 없음.
    FollowupScore {
        #[arg(long, default_value = "target/followup.jsonl")]
        results: PathBuf,
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
        /// trait별 하위 집합을 보고하려면 라벨 파일이 필요하다.
        #[arg(long, default_value = DEFAULT_DATA)]
        data: PathBuf,
        /// 비교의 기준이 될 비교군. 차이의 신뢰구간을 이 비교군 대비로 낸다.
        #[arg(long, default_value = "improved")]
        baseline: String,
    },
    /// `docs/PRD-JEV-PROBE-JUDGMENT.md`의 판정 fixture 라벨이 실제 scanned_severities와
    /// 일치하는지 확인한다. 네트워크를 쓰지 않는다.
    JudgeValidate {
        #[arg(long, default_value = DEFAULT_JUDGMENT_DATA)]
        data: PathBuf,
    },
    /// `docs/PRD-JEV-PROBE-JUDGMENT.md`의 Choice 판정 비교군을 실행해 원시 결과를 남긴다.
    /// 유일한 네트워크 진입점이다 — `cargo test`는 이 커맨드를 부르지 않는다.
    JudgeRun {
        #[arg(long, default_value = DEFAULT_JUDGMENT_DATA)]
        data: PathBuf,
        /// dev | final. 생략하면 전부.
        #[arg(long)]
        split: Option<String>,
        /// 같은 입력을 몇 번 반복할지.
        #[arg(long, default_value_t = 1)]
        repeats: u32,
        #[arg(long, default_value = DEFAULT_JUDGE_RESULTS)]
        out: PathBuf,
        #[arg(long, default_value = "jev-1.13.0")]
        jev_model: String,
    },
    /// judge-run 원시 결과를 혼동행렬·신뢰구간으로 채점한다. 네트워크를 쓰지 않는다.
    JudgeScore {
        #[arg(long, default_value = DEFAULT_JUDGE_RESULTS)]
        results: PathBuf,
        #[arg(long, default_value = DEFAULT_JUDGMENT_DATA)]
        data: PathBuf,
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
            llm_model,
            adaptive_threshold,
        } => {
            run(RunOptions {
                data: &data,
                arm_names: &arms,
                split: split.as_deref(),
                repeats,
                out: &out,
                jev_model: &jev_model,
                llm_model: Some(llm_model.as_str()),
                adaptive_threshold,
            })
            .await
        }
        Command::Confidence { results, data, arm } => {
            let records = load_records(&results)?;
            let ds = Dataset::load(&data)?;
            confidence::report(&records, &ds, &arm);
            confidence::top_n_report(&records, &ds, &arm);
            confidence::adaptive_report(&records, &ds, &arm);
            Ok(())
        }
        Command::FollowupValidate { data } => followup_validate(&data),
        Command::FollowupRun {
            data,
            arms,
            split,
            repeats,
            out,
            jev_model,
            llm_model,
        } => {
            followup_run(
                &data,
                &arms,
                split.as_deref(),
                repeats,
                &out,
                &jev_model,
                &llm_model,
            )
            .await
        }
        Command::IntentValidate { data } => intent_validate(&data),
        Command::IntentGenerate {
            data,
            per_intent,
            model,
        } => intent_generate(&data, per_intent, &model).await,
        Command::IntentRun {
            data,
            arms,
            split,
            repeats,
            out,
            jev_model,
            llm_model,
        } => {
            intent_run(
                &data,
                &arms,
                split.as_deref(),
                repeats,
                &out,
                &jev_model,
                &llm_model,
            )
            .await
        }
        Command::ErrcauseValidate { data } => errcause_validate(&data),
        Command::ErrcauseRun {
            data,
            arms,
            split,
            repeats,
            out,
            jev_model,
            llm_model,
        } => {
            errcause_run(
                &data,
                &arms,
                split.as_deref(),
                repeats,
                &out,
                &jev_model,
                &llm_model,
            )
            .await
        }
        Command::ErrcauseScore { results } => errcause_score(&results),
        Command::FollowupCandidates { files } => followup_candidates(&files),
        Command::FollowupScore { results } => followup_score(&results),
        Command::Probes { category, docker } => show_probes(category.as_deref(), docker),
        Command::Score {
            results,
            data,
            baseline,
        } => score(&results, &data, &baseline),
        Command::JudgeValidate { data } => judge_validate(&data),
        Command::JudgeRun {
            data,
            split,
            repeats,
            out,
            jev_model,
        } => {
            judge_run(JudgeRunOptions {
                data: &data,
                split: split.as_deref(),
                repeats,
                out: &out,
                jev_model: &jev_model,
            })
            .await
        }
        Command::JudgeScore { results, data } => {
            let records: Vec<JudgeRecord> = load_judge_records(&results)?;
            let ds = JudgmentDataset::load(&data)?;
            judge_scoring::report(&records, &ds);
            Ok(())
        }
    }
}

fn load_judge_records(results: &std::path::Path) -> Result<Vec<JudgeRecord>> {
    let raw = std::fs::read_to_string(results)
        .with_context(|| format!("결과를 읽지 못했습니다: {}", results.display()))?;
    let records: Vec<JudgeRecord> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .context("결과 파싱 실패")?;
    if records.is_empty() {
        bail!("결과가 비어 있습니다");
    }
    Ok(records)
}

fn judge_validate(data: &std::path::Path) -> Result<()> {
    let ds = JudgmentDataset::load(data)?;
    println!(
        "✔ {} 사례, schema_version {}",
        ds.cases.len(),
        ds.schema_version
    );
    println!("  확정일: {}", ds.generated);
    println!();
    println!("  {:<24} {:>5} {:>6}", "probe", "dev", "final");
    for (probe, dev, fin) in ds.counts() {
        println!("  {probe:<24} {dev:>5} {fin:>6}");
    }
    println!();
    println!("  선언 라벨이 scanned_severities와 전부 일치합니다.");
    Ok(())
}

/// judge-run 원시 결과 한 줄. `scoring::CaseRecord`와 같은 형태(사례 식별자 + `outcome` 중첩)를
/// 따른다 — 원시 결과의 필드 구성을 실험마다 다시 고민하지 않도록 기존 관례를 그대로 쓴다.
/// `judge_scoring`(T7)이 채점에 쓰므로 crate 내부로 연다.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct JudgeRecord {
    pub(crate) case_id: String,
    pub(crate) split: judgment::Split,
    pub(crate) probe_id: String,
    pub(crate) repeat: u32,
    pub(crate) model: String,
    pub(crate) question_version: String,
    /// 실제로 보낸 state(섹션에서 stderr를 뺀 나머지)의 해시. 같은 입력을 썼는지 나중에 대조한다.
    pub(crate) input_sha256: String,
    pub(crate) expected: judgment::Expected,
    pub(crate) outcome: arms::jev_judge::JudgeOutcome,
}

struct JudgeRunOptions<'a> {
    data: &'a std::path::Path,
    split: Option<&'a str>,
    repeats: u32,
    out: &'a std::path::Path,
    jev_model: &'a str,
}

async fn judge_run(opts: JudgeRunOptions<'_>) -> Result<()> {
    let JudgeRunOptions {
        data,
        split,
        repeats,
        out,
        jev_model,
    } = opts;
    let ds = JudgmentDataset::load(data)?;
    let split = match split {
        None => None,
        Some("dev") => Some(judgment::Split::Dev),
        Some("final") => Some(judgment::Split::Final),
        Some(other) => bail!("알 수 없는 split: {other}"),
    };
    let cases: Vec<&judgment::JudgmentCase> = ds
        .cases
        .iter()
        .filter(|c| split.is_none_or(|want| c.split == want))
        .collect();
    if cases.is_empty() {
        bail!("실행할 사례가 없습니다");
    }

    let client = JudgeClient::from_env(jev_model)?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = std::fs::File::create(out)
        .with_context(|| format!("결과 파일을 만들지 못했습니다: {}", out.display()))?;

    let total = cases.len() * repeats as usize;
    let mut done = 0usize;
    for repeat in 1..=repeats {
        for case in &cases {
            let outcome = client.judge(&case.section).await;
            let record = JudgeRecord {
                case_id: case.id.clone(),
                split: case.split,
                probe_id: case.probe_id.clone(),
                repeat,
                model: client.model().to_string(),
                question_version: arms::jev_judge::QUESTION_VERSION.to_string(),
                input_sha256: scoring::input_hash(&arms::jev_judge::build_state(&case.section)),
                expected: case.expected,
                outcome,
            };
            writeln!(file, "{}", serde_json::to_string(&record)?)?;
            done += 1;
            if done.is_multiple_of(20) || done == total {
                eprintln!("  {done}/{total}");
            }
        }
    }
    println!("✔ {done}건을 {}에 기록했습니다", out.display());
    Ok(())
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
    /// 개선 규칙과 같은 판정을 쓰되 점수 간격이 좁으면 2등 범주까지 조사한다.
    ImprovedAdaptive(f64),
    Jev(Box<JevClient>),
    /// Jev와 같은 호출을 쓰되 probe 선택에서 확률 분포를 활용한다.
    JevAdaptive(Box<JevClient>, f64),
    Llm(Box<LlmArm>),
}

impl Runner {
    fn build(
        name: &str,
        jev_model: &str,
        llm_model: Option<&str>,
        adaptive_threshold: f64,
    ) -> Result<Self> {
        Ok(match name {
            "current" => Runner::Current,
            "improved" => Runner::Improved,
            "improved-adaptive" => Runner::ImprovedAdaptive(adaptive_threshold),
            "jev" => Runner::Jev(Box::new(JevClient::from_env(jev_model)?)),
            "jev-adaptive" => Runner::JevAdaptive(
                Box::new(JevClient::from_env(jev_model)?),
                adaptive_threshold,
            ),
            "llm" => Runner::Llm(Box::new(LlmArm::from_config(llm_model)?)),
            other => bail!("알 수 없는 비교군: {other}"),
        })
    }

    /// 결과에 함께 기록할 모델·provider 식별자.
    fn model(&self) -> Option<String> {
        match self {
            Runner::Current | Runner::Improved | Runner::ImprovedAdaptive(_) => None,
            Runner::Jev(c) | Runner::JevAdaptive(c, _) => Some(c.model().to_string()),
            Runner::Llm(a) => Some(a.identity()),
        }
    }

    /// 어떤 질문·규칙으로 얻은 수치인지 결과에 남긴다. 규칙 비교군도 버전이 필요하다 —
    /// 어휘를 보강하면 같은 이름의 비교군이 다른 것을 재기 때문이다.
    fn question_version(&self) -> Option<String> {
        match self {
            Runner::Current => Some(format!("rules:{}", rules::RULES_VERSION)),
            Runner::Improved => Some(format!("rules:{}", rules::RULES_VERSION)),
            Runner::ImprovedAdaptive(t) => {
                Some(format!("rules:{}+adaptive@{t}", rules::RULES_VERSION))
            }
            Runner::Jev(_) => Some(arms::jev::QUESTION_VERSION.to_string()),
            Runner::JevAdaptive(_, t) => {
                Some(format!("{}+adaptive@{t}", arms::jev::QUESTION_VERSION))
            }
            Runner::Llm(_) => Some(arms::llm::QUESTION_VERSION.to_string()),
        }
    }

    async fn categorize(&self, symptom: &str) -> ArmOutcome {
        match self {
            Runner::Current => local(rules::current(symptom)),
            Runner::Improved => local(rules::improved(symptom)),
            Runner::ImprovedAdaptive(_) => rules::improved_outcome(symptom),
            Runner::Jev(c) | Runner::JevAdaptive(c, _) => c.categorize(symptom).await,
            Runner::Llm(a) => a.categorize(symptom).await,
        }
    }

    /// 판정 결과에서 probe 목록을 만든다. 적응형만 확률 분포를 쓴다.
    fn probes(&self, outcome: &ArmOutcome, docker_available: bool) -> Vec<String> {
        match self {
            Runner::JevAdaptive(_, t) | Runner::ImprovedAdaptive(t) => {
                arms::probes_adaptive(outcome, docker_available, *t)
            }
            _ => outcome
                .category
                .as_deref()
                .map(|cat| {
                    arms::probes_for(cat, docker_available)
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
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

/// 한 번의 실행 설정. 인자를 늘어놓으면 호출부에서 순서를 헷갈린다.
struct RunOptions<'a> {
    data: &'a std::path::Path,
    arm_names: &'a [String],
    split: Option<&'a str>,
    repeats: u32,
    out: &'a std::path::Path,
    jev_model: &'a str,
    llm_model: Option<&'a str>,
    adaptive_threshold: f64,
}

async fn run(opts: RunOptions<'_>) -> Result<()> {
    let RunOptions {
        data,
        arm_names,
        split,
        repeats,
        out,
        jev_model,
        llm_model,
        adaptive_threshold,
    } = opts;
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
        runners.push((
            name.clone(),
            Runner::build(name, jev_model, llm_model, adaptive_threshold)?,
        ));
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
                    let selected = runner.probes(&outcome, sc.docker_available);
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

fn load_records(results: &std::path::Path) -> Result<Vec<CaseRecord>> {
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
    Ok(records)
}

fn score(results: &std::path::Path, data: &std::path::Path, baseline: &str) -> Result<()> {
    let records = load_records(results)?;

    // 반복이 있으면 **최초 실행만** 주 평가로 쓴다(PRD 5절). 여러 번 중 좋은 쪽을 고르거나
    // 평균을 내면, 실제 운영에서 한 번만 묻는 조건보다 관대한 수치가 나온다.
    let primary: Vec<CaseRecord> = records.iter().filter(|r| r.repeat == 1).cloned().collect();
    let repeats = records.iter().map(|r| r.repeat).max().unwrap_or(1);
    if repeats > 1 {
        println!("(반복 {repeats}회 중 최초 실행을 주 평가로 사용합니다)");
        println!();
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
        let s = scoring::summarize(arm, &primary);
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
        let grouped = group_by_scenario(&primary, arm, baseline, &|s| s.coverage);
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
    println!("토큰과 비용 (실행 전체 합계)");
    for s in &summaries {
        if s.total_input_tokens == 0 && s.total_output_tokens == 0 {
            println!("  {:<10} 원격 호출 없음", s.arm);
            continue;
        }
        // Jev만 공개 단가를 안다. 다른 provider는 단가를 모르므로 토큰만 싣는다 —
        // 모르는 값을 0으로 채우면 비용이 없는 것처럼 보인다.
        let cost = if s.arm == "jev" {
            format!(
                "${:.5}",
                s.total_input_tokens as f64 * JEV_INPUT_USD_PER_TOKEN
            )
        } else {
            "단가 미상".to_string()
        };
        println!(
            "  {:<10} 입력 {:>7}  출력 {:>6}  {}",
            s.arm, s.total_input_tokens, s.total_output_tokens, cost
        );
    }

    println!();
    println!("불필요 probe (두 비교군이 모두 정상 반환한 사례에서만)");
    for arm in arm_names.iter().filter(|a| *a != baseline) {
        let (a, b, n) = scoring::unnecessary_paired(&primary, arm, baseline);
        println!("  {arm:<10} {a:.2} vs {baseline} {b:.2}  (n={n})");
    }

    // PRD 5절이 요구하는 하위 집합 보고. 명확한 단일 증상에서 품질이 떨어지면, 전체 평균이
    // 올라갔어도 후속 연동을 보류한다 — 쉬운 사례를 망가뜨리는 개선은 순이득이 아니다.
    if let Ok(ds) = Dataset::load(data) {
        let traits_of: std::collections::HashMap<&str, &Vec<String>> = ds
            .scenarios
            .iter()
            .map(|s| (s.id.as_str(), &s.traits))
            .collect();
        let mut all_traits: Vec<&str> = traits_of
            .values()
            .flat_map(|v| v.iter().map(String::as_str))
            .collect();
        all_traits.sort_unstable();
        all_traits.dedup();

        println!();
        println!("trait별 확보율 (주 평가)");
        print!("  {:<22}", "trait");
        for arm in &arm_names {
            print!(" {arm:>10}");
        }
        println!("  {:>5}", "n");
        for t in all_traits {
            let subset: Vec<CaseRecord> = primary
                .iter()
                .filter(|r| {
                    traits_of
                        .get(r.scenario_id.as_str())
                        .is_some_and(|v| v.iter().any(|x| x == t))
                })
                .cloned()
                .collect();
            let mut cells = Vec::new();
            let mut n = 0;
            for arm in &arm_names {
                let s = scoring::summarize(arm, &subset);
                n = s.scored_cases;
                cells.push(s.mean_coverage);
            }
            if n == 0 {
                continue;
            }
            print!("  {t:<22}");
            for c in cells {
                print!(" {c:>10.3}");
            }
            println!("  {n:>5}");
        }
    }

    if repeats > 1 {
        println!();
        println!("반복별 확보율 (주 평가는 1회차)");
        for arm in &arm_names {
            print!("  {arm:<10}");
            for rep in 1..=repeats {
                let subset: Vec<CaseRecord> = records
                    .iter()
                    .filter(|r| r.repeat == rep)
                    .cloned()
                    .collect();
                let s = scoring::summarize(arm, &subset);
                print!(" {}회 {:.3}", rep, s.mean_coverage);
            }
            println!();
        }
    }

    println!();
    println!("언어별 확보율");
    for arm in &arm_names {
        for lang in Lang::ALL {
            let subset: Vec<CaseRecord> =
                primary.iter().filter(|r| r.lang == lang).cloned().collect();
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

fn followup_validate(data: &std::path::Path) -> Result<()> {
    let ds = followup::FollowupDataset::load(data)?;
    let (dev, fin, none) = ds.counts();
    println!(
        "✔ {} 번들 (dev {dev} / final {fin}), 신호 없음 {none}",
        ds.bundles.len()
    );
    println!("  모든 정답이 결정적 후보 집합과 같고 게이트를 통과합니다.");
    Ok(())
}

async fn followup_run(
    data: &std::path::Path,
    arm_names: &[String],
    split: Option<&str>,
    repeats: u32,
    out: &std::path::Path,
    jev_model: &str,
    llm_model: &str,
) -> Result<()> {
    use arms::jev_followup::FollowupClient;
    use arms::llm_followup::LlmFollowupArm;
    use followup_scoring::FollowupRecord;

    let ds = followup::FollowupDataset::load(data)?;
    let want = match split {
        None => None,
        Some("dev") => Some(followup::Split::Dev),
        Some("final") => Some(followup::Split::Final),
        Some(o) => bail!("알 수 없는 split: {o}"),
    };
    let bundles: Vec<&followup::Bundle> = ds
        .bundles
        .iter()
        .filter(|b| want.is_none_or(|w| b.split == w))
        .collect();
    if bundles.is_empty() {
        bail!("실행할 번들이 없습니다");
    }
    let mut jev: Option<FollowupClient> = None;
    let mut llm: Option<LlmFollowupArm> = None;
    let mut rules = false;
    for a in arm_names {
        match a.as_str() {
            "jev" => jev = Some(FollowupClient::from_env(jev_model)?),
            "llm" => llm = Some(LlmFollowupArm::from_config(Some(llm_model))?),
            "rules" => rules = true,
            o => bail!("알 수 없는 비교군: {o}"),
        }
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = std::fs::File::create(out)?;
    let total = bundles.len() * arm_names.len() * repeats as usize;
    let mut done = 0usize;
    for rep in 1..=repeats {
        for b in &bundles {
            let hash = scoring::input_hash(&b.evidence);
            if rules {
                let o = arms::rules_followup::choose(&b.evidence);
                let rec = FollowupRecord {
                    bundle_id: b.id.clone(),
                    split: b.split,
                    arm: "rules".into(),
                    repeat: rep,
                    model: Some(arms::rules_followup::RULES_VERSION.into()),
                    question_version: None,
                    input_sha256: hash.clone(),
                    accepted: b.accepted.clone(),
                    traits: b.traits.clone(),
                    jev: Some(o),
                    llm: None,
                };
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if let Some(c) = &jev {
                let o = c.choose(&b.evidence).await;
                let rec = FollowupRecord {
                    bundle_id: b.id.clone(),
                    split: b.split,
                    arm: "jev".into(),
                    repeat: rep,
                    model: Some(format!("{}@{}", c.model(), c.endpoint_host())),
                    question_version: Some(arms::jev_followup::QUESTION_VERSION.into()),
                    input_sha256: hash.clone(),
                    accepted: b.accepted.clone(),
                    traits: b.traits.clone(),
                    jev: Some(o),
                    llm: None,
                };
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if let Some(a) = &llm {
                let o = a.choose(b.symptom.as_deref(), &b.evidence).await;
                let rec = FollowupRecord {
                    bundle_id: b.id.clone(),
                    split: b.split,
                    arm: "llm".into(),
                    repeat: rep,
                    model: Some(a.identity().to_string()),
                    question_version: None,
                    input_sha256: hash,
                    accepted: b.accepted.clone(),
                    traits: b.traits.clone(),
                    jev: None,
                    llm: Some(o),
                };
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if done.is_multiple_of(5) || done == total {
                eprintln!("  {done}/{total}");
            }
        }
    }
    println!("✔ {done}건을 {}에 기록했습니다", out.display());
    Ok(())
}

/// `aic diagnose --json` 봉투에서 evidence를 꺼낸다. JSON이 아니면 파일 전체를 evidence로 본다.
fn evidence_of(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| {
            v.pointer("/diagnosis/evidence")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| raw.to_string())
}

fn followup_candidates(files: &[PathBuf]) -> Result<()> {
    for f in files {
        let raw = std::fs::read_to_string(f)
            .with_context(|| format!("읽지 못했습니다: {}", f.display()))?;
        let evidence = evidence_of(&raw);
        let secs: Vec<&str> = evidence
            .lines()
            .filter_map(|l| l.strip_prefix("## "))
            .collect();
        println!("=== {} ({} 섹션)", f.display(), secs.len());
        println!("  섹션: {}", secs.join(" "));
        let cands = followup::candidates(&evidence);
        if cands.is_empty() {
            println!("  후보 없음 → follow-up 불필요(none)");
        }
        for (tmpl, args) in &cands {
            println!("  {tmpl}: {}", args.join(", "));
        }
        // 뽑은 후보가 실제 게이트를 통과하는지까지 본다 — 통과하지 못하면 production에서 실행되지 않는다.
        for line in followup::candidate_lines(&evidence) {
            if let Err(e) = aic_client::agent::diagnose::resolve_followup_line(&line, &evidence) {
                println!("  [게이트 거부] {line} — {e}");
            }
        }
        println!();
    }
    Ok(())
}

fn followup_score(results: &std::path::Path) -> Result<()> {
    use followup_scoring::{summarize, FollowupRecord};
    let raw = std::fs::read_to_string(results)
        .with_context(|| format!("결과를 읽지 못했습니다: {}", results.display()))?;
    let records: Vec<FollowupRecord> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    if records.is_empty() {
        bail!("결과가 비어 있습니다");
    }
    let mut arms: Vec<String> = records.iter().map(|r| r.arm.clone()).collect();
    arms.sort();
    arms.dedup();
    println!(
        "{:<6} {:>4} {:>8} {:>8} {:>8} {:>8} {:>8} {:>9} {:>9} {:>8}",
        "비교군",
        "n",
        "top1",
        "top3",
        "none정답",
        "실패율",
        "게이트거부",
        "p50(ms)",
        "p95(ms)",
        "입력토큰"
    );
    for a in &arms {
        let s = summarize(a, &records);
        println!(
            "{:<6} {:>4} {:>8.3} {:>8.3} {:>8.3} {:>8.3} {:>10} {:>9} {:>9} {:>8}",
            s.arm,
            s.n,
            s.top1_correct,
            s.top3_correct,
            s.none_correct,
            s.failure_rate,
            s.gate_reject_rate
                .map_or("-".to_string(), |g| format!("{g:.3}")),
            s.latency_p50_ms,
            s.latency_p95_ms,
            s.total_input_tokens
        );
    }
    println!();
    println!(
        "(top1/top3는 신호 있는 사례 기준, none정답은 신호 없는 사례 기준. 실패는 오답으로 센다.)"
    );
    let repeats = records.iter().map(|r| r.repeat).max().unwrap_or(1);
    if repeats > 1 {
        println!();
        println!("반복 일치율 (같은 번들 {repeats}회, 첫 선택이 전부 같은 비율)");
        for a in &arms {
            match followup_scoring::repeat_agreement(a, &records) {
                Some((rate, n)) => println!("  {a:<6} {rate:.3} (번들 {n}개)"),
                None => println!("  {a:<6} 반복 없음"),
            }
        }
    }
    // trait별 — 어느 계열·함정에서 갈리는지. 1라운드 기록에는 trait이 없어 표가 비어 있다.
    let traits: std::collections::BTreeSet<String> = records
        .iter()
        .flat_map(|r| r.traits.iter().cloned())
        .collect();
    if !traits.is_empty() {
        let per_arm: Vec<(String, followup_scoring::TraitRows)> = arms
            .iter()
            .map(|a| (a.clone(), followup_scoring::by_trait(a, &records)))
            .collect();
        println!();
        println!("trait별 첫 선택 정답 (1회차)");
        for t in &traits {
            let cells: Vec<String> = per_arm
                .iter()
                .map(|(a, rows)| {
                    rows.iter()
                        .find(|(x, _, _)| x == t)
                        .map_or(format!("{a} -"), |(_, c, n)| format!("{a} {c}/{n}"))
                })
                .collect();
            println!("  {t:<28} {}", cells.join("   "));
        }
    }
    // 사례별 대조 — 어디서 갈리는지 보려면 줄 단위가 필요하다.
    println!();
    println!("사례별 (1회차)");
    let mut ids: Vec<&str> = records.iter().map(|r| r.bundle_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let mut cells = Vec::new();
        let mut accepted: &[String] = &[];
        for a in &arms {
            if let Some(r) = records
                .iter()
                .find(|r| r.bundle_id == id && r.arm == *a && r.repeat == 1)
            {
                accepted = &r.accepted;
                let got = match (&r.jev, &r.llm) {
                    (Some(j), _) => j
                        .line
                        .clone()
                        .or_else(|| j.template.clone())
                        .or_else(|| j.error.clone())
                        .unwrap_or_default(),
                    (_, Some(l)) => l.accepted_lines.first().cloned().unwrap_or_else(|| {
                        if l.lines.is_empty() {
                            "(빈 블록)".into()
                        } else {
                            format!("(전부 거부) {}", l.lines[0])
                        }
                    }),
                    _ => String::new(),
                };
                let ok = if accepted.is_empty() {
                    got == "none" || got == "(빈 블록)"
                } else {
                    accepted.contains(&got)
                };
                cells.push(format!("{a}={}{}", if ok { "✔ " } else { "✘ " }, got));
            }
        }
        let truth = if accepted.is_empty() {
            "none".to_string()
        } else {
            accepted.join(" | ")
        };
        println!("  {id:<6} 정답[{truth}]  {}", cells.join("   "));
    }
    Ok(())
}

fn errcause_validate(data: &std::path::Path) -> Result<()> {
    let ds = errcause::ErrCauseDataset::load(data)?;
    let (dev, fin, multi) = ds.counts();
    println!(
        "✔ {} 사례 (dev {dev} / final {fin}), 범주 {}개, 다중 라벨 {multi}건",
        ds.cases.len(),
        ds.categories.len()
    );
    println!("  모든 사례가 production의 결정적 테이블 밖이고 정답이 범주 목록 안에 있습니다.");
    Ok(())
}

async fn errcause_run(
    data: &std::path::Path,
    arm_names: &[String],
    split: Option<&str>,
    repeats: u32,
    out: &std::path::Path,
    jev_model: &str,
    llm_model: &str,
) -> Result<()> {
    use arms::jev_errcause::CauseClient;
    use arms::llm_errcause::LlmCauseArm;
    use errcause_scoring::CauseRecord;

    let ds = errcause::ErrCauseDataset::load(data)?;
    let want = match split {
        None => None,
        Some("dev") => Some(errcause::Split::Dev),
        Some("final") => Some(errcause::Split::Final),
        Some(o) => bail!("알 수 없는 split: {o}"),
    };
    let cases: Vec<&errcause::ErrCase> = ds
        .cases
        .iter()
        .filter(|c| want.is_none_or(|w| c.split == w))
        .collect();
    if cases.is_empty() {
        bail!("실행할 사례가 없습니다");
    }
    let mut jev: Option<CauseClient> = None;
    let mut llm: Option<LlmCauseArm> = None;
    let mut rules = false;
    for a in arm_names {
        match a.as_str() {
            "jev" => jev = Some(CauseClient::from_env(jev_model)?),
            "llm" => llm = Some(LlmCauseArm::from_config(Some(llm_model))?),
            "rules" => rules = true,
            o => bail!("알 수 없는 비교군: {o}"),
        }
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = std::fs::File::create(out)?;
    let total = cases.len() * arm_names.len() * repeats as usize;
    let mut done = 0usize;
    for rep in 1..=repeats {
        for c in &cases {
            let input = errcause::render_input(c);
            let hash = scoring::input_hash(&input);
            let base = |arm: &str, model: Option<String>, qv: Option<String>| CauseRecord {
                case_id: c.id.clone(),
                split: c.split,
                arm: arm.to_string(),
                repeat: rep,
                model,
                question_version: qv,
                input_sha256: hash.clone(),
                accepted: c.accepted.clone(),
                traits: c.traits.clone(),
                jev: None,
                llm: None,
            };
            if rules {
                let started = std::time::Instant::now();
                let picked = arms::rules_errcause::classify(&input);
                let mut rec = base(
                    "rules",
                    Some(arms::rules_errcause::RULES_VERSION.into()),
                    None,
                );
                rec.jev = Some(arms::jev_errcause::CauseOutcome {
                    category: (picked != arms::rules_errcause::UNKNOWN).then(|| picked.to_string()),
                    raw_category: Some(picked.to_string()),
                    attempts: 1,
                    latency_ms: started.elapsed().as_millis() as u64,
                    error: (picked == arms::rules_errcause::UNKNOWN)
                        .then(|| "어느 키워드에도 걸리지 않음".to_string()),
                    ..Default::default()
                });
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if let Some(client) = &jev {
                let o = client.classify(&input, &ds.categories).await;
                let mut rec = base(
                    "jev",
                    Some(format!("{}@{}", client.model(), client.endpoint_host())),
                    Some(arms::jev_errcause::QUESTION_VERSION.into()),
                );
                rec.jev = Some(o);
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if let Some(arm) = &llm {
                let o = arm.classify(&input, &ds.categories).await;
                let mut rec = base("llm", Some(arm.identity().to_string()), None);
                rec.llm = Some(o);
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if done.is_multiple_of(10) || done == total {
                eprintln!("  {done}/{total}");
            }
        }
    }
    println!("✔ {done}건을 {}에 기록했습니다", out.display());
    Ok(())
}

fn errcause_score(results: &std::path::Path) -> Result<()> {
    use errcause_scoring::{summarize, CauseRecord};
    let raw = std::fs::read_to_string(results)
        .with_context(|| format!("결과를 읽지 못했습니다: {}", results.display()))?;
    let records: Vec<CauseRecord> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    if records.is_empty() {
        bail!("결과가 비어 있습니다");
    }
    let mut arms: Vec<String> = records.iter().map(|r| r.arm.clone()).collect();
    arms.sort();
    arms.dedup();
    println!(
        "{:<6} {:>4} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9}",
        "비교군", "n", "정확도", "top3", "기권율", "p50(ms)", "p95(ms)", "입력토큰"
    );
    for a in &arms {
        let s = summarize(a, &records);
        println!(
            "{:<6} {:>4} {:>8.3} {:>8.3} {:>8.3} {:>9} {:>9} {:>9}",
            s.arm,
            s.n,
            s.accuracy,
            s.top3,
            s.abstain_rate,
            s.latency_p50_ms,
            s.latency_p95_ms,
            s.total_input_tokens
        );
    }
    println!();
    println!("(정답 집합에 하나라도 맞으면 정탐. 기권과 목록 밖 응답은 오답으로 센다.)");

    let repeats = records.iter().map(|r| r.repeat).max().unwrap_or(1);
    if repeats > 1 {
        println!();
        println!("반복 일치율 (같은 사례 {repeats}회)");
        for a in &arms {
            match errcause_scoring::repeat_agreement(a, &records) {
                Some((rate, n)) => println!("  {a:<6} {rate:.3} (사례 {n}개)"),
                None => println!("  {a:<6} 반복 없음"),
            }
        }
    }

    println!();
    println!("짝지은 비교 (같은 사례, 1회차)");
    for i in 0..arms.len() {
        for j in (i + 1)..arms.len() {
            let (a, b) = (&arms[i], &arms[j]);
            let (only_a, only_b, both, neither) = errcause_scoring::paired(a, b, &records);
            println!(
                "  {a} vs {b}: {a}만 {only_a} · {b}만 {only_b} · 둘 다 {both} · 둘 다 오답 {neither}"
            );
        }
    }

    println!();
    println!("고른 값별 정밀도 (1회차) — 그 값을 고른 것 중 맞은 비율");
    for a in &arms {
        let rows = errcause_scoring::precision_by_pick(a, &records);
        let cells: Vec<String> = rows
            .iter()
            .map(|(k, c, n)| format!("{k} {c}/{n}"))
            .collect();
        println!("  {a:<6} {}", cells.join(" · "));
    }

    for (title, f) in [
        (
            "범주별 정답",
            errcause_scoring::by_category
                as fn(&str, &[CauseRecord]) -> errcause_scoring::GroupRows,
        ),
        ("trait별 정답", errcause_scoring::by_trait),
    ] {
        let per_arm: Vec<(String, errcause_scoring::GroupRows)> =
            arms.iter().map(|a| (a.clone(), f(a, &records))).collect();
        let keys: std::collections::BTreeSet<String> = per_arm
            .iter()
            .flat_map(|(_, rows)| rows.iter().map(|(k, _, _)| k.clone()))
            .collect();
        if keys.is_empty() {
            continue;
        }
        println!();
        println!("{title} (1회차)");
        for k in keys {
            let cells: Vec<String> = per_arm
                .iter()
                .map(|(a, rows)| {
                    rows.iter()
                        .find(|(x, _, _)| *x == k)
                        .map_or(format!("{a} -"), |(_, c, n)| format!("{a} {c}/{n}"))
                })
                .collect();
            println!("  {k:<18} {}", cells.join("   "));
        }
    }
    Ok(())
}

fn intent_validate(data: &std::path::Path) -> Result<()> {
    let ds = intent::IntentDataset::load(data)?;
    let (dev, fin, multi) = ds.counts();
    println!(
        "✔ {} 사례 (dev {dev} / final {fin}), 경로 {}개, 다중 라벨 {multi}건",
        ds.cases.len(),
        ds.categories.len()
    );
    Ok(())
}

async fn intent_generate(data: &std::path::Path, per_intent: usize, model: &str) -> Result<()> {
    use arms::llm_errcause::LlmCauseArm;
    let mut ds = intent::IntentDataset::load(data)?;
    // 다시 생성하면 최종 분할을 통째로 바꾼다. 일부만 바꾸면 어느 문장이 어느 실행에서 왔는지 흐려진다.
    ds.cases.retain(|c| c.split == intent::Split::Dev);
    let gen = LlmCauseArm::from_config(Some(model))?;
    let mut seen: std::collections::BTreeSet<String> = ds
        .cases
        .iter()
        .map(|c| intent::normalize(&c.text))
        .collect();
    let routes: Vec<(String, String)> = ds
        .categories
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (route, def) in &routes {
        let others = routes
            .iter()
            .filter(|(k, _)| k != route)
            .map(|(k, v)| format!("- {k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let raw = gen
            .complete(&intent::generation_prompt(route, def, &others, per_intent))
            .await?;
        let texts = intent::parse_generated(&raw)
            .with_context(|| format!("{route}: 생성 응답을 읽지 못했습니다"))?;
        let mut kept = 0usize;
        let mut dup = 0usize;
        for t in texts {
            if !seen.insert(intent::normalize(&t)) {
                dup += 1;
                continue;
            }
            let lang = if t.is_ascii() { "en" } else { "ko" };
            let id = format!("in-{}", &scoring::input_hash(&t)[..8]);
            ds.cases.push(intent::IntentCase {
                id,
                split: intent::Split::Final,
                text: t,
                accepted: vec![route.clone()],
                traits: vec![format!("lang:{lang}"), "generated".into()],
                source: format!("generated:{model}"),
            });
            kept += 1;
        }
        // 문장 자체는 출력하지 않는다 — 규칙을 쓴 사람이 최종 분할을 읽으면 블라인드가 깨진다.
        println!("  {route:<13} 생성 {kept}건 (중복 제외 {dup}건)");
    }
    ds.save(data)?;
    let (dev, fin, _) = ds.counts();
    println!("✔ 저장: dev {dev} / final {fin}");
    Ok(())
}

async fn intent_run(
    data: &std::path::Path,
    arm_names: &[String],
    split: Option<&str>,
    repeats: u32,
    out: &std::path::Path,
    jev_model: &str,
    llm_model: &str,
) -> Result<()> {
    use arms::jev_errcause::{CauseClient, CauseOutcome};
    use arms::llm_errcause::LlmCauseArm;
    use errcause_scoring::CauseRecord;

    let ds = intent::IntentDataset::load(data)?;
    let want = match split {
        None => None,
        Some("dev") => Some(intent::Split::Dev),
        Some("final") => Some(intent::Split::Final),
        Some(o) => bail!("알 수 없는 split: {o}"),
    };
    let cases: Vec<&intent::IntentCase> = ds
        .cases
        .iter()
        .filter(|c| want.is_none_or(|w| c.split == w))
        .collect();
    if cases.is_empty() {
        bail!("실행할 사례가 없습니다");
    }
    let mut jev: Option<CauseClient> = None;
    let mut llm: Option<LlmCauseArm> = None;
    let mut rules = false;
    for a in arm_names {
        match a.as_str() {
            "jev" => jev = Some(CauseClient::from_env(jev_model)?),
            "llm" => llm = Some(LlmCauseArm::from_config(Some(llm_model))?),
            "rules" => rules = true,
            o => bail!("알 수 없는 비교군: {o}"),
        }
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = std::fs::File::create(out)?;
    let total = cases.len() * arm_names.len() * repeats as usize;
    let mut done = 0usize;
    for rep in 1..=repeats {
        for c in &cases {
            let hash = scoring::input_hash(&c.text);
            let base = |arm: &str, model: Option<String>| CauseRecord {
                case_id: c.id.clone(),
                split: c.split,
                arm: arm.to_string(),
                repeat: rep,
                model,
                question_version: Some("intent-v1".into()),
                input_sha256: hash.clone(),
                accepted: c.accepted.clone(),
                traits: c.traits.clone(),
                jev: None,
                llm: None,
            };
            if rules {
                let started = std::time::Instant::now();
                let picked = arms::rules_intent::classify(&c.text);
                let mut rec = base("rules", Some(arms::rules_intent::RULES_VERSION.into()));
                rec.jev = Some(CauseOutcome {
                    category: Some(picked.to_string()),
                    raw_category: Some(picked.to_string()),
                    attempts: 1,
                    latency_ms: started.elapsed().as_millis() as u64,
                    ..Default::default()
                });
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if let Some(client) = &jev {
                let o = client
                    .classify_with(&ds.instructions, &c.text, &ds.categories)
                    .await;
                let mut rec = base(
                    "jev",
                    Some(format!("{}@{}", client.model(), client.endpoint_host())),
                );
                rec.jev = Some(o);
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if let Some(arm) = &llm {
                let o = arm
                    .classify_with(&ds.instructions, "채팅 입력", &c.text, &ds.categories)
                    .await;
                let mut rec = base("llm", Some(arm.identity().to_string()));
                rec.llm = Some(o);
                writeln!(file, "{}", serde_json::to_string(&rec)?)?;
                done += 1;
            }
            if done.is_multiple_of(20) || done == total {
                eprintln!("  {done}/{total}");
            }
        }
    }
    println!("✔ {done}건을 {}에 기록했습니다", out.display());
    Ok(())
}
