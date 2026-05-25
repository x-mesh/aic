use aic_client::auto_brancher::{AutoBrancher, ExecutionMode};
use aic_client::cache;
use aic_client::config::ConfigManager;
use aic_client::error_analyzer::{clean_output_lines, ErrorAnalyzer};
use aic_client::llm_dispatcher::LlmDispatcher;
use aic_client::local_record;
use aic_client::repl::ReplSession;
use aic_client::uds_client::{ReadCascade, UdsClient};
use aic_common::{
    AicError, AnalysisResult, AppConfig, BoundaryStrategyConfig, LlmConfig, ProviderConfig,
    ProviderType, ServerConfig,
};
use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;
use unicode_width::UnicodeWidthStr;

// ── ANSI 색상 상수 ─────────────────────────────────────────────
const COL_RESET: &str = "\x1b[0m";
const COL_BOLD: &str = "\x1b[1m";
const COL_DIM: &str = "\x1b[90m";
const COL_CYAN: &str = "\x1b[36m";
const COL_GREEN: &str = "\x1b[32m";
const COL_YELLOW: &str = "\x1b[33m";
const COL_BLUE: &str = "\x1b[34m";
const COL_RED: &str = "\x1b[31m";

/// 디버그 모드 확인 (AIC_DEBUG 환경변수)
fn is_debug_mode() -> bool {
    env_flag("AIC_DEBUG")
}

/// 불리언 환경변수 판정 — `1` 또는 `true`(대소문자 무시)면 true.
fn env_flag(name: &str) -> bool {
    // 공통 semantics: trim + case-insensitive로 `1`/`true`만 ON(그 외/unset=OFF).
    // (lib의 `agent::debug::env_truthy`는 pub(crate)라 bin에서 못 쓰므로 동일 규칙을 둔다.)
    std::env::var(name)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true"
        })
        .unwrap_or(false)
}

/// `aic chat`에서 run_command(SRE 실행) 활성 여부를 결정한다.
///
/// 기본 활성. `--no-run`/`--read-only`(read_only_flag) 또는 env `AIC_AGENT_NO_RUN`
/// (env_no_run)으로 opt-out하면 비활성. 보안 게이트는 별개로 항상 적용된다.
fn chat_run_command_enabled(read_only_flag: bool, env_no_run: bool) -> bool {
    !(read_only_flag || env_no_run)
}

/// 첫 디버그 호출 시점을 캐시하고, 그 시점부터의 누적 경과 시간(초)을 반환한다.
fn debug_elapsed_secs() -> f64 {
    static DEBUG_START: OnceLock<Instant> = OnceLock::new();
    DEBUG_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_secs_f64()
}

/// debug 로그에 ANSI 색상을 쓸지 — `NO_COLOR` 미설정 && stderr TTY일 때만.
/// (agent UI 색상 정책과 동일.)
fn debug_color() -> bool {
    use std::io::IsTerminal;
    std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

/// 단순 디버그 정보 라인 — `[debug +0.001s] <message>` (TTY+색상 시 흐린 회색).
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if is_debug_mode() {
            let t = debug_elapsed_secs();
            let body = format!("[debug +{:.3}s] {}", t, format!($($arg)*));
            if debug_color() {
                eprintln!("\x1b[90m{}\x1b[0m", body);
            } else {
                eprintln!("{}", body);
            }
        }
    };
}

/// 정보와 측정 시간을 한 라인으로 출력 — `[debug +0.001s] <message> (1.23ms)`.
macro_rules! debug_step {
    ($start:expr, $($arg:tt)*) => {
        if is_debug_mode() {
            let elapsed = $start.elapsed();
            let t = debug_elapsed_secs();
            let msg = format!($($arg)*);
            let body = format!("[debug +{:.3}s] {} ({:.2}ms)", t, msg, elapsed.as_secs_f64() * 1000.0);
            if debug_color() {
                eprintln!("\x1b[90m{}\x1b[0m", body);
            } else {
                eprintln!("{}", body);
            }
        }
    };
}

/// 문자열을 지정된 너비로 분할 (유니코드 너비 고려, 단어 경계 우선)
fn split_at_width(s: &str, max_width: usize) -> (&str, &str) {
    if s.is_empty() || max_width == 0 {
        return (s, "");
    }

    if s.width() <= max_width {
        return (s, "");
    }

    let mut width = 0;
    let mut split_idx = 0;
    let mut last_space_idx = 0;
    let mut last_space_width = 0;

    for (idx, ch) in s.char_indices() {
        let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(1);

        // 공백 위치 기록 (단어 경계)
        if ch.is_whitespace() {
            last_space_idx = idx;
            last_space_width = width;
        }

        if width + ch_width > max_width {
            // 단어 경계가 있으면 그 위치에서 분할
            if last_space_idx > 0 && last_space_width > max_width / 3 {
                return (&s[..last_space_idx], s[last_space_idx..].trim_start());
            }
            // 단어 경계가 없으면 현재 위치에서 분할
            if split_idx == 0 {
                split_idx = idx + ch.len_utf8();
            }
            break;
        }
        width += ch_width;
        split_idx = idx + ch.len_utf8();
    }

    if split_idx == 0 {
        return (s, "");
    }

    (&s[..split_idx], &s[split_idx..])
}

#[derive(Parser)]
#[command(name = "aic", version, about = "지능형 CLI 도우미")]
struct Cli {
    /// 직접 질문하기 (예: aic "이 에러 어떻게 해결해?")
    #[arg(trailing_var_arg = true)]
    prompt: Vec<String>,

    /// 실제 LLM 호출 없이 추정 토큰·비용·timeout만 미리보기
    #[arg(long)]
    dry_run: bool,

    /// 사용할 provider 이름 — config의 `default_provider`를 1회 override한다.
    /// 환경변수 `AIC_PROVIDER`로도 지정 가능. 두 값이 모두 있으면 CLI 플래그가 우선한다.
    #[arg(long, env = "AIC_PROVIDER", global = true)]
    provider: Option<String>,

    /// 분석 대상 record를 id prefix로 명시 (P1).
    ///
    /// `aic history`로 본 8자 prefix를 그대로 사용하면 된다. 일치하는 record가
    /// 0건/2건 이상이면 명시적 에러를 낸다.
    #[arg(long = "record", value_name = "PREFIX")]
    record_prefix: Option<String>,

    /// 분석 대상 record 선택 시 참조할 세션 ID 명시 (기본: AIC_SESSION_ID env > 최신 세션).
    #[arg(long)]
    session: Option<String>,

    /// 직접 질문 흐름에 project context pack을 함께 첨부 (P3 'aic ask --context').
    ///
    /// 에러 record 없이도 "이 프로젝트에서 …" 같은 질문에 repo branch/runtime/
    /// dirty 요약 등이 같이 LLM에 전달된다.
    #[arg(long)]
    context: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 설정 파일 경로 및 현재 설정 표시/편집
    Config {
        #[command(subcommand)]
        op: Option<ConfigOp>,
    },
    /// 환경 진단 — config / 데몬 / 셸 hook / LLM endpoint 상태를 점검
    Doctor {
        /// 결과를 JSON으로 출력 (CI/스크립트 친화)
        #[arg(long)]
        json: bool,
        /// 특정 세션 ID를 명시적으로 점검 (기본: AIC_SESSION_ID env > 최신 세션 > legacy)
        #[arg(long, value_name = "ID")]
        session: Option<String>,
        /// 진단 후 자동 수정 시도 (P2 'doctor --fix'). aicd 시작/hook 재생성/
        /// stale session cleanup/registry prune을 순서대로 시도한다.
        #[arg(long)]
        fix: bool,
        /// `--fix`와 함께 사용. 실제 변경 없이 적용될 작업만 출력.
        #[arg(long)]
        dry_run: bool,
        /// opt-in tool-calling live probe (GA Gate G1). 설정된 provider에 최소 tool spec으로
        /// `send_messages`를 1회 보내 ok/unsupported/degraded/error를 진단한다.
        /// credential/network 없으면 명확히 skip/fail. 세션 시작 시 자동 수행하지 않는다.
        #[arg(long)]
        probe_tools: bool,
    },
    /// 데몬 상태 표시 — PID, ping, 마지막 명령어 요약
    Status {
        /// `--watch` 라이브 모드 — interval(초)마다 갱신, Ctrl+C로 종료
        #[arg(long, short = 'w')]
        watch: bool,
        /// watch 갱신 간격(초). 기본 1
        #[arg(long, default_value = "1")]
        interval: u64,
        /// 특정 세션 ID 명시 (기본: AIC_SESSION_ID env > 최신 세션)
        #[arg(long, value_name = "ID")]
        session: Option<String>,
        /// JSON 출력 (CI/스크립트 친화). watch 모드와 함께 쓸 수 없음.
        #[arg(long)]
        json: bool,
        /// 모든 활성 세션을 한 번에 표시 (sessions list 동작과 결합)
        #[arg(long)]
        all: bool,
    },
    /// Audit log 관리 (HMAC chain 무결성 검증)
    Audit {
        #[command(subcommand)]
        op: AuditOp,
    },
    /// config.toml의 평문 API key를 OS keychain으로 일괄 이동
    MigrateKeys,
    /// 셸 hook 자동 설치 — `~/.zshrc`/`~/.bashrc`에 source 라인을 멱등 추가
    Init {
        /// 셸 종류 (자동 감지: $SHELL)
        #[arg(value_parser = ["zsh", "bash"])]
        shell: Option<String>,
        /// Phase 3 metadata-only hook(`~/.aic/hook-events.{zsh,bash}`)을 함께 설치한다.
        /// PTY hook과 충돌하지 않으며, aicd가 떠 있을 때만 실제로 동작한다.
        #[arg(long)]
        hook_mode: bool,
    },
    /// 데몬 라이브 모니터링 — `aic status --watch` alias (interval 1s)
    Top {
        /// 갱신 간격(초). 기본 1
        #[arg(long, default_value = "1")]
        interval: u64,
        /// 특정 세션 ID 명시 (기본: AIC_SESSION_ID env > 최신 세션)
        #[arg(long, value_name = "ID")]
        session: Option<String>,
    },
    /// 실행 중인 세션 목록 조회
    Sessions {
        /// JSON 출력 (CI/스크립트 친화)
        #[arg(long)]
        json: bool,
        /// 라인 모드 TUI로 세션을 골라 action을 실행 (status/last/analyze/stop) — P2.
        #[arg(long, conflicts_with = "json")]
        interactive: bool,
    },
    /// SSH 멀티호스트 인벤토리 조회 (RFC-005 Phase 1) — `~/.aic/hosts.toml`과
    /// `~/.ssh/config` import + overlay 결과를 표시. 실제 SSH 호출은 Phase 2 이후.
    Hosts {
        #[command(subcommand)]
        op: HostsOp,
    },
    /// `run_command` tokenizer 화이트리스트 조회·검사 (RFC-005 Phase 6, O3).
    /// builtin(8) + `~/.aic/whitelist.toml` user 확장 + path_guard 연결.
    Whitelist {
        #[command(subcommand)]
        op: WhitelistOp,
    },
    /// 첫 사용 통합 가이드 — config + init + migrate-keys + doctor 순으로 안내
    Setup {
        /// 셸 종류 (자동 감지: $SHELL)
        #[arg(value_parser = ["zsh", "bash"])]
        shell: Option<String>,
    },
    /// 진단 번들 출력 — redacted config / doctor / sessions / server log tail / cache stats를
    /// JSON으로 묶어 stdout에 한 번에 출력. 이슈 리포팅 용도.
    Debug {
        #[command(subcommand)]
        op: DebugOp,
    },
    /// 셀프 업데이트 — 설치 출처(brew/manual/cargo)를 감지해 적절히 처리한다.
    Update {
        /// 다운로드 없이 신버전 존재 여부만 확인. 최신이면 exit 0, 신버전이면 exit 1.
        #[arg(long)]
        check: bool,
        /// 동일 버전이어도 강제 재설치.
        #[arg(long)]
        force: bool,
        /// 특정 tag으로 고정 (예: `v0.3.1`). manual install에만 적용.
        #[arg(long, value_name = "TAG")]
        to: Option<String>,
    },
    /// aicd supervisor daemon 관리 (Phase 1.5).
    Daemon {
        #[command(subcommand)]
        op: DaemonOp,
    },
    /// 세션 lifecycle 제어 (Phase 2.1).
    Session {
        #[command(subcommand)]
        op: SessionOp,
    },
    /// (internal) shell hook이 호출하는 metadata-only 이벤트 송신 (Phase 3).
    /// 사용자 직접 호출 용도가 아니다 — `~/.aic/hook-events.{zsh,bash}`가 백그라운드로 실행한다.
    #[command(name = "_hook-event", hide = true)]
    HookEvent {
        #[command(subcommand)]
        op: HookEventOp,
    },
    /// 명시적 capture wrapper (Phase 3.3) — hook mode에서도 정확한 출력을 잡고 싶을 때.
    ///
    /// `aic run -- <cmd...>`로 실행하면 wrapper가 stdout/stderr tail을 캡처하고
    /// FullOutput 품질의 record로 분석 흐름에 등록한다. exit code는 wrapped 명령의
    /// 결과를 그대로 보존한다.
    Run {
        /// 실행할 명령어와 인자. `--` 뒤에 그대로 전달.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
        cmd: Vec<String>,
    },
    /// LLM과 대화 — 질문을 주면 1회 답변, 생략하면 대화형 REPL로 진입.
    ///
    /// `aic chat "질문"` → 1회성 답변 후 종료(도구 없음, 단발 답변).
    /// `aic chat` (인자 없음) → 대화형 REPL. exit code와 무관하게 항상 대화형으로
    /// 진입하며, 직전 명령 record가 있으면 best-effort로 첫 턴 context에 첨부한다.
    /// **tools(read_file/list_dir/grep/glob)와 run_command는 인자 없는 대화형 모드에서만
    /// 동작한다.**
    Chat {
        /// 질문 (생략 시 대화형 REPL).
        #[arg(trailing_var_arg = true)]
        prompt: Vec<String>,
        /// 실제 LLM 호출 없이 추정 토큰·비용·timeout만 미리보기.
        #[arg(long)]
        dry_run: bool,
        /// 1회성 질문 흐름에 project context pack을 함께 첨부 (P3).
        #[arg(long)]
        context: bool,
        /// 읽기 전용 모드 — 대화형 `aic chat`에서 run_command(셸 실행)를 끄고
        /// read_file/list_dir/grep/glob만 노출한다. 기본은 run_command 활성(SRE).
        /// env: AIC_AGENT_NO_RUN(=1|true). 다시 켜려면 이 플래그를 빼고 env도 unset/0.
        #[arg(long)]
        no_run: bool,
        /// `--no-run` 동의어(읽기 전용 도구만).
        #[arg(long)]
        read_only: bool,
        /// (호환) SRE 모드 명시. run_command는 이제 기본 활성이라 사실상 no-op.
        #[arg(long)]
        sre: bool,
        /// (호환) run_command 실행 허용 명시. 기본 활성이라 no-op. 끄려면 `--no-run`.
        #[arg(long)]
        allow_run: bool,
    },
    /// 세션 ring buffer의 최근 command record 목록 조회 (P1).
    ///
    /// 우선 source는 PTY 세션의 ring buffer. hook-only metadata record는
    /// 별도 store(aicd hook-event)에 있어 향후 통합 예정.
    History {
        /// 표시할 최대 record 수 (기본 20).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// non-zero exit만 표시.
        #[arg(long)]
        failed: bool,
        /// JSON 출력 (CI/스크립트 친화).
        #[arg(long)]
        json: bool,
        /// 특정 세션 ID 명시 (기본: AIC_SESSION_ID env > 최신 세션).
        #[arg(long)]
        session: Option<String>,
    },
    /// 가장 최근 command record를 한 건 표시 (P1).
    ///
    /// `aic` 기본 흐름이 분석을 트리거한다면, `aic last`는 분석 없이 record만
    /// 빠르게 확인하는 비용 0 명령이다.
    Last {
        /// JSON 출력.
        #[arg(long)]
        json: bool,
        /// 특정 세션 ID 명시.
        #[arg(long)]
        session: Option<String>,
    },
    /// hook mode metadata-only record를 risk_guard 통과 후 explicit capture로 재실행 (P1).
    ///
    /// 마지막 record의 command를 `$SHELL -c`로 다시 실행해 stdout/stderr tail을
    /// 잡는다. risk_guard가 Dangerous/Unknown으로 판정한 명령은 거부하고,
    /// NeedsConfirm은 사용자 확인을 받는다. `--yes`는 Safe 등급에만 효과가 있다.
    CaptureLast {
        /// Safe 등급에서만 자동 진행. NeedsConfirm/Dangerous에는 영향이 없다.
        #[arg(long)]
        yes: bool,
        /// 특정 세션 ID 명시.
        #[arg(long)]
        session: Option<String>,
    },
    /// 분석 결과의 suggested_command를 risk_guard 검증 후 실행 (P1 'aic fix').
    ///
    /// 사용 흐름: 먼저 `aic`로 분석을 한 번 돌려 cache/deterministic 결과를
    /// 만들어둔 뒤, `aic fix`로 그 제안 명령을 안전하게 적용한다.
    /// 명령 실행만 지원한다 — 파일 패치(diff)는 향후 슬라이스에서.
    Fix {
        /// 분석 대상 record의 id prefix. 미지정 시 마지막 record.
        #[arg(long, value_name = "PREFIX")]
        record: Option<String>,
        /// Safe 등급에서만 자동 진행.
        #[arg(long)]
        yes: bool,
        /// 실제 실행 없이 plan(record/analysis/suggested/risk)만 출력.
        #[arg(long)]
        dry_run: bool,
        /// 특정 세션 ID 명시.
        #[arg(long)]
        session: Option<String>,
    },
    /// 세션 ring buffer를 polling해 실패 시 비침습 hint를 출력한다 (P2).
    ///
    /// LLM 호출 없이 deterministic_result만 사용한다. 기본은 다른 터미널에서
    /// 백그라운드로 실행하는 용도 — `aic watch &` 또는 tmux pane.
    /// Ctrl-C로 중단한다.
    Watch {
        /// polling 간격(초). 기본 2초.
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// 특정 세션 ID 명시.
        #[arg(long)]
        session: Option<String>,
    },
    /// 직전 분석 결과를 local recipe로 저장 (P2 'aic learn').
    ///
    /// 같은 fingerprint 에러가 다시 일어나면 LLM 호출 전 학습된 recipe를 먼저
    /// 보여준다. recipe 데이터는 `~/.local/share/aic/recipes.json`에 저장된다.
    Learn {
        /// 분석 대상 record id prefix (기본: 마지막 record).
        #[arg(long, value_name = "PREFIX")]
        record: Option<String>,
        /// 사용자 메모 — recipe와 함께 저장된다.
        #[arg(long)]
        note: Option<String>,
        /// 특정 세션 ID 명시.
        #[arg(long)]
        session: Option<String>,
    },
    /// 학습된 recipe 관리 (P2).
    Recipes {
        #[command(subcommand)]
        op: RecipesOp,
    },
    /// 분석 결과의 품질 피드백 (P3 'Solution Feedback').
    ///
    /// `worked`/`not-worked`/`irrelevant`로 평가한다. `worked`는 자동으로 recipe로
    /// 승격되어 다음 동일 fingerprint 발생 시 LLM 호출 없이 적용된다.
    /// `not-worked`는 기존 recipe가 있으면 삭제한다.
    Feedback {
        /// 평가 — worked/not-worked/irrelevant.
        #[arg(value_parser = ["worked", "not-worked", "irrelevant"])]
        verdict: String,
        /// 분석 대상 record id prefix (기본: 마지막 record).
        #[arg(long, value_name = "PREFIX")]
        record: Option<String>,
        /// 사용자 메모.
        #[arg(long)]
        note: Option<String>,
        /// 특정 세션 ID 명시.
        #[arg(long)]
        session: Option<String>,
    },
}

#[derive(Subcommand)]
enum RecipesOp {
    /// 저장된 recipe 목록을 표시.
    List {
        /// JSON 출력.
        #[arg(long)]
        json: bool,
    },
    /// fingerprint prefix로 recipe를 표시.
    Show {
        /// fingerprint 또는 prefix.
        prefix: String,
    },
    /// fingerprint prefix로 recipe를 삭제.
    Delete {
        /// fingerprint 또는 prefix.
        prefix: String,
    },
}

#[derive(Subcommand)]
enum HookEventOp {
    /// preexec/DEBUG-trap에서 발화 — command 시작 metadata 전송.
    Start {
        #[arg(long)]
        session: String,
        #[arg(long = "command-id")]
        command_id: String,
        #[arg(long)]
        command: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        shell: Option<String>,
        #[arg(long)]
        pid: u32,
    },
    /// precmd/PROMPT_COMMAND에서 발화 — command 종료 metadata 전송.
    End {
        #[arg(long)]
        session: String,
        #[arg(long = "command-id")]
        command_id: String,
        #[arg(long)]
        exit: i32,
        #[arg(long = "duration-ms", default_value = "0")]
        duration_ms: u64,
    },
}

#[derive(Subcommand)]
enum SessionOp {
    /// 특정 세션에 graceful 종료(SIGTERM)를 보낸다.
    Stop {
        /// 세션 ID (8자 lowercase hex)
        id: String,
    },
    /// 오래된 inactive(detached/stopping/stopped/failed) 세션을 registry에서 제거한다.
    Prune {
        /// 이 시간보다 오래된 inactive 세션 제거. 기본 1h.
        #[arg(long, default_value = "3600")]
        older_than_secs: u64,
    },
    /// 세션에 사용자 label을 부여한다 (status/sessions에 표시).
    Tag {
        /// 세션 ID (8자 lowercase hex).
        id: String,
        /// label 텍스트. 빈 문자열은 untag와 동일.
        label: String,
    },
    /// 세션 label을 제거한다.
    Untag {
        /// 세션 ID.
        id: String,
    },
}

#[derive(Subcommand)]
enum DaemonOp {
    /// aicd가 실행 중인지 확인하고 PID/socket을 출력한다.
    Status,
    /// aicd를 시작한다 (이미 실행 중이면 no-op).
    Start {
        /// 현재 터미널에 붙여 실행한다. aicd 디버깅용.
        #[arg(long)]
        foreground: bool,
    },
    /// aicd에 graceful Shutdown을 요청한다.
    Stop,
    /// 부팅 시 자동 시작용 OS unit을 설치한다 (macOS launchd / Linux systemd --user).
    Install {
        /// unit 파일만 쓰고 launchctl/systemctl load는 하지 않는다.
        #[arg(long)]
        no_load: bool,
    },
    /// 자동 시작 unit을 unload + 제거한다.
    Uninstall,
}

#[derive(Subcommand)]
enum DebugOp {
    /// 진단 번들을 JSON으로 출력
    Bundle,
}

#[derive(Subcommand)]
enum AuditOp {
    /// HMAC chain 무결성 검증 (exit 0=pass, 2=tampered, 3=key/IO error)
    Verify,
    /// 멀티호스트 batch audit segment 무결성 검증 (RFC-005 §4.6, O2).
    /// `~/.aic/audit/YYYY-MM-DD.jsonl` 파일의 SHA256 chain을 재계산해 검증한다.
    /// 인자 없으면 모든 segment 검증, `--date`로 특정 일자만.
    BatchVerify {
        /// 특정 일자(YYYY-MM-DD)만 검증. 생략 시 모든 segment.
        #[arg(long)]
        date: Option<String>,
    },
}

#[derive(Subcommand)]
enum HostsOp {
    /// 인벤토리 표시 — `~/.aic/hosts.toml` + `~/.ssh/config` import + overlay 적용 결과.
    /// 이름 인자가 없으면 전체 호스트·그룹 목록, 있으면 단일 호스트의 최종 해석값
    /// (어느 필드가 어느 source에서 왔는지) + ssh_config 위임 경고를 표시한다.
    Show {
        /// 단일 호스트 이름. 생략 시 전체 인벤토리.
        name: Option<String>,
        /// JSON 출력(머신 파싱 친화). 디버깅 surface.
        #[arg(long)]
        json: bool,
    },
    /// 단일 호스트 또는 그룹(`@group`)에 ssh로 read-only 명령을 실행한다.
    /// Phase 2: 단일 호스트. Phase 3: `@group` fan-out (cap + 3-layer timeout + 카드 stack).
    /// BatchMode=yes + ForwardAgent=no + ControlMaster=auto.
    Ping {
        /// 호스트 이름 또는 `@group` 패턴. hosts.toml `name`/`groups.X` 또는 ssh_config Host.
        target: String,
        /// 실행할 read-only 명령(공백 분리 인자). 기본 `uptime`.
        #[arg(long, default_value = "uptime")]
        cmd: String,
    },
    /// 신규 호스트의 host key를 ssh-keyscan으로 수집해 SHA256 fingerprint를 노출하고,
    /// 승인 시 `~/.ssh/known_hosts`에 append한다 (RFC-005 §4.1 TOFU 4-step의 step 2~4).
    /// BatchMode=yes로 인해 ssh 자체 prompt가 차단되어 신규 호스트는 `[auth_fail]`로
    /// 떨어지는데, 이 명령으로 명시 trust 후 `aic hosts ping`을 재시도한다. chat TUI의
    /// 자동 confirm flow는 후속(1.1).
    Trust {
        /// 호스트 이름(hosts.toml `name` 또는 ssh_config Host).
        name: String,
        /// ssh-keyscan timeout 초. 기본 5.
        #[arg(long, default_value = "5")]
        timeout_secs: u32,
        /// 비-TTY/스크립트 환경에서 prompt 없이 자동 승인. 보안 주의 — MITM 위험.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum WhitelistOp {
    /// builtin + user(`~/.aic/whitelist.toml`) 화이트리스트 program 목록 표시.
    Status,
    /// 단일 명령(공백 분리)을 4단 게이트(shell metachar / program allowlist /
    /// path_guard / allowed_args 규칙)로 검사하고 Allowed/Blocked + 이유를 출력.
    Check {
        /// 예: `"ps aux"`, `"cat /etc/shadow"`. 따옴표로 감싸 단일 인자로.
        cmd: String,
    },
}

#[derive(Subcommand)]
enum ConfigOp {
    /// 현재 설정을 비-인터랙티브로 출력 (기본 TOML, `--json`도 가능). API key는 마스킹된다.
    Show {
        /// JSON 형식으로 출력
        #[arg(long)]
        json: bool,
        /// 마스킹 없이 raw 값(api_key 포함) 출력. 외부 자동화/디버깅 용도.
        #[arg(long)]
        show_secrets: bool,
    },
    /// dotted path로 단일 값 추출 (예: `aic config get llm.default_provider`)
    Get {
        /// dot으로 구분된 path (예: `llm.default_provider`, `server.max_buffer_lines`)
        path: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Config { op }) => match op {
            None => handle_config(),
            Some(ConfigOp::Show { json, show_secrets }) => handle_config_show(json, show_secrets),
            Some(ConfigOp::Get { path }) => handle_config_get(&path),
        },
        Some(Commands::Doctor {
            json,
            session,
            fix,
            dry_run,
            probe_tools,
        }) => {
            if probe_tools {
                handle_doctor_probe_tools(cli.provider).await;
            } else if fix {
                handle_doctor_fix(dry_run).await;
            } else {
                handle_doctor(json, session).await;
            }
        }
        Some(Commands::Status {
            watch,
            interval,
            session,
            json,
            all,
        }) => handle_status(watch, interval, session, json, all).await,
        Some(Commands::Hosts { op }) => match op {
            HostsOp::Show { name, json } => handle_hosts_show(name, json),
            HostsOp::Ping { target, cmd } => handle_hosts_ping(target, cmd).await,
            HostsOp::Trust {
                name,
                timeout_secs,
                yes,
            } => handle_hosts_trust(name, timeout_secs, yes).await,
        },
        Some(Commands::Whitelist { op }) => match op {
            WhitelistOp::Status => handle_whitelist_status(),
            WhitelistOp::Check { cmd } => handle_whitelist_check(cmd),
        },
        Some(Commands::Audit { op }) => match op {
            AuditOp::Verify => handle_audit_verify(),
            AuditOp::BatchVerify { date } => handle_audit_batch_verify(date),
        },
        Some(Commands::MigrateKeys) => handle_migrate_keys(),
        Some(Commands::Init { shell, hook_mode }) => handle_init(shell, hook_mode),
        Some(Commands::Top { interval, session }) => handle_top(interval, session).await,
        Some(Commands::Daemon { op }) => match op {
            DaemonOp::Status => handle_daemon_status().await,
            DaemonOp::Start { foreground } => handle_daemon_start(foreground).await,
            DaemonOp::Stop => handle_daemon_stop().await,
            DaemonOp::Install { no_load } => handle_daemon_install(no_load),
            DaemonOp::Uninstall => handle_daemon_uninstall(),
        },
        Some(Commands::Session { op }) => match op {
            SessionOp::Stop { id } => handle_session_stop(id).await,
            SessionOp::Prune { older_than_secs } => handle_session_prune(older_than_secs).await,
            SessionOp::Tag { id, label } => handle_session_tag(id, Some(label)).await,
            SessionOp::Untag { id } => handle_session_tag(id, None).await,
        },
        Some(Commands::HookEvent { op }) => handle_hook_event(op).await,
        Some(Commands::Run { cmd }) => handle_run(cmd, cli.provider).await,
        Some(Commands::Chat {
            prompt,
            dry_run,
            context,
            no_run,
            read_only,
            sre,
            allow_run,
        }) => {
            // 레거시 호환 안내(1회): --sre/--allow-run은 이제 no-op(run_command 기본 활성).
            if sre || allow_run {
                eprintln!(
                    "\x1b[2m[aic] 안내: run_command/tools는 인자 없는 대화형 `aic chat`에서만 \
                     동작하며 이제 기본 활성입니다. `--sre`/`--allow-run`은 호환용 no-op이고, \
                     끄려면 `--no-run`(또는 AIC_AGENT_NO_RUN=1). 1회성 `aic chat \"질문\"`은 \
                     도구 없이 단발 답변만 합니다.\x1b[0m"
                );
            }
            if let Err(e) =
                handle_chat(prompt, dry_run, cli.provider, context, no_run || read_only).await
            {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Some(Commands::History {
            limit,
            failed,
            json,
            session,
        }) => aic_client::history::run(session, limit, failed, json).await,
        Some(Commands::Last { json, session }) => handle_last(json, session).await,
        Some(Commands::CaptureLast { yes, session }) => {
            handle_capture_last(yes, session, cli.provider).await
        }
        Some(Commands::Fix {
            record,
            yes,
            dry_run,
            session,
        }) => handle_fix(record, yes, dry_run, session, cli.provider).await,
        Some(Commands::Watch { interval, session }) => handle_watch(interval, session).await,
        Some(Commands::Learn {
            record,
            note,
            session,
        }) => handle_learn(record, note, session).await,
        Some(Commands::Recipes { op }) => handle_recipes(op),
        Some(Commands::Feedback {
            verdict,
            record,
            note,
            session,
        }) => handle_feedback(verdict, record, note, session).await,
        Some(Commands::Sessions { json, interactive }) => {
            if interactive {
                handle_sessions_interactive().await;
            } else if json {
                print_sessions_json().await;
            } else {
                handle_sessions().await;
            }
        }
        Some(Commands::Setup { shell }) => handle_setup(shell).await,
        Some(Commands::Debug { op }) => match op {
            DebugOp::Bundle => handle_debug_bundle().await,
        },
        Some(Commands::Update { check, force, to }) => {
            if let Err(e) = aic_client::update::run(aic_client::update::UpdateOptions {
                check,
                force,
                pinned: to,
            })
            .await
            {
                eprintln!("aic update 실패: {e}");
                std::process::exit(1);
            }
        }
        None => {
            // --record <prefix>가 있으면 history에서 매칭되는 record를 분석 흐름에 투입.
            if let Some(prefix) = cli.record_prefix.as_deref() {
                if let Err(e) =
                    handle_record_by_prefix(prefix, cli.session.clone(), cli.dry_run, cli.provider)
                        .await
                {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return;
            }

            // 인자가 있으면 프롬프트로 사용, 없으면 기본 동작
            let prompt = if cli.prompt.is_empty() {
                None
            } else {
                Some(cli.prompt.join(" "))
            };

            if let Err(e) = handle_default(prompt, cli.dry_run, cli.provider, cli.context).await {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}

/// `aic config get <path>`: dotted path로 단일 값 추출 (스크립팅 친화).
/// scalar는 raw 값, object/array는 JSON pretty로 출력.
fn handle_config_get(path: &str) {
    let config = match ConfigManager::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} 설정 로드 실패: {e}");
            std::process::exit(1);
        }
    };
    let json = match serde_json::to_value(&config) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("직렬화 실패: {e}");
            std::process::exit(2);
        }
    };
    let mut current = &json;
    for part in path.split('.') {
        match current.get(part) {
            Some(v) => current = v,
            None => {
                eprintln!("{COL_YELLOW}⚠{COL_RESET} path not found: {path} (segment: {part})");
                std::process::exit(3);
            }
        }
    }
    match current {
        serde_json::Value::String(s) => println!("{s}"),
        serde_json::Value::Number(n) => println!("{n}"),
        serde_json::Value::Bool(b) => println!("{b}"),
        serde_json::Value::Null => {} // empty output
        // object/array는 JSON pretty
        v => match serde_json::to_string_pretty(v) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("출력 실패: {e}");
                std::process::exit(2);
            }
        },
    }
}

/// `aic config show [--json] [--show-secrets]`: 현재 설정을 비-인터랙티브로 출력.
/// 기본은 api_key를 마스킹한다. `--show-secrets`는 raw 값을 출력 (외부 자동화/디버깅 용도).
fn handle_config_show(json: bool, show_secrets: bool) {
    let mut config = match ConfigManager::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} 설정 로드 실패: {e}");
            std::process::exit(1);
        }
    };
    if !show_secrets {
        for provider in config.llm.providers.values_mut() {
            if let Some(key) = provider.api_key.as_deref() {
                provider.api_key = Some(mask_api_key(key));
            }
        }
    }
    let serialized = if json {
        serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
    } else {
        toml::to_string_pretty(&config).map_err(|e| e.to_string())
    };
    match serialized {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} 직렬화 실패: {e}");
            std::process::exit(2);
        }
    }
}

/// `--record <prefix>` 또는 last record를 조회해 단일 CommandRecord를 반환한다.
/// `aic fix`/`aic capture-last`/`aic learn`/`aic feedback`/--record 분기에서
/// 공유하는 record 결정 로직.
///
/// Phase 3.2 Task 2.2: socket path 로부터 session_id 를 추출할 수 있으면
/// `ReadCascade` 로 aicd → session socket 순으로 조회한다. session_id 추출이
/// 실패하는 경우에만 legacy `UdsClient` 단일-소켓 경로로 폴백한다.
async fn resolve_record(
    client: &UdsClient,
    sock_display: std::path::Display<'_>,
    record_prefix: Option<&str>,
) -> anyhow::Result<aic_common::CommandRecord> {
    // cascade 대상 socket path 를 복원. display 는 PathBuf 의 reference 이므로
    // 직접 재귀 추출하는 대신 sock_display 의 문자열에서 PathBuf 를 재구성한다.
    let sock_path = std::path::PathBuf::from(sock_display.to_string());
    let cascade = build_cascade_for_session_path(&sock_path);

    if let Some(prefix) = record_prefix.map(str::trim).filter(|s| !s.is_empty()) {
        if !aic_common::is_valid_record_id(prefix) {
            anyhow::bail!(
                "record id prefix가 유효하지 않음: '{prefix}' (1~16자 lowercase hex 필요)"
            );
        }
        let matched = if let Some(ref c) = cascade {
            c.find_record_by_prefix(prefix)
                .await
                .map_err(|e| anyhow::anyhow!("세션 record 조회 실패 ({sock_display}): {e}"))?
        } else {
            client
                .find_record_by_prefix(prefix)
                .await
                .map_err(|e| anyhow::anyhow!("세션 record 조회 실패 ({sock_display}): {e}"))?
        };
        match matched.len() {
            0 => anyhow::bail!(
                "prefix '{prefix}'와 일치하는 record가 없습니다 — `aic history`로 id를 확인하세요"
            ),
            1 => Ok(matched.into_iter().next().expect("len==1")),
            n => {
                let preview: Vec<String> = matched
                    .iter()
                    .take(5)
                    .map(|r| {
                        format!(
                            "  {} {}",
                            &r.id[..r.id.len().min(8)],
                            r.command.as_deref().unwrap_or("∅")
                        )
                    })
                    .collect();
                anyhow::bail!(
                    "prefix '{prefix}'가 {n}건 매칭됩니다 — 더 긴 prefix로 좁혀주세요:\n{}",
                    preview.join("\n")
                );
            }
        }
    } else if let Some(ref c) = cascade {
        match c.get_last_command().await {
            Ok(Some(rec)) => Ok(rec),
            Ok(None) => Err(anyhow::anyhow!(
                "마지막 record가 없습니다 ({sock_display}) — aic-session 안에서 명령을 실행한 뒤 다시 시도하세요"
            )),
            Err(e) => Err(anyhow::anyhow!(
                "마지막 record 조회 실패 ({sock_display}): {e}"
            )),
        }
    } else {
        client
            .get_last_command()
            .await
            .map_err(|e| anyhow::anyhow!("마지막 record 조회 실패 ({sock_display}): {e}"))
    }
}

/// 활성 세션 소켓 경로 결정. 우선순위:
/// 1) explicit `--session <id>`
/// 2) `$AIC_SESSION_ID`
/// 3) `config.server.socket_path` (사용자 override)
/// 4) 가장 최근 `session-*.sock`
/// 5) legacy `default_socket_path()`
fn resolve_socket(explicit_id: Option<&str>) -> std::path::PathBuf {
    if let Some(id) = explicit_id.map(str::trim).filter(|s| !s.is_empty()) {
        return aic_common::session_socket_path(id);
    }
    if let Ok(env_id) = std::env::var("AIC_SESSION_ID") {
        let trimmed = env_id.trim();
        if !trimmed.is_empty() {
            return aic_common::session_socket_path(trimmed);
        }
    }
    if let Some(p) = ConfigManager::load()
        .ok()
        .and_then(|c| c.server.socket_path)
    {
        return p;
    }
    if let Some(p) = aic_common::list_session_sockets().into_iter().next() {
        return p;
    }
    aic_common::default_socket_path()
}

// ── aicd supervisor (Phase 1.5) ────────────────────────────────────

/// `aic daemon status`: aicd가 떠 있는지 ping으로 확인하고 PID/socket을 표시.
async fn handle_daemon_status() {
    let sock = aic_common::aicd_socket_path();
    let lock_path = aic_common::aicd_lock_path();
    println!("{COL_BOLD}aicd supervisor{COL_RESET}");
    println!("  socket: {}", sock.display());
    println!("  lock:   {}", lock_path.display());

    let client = UdsClient::new(sock.clone());
    match client.ping().await {
        Ok(true) => {
            // PID는 lock 파일에서 읽는다 — aicd가 ping에 응답한다면 lock도 살아있을 것.
            let pid = std::fs::read_to_string(&lock_path)
                .ok()
                .and_then(|c| c.lines().next().map(|s| s.trim().to_string()));
            let pid_label = pid.as_deref().unwrap_or("unknown");
            println!("  status: {COL_GREEN}running{COL_RESET} (pid {pid_label})");
            // 등록된 세션 수 함께 표시
            match client.list_sessions().await {
                Ok(sessions) => println!("  sessions: {}", sessions.len()),
                Err(e) => println!("  sessions: {COL_YELLOW}조회 실패{COL_RESET} ({e})"),
            }
        }
        _ => {
            println!("  status: {COL_DIM}stopped{COL_RESET}");
            println!("  start with: {COL_BOLD}aic daemon start{COL_RESET}");
        }
    }

    // 자동 시작 unit 설치 상태 (Phase 5)
    if let Some(unit) = aic_client::daemon_install::current_unit_path() {
        let installed = unit.exists();
        let label = if installed {
            format!("{COL_GREEN}installed{COL_RESET}")
        } else {
            format!(
                "{COL_DIM}not installed (run: {COL_BOLD}aic daemon install{COL_RESET}{COL_DIM}){COL_RESET}"
            )
        };
        println!("  autostart: {label}");
        if installed {
            println!("    {COL_DIM}unit: {}{COL_RESET}", unit.display());
        }
    }
}

/// `aic daemon install [--no-load]`: OS-native auto-start unit 설치.
fn handle_daemon_install(no_load: bool) {
    match aic_client::daemon_install::install(no_load) {
        Ok(report) => {
            let plat = match report.platform {
                aic_client::daemon_install::Platform::Macos => "macOS launchd",
                aic_client::daemon_install::Platform::Linux => "Linux systemd --user",
                aic_client::daemon_install::Platform::Unsupported => "unsupported",
            };
            println!("{COL_GREEN}✓{COL_RESET} {plat} unit 설치 완료");
            println!("  unit:    {}", report.unit_path.display());
            println!("  aicd:    {}", report.aicd_path.display());
            println!(
                "  logs:    {}/aicd.{{out,err}}.log",
                report.log_dir.display()
            );
            if report.loaded {
                println!("  loaded:  {COL_GREEN}yes{COL_RESET} — 부팅 시 자동 시작 + 즉시 실행");
            } else {
                let cmd = match report.platform {
                    aic_client::daemon_install::Platform::Macos => {
                        "launchctl bootstrap gui/$UID <plist>"
                    }
                    _ => "systemctl --user enable --now aicd.service",
                };
                println!("  loaded:  {COL_DIM}no (--no-load) — 직접: {cmd}{COL_RESET}");
            }
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 설치 실패: {e}");
            std::process::exit(1);
        }
    }
}

/// `aic daemon uninstall`: unit unload + 파일 제거.
fn handle_daemon_uninstall() {
    match aic_client::daemon_install::uninstall() {
        Ok(report) => {
            let plat = match report.platform {
                aic_client::daemon_install::Platform::Macos => "macOS launchd",
                aic_client::daemon_install::Platform::Linux => "Linux systemd --user",
                aic_client::daemon_install::Platform::Unsupported => "unsupported",
            };
            if report.removed {
                println!("{COL_GREEN}✓{COL_RESET} {plat} unit 제거 완료");
                println!("  unit: {}", report.unit_path.display());
            } else {
                println!(
                    "{COL_DIM}{plat} unit 파일이 이미 없습니다 (이전 unload만 정리){COL_RESET}"
                );
            }
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 제거 실패: {e}");
            std::process::exit(1);
        }
    }
}

/// `aic daemon start`: aicd binary를 시작한다 (이미 떠 있으면 no-op).
async fn handle_daemon_start(foreground: bool) {
    let sock = aic_common::aicd_socket_path();
    let client = UdsClient::new(sock.clone());
    if let Ok(true) = client.ping().await {
        println!("{COL_GREEN}✓{COL_RESET} aicd가 이미 실행 중입니다");
        return;
    }

    // aic 실행 파일과 같은 디렉토리에 있는 aicd를 우선 시도, 없으면 PATH로 폴백.
    let aicd_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("aicd")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("aicd"));

    if foreground {
        println!(
            "{COL_GREEN}▶{COL_RESET} aicd foreground 실행 — {bin}",
            bin = aicd_bin.display()
        );
        let status = std::process::Command::new(&aicd_bin)
            .arg("--foreground")
            .status();
        match status {
            Ok(status) if status.success() => return,
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(e) => {
                eprintln!(
                    "{COL_RED}✗{COL_RESET} aicd 실행 실패: {e}\n  시도한 경로: {}",
                    aicd_bin.display()
                );
                std::process::exit(1);
            }
        }
    }

    match std::process::Command::new(&aicd_bin)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            println!(
                "{COL_GREEN}✓{COL_RESET} aicd 시작 — pid {pid} ({bin})",
                pid = child.id(),
                bin = aicd_bin.display()
            );
            // 짧게 기다린 뒤 ping이 되는지 검증
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            match client.ping().await {
                Ok(true) => println!("  socket: {}", sock.display()),
                _ => eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} aicd가 spawn 됐으나 아직 응답이 없습니다. \
                     `aic daemon status`로 다시 확인하세요."
                ),
            }
        }
        Err(e) => {
            eprintln!(
                "{COL_RED}✗{COL_RESET} aicd 실행 실패: {e}\n  시도한 경로: {}",
                aicd_bin.display()
            );
            std::process::exit(1);
        }
    }
}

/// `aic run -- <cmd...>`: explicit capture wrapper.
///
/// 동작:
/// 1. cmd를 spawn하고 stdout/stderr tail을 byte cap 안에서 수집한다.
/// 2. wrapped 명령의 exit code를 그대로 보존하여 종료한다.
/// 3. 분석 record는 capture_mode = ExplicitCapture, capture_quality = FullOutput
///    (또는 truncation/binary 시 그에 맞는 quality)로 표시된다.
///
/// 현재 구현 한계:
/// - aicd registry/buffer로 보내는 단계는 이후 sub-step에서 추가한다.
///   (구조 정의만 하고 stdout으로 record JSON을 hint로 표시 — 사용자가 결과를 확인)
/// - line cap 1000, byte cap 256 KiB. 초과 시 tail만 보존.
async fn handle_run(cmd: Vec<String>, provider_override: Option<String>) {
    if cmd.is_empty() {
        eprintln!("{COL_RED}✗{COL_RESET} 실행할 명령이 없습니다 — `aic run -- <cmd...>`");
        std::process::exit(2);
    }

    const LINE_CAP: usize = 1000;
    const BYTE_CAP: u64 = 256 * 1024;

    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};

    let started_at = chrono::Utc::now();
    let mut child = match tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} {} 실행 실패: {e}", cmd[0]);
            std::process::exit(127);
        }
    };

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // tail 수집을 위한 ring (실제 cap을 enforce하기 위해 VecDeque 사용).
    let lines: std::sync::Arc<tokio::sync::Mutex<std::collections::VecDeque<String>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::VecDeque::new()));
    let truncated = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stored_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    async fn pump<R: tokio::io::AsyncRead + Unpin>(
        reader: R,
        sink: std::sync::Arc<tokio::sync::Mutex<std::collections::VecDeque<String>>>,
        truncated: std::sync::Arc<std::sync::atomic::AtomicBool>,
        stored_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
        write_to: bool, // true=stdout, false=stderr — 사용자에게는 그대로 echo
    ) {
        let mut br = BufReader::new(reader).lines();
        while let Ok(Some(line)) = br.next_line().await {
            if write_to {
                println!("{line}");
            } else {
                eprintln!("{line}");
            }
            let line_bytes = line.len() as u64 + 1;
            let cur = stored_bytes.fetch_add(line_bytes, std::sync::atomic::Ordering::Relaxed);
            let mut q = sink.lock().await;
            if cur + line_bytes > BYTE_CAP || q.len() >= LINE_CAP {
                if !q.is_empty() {
                    q.pop_front();
                }
                truncated.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            q.push_back(line);
        }
    }

    let lines_out = std::sync::Arc::clone(&lines);
    let trunc_out = std::sync::Arc::clone(&truncated);
    let bytes_out = std::sync::Arc::clone(&stored_bytes);
    let stdout_task = tokio::spawn(pump(stdout, lines_out, trunc_out, bytes_out, true));

    let lines_err = std::sync::Arc::clone(&lines);
    let trunc_err = std::sync::Arc::clone(&truncated);
    let bytes_err = std::sync::Arc::clone(&stored_bytes);
    let stderr_task = tokio::spawn(pump(stderr, lines_err, trunc_err, bytes_err, false));

    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} child wait 실패: {e}");
            std::process::exit(1);
        }
    };
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    let exit_code = status.code().unwrap_or_else(|| {
        // signal 종료 — POSIX 관례 128 + signal
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            128 + status.signal().unwrap_or(15)
        }
        #[cfg(not(unix))]
        {
            1
        }
    });

    let collected: Vec<String> = lines.lock().await.iter().cloned().collect();
    let stored = stored_bytes.load(std::sync::atomic::Ordering::Relaxed);
    let was_truncated = truncated.load(std::sync::atomic::Ordering::Relaxed);

    let record = aic_common::CommandRecord {
        id: aic_common::generate_record_id(),
        command: Some(cmd.join(" ")),
        exit_code,
        output_lines: collected.clone(),
        timestamp: chrono::Utc::now(),
        capture_mode: aic_common::CaptureMode::ExplicitCapture,
        capture_quality: if was_truncated {
            aic_common::CaptureQuality::TruncatedOutput
        } else {
            aic_common::CaptureQuality::FullOutput
        },
        output_metadata: Some(aic_common::OutputMetadata {
            original_bytes: None,
            stored_bytes: stored,
            stored_lines: collected.len(),
            truncated: was_truncated,
            binary: false,
            sha256: None,
        }),
    };

    // duration은 trace 로그에만 — record schema에 duration 필드는 향후 확장.
    let duration = chrono::Utc::now() - started_at;
    eprintln!(
        "{COL_DIM}── aic run: exit={exit} lines={n} bytes={b} truncated={t} duration={d}ms ──{COL_RESET}",
        exit = record.exit_code,
        n = record.output_lines.len(),
        b = record
            .output_metadata
            .as_ref()
            .map(|m| m.stored_bytes)
            .unwrap_or(0),
        t = was_truncated,
        d = duration.num_milliseconds().max(0)
    );

    let _ = local_record::save_last(&record);
    // best-effort: 세션 ring buffer에도 등록해 history/--record/fix가 찾을 수 있게.
    // 세션 소켓이 없으면 silent 무시 (daemonless 환경 호환). 디버깅을 위해 실패
    // 원인은 debug 로그로만 남긴다.
    {
        let sock = resolve_socket(None);
        let client = UdsClient::new(sock);
        if let Err(e) = client.register_record(record.clone()).await {
            debug_log!("register_record 실패 (best-effort 무시): {e}");
        }
    }
    if record.exit_code != 0 {
        match ConfigManager::load() {
            Ok(config) => {
                // CLI --provider override를 config에 실제 반영 → dispatcher가 override를 사용.
                let (config, provider_name) =
                    match apply_provider_override(config, provider_override.as_deref()) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("{COL_YELLOW}⚠{COL_RESET} 분석 건너뜀: {e}");
                            std::process::exit(exit_code);
                        }
                    };
                let model_name = config
                    .llm
                    .providers
                    .get(&provider_name)
                    .and_then(|p| p.model.clone())
                    .unwrap_or_else(|| "(CLI)".to_string());
                let lang = aic_common::resolve_lang(&config.llm.lang);
                let dispatcher = LlmDispatcher::from_config(config.llm.clone());
                if let Err(e) = handle_record(
                    record.clone(),
                    dispatcher,
                    &config,
                    &provider_name,
                    &model_name,
                    &lang,
                    false,
                )
                .await
                {
                    eprintln!("{COL_YELLOW}⚠{COL_RESET} 분석 실패: {e}");
                }
            }
            Err(e) => {
                eprintln!(
                    "{COL_DIM}분석은 건너뜀: 설정 로드 실패 ({e}). 나중에 `aic`로 마지막 기록을 분석할 수 있습니다.{COL_RESET}"
                );
            }
        }
    }

    std::process::exit(exit_code);
}

/// `aic _hook-event {start,end}`: shell hook이 호출하는 metadata 송신.
///
/// 정책:
/// - aicd가 미실행이면 silent skip + exit 0. shell prompt를 절대 막지 않는다.
/// - 100ms timeout. shell prompt latency를 방해하면 안 된다.
/// - 모든 출력은 stderr에만 (stdout 오염 금지).
async fn handle_hook_event(op: HookEventOp) {
    let sock = aic_common::aicd_socket_path();
    let now = chrono::Utc::now();
    let request = match op {
        HookEventOp::Start {
            session,
            command_id,
            command,
            cwd,
            shell,
            pid,
        } => {
            let cwd = cwd.map(std::path::PathBuf::from);
            let _ = local_record::save_hook_start(
                session.clone(),
                command_id.clone(),
                command.clone(),
                cwd.clone(),
                shell.clone(),
                pid,
                now,
            );
            aic_common::IpcRequest::CommandStarted {
                session_id: session,
                command_id,
                command,
                cwd,
                shell,
                pid,
                started_at: now,
            }
        }
        HookEventOp::End {
            session,
            command_id,
            exit,
            duration_ms,
        } => {
            let _ = local_record::finish_hook(&session, &command_id, exit, now);
            aic_common::IpcRequest::CommandFinished {
                session_id: session,
                command_id,
                exit_code: exit,
                finished_at: now,
                duration_ms,
            }
        }
    };
    let client = UdsClient::new(sock);
    let send = async {
        let _ = client.send_raw(request).await;
    };
    // 짧은 timeout — aicd가 hang 또는 미실행이면 프롬프트 멈추지 않게 즉시 포기.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), send).await;
}

/// `aic session stop <id>`: 특정 세션을 종료한다 (Phase 2.1).
///
/// aicd가 떠 있어야 한다. 떠 있지 않다면 사용자에게 자체적으로 `kill <pid>`
/// 또는 `aic daemon start` 하라고 안내한다.
async fn handle_session_stop(id: String) {
    if !aic_common::is_valid_session_id(&id) {
        eprintln!("{COL_RED}✗{COL_RESET} 유효하지 않은 세션 ID: '{id}' (1~8자 lowercase hex 필요)");
        std::process::exit(2);
    }
    let client = UdsClient::new(aic_common::aicd_socket_path());
    match client.stop_session(&id).await {
        Ok(()) => println!("{COL_GREEN}✓{COL_RESET} 세션 {id}에 SIGTERM 전송"),
        Err(AicError::ServerNotRunning) => {
            eprintln!(
                "{COL_YELLOW}⚠{COL_RESET} aicd가 실행 중이 아닙니다 — 세션 종료를 위해 \
                 `aic daemon start` 후 다시 시도하거나 직접 `kill` 명령을 사용하세요."
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 세션 종료 실패: {e}");
            std::process::exit(1);
        }
    }
}

async fn handle_session_tag(id: String, label: Option<String>) {
    if !aic_common::is_valid_session_id(&id) {
        eprintln!("{COL_RED}✗{COL_RESET} 유효하지 않은 세션 ID: '{id}' (1~8자 lowercase hex 필요)");
        std::process::exit(2);
    }
    let label = label.and_then(|l| {
        let trimmed = l.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let client = UdsClient::new(aic_common::aicd_socket_path());
    match client.tag_session(&id, label.clone()).await {
        Ok(()) => match label {
            Some(l) => println!("{COL_GREEN}✓{COL_RESET} 세션 {id} label='{l}' 설정"),
            None => println!("{COL_GREEN}✓{COL_RESET} 세션 {id} label 제거"),
        },
        Err(AicError::ServerNotRunning) => {
            eprintln!(
                "{COL_YELLOW}⚠{COL_RESET} aicd가 실행 중이 아닙니다 — `aic daemon start` 후 다시 시도하세요."
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} session tag 실패: {e}");
            std::process::exit(1);
        }
    }
}

async fn handle_session_prune(older_than_secs: u64) {
    let client = UdsClient::new(aic_common::aicd_socket_path());
    match client.prune_sessions(older_than_secs).await {
        Ok(count) => println!("{COL_GREEN}✓{COL_RESET} inactive 세션 {count}개 정리"),
        Err(AicError::ServerNotRunning) => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} aicd가 실행 중이 아닙니다 — `aic daemon start` 후 다시 시도하세요.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 세션 정리 실패: {e}");
            std::process::exit(1);
        }
    }
}

/// `aic daemon stop`: aicd에 graceful Shutdown 요청.
async fn handle_daemon_stop() {
    let sock = aic_common::aicd_socket_path();
    let client = UdsClient::new(sock);
    match client.shutdown().await {
        Ok(()) => println!("{COL_GREEN}✓{COL_RESET} aicd Shutdown 요청 전송"),
        Err(AicError::ServerNotRunning) => {
            println!("{COL_DIM}aicd가 실행 중이 아닙니다{COL_RESET}");
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} aicd Shutdown 실패: {e}");
            std::process::exit(1);
        }
    }
}

/// `aic top [--interval N]`: ratatui 라이브 TUI. 비-TTY는 status --watch로 fallback.
async fn handle_top(interval: u64, session: Option<String>) {
    use std::io::IsTerminal;
    let socket_path = resolve_socket(session.as_deref());
    let client = UdsClient::new(socket_path);

    if !std::io::stdout().is_terminal() {
        // 비-TTY: ratatui 대신 watch 텍스트 모드로 fallback
        handle_status(true, interval, session, false, false).await;
        return;
    }

    if let Err(e) = aic_client::top::run_top(client, interval).await {
        eprintln!("{COL_YELLOW}⚠{COL_RESET} aic top 종료: {e}");
        std::process::exit(1);
    }
}

/// `aic setup [shell]`: 첫 사용 통합 가이드.
/// config 파일 존재 점검 → 없으면 wizard, 있으면 "현재 설정 유지" 안내 →
/// shell hook 설치 → migrate-keys (평문 키 있으면) → doctor 한 번 실행 → 다음 단계 안내.
async fn handle_setup(shell: Option<String>) {
    println!("{COL_BOLD}aic 초기 설정{COL_RESET}\n");

    // 1) config
    let config_path = ConfigManager::config_path();
    if !config_path.exists() {
        println!("{COL_CYAN}1/4{COL_RESET} 설정 파일이 없습니다 → 인터랙티브 wizard를 실행합니다.");
        println!("    경로: {}\n", config_path.display());
        handle_config();
    } else {
        println!(
            "{COL_CYAN}1/4{COL_RESET} 설정 파일 확인됨: {}",
            config_path.display()
        );
        println!("    수정하려면 나중에 `aic config`를 실행하세요.\n");
    }

    // 2) shell hook 설치
    println!("{COL_CYAN}2/4{COL_RESET} 셸 hook 설치 (idempotent)...");
    handle_init(shell, false);
    println!();

    // 3) migrate-keys (config 로드 후 평문 key 있는지 확인 후만)
    println!("{COL_CYAN}3/4{COL_RESET} 평문 API key를 OS keychain으로 이동...");
    if let Ok(cfg) = ConfigManager::load() {
        let has_plaintext = cfg.llm.providers.values().any(|p| {
            p.api_key
                .as_deref()
                .map(|k| !k.is_empty() && !aic_client::keychain::is_reference(k))
                .unwrap_or(false)
        });
        if has_plaintext {
            handle_migrate_keys();
        } else {
            println!("    평문 key 없음 — skip\n");
        }
    } else {
        println!("    설정 로드 실패 — skip\n");
    }

    // 4) doctor
    println!("{COL_CYAN}4/4{COL_RESET} 환경 진단 (doctor)...\n");
    handle_doctor(false, None).await;

    println!("\n{COL_GREEN}{COL_BOLD}✔ setup 완료{COL_RESET}");
    println!("\n다음 단계:");
    println!("  1. {COL_BOLD}새 터미널을 열거나 `source ~/.zshrc`{COL_RESET} (또는 .bashrc)");
    println!("  2. {COL_BOLD}aic-session{COL_RESET} 으로 PTY 셸 진입");
    println!("  3. 명령 실행 → 실패하면 {COL_BOLD}aic{COL_RESET} 으로 분석");
}

/// `aic debug bundle`: 진단 번들을 stdout에 JSON으로 출력.
async fn handle_debug_bundle() {
    use serde_json::{json, Value};

    // 1) redacted config
    let config_value: Value = match ConfigManager::load() {
        Ok(mut c) => {
            for p in c.llm.providers.values_mut() {
                if let Some(k) = p.api_key.as_deref() {
                    p.api_key = Some(mask_api_key(k));
                }
            }
            serde_json::to_value(&c).unwrap_or(Value::Null)
        }
        Err(e) => json!({ "error": e.to_string() }),
    };

    // 2) doctor (현재 활성 세션 sock 결정 → run_all_checks에 전달)
    let doctor_socket = resolve_socket(None);
    let doctor_value: Value =
        serde_json::to_value(aic_client::doctor::run_all_checks(&doctor_socket).await)
            .unwrap_or(Value::Null);

    // 3) sessions
    let sessions_value: Value = Value::Array(
        list_sessions()
            .into_iter()
            .map(|s| {
                json!({
                    "session_id": s.session_id,
                    "socket": s.socket_path.display().to_string(),
                    "alive": s.is_alive,
                })
            })
            .collect(),
    );

    // 4) server log tail (~/.local/state/aic/server.log) 최근 50라인.
    //    M3: secret/PII 마스킹 후 출력 — 이슈 리포팅 시 우발적 노출 방지.
    let log_path = std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".local/state/aic/server.log"))
        .unwrap_or_default();
    let log_tail: Vec<String> = std::fs::read_to_string(&log_path)
        .ok()
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(50);
            lines[start..]
                .iter()
                .map(|l| aic_client::redaction::redact(l).0)
                .collect()
        })
        .unwrap_or_default();

    // 5) cache stats
    let cache_dir = aic_client::cache::cache_dir();
    let (cache_files, cache_bytes) = std::fs::read_dir(&cache_dir)
        .map(|entries| {
            entries.flatten().fold((0u64, 0u64), |(n, b), e| {
                let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
                (n + 1, b + sz)
            })
        })
        .unwrap_or((0, 0));

    let bundle = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "config": config_value,
        "doctor": doctor_value,
        "sessions": sessions_value,
        "server_log_tail": log_tail,
        "server_log_path": log_path.display().to_string(),
        "cache": {
            "dir": cache_dir.display().to_string(),
            "files": cache_files,
            "bytes": cache_bytes,
        }
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".into())
    );
}

/// `aic init <shell>`: 셸 rc 파일에 `source ~/.aic/hooks.{shell}` 라인을 멱등 추가.
/// 마커 `# >>> aic hooks >>>` ~ `# <<< aic hooks <<<` 로 감싸서 안전하게 롤백 가능.
fn handle_init(shell_arg: Option<String>, hook_mode: bool) {
    const MARKER_BEGIN: &str = "# >>> aic hooks >>>";
    const MARKER_END: &str = "# <<< aic hooks <<<";

    let shell_name = shell_arg.unwrap_or_else(|| {
        let s = std::env::var("SHELL").unwrap_or_default();
        std::path::Path::new(&s)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string()
    });

    let (rc_filename, hook_filename) = match shell_name.as_str() {
        "zsh" => (".zshrc", "hooks.zsh"),
        "bash" => (".bashrc", "hooks.bash"),
        other => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} 지원하지 않는 셸: {other} (zsh/bash만 지원)");
            std::process::exit(1);
        }
    };

    if hook_mode {
        install_hook_mode(&shell_name);
    }

    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} HOME 환경 변수 없음");
            std::process::exit(1);
        }
    };

    let rc_path = home.join(rc_filename);
    let hook_path = home.join(".aic").join(hook_filename);
    let snippet = format!(
        "{MARKER_BEGIN}\nsource {hook}\n{MARKER_END}\n",
        hook = hook_path.display()
    );

    let existing = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if existing.contains(MARKER_BEGIN) {
        println!(
            "{COL_DIM}↪ {rc} 에 이미 aic hook 마커가 있어 skip{COL_RESET}",
            rc = rc_path.display()
        );
        std::process::exit(0);
    }

    let new_content = if existing.is_empty() {
        snippet
    } else if existing.ends_with('\n') {
        format!("{existing}\n{snippet}")
    } else {
        format!("{existing}\n\n{snippet}")
    };

    if let Err(e) = std::fs::write(&rc_path, new_content) {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} {} 쓰기 실패: {e}",
            rc_path.display()
        );
        std::process::exit(2);
    }

    println!(
        "{COL_GREEN}✔{COL_RESET} {rc}에 aic hook 추가됨\n  새 셸을 띄우거나 `source {rc}`로 활성화하세요",
        rc = rc_path.display()
    );
}

/// `aic init --hook-mode`: Phase 3 metadata-only hook 설치.
///
/// 정책:
/// - hook 파일은 항상 덮어쓴다 (멱등 — 버전/내용이 바뀌면 다음 init이 갱신).
/// - rc source 라인은 marker 사이에서만 작업 — 기존 라인 유지.
/// - hook 파일이 없으면 만들고, 있으면 새 내용으로 덮어쓴다 (생성된 파일이라
///   사용자가 수정할 일이 없다).
fn install_hook_mode(shell_name: &str) {
    use aic_client::hook_install;
    let (rc_filename, hook_filename, script) = match shell_name {
        "zsh" => (".zshrc", "hook-events.zsh", hook_install::zsh_hook_script()),
        "bash" => (
            ".bashrc",
            "hook-events.bash",
            hook_install::bash_hook_script(),
        ),
        other => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} hook-mode 지원하지 않는 셸: {other}");
            return;
        }
    };

    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} HOME 환경 변수 없음 — hook-mode skip");
            return;
        }
    };

    let aic_dir = home.join(".aic");
    if let Err(e) = std::fs::create_dir_all(&aic_dir) {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} {} 생성 실패: {e}",
            aic_dir.display()
        );
        return;
    }
    let hook_path = aic_dir.join(hook_filename);
    if let Err(e) = std::fs::write(&hook_path, &script) {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} hook 파일 쓰기 실패: {} — {e}",
            hook_path.display()
        );
        return;
    }
    println!(
        "{COL_GREEN}✔{COL_RESET} {} 작성 (version {})",
        hook_path.display(),
        hook_install::HOOK_VERSION
    );

    // rc 파일에 source 라인 추가 (marker 기반 멱등).
    let rc_path = home.join(rc_filename);
    let snippet = format!(
        "{begin}\nsource {hook}\n{end}\n",
        begin = hook_install::RC_MARKER_BEGIN,
        hook = hook_path.display(),
        end = hook_install::RC_MARKER_END,
    );
    let existing = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if existing.contains(hook_install::RC_MARKER_BEGIN) {
        println!(
            "{COL_DIM}↪ {} 에 hook-events 마커가 이미 있음 (skip){COL_RESET}",
            rc_path.display()
        );
        return;
    }
    let new_content = if existing.is_empty() {
        snippet
    } else if existing.ends_with('\n') {
        format!("{existing}\n{snippet}")
    } else {
        format!("{existing}\n\n{snippet}")
    };
    if let Err(e) = std::fs::write(&rc_path, new_content) {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} {} 쓰기 실패: {e}",
            rc_path.display()
        );
        return;
    }
    println!(
        "{COL_GREEN}✔{COL_RESET} {} 에 hook-events source 라인 추가",
        rc_path.display()
    );
    println!("  {COL_DIM}aicd가 떠 있어야 실제로 동작합니다 — `aic daemon start`{COL_RESET}");
}

/// `aic migrate-keys`: config.toml의 평문 API key를 OS keychain으로 일괄 이동.
fn handle_migrate_keys() {
    let mut config = match ConfigManager::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} 설정 로드 실패: {e}");
            std::process::exit(1);
        }
    };

    let mut migrated = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for (name, provider) in config.llm.providers.iter_mut() {
        let key = match provider.api_key.as_deref() {
            Some(k) if !k.is_empty() => k,
            _ => continue, // CLI backend 등 키 없는 provider
        };
        if aic_client::keychain::is_reference(key) {
            println!("{COL_DIM}↪ {name}: 이미 keychain reference{COL_RESET}");
            skipped += 1;
            continue;
        }
        match aic_client::keychain::store(name, key) {
            Ok(()) => {
                provider.api_key = Some(aic_client::keychain::make_reference(name));
                println!("{COL_GREEN}✔{COL_RESET} {name}: keychain 저장 완료");
                migrated += 1;
            }
            Err(e) => {
                eprintln!("{COL_YELLOW}⚠{COL_RESET} {name}: keychain 저장 실패 — {e}");
                failed += 1;
            }
        }
    }

    if migrated > 0 {
        if let Err(e) = save_config(&config) {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} config 저장 실패: {e}");
            std::process::exit(2);
        }
        println!();
        println!("{COL_BOLD}{migrated}개 이동, {skipped}개 skip, {failed}개 실패{COL_RESET}");
        println!("config.toml의 api_key가 'keychain:<provider-name>' reference로 변경되었습니다.");
    } else if skipped > 0 {
        println!();
        println!("이미 모든 키가 keychain reference입니다 ({skipped}개 skip).");
    } else {
        println!("이동할 평문 키가 없습니다.");
    }

    if failed > 0 {
        std::process::exit(3);
    }
}

/// `aic audit verify`: HMAC chain 무결성 검증.
fn handle_audit_verify() {
    match aic_client::audit::verify() {
        Ok(report) if report.valid => {
            println!(
                "{COL_GREEN}✔{COL_RESET} audit log valid ({n} lines)",
                n = report.lines
            );
            std::process::exit(0);
        }
        Ok(report) => {
            println!(
                "{COL_RED}✗{COL_RESET} audit log tampered at line {at}",
                at = report.broken_at.unwrap_or(0)
            );
            std::process::exit(2);
        }
        Err(e) => {
            println!("{COL_YELLOW}⚠{COL_RESET} audit verify error: {e}");
            std::process::exit(3);
        }
    }
}

/// `aic audit batch-verify [--date YYYY-MM-DD]` — 멀티호스트 batch audit segment 검증.
/// `~/.aic/audit/YYYY-MM-DD.jsonl`의 SHA256 chain을 재계산해 무결성을 보고한다.
/// exit 0=all pass, 2=하나라도 tampered, 3=IO/parse error.
fn handle_audit_batch_verify(date: Option<String>) {
    use aic_client::agent::audit_batch::{list_segments, verify_segment};

    let Some(home) = dirs::home_dir() else {
        eprintln!("{COL_RED}✗{COL_RESET} $HOME not set");
        std::process::exit(3);
    };
    let audit_dir = home.join(".aic").join("audit");

    let segments: Vec<std::path::PathBuf> = if let Some(d) = &date {
        let p = audit_dir.join(format!("{d}.jsonl"));
        if !p.exists() {
            eprintln!("{COL_YELLOW}⚠{COL_RESET} segment not found: {}", p.display());
            std::process::exit(3);
        }
        vec![p]
    } else {
        match list_segments(&audit_dir) {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                println!("{COL_YELLOW}⚠{COL_RESET} no audit segments in {}", audit_dir.display());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("{COL_RED}✗{COL_RESET} list segments: {e:#}");
                std::process::exit(3);
            }
        }
    };

    let mut any_broken = false;
    for path in &segments {
        match verify_segment(path) {
            Ok(report) if report.valid => {
                println!(
                    "{COL_GREEN}✔{COL_RESET} {} — {} entries, chain OK",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                    report.entries
                );
            }
            Ok(report) => {
                any_broken = true;
                println!(
                    "{COL_RED}✗{COL_RESET} {} — {} entries, broken at line {}",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                    report.entries,
                    report.broken_at.unwrap_or(0)
                );
            }
            Err(e) => {
                eprintln!("{COL_RED}✗{COL_RESET} {}: {e:#}", path.display());
                std::process::exit(3);
            }
        }
    }
    std::process::exit(if any_broken { 2 } else { 0 });
}

/// `aic hosts show [name] [--json]` — RFC-005 Phase 1 디버깅 surface.
///
/// `~/.aic/hosts.toml` + `~/.ssh/config` import + overlay 결과를 노출한다. 이 단계에서
/// 실제 SSH 호출은 없다(Phase 2 RemoteExecutor). 사용자가 "왜 호스트가 비어있나" /
/// "어느 필드가 어디서 왔나"를 즉시 검사할 수 있게 하는 것이 목적(red-team O1 해소).
fn handle_hosts_show(name: Option<String>, json: bool) {
    use aic_client::agent::hosts::Inventory;

    let inv = match Inventory::load() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 인벤토리 로드 실패: {e:#}");
            std::process::exit(2);
        }
    };

    if json {
        // 전체(name=None) 또는 단일(name=Some)을 JSON으로.
        let v = match &name {
            Some(n) => match inv.host(n) {
                Some(e) => serde_json::to_value(e).unwrap_or_default(),
                None => {
                    eprintln!("{COL_RED}✗{COL_RESET} host not found: {n}");
                    std::process::exit(1);
                }
            },
            None => serde_json::to_value(&inv).unwrap_or_default(),
        };
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }

    match name {
        None => print_hosts_summary(&inv),
        Some(n) => print_host_detail(&inv, &n),
    }
}

fn print_hosts_summary(inv: &aic_client::agent::hosts::Inventory) {
    use aic_client::agent::hosts::HostSource;

    let n_hosts = inv.hosts.len();
    let n_groups = inv.groups.len();
    println!(
        "inventory: {n_hosts} hosts · {n_groups} groups · ssh_config_import={}",
        inv.options.ssh_config_import
    );
    println!(
        "concurrency: max_parallel={} · per_host_timeout={}s · wall_clock={}s",
        inv.concurrency.max_parallel,
        inv.concurrency.per_host_timeout_secs,
        inv.concurrency.wall_clock_timeout_secs,
    );

    if !inv.groups.is_empty() {
        println!("\n{COL_BOLD}groups{COL_RESET}");
        for (name, g) in &inv.groups {
            let tags = if g.tags.is_empty() {
                String::new()
            } else {
                format!("  tags: {}", g.tags.join(", "))
            };
            println!("  @{name}  ({} hosts){tags}", g.hosts.len());
        }
    }

    if !inv.hosts.is_empty() {
        println!("\n{COL_BOLD}hosts{COL_RESET}");
        // 가독성: 가장 긴 name 폭 기준으로 정렬.
        let name_w = inv.hosts.keys().map(|k| k.len()).max().unwrap_or(0).max(8);
        for (name, e) in &inv.hosts {
            let src = match e.source {
                HostSource::HostsToml => "hosts.toml",
                HostSource::SshConfig => "ssh_config",
                HostSource::Overlay => "ssh_config + hosts.toml",
            };
            let target = format!("{}@{}:{}", e.user, e.hostname, e.port);
            println!(
                "  {name:<name_w$}  {target:<32}  [source: {src}]",
                name_w = name_w
            );
        }
    }

    if !inv.ssh_config_warnings.is_empty() {
        println!("\n{COL_YELLOW}ssh_config_warnings{COL_RESET} (위임 directive, ssh가 직접 처리)");
        for w in &inv.ssh_config_warnings {
            println!("  · {w}");
        }
    }
}

fn print_host_detail(inv: &aic_client::agent::hosts::Inventory, name: &str) {
    use aic_client::agent::hosts::{HostKeyCheck, HostSource};

    let Some(e) = inv.host(name) else {
        eprintln!("{COL_RED}✗{COL_RESET} host not found: {name}");
        // 유사 이름 제안(Levenshtein 미사용, 간단한 substring 매칭).
        let candidates: Vec<&String> = inv
            .hosts
            .keys()
            .filter(|k| k.contains(name) || name.contains(k.as_str()))
            .collect();
        if !candidates.is_empty() {
            eprintln!("    did you mean: {:?}", candidates);
        }
        std::process::exit(1);
    };

    let src = match e.source {
        HostSource::HostsToml => "hosts.toml",
        HostSource::SshConfig => "ssh_config",
        HostSource::Overlay => "ssh_config + hosts.toml overlay",
    };
    let hkc = match e.host_key_check {
        HostKeyCheck::Strict => "strict",
        HostKeyCheck::AcceptNew => "accept-new",
    };

    println!("{COL_BOLD}{}{COL_RESET}", e.name);
    println!("  source:                {src}");
    println!("  hostname:              {}", e.hostname);
    println!("  user:                  {}", e.user);
    println!("  port:                  {}", e.port);
    println!(
        "  identity_file:         {}",
        e.identity_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "—".into())
    );
    println!(
        "  proxy_jump:            {}",
        e.proxy_jump.as_deref().unwrap_or("—")
    );
    println!("  forward_agent:         {}", e.forward_agent);
    println!("  host_key_check:        {hkc}");
    println!("  connect_timeout_secs:  {}", e.connect_timeout_secs);
    println!(
        "  tags:                  {}",
        if e.tags.is_empty() {
            "—".into()
        } else {
            e.tags.join(", ")
        }
    );

    if !inv.ssh_config_warnings.is_empty() {
        println!("\n{COL_YELLOW}ssh_config_warnings{COL_RESET} (전역 — 이 호스트만의 경고는 아님)");
        for w in &inv.ssh_config_warnings {
            println!("  · {w}");
        }
    }
}

/// `aic hosts ping <target> [--cmd "uptime"]` — RFC-005 Phase 2(단일) + Phase 3(`@group` fan-out).
///
/// 단일 호스트면 카드 1장, 그룹이면 cap + 3-layer timeout으로 병렬 실행 후 호스트별 카드 stack
/// + 진단 헤더 통계(8종 상태별 카운트) + 미완료 호스트 목록(wall timeout 시).
///
/// exit code: 단일 — ok/ok_warn=0, 그 외=1. 그룹 — 모든 호스트 ok/ok_warn이면 0, 하나라도
/// 실패/timeout이면 1, wall timeout이면 2.
async fn handle_hosts_ping(target: String, cmd: String) {
    use aic_client::agent::hosts::Inventory;
    use aic_client::agent::remote::{
        run_fanout, HostStatus, RemoteCommand, RemoteExecutor, SshProcessExecutor,
    };

    let inv = match Inventory::load() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 인벤토리 로드 실패: {e:#}");
            std::process::exit(2);
        }
    };

    let hosts: Vec<aic_client::agent::hosts::HostEntry> = match inv.resolve_pattern(&target) {
        Ok(refs) => refs.into_iter().cloned().collect(),
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} {e}");
            std::process::exit(1);
        }
    };

    let mut parts = cmd.split_whitespace();
    let Some(program) = parts.next() else {
        eprintln!("{COL_RED}✗{COL_RESET} --cmd is empty");
        std::process::exit(2);
    };
    let arg_vec: Vec<String> = parts.map(String::from).collect();

    // 화이트리스트 게이트(Phase 6, O3): 멀티호스트로 실행 가능한 명령은 builtin 또는
    // user(`~/.aic/whitelist.toml`)에 있어야 한다. metachar·경로 denylist도 함께 검사.
    {
        use aic_client::agent::whitelist::{CheckResult, Whitelist};
        let wl = match Whitelist::load() {
            Ok(w) => w,
            Err(e) => {
                eprintln!("{COL_RED}✗{COL_RESET} whitelist 로드 실패: {e:#}");
                std::process::exit(2);
            }
        };
        if let CheckResult::Blocked { reason } = wl.check(program, &arg_vec) {
            eprintln!(
                "{COL_RED}✗ whitelist 차단:{COL_RESET} {reason}\n\
                 → 허용된 명령은 `aic whitelist status`로 확인. 추가하려면 \
                 `~/.aic/whitelist.toml`에 program 항목 작성.\n\
                 → 단일 명령 검사: `aic whitelist check \"{cmd}\"`"
            );
            std::process::exit(1);
        }
    }
    let rcmd = RemoteCommand::new(program).args(arg_vec.iter().cloned());

    let batch_id = format!(
        "ping-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    // batch_id는 executor(ControlPath namespace)와 audit_batch(BatchAppender) 모두 사용.
    let exec = SshProcessExecutor::new(batch_id.clone());

    // 단일 호스트: 기존 카드 1장 (Phase 2 동작 유지) — 본문 항상 펼침.
    if hosts.len() == 1 {
        let host = &hosts[0];
        println!(
            "{COL_BOLD}{}{COL_RESET}  →  {}@{}:{}  cmd={cmd:?}",
            host.name, host.user, host.hostname, host.port
        );
        let r = exec.exec(host, &rcmd).await;
        print_host_card(&r, true);
        if matches!(r.status, HostStatus::AuthFail) {
            print_auth_fail_hint(&r.stderr).await;
        }
        let code = match r.status {
            HostStatus::Ok | HostStatus::OkWithWarn => 0,
            _ => 1,
        };
        std::process::exit(code);
    }

    // 그룹: fan-out + 카드 stack + 헤더 통계.
    let total = hosts.len();
    println!(
        "{COL_BOLD}{target}{COL_RESET}  →  {total} hosts  cap={}  wall={}s  cmd={cmd:?}",
        inv.concurrency.max_parallel, inv.concurrency.wall_clock_timeout_secs,
    );

    // Audit batch — best-effort. 실패해도 진단은 계속 진행하되 stderr에 경고.
    let mut appender = match dirs::home_dir().map(|h| h.join(".aic").join("audit")) {
        Some(dir) => match aic_client::agent::audit_batch::BatchAppender::open(dir, batch_id.clone()) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("{COL_YELLOW}⚠ audit batch open 실패(계속):{COL_RESET} {e:#}");
                None
            }
        },
        None => None,
    };
    if let Some(a) = appender.as_mut() {
        let host_names: Vec<String> = hosts.iter().map(|h| h.name.clone()).collect();
        let _ = a.batch_start("diagnose", &target, &host_names);
    }

    let start = std::time::Instant::now();
    let r = run_fanout(&exec, &hosts, &rcmd, &inv.concurrency).await;
    let elapsed = start.elapsed();

    // 각 host_result audit 기록 (redact·truncate·status 정합).
    if let Some(a) = appender.as_mut() {
        for result in &r.results {
            let _ = a.host_result(
                &result.host,
                result.status.label(),
                &cmd,
                result.duration_ms,
                result.exit_code,
                result.truncated,
                result.redacted,
            );
        }
    }

    // 진단 헤더: 카운트 + 실패 호스트명 inline (5개 초과면 +N more).
    let c = r.counts();
    let mut parts_buf: Vec<String> = Vec::new();
    if c.ok > 0 { parts_buf.push(format!("{COL_GREEN}{} ok{COL_RESET}", c.ok)); }
    if c.ok_warn > 0 { parts_buf.push(format!("{COL_YELLOW}{} ok_warn{COL_RESET}", c.ok_warn)); }
    // 실패 카테고리는 호스트명 inline.
    add_named(&mut parts_buf, "unreachable", c.unreachable, COL_YELLOW, &r.results, HostStatus::Unreachable);
    add_named(&mut parts_buf, "timeout", c.timeout, COL_RED, &r.results, HostStatus::Timeout);
    add_named(&mut parts_buf, "auth_fail", c.auth_fail, COL_RED, &r.results, HostStatus::AuthFail);
    add_named(&mut parts_buf, "proxy_fail", c.proxy_fail, COL_RED, &r.results, HostStatus::ProxyFail);
    add_named(&mut parts_buf, "remote_err", c.remote_err, COL_RED, &r.results, HostStatus::RemoteErr);
    add_named(&mut parts_buf, "host_key_mismatch", c.host_key_mismatch, COL_RED, &r.results, HostStatus::HostKeyMismatch);
    if c.cancelled > 0 { parts_buf.push(format!("{COL_RED}{} cancelled{COL_RESET}", c.cancelled)); }
    println!("  {} · {:.1}s elapsed", parts_buf.join(" · "), elapsed.as_secs_f32());

    // severity-sort: 가장 심각한 카드가 위로(host_key_mismatch > auth_fail > ... > ok).
    let mut sorted: Vec<&aic_client::agent::remote::RemoteResult> = r.results.iter().collect();
    sorted.sort_by(|a, b| {
        b.status
            .severity()
            .cmp(&a.status.severity())
            .then_with(|| a.host.cmp(&b.host))
    });

    // 카드 stack: ok(no-anomaly)는 collapsed(헤더 1줄만), 그 외는 펼침.
    let mut collapsed_ok: Vec<&str> = Vec::new();
    let mut has_auth_fail_in_group = false;
    for result in &sorted {
        if matches!(result.status, HostStatus::Ok) {
            collapsed_ok.push(result.host.as_str());
            continue;
        }
        println!();
        println!("─ {COL_BOLD}{}{COL_RESET}", result.host);
        print_host_card(result, true);
        if matches!(result.status, HostStatus::AuthFail) {
            has_auth_fail_in_group = true;
        }
    }
    if !collapsed_ok.is_empty() {
        println!();
        let suffix = if collapsed_ok.len() > 5 {
            format!(" +{} more", collapsed_ok.len() - 5)
        } else {
            String::new()
        };
        let names: Vec<&str> = collapsed_ok.iter().take(5).copied().collect();
        println!(
            "─ {COL_GREEN}[ok, no anomaly] {} hosts{COL_RESET}: {}{suffix}  (collapsed)",
            collapsed_ok.len(),
            names.join(", ")
        );
    }

    // auth_fail hint block: 그룹 중 하나라도 있으면 ssh-agent 점검 + 패턴별 hint 1회 표시.
    if has_auth_fail_in_group {
        let first_auth_stderr = sorted
            .iter()
            .find(|r| matches!(r.status, HostStatus::AuthFail))
            .map(|r| r.stderr.as_str())
            .unwrap_or_default();
        println!();
        print_auth_fail_hint(first_auth_stderr).await;
    }

    // 미완료 호스트(wall timeout 시).
    if r.wall_timed_out {
        if let Some(a) = appender.as_mut() {
            let _ = a.batch_cancelled(r.results.len(), r.incomplete.clone());
        }
        println!();
        println!(
            "{COL_RED}⚠ wall_clock_timeout {}s 도달{COL_RESET} — 미완료 {} 호스트:",
            inv.concurrency.wall_clock_timeout_secs,
            r.incomplete.len()
        );
        for name in &r.incomplete {
            println!("  · {name}  [cancelled]");
        }
        std::process::exit(2);
    }

    // batch_end audit (정상 완료).
    if let Some(a) = appender.as_mut() {
        let stats = aic_client::agent::audit_batch::BatchStats {
            ok: c.ok,
            ok_warn: c.ok_warn,
            unreachable: c.unreachable,
            timeout: c.timeout,
            auth_fail: c.auth_fail,
            proxy_fail: c.proxy_fail,
            remote_err: c.remote_err,
            host_key_mismatch: c.host_key_mismatch,
            cancelled: c.cancelled,
        };
        let _ = a.batch_end(stats);
    }

    // exit code: 모든 호스트가 ok/ok_warn이면 0, 하나라도 실패면 1.
    let all_ok = r.results.iter().all(|res| {
        matches!(res.status, HostStatus::Ok | HostStatus::OkWithWarn)
    });
    std::process::exit(if all_ok { 0 } else { 1 });
}

/// 카드 헤더(상태 태그 + duration) + 선택적 본문(stdout/stderr).
/// `verbose=false`이면 헤더만 출력(그룹의 collapsed ok에는 미사용 — 별도 경로).
fn print_host_card(r: &aic_client::agent::remote::RemoteResult, verbose: bool) {
    let color = match r.status.severity() {
        0..=10 => COL_GREEN,
        11..=40 => COL_YELLOW,
        _ => COL_RED,
    };
    let truncated_tag = if r.truncated { "  [truncated]" } else { "" };
    let redacted_tag = if r.redacted > 0 {
        format!("  {COL_YELLOW}[redacted: {}]{COL_RESET}", r.redacted)
    } else {
        String::new()
    };
    println!(
        "  {color}[{}]{COL_RESET}  {}  exit={}  {}ms{truncated_tag}{redacted_tag}",
        r.status.label(),
        r.host,
        r.exit_code,
        r.duration_ms,
    );
    if !verbose {
        return;
    }
    if !r.stdout.is_empty() {
        for line in r.stdout.trim_end().lines() {
            println!("    {line}");
        }
    }
    if !r.stderr.is_empty() {
        for line in r.stderr.trim_end().lines() {
            println!("    {COL_YELLOW}stderr:{COL_RESET} {line}");
        }
    }
}

/// 상태별 카운트를 헤더에 inline으로 추가하면서 실패 호스트명을 5개까지 노출(+N more).
fn add_named(
    parts: &mut Vec<String>,
    label: &str,
    count: usize,
    color: &str,
    results: &[aic_client::agent::remote::RemoteResult],
    status: aic_client::agent::remote::HostStatus,
) {
    if count == 0 {
        return;
    }
    let names: Vec<&str> = results
        .iter()
        .filter(|r| r.status == status)
        .map(|r| r.host.as_str())
        .take(5)
        .collect();
    let suffix = if count > names.len() {
        format!(" +{} more", count - names.len())
    } else {
        String::new()
    };
    parts.push(format!(
        "{color}{count} {label}({}){suffix}{COL_RESET}",
        names.join(", ")
    ));
}

/// `[auth_fail]` 호스트에 대한 hint block — 로컬 ssh-agent 자동 점검(`ssh-add -l`) +
/// stderr 패턴별 단계적 해결 안내(RFC-005 §4.4 U3).
async fn print_auth_fail_hint(stderr: &str) {
    let agent = probe_local_ssh_agent().await;
    println!(
        "  {COL_BOLD}local ssh-agent{COL_RESET}  (auto-probed)"
    );
    match agent {
        SshAgentStatus::NoSocket => println!("    SSH_AUTH_SOCK: {COL_YELLOW}unset{COL_RESET}  → ssh-agent를 시작하거나 `eval $(ssh-agent)`"),
        SshAgentStatus::NoKeys(sock) => {
            println!("    SSH_AUTH_SOCK: {sock}");
            println!("    loaded keys:   {COL_YELLOW}0{COL_RESET}  ← 키 미등록");
            println!("    → ssh-add ~/.ssh/id_ed25519 (또는 사용 중인 키) 실행");
        }
        SshAgentStatus::Loaded { sock, keys } => {
            println!("    SSH_AUTH_SOCK: {sock}");
            println!("    loaded keys:   {COL_GREEN}{keys}{COL_RESET}");
            println!("    → hosts.toml에 identity_file 지정 또는 서버 authorized_keys 확인");
        }
        SshAgentStatus::ProbeFailed(reason) => {
            println!("    {COL_YELLOW}probe 실패{COL_RESET}: {reason}");
        }
    }
    println!();
    println!("  {COL_BOLD}hint{COL_RESET}");
    let lower = stderr.to_lowercase();
    if lower.contains("publickey") {
        println!("    1. ssh-add -l 로 등록 키 확인");
        println!("    2. hosts.toml `[[hosts]] identity_file = \"~/.ssh/...\"`로 명시 지정");
        println!("    3. 서버 authorized_keys에 공개키 등록 여부 확인");
    } else if lower.contains("gssapi") || lower.contains("kerberos") {
        println!("    · Kerberos TGT 만료 가능 — `klist`로 확인 후 `kinit`으로 갱신");
    } else if lower.contains("keyboard-interactive") {
        println!("    · MFA(keyboard-interactive) 호스트 — RFC-005 §1.2 멀티호스트 미지원");
        println!("    · 단일 호스트로 직접 ssh 접속(BatchMode=no) 후 재시도");
    } else if lower.contains("too many authentication failures") {
        println!("    · ssh-add -D 로 모든 키 제거 후 필요한 키만 ssh-add -t 60");
    } else {
        println!("    · ssh-add -l 로 ssh-agent 상태 확인");
        println!("    · ssh -v {{host}} -- echo ok 로 verbose 디버깅(BatchMode 외부)");
    }
    println!("    → 신규 호스트(known_hosts 미등록)는 `aic hosts trust <name>` 후 재시도");
    println!("    → 수정 후 `aic hosts ping <target> --retry-failed`로 실패 호스트만 재시도(1.1)");
}

/// `aic whitelist status` — builtin + user 화이트리스트 program 목록 출력.
fn handle_whitelist_status() {
    use aic_client::agent::whitelist::{Whitelist, BUILTIN_PROGRAMS};
    let wl = match Whitelist::load() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} whitelist 로드 실패: {e:#}");
            std::process::exit(2);
        }
    };
    let user_count = wl.programs.len() - BUILTIN_PROGRAMS.len();
    println!(
        "{COL_BOLD}builtin{COL_RESET} ({}): {}",
        BUILTIN_PROGRAMS.len(),
        BUILTIN_PROGRAMS.join(", ")
    );
    if let Some(p) = &wl.user_path {
        println!(
            "{COL_BOLD}user{COL_RESET} ({}) [{}]:",
            user_count.max(0),
            p.display()
        );
        for (name, rules) in &wl.programs {
            if BUILTIN_PROGRAMS.contains(&name.as_str()) {
                continue;
            }
            let rules_count = rules.as_ref().map(|r| r.len()).unwrap_or(0);
            let suffix = if rules_count > 0 {
                format!("  ({rules_count} allowed_args rules)")
            } else {
                String::new()
            };
            println!("  · {name}{suffix}");
        }
    } else {
        println!(
            "{COL_BOLD}user{COL_RESET}: ~/.aic/whitelist.toml 없음 (선택 사항 — builtin만 사용 가능)"
        );
    }
    println!(
        "\n{COL_BOLD}total{COL_RESET}: {} programs",
        wl.programs.len()
    );
}

/// `aic whitelist check "<cmd>"` — 단일 명령 4단 게이트 검사.
fn handle_whitelist_check(cmd: String) {
    use aic_client::agent::whitelist::{CheckResult, Whitelist};
    let wl = match Whitelist::load() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} whitelist 로드 실패: {e:#}");
            std::process::exit(2);
        }
    };
    let mut parts = cmd.split_whitespace();
    let Some(program) = parts.next() else {
        eprintln!("{COL_RED}✗{COL_RESET} cmd is empty");
        std::process::exit(2);
    };
    let args: Vec<String> = parts.map(String::from).collect();
    println!("program: {COL_BOLD}{program}{COL_RESET}");
    println!("args:    {args:?}");
    match wl.check(program, &args) {
        CheckResult::Allowed => {
            println!("result:  {COL_GREEN}ALLOW{COL_RESET}");
            std::process::exit(0);
        }
        CheckResult::Blocked { reason } => {
            println!("result:  {COL_RED}BLOCK{COL_RESET}");
            println!("reason:  {reason}");
            std::process::exit(1);
        }
    }
}

/// `aic hosts trust <name>` — RFC-005 §4.1 TOFU step 2~4 (scan + confirm + append).
///
/// 1. inventory에서 호스트 해석(hostname/port 추출)
/// 2. `ssh-keyscan -T {n} -p {port} {hostname}` 호출
/// 3. SHA256 fingerprint를 사용자에게 노출 + stdin prompt(또는 `--yes`)
/// 4. 승인 시 `~/.ssh/known_hosts`에 append
///
/// 보안 주의: ssh-keyscan 자체가 MITM 노출 위험 — 사용자에게 fingerprint를 외부 채널로
/// 검증할 것을 안내한다. `--yes`는 비대화 환경(CI) 용이지만 신뢰 가능한 네트워크에서만.
async fn handle_hosts_trust(name: String, timeout_secs: u32, yes: bool) {
    use aic_client::agent::hosts::Inventory;
    use aic_client::agent::remote::tofu;

    let inv = match Inventory::load() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 인벤토리 로드 실패: {e:#}");
            std::process::exit(2);
        }
    };
    let Some(host) = inv.host(&name) else {
        eprintln!("{COL_RED}✗{COL_RESET} host not found: {name}");
        std::process::exit(1);
    };

    println!(
        "{COL_BOLD}{}{COL_RESET}  →  {}:{}  (ssh-keyscan -T {timeout_secs}s)",
        host.name, host.hostname, host.port
    );
    let scan = match tofu::scan_host(&host.hostname, host.port, timeout_secs).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} ssh-keyscan 실패: {e:#}");
            eprintln!("    네트워크/DNS 점검 또는 ssh-keyscan 설치 확인.");
            std::process::exit(1);
        }
    };

    println!("\n{COL_BOLD}수집한 host key{COL_RESET} ({} 종)", scan.host_keys.len());
    for key in &scan.host_keys {
        let fp = match tofu::fingerprint_sha256(&key.known_hosts_line).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("    {COL_YELLOW}fingerprint 계산 실패:{COL_RESET} {e}");
                continue;
            }
        };
        println!("    {COL_BOLD}{}{COL_RESET}  {COL_GREEN}{fp}{COL_RESET}", key.key_type);
    }
    println!(
        "\n{COL_YELLOW}⚠ 보안:{COL_RESET} ssh-keyscan은 MITM 공격에 노출될 수 있다. fingerprint를"
    );
    println!("  외부 채널(서버 관리자 / 사내 wiki / 다른 호스트의 known_hosts)로 검증한 뒤 승인.");

    let accept = if yes {
        eprintln!("\n{COL_YELLOW}--yes 자동 승인 (보안 주의){COL_RESET}");
        true
    } else {
        use std::io::Write;
        eprint!("\nAccept and append to ~/.ssh/known_hosts? [y/N]: ");
        let _ = std::io::stderr().flush();
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            eprintln!("{COL_RED}✗{COL_RESET} stdin read failed (non-TTY?). use --yes for CI.");
            std::process::exit(1);
        }
        let trimmed = input.trim().to_lowercase();
        trimmed == "y" || trimmed == "yes"
    };

    if !accept {
        eprintln!("{COL_YELLOW}✗ rejected — known_hosts not modified{COL_RESET}");
        std::process::exit(1);
    }

    let Some(home) = dirs::home_dir() else {
        eprintln!("{COL_RED}✗{COL_RESET} $HOME not set");
        std::process::exit(2);
    };
    let known_hosts = home.join(".ssh").join("known_hosts");
    if let Err(e) = tofu::append_known_hosts(&known_hosts, &scan.host_keys) {
        eprintln!("{COL_RED}✗{COL_RESET} known_hosts append 실패: {e:#}");
        std::process::exit(2);
    }
    println!(
        "{COL_GREEN}✔{COL_RESET} added {} host key(s) to {}",
        scan.host_keys.len(),
        known_hosts.display()
    );
    println!("  이제 `aic hosts ping {}` 재시도 가능.", host.name);
}

enum SshAgentStatus {
    NoSocket,
    NoKeys(String),
    Loaded { sock: String, keys: usize },
    ProbeFailed(String),
}

async fn probe_local_ssh_agent() -> SshAgentStatus {
    let Ok(sock) = std::env::var("SSH_AUTH_SOCK") else {
        return SshAgentStatus::NoSocket;
    };
    match tokio::process::Command::new("ssh-add")
        .arg("-l")
        .output()
        .await
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let combined = if stdout.is_empty() {
                String::from_utf8_lossy(&out.stderr).to_string()
            } else {
                stdout.to_string()
            };
            if combined.contains("no identities") || combined.contains("agent has no") {
                SshAgentStatus::NoKeys(sock)
            } else {
                let keys = combined
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .count();
                SshAgentStatus::Loaded { sock, keys }
            }
        }
        Err(e) => SshAgentStatus::ProbeFailed(format!("ssh-add not available: {e}")),
    }
}

/// `aic status --json`: 단일 세션 status를 JSON으로 출력.
async fn print_status_json(session: Option<&str>) {
    let socket_path = resolve_socket(session);
    let pid_path = socket_path.with_extension("pid");
    let pid = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());

    let client = UdsClient::new(socket_path.clone());
    let alive = client.ping().await.unwrap_or(false);

    let mut obj = serde_json::Map::new();
    obj.insert(
        "socket".into(),
        serde_json::Value::String(socket_path.display().to_string()),
    );
    obj.insert(
        "pid_file".into(),
        serde_json::Value::String(pid_path.display().to_string()),
    );
    obj.insert(
        "pid".into(),
        match pid {
            Some(p) => serde_json::Value::from(p),
            None => serde_json::Value::Null,
        },
    );
    obj.insert("alive".into(), serde_json::Value::Bool(alive));
    if alive {
        if let Ok(m) = client.get_metrics().await {
            obj.insert(
                "metrics".into(),
                serde_json::to_value(&m).unwrap_or(serde_json::Value::Null),
            );
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{}".into())
    );
}

/// `aic status --all --json`: 모든 활성 세션 list를 JSON으로 출력.
async fn print_sessions_json() {
    let aicd_client = UdsClient::new(aic_common::aicd_socket_path());
    if let Ok(true) = aicd_client.ping().await {
        match aicd_client.list_sessions().await {
            Ok(list) => {
                let arr: Vec<serde_json::Value> =
                    list.into_iter().map(registry_session_json).collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::Value::Array(arr))
                        .unwrap_or_else(|_| "[]".into())
                );
                return;
            }
            Err(e) => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} aicd registry 조회 실패 — file-system scan으로 fallback: {e}"
                );
            }
        }
    }

    let sessions = list_sessions();
    let arr: Vec<serde_json::Value> = sessions
        .into_iter()
        .map(|s| {
            let mut o = serde_json::Map::new();
            o.insert("session_id".into(), serde_json::Value::String(s.session_id));
            o.insert(
                "socket".into(),
                serde_json::Value::String(s.socket_path.display().to_string()),
            );
            o.insert("alive".into(), serde_json::Value::Bool(s.is_alive));
            serde_json::Value::Object(o)
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Array(arr))
            .unwrap_or_else(|_| "[]".into())
    );
}

fn registry_session_json(s: aic_common::SessionInfo) -> serde_json::Value {
    serde_json::json!({
        "session_id": s.id,
        "pid": s.pid,
        "state": format!("{:?}", s.state).to_lowercase(),
        "created_at": s.created_at,
        "last_seen_at": s.last_seen_at,
        "last_command_at": s.last_command_at,
        "attached_tty": s.attached_tty,
        "shell": s.shell,
        "cwd": s.cwd,
    })
}

/// `aic status [--watch] [--interval N] [--session ID] [--json] [--all]`: 데몬 상태 출력.
async fn handle_status(watch: bool, interval: u64, session: Option<String>, json: bool, all: bool) {
    if all {
        if json {
            print_sessions_json().await;
        } else {
            handle_sessions().await;
        }
        return;
    }
    if json && watch {
        eprintln!("{COL_YELLOW}⚠{COL_RESET} --json은 --watch와 함께 쓸 수 없습니다.");
        std::process::exit(2);
    }
    if !watch {
        if json {
            print_status_json(session.as_deref()).await;
        } else {
            print_status_once(session.as_deref()).await;
        }
        return;
    }

    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).ok();
    let mut sigterm = signal(SignalKind::terminate()).ok();
    let interval = interval.max(1);

    loop {
        // clear screen + cursor home (ANSI)
        print!("\x1b[2J\x1b[H");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        print_status_once(session.as_deref()).await;
        println!();
        let now = chrono::Local::now().format("%H:%M:%S");
        println!("{COL_DIM}── watch (interval {interval}s · {now}) — Ctrl+C로 종료 ──{COL_RESET}");

        let sleep = tokio::time::sleep(std::time::Duration::from_secs(interval));
        tokio::pin!(sleep);

        let stop = tokio::select! {
            _ = &mut sleep => false,
            _ = async {
                if let Some(s) = sigint.as_mut() { s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => true,
            _ = async {
                if let Some(s) = sigterm.as_mut() { s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => true,
        };
        if stop {
            println!();
            break;
        }
    }
}

/// 데몬 PID/ping/마지막 명령어 요약을 1회 출력.
async fn print_status_once(session: Option<&str>) {
    println!("{COL_BOLD}aic-session 상태{COL_RESET}");

    let socket_path = resolve_socket(session);
    let pid_path = socket_path.with_extension("pid");

    let pid = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());

    let client = UdsClient::new(socket_path.clone());
    let ping_start = std::time::Instant::now();
    let alive = client.ping().await.unwrap_or(false);
    let ping_ms = ping_start.elapsed().as_secs_f64() * 1000.0;

    println!("  socket:    {}", socket_path.display());
    println!("  pid file:  {}", pid_path.display());
    match pid {
        Some(pid) => println!("  pid:       {pid}"),
        None => println!("  pid:       {COL_DIM}(lock 파일 없음){COL_RESET}"),
    }
    println!(
        "  ping:      {}",
        if alive {
            format!("{COL_GREEN}✔{COL_RESET} ({ping_ms:.2}ms)")
        } else {
            format!("{COL_YELLOW}✗ 응답 없음{COL_RESET} ({ping_ms:.2}ms)")
        }
    );

    if alive {
        // metrics
        if let Ok(m) = client.get_metrics().await {
            println!();
            println!("  metrics:");
            let h = m.uptime_secs / 3600;
            let mn = (m.uptime_secs / 60) % 60;
            let s = m.uptime_secs % 60;
            println!("    uptime:    {h}h {mn}m {s}s");
            println!("    pid:       {} (from daemon)", m.pid);
            println!("    ipc reqs:  {} (cumulative)", m.ipc_request_count);
            let pct = if m.rb_capacity > 0 {
                (m.rb_used as f64 / m.rb_capacity as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "    rb usage:  {used}/{cap} lines ({pct:.1}%)",
                used = m.rb_used,
                cap = m.rb_capacity
            );
            if let Some(secs) = m.last_command_secs_ago {
                println!("    last cmd:  {secs}s ago");
            }
        }

        // Phase 3.2 Task 2.2: cascade 를 선호하고, 가능하지 않으면 legacy 단일-소켓 경로.
        let status_cascade = build_cascade_for_session_path(&socket_path);
        let last_res = if let Some(ref c) = status_cascade {
            match c.get_last_command().await {
                Ok(Some(r)) => Ok(r),
                Ok(None) => Err(aic_common::AicError::UserMessage(
                    "저장된 명령어가 없습니다".to_string(),
                )),
                Err(e) => Err(e),
            }
        } else {
            client.get_last_command().await
        };
        match last_res {
            Ok(rec) => {
                let cmd = rec.command.as_deref().unwrap_or("(unknown)");
                println!();
                println!("  마지막 명령어:");
                println!("    $ {cmd} (exit {code})", code = rec.exit_code);
                println!("    출력 {n} 라인", n = rec.output_lines.len());
            }
            Err(e) => {
                println!("  마지막 명령어: {COL_DIM}조회 실패 ({e}){COL_RESET}");
            }
        }
    }
}
/// `aic doctor [--json]`: 환경 진단 리포트 출력. FAIL이 하나라도 있으면 exit 1.
async fn handle_doctor_fix(dry_run: bool) {
    println!(
        "{COL_BOLD}aic doctor --fix{COL_RESET}{}",
        if dry_run {
            format!(" {COL_DIM}(dry-run){COL_RESET}")
        } else {
            String::new()
        }
    );

    // 1. aicd ping → 응답 없으면 spawn 시도.
    let aicd_sock = aic_common::aicd_socket_path();
    let aicd_client = UdsClient::new(aicd_sock.clone());
    let aicd_alive = matches!(aicd_client.ping().await, Ok(true));
    if aicd_alive {
        println!("  {COL_GREEN}✓{COL_RESET} aicd 응답 OK");
    } else if dry_run {
        println!("  {COL_YELLOW}⚠{COL_RESET} aicd 응답 없음 — (dry-run) 데몬 시작 예정");
    } else {
        println!("  {COL_YELLOW}⚠{COL_RESET} aicd 응답 없음 → 데몬 시작");
        handle_daemon_start(false).await;
    }

    // 2. hook 파일 ensure (~/.aic/hooks.{zsh,bash}).
    let hook_dir = dirs::home_dir().map(|h| h.join(".aic"));
    match hook_dir {
        Some(dir) => {
            println!("  {COL_DIM}↳{COL_RESET} hook 파일 위치: {}", dir.display());
            if !dry_run {
                let zsh_path = dir.join("hooks.zsh");
                let bash_path = dir.join("hooks.bash");
                let result = (|| -> std::io::Result<()> {
                    std::fs::create_dir_all(&dir)?;
                    std::fs::write(&zsh_path, aic_client::hook_install::zsh_hook_script())?;
                    std::fs::write(&bash_path, aic_client::hook_install::bash_hook_script())?;
                    Ok(())
                })();
                match result {
                    Ok(()) => println!("  {COL_GREEN}✓{COL_RESET} hook 파일 재생성"),
                    Err(e) => println!("  {COL_RED}✗{COL_RESET} hook 재생성 실패: {e}"),
                }
            } else {
                println!("  {COL_DIM}↳ (dry-run) zsh/bash hook 스크립트 덮어쓰기 예정{COL_RESET}");
            }
        }
        None => println!("  {COL_YELLOW}⚠{COL_RESET} HOME 경로를 알 수 없어 hook 재생성 건너뜀"),
    }

    // 3. stale session artifacts는 aicd가 부팅 시 정리한다.
    //    여기서는 사용자에게 안내만 — 별도 client-side cleanup은 단계 4의 prune이 커버.
    println!("  {COL_DIM}↳ stale .sock/.pid 정리는 aicd 부팅 단계에서 자동 수행{COL_RESET}");

    // 4. registry inactive 1시간 초과 prune. dry-run이면 항상 안내만, 아니면 ping
    //    재확인 후 실제 호출.
    if dry_run {
        println!("  {COL_DIM}↳ (dry-run) registry prune (--older-than-secs 3600) 예정{COL_RESET}");
    } else {
        let recheck = matches!(aicd_client.ping().await, Ok(true));
        if recheck {
            match aicd_client.prune_sessions(3600).await {
                Ok(count) => println!("  {COL_GREEN}✓{COL_RESET} registry prune (제거 {count}개)"),
                Err(e) => println!("  {COL_YELLOW}⚠{COL_RESET} prune 실패: {e}"),
            }
        } else {
            println!(
                "  {COL_YELLOW}⚠{COL_RESET} aicd 응답 없음 — registry prune 건너뜀 (단계 1을 다시 실행해 보세요)"
            );
        }
    }

    println!("{COL_DIM}완료. 자세한 진단은 `aic doctor`로 확인.{COL_RESET}");
}

/// `aic doctor --probe-tools` — opt-in tool-calling live probe (GA Gate G1-b).
///
/// 설정된 provider에 최소 tool spec으로 `send_messages`를 1회 보내 결과를 진단한다.
/// ok / unsupported / degraded / error / skip(credential 없음)으로 분류해 출력한다.
/// 세션 시작 시 자동 수행하지 않으며, 이 명령으로만 실제 네트워크 호출이 발생한다.
async fn handle_doctor_probe_tools(provider_override: Option<String>) {
    use aic_client::agent::{ChatMessage, ChatResponse, ToolSpec};

    let config = match ConfigManager::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config 로드 실패: {e}");
            std::process::exit(2);
        }
    };
    // CLI --provider override를 config(default_provider)에 실제 반영 → probe가 override provider를 검증.
    let (config, provider_name) =
        match apply_provider_override(config, provider_override.as_deref()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
    let model_name = config
        .llm
        .providers
        .get(&provider_name)
        .and_then(|p| p.model.clone())
        .unwrap_or_else(|| "(provider default)".to_string());
    let dispatcher = LlmDispatcher::from_config(config.llm.clone());

    println!("tool-calling live probe");
    println!("  provider: {provider_name}");
    println!("  model: {model_name}");

    if !dispatcher.supports_tool_calling() {
        println!(
            "  result: unsupported — provider_type가 OpenAI 호환이 아님(정적 판정). \
             `aic chat`은 ReplSession(단발 send)으로 폴백합니다."
        );
        return;
    }

    // 최소 tool spec + user 메시지로 1회 호출(probe 전용 — 모델이 호출할 필요 없음).
    let tools = vec![ToolSpec {
        name: "noop_probe",
        description: "probe only; do not call",
        parameters: serde_json::json!({"type": "object", "properties": {}}),
    }];
    let msgs = vec![ChatMessage::User("reply with: ok".to_string())];

    match dispatcher.send_messages(&msgs, &tools).await {
        Ok(ChatResponse::Text(_)) => {
            println!("  result: ok — provider가 `tools` 파라미터를 수락하고 텍스트로 응답함.");
        }
        Ok(ChatResponse::ToolCalls(_)) => {
            println!("  result: ok — provider가 tool_calls를 반환함(tool-calling 동작).");
        }
        Err(aic_common::AicError::ApiKeyMissing { provider }) => {
            println!(
                "  result: skip — API key 미설정({provider}). 네트워크 호출 없이 종료. \
                 credential 설정 후 다시 실행하세요."
            );
        }
        Err(aic_common::AicError::ConfigError(m)) => {
            println!("  result: unsupported — {m}");
        }
        Err(aic_common::AicError::LlmApiError { status, message }) => {
            if matches!(status, 400 | 404 | 405 | 415 | 422 | 501) {
                println!(
                    "  result: degraded — provider가 `tools`를 거부(HTTP {status}). \
                     `aic chat`은 런타임에 일반 대화로 degrade합니다."
                );
            } else if status == 0 {
                println!("  result: error — 네트워크 오류: {message} (연결/endpoint 확인).");
            } else {
                println!("  result: error — HTTP {status}: {message} (auth/endpoint 확인).");
            }
        }
        Err(e) => {
            println!("  result: error — {e}");
        }
    }
}

async fn handle_doctor(json: bool, session: Option<String>) {
    let socket = resolve_socket(session.as_deref());
    let results = aic_client::doctor::run_all_checks(&socket).await;
    // Central Store 섹션 (R14.6): 세션 socket 이 실제로 존재할 때만 GetMetrics 를 시도.
    // 없거나 실패하면 report 내부의 session_metrics_error 에 기록된다.
    let session_socket: Option<&std::path::Path> =
        if socket.exists() { Some(&socket) } else { None };
    let central_store = aic_client::doctor::probe_central_store_default(session_socket).await;
    if json {
        #[derive(serde::Serialize)]
        struct DoctorReport<'a> {
            checks: &'a [aic_client::doctor::CheckResult],
            central_store: &'a aic_client::doctor::CentralStoreReport,
        }
        let report = DoctorReport {
            checks: &results,
            central_store: &central_store,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("JSON 직렬화 실패: {e}");
                std::process::exit(2);
            }
        }
    } else {
        aic_client::doctor::print_report(&results);
        aic_client::doctor::print_central_store_section(&central_store);
    }
    let any_fail = results
        .iter()
        .any(|r| r.status == aic_client::doctor::Status::Fail);
    if any_fail {
        std::process::exit(1);
    }
}

/// `ac config`: 인터랙티브 설정 UI
fn handle_config() {
    let path = ConfigManager::config_path();
    println!("설정 파일: {}\n", path.display());

    let theme = ColorfulTheme::default();

    let options = &[
        "현재 설정 보기",
        "LLM Provider 설정",
        "응답 언어 설정",
        "설정 파일 직접 편집 (예제 포함)",
        "종료",
    ];

    loop {
        let selection = Select::with_theme(&theme)
            .with_prompt("무엇을 하시겠습니까?")
            .items(options)
            .default(0)
            .interact()
            .unwrap_or(4);

        match selection {
            0 => show_current_config(),
            1 => configure_llm_provider(),
            2 => configure_lang(),
            3 => show_config_example(),
            _ => break,
        }
        println!();
    }
}

fn show_current_config() {
    match ConfigManager::load() {
        Ok(config) => match toml::to_string_pretty(&config) {
            Ok(s) => println!("\n현재 설정:\n{s}"),
            Err(e) => eprintln!("설정 직렬화 실패: {e}"),
        },
        Err(e) => eprintln!("설정 로드 실패: {e}"),
    }
}

fn configure_llm_provider() {
    let theme = ColorfulTheme::default();
    let existing_config = ConfigManager::load().ok();

    let providers = &[
        "OpenAI (gpt-4o, gpt-4o-mini)",
        "Anthropic (claude-sonnet-4-6, claude-opus-4-7, claude-haiku-4-5)",
        "Groq (llama-3.3-70b, llama-3.1-8b-instant)",
        "NVIDIA NIM (qwen, nemotron, llama)",
        "Kiro CLI (로컬)",
        "Claude CLI (로컬)",
        "뒤로",
    ];

    let selection = Select::with_theme(&theme)
        .with_prompt("LLM Provider 선택")
        .items(providers)
        .default(0)
        .interact()
        .unwrap_or(6);

    let (provider_name, provider_config) = match selection {
        0 => configure_openai(&theme, &existing_config),
        1 => configure_anthropic(&theme, &existing_config),
        2 => configure_groq(&theme, &existing_config),
        3 => configure_nvidia(&theme, &existing_config),
        4 => configure_kiro_cli(&theme, &existing_config),
        5 => configure_claude_cli(&theme, &existing_config),
        _ => return,
    };

    if provider_name.is_empty() {
        return;
    }

    // 설정 저장
    let mut config = existing_config.unwrap_or_else(default_config);
    config.llm.default_provider = provider_name.clone();
    config
        .llm
        .providers
        .insert(provider_name.clone(), provider_config);

    if let Err(e) = save_config(&config) {
        eprintln!("설정 저장 실패: {e}");
    } else {
        println!("설정이 저장되었습니다.");
    }
}

fn configure_lang() {
    let theme = ColorfulTheme::default();
    let existing_config = ConfigManager::load().ok();
    let current_lang = existing_config
        .as_ref()
        .map(|c| c.llm.lang.as_str())
        .unwrap_or("korean");

    println!("\n현재 언어: {}\n", current_lang);

    let langs = &["korean", "english", "japanese", "chinese"];
    let default_idx = langs.iter().position(|&l| l == current_lang).unwrap_or(0);

    let selection = Select::with_theme(&theme)
        .with_prompt("응답 언어 선택")
        .items(langs)
        .default(default_idx)
        .interact()
        .unwrap_or(default_idx);

    let mut config = existing_config.unwrap_or_else(default_config);
    config.llm.lang = langs[selection].to_string();

    if let Err(e) = save_config(&config) {
        eprintln!("설정 저장 실패: {e}");
    } else {
        println!("응답 언어가 '{}'로 설정되었습니다.", langs[selection]);
    }
}

/// API Key를 마스킹해서 표시 (앞 8문자 + *** + 뒤 4문자).
/// chars 단위 — UTF-8 multi-byte 키가 들어와도 panic 없이 안전 처리.
fn mask_api_key(key: &str) -> String {
    let total = key.chars().count();
    if total <= 12 {
        return "***".to_string();
    }
    let head: String = key.chars().take(8).collect();
    let tail: String = key.chars().skip(total - 4).collect();
    format!("{head}***{tail}")
}

#[cfg(test)]
mod mask_api_key_tests {
    use super::mask_api_key;

    #[test]
    fn short_key_returns_stars() {
        assert_eq!(mask_api_key(""), "***");
        assert_eq!(mask_api_key("short"), "***");
        assert_eq!(mask_api_key("abcdefghijkl"), "***"); // 12 chars
    }

    #[test]
    fn long_ascii_key_masked() {
        // 22 chars → 앞 8 + *** + 뒤 4
        let result = mask_api_key("sk-1234567890abcdefXYZ");
        assert!(result.starts_with("sk-12345"));
        assert!(result.contains("***"));
        assert!(result.ends_with("fXYZ"));
    }

    #[test]
    fn multibyte_key_does_not_panic() {
        // 16 chars (multibyte 포함) — UTF-8 byte slicing이면 panic. chars 기반이면 안전.
        let key = "키1234567890키키키키";
        let result = mask_api_key(key);
        assert!(result.contains("***"));
        assert!(result.starts_with("키1234567"));
        assert!(result.ends_with("키키키키"));
    }
}

/// 기존 Provider 설정 가져오기
fn get_existing_provider(config: &Option<AppConfig>, name: &str) -> Option<ProviderConfig> {
    config.as_ref()?.llm.providers.get(name).cloned()
}

fn configure_openai(
    theme: &ColorfulTheme,
    existing_config: &Option<AppConfig>,
) -> (String, ProviderConfig) {
    println!("\nOpenAI 설정");
    println!("API Key: https://platform.openai.com/api-keys\n");

    let existing = get_existing_provider(existing_config, "openai");
    let existing_key = existing.as_ref().and_then(|p| p.api_key.as_ref());
    let existing_model = existing.as_ref().and_then(|p| p.model.as_ref());

    // 기존 설정 표시
    if let Some(key) = existing_key {
        println!("현재 API Key: {}", mask_api_key(key));
    }
    if let Some(model) = existing_model {
        println!("현재 모델: {}", model);
    }
    if existing_key.is_some() {
        println!();
    }

    let api_key: String = Input::with_theme(theme)
        .with_prompt("API Key (sk-..., 유지하려면 Enter)")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_default();

    let final_key = if api_key.is_empty() {
        existing_key.cloned()
    } else {
        Some(api_key)
    };

    if final_key.is_none() {
        println!("API Key가 필요합니다.");
        return (
            String::new(),
            ProviderConfig {
                provider_type: ProviderType::OpenAiCompatible,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: None,
                cli_args: None,
            },
        );
    }

    let models = &["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"];
    let default_idx = existing_model
        .and_then(|m| models.iter().position(|&x| x == m))
        .unwrap_or(0);

    let model_idx = Select::with_theme(theme)
        .with_prompt("모델 선택")
        .items(models)
        .default(default_idx)
        .interact()
        .unwrap_or(0);

    (
        "openai".to_string(),
        ProviderConfig {
            provider_type: ProviderType::OpenAiCompatible,
            endpoint: Some("https://api.openai.com/v1/chat/completions".to_string()),
            api_key: final_key,
            model: Some(models[model_idx].to_string()),
            cli_path: None,
            cli_args: None,
        },
    )
}

fn configure_anthropic(
    theme: &ColorfulTheme,
    existing_config: &Option<AppConfig>,
) -> (String, ProviderConfig) {
    println!("\nAnthropic 설정");
    println!("API Key: https://console.anthropic.com/settings/keys\n");

    let existing = get_existing_provider(existing_config, "anthropic");
    let existing_key = existing.as_ref().and_then(|p| p.api_key.as_ref());
    let existing_model = existing.as_ref().and_then(|p| p.model.as_ref());

    if let Some(key) = existing_key {
        println!("현재 API Key: {}", mask_api_key(key));
    }
    if let Some(model) = existing_model {
        println!("현재 모델: {}", model);
    }
    if existing_key.is_some() {
        println!();
    }

    let api_key: String = Input::with_theme(theme)
        .with_prompt("API Key (sk-ant-..., 유지하려면 Enter)")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_default();

    let final_key = if api_key.is_empty() {
        existing_key.cloned()
    } else {
        Some(api_key)
    };

    if final_key.is_none() {
        println!("API Key가 필요합니다.");
        return (
            String::new(),
            ProviderConfig {
                provider_type: ProviderType::Anthropic,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: None,
                cli_args: None,
            },
        );
    }

    // 권장: claude-sonnet-4-6 (균형, 기본). claude-3-* 시리즈는 retire되어
    // 404를 반환할 수 있으므로 옵션에 두지 않는다 — 사용자가 직접 명시할 수는 있다.
    let models = &[
        "claude-sonnet-4-6",
        "claude-opus-4-7",
        "claude-haiku-4-5-20251001",
    ];
    let default_idx = existing_model
        .and_then(|m| models.iter().position(|&x| x == m))
        .unwrap_or(0);

    let model_idx = Select::with_theme(theme)
        .with_prompt("모델 선택")
        .items(models)
        .default(default_idx)
        .interact()
        .unwrap_or(0);

    (
        "anthropic".to_string(),
        ProviderConfig {
            provider_type: ProviderType::Anthropic,
            endpoint: Some("https://api.anthropic.com/v1/messages".to_string()),
            api_key: final_key,
            model: Some(models[model_idx].to_string()),
            cli_path: None,
            cli_args: None,
        },
    )
}

fn configure_groq(
    theme: &ColorfulTheme,
    existing_config: &Option<AppConfig>,
) -> (String, ProviderConfig) {
    println!("\nGroq 설정");
    println!("API Key: https://console.groq.com/keys\n");

    let existing = get_existing_provider(existing_config, "groq");
    let existing_key = existing.as_ref().and_then(|p| p.api_key.as_ref());
    let existing_model = existing.as_ref().and_then(|p| p.model.as_ref());

    if let Some(key) = existing_key {
        println!("현재 API Key: {}", mask_api_key(key));
    }
    if let Some(model) = existing_model {
        println!("현재 모델: {}", model);
    }
    if existing_key.is_some() {
        println!();
    }

    let api_key: String = Input::with_theme(theme)
        .with_prompt("API Key (gsk_..., 유지하려면 Enter)")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_default();

    let final_key = if api_key.is_empty() {
        existing_key.cloned()
    } else {
        Some(api_key)
    };

    if final_key.is_none() {
        println!("API Key가 필요합니다.");
        return (
            String::new(),
            ProviderConfig {
                provider_type: ProviderType::Groq,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: None,
                cli_args: None,
            },
        );
    }

    let models = &[
        "llama-3.1-8b-instant",
        "llama-3.3-70b-versatile",
        "deepseek-r1-distill-llama-70b",
        "gemma2-9b-it",
    ];
    let default_idx = existing_model
        .and_then(|m| models.iter().position(|&x| x == m))
        .unwrap_or(1);

    let model_idx = Select::with_theme(theme)
        .with_prompt("모델 선택")
        .items(models)
        .default(default_idx)
        .interact()
        .unwrap_or(1);

    (
        "groq".to_string(),
        ProviderConfig {
            provider_type: ProviderType::Groq,
            endpoint: Some("https://api.groq.com/openai/v1/chat/completions".to_string()),
            api_key: final_key,
            model: Some(models[model_idx].to_string()),
            cli_path: None,
            cli_args: None,
        },
    )
}

fn configure_nvidia(
    theme: &ColorfulTheme,
    existing_config: &Option<AppConfig>,
) -> (String, ProviderConfig) {
    println!("\nNVIDIA NIM 설정");
    println!("API Key: https://build.nvidia.com\n");

    let existing = get_existing_provider(existing_config, "nvidia");
    let existing_key = existing.as_ref().and_then(|p| p.api_key.as_ref());
    let existing_model = existing.as_ref().and_then(|p| p.model.as_ref());

    if let Some(key) = existing_key {
        println!("현재 API Key: {}", mask_api_key(key));
    }
    if let Some(model) = existing_model {
        println!("현재 모델: {}", model);
    }
    if existing_key.is_some() {
        println!();
    }

    let api_key: String = Input::with_theme(theme)
        .with_prompt("API Key (nvapi-..., 유지하려면 Enter)")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_default();

    let final_key = if api_key.is_empty() {
        existing_key.cloned()
    } else {
        Some(api_key)
    };

    if final_key.is_none() {
        println!("API Key가 필요합니다.");
        return (
            String::new(),
            ProviderConfig {
                provider_type: ProviderType::OpenAiCompatible,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: None,
                cli_args: None,
            },
        );
    }

    // 가벼운 모델부터 무거운 모델 순서
    let models = &[
        "meta/llama-3.1-8b-instruct",
        "qwen/qwen2.5-coder-32b-instruct",
        "meta/llama-3.1-70b-instruct",
        "nvidia/nemotron-3-super-120b-a12b",
        "meta/llama-3.1-405b-instruct",
        "mistralai/mixtral-8x22b-instruct-v0.1",
    ];
    let default_idx = existing_model
        .and_then(|m| models.iter().position(|&x| x == m))
        .unwrap_or(0);

    let model_idx = Select::with_theme(theme)
        .with_prompt("모델 선택 (위에서부터 가벼운 순)")
        .items(models)
        .default(default_idx)
        .interact()
        .unwrap_or(0);

    (
        "nvidia".to_string(),
        ProviderConfig {
            provider_type: ProviderType::OpenAiCompatible,
            endpoint: Some("https://integrate.api.nvidia.com/v1/chat/completions".to_string()),
            api_key: final_key,
            model: Some(models[model_idx].to_string()),
            cli_path: None,
            cli_args: None,
        },
    )
}

fn configure_kiro_cli(
    theme: &ColorfulTheme,
    existing_config: &Option<AppConfig>,
) -> (String, ProviderConfig) {
    println!("\nKiro CLI 설정");
    println!("Kiro CLI가 설치되어 있어야 합니다.\n");

    let existing = get_existing_provider(existing_config, "kiro-cli");
    let existing_path = existing.as_ref().and_then(|p| p.cli_path.as_ref());

    if let Some(path) = existing_path {
        println!("현재 CLI 경로: {}\n", path);
    }

    let default_path = existing_path.map(|s| s.as_str()).unwrap_or("kiro");
    let cli_path: String = Input::with_theme(theme)
        .with_prompt("CLI 경로")
        .default(default_path.to_string())
        .interact_text()
        .unwrap_or_else(|_| default_path.to_string());

    (
        "kiro-cli".to_string(),
        ProviderConfig {
            provider_type: ProviderType::CliBackend,
            endpoint: None,
            api_key: None,
            model: None,
            cli_path: Some(cli_path),
            cli_args: None,
        },
    )
}

fn configure_claude_cli(
    theme: &ColorfulTheme,
    existing_config: &Option<AppConfig>,
) -> (String, ProviderConfig) {
    println!("\nClaude CLI 설정");
    println!("Claude CLI가 설치되어 있어야 합니다.\n");

    let existing = get_existing_provider(existing_config, "claude-cli");
    let existing_path = existing.as_ref().and_then(|p| p.cli_path.as_ref());

    if let Some(path) = existing_path {
        println!("현재 CLI 경로: {}\n", path);
    }

    let default_path = existing_path.map(|s| s.as_str()).unwrap_or("claude");
    let cli_path: String = Input::with_theme(theme)
        .with_prompt("CLI 경로")
        .default(default_path.to_string())
        .interact_text()
        .unwrap_or_else(|_| default_path.to_string());

    (
        "claude-cli".to_string(),
        ProviderConfig {
            provider_type: ProviderType::CliBackend,
            endpoint: None,
            api_key: None,
            model: None,
            cli_path: Some(cli_path),
            cli_args: None,
        },
    )
}

fn show_config_example() {
    let path = ConfigManager::config_path();

    let example = r#"# AIC 설정 파일 예제
# 파일 위치: ~/.config/aic/config.toml

[llm]
# 기본 Provider 선택: "openai", "anthropic", "groq", "nvidia", "kiro-cli", "claude-cli"
default_provider = "openai"
# 응답 언어: "korean", "english", "japanese", "chinese" 등
lang = "korean"
# TCP 연결 타임아웃(초) — endpoint reachability 확인. 기본 5
connect_timeout_secs = 5
# 요청 전체 타임아웃(초) — LLM 응답 대기 포함. 405b 같은 큰 모델은 60+ 권장. 기본 30
request_timeout_secs = 30

# OpenAI 설정
[llm.providers.openai]
provider_type = "OpenAiCompatible"
endpoint = "https://api.openai.com/v1/chat/completions"
api_key = "sk-your-api-key-here"
model = "gpt-4o-mini"

# Anthropic 설정 (선택)
# 모델 권장: claude-sonnet-4-6 (균형) / claude-opus-4-7 (최강) /
#            claude-haiku-4-5-20251001 (저렴/빠름).
# claude-3-5-* 시리즈는 retire되어 404가 발생할 수 있습니다.
[llm.providers.anthropic]
provider_type = "Anthropic"
endpoint = "https://api.anthropic.com/v1/messages"
api_key = "sk-ant-your-api-key-here"
model = "claude-sonnet-4-6"

# Groq 설정 (선택, OpenAI 호환 — endpoint/model 미지정 시 Groq 기본값 적용)
[llm.providers.groq]
provider_type = "Groq"
api_key = "gsk_your-api-key-here"
model = "llama-3.3-70b-versatile"
# 다른 모델 옵션:
# - llama-3.1-8b-instant
# - deepseek-r1-distill-llama-70b
# - gemma2-9b-it
# endpoint를 명시하지 않으면 https://api.groq.com/openai/v1/chat/completions 사용

# NVIDIA NIM 설정 (선택)
[llm.providers.nvidia]
provider_type = "OpenAiCompatible"
endpoint = "https://integrate.api.nvidia.com/v1/chat/completions"
api_key = "nvapi-your-api-key-here"
model = "meta/llama-3.1-8b-instruct"
# 다른 모델 옵션:
# - qwen/qwen2.5-coder-32b-instruct
# - meta/llama-3.1-70b-instruct
# - nvidia/nemotron-3-super-120b-a12b
# - meta/llama-3.1-405b-instruct

# Kiro CLI 설정 (선택)
[llm.providers.kiro-cli]
provider_type = "CliBackend"
cli_path = "kiro"

# Claude CLI 설정 (선택)
[llm.providers.claude-cli]
provider_type = "CliBackend"
cli_path = "claude"

[server]
max_buffer_lines = 500
# socket_path = "/tmp/aic-session.sock"  # 기본값 사용 시 생략

[server.boundary_strategy]
method = "prompt_marker"
# idle_threshold_ms = 500  # timing_heuristic 사용 시

# 환경변수:
# AIC_DEBUG=1  디버그 모드 활성화 (로그 출력)
"#;

    println!("\n{}", example);
    println!("설정 파일 경로: {}", path.display());

    let theme = ColorfulTheme::default();
    if Confirm::with_theme(&theme)
        .with_prompt("이 예제를 설정 파일로 저장할까요?")
        .default(false)
        .interact()
        .unwrap_or(false)
    {
        // 디렉토리 생성
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if let Err(e) = std::fs::write(&path, example) {
            eprintln!("파일 저장 실패: {e}");
        } else {
            println!("예제가 {}에 저장되었습니다.", path.display());
            println!("API Key를 실제 값으로 수정하세요.");
        }
    }
}

fn default_config() -> AppConfig {
    AppConfig {
        llm: LlmConfig {
            default_provider: "openai".to_string(),
            providers: HashMap::new(),
            lang: "korean".to_string(),
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        },
        server: ServerConfig {
            max_buffer_lines: 500,
            socket_path: None,
            boundary_strategy: BoundaryStrategyConfig {
                method: "prompt_marker".to_string(),
                idle_threshold_ms: None,
            },
        },
        session: aic_common::SessionConfig::default(),
    }
}

fn save_config(config: &AppConfig) -> anyhow::Result<()> {
    let path = ConfigManager::config_path();

    // 디렉토리 생성
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let toml_str = toml::to_string_pretty(config)?;
    std::fs::write(&path, toml_str)?;
    Ok(())
}

// ── 세션 목록 조회 ──────────────────────────────────────────────

/// 세션 목록 항목.
struct SessionInfo {
    session_id: String,
    socket_path: std::path::PathBuf,
    is_alive: bool,
}

/// `session_dir()` 내의 `session-*.sock` 파일을 스캔하여 세션 목록을 반환한다.
/// 각 소켓에 `UnixStream::connect`를 시도하여 활성 여부를 판별한다.
fn list_sessions() -> Vec<SessionInfo> {
    let dir = aic_common::session_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut sessions = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(id) = aic_common::extract_session_id(&path) {
            // connect 후 즉시 정상 종료하여 서버 측 early eof 경고 방지
            let is_alive = match std::os::unix::net::UnixStream::connect(&path) {
                Ok(stream) => {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    true
                }
                Err(_) => false,
            };
            sessions.push(SessionInfo {
                session_id: id,
                socket_path: path,
                is_alive,
            });
        }
    }

    sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    sessions
}

/// `aic sessions`: 실행 중인 세션 목록을 출력한다.
///
/// Phase 1.5 이후 우선순위:
/// 1. `aicd`가 떠 있으면 control registry를 source-of-truth로 사용한다.
/// 2. `aicd`가 없으면 기존 file-system scan(`list_sessions()`)으로 fallback —
///    aicd 없이도 멀티세션은 동작해야 하므로.
async fn handle_sessions_interactive() {
    use std::io::{self, BufRead, IsTerminal, Write};

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "{COL_RED}✗{COL_RESET} --interactive는 TTY가 필요합니다 — pipe/CI 환경에서는 \
             `aic sessions` 또는 `aic sessions --json`을 사용하세요."
        );
        std::process::exit(1);
    }

    let aicd_client = UdsClient::new(aic_common::aicd_socket_path());
    let aicd_alive = matches!(aicd_client.ping().await, Ok(true));
    if !aicd_alive {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} aicd 응답 없음 — interactive 모드는 aicd가 필요합니다 (`aic daemon start`)."
        );
        std::process::exit(1);
    }

    let list = match aicd_client.list_sessions().await {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => {
            println!("{COL_DIM}aicd registry: 등록된 세션 없음{COL_RESET}");
            return;
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} 세션 목록 조회 실패: {e}");
            std::process::exit(1);
        }
    };

    let current_id = std::env::var("AIC_SESSION_ID").ok();

    println!("{COL_BOLD}aic sessions{COL_RESET} {COL_DIM}(interactive){COL_RESET}");
    for (idx, s) in list.iter().enumerate() {
        let marker = match &current_id {
            Some(cid) if cid == &s.id => format!(" {COL_GREEN}*current{COL_RESET}"),
            _ => String::new(),
        };
        let label = s
            .label
            .as_deref()
            .map(|l| format!(" [{COL_BOLD}{l}{COL_RESET}]"))
            .unwrap_or_default();
        let state = format_session_state(&s.state);
        println!(
            "  {n}) {COL_CYAN}{id}{COL_RESET}{marker}{label}  {state}",
            n = idx + 1,
            id = s.id,
        );
    }

    let stdin = io::stdin();
    let mut input = String::new();
    print!("\nSelect [1-{}] (q to quit): ", list.len());
    let _ = io::stdout().flush();
    input.clear();
    if stdin.lock().read_line(&mut input).is_err() {
        return;
    }
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("q") {
        return;
    }
    let Ok(idx) = trimmed.parse::<usize>() else {
        eprintln!("{COL_RED}✗{COL_RESET} 잘못된 선택");
        std::process::exit(2);
    };
    let Some(selected) = list.get(idx.saturating_sub(1)) else {
        eprintln!("{COL_RED}✗{COL_RESET} 범위를 벗어남");
        std::process::exit(2);
    };
    let id = selected.id.clone();
    let is_inactive = matches!(
        selected.state,
        aic_common::SessionState::Detached
            | aic_common::SessionState::Stopping
            | aic_common::SessionState::Stopped
            | aic_common::SessionState::Failed
    );

    println!(
        "\nActions for {COL_CYAN}{id}{COL_RESET}: (s)tatus  (l)ast  (a)nalyze  (k)ill  (q)uit"
    );
    print!("> ");
    let _ = io::stdout().flush();
    input.clear();
    if stdin.lock().read_line(&mut input).is_err() {
        return;
    }
    let action = input.trim().to_ascii_lowercase();

    match action.as_str() {
        "s" | "status" => handle_status(false, 1, Some(id), false, false).await,
        "l" | "last" => handle_last(false, Some(id)).await,
        "a" | "analyze" => {
            // 직전 record 분석 흐름. ad-hoc — 가장 최근 record 1건을 받아 handle_record 호출.
            let sock = resolve_socket(Some(&id));
            let session_client = UdsClient::new(sock.clone());
            // Phase 3.2 Task 2.2: cascade 가 가능한 경우 aicd → session 순으로 조회.
            let cascade = build_cascade_for_session_path(&sock);
            let lookup: Result<aic_common::CommandRecord, aic_common::AicError> =
                if let Some(ref c) = cascade {
                    match c.get_last_command().await {
                        Ok(Some(r)) => Ok(r),
                        Ok(None) => Err(aic_common::AicError::UserMessage(
                            "저장된 명령어가 없습니다".to_string(),
                        )),
                        Err(e) => Err(e),
                    }
                } else {
                    session_client.get_last_command().await
                };
            match lookup {
                Ok(record) => {
                    let config = match ConfigManager::load() {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("config 로드 실패: {e}");
                            std::process::exit(1);
                        }
                    };
                    let provider_name = match resolve_provider(&config, None) {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("{e}");
                            std::process::exit(1);
                        }
                    };
                    let model_name = config
                        .llm
                        .providers
                        .get(&provider_name)
                        .and_then(|p| p.model.clone())
                        .unwrap_or_else(|| "(CLI)".to_string());
                    let lang = aic_common::resolve_lang(&config.llm.lang);
                    let dispatcher = LlmDispatcher::from_config(config.llm.clone());
                    if let Err(e) = handle_record(
                        record,
                        dispatcher,
                        &config,
                        &provider_name,
                        &model_name,
                        &lang,
                        false,
                    )
                    .await
                    {
                        eprintln!("{e}");
                    }
                }
                Err(e) => eprintln!("record 조회 실패: {e}"),
            }
        }
        "k" | "kill" | "stop" => {
            if is_inactive {
                print!(
                    "{COL_YELLOW}⚠{COL_RESET} 이미 inactive 상태입니다. 그래도 SIGTERM을 보낼까요? [y/N] "
                );
                let _ = io::stdout().flush();
                input.clear();
                if stdin.lock().read_line(&mut input).is_err() {
                    return;
                }
                if !matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    println!("{COL_DIM}취소됨{COL_RESET}");
                    return;
                }
            }
            handle_session_stop(id).await;
        }
        "q" | "quit" | "" => {}
        other => {
            eprintln!("{COL_RED}✗{COL_RESET} 알 수 없는 action: '{other}'");
            std::process::exit(2);
        }
    }
}

async fn handle_sessions() {
    let current_id = std::env::var("AIC_SESSION_ID").ok();

    let aicd_client = UdsClient::new(aic_common::aicd_socket_path());
    if let Ok(true) = aicd_client.ping().await {
        match aicd_client.list_sessions().await {
            Ok(list) if list.is_empty() => {
                println!("{COL_DIM}aicd registry: 등록된 세션 없음{COL_RESET}");
                return;
            }
            Ok(list) => {
                println!(
                    "{COL_BOLD}aic sessions{COL_RESET} {COL_DIM}(from aicd registry){COL_RESET}"
                );
                for s in &list {
                    let marker = match &current_id {
                        Some(cid) if cid == &s.id => format!(" {COL_GREEN}*{COL_RESET}"),
                        _ => String::new(),
                    };
                    let label_part = s
                        .label
                        .as_deref()
                        .map(|l| format!(" [{COL_BOLD}{l}{COL_RESET}]"))
                        .unwrap_or_default();
                    let tty = s.attached_tty.as_deref().unwrap_or("?");
                    let shell = s
                        .shell
                        .as_deref()
                        .and_then(|p| p.rsplit('/').next())
                        .unwrap_or("?");
                    let state = format_session_state(&s.state);
                    let seen = format_optional_time(s.last_seen_at);
                    let command = format_optional_time(s.last_command_at);
                    let cwd = s
                        .cwd
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "?".to_string());
                    println!(
                        "  {COL_CYAN}{id}{COL_RESET}{marker}{label_part}  {state}  {COL_DIM}pid {pid}  {tty}  {shell}  seen {seen}  cmd {command}  {cwd}{COL_RESET}",
                        id = s.id,
                        pid = s.pid,
                    );
                }
                println!(
                    "{COL_DIM}정리: aic session prune [--older-than-secs 3600] · 라벨: aic session tag <id> <label>{COL_RESET}"
                );
                return;
            }
            Err(e) => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} aicd registry 조회 실패 — file-system scan으로 fallback: {e}"
                );
            }
        }
    }

    // Fallback: 기존 file-system scan 동작.
    let sessions = list_sessions();
    let alive_sessions: Vec<&SessionInfo> = sessions.iter().filter(|s| s.is_alive).collect();

    if alive_sessions.is_empty() {
        println!("실행 중인 세션이 없습니다");
        return;
    }

    println!("{COL_BOLD}aic sessions{COL_RESET} {COL_DIM}(from socket scan){COL_RESET}");
    for s in &alive_sessions {
        let marker = match &current_id {
            Some(cid) if cid == &s.session_id => format!(" {COL_GREEN}*{COL_RESET}"),
            _ => String::new(),
        };
        println!(
            "  {COL_CYAN}{id}{COL_RESET}{marker}  {COL_DIM}{path}{COL_RESET}",
            id = s.session_id,
            path = s.socket_path.display(),
        );
    }
}

fn format_session_state(state: &aic_common::SessionState) -> String {
    match state {
        aic_common::SessionState::Attached => format!("{COL_GREEN}attached{COL_RESET}"),
        aic_common::SessionState::Creating => format!("{COL_CYAN}creating{COL_RESET}"),
        aic_common::SessionState::Detached => format!("{COL_YELLOW}detached{COL_RESET}"),
        aic_common::SessionState::Stopping => format!("{COL_YELLOW}stopping{COL_RESET}"),
        aic_common::SessionState::Stopped => format!("{COL_DIM}stopped{COL_RESET}"),
        aic_common::SessionState::Failed => format!("{COL_RED}failed{COL_RESET}"),
    }
}

fn format_optional_time(ts: Option<chrono::DateTime<chrono::Utc>>) -> String {
    ts.map(format_relative_time)
        .unwrap_or_else(|| "never".to_string())
}

fn format_relative_time(ts: chrono::DateTime<chrono::Utc>) -> String {
    let elapsed = chrono::Utc::now() - ts;
    let secs = elapsed.num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

// ── aic history / aic last (P1 record listing) ─────────────────

fn record_id_short(id: &str) -> &str {
    if id.is_empty() {
        "-"
    } else {
        &id[..id.len().min(8)]
    }
}

fn capture_quality_short(q: aic_common::CaptureQuality) -> &'static str {
    match q {
        aic_common::CaptureQuality::FullOutput => "full",
        aic_common::CaptureQuality::MetadataOnly => "meta",
        aic_common::CaptureQuality::TruncatedOutput => "trunc",
        aic_common::CaptureQuality::BinaryOmitted => "bin",
        aic_common::CaptureQuality::RedactedOutput => "redact",
        aic_common::CaptureQuality::Unknown => "?",
    }
}

fn format_exit_code(code: i32) -> String {
    if code == 0 {
        format!("{COL_GREEN}{code:>3}{COL_RESET}")
    } else {
        format!("{COL_RED}{code:>3}{COL_RESET}")
    }
}

async fn handle_capture_last(
    yes: bool,
    session: Option<String>,
    provider_override: Option<String>,
) {
    use aic_client::risk_guard::{classify, RiskLevel};

    let sock = resolve_socket(session.as_deref());
    let client = UdsClient::new(sock.clone());
    // Phase 3.2 Task 2.2: cascade 로 aicd → session socket 순 조회.
    let cascade = build_cascade_for_session_path(&sock);
    let record = if let Some(ref c) = cascade {
        match c.get_last_command().await {
            Ok(Some(r)) => r,
            Ok(None) => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} 마지막 record를 찾지 못했습니다 ({}). aic-session 안에서 명령을 먼저 실행하세요.",
                    sock.display()
                );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} 마지막 record 조회 실패 ({}): {e}",
                    sock.display()
                );
                std::process::exit(1);
            }
        }
    } else {
        match client.get_last_command().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} 마지막 record 조회 실패 ({}): {e}",
                    sock.display()
                );
                std::process::exit(1);
            }
        }
    };

    let Some(cmd) = record
        .command
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} 마지막 record에 command 정보가 없어 재실행할 수 없습니다."
        );
        std::process::exit(1);
    };

    if record.capture_quality == aic_common::CaptureQuality::FullOutput {
        eprintln!(
            "{COL_DIM}직전 record는 이미 FullOutput 입니다 — capture-last 없이도 분석에 충분합니다.{COL_RESET}"
        );
        eprintln!("  command: {cmd}");
        return;
    }

    let assessment = classify(cmd);
    println!("{COL_BOLD}aic capture-last{COL_RESET}");
    println!("  command : {cmd}");
    println!(
        "  risk    : {} {COL_DIM}({}){COL_RESET}",
        risk_label(assessment.level),
        assessment.rule.unwrap_or("(unrated)")
    );
    if let Some(reason) = assessment.reason.as_deref() {
        println!("  reason  : {reason}");
    }

    match assessment.level {
        RiskLevel::Dangerous => {
            eprintln!("{COL_RED}✗{COL_RESET} dangerous로 분류되어 재실행을 거부했습니다.");
            std::process::exit(2);
        }
        RiskLevel::Unknown => {
            eprintln!(
                "{COL_YELLOW}⚠{COL_RESET} 분류할 수 없어 안전을 위해 재실행을 거부합니다 — \
                 직접 `aic run -- {cmd}` 형태로 실행을 검토하세요."
            );
            std::process::exit(2);
        }
        RiskLevel::NeedsConfirm => {
            if !confirm_yes_no("이 명령을 다시 실행할까요?") {
                eprintln!("{COL_DIM}취소됨{COL_RESET}");
                return;
            }
        }
        RiskLevel::Safe => {
            if !yes && !confirm_yes_no("이 명령을 다시 실행할까요?") {
                eprintln!("{COL_DIM}취소됨{COL_RESET}");
                return;
            }
        }
    }

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let argv = vec![shell, "-c".to_string(), cmd.to_string()];
    println!(
        "{COL_DIM}re-running via {} -c …{COL_RESET}",
        argv.first().map(String::as_str).unwrap_or("sh")
    );
    handle_run(argv, provider_override).await;
}

async fn handle_fix(
    record_prefix: Option<String>,
    yes: bool,
    dry_run: bool,
    session: Option<String>,
    provider_override: Option<String>,
) {
    use aic_client::risk_guard::{classify, RiskLevel};

    let sock = resolve_socket(session.as_deref());
    let client = UdsClient::new(sock.clone());

    let record = match resolve_record(&client, sock.display(), record_prefix.as_deref()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} {e}");
            std::process::exit(2);
        }
    };

    let config = match ConfigManager::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} config 로드 실패: {e}");
            std::process::exit(1);
        }
    };
    let lang = aic_common::resolve_lang(&config.llm.lang);

    // 2. 분석 결과 결정 — deterministic 우선, 그 다음 cache.
    let analysis = if let Some(det) = ErrorAnalyzer::deterministic_result(&record, &lang) {
        det
    } else {
        let project_context = aic_client::project_context::build_context_pack();
        let key = cache::cache_key_with_context(
            record.command.as_deref().unwrap_or(""),
            record.exit_code,
            &record.output_lines,
            project_context.as_deref(),
        );
        match cache::load(&key) {
            Some(hit) => hit.result,
            None => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} 분석 결과를 찾지 못했습니다 — \
                     먼저 `aic` 또는 `aic --record {}`로 분석을 한 번 돌리고 다시 시도하세요.",
                    &record.id[..record.id.len().min(8)]
                );
                std::process::exit(1);
            }
        }
    };

    // 3. plan 출력.
    let id_short = if record.id.is_empty() {
        "-"
    } else {
        &record.id[..record.id.len().min(8)]
    };
    let cmd_str = record.command.as_deref().unwrap_or("(no command)");
    println!("{COL_BOLD}aic fix{COL_RESET}");
    println!("  record  : {COL_CYAN}{id_short}{COL_RESET}");
    println!("  command : {cmd_str}");
    println!(
        "  exit    : {}",
        if record.exit_code == 0 {
            format!("{COL_GREEN}{}{COL_RESET}", record.exit_code)
        } else {
            format!("{COL_RED}{}{COL_RESET}", record.exit_code)
        }
    );
    println!();
    println!("{COL_BOLD}analysis{COL_RESET}");
    for line in analysis.explanation.lines() {
        println!("  {line}");
    }

    let Some(suggested) = analysis
        .suggested_command
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        println!();
        println!(
            "{COL_DIM}(분석 결과에 실행 가능한 suggested_command가 없습니다 — \
             설명을 참고해 수동으로 처리하세요){COL_RESET}"
        );
        return;
    };

    let assessment = classify(suggested);
    println!();
    println!("{COL_BOLD}plan{COL_RESET}");
    println!("  suggested: {suggested}");
    println!(
        "  risk     : {} {COL_DIM}({}){COL_RESET}",
        risk_label(assessment.level),
        assessment.rule.unwrap_or("(unrated)")
    );
    if let Some(reason) = assessment.reason.as_deref() {
        println!("  reason   : {reason}");
    }

    if dry_run {
        println!();
        println!("{COL_DIM}--dry-run: 실행 없이 종료{COL_RESET}");
        return;
    }

    // 4. risk-aware confirm.
    match assessment.level {
        RiskLevel::Dangerous => {
            eprintln!(
                "{COL_RED}✗{COL_RESET} dangerous로 분류되어 실행을 거부했습니다 — \
                 직접 검토 후 `aic run -- {suggested}` 형태로 실행을 검토하세요."
            );
            std::process::exit(2);
        }
        RiskLevel::Unknown => {
            eprintln!(
                "{COL_YELLOW}⚠{COL_RESET} 분류할 수 없어 안전을 위해 실행을 거부합니다 — \
                 직접 `aic run -- {suggested}` 형태로 실행을 검토하세요."
            );
            std::process::exit(2);
        }
        RiskLevel::NeedsConfirm => {
            if !confirm_yes_no("이 명령을 실행할까요?") {
                eprintln!("{COL_DIM}취소됨{COL_RESET}");
                return;
            }
        }
        RiskLevel::Safe => {
            if !yes && !confirm_yes_no("이 명령을 실행할까요?") {
                eprintln!("{COL_DIM}취소됨{COL_RESET}");
                return;
            }
        }
    }

    // 5. 실행 — $SHELL -c.
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let argv = vec![shell, "-c".to_string(), suggested.to_string()];
    println!(
        "{COL_DIM}running via {} -c …{COL_RESET}",
        argv.first().map(String::as_str).unwrap_or("sh")
    );
    handle_run(argv, provider_override).await;
}

async fn handle_watch(interval_secs: u64, session: Option<String>) {
    use std::collections::HashSet;
    use std::time::Duration;

    let interval = Duration::from_secs(interval_secs.max(1));
    let sock = resolve_socket(session.as_deref());
    let client = UdsClient::new(sock.clone());
    // Phase 3.2 Task 2.2: cascade 로 aicd → session socket 순 조회.
    let cascade = build_cascade_for_session_path(&sock);

    let config = ConfigManager::load().ok();
    let lang = config
        .as_ref()
        .map(|c| aic_common::resolve_lang(&c.llm.lang))
        .unwrap_or_else(|| "korean".to_string());

    eprintln!(
        "{COL_BOLD}aic watch{COL_RESET} {COL_DIM}({}, interval={}s, Ctrl-C로 중단){COL_RESET}",
        sock.display(),
        interval.as_secs()
    );

    // 첫 fetch는 baseline — 기존 record는 hint 대상이 아님.
    //
    // Phase 3.2 Task 2.2: 각 polling 호출에서 cascade 를 선호하고, 없으면
    // legacy 단일-소켓으로 폴백한다. cascade 가 FnOnce 로 소비되는 것을 피하려고
    // 인라인 헬퍼 매크로 대신 매 호출 지점에 동일 패턴을 복사한다.
    let mut seen: HashSet<String> = HashSet::new();
    let baseline = if let Some(ref c) = cascade {
        c.get_recent_commands(50).await
    } else {
        client.get_recent_commands(50).await
    };
    if let Ok(records) = baseline {
        for r in &records {
            if !r.id.is_empty() {
                seen.insert(r.id.clone());
            }
        }
        eprintln!(
            "{COL_DIM}baseline: {} record(s) — 이후 도착하는 실패만 알립니다.{COL_RESET}",
            records.len()
        );
    } else {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} 세션 record 조회 실패 — daemon이 떠 있는지 확인하세요. 그래도 polling을 계속합니다."
        );
    }

    loop {
        tokio::time::sleep(interval).await;

        let records = match if let Some(ref c) = cascade {
            c.get_recent_commands(50).await
        } else {
            client.get_recent_commands(50).await
        } {
            Ok(r) => r,
            Err(_) => continue, // best-effort — daemon 재시작 등 일시 오류는 다음 tick에서 재시도.
        };

        for rec in &records {
            if rec.id.is_empty() || seen.contains(&rec.id) {
                continue;
            }
            seen.insert(rec.id.clone());
            if rec.exit_code == 0 {
                continue;
            }
            print_watch_hint(rec, &lang);
        }

        // seen이 무한히 커지지 않도록 hard cap (가장 오래된 것부터 자르기는 어려우므로
        // 단순 cap. record id는 16자 hex이므로 1000개 X 16바이트 = ~16KB로 충분히 작다).
        if seen.len() > 1000 {
            seen.clear();
            for r in &records {
                if !r.id.is_empty() {
                    seen.insert(r.id.clone());
                }
            }
        }
    }
}

fn print_watch_hint(record: &aic_common::CommandRecord, lang: &str) {
    let id_short = if record.id.is_empty() {
        "-"
    } else {
        &record.id[..record.id.len().min(8)]
    };
    let cmd = record.command.as_deref().unwrap_or("(no command)");
    let cmd_short = if cmd.chars().count() > 60 {
        let mut s: String = cmd.chars().take(60).collect();
        s.push('…');
        s
    } else {
        cmd.to_string()
    };

    if let Some(result) = ErrorAnalyzer::deterministic_result(record, lang) {
        // deterministic 분류된 경우 한 줄 hint.
        let first_line = result
            .explanation
            .lines()
            .next()
            .unwrap_or(&result.explanation);
        eprintln!(
            "{COL_BOLD}aic{COL_RESET} {COL_RED}exit {}{COL_RESET} {COL_CYAN}{id_short}{COL_RESET} {cmd_short}",
            record.exit_code
        );
        eprintln!("  {COL_DIM}↳{COL_RESET} {first_line}");
        if let Some(suggested) = result.suggested_command.as_deref() {
            eprintln!(
                "  {COL_DIM}↳ 제안:{COL_RESET} {suggested} {COL_DIM}(직접 실행하지 않습니다){COL_RESET}"
            );
        }
    } else {
        // deterministic으로 분류 못 하면 분석 명령만 안내 (LLM 자동 호출 안 함).
        eprintln!(
            "{COL_BOLD}aic{COL_RESET} {COL_RED}exit {}{COL_RESET} {COL_CYAN}{id_short}{COL_RESET} {cmd_short}",
            record.exit_code
        );
        eprintln!(
            "  {COL_DIM}↳ 분석:{COL_RESET} `aic --record {id_short}` {COL_DIM}또는{COL_RESET} `aic`"
        );
    }
}

async fn handle_learn(
    record_prefix: Option<String>,
    note: Option<String>,
    session: Option<String>,
) {
    use aic_client::recipes::{self, Recipe};

    let sock = resolve_socket(session.as_deref());
    let client = UdsClient::new(sock.clone());

    let record = match resolve_record(&client, sock.display(), record_prefix.as_deref()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} {e}");
            std::process::exit(2);
        }
    };

    // 2. 분석 결과 결정 — deterministic 우선, 그 다음 cache.
    let config = match ConfigManager::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} config 로드 실패: {e}");
            std::process::exit(1);
        }
    };
    let lang = aic_common::resolve_lang(&config.llm.lang);

    let project_context = aic_client::project_context::build_context_pack();
    let fingerprint = cache::cache_key_with_context(
        record.command.as_deref().unwrap_or(""),
        record.exit_code,
        &record.output_lines,
        project_context.as_deref(),
    );

    let analysis = if let Some(det) = ErrorAnalyzer::deterministic_result(&record, &lang) {
        Some(det)
    } else {
        cache::load(&fingerprint).map(|hit| hit.result)
    };

    let Some(analysis) = analysis else {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} 분석 결과를 찾지 못했습니다 — \
             먼저 `aic`로 분석을 한 번 돌려 cache를 만든 뒤 다시 시도하세요."
        );
        std::process::exit(1);
    };

    // 3. recipe 저장.
    let recipe = Recipe {
        fingerprint: fingerprint.clone(),
        command: record.command.clone(),
        explanation: analysis.explanation.clone(),
        suggested_command: analysis.suggested_command.clone(),
        note: note.clone(),
        created_at: chrono::Utc::now(),
        hits: 1,
    };
    match recipes::upsert(recipe) {
        Ok(()) => {
            let id_short = if record.id.is_empty() {
                "-"
            } else {
                &record.id[..record.id.len().min(8)]
            };
            println!(
                "{COL_GREEN}✓{COL_RESET} recipe 저장 ({COL_CYAN}{}{COL_RESET})",
                &fingerprint[..fingerprint.len().min(8)]
            );
            println!("  record   : {id_short}");
            if let Some(cmd) = record.command.as_deref() {
                println!("  command  : {cmd}");
            }
            if let Some(suggested) = analysis.suggested_command.as_deref() {
                println!("  suggested: {suggested}");
            }
            if let Some(n) = note.as_deref() {
                println!("  note     : {n}");
            }
        }
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} recipe 저장 실패: {e}");
            std::process::exit(1);
        }
    }
}

async fn handle_feedback(
    verdict: String,
    record_prefix: Option<String>,
    note: Option<String>,
    session: Option<String>,
) {
    use aic_client::feedback::{self, FeedbackEntry, Verdict};
    use aic_client::recipes;

    let verdict = match verdict.as_str() {
        "worked" => Verdict::Worked,
        "not-worked" => Verdict::NotWorked,
        "irrelevant" => Verdict::Irrelevant,
        other => {
            eprintln!("{COL_RED}✗{COL_RESET} 알 수 없는 verdict: '{other}'");
            std::process::exit(2);
        }
    };

    let sock = resolve_socket(session.as_deref());
    let client = UdsClient::new(sock.clone());

    let record = match resolve_record(&client, sock.display(), record_prefix.as_deref()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{COL_RED}✗{COL_RESET} {e}");
            std::process::exit(2);
        }
    };

    // fingerprint 계산 (project context 포함).
    let project_context = aic_client::project_context::build_context_pack();
    let fingerprint = cache::cache_key_with_context(
        record.command.as_deref().unwrap_or(""),
        record.exit_code,
        &record.output_lines,
        project_context.as_deref(),
    );

    // verdict별 처리:
    // - Worked → recipes::upsert로 자동 학습.
    // - NotWorked → 기존 recipe 삭제.
    // - Irrelevant → 로그만 남기고 다른 액션 없음.
    let action_msg: String;
    match verdict {
        Verdict::Worked => {
            let config = ConfigManager::load().ok();
            let lang = config
                .as_ref()
                .map(|c| aic_common::resolve_lang(&c.llm.lang))
                .unwrap_or_else(|| "korean".to_string());
            let analysis = ErrorAnalyzer::deterministic_result(&record, &lang)
                .or_else(|| cache::load(&fingerprint).map(|hit| hit.result));
            if let Some(analysis) = analysis {
                let recipe = recipes::Recipe {
                    fingerprint: fingerprint.clone(),
                    command: record.command.clone(),
                    explanation: analysis.explanation.clone(),
                    suggested_command: analysis.suggested_command.clone(),
                    note: note.clone(),
                    created_at: chrono::Utc::now(),
                    hits: 1,
                };
                match recipes::upsert(recipe) {
                    Ok(()) => action_msg = "recipe로 자동 학습됨".to_string(),
                    Err(e) => action_msg = format!("recipe 저장 실패: {e}"),
                }
            } else {
                action_msg =
                    "분석 결과 없음 — 먼저 `aic`로 분석을 만들어두면 자동 학습됩니다.".to_string();
            }
        }
        Verdict::NotWorked => match recipes::delete_by_prefix(&fingerprint) {
            Ok(0) => action_msg = "관련 recipe 없음 (삭제할 것 없음)".to_string(),
            Ok(n) => action_msg = format!("관련 recipe {n}건 삭제"),
            Err(e) => action_msg = format!("recipe 삭제 실패: {e}"),
        },
        Verdict::Irrelevant => {
            action_msg = "deterministic rule/prompt 개선 후보로 기록만 남깁니다.".to_string();
        }
    }

    // feedback log append.
    let entry = FeedbackEntry {
        fingerprint: fingerprint.clone(),
        verdict,
        note,
        at: chrono::Utc::now(),
    };
    if let Err(e) = feedback::append(entry) {
        eprintln!("{COL_YELLOW}⚠{COL_RESET} feedback 저장 실패: {e}");
        std::process::exit(1);
    }

    println!(
        "{COL_GREEN}✓{COL_RESET} feedback 기록: {COL_CYAN}{}{COL_RESET} ({})",
        verdict.label(),
        &fingerprint[..fingerprint.len().min(8)]
    );
    if !action_msg.is_empty() {
        println!("  {COL_DIM}↳{COL_RESET} {action_msg}");
    }
}

fn handle_recipes(op: RecipesOp) {
    use aic_client::recipes;
    let store = recipes::load();
    match op {
        RecipesOp::List { json } => {
            if json {
                match serde_json::to_string_pretty(&store.recipes) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("JSON 직렬화 실패: {e}");
                        std::process::exit(2);
                    }
                }
                return;
            }
            if store.recipes.is_empty() {
                println!("{COL_DIM}저장된 recipe 없음{COL_RESET}");
                return;
            }
            println!(
                "{COL_BOLD}aic recipes{COL_RESET} {COL_DIM}({} 건){COL_RESET}",
                store.recipes.len()
            );
            for r in &store.recipes {
                let fp_short = &r.fingerprint[..r.fingerprint.len().min(8)];
                let cmd = r.command.as_deref().unwrap_or("(no command)");
                println!(
                    "  {COL_CYAN}{fp_short}{COL_RESET}  hits={hits:<3}  {when}  {cmd}",
                    hits = r.hits,
                    when = format_relative_time(r.created_at),
                );
                if let Some(suggested) = r.suggested_command.as_deref() {
                    println!("    {COL_DIM}↳ 제안:{COL_RESET} {suggested}");
                }
                if let Some(note) = r.note.as_deref() {
                    println!("    {COL_DIM}↳ note:{COL_RESET} {note}");
                }
            }
        }
        RecipesOp::Show { prefix } => {
            let matched: Vec<_> = store
                .recipes
                .iter()
                .filter(|r| r.fingerprint.starts_with(&prefix))
                .collect();
            match matched.len() {
                0 => {
                    eprintln!("{COL_RED}✗{COL_RESET} prefix '{prefix}' 매칭 recipe 없음");
                    std::process::exit(2);
                }
                _ => {
                    for r in matched {
                        match serde_json::to_string_pretty(r) {
                            Ok(s) => println!("{s}"),
                            Err(e) => eprintln!("직렬화 실패: {e}"),
                        }
                    }
                }
            }
        }
        RecipesOp::Delete { prefix } => match recipes::delete_by_prefix(&prefix) {
            Ok(0) => {
                eprintln!("{COL_YELLOW}⚠{COL_RESET} prefix '{prefix}' 매칭 recipe 없음");
                std::process::exit(1);
            }
            Ok(n) => {
                println!("{COL_GREEN}✓{COL_RESET} {n}개 recipe 삭제");
            }
            Err(e) => {
                eprintln!("{COL_RED}✗{COL_RESET} 삭제 실패: {e}");
                std::process::exit(1);
            }
        },
    }
}

fn risk_label(level: aic_client::risk_guard::RiskLevel) -> String {
    use aic_client::risk_guard::RiskLevel;
    match level {
        RiskLevel::Safe => format!("{COL_GREEN}safe{COL_RESET}"),
        RiskLevel::NeedsConfirm => format!("{COL_YELLOW}needs-confirm{COL_RESET}"),
        RiskLevel::Dangerous => format!("{COL_RED}dangerous{COL_RESET}"),
        RiskLevel::Unknown => format!("{COL_DIM}unknown{COL_RESET}"),
    }
}

fn confirm_yes_no(question: &str) -> bool {
    use std::io::{self, Write};
    print!("{question} [y/N] ");
    if io::stdout().flush().is_err() {
        return false;
    }
    let mut buf = String::new();
    if io::stdin().read_line(&mut buf).is_err() {
        return false;
    }
    matches!(buf.trim().to_lowercase().as_str(), "y" | "yes")
}

async fn handle_last(json: bool, session: Option<String>) {
    let sock = resolve_socket(session.as_deref());
    let client = UdsClient::new(sock.clone());
    // Phase 3.2 Task 2.2: cascade 로 aicd → session socket 순 조회.
    let cascade = build_cascade_for_session_path(&sock);
    let records: Vec<aic_common::CommandRecord> = if let Some(ref c) = cascade {
        match c.get_recent_commands(1).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} 세션 record 조회 실패 ({}): {e}",
                    sock.display()
                );
                std::process::exit(1);
            }
        }
    } else {
        match client.get_recent_commands(1).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{COL_YELLOW}⚠{COL_RESET} 세션 record 조회 실패 ({}): {e}",
                    sock.display()
                );
                std::process::exit(1);
            }
        }
    };
    let Some(rec) = records.into_iter().next_back() else {
        println!("{COL_DIM}저장된 record 없음{COL_RESET}");
        return;
    };

    if json {
        match serde_json::to_string_pretty(&rec) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("JSON 직렬화 실패: {e}");
                std::process::exit(2);
            }
        }
        return;
    }

    let id_short = record_id_short(&rec.id);
    let exit = format_exit_code(rec.exit_code);
    let quality = capture_quality_short(rec.capture_quality);
    let when = format_relative_time(rec.timestamp);
    let cmd = rec.command.as_deref().unwrap_or("(no command)");
    println!("{COL_BOLD}aic last{COL_RESET}");
    println!("  id      : {COL_CYAN}{id_short}{COL_RESET}  ({})", rec.id);
    println!("  command : {cmd}");
    println!("  exit    : {exit}  {COL_DIM}({quality}){COL_RESET}");
    println!(
        "  when    : {when}  {COL_DIM}({}){COL_RESET}",
        rec.timestamp
    );
    if !rec.output_lines.is_empty() {
        println!("  output  : {} lines", rec.output_lines.len());
    }
}

// ── 세션 소켓 결정 ──────────────────────────────────────────────

/// `AIC_SESSION_ID` 환경변수 기반 소켓 경로 결정 결과.
enum SessionSocket {
    /// 유효한 소켓 경로 (UDS 연결 시도 대상)
    Path(std::path::PathBuf),
    /// 히스토리 폴백 (세션 소켓 사용 불가)
    HistoryFallback,
}

/// `Central_Store_Flag` 를 현재 프로세스 env + config 로부터 평가한다.
///
/// Phase 3.2 read-path cascade 가 필요로 하는 단일 진입점. `aic_common` 의
/// `resolve_central_store_flag` 가 내부적으로 `OnceLock` 캐시를 사용하므로
/// 프로세스 수명 동안 동일 값이 반환된다 (R2.7).
fn resolve_central_store_flag_from_env() -> bool {
    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    // `[daemon]` 섹션은 레거시 config 에 없을 수도 있으므로 best-effort 로 읽어본다.
    // 파일을 직접 읽어 `AppConfigWithDaemon` 으로 파싱하고, 어떤 단계에서 실패해도
    // env + Phase default 만으로 평가할 수 있게 None 을 넘긴다 (R2.6, R12.2).
    let daemon_cfg = read_daemon_config_best_effort();
    aic_common::central_store_flag::resolve_central_store_flag(&env, daemon_cfg.as_ref())
}

/// `config.toml` 에서 `[daemon]` 섹션만 best-effort 로 파싱한다. 어떤 오류도
/// 조용히 삼키고 `None` 을 돌려준다 — config 전체 로드 실패가 read-path 평가를
/// 막아서는 안 된다 (R12.2).
fn read_daemon_config_best_effort() -> Option<aic_common::central_store_flag::DaemonConfig> {
    let path = ConfigManager::config_path();
    let content = std::fs::read_to_string(&path).ok()?;
    let parsed: aic_common::central_store_flag::AppConfigWithDaemon =
        toml::from_str(&content).ok()?;
    Some(parsed.daemon)
}

/// `SessionSocket::Path` 로부터 cascade 를 구성한다.
///
/// socket path 에서 session id 를 추출해 `ReadCascade::new` 로 넘긴다. socket path 가
/// `session-{id}.sock` 형식이 아니면 `extract_session_id` 가 `None` 을 돌려주므로
/// `AIC_SESSION_ID` env 로 한 번 더 확인한 뒤, 그마저 없으면 `None` 을 반환해
/// 호출자가 session-scoped read 를 포기하고 기존 경로로 돌아가도록 한다.
fn build_cascade_for_session_path(socket_path: &std::path::Path) -> Option<ReadCascade> {
    let session_id = aic_common::extract_session_id(socket_path).or_else(|| {
        std::env::var("AIC_SESSION_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })?;
    let flag = resolve_central_store_flag_from_env();
    Some(ReadCascade::new(session_id, flag))
}

fn hook_lookup_enabled(config: &AppConfig) -> bool {
    matches!(
        config.session.capture_mode,
        aic_common::SessionCaptureMode::Hook | aic_common::SessionCaptureMode::Hybrid
    )
}

fn current_session_id_from_env() -> Option<String> {
    let id = std::env::var("AIC_SESSION_ID").ok()?;
    let trimmed = id.trim();
    if aic_common::is_valid_session_id(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

async fn get_hook_metadata_record(config: &AppConfig) -> Option<aic_common::CommandRecord> {
    if !hook_lookup_enabled(config) {
        return None;
    }
    if let Some(session_id) = current_session_id_from_env() {
        let client = UdsClient::new(aic_common::aicd_socket_path());
        match client.get_last_command_for_session(&session_id).await {
            Ok(record) => {
                debug_log!(
                    "aicd     hook metadata · session={} exit={} cmd={}",
                    session_id,
                    record.exit_code,
                    record.command.as_deref().unwrap_or("∅")
                );
                return Some(record);
            }
            Err(e) => {
                debug_log!(
                    "aicd     hook metadata miss · session={} · {}",
                    session_id,
                    e
                );
            }
        }
    }
    let record = local_record::load_last()?;
    debug_log!(
        "local    hook metadata · exit={} cmd={}",
        record.exit_code,
        record.command.as_deref().unwrap_or("∅")
    );
    Some(record)
}

/// `AIC_SESSION_ID` 환경변수를 확인하여 소켓 경로를 결정한다.
///
/// - 설정 + 유효 + 소켓 존재 → `SessionSocket::Path`
/// - 설정 + 유효 + 소켓 미존재 → 안내 메시지 + `HistoryFallback`
/// - 설정 + 형식 오류 → 경고 + `HistoryFallback`
/// - 미설정 → config 기반 기본 소켓 경로로 `SessionSocket::Path`
fn resolve_session_socket(_config: &AppConfig) -> SessionSocket {
    let session_id = match std::env::var("AIC_SESSION_ID") {
        Ok(id) if !id.is_empty() => id,
        _ => {
            // AIC_SESSION_ID 미설정
            // AIC_SESSION=1이면 세션 안이지만 ID를 잃은 경우 → 히스토리 폴백
            // AIC_SESSION 미설정이면 세션 밖 → 히스토리 폴백
            // 어느 경우든 다른 세션에 연결하면 안 됨 (세션 엉킴 방지)
            if std::env::var("AIC_SESSION").ok().as_deref() == Some("1") {
                debug_log!("session  AIC_SESSION=1이지만 AIC_SESSION_ID 미설정 → history fallback");
            } else {
                debug_log!("session  aic-session 밖 → history fallback");
            }
            return SessionSocket::HistoryFallback;
        }
    };

    // 형식 검증
    if !aic_common::is_valid_session_id(&session_id) {
        eprintln!(
            "{COL_YELLOW}⚠{COL_RESET} AIC_SESSION_ID 형식 오류: '{}' (1~8자 lowercase hex 필요)",
            session_id
        );
        return SessionSocket::HistoryFallback;
    }

    // 세션별 소켓 경로 결정
    let socket_path = aic_common::session_socket_path(&session_id);
    debug_log!(
        "session  AIC_SESSION_ID={session_id} → {}",
        socket_path.display()
    );

    // 소켓 파일 존재 여부 확인
    if !socket_path.exists() {
        eprintln!(
            "{COL_YELLOW}ℹ{COL_RESET} 세션 {COL_BOLD}{session_id}{COL_RESET}이(가) 종료되었습니다. 히스토리 모드로 전환합니다."
        );
        return SessionSocket::HistoryFallback;
    }

    SessionSocket::Path(socket_path)
}

/// 히스토리 폴백: 셸 히스토리에서 마지막 명령어를 가져오거나, 없으면 REPL을 시작한다.
/// REPL 진입 시 `Ok(())` 반환 후 `handle_default`가 즉시 종료되도록 `return Ok(())`를 호출해야 하므로,
/// 이 함수는 `Option<CommandRecord>`를 반환하지 않고 직접 REPL을 실행한 뒤 early return을 유도한다.
async fn history_fallback_or_repl(
    dispatcher: &LlmDispatcher,
    provider_name: &str,
    model_name: &str,
    config: &AppConfig,
    lang: &str,
    dry_run: bool,
    total_start: Instant,
) -> anyhow::Result<aic_common::CommandRecord> {
    match get_last_command_from_shell() {
        Some(rec) => Ok(rec),
        None => {
            debug_log!("mode     repl (no server, no history)");
            if dry_run {
                print_dry_run(
                    "repl",
                    "(interactive)",
                    provider_name,
                    model_name,
                    &config.llm,
                );
                debug_step!(total_start, "total");
                std::process::exit(0);
            }
            let dummy = aic_common::CommandRecord {
                command: None,
                exit_code: 0,
                output_lines: vec![],
                timestamp: chrono::Utc::now(),
                ..Default::default()
            };
            let mut session = ReplSession::new(dispatcher.clone(), dummy, lang.to_string());
            session.run().await?;
            debug_step!(total_start, "total");
            std::process::exit(0);
        }
    }
}

async fn stdin_record_if_piped() -> anyhow::Result<Option<aic_common::CommandRecord>> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }

    use tokio::io::AsyncReadExt;
    let mut input = String::new();
    tokio::io::stdin().read_to_string(&mut input).await?;
    if input.trim().is_empty() {
        return Ok(None);
    }

    const LINE_CAP: usize = 1000;
    let command = std::env::var("AIC_COMMAND")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let exit_code = std::env::var("AIC_EXIT_CODE")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1);
    let raw_lines: Vec<String> = input.lines().map(ToString::to_string).collect();
    let start = raw_lines.len().saturating_sub(LINE_CAP);
    let output_lines = clean_output_lines(&raw_lines[start..], command.as_deref());
    let original_bytes = input.len() as u64;
    let stored_bytes = output_lines.iter().map(|line| line.len() as u64 + 1).sum();
    let stored_lines = output_lines.len();
    let truncated = start > 0;

    Ok(Some(aic_common::CommandRecord {
        id: aic_common::generate_record_id(),
        command,
        exit_code,
        output_lines,
        timestamp: chrono::Utc::now(),
        capture_mode: aic_common::CaptureMode::ExplicitCapture,
        capture_quality: if truncated {
            aic_common::CaptureQuality::TruncatedOutput
        } else {
            aic_common::CaptureQuality::FullOutput
        },
        output_metadata: Some(aic_common::OutputMetadata {
            original_bytes: Some(original_bytes),
            stored_bytes,
            stored_lines,
            truncated,
            binary: false,
            sha256: None,
        }),
    }))
}

/// `--provider` 플래그 또는 `AIC_PROVIDER` env로 지정된 provider override를 검증한다.
/// override가 없으면 config의 `default_provider`를 그대로 반환한다.
/// override 이름이 `[llm.providers]`에 없으면 사용 가능한 목록을 포함한 에러를 돌려준다.
fn resolve_provider(config: &AppConfig, override_name: Option<&str>) -> anyhow::Result<String> {
    match override_name {
        Some(name) if !name.is_empty() => {
            if config.llm.providers.contains_key(name) {
                Ok(name.to_string())
            } else {
                let mut available: Vec<&str> =
                    config.llm.providers.keys().map(String::as_str).collect();
                available.sort_unstable();
                let listed = if available.is_empty() {
                    "(없음)".to_string()
                } else {
                    available.join(", ")
                };
                anyhow::bail!(
                    "provider '{name}'이(가) [llm.providers]에 없습니다. 사용 가능: {listed}"
                )
            }
        }
        _ => Ok(config.llm.default_provider.clone()),
    }
}

/// CLI `--provider` override를 검증하고, override가 있으면 `config.llm.default_provider`를
/// 그 provider로 실제로 바꾼 config를 돌려준다.
///
/// `LlmDispatcher::from_config`는 `default_provider`를 따라 동작하므로, 표시용 이름만
/// 바꾸고 config를 그대로 두면 dispatcher가 여전히 원래 default provider를 사용/검증한다
/// (표시≠실제 버그). 이 헬퍼로 만든 config로 dispatcher를 생성하면 표시=실제가 보장된다.
/// model은 provider config(`providers[provider].model`)에서 파생되므로 함께 일치한다.
/// 반환: (override 반영된 config, 사용 provider name).
fn apply_provider_override(
    mut config: AppConfig,
    override_name: Option<&str>,
) -> anyhow::Result<(AppConfig, String)> {
    let name = resolve_provider(&config, override_name)?;
    config.llm.default_provider = name.clone();
    Ok((config, name))
}

/// 기본 동작: 서버 연결 → 직전 명령어 조회 → 자동 분기
/// 또는 직접 프롬프트가 주어지면 LLM에 바로 질문
/// `--record <prefix>` 흐름. session ring buffer에서 prefix로 record를 찾아
/// 분석 흐름에 투입한다 (P1 'aic history / record id' 가치 루프).
async fn handle_record_by_prefix(
    prefix: &str,
    session: Option<String>,
    dry_run: bool,
    provider_override: Option<String>,
) -> anyhow::Result<()> {
    let total_start = Instant::now();

    let sock = resolve_socket(session.as_deref());
    let client = UdsClient::new(sock.clone());
    let record = resolve_record(&client, sock.display(), Some(prefix)).await?;

    debug_log!(
        "record   prefix='{prefix}' → id={} cmd={} exit={}",
        &record.id[..record.id.len().min(8)],
        record.command.as_deref().unwrap_or("∅"),
        record.exit_code
    );

    let config = ConfigManager::load()?;
    // CLI --provider override를 config(default_provider)에 실제 반영 → dispatcher가 override를 사용.
    let (config, provider_name) = apply_provider_override(config, provider_override.as_deref())?;
    let model_name = config
        .llm
        .providers
        .get(&provider_name)
        .and_then(|p| p.model.clone())
        .unwrap_or_else(|| "(CLI)".to_string());
    let lang = aic_common::resolve_lang(&config.llm.lang);
    let dispatcher = LlmDispatcher::from_config(config.llm.clone());

    let r = handle_record(
        record,
        dispatcher,
        &config,
        &provider_name,
        &model_name,
        &lang,
        dry_run,
    )
    .await;
    debug_step!(total_start, "total");
    r
}

/// 직전 명령 record를 best-effort로 조회한다 (side-effect 없음).
///
/// `handle_default`의 record 조회와 달리 history/REPL 폴백을 트리거하지 않고,
/// 데몬·세션 소켓 또는 hook metadata에서 의미 있는 record를 찾으면 `Some`을,
/// 없으면 `None`을 돌려준다. `aic chat` REPL 진입 시 첫 턴 context 첨부 용도.
async fn resolve_last_record_best_effort(config: &AppConfig) -> Option<aic_common::CommandRecord> {
    let rec = match resolve_session_socket(config) {
        SessionSocket::Path(socket_path) => {
            let lookup = if let Some(cascade) = build_cascade_for_session_path(&socket_path) {
                cascade.get_last_command().await
            } else {
                match UdsClient::new(socket_path).get_last_command().await {
                    Ok(rec) => Ok(Some(rec)),
                    Err(_) => Ok(None),
                }
            };
            lookup.ok().flatten()
        }
        SessionSocket::HistoryFallback => None,
    };

    // 데몬이 record는 줬지만 command를 캡처하지 못한 경우 hook metadata로 보강.
    match rec {
        Some(r)
            if r.command
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty) =>
        {
            get_hook_metadata_record(config).await
        }
        Some(r) => Some(r),
        None => get_hook_metadata_record(config).await,
    }
}

/// `aic chat` 처리. 질문 인자가 있으면 1회성 답변, 없으면 대화형 REPL.
async fn handle_chat(
    prompt_parts: Vec<String>,
    dry_run: bool,
    provider_override: Option<String>,
    with_context: bool,
    read_only: bool,
) -> anyhow::Result<()> {
    let total_start = Instant::now();

    // run_command(SRE 실행)는 기본 활성. `--no-run`/`--read-only`(또는 env
    // AIC_AGENT_NO_RUN)로만 끈다. 보안 게이트(risk_guard/validator/confirm)는 그대로.
    let run_command_enabled = chat_run_command_enabled(read_only, env_flag("AIC_AGENT_NO_RUN"));

    let config = ConfigManager::load()?;
    // CLI --provider override를 config(default_provider)에 실제 반영 → dispatcher가 override를 사용.
    let (config, provider_name) = apply_provider_override(config, provider_override.as_deref())?;
    let model_name = config
        .llm
        .providers
        .get(&provider_name)
        .and_then(|p| p.model.clone())
        .unwrap_or_else(|| "(CLI)".to_string());
    let lang = aic_common::resolve_lang(&config.llm.lang);
    let dispatcher = LlmDispatcher::from_config(config.llm.clone());

    // 인자가 있으면 1회성 답변 (direct-prompt와 동일 경로).
    if !prompt_parts.is_empty() {
        let prompt = prompt_parts.join(" ");
        let prompt = if with_context {
            let ctx = aic_client::project_context::build_context_pack();
            if let Some(c) = ctx.as_deref() {
                debug_log!("context  project · {} chars", c.len());
            }
            aic_client::project_context::append_to_prompt(prompt, ctx.as_deref())
        } else {
            prompt
        };
        debug_log!("mode     chat-prompt · {} chars", prompt.len());
        if dry_run {
            print_dry_run(
                "direct-prompt",
                &prompt,
                &provider_name,
                &model_name,
                &config.llm,
            );
            return Ok(());
        }
        let r = handle_direct_prompt(&dispatcher, &prompt, &model_name, &lang).await;
        debug_step!(total_start, "total");
        return r;
    }

    // 인자 없음 → 항상 대화형 REPL (exit code 무관).
    debug_log!("mode     chat-repl");
    if dry_run {
        print_dry_run(
            "repl",
            "(interactive)",
            &provider_name,
            &model_name,
            &config.llm,
        );
        return Ok(());
    }

    let record = resolve_last_record_best_effort(&config)
        .await
        .unwrap_or_else(|| aic_common::CommandRecord {
            command: None,
            exit_code: 0,
            output_lines: vec![],
            timestamp: chrono::Utc::now(),
            ..Default::default()
        });

    // provider가 tool-calling을 지원하면 읽기 전용 agent 세션, 아니면 기존 REPL.
    if dispatcher.supports_tool_calling() {
        match aic_client::agent::Sandbox::from_cwd() {
            Ok(sandbox) => {
                debug_log!("mode     chat-agent (run_command={})", run_command_enabled);
                let mut session = aic_client::agent::AgentSession::new(
                    dispatcher,
                    sandbox,
                    record,
                    lang.to_string(),
                )
                .allow_run_command(run_command_enabled)
                .with_provider_model(provider_name.clone(), model_name.clone());
                session.run().await?;
            }
            Err(e) => {
                debug_log!("agent sandbox 실패 — ReplSession 폴백: {e}");
                let mut session = ReplSession::new(dispatcher, record, lang.to_string());
                session.run().await?;
            }
        }
    } else {
        let mut session = ReplSession::new(dispatcher, record, lang.to_string());
        session.run().await?;
    }
    debug_step!(total_start, "total");
    Ok(())
}

async fn handle_default(
    direct_prompt: Option<String>,
    dry_run: bool,
    provider_override: Option<String>,
    with_context: bool,
) -> anyhow::Result<()> {
    let total_start = Instant::now();

    let config_start = Instant::now();
    let config = ConfigManager::load()?;
    // CLI --provider override를 config에 실제 반영 → dispatcher가 override를 사용.
    let (config, provider_name) = apply_provider_override(config, provider_override.as_deref())?;
    let model_name = config
        .llm
        .providers
        .get(&provider_name)
        .and_then(|p| p.model.clone())
        .unwrap_or_else(|| "(CLI)".to_string());
    let lang = aic_common::resolve_lang(&config.llm.lang);
    debug_step!(
        config_start,
        "config   {provider_name} · {model_name} · lang={lang}"
    );

    let dispatcher = LlmDispatcher::from_config(config.llm.clone());

    // 직접 프롬프트가 주어진 경우
    if let Some(prompt) = direct_prompt {
        // --context: project context pack을 prompt 끝에 붙인다 (P3 'aic ask --context').
        let prompt = if with_context {
            let ctx = aic_client::project_context::build_context_pack();
            if let Some(c) = ctx.as_deref() {
                debug_log!("context  project · {} chars", c.len());
            }
            aic_client::project_context::append_to_prompt(prompt, ctx.as_deref())
        } else {
            prompt
        };
        debug_log!("mode     prompt · {} chars", prompt.len());
        if dry_run {
            print_dry_run(
                "direct-prompt",
                &prompt,
                &provider_name,
                &model_name,
                &config.llm,
            );
            return Ok(());
        }
        let r = handle_direct_prompt(&dispatcher, &prompt, &model_name, &lang).await;
        debug_step!(total_start, "total");
        return r;
    }

    if let Some(record) = stdin_record_if_piped().await? {
        debug_log!(
            "mode     stdin · exit={} lines={}",
            record.exit_code,
            record.output_lines.len()
        );
        let _ = local_record::save_last(&record);
        return handle_record(
            record,
            dispatcher,
            &config,
            &provider_name,
            &model_name,
            &lang,
            dry_run,
        )
        .await;
    }

    // 서버에서 마지막 명령어 조회, 실패 시 히스토리 폴백
    //
    // AIC_SESSION_ID 환경변수가 설정되어 있으면 세션별 소켓으로 연결을 시도한다.
    // 미설정 시 기존 config 기반 소켓 경로를 사용한다.
    let session_socket = resolve_session_socket(&config);

    let record = match session_socket {
        SessionSocket::Path(socket_path) => {
            let connect_start = Instant::now();

            // Phase 3.2 Task 2.2: aicd → session-socket cascade 로 전환.
            // `Central_Store_Flag=true` 이면 (1) aicd `GetLastCommandForSession` 을 먼저,
            // false 이면 기존대로 (2) session socket `GetLastCommand` 만 시도한다.
            // cascade 가 socket_path 로부터 session_id 를 추출하지 못하면(일반적이지 않음)
            // 기존 UdsClient 직행 경로로 폴백한다 — 레거시 socket 레이아웃 보호.
            let cascaded = build_cascade_for_session_path(&socket_path);
            let lookup_result: Result<Option<aic_common::CommandRecord>, aic_common::AicError> =
                if let Some(ref cascade) = cascaded {
                    cascade.get_last_command().await
                } else {
                    // cascade 를 만들 수 없는 경우에만 legacy 단일-소켓 경로.
                    let client = UdsClient::new(socket_path.clone());
                    match client.get_last_command().await {
                        Ok(rec) => Ok(Some(rec)),
                        Err(aic_common::AicError::UserMessage(_))
                        | Err(aic_common::AicError::ServerNotRunning) => Ok(None),
                        Err(other) => Err(other),
                    }
                };

            match lookup_result {
                Ok(Some(rec)) => {
                    debug_step!(
                        connect_start,
                        "cascade  {} · flag={} · exit={} lines={} cmd={}",
                        socket_path.display(),
                        cascaded
                            .as_ref()
                            .map(|c| c.central_store_flag())
                            .unwrap_or(false),
                        rec.exit_code,
                        rec.output_lines.len(),
                        rec.command.as_deref().unwrap_or("∅"),
                    );
                    // 서버가 응답은 했지만 직전 명령을 캡처하지 못한 케이스 (cmd=None).
                    // boundary detector hook이 셸에 설치되지 않았거나 prompt marker가
                    // 동작하지 않은 상황. exit_code=0은 default 값일 가능성이 높아 신뢰 불가.
                    // 히스토리 폴백으로 우회한다.
                    let cmd_unknown = rec
                        .command
                        .as_deref()
                        .map(str::trim)
                        .is_none_or(str::is_empty);
                    if cmd_unknown {
                        if let Some(hook_record) = get_hook_metadata_record(&config).await {
                            hook_record
                        } else {
                            eprintln!(
                                "{COL_YELLOW}ℹ{COL_RESET} 데몬이 직전 명령을 캡처하지 못했습니다. 셸 히스토리에서 폴백합니다.\n   {COL_DIM}hook 미설치 의심 — `aic init`으로 설치 후 새 셸에서 시도하세요.{COL_RESET}"
                            );
                            history_fallback_or_repl(
                                &dispatcher,
                                &provider_name,
                                &model_name,
                                &config,
                                &lang,
                                dry_run,
                                total_start,
                            )
                            .await?
                        }
                    } else {
                        rec
                    }
                }
                Ok(None) | Err(_) => {
                    // Ok(None) = cascade 가 "record 없음" 으로 수렴 — 상위 fallback 진입.
                    // Err(_)  = 진짜 IPC 고장 — 동일하게 hook/shell history 폴백으로 처리.
                    if let Some(hook_record) = get_hook_metadata_record(&config).await {
                        hook_record
                    } else {
                        history_fallback_or_repl(
                            &dispatcher,
                            &provider_name,
                            &model_name,
                            &config,
                            &lang,
                            dry_run,
                            total_start,
                        )
                        .await?
                    }
                }
            }
        }
        SessionSocket::HistoryFallback => {
            if let Some(hook_record) = get_hook_metadata_record(&config).await {
                hook_record
            } else {
                history_fallback_or_repl(
                    &dispatcher,
                    &provider_name,
                    &model_name,
                    &config,
                    &lang,
                    dry_run,
                    total_start,
                )
                .await?
            }
        }
    };

    handle_record(
        record,
        dispatcher,
        &config,
        &provider_name,
        &model_name,
        &lang,
        dry_run,
    )
    .await?;

    debug_step!(total_start, "total");
    Ok(())
}

/// 레코드 기반 분기 처리 (에러 분석 또는 REPL)
async fn handle_record(
    record: aic_common::CommandRecord,
    dispatcher: LlmDispatcher,
    config: &AppConfig,
    provider_name: &str,
    model_name: &str,
    lang: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
    match AutoBrancher::determine_mode(&record) {
        ExecutionMode::ErrorAnalysis(rec) => {
            debug_log!("mode     error-analysis");
            print_error_context(&rec);
            print_capture_quality_hint(&rec, config);

            if let Some(result) = ErrorAnalyzer::deterministic_result(&rec, lang) {
                debug_log!("analysis builtin · exit={}", rec.exit_code);
                print_analysis_result(&result, lang);
                return Ok(());
            }

            let project_context = aic_client::project_context::build_context_pack();
            if let Some(context) = project_context.as_deref() {
                debug_log!("context  project · {} chars", context.len());
            }

            let cache_key = cache::cache_key_with_context(
                rec.command.as_deref().unwrap_or(""),
                rec.exit_code,
                &rec.output_lines,
                project_context.as_deref(),
            );
            // 학습된 recipe가 있으면 LLM 호출 없이 먼저 보여준다 (P2 'aic learn').
            if let Some(recipe) = aic_client::recipes::find(&cache_key) {
                debug_log!(
                    "recipe   HIT fp={} hits={}",
                    &cache_key[..cache_key.len().min(8)],
                    recipe.hits
                );
                println!(
                    "{COL_DIM}(학습된 recipe — {} 적용 횟수 {}){COL_RESET}",
                    format_relative_time(recipe.created_at),
                    recipe.hits
                );
                let result = aic_common::AnalysisResult {
                    explanation: recipe.explanation.clone(),
                    suggested_command: recipe.suggested_command.clone(),
                    additional_info: recipe.note.clone(),
                };
                print_analysis_result(&result, lang);
                let _ = aic_client::recipes::touch(&cache_key);
                if let Some(cmd) = &result.suggested_command {
                    maybe_run_suggested(cmd, lang);
                }
                return Ok(());
            }
            if let Some(hit) = cache::load(&cache_key) {
                let age_min = (chrono::Utc::now() - hit.cached_at).num_minutes();
                debug_log!("cache    HIT key={cache_key} age={age_min}min");
                println!("{COL_DIM}(캐시 — {age_min}분 전 분석){COL_RESET}");
                print_analysis_result(&hit.result, lang);
                if let Some(cmd) = &hit.result.suggested_command {
                    maybe_run_suggested(cmd, lang);
                }
                return Ok(());
            }
            debug_log!("cache    MISS key={cache_key}");

            let prompt_start = Instant::now();
            let prompt = aic_client::project_context::append_to_prompt(
                ErrorAnalyzer::build_prompt(&rec, lang),
                project_context.as_deref(),
            );
            debug_step!(prompt_start, "prompt   {} chars", prompt.len());

            if dry_run {
                print_dry_run(
                    "error-analysis",
                    &prompt,
                    provider_name,
                    model_name,
                    &config.llm,
                );
                return Ok(());
            }

            let streamable = matches!(
                config
                    .llm
                    .providers
                    .get(provider_name)
                    .map(|p| &p.provider_type),
                Some(ProviderType::OpenAiCompatible)
                    | Some(ProviderType::Groq)
                    | Some(ProviderType::Anthropic)
            );
            use std::io::IsTerminal;
            let streaming_enabled = streamable
                && std::env::var("AIC_NO_STREAM").is_err()
                && std::io::stdout().is_terminal();

            let llm_start = Instant::now();
            let send_result = if streaming_enabled {
                use std::io::Write;
                let mut in_think = false;
                let mut think_done = false;
                let mut think_buf = String::new();
                let mut accum = String::new();

                let on_chunk = |chunk: &str| {
                    accum.push_str(chunk);
                    if think_done {
                        return;
                    }
                    if !in_think && accum.contains("<think>") {
                        in_think = true;
                        if let Some(pos) = accum.find("<think>") {
                            think_buf = accum[pos + 7..].to_string();
                        }
                        eprint!("{COL_DIM}[Thinking...]{COL_RESET}");
                        let _ = std::io::stderr().flush();
                        return;
                    }
                    if in_think {
                        think_buf.push_str(chunk);
                        if think_buf.contains("</think>") {
                            in_think = false;
                            think_done = true;
                            let think_content = think_buf.split("</think>").next().unwrap_or("");
                            let tl: Vec<&str> = think_content
                                .lines()
                                .filter(|l| !l.trim().is_empty())
                                .collect();
                            let first: String =
                                tl.first().unwrap_or(&"").trim().chars().take(40).collect();
                            let last: String = tl
                                .last()
                                .unwrap_or(&"")
                                .trim()
                                .chars()
                                .rev()
                                .take(30)
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .collect();
                            if tl.len() <= 1 {
                                eprint!("\r{COL_DIM}[Thinking] {first}{COL_RESET}\x1b[K");
                            } else {
                                eprint!(
                                    "\r{COL_DIM}[Thinking] {first} ... {last}{COL_RESET}\x1b[K"
                                );
                            }
                            eprintln!();
                            think_buf.clear();
                            return;
                        }
                        if let Some(ll) = think_buf.lines().last() {
                            let preview: String = ll.chars().take(60).collect();
                            eprint!("\r{COL_DIM}[Thinking] {preview}\x1b[K{COL_RESET}");
                            let _ = std::io::stderr().flush();
                        }
                    }
                };
                dispatcher.send_streaming(&prompt, on_chunk).await
            } else {
                let spinner =
                    aic_client::spinner::Spinner::start(format!("asking {model_name}..."));
                let r = dispatcher.send(&prompt).await;
                spinner.stop().await;
                r
            };

            match send_result {
                Ok(response) => {
                    debug_step!(
                        llm_start,
                        "llm      {model_name} → {} chars",
                        response.len()
                    );
                    let parse_start = Instant::now();
                    let result = ErrorAnalyzer::parse_response_for_record(&response, &rec, lang);
                    debug_step!(parse_start, "parse");
                    let _ = cache::save(&cache::CachedAnalysis {
                        key: cache_key,
                        cached_at: chrono::Utc::now(),
                        provider: provider_name.to_string(),
                        model: model_name.to_string(),
                        result: result.clone(),
                    });
                    print_analysis_result(&result, lang);
                    if let Some(cmd) = &result.suggested_command {
                        maybe_run_suggested(cmd, lang);
                    }
                }
                Err(e) => {
                    debug_step!(llm_start, "llm      에러: {e}");
                    eprintln!("\n{COL_YELLOW}⚠{COL_RESET} {}", e.user_message());
                }
            }
        }
        ExecutionMode::InteractiveRepl(rec) => {
            debug_log!("mode     repl");
            if dry_run {
                print_dry_run(
                    "repl",
                    "(interactive)",
                    provider_name,
                    model_name,
                    &config.llm,
                );
                return Ok(());
            }
            let mut session = ReplSession::new(dispatcher, rec, lang.to_string());
            session.run().await?;
        }
    }
    Ok(())
}

/// 직접 프롬프트 처리
async fn handle_direct_prompt(
    dispatcher: &LlmDispatcher,
    prompt: &str,
    model_name: &str,
    lang: &str,
) -> anyhow::Result<()> {
    let llm_start = Instant::now();

    let lang_instruction = match lang {
        "korean" => "Respond in Korean.",
        "english" => "Respond in English.",
        "japanese" => "Respond in Japanese.",
        "chinese" => "Respond in Chinese.",
        other => &format!("Respond in {}.", other),
    };
    let full_prompt = format!(
        "{prompt}\n\n\
         Please provide in PLAIN TEXT (no markdown, no code blocks, no formatting).\n\
         {lang_instruction}"
    );

    let spinner = aic_client::spinner::Spinner::start(format!("asking {model_name}..."));
    let send_result = dispatcher.send(&full_prompt).await;
    spinner.stop().await;
    match send_result {
        Ok(response) => {
            debug_step!(
                llm_start,
                "llm      {model_name} → {} chars",
                response.len()
            );
            print_llm_response(&response);
        }
        Err(e) => {
            debug_step!(llm_start, "llm      에러: {e}");
            eprintln!("\n{COL_YELLOW}⚠{COL_RESET} {}", e.user_message());
        }
    }

    Ok(())
}

/// 셸 히스토리 파일에서 마지막 명령어를 가져오는 폴백.
/// aic-session 서버가 없거나 연결 실패 시 사용.
fn get_last_command_from_shell() -> Option<aic_common::CommandRecord> {
    let home = std::env::var("HOME").ok()?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let shell_name = std::path::Path::new(&shell)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    let hist_path = match shell_name {
        "zsh" => std::env::var("HISTFILE").unwrap_or_else(|_| format!("{home}/.zsh_history")),
        "bash" => std::env::var("HISTFILE").unwrap_or_else(|_| format!("{home}/.bash_history")),
        _ => {
            debug_log!("history  unsupported shell: {shell_name}");
            return None;
        }
    };

    let content = match std::fs::read(&hist_path) {
        Ok(c) => c,
        Err(e) => {
            debug_log!("history  read fail {hist_path}: {e}");
            return None;
        }
    };

    let last_cmd = if shell_name == "zsh" {
        parse_zsh_last_command(&content)
    } else {
        // bash: aic 자신의 명령어 건너뛰기
        String::from_utf8_lossy(&content)
            .lines()
            .rev()
            .find(|l| {
                let t = l.trim();
                if t.is_empty() {
                    return false;
                }
                let cmd_base = t.split_whitespace().next().unwrap_or("");
                let cmd_name = std::path::Path::new(cmd_base)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(cmd_base);
                cmd_name != "aic"
            })
            .map(|s| s.to_string())
    };

    let cmd = last_cmd.filter(|s| !s.is_empty())?;
    debug_log!(
        "history  {shell_name} {hist_path} ({} bytes) → {cmd}",
        content.len()
    );

    Some(aic_common::CommandRecord {
        command: Some(cmd),
        exit_code: -1,
        output_lines: vec!["(히스토리에서 가져옴 - 출력 없음)".to_string()],
        timestamp: chrono::Utc::now(),
        ..Default::default()
    })
}

/// zsh 히스토리 파일에서 마지막 명령어를 파싱한다.
/// `skip_commands`에 포함된 명령어는 건너뛴다 (aic 자신 등).
/// 형식: `: 1234567890:0;actual command`
fn parse_zsh_last_command(content: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(content);

    for line in text.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // zsh extended history: ": timestamp:0;command"
        let cmd = if let Some(pos) = trimmed.find(';') {
            if trimmed.starts_with(": ") {
                &trimmed[pos + 1..]
            } else {
                trimmed
            }
        } else {
            trimmed
        };

        // aic 자신의 명령어는 건너뛰기
        let cmd_base = cmd.split_whitespace().next().unwrap_or("");
        let cmd_name = std::path::Path::new(cmd_base)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(cmd_base);
        if cmd_name == "aic" {
            continue;
        }

        return Some(cmd.to_string());
    }

    None
}

/// 터미널 너비를 가져온다. 감지 실패 시 80을 사용한다.
fn term_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
}

/// 에러 컨텍스트 표시 (주황색 왼쪽 선 + 명령어 + 노이즈 정제된 마지막 5줄)
/// 분석 직전, capture quality에 따라 사용자에게 신뢰도/대안 안내 (Phase 4).
///
/// `aic_common::capture_quality_hint`를 한 번 감싸 ANSI 색상을 입혀 출력한다.
/// FullOutput에서는 무음.
fn print_capture_quality_hint(rec: &aic_common::CommandRecord, config: &AppConfig) {
    if let Some(msg) = aic_common::capture_quality_hint(rec, config.session.capture_mode) {
        eprintln!("{COL_DIM}ℹ {msg}{COL_RESET}");
    }
}

fn print_error_context(rec: &aic_common::CommandRecord) {
    let prefix = format!("{COL_YELLOW}▐{COL_RESET} ");
    let empty_prefix = format!("{COL_YELLOW}▐{COL_RESET}");

    let cmd = rec.command.as_deref().unwrap_or("(unknown)");
    println!(
        "{prefix}{COL_DIM}$ {cmd} (exit {code}){COL_RESET}",
        code = rec.exit_code
    );

    // 빈 줄 / 셸 프롬프트 / 백스페이스 잔재 / 명령어 에코를 제거한 라인만 표시
    let cleaned = clean_output_lines(&rec.output_lines, rec.command.as_deref());
    let show_from = if cleaned.len() > 5 {
        cleaned.len() - 5
    } else {
        0
    };
    if show_from > 0 {
        println!("{prefix}{COL_DIM}  ... ({show_from} lines omitted){COL_RESET}");
    }
    for line in &cleaned[show_from..] {
        println!("{prefix}{COL_DIM}  {line}{COL_RESET}");
    }
    println!("{empty_prefix}");
}

/// LLM 응답에서 <think> 블록을 분리한다.
/// 반환: (think_content, main_content)
fn split_think_block(text: &str) -> (Option<String>, String) {
    let trimmed = text.trim();
    if let Some(start) = trimmed.find("<think>") {
        if let Some(end) = trimmed.find("</think>") {
            let think = trimmed[start + 7..end].trim().to_string();
            let rest = format!("{}{}", &trimmed[..start], &trimmed[end + 8..])
                .trim()
                .to_string();
            let think_opt = if think.is_empty() { None } else { Some(think) };
            return (think_opt, rest);
        }
    }
    (None, trimmed.to_string())
}

/// <think> 블록을 처음과 끝을 보여주는 요약 한 줄로 출력
/// 형태: [Thinking] 첫 부분 ... 끝 부분
fn print_think_block(think: &str) {
    let lines: Vec<&str> = think.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return;
    }

    let first: String = lines
        .first()
        .unwrap_or(&"")
        .trim()
        .chars()
        .take(40)
        .collect();
    let last: String = lines
        .last()
        .unwrap_or(&"")
        .trim()
        .chars()
        .rev()
        .take(30)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    if lines.len() <= 1 {
        println!("{COL_DIM}[Thinking] {first}{COL_RESET}");
    } else {
        println!("{COL_DIM}[Thinking] {first} ... {last}{COL_RESET}");
    }
}

/// LLM 응답을 파란색 왼쪽 선과 함께 출력 (자유 텍스트용 — 직접 프롬프트 모드에서 사용)
/// <think> 블록은 흐린 회색 들여쓰기로 별도 표시
fn print_llm_response(text: &str) {
    let (think, main) = split_think_block(text);

    if let Some(ref t) = think {
        print_think_block(t);
    }

    let prefix = format!("{COL_BLUE}▐{COL_RESET} ");
    let empty_prefix = format!("{COL_BLUE}▐{COL_RESET}");
    let content_width = term_width().saturating_sub(3);

    for line in main.lines() {
        if line.is_empty() {
            println!("{empty_prefix}");
        } else {
            let mut remaining = line;
            while !remaining.is_empty() {
                let (chunk, rest) = split_at_width(remaining, content_width);
                println!("{prefix}{chunk}");
                remaining = rest;
            }
        }
    }
}

/// 응답 언어에 따른 섹션 라벨.
fn section_labels(lang: &str) -> (&'static str, &'static str, &'static str) {
    match lang {
        "english" => ("Cause", "Try this", "Note"),
        "japanese" => ("原因", "次のコマンド", "補足"),
        "chinese" => ("原因", "建议命令", "备注"),
        _ => ("원인", "다음 시도", "참고"),
    }
}

/// 분석 결과를 섹션 단위로 포맷해 출력한다.
/// `▸ 원인` (cyan) → `▸ 다음 시도` (green + `$ cmd`) → `▸ 참고` (dim) 순서.
/// <think> 블록이 있으면 먼저 흐린 회색으로 표시.
fn print_analysis_result(result: &AnalysisResult, lang: &str) {
    let (cause_label, fix_label, info_label) = section_labels(lang);

    // explanation에서 <think> 블록 분리
    let (think, explanation) = split_think_block(&result.explanation);
    if let Some(ref t) = think {
        print_think_block(t);
    }

    print_analysis_section(cause_label, &explanation, COL_CYAN);
    if let Some(cmd) = &result.suggested_command {
        print_command_block(fix_label, cmd);
    }
    if let Some(info) = &result.additional_info {
        print_dim_section(info_label, info);
    }
}

/// `cmd`가 destructive한 패턴을 포함하는지 (sudo, rm -rf, dd, mkfs).
fn is_destructive_command(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let patterns = [
        "rm -rf",
        "rm -fr",
        "sudo ",
        " dd ",
        "mkfs",
        ":(){", // fork bomb
        "> /dev/sd",
        "chmod -r 777 /",
    ];
    if patterns.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // dd는 줄 시작에서도 잡아야 함
    lower.starts_with("dd ")
        || lower.starts_with("rm ")
            && lower.contains(" /")
            && (lower.contains(" -rf") || lower.contains(" -fr"))
}

/// LLM 제안 명령을 인라인 실행할지 사용자에게 물어보고 실행한다.
/// - 비-TTY → 무시
/// - `AIC_NO_RUN` 설정 → 무시
/// - `AIC_AUTO_RUN=1` → prompt 없이 실행 (단, destructive면 prompt 강제)
/// - 그 외: dialoguer::Confirm
fn maybe_run_suggested(cmd: &str, lang: &str) {
    use std::io::IsTerminal;

    if std::env::var("AIC_NO_RUN").is_ok() {
        return;
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return;
    }
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return;
    }

    let destructive = is_destructive_command(cmd);
    let auto_run = std::env::var("AIC_AUTO_RUN")
        .map(|v| v == "1")
        .unwrap_or(false);

    // prompt에 명령어를 직접 포함시켜 어떤 명령인지 모호함이 없도록 한다.
    // 길면(>80자) 잘라서 표시.
    let display_cmd: String = if cmd.chars().count() > 80 {
        let mut s: String = cmd.chars().take(80).collect();
        s.push('…');
        s
    } else {
        cmd.to_string()
    };
    let prompt_msg = match lang {
        "korean" => format!("실행: `{display_cmd}` ?"),
        "japanese" => format!("実行: `{display_cmd}` ?"),
        "chinese" => format!("执行: `{display_cmd}` ?"),
        _ => format!("Run: `{display_cmd}` ?"),
    };
    let warn_msg = match lang {
        "korean" => "⚠ 위험할 수 있는 명령입니다",
        "japanese" => "⚠ 危険な可能性があるコマンドです",
        "chinese" => "⚠ 此命令可能有危险",
        _ => "⚠ Potentially destructive command",
    };

    if destructive {
        eprintln!("{COL_RED}{COL_BOLD}{warn_msg}{COL_RESET}");
    }

    let should_run = if auto_run && !destructive {
        true
    } else {
        match Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(&prompt_msg)
            .default(false)
            .interact()
        {
            Ok(v) => v,
            Err(_) => return,
        }
    };

    if !should_run {
        return;
    }

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let status = std::process::Command::new(&shell)
        .arg("-c")
        .arg(cmd)
        .status();

    match status {
        Ok(s) => {
            let code = s.code().unwrap_or(-1);
            eprintln!("{COL_DIM}[aic] 종료 코드: {code}{COL_RESET}");
        }
        Err(e) => {
            eprintln!("{COL_YELLOW}[aic] 명령 실행 실패: {e}{COL_RESET}");
        }
    }
}

/// `▸ <title>` 헤더 + 들여쓴 본문 + 빈 줄. 본문은 일반 색.
fn print_analysis_section(title: &str, body: &str, accent: &str) {
    let indent = "  ";
    let content_width = term_width().saturating_sub(2);

    println!("{accent}{COL_BOLD}▸ {title}{COL_RESET}");
    for line in body.lines() {
        if line.is_empty() {
            println!();
            continue;
        }
        let mut remaining = line;
        while !remaining.is_empty() {
            let (chunk, rest) = split_at_width(remaining, content_width);
            println!("{indent}{chunk}");
            remaining = rest;
        }
    }
    println!();
}

/// 참고 섹션: 헤더와 본문 모두 dim 색상.
fn print_dim_section(title: &str, body: &str) {
    let indent = "  ";
    let content_width = term_width().saturating_sub(2);

    println!("{COL_DIM}{COL_BOLD}▸ {title}{COL_RESET}");
    for line in body.lines() {
        if line.is_empty() {
            println!();
            continue;
        }
        let mut remaining = line;
        while !remaining.is_empty() {
            let (chunk, rest) = split_at_width(remaining, content_width);
            println!("{indent}{COL_DIM}{chunk}{COL_RESET}");
            remaining = rest;
        }
    }
    println!();
}

/// `aic --dry-run` 미리보기 — 실제 LLM 호출 없이 비용/timeout/토큰 추정 출력.
fn print_dry_run(mode: &str, prompt: &str, provider: &str, model: &str, llm: &LlmConfig) {
    let chars = prompt.len();
    let est_input_tokens = chars.div_ceil(4); // chars/4 (영문 평균; 한국어는 보수적으로 더 많음)
    const ASSUMED_OUTPUT_TOKENS: usize = 512;

    println!("{COL_CYAN}{COL_BOLD}🔍 Dry-run preview{COL_RESET}");
    println!("  mode:        {mode}");
    println!("  provider:    {provider}");
    println!("  model:       {model}");
    println!("  prompt:      {chars} chars (~{est_input_tokens} tokens 추정)");
    println!("  max output:  ~{ASSUMED_OUTPUT_TOKENS} tokens (가정)");
    println!(
        "  timeout:     {req}s (request) / {conn}s (connect)",
        req = llm.request_timeout_secs,
        conn = llm.connect_timeout_secs
    );
    match estimate_cost_usd(model, est_input_tokens, ASSUMED_OUTPUT_TOKENS) {
        Some((cin, cout)) if cin == 0.0 && cout == 0.0 => {
            println!("  estimated:   $0 (free tier)");
        }
        Some((cin, cout)) => {
            println!(
                "  estimated:   ${cin:.6} input + ${cout:.6} output = ${total:.6}",
                total = cin + cout
            );
        }
        None => {
            println!("  estimated:   단가 정보 없음 (model={model})");
        }
    }
    println!("  {COL_DIM}⚠ 실제 호출 없음{COL_RESET}");
}

/// 모델별 토큰당 단가(USD). 모르는 모델은 None.
fn estimate_cost_usd(model: &str, input_tokens: usize, output_tokens: usize) -> Option<(f64, f64)> {
    let (in_per_1m, out_per_1m): (f64, f64) = match model {
        // OpenAI
        "gpt-4o-mini" => (0.15, 0.60),
        "gpt-4o" => (5.00, 20.00),
        "gpt-4-turbo" => (10.00, 30.00),
        "gpt-3.5-turbo" => (0.50, 1.50),
        // Anthropic — 4.x family 단가는 sonnet 4 시리즈 공시 기준($3 in / $15 out).
        // 정확한 단가는 https://www.anthropic.com/pricing 참조; 여기 매핑은 dry-run
        // 추정용이라 실제 결제와 다를 수 있다.
        "claude-3-5-sonnet-20241022" | "claude-sonnet-4-20250514" | "claude-sonnet-4-6" => {
            (3.00, 15.00)
        }
        "claude-3-5-haiku-20241022" | "claude-haiku-4-5-20251001" => (1.00, 5.00),
        "claude-3-opus-20240229" | "claude-opus-4-7" => (15.00, 75.00),
        // NVIDIA NIM (대부분 무료 tier)
        m if m.starts_with("meta/llama") => (0.0, 0.0),
        m if m.starts_with("nvidia/") => (0.0, 0.0),
        m if m.starts_with("qwen/") => (0.0, 0.0),
        m if m.starts_with("mistralai/") => (0.0, 0.0),
        // Groq (2025 공시 단가, $/1M tokens)
        "llama-3.3-70b-versatile" => (0.59, 0.79),
        "llama-3.1-8b-instant" => (0.05, 0.08),
        "deepseek-r1-distill-llama-70b" => (0.75, 0.99),
        "gemma2-9b-it" => (0.20, 0.20),
        _ => return None,
    };
    let cin = in_per_1m * (input_tokens as f64) / 1_000_000.0;
    let cout = out_per_1m * (output_tokens as f64) / 1_000_000.0;
    Some((cin, cout))
}

/// `▸ 다음 시도` + 들여쓴 `$ <cmd>` (강조) + 빈 줄.
fn print_command_block(title: &str, cmd: &str) {
    println!("{COL_GREEN}{COL_BOLD}▸ {title}{COL_RESET}");
    println!("  {COL_GREEN}${COL_RESET} {COL_BOLD}{cmd}{COL_RESET}");
    println!();
}

#[cfg(test)]
mod tests {
    use super::{
        apply_provider_override, chat_run_command_enabled, is_destructive_command, resolve_provider,
    };
    use aic_client::llm_dispatcher::LlmDispatcher;
    use aic_common::{
        AppConfig, BoundaryStrategyConfig, LlmConfig, ProviderConfig, ProviderType, ServerConfig,
        SessionConfig,
    };
    use std::collections::HashMap;

    #[test]
    fn chat_run_command_default_enabled() {
        // 기본 chat(opt-out 없음) → run_command 활성.
        assert!(chat_run_command_enabled(false, false));
    }

    #[test]
    fn chat_run_command_opt_out_disables() {
        // --no-run/--read-only 플래그 → 비활성.
        assert!(!chat_run_command_enabled(true, false));
        // env AIC_AGENT_NO_RUN → 비활성.
        assert!(!chat_run_command_enabled(false, true));
        // 둘 다 → 비활성.
        assert!(!chat_run_command_enabled(true, true));
    }

    #[test]
    fn destructive_rm_rf_root() {
        assert!(is_destructive_command("rm -rf /"));
        assert!(is_destructive_command("rm -rf /tmp/foo"));
        assert!(is_destructive_command("RM -RF /")); // case insensitive
    }

    #[test]
    fn destructive_sudo() {
        assert!(is_destructive_command("sudo apt install"));
        assert!(is_destructive_command("sudo dd if=/dev/zero of=/dev/sda"));
    }

    #[test]
    fn destructive_dd() {
        assert!(is_destructive_command("dd if=/dev/zero of=/dev/sdb"));
    }

    #[test]
    fn destructive_mkfs() {
        assert!(is_destructive_command("mkfs.ext4 /dev/sda1"));
    }

    #[test]
    fn safe_commands_not_flagged() {
        assert!(!is_destructive_command("ls -la"));
        assert!(!is_destructive_command("git status"));
        assert!(!is_destructive_command("cat /etc/hosts"));
        assert!(!is_destructive_command("rm foo.txt")); // no -rf
    }

    fn config_with_providers(default: &str, names: &[&str]) -> AppConfig {
        let mut providers = HashMap::new();
        for name in names {
            providers.insert(
                (*name).to_string(),
                ProviderConfig {
                    provider_type: ProviderType::OpenAiCompatible,
                    endpoint: None,
                    api_key: None,
                    model: None,
                    cli_path: None,
                    cli_args: None,
                },
            );
        }
        AppConfig {
            llm: LlmConfig {
                default_provider: default.to_string(),
                providers,
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: ServerConfig {
                max_buffer_lines: 500,
                socket_path: None,
                boundary_strategy: BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
            session: SessionConfig::default(),
        }
    }

    #[test]
    fn resolve_provider_returns_default_when_override_is_none() {
        let cfg = config_with_providers("openai", &["openai", "anthropic"]);
        assert_eq!(resolve_provider(&cfg, None).unwrap(), "openai");
    }

    #[test]
    fn resolve_provider_returns_override_when_known() {
        let cfg = config_with_providers("openai", &["openai", "anthropic"]);
        assert_eq!(
            resolve_provider(&cfg, Some("anthropic")).unwrap(),
            "anthropic"
        );
    }

    #[test]
    fn resolve_provider_errors_with_available_list_when_unknown() {
        let cfg = config_with_providers("openai", &["openai", "anthropic"]);
        let err = resolve_provider(&cfg, Some("ghost")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghost"), "msg should mention bad name: {msg}");
        assert!(
            msg.contains("anthropic") && msg.contains("openai"),
            "msg should list available providers: {msg}"
        );
    }

    #[test]
    fn resolve_provider_treats_empty_override_as_no_override() {
        let cfg = config_with_providers("openai", &["openai"]);
        assert_eq!(resolve_provider(&cfg, Some("")).unwrap(), "openai");
    }

    #[test]
    fn provider_override_is_applied_to_dispatcher_config() {
        // default=anthropic(Anthropic, tool-calling 미지원), override=groq(OpenAI-compat 지원).
        let mut cfg = config_with_providers("anthropic", &["anthropic", "groq"]);
        if let Some(p) = cfg.llm.providers.get_mut("anthropic") {
            p.provider_type = ProviderType::Anthropic;
            p.model = Some("claude-x".to_string());
        }
        if let Some(p) = cfg.llm.providers.get_mut("groq") {
            p.provider_type = ProviderType::Groq;
            p.model = Some("llama-x".to_string());
        }

        // override 없음 → default(anthropic) 보존, dispatcher도 anthropic(미지원).
        let (cfg_def, name_def) = apply_provider_override(cfg.clone(), None).unwrap();
        assert_eq!(name_def, "anthropic");
        assert_eq!(cfg_def.llm.default_provider, "anthropic");
        assert!(!LlmDispatcher::from_config(cfg_def.llm.clone()).supports_tool_calling());

        // override=groq → default_provider가 실제로 groq로 바뀌고 dispatcher가 override를 사용.
        let (cfg_ov, name_ov) = apply_provider_override(cfg.clone(), Some("groq")).unwrap();
        assert_eq!(name_ov, "groq");
        assert_eq!(cfg_ov.llm.default_provider, "groq");
        assert!(LlmDispatcher::from_config(cfg_ov.llm.clone()).supports_tool_calling());
        // model도 override provider의 것을 따른다(표시=실제).
        assert_eq!(
            cfg_ov
                .llm
                .providers
                .get("groq")
                .and_then(|p| p.model.clone()),
            Some("llama-x".to_string())
        );

        // 알 수 없는 override는 에러(기존 검증 동작 보존).
        assert!(apply_provider_override(cfg, Some("ghost")).is_err());
    }

    #[test]
    fn resolve_provider_empty_providers_map_lists_none_marker() {
        let cfg = config_with_providers("openai", &[]);
        let err = resolve_provider(&cfg, Some("ghost")).unwrap_err();
        assert!(
            err.to_string().contains("(없음)"),
            "msg should show (없음) when providers map is empty: {err}"
        );
    }
}
