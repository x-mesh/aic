use aic_client::auto_brancher::{AutoBrancher, ExecutionMode};
use aic_client::cache;
use aic_client::config::ConfigManager;
use aic_client::error_analyzer::{clean_output_lines, ErrorAnalyzer};
use aic_client::llm_dispatcher::LlmDispatcher;
use aic_client::repl::ReplSession;
use aic_client::uds_client::UdsClient;
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
    std::env::var("AIC_DEBUG")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// 첫 디버그 호출 시점을 캐시하고, 그 시점부터의 누적 경과 시간(초)을 반환한다.
fn debug_elapsed_secs() -> f64 {
    static DEBUG_START: OnceLock<Instant> = OnceLock::new();
    DEBUG_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_secs_f64()
}

/// 단순 디버그 정보 라인 — `[debug +0.001s] <message>` (흐린 회색).
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if is_debug_mode() {
            let t = debug_elapsed_secs();
            eprintln!("\x1b[90m[debug +{:.3}s] {}\x1b[0m", t, format!($($arg)*));
        }
    };
}

/// 정보와 측정 시간을 한 라인으로 출력 — `[debug +0.001s] <message> (1.23ms)` (흐린 회색).
macro_rules! debug_step {
    ($start:expr, $($arg:tt)*) => {
        if is_debug_mode() {
            let elapsed = $start.elapsed();
            let t = debug_elapsed_secs();
            let msg = format!($($arg)*);
            eprintln!(
                "\x1b[90m[debug +{:.3}s] {} ({:.2}ms)\x1b[0m",
                t, msg, elapsed.as_secs_f64() * 1000.0
            );
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
}

#[derive(Subcommand)]
enum DaemonOp {
    /// aicd가 실행 중인지 확인하고 PID/socket을 출력한다.
    Status,
    /// aicd를 백그라운드로 시작한다 (이미 실행 중이면 no-op).
    Start,
    /// aicd에 graceful Shutdown을 요청한다.
    Stop,
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
        Some(Commands::Doctor { json, session }) => handle_doctor(json, session).await,
        Some(Commands::Status {
            watch,
            interval,
            session,
            json,
            all,
        }) => handle_status(watch, interval, session, json, all).await,
        Some(Commands::Audit { op }) => match op {
            AuditOp::Verify => handle_audit_verify(),
        },
        Some(Commands::MigrateKeys) => handle_migrate_keys(),
        Some(Commands::Init { shell, hook_mode }) => handle_init(shell, hook_mode),
        Some(Commands::Top { interval, session }) => handle_top(interval, session).await,
        Some(Commands::Daemon { op }) => match op {
            DaemonOp::Status => handle_daemon_status().await,
            DaemonOp::Start => handle_daemon_start().await,
            DaemonOp::Stop => handle_daemon_stop().await,
        },
        Some(Commands::Session { op }) => match op {
            SessionOp::Stop { id } => handle_session_stop(id).await,
        },
        Some(Commands::HookEvent { op }) => handle_hook_event(op).await,
        Some(Commands::Run { cmd }) => handle_run(cmd).await,
        Some(Commands::Sessions { json }) => {
            if json {
                print_sessions_json().await;
            } else {
                handle_sessions().await;
            }
        }
        Some(Commands::Setup { shell }) => handle_setup(shell).await,
        Some(Commands::Debug { op }) => match op {
            DebugOp::Bundle => handle_debug_bundle().await,
        },
        None => {
            // 인자가 있으면 프롬프트로 사용, 없으면 기본 동작
            let prompt = if cli.prompt.is_empty() {
                None
            } else {
                Some(cli.prompt.join(" "))
            };

            if let Err(e) = handle_default(prompt, cli.dry_run).await {
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
}

/// `aic daemon start`: aicd binary를 백그라운드 spawn한다 (이미 떠 있으면 no-op).
async fn handle_daemon_start() {
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
async fn handle_run(cmd: Vec<String>) {
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
    let request = match op {
        HookEventOp::Start {
            session,
            command_id,
            command,
            cwd,
            shell,
            pid,
        } => aic_common::IpcRequest::CommandStarted {
            session_id: session,
            command_id,
            command,
            cwd: cwd.map(std::path::PathBuf::from),
            shell,
            pid,
            started_at: chrono::Utc::now(),
        },
        HookEventOp::End {
            session,
            command_id,
            exit,
            duration_ms,
        } => aic_common::IpcRequest::CommandFinished {
            session_id: session,
            command_id,
            exit_code: exit,
            finished_at: chrono::Utc::now(),
            duration_ms,
        },
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

        match client.get_last_command().await {
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
async fn handle_doctor(json: bool, session: Option<String>) {
    let socket = resolve_socket(session.as_deref());
    let results = aic_client::doctor::run_all_checks(&socket).await;
    if json {
        match serde_json::to_string_pretty(&results) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("JSON 직렬화 실패: {e}");
                std::process::exit(2);
            }
        }
    } else {
        aic_client::doctor::print_report(&results);
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
                    let tty = s.attached_tty.as_deref().unwrap_or("?");
                    let shell = s
                        .shell
                        .as_deref()
                        .and_then(|p| p.rsplit('/').next())
                        .unwrap_or("?");
                    println!(
                        "  {COL_CYAN}{id}{COL_RESET}{marker}  {COL_DIM}pid {pid}  {tty}  {shell}{COL_RESET}",
                        id = s.id,
                        pid = s.pid,
                    );
                }
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

// ── 세션 소켓 결정 ──────────────────────────────────────────────

/// `AIC_SESSION_ID` 환경변수 기반 소켓 경로 결정 결과.
enum SessionSocket {
    /// 유효한 소켓 경로 (UDS 연결 시도 대상)
    Path(std::path::PathBuf),
    /// 히스토리 폴백 (세션 소켓 사용 불가)
    HistoryFallback,
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

/// 기본 동작: 서버 연결 → 직전 명령어 조회 → 자동 분기
/// 또는 직접 프롬프트가 주어지면 LLM에 바로 질문
async fn handle_default(direct_prompt: Option<String>, dry_run: bool) -> anyhow::Result<()> {
    let total_start = Instant::now();

    let config_start = Instant::now();
    let config = ConfigManager::load()?;
    let provider_name = config.llm.default_provider.clone();
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

    // 서버에서 마지막 명령어 조회, 실패 시 히스토리 폴백
    //
    // AIC_SESSION_ID 환경변수가 설정되어 있으면 세션별 소켓으로 연결을 시도한다.
    // 미설정 시 기존 config 기반 소켓 경로를 사용한다.
    let session_socket = resolve_session_socket(&config);

    let record = match session_socket {
        SessionSocket::Path(socket_path) => {
            let connect_start = Instant::now();
            let client = UdsClient::new(socket_path.clone());

            match client.get_last_command().await {
                Ok(rec) => {
                    debug_step!(
                        connect_start,
                        "uds      {} · exit={} lines={} cmd={}",
                        socket_path.display(),
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
                    } else {
                        rec
                    }
                }
                Err(_) => {
                    // 서버 없음 → 히스토리 폴백
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
        SessionSocket::HistoryFallback => {
            eprintln!(
                "{COL_YELLOW}ℹ{COL_RESET} aic-session 안에서 실행해주세요. 직접 질문은 {COL_BOLD}aic \"질문\"{COL_RESET} 형식으로 가능합니다."
            );
            debug_step!(total_start, "total");
            return Ok(());
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

            let cache_key = cache::cache_key(
                rec.command.as_deref().unwrap_or(""),
                rec.exit_code,
                &rec.output_lines,
            );
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
            let prompt = ErrorAnalyzer::build_prompt(&rec, lang);
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
        .arg("-lc")
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
        "claude-3-5-sonnet-20241022"
        | "claude-sonnet-4-20250514"
        | "claude-sonnet-4-6" => (3.00, 15.00),
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
    use super::is_destructive_command;

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
}
