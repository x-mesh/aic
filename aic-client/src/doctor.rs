//! `aic doctor` — 통합 진단 서브커맨드.
//!
//! 다음 항목을 순서대로 점검하고 PASS/WARN/FAIL 리포트를 출력한다.
//! 1. config 파일 파싱
//! 2. default provider 설정 유효성 (API key / cli_path / endpoint)
//! 3. UDS 소켓 경로 존재
//! 4. aic-session 데몬 응답 (Ping)
//! 5. 셸 hook 설치 여부 (~/.aic/hooks.* + ~/.zshrc·.bashrc source 라인)
//! 6. LLM endpoint reachability (HEAD 요청, 2s timeout)
//! 7. Central Store 상태 (R14.6) — Central_Store_Flag 값/소스, Attach_UDS
//!    소켓 경로와 연결 가능 여부, 세션 metrics 의 `dropped_bytes` /
//!    `attach_reconnect_total` 을 출력한다.

use crate::config::ConfigManager;
use crate::uds_client::UdsClient;
use aic_common::central_store_flag::{
    current_phase, resolve_central_store_flag_with_source_uncached, AppConfigWithDaemon,
    DaemonConfig,
};
use aic_common::{AppConfig, ProviderConfig, ProviderType};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 단일 체크 결과.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub status: Status,
    pub detail: String,
    pub fix_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl CheckResult {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Pass,
            detail: detail.into(),
            fix_hint: None,
        }
    }
    fn warn(name: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Warn,
            detail: detail.into(),
            fix_hint: Some(fix.into()),
        }
    }
    fn fail(name: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
            fix_hint: Some(fix.into()),
        }
    }
}

/// 모든 체크를 실행하고 결과 리스트를 반환한다.
/// `socket`은 호출자(main.rs::resolve_socket)가 결정한 활성 세션 경로를 그대로 사용한다.
/// status / doctor / top이 동일한 우선순위 체인을 공유해야 H1 회귀가 재발하지 않는다.
pub async fn run_all_checks(socket: &std::path::Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let config = match ConfigManager::load() {
        Ok(c) => {
            results.push(CheckResult::pass(
                "config 파일",
                format!("파싱 성공 ({})", ConfigManager::config_path().display()),
            ));
            Some(c)
        }
        Err(e) => {
            results.push(CheckResult::fail(
                "config 파일",
                format!("파싱 실패: {e}"),
                "`aic config`로 설정 파일을 점검하세요",
            ));
            None
        }
    };

    if let Some(cfg) = config.as_ref() {
        results.push(check_provider(cfg));
        results.push(check_socket_path(socket));
        results.push(check_daemon_alive(socket).await);
        results.push(check_aicd_supervisor().await);
        results.push(check_shell_hooks());
        if let Some(provider) = cfg.llm.providers.get(&cfg.llm.default_provider) {
            results.push(check_llm_endpoint(provider).await);
            results.push(check_keychain_access(cfg, provider));
        }
        results.push(check_audit_log());
    }

    results
}

fn check_keychain_access(cfg: &AppConfig, provider: &ProviderConfig) -> CheckResult {
    let raw = match provider.api_key.as_deref() {
        Some(k) if !k.is_empty() => k,
        _ => return CheckResult::pass("keychain", "(api_key 없는 provider)"),
    };
    if !crate::keychain::is_reference(raw) {
        return CheckResult::warn(
            "keychain",
            "API key가 config.toml에 평문으로 저장됨",
            "`aic migrate-keys`로 OS keychain으로 이동하세요",
        );
    }
    let provider_name = &cfg.llm.default_provider;
    match crate::keychain::resolve(raw) {
        Ok(_) => CheckResult::pass("keychain", format!("{provider_name} entry 접근 가능")),
        Err(e) => CheckResult::fail(
            "keychain",
            format!("keychain 접근 실패: {e}"),
            "OS keychain (Keychain/Secret Service) 잠금 해제 또는 entry 재생성하세요",
        ),
    }
}

fn check_audit_log() -> CheckResult {
    match crate::audit::verify() {
        Ok(report) if report.valid => CheckResult::pass(
            "audit log",
            format!("HMAC chain 무결성 OK ({n} 라인)", n = report.lines),
        ),
        Ok(report) => CheckResult::fail(
            "audit log",
            format!(
                "chain 변조 의심 — 라인 {at}",
                at = report.broken_at.unwrap_or(0)
            ),
            "`~/.local/state/aic/audit.log`를 백업 후 삭제하고 새 chain 시작",
        ),
        Err(e) => CheckResult::warn(
            "audit log",
            format!("검증 실패: {e}"),
            "키 또는 로그 파일 권한을 확인하세요",
        ),
    }
}

/// 결과 리스트를 컬러 콘솔 출력.
pub fn print_report(results: &[CheckResult]) {
    let pass_count = results.iter().filter(|r| r.status == Status::Pass).count();
    let warn_count = results.iter().filter(|r| r.status == Status::Warn).count();
    let fail_count = results.iter().filter(|r| r.status == Status::Fail).count();

    for r in results {
        let (sym, color) = match r.status {
            Status::Pass => ("✔", "\x1b[32m"), // green
            Status::Warn => ("⚠", "\x1b[33m"), // yellow
            Status::Fail => ("✗", "\x1b[31m"), // red
        };
        println!(
            "{color}{sym}\x1b[0m \x1b[1m{}\x1b[0m — {}",
            r.name, r.detail
        );
        if let Some(hint) = &r.fix_hint {
            println!("    \x1b[90m↳ {hint}\x1b[0m");
        }
    }

    println!();
    println!(
        "요약: \x1b[32m{pass_count} PASS\x1b[0m, \x1b[33m{warn_count} WARN\x1b[0m, \x1b[31m{fail_count} FAIL\x1b[0m"
    );
}

// ── Central Store 섹션 (R14.6) ───────────────────────────────────

/// `aic doctor` 의 Central Store 섹션 리포트.
///
/// `run_all_checks` 가 돌려주는 `CheckResult` 벡터와는 별개의 구조체다 —
/// Central Store 섹션은 단일 PASS/WARN/FAIL 로 환원되지 않고, 여러 개의 관측치
/// (flag / phase / attach 경로 / metric) 를 한 번에 보여 주어야 하기 때문이다.
/// `handle_doctor` 가 이 구조체를 `run_all_checks` 결과 다음에 별도 블록으로 출력한다.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CentralStoreReport {
    /// Central_Store_Flag 의 현재 평가 값.
    pub flag_resolved: bool,
    /// flag 가 어디서 유래했는지 — "env" / "config" / "phase-default".
    pub flag_source: String,
    /// 빌드된 Phase 라벨 (예: "phase-3_4").
    pub phase: String,
    /// Attach_UDS 소켓 경로. aic-session 이 dial 하는 경로와 동일해야 한다.
    pub attach_socket_path: PathBuf,
    /// `UnixStream::connect` 를 짧은 타임아웃으로 시도한 결과. `true` 면 aicd 가
    /// 해당 소켓을 listen 중이라는 신호다 (R14.6).
    pub attach_connected: bool,
    /// 현재 세션의 `aic-session` metric — backpressure 로 drop 된 byte 수 (R14.4).
    pub dropped_bytes: u64,
    /// 현재 세션의 `aic-session` metric — Attach_UDS 재연결 시도 수 (R14.5).
    pub attach_reconnect_total: u64,
    /// 세션 metric 조회 시 실패한 이유. 세션 소켓이 없거나 `GetMetrics` 가 실패한
    /// 경우 사용자에게 어떤 필드가 누락되었는지 알려 준다. `Some` 이면
    /// `dropped_bytes` / `attach_reconnect_total` 은 0 으로 채워진 placeholder 다.
    pub session_metrics_error: Option<String>,
}

/// Central Store 섹션을 조사한다 (R14.6).
///
/// - `env`: `AIC_CENTRAL_STORE` 를 포함할 수 있는 환경변수 맵. 실제 호출은
///   `std::env::vars().collect()` 를 넘기고, 테스트는 임의 맵으로 주입한다.
/// - `config`: `[daemon]` 섹션. `None` 이면 env / Phase default 만으로 평가.
/// - `session_socket`: 현재 세션의 UDS 경로. `dropped_bytes` /
///   `attach_reconnect_total` 은 이 소켓의 `GetMetrics` 응답에서 읽는다. 세션이
///   없거나 조회에 실패하면 값은 0, 원인은 `session_metrics_error` 에 저장된다.
///
/// 내부 I/O 에러는 결과 필드 (`attach_connected=false`, `session_metrics_error`)
/// 로 표현되며 panic 하지 않는다 (doctor 는 어떤 상황에서도 완주해야 한다).
pub async fn probe_central_store(
    env: &HashMap<String, String>,
    config: Option<&DaemonConfig>,
    session_socket: Option<&Path>,
) -> CentralStoreReport {
    let (flag_resolved, source) =
        resolve_central_store_flag_with_source_uncached(env, config);
    let phase = current_phase();
    let attach_socket_path = aic_common::aicd_attach_socket_path();
    let attach_connected = probe_attach_socket(&attach_socket_path).await;

    let (dropped_bytes, attach_reconnect_total, session_metrics_error) =
        probe_session_metrics(session_socket).await;

    CentralStoreReport {
        flag_resolved,
        flag_source: source.as_str().to_string(),
        phase: phase.as_str().to_string(),
        attach_socket_path,
        attach_connected,
        dropped_bytes,
        attach_reconnect_total,
        session_metrics_error,
    }
}

/// 현재 프로세스의 환경변수 + config 파일 + 주어진 session socket 으로부터
/// `probe_central_store` 를 실행하는 편의 wrapper.
///
/// `handle_doctor` 에서 사용한다. config 파일 파싱 실패는 `None` 으로 떨어져
/// env + Phase default 로만 평가된다 (R12.2).
pub async fn probe_central_store_default(
    session_socket: Option<&Path>,
) -> CentralStoreReport {
    let env: HashMap<String, String> = std::env::vars().collect();
    let daemon = read_daemon_config_best_effort();
    probe_central_store(&env, daemon.as_ref(), session_socket).await
}

/// Attach_UDS 소켓이 listen 중인지 짧은 타임아웃으로 `connect` 를 시도한다.
///
/// 연결 직후 stream 을 drop 하므로 `AttachOpen` 은 보내지 않는다 — aicd 는 첫 프레임
/// 읽기에서 EOF 를 관측하고 조용히 종료한다. probe 만의 부수효과는 metrics 증가
/// 없이도 안전하다 (attach_open 카운터는 AttachOpen 프레임을 받아야만 증가).
async fn probe_attach_socket(path: &Path) -> bool {
    use tokio::net::UnixStream;
    tokio::time::timeout(Duration::from_millis(100), UnixStream::connect(path))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// 세션 socket 의 `GetMetrics` 에서 dropped_bytes / attach_reconnect_total 을 뽑아 온다.
///
/// 두 필드는 `aic-session` 측 counter 이고 aicd 에는 존재하지 않는다 (R14.4, R14.5).
/// 세션 소켓이 없거나 `GetMetrics` 가 에러로 끝나면 placeholder 0 값을 돌려주고
/// 원인을 `Some(String)` 으로 반환한다.
async fn probe_session_metrics(
    session_socket: Option<&Path>,
) -> (u64, u64, Option<String>) {
    let Some(path) = session_socket else {
        return (
            0,
            0,
            Some("세션 소켓이 주어지지 않아 metric을 조회하지 못했습니다".to_string()),
        );
    };
    if !path.exists() {
        return (
            0,
            0,
            Some(format!("세션 소켓 {} 이 존재하지 않습니다", path.display())),
        );
    }
    let client = UdsClient::new(path.to_path_buf());
    match tokio::time::timeout(Duration::from_secs(2), client.get_metrics()).await {
        Ok(Ok(snap)) => (snap.dropped_bytes, snap.attach_reconnect_total, None),
        Ok(Err(e)) => (0, 0, Some(format!("GetMetrics 실패: {e}"))),
        Err(_) => (0, 0, Some("GetMetrics 2초 timeout".to_string())),
    }
}

/// `config.toml` 의 `[daemon]` 섹션만 best-effort 로 읽어 온다.
///
/// 어떤 단계에서 실패해도 `None` 으로 떨어져 env / Phase default 로만 평가되도록
/// 한다 (R12.2). `main.rs::read_daemon_config_best_effort` 와 같은 동작이지만
/// doctor 모듈 단독으로도 사용할 수 있게 이곳에 복제해 둔다 — 두 경로 모두
/// `AppConfigWithDaemon` 을 파싱하므로 동작은 동일하다.
fn read_daemon_config_best_effort() -> Option<DaemonConfig> {
    let path = ConfigManager::config_path();
    let content = std::fs::read_to_string(&path).ok()?;
    let parsed: AppConfigWithDaemon = toml::from_str(&content).ok()?;
    Some(parsed.daemon)
}

/// Central Store 섹션을 컬러 콘솔 출력한다. `print_report` 다음에 호출한다.
///
/// 출력 예:
/// ```text
/// Central Store:
///   flag        : true (source: env)
///   phase       : phase-3_4
///   attach sock : /tmp/aic-501/aicd-attach.sock (connected)
///   dropped     : 0 bytes
///   reconnects  : 0
/// ```
pub fn print_central_store_section(report: &CentralStoreReport) {
    let connected_label = if report.attach_connected {
        "\x1b[32mconnected\x1b[0m"
    } else {
        "\x1b[33mnot connected\x1b[0m"
    };
    println!();
    println!("\x1b[1mCentral Store:\x1b[0m");
    println!(
        "  flag        : {} (source: {})",
        report.flag_resolved, report.flag_source
    );
    println!("  phase       : {}", report.phase);
    println!(
        "  attach sock : {} ({})",
        report.attach_socket_path.display(),
        connected_label
    );
    match &report.session_metrics_error {
        None => {
            println!("  dropped     : {} bytes", report.dropped_bytes);
            println!("  reconnects  : {}", report.attach_reconnect_total);
        }
        Some(reason) => {
            println!(
                "  dropped     : \x1b[90mN/A\x1b[0m ({reason})"
            );
            println!("  reconnects  : \x1b[90mN/A\x1b[0m");
        }
    }
}

// ── 개별 체크 ───────────────────────────────────────────────────

fn check_provider(cfg: &AppConfig) -> CheckResult {
    let name = &cfg.llm.default_provider;
    let provider = match cfg.llm.providers.get(name) {
        Some(p) => p,
        None => {
            return CheckResult::fail(
                format!("provider '{name}'"),
                "default_provider가 [llm.providers]에 정의되지 않음",
                "`aic config` → 'LLM Provider 설정'으로 등록하세요",
            );
        }
    };

    match provider.provider_type {
        ProviderType::OpenAiCompatible | ProviderType::Groq | ProviderType::Anthropic => {
            if provider
                .api_key
                .as_ref()
                .map(|k| k.is_empty())
                .unwrap_or(true)
            {
                return CheckResult::fail(
                    format!("provider '{name}'"),
                    "API key가 비어 있음",
                    "`aic config` → 'LLM Provider 설정'에서 API key를 입력하세요",
                );
            }
            let model = provider.model.as_deref().unwrap_or("(미지정)");
            // Anthropic의 retired 모델은 404로 응답해 분석이 통째로 실패한다.
            // 사용자가 dry-run 단계에서 알 수 있도록 doctor에서 미리 경고한다.
            if matches!(provider.provider_type, ProviderType::Anthropic)
                && is_anthropic_retired_model(model)
            {
                return CheckResult::warn(
                    format!("provider '{name}'"),
                    format!(
                        "{:?} · model={model} · 이 모델은 retire되어 호출 시 HTTP 404가 \
                         발생할 수 있습니다",
                        provider.provider_type
                    ),
                    "claude-sonnet-4-6 / claude-opus-4-7 / claude-haiku-4-5-20251001 중 하나로 \
                     교체하세요 (`aic config` → 'LLM Provider 설정')",
                );
            }
            CheckResult::pass(
                format!("provider '{name}'"),
                format!("{:?} · model={model} · key=설정됨", provider.provider_type),
            )
        }
        ProviderType::CliBackend => {
            let cli_path = provider.cli_path.as_deref().unwrap_or("");
            if cli_path.is_empty() {
                return CheckResult::fail(
                    format!("provider '{name}'"),
                    "CLI Backend의 cli_path가 비어 있음",
                    "config.toml의 cli_path를 셸에서 실행 가능한 경로로 설정하세요",
                );
            }
            // 실행 가능 여부 검사
            match std::process::Command::new(cli_path)
                .arg("--version")
                .output()
            {
                Ok(out) if out.status.success() => CheckResult::pass(
                    format!("provider '{name}'"),
                    format!("CLI '{cli_path}' 실행 가능"),
                ),
                Ok(_) => CheckResult::warn(
                    format!("provider '{name}'"),
                    format!("CLI '{cli_path}' --version 실패 (다른 인자가 필요할 수 있음)"),
                    format!("`{cli_path}`을 직접 실행해 동작을 확인하세요"),
                ),
                Err(e) => CheckResult::fail(
                    format!("provider '{name}'"),
                    format!("CLI '{cli_path}' 실행 불가: {e}"),
                    "PATH에 CLI가 있는지 확인하거나 cli_path에 절대경로를 지정하세요",
                ),
            }
        }
    }
}

/// Anthropic API에서 retire되었거나 retire가 임박한 모델 ID인지 휴리스틱 판정.
///
/// 보수적 매칭 — 새 모델(`claude-sonnet-4-6`, `claude-opus-4-7`,
/// `claude-haiku-4-5-*`)에는 false. 알려진 옛 모델 prefix만 잡는다.
fn is_anthropic_retired_model(model: &str) -> bool {
    // claude-3-* 시리즈 (3, 3-5, 3-7) — Anthropic이 단계적으로 retire 중.
    // claude-2-*, claude-instant-*는 이미 retire.
    // claude-sonnet-4-20250514 는 4.6에 의해 superseded — retire 가능성 표시.
    let m = model;
    m.starts_with("claude-2")
        || m.starts_with("claude-instant")
        || m.starts_with("claude-3-")
        || m == "claude-sonnet-4-20250514"
        || m == "claude-opus-4-20250514"
}

fn check_socket_path(path: &std::path::Path) -> CheckResult {
    if path.exists() {
        CheckResult::pass("UDS 소켓 경로", format!("{} 존재", path.display()))
    } else {
        CheckResult::warn(
            "UDS 소켓 경로",
            format!("{} 없음", path.display()),
            "aic-session을 시작하면 자동 생성됩니다",
        )
    }
}

async fn check_daemon_alive(path: &std::path::Path) -> CheckResult {
    let client = UdsClient::new(path.to_path_buf());
    match tokio::time::timeout(Duration::from_secs(2), client.ping()).await {
        Ok(Ok(true)) => CheckResult::pass("aic-session 데몬", "Ping 응답 정상"),
        Ok(Ok(false)) => CheckResult::warn(
            "aic-session 데몬",
            "Ping 응답이 Pong이 아님",
            "데몬을 재시작해보세요",
        ),
        Ok(Err(_)) | Err(_) => CheckResult::warn(
            "aic-session 데몬",
            "응답 없음 — 데몬이 실행되지 않았거나 hang 상태",
            "터미널에서 `aic-session`을 실행하세요",
        ),
    }
}

/// `aicd` supervisor 진단 (Phase 1.5).
///
/// 정책:
/// - `aicd`가 떠 있으면 PASS — 등록된 세션 수를 함께 표시한다.
/// - `aicd`가 없는 상태는 FAIL이 아니라 INFO/WARN — 현재 제품은 aicd 없이도
///   정상 동작하므로(legacy multi-session path) 강한 경고를 띄우면 신규 사용자가
///   당황한다. 따라서 "선택적 supervisor — `aic daemon start`로 켜세요" WARN.
async fn check_aicd_supervisor() -> CheckResult {
    let sock = aic_common::aicd_socket_path();
    let client = UdsClient::new(sock.clone());
    match tokio::time::timeout(Duration::from_secs(1), client.ping()).await {
        Ok(Ok(true)) => match client.list_sessions().await {
            Ok(list) => CheckResult::pass(
                "aicd supervisor",
                format!("Ping 응답 정상, 등록 세션 {}개", list.len()),
            ),
            Err(_) => CheckResult::pass("aicd supervisor", "Ping 응답 정상"),
        },
        _ => CheckResult::warn(
            "aicd supervisor",
            "실행되지 않음 (선택사항 — 미설치 시 기존 멀티세션 path로 동작)",
            "백그라운드 supervisor를 쓰려면 `aic daemon start`",
        ),
    }
}

fn check_shell_hooks() -> CheckResult {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let shell_name = std::path::Path::new(&shell)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    let (rc_filename, hook_filename) = match shell_name {
        "zsh" => (".zshrc", "hooks.zsh"),
        "bash" => (".bashrc", "hooks.bash"),
        other => {
            return CheckResult::warn(
                "셸 hooks",
                format!("지원하지 않는 셸: {other}"),
                "zsh 또는 bash를 사용하세요. 그 외 셸은 셸 히스토리 폴백으로 동작합니다",
            );
        }
    };

    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => {
            return CheckResult::warn(
                "셸 hooks",
                "HOME 환경변수 없음",
                "정상 셸 환경에서 실행하세요",
            );
        }
    };

    let hook_file = home.join(".aic").join(hook_filename);
    if !hook_file.exists() {
        return CheckResult::warn(
            "셸 hooks",
            format!("hook 파일 없음: {}", hook_file.display()),
            "aic-session을 한 번 실행하면 자동 생성됩니다",
        );
    }

    let rc_path = home.join(rc_filename);
    let rc_content = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if rc_content.contains(".aic/hooks") {
        CheckResult::pass("셸 hooks", format!("{} 활성", hook_file.display()))
    } else {
        CheckResult::warn(
            "셸 hooks",
            format!("hook 파일은 있지만 {rc_filename}에 source 라인이 없음"),
            format!("`aic init {shell_name}` 으로 자동 설치하세요"),
        )
    }
}

async fn check_llm_endpoint(provider: &ProviderConfig) -> CheckResult {
    let endpoint = match &provider.endpoint {
        Some(e) => e,
        None => {
            // CliBackend 등 endpoint 없는 provider — provider 체크에서 별도 검증됨
            return CheckResult::pass("LLM endpoint", "(endpoint 없는 provider)");
        }
    };

    // 호스트 reachability만 체크 (인증 검증 X — provider 체크에서 key 존재만 확인)
    let url = match reqwest::Url::parse(endpoint) {
        Ok(u) => u,
        Err(e) => {
            return CheckResult::fail(
                "LLM endpoint",
                format!("URL 파싱 실패: {endpoint} ({e})"),
                "config.toml의 endpoint를 점검하세요",
            );
        }
    };

    let host_url = match url.host_str() {
        Some(h) => format!("{}://{}", url.scheme(), h),
        None => {
            return CheckResult::fail(
                "LLM endpoint",
                format!("호스트 누락: {endpoint}"),
                "config.toml의 endpoint를 점검하세요",
            );
        }
    };

    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return CheckResult::warn(
                "LLM endpoint",
                format!("HTTP client 생성 실패: {e}"),
                "reqwest 빌드 환경을 점검하세요",
            );
        }
    };

    match client.head(&host_url).send().await {
        Ok(resp) => CheckResult::pass(
            "LLM endpoint",
            format!("{} 응답 (HTTP {})", host_url, resp.status().as_u16()),
        ),
        Err(e) => {
            // 일부 endpoint는 HEAD를 허용하지 않음 → GET 재시도
            match client.get(&host_url).send().await {
                Ok(resp) => CheckResult::pass(
                    "LLM endpoint",
                    format!("{} 응답 (HTTP {})", host_url, resp.status().as_u16()),
                ),
                Err(_) => CheckResult::warn(
                    "LLM endpoint",
                    format!("{host_url} 도달 불가: {e}"),
                    "네트워크 연결과 endpoint URL을 확인하세요",
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_pass_constructor() {
        let r = CheckResult::pass("name", "detail");
        assert_eq!(r.status, Status::Pass);
        assert_eq!(r.name, "name");
        assert_eq!(r.detail, "detail");
        assert!(r.fix_hint.is_none());
    }

    #[test]
    fn check_result_warn_includes_fix() {
        let r = CheckResult::warn("n", "d", "fix me");
        assert_eq!(r.status, Status::Warn);
        assert_eq!(r.fix_hint.as_deref(), Some("fix me"));
    }

    #[test]
    fn check_result_fail_includes_fix() {
        let r = CheckResult::fail("n", "d", "fix me");
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.fix_hint.as_deref(), Some("fix me"));
    }

    #[test]
    fn check_provider_missing_key_returns_fail() {
        use std::collections::HashMap;
        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderConfig {
                provider_type: ProviderType::OpenAiCompatible,
                endpoint: Some("https://api.openai.com/v1/chat/completions".to_string()),
                api_key: None,
                model: Some("gpt-4o-mini".to_string()),
                cli_path: None,
                cli_args: None,
            },
        );
        let cfg = AppConfig {
            llm: aic_common::LlmConfig {
                default_provider: "openai".to_string(),
                providers,
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: aic_common::ServerConfig {
                max_buffer_lines: 500,
                socket_path: None,
                boundary_strategy: aic_common::BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
            session: aic_common::SessionConfig::default(),
        };

        let result = check_provider(&cfg);
        assert_eq!(result.status, Status::Fail);
        assert!(result.detail.contains("API key"));
    }

    #[test]
    fn check_provider_unknown_default_returns_fail() {
        use std::collections::HashMap;
        let cfg = AppConfig {
            llm: aic_common::LlmConfig {
                default_provider: "nonexistent".to_string(),
                providers: HashMap::new(),
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: aic_common::ServerConfig {
                max_buffer_lines: 500,
                socket_path: None,
                boundary_strategy: aic_common::BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
            session: aic_common::SessionConfig::default(),
        };
        let result = check_provider(&cfg);
        assert_eq!(result.status, Status::Fail);
        assert!(result.detail.contains("정의되지 않음"));
    }

    #[test]
    fn retired_anthropic_models_are_detected() {
        assert!(is_anthropic_retired_model("claude-3-5-haiku-20241022"));
        assert!(is_anthropic_retired_model("claude-3-5-sonnet-20241022"));
        assert!(is_anthropic_retired_model("claude-3-opus-20240229"));
        assert!(is_anthropic_retired_model("claude-3-7-sonnet-20250219"));
        assert!(is_anthropic_retired_model("claude-2.1"));
        assert!(is_anthropic_retired_model("claude-instant-1.2"));
        assert!(is_anthropic_retired_model("claude-sonnet-4-20250514"));
    }

    #[test]
    fn current_anthropic_models_are_not_retired() {
        assert!(!is_anthropic_retired_model("claude-sonnet-4-6"));
        assert!(!is_anthropic_retired_model("claude-opus-4-7"));
        assert!(!is_anthropic_retired_model("claude-haiku-4-5-20251001"));
    }

    #[test]
    fn check_provider_warns_on_retired_anthropic_model() {
        use std::collections::HashMap;
        let mut providers = HashMap::new();
        providers.insert(
            "anthropic".to_string(),
            ProviderConfig {
                provider_type: ProviderType::Anthropic,
                endpoint: Some("https://api.anthropic.com/v1/messages".to_string()),
                api_key: Some("sk-ant-xxx".to_string()),
                model: Some("claude-3-5-haiku-20241022".to_string()),
                cli_path: None,
                cli_args: None,
            },
        );
        let cfg = AppConfig {
            llm: aic_common::LlmConfig {
                default_provider: "anthropic".to_string(),
                providers,
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: aic_common::ServerConfig {
                max_buffer_lines: 500,
                socket_path: None,
                boundary_strategy: aic_common::BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
            session: aic_common::SessionConfig::default(),
        };
        let result = check_provider(&cfg);
        assert_eq!(result.status, Status::Warn);
        assert!(result.detail.contains("retire"));
        let hint = result.fix_hint.unwrap();
        assert!(hint.contains("claude-sonnet-4-6"));
    }

    #[test]
    fn check_socket_path_missing_returns_warn() {
        let cfg = AppConfig {
            llm: aic_common::LlmConfig {
                default_provider: "x".to_string(),
                providers: Default::default(),
                lang: "korean".to_string(),
                connect_timeout_secs: 5,
                request_timeout_secs: 30,
            },
            server: aic_common::ServerConfig {
                max_buffer_lines: 500,
                socket_path: Some(PathBuf::from("/tmp/nonexistent-aic-socket-xyz.sock")),
                boundary_strategy: aic_common::BoundaryStrategyConfig {
                    method: "prompt_marker".to_string(),
                    idle_threshold_ms: None,
                },
            },
            session: aic_common::SessionConfig::default(),
        };
        let path = cfg
            .server
            .socket_path
            .clone()
            .unwrap_or_else(ConfigManager::socket_path);
        let result = check_socket_path(&path);
        assert_eq!(result.status, Status::Warn);
    }

    // ── Central Store 섹션 (R14.6) ────────────────────────────

    fn env_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[tokio::test]
    async fn probe_central_store_reads_flag_from_env() {
        // env=1 이면 flag_resolved=true, flag_source="env" 이어야 한다.
        let env = env_with(&[("AIC_CENTRAL_STORE", "1")]);
        let cfg = DaemonConfig {
            central_store: Some(false),
        };
        let report = probe_central_store(&env, Some(&cfg), None).await;
        assert!(report.flag_resolved);
        assert_eq!(report.flag_source, "env");
    }

    #[tokio::test]
    async fn probe_central_store_reads_flag_from_config_when_env_absent() {
        let env: HashMap<String, String> = HashMap::new();
        let cfg = DaemonConfig {
            central_store: Some(true),
        };
        let report = probe_central_store(&env, Some(&cfg), None).await;
        assert!(report.flag_resolved);
        assert_eq!(report.flag_source, "config");
    }

    #[tokio::test]
    async fn probe_central_store_falls_back_to_phase_default() {
        // env 비고 config 도 없으면 Phase default 가 적용되고 source="phase-default".
        let env: HashMap<String, String> = HashMap::new();
        let report = probe_central_store(&env, None, None).await;
        assert_eq!(
            report.flag_resolved,
            current_phase().default_central_store_flag()
        );
        assert_eq!(report.flag_source, "phase-default");
    }

    #[tokio::test]
    async fn probe_central_store_reports_phase_label() {
        let env: HashMap<String, String> = HashMap::new();
        let report = probe_central_store(&env, None, None).await;
        assert_eq!(report.phase, current_phase().as_str());
        assert!(report.phase.starts_with("phase-3_"));
    }

    #[tokio::test]
    async fn probe_central_store_uses_common_attach_socket_path() {
        // attach_socket_path 는 항상 aic_common::aicd_attach_socket_path() 와 일치.
        let env: HashMap<String, String> = HashMap::new();
        let report = probe_central_store(&env, None, None).await;
        assert_eq!(
            report.attach_socket_path,
            aic_common::aicd_attach_socket_path()
        );
    }

    #[tokio::test]
    async fn probe_central_store_reports_connected_when_socket_listens() {
        // 실제 UnixListener 를 bind 해 두면 probe_attach_socket 이 true 여야 한다.
        // 테스트는 임의 경로로 바인드한 뒤 `probe_attach_socket` 을 직접 호출해
        // 공용 `aicd_attach_socket_path()` 를 건드리지 않는다 — 사용자 환경의 실제
        // aicd 유무와 독립적이어야 하기 때문이다.
        let tempdir = tempfile::tempdir().unwrap();
        let sock = tempdir.path().join("attach-probe.sock");
        let _listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let ok = probe_attach_socket(&sock).await;
        assert!(ok, "listener 가 떠 있으면 connect 에 성공해야 한다");
    }

    #[tokio::test]
    async fn probe_central_store_reports_not_connected_when_absent() {
        // 없는 경로면 probe_attach_socket 은 false.
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("no-such-attach.sock");
        let ok = probe_attach_socket(&missing).await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn probe_session_metrics_returns_error_when_session_missing() {
        // session_socket=None → placeholder 0 + 에러 메시지.
        let (dropped, reconnects, err) = probe_session_metrics(None).await;
        assert_eq!(dropped, 0);
        assert_eq!(reconnects, 0);
        assert!(err.is_some());
    }

    #[tokio::test]
    async fn probe_session_metrics_returns_error_when_socket_file_missing() {
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("session-missing.sock");
        let (dropped, reconnects, err) = probe_session_metrics(Some(&missing)).await;
        assert_eq!(dropped, 0);
        assert_eq!(reconnects, 0);
        let reason = err.expect("Some(String) 이어야 한다");
        assert!(
            reason.contains("존재하지 않습니다"),
            "reason={reason}"
        );
    }

    #[tokio::test]
    async fn probe_session_metrics_reads_snapshot_fields_from_server() {
        // mock UDS 서버가 GetMetrics 에 대해 dropped_bytes/attach_reconnect_total 이 채워진
        // MetricsSnapshot 을 돌려주면, probe_session_metrics 는 그 값을 그대로 돌려준다.
        use aic_common::{encode_frame, IpcRequest, IpcResponse, MetricsSnapshot};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let tempdir = tempfile::tempdir().unwrap();
        let sock = tempdir.path().join("session-metrics.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let snap = MetricsSnapshot {
            dropped_bytes: 4096,
            attach_reconnect_total: 3,
            ..Default::default()
        };
        let snap_resp = snap.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // 요청 수신 (내용은 확인만)
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let plen = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; plen];
            stream.read_exact(&mut payload).await.unwrap();
            let req: IpcRequest = serde_json::from_slice(&payload).unwrap();
            assert!(matches!(req, IpcRequest::GetMetrics));

            // 응답 송신
            let resp = IpcResponse::Metrics(snap_resp);
            let body = serde_json::to_vec(&resp).unwrap();
            let frame = encode_frame(&body);
            stream.write_all(&frame).await.unwrap();
        });

        let (dropped, reconnects, err) = probe_session_metrics(Some(&sock)).await;
        assert_eq!(dropped, 4096);
        assert_eq!(reconnects, 3);
        assert!(err.is_none(), "err={err:?}");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn probe_central_store_merges_metric_error_without_panic() {
        // 존재하지 않는 세션 소켓을 넘겨도 전체 리포트는 정상 생성되고
        // session_metrics_error 만 Some 으로 채워진다.
        let env: HashMap<String, String> = HashMap::new();
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("not-a-socket.sock");
        let report = probe_central_store(&env, None, Some(&missing)).await;
        assert_eq!(report.dropped_bytes, 0);
        assert_eq!(report.attach_reconnect_total, 0);
        assert!(report.session_metrics_error.is_some());
    }
}
