//! `aic doctor` — 통합 진단 서브커맨드.
//!
//! 다음 항목을 순서대로 점검하고 PASS/WARN/FAIL 리포트를 출력한다.
//! 1. config 파일 파싱
//! 2. default provider 설정 유효성 (API key / cli_path / endpoint)
//! 3. UDS 소켓 경로 존재
//! 4. aic-session 데몬 응답 (Ping)
//! 5. 셸 hook 설치 여부 (~/.aic/hooks.* + ~/.zshrc·.bashrc source 라인)
//! 6. LLM endpoint reachability (HEAD 요청, 2s timeout)

use crate::config::ConfigManager;
use crate::uds_client::UdsClient;
use aic_common::{AppConfig, ProviderConfig, ProviderType};
use serde::Serialize;
use std::path::PathBuf;
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
        ProviderType::OpenAiCompatible | ProviderType::Anthropic => {
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
        };
        let result = check_provider(&cfg);
        assert_eq!(result.status, Status::Fail);
        assert!(result.detail.contains("정의되지 않음"));
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
        };
        let path = cfg
            .server
            .socket_path
            .clone()
            .unwrap_or_else(ConfigManager::socket_path);
        let result = check_socket_path(&path);
        assert_eq!(result.status, Status::Warn);
    }
}
