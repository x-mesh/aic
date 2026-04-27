//! CLI Backend mock 통합 테스트
//!
//! mock CLI 스크립트를 생성하여 kiro-cli/claude-cli 연동을 검증한다.
//!
//! Requirements: 9.1, 9.2, 9.3

use aic_common::{AicError, LlmConfig, ProviderConfig, ProviderType};
use std::collections::HashMap;
use std::io::Write;

fn make_cli_config(cli_path: &str) -> LlmConfig {
    LlmConfig {
        default_provider: "cli".to_string(),
        providers: HashMap::from([(
            "cli".to_string(),
            ProviderConfig {
                provider_type: ProviderType::CliBackend,
                endpoint: None,
                api_key: None,
                model: None,
                cli_path: Some(cli_path.to_string()),
                cli_args: None,
            },
        )]),
        lang: "korean".to_string(),
        connect_timeout_secs: 5,
        request_timeout_secs: 30,
    }
}

/// 입력을 그대로 echo하는 mock CLI 스크립트를 생성한다.
fn create_echo_script(dir: &std::path::Path) -> std::path::PathBuf {
    let script_path = dir.join("mock-cli");
    let mut file = std::fs::File::create(&script_path).unwrap();
    writeln!(file, "#!/bin/sh").unwrap();
    writeln!(file, "echo \"$1\"").unwrap();
    drop(file);

    // 실행 권한 부여
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    script_path
}

/// 에러를 반환하는 mock CLI 스크립트를 생성한다.
fn create_failing_script(dir: &std::path::Path) -> std::path::PathBuf {
    let script_path = dir.join("mock-cli-fail");
    let mut file = std::fs::File::create(&script_path).unwrap();
    writeln!(file, "#!/bin/sh").unwrap();
    writeln!(file, "echo 'something went wrong' >&2").unwrap();
    writeln!(file, "exit 1").unwrap();
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    script_path
}

#[tokio::test]
async fn cli_backend_echo_returns_input() {
    let dir = tempfile::tempdir().unwrap();
    let script = create_echo_script(dir.path());

    let config = make_cli_config(script.to_str().unwrap());
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let result = dispatcher.send("hello world").await.unwrap();
    assert!(
        result.contains("hello world"),
        "echo 스크립트가 입력을 반환해야 합니다. 실제: '{}'",
        result.trim()
    );
}

#[tokio::test]
async fn cli_backend_nonexistent_returns_cli_not_found() {
    let config = make_cli_config("/nonexistent/path/to/fake-cli-xyz-12345");
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let err = dispatcher.send("test").await.unwrap_err();
    assert!(
        matches!(err, AicError::CliNotFound { .. }),
        "CliNotFound를 기대했지만 {:?}를 받았습니다",
        err
    );
}

#[tokio::test]
async fn cli_backend_failing_script_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let script = create_failing_script(dir.path());

    let config = make_cli_config(script.to_str().unwrap());
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let err = dispatcher.send("test").await.unwrap_err();
    assert!(
        matches!(err, AicError::LlmApiError { .. }),
        "LlmApiError를 기대했지만 {:?}를 받았습니다",
        err
    );
}

#[tokio::test]
async fn cli_backend_passes_prompt_as_argument() {
    let dir = tempfile::tempdir().unwrap();
    let script = create_echo_script(dir.path());

    let config = make_cli_config(script.to_str().unwrap());
    let dispatcher = aic_client::llm_dispatcher::LlmDispatcher::from_config(config);

    let prompt = "Why did cargo build fail with E0308?";
    let result = dispatcher.send(prompt).await.unwrap();
    assert!(
        result.contains(prompt),
        "프롬프트가 CLI 인자로 전달되어야 합니다. 실제: '{}'",
        result.trim()
    );
}
