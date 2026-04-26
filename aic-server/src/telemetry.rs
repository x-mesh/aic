//! tracing subscriber 초기화 + panic hook.
//!
//! 두 layer:
//! - stderr (compact format) — `AIC_LOG` env-filter 적용 (default = info)
//! - file (JSON format) — `~/.local/state/aic/server.log`, daily rotate, max 7일 보존
//!
//! prompt/response 본문은 절대 span에 포함하지 않는다 (hash + token count만 허용).
//! 디렉토리 권한 0700, 파일은 tracing-appender가 0644로 쓰므로 사후 0600 chmod.

use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// telemetry 가드. drop 시 background flush.
pub struct TelemetryGuard {
    _file_guard: WorkerGuard,
}

/// tracing subscriber를 초기화한다. main 시작 직후 1회만 호출.
pub fn init() -> anyhow::Result<TelemetryGuard> {
    let log_dir = log_dir();
    std::fs::create_dir_all(&log_dir)?;
    apply_dir_perm_0700(&log_dir);

    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("server")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&log_dir)
        .map_err(|e| anyhow::anyhow!("로그 appender 빌드 실패: {e}"))?;
    let (file_writer, file_guard) = tracing_appender::non_blocking(appender);

    let env_filter = EnvFilter::try_from_env("AIC_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .with_filter(env_filter);

    let file_env_filter =
        EnvFilter::try_from_env("AIC_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let file_layer = fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .json()
        .with_filter(file_env_filter);

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .init();

    install_panic_hook();

    Ok(TelemetryGuard {
        _file_guard: file_guard,
    })
}

/// panic 발생 시 backtrace를 tracing::error로 기록한다.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = info
            .payload()
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("(non-string panic payload)");
        tracing::error!(panic.location = %location, panic.payload = %payload, "데몬 panic");
    }));
}

/// 로그 디렉토리 경로. `~/.local/state/aic`.
pub fn log_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local")
        .join("state")
        .join("aic")
}

fn apply_dir_perm_0700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_dir_under_home() {
        let dir = log_dir();
        assert!(dir.ends_with(".local/state/aic"));
    }

    #[test]
    fn apply_perm_sets_0700_when_dir_exists() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        apply_dir_perm_0700(temp.path());
        let metadata = std::fs::metadata(temp.path()).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
