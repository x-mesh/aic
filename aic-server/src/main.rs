//! aic-session: PTY 셸 래퍼 데몬.
//!
//! 사용자의 기본 셸을 PTY 자식 프로세스로 실행하고, 입출력을 투명하게 중계하면서
//! 출력 스트림을 전처리하여 RingBuffer에 저장한다.
//! UDS를 통해 AIC_Client의 데이터 요청을 처리한다.
//!
//! Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 10.1

use aic_server::pty_manager::HookPolicy;
use aic_server::session_runtime::{self, SessionRuntimeConfig};
use aic_server::telemetry;
use clap::Parser;

/// PTY 셸 래퍼 데몬. 사용자의 기본 셸을 PTY로 실행하고, 출력 스트림을 RingBuffer에
/// 저장하여 UDS로 클라이언트(`aic`)에 제공한다.
#[derive(Parser, Debug)]
#[command(
    name = "aic-session",
    version,
    about = "PTY 셸 래퍼 데몬",
    long_about = None,
)]
struct Cli {
    /// 사용할 셸 경로 override (기본: $SHELL → /bin/sh)
    #[arg(long, value_name = "PATH")]
    shell: Option<String>,
    /// 자동 hook 설정 skip — ~/.aic/hooks.{shell} 갱신 안 함
    #[arg(long)]
    no_hook: bool,
    /// 새 session_id를 생성해 stdout에 출력하고 종료 (PTY 시작 안 함)
    #[arg(long)]
    print_session_id: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // --print-session-id: 새 ID 생성만 하고 종료 (PTY 시작 X). 외부 스크립트가 미리 ID를 잡을 때 사용.
    if cli.print_session_id {
        println!("{}", aic_common::generate_session_id());
        return Ok(());
    }

    // --shell <path>: $SHELL env override (PtyManager가 SHELL env로 셸을 spawn하므로).
    if let Some(ref shell) = cli.shell {
        // SAFETY: PtyManager spawn 전의 단발성 env override다.
        unsafe {
            std::env::set_var("SHELL", shell);
        }
    }

    let hook_policy = if cli.no_hook {
        HookPolicy::Disabled
    } else {
        HookPolicy::AutoInstall
    };

    // telemetry 초기화 (stderr + ~/.local/state/aic/server.log JSONL daily rotate, max 7일)
    let telemetry_guard = telemetry::init().ok();
    aic_server::metrics::init();

    let result = session_runtime::run(SessionRuntimeConfig { hook_policy }).await;

    // run() 의 graceful 정리는 끝났지만 일부 `spawn_blocking` task 의 OS 스레드가 syscall 에
    // 묶인 채 남는다. abort 는 실행 중인 blocking task 를 멈추지 못하기 때문이다.
    //   - stdin_handle(`stdin.read()`): fd 0 가 EOF 를 받지 않아 **모든 trigger 에서** 영구
    //     블록되는 공통 주범.
    //   - wait_handle(`child.wait()`)·output_handle(`reader.read()`): trigger 의존적이다.
    //     pty-eof/shell-exit 에서는 셸이 이미 pty 를 닫아 곧 종료되지만, SIGTERM/SIGINT 로
    //     `request_child_shutdown` 의 SIGHUP 을 셸이 무시하면 함께 블록될 수 있다.
    // 이 상태로 main 을 반환하면 `#[tokio::main]` 의 Runtime::drop 이 blocking 풀 스레드
    // 완료를 무한 대기하여 프로세스가 hang 한다(소켓은 삭제됐는데 종료가 안 됨). telemetry 를
    // flush 한 뒤 명시적으로 exit 하여 runtime drop 의 blocking-thread join 을 우회한다.
    drop(telemetry_guard);
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("aic-session 종료 오류: {e:#}");
            std::process::exit(1);
        }
    }
}
