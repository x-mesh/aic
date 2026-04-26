use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, ExitStatus, MasterPty, PtySize};

use crate::boundary_detector::generate_shell_hooks;

/// PTY 생성, 셸 프로세스 실행, I/O 중계를 담당한다.
pub struct PtyManager {
    master: Box<dyn MasterPty + Send>,
    /// 자식 프로세스 핸들. `take_child()`로 분리되면 None.
    /// 분리 후에는 PtyManager가 mutex 안에 있어도 wait()를 lock 밖에서 호출 가능.
    child: Option<Box<dyn Child + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    /// 훅 스크립트 임시 파일 (폴백용, 셸 종료 시까지 유지)
    hook_file: Option<tempfile::NamedTempFile>,
    /// 셸 이름 (zsh, bash 등)
    shell_name: String,
}

/// 훅 설정 상태
pub enum HookStatus {
    /// 사용자가 이미 ~/.aic/hooks.{shell}을 설정함
    Configured,
    /// 설정 안 됨, 폴백 스크립트 경로 제공
    NeedsSetup { fallback_path: PathBuf },
    /// 지원하지 않는 셸
    Unsupported,
}

impl PtyManager {
    /// 사용자의 기본 셸($SHELL)을 PTY 자식 프로세스로 실행한다.
    /// $SHELL 환경변수가 없으면 "/bin/sh"를 기본값으로 사용한다.
    /// `session_id`는 PTY 셸에 `AIC_SESSION_ID` 환경변수로 전파된다.
    pub fn spawn_shell(rows: u16, cols: u16, session_id: &str) -> Result<Self> {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let shell_name = std::path::Path::new(&shell)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("PTY pair 생성 실패")?;

        let mut cmd = CommandBuilder::new(&shell);

        // aic-session 안에서 실행 중임을 표시 (aic 클라이언트가 서버 사용 여부 판별)
        cmd.env("AIC_SESSION", "1");
        // 세션 ID를 PTY 셸에 전파 (클라이언트가 올바른 세션 소켓에 연결하기 위해)
        cmd.env("AIC_SESSION_ID", session_id);

        // 현재 작업 디렉토리를 PTY 셸에 전달
        if let Ok(cwd) = std::env::current_dir() {
            cmd.cwd(cwd);
        }

        // locale 환경변수 보장 (한글 등 유니코드 입출력)
        if std::env::var("LANG").is_err() {
            cmd.env("LANG", "en_US.UTF-8");
        }
        if std::env::var("LC_CTYPE").is_err() {
            cmd.env("LC_CTYPE", "UTF-8");
        }

        // ~/.aic/ 디렉토리에 훅 스크립트 생성 (없으면)
        let _ = ensure_hook_files();

        // 폴백용 임시 파일 생성
        let hooks = generate_shell_hooks(&shell_name);
        let hook_file = if !hooks.is_empty() {
            let mut file =
                tempfile::NamedTempFile::new().context("훅 스크립트 임시 파일 생성 실패")?;
            file.write_all(hooks.as_bytes())
                .context("훅 스크립트 쓰기 실패")?;
            file.flush()?;
            Some(file)
        } else {
            None
        };

        let child = pair
            .slave
            .spawn_command(cmd)
            .context("셸 프로세스 실행 실패")?;

        let writer = pair.master.take_writer().context("PTY writer 획득 실패")?;

        Ok(Self {
            master: pair.master,
            child: Some(child),
            writer: Some(writer),
            hook_file,
            shell_name,
        })
    }

    /// 자식 프로세스 핸들을 분리하여 반환한다. mutex 밖에서 `wait()`을 호출하기 위해 사용.
    /// 한 번 호출되면 이후에는 None을 반환한다.
    pub fn take_child(&mut self) -> Option<Box<dyn Child + Send>> {
        self.child.take()
    }

    /// 훅 설정 상태를 확인한다.
    pub fn check_hook_status(&self) -> HookStatus {
        let hooks = generate_shell_hooks(&self.shell_name);
        if hooks.is_empty() {
            return HookStatus::Unsupported;
        }

        // 사용자의 rc 파일에서 aic 훅이 설정되어 있는지 확인
        if is_hook_configured(&self.shell_name) {
            return HookStatus::Configured;
        }

        // 폴백 경로 반환
        match &self.hook_file {
            Some(f) => HookStatus::NeedsSetup {
                fallback_path: f.path().to_path_buf(),
            },
            None => HookStatus::Unsupported,
        }
    }

    /// 셸 이름을 반환한다.
    pub fn shell_name(&self) -> &str {
        &self.shell_name
    }

    /// PTY master에서 출력 읽기용 reader를 반환한다.
    /// 내부적으로 master의 reader를 take하므로 한 번만 호출할 수 있다.
    pub fn take_reader(&mut self) -> Result<Box<dyn Read + Send>> {
        self.master
            .try_clone_reader()
            .context("PTY reader 획득 실패")
    }

    /// PTY 터미널 크기를 변경한다 (SIGWINCH 처리).
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("PTY 크기 변경 실패")
    }

    /// 사용자 입력을 PTY stdin으로 전달한다.
    pub fn write_input(&mut self, data: &[u8]) -> Result<()> {
        let writer = self.writer.as_mut().context("PTY writer가 이미 분리됨")?;
        writer.write_all(data).context("PTY 입력 쓰기 실패")?;
        writer.flush().context("PTY 입력 flush 실패")?;
        Ok(())
    }

    /// PTY writer를 분리하여 반환한다. stdin relay 태스크에서 직접 사용.
    pub fn take_writer(&mut self) -> Result<Box<dyn Write + Send>> {
        self.writer.take().context("PTY writer가 이미 분리됨")
    }

    /// 자식 프로세스 종료를 대기하고 ExitStatus를 반환한다.
    ///
    /// 주의: 이 메서드는 `child`가 분리되어 있지 않은 경우에만 동작하며, 호출하는 동안
    /// `&mut self`를 점유한다. 따라서 `Mutex<PtyManager>` 패턴에서는 lock을 영구 점유한다.
    /// 데드락을 피하려면 호출 전에 `take_child()`로 분리하고 락 밖에서 `wait()`를 호출하라.
    pub fn wait_for_exit(&mut self) -> Result<Option<ExitStatus>> {
        let mut child = self
            .child
            .take()
            .context("자식 프로세스가 이미 take 되었거나 존재하지 않음")?;
        let status = child.wait().context("자식 프로세스 종료 대기 실패")?;
        Ok(Some(status))
    }
}

// ── 훅 파일 관리 유틸리티 ──────────────────────────────────────

/// ~/.aic/ 디렉토리에 훅 스크립트 파일들을 생성한다.
/// 항상 최신 버전으로 덮어쓴다.
fn ensure_hook_files() -> Result<()> {
    let aic_dir = get_aic_dir()?;
    std::fs::create_dir_all(&aic_dir).context("~/.aic 디렉토리 생성 실패")?;

    // zsh 훅 (항상 최신으로 갱신)
    let zsh_hook_path = aic_dir.join("hooks.zsh");
    let hooks = generate_shell_hooks("zsh");
    std::fs::write(&zsh_hook_path, hooks).context("hooks.zsh 생성 실패")?;

    // bash 훅 (항상 최신으로 갱신)
    let bash_hook_path = aic_dir.join("hooks.bash");
    let hooks = generate_shell_hooks("bash");
    std::fs::write(&bash_hook_path, hooks).context("hooks.bash 생성 실패")?;

    Ok(())
}

/// ~/.aic 디렉토리 경로를 반환한다.
fn get_aic_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME 환경변수가 설정되지 않음")?;
    Ok(PathBuf::from(home).join(".aic"))
}

/// 사용자의 rc 파일에서 aic 훅이 설정되어 있는지 확인한다.
fn is_hook_configured(shell_name: &str) -> bool {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };

    let rc_path = match shell_name {
        "zsh" => PathBuf::from(&home).join(".zshrc"),
        "bash" => PathBuf::from(&home).join(".bashrc"),
        _ => return false,
    };

    if let Ok(content) = std::fs::read_to_string(&rc_path) {
        // ~/.aic/hooks 또는 .aic/hooks가 포함되어 있는지 확인
        content.contains(".aic/hooks")
    } else {
        false
    }
}

/// 훅 설정 안내 메시지를 반환한다.
pub fn get_hook_setup_message(shell_name: &str) -> String {
    let rc_file = match shell_name {
        "zsh" => "~/.zshrc",
        "bash" => "~/.bashrc",
        _ => return String::new(),
    };

    let hook_file = match shell_name {
        "zsh" => "~/.aic/hooks.zsh",
        "bash" => "~/.aic/hooks.bash",
        _ => return String::new(),
    };

    format!(
        "\n💡 더 나은 경험을 위해 {}에 다음을 추가하세요:\n   source {}\n",
        rc_file, hook_file
    )
}
