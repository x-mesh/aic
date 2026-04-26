//! LLM 호출 대기 중 stderr에 비동기 spinner를 표시한다.
//! isatty(stderr) 환경에서만 동작, 비-TTY는 no-op (CI/파이프 회귀 방지).

use std::io::{IsTerminal, Write};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// LLM 호출용 spinner. `start`로 시작, `stop`으로 종료 + 라인 정리.
pub struct Spinner {
    handle: Option<JoinHandle<()>>,
    stop_tx: Option<mpsc::Sender<()>>,
}

impl Spinner {
    /// stderr이 TTY면 spinner를 띄우고, 아니면 no-op 인스턴스를 반환한다.
    pub fn start(label: String) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self {
                handle: None,
                stop_tx: None,
            };
        }
        let (tx, mut rx) = mpsc::channel::<()>(1);
        let handle = tokio::spawn(async move {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let start = std::time::Instant::now();
            let mut idx = 0usize;
            loop {
                let elapsed = start.elapsed().as_secs_f32();
                eprint!(
                    "\r\x1b[90m{frame} {label} ({elapsed:.1}s)\x1b[0m\x1b[K",
                    frame = frames[idx % frames.len()]
                );
                let _ = std::io::stderr().flush();
                idx += 1;
                tokio::select! {
                    _ = rx.recv() => break,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
            // 종료 시 라인 정리
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        });
        Self {
            handle: Some(handle),
            stop_tx: Some(tx),
        }
    }

    /// spinner를 멈추고 background task가 종료될 때까지 기다린다.
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(()).await;
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_op_in_non_tty_environment() {
        // 테스트 환경에서는 stderr이 TTY 아님 → spinner는 no-op
        let s = Spinner::start("test".to_string());
        // start/stop이 panic 없이 완료되는지만 검증
        s.stop().await;
    }

    #[tokio::test]
    async fn multiple_start_stop_cycles() {
        for i in 0..3 {
            let s = Spinner::start(format!("test-{i}"));
            s.stop().await;
        }
    }
}
