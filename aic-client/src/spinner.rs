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
    /// 기본 dim grey 색(`90`)으로 표시한다(하위호환).
    pub fn start(label: String) -> Self {
        Self::start_styled(label, "90")
    }

    /// [`start`]에 색 지정을 더한 변형. `color_code`가 ANSI SGR 코드면 그 색으로,
    /// **빈 문자열이면 색 없이**(plain) 표시한다(NO_COLOR 정책: 호출부가 `""` 전달).
    /// stderr 비-TTY면 no-op. 성공/실패/timeout 무관 `stop()`에서 라인을 정리한다.
    pub fn start_styled(label: String, color_code: &str) -> Self {
        Self::start_with_metrics(label, color_code, false)
    }

    /// [`start_styled`]에 시스템 지표(load/cpu/mem/disk-i/o)를 spinner 라인 뒤에 덧붙이는 변형.
    /// `with_metrics`면 spinner 생애 동안 `SysSampler`를 재사용(disk i/o delta 정확)하며 **2초마다**
    /// 지표를 재샘플한다(애니메이션은 100ms). LLM 호출/대기 구간은 `read_line` 밖이라 reedline과
    /// 충돌하지 않고, spinner가 화면(한 줄)을 단독 소유하므로 status bar 갱신과도 충돌이 없다.
    pub fn start_with_metrics(label: String, color_code: &str, with_metrics: bool) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self {
                handle: None,
                stop_tx: None,
            };
        }
        let color_code = color_code.to_string();
        let (tx, mut rx) = mpsc::channel::<()>(1);
        let handle = tokio::spawn(async move {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            // 색이 있으면 ANSI로 감싸고, 없으면 plain.
            let (pre, post) = if color_code.is_empty() {
                (String::new(), String::new())
            } else {
                (format!("\x1b[{color_code}m"), "\x1b[0m".to_string())
            };
            let start = std::time::Instant::now();
            let mut idx = 0usize;
            // 시스템 지표 샘플러(옵션) — disk i/o delta를 위해 spinner 생애 동안 재사용.
            let mut sampler = with_metrics.then(crate::agent::sys_sampler::SysSampler::new);
            let mut status = String::new();
            let mut last_sample = std::time::Instant::now();
            loop {
                // 지표는 2초마다(또는 최초) 갱신, 애니메이션은 매 tick.
                if let Some(s) = sampler.as_mut() {
                    if status.is_empty() || last_sample.elapsed().as_secs() >= 2 {
                        status = format!(" · {}", s.sample().status_line());
                        last_sample = std::time::Instant::now();
                    }
                }
                let elapsed = start.elapsed().as_secs_f32();
                eprint!(
                    "\r{pre}{frame} {label} ({elapsed:.1}s){status}{post}\x1b[K",
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
