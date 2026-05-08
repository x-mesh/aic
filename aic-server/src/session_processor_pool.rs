//! `SessionProcessorPool` — per-session OutputProcessor + CommandBoundaryDetector.
//!
//! aicd 의 Attach_UDS 는 한 연결 = 한 session_id 로 바인드된다. 각 연결은
//! 이 pool 에서 해당 세션용 `SessionProcessor` (OutputProcessor +
//! CommandBoundaryDetector) 인스턴스를 **독립적으로** 소유한다.
//!
//! 투입된 raw PTY bytes 는 `session_runtime::output_handle` 의 루프와 동일한
//! 순서로 처리된다:
//!   1. `OutputProcessor::process(bytes)` → `ProcessedOutput`
//!   2. `osc133_markers` 각각을 `detector.feed_line(marker)`
//!   3. `clean_text.lines()` 각각을 `detector.feed_line(line)`
//!   4. detector 가 완성한 `CommandRecord` 를 모두 모아 반환
//!
//! 반환된 record 의 `capture_mode` 는 `CaptureMode::Pty` 로 덮어써진다
//! (detector 는 `CaptureMode` 를 명시적으로 설정하지 않음).
//!
//! Requirements: R5.9, R5.10, R11.3, R11.4

use std::collections::HashMap;
use std::sync::Arc;

use aic_common::{CaptureMode, CommandRecord};
use tokio::sync::{Mutex, RwLock};

use crate::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
use crate::output_processor::OutputProcessor;

/// `AttachOpen` 시점에 반환될 수 있는 에러.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttachOpenError {
    /// 같은 session_id 에 대한 두 번째 `AttachOpen` 요청. 멀티플렉싱 금지.
    #[error("attach 연결이 이미 열려 있습니다: {0}")]
    AlreadyOpen(String),
}

/// 세션 하나당 유지되는 처리기 세트.
///
/// 이 구조체는 attach 연결 task 가 `Arc<Mutex<...>>` 로 단독 소유하므로
/// 내부에서 별도 동기화가 필요하지 않다.
pub struct SessionProcessor {
    pub processor: OutputProcessor,
    pub detector: CommandBoundaryDetector,
}

impl SessionProcessor {
    fn new() -> Self {
        Self {
            processor: OutputProcessor::new(),
            // session_runtime 의 기본 전략과 동일.
            detector: CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
                marker_sequence: "osc133".to_string(),
            }),
        }
    }
}

/// 세션 ID → SessionProcessor 를 보관하는 pool.
///
/// - `open`: 해당 세션용 신규 instance 를 등록. 이미 존재하면 `AlreadyOpen`.
/// - `feed`: 해당 세션의 instance 를 잠그고 bytes 를 처리. 열린 적 없는
///   session_id 또는 `close` 이후 session_id 에 대한 `feed` 는 빈 `Vec` 를 반환.
/// - `close`: HashMap 에서 제거해 state 를 drop (R11.4).
#[derive(Clone, Default)]
pub struct SessionProcessorPool {
    active: Arc<RwLock<HashMap<String, Arc<Mutex<SessionProcessor>>>>>,
}

impl SessionProcessorPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// 해당 session_id 에 대한 processor 를 등록. 이미 존재하면 `AlreadyOpen`.
    pub async fn open(&self, session_id: &str) -> Result<(), AttachOpenError> {
        let mut guard = self.active.write().await;
        if guard.contains_key(session_id) {
            return Err(AttachOpenError::AlreadyOpen(session_id.to_string()));
        }
        guard.insert(
            session_id.to_string(),
            Arc::new(Mutex::new(SessionProcessor::new())),
        );
        Ok(())
    }

    /// 해당 세션에 raw bytes 를 공급하고 완성된 `CommandRecord` 목록을 반환한다.
    ///
    /// 처리 순서는 `session_runtime::output_handle` 루프와 동일하다:
    ///   1. `processor.process(bytes)` → `ProcessedOutput`
    ///   2. `osc133_markers` 각각 `feed_line`
    ///   3. `clean_text.lines()` 각각 `feed_line`
    ///
    /// 반환 record 의 `capture_mode` 는 `CaptureMode::Pty` 로 명시 설정된다.
    pub async fn feed(&self, session_id: &str, bytes: &[u8]) -> Vec<CommandRecord> {
        // 대부분 경우 존재하는 세션을 잠그므로 read lock 으로 먼저 조회.
        let entry = {
            let guard = self.active.read().await;
            guard.get(session_id).cloned()
        };
        let Some(entry) = entry else {
            return Vec::new();
        };

        let mut state = entry.lock().await;
        let output = state.processor.process(bytes);

        let mut records: Vec<CommandRecord> = Vec::new();

        // (1) OSC 133 마커를 먼저 feed — prompt 경계/exit code/command 텍스트를 포함.
        for marker in &output.osc133_markers {
            if let Some(mut record) = state.detector.feed_line(marker) {
                record.capture_mode = CaptureMode::Pty;
                records.push(record);
            }
        }

        // (2) ANSI-stripped clean_text 의 라인들도 동일하게 feed.
        if let Some(ref text) = output.clean_text {
            for line in text.lines() {
                if let Some(mut record) = state.detector.feed_line(line) {
                    record.capture_mode = CaptureMode::Pty;
                    records.push(record);
                }
            }
        }

        records
    }

    /// 해당 session_id 의 SessionProcessor 를 drop.
    /// 이미 없어도 no-op.
    pub async fn close(&self, session_id: &str) {
        let mut guard = self.active.write().await;
        guard.remove(session_id);
    }

    /// 현재 활성화된 attach 세션 수 (R14.2 의 `attach_connections` 계산 보조용).
    #[allow(dead_code)]
    pub async fn active_len(&self) -> usize {
        self.active.read().await.len()
    }
}

// ── 테스트 ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary_detector::{BoundaryStrategy, CommandBoundaryDetector};
    use crate::output_processor::OutputProcessor;

    /// `SessionProcessorPool::feed` 와 동일한 처리 로직을 직접 조합한 참조 구현.
    /// shadow test 의 **전초 단계** 로, Pool 이 OutputProcessor + BoundaryDetector
    /// 직접 조합과 동일한 결과를 내는지 검증한다.
    fn reference_feed(
        processor: &mut OutputProcessor,
        detector: &mut CommandBoundaryDetector,
        bytes: &[u8],
    ) -> Vec<CommandRecord> {
        let output = processor.process(bytes);
        let mut out = Vec::new();
        for marker in &output.osc133_markers {
            if let Some(mut r) = detector.feed_line(marker) {
                r.capture_mode = CaptureMode::Pty;
                out.push(r);
            }
        }
        if let Some(ref text) = output.clean_text {
            for line in text.lines() {
                if let Some(mut r) = detector.feed_line(line) {
                    r.capture_mode = CaptureMode::Pty;
                    out.push(r);
                }
            }
        }
        out
    }

    fn make_reference() -> (OutputProcessor, CommandBoundaryDetector) {
        (
            OutputProcessor::new(),
            CommandBoundaryDetector::new(BoundaryStrategy::PromptMarker {
                marker_sequence: "osc133".to_string(),
            }),
        )
    }

    /// record 동등성 비교용 projection — timestamp 와 id 는 검증에서 제외한다.
    fn project(r: &CommandRecord) -> (Option<String>, i32, Vec<String>, CaptureMode) {
        (
            r.command.clone(),
            r.exit_code,
            r.output_lines.clone(),
            r.capture_mode,
        )
    }

    #[tokio::test]
    async fn open_registers_new_session() {
        let pool = SessionProcessorPool::new();
        assert!(pool.open("s1").await.is_ok());
        assert_eq!(pool.active_len().await, 1);
    }

    #[tokio::test]
    async fn open_twice_returns_already_open() {
        let pool = SessionProcessorPool::new();
        pool.open("s1").await.unwrap();
        let err = pool.open("s1").await.unwrap_err();
        assert_eq!(err, AttachOpenError::AlreadyOpen("s1".to_string()));
    }

    #[tokio::test]
    async fn feed_before_open_returns_empty() {
        let pool = SessionProcessorPool::new();
        // 열지 않은 session 에 대한 feed 는 빈 Vec.
        assert!(pool.feed("unknown", b"hello\n").await.is_empty());
    }

    /// 하나의 shell 명령에 해당하는 "자연스러운" chunk 분할.
    /// 실제 PTY 흐름은 preexec → 명령 출력 → precmd 순으로 chunk 가 분리된다.
    fn natural_command_chunks(cmd_hex: &str, output_lines: &[&str], exit: i32) -> Vec<Vec<u8>> {
        let preexec = format!("\x1b]133;C;cmd={cmd_hex}\x07").into_bytes();
        let body = {
            let mut s = String::new();
            for line in output_lines {
                s.push_str(line);
                s.push('\n');
            }
            s.into_bytes()
        };
        let precmd = format!("\x1b]133;D;{exit}\x07").into_bytes();
        vec![preexec, body, precmd]
    }

    #[tokio::test]
    async fn feed_matches_direct_output_processor_boundary_detector_combo() {
        // Pool 경로
        let pool = SessionProcessorPool::new();
        pool.open("s1").await.unwrap();

        // 참조 경로: 같은 bytes 를 OutputProcessor + CommandBoundaryDetector 직접 조합에 feed.
        let (mut ref_proc, mut ref_det) = make_reference();

        // "make" = 6d 61 6b 65
        let chunks = natural_command_chunks("6d616b65", &["error: file not found"], 1);

        let mut pool_all = Vec::new();
        let mut ref_all = Vec::new();
        for chunk in &chunks {
            pool_all.extend(pool.feed("s1", chunk).await);
            ref_all.extend(reference_feed(&mut ref_proc, &mut ref_det, chunk));
        }

        // 두 경로의 결과가 동일해야 한다 (Pool == 직접 조합).
        let pool_proj: Vec<_> = pool_all.iter().map(project).collect();
        let ref_proj: Vec<_> = ref_all.iter().map(project).collect();
        assert_eq!(pool_proj, ref_proj);

        // 정확히 1개 record 가 만들어졌는지, 내용도 정확한지 확인.
        assert_eq!(pool_all.len(), 1);
        for r in &pool_all {
            assert_eq!(r.capture_mode, CaptureMode::Pty);
        }
        let rec = &pool_all[0];
        assert_eq!(rec.command.as_deref(), Some("make"));
        assert_eq!(rec.exit_code, 1);
        assert_eq!(rec.output_lines, vec!["error: file not found".to_string()]);
    }

    #[tokio::test]
    async fn feed_preserves_state_across_multiple_calls() {
        // 같은 명령 경계가 여러 번의 feed 호출에 걸쳐 나뉘어도 Pool 이 상태를
        // 유지해 정확히 하나의 record 를 만들어야 한다.
        let pool = SessionProcessorPool::new();
        pool.open("s1").await.unwrap();
        let (mut ref_proc, mut ref_det) = make_reference();

        // "ls" = 6c 73
        let chunks = natural_command_chunks("6c73", &["file1", "file2"], 0);

        // 출력을 여러 작은 조각으로 더 잘게 쪼개서 상태 보존을 강하게 검증.
        // [preexec, "file1\n", "file2\n", precmd] — body 를 라인별로 분할.
        let preexec = chunks[0].clone();
        let precmd = chunks[2].clone();
        let pieces: Vec<Vec<u8>> = vec![
            preexec,
            b"file1\n".to_vec(),
            b"file2\n".to_vec(),
            precmd,
        ];

        let mut pool_all = Vec::new();
        let mut ref_all = Vec::new();
        for chunk in &pieces {
            pool_all.extend(pool.feed("s1", chunk).await);
            ref_all.extend(reference_feed(&mut ref_proc, &mut ref_det, chunk));
        }

        let pool_proj: Vec<_> = pool_all.iter().map(project).collect();
        let ref_proj: Vec<_> = ref_all.iter().map(project).collect();
        assert_eq!(pool_proj, ref_proj);

        assert_eq!(pool_all.len(), 1);
        let rec = &pool_all[0];
        assert_eq!(rec.command.as_deref(), Some("ls"));
        assert_eq!(rec.exit_code, 0);
        assert_eq!(rec.output_lines, vec!["file1".to_string(), "file2".to_string()]);
    }

    #[tokio::test]
    async fn different_sessions_are_isolated() {
        // 두 session 이 같은 pool 에서 각자 독립된 파이프라인을 가져야 한다.
        // 한 session 의 미완성 상태가 다른 session 의 결과에 영향을 주면 안 된다.
        let pool = SessionProcessorPool::new();
        pool.open("alpha").await.unwrap();
        pool.open("beta").await.unwrap();

        // alpha: preexec + body 까지만 feed (아직 D 없음).
        let alpha_preexec = b"\x1b]133;C;cmd=6d616b65\x07".to_vec(); // "make"
        let alpha_body = b"alpha output line\n".to_vec();
        assert!(pool.feed("alpha", &alpha_preexec).await.is_empty());
        assert!(pool.feed("alpha", &alpha_body).await.is_empty());

        // beta: 온전한 한 명령을 처음부터 끝까지.
        let beta_chunks = natural_command_chunks("6c73", &["beta-line-1"], 0); // "ls"
        let mut beta_records = Vec::new();
        for c in &beta_chunks {
            beta_records.extend(pool.feed("beta", c).await);
        }
        assert_eq!(beta_records.len(), 1);
        assert_eq!(beta_records[0].command.as_deref(), Some("ls"));
        assert_eq!(beta_records[0].exit_code, 0);
        assert_eq!(beta_records[0].output_lines, vec!["beta-line-1".to_string()]);

        // 이제 alpha 에 D 마커를 feed. alpha 의 누적 상태가 보존되어 있었어야 한다.
        let alpha_end = b"\x1b]133;D;2\x07".to_vec();
        let alpha_records = pool.feed("alpha", &alpha_end).await;
        assert_eq!(alpha_records.len(), 1);
        assert_eq!(alpha_records[0].command.as_deref(), Some("make"));
        assert_eq!(alpha_records[0].exit_code, 2);
        assert_eq!(
            alpha_records[0].output_lines,
            vec!["alpha output line".to_string()]
        );
    }

    #[tokio::test]
    async fn close_drops_state_and_subsequent_feed_returns_empty() {
        let pool = SessionProcessorPool::new();
        pool.open("s1").await.unwrap();

        // 진행 중인 명령 상태를 쌓아둔다.
        let _ = pool
            .feed("s1", b"\x1b]133;C;cmd=6d616b65\x07output\n")
            .await;
        assert_eq!(pool.active_len().await, 1);

        // close 후엔 entry 가 사라지고, feed 는 빈 Vec.
        pool.close("s1").await;
        assert_eq!(pool.active_len().await, 0);
        let after = pool.feed("s1", b"\x1b]133;D;0\x07").await;
        assert!(after.is_empty());

        // 같은 session_id 를 다시 open 할 수 있어야 한다.
        assert!(pool.open("s1").await.is_ok());
        // 새 instance 는 이전 상태를 이어받지 않는다.
        let fresh = pool.feed("s1", b"\x1b]133;D;0\x07").await;
        assert!(
            fresh.is_empty(),
            "새 open 은 빈 상태여야 하므로 D 마커만으론 record 가 없어야 한다"
        );
    }

    #[tokio::test]
    async fn close_is_idempotent() {
        let pool = SessionProcessorPool::new();
        pool.close("never-opened").await; // panic 없이 통과.
        pool.open("s1").await.unwrap();
        pool.close("s1").await;
        pool.close("s1").await; // 두 번째 close 도 no-op.
    }
}
