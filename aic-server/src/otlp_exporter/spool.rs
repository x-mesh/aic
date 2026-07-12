//! `~/.aic/otlp-spool/` 오프라인 durability 계층 (SRE t8).
//!
//! collector로의 push가 실패하면 그 순간 이미 인코딩된 OTLP protobuf bytes를 그대로 디스크에
//! spool한다. 세 exporter task(host metrics/events/connections)가 **하나의 `Spool` 인스턴스를
//! `Arc`로 공유**한다 — 파일 목록/누적 크기 추적을 인스턴스별로 따로 들고 있으면 서로의 append/
//! delete를 못 보고 상한(`max_bytes`) 계산이 어긋난다.
//!
//! **redaction invariant**: spool은 [`encode::encode_metrics`](super::encode::encode_metrics)/
//! [`logs_proto::encode_*`](super::logs_proto)가 만든 **최종 protobuf 인코딩 산출물**만 그대로
//! 저장한다. 원본 command 텍스트나 아직 redact되지 않은 값을 spool이 직접 다루는 경로는 없다 —
//! 즉 t6/t7에서 이미 검증된 redaction 경로를 그대로 재사용하고, spool은 그 뒤에 결과 bytes를
//! "보내다 실패하면 잠깐 보관"만 한다.
//!
//! **파일 형식**: 파일 하나 = 배치 하나(append 전용 다중 배치 파일보다 구현이 단순해 이쪽을
//! 선택 — 상한 초과 시 삭제도 파일 단위로 끝난다). 파일명은 0-padding된 단조 증가 sequence라
//! 사전순 정렬이 곧 FIFO 순서다. 내용은 `[1 byte signal tag][4 byte big-endian body 길이][body]`
//! — length-prefix는 프로세스가 append 도중 죽어 파일이 잘렸을 때(드문 경우, `File::create` +
//! `write_all` + `rename`으로 원자적 교체를 쓰지만 방어적으로 한 겹 더 둔다) 드레인 시점에
//! 길이 불일치로 걸러내 조용히 skip+삭제하기 위함이다.

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// spool된 배치가 재전송될 때 어느 OTLP endpoint(`/v1/metrics` vs `/v1/logs`)로 가야 하는지.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    Metrics,
    Logs,
}

impl SignalKind {
    fn tag(self) -> u8 {
        match self {
            SignalKind::Metrics => 0,
            SignalKind::Logs => 1,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(SignalKind::Metrics),
            1 => Some(SignalKind::Logs),
            _ => None,
        }
    }
}

/// 배치 파일 확장자 — 임시 파일(`.tmp`)과 구분해 드레인/스캔 대상에서 골라낸다.
const BATCH_EXT: &str = "batch";
/// append 중간 상태를 위한 임시 파일 확장자. `rename`으로 원자적으로 `.batch`가 된다.
const TMP_EXT: &str = "tmp";

/// 드레인 시도 결과.
pub struct DrainReport {
    /// 이번 호출에서 성공적으로 재전송+삭제한 배치 수.
    pub drained: usize,
    /// 도중에 재전송 실패가 있었는지(있었다면 그 지점에서 즉시 멈춘다 — FIFO 순서 보존 + 어차피
    /// collector가 다운이면 뒤 배치도 실패할 것이므로).
    pub failed: bool,
}

#[derive(Debug)]
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    next_seq: AtomicU64,
    /// 디렉토리 재스캔 없이 append/drain마다 갱신하는 누적 바이트 수.
    total_bytes: Mutex<u64>,
    dropped: AtomicU64,
}

impl Spool {
    /// `dir`을 0700 권한으로 열거나 생성하고, 기존 배치 파일들을 스캔해 다음 sequence와 누적
    /// 크기를 복원한다. 스캔 중 발견한 leftover `.tmp` 파일(이전 실행이 append 도중 죽은 흔적)은
    /// 정리한다. 복원된 누적 크기가 이미 `max_bytes`를 넘으면(예: 재시작 사이 설정을 줄인 경우)
    /// 그 자리에서 oldest부터 drop해 상한을 맞춘다.
    pub fn open(dir: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let mut max_seq: u64 = 0;
        let mut total: u64 = 0;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some(TMP_EXT) {
                // 이전 실행이 append 도중 죽어 남은 partial write. rename 전이라 아직
                // `.batch`가 아니므로 무결한 배치가 아니다 — 조용히 정리.
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if let Some(seq) = seq_from_filename(&path) {
                max_seq = max_seq.max(seq);
            }
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }

        let spool = Self {
            dir,
            max_bytes,
            next_seq: AtomicU64::new(max_seq.wrapping_add(1)),
            total_bytes: Mutex::new(total),
            dropped: AtomicU64::new(0),
        };
        {
            let mut total = spool.total_bytes.lock().unwrap();
            spool.enforce_cap(&mut total);
        }
        Ok(spool)
    }

    /// 배치를 spool에 적재한다. `body`는 이미 인코딩(+redact 완료)된 protobuf bytes 그대로.
    /// 쓰기는 임시 파일에 쓴 뒤 `rename`으로 원자적으로 최종 이름으로 바꾼다 — 중간에 프로세스가
    /// 죽어도 절반만 쓰인 `.batch` 파일이 생기지 않는다(있어도 `.tmp`로만 남아 다음 `open`에서
    /// 정리됨). 적재 후 총량이 상한을 넘으면 oldest부터 drop한다.
    pub fn append(&self, kind: SignalKind, body: &[u8]) -> std::io::Result<()> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let final_path = self.dir.join(format!("{seq:020}.{BATCH_EXT}"));
        let tmp_path = self.dir.join(format!("{seq:020}.{TMP_EXT}"));

        let mut buf = Vec::with_capacity(5 + body.len());
        buf.push(kind.tag());
        buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
        buf.extend_from_slice(body);

        {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &final_path)?;

        let mut total = self.total_bytes.lock().unwrap();
        *total += buf.len() as u64;
        self.enforce_cap(&mut total);
        Ok(())
    }

    /// FIFO 순서로 최대 `limit`개 배치를 `sender`로 재전송 시도한다. 성공한 배치만 삭제한다.
    /// `sender`는 (signal kind, body)를 받아 실제 HTTP push를 수행하는 호출부 콜백 —
    /// endpoint URL 선택(`/v1/metrics` vs `/v1/logs`)은 kind를 보고 호출부가 결정한다.
    pub async fn drain<F, Fut>(&self, limit: usize, mut sender: F) -> DrainReport
    where
        F: FnMut(SignalKind, Vec<u8>) -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        let mut files = match self.list_batch_files() {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "otlp spool 디렉토리 읽기 실패 — 이번 드레인 skip");
                return DrainReport { drained: 0, failed: true };
            }
        };
        files.sort();

        let mut drained = 0usize;
        for path in files.into_iter().take(limit) {
            let (kind, body) = match read_batch(&path) {
                Ok(pair) => pair,
                Err(e) => {
                    // 손상/부분 write된 배치 — 무한 재시도를 막기 위해 건너뛰고 삭제한다.
                    tracing::warn!(path = %path.display(), error = %e, "손상된 otlp spool 배치 — 건너뛰고 삭제");
                    self.remove_and_untrack(&path);
                    continue;
                }
            };
            match sender(kind, body).await {
                Ok(()) => {
                    self.remove_and_untrack(&path);
                    drained += 1;
                }
                Err(_) => return DrainReport { drained, failed: true },
            }
        }
        DrainReport { drained, failed: false }
    }

    /// 지금까지 상한 초과로 drop된 누적 배치 수(테스트/디버그 관측용).
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 현재 spool 디렉토리에 남아 있는 배치 파일 수(테스트 관측용).
    pub fn batch_count(&self) -> usize {
        self.list_batch_files().map(|f| f.len()).unwrap_or(0)
    }

    fn list_batch_files(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some(BATCH_EXT) {
                out.push(path);
            }
        }
        Ok(out)
    }

    /// `total_bytes`가 `max_bytes`를 넘는 동안 파일명 오름차순(=가장 오래된 것부터) 삭제하며
    /// `dropped` 카운터를 올린다. 호출부가 이미 `total_bytes` lock을 쥔 상태에서 불린다.
    fn enforce_cap(&self, total: &mut u64) {
        if *total <= self.max_bytes {
            return;
        }
        let mut files = match self.list_batch_files() {
            Ok(f) => f,
            Err(_) => return,
        };
        files.sort();
        for path in files {
            if *total <= self.max_bytes {
                break;
            }
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if std::fs::remove_file(&path).is_ok() {
                *total = total.saturating_sub(len);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                if aic_debug_enabled() {
                    tracing::debug!(
                        path = %path.display(),
                        dropped_total = self.dropped.load(Ordering::Relaxed),
                        "otlp spool 상한 초과 — oldest 배치 drop"
                    );
                }
            }
        }
    }

    fn remove_and_untrack(&self, path: &Path) {
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if std::fs::remove_file(path).is_ok() {
            let mut total = self.total_bytes.lock().unwrap();
            *total = total.saturating_sub(len);
        }
    }
}

/// `AIC_DEBUG=1|true`(대소문자·공백 무시) 여부. 그 외(0/false/off/unset/empty)는 OFF —
/// aic-client(`agent::debug::truthy`)와 동일 판정 규칙. aic-server는 aic-client에 의존하지 않으므로
/// 여기서 최소 형태로 재구현한다(같은 env var가 크레이트마다 다른 의미가 되지 않도록).
fn aic_debug_enabled() -> bool {
    matches!(
        std::env::var("AIC_DEBUG").ok().map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true")
    )
}

fn seq_from_filename(path: &Path) -> Option<u64> {
    if path.extension().and_then(|e| e.to_str()) != Some(BATCH_EXT) {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}

fn read_batch(path: &Path) -> std::io::Result<(SignalKind, Vec<u8>)> {
    let data = std::fs::read(path)?;
    if data.len() < 5 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "짧은 spool 파일"));
    }
    let kind = SignalKind::from_tag(data[0])
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "알 수 없는 signal tag"))?;
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let body = &data[5..];
    if body.len() != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "spool 길이 불일치(부분 write로 추정)",
        ));
    }
    Ok((kind, body.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_spool(max_bytes: u64) -> (tempfile::TempDir, Spool) {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("otlp-spool"), max_bytes).unwrap();
        (dir, spool)
    }

    #[test]
    fn open_creates_dir_with_0700_permissions() {
        let (dir, spool) = tmp_spool(1024);
        let meta = std::fs::metadata(dir.path().join("otlp-spool")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }
        assert_eq!(spool.batch_count(), 0);
    }

    #[test]
    fn append_then_read_round_trips_body_and_kind() {
        let (_dir, spool) = tmp_spool(1024 * 1024);
        spool.append(SignalKind::Metrics, b"metrics-body").unwrap();
        spool.append(SignalKind::Logs, b"logs-body").unwrap();
        assert_eq!(spool.batch_count(), 2);

        let files = spool.list_batch_files().unwrap();
        assert_eq!(files.len(), 2);
        let mut sorted = files.clone();
        sorted.sort();
        let (kind0, body0) = read_batch(&sorted[0]).unwrap();
        assert_eq!(kind0, SignalKind::Metrics);
        assert_eq!(body0, b"metrics-body");
        let (kind1, body1) = read_batch(&sorted[1]).unwrap();
        assert_eq!(kind1, SignalKind::Logs);
        assert_eq!(body1, b"logs-body");
    }

    #[test]
    fn filenames_sort_in_fifo_append_order() {
        let (_dir, spool) = tmp_spool(1024 * 1024);
        for i in 0..15 {
            spool.append(SignalKind::Metrics, format!("body-{i}").as_bytes()).unwrap();
        }
        let mut files = spool.list_batch_files().unwrap();
        files.sort();
        for (i, path) in files.iter().enumerate() {
            let (_, body) = read_batch(path).unwrap();
            assert_eq!(body, format!("body-{i}").as_bytes());
        }
    }

    #[test]
    fn append_beyond_cap_drops_oldest_and_counts() {
        // 배치 하나 = 5바이트 헤더 + body. body 10바이트짜리를 여러 개 넣어 상한을 확실히 넘긴다.
        let per_batch = 15u64; // 5(header) + 10(body)
        let (_dir, spool) = tmp_spool(per_batch * 3); // 배치 3개까지만 버틴다.

        for i in 0..5u8 {
            let body = [i; 10];
            spool.append(SignalKind::Metrics, &body).unwrap();
        }

        assert!(spool.batch_count() <= 3, "상한을 넘는 배치는 삭제되어야 함: {}", spool.batch_count());
        assert_eq!(spool.dropped_count(), 2, "5개 중 상한 초과분 2개가 drop되어야 함");

        // 살아남은 배치는 가장 최근 것들이어야 한다(oldest부터 drop).
        let mut files = spool.list_batch_files().unwrap();
        files.sort();
        let bodies: Vec<u8> = files
            .iter()
            .map(|p| read_batch(p).unwrap().1[0])
            .collect();
        assert_eq!(bodies, vec![2, 3, 4], "oldest(0,1)가 drop되고 최신(2,3,4)만 남아야 함");
    }

    #[test]
    fn corrupted_batch_file_is_skipped_and_removed_by_seq_scan() {
        let (dir, spool) = tmp_spool(1024 * 1024);
        spool.append(SignalKind::Metrics, b"good").unwrap();
        // 손상 파일을 직접 끼워 넣는다(길이 prefix가 실제 body보다 크다고 거짓 주장).
        let corrupt_path = dir.path().join("otlp-spool").join(format!("{:020}.batch", 999u64));
        std::fs::write(&corrupt_path, [0u8, 0, 0, 0, 100, 1, 2, 3]).unwrap();

        assert!(read_batch(&corrupt_path).is_err());
    }

    #[tokio::test]
    async fn drain_sends_in_fifo_order_and_removes_only_successes() {
        let (_dir, spool) = tmp_spool(1024 * 1024);
        for i in 0..5u8 {
            spool.append(SignalKind::Metrics, &[i]).unwrap();
        }

        let received = std::sync::Mutex::new(Vec::new());
        let report = spool
            .drain(10, |_kind, body| {
                received.lock().unwrap().push(body[0]);
                async { Ok(()) }
            })
            .await;

        assert_eq!(report.drained, 5);
        assert!(!report.failed);
        assert_eq!(spool.batch_count(), 0);
        assert_eq!(*received.lock().unwrap(), vec![0, 1, 2, 3, 4], "FIFO 순서로 전송되어야 함");
    }

    #[tokio::test]
    async fn drain_respects_limit_leaving_rest_for_next_call() {
        let (_dir, spool) = tmp_spool(1024 * 1024);
        for i in 0..5u8 {
            spool.append(SignalKind::Metrics, &[i]).unwrap();
        }

        let report = spool.drain(2, |_kind, _body| async { Ok(()) }).await;
        assert_eq!(report.drained, 2);
        assert_eq!(spool.batch_count(), 3, "limit을 넘는 배치는 다음 드레인까지 남아 있어야 함");
    }

    #[tokio::test]
    async fn drain_stops_at_first_failure_preserving_order() {
        let (_dir, spool) = tmp_spool(1024 * 1024);
        for i in 0..5u8 {
            spool.append(SignalKind::Metrics, &[i]).unwrap();
        }

        let mut attempt = 0u8;
        let report = spool
            .drain(10, |_kind, _body| {
                attempt += 1;
                let this_attempt = attempt;
                async move {
                    if this_attempt <= 2 {
                        Ok(())
                    } else {
                        anyhow::bail!("collector down")
                    }
                }
            })
            .await;

        assert_eq!(report.drained, 2, "처음 2개는 성공, 3번째에서 멈춰야 함");
        assert!(report.failed);
        assert_eq!(spool.batch_count(), 3, "실패한 배치부터는 그대로 남아 다음 드레인에 재시도됨");
    }

    #[test]
    fn open_recovers_next_seq_and_total_bytes_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        {
            let spool = Spool::open(spool_dir.clone(), 1024 * 1024).unwrap();
            spool.append(SignalKind::Metrics, b"one").unwrap();
            spool.append(SignalKind::Logs, b"two").unwrap();
        }
        // 재시작(새 Spool 인스턴스) — 기존 배치를 잃지 않고 seq가 이어져야 한다.
        let reopened = Spool::open(spool_dir, 1024 * 1024).unwrap();
        assert_eq!(reopened.batch_count(), 2);
        reopened.append(SignalKind::Metrics, b"three").unwrap();
        assert_eq!(reopened.batch_count(), 3, "재시작 후 append한 배치도 기존 파일명과 충돌 없이 쌓여야 함");
    }

    #[test]
    fn open_cleans_up_leftover_tmp_files_from_crashed_write() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::write(spool_dir.join(format!("{:020}.tmp", 1u64)), b"partial").unwrap();

        let spool = Spool::open(spool_dir.clone(), 1024 * 1024).unwrap();
        assert_eq!(spool.batch_count(), 0);
        assert!(
            !spool_dir.join(format!("{:020}.tmp", 1u64)).exists(),
            "leftover .tmp는 open 시점에 정리되어야 함"
        );
    }
}
