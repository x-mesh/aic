//! `~/.aic/otlp-spool/` 오프라인 durability 계층 (SRE t8) + kind별 쿼터 (SRE R3).
//!
//! collector로의 push가 실패하면 그 순간 이미 인코딩된 OTLP protobuf bytes를 그대로 디스크에
//! spool한다. exporter task들(host metrics/events/connections/agent/changes/app logs)이 **하나의
//! `Spool` 인스턴스를 `Arc`로 공유**한다 — 파일 목록/누적 크기 추적을 인스턴스별로 따로 들고
//! 있으면 서로의 append/delete를 못 보고 상한 계산이 어긋난다.
//!
//! **redaction invariant**: spool은 [`encode::encode_metrics`](super::encode::encode_metrics)/
//! [`logs_proto::encode_*`](super::logs_proto)가 만든 **최종 protobuf 인코딩 산출물**만 그대로
//! 저장한다. 원본 command 텍스트나 아직 redact되지 않은 값을 spool이 직접 다루는 경로는 없다 —
//! 즉 t6/t7에서 이미 검증된 redaction 경로를 그대로 재사용하고, spool은 그 뒤에 결과 bytes를
//! "보내다 실패하면 잠깐 보관"만 한다.
//!
//! **파일 형식**: 파일 하나 = 배치 하나(append 전용 다중 배치 파일보다 구현이 단순해 이쪽을
//! 선택 — 상한 초과 시 삭제도 파일 단위로 끝난다). 파일명은 `{seq:020}.{code}.batch`(0-padding된
//! 단조 증가 sequence + 1글자 kind 코드) — 사전순 정렬이 곧 FIFO 순서다(seq가 고정폭 접두사라
//! code가 섞여도 깨지지 않는다). 내용은 `[1 byte signal tag][4 byte big-endian body 길이][body]`
//! — length-prefix는 프로세스가 append 도중 죽어 파일이 잘렸을 때(드문 경우, `File::create` +
//! `write_all` + `rename`으로 원자적 교체를 쓰지만 방어적으로 한 겹 더 둔다) 드레인 시점에
//! 길이 불일치로 걸러내 조용히 skip+삭제하기 위함이다.
//!
//! **kind별 쿼터(R3)**: `SignalKind`는 이제 endpoint 선택자를 넘어 **쿼터 버킷**이다. 로그
//! 수집기(볼륨 100~1000배)가 command 감사 이벤트(`SignalKind::Logs`)와 같은 버킷을 쓰면 로그가
//! 감사 기록을 evict할 수 있어 `AppLogs`를 별도 버킷으로 신설했다. 파일명에 kind가 박혀 있는
//! 이유: `enforce_cap`은 append마다(초당 수십 회) 불리는데, 파일명에 kind가 없으면 "이 kind의
//! 가장 오래된 파일"을 찾기 위해 매번 디렉토리 전체를 열어 첫 바이트씩 읽어야 한다 — 로그
//! 볼륨에서는 즉사한다. `Metrics`/`Logs`는 기존과 동일하게 oldest-drop(회귀 금지 —
//! `append_beyond_cap_drops_oldest_and_counts`가 지킨다), `AppLogs`만 newest-drop이다(조사한
//! Vector/OTel Collector/Filebeat/Promtail 중 oldest-drop을 하는 구현이 하나도 없었다 — oldest를
//! 버리면 시퀀스에 구멍이 생겨 체크포인트 전진 로직이 무너지고, 사고 조사에 필요한 건 원인(오래된
//! 것)이지 증상(최신)이 아니기 때문).
//!
//! **레거시 마이그레이션**: 구버전이 남긴 `{seq:020}.batch`(kind가 파일명에 없음) 파일은 `open()`
//! 시점에 내용 첫 바이트(기존에도 있던 signal tag)로 kind를 판정해 신규 파일명으로 1회 rename한다.
//! tag가 불명이거나 rename이 실패하면 삭제한다(남겨두면 kind를 몰라 쿼터 계산에서 영원히 빠지고,
//! 어차피 `read_batch`가 나중에 버릴 파일이다).

use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aic_common::SpoolQuotas;

/// spool된 배치가 재전송될 때 어느 OTLP endpoint(`/v1/metrics` vs `/v1/logs`)로 가야 하는지 +
/// spool 용량 쿼터를 어느 버킷으로 채점할지. `Logs`/`AppLogs`는 엔드포인트가 둘 다 `/v1/logs`로
/// 같다 — 여기서 갈리는 건 오직 쿼터다(모듈 doc의 R3 설명 참고).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    Metrics = 0,
    Logs = 1,
    AppLogs = 2,
}

/// `SignalKind` variant 수. `totals`/`dropped` 배열 크기 및 stress 테스트의 재계산에 쓴다.
const SIGNAL_KIND_COUNT: usize = 3;

impl SignalKind {
    /// wire(파일 **내용** 첫 바이트) tag. 파일명 `code`와는 별개 축이다 — 값 자체는 순전히
    /// 내부용이라 바뀌어도 파일명 포맷엔 영향이 없다.
    fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(SignalKind::Metrics),
            1 => Some(SignalKind::Logs),
            2 => Some(SignalKind::AppLogs),
            _ => None,
        }
    }

    /// 파일**명**에 박히는 1글자 코드(`{seq:020}.{code}.batch`). tag는 wire, code는 파일명 —
    /// 분리해 둔다(하나가 바뀌어도 다른 쪽 포맷을 건드리지 않도록).
    fn code(self) -> &'static str {
        match self {
            SignalKind::Metrics => "m",
            SignalKind::Logs => "l",
            SignalKind::AppLogs => "a",
        }
    }

    fn from_code(s: &str) -> Option<Self> {
        match s {
            "m" => Some(SignalKind::Metrics),
            "l" => Some(SignalKind::Logs),
            "a" => Some(SignalKind::AppLogs),
            _ => None,
        }
    }

    /// `totals`/`dropped` 배열 인덱스.
    fn index(self) -> usize {
        self as usize
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
    /// collector가 **영구 거부**(4xx)해서 버린 배치 수. 재전송해도 결과가 같으므로 큐에 남기지
    /// 않는다 — 남기면 그 배치가 FIFO 머리에서 모든 kind의 드레인을 막는다(RFC-006 §6.6).
    /// 유실이므로 조용히 넘어가지 않고 여기로 올린다.
    pub rejected: usize,
    /// 도중에 **일시** 실패가 있었는지(있었다면 그 지점에서 즉시 멈춘다 — FIFO 순서 보존 + 어차피
    /// collector가 다운이면 뒤 배치도 실패할 것이므로). 영구 거부는 여기 해당하지 않는다.
    pub failed: bool,
}

#[derive(Debug)]
pub struct Spool {
    dir: PathBuf,
    quotas: SpoolQuotas,
    next_seq: AtomicU64,
    /// 디렉토리 재스캔 없이 append/drain마다 갱신하는 kind별 누적 바이트 수. kind별로 별도
    /// `Mutex`를 두지 않고 하나로 유지한다 — 쪼개면 `enforce_cap`이 다른 kind 파일을 건드릴 때
    /// 경합이 생긴다.
    totals: Mutex<[u64; SIGNAL_KIND_COUNT]>,
    dropped: [AtomicU64; SIGNAL_KIND_COUNT],
}

impl Spool {
    /// `dir`을 0700 권한으로 열거나 생성하고, 기존 배치 파일들을 스캔해 다음 sequence와 kind별
    /// 누적 크기를 복원한다. 스캔 중 발견한 leftover `.tmp` 파일(이전 실행이 append 도중 죽은
    /// 흔적)은 정리한다. 레거시 `{seq:020}.batch` 파일은 내용 첫 바이트로 kind를 판정해 신규
    /// 포맷으로 1회 rename한다(모듈 doc 참고) — tag 불명/rename 실패 시 삭제. 파일명이 신규/
    /// 레거시 어느 포맷에도 맞지 않는(적대적/손상) 항목은 조용히 무시한다(panic 없음, 집계
    /// 제외). 복원된 kind별 누적 크기가 이미 쿼터를 넘으면(예: 재시작 사이 설정을 줄인 경우)
    /// 그 자리에서 각 kind의 규칙대로(oldest/newest-drop) drop해 상한을 맞춘다.
    pub fn open(dir: PathBuf, quotas: SpoolQuotas) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let mut max_seq: u64 = 0;
        let mut totals = [0u64; SIGNAL_KIND_COUNT];

        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some(TMP_EXT) {
                // 이전 실행이 append 도중 죽어 남은 partial write. rename 전이라 아직
                // `.batch`가 아니므로 무결한 배치가 아니다 — 조용히 정리.
                let _ = std::fs::remove_file(&path);
                continue;
            }

            let Some((seq, kind)) = parse_batch_filename(&path) else {
                // 신규/레거시 어느 포맷과도 맞지 않는 파일명(적대적 입력, 손상) — 무시하고
                // 다음 항목으로. seq를 못 뽑았으니 max_seq/쿼터 어느 쪽도 오염시키지 않는다.
                continue;
            };
            max_seq = max_seq.max(seq);

            match kind {
                Some(kind) => {
                    // 이미 신규 포맷 — 그대로 집계.
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    totals[kind.index()] += len;
                }
                None => {
                    // 레거시 — 내용 첫 바이트로 kind를 판정해 신규 포맷으로 1회 마이그레이션.
                    match migrate_legacy_batch(&path, seq) {
                        Some((kind, len)) => totals[kind.index()] += len,
                        None => {
                            // tag 불명이거나 rename 실패 — 삭제(모듈 doc 참고).
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
            }
        }

        let spool = Self {
            dir,
            quotas,
            next_seq: AtomicU64::new(max_seq.wrapping_add(1)),
            totals: Mutex::new(totals),
            dropped: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
        };
        {
            let mut totals = spool.totals.lock().unwrap();
            for kind in [SignalKind::Metrics, SignalKind::Logs, SignalKind::AppLogs] {
                spool.enforce_cap(kind, &mut totals);
            }
        }
        Ok(spool)
    }

    /// 배치를 spool에 적재한다. `body`는 이미 인코딩(+redact 완료)된 protobuf bytes 그대로.
    /// 쓰기는 임시 파일에 쓴 뒤 `rename`으로 원자적으로 최종 이름으로 바꾼다 — 중간에 프로세스가
    /// 죽어도 절반만 쓰인 `.batch` 파일이 생기지 않는다(있어도 `.tmp`로만 남아 다음 `open`에서
    /// 정리됨). 적재 후 해당 kind의 누적 총량이 쿼터를 넘으면 kind별 규칙(oldest/newest-drop)대로
    /// drop한다.
    pub fn append(&self, kind: SignalKind, body: &[u8]) -> std::io::Result<()> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let code = kind.code();
        let final_path = self.dir.join(format!("{seq:020}.{code}.{BATCH_EXT}"));
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

        let mut totals = self.totals.lock().unwrap();
        totals[kind.index()] += buf.len() as u64;
        self.enforce_cap(kind, &mut totals);
        Ok(())
    }

    /// FIFO 순서로 최대 `limit`개 배치를 `sender`로 재전송 시도한다. 전역 FIFO 순서는 kind와
    /// 무관하게 seq(파일명 접두사) 오름차순 그대로다 — `sender`는 (signal kind, body)를 받아 실제
    /// HTTP push를 수행하는 호출부 콜백이고, endpoint URL 선택(`/v1/metrics` vs `/v1/logs`)은
    /// kind를 보고 호출부가 결정한다.
    ///
    /// 배치의 운명은 셋 중 하나다:
    ///
    /// - **성공** → 삭제하고 다음으로.
    /// - **[`PushError::Permanent`]**(4xx) → **삭제하고 다음으로.** 재전송해도 결과가 같은 배치다.
    ///   지우지 않으면 이 배치가 FIFO 머리에 영구히 박히고, spool은 모든 kind가 한 큐를 공유하므로
    ///   **metrics·events·agent·changes까지 전부 드레인이 멈춘다**(RFC-006 §6.6). 손상된 배치 파일을
    ///   이미 같은 이유로 건너뛰고 삭제하는데(아래), 4xx는 정확히 같은 부류다 — 몇 번을 보내도
    ///   성공하지 않는 배치.
    /// - **[`PushError::Transient`]**(5xx·타임아웃·커넥션 실패) → **남겨두고 즉시 중단.** collector가
    ///   다운이면 뒤 배치도 실패할 테니 FIFO 순서를 지키며 다음 tick을 기다린다.
    pub async fn drain<F, Fut>(&self, limit: usize, mut sender: F) -> DrainReport
    where
        F: FnMut(SignalKind, Vec<u8>) -> Fut,
        Fut: Future<Output = Result<(), super::PushError>>,
    {
        let mut files = match self.list_batch_files() {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "otlp spool 디렉토리 읽기 실패 — 이번 드레인 skip");
                return DrainReport {
                    drained: 0,
                    rejected: 0,
                    failed: true,
                };
            }
        };
        files.sort();

        let mut drained = 0usize;
        let mut rejected = 0usize;
        for path in files.into_iter().take(limit) {
            let (kind, body) = match read_batch(&path) {
                Ok(pair) => pair,
                Err(e) => {
                    // 손상/부분 write된 배치 — 무한 재시도를 막기 위해 건너뛰고 삭제한다.
                    // 파일명이 신규 포맷이면 거기서 kind를 얻어 총량을 바로잡는다(불명이면
                    // 애초에 open()이 집계하지 않았을 파일이라 총량을 건드리지 않는다).
                    tracing::warn!(path = %path.display(), error = %e, "손상된 otlp spool 배치 — 건너뛰고 삭제");
                    let kind_hint = parse_batch_filename(&path).and_then(|(_, k)| k);
                    self.remove_and_untrack(&path, kind_hint);
                    continue;
                }
            };
            match sender(kind, body).await {
                Ok(()) => {
                    self.remove_and_untrack(&path, Some(kind));
                    drained += 1;
                }
                Err(e) if e.is_permanent() => {
                    // 손상 배치와 같은 처리 — 지우지 않으면 큐 전체가 여기서 멈춘다.
                    // 조용히 버리지 않는다: 카운터로 올리고 warn을 남긴다.
                    tracing::warn!(
                        path = %path.display(),
                        kind = ?kind,
                        error = %e,
                        "collector가 배치를 영구 거부 — 건너뛰고 삭제(재전송해도 같은 응답)"
                    );
                    self.dropped[kind.index()].fetch_add(1, Ordering::Relaxed);
                    self.remove_and_untrack(&path, Some(kind));
                    rejected += 1;
                }
                Err(_) => {
                    return DrainReport {
                        drained,
                        rejected,
                        failed: true,
                    }
                }
            }
        }
        DrainReport {
            drained,
            rejected,
            failed: false,
        }
    }

    /// 지금까지 상한 초과로 drop된 누적 배치 수(테스트/디버그 관측용).
    pub fn dropped_count(&self, kind: SignalKind) -> u64 {
        self.dropped[kind.index()].load(Ordering::Relaxed)
    }

    /// 현재 spool 디렉토리에 남아 있는 배치 파일 수(테스트 관측용, kind 무관 합계).
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

    /// `list_batch_files`와 동일하지만 파일명에서 파싱한 kind가 `kind`와 일치하는 것만 남긴다.
    /// `enforce_cap`이 "이 kind의 파일들"만 훑을 때 쓴다 — append 경로(초당 수십 회)에서 도니까
    /// 파일 내용을 열어 확인하지 않고 파일명만 본다.
    fn list_batch_files_for_kind(&self, kind: SignalKind) -> std::io::Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some((_, Some(k))) = parse_batch_filename(&path) {
                if k == kind {
                    out.push(path);
                }
            }
        }
        Ok(out)
    }

    /// `totals[kind]`가 해당 kind 쿼터를 넘는 동안 파일을 지우며 `dropped[kind]`를 올린다.
    /// 호출부가 이미 `totals` lock을 쥔 상태에서 불린다.
    ///
    /// `Metrics`/`Logs`는 파일명 오름차순(=가장 오래된 것부터) 삭제하는 **oldest-drop**을
    /// 유지한다(회귀 금지 — `append_beyond_cap_drops_oldest_and_counts`가 지킨다). `AppLogs`만
    /// **newest-drop**이다 — 모듈 doc 설명대로, 조사한 4개 오픈소스 로그 수집기 중 oldest-drop을
    /// 하는 게 하나도 없었고, 시퀀스 연속성(체크포인트 전진)과 사고 조사(원인은 오래된 로그에
    /// 있다) 둘 다 oldest를 지키는 쪽이 유리하기 때문.
    fn enforce_cap(&self, kind: SignalKind, totals: &mut [u64; SIGNAL_KIND_COUNT]) {
        let quota = self.quota_for(kind);
        let idx = kind.index();
        if totals[idx] <= quota {
            return;
        }
        let mut files = match self.list_batch_files_for_kind(kind) {
            Ok(f) => f,
            Err(_) => return,
        };
        files.sort();
        if kind == SignalKind::AppLogs {
            // seq 내림차순 — 가장 최근(newest) 것부터 지운다.
            files.reverse();
        }
        for path in files {
            if totals[idx] <= quota {
                break;
            }
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if std::fs::remove_file(&path).is_ok() {
                totals[idx] = totals[idx].saturating_sub(len);
                self.dropped[idx].fetch_add(1, Ordering::Relaxed);
                if aic_debug_enabled() {
                    tracing::debug!(
                        path = %path.display(),
                        kind = ?kind,
                        dropped_total = self.dropped[idx].load(Ordering::Relaxed),
                        "otlp spool 상한 초과 — 배치 drop"
                    );
                }
            }
        }
    }

    fn quota_for(&self, kind: SignalKind) -> u64 {
        match kind {
            SignalKind::Metrics => self.quotas.metrics,
            SignalKind::Logs => self.quotas.logs,
            SignalKind::AppLogs => self.quotas.app_logs,
        }
    }

    /// 파일을 지우고, `kind`가 주어졌으면 그 kind의 총량에서 파일 크기를 뺀다. `kind`가
    /// `None`이면(파일명에서 kind를 못 뽑은 경우) 애초에 `open()`이 이 파일을 집계하지 않았을
    /// 것이므로 총량은 건드리지 않는다.
    fn remove_and_untrack(&self, path: &Path, kind: Option<SignalKind>) {
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if std::fs::remove_file(path).is_ok() {
            if let Some(kind) = kind {
                let mut totals = self.totals.lock().unwrap();
                let idx = kind.index();
                totals[idx] = totals[idx].saturating_sub(len);
            }
        }
    }
}

/// `AIC_DEBUG=1|true`(대소문자·공백 무시) 여부. 그 외(0/false/off/unset/empty)는 OFF —
/// aic-client(`agent::debug::truthy`)와 동일 판정 규칙. aic-server는 aic-client에 의존하지 않으므로
/// 여기서 최소 형태로 재구현한다(같은 env var가 크레이트마다 다른 의미가 되지 않도록).
fn aic_debug_enabled() -> bool {
    matches!(
        std::env::var("AIC_DEBUG")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true")
    )
}

/// 배치 파일명을 파싱해 `(seq, kind)`를 뽑는다.
///
/// - 신규: `{seq:020}.{code}.batch` → `kind = Some(...)`.
/// - 레거시: `{seq:020}.batch` → `kind = None`(내용 첫 바이트를 봐야 안다 — `open()`의
///   마이그레이션이 담당).
/// - 그 외(확장자가 `.batch`가 아니거나, seq가 숫자가 아니거나, code가 `m`/`l`/`a`가 아니거나,
///   점이 더 있는 등) → `None`. 적대적/손상 파일명을 panic 없이 조용히 걸러내기 위함이다.
fn parse_batch_filename(path: &Path) -> Option<(u64, Option<SignalKind>)> {
    if path.extension().and_then(|e| e.to_str()) != Some(BATCH_EXT) {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    match stem.split_once('.') {
        Some((seq, code)) => Some((seq.parse().ok()?, Some(SignalKind::from_code(code)?))),
        None => Some((stem.parse().ok()?, None)),
    }
}

/// 레거시 `.batch` 파일(파일명에 kind 없음) 하나를 신규 포맷(`{seq:020}.{code}.batch`)으로
/// rename한다. kind는 파일 **내용 첫 1바이트**(`append`가 쓰는 tag)로 판정한다 — 파일 전체를
/// 읽지 않는다(레거시 배치가 클 수도 있어서). 판정 실패/rename 실패 시 `None`(호출부가 원본
/// 삭제를 담당).
fn migrate_legacy_batch(path: &Path, seq: u64) -> Option<(SignalKind, u64)> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut tag_buf = [0u8; 1];
    f.read_exact(&mut tag_buf).ok()?;
    let kind = SignalKind::from_tag(tag_buf[0])?;
    drop(f);
    let len = std::fs::metadata(path).map(|m| m.len()).ok()?;
    let new_path = path.with_file_name(format!("{seq:020}.{}.{BATCH_EXT}", kind.code()));
    std::fs::rename(path, &new_path).ok()?;
    Some((kind, len))
}

fn read_batch(path: &Path) -> std::io::Result<(SignalKind, Vec<u8>)> {
    let data = std::fs::read(path)?;
    if data.len() < 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "짧은 spool 파일",
        ));
    }
    let kind = SignalKind::from_tag(data[0]).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "알 수 없는 signal tag")
    })?;
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

    fn quotas_uniform(bytes: u64) -> SpoolQuotas {
        SpoolQuotas {
            metrics: bytes,
            logs: bytes,
            app_logs: bytes,
        }
    }

    fn tmp_spool(max_bytes: u64) -> (tempfile::TempDir, Spool) {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("otlp-spool"), quotas_uniform(max_bytes)).unwrap();
        (dir, spool)
    }

    /// 신규 포맷(`{seq:020}.{code}.batch`) 배치 파일을 `spool.append`을 거치지 않고 직접 심는다
    /// — `open()` 이전 상태를 시뮬레이션할 때 쓴다.
    fn write_new_batch(dir: &Path, seq: u64, kind: SignalKind, body: &[u8]) {
        let mut buf = Vec::with_capacity(5 + body.len());
        buf.push(kind.tag());
        buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
        buf.extend_from_slice(body);
        std::fs::write(
            dir.join(format!("{seq:020}.{}.{BATCH_EXT}", kind.code())),
            buf,
        )
        .unwrap();
    }

    /// 레거시 포맷(`{seq:020}.batch`, kind는 내용 첫 바이트) 배치 파일을 직접 심는다.
    fn write_legacy_batch(dir: &Path, seq: u64, tag: u8, body: &[u8]) {
        let mut buf = Vec::with_capacity(5 + body.len());
        buf.push(tag);
        buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
        buf.extend_from_slice(body);
        std::fs::write(dir.join(format!("{seq:020}.{BATCH_EXT}")), buf).unwrap();
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
            spool
                .append(SignalKind::Metrics, format!("body-{i}").as_bytes())
                .unwrap();
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

        assert!(
            spool.batch_count() <= 3,
            "상한을 넘는 배치는 삭제되어야 함: {}",
            spool.batch_count()
        );
        assert_eq!(
            spool.dropped_count(SignalKind::Metrics),
            2,
            "5개 중 상한 초과분 2개가 drop되어야 함"
        );

        // 살아남은 배치는 가장 최근 것들이어야 한다(oldest부터 drop).
        let mut files = spool.list_batch_files().unwrap();
        files.sort();
        let bodies: Vec<u8> = files.iter().map(|p| read_batch(p).unwrap().1[0]).collect();
        assert_eq!(
            bodies,
            vec![2, 3, 4],
            "oldest(0,1)가 drop되고 최신(2,3,4)만 남아야 함"
        );
    }

    #[test]
    fn corrupted_batch_file_is_skipped_and_removed_by_seq_scan() {
        let (dir, spool) = tmp_spool(1024 * 1024);
        spool.append(SignalKind::Metrics, b"good").unwrap();
        // 손상 파일을 직접 끼워 넣는다(길이 prefix가 실제 body보다 크다고 거짓 주장).
        let corrupt_path = dir
            .path()
            .join("otlp-spool")
            .join(format!("{:020}.m.batch", 999u64));
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
        assert_eq!(
            *received.lock().unwrap(),
            vec![0, 1, 2, 3, 4],
            "FIFO 순서로 전송되어야 함"
        );
    }

    #[tokio::test]
    async fn drain_respects_limit_leaving_rest_for_next_call() {
        let (_dir, spool) = tmp_spool(1024 * 1024);
        for i in 0..5u8 {
            spool.append(SignalKind::Metrics, &[i]).unwrap();
        }

        let report = spool.drain(2, |_kind, _body| async { Ok(()) }).await;
        assert_eq!(report.drained, 2);
        assert_eq!(
            spool.batch_count(),
            3,
            "limit을 넘는 배치는 다음 드레인까지 남아 있어야 함"
        );
    }

    #[tokio::test]
    async fn drain_stops_at_first_transient_failure_preserving_order() {
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
                        Err(super::super::PushError::Transient("collector down".into()))
                    }
                }
            })
            .await;

        assert_eq!(report.drained, 2, "처음 2개는 성공, 3번째에서 멈춰야 함");
        assert!(report.failed);
        assert_eq!(report.rejected, 0, "일시 실패는 거부가 아니다");
        assert_eq!(
            spool.batch_count(),
            3,
            "일시 실패한 배치부터는 그대로 남아 다음 드레인에 재시도됨"
        );
    }

    /// 영구 거부(4xx)당한 배치는 **큐에서 빠져야 한다.**
    ///
    /// 남겨두면 FIFO 머리에 영원히 박힌다 — 재전송해도 같은 4xx라서다. 그리고 spool은 모든
    /// kind가 한 큐를 공유하므로, 앱 로그 배치 하나가 그 뒤의 **metrics·events까지 전부**
    /// 드레인을 멈춘다(RFC-006 §6.6). 이 테스트가 지키는 게 정확히 그 불변식이다:
    /// **거부된 배치 뒤의 다른 시그널이 계속 흘러야 한다.**
    #[tokio::test]
    async fn a_permanently_rejected_batch_is_dropped_and_does_not_block_other_signals() {
        let (_dir, spool) = tmp_spool(1024 * 1024);
        // 큐 머리에 앱 로그(거부당할 배치), 그 뒤에 다른 시그널들.
        spool.append(SignalKind::AppLogs, b"poison").unwrap();
        spool.append(SignalKind::Metrics, b"m1").unwrap();
        spool.append(SignalKind::Logs, b"e1").unwrap();

        let sent = std::sync::Mutex::new(Vec::new());
        let report = spool
            .drain(10, |kind, body| {
                let permanent = body == b"poison";
                sent.lock().unwrap().push(kind);
                async move {
                    if permanent {
                        // 413 — 배치가 수신 측 본문 상한을 넘었다. 몇 번을 보내도 같다.
                        Err(super::super::PushError::Permanent(
                            "collector가 413 Payload Too Large 응답".into(),
                        ))
                    } else {
                        Ok(())
                    }
                }
            })
            .await;

        assert_eq!(report.rejected, 1, "거부된 배치가 카운트돼야 한다");
        assert_eq!(report.drained, 2, "거부 배치 뒤의 두 시그널이 흘러야 한다");
        assert!(
            !report.failed,
            "영구 거부는 드레인 실패가 아니다 — 큐는 계속 흐른다"
        );
        assert_eq!(spool.batch_count(), 0, "거부된 배치도 큐에서 사라져야 한다");
        assert_eq!(
            spool.dropped_count(SignalKind::AppLogs),
            1,
            "유실을 조용히 넘기지 않고 드롭 카운터로 드러내야 한다"
        );
        assert_eq!(
            *sent.lock().unwrap(),
            vec![SignalKind::AppLogs, SignalKind::Metrics, SignalKind::Logs],
            "거부 배치에서 멈추지 않고 뒤의 배치를 전부 시도해야 한다"
        );
    }

    #[test]
    fn open_recovers_next_seq_and_total_bytes_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        {
            let spool = Spool::open(spool_dir.clone(), quotas_uniform(1024 * 1024)).unwrap();
            spool.append(SignalKind::Metrics, b"one").unwrap();
            spool.append(SignalKind::Logs, b"two").unwrap();
        }
        // 재시작(새 Spool 인스턴스) — 기존 배치를 잃지 않고 seq가 이어져야 한다.
        let reopened = Spool::open(spool_dir, quotas_uniform(1024 * 1024)).unwrap();
        assert_eq!(reopened.batch_count(), 2);
        reopened.append(SignalKind::Metrics, b"three").unwrap();
        assert_eq!(
            reopened.batch_count(),
            3,
            "재시작 후 append한 배치도 기존 파일명과 충돌 없이 쌓여야 함"
        );
    }

    #[test]
    fn open_cleans_up_leftover_tmp_files_from_crashed_write() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::write(spool_dir.join(format!("{:020}.tmp", 1u64)), b"partial").unwrap();

        let spool = Spool::open(spool_dir.clone(), quotas_uniform(1024 * 1024)).unwrap();
        assert_eq!(spool.batch_count(), 0);
        assert!(
            !spool_dir.join(format!("{:020}.tmp", 1u64)).exists(),
            "leftover .tmp는 open 시점에 정리되어야 함"
        );
    }

    #[test]
    fn open_migrates_legacy_batch_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        std::fs::create_dir_all(&spool_dir).unwrap();

        write_legacy_batch(&spool_dir, 1, 0, b"metrics-body"); // tag 0 = Metrics
        write_legacy_batch(&spool_dir, 2, 1, b"logs-body"); // tag 1 = Logs
        write_legacy_batch(&spool_dir, 3, 2, b"applogs-body"); // tag 2 = AppLogs

        let spool = Spool::open(spool_dir.clone(), quotas_uniform(1024 * 1024)).unwrap();

        assert!(
            !spool_dir.join(format!("{:020}.batch", 1u64)).exists(),
            "레거시 파일명이 남아있으면 안 됨"
        );
        assert!(spool_dir.join(format!("{:020}.m.batch", 1u64)).exists());
        assert!(spool_dir.join(format!("{:020}.l.batch", 2u64)).exists());
        assert!(spool_dir.join(format!("{:020}.a.batch", 3u64)).exists());
        assert_eq!(spool.batch_count(), 3);

        {
            let totals = spool.totals.lock().unwrap();
            assert_eq!(
                totals[SignalKind::Metrics.index()],
                5 + "metrics-body".len() as u64
            );
            assert_eq!(
                totals[SignalKind::Logs.index()],
                5 + "logs-body".len() as u64
            );
            assert_eq!(
                totals[SignalKind::AppLogs.index()],
                5 + "applogs-body".len() as u64
            );
        }

        // next_seq 복원 확인 — 다음 append가 4부터 시작해야(기존 파일과 충돌 없이).
        spool.append(SignalKind::Metrics, b"next").unwrap();
        assert!(spool_dir.join(format!("{:020}.m.batch", 4u64)).exists());
    }

    #[test]
    fn app_logs_quota_does_not_evict_audit_logs() {
        let per_batch = 15u64; // 5(header) + 10(body)
        let dir = tempfile::tempdir().unwrap();
        let quotas = SpoolQuotas {
            metrics: per_batch * 3,
            logs: per_batch * 3,
            app_logs: per_batch * 3,
        };
        let spool = Spool::open(dir.path().join("otlp-spool"), quotas).unwrap();

        // 감사 로그(Logs)를 자기 쿼터만큼 채운다.
        for i in 0..3u8 {
            spool.append(SignalKind::Logs, &[i; 10]).unwrap();
        }
        assert_eq!(spool.dropped_count(SignalKind::Logs), 0);

        // AppLogs를 자기 쿼터 초과하도록 잔뜩 넣는다 — Logs 쿼터/파일과 무관해야 한다.
        for i in 0..5u8 {
            spool.append(SignalKind::AppLogs, &[i; 10]).unwrap();
        }

        assert!(
            spool.dropped_count(SignalKind::AppLogs) > 0,
            "AppLogs는 자기 쿼터 내에서 drop되어야 함"
        );
        assert_eq!(
            spool.dropped_count(SignalKind::Logs),
            0,
            "AppLogs 쿼터 초과가 Logs를 건드리면 안 됨"
        );

        let logs_files = spool.list_batch_files_for_kind(SignalKind::Logs).unwrap();
        assert_eq!(
            logs_files.len(),
            3,
            "감사 로그 3개는 AppLogs 쿼터 초과에 영향받지 않고 그대로 남아 있어야 함"
        );
    }

    #[test]
    fn app_logs_drops_newest_not_oldest() {
        let per_batch = 15u64;
        let dir = tempfile::tempdir().unwrap();
        let quotas = SpoolQuotas {
            metrics: per_batch * 3,
            logs: per_batch * 3,
            app_logs: per_batch * 3,
        };
        let spool = Spool::open(dir.path().join("otlp-spool"), quotas).unwrap();

        for i in 0..5u8 {
            spool.append(SignalKind::AppLogs, &[i; 10]).unwrap();
        }

        assert_eq!(spool.dropped_count(SignalKind::AppLogs), 2);
        let mut files = spool
            .list_batch_files_for_kind(SignalKind::AppLogs)
            .unwrap();
        files.sort();
        let bodies: Vec<u8> = files.iter().map(|p| read_batch(p).unwrap().1[0]).collect();
        assert_eq!(
            bodies,
            vec![0, 1, 2],
            "newest(3,4)가 drop되고 oldest(0,1,2)만 남아야 함(newest-drop)"
        );
    }

    #[test]
    fn open_ignores_corrupt_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        std::fs::create_dir_all(&spool_dir).unwrap();

        // 유효한 정상 파일 하나(신규 포맷) — 이것만 next_seq에 반영되어야 한다.
        write_new_batch(&spool_dir, 5, SignalKind::Metrics, b"ok");

        // 다양한 손상 파일명 — 전부 panic 없이 무시되어야 한다.
        std::fs::write(spool_dir.join(".batch"), b"garbage").unwrap(); // 빈 stem 취급(확장자 없음)
        std::fs::write(spool_dir.join("123456789012345678901.batch"), b"garbage").unwrap(); // 21자리 seq(u64 overflow)
        std::fs::write(spool_dir.join("00000000000000000009.zz.batch"), b"garbage").unwrap(); // 알 수 없는 code
        std::fs::write(
            spool_dir.join("00000000000000000010.m.extra.batch"),
            b"garbage",
        )
        .unwrap(); // 이중 점
        std::fs::write(spool_dir.join("🎉.batch"), b"garbage").unwrap(); // 유니코드

        // panic 없이 열려야 한다.
        let spool = Spool::open(spool_dir.clone(), quotas_uniform(1024 * 1024)).unwrap();

        // next_seq는 정상 파일(5)에서만 복원 — 다음 append는 6.
        spool.append(SignalKind::Metrics, b"next").unwrap();
        assert!(
            spool_dir.join(format!("{:020}.m.batch", 6u64)).exists(),
            "next_seq는 손상 파일명에 영향받지 않고 정상 파일(seq=5)에서만 복원되어야 함"
        );
    }

    #[test]
    fn open_deletes_unknown_kind_tag() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        std::fs::create_dir_all(&spool_dir).unwrap();

        // 정상 레거시 파일(tag 0 = Metrics).
        write_legacy_batch(&spool_dir, 1, 0, b"ok");
        // tag 불명(3..255) 레거시 파일들.
        write_legacy_batch(&spool_dir, 2, 3, b"bad");
        write_legacy_batch(&spool_dir, 3, 255, b"bad2");

        let spool = Spool::open(spool_dir.clone(), quotas_uniform(1024 * 1024)).unwrap();

        assert!(
            !spool_dir.join(format!("{:020}.batch", 2u64)).exists(),
            "tag 불명 레거시 파일은 삭제되어야 함"
        );
        assert!(!spool_dir.join(format!("{:020}.batch", 3u64)).exists());
        assert!(
            spool_dir.join(format!("{:020}.m.batch", 1u64)).exists(),
            "정상 파일은 마이그레이션되어 살아남아야 함"
        );
        assert_eq!(spool.batch_count(), 1);

        // 쿼터 계산 오염 없음 — 삭제는 drop 카운터가 아니라(상한 초과로 버린 게 아니므로),
        // Metrics 총량은 살아남은 파일 하나(5+2바이트)뿐이어야 한다.
        assert_eq!(spool.dropped_count(SignalKind::Metrics), 0);
        assert_eq!(spool.dropped_count(SignalKind::Logs), 0);
        assert_eq!(spool.dropped_count(SignalKind::AppLogs), 0);
        {
            let totals = spool.totals.lock().unwrap();
            assert_eq!(
                totals[SignalKind::Metrics.index()],
                5 + 2,
                "삭제된 tag-불명 파일이 total에 섞이면 안 됨"
            );
        }
    }

    #[test]
    fn open_recovers_from_interrupted_migration() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("otlp-spool");
        std::fs::create_dir_all(&spool_dir).unwrap();

        // 이미 마이그레이션된 파일(신규 포맷) — 이전 open() 호출에서 처리됐다고 가정.
        write_new_batch(&spool_dir, 1, SignalKind::Metrics, b"already-migrated");
        // 아직 마이그레이션 안 된 레거시 파일 — 이전 open()이 이 파일 처리 전에 죽었다고 가정.
        write_legacy_batch(&spool_dir, 2, 1, b"still-legacy");
        // append 도중 죽어 남은, 마이그레이션과 무관한 .tmp 잔재.
        std::fs::write(
            spool_dir.join(format!("{:020}.{TMP_EXT}", 3u64)),
            b"partial",
        )
        .unwrap();

        let spool = Spool::open(spool_dir.clone(), quotas_uniform(1024 * 1024)).unwrap();

        assert!(
            !spool_dir.join(format!("{:020}.{TMP_EXT}", 3u64)).exists(),
            ".tmp 잔재는 정리되어야 함"
        );
        assert!(
            spool_dir.join(format!("{:020}.m.batch", 1u64)).exists(),
            "이미 마이그레이션된 파일은 그대로 유지되어야 함"
        );
        assert!(
            spool_dir.join(format!("{:020}.l.batch", 2u64)).exists(),
            "남은 레거시 파일도 이번 open()에서 마이그레이션 완료되어야 함"
        );
        assert_eq!(
            spool.batch_count(),
            2,
            "유실도 덮어쓰기도 없이 둘 다 살아남아야 함"
        );

        // .tmp(seq=3)은 완결된 배치가 아니었으므로 max_seq에 기여하지 않는다 — 다음 seq는 3.
        spool.append(SignalKind::AppLogs, b"next").unwrap();
        assert!(spool_dir.join(format!("{:020}.a.batch", 3u64)).exists());
    }

    #[test]
    fn stress_random_append_totals_match_disk_and_no_seq_collisions() {
        let dir = tempfile::tempdir().unwrap();
        // 작은 쿼터로 enforce_cap이 자주 돌게 만든다.
        let quotas = SpoolQuotas {
            metrics: 2_000,
            logs: 2_000,
            app_logs: 2_000,
        };
        let spool = Spool::open(dir.path().join("otlp-spool"), quotas).unwrap();

        let kinds = [SignalKind::Metrics, SignalKind::Logs, SignalKind::AppLogs];
        // 결정적 의사난수(외부 crate 의존 없이) — 간단한 LCG.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next_rand = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        for i in 0..10_000u32 {
            let kind = kinds[(next_rand() % 3) as usize];
            let body_len = (next_rand() % 20) as usize;
            let body = vec![(i % 251) as u8; body_len];
            spool.append(kind, &body).unwrap();
        }

        // 디렉토리를 재스캔해 실제 총 바이트/seq 유일성을 재계산 — 내부 totals 카운터와
        // 일치해야 한다.
        let mut actual = [0u64; SIGNAL_KIND_COUNT];
        let mut seen_seqs = std::collections::HashSet::new();
        for path in spool.list_batch_files().unwrap() {
            if let Some((seq, Some(k))) = parse_batch_filename(&path) {
                assert!(seen_seqs.insert(seq), "seq 충돌: {seq}");
                let len = std::fs::metadata(&path).unwrap().len();
                actual[k.index()] += len;
            }
        }

        let totals = spool.totals.lock().unwrap();
        assert_eq!(
            *totals, actual,
            "누적 totals가 실제 디스크 사용량과 일치해야 함"
        );
    }
}
