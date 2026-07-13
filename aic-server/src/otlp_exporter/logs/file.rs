//! 파일 tail 로그 수집기 (RFC-006 t9) — fingerprint 기반 식별 + rotate_wait 드레인.
//!
//! ★★★ 설계의 핵심 두 가지 ★★★
//!
//! **(1) 식별자는 fingerprint다, inode가 아니다.** inode는 재사용된다 — 파일 삭제 후 커널이
//! 같은 inode 번호를 새 파일에 재배정하면, "inode 동일 + size >= offset → 변화 없음"으로
//! 판정해 새 파일의 앞 offset 바이트를 통째로 건너뛴다. 조용한 유실이고, 로그가 안 보인다는
//! 사실조차 모른다. Docker/overlayfs·ext4에서 흔하다. Vector/OTel filelog/Filebeat 셋 다
//! fingerprint(첫 N바이트 해시)를 기본값으로 쓰고 inode는 옵션으로 강등했다.
//!
//! 여기서는 `fingerprint = 첫 [`FINGERPRINT_MIN_BYTES`]바이트의 안정적 해시`([`hash_bytes`] —
//! `changes.rs`의 `record_id` 관례와 동일하게 `DefaultHasher`를 쓴다. `DefaultHasher::new()`는
//! 키가 고정이라 프로세스를 재시작해도 같은 바이트열엔 같은 값을 낸다 — 체크포인트에 저장된
//! fingerprint와 재기동 후 새로 계산한 fingerprint를 비교하는 데 필요한 성질이다). 파일이
//! `FINGERPRINT_MIN_BYTES` 미만이면 fingerprint를 만들지 않는다 — 임계에 도달할 때까지
//! **수집 보류**(Vector의 `known_small_files` 패턴). 짧은 파일들끼리 fingerprint가 충돌해
//! 서로 다른 파일을 같은 것으로 오인하는 걸 막는다. inode는 fingerprint를 만들 수 없을 때
//! (임계 미만으로 truncate된 직후 등)에만 "그래도 같은 파일인가"를 판단하는 보조 힌트로만 쓴다
//! ([`decide_change`] 참고).
//!
//! **(2) 로테이션 감지 = "닫아라"가 아니라 "열린 핸들로 EOF까지 마저 읽고 나서 닫아라".**
//! logrotate의 기본 move-create(`mv app.log app.log.1 && create app.log`)는 rename 직후에도
//! 옛 파일에 미독 데이터가 남는다 — 그리고 그건 정확히 장애 직전 마지막 로그다. 유닉스에서는
//! rename이 inode를 옮길 뿐 이미 열어 둔 fd는 계속 그 inode(옛 파일의 실제 데이터)를 가리키므로,
//! 새 파일로 갈아타기 전에 **그 fd로 EOF까지 드레인**하면 이 꼬리를 잃지 않는다([`FileTail::tick`]의
//! `Rotated` 분기, [`FileTail::drain_and_emit`]).
//!
//! **notify(inotify)는 쓰지 않는다.** inotify는 경로가 아니라 inode를 watch해서 mv+create 후
//! 옛 inode를 계속 따라간다 — 새 파일의 새 로그를 놓친다. macOS FSEvents도 "남의 파일"을 잘 못
//! 본다. 대신 1초 `tokio::time::interval` + `MissedTickBehavior::Skip`로 폴링한다
//! ([`serve_files`] — `otlp_exporter/mod.rs`·`connections.rs`의 기존 exporter task 관례와 동일).
//! `batch_max_ms = 2000`이라 1초 폴링의 지연은 배치 창에 흡수된다.
//!
//! t10(`container.rs`)이 이 모듈을 그대로 재사용한다 — [`FileTail`]은 경로 하나·라벨 하나에
//! 대해 일반화되어 있고, 라인 → [`LogLine`] 변환은 [`LineParser`] 클로저로 주입 가능하다(기본은
//! [`default_file_line_parser`]). 컨테이너 수집기는 `source`/`attrs`가 다른 자체 파서를 넣어
//! 재사용하면 된다.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use aic_common::LogLine;

use super::checkpoint::{self, CheckpointStore};
use super::DropCounters;

/// fingerprint를 만드는 데 쓰는 선두 바이트 수. 이보다 짧은 파일은 fingerprint 충돌 위험이 커서
/// 수집을 보류한다(Vector `known_small_files`와 동일한 이유).
const FINGERPRINT_MIN_BYTES: u64 = 1024;

/// 라인 문자열 → [`LogLine`] 변환 훅. `record_id`는 [`FileTail`]이 나중에 덮어쓰므로 여기서
/// 채운 값은 무시된다 — 신경 쓰지 않아도 된다.
/// 한 줄을 [`LogLine`]으로 변환한다. `None`은 **"이 줄은 버려라"** — 파서가 해석할 수 없는
/// 라인(예: container의 깨진 json-file 한 줄)을 파이프라인에 흘리지 않기 위한 것이다.
/// 버린 사실은 파서가 자기 카운터에 기록한다(여기서는 알 바 아니다).
pub type LineParser = dyn Fn(&str) -> Option<LogLine> + Send + Sync;

/// 라인 앞머리에서 `ERROR|WARN|INFO|DEBUG`를 토큰 단위로 찾는다(부분 문자열 매치가 아니다 —
/// 예: `MIRROR`가 `ERROR`로 오인되지 않는다). 앞의 최대 8개 공백 구분 토큰만 본다(타임스탬프
/// 등 앞머리를 넘어가면 검사하지 않음). 못 찾으면 `"INFO"`.
pub fn parse_severity_prefix(line: &str) -> &'static str {
    const LEVELS: [&str; 4] = ["ERROR", "WARN", "INFO", "DEBUG"];
    for word in line.split_whitespace().take(8) {
        let trimmed = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if let Some(level) = LEVELS.iter().find(|&&l| l == trimmed) {
            return level;
        }
    }
    "INFO"
}

/// 기본 라인 파서. `source = "file"`, `service` = 호출부가 준 라벨. severity는 원문(redact 전)
/// 앞머리에서 뽑고, message는 `redact(line).0`이다(원본이 데몬 경계를 넘지 않는 게 1차 방어선).
pub fn default_file_line_parser(service: impl Into<String>) -> Arc<LineParser> {
    let service = service.into();
    Arc::new(move |raw: &str| {
        let severity = parse_severity_prefix(raw).to_string();
        let (message, _report) = aic_common::redaction::redact(raw);
        // 평문 로그 파일은 어떤 줄도 버리지 않는다 — 항상 Some.
        Some(LogLine {
            source: "file".to_string(),
            service: service.clone(),
            severity,
            message,
            attrs: BTreeMap::new(),
            ts: chrono::Utc::now(),
            record_id: String::new(), // FileTail::read_and_emit이 덮어쓴다.
        })
    })
}

/// [`decide_change`]가 내리는 판정. `FileTail::tick`이 그대로 분기한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TailDecision {
    /// 아직 이 경로를 추적한 적이 없고(identity 미확립) 파일이 fingerprint 임계 미만 — 수집 보류.
    Deferred,
    /// 동일 파일 이어서 읽기.
    Continue,
    /// 동일 파일이지만 truncate됨(`size < offset`) — offset을 0으로 되돌리고 계속 추적.
    Truncated,
    /// 다른 내용(또는 이전에 추적한 적이 없어 처음 확립하는 경우) — 새 파일로 전환.
    Rotated,
}

/// 파일 identity 변화를 판정하는 순수 함수. 부작용 없이 여섯 값만으로 결정하므로 단위 테스트가
/// 실제 tempdir에서 inode 재사용을 강제하지 못해도(대부분의 파일시스템/테스트 환경에서
/// 어렵다) 이 함수에 직접 조합을 넣어 "fingerprint가 inode보다 우선한다"는 불변식을 검증할 수
/// 있다.
///
/// - `old_fingerprint`: 지금까지 추적해 온 파일의 fingerprint. 한 번도 추적한 적 없으면 `None`.
/// - `new_fingerprint`: 이번 tick에 경로를 다시 stat/read해서 계산한 fingerprint. 파일이
///   [`FINGERPRINT_MIN_BYTES`] 미만이면 `None`(계산 불가).
/// - `old_inode`/`new_inode`: 보조 힌트. fingerprint를 계산할 수 없을 때만 참조한다.
/// - `size`/`offset`: 이번 tick 기준 파일 크기와, 지금까지 읽은 바이트 오프셋.
fn decide_change(
    old_fingerprint: Option<u64>,
    new_fingerprint: Option<u64>,
    old_inode: u64,
    new_inode: u64,
    size: u64,
    offset: u64,
) -> TailDecision {
    match (old_fingerprint, new_fingerprint) {
        // 한 번도 추적한 적 없고 지금도 임계 미만 — 계속 보류.
        (None, None) => TailDecision::Deferred,
        // 한 번도 추적한 적 없지만 지금은 임계 이상 — 새로 확립(백필 규칙은 호출부가 적용).
        (None, Some(_)) => TailDecision::Rotated,
        (Some(old), Some(new)) => {
            if old == new {
                // 내용 fingerprint가 같다 — 진짜 같은 파일. size < offset이면 첫
                // FINGERPRINT_MIN_BYTES는 그대로인 채 뒷부분만 잘려나간 truncate(ftruncate로
                // 앞부분 보존한 축소)다.
                if size < offset {
                    TailDecision::Truncated
                } else {
                    TailDecision::Continue
                }
            } else {
                // ★ 핵심 ★ inode/size가 뭐라고 말하든 fingerprint가 다르면 다른 파일이다 —
                // 이게 inode 재사용을 조용한 유실 없이 잡아내는 지점이다.
                TailDecision::Rotated
            }
        }
        (Some(_), None) => {
            // 임계 미만으로 줄었다(예: `> file`로 0바이트 truncate). inode가 그대로면 같은
            // 파일이 truncate된 것으로 본다(fingerprint는 다시 임계를 넘을 때 재계산). inode가
            // 다르면(같은 자리에 다른 작은 파일이 생겼다) 로테이션이다.
            if new_inode == old_inode {
                TailDecision::Truncated
            } else {
                TailDecision::Rotated
            }
        }
    }
}

/// 안정적 해시. `changes.rs`의 `record_id` 관례와 동일하게 워크스페이스에 새 크레이트를 추가하지
/// 않기 위해 `DefaultHasher`를 쓴다 — 중요한 건 "첫 N바이트 내용 기반"이라는 성질이지 특정
/// 알고리즘이 아니다. `DefaultHasher::new()`는 키가 고정이라(문서상 randomize되지 않음) 같은
/// 바이트열은 프로세스를 재시작해도 같은 값을 낸다.
fn hash_bytes(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// `path`의 fingerprint를 계산한다. `size < FINGERPRINT_MIN_BYTES`면 `Ok(None)`(수집 보류
/// 대상). stat과 open 사이에 파일이 더 줄어드는 TOCTOU 레이스로 `read_exact`가
/// `UnexpectedEof`를 내면(드묾) 하드 에러로 올리지 않고 `Ok(None)`으로 흡수한다 — 다음 tick에
/// 다시 계산하면 그만이다.
fn compute_fingerprint(path: &std::path::Path, size: u64) -> io::Result<Option<u64>> {
    if size < FINGERPRINT_MIN_BYTES {
        return Ok(None);
    }
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; FINGERPRINT_MIN_BYTES as usize];
    match f.read_exact(&mut buf) {
        Ok(()) => Ok(Some(hash_bytes(&buf))),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

/// 파일 inode. unix가 아니면 보조 힌트를 아예 못 쓰므로 항상 0을 반환한다 — 그 경우
/// `decide_change`의 "임계 미만으로 줄었을 때 inode로 truncate/rotation을 구분"하는 분기가 항상
/// `Truncated`로 흐르지만(inode 비교가 무의미해지므로), fingerprint가 우선하는 주경로에는 영향이
/// 없다.
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// 체크포인트 값(`"{fingerprint:x}:{offset}"`)을 파싱한다. 형식이 안 맞으면 `None`(호출부가
/// "체크포인트 없음"과 동일하게 취급 — no-backfill 규칙이 적용된다).
fn parse_checkpoint_value(value: &str) -> Option<(u64, u64)> {
    let (fp_str, offset_str) = value.split_once(':')?;
    let fp = u64::from_str_radix(fp_str, 16).ok()?;
    let offset = offset_str.parse::<u64>().ok()?;
    Some((fp, offset))
}

/// 지금 추적 중인 파일의 열린 핸들 + identity + 진행 상태.
struct TrackedHandle {
    file: std::fs::File,
    /// 이 핸들이 가리키는 파일의 fingerprint. 임계 미만으로 줄어든 뒤에는(truncate) 다시 임계를
    /// 넘을 때까지 "마지막으로 알려진" 값을 그대로 들고 있는다(§ decide_change 문서 참고) —
    /// identity 기억을 truncate 구간 동안 잃지 않기 위함이다.
    fingerprint: u64,
    inode: u64,
    /// 다음에 읽어야 할 바이트 오프셋.
    offset: u64,
}

/// 파일 하나를 폴링 tail한다. 경로/라벨별로 하나씩 만든다 — 여러 경로는 [`serve_files`]가
/// `Vec<FileTail>`을 순회하며 굴린다.
pub struct FileTail {
    path: PathBuf,
    /// 체크포인트 키(`file/<label>`)와 `LogLine::service`에 쓰는 라벨.
    label: String,
    /// `record_id` 계산에 넘기는 host.
    host: String,
    parser: Arc<LineParser>,
    handle: Option<TrackedHandle>,
    /// "임계 미만 — 수집 보류" 경고를 tick마다 반복 로깅하지 않기 위한 1회성 플래그.
    deferred_warned: bool,
}

impl FileTail {
    /// 기본 파서([`default_file_line_parser`])로 만든다.
    pub fn new(path: PathBuf, label: String, host: String) -> Self {
        let parser = default_file_line_parser(label.clone());
        Self::with_parser(path, label, host, parser)
    }

    /// 라인 파서를 주입한다. t10 컨테이너 수집기가 `source`/`attrs`가 다른 자체 파서로 이
    /// 타입을 재사용하는 지점.
    pub fn with_parser(
        path: PathBuf,
        label: String,
        host: String,
        parser: Arc<LineParser>,
    ) -> Self {
        Self {
            path,
            label,
            host,
            parser,
            handle: None,
            deferred_warned: false,
        }
    }

    /// 테스트/관측용 — 아직 identity가 확립되지 않아 수집이 보류 중인지.
    #[cfg(test)]
    fn is_deferred(&self) -> bool {
        self.handle.is_none()
    }

    fn checkpoint_key(&self) -> String {
        format!("file/{}", self.label)
    }

    /// 한 번의 폴링 tick. 파일 상태를 재확인하고, 가능한 만큼 라인을 읽어 `tx`로 전달한다.
    /// 파일이 순간적으로 없으면(rename 중간 등) 조용히 넘어간다 — 다음 tick에 재시도.
    pub fn tick(
        &mut self,
        tx: &mpsc::Sender<LogLine>,
        drop_counters: &DropCounters,
        checkpoint: &CheckpointStore,
    ) -> io::Result<()> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let size = meta.len();
        let new_inode = inode_of(&meta);
        let new_fingerprint = compute_fingerprint(&self.path, size)?;

        let (old_fingerprint, old_inode, offset) = match &self.handle {
            Some(h) => (Some(h.fingerprint), h.inode, h.offset),
            None => (None, 0, 0),
        };

        match decide_change(
            old_fingerprint,
            new_fingerprint,
            old_inode,
            new_inode,
            size,
            offset,
        ) {
            TailDecision::Deferred => {
                if !self.deferred_warned {
                    tracing::warn!(
                        path = %self.path.display(),
                        size,
                        min_bytes = FINGERPRINT_MIN_BYTES,
                        "파일이 fingerprint 임계 미만 — 수집 보류"
                    );
                    self.deferred_warned = true;
                }
            }
            TailDecision::Continue => {
                self.read_and_emit(tx, drop_counters, checkpoint)?;
            }
            TailDecision::Truncated => {
                tracing::info!(path = %self.path.display(), "파일 truncate 감지 — offset 0부터 재시작");
                if let Some(h) = self.handle.as_mut() {
                    h.offset = 0;
                    if let Some(fp) = new_fingerprint {
                        h.fingerprint = fp;
                    }
                }
                self.read_and_emit(tx, drop_counters, checkpoint)?;
            }
            TailDecision::Rotated => {
                self.handle_rotation(
                    new_fingerprint,
                    new_inode,
                    size,
                    tx,
                    drop_counters,
                    checkpoint,
                )?;
            }
        }
        Ok(())
    }

    /// 로테이션(또는 최초 확립) 처리. 옛 핸들이 있으면 **EOF까지 드레인**한 뒤에야 닫는다 —
    /// 모듈 doc의 핵심 (2)번.
    fn handle_rotation(
        &mut self,
        new_fingerprint: Option<u64>,
        new_inode: u64,
        size: u64,
        tx: &mpsc::Sender<LogLine>,
        drop_counters: &DropCounters,
        checkpoint: &CheckpointStore,
    ) -> io::Result<()> {
        let had_prior_handle = self.handle.is_some();

        if let Some(mut old) = self.handle.take() {
            // 옛 fd는 rename되었거나 unlink되었어도 여전히 그 inode의 데이터를 가리킨다(유닉스
            // 시맨틱) — logrotate가 mv 직후 아직 못 읽은 "장애 직전 마지막 로그"가 바로 여기서
            // 나온다.
            self.drain_and_emit(&mut old, tx, drop_counters)?;
            // old.file은 여기서 drop되며 닫힌다.
        }

        self.deferred_warned = false;

        let Some(fingerprint) = new_fingerprint else {
            // 새 파일이 아직 fingerprint 임계 미만 — 지금은 핸들을 열지 않고 다음 tick에서
            // 재평가한다. old_fingerprint가 없는 상태로 다음 tick을 맞으므로 decide_change는
            // (None,None)→Deferred 아니면 (None,Some)→Rotated로만 갈 수 있어 안전하다.
            return Ok(());
        };

        let new_file = std::fs::File::open(&self.path)?;

        let start_offset = if had_prior_handle {
            // 진짜 로테이션 — 새 파일은 항상 처음부터 읽는다(로테이션마다 놓치는 세대가 있어도
            // "지금 있는 파일"은 통째로 본다 — 조용히 이어붙이지 않는다).
            0
        } else {
            // 이 프로세스가 이 경로를 추적하는 첫 순간이다 — 체크포인트가 있고 그 fingerprint가
            // 지금 파일과 일치하면 거기서 재개하고, 없거나 다른 세대의 것이면 **백필하지 않고**
            // 현재 크기(=지금 이 순간)부터 시작한다.
            checkpoint
                .load(&self.checkpoint_key())
                .and_then(|v| parse_checkpoint_value(&v))
                .filter(|(cp_fp, _)| *cp_fp == fingerprint)
                .map(|(_, cp_offset)| cp_offset.min(size))
                .unwrap_or(size)
        };

        self.handle = Some(TrackedHandle {
            file: new_file,
            fingerprint,
            inode: new_inode,
            offset: start_offset,
        });

        // 체크포인트 재개 시 이미 그 이후로 더 쓰였을 수 있으니 곧바로 한 번 읽어 본다.
        self.read_and_emit(tx, drop_counters, checkpoint)?;
        Ok(())
    }

    /// 현재 추적 중인 핸들(`self.handle`)에서 읽을 수 있는 만큼 읽어 emit하고, offset과
    /// 체크포인트를 갱신한다.
    fn read_and_emit(
        &mut self,
        tx: &mpsc::Sender<LogLine>,
        drop_counters: &DropCounters,
        checkpoint: &CheckpointStore,
    ) -> io::Result<()> {
        // self.handle의 가변 borrow와 self.checkpoint_key()/self.parser의 불변 borrow가
        // 겹치지 않도록, self 필드를 참조하는 계산은 handle을 빌리기 전에 먼저 끝내 둔다.
        let key = self.checkpoint_key();
        let host = self.host.clone();
        let parser = self.parser.clone();

        let Some(handle) = self.handle.as_mut() else {
            return Ok(());
        };
        let (lines, new_offset) = drain_complete_lines(&mut handle.file, handle.offset)?;
        if lines.is_empty() {
            return Ok(());
        }
        let fingerprint = handle.fingerprint;
        emit_lines(
            parser.as_ref(),
            &host,
            fingerprint,
            lines,
            tx,
            drop_counters,
        );
        handle.offset = new_offset;
        let checkpoint_value = format!("{fingerprint:x}:{}", handle.offset);

        // t9 범위: 배치가 durable해진 뒤(AckTracker::committed 반영) 저장하는 게 원칙(RFC-006
        // D9)이지만, 이 태스크는 "라인을 채널로 넘긴 시점"에 저장한다. t12에서 end-to-end ack를
        // 배선할 때 바꿀 지점:
        //   1) 이 tick에서 만든 record_id들을 이 배치가 발급받을 AckTracker::issue() seq에 매핑,
        //   2) exporter가 배치 push 성공(또는 spool append=durable) 시 AckTracker::complete(seq),
        //   3) AckTracker::committed()가 이 tick의 offset을 지난 뒤에야 save() 호출.
        // 지금은 그 배선이 없어 "넘기자마자 저장" — 프로세스가 flush 전에 죽으면 이 tick의
        // 라인이 최대 1번 재전송될 수 있다(유실은 아니다 — record_id가 파일 바이트 위치
        // 기반이라 재시작 후 재계산해도 동일해 수신측 ReplacingMergeTree가 접는다).
        if let Err(e) = checkpoint.save(&key, &checkpoint_value) {
            tracing::warn!(path = %self.path.display(), error = %e, "파일 tail 체크포인트 저장 실패");
        }
        Ok(())
    }

    /// 로테이션으로 곧 버려질 옛 핸들을 EOF까지 드레인한다. `self.handle`이 아니라 넘겨받은
    /// `handle`을 직접 조작한다 — 호출 시점엔 이미 `self.handle`에서 떼어져 있다.
    fn drain_and_emit(
        &self,
        handle: &mut TrackedHandle,
        tx: &mpsc::Sender<LogLine>,
        drop_counters: &DropCounters,
    ) -> io::Result<()> {
        let (lines, new_offset) = drain_complete_lines(&mut handle.file, handle.offset)?;
        if !lines.is_empty() {
            emit_lines(
                self.parser.as_ref(),
                &self.host,
                handle.fingerprint,
                lines,
                tx,
                drop_counters,
            );
        }
        handle.offset = new_offset;
        Ok(())
    }
}

/// `parser`로 라인을 변환하고 `record_id`를 채워 `tx.try_send`한다. 채널이 가득 차면
/// `drop_counters.by_channel_full`만 올린다 — `send().await`로 블록하지 않는다(모듈 doc의
/// 불변식, `logs/mod.rs`의 `DropCounters` 계약).
fn emit_lines(
    parser: &LineParser,
    host: &str,
    fingerprint: u64,
    lines: Vec<(u64, String)>,
    tx: &mpsc::Sender<LogLine>,
    drop_counters: &DropCounters,
) {
    for (line_offset, text) in lines {
        // 파서가 None을 주면 그 줄은 파이프라인에 닿지 않는다(깨진 라인 등). 버린 이유와
        // 카운트는 파서 쪽 책임이다 — 여기서 채널 드롭 카운터를 올리면 의미가 섞인다.
        let Some(mut line) = parser(&text) else {
            continue;
        };
        line.record_id =
            checkpoint::record_id(Some(&format!("{fingerprint:x}:{line_offset}")), host, &line);
        if tx.try_send(line).is_err() {
            drop_counters
                .by_channel_full
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `file`의 `start_offset`부터 지금 볼 수 있는 EOF까지 읽어, **마지막 개행까지만** 완결된
/// 라인으로 취급한다. 개행 없이 끝나는 꼬리(부분 라인)는 절대 소비하지 않는다 — offset을 그
/// 라인의 시작 지점 그대로 두어, 다음 tick에 이어 쓰인 나머지와 합쳐 온전히 다시 읽히게 한다
/// (폴링 tail의 유일한 진짜 함정: 쓰는 쪽이 라인 중간까지만 flush한 순간에 stat이 걸리는 경우).
///
/// 반환하는 `Vec<(u64, String)>`의 각 원소는 `(그 라인이 파일에서 시작하는 바이트 오프셋,
/// 라인 텍스트)`다. 시작 오프셋 기준인 이유: 재시작 후 같은 위치에서 다시 읽어도 각 라인의
/// `record_id`가 동일하게 재계산되어(§ `checkpoint::record_id`) 수신측 dedup이 자연스럽게
/// 성립한다.
fn drain_complete_lines(
    file: &mut std::fs::File,
    start_offset: u64,
) -> io::Result<(Vec<(u64, String)>, u64)> {
    file.seek(SeekFrom::Start(start_offset))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    let Some(last_newline) = buf.iter().rposition(|&b| b == b'\n') else {
        // 개행이 하나도 없다 — 전부 미완결 꼬리. 아무것도 소비하지 않는다.
        return Ok((Vec::new(), start_offset));
    };

    // buf[..=last_newline]만 완결된 라인들이다. '\n' 기준으로 자르면 이 슬라이스는 반드시
    // '\n'로 끝나므로 split의 마지막 원소는 항상 빈 슬라이스(구분자 뒤 아티팩트)다 — 실제
    // 라인이 아니므로 버린다. 중간의 진짜 빈 줄("\n\n")은 그대로 보존된다.
    let mut parts: Vec<&[u8]> = buf[..=last_newline].split(|&b| b == b'\n').collect();
    parts.pop();

    let mut lines = Vec::with_capacity(parts.len());
    let mut cursor = start_offset;
    for raw in parts {
        let advance = raw.len() as u64 + 1; // +1 = 소비한 '\n'
        let text = String::from_utf8_lossy(raw)
            .trim_end_matches('\r')
            .to_string();
        lines.push((cursor, text));
        cursor += advance;
    }

    Ok((lines, cursor))
}

/// 여러 파일을 1초 간격으로 폴링한다(모듈 doc — notify를 쓰지 않는 이유). `mod.rs:93-95`,
/// `connections.rs:74-75`의 기존 exporter task 관례와 동일하게 `MissedTickBehavior::Skip` +
/// 공유 shutdown watch를 쓴다.
pub async fn serve_files(
    mut tails: Vec<FileTail>,
    tx: mpsc::Sender<LogLine>,
    checkpoint: Arc<CheckpointStore>,
    drop_counters: Arc<DropCounters>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                for tail in tails.iter_mut() {
                    if let Err(e) = tail.tick(&tx, &drop_counters, &checkpoint) {
                        tracing::warn!(path = %tail.path.display(), error = %e, "file tail tick 실패");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_checkpoint() -> (tempfile::TempDir, CheckpointStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(dir.path().join("checkpoints")).unwrap();
        (dir, store)
    }

    /// fingerprint 임계(1024B)를 넘기기 위한 패딩 + 실제 라인들을 이어붙인다. 각 라인은
    /// `\n`으로 끝난다.
    fn padded_lines(lines: &[&str]) -> Vec<u8> {
        let mut content = Vec::new();
        // 실제 라인을 먼저 넣는다 — fingerprint는 첫 FINGERPRINT_MIN_BYTES바이트만 보므로,
        // 구분용 내용이 패딩 뒤(첫 1024B 밖)에 있으면 서로 다른 "세대"인데도 fingerprint가
        // 우연히 같아져 테스트가 로테이션을 감지하지 못한다.
        for line in lines {
            content.extend_from_slice(line.as_bytes());
            content.push(b'\n');
        }
        // 임계를 확실히 넘기기 위한 패딩 라인.
        while content.len() < FINGERPRINT_MIN_BYTES as usize {
            content.extend_from_slice(b"padding-line-to-reach-fingerprint-threshold\n");
        }
        content
    }

    fn append(path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    fn recv_all(rx: &mut mpsc::Receiver<LogLine>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(line) = rx.try_recv() {
            out.push(line.message);
        }
        out
    }

    // ── decide_change: 순수 함수 단위 테스트 ─────────────────────────────

    #[test]
    fn decide_change_continue_when_fingerprint_unchanged_and_grown() {
        assert_eq!(
            decide_change(Some(1), Some(1), 10, 10, 2000, 1000),
            TailDecision::Continue
        );
    }

    #[test]
    fn decide_change_truncated_when_same_fingerprint_but_size_shrank() {
        // 같은 fingerprint(첫 1024B 보존) + size < offset → ftruncate로 뒷부분만 잘린 케이스.
        assert_eq!(
            decide_change(Some(1), Some(1), 10, 10, 500, 1500),
            TailDecision::Truncated
        );
    }

    #[test]
    fn decide_change_truncated_when_below_threshold_same_inode() {
        // 임계 미만으로 줄었지만(fingerprint 계산 불가) inode는 그대로 — truncate로 간주.
        assert_eq!(
            decide_change(Some(1), None, 10, 10, 0, 1500),
            TailDecision::Truncated
        );
    }

    #[test]
    fn decide_change_rotated_when_inode_reused_but_fingerprint_differs() {
        // ★ DoD 3 핵심 ★ inode가 같고(재사용) size >= offset이라 "변화 없음"처럼 보이지만,
        // fingerprint가 다르면 무조건 Rotated여야 한다 — 이게 이 태스크의 존재 이유다.
        assert_eq!(
            decide_change(Some(1), Some(2), 10, 10, 5000, 100),
            TailDecision::Rotated
        );
    }

    #[test]
    fn decide_change_rotated_when_inode_differs_and_below_threshold() {
        assert_eq!(
            decide_change(Some(1), None, 10, 99, 10, 1500),
            TailDecision::Rotated
        );
    }

    #[test]
    fn decide_change_deferred_when_never_tracked_and_below_threshold() {
        assert_eq!(
            decide_change(None, None, 0, 10, 10, 0),
            TailDecision::Deferred
        );
    }

    #[test]
    fn decide_change_rotated_when_never_tracked_and_now_above_threshold() {
        assert_eq!(
            decide_change(None, Some(1), 0, 10, 2000, 0),
            TailDecision::Rotated
        );
    }

    // ── FileTail 통합 테스트(DoD 1-9) ────────────────────────────────────

    /// DoD 1: mv+create 로테이션 — 옛 핸들이 EOF까지 드레인된 뒤 새 파일로 전환. 꼬리 유실 0.
    #[test]
    fn rotation_move_create_drains_tail_before_switching() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("app.log");
        std::fs::write(&path, padded_lines(&[])).unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string());

        // 최초 tick: 체크포인트 없음 → 백필 없이 offset=size로 확립. 아무것도 emit 안 됨.
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert!(
            recv_all(&mut rx).is_empty(),
            "최초 확립은 백필 없이 시작해야 함"
        );

        // mv 직전, 아직 읽히지 않은 "장애 직전 마지막 로그"를 남긴다.
        append(&path, b"LAST-LINE-BEFORE-MV\n");

        // rotate: mv + create(새 세대는 다른 내용으로, 임계를 넘기도록 패딩).
        let rotated = dir.path().join("app.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, padded_lines(&["FIRST-LINE-OF-NEW-GEN"])).unwrap();

        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        let got = recv_all(&mut rx);
        assert!(
            got.iter().any(|m| m.contains("LAST-LINE-BEFORE-MV")),
            "로테이션 직전 미독 라인이 드레인되어야 함: {got:?}"
        );
        assert!(
            got.iter().any(|m| m.contains("FIRST-LINE-OF-NEW-GEN")),
            "새 세대 파일도 처음부터 읽혀야 함: {got:?}"
        );
    }

    /// DoD 2: truncate(`> file`) — size < offset → offset 0부터 다시.
    #[test]
    fn truncate_resets_offset() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("app.log");
        std::fs::write(&path, padded_lines(&[])).unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string());

        tail.tick(&tx, &drop_counters, &checkpoint).unwrap(); // 확립, offset=size
        recv_all(&mut rx);

        append(&path, b"pre-truncate-line\n");
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert_eq!(recv_all(&mut rx), vec!["pre-truncate-line".to_string()]);

        // `> file`과 동일 효과: 같은 경로를 O_TRUNC로 다시 씀(같은 inode, 크기 0).
        std::fs::write(&path, b"").unwrap();
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert!(
            recv_all(&mut rx).is_empty(),
            "truncate 직후엔 파일이 비어 있으니 아무것도 emit되면 안 됨"
        );

        std::fs::write(&path, b"post-truncate-line\n").unwrap();
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert_eq!(
            recv_all(&mut rx),
            vec!["post-truncate-line".to_string()],
            "truncate 이후 offset이 0부터 다시 시작해야 새 내용을 그대로 읽는다"
        );
    }

    /// DoD 3: 순수 함수 레벨(위 decide_change_rotated_when_inode_reused_but_fingerprint_differs)로
    /// 이미 검증했다. 여기서는 FileTail이 실제로 fingerprint 변화를 감지해 offset 0부터 다시
    /// 읽는 경로(로테이션 처리)가 유실 없이 동작함을 통합 테스트로 한 번 더 확인한다.
    #[test]
    fn inode_reuse_like_content_swap_is_detected_and_restarts_from_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("app.log");
        std::fs::write(&path, padded_lines(&["gen0-line"])).unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string());
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        recv_all(&mut rx);

        // 같은 경로에, 완전히 다른 내용으로 파일을 교체(재사용된 inode를 흉내). 같은 크기대에
        // 있어도(>= 이전 offset) 내용이 다르므로 fingerprint가 달라져야 한다.
        std::fs::write(&path, padded_lines(&["gen1-different-content"])).unwrap();
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        let got = recv_all(&mut rx);
        assert!(
            got.iter().any(|m| m.contains("gen1-different-content")),
            "내용이 다르면 새 파일로 인식해 offset 0부터 다시 읽어야 함: {got:?}"
        );
    }

    /// DoD 4: 개행 없는 꼬리는 offset 미진전, 다음 tick에 온전히 읽힌다.
    #[test]
    fn partial_line_not_advanced() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("app.log");
        std::fs::write(&path, padded_lines(&[])).unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string());
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        recv_all(&mut rx);

        append(&path, b"complete-line\nPARTIAL-NO-NEWLINE-YET");
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert_eq!(
            recv_all(&mut rx),
            vec!["complete-line".to_string()],
            "개행 없는 꼬리는 이번 tick에 나오면 안 됨"
        );

        append(&path, b"-NOW-DONE\n");
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert_eq!(
            recv_all(&mut rx),
            vec!["PARTIAL-NO-NEWLINE-YET-NOW-DONE".to_string()],
            "다음 tick엔 이어붙은 내용이 온전한 한 줄로 읽혀야 함"
        );
    }

    /// DoD 5: 1024B 미만이면 수집 보류, 임계 도달 후 수집 시작.
    #[test]
    fn file_under_1024_bytes_is_deferred() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("small.log");
        std::fs::write(&path, b"tiny-line\n").unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "small".to_string(), "host-a".to_string());

        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert!(
            recv_all(&mut rx).is_empty(),
            "임계 미만이면 아무것도 읽지 않아야 함"
        );
        assert!(
            tail.is_deferred(),
            "임계 미만이면 identity가 확립되면 안 됨"
        );

        // 임계를 넘긴다.
        std::fs::write(&path, padded_lines(&["now-above-threshold"])).unwrap();
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert!(!tail.is_deferred(), "임계 도달 후엔 추적이 시작되어야 함");
    }

    /// DoD 6: tick 사이에 로테이션이 2번 일어나 한 세대를 완전히 건너뛰어도, 유실을 인지하고
    /// (조용히 이어붙이지 않고) 새 파일부터 다시 읽는다.
    #[test]
    fn rotation_twice_between_ticks_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("app.log");
        std::fs::write(&path, padded_lines(&["gen0-line"])).unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string());
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        recv_all(&mut rx);

        // tick 사이에 두 세대가 지나간다 — gen1은 tail이 한 번도 못 본 채 사라진다.
        std::fs::rename(&path, dir.path().join("app.log.1")).unwrap();
        std::fs::write(&path, padded_lines(&["gen1-line-never-seen"])).unwrap();
        std::fs::rename(&path, dir.path().join("app.log.2")).unwrap();
        std::fs::write(&path, padded_lines(&["gen2-line-current"])).unwrap();

        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        let got = recv_all(&mut rx);
        assert!(
            !got.iter().any(|m| m.contains("gen1-line-never-seen")),
            "건너뛴 세대 내용이 섞여 들어가면 안 됨: {got:?}"
        );
        assert!(
            got.iter().any(|m| m.contains("gen2-line-current")),
            "현재 세대 파일부터는 정상적으로 읽혀야 함: {got:?}"
        );
    }

    /// DoD 7: 체크포인트 없으면 기존 내용은 안 읽고 이후 추가분부터.
    #[test]
    fn no_backfill_without_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("app.log");
        // FileTail을 만들기 전부터 이미 내용이 쌓여 있던 파일(예: aicd 최초 설치 시 /var/log).
        std::fs::write(&path, padded_lines(&["pre-existing-old-content"])).unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string());

        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert!(
            recv_all(&mut rx).is_empty(),
            "체크포인트 없이 시작하면 기존 내용을 백필하면 안 됨"
        );

        append(&path, b"new-line-after-start\n");
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();
        assert_eq!(
            recv_all(&mut rx),
            vec!["new-line-after-start".to_string()],
            "시작 이후 추가분만 읽혀야 함"
        );
    }

    /// DoD 8: 채널이 가득 차면 try_send가 실패하고 by_channel_full만 오르며, 수집기는 막히지
    /// 않는다.
    #[test]
    fn channel_full_drops_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let (_cp_dir, checkpoint) = test_checkpoint();
        let path = dir.path().join("app.log");
        std::fs::write(&path, padded_lines(&[])).unwrap();

        // 용량 1 — 아무도 recv하지 않으므로 두 번째 try_send부터 실패한다.
        let (tx, _rx) = mpsc::channel(1);
        let drop_counters = DropCounters::new();
        let mut tail = FileTail::new(path.clone(), "app".to_string(), "host-a".to_string());
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap(); // 확립, offset=size, emit 없음

        append(&path, b"line-a\nline-b\nline-c\n");
        tail.tick(&tx, &drop_counters, &checkpoint).unwrap();

        assert!(
            drop_counters.by_channel_full.load(Ordering::Relaxed) >= 2,
            "3줄 중 채널 용량(1)을 넘는 최소 2줄은 드롭 카운트되어야 함"
        );
    }

    /// DoD 9: severity는 라인 앞머리에서 파싱하고, message는 redact를 거친다.
    #[test]
    fn severity_parsed_from_line_prefix() {
        assert_eq!(parse_severity_prefix("ERROR something failed"), "ERROR");
        assert_eq!(parse_severity_prefix("[WARN] disk low"), "WARN");
        assert_eq!(
            parse_severity_prefix("2024-01-01T00:00:00Z DEBUG hello"),
            "DEBUG"
        );
        assert_eq!(
            parse_severity_prefix("no level token here at all"),
            "INFO",
            "레벨 토큰이 없으면 INFO로 폴백"
        );
        assert_eq!(
            parse_severity_prefix("MIRROR sync completed"),
            "INFO",
            "부분 문자열(MIRROR가 ERROR를 포함하지 않음에도)로 오인하면 안 됨"
        );
    }

    #[test]
    fn message_is_redacted() {
        let parser = default_file_line_parser("app");
        // 평문 파일 파서는 어떤 줄도 버리지 않는다 — 항상 Some.
        let line = parser("ERROR leaked AKIAABCDEFGHIJKLMNOP in config")
            .expect("평문 파일 파서는 라인을 버리지 않는다");
        assert!(
            !line.message.contains("AKIAABCDEFGHIJKLMNOP"),
            "AWS access key 패턴은 redact되어야 함: {}",
            line.message
        );
        assert_eq!(line.source, "file");
        assert_eq!(line.service, "app");
        assert_eq!(line.severity, "ERROR");
    }
}
