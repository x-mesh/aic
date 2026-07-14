//! chat/agent 행위를 aicd로 넘기는 fire-and-forget 송신기 (OTLP `aic.agent` scope).
//!
//! chat은 단명하는 프로세스라 collector 연결·spool·backoff를 직접 들 수 없다. 그래서 행위를
//! aicd에 넘기고, 상주 데몬의 exporter가 무유실 전송을 책임진다 — shell hook이 command를 넘기는
//! 구조와 같다.
//!
//! **sync 블로킹**으로 구현한다. 호출부(`run_command::execute_with_corr`, `risk_guard` 차단
//! 경로, diagnose 스캔)가 전부 sync라 async 런타임 핸들을 가정할 수 없고, `crate::audit::append`가
//! 이미 같은 성격(동기 best-effort 기록)이라 관례도 맞다. 소켓 I/O에 짧은 timeout을 걸어
//! aicd가 느리거나 죽어 있어도 chat이 멈추지 않게 한다.
//!
//! **실패는 전부 무시한다**(silent skip). aicd 미실행은 정상 상태이고, 텔레메트리 송신 실패가
//! 사용자의 chat 흐름을 방해해서는 안 된다.
//!
//! **redaction은 여기서 한다** — summary/attrs 값이 프로세스 경계를 넘기 전에 마스킹한다.
//! 인코딩 단계(`logs_proto`)에서 한 번 더 redact되지만(idempotent), 원본이 데몬으로 넘어가지
//! 않게 하는 게 1차 방어선이다.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use aic_common::{
    encode_frame, AgentEvent, IpcRequest, IpcResponse, AGENT_KIND_FINDING_CREATED,
    AGENT_KIND_RISK_DENIED, AGENT_KIND_SNAPSHOT_RECORDED, AGENT_KIND_TOOL_RUN_COMMAND,
};

/// 소켓 연결/송신/응답 대기 상한. chat 흐름을 막지 않도록 짧게 잡는다 — aicd는 로컬 UDS라
/// 정상 상황에서 밀리초 단위로 끝난다.
const IO_TIMEOUT: Duration = Duration::from_millis(300);

/// 응답 본문 상한 — 우리가 읽는 응답(Pong/ExporterStatus)은 수백 바이트다. 손상된 길이
/// 헤더가 거대한 할당으로 이어지지 않게 막는다.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// `/record now <메모>`가 보낼 수 있는 메모 상한(바이트). 사람이 손으로 남기는 관찰 메모치고는
/// 넉넉하되(64KiB), IPC 프레임 상한(`aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES`, 16MiB)에는 한참
/// 못 미친다 — 1MB 메모 같은 병적 입력이 프레임 상한에 닿는 일을 여기서 미리 막는다(F16).
pub const MEMO_MAX_BYTES: usize = 64 * 1024;

/// agent가 셸 명령을 실행했다. 시스템을 바꿨을 수 있는 유일한 도구라 항상 보낸다.
/// 차단된 명령은 여기가 아니라 [`risk_denied`]로 간다.
pub fn tool_run_command(command: &str, exit_code: Option<i32>, duration_ms: u64, cwd: &str) {
    let mut attrs = BTreeMap::new();
    attrs.insert(
        "exit_code".to_string(),
        exit_code.map_or_else(|| "unknown".to_string(), |c| c.to_string()),
    );
    attrs.insert("duration_ms".to_string(), duration_ms.to_string());
    attrs.insert("cwd".to_string(), cwd.to_string());
    // 실패한 명령은 RCA에서 먼저 봐야 하므로 severity를 올린다.
    let severity = match exit_code {
        Some(0) => "INFO",
        _ => "ERROR",
    };
    emit(AGENT_KIND_TOOL_RUN_COMMAND, command, severity, attrs);
}

/// risk_guard가 명령을 차단했다 — 위험한 시도가 있었다는 보안 신호라 항상 WARN이다.
pub fn risk_denied(command: &str, risk_level: &str, rule: Option<&str>) {
    let mut attrs = BTreeMap::new();
    attrs.insert("risk_level".to_string(), risk_level.to_string());
    if let Some(rule) = rule {
        attrs.insert("rule".to_string(), rule.to_string());
    }
    emit(AGENT_KIND_RISK_DENIED, command, "WARN", attrs);
}

/// 진단이 finding을 만들었다. `severity`는 이미 OTLP 표기(ERROR/WARN/INFO)로 매핑된 값이다.
pub fn finding_created(probe_id: &str, severity: &str, message: &str) {
    let mut attrs = BTreeMap::new();
    attrs.insert("probe_id".to_string(), probe_id.to_string());
    emit(AGENT_KIND_FINDING_CREATED, message, severity, attrs);
}

/// 사람이 "지금 이 순간을 남긴다"고 판단해 기록한다 — 임계에 안 걸려도 사람이 이상하다고
/// 느낀 순간을 남기는 경로. severity는 항상 INFO(사건이 아니라 사람의 관찰 기록이다).
///
/// **`attrs` 키에 `exit_code`/`cwd`/`duration_ms`를 쓰지 마라** — 서버의 `EVENT_MAPPED_KEYS`가
/// 이 키들을 컬럼으로 흡수하며 attrs에서 지운다.
///
/// sync 호출부(CLI `aic snapshot record --memo`)용. async 호출부(chat `handle_record`)는 tokio
/// worker를 막지 않는 [`snapshot_recorded_async`]를 쓴다 — 병적 입력 처리는 둘 다
/// [`prepare_snapshot_event`] 하나를 지난다.
///
/// **한 번만** 정제된 메모 — 정제 결과와 "그때 잘렸는가"를 **같이** 들고 다닌다.
///
/// 왜 타입이 필요한가(뼈아픈 교훈): 예전엔 `sanitize_memo(&str) -> (String, bool)`를 호출부가 한 번,
/// 전송부가 또 한 번 불렀다. 두 번째 호출에는 **이미 잘린 문자열**이 들어오니 "잘렸다"고 판정할
/// 근거가 없고, `memo_truncated`는 실제 경로에서 **항상 false**였다. 단위 테스트는 전송부를 직접
/// 불러서 통과했지만 **진짜 호출 경로는 그 코드를 그렇게 지나가지 않았다** — "고친 줄 알았는데
/// 실제로는 작동하지 않는" 바로 그 부류다.
///
/// 절단 여부는 **정제 순간에만 알 수 있는 정보**다. 나중에 재계산하려 하면 이미 소실됐다. 그래서
/// 값과 함께 실어 나르고, 타입으로 **재정제를 불가능하게** 만든다(`&str`을 받는 전송 API를 없앴다).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memo {
    /// 정제된 본문(제어문자 제거 + UTF-8 경계 보존 절단). 비어 있지 않음이 보장된다.
    text: String,
    /// 정제 과정에서 상한을 넘겨 잘렸는가.
    truncated: bool,
}

impl Memo {
    /// 원문을 **딱 한 번** 정제한다. 정제 후 비면(F15) `None` — 보낼 것도 저장할 것도 없다.
    ///
    /// 여기서 하는 일:
    /// - **제어문자·ANSI escape 제거**(F17) — 수신측(터미널로 events를 훑어보는 사람)의 화면을 깨지
    ///   않게. 개행/탭은 메모의 정상적인 부분이라 남긴다. ESC(`\x1b`)만 지워도 뒤따르는 CSI
    ///   바이트열(`[33m` 등)은 평문으로 남아 터미널이 시퀀스로 해석하지 않는다.
    /// - **UTF-8 경계 보존 절단**(F16) — IPC 프레임 상한(16MiB)에 닿지 않게 훨씬 낮은 선에서 자른다.
    pub fn sanitize(raw: &str) -> Option<Self> {
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .collect();
        let (text, truncated) = crate::agent::tool_record::cap_str(&cleaned, MEMO_MAX_BYTES);
        if text.trim().is_empty() {
            return None;
        }
        Some(Self { text, truncated })
    }

    /// 정제된 본문 — **로컬 저장과 원격 전송이 이 하나의 값을 공유한다**(둘이 각자 정규화하면
    /// 저장된 메모와 전송된 메모가 달라진다).
    pub fn text(&self) -> &str {
        &self.text
    }

    /// 상한을 넘겨 잘렸는가. 호출부가 사용자에게 알리는 데 쓴다.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// 반환값 = **이 메모가 실제로 어떻게 됐는가**([`RecordOutcome`]).
///
/// **결론은 전송 결과에서 나온다** — `dispatch`가 실패하면 어떤 probe 결과와도 무관하게 `NotSent`다.
///
/// 빈 메모(F15)는 [`Memo::sanitize`]가 `None`을 내며 이 함수에 **도달조차 하지 않는다** — 그래서
/// 여기서 다시 걸러낼 필요가 없다(타입이 불변식을 지킨다).
pub fn snapshot_recorded(memo: &Memo, attrs: BTreeMap<String, String>) -> RecordOutcome {
    let ev = build_snapshot_event(memo, attrs);
    // 먼저 **보내고**, 그 결과로 결론을 낸다. 상태 조회는 데몬이 받아들였을 때만 의미가 있으므로
    // 아니면 IPC를 한 번 더 걸지도 않는다.
    let sent = dispatch(ev);
    let status = matches!(sent, SendResult::Accepted)
        .then(exporter_status)
        .flatten();
    classify_outcome(sent, status.as_ref())
}

/// [`snapshot_recorded`]의 async 판(chat `/record now <메모>`). 전송을 **async IPC**로 한다 —
/// 이유는 [`query_async`] 문서 참고(sync IPC를 async에서 그냥 부르면 tokio worker가 막힌다).
pub async fn snapshot_recorded_async(
    memo: &Memo,
    attrs: BTreeMap<String, String>,
) -> RecordOutcome {
    let ev = build_snapshot_event(memo, attrs);
    let sent = dispatch_async(ev).await;
    let status = if matches!(sent, SendResult::Accepted) {
        exporter_status_async().await
    } else {
        None
    };
    classify_outcome(sent, status.as_ref())
}

/// 메모가 잘렸을 때 사용자에게 보여줄 한 줄(chat·CLI 공용 — 두 진입점이 각자 문구를 지으면 한쪽만
/// 고치고 잊는다).
pub fn memo_truncated_notice() -> String {
    format!(
        "ℹ 메모가 너무 길어 {}KiB에서 잘렸습니다(뒷부분은 저장·전송되지 않습니다).",
        MEMO_MAX_BYTES / 1024
    )
}

/// 정제된 메모로 보낼 이벤트를 만든다. **재정제하지 않는다** — 절단 여부는 [`Memo`]가 들고 온 값을
/// 그대로 쓴다(다시 계산하면 이미 잘린 문자열을 보게 되어 영영 false다).
///
/// 잘렸으면 **`memo_truncated` attr로 표시**한다 — 뒤가 잘린 줄 모르는 채 나가면, 나중에 그 이벤트를
/// 보는 사람이 잘린 문장을 원문으로 읽는다.
fn build_snapshot_event(memo: &Memo, mut attrs: BTreeMap<String, String>) -> AgentEvent {
    if memo.truncated() {
        attrs.insert("memo_truncated".to_string(), "true".to_string());
    }
    snapshot_event(memo.text(), attrs)
}

/// `snapshot_recorded`가 보낼 이벤트를 만든다. kind/severity를 **인자로 받지 않고 본문에
/// 고정**한다 — 그래야 테스트가 이 두 값을 주입하지 않고 결과만 검증할 수 있다(회귀를 실제로 잡는다).
fn snapshot_event(memo: &str, attrs: BTreeMap<String, String>) -> AgentEvent {
    build_event(AGENT_KIND_SNAPSHOT_RECORDED, memo, "INFO", attrs)
}

/// 방금 보낸 메모가 **실제로 어떻게 됐는가** — 사전 관찰이 아니라 **사후 결과**다.
///
/// 예전 모델(`RemoteRecord`)은 보내기 **전에** exporter 상태를 probe해 "잘 갈 것 같다"를
/// "갔다"로 단언했다. 그건 지난 라운드에 고친 거짓말(로컬 저장 성공을 알지도 못한 채 단언)과
/// **똑같은 오류가 한 겹 아래 있던 것**이다. 사용자가 알고 싶은 건 "exporter가 대체로 건강한가"가
/// 아니라 **"내가 방금 남긴 이 메모가 어떻게 됐나"**다.
///
/// 그래서 결론의 근거를 뒤집었다:
/// - **"aicd가 받았다"는 오직 전송 결과에서만 나온다**(`dispatch`의 반환값).
/// - 구독자 유무(exporter/agent exporter 꺼짐)는 **보내기 전에도 참인 사실**이라 probe해도 정직하다
///   — "이 이벤트는 받는 쪽이 없어 버려진다"는 단언은 config 상태만으로 성립한다.
/// - **누적 카운터(`spool_dropped`)는 쓰지 않는다.** 그건 "과거에 한 번이라도 버린 적 있음"이라,
///   현재 상태로 읽으면 한 번 드롭된 이후 **영원히** "유실 중"이라고 오보한다. 전송 결과가 진실을
///   말해 주는데 누적 카운터로 추측할 이유가 없다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    /// aicd가 **받아들였고**(성공 응답) 받아 갈 구독자도 있다.
    ///
    /// **"서버에 도착했다"는 뜻이 아니다** — 우리가 동기적으로 알 수 있는 최대치는 여기까지다
    /// ([`SendResult`] 문서의 "우리가 알 수 있는 것의 천장" 참고). aicd가 이후 collector로 push하는
    /// 과정은 비동기이고, 실패하면 spool에 쌓였다가 나중에 드레인된다.
    ///
    /// `backlog` = 지금 spool에 밀려 있는 배치 수. **단언이 아니라 관찰**이다. `spool_batches`는
    /// 누적이 아니라 **현재 적재량**이라 드레인되면 줄어든다(`spool_dropped`와 다른 점이다).
    Delivered { backlog: u64 },
    /// aicd가 받아들였지만 **구독 상태를 확인하지 못했다**(status 조회 실패). 도달 여부를 **모른다**.
    ///
    /// `Delivered`로 뭉개면 **모르는 것을 안다고 말하는 것**이다. 이 라운드에서 걸린 바로 그 종류의
    /// 거짓말이라, 모름은 모름으로 남긴다.
    Unknown,
    /// **보내지 못했다** — aicd 미실행·응답 없음·timeout. 이건 probe가 아니라 **전송 실패 그 자체**다.
    NotSent,
    /// 소켓으로 보내는 데는 성공했지만 **데몬이 명시적으로 거절했다**(`IpcResponse::Error`, 또는
    /// 알 수 없는 응답). 메모는 버려졌다.
    ///
    /// "보냈다"(전송 계층의 사실)와 "받아들여졌다"(데몬의 사실)는 **다른 명제**다. 예전엔 소켓 write가
    /// 성공하기만 하면 성공으로 세서, 데몬이 거절해도 "기록됐습니다"라고 말했다.
    Rejected(String),
    /// aicd는 받았지만 exporter **전체**가 꺼져 있어(`[aicd.exporter] enabled = false`) 구독자가
    /// 없다 — publish된 이벤트는 그대로 버려진다. **설정을 켜면 해결된다.**
    DroppedExporterOff,
    /// aicd는 받았지만 **agent exporter가 config에서 꺼져 있어**(`agent_enabled = false`) 구독자가
    /// 없다. 다른 signal(host metrics 등)은 멀쩡히 나가고 있어서 **가장 눈치채기 어려운 유실**이다.
    /// **설정을 켜면 해결된다.**
    DroppedAgentExporterOff,
    /// **설정은 켜져 있는데 agent exporter task가 떠 있지 않다** — endpoint 오류·spool 실패로 기동
    /// 실패했거나, 떴다가 죽었다.
    ///
    /// [`DroppedAgentExporterOff`](Self::DroppedAgentExporterOff)와 반드시 구분해야 한다: 여기서
    /// "`agent_enabled = true`로 켜세요"라고 안내하면 **이미 켜 둔 사용자**가 시키는 대로 해도 안
    /// 고쳐진다(오진). 진짜 이유는 aicd 로그에 있다.
    AgentExporterDown,
}

/// 원격 기록의 최종 판정 — 안내 문구를 조립할 때 "실패인가"를 **문구 유무가 아니라 이 값으로** 가른다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteVerdict {
    /// 구독자가 받아 갔다(밀려 있어도 지연일 뿐 유실은 아니다).
    Reaches,
    /// 도달 여부를 모른다 — 실패라고 단정할 수도, 성공이라 말할 수도 없다.
    Unknown,
    /// 서버에 남지 않는다(전송 실패·거절·구독자 없음).
    Lost,
}

/// IPC **전송 결과** — "소켓에 썼다"가 아니라 "데몬이 받아들였다"를 구분한다.
///
/// **우리가 알 수 있는 것의 천장**(정직하게 적어 둔다 — 이 위로 더 단언하면 또 거짓말이 된다):
/// 성공 응답(`Pong`)이 증명하는 것은 "aicd가 이벤트를 받아 `AgentEventBus`에 publish했다"까지다.
/// 그 아래로는 우리가 동기적으로 알 수 없는 것이 두 겹 더 있다 —
/// (1) `AgentEventBus::publish`는 구독자가 0이면 조용히 버린다(그래서 구독자 유무를 status로 따로
///     확인한다), (2) 구독자가 있어도 broadcast는 lossy라 폭주 시 `Lagged`로 유실될 수 있고, 이후
///     collector push는 비동기다.
/// 그래서 최선의 결론은 [`RecordOutcome::Delivered`]("받아들여졌고 받아 갈 구독자가 있다")이지
/// "서버에 있다"가 아니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendResult {
    /// 데몬이 성공 응답을 돌려줬다(= 받아서 bus에 publish했다).
    Accepted,
    /// 데몬이 명시적으로 거절했거나(`Error`) 알 수 없는 응답을 줬다.
    Rejected(String),
    /// 소켓 자체가 안 됐다(미실행·timeout·프레이밍 오류).
    Failed,
}

impl RecordOutcome {
    /// 사용자에게 보여줄 한 줄 안내. 완전한 성공이면 `None`(조용한 성공 — 잘 된 걸 떠들지 않는다).
    /// 스타일(색/아이콘)은 호출부가 입힌다(chat은 note, CLI는 dim stderr).
    ///
    /// **로컬 스냅샷 성공 여부를 여기서 주장하지 않는다** — 그건 이 함수가 알 수 없는 사실이다.
    /// 원격 결과만 말하고, 로컬 사실은 호출부가 실제 결과로 합친다(`session::record_remote_notice`).
    pub fn notice(&self) -> Option<String> {
        match self {
            // 전송 수용 + 구독자 있음 + spool 비어 있음 = 할 말 없음.
            RecordOutcome::Delivered { backlog: 0 } => None,
            // 갔지만 아직 collector에 못 닿아 디스크에 쌓여 있다 — "서버에서 이미 보인다"고
            // 오해하지 않도록 관찰 사실을 덧붙인다(유실은 아니다).
            RecordOutcome::Delivered { backlog } => Some(format!(
                "메모를 aicd에 전달했습니다. 다만 지금 collector에 닿지 못해 spool에 {backlog}개 \
                 배치가 밀려 있어, 서버 반영이 지연될 수 있습니다(복구되면 전송됩니다)."
            )),
            RecordOutcome::Unknown => Some(
                "메모를 aicd에 전달했지만 exporter 상태를 확인하지 못해 **서버 도달 여부는 알 수 \
                 없습니다**."
                    .to_string(),
            ),
            RecordOutcome::NotSent => Some(
                "원격 전송 실패(aicd 미실행·응답 없음) — 이 메모는 서버에 남지 않습니다."
                    .to_string(),
            ),
            RecordOutcome::Rejected(why) => Some(format!(
                "aicd가 이 메모를 거절했습니다({why}) — 서버에 남지 않습니다."
            )),
            // 주의: aicd는 `enabled=true`라도 **endpoint가 비어 있으면** exporter를 아예 띄우지 않고
            // 기본 status(`enabled: false`)를 돌려준다. 즉 이 분기는 "설정을 껐다"와 "켰는데 endpoint가
            // 없다" 둘 다에서 온다 — 그래서 "켜세요"만 말하면 endpoint를 빠뜨린 사용자에게 오진이 된다.
            // 둘 다 짚어 준다(가장 저렴한 정직).
            RecordOutcome::DroppedExporterOff => Some(
                "aicd는 받았지만 OTLP exporter가 돌고 있지 않아 이 메모는 버려집니다 — \
                 config `[aicd.exporter]`의 `enabled = true`와 `endpoint` 설정을 확인하세요."
                    .to_string(),
            ),
            RecordOutcome::DroppedAgentExporterOff => Some(
                "aicd는 받았지만 OTLP agent exporter가 config에서 꺼져 있어 이 메모는 버려집니다 — \
                 config `[aicd.exporter] agent_enabled = true`로 켜세요."
                    .to_string(),
            ),
            RecordOutcome::AgentExporterDown => Some(
                "aicd는 받았지만 OTLP agent exporter가 떠 있지 않습니다(설정은 켜져 있음) — \
                 기동 실패했거나 죽은 것이니 **aicd 로그를 확인하세요**. 이 메모는 서버에 \
                 남지 않았을 수 있습니다."
                    .to_string(),
            ),
        }
    }

    /// 원격 판정. **`notice()` 유무로 성패를 가르지 마라** — 밀림(Delivered{backlog>0})은 안내가
    /// 있지만 유실이 아니고, Unknown은 실패가 아니라 모름이다.
    ///
    /// **왜 `AgentExporterDown`이 `Lost`가 아니라 `Unknown`인가**: 우리가 관측한 건 "publish 직후
    /// 시점에 구독자가 없다"이지 "publish 순간에 없었다"가 아니다. task가 방금 죽은 경우라면 이벤트는
    /// 죽기 전에 소비됐을 수도 있다 — **한 번의 관측으로 유실을 확정할 수 없다.** 반면 config가
    /// 꺼져 있는 경우(`Dropped*Off`)는 애초에 구독자가 존재한 적이 없으므로 `Lost`가 사실이다.
    /// 모르는 것은 모른다고 하고, 아는 것만 단언한다.
    pub fn verdict(&self) -> RemoteVerdict {
        match self {
            RecordOutcome::Delivered { .. } => RemoteVerdict::Reaches,
            // 도달 여부를 확인할 수 없는 두 경우 — 단정하지 않는다.
            RecordOutcome::Unknown | RecordOutcome::AgentExporterDown => RemoteVerdict::Unknown,
            // 구독자가 애초에 없었음이 확실한 경우들.
            RecordOutcome::NotSent
            | RecordOutcome::Rejected(_)
            | RecordOutcome::DroppedExporterOff
            | RecordOutcome::DroppedAgentExporterOff => RemoteVerdict::Lost,
        }
    }
}

/// **실제 전송 결과**(`sent`)와 exporter 구독 상태(`status`)를 합쳐 사후 결과를 낸다
/// (순수 함수 — 소켓 없이 테스트 가능).
///
/// 결론의 근거가 무엇인지가 이 함수의 전부다:
/// - **보내지 못했으면**(`Failed`) 무조건 [`NotSent`](RecordOutcome::NotSent)다. exporter가 아무리
///   건강해 보여도, 보내지 못한 메모는 서버에 없다.
/// - **데몬이 거절했으면**(`Rejected`) 소켓 write가 성공했어도 실패다. "보냈다"는 전송 계층의
///   사실이지 "받아들여졌다"는 사실이 아니다 — 이 둘을 뭉개면 데몬이 거절한 메모를 "기록됐다"고
///   말하게 된다.
/// - 받아들여졌다면, 그걸 **받아 갈 구독자가 있는지**를 본다. 구독자 없음(exporter/agent exporter가
///   안 떠 있음)은 config·task 상태의 사실이라 probe로 단언해도 정직하다.
/// - `backlog`(현재 spool 적재량)는 **관찰로만** 싣는다 — 지연이지 유실이 아니다.
///
/// `agent_enabled`가 `None`(구버전 aicd — 이 필드를 모른다)이면 **경고하지 않는다**: 모름을
/// "꺼짐"으로 읽으면 멀쩡히 동작하는 구버전 사용자에게 매번 헛경고를 낸다.
///
/// status가 `None`(받아들여졌는데 상태 조회는 실패)이면 구독자 유무를 **모른다** →
/// [`Unknown`](RecordOutcome::Unknown). 예전엔 이걸 `Delivered`로 뭉갰는데, 그건 **모르는 것을
/// 안다고 말하는 것**이다.
fn classify_outcome(
    sent: SendResult,
    status: Option<&aic_common::ExporterStatus>,
) -> RecordOutcome {
    // 1) 전송 계층/데몬 수용 여부가 먼저다. 그 어떤 probe도 이 사실을 뒤집지 못한다.
    match sent {
        SendResult::Failed => return RecordOutcome::NotSent,
        SendResult::Rejected(why) => return RecordOutcome::Rejected(why),
        SendResult::Accepted => {}
    }
    // 2) 받아들여졌다면, 받아 갈 구독자가 있는가. 모르면 모른다고 한다.
    let Some(s) = status else {
        return RecordOutcome::Unknown;
    };
    if !s.enabled {
        return RecordOutcome::DroppedExporterOff;
    }
    if s.agent_enabled == Some(false) {
        // 구독자가 없다. 그런데 **왜** 없는지에 따라 사용자가 할 일이 다르다:
        // - config가 꺼짐 → 켜면 된다.
        // - config는 켰는데 안 떠 있음 → 켜라고 하면 오진이다. aicd 로그를 봐야 한다.
        // 구버전 aicd는 `agent_configured`를 모른다(None) → 예전처럼 "설정을 확인하라"로 접는다
        // (그 버전에선 구분할 정보 자체가 없다 — 정직한 한계).
        return match s.agent_configured {
            Some(true) => RecordOutcome::AgentExporterDown,
            _ => RecordOutcome::DroppedAgentExporterOff,
        };
    }
    // 3) 구독자가 있다 → 나간다. 지금 밀려 있는 양은 관찰로만 덧붙인다(단언 아님).
    RecordOutcome::Delivered {
        backlog: s.spool_batches,
    }
}

/// IPC 응답을 [`SendResult`]로 접는다(순수 함수). **성공 응답일 때만 `Accepted`다** — 알 수 없는
/// 응답 variant도 성공으로 세지 않는다(모르는 응답을 성공으로 낙관하면 그게 곧 다음 거짓말이 된다).
fn to_send_result(res: std::io::Result<IpcResponse>) -> SendResult {
    match res {
        Ok(IpcResponse::Pong) => SendResult::Accepted,
        Ok(IpcResponse::Error { message }) => SendResult::Rejected(message),
        // 이 요청에 올 수 없는 응답 — 프로토콜이 어긋난 것이니 성공이라 볼 근거가 없다.
        Ok(other) => SendResult::Rejected(format!("예상하지 못한 응답: {other:?}")),
        Err(e) => {
            // 소켓 자체가 안 됐다(미실행·timeout). 사용자에게는 "aicd 미실행"으로 접어서 보여주므로
            // 원인 문자열은 여기서 흘리지 않는다.
            let _ = e;
            SendResult::Failed
        }
    }
}

/// exporter가 지금 collector에 닿고 있는지 aicd에 묻는다 (chat status bar용).
///
/// `None`은 **aicd에 물어보지 못했다**는 뜻이다 — 미실행이거나, 이 요청을 모르는 구버전이거나,
/// 응답이 timeout됐다. `Some(status)`의 `enabled: false`는 "aicd는 살아있지만 exporter가 꺼져
/// 있다"로, 둘은 사용자에게 전혀 다른 상태라 구분해서 돌려준다([`classify_remote`]).
pub fn exporter_status() -> Option<aic_common::ExporterStatus> {
    to_exporter_status(query(&IpcRequest::GetExporterStatus))
}

/// [`exporter_status`]의 async 판.
pub async fn exporter_status_async() -> Option<aic_common::ExporterStatus> {
    to_exporter_status(query_async(&IpcRequest::GetExporterStatus).await)
}

/// IPC 결과에서 `ExporterStatus`를 뽑는다. 구버전 aicd는 unknown request를 graceful Error로
/// 답하므로 그 응답도 "조회 불가"(None)로 접는다.
fn to_exporter_status(res: std::io::Result<IpcResponse>) -> Option<aic_common::ExporterStatus> {
    match res {
        Ok(IpcResponse::ExporterStatus(s)) => Some(s),
        _ => None,
    }
}

/// `AgentEvent`를 만든다(summary/attrs 값 redaction 포함). 순수 함수라 네트워크 없이 검증 가능하다.
fn build_event(
    kind: &str,
    summary: &str,
    severity: &str,
    attrs: BTreeMap<String, String>,
) -> AgentEvent {
    AgentEvent {
        kind: kind.to_string(),
        summary: redact(summary),
        severity: severity.to_string(),
        attrs: attrs
            .into_iter()
            .map(|(k, v)| (k, redact(&v)))
            .collect::<BTreeMap<_, _>>(),
        ts: chrono::Utc::now(),
    }
}

/// 만들어진 이벤트를 aicd로 보내고 **실제 전송 성공 여부를 돌려준다**.
///
/// 반환값을 버리지 않는 이유: `/record now <메모>`는 "이 메모가 어떻게 됐나"를 사용자에게
/// 말해야 하는데, 결과를 `let _ =`로 버리면 **전송 실패와 성공이 구분되지 않는다**. 그 상태에서
/// "원격에 기록됐습니다"라고 말하면 그건 추측이 아니라 거짓말이다. 다른 emitter(tool_run_command
/// 등)는 fire-and-forget이라 결과를 무시해도 되지만, 무시는 **호출부의 선택**이어야지 전송 계층이
/// 정보를 없애 버릴 일이 아니다.
///
/// **테스트에서는 소켓 대신 in-process sink로 간다**([`test_sink`]) — `cargo test`가 개발 머신의
/// 실 aicd에 가짜 이벤트를 밀어 넣고, exporter가 켜져 있으면 그게 **운영 이벤트 스토어까지 나가는**
/// 사고를 막는다(이 저장소에서 실제로 난 적이 있다). "무엇을 보내는가"는 sink로 검증하고, "소켓이
/// 없을 때 조용한가"는 [`query_at`]에 없는 경로를 주입해 검증한다 — 실 소켓은 어느 쪽에도 필요 없다.
#[cfg(not(test))]
fn dispatch(ev: AgentEvent) -> SendResult {
    to_send_result(query(&IpcRequest::AgentEvent(ev)))
}

#[cfg(test)]
fn dispatch(ev: AgentEvent) -> SendResult {
    test_sink::push(ev)
}

/// [`dispatch`]의 async 판 — chat(async)에서 tokio worker를 막지 않고 보낸다.
#[cfg(not(test))]
async fn dispatch_async(ev: AgentEvent) -> SendResult {
    to_send_result(query_async(&IpcRequest::AgentEvent(ev)).await)
}

#[cfg(test)]
async fn dispatch_async(ev: AgentEvent) -> SendResult {
    test_sink::push(ev)
}

/// 한 행위를 aicd로 보낸다(build + dispatch). 이 emitter들은 fire-and-forget이라 결과를 **호출부가
/// 명시적으로 무시**한다(전송 계층이 정보를 지우는 것과는 다르다 — [`dispatch`] 참고).
fn emit(kind: &str, summary: &str, severity: &str, attrs: BTreeMap<String, String>) {
    let _sent = dispatch(build_event(kind, summary, severity, attrs));
}

/// 송신 대상 문자열을 마스킹한다. `redaction::redact`는 idempotent라 이미 redact된 입력에
/// 다시 적용해도 안전하다. 반환 튜플의 `.1`(리포트)은 여기선 쓰지 않는다.
fn redact(s: &str) -> String {
    crate::redaction::redact(s).0
}

/// 요청을 보내고 응답을 파싱해 돌려준다(실 aicd 소켓). 프레임은 length-prefixed JSON(`encode_frame`).
#[cfg(not(test))]
fn query(req: &IpcRequest) -> std::io::Result<IpcResponse> {
    query_at(&aic_common::aicd_socket_path(), req)
}

/// 테스트에서는 **실 aicd 소켓을 절대 건드리지 않는다**. 쓰기 경로는 [`dispatch`]가 sink로 돌리지만,
/// 읽기 경로(`exporter_status` → `sys_sampler::sample`)가 남아 있으면 테스트 결과가 "이 개발 머신에
/// aicd가 떠 있는가"에 따라 달라진다 — 이 저장소가 금지하는 바로 그 패턴이다(테스트는 코드의
/// 불변식을 검증해야지 머신 상태를 반영하면 안 된다). 데몬 없음(=Err)으로 고정해 결정적으로 만든다.
/// 전송 계층 자체는 [`query_at`]에 경로를 주입해 따로 검증한다.
#[cfg(test)]
fn query(_req: &IpcRequest) -> std::io::Result<IpcResponse> {
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "테스트에서는 실 aicd에 연결하지 않는다",
    ))
}

/// 소켓 경로를 **주입받는** sync IPC. 프로덕션은 [`query`]가 실 경로를 넣고, 테스트는 존재하지 않는
/// 경로를 넣어 "데몬이 없을 때 조용히 실패하는가"를 실 aicd 없이 검증한다.
fn query_at(socket: &std::path::Path, req: &IpcRequest) -> std::io::Result<IpcResponse> {
    let payload = serde_json::to_vec(req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&encode_frame(&payload))?;
    stream.flush()?;

    // 4바이트 길이 헤더 → 본문. 상한을 두어 손상된 헤더가 거대한 할당으로 이어지지 않게 한다.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_RESPONSE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("응답이 너무 큼: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// async 호출부(chat `handle_record`)를 위한 IPC.
///
/// **왜 sync 버전을 그냥 부르지 않는가**: 위 [`query_at`]은 blocking `UnixStream`이라 async 함수에서
/// 직접 부르면 tokio worker 스레드가 최대 `IO_TIMEOUT`만큼 통째로 막힌다(`/record now`는 dispatch +
/// 상태조회로 두 번 왕복한다).
///
/// **왜 `spawn_blocking`이 아닌가**: t2가 지표 폴백에서 정확히 그걸 시도했다가 걷어냈다 —
/// `tokio::time::timeout`은 **기다리기를 포기할 뿐 클로저를 멈추지 못하므로**, 안에서 걸린 스레드는
/// blocking pool에 영구히 pin된다. 반면 **tokio `UnixStream`은 진짜로 취소된다**: future를 drop하면
/// 소켓이 닫히고 스레드가 남지 않는다. 그래서 여기서는 sync를 감싸는 대신 **async I/O로 다시 쓴다** —
/// `timeout`이 connect·write·read 전 구간을 덮으므로, aicd가 hang이든 미실행이든 `IO_TIMEOUT` 안에
/// 확실히 풀려나고 아무것도 pin되지 않는다.
#[cfg(not(test))]
async fn query_async(req: &IpcRequest) -> std::io::Result<IpcResponse> {
    tokio::time::timeout(IO_TIMEOUT, query_async_inner(req))
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "aicd 응답 timeout",
            ))
        })
}

/// sync [`query`]와 같은 이유로 테스트에서는 소켓에 나가지 않는다.
#[cfg(test)]
async fn query_async(_req: &IpcRequest) -> std::io::Result<IpcResponse> {
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "테스트에서는 실 aicd에 연결하지 않는다",
    ))
}

/// [`query_async`]의 본체(취소 가능). timeout은 호출부가 전 구간에 씌운다.
#[cfg(not(test))]
async fn query_async_inner(req: &IpcRequest) -> std::io::Result<IpcResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let payload = serde_json::to_vec(req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut stream = tokio::net::UnixStream::connect(aic_common::aicd_socket_path()).await?;
    stream.write_all(&encode_frame(&payload)).await?;
    stream.flush().await?;

    // sync 경로와 동일한 프레이밍(4바이트 길이 헤더 → 본문)과 동일한 할당 상한.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_RESPONSE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("응답이 너무 큼: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// 테스트 전용 이벤트 sink — `cargo test`가 개발 머신의 **실 aicd에 가짜 이벤트를 밀어 넣지 않도록**
/// [`dispatch`]/[`dispatch_async`]를 소켓 대신 여기로 보낸다. 이 저장소에서 실제로 났던 사고다
/// (테스트 픽스처가 실 aicd를 거쳐 서버까지 나갔다).
///
/// thread-local이라 병렬 테스트끼리 섞이지 않는다(각 테스트는 자기 스레드의 sink만 본다).
/// **주의**: `#[cfg(test)]`는 이 크레이트의 unit test에만 걸린다 — `tests/`의 integration test는
/// 라이브러리를 cfg(test) 없이 링크하므로 여기 오지 않는다(현재 agent_event를 쓰는 integration
/// test는 없다).
#[cfg(test)]
pub(crate) mod test_sink {
    use super::{AgentEvent, SendResult};
    use std::cell::RefCell;

    thread_local! {
        static SENT: RefCell<Vec<AgentEvent>> = const { RefCell::new(Vec::new()) };
        /// 다음 전송이 어떻게 끝날지. aicd 미실행(IPC 실패)·데몬 거절(`IpcResponse::Error`)을
        /// 실 소켓 없이 재현해, "실패/거절인데 성공이라고 보고하는" 회귀를 end-to-end로 잡는다.
        static OUTCOME: RefCell<SendResult> = const { RefCell::new(SendResult::Accepted) };
    }

    /// dispatch가 보내려던 이벤트를 기록한다(소켓 대신). 반환값 = 전송 결과(실 dispatch와 동일 계약).
    /// 실패/거절 모드에서는 **이벤트를 기록하지 않는다** — 실제 IPC 실패·데몬 거절과 같은 관찰
    /// (아무것도 안 남았고, 호출부는 실패를 안다)을 만든다.
    pub(crate) fn push(ev: AgentEvent) -> SendResult {
        let outcome = OUTCOME.with(|o| o.borrow().clone());
        if !matches!(outcome, SendResult::Accepted) {
            return outcome;
        }
        SENT.with(|s| s.borrow_mut().push(ev));
        SendResult::Accepted
    }

    /// 이 스레드의 다음 전송 결과를 정한다(기본 `Accepted`). 테스트 종료 시 되돌린다.
    pub(crate) fn set_send_result(outcome: SendResult) {
        OUTCOME.with(|o| *o.borrow_mut() = outcome);
    }

    /// 이 스레드에서 지금까지 dispatch된 이벤트를 꺼내 비운다.
    pub(crate) fn drain() -> Vec<AgentEvent> {
        SENT.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// redaction 테스트 공용 fixture — AWS 공식 문서가 예시용으로 지정한 **가짜** access key
    /// (실제 자격증명 아님). 이 모듈의 모든 secret-redaction 테스트가 각자 리터럴을 새로 선언하는
    /// 대신 이 상수 하나를 재사용한다 — privacy 스캐너(`git-kit commit`)가 파일 전체에서 "AKIA…"
    /// 꼴 리터럴 개수를 threshold로 세는데, 같은 fixture를 테스트마다 다시 타이핑하면 실제 secret
    /// 유출과 무관하게 그 카운트만 늘어난다.
    const AWS_KEY_FIXTURE: &str = "AKIAIOSFODNN7EXAMPLE";

    /// 테스트용 — 원문을 한 번 정제해 `Memo`로 만든다(비면 패닉: 픽스처가 잘못된 것이다).
    fn memo(raw: &str) -> Memo {
        Memo::sanitize(raw).expect("테스트 픽스처가 빈 메모다")
    }

    #[test]
    fn query_without_daemon_fails_quietly_instead_of_panicking() {
        // aicd가 없을 때(미실행) 조용히 Err로 떨어지고 패닉하지 않아야 한다 — 정상 경로다(F19).
        // **실 소켓을 쓰지 않는다**: 존재하지 않는 경로를 주입해 "데몬 없음"을 결정적으로 만든다.
        // 예전 이 테스트는 실 aicd 경로로 나갔는데, 그러면 개발 머신에 aicd가 떠 있느냐에 따라
        // 다른 코드를 실행하는 데다(회귀를 못 잡는다) 실 데몬을 오염시켰다.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-aicd.sock");
        let res = query_at(&missing, &IpcRequest::GetExporterStatus);
        assert!(res.is_err(), "없는 소켓인데 성공했다");
        // 그리고 이 실패는 to_exporter_status를 통해 "조회 불가"(None)로 접힌다 — 그 상태에서
        // 전송까지 실패했다면(데몬이 없으니 당연히) 결론은 NotSent다.
        assert_eq!(to_exporter_status(res), None);
        assert_eq!(
            classify_outcome(SendResult::Failed, None),
            RecordOutcome::NotSent
        );
    }

    #[test]
    fn all_emitters_dispatch_exactly_one_event_each() {
        // 각 emitter가 이벤트를 **하나씩** 실제로 dispatch에 넘기는지 sink로 확인한다(실 소켓 없음).
        // 예전 이 테스트는 "패닉만 안 하면 통과"였다 — emit이 통째로 사라져도 통과했을 것이다.
        let _ = test_sink::drain(); // 앞선 테스트 잔여물 제거(같은 스레드 재사용 대비)
        tool_run_command("echo hi", Some(0), 12, "/tmp");
        risk_denied("rm -rf /", "Dangerous", Some("builtin_denylist"));
        finding_created("disk_full", "WARN", "/ 사용률 95%");
        snapshot_recorded(
            &Memo::sanitize("cpu sys 26%, idle 67% — 커널 모드 비율이 높음").unwrap(),
            BTreeMap::new(),
        );

        let kinds: Vec<String> = test_sink::drain().into_iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                "tool.run_command",
                "risk.denied",
                "finding.created",
                "snapshot.recorded",
            ]
        );
    }

    #[test]
    fn snapshot_event_kind_and_severity_come_from_the_function_body() {
        // kind/severity를 테스트가 주입하지 않는다 — snapshot_event()가 본문에 고정한 값을
        // 그대로 검증한다. 누가 kind를 다른 상수로 바꾸거나 severity를 WARN으로 바꾸면 실패한다.
        let ev = snapshot_event("이상하게 느려짐", BTreeMap::new());

        assert_eq!(ev.kind, "snapshot.recorded");
        assert_eq!(
            ev.severity, "INFO",
            "사람의 관찰 기록이라 사건 severity를 달지 않는다"
        );
        assert_eq!(ev.summary, "이상하게 느려짐");
    }

    #[test]
    fn snapshot_event_carries_caller_attrs() {
        let mut attrs = BTreeMap::new();
        attrs.insert("memo_source".to_string(), "manual".to_string());
        let ev = snapshot_event("memo", attrs);

        assert_eq!(ev.attrs.get("memo_source"), Some(&"manual".to_string()));
    }

    #[test]
    fn snapshot_event_redacts_summary_and_attrs() {
        // snapshot_recorded() 경로가 실제로 redaction을 거치는지 본다 — summary와 attrs 값 양쪽.
        let secret = AWS_KEY_FIXTURE;
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "note".to_string(),
            format!("export AWS_SECRET_ACCESS_KEY={secret}"),
        );
        let ev = snapshot_event(&format!("키가 노출됨: {secret}"), attrs);

        assert!(
            !ev.summary.contains(secret),
            "summary가 마스킹되지 않음: {}",
            ev.summary
        );
        let masked = ev.attrs.get("note").expect("note attr 존재");
        assert!(
            !masked.contains(secret),
            "attrs 값이 마스킹되지 않음: {masked}"
        );
    }

    #[test]
    fn summary_and_attrs_are_redacted_before_leaving_the_process() {
        // emit이 만드는 AgentEvent를 직접 만들어 redaction이 걸리는지 확인한다.
        let secret = format!("export AWS_SECRET_ACCESS_KEY={AWS_KEY_FIXTURE}");
        let masked = redact(&secret);
        assert!(
            !masked.contains(AWS_KEY_FIXTURE),
            "secret이 마스킹되지 않음: {masked}"
        );
    }

    #[test]
    fn failed_command_is_error_severity() {
        // exit_code 0만 INFO, 나머지(실패/unknown)는 ERROR — RCA에서 실패를 먼저 보게 한다.
        let sev = |c: Option<i32>| match c {
            Some(0) => "INFO",
            _ => "ERROR",
        };
        assert_eq!(sev(Some(0)), "INFO");
        assert_eq!(sev(Some(1)), "ERROR");
        assert_eq!(sev(None), "ERROR");
    }

    // ── t3 B3: `/record now <메모>` 적대적 입력(F14~F17) ─────────────────────────

    #[test]
    fn snapshot_recorded_skips_empty_or_whitespace_only_memo() {
        // F15: 빈 메모/공백뿐인 메모는 발화하지 않는다 — 반환값(None)뿐 아니라 **sink가 비어 있는지**
        // 까지 본다(반환값만 보면 "None을 돌려주면서 보내기는 하는" 회귀를 놓친다).
        let _ = test_sink::drain();
        // 이제 타입이 막는다: 빈 메모는 `Memo`가 만들어지지 않으므로 전송 API에 **도달조차 못 한다**.
        assert_eq!(Memo::sanitize(""), None);
        assert_eq!(Memo::sanitize("   \n\t  "), None);
        assert!(
            test_sink::drain().is_empty(),
            "빈 메모인데 이벤트가 전송됐다"
        );
    }

    #[test]
    fn snapshot_recorded_skips_memo_that_sanitizes_to_empty() {
        // F15+F17 결합: 공백은 아니지만(제어문자만 있음) sanitize 후 공백만 남는 메모도 스킵해야
        // 한다 — parse 단계의 `.trim()`(유니코드 공백만 제거)은 ESC 같은 제어문자를 못 거르므로,
        // 이 판정이 sanitize **이후**에 있어야만 잡히는 케이스다.
        let _ = test_sink::drain();
        assert_eq!(Memo::sanitize("\x1b\x1b\x1b"), None);
        assert!(
            test_sink::drain().is_empty(),
            "제어문자뿐인 메모인데 이벤트가 전송됐다"
        );
    }

    #[test]
    fn snapshot_recorded_sends_memo_as_body_with_attrs() {
        // 진짜 메모는 정확히 1건 나가고, body(summary)와 attrs가 그대로 실린다.
        let _ = test_sink::drain();
        let mut attrs = BTreeMap::new();
        attrs.insert("note_source".to_string(), "chat".to_string());
        snapshot_recorded(&memo("cpu 이상하게 높음"), attrs);

        let sent = test_sink::drain();
        assert_eq!(sent.len(), 1, "정확히 1건이어야: {sent:?}");
        assert_eq!(sent[0].kind, "snapshot.recorded");
        assert_eq!(sent[0].summary, "cpu 이상하게 높음");
        assert_eq!(sent[0].attrs.get("note_source"), Some(&"chat".to_string()));
    }

    #[test]
    fn snapshot_recorded_reports_not_sent_when_delivery_fails() {
        // **A의 핵심 회귀 테스트**: 전송이 실패하면 결과는 반드시 NotSent다. 예전엔 dispatch 결과를
        // `let _ =`로 버리고 "보내기 전 exporter 상태"로 성공을 단언해, aicd가 죽어 있어도
        // "원격에 기록됐습니다"라고 말했다. sink를 실패 모드로 두어 실 소켓 없이 그 경로를 재현한다.
        let _ = test_sink::drain();
        test_sink::set_send_result(SendResult::Failed);
        let outcome = snapshot_recorded(&memo("디스크가 이상하다"), BTreeMap::new());
        test_sink::set_send_result(SendResult::Accepted); // 같은 스레드를 재사용하는 뒤 테스트를 오염시키지 않게 복구

        assert_eq!(
            outcome,
            RecordOutcome::NotSent,
            "전송에 실패했는데 실패라고 보고하지 않는다"
        );
        assert!(
            outcome.verdict() == RemoteVerdict::Lost,
            "보내지도 못한 메모를 '서버에 남는다'고 말하면 안 된다"
        );
        assert!(
            test_sink::drain().is_empty(),
            "전송 실패인데 이벤트가 기록됐다"
        );
    }

    #[tokio::test]
    async fn snapshot_recorded_async_reports_not_sent_when_delivery_fails() {
        // async(chat) 경로도 같은 계약 — 여기만 성공으로 단언하는 회귀를 막는다.
        let _ = test_sink::drain();
        test_sink::set_send_result(SendResult::Failed);
        let outcome = snapshot_recorded_async(&memo("느려짐"), BTreeMap::new()).await;
        test_sink::set_send_result(SendResult::Accepted);

        assert_eq!(outcome, RecordOutcome::NotSent);
        assert!(test_sink::drain().is_empty());
    }

    #[tokio::test]
    async fn snapshot_recorded_async_matches_sync_contract() {
        // chat(async) 경로도 sync와 **같은 계약**을 지킨다: 빈 메모는 스킵, 진짜 메모는 1건 전송.
        // 두 진입점이 prepare_snapshot_event를 공유하므로 여기서 갈라지면 곧바로 드러난다.
        let _ = test_sink::drain();
        assert_eq!(Memo::sanitize("  "), None);
        assert!(test_sink::drain().is_empty(), "빈 메모인데 전송됨(async)");

        snapshot_recorded_async(&memo("디스크가 이상하다"), BTreeMap::new()).await;
        let sent = test_sink::drain();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].kind, "snapshot.recorded");
        assert_eq!(sent[0].summary, "디스크가 이상하다");
    }

    // ── 원격 기록 가능 상태 분류(조용한 유실 방지) ────────────────────────────────

    /// exporter가 정상 가동 중인 status(부모 게이트 on + agent exporter task 떠 있음 + spool 비어 있음).
    fn healthy_status() -> aic_common::ExporterStatus {
        aic_common::ExporterStatus {
            enabled: true,
            agent_enabled: Some(true),
            agent_configured: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn only_a_success_response_counts_as_accepted() {
        // **"보냈다"(전송 계층)와 "받아들여졌다"(데몬)는 다른 명제다.** 소켓 write가 성공해도 데몬이
        // `IpcResponse::Error`로 거절하면 그 메모는 버려진 것이다 — 예전엔 `.is_ok()`만 봐서 거절을
        // 성공으로 셌고, 그 위에 "원격에 기록됐습니다"를 얹었다.
        assert_eq!(to_send_result(Ok(IpcResponse::Pong)), SendResult::Accepted);

        // 명시적 거절 → 실패. 이유(에러 메시지)를 보존해 사용자에게 보여준다(왜 거절됐는지가 진단이다).
        let rejected = to_send_result(Ok(IpcResponse::Error {
            message: "bus full".to_string(),
        }));
        assert_eq!(rejected, SendResult::Rejected("bus full".to_string()));

        // 이 요청에 올 수 없는 응답도 성공으로 낙관하지 않는다 — 모르는 응답을 성공으로 세는 게
        // 바로 다음 거짓말의 씨앗이다.
        let weird = to_send_result(Ok(IpcResponse::Lines(vec![])));
        assert!(
            matches!(weird, SendResult::Rejected(_)),
            "예상 못 한 응답을 성공으로 셌다: {weird:?}"
        );

        // 소켓 자체 실패 → 전송 실패.
        let io_err = Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no sock"));
        assert_eq!(to_send_result(io_err), SendResult::Failed);
    }

    #[test]
    fn daemon_rejection_is_never_reported_as_delivered() {
        // 거절은 exporter가 아무리 건강해도 실패다(전송 계층의 성공이 수용을 뜻하지 않는다).
        let outcome = classify_outcome(
            SendResult::Rejected("bus full".to_string()),
            Some(&healthy_status()),
        );
        assert_eq!(outcome, RecordOutcome::Rejected("bus full".to_string()));
        assert_eq!(outcome.verdict(), RemoteVerdict::Lost);
        // 거절 사유를 사용자에게 보여준다 — 왜 거절됐는지가 진단의 핵심이다.
        assert!(
            outcome
                .notice()
                .expect("안내가 있어야")
                .contains("bus full"),
            "거절 사유가 안내에 없다"
        );
    }

    #[test]
    fn accepted_but_unqueryable_status_is_unknown_not_delivered() {
        // #4: 전송은 받아들여졌는데 상태 조회를 못 했다 → 도달 여부를 **모른다**. Delivered로
        // 뭉개면 **모르는 것을 안다고 말하는 것**이다.
        let outcome = classify_outcome(SendResult::Accepted, None);
        assert_eq!(outcome, RecordOutcome::Unknown);
        assert_eq!(outcome.verdict(), RemoteVerdict::Unknown);
        assert!(
            outcome
                .notice()
                .expect("모름도 알려야 한다")
                .contains("알 수"),
            "도달 여부를 모른다는 사실이 안내에 없다"
        );
    }

    #[test]
    fn failed_send_beats_every_probe_and_is_never_reported_as_delivered() {
        // **A의 뿌리**: 결론은 전송 결과에서만 나온다. exporter가 아무리 건강해 보여도(healthy),
        // 보내지 못했으면 그 메모는 서버에 없다. 이 순서가 뒤집히면 "보내지도 못했는데 기록됐다"가 된다.
        assert_eq!(
            classify_outcome(SendResult::Failed, Some(&healthy_status())),
            RecordOutcome::NotSent,
            "전송 실패인데 exporter가 건강하다는 이유로 성공이라 보고한다"
        );
        assert_eq!(
            classify_outcome(SendResult::Failed, None),
            RecordOutcome::NotSent
        );
        assert!(RecordOutcome::NotSent.verdict() == RemoteVerdict::Lost);
    }

    #[test]
    fn cumulative_drop_counter_does_not_poison_every_future_record() {
        // **finding #1의 회귀 테스트**: `spool_dropped`는 **누적** 카운터다("과거에 한 번이라도 버림").
        // 그걸 현재 상태로 읽으면, 오래전 collector 장애로 한 번 드롭된 이후 **이후 모든**
        // `/record now`가 영구히 "유실 중"이라고 오보한다. 이제 그 필드는 판정에 쓰지 않는다 —
        // 지금 전송이 성공했고 구독자가 있다면 이 메모는 나간다.
        let long_ago_drop = aic_common::ExporterStatus {
            spool_dropped: 9_999, // 과거의 유실 — 지금 이 메모와는 무관하다
            spool_batches: 0,     // 지금은 밀린 것도 없다(정상 복구됨)
            ..healthy_status()
        };
        assert_eq!(
            classify_outcome(SendResult::Accepted, Some(&long_ago_drop)),
            RecordOutcome::Delivered { backlog: 0 },
            "과거 누적 드롭 때문에 지금 잘 간 메모를 유실이라고 오보한다"
        );
        assert!(
            classify_outcome(SendResult::Accepted, Some(&long_ago_drop)).verdict()
                == RemoteVerdict::Reaches
        );
    }

    #[test]
    fn classify_outcome_catches_disabled_agent_exporter_behind_enabled_parent() {
        // **부모 게이트만 보면 놓치는 유실**: `[aicd.exporter] enabled = true`인데
        // `agent_enabled = false`면 serve_agent task가 안 떠서 AgentEventBus에 구독자가 없다 —
        // 우리 이벤트만 조용히 버려지는데 host metrics 등 다른 signal은 멀쩡히 나가므로
        // 사용자가 눈치챌 방법이 없다. 전송이 성공해도 이건 유실이다.
        let agent_off = aic_common::ExporterStatus {
            enabled: true, // 부모 게이트는 켜져 있다
            agent_enabled: Some(false),
            agent_configured: Some(false), // config에서도 꺼 뒀다 → 켜면 해결된다
            ..Default::default()
        };
        assert_eq!(
            classify_outcome(SendResult::Accepted, Some(&agent_off)),
            RecordOutcome::DroppedAgentExporterOff
        );
        assert!(RecordOutcome::DroppedAgentExporterOff.verdict() == RemoteVerdict::Lost);

        // 부모 게이트가 꺼진 경우도 마찬가지로 유실이다(다른 조치가 필요하므로 다른 상태).
        let all_off = aic_common::ExporterStatus {
            enabled: false,
            ..Default::default()
        };
        assert_eq!(
            classify_outcome(SendResult::Accepted, Some(&all_off)),
            RecordOutcome::DroppedExporterOff
        );
    }

    #[test]
    fn configured_but_down_is_not_misdiagnosed_as_a_config_problem() {
        // **오진 회귀 테스트**: endpoint 오류·spool 실패·task 사망으로 안 떠 있는 경우에
        // "`agent_enabled = true`로 켜세요"라고 안내하면, **이미 켜 둔 사용자**가 시키는 대로 해도
        // 안 고쳐진다. 진짜 이유는 aicd 로그에 있다.
        let down = aic_common::ExporterStatus {
            enabled: true,
            agent_enabled: Some(false),   // 안 떠 있다
            agent_configured: Some(true), // 그런데 설정은 켜져 있다
            ..Default::default()
        };
        let outcome = classify_outcome(SendResult::Accepted, Some(&down));
        assert_eq!(outcome, RecordOutcome::AgentExporterDown);

        let notice = outcome.notice().expect("안내가 있어야");
        assert!(
            notice.contains("aicd 로그"),
            "진짜 원인을 볼 곳(aicd 로그)을 안내하지 않는다: {notice}"
        );
        assert!(
            !notice.contains("agent_enabled = true"),
            "이미 켜 둔 설정을 켜라고 오진한다: {notice}"
        );

        // 그리고 **유실로 확정하지 않는다**: 우리가 본 건 "publish 직후 시점에 구독자가 없다"이지
        // "publish 순간에 없었다"가 아니다. 방금 죽은 task라면 이벤트는 죽기 전에 소비됐을 수 있다.
        assert_eq!(
            outcome.verdict(),
            RemoteVerdict::Unknown,
            "한 번의 관측으로 유실을 확정한다"
        );
    }

    #[test]
    fn classify_outcome_treats_unknown_agent_flag_as_ok_for_old_daemons() {
        // 구버전 aicd는 이 필드를 모른다 → None. 모름을 "꺼짐"으로 읽으면 멀쩡한 구버전에 매번
        // 헛경고를 낸다. 하위 호환: 모르면 경고하지 않는다(#[serde(default)] → None).
        let old = aic_common::ExporterStatus {
            enabled: true,
            agent_enabled: None, // 구버전 — 필드 없음
            ..Default::default()
        };
        assert_eq!(
            classify_outcome(SendResult::Accepted, Some(&old)),
            RecordOutcome::Delivered { backlog: 0 }
        );
    }

    #[test]
    fn backlog_is_an_observation_not_a_failure() {
        // 밀림은 **지연이지 유실이 아니다** — 전송은 됐고 구독자도 있으니 복구되면 나간다.
        // 그래서 will_reach_server()는 true지만, "이미 서버에서 보인다"고 오해하지 않도록
        // 관찰 사실은 안내로 덧붙인다.
        let backlogged = aic_common::ExporterStatus {
            spool_batches: 1_500, // 실제로 이 개발 머신에서 관측된 값
            ..healthy_status()
        };
        let outcome = classify_outcome(SendResult::Accepted, Some(&backlogged));
        assert_eq!(outcome, RecordOutcome::Delivered { backlog: 1_500 });
        assert!(
            outcome.verdict() == RemoteVerdict::Reaches,
            "밀림은 유실이 아니다 — 복구되면 전송된다"
        );
        let notice = outcome.notice().expect("밀려 있으면 알려야 한다");
        assert!(
            notice.contains("1500") || notice.contains("1,500"),
            "{notice}"
        );
    }

    // (구 `delivered_without_status_claims_only_what_the_send_result_proves`는
    //  `accepted_but_unqueryable_status_is_unknown_not_delivered`로 대체됐다 — 그때는 status 조회
    //  실패를 `Delivered`로 뭉갰는데, 그게 바로 "모르는 것을 안다고 말하는" 오류였다.)

    #[test]
    fn only_clean_delivery_is_silent_and_each_state_has_its_own_actionable_notice() {
        // 완전한 성공만 조용하고, 나머지는 **서로 다른** 안내를 낸다 — 같은 문구면 사용자가 원인을
        // 구분할 수 없다(aicd를 띄울지, 부모 게이트를 켤지, agent_enabled를 켤지가 다른 조치다).
        assert_eq!(RecordOutcome::Delivered { backlog: 0 }.notice(), None);
        let notices: Vec<String> = [
            RecordOutcome::NotSent,
            RecordOutcome::DroppedExporterOff,
            RecordOutcome::DroppedAgentExporterOff,
            RecordOutcome::Delivered { backlog: 7 },
        ]
        .into_iter()
        .map(|s| s.notice().expect("완전한 성공 외에는 안내가 있어야 한다"))
        .collect();

        // 전부 서로 다른 문구여야 한다.
        let uniq: std::collections::HashSet<&String> = notices.iter().collect();
        assert_eq!(uniq.len(), notices.len(), "안내가 겹친다: {notices:?}");

        // 각 안내는 사용자가 취할 조치(또는 알아야 할 사실)를 짚는다.
        assert!(notices[0].contains("aicd"), "{}", notices[0]);
        assert!(notices[1].contains("enabled = true"), "{}", notices[1]);
        assert!(
            notices[2].contains("agent_enabled = true"),
            "{}",
            notices[2]
        );
        assert!(notices[3].contains('7'), "{}", notices[3]);

        // **로컬 스냅샷 성공을 주장하지 않는다** — 이 함수는 그걸 알 수 없다(예전엔 무조건
        // "로컬 스냅샷은 정상 저장되었습니다"를 붙여 캡처 실패 시 거짓말을 했다).
        for n in &notices {
            assert!(
                !n.contains("정상 저장"),
                "원격 안내가 로컬 성공을 주장한다: {n}"
            );
        }
    }

    #[test]
    fn sanitize_memo_strips_control_chars_and_ansi_but_keeps_newline_and_tab() {
        // F17: 제어문자/ANSI escape가 수신측 표시를 깨지 않아야 한다. ESC를 지우면 뒤따르는
        // CSI 바이트열은 이스케이프 시퀀스가 아니라 평범한 문자로 남는다(터미널이 해석 안 함).
        let input = "line1\x1b[31mRED\x1b[0m\tline1-tab\nline2\x07bell";
        let m = memo(input);
        let (out, truncated) = (m.text(), m.truncated());
        assert!(!out.contains('\x1b'), "ESC가 남음: {out:?}");
        assert!(!out.contains('\x07'), "BEL이 남음: {out:?}");
        assert!(out.contains('\n'), "개행이 지워짐: {out:?}");
        assert!(out.contains('\t'), "탭이 지워짐: {out:?}");
        // ESC만 사라지고 나머지 텍스트(색상 코드 잔여물 포함)는 평문으로 보존.
        assert!(out.contains("[31mRED[0m"), "본문이 훼손됨: {out:?}");
        assert!(!truncated, "짧은 메모인데 절단됐다고 표시된다");
    }

    #[test]
    fn sanitize_memo_truncates_oversized_input_at_utf8_boundary_and_says_so() {
        // F16: 1MB 메모 같은 병적 입력이 절단되어 IPC 프레임 상한(16MiB)에 닿지 않는다.
        // 멀티바이트 문자(한글, 3바이트)로 채워 절단 지점이 문자 중간이면 즉시 드러나게 한다.
        let oversized = "가".repeat(1_000_000); // 3MB (문자당 3바이트)
        let m = memo(&oversized);
        let (out, truncated) = (m.text(), m.truncated());
        assert!(
            out.len() <= MEMO_MAX_BYTES,
            "절단이 상한을 넘음: {} bytes",
            out.len()
        );
        assert!(out.len() < 1_000_000 * 3, "절단이 전혀 안 됨");
        // UTF-8 경계 보존 — 잘렸어도 유효한 문자열이어야 한다(패닉하면 경계를 깬 것).
        assert!(
            out.chars().all(|c| c == '가'),
            "절단이 문자 중간을 깨서 깨진 바이트가 섞임: {out:?}"
        );
        // **잘렸으면 잘렸다고 말해야 한다** — 예전엔 이 플래그를 버려서 사용자도 이벤트도 몰랐다.
        assert!(truncated, "절단됐는데 절단 사실이 보고되지 않는다");
    }

    #[test]
    fn truncated_memo_is_flagged_on_the_event() {
        // 절단 사실이 **이벤트에도** 실려야 한다 — 나중에 그 이벤트를 보는 사람이 잘린 문장을
        // 원문으로 읽지 않도록.
        let _ = test_sink::drain();
        let oversized = "가".repeat(1_000_000);
        snapshot_recorded(&memo(&oversized), BTreeMap::new());

        let sent = test_sink::drain();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].attrs.get("memo_truncated"),
            Some(&"true".to_string()),
            "절단된 메모인데 이벤트에 표시가 없다: {:?}",
            sent[0].attrs
        );
        assert!(sent[0].summary.len() <= MEMO_MAX_BYTES);

        // 짧은 메모에는 그 플래그가 붙지 않는다(항상 붙이면 의미가 없다).
        snapshot_recorded(&memo("짧은 메모"), BTreeMap::new());
        let sent = test_sink::drain();
        assert!(!sent[0].attrs.contains_key("memo_truncated"));
    }

    #[test]
    fn sanitize_memo_does_not_defeat_redaction() {
        // F14: sanitize_memo(제어문자 제거)를 먼저 거쳐도 redaction이 여전히 걸려야 한다(두 방어가
        // 서로를 무력화하지 않는다).
        let secret = AWS_KEY_FIXTURE;
        let noisy = format!("\x1b[31mexport AWS_SECRET_ACCESS_KEY={secret}\x1b[0m");
        let ev = snapshot_event(memo(&noisy).text(), BTreeMap::new());
        assert!(
            !ev.summary.contains(secret),
            "sanitize 이후에도 secret이 마스킹돼야 함: {}",
            ev.summary
        );
    }
}
