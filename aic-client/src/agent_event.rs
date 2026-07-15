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

/// 소켓 연결/송신/응답 대기 상한(emit 경로). chat 흐름을 막지 않도록 짧게 잡는다 — aicd는 로컬
/// UDS라 정상 상황에서 밀리초 단위로 끝난다. emit(`risk_denied` 등)은 사용자 입력 흐름에 얹히므로
/// 지연에 민감해 이 짧은 값을 쓴다.
const IO_TIMEOUT: Duration = Duration::from_millis(300);

/// status bar exporter 조회 전용 상한. emit보다 **여유롭게** 잡는다 — status 조회는 주기 갱신이라
/// 지연에 안 민감한데, aicd가 큰 spool 드레인·다수 세션으로 잠깐 바쁠 때 300ms를 넘겨 응답하면
/// (=`NoReply`) 그걸 "aicd off"로 오보하게 된다(살아있는데 꺼졌다고 거짓 보고). 여유를 줘 그 오탐을
/// 줄이고, 그래도 `NoReply`면 호출부가 "모름"으로 다뤄 직전 상태를 유지한다([`ExporterProbe`]).
///
/// `query_status`가 `cfg(not(test))`라 test 빌드에선 이 상수가 안 쓰인다(test는 실 소켓 금지 →
/// SendFailed 고정). 그때만 dead_code를 허용한다.
#[cfg_attr(test, allow(dead_code))]
const STATUS_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// 응답 본문 상한 — 우리가 읽는 응답(Pong/ExporterStatus)은 수백 바이트다. 손상된 길이
/// 헤더가 거대한 할당으로 이어지지 않게 막는다.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// `/record now <메모>`가 저장·전송할 수 있는 메모 상한(바이트). 사람이 손으로 남기는 관찰 메모치고는
/// 넉넉하되(64KiB), IPC 프레임 상한(`aic_common::ipc::MAX_FRAME_PAYLOAD_BYTES`, 16MiB)에는 한참
/// 못 미친다 — 1MB 메모 같은 병적 입력이 프레임 상한에 닿는 일을 미리 막는다(F16).
///
/// **최종 저장 바이트의 진짜 상한이다**: [`Memo::sanitize`]가 redaction 후 이 값으로 2차 절단하므로,
/// `[REDACTED:…]` 치환이 길이를 늘려도 저장/전송되는 바이트는 이 값을 넘지 않는다.
///
/// 단, 이건 **저장 상한**이지 **처리 상한**이 아니다 — regex가 보는 입력 크기는 [`MEMO_REDACT_INPUT_MAX`]가
/// 따로 막는다(무제한 입력을 regex에 넘기면 ReDoS·메모리 압박 표면이 된다).
pub const MEMO_MAX_BYTES: usize = 64 * 1024;

/// redaction **전** 절단 상한(**처리 상한**) — regex가 보는 입력을 유계로 만든다. **순수 내부 비용
/// 방어**이지 사용자 대면 상한이 아니다(여기서 잘려도 `Memo::truncated`에 안 든다 — 13차 교정).
///
/// 왜 별도 상한인가(11차 코디네이터 지시의 미완성 보완): [`Memo::sanitize`]는 redaction을 먼저 하고
/// 그 결과를 자르는데(저장 상한이 진짜 상한이 되도록), 절단이 맨 뒤라 **redaction regex가 상한 없는
/// 원문 전체를 본다.** 3MB 메모면 3MB 전체에 regex를 돌린다 — `MEMO_MAX_BYTES`는 저장 바이트만 막지
/// 처리 비용(CPU/메모리)은 못 막아 ReDoS·거대 입력 압박의 표면이 된다. 그래서 redaction **전에** 원문을
/// 이 값으로 절단해 regex 입력을 유계로 만든다.
///
/// `MEMO_MAX_BYTES × 8`인 근거:
/// - **성장 여유**: redaction 최대 성장은 짧은 이메일(`a@b.co` 6B → `[REDACTED:email]` 16B ≈ 2.4배)로
///   관측됐다. 8배는 그보다 넉넉해, 1차로 자른 입력이 redaction 후 저장 상한을 못 채우는 일이 없다.
/// - **정상 메모 미손상**: 사람이 손으로 남기는 메모는 수 KB 규모라 512KiB(=8×64KiB)에 한참 못 미친다.
///   1차 절단은 **병적 입력**(수 MB)에만 걸리고, 정상 메모는 redaction 전에 잘리지 않는다.
/// - **처리 유계**: regex가 보는 입력이 512KiB로 상한 → µs∼ms급, 무제한 입력의 DoS 표면이 사라진다.
const MEMO_REDACT_INPUT_MAX: usize = MEMO_MAX_BYTES * 8;

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
/// 화면에 아무것도 그리지 않는 폭 0/비가시 format 문자인가. **빈 판정에서만** 쓴다 — 저장 내용은
/// 안 건드린다(이모지 ZWJ·다국어 조이너가 **보이는 문자와 섞이면** 그대로 보존돼야 하므로).
/// bidi 제어(U+202A–E·U+2066–9)도 포함한다: 폭 0이라 "빈 것처럼 보임"에 해당하고, 단독으론 의미가 없다.
fn is_zero_width_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}' // bidi embedding/override
        | '\u{2060}'..='\u{2064}' // WORD JOINER, invisible operators
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{00AD}'              // SOFT HYPHEN
        | '\u{FEFF}'              // BOM / zero-width no-break space
        | '\u{180E}'              // Mongolian vowel separator
    )
}

/// 사람 눈에 **보이는 문자가 하나도 없는가**. `trim().is_empty()`는 공백(White_Space)만 보므로 폭 0
/// 문자로만 이뤄진 메모를 놓친다(gate에서만 쓴다 — 저장 내용은 안 바꾼다).
fn is_visually_empty(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_whitespace() || is_zero_width_invisible(c))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memo {
    /// 정제된 본문(제어문자 제거 + UTF-8 경계 보존 절단). 비어 있지 않음이 보장된다.
    text: String,
    /// **저장 상한(`MEMO_MAX_BYTES`, 64KiB)에서** 잘렸는가. 처리 상한(512KiB) 절단은 여기 안 든다
    /// (내부 비용 방어일 뿐 — `sanitize` doc 참고). 그래서 이 값이 true면 잘린 지점이 정확히 64KiB이고
    /// `memo_truncated_notice`가 말하는 임계와 일치한다(틀린 임계를 말할 여지가 없다).
    truncated: bool,
}

impl Memo {
    /// 원문을 **딱 한 번** 정제한다. 정제 후 비면(F15) `None` — 보낼 것도 저장할 것도 없다.
    ///
    /// 파이프라인은 **입력이 무한대여도 각 단계가 유계**여야 한다(11차 sweep). 순서:
    /// 1. **처리 상한 절단(`MEMO_REDACT_INPUT_MAX`)을 원문에 먼저** — 이 한 번의 절단이 **뒤의 모든
    ///    단계**(제어문자 제거의 O(n) 할당, redaction regex)의 입력을 유계로 만든다. strip 앞에 두는
    ///    이유: chat paste는 수십 MB일 수 있어, strip을 먼저 하면 그 할당이 무제한이 된다.
    /// 2. **제어문자·ANSI escape 제거**(F17) — 화면을 깨지 않게. 개행/탭은 남긴다. ESC(`\x1b`)만 지워도
    ///    뒤따르는 CSI 바이트열(`[33m` 등)은 평문으로 남아 터미널이 시퀀스로 해석하지 않는다.
    /// 3. **redaction**(F14) — secret/PII 마스킹. `[REDACTED:…]` 치환은 **길이를 늘릴 수 있다**.
    /// 4. **저장 상한 절단(`MEMO_MAX_BYTES`)**(F16) — 최종 저장/전송 바이트를 진짜 상한 이하로.
    ///
    /// **두 상한의 역할이 다르다 — 사용자에겐 저장 상한 하나만 보인다**:
    /// - **저장 상한(`MEMO_MAX_BYTES`, 64KiB)**: 사용자 대면. 여기서 잘리면 `truncated=true`이고, notice가
    ///   이 값을 말한다. redaction을 이 절단보다 먼저 해야 실제 상한이 된다(9차→10차 교정 — 치환이 늘린
    ///   길이까지 잡는다). `cap_str`이 UTF-8 경계를 지켜 문자 중간이 깨지지 않는다.
    /// - **처리 상한(`MEMO_REDACT_INPUT_MAX`, 512KiB)**: **순수 내부 비용 방어**(regex 입력·strip 할당을
    ///   유계로). redaction이 맨 앞이면 regex가 원문 전체(무제한)를 보기 때문이다(11차). **이 절단은
    ///   `truncated`에 넣지 않는다** — 사용자 대면 절단이 아니기 때문이다(13차 교정).
    ///
    /// **왜 처리 상한 절단을 truncated에 안 넣나**(핵심): 두 절단을 OR로 합치면 512KiB에서 잘린 걸 notice가
    /// "64KiB에서 잘렸다"고 **틀린 임계**로 말한다. 그리고 실질적으로 최종 사용자가 보는 절단은 **언제나
    /// 저장 상한(64KiB)**이다 — `truncated=true`(post)이려면 redaction 결과가 64KiB를 넘어야 하고, 그때
    /// 잘린 지점은 정확히 64KiB다. 처리 상한(512KiB)이 잘린 극단 입력도 정상 텍스트라면 redaction이 길이를
    /// 안 바꿔 저장 상한이 다시 이겨 결국 64KiB에서 잘린다(post도 true). 처리 상한만 잘리고 저장 상한은
    /// 안 잘리는 유일한 경우는 **512KiB 이상이 redaction으로 64KiB 미만으로 줄어드는 병적 입력**(secret
    /// 도배)뿐인데, 그건 최종 저장물이 온전(redacted)해 "잘렸다"고 할 의미 있는 손실이 없다. 그래서
    /// **처리 상한은 조용히 두고, 사용자에겐 저장 상한 하나만** 보인다 — 틀린 임계를 말할 여지가 없어진다.
    ///
    /// (downstream의 store·build_event redaction은 idempotent라 이미 마스킹된 값에 다시 걸려도 무해하다.)
    pub fn sanitize(raw: &str) -> Option<Self> {
        // 처리 상한 절단을 **맨 앞·원문에** — 이 아래 모든 단계의 입력이 이걸로 유계다. 잘림 플래그는
        // 버린다(`_`): 이건 내부 비용 방어이지 사용자 대면 절단이 아니다(위 doc 참고).
        let (bounded_raw, _processing_cut) =
            crate::agent::tool_record::cap_str(raw, MEMO_REDACT_INPUT_MAX);
        let cleaned: String = bounded_raw
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .collect();
        // redact가 실제로 받는 입력 길이를 테스트가 관찰한다 — 처리 상한 절단을 제거하면(무제한 입력이
        // regex에 감) 이 값이 상한을 넘어 `sanitize_bounds_redaction_input…`이 결정적으로 깨진다.
        #[cfg(test)]
        test_redact_probe::record(cleaned.len());
        let redacted = redact(&cleaned);
        // 저장 상한 절단: redaction이 늘린 최종 바이트를 진짜 상한 이하로. **이것만** 사용자 대면
        // `truncated`다 — notice가 말하는 임계(64KiB)와 정확히 일치한다.
        let (text, truncated) = crate::agent::tool_record::cap_str(&redacted, MEMO_MAX_BYTES);
        // 빈 판정은 **사람 눈 기준**이다. `trim()`은 공백(White_Space)만 지우므로, 폭 0/비가시 format
        // 문자(U+200B ZWSP, U+FEFF BOM, U+2060 WJ, bidi 제어 등)로만 이뤄진 메모는 화면엔 비었는데
        // `trim().is_empty()`를 통과해 "기록됨"이 된다 — 사람은 빈 걸 넣었다고 느끼는데 보이지 않는
        // 기록이 남는다. **저장 내용은 건드리지 않는다**(이모지 ZWJ·다국어 조이너가 보이는 문자와
        // 섞이면 그대로 보존): 여기선 오직 "보이는 문자가 하나도 없는가"만 보고, 순수 비가시 메모면
        // `None` → 빈-메모 경로가 사람에게 "메모가 비었다"고 알린다(빈 문자열·공백뿐과 같은 취급).
        if is_visually_empty(&text) {
            return None;
        }
        Some(Self { text, truncated })
    }

    /// 정제된 본문 — **로컬 저장과 원격 전송이 이 하나의 값을 공유한다**(둘이 각자 정규화하면
    /// 저장된 메모와 전송된 메모가 달라진다).
    pub fn text(&self) -> &str {
        &self.text
    }

    /// **저장 상한(64KiB)에서** 잘렸는가. 호출부가 `memo_truncated_notice`로 사용자에게 알리는 데 쓴다
    /// (처리 상한 절단은 여기 안 든다 — `Memo::sanitize` doc 참고).
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// 사람이 "지금 이 순간을 남긴다"고 판단해 기록한다 — 임계에 안 걸려도 사람이 이상하다고
/// 느낀 순간을 남기는 경로. severity는 항상 INFO(사건이 아니라 사람의 관찰 기록이다).
///
/// **`attrs` 키에 `exit_code`/`cwd`/`duration_ms`를 쓰지 마라** — 서버의 `EVENT_MAPPED_KEYS`가
/// 이 키들을 컬럼으로 흡수하며 attrs에서 지운다.
///
/// sync 호출부(CLI `aic snapshot record --memo`)용. async 호출부(chat `handle_record`)는 tokio
/// worker를 막지 않는 [`snapshot_recorded_async`]를 쓴다 — 병적 입력 처리는 이미 [`Memo::sanitize`]가
/// 끝냈고(빈 메모면 `Memo` 자체가 안 만들어진다), 여기선 `build_snapshot_event`로 조립만 한다.
///
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
/// 이유는 `query_async` 문서 참고(sync IPC를 async에서 그냥 부르면 tokio worker가 막힌다).
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
    ///
    /// **이 메모의 지연량이 아니다.** spool은 네 exporter(events/connections/changes/agent)가
    /// **공유**하므로, 이 수치는 "지금 collector로 못 나가고 있는 배치 전체"이지 이 메모가 그 안
    /// 어디에 있는지는 말해 주지 않는다. 안내 문구도 그 선을 넘지 않아야 한다.
    Delivered { backlog: u64 },
    /// aicd가 받아들였지만 **구독 상태를 확인하지 못했다**(status 조회 실패). 도달 여부를 **모른다**.
    ///
    /// `Delivered`로 뭉개면 **모르는 것을 안다고 말하는 것**이다. 이 라운드에서 걸린 바로 그 종류의
    /// 거짓말이라, 모름은 모름으로 남긴다.
    Unknown,
    /// **write는 성공했는데 aicd 응답을 못 받았다**(read timeout 등). 메모가 소켓을 떠났으므로 aicd가
    /// 받아 publish했을 수 있는데, 응답만 늦게/못 왔다.
    ///
    /// [`NotSent`](Self::NotSent)와 **다르다**: NotSent는 "확실히 안 나감"(connect/write 실패)이고,
    /// 이건 "나갔을 수 있으나 수용 여부 모름"이다. read timeout을 NotSent로 뭉치면 도달했을 메모를
    /// 유실로 오보한다. [`Unknown`](Self::Unknown)과도 다르다: Unknown은 aicd가 **받았음이 확실**하고
    /// (Pong) 이후 도달만 모르지만, 여기선 aicd가 받았는지조차 모른다. verdict는 셋 다 `Unknown`이되
    /// 문구가 각각 아는 만큼만 말한다.
    SentNoReply,
    /// **보내지 못했다** — connect/write 실패(미실행·backlog 포화·부분 write). 이건 probe가 아니라
    /// **전송 실패 그 자체**이며, 메모가 소켓을 떠나지 못했음이 확실하다.
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
    /// aicd가 받아들였고 **받아 갈 구독자가 있다**. 우리가 동기적으로 알 수 있는 최선이다.
    ///
    /// **"서버에 도착했다"가 아니다** — [`SendResult`]의 "우리가 알 수 있는 것의 천장" 참고. 구독자
    /// 존재가 이 이벤트의 소비를 보장하지 않고(버스는 lossy broadcast — 폭주 시 `Lagged`로 유실),
    /// 그 뒤 collector push는 비동기다. 즉 **"도달 경로에 올랐다"까지**이지 "서버가 갖고 있다"가
    /// 아니다. 안내 문구도 이 선을 넘으면 안 된다(로컬 실패 경로에서 특히 — 유일 사본을 과신시킨다).
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
    /// **write는 성공했는데 응답을 못 받았다**(read timeout·과대 length·응답 파싱 실패).
    ///
    /// 메모가 소켓을 **떠났다** — aicd가 받아 publish까지 했을 수 있는데 응답만 늦게/못 온 경우다.
    /// 이걸 [`Failed`](Self::Failed)로 뭉치면 **도달했을 메모를 "안 보냈다"고 오보**한다. "보냈다"(write
    /// 성공)와 "받아들여졌다"(응답 확인)는 다른 명제라는, 우리가 `Accepted`를 팔 때 세운 구분의 반대편이다.
    SentNoReply,
    /// **connect/write 단계에서 실패**(미실행·backlog 포화·부분 write) — 메모가 소켓을 떠나지 못했다.
    /// 확실히 안 나갔다.
    Failed,
}

/// IPC 왕복 결과 — **실패 단계**를 구분한다(transport 내부). read 단계 실패("write는 됐으니 나갔을 수
/// 있음")와 connect/write 단계 실패("확실히 안 나감")를 뭉치면 나간 메모를 유실로 오보하므로, 경계를
/// write 성공 지점에 둔다.
enum Roundtrip {
    /// 응답을 받아 파싱까지 성공. `IpcResponse`가 큰 enum이라 box로 담아 variant 크기 편차를 줄인다.
    Replied(Box<IpcResponse>),
    /// connect/write 이전·도중 실패 — 메모가 **소켓을 떠나지 못했다**.
    SendFailed,
    /// write 성공 후 실패(read timeout·과대 length·파싱 실패) — 메모가 **나갔을 수 있으나** 수용 여부 모름.
    NoReply,
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
            // 갔지만 collector로 나가지 못한 배치가 spool에 쌓여 있다 — "서버에서 이미 보인다"고
            // 오해하지 않도록 관찰 사실을 덧붙인다(유실은 아니다).
            //
            // backlog는 **공유 spool 전체**의 적재량이라 이 메모의 지연량이 아니다. 그래서 "이 메모가
            // {backlog}개만큼 밀렸다"가 아니라 "지금 spool이 밀려 있다"는 사실만 말한다.
            // "복구되면 전송됩니다"는 **단언**이 되면 안 된다 — spool은 적재 한도를 넘기면 배치를
            // 버린다(`spool_dropped`가 그 증거다). 보장할 수 없는 걸 보장처럼 쓰지 않고, 사실만 말한다:
            // collector가 살아나면 재전송을 **시도**한다.
            RecordOutcome::Delivered { backlog } => Some(format!(
                "메모를 aicd에 전달했습니다. 다만 지금 collector로 나가지 못한 배치가 spool에 \
                 {backlog}개 쌓여 있어(모든 exporter 합계), 서버 반영이 지연될 수 있습니다\
                 (collector가 복구되면 재전송을 시도합니다)."
            )),
            RecordOutcome::Unknown => Some(
                "메모를 aicd에 전달했지만 exporter 상태를 확인하지 못해 서버 도달 여부는 알 수 \
                 없습니다."
                    .to_string(),
            ),
            // "보냈지만 응답을 못 받았다" — aicd가 받았는지조차 모른다(Unknown은 Pong으로 수용이
            // 확실했지만 여기선 아니다). "보내지 못했습니다"(NotSent)라고 하면 나갔을 메모를 유실로
            // 오보하는 거짓말이라, 아는 만큼만 말한다.
            RecordOutcome::SentNoReply => Some(
                "메모를 보냈지만 aicd 응답을 확인하지 못했습니다 — 받았는지 알 수 없습니다."
                    .to_string(),
            ),
            RecordOutcome::NotSent => Some(
                "원격 전송 실패(aicd 미실행·연결 불가) — 이 메모는 서버에 남지 않습니다."
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
                 기동 실패했거나 죽은 것이니 aicd 로그를 확인하세요. 이 메모는 서버에 \
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
            // 도달 여부를 확인할 수 없는 경우들 — 단정하지 않는다. `SentNoReply`(응답 못 받음)와
            // `AgentExporterDown`(방금 죽었을 수 있음) 모두 유실을 확정할 근거가 없다.
            RecordOutcome::Unknown
            | RecordOutcome::SentNoReply
            | RecordOutcome::AgentExporterDown => RemoteVerdict::Unknown,
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
        // write는 성공했으나 응답을 못 받았다 — 나갔을 수 있으니 "안 보냈다"(NotSent)로 뭉치지 않는다.
        SendResult::SentNoReply => return RecordOutcome::SentNoReply,
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

/// IPC 왕복 결과를 [`SendResult`]로 접는다(순수 함수). **성공 응답일 때만 `Accepted`다** — 알 수 없는
/// 응답 variant도 성공으로 세지 않는다(모르는 응답을 성공으로 낙관하면 그게 곧 다음 거짓말이 된다).
/// 그리고 **`NoReply`(write 성공 후 응답 실패)를 `Failed`로 뭉치지 않는다** — 나갔을 메모를 유실로
/// 오보하지 않으려는 게 이 함수의 핵심이다.
fn to_send_result(rt: Roundtrip) -> SendResult {
    match rt {
        Roundtrip::Replied(resp) => match *resp {
            IpcResponse::Pong => SendResult::Accepted,
            IpcResponse::Error { message } => SendResult::Rejected(message),
            // 이 요청에 올 수 없는 응답 — 프로토콜이 어긋난 것이니 성공이라 볼 근거가 없다.
            other => SendResult::Rejected(format!("예상하지 못한 응답: {other:?}")),
        },
        // connect/write 실패 = 확실히 안 나감.
        Roundtrip::SendFailed => SendResult::Failed,
        // write는 됐는데 응답을 못 받음 = 나갔을 수 있으나 수용 여부 모름.
        Roundtrip::NoReply => SendResult::SentNoReply,
    }
}

/// exporter가 지금 collector에 닿고 있는지 aicd에 묻는다 — **`/record now` 결과 보강용**.
///
/// `None`은 **aicd에 물어보지 못했다**는 뜻이다 — 미실행이거나, 이 요청을 모르는 구버전이거나,
/// 응답이 timeout됐다. `/record now`는 send 결과가 1차 신호이고 이 status는 부가 보강이라, 여기선
/// 실패 단계를 뭉개도 된다. **status bar는 다르다** — 아래 [`exporter_status_probe`]를 써야 한다
/// (timeout을 "off"로 오보하면 안 되므로).
pub fn exporter_status() -> Option<aic_common::ExporterStatus> {
    to_exporter_status(query(&IpcRequest::GetExporterStatus))
}

/// [`exporter_status`]의 async 판.
pub async fn exporter_status_async() -> Option<aic_common::ExporterStatus> {
    to_exporter_status(query_async(&IpcRequest::GetExporterStatus).await)
}

/// status bar가 본 exporter 조회 결과 — **"값 있음 / 못 닿음 / 못 알아냄"을 구분**한다.
///
/// 왜 `Option`으로 뭉치지 않나(뼈아픈 교훈): 예전엔 status bar도 [`exporter_status`]의 `None`을 받아
/// `DaemonDown`("aicd off")으로 접었다. 그런데 `None`엔 **"connect가 거부됨(진짜 꺼짐)"**과
/// **"write는 됐는데 응답이 timeout(살아있는데 느림)"**이 섞여 있었다 — 후자를 "off"라 말하는 건
/// 우리가 이 프로젝트 내내 잡은 "모르는 걸 안다고 단언"하는 거짓말이다(aicd는 떠 있는데 꺼졌다고 보고).
pub enum ExporterProbe {
    /// 응답을 받았다 — 이 값으로 상태를 접는다.
    Status(aic_common::ExporterStatus),
    /// connect/write가 실패했다(`SendFailed`) = 소켓에 **못 닿았다**. "aicd off"가 정직한 유일한 경우.
    Down,
    /// 요청은 나갔는데 응답을 못 받았다(`NoReply` — read timeout 등), 또는 이 요청을 모르는 구버전이
    /// graceful Error로 답했다. 어느 쪽도 **"꺼짐"이 아니다** — aicd는 살아있다. "모름"으로 다뤄
    /// 직전 상태를 유지한다(호출부 책임).
    Unknown,
}

/// status bar 전용 조회. emit 경로와 달리 여유로운 [`STATUS_QUERY_TIMEOUT`]을 쓰고, 실패 단계를
/// [`ExporterProbe`]로 **구분해** 돌려준다(timeout을 "off"로 오보하지 않으려고).
pub fn exporter_status_probe() -> ExporterProbe {
    to_exporter_probe(query_status(&IpcRequest::GetExporterStatus))
}

/// IPC 왕복 결과를 [`ExporterProbe`]로 접는다(순수 함수). **`SendFailed`(못 닿음)만 `Down`**이고,
/// `NoReply`·예상 못 한 응답은 `Unknown`이다 — "못 알아냄"을 "꺼짐"으로 단정하지 않는 게 핵심이다.
fn to_exporter_probe(rt: Roundtrip) -> ExporterProbe {
    match rt {
        Roundtrip::Replied(resp) => match *resp {
            IpcResponse::ExporterStatus(s) => ExporterProbe::Status(s),
            // 이 요청에 올 수 없는 응답(구버전 graceful Error 포함) — 상태를 알 수 없지만 aicd는 답했다.
            _ => ExporterProbe::Unknown,
        },
        // connect/write 실패 = 소켓에 못 닿음. 진짜 "off".
        Roundtrip::SendFailed => ExporterProbe::Down,
        // 나갔는데 응답 없음 = 살아있는데 느림. "off"라 단정하지 않는다.
        Roundtrip::NoReply => ExporterProbe::Unknown,
    }
}

/// IPC 왕복 결과에서 `ExporterStatus`를 뽑는다(`/record now` 보강용). 구버전 aicd는 unknown request를
/// graceful Error로 답하므로 그 응답도 "조회 불가"(None)로 접는다. **`/record now`는** send 결과가
/// 1차 신호라 실패 단계를 구분할 필요가 없어(SendFailed·NoReply 모두 "상태 모름") `Replied` 외엔 전부
/// None이다 — status bar는 이 뭉개기를 쓰면 안 된다([`to_exporter_probe`]로 구분).
fn to_exporter_status(rt: Roundtrip) -> Option<aic_common::ExporterStatus> {
    match rt {
        Roundtrip::Replied(resp) => match *resp {
            IpcResponse::ExporterStatus(s) => Some(s),
            _ => None,
        },
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
/// **테스트에서는 소켓 대신 in-process sink로 간다**(`test_sink`) — `cargo test`가 개발 머신의
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

/// 요청을 보내고 응답을 받아 돌려준다(실 aicd 소켓). 프레임은 length-prefixed JSON(`encode_frame`).
/// emit 경로(fire-and-forget + `/record now`)용 — 짧은 [`IO_TIMEOUT`].
#[cfg(not(test))]
fn query(req: &IpcRequest) -> Roundtrip {
    query_at(&aic_common::aicd_socket_path(), req, IO_TIMEOUT)
}

/// status bar 조회 전용 — emit보다 여유로운 [`STATUS_QUERY_TIMEOUT`]. 지연에 안 민감한 주기 조회가
/// 부하 중 300ms를 넘겨 "off"로 오보하는 걸 막는다.
#[cfg(not(test))]
fn query_status(req: &IpcRequest) -> Roundtrip {
    query_at(&aic_common::aicd_socket_path(), req, STATUS_QUERY_TIMEOUT)
}

/// 테스트에선 실 소켓을 안 건드린다 — 데몬 없음(=SendFailed)으로 고정([`query`] cfg(test) 참고).
#[cfg(test)]
fn query_status(_req: &IpcRequest) -> Roundtrip {
    Roundtrip::SendFailed
}

/// 테스트에서는 **실 aicd 소켓을 절대 건드리지 않는다**. 쓰기 경로는 [`dispatch`]가 sink로 돌리지만,
/// 읽기 경로(`exporter_status` → `sys_sampler::sample`)가 남아 있으면 테스트 결과가 "이 개발 머신에
/// aicd가 떠 있는가"에 따라 달라진다 — 이 저장소가 금지하는 바로 그 패턴이다(테스트는 코드의
/// 불변식을 검증해야지 머신 상태를 반영하면 안 된다). 데몬 없음(=SendFailed)으로 고정한다.
/// 전송 계층 자체는 [`query_at`]에 경로를 주입해 따로 검증한다(fake 서버로 NoReply까지).
#[cfg(test)]
fn query(_req: &IpcRequest) -> Roundtrip {
    Roundtrip::SendFailed
}

/// 소켓 경로를 **주입받는** sync IPC. 프로덕션은 [`query`]가 실 경로를 넣고, 테스트는 존재하지 않는
/// 경로(→ SendFailed)나 fake 서버(→ NoReply)를 주입해 각 단계를 실 aicd 없이 검증한다.
///
/// **실패 단계를 [`Roundtrip`]으로 구분한다**: connect/write 이전·도중 실패는 `SendFailed`(확실히
/// 안 나감), write 성공 후 실패는 `NoReply`(나갔을 수 있음). 경계는 **write+flush 성공 지점**이다 —
/// 그 전 실패는 부분 write든 connect 실패든 aicd가 유효 프레임을 못 받으므로 안 나간 것이고, 그 후
/// 실패(read timeout 등)는 프레임이 이미 커널로 넘어갔으므로 나갔을 수 있다.
fn query_at(socket: &std::path::Path, req: &IpcRequest, timeout: Duration) -> Roundtrip {
    let Ok(payload) = serde_json::to_vec(req) else {
        return Roundtrip::SendFailed;
    };
    // **단일 절대 deadline** — connect·write·read **총합**을 `timeout`으로 묶는다(async 판과 대칭).
    // 예전엔 세 단계가 각각 `set_*_timeout`을 독립으로 받아 최악 3×timeout까지 막혔다 — sync 경로는
    // chat emit(`risk_denied` 등)과 status bar가 쓰므로 사용자 눈앞에서 멈춘다. 각 blocking op 직전에
    // **남은 예산**(`deadline.remaining()`)으로 timeout을 다시 준다. `timeout`은 호출부가 정한다 —
    // emit 경로는 `IO_TIMEOUT`(300ms), status 조회는 `STATUS_QUERY_TIMEOUT`(더 여유, 부하 중 오탐 방지).
    let deadline = Deadline::new(timeout);
    // **`UnixStream::connect`를 쓰지 않는다** — 상한이 없다([`connect_unix_timeout`] 참고). connect가
    // 예산을 얼마나 쓰든 아래 remaining()이 그만큼 줄어든 값을 write/read에 준다(총합 유지).
    let Ok(mut stream) = connect_unix_timeout(socket, timeout) else {
        return Roundtrip::SendFailed;
    };

    // write: 남은 예산으로. 만료면 아직 안 보냈으니 SendFailed. `remaining()`은 0(만료)을 `None`으로
    // 주므로 `set_write_timeout(Some(0))`(= 플랫폼상 "무한 대기") 함정에 빠지지 않는다.
    let Some(rem) = deadline.remaining() else {
        return Roundtrip::SendFailed;
    };
    #[cfg(test)]
    test_timeout_probe::record(rem);
    if stream.set_write_timeout(Some(rem)).is_err() {
        return Roundtrip::SendFailed;
    }
    // write_all은 전부 쓰거나 Err(부분 write 포함) — Err면 aicd가 유효 프레임을 못 받으니 SendFailed.
    if stream.write_all(&encode_frame(&payload)).is_err() || stream.flush().is_err() {
        return Roundtrip::SendFailed;
    }

    // ── 여기부터 프레임은 나갔다. 이후 실패는 전부 NoReply(나갔을 수 있으나 수용 여부 모름). ──
    // 4바이트 길이 헤더 → 본문. 상한을 두어 손상된 헤더가 거대한 할당으로 이어지지 않게 한다.
    let Some(rem) = deadline.remaining() else {
        return Roundtrip::NoReply;
    };
    #[cfg(test)]
    test_timeout_probe::record(rem);
    if stream.set_read_timeout(Some(rem)).is_err() {
        return Roundtrip::NoReply;
    }
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        return Roundtrip::NoReply;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_RESPONSE_BYTES {
        return Roundtrip::NoReply; // 응답은 왔으나 못 쓴다 — 수용 여부는 여전히 모름.
    }
    // body read도 같은 deadline의 남은 예산으로(총합 유지).
    let Some(rem) = deadline.remaining() else {
        return Roundtrip::NoReply;
    };
    #[cfg(test)]
    test_timeout_probe::record(rem);
    if stream.set_read_timeout(Some(rem)).is_err() {
        return Roundtrip::NoReply;
    }
    let mut body = vec![0u8; len];
    if stream.read_exact(&mut body).is_err() {
        return Roundtrip::NoReply;
    }
    match serde_json::from_slice(&body) {
        Ok(resp) => Roundtrip::Replied(Box::new(resp)),
        Err(_) => Roundtrip::NoReply,
    }
}

/// EAGAIN(backlog 가득) 재시도 간격. 아래 [`connect_unix_timeout`]의 실측 근거 참고.
const CONNECT_RETRY_SLICE: Duration = Duration::from_millis(10);

/// 데드라인 — `IO_TIMEOUT`이 **connect 전 구간**에 걸리게 하는 단일 기준점.
///
/// 각 재시도마다 timeout을 새로 주면 상한이 무의미해진다(EINTR·EAGAIN이 반복되면 영원히 늘어난다).
/// 그래서 시작 시각을 한 번 잡고 **남은 시간**만 나눠 준다. 순수 로직이라 syscall 없이 테스트된다.
#[derive(Clone, Copy)]
struct Deadline {
    start: std::time::Instant,
    budget: Duration,
}

impl Deadline {
    fn new(budget: Duration) -> Self {
        Self {
            start: std::time::Instant::now(),
            budget,
        }
    }

    /// 남은 시간. 다 썼으면 `None`(= 만료). 남은 시간이 정확히 0인 경우도 만료로 본다
    /// (`Some(0)`을 돌려주면 poll에 timeout=0을 주게 되어 만료를 만료로 다루지 않는다).
    fn remaining(&self) -> Option<Duration> {
        self.budget
            .checked_sub(self.start.elapsed())
            .filter(|left| !left.is_zero())
    }
}

/// timeout 만료 에러(호출부가 `ErrorKind::TimedOut`으로 식별한다).
fn connect_timed_out() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "aicd 소켓 connect timeout (backlog 포화 가능성)",
    )
}

/// 어떤 에러 경로로 빠져나가도 fd를 닫는 가드(누수 금지). `into_raw`로 소유권을 넘길 때만 살아남는다.
struct FdGuard(std::os::unix::io::RawFd);

impl FdGuard {
    /// 소유권을 호출부로 넘기고 Drop의 close를 막는다.
    fn into_raw(self) -> std::os::unix::io::RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// **connect에 상한을 건 UDS 연결.** `std`에는 `UnixStream::connect_timeout`이 없다
/// (`TcpStream`에만 있다). 그래서 `UnixStream::connect`는 **무한정 막힐 수 있고**,
/// `set_read_timeout`/`set_write_timeout`은 **연결이 선 뒤에만** 적용되므로 그 구멍을 못 막는다.
///
/// 왜 실질 위험인가: aicd의 listen backlog가 가득 차면 connect가 막힌다. 그 자리에서 막히는 건
/// chat의 **sync emit 경로**(`tool_run_command`/`risk_denied`/`finding_created`)와 status bar의
/// `exporter_status()`다 — 사용자 눈앞에서 멈춘다. async 경로는 `tokio::time::timeout`이 전 구간을
/// 덮으므로 sync 쪽만 구멍이었다.
///
/// **커널 실측**(추측이 아니라 두 플랫폼에서 직접 재현했다 — 교과서적 recipe와 다르다):
/// - **Linux**: backlog가 가득 찬 AF_UNIX에 non-blocking connect → `EINPROGRESS`가 아니라
///   **`EAGAIN`**. 그리고 그 소켓에 `poll(POLLOUT)`을 걸면 **즉시** 깬다(`revents=0x14`) —
///   즉 poll로 기다리면 **스핀 루프**가 된다. 그래서 `EAGAIN`은 poll하지 않고 **짧게 자고 connect를
///   재시도**한다(연결 상태로 진입한 게 아니라 "지금은 자리 없음"이라는 뜻이기 때문이다).
///   blocking 소켓이었다면 여기서 그냥 멈춘다 — 그게 우리가 막으려는 바로 그 상황이다.
/// - **macOS**: 같은 상황에서 즉시 `ECONNREFUSED`. 멈추지는 않지만, 상한이 있어도 손해가 없다.
///
/// `EINPROGRESS`(다른 커널/미래 대비) 경로는 poll로 기다린 뒤 **반드시 `SO_ERROR`를 확인**한다 —
/// 실패한 connect도 writable로 깨어나므로, 이 확인을 빼면 실패를 성공으로 센다.
fn connect_unix_timeout(path: &std::path::Path, timeout: Duration) -> std::io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    // sockaddr_un 구성 — 경로가 sun_path에 안 들어가면 **명확히 실패**한다. 조용히 잘라 붙이면
    // 엉뚱한 소켓에 연결된다(가장 나쁜 실패).
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= std::mem::size_of_val(&addr.sun_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "소켓 경로가 sun_path 상한을 넘음: {} bytes (max {})",
                bytes.len(),
                std::mem::size_of_val(&addr.sun_path) - 1
            ),
        ));
    }
    for (slot, b) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *b as libc::c_char;
    }

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let guard = FdGuard(fd); // 이 아래 어떤 경로로 나가도 fd가 닫힌다.

    // macOS엔 SOCK_CLOEXEC가 없다 — fcntl로 따로 건다(Linux와 다름).
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let deadline = Deadline::new(timeout);
    let addr_ptr = &addr as *const libc::sockaddr_un as *const libc::sockaddr;
    let addr_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;

    loop {
        if deadline.remaining().is_none() {
            return Err(connect_timed_out());
        }
        let ret = unsafe { libc::connect(fd, addr_ptr, addr_len) };
        if ret == 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // 시그널에 깨졌다 — **남은 시간으로** 재시도한다(전체 timeout을 새로 주지 않는다).
            Some(libc::EINTR) => continue,
            // 이미 연결됨(직전 시도가 비동기로 성사된 경우).
            Some(libc::EISCONN) => break,
            // 연결 진행 중 — poll로 기다린 뒤 SO_ERROR로 진짜 성패를 확인한다.
            Some(libc::EINPROGRESS) | Some(libc::EALREADY) => {
                wait_writable(fd, deadline)?;
                let soerr = socket_error(fd)?;
                if soerr != 0 {
                    return Err(std::io::Error::from_raw_os_error(soerr));
                }
                break;
            }
            // Linux AF_UNIX: backlog 포화. poll하면 즉시 깨어 스핀이 되므로(실측) 자고 재시도한다.
            Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                let Some(left) = deadline.remaining() else {
                    return Err(connect_timed_out());
                };
                std::thread::sleep(CONNECT_RETRY_SLICE.min(left));
                continue;
            }
            _ => return Err(err),
        }
    }

    // blocking으로 되돌린다 — set_read_timeout/set_write_timeout은 blocking 소켓을 전제로 동작한다.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { UnixStream::from_raw_fd(guard.into_raw()) })
}

/// fd가 writable해질 때까지 **남은 시간만큼** 기다린다. `EINTR`이면 남은 시간으로 재시도한다
/// (매번 전체 timeout을 새로 주면 상한이 무의미해진다).
fn wait_writable(fd: std::os::unix::io::RawFd, deadline: Deadline) -> std::io::Result<()> {
    loop {
        let Some(left) = deadline.remaining() else {
            return Err(connect_timed_out());
        };
        let ms = left.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // 남은 시간으로 재시도
            }
            return Err(err);
        }
        if n == 0 {
            return Err(connect_timed_out());
        }
        // POLLOUT/POLLERR/POLLHUP 어느 쪽이든 깼다 — **성패 판정은 호출부의 SO_ERROR가 한다**.
        return Ok(());
    }
}

/// `SO_ERROR`를 읽는다. poll이 깨웠다는 사실만으로 connect 성공이라 볼 수 없다(실패한 connect도
/// writable로 깨어난다) — 이 확인을 빼면 실패한 연결을 성공으로 센다.
fn socket_error(fd: std::os::unix::io::RawFd) -> std::io::Result<libc::c_int> {
    let mut err: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(err)
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
/// **실패 단계를 [`Roundtrip`]으로 구분**하면서 전 구간을 `IO_TIMEOUT` 하나로 덮는다.
///
/// sync `query_at`처럼 경계는 **write+flush 성공 지점**이다: 그 전(connect·write) 실패/timeout은
/// `SendFailed`(안 나감), 그 후(read) 실패/timeout은 `NoReply`(나갔을 수 있음). 예전엔 바깥 timeout
/// 하나가 connect~read를 통째로 덮어 **어느 단계에서 끊겼는지 몰랐다** — read timeout을 SendFailed로
/// 오판해 나간 메모를 유실로 오보하던 자리다.
///
/// 각 단계에 **같은 절대 deadline**(`timeout_at`)을 줘서 총합이 `IO_TIMEOUT`을 넘지 않게 한다(단계마다
/// 새 timeout을 주면 최대 3배로 늘어난다). `spawn_blocking`이 아니라 async I/O인 이유는 [`Roundtrip`]
/// 없던 옛 `query_async` 주석과 동일하다 — future를 drop하면 소켓이 닫혀 스레드가 pin되지 않는다.
#[cfg(not(test))]
async fn query_async(req: &IpcRequest) -> Roundtrip {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout_at;

    let Ok(payload) = serde_json::to_vec(req) else {
        return Roundtrip::SendFailed;
    };
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;

    // connect (실패/timeout = 안 나감).
    let connect = timeout_at(
        deadline,
        tokio::net::UnixStream::connect(aic_common::aicd_socket_path()),
    );
    let Ok(Ok(mut stream)) = connect.await else {
        return Roundtrip::SendFailed;
    };

    // write + flush (실패/timeout = 유효 프레임 못 보냄 = 안 나감).
    let frame = encode_frame(&payload);
    let write = timeout_at(deadline, async {
        stream.write_all(&frame).await?;
        stream.flush().await
    });
    if !matches!(write.await, Ok(Ok(()))) {
        return Roundtrip::SendFailed;
    }

    // ── 여기부터 프레임은 나갔다. 이후 실패는 전부 NoReply. ──
    let read = timeout_at(deadline, async {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_RESPONSE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "응답이 너무 큼",
            ));
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok::<Vec<u8>, std::io::Error>(body)
    });
    let Ok(Ok(body)) = read.await else {
        return Roundtrip::NoReply;
    };
    match serde_json::from_slice(&body) {
        Ok(resp) => Roundtrip::Replied(Box::new(resp)),
        Err(_) => Roundtrip::NoReply,
    }
}

/// sync [`query`]와 같은 이유로 테스트에서는 소켓에 나가지 않는다.
#[cfg(test)]
async fn query_async(_req: &IpcRequest) -> Roundtrip {
    Roundtrip::SendFailed
}

/// 테스트 전용 이벤트 sink — `cargo test`가 개발 머신의 **실 aicd에 가짜 이벤트를 밀어 넣지 않도록**
/// [`dispatch`]/[`dispatch_async`]를 소켓 대신 여기로 보낸다. 이 저장소에서 실제로 났던 사고다
/// (테스트 픽스처가 실 aicd를 거쳐 서버까지 나갔다).
///
/// thread-local이라 병렬 테스트끼리 섞이지 않는다(각 테스트는 자기 스레드의 sink만 본다).
/// **주의**: `#[cfg(test)]`는 이 크레이트의 unit test에만 걸린다 — `tests/`의 integration test는
/// 라이브러리를 cfg(test) 없이 링크하므로 여기 오지 않는다(현재 agent_event를 쓰는 integration
/// test는 없다).
/// 테스트 전용 — `Memo::sanitize`가 **redact에 넘긴 입력 길이**를 기록한다. 처리 상한(1차 절단)이
/// 실제로 적용됐는지 **시계 없이 결정적으로** 관찰하려는 것이다(시간 기반 테스트는 flaky). 1차 절단을
/// 제거하면 이 값이 상한을 넘어 테스트가 깨진다. thread-local이라 병렬 테스트끼리 섞이지 않는다
/// (`Memo::sanitize`는 handle_record의 spawn_blocking **이전**, 같은 스레드에서 불린다).
#[cfg(test)]
pub(crate) mod test_redact_probe {
    use std::cell::Cell;

    thread_local! {
        static LAST_INPUT_LEN: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub(crate) fn record(len: usize) {
        LAST_INPUT_LEN.with(|c| c.set(Some(len)));
    }
    pub(crate) fn reset() {
        LAST_INPUT_LEN.with(|c| c.set(None));
    }
    /// 마지막 `Memo::sanitize`가 redact에 넘긴 입력 길이(호출 없었으면 `None`).
    pub(crate) fn last_input_len() -> Option<usize> {
        LAST_INPUT_LEN.with(|c| c.get())
    }
}

/// 테스트 전용 — `query_at`가 각 blocking op 직전에 `set_*_timeout`에 넘긴 timeout을 순서대로 기록한다.
/// **단일 deadline**을 쓰는지(값이 단조 감소)를 **시계 없이** 결정적으로 관찰한다 — 세 단계 독립
/// `IO_TIMEOUT`으로 되돌리면 값이 전부 같아져(감소 안 함) 테스트가 깨진다. thread-local이라 병렬 안전.
#[cfg(test)]
pub(crate) mod test_timeout_probe {
    use std::cell::RefCell;
    use std::time::Duration;

    thread_local! {
        static TIMEOUTS: RefCell<Vec<Duration>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(d: Duration) {
        TIMEOUTS.with(|c| c.borrow_mut().push(d));
    }
    /// 기록을 꺼내 비운다(호출 순서 = write, read-len, read-body).
    pub(crate) fn drain() -> Vec<Duration> {
        TIMEOUTS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }
}

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

    // ── connect 상한(sync IPC의 유일한 구멍이었다) ──────────────────────────────

    #[test]
    fn deadline_shrinks_and_expires_and_never_renews() {
        // 상한이 **전 구간**에 걸린다는 불변식의 핵심 — 재시도(EINTR/EAGAIN)마다 timeout을 새로
        // 주면 상한이 무의미해진다. 시계·syscall 없이 순수 로직만 고정한다.
        let d = Deadline::new(Duration::from_millis(50));
        let first = d.remaining().expect("방금 만들었으니 남아 있어야");
        assert!(first <= Duration::from_millis(50));

        std::thread::sleep(Duration::from_millis(60));
        assert!(
            d.remaining().is_none(),
            "예산을 다 썼는데 남은 시간이 있다고 한다(재시도마다 상한이 갱신되는 버그)"
        );

        // 예산 0은 즉시 만료(poll에 timeout=0을 넘겨 '만료를 만료로 다루지 않는' 경로 방지).
        assert!(Deadline::new(Duration::ZERO).remaining().is_none());
    }

    #[test]
    fn connect_rejects_path_too_long_for_sun_path_instead_of_truncating() {
        // 조용히 잘라 붙이면 **엉뚱한 소켓에 연결**된다 — 가장 나쁜 실패다. 명확한 에러로 거절한다.
        let long = std::path::PathBuf::from("/tmp").join("a".repeat(300));
        let err = connect_unix_timeout(&long, Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
    }

    #[test]
    fn connect_succeeds_and_roundtrips_against_a_real_listener() {
        // 상한을 걸면서 **정상 경로를 깨뜨리지 않았는지**(O_NONBLOCK 해제, SO_ERROR 오판 없음).
        // 여기서 blocking으로 되돌리지 않으면 아래 read가 WouldBlock으로 깨진다.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            s.write_all(b"pong!").unwrap();
        });

        let mut c = connect_unix_timeout(&path, Duration::from_millis(500)).expect("연결 실패");
        c.write_all(b"ping!").unwrap();
        let mut buf = [0u8; 5];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong!");
        server.join().unwrap();
    }

    #[test]
    fn connect_to_missing_socket_fails_fast_not_by_timing_out() {
        // 데몬 미실행(정상 상태)은 **즉시** 에러여야 한다 — timeout까지 기다리면 그만큼 chat이 멈춘다.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sock");
        let t0 = std::time::Instant::now();
        let err = connect_unix_timeout(&missing, Duration::from_secs(5)).unwrap_err();
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "없는 소켓인데 timeout까지 기다렸다: {:?}",
            t0.elapsed()
        );
        assert_ne!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    }

    #[test]
    fn connect_never_hangs_when_backlog_is_saturated() {
        // **이 테스트가 게이트의 본체다**: aicd가 accept를 못 따라가면 backlog가 차고, 그때
        // `UnixStream::connect`는 **상한 없이 막힌다**(std에 connect_timeout이 없다). 그 자리에서
        // 멈추는 건 chat의 sync emit 경로와 status bar다.
        //
        // 커널 실측(추측이 아니라 두 플랫폼에서 재현):
        // - **Linux**: backlog 포화 시 non-blocking connect가 `EAGAIN`을 낸다(=blocking이었다면
        //   여기서 멈춘다). 따라서 우리 함수는 `TimedOut`으로 빠져나와야 한다. 상한이 없으면 이
        //   테스트는 **영원히 끝나지 않는다**(= 회귀가 즉시 드러난다).
        // - **macOS**: 같은 상황에서 즉시 `ECONNREFUSED`라 멈추지 않는다. 그래서 macOS에서 이
        //   테스트가 검증하는 건 "행이 없다 + 유한 시간에 Err"까지다. 커널이 다른 것뿐이라 skip하지
        //   않고, **두 플랫폼 공통 불변식**("절대 무한정 막히지 않는다")을 고정한다.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full.sock");
        // backlog를 최소로 잡고 **accept하지 않는다**(리스너는 살려 둔다 — drop되면 ECONNREFUSED가 된다).
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        unsafe {
            use std::os::unix::io::AsRawFd;
            libc::listen(listener.as_raw_fd(), 0);
        }

        let timeout = Duration::from_millis(200);
        let mut held = Vec::new(); // 성공한 연결은 살려 둬야 큐가 안 빈다.
        let mut saw_err = false;
        let t0 = std::time::Instant::now();
        for _ in 0..256 {
            match connect_unix_timeout(&path, timeout) {
                Ok(s) => held.push(s),
                Err(_) => {
                    saw_err = true;
                    break;
                }
            }
            // 상한이 있으면 최악이라도 (시도 수 × timeout) 안에 끝난다. 무한정 막히면 여기 못 온다.
            assert!(
                t0.elapsed() < Duration::from_secs(30),
                "connect가 상한 없이 막혔다"
            );
        }

        assert!(
            saw_err,
            "backlog를 채웠는데도 256번 모두 성공했다 — 이 테스트가 공허하다"
        );
        // 어떤 커널이든 **유한 시간**에 끝나야 한다(이게 이 게이트의 불변식이다).
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "connect가 상한 없이 막혔다: {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn query_without_daemon_is_send_failed_not_no_reply() {
        // aicd가 없을 때(connect 실패) `SendFailed`여야 한다 — 소켓을 못 열었으니 프레임이 나가지도
        // 못했다. 이걸 NoReply("나갔을 수 있음")로 오판하면 안 된다. **실 소켓을 쓰지 않는다**:
        // 존재하지 않는 경로를 주입해 "데몬 없음"을 결정적으로 만든다.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-aicd.sock");
        let rt = query_at(&missing, &IpcRequest::GetExporterStatus, IO_TIMEOUT);
        assert!(
            matches!(rt, Roundtrip::SendFailed),
            "없는 소켓(connect 실패)인데 SendFailed가 아니다"
        );
        // 상태 조회로는 "조회 불가"(None)로 접히고, 전송 결과로는 NotSent다(확실히 안 나감).
        assert_eq!(to_exporter_status(rt), None);
        assert_eq!(to_send_result(Roundtrip::SendFailed), SendResult::Failed);
        assert_eq!(
            classify_outcome(SendResult::Failed, None),
            RecordOutcome::NotSent
        );
    }

    #[test]
    fn exporter_probe_distinguishes_down_from_unknown() {
        use aic_common::ExporterStatus;
        // **핵심**: status bar는 "못 닿음(Down)"과 "못 알아냄(Unknown)"을 구분해야 한다.
        // SendFailed(connect/write 실패)만 Down("aicd off")이고, NoReply(응답 timeout)는 Unknown이다 —
        // 살아있는 aicd가 잠깐 느린 걸 "꺼짐"으로 오보하지 않으려는 게 이 매핑의 전부다.
        // mutation: NoReply를 Down으로 바꾸면(=예전 거짓 "off") 이 단언이 깨진다.
        assert!(matches!(
            to_exporter_probe(Roundtrip::SendFailed),
            ExporterProbe::Down
        ));
        assert!(
            matches!(
                to_exporter_probe(Roundtrip::NoReply),
                ExporterProbe::Unknown
            ),
            "NoReply(살아있는데 느림)를 Down으로 오보한다"
        );
        // 응답을 받으면 그 값으로 Status.
        let s = ExporterStatus {
            enabled: true,
            ..Default::default()
        };
        assert!(matches!(
            to_exporter_probe(Roundtrip::Replied(Box::new(IpcResponse::ExporterStatus(s)))),
            ExporterProbe::Status(_)
        ));
        // 예상 못 한 응답(구버전 graceful Error 등)은 "꺼짐"이 아니라 "모름"이다 — aicd는 답했으니까.
        assert!(
            matches!(
                to_exporter_probe(Roundtrip::Replied(Box::new(IpcResponse::Error {
                    message: "unknown request".into()
                }))),
                ExporterProbe::Unknown
            ),
            "구버전 graceful Error를 Down으로 오보한다"
        );
    }

    #[test]
    fn read_timeout_after_write_is_sent_no_reply_not_failed() {
        // **게이트 1의 본체**: fake 서버가 요청을 받되 **응답을 안 보내면**, client는 write까지 성공한
        // 뒤 read가 timeout된다 — 프레임은 이미 나갔으니 `NoReply`(나갔을 수 있음)여야지 `SendFailed`
        // (안 나감)가 아니다. read timeout을 SendFailed로 뭉치면 도달했을 메모를 유실로 오보한다.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mute.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // 요청을 받아 읽기만 하고 응답은 절대 안 보내는 서버 — accept한 소켓을 살려 둬 연결을 유지한다.
        let server = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                use std::io::Read;
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf); // 요청은 읽되 응답은 안 씀
                std::thread::sleep(IO_TIMEOUT * 3); // client read가 timeout날 때까지 소켓 유지
            }
        });

        let rt = query_at(&path, &IpcRequest::GetExporterStatus, IO_TIMEOUT);
        assert!(
            matches!(rt, Roundtrip::NoReply),
            "write 성공 후 read timeout인데 NoReply가 아니다"
        );
        assert_eq!(to_send_result(Roundtrip::NoReply), SendResult::SentNoReply);
        // 그리고 사후 결과는 NotSent가 아니라 SentNoReply(verdict Unknown)다.
        let outcome = classify_outcome(SendResult::SentNoReply, None);
        assert_eq!(outcome, RecordOutcome::SentNoReply);
        assert_eq!(outcome.verdict(), RemoteVerdict::Unknown);
        assert_ne!(outcome, RecordOutcome::NotSent, "나간 메모를 유실로 오보");
        let _ = server.join();
    }

    #[test]
    fn sync_query_shares_one_deadline_across_stages_not_three_independent() {
        // **게이트 2**: sync query_at도 async처럼 **단일 deadline**을 써야 총 상한이 IO_TIMEOUT이다.
        // 세 단계가 독립 IO_TIMEOUT을 받으면 최악 3×IO_TIMEOUT(=900ms) — sync는 chat emit·status bar가
        // 쓰므로 사용자 눈앞 멈춤이다. **시계에 의존하지 않고**, 각 op에 넘긴 timeout이 **단조 감소**하는지
        // (= 하나의 줄어드는 deadline에서 나왔는지)로 결정적으로 잡는다.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reply.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // 요청을 받고 **즉시 Pong으로 응답** → client의 read(len·body)가 성사돼 timeout 3개(write·len·body)
        // 가 모두 기록된다(mute 서버였다면 read가 timeout나 body 단계에 못 가 2개만 기록된다).
        let server = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut hdr = [0u8; 4];
                if s.read_exact(&mut hdr).is_ok() {
                    let n = u32::from_be_bytes(hdr) as usize;
                    let mut body = vec![0u8; n];
                    let _ = s.read_exact(&mut body);
                }
                let resp = serde_json::to_vec(&IpcResponse::Pong).unwrap();
                let _ = s.write_all(&encode_frame(&resp));
            }
        });

        let _ = test_timeout_probe::drain(); // 앞선 잔여 제거
        let _ = query_at(&path, &IpcRequest::GetExporterStatus, IO_TIMEOUT);
        let timeouts = test_timeout_probe::drain();

        assert_eq!(
            timeouts.len(),
            3,
            "write + read-len + read-body 3단계여야: {timeouts:?}"
        );
        // 모든 op의 timeout ≤ IO_TIMEOUT(총 예산을 넘게 주지 않는다).
        for t in &timeouts {
            assert!(*t <= IO_TIMEOUT, "op timeout이 총 예산을 넘음: {t:?}");
        }
        // **단조 감소**: 하나의 줄어드는 deadline에서 나왔다. 세 독립 IO_TIMEOUT이면 전부 같아 깨진다.
        // (op 사이에 실시간이 지나므로 remaining이 strict하게 준다 — 시계 값을 단언하는 게 아니라 순서만.)
        assert!(
            timeouts[1] < timeouts[0],
            "read-len이 write보다 크거나 같다(독립 timeout 회귀): {timeouts:?}"
        );
        assert!(
            timeouts[2] < timeouts[1],
            "read-body가 read-len보다 크거나 같다(독립 timeout 회귀): {timeouts:?}"
        );
        let _ = server.join();
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
        assert_eq!(
            to_send_result(Roundtrip::Replied(Box::new(IpcResponse::Pong))),
            SendResult::Accepted
        );

        // 명시적 거절 → 실패. 이유(에러 메시지)를 보존해 사용자에게 보여준다(왜 거절됐는지가 진단이다).
        let rejected = to_send_result(Roundtrip::Replied(Box::new(IpcResponse::Error {
            message: "bus full".to_string(),
        })));
        assert_eq!(rejected, SendResult::Rejected("bus full".to_string()));

        // 이 요청에 올 수 없는 응답도 성공으로 낙관하지 않는다 — 모르는 응답을 성공으로 세는 게
        // 바로 다음 거짓말의 씨앗이다.
        let weird = to_send_result(Roundtrip::Replied(Box::new(IpcResponse::Lines(vec![]))));
        assert!(
            matches!(weird, SendResult::Rejected(_)),
            "예상 못 한 응답을 성공으로 셌다: {weird:?}"
        );

        // connect/write 실패 → 전송 실패(확실히 안 나감). read 실패는 별건이다(위 전용 테스트).
        assert_eq!(to_send_result(Roundtrip::SendFailed), SendResult::Failed);
        assert_eq!(to_send_result(Roundtrip::NoReply), SendResult::SentNoReply);
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
    fn sanitize_treats_zero_width_only_memo_as_empty() {
        // 폭 0/비가시 문자로만 이뤄진 메모는 사람 눈엔 비었다 — `.is_control()`(Cc)은 이걸 안 지우고
        // `trim().is_empty()`(White_Space)도 안 잡아, 예전엔 "보이지 않는 기록"이 저장·전송됐다.
        // 빈-메모로 취급(None)해야 한다. mutation: gate를 `trim().is_empty()`로 되돌리면 Some이 돼 깨진다.
        for s in [
            "\u{200B}\u{200B}",     // ZWSP만
            "\u{FEFF}",             // BOM
            "\u{200D}\u{2060}",     // ZWJ + WORD JOINER
            " \u{200B}\t\u{FEFF} ", // 공백 + 폭 0 혼합
            "\u{202E}\u{202C}",     // bidi override
        ] {
            assert!(
                Memo::sanitize(s).is_none(),
                "폭 0 문자뿐인 메모({s:?})를 빈 것으로 안 봤다 — 보이지 않는 기록이 남는다"
            );
        }
    }

    #[test]
    fn sanitize_preserves_zero_width_joiners_inside_visible_text() {
        // **저장 내용은 안 건드린다**는 불변식: 정상 이모지 ZWJ 시퀀스는 **보이는 이모지**가 있으니
        // 빈 게 아니고, 조이너(ZWJ)도 그대로 보존돼야 한다 — 폭 0 문자를 무조건 지우면 가족 이모지가
        // 세 개의 낱개 이모지로 깨진다. is_visually_empty는 판정에만 쓰고 content를 바꾸지 않으므로 안전.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"; // 👨‍👩‍👧
        let m = Memo::sanitize(family).expect("보이는 이모지가 있으니 빈 게 아니다");
        assert!(
            m.text().contains('\u{200D}'),
            "ZWJ가 저장에서 사라져 이모지가 깨졌다: {:?}",
            m.text()
        );
        assert_eq!(m.text(), family, "저장 내용이 원문과 달라졌다");
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

    #[test]
    fn redaction_happens_before_truncation_so_cap_is_the_real_final_ceiling() {
        // 10차: redaction은 절단보다 **먼저**여야 한다. `[REDACTED:…]` 치환이 길이를 **늘리면**,
        // 절단이 먼저일 때 redaction 후 최종 바이트가 MEMO_MAX_BYTES를 넘는다 — 상한이 상한이 아니다.
        //
        // **길이가 늘어나는** redaction을 써야 이 순서를 실제로 검증한다: 짧은 email(`a@b.co`, 6바이트)이
        // `[REDACTED:email]`(16바이트)로 커진다(≈2.4배). AWS 키처럼 줄어드는 secret으로는 순서가
        // 뒤집혀도 상한을 안 넘어 테스트가 공허해진다(9차의 함정을 여기서 피한다).
        let raw = "a@b.co ".repeat(20_000); // ≈140KB 입력, redaction 후 ≈340KB로 팽창
        let m = memo(&raw);

        // 최종 바이트가 진짜로 상한 이하다 — 이 게이트의 핵심 불변식.
        // (절단 먼저였다면: 140KB→64KiB로 자른 뒤 redact가 ≈155KB로 부풀어 이 단언이 깨진다.)
        assert!(
            m.text().len() <= MEMO_MAX_BYTES,
            "redaction 후 최종 바이트가 상한을 넘었다(절단이 redaction보다 먼저인 버그): {} > {}",
            m.text().len(),
            MEMO_MAX_BYTES
        );
        assert!(m.truncated(), "상한을 넘긴 입력인데 절단 표시가 없다");
        // redaction이 실제로 걸렸다(원본 email이 남아 있지 않다).
        assert!(
            !m.text().contains("a@b.co"),
            "최종 메모에 원본 email이 남아 있다"
        );
        assert!(
            m.text().contains("[REDACTED:email]"),
            "redaction이 안 걸렸다"
        );
        // UTF-8 경계 안전(절단이 문자 중간을 깨면 String이 성립하지 않는다 — 명시 확인).
        assert!(m.text().is_char_boundary(m.text().len()));
    }

    #[test]
    fn sanitize_bounds_redaction_input_so_regex_never_sees_unbounded() {
        // 11차: redaction이 맨 앞이면 regex가 원문 전체(무제한)를 본다 — ReDoS·메모리 압박 표면.
        // 1차 절단이 redact **입력**을 처리 상한으로 막는지, **시계 없이** probe로 결정적으로 본다.
        //
        // 성장하는 redaction(email)을 써서 공허 함정을 피한다(9차: AWS 키는 줄어들어 무의미했다).
        // 입력을 처리 상한(512KiB)보다 훨씬 크게(≈700KB) 잡아 1차 절단이 반드시 걸리게 한다.
        let raw = "a@b.co ".repeat(100_000); // ≈700KB > MEMO_REDACT_INPUT_MAX(512KiB)
        assert!(
            raw.len() > MEMO_REDACT_INPUT_MAX,
            "테스트 입력이 처리 상한을 안 넘어 공허하다"
        );

        test_redact_probe::reset();
        let _ = Memo::sanitize(&raw);

        let redact_input =
            test_redact_probe::last_input_len().expect("sanitize가 redact를 안 불렀다");
        assert!(
            redact_input <= MEMO_REDACT_INPUT_MAX,
            "redact가 무제한 입력을 봤다(1차 절단 제거 회귀): {redact_input} > {MEMO_REDACT_INPUT_MAX}"
        );
        // 실제로 잘렸음을 확인(입력보다 작아졌다) — 상한과 우연히 같아서 통과하는 게 아니다.
        assert!(
            redact_input < raw.len(),
            "1차 절단이 전혀 안 일어났다: {redact_input} == 원문 {}",
            raw.len()
        );
    }

    #[test]
    fn first_stage_cap_does_not_cut_normal_sized_memos() {
        // 1차 상한을 너무 빡세게 잡으면 redaction 전에 정상 메모를 잘라버린다 — 그러면 안 된다.
        // 사람이 남기는 정상 규모 메모(수 KB, 처리 상한에 한참 못 미침)는 1차에서 안 잘리고 그대로
        // redact를 통과해야 한다.
        let normal = "디스크가 이상하게 느립니다. ".repeat(500); // 수십 KB, MEMO_REDACT_INPUT_MAX 이하
        assert!(normal.len() < MEMO_REDACT_INPUT_MAX);

        test_redact_probe::reset();
        let m = Memo::sanitize(&normal).expect("정상 메모");

        // redact 입력이 원문 그대로다(1차 절단이 안 건드렸다 — secret이 없어 redact도 길이 불변).
        assert_eq!(
            test_redact_probe::last_input_len(),
            Some(normal.len()),
            "정상 메모가 1차 절단에서 손상됐다"
        );
        assert!(!m.truncated(), "정상 메모인데 절단됐다고 표시된다");
        assert_eq!(m.text(), normal, "정상 메모 내용이 바뀌었다");
    }

    #[test]
    fn processing_cap_truncation_is_not_reported_as_user_facing_truncated() {
        // **13차 교정 + gate 2 공허 방지**: `truncated`는 **저장 상한(64KiB)에서** 잘렸을 때만 true다.
        // 처리 상한(512KiB) 절단은 내부 비용 방어라 여기 안 든다 — 두 절단을 OR로 합치면 notice가
        // 512KiB에서 잘린 걸 "64KiB에서 잘렸다"고 **틀린 임계**로 말한다.
        //
        // 이걸 잡으려면 **처리 상한만 걸리고 저장 상한은 안 걸리는** 입력이 필요하다: 512KiB 이상이
        // redaction으로 64KiB 미만으로 **줄어드는** 병적 입력. 긴 conn_string(`scheme://u:p@host…`)은
        // 통째로 `[REDACTED:conn_string]`(22B)로 접혀 대폭 축소된다. (성장하는 email로는 이 케이스를
        // 못 만든다 — 그건 저장 상한이 이겨 공허해진다. 9차의 반대 함정.)
        let one = format!("x://u:p@{} ", "h".repeat(1000)); // ≈1010B, redact → 23B(라벨+공백)
        let raw = one.repeat(600); // ≈606KB > 처리 상한(512KiB)
        assert!(
            raw.len() > MEMO_REDACT_INPUT_MAX,
            "입력이 처리 상한을 안 넘어 공허"
        );

        let m = Memo::sanitize(&raw).expect("redacted conn_string 도배");

        // redaction이 대폭 줄여 최종은 저장 상한 **미만** — 즉 저장 상한 절단은 안 걸렸다.
        assert!(
            m.text().len() < MEMO_MAX_BYTES,
            "redaction이 저장 상한 밑으로 안 줄었다(테스트 전제 실패): {}",
            m.text().len()
        );
        assert!(
            m.text().contains("[REDACTED:conn_string]"),
            "conn_string이 redact되지 않았다(전제 실패)"
        );
        // **핵심 단언**: 처리 상한만 잘렸으므로 사용자 대면 truncated는 **false**여야 한다.
        // `truncated`를 `pre || post`로 되돌리면(=처리 상한을 사용자에게 노출) 이 단언이 깨진다.
        assert!(
            !m.truncated(),
            "처리 상한 절단을 사용자 대면 truncated로 노출했다(틀린 임계 회귀)"
        );
    }
}
