# PRD: Hook Capture Mode

> PTY wrapper 없이 shell hook 중심으로 command metadata를 수집하고, 필요할 때만 opt-in output capture를 수행하는 가벼운 캡처 모드.

## 1. 배경

현재 `aic-session`은 PTY wrapper로 셸을 감싸고 출력 스트림을 직접 중계한다. 이 방식은 출력 캡처 정확도와 TUI 호환성이 좋지만, 터미널마다 foreground wrapper가 필요하고 세션 lifecycle 관리 비용이 크다.

Hook Capture Mode는 셸의 native hook을 사용한다. zsh의 `preexec`/`precmd`, bash의 `DEBUG trap`/`PROMPT_COMMAND`를 통해 command start/end, exit code, cwd, duration 같은 metadata를 `aicd`에 보낸다. 기본 모드에서는 전체 stdout/stderr를 가로채지 않는다.

이 모드는 “정확한 terminal replay”가 아니라 “낮은 오버헤드의 command activity tracking”을 목표로 한다. 에러 분석에 충분한 출력이 없을 때는 사용자가 명시적으로 capture 재실행을 선택할 수 있어야 한다.

## 2. 목표

### 2.1 Product Goals

- 사용자가 터미널마다 `aic-session` foreground wrapper를 실행하지 않아도 된다.
- command, cwd, exit code, duration, shell, timestamp는 안정적으로 기록한다.
- 실패한 명령에 대해 가능한 경우 즉시 분석하고, 출력이 부족하면 capture 재실행을 제안한다.
- `aicd` 단일 데몬 UX와 잘 결합되는 low-overhead mode를 제공한다.
- 정확도가 필요한 사용자는 언제든 PTY mode로 전환할 수 있다.

### 2.2 Engineering Goals

- shell hook은 command execution을 막지 않는 best-effort event sender여야 한다.
- hook 실패가 사용자의 셸 명령 실행 결과에 영향을 주지 않아야 한다.
- stdout/stderr 전역 redirect는 기본적으로 사용하지 않는다.
- 캡처 정확도 등급을 명시적으로 모델링한다.
- zsh/bash를 MVP 지원 범위로 제한한다.

## 3. 비목표

- Hook mode에서 모든 stdout/stderr를 정확히 캡처하지 않는다.
- TUI, interactive, binary output을 hook mode에서 완전 지원하지 않는다.
- MVP에서 fish, nushell, powershell은 지원하지 않는다.
- 사용자 승인 없이 실패 명령을 자동 재실행하지 않는다.
- destructive command를 자동 capture 재실행하지 않는다.

## 4. 핵심 개념

### 4.1 Capture Modes

```toml
[session]
capture_mode = "pty"      # 기본값: 정확한 PTY 캡처
# capture_mode = "hook"   # metadata 중심 경량 모드
# capture_mode = "hybrid" # hook 우선, 필요 시 capture 재실행
```

`pty`:

- 기존 PTY wrapper 기반 정확한 캡처.
- 출력 기반 에러 분석의 기본 모드.

`hook`:

- shell hook 기반 metadata-only 기본 수집.
- 출력 캡처는 opt-in command wrapper에서만 수행.

`hybrid`:

- 평소에는 hook으로 metadata를 수집한다.
- 실패 명령 분석 시 출력이 부족하면 `aic capture-last` 또는 `aic run -- <cmd>` 흐름을 제안한다.

### 4.2 Capture Quality

모든 `CommandRecord`는 캡처 품질을 가져야 한다.

```text
FullOutput       PTY 또는 explicit capture로 stdout/stderr tail이 있음
MetadataOnly     command/cwd/exit/duration만 있음
RedactedOutput   출력이 있었지만 policy에 따라 일부 제거됨
BinaryOmitted    binary/non-UTF8 출력이 감지되어 본문 생략됨
TruncatedOutput  line/byte cap으로 일부만 저장됨
Unknown          legacy record 또는 품질 판단 불가
```

분석 UI는 `MetadataOnly`일 때 결과 신뢰도가 낮다는 것을 보여주고, 정확한 분석을 위해 capture flow를 제안해야 한다.

## 5. 사용자 흐름

### 5.1 Hook Mode 설정

1. 사용자가 `aic config set session.capture_mode hook` 또는 wizard에서 Hook mode를 선택한다.
2. `aic init zsh|bash`가 hook 파일을 설치한다.
3. 새 셸부터 hook이 command start/end event를 `aicd`에 보낸다.
4. `aic doctor`가 hook active 여부와 hook version을 검증한다.

### 5.2 실패 명령 분석

1. 사용자가 일반 셸에서 명령을 실행한다.
2. hook이 `CommandStarted`와 `CommandFinished` event를 `aicd`에 보낸다.
3. 명령이 실패한다.
4. 사용자가 `aic`를 실행한다.
5. `aic`는 metadata-only record를 확인한다.
6. builtin deterministic analyzer로 해결 가능하면 바로 답한다.
7. 출력이 필요하면 `aic`는 capture 재실행을 제안한다.

### 5.3 Capture 재실행

1. 사용자가 `aic capture-last` 또는 prompt confirm을 승인한다.
2. `aic`는 마지막 명령을 안전성 검사한다.
3. 안전하지 않은 명령은 재실행을 거부하거나 강한 confirm을 요구한다.
4. 안전한 명령은 wrapper로 재실행하고 stdout/stderr tail을 cap 안에서 수집한다.
5. 새 `FullOutput` record로 분석을 수행한다.

### 5.4 Explicit Capture

```text
aic run -- cargo build
```

`aic run -- <cmd>`는 hook mode에서도 정확한 output capture를 제공한다. 사용자가 처음부터 분석 가능한 record를 만들고 싶을 때 사용한다.

## 6. 요구사항

### R1. Shell Hook Event Collection

- zsh `preexec`에서 command start event를 전송해야 한다.
- zsh `precmd`에서 command finish event를 전송해야 한다.
- bash는 `DEBUG trap`과 `PROMPT_COMMAND`를 사용해 유사 event를 전송해야 한다.
- event 전송 실패는 사용자 command exit code를 바꾸면 안 된다.

Acceptance Criteria:

- zsh에서 `false` 실행 후 `aic`가 command와 exit code 1을 볼 수 있다.
- bash에서 `cd /tmp && false` 실행 후 cwd가 `/tmp`로 기록된다.
- `aicd`가 꺼져 있어도 사용자의 명령 실행은 지연되거나 실패하지 않는다.

### R2. Event Schema

Hook은 다음 event를 보낸다.

```text
CommandStarted {
  session_id,
  command_id,
  command,
  cwd,
  shell,
  pid,
  started_at
}

CommandFinished {
  session_id,
  command_id,
  exit_code,
  finished_at,
  duration_ms
}
```

Acceptance Criteria:

- start/finish event는 `command_id`로 매칭된다.
- finish event만 도착해도 partial record로 저장된다.
- start event만 도착하고 timeout되면 `Abandoned` 상태로 정리된다.

### R3. Nonblocking Transport

- hook event sender는 shell prompt latency를 최소화해야 한다.
- MVP transport는 UDS datagram 또는 short-lived UDS stream 중 하나를 선택한다.
- `aicd` 연결 실패 시 event를 조용히 버리거나 bounded spool에 저장해야 한다.
- hook에서 긴 timeout을 사용하면 안 된다.

Acceptance Criteria:

- `aicd` down 상태에서 command prompt overhead p95가 10ms 이하이다.
- event queue/spool이 가득 차도 command 실행은 계속된다.
- hook sender 실패 메시지가 기본적으로 terminal에 출력되지 않는다.

### R4. Metadata-Only Record

- hook mode의 기본 `CommandRecord`는 output이 없을 수 있다.
- record는 `capture_quality = MetadataOnly`를 명시해야 한다.
- analysis prompt는 output 없음 상태를 LLM에 명시해야 한다.

Acceptance Criteria:

- `aic` 출력에 “metadata-only” 상태가 표시된다.
- output-dependent 분석이 필요한 경우 capture 재실행을 제안한다.
- deterministic analyzer는 output 없이도 가능한 케이스를 처리한다.

### R5. Explicit Output Capture

- `aic run -- <cmd>`는 stdout/stderr tail을 수집해야 한다.
- `aic capture-last`는 마지막 명령을 재실행하기 전 안전성 검사를 해야 한다.
- capture wrapper는 원래 exit code를 보존해야 한다.
- stdout/stderr는 line cap과 byte cap을 적용해야 한다.

Acceptance Criteria:

- `aic run -- cargo build` 실패 후 `aic`가 `FullOutput` record로 분석한다.
- pipeline command의 exit code 보존 정책이 shell별로 테스트된다.
- capture output은 최대 byte cap을 넘지 않는다.

### R6. Interactive/TUI Detection

- hook mode는 interactive/TUI command를 metadata-only로 기록해야 한다.
- `vim`, `nvim`, `less`, `more`, `top`, `htop`, `ssh`, `fzf`, `man`, `watch` 등은 기본 denylist에 포함한다.
- 사용자는 denylist를 config로 확장할 수 있어야 한다.

Acceptance Criteria:

- `vim file` 실행 후 output capture를 시도하지 않는다.
- TUI command는 `capture_quality = MetadataOnly`로 저장된다.
- `aic`는 TUI command에 대해 재실행 capture를 기본 제안하지 않는다.

### R7. Binary and Large Output Safety

- output capture는 UTF-8 검증을 수행해야 한다.
- binary output은 본문을 저장하지 않고 hash/size만 저장해야 한다.
- large output은 tail 중심으로 저장해야 한다.

Acceptance Criteria:

- non-UTF8 output은 `BinaryOmitted`로 저장된다.
- 10MB output command는 cap 이하의 tail만 저장한다.
- output truncation 여부가 analysis prompt와 UI에 표시된다.

### R8. Hook Installation and Versioning

- hook 파일은 version marker를 가져야 한다.
- `aic init`은 hook을 멱등 설치해야 한다.
- `aic doctor`는 hook version mismatch를 감지해야 한다.
- `aic hook update` 또는 `aic init --upgrade`가 hook을 갱신해야 한다.

Acceptance Criteria:

- 오래된 hook 파일이면 `doctor`가 upgrade hint를 보여준다.
- 두 번 init해도 rc 파일에 중복 source가 생기지 않는다.
- hook 제거 명령이 marker block만 제거한다.

### R9. Privacy and Redaction

- hook event command text에는 secret redaction을 적용해야 한다.
- cwd path에서 username redaction 옵션을 제공해야 한다.
- output capture는 LLM 전송 전 기존 redaction pipeline을 통과해야 한다.

Acceptance Criteria:

- `curl -H 'Authorization: Bearer ...'` 형태 command는 redacted command로 저장된다.
- `AIC_PRIVACY=strict`에서 cwd username이 마스킹된다.
- redaction off는 audit event를 남긴다.

### R10. Mode Switching

- 사용자는 config로 mode를 변경할 수 있어야 한다.
- 현재 mode는 `aic status`와 `aic doctor`에 표시되어야 한다.
- mode 변경 후 필요한 action, 예를 들어 새 셸 열기나 hook update를 안내해야 한다.

Acceptance Criteria:

- `aic config get session.capture_mode`가 현재 mode를 출력한다.
- `capture_mode = hook`인데 hook이 설치되지 않았으면 `doctor`가 WARN을 낸다.
- `capture_mode = pty`에서는 hook absence가 FAIL이 아니다.

## 7. 데이터 모델 변경

### 7.1 CommandRecord 확장

```rust
pub struct CommandRecord {
    pub command: Option<String>,
    pub exit_code: i32,
    pub output_lines: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub cwd: Option<PathBuf>,
    pub duration_ms: Option<u64>,
    pub capture_mode: CaptureMode,
    pub capture_quality: CaptureQuality,
    pub output_metadata: Option<OutputMetadata>,
}
```

### 7.2 CaptureMode

```rust
pub enum CaptureMode {
    Pty,
    Hook,
    ExplicitCapture,
}
```

### 7.3 CaptureQuality

```rust
pub enum CaptureQuality {
    FullOutput,
    MetadataOnly,
    RedactedOutput,
    BinaryOmitted,
    TruncatedOutput,
    Unknown,
}
```

### 7.4 OutputMetadata

```rust
pub struct OutputMetadata {
    pub original_bytes: Option<u64>,
    pub stored_bytes: u64,
    pub stored_lines: usize,
    pub truncated: bool,
    pub binary: bool,
    pub sha256: Option<String>,
}
```

## 8. CLI 변경안

```text
aic config set session.capture_mode hook
  Hook mode 활성화.

aic hook status
  현재 shell hook 설치 및 버전 상태 확인.

aic hook update
  hook 파일 재생성 및 rc marker 갱신.

aic run -- <cmd>
  명령을 explicit capture wrapper로 실행.

aic capture-last
  마지막 metadata-only 명령을 안전성 검사 후 재실행 capture.

aic doctor --fix
  capture_mode에 맞는 hook 설치/업데이트 수행.
```

## 9. UX 원칙

- Hook mode는 “정확한 output capture mode”로 홍보하지 않는다.
- 출력이 없을 때는 분석 신뢰도를 낮춰 표시한다.
- 재실행은 항상 사용자 통제 아래 둔다.
- destructive command는 재실행을 기본 거부한다.
- TUI/interactive command는 metadata-only로 남기는 것이 정상 동작이다.

예시 메시지:

```text
이 기록은 Hook mode에서 수집되어 출력이 없습니다.
정확한 분석을 위해 마지막 명령을 capture mode로 다시 실행할 수 있습니다.

  aic capture-last
```

## 10. MVP 범위

### Phase 1: Metadata Hook

- zsh hook event sender
- bash hook event sender
- `aicd` event receiver
- `CommandRecord` capture metadata 확장
- `doctor` hook status 추가

### Phase 2: Explicit Capture

- `aic run -- <cmd>`
- output cap/truncation/binary detection
- exit code preservation
- analysis prompt에 capture quality 반영

### Phase 3: Capture Last

- last command reconstruction
- destructive command detection
- confirm UX
- `capture-last` result를 새 record로 저장

### Phase 4: Hybrid Mode

- `capture_mode = hybrid`
- metadata-only 실패 시 capture suggestion 자동 노출
- `status`/`top`에 capture quality 통계 추가

## 11. 테스트 계획

### Unit Tests

- hook event schema serialization roundtrip
- capture quality state mapping
- destructive command detection
- binary output detection
- output truncation policy
- redaction on command text

### Integration Tests

- zsh false command metadata capture
- bash false command metadata capture
- `aicd` down 상태에서 hook no-op
- `aic run --` exit code preservation
- large output truncation
- TUI denylist metadata-only behavior

### Manual Tests

- zsh interactive session
- bash interactive session
- terminal close
- `kill -9 aicd`
- `kill -9 hook event receiver`
- `cargo build` failure
- `git status` success
- `vim`, `less`, `ssh`, `fzf`

## 12. 성공 지표

- Hook mode에서 prompt latency p95 < 10ms.
- Hook mode에서 command/exit code capture success > 99%.
- `aicd` down 상태에서 shell command failure rate = 0.
- Metadata-only record에서 capture 재실행 전환 completion rate 측정 가능.
- Hook version mismatch 이슈가 `doctor`에서 진단 가능.

## 13. 리스크

- bash hook 구현은 zsh보다 edge case가 많다.
- 사용자가 output capture를 기대하면 hook mode 결과가 실망스러울 수 있다.
- command string 재실행은 side effect 위험이 있다.
- pipeline/alias/function command 재구성이 shell별로 다르다.
- hook event sender가 prompt latency를 늘릴 수 있다.

완화책:

- 기본 mode는 `pty`로 유지한다.
- hook mode UI에 capture quality를 항상 표시한다.
- `capture-last`는 destructive/interactive command를 기본 차단한다.
- explicit capture인 `aic run -- <cmd>`를 권장한다.
- hook sender는 timeout 없이 best-effort로 설계한다.

## 14. Open Questions

- `hook`과 `hybrid` 중 어느 것을 사용자에게 먼저 노출할지 결정이 필요하다.
- bash support를 MVP에 포함할지, zsh-first로 갈지 결정이 필요하다.
- bounded spool을 둘지, daemon down이면 event drop으로 단순화할지 결정이 필요하다.
- `capture-last`가 alias/function을 어떻게 재실행할지 정책이 필요하다.
- command redaction을 hook shell script에서 할지 daemon 수신 후 할지 결정이 필요하다.

## 15. Decision

Hook Capture Mode는 기본 캡처 모델의 대체재가 아니라 lightweight option이다. 정확한 output 기반 분석은 PTY mode 또는 explicit capture에서 제공하고, hook mode는 낮은 lifecycle 부담과 빠른 command metadata capture를 제공한다.

제품 기본값은 `pty`로 유지하되, 단일 `aicd` 도입 이후 `hybrid`를 실험 옵션으로 제공하는 방향이 가장 안전하다.
