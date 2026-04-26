# Capture Mode Tradeoffs

> `aicd supervisor`, `hook capture mode`, `hybrid mode`를 별도로 논의하기 위한 장단점 비교 문서.

## 1. 비교 대상

### A. Supervisor PTY Mode

사용자당 하나의 `aicd`가 세션 registry와 PTY child lifecycle을 관리하고, 터미널별 `aic-session`은 얇은 attach relay로 동작한다.

관련 문서:

- [PRD-AICD-SUPERVISOR.md](./PRD-AICD-SUPERVISOR.md)

### B. Hook Capture Mode

PTY wrapper 없이 shell native hook이 command start/end metadata를 `aicd`에 보낸다. 출력 캡처는 기본적으로 하지 않고, 필요 시 explicit capture를 사용한다.

관련 문서:

- [PRD-HOOK-CAPTURE-MODE.md](./PRD-HOOK-CAPTURE-MODE.md)

### C. Hybrid Mode

평소에는 hook으로 metadata를 수집하고, 실패 분석에 출력이 필요하면 `aic run -- <cmd>` 또는 `aic capture-last`로 opt-in capture를 수행한다.

## 2. 요약

| 기준 | Supervisor PTY | Hook Capture | Hybrid |
|---|---|---|---|
| 출력 캡처 정확도 | 높음 | 낮음 | 중간 |
| 터미널 lifecycle 부담 | 중간 | 낮음 | 낮음 |
| TUI 호환성 | 높음 | metadata-only | metadata-only 또는 PTY fallback |
| 구현 난도 | 높음 | 중간 | 높음 |
| 사용자 기대 일치 | 높음 | 주의 필요 | 중간 |
| crash cleanup | 중앙화 가능 | 단순 | 중앙화 가능 |
| prompt latency | attach relay 비용 | 매우 낮아야 함 | 낮음 |
| 분석 품질 | 높음 | 출력 없으면 낮음 | 상황별 |
| shell별 차이 | 낮음 | 높음 | 높음 |
| 기본 모드 적합성 | 높음 | 낮음 | 중간 |

## 3. Supervisor PTY Mode

### 장점

- stdout/stderr tail을 가장 정확하게 캡처할 수 있다.
- 현재 구현의 PTY/output/boundary/ring buffer 로직을 많이 유지할 수 있다.
- TUI와 alternate screen 처리를 현재 모델과 비슷하게 유지할 수 있다.
- 사용자가 `aic`를 실행했을 때 “직전 실패 출력 기반 분석”이라는 기대와 잘 맞는다.
- command output이 있으므로 LLM 분석 품질이 안정적이다.
- `aicd`가 cleanup을 중앙화하면 stale session 문제를 크게 줄일 수 있다.

### 단점

- 터미널별 foreground attach process는 여전히 필요하다.
- PTY ownership을 `aicd`로 옮기는 과정이 복잡하다.
- `aicd` 장애가 active sessions에 더 큰 영향을 줄 수 있다.
- raw mode 복원과 attach crash recovery를 신중하게 설계해야 한다.
- 구현량이 크고 regression 위험이 있다.

### 적합한 경우

- 정확한 output 기반 에러 분석이 제품의 기본 가치일 때.
- TUI/interactive compatibility를 유지해야 할 때.
- 사용자가 “그냥 실패 후 `aic`”를 기대할 때.

### 부적합한 경우

- foreground wrapper 자체를 없애는 것이 최우선 목표일 때.
- shell hook 기반 가벼운 telemetry만 필요할 때.
- 초기 구현 비용을 최소화해야 할 때.

## 4. Hook Capture Mode

### 장점

- 터미널별 `aic-session` foreground wrapper가 필요 없다.
- 사용자는 일반 셸을 그대로 쓰고 hook만 설치하면 된다.
- `aicd`는 command metadata event만 받으면 되므로 lifecycle이 단순하다.
- terminal raw mode 복원 문제가 거의 사라진다.
- prompt startup과 terminal attach UX가 가벼워진다.
- daemon이 죽어도 hook event만 유실되고 command 실행은 계속될 수 있다.

### 단점

- 기본적으로 stdout/stderr를 정확하게 캡처하지 못한다.
- output 없는 LLM 분석은 품질이 떨어질 수 있다.
- bash/zsh/fish 등 shell별 hook 차이가 크다.
- alias/function/pipeline/subshell 재구성이 어렵다.
- TUI/interactive command는 metadata-only로 남겨야 한다.
- 사용자가 “왜 출력 분석이 안 되지?”라고 느낄 수 있다.
- `capture-last` 재실행은 side effect 위험이 있다.

### 적합한 경우

- 낮은 오버헤드와 쉬운 lifecycle이 가장 중요할 때.
- command history, exit code, cwd 기반의 lightweight assistant가 필요할 때.
- 출력이 없어도 deterministic hint 또는 재실행 capture flow로 충분한 workflow일 때.

### 부적합한 경우

- 직전 실패 출력 기반 분석을 기본값으로 보장해야 할 때.
- command 재실행 side effect를 피해야 할 때.
- shell별 편차를 감당하기 어려울 때.

## 5. Hybrid Mode

### 장점

- 평소에는 hook mode의 낮은 lifecycle 부담을 얻는다.
- 실패 분석에 출력이 필요할 때만 explicit capture를 사용한다.
- 사용자가 output capture 비용과 side effect를 직접 승인한다.
- 단일 `aicd` UX와 잘 맞는다.
- 향후 PTY mode와 hook mode 사이의 migration path가 된다.

### 단점

- 제품 설명이 복잡해진다.
- capture quality를 UI/Prompt/Cache key에 모두 반영해야 한다.
- `capture-last` 재실행 정책이 어렵다.
- hook과 capture wrapper를 모두 구현해야 해서 전체 구현량이 크다.
- 분석 결과가 record quality에 따라 달라져 테스트 matrix가 커진다.

### 적합한 경우

- hook mode를 옵션으로 제공하되 분석 품질 저하를 보완하고 싶을 때.
- 낮은 overhead와 정확한 output capture를 상황별로 모두 제공하고 싶을 때.
- 사용자에게 mode 선택권을 주고 싶을 때.

### 부적합한 경우

- MVP를 최대한 단순하게 유지해야 할 때.
- mode별 UX 차이를 설명할 여유가 없을 때.
- command 재실행을 제품 흐름에 넣고 싶지 않을 때.

## 6. 핵심 쟁점

### 6.1 Output Capture

Supervisor PTY는 output capture가 기본 강점이다. Hook mode는 이 부분이 약점이다. Hook mode를 옵션으로 제공하려면 `capture_quality`를 데이터 모델에 넣고, output 없는 분석을 명확히 표시해야 한다.

결정 기준:

- 제품의 기본 promise가 “직전 실패 출력 분석”이면 PTY가 기본이어야 한다.
- 제품의 기본 promise가 “명령 실패를 기억하고 도와주는 lightweight assistant”이면 hook도 가능하다.

### 6.2 Terminal Lifecycle

Supervisor PTY는 attach process가 필요하다. Hook mode는 foreground wrapper를 없앨 수 있다.

결정 기준:

- `aic-session` 실행 부담 제거가 최우선이면 hook이 강하다.
- 출력 캡처와 TUI 안정성이 최우선이면 PTY가 강하다.

### 6.3 Failure Recovery

Supervisor PTY는 `aicd`가 중앙 cleanup을 맡아야 한다. Hook mode는 daemon down 시 event를 버리면 된다.

결정 기준:

- “데몬이 죽어도 셸은 절대 영향받지 않아야 한다”면 hook이 단순하다.
- “데몬이 세션 상태를 정확히 알고 정리해야 한다”면 supervisor가 필요하다.

### 6.4 Security and Privacy

Supervisor PTY는 많은 output을 볼 수 있으므로 redaction과 storage policy가 중요하다. Hook mode는 기본적으로 command text/cwd만 보지만, command 자체에 secret이 들어갈 수 있다.

결정 기준:

- strict privacy mode에서는 hook metadata-only가 매력적이다.
- output 분석이 필요하면 redaction pipeline이 반드시 선행되어야 한다.

## 7. 의사결정 Matrix

| 질문 | PTY 쪽 신호 | Hook 쪽 신호 |
|---|---|---|
| 직전 실패 출력 분석이 핵심인가? | 예 | 아니오 |
| foreground wrapper를 없애야 하는가? | 아니오 | 예 |
| TUI 호환성이 중요한가? | 예 | metadata-only 허용 |
| command 재실행이 위험한 도메인인가? | 예 | 아니오 |
| shell별 hook 유지보수가 부담인가? | 예 | 아니오 |
| 낮은 prompt latency가 최우선인가? | 아니오 | 예 |
| 정확한 status/top/session lifecycle이 필요한가? | 예 | 부분 |

## 8. 권장 제품 전략

### 기본값

`capture_mode = "pty"`를 기본값으로 유지한다.

이유:

- 현재 제품의 핵심 가치는 output 기반 error analysis다.
- 사용자는 실패 직후 `aic`를 실행하면 실제 출력 기반 답을 기대한다.
- Hook-only는 이 기대를 자주 깨뜨릴 수 있다.

### 옵션

`capture_mode = "hook"`은 lightweight/privacy/low-overhead 옵션으로 제공한다.

제공 조건:

- UI에 metadata-only 제한을 명확히 표시한다.
- `aic doctor`가 hook 설치와 mode mismatch를 진단한다.
- `aic run --` 또는 `capture-last`를 함께 제공한다.

### 실험값

`capture_mode = "hybrid"`를 실험 옵션으로 제공한다.

이유:

- Hook mode의 lifecycle 장점을 가져오면서 output 부족 문제를 capture flow로 보완할 수 있다.
- 다만 UX와 구현이 복잡하므로 기본값으로 두기 전 실제 사용 데이터를 봐야 한다.

## 9. 단계별 검증 계획

1. `aicd supervisor` PRD를 기준으로 daemon-first status/doctor를 구현한다.
2. `hook` mode는 metadata-only MVP로 별도 feature flag 뒤에 둔다.
3. `capture_quality`를 먼저 데이터 모델에 넣어 UI와 cache key가 품질 차이를 알게 한다.
4. `aic run -- <cmd>`를 구현해 explicit capture의 안전한 경로를 만든다.
5. `capture-last`는 destructive detection과 confirm UX가 안정된 뒤 추가한다.
6. 실제 사용에서 metadata-only 분석의 만족도를 본 뒤 hybrid 기본 노출 여부를 결정한다.

## 10. Open Questions

- Hook mode를 `aic config` wizard에 바로 노출할지, hidden/experimental로 둘지.
- `hybrid`를 별도 mode로 둘지, hook mode의 기본 behavior로 둘지.
- `capture-last`가 side effect 있는 명령을 어떻게 판별할지.
- output 없는 LLM prompt를 허용할지, deterministic/builtin hint만 제공할지.
- shell support를 zsh-first로 할지 zsh/bash 동시 MVP로 할지.

## 11. Decision Draft

초기 decision은 다음과 같이 둔다.

- 기본 모드: `pty`
- 옵션 모드: `hook`
- 실험 모드: `hybrid`
- 필수 데이터 모델: `capture_mode`, `capture_quality`, `output_metadata`
- 필수 보완 기능: `aic hook status`, `aic run -- <cmd>`, `aic doctor` mode 진단

이렇게 하면 PTY의 정확도를 기본값으로 유지하면서, 사용자가 원한 “세션별 wrapper 부담 없는 방식”을 명시적 옵션으로 실험할 수 있다.
