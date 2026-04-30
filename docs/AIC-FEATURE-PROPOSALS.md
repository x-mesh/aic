# aic Feature Proposals

> `aic-session`/`aicd` 구조 개선과 별개로, `aic` CLI 자체의 제품 가치를 키울 수 있는 기능 제안 모음.

## 배경

현재 `aic`의 중심 가치는 "직전 명령의 실패 record를 잡아 LLM 분석으로 연결한다"이다. 이 기반은 좋지만 사용자가 실제로 원하는 것은 단순 설명보다 다음에 가깝다.

- 왜 실패했는지 빠르게 안다.
- 현재 프로젝트 맥락에 맞는 답을 받는다.
- 안전한 해결책은 바로 실행하거나 적용한다.
- 같은 문제를 다시 만나면 더 싸고 빠르게 해결한다.
- 여러 세션과 과거 실패 중 원하는 record를 골라 다시 분석한다.

따라서 기능 확장은 `context`, `action`, `memory`, `safety` 네 축으로 잡는 것이 좋다.

## 우선순위 요약

| Priority | Feature | 핵심 가치 | 선행 조건 |
|---|---|---|---|
| P0 | deterministic analyzer | LLM 없이 빠른 진단, 비용 절감 | 현재 record 모델 |
| P0 | project context pack | 답변 품질 개선 | repo 감지 유틸 |
| P1 | `aic history` / record id | 직전 명령 한계 해소 | command store 정리 |
| P1 | `aic fix` | 제안에서 실행까지 연결 | risk guard |
| P1 | `aic capture-last` | metadata-only 약점 보완 | session roadmap Phase 2 |
| P2 | `aic learn` | 개인화된 재발 해결 | fingerprint/cache 확장 |
| P2 | `aic watch` | 실패 감지 후 비침습 hint | hook/session event 안정화 |
| P2 | command risk guard | 위험 명령 사전 경고 | hook mode |
| P3 | `aic ask --context` | 일반 질문에 repo 맥락 결합 | project context pack |
| P3 | solution feedback | 답변 품질 개선 루프 | cache/telemetry policy |

## P0: Deterministic Analyzer

### 문제

모든 에러를 LLM으로 보내면 느리고 비용이 든다. `command not found`, permission, port already in use, git non-fast-forward, Rust compiler code, npm script failure 같은 유형은 rule 기반으로도 좋은 1차 답을 줄 수 있다.

### 제안

LLM 호출 전에 deterministic analyzer를 실행한다.

대상 후보:

- Shell: `command not found`, exit 126/127, permission denied.
- Network/port: `EADDRINUSE`, connection refused, DNS failure.
- Git: non-fast-forward, merge conflict, detached HEAD, auth failure.
- Rust: `rustc` error code, missing feature, borrow checker 대표 패턴.
- Node/npm: missing script, dependency not found, peer dependency conflict.
- Docker: daemon not running, image pull auth, port conflict.
- Kubernetes: context missing, forbidden, resource not found.

동작 방식:

1. `CommandRecord`에서 command, exit code, output tail을 본다.
2. fingerprint를 만든다.
3. rule이 high confidence이면 즉시 결과를 출력한다.
4. confidence가 낮으면 deterministic hint를 LLM prompt에 context로 추가한다.

Acceptance Criteria:

- LLM 설정이 없어도 대표 에러는 설명과 해결 후보를 출력한다.
- rule 결과에는 confidence와 matched rule id가 포함된다.
- 사용자가 `AIC_NO_RULES=1` 또는 config로 비활성화할 수 있다.

## P0: Project Context Pack

### 문제

같은 에러라도 프로젝트 종류, package manager, workspace 구조, 최근 변경 파일에 따라 답이 달라진다. 현재 record만으로는 LLM이 일반론을 말할 가능성이 높다.

### 제안

분석 직전에 현재 디렉토리 기준의 작은 context pack을 생성한다.

포함 후보:

- VCS: repo root, current branch, dirty file summary, recent changed files.
- Language/runtime: Rust/Node/Python/Go 감지, lockfile/package manifest.
- Build tool: Cargo, npm/pnpm/yarn, Makefile, pytest, go test 등.
- Relevant config: `Cargo.toml`, `package.json`, `pyproject.toml` 등에서 핵심 필드만.
- Last command relation: command가 참조한 파일/패키지/test 이름.

제한:

- 파일 본문을 대량으로 보내지 않는다.
- 기본은 metadata 중심, 본문은 작은 config snippet만.
- secrets redaction을 반드시 통과한다.

Acceptance Criteria:

- `aic --dry-run`이 context pack의 token estimate를 보여준다.
- context pack은 deterministic하고 cache key에 반영된다.
- `AIC_CONTEXT=off|min|auto|full` 같은 제어가 가능하다.

## P1: `aic history` / Record ID

### 문제

현재 UX는 "직전 명령" 중심이다. 실제 사용자는 몇 분 전 실패, 다른 터미널 실패, hook mode metadata record를 다시 보고 싶어 한다.

### 제안

모든 command record에 stable id를 부여하고, 최근 record를 조회/선택할 수 있게 한다.

명령 후보:

```text
aic history --limit 20
aic history --failed
aic last
aic analyze --record <id>
```

표시 정보:

- record id.
- time ago.
- session id / label.
- cwd.
- command.
- exit code.
- capture mode/quality.
- output line count/truncation 여부.

Acceptance Criteria:

- PTY, hook, explicit capture record가 같은 목록에 표시된다.
- `aic analyze --record <id>`는 현재 session이 종료되어도 가능한 범위에서 동작한다.
- `--json` 출력이 있어 scripting에 쓸 수 있다.

## P1: `aic fix`

### 문제

분석 결과를 받은 뒤 사용자는 대부분 제안된 명령을 직접 복사해 실행하거나 파일을 고친다. 안전하게 자동화할 수 있는 경우에는 `aic`가 preview와 confirm을 제공하는 것이 더 효율적이다.

### 제안

분석 결과를 action 후보로 변환해 실행한다.

지원 범위 MVP:

- 명령 실행: `cargo fmt`, `cargo update -p`, `npm install`, `git config` 등.
- 파일 패치: 작은 config/test/code patch를 unified diff로 preview 후 적용.
- 재시도: 원래 command를 context pack 개선 후 다시 실행.

Safety 정책:

- destructive command는 기본 거부.
- 파일 변경은 diff preview 필수.
- git dirty 상태를 보여주고 confirm 받기.
- `--yes`는 safe action에만 허용.

명령 후보:

```text
aic fix
aic fix --record <id>
aic fix --dry-run
```

Acceptance Criteria:

- 실행 전 action plan을 보여준다.
- 적용 후 원래 command 또는 관련 test를 재실행할지 묻는다.
- 실패하면 rollback 가능 여부와 남은 변경을 명확히 표시한다.

## P1: `aic capture-last`

### 문제

hook mode의 metadata-only record는 command, cwd, exit code는 알지만 output이 없다. 출력 기반 분석이 필요한 에러에서는 답변 품질이 낮다.

### 제안

마지막 metadata-only command를 안전성 검사 후 explicit capture로 재실행한다.

동작:

1. 마지막 record를 찾는다.
2. command risk guard를 실행한다.
3. 안전하면 실제 재실행 command를 보여주고 confirm 받는다.
4. stdout/stderr tail을 cap 안에서 저장한다.
5. 새 `ExplicitCapture` record로 분석한다.

Acceptance Criteria:

- unsafe command는 기본 거부한다.
- 원래 exit code와 새 exit code를 모두 표시한다.
- binary/truncated output metadata가 정확히 채워진다.

## P2: `aic learn`

### 문제

반복되는 에러를 매번 LLM에 물을 필요가 없다. 사용자 환경에서 한 번 맞았던 해결책은 다음에 먼저 보여주는 편이 빠르다.

### 제안

성공한 해결책을 local recipe로 저장한다.

명령 후보:

```text
aic learn --worked
aic learn --note "이 프로젝트에서는 protobuf 재생성이 필요"
aic recipes list
```

저장 데이터:

- error fingerprint.
- command pattern.
- project signature.
- worked solution.
- timestamp and confidence.

Acceptance Criteria:

- 같은 fingerprint가 다시 나오면 LLM 호출 전 learned recipe를 보여준다.
- recipe는 local-only 기본값이다.
- 사용자가 recipe를 삭제/수정할 수 있다.

## P2: `aic watch`

### 문제

사용자는 실패 직후 `aic`를 직접 실행해야 한다. 자동 분석은 방해가 될 수 있지만, 비침습적인 hint는 유용하다.

### 제안

세션 또는 hook event를 watch해서 실패 명령이 생기면 짧은 hint만 표시한다.

동작:

- exit code non-zero 감지.
- deterministic analyzer로 즉시 분류 가능한 경우 한 줄 hint.
- LLM 호출은 자동 실행하지 않고 `aic` 실행을 안내.

Acceptance Criteria:

- prompt latency를 늘리지 않는다.
- TUI/interactive command에는 hint를 내지 않는다.
- 사용자가 config로 끌 수 있다.

## P2: Command Risk Guard

### 문제

`aic fix`, `capture-last`, hook mode가 커질수록 "명령을 실행하거나 재실행해도 되는가" 판단이 중요해진다.

### 제안

명령 risk classifier를 공통 모듈로 둔다.

Risk level:

- `Safe`: 읽기 전용 또는 formatting처럼 낮은 위험.
- `NeedsConfirm`: 파일 변경, dependency install, network write.
- `Dangerous`: destructive command, production/deploy, irreversible action.
- `Unknown`: shell parsing 실패 또는 복잡한 command.

사용처:

- `aic capture-last`.
- `aic fix`.
- hook mode 사전 경고.
- `aic run` 실행 전 optional warning.

Acceptance Criteria:

- shell quoting과 pipeline을 가능한 안전하게 파싱한다.
- denylist는 config로 확장 가능하다.
- dangerous command에는 `--yes`가 통하지 않는다.

## P3: `aic ask --context`

### 문제

사용자는 에러가 없어도 현재 프로젝트에 대해 질문하고 싶다. 일반 LLM CLI와 다른 점은 `aic`가 repo/session/runtime context를 이미 알고 있다는 점이다.

### 제안

직전 실패 없이도 project context pack을 붙여 질문한다.

예시:

```text
aic ask --context "이 테스트가 flaky할 수 있는 지점 찾아줘"
aic ask --context --files src/foo.rs tests/foo.rs "이 변경 영향 설명해줘"
```

Acceptance Criteria:

- context pack을 dry-run으로 확인할 수 있다.
- 명시 파일 지정 시 파일 크기 cap과 redaction을 적용한다.
- 에러 분석 prompt와 일반 질문 prompt를 분리한다.

## P3: Solution Feedback

### 문제

LLM 답변 품질을 개선하려면 최소한의 feedback loop가 필요하다.

### 제안

분석 후 짧은 피드백을 저장한다.

후보:

```text
aic feedback worked
aic feedback not-worked
aic feedback irrelevant
```

활용:

- cache ranking.
- learned recipe 후보.
- deterministic analyzer rule 개선.
- prompt template 개선.

Acceptance Criteria:

- 기본 저장은 local-only다.
- prompt/response 본문은 기존 privacy 정책을 따른다.
- feedback은 debug bundle에서 redacted summary로 볼 수 있다.

## 권장 구현 순서

1. Deterministic analyzer: 독립적이고 즉시 체감된다.
2. Project context pack: LLM 답변 품질을 전반적으로 올린다.
3. Record id와 `aic history`: 이후 기능들의 공통 기반이다.
4. Command risk guard: 실행/재실행 기능의 안전 기반이다.
5. `aic fix`: action loop를 닫는다.
6. `aic capture-last`: hook/hybrid mode의 약점을 보완한다.
7. `aic learn`: 반복 문제를 줄인다.
8. `aic watch`, `aic ask --context`, feedback은 기반 기능이 안정된 뒤 확장한다.

## `aic-session` Roadmap과의 관계

- `aic history`, `capture-last`, `watch`는 세션/record store 안정화와 강하게 연결된다.
- `deterministic analyzer`, `project context pack`, `aic fix`는 현재 구조에서도 시작할 수 있다.
- `aicd` 중심 구조로 전환되면 record id, history, watch의 구현이 단순해진다.
- `command risk guard`는 `capture-last`와 `aic fix`의 공통 prerequisite로 먼저 만들수록 좋다.

## 열린 질문

- deterministic analyzer의 결과가 high confidence이면 LLM 호출을 자동 생략할 것인가, 아니면 항상 "더 분석하기" 옵션을 둘 것인가?
- project context pack이 파일 본문을 포함하는 기준은 무엇인가?
- `aic fix`의 파일 패치 적용은 자체 구현할 것인가, git apply를 사용할 것인가?
- learned recipe는 project-local로 저장할 것인가, user-global로 저장할 것인가?
- risk guard의 default denylist를 얼마나 보수적으로 잡을 것인가?

