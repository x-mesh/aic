# aic-session Improvement Roadmap

> 현재 `aic-session` 개선 후보를 Phase 1로 두고, 이어서 진행할 만한 Phase 2/3 기능과 구조 변경을 정리한다.

## 배경

현재 구조의 큰 방향은 맞다. `aic-session`은 터미널별 data plane으로 PTY relay와 output capture를 맡고, `aicd`는 사용자별 control plane으로 registry, lifecycle, hook event sink를 맡는다. 이 분리는 유지할 가치가 있다.

다만 구현상 `aic-server/src/main.rs`가 `aic-session`의 대부분의 런타임 책임을 직접 조율한다. CLI parsing, session id 생성, PID lock, PTY spawn, hook setup, UDS server, heartbeat, stdin/stdout relay, resize, shutdown cleanup이 한 파일의 `main()`에 모여 있어 다음 기능을 얹을수록 변경 위험이 커진다.

이 문서는 "지금 구조를 갈아엎기"보다, 먼저 안정화한 뒤 사용자 가치가 높은 기능을 붙이고, 마지막에 `aicd` 중심 구조로 옮기는 순서를 제안한다.

## Phase 1: aic-session 안정화와 구조 정리

목표: 현재 동작을 유지하면서 세션 런타임의 변경 가능성과 신뢰도를 높인다.

### 1. `aic-session` runtime 분리

현재 상태:

- `aic-server/src/main.rs`가 세션 lifecycle 전체를 직접 조립한다.
- blocking relay task, async UDS task, heartbeat task, signal task가 한 흐름에 섞여 있다.

제안:

- `aic-server/src/session_daemon.rs` 또는 `aic-server/src/session_runtime.rs` 추가.
- `SessionRuntime`이 다음을 소유하게 한다.
  - `SessionPaths`: `session_id`, socket path, PID lock path.
  - `SessionState`: ring buffer, shell name, PTY handle.
  - `SessionTasks`: UDS, stdin relay, output relay, heartbeat, SIGWINCH, wait task.
  - `shutdown(trigger)` cleanup 순서.
- `main.rs`는 CLI parsing, telemetry init, runtime start만 담당한다.

Acceptance Criteria:

- `aic-session --help`, `--print-session-id`는 TTY/raw mode를 건드리지 않는다.
- 세션 시작과 종료 경로가 unit/integration test에서 독립적으로 검증된다.
- 기존 `cargo test`와 multi-session integration test가 통과한다.

### 2. `--no-hook` 실제 동작 구현

현재 상태:

- `aic-session --no-hook` 옵션은 surface에 있지만 현재 no-op이다.
- `PtyManager::spawn_shell()`은 항상 `~/.aic/hooks.zsh`, `~/.aic/hooks.bash`를 갱신한다.

제안:

- `PtyManager::spawn_shell(rows, cols, session_id, HookPolicy)` 형태로 hook 정책을 명시한다.
- `HookPolicy::AutoInstall`, `HookPolicy::FallbackOnly`, `HookPolicy::Disabled` 정도로 분리한다.
- `--no-hook`은 사용자 홈의 hook 파일 갱신과 fallback source 주입을 모두 끈다.

Acceptance Criteria:

- `aic-session --no-hook` 실행 시 `~/.aic/hooks.*`가 생성/갱신되지 않는다.
- hook이 없어도 timing heuristic 또는 graceful no-capture fallback으로 세션이 뜬다.
- `doctor`는 `--no-hook` 세션을 hook 설치 실패로 오인하지 않는다.

### 3. cwd 추적 정확도 개선

현재 상태:

- heartbeat는 부모 `aic-session` 프로세스의 `std::env::current_dir()`를 보낸다.
- 사용자가 child shell 안에서 `cd`하면 registry의 cwd가 실제 셸 cwd와 어긋날 수 있다.
- hook event는 cwd를 보낼 수 있으나 PTY session heartbeat와 별도 흐름이다.

제안:

- hook/OSC event에서 얻은 cwd를 `SessionInfo.cwd`의 우선 소스로 삼는다.
- heartbeat의 cwd는 "프로세스 cwd"가 아니라 "last known shell cwd"로 명명하거나, 알 수 없으면 갱신하지 않는다.
- status/sessions 출력에서 cwd freshness를 표시할 수 있게 `last_seen_at`과 `last_command_at` 의미를 명확히 한다.

Acceptance Criteria:

- `cd /tmp && false` 후 `aic sessions` 또는 `aic status`가 `/tmp`를 보여준다.
- hook 없는 PTY session은 부정확한 cwd를 새 값처럼 덮어쓰지 않는다.

### 4. session routing 완성

현재 상태:

- `aicd`의 `GetLastCommand`는 아직 세션 ID 라우팅이 필요하다는 에러를 반환한다.
- client에는 `GetLastCommandForSession` 경로가 있으나 기본 UX와 완전히 결합되어 있지는 않다.

제안:

- client의 default flow에서 다음 순서로 record를 찾는다.
  1. explicit `--session <id>`.
  2. `AIC_SESSION_ID`.
  3. 해당 session socket의 PTY record.
  4. 실패 시 `aicd.GetLastCommandForSession(id)` hook record.
  5. 그래도 실패하면 history fallback.
- `aicd`에는 `GetLastCommandForSession`만 남기고, session-id 없는 `GetLastCommand`는 명시적으로 unsupported로 유지하거나 `current session` 정책이 생긴 뒤 활성화한다.

Acceptance Criteria:

- hook mode만 켜진 shell에서 `false` 후 `aic`가 metadata-only record를 찾아낸다.
- PTY mode에서는 기존 full output record가 우선된다.
- 라우팅 실패 메시지가 "어떤 세션을 찾았고 어느 단계에서 실패했는지"를 보여준다.

### 5. `StopSession` PID race 완화

현재 상태:

- `aicd`는 registry의 PID에 `SIGTERM`을 보낸다.
- 현재 PID는 `aic-session` 프로세스이며, PID 재사용 가능성이 있다.

제안:

- SIGTERM 전 다음 중 최소 하나를 확인한다.
  - session socket ping 성공.
  - process command name이 `aic-session` 또는 expected binary path와 일치.
  - registry의 `created_at` 이후 process start time 확인.
- 실패 시 registry를 바로 지우지 말고 `Detached`/`Failed` 상태로 낮춘다.

Acceptance Criteria:

- 이미 죽은 PID는 registry cleanup만 수행한다.
- 다른 프로세스 PID로 보이면 SIGTERM을 거부한다.

### 6. Session ID 충돌 방어

현재 상태:

- session id는 8자 lowercase hex다.
- 충돌 확률은 낮지만 기존 socket/lock과 충돌하면 bind/remove 과정이 애매해질 수 있다.

제안:

- `generate_unused_session_id(max_attempts)`를 추가한다.
- socket 또는 pid lock path가 이미 살아 있으면 새 id를 생성한다.
- max attempts 초과 시 명시적 에러를 낸다.

Acceptance Criteria:

- 기존 live `session-{id}.sock`이 있으면 같은 id를 재사용하지 않는다.
- stale artifact는 기존 cleanup 경로로 정리된다.

## Phase 2: 사용자 가치가 큰 기능 확장

목표: Phase 1에서 안정화한 세션 기반 위에 "무엇을 분석할지 고르는 경험"과 "출력 부족을 복구하는 경험"을 붙인다.

### 1. `aic last` / `aic history`

제안:

- 최근 command record를 시간순으로 보여주는 CLI를 추가한다.
- PTY ring buffer record와 hook metadata record를 같은 UI에서 표시한다.
- capture quality, exit code, cwd, duration, source를 함께 보여준다.

예시:

```text
aic history --limit 10
aic last --session abcd1234
```

Acceptance Criteria:

- `FullOutput`, `MetadataOnly`, `TruncatedOutput`이 구분되어 표시된다.
- 특정 record를 골라 `aic analyze --record <id>` 같은 후속 동작으로 연결할 수 있다.

### 2. `aic sessions --interactive`

제안:

- 여러 터미널을 쓰는 사용자가 세션을 고르고 action을 실행할 수 있게 한다.
- action 후보: status, last command, analyze last, stop, prune detached.

Acceptance Criteria:

- 현재 세션은 `current`로 표시된다.
- stale/detached 세션은 위험 action 전에 confirm을 요구한다.

### 3. `aic capture-last`

제안:

- hook mode의 `MetadataOnly` record를 full output record로 승격하는 명령.
- 마지막 명령을 그대로 재실행하기 전 safety classifier를 적용한다.
- 기본은 destructive command 재실행 금지, 애매한 경우 강한 confirm.

Safety denylist 후보:

- `rm`, `mv`, `cp -f`, `chmod`, `chown`, `kill`, `pkill`.
- `git reset`, `git clean`, `git push --force`.
- `docker rm`, `kubectl delete`, `terraform apply/destroy`.
- redirect overwrite, pipe to shell, package publish/deploy 계열.

Acceptance Criteria:

- `aic capture-last`는 원래 exit code를 보존한 새 `ExplicitCapture` record를 만든다.
- unsafe command는 기본 거부한다.
- 사용자에게 실제 재실행될 command를 보여준다.

### 4. `aic run` record 저장과 재분석 연결 강화

현재 상태:

- `aic run -- <cmd>`는 explicit capture wrapper로 존재한다.

제안:

- 실행 결과를 local record 또는 session/aicd store에 저장해 바로 `aic` 기본 분석 흐름과 연결한다.
- byte cap, line cap, binary detection, truncation metadata를 일관되게 채운다.

Acceptance Criteria:

- `aic run -- cargo build` 실패 직후 `aic`가 같은 record를 다시 찾는다.
- truncation/binary 상태가 prompt와 UI에 반영된다.

### 5. `aic doctor --fix`

제안:

- 반복적인 환경 문제를 자동 수정한다.
- 가능한 fix:
  - `aicd` 시작.
  - hook 파일 재생성.
  - rc marker block 설치/갱신.
  - stale socket/pid cleanup.
  - 오래된 registry prune.

Acceptance Criteria:

- 모든 fix는 실행 전 변경 내용을 보여준다.
- rc 파일 변경은 marker block 안에서만 한다.
- `--dry-run`으로 변경 없이 계획을 볼 수 있다.

### 6. 세션 tag/rename

제안:

- `aic session tag <id> <name>` 또는 `aic session rename <id> <name>`.
- registry snapshot에 사용자 label을 추가한다.
- status/sessions/history에서 label을 표시한다.

Acceptance Criteria:

- label은 session id와 별도로 저장된다.
- detached 후 snapshot restore에서도 유지된다.

## Phase 3: aicd 중심 구조 전환

목표: 장기적으로 `aic-session`을 얇은 attach process로 줄이고, `aicd`가 PTY lifecycle과 command store를 소유하게 한다.

### 1. PTY ownership을 `aicd`로 이동

현재 상태:

- `aic-session`이 PTY child를 spawn하고 소유한다.
- `aicd`는 registry와 lifecycle command만 관리한다.

제안:

- `aicd`가 `CreateSession`, `AttachSession`, `DetachSession`을 처리한다.
- `aic-session`은 terminal raw mode와 byte relay만 맡는다.
- ring buffer, boundary detection, command store는 `aicd` 안으로 이동한다.

Acceptance Criteria:

- `aic-session` 비정상 종료 후 `aicd`가 PTY child cleanup 정책을 실행한다.
- `aic status`, `aic top`, `aic sessions`가 socket scan 없이 registry 기준으로 동작한다.
- 기존 PTY capture 정확도는 유지된다.

### 2. attach stream protocol 추가

제안:

- control IPC와 data stream IPC를 분리한다.
- attach stream은 stdin bytes, stdout bytes, resize event, detach event를 처리한다.
- protocol version을 넣어 client/server mismatch를 진단 가능하게 한다.

Acceptance Criteria:

- resize, Ctrl-C, EOF가 기존 PTY wrapper와 동일하게 동작한다.
- unknown/new frame은 graceful error 또는 negotiated downgrade로 처리된다.

### 3. 중앙 command store

제안:

- 세션별 ring buffer를 `aicd`가 소유한다.
- PTY record, hook record, explicit capture record를 하나의 store API로 통합한다.
- record id를 도입해 history, analyze, capture-last, debug bundle이 같은 식별자를 쓴다.

Acceptance Criteria:

- `aic history`가 모든 capture source를 통합해서 보여준다.
- `aic analyze --record <id>`가 session live 여부와 무관하게 동작한다.
- store는 bounded retention 정책을 갖는다.

### 4. Hybrid capture mode 제품화

제안:

- 기본은 hook metadata로 가볍게 기록한다.
- 실패 분석 시 output이 부족하면 `capture-last` 또는 `aic run`으로 자연스럽게 연결한다.
- PTY mode는 정확도가 필요한 사용자의 opt-in으로 유지한다.

Acceptance Criteria:

- `session.capture_mode = hybrid`에서 metadata-only failure는 actionable hint를 보여준다.
- TUI/interactive command는 capture 재실행을 기본 제안하지 않는다.
- destructive command는 자동 재실행하지 않는다.

### 5. daemon autostart와 crash recovery 강화

제안:

- `aic daemon install`을 기본 onboarding 흐름에 더 강하게 연결한다.
- daemon restart 후 registry snapshot을 복구하고 live process 검증을 수행한다.
- stale artifact cleanup 결과를 `doctor`와 `debug bundle`에 포함한다.

Acceptance Criteria:

- 재부팅 후 `aicd`가 자동 시작된다.
- stale registry entry는 `Detached` 또는 `Failed`로 복구된다.
- debug bundle만으로 세션/daemon 상태를 재현 가능하게 설명할 수 있다.

## 권장 순서

1. Phase 1.2 `--no-hook` 구현: surface와 실제 동작 불일치를 먼저 제거한다.
2. Phase 1.1 runtime 분리: 이후 작업의 충돌과 회귀를 줄인다.
3. Phase 1.3/1.4 cwd와 routing: hook mode 기본 경험을 안정화한다.
4. Phase 2.1 history/last: record store의 사용자 노출면을 만든다.
5. Phase 2.3 capture-last: metadata-only의 가장 큰 약점을 보완한다.
6. Phase 3.1 이후: `aicd` ownership 전환은 별도 PRD/마이그레이션 플랜으로 쪼개서 진행한다.

## 열린 질문

- `aicd` 없는 환경을 장기적으로 계속 1급 지원할 것인가, 아니면 fallback으로만 둘 것인가?
- `hook mode`에서 생성한 session id와 `aic-session`의 session id가 같은 shell에서 어떻게 공존해야 하는가?
- `capture-last`의 safety classifier를 rule 기반으로 충분히 갈 것인가, project-specific allowlist를 둘 것인가?
- command store retention은 line count, byte count, age 중 무엇을 1차 기준으로 삼을 것인가?
- `aic-session` thin attach 전환 시 backward-compatible IPC를 얼마 동안 유지할 것인가?

