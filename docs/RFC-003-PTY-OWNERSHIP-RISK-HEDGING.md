# RFC-003: PTY Ownership Transfer — Risk Hedging Design

> PRD-AICD-SUPERVISOR Phase 2의 “PTY ownership을 `aicd`로 이전”을 안전하게 굴리기 위한 리스크 헷징 설계.
> 이전 자체의 가치/모델은 PRD에서 정의되어 있고, 본 RFC는 §16 Risks를 구현 수준의 mitigations 으로 확장한다.

- 상태: Draft
- 관련 문서:
  - [PRD-AICD-SUPERVISOR.md](./PRD-AICD-SUPERVISOR.md) — 전체 모델 (Phase 2 PTY ownership 이전 결정)
    - [§11 MVP 범위](./PRD-AICD-SUPERVISOR.md#11-mvp-범위) (Phase 3 = 본 RFC가 헷지하는 단계)
    - [§13 대안 검토](./PRD-AICD-SUPERVISOR.md#13-대안-검토) (특히 [§13.1 fd passing](./PRD-AICD-SUPERVISOR.md#131-완전-단일-데몬--fd-passing))
    - [§15 성공 지표](./PRD-AICD-SUPERVISOR.md#15-성공-지표) (정량 acceptance gate 의 출처)
    - [§16 리스크](./PRD-AICD-SUPERVISOR.md#16-리스크) (본 RFC §5 헷징 5종이 1:1 대응)
    - [§17 Open Questions](./PRD-AICD-SUPERVISOR.md#17-open-questions)
  - [RFC-001-CENTRALIZED-RECORD-STORE.md](./RFC-001-CENTRALIZED-RECORD-STORE.md) §3 비목표 (“fd passing은 별도 RFC”)
  - [AIC-SESSION-IMPROVEMENT-ROADMAP.md](./AIC-SESSION-IMPROVEMENT-ROADMAP.md)
- 헷징 섹션 바로가기:
  - [§5.1 — Relay 회귀](#51-리스크-1--relay-behavior-회귀)
  - [§5.2 — attach ↔ child race](#52-리스크-2--attach--child-lifecycle-race)
  - [§5.3 — Raw mode 복원](#53-리스크-3--terminal-raw-mode-복원-책임)
  - [§5.4 — `aicd` 다운 blast radius](#54-리스크-4--aicd-다운의-blast-radius)
  - [§5.5 — Registry SPOF](#55-리스크-5--registry-persistence가-새-spof)

## 1. 배경

PRD-AICD-SUPERVISOR [§11](./PRD-AICD-SUPERVISOR.md#11-mvp-범위)에서 정의한 Phase 1·2(control plane + registry)는 이미 master에 들어와 있다. 코드 상 현재 상태:

- `aicd`: registry / control UDS / heartbeat / stale cleanup 담당
- `aic-session`: 터미널마다 1개. 여전히 **자신이 PTY child를 spawn하고 소유**한다.
  - `aic-server/src/pty_manager.rs`: `PtyManager::spawn_shell_with_hook_policy(...)`
  - `aic-server/src/session_runtime.rs:479`: 같은 함수 호출 후 ring buffer / output processor / boundary detector를 모두 `aic-session` 안에서 운영

PRD [§11](./PRD-AICD-SUPERVISOR.md#11-mvp-범위) Phase 3은 PTY child의 spawn/소유를 `aicd`로 이전하고, `aic-session`을 “raw mode + stdin/stdout relay + heartbeat”만 하는 얇은 attach 프로세스로 축소한다. 데이터 plane 분리(ring/processor/boundary 이동)는 [RFC-001](./RFC-001-CENTRALIZED-RECORD-STORE.md)이 담당하고, 본 RFC는 **PTY child fd 자체의 ownership 이동**과 그에 따라 새로 등장하는 다섯 가지 리스크의 mitigations 를 다룬다.

PRD [§16 리스크](./PRD-AICD-SUPERVISOR.md#16-리스크)가 명시한 항목은 다음과 같다 (괄호는 본 RFC 의 헷징 섹션).

1. PTY ownership 이동 과정에서 relay behavior 회귀 ([§5.1](#51-리스크-1--relay-behavior-회귀))
2. attach ↔ child lifecycle race condition ([§5.2](#52-리스크-2--attach--child-lifecycle-race))
3. terminal raw mode 복원 책임 경계 모호 → 사용자 터미널 깨짐 ([§5.3](#53-리스크-3--terminal-raw-mode-복원-책임))
4. `aicd`가 죽으면 모든 active terminal 동시 영향 ([§5.4](#54-리스크-4--aicd-다운의-blast-radius))
5. registry persistence가 새로운 단일 장애점이 됨 ([§5.5](#55-리스크-5--registry-persistence가-새-spof))

PRD [§16 완화책](./PRD-AICD-SUPERVISOR.md#16-리스크)은 “feature flag 제공 / 멀티세션 fallback / crash 테스트 우선”까지만 적혀 있다. 본 RFC는 각 리스크에 대해 “타입과 invariant로 컴파일 타임에 가두는” 구조 설계 + 운영 안전망 + 정량 acceptance gate 를 구체화한다.

## 2. 목표

### 2.1 Product

- Phase 3 활성화가 사용자 터미널을 깨뜨리지 않는다. 회귀 발생 시 한 줄 명령으로 복구 가능.
- `aicd` 다운이 active terminal 모두를 끊지 않는다. 최소 “셸 작업은 계속 가능”이 유지된다.
- attach가 강제 종료돼도 session·child lifecycle이 결정적이다.

### 2.2 Engineering

- PTY fd ownership을 타입으로 봉인해 attach 코드가 child lifecycle을 직접 만지지 못한다.
- attach generation counter, single-writer invariant, RAII raw-mode guard로 race·복원 누락을 컴파일/런타임에서 잡는다.
- registry 디스크 표현은 truth가 아니라 hint 로만 둔다. `aicd` 시작 시 process scan + socket inode + 디스크의 3-source reconcile.
- 모든 헷징은 PRD [§15 성공 지표](./PRD-AICD-SUPERVISOR.md#15-성공-지표)(p95 cleanup < 10s, cold start < 300ms 등)를 회귀 gate 로 둔다.

## 3. 비목표

- 본 RFC는 PRD [§11](./PRD-AICD-SUPERVISOR.md#11-mvp-범위) Phase 4(`aic` default flow의 daemon-first 전환)를 정의하지 않는다. CLI 흐름 변경은 별도 PR.
- 본 RFC는 “완전 단일 데몬 + `SCM_RIGHTS` fd passing” 모델([PRD §13.1](./PRD-AICD-SUPERVISOR.md#131-완전-단일-데몬--fd-passing))을 채택하지 않는다. attach 프로세스는 그대로 두되 PTY fd만 `aicd`로 옮긴다.
- launchd / systemd unit 자동 설치 자체는 README Roadmap에 위임한다. 본 RFC는 “있으면 리스크 4가 더 줄어든다” 정도로만 참조한다 ([§5.4](#54-리스크-4--aicd-다운의-blast-radius)).
- 새 persistence backend (SQLite 등) 도입은 비목표. JSONL append-only + snapshot 컴팩션을 권장한다 ([§5.5](#55-리스크-5--registry-persistence가-새-spof)).

## 4. 핵심 원칙

1. **Owner 단순화**: PTY child의 `wait()`·`kill()`은 `aicd` 내부 한 타입만 호출한다. attach는 byte stream만 만진다.
2. **Single writer per direction**: PTY master에 쓰는 task 1개, 읽는 task 1개. attach 교체는 “읽기 task의 sink만 바꾸기”로 표현된다.
3. **Generation counter**: 모든 attach 메시지는 `(session_id, attach_generation)` 튜플로 라우팅. 옛 generation은 즉시 폐기.
4. **Disk는 hint, in-memory가 truth**: registry는 reconstructable. 디스크 손상이 시작 실패로 이어지지 않는다.
5. **Graceful degradation**: `aicd` 다운 시 attach는 즉시 종료하지 않고, relay-only degraded mode로 살아있다가 reattach.
6. **Failure observable**: 모든 mitigation 은 `aic doctor`의 새로운 진단 축으로 노출된다.

## 5. 헷징 설계

### 5.1 리스크 1 — Relay behavior 회귀

**Mitigations**

- **Owner toggle.** `phase-3_5` feature flag를 런타임 env `AIC_PTY_OWNER=session|daemon`으로 승격. 같은 빌드에서 두 경로를 전환 가능하게 둔다. 회귀 의심 시 사용자가 `AIC_PTY_OWNER=session aic-session`으로 즉시 fallback.
- **Library-first 분리.** `output_processor` / `boundary_detector` / `ring_buffer`는 owner와 무관한 lib crate API로 둔다(이미 lib에 있음). PTY를 누가 spawn하든 같은 함수가 호출되도록 호출 site만 분기한다. 코어 동작은 한 번만 검증한다.
- **Golden trace replay.** zsh / bash 실세션의 stdin·stdout·SIGWINCH·OSC 133 시퀀스를 JSONL로 녹화. legacy / daemon 두 owner에 같은 입력을 흘려 ring buffer + `CommandRecord` 결과의 byte-identical 여부를 비교. 차이 위치를 회귀 트리아지의 첫 단서로 사용.
- **Canary 단계.** Phase 3 rollout 순서:
  1. shell hook off + non-TTY (CI)
  2. bash 단일 세션
  3. zsh 단일 세션
  4. alternate-screen TUI (vim/htop/less -R)
  5. multi-session 동시
  각 단계마다 “probe relay” 명령으로 fixture 흘려 PASS 후 다음.
- **Acceptance gate**:
  - golden trace 결과 byte-identical
  - alt-screen TUI smoke test (vim 진입/저장/종료, htop 1초 프레임)
  - 회귀 발견 시 `AIC_PTY_OWNER=session` fallback 으로 사용자 단계에서 복구되는지 확인

### 5.2 리스크 2 — attach ↔ child lifecycle race

**Mitigations**

- **Type-sealed PTY ownership.** `aicd` 내부에 다음 두 타입을 둔다.
  ```rust
  // aic-server/src/pty_session.rs (new, aicd-only)
  pub struct PtySession { /* master, child, generation, ... — pub(crate) only */ }
  pub struct AttachStream<'a> { session: &'a PtySession, generation: u64 }
  ```
  attach 핸들러는 `&AttachStream`만 받는다. PTY fd / `Child` 핸들에는 컴파일 타임에 접근 불가.
- **Attach generation counter.** 세션마다 `attach_generation: AtomicU64`. `attach_open` 시 += 1. 모든 client→server frame은 헤더에 generation을 싣고, 다른 generation은 폐기한다. 죽기 직전 attach가 새 attach 화면에 garbage를 흘리는 race 차단.
- **Single-writer invariant.** PTY master에 쓰는 task 1개, 읽는 task 1개. attach 교체는 “읽기 task의 sink (Sender) 만 swap”. invariant 위반 시 panic 후 fast-fail (회귀 빨리 발견).
- **두-단계 detach.**
  1. `Detached` 진입 = PTY input pipe 만 끊기 (child는 살아있음)
  2. `detach_grace_secs` 후 child 종료
  - 결과: grace 안에 reattach 시 SIGCONT 같은 신호 없이 그대로 이어진다. “끊는 순간”과 “죽이는 순간”이 분리된다.
- **State invariant property test.** PRD [§10.2 Session State](./PRD-AICD-SUPERVISOR.md#102-session-state) (`Creating→Attached→Detached→Stopping→Stopped`)을 `proptest`로 검증. 무작위 이벤트(attach close / SIGCHLD / heartbeat timeout / Shutdown / 재attach)을 섞어도 invariant 깨지지 않는지 확인. 코드에 이미 `proptest` 인프라 있음.
- **Acceptance gate**:
  - state machine proptest 1024 cases 통과
  - “attach kill -9 → 5s 안에 reattach” 시나리오에서 child 살아있고 buffer 연속

### 5.3 리스크 3 — Terminal raw mode 복원 책임

**Mitigations**

- **`RawModeGuard` RAII.** `aic-session` 내부에 `set_raw_mode()` 결과를 들고 있는 RAII 타입을 도입. `Drop` + panic hook 둘 다에서 `restore_terminal()` 호출 보장. 현재 코드는 정상 종료 path만 보장한다(`session_runtime.rs:875`).
- **Termios disk snapshot.** attach 시작 시 `tcgetattr` 결과를 `~/.local/state/aic/termios/<tty>.json`에 저장. attach가 SIGKILL돼도 `aicd`가 detach 이벤트를 보면 같은 TTY에 한해 그 스냅샷으로 `tcsetattr` rescue 시도.
- **TTY ownership 경계 명문화.** raw mode 토글은 `aic-session` 만 한다. `aicd`는 PTY master fd를 들고 있을 뿐 controlling TTY를 만지지 않는다. 책임 경계가 모호하면 raw mode 깨짐 = 사용자 터미널 깨짐으로 직결된다.
- **Last-resort 복구 명령.** `aic doctor --fix-tty`(내부적으로 `stty sane`)을 표준화. README 의 `aic doctor --fix` 자리에 명시. 사용자가 이 한 줄로 복구할 수 있음을 보장.
- **Acceptance gate**:
  - panic 주입 테스트(`std::panic!()` from relay task) 후 termios가 원복되는지 확인
  - SIGKILL 후 다음 새 셸에서 입력이 정상인지 manual test 체크리스트
  - `aic doctor --fix-tty`로 인공 깨짐(`stty -icanon -echo`) 복구 확인

### 5.4 리스크 4 — `aicd` 다운의 blast radius

**Mitigations**

- **Attach degraded mode.** daemon stream 끊김 = 즉시 종료가 아니다. 기본 동작:
  - PTY relay는 그대로 계속 (사용자는 셸에서 작업 마저 가능)
  - 새 command 분석 / record 조회는 “데몬 부재” 메시지
  - daemon 부활 감지 시 reattach 시도, 백필
- **Bounded local ring.** attach가 daemon 없이도 보유하는 local ring buffer 를 작게(예: 64KB) 유지. daemon 부활 시 backfill. 죽어도 “마지막 명령은 분석 가능” 보장.
- **Stampede-safe restart.** attach들이 daemon 다운을 감지하면 `aicd.lock` 시도 → **단 하나의** attach만 `aicd` 재시작. 나머지는 polling. 멀티터미널 stampede 회피.
- **Crash artifact.** `aicd`가 panic / SIGSEGV로 죽으면 마지막 registry snapshot + 마지막 N개 lifecycle 이벤트를 `~/.local/state/aic/crash/<ts>.json`에 남김. 다음 `aicd` 시작 시 “last shutdown reason”으로 노출 ([PRD R10 Observability](./PRD-AICD-SUPERVISOR.md#r10-observability)).
- **OS service unit 권장(옵션).** README Roadmap의 launchd/systemd user unit 자동 설치는 사실상 본 헷징의 일부. PRD [§3 비목표](./PRD-AICD-SUPERVISOR.md#3-비목표)가 “모든 OS service manager 통합을 필수로 하지 않는다”고 한 것과 충돌하지 않음. 설치는 옵션, 실행은 standalone 가능.
- **Acceptance gate**:
  - `kill -9 aicd` 직후 active attach 5개 모두 셸 입력 가능
  - daemon 부활까지 p95 < 5s (lock-한 attach 1개가 spawn)
  - 부활 후 record backfill 으로 최근 1개 명령 분석 가능

### 5.5 리스크 5 — Registry persistence가 새 SPOF

**Mitigations**

- **Truth는 in-memory.** disk file은 hint. `aicd` 시작 시 다음 3-source reconcile:
  1. disk registry (있으면 읽음)
  2. `ps` 기반 PTY child 후보 scan
  3. socket inode 목록 (`/tmp/aic-{uid}/...`)
  하나가 손상돼도 나머지 둘로 active session 을 재구성한다.
- **JSONL append-only + snapshot 컴팩션.** PRD [§17 Open Questions](./PRD-AICD-SUPERVISOR.md#17-open-questions)가 묻는 “JSONL vs snapshot vs SQLite” 중 가장 보수적 선택.
  - SQLite: fsync 비용·잠금 처리가 새 SPOF가 될 수 있음. MVP 비추.
  - 단일 snapshot JSON: 부분 손상 시 전체가 못 읽힘.
  - **권장**: events.jsonl append-only + 주기적(예: 100 event마다) snapshot.json 생성. snapshot 이후 events 만 replay.
- **Schema versioning.** 각 record 첫 필드에 `schema_version`. 미지원 버전은 quarantine 으로 옮기고 새 registry 시작. 포맷 변경이 stale 장애로 이어지지 않게.
- **Lock 분리.** `aicd.lock`(singleton)과 `registry.lock`(파일 잠금)을 분리. registry 손상이 daemon 시작 자체를 막지 않는다.
- **Idempotent reconcile.** 같은 reconcile 을 N 번 실행해도 결과 동일. proptest 로 검증.
- **Acceptance gate**:
  - registry 파일 절반을 무작위 truncate 한 fixture 에서도 daemon cold start 성공 + 살아있는 PTY child 인식
  - schema_version 미지원 fixture → quarantine 후 정상 시작
  - reconcile property test 1024 cases 통과

## 6. 구현 단계

PRD [§11 MVP 범위](./PRD-AICD-SUPERVISOR.md#11-mvp-범위)의 Phase 3을 다음 7개 sub-phase 로 쪼갠다. 각 단계는 자체 acceptance gate 가 통과해야 다음으로 진행한다.

1. **3a. Type sealing.** `PtySession` / `AttachStream` 타입 도입. 기존 owner 는 그대로 `aic-session`. attach 핸들러가 PTY fd 에 직접 접근하지 않는 구조로 리팩터링. → [§5.2](#52-리스크-2--attach--child-lifecycle-race)
2. **3b. Generation counter + single-writer.** attach 프로토콜에 generation 추가. invariant 위반 시 panic. proptest 추가. → [§5.2](#52-리스크-2--attach--child-lifecycle-race)
3. **3c. RawModeGuard + termios snapshot.** RAII guard, panic hook, disk snapshot, `aic doctor --fix-tty`. 이 단계는 owner 가 `aic-session` 인 상태에서도 단독으로 가치가 있음 → 먼저 머지. → [§5.3](#53-리스크-3--terminal-raw-mode-복원-책임)
4. **3d. Owner toggle skeleton.** `AIC_PTY_OWNER=daemon` 코드 path 추가. 기본은 `session`. `aicd` 안에 PTY spawn/소유 코드(`PtyManager` 재사용) 도입. → [§5.1](#51-리스크-1--relay-behavior-회귀)
5. **3e. Degraded mode + crash artifact.** attach 의 daemon-down 동작, bounded local ring, stampede-safe restart, crash JSON. owner 와 무관하게 가치가 있어 별도 머지 가능. → [§5.4](#54-리스크-4--aicd-다운의-blast-radius)
6. **3f. Registry hardening.** events.jsonl + snapshot 컴팩션, schema_version, 3-source reconcile, lock 분리. → [§5.5](#55-리스크-5--registry-persistence가-새-spof)
7. **3g. Canary rollout.** [§5.1 Canary 단계](#51-리스크-1--relay-behavior-회귀) 순서대로 `AIC_PTY_OWNER=daemon` 활성화. 마지막에 default 전환.

각 단계는 단독 PR로 머지 가능하고, 문제 발견 시 직전 단계 까지 사용 가능한 상태로 둔다.

## 7. 정량 Acceptance Gate

PRD [§15 성공 지표](./PRD-AICD-SUPERVISOR.md#15-성공-지표)를 CI에서 자동 측정·gating.

| 지표 | 목표 | 측정 방식 |
|------|------|-----------|
| attach crash → cleanup p95 | < 10s | integration test, 50 iter |
| `aic status` 응답 p95 | < 100ms | bench harness |
| `aic sessions` 응답 p95 with 20 sessions | < 100ms | bench harness |
| stale artifact cleanup success rate | > 99% | property test 1024 cases |
| daemon cold start p95 | < 300ms | bench harness, 100 iter |
| `aicd` kill -9 → 활성 attach 셸 입력 가능 | 100% | integration |
| daemon 부활 p95 (1개 attach 가 lock 시도) | < 5s | integration |
| registry 절반 truncate 후 cold start | 성공 | fixture-driven test |

CI에서 이 숫자가 회귀하면 머지 차단.

## 8. 새 진단 축 (`aic doctor`)

기존 doctor 9-axis ([PRD §7 R6](./PRD-AICD-SUPERVISOR.md#r6-status--doctor--top-ux))에 다음 3축 추가.

- **PTY owner**: 현재 owner (`session` / `daemon`), feature flag 상태
- **Attach generation**: 현재 attach generation, daemon 측 generation 과 일치 여부
- **Termios snapshot**: 디스크에 snapshot 존재 여부, 권한 (`0600`), 마지막 갱신 시각

진단 가능한 상태가 곧 회복 가능한 상태이며, doctor 가 새 mitigation 의 운영 진입점이 된다.

## 9. 대안 검토

### 9.1 Mitigation 없이 Phase 3 직진

- 장점: 구현량 최소.
- 단점: 첫 회귀가 사용자 터미널을 깨뜨리는 형태로 노출됨. fallback 경로 없음.
- 판단: 채택 불가.

### 9.2 `SCM_RIGHTS` fd passing 으로 attach 도 제거

- 장점: attach 프로세스 자체가 사라져 lifecycle 단순.
- 단점: macOS/Linux controlling TTY 차이, raw mode 복원 위험이 더 커짐. PRD [§13.1](./PRD-AICD-SUPERVISOR.md#131-완전-단일-데몬--fd-passing) 에서 이미 “MVP 부적합” 결론.
- 판단: 본 RFC 비목표. 별도 RFC 로.

### 9.3 SQLite registry 로 SPOF 해소

- 장점: 트랜잭션·인덱스 활용 가능.
- 단점: fsync / WAL 잠금 / corrupt DB 복구 비용. 새 SPOF 가능성.
- 판단: 비채택. JSONL append-only + snapshot 컴팩션이 더 보수적.

### 9.4 OS service unit 으로 daemon HA 만 강화

- 장점: 다운타임 자동 복구.
- 단점: attach degraded mode 가 없으면 “service 가 재시작될 때까지 셸이 막힘” 경험은 그대로.
- 판단: 부분 채택. 본 RFC 의 [§5.4](#54-리스크-4--aicd-다운의-blast-radius) 와 직교 — 둘 다 적용.

## 10. Open Questions

- **OQ1.** termios snapshot rescue 를 daemon 이 실제로 적용해도 되는 조건은? 같은 TTY major/minor 매칭만으로 안전한가, 아니면 사용자 confirm 이 필요한가.
- **OQ2.** `attach generation` 을 protocol breaking 으로 도입할지, optional field 로 하위 호환을 둘지. [RFC-001](./RFC-001-CENTRALIZED-RECORD-STORE.md) 의 record store API 변경과 동시 진행할지.
- **OQ3.** crash artifact 의 보존 기간 / 회전 정책 (현재 audit log 는 7일). 동일 정책을 따를지.
- **OQ4.** `AIC_PTY_OWNER` env 의 위치 — 사용자별 (`config.toml`) vs 세션별 (env). canary 기간에는 env 가 편하지만 default 전환 후에는 config 가 자연스러움.
- **OQ5.** registry events.jsonl 의 한 record schema 를 [RFC-001](./RFC-001-CENTRALIZED-RECORD-STORE.md) 의 `CommandRecord` 와 통합할지, 별도 namespace 로 둘지.

## 11. 권장 로드맵

1. RFC-003 머지 (이 문서).
2. Phase 3c (RawModeGuard + termios snapshot + `aic doctor --fix-tty`) 먼저. owner 와 무관하게 사용자 안전성 즉시 향상. → [§5.3](#53-리스크-3--terminal-raw-mode-복원-책임)
3. Phase 3a/3b (type sealing + generation) — 리스크 2 차단. → [§5.2](#52-리스크-2--attach--child-lifecycle-race)
4. Phase 3e (degraded mode + crash artifact) — 리스크 4 차단. 여전히 owner 는 `aic-session`. → [§5.4](#54-리스크-4--aicd-다운의-blast-radius)
5. Phase 3f (registry hardening) — 리스크 5 차단. → [§5.5](#55-리스크-5--registry-persistence가-새-spof)
6. Phase 3d/3g (owner toggle + canary) — 리스크 1 을 측정 가능한 형태로 직면. canary 단계 통과 후 default 전환. → [§5.1](#51-리스크-1--relay-behavior-회귀)
7. PRD [§11](./PRD-AICD-SUPERVISOR.md#11-mvp-범위) Phase 4 (CLI flow daemon-first) — 본 RFC 의 후속.

## 12. Decision

PRD [§16 리스크](./PRD-AICD-SUPERVISOR.md#16-리스크) 5종은 “feature flag 와 fallback 으로 막는다” 수준에서 멈추면 운영에 부족하다. 본 RFC 는 각 리스크를 **타입 봉인 / single-writer invariant / generation counter / RAII guard / 3-source reconcile / degraded mode / 정량 acceptance gate** 의 조합으로 헷지한다 ([§5](#5-헷징-설계)). 7개 sub-phase ([§6](#6-구현-단계))로 쪼개 단독 머지 가능하게 두며, owner 전환 자체는 가장 마지막 canary 단계로 미룬다. 사용자 터미널이 깨질 수 있는 변경은 항상 한 줄 fallback (`AIC_PTY_OWNER=session` 또는 `aic doctor --fix-tty`) 으로 복구 가능해야 한다.
