# RFC-001: Centralized Command Record Store

> `aic-session`의 data plane(ring buffer, output processor, boundary detector)을
> `aicd`로 옮겨서 터미널마다 중복되던 1400 LOC를 사용자당 한 벌로 합친다.
> `aic-session`은 PTY relay와 raw mode 관리만 담당하는 얇은 프로세스로 축소한다.

- 상태: Draft
- 관련 문서:
  - [PRD-AICD-SUPERVISOR.md](./PRD-AICD-SUPERVISOR.md) (Phase 3 — 본 RFC가 해당 단계)
  - [CAPTURE-MODE-TRADEOFFS.md](./CAPTURE-MODE-TRADEOFFS.md)
  - [AIC-SESSION-IMPROVEMENT-ROADMAP.md](./AIC-SESSION-IMPROVEMENT-ROADMAP.md) Phase 3.1, 3.3

## 1. 배경과 문제

현재 구조는 터미널마다 `aic-session` foreground 프로세스가 뜬다. 각 인스턴스는 데이터 plane 전체를 독립적으로 들고 있다.

LOC 측정 (현재 master 기준):

```
aic-server/src/main.rs                64
aic-server/src/session_runtime.rs    340  (조합 로직)
aic-server/src/pty_manager.rs        302  (PTY spawn/relay — 세션 local)
aic-server/src/uds_server.rs         350  (IPC server)
aic-server/src/ring_buffer.rs        451  (command record store)
aic-server/src/output_processor.rs   339  (ANSI strip + clean text)
aic-server/src/boundary_detector.rs  609  (OSC 133 / timing heuristic)
```

이 중 ring buffer, output processor, boundary detector 1399 LOC는 **사용자당 한 번만 필요한 로직**이다. 한 사용자가 터미널 10개를 열면 같은 로직이 10번 실행되고, 메모리도 10 × 500 라인 × 2KB 수준으로 불어난다. `aicd` 쪽에는 이미 `HookEventStore`로 session-id별 command record를 보관하는 기반이 깔려 있으므로, 같은 store를 PTY record까지 확장하면 중복이 제거된다.

추가로 현재 설계에서 `aic-session` IPC는 자기 세션의 ring buffer만 보기 때문에, 사용자가 `aic --session <id>`로 다른 터미널의 마지막 명령을 조회하려면 해당 세션 socket을 직접 찾아가야 한다. 사용자 단위 store로 합치면 `aicd` 한 곳에서 라우팅할 수 있다.

## 2. 목표

### 2.1 Product

- 터미널당 `aic-session` 메모리 상주량을 현재 대비 60% 이상 줄인다 (ring buffer/boundary detector 제거분).
- `aic --session <id>`와 `aic history`가 터미널 수와 무관하게 `aicd` 한 곳을 조회한다.
- PTY mode의 출력 캡처 정확도와 TUI 호환성을 유지한다.

### 2.2 Engineering

- `aic-session`의 책임을 다음으로 축소한다.
  - PTY child spawn, stdin/stdout relay, raw mode 관리
  - SIGWINCH 처리, 종료 시 cleanup
- 다음은 `aicd`로 이동한다.
  - ring buffer
  - output processor (ANSI strip + clean text)
  - boundary detector (OSC 133 / timing heuristic)
  - command record 조회 IPC (`GetLastCommand`, `GetRecentLines`, `GetRecentCommands`, `FindRecordByPrefix`)
- 기존 `HookEventStore`를 일반 `CommandRecordStore`로 승격한다. PTY record, hook record, explicit capture record가 같은 store에 공존한다.
- 마이그레이션은 feature flag로 점진 도입한다. 기존 session socket 경로는 한동안 fallback으로 유지한다.

## 3. 비목표

- `aic-session` 프로세스 자체를 없애지 않는다. Terminal fd 소유와 raw mode 복원 때문에 foreground 프로세스는 필요하다.
- `SCM_RIGHTS` 기반 fd passing으로 PTY ownership을 `aicd`로 옮기지 않는다 (별도 RFC). 이 RFC에서 PTY child는 여전히 `aic-session`이 spawn/소유한다.
- 기존 shell hook 스크립트(`~/.aic/hooks.zsh` 등)의 포맷은 변경하지 않는다.
- 새 저장 backend(SQLite 등)를 도입하지 않는다. in-memory ring + `aicd`가 죽으면 유실된다는 현재 의미는 그대로 둔다.

## 4. 제안 구조

### 4.1 프로세스 역할

```
aic-session (terminal-local, thin)
├─ CLI parsing, raw mode 관리
├─ PTY child spawn (PtyManager 그대로 유지)
├─ stdin → PTY writer relay
└─ PTY reader → bytes를 그대로 aicd로 stream (processing 없음)

aicd (user-local, singleton)
├─ Session registry (기존)
├─ CommandRecordStore (기존 HookEventStore 승격)
├─ 세션별 OutputProcessor + BoundaryDetector
│   - aic-session으로부터 raw bytes를 받아서 처리
│   - 완성된 CommandRecord를 store에 push
├─ Control IPC (기존 + 아래 신규)
└─ Data stream IPC (신규 — 아래 4.3)
```

### 4.2 CommandRecordStore

`aic-server/src/hook_events.rs`의 `HookEventStore`를 `command_record_store.rs`로 옮기고 다음으로 확장한다.

```rust
pub struct CommandRecordStore {
    // session_id → ring
    sessions: Arc<RwLock<HashMap<String, SessionRing>>>,
}

struct SessionRing {
    buffer: RingBuffer,              // 기존 RingBuffer 재사용
    pending_start: Option<StartEvt>, // hook mode의 started→finished 매칭용
}

impl CommandRecordStore {
    // PTY path — boundary detector가 record를 만들었을 때
    pub async fn push_pty(&self, session_id: &str, record: CommandRecord);

    // Hook path — 기존 on_started/on_finished를 유지
    pub async fn on_started(&self, session_id: &str, command_id: &str, ...);
    pub async fn on_finished(&self, session_id: &str, command_id: &str, ...);

    // Explicit capture — aic run --의 결과
    pub async fn push_explicit(&self, session_id: &str, record: CommandRecord);

    // 조회
    pub async fn last(&self, session_id: &str) -> Option<CommandRecord>;
    pub async fn recent(&self, session_id: &str, count: usize) -> Vec<CommandRecord>;
    pub async fn find_by_prefix(&self, session_id: &str, prefix: &str) -> Vec<CommandRecord>;
}
```

`CommandRecord.capture_mode`는 이미 `Pty | Hook | ExplicitCapture`로 모델링돼 있어서 그대로 쓸 수 있다.

### 4.3 Data stream IPC

`aic-session`이 PTY reader에서 읽은 raw bytes를 `aicd`로 보낼 경로가 필요하다. Control UDS로 보내면 요청/응답 모델과 섞여서 지저분해지므로, `aicd`에 별도 **attach stream UDS**를 연다.

```
aicd attach socket: $XDG_RUNTIME_DIR/aic/aicd-attach.sock   (또는 /tmp/aic-{uid}/aicd-attach.sock)
```

프로토콜:

```
client→server:
  AttachOpen { session_id }         // 연결 직후 한 번
  PtyBytes { bytes: Bytes }          // N번 반복
  AttachClose { reason }             // 명시 종료

server→client:
  AttachAck { protocol_version }
  Error { message }
```

프레이밍은 기존 `encode_frame`(length-prefixed)을 재사용한다. `PtyBytes`만 전용 path로 빠질 가능성이 있으면 future RFC에서 `SCM_RIGHTS`로 shared pipe 전달로 대체할 수 있게 protocol version을 둔다.

성능:
- PTY output은 초당 많아야 수 MB 수준. length-prefixed JSON은 binary bytes 전달에 비효율적이므로, `PtyBytes` variant만 **raw length-prefixed binary**로 인코딩한다(enum discriminant 1 byte + length 4 bytes + bytes). 이는 현재 IPC 모듈에 작은 helper를 추가하면 해결된다.

### 4.4 Control IPC 확장

기존 `IpcRequest`에서 `aicd control` 소켓이 처리하는 요청에 record 조회 계열을 정식화한다.

신규 variant (aicd에서만 처리):

```
GetLastCommand { session_id }
GetRecentLines { session_id, count }
GetRecentCommands { session_id, count }
FindRecordByPrefix { session_id, prefix }
```

기존 `IpcRequest::GetLastCommand` (session_id 없음)는 다음 정책을 적용한다.

- `aic-session` 소켓에 오면: 세션 local ring buffer를 그대로 반환 (현재 동작, legacy)
- `aicd` 소켓에 오면: graceful `Error` 유지 — client가 반드시 session_id를 넣도록 요구

client 라우팅은 기존 `GetLastCommandForSession` 경로를 그대로 따른다. 즉 client는 다음 우선순위로 시도한다.

1. `--session <id>` 또는 `AIC_SESSION_ID` → `aicd.GetLastCommand { session_id }`
2. (legacy) session socket에 `GetLastCommand` (마이그레이션 기간 fallback)
3. history fallback

### 4.5 `aic-session` 내부 변경

현재 `session_runtime::run`의 task 구성 중 다음이 바뀐다.

```
[현재]
PTY reader → OutputProcessor → stdout (passthrough)
                              → BoundaryDetector → RingBuffer
UDS server ← client IPC

[RFC 적용 후]
PTY reader → aicd attach stream (raw bytes)
          ↘  stdout (passthrough, tee)
UDS server는 Ping만 처리 (또는 제거하고 aicd로 완전 이관)
```

즉 `aic-session`은 다음을 **소유하지 않는다**.

- RingBuffer
- OutputProcessor
- BoundaryDetector

`stdout` passthrough는 local에서 해야 한다(latency + correctness). `aicd`에는 순수 bytes만 보내고 `aicd` 안에서 OutputProcessor + BoundaryDetector가 다시 bytes를 읽는다.

## 5. 마이그레이션 경계

|항목|이동 전 (현재)|이동 후|
|---|---|---|
|RingBuffer|aic-session local|aicd CommandRecordStore|
|OutputProcessor|aic-session local|aicd, session별 instance|
|BoundaryDetector|aic-session local|aicd, session별 instance|
|PTY spawn/owner|aic-session|aic-session (유지)|
|PTY stdin relay|aic-session|aic-session (유지)|
|PTY stdout passthrough|aic-session|aic-session (유지)|
|PTY bytes → processing|aic-session local|aic-session이 aicd로 stream|
|IPC: GetLastCommand|session socket|aicd control (session_id 필수)|
|IPC: GetRecentLines/Commands|session socket|aicd control|
|IPC: RegisterRecord|session socket (hook fallback)|aicd control|
|IPC: Ping|session socket (liveness)|session socket 유지|

## 6. 단계적 도입

Feature flag: `AIC_CENTRAL_STORE=1` (env) 또는 `[daemon] central_store = true` (config).

### Phase 3.1 — Store 승격과 이중 쓰기

- `HookEventStore` → `CommandRecordStore`로 rename
- PTY record도 push할 수 있게 `push_pty` 추가
- `aic-session`은 기존대로 local ring buffer에 push하면서, **추가로** aicd에 `RegisterRecord { session_id, record }`를 보낸다 (dual-write)
- client는 기존대로 session socket에서 읽는다
- 이 단계에서는 aicd는 관측용으로만 record를 쌓는다

검증:
- `aic history` (신규, 이 단계에서 aicd store만 읽는 read-only CLI로 먼저 출시)
- 두 store의 결과가 일치하는지 integration test

### Phase 3.2 — Read path 전환

- client의 default flow를 aicd store first, session socket fallback으로 바꾼다
- `aic --session <id>`는 이미 aicd 경로를 우선하므로 default flow만 바꾸면 됨
- 이 단계에서 session socket은 여전히 동작한다

검증:
- aicd down 상황에서 기존 session socket fallback이 동작하는지
- multi-session integration test

### Phase 3.3 — Data stream IPC 도입

- aicd에 attach stream UDS 추가
- aic-session에 `AIC_CENTRAL_STORE=1`일 때 PTY reader → attach stream으로 보내는 경로를 추가
- aicd는 session별 OutputProcessor/BoundaryDetector를 돌리고 CommandRecordStore에 push
- 이 단계에서 aic-session은 여전히 local processing도 유지 (dual-processing)
- 두 경로 결과가 같은지 shadow test

### Phase 3.4 — Aic-session local processing 제거

- `AIC_CENTRAL_STORE=1` 기본값 on
- aic-session의 OutputProcessor/BoundaryDetector/RingBuffer 제거
- uds_server를 Ping-only로 축소하거나 제거
- 관련 코드 1399 LOC 삭제

### Phase 3.5 — Legacy cleanup

- 몇 개 릴리스 후 fallback 경로 제거
- session socket은 liveness ping 전용 또는 완전 폐지

## 7. 호환성과 롤백

- Phase 3.1~3.3은 dual-write/dual-read로 동작하므로 각 단계에서 `AIC_CENTRAL_STORE=0`으로 즉시 롤백 가능.
- Phase 3.4 이후 기존 client가 새 aicd에 붙을 때: `GetLastCommand` (session_id 없음)는 graceful error를 반환하므로 client가 업그레이드되지 않았다면 history fallback으로 빠진다. 조용히 깨지지 않는다.
- config migration은 없다. 기존 `config.toml`은 그대로 동작한다.

## 8. 장애 시나리오

### 8.1 aicd down + `AIC_CENTRAL_STORE=1`

- aic-session은 attach stream UDS 연결이 실패한다.
- 정책 후보:
  - A. aic-session이 aicd를 best-effort autostart한다 (기존 register path와 동일).
  - B. 실패하면 **local fallback**: 예전처럼 local RingBuffer에 push하고 session socket으로 내놓는다.
- 권장: **B**. aicd가 죽었다고 사용자의 셸이 degraded 상태로 빠지는 건 위험하다. local fallback을 유지하면 aicd는 optional dependency로 남는다.

### 8.2 attach stream backpressure

- aicd가 느려서 `PtyBytes` 쓰기가 블록되면 PTY read가 밀린다.
- 해결: aic-session → aicd는 **bounded async channel** 뒤에 두고, channel 가득 차면 해당 chunk는 drop하고 `dropped_bytes` counter를 올린다. passthrough stdout은 영향받지 않는다.
- record 유실 가능성이 생기지만 셸 체감은 유지된다. metric으로 관찰한다.

### 8.3 aic-session crash 중 진행 중 command

- 이미 aicd에 push된 record는 남는다.
- started만 보낸 hook record는 기존 `pending_start` timeout 정책으로 abandoned 처리.
- PTY 경로는 boundary가 완성되지 않으면 record가 만들어지지 않는다 (현재와 동일).

## 9. 테스트

### Unit
- `CommandRecordStore.push_pty/on_started/on_finished`의 concurrent 접근 invariant
- attach stream frame encoding/decoding roundtrip (binary path 포함)
- dual-write mode의 local vs aicd result 동등성

### Integration
- `AIC_CENTRAL_STORE=0/1` 두 설정에서 기존 `aic-server/tests/*`가 모두 통과
- aicd down + central_store on → local fallback 동작
- multi-session: 두 터미널에서 각각 fail, `aic --session <other-id>`로 조회

### Property
- attach stream을 통해 들어오는 임의 byte 시퀀스에 대해 OutputProcessor + BoundaryDetector 결과가 **local 처리 결과와 동일**해야 한다 (shadow test)

### Manual
- macOS zsh, Linux bash
- `vim` 진입/종료 (alternate screen 영향 없어야 함)
- 10개 터미널 동시 운영 시 aicd 메모리 증가율 측정

## 10. 성능 예측

현재:
- aic-session 프로세스당 RSS 기준 약 ~8-12MB (tokio runtime + RingBuffer 500 × 2KB + 기타)
- 10개 터미널 = 80~120MB

RFC 적용 후:
- aic-session: raw byte relay만 하므로 ~3-5MB로 예상 (tokio runtime 축소 여지 있음)
- aicd: session당 RingBuffer 500 × 2KB ≈ 1MB, 10 sessions = 10MB + daemon 자체 ~8MB
- 10개 터미널 총합: **~40~60MB** (약 50% 감소 예상)

실측 검증은 Phase 3.4 이후.

## 11. 리스크

- **가장 큰 리스크**: `aic-session` 프로세스 bytes relay가 현재 local OutputProcessor/BoundaryDetector 조합과 **1 byte도 다르지 않은** 입력을 aicd에 전달해야 한다. 중간에 buffering 경계가 달라지면 boundary detector의 상태가 갈린다. Phase 3.3의 shadow test로 pick-up.
- aicd가 user experience의 단일 장애점으로 격상된다. 8.1의 local fallback 정책이 필수.
- attach stream UDS를 추가해서 daemon의 connection 수가 선형 증가한다. tokio로 감당 가능한 범위지만 max connection 제한과 stale 감지가 필요.
- `AIC_CENTRAL_STORE` flag를 두 단계(3.1~3.3, 3.4~) 관리해야 해서 test matrix가 커진다.

## 12. 대안

### 12.1 aic-session을 그대로 두고 aicd에 duplicate store만 둔다

- 장점: 구현 최소.
- 단점: 중복 메모리 문제가 해결되지 않는다. 본 RFC의 core 목적 실패.
- 판단: 기각.

### 12.2 PTY ownership도 aicd로 옮긴다 (PRD-AICD-SUPERVISOR 원안)

- 장점: aic-session을 거의 제거할 수 있다.
- 단점: `SCM_RIGHTS`/controlling terminal/raw mode 복원 리스크가 크다. macOS/Linux 차이.
- 판단: 별도 RFC. 본 RFC는 **data plane만** 먼저 옮겨서 낮은 리스크로 큰 이익을 얻는다.

### 12.3 shared memory + atomic queue

- 장점: IPC 오버헤드 최소.
- 단점: Rust ergonomics, cross-platform, crash recovery 복잡도.
- 판단: 필요하면 Phase 4 이후 최적화.

## 13. 열린 질문

- Phase 3.1의 dual-write에서 session socket과 aicd가 같은 record의 `timestamp`를 갖게 하려면 `aic-session`이 push 전에 timestamp를 찍고 둘 다에 같은 object를 보내야 한다. 이 경우 `CommandRecord`의 `id` 필드를 명시적으로 추가할 필요가 있는가?
- `AIC_CENTRAL_STORE` 기본값을 언제 on으로 바꿀지. 릴리스 노트 2~3개 뒤가 적절해 보임.
- attach stream UDS의 권한은 control UDS와 같은 0700 디렉토리로 충분한가, 아니면 peer credential 검증을 매 frame마다 해야 하는가? (연결 시점 한 번으로 충분하다고 봄)
- `aic-session`의 `--no-hook` flag와 central store의 관계. hook 없이도 central store로 PTY record가 흘러가야 하므로 두 flag는 직교.
- `aic history --limit 100`이 aicd 재시작을 넘어서도 동작해야 하는가? In-memory만으로는 안 된다. 이 RFC는 "그대로 유실" 정책을 유지하되, 후속 RFC에서 persistent store를 검토.

## 14. Decision Draft

이 RFC를 채택하면 Phase 3.1부터 순차 진행한다. 각 Phase는 독립 PR이며, feature flag로 롤백 가능하다. Phase 3.4 이전까지는 기존 UX와 성능이 동일하고, 3.4에서 비로소 목표 이득(메모리 50% 감소, code 1400 LOC 제거)이 실현된다.

Phase 3.5는 fallback을 걷어내는 단계로, 최소 3개 마이너 릴리스 이후에 진행한다.

## 15. 다음 액션

1. 이 RFC를 리뷰 받고 scope 합의 (특히 8.1 local fallback 정책).
2. Phase 3.1 skeleton PR:
   - `HookEventStore` → `CommandRecordStore` rename
   - `push_pty` API 추가
   - `aic-session`에 dual-write (feature flag 뒤)
   - `aic history` read-only CLI 추가 (aicd store만 조회)
3. Phase 3.1 release 후 shadow data 수집, 문제 없으면 3.2.

