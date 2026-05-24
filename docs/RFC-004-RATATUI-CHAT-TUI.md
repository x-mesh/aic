# RFC-004: ratatui chat TUI — 하단 고정 status bar

> `aic chat`을 reedline 라인 모드에서 ratatui Inline TUI로 전환해, **타이핑 중에도 흐르는 하단 고정
> status bar**(load/cpu/mem/disk-i/o)를 구현한다. 0.9.0의 "입력경계 + spinner 구간 갱신"의 후속(장기안).
> 배경: `/xm:op investigate | debate` (`.xm/op/investigate-2026-05-24-statusbar-metrics.json`,
> `.xm/op/debate-2026-05-24-statusbar-ratatui.json`), memory `project-aic-statusbar-trend`.

## 동기

0.9.0의 status bar는 reedline이 `read_line()` 중 raw mode를 **독점**해, 입력 직전과 LLM 대기(spinner)
구간에만 갱신된다(타이핑 중은 정적). 사용자가 화면 하단 고정 + 상시 흐름을 원함(debate에서 "실측으로
필요해질 때 재평가" 조건 충족). 하단 고정은 reedline 폐기 → 단일 화면 소유자(ratatui)가 필요하다.

## 확정 설계 (조사 기반)

| 결정 | 선택 | 근거 |
|------|------|------|
| Viewport | **`Viewport::Inline(N)` + `Terminal::insert_before`** (AlternateScreen ❌) | 로그를 `insert_before`로 출력하면 터미널 **scrollback에 자동 보존**. 뷰포트는 status bar + 입력만 고정 → 자체 로그 위젯 불필요 |
| 입력 위젯 | **`tui-textarea = "0.7"` 채택 확정** (crossterm 0.28 단일 — 중복 없음) | **CJK PoC 통과(2026-05-24, `aic-client/tests/cjk_poc.rs`)**: char 단위 편집·렌더 display width(가=cell0/나=cell2)·혼용 backspace 모두 정확. 조사의 "커서 픽스 미확인" 우려 실측 해소 |
| async 루프 | `crossterm::event::EventStream` + `tokio::select!`(키 vs 2초 status tick) | crossterm `event-stream` feature 추가 |
| slash popup | `Clear` + `List` + 입력창 위 Rect 계산 (ColumnarMenu 대체) | ratatui 전용 popup 위젯 없음; 단일 컬럼으로 충분 |

핵심 단순화: **Inline viewport이면 대화 로그 관리가 단순**(insert_before로 밀어올림 → 터미널이 스크롤),
top.rs식 자체 스크롤 로그 위젯이 불필요하다.

### 레이아웃
```
[scrollback ↑ : 이전 대화 — insert_before 출력]
─────────────────────────────────
· load·cpu·mem·io          ← status bar (Inline viewport, 고정)
◇ you ❯ 입력...            ← 입력
    [/local /diagnose ...]  ← slash popup (Clear+List overlay, 조건부)
```

## 대체 대상 — reedline 4기능 (repl.rs)

| 기능 | 현재 | 대체 |
|------|------|------|
| CJK 라인 편집 | reedline + `split_at_width`(repl.rs:484) | tui-textarea or 직접 |
| FileBackedHistory + FilteredHistory | repl.rs:329-380 | Vec+파일, FilteredHistory 로직 재사용 |
| SlashCompleter + ColumnarMenu | repl.rs:182-216 | `slash_completion_entries` + List popup |
| 키바인딩(Tab//Enter) | repl.rs:293-326 | crossterm KeyEvent 직접 매칭 |

## 단계

1. ~~**CJK PoC**~~ ✅ **통과** (`aic-client/tests/cjk_poc.rs`, 2026-05-24) — tui-textarea 0.7 한글 정확. go.
2. ~~`chat_tui.rs` 골격~~ ✅ (2026-05-24, 5bb16eb) — Inline viewport + **동기 `event::poll` 루프**(top.rs 패턴, EventStream 불필요) + `draw_viewport`(status bar dim / prompt+tui-textarea) TestBackend 검증. status 흐름·**하단 고정(단계 3)도 골격에 포함**. `read_line_tui`는 미연결(mod allow dead_code).
3. ~~status bar 하단 고정~~ ✅ (단계 2 골격에 흡수 — Inline viewport 상단 1줄 dim).
4. **LLM 호출 통합 (현재 진행 — insert_before 채택 확정 2026-05-24)** — 아래 [§단계 4 상세 설계](#단계-4-상세-설계-insert_before-채택) 참조. `read_line_tui`(매번 terminal 생성)를 폐기하고 **terminal 보관 `ChatTui` + 전체 루프 소유**로 재설계, 답변/spinner/tool 카드를 `insert_before`로 일원화. **실제 터미널 검증 필수**(자동 테스트는 ANSI→Text·height 변환만 커버).
5. history 이식(FilteredHistory 재사용).
6. slash popup(Clear+List).
7. non-TTY fallback 유지(기존 stdin read_line) + 테스트.

## 리스크

| 리스크 | 완화 |
|--------|------|
| CJK 커서(회귀 1순위) | 단계 1 PoC 선제 검증 |
| LLM 출력 경로 대수술(stdout→insert_before) | 점진적, 스트리밍 줄단위 |
| Inline resize 이슈(ratatui #2086) | resize 시 redraw, best-effort |
| non-TTY/파이프 | 기존 read_line fallback 유지(전환은 TTY만) |

## 비전환 결정 (debate)

reedline을 당장 버리는 게 아니라, **CJK PoC 통과**를 게이트로 둔다. PoC 실패 시 직접 입력 위젯(중간 비용)
또는 전환 보류. 0.9.0의 입력경계/spinner 갱신은 fallback으로 유지 가능.

---

## 단계 4 상세 설계 (insert_before + 단일 이벤트 루프)

> 사용자 결정(2026-05-24): suspend/resume(소수술) 대신 **insert_before(대수술)**. status bar가
> **항상 화면 맨 아래 영구 고정**되고, 답변·tool 카드·spinner가 그 위로 흐르는 "진짜 chat TUI".
> **critic 검증(2026-05-24) 반영 개정**: 초안의 `Arc<Mutex<Terminal>>` 3주체 공유 + `Rc<RefCell>` sink는
> (a) `Rc<RefCell>`이 `!Send`라 multi_thread runtime에서 `run()` future Send 위반으로 **컴파일 불가**(B1),
> (b) 입력 draw·spinner draw·insert_before가 같은 lock을 다퉈 status bar 잔상/깨짐(B2)이었다.
> → **terminal을 단일 task가 단독 소유 + `mpsc` 채널 통신**으로 재설계해 Arc/Mutex/Rc를 전부 제거한다.

### 검증된 기술 사실 (선제 확인 완료)

| 항목 | 사실 | 출처 |
|------|------|------|
| ANSI→ratatui 변환 | `ansi-to-tui = "7.0.0"` (`ratatui ^0.29` 의존 — 우리 버전 정합, 충돌 0) | crates.io deps. **8.x는 `ratatui-core 0.1`(0.30+)이라 금지** |
| 출력 API | `terminal.insert_before(height: u16, draw_fn: impl FnOnce(&mut Buffer))` | ratatui 0.29 `terminal.rs:579` — **height(줄 수) 사전 계산 필요** |
| 입력 위젯 | tui-textarea 0.7 (CJK PoC 통과) | 단계 1 |
| width 계산 재료 | `unicode-width = "0.2"` 이미 존재, `split_at_width`(repl.rs:484~526)가 cell-width wrap | Cargo.toml |
| runtime | `main.rs`는 `#[tokio::main]`(기본 **multi_thread**) + `session.run().await`(spawn 없음) → **run() future는 Send 필수** | main.rs:596,4572 |
| async 입력 | crossterm `EventStream` + `tokio::select!`(확정설계 표) — 단계 2 동기 poll을 단계 4는 async로 | crossterm `event-stream` feature 추가 |

### 왜 대수술인가 (영향 범위 정량)

현재 화면 출력은 **stdout=답변 / stderr=UI**로 분리된 line-based 설계(`ui.rs:2-6`)이고 **ANSI escape 범벅**
(`print_with_border`=`\x1b[34m▐`, `print_think_summary`=`\x1b[90m`, markdown 렌더, `paint`, spinner).
ratatui viewport는 단일 백엔드가 화면을 점유하므로, **TTY 경로의 모든 화면 출력이 `insert_before`(=ANSI→Text
변환)를 거쳐야** 한다. 직접 print는 viewport를 깨뜨린다.

- `session.rs`: `println!` 54(답변) + `eprintln!` 53 + `eprint!` 3 = **약 110곳**
- `run_command.rs`: `card_line`/`print_command_card` 등 카드 출력(단 `detail_cards_enabled`=AIC_DEBUG/VERBOSE일 때만)
- `repl.rs`: `print_with_border`/`print_think_summary`(답변 렌더 헬퍼)
- `spinner.rs`: stderr `\r` 애니메이션 — **viewport와 직접 충돌**
- `session.rs:596` `collect_local_snapshot` 진행표시 `eprint!("\r\x1b[K…")` — **기본 활성**이라 카드보다 우선 우회 필요(m6)

### 컴포넌트 구조 — 단일 소유자 + 채널

terminal을 만지는 주체는 **`ChatLoop` task 하나뿐**. session은 terminal을 모르고 채널 핸들(`Send`)만 든다.

```
ChatLoop  (별도 task — terminal 단독 소유, Arc/Mutex/Rc 없음)
├─ terminal: Terminal<CrosstermBackend<Stdout>>      // 이 task만 소유
├─ textarea: TextArea<'static>, status: String, sampler, spin: Option<SpinState>
├─ events:   EventStream                              // crossterm async 키 이벤트
└─ select! 루프:
     ├─ key  = events.next()      → textarea 편집; Enter→ line_tx.send(Line); Ctrl+D/C→ line_tx.send(Eof)
     ├─ _    = tick(200ms)        → sampler 갱신 + viewport redraw(status + (spin? thinking : textarea))
     └─ msg  = out_rx.recv()      → Answer/Note(ansi) = insert_before_ansi; SpinStart/Stop = spin 토글; Shutdown=break

채널 (session ↔ ChatLoop, 둘 다 Send):
  line_tx:  mpsc::Sender<ChatLine>        ChatLoop → session  (입력 줄/EOF)
  out_tx:   mpsc::Sender<OutMsg>          session → ChatLoop  (출력/스핀/종료)
  enum OutMsg { Answer(String), Note(String), SpinStart(String), SpinStop, Shutdown }

ChatOut  (session 출력 sink — 110곳을 의미 단위 2개로 우회, 모두 Send)
├─ Direct                         // non-TTY: 기존 stdout(답변)/stderr(UI) 분리 byte-identical
└─ Tui(mpsc::Sender<OutMsg>)
   ├─ answer(ansi)  → out_tx.send(Answer)   // Direct→stdout println
   └─ note(ansi)    → out_tx.send(Note)     // Direct→stderr eprintln
```

핵심: spinner는 **spawn하지 않는다**. `SpinStart`/`SpinStop`은 ChatLoop의 `spin` 플래그만 토글하고, 흐르는
애니메이션은 **tick arm이 viewport에 그린다**(scrollback 도배 0, lock 0). LLM `send_messages().await` 동안
status가 흐르는 요구는, ChatLoop의 tick이 독립적으로 계속 도는 것으로 충족된다(메인 await와 무관). 기존 stderr
`\r` spinner는 **Direct(non-Tui) 전용**으로 격리한다.

### 동작 시퀀스 (한 턴)

```
ChatLoop task: 시작과 함께 select! 루프 진입(terminal 단독 소유, 종료까지 유지).
session.run (메인, future=Send):
  1. line = line_rx.recv().await          // ChatLoop가 Enter로 보낸 입력(타이핑 중 status는 tick이 이미 흐름)
  2. out_tx.send(SpinStart("thinking"))    // ChatLoop tick이 viewport에 thinking 흐름
  3. resp = dispatcher.send_messages().await
  4. out_tx.send(SpinStop)
  5. out_tx.send(Answer(rendered))         // ChatLoop가 insert_before_ansi로 viewport 위에 쌓음
  6. → 1 반복.   종료 시 out_tx.send(Shutdown) → ChatLoop가 raw 복원 후 종료.
```

데드락 불가: terminal 소유자가 1개라 lock이 없다. 입력 줄 echo(`❯ you: …`)도 ChatLoop가 Enter 처리 시
`insert_before_ansi`로 직접 남긴다(session 왕복 불필요).

### height 계산 — 단일 함수 강제 (M1)

`insert_before(height, …)`의 height 오차 = 화면 깨짐. **answer/note/echo가 모두 같은 함수**를 통과한다:
`ansi_block_height(ansi: &str, width: u16) -> (Text, u16)` — ① ansi-to-tui로 `Text` 생성 → ② 각 line을
`width`(=`render_width` clamp[40,100] **하나로 통일**, `term_width-3` 혼용 금지)로 cell-width wrap →
③ 최종 line 수 반환. 4a 단위테스트 **고정 입력**: tab(`\t`), 빈 줄, trailing newline(`"a\n"` off-by-one),
CJK+ASCII 혼용 wrap 경계, wide char가 경계에 정확히 걸치는 케이스, 잔존 `\r`/`\x1b[K`.

### println→answer/note 매핑 + Direct byte-identical 게이트 (M3)

"의미 단위 우회"는 byte 동일을 자동 보장하지 않는다(`render`는 think요약+border 2종을 stdout에 냄).
4d 착수 전 **매핑 표**(각 print 지점 → answer|note, 스트림·ANSI·개행 보존) 작성, Direct 경로는 **전환 전
golden 스냅샷(stdout/stderr 각각) → 전환 후 byte diff=0**을 4d/4f 게이트로 명문화.

### sub-step 분해 (재정렬 — spinner는 4d 흡수)

| # | 범위 | 검증 |
|---|------|------|
| ~~**4a**~~ ✅ | `ansi-to-tui 7` + ratatui `unstable-rendered-line-info` feature + `ansi_to_paragraph`(=height 단일 계산, `Paragraph::line_count` 사용)/`insert_before_ansi` 헬퍼 (`chat_tui.rs`, 2026-05-24) | ✅ 단위테스트 7개 통과: tab·빈줄·**trailing nl=off-by-one 고정("a\n"=1줄)**·CJK cell-width wrap 경계·색(Blue) 보존·insert_before TestBackend. crossterm `event-stream`은 실사용하는 4b로 이연 |
| **4b** | `ChatLoop` task(terminal 단독 소유) + `EventStream` select! 루프 + `line_tx`/`out_rx` 채널 + 입력 echo + `Drop`/패닉훅(raw 복원) | 수동 실터미널(한글 입력·echo·tick 흐름) |
| **4c** | `OutMsg::Spin*` tick 렌더(별도 task 아님) — 4b 루프에 통합 | 4b와 함께(LLM 없이 SpinStart→tick 흐름 확인) |
| **4d** | `ChatOut` sink + `session.run`을 채널 모델로(`line_rx`/`out_tx`) + `render()`→`answer`. non-TTY=Direct fallback | **golden byte-diff=0** + 수동 |
| **4e** | slash 출력(`note`) + `collect_local_snapshot` 진행표시(`\r`, 기본활성·우선) 이전. run_command 카드는 verbose-only라 보류 가능 | 수동(/local·/diagnose) |
| **4f** | 통합 검증 체크리스트 | 한글·긴 답변 wrap·resize(#2086)·Ctrl+C·패닉 복원·파이프 fallback byte-diff=0 |

### 추가 리스크 (단계 4 한정)

| 리스크 | 완화 |
|--------|------|
| ~~Arc<Mutex<Terminal>> 경합~~ | **단일 소유자 + 채널로 구조적 제거**(critic B1/B2) — lock 없음 |
| height 계산 오차 → 출력 잘림/겹침 | `ansi_block_height` 단일 함수 + 고정 입력 단위테스트(M1) |
| Direct byte 회귀 | 매핑 표 + golden byte-diff=0 게이트(M3) |
| insert_before 잦으면 깜빡임/비용 | 답변 1회 batch(비스트리밍 — 현재 `ChatResponse::Text` 1회). 스트리밍 도입 시 **완성 줄만** insert_before(부분 줄 height 불확정, 미래 노트 m4) |
| raw mode 잔존(에러/패닉) | `Drop` + `std::panic::set_hook`로 `disable_raw_mode` 보장(m5) |
| run_command 카드(별도 모듈) | verbose-only라 기본 무출력 → 보류 안전. 단 `collect`의 `\r` 진행표시는 4e에서 반드시 우회(m6) |
| non-TTY/CI 회귀 | `ChatOut::Direct` byte-identical — golden/파이프 테스트로 고정 |
