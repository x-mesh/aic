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
4. **LLM 호출 통합 (다음, 대수술)** — `read_line_tui`(매번 terminal 생성)는 LLM 로그 `insert_before`와 안 맞음 → **terminal 보관 `ChatTui` struct + 전체 루프 소유**로 재설계 필요. session.run의 `reader.read` 루프를 TTY면 ChatTui로 교체, 답변/spinner/tool 카드를 stdout `println` → `insert_before`. **실제 터미널 검증 필수**(자동 테스트 불가).
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
