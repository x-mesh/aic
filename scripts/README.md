# scripts/

본 디렉토리는 `aic-rust` 운영 및 성능 계측에 쓰이는 bash helper 스크립트를
모아 둔다.

## RSS 측정 — Phase 3.4 목표치 검증

centralized-record-store spec ([tasks.md](../.kiro/specs/centralized-record-store/tasks.md),
Task 4.5) 의 R6.5 / R6.6 목표를 수동으로 검증하기 위한 harness.

### 파일

| 파일 | 역할 |
|---|---|
| `measure-rss-phase34.sh` | 현재 돌고 있는 `aic-session` 및 `aicd` 프로세스의 RSS(KB) 를 모아 JSON 리포트 생성. 옵션 `--phase`, `--single`, `--processes`, `--wait`, `--output`. |
| `measure-rss-phase30.sh` | 위 스크립트를 `--phase 3_0` 으로 호출하는 얇은 wrapper. Phase 3.0 baseline 수집 용도. |
| `spawn-aic-sessions.sh` | tmux 기반 N-세션 런처. `--with-aicd` 시 aicd 도 같은 tmux session 의 window 0 에 기동하고 attach socket ready 를 대기한다 (race 방지). |
| `pkill-aic.sh` | 상태 확인 + SIGTERM → (필요 시) SIGKILL. 측정 사이클 전환용. |
| `verify-attach.sh` | 세션 10 개가 모두 aicd Attach_UDS 에 연결되어 있는지, reconnect=0 인지 점검. Local Fallback 발생 여부의 판정 기준. |
| `aicd-metrics.sh` | aicd Control_UDS 에 `GetMetrics` 를 직접 찌르고 `attach_connections`/`central_store_push_total`/`dropped_bytes` 등을 프린트. |
| `compare-rss.sh` | 두 JSON 비교 + R6.5 / R6.6 자동 판정. |

### 실행 전 준비

1. 비교하려는 빌드(Phase 3.0 또는 Phase 3.4)의 `aicd` 와 `aic-session` 이
   이미 기동돼 있어야 한다. Phase 3.4 측정 시에는 `AIC_CENTRAL_STORE=1`
   환경에서 `aicd` 가 실행 중이어야 R6.5 시나리오가 성립한다.
2. multi 시나리오(R6.5)는 **10 개 aic-session** 을 동시에 띄워 둔 상태를
   가정한다. iTerm/tmux 등에서 10개 창을 연 뒤 각각 `aic` 를 한 번씩 호출해
   PTY child(zsh/bash) 를 붙이고, 원한다면 세션당 몇 개 명령을 실행해 5s 정도
   워밍업 후 본 스크립트를 실행한다. TTY가 없는 bash 스크립트에서 직접
   `aic-session` 을 띄우기는 어렵기 때문에 이 수동 준비 단계는 필수.
3. steady-state 대기는 스크립트 내부에서 기본 30s (변경: `--wait N`).

### 실행

```bash
# Phase 3.4 빌드 실행 상태에서 multi 시나리오 (R6.5)
AIC_CENTRAL_STORE=1 scripts/measure-rss-phase34.sh --phase 3_4 --processes 10

# 단일 프로세스 steady-state RSS (R6.6 비교용)
AIC_CENTRAL_STORE=1 scripts/measure-rss-phase34.sh --phase 3_4 --single

# Phase 3.0 빌드 상태에서 baseline — 별도 체크아웃/빌드 필요
scripts/measure-rss-phase30.sh --processes 10
scripts/measure-rss-phase30.sh --single
```

결과는 `target/phase-${PHASE}-rss.json` 에 저장된다. `--output` 으로 경로를
재지정할 수 있다.

### 출력 JSON 스키마

```jsonc
{
  "phase": "3_4",                 // --phase 값
  "mode": "multi",                // "multi" 또는 "single"
  "timestamp": "2026-05-10T02:15:00Z",
  "hostname": "laptop.local",
  "uname": "Darwin laptop.local 23.4.0 ...",
  "expected_sessions": 10,        // --processes
  "actual_sessions": 10,          // pgrep 결과
  "actual_aicd": 1,
  "wait_seconds": 30,
  "aic_session_processes": [
    { "pid": 12345, "rss_kb": 1800, "command": "aic-session" }
  ],
  "aicd_processes": [
    { "pid": 10001, "rss_kb": 22000, "command": "aicd" }
  ],
  "total_aic_session_rss_kb": 18000,
  "total_aicd_rss_kb":        22000,
  "total_rss_kb":             40000,
  "total_rss_mb":             "39.06",
  "interpretation": {
    "R6_5_range_mb": "40-60",
    "R6_5_pass": true,
    "R6_6_note": "Run twice (--phase 3_0 and --phase 3_4) and compare aic_session RSS; target is >=60% reduction."
  }
}
```

### 해석 기준 (2026-05 실측 반영)

당초 spec 의 "total 40~60 MB / session -60%" 는 Rust release 바이너리의 공유 라이브러리 + tokio runtime 고정 비용을 간과한 비현실적 수치임이 실측으로 밝혀졌다 (각 세션 RSS 의 절대다수가 이 고정 비용이고, `RingBuffer`/`OutputProcessor`/`BoundaryDetector` 제거의 실효 절감은 per-session ~200KB). 2026-05 requirements.md R6 AC5/AC6 을 아래 기준으로 현실화했다.

- **R6.5 (회귀 방지)**: Phase 3.4 total RSS 가 Phase 3.0 baseline 대비 **증가하지 않는다**. `compare-rss.sh` 가 `baseline_total vs target_total` 을 비교해 판정. 자동 판정 결과는 JSON 의 `interpretation.R6_5_pass` (현재는 absolute range 기준) 와 compare 스크립트 출력을 함께 본다.
- **R6.6 (구조적 검증)**: N 개 세션이 모두 aicd Attach_UDS 에 연결되어 있고 (attach_connections=N, reconnect_total=0), 세션 프로세스가 로컬 data plane (RingBuffer/OutputProcessor/BoundaryDetector) 을 생성하지 않는다. `verify-attach.sh` 가 각 세션 socket 에 대해 `reconnects` 를 집계해 판정.
- **R6.7 (구조적 이득)**: CPU 중복 제거, record durability, cross-session query, 단일 observability snapshot — 실측은 별도 검증이 필요하나 설계 의도는 그대로 유지된다 (requirements.md R6.7 참조).

### 측정 사이클 전체 흐름

```bash
# ── Phase 3.0 baseline ──────────────────────
scripts/pkill-aic.sh
scripts/spawn-aic-sessions.sh --phase 3_0 --with-aicd
sleep 5
scripts/measure-rss-phase30.sh --processes 10

# ── Phase 3.4 target ────────────────────────
scripts/pkill-aic.sh
tmux kill-session -t rss-3_0 2>/dev/null
scripts/spawn-aic-sessions.sh --phase 3_4 --with-aicd
sleep 5
scripts/verify-attach.sh --phase 3_4 --expected 10   # ✓ 확인 필수
scripts/aicd-metrics.sh                                # 선택 — 진짜 attach 수치
scripts/measure-rss-phase34.sh --processes 10

# ── 비교 ────────────────────────────────────
scripts/compare-rss.sh
```

### 한계

- Bash 스크립트만으로 PTY 를 가진 `aic-session` 을 자동으로 기동할 수 없다.
  따라서 N 개 프로세스 기동은 **사용자가 수동으로** 수행한다.
- `ps -o rss` 는 공유 라이브러리 페이지를 포함하므로 여러 `aic-session` 이
  같은 라이브러리를 공유하면 실제 증분 메모리보다 합계가 크게 나올 수 있다.
  RSS 기반이므로 OS 수준 비교에는 충분하지만, 정밀 분석이 필요하면
  `/proc/<pid>/smaps_rollup` (Linux) 또는 `vmmap --summary` (macOS) 을
  병행 사용한다.
- 아직 central store 모드의 PTY relay (Phase 3.3 이상) 가 aic-session RSS 를
  정확히 얼마로 끌어내릴지는 런타임 메모리 누수/캐시 정책에 따라 달라질 수
  있어, 본 스크립트는 **계측 도구**이지 정의된 PASS/FAIL 테스트가 아니다.
  목표 범위에 들지 않으면 RFC-001 및 requirements.md 의 R6.5/R6.6 과 함께
  재점검한다.

### CI 통합

본 harness 는 수동 실행 전용이다. CI에서는
`aic-server/tests/rss_measurement.rs` 의 `#[ignore] #[test]` 를 통해
스크립트가 문법적으로 파싱 가능한지만 선택적으로 검증한다.
명시적으로 돌리려면:

```bash
cargo test -p aic-server --test rss_measurement -- --ignored
```
