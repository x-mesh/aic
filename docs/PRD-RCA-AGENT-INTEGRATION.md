# PRD: rca-agent 자원 측정 연동 — 호출·측정 방법과 플랫폼 편입

> 상태: Draft — 2026-08-04
> 목적: **aic에서 rca-agent(RCA-eBPF)를 이용해 자원 정보를 호출·측정하는 방법**을 계약 수준으로 확정하고,
> rca-web까지 잇는 연동 경로를 정한다. rca-web 기능 인벤토리(§2)를 함께 실어 소비 측 설계 근거로 삼는다.
> 관련 문서: `rca-web/docs/PRD-rca-agent-kernel-evidence.md`(Draft, 같은 날 — 상시 파이프라인의 rca-web측 계획),
> `/app/integration-plan.md`(Log_parser↔rca-web↔aic 마스터플랜), RCA-eBPF `ADR-0043`(localhost snapshot API)·
> `ADR-0048`(analyzer 통합 경계), `PHASE2-RCA-PLAN.md`, `SRE-SCOPE-BOUNDARY.md`
> 관련 코드: `aic-client/src/agent/rca_agent.rs`, `aic-common/src/lib.rs`(`[rca_agent]`),
> `aic-client/src/main.rs`(`rca_collect`), `rca-web/rca-server/src/otlp/decode.rs`, `RCA-eBPF/internal/control/`
> 근거: 3개 저장소(`/app/aic`, `/app/RCA-eBPF`, `/app/rca-web`) 코드·문서 전수 조사 + 계약 사실 교차 검증 (2026-08-04 스냅샷)

---

## 0. 세 줄 요약

1. **호출·측정의 1차 경로는 이미 출하됐다** (aic e2ab3cb, Phase 1): aic가 loopback 전용으로
   rca-agent control API(`POST /collectz`, `GET /featuresz`)를 pull하는 chat 도구 2종 + `aic rca collect` CLI.
2. 이 PRD는 그 위에 **(a) aic 로컬 보강**(doctor 헬스체크, 진단 플로우 편입, 신선도 표시)과
   **(b) 상시 파이프라인**(aicd 주기 수집 → OTLP `aic.kernel.*` → rca-web)을 정의한다.
   (b)는 rca-web측 Draft PRD와 한 쌍이며, 관문은 rca-agent의 논블로킹 `GET /countersz` 수용 여부([D1])다.
3. rca-agent(OTLP **gRPC**)와 rca-web(OTLP **HTTP/protobuf** 전용)은 wire가 맞지 않아 직행 push가 불가능하다 —
   **rca-agent 데이터가 플랫폼에 도달하는 유일한 현실 경로는 aic/aicd 릴레이**다. 이 비대칭이 본 설계의 전제다.

---

## 1. 배경 — 세 시스템의 현재

### 1.1 rca-agent(RCA-eBPF) — 무엇을 측정하는가

Go 단일 바이너리, eBPF 기반 커널 신호 수집기. systemd 비root(`rca-agent` 유저 +
`CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE`)로 상주하며, **판정하지 않는 collector**다
(evidence의 `root_cause_ready`/`root_cause_decision`은 영구 false — 코드가 panic 가드로 강제,
`internal/control/evidence.go` `assertNoVerdict`).

측정 신호 카탈로그 (기본 1 + opt-in 11, 모두 config `signals.*.optin` 기본 false):

| 신호 | 측정 대상 | OTLP 메트릭 (scope `rca-agent`) | 카디널리티 비용 |
|---|---|---|---:|
| TCP RTT (기본, 상시) | smoothed RTT (fentry `tcp_rcv_established`) | `system.network.tcp.rtt` Histogram(us) | 기본 예산 |
| `capability_check` | capability 검사 실패 수 | `system.security.capability_check.fail.count` Counter | 2 |
| `process_lifecycle` | fork/exit 수 | `system.process.lifecycle.{fork,exit}.count` Counter | 4 |
| `userspace` | malloc/free/USDT retry | `system.userspace.{malloc,free}.count` 등 Counter | 6 |
| `scheduler` | runqueue 대기 지연 | `system.scheduler.runqueue.latency` Histogram(us) | 3 |
| `oom` | OOM kill 수 (+victim evidence) | `system.memory.oom_kill.count` Counter | 2 |
| `block_io` | block I/O 요청 지연 | `system.block_io.latency` Histogram(us) | 3 |
| `syscall` | read/write/openat/futex 지연 | `system.syscall.latency` Histogram(us, syscall_name attr) | 12 |
| `file_io` | vfs_read/write 지연 | `system.file_io.latency` Histogram(us) | 4 |
| `context_switch` | 문맥 전환 수 | `system.scheduler.context_switch.count` Counter | 2 |
| `tcp_servicemap` | TCP 연결 edge/방향 | `tcp.servicemap.{edges,connections}.count` | 3 |
| `network` | 송수신 관측 (evidence 전용) | 메트릭 없음 — evidence top에만 | 0 |

표기 주의: OTLP unit 문자열은 RTT만 `"us"`, 지연 계열은 `"microseconds"`(의미 동일);
`tcp.servicemap.edges.count`는 Counter가 아니라 **Gauge**다.
opt-in 합산 비용은 **14 이하**여야 시작 가능(`internal/config/config.go` 검증, 정책 총 상한 46 series/host).
신호는 **시작 시점에만** 켜진다 — control API에 toggle 라우트가 없고 SIGHUP은 클라우드 메타 갱신 전용,
변경은 config/CLI 플래그 + **재시작**이다. 기본 구성의 telemetry 출구는 OTLP **gRPC**
(기본 `127.0.0.1:4317`) 하나(그 외는 opt-in: Kafka RTT 이벤트 export, analyzer push sink).
부수 산출물: baseline SQLite(`/var/lib/rca-agent/baseline.db`, 신호별 256 window 이력),
opt-in profiling pprof 파일(`/var/lib/rca-agent/profiles/`).

### 1.2 aic — 이미 있는 것 (Phase 1, 출하됨)

`aic-client/src/agent/rca_agent.rs`의 `RcaAgentClient`:

- config `[rca_agent]` (`aic-common/src/lib.rs`): `enabled`(기본 **false**), `url`(기본 `http://127.0.0.1:9090`).
  **loopback 강제** — evidence가 PID/comm/cgroup entity를 담으므로 원격 URL은 생성 시점에 거부.
- chat 도구 2종: `rca_agent_collect`(window 측정), `rca_agent_features`(attach 상태 조회).
  응답은 obs_tools 공통 게이트(512KB bounded read → redaction → **64KB truncate**)를 거쳐 LLM에 원문 JSON 텍스트로 전달.
- CLI `aic rca collect [id] [--window 30s] [--json]`: evidence bundle을 incident에
  `EvidenceKind::Observability`로 첨부 (tags `["rca-agent","kernel"]`).
- wiremock 통합 테스트(`tests/rca_agent_integration.rs`)가 클라이언트 계약을 고정:
  `profile=incident&duration=30s`, 하한 clamp(1→5s), featuresz 필드, 비-2xx 상태·본문 노출
  (409 목 케이스는 일반 오류 처리 검증이다 — 실제 rca-agent는 409를 반환하지 않는다, §3.1).

**없는 것**: doctor 헬스체크(도구 호출 실패 시 에러 힌트가 전부), `/snapshotz`·`/healthz`·`/readyz` 활용,
`/diagnose` 편입, aicd측 클라이언트(상시 수집) — 전부 §5의 대상이다.

### 1.3 rca-web — 아직 아무것도 모른다

rca-web에는 rca-agent 관련 코드가 0건이다. scope 라우팅은 `aic.*` 9종뿐이고 커널 데이터용
scope/metric 처리는 계획 문서(Draft PRD)만 존재한다. 결정적 제약 두 가지:

- **wire 불일치**: rca-agent 출구는 gRPC, rca-web 입구는 HTTP/protobuf 전용(gRPC 미지원, `/v1/traces` 없음).
  rca-agent의 opt-in push(analyzer sink)도 evidence JSON이지 OTLP가 아니므로 직행 불가.
- **Histogram 거부**: `/v1/metrics` 디코더는 Gauge·Sum만 수용, Histogram 계열은 reject
  (`otlp/decode.rs`). rca-agent의 주력 신호(RTT·지연 계열)는 히스토그램이라 **원형 그대로는
  rca-web에 저장할 수 없다**. 상시 파이프라인이 "카운터 delta만 나른다"(§5 Lane C)는 원칙의 기술적 근거.

---

## 2. rca-web으로 할 수 있는 것들 (기능 인벤토리)

> 연동 설계의 소비 측 근거. 2026-08-04 코드 기준, 상세 file:line은 조사 기록 참조.

### 2.1 수집 (유일한 데이터 입구)

| 항목 | 내용 |
|---|---|
| 엔드포인트 | `POST /v1/metrics`, `POST /v1/logs` — 이 둘뿐 (gRPC·traces·JSON 없음) |
| 인코딩/한도 | `application/x-protobuf`만(아니면 415), body 8 MiB(초과 413), 실패 시에도 200 + `partial_success` |
| 인증 | `Authorization: Bearer <agent token>` — DB 관리, SHA-256 해시 저장, 토큰 0개면 전량 401(fail-closed) |
| scope 라우팅 | instrumentation scope name 기준 9종: `aic.events/sessions/connections/process/process.inventory/alerts/agent/changes/logs`. **미등록 scope는 200 OK로 무음 폐기**(rejected 카운트만) |
| metric 경로 | **이름 무관**(name-agnostic) — Gauge/Sum이면 어떤 metric명이든 저장. Histogram 계열은 거부 |
| 멱등 | ReplacingMergeTree + `record_id`(`aic.record.id` 또는 derived hash) — at-least-once 재전송 흡수 |
| 시각 | 수신 시각 ±24h clamp |
| 온보딩 | enrollment key(TTL 1h~30d) → `POST /api/agent-enrollments/exchange` → ingest token + LLM 설정까지 zero-config. `GET /install/aic` 원라이너 |

### 2.2 저장 (ClickHouse 전용)

16개 테이블: `hosts, metrics, metrics_1m(+MV), events, connections, alerts, rca_reports, monitors,
settings, mute_rules, maintenance_windows, incidents, changes, logs, process, process_inventory`.
TTL은 9개 테이블에 대해 `RCA_TTL_*_DAYS` env 또는 Settings UI(step-up 게이트)로 조정
(logs만 7일 하드코딩 — PHASE2 P1-2). `changes.change_type`에 `kernel` 값이 **0014부터 예약**되어
있으나 수집기 부재 — 커널 이산 이벤트의 자리가 이미 파여 있다.

### 2.3 조회 API (`/api`, 단일 admin 세션 Bearer)

- 호스트: `GET /hosts`, `/hosts/{host}` + `/events /processes /changes /connections-by-process /process-inventory /metrics`
- 메트릭: `GET /hosts/{host}/metrics?metric=&from=&to=&step=`(최대 92일, ~500 포인트 자동 step),
  `GET /metrics/catalog`(**24h 데이터 유도** — 새 metric명은 유입 즉시 자동 노출)
- 이벤트/로그: `GET /events`, `GET /logs`(파셋+히스토그램) + SSE 라이브 테일(단회용 ticket 인증)
- 토폴로지: `GET /api/topology`(연결 스냅샷 유도 서비스 그래프, PTR/RDAP 옵션)
- 룰·알림: `GET/POST /monitors`, `GET /alerts`, mute-rules, maintenance-windows, storm 조회
- 사건: `GET/POST/PATCH /incidents`, postmortem 생성, `GET /rca`, `GET /rca/{id}`
- 기타: `POST /chat`(SSE), settings(LLM/webhook/retention/tokens/enrollment), `GET /overview`, `/healthz`, `/internal/metrics`
- 모든 목록형에 LIMIT·시간범위 상한 내장

주의: **agent token은 ingest 전용**이다. `/api` 조회는 24h 단일 admin 세션 토큰뿐 —
aic가 프로그램적으로 질의하려면 read 자격증명 신설이 필요하다(§10 Q4, integration-plan Phase 3와 공통 과제).

### 2.4 웹 콘솔 (React SPA, 12 페이지)

dashboard(KPI)·hosts(fleet 맵+호스트 상세: 메트릭 차트+이벤트 마커, 프로세스, changes/anomaly feed,
인벤토리, 연결)·explorer(파셋 이벤트 브라우저+라이브 테일)·logs·topology·monitors·incidents(포스트모템
에디터)·rca(리포트)·chat(도구 카드 스트리밍)·settings(+tokens)·login.

### 2.5 룰 엔진·알림

- 룰 6종: `metric_threshold`, `event_pattern`, `host_down`, `baseline`(z-score), `disk_eta`(R² 회귀),
  `process_leak`. edge-trigger + duration 게이트 + cooldown + Warn→Crit 승격 + fingerprint dedup.
- **changes·logs를 보는 룰 종류는 없다** — 커널 이산 이벤트로 알림을 만들려면 events 이중 기록(권장)
  또는 `change_pattern` 신설이 필요 (rca-web PRD [D2]).
- 알림 채널은 전역 webhook 1개(deep link 포함). Slack/메일 없음.

### 2.6 auto-RCA · incident · chat

- **auto-RCA**: crit-onset 알림 트리거 → ±30분 증거 수집(호스트 메타, 메트릭 delta, events≤100,
  **changes≤10 — change_type 무필터라 kernel 행도 수신 즉시 자동 포함**, 연결) → 결정적 findings
  (host_down/OOM/디스크/CPU/스왑/최근 변경 상관) → LLM 분석(일일 cap, 초과 시 data-only degrade) →
  `rca_reports` 저장, `[evidence:id]` 인용.
- **incident**: warn+ onset에서 fingerprint당 1건 자동 생성, 결정적 postmortem 마크다운 생성.
- **chat**: SSE LLM 에이전트, read-only 도구 4종(query_metrics/query_events/query_connections/get_host).
  `query_metrics`는 **닫힌 metric 허용목록**(`chat/tools.rs`의 `METRICS` 상수 + `METRIC_NOTES`) —
  `aic.kernel.*`를 넣기 전까지 커널 메트릭은 저장돼도 chat에서 조회 불가(§6 rca-web 백로그).

### 2.7 운영·보안·검증

단일 admin(24h 세션 + 5분 step-up), 로그인 rate limit, HMAC 체인 audit 로그, LLM 키 봉투 암호화,
`rca-simd` 가짜 에이전트 플릿 시뮬레이터(장애 주입 `--inject cpu-spike|mem-leak`), `/internal/metrics` 수신 카운터.

### 2.8 지금 없는 것 (연동 설계가 기대면 안 되는 것)

gRPC 수신 · Histogram 수신 · traces · 로그 파싱(원문 저장) · changes/logs 기반 룰 ·
멀티유저/RBAC · agent용 read API 자격증명 · Slack 등 목적지별 알림 · (PHASE2 실측) 프로덕션에서
룰/webhook/LLM 대부분 미설정 상태.

---

## 3. aic에서 rca-agent 자원 정보 호출·측정 방법 (계약 레퍼런스)

### 3.1 호출 — control API 전체 표

바인딩 `127.0.0.1:{control.health_port}`(기본 **9090**), 인증 **없음**(loopback이 유일한 보호), plain HTTP.

| API | 조건 | 블록 | 반환 | 용도 |
|---|---|---|---|---|
| `GET /healthz` | 상시 | 즉시 | `ok` | 생존 확인 (doctor 후보) |
| `GET /readyz` | 상시 | 즉시 | cloud-meta 확보 전 503, 후 200 | 기동 완료 확인 |
| `GET /featuresz` | 상시 | 즉시 | 신호별 `{enabled, attach, disabled_reason}` + `kernel_capabilities`(btf/tracing/ringbuf…) + `filter_dropped` | **자원 측정 능력 조회** — 어떤 신호가 실제 붙었나 |
| `GET /snapshotz` | `control.snapshot_api: true` | 즉시 | `{ready, service, cloud{provider,region,az,instance_type}, host{os,arch}, features}` 캐시 스냅샷 (계정ID·호스트명 등 민감 필드 제외 설계, ADR-0043) | 실행 컨텍스트 조회 |
| `POST /collectz?profile=incident&duration=<N>s` | `control.snapshot_api: true` | **window만큼 블록** | `rca.evidence.v1` 번들 | **측정** (아래 3.2) |

오류 계약: `/collectz`는 duration 파싱 불가 400 "invalid duration" / 범위 밖(<0 또는 >5m) 400
"duration out of range" / profile≠incident 400 / 종료 중 503. `snapshot_api=false`면 404
(aic에서는 "rca-agent 오류 404"로 표시 — "systemctl status" 힌트는 연결 실패 시에만 붙는다).
**동시 collect 제한 없음** — 서버는 경합을 직렬화하지도 거부하지도 않으며, 동시 요청은 각자
window를 돌아 각자 번들을 받는다(`internal/control/collector.go`에 mutex 없음). 자원 경합과
window 중첩 관리는 **소비자 책임**이다.

### 3.2 측정 — `/collectz`의 의미론과 evidence bundle

측정은 **window 방식**이다: 요청 시각에 신호별 누적 카운터·top 맵을 스냅샷(start) → `duration`만큼
대기 → 다시 스냅샷(end) → **delta**를 계산해 번들로 반환. 즉 "지금부터 N초간 커널에서 무슨 일이
일어나는지"를 재는 능동 계측이며, 과거 조회가 아니다 (과거 이력은 §5 Lane C의 몫).

`rca.evidence.v1` 구조 (소비자 관점):

```
schema_version, profile, window{started_at, ended_at, requested_duration, elapsed_millis}
source{type: control_api|push_scheduler}, service, host, cloud, features
snapshots{start, end}
observations{
  unit: "cumulative_counts_with_window_delta"
  start / end / delta        ← 신호별 원시 카운터 (판정 없음)
  top                        ← 신호별 top-N(고정 5) items / by_comm / by_cgroup — PID·comm·cgroup entity 포함
  summary                    ← root_cause_ready=false·root_cause_decision=false 불변(패닉 가드),
                               attribution_level, active_signals, notable_count, baseline{}, limitations
  findings[]                 ← 무임계 관측 delta (severity warning|info, confidence: observed_delta_only)
  correlation_hint           ← co_occurrence_v1, rule 5종(memory_pressure/io_contention/…) — 참고 힌트
}
quality{ready, errors[], signal_count}
```

소비자 호환 계약(`docs/architecture/evidence-v1-schema.md`): 필드는 additive-only, top은
`items/by_comm/by_cgroup`만 의존할 것, `findings`·`correlation_hint`는 판정이 아니라 힌트,
`baseline.available`은 "저장 이력 있음"일 뿐. **판정은 소비자(aic)의 몫** — 이 해석 주의는
aic 도구 description에 이미 새겨져 있다.

측정 파라미터: window 5s~300s(aic가 clamp), 기본 30s. baseline 비교는 500ms 하드 타임아웃
(초과 시 `baseline_timeout`으로 degrade). `duration=0`은 즉시 스냅샷 diff(의미론 미문서 — §10 Q3).

### 3.3 aic 수집 범위 계약

aic가 가져올 데이터는 **상태**, **진단 시점 증거**, **상시 변화량**의 세 계층으로 나눈다.
RCA-eBPF의 BPF map 원본이나 프로파일 파일을 직접 읽지 않고, loopback control API의 버전된
응답만 소비한다.

#### 상태·실행 문맥 (항상 조회 가능)

| 출처 | 가져올 데이터 | aic 소비처 |
|---|---|---|
| `/healthz`, `/readyz` | 생존·준비 여부와 실패 이유 | doctor, 수집 결과 신뢰도 |
| `/featuresz` | 신호별 enabled/attach/disabled reason, kernel capability, filter/profiling drop | doctor, 데이터 부재 설명, 신선도 |
| `/snapshotz` | rca-agent 버전, OS/arch, cloud provider/region/AZ/instance type, cloud metadata 신선도 | collect/incident 문맥과 중앙 조인 |

`/snapshotz`는 독립 chat 도구로 노출하지 않는다. `/collectz` 번들에 이미 start/end snapshot이
들어가므로 doctor와 evidence 문맥에 자동 편입한다. 상태 응답에는 호스트명·계정 ID 같은 새 식별자를
추가하지 않는다.

#### 진단 시점 증거 (`POST /collectz`)

진단 요청이 있을 때만 window를 잡는다. `diagnose --kernel`은 기본 5초, chat과 CLI는 기본 30초,
허용 범위는 5~300초다. 다음 항목을 원본 evidence에 보존한다.

| 우선순위 | 신호 | 가져올 값 |
|---|---|---|
| P0 | OOM | kill delta, victim PID/comm/cgroup, 메모리 수치, event seq |
| P0 | scheduler | latency histogram·총 이벤트, PID/comm/cgroup top |
| P0 | block I/O | latency histogram·총 이벤트, PID/comm/cgroup top |
| P0 | network·TCP service map | 송수신 bytes/calls, retransmit, RTT, 방향·peer port·연결 수, entity top |
| P1 | capability check | capability denial delta |
| P1 | process lifecycle·context switch | fork/exit/switch delta |
| P1 | syscall·file I/O | latency histogram과 이벤트 delta |
| P2 | userspace | malloc/free/malloc retry delta |

모든 신호에 window 시각·실제 소요 시간, 활성 신호, 수집 오류, `quality`, baseline 상태, attribution
수준, drop/누락 정보를 함께 저장한다. 원본 `rca.evidence.v1`은 redaction 후 incident evidence로
보존하고, chat에 보내는 표현만 64KB로 제한한다.

`findings`, `summary`, `correlation_hint`, `top`은 **해석 보조 데이터**다. aic는 P0 신호부터
결정적으로 `Finding` 후보로 변환하되 root cause로 채택하지 않는다. PID/comm/cgroup은 활동이 관측된
entity일 뿐 책임 주체가 아니다. `correlation_hint`는 초기 Finding 매핑에서 제외하고 원본 evidence에만
남긴다. aic의 프로세스 인벤토리·로그·변경 이력과 교차 검증한 뒤에만 진단 결론에 사용한다.

#### 상시 변화량 (`GET /countersz`, 후속 계약)

현재 RCA-eBPF에는 `/countersz`가 없다. 상시 수집은 블로킹 `/collectz` 번들을 반복 호출하지 않고,
다음 최소 응답을 제공하는 논블로킹 API가 추가된 뒤 시작한다.

- `schema_version`, `snapshot_at`, agent instance ID와 host boot ID
- 신호별 누적 카운터와 histogram bucket
- OOM 등 이산 이벤트 ring과 단조 증가 `seq`
- 신호별 읽기 오류와 filter/profiling/event drop 수

aicd는 이전 snapshot과 비교해 delta를 계산한다. 카운터가 감소하거나 instance/boot ID가 바뀌면
재시작으로 보고 해당 구간 delta를 폐기한다. 중앙에는 카운터 delta와 redaction한 이산 이벤트만
전송한다. `findings`, `summary`, `correlation_hint`, PID별 top은 민감정보와 카디널리티 때문에
상시 전송하지 않는다. `/countersz`가 합의되기 전 `/collectz` 주기 수집은 실험용 fallback으로만
허용하며 기본 비활성으로 둔다.

초기 범위에서 제외하는 항목은 profiling 파일, 전체 process dump, BPF map 원본, 임의 원격 호스트의
evidence다. loopback 전용 접근과 bounded read·redaction 불변식을 유지한다.

### 3.4 aic 노출면 (현재)

| 진입점 | 동작 |
|---|---|
| chat 도구 `rca_agent_collect(duration_secs)` | `/collectz` pull → redact+64KB cap → LLM에 JSON 텍스트로. 요청 timeout = window + 15s |
| chat 도구 `rca_agent_features()` | `/featuresz` pull, 10s timeout |
| CLI `aic rca collect [id] [--window 30s] [--json]` | 번들을 incident evidence(`Observability`)로 첨부 |
| config `[rca_agent]` | `enabled`(기본 false) / `url`(기본 `http://127.0.0.1:9090`, loopback 강제) |

### 3.5 불가능한 것 (설계가 우회해야 하는 제약)

1. **신호 runtime toggle 불가** — 측정 항목 변경은 rca-agent 재시작. "필요할 때 syscall 신호만 켜서
   재기" 같은 UX는 불가능하고, opt-in 셋은 배포 결정이다(§5 Lane C의 기본셋 합의).
2. **원격 rca-agent 불가** — aic는 loopback만. 다중 호스트 커널 증거는 상시 파이프라인(Lane C) 경유.
3. **동시 collect 무제한(무가드)** — chat 도구·CLI·(향후) aicd 루프가 겹치면 409 같은 신호 없이
   **조용히 중첩 실행**된다. window 중첩은 번들 해석을 흐리므로 소비자 측 상호배제가 필요하다.
   [D1]의 논블로킹 countersz가 근본 해소책.
4. **64KB 출력 cap** — 신호를 많이 켠 호스트의 번들은 LLM 도구 출력에서 잘릴 수 있다(finalize truncate).
   원문 보존은 CLI `--json`/incident evidence 경로 사용.
5. **rca-agent 히스토그램의 rca-web 직행 불가** — §1.3. 지연 분포는 로컬 pull로만 보고,
   플랫폼에는 카운터 delta만 나른다.

---

## 4. 목표 / 비목표

### 목표

- **G1 (호출·측정 방법의 문서화)** — §3이 그 자체로 산출물이다. 이후 작업은 §3 계약만 참조하면 된다.
- **G2 (aic 로컬 보강)** — rca-agent를 aic의 1급 데이터 소스로: doctor 헬스체크, `/diagnose` 편입
  (SourceQuality 구분), 신선도 표시.
- **G3 (플랫폼 편입)** — aicd 주기 수집으로 커널 카운터·OOM 이벤트를 rca-web에 상시 적재,
  기존 소비 경로(Explorer·anomaly feed·auto-RCA·룰)에 무개조 흡수. rca-web측 Draft PRD와 한 쌍.
- **G4 (경계 유지)** — ADR-0048 D2(소비자는 pull, 에이전트 무변경)·SRE-SCOPE-BOUNDARY
  (aic는 pull·read-only·stateless) 불변식을 모든 레인에서 유지.

### 비목표

- rca-agent 쪽 판정 로직 추가, findings/correlation_hint 원문의 서버 export (해석층은 로컬에 남는다)
- 원격 rca-agent URL 허용, rca-agent의 OTLP direct push 아키텍처 변경
- rca-agent 신호의 runtime toggle API (rca-agent 소관, 본 PRD는 요청하지 않음)
- syscall/block_io/network/userspace의 상시 활성 (오버헤드 실측 전)
- aic 상시 감시 루프 신설 (aicd 기존 opt-in exporter tick에 얹는 것만 허용)
- macOS (eBPF 부재)

---

## 5. 연동 설계 — 3개 레인

```
                      ┌──────────────── Lane A (출하됨) ────────────────┐
    사람 ── aic chat/CLI ──▶ rca-agent :9090 /collectz·/featuresz (loopback pull)
                      └── Lane B: doctor·/diagnose·freshness 보강 ──┘

    Lane C (제안): rca-agent :9090 /countersz[D1] ◀── aicd tick(60s) ── delta 계산
                                                        │ OTLP HTTP/protobuf (기존 파이프라인)
                                                        ▼
                    rca-web /v1/metrics (aic.kernel.* — 무개조) · /v1/logs (이산 이벤트 scope)
                                                        ▼
                    Explorer 그래프 · anomaly feed · 룰 · auto-RCA 증거 · (allowlist 갱신 후) chat

    Lane D (후속): aic chat/diagnose ──▶ rca-web /api 질의 — read 자격증명 신설이 선결(Q4)
```

### Lane A — 대화형 pull (출하됨: 유지·회귀 보호만)

현행 유지. wiremock 계약 테스트가 wire를 고정하고 있으므로 rca-agent 버전 갱신 시 스키마
추가(additive)만 허용됨을 확인한다. 변경 없음.

### Lane B — aic 로컬 보강 (이 PRD의 aic측 신규 작업)

- **B1. doctor 헬스체크** (우선순위 1): `[rca_agent] enabled=true`일 때 `check_aicd_supervisor`와
  동형의 optional 체크 — `GET /healthz`(2s) 도달성 + `GET /featuresz` 요약(활성 신호 n개,
  attach 실패 목록, `snapshot_api` 활성 여부 → collectz 사용 가능성). 미설치/미기동은 WARN
  (aicd supervisor와 같은 "optional" 등급). disabled면 스킵.
- **B2. `/diagnose` 편입** (우선순위 1): opt-in 플래그(예: `aic diagnose --kernel`, 기본 off)로
  짧은 window(기본 5s) collect를 probe 목록에 추가. 번들 `findings[]`를 결정적 매핑으로
  `Finding{confidence, source_quality}`에 변환 — `SourceQuality::External`이 이미 "외부 소스용"으로
  예약돼 있고(PHASE2 Track D의 신뢰도 배지 D1 — 본 문서의 countersz 관문 [D1]과 무관),
  severity warning→Medium/info→Low 매핑, LLM 불필요.
  30s 기본을 쓰지 않는 이유: diagnose는 단발 분석이라 5s 블록이 UX 상한이다.
- **B3. 신선도(D3) 편입** (우선순위 2): PHASE2 Track D3의 소스 목록(로컬 샘플러, webhook,
  관측 백엔드, sre-agent)에 rca-agent를 추가 — 마지막 성공 pull 시각 + `/featuresz` attach 상태를
  web·chat 브리핑 신선도 스트립에 표시. PHASE2-RCA-PLAN 문서 갱신 포함.
- **B4. snapshot 자동 문맥 편입** (우선순위 3): `GET /snapshotz`를 별도 LLM 도구로 노출하지 않고
  doctor와 collect/incident evidence 문맥에 포함. collect 번들의 start/end snapshot을 우선 사용하고,
  doctor만 논블로킹 endpoint를 직접 조회한다.

Lane B는 전부 read-only·loopback·기존 게이트(redaction/bounded) 재사용 — 경계 논쟁 없음.

### Lane C — 상시 파이프라인: rca-agent → aicd → rca-web

rca-web측 Draft PRD(`PRD-rca-agent-kernel-evidence.md`)의 aic측 상세. 핵심 원칙:
**번들이 아니라 원시 카운터 delta와 이산 이벤트만 나른다** (entity 담은 findings/correlation_hint는
로컬 해석층에 남김 — redaction 표면 최소화 + Histogram 제약 회피).

- **C1. `[aicd.rca_agent]` config 신설** (CLI용 `[rca_agent]`와 별도 게이트, 기본 off):
  `enabled`, `url`(loopback 강제 — `ensure_loopback` 재사용), `interval_secs`(기본 60).
  aicd 기존 exporter tick 구조에 태스크 1개 추가 — 신규 감시 주체가 아니라 기존 opt-in
  exporter의 신호원 확장으로 프레이밍(SRE-SCOPE-BOUNDARY 유지).
- **C2. 수집 방식 — [D1] 관문**: 1순위는 rca-agent에 논블로킹 `GET /countersz`(신호별 누적 카운터
  스냅샷 + 이산 이벤트 ring 버퍼 with seq) 요청. aicd가 폴링·delta 계산(카운터 후퇴 = 재시작으로
  간주, 그 구간 폐기). **Fallback**: countersz가 늦어지면 30s 블로킹 `/collectz` 루프로 출하하되
  CLI/chat collect와의 409 경합을 문서화된 한계로 남긴다.
- **C3. 송신 매핑**:
  - 카운터 delta → 기존 metrics push 합류, metric명 `aic.kernel.*`
    (`context_switches`/`forks`/`exits`/`oom_kills`/…, Gauge/Sum — rca-web 무개조 저장,
    catalog 자동 노출).
  - OOM kill 등 이산 이벤트 → `aic.changes` scope 재사용(change_type `kernel`, action `oom_kill`,
    subject=victim comm) 또는 신설 scope — Q2. `record_id = hash(host, victim, 시각 bucket)` 멱등.
    victim comm은 기존 redaction 게이트 통과 후 송신.
  - [D2]는 rca-web PRD 권고대로 (a) events 이중 기록으로 시작 → 기존 `event_pattern` 룰이 즉시 소비.
- **C4. 배포 순서**: 신설 scope를 쓰는 경우 **rca-web scope 라우팅을 먼저 배포** — 미등록 scope는
  200 OK 무음 폐기라 순서가 뒤집히면 소리 없이 사라진다(integration-plan 리스크 #2와 동일 유형).
  metric 경로는 이름 무관이라 순서 자유, `/api/metrics/catalog`로 유입 확인.
- **C5. 관측성**: doctor에 aicd 수집 상태(마지막 성공 tick, rca-agent 도달성) 표시 — B1과 합류.
  aicd의 기존 partial_success 카운터(`aic.log.dropped`/collector_dropped 감시)가 scope 누락을 드러낸다.

### Lane D — aic → rca-web 질의 (후속, 본 PRD 범위 밖 선언만)

integration-plan Phase 3(`obs_tools.rs`에 rca-web 백엔드 타입 추가)과 동일 트랙. 선결 조건이
**read 자격증명**(현행: agent token=ingest 전용, admin 세션=단일 24h)이므로 rca-web에 Q4를 넘긴다.

---

## 6. 요구사항·작업 분해 (저장소별)

### aic

- [ ] **P1** B1 doctor `check_rca_agent` (healthz+featuresz, optional 등급)
- [ ] **P1** B2 `/diagnose --kernel` — collect(5s) → `Finding{SourceQuality::External}` 결정적 매핑
- [ ] **P2** C1 `[aicd.rca_agent]` config + aicd 수집 태스크 (countersz 또는 fallback 루프)
- [ ] **P2** C3 송신 매핑 (aic.kernel.* metrics + OOM 이산 이벤트 + record_id 멱등 + redaction)
- [ ] **P2** B3 신선도 스트립에 rca-agent 소스 추가 (PHASE2-RCA-PLAN D3 문서 갱신 포함)
- [ ] **P3** B4 snapshot 자동 문맥 편입 (doctor + collect/incident evidence, 독립 도구 없음)
- ⚠ config 필드 추가 시 **테스트 AppConfig 생성부 전부 같은 커밋에서 갱신** — RcaConfig 때 두 번 겪은
  함정(PHASE2-RCA-PLAN §O3 기록). 신규 도구는 `session.rs exec_tool`의 matches! arm 갱신 필수,
  ToolSpec name은 `&'static str`.

### rca-agent (요청 — 에이전트 변경 최소 원칙)

- [ ] **P1 [D1]** 논블로킹 `GET /countersz` 검토·수용 여부 회신 (누적 카운터 + 이산 이벤트 ring).
  기각 시 aic는 fallback으로 진행 — 착수 블로커 아님
- [ ] **P3** (문서 부채) `/featuresz`에 tcp_servicemap 상태 미노출, systemd unit ExecReload 부재로
  `systemctl reload` 안내 불일치 — 본 연동과 직접 무관하나 조사에서 발견, 전달

### rca-web (Draft PRD 소유 — 여기선 aic 관점 요구만)

- [ ] **P2** 이산 이벤트 scope 라우팅 1건 (Q2 결정 후, C4 배포 순서 준수)
- [ ] **P2** chat metric 허용목록(`chat/tools.rs` `METRICS`/`METRIC_NOTES`)에 `aic.kernel.*` 추가 (없으면 저장돼도 chat 조회 불가)
- [ ] **P2** OOM 모니터 기본 룰 ([D2]=(a) events 이중 기록 전제, event_pattern)
- [ ] **P3** Q4 agent read 자격증명 설계 (Lane D 선결)
- [ ] (문서 부채) `PRD-rca-agent-kernel-evidence.md` §0의 "신호군 8종 … 기본은 process_lifecycle·oom만"
  서술이 코드와 불일치 — 실제는 기본 TCP RTT 상시 + opt-in 11종 전부 기본 false (§1.1). 정정 전달

### 검증 게이트 (rca-web PRD SC와 합류)

- Phase 순서: [D1] 회신 → C1/C2 → scope 배포(C4) → E2E → 기본셋 fleet 배포
  (상시 opt-in 기본셋: `process_lifecycle(4)+oom(2)+scheduler(3)=9/14` — 카디널리티 상한 내, 저오버헤드 검증분만)

---

## 7. 함정·리스크

| # | 함정 | 대응 |
|---|---|---|
| 1 | `/collectz` 동시 호출이 **무음 중첩** — 서버에 직렬화·409 가드가 없어 aicd 루프(fallback 모드)와 chat/CLI가 겹쳐도 아무 신호가 없다 | countersz([D1])가 근본 해소. fallback 기간엔 aicd 쪽 자체 상호배제(수집 중 tick 스킵) + 문서화. 필요 시 [D1]과 함께 rca-agent에 직렬화(409) 신규 요청 |
| 2 | 미등록 scope 200 OK 무음 폐기 | C4 배포 순서 엄수 + `aic.log.dropped`/collector_dropped 카운터 감시 + E2E row 대사 |
| 3 | rca-web Histogram 거부 | 카운터 delta만 relay(설계 원칙으로 흡수). 지연 분포는 Lane A 로컬 pull 전용임을 문서 명시 |
| 4 | evidence 64KB truncate로 LLM이 잘린 JSON을 봄 | 신호 多 호스트에서 발생 가능. chat 도구 description에 한계 명시, 원문은 `aic rca collect`/`--json` 경로 안내 |
| 5 | 카운터 후퇴(rca-agent/aicd 재시작) → 음수 delta | 후퇴 감지 시 해당 구간 폐기(표준 카운터 수집기 처리) — C2에 명시 |
| 6 | entity(PID/comm/cgroup) 유출 | loopback 불변식 유지, 서버 송신분은 카운터+redact된 victim comm만. findings/hint 원문은 로컬에 남김 |
| 7 | opt-in 셋 변경 = rca-agent 재시작 | 기본셋을 배포 결정으로 합의(9/14), 변경 절차를 운영 런북에 |
| 8 | config 추가 시 테스트 생성부 누락 | 같은 커밋 원칙 (§6 aic ⚠) |
| 9 | aicd 폴링이 "상시 감시 루프" 원칙과 충돌한다는 오해 | 기존 opt-in aicd exporter tick의 신호원 확장으로 프레이밍 — 신규 데몬·스레드 0 (SRE-SCOPE-BOUNDARY 문서에 각주) |
| 10 | rca-agent 부재/미기동 호스트 | 모든 레인 graceful: doctor WARN, 도구 에러 힌트, aicd tick 스킵. 신호 부재=데이터 없음(스큐 무해) |

---

## 8. 테스트 계획

- **Lane A 회귀**: 기존 wiremock 계약 테스트 유지 + rca-agent 버전 갱신 시 additive 확인.
- **B1**: healthz 200/미기동/비활성 3분기 doctor 스냅샷 테스트.
- **B2**: 고정 번들 fixture → Finding 매핑 골든 테스트 (LLM 무관 결정적).
- **C 계열**: wiremock rca-agent(countersz/collectz) → aicd delta 계산(후퇴 케이스 포함) 단위 테스트;
  E2E는 rca-web PRD SC1~SC4를 그대로 판정 기준으로 (OOM 유발 실험 → changes 행 → auto-RCA 인용 → 모니터 발화).
- **경합**: fallback 모드에서 aicd 수집 중 CLI collect 동시 실행 — aicd 자체 상호배제(tick 스킵)
  동작 확인 (서버는 중첩을 막아주지 않음, §3.5-3).

## 9. 성공 기준

1. `aic doctor`가 rca-agent 상태(도달성·활성 신호·snapshot_api)를 보여준다.
2. `aic diagnose --kernel`이 5초 측정으로 커널 finding을 SourceQuality 배지와 함께 표시한다.
3. rca-web Explorer에서 `aic.kernel.*` 그래프가 그려지고, OOM kill이 anomaly feed에 뜨며,
   auto-RCA 리포트가 커널 증거를 인용한다 (rca-web PRD SC1~SC3와 동일 판정).
4. rca-agent 없는 호스트·구버전 조합에서 기존 동작 무변화 (스큐 무해).

## 10. Open Questions

- **Q1 [D1]** rca-agent가 `GET /countersz`를 수용하는가? 스키마(이산 이벤트 ring + seq) 합의 필요.
  기각 시 fallback 확정. — *관문, rca-agent 팀 회신 대기*
- **Q2** 이산 이벤트 scope: `aic.changes` 재사용(rca-web 무변경) vs `aic.kernel.events` 신설
  (라우팅 1건 추가, 의미 분리). 권장: 재사용으로 시작 — 0014가 이미 자리를 파 놨다.
- **Q3** `duration=0`(즉시 스냅샷 diff)의 의미론이 미문서 — B2에서 활용할지, rca-agent에 문서화 요청할지.
- **Q4** aic→rca-web 질의용 read 자격증명(agent token은 ingest 전용) — rca-web 설계 과제로 이관 (Lane D 선결).
- **Q5 (결정)** `rca_agent_snapshot` 독립 도구는 만들지 않고 doctor와 evidence에 자동 편입한다.
- **Q6 (결정)** `correlation_hint`는 초기 Finding 매핑에서 제외하고 원본 evidence에만 보존한다.

## 11. Decision

- (확정) 플랫폼 도달 경로는 **aicd 릴레이 단일** — rca-agent OTLP direct push는 아키텍처 변경이라 비범위 (ADR-0048 D2 경계 유지).
- (확정) 서버로 나르는 것은 **원시 카운터 delta + 이산 커널 이벤트뿐** — 해석층(findings/hint)은 로컬.
- (확정) 상시 opt-in 기본셋은 `process_lifecycle + oom + scheduler` (비용 9/14)로 시작.
- (확정) 상태·실행 문맥은 doctor/evidence에 자동 편입하고 snapshot 전용 chat 도구는 만들지 않는다.
- (확정) 진단 Finding은 P0(OOM·scheduler·block I/O·network/service map)부터 결정적으로 매핑하며,
  `correlation_hint`는 원본 evidence에만 보존한다.
- (확정) 상시 수집은 `/countersz` 합의 후 시작하고 `/collectz` 주기 호출은 기본 비활성 fallback이다.
- (대기) Q1~Q4.
