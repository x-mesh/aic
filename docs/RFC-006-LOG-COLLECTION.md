# RFC-006: aicd 로그 수집기 — journald / container / file / self → OTLP Logs

> aicd에 로그 수집기를 추가해 4종 소스(journald, 컨테이너 stdout, 지정 파일, aic·rca
> 자체 로그)를 하나의 정규 스키마로 모아 OTLP Logs `aic.logs` scope로 중앙
> rca-server에 push한다. 기존 exporter의 spool·backoff·redaction 규약을 그대로
> 재사용하고, **체크포인트(재시작 복구)** 와 **에이전트측 레벨 필터**를 1급 요구사항으로
> 둔다. 수신 측(rca)은 `events`가 아닌 **신규 `logs` 테이블**에 저장한다.

- 상태: **Draft — 미구현**
- 작성일: 2026-07-13
- 대상 바이너리: `aicd` (crate `aic-server`), 설정은 `aic-common`
- 범위: 로그 **수집·전송**. 로그 기반 알림 규칙·이상탐지는 비목표(중앙 rca 몫).
- 관련 문서:
  - [SRE-SCOPE-BOUNDARY.md](./SRE-SCOPE-BOUNDARY.md) — aic는 상태 없는 수집·전송, 통계 감시/기억은 중앙 몫
  - [RFC-001-CENTRALIZED-RECORD-STORE.md](./RFC-001-CENTRALIZED-RECORD-STORE.md) — 중앙 저장소 전제
- 관련 코드(확장 대상):
  - `aic-server/src/otlp_exporter/mod.rs` — `serve`(host metrics) + spool 드레인 단일 주체
  - `aic-server/src/otlp_exporter/events.rs` — tap 구독 → 즉시 push (구조적 참고 대상)
  - `aic-server/src/otlp_exporter/agent.rs` — 동일 패턴 (broadcast tap)
  - `aic-server/src/otlp_exporter/spool.rs` — 오프라인 spool, `SignalKind`
  - `aic-server/src/otlp_exporter/logs_proto.rs` — OTLP LogRecord 인코딩
  - `aic-common/src/lib.rs` — `AicdExporterConfig`
  - `aic-client/src/redaction.rs` — `redact()`

---

## 1. 목표 / 비목표

### 목표

- **4종 소스를 하나의 스키마로.** journald / 컨테이너 stdout / 지정 파일 / aic·rca 자체
  로그를 `(source, service)` 두 축으로 정규화해 수신 측이 소스별 분기 없이 질의할 수 있게 한다.
- **재시작해도 안 빠지고 안 겹친다.** 소스별 체크포인트(journald cursor, 파일 inode+offset,
  컨테이너 마지막 타임스탬프)를 디스크에 저장하고, at-least-once + `record_id` 멱등키로
  중복은 수신 측 ReplacingMergeTree가 접는다.
- **볼륨을 에이전트에서 막는다.** 로그는 명령 이벤트의 100~1000배다. 레벨 필터·rate limit을
  **push 이전**에 적용한다. 이건 최적화가 아니라 **안전장치**다(§6).
- **기존 규약 재사용.** spool, backoff, redaction, `[aicd.exporter]` config, bearer 토큰.

### 비목표

- 로그 파싱·구조화(JSON 로그의 필드 추출 등). 원문 라인을 그대로 보낸다. 구조화는 후속.
- 로그 기반 규칙/알림. 중앙 rca-server의 rule engine 몫.
- 과거 로그 백필. 수집기는 **켠 시점 이후**부터 읽는다(§4.5).

---

## 2. 왜 지금인가 — 현재 갭

aicd가 내보내는 OTLP scope는 4개뿐이다:

| scope | 내용 | 트리거 |
|---|---|---|
| `aic.events` | command 종료 이벤트 | `CommandRecordStore` tap |
| `aic.agent` | agent 행위 (tool.run_command / risk.denied / finding.created) | `AgentEventBus` tap |
| `aic.changes` | 상태 전이 저널 | 주기 diff |
| `aic.connections` | 커넥션·인벤토리 스냅샷 | 주기 spawn |

**로그 시그널이 없다.** 중앙 rca-web의 Explorer에 사람이 친 명령만 보이는 근본 원인이며,
"이 명령 직후 nginx가 뭘 뱉었나"를 답할 데이터가 애초에 수집되지 않는다.

---

## 3. 정규 스키마 — `(source, service)`

4종 소스를 두 축으로 통합한다. 수신 측 쿼리는 거의 항상 "이 호스트의 이 서비스"로 시작하므로,
`service`가 1급 축이어야 한다.

| `source` | `service`가 되는 것 | 체크포인트 |
|---|---|---|
| `journald` | systemd unit (`nginx.service`) | journald cursor |
| `container` | 컨테이너 이름 | 컨테이너별 마지막 타임스탬프 |
| `file` | config가 준 라벨 (`/var/log/nginx/error.log` → `nginx-error`) | inode + byte offset |
| `aic` | 컴포넌트 (`aicd`, `aic-client`) | 없음(자체 tap, 프로세스 생명주기와 동일) |

### `LogLine` (aic-common)

```rust
pub struct LogLine {
    /// journald | container | file | aic
    pub source: String,
    /// systemd unit / 컨테이너명 / 파일 라벨 / 컴포넌트명
    pub service: String,
    /// ERROR | WARN | INFO | DEBUG. 소스가 안 주면 INFO.
    pub severity: String,
    /// 원문 한 줄. **호출부가 redaction을 마친 문자열을 넘긴다**
    /// (agent_event.rs와 동일 관례 — 원본이 데몬 경계를 넘지 않는 게 1차 방어선).
    pub message: String,
    /// 소스 고유 부가 정보 (pid, container_id, unit, syslog_facility 등).
    pub attrs: BTreeMap<String, String>,
    /// 로그가 **발생한** 시각. 수집 시각이 아니다.
    pub ts: DateTime<Utc>,
    /// 멱등키 — §5 참고.
    pub record_id: String,
}
```

### OTLP 인코딩 (`logs_proto.rs`에 `encode_log_line` 추가)

- scope: **`aic.logs`**
- `LogRecord.body` = `message`
- `severity_number` / `severity_text`: ERROR=17 / WARN=13 / INFO=9 / DEBUG=5
- attributes:
  - `aic.log.source`, `aic.log.service`, `aic.log.record_id`
  - 나머지는 `aic.log.{k}` prefix (수신 측이 prefix 하나로 걸러낼 수 있게 — `aic.agent.*`와 동일 관례)
- `time_unix_nano` = `ts` (**`unix_nanos_now()`가 아니다** — 로그는 발생 시각이 곧 의미다.
  `encode_agent_event`가 `ev.ts` 대신 `unix_nanos_now()`를 쓰는 건 별건의 개선 여지)

---

## 4. 소스별 수집기

각 수집기는 `mpsc::Sender<LogLine>` 하나로 배출하고, 단일 **exporter task**(`serve_logs`)가
받아서 배치·인코딩·push한다. tap 패턴은 `events.rs`/`agent.rs`와 동일하되, **배치**가 다르다:
로그는 라인당 push하면 안 되고 **N줄 또는 T초 단위로 묶는다**(§6).

### 4.1 journald

- `sd-journal` FFI 또는 `journalctl --output=json --follow --cursor=<c>` spawn.
  **권장: `journalctl` spawn.** FFI는 배포 환경별 libsystemd 링크 문제를 떠안는다.
  aic는 이미 `aic snapshot inventory --json`을 spawn하는 선례가 있다(`connections.rs`).
- `service` = `_SYSTEMD_UNIT` (없으면 `SYSLOG_IDENTIFIER`, 그것도 없으면 `unknown`)
- `severity` = `PRIORITY` (0-7) → ERROR(≤3) / WARN(4) / INFO(5-6) / DEBUG(7)
- `ts` = `__REALTIME_TIMESTAMP` (µs)
- 체크포인트 = `__CURSOR` → `~/.aic/logs/journald.cursor`
- Linux 전용. macOS에선 이 수집기를 띄우지 않는다.

### 4.2 컨테이너

- `docker logs --follow --since=<ts> --timestamps <id>` 또는 podman 동형.
  컨테이너 목록은 주기적으로 `docker ps --format=json`으로 갱신 — **새로 뜬 컨테이너를 잡아야 한다.**
- `service` = 컨테이너 이름, `attrs`에 `container_id`, `image`
- `severity` = stderr → WARN, stdout → INFO (더 정교한 추론은 비목표)
- 체크포인트 = 컨테이너별 마지막 타임스탬프 → `~/.aic/logs/container/<name>.ts`
- **주의**: 컨테이너 재생성 시 이름이 같아도 다른 컨테이너다. `container_id`가 바뀌면
  체크포인트를 버리고 `--since=now`로 시작한다(과거 로그 폭주 방지).

### 4.3 파일

- config가 준 경로 목록을 tail. **로테이션 처리가 이 수집기의 전부다.**
- 상태 = `(inode, offset)` → `~/.aic/logs/file/<label>.json`
- 매 tick:
  1. `stat(path)` → inode가 바뀌었으면 **로테이션됨** → 새 파일을 offset 0부터
  2. inode 같고 `size < offset`이면 **truncate됨** → offset 0으로 리셋
  3. 그 외엔 offset부터 읽고 offset 갱신
- `service` = config 라벨, `severity`는 라인 앞머리에서 `ERROR|WARN|INFO|DEBUG` 정규식 추출,
  못 찾으면 INFO
- 심볼릭 링크·glob은 v1 비목표(경로 명시만)

### 4.4 aic·rca 자체 로그

- 별도 프로세스를 읽지 않는다. **`tracing` layer를 하나 더 붙여** `LogLine`으로 배출한다.
- `service` = `aicd` / `aic-client`
- **재귀 차단이 필수**: 이 layer가 만든 로그를 exporter가 push하다 실패해 `tracing::warn!`을
  찍으면 그게 다시 로그가 된다. **exporter 자신의 모듈 경로(`aic_server::otlp_exporter`)에서
  나온 이벤트는 이 layer가 무조건 버린다.**

### 4.5 백필하지 않는다

모든 수집기는 체크포인트가 **없으면** 현재 시점부터 시작한다(`--since=now`, journald `SEEK_TAIL`,
파일은 `offset = size`). 처음 켤 때 `/var/log`를 통째로 밀어 올리면 spool과 네트워크가 즉사한다.

---

## 5. 멱등키 (`record_id`)

spool은 at-least-once다. 재전송이 수신 측 `ReplacingMergeTree`에서 접히려면 같은 라인이
같은 키로 해싱돼야 한다.

```
record_id = "log:" + hex(sha256(host ‖ source ‖ service ‖ ts_millis ‖ message)[..16])
```

- **소스 고유 id를 쓰지 않는 이유**: journald cursor는 있지만 파일·컨테이너엔 없다. 내용 해시는
  4종 모두에 통일 적용된다(`decode.rs`의 `derived_record_id`가 events에 쓰는 것과 같은 전략).
- **충돌 위험**: 같은 호스트·서비스가 **같은 밀리초에 완전히 동일한 라인**을 두 번 뱉으면 하나로
  접힌다. 반복 로그(`connection reset` ×1000)에서 실제로 일어난다. 이건 **수용한다** —
  대안(시퀀스 번호)은 재전송 시 키가 달라져 멱등성이 깨진다. 볼륨 카운터로 보완한다(§6).

---

## 6. 볼륨 안전장치 — 이게 핵심이다

호스트 하나가 하루 수백만 줄을 뱉는다. **에이전트에서 막지 않으면 ClickHouse보다 네트워크와
spool 디스크가 먼저 터진다.**

1. **레벨 필터 (기본 WARN 이상).**
   `[aicd.logs] min_severity = "WARN"`. 서비스별 override:
   `[aicd.logs.services.nginx] min_severity = "INFO"`.
   기본을 INFO로 두면 안 된다 — 켜자마자 사고가 난다.
2. **rate limit (서비스당).** `max_lines_per_sec = 100` (기본). 초과분은 **버리고 카운트**한다.
   버린 사실을 `aic.log.dropped` 카운터 이벤트로 주기 push — **조용히 버리면 안 된다.**
3. **배치.** 라인당 HTTP 요청은 금물. `batch_max_lines = 500` 또는 `batch_max_ms = 2000` 중
   먼저 도달하는 쪽에서 flush.
4. **spool 상한.** 기존 `spool_max_bytes`(256MiB)를 공유하되, 로그가 metrics/events의 spool을
   밀어내지 않도록 **`SignalKind::Logs`에 별도 쿼터**를 두는 것을 검토한다(v1은 공유 + oldest-drop
   유지, 실측 후 결정).

---

## 7. 설정

```toml
[aicd.exporter]
enabled = true
endpoint = "http://rca:8080"
token = "..."
logs_enabled = true          # 신규. 기본 false — opt-in (다른 exporter는 기본 true지만
                             # 로그는 볼륨 리스크가 있어 명시적 opt-in이 맞다)

[aicd.logs]
min_severity = "WARN"        # 전역 기본
max_lines_per_sec = 100      # 서비스당
batch_max_lines = 500
batch_max_ms = 2000

[aicd.logs.journald]
enabled = true
units = []                   # 빈 배열 = 전체. 명시하면 그 unit만.

[aicd.logs.container]
enabled = false
runtime = "docker"           # docker | podman

[[aicd.logs.files]]
label = "nginx-error"
path = "/var/log/nginx/error.log"

[aicd.logs.self]
enabled = true               # aic 자체 로그 (운영 가시성)

[aicd.logs.services.nginx-error]
min_severity = "INFO"        # 이 서비스만 INFO까지
```

`AicdExporterConfig`에 `logs_enabled: bool`, 신규 `AicdLogsConfig`를 `aic-common/src/lib.rs`에 추가.
`[aicd.logs]` 섹션 부재 시 전부 안전한 기본값(수집 off).

---

## 8. 수신 측(rca-server)이 해야 할 일 — 참고

이 RFC의 범위 밖이지만, 짝이 맞아야 동작하므로 명시한다.

1. **`RouteTarget::from_scope`에 `"aic.logs"` 추가.** 지금은 모르는 scope를 **거부(rejection)**
   처리하므로, 이걸 안 하면 로그가 전부 조용히 버려진다(`aic.agent` 때 실제로 발생했던 문제).
2. **신규 `logs` 테이블.** `events`에 넣으면 안 된다 — `0014_changes.sql`이 이미 같은 논리를
   적어뒀다: 볼륨 100배, TTL 다름(로그 7일 vs 명령 감사 30일), `exit_code`/`cwd`/`duration_ms`가
   전부 빈 값이라 **스키마가 거짓말하게 됨**, `(host, ts, record_id)` ORDER BY에 서비스로 prune할
   슬롯 없음.

```sql
CREATE TABLE logs (
    ts         DateTime64(3),
    host       LowCardinality(String),
    source     LowCardinality(String),
    service    LowCardinality(String),
    severity   LowCardinality(String),
    message    String CODEC(ZSTD(3)),
    -- ILIKE는 tokenbf skip index를 타지 못한다(rca에서 EXPLAIN indexes=1로 실측:
    -- LIKE는 idx를 쓰고 ILIKE는 드롭된다). 검색을 이 소문자 사본에 고정해야
    -- 로그 규모에서 풀스캔을 면한다.
    message_lc String MATERIALIZED lower(message) CODEC(ZSTD(3)),
    attrs      Map(LowCardinality(String), String),
    record_id  String,
    INDEX idx_msg message_lc TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (host, service, ts, record_id)   -- 로그 조회는 항상 "이 호스트의 이 서비스"
TTL toDateTime(ts) + INTERVAL 7 DAY
SETTINGS ttl_only_drop_parts = 1;
```

3. **Explorer는 로그를 events와 섞지 않는다.** 별도 화면 또는 소스 전환 UI.

---

## 9. 단계

| 단계 | 내용 | 검증 |
|---|---|---|
| L1 | `LogLine` 타입 + `encode_log_line`(scope `aic.logs`) + `serve_logs` exporter task(배치·spool·backoff) | 유닛: 인코딩 라운드트립, 배치 flush 경계 |
| L2 | **self** 수집기 (tracing layer, 재귀 차단) — 가장 단순하고 즉시 유용 | aicd 로그가 중앙에 뜨는지 e2e |
| L3 | **journald** 수집기 + cursor 체크포인트 | 데몬 재시작 후 유실·중복 0 |
| L4 | **file** 수집기 + 로테이션(inode/truncate) | `logrotate` 강제 실행 후 유실 0 |
| L5 | **container** 수집기 | 컨테이너 재생성 시 과거 로그 재전송 안 함 |
| L6 | rate limit + drop 카운터 | 초당 10k 라인 주입 시 spool 상한 안 넘김 |

**L2(self)부터 시작할 것을 권한다.** 외부 의존이 없고, "에이전트가 왜 안 보내나"를 중앙에서
디버깅할 수 있게 되므로 이후 L3~L5의 개발 속도를 직접 끌어올린다.

---

## 10. 미해결

- `SignalKind::Logs` spool 쿼터 분리 필요 여부 — L6 실측 후 결정.
- 컨테이너 로그의 severity 추론이 stdout/stderr뿐이라 거칠다. JSON 로그 파싱은 후속 RFC.
- `encode_agent_event`가 `ev.ts`를 무시하고 `unix_nanos_now()`를 쓰는 문제 — 로그와 무관하지만
  같은 파일을 건드리는 김에 같이 고칠지 결정 필요.
