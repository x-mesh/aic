# RFC-006: aicd 로그 수집기 — journald / container / file / self → OTLP Logs

> aicd에 로그 수집기를 추가해 4종 소스(journald, 컨테이너 stdout, 지정 파일, aic 자체 로그)를
> 하나의 정규 스키마로 모아 OTLP Logs **`aic.logs` scope**(기존 4개 scope에 이어지는 **5번째**)로
> 중앙 rca-server에 push한다. 기존 exporter의 spool·backoff·redaction 규약을 그대로 재사용하고,
> **체크포인트(재시작 복구)** 와 **에이전트측 볼륨 안전장치**를 1급 요구사항으로 둔다.
> 수신 측(rca)은 `events`가 아닌 **신규 `logs` 테이블**에 저장한다.

- 상태: **구현 완료 (송신부) — 단, [§6.4](#64-배치--batch_max_bytes가-없으면-수신-측이-배치를-거부한다--미구현)와
  [§6.6](#66-4xx는-재시도하지-않는다--poison-batch가-spool-전체를-멈춘다--미구현)이 남았다. 이 둘을 넣기 전에
  `logs_enabled = true`로 켜면 안 된다.** 앱 로그 배치 하나가 그 호스트의 **텔레메트리 전체**를
  멈출 수 있다(§6.6).
  **수신 측(rca-server)도 미구현** — §8의 후속 티켓을 처리하기 전까지 보낸 로그는 100% 버려진다.
- 작성일: 2026-07-13 / 개정: 2026-07-14 (수신 측 실측에서 §6.4·§6.6 결함 발견 — 두 절 신설)
- 대상 바이너리: `aicd` (crate `aic-server`), 설정은 `aic-common`
- 범위: 로그 **수집·전송**. 로그 기반 알림 규칙·이상탐지는 비목표(중앙 rca 몫).
- 관련 문서:
  - [SRE-SCOPE-BOUNDARY.md](./SRE-SCOPE-BOUNDARY.md) — aic는 상태 없는 수집·전송, 통계 감시/기억은 중앙 몫
  - [RFC-001-CENTRALIZED-RECORD-STORE.md](./RFC-001-CENTRALIZED-RECORD-STORE.md) — 중앙 저장소 전제

> **이 문서는 초안(Draft)에서 크게 뒤집혔다.** 초안이 제안한 설계 중 **컨테이너 수집 방식
> (`docker logs --follow`)**, **파일 식별자(`inode + offset`)**, **`record_id`(내용 sha256)**,
> **드롭 노출(합성 로그)**, **rate limit 기본값(100/s)** 다섯 가지는 구현 과정에서 **틀렸음이
> 확인되어 폐기**되었다. 각 절에 "왜 뒤집혔는지"를 근거와 함께 남긴다 — 그러지 않으면 다음
> 사람이 같은 함정에 그대로 빠진다.

---

## 1. 목표 / 비목표

### 목표

- **4종 소스를 하나의 스키마로.** journald / 컨테이너 stdout / 지정 파일 / aic 자체 로그를
  `(source, service)` 두 축으로 정규화해 수신 측이 소스별 분기 없이 질의할 수 있게 한다.
- **재시작해도 안 빠지고 안 겹친다.** 소스별 체크포인트를 디스크에 원자적으로 저장하고,
  **소스별 자연키 `record_id`**(§5)로 중복은 수신 측 ReplacingMergeTree가 접는다.
- **볼륨을 에이전트에서 막는다.** 로그는 명령 이벤트의 100~1000배다. 레벨 필터·rate limit·
  spool 쿼터를 **push 이전**에 적용한다. 이건 최적화가 아니라 **안전장치**다(§6).
- **기존 규약 재사용.** spool, backoff, redaction, `[aicd.exporter]` config, bearer 토큰.

### 비목표

- 로그 파싱·구조화(JSON 로그의 필드 추출 등). 원문 라인을 그대로 보낸다. 구조화는 후속.
- 로그 기반 규칙/알림. 중앙 rca-server의 rule engine 몫.
- 과거 로그 백필. 수집기는 **켠 시점 이후**부터 읽는다(§4.5).
- podman. v1은 docker json-file 드라이버만(§4.2).

---

## 2. 왜 지금인가 — 현재 갭

> **초안 정정.** 초안은 "**로그 시그널이 없다**"고 썼다. **틀렸다.** aicd가 이미 내보내던 4개
> scope는 **전부 OTLP Logs(`/v1/logs`)로 나가고 있었고**, `SignalKind::Logs` spool 버킷도,
> `/v1/logs` 드레인 경로도 이미 있었다. 없었던 것은 "로그 전송 능력"이 아니라 **"운영체제·
> 애플리케이션이 뱉는 로그를 읽어들이는 소스(수집기)"** 다.

aicd가 내보내던 OTLP scope는 4개였다 — **네 개 다 OTLP Logs 신호로 나간다**:

| scope | 내용 | 트리거 | 신호 |
|---|---|---|---|
| `aic.events` | command 종료 이벤트 | `CommandRecordStore` tap | OTLP Logs |
| `aic.agent` | agent 행위 (tool.run_command / risk.denied / finding.created) | `AgentEventBus` tap | OTLP Logs |
| `aic.changes` | 프로세스 생명주기 전이 저널 | 주기 diff | OTLP Logs |
| `aic.connections` | 커넥션·인벤토리 스냅샷 | 주기 spawn | OTLP Logs |

**빠진 것은 "호스트·서비스가 실제로 뱉는 로그"다.** 중앙 rca-web의 Explorer에 사람이 친 명령만
보이는 근본 원인이며, "이 명령 직후 nginx가 뭘 뱉었나"를 답할 데이터가 애초에 수집되지 않는다.

`aic.logs`는 **5번째 scope 추가**다. 그리고 이 구분이 §6.4의 spool 쿼터 설계에 직접 영향을
준다 — 기존 4개가 `SignalKind::Logs` 버킷 하나를 **공유**하고 있었기 때문이다.

---

## 3. 정규 스키마 — `(source, service)`

4종 소스를 두 축으로 통합한다. 수신 측 쿼리는 거의 항상 "이 호스트의 이 서비스"로 시작하므로,
`service`가 1급 축이어야 한다.

| `source` | `service`가 되는 것 | 체크포인트 | 자연키 |
|---|---|---|---|
| `journald` | systemd unit (`nginx.service`) | journald `__CURSOR` | ✅ `__CURSOR` |
| `container` | 컨테이너 이름 (`config.v2.json`의 `Name`) | fingerprint + offset | ✅ `fingerprint:offset` |
| `file` | config가 준 라벨 (`nginx-error`) | fingerprint + offset | ✅ `fingerprint:offset` |
| `aic` | 컴포넌트 (`aicd`, `aic`) | 없음(자체 tap, 프로세스 생명주기와 동일) | ❌ 내용 해시 폴백 |

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
    /// (agent_event와 동일 관례 — 원본이 데몬 경계를 넘지 않는 게 1차 방어선).
    pub message: String,
    /// 소스 고유 부가 정보 (pid, container_id, unit, syslog_facility 등).
    pub attrs: BTreeMap<String, String>,
    /// 로그가 **발생한** 시각. 수집 시각이 아니다.
    pub ts: DateTime<Utc>,
    /// 멱등키 — §5 참고.
    pub record_id: String,
}
```

### OTLP 인코딩 (`logs_proto.rs::encode_log_line`)

- scope: **`aic.logs`**
- `LogRecord.body` = `message`
- `severity_number` / `severity_text`: ERROR=17 / WARN=13 / INFO=9 / DEBUG=5
- attributes: `aic.log.source`, `aic.log.service`, `aic.log.record_id` + 나머지는 `aic.log.{k}` prefix
- `time_unix_nano` = **`line.ts`** (`unix_nanos_now()`가 아니다 — 로그는 발생 시각이 곧 의미다)
- 라인이 상한을 넘으면 **UTF-8 문자 경계에서 truncate**하고 `aic.log.truncated=true`를 붙인다 —
  버리는 대신 잘라서라도 보낸다.

---

## 4. 소스별 수집기

각 수집기는 `mpsc::Sender<LogLine>` 하나로 배출하고, 단일 **exporter task**(`serve_logs`)가
받아서 필터 → rate limit → 배치 → 인코딩 → push한다. 채널이 가득 차면 수집기는 **막히지 않고**
`try_send` 실패로 드롭하며 `DropCounters::by_channel_full`만 올린다.

### 4.1 journald — `journalctl` spawn

FFI(`sd-journal`) 대신 `journalctl` 프로세스를 spawn한다. FFI는 배포 환경별 libsystemd 링크
문제를 떠안는다(`connections.rs`가 이미 `aic snapshot inventory --json`을 spawn하는 선례).

다만 **그 선례를 그대로 베끼면 안 된다**: `connections.rs`는 `wait_with_output()`으로 자식 종료를
기다리는 one-shot이고, `--follow`는 **끝나지 않는다**. `Child`를 계속 들고 있다가 shutdown 시
명시적으로 죽이는 long-running 패턴이 필요하다.

#### 인자 계약 (전부 필수 — 하나라도 빠지면 조용히 깨진다)

```
journalctl --follow --all --show-cursor --output=json --no-pager \
           (--after-cursor=<c> | --since=now)
```

- **`--cursor`가 아니라 `--after-cursor`.** `--cursor`는 **그 엔트리를 포함**해서 재시작마다
  1건씩 중복시킨다.
- **`--follow` 단독은 마지막 몇 줄만 뱉는다.** 커서가 없으면 **`--since=now`를 명시**해야
  §4.5("백필 안 함")가 성립한다.
- `--show-cursor`가 있어야 출력에서 `__CURSOR`를 받는다.
- **`--boot`는 쓰지 않는다.** systemd 242에서 `--boot=all` 도입, 250부터 `--follow`가 `--boot`를
  암묵 적용, 258에서 다시 override 가능 — 버전마다 동작이 갈린다. v1은 이 옵션을 만들지 않는다.

#### 프로세스 관리 계약

- **stderr 전용 리더가 필수다.** piped로 열어놓고 **안 읽으면** 파이프 버퍼(리눅스 64KiB)가 차는
  순간 journalctl이 `write(2)`에서 블록하고 **stdout도 함께 멈춘다**. `tokio::select!`로
  stdout/stderr를 동시에 읽는다. stderr 라인은 `target: "aic_server::otlp_exporter::logs"`로만
  흘린다 — 그 target이 §4.4의 `LOOP_TARGETS`에 걸려 되먹임 루프를 원천 차단한다.
- **자식은 죽는다.** stdout EOF = journalctl 사망. 즉시 재spawn하면 크래시 루프이므로
  `Backoff`(1s→60s+jitter)로 간격을 벌린 뒤 **저장된 커서로 이어붙여** 재spawn한다.
- **shutdown 순서는 `start_kill()` → 리더 drop → `wait().await` 고정.** 뒤집어 `wait()`부터
  부르면 **데드락**이다 — 자식이 꽉 찬 파이프에 블록돼 있고 우리는 읽기를 멈춘 채 서로 기다린다.
  `kill_on_drop(true)`는 panic/abort 대비 안전망으로만 켠다(정상 경로의 destructor kill은 tokio
  문서상 "best-effort"라 좀비 방지를 보장하지 않는다).
- **바이너리 부재는 이 수집기만 비활성화한다.** `?`로 전파하면 aicd 전체가 죽는다.

#### 필드 매핑

- `service` = `_SYSTEMD_UNIT` → `SYSLOG_IDENTIFIER` → `"unknown"`
- `severity` = `PRIORITY`(0..7): `≤3` ERROR / `4` WARN / `5..6` INFO / `7` DEBUG
- `ts` = `__REALTIME_TIMESTAMP`(µs)
- `record_id` = `log:<__CURSOR>` (자연키 — §5)
- `message`: **non-UTF8 필드는 JSON에서 문자열이 아니라 바이트 배열**(`"MESSAGE": [72, 101, ...]`)로
  온다(OTel collector에 `convert_message_bytes` 옵션이 존재하는 이유와 같은 함정) — lossy 변환한다.

**Linux 전용.** macOS에서는 no-op 스텁으로 즉시 반환한다. 파싱 로직은 순수 함수로 분리해 macOS에서도
테스트하고, `#[cfg]`는 spawn 경계에만 둔다.

### 4.2 컨테이너 — **파일 tail** (초안의 `docker logs --follow` 폐기)

> **★ 초안 §4.2(`docker logs --follow --since=<ts>` spawn + `docker ps` 폴링) 전면 폐기 ★**

초안 설계는 세 겹으로 깨진다:

1. **`docker logs -f`는 json-file 로테이션 시 조용히 멈춘다** — moby#23913, moby#37646 (둘 다
   **미해결**). `max-size`가 걸린 **모든 프로덕션 컨테이너**에서 첫 로테이션에 죽는다. 로그가
   안 온다는 사실조차 모른다.
2. **Engine API의 `since`는 초 해상도 정수다.** 재접속마다 최대 1초가 중복되거나 샌다 — Vector
   조차 이를 못 피해 `since - 1`로 일부러 겹쳐 요청하고 메모리에서 dedup한다.
3. **컨테이너당 자식 프로세스 1개**는 스케일이 안 되고, containerd/CRI-O엔 Docker API가 없다.

조사한 4개 구현(Vector `kubernetes_logs` / OTel `filelog` / Filebeat `container` input /
Fluent Bit)이 **전부 파일 tail**을 쓴다. (Vector의 `docker_logs`만 API 방식인데, 디스크
체크포인트가 없어 재시작마다 재읽기/중복이 난다.)

#### → §4.3의 `FileTail`을 그대로 재사용한다

이 수집기가 새로 만드는 건 **경로 발견(glob) + 라인 파서** 둘뿐이다. fingerprint/rotation/
offset/truncate 판정은 전부 `FileTail`에 위임한다.

- 경로: `/var/lib/docker/containers/<id>/<id>-json.log`
- **★ 경로에 컨테이너 id가 박혀 있다는 게 핵심이다.** 컨테이너를 재생성하면 id가 바뀌어 **경로
  자체가 달라진다** — 새 파일로 인식되고 fingerprint도 다르다. 초안 §4.2가 걱정한 *"이름은 같은데
  다른 컨테이너 → 체크포인트를 버리고 `--since=now`로 되돌아가는 로직"* 이 **통째로 불필요해진다.**
  **`docker ps` 폴링도 같이 소멸한다** — 디렉토리 재스캔(5초 주기)만으로 새 컨테이너가 잡힌다.
- `service` = `config.v2.json`의 `Name`(앞 `/` 제거), 못 읽으면 짧은 id(앞 12자)로 폴백
- `attrs`: `container_id`(전체), `image`(있으면)
- `severity`: `stream == "stderr"` → WARN, 그 외 → INFO (더 정교한 추론은 비목표)
- **깨진 json-file 라인은 파서가 `None`으로 버린다.** `LineParser`가 `Fn(&str) -> Option<LogLine>`
  이라, 반쪽 라인은 카운터(`invalid_json`/`invalid_time`)만 올리고 **파이프라인에 절대 도달하지
  않는다.**
- **심볼릭 링크는 따라가지 않는다**(경로 탈출 방지 — `symlink_metadata`로 확인).
- 베이스 디렉토리를 못 읽으면(권한/미설치) **이 수집기만** 비활성화한다(aicd는 계속 산다).

**podman은 범위 밖.** 경로 규약이 docker와 다르다.

### 4.3 파일 — **fingerprint 기반 식별** (초안의 `(inode, offset)` 폐기)

> **★ 초안 §4.3의 식별자 `(inode, offset)` 폐기 ★**

**inode는 재사용된다.** 파일 삭제 후 커널이 같은 inode 번호를 새 파일에 재배정하면, 초안의 판정
로직("inode 동일 + `size >= offset` → 변화 없음")이 **새 파일의 앞 `offset` 바이트를 통째로
건너뛴다.** 조용한 유실이고, 로그가 안 보인다는 사실조차 모른다. Docker/overlayfs·ext4에서 흔하다.
Vector / OTel `filelog` / Filebeat 셋 다 **fingerprint(첫 N바이트 해시)를 기본값**으로 쓰고
inode는 옵션으로 강등했다.

#### 식별자 = fingerprint(첫 1024B 해시), inode는 **보조**

- `fingerprint = hash(첫 1024바이트)`. 안정적 해시(`DefaultHasher` — 키가 고정이라 프로세스를
  재시작해도 같은 바이트열엔 같은 값. 체크포인트에 저장된 fingerprint와 재기동 후 계산한 값을
  비교하려면 이 성질이 필수다). **sha256이 아니다** — 중요한 건 "첫 N바이트 내용 기반"이라는
  성질이지 특정 알고리즘이 아니고, 워크스페이스에 새 crate를 추가하지 않는다.
- **1024B 미만 파일은 수집 보류**(Vector의 `known_small_files` 패턴). 짧은 파일들끼리 fingerprint가
  충돌해 서로 다른 파일을 같은 것으로 오인하는 걸 막는다.
- **inode는 fingerprint를 만들 수 없을 때만** 참조한다(임계 미만으로 truncate된 직후 등):
  같은 inode면 truncate, 다른 inode면 로테이션.
- **fingerprint가 다르면 inode/size가 뭐라 하든 무조건 다른 파일이다.** 이게 inode 재사용을
  조용한 유실 없이 잡아내는 지점이다.

#### 로테이션 = "닫아라"가 아니라 **"열린 핸들로 EOF까지 마저 읽고 나서 닫아라"**

logrotate의 기본 move-create(`mv app.log app.log.1 && create app.log`)는 rename **직후에도 옛
파일에 미독 데이터가 남는다** — 그리고 그건 정확히 **장애 직전 마지막 로그**다. 유닉스에서는
rename이 inode를 옮길 뿐 이미 열어 둔 fd는 계속 그 inode를 가리키므로, 새 파일로 갈아타기 전에
**그 fd로 EOF까지 드레인**하면 이 꼬리를 잃지 않는다.

#### 그 외

- **notify(inotify)는 쓰지 않는다.** inotify는 경로가 아니라 **inode를 watch**해서 mv+create 후
  옛 inode를 계속 따라간다 — 새 파일의 새 로그를 놓친다. macOS FSEvents도 "남의 파일"을 잘 못
  본다. 대신 **1초 폴링**(`tokio::time::interval` + `MissedTickBehavior::Skip`)이다.
  `batch_max_ms = 2000`이라 1초 폴링의 지연은 배치 창에 흡수된다.
- **개행 없는 꼬리(부분 라인)는 절대 소비하지 않는다.** 마지막 개행까지만 완결된 라인으로 취급하고
  offset을 그 자리에 둔다 — 다음 tick에 이어 쓰인 나머지와 합쳐 온전히 읽힌다. (폴링 tail의
  유일한 진짜 함정: 쓰는 쪽이 라인 중간까지만 flush한 순간에 stat이 걸리는 경우.)
- `service` = config 라벨. `severity`는 라인 앞머리 최대 8토큰에서 `ERROR|WARN|INFO|DEBUG`를
  **토큰 단위로** 찾는다(부분 문자열 매치 금지 — `MIRROR`가 `ERROR`로 오인되면 안 된다). 못 찾으면 INFO.

### 4.4 aic 자체 로그 — **재귀 차단이 필수다**

별도 프로세스를 읽지 않는다. **`tracing` layer(`SelfLogLayer`)를 하나 더 붙여** `LogLine`으로
배출한다. `service` = `aicd` / `aic`.

#### 왜 "필수"인가 — 실측 근거

**`tracing-core`의 재진입 가드(`dispatcher::get_default`의 `can_enter` 체크)는 전역 subscriber
(`set_global_default` / `.init()`)에서 우회된다** — `SCOPED_COUNT == 0`이면 가드 없이
`get_global()`을 바로 호출하는 fast path를 탄다. `aicd`는 `.init()`을 쓰므로, `on_event` 안에서
`tracing::` 매크로를 호출하면 **그 즉시 무한재귀 → 스택 오버플로**다.

게다가 **task 경계를 넘는 피드백 루프**도 있다(스택이 갈리므로 `can_enter`가 애초에 못 잡는다):

```
exporter task가 push 실패 → tracing::warn! → SelfLogLayer가 LogLine으로 만들어 채널로 try_send
  → serve_logs가 그 LogLine을 다시 push 시도 → 또 실패 → tracing::warn! → ... 무한
```

#### 방어 두 겹 (둘 다 필수)

1. **per-layer `.with_filter(filter_fn(...))`** 로 `LOOP_TARGETS`를 배제한다:
   `aic_server::otlp_exporter` + `hyper` / `h2` / `reqwest` / `rustls` / `tower`
   (exporter의 HTTP 클라이언트 내부 로그 — `AIC_LOG=debug`를 켜는 순간 push 1건이 수십 라인을
   만들어 같은 루프를 돈다).
   **전역 `EnvFilter`로 걸면 안 된다** — 그러면 stderr/file 등 **다른 layer에서도 그 이벤트가
   사라진다**(opentelemetry-rust issue #1682와 동일한 함정).
2. **`on_event` 안에서 `tracing::` 매크로를 절대 호출하지 않는다.** 채널이 가득 차면 `dropped`
   카운터만 올린다. `try_send`만 쓴다 — `blocking_send`는 async 컨텍스트(tokio worker 스레드)에서
   **panic**한다.

#### `aic-client`는 subscriber가 **아예 없었다**

`aicd`는 `telemetry.rs`가 있었지만 **`aic-client`에는 tracing subscriber가 하나도 없었다** —
`tracing::warn!`을 아무리 불러도 어디에도 기록되지 않았다. 그래서 이 RFC에서 **최초로 도입**하고,
버퍼링한 라인을 IPC(`IpcRequest::PushLogLines`)로 aicd에 넘긴다.

flush는 **2초 주기 + 프로세스 종료 시**다. 종료 flush에 `Drop`을 쓸 수 없다 — `main.rs`에
`std::process::exit()` 호출이 **40개소 이상**이라 `Drop`이 아예 돌지 않는다. **`libc::atexit`**
으로 등록한다(못 잡는 종료는 §10 참고).

### 4.5 백필하지 않는다

모든 수집기는 체크포인트가 **없으면** 현재 시점부터 시작한다(journald `--since=now`, 파일/컨테이너는
`offset = size`). 처음 켤 때 `/var/log`를 통째로 밀어 올리면 spool과 네트워크가 즉사한다.

로테이션이 감지되면 새 파일은 **항상 offset 0부터** 읽는다 — tick 사이에 두 세대가 지나가 한
세대를 통째로 놓쳐도 **조용히 이어붙이지 않는다**(현재 파일은 통째로 본다).

---

## 5. 멱등키 (`record_id`) — **소스별 자연키 우선** (초안의 내용 sha256 폐기)

> **★ 초안 §5(`record_id = "log:" + hex(sha256(host ‖ source ‖ service ‖ ts_millis ‖ message))`)
> 폐기 ★**

spool은 at-least-once다. 재전송이 수신 측 `ReplacingMergeTree`에서 접히려면 같은 라인이 **재전송
후에도 같은 키**로 해싱돼야 한다. 자연키는 그 성질을 **공짜로** 준다:

| source | `record_id` | 자연키인가 |
|---|---|---|
| `journald` | `log:<__CURSOR>` | ✅ |
| `file` | `log:<fingerprint:offset>` | ✅ |
| `container` | `log:<fingerprint:offset>` | ✅ |
| `aic` (self) | `log:<hex(DefaultHasher(host ‖ source ‖ service ‖ ts_millis ‖ message))>` | ❌ 폴백 |

- 자연키는 **재전송해도 불변**이다 — 파일 바이트 위치·journald 커서는 내용과 무관하게 같은 라인을
  같은 키로 가리킨다.
- **초안이 "수용한다"던 반복 로그 접힘 문제가 2/4 소스(journald, file)에서 사라진다.** 초안은
  *"같은 밀리초에 완전히 동일한 라인(`connection reset` ×1000)이 하나로 접히는 건 수용한다"* 고
  적었지만, 자연키를 쓰면 애초에 그런 충돌이 없다. 컨테이너까지 합치면 3/4다.
- **self 소스만 자연키가 없어 내용 해시로 폴백**한다(§10 Known Limitations).
- 해시는 `sha256`이 아니라 **`DefaultHasher`** 다 — `changes.rs`의 `record_id` 관례와 동일하고,
  워크스페이스에 새 crate를 추가하지 않는다.

---

## 6. 볼륨 안전장치 — 이게 핵심이다

호스트 하나가 하루 수백만 줄을 뱉는다. **에이전트에서 막지 않으면 ClickHouse보다 네트워크와
spool 디스크가 먼저 터진다.**

### 6.1 레벨 필터 (`min_severity`) — **소스별 기본값이 다르다**

`serve_logs` 앞단에서 **가장 먼저** 돈다(순수 함수라 제일 싸다).

- **외부 소스(journald/container/file) 기본 `WARN`.** 기본을 INFO로 두면 **켜자마자 사고가 난다.**
- **`aic` self만 기본 `INFO`.** 볼륨이 작고, "에이전트가 왜 안 보내나"를 중앙에서 디버깅하려면
  INFO 가시성이 필요하다.
- 우선순위: **서비스별 override > 명시적 전역값 > 소스별 안전 기본.**
  (`[aicd.logs].min_severity`를 사용자가 명시적으로 바꾸면 소스 기본을 이긴다.)

### 6.2 rate limit — **토큰버킷, 기본 1000/s** (초안의 `100/s` 폐기)

> **★ 초안 §6-2(`max_lines_per_sec = 100`) 폐기 ★**

**100/s는 안전장치가 아니라 무작위 샘플러였다.** Promtail의 기본은 **10,000/s**이고, 게다가
**rate limit 자체가 기본 off**다. 100/s면 **nginx access log 하나만 붙여도 상시 드롭**한다 —
사고를 막는 게 아니라 관측을 상시로 망가뜨린다. **기본 1000/s**로 올린다.

- **알고리즘은 토큰버킷.** 고정 윈도우는 **경계에서 2배 버스트가 그대로 샌다**(윈도우 끝에서
  `rate`만큼 + 다음 윈도우 시작에서 `rate`만큼이 거의 동시에 통과). 토큰버킷은 경과 시간에
  비례해서만 채우므로 이 버스트를 만들지 않는다.
- **카디널리티 방어가 필수다.** 서비스 이름이 매 라인 다르면(로그에서 드물지 않다) 버킷 맵이
  무한 성장해 **OOM**이다. `max_services`(기본 200) 상한 + **LRU eviction**.

### 6.3 드롭 노출 — **카운터 메트릭이다, 합성 로그가 아니다**

> **★ 초안 §6-2의 "버린 사실을 `aic.log.dropped` **카운터 이벤트**로 주기 push" 를 **메트릭**으로
> 확정 ★** — 여기서 "이벤트"를 로그로 읽으면 안 된다.

**★ 불변식 ★ 드롭 시점에 합성 `LogLine`을 만들어 파이프라인에 넣지 않는다.**
드롭은 **폭주 중에** 일어난다. 그 순간 로그를 더 만들면 **폭주에 기름을 붓는다.** Vector·Promtail
둘 다 **메트릭만** 쓴다.

`DropCounters`는 사유별 atomic 카운터일 뿐이고(새 할당도, 새 `LogLine`도 없다 — 폭주와 무관하게
고정 비용), host-metrics task가 매 tick마다 **`aic.log.dropped` 게이지**로 스냅샷을 실어 보낸다:

| reason | 언제 |
|---|---|
| `severity` | `min_severity` 필터에서 걸림 |
| `rate_limit` | 토큰버킷 토큰 부족 |
| `channel_full` | 수집기의 `mpsc::try_send` 실패(exporter가 못 따라감) |
| `spool_quota` | spool `AppLogs` 쿼터 초과 |

**서비스 태그는 붙이지 않는다** — `reason` 태그만 붙인다(카디널리티 방어).

> **배선 주의(실제로 밟은 지뢰).** metrics를 인코딩하는 task(`serve`)와 드롭을 세는
> task(`serve_logs`)는 **서로 다른 task**다. **반드시 같은 `Arc<DropCounters>`를 양쪽에 넘겨야**
> 한다 — 각자 `Arc`를 들면 `aic.log.dropped`가 **영원히 0**이라 "안 보내고 있다"와 "보낼 게 없다"를
> 중앙에서 구분할 수 없다. (`tests/log_collection_e2e.rs::dropped_lines_appear_in_metrics_as_aic_log_dropped`가
> 이 배선을 wire에서 검증한다.)

### 6.4 배치 — **`batch_max_bytes`가 없으면 수신 측이 배치를 거부한다** ⚠ 미구현

라인당 HTTP 요청은 금물. `batch_max_lines = 500` **또는** `batch_max_ms = 2000` 중 **먼저 도달하는
쪽**에서 flush. 타이머는 **첫 라인이 버퍼에 들어온 시점부터** 잰다 — 버퍼가 비어 있는 동안은
데드라인 자체가 없어, 빈 버퍼에서 매 2초 깨어나 아무것도 안 하는 낭비가 없다.

> **⚠ 현재 구현에는 바이트 상한이 없다. 이건 버그다.** 수신 측(rca)에서 실측하며 드러났다.

```
batch_max_lines           500
MAX_LOG_LINE_BYTES        64 KiB      (§3 — 초과 라인은 자르되 버리진 않는다)
────────────────────────────────────
최악 배치                  500 × 64 KiB = 31 MiB
rca MAX_BODY_BYTES        8 MiB       (rca-server/src/otlp/mod.rs:43)
                          → 413. 디코드에 닿기도 전에 body-limit 레이어가 거부한다.
```

**배치가 라인 수로만 잘리기 때문**이다. 자바 스택 트레이스나 JSON 덤프가 몰려 라인당 평균이
16 KiB만 돼도 500줄에서 8 MiB를 넘는다. 파일·컨테이너 수집기는 **임의의 앱 로그**를 읽으므로
이건 이론적 상황이 아니다.

그리고 413은 **§6.6의 poison batch로 이어진다** — 거기가 진짜 피해가 나는 지점이다.

**조치**: `batch_max_bytes = 4 MiB`(수신 측 상한의 절반) 추가. 라인 수 · 바이트 · 시간 중
**가장 먼저 도달하는 것**에서 flush한다. 인코딩 전 원문 바이트로 세되, protobuf 오버헤드를 감안해
상한을 수신 측의 절반으로 잡는다.

### 6.5 spool 쿼터 — **`SignalKind::AppLogs`(tag=2) 신설로 확정** (초안의 "검토한다" 종결)

> **★ 초안 §6-4("`SignalKind::Logs`에 별도 쿼터를 두는 것을 **검토**한다, v1은 공유 + oldest-drop
> 유지") → **AppLogs 신설로 확정** ★**

**§2에서 정정한 사실이 여기서 값을 한다.** 기존 `SignalKind::Logs`는 **events / agent / changes /
connections 4개가 공유**한다. 그러니 "로그에 별도 쿼터"를 `Logs`만 쪼개는 식으로 풀면 **앱 로그가
여전히 명령 감사 이벤트를 evict한다.** 앱 로그(볼륨 100배)가 `risk.denied` 같은 **감사 기록**을
밀어내는 건 절대 허용할 수 없다.

→ **`SignalKind::AppLogs`(tag=2) 신설.** `aic.logs`만 이 버킷을 쓴다.

| kind | 쓰는 scope | 쿼터(기본) | 상한 초과 시 |
|---|---|---|---|
| `Metrics`(0) | host metrics | `spool_max_bytes` × 25% | **oldest-drop** (기존 동작, 회귀 금지) |
| `Logs`(1) | events / agent / changes / connections | × 25% | **oldest-drop** (기존 동작, 회귀 금지) |
| `AppLogs`(2) | **`aic.logs`** | × 50% | **newest-drop** |

**`AppLogs`만 newest-drop인 이유**: 조사한 4개 오픈소스 수집기(Vector / OTel Collector / Filebeat /
Promtail) 중 **oldest-drop을 하는 구현이 하나도 없었다.** oldest를 지우면 (a) 순서가 깨지고
(b) **이미 durable해진 것**을 지우게 된다. 로그 볼륨에서는 그 조합이 즉사다.

쿼터는 기존 `spool_max_bytes`(256MiB)에서 **파생**한다(하위호환) — `spool_metrics_max_bytes` /
`spool_logs_max_bytes` / `spool_app_logs_max_bytes`로 개별 override 가능.

### 6.6 4xx는 재시도하지 않는다 — **poison batch가 spool 전체를 멈춘다** ⚠ 미구현

> **§6.5의 kind별 쿼터로는 이걸 막을 수 없다.** 쿼터는 "누가 누굴 evict하는가"를 가르지만,
> poison batch는 **evict되지 않고 드레인 큐의 머리에 남는 문제**다. 다른 축이다.

`drain()`은 **모든 kind의 배치 파일을 한 FIFO로 섞어 돌고**(`list_batch_files()` → `sort()`),
**첫 실패에서 즉시 반환한다**:

```rust
// spool.rs — drain 루프
Err(_) => return DrainReport { drained, failed: true }   // ← 건너뛰지 않는다
```

여기에 §6.4의 413이 만나면:

1. 8 MiB 초과 배치가 413을 받는다 → spool에 적재된다
2. drain이 그 배치에 닿는다 → **또 413** (몇 번을 보내도 크기는 그대로다 — **영구 실패**다)
3. `failed: true`로 즉시 반환. backoff가 늘어나고, 다음 tick에 **또 같은 배치부터** 시작
4. **그 배치가 FIFO 머리에 영원히 박힌다.** 뒤에 쌓인 metrics · events · agent · changes ·
   connections가 **전부 함께 드레인 정지**한다 (드레인 주체는 host metrics task 하나뿐 — §4)

**앱 로그 배치 하나가 그 호스트의 텔레메트리 전체를 죽인다.** `AppLogs` 쿼터를 아무리 잘 갈라도
소용없다 — 쿼터는 그 배치를 **지우지 않기 때문**이다.

#### 코드에 이미 정답의 선례가 있다

`drain()`은 **손상된 배치**를 이렇게 다룬다:

```rust
// 손상/부분 write된 배치 — 무한 재시도를 막기 위해 건너뛰고 삭제한다.
self.remove_and_untrack(&path, kind_hint);
continue;
```

**413도 정확히 같은 부류다** — 무한 재시도해도 절대 성공하지 않는 배치. 그런데 이 처리가
**HTTP 영구 실패에는 적용되지 않는다.** 파일이 깨진 것만 영구 실패로 보고, 내용이 수신 측
계약을 위반한 것은 일시 실패로 오인한다.

#### 조치

`push`/`push_logs`가 **재시도 가능 여부**를 구분해 반환한다:

| 응답 | 분류 | drain의 처리 |
|---|---|---|
| 2xx | 성공 | 삭제 |
| **4xx** (413 / 400 / 401 / 404) | **영구 실패** | **건너뛰고 삭제 + `DropCounters` 증가.** 손상 배치와 동일 |
| 5xx · 타임아웃 · 커넥션 오류 | 일시 실패 | 지금처럼 `failed: true`로 반환 (재시도) |

- **401은 논쟁의 여지가 있다** — 토큰을 고치면 성공할 수도 있다. 하지만 토큰 교체는 **재시작을
  동반**하고, 그때까지 401 배치가 큐를 막는 것보다는 버리는 게 낫다. 드롭 카운터가 그 사실을
  드러낸다.
- **드롭은 반드시 카운터로 노출한다**(§6.3의 규약). 조용히 버리면 §6.4의 버그가 다시 숨는다.

#### 왜 둘 다 필요한가

`batch_max_bytes`(§6.4)만 넣으면 **이 특정 413**은 사라진다. 하지만 poison batch를 만드는 원인은
그것 하나가 아니다 — 수신 측이 스키마를 바꿔 400을 뱉거나, 토큰이 만료돼 401이 나면 **같은 방식으로
spool이 멈춘다.** §6.4는 알려진 구멍 하나를 막고, **§6.6은 그 부류 전체를 막는다.**

```toml
[aicd.exporter]
enabled = true
endpoint = "http://rca:8080"
token = "..."
logs_enabled = false         # 기본 false — opt-in. 다른 하위 플래그(events/connections/
                             # agent/changes)는 부모 게이트가 켜지면 기본 true지만, 로그는
                             # 볼륨 리스크가 있어 명시적 opt-in이 맞다.

# spool 쿼터 (전부 Option<u64>. 미지정 시 spool_max_bytes에서
# metrics 25% / logs 25% / app_logs 50%로 파생 — 하위호환)
# spool_metrics_max_bytes  = ...
# spool_logs_max_bytes     = ...
# spool_app_logs_max_bytes = ...

[aicd.logs]
min_severity = "WARN"        # 외부 소스 기본. aic self는 INFO(§6.1이 소스별로 처리)
max_lines_per_sec = 1000     # 서비스당 토큰버킷
batch_max_lines = 500
batch_max_bytes = 4194304    # 4 MiB. ⚠ 미구현(§6.4) — 없으면 최악 31 MiB 배치가 413을 받는다
batch_max_ms = 2000
max_services = 50            # 토큰버킷 맵 상한(카디널리티 방어)

[aicd.logs.journald]
enabled = false
units = []                   # 빈 배열 = 전체

[aicd.logs.container]
enabled = false

[[aicd.logs.files]]          # 배열-of-테이블. 빈 배열 = 파일 수집 없음
label = "nginx-error"
path = "/var/log/nginx/error.log"

[aicd.logs.self]
enabled = true               # aic 자체 로그 (운영 가시성)

[aicd.logs.services.nginx-error]
min_severity = "INFO"        # 이 서비스만 INFO까지
```

### 게이트 규칙 (`aicd_main.rs`)

- `[aicd.exporter].enabled = false` (기본) → 로그 포함 **모든** exporter off.
- `logs_enabled = false` (기본) → **`serve_logs`도 수집기도 안 뜬다.** 로그 채널조차 만들지 않아
  코드 경로가 통째로 비활성이다(회귀 0).
- `[aicd.logs]` 섹션 부재 → 각 하위 `enabled`의 serde 기본값이 `false`라 **전부 off**.
- 각 수집기는 자기 `enabled`(파일은 **빈 배열 여부**)로 개별 on/off.
- journald는 **Linux에서만**(macOS는 no-op).

체크포인트는 `~/.aic/log-checkpoints/`(0700). 못 열면 journald/container/file 수집기를 전부
비활성화한다 — 체크포인트 없이 tail을 시작하면 재시작마다 어디까지 읽었는지 알 수 없다.

---

## 8. 수신 측(rca-server)이 해야 할 일 — **후속 티켓 (별도 레포)**

> **⚠ 이걸 안 하면 aicd가 보내는 로그는 100% 조용히 버려진다.** `aic.agent` 때 **실제로 겪었다.**
> 송신부가 완성되어도 이 두 개가 없으면 아무 일도 일어나지 않는다.

1. **`RouteTarget::from_scope`에 `"aic.logs"` 추가.** 지금은 모르는 scope를 **거부(rejection)**
   처리한다. 로그는 정상 전송되고, 200 OK를 받고, **사라진다.**
2. **신규 `logs` 테이블 마이그레이션.** `events`에 넣으면 안 된다 — `0014_changes.sql`이 이미 같은
   논리를 적어뒀다: 볼륨 100배, TTL 다름(로그 7일 vs 명령 감사 30일), `exit_code`/`cwd`/
   `duration_ms`가 전부 빈 값이라 **스키마가 거짓말하게 됨**, `(host, ts, record_id)` ORDER BY에
   서비스로 prune할 슬롯 없음.

```sql
CREATE TABLE logs (
    ts         DateTime64(3),
    host       LowCardinality(String),
    source     LowCardinality(String),
    service    LowCardinality(String),
    severity   LowCardinality(String),
    message    String CODEC(ZSTD(3)),
    -- ILIKE는 skip index를 아예 못 탄다. 검색을 이 소문자 사본 + LIKE로 고정한다.
    message_lc String MATERIALIZED lower(message) CODEC(ZSTD(3)),
    attrs      Map(LowCardinality(String), String),
    record_id  String,
    -- ngrambf다. tokenbf가 아니다 — 아래 실측 참고.
    INDEX idx_msg message_lc TYPE ngrambf_v1(3, 65536, 3, 0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (host, service, ts, record_id)   -- 로그 조회는 항상 "이 호스트의 이 서비스"
TTL toDateTime(ts) + INTERVAL 7 DAY
SETTINGS ttl_only_drop_parts = 1;
```

**인덱스 실측 (rca, 2026-07-14 — 50만 행 / 62 granule, 1행에만 있는 희귀 토큰 검색):**

| 인덱스 | 질의 | 스캔 granule |
|---|---|---|
| `tokenbf_v1` | `hasToken(message_lc, 'rareword')` | **4 / 62** ✅ |
| `tokenbf_v1` | `message_lc LIKE '%rareword%'` | **62 / 62** ❌ |
| `ngrambf_v1(3, …)` | `message_lc LIKE '%rareword%'` | **4 / 62** ✅ |
| `ngrambf_v1(3, …)` | `message_lc LIKE '%areword%'` (단어 중간) | **4 / 62** ✅ |

**`tokenbf_v1`은 `hasToken`에만 프루닝하고 `LIKE`에는 아무것도 안 한다.** 이 문서의 이전 개정판이
"LIKE는 idx를 쓴다"고 적었던 건 **`EXPLAIN`에 인덱스 *이름*이 뜨는 것만 보고 granule 수를 안 본
오독**이었다. 이름은 뜨는데 62/62를 스캔한다. `hasToken`은 **완전 토큰만** 매치하므로
"`oomkill`이 든 줄을 찾아줘" 같은 실제 검색을 못 한다. → **`ngrambf_v1`**. 디스크 비용은 동일했다.

3. **severity는 `severity_number`가 아니라 `severity_text`에서 읽는다.** rca의 기존 `event_row`
   (events/sessions/agent가 공유하는 유일한 빌더)가 이미 그렇게 한다. 송신부도 `severity_text`에
   `"ERROR"`/`"WARN"`/`"INFO"`/`"DEBUG"`를 실어 보낸다(§3) — 숫자를 문자열로 되돌릴 이유가 없고,
   그렇게 하면 같은 정보에 진실이 두 개 생긴다.

4. **Explorer는 로그를 events와 섞지 않는다.** 별도 화면 또는 소스 전환 UI.

> 수신 측 상세 설계는 rca 레포의 **`docs/PRD-aic-logs-ingestion.md`**에 있다.

---

## 9. 구현 단계 — **실제 순서** (안전장치를 수집기보다 **먼저** 깔았다)

초안 §9의 순서(L1 → self → journald → file → container → rate limit)는 **rate limit을 맨 뒤에**
뒀다. 실제로는 **안전장치를 수집기보다 먼저** 깔았다 — 수집기가 먼저 붙으면 안전장치가 붙기 전
구간에서 폭주를 그대로 맞기 때문이다.

| 순서 | 내용 | 검증 |
|---|---|---|
| t2 | `LogLine` / `SpoolQuotas` / `AicdLogsConfig` 타입 (aic-common) | config 파싱 라운드트립 |
| t3 | `SignalKind::AppLogs` 신설 + kind별 쿼터 + newest-drop | `app_logs_quota_does_not_evict_audit_logs` |
| t4 | `record_id`(자연키) + `AckTracker` + `CheckpointStore`(원자적 저장) | ordered ack 구멍 시나리오, 크래시 후 커서 복구 |
| t5 | `serve_logs` exporter task (배치·spool·backoff) | 배치 flush 경계(라인/ms), shutdown flush |
| **t6** | **볼륨 안전장치 — min_severity 필터 + 토큰버킷 + `DropCounters`** | 10k/s 주입 시 드롭 카운트 정확, 합성 로그 0 |
| t7 | **self** 수집기 (`SelfLogLayer` + 재귀 차단) | `self_log_recursion.rs` — push 실패 폭주에도 스택 오버플로 없음 |
| t8 | **journald** 수집기 (spawn 계약 + 커서 체크포인트) | EOF→backoff 재spawn, shutdown kill+reap |
| t9 | **file** 수집기 (fingerprint + rotate 드레인) | inode 재사용 감지, mv+create 꼬리 유실 0, 부분 라인 |
| t10 | **container** 수집기 (`FileTail` 재사용) | 컨테이너 재생성 시 중복 0, 깨진 라인 격리 |
| t11 | `aic-client` subscriber + `PushLogLines` IPC + `atexit` flush | `log_sink_integration.rs` |
| **t12** | **config 배선 + `aicd_main` 조건부 spawn + 배선 부채 해소** | `log_collection_e2e.rs` — self/IPC/드롭이 wire에 도달 |
| **t13** ⚠ | **`batch_max_bytes`(§6.4)** — 라인 수·바이트·시간 중 먼저 도달하는 것에서 flush | 64 KiB 라인 500개를 넣고 flush된 배치가 4 MiB 이하인지 |
| **t14** ⚠ | **4xx 비재시도(§6.6)** — `push`가 재시도 가능 여부를 반환, drain이 영구 실패를 건너뛰고 삭제 + 카운트 | 413을 뱉는 mock collector에 배치를 물리고, **뒤의 metrics 배치가 정상 드레인되는지** |

> **t13·t14는 아직 안 됐다.** 둘 다 수신 측 실측에서 드러난 결함이고(§6.4·§6.6), **`logs_enabled`를
> 켜기 전에 끝나야 한다.** t14의 검증이 핵심이다 — "앱 로그 배치가 막혀도 **다른 시그널은 흘러야
> 한다**"가 이 두 티켓의 존재 이유 전부다.

---

## 10. Known Limitations — **버그가 아니라 명시된 한계**

### 10.1 `copytruncate`는 구제 불가

logrotate의 `copytruncate` 모드는 **복사 → 트렁케이트** 사이에 쓰인 데이터를 **잃는다.** 우리가
아무리 빨리 폴링해도 그 창을 닫을 수 없다 — 파일이 이미 잘린 뒤엔 읽을 것이 없다.

**OTel Collector도 이걸 "Known Limitations"로 인정한다.** 회피책은 하나뿐이다:
**logrotate를 `copytruncate`가 아니라 기본 `create`(move-create) 모드로 쓸 것.** 그 모드는 §4.3의
"옛 핸들 EOF 드레인"이 꼬리까지 완전히 건진다.

### 10.2 `libc::atexit`이 못 잡는 종료 (`aic-client`)

`aic-client`의 종료 flush는 `libc::atexit`이다(§4.4 — `Drop`은 `process::exit()` 40+개소에서 안
돈다). **`atexit`도 다음은 못 잡는다:**

- `SIGKILL` (`kill -9`) — 프로세스가 즉사한다. 어떤 핸들러도 안 돈다.
- `SIGSEGV` / `abort()` — 비정상 종료 경로.
- **기본 처분(default disposition) `SIGINT` / `SIGTERM`** — 핸들러를 설치하지 않은 상태에서
  받으면 `atexit` 없이 종료한다.

이 경우 **마지막 flush 주기(최대 2초) 분량의 클라이언트 로그가 유실된다.** 클라이언트 자체 로그의
운영 가치 대비 감내 가능한 범위로 판단했다 — 유실되는 건 aic CLI 자신의 진단 로그이지 호스트/
서비스 로그가 아니다.

### 10.3 self 소스는 `record_id` 충돌로 접힌다

self 소스만 자연키가 없어 내용 해시로 폴백한다(§5). 따라서 **같은 밀리초에 완전히 동일한 라인**을
두 번 뱉으면 수신 측 ReplacingMergeTree가 **하나로 접는다**(재시도 루프의 반복 WARN 등).

대안(시퀀스 번호)은 **재전송 시 키가 달라져 멱등성이 깨진다** — 그게 더 나쁘다. 자연키가 있는
3/4 소스(journald, file, container)에서는 이 문제가 **없다.**

### 10.4 ⚠ ordered ack가 **배선되지 않았다** — 최대 1배치 창의 유실 가능

**현재 체크포인트는 "라인을 채널에 넘긴 시점"에 저장된다.** 원래 규약(§4 D9)은
*"spool append(fsync) 성공 = durable → 그때 전진"* + *"연속 prefix 최댓값까지만"* 이었다.

**결과적으로 지금은 at-most-once에 가깝다:**

```
FileTail이 라인 N줄을 채널에 넣음 → 체크포인트를 그 offset으로 전진 → 저장
  → serve_logs가 아직 flush 전(배치 창 안) → 프로세스가 하드 크래시
  → 재시작: 체크포인트가 이미 지나갔으므로 그 N줄을 다시 읽지 않음 → 유실
```

**`record_id`가 자연키라 중복은 안 나지만, 유실은 막지 못한다** — 체크포인트가 이미 전진해 그
라인을 **다시 읽지 않기 때문에** 수신측 dedup이 도울 자리가 없다.

- **유실 창의 크기**: 최대 한 배치 창(`batch_max_ms = 2000` 또는 `batch_max_lines = 500` 중 먼저
  도달) 분량.
- **정상 shutdown에서는 유실이 없다** — `serve_logs`가 shutdown 시 남은 버퍼를 강제 flush한다.
  **하드 크래시(SIGKILL/panic/전원 차단)에서만** 발생한다.

**부품은 이미 있다.** `checkpoint.rs`의 `AckTracker`(`issue()` / `complete(seq)` /
`committed()` — 연속 prefix 최댓값만 전진, 구멍이 있으면 그 앞에서 멈춤)가 t4에서 구현·테스트까지
끝나 있다. **없는 것은 배선뿐이다:**

1. 각 tick이 만든 라인들을 그 배치가 발급받을 `AckTracker::issue()` seq에 매핑
2. `serve_logs`가 push 성공(**또는** spool `append()` = fsync 완료 — 둘 다 durable)했을 때
   `AckTracker::complete(seq)`를 수집기 쪽으로 콜백
3. `AckTracker::committed()`가 그 tick의 offset을 지난 뒤에야 `CheckpointStore::save()` 호출

→ **후속 티켓으로 분리한다.** 배선하려면 `LogLine`(aic-common)이 `(source_key, offset, seq)`를
실어 날라야 하고, 4개 수집기 전부와 `serve_logs`가 함께 바뀐다. 그 크기의 변경을 **5개 기존 exporter
task가 공유하는 spool/health 경로**와 같은 커밋에 섞는 것은 위험 대비 이득이 낮다고 판단했다.
**당장의 실질 위험은 "하드 크래시 시 최대 2초 분량 로그 유실"이며, 이는 관측 데이터로서 감내
가능한 범위**다(감사 기록인 `aic.events`/`aic.agent`는 이 경로를 쓰지 않는다 — 그쪽은 tap 기반이라
체크포인트 자체가 없다).

---

## 11. 미해결

- 컨테이너 로그의 severity 추론이 stdout/stderr뿐이라 거칠다. JSON 로그 파싱은 후속 RFC.
- podman(`/var/run/containers/storage/...`) 경로 규약 지원.
- `[aicd.logs.journald].units` 필터가 아직 `journalctl` 인자로 내려가지 않는다(현재는 전체 수집 후
  `max_services`로만 방어).
- §10.4의 ordered ack 배선 (후속 티켓).
