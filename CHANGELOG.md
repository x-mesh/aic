# Changelog

[Keep a Changelog](https://keepachangelog.com/) 형식. 모든 항목은 사용자가 직접 체감 가능한 변화 기준.

## [Unreleased]

### Fixed
- **v0.31.0의 스레드 필터가 커널 스레드까지 잘라내던 회귀** — 스레드 제외를
  `thread_kind().is_none()`으로 구현했는데, sysinfo는 **`Some`이라고 다 스레드가 아니다**:
  `Some(Kernel)`은 `PF_KTHREAD`가 선 커널 스레드(`[kworker/*]` 등)로 `Tgid == Pid`인 독립
  top-level 항목이고 `ps -e`에도 나온다. 그것까지 제외해 **Linux에서 관측 대상이 실제의 30%로
  줄었다** — jw-server 실측 `Tgid == Pid` 302개 중 **210개가 커널 스레드**였고 92개만 남았다.
  수신측(rca) 기준으로도 keyframe 배치가 1166 → 47(실제 173)로 떨어졌다. 그 집합 위에서 도는
  rss_spike 이상 탐지가 **그날 0건**이 됐다(직전까지 매일 14~423건). 이제 제외 대상은
  **유저랜드 스레드(`Some(Userland)`) 하나뿐**이다.

  **커버리지 손실은 조용하다** — 수신측은 aic가 보낸 것만 저장하므로 "프로세스가 47개인 서버"로
  보일 뿐 누락을 알 방법이 없다. 그래서 이 구분을 회귀 테스트로 못박았다.

## [0.31.0] - 2026-07-23

### Fixed
- **Linux에서 스레드를 프로세스로 집계하던 문제** — sysinfo의 `processes()`는 Linux에서 스레드
  (task)까지 돌려주는데 이를 걸러내지 않아, 프로세스 관측 전반이 오염돼 있었다. 실측(jw-server)에서
  `tokio-rt-worker`가 1시간 동안 고유 pid **812개**로 잡혔고 그중에는 aicd **자신의** tokio 워커
  스레드도 있었다(`/proc/<tid>/status`의 `Tgid != Pid`). 영향은 세 갈래였다: (1) top-N
  (`aic.process`)에서 스레드가 자리를 차지해 **진짜 자원 소비 프로세스가 밀려남** — ClickHouse
  호스트의 상위가 `MergeMutate`·`BgSchPool` 같은 내부 스레드로 채워졌다, (2) 프로세스 수 메트릭과
  `aic.process.inventory` 볼륨이 스레드 수만큼 부풀어 호스트/시점 간 비교가 무의미해짐,
  (3) `aic.changes`의 프로세스 start/exit 이벤트와 rss_spike가 스레드 단위로 발생.
  이제 `Process::thread_kind()`가 `Some`인 항목을 전 수집 경로에서 제외한다(프로세스 수·최대 RSS·
  top-N·인벤토리·changes, 그리고 클라이언트 `/local`의 `proc_fd_top`). **macOS에서는 `thread_kind()`가
  항상 `None`이라 no-op**이며, 그래서 이 결함은 Linux 배포 후에야 드러났다.

### Added
- **프로세스 종료 시각의 하한을 함께 보낸다 (`process.last_seen_unix`)** — `aic.process.inventory`의
  `remove` 레코드에 **직전 스캔 시각**을 싣는다. diff가 직전 스냅샷 대비이므로 사라진 프로세스는 그
  시점에 살아 있었던 것이 확정이고, 따라서 종료 시각은 `[process.last_seen_unix, 레코드 시각]` 구간
  안에 있다. 이전에는 레코드 시각(= 발견한 스캔 시각)만 보내 수신측이 수명을 **최대 한 tick만큼
  과대평가**했다 — rca 실측에서 수명이 60초에 몰리고 60초 미만이 정확히 0건으로 나온 것이 그
  증거(스캔 주기의 지문)다. 이제 수신측은 점 추정 대신 구간을 갖는다. 직전 스캔이 없으면(첫 tick)
  attr을 **생략**하므로, 이 attr을 모르는 수신측은 기존 폴백 그대로 동작한다(하위호환).

  **정확도가 아니라 정직함의 개선이다.** 실제 종료 시각은 커널 이벤트(netlink proc connector /
  eBPF `sched_process_exit`)로만 알 수 있고, 두 스캔 사이에 태어나 죽은 프로세스는 여전히 add/remove
  자체가 생성되지 않는다 — 그건 폴링의 구조적 한계이며 이벤트 기반 수집으로만 해소된다.

## [0.30.0] - 2026-07-23

### Added
- **전체 프로세스 인벤토리 CDC exporter (`aic.process.inventory`)** — aicd가 host metrics tick마다
  전수 프로세스를 이전 tick과 diff해 **변화분만**(생성 `add`/소멸 `remove`/정적 속성 변경 `change`)
  OTLP Logs로 보낸다. 기존 top-N 리소스 스냅샷(`aic.process`)이 "지금 누가 자원을 먹나"라면 이쪽은
  "무엇이 떴다 죽었나"다 — `ps`로는 얻을 수 없는 정보다(방금 죽은 프로세스는 이미 목록에 없다).
  게이지(cpu/rss/io)는 매 tick 변해 delta로 압축되지 않으므로 여기서 다루지 않는다(상태=CDC /
  메트릭=주기 스냅샷 분리). 식별자는 `(process.pid, process.start_time)` **복합키**다 — pid는
  재사용되므로 단독으로 쓰면 짧게 죽고 재사용된 프로세스가 한 시계열에 섞인다. 매 batch에 단조 증가
  `aic.process.inventory.sequence`를 실어 수신측이 갭을 감지하고, 주기적
  `aic.process.inventory.keyframe`(전체 스냅샷)으로 재동기화한다. uid/container는 정적 속성이라
  **새로 등장한 프로세스에만** `/proc`을 읽어 붙여 비용을 "매 tick 새 프로세스 수"로 묶는다.
  config `[aicd.exporter].process_inventory_enabled`(**기본 false**, opt-in — 수신측 디코더가
  준비되기 전에 켜면 collector가 partial_success로 전량 폐기한다).
- **chat에서 프로세스 변화 확인 — `/local`의 `proc_changes` 섹션과 `/procs [N]` 커맨드** — aicd가
  관측한 최근 생성/소멸을 로컬에서 바로 본다(`/local`은 요약 15줄, `/procs`는 관측 시각까지 포함해
  기본 40개, LLM 미호출). **collector 설정과 무관하게 동작한다** — OTLP 전송을 켜지 않아도 로컬 링은
  채워지므로 chat 뷰가 살아 있다. 조회 실패(aicd 미실행·구버전)와 변화 없음을 **다른 문구**로 내어
  "조용한 것"과 "고장난 것"을 구분한다. 유저스페이스 폴링이라 tick(기본 60초) 사이에 떴다 사라진
  단명 프로세스는 관측되지 않는다.

## [0.29.0] - 2026-07-16

### Added
- **프로세스별 리소스 top-N exporter (`aic.process`)** — aicd가 host metrics tick(60초)에 편승해
  CPU/메모리/디스크 IO 상위 소비자를 OTLP Logs(scope `aic.process`)로 전송한다. 각 LogRecord가
  프로세스 하나이며 `process.executable.name`·`process.pid`·`process.cpu_utilization`(%, 코어 합산이라
  100% 초과 가능)·`process.memory_rss_bytes`·`process.disk.read_bytes`·`process.disk.write_bytes`
  (직전 tick delta) attr을 싣는다. **왜 metrics가 아니라 logs인가**: host metrics는 무차원 Gauge
  (수신측이 `avg(value)`, GROUP BY 없음)라 이름/PID 차원을 못 싣는다 — 프로세스별은 필터·집계돼야
  하므로 connections와 같은 logs 경로로 보낸다. **카디널리티**: 매 tick 호스트당 최대 3N=30개
  (CPU 상위 N ∪ 메모리 상위 N ∪ 디스크 IO 상위 N, pid dedupe; N=10). 디스크를 별도 축으로 둬
  백업/로그 flush처럼 CPU·메모리는 낮고 IO만 큰 프로세스도 잡는다. 이미 refresh한 프로세스 목록을
  재사용하므로 추가 열거 비용이 없다. config `[aicd.exporter].process_enabled`(**기본 true**,
  events/connections 관례)로 끌 수 있다.

### Fixed
- **`aic daemon start`/`restart`가 설정 오류 시 재시작하지 않고 중단** — config.toml 파싱 실패나
  검증 오류가 있으면 데몬을 띄우지 않고 에러를 낸다(기존엔 조용히 기본값으로 폴백해 오설정이 묻혔다).
  start는 ping 후, restart는 기존 프로세스를 내린 뒤 preflight로 검사한다.
- **`aic update`가 셸 hook 파일을 재생성** — 바이너리 교체 후 `~/.aic/hooks.{bash,zsh}`·
  `~/.aic/hook-events.{bash,zsh}`을 최신 내용으로 다시 쓴다. hook 포맷이 바뀐 버전으로 업데이트해도
  사용자가 `aic init`을 다시 돌릴 필요가 없다(구 hook로 인한 명령 이벤트 유실 방지).

## [0.28.0] - 2026-07-16

### Added
- **connections에 방향(`direction`)과 프로세스명(`process`) 추가** — `aic.connections` LogRecord에
  `aic.connection.direction`(`listen`|`inbound`|`outbound`)과 `aic.connection.process` attr이 붙는다.
  수집 명령이 Linux는 `ss -tuna` → **`ss -tunap`**, macOS는 `lsof -nP -iTCP -iUDP` →
  **`lsof -nP +c 0 -iTCP -iUDP`**로 바뀌었다(각각 프로세스 정보 획득, COMMAND truncate 해제).
  - **방향은 스냅샷 전체를 보고 파생한다** — peer 없는 소켓의 `(protocol, local_port)` 집합이 이
    호스트의 서비스 포트고, peer가 있는 소켓의 local_port가 거기 속하면 우리가 accept한 `inbound`,
    아니면 우리가 건 `outbound`다. `state` 문자열이 아니라 peer 유무로 판정하므로 LISTEN 상태가
    없는 UDP도 올바르게 분류된다. 이전까지 수신측(rca)은 "LISTEN이 아니면 무조건 outbound"로 추론할
    수밖에 없어 **`inbound`가 한 건도 생기지 않았다.**
  - **알려진 제약(Linux)**: `ss -p`는 타 사용자 소유 소켓의 프로세스를 읽으려면 root/CAP_SYS_PTRACE가
    필요한데 aicd는 user unit이라, sshd/nginx 같은 root 데몬 소켓은 **프로세스명이 빈 채로 나간다**
    (수집 실패가 아니라 정상 경로 — 해당 attr을 생략한다). **방향 판정은 이 권한과 무관하게 항상
    정확하다** — `ss`는 권한 없이도 전역 소켓 *목록*은 다 보여주기 때문이다. macOS는 lsof가
    user-scoped라 반환된 행에는 프로세스명이 모두 채워진다.
  - 두 attr 모두 값이 없으면 **생략**되므로, 구 버전 수신측/발신측과 섞여도 회귀가 없다.
- **aicd OTLP host-metrics exporter (opt-in, SRE t6)** — config `[aicd.exporter]`(`enabled`/`endpoint`/
  `token`/`interval_secs`)를 켜면 aicd가 주기적으로 host metrics(cpu/load/mem/swap/disk·net i/o)를
  sysinfo로 수집해 OTLP protobuf로 인코딩한 뒤 `{endpoint}/v1/metrics`(Content-Type
  `application/x-protobuf`, 선택적 `Authorization: Bearer`)로 push한다. **기본 비활성**이며, 끄면 관련
  task 자체가 뜨지 않아 기존 동작에 회귀가 없다. 전송하는 **모든 문자열 필드(hostname 포함)는
  redaction을 거쳐** secret/PII가 collector로 새지 않는다. 실패 시 다음 주기까지 단순 skip한다
  (spool/backoff·events tap은 후속 범위).
- **aicd OTLP events/connections exporter (opt-in, SRE t7)** — 같은 `[aicd.exporter]`에 하위 플래그
  `events_enabled`/`connections_enabled`/`connections_interval_secs`(각각 기본 true/true/60)를
  추가했다. `enabled=true`일 때:
  - **events**: `CommandRecordStore`에 broadcast tap을 달아, 세션 ring에 finished command record가
    실제로 삽입될 때(dedup으로 skip된 push는 제외) OTLP LogRecord(scope=`aic.events`, exit_code≠0이면
    severity=ERROR·아니면 INFO, attrs: `aic.record.id`/`aic.command.text`/`aic.command.exit_code`/
    `aic.command.capture_quality`)로 인코딩해 실시간으로 `{endpoint}/v1/logs`에 push한다.
  - **connections**: 기본 60초마다 `aic snapshot inventory --json`(신규 hidden CLI leaf)을 spawn해
    LISTEN/ESTABLISHED 소켓(Linux `ss -tuna`, macOS `lsof -nP -iTCP -iUDP`)과 host IP를 얻어
    OTLP LogRecord(scope=`aic.connections`, attrs: `network.transport`/`aic.connection.state`/
    `network.local.address`/`network.local.port`/`network.peer.address`/`network.peer.port`)로 배치
    push한다. resource에 `host.ip`도 갱신한다.
  - **`aic.agent.ntp_offset_ms`**: host metrics에 조건부로 추가되는 Gauge — Linux 커널의
    `adjtimex`(로컬 clock discipline 상태, **네트워크 NTP 질의 없음**)에서 얻을 수 있을 때만 보낸다.
    macOS 등 non-Linux는 안전한 no-network local API가 없어 생략한다(과설계 금지 — 값이 빠질 뿐 나머지
    host metrics는 그대로 나간다).
  - events/connections 둘 다 host metrics와 동일하게 실패 시 재시도 없이 다음 이벤트/주기로 넘어간다
    (spool/backoff는 t8 범위). **예외**: `network.*`/`host.ip` 값은 redaction을 건너뛴다 — 이
    exporter의 목적 자체가 실제 IP 토폴로지를 보내는 것이라, 일반 redaction의 IPv4 패턴을 그대로
    적용하면 모든 연결이 `[REDACTED:ipv4]`로 뭉개져 기능이 무의미해지기 때문이다(command text 등
    "우연히 섞여든" 문자열은 계속 redact).
- **aicd OTLP exporter 오프라인 spool/backoff (SRE t8)** — collector가 다운돼도 host metrics/
  events/connections push 실패분을 유실 없이 버티도록 두 가지를 추가했다.
  - **spool**: push 실패 시 이미 redact·인코딩된 protobuf 결과를 `~/.aic/otlp-spool/`(0700 권한)에
    파일 단위 배치로 적재한다. 상한(config `spool_max_bytes`, 기본 256MiB)을 넘으면 가장 오래된
    배치부터 삭제(oldest drop)하며 카운터를 올린다(`AIC_DEBUG` 로그). collector 복구 후 host
    metrics task가 매 tick FIFO 순서로 드레인한다(배치당 HTTP 요청 1개, `spool_drain_batch_limit`
    기본 20으로 속도 제한 — 밀린 만큼 한 번에 몰아치지 않음).
  - **backoff**: 연속 실패마다 재시도 간격을 1s→2s→4s→...→60s(cap)+jitter로 늘려, 죽은 collector를
    매 tick마다 두들기지 않는다. 성공하면 즉시 리셋. backoff 윈도 안에는 네트워크 시도 자체를
    건너뛰고 새 데이터를 spool에만 쌓아 둔다(무유실).
  - 세 exporter task가 spool 인스턴스 하나를 공유하지만, 드레인은 host metrics task만 담당한다
    (`enabled=true`면 `events_enabled`/`connections_enabled`와 무관하게 항상 뜨는 유일한 task라
    드레인 주체가 항상 존재함을 보장할 수 있어서다). events/connections는 자기 push 실패만 spool에
    적재하고 backoff도 독립적으로 관리한다.

- **chat status bar에 exporter 상태 표시** — exporter는 aicd 안에서 조용히 돌기 때문에, 전송이
  실패해도 aicd 로그에만 WARN이 남고 chat을 쓰는 사람은 "내 데이터가 서버로 나가고 있다"고 **믿을
  뿐 확인할 방법이 없었다**(실제로 exporter 없는 구버전 aicd가 도는 동안 아무도 눈치채지 못한
  사고가 있었다). 이제 status bar 맨 뒤에 한 칸이 붙는다:
  - `otlp ●` (dim) — 정상 전송 중
  - `otlp aicd off` (빨강) — aicd 미실행 또는 `GetExporterStatus` 이전 구버전. **데이터가 전혀
    나가지 않고 있다**는 뜻이다.
  - `otlp ⚠ N밀림` (주황) — push 실패로 spool에 N개 배치가 밀려 있다(collector에 못 닿는 중).
  - `otlp ✕ N유실` (빨강) — spool 상한을 넘겨 N개를 실제로 버렸다. 밀림보다 먼저 알린다.

  config에서 exporter를 안 켠 경우에는 **아무것도 표시하지 않는다** — 안 쓰는 기능을 계속 띄우면
  노이즈다. 상태는 aicd에 `GetExporterStatus`로 묻고 2초 캐시를 둔다(status bar 갱신 빈도와 무관하게
  IPC는 그 주기로만 나간다). 네 exporter task(host metrics/events/connections/agent)가 전송 성패
  카운터를 공유하므로, 어느 signal이 실패했는지가 아니라 "이 호스트의 텔레메트리가 서버에 닿고
  있나"를 한 칸으로 답한다.
- **chat/agent 행위 exporter (opt-in, OTLP `aic.agent` scope)** — chat에서 일어난 **주목할 만한
  행위**를 aicd로 넘겨 collector로 push한다. 하위 플래그 `[aicd.exporter] agent_enabled`(기본 true,
  부모 `enabled`가 실제 게이트)로 끌 수 있다. 보내는 것은 세 종류뿐이다:
  - `tool.run_command` — agent가 셸 명령을 **실행**했다(시스템을 바꿨을 수 있는 유일한 도구).
    명령어·exit_code·duration·cwd만 싣고 **출력 본문은 보내지 않는다**. exit≠0이면 severity=ERROR.
  - `risk.denied` — risk_guard가 명령을 **차단**했다(Dangerous/Unknown 등급, 또는 샌드박스 검증
    실패). 실행되지 않았어도 위험한 시도가 있었다는 신호라 항상 WARN으로 보낸다.
  - `finding.created` — 진단이 finding을 만들었다. Crit=ERROR / Warn=WARN으로 매핑한다.

  chat 대화·LLM prompt/response·읽기 도구(read_file/grep/glob) 실행은 **보내지 않는다** — RCA에
  쓸모없는 노이즈다. 전송 문자열은 프로세스 경계를 넘기 전에 redaction을 거친다.

  구조는 shell hook이 command를 넘기는 것과 같다: chat은 단명 프로세스라 collector 연결·spool·
  backoff를 직접 들 수 없으므로, 행위를 IPC(`IpcRequest::AgentEvent`)로 aicd에 넘기고 상주 데몬의
  exporter가 무유실 전송을 책임진다. aicd 미실행이면 chat 쪽은 조용히 skip한다(정상 경로).
- **host metrics 항목 확대 (13종 → 26종)** — 기존 cpu/mem/swap/fs/disk-io/net-io에 더해:
  `system.cpu.load_average.5m`·`.15m`(1m과 함께 봐야 "치솟는 중"과 "계속 높음"이 구분된다),
  `system.cpu.logical.count`(load를 코어 수로 정규화해야 호스트 간 비교가 된다),
  `system.memory.available`(캐시는 회수 가능하므로 OOM 여유는 used가 아니라 이 값),
  `system.swap.utilization`, `system.filesystem.usage`·`.utilization`,
  `system.network.packets.receive`·`.transmit`(bytes만으로는 작은 패킷 폭주가 안 보인다),
  `system.network.errors.receive`·`.transmit`(평소 0이라 0이 아닌 순간 자체가 신호),
  `system.process.count`, `system.uptime`. 전부 기존과 같이 순간값 Gauge다.
- **`aic daemon status`가 실행 중인 aicd의 버전을 표시** — IPC에 `GetVersion`을 추가해, 디스크의
  binary가 아니라 **지금 도는 프로세스**에 직접 빌드 identity(version/commit/build_info)를 묻는다.
  이 CLI와 다른 빌드가 돌고 있으면 경고와 함께 `aic daemon restart`를 안내한다. `GetVersion`을 모르는
  구버전 데몬은 graceful `Error`로 응답하므로, 그 응답 자체를 "구버전이 돌고 있다"는 신호로 삼는다
  (`version: unknown`). `aic-session`도 같은 요청에 자기 빌드로 답한다.
- **`/record now <메모>` — 지금 이 순간을 강제 기록** — 임계와 무관하게 현재 시스템 스냅샷을 즉시
  캡처해 **로컬 스냅샷 store에 저장**하고, 메모가 있으면 OTLP `snapshot.recorded` 이벤트로도 보낸다.
  로컬 저장이 본체라 **aicd 미실행이어도 메모는 남는다**(원격은 부가 경로). 이벤트 attrs에는 그 순간의
  자원 지표를 싣는다: `cpu_utilization`·`memory_utilization`·`swap_utilization`·`load_1m`·
  `filesystem_avail_bytes`에 더해 **`cores`(load 정규화용), `memory_total_bytes`/`swap_total_bytes`
  (백분율의 분모), `top_mem_proc_name`/`top_mem_proc_rss_bytes`(메모리 최다 프로세스)**를 첨부한다.
  status bar 표시 여부와 무관하게 지표가 자기완결적으로 수집된다. CLI는 `aic snapshot record --memo`.
- **connection 누적 트래픽(`bytes_sent`/`bytes_recv`)** — `aic.connections` LogRecord에 소켓별 누적
  송수신 바이트가 붙는다. Linux `ss -i`의 tcp_info(`ss -tunap` → **`ss -tiunap`**)에서 얻으며,
  지원하지 않는 플랫폼/프로토콜(macOS lsof 등)은 0이다. RCA topology가 엣지 트래픽을 표현하는 데
  쓴다. 값이 커널의 u64 범위를 넘으면 OTLP int64 최댓값에 고정한다.
- **DNS observer (opt-in, `aic.dns` scope)** — `[aicd.exporter] dns_enabled`(기본 false, opt-in —
  도메인은 운영/PII 정보)를 켜면 aicd가 프로세스의 이름 해석(FQDN↔IP)을 관측해 OTLP
  Logs(scope=`aic.dns`, attrs: `dns.question.name`/`.type`·`dns.answers`·`dns.ttl`·`aic.dns.source`
  등)로 push한다. RCA가 connection의 숫자 IP에 실제 도메인을 붙이는 신호다. **관측 백엔드는 eBPF
  getaddrinfo uprobe(Linux 전용)로, 현재 골격이다** — `dns_enabled`를 켜도 아직 데이터는 나가지 않고
  (인코딩 계약·task 배선까지 완성), 미지원 플랫폼/권한 부족이면 no-op이다.
- **`/flush` 명령 — spool 즉시 전량 드레인** — collector 복구 직후 밀린 배치를 기본 rate-limit
  (`spool_drain_batch_limit`)에 얽매이지 않고 한 번에 전부 재전송한다(급할 때 수동 드레인).
- **spool 나이 cap (`[aicd.exporter] spool_max_age_secs`)** — 설정하면 그보다 오래된 spool 배치를
  드레인 직전에 네트워크 없이 드롭해, collector가 오래 다운돼 쌓인 낡은 배치 뒤에 최근 이벤트가 갇히지
  않게 한다. **기본 `None`(무제한 — 기본으로는 어떤 데이터도 지우지 않는다)**, 명시할 때만 적용된다.

### Fixed
- **`make install` / `aic update` 후 구버전 aicd가 계속 도는 문제** — 두 경로 모두 세 binary를
  교체하지만 이미 떠 있는 aicd는 자기 메모리의 옛 코드로 계속 돌아, 재시작 전까지는 새로 추가된
  기능(예: OTLP exporter)이 config에 켜져 있어도 조용히 동작하지 않았다. 경로가 같아 `stat`으로는
  구분되지 않고, 미출시 빌드는 semver까지 같을 수 있어 `--version` 비교로도 잡히지 않는다. 이제
  `make install`은 설치 후 `aic daemon restart --if-running`을 호출하고, `aic update`는 binary를
  실제로 교체했을 때(`Outcome::Replaced`) 재시작까지 수행한다. 자동 시작 unit이 설치되어 있으면
  launchd(`launchctl kickstart -k`)/systemd(`systemctl --user restart`)에 재시작을 맡긴다 —
  `KeepAlive`/`Restart=on-failure`가 걸려 있어 우리가 직접 죽이고 띄우면 매니저의 재기동과 singleton
  PID lock을 두고 경쟁하기 때문이다. `--if-running`은 aicd가 꺼져 있으면 아무것도 하지 않아, 설치가
  데몬을 새로 띄우는 부작용을 만들지 않는다.
- **OTLP push 실패 로그에 실제 원인 보존** — 예전엔 exporter push 실패가 `error sending request for
  url (...)`이라는 reqwest 껍데기 메시지만 남겨, 수신 서버가 잠깐 죽은 건지(connection refused/reset)
  keep-alive 연결이 만료된 건지(closed before message completed) 구분할 수 없었다. 이제 에러의 source
  chain을 끝까지 이어 붙여 진짜 원인을 로그에 남긴다(무유실 동작은 그대로 — spool 적재로 복구).
- **status bar가 exporter 상태를 오보하던 문제** — (1) status 쿼리가 잠깐 느려 timeout이 나면 살아
  있는 aicd를 "aicd off"로 오보하던 것을 직전 상태 유지로 바로잡았다. (2) status bar가 agent exporter
  전송 유실을 숨기던 맹점을 수정했다.
- **status bar를 끈 세션에서 주기 캡처가 계약과 다르게 동작하던 회귀** — `/record now`가 status bar
  표시 여부와 무관하게 지표를 얻도록 sampler를 상시 구동하면서, `AIC_NO_STATUSBAR`/`AIC_QUIET` 세션에서
  `/record on`이 주기 캡처를 시작해 "status bar가 꺼지면 주기 캡처는 살지 않는다"는 계약을 깨던 것을
  막았다(지표 캐시 갱신은 유지, 주기 캡처만 status bar 활성 시로 게이트).

### Changed
- **redaction 로직을 `aic-common`으로 이동** — LLM prompt(aic-client)와 OTLP exporter(aic-server)가
  동일한 secret/PII 마스킹을 공유하도록 `redaction` 모듈을 `aic-common`으로 옮겼다. 기존
  `aic_client::redaction::{redact, RedactionReport}` API는 re-export로 그대로 유지되어 호출부 변경이
  없다.

### 결정 근거
- OTLP protobuf 인코딩에 `opentelemetry-proto` 대신 **prost 직접 + 최소 메시지 subset**을 썼다.
  opentelemetry-proto의 `gen-tonic(-messages)`는 tonic/grpc 스택을 끌어오는데, 우리는 OTLP/HTTP로
  Gauge + resource attrs만 보내므로 과한 의존성이다. 필요한 message만 필드 번호까지 스펙과 맞춰
  정의하고 encode/decode 왕복 테스트로 wire 유효성을 검증한다.
- config 키는 repo 관례(`dedup_ttl_secs` 등 단위 suffix)를 따라 `interval_secs`로 명시했다.

## [0.27.0] - 2026-06-30

### Added
- `aic web` resource charts are now investigable: hover or click a chart to pin a moment and see that instant's CPU/mem/load/disk/net plus the top CPU/memory processes (click to drill in) and any threshold events at that time. ResourceEvent threshold transitions are overlaid as severity-colored markers, with 1m/5m/10m zoom and wall-clock axis labels (the 10-minute ring buffer is unchanged).
- `aic web` incident-now banner under the header aggregating worst-state across signals (resource crit/warn, open incidents + worst severity, latest webhook alert, aicd online, audit-chain validity), each segment clicking through to its tab.
- `aic web` URL hash deep-links — the active tab and the open process/incident/chat-session are reflected in the URL and restored on load, so a shared dashboard URL lands on the exact view.
- `aic web` chart moment → External query deep-link: pick a moment on a chart and jump to the External tab with the Prometheus/Loki query window anchored on that timestamp.
- `aic web` Server log tab tailing aicd's own daily-rotated JSON log (redacted, fixed app-owned path); client-side filter boxes on the audit/history/webhooks/incidents tables; snapshot N-vs-N-1 diff (changed/new section badges); and a "similar past incidents" button on an incident.
- `aic rca diagnose [id]` re-runs the headless Safe-probe diagnose into an existing incident so evidence accumulates across rounds and converges on the cause.
- `aic rca bundle [id]` exports a full incident (meta + evidence + hypotheses + report) as a single shareable redacted markdown bundle.
- RCA ↔ sre-agent incident-memory bridge (best-effort, no-op without sre-agent): `aic rca similar [id]` finds similar past incidents, `aic rca runbooks [id]` asks for recommended runbooks, and `aic rca close --remember` (or `[rca] auto_remember`) hands a closed incident off to sre-agent.

### Changed
- `/web/incidents` now exposes incident severity and `/web/webhooks` now exposes the alert fingerprint, so the dashboard can color incidents by severity and tie deduplicated alerts together.

### Security
- The new `/web/serverlog` reads only the fixed app-owned state directory (no caller-supplied path, no traversal); the incident-memory bridge reads via MCP only, whose responses the client redacts and caps. The dashboard stays read-only.

## [0.26.0] - 2026-06-30

### Added
- **`aic rca` 인시던트 워크플로 대폭 확장** — evidence 저장소를 넘어 원인 분석 도구로:
  - **lifecycle + MTTR** — `aic rca mitigate|close|reopen`으로 상태를 전이하고(전이는 timeline에
    evidence로 기록), 종료 시 MTTR(time-to-resolve)·TTM(time-to-mitigate)을 계산해 report의 Resolution
    섹션에 싣는다.
  - **`aic rca observe`** — incident 시간창([created−before, closed/now])으로 등록된 Prometheus/Loki를
    질의해 결과를 Observability evidence로 첨부한다(redacted, 등록 백엔드만).
  - **`aic rca hypothesis`** — 후보 root cause를 추가하고 `support`/`refute`/`confirm`/`reject`로 좁혀
    probable cause에 수렴시킨다. report에 Probable Cause + Hypotheses 섹션.
  - **`aic rca severity`** — sev1~4 triage 심각도(`--severity`로 생성 시 지정 가능, status/report/list에 표시).
  - **`aic rca note`** — 조사 중 관찰을 수동 evidence로 기록한다.
- **`aic web` 프로세스 드릴다운** — top CPU/메모리 프로세스를 클릭하면 상세를 보여준다: 명령행·exe·cwd
  (redacted), 네트워크 소켓(listen 포트·연결 수, peer IP 마스킹), read-only runtime 상태(state·blocked-in
  심볼·threads·context-switch).
- **`aic web` CPU 스택 샘플 (기본 활성)** — 프로세스의 self-time hot frame을 구조화해 보여준다
  (macOS `sample`, Linux `perf`). 표시된 top 프로세스로 범위 제한 + single-flight + timeout + redaction으로
  공유 대시보드에서도 안전하다. 끄려면 `aic web --no-stack-sample`.
- **`aic trace <pid>`** — 운영자용 프로세스 트레이스(Linux strace / macOS sample). confirm gate + timeout +
  redaction을 거치며, 침습적이라 web 대시보드에는 노출하지 않는다.

### Fixed
- **RCA incident workspace 견고성** — meta/index/report를 원자적(temp+rename)·내구적으로 쓰고, incident
  목록을 디렉터리 스캔으로 권위화해(corrupt index가 incident를 숨기지 못함) 손상된 evidence 줄은 건너뛴다.
  동시 append를 flock으로 직렬화하고(중복 id 방지), incident id 충돌과 path traversal을 막으며, redaction을
  metadata까지 확장했다.
- **webhook 이벤트 tail을 전체 파일 로드 없이 읽기** — 큰 `webhook-events.jsonl`도 요청당 비용이 표시 개수에
  바운드된다.

### Security
- **`aic web` 추가 하드닝** — web 접근 감사 로깅(인증 실패·민감 read), CSP/Referrer-Policy/Cache-Control
  헤더, MAC 주소 마스킹, 내부 에러 메시지 누출 차단, metrics/logs 프록시 본문 크기 제한, `/web/local` 증분
  폴링.

## [0.25.0] - 2026-06-25

### Added
- **`aic web` 로컬 대시보드 (MVP-0)** — 토큰으로 게이트되는 read-only 웹 대시보드를 on-demand로 띄운다
  (`aic web`). 라이브 로컬 자원 차트(CPU·메모리·디스크·네트워크)를 zero-config·self-contained로
  제공하고, metrics/logs 쿼리 엔드포인트와 차트 대시보드를 포함한다.
- **chat 관찰(observability) 탭** — 대시보드에서 실행 중·과거 `aic chat` 세션을 추적한다. chat run
  registry가 세션 메타데이터를 기록하고, 프로세스 fallback으로 registry에 없는 활성 세션도 노출한다.

### Security
- **web 대시보드 보안 하드닝** — path traversal 차단, incident 목록의 민감정보 redaction, SSRF 및 응답
  헤더 방어를 적용했다.

## [0.24.0] - 2026-06-23

### Added
- **LLM 미등록 세션 지원** — provider가 하나도 등록되지 않아도 `aic chat`이 status bar와 진단 slash
  명령(`/local`·`/watch`·`/metrics`·`/logs` 등)을 그대로 제공한다. 이전에는 LLM이 없으면 최소
  line REPL로 빠져 하단 status line이 표시되지 않았다. 이제 LLM 미등록 시 agent UI로 진입하되 채팅
  답변만 비활성화한다.

### Changed
- **LLM 미등록 경고를 세션 시작 시 표시** — 메시지를 입력한 뒤에야 cryptic한 provider 에러를 보던 것을,
  진입 즉시 "등록된 LLM provider가 없습니다" 경고 + provider 등록 방법·LLM 없이 동작하는 명령 안내로
  바꿨다. 미등록 세션에서 일반 채팅은 등록 안내만 내고 LLM을 호출하지 않는다.
- **`/local`은 LLM 미등록 시 raw 스냅샷으로 자동 degrade** — 분석(analyze) 모드가 LLM을 필요로 하므로,
  provider가 없으면 raw 시스템 스냅샷을 바로 보여준다.

## [0.23.0] - 2026-06-20

### Added
- **세션 스냅샷 레코더 (L0–L3)** — opt-in(`AIC_SNAPSHOT_RECORD=1`, 기본 off)으로 시스템 스냅샷을
  `~/.aic/snapshots/`에 영속 기록한다. **(L0)** `/compare` 스냅샷을 JSONL append(0600 atomic, 최근
  200개 self-heal trim). **(L1)** `aic chat` status bar 샘플러가 자원 악화(Normal→Warn↑)를 감지하면
  전체 `/local` 스냅샷을 자동 캡처. **(L2)** `aic snapshot install`로 주기 캡처 타이머(macOS launchd /
  Linux systemd-user)를 설치하고 `aic snapshot capture|list|status|uninstall` CLI로 제어. **(L3)** Crit
  전이 시 `AIC_AUTO_RCA=1`이면 진단 증거를 모아 RCA 인시던트를 LLM 호출 없이 자동 생성. 동시 writer는
  process-internal Mutex + cross-process flock으로 직렬화(잃은 쓰기 0).
- **chat `/record`, `/snapshots` 슬래시 명령 + `● REC` 인디케이터** — `/record [on|off|now]`로 세션
  스냅샷 자동 기록을 토글(`now`=즉시 1회 캡처, 게이트 우회), `/snapshots [N]`으로 store 최근 N개(기본
  10)를 메타만 inline 조회. 기록 중에는 status bar 선두에 빨강 `● REC`가 표시된다. (`/snapshot` 단수는
  기존 `/local` 별칭 유지.)
- **RCA workspace (`aic rca`) + `/rca` 슬래시** — RCA를 incident id 기준으로 `~/.aic/incidents/<id>/`에
  영속 저장한다(evidence.jsonl 0600 / report.md, incident dir 0700). `aic rca start|status|timeline|report`,
  `--diagnose`로 headless `/diagnose` 엔진을 재사용해 초동 증거를 첨부. chat에서는 `/rca start|use|add|timeline|report`로
  대화 증거를 워크스페이스에 적립한다.
- **`aic diagnose --json` + typed Finding 모델** — 진단 결과를 machine-readable 봉투
  (`{schema_version, diagnosis}`, snake_case enum)로 출력한다. severity/confidence/probe_id를 갖는 통합
  Finding 모델로 `/local`·`/diagnose`에 결정적 발견을 노출하고, 결정적 임계 스캔을 inodes/fd/swap까지
  확대(macOS `df -i` `%iused='-'` 오탐 수정).
- **read-only probe 확대 + baseline 엔티티 diff** — `kernel_limits`/`cpu_count`/`timer_schedule`/
  `mac_thermal`/`cron_jobs`/`dns_resolver`/`launchd_failed` probe 추가(전부 read-only Safe). 실패
  systemd 유닛에는 실행 가능한 값만 노출하는 `journal_unit <unit>` follow-up hint를 달고, `/compare`는
  신규 listening 포트·실패 유닛을 set diff로 보고(ephemeral ≥32768 제외).

### Changed
- **risk_guard read-only safelist 확장** — `pmset -g`/`launchctl list`/`crontab -l`(stdin `-` 차단)/
  `scutil --dns` 등 **읽기 전용 형태만** 자동 실행(Safe)으로 허용한다. 상태 변경·임의 파일/stdin 입력
  형태는 Safe에서 제외해 secret 자동 read 표면이 늘지 않도록 한다.

## [0.22.0] - 2026-06-16

### Added
- **chat: MCP 도구 서버 연동(HTTP)** — config `[mcp.servers.<name>]`에 등록한 MCP 서버(예: mem-mesh
  메모리)의 tool을 `aic chat` 에이전트가 직접 호출한다. Streamable HTTP transport(initialize/tools/list/
  tools/call), 발견된 tool은 `<server>__<tool>` 이름으로 노출. `auto_approve`에 적은 read-only tool은
  자동 실행, 변경 tool(add/delete 등)은 실행 전 확인을 받는다. SSRF 방어·응답 redaction·크기 cap을
  obs 백엔드와 동일하게 적용하고, 서버 다운/지연 시 해당 서버만 건너뛴다(graceful degrade).

### Fixed
- **chat: `AIC_NO_STREAM`이 에이전트 chat 루프에도 적용** — 기존엔 에러 분석 경로만 streaming opt-out을
  존중했고 tool-calling chat 루프는 무시했다. 이제 두 경로 모두 `AIC_NO_STREAM`으로 끌 수 있다.

## [0.21.0] - 2026-06-16

### Added

- **chat:** stream LLM responses token-by-token with spinner
- **chat:** /watch alert toggle + recovery notes (C7)
- **chat:** metric sparkline + delta arrow (C2b)
- **chat:** disk exhaustion ETA (C2a)
- **chat:** name top mem process in alerts (proc-enrich)
- **chat:** edge-triggered system alerts (C1)
- **chat:** off-thread sysinfo sampler (C4), fix status freeze

## [0.20.0] - 2026-06-13

### Added
- **SRE 심층 probe 10종(R8)** — 기존 catalog가 못 보던 고신호 신호를 추가해 "디스크가 꽉 찼나"뿐
  아니라 "디스크가 느린가(iowait/await)", "이미 누가 OOM으로 죽었나", "어떤 서비스가 안 떴나"까지
  진단한다. `journal_errors`(systemd 에러 로그)·`dmesg_oom`(커널 OOM-killer)·`iostat_devices`
  (per-device I/O await/%util)·`vmstat_iowait`(iowait/run-queue)·`failed_units`(실패 systemd 유닛)·
  `conntrack_max`(연결추적 테이블 포화)·`listen_backlog`(accept-queue 포화)·`time_sync`(NTP/clock
  skew)·`block_topology`(블록디바이스/ro 리마운트)·`reboot_history`(재부팅 이력). `/diagnose`(증상
  카테고리)·`/triage`·`/watch`에서 자동 선택되며, `journal_unit` follow-up 템플릿으로 실패 유닛 →
  해당 unit 로그 2-hop 추적이 가능하다. Linux 전용 도구는 macOS에서 동등 read-only 명령으로 대체.
- **결정적 임계 스캔(annotation)** — `/diagnose` 증거에서 LLM 호출 없이(오프라인/`--no-analyze`에서도)
  확실한 위반만 골라 증거 상단에 `## ⚠ 자동 발견` 으로 고정한다: 디스크 사용률 ≥90%(실제 쓰기가능
  마운트만 — snap/iso9660/DMG/ESP 등 항상-가득 read-only는 제외), 커널 OOM-killer 흔적, 누적 좀비
  프로세스(≥10), 실패한 systemd 유닛. 오탐이 신뢰를 깎으므로 보수적으로(확실한 신호만) 잡는다.
- **chat status bar 임계 컬러링** — 하단 status bar의 라이브 지표(load·cpu·mem·swap·disk free)에
  임계 2단계를 둬 위반 지표만 **주황(warn)→빨강(crit)**으로 칠한다(정상은 기존 dim). 어느 자원이
  문제인지 한눈에. 임계는 보수적(cpu≥85/95%·mem≥90/97%·swap≥50/90%·load≥코어수/2배), disk는
  macOS APFS 사용률 % 부정확을 피해 **신뢰 가능한 free bytes 절대값**(≤5G/≤1G)으로 판정.

### Changed
- **risk_guard read-only safelist 확장** — `journalctl`/`dmesg`/`iostat`/`vmstat`/`systemctl`/
  `timedatectl`/`last`/`lsblk` 의 **읽기 전용 형태만** 자동 실행(Safe)으로 허용한다. 상태 변경/파괴
  형태는 차단: dmesg ring buffer clear(`-C`/`-c`/묶음 `-Tc`)·follow(`-w`/`-W`), journalctl
  rotate/vacuum/flush·follow(`-f`/묶음 `-fn`)·임의 파일 소스(`--file`/`--root`/`-D`), systemctl
  start/stop/restart/mask 등(read 서브커맨드만 carve-out), timedatectl `set-*`, vmstat/iostat
  interval-only·count=0(무한스트림), last 임의 wtmp(`-f`/`--file`). `--no-pager` 강제로 pager hang
  방지. secret 파일 자동 read 표면이 새로 생기지 않도록 임의 파일/경로 입력 옵션은 Safe에서 제외.

## [0.19.0] - 2026-06-11

### Added
- **diagnose follow-up probe 자동 실행** — 1차 분석에서 LLM이 ```` ```aic-followup ```` 블록으로
  제안한 추가 probe를 4층 직렬 게이트(catalog/템플릿 id 한정 → 인자는 1차 증거에 실존하는 값만 →
  risk_guard Safe → validator) 통과분만 1라운드 자동 실행하고 합산 증거로 재분석한다.
  상한: 명령 3개·출력 16KB. 거부된 제안은 사유와 함께 번들에 기록(투명성).
  `[aicd.webhook] follow_up`(기본 off) 또는 `aic diagnose --follow-up`으로 opt-in.
- **`/local` 다중 섹션 + docker 섹션** — `/local disk memory`처럼 섹션을 여러 개 지정할 수
  있다(알 수 없는 섹션이 섞이면 이름을 들어 전체 거부). docker 설치 호스트에서는
  `docker_ps`/`docker_stats`/`docker_df`가 기본 스냅샷에 자동 포함된다(미설치면 노이즈 0).
- **`--version` 빌드 메타데이터** — `aic`/`aic-session`/`aicd`가
  `0.19.0 (b652397* develop, 2026-06-11T00:17:09Z)` 형식으로 commit/브랜치/dirty(`*`)/빌드
  시각을 표시한다. chat 배너에도 `v0.19.0+<hash> (<branch>)`로 노출. git 밖 빌드는 버전+시각만.
- **chat TUI 드래그 복사** — 로그 영역을 좌클릭 드래그하면 줄 단위로 선택(반전 강조 +
  "N줄 선택 중" status)되고, 놓으면 클립보드에 복사된다. 복사는 OSC 52 +
  pbcopy/wl-copy/xclip fallback 병행. Ctrl+Y(전체 복사)·Ctrl+T(네이티브 선택)는 유지.

### Changed
- **macOS도 chat TUI 기본** — 한글 IME 조합 충돌(자모 분리/커서 밀림)이 하드웨어 커서 정렬과
  입력 대기 중 redraw 금지로 해소되어, macOS 기본을 Direct(reedline)에서 TUI로 전환했다.
  `AIC_NO_TUI=1`로 이전 동작 복귀(`AIC_CHAT_TUI`는 no-op).

## [0.18.1] - 2026-06-10

### Changed
- 저장소 정비만 포함(런타임/기능 변화 없음) — `AGENTS.md`를 `CLAUDE.md` 심볼릭링크로 통합하고,
  에이전트용 git-kit 워크플로우 안내 블록을 갱신했다.

## [0.18.0] - 2026-06-10

SRE 로드맵 R0–R5 — `aic`를 단일 머신 진단 도구에서 관측 백엔드·k8s·webhook까지
다루는 SRE 보조 도구로 확장한다.

### Added
- **관측 백엔드 read-only 질의 (R1)** — `[observability.backends.<name>]`에 등록한
  Prometheus/Loki/Elasticsearch(VictoriaMetrics는 Prometheus 호환)에 질의해 진단 근거를
  로컬 sysinfo 너머로 확장한다. `/metrics`·`/logs` slash 명령(LLM 미호출 redacted raw) +
  LLM tool-calling 노출. SSRF 방어(redirect 차단·link-local 차단·backend allowlist),
  응답 bounded(512KB/64KB), Bearer·conn-string redaction.
- **headless 진단 + `aic diagnose` CLI (R0)** — TTY 없이 증상→읽기전용 Safe probe 수집→
  redacted 증거(+옵션 LLM 분석)를 stdout markdown으로 출력. cron/스크립트/webhook spawn용.
  `aic diagnose [증상] [--no-analyze] [--bundle --name N] [--provider P]`.
- **webhook 알림 → 자동 초동 진단 (R2)** — aicd가 Alertmanager/Grafana/PagerDuty/generic
  webhook을 수신해 firing alert마다 `aic diagnose --bundle`(읽기전용+증거 번들)을 자동
  spawn. 온콜이 터미널을 열기 전에 증거가 준비된다. `[aicd.webhook]`(기본 off, 127.0.0.1:9099),
  HMAC-SHA256/Bearer 인증·rate limit·5분 dedup. `aic webhook list [--json]`.
- **k8s 네이티브 probe + `/triage k8s` (R3)** — kubectl 기반 read-only 진단 4종
  (notready pods/warning events/node ready/node pressure)을 probe catalog에 추가. docker
  probe와 동일 철학(미설치/context 부재 시 출력 자체가 진단 정보). `aic diagnose`가 k8s
  키워드를 최우선 매핑.
- **Anthropic 네이티브 tool-calling (R4)** — Anthropic provider에서도 agent loop
  (run_command/obs/read 도구)가 완전 동작한다. 기존엔 Claude 사용자의 tool-calling이
  read-only로 강등됐었다. content 블록 텍스트도 송신 전 redaction.
- **`aic audit tail`/`search` (R5)** — HMAC 감사 로그를 CLI로 조회.
  `aic audit tail [-n N]`, `aic audit search [--kind] [--host] [--since] [--until] [--grep]
  [--multihost]` (+`--json`). 멀티호스트 segment도 함께 스캔.

### Changed
- **출력 없는 exit-code-only 실패는 LLM 호출을 건너뛴다** — 종료 시그널·일반 exit code만
  있고 캡처된 출력이 없으면 결정론적으로 설명해 토큰을 아낀다. 공백뿐인 프롬프트는 None으로
  정규화해 불필요한 호출을 막는다.

## [0.17.0] - 2026-06-08

### Added
- **`aic chat`에서 대화 복사 지원** — TUI가 마우스 휠을 캡처해 터미널 드래그 선택이
  막혀 복사가 안 되던 문제를 해결했다. **Ctrl+Y**로 대화 전체를 클립보드에 복사하고
  (OSC 52라 SSH 원격에서도 로컬 클립보드로 복사된다), **Ctrl+T**로 마우스 캡처를 꺼
  터미널 네이티브 드래그 선택/복사를 쓸 수 있다(다시 켜면 휠 스크롤 복귀).

### Fixed
- **`aic` in-place 업그레이드 후 aicd 데몬이 중복으로 뜨던 문제 수정** — Linux에서
  데몬이 떠 있는 동안 바이너리를 교체하면 단일 인스턴스 판정이 살아있는 aicd를 죽은
  것으로 오인해 두 번째 aicd를 기동했고, 업그레이드마다 중복이 누적됐다. 이제 같은
  데몬의 in-place 업그레이드를 올바르게 인식한다. (이미 중복이 떠 있다면 `aic daemon
  stop` 후 다시 기동하면 정리된다.)

## [0.16.2] - 2026-06-08

### Fixed
- **autostart한 aicd가 zombie(defunct) 프로세스로 남던 문제 수정** — aicd를 자동
  기동할 때 자식 프로세스를 reap하지 않아, 중복 인스턴스가 단일-인스턴스 락에 막혀
  즉시 종료하거나 제어 터미널이 닫혀 죽으면 `[aicd] <defunct>` zombie가 남았다. 이제
  aicd를 별도 세션으로 분리(setsid)해 터미널 종료 신호에 휘둘리지 않게 하고, 종료 시
  자식을 reap하는 reaper로 zombie를 막는다. `aic daemon start`로 띄운 aicd도 세션
  분리되어 터미널을 닫아도 살아남는다.

## [0.16.1] - 2026-06-08

### Fixed
- **Warp 터미널에서 화면이 깨지던 문제 수정** — Warp는 자체 PTY와 block 렌더링을
  쓰기 때문에 그 안에서 aic-session(PTY 래퍼)으로 auto-attach하면 셸 통합(OSC 133)이
  이중으로 들어가 화면이 깨지고 스크롤이 어긋났다. 이제 `aic init`이 만드는 auto-attach
  스니펫이 Warp(`TERM_PROGRAM=WarpTerminal`)를 건너뛰고, aic-session도 Warp에서 실행되면
  PTY를 인수하지 않고 셸로 전환한다. Warp에서 캡처가 필요하면 hook/hybrid 모드를 쓴다
  (`aic config set session.capture_mode hybrid`). 기존 rc에 박힌 스니펫은 `aic init <shell>`
  을 다시 실행하면 Warp 가드가 반영된다.

## [0.16.0] - 2026-06-08

### Added
- **capture-mode 설정(`pty`/`hook`/`hybrid`)** — `aic config set session.capture_mode <mode>`
  또는 `aic init` 대화형 설정으로 세션 캡처 방식을 고른다. `hybrid`(신규 기본)·`hook`는
  metadata-only로 동작하며 PTY auto-attach(`exec aic-session`)를 rc에 주입하지 않는다.
  출력이 필요하면 `aic run -- <cmd>` 또는 `aic capture-last`를 사용한다.

### Changed
- **기본 capture-mode가 `pty` → `hybrid`로 변경** — ⚠️ `[session]` 섹션이 없는 기존
  설정은 이제 hybrid(metadata-only)로 동작해, 새 셸에서 PTY auto-attach가 더 이상 자동
  주입되지 않는다. **기존 PTY 캡처 동작을 유지하려면** `aic config set session.capture_mode pty`
  실행 후 `aic init <shell>`을 다시 돌려 auto-attach 스니펫을 재주입한다.
- 세션 종료 시 trigger(PtyEof/Signal)에 따라 자식 셸에 종료 신호(SIGHUP)를 보내고,
  wait/output relay를 timeout 후 정리한다.

### Fixed
- **세션 종료 시 터미널이 raw mode로 남던 문제 수정** — `set_raw_mode` 이후 UDS bind
  실패 같은 조기 종료 경로가 터미널을 복원하지 않고 종료해 셸 입력이 깨지던 버그를, RAII
  가드로 모든 종료 경로(정상/오류)에서 복원하도록 일원화했다.

## [0.15.2] - 2026-06-08

### Fixed
- **세션 종료 시 셸을 빠져나오지 못하던 hang 수정** — PTY master가 EOF를 먼저
  받는 경우(`trigger=pty-eof`, 셸은 아직 살아있음) `wait_handle`(`child.wait()`)·
  `stdin_handle`(`stdin.read()`) 같은 `spawn_blocking` task가 syscall에 묶인 채
  `abort()`로 멈추지 않아, `#[tokio::main]` 런타임 drop이 blocking 스레드 완료를
  무한 대기하면서 프로세스가 종료되지 않던 문제(세션 소켓은 삭제됐는데 프로세스가
  남고 `^C`도 먹지 않음)를 막는다. graceful 정리 후 명시적으로 프로세스를 종료해
  런타임 drop의 blocking-thread join을 우회한다.

## [0.15.1] - 2026-06-05

### Fixed
- **auto-attach가 AI 코딩 에이전트 셸을 교체하지 않도록 가드 추가** — claude
  (`CLAUDECODE`), codex(`CODEX_SANDBOX`), kiro-cli(`KIRO_SESSION_ID`) 환경에서 셸을
  인터랙티브 PTY로 띄울 때 `exec aic-session`이 발동해 에이전트 세션을 깨뜨릴 수 있던
  문제를 막는다. 세 마커 중 하나라도 설정돼 있으면 auto-attach를 건너뛴다. (대부분의
  에이전트는 명령을 비대화형으로 실행해 기존 대화형 가드에 이미 걸리지만, PTY로 띄우는
  엣지 케이스를 위한 방어 심층화.)

## [0.15.0] - 2026-06-05

### Added
- **`aic init`이 PTY auto-attach를 기본 주입** — 이제 `aic init <shell>`이 rc에
  `exec aic-session` 진입 스니펫을 함께 넣어, 새 셸을 열면 자동으로 aic-session(PTY
  래퍼)에 진입한다. 이전에는 init이 OSC 133 hook만 깔고 PTY 진입은 매번 수동으로
  `aic-session`을 실행해야 했다. 끄려면 `aic init <shell> --no-attach`, 일시 우회는
  `AIC_NO_ATTACH=1`(SSH 락아웃 복구용). 5중 가드(대화형·`AIC_SESSION` 재진입 차단·
  `AIC_NO_ATTACH`·stdin/stdout tty·바이너리 존재)로 무한 재진입과 로그인 락아웃을 막는다.
- **`aic init --no-attach` 플래그** — auto-attach 없이 hook source 라인만 설치한다
  (기존 동작). 이미 aic hook 마커가 있는 rc는 그대로 두므로, auto-attach를 토글하려면
  마커 블록을 지우고 재실행한다.

## [0.14.0] - 2026-06-04

### Changed
- **macOS `aic chat`는 기본 line 모드(reedline)** — raw-mode ratatui TUI가 macOS의
  한글 IME 조합(preedit)과 충돌해 입력 중 자모가 분리되거나 커서가 옆으로 밀리는
  문제가 있었다. macOS는 reedline 기본으로 되돌리고, ratatui TUI는 `AIC_CHAT_TUI=1`로
  opt-in하도록 바꿨다. Linux는 그대로 TUI 기본(`AIC_NO_TUI=1`로 opt-out).

### Added
- **chat TUI 마우스 휠 스크롤** — 휠을 위/아래로 굴려 대화 로그를 스크롤한다. 이전에는
  alternate screen에서 휠이 `↑/↓` 키로 변환돼 들어와, 스크롤하려다 입력 history가
  바뀌었다. 진입 시 마우스 캡처를 켜 휠을 로그 viewport 스크롤로 라우팅한다(종료 시
  캡처 해제).
- **chat TUI 한글 조합 입력기** — TUI 입력 줄에서 한글 자모를 직접 조합한다(초성·중성·
  종성 결합, 받침 분리/재조합 포함). raw-mode에서 IME 없이도 한글을 입력할 수 있다.

## [0.13.2] - 2026-06-03

### Added
- **`aic daemon restart` 서브커맨드** — stop → socket 해제 대기 → start를 한 번에
  수행한다. 새 바이너리로 업그레이드한 뒤 실행 중인 aicd에 적용할 때 쓴다(업그레이드
  안내가 이미 이 명령을 가리키고 있었으나 실제로는 없던 것을 추가). 미실행 상태면
  곧장 start만 한다.

### Fixed
- **aicd가 Shutdown 요청에 실제로 종료되지 않던 버그** — `aic daemon stop`/`restart`가
  Shutdown을 보내고 서버가 Pong을 응답해도 데몬 프로세스가 종료되지 않고 socket이
  남아 있었다. 원인은 control·attach 두 serve 루프가 같은 `Notify`를 공유하는데
  `notify_one()`이 단일 waiter만 깨워, 요청을 처리 중이라 park 상태가 아니던 control
  루프가 신호를 놓치고 영원히 hang 한 것(`server.serve()`가 리턴하지 않음). shutdown
  신호를 level-triggered인 `tokio::sync::watch`로 바꿔 한 번의 `send_replace(true)`로
  모든 serve 루프가 신호를 놓치지 않고 깨어나도록 수정했다. 이제 stop/restart가 즉시
  데몬을 종료한다.

## [0.13.1] - 2026-06-03

### Fixed
- **`aic init`이 셸 hook 파일을 직접 생성** — 이전에는 `.bashrc`/`.zshrc`에
  `source ~/.aic/hooks.{shell}` 라인만 추가하고 정작 `~/.aic/hooks.{shell}` 파일은
  서버(PTY 세션)가 lazy 생성하는 구조라, init만 하고 세션을 안 띄운 호스트에서
  새 셸을 열 때마다 `source: No such file or directory` 에러가 났다. 이제 `aic init`이
  source 라인과 함께 hook 파일을 즉시 생성하며, rc에 마커가 이미 있어도 파일이 없으면
  self-heal 한다. OSC 133 boundary hook generator를 `aic-common`으로 이전해 client에서도
  생성 가능하게 했고, `aic doctor --fix`도 `hooks.{zsh,bash}`에 올바른 boundary 내용을
  쓰도록 수정했다(기존엔 metadata hook 내용이 잘못 들어갔다).

## [0.13.0] - 2026-06-03

### Added
- **`aic config`에 Custom (OpenAI 호환 endpoint) 등록** — LLM Provider 설정 메뉴에서
  ai-mesh·vLLM·LiteLLM·LM Studio 등 임의의 OpenAI Chat Completions 호환 endpoint를
  대화형으로 추가할 수 있다. provider 이름·endpoint URL·API Key·모델을 직접 입력하며,
  지정한 이름이 그대로 `default_provider`가 되어 `aic --provider <name>`으로도 선택 가능.
  같은 이름으로 다시 들어가면 기존 값이 prefill되어 수정도 된다. 설정 예제(`설정 파일
  직접 편집`)에도 custom endpoint 주석 블록을 추가.

## [0.12.0] - 2026-05-29

### Added
- **`aic ssh <host> [cmd]` 서브커맨드** — 인벤토리/`~/.ssh/config` 등록 호스트는 물론
  ad-hoc 지정(`aic ssh root@jw-server` 또는 hostname만)도 받아 ping/명령 실행.
  `-i, --identity-file <PATH>`로 SSH 키 파일 지정. 내부적으로 `hosts ping` 경로를
  재사용하므로 화이트리스트 게이트가 동일하게 적용된다.
- **hostname-only ad-hoc 해석** — `user@host[:port]` 외에 단순 `host`(예: `jw-server`)도
  `$USER@host:22` ad-hoc 호스트로 자동 해석. `aic ssh`/`hosts ping`에서 즉석 호스트
  지정이 한층 간결해진다.

### Changed
- **TOFU auto-trust 1회 재시도** — SSH 인증 실패 stderr에 `host key verification failed`
  패턴이 보이면 TTY 환경에서 confirm을 받아 `ssh-keyscan` + `known_hosts` append 후
  1회 자동 retry. non-TTY(CI 등)에서는 자동 차단되어 가드레일을 유지한다.

### Fixed
- **chat TUI 한글 IME 하드웨어 커서 위치 보정** + alternate screen 진입 시 터미널 clear로
  잔상 제거.

## [0.11.1] - 2026-05-28

### Added
- **`aic hosts ping/trust` ad-hoc 호스트 + `-i` identity_file 옵션** — 인벤토리
  (`~/.aic/hosts.toml`)나 `~/.ssh/config`에 등록되지 않은 호스트도 `aic hosts ping
  root@jw-server[:port]`처럼 즉석 지정 가능. `-i, --identity-file <PATH>`로 SSH 키 파일을
  명시 지정(또는 인벤토리 등록 호스트의 키를 일회성 override). 신규 ad-hoc 호스트는
  `aic hosts trust root@jw-server`로 동일하게 TOFU 등록. 화이트리스트 게이트는 그대로
  적용된다. RFC-005 §4.1 ad-hoc(`HostSource::AdHoc`) 1.1 후속 항목 선반영.

## [0.11.0] - 2026-05-26

### Added
- **status bar에 swap·디스크 free 표시** — `mem` 옆에 `swap {pct}%`(메모리 압박/OOM 조기 신호),
  `io` 앞에 `disk {N}G free`(root fs 여유 용량 — SRE의 "얼마 남았나" 핵심 지표). macOS APFS
  컨테이너 공유로 `total-avail` 기반 사용률 %가 부정확한 점을 피하기 위해 `available_space()`만
  쓴다(플랫폼 무관 신뢰).
- **SSH 멀티호스트 진단(RFC-005)** — `aic hosts {show,ping,trust}` + `aic whitelist {status,check}` +
  `aic audit batch-verify` 신규 (`feat/ssh-multihost` 11 커밋, ~2,900 LOC, 70 tests).
  - `~/.aic/hosts.toml`(+ `~/.ssh/config` 자동 import + overlay) 기반 `aic hosts ping @group`이
    cap 8 + 3-layer timeout(connect 10s / cmd 30s / wall 300s)으로 병렬 진단, 8종 상태 태그 +
    severity-sort + `[ok] collapsed` + 헤더 inline 실패명 + `[auth_fail]` hint(ssh-agent 자동 점검)를
    카드 stack으로 표시. 결과는 `~/.aic/audit/YYYY-MM-DD.jsonl`에 SHA256 chain으로 자동 기록.
  - `aic hosts trust <name>` — TOFU 4-step(ssh-keyscan + SHA256 fingerprint + stdin confirm +
    known_hosts append)을 명시 단계로 실행. BatchMode↔TOFU 양립 해소.
  - `aic whitelist` — builtin 8개(`ps/df/free/uptime/cat/journalctl/ls/find`) + `~/.aic/whitelist.toml`
    user 확장 + 4단 게이트(shell metachar / program / `path_guard`(procfs allowlist 반전 + secret
    파일명 차단) / allowed_args 규칙). `hosts ping --cmd`도 동일 게이트 통과해야 실행.
  - `aic audit batch-verify [--date YYYY-MM-DD]` — 멀티호스트 batch audit segment SHA256 chain
    무결성 검증. 변조 감지 시 broken_at line 보고.
  - red-team Critical **12/12 반영 완료**(S1·S2·S3·R1·R2·R3·U1·U2·U3·O1·O2·O3).
  - 자세한 Implementation Status는 `docs/RFC-005-SSH-MULTIHOST.md §10`.

## [0.10.0] - 2026-05-25

### Added — ratatui 전면 chat TUI + agentic 쓰기 도구

- **전면 TUI (alternate screen)** — `aic chat`이 전체 화면을 소유한다. 대화 로그를 자체 스크롤
  버퍼로 관리(`PageUp`/`PageDown`), 입력창 **아래에 하단 고정 status bar**(타이핑 중에도 흐름),
  종료 시 대화를 터미널 scrollback에 색 그대로 dump. `AIC_NO_TUI=1`로 기존 reedline 라인 모드.
- **slash 자동완성 popup** — `/` 입력 시 세로 목록(카테고리 색 + 설명)을 띄운다. ↑↓로 선택,
  Tab 완성, Enter 제출.
- **history ↑↓** — 이전 입력 탐색(reedline과 동일 `chat_history` 파일 공유).
- **`/clear`** — 대화 컨텍스트 리셋(시스템 프롬프트 유지).
- **`/resume`** — 종료한 세션의 대화 복원(`~/.aic/sessions/last.json`).
- **`/fix`** — 직전 진단·대화 맥락에서 실행할 명령을 제안·실행(확인 후).
- **컨텍스트 토큰 표시** — status bar에 대화 토큰 추정치 `ctx ~Nk`.
- **로그 내 검색** — `Ctrl+F`로 대화 로그를 검색(`n`/`N` 이동, `Esc` 종료).
- **작업 중 `Ctrl+C` 중단** — LLM 응답·분석이 도는 동안 `Ctrl+C`로 현재 turn만 취소(앱은 유지,
  입력 프롬프트로 복귀). idle 상태에선 입력 줄 비우기, 빈 입력에서만 종료(claude CLI 스타일).
- **분석↔대화 통합** — `/diagnose`·`/local`·`/incident` 등 분석 후 "왜?/어떻게?" 후속 질문을
  같은 대화로 이어갈 수 있다.
- **`write_file`/`edit_file` 도구** — agentic 파일 작성·수정. sandbox 경계 + 쓰기 전 미리보기·확인.
  `run_command` 활성(mutation) 세션에서만 노출, read-only 세션엔 없음.
- **TUI confirm UI** — `NeedsConfirm` 명령을 `⚠ {명령} — {이유} [y/N]`로 확인.
- **시작 배너** — 버전 + 미니 봇 마스코트 + tagline.

### Changed

- **TUI 기본 전환** — TTY는 기본 ratatui chat TUI(`AIC_NO_TUI=1`로 reedline opt-out). 레이아웃은
  입력 위 / status bar 아래(claude CLI 스타일).
- status bar redraw 주기를 1초로(입력 대기 중 불필요한 깨어남 감소).

### Fixed

- TUI에서 slash 출력·tool 출력·확인 입력이 화면을 깨거나 멈추던 문제(출력 sink 일원화 + confirm UI).
- 작은 터미널에서 slash popup 표시 항목과 제출 항목이 어긋나던 문제.
- 입력 prompt 폭(`◇`/`❯` 밀림), 분석 spinner 프레임 누적.

## [0.9.0] - 2026-05-24

### Added — chat status bar (실시간 시스템 지표) + `/trend`

- **status bar** — `aic chat`에서 load average·cpu%·memory·disk i/o를 보여준다. **입력 프롬프트 직전**(매
  입력마다 최신)과 **LLM 응답 대기 중 spinner 라인**(2초마다 갱신)에 표시한다. reedline이 `read_line()`
  중 raw mode를 독점하므로, 충돌이 없는 이 두 구간에만 갱신한다(타이핑 중 갱신은 ratatui 전환이 필요해
  현재는 정적). 수집은 `sysinfo` crate(in-process), disk i/o는 `Disks` 인스턴스 재사용으로 delta 자동 계산.
  - non-TTY/파이프/CI에서는 자동 비활성(spinner와 동일 정책). `AIC_NO_STATUSBAR=1`로 끄기.
- **`/trend [N]`** — 최근 명령 exit code 추세를 `✓`/`✗` 시퀀스 + 성공/실패율 + 최근 실패 명령으로 보여준다.
  ring buffer의 exit 기록만 집계(LLM 미호출). Evidence 카테고리(`/last`·`/timeline`과 함께).

## [0.8.1] - 2026-05-24

### Fixed — `aic update`의 GitHub API rate limit(403)

- **brew 설치인데도 GitHub API를 먼저 타서 죽던 문제** — `update::run`이 source 분기(brew/manual) 전에
  무조건 `fetch_latest_tag()`(GitHub API)를 호출해, 미인증 rate limit(IP당 60회/시간) 소진 시 403으로
  중단되며 `brew upgrade`에 도달조차 못 했다. 이제 brew/cargo는 태그 조회를 **best-effort**로 두어
  실패해도 `brew upgrade`로 진행한다(brew가 tap에서 최신을 가져옴).
- **태그 조회를 `api.github.com` → `github.com/.../releases/latest` redirect로 변경** — 302 `Location`
  (`.../releases/tag/<tag>`)에서 태그를 추출한다. 웹 redirect는 API rate limit·토큰과 무관하므로
  미인증 60회/시간 한도를 더는 타지 않는다(토큰 설정 불필요).

## [0.8.0] - 2026-05-24

### Changed — `/diagnose` 진단 커버리지 대폭 확장

- **docker를 의심하지 않아도 발견** — `/diagnose`가 docker 설치 호스트면 카테고리에 맞는 docker probe를
  자동 포함한다(cpu/memory/process/network → `docker_ps`, disk → `docker_df`, 원인 미상 → 둘 다).
  이전엔 증상에 "docker"를 직접 써야만 봤다. **docker 미설치 호스트면 docker probe를 전혀 안 붙여 노이즈 0.**
- **`/tmp` 비대를 disk/원인미상 진단에서 자동 수집** — `tmp_big`(du), `tmp_recent`(최근 10분 수정).
  이전엔 `/triage`·`/watch`로만 접근 가능했다. 증가 추세 추적은 여전히 `/watch tmp_recent`.

### Added — 흔한 장애 probe 4종 (inode · 로그 · 연결 · 프로세스 상태)

- **`inodes`** (`df -i`) — 용량이 남아도 `No space left on device`면 inode 고갈. disk·원인미상 진단에 포함.
- **`log_big`** (`du -ah /var/log | sort -rh | head`) — `/var/log` 누적(디스크 full의 흔한 원인). disk 진단에 포함.
- **`conn_states`** (linux `ss -s` / macOS `netstat`) — TCP 연결 상태 폭주(established/time_wait). network 진단에 포함.
- **`proc_states`** (`ps -eo stat | sort | uniq -c | sort -rn`) — 프로세스 상태 분포(좀비 Z 등). process 진단에 포함.

### Fixed

- **`/release` 커맨드 clippy를 CI와 일치** — Step 2 로컬 검증의 clippy를 `--all-targets`에서 CI(`ci.yml`)와
  동일한 `--workspace -- -D warnings`로 변경. `--all-targets`는 CI가 검사하지 않는 test 타겟 경고까지 잡아
  "CI는 통과할 릴리스"를 로컬에서 잘못 막았다(게이트가 CI보다 엄격하면 안 됨).

## [0.7.0] - 2026-05-24

### Added — host-wide SRE 진단 (docker · filesystem · fd)

- **docker 진단 probe** — `docker_df`(`docker system df` — images/containers/volumes/build cache 디스크
  사용량), `docker_ps`(`docker ps -s` — 컨테이너 writable layer 크기), `docker_images`(이미지별 크기).
  `/triage docker` 토픽 신설, `/diagnose`의 docker/disk 카테고리에서 자동 선택된다. **"디스크 full"만
  말해도** docker가 원인이면 `docker_df`가 함께 수집돼 발견된다.
- **`/local fd` 섹션** — 열린 파일 디스크립터 수(현재/최대). Linux `sysctl fs.file-nr fs.file-max`,
  macOS `sysctl kern.num_files kern.maxfiles`.
- **filesystem probe** — `tmp_big`(`du -ah /tmp | sort -rh | head` — 큰 파일/디렉토리),
  `tmp_recent`(`find /tmp -type f -mmin -10` — 최근 수정 파일). `/triage disk`가 `tmp_big`을 포함한다.
- **`/watch`가 모든 Probe Catalog probe를 대상으로** — 기존 LOCAL 섹션 제한을 풀어 `docker_df`·
  `tmp_recent` 등도 watch 가능. `/watch tmp_recent`로 `/tmp`에서 **늘어나는 파일을 시계열로 추적**한다.

### Changed — SRE sandbox 경계 재정의 (read-only는 호스트 전역)

- **read-only 진단의 host-wide read 허용** — `run_command`의 읽기 전용(Safe) 명령은 이제 cwd sandbox에
  갇히지 않고 호스트 전역을 읽을 수 있다(`tail -n 100 /var/log/...`, `du -ah /tmp`, `cat /proc/meminfo`
  등). 이전엔 절대경로·`..`가 일률 차단돼 SRE 지침이 권하던 로그 tail조차 막혔다. mutation/위험 명령은
  기존대로 cwd sandbox에 격리된다.
- **risk_guard safe_set 보강** — 순수 텍스트 필터 `sort`/`uniq`/`cut`/`tr`/`column`/`comm`과 `vm_stat`를
  Safe 자동 실행에 추가(`awk`/`sed`는 코드 실행 위험이라 제외, `sort`/`uniq -o`는 파일 쓰기라 가드).
  `du /tmp | sort -rh | head` 같은 진단이 막힘 없이 실행된다.
- **docker prune Dangerous화** — `docker system prune`/`<area> prune`/`prune`을 복구 불가 삭제로 분류해
  자동 실행을 차단한다(이전엔 미분류). `docker system df`(읽기)만 Safe로 구분.

### Security

- **secret 경로 denylist** — host-wide read가 열린 대신, 읽기 전용 명령이라도 secret 경로는 차단한다:
  `~/.ssh`·`~/.aws`·`~/.gnupg`·`~/.kube`·`~/.docker`, `/etc/shadow`, `/etc/ssl/private`,
  `/proc/*/environ`, `*.pem`/`*.key`/`.env`/`id_rsa`/`credentials`. symlink 대상은 `canonicalize`로
  해소해 우회를 막는다. egress(curl/ssh)·mutation 게이트와 출력 redaction은 그대로 유지된다.
- **`sysctl` write 차단** — `sysctl` 읽기 조회만 Safe, `-w`/`key=value`(커널 파라미터 변경)는 Safe에서 제외.

## [0.6.0] - 2026-05-22

`aic chat`을 SRE 진단 어시스턴트로 굳히는 릴리즈 — slash 명령 팔레트/안전성 개선, 새 진단 명령
(`/watch`), `/compare` 강화, 더 깔끔한 `/local` 분석 출력, audit 키 backend 기본값 변경.

### Added — chat slash UX (palette · prefix · `/watch` · `/compare` 강화)

- **slash 명령 팔레트 카테고리화** — `/` 단독 입력 시 후보가 `[Diagnostics]`/`[System]`/`[Evidence]`/
  `[Meta]` 카테고리로 묶여 정렬·표시된다(discovery만 적용; prefix 완성에는 영향 없음).
- **prefix Enter 완성** — `/lo`처럼 유일하게 결정되는 prefix는 Enter 한 번에 `/local`로 확정·실행된다.
  ambiguous prefix(`/d` → diagnose/doctor)는 첫 후보를 실수로 실행하지 않고 후보를 안내한다.
- **`/watch [target] [--count N] [--every Ns]`** — 로컬 probe를 bounded하게 반복 실행하고 tick마다
  변화량을 요약(LLM 미호출). 무한 watch 없음(기본 3회, 최대 20, 간격 1s clamp). `target`은 섹션 이름,
  생략하면 compact 세트(uptime/memory/disk). unknown target은 조용한 fallback 대신 사용 가능 섹션을 안내.
- **`/compare` 강화** — 변경/동일 섹션 수와 추가/삭제 라인 수를 요약하고 변경 섹션 이름을 보여준다.
  run_command 실행 메타(duration_ms 등)는 비교에서 제외해 동일 상태가 changed로 보이는 false positive 제거.

### Changed — `/local`·`/diagnose`·`/incident` 출력 정리

- **분석 모드 출력 간소화** — `/local`(기본 analyze)에서 빈 `=== local system snapshot ===`/섹션 헤더를
  더 이상 남기지 않는다. 수집 중에는 `<thinking> 수집 중: <probe> (i/n)` 진행 표시(같은 줄 갱신, TTY)만
  보이고, 완료 후 `=== local analysis ===` 결과만 남는다. `--raw`(또는 `AIC_LOCAL_NO_ANALYZE=1`)는 기존처럼
  헤더+본문을 보여준다.
- **`/incident` 분석 입력 bounding** — 과대 evidence로 인한 provider parsing/context 오류를 막기 위해
  섹션별 라인 cap·최근 기록 축소·전체 크기 cap을 적용한다(핵심 섹션은 보존). 분석 실패 시 사용자 친화
  메시지와 함께 수집한 raw 증거를 보여준다.

### Changed — run_command 상세 카드 기본 조용화 (`AIC_VERBOSE`)

- **`/local`·`/diagnose`·`/triage --run` 등에서 probe마다 출력되던 상세 `run_command` 카드**
  (`▌ run_command [corr]`, `cwd/policy/timeout/output cap`, `→ done duration`)를 **기본 OFF**로 바꿔
  조용히 실행한다. 섹션 헤더(`[name]`)와 결과 본문만 보여 다수 probe 출력이 깔끔해진다.
  - `AIC_VERBOSE=1`(또는 `AIC_DEBUG=1`)이면 기존 상세 카드 전체를 표시.
  - **보안 경고는 기본에서도 항상 표시**: blocked/denied/NeedsConfirm/Dangerous/Unknown(`→ blocked`/
    `→ denied`/확인 프롬프트/validator 차단 hint)는 flag와 무관하게 유지.

### Changed — AIC_DEBUG 판정 통일 + 시작 배너 opt-out

- **AIC_DEBUG는 `1`/`true`(대소문자·공백 무시)만 ON.** `0`/`false`/`off`/빈값/unset은 모두 OFF로 통일.
  기존에 `var_os().is_some()`로 "값과 무관하게 set이면 ON" 취급하던 audit keychain 힌트와 chat
  `/doctor`의 AIC_DEBUG 표기를 truthy 판정(`agent::debug`)으로 교체 — `AIC_DEBUG=0`에서 디버그 출력이
  새지 않는다.
- **`aic chat` 시작 배너 opt-out 추가.** `AIC_NO_BANNER=1`(또는 `AIC_QUIET=1`)이면 ASCII 배너,
  status 줄, **context header**(직전 명령 컨텍스트)를 모두 출력하지 않는다(기본은 계속 표시). 이 시작
  chrome은 debug 로그와 무관함을 명확히 하기 위한 분리.

### Changed — audit key backend 기본값(file) + keychain opt-in

- **audit HMAC 키 backend 기본을 file로 변경.** OS keychain은 이제 **opt-in**(`AIC_AUDIT_KEYCHAIN=1`)
  일 때만 사용한다. `AIC_NO_KEYCHAIN=1`은 최우선으로 keychain을 끄며(opt-in보다 우선), 단위 테스트는
  항상 file. 기본 환경(특히 macOS nested-PTY/headless)에서 keychain Mach IPC block으로 인한 hang을
  피하기 위함. backend 라벨(`file (default)` / `keychain (opt-in: AIC_AUDIT_KEYCHAIN)` /
  `file (keychain off: AIC_NO_KEYCHAIN)`)을 `aic doctor`와 chat `/doctor` 출력에 표시한다.
  - **업그레이드/마이그레이션**: 이전 버전에서 audit 키가 keychain에만 있던 사용자는 file 기본 전환 후
    `aic doctor`의 audit 검증이 WARN/키 없음을 보고하거나 chain 보호로 append가 skip될 수 있다. doctor
    fix hint가 두 선택지를 안내한다 — (1) `AIC_AUDIT_KEYCHAIN=1`로 실행해 기존 keychain chain 유지,
    (2) `~/.local/state/aic/audit.log`를 백업/rotate 후 재실행해 새 file chain 시작.

### Added — Probe Catalog + `/triage`

- **Probe Catalog (`agent::probes`)** — 읽기 전용 SRE probe의 단일 출처. `ProbeSpec{id, category,
  tags, description, linux_command, macos_command, max_lines}`에 기존 local 섹션
  (date/host/os/uptime/disk/memory/ip/route/ports) + `process` + git read-only
  (status/branch/log/diff)를 모았다. 모든 명령은 고정 상수 bounded Safe.
  `sysinfo::local_probes`/`probes_for`, `/diagnose` probe, `/incident`·`/bundle` git 증거가 catalog를
  조회하도록 통일(동작 동일).
- **`/triage [--run] [topic]`** — 토픽별 read-only 체크리스트 + 후보 probe(id/설명/명령)를 화면에
  렌더. topic: `mac-slow web disk memory cpu network build-fail generic`(unknown은 generic으로
  fallback하되 원 라벨 표시). 기본은 **LLM 미호출** 안내만, `--run`이면 run_command 활성 시 후보
  probe를 `collect_local_snapshot`으로 실행해 redacted 증거 출력(여전히 LLM/history 미사용). topic은
  라벨 선택에만 쓰고 셸 명령에 섞지 않는다.

## [0.5.0] - 2026-05-22

### Added — `aic chat` Agentic Assistant (RFC-002 Phase 0~2)

`aic chat` 서브커맨드 도입 — exit code와 무관한 명시적 대화 진입점. 단발성
`send(prompt)` LLM 계층 위에 multi-turn + tool-calling 경로를 얹어 SRE/코딩
어시스턴트로 확장. 설계는
[RFC-002-AIC-CHAT-AGENTIC.md](./docs/RFC-002-AIC-CHAT-AGENTIC.md).

- **Phase 0 — 진입점** — `aic chat "질문"`은 1회 답변, `aic chat`은 대화형 REPL
  (exit code 무관, 직전 record best-effort 첨부). `--dry-run`(토큰·비용 미리보기),
  `--context`(project context pack 첨부) 플래그.
- **Phase 1 — 읽기 전용 agent** — OpenAI 호환 provider에서 `aic chat`이
  tool-calling agent로 동작. 읽기 전용 도구 `read_file`/`list_dir`/`grep`/`glob`로
  프로젝트를 탐색한다. `LlmDispatcher::send_messages`(OpenAI function-calling,
  송신 전 redaction) + `AgentSession` agent loop(반복 한도 안전 종료).
- **안전** — 파일 접근은 **현재 작업 디렉터리(canonical cwd) 샌드박스**로 제한
  (symlink/`..`/절대경로 탈출 거부), **`.gitignore`/`.git/info/exclude`** 존중,
  secrets·hidden·binary·대용량 파일 규칙 적용. 쓰기·실행 도구는 미등록(Phase 2 예정).
- **호환/degrade** — Anthropic·CLI Backend는 기존 `ReplSession`으로 폴백.
  OpenAI 호환이라도 provider가 `tools`를 거부하면 일반 대화 모드로 graceful degrade
  (반복 실패 방지). 기존 `send`/`send_streaming`/direct prompt 동작 무변경.
- **Phase 2 — SRE `run_command` (기본 활성)** — 대화형 `aic chat`이 **bounded·
  sandbox** 셸 명령을 실행한다. `run_command`는 **기본 on**이며, 읽기 전용으로
  끄려면 `--no-run`/`--read-only`/`AIC_AGENT_NO_RUN=1`. (레거시 `--sre`/`--allow-run`은
  호환용 no-op으로 유지.) `risk_guard` 분류로 **Safe=자동 실행**, **NeedsConfirm=
  TTY 확인**(비-TTY 거부), **Dangerous/Unknown=차단**. SRE shortcut: `ps`/`cpu` ⇒
  `ps aux | head -n 20`, `disk` ⇒ `df -h`, `memory`/`net`은 OS별 bounded 명령.
- **run_command 안전 모델** — `sh -c` 실행이되 cwd 샌드박스, env allowlist(API key
  미전달), 출력 redaction, audit 기록, timeout(기본 15s/하드캡 30s, process group
  SIGKILL로 descendant 정리), bounded stdout/stderr(64KB, truncated hint). 셸은 제한:
  `$`·glob/brace(`* ? [ ] { }`)·따옴표·백슬래시·redirect·`;`·`&`·`||`·newline·`~`·
  backtick·절대경로 인자·`..`·find/fd 위험 옵션 차단(패턴/고급 셸은 grep/glob tool 또는
  후속 argv runner로 처리).
- **대화형 입력 개선** — `aic chat` 입력기를 전용 라인 에디터로 교체: 한글/CJK 편집
  잔상 수정, up/down 명령 history(`~/.config/aic/chat_history` 영속), 비-TTY는 기존
  방식으로 fallback. `AIC_DEBUG=1`이면 iteration·tool 호출·`tools=5`(읽기전용 시 `tools=4`)
  등 agent 디버그 로그를 stderr로 출력. (라인 에디터는 이후 reedline으로 이주 — 아래 항목 참조.)
- **SRE 터미널 UI** — `aic chat` 시작 시 ASCII art banner + status line(mode/tools/policy/
  cwd/provider/model) 출력(폭 좁으면 compact). 채팅 프롬프트 `◇ you ❯ `(TTY)/`you> `(non-TTY),
  run_command command card·done·confirm·blocked/denied 액션 안내를 `▌` 스타일로 일관화.
  LLM 답변은 stdout, banner/status/card/debug는 stderr로 분리.
- **색상/디버그 정책** — `NO_COLOR` 설정 또는 non-TTY면 banner/status/card/debug의 ANSI 색상을
  억제(`aic chat`). `AIC_DEBUG=1`은 banner를 유지하면서 `provider_tools=…`/`tool_specs=…` 등
  grep 가능한 structured 라인을 출력.
- **read-only 토글** — `aic chat`은 `run_command` 기본 활성. `--no-run`/`--read-only`/
  `AIC_AGENT_NO_RUN=1`로 읽기 전용 전환(레거시 `--sre`/`--allow-run`은 no-op).
- **설계 문서** — `aic chat` SRE Agent PRD([docs/PRD-AIC-SRE-CHAT.md](./docs/PRD-AIC-SRE-CHAT.md))
  추가.
- **GA Gate P0 반영** —
  - **G2 네트워크 egress**: `curl`/`wget`이 **GET 포함 모두 NeedsConfirm**으로 분류된다
    (`risk_guard`: GET=`http.egress`, POST/upload/output=`http.write`). 더 이상 GET이 자동 실행되지
    않아 쿼리스트링을 통한 데이터 유출이 비-TTY에서 자동 거부된다(보안 강화, 정책 완화 아님).
  - **G1 tool-calling 진단**: `aic doctor --probe-tools`(opt-in) — provider에 최소 tool spec으로
    `send_messages` 1회를 보내 ok/unsupported/degraded/error/skip을 진단(세션 시작 시 자동 아님).
    런타임 tool-calling degrade 시 사용자에게 1회 명시 고지 + audit `tool_calling_degraded` 기록.
- **P1 안전 강화/관측성** —
  - **DNS exfil 축소**: `dig @server`/`nslookup name server`/`host name server`처럼 custom
    resolver/explicit server를 쓰는 DNS 조회를 Safe 자동실행에서 제외하고 NeedsConfirm
    (`risk_guard` rule `dns.custom_resolver`)으로 올림. 기본 resolver 단순 조회(`dig name` 등)는
    Safe 유지.
  - **원격 네트워크 도구 명시 차단**: `ssh`/`scp`/`sftp`/`nc`/`ncat`/`netcat`/`socat`/`telnet`/
    `rsh`/`rlogin`을 Unknown 의존이 아니라 명시적 **Dangerous**(`net.remote_access`)로 분류.
  - **correlation id**: `AgentSession`이 세션마다 `run_id`를, tool call마다 `run_id.seq`를
    부여해 AIC_DEBUG `tool_call`/`tool_result`, run_command command card, audit JSON(`corr`),
    degrade audit(`run_id`)에서 동일 id로 추적 가능. stdout(LLM 답변)에는 노출하지 않음.
  - argv runner / 외부 egress allowlist 실허용은 **P2**로 보류.
- **P2-1 audit 조회 UX(in-memory)** — `aic chat` agent 모드 REPL에서 slash 명령 지원:
  `/help`, `/last [N]`(직전 tool 카드 / 최근 N개 요약), `/raw [seq|corr]`(redacted 전체 출력,
  cap 시 라벨 표기). slash 입력은 LLM에 전송하지 않고 history/context에도 넣지 않으며 출력은
  화면(stderr)에만 — stdout(LLM 답변) 미오염. tool 실행은 in-memory ring(상한 20)에 `corr`·tool
  이름·command(redacted)·status·exit/duration/truncated와 함께 기록(저장 시 항상 redact).
  비-agent(ReplSession)에서는 slash가 agent 모드 전용임을 안내. persistent audit 파일 조회
  (`/audit tail`)는 **P2-2**로 보류.
- **`/local` 로컬 스냅샷 + slash 자동완성** — `/local`(alias `/sys`, `/snapshot`)은 내장 sysinfo
  probe(date/host/os/uptime/disk/memory/ip/route/ports)를 **shell chain 없이 개별 bounded Safe
  명령**으로 실행해 로컬 스냅샷을 보여준다(`/local <section>`으로 단일 섹션). 각 probe는 기존
  `run_command` 프리미티브로 실행돼 timeout/cap/redaction/audit/`corr`가 동일 적용되고 결과는
  `/last`·`/raw`로 재조회 가능. read-only 세션에서는 비활성.
- **`/local` 기본값 = LLM 분석 요약** — `/local`은 이제 redacted 스냅샷을 **tool 없는 stateless 단발
  LLM 호출**로 분석해 상태 요약을 보여준다(대화 history에 push하지 않음, 프롬프트는 스냅샷을 데이터로만
  취급해 injection 방지·읽기 전용 진단 고정). provider 미설정/오류/rate-limit/timeout 등 분석 실패 시
  사용자에게 명령 실패로 보이지 않게 **raw 스냅샷으로 fallback**하고 짧은 사유만 표시. `/local --raw`(`-r`)는
  모델 호출 없이 원본만, `/local --analyze`(`-a`)는 명시 분석. 환경변수 `AIC_LOCAL_NO_ANALYZE=1`로 분석을
  끄면 항상 raw. 분석/실패 여부는 audit(`local_analyze`)·`AIC_DEBUG`에 기록.
- **`/local` 분석 CLI 렌더링** — 분석 출력이 raw `##`/`**` markdown 원문으로 보이지 않게, 제한된
  markdown subset(heading/bullet/번호/bold/inline code/fenced/blockquote)을 ANSI 구조로 렌더한다
  (의존성 없는 in-house `agent::markdown::render_markdown`, CJK 폭 wrap). 분석 prompt에 "CLI 친화 markdown
  subset만(표/HTML 금지)" 제약 추가. TTY는 렌더, **NO_COLOR(TTY)는 ANSI 없이 구조만**, **non-TTY(파이프)는
  raw markdown 그대로**(도구 파싱·손실 0). 출력 채널은 기존대로 stderr(stdout=chat 답변 전용 불변).
  스트리밍은 buffer-then-render(P1). raw/fallback 출력에는 렌더를 적용하지 않는다.
  강조색은 opencode 스타일 **amber/yellow**(256색 `38;5;214`, 단일 상수)로 heading·bullet 마커·inline
  code에만 적용(본문은 기본 fg, strong은 bold만). 분석 진행 중에는 정적 메시지 대신 **amber spinner
  상태 UI**(`redacted 스냅샷을 <provider>로 보내 분석 중…`, TTY-only, 성공/실패/timeout 모두 정리).
  NO_COLOR/non-TTY는 색 없이 plain·spinner no-op.
- **`/diagnose "<증상>"` — read-only SRE 진단(MVP)** — 증상을 받아 호스트가 **결정적으로** Safe probe를
  선택(cpu/memory/disk/network/process/generic 카테고리, 키워드 ko/en)·수집한 뒤, 증거 스냅샷+증상을
  **tool 없는 stateless 단발 LLM 호출**로 분석해 **가설→증거 인용→다음 안전 확인**을 제시한다(history
  미push). `/diagnose memory pressure`, `/diagnose "맥이 느림"`, `/diagnose --raw 느림`(증거만), no-arg=일반
  health. probe는 전부 고정 Safe 상수(injection 안전), prompt는 스냅샷을 데이터로만 취급·read-only 고정.
  실패/timeout 시 raw 증거 fallback. redaction/corr/audit(kind=`diagnose`)/렌더(amber)·spinner는 `/local`
  패턴 재사용. `AIC_LOCAL_NO_ANALYZE=1`이면 증거만.
- **`/explain-last` / `/incident` — read-only 분석 slash(MVP)** —
  - `/explain-last [--raw] [seq|corr]`: 최근(또는 지정) tool 기록(ring, 이미 redacted)을 증거로
    **무슨 일이었나/원인 후보/다음 안전 확인**을 분석. 새 명령 실행이 없어 read-only 세션도 동작.
  - `/incident [--raw] [name]`: 시스템 스냅샷(sysinfo) + git read-only 증거(repo일 때만: `git status
    --short`/`branch --show-current`/`log -n 10 --oneline`/`diff --stat`, 전부 고정 Safe 상수) +
    최근 tool 기록을 묶어 분석. **name은 라벨 전용으로 셸 명령에 절대 포함하지 않음**.
  - 분석은 tool-less·stateless 단발(history 미push), prompt는 증거를 데이터로만 취급(injection 방지)·
    read-only 고정. `--raw`/`AIC_LOCAL_NO_ANALYZE`=증거만, 실패/timeout 시 raw fallback. redaction/corr/
    audit(kind=`explain-last`/`incident`)/markdown 렌더(amber)·spinner는 `/local`·`/diagnose` 패턴 재사용.
- **`/doctor` · `/timeline` · `/compare` · `/bundle` — P0 운영 slash(LLM 미호출)** —
  - `/doctor`: AIC 자체 상태(provider/model 식별자, tool-calling 지원, run_command on/off, env flag는
    **값이 아니라 set/unset만**)를 표시. config/env 전체 dump·secret 값 노출 없음.
  - `/timeline [N]`: 세션 in-memory tool 기록을 시간순 compact(redacted seq/corr/name/status/exit/duration).
  - `/compare`: 고정 Safe probe로 현재 시스템 스냅샷을 수집해 직전 baseline과 **line-set diff**(추가/제거).
    첫 호출은 baseline 저장 안내, 이후 변화 출력 + baseline 갱신. **LLM 호출 없음**.
  - `/bundle [name]`: 인시던트 증거(시스템+git read-only+최근 기록)를 redacted markdown으로
    `~/.aic/bundles/<name>-<ts>.md`에 저장(파일명 sanitize, dir 0700/file 0600 best-effort unix, 경로 출력).
    **name은 파일 라벨 전용으로 셸 명령에 미포함**. provider egress·history push 없음.
  - 보류(roadmap): `/runbook`(승인형 절차 실행), `/fix-preview`(diff 미리보기+confirm), `/config`(설정 편집),
    watch daemon(상시 모니터링), persistent audit 조회(`/audit tail`) 등은 후속.
- **slash 후보 선택형 패널 — reedline 이주(P2 완료)** — `aic chat` 대화형 입력기를 rustyline에서
  **reedline**으로 이주해 Claude 스타일 후보 패널을 제공한다. **`/` 입력 즉시** `command  설명`
  후보 패널(`ColumnarMenu`)이 열리고(Tab으로도 열기/순환), 메뉴 열림 상태에서 **↑↓**로 항목 이동(선택행 highlight), **Tab**
  순환, **Enter** 선택, **Esc** 닫기(라인 보존). 메뉴 닫힘 상태 ↑↓는 입력 history. `/local <section>`
  섹션 후보 포함. **삽입은 command/section 이름만**(설명은 표시용). 매칭은 prefix 우선 + subsequence
  fuzzy 폴백. history는 `FileBackedHistory`(`~/.config/aic/chat_history`)로 영속, NO_COLOR/non-TTY면
  메뉴 색상 비활성(선택행 reverse), 비-TTY는 기존 `read_line` 폴백. `LineReader` 공개 API 불변(호출부
  무변경). rustyline 의존성 제거.

### Added — Centralized Command Record Store (Phase 0~3.5)

세션 로컬 data plane (`RingBuffer` / `OutputProcessor` / `CommandBoundaryDetector`)
을 `aicd` 중앙 store 로 이전. 터미널 10 개 기동 기준 PTY byte processing 중복을
10 경로 -> 1 경로 (+ 세션별 state) 로 통합. 설계는
[RFC-001-CENTRALIZED-RECORD-STORE.md](./docs/RFC-001-CENTRALIZED-RECORD-STORE.md),
상세 spec 은 `.kiro/specs/centralized-record-store/`.

- **Phase 0** — `Central_Store_Flag` (env > config > Phase default 우선순위),
  `phase-3_1`~`phase-3_5` Cargo feature, Attach_UDS wire format,
  `BoundedByteChannel` (non-blocking drop + atomic counter),
  `AicdMetrics` / `AttachMetrics`. `HookEventStore` 를 `CommandRecordStore`
  로 rename.
- **Phase 3.1 Dual-Write** — `aic-session` 이 boundary 확정 시 local push 직후
  aicd 로 best-effort 복제 (100 ms timeout, silent skip). `aic history` 신규
  CLI.
- **Phase 3.2 Read Path** — `--session`/`--record`/`AIC_SESSION_ID` 경로가
  `aicd -> session socket -> shell history` 로 cascade.
- **Phase 3.3 Attach Stream** — 별도 Unix socket `aicd-attach.sock` 으로 PTY
  bytes streaming. stdout passthrough 가 backpressure 에 영향받지 않도록
  fan-out 순서 고정 (stdout -> attach -> local).
- **Phase 3.4 Local Removal** — `Central_Store_Flag=true` + attach 성공 시
  세션 로컬 data plane 을 아예 생성하지 않음. `Local_Fallback` on-demand,
  `BoundaryOwnershipGate`, 재연결 지수 backoff.
- **Phase 3.5 Legacy Cleanup** — 세션 로컬 socket 의 data plane variant 제거,
  client fallback 제거. Ping / RegisterRecord (hook CLI) / GetMetrics 만
  유지.
- **Observability** — `aic doctor` Central Store 섹션 (flag/source/phase/
  attach 연결 상태/dropped bytes/reconnect count). `GetMetrics` 로
  MetricsSnapshot 에 5 개 신규 필드 (`central_store_push_total`,
  `attach_connections`, `attach_open_total`, `dropped_bytes`,
  `attach_reconnect_total`).
- **CI** — phase x central_store x os 3D matrix, release 는 Phase 3.4 고정.
- **검증** — Correctness Properties P1~P6 를 proptest 256 cases 로 각각 검증.
  시나리오 A~D 의 cascade / attach 통합 테스트 추가.

### Tooling — RSS 측정 / 운영 스크립트

수동 RSS 검증 워크플로를 자동화하기 위한 bash helper 모음을 `scripts/`
디렉토리에 추가:

- `measure-rss-phase34.sh` / `measure-rss-phase30.sh` — `ps -o rss,comm` 으로
  현재 기동 중 세션의 RSS 를 모아 JSON 리포트 생성. 프로세스 0 개면 친절한
  ERROR 로 탈출.
- `spawn-aic-sessions.sh` — tmux 기반 N-세션 런처. `--with-aicd` 시 aicd 를
  같은 tmux session 에 띄우고 attach socket ready 대기 (race 회피).
- `pkill-aic.sh` — 상태 확인 + SIGTERM -> SIGKILL escalation.
- `verify-attach.sh` — 세션별 `AIC_SESSION_ID` 로 `aic doctor` 를 호출해
  각 세션이 실제로 attach 상태인지 (reconnect=0) 점검. **R6.6 의 실질적
  판정자**.
- `aicd-metrics.sh` — aicd Control_UDS 에 GetMetrics IPC 를 직접 보내
  `attach_connections` / `central_store_push_total` 등을 확인 (Python stdlib).
- `compare-rss.sh` — baseline/target JSON 비교 + 재정의된 R6.5 (회귀 방지)
  자동 판정.

### Changed — 측정 결과 반영한 spec 재조정 (requirements.md R6)

2026-05 실측 결과 Rust release 바이너리의 고정 비용 (공유 라이브러리 페이지 +
tokio runtime) 이 세션 RSS 의 절대다수를 차지해 당초 목표 "total 40~60 MB
/ session -60%" 가 달성 불가능함이 확인됐다. `.kiro/specs/centralized-
record-store/requirements.md` 의 R6 AC 를 아래로 현실화:

- R6.5: 절대 range -> **baseline 대비 +10% 이내 (회귀 방지)**
- R6.6: session 평균 -60% -> **10 세션 모두 attach 상태 + Local Fallback 없음
  의 구조적 검증** (`verify-attach.sh` 로 확인)
- R6.7 (신설): 아키텍처로 얻은 CPU 중복 제거 / durability / cross-session
  query / observability 이득을 명시

이 경로로 Task 7 (Final Checkpoint) 는 PASS 로 닫힘. 실측 히스토리:

- Phase 3.0 baseline: total 136.52 MB (session 평균 12.43 MB)
- Phase 3.4 target: total 139.36 MB (session 평균 12.65 MB, +2.1%)
- 10 세션 모두 attach_connections=10, reconnect=0 확인

## [0.4.0] - 2026-05-06

### Added — `aic update` 셀프업데이터 + `install.sh`

배포 경로가 brew 한 줄, source 빌드 두세 단계, 그리고 (지금까지) 모자란
manual install 경로로 흩어져 있어 신규 사용자 진입과 기존 사용자 갱신이
모두 번거로웠다. `x-mesh/gk`의 패턴을 그대로 차용해 정리.

- **`install.sh`** (POSIX sh) — `curl … | sh` 한 줄로 OS/arch
  (`linux`/`darwin` × `amd64`/`arm64`) 감지 → release archive +
  `checksums.txt` 다운 → SHA-256 검증 → `aic`/`aic-session`/`aicd`
  세 binary를 `/usr/local/bin`(권한 없으면 sudo) 또는 `~/.local/bin`에
  설치. `AIC_VERSION` / `AIC_INSTALL_DIR`로 핀/경로 override.
- **`aic update`** — `current_exe()` 경로로 설치 출처를 분류:
  - Brew(`/opt/homebrew`, `/usr/local/Cellar`, linuxbrew) →
    `brew upgrade x-mesh/tap/aic`로 위임.
  - Manual(`install.sh` 결과) → GitHub `releases/latest`의 tag을 받아
    archive 다운 + sha256 검증 + flate2/tar로 추출 → 세 binary를
    원자적으로 교체. 디렉토리 권한이 없으면 `sudo install`로 fallback.
    같은 디렉토리에 사이드카 binary가 없으면 그 항목만 skip하고
    경고 출력.
  - Cargo(`~/.cargo/bin`) → 자동 교체 거부, `cargo install --git ...`
    안내.
- **옵션** — `--check`(버전만 비교, 신버전이면 exit 1), `--force`,
  `--to <TAG>`(특정 tag 고정).
- **버전 비교** — semver(major.minor.patch) 기반, `v` prefix와 `-rc1`
  류 suffix는 무시. `dev` 같은 비-숫자 버전은 항상 "구버전"으로
  간주해 강제 재설치 없이도 update 가능 안내.
- **신규 의존성** — `flate2 = "1"`, `tar = "0.4"` (release archive
  추출용).

### Added — aicd 30s 주기 stale 세션 reconcile 루프

이전에는 `mark_stale_active_detached`가 `ListSessions`/`PruneSessions`
요청 처리 시점에만 돌아서, 외부 호출이 없으면 비정상 종료된 active
세션이 detached로 수렴하지 않았다.

- **`control_server::RECONCILE_INTERVAL`**(30s) 상수 +
  `pub fn spawn_reconcile_loop(ctx) -> JoinHandle<()>`. `tokio::time::
  interval` + `MissedTickBehavior::Skip`. 첫 즉시 tick은 건너뛰고
  한 주기 뒤부터 reconcile 시작.
- **`aicd_main`**: `ControlContext`를 변수로 묶어 `clone()`으로 백그라운드
  태스크 spawn, `serve()`가 shutdown으로 반환되면 `JoinHandle::abort()`.
  `Notify` 경합 없이 `serve()`만 shutdown 신호를 기다림.
- **idle 비용 0** — `mark_stale_active_detached`가 변경분 0이면
  `persist_registry`를 호출하지 않으므로 디스크 I/O 없음. STALE 후보가
  생긴 주기에서만 snapshot이 갱신된다.
- **주기 = STALE_ACTIVE_AFTER 동일** — active → detached 전환이 한
  주기 안에 잡히도록 의도적으로 같은 값.

### Docs

- **README.md / README.ko.md** — 원라이너 installer 섹션 + `aic update`
  서브커맨드 사용 가이드 추가. 한국어 README는 톤도 함께 다듬어 LLM
  분석/REPL 분기 설명 문구를 자연스럽게 정리.

### Tests

- aic-client `update` 모듈 9개 단위 테스트 — semver 비교, brew/manual/
  cargo 분류, asset 이름 템플릿(`aic_<ver>_<os>_<arch>.tar.gz`),
  archive 화이트리스트 추출(BINARIES 외 항목 무시), writable probe.
- 전 워크스페이스 테스트 통과(failed = 0), `cargo clippy --workspace
  -- -D warnings` 깨끗.

## [0.2.1] - 2026-04-30

### Added — Groq Cloud provider 정식 지원

- **`ProviderType::Groq` enum variant 추가** (aic-common). OpenAI 호환 API path를
  재사용하지만, `provider_type = "Groq"`로 지정하면 `endpoint`/`model`을 비워둬도
  `https://api.groq.com/openai/v1/chat/completions` + `llama-3.3-70b-versatile`
  기본값이 자동 적용된다. 기존 `OpenAiCompatible`로 endpoint를 직접 지정하던
  설정도 그대로 동작.
- **`aic config` wizard에 Groq 항목** — API key 입력 후 모델 선택
  (`llama-3.1-8b-instant` / `llama-3.3-70b-versatile` /
  `deepseek-r1-distill-llama-70b` / `gemma2-9b-it`).
- **`aic doctor`** — Groq variant도 OpenAI 호환과 동일한 검증 path를 탄다
  (api_key 존재, endpoint reachability, keychain 접근).
- **Streaming 지원** — Groq도 OpenAI-compat SSE를 사용하므로 TTY 환경에서
  자동 streaming.
- **`--dry-run` cost 추정** — Groq 공시 단가($/1M tokens) 매핑 추가.

### Added — `aicd` supervisor daemon (Phase 0~2.1)

PRD-AICD-SUPERVISOR의 control plane 부분. PTY ownership은 그대로 두고
사용자당 하나의 supervisor daemon으로 lifecycle/registry/cleanup을 중앙화.

- **`aicd` binary** (aic-server에 추가) — 사용자당 1개. `aicd.pid` singleton
  lock + `aicd.sock` control UDS. SIGINT/SIGTERM graceful shutdown.
- **Session registry** — `Arc<RwLock<HashMap<String, SessionInfo>>>`,
  read-heavy 동시성 (ListSessions가 압도적). `aic-session`이 시작 시
  `RegisterSession`, 종료 시 `UnregisterSession`을 best-effort로 호출.
- **Control IPC** — `Ping`/`ListSessions`/`Shutdown`/`RegisterSession`/
  `UnregisterSession`/`StopSession`. 모든 변종은 `IpcRequest` enum에
  통합되며 잘못된 데몬으로 보내면 graceful "wrong socket" Error 반환.
- **`SessionInfo` / `SessionState`** — id / pid / state / created_at /
  attached_tty / shell / cwd. PRD §10.2와 일치하는 6-state lifecycle.
- **CLI surface**
  - `aic daemon { status | start | stop }` — supervisor 제어. start는
    `current_exe()` 옆의 `aicd`를 우선, 없으면 PATH fallback.
  - `aic session stop <id>` — registry lookup → `SIGTERM` (PTY ownership
    이동 전까지의 bridge 구현; 프로세스 없음(ESRCH)이면 registry만 정리).
  - `aic sessions` — aicd registry-first. aicd 없으면 기존 socket scan
    fallback.
  - `aic doctor` — `aicd supervisor` 항목 추가. 실행 중이면 PASS+세션 수,
    아니면 WARN(선택사항이라 명확히 표시).

### Added — Hook capture mode (Phase 0, 3.1~3.3)

PRD-HOOK-CAPTURE-MODE의 metadata-only 캡처 옵션. PTY hook과 충돌 없이
공존 가능.

- **`CommandRecord` 확장** — `capture_mode`(Pty/Hook/ExplicitCapture),
  `capture_quality`(FullOutput/MetadataOnly/RedactedOutput/BinaryOmitted/
  TruncatedOutput/Unknown), `output_metadata`(stored bytes/lines, truncated
  flag, sha256). 모두 `#[serde(default)]` — 레거시 JSON/IPC 호환.
- **Hook event protocol** — `IpcRequest::CommandStarted` / `CommandFinished`.
  `aicd`가 per-session bounded ring(64)에 누적, command_id로 start/finish
  매칭, 매칭 실패 시 partial record(`command = None`)로 저장.
- **Hidden CLI** — `aic _hook-event { start | end }` (clap `hide=true`).
  Shell hook이 백그라운드로 호출. 100ms timeout, stderr only, aicd 미실행
  시 silent skip.
- **Shell hook installer** — `aic init --hook-mode` 시 `~/.aic/hook-events.
  {zsh,bash}` 설치 (version marker 1). zsh는 `preexec`/`precmd` +
  `add-zsh-hook`, bash는 `DEBUG trap` + `PROMPT_COMMAND`. 모든 호출은
  `(... &)`로 detach, redirect to `/dev/null` — prompt latency 영향 0.
  rc 파일에는 `# >>> aic hook-events >>>` ~ `# <<< aic hook-events <<<`
  마커로 멱등 source 라인 추가.
- **Explicit capture wrapper** — `aic run -- <cmd...>`. stdout/stderr를
  실시간 echo하면서 동시에 ring(line cap 1000, byte cap 256 KiB)에 수집.
  exit code 보존 (signal-killed는 128+sig). 결과 record는 capture_mode =
  ExplicitCapture, quality = FullOutput / TruncatedOutput.

### Added — Makefile release helpers

3개 workspace Cargo.toml의 버전을 손으로 바꾸는 부담 제거. release
워크플로우와 함께 동작.

- `make bump-version VERSION=0.3.0` — `[package]` section 안의 첫
  `version =` 줄만 awk로 교체. `[dependencies]` block의 `version`은
  안 건드린다 (`libc = "0.2"` 같은 entry 안전). cargo build로
  Cargo.lock도 자동 동기화.
- `make tag VERSION=0.3.0` — bump + commit + annotated tag(`v0.3.0`).
  버전 변경이 없으면 commit은 skip하고 tag만 생성.
- `make release-publish VERSION=0.3.0` — tag + push origin main + push
  tag. CI(GoReleaser)가 발화. origin remote가 `git@github.com:x-mesh/aic.git`을
  가리키는지 사용자가 사전에 확인.
- 0.2.0 round-trip 검증 — dependency version은 그대로 유지됨.

### Added — Release workflow (GoReleaser, gk 패턴 통일)

`v*` 태그 push 한 번으로 multi-arch binary 빌드 + GitHub Release +
`x-mesh/homebrew-tap` Formula 자동 갱신까지 처리. `x-mesh/gk`와 동일한
GoReleaser 파이프라인이라 팀 한 secret/한 멘탈 모델로 통일.

- **`.goreleaser.yaml`**:
  - 3 binary(`aic`/`aic-session`/`aicd`) × 4 target triple(linux/darwin
    × x86_64/aarch64) = 12 cross-compile job
  - `builder: rust` + `tool: cargo-zigbuild`로 ubuntu runner 단일에서
    darwin/linux 모두 cross-compile
  - 한 (os, arch)당 tar.gz 1개에 세 binary 모두 묶어 `brew install`
    한 번에 끝나게 함
  - `brews:` block이 `x-mesh/homebrew-tap/Formula/aic.rb`를 자동
    생성/갱신 — `Hardware::CPU.intel? / arm?` 분기 + url + sha256 +
    `bin.install` 3줄 + caveats(aic daemon install 안내)
- **`.github/workflows/release.yml`**:
  - `tags: ['v*']` push 또는 workflow_dispatch로 발화
  - Rust stable + 4 targets 설치 → cargo registry 캐시 → setup-zig +
    cargo-zigbuild 설치 → `goreleaser check` → `goreleaser release --clean`
  - `HOMEBREW_TAP_GITHUB_TOKEN` secret (gk와 동일 — org-level이면
    추가 등록 불필요)
- **`packaging/homebrew/aic.rb` 제거** — source-build Formula는
  GoReleaser binary path와 충돌하므로 단일 출처화 (GoReleaser가 master).
- **`RELEASING.md`** — TL;DR, secret 등록 절차(org-level 우선), 수동
  dry-run, 트러블슈팅, "왜 source-build를 안 쓰는가" 결정 기록.

이전 minimum 워크플로우(`mislav/bump-homebrew-formula-action` +
source tarball)는 GoReleaser 패턴으로 완전 교체됐다.

### Added — `aic daemon install` / `uninstall` (OS-native auto-start)

부팅 시 `aicd` 자동 시작을 한 명령으로 양 OS 모두 처리. `brew services`는
macOS launchd만 잘 통합하고 Linux brew에선 stub이라 이 경로를 직접 둔다.

- **macOS**: `~/Library/LaunchAgents/com.x-mesh.aicd.plist`
  - `RunAtLoad=true`, `KeepAlive=true`, `ProcessType=Background`
  - stdout/stderr → `~/.local/state/aic/aicd.{out,err}.log`
  - `launchctl bootstrap gui/$UID <plist>` (modern), 실패 시 `launchctl load`
    fallback. uninstall은 `bootout`/`unload` 둘 다 시도.
- **Linux**: `~/.config/systemd/user/aicd.service` (또는 `$XDG_CONFIG_HOME`)
  - `Type=simple`, `Restart=on-failure`, `WantedBy=default.target`
  - `systemctl --user daemon-reload && enable --now aicd.service`. uninstall은
    `disable --now` + `daemon-reload`.
- **공통**: `--no-load`로 파일만 쓰고 OS 호출은 건너뛸 수 있음 (CI / 시스템
  영향 없는 dry-run). 멱등 — 같은 내용이면 mtime 보존을 위해 write도 skip.
  Unit 내용이 바뀌면 자동 재작성.
- **`aic daemon status`** 가 unit 설치 상태도 함께 표시
  (`autostart: installed (unit: ...)` 또는 `not installed (run: aic daemon install)`).
- **`aicd` 경로 결정**: `current_exe()` 옆의 `aicd`를 우선 사용 (brew/cargo
  install 모두 같은 디렉토리에 둠). 없으면 PATH fallback.

테스트:
- `daemon_install::tests` 5개 — plist/unit 렌더링, OS 감지,
  `XDG_CONFIG_HOME` 존중, plist 경로 형식. OS 호출은 manual smoke로 검증
  (임시 HOME으로 install/uninstall 사이클 PASS).

사용자 흐름:
```sh
brew install x-mesh/tap/aic   # 또는 source 빌드
aic daemon install            # 부팅 시 자동 시작 + 즉시 실행
aic daemon status             # ✓ running, ✓ installed
aic daemon uninstall          # 정리
```

### Fixed — CLI Backend(`kiro-cli`/`claude`) 호출 형식 수정

`send_cli`가 prompt를 첫 positional argument로 그대로 전달하는 바람에:
- `kiro-cli`는 prompt 첫 단어를 unknown subcommand로 해석 → "unrecognized
  subcommand 'ssdsd...'" 에러
- `claude` (claude-cli)는 interactive session 시작 시도 → non-interactive
  컨텍스트에서 행 또는 깨짐

해결:
- **`ProviderConfig::cli_args: Option<Vec<String>>`** 신규 필드
  (`#[serde(default)]`, 레거시 config 호환). prompt 앞에 prepend되는 인자.
- **`resolve_cli_args(cli_path, override)` helper** — 사용자 명시값이
  있으면 그대로, 없으면 `cli_path` basename에서 자동 추론:
  - `kiro-cli` / `kiro` → `["chat"]`
  - `claude` / `claude-cli` → `["-p"]`
  - 그 외 → `[]` (legacy 동작 보존)
- `send_cli`은 `<cli_path> <args...> <prompt>` 순서로 spawn.
- 모든 ProviderConfig literal site에 `cli_args: None` 마이그레이션
  (perl 일괄 + nested struct 2건 수동).
- 4개 unit test: kiro chat 자동 추론, claude -p 자동 추론, unknown CLI
  no-op, user override 우선.

사용자 측 영향:
- 기존 `cli_path = "kiro-cli"` config는 자동으로 `chat` subcommand가
  붙는다 — config 수정 불필요.
- 다른 인자가 필요한 경우 `cli_args = ["chat", "--no-color"]` 식으로
  명시 가능.

### Fixed — Anthropic 모델 ID 갱신 (HTTP 404 회귀)

옛 모델 ID(`claude-3-5-haiku-20241022`, `claude-sonnet-4-20250514` 등)가
Anthropic API에서 retire되어 호출 시 HTTP 404를 반환하던 회귀를 차단.

- `LlmDispatcher::send_anthropic` / `streaming` Anthropic path의 default
  모델을 `claude-sonnet-4-6`로 갱신 (두 곳 모두).
- `aic config` wizard의 Anthropic 모델 선택 옵션을
  `claude-sonnet-4-6` / `claude-opus-4-7` / `claude-haiku-4-5-20251001`로
  교체. 라벨도 함께 갱신.
- example `config.toml` 템플릿 (`aic config show example`) 모델 + 권장 안내
  코멘트 추가.
- `dry-run` cost 매핑(`estimate_cost_usd`)에 4.x family 단가 추가
  (sonnet 4.6 = $3/$15, opus 4.7 = $15/$75, haiku 4.5 = $1/$5; 정확한
  단가는 https://www.anthropic.com/pricing 참조).
- `aic doctor`가 retired 모델 ID 사용 시 WARN으로 안내 + fix hint 제공
  (`is_anthropic_retired_model` heuristic으로 `claude-2*`, `claude-instant*`,
  `claude-3-*`, `claude-{sonnet,opus}-4-20250514` 매칭). 새 4.x family는
  PASS.
- 통합 테스트(`aic-client/tests/llm_integration.rs`)도 새 모델 ID로 갱신.

### Added — Hybrid mode + capture quality hint (Phase 4)

- **`SessionCaptureMode`** — `Pty` / `Hook` / `Hybrid`. `[session]
  capture_mode` config. 레거시 config는 default(Pty)로 자동 채움.
- **`capture_quality_hint(record, mode)`** — FullOutput에선 무음, 그 외
  품질에서는 사용자에게 신뢰도 + 대안(`aic run -- <cmd>` 등) 안내.
  `aic` 분석 시 `print_error_context` 직후 stderr에 dim line으로 출력.

### Removed
- root의 `PRD-AICD-SUPERVISOR.md` / `PRD-HOOK-CAPTURE-MODE.md` /
  `CAPTURE-MODE-TRADEOFFS.md` — `docs/` 하위로 이동, 단일 출처화.

### Tests
- aic-common lib: 42 → 64 (capture mode/quality, hint, registry serde,
  legacy compat, hook event proptest 확장)
- aic-server lib: 56 → 95 (control_server 6, session_registry 7,
  hook_events 4, aicd_client 4 + 통합)
- aic-client lib: 130 → 162 (hook_install 3, doctor aicd, daemon CLI 등)
- 전 워크스페이스 직렬 실행: failed = 0

### Architectural Decisions
- **PTY ownership 이동(PRD-AICD-SUPERVISOR Phase 2 본 구현)은 보류** —
  raw mode 복원/relay regression 위험이 커서 별도 sprint로 분리. 현재
  `aic session stop`은 PID에 SIGTERM을 보내는 bridge 구현이며,
  `aic-session`의 기존 shutdown 핸들러가 PTY/소켓을 정리한다.
- **Control plane 분리** — `UdsServer`(RingBuffer 결합)와 별도로
  `ControlServer` 신규. aicd는 출력을 소유하지 않으므로 같은 서버를
  재사용하면 layering이 흐려진다.
- **Hook event는 외부 명령(`aic _hook-event`) 호출** — shell에서 raw UDS
  바이트 전송이 어려워 단순함을 우선. 백그라운드(`&`) detach + 100ms
  timeout으로 prompt latency 영향 방지. 향후 socket connector로 최적화 여지.
- **aicd 자동 spawn은 명시 명령에서만** — `aic daemon start` /
  `aic doctor --fix`(미구현). `aic-session`/`aic` 자동 spawn은 사용자
  의도 모호 + 권한 이슈로 보류.

---

## [0.2.0] — Pre-Phase Baseline

### Added — Subcommand
- `aic doctor [--json]` — 8축 환경 진단 (config / provider / UDS 소켓 / 데몬 / 셸 hook / LLM endpoint / keychain / audit log). FAIL 시 exit 1.
- `aic status [--watch] [--interval N]` — 데몬 PID/ping/마지막 명령어 + metrics(uptime, IPC count, RingBuffer 사용률, last cmd ago). watch 모드는 1초 polling + clear-screen.
- `aic top [--interval N]` — `aic status --watch`의 alias.
- `aic audit verify` — audit log HMAC chain 무결성 검증. Exit 0=valid, 2=tampered, 3=key/IO error.
- `aic config show [--json]` — 비-인터랙티브 설정 출력 (TOML 기본, JSON 옵션).
- `aic config get <path>` — dotted path 단일 값 추출. scalar는 raw, object는 JSON pretty.
- `aic migrate-keys` — config.toml의 평문 API key를 OS keychain으로 일괄 이동.
- `aic init <shell>` — `~/.zshrc`/`~/.bashrc`에 `source ~/.aic/hooks.{shell}` 멱등 추가 (마커 기반 롤백 가능).
- `aic --dry-run "<prompt>"` — 실제 LLM 호출 없이 토큰·비용·timeout 미리보기.
- `aic --version` / `aic-session --version`.

### Added — 보안 baseline (judge2 FAIL 보강)
- **Secret/PII redaction**: secret 5종 (anthropic key, openai key, AWS, GitHub, JWT) + Shannon entropy ≥3.0 보조 검증, PII 4종 (email, 한국 전화, 주민번호, IPv4). LLM 송신 직전 단일 stage. `AIC_REDACT=off` opt-out.
- **Audit log HMAC chain**: `~/.local/state/aic/audit.log` JSONL append-only (file 0600, dir 0700), HMAC-SHA256 line chain. 변조 시 `aic audit verify`가 정확한 라인 번호 반환. 100MB×5 rotate.
- **OS keychain**: macOS Keychain / Linux Secret Service / Windows Credential Manager. config.toml에는 `api_key = "keychain:<name>"` reference.

### Added — 가시성·진단
- **구조화 trace 로그** (aic-session): `tracing` + `tracing-subscriber` + `tracing-appender` 도입. `~/.local/state/aic/server.log` JSONL daily rotate (max 7 files). `AIC_LOG=info|debug|trace` env-filter. panic hook 자동 등록.
- **데몬 metrics**: `IpcRequest::GetMetrics` + `MetricsSnapshot` (uptime, PID, IPC request count, RB used/capacity, last command secs ago).
- **Ring Buffer 점유율**: `RingBuffer::capacity()` 메서드 추가.

### Added — 안정성
- **PID lock 단일 인스턴스**: `fcntl(F_SETLK)` advisory write lock + PID file. 이미 살아있는 인스턴스 감지 시 즉시 종료, stale lock 자동 정리.
- **Graceful shutdown**: SIGTERM/SIGINT 핸들러 — 터미널 raw mode 복원 → background task abort → 소켓 unlink → lock drop 순서.
- **Retry circuit breaker**: 60초 window 5회 실패 시 30초 fail-fast. provider별로 격리.
- **AicError::is_retryable / user_message**: HTTP 5xx/429/network=retryable, status별 친화 메시지.
- **HTTP timeout 분리**: connect 5s + request 30s (이전 단일 60s).

### Added — UX
- **LLM streaming**: OpenAI compat + TTY + `AIC_NO_STREAM` 미설정 시 자동 활성. SSE 파싱 (`eventsource-stream` 없이 직접 구현). 첫 토큰부터 incremental stdout.
- **Spinner**: 비-streaming 호출 대기 중 isatty(stderr)에만 출력. stdout 파이프 회귀 없음.
- **결과 캐시**: `~/.cache/aic/analyses/<hash>.json`. 24h TTL. 같은 (cmd, exit, output_tail) 조합은 즉시 응답 + "(캐시)" 신호.
- **i18n 자동 감지**: `lang = "auto"` 시 `$LC_ALL`/`$LANG` 추론 (ko/en/ja/zh).

### Added — Onboarding
- **셀프-힐링 워크플로우**: `aic doctor`가 다음 액션 명령(`aic init zsh`, `aic migrate-keys`)을 직접 안내.

### Fixed
- **SIGWINCH ↔ wait_for_exit Mutex 데드락** (aic-server) — `Arc<Mutex<PtyManager>>`를 `wait_handle`이 자식 셸 종료까지 영구 점유, SIGWINCH 핸들러가 lock 대기로 worker thread hang. PtyManager에 `take_child()` 추가하여 spawn 직전에 child만 take, lock 해제 후 lock 밖에서 `wait()`. macOS `sample <pid>`로 진단.
- **PTY stderr 누수** — `uds_server::serve`/`handle_client`의 `eprintln!`을 `tracing::warn`/`debug`로 변경. PTY 환경에서 server stderr가 사용자 터미널에 직접 출력되던 문제 해결.
- **Forward compatibility** — `IpcRequest` 역직렬화 실패 시 graceful `IpcResponse::Error` 응답. 옛 client + 새 server 또는 그 반대 호환.
- **redaction false positive 감소** — secret 패턴에 Shannon entropy ≥3.0 보조 검증. `ghp_aaaa...` 같은 단조 패턴은 redact 안 함.

### Added — Environment Variables
| 변수 | 효과 |
|---|---|
| `AIC_LOG=info|debug|trace` | aic-session tracing 레벨 (기본 info) |
| `AIC_REDACT=off` | secret/PII redaction 비활성 (audit `redact_bypassed` 기록) |
| `AIC_NO_STREAM=1` | streaming 비활성 (spinner + sectional 출력) |
| `AIC_DEBUG=1` | client `[debug +X.XXXs]` prefix 출력 |

### Dependencies (신규, 모두 MIT/Apache/ISC)
- aic-server: `tracing`, `tracing-subscriber`, `tracing-appender`
- aic-client: `regex`, `sha2`, `hmac`, `keyring`

### Tests
- aic-client lib: 130 tests (이전 76 → +54)
- aic-server lib: 56 tests (이전 44 → +12)
- aic-common lib: 42 tests
- **합계 228/228 통과**, `cargo clippy --workspace --all-targets -- -D warnings` ✅ 깨끗.

### Architectural Decisions
- **launchd/systemd unit**: PTY-wrapping 모델은 사용자 터미널에 stdin/stdout 종속이라 background autostart 부적합. 보류, RFC 후 재검토.
- **네임스페이스 멀티 소켓**: PID lock 단일 인스턴스 보장으로 stale 충돌 자체가 막힘. 별도 항목 불필요.
- **OSC 8 hyperlink**: URL handler 등록 비용 모호. 가치 재평가 후 진행.

---

## [0.1.0] — initial

기본 기능 (PTY 셸 wrapping, OSC 133 명령어 경계, exit_code 분기, 다중 LLM provider, REPL 모드, TUI 호환).
