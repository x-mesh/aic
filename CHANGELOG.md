# Changelog

[Keep a Changelog](https://keepachangelog.com/) 형식. 모든 항목은 사용자가 직접 체감 가능한 변화 기준.

## [Unreleased]

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
