# Phase 2 — RCA 도구 확장 계획

> Phase 1(v0.27.0, 가시성 1차: web 탭 확장·External 딥링크·유사 과거 사건 버튼·runbooks 조회·auto_remember)의 후속.
> 목표: **문제 상황을 더 빠르고 확실하게 알게 한다.** 그리고 알아낸 것을 **밖으로 보낼 준비**를 한다.
>
> 참고: Cargo feature의 `phase-3_x`는 빌드 단계 이름이고, 이 문서의 "Phase 2"는 RCA/가시성 작업 스트림 이름이다. 서로 무관하다.
>
> 이 문서는 5개 모델 적대 패널(claude-opus-4-8 / codex-gpt-5.5 / gemini-3.1-pro / cursor / kiro) 리뷰를 1회 반영했다.
> 반영 요지: O2 "어댑터만" 자기모순 해소, C1/C4의 pull 경계 근거 명시, 실행 순서 재배치(W3↑·M1↓),
> M1/M2 신뢰·보안 게이트 추가, **Track D(진단 품질·신뢰도) 신설**. 변경 이력은 문서 끝에 요약.

## 원칙 (SRE-SCOPE-BOUNDARY.md 유지)

- aic는 **pull**이다. 사람이 부르거나, webhook이 한 번 트리거한다. 상시 감시 루프를 만들지 않는다.
- 상시 감시·기억(anomaly score, fingerprint DB, incident 매칭)은 **sre-agent** 것이다. aic는 MCP로 **조회만** 한다.
- 외부로 나가는 모든 데이터는 **redaction 통과 + confirm gate + HMAC audit** 3종을 거친다.
- **외부 전송 목적지는 deny-by-default.** config `allowlist`에 등록된 목적지에만 나간다. 임의 URL 전송 불가.
- read-only 원칙 유지. 이번 Phase에도 원격 시스템을 바꾸는 mutation 도구는 없다. (외부 "전송"은 로컬 데이터를 내보내는 것이지 원격 상태를 바꾸는 게 아니다 — 경계 안.)
- **세션 스코프 구독 ≠ 상시 감시 루프.** chat 세션이 열려 있는 동안, 사용자가 opt-in(`/watch`)한 이벤트만 수신한다. 세션이 닫히면 사라진다. 백그라운드 데몬이 상시 도는 것이 아니다 — pull 경계 안.

## 현재 상태 요약

| 영역 | 있는 것 | 없는 것 |
|------|---------|---------|
| web (`aic-client/src/web.rs`, 2.7k LOC) | 9개 탭(Chat/Snapshots/Incidents/Audit/History/Webhooks/Server log/Config/External), 유사 사건 버튼, External 딥링크, 전면 redaction | incident 상세(evidence/가설/타임라인), fingerprint 반복 추이, 첫 화면 요약, sre-agent 데이터 뷰 |
| chat (`agent/session.rs`, `chat_tui.rs`) | alert lane(로컬 메트릭 edge-trigger), `/diagnose`, `/local`, `/watch`, `/rca`, `/triage`, MCP 도구 자동 병합 | webhook alert의 chat 유입, 세션 시작 브리핑, finding→과거 사건 자동 힌트 |
| outbound | `aic rca bundle`(로컬 파일), `record_incident`(sre-agent push) | **전무.** Notifier/Sink 추상화 없음, Slack/webhook-out 없음 |
| MCP (`agent/mcp.rs`) | HTTP(Streamable) client, chat 도구 병합, rca_memory 3종(match/runbooks/record), web similar 연동 | stdio transport, sre-agent 조회 래퍼 확대, aic-as-MCP-server |

---

## Track W — web 가시성 확장

### W1. Incident 상세 뷰 (우선순위 1)

- **무엇**: `/web/incidents/{id}`에 상세 화면 추가. evidence 목록, 가설(hypothesis) 목록과 상태(support/refute/confirm), 타임라인, TTM/MTTR을 보여준다.
- **왜**: 데이터는 이미 디스크에 있다(`rca.rs`의 meta.json + evidence.jsonl + hypotheses). 지금 web은 요약 6개 필드만 보여줘서, 결국 터미널로 돌아가야 한다.
- **어떻게**: `incident_view`(web.rs:2170) 옆에 `incident_detail` 핸들러 추가. evidence는 페이지네이션(`?offset=`, 서버 측 상한 200줄/요청), 본문은 기존 redaction 경유. 대시보드 JS에 Incidents 탭 클릭 → 상세 패널. **파일 읽기는 `spawn_blocking`으로** — axum async 런타임을 sync file I/O로 블로킹하지 않는다(패널 지적: gemini).
- **완료 기준**: 열린 incident의 증거·가설·타임라인이 브라우저에서 모두 보인다. 시크릿이 새지 않는다(redaction 테스트 포함). evidence.jsonl이 손상/부분기록이어도 파싱 실패 줄을 건너뛰고 나머지를 렌더한다(대용량·정합성 실패 모드).

### W2. 첫 화면 "지금 상태" 요약 스트립 (우선순위 1)

- **무엇**: 대시보드 최상단에 한 줄 요약 — 열린 incident 수, 최근 1시간 webhook alert 수, 마지막 finding, 리소스 스파크라인.
- **왜**: 지금은 탭을 돌아다녀야 전체 그림이 잡힌다. "문제가 있는가?"에 3초 안에 답해야 한다.
- **어떻게**: 단일 요약 엔드포인트 `/web/summary` 하나를 서버에서 조합해 내려준다(패널 지적: 3개 엔드포인트 waterfall은 TTFB·지터로 3초 목표를 깬다 — codex/cursor/kiro). 각 값에 **freshness(마지막 수집 시각)와 데이터 유무**를 함께 실어, 수집 실패를 "정상"으로 오인하지 않게 한다(Track D의 D3와 연동). 항목 클릭 시 해당 탭으로 이동.
- **완료 기준**: 접속 직후 스크롤 없이 상태 판단이 가능하다. 각 지표에 "N초 전" 신선도가 붙는다. 문제가 없으면 명시적 초록 all-clear(D4)를 보여준다.

### W3. Fingerprint 반복 추이 뷰 (우선순위 1 — 패널 반영, 2→1 승격)

- **무엇**: Webhooks 탭에 fingerprint별 그룹핑 — 같은 알림이 몇 번, 언제부터 반복되는지 미니 타임라인.
- **왜**: "이 alert 처음인가, 만성인가"가 초동 판단의 절반이다. fingerprint는 이미 webhook_server가 계산해 저장한다. 의존성이 없고 초동 판단에 직결되므로 1차로 올린다(패널 지적: claude — W3가 3차로 밀린 건 목표 역행).
- **어떻게**: 그룹핑은 **서버 측 단일 책임**으로 `/web/webhooks?group=fingerprint`에서 수행(프런트 이중 그룹핑 금지 — 책임 경계 명확화). **기본 시간창 24h·최대 top-N(50) 그룹** 상한을 두어 알림 수백 종에서도 UI·성능이 무너지지 않게 한다(패널 지적: kiro/cursor/agy). 각 그룹에서 External 딥링크(`externalAtMoment`) 재사용.
- **경계**: aic는 **로컬 webhook 저장소만** 그룹핑한다(bounded). 교차 호스트·장기 fingerprint 추이는 sre-agent 소유 — 여기서 계산하지 않는다.
- **완료 기준**: 반복 알림이 한 행으로 접히고, 발생 시각들이 점으로 보인다. 24h·top-50 상한이 적용된다.

### W4. sre-agent 읽기 전용 뷰 (우선순위 2, Track M2에 의존)

- **무엇**: "Watch" 탭 신설 — sre-agent의 anomaly_scores, 최근 findings, fingerprint 상태를 MCP로 조회해 표시. sre-agent 미설정이면 탭에 `available: false` 안내(기존 similar 버튼과 같은 패턴, web.rs:2220).
- **왜**: 상시 감시 결과는 sre-agent에 있는데, 보려면 별도 도구가 필요하다. aic web이 조회 창구가 되면 경계(조회만)를 지키면서 가시성이 완성된다.
- **어떻게**: **web 요청 경로에서 MCP를 동기 호출하지 않는다**(패널 지적: cursor — 대시보드 지연·장애 전파). 백그라운드 태스크가 주기적으로 sre-agent를 조회해 **최근 스냅샷을 로컬 캐시**에 적재하고, web 핸들러는 캐시만 읽는다(stale-while-revalidate, TTL 30초). sre-agent 장애가 대시보드를 멈추게 하지 않는다.
- **완료 기준**: sre-agent가 켜져 있으면 anomaly/finding이 브라우저에 보이고, 꺼져 있으면 조용히 안내만 나온다. sre-agent가 죽어도 대시보드는 마지막 캐시로 응답한다.

---

## Track C — chat 즉시 감지 강화

### C1. webhook alert의 chat 유입 (우선순위 1)

- **무엇**: aicd webhook_server가 받은 alert를, 열려 있는 interactive chat 세션에 ambient Note로 주입한다. 기존 alert lane(로컬 메트릭)과 같은 레인을 쓴다.
- **왜**: 지금 webhook은 `aic diagnose --bundle`을 백그라운드로 띄울 뿐, 사용자가 chat에 앉아 있어도 아무것도 모른다. "즉시 안다"의 가장 큰 구멍.
- **경계 (패널 지적: cursor/kiro — pull 원칙 위반 우려)**: 이건 상시 감시 데몬이 아니다. **열려 있는 chat 세션이, opt-in(`/watch`)한 동안에만** UDS 이벤트를 소비한다. 세션이 닫히면 구독도 끝난다. webhook을 "받아 진단"하는 기존 aicd 역할(이미 존재)의 결과를, 마침 열려 있는 사람 세션에 **보여줄 뿐** — 새 감시 주체를 만들지 않는다. 기본값은 off, 명시적 arm 필요.
- **어떻게**: webhook_server(612 LOC)가 alert 수신 시 UDS 이벤트를 발행 → chat의 `AlertTracker` 경로(chat_tui.rs:1358 배선)에 새 소스로 합류. edge-trigger·mute 규칙은 기존 것 재사용. **세션 레벨 noise gate**(D5)로 동일 fingerprint 폭주를 throttle/dedup. `/watch` 토글로 켜고 끈다.
- **완료 기준**: chat을 켜둔 상태에서 webhook alert가 오면 수 초 내 Note + bell이 뜬다. mute 시 조용하다. 같은 fingerprint 100개가 와도 Note는 throttle된다. 세션을 닫으면 구독이 사라진다.

### C2. 세션 시작 브리핑 (우선순위 1)

- **무엇**: interactive chat 시작 시 한 블록 브리핑 — 열린 incident, 최근 24h alert 요약, 마지막 세션의 미결 `/rca` 상태.
- **왜**: "어제 그 문제 어떻게 됐지"를 매번 수동으로 캐야 한다. 시작 시점이 문제 인지의 첫 기회다.
- **어떻게**: `ChatLoop` 시작부(session.rs:326 인근)에서 로컬 incident index + webhook store를 읽어 시스템 컨텍스트 블록 1개로 렌더. LLM 호출 없음(비용 0). 없으면 아예 출력 생략.
- **완료 기준**: 열린 incident가 있으면 첫 화면에 보이고, 없으면 브리핑 자체가 안 보인다.

### C3. finding → 과거 사건 자동 힌트 (우선순위 2)

- **무엇**: `/diagnose`·`/local`이 finding을 만들면, sre-agent `match_incidents`를 자동 조회해 "유사 과거 사건 N건 — `/rca similar`로 확인" 한 줄을 덧붙인다.
- **왜**: web에는 이미 있는 기능(similar 버튼)인데 chat에는 없다. 진단 순간이 매칭이 가장 유용한 순간이다.
- **어떻게**: `scan_findings` 후처리에서 `rca_memory::match_incidents`(rca_memory.rs:57) 호출. 미설정 시 기존처럼 조용히 None. 타임아웃 2초 — 진단 출력을 지연시키지 않는다. **동일 finding fingerprint에 대한 힌트는 세션당 1회만**(noise gate, D5) — 매 진단마다 같은 줄이 반복되지 않는다(패널 지적: codex).
- **완료 기준**: sre-agent 연결 시 finding 아래 힌트 한 줄, 미연결 시 아무 변화 없음. 같은 finding 반복 시 힌트가 중복되지 않는다.

### C4. `/watch` 대상 확장 (우선순위 2 — 패널 반영, 3→2 승격)

- **무엇**: `/watch add proc <name>`, `/watch add port <n>` — 특정 프로세스 사망·포트 소실을 alert lane에 추가.
- **왜**: 지금 alert lane은 전역 메트릭만 본다. "이 데몬이 죽으면 알려줘"가 실전에서 가장 흔한 요구다. 문서 스스로 최빈 요구라 하면서 3차로 둔 건 자기모순이고, 비용도 세션-바운드로 저렴하다(패널 지적: claude).
- **경계 (패널 지적: kiro/codex/cursor)**: 새 polling 루프를 만드는 게 아니라 **이미 도는 `sys_sampler` 샘플 주기에 대상 검사만 얹는다**. 상태는 세션 메모리에만 있고 디스크에 안 쓴다. 세션이 끝나면 사라지는 bounded probe — 상시 감시 데몬이 아니다.
- **어떻게**: `sys_sampler.rs`의 기존 샘플 루프에 대상 목록 검사 추가(신규 스레드 없음). edge-trigger·noise gate 재사용.
- **완료 기준**: watch 대상 프로세스를 kill하면 Note가 뜬다. 세션 종료 시 목록이 사라진다. 신규 백그라운드 스레드가 생기지 않는다.

---

## Track O — outbound 어댑터 준비 (어댑터만)

> Phase 2는 **전송 계층의 뼈대**까지만 만든다. Slack 등 실제 목적지 구현은 Phase 3.
> 근거: SRE-SCOPE-BOUNDARY.md 로드맵 4번(팀 공유)의 선행 작업.
>
> **"어댑터만"의 정확한 뜻 (패널 지적: cursor/codex/agy 합의)**: 이 Phase에서 **실제로 네트워크 전송이 켜지는 어댑터는 없다.**
> `FileAdapter`(로컬 파일 기록)만 기본 활성이고, `WebhookAdapter`는 코드·테스트로 완성하되 **기본 비활성 + allowlist 미등록 시 전송 거부**다.
> 즉 뼈대(스키마·trait·redaction·confirm·audit·정책)는 완성하지만, 임의 외부 URL로 데이터가 나가는 경로는 Phase 2에서 열리지 않는다.
> 이렇게 하면 "read-only/pull" 원칙과 충돌하지 않으면서 Phase 3의 실전송을 위한 안전한 토대만 깐다.

### O1. OutboundPayload 정규화 스키마 (우선순위 1)

- **무엇**: 밖으로 보낼 수 있는 것들(incident report, bundle, finding 요약)을 하나의 구조체로 통일 — `title, severity, fingerprint, body_md, evidence_refs, created_at, source(host/session)`.
- **왜**: 목적지마다 페이로드를 따로 만들면 어댑터를 늘릴 때마다 변환 코드가 곱으로 는다. 스키마를 먼저 고정해야 어댑터가 얇아진다.
- **어떻게**: `aic-client/src/outbound/mod.rs` 신설. `rca.rs`의 report 렌더러와 bundle 생성기가 이 구조체를 거치도록 리팩터. 직렬화는 serde JSON. **redaction 상태를 타입으로 인코딩** — `OutboundPayload`는 항상 redacted 마커 타입만 담고, raw→redacted 변환은 생성자에서만 일어난다(O2가 아니라 O1의 책임으로 못박음, 패널 지적: kiro). **deny-by-default 정책과 audit 레코드 스키마도 O1에서 함께 고정**한다(어댑터 구현이 정책보다 먼저 가지 않게 — 패널 지적: cursor).
- **완료 기준**: `aic rca report`와 `aic rca bundle`이 내부적으로 OutboundPayload를 경유하며, 기존 출력이 바이트 단위로 달라지지 않는다(회귀 테스트). redaction 안 된 데이터로 `OutboundPayload`를 만들 수 없다(컴파일 단계 차단). audit 레코드 필드·정책 스키마가 문서화된다.

### O2. OutboundAdapter trait + 2개 구현 (우선순위 1)

- **무엇**:
  ```rust
  trait OutboundAdapter {
      fn name(&self) -> &str;
      fn deliver(&self, payload: &OutboundPayload) -> Result<DeliveryReceipt>;
  }
  ```
  구현은 딱 2개 — `FileAdapter`(디렉토리에 JSON/MD 기록, **기본 활성**, dry-run 겸 검증용)와 `WebhookAdapter`(generic HTTP POST, Bearer/HMAC-signature 헤더 옵션, **기본 비활성 + allowlist 게이트**).
- **왜**: file 어댑터는 외부 의존 없이 파이프라인 전체(정규화→redaction→confirm→audit→기록)를 CI에서 검증하게 해준다. generic webhook 하나면 Slack incoming-webhook·사내 시스템 대부분이 이미 커버된다.
- **payload 변환 주의 (패널 지적: agy)**: generic webhook은 Slack/PagerDuty의 고유 JSON 스키마와 다르다. Phase 2의 `WebhookAdapter`는 **범용 envelope**(OutboundPayload를 그대로 POST)만 보내고, 목적지별 포맷 변환(Slack blocks 등)은 Phase 3의 목적지 전용 어댑터가 맡는다. 이 한계를 문서에 명시.
- **어떻게**: `outbound/file.rs`, `outbound/webhook.rs`. 전송 직전 `redaction::redact` 강제는 O1의 타입으로 이미 보장. `WebhookAdapter.deliver`는 목적지가 **allowlist에 없으면 즉시 거부**(전송 시도조차 안 함). confirm gate는 interactive면 프롬프트, 비-interactive면 `--yes` 필수. `--dry-run`은 redacted payload를 stdout에 렌더하고 전송 안 함(보내기 전 "이렇게 나갑니다" 확인, 패널 제안: gemini). 전송 성공/실패를 HMAC audit 로그에 기록.
- **완료 기준**: `FileAdapter` 왕복 CI 테스트 green. redaction을 우회한 전송이 컴파일 단계에서 불가능하다. `WebhookAdapter`는 allowlist 미등록 목적지를 거부하는 테스트가 green. `--dry-run`이 실제 전송 없이 미리보기를 낸다.

### O3. config `[outbound]` 섹션 + CLI 진입점 (우선순위 2)

- **무엇**: `AppConfig`에 `outbound: OutboundConfig` 추가(`#[serde(default)]`, 기존 섹션과 같은 패턴 — aic-common/lib.rs:242 인근). 목적지 목록 `targets: HashMap<name, TargetConfig>`. CLI는 `aic rca send <incident-id> --to <target>` 하나만.
- **왜**: 어댑터가 있어도 부를 방법이 없으면 죽은 코드다. 단, 진입점은 최소로 — chat `/bundle --send`나 자동 전송은 Phase 3에서 판단.
- **어떻게**: RcaConfig 추가 때(0.27.0)와 동일한 절차 — 테스트 AppConfig 생성부 전부 갱신(18d704f, 073c258에서 두 번 겪은 함정. 처음부터 한 커밋에 포함할 것).
- **완료 기준**: `aic rca send <id> --to file-local`이 confirm 후 파일을 만들고 audit에 남는다. config 없는 기존 사용자는 아무 변화를 못 느낀다.

---

## Track M — MCP 외부 연동

### M1. stdio transport 추가 (우선순위 2 — 패널 반영, 1→2 강등)

- **무엇**: `McpClient`(agent/mcp.rs:70)에 stdio transport 추가. config에서 `url` 대신 `command + args`를 주면 자식 프로세스로 spawn해 JSON-RPC over stdio.
- **왜**: 현재 HTTP(Streamable)만 지원해서, 로컬 stdio 전용 MCP 서버(대부분의 커뮤니티 서버, 로컬 sre-agent stdio 모드)를 못 붙인다. 외부 연동의 관문. 단, **sre-agent는 이미 HTTP MCP로 도달 가능**하므로 M2의 선행 조건은 아니다(패널 지적: claude — stdio의 구체 소비자가 불명확하니 M2를 먼저).
- **보안 게이트 (패널 지적: cursor/kiro/agy 합의)**: config 기반 임의 command spawn은 위험하다. (1) command는 **명시적 config 등록분만** 실행(암묵 실행 금지), (2) **first-use confirm** — 처음 spawn하는 command는 사용자 승인 1회 필요, (3) 자식은 `kill_on_drop` + **비정상 종료·행 감지 시 강제 회수 타임아웃**(패널 지적: agy — 프로세스 종료 가드), (4) 자식 stdout/stderr 크기 상한.
- **어떻게**: transport를 enum으로 분리(`Http { url } | Stdio { command, args, env }`), 핸드셰이크(initialize → initialized → tools/list, mcp.rs:113)는 공용. `auto_approve`·confirm 정책은 transport와 무관하게 동일 적용.
- **완료 기준**: stdio MCP 서버 mock을 띄우는 CI 테스트에서 tools/list까지 성공. 프로세스 누수 없음(비정상 종료·행 케이스 포함). 미등록 command는 실행 거부.

### M2. sre-agent 조회 래퍼 확대 (우선순위 1)

- **무엇**: `rca_memory.rs`의 3종(match/runbooks/record)에 더해 `anomaly_scores`, `fingerprint_status`, `incident_replay`, `list_findings` 조회 래퍼 추가. CLI는 `aic rca replay <id>`, `aic rca anomaly` 노출.
- **왜**: sre-agent에 이미 있는 답(이상 점수, 재연 타임라인)을 aic에서 못 꺼낸다. W4(web Watch 탭)와 C3(자동 힌트)의 토대이기도 하다. HTTP MCP로 도달 가능하므로 M1 없이 착수 가능 — **연동 트랙의 실질 1순위**.
- **신뢰 모델 (패널 지적: cursor — "read-only니까 auto_approve"는 과신)**: read-only는 "부작용이 없다"는 뜻이지 "신뢰됨"이 아니다. sre-agent가 반환하는 데이터도 오염될 수 있다(예: 조작된 finding 텍스트). 따라서 (1) auto_approve는 **명시적으로 신뢰 표시한 sre-agent 서버에 한정**, (2) 반환 텍스트는 chat/web에 넣기 전 redaction·이스케이프 경유, (3) 첫 연결 서버는 approve 1회.
- **어떻게**: 기존 suffix-match 패턴(rca_memory.rs:57-81) 그대로 확장. 미설정 시 None 반환 원칙 유지.
- **완료 기준**: sre-agent 연결 시 `aic rca replay`가 타임라인을 렌더. 미연결 시 "sre-agent 미설정" 한 줄로 끝난다. 신뢰 안 한 서버는 auto_approve되지 않는다.

### M3. aic-as-MCP-server, read-only (Phase 2 범위 밖 — 별도 Phase로 분리, 패널 반영)

- **무엇**: aic가 자기 데이터를 MCP 서버로 노출 — `list_incidents`, `get_incident_report`, `list_findings`, `search_history`. 전부 read-only.
- **왜**: 역방향 연동. Claude Code나 다른 에이전트가 "이 호스트에서 최근 무슨 일 있었나"를 aic에게 물을 수 있게 된다. 어댑터(Track O)가 push라면 이것은 pull-노출이다.
- **판정 (패널 지적: codex/kiro 합의)**: 신규 서버 구현은 인증·수명·보안 표면이 넓어 "여유 시" 항목으로 두기엔 위험하다. Phase 2 범위에서 **제외**하고 별도 미니 Phase(설계 문서 선행)로 분리한다. Phase 2에서는 착수하지 않는다.
- **어떻게(향후)**: `aic mcp-serve` 서브커맨드, stdio 우선(HTTP는 이후). 응답은 web과 동일하게 redaction 경유. 도구 4개로 시작하고 mutation은 절대 넣지 않는다.

---

## Track D — 진단 품질·신뢰도 (패널 발산으로 신설)

> 5개 모델이 독립적으로 지목한 공백: **"빠르게 안다"는 있는데 "확실하게 안다"의 근거·측정·정직성이 없다.**
> 지금 계획은 진단을 더 많이·빨리 보여주지만, 그 진단이 맞는지·믿을 만한지·수집이 실제로 되고 있는지를 사용자가 알 방법이 없다.
> 이 트랙 전체는 **로컬·pull·read-mostly**라 경계 안이다(주석 append만 로컬 incident store에 쓴다 — 아래 표기).

### D1. 진단 신뢰도 신호 (우선순위 1 — 4개 모델 지목)

- **무엇**: finding과 가설에 `confidence`(high/med/low)와 `source_quality`(직접측정/추론/외부백엔드) 메타를 붙여 렌더.
- **왜**: 지금은 모든 finding이 같은 무게로 보인다. "확실히 안다"는 곧 "얼마나 확실한지 안다"이다. 이게 없으면 사용자는 약한 추론과 직접 측정을 구분 못 한다.
- **어떻게**: `diagnose::scan_findings`가 이미 finding 종류를 안다 — 종류별로 confidence를 매핑(예: 프로세스 실측=high, 로그 상관=med). web/chat 렌더에 배지 추가. LLM 불필요.
- **완료 기준**: 각 finding·가설 옆에 신뢰도 배지가 뜬다. 직접측정과 추론이 시각적으로 구분된다.

### D2. 진단 품질 피드백 루프 (우선순위 2 — 3개 모델 지목: 진단이 맞았나?)

- **무엇**: incident close 시 각 가설/finding에 `outcome`(정답/오답/무관)을 한 번 표시. 누적해 finding 종류별 과거 적중률을 D1 confidence에 반영.
- **왜**: 신뢰도가 고정 매핑이면 결국 추측이다. 실제 적중 이력이 쌓이면 "이 종류 finding은 지난 20건 중 3건만 맞았다"를 confidence에 녹일 수 있다. 진단이 시간이 갈수록 정직해진다.
- **어떻게**: `aic rca close` 흐름에 outcome 프롬프트 1개 추가(선택). 집계는 로컬 `~/.aic`에 append-only. **이건 로컬 incident store에 쓰는 유일한 append** — read-only 원칙에 표면 충돌하므로 "로컬 자기 기록"으로 명시(원격 mutation 아님).
- **완료 기준**: close 시 outcome을 남길 수 있고, 집계된 적중률이 D1 배지에 반영된다. 스킵해도 흐름이 막히지 않는다.

### D3. 데이터 신선도 / 수집 health strip (우선순위 1 — claude 지목: 위장된 정상)

- **무엇**: web·chat 브리핑에 각 데이터 소스(로컬 샘플러, webhook, 관측 백엔드, sre-agent)의 **마지막 성공 수집 시각·상태**를 한 줄로.
- **왜**: 가장 위험한 실패는 "수집이 죽었는데 화면은 조용한 것" = 문제 없음으로 위장된 장애. "확실히 안다"를 정면으로 깬다. freshness 없는 대시보드는 신뢰 못 한다.
- **어떻게**: 각 소스가 이미 마지막 수집 시각을 안다(또는 쉽게 노출 가능). W2 요약 스트립에 stale(예: >2×주기) 소스를 노랑/빨강으로. 신규 데이터 수집 없음 — 기존 타임스탬프 노출만.
- **완료 기준**: 샘플러/webhook을 멈추면 해당 소스가 몇 초 내 stale로 표시된다.

### D4. 명시적 all-clear(정상 확신) 상태 (우선순위 2 — claude 지목: 음성 답 부재)

- **무엇**: 열린 incident 0 + alert 0 + 모든 소스 fresh일 때, web 첫 화면과 chat 브리핑에 **명시적 "이상 없음"**을 보여준다(빈 화면이 아니라).
- **왜**: "문제가 있는가?"의 답은 두 개다 — "있다"와 "확실히 없다". 지금 계획은 전자만 설계했다. 빈 화면은 "정상"인지 "수집 실패"인지 구분 안 된다. D3와 짝을 이뤄야 정상 확신이 성립한다.
- **어떻게**: W2 요약 로직에서 모든 조건 green이면 all-clear 카드. all-clear는 **D3의 freshness가 전부 fresh일 때만** 유효(수집 죽은 채 초록 금지).
- **완료 기준**: 모두 정상이면 초록 "이상 없음"이 뜨고, 소스 하나라도 stale이면 초록 대신 "확인 필요"가 뜬다.

### D5. 세션 noise gate (우선순위 1 — kiro/codex 지목, C1·C3의 전제)

- **무엇**: alert lane·webhook 유입·자동 힌트에 공통으로 적용되는 세션 레벨 throttle/dedup — 동일 fingerprint는 창(예: 5분) 안에서 1회만 알린다.
- **왜**: C1(webhook 유입)·C3(자동 힌트)가 소음 억제 없이 들어가면 폭주 알림이 도구를 못 쓰게 만든다. 알림 도구의 신뢰는 소음 억제에서 나온다. C1/C3의 선행 조건.
- **어떻게**: `AlertTracker` 경로에 fingerprint→마지막알림시각 맵 추가(세션 메모리). mute·창 크기는 `/watch` 설정. 디스크 저장 없음.
- **완료 기준**: 같은 fingerprint 100개가 5분 안에 와도 알림은 1회. 창이 지나면 다시 1회 허용.

### D-time. 시간여행 비교(time-window diff) (우선순위 3 — 4개 모델 지목)

- **무엇**: "지금 vs N분 전" 스냅샷 diff — 리소스·top 프로세스·리스닝 포트의 변화를 한 화면에. `aic rca compare --ago 10m` + web Snapshots 탭의 diff 뷰.
- **왜**: RCA의 핵심 질문은 "뭐가 바뀌었나"다. 지금은 두 스냅샷을 눈으로 비교해야 한다. 변화점이 곧 용의자다. 4개 모델이 독립적으로 지목한 강한 신호.
- **어떻게**: 스냅샷은 이미 저장된다(`/web/snapshots`). 두 시점을 골라 필드 단위 diff 렌더(추가/삭제/증감). 신규 수집 없음 — 기존 스냅샷 재활용.
- **완료 기준**: 두 시점 diff가 프로세스·포트·리소스의 변화를 강조 표시한다.
- **비고**: 범위가 있어 3차. 여유 없으면 Phase 3로 미뤄도 무방.

### D-note. incident 협업 주석 (우선순위 3 — kiro/claude/agy 지목)

- **무엇**: incident에 사람이 남기는 메모·태그·열람 흔적. web 상세 뷰(W1)에서 추가.
- **왜**: incident는 혼자 안 본다. "누가 뭘 확인했나"가 남아야 협업이 된다. 지금은 증거만 있고 사람 개입 흔적이 없다.
- **어떻게**: 기존 `aic rca note`(이미 있음)를 web에서 노출 + 태그 필드. 로컬 incident store append(D2와 같은 "로컬 자기 기록" 범주).
- **완료 기준**: web에서 incident에 메모를 남기고 타임라인에서 볼 수 있다.

---

## 실행 순서

의존 관계와 가치 기준으로 3묶음. (패널 반영: W3↑, C4↑, M1↓, D 트랙 삽입, M3 제외.)

| 묶음 | 항목 | 이유 |
|------|------|------|
| 1차 | **C1, C2, W1, W2, W3, D3, D5** | 의존성 없음, "즉시·확실히 안다"에 직결, 전부 기존 데이터 재활용. D5(noise gate)·D3(신선도)는 C1이 켜지기 전에 있어야 함 |
| 2차 | **M2, O1, D1, D4, C3, C4** | 연동·전송·신뢰의 토대. M2가 끝나야 W4·C3가 가능. D1(신뢰도)은 W1/W2 위에 얹음 |
| 3차 | **O2, O3, W4, M1, D2, D-time, D-note** | 토대 위의 마무리. M1은 M2 이후로 강등 |
| 별도 | **M3** | 신규 MCP 서버 — 보안 표면이 넓어 Phase 2 제외, 설계 문서 선행 |

우선순위 정렬 원칙: "확실히 안다"의 **음성 답(D3·D4)과 소음 억제(D5)**가 "빠르게 안다"(C1·W2)보다 먼저 또는 같이 가야 한다. 신선도 없는 대시보드와 소음 나는 알림은 새 기능을 무력화한다.

## 비범위 (Phase 2에서 하지 않는 것)

- Slack/PagerDuty 전용 포맷 어댑터 — generic envelope webhook으로 대체, Phase 3.
- **실제 외부 네트워크 전송의 기본 활성** — Phase 2는 FileAdapter만 켜고 WebhookAdapter는 비활성·allowlist 게이트. 실전송은 Phase 3.
- 자동 전송(사람 confirm 없는 outbound) — 절대 금지 원칙 유지.
- aic 자체 anomaly 탐지·상시 감시 루프 — sre-agent 영역.
- **aic-as-MCP-server(M3)** — 별도 미니 Phase, 설계 문서 선행.
- write/mutation MCP 도구, runbook 실행기 — SRE-SCOPE-BOUNDARY.md 로드맵 3·5번, 별도 설계 필요.
- multi-host — RFC-005에서 계속 보류.

---

## 부록: 패널 리뷰 반영 이력 (2026-07-02)

5개 모델 적대 패널(claude-opus-4-8 / codex-gpt-5.5 / gemini-3.1-pro / cursor / kiro), 2라운드(리뷰+반박). 여러 모델이 수긍한 항목만 반영.

**결함 수정:**
- O2 "어댑터만" 자기모순 → FileAdapter만 기본 활성, WebhookAdapter 비활성+allowlist. (cursor/codex/agy)
- C1 pull 원칙 위반 우려 → "세션 스코프 opt-in 구독 ≠ 상시 루프" 경계 명시. (cursor/kiro)
- 우선순위 역행 → W3(2→1), C4(3→2) 승격, M1(1→2) 강등, outbound를 후순위로. (claude)
- M1 임의 command spawn 보안 게이트(등록분만·first-use confirm·종료 가드) 추가. (cursor/kiro/agy)
- M2 "read-only=auto_approve" 과신 → 신뢰 서버 한정·반환 텍스트 이스케이프. (cursor)
- W4 web 요청경로 MCP 동기 호출 → 백그라운드 캐시(SWR)로 전환, 장애 격리. (cursor)
- W1 sync file I/O → `spawn_blocking`, 손상 evidence 부분 렌더. (agy)
- W2 3-엔드포인트 waterfall → 단일 `/web/summary`. (codex/cursor/kiro)
- W3 시간창·top-N 상한 추가. (kiro/cursor/agy)
- O1이 redaction 타입·정책·audit 스키마를 선고정(어댑터보다 먼저). (kiro/cursor)

**발산 신설 (Track D):** D1 신뢰도 신호(4모델) · D2 품질 피드백 루프(3모델) · D3 데이터 신선도(claude) · D4 명시적 all-clear(claude) · D5 noise gate(kiro/codex) · D-time 시간여행 diff(4모델) · D-note 협업 주석(kiro/claude/agy).

원본 verdict: `.xm/review/panel-20260702-082848-720/verdict.json`.
