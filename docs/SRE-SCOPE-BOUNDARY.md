# aic SRE 범위 경계 & 후속 로드맵 (R7)

> aic를 SRE 도구로 확장하면서 **무엇을 aic가 하고, 무엇을 하지 않는지**를 명확히 한다.
> 특히 별도 `sre-agent`(상시 감시·기억) 프로젝트와 기능이 겹치지 않게 경계를 고정한다.

## 핵심 경계: aic(pull) vs sre-agent(push)

| 축 | **aic** | **sre-agent** (별도 프로젝트) |
|----|---------|------------------------------|
| 트리거 | **pull** — 사람이 호출(`aic chat`/`diagnose`) 또는 alert webhook 1회성 | **push** — 상시 백그라운드 감시 루프 |
| 상태 | 대체로 stateless(세션·번들·audit 로그) | stateful — 시계열 anomaly score, fingerprint DB, incident 기억 |
| 역할 | **대화형 진단** — 증상→Safe probe→가설/증거/다음확인 | **상시 감시·기억** — drift/anomaly 탐지, 유사 incident 매칭, runbook 추천 |
| LLM | 진단/분석 시 호출 | 탐지는 비-LLM(통계), 요약·매칭에만 LLM |
| 데이터 | 로컬 호스트 + 등록 관측 백엔드 read | 지속 수집된 메트릭/이벤트/config 스냅샷 |

원칙: **aic는 "지금 이 증상을 진단"하고, sre-agent는 "계속 지켜보고 기억"한다.** 같은 기능을
두 곳에 만들지 않는다.

## 이번에 구현한 것 (R1~R6)

- R1 관측 백엔드 read 통합(Prometheus/Loki/Elasticsearch) — `obs_tools.rs`
- R2 webhook alert ingestion → 자동 초동 진단(`aic diagnose` spawn) — `webhook_server.rs`
- R3 k8s 네이티브 probe(`/triage k8s`, `/diagnose` k8s 카테고리)
- R4 Anthropic 네이티브 tool-calling
- R5 audit tail/search 조회
- R6 headless/air-gapped 검증(CI headless job)

이 전부는 **pull/1회성** 성격이라 sre-agent와 겹치지 않는다.

## 후속 로드맵 (이번 범위 밖)

차별화 기능. 일부는 **sre-agent 영역**이므로 거기로 보내거나, aic에 넣더라도 경계를 지킨다.

1. **incident memory / 유사 장애 검색** → **sre-agent 영역**.
   - aic의 `/bundle`은 증거 저장까지만. fingerprint 기반 "지난번 비슷한 장애" 매칭은
     상시 기억이 필요하므로 sre-agent(`match_incidents`/`fingerprint_anomaly`)가 담당.
   - aic는 필요 시 sre-agent를 **조회**(MCP/CLI)만 하고 자체 incident DB는 두지 않는다.

2. **상시 감시 / drift·anomaly 탐지** → **sre-agent 영역**. aic는 webhook으로 "알림을 받는"
   쪽이지 "감시하는" 쪽이 아니다.

3. **`/runbook` 실행** → **aic 영역(후속)**. YAML runbook을 단계별 confirm gate +
   기존 risk_guard/HMAC audit로 실행. `/triage`가 체크리스트까지 하므로 자연 확장.

4. **팀 공유** → **aic 영역(후속)**. `/bundle` 결과를 Slack/webhook으로 전송(외부 전송이라
   confirm gate 필수). org-level config 배포 + read-only 강제 lockdown.

5. **write/mutation 도구** → 신중히. 현재 read-only 원칙. runbook 실행과 함께 설계.

## 결정 근거

- 중복 구현은 유지보수 비용 2배 + 동작 불일치 위험. 경계를 코드/문서로 고정.
- aic의 강점(대화형 진단 + bounded Safe probe + audit)과 sre-agent의 강점(상시 통계 감시 +
  기억)은 **상보적**이다. 연동(aic가 sre-agent를 조회)이 통합보다 낫다.
