# Probe Follow-up Selection Evaluation

> `aic diagnose`가 1차 probe 증거를 본 뒤 고르는 follow-up probe(예: `journal_unit nginx.service`)를
> TypeSafe Jev의 Choice로 고를 수 있는지 잰 결과. 실행 상세와 원시 수치는 `eval/RESULTS.md`의
> "Jev follow-up 선택 평가" 절.
> 작성일: 2026-09-22 · 상태: 1차 완료 · 결론: 유망. 도입 전에 `proc_fd` 편향 차단과 데이터 보강이 필요

## 무엇을 쟀나

`aic diagnose`는 1차 probe 출력을 LLM에 넘기고, LLM은 분석과 함께 follow-up 블록에 최대 3줄을
쓴다. 메뉴는 catalog 59개와 인자형 템플릿 10개(`journal_unit <unit>`, `proc_fd <pid>`,
`docker_logs <container>`, `k8s_pod_describe <pod>` 등)다. `resolve_followup_line`이 각 줄을
게이트한다: 인자는 evidence 안에 토큰 단위로 등장해야 하고 문자 집합과 길이 제한을 지켜야 한다.

이 단계가 Jev에 맞는다고 본 이유는 세 가지다. 선택지가 닫혀 있다(70개 메뉴 + `none`). 인자
후보를 evidence에서 결정적으로 뽑을 수 있다(`failed_units` 표의 유닛명, `proc_fd_top` 표의 PID,
`docker ps`의 NAMES 열, `kubectl get pods`의 NAME 열). 정답이 구성상 정해진다 — 신호 섹션이
대상을 드러내고, 그 대상을 더 깊이 보는 템플릿이 정답이다.

Jev 비교군은 두 질문을 한 요청에 묶는다: Q1 템플릿 Choice(catalog 59 + 템플릿 10 + `none`),
Q2 템플릿별 인자 Choice(evidence에서 뽑은 후보 + `__none__`). LLM 비교군은 production
프롬프트(`build_diagnose_prompt_followup`)를 `kiro/gpt-5.6-luna`로 그대로 돌려 follow-up 블록을
추출하고 같은 게이트를 통과시킨다.

데이터는 26개 번들(개발 10, 최종 16)이다. 신호 섹션은 probe-judgment fixture와 새로 쓴
docker/k8s 표에서, 잡음 섹션은 판정이 none인 clean-negative fixture에서 가져왔다. 실제 호스트
출력은 섞지 않았다.

## 결과

최종 분할 16 번들(신호 12, 신호 없음 4), 3회 반복, 주 평가는 1회차.

| 지표 | Jev | LLM(luna) |
|---|---|---|
| top-1 정답(신호 12) | **0.833** (10/12) | 0.333 (4/12) |
| top-3 정답(신호 12) | 1.000 | 0.750 |
| none 정답(신호 없음 4) | 0.500 (2/4) | 0.000 (0/4) |
| 게이트 거부 | 0 | 0 |
| 반복 일치율(16 번들 × 3회) | **0.938** | 0.438 |
| p50 / p95 지연 | 246 / 332 ms | 10,052 / 14,090 ms |
| 입력 토큰(1회차 16회 합) | 52,719 (호출당 ≈ 3,300, ≈ 0.0022 USD) | 미측정 |

개발 분할 10 번들에서는 Jev top-1 8/8·none 2/2, LLM 3/8·0/2였다. 두 분할을 합치면 Jev
18/20·4/6, LLM 7/20·0/6이다.

LLM 지연이 10초인 이유는 production 프롬프트가 분석 전문을 쓴 뒤 follow-up 블록을 붙이기
때문이다. Jev는 follow-up만 고른다. 같은 조건은 아니지만, production에서 follow-up이 나오기까지
걸리는 시간은 이 값이다.

## LLM이 약한 이유

LLM 오답 8건 중 6건은 인자형 템플릿 대신 catalog probe를 골랐다: `proc_fd 73006` 대신
`fd`(4건), `journal_unit a.service` 대신 `journal_errors`(2건), `k8s_pod_describe ingest-5d2a-q9`
대신 `k8s_crashloop_pods`. 대상이 표에 그대로 있는데도 넓은 probe로 되돌아간다. 신호 없는
4건에서는 매번 다른 probe(`proc_changes`, `vmstat_iowait`, `memory`, `uptime`)를 골랐고 `none`을
쓴 적이 없다. 반복 일치율 0.438은 같은 evidence에 세 번 중 두 번은 다른 follow-up을 낸다는
뜻이다.

production의 follow-up 단계는 지금 이 상태로 동작한다.

## Jev가 틀린 4건 — 전부 `proc_fd`

| 번들 | 정답 | Jev(1회차) | confidence | 표의 행 |
|---|---|---|---|---|
| nn-05 | none | `proc_fd 904` (3/3회) | 0.65 | `50 904 tiny`, 한도 100000 |
| nn-06 | none | `proc_fd 904` (3/3회) | 0.49 | 같은 행 |
| dk-04 | docker_* api-2 | `proc_fd 905` (3/3회) | 0.69 | `900 905 mid2`, 한도 줄 없음 |
| pf-08 | proc_fd 103 | `proc_fd 905` (1회), `proc_fd 100` (2·3회) | 0.86 | 같은 행 + 한도 5000 표 |

네 건 모두 `proc_fd_top` 표의 행을 대상으로 골랐고, 스캐너(`scan_proc_fd`) 기준으로 그 행은
신호가 아니다: 50/100000은 0.05%이고, 한도 줄이 없는 900은 절대량 경고선(10,000)에 못
미친다. `proc_fd_top` 표가 없는 12 번들은 전부 맞혔고, 표가 있는 14 번들 중 4건이 틀렸다.

다만 표가 있다고 무조건 틀리지는 않았다. 같은 `900 905 mid2`나 `50 904 tiny` 행이 잡음으로 든
fu-02·fu-03·pf-05는 맞혔다. 증상이 유닛을 가리키거나(`서비스가 죽었습니다`) 진짜 90% 행이 같이
있으면 그쪽을 골랐다. 틀린 경우는 두 가지다. 증상이 없고 다른 신호도 없으면 `none` 대신 표에
있는 아무 행을 고른다(nn-05·nn-06). 한도 없는 `900`을 크다고 보고 컨테이너 증상(dk-04)이나 80%
행(pf-08 1회차)보다 앞세운다. 두 번째는 판정 실험에서 확인한 것과 같은 약점이다: Jev는 수치를
한도와 견줘 판단하지 못한다.

confidence로는 못 거른다. 정답 46건의 confidence는 0.39 이상(중앙값 0.86), 오답 12건은
0.46~0.89로 겹친다.

## 데이터 결함(실측 후 발견, 고치지 않음)

최종 분할의 실패를 읽었으므로 이 분할은 질문 조정에 다시 쓰지 않는다. 결함은 다음 라운드용으로
기록만 한다.

- 생성기 `noise(k, signal_sections and "" or "")`가 제외 probe에 항상 빈 문자열을 넘긴다. 잡음
  풀에서 신호 probe를 빼지 못해 pf-05는 `proc_fd_top` 표 2개, pf-08은 3개를 품었고, 신호 없는
  nn-05·nn-06에 `proc_fd_top` 정상 행이 들어갔다. 후자는 Jev의 약점을 드러냈으니 결과적으로 쓸모
  있었지만 의도한 설계는 아니다.
- dk-04 정답이 evidence와 어긋난다. `replace("Up 5 days", …, 1)`이 `db-1`이 아니라 `worker-3`
  행을 바꿨는데 정답은 `db-1`을 적었고, dk-02·dk-03과 달리 `docker_health`·`docker_logs_since`를
  뺐다. 일관된 정답이면 LLM의 `docker_logs_since api-2`는 정답이라 LLM top-1은 5/12(0.417)가
  된다. Jev는 어느 정답으로도 오답이다.
- pf-08 정답이 "fd 열이 가장 큰 PID"(103) 하나뿐이다. 스캐너는 한도의 50% 이상을 표 순서로 최대
  3개까지 보고하므로 실제 출력은 100·101·102이고 103은 나오지도 않는다. Jev 2·3회차의
  `proc_fd 100`은 스캐너 기준 정답이다.

정답을 고쳐도 Jev 1회차 top-1은 10/12로 같고, 2·3회차는 11/12가 된다.

## 배운 것

- **follow-up 선택은 지금까지 시험한 세 단계 중 Jev에 가장 잘 맞는다.** 증상→범주(1단계)는
  규칙이 Jev와 같은 품질에 닿았고, probe 판정(2단계)은 수치 비교에서 실패했다. follow-up은
  선택지가 닫혀 있고 인자 후보가 결정적으로 뽑히며 정답이 범주형(실패 유닛, 죽은 컨테이너, 못
  뜨는 파드)이다. 이 조건에서 Jev는 LLM보다 top-1 정답이 2.5배, 반복 일치율이 2배 높았고 지연은
  40분의 1이었다.
- **약점은 2단계와 같은 곳에서 나온다.** 수치를 한도와 견주는 판단은 Jev가 아니라 스캐너
  몫이다. `proc_fd` 후보를 `scan_proc_fd`가 실제로 경고한 PID로 제한하면 네 건 모두 구성상
  사라진다. 후보가 없으면 `proc_fd` 템플릿 자체를 메뉴에서 뺀다. 결정적 스캐너가 후보를 좁히고
  Jev가 그 안에서 고르는 구조는 1단계의 "규칙이 조절하고 모델이 고른다"와 같다.
- **정답 키는 생성기 코드가 아니라 스캐너 출력으로 만들어야 한다.** pf-08과 dk-04 결함은 둘 다
  정답을 손으로 정한 데서 왔다. `scan_findings`가 뽑는 대상을 정답으로 삼으면 스캐너와 어긋날 수
  없다.
- **LLM이 인자형 템플릿을 쓰지 않는다는 사실은 production 결함이다.** Jev 도입과 별개로,
  프롬프트가 템플릿 사용을 유도하지 못하거나 LLM이 넓은 probe를 선호한다. 원인은 확인하지
  않았다.

## 남은 제한

- 최종 n=16은 작다. docker 3, k8s 1 번들뿐이고 `k8s_nodes`·`k8s_node_describe` 같은 템플릿은
  시험하지 못했다. 신뢰구간을 계산하지 않았다.
- 정답이 구성상 정해진 합성 번들이다. 실제 `aic diagnose` evidence는 섹션이 더 많고 길며, 기존
  redaction이 호스트명·경로·저널 본문을 남긴다. Jev 64k 문맥 한도와 전송 정책을 실제 evidence로
  확인하지 않았다.
- LLM 토큰은 `send()` 경로가 사용량을 기록하지 않아 재지 못했다.
- Jev 비교군은 follow-up만 고르고 LLM 비교군은 분석까지 쓴다. 지연 차이의 일부는 이 차이다.

## 다음 단계

1. 생성기 수정: 제외 probe 인자, dk-04·pf-08 정답, 정답을 스캐너 출력에서 생성. 최종 분할을 새로
   뽑는다(현재 최종 분할은 소진).
2. `proc_fd` 후보를 스캐너 경고 PID로 제한하고 후보 없는 템플릿을 메뉴에서 제외한 뒤 개발 분할로
   재확인.
3. n을 50 이상으로, docker·k8s 번들을 늘려 최종 재측정. 진행 문턱은 실측 전에 고정한다: top-1
   ≥ 0.85, none 정답 ≥ 0.90, 반복 일치율 ≥ 0.90.
4. 통과하면 production 배선 설계: 1차 evidence → Jev follow-up 선택 → follow-up 실행 → LLM 분석
   한 번. follow-up이 LLM 분석 앞으로 옮겨져 지연이 줄고, 실제 evidence 길이와 redaction 범위를 이
   시점에 확인한다.
