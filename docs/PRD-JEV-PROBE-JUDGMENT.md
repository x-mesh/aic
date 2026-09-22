# PRD: TypeSafe Jev가 결정적 스캐너의 이상 판정을 재현하는지 검증(1단계)

> 상태: 1단계 완료 — 결과와 결론은 [PROBE-JUDGMENT-EVALUATION.md](PROBE-JUDGMENT-EVALUATION.md)
> (**중단**: 스캐너 대비 정밀도 0.750 < 중단 문턱 0.85)
> 작성일: 2026-09-22 · 개정: 2026-09-22(1단계 실행 완료 후 상태 갱신)
> 선행: [PRD-JEV-PROBE-SELECTION.md](PRD-JEV-PROBE-SELECTION.md)(probe **선택**) — 이 PRD는 probe **출력 판정**을 다룬다. 서로 다른 계약이라 별도 문서로 둔다.
> 대상: aic 저장소의 독립적인 기능 검증 작업

## 1. 목적과 범위

`aic diagnose`와 `/local`은 수집한 probe 출력(evidence)을 결정적 임계 스캔(`scan_findings`)으로
훑어 정상·경고·위험을 가른다. 스캐너는 `disk`·`inodes`·`dmesg_oom`·`journal_daemon_errors`·
`proc_states`·`failed_units`·`fd`·`proc_fd_top`·`swap_usage` 9개 probe만 판정하고, 나머지 약 50개
probe는 사람이나 LLM이 evidence 텍스트를 읽어야 한다.

이 1단계가 재는 것은 **"9개 probe에서 Jev가 기존 결정적 스캐너의 판정을 재현하는가"**다. "Jev의
일반적인 이상 탐지 능력"을 재는 것이 아니다 — 스캐너는 오탐을 줄이려고 보수적으로 설계됐으므로
스캐너가 조용한 섹션이 실제로 정상이라는 보장은 없다(스캐너 음성 = 미판정, 정상 아님). 지표
이름을 **스캐너 재현율**과 **스캐너 대비 정밀도**로 고정해 이 범위를 벗어난 해석을 막는다.

목표는 나머지 50개 probe에 스캐너를 추가로 손코딩하는 대신 Jev로 판정할 수 있는지 가늠할
1차 신호를 얻는 것이다. 9개 probe에서 재현에 실패하면, 스캐너가 없는 50개 probe에서 잘될
근거는 더 약하므로 2단계(실제 확장) 전에 멈춘다.

## 2. 현재 구현과 근거

- [`scan_findings`](../aic-client/src/agent/diagnose.rs): evidence 섹션을 순회하며 9개 probe id에
  고정 매핑된 하위 스캐너(`scan_disk_full`, `scan_inodes`, `scan_oom`, `scan_journal_daemon_errors`,
  `scan_zombies`, `scan_failed_units`, `scan_fd`, `scan_proc_fd`, `scan_swap`)를 돌리고, 발견을
  `Finding`(severity·confidence·source·probe_id·message)으로 만든다. 순수 함수다.
- `journal_errors`(no-arg 진단의 cron 파싱 오류 탐지)는 `scan_findings`의 10번째 match arm이지만
  제외한다. `!has_structured_journal`로 게이트돼 있어 발화 여부가 **같은 evidence의 다른 섹션**
  (`journal_daemon_errors`의 구조화 파싱 성공 여부)에 의존한다. 섹션 하나를 독립 fixture로 다루는
  이 실험의 전제(R3 — 질문은 probe별 임계를 담지 않는 단일 계약)와 맞지 않아, 9개에서 뺀다.
  `comprehensive_probes_cover_all_scan_findings_keys` 테스트가 열거하는 8개에 `journal_daemon_errors`
  를 더하면 9개가 된다.
- 각 하위 스캐너는 명명 상수 임계를 쓴다: `DISK_FULL_PCT`/`INODE_FULL_PCT` = 90, `FD_USED_PCT`/
  `SWAP_USED_PCT` = 80, `PROC_FD_PCT_WARN` = 50 또는 `PROC_FD_ABS_WARN` = 10,000, `ZOMBIE_WARN_MIN`
  = 10. `dmesg_oom`·`failed_units`·`journal_daemon_errors`는 수치 임계가 아니라 신호 존재 여부로
  판정한다(OOM 시그니처, unit 접미사 토큰, 파싱 가능한 JSONL 라인).
- 심각도는 신호 성격으로 고정 매핑된다: OOM-kill(이미 벌어진 사건) = Crit, 그 외 임계 위반 =
  Warn. 발견이 없는 섹션은 결과에서 빠진다(=암묵적 정상).

## 3. 질문 계약

Choice 하나로 정상·경고·위험을 고른다. `criteria`는 세 범주의 일반 정의만 담고, probe 이름이나
수치 임계는 넣지 않는다 — 질문이 probe별 임계를 알면 2단계에서 같은 질문을 재사용할 수 없고,
사실상 스캐너를 프롬프트로 재구현하는 것이 된다.

입력 state는 evidence 섹션 하나를 그대로 옮긴다: `## <probe_id>` 줄, `command:` 줄, `exit_code=`
줄, stdout 본문. `stderr`는 신지 않는다 — 이 9개 스캐너가 보는 것은 전부 stdout이고(`section_stdout`
이 stdout만 매처에 넘긴다), stderr를 포함하면 모델이 스캐너보다 더 많은 정보를 갖게 돼 "같은
입력에서 같은 판정을 재현하는가"라는 질문이 어긋난다. 이 결정의 한계는 stderr에만 있는 이상
신호(예: 명령 자체의 실패)를 이 실험이 놓친다는 것이다 — 9개 스캐너가 stderr를 안 보므로 정답
라벨 자체에도 반영되지 않아, 1단계 범위에서는 손실이 없다.

## 4. 불변 조건

- production 변경은 `aic-client`에 좁은 함수 하나(`scanned_severities`)를 여는 것으로 제한한다.
  `Finding`·`Confidence`·`SourceQuality`·`Severity`의 가시성은 바꾸지 않는다. CLI·IPC·설정·진단
  JSON 외부 계약은 바꾸지 않는다.
- 정답 라벨은 `scan_findings`의 실제 판정에서 파생한다. 데이터 파일의 선언 라벨과
  `scanned_severities`의 실제 판정이 어긋나면 `judge-validate`가 0이 아닌 코드로 종료한다.
- 1단계가 외부로 보내는 입력은 합성 fixture로 한정한다. 실제 호스트에서 수집한 출력은 보내지
  않는다. 송신 직전 `aic_common::redaction::redact`를 한 번 더 적용하되, 이것은 방어선이며 실제
  출력 전송의 허가 근거가 아니다 — 실제 출력 확장은 2단계의 별도 승인 항목이다.
- 응답 계약 위반(선택지 밖 값, `answers` 키 누락, HTTP 영구 오류)은 실패로 세고 원문을 보존한다.
  어떤 판정으로도 대체하지 않는다.
- `cargo test`는 순수 파싱·검증·채점만 돈다. 네트워크 진입점은 `judge-run` 서브커맨드 하나뿐이다.

## 5. 평가 데이터

9개 probe 각각에 명백한 양성, 임계 바로 위 경계 양성, 임계 바로 아래 음성, 정상 출력 음성,
형태 변형(다른 OS 포맷 등)을 만든다. 개발 45개(probe당 5개), 최종 90개(probe당 10개)다.

각 fixture는 기존 스캐너 단위 테스트에서 파생했는지, `probes.rs`의 명령 문자열이 규정하는 출력
형태에서 새로 작성했는지를 `source` 필드에 밝힌다. `source`가 비어 있으면 `judge-validate`가
거부한다 — 실제 호스트 출력이 섞여 들어오는 것을 데이터 단계에서 막는 유일한 방어선이다.

개발과 최종 분할은 겹치지 않는다. 직전 probe-selection 평가(3라운드)의 데이터 소각 규칙을
그대로 승계한다 — 최종 분할의 실패 사례를 읽으면 그 분할은 개발용으로 격하하고 새 최종 분할을
만든다.

## 6. 성공·중단 기준

다음 수치는 실측 결과가 아니라 최초 측정 전에 고정하는 목표다. 결과를 본 뒤 고치지 않는다.

- **진행**: 스캐너 재현율 ≥ 0.90이고 스캐너 대비 정밀도 ≥ 0.95이며 응답 계약 위반 0건이면
  2단계(스캐너 없는 나머지 50개 probe로 확장)로 간다.
- **중단**: 정밀도 < 0.85 또는 재현율 < 0.75면 중단한다. 실패한 probe 계열을 지목하고 거기서
  멈춘다.
- **보류**: 위 두 구간 사이는 보류다. 어느 지표가 어느 probe 계열에서 걸렸는지 원문과 함께
  남기고, 2단계로 넘어가지 않는다.

정밀도 문턱(0.95)을 재현율 문턱(0.90)보다 높게 잡은 이유: 2단계에는 대조할 스캐너가 없다.
거짓 양성(Jev가 조용한 섹션을 경고·위험으로 판정)은 그대로 사용자에게 가짜 경고로 나가 현재
동작(스캐너가 조용하면 알림 없음)에 대한 후퇴다. 반면 거짓 음성(Jev가 스캐너가 잡은 섹션을
정상으로 판정)은 현재도 스캐너가 없는 50개 probe에서 일어나는 일과 같은 상태이며 후퇴가
아니다. 그래서 정밀도를 더 엄격한 게이트로 둔다.

불일치는 사전에 정한 세 범주로 사후 분류한다: Jev 오판, 스캐너 공백(스캐너가 놓친 실제
이상을 Jev가 잡음), fixture 결함. 게이트 판정은 이 분류 이전의 미보정 수치로 내리고, 분류
결과는 2단계 설계 근거로만 쓴다 — 사후 분류로 게이트를 통과시키지 않는다.

confidence 구간별 정확도를 보고하되, 2단계 게이트 후보 임계는 개발 분할에서만 고른다. 최종
분할을 보고 임계를 고르지 않는다.

## 7. 실행 단계

1. 정답 판정을 여는 `scanned_severities`를 추가하고, 합성 fixture와 라벨 대조 검증을 만든다.
2. Choice 판정 arm과 토큰 예산 가드를 구현한다. 예산을 넘는 섹션은 잘라 보내지 않고 `oversize`로
   기록해 주 지표에서 뺀다 — 잘림과 모델의 누락을 구분할 수 없게 만들지 않는다.
3. Noul(보조 신호)의 응답 형식을 라이브 1회로 확인한다. 저장소에 형식 근거가 없으므로(9절 A3),
   확인 전에는 필드 이름을 코드에 쓰지 않는다. 확인하지 못하면 배선하지 않는다 — 주 지표는
   항상 Choice로만 계산한다.
4. 개발 45섹션으로 질문을 조정한 뒤(조정마다 질문 버전을 올린다) 최종 90섹션을 3회 반복
   실행한다. 1회차를 주 평가로 쓴다.
5. 혼동행렬과 신뢰구간으로 채점하고, 불일치를 삼분해 진행·보류·중단 결론을 내린다.

예상 호출량은 개발 45 + 최종 90×3 = 315회다. 요청당 약 600 입력 토큰으로 약 19만 토큰이며,
Jev 공개 단가(입력 100만 토큰당 0.042 USD)로 0.05 USD 미만이다. 분당 1,200요청 제한 대비
순차 실행 규모가 작아 제약이 아니다.

결과가 진행이면 2단계가 풀어야 할 것: 스캐너 없는 50개 probe의 정답을 무엇으로 삼을지, 실제
출력 전송 승인, 실제 출력에서의 oversize 처리 정책. 결과가 중단이면 어느 probe 계열에서 무엇이
실패했는지만 적고 멈춘다.

## 8. 검증

```sh
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cd eval && cargo fmt --all -- --check
cd eval && cargo test
cd eval && cargo clippy --all-targets -- -D warnings
cd eval && cargo run -- judge-validate --data data/probe-judgments.json
```

`TYPESAFE_API_KEY`를 비운 채 `cd eval && cargo test`가 통과해야 한다 — 단위 테스트가 실수로
라이브 API를 호출하면 개발 환경에 이미 로드된 키로 조용히 성공하기 때문이다.

## 9. 외부 근거와 알려진 한계

- Choice·Confidence·API 계약·재시도 정책은 [PRD-JEV-PROBE-SELECTION.md 9절](PRD-JEV-PROBE-SELECTION.md#9-외부-근거와-알려진-한계)의 확인(2026-09-22)을 그대로 승계한다. 같은 API이므로 다시 확인하지 않는다.
- **A3 — Noul과 Score의 wire 형식은 저장소에 근거가 없었다.** T5에서 공식 문서
  (`docs.typesafe.ai/primitives/noul`, 2026-09-22 확인)와 라이브 요청 1회로 확인했다. 응답은
  `{"type":"noul","noul":<0..1>}` 하나뿐이고 confidence는 없다(값 자체가 분포 전체를 표현).
  같은 fixture(`disk-dev-2`, 90% 사용률)로 `severity`(Choice)와 `abnormal`(Noul)을 한 요청에
  같이 보낸 결과: `{"severity":{"choice":"warn","confidence":0.91,"probabilities":
  {"warn":0.94,"none":0.01,"crit":0.05}},"abnormal":{"noul":0.84}}` — 정답(warn)과 방향이 일치
  했다. 필드 이름과 범위를 확인했으므로 `eval/src/arms/jev_judge.rs`가 같은 state에 Noul
  질문을 보조로 붙여 보낸다. 주 지표는 그대로 Choice(`label`)로만 계산하고, Noul(`noul`)은
  judge-score(T7)의 임계값별 정밀도·재현율 보조 곡선에만 쓴다.
- 이 1단계는 9개 probe의 재현 여부만 재고, "이상 탐지 능력" 일반을 재지 않는다(1절). kubectl·
  docker stats처럼 형태가 크게 다른 출력은 표본에 없어, 재현 성공이 그 확장까지 보장하지 않는다.

## 10. 결론

1단계를 실행했다. 스캐너 재현율 0.878, 스캐너 대비 정밀도 0.750(최종 90섹션 1회차) — 정밀도가
6절의 중단 문턱(0.85) 아래라 **중단**했다. 실패한 probe 계열, 불일치 삼분, 배운 것은
[PROBE-JUDGMENT-EVALUATION.md](PROBE-JUDGMENT-EVALUATION.md)에 있다. 원시 수치와 재현 절차는
`eval/RESULTS.md`의 "Jev 판정 재현 평가" 절에 있다.
