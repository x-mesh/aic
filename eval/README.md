# aic-eval

`docs/PRD-JEV-PROBE-SELECTION.md`의 비교 실험을 실행한다. 결론은
`docs/PROBE-SELECTION-EVALUATION.md`, 라운드별 수치는 `RESULTS.md`에 있다.

증상 문자열에서 진단 범주를 고르는 네 가지 방식을 같은 데이터로 재고, 각 방식이 첫 진단에서
필요한 증거(probe)를 얼마나 확보하는지 비교한다.

| 비교군 | 범주 판정 |
|---|---|
| `current` | `aic`의 현재 키워드 규칙 |
| `improved` | 단어 경계·점수 합산·부정 처리를 더한 규칙 |
| `jev` | TypeSafe Jev의 Choice |
| `llm` | 설정된 LLM provider의 tool calling |

네 비교군 모두 **범주만 다르게 정하고 probe 구성은 `aic-client`의 같은 함수를 쓴다**
(`select_probes_for_category`). 목록을 복제하면 두 벌이 갈라지고, 그 시점부터 실험은 운영과
다른 것을 재게 된다.

이 크레이트는 워크스페이스 밖에 있다. 배포물에 포함되지 않으며 `cargo test --workspace`에도
잡히지 않는다.

## 실행

```sh
cd eval

# 데이터 라벨이 규칙을 지키는지만 확인(네트워크 없음)
cargo run -- validate

# 규칙 기반 두 비교군만 실행(네트워크 없음)
cargo run -- run --arm current --arm improved --split dev

# 모델을 포함한 실행. 키가 있어야 한다.
TYPESAFE_API_KEY=... cargo run -- run --arm jev --split dev

# 채점과 보고
cargo run -- score --results target/results
```

`jev`와 `llm`은 실제 네트워크 호출이다. `validate`와 규칙 비교군은 호출하지 않는다.

## 환경변수

- `TYPESAFE_API_KEY` — Jev 비교군에 필요하다.
- LLM 비교군은 `~/.config/aic/config.toml`의 provider 설정을 쓰고, 모델은
  `kiro/gpt-5.6-luna`로 고정한다(`--llm-model`로 바꿀 수 있다). provider 기본값에 맡기면 그
  값이 언제 바뀌었는지 결과만 보고는 알 수 없다.

## probe를 실행하지 않는다

이 도구는 **어떤 probe를 고를지만** 계산한다. 고른 명령을 호스트에서 실행하지 않는다. 따라서
실제 진단 시간이나 장애 해결 시간의 단축을 이 결과로 주장할 수 없다.
