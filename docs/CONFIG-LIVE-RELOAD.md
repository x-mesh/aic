# Config Live Reload

> `aicd`를 재시작하지 않고 바꿀 수 있는 `[aicd.exporter]` 설정과 그 반영 규칙.

## 왜 필요한가

`aicd`는 기동할 때 `config.toml`을 한 번 읽었다. 주기 하나, 토큰 하나를 바꾸려 해도 데몬을
재시작해야 했고 재시작은 수집 공백을 만든다. 이 공백은 spool이 메워주지 않는다. spool은
collector가 죽어 있는 동안 쌓아 두었다가 재전송하는 버퍼이지, 데몬이 꺼져 있던 동안의 데이터를
만들어내지 못한다.

그래서 **이미 각 exporter의 tick 안에서 소비되는 값**만 골라 실행 중 교체할 수 있게 했다. 자원을
다시 만들어야 하는 값은 대상이 아니다.

## 재시작 없이 바뀌는 설정

전부 `[aicd.exporter]` 섹션이다.

| 설정 | 기본값 | 반영 시점 |
|---|---|---|
| `token` | 없음 | 다음 전송 |
| `interval_secs` | 60 | 다음 tick |
| `connections_interval_secs` | 60 | 다음 tick |
| `changes_interval_secs` | 30 | 다음 tick |
| `docker_interval_secs` | 60 | 다음 tick |
| `kernel_interval_secs` | 60 | 다음 tick |
| `self_update_enabled` | false | 다음 확인 주기 |
| `self_update_interval_secs` | 3600 | 마지막 확인 시각 기준으로 재계산 |
| `spool_drain_batch_limit` | 20 | 다음 tick |
| `spool_max_age_secs` | 없음 | 다음 tick |
| `process_enabled` | true | 다음 tick |
| `process_inventory_enabled` | false | 다음 tick |
| `docker_bin` | 없음(자동 탐색) | 다음 tick |

`token`은 여덟 개 전송 task(host metrics, events, connections, changes, docker, kernel, agent,
logs)에 **동시에** 적용된다. 일부만 바뀌면 회전 직후 나머지가 401을 받는다.

주기를 0으로 적으면 1초로 올린다. `tokio`의 주기 타이머는 0초에서 패닉하므로, 오타 하나로 데몬이
죽지 않게 기동 경로와 같은 하한을 재적용에도 건다.

`self_update_interval_secs`를 줄였는데 그만큼이 이미 지났으면 곧바로 확인한다. 기준은 변경 시각이
아니라 마지막 확인 시각이다. 변경 시각을 기준으로 다시 재면 설정을 연달아 고치는 동안 확인이
영원히 밀린다.

`self_update_enabled`는 조건이 하나 붙는다. `aicd`는 **`endpoint`가 설정돼 있으면** 셀프업데이트
task를 띄우고, 꺼져 있는 동안 그 task는 중앙에 묻지 않고 대기만 한다. 그래서 켜고 끄는 것은
재시작 없이 된다. `endpoint`가 비어 있는 상태로 기동했다면 task 자체가 없으므로, 주소를 채운 뒤
한 번은 재시작해야 한다.

셀프업데이트는 `[aicd.exporter] enabled`와 독립이다. 텔레메트리를 보내는 것과 디스크의 binary를
교체하는 것은 같은 동의가 아니라서 게이트를 따로 둔다. exporter를 꺼 두어도 셀프업데이트는
동작한다.

## 반영 흐름

`aicd`는 `config.toml`의 mtime을 10초마다 확인한다. mtime이 그대로면 파일을 읽지 않는다. 바뀌었으면
`[aicd.exporter]`를 다시 읽어 공유 스냅샷을 교체하고, 대기 중인 task를 깨운다.

깨우기가 필요한 이유는 주기가 길어서다. 셀프업데이트 기본 주기는 한 시간이다. 깨우지 않으면 주기를
10분으로 줄여도 한 시간 뒤에야 바뀌고, 설정을 고친 사람에게는 반영이 안 된 것과 구별되지 않는다.

깨어난 task는 주기만 다시 잡고 계속 기다린다. 설정 변경이 수집이나 업데이트 확인을 앞당기지는
않는다.

각 task는 tick을 시작할 때 스냅샷을 한 번 고정해 그 tick 내내 같은 값을 쓴다. tick 도중에 값이
갈리면 같은 배치의 앞뒤가 서로 다른 설정으로 만들어진다.

## 바꾸는 방법

```sh
# 자체 업데이트를 켜고 확인 주기를 10분으로
aic config set aicd.exporter.self_update_enabled true
aic config set aicd.exporter.self_update_interval_secs 600

# 수집 주기를 30초로
aic config set aicd.exporter.interval_secs 30

# ingest 토큰 회전. 값이 shell history에 남지 않게 stdin으로 넣는다
aic config set aicd.exporter.token - < new-token.txt
```

`aic config set`은 바꾼 값이 언제 적용되는지 마지막 줄에 알린다.

```
✔ aicd.exporter.self_update_enabled = true
  aicd가 최대 10초 안에 설정을 다시 읽습니다 — 재시작이 필요 없습니다
```

재시작이 필요한 값에는 대신 `aic daemon restart`를 안내한다. 어느 쪽인지 외울 필요가 없다.

`aic config set`은 임시 파일에 쓰고 rename한다. rename은 같은 파일시스템 안에서 원자적이므로,
`aicd`가 읽는 순간에는 이전 완성본이나 새 완성본 중 하나만 보인다. 부분 작성 파일을 파싱해 exporter가
꺼지는 일은 없다.

`config.toml`을 편집기로 직접 고쳐도 같다. 저장하면 mtime이 바뀐다.

## 반영을 확인하는 방법

`aicd` 로그에 다음 세 문구가 뜬다.

- `[aicd.exporter] 재적용` — 파일을 다시 읽어 스냅샷을 교체했다.
- `수집 주기 변경 적용` — 어느 exporter의 주기가 몇 초에서 몇 초로 바뀌었는지 `exporter` 필드가
  가리킨다.
- `셀프업데이트 주기 변경 적용` — 셀프업데이트 확인 주기가 바뀌었다.
- `셀프업데이트 스위치 변경 적용` — `self_update_enabled`가 바뀌었다. `enabled` 필드가 지금 값이다.

셀프업데이트 설정은 `aic status`에도 실린다.

```sh
aic status --json | jq .self_update
```

`aic status`의 "자동 업데이트" 줄에서도 같은 값을 읽는다. 껐으면 `꺼짐`, 켰으면 `동작 중 (N초
주기)`로 바뀐다.

값이 바뀌지 않으면 스냅샷이 교체되지 않은 것이다. 설정 경로 철자와 파일 mtime을 확인한다.

### 설정이 무시되는 가장 흔한 원인

점 표기 키를 다른 테이블 **안**에 적으면 TOML은 그 테이블의 하위 키로 해석한다.

```toml
[rca_agent]
enabled = false
aicd.exporter.self_update_enabled = true   # rca_agent.aicd.exporter.… 가 된다
```

이 줄은 오류를 내지 않고 조용히 무시된다. `aic config get`으로 확인한다.

```sh
aic config get aicd.exporter.self_update_enabled
```

`aic config set`은 값을 항상 올바른 테이블에 쓰므로 이 함정이 없다. 파일을 손으로 고칠 이유가
없다면 명령을 쓴다.

## 재시작이 필요한 설정

다음은 자원을 다시 만들거나 task를 새로 띄워야 하므로 실행 중 바꿔도 반영되지 않는다. 값은 스냅샷에
들어가지만 읽는 쪽이 없다.

| 설정 | 이유 |
|---|---|
| `enabled` | exporter task 전체를 띄울지 결정한다 |
| `events_enabled`, `connections_enabled`, `agent_enabled`, `changes_enabled`, `logs_enabled`, `docker_enabled`, `dns_enabled`, `kernel_enabled` | 각 task를 띄울지 결정한다 |
| `endpoint` | 전송 URL을 기동 시 조립한다. 도중에 바꾸면 spool에 쌓인 배치의 목적지가 갈린다 |
| `kernel_url` | 같은 이유. loopback 검증도 기동 시 한 번 한다 |
| `spool_max_bytes` | spool을 열 때 쿼터가 정해진다 |
| `enrollment_id` | 전송 payload의 리소스 속성에 실린다 |

`kernel_window_secs`는 어느 쪽도 아니다. duration=0 폴링으로 전환한 뒤로 쓰이지 않으며, 기본값과
다르게 설정하면 기동 시 무시한다는 안내만 남긴다.

바꾸려면 데몬을 재시작한다.

```sh
aic daemon restart
```

## 한계

mtime이 같은 초 안에 두 번 바뀌면 두 번째를 놓칠 수 있다. 파일시스템에 따라 mtime 해상도가 1초다.
확인 주기가 10초이므로 실사용에서는 다음 변경 때 따라잡는다. 확실히 하려면 1초를 띄우고 다시
저장한다.

파일을 읽지 못하거나 TOML 파싱에 실패하면 직전 스냅샷을 유지한다. 읽지 못한 것을 "꺼졌다"로
해석하면, 편집 중 잠깐 깨진 파일 하나로 텔레메트리가 끊긴다. 파싱 실패는 로그에 한 번 남는다. 같은
파일이 그대로 있는 동안은 다시 읽지 않으므로 경고가 반복되지 않는다.

환경변수 `AIC_EXPORTER_TOKEN`을 설정한 호스트에서는 config의 `token`을 바꿔도 적용되지 않는다.
환경변수가 config 평문보다 우선한다는 기존 규칙을 재적용에도 유지한다. 그 호스트에서 토큰을 바꾸려면
환경변수를 고치고 데몬을 재시작한다.
