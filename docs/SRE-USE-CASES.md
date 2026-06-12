# aic SRE 사용 시나리오

> R1~R6에서 추가한 SRE 기능을 **실제 온콜 워크플로**로 엮은 사용 시나리오집.
> 각 시나리오는 "상황 → 명령 → 기대 동작 → 왜 안전한가" 순으로 적는다.
> 기능 설계 경계는 [SRE-SCOPE-BOUNDARY.md](./SRE-SCOPE-BOUNDARY.md) 참조.

---

## 1. 관측 백엔드 read 통합 (R1)

진단 근거를 로컬 호스트 `ps`/`df` 너머 **메트릭/로그 백엔드**로 확장한다.

### 1-1. 사전 설정

`~/.config/aic/config.toml`에 백엔드를 등록한다. 등록된 백엔드만 질의 가능하다(allowlist).

```toml
[observability.backends.prom]
backend_type = "Prometheus"          # VictoriaMetrics도 동일
url = "http://prometheus:9090"
# auth = "keychain:obs_prom"          # 선택: Bearer 토큰

[observability.backends.logs]
backend_type = "Loki"
url = "http://loki:3100"

[observability.backends.es]
backend_type = "Elasticsearch"
url = "http://elasticsearch:9200"
```

### 1-2. 시나리오: "API p99 레이턴시가 튀는데 원인이 뭐지"

대화형으로 자연어 질문 → 에이전트가 `prometheus_query` 도구를 호출해 메트릭을 본다.

```sh
aic chat
> api 서비스 p99 레이턴시가 5분 전부터 올라가는데 뭐가 원인일까?
```

에이전트가 `prometheus_query(backend=prom, query=histogram_quantile(0.99, ...))`,
`loki_query(backend=logs, query={app="api"} |= "error")`를 순차 호출하고 증거를 종합한다.

### 1-3. 시나리오: 빠른 raw 조회 (LLM 미호출)

분석 없이 숫자만 즉시 보고 싶을 때 slash 명령. backend가 타입별 1개면 `-b` 생략.

```sh
aic chat
> /metrics rate(http_requests_total{job="api"}[5m])
> /metrics -b prom up
> /logs {app="api"} |= "OOMKill"
```

→ redacted raw JSON 출력, history 미오염, 비용 0.

**왜 안전한가**: LLM은 backend *이름*만 고르고 URL을 직접 줄 수 없다(allowlist). reqwest
redirect 비활성 + link-local(169.254 메타데이터) 차단으로 SSRF를 막는다. 응답은 64KB cap +
Bearer/conn-string redaction을 통과한 뒤 LLM에 전달된다.

---

## 2. Webhook alert ingestion → 자동 초동 진단 (R2)

장애가 aic를 찾아오게 한다. 온콜이 터미널을 열기 *전에* 증거 번들이 준비된다.

### 2-1. 사전 설정

```toml
[aicd.webhook]
enabled = true
listen_addr = "127.0.0.1:9099"       # 기본 localhost
secret = "shared-secret"             # env AIC_WEBHOOK_SECRET가 우선
rate_limit_per_min = 10              # storm 비용 폭주 차단
dedup_ttl_secs = 300                # 동일 alert 재진단 차단(루프 방지)
auto_diagnose = true
```

```sh
aic daemon restart   # aicd가 config를 읽어 webhook 리스너 기동
```

Alertmanager receiver 예시:

```yaml
receivers:
  - name: aic
    webhook_configs:
      - url: http://127.0.0.1:9099/webhook/alertmanager
        http_config:
          authorization: { credentials: "shared-secret" }
```

### 2-2. 시나리오: 새벽 3시 HighCPU alert

1. Alertmanager가 firing alert를 POST → aicd가 HMAC/Bearer 인증 검증
2. aicd가 `aic diagnose "HighCPU: web1 CPU 95%" --bundle` 을 **읽기 전용**으로 spawn
3. `~/.aic/bundles/HighCPU-...-<ts>.md`에 증거(probe 수집 + LLM 분석)가 저장됨
4. 온콜이 깨서 로그인하면 번들이 이미 있음

```sh
aic webhook list                 # 수신·진단·dedup·rate-limit 이력
ls -t ~/.aic/bundles | head      # 준비된 증거 번들
```

### 2-3. 시나리오: alert storm

같은 `HighCPU`(같은 fingerprint)가 5분간 50번 와도:
- dedup TTL로 **첫 1회만** 진단 spawn
- 서로 다른 alert가 폭주해도 token-bucket(10/분)으로 LLM 비용 상한

```sh
aic webhook list --json | jq '.[] | {action, alert}'
# "deduped" / "rate_limited" / "diagnosing" 액션이 기록됨
```

**왜 안전한가**: 자동 진단은 `aic diagnose`(고정 Safe probe만)라 상태 변경 명령이 자동
실행되지 않는다(NeedsConfirm 비대화 거부). alert payload symptom은 sanitize(개행/제어문자
제거 + 200자 cap)되어 argv로만 전달된다(셸 미경유). 기본 비활성 + 127.0.0.1 바인드.

---

## 3. Kubernetes 네이티브 probe (R3)

docker probe와 동일 철학 — kubectl 미설치/connection 실패 시 그 출력 자체가 진단 정보.

### 3-1. 시나리오: pod이 자꾸 죽는다

```sh
aic chat
> /triage k8s
```

→ 체크리스트 + 후보 probe 출력:
- `k8s_pods_notready` — Running이 아닌 pod(Pending/CrashLoop/OOMKilled/Error) + RESTARTS
- `k8s_events_warning` — FailedScheduling/OOMKilling/BackOff 이벤트
- `k8s_nodes` — NotReady 노드
- `k8s_node_pressure` — `kubectl top nodes` (CPU/메모리 압박)

### 3-2. 시나리오: 증상 자연어 진단

```sh
aic chat
> /diagnose pod이 CrashLoopBackOff 상태야
```

→ k8s 카테고리로 매핑되어 위 probe들을 수집하고 가설/증거/다음확인을 제시한다.
("pod"/"kubernetes"/"쿠버"/"oomkilled" 등은 최우선으로 k8s로 분류 — `pod oom`도 memory가
아니라 k8s로.)

**왜 안전한가**: 모든 k8s probe는 단일 bounded Safe 명령(`kubectl get/top` read-only,
따옴표/glob 없이 validator 통과)이라 자동 실행 가능. `kubectl top`도 read-only로 분류됨.

---

## 4. Anthropic 네이티브 tool-calling (R4)

Claude 사용자도 tool-calling agent loop가 완전 동작한다(기존엔 read-only로 강등됐었음).

### 4-1. 사전 설정

```toml
[llm]
default_provider = "anthropic"

[llm.providers.anthropic]
provider_type = "Anthropic"
endpoint = "https://api.anthropic.com/v1/messages"
api_key = "keychain:anthropic"
model = "claude-sonnet-4-6"
```

### 4-2. 시나리오: Claude로 진단 대화

```sh
aic chat
> 디스크가 가득 찼는데 뭐가 잡아먹는지 찾아줘
```

→ Claude가 `run_command(df -h)`, `run_command(du ... | sort)` 등 도구를 호출하며 진단한다.
이전엔 Anthropic provider면 도구 호출이 안 돼 단발 답변만 됐지만, 이제 OpenAI provider와
동일하게 동작한다. R1 관측 도구·R3 k8s probe도 Claude에서 그대로 호출된다.

**왜 안전한가**: 도구 정의는 단일 출처(types.rs)에서 Anthropic wire format(`input_schema`,
`tool_use`/`tool_result` 블록)으로 변환된다. 송신 전 content 블록 텍스트도 redaction을 통과.
risk_guard/audit 게이트는 provider와 무관하게 동일 적용된다.

---

## 5. Audit tail/search 조회 (R5)

HMAC 감사 로그를 사후에 조회한다(기존엔 verify만 가능).

### 5-1. 시나리오: "방금 누가 뭘 실행했지"

```sh
aic audit tail -n 20             # 최근 20개 이벤트 시간순
aic audit tail -n 50 --json      # 스크립팅용
```

### 5-2. 시나리오: 사후 조사(post-incident)

```sh
# 차단된 위험 명령만
aic audit search --kind run_command_blocked

# 특정 시간대 + 패턴
aic audit search --since 2026-06-10T02:00:00Z --until 2026-06-10T04:00:00Z --grep restart

# 멀티호스트 fan-out 감사까지 포함
aic audit search --host web1 --multihost
```

→ 사람용 테이블(ts/kind/host/요약) 또는 `--json`. 로컬 `audit.log`와 멀티호스트
`~/.aic/audit/*.jsonl`을 통합 view로 검색한다.

**왜 이렇게**: 순차 스캔(인덱스 없음) — 연 ~10MB 규모라 충분하고 SQLite는 over-engineering.
무결성 검증은 기존 `aic audit verify`(HMAC chain)가 그대로 담당.

---

## 6. Headless / air-gapped 운영 (R6)

aic를 TTY·키체인·인터넷 없는 서버에서 1급으로 돌린다. CI의 `headless` job이 매 PR마다 검증한다.

### 6-1. 시나리오: cron 정기 진단

```sh
# crontab — 비대화, 결과를 번들로 저장
*/30 * * * * AIC_NO_KEYCHAIN=1 aic diagnose --no-analyze --bundle --name cron-health
```

→ TTY 없이 동작, NeedsConfirm 명령은 자동 거부, Safe probe만 수집.

### 6-2. 시나리오: air-gapped(폐쇄망)

외부 LLM 대신 사내 OpenAI-compat 엔드포인트(vLLM/LiteLLM 등)만 사용.

```toml
[llm.providers.internal]
provider_type = "OpenAiCompatible"
endpoint = "http://llm.internal:8000/v1/chat/completions"
api_key = "keychain:internal"        # headless면 평문/env
model = "qwen2.5-coder"
```

관측 백엔드·webhook도 전부 사내망 주소 → 외부 송신 0으로 운영 가능.

### 6-3. 시나리오: 키체인 없는 서버

```sh
# Secret Service가 없는 헤드리스 Linux
export AIC_NO_KEYCHAIN=1             # keychain 우회, API key는 config 평문/env
aic diagnose --no-analyze cpu
```

**왜 안전한가**: 비대화에서 NeedsConfirm(상태 변경) 명령은 실행되지 않는다(e2e로 고정).
PTY 테스트는 실제 터미널이 필요해 headless CI에서 제외된다.

---

## 7. 심층 신호 probe + 자동 발견 (R8)

기존 probe는 risk_guard safelist 바이너리(df/free/ps/ss/sysctl 등)만 써서 **"디스크가 꽉 찼나"는
보지만 "디스크가 느린가(iowait/await)"·"이미 누가 OOM으로 죽었나"·"어떤 서비스가 안 떴나"는
못 봤다.** R8은 read-only로 게이트한 도구(`journalctl`/`dmesg`/`iostat`/`vmstat`/`systemctl
--failed`/`timedatectl`/`lsblk`/`last`)로 이 사각을 메운다.

### 7-1. 시나리오: "서버가 느린데 CPU야 I/O야"

```sh
aic chat
> /diagnose 서버가 느려요
```

→ cpu 카테고리에 `vmstat_iowait`가 붙어 iowait/run-queue/blocked를 분해한다. iowait가 높으면
디스크 I/O 병목, run-queue가 높으면 CPU 병목으로 가른다(마지막 샘플이 현재값).

### 7-2. 시나리오: "앱이 안 떠요" → 실패 유닛 → 로그 2-hop

```sh
aic chat
> /diagnose 앱이 자꾸 죽어요
```

→ process/generic 카테고리에서 `failed_units`(systemctl --failed)와 `journal_errors`(systemd
에러 로그)를 수집한다. follow-up으로 LLM이 `journal_unit <실패유닛>`을 제안하면 게이트를 통과해
해당 unit의 최근 에러 로그를 자동 추적한다(실패 유닛 → 로그 2-hop 체인).

### 7-3. 자동 발견(결정적 임계 스캔)

`/diagnose` 증거 상단에 LLM 호출 없이(오프라인/`--no-analyze`에서도) 확실한 위반만 고정된다:

```
## ⚠ 자동 발견 (결정적 임계 스캔)
- /System/Volumes/Data 디스크 92% 사용 (>= 90%)
- 커널 OOM-killer 흔적 발견(3줄) — 메모리 부족으로 프로세스 강제 종료됨
```

→ 임계: 디스크 ≥90%(실제 쓰기가능 마운트만 — snap/iso9660/DMG/ESP 등 항상-가득 read-only 제외),
OOM-killer 이벤트 시그니처, 누적 좀비(≥10), 실패 systemd 유닛. **오탐이 신뢰를 깎으므로** 보수적으로
잡는다(불확실/baseline 필요 신호는 evidence에만 두고 ⚠로 강조하지 않는다).

**왜 안전한가**: 모든 신규 probe는 단일 bounded Safe 명령(risk_guard arg-gate로 read-only 형태만
Safe). 상태 변경(dmesg clear·journalctl rotate·systemctl start·timedatectl set-*)·무한스트림
(follow·interval-only·count=0)·임의 파일 소스(journalctl/last `--file`)는 Safe에서 제외돼 자동
실행되지 않는다. 자동 발견은 정규식 없는 토큰 파싱 순수 함수라 injection 안전(출력은 데이터로만 취급).

---

## 부록: 한 장 요약

| 기능 | 진입점 | 핵심 안전장치 |
|------|--------|--------------|
| R1 관측 백엔드 | `aic chat` 도구 / `/metrics` `/logs` | allowlist + redirect off + link-local 차단 |
| R2 webhook | `aicd` `[aicd.webhook]` / `aic webhook list` | HMAC/Bearer + rate limit + dedup + 읽기전용 spawn |
| R3 k8s probe | `/triage k8s` / `/diagnose` | bounded Safe kubectl read만 |
| R4 Anthropic | `[llm.providers.*] Anthropic` | 단일소스 변환 + 동일 risk/audit 게이트 |
| R5 audit 조회 | `aic audit tail` / `search` | read-only, HMAC verify는 별도 |
| R6 headless | `AIC_NO_KEYCHAIN=1` + 사내 endpoint | NeedsConfirm 비대화 거부(e2e 고정) |
| R8 심층 probe + 자동 발견 | `/diagnose` / `/triage` / `/watch` | risk_guard arg-gate(read-only만 Safe) + 보수적 결정적 스캔 |
