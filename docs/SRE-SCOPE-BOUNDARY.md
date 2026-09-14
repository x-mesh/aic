# AIC의 SRE 범위와 후속 로드맵

> AIC의 대화형 진단, 제한된 주기 수집, 별도 상시 감시 시스템의 경계를 정의한다.

## 핵심 경계

| 구분 | AIC | 별도 상시 감시 시스템 |
|------|-----|----------------------|
| 시작 조건 | 운영자 명령, webhook, 저장한 workload 정의 | 계속 실행되는 감시 정책 |
| 수집 | `aicd`가 저장한 workload를 60초마다 제한된 읽기 전용 probe로 수집 | 여러 신호를 장기간 연속 수집 |
| 상태 | 로컬 세션, bundle, audit, 제한된 workload 이력 | 장기 시계열, 이상 점수, fingerprint와 incident 기억 |
| 역할 | 현재 증상 진단, 안전한 증거 수집, workload 상태와 최근 이력 조회 | drift와 이상 탐지, incident 연관 분석과 선제 alert |
| LLM | 진단과 분석을 요청할 때 호출 | 탐지는 비-LLM 방식으로 수행하고 필요한 요약에만 호출 |
| 데이터 범위 | 로컬 호스트, SSH 대상, 등록한 관측 백엔드, 명시적으로 활성화한 workload | 지속 수집한 지표, event와 configuration snapshot |

AIC는 더 이상 요청에 따른 단발 진단만 제공하지 않는다. `aicd`는 활성화한 service workload에
60초마다 제한된 probe를 실행하고, 결과를 로컬 JSONL 이력에 저장한다. 이 기능은 연결 상태와
서비스 지표의 최근 변화를 확인하기 위한 제한된 수집 기능이다.

다만 AIC는 프로세스를 계속 재발견하지 않는다. `discover` 결과도 자동으로 활성화하지 않는다.
운영자가 workload 정의를 저장해야 수집을 시작한다. 이력은 모든 어댑터를 합쳐 1,440개 표본만
보존하며, 원격 이력 전송도 지원하지 않는다.

따라서 다음 기능은 별도 상시 감시 시스템의 영역이다.

- 여러 신호를 결합한 연속 이상 탐지와 drift 탐지
- 장기 baseline과 이상 점수 관리
- 여러 호스트와 service를 연결한 incident 연관 분석
- 과거 incident fingerprint 검색과 자동 유사 장애 매칭
- 정책 기반 선제 alert와 자동 복구

## 현재 구현 범위

- Prometheus, Loki와 Elasticsearch의 관측 데이터 조회
- webhook alert를 받아 실행하는 일회성 초동 진단
- Kubernetes read-only probe
- audit tail과 검색
- headless와 air-gapped 검증
- SSH 인벤토리를 사용한 제한된 다중 호스트 diagnose와 batch audit
- `aicd`의 60초 workload probe와 제한된 로컬 이력
- workload의 최신 상태와 최근 지표 이력 조회

Workload monitor 어댑터는 Redis, Memcached, PostgreSQL, MySQL, MongoDB, Prometheus,
ClickHouse, etcd, Elasticsearch, OpenSearch, RabbitMQ, Nginx와 HAProxy를 지원한다. JVM, Kafka와
Consul은 discovery-only 상태이며 서비스 지표 이력을 만들지 않는다.
구체적인 활성화 절차와 수집 계약은 [워크로드 모니터링](./WORKLOAD-MONITORING.md)을 따른다.

## 후속 로드맵

1. Incident memory와 유사 장애 검색은 별도 상시 감시 시스템이 담당한다. AIC는 필요할 때 그
   시스템을 조회할 수 있지만 자체 장기 incident database는 두지 않는다.
2. 연속 이상 탐지와 drift 탐지는 별도 상시 감시 시스템이 담당한다. AIC는 webhook으로 alert를
   받거나 최근 workload 이력을 진단 증거로 사용할 수 있다.
3. `/runbook` 실행은 AIC의 후속 범위다. 각 단계를 확인하고 기존 risk guard와 HMAC audit를
   적용해야 한다.
4. 팀 공유는 AIC의 후속 범위다. 외부 전송에는 명시적 확인과 redaction을 적용해야 한다.
5. Mutation 도구는 read-only 원칙과 분리해 설계해야 한다. Runbook 실행 계약과 함께 검토한다.

## 결정 근거

AIC의 강점은 대화형 진단, 제한된 probe와 audit이다. 60초 workload 수집은 진단에 필요한 최근
서비스 상태를 제공하지만, 장기 관측 시스템을 대체하지 않는다. 별도 시스템은 상시 통계 감시와
incident 기억을 담당한다. 두 시스템을 이 경계에서 연동하면 중복 수집과 서로 다른 판정을 줄일 수 있다.

## 다중 호스트 점검 계약

원격 점검은 SSH 인벤토리와 fan-out 실행기를 사용한다. 각 호스트는 버전이 명시된 같은 결과 계약을
반환한다. 집계 계층은 성공을 추정하지 않고 호스트별 상태와 미완료 대상을 보존한다.

원격 명령은 제한된 읽기 전용 probe만 허용한다. 인증 실패, timeout과 host key 불일치는 진단
결과가 아닌 연결 상태로 보고한다. Batch 결과는 audit chain에 기록한다.
