# 디스크 소진 주체 분석 계약

## 설정

두 기능은 기본 비활성화 상태입니다. 수신기 준비 후 활성화하고 aicd를 재시작합니다.

```toml
[aicd.exporter]
directory_snapshot_enabled = true
process_io_diagnostics_enabled = true
```

기존 exporter의 활성화·endpoint·인증 설정은 별도로 필요합니다.
프로세스별 상태 전송에는 기존 `process_enabled = true`도 필요합니다.
새 플래그는 실행 중 재적용하지 않습니다. 별도 외부 의존성을 추가하지 않습니다.
디렉터리 스냅샷은 새 플래그로 제어하며 기존 `changes_enabled`와 별개입니다.

## R1: 디렉터리 사용량

시작 직후 한 번, 이후 30분마다 수집합니다. 사용률 변화에 따른 추가 수집은 없습니다.
파일시스템 목록 조회와 마운트별 스캔은 별도 aicd 작업 프로세스에서 실행합니다.
각 작업의 시간 상한은 5초입니다. 스캔 종료 후 프로세스 회수 대기는 최대 1초입니다.
커널이 프로세스 종료를 지연하면 `reap_timeout`으로 보고합니다.

sysinfo가 발견한 마운트 중 한 주기에 경로순으로 최대 32개를 처리합니다.
초과 시 포함된 결과에도 `mount_limit`을 표시합니다.
네트워크·미지원 파일시스템은 스캔하지 않고 `excluded_filesystem` 결과를 보냅니다.
수집 가능한 파일시스템은 다음과 같습니다.

```text
apfs hfs hfs+ ext2 ext3 ext4 xfs btrfs zfs tmpfs overlay ufs
```

마운트마다 최대 100,000개 항목을 방문합니다. 재귀 탐색 깊이는 최대 64입니다.
깊이 1~3인 디렉터리 중 사용량 상위 20개를 보고합니다. 경로 길이 상한은 1,024바이트입니다.
보고 깊이만으로 탐색을 제한하면 하위 파일 사용량을 알 수 없으므로, 탐색에는 별도 시간·항목 상한을 적용합니다.

파일 내용을 읽지 않습니다. 디렉터리 목록과 파일 메타데이터만 조회합니다.
사용량은 `st_blocks * 512`인 할당 바이트입니다. 논리 파일 길이와 다릅니다.
심볼릭 링크를 따라가지 않습니다. 다른 마운트와 장치로 이동하지 않습니다.
같은 inode의 hard link는 마운트 스캔에서 한 번만 셉니다.
다음 이름은 메타데이터 조회 전에 제외하며, 결과에 `excluded_path`를 표시합니다.

```text
.ssh .aws .gnupg .kube credentials secrets
.env .env.* *.pem *.key
```

OTLP 계약은 다음과 같습니다.

```text
signal: Logs
endpoint: {endpoint}/v1/logs
scope: aic.changes
resource: host.name, host.id, os.type, service.name=aicd, service.version
aic.change.type: filesystem
aic.change.action: fs_snapshot
aic.change.subject: mount
aic.change.prev_state: 생략
aic.change.new_state: JSON 문자열
aic.change.confidence: observed 또는 degraded
aic.change.source: collector:directory_snapshot
aic.change.record_id: fs_snapshot:{snapshot_id}:{mount}
```

JSON 예시는 다음과 같습니다. `bytes`의 단위는 바이트이며, 디렉터리마다 하위 경로의 사용량을 포함합니다.

```json
{
  "version": 1,
  "snapshot_id": "123-1791000000000000000",
  "mount": "/data",
  "entries": [{"path": "/data/logs", "depth": 1, "bytes": 4096}],
  "truncated": true,
  "reasons": ["permission_denied"],
  "visited_entries": 150,
  "duration_ms": 15
}
```

부분 결과는 `truncated=true`, `confidence=degraded`입니다.
원인은 `timeout`, `entry_limit`, `depth_limit`, `path_limit`, `excluded_path`, `permission_denied`,
`disappeared`, `io_error`, `worker_error`, `reap_timeout`, `excluded_filesystem`, `mount_limit` 중 하나 이상입니다.
작업이 중단되면 마지막 진행 결과를 보냅니다. 진행 결과가 없으면 빈 목록과 실패 원인을 보냅니다.
경로와 JSON은 기존 redaction을 통과합니다. 마스킹된 경로는 실제 경로와 일치하지 않을 수 있습니다.

부분 바이트는 관측한 항목의 합계이며 완전한 사용량이나 정확한 상위 순위가 아닙니다.
하위 디렉터리는 상위 디렉터리에 포함되므로 행을 합산하지 않습니다.
목록에서 사라진 경로를 0으로 해석하지 않습니다. hard link 귀속은 열거 순서에 따라 달라질 수 있습니다.
스캔은 원자적이지 않으며, 진행 중 파일 생성·삭제·이동이 값에 영향을 줍니다.

rca-web은 기존 changes 소비 경로에서 이 JSON을 읽고 마운트·경로별로 두 스냅샷을 비교해야 합니다.
부분 결과끼리의 차분을 정확한 증가량으로 단정하지 않습니다. 두 결과에 모두 있는 경로의 완전성을 확인합니다.
현재 결과는 스냅샷 전체의 완전성만 제공하며, 경로별 완전성은 제공하지 않습니다.
기존 디코더는 changes의 문자열을 저장하므로 새 scope나 metrics 차원을 요구하지 않습니다.

HTTP 실패 시 기존 Logs spool을 사용합니다. 수신기의 부분 거부는 기존 폐기 카운터에 반영합니다.
수집 작업 실패는 로그와 부분 스냅샷으로 표시합니다. 마운트 조회 실패는 exporter 작업 오류로 표시합니다.

## R2: Linux 프로세스 I/O

활성화 시 `/proc/<pid>/io`의 `read_bytes`와 `write_bytes`를 직접 읽습니다.
기존 host metrics 주기를 사용합니다. 기본 주기는 60초입니다.
이전 카운터는 `(pid, start_time)`으로 식별합니다. 값은 누적 카운터의 구간 차분입니다.
첫 관측·측정 복구·카운터 감소에는 기준선만 설정합니다.
조회 실패는 이전 기준선을 제거하며, 다음 성공 시 여러 구간의 값을 한 구간으로 보내지 않습니다.

```text
signal: Logs
endpoint: {endpoint}/v1/logs
scope: aic.process
process.disk.io.status: measured | baseline | permission_denied |
                        unavailable | unsupported | partial
process.disk.read_bytes: 측정 구간의 읽기 delta, 바이트 단위
process.disk.write_bytes: 측정 구간의 쓰기 delta, 바이트 단위
```

`measured`는 실제 0을 포함해 두 바이트 속성을 보냅니다.
다른 상태는 바이트 속성을 생략합니다. OTLP에 NULL 숫자를 넣지 않습니다.
`baseline`은 아직 유효한 차분 구간이 없다는 뜻입니다.
`permission_denied`는 권한 오류이며, `unavailable`은 소멸·파싱 실패 등 다른 조회 실패입니다.
Linux 외 플랫폼은 `unsupported`입니다. macOS의 기존 sysinfo 표본을 신뢰 가능한 측정으로 승격하지 않습니다.
`__rest__` 집계에 미측정 항목이 하나라도 있으면 `partial`로 보고하고 바이트 합계는 생략합니다.
CPU·RSS·I/O·FD 각 상위 10개의 합집합과 나머지 집계라는 선정 정책은 유지합니다.

최초 권한 실패가 관측되면 데몬 기동마다 한 번 진단 이벤트를 spool에 기록합니다.

```text
signal: Logs
scope: aic.agent
severity: WARN
aic.agent.kind: process.io.permission_denied
aic.agent.denied_count: 해당 구간에 읽기 권한이 없던 프로세스 수, 문자열
```

이 이벤트는 새 진단 플래그로 제어하며 기존 `agent_enabled`와 별개입니다.
진단 이벤트의 전송·저장은 기존 Logs spool 경로를 사용합니다.
권한 오류는 데몬 UID와 procfs 접근 정책을 확인할 근거이며, 특정 정책이 원인이라는 확정은 아닙니다.

현재 rca-web의 process 디코더는 누락된 바이트를 0으로 저장합니다.
수신기에 `process.disk.io.status` 저장과 nullable 바이트 필드 처리를 추가한 뒤 이 플래그를 켭니다.
플래그가 꺼져 있으면 기존 sysinfo 값과 기존 속성 계약을 유지하며 상태 속성을 추가하지 않습니다.
소비자는 이 delta를 합산합니다. 누적 카운터처럼 다시 차분하지 않습니다.

## R3: macOS 한계

별도 `fs_usage` 추적과 APFS 스냅샷 크기 게이지는 추가하지 않습니다.
R1은 로그·캐시·VM 이미지가 있는 디렉터리의 증가를 관측할 수 있습니다.
APFS clone·공유 블록·스냅샷·삭제됐지만 열린 파일은 디렉터리 할당 바이트만으로 귀속을 확정할 수 없습니다.
큰 파일시스템에서는 시간 상한 때문에 반복해서 부분 결과만 얻을 수 있습니다.

`tmutil help listlocalsnapshots`는 목록 조회 기능을 제공하며, 이 확인으로 스냅샷의 총 크기를 측정하지는 않았습니다.
[Apple 문서](https://support.apple.com/en-us/102154)는 로컬 스냅샷 공간을 가용 공간으로 계산하며 필요할 때 자동 삭제한다고 설명합니다.
따라서 스냅샷 개수를 소진 바이트로 해석하지 않습니다. 해당 호스트에서 R1이 원인을 설명하는지는 실제 수신 데이터로 확인해야 합니다.

## 검증 경계

테스트는 임시 디렉터리와 로컬 mock collector를 사용합니다.
작업 프로세스의 제한·부분 결과·OTLP 계약과 I/O 상태 전이를 확인합니다.
rca-web 저장·조회·RCA finding·실제 서버의 권한 정책은 별도 검증 대상입니다.
배포·릴리스·푸시는 이 변경에 포함하지 않습니다.
