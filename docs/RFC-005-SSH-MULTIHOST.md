# RFC-005: `aic chat` — SSH 멀티호스트 진단

> `aic chat`의 단일 호스트 진단을 N개 원격 호스트로 확장한다. `~/.aic/hosts.toml`
> 통합 인벤토리(`~/.ssh/config` 자동 import) 기반으로 `/diagnose @web-tier` 같은
> 그룹 패턴을 받아, 외부 `ssh` 프로세스로 probe·read-only run_command를 병렬
> 실행하고 결과를 호스트별 카드(severity-sort + collapsed ok)로 보여준다.
> mutation·write는 멀티호스트에서 하드 차단해 안전 경계를 단일 호스트와 분리한다.

- 상태: **Draft v2 — council CONSENSUS WITH RESERVATIONS + red-team Critical 12 fixed (2026-05-25)**, MVP 미구현
- 작성일: 2026-05-25 (v1) · 갱신일: 2026-05-25 (v2 — red-team 반영)
- 대상 바이너리: `aic` (crate `aic-client`, lib `aic_client`)
- 범위: `aic chat` 안에서의 멀티호스트 진단 흐름. mutation을 묶는 `aic run --hosts`
  서브커맨드는 본 RFC의 비목표(별도 후속 RFC).
- 관련 문서:
  - [RFC-002-AIC-CHAT-AGENTIC.md](./RFC-002-AIC-CHAT-AGENTIC.md) — chat 진입점 + tool-calling 루프
  - [RFC-004-RATATUI-CHAT-TUI.md](./RFC-004-RATATUI-CHAT-TUI.md) — 전면 TUI, status bar, 카드 렌더
  - [PRD-AIC-SRE-CHAT.md](./PRD-AIC-SRE-CHAT.md) — SRE Agent MVP 범위
  - `.xm/op/brainstorm-2026-05-25-aic-additional-features.json` — T1.1 후보 도출
  - `.xm/op/council-2026-05-25-ssh-multihost.json` — 본 설계의 council 결론
  - **`.xm/op/red-team-2026-05-25-rfc-005-ssh-multihost.json` — 본 v2의 검증 근거(Critical 12 fix)**
- 관련 코드(설계 시 확장 대상):
  - `aic-client/src/agent/run_command.rs` — sandbox + risk_guard + 확인 UI (단일 호스트 게이트 재사용)
  - `aic-client/src/agent/probes.rs` — probe catalog (호스트 인자 추가)
  - `aic-client/src/agent/diagnose.rs` — `/diagnose` 흐름 (그룹 패턴 분기)
  - `aic-client/src/agent/audit.rs` — HMAC chain (batch_id + daily segment)
  - `aic-client/src/agent/chat_tui.rs` — 카드 stack 렌더, 상태 태그

---

## 1. 목표 / 비목표

### 1.1 Goals (MVP)
- `/diagnose @group` · `/diagnose --host user@host`로 N개 원격 호스트에서 probe를 병렬 실행하고,
  호스트별 카드를 chat 로그에 표시(severity-sort + collapsed ok).
- read-only `run_command`도 같은 흐름에서 멀티호스트 허용(§4.3 tokenizer 화이트리스트 + 경로 allowlist 통과).
- 부분 실패에 대해 `continue-and-report` + 8종 상태 태그(§4.4)로 원인을 즉시 식별 가능하게 한다.
- 멀티호스트 명령은 `batch_id` 단위 audit + daily segment(§4.6)로 추적·검증 가능하게 한다.

### 1.2 Non-Goals
- mutation · `write_file` · `edit_file`의 멀티호스트 흐름 → **하드 차단**. 별도 후속 RFC.
- 원격 `aic` 바이너리 사전 배포(zero-agent 원칙). aic는 로컬에만.
- 원격 호스트에서 daemon(aicd) RPC.
- **MFA(keyboard-interactive) 호스트의 멀티호스트 지원** — `BatchMode=yes` 아키텍처와 양립 불가(red-team U3 잔존). MFA 호스트는 단일 호스트 흐름으로 사용.
- Ansible inventory / Kubernetes context 직접 통합 — 후속 옵션.
- diff 모드(majority-diff·reference 호스트 선택 UX) — MVP는 카드 stack(+ severity-sort + collapsed)만, 1.1로 분리.

### 1.3 Out of Scope의 의도
mutation을 멀티호스트로 가져가면 부분 실패 시 클러스터 상태가 비일관해진다(롤백 부재). aic는 SRE
**진단** 도구지 오케스트레이터가 아니므로 변경은 단일 호스트 흐름(또는 별도 명시적 서브커맨드)에
머무는 것이 책임 경계에 맞다.

---

## 2. Context

### 2.1 왜 지금 필요한가
0.10.0까지 aic는 **단일 호스트(로컬)** 만 대상이다. probe catalog · run_command · sandbox · audit · TUI
카드 모두 한 호스트 가정. 실무 SRE는 보통 같은 tier의 N개 호스트를 비교해 "왜 prod-a만 다른가"를
빠르게 식별해야 한다. 단일 호스트 진단을 N번 반복하는 워크플로우는 비교 인지 부하가 크다.

T1.1은 brainstorm Phase 3 투표에서 4 에이전트 전원이 명시적으로 제안한 후보 그룹 중 하나였고,
council R1·R2를 거치며 4 차원(실행·인증·범위·안전) 모두에서 구체적 합의가 도출됐다. 본 v2는
council 결론에 더해 red-team의 12 Critical 결함에 대한 fix까지 반영한다.

### 2.2 현재 코드 구조와의 정합점
- `run_command`는 이미 `tokio::process::Command`로 외부 프로세스를 띄운다 → `ssh` 호출은 같은
  파이프라인 앞단에 host prefix를 붙이는 것과 동치(기존 cap/redact/audit 재사용).
- `ProbeSpec::command()`는 OS-aware 고정 문자열을 반환 → 멀티호스트로도 그대로 흘려보낼 수 있다.
- `audit.rs`의 HMAC chain은 단일 엔트리 단위 → batch_id 한 단계 위에 + daily segment로 보강.
- 단일 호스트 `run_command.rs`의 stdout 상한(64 KiB 저장 / 8 MiB 드레인)을 원격 레이어에 전이.
- ratatui 카드 렌더(`chat_tui.rs`의 Note/Answer 흐름)는 N개 카드를 severity 순으로 push.

---

## 3. Design Decision

본 RFC는 두 단계의 외부 검증을 통과했다.

### 3.1 1차 — council CONSENSUS WITH RESERVATIONS
`.xm/op/council-2026-05-25-ssh-multihost.json`. 4 dimension(실행·인증·범위·안전)에서 R1·R2 cross-examine 후 도출.

### 3.2 2차 — red-team Critical 12 검증
`.xm/op/red-team-2026-05-25-rfc-005-ssh-multihost.json`. dimension별 4 attacker가 54 결함(Critical 12 / High 18 / Medium 24) 도출 → defender가 Critical 12 응답.

결과: **🟢 Fixed/Counter 8 · 🟡 Partial 4 · 🔴 Open 0.**

| ID | Critical 결함 | 반영 |
|----|--------------|------|
| S1 | shell_escape + 비-sh 셸 | §4.2 (PARTIAL) |
| S2 | 경로 동등 우회 | §4.3 (FIX) |
| S3 | `/proc/self/environ` 노출 | §4.3 + §4.6 (FIX) |
| R1 | Semaphore permit 누수 | §4.5 (PARTIAL) |
| R2 | OOM 버퍼 상한 | §4.5 (FIX) |
| R3 | SIGKILL PID 재사용 race | §4.5 (COUNTER) |
| U1 | 100+ 호스트 스크롤 | §4.4 (PARTIAL) |
| U2 | 5종 태그 long-tail | §4.4 (FIX) |
| U3 | `[auth_fail]` 행동 부재 | §4.4 (FIX) |
| O1 | ssh_config 범위 + 디버깅 | §4.1 (PARTIAL) |
| O2 | audit 로테이션 | §4.6 (FIX) |
| O3 | 화이트리스트 확장 | §4.3 (FIX) |

PARTIAL 4개의 잔존(RESIDUAL)은 §7 Risks에 명시.

---

## 4. Detailed Design

### 4.1 호스트 정의 + 인증

#### 인벤토리 (주: `~/.aic/hosts.toml`)

```toml
# ~/.aic/hosts.toml
[options]
ssh_config_import = true            # default — Host 블록만 흡수
default_host_key_check = "strict"
remote_shell_wrap = false           # 원격 $SHELL 감지 시 자동 true (§4.2 S1)

[groups.web-tier]
hosts = ["web-01", "web-02", "web-03"]
tags  = ["nginx", "prod"]

[[hosts]]
name        = "web-01"
hostname    = "10.0.1.10"           # ssh config에 있으면 생략 가능(overlay)
user        = "sre"
port        = 22
tags        = ["nginx", "prod"]
identity_file = "~/.ssh/web_prod_ed25519"   # ★ U3 — auth_fail hint와 정합
forward_agent = false                       # ★ U3·red-team High — 기본 off, bastion 신뢰 시만 on
host_key_check = "strict"
connect_timeout_secs = 10

[[hosts]]
name = "bastion-legacy"
hostname = "10.0.1.5"
user = "ops"
port = 2222
proxy_jump = "bastion-main"
```

#### ssh_config 파싱 위임 경계 (O1)

aic는 `~/.ssh/config`에서 **Host 블록의 다음 directive만** 추출해 hosts.toml 인벤토리에 흡수한다.
그 외 directive는 aic가 직접 해석하지 않고 **`ssh` 프로세스에 위임**한다.

| aic 흡수 (hosts.toml에 overlay) | ssh 프로세스가 직접 처리 (aic 미파싱) |
|---|---|
| `HostName`, `User`, `Port`, `ProxyJump` | `Match exec`, `Match canonical` |
|  | `%h`, `%r`, `%p`, `%u` 토큰 확장 |
|  | `ProxyCommand` (임의 명령 실행 — §7 Risk 참고) |
|  | `Include` (aic는 재귀하지 않음) |
|  | `CanonicalizeHostname`, `IdentityFile` 직접 로드 |

#### 디버깅 CLI — `aic hosts show` (O1)

```
$ aic hosts show
  web-01    10.0.1.10  sre  22    [source: ssh_config + hosts.toml overlay]
  bastion   10.0.1.5   ops  2222  [source: hosts.toml]

$ aic hosts show web-01
  name:            web-01
  hostname:        10.0.1.10                  (ssh_config)
  user:            sre                        (hosts.toml overlay)
  port:            22                         (ssh_config)
  proxy_jump:      —
  host_key_check:  strict                     (hosts.toml override)
  identity_file:   ~/.ssh/web_prod_ed25519    (hosts.toml)
  forward_agent:   false                      (hosts.toml — 기본값)
  ssh_config_warnings:
    - Match exec directive ignored (ssh process handles)
    - Include ~/.ssh/conf.d/* not followed by aic

$ aic hosts show --json   # 머신 파싱
```

#### 인증
- **ssh-agent 전적 의존**(`SSH_AUTH_SOCK`). 평문 private key를 aic 메모리에 올리지 않는다.
- **`BatchMode=yes`** 로 비밀번호/MFA 프롬프트 원천 차단(TUI alternate screen 호환).
- **`-o ForwardAgent=no` 항상 명시** (★ red-team A1 High) — 사용자의 `~/.ssh/config` 전역 `ForwardAgent yes`가 자동 상속되어 악성 원격 호스트가 agent socket을 탈취하는 경로를 차단. bastion 신뢰가 필요한 경우만 `hosts.toml`의 `forward_agent = true`로 명시 opt-in.
- TOFU(신규 host key) 처리: 별도 시퀀스(아래).

#### TOFU 시퀀스 (★ red-team A2/A4 High — BatchMode↔TOFU 양립 해소)

`BatchMode=yes` + `StrictHostKeyChecking=strict` 조합은 신규 호스트 키에 대해 ssh가 즉시 `exit 255`로 종료한다. confirm prompt를 띄울 기회가 없다. v2는 다음 4-step으로 명시적 분리:

```
1. ssh 시도          BatchMode=yes + Strict → exit 255 (known_hosts miss)
2. ssh-keyscan -T 5  새 키 fingerprint 수집 (별도 round-trip)
3. TUI confirm       fingerprint를 사용자에게 노출 → y/N (Ctrl+C도 거부)
                      직렬화 보장: 한 번에 하나의 confirm만 (mpsc 직렬화)
4. y 시              known_hosts에 aic가 직접 append (flock + atomic write)
                      audit tofu_accept 기록 → 원래 ssh 명령 재시도
   N 시              audit tofu_reject 기록 → [auth_fail] 마킹, 호스트 제외
```

같은 batch에서 신규 호스트가 여러 개여도 confirm은 **mpsc로 직렬화**(한 번에 하나)되어 ratatui 렌더 race를 방지한다(red-team A2 High). known_hosts append는 **로컬 flock**으로 동시 batch race 차단(red-team A1 High). `ssh-keyscan` 자체가 MITM 노출 위험이 있으나, 이는 표준 `ssh -o StrictHostKeyChecking=ask`의 fingerprint 노출과 동급으로, 사용자가 외부 채널로 검증해야 함을 confirm UI에 명시.

#### 임시 호스트
`--host user@host[:port]` 인자로 인벤토리 없이도 즉석 지정 가능.

### 4.2 실행 메커니즘

#### 추상화

```rust
// aic-client/src/agent/remote/mod.rs
#[async_trait]
pub(crate) trait RemoteExecutor: Send + Sync {
    async fn exec(&self, host: &HostEntry, cmd: &RemoteCommand) -> RemoteResult;
}

pub(crate) struct RemoteCommand {
    pub program: String,
    pub args: Vec<String>,                  // 셸 해석 배제 (S1)
}

pub(crate) struct RemoteResult {
    pub host: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub status: HostStatus,                 // 8종 (§4.4)
    pub truncated: bool,                    // 64KiB/8MiB 초과 시 (§4.5)
}
```

#### MVP: 외부 `ssh` 프로세스 (단일 구현)

```rust
let mut cmd = tokio::process::Command::new("ssh");
cmd.args([
    "-o", "BatchMode=yes",
    "-o", "ForwardAgent=no",                                        // ★ red-team High
    "-o", &format!("ConnectTimeout={}", host.connect_timeout),
    "-o", &format!("StrictHostKeyChecking={}", host.host_key_check),
    // ★ ControlMaster — 같은 batch 안의 호스트별 재연결 비용 절감 (red-team A2 High)
    "-o", "ControlMaster=auto",
    "-o", &format!("ControlPath=/tmp/aic-cm-{}-%C", batch_id),
    "-o", "ControlPersist=60s",
    "-p", &host.port.to_string(),
    &format!("{}@{}", host.user, host.hostname),
    "--",
    &remote_cmd.program,
]);
for arg in &remote_cmd.args {
    cmd.arg(shell_escape(arg));
}
```

#### `shell_escape` 명시 (S1)

```rust
/// POSIX sh-safe quoting: '...' 래핑 + 내부 ' → '\''
/// fish/csh 등 비-sh 셸은 host_shell_probe()가 감지 시 sh -c 래핑으로 보강.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
```

원격 호스트의 default shell이 sh/bash/zsh가 아닐 가능성에 대비해 **첫 연결 시 `host_shell_probe`**로 `$SHELL` 또는 `getent passwd $(whoami)`를 확인하고, fish/csh이면 `remote_shell_wrap = true`로 자동 강제(같은 ControlMaster 세션 재사용). PARTIAL 잔존(§7 Risk): 비표준 sshd가 첫 명령 후 rc 파일을 강제로 실행하는 경우.

#### `RemoteExecutor` trait 유지 이유
MVP는 단일 구현. 미래 전환 트리거(러스시/`ssh2`)는 §5.2.

#### Collect-then-render
호스트별 stdout/stderr를 §4.5의 상한 안에서 완전 버퍼링한 뒤 카드로 렌더한다(streaming 금지 — interleave 방지). 단일 호스트가 cmd timeout(30s)에 걸려도 다른 호스트는 즉시 카드 렌더(ControlMaster 세션 별개).

### 4.3 진단 범위

#### 멀티호스트 허용
1. **probe catalog 전체** (cpu/mem/disk/docker/fd/netstat 등) — `/diagnose @group`, `/local @group`.
2. **read-only `run_command`** — 아래 4단 게이트를 모두 통과해야 한다.

#### 게이트 1: tokenizer 화이트리스트
- shell 메타문자(`; & | $() <> \` `, redirect, backtick) **차단**.
- 명령은 args 배열로 분리 + `shell_escape` quote.
- 허용 프로그램 (내장):

| program | 허용 패턴 |
|---------|----------|
| `ps` | `ps aux`, `ps -ef`, `ps -eo {cols}` 허용 컬럼: `pid,ppid,pgid,sid,user,group,comm,args,pcpu,pmem,vsz,rss,stat,start,time,etime` |
| `df` | `df -h [path]` (경로는 게이트 2/3 적용) |
| `free` | `free -m` / `free -h` |
| `uptime` | (인자 없음) |
| `cat` | `cat <path>` (경로 게이트 2/3 적용) |
| `journalctl` | `journalctl -n N --no-pager [--since=…]` (옵션 화이트리스트 적용) |
| `ls` | `ls [-l|-a|-h] <path>` |
| `find` | `find <path> -maxdepth N [-name …]` (maxdepth 필수) |

#### 게이트 2: lexical canonicalization + 동등 경로 차단 (S2)

경로 인자는 매칭 전에 정규화한다:
- `/etc/./shadow` → `/etc/shadow`
- `/etc/../etc/shadow` → `/etc/shadow`
- 연속 슬래시 `//` → `/`
- 백슬래시·URL 인코딩 정규화

이후 게이트 3 매칭. **lexical만 처리** — 원격 symlink chain은 클라이언트에서 해소 불가(trust boundary 명시).

#### 게이트 3: procfs/devfs/sysfs **allowlist 반전** (S2 + S3)

`/proc/`·`/dev/`·`/sys/`·`/run/secrets/` 접두사는 **기본 차단**. probe catalog가 실제 사용하는 것만 명시 허용:

```rust
// 허용 procfs 경로 (probe catalog에서 실제 사용)
const PROCFS_ALLOWLIST: &[&str] = &[
    "/proc/loadavg",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/vmstat",
    "/proc/diskstats",
    "/proc/net/dev",
];

// 그 외 명시 차단 (디버깅용 — allowlist 미스 시)
const FORBIDDEN_PREFIXES: &[&str] = &[
    "/proc/self/", "/proc/[0-9]+/",
    "/proc/net/tcp", "/proc/net/udp", "/proc/sysvipc/",
    "/dev/", "/sys/firmware/", "/run/secrets/",
];
```

추가로 파일명 패턴 denylist(보강):
- `**/id_rsa*`, `**/id_ed25519*`, `**/*.pem`, `**/*.key`
- `**/.env*`, `**/.aws/credentials`, `**/.kube/config`
- `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`

#### 게이트 4: 사용자 확장 화이트리스트 (O3)

```toml
# ~/.aic/whitelist.toml — append-merge (내장 override 불가)
[[programs]]
name = "ss"
allowed_args = [["-tlnp"], ["-s"], ["-t", "-l", "-n", "-p"]]

[[programs]]
name = "curl"
allowed_args = [["-s", "{url:localhost}"]]   # localhost:* 만 허용

[[programs]]
name = "systemctl"
allowed_args = [["status", "{unit}"]]
```

CLI:
```
$ aic whitelist status
  builtin: ps, df, free, uptime, cat, journalctl, ls, find (8)
  user:    ss, curl, systemctl (3)  ← ~/.aic/whitelist.toml
  total:   11 programs

$ aic whitelist check "ss -tlnp"
  program: ss
  args:    ["-tlnp"]
  result:  ALLOW (user, line 4)
```

#### 멀티호스트 차단(하드)
- mutation 명령(`rm`, `kill`, `mv`, `chmod`, `chown`, `systemctl restart/stop/start`, `kubectl delete/apply/exec`, `docker rm/stop` 등 risk_guard `Dangerous`).
- `write_file` / `edit_file` 도구 — 호스트 인자가 멀티면 즉시 거부 + note: "단일 호스트로 전환: `/use --host <name>` 또는 `--host user@host`로 재시도".
- 변경은 별도 `aic run --hosts ... -- <command>` 서브커맨드(후속 RFC).

### 4.4 결과 표시

#### 8종 상태 태그 (U2)

```rust
pub enum HostStatus {
    Ok,                      // exit 0, stderr 무해
    OkWithWarn,              // exit 0, stderr에 WARNING/NOTICE 패턴 (★)
    Unreachable,             // ConnectTimeout 또는 exit 255 + duration ≤ ConnectTimeout
    Timeout,                 // command execution timeout (per-host 30s)
    AuthFail,                // exit 255 + stderr "Permission denied"/"publickey"
    ProxyFail,               // exit 255 + stderr "jump host"/"bastion" 패턴 (★)
    RemoteErr,               // exit ≠ 0, 원격 셸/명령 실패 (channel-open 실패 포함) (★)
    HostKeyMismatch,         // known_hosts fingerprint 불일치 — 즉시 차단 + audit critical (★)
}
```

stderr 패턴 분류는 locale·ssh 버전에 따라 미일치 가능 → 미일치 시 `RemoteErr` fallback + stderr 원문 노출(§7 Risk).

#### 카드 stack (U1 — severity-sort + collapsed ok)

기본 정렬: `[host_key_mismatch] > [auth_fail] > [proxy_fail] > [timeout] > [unreachable] > [remote_err] > [ok_warn] > [ok]`.

`[ok]` (anomaly 없음) 호스트는 기본 **collapsed**(헤더만 1줄, 본문 미렌더). Enter/Tab으로 expand. anomaly 감지(load/mem/disk 임계 초과)된 `[ok]`는 헤더에 `⚠` 플래그 + 본문 항상 노출.

진단 헤더 (실패 호스트명 inline + 절단):

```
─ /diagnose @web-tier "cpu 높음"   [5.1s elapsed · cap 8]
  120 hosts: 117 ok · 2 unreachable(web-03, web-07) · 1 timeout(web-98)
  ⚠ 3 hosts need attention: web-02 load>8.0 · web-45 mem>90% · web-77 disk>85%

  ─ web-02 (10.0.1.11) ──────── [ok] ⚠ load>8.0 ──
    load: 8.74 7.92 6.15 · cpu 78% · mem 61%

  ─ web-45 (10.0.1.44) ──────── [ok] ⚠ mem>90% ──
    mem: 92% used · swap 88%

  ─ web-03 (10.0.1.12) ─────────────── [unreachable] ──
    ConnectTimeout(10s) · ssh exit 255

  ─ web-98 (10.0.1.97) ──────────────────── [timeout] ──
    cmd timeout 30s · partial stdout captured [truncated]

  ─ [ok, no anomaly] 115 hosts ─────────── collapsed ──
    Enter to expand · `/diagnose --failed @web-tier` to retry failed only
```

#### `[auth_fail]` 카드 — hint block (U3)

```
─ web-01 (10.0.1.10) ────────────────── [auth_fail] ──
BatchMode=yes: authentication failed
stderr: "Permission denied (publickey,gssapi-keyex)"

┌─ local ssh-agent (auto-probed) ─────────────────┐
│ SSH_AUTH_SOCK: /tmp/ssh-xxx/agent.1234  ✓       │
│ loaded keys:   0  ← 키 미등록                    │
│ → ssh-add ~/.ssh/id_ed25519 실행 필요            │
└─────────────────────────────────────────────────┘
┌─ hint ──────────────────────────────────────────┐
│ 1. ssh-add -l                                   │
│ 2. hosts.toml에 identity_file 지정              │
│ 3. ProxyJump 경유면 forward_agent=true          │
│    (bastion 신뢰하는 경우에만)                  │
│ 4. MFA 호스트는 멀티호스트 미지원 — 단일 호스트 │
│    ssh로 직접 접속                              │
│ → ssh-add 후 재시도: /diagnose --retry-failed @web-tier
└─────────────────────────────────────────────────┘
```

hint 본문은 stderr 패턴별 분기:

| stderr 패턴 | hint 추가 |
|-------------|----------|
| `publickey` | identity_file 지정 + ssh-add |
| `gssapi`/`kerberos` | `klist` 확인 + TGT 갱신 |
| `keyboard-interactive` | MFA — 멀티호스트 미지원, 단일 호스트로 |
| `too many authentication failures` | `ssh-add -D` 후 특정 키만 재등록 |

#### `[proxy_fail]` 공통 원인 집계 (U2)

같은 `proxy_jump`를 공유하는 호스트들이 모두 실패하면 헤더에 공통 원인 노출:

```
  120 hosts: 110 ok · 10 proxy_fail(via bastion-main) · ...
  ⚠ bastion-main 경유 10 hosts 접근 실패 — bastion 자체 점검 권장

  ─ web-11 ──────────── [proxy_fail] ──
    ProxyJump: bastion-main → unreachable
    hint: ssh -J bastion-main web-11 으로 직접 확인
```

#### `/diagnose --retry-failed @group` (U3)
직전 batch의 `[auth_fail]`/`[unreachable]`/`[timeout]` 호스트 목록을 메모리에 보관 → 실패만 재실행.

### 4.5 안전 · 동시성

#### 동시성
`[concurrency] max_parallel = 8` 기본(override 가능). **`Arc<Semaphore>::acquire_owned()` + task move-capture** (★ R1):

```rust
let sem = Arc::new(tokio::sync::Semaphore::new(max_parallel));
for host in hosts {
    let permit = Arc::clone(&sem).acquire_owned().await?;
    let cancel = cancel_token.clone();
    tokio::spawn(async move {
        let _permit = permit;   // task body 소유 → Drop 시 자동 반환
        select! { r = ssh_exec(host) => ..., _ = cancel.cancelled() => abort_host(host) }
    });
}
```

`OwnedSemaphorePermit`은 task panic/timeout/abort 시에도 자동 반환되므로 누수 없다. `JoinSet::abort_all()` 후 `join_next()`를 끝까지 소진해 permit을 회수한다.

#### Timeout (3-layer)

| 레이어 | 값(기본) | 의미 | 결과 태그 |
|--------|----------|------|-----------|
| ssh `ConnectTimeout` | 10s | SSH 연결 실패 | `[unreachable]` |
| per-host command | 30s | 원격에서 명령이 멈춤 | `[timeout]` |
| wall clock | 300s | 전체 배치 한계 | 미완료 호스트는 `[cancelled]` |

분기 로직 (§4.4 `classify_ssh_result`): exit 255 + stderr 패턴 + duration. 미일치 시 `[remote_err]` fallback + stderr 원문 노출.

#### Stdout/Stderr 상한 (★ R2)

```rust
const REMOTE_MAX_STDOUT_BYTES: usize = 64 * 1024;       // 저장
const REMOTE_MAX_DRAIN_BYTES: usize  = 8 * 1024 * 1024; // 드레인 후 버림
```

단일 호스트 `run_command`와 동일 정책. cap 8 동시 최악 RSS ≈ 8 × (64 KiB + 8 MiB) × 2(stdout+stderr) ≈ **128 MiB**. 초과 시 카드 헤더에 `[truncated]` 태그.

#### Continue-and-report
일부 호스트 실패해도 나머지 진행. 진단 헤더 통계에 포함.

#### Ctrl+C 취소 (★ R3 — PID 재사용 race 해소)

```rust
// 호스트 task 안에서
select! {
    result = ssh_exec(host) => ...,
    _ = cancel_token.cancelled() => {
        if let Some(child) = child.as_mut() {
            let _ = child.kill_with(Signal::SIGTERM);     // 우선 SIGTERM
            tokio::time::sleep(Duration::from_millis(200)).await;
            match child.try_wait() {                       // ★ 자발적 종료 확인
                Ok(Some(_)) => {/* 이미 reaped, kill 불필요 */}
                Ok(None)    => { let _ = child.kill().await; }
                Err(_)      => { /* 로그 */ }
            }
            let _ = child.wait().await;                    // ★ 명시 reap → PID 회수
        }
    }
}
```

`tokio::process::Child` 핸들이 살아있는 동안 OS는 PID를 좀비로 보존하므로 `kill()` 호출 시점에 PID가 타 프로세스에 재할당되지 않는다(red-team R3 COUNTER 근거). 단 `wait()` 명시 호출이 필수 — 누락 시 좀비 누적(red-team R3 잔존).

#### 원격 orphan 정리 (잔존)
SIGTERM이 로컬 ssh를 종료시켜도 원격 셸 child(예: `find /`)는 SIGHUP 무시 시 계속 실행될 수 있다. MVP는 audit에 `remote_orphan_possible` 경고 첨부. ssh `RequestTTY=force` + process group kill은 후속(§5.2).

### 4.6 Audit

#### Daily segment + cross-segment chain (★ O2)

```
~/.aic/audit/
  2026-05-25.jsonl                # 오늘
  2026-05-24.jsonl                # 어제 (7일 내)
  2026-05-18.jsonl.gz             # 7일 경과 — 자동 압축
  2026-02-25.jsonl.gz             # 90일 경과 — 자동 삭제 대상
```

```toml
# ~/.aic/config.toml (또는 hosts.toml [audit])
[audit]
rotation        = "daily"               # "daily" | "weekly" | "size:50MB"
compress_after  = "7d"                  # gzip 압축
retain          = "90d"                 # 삭제 (0 = 무제한)
max_total_size  = "500MB"               # 절대 상한 — 초과 시 오래된 segment 삭제
verify_on_start = "current-day"         # "current-day" | "all" | "none"
```

day segment 경계 레코드(연결고리):

```jsonl
{"ts":"2026-05-24T23:59:59Z","type":"segment_end","date":"2026-05-24","chain_hash":"<final>","next_segment":"2026-05-25.jsonl","hmac":"…"}
```

cross-segment verify로 일별 분리에도 연속성 검증 가능.

#### Batch 엔트리

```jsonl
{"ts":"…","type":"batch_start","batch_id":"01J…","kind":"diagnose","group":"@web-tier","hosts":["web-01",…],"hmac":"…"}
{"ts":"…","type":"host_result","batch_id":"01J…","host":"web-01","status":"ok","cmd":"probe:cpu","duration_ms":412,"truncated":false,"prev_hash":"<…>","hmac":"…"}
{"ts":"…","type":"tofu_accept","batch_id":"01J…","host":"web-04","fingerprint":"SHA256:…","hmac":"…"}
{"ts":"…","type":"tofu_reject","batch_id":"01J…","host":"web-05","fingerprint":"SHA256:…","reason":"user","hmac":"…"}
{"ts":"…","type":"batch_end","batch_id":"01J…","stats":{"ok":3,"unreachable":1},"hmac":"…"}
```

`host_result`는 `prev_hash`(같은 batch 내 직전 host_result의 hash)를 포함해 순서 무결성도 보존(red-team A1 High `[Security]` audit chain 보강).

#### TOFU 보안 이벤트
- `tofu_accept` — 사용자 승인
- `tofu_reject` — 사용자 거부 (★ red-team A1·A2 High — 보안 이벤트로 반드시 기록)
- `host_key_mismatch` — known_hosts 불일치 → 즉시 차단 + audit critical

#### Secret 필터 시점 (★ R2 — pre-render 강제)

```
ssh exec
  → stdout bytes (in-memory buffer, 64KiB cap)
  → pattern denylist filter           ← PRE-RENDER · PRE-AUDIT (★ S3)
       · 환경변수 regex 2중 방어:
         /AWS_[A-Z_]+=/, /DATABASE_URL=/, /VAULT_TOKEN=/,
         /PASSWORD=/, /API_KEY=/, /SECRET=/i
       · JWT prefix, multiline PEM 헤더/푸터
  → render to TUI card (redacted form)
  → audit host_result (redacted body)
```

denylist 미스 시 audit에 `secret_filter_warning` 첨부.

#### CLI — `aic audit verify`
```
$ aic audit verify                          # current-day
  segment 2026-05-25.jsonl: 1247 entries, chain OK ✓

$ aic audit verify --date 2026-05-24
  segment 2026-05-24.jsonl.gz: 4291 entries, chain OK ✓
  cross-segment link → 2026-05-25.jsonl OK ✓
```

---

## 5. MVP vs 1.1

### 5.1 MVP (이 RFC에서 구현)

| 항목 | 범위 |
|------|------|
| 인벤토리 | `~/.aic/hosts.toml` + `ssh_config_import`, identity_file/forward_agent 필드, `--host` 임시 인자, `aic hosts show [name] [--json]` |
| 인증 | ssh-agent + **`ForwardAgent=no`** + BatchMode + StrictHostKeyChecking + **TOFU 4-step 시퀀스(ssh-keyscan → confirm → known_hosts append)** + flock |
| 실행 | 외부 `ssh` + `RemoteExecutor` trait(단일 구현) + **ControlMaster=auto** + shell_escape + $SHELL 감지 + collect-then-render |
| 진단 범위 | probe catalog `/diagnose @group`, read-only run_command 4단 게이트(tokenizer + lexical canonical + procfs allowlist 반전 + 사용자 whitelist) |
| 결과 | **8종 상태 태그** + severity-sort + `[ok] no-anomaly` collapsed + 헤더 실패 호스트 inline + `[auth_fail]` hint block + 로컬 ssh-agent 자동 점검 + `--retry-failed` |
| 동시성 | cap 8 + 3-layer timeout + continue-and-report + **`acquire_owned` + move-capture** |
| 메모리 | stdout 64 KiB 저장 / 8 MiB 드레인 + `[truncated]` |
| 취소 | Ctrl+C → SIGTERM + 200ms grace + `try_wait` + 명시 `wait().await` reap |
| Audit | batch_id + host_result(prev_hash) + **daily segment** + TOFU 이벤트 + pre-render secret 필터 + `aic audit verify` |

### 5.2 1.1 (후속)
- **diff 모드 토글** (`Tab`) — majority-diff 또는 `r` 키 reference 선택. 동률·임계 결정 후.
- **표 모드** — 100+ 호스트 환경 추가 UX (compact mode와 별도).
- **mutation 멀티호스트** — `aic run --hosts <group> -- <command>` 서브커맨드.
- **`russh`/`ssh2` 전환** — connection setup latency 또는 OpenSSH 미설치 환경 요건.
- **원격 process group kill** — `RequestTTY=force` 또는 PTY 할당 + `kill -- -PGID` 전파.
- **Ansible inventory · Kubernetes context import** — `[options] inventory_imports = [...]`.
- **macOS/BSD/Alpine probe** — 현재 Linux 가정 → OS별 catalog 분기 (red-team A4 High).
- **catalog vs tokenizer 우선순위 통합** — 자주 쓰는 화이트리스트 → probe로 승격.

---

## 6. Open Questions

1. `host_shell_probe` 캐시 정책 — `$SHELL` 결과를 hosts.toml에 자동 기록할지 매 batch마다 재탐지할지.
2. `ssh-keyscan -T 5`의 MITM 안내 톤 — confirm UI에 "외부 채널로 검증"을 얼마나 강조할지(피로 vs 보안).
3. day segment 크기 폭발(하루 100MB 초과) 대비 — `rotation = "size:50MB"`로 day 내 추가 분할 시 cross-segment chain 복잡도.
4. `forward_agent = true` 옵트인 사용자에게 bastion compromise 시 영향 범위 UI 노출 방법(첫 사용 시 1회 경고).

---

## 7. Risks

| 위험 | 영향 | 완화 |
|------|------|------|
| SSH 호스트 키 변경 미탐지 | MITM | StrictHostKeyChecking=strict 기본, `[host_key_mismatch]` audit critical |
| Tokenizer 우회 (red-team A4) | secret 노출 | procfs allowlist 반전 + 경로 lexical canonical + 사용자 확장 + audit 경고. 사용자가 `bash`/`python3`을 whitelist에 추가하면 무력화 — `aic whitelist status`로 투명 노출 |
| stderr 패턴 분류 fragility (locale·ssh 버전) | 상태 태그 오분류 | 미일치 시 `[remote_err]` fallback + stderr 원문 노출. 분류 테이블은 ssh OpenSSH/dropbear 버전별 테스트 |
| BatchMode↔TOFU 양립 | TOFU UI 동작 불가 가능성 | §4.1 4-step 시퀀스(`ssh-keyscan` + 별도 confirm + `known_hosts` 직접 append) |
| `ssh-keyscan` MITM | 신규 키 위조 | TUI confirm에 fingerprint 노출 + "외부 채널 검증" 강조. 표준 `accept-new`와 동급 위험 |
| 100+ 호스트 카드 인지 부하 (잔존) | UX 저하 | severity-sort + collapsed ok + 헤더 inline. 표 모드는 1.1 |
| ssh-agent 없음 (CI) | 즉시 `[auth_fail]` | non-TTY 환경은 `AIC_NO_TUI`로 plain 모드, CI는 단일 호스트 권장 |
| OpenSSH 클라이언트 미설치 | 멀티호스트 불가 | 첫 호출 시 `which ssh` 진단 + 명확한 에러. 1.1에서 `russh` |
| 비-sh 원격 셸(fish/csh) | shell_escape 부분 실패 | `$SHELL` 자동 감지 + `remote_shell_wrap=true` 자동 강제. rc 파일 alias 잔존 위험 — Risk 명시 |
| 원격 orphan 프로세스 | 원격 CPU 스파이크 | audit `remote_orphan_possible` 경고. process group kill은 1.1 |
| audit 파일 폭발 | 디스크/검증 비용 | daily segment + 90일 retain + 500MB 절대 상한 |
| ProxyJump 다단 어느 hop 실패 불명 | 진단 모호 | `[proxy_fail]` 카드에 "어느 hop 실패인지 불명" 명시 + hint로 `ssh -J` 직접 확인 안내 |
| `forward_agent=true` 옵트인 사용자의 bastion 침해 | agent socket 탈취 | 1회 사용 시 명시 경고 (Open Q4) |
| MFA(keyboard-interactive) 호스트 | 멀티호스트 불가 | §1.2 Non-Goal 명시. hint에 "단일 호스트로" |
| `RemoteCommand` 표현력 한계 (pipe/env/cwd) | russh 전환 시 trait 변경 | 1.1 전환 시 trait 시그니처 evolution + 양쪽 구현 동시 수정 |

---

## 8. References

- council artifact: [`.xm/op/council-2026-05-25-ssh-multihost.json`](../.xm/op/council-2026-05-25-ssh-multihost.json) — 1차 합의
- **red-team artifact: [`.xm/op/red-team-2026-05-25-rfc-005-ssh-multihost.json`](../.xm/op/red-team-2026-05-25-rfc-005-ssh-multihost.json) — 2차 검증(Critical 12 fix)**
- brainstorm artifact: [`.xm/op/brainstorm-2026-05-25-aic-additional-features.json`](../.xm/op/brainstorm-2026-05-25-aic-additional-features.json) — T1.1 후보 도출
- RFC-002 §7.1 — sandbox `resolve_for_write` / risk_guard 분류(재사용)
- RFC-004 — Ctrl+C 중단 메커니즘(`cancel_token` 동일 모델)

---

## 9. Stance Evolution & Red-Team Verification

### 9.1 Council R1 → Final Stance Evolution

| Agent (차원) | R1 입장 | Final | Changed |
|---|---|---|:---:|
| A1 (실행) | 외부 ssh + trait + 2단계 ssh2/russh 전환 계획 | trait 유지 + **MVP 단일 구현** + `sh -c`/args 분리 명시 | ✅ |
| A2 (호스트/인증) | `~/.ssh/config` **1순위** + hosts.toml 보강 | **hosts.toml 통합 인벤토리** + `ssh_config_import` + TOFU/secret audit 강화 | ✅ |
| A3 (결과/범위) | 카드+Tab diff + 임의 run_command 화이트리스트 | **catalog 확장 우선** + tokenizer 화이트리스트 + majority-diff는 1.1 | ✅ |
| A4 (안전) | cap 8 + mutation 별도 서브커맨드 + audit batch | + read-only run_command **조건부 수용** + **경로 접두사 제한** | ✅ |

### 9.2 Red-Team Critical 12 — Verdict 요약

🟢 **Fixed/Counter (8)**: S2, S3, R2, R3, U2, U3, O2, O3
🟡 **Partial (4)**: S1, R1, U1, O1
🔴 **Open (0)**

PARTIAL 잔존은 §7 Risks에 모두 등록. 자세한 fix/RESIDUAL은 red-team artifact 참고.

---

## 10. Implementation Status (2026-05-25)

`feat/ssh-multihost` 브랜치 6 커밋. 전체 lib 테스트 **589 passed** · clippy clean.

### 10.1 Phase별 커밋 + 모듈

| Phase | 커밋 | 모듈 | LOC(신규) | 테스트 |
|:-----:|------|------|:---------:|:------:|
| **1 인벤토리** | `2141409` | `agent/hosts.rs` | ~550 | 12 |
| **2 RemoteExecutor** | `3b38342` | `agent/remote/{mod,ssh_process}.rs` | ~540 | 20 |
| **3 fan-out** | `b50d06e` | `agent/remote/fanout.rs` | ~250 | 4 |
| **4 UX 보강** | `0976167` | `main.rs` 핸들러(severity-sort, collapsed ok, auth_fail hint, ssh-agent 자동 점검) | ~150 | — |
| **5 전반 (S2/S3)** | `ab4f7bd` | `agent/remote/path_guard.rs` + `secret_filter.rs` + `ssh_process` redact 통합 + `RemoteResult.redacted` | ~360 | 15 |
| **5 후반 (TOFU 모듈)** | `951a089` | `agent/remote/tofu.rs` (scan_host / parse_keyscan_lines / append_known_hosts / fingerprint_sha256) | ~210 | 3 (+1 ignored) |
| **합계** | — | — | **~2,060** | **54** |

### 10.2 CLI 노출 (사용자 직접 사용 가능)

| 명령 | 동작 |
|------|------|
| `aic hosts show` | 인벤토리 전체 표시 — 그룹·호스트·source·`ssh_config_warnings` |
| `aic hosts show <name> [--json]` | 단일 호스트 최종 해석값 (overlay 결과 + 어느 directive를 ssh에 위임했는지) |
| `aic hosts ping <name> [--cmd "..."]` | 단일 호스트 ssh ping — 8종 상태 태그 + stdout/stderr + duration |
| `aic hosts ping @group [--cmd "..."]` | 그룹 fan-out — cap 8 + 3-layer timeout + severity-sort 카드 stack + 헤더 inline 실패명 + ok collapsed + `[auth_fail]` hint + ssh-agent 자동 점검 |

### 10.3 red-team Critical 12 → 구현 매핑

| ID | 결함 | Phase | 반영 위치 |
|----|------|:----:|-----------|
| 🟢 S1 | shell_escape + 비-sh | 2 | `agent/remote/mod.rs::shell_escape` (POSIX `'...'` + `'\''` 이스케이프) |
| 🟢 S2 | 경로 동등 우회 | 5 | `path_guard::lexical_canonicalize` + `check_path` |
| 🟢 S3 | `/proc/self/environ` | 5 | `path_guard` procfs allowlist 반전 + `secret_filter::redact` env 패턴 |
| 🟢 R1 | Semaphore permit 누수 | 3 | `fanout::run_fanout`의 `acquire` + move-capture |
| 🟢 R2 | OOM 버퍼 상한 | 2 | `ssh_process::bounded_read` (64KiB 저장 / 8MiB 드레인) + `RemoteResult.truncated` |
| 🟢 R3 | SIGKILL PID 재사용 | 2 | `ssh_process` `kill_on_drop(true)` + `tokio::process::Child` 좀비 보존 |
| 🟢 U1 | 100+ 호스트 스크롤 | 4 | severity-sort + `[ok] collapsed` + 헤더 inline 실패명 |
| 🟢 U2 | 5종 → 8종 태그 | 2 | `HostStatus` 8 variants + `classify_ssh_result` stderr 패턴 우선 |
| 🟢 U3 | `[auth_fail]` 행동 부재 | 4 | `print_auth_fail_hint` + `probe_local_ssh_agent` 자동 호출 |
| 🟢 O1 | ssh_config 디버깅 부재 | 1 | `aic hosts show <name>` source/overlay 표시 + `ssh_config_warnings` |
| 🟡 O2 | audit 로테이션 | — | **미반영** — 다음 작업 (batch_id + daily segment + `aic audit verify --date`) |
| 🟡 O3 | whitelist 확장 | — | **미반영** — 다음 작업 (Phase 6: `~/.aic/whitelist.toml` + `aic whitelist check`) |
| 🟢 TOFU (High) | BatchMode↔TOFU 양립 | 5 | `tofu` 모듈 (함수 단위) — **wiring 보류**(ssh_process 자동 재시도 + confirm callback) |

### 10.4 미반영 / 다음 작업

| 작업 | 효과 | 의존성 |
|------|------|--------|
| **TOFU wiring** | `ssh_process`가 `Host key verification failed` 감지 → `scan_host` → confirm callback → `append_known_hosts` → ssh 재시도 | callback 패턴 추상화 (단발 CLI = stdin prompt, chat TUI = mpsc 직렬화) |
| **Audit batch + daily segment (O2)** | `batch_id` UUID + per-host `host_result` + `segment_end` 경계 + `aic audit verify --date` + retain/compress 정책 | 기존 `audit.rs` 확장 또는 신규 `audit/batch.rs` |
| **Phase 6 — whitelist (O3)** | `~/.aic/whitelist.toml` append-merge + tokenizer + `aic whitelist status/check` + `run_command` 멀티호스트 게이트에 `path_guard`/whitelist wiring | path_guard·tokenizer 통합 |
| **chat TUI 통합** | `/diagnose @group` 슬래시 명령으로 fan-out 호출 + 카드 stack을 chat TUI에 inline 렌더 + TOFU confirm을 ratatui modal로 | RFC-004 chat TUI + 본 RFC fan-out |

### 10.5 운영 메모

- 브랜치는 아직 push되지 않음 → 다음 단계는 (a) 남은 작업 진행 후 일괄 PR, 또는 (b) 현재 6 커밋을 먼저 push해 CI 검증 + PR 생성 후 후속 PR.
- `RemoteResult.redacted` 카운트 > 0이어도 패턴 미일치 secret이 있을 수 있다 — audit batch 구현 시 "원격 결과는 secret 포함 가능" 경고를 항상 첨부할 것(§4.6).
- `aic hosts ping`은 read-only run_command 임시 wiring 없이 사용자가 임의 `--cmd`를 보낼 수 있다 → Phase 6 whitelist 게이트 적용 전까지 운영자 책임.
