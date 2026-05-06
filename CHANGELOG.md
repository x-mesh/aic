# Changelog

[Keep a Changelog](https://keepachangelog.com/) 형식. 모든 항목은 사용자가 직접 체감 가능한 변화 기준.

## [Unreleased]

## [0.4.0] - 2026-05-06

### Added — `aic update` 셀프업데이터 + `install.sh`

배포 경로가 brew 한 줄, source 빌드 두세 단계, 그리고 (지금까지) 모자란
manual install 경로로 흩어져 있어 신규 사용자 진입과 기존 사용자 갱신이
모두 번거로웠다. `x-mesh/gk`의 패턴을 그대로 차용해 정리.

- **`install.sh`** (POSIX sh) — `curl … | sh` 한 줄로 OS/arch
  (`linux`/`darwin` × `amd64`/`arm64`) 감지 → release archive +
  `checksums.txt` 다운 → SHA-256 검증 → `aic`/`aic-session`/`aicd`
  세 binary를 `/usr/local/bin`(권한 없으면 sudo) 또는 `~/.local/bin`에
  설치. `AIC_VERSION` / `AIC_INSTALL_DIR`로 핀/경로 override.
- **`aic update`** — `current_exe()` 경로로 설치 출처를 분류:
  - Brew(`/opt/homebrew`, `/usr/local/Cellar`, linuxbrew) →
    `brew upgrade x-mesh/tap/aic`로 위임.
  - Manual(`install.sh` 결과) → GitHub `releases/latest`의 tag을 받아
    archive 다운 + sha256 검증 + flate2/tar로 추출 → 세 binary를
    원자적으로 교체. 디렉토리 권한이 없으면 `sudo install`로 fallback.
    같은 디렉토리에 사이드카 binary가 없으면 그 항목만 skip하고
    경고 출력.
  - Cargo(`~/.cargo/bin`) → 자동 교체 거부, `cargo install --git ...`
    안내.
- **옵션** — `--check`(버전만 비교, 신버전이면 exit 1), `--force`,
  `--to <TAG>`(특정 tag 고정).
- **버전 비교** — semver(major.minor.patch) 기반, `v` prefix와 `-rc1`
  류 suffix는 무시. `dev` 같은 비-숫자 버전은 항상 "구버전"으로
  간주해 강제 재설치 없이도 update 가능 안내.
- **신규 의존성** — `flate2 = "1"`, `tar = "0.4"` (release archive
  추출용).

### Added — aicd 30s 주기 stale 세션 reconcile 루프

이전에는 `mark_stale_active_detached`가 `ListSessions`/`PruneSessions`
요청 처리 시점에만 돌아서, 외부 호출이 없으면 비정상 종료된 active
세션이 detached로 수렴하지 않았다.

- **`control_server::RECONCILE_INTERVAL`**(30s) 상수 +
  `pub fn spawn_reconcile_loop(ctx) -> JoinHandle<()>`. `tokio::time::
  interval` + `MissedTickBehavior::Skip`. 첫 즉시 tick은 건너뛰고
  한 주기 뒤부터 reconcile 시작.
- **`aicd_main`**: `ControlContext`를 변수로 묶어 `clone()`으로 백그라운드
  태스크 spawn, `serve()`가 shutdown으로 반환되면 `JoinHandle::abort()`.
  `Notify` 경합 없이 `serve()`만 shutdown 신호를 기다림.
- **idle 비용 0** — `mark_stale_active_detached`가 변경분 0이면
  `persist_registry`를 호출하지 않으므로 디스크 I/O 없음. STALE 후보가
  생긴 주기에서만 snapshot이 갱신된다.
- **주기 = STALE_ACTIVE_AFTER 동일** — active → detached 전환이 한
  주기 안에 잡히도록 의도적으로 같은 값.

### Docs

- **README.md / README.ko.md** — 원라이너 installer 섹션 + `aic update`
  서브커맨드 사용 가이드 추가. 한국어 README는 톤도 함께 다듬어 LLM
  분석/REPL 분기 설명 문구를 자연스럽게 정리.

### Tests

- aic-client `update` 모듈 9개 단위 테스트 — semver 비교, brew/manual/
  cargo 분류, asset 이름 템플릿(`aic_<ver>_<os>_<arch>.tar.gz`),
  archive 화이트리스트 추출(BINARIES 외 항목 무시), writable probe.
- 전 워크스페이스 테스트 통과(failed = 0), `cargo clippy --workspace
  -- -D warnings` 깨끗.

## [0.2.1] - 2026-04-30

### Added — Groq Cloud provider 정식 지원

- **`ProviderType::Groq` enum variant 추가** (aic-common). OpenAI 호환 API path를
  재사용하지만, `provider_type = "Groq"`로 지정하면 `endpoint`/`model`을 비워둬도
  `https://api.groq.com/openai/v1/chat/completions` + `llama-3.3-70b-versatile`
  기본값이 자동 적용된다. 기존 `OpenAiCompatible`로 endpoint를 직접 지정하던
  설정도 그대로 동작.
- **`aic config` wizard에 Groq 항목** — API key 입력 후 모델 선택
  (`llama-3.1-8b-instant` / `llama-3.3-70b-versatile` /
  `deepseek-r1-distill-llama-70b` / `gemma2-9b-it`).
- **`aic doctor`** — Groq variant도 OpenAI 호환과 동일한 검증 path를 탄다
  (api_key 존재, endpoint reachability, keychain 접근).
- **Streaming 지원** — Groq도 OpenAI-compat SSE를 사용하므로 TTY 환경에서
  자동 streaming.
- **`--dry-run` cost 추정** — Groq 공시 단가($/1M tokens) 매핑 추가.

### Added — `aicd` supervisor daemon (Phase 0~2.1)

PRD-AICD-SUPERVISOR의 control plane 부분. PTY ownership은 그대로 두고
사용자당 하나의 supervisor daemon으로 lifecycle/registry/cleanup을 중앙화.

- **`aicd` binary** (aic-server에 추가) — 사용자당 1개. `aicd.pid` singleton
  lock + `aicd.sock` control UDS. SIGINT/SIGTERM graceful shutdown.
- **Session registry** — `Arc<RwLock<HashMap<String, SessionInfo>>>`,
  read-heavy 동시성 (ListSessions가 압도적). `aic-session`이 시작 시
  `RegisterSession`, 종료 시 `UnregisterSession`을 best-effort로 호출.
- **Control IPC** — `Ping`/`ListSessions`/`Shutdown`/`RegisterSession`/
  `UnregisterSession`/`StopSession`. 모든 변종은 `IpcRequest` enum에
  통합되며 잘못된 데몬으로 보내면 graceful "wrong socket" Error 반환.
- **`SessionInfo` / `SessionState`** — id / pid / state / created_at /
  attached_tty / shell / cwd. PRD §10.2와 일치하는 6-state lifecycle.
- **CLI surface**
  - `aic daemon { status | start | stop }` — supervisor 제어. start는
    `current_exe()` 옆의 `aicd`를 우선, 없으면 PATH fallback.
  - `aic session stop <id>` — registry lookup → `SIGTERM` (PTY ownership
    이동 전까지의 bridge 구현; 프로세스 없음(ESRCH)이면 registry만 정리).
  - `aic sessions` — aicd registry-first. aicd 없으면 기존 socket scan
    fallback.
  - `aic doctor` — `aicd supervisor` 항목 추가. 실행 중이면 PASS+세션 수,
    아니면 WARN(선택사항이라 명확히 표시).

### Added — Hook capture mode (Phase 0, 3.1~3.3)

PRD-HOOK-CAPTURE-MODE의 metadata-only 캡처 옵션. PTY hook과 충돌 없이
공존 가능.

- **`CommandRecord` 확장** — `capture_mode`(Pty/Hook/ExplicitCapture),
  `capture_quality`(FullOutput/MetadataOnly/RedactedOutput/BinaryOmitted/
  TruncatedOutput/Unknown), `output_metadata`(stored bytes/lines, truncated
  flag, sha256). 모두 `#[serde(default)]` — 레거시 JSON/IPC 호환.
- **Hook event protocol** — `IpcRequest::CommandStarted` / `CommandFinished`.
  `aicd`가 per-session bounded ring(64)에 누적, command_id로 start/finish
  매칭, 매칭 실패 시 partial record(`command = None`)로 저장.
- **Hidden CLI** — `aic _hook-event { start | end }` (clap `hide=true`).
  Shell hook이 백그라운드로 호출. 100ms timeout, stderr only, aicd 미실행
  시 silent skip.
- **Shell hook installer** — `aic init --hook-mode` 시 `~/.aic/hook-events.
  {zsh,bash}` 설치 (version marker 1). zsh는 `preexec`/`precmd` +
  `add-zsh-hook`, bash는 `DEBUG trap` + `PROMPT_COMMAND`. 모든 호출은
  `(... &)`로 detach, redirect to `/dev/null` — prompt latency 영향 0.
  rc 파일에는 `# >>> aic hook-events >>>` ~ `# <<< aic hook-events <<<`
  마커로 멱등 source 라인 추가.
- **Explicit capture wrapper** — `aic run -- <cmd...>`. stdout/stderr를
  실시간 echo하면서 동시에 ring(line cap 1000, byte cap 256 KiB)에 수집.
  exit code 보존 (signal-killed는 128+sig). 결과 record는 capture_mode =
  ExplicitCapture, quality = FullOutput / TruncatedOutput.

### Added — Makefile release helpers

3개 workspace Cargo.toml의 버전을 손으로 바꾸는 부담 제거. release
워크플로우와 함께 동작.

- `make bump-version VERSION=0.3.0` — `[package]` section 안의 첫
  `version =` 줄만 awk로 교체. `[dependencies]` block의 `version`은
  안 건드린다 (`libc = "0.2"` 같은 entry 안전). cargo build로
  Cargo.lock도 자동 동기화.
- `make tag VERSION=0.3.0` — bump + commit + annotated tag(`v0.3.0`).
  버전 변경이 없으면 commit은 skip하고 tag만 생성.
- `make release-publish VERSION=0.3.0` — tag + push origin main + push
  tag. CI(GoReleaser)가 발화. origin remote가 `git@github.com:x-mesh/aic.git`을
  가리키는지 사용자가 사전에 확인.
- 0.2.0 round-trip 검증 — dependency version은 그대로 유지됨.

### Added — Release workflow (GoReleaser, gk 패턴 통일)

`v*` 태그 push 한 번으로 multi-arch binary 빌드 + GitHub Release +
`x-mesh/homebrew-tap` Formula 자동 갱신까지 처리. `x-mesh/gk`와 동일한
GoReleaser 파이프라인이라 팀 한 secret/한 멘탈 모델로 통일.

- **`.goreleaser.yaml`**:
  - 3 binary(`aic`/`aic-session`/`aicd`) × 4 target triple(linux/darwin
    × x86_64/aarch64) = 12 cross-compile job
  - `builder: rust` + `tool: cargo-zigbuild`로 ubuntu runner 단일에서
    darwin/linux 모두 cross-compile
  - 한 (os, arch)당 tar.gz 1개에 세 binary 모두 묶어 `brew install`
    한 번에 끝나게 함
  - `brews:` block이 `x-mesh/homebrew-tap/Formula/aic.rb`를 자동
    생성/갱신 — `Hardware::CPU.intel? / arm?` 분기 + url + sha256 +
    `bin.install` 3줄 + caveats(aic daemon install 안내)
- **`.github/workflows/release.yml`**:
  - `tags: ['v*']` push 또는 workflow_dispatch로 발화
  - Rust stable + 4 targets 설치 → cargo registry 캐시 → setup-zig +
    cargo-zigbuild 설치 → `goreleaser check` → `goreleaser release --clean`
  - `HOMEBREW_TAP_GITHUB_TOKEN` secret (gk와 동일 — org-level이면
    추가 등록 불필요)
- **`packaging/homebrew/aic.rb` 제거** — source-build Formula는
  GoReleaser binary path와 충돌하므로 단일 출처화 (GoReleaser가 master).
- **`RELEASING.md`** — TL;DR, secret 등록 절차(org-level 우선), 수동
  dry-run, 트러블슈팅, "왜 source-build를 안 쓰는가" 결정 기록.

이전 minimum 워크플로우(`mislav/bump-homebrew-formula-action` +
source tarball)는 GoReleaser 패턴으로 완전 교체됐다.

### Added — `aic daemon install` / `uninstall` (OS-native auto-start)

부팅 시 `aicd` 자동 시작을 한 명령으로 양 OS 모두 처리. `brew services`는
macOS launchd만 잘 통합하고 Linux brew에선 stub이라 이 경로를 직접 둔다.

- **macOS**: `~/Library/LaunchAgents/com.x-mesh.aicd.plist`
  - `RunAtLoad=true`, `KeepAlive=true`, `ProcessType=Background`
  - stdout/stderr → `~/.local/state/aic/aicd.{out,err}.log`
  - `launchctl bootstrap gui/$UID <plist>` (modern), 실패 시 `launchctl load`
    fallback. uninstall은 `bootout`/`unload` 둘 다 시도.
- **Linux**: `~/.config/systemd/user/aicd.service` (또는 `$XDG_CONFIG_HOME`)
  - `Type=simple`, `Restart=on-failure`, `WantedBy=default.target`
  - `systemctl --user daemon-reload && enable --now aicd.service`. uninstall은
    `disable --now` + `daemon-reload`.
- **공통**: `--no-load`로 파일만 쓰고 OS 호출은 건너뛸 수 있음 (CI / 시스템
  영향 없는 dry-run). 멱등 — 같은 내용이면 mtime 보존을 위해 write도 skip.
  Unit 내용이 바뀌면 자동 재작성.
- **`aic daemon status`** 가 unit 설치 상태도 함께 표시
  (`autostart: installed (unit: ...)` 또는 `not installed (run: aic daemon install)`).
- **`aicd` 경로 결정**: `current_exe()` 옆의 `aicd`를 우선 사용 (brew/cargo
  install 모두 같은 디렉토리에 둠). 없으면 PATH fallback.

테스트:
- `daemon_install::tests` 5개 — plist/unit 렌더링, OS 감지,
  `XDG_CONFIG_HOME` 존중, plist 경로 형식. OS 호출은 manual smoke로 검증
  (임시 HOME으로 install/uninstall 사이클 PASS).

사용자 흐름:
```sh
brew install x-mesh/tap/aic   # 또는 source 빌드
aic daemon install            # 부팅 시 자동 시작 + 즉시 실행
aic daemon status             # ✓ running, ✓ installed
aic daemon uninstall          # 정리
```

### Fixed — CLI Backend(`kiro-cli`/`claude`) 호출 형식 수정

`send_cli`가 prompt를 첫 positional argument로 그대로 전달하는 바람에:
- `kiro-cli`는 prompt 첫 단어를 unknown subcommand로 해석 → "unrecognized
  subcommand 'ssdsd...'" 에러
- `claude` (claude-cli)는 interactive session 시작 시도 → non-interactive
  컨텍스트에서 행 또는 깨짐

해결:
- **`ProviderConfig::cli_args: Option<Vec<String>>`** 신규 필드
  (`#[serde(default)]`, 레거시 config 호환). prompt 앞에 prepend되는 인자.
- **`resolve_cli_args(cli_path, override)` helper** — 사용자 명시값이
  있으면 그대로, 없으면 `cli_path` basename에서 자동 추론:
  - `kiro-cli` / `kiro` → `["chat"]`
  - `claude` / `claude-cli` → `["-p"]`
  - 그 외 → `[]` (legacy 동작 보존)
- `send_cli`은 `<cli_path> <args...> <prompt>` 순서로 spawn.
- 모든 ProviderConfig literal site에 `cli_args: None` 마이그레이션
  (perl 일괄 + nested struct 2건 수동).
- 4개 unit test: kiro chat 자동 추론, claude -p 자동 추론, unknown CLI
  no-op, user override 우선.

사용자 측 영향:
- 기존 `cli_path = "kiro-cli"` config는 자동으로 `chat` subcommand가
  붙는다 — config 수정 불필요.
- 다른 인자가 필요한 경우 `cli_args = ["chat", "--no-color"]` 식으로
  명시 가능.

### Fixed — Anthropic 모델 ID 갱신 (HTTP 404 회귀)

옛 모델 ID(`claude-3-5-haiku-20241022`, `claude-sonnet-4-20250514` 등)가
Anthropic API에서 retire되어 호출 시 HTTP 404를 반환하던 회귀를 차단.

- `LlmDispatcher::send_anthropic` / `streaming` Anthropic path의 default
  모델을 `claude-sonnet-4-6`로 갱신 (두 곳 모두).
- `aic config` wizard의 Anthropic 모델 선택 옵션을
  `claude-sonnet-4-6` / `claude-opus-4-7` / `claude-haiku-4-5-20251001`로
  교체. 라벨도 함께 갱신.
- example `config.toml` 템플릿 (`aic config show example`) 모델 + 권장 안내
  코멘트 추가.
- `dry-run` cost 매핑(`estimate_cost_usd`)에 4.x family 단가 추가
  (sonnet 4.6 = $3/$15, opus 4.7 = $15/$75, haiku 4.5 = $1/$5; 정확한
  단가는 https://www.anthropic.com/pricing 참조).
- `aic doctor`가 retired 모델 ID 사용 시 WARN으로 안내 + fix hint 제공
  (`is_anthropic_retired_model` heuristic으로 `claude-2*`, `claude-instant*`,
  `claude-3-*`, `claude-{sonnet,opus}-4-20250514` 매칭). 새 4.x family는
  PASS.
- 통합 테스트(`aic-client/tests/llm_integration.rs`)도 새 모델 ID로 갱신.

### Added — Hybrid mode + capture quality hint (Phase 4)

- **`SessionCaptureMode`** — `Pty` / `Hook` / `Hybrid`. `[session]
  capture_mode` config. 레거시 config는 default(Pty)로 자동 채움.
- **`capture_quality_hint(record, mode)`** — FullOutput에선 무음, 그 외
  품질에서는 사용자에게 신뢰도 + 대안(`aic run -- <cmd>` 등) 안내.
  `aic` 분석 시 `print_error_context` 직후 stderr에 dim line으로 출력.

### Removed
- root의 `PRD-AICD-SUPERVISOR.md` / `PRD-HOOK-CAPTURE-MODE.md` /
  `CAPTURE-MODE-TRADEOFFS.md` — `docs/` 하위로 이동, 단일 출처화.

### Tests
- aic-common lib: 42 → 64 (capture mode/quality, hint, registry serde,
  legacy compat, hook event proptest 확장)
- aic-server lib: 56 → 95 (control_server 6, session_registry 7,
  hook_events 4, aicd_client 4 + 통합)
- aic-client lib: 130 → 162 (hook_install 3, doctor aicd, daemon CLI 등)
- 전 워크스페이스 직렬 실행: failed = 0

### Architectural Decisions
- **PTY ownership 이동(PRD-AICD-SUPERVISOR Phase 2 본 구현)은 보류** —
  raw mode 복원/relay regression 위험이 커서 별도 sprint로 분리. 현재
  `aic session stop`은 PID에 SIGTERM을 보내는 bridge 구현이며,
  `aic-session`의 기존 shutdown 핸들러가 PTY/소켓을 정리한다.
- **Control plane 분리** — `UdsServer`(RingBuffer 결합)와 별도로
  `ControlServer` 신규. aicd는 출력을 소유하지 않으므로 같은 서버를
  재사용하면 layering이 흐려진다.
- **Hook event는 외부 명령(`aic _hook-event`) 호출** — shell에서 raw UDS
  바이트 전송이 어려워 단순함을 우선. 백그라운드(`&`) detach + 100ms
  timeout으로 prompt latency 영향 방지. 향후 socket connector로 최적화 여지.
- **aicd 자동 spawn은 명시 명령에서만** — `aic daemon start` /
  `aic doctor --fix`(미구현). `aic-session`/`aic` 자동 spawn은 사용자
  의도 모호 + 권한 이슈로 보류.

---

## [0.2.0] — Pre-Phase Baseline

### Added — Subcommand
- `aic doctor [--json]` — 8축 환경 진단 (config / provider / UDS 소켓 / 데몬 / 셸 hook / LLM endpoint / keychain / audit log). FAIL 시 exit 1.
- `aic status [--watch] [--interval N]` — 데몬 PID/ping/마지막 명령어 + metrics(uptime, IPC count, RingBuffer 사용률, last cmd ago). watch 모드는 1초 polling + clear-screen.
- `aic top [--interval N]` — `aic status --watch`의 alias.
- `aic audit verify` — audit log HMAC chain 무결성 검증. Exit 0=valid, 2=tampered, 3=key/IO error.
- `aic config show [--json]` — 비-인터랙티브 설정 출력 (TOML 기본, JSON 옵션).
- `aic config get <path>` — dotted path 단일 값 추출. scalar는 raw, object는 JSON pretty.
- `aic migrate-keys` — config.toml의 평문 API key를 OS keychain으로 일괄 이동.
- `aic init <shell>` — `~/.zshrc`/`~/.bashrc`에 `source ~/.aic/hooks.{shell}` 멱등 추가 (마커 기반 롤백 가능).
- `aic --dry-run "<prompt>"` — 실제 LLM 호출 없이 토큰·비용·timeout 미리보기.
- `aic --version` / `aic-session --version`.

### Added — 보안 baseline (judge2 FAIL 보강)
- **Secret/PII redaction**: secret 5종 (anthropic key, openai key, AWS, GitHub, JWT) + Shannon entropy ≥3.0 보조 검증, PII 4종 (email, 한국 전화, 주민번호, IPv4). LLM 송신 직전 단일 stage. `AIC_REDACT=off` opt-out.
- **Audit log HMAC chain**: `~/.local/state/aic/audit.log` JSONL append-only (file 0600, dir 0700), HMAC-SHA256 line chain. 변조 시 `aic audit verify`가 정확한 라인 번호 반환. 100MB×5 rotate.
- **OS keychain**: macOS Keychain / Linux Secret Service / Windows Credential Manager. config.toml에는 `api_key = "keychain:<name>"` reference.

### Added — 가시성·진단
- **구조화 trace 로그** (aic-session): `tracing` + `tracing-subscriber` + `tracing-appender` 도입. `~/.local/state/aic/server.log` JSONL daily rotate (max 7 files). `AIC_LOG=info|debug|trace` env-filter. panic hook 자동 등록.
- **데몬 metrics**: `IpcRequest::GetMetrics` + `MetricsSnapshot` (uptime, PID, IPC request count, RB used/capacity, last command secs ago).
- **Ring Buffer 점유율**: `RingBuffer::capacity()` 메서드 추가.

### Added — 안정성
- **PID lock 단일 인스턴스**: `fcntl(F_SETLK)` advisory write lock + PID file. 이미 살아있는 인스턴스 감지 시 즉시 종료, stale lock 자동 정리.
- **Graceful shutdown**: SIGTERM/SIGINT 핸들러 — 터미널 raw mode 복원 → background task abort → 소켓 unlink → lock drop 순서.
- **Retry circuit breaker**: 60초 window 5회 실패 시 30초 fail-fast. provider별로 격리.
- **AicError::is_retryable / user_message**: HTTP 5xx/429/network=retryable, status별 친화 메시지.
- **HTTP timeout 분리**: connect 5s + request 30s (이전 단일 60s).

### Added — UX
- **LLM streaming**: OpenAI compat + TTY + `AIC_NO_STREAM` 미설정 시 자동 활성. SSE 파싱 (`eventsource-stream` 없이 직접 구현). 첫 토큰부터 incremental stdout.
- **Spinner**: 비-streaming 호출 대기 중 isatty(stderr)에만 출력. stdout 파이프 회귀 없음.
- **결과 캐시**: `~/.cache/aic/analyses/<hash>.json`. 24h TTL. 같은 (cmd, exit, output_tail) 조합은 즉시 응답 + "(캐시)" 신호.
- **i18n 자동 감지**: `lang = "auto"` 시 `$LC_ALL`/`$LANG` 추론 (ko/en/ja/zh).

### Added — Onboarding
- **셀프-힐링 워크플로우**: `aic doctor`가 다음 액션 명령(`aic init zsh`, `aic migrate-keys`)을 직접 안내.

### Fixed
- **SIGWINCH ↔ wait_for_exit Mutex 데드락** (aic-server) — `Arc<Mutex<PtyManager>>`를 `wait_handle`이 자식 셸 종료까지 영구 점유, SIGWINCH 핸들러가 lock 대기로 worker thread hang. PtyManager에 `take_child()` 추가하여 spawn 직전에 child만 take, lock 해제 후 lock 밖에서 `wait()`. macOS `sample <pid>`로 진단.
- **PTY stderr 누수** — `uds_server::serve`/`handle_client`의 `eprintln!`을 `tracing::warn`/`debug`로 변경. PTY 환경에서 server stderr가 사용자 터미널에 직접 출력되던 문제 해결.
- **Forward compatibility** — `IpcRequest` 역직렬화 실패 시 graceful `IpcResponse::Error` 응답. 옛 client + 새 server 또는 그 반대 호환.
- **redaction false positive 감소** — secret 패턴에 Shannon entropy ≥3.0 보조 검증. `ghp_aaaa...` 같은 단조 패턴은 redact 안 함.

### Added — Environment Variables
| 변수 | 효과 |
|---|---|
| `AIC_LOG=info|debug|trace` | aic-session tracing 레벨 (기본 info) |
| `AIC_REDACT=off` | secret/PII redaction 비활성 (audit `redact_bypassed` 기록) |
| `AIC_NO_STREAM=1` | streaming 비활성 (spinner + sectional 출력) |
| `AIC_DEBUG=1` | client `[debug +X.XXXs]` prefix 출력 |

### Dependencies (신규, 모두 MIT/Apache/ISC)
- aic-server: `tracing`, `tracing-subscriber`, `tracing-appender`
- aic-client: `regex`, `sha2`, `hmac`, `keyring`

### Tests
- aic-client lib: 130 tests (이전 76 → +54)
- aic-server lib: 56 tests (이전 44 → +12)
- aic-common lib: 42 tests
- **합계 228/228 통과**, `cargo clippy --workspace --all-targets -- -D warnings` ✅ 깨끗.

### Architectural Decisions
- **launchd/systemd unit**: PTY-wrapping 모델은 사용자 터미널에 stdin/stdout 종속이라 background autostart 부적합. 보류, RFC 후 재검토.
- **네임스페이스 멀티 소켓**: PID lock 단일 인스턴스 보장으로 stale 충돌 자체가 막힘. 별도 항목 불필요.
- **OSC 8 hyperlink**: URL handler 등록 비용 모호. 가치 재평가 후 진행.

---

## [0.1.0] — initial

기본 기능 (PTY 셸 wrapping, OSC 133 명령어 경계, exit_code 분기, 다중 LLM provider, REPL 모드, TUI 호환).
