# Changelog

[Keep a Changelog](https://keepachangelog.com/) 형식. 모든 항목은 사용자가 직접 체감 가능한 변화 기준.

## [Unreleased]

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
