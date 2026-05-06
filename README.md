# aic

> CLI tool that analyzes shell command errors via LLM and suggests fixes

[![CI](https://github.com/x-mesh/aic/actions/workflows/ci.yml/badge.svg)](https://github.com/x-mesh/aic/actions/workflows/ci.yml)

**Languages:** English · [한국어](./README.ko.md)

## Overview

`aic` feeds your terminal's error output to an LLM, which explains what went wrong and suggests a fix command.

Under the hood, a PTY-based daemon (`aic-session`) wraps your shell, relaying I/O while capturing output into a ring buffer. The CLI client (`aic`) checks the previous command's exit code and branches into error-analysis mode or an interactive REPL.

A per-user supervisor daemon (`aicd`) manages session lifecycle, registry, and cleanup. For workflows where PTY wrapping is too expensive, a metadata-only **hook capture mode** skips output capture entirely (PRDs: [docs/PRD-AICD-SUPERVISOR.md](./docs/PRD-AICD-SUPERVISOR.md), [docs/PRD-HOOK-CAPTURE-MODE.md](./docs/PRD-HOOK-CAPTURE-MODE.md)).

```mermaid
graph LR
    User[User Terminal] --> Session[aic-session]
    Session -->|PTY relay| Shell[Shell zsh/bash]
    Session -->|capture output| RB[Ring Buffer]
    Session -.register/unregister.-> AICD[aicd supervisor]
    Hook[shell hook] -.metadata only.-> AICD
    Client[aic] -->|UDS| Session
    Client -->|control UDS| AICD
    Client -->|error analysis| LLM[LLM Provider]
```

## Features

### Core
- ✅ PTY shell wrapper — captures output without changing your workflow
- ✅ Command boundary detection — OSC 133 markers + timing-heuristic fallback
- ✅ Automatic error analysis — when exit code ≠ 0, the LLM explains the cause and suggests fixes
- ✅ Interactive REPL — when exit code = 0, freeform chat with the LLM
- ✅ Multiple LLM providers — OpenAI-compatible, Groq, Anthropic, CLI Backend (kiro-cli, claude-cli)
- ✅ TUI compatibility — alternate-screen-buffer detection keeps vim, htop, etc. working correctly
- ✅ Cross-platform — macOS (Apple Silicon, x86_64), Linux (x86_64, aarch64)

### Reliability & Diagnostics
- ✅ Single-instance guarantee — `fcntl(F_SETLK)` PID lock with automatic stale cleanup
- ✅ Graceful shutdown — SIGTERM/SIGINT handling, drain then cleanup
- ✅ Structured trace logs — JSONL daily-rotate (7-day retention), `AIC_LOG=info|debug`
- ✅ `aic doctor` — 8-axis environment diagnosis (config / daemon / shell hook / LLM endpoint / keychain / audit)
- ✅ `aic status` — daemon PID / ping / last command, one-shot output

### Security baseline
- ✅ Secret/PII redaction — automatic masking for 5 secret types (AWS / GitHub / OpenAI / Anthropic / JWT) and 4 PII types (email / KR phone / KR resident number / IPv4); opt-out via `AIC_REDACT=off`
- ✅ Audit log HMAC chain — `~/.local/state/aic/audit.log` JSONL append-only, integrity verification via `aic audit verify`
- ✅ OS keychain — store API keys in macOS Keychain / Linux Secret Service / Windows Credential Manager; bulk migrate plaintext via `aic migrate-keys`

### LLM UX
- ✅ Streaming — automatic streaming for OpenAI-compatible providers (in TTY environments); opt-out via `AIC_NO_STREAM=1`
- ✅ Result cache — same (cmd, exit, output) for 24h TTL, instant response
- ✅ Dry-run preview — `aic --dry-run "..."` previews tokens, cost, and timeout in advance
- ✅ Retry circuit breaker — after 5 failures within a 60s window, fail-fast for 30s
- ✅ i18n auto-detect — when `lang = "auto"`, infer from `$LC_ALL` / `$LANG`

### Onboarding
- ✅ `aic init zsh|bash` — automatic shell-hook installation (idempotent via markers)
- ✅ `aic init --hook-mode` — additionally install Phase 3 metadata-only hook
- ✅ `aic config` interactive wizard

### Supervisor / Capture Modes (new)
- ✅ `aicd` supervisor daemon — one per user. Session registry, control UDS,
  graceful shutdown
- ✅ `aic daemon { status | start | stop }` — supervisor control
- ✅ `aic session stop <id>` — registry-backed session termination
- ✅ `aic sessions` — aicd registry-first, fallback to socket scan
- ✅ Hook capture mode — collects metadata only via `~/.aic/hook-events.{zsh,bash}`
- ✅ `aic run -- <cmd>` — explicit FullOutput capture wrapper
- ✅ `CommandRecord.capture_mode/quality` + capture-quality hint during analysis

### Roadmap
- 🚧 `aic-proxy` — LLM API proxy server (planned)
- 🚧 Move PTY ownership into `aicd` (full implementation of PRD-AICD-SUPERVISOR Phase 2)
- 🚧 `aic capture-last` — destructive-command detection + confirm UX
- 🚧 Automatic launchd / systemd unit installation

## How it works

1. `aic-session` spawns your default shell as a PTY child process
2. Shell I/O passes through while an ANSI-stripped clean-text copy goes into a ring buffer
3. OSC 133 markers (or a timing heuristic) identify command boundaries and produce a `CommandRecord`
4. When you run `aic`, it queries the previous command's data via UDS
5. Based on exit code it auto-branches into error analysis (LLM) or an interactive REPL

## Quick Start

### Prerequisites

- Rust 1.75+ (2021 edition)
- macOS or Linux
- An LLM API key (OpenAI, Anthropic, Groq, etc.) or a CLI Backend (kiro-cli, claude-cli)

### Build & Install

#### Homebrew (macOS / Linux)

```bash
brew tap x-mesh/tap
brew install aic
# Enable autostart, once after install:
aic daemon install     # auto-branches between macOS launchd and Linux systemd user unit
```

`brew services` works well with macOS launchd but its Linux-systemd
support is spotty, so `aic daemon install` handles both OSes consistently.

#### Build from source

```bash
git clone https://github.com/x-mesh/aic.git && cd aic
cargo build --workspace --release
cargo install --path aic-server   # installs aic-session + aicd
cargo install --path aic-client   # installs aic
```

Or via Makefile:

```bash
make install
```

### Configuration

```bash
mkdir -p ~/.config/aic
cp <<'EOF' > ~/.config/aic/config.toml
[server]
max_buffer_lines = 500

[server.boundary_strategy]
method = "prompt_marker"

[llm]
default_provider = "openai"

[llm.providers.openai]
provider_type = "OpenAiCompatible"
endpoint = "https://api.openai.com/v1/chat/completions"
api_key = "sk-..."
model = "gpt-4o"
EOF
```

### Usage

```bash
# 1. First-time setup — config + automatic shell-hook install
aic config             # interactive provider/api_key/model setup
aic init zsh           # idempotently appends 'source ~/.aic/hooks.zsh' to ~/.zshrc
aic migrate-keys       # move plaintext API keys into the OS keychain (optional)
aic doctor             # 9-axis diagnosis — see PASS/WARN/FAIL at a glance

# 2. (optional) Start the supervisor — central multi-session lifecycle
aic daemon start       # spawns aicd in the background
aic daemon status      # check liveness + registered session count

# 3. Start a shell with aic-session — auto-registers if aicd is up
aic-session

# 4. Use commands as usual
cargo build   # error!

# 5. Analyze the error with aic
aic
# → LLM explains the cause and suggests fix commands (auto-streams in TTY)

# 6. Running aic with no error → REPL mode
aic
# → Freeform chat with the LLM (exit/quit/Ctrl+D to leave)

# 7. Direct question + dry-run for cost preview
aic --dry-run "how do I fix this error?"

# 8. Operations
aic status             # daemon PID / ping / last command
aic sessions           # all active sessions (aicd registry-first)
aic session stop <id>  # terminate a specific session (requires aicd)
aic audit verify       # audit-log HMAC-chain integrity (exit 0/2/3)
```

### Optional: Hook capture mode (metadata only, no PTY wrapper)

When you want to collect command metadata without paying the PTY-wrapping cost:

```bash
aic daemon start                    # aicd required (receives hook events)
aic init zsh --hook-mode            # installs ~/.aic/hook-events.zsh
exec zsh                            # new shell → preexec/precmd hooks active

# Run commands as usual — metadata accumulates without aic-session
ls -la
cargo build

# Use explicit capture only when exact output is needed
aic run -- cargo build              # preserves stdout/stderr and exit code
```

### Environment variables

| Variable | Effect |
|---|---|
| `AIC_LOG=info|debug|trace` | aic-session/aicd tracing level (default info) |
| `AIC_REDACT=off` | disable secret/PII redaction (recorded in audit) |
| `AIC_NO_STREAM=1` | disable streaming (spinner + sectional output) |
| `AIC_DEBUG=1` | client emits `[debug +X.XXXs]` prefix |
| `AIC_SESSION_ID` | active session ID. Exported automatically by `aic-session`; hooks reference it too |

## Project Structure

```
aic/
├── aic-common/                      # shared data models, IPC protocol, errors
│   └── src/
│       ├── lib.rs                   # CommandRecord (+ capture_mode/quality),
│       │                            # SessionInfo/SessionState, SessionConfig,
│       │                            # AppConfig, capture_quality_hint()
│       ├── ipc.rs                   # IpcRequest/Response — session/control/hook
│       ├── error.rs                 # AicError
│       └── paths.rs                 # session_socket_path, aicd_socket_path,
│                                    # aicd_lock_path
├── aic-server/                      # two binaries: aic-session + aicd
│   └── src/
│       ├── main.rs                  # aic-session: PTY wrapper + register/
│       │                            # unregister to aicd
│       ├── aicd_main.rs             # aicd: singleton + control UDS + signal
│       ├── control_server.rs        # aicd control plane (RingBuffer-free)
│       ├── session_registry.rs      # in-memory HashMap registry
│       ├── hook_events.rs           # per-session bounded ring (Phase 3)
│       ├── aicd_client.rs           # aic-session → aicd best-effort RPC
│       ├── pty_manager.rs / output_processor.rs / boundary_detector.rs /
│       │   ring_buffer.rs / uds_server.rs / lock.rs / metrics.rs / telemetry.rs
├── aic-client/                      # CLI client (binary: aic)
│   └── src/
│       ├── main.rs                  # clap CLI: 11+ subcommands
│       ├── hook_install.rs          # zsh/bash hook script generator (Phase 3)
│       ├── uds_client.rs            # session UDS + aicd control client
│       ├── doctor.rs                # 9-axis diagnosis (incl. aicd supervisor)
│       ├── config.rs / auto_brancher.rs / error_analyzer.rs /
│       │   llm_dispatcher.rs / repl.rs / cache.rs / redaction.rs /
│       │   audit.rs / keychain.rs / streaming.rs / spinner.rs / top.rs
├── docs/                            # PRDs, capture-mode trade-offs
├── Cargo.toml                       # workspace definition
└── Makefile
```

## Configuration file

Config file path: `~/.config/aic/config.toml` (XDG Base Directory compliant)

```toml
[server]
max_buffer_lines = 500
# socket_path = "/custom/path/session.sock"  # optional: override the socket path

[server.boundary_strategy]
method = "prompt_marker"           # "prompt_marker" or "timing_heuristic"
# idle_threshold_ms = 500          # idle threshold when using timing_heuristic

[llm]
default_provider = "openai"        # default provider name

# ── OpenAI-compatible (OpenAI, NVIDIA, etc.) ──
[llm.providers.openai]
provider_type = "OpenAiCompatible"
endpoint = "https://api.openai.com/v1/chat/completions"
api_key = "sk-..."
model = "gpt-4o"

[llm.providers.nvidia]
provider_type = "OpenAiCompatible"
endpoint = "https://integrate.api.nvidia.com/v1/chat/completions"
api_key = "nvapi-..."
model = "meta/llama-3.1-70b-instruct"

# ── Groq (OpenAI-compatible — defaults applied automatically when endpoint/model are omitted) ──
[llm.providers.groq]
provider_type = "Groq"
api_key = "gsk_..."
model = "llama-3.3-70b-versatile"
# When endpoint is omitted, https://api.groq.com/openai/v1/chat/completions is used.
# Other models: llama-3.1-8b-instant · deepseek-r1-distill-llama-70b · gemma2-9b-it

# ── Anthropic ──
# Model IDs: see https://docs.anthropic.com/en/docs/about-claude/models
# Recommended: claude-opus-4-7 (most capable), claude-sonnet-4-6 (balanced, default),
#              claude-haiku-4-5-20251001 (cheap/fast).
# Older models (claude-sonnet-4-20250514, claude-3-5-haiku-20241022, etc.) may
# return 404 once retired — update to the IDs above.
[llm.providers.anthropic]
provider_type = "Anthropic"
endpoint = "https://api.anthropic.com/v1/messages"
api_key = "sk-ant-..."
model = "claude-sonnet-4-6"

# ── CLI Backend (local CLI tools) ──
[llm.providers.kiro-cli]
provider_type = "CliBackend"
cli_path = "kiro"

[llm.providers.claude-cli]
provider_type = "CliBackend"
cli_path = "claude"
```

## Environment Variables

| Variable | Description | Default |
|------|------|--------|
| `XDG_CONFIG_HOME` | config-file directory | `~/.config` |
| `XDG_RUNTIME_DIR` | socket path (Linux) | `/tmp/aic-{uid}` |
| `AIC_SESSION_ID` | active session identifier — `aic-session` exports it into the shell. Clients (`aic`/`status`/`doctor`/`top`) use it to locate the socket. | (auto-generated) |
| `AIC_NO_RUN` | when set, disables the inline-run prompt for LLM-suggested commands | unset |
| `AIC_AUTO_RUN` | when `1`, auto-runs without an inline-run prompt (excluding destructive commands) | unset |
| `AIC_DEBUG` | when `1` or `true`, emits debug logs to stderr | unset |
| `AIC_REDACT` | when `1`, masks secrets/PII in the prompt right before sending to the LLM | unset |
| `AIC_NO_STREAM` | when set, disables streaming responses (received and displayed all at once) | unset |

## Socket paths (multi-session)

Running `aic-session` from multiple terminals creates an independent socket for each.

| Platform | Path pattern |
|--------|-----------|
| macOS | `/tmp/aic-{uid}/session-{id}.sock` |
| Linux (XDG set) | `$XDG_RUNTIME_DIR/aic/session-{id}.sock` |
| Linux (XDG unset) | `/tmp/aic-{uid}/session-{id}.sock` |

`{id}` is a 16-hex identifier auto-generated by `aic-session` (exported as the `AIC_SESSION_ID` env var).

### Client session-resolution priority
How `aic status` / `aic doctor` / `aic top` etc. pick a session:

1. `--session <id>` (explicit argument)
2. `$AIC_SESSION_ID` (shell export — typically automatic)
3. `config.server.socket_path` (user override)
4. Most recently mtime-updated `session-*.sock` (auto-pick the active session)
5. Legacy `session.sock` (backwards compatibility)

Use `aic sessions` or `aic status --all` to see the full list.

## IPC Protocol

JSON-over-UDS communication between server and client. Length-prefixed framing:

```
[4 bytes: payload length (u32 big-endian)][JSON payload]
```

Session daemon (`aic-session`) socket:

| Request | Description |
|---------|------|
| `GetLastCommand` | retrieve the previous command's CommandRecord |
| `GetRecentLines { count }` | retrieve the last N lines of text |
| `Ping` / `GetMetrics` | health / metrics |

Supervisor (`aicd`) control socket:

| Request | Description |
|---------|------|
| `Ping` | aicd health |
| `ListSessions` | every SessionInfo in the registry |
| `RegisterSession(SessionInfo)` | register a session (called by aic-session) |
| `UnregisterSession { id }` | deregister a session |
| `StopSession { id }` | SIGTERM the registry's PID |
| `Shutdown` | aicd graceful termination |
| `CommandStarted/Finished` | metadata events sent by the shell hook |

Sending to the wrong socket returns a graceful `Error` response ("connect to the aicd socket").

## Development guide

### Build

```bash
make              # debug build
make release      # release build (optimized)
make check        # quick compile check
```

### Test

```bash
make test         # full test suite
make test-unit    # unit tests only
make e2e          # E2E tests only
make test-prop    # property-based tests (1024 cases)
make test-pty     # PTY integration tests (requires a terminal)
```

### Lint

```bash
make lint         # clippy + fmt check
make fix          # autofix
```

### Run (development mode)

```bash
make run-server   # run aic-session
make run-client   # run aic
make run-config   # run aic config
```

### Misc

```bash
make ci           # reproduce CI locally (lint + test)
make doc          # generate and open rustdoc
make loc          # lines-of-code statistics
make deps         # dependency tree
make help         # full command list
```

## Tech stack

| Area | Technology |
|------|------|
| Language | Rust (2021 edition) |
| PTY management | `portable-pty` |
| Async runtime | `tokio` |
| HTTP client | `reqwest` (rustls) |
| IPC | Unix Domain Socket (`tokio::net::UnixListener`) |
| Serialization | `serde` + `serde_json` / `toml` |
| CLI parsing | `clap` |
| ANSI stripping | `strip-ansi-escapes` |
| Testing | `proptest` (property-based testing) |

## License

[MIT](./LICENSE)
