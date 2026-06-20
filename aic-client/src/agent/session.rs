//! 읽기 전용 agent 세션 — tool-calling loop.
//!
//! `ReplSession`과 달리 multi-turn history와 도구 호출 사이클을 관리한다.
//! provider가 tool-calling을 지원하지 않으면 호출부가 `ReplSession`으로 폴백하므로,
//! 이 세션은 OpenAI-compat 경로에서만 생성된다.
//!
//! 안전 가드:
//! - `MAX_ITERATIONS` 초과 시 안전 종료(무한 tool 호출 차단).
//! - tool 결과는 `MAX_TOOL_RESULT_BYTES`로 cap.
//! - 인자 파싱 실패·도구 예외는 모두 tool 에러 메시지로 흡수(loop가 죽지 않음).

use aic_common::{AicError, CommandRecord};

use crate::llm_dispatcher::LlmDispatcher;
use crate::repl;

use std::collections::VecDeque;

use super::debug::adbg;
use super::obs_tools::ObsClient;
use super::sandbox::Sandbox;
use super::tool_record::{self, ToolRecord};
use super::tools;
use super::types::{ChatMessage, ChatResponse, ToolCall};
use super::ui;

/// tool_call → 실행 → 재요청 사이클의 최대 반복 횟수.
const MAX_ITERATIONS: usize = 8;
/// 단일 tool 결과를 LLM에 전달할 때의 최대 바이트.
const MAX_TOOL_RESULT_BYTES: usize = 64 * 1024;

/// SRE 모드(run_command 활성) 전용 시스템 지침. generic preface 뒤에 덧붙인다.
const SRE_PREFACE: &str = "\n\nYou are operating as an SRE diagnostics assistant with a \
run_command tool. Behave like an autonomous on-call engineer:\n\
- For actionable diagnostic requests, DO NOT ask clarifying questions — run a safe, bounded \
command immediately.\n\
- Interpret short intents as canonical commands: 'ps'/'processes' -> `ps aux | head -n 20`; \
'cpu' -> `ps aux | head -n 20` (sorted by CPU when supported); 'mem'/'memory' -> a small \
memory snapshot (`vm_stat` on macOS, `free -h` on Linux, else `ps aux | head -n 20`); \
'disk' -> `df -h`; 'net'/'network' -> `ss -tunl` or `netstat -an | head -n 50`; \
'logs' -> a bounded tail (`tail -n 100 <file>` or `journalctl --no-pager -n 100`).\n\
- ALWAYS keep output bounded: pipe large output through `head`/`sort`/limit (e.g. `| head -n 20`). \
Never run unbounded streaming commands.\n\
- Only state-changing or risky commands require confirmation; read-only diagnostics run automatically.\n\
- Read-only diagnostics may inspect the WHOLE host — use absolute paths freely: \
`tail -n 100 /var/log/syslog`, `du -ah /tmp | sort -rh | head -n 20`, `find /tmp -type f -mmin -10`, \
`cat /proc/meminfo`. Secret paths (~/.ssh, ~/.aws, /etc/shadow, *.pem, *.key, .env) are blocked even \
for reads, and mutation/egress still require confirmation or are blocked.\n\
- The shell is restricted (no $, globs, quotes, backslashes, redirects, ;, &). If a command is \
blocked for that reason, propose and run a simpler safe alternative instead of giving up.\n\
- If a tool result says output was truncated, re-run with a narrower/limited command.\n\
- If a file change is needed, use write_file/edit_file — every write goes through a user \
confirm and is rejected outside the sandbox or on secret files.\n";

/// session 화면 출력 sink (RFC-004 step 4d). 비-TTY/배너 opt-out은 `Direct`로 기존 line-based
/// 출력(stdout=답변/stderr=UI)을 **byte-identical** 유지하고, TTY는 `Tui`로 ChatLoop에 위임해
/// 답변을 viewport 위 scrollback에 insert_before하고 spinner를 tick arm으로 흐르게 한다.
enum ChatOut {
    /// non-TTY/파이프/배너 opt-out — 기존 동작 보존. thinking은 stderr spinner.
    Direct {
        spinner: Option<crate::spinner::Spinner>,
    },
    /// TTY — ChatLoop에 메시지로 위임(answer=insert_before, spin=tick arm).
    Tui(tokio::sync::mpsc::Sender<super::chat_tui::OutMsg>),
}

impl ChatOut {
    /// LLM 답변(<think> 요약 + 파란 border)을 출력한다. 두 경로가 같은 `repl::format_*`를
    /// 통과해 Direct는 stdout, Tui는 insert_before로 내되 내용이 일치한다(critic M3).
    async fn answer(&self, text: &str) {
        let (think, main) = repl::split_think_block(text);
        match self {
            ChatOut::Direct { .. } => {
                if let Some(t) = &think {
                    repl::print_think_summary(t);
                }
                repl::print_with_border(&main);
            }
            ChatOut::Tui(tx) => {
                let mut block = String::new();
                if let Some(t) = &think {
                    if let Some(s) = repl::format_think_summary(t) {
                        block.push_str(&s);
                        block.push('\n');
                    }
                }
                // 전면 TUI는 화면 폭 wrap을 ratatui Paragraph가 하므로 사전 wrap 끔(critic B1).
                // think 요약은 한 줄이라 wrap 무관 → format_think_summary 그대로.
                block.push_str(&repl::format_with_border_raw(&main));
                let _ = tx.send(super::chat_tui::OutMsg::Answer(block)).await;
            }
        }
    }

    /// thinking spinner 시작. Direct=stderr spinner(색/지표 포함), Tui=ChatLoop tick(SpinStart).
    async fn spin_start(&mut self, label: String, color: &str) {
        match self {
            ChatOut::Direct { spinner } => {
                *spinner = Some(crate::spinner::Spinner::start_with_metrics(
                    label,
                    color,
                    ui::statusbar_enabled(),
                ));
            }
            ChatOut::Tui(tx) => {
                let _ = tx.send(super::chat_tui::OutMsg::SpinStart(label)).await;
            }
        }
    }

    /// thinking spinner 종료(Direct는 라인 정리, Tui는 입력 줄 복귀).
    async fn spin_stop(&mut self) {
        match self {
            ChatOut::Direct { spinner } => {
                if let Some(s) = spinner.take() {
                    s.stop().await;
                }
            }
            ChatOut::Tui(tx) => {
                let _ = tx.send(super::chat_tui::OutMsg::SpinStop).await;
            }
        }
    }

    /// UI/에러 한 줄. Direct=stderr(기존 byte-identical), Tui=insert_before(Note).
    /// slash 핸들러의 stderr 출력은 4e에서 이 sink로 이전됨(TUI viewport 보존).
    async fn note(&self, line: &str) {
        match self {
            ChatOut::Direct { .. } => eprintln!("{line}"),
            ChatOut::Tui(tx) => {
                let _ = tx
                    .send(super::chat_tui::OutMsg::Note(line.to_string()))
                    .await;
            }
        }
    }

    /// Direct(line-based) sink인지. `collect_local_snapshot`의 `\r` ephemeral 진행표시는
    /// insert_before(줄 추가)와 충돌하므로 Direct일 때만 출력하기 위한 분기 헬퍼(RFC-004 step 4e).
    fn is_direct(&self) -> bool {
        matches!(self, ChatOut::Direct { .. })
    }

    /// 컨텍스트 토큰 추정치를 status bar에 전달한다. Tui면 `OutMsg::Ctx`, Direct면 no-op
    /// (Direct status bar는 시스템 지표만 표시하며 토큰 표시 자리가 없다).
    async fn send_ctx(&self, tokens: usize) {
        if let ChatOut::Tui(tx) = self {
            let _ = tx.send(super::chat_tui::OutMsg::Ctx(tokens)).await;
        }
    }

    /// proactive 알림 레인(C7)을 켜고 끈다. Tui면 `OutMsg::AlertsArmed`로 ChatLoop의 alert tracker를
    /// 토글한다. Direct는 alert 레인이 없으므로 no-op(호출부가 안내 note를 따로 출력).
    async fn alerts_armed(&self, on: bool) {
        if let ChatOut::Tui(tx) = self {
            let _ = tx.send(super::chat_tui::OutMsg::AlertsArmed(on)).await;
        }
    }

    /// streaming chunk를 ChatLoop로 보낼 sender clone(Tui 모드만). 콜백에서 try_send로 비차단 전송하며,
    /// 채널이 차면 미리보기 청크는 드롭된다(최종 Answer가 포맷본으로 교체하므로 결과엔 영향 없음).
    /// Direct/비-TTY는 None — 호출부가 버퍼링 경로로 폴백한다.
    fn chunk_sender(&self) -> Option<tokio::sync::mpsc::Sender<super::chat_tui::OutMsg>> {
        match self {
            ChatOut::Tui(tx) => Some(tx.clone()),
            _ => None,
        }
    }

    /// NeedsConfirm 명령 확인. y면 true, 그 외(거부/Esc/비-TTY)는 false(기본 거부).
    /// - Direct: stdin y/N(비-TTY는 출력 없이 즉시 false — 기존 비대화형 거부와 byte-identical).
    /// - Tui: `OutMsg::Confirm`으로 ChatLoop에 위임하고 oneshot으로 결과를 받는다(EventStream과
    ///   경쟁하던 동기 stdin hang을 해소 — investigate F2). 채널이 닫히면 false(안전 거부).
    async fn confirm(&self, prompt: &str) -> bool {
        match self {
            ChatOut::Direct { .. } => {
                use std::io::{IsTerminal, Write};
                if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
                    return false;
                }
                eprint!("{prompt} ");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                if std::io::stdin().read_line(&mut line).is_err() {
                    return false;
                }
                matches!(line.trim(), "y" | "Y" | "yes" | "YES")
            }
            ChatOut::Tui(tx) => {
                let (rtx, rrx) = tokio::sync::oneshot::channel();
                if tx
                    .send(super::chat_tui::OutMsg::Confirm(prompt.to_string(), rtx))
                    .await
                    .is_err()
                {
                    return false;
                }
                rrx.await.unwrap_or(false)
            }
        }
    }
}

pub struct AgentSession {
    dispatcher: LlmDispatcher,
    sandbox: Sandbox,
    context: CommandRecord,
    lang: String,
    history: Vec<ChatMessage>,
    first_turn: bool,
    /// provider가 tool-calling을 거부하면 true로 전환되어 이후 턴은 단발 send()로
    /// 처리한다(읽기 도구 없이 일반 대화). 기존 REPL과 동등하게 degrade.
    degraded: bool,
    /// run_command 도구를 registry에 노출할지. `aic chat`에서 기본 true이며
    /// `--no-run`/`--read-only`/`AIC_AGENT_NO_RUN`로 끄면 false(읽기 전용).
    allow_run_command: bool,
    /// status line 표시용 provider/model(선택).
    provider: Option<String>,
    model: Option<String>,
    /// 세션 correlation id(run). debug/card/audit에서 tool call들을 묶는다.
    run_id: String,
    /// tool call 순번 — correlation id `{run_id}.{seq}`로 사용.
    tool_seq: u64,
    /// in-memory tool 실행 기록(P2-1 `/last`·`/raw` 조회용). 상한 ring buffer.
    tool_records: VecDeque<ToolRecord>,
    /// `/compare` 직전 시스템 스냅샷(baseline). 첫 호출 시 저장, 이후 diff 후 갱신.
    compare_baseline: Option<String>,
    /// 현재 chat 세션에서 이어붙일 persistent RCA incident id.
    active_rca_id: Option<String>,
    /// 화면 출력 sink. 기본 `Direct`(기존 동작), TTY chat은 `run()`에서 `Tui`로 교체(RFC-004 step 4).
    out: ChatOut,
    /// 관측 백엔드(Prometheus/Loki/ES) 질의 클라이언트(SRE R1). config에 등록 백엔드가
    /// 있을 때만 Some. 등록된 백엔드만 질의 가능 — endpoint allowlist.
    obs: Option<ObsClient>,
    /// MCP 클라이언트 — config `[mcp.servers.*]`에 enabled 서버가 있을 때만 Some. 발견된 tool을
    /// chat tool-calling에 노출하고, 변경 도구는 confirm 후 실행한다. 연결은 `run()`에서 비동기로 수행.
    mcp: Option<super::mcp::McpClient>,
}

impl AgentSession {
    pub fn new(
        dispatcher: LlmDispatcher,
        sandbox: Sandbox,
        context: CommandRecord,
        lang: String,
    ) -> Self {
        Self {
            dispatcher,
            sandbox,
            context,
            lang,
            history: Vec::new(),
            first_turn: true,
            degraded: false,
            allow_run_command: false,
            provider: None,
            model: None,
            run_id: new_run_id(),
            tool_seq: 0,
            tool_records: VecDeque::new(),
            compare_baseline: None,
            active_rca_id: None,
            out: ChatOut::Direct { spinner: None },
            obs: None,
            mcp: None,
        }
    }

    /// run_command 도구 노출 여부를 설정한다(`aic chat` 기본 활성, `--no-run`로 끔).
    pub fn allow_run_command(mut self, enabled: bool) -> Self {
        self.allow_run_command = enabled;
        self
    }

    /// 관측 백엔드(Prometheus/Loki/ES) 질의 도구를 설정한다(SRE R1).
    /// config `[observability.backends.*]`에 등록 백엔드가 있을 때만 활성화된다.
    pub fn with_observability(mut self, cfg: &aic_common::ObservabilityConfig) -> Self {
        if !cfg.backends.is_empty() {
            match ObsClient::new(cfg) {
                Ok(client) => self.obs = Some(client),
                Err(e) => adbg!("obs client 생성 실패 — 관측 도구 비활성: {}", e),
            }
        }
        self
    }

    /// MCP 클라이언트를 설정한다. config `[mcp.servers.*]`에 enabled 서버가 있을 때만 활성화된다.
    /// 실제 연결(핸드셰이크·tool 발견)은 `run()`에서 비동기로 수행한다.
    pub fn with_mcp(mut self, cfg: &aic_common::McpConfig) -> Self {
        self.mcp = super::mcp::McpClient::new(cfg);
        self
    }

    /// status line 표시용 provider/model을 설정한다(선택).
    pub fn with_provider_model(mut self, provider: String, model: String) -> Self {
        self.provider = Some(provider);
        self.model = Some(model);
        self
    }

    /// REPL 루프 실행. exit/quit/Ctrl+D로 종료.
    ///
    /// system preface를 시드한 뒤, 입출력이 TTY면 ratatui chat TUI([`run_loop_tui`])로,
    /// non-TTY/파이프 또는 `AIC_NO_TUI=1`이면 line-based 루프([`run_loop_direct`])로 분기한다.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        // system preface를 history 시드로 둔다(OpenAI system role 사용).
        // SRE 모드면 generic preface 뒤에 SRE 지침을 덧붙인다.
        let mut preface = repl::system_preface().to_string();
        if self.allow_run_command {
            preface.push_str(SRE_PREFACE);
        }
        self.history.push(ChatMessage::System(preface));

        // MCP 서버 연결(핸드셰이크 + tool 발견). 서버별 독립·graceful degrade — 무응답 서버는 서버당
        // 상한(CONNECT_OVERALL_SECS) 후 skip하고 나머지로 진행한다(요청별로도 짧은 타임아웃). 서버는
        // 순차 연결되며 요약은 Direct note로 남긴다(TUI 진입 전 — 다수 서버면 startup이 그만큼 늘 수 있음).
        let mcp_notes = match &mut self.mcp {
            Some(mcp) => mcp.connect().await,
            None => Vec::new(),
        };
        for note in mcp_notes {
            self.out.note(&note).await;
        }

        use std::io::IsTerminal;
        let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        // macOS 한글 IME 조합 충돌(자모 분리/커서 밀림)은 하드웨어 커서 정렬(place_textarea_cursor)
        // + 입력 대기 중 자발적 redraw 금지로 해소되어, macOS도 TUI 기본이다(2026-06 실사용 검증).
        // 재발 시 `AIC_NO_TUI=1`로 Direct(reedline) fallback. non-TTY/파이프는 항상 Direct.
        // (`AIC_CHAT_TUI`는 과거 macOS opt-in 플래그 — 이제 기본이 TUI라 no-op, 설정돼 있어도 무해.)
        let result = if tty && !super::debug::env_truthy("AIC_NO_TUI") {
            self.run_loop_tui().await
        } else {
            self.run_loop_direct().await
        };
        // 루프 종료(=세션 종료) 시점에 1회 저장 → `/resume`로 복원. best-effort(출력 없음).
        self.save_session();
        result
    }

    /// 시작 배너 + context 헤더(banner opt-out이면 생략). Direct/Tui 공용.
    fn print_banner(&self) {
        if !ui::banner_suppressed() {
            ui::print_banner_and_status(&ui::StatusInfo {
                run_state: if self.allow_run_command {
                    ui::RunState::On
                } else {
                    ui::RunState::ReadOnly
                },
                cwd: self.sandbox.root().display().to_string(),
                provider: self.provider.clone(),
                model: self.model.clone(),
            });
            repl::print_context_header(&self.context);
        }
    }

    /// 기존 line-based REPL 루프(reedline/stdin). non-TTY·기본 경로. 출력은 stdout=답변/stderr=UI.
    async fn run_loop_direct(&mut self) -> anyhow::Result<()> {
        let mut reader = repl::LineReader::new();
        self.print_banner();

        // status bar 샘플러 — TTY이고 opt-out 미설정일 때만 생성(비-TTY/파이프/CI는 None = 비용 0).
        let mut sampler = ui::statusbar_enabled().then(super::sys_sampler::SysSampler::new);

        loop {
            // 입력 프롬프트 직전 1회 status bar 갱신 — reedline read_line 진입 전이라 충돌 0.
            if let Some(s) = sampler.as_mut() {
                ui::print_status_bar(&s.sample().status_line());
            }
            // 한 줄 읽기 (TTY는 Unicode-aware 라인 에디터, 비-TTY는 read_line)
            let line = match reader.read(ui::prompt_label())? {
                repl::ReadLine::Eof => {
                    println!();
                    break;
                }
                repl::ReadLine::Line(l) => l,
            };
            if repl::ReplSession::is_exit_command(&line) {
                break;
            }
            let input = line.trim();
            if input.is_empty() {
                continue;
            }

            // slash 명령은 LLM 전송 전에 가로채 처리한다 — history/context에 push하지 않고,
            // 출력은 stderr로만 내보내 stdout(LLM 답변)을 오염시키지 않는다.
            if let Some(cmd) = tool_record::parse_slash(input) {
                self.handle_slash(cmd).await;
                continue;
            }

            let user_text = self.build_user_message(input);
            self.history.push(ChatMessage::User(user_text));

            if let Err(e) = self.run_turn().await {
                eprintln!("LLM 요청 실패: {e}");
            }
        }

        Ok(())
    }

    /// RFC-004 step 4: ratatui chat TUI 루프(TTY 기본 경로). `ChatLoop`가 terminal을 단독
    /// 소유하고, 여기선 채널로 입력을 받고(`recv_line`) 답변/spinner를 `ChatOut::Tui`로 보낸다.
    /// 배너는 raw mode 진입(spawn) 전에 일반 출력해 scrollback에 남긴다. slash 출력 이전은 4e.
    async fn run_loop_tui(&mut self) -> anyhow::Result<()> {
        let prompt = ui::prompt_label().to_string();
        let mut handle = super::chat_tui::start_chat_loop(prompt, ui::statusbar_enabled());
        self.out = ChatOut::Tui(handle.out_sender());

        // 시작 배너 — alternate screen이라 stderr 배너는 안 보이므로 대화 로그에 넣는다(step 8 후속).
        if !ui::banner_suppressed() {
            let banner = ui::format_banner_and_status(&ui::StatusInfo {
                run_state: if self.allow_run_command {
                    ui::RunState::On
                } else {
                    ui::RunState::ReadOnly
                },
                cwd: self.sandbox.root().display().to_string(),
                provider: self.provider.clone(),
                model: self.model.clone(),
            });
            self.out.note(&banner).await;
        }

        // 시작 시 1회 컨텍스트 토큰 표시(preface seed 후 — 보통 system 프롬프트만 있는 상태).
        self.out.send_ctx(self.estimate_tokens()).await;

        loop {
            let line = match handle.recv_line().await {
                super::chat_tui::ChatLine::Eof => break,
                super::chat_tui::ChatLine::Line(l) => l,
            };
            if repl::ReplSession::is_exit_command(&line) {
                break;
            }
            let input = line.trim();
            if input.is_empty() {
                continue;
            }
            if let Some(cmd) = tool_record::parse_slash(input) {
                // slash 처리 동안 spin으로 즉시 반응 + 입력 차단(probe 수집 등으로 무반응·중복 실행
                // 되던 문제 해소). 분석 단계의 run_analysis가 라벨을 "분석 중…"으로 덮어쓴다.
                self.out
                    .spin_start(format!("{input} 처리 중…"), "90")
                    .await;
                // Ctrl+C 취소: probe 수집/분석이 길어질 때 중단(future drop). 직전 잔여 신호는 drain.
                handle.drain_cancel();
                let cancelled = tokio::select! {
                    _ = self.handle_slash(cmd) => false,
                    _ = handle.recv_cancel() => true,
                };
                self.out.spin_stop().await;
                if cancelled {
                    self.out.note("⨯ 중단됨 (Ctrl+C)").await;
                }
                // /clear 등으로 history가 바뀔 수 있어 매 처리 후 토큰 표시 갱신.
                self.out.send_ctx(self.estimate_tokens()).await;
                continue;
            }
            let user_text = self.build_user_message(input);
            self.history.push(ChatMessage::User(user_text));
            // Ctrl+C 취소: run_turn future를 cancel과 race한다 — 취소되면 future가 drop되며 진행 중인
            // reqwest/도구 await가 중단된다. 직전 turn 종료와 동시에 눌린 잔여 신호는 drain으로 제거.
            handle.drain_cancel();
            let mark = self.history.len();
            let outcome = tokio::select! {
                r = self.run_turn() => Some(r),
                _ = handle.recv_cancel() => None,
            };
            match outcome {
                Some(Ok(())) => {}
                Some(Err(e)) => self.out.note(&format!("LLM 요청 실패: {e}")).await,
                None => {
                    // 취소: 미완성 응답(Assistant/Tool, dangling tool_call 포함)을 history에서 제거해
                    // 다음 turn의 OpenAI 정합성을 지킨다. User 메시지는 유지(무엇을 물었는지 보존).
                    self.history.truncate(mark);
                    self.out.spin_stop().await;
                    self.out.note("⨯ 중단됨 (Ctrl+C)").await;
                }
            }
            // 턴 처리(답변/도구 호출로 history 증가) 후 토큰 표시 갱신.
            self.out.send_ctx(self.estimate_tokens()).await;
        }

        // raw mode 복원 보장(Shutdown + task join).
        handle.shutdown().await;
        Ok(())
    }

    /// 한 번의 사용자 입력에 대해 tool-calling loop를 돈다.
    /// degrade 상태이면 도구 없이 단발 send()로 처리한다.
    async fn run_turn(&mut self) -> anyhow::Result<()> {
        if self.degraded {
            return self.run_turn_degraded().await;
        }

        let mut specs = tools::read_only_specs();
        if self.allow_run_command {
            specs.push(super::run_command::spec());
            // 쓰기 도구는 run_command와 동일 게이트(SRE 모드)에서만 노출. read-only 세션엔 미노출.
            specs.push(tools::write_file_spec());
            specs.push(tools::edit_file_spec());
        }
        // 관측 백엔드 도구(R1)는 read-only라 run_command 게이트와 무관하게, 등록 백엔드가
        // 있으면 항상 노출한다.
        if let Some(obs) = &self.obs {
            specs.extend(obs.specs());
        }
        // MCP 서버 tool(mem-mesh 등)은 namespaced 이름(server__tool)으로 노출한다. read-only는 자동,
        // 변경 도구는 exec_tool에서 confirm 게이팅.
        if let Some(mcp) = &self.mcp {
            specs.extend(mcp.specs());
        }

        for iter in 0..MAX_ITERATIONS {
            adbg!(
                "run={} iter={}/{} send_messages: history_msgs={} tool_specs={} run_command={} provider_tools=enabled",
                self.run_id,
                iter + 1,
                MAX_ITERATIONS,
                self.history.len(),
                specs.len(),
                if self.allow_run_command { "on" } else { "off" }
            );
            self.out.spin_start("thinking...".to_string(), "90").await;
            // TUI 모드면 streaming으로 텍스트를 라이브 전달(첫 토큰이 spinner를 멈추고 최종 Answer가
            // 미리보기를 포맷본으로 교체한다). Direct/비-TTY는 sink가 없어 버퍼링 경로를 그대로 쓴다.
            // `AIC_NO_STREAM`이면(REPL 경로와 동일 opt-out) streaming을 끄고 버퍼링으로 처리한다.
            let chunk_sink = self
                .out
                .chunk_sender()
                .filter(|_| !super::debug::env_truthy("AIC_NO_STREAM"));
            let resp = if let Some(tx) = chunk_sink {
                self.dispatcher
                    .send_messages_streaming(&self.history, &specs, |delta| {
                        let _ = tx.try_send(super::chat_tui::OutMsg::AnswerChunk(delta.to_string()));
                    })
                    .await
            } else {
                self.dispatcher.send_messages(&self.history, &specs).await
            };
            self.out.spin_stop().await;

            match resp {
                Ok(ChatResponse::Text(text)) => {
                    adbg!("iter={} response=text text_len={}", iter + 1, text.len());
                    self.history.push(ChatMessage::Assistant {
                        content: Some(text.clone()),
                        tool_calls: vec![],
                    });
                    self.out.answer(&text).await;
                    return Ok(());
                }
                Ok(ChatResponse::ToolCalls(calls)) => {
                    let names: Vec<&str> = calls.iter().map(|c| c.name.as_str()).collect();
                    adbg!(
                        "iter={} response=tool_calls count={} names=[{}]",
                        iter + 1,
                        calls.len(),
                        names.join(",")
                    );
                    // assistant turn(도구 호출)을 history에 기록.
                    self.history.push(ChatMessage::Assistant {
                        content: None,
                        tool_calls: calls.clone(),
                    });
                    // 각 도구를 실행하고 결과를 tool 메시지로 회신.
                    for call in &calls {
                        let result = self.exec_tool(call).await;
                        self.history.push(ChatMessage::Tool {
                            call_id: call.id.clone(),
                            content: result,
                        });
                    }
                    // loop 계속 → 갱신된 history로 재요청.
                }
                Err(e) => {
                    // 첫 시도(아직 도구 결과가 history에 없음)에서 provider가 tools를
                    // 거부한 것으로 보이면, 일반 대화 모드로 degrade해 재시도한다.
                    // (모르는 OpenAI-compat 프록시에서 반복 실패 대신 ReplSession과 동등 동작)
                    if iter == 0 && is_tools_unsupported(&e) {
                        self.degraded = true;
                        adbg!(
                            "iter=1 provider_tools=degraded reason=tool_calling_unsupported err_kind={} → plain chat",
                            err_kind(&e)
                        );
                        // G1-a: degrade 전환을 audit에 1회 기록(메시지 본문 제외, err_kind만).
                        let _ = crate::audit::append(
                            "tool_calling_degraded",
                            serde_json::json!({
                                "run_id": self.run_id,
                                "provider": self.provider,
                                "model": self.model,
                                "err_kind": err_kind(&e),
                            }),
                        );
                        // 사용자에게 1회 명시 고지(silent 전환 금지).
                        ui::print_status_note(
                            "provider가 tool-calling을 지원하지 않아 일반 대화 모드로 전환합니다 \
                             (provider_tools=degraded, 도구 비활성).",
                        );
                        return self.run_turn_degraded().await;
                    }
                    adbg!(
                        "iter={} send_messages error (err_kind={}) → surface",
                        iter + 1,
                        err_kind(&e)
                    );
                    return Err(anyhow::anyhow!(e));
                }
            }
        }

        adbg!("max iterations reached ({}) → safe stop", MAX_ITERATIONS);
        eprintln!(
            "\x1b[33m⚠ 도구 호출 반복 한도({MAX_ITERATIONS})에 도달해 안전하게 종료합니다. \
             더 구체적으로 질문해 주세요.\x1b[0m"
        );
        Ok(())
    }

    /// degrade 경로 — 마지막 user 메시지를 단발 `send()`로 처리(도구 없음).
    /// 기존 `ReplSession`과 동등한 1회 답변 동작.
    async fn run_turn_degraded(&mut self) -> anyhow::Result<()> {
        let prompt = self
            .history
            .iter()
            .rev()
            .find_map(|m| match m {
                ChatMessage::User(c) => Some(c.clone()),
                _ => None,
            })
            .unwrap_or_default();

        adbg!(
            "degraded turn: provider_tools=off send() prompt_len={}",
            prompt.len()
        );
        self.out.spin_start("thinking...".to_string(), "90").await;
        let resp = self.dispatcher.send(&prompt).await;
        self.out.spin_stop().await;

        match resp {
            Ok(text) => {
                adbg!("degraded response: text_len={}", text.len());
                self.history.push(ChatMessage::Assistant {
                    content: Some(text.clone()),
                    tool_calls: vec![],
                });
                self.out.answer(&text).await;
                Ok(())
            }
            Err(e) => {
                adbg!("degraded send() error (err_kind={})", err_kind(&e));
                Err(anyhow::anyhow!(e))
            }
        }
    }

    /// 단일 도구 호출을 실행하고 LLM에 회신할 문자열을 만든다(에러도 문자열로 흡수).
    /// `corr`(=`run_id.seq`)로 tool_call ↔ tool_result ↔ run_command card/audit를 묶는다.
    async fn exec_tool(&mut self, call: &ToolCall) -> String {
        self.tool_seq += 1;
        let corr = format!("{}.{}", self.run_id, self.tool_seq);
        // run_command는 자체 command card를 출력하므로 generic [tool] 줄은 생략.
        // [tool] 줄은 sink(note) 경유 — TUI raw mode에서 직접 eprintln하면 화면이 깨진다(codex P1).
        if call.name != "run_command" {
            self.out
                .note(&format!("\x1b[2m[tool] {} [{corr}]\x1b[0m", call.name))
                .await;
        }
        adbg!(
            "tool_call corr={corr} name={} args_len={}",
            call.name,
            call.arguments.len()
        );
        let args: serde_json::Value = match serde_json::from_str(&call.arguments) {
            Ok(v) => v,
            Err(e) => {
                adbg!(
                    "tool_result corr={corr} name={} status=arg_parse_error",
                    call.name
                );
                let out = format!("[tool error] 인자 JSON 파싱 실패: {e}");
                self.record_tool(&corr, &call.name, None, &out);
                return out;
            }
        };

        // run_command는 별도 정책 경로(risk_guard + confirm). 비활성 시 거부.
        let result = if call.name == "run_command" {
            if !self.allow_run_command {
                self.out
                    .note(&format!(
                        "\x1b[33m[run_command] [{corr}] 비활성(read-only 세션)\x1b[0m"
                    ))
                    .await;
                Ok("[tool error] run_command은 현재 read-only 세션이라 비활성입니다. \
                    셸 실행이 필요하면 `--no-run`/`--read-only` 없이(또는 AIC_AGENT_NO_RUN 미설정) \
                    `aic chat`을 다시 실행하세요. 지금은 read_file/list_dir/grep/glob로 진단하세요."
                    .to_string())
            } else {
                // risk 선평가 — NeedsConfirm일 때만 sink(Direct stdin / Tui y·n UI)로 확인을 받는다.
                // Safe는 confirm을 호출하지 않고 자동 실행, Dangerous/Unknown은 execute_with_corr가
                // 클로저와 무관하게 차단한다. 이로써 TUI에서도 동기 stdin hang 없이 확인이 동작한다
                // (investigate F2 해소). execute_with_corr 내부의 risk 재평가·정책은 그대로 둔다.
                use crate::risk_guard::RiskLevel;
                let command = args
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let assessment = crate::risk_guard::classify(&command);
                let approved = if assessment.level == RiskLevel::NeedsConfirm {
                    // 위험 이유(reason)를 confirm 프롬프트에 함께 보여 사용자가 근거로 판단하게 한다.
                    let reason = assessment.reason.as_deref().unwrap_or("상태 변경 가능");
                    self.out
                        .confirm(&format!("⚠ {command} — {reason} [y/N]"))
                        .await
                } else {
                    // Safe는 confirm 미호출(아래 클로저는 호출되지 않음), Dangerous/Unknown은 차단됨.
                    false
                };
                super::run_command::execute_with_corr(
                    &args,
                    &self.sandbox,
                    &corr,
                    move |_, _, _| approved,
                )
            }
        } else if call.name == "write_file" || call.name == "edit_file" {
            // mutation 도구: 쓰기 전 미리보기를 note로 출력하고 confirm을 받는다.
            // (sandbox 경계·secrets 위반은 confirm 후 tools::execute가 최종 거부한다.)
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let preview = build_write_preview(&call.name, &args, &self.sandbox);
            self.out.note(&preview).await;
            let ok = self
                .out
                .confirm(&format!("⚠ {path} 쓰기? [y/N]"))
                .await;
            if ok {
                tools::execute(&call.name, &args, &self.sandbox)
            } else {
                Ok("[denied] 파일 쓰기를 사용자가 거부했습니다.".to_string())
            }
        } else if matches!(
            call.name.as_str(),
            "prometheus_query" | "loki_query" | "es_search"
        ) {
            // 관측 백엔드 도구(R1): 등록된 backend allowlist 안에서만 HTTP read 질의.
            match &self.obs {
                Some(obs) => obs.run(&call.name, &args).await,
                None => Ok("[tool error] 관측 백엔드가 설정되지 않았습니다. \
                    config [observability.backends.<name>]에 추가하세요."
                    .to_string()),
            }
        } else if self.mcp.as_ref().is_some_and(|m| m.is_tool(&call.name)) {
            // MCP 도구(mem-mesh 등): auto_approve의 read-only는 자동 실행, 그 외(변경 도구)는 confirm.
            let needs_confirm = self
                .mcp
                .as_ref()
                .is_some_and(|m| m.needs_confirm(&call.name));
            let approved = if needs_confirm {
                self.out
                    .confirm(&format!("⚠ MCP 도구 {} 실행? [y/N]", call.name))
                    .await
            } else {
                true
            };
            if !approved {
                Ok(format!(
                    "[denied] MCP 도구 {} 실행을 사용자가 거부했습니다.",
                    call.name
                ))
            } else {
                match &self.mcp {
                    Some(mcp) => mcp.call(&call.name, &args).await,
                    None => Ok("[tool error] MCP 클라이언트가 없습니다.".to_string()),
                }
            }
        } else {
            tools::execute(&call.name, &args, &self.sandbox)
        };

        let final_out = match result {
            Ok(out) => {
                let truncated = out.len() > MAX_TOOL_RESULT_BYTES;
                let capped = cap_bytes(&out, MAX_TOOL_RESULT_BYTES);
                adbg!(
                    "tool_result corr={corr} name={} status=ok bytes={} truncated={}",
                    call.name,
                    capped.len(),
                    truncated
                );
                capped
            }
            Err(e) => {
                adbg!("tool_result corr={corr} name={} status=error", call.name);
                format!("[tool error] {e}")
            }
        };
        // command_display는 run_command 결과에 이미 redacted로 들어있는 `command:` 줄에서 추출
        // (재-redaction 불필요, secrets 원문 미보관).
        let command_display = if call.name == "run_command" {
            extract_command_line(&final_out)
        } else {
            None
        };
        self.record_tool(&corr, &call.name, command_display, &final_out);
        final_out
    }

    /// tool 실행 결과를 in-memory ring에 기록한다(`/last`·`/raw` 조회용).
    fn record_tool(
        &mut self,
        corr: &str,
        name: &str,
        command_display: Option<String>,
        output: &str,
    ) {
        let rec = ToolRecord::from_result(corr, name, command_display, output);
        tool_record::push_record(&mut self.tool_records, rec);
    }

    /// slash 명령을 처리한다(출력은 stderr 전용, history 미push).
    async fn handle_slash(&mut self, cmd: tool_record::SlashCommand) {
        use tool_record::SlashCommand;
        match cmd {
            SlashCommand::Help => self.out.note(&tool_record::help_text()).await,
            SlashCommand::Clear => {
                // history[0]=system preface는 유지하고 이후 대화 턴만 비운다(컨텍스트 리셋).
                self.history.truncate(1);
                self.out
                    .note("대화 컨텍스트를 초기화했습니다 (시스템 프롬프트 유지).")
                    .await;
            }
            SlashCommand::Resume => self.handle_resume().await,
            SlashCommand::Last(n) => {
                self.out
                    .note(&tool_record::render_last(&self.tool_records, n))
                    .await
            }
            SlashCommand::Raw(t) => {
                self.out
                    .note(&tool_record::render_raw(&self.tool_records, t.as_deref()))
                    .await
            }
            SlashCommand::Local { sections, analyze } => {
                self.handle_local(&sections, analyze).await
            }
            SlashCommand::Diagnose { symptom, analyze } => {
                self.handle_diagnose(symptom.as_deref(), analyze).await
            }
            SlashCommand::ExplainLast { target, analyze } => {
                self.handle_explain_last(target.as_deref(), analyze).await
            }
            SlashCommand::Incident { name, analyze } => {
                self.handle_incident(name.as_deref(), analyze).await
            }
            SlashCommand::Doctor => self.handle_doctor().await,
            SlashCommand::Fix => self.handle_fix().await,
            SlashCommand::Timeline(n) => {
                self.out
                    .note(&tool_record::render_timeline(&self.tool_records, n))
                    .await
            }
            SlashCommand::Trend(n) => {
                self.out
                    .note(&tool_record::render_trend(&self.tool_records, n))
                    .await
            }
            SlashCommand::Compare => self.handle_compare().await,
            SlashCommand::Bundle(name) => self.handle_bundle(name.as_deref()).await,
            SlashCommand::Rca(cmd) => self.handle_rca(cmd).await,
            SlashCommand::Triage { topic, run } => {
                self.handle_triage(topic.as_deref(), run).await
            }
            SlashCommand::Watch {
                target,
                count,
                every_ms,
            } => self.handle_watch(target.as_deref(), count, every_ms).await,
            SlashCommand::AlertLane { on } => self.handle_alert_lane(on).await,
            SlashCommand::Metrics { backend, query } => {
                self.handle_obs_query(
                    aic_common::BackendType::Prometheus,
                    "prometheus_query",
                    backend.as_deref(),
                    &query,
                )
                .await
            }
            SlashCommand::Logs { backend, query } => {
                self.handle_obs_query(
                    aic_common::BackendType::Loki,
                    "loki_query",
                    backend.as_deref(),
                    &query,
                )
                .await
            }
            SlashCommand::Ambiguous { input, candidates } => {
                let cands = candidates
                    .iter()
                    .map(|c| format!("/{c}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                self.out
                    .note(&format!(
                        "/{input}는 여러 명령과 일치합니다: {cands}. 더 입력해 구분하세요."
                    ))
                    .await;
            }
            SlashCommand::Unknown(name) => {
                self.out
                    .note(&format!(
                        "알 수 없는 명령: /{name}. /help 로 사용법을 확인하세요."
                    ))
                    .await
            }
        }
    }

    /// `/metrics`·`/logs` — 등록된 관측 백엔드에 직접 질의해 redacted raw 결과를 출력한다(LLM 미호출).
    /// backend 미지정 시 해당 타입 백엔드가 정확히 1개면 자동 선택, 여러 개면 목록을 안내한다.
    async fn handle_obs_query(
        &mut self,
        backend_type: aic_common::BackendType,
        tool: &str,
        backend: Option<&str>,
        query: &str,
    ) {
        let Some(obs) = &self.obs else {
            self.out
                .note(
                    "관측 백엔드가 설정되지 않았습니다. config [observability.backends.<name>]에 \
                     url/backend_type을 등록하세요.",
                )
                .await;
            return;
        };
        if query.trim().is_empty() {
            self.out
                .note("질의가 비었습니다. 예) /metrics up  ·  /logs {app=\"api\"}")
                .await;
            return;
        }
        // backend 결정: 명시값 우선, 없으면 해당 타입 백엔드가 1개일 때만 자동 선택.
        let names = obs.backend_names_of(backend_type);
        let chosen = match backend {
            Some(b) => b.to_string(),
            None => match names.as_slice() {
                [only] => only.clone(),
                [] => {
                    self.out
                        .note(&format!("등록된 {backend_type:?} 백엔드가 없습니다."))
                        .await;
                    return;
                }
                many => {
                    self.out
                        .note(&format!(
                            "{backend_type:?} 백엔드가 여러 개입니다: {}. -b <name>으로 지정하세요.",
                            many.join(", ")
                        ))
                        .await;
                    return;
                }
            },
        };
        let args = serde_json::json!({ "backend": chosen, "query": query });
        match obs.run(tool, &args).await {
            Ok(out) => self.out.note(&out).await,
            Err(e) => self.out.note(&format!("[obs error] {e}")).await,
        }
    }

    /// `/local` — 내장 sysinfo probe(개별 Safe 명령)를 실행해 로컬 스냅샷을 만든다.
    /// 섹션 다중 지정 가능(`/local disk memory`, 빈 목록=전체). docker 설치 호스트면 docker 섹션
    /// (`docker_ps`/`docker_stats`/`docker_df`)이 기본 스냅샷에 덧붙는다.
    /// 기본은 redacted 스냅샷을 **tool-less·stateless 단발 LLM 호출**로 분석 요약(history 미push).
    /// `--raw`이거나 `AIC_LOCAL_NO_ANALYZE`이거나 분석 실패(설정 없음/오류/timeout)면 raw 스냅샷으로
    /// fallback하고 짧은 사유만 표시한다. 출력은 stderr 전용, read-only 세션에서는 비활성.
    async fn handle_local(&mut self, sections: &[String], analyze: bool) {
        if !self.allow_run_command {
            self.out
                .note(
                    "/local은 run_command가 필요합니다 — 현재 read-only 세션(--no-run/--read-only/\
                     AIC_AGENT_NO_RUN)이라 비활성입니다.",
                )
                .await;
            return;
        }
        let probes = match super::sysinfo::probes_for(sections) {
            Ok(p) => p,
            Err(unknown) => {
                self.out
                    .note(&format!(
                        "알 수 없는 섹션: {}. 사용 가능: {}",
                        unknown.join(" "),
                        super::sysinfo::available_sections().join(" ")
                    ))
                    .await;
                return;
            }
        };

        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());

        // raw 모드만 snapshot 헤더/섹션/본문을 보인다. analyze 모드는 spinner만 두고 조용히 수집한다.
        if !do_analyze {
            self.out.note("=== local system snapshot ===").await;
        }
        let mut snapshot = self.collect_local_snapshot(probes, !do_analyze).await;
        // 결정적 임계 스캔 — /local 기본 섹션(disk 등)의 임계 위반을 LLM 무관하게 즉시 표면화한다.
        // 사용자에게 표시하고, analyze면 분석 프롬프트 evidence 상단에도 prepend한다(/diagnose와 동일).
        let findings = super::diagnose::scan_findings(&snapshot);
        let block = super::diagnose::render_findings_block(&findings);
        if !block.is_empty() {
            self.out.note(&format!("\n{}", block.trim_end())).await;
            // prepend는 LLM 프롬프트 evidence용 — analyze 모드에서만(raw는 표시만 하고 곧 return).
            if do_analyze {
                snapshot.insert_str(0, &format!("{block}\n"));
            }
        }

        if !do_analyze {
            return; // raw 출력 완료(또는 opt-out).
        }

        let prompt = tool_record::build_local_analyze_prompt(&snapshot);
        self.run_analysis(
            &snapshot,
            &prompt,
            "local_analyze",
            analyze_status_label("스냅샷", self.provider.as_deref()),
            "local analysis",
        )
        .await;
    }

    /// 스냅샷+프롬프트로 **tool-less·stateless 단발 분석**을 수행한다(self.history 미push).
    /// 성공: markdown 렌더(TTY)/raw(파이프)로 stderr 출력. 실패/timeout: raw 증거 fallback.
    /// `/local`·`/diagnose`가 공유한다. ANSI/스피너 색은 color 정책을 따른다.
    async fn run_analysis(
        &mut self,
        snapshot: &str,
        prompt: &str,
        kind: &'static str,
        label: String,
        heading: &str,
    ) {
        adbg!(
            "{kind} run={} sending snapshot_len={}",
            self.run_id,
            snapshot.len()
        );
        // 정적 메시지 대신 spinner 상태 UI(전송 투명성 라벨). TTY-only, amber(색 정책 준수).
        let amber = if ui::color_enabled() {
            super::markdown::AMBER
        } else {
            ""
        };
        // spinner를 ChatOut sink로 — TUI는 viewport tick arm(누적 없음), Direct는 stderr spinner.
        // (4d/4e에서 run_turn만 이전했고 이 분석 경로가 누락되어 TUI에서 spinner 프레임이 누적됐었음.)
        self.out.spin_start(label, amber).await;
        let result =
            tokio::time::timeout(LOCAL_ANALYZE_TIMEOUT, self.dispatcher.send(prompt)).await;
        self.out.spin_stop().await;

        match result {
            Ok(Ok(text)) => {
                let _ = crate::audit::append(
                    kind,
                    serde_json::json!({ "run_id": self.run_id, "analyzed": true }),
                );
                // 분석 결과는 slash 출력 규칙대로 stderr(stdout=LLM chat 답변 전용 불변).
                // TTY면 markdown subset을 ANSI/구조로 렌더, non-TTY(파이프)면 raw markdown(손실 0).
                let body = if ui::is_tty() {
                    super::markdown::render_markdown(
                        text.trim(),
                        ui::render_width(),
                        ui::color_enabled(),
                    )
                } else {
                    text.trim().to_string()
                };
                self.out.note(&format!("\n=== {heading} ===\n{body}")).await;
                // 분석을 history에 push해 후속 질문(왜/어떻게)을 같은 대화로 이을 수 있게 한다
                // (investigate F1 해소). 토큰 증가는 status의 ctx 표시 + /clear로 관리.
                self.history
                    .push(ChatMessage::User(format!("[{kind}] 진단 분석 요청")));
                self.history.push(ChatMessage::Assistant {
                    content: Some(text.clone()),
                    tool_calls: vec![],
                });
            }
            Ok(Err(e)) => {
                self.analysis_fallback(kind, &format!("provider 오류: {}", err_kind(&e)), snapshot)
                    .await
            }
            Err(_) => {
                self.analysis_fallback(
                    kind,
                    &format!("분석 timeout({}s)", LOCAL_ANALYZE_TIMEOUT.as_secs()),
                    snapshot,
                )
                .await
            }
        }
    }

    /// probe들을 개별 Safe 명령으로 실행해 **raw 본문 포함** 스냅샷(`## section\n<redacted out>`)을
    /// 만든다. 각 결과는 ring에 기록(/last·/raw 재조회). `print_bodies`면 본문도 stderr로 즉시 출력.
    async fn collect_local_snapshot(
        &mut self,
        probes: Vec<(&'static str, String)>,
        print_bodies: bool,
    ) -> String {
        use std::io::Write;
        let total = probes.len();
        // ephemeral `\r` 진행표시는 insert_before(줄 추가)와 충돌하므로 Direct sink일 때만.
        // analyze 모드(헤더/본문 미출력) + TTY일 때만 같은 줄을 overwrite하는 진행 표시.
        let show_progress = !print_bodies && self.out.is_direct() && ui::is_tty();
        let mut snapshot = String::new();
        for (idx, (name, cmd)) in probes.into_iter().enumerate() {
            self.tool_seq += 1;
            let corr = format!("{}.{}", self.run_id, self.tool_seq);
            if print_bodies {
                // raw 모드만 섹션 헤더/본문을 보인다.
                self.out.note(&format!("\n[{name}]")).await;
            } else if show_progress {
                // 현재 probe 진행 상태를 같은 줄에 갱신(ephemeral, Direct stderr 전용). NO_COLOR면 plain.
                let label = collect_progress_label(name, idx + 1, total);
                eprint!("\r\x1b[K{}", ui::paint(&label, "2"));
                let _ = std::io::stderr().flush();
            }
            let args = serde_json::json!({ "command": cmd });
            // Safe 명령이라 confirm은 호출되지 않지만, 비대화형 안전을 위해 거부 클로저 전달.
            // execute_with_corr가 (AIC_VERBOSE/AIC_DEBUG일 때만) command card를 출력, 결과는 redacted.
            let out =
                super::run_command::execute_with_corr(&args, &self.sandbox, &corr, |_, _, _| false)
                    .unwrap_or_else(|e| format!("[tool error] {e}"));
            if print_bodies {
                self.out.note(&out).await;
            }
            snapshot.push_str(&format!("## {name}\n{out}\n\n"));
            self.record_tool(&corr, "run_command", Some(cmd), &out);
        }
        if show_progress {
            // 진행 줄 정리(다음 단계의 분석 spinner와 겹치지 않게, Direct stderr 전용).
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        }
        snapshot
    }

    /// 분석 실패 시 — **실제 raw 증거 본문**(redacted)을 그대로 보여주고 짧은 사유만 표시.
    /// 색상은 ui::paint 정책(NO_COLOR/non-TTY면 plain)을 따른다. `/local`·`/diagnose` 공용.
    async fn analysis_fallback(&self, kind: &'static str, reason: &str, snapshot: &str) {
        adbg!("{kind} run={} fallback reason={}", self.run_id, reason);
        let _ = crate::audit::append(
            kind,
            serde_json::json!({ "run_id": self.run_id, "analyzed": false, "fallback": reason }),
        );
        // 사용자 친화 문구: provider/내부 사정 대신 "수집한 raw 증거를 보여준다"는 결과 중심.
        // 구체 사유(provider 오류/timeout 등)는 audit + AIC_DEBUG에만 남겨 출력을 시끄럽게 하지 않는다.
        self.out
            .note(&format!(
                "\n{}",
                ui::paint(
                    &format!("[{kind}] 분석을 완료하지 못해 수집한 raw 증거를 아래에 표시합니다."),
                    "33"
                )
            ))
            .await;
        if super::debug::enabled() {
            self.out
                .note(&ui::paint(&format!("  (사유: {reason})"), "2"))
                .await;
        }
        // 분석 모드에서는 본문을 안 찍었으므로, fallback 시 raw 증거(요약/cap된)를 출력한다.
        self.out.note(snapshot.trim_end()).await;
    }

    /// `/diagnose` — 증상→결정적 Safe probe 선택→수집→가설/증거/다음확인 분석(read-only).
    /// `/local`과 동일 철학: probe 선택은 호스트가 결정, 분석은 tool-less·stateless 단발(history 미push).
    async fn handle_diagnose(&mut self, symptom: Option<&str>, analyze: bool) {
        if !self.allow_run_command {
            self.out
                .note(
                    "/diagnose는 run_command가 필요합니다 — 현재 read-only 세션(--no-run/--read-only/\
                     AIC_AGENT_NO_RUN)이라 비활성입니다.",
                )
                .await;
            return;
        }
        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());
        let probes =
            super::diagnose::select_probes(symptom, super::diagnose::docker_available());
        self.out
            .note(&format!(
                "=== diagnose: {} ===",
                symptom.unwrap_or("(generic health)")
            ))
            .await;
        let mut snapshot = self.collect_local_snapshot(probes, !do_analyze).await;
        // 결정적 임계 스캔(LLM 무관 즉시 신호) — 대화형에도 노출(headless와 동등). 발견을 사용자에게
        // 표시하고, analyze면 LLM evidence 상단에도 prepend해 진단을 그 신호 위에서 시작하게 한다.
        let findings = super::diagnose::scan_findings(&snapshot);
        let block = super::diagnose::render_findings_block(&findings);
        if !block.is_empty() {
            self.out.note(&format!("\n{}", block.trim_end())).await;
            // prepend는 LLM 프롬프트 evidence용 — analyze 모드에서만(raw는 표시만 하고 곧 return).
            if do_analyze {
                snapshot.insert_str(0, &format!("{block}\n"));
            }
        }
        if !do_analyze {
            return;
        }
        let prompt = super::diagnose::build_diagnose_prompt(symptom, &snapshot);
        self.run_analysis(
            &snapshot,
            &prompt,
            "diagnose",
            analyze_status_label("증거", self.provider.as_deref()),
            "diagnosis",
        )
        .await;
    }

    /// `/explain-last [--raw] [seq|corr]` — 최근(또는 지정) tool 기록을 증거로 원인/다음확인 분석.
    /// 새 명령을 실행하지 않으므로 read-only 세션에서도 동작한다(이미 ring에 redacted 기록).
    async fn handle_explain_last(&mut self, target: Option<&str>, analyze: bool) {
        let evidence = match tool_record::record_evidence(&self.tool_records, target) {
            Some(e) => e,
            None => {
                self.out
                    .note(
                        "설명할 tool 기록이 없습니다. 먼저 명령을 실행하거나 /local·/diagnose로 증거를 \
                         만든 뒤 다시 시도하세요.",
                    )
                    .await;
                return;
            }
        };
        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());
        if !do_analyze {
            self.out
                .note(&format!("=== explain-last (raw evidence) ===\n{}", evidence))
                .await;
            return;
        }
        let prompt = tool_record::build_explain_last_prompt(&evidence);
        self.run_analysis(
            &evidence,
            &prompt,
            "explain-last",
            analyze_status_label("기록", self.provider.as_deref()),
            "explain-last",
        )
        .await;
    }

    /// `/incident [--raw] [name]` — 시스템 스냅샷 + git(repo) + 최근 기록을 묶어 분석. name은 라벨 전용.
    async fn handle_incident(&mut self, name: Option<&str>, analyze: bool) {
        if !self.allow_run_command {
            self.out
                .note(
                    "/incident는 run_command가 필요합니다 — 현재 read-only 세션(--no-run/--read-only/\
                     AIC_AGENT_NO_RUN)이라 비활성입니다.",
                )
                .await;
            return;
        }
        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());
        self.out
            .note(&format!("=== incident: {} ===", name.unwrap_or("(unnamed)")))
            .await;

        // raw 모드는 full 출력(print_bodies=true)을 보이고, analyze 모드는 조용히 수집한 뒤
        // **bounded** evidence로 분석한다(과대 evidence로 인한 provider parsing/context 오류 방지).
        let sys_raw = self
            .collect_local_snapshot(super::sysinfo::local_probes(), !do_analyze)
            .await;
        let git_raw = if self.sandbox.root().join(".git").exists() {
            Some(
                self.collect_local_snapshot(super::probes::by_category("git"), !do_analyze)
                    .await,
            )
        } else {
            None
        };

        if !do_analyze {
            // raw 모드: 본문은 collect가 이미 출력했고, 최근 기록만 추가 표시.
            let recent = tool_record::recent_records_evidence(&self.tool_records, 10);
            self.out
                .note(&format!("\n# recent tool records\n{recent}"))
                .await;
            return;
        }

        // analyze evidence: 섹션별 line cap으로 핵심(date/host/os/uptime/disk/memory/ip/route/ports)은
        // 보존하되 각 섹션을 짧게, 최근 기록은 적게, 마지막에 전체 byte cap.
        let mut evidence = String::from("# system\n");
        evidence.push_str(&cap_section_lines(&sys_raw, INCIDENT_SECTION_MAX_LINES));
        if let Some(git) = git_raw {
            evidence.push_str("\n# git\n");
            evidence.push_str(&cap_section_lines(&git, INCIDENT_SECTION_MAX_LINES));
        }
        evidence.push_str("\n# recent tool records\n");
        evidence.push_str(&tool_record::recent_records_evidence(
            &self.tool_records,
            INCIDENT_RECENT_RECORDS,
        ));
        let evidence = cap_evidence(&evidence, INCIDENT_EVIDENCE_MAX_BYTES);

        let prompt = tool_record::build_incident_prompt(name, &evidence);
        self.run_analysis(
            &evidence,
            &prompt,
            "incident",
            analyze_status_label("증거", self.provider.as_deref()),
            "incident",
        )
        .await;
    }

    /// `/doctor` — AIC 자체 상태를 secret 값 없이(presence-only) 표시한다. LLM/명령 실행 없음.
    async fn handle_doctor(&self) {
        let flags = [
            // AIC_DEBUG는 truthy(1|true)만 ON으로 통일 — 0/false/off는 OFF 표기.
            ("AIC_DEBUG", super::debug::enabled()),
            (
                "AIC_AGENT_NO_RUN",
                std::env::var_os("AIC_AGENT_NO_RUN").is_some(),
            ),
            (
                "AIC_LOCAL_NO_ANALYZE",
                std::env::var_os("AIC_LOCAL_NO_ANALYZE").is_some(),
            ),
            ("NO_COLOR", std::env::var_os("NO_COLOR").is_some()),
            ("AIC_REDACT", std::env::var_os("AIC_REDACT").is_some()),
        ];
        let report = tool_record::build_doctor_report(
            self.provider.as_deref(),
            self.model.as_deref(),
            self.dispatcher.supports_tool_calling(),
            self.allow_run_command,
            crate::audit::audit_key_backend(),
            &flags,
        );
        let body = if ui::is_tty() {
            super::markdown::render_markdown(&report, ui::render_width(), ui::color_enabled())
        } else {
            report
        };
        self.out.note(&format!("\n=== aic doctor ===\n{body}")).await;
    }

    /// `/fix` — 직전 대화·진단 맥락에서 지금 실행하면 좋을 **안전한 명령 하나**를 run_command로
    /// 제안·실행하도록 LLM에 턴을 위임한다. run_command가 비활성(read-only)이면 안내만 하고 종료한다.
    /// 활성이면 사용자 메시지를 history에 push한 뒤 `run_turn`을 돌린다 — LLM이 run_command tool_call을
    /// 내면 `exec_tool`이 risk 선평가 + confirm UI(기능 A)를 거쳐 실행/거부한다(상태 변경은 확인 후).
    async fn handle_fix(&mut self) {
        if !self.allow_run_command {
            self.out
                .note("`/fix`는 run_command가 필요합니다 — read-only 세션에서는 비활성입니다.")
                .await;
            return;
        }
        self.history.push(ChatMessage::User(
            "직전 대화·진단 맥락에서 지금 실행하면 좋을 안전한 명령 하나를 run_command 도구로 \
             실행해줘. 상태 변경이 위험하면 실행하지 말고 이유를 설명해줘."
                .to_string(),
        ));
        if let Err(e) = self.run_turn().await {
            self.out.note(&format!("LLM 요청 실패: {e}")).await;
        }
    }

    /// `/compare` — 고정 Safe probe로 현재 시스템 스냅샷을 만들고 직전 baseline과 diff(LLM 미호출).
    /// 첫 호출은 baseline만 저장. 이후 diff 출력 후 baseline 갱신.
    async fn handle_compare(&mut self) {
        if !self.allow_run_command {
            self.out
                .note("/compare는 run_command가 필요합니다 — 현재 read-only 세션이라 비활성입니다.")
                .await;
            return;
        }
        let snapshot = self
            .collect_local_snapshot(super::sysinfo::local_probes(), false)
            .await;
        // 영구 기록 opt-in(스냅샷 레코더 L0): /compare 스냅샷을 시계열 store(~/.aic/snapshots)에 append한다.
        // 기본 off(AIC_SNAPSHOT_RECORD). best-effort — 실패해도 /compare는 진행한다. 연속/이상-트리거는 후속(L1+).
        if crate::snapshot_store::record_enabled() {
            let cwd = std::env::current_dir().ok().map(|p| p.display().to_string());
            let rec = crate::snapshot_store::SnapshotRecord::new(
                "compare",
                &snapshot,
                None,
                cwd,
                chrono::Utc::now(),
            );
            if let Err(e) = crate::snapshot_store::append_snapshot(&rec) {
                adbg!("snapshot_store append failed: {e}");
            }
        }
        match self.compare_baseline.take() {
            None => {
                self.out
                    .note("baseline 스냅샷을 저장했습니다. 잠시 후 다시 /compare로 변화를 확인하세요.")
                    .await;
                self.compare_baseline = Some(snapshot);
            }
            Some(old) => {
                // 엔티티 set diff(신규 listening 포트·실패 유닛)를 결정적으로 추출해 라인 diff 위에 ⚠로 표면화.
                let findings = super::diagnose::scan_baseline_findings(&old, &snapshot);
                // baseline 엔티티 diff는 임계 스캔이 아니므로 맥락에 맞는 헤더를 쓴다.
                let block = super::diagnose::render_findings_block_with(
                    &findings,
                    "## ⚠ baseline 대비 신규 엔티티",
                );
                let report = tool_record::compare_report(&old, &snapshot);
                let body = if block.is_empty() {
                    report
                } else {
                    format!("{}\n{report}", block.trim_end())
                };
                self.out
                    .note(&format!("\n=== compare (직전 baseline 대비) ===\n{body}"))
                    .await;
                self.compare_baseline = Some(snapshot);
            }
        }
    }

    /// `/watch [target] [--count N] [--every Ns]` — local probe를 bounded하게 반복 실행하고
    /// 각 tick마다 직전 대비 변화 라인 수를 compact하게 보여준다. 무한 watch 없음(count clamp).
    /// run_command 안전정책·local probe(Safe 카탈로그) 재사용, LLM 미호출.
    async fn handle_watch(&mut self, target: Option<&str>, count: usize, every_ms: u64) {
        if !self.allow_run_command {
            self.out
                .note("/watch는 run_command가 필요합니다 — 현재 read-only 세션이라 비활성입니다.")
                .await;
            return;
        }
        // unknown target은 조용히 compact로 fallback하지 않고 명확히 거부 + 사용 가능 섹션 안내.
        if let Some(msg) = watch_target_error(target) {
            self.out.note(&msg).await;
            return;
        }
        let probes = watch_probes(target);
        if probes.is_empty() {
            self.out.note("watch할 probe가 없습니다.").await;
            return;
        }
        let label = target.unwrap_or("local(compact)");
        self.out
            .note(&format!(
                "=== watch: {label} ({count}회, {every_ms}ms 간격) ==="
            ))
            .await;
        let interval = std::time::Duration::from_millis(every_ms);
        let mut prev: Option<String> = None;
        for i in 1..=count {
            let snap = self.collect_local_snapshot(probes.clone(), false).await;
            let digest = match &prev {
                None => "baseline".to_string(),
                Some(p) => format!("{} 라인 변동", tool_record::changed_line_count(p, &snap)),
            };
            self.out
                .note(&ui::paint(&format!("[watch {i}/{count}] {digest}"), "2"))
                .await;
            prev = Some(snap);
            if i < count {
                tokio::time::sleep(interval).await;
            }
        }
        self.out.note(&format!("watch 완료({count} ticks).")).await;
    }

    /// `/watch arm|on|off|mute` — proactive 알림 레인(C7)을 켜고 끈다. TUI의 alert tracker를 토글한다
    /// (실제 상태는 ChatLoop가 보유 — OutMsg::AlertsArmed로 전달). 끄면 edge alert·sparkline 추세
    /// 알림이 표시되지 않는다. Direct 모드엔 alert 레인이 없어 안내만 한다.
    async fn handle_alert_lane(&mut self, on: bool) {
        self.out.alerts_armed(on).await;
        let msg = if on {
            "알림 레인 ON — 시스템 자원이 위험 단계로 올라가면 대화에 한 줄로 알립니다 (/watch off로 끄기)"
        } else {
            "알림 레인 OFF — proactive 알림을 표시하지 않습니다 (/watch arm으로 켜기)"
        };
        self.out.note(msg).await;
    }

    /// `/bundle [name]` — 인시던트 증거(시스템+git+최근 기록)를 redacted markdown으로 파일 저장.
    /// name은 파일 라벨 전용(셸 명령에 미포함). dir 0700 / file 0600(unix best-effort).
    async fn handle_bundle(&mut self, name: Option<&str>) {
        if !self.allow_run_command {
            self.out
                .note("/bundle은 run_command가 필요합니다 — 현재 read-only 세션이라 비활성입니다.")
                .await;
            return;
        }
        // 증거 수집(화면 본문 출력 없이 파일용으로만; collect는 redacted + ring 기록).
        let mut evidence = String::from("# system\n");
        evidence.push_str(
            &self
                .collect_local_snapshot(super::sysinfo::local_probes(), false)
                .await,
        );
        if self.sandbox.root().join(".git").exists() {
            let git_probes = super::probes::by_category("git");
            evidence.push_str("\n# git\n");
            evidence.push_str(&self.collect_local_snapshot(git_probes, false).await);
        }
        evidence.push_str("\n# recent tool records\n");
        evidence.push_str(&tool_record::recent_records_evidence(
            &self.tool_records,
            20,
        ));

        match super::bundle::write_bundle(name, &evidence) {
            Ok(path) => self.out.note(&format!("\nbundle 저장됨: {}", path.display())).await,
            Err(e) => self.out.note(&format!("\nbundle 저장 실패: {e}")).await,
        }
    }

    /// `/rca ...` — persistent RCA workspace를 chat 안에서 조작한다.
    async fn handle_rca(&mut self, cmd: tool_record::RcaCommand) {
        use crate::rca::{self, EvidenceKind};
        use tool_record::RcaCommand;

        match cmd {
            RcaCommand::Start { title } => {
                let cwd = std::env::current_dir().ok();
                match rca::create_incident(&title, Some(&title), cwd.as_deref()) {
                    Ok(meta) => {
                        self.active_rca_id = Some(meta.id.clone());
                        self.out
                            .note(&format!(
                                "RCA 시작: {}\n경로: {}",
                                meta.id,
                                rca::incident_dir(&meta.id).display()
                            ))
                            .await;
                    }
                    Err(e) => self.out.note(&format!("RCA 시작 실패: {e}")).await,
                }
            }
            RcaCommand::Use { id } => match rca::resolve_id(Some(&id)) {
                Ok(resolved) => {
                    self.active_rca_id = Some(resolved.clone());
                    match rca::load_meta(&resolved) {
                        Ok(meta) => {
                            self.out
                                .note(&format!(
                                    "active RCA: {}\n{}",
                                    resolved,
                                    rca::render_status(&meta)
                                ))
                                .await;
                        }
                        Err(e) => self.out.note(&format!("RCA 로드 실패: {e}")).await,
                    }
                }
                Err(e) => self.out.note(&format!("RCA 선택 실패: {e}")).await,
            },
            RcaCommand::Status { id } => {
                let id = id.or_else(|| self.active_rca_id.clone());
                if let Some(id) = id {
                    match rca::resolve_id(Some(&id)).and_then(|rid| rca::load_meta(&rid)) {
                        Ok(meta) => {
                            self.active_rca_id = Some(meta.id.clone());
                            self.out.note(&rca::render_status(&meta)).await;
                        }
                        Err(e) => self.out.note(&format!("RCA 상태 조회 실패: {e}")).await,
                    }
                } else {
                    match rca::list_incidents() {
                        Ok(list) if list.is_empty() => {
                            self.out
                                .note("RCA incident가 없습니다. `/rca start <title>`로 시작하세요.")
                                .await;
                        }
                        Ok(list) => {
                            let mut lines = vec!["최근 RCA incidents:".to_string()];
                            for item in list.iter().take(10) {
                                lines.push(format!(
                                    "- {} · {:?} · {} · evidence={} · updated={}",
                                    item.id,
                                    item.status,
                                    item.title,
                                    item.evidence_count,
                                    item.updated_at.to_rfc3339()
                                ));
                            }
                            self.out.note(&lines.join("\n")).await;
                        }
                        Err(e) => self.out.note(&format!("RCA 목록 조회 실패: {e}")).await,
                    }
                }
            }
            RcaCommand::AddLast { count } => {
                let Some(body) = self.rca_recent_tool_evidence(count) else {
                    self.out
                        .note("저장할 tool 기록이 없습니다. 먼저 진단 명령을 실행하세요.")
                        .await;
                    return;
                };
                match self.resolve_active_rca_id().and_then(|id| {
                    let mut meta = rca::load_meta(&id)?;
                    let event = rca::append_evidence(
                        &mut meta,
                        EvidenceKind::Timeline,
                        &format!("chat tool records (last {count})"),
                        "aic chat /rca add last",
                        &body,
                        &["chat", "tool"],
                    )?;
                    Ok((meta.id, event.id))
                }) {
                    Ok((id, ev)) => {
                        self.active_rca_id = Some(id.clone());
                        self.out
                            .note(&format!("RCA {id}에 evidence 저장: {ev}"))
                            .await;
                    }
                    Err(e) => self.out.note(&format!("RCA evidence 저장 실패: {e}")).await,
                }
            }
            RcaCommand::AddNote { text } => {
                if text.trim().is_empty() {
                    self.out
                        .note("note가 비었습니다. 예: /rca add note deploy 이후 p99 상승 확인")
                        .await;
                    return;
                }
                match self.resolve_active_rca_id().and_then(|id| {
                    let mut meta = rca::load_meta(&id)?;
                    let event = rca::append_evidence(
                        &mut meta,
                        EvidenceKind::Note,
                        "chat note",
                        "aic chat /rca add note",
                        &text,
                        &["chat", "note"],
                    )?;
                    Ok((meta.id, event.id))
                }) {
                    Ok((id, ev)) => {
                        self.active_rca_id = Some(id.clone());
                        self.out.note(&format!("RCA {id}에 note 저장: {ev}")).await;
                    }
                    Err(e) => self.out.note(&format!("RCA note 저장 실패: {e}")).await,
                }
            }
            RcaCommand::Timeline { id } => {
                match self.resolve_rca_id_for_read(id.as_deref()).and_then(|rid| {
                    let meta = rca::load_meta(&rid)?;
                    let events = rca::load_events(&rid)?;
                    Ok((meta, events))
                }) {
                    Ok((meta, events)) => {
                        self.active_rca_id = Some(meta.id.clone());
                        self.out.note(&rca::render_timeline(&meta, &events)).await;
                    }
                    Err(e) => self.out.note(&format!("RCA timeline 조회 실패: {e}")).await,
                }
            }
            RcaCommand::Report { id, write } => {
                match self.resolve_rca_id_for_read(id.as_deref()).and_then(|rid| {
                    let meta = rca::load_meta(&rid)?;
                    let events = rca::load_events(&rid)?;
                    let report = rca::render_report(&meta, &events);
                    let path = if write {
                        Some(rca::write_report(&meta, &report)?)
                    } else {
                        None
                    };
                    Ok((meta, report, path))
                }) {
                    Ok((meta, report, path)) => {
                        self.active_rca_id = Some(meta.id.clone());
                        let suffix = path
                            .map(|p| format!("\nreport 저장됨: {}", p.display()))
                            .unwrap_or_default();
                        self.out.note(&format!("{report}{suffix}")).await;
                    }
                    Err(e) => self.out.note(&format!("RCA report 생성 실패: {e}")).await,
                }
            }
        }
    }

    fn resolve_active_rca_id(&self) -> anyhow::Result<String> {
        match self.active_rca_id.as_deref() {
            Some(id) => crate::rca::resolve_id(Some(id)),
            None => crate::rca::resolve_id(None),
        }
    }

    fn resolve_rca_id_for_read(&self, id: Option<&str>) -> anyhow::Result<String> {
        match id {
            Some(id) => crate::rca::resolve_id(Some(id)),
            None => self.resolve_active_rca_id(),
        }
    }

    fn rca_recent_tool_evidence(&self, count: usize) -> Option<String> {
        if self.tool_records.is_empty() {
            return None;
        }
        let count = count.clamp(1, self.tool_records.len());
        let skip = self.tool_records.len().saturating_sub(count);
        let mut out = String::new();
        for rec in self.tool_records.iter().skip(skip) {
            let cmd = rec
                .command_display
                .as_deref()
                .map(|c| format!("\ncommand: {c}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "## tool [{}] {} ({}){}\n{}\n\n",
                rec.corr, rec.name, rec.status, cmd, rec.output
            ));
        }
        Some(out)
    }

    /// `/triage [--run] [topic]` — 토픽별 read-only 체크리스트 + 후보 probe를 stderr로 렌더.
    /// `run`이면 (run_command 활성 시) 후보 probe를 실행해 redacted evidence를 보여준다. LLM 미호출.
    /// topic은 라벨 선택에만 쓰고 셸 명령에 섞지 않는다(probe는 catalog의 고정 상수).
    async fn handle_triage(&mut self, topic: Option<&str>, run: bool) {
        let plan = super::probes::triage_plan(topic);
        let probes = super::probes::resolve_ids(plan.probe_ids);

        self.out
            .note(&format!(
                "=== triage: {} (topic: {}) ===",
                plan.label, plan.resolved
            ))
            .await;
        self.out.note("\n[checklist]").await;
        for item in plan.checklist {
            self.out.note(&format!("  - {item}")).await;
        }
        self.out.note("\n[candidate probes]").await;
        for (id, cmd) in &probes {
            if let Some(p) = super::probes::probe_by_id(id) {
                let bound = match p.max_lines {
                    Some(n) => format!(" (≤{n} lines)"),
                    None => String::new(),
                };
                self.out
                    .note(&format!(
                        "  - {id} [{}]: {}{bound}  →  {cmd}",
                        p.tags.join(","),
                        p.description
                    ))
                    .await;
            } else {
                self.out.note(&format!("  - {id}  →  {cmd}")).await;
            }
        }

        if !run {
            self.out
                .note(&format!(
                    "\n(--run 으로 위 probe를 실행해 redacted 증거를 볼 수 있습니다. LLM 호출 없음. \
                     topics: {})",
                    super::probes::TRIAGE_TOPICS.join(" ")
                ))
                .await;
            return;
        }
        if !self.allow_run_command {
            self.out
                .note(
                    "\n--run은 run_command가 필요합니다 — 현재 read-only 세션(--no-run/--read-only/\
                     AIC_AGENT_NO_RUN)이라 probe를 실행하지 않습니다.",
                )
                .await;
            return;
        }
        self.out
            .note("\n=== triage evidence (read-only, redacted) ===")
            .await;
        // collect_local_snapshot은 redaction/timeout/cap/corr/ring을 그대로 적용한다. LLM 미전송.
        let _ = self.collect_local_snapshot(probes, true).await;
    }

    /// 컨텍스트 토큰 **추정치** — provider 응답에 usage가 없어 history의 모든 메시지 content
    /// 문자 수 합을 4로 나눈 근사값(영문 ≈4자/토큰)을 쓴다. tool_calls 자체(인자 JSON)는 제외하고
    /// Assistant content·Tool content만 센다(표시용 근사라 정밀도보다 일관성 우선).
    fn estimate_tokens(&self) -> usize {
        let chars: usize = self
            .history
            .iter()
            .map(|m| match m {
                ChatMessage::System(c) | ChatMessage::User(c) => c.chars().count(),
                ChatMessage::Assistant { content, .. } => {
                    content.as_ref().map(|c| c.chars().count()).unwrap_or(0)
                }
                ChatMessage::Tool { content, .. } => content.chars().count(),
            })
            .sum();
        chars / 4
    }

    /// 사용자 입력에 언어 지시 + (첫 턴) 직전 명령 컨텍스트를 붙인다.
    fn build_user_message(&mut self, input: &str) -> String {
        let mut text = format!("{input}\n\n{}", repl::lang_instruction(&self.lang));
        if self.first_turn {
            if let Some(ctx) = repl::format_first_turn_prefix(&self.context) {
                text = format!("{ctx}{text}");
            }
            self.first_turn = false;
        }
        text
    }

    /// 세션 종료 시 대화를 `~/.aic/sessions/last.json`에 저장한다(`/resume`로 복원).
    /// User/Assistant(content) 메시지만 추출하며, 추출 결과가 비면(대화 없음) 파일을 만들지 않는다.
    /// dir 0700 / file 0600(unix best-effort). 직렬화/IO 실패는 무시한다(best-effort, 출력 없음).
    fn save_session(&self) {
        let messages = history_to_session_values(&self.history);
        if messages.is_empty() {
            return; // 대화 없음 — 저장 skip(파일 안 만듦).
        }
        let Some(path) = session_file_path() else {
            return; // 홈 디렉터리 미발견 — best-effort로 무시.
        };
        let Some(dir) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let Ok(body) = serde_json::to_string_pretty(&messages) else {
            return;
        };
        if std::fs::write(&path, body).is_err() {
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }

    /// `/resume` — 이전 세션 대화(`~/.aic/sessions/last.json`)를 history에 append 복원한다.
    /// 파일 없음/파싱 실패는 "복원할 이전 세션이 없습니다." 안내. LLM 미호출.
    async fn handle_resume(&mut self) {
        let restored = session_file_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s).ok())
            .map(|values| session_values_to_messages(&values));
        match restored {
            Some(msgs) if !msgs.is_empty() => {
                let n = msgs.len();
                self.history.extend(msgs);
                self.out
                    .note(&format!("이전 세션 {n}개 메시지를 복원했습니다."))
                    .await;
            }
            _ => {
                self.out.note("복원할 이전 세션이 없습니다.").await;
            }
        }
    }
}

/// `/local` 분석 단발 LLM 호출의 최대 대기 시간(초). 초과 시 raw fallback.
const LOCAL_ANALYZE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `/incident` analyze evidence 바운드 — 과대 evidence로 인한 provider parsing/context 오류 방지.
/// 섹션(=probe)별 본문 최대 줄 수(핵심 섹션은 모두 보존하되 각 섹션을 짧게).
const INCIDENT_SECTION_MAX_LINES: usize = 12;
/// 최근 tool 기록 포함 개수(작게).
const INCIDENT_RECENT_RECORDS: usize = 8;
/// 조립된 evidence 전체 byte 상한(안전망).
const INCIDENT_EVIDENCE_MAX_BYTES: usize = 8 * 1024;

/// `## section\n<body>` 블록들에서 각 섹션 본문을 최대 `max_lines`줄로 자른다(순수, 테스트 가능).
/// 섹션 헤더(`## name`)·빈 줄 구분은 보존해 모든 핵심 섹션이 남되 각 섹션을 짧게 만든다.
fn cap_section_lines(snapshot: &str, max_lines: usize) -> String {
    let mut out = String::new();
    let mut body_lines = 0usize;
    let mut elided = false;
    for line in snapshot.lines() {
        if line.starts_with("## ") {
            out.push_str(line);
            out.push('\n');
            body_lines = 0;
            elided = false;
        } else if line.trim().is_empty() {
            out.push('\n');
        } else if body_lines < max_lines {
            out.push_str(line);
            out.push('\n');
            body_lines += 1;
        } else if !elided {
            out.push_str("…\n");
            elided = true;
        }
    }
    out
}

/// `/watch` 대상 probe 목록 — 단일 섹션(유효 + Safe 카탈로그) 지정 시 그 probe만, 아니면
/// compact 기본 세트(uptime/memory/disk; 가장 변동이 잦은 자원). 모두 catalog의 고정 Safe 상수.
/// `/watch` 대상 검증(순수) — None/유효 섹션은 OK(None), 그 외는 거부 안내 메시지(Some).
/// parse 단계에서 `local`은 None으로 정규화되므로 Some(t)는 항상 non-`local` 토큰이다.
fn watch_target_error(target: Option<&str>) -> Option<String> {
    match target {
        None => None,
        // catalog의 모든 probe를 watch 대상으로 허용한다(LOCAL 섹션 + docker_df/tmp_recent 등).
        Some(t) if super::probes::probe_by_id(t).is_some() => None,
        Some(t) => Some(format!(
            "알 수 없는 watch 대상 '{t}'. 사용 가능: local(기본 compact), LOCAL 섹션({}), \
             또는 catalog probe(docker_df/docker_ps/tmp_big/tmp_recent 등)",
            super::sysinfo::LOCAL_SECTIONS.join(" ")
        )),
    }
}

fn watch_probes(target: Option<&str>) -> Vec<(&'static str, String)> {
    if let Some(t) = target {
        // LOCAL 섹션뿐 아니라 catalog 전체 probe를 watch할 수 있다(tmp_recent로 늘어나는 파일 추적 등).
        if let Some(p) = super::probes::probe_by_id(t) {
            return vec![(p.id, p.command())];
        }
    }
    ["uptime", "memory", "disk"]
        .iter()
        .filter_map(|n| super::probes::probe_by_id(n).map(|p| (p.id, p.command())))
        .collect()
}

/// evidence 전체를 `max_bytes`로 UTF-8 경계 안전하게 자른다(순수, 테스트 가능).
fn cap_evidence(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…", &text[..end])
}

/// history에서 세션 재개용 메시지만 추출해 `[{role,content}]` JSON 배열로 만든다(순수, 테스트 가능).
/// 대상: `User(content)`와 `Assistant{content:Some(c)}`만. System preface·Tool 결과·tool_calls-only
/// Assistant(content=None)는 제외한다(재개 시 대화 흐름만 복원하고 도구 사이클은 버린다).
fn history_to_session_values(history: &[ChatMessage]) -> Vec<serde_json::Value> {
    history
        .iter()
        .filter_map(|m| match m {
            ChatMessage::User(c) => Some(serde_json::json!({ "role": "user", "content": c })),
            ChatMessage::Assistant {
                content: Some(c), ..
            } => Some(serde_json::json!({ "role": "assistant", "content": c })),
            _ => None,
        })
        .collect()
}

/// 저장된 `[{role,content}]` 값을 `ChatMessage`로 복원한다(순수, 테스트 가능).
/// role=user → `User(content)`, role=assistant → `Assistant{content:Some(content), tool_calls:[]}`.
/// role/content가 없거나 알 수 없는 role 항목은 건너뛴다(best-effort, 손상 항목 무시).
fn session_values_to_messages(values: &[serde_json::Value]) -> Vec<ChatMessage> {
    values
        .iter()
        .filter_map(|v| {
            let role = v.get("role").and_then(|r| r.as_str())?;
            let content = v.get("content").and_then(|c| c.as_str())?.to_string();
            match role {
                "user" => Some(ChatMessage::User(content)),
                "assistant" => Some(ChatMessage::Assistant {
                    content: Some(content),
                    tool_calls: vec![],
                }),
                _ => None,
            }
        })
        .collect()
}

/// 세션 저장 파일 경로(`~/.aic/sessions/last.json`). 홈을 못 찾으면 None.
fn session_file_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".aic").join("sessions").join("last.json"))
}

/// `/bundle` — redacted 증거를 `~/.aic/bundles/<sanitized>-<ts>.md`에 저장하고 경로를 반환한다.
/// name은 파일명 라벨(sanitize)로만 쓰고 셸 명령에 섞지 않는다. dir 0700 / file 0600(unix best-effort).
/// 수집 진행 라벨(순수) — analyze 모드에서 probe별 같은 줄 갱신용. 짧은 Claude-like 톤.
/// 예: `<thinking> 수집 중: date (1/9)`.
fn collect_progress_label(name: &str, idx: usize, total: usize) -> String {
    format!("<thinking> 수집 중: {name} ({idx}/{total})")
}

/// 분석 spinner 라벨 — Claude-like 짧은 `<thinking>` 톤. provider명이 있으면 전송 투명성을 위해
/// 괄호로 덧붙인다(`noun`=스냅샷/증거/기록 등). spinner는 ephemeral(완료 시 정리).
fn analyze_status_label(noun: &str, provider: Option<&str>) -> String {
    match provider {
        Some(p) if !p.is_empty() => format!("<thinking> redacted {noun} 분석 중… ({p})"),
        _ => format!("<thinking> redacted {noun} 분석 중…"),
    }
}

/// `AIC_LOCAL_NO_ANALYZE=1|true`이면 `/local`을 raw fallback처럼 동작시킨다(분석 opt-out).
fn env_local_no_analyze() -> bool {
    std::env::var("AIC_LOCAL_NO_ANALYZE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// 세션 correlation id(run). 시계열 nanos 하위 32비트를 8자리 hex로 — 로그 추적용
/// (충돌 내성보다 가독성 우선, 외부 dependency 없이 생성).
fn new_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:08x}", (nanos as u64) & 0xffff_ffff)
}

/// run_command 결과 문자열의 `command: <redacted>` 줄에서 표시용 command를 뽑는다.
/// (이미 redacted된 출력에서만 추출 — secrets 원문 미보관.) 없으면 None.
fn extract_command_line(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| l.strip_prefix("command: "))
        .map(|s| s.to_string())
}

/// provider가 `tools` 파라미터를 거부한 것으로 보이는 에러인지 분류한다.
///
/// 보수적으로: 4xx 클라이언트 에러(잘못된 요청 파라미터 — 보통 400/404/405/422)나
/// OpenAI-compat이 아니라는 ConfigError를 "tools 미지원"으로 간주해 degrade한다.
/// 단, 인증(401/403)·rate limit(429)·서버측 일시 오류(5xx)·네트워크(status 0)는
/// degrade하지 않고 그대로 surface한다(실제 문제이거나 재시도 대상).
fn is_tools_unsupported(e: &AicError) -> bool {
    match e {
        AicError::ConfigError(_) => true,
        AicError::LlmApiError { status, .. } => {
            matches!(status, 400 | 404 | 405 | 415 | 422 | 501)
        }
        _ => false,
    }
}

/// 에러의 종류/상태만 반환한다(메시지 본문은 제외 — debug 로그에 내용 누출 방지).
fn err_kind(e: &AicError) -> String {
    match e {
        AicError::ConfigError(_) => "ConfigError".to_string(),
        AicError::ApiKeyMissing { .. } => "ApiKeyMissing".to_string(),
        AicError::LlmApiError { status, .. } => format!("LlmApiError({status})"),
        other => {
            // 다른 variant는 이름만 (Debug 표현에서 첫 토큰만 취해 본문 제외).
            let dbg = format!("{other:?}");
            dbg.split([' ', '(', '{'])
                .next()
                .unwrap_or("Error")
                .to_string()
        }
    }
}

/// 문자열을 최대 바이트로 자른다(char 경계 보존). 잘리면 안내를 덧붙인다.
fn cap_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…[tool 결과 truncated: {} bytes]", &s[..end], s.len())
}

/// 미리보기에서 한 줄 길이를 자를 char 상한.
const WRITE_PREVIEW_STR_CAP: usize = 200;
/// write_file 미리보기에서 보여줄 본문 앞부분 라인 수.
const WRITE_PREVIEW_HEAD_LINES: usize = 10;

/// char 경계를 지키며 문자열을 최대 길이로 자른다(미리보기 전용).
fn cap_preview_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let body: String = s.chars().take(max).collect();
    format!("{body}…")
}

/// 쓰기 도구의 변경 미리보기를 만든다(실제 쓰기 전 note로 출력). 외부 diff crate 없이
/// 간단 라인 표시(MVP). 파일 읽기 실패는 새 파일로 간주한다(secrets/경계는 confirm 후 거부).
fn build_write_preview(name: &str, args: &serde_json::Value, sandbox: &Sandbox) -> String {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    match name {
        "write_file" => {
            let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let new_lines = content.lines().count();
            // 대상 파일 존재 여부는 resolve_for_write로 검증된 경로의 read로 판단(실패=새 파일).
            let existing = sandbox
                .resolve_for_write(path)
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok());
            let header = match &existing {
                Some(old) => {
                    let old_lines = old.lines().count();
                    format!("[write_file] {path} 덮어쓰기 ({old_lines}줄 → {new_lines}줄)")
                }
                None => format!("[write_file] 새 파일 {path} ({new_lines}줄)"),
            };
            let head: Vec<String> = content
                .lines()
                .take(WRITE_PREVIEW_HEAD_LINES)
                .map(|l| format!("  {}", cap_preview_str(l, WRITE_PREVIEW_STR_CAP)))
                .collect();
            let mut out = header;
            if !head.is_empty() {
                out.push('\n');
                out.push_str(&head.join("\n"));
            }
            if new_lines > WRITE_PREVIEW_HEAD_LINES {
                out.push_str(&format!(
                    "\n  …[{}줄 더]",
                    new_lines - WRITE_PREVIEW_HEAD_LINES
                ));
            }
            out
        }
        "edit_file" => {
            let old_string = args.get("old_string").and_then(|v| v.as_str()).unwrap_or("");
            let new_string = args.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
            format!(
                "[edit_file] {path}\n- {}\n+ {}",
                cap_preview_str(old_string, WRITE_PREVIEW_STR_CAP),
                cap_preview_str(new_string, WRITE_PREVIEW_STR_CAP)
            )
        }
        other => format!("[{other}] {path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::types::parse_openai_response;
    use serde_json::json;
    use std::fs;

    #[test]
    fn cap_bytes_truncates_large() {
        let s = "a".repeat(100);
        let out = cap_bytes(&s, 10);
        assert!(out.contains("truncated"));
        assert!(out.starts_with("aaaaaaaaaa\n"));
    }

    #[test]
    fn cap_bytes_keeps_small() {
        assert_eq!(cap_bytes("short", 100), "short");
    }

    #[test]
    fn err_kind_reports_kind_without_message_body() {
        // debug 로그용 — 메시지 본문(잠재적 내용 누출)은 제외하고 종류/상태만.
        assert_eq!(
            err_kind(&AicError::ConfigError("secret detail".into())),
            "ConfigError"
        );
        assert_eq!(
            err_kind(&AicError::ApiKeyMissing {
                provider: "p".into()
            }),
            "ApiKeyMissing"
        );
        assert_eq!(
            err_kind(&AicError::LlmApiError {
                status: 400,
                message: "secret detail".into()
            }),
            "LlmApiError(400)"
        );
        // 어떤 경우에도 메시지 본문은 포함되지 않는다.
        let k = err_kind(&AicError::LlmApiError {
            status: 500,
            message: "TOPSECRET".into(),
        });
        assert!(!k.contains("TOPSECRET"));
    }

    #[test]
    fn is_tools_unsupported_classifies_client_errors_and_config() {
        // tools 미지원으로 보이는 케이스 → degrade.
        assert!(is_tools_unsupported(&AicError::ConfigError("x".into())));
        for s in [400u16, 404, 405, 415, 422, 501] {
            assert!(
                is_tools_unsupported(&AicError::LlmApiError {
                    status: s,
                    message: "bad".into()
                }),
                "status {s} should degrade"
            );
        }
    }

    #[test]
    fn is_tools_unsupported_excludes_auth_ratelimit_server_network() {
        // 실제 문제이거나 재시도 대상 → degrade 안 함(그대로 surface).
        for s in [401u16, 403, 429, 500, 502, 503, 0] {
            assert!(
                !is_tools_unsupported(&AicError::LlmApiError {
                    status: s,
                    message: "x".into()
                }),
                "status {s} should NOT degrade"
            );
        }
        assert!(!is_tools_unsupported(&AicError::ApiKeyMissing {
            provider: "p".into()
        }));
    }

    /// mock tool-call round trip:
    /// 모의 OpenAI 응답(tool_calls) → parse → 도구 실행 → tool 메시지 직렬화까지
    /// 한 사이클이 올바로 이어지는지 검증한다(네트워크/credential 없이).
    #[test]
    fn mock_tool_call_round_trip() {
        // 1) 샌드박스 + 대상 파일 준비.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("note.txt"), "round trip ok").unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();

        // 2) 모의 LLM 응답: read_file 도구 호출.
        let mock = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_42",
                        "type": "function",
                        "function": { "name": "read_file", "arguments": "{\"path\":\"note.txt\"}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });

        // 3) parse → ToolCalls.
        let calls = match parse_openai_response(&mock) {
            Some(ChatResponse::ToolCalls(c)) => c,
            other => panic!("expected ToolCalls, got {other:?}"),
        };
        assert_eq!(calls.len(), 1);

        // 4) 도구 실행.
        let call = &calls[0];
        let parsed_args: serde_json::Value = serde_json::from_str(&call.arguments).unwrap();
        let result = tools::execute(&call.name, &parsed_args, &sb).unwrap();
        assert!(result.contains("round trip ok"));

        // 5) tool 메시지로 회신 직렬화.
        let tool_msg = ChatMessage::Tool {
            call_id: call.id.clone(),
            content: cap_bytes(&result, MAX_TOOL_RESULT_BYTES),
        };
        let wire = tool_msg.to_openai_json();
        assert_eq!(wire["role"], "tool");
        assert_eq!(wire["tool_call_id"], "call_42");
        assert!(wire["content"].as_str().unwrap().contains("round trip ok"));
    }

    #[test]
    fn sre_preface_contains_key_instructions() {
        // SRE 모드 핵심 지침이 preface에 포함되어야 한다.
        assert!(SRE_PREFACE.contains("run_command"));
        assert!(SRE_PREFACE.contains("DO NOT ask"));
        assert!(SRE_PREFACE.contains("bounded"));
        assert!(SRE_PREFACE.contains("ps aux | head"));
        assert!(SRE_PREFACE.contains("truncated"));
    }

    #[test]
    fn new_run_id_is_8_hex() {
        let id = new_run_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_extract_filters_to_user_and_assistant_content() {
        // System preface·Tool·tool_calls-only Assistant는 제외, User·Assistant(content)만 추출.
        let history = vec![
            ChatMessage::System("preface".to_string()),
            ChatMessage::User("hi".to_string()),
            ChatMessage::Assistant {
                content: None,
                tool_calls: vec![ToolCall {
                    id: "c1".to_string(),
                    name: "read_file".to_string(),
                    arguments: "{}".to_string(),
                }],
            },
            ChatMessage::Tool {
                call_id: "c1".to_string(),
                content: "result".to_string(),
            },
            ChatMessage::Assistant {
                content: Some("answer".to_string()),
                tool_calls: vec![],
            },
        ];
        let vals = history_to_session_values(&history);
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0]["role"], "user");
        assert_eq!(vals[0]["content"], "hi");
        assert_eq!(vals[1]["role"], "assistant");
        assert_eq!(vals[1]["content"], "answer");
    }

    #[test]
    fn session_extract_empty_when_no_conversation() {
        // System preface만(또는 tool 사이클만) → 추출 결과 비어야 함(저장 skip 조건).
        let history = vec![
            ChatMessage::System("preface".to_string()),
            ChatMessage::Assistant {
                content: None,
                tool_calls: vec![ToolCall {
                    id: "c1".to_string(),
                    name: "x".to_string(),
                    arguments: "{}".to_string(),
                }],
            },
        ];
        assert!(history_to_session_values(&history).is_empty());
    }

    #[test]
    fn session_round_trip_preserves_conversation() {
        // history → values → JSON → values → messages 라운드트립이 대화를 보존한다.
        let history = vec![
            ChatMessage::System("preface".to_string()),
            ChatMessage::User("질문1".to_string()),
            ChatMessage::Assistant {
                content: Some("답변1".to_string()),
                tool_calls: vec![],
            },
            ChatMessage::User("질문2".to_string()),
        ];
        let vals = history_to_session_values(&history);
        let json = serde_json::to_string_pretty(&vals).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let restored = session_values_to_messages(&parsed);
        assert_eq!(
            restored,
            vec![
                ChatMessage::User("질문1".to_string()),
                ChatMessage::Assistant {
                    content: Some("답변1".to_string()),
                    tool_calls: vec![],
                },
                ChatMessage::User("질문2".to_string()),
            ]
        );
    }

    #[test]
    fn session_restore_skips_malformed_and_unknown_roles() {
        // role/content 누락·알 수 없는 role 항목은 건너뛴다(best-effort).
        let vals = vec![
            serde_json::json!({ "role": "user", "content": "ok" }),
            serde_json::json!({ "role": "system", "content": "skip-unknown-role" }),
            serde_json::json!({ "role": "assistant" }), // content 누락 → skip
            serde_json::json!({ "content": "no-role" }), // role 누락 → skip
            serde_json::json!({ "role": "assistant", "content": "ok2" }),
        ];
        let restored = session_values_to_messages(&vals);
        assert_eq!(
            restored,
            vec![
                ChatMessage::User("ok".to_string()),
                ChatMessage::Assistant {
                    content: Some("ok2".to_string()),
                    tool_calls: vec![],
                },
            ]
        );
    }

    #[test]
    fn session_file_path_under_aic_sessions() {
        // 경로가 ~/.aic/sessions/last.json 형태인지(홈 환경이 있을 때).
        if let Some(p) = session_file_path() {
            assert!(p.ends_with(".aic/sessions/last.json"), "path={p:?}");
        }
    }

    #[tokio::test]
    async fn exec_tool_assigns_incrementing_correlation_seq() {
        use crate::llm_dispatcher::LlmDispatcher;
        use aic_common::{CommandRecord, LlmConfig};
        use std::collections::HashMap;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        let cfg = LlmConfig {
            default_provider: "x".to_string(),
            providers: HashMap::new(),
            lang: "english".to_string(),
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        };
        let dispatcher = LlmDispatcher::from_config(cfg);
        let mut session = AgentSession::new(
            dispatcher,
            sb,
            CommandRecord::default(),
            "english".to_string(),
        );

        assert_eq!(session.tool_seq, 0);
        assert_eq!(session.run_id.len(), 8);
        let call = ToolCall {
            id: "c1".to_string(),
            name: "read_file".to_string(),
            arguments: "{\"path\":\"a.txt\"}".to_string(),
        };
        let out1 = session.exec_tool(&call).await;
        assert!(out1.contains('x'));
        assert_eq!(session.tool_seq, 1);
        let _ = session.exec_tool(&call).await;
        assert_eq!(session.tool_seq, 2);
        // run_id는 세션 동안 고정 → corr는 run_id.{1,2}로 구분된다.
    }

    #[tokio::test]
    async fn handle_local_raw_does_not_push_history() {
        use crate::llm_dispatcher::LlmDispatcher;
        use aic_common::{CommandRecord, LlmConfig};
        use std::collections::HashMap;

        let dir = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        let cfg = LlmConfig {
            default_provider: "x".to_string(),
            providers: HashMap::new(),
            lang: "english".to_string(),
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        };
        let dispatcher = LlmDispatcher::from_config(cfg);
        let mut session = AgentSession::new(
            dispatcher,
            sb,
            CommandRecord::default(),
            "english".to_string(),
        )
        .allow_run_command(true);

        let before = session.history.len();
        // raw 모드(analyze=false) → 네트워크 호출 없음, 결정적. 단일 섹션으로 빠르게.
        session.handle_local(&["date".to_string()], false).await;
        // slash/local 경로는 대화 history에 push하지 않는다(no-history 원칙).
        assert_eq!(session.history.len(), before);
        // probe는 ring에 기록되어 /last·/raw로 재조회 가능.
        assert!(!session.tool_records.is_empty());
    }

    #[test]
    fn watch_target_validation() {
        // None(기본 compact)·유효 섹션은 통과.
        assert!(watch_target_error(None).is_none());
        assert!(watch_target_error(Some("memory")).is_none());
        assert!(watch_target_error(Some("disk")).is_none());
        // unknown target은 거부 + 사용 가능 섹션 힌트.
        let err = watch_target_error(Some("memroy")).expect("invalid target should error");
        assert!(err.contains("memroy") && err.contains("사용 가능"));
        assert!(err.contains("memory"), "힌트에 실제 섹션명 포함: {err}");
    }

    #[test]
    fn cap_section_lines_preserves_headers_and_caps_body() {
        let snap = "## date\nl1\nl2\nl3\nl4\n\n## host\nh1\nh2\n";
        let capped = cap_section_lines(snap, 2);
        // 헤더는 모두 보존, 각 섹션 본문은 최대 2줄 + 생략 마커.
        assert!(capped.contains("## date") && capped.contains("## host"));
        assert!(capped.contains("l1") && capped.contains("l2") && !capped.contains("l3"));
        assert!(capped.contains("…"));
        assert!(capped.contains("h1") && capped.contains("h2"));
    }

    #[test]
    fn cap_evidence_bounds_total_bytes() {
        let big = "x".repeat(20_000);
        let capped = cap_evidence(&big, 8 * 1024);
        assert!(capped.len() <= 8 * 1024 + 8, "byte cap: {}", capped.len());
        assert!(capped.ends_with('…'));
        // 작은 입력은 그대로.
        assert_eq!(cap_evidence("short", 1024), "short");
    }

    #[test]
    fn collect_progress_label_shows_name_and_index() {
        assert_eq!(
            collect_progress_label("date", 1, 9),
            "<thinking> 수집 중: date (1/9)"
        );
        assert_eq!(
            collect_progress_label("ports", 9, 9),
            "<thinking> 수집 중: ports (9/9)"
        );
        // 짧은 Claude-like 톤(<thinking> 프리픽스) + name/진행도 포함.
        let l = collect_progress_label("host", 2, 9);
        assert!(l.starts_with("<thinking>") && l.contains("host") && l.contains("(2/9)"));
    }

    #[test]
    fn analyze_status_label_thinking_tone_and_provider() {
        // Claude-like <thinking> 톤 + provider는 괄호로(전송 투명성).
        assert_eq!(
            analyze_status_label("스냅샷", Some("ai-mesh")),
            "<thinking> redacted 스냅샷 분석 중… (ai-mesh)"
        );
        // provider 없거나 빈 문자열이면 괄호 생략.
        assert_eq!(
            analyze_status_label("스냅샷", None),
            "<thinking> redacted 스냅샷 분석 중…"
        );
        assert_eq!(
            analyze_status_label("증거", Some("")),
            "<thinking> redacted 증거 분석 중…"
        );
        // 항상 redacted + noun 유지, <thinking> 프리픽스 포함.
        let l = analyze_status_label("증거", Some("x"));
        assert!(l.starts_with("<thinking>") && l.contains("redacted 증거") && l.contains("(x)"));
    }

    #[tokio::test]
    async fn local_snapshot_includes_raw_probe_bodies() {
        use crate::llm_dispatcher::LlmDispatcher;
        use aic_common::{CommandRecord, LlmConfig};
        use std::collections::HashMap;

        let dir = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        let cfg = LlmConfig {
            default_provider: "x".to_string(),
            providers: HashMap::new(),
            lang: "english".to_string(),
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        };
        let dispatcher = LlmDispatcher::from_config(cfg);
        let mut session = AgentSession::new(
            dispatcher,
            sb,
            CommandRecord::default(),
            "english".to_string(),
        )
        .allow_run_command(true);

        // fallback이 출력하는 것과 동일한 스냅샷. 분석 실패 시 이 본문이 그대로 표시된다.
        let probes = super::super::sysinfo::probes_for(&[]).unwrap();
        let snap = session.collect_local_snapshot(probes, false).await;
        // 섹션 헤더 + 실제 raw 본문(redacted run_command 결과)이 포함되어야 한다.
        for section in ["date", "disk", "memory"] {
            assert!(
                snap.contains(&format!("## {section}")),
                "missing ## {section}"
            );
        }
        // raw 본문 마커(run_command 결과 형식) — summary가 아니라 실제 출력.
        assert!(
            snap.contains("--- stdout ---"),
            "raw stdout body 누락: {snap}"
        );
        assert!(snap.contains("exit_code="), "raw exit_code 누락");
    }

    #[test]
    fn write_preview_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        let args = json!({ "path": "new.txt", "content": "line1\nline2\nline3" });
        let preview = build_write_preview("write_file", &args, &sb);
        assert!(preview.contains("새 파일 new.txt"));
        assert!(preview.contains("(3줄)"));
        assert!(preview.contains("line1"));
    }

    #[test]
    fn write_preview_overwrite_existing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("exists.txt"), "a\nb").unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        let args = json!({ "path": "exists.txt", "content": "x\ny\nz" });
        let preview = build_write_preview("write_file", &args, &sb);
        assert!(preview.contains("덮어쓰기"));
        assert!(preview.contains("2줄 → 3줄"));
    }

    #[test]
    fn write_preview_edit_shows_diff_lines() {
        let dir = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        let args = json!({
            "path": "f.txt",
            "old_string": "foo",
            "new_string": "bar"
        });
        let preview = build_write_preview("edit_file", &args, &sb);
        assert!(preview.contains("[edit_file] f.txt"));
        assert!(preview.contains("- foo"));
        assert!(preview.contains("+ bar"));
    }

    #[test]
    fn write_preview_caps_long_lines() {
        let dir = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(dir.path()).unwrap();
        let long = "z".repeat(500);
        let args = json!({
            "path": "f.txt",
            "old_string": long.clone(),
            "new_string": "short"
        });
        let preview = build_write_preview("edit_file", &args, &sb);
        // 200자 cap + 말줄임 → 원문 500자가 그대로 들어가지 않는다.
        assert!(!preview.contains(&long));
        assert!(preview.contains('…'));
    }
}
