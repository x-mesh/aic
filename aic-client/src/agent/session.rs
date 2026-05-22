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
- The shell is restricted (no $, globs, quotes, backslashes, redirects, ;, &). If a command is \
blocked for that reason, propose and run a simpler safe alternative instead of giving up.\n\
- If a tool result says output was truncated, re-run with a narrower/limited command.\n";

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
        }
    }

    /// run_command 도구 노출 여부를 설정한다(`aic chat` 기본 활성, `--no-run`로 끔).
    pub fn allow_run_command(mut self, enabled: bool) -> Self {
        self.allow_run_command = enabled;
        self
    }

    /// status line 표시용 provider/model을 설정한다(선택).
    pub fn with_provider_model(mut self, provider: String, model: String) -> Self {
        self.provider = Some(provider);
        self.model = Some(model);
        self
    }

    /// REPL 루프 실행. exit/quit/Ctrl+D로 종료.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut reader = repl::LineReader::new();

        // ASCII art banner + status line(TTY/색상/폭 자동, non-TTY는 plain fallback).
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

        // system preface를 history 시드로 둔다(OpenAI system role 사용).
        // SRE 모드면 generic preface 뒤에 SRE 지침을 덧붙인다.
        let mut preface = repl::system_preface().to_string();
        if self.allow_run_command {
            preface.push_str(SRE_PREFACE);
        }
        self.history.push(ChatMessage::System(preface));

        loop {
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

    /// 한 번의 사용자 입력에 대해 tool-calling loop를 돈다.
    /// degrade 상태이면 도구 없이 단발 send()로 처리한다.
    async fn run_turn(&mut self) -> anyhow::Result<()> {
        if self.degraded {
            return self.run_turn_degraded().await;
        }

        let mut specs = tools::read_only_specs();
        if self.allow_run_command {
            specs.push(super::run_command::spec());
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
            let spinner = crate::spinner::Spinner::start("thinking...".to_string());
            let resp = self.dispatcher.send_messages(&self.history, &specs).await;
            spinner.stop().await;

            match resp {
                Ok(ChatResponse::Text(text)) => {
                    adbg!("iter={} response=text text_len={}", iter + 1, text.len());
                    self.history.push(ChatMessage::Assistant {
                        content: Some(text.clone()),
                        tool_calls: vec![],
                    });
                    self.render(&text);
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
                        let result = self.exec_tool(call);
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
        let spinner = crate::spinner::Spinner::start("thinking...".to_string());
        let resp = self.dispatcher.send(&prompt).await;
        spinner.stop().await;

        match resp {
            Ok(text) => {
                adbg!("degraded response: text_len={}", text.len());
                self.history.push(ChatMessage::Assistant {
                    content: Some(text.clone()),
                    tool_calls: vec![],
                });
                self.render(&text);
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
    fn exec_tool(&mut self, call: &ToolCall) -> String {
        self.tool_seq += 1;
        let corr = format!("{}.{}", self.run_id, self.tool_seq);
        // run_command는 자체 command card를 출력하므로 generic [tool] 줄은 생략.
        if call.name != "run_command" {
            eprintln!("\x1b[2m[tool] {} [{corr}]\x1b[0m", call.name);
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
                eprintln!("\x1b[33m[run_command] [{corr}] 비활성(read-only 세션)\x1b[0m");
                Ok("[tool error] run_command은 현재 read-only 세션이라 비활성입니다. \
                    셸 실행이 필요하면 `--no-run`/`--read-only` 없이(또는 AIC_AGENT_NO_RUN 미설정) \
                    `aic chat`을 다시 실행하세요. 지금은 read_file/list_dir/grep/glob로 진단하세요."
                    .to_string())
            } else {
                super::run_command::execute_with_corr(&args, &self.sandbox, &corr, tty_confirm)
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
            SlashCommand::Help => eprintln!("{}", tool_record::help_text()),
            SlashCommand::Last(n) => {
                eprintln!("{}", tool_record::render_last(&self.tool_records, n))
            }
            SlashCommand::Raw(t) => {
                eprintln!(
                    "{}",
                    tool_record::render_raw(&self.tool_records, t.as_deref())
                )
            }
            SlashCommand::Local { section, analyze } => {
                self.handle_local(section.as_deref(), analyze).await
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
            SlashCommand::Doctor => self.handle_doctor(),
            SlashCommand::Timeline(n) => {
                eprintln!("{}", tool_record::render_timeline(&self.tool_records, n))
            }
            SlashCommand::Compare => self.handle_compare(),
            SlashCommand::Bundle(name) => self.handle_bundle(name.as_deref()),
            SlashCommand::Unknown(name) => {
                eprintln!("알 수 없는 명령: /{name}. /help 로 사용법을 확인하세요.")
            }
        }
    }

    /// `/local` — 내장 sysinfo probe(개별 Safe 명령)를 실행해 로컬 스냅샷을 만든다.
    /// 기본은 redacted 스냅샷을 **tool-less·stateless 단발 LLM 호출**로 분석 요약(history 미push).
    /// `--raw`이거나 `AIC_LOCAL_NO_ANALYZE`이거나 분석 실패(설정 없음/오류/timeout)면 raw 스냅샷으로
    /// fallback하고 짧은 사유만 표시한다. 출력은 stderr 전용, read-only 세션에서는 비활성.
    async fn handle_local(&mut self, section: Option<&str>, analyze: bool) {
        if !self.allow_run_command {
            eprintln!(
                "/local은 run_command가 필요합니다 — 현재 read-only 세션(--no-run/--read-only/\
                 AIC_AGENT_NO_RUN)이라 비활성입니다."
            );
            return;
        }
        let probes = super::sysinfo::probes_for(section);
        if probes.is_empty() {
            eprintln!(
                "알 수 없는 섹션: {}. 사용 가능: {}",
                section.unwrap_or(""),
                super::sysinfo::LOCAL_SECTIONS.join(" ")
            );
            return;
        }

        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());

        eprintln!("=== local system snapshot ===");
        // raw 모드면 본문도 즉시 출력. 분석 모드면 스냅샷으로만 모은다(요약 우선, 실패 시 fallback에서 출력).
        let snapshot = self.collect_local_snapshot(probes, !do_analyze);

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
        let spinner = crate::spinner::Spinner::start_styled(label, amber);
        let result =
            tokio::time::timeout(LOCAL_ANALYZE_TIMEOUT, self.dispatcher.send(prompt)).await;
        spinner.stop().await;

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
                eprintln!("\n=== {heading} ===\n{body}");
            }
            Ok(Err(e)) => {
                self.analysis_fallback(kind, &format!("provider 오류: {}", err_kind(&e)), snapshot)
            }
            Err(_) => self.analysis_fallback(
                kind,
                &format!("분석 timeout({}s)", LOCAL_ANALYZE_TIMEOUT.as_secs()),
                snapshot,
            ),
        }
    }

    /// probe들을 개별 Safe 명령으로 실행해 **raw 본문 포함** 스냅샷(`## section\n<redacted out>`)을
    /// 만든다. 각 결과는 ring에 기록(/last·/raw 재조회). `print_bodies`면 본문도 stderr로 즉시 출력.
    fn collect_local_snapshot(
        &mut self,
        probes: Vec<(&'static str, String)>,
        print_bodies: bool,
    ) -> String {
        let mut snapshot = String::new();
        for (name, cmd) in probes {
            self.tool_seq += 1;
            let corr = format!("{}.{}", self.run_id, self.tool_seq);
            eprintln!("\n[{name}]");
            let args = serde_json::json!({ "command": cmd });
            // Safe 명령이라 confirm은 호출되지 않지만, 비대화형 안전을 위해 거부 클로저 전달.
            // execute_with_corr가 command card를 stderr로 출력(visibility), 결과는 redacted.
            let out =
                super::run_command::execute_with_corr(&args, &self.sandbox, &corr, |_, _, _| false)
                    .unwrap_or_else(|e| format!("[tool error] {e}"));
            if print_bodies {
                eprintln!("{out}");
            }
            snapshot.push_str(&format!("## {name}\n{out}\n\n"));
            self.record_tool(&corr, "run_command", Some(cmd), &out);
        }
        snapshot
    }

    /// 분석 실패 시 — **실제 raw 증거 본문**(redacted)을 그대로 보여주고 짧은 사유만 표시.
    /// 색상은 ui::paint 정책(NO_COLOR/non-TTY면 plain)을 따른다. `/local`·`/diagnose` 공용.
    fn analysis_fallback(&self, kind: &'static str, reason: &str, snapshot: &str) {
        adbg!("{kind} run={} fallback reason={}", self.run_id, reason);
        let _ = crate::audit::append(
            kind,
            serde_json::json!({ "run_id": self.run_id, "analyzed": false, "fallback": reason }),
        );
        eprintln!(
            "\n{}",
            ui::paint(
                &format!("[{kind}] LLM 분석을 못 해 raw 증거를 표시합니다 ({reason})."),
                "33"
            )
        );
        // 분석 모드에서는 본문을 안 찍었으므로, fallback 시 raw 증거 본문 전체를 출력한다.
        eprintln!("{}", snapshot.trim_end());
    }

    /// `/diagnose` — 증상→결정적 Safe probe 선택→수집→가설/증거/다음확인 분석(read-only).
    /// `/local`과 동일 철학: probe 선택은 호스트가 결정, 분석은 tool-less·stateless 단발(history 미push).
    async fn handle_diagnose(&mut self, symptom: Option<&str>, analyze: bool) {
        if !self.allow_run_command {
            eprintln!(
                "/diagnose는 run_command가 필요합니다 — 현재 read-only 세션(--no-run/--read-only/\
                 AIC_AGENT_NO_RUN)이라 비활성입니다."
            );
            return;
        }
        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());
        let probes = super::diagnose::select_probes(symptom);
        eprintln!(
            "=== diagnose: {} ===",
            symptom.unwrap_or("(generic health)")
        );
        let snapshot = self.collect_local_snapshot(probes, !do_analyze);
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
                eprintln!(
                    "설명할 tool 기록이 없습니다. 먼저 명령을 실행하거나 /local·/diagnose로 증거를 \
                     만든 뒤 다시 시도하세요."
                );
                return;
            }
        };
        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());
        if !do_analyze {
            eprintln!("=== explain-last (raw evidence) ===\n{}", evidence);
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
            eprintln!(
                "/incident는 run_command가 필요합니다 — 현재 read-only 세션(--no-run/--read-only/\
                 AIC_AGENT_NO_RUN)이라 비활성입니다."
            );
            return;
        }
        let do_analyze = tool_record::local_analyze_enabled(analyze, env_local_no_analyze());
        eprintln!("=== incident: {} ===", name.unwrap_or("(unnamed)"));

        let mut evidence = String::from("# system\n");
        evidence
            .push_str(&self.collect_local_snapshot(super::sysinfo::local_probes(), !do_analyze));

        // git read-only 증거(repo일 때만). 고정 Safe 상수만 — name은 명령에 절대 포함하지 않는다.
        if self.sandbox.root().join(".git").exists() {
            let git_probes: Vec<(&'static str, String)> = vec![
                ("git_status", "git status --short".to_string()),
                ("git_branch", "git branch --show-current".to_string()),
                ("git_log", "git log -n 10 --oneline".to_string()),
                ("git_diff", "git diff --stat".to_string()),
            ];
            evidence.push_str("\n# git\n");
            evidence.push_str(&self.collect_local_snapshot(git_probes, !do_analyze));
        }

        // 최근 tool 기록 요약(분석/raw 모두 포함).
        let recent = tool_record::recent_records_evidence(&self.tool_records, 10);
        evidence.push_str("\n# recent tool records\n");
        evidence.push_str(&recent);

        if !do_analyze {
            eprintln!("\n# recent tool records\n{recent}");
            return;
        }
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
    fn handle_doctor(&self) {
        let flags = [
            ("AIC_DEBUG", std::env::var_os("AIC_DEBUG").is_some()),
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
            &flags,
        );
        let body = if ui::is_tty() {
            super::markdown::render_markdown(&report, ui::render_width(), ui::color_enabled())
        } else {
            report
        };
        eprintln!("\n=== aic doctor ===\n{body}");
    }

    /// `/compare` — 고정 Safe probe로 현재 시스템 스냅샷을 만들고 직전 baseline과 diff(LLM 미호출).
    /// 첫 호출은 baseline만 저장. 이후 diff 출력 후 baseline 갱신.
    fn handle_compare(&mut self) {
        if !self.allow_run_command {
            eprintln!(
                "/compare는 run_command가 필요합니다 — 현재 read-only 세션이라 비활성입니다."
            );
            return;
        }
        let snapshot = self.collect_local_snapshot(super::sysinfo::local_probes(), false);
        match self.compare_baseline.take() {
            None => {
                eprintln!(
                    "baseline 스냅샷을 저장했습니다. 잠시 후 다시 /compare로 변화를 확인하세요."
                );
                self.compare_baseline = Some(snapshot);
            }
            Some(old) => {
                eprintln!(
                    "\n=== compare (직전 baseline 대비) ===\n{}",
                    tool_record::snapshot_diff(&old, &snapshot)
                );
                self.compare_baseline = Some(snapshot);
            }
        }
    }

    /// `/bundle [name]` — 인시던트 증거(시스템+git+최근 기록)를 redacted markdown으로 파일 저장.
    /// name은 파일 라벨 전용(셸 명령에 미포함). dir 0700 / file 0600(unix best-effort).
    fn handle_bundle(&mut self, name: Option<&str>) {
        if !self.allow_run_command {
            eprintln!("/bundle은 run_command가 필요합니다 — 현재 read-only 세션이라 비활성입니다.");
            return;
        }
        // 증거 수집(화면 본문 출력 없이 파일용으로만; collect는 redacted + ring 기록).
        let mut evidence = String::from("# system\n");
        evidence.push_str(&self.collect_local_snapshot(super::sysinfo::local_probes(), false));
        if self.sandbox.root().join(".git").exists() {
            let git_probes: Vec<(&'static str, String)> = vec![
                ("git_status", "git status --short".to_string()),
                ("git_branch", "git branch --show-current".to_string()),
                ("git_log", "git log -n 10 --oneline".to_string()),
                ("git_diff", "git diff --stat".to_string()),
            ];
            evidence.push_str("\n# git\n");
            evidence.push_str(&self.collect_local_snapshot(git_probes, false));
        }
        evidence.push_str("\n# recent tool records\n");
        evidence.push_str(&tool_record::recent_records_evidence(
            &self.tool_records,
            20,
        ));

        match write_bundle(name, &evidence) {
            Ok(path) => eprintln!("\nbundle 저장됨: {}", path.display()),
            Err(e) => eprintln!("\nbundle 저장 실패: {e}"),
        }
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

    /// 최종 텍스트 응답을 <think> 분리 후 렌더링한다(repl 렌더러 재사용).
    fn render(&self, text: &str) {
        let (think, main) = repl::split_think_block(text);
        if let Some(ref t) = think {
            repl::print_think_summary(t);
        }
        repl::print_with_border(&main);
    }
}

/// `/local` 분석 단발 LLM 호출의 최대 대기 시간(초). 초과 시 raw fallback.
const LOCAL_ANALYZE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `/bundle` — redacted 증거를 `~/.aic/bundles/<sanitized>-<ts>.md`에 저장하고 경로를 반환한다.
/// name은 파일명 라벨(sanitize)로만 쓰고 셸 명령에 섞지 않는다. dir 0700 / file 0600(unix best-effort).
fn write_bundle(name: Option<&str>, evidence: &str) -> anyhow::Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("홈 디렉터리를 찾을 수 없습니다"))?;
    let dir = home.join(".aic").join("bundles");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let label = tool_record::sanitize_bundle_name(name.unwrap_or(""));
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("{label}-{ts}.md"));
    let body = format!(
        "# aic incident bundle: {label}\n생성: {ts}\n\n{evidence}\n",
        label = name.unwrap_or("(unnamed)"),
    );
    std::fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

/// 분석 spinner 라벨 — provider 전송 투명성을 유지한다(`noun`=스냅샷/증거 등). provider명이 있으면 포함.
fn analyze_status_label(noun: &str, provider: Option<&str>) -> String {
    match provider {
        Some(p) if !p.is_empty() => format!("redacted {noun}를 {p}로 보내 분석 중…"),
        _ => format!("redacted {noun}를 provider로 보내 분석 중…"),
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

/// run_command NeedsConfirm용 TTY 확인. 비-TTY는 무조건 거부(false).
/// command/cwd/risk를 보여주고 y/N을 받는다(기본 N).
fn tty_confirm(command: &str, cwd: &str, reason: &str) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return false;
    }
    eprintln!("\x1b[33m[run_command] ⚠ 확인 필요 (risk: NeedsConfirm — 상태 변경 가능)\x1b[0m");
    eprintln!("  command: {command}");
    eprintln!("  cwd:     {cwd}");
    eprintln!("  reason:  {reason}");
    eprint!("\x1b[33m실행할까요? [y/N] (Enter=No)\x1b[0m ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
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
    fn exec_tool_assigns_incrementing_correlation_seq() {
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
        let out1 = session.exec_tool(&call);
        assert!(out1.contains('x'));
        assert_eq!(session.tool_seq, 1);
        let _ = session.exec_tool(&call);
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
        session.handle_local(Some("date"), false).await;
        // slash/local 경로는 대화 history에 push하지 않는다(no-history 원칙).
        assert_eq!(session.history.len(), before);
        // probe는 ring에 기록되어 /last·/raw로 재조회 가능.
        assert!(!session.tool_records.is_empty());
    }

    #[test]
    fn analyze_status_label_includes_provider() {
        assert_eq!(
            analyze_status_label("스냅샷", Some("ai-mesh")),
            "redacted 스냅샷를 ai-mesh로 보내 분석 중…"
        );
        // provider 없거나 빈 문자열이면 일반 라벨.
        assert!(analyze_status_label("스냅샷", None).contains("provider로"));
        assert!(analyze_status_label("증거", Some("")).contains("provider로"));
        // 항상 전송 투명성(redacted) + noun 문구 유지.
        assert!(analyze_status_label("증거", Some("x")).contains("redacted 증거"));
    }

    #[test]
    fn local_snapshot_includes_raw_probe_bodies() {
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
        let probes = super::super::sysinfo::probes_for(None);
        let snap = session.collect_local_snapshot(probes, false);
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
}
