//! `aic init --hook-mode`가 설치하는 Phase 3 metadata-only hook.
//!
//! 기존 PTY hook(`~/.aic/hooks.zsh`, OSC 133 marker)과는 별도 파일이며,
//! 두 hook은 동시에 켜둬도 충돌하지 않는다. PTY hook은 boundary 마커, 이 hook은
//! `aicd`에 metadata 이벤트를 전송한다.
//!
//! 핵심 정책 (PRD-HOOK-CAPTURE-MODE R3):
//! - 모든 hook 호출은 백그라운드(`&`)로 detach해 prompt latency를 늘리지 않는다.
//! - aicd가 미실행이면 `aic _hook-event`가 silent skip한다.
//! - hook 실패가 사용자 명령의 exit code를 바꾸지 않는다.

/// version marker — 설치된 파일이 오래된 버전인지 `aic doctor`가 감지한다.
pub const HOOK_VERSION: u32 = 1;

/// rc 파일에 추가하는 source 라인의 시작/끝 마커.
pub const RC_MARKER_BEGIN: &str = "# >>> aic hook-events >>>";
pub const RC_MARKER_END: &str = "# <<< aic hook-events <<<";

/// zsh용 hook script.
pub fn zsh_hook_script() -> String {
    format!(
        r#"# aic metadata hook (zsh) — version {HOOK_VERSION}
# 자동 생성됨. 직접 수정하지 마세요. `aic init --hook-mode`로 갱신합니다.

typeset -g _AIC_HOOK_VERSION={HOOK_VERSION}
typeset -g _AIC_HOOK_CMD_ID=""
typeset -g _AIC_HOOK_START_NS=0

_aic_hook_now_ns() {{
    if zmodload -F zsh/datetime b:strftime 2>/dev/null; then
        printf '%d' $(( EPOCHREALTIME * 1000000000 ))
    else
        printf '0'
    fi
}}

_aic_hook_preexec() {{
    _AIC_HOOK_CMD_ID="${{RANDOM}}${{RANDOM}}"
    _AIC_HOOK_START_NS=$(_aic_hook_now_ns)
    # background detach + redirect to /dev/null. prompt 차단 절대 금지.
    (aic _hook-event start \
        --session "${{AIC_SESSION_ID:-none}}" \
        --command-id "$_AIC_HOOK_CMD_ID" \
        --command "$1" \
        --cwd "$PWD" \
        --shell zsh \
        --pid "$$" >/dev/null 2>&1 &) 2>/dev/null
}}

_aic_hook_precmd() {{
    local exit=$?
    [[ -z "$_AIC_HOOK_CMD_ID" ]] && return
    local end=$(_aic_hook_now_ns)
    local dur_ms=0
    if [[ "$end" != "0" && "$_AIC_HOOK_START_NS" != "0" ]]; then
        dur_ms=$(( (end - _AIC_HOOK_START_NS) / 1000000 ))
    fi
    (aic _hook-event end \
        --session "${{AIC_SESSION_ID:-none}}" \
        --command-id "$_AIC_HOOK_CMD_ID" \
        --exit "$exit" \
        --duration-ms "$dur_ms" >/dev/null 2>&1 &) 2>/dev/null
    _AIC_HOOK_CMD_ID=""
    _AIC_HOOK_START_NS=0
}}

autoload -Uz add-zsh-hook 2>/dev/null
add-zsh-hook preexec _aic_hook_preexec 2>/dev/null
add-zsh-hook precmd _aic_hook_precmd 2>/dev/null
"#
    )
}

/// bash용 hook script. zsh보다 edge case가 많아 단순화한다.
pub fn bash_hook_script() -> String {
    format!(
        r#"# aic metadata hook (bash) — version {HOOK_VERSION}
# 자동 생성됨. 직접 수정하지 마세요. `aic init --hook-mode`로 갱신합니다.

_AIC_HOOK_VERSION={HOOK_VERSION}
_AIC_HOOK_CMD_ID=""
_AIC_HOOK_START_NS=0

_aic_hook_now_ns() {{
    if [[ -n "${{EPOCHREALTIME:-}}" ]]; then
        awk -v t="$EPOCHREALTIME" 'BEGIN{{printf "%d", t*1000000000}}'
    else
        printf '0'
    fi
}}

# DEBUG trap은 모든 simple command 직전에 발화한다. 자기 자신이나
# PROMPT_COMMAND 안에서 발화한 경우는 무시한다.
_aic_hook_debug_trap() {{
    [[ "$BASH_COMMAND" == "$PROMPT_COMMAND" ]] && return
    [[ "$BASH_COMMAND" == _aic_hook_* ]] && return
    _AIC_HOOK_CMD_ID="${{RANDOM}}${{RANDOM}}"
    _AIC_HOOK_START_NS=$(_aic_hook_now_ns)
    (aic _hook-event start \
        --session "${{AIC_SESSION_ID:-none}}" \
        --command-id "$_AIC_HOOK_CMD_ID" \
        --command "$BASH_COMMAND" \
        --cwd "$PWD" \
        --shell bash \
        --pid "$$" >/dev/null 2>&1 &) 2>/dev/null
}}

_aic_hook_prompt_command() {{
    local exit=$?
    [[ -z "$_AIC_HOOK_CMD_ID" ]] && return
    local end=$(_aic_hook_now_ns)
    local dur_ms=0
    if [[ "$end" != "0" && "$_AIC_HOOK_START_NS" != "0" ]]; then
        dur_ms=$(( (end - _AIC_HOOK_START_NS) / 1000000 ))
    fi
    (aic _hook-event end \
        --session "${{AIC_SESSION_ID:-none}}" \
        --command-id "$_AIC_HOOK_CMD_ID" \
        --exit "$exit" \
        --duration-ms "$dur_ms" >/dev/null 2>&1 &) 2>/dev/null
    _AIC_HOOK_CMD_ID=""
    _AIC_HOOK_START_NS=0
}}

trap '_aic_hook_debug_trap' DEBUG
PROMPT_COMMAND="_aic_hook_prompt_command${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zsh_script_contains_required_hooks() {
        let s = zsh_hook_script();
        assert!(s.contains("preexec _aic_hook_preexec"));
        assert!(s.contains("precmd _aic_hook_precmd"));
        assert!(s.contains("aic _hook-event start"));
        assert!(s.contains("aic _hook-event end"));
        assert!(s.contains(&format!("version {HOOK_VERSION}")));
    }

    #[test]
    fn bash_script_contains_required_hooks() {
        let s = bash_hook_script();
        assert!(s.contains("trap '_aic_hook_debug_trap' DEBUG"));
        assert!(s.contains("PROMPT_COMMAND"));
        assert!(s.contains("aic _hook-event start"));
        assert!(s.contains("aic _hook-event end"));
    }

    #[test]
    fn rc_markers_are_unique_pair() {
        assert_ne!(RC_MARKER_BEGIN, RC_MARKER_END);
        assert!(RC_MARKER_BEGIN.contains("aic hook-events"));
        assert!(RC_MARKER_END.contains("aic hook-events"));
    }
}
