//! 셸 OSC 133 boundary hook 스크립트 생성.
//!
//! `~/.aic/hooks.{zsh,bash}`에 설치되는 내용으로, precmd/preexec(zsh) 또는
//! DEBUG trap/PROMPT_COMMAND(bash)에서 OSC 133 마커를 출력해 PTY wrapper가
//! 명령어 경계와 exit code를 감지할 수 있게 한다.
//!
//! 이 generator는 `aic-server`(PTY 세션 시작 시 lazy 생성)와
//! `aic-client`(`aic init`이 source 라인과 함께 파일 생성) 양쪽에서 쓰이므로
//! 공유 crate인 `aic-common`에 둔다.

/// 지정된 셸에 대한 OSC 133 마커 출력 훅 스크립트를 생성한다.
///
/// zsh: precmd/preexec 함수 정의
/// bash: PROMPT_COMMAND 설정
/// 그 외 셸: 빈 문자열
pub fn generate_shell_hooks(shell: &str) -> String {
    match shell {
        "zsh" => ZSH_HOOKS.to_string(),
        "bash" => BASH_HOOKS.to_string(),
        _ => String::new(),
    }
}

const ZSH_HOOKS: &str = r#"
# AIC OSC 133 shell integration (zsh)
# precmd 훅 목록의 맨 앞에 등록하여 $?가 다른 훅에 의해 덮어쓰이기 전에 캡처
_aic_save_exit_code() {
    _aic_last_exit=$?
}
_aic_hex() {
    printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}
_aic_preexec() {
    local _aic_cmd_hex
    _aic_cmd_hex="$(_aic_hex "$1")"
    printf '\x1b]133;C;cmd=%s\x07' "${_aic_cmd_hex[1,8192]}"
}
_aic_precmd() {
    printf '\x1b]133;D;%d\x07' "$_aic_last_exit"
    printf '\x1b]133;A\x07'
    printf '\x1b]133;B\x07'
}
autoload -Uz add-zsh-hook
# save_exit_code를 맨 먼저 실행하여 $? 보존
add-zsh-hook precmd _aic_save_exit_code
add-zsh-hook precmd _aic_precmd
add-zsh-hook preexec _aic_preexec
"#;

const BASH_HOOKS: &str = r#"
# AIC OSC 133 shell integration (bash)
_aic_hex() {
    printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}
_aic_debug_trap() {
    _aic_last_exit=$?
    case "$BASH_COMMAND" in
        _aic_prompt_command*|_aic_debug_trap*|trap\ *) return ;;
    esac
    local _aic_cmd_hex
    _aic_cmd_hex="$(_aic_hex "$BASH_COMMAND")"
    printf '\x1b]133;C;cmd=%s\x07' "${_aic_cmd_hex:0:8192}"
}
_aic_prompt_command() {
    local exit_code=${_aic_last_exit:-$?}
    printf '\x1b]133;D;%d\x07' "$exit_code"
    printf '\x1b]133;A\x07'
    printf '\x1b]133;B\x07'
}
# trap DEBUG로 명령어 실행 직후 exit code를 즉시 캡처
trap '_aic_debug_trap' DEBUG
PROMPT_COMMAND="_aic_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_zsh_hooks_contains_osc_markers() {
        let hooks = generate_shell_hooks("zsh");
        assert!(hooks.contains("precmd"));
        assert!(hooks.contains("preexec"));
        assert!(hooks.contains("133;D"));
        assert!(hooks.contains("133;C;cmd="));
        assert!(hooks.contains("133;A"));
    }

    #[test]
    fn generate_bash_hooks_contains_prompt_command() {
        let hooks = generate_shell_hooks("bash");
        assert!(hooks.contains("PROMPT_COMMAND"));
        assert!(hooks.contains("133;D"));
        assert!(hooks.contains("133;C;cmd="));
        assert!(hooks.contains("133;A"));
    }

    #[test]
    fn generate_hooks_unknown_shell_returns_empty() {
        assert!(generate_shell_hooks("fish").is_empty());
        assert!(generate_shell_hooks("").is_empty());
    }
}
