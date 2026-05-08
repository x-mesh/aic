#!/usr/bin/env bash
#
# spawn-aic-sessions.sh
# -----------------------------------------------------------------------------
# RSS 측정용 aic-session N개를 tmux detached session 으로 한번에 띄운다.
# aic-session 은 PTY wrapper 라 TTY 가 없으면 raw mode 실패로 즉시 죽는데,
# tmux window 는 각자 PTY 를 가지므로 N 개 기동이 안정적으로 된다.
#
# 사용법
#   scripts/spawn-aic-sessions.sh --phase 3_0 [-n 10] [-s rss-30]
#   scripts/spawn-aic-sessions.sh --phase 3_4 [-n 10] [-s rss-34]
#
# 옵션
#   --phase 3_0|3_4   필수. target/rss-builds/phase-${PHASE}/aic-session 를 띄운다.
#   -n, --count N     세션 수 (기본 10, R6.5 시나리오).
#   -s, --session S   tmux session 이름 (기본 rss-${PHASE}).
#   --with-aicd       같은 tmux session 의 0번 window 에 aicd 도 기동.
#                     AIC_CENTRAL_STORE=1 은 Phase 3.4 에만 자동 설정.
#   --kill            기존 tmux session 이 있으면 먼저 kill.
#   --list            현재 tmux session/windows 를 출력하고 종료.
#
# 기동 후
#   tmux ls                       # 실행된 session 목록
#   tmux attach -t rss-${PHASE}   # 확인/워밍업
#   scripts/measure-rss-phase34.sh --phase ${PHASE} --processes N
#   scripts/pkill-aic.sh          # 정리
# -----------------------------------------------------------------------------

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PHASE=""
COUNT=10
SESSION=""
WITH_AICD=0
DO_KILL=0
DO_LIST=0

while [ $# -gt 0 ]; do
    case "$1" in
        --phase)
            shift
            PHASE="${1:-}"
            ;;
        -n|--count)
            shift
            COUNT="${1:-}"
            ;;
        -s|--session)
            shift
            SESSION="${1:-}"
            ;;
        --with-aicd) WITH_AICD=1 ;;
        --kill) DO_KILL=1 ;;
        --list) DO_LIST=1 ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift || true
done

if [ "$DO_LIST" -eq 1 ]; then
    echo "── tmux sessions ──"
    tmux ls 2>/dev/null || echo "(tmux session 없음)"
    exit 0
fi

if [ -z "$PHASE" ]; then
    echo "error: --phase 가 필요합니다 (3_0 또는 3_4)" >&2
    exit 2
fi
if ! printf '%s' "$COUNT" | grep -Eq '^[1-9][0-9]*$'; then
    echo "error: --count 는 1 이상의 정수여야 합니다" >&2
    exit 2
fi

BIN_DIR="$REPO_ROOT/target/rss-builds/phase-${PHASE}"
AIC_SESSION_BIN="$BIN_DIR/aic-session"
AICD_BIN="$BIN_DIR/aicd"

if [ ! -x "$AIC_SESSION_BIN" ]; then
    echo "error: $AIC_SESSION_BIN 이 없습니다." >&2
    echo "       Phase ${PHASE} 빌드를 먼저 수행하세요." >&2
    exit 2
fi

if ! command -v tmux >/dev/null 2>&1; then
    echo "error: tmux 가 필요합니다 (brew install tmux)" >&2
    exit 2
fi

if [ -z "$SESSION" ]; then
    SESSION="rss-${PHASE}"
fi

# 기존 tmux session 처리
if tmux has-session -t "$SESSION" 2>/dev/null; then
    if [ "$DO_KILL" -eq 1 ]; then
        echo "기존 tmux session '$SESSION' kill"
        tmux kill-session -t "$SESSION"
    else
        echo "error: tmux session '$SESSION' 이 이미 있습니다. --kill 또는 -s 로 다른 이름 사용." >&2
        exit 1
    fi
fi

# Phase 3.4 는 central store flag 기본값이 true 지만 명시적으로 export.
ENV_PREFIX=""
if [ "$PHASE" = "3_4" ]; then
    ENV_PREFIX="AIC_CENTRAL_STORE=1 "
fi

# ── aicd attach socket 경로 (race 회피용) ─────────────────────
# aic-session 의 AttachClient::connect 는 100ms timeout 인데 aicd bind 는
# 수십~수백 ms 걸린다. 세션이 먼저 떠서 connect 실패 → Local Fallback 으로
# 내려가는 경우를 막기 위해, --with-aicd 로 aicd 를 띄우면 이 소켓이 생길
# 때까지 대기한 뒤에야 세션 window 를 연다.
ATTACH_SOCK="/tmp/aic-$(id -u)/aicd-attach.sock"
if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    ATTACH_SOCK="$XDG_RUNTIME_DIR/aic/aicd-attach.sock"
fi

wait_for_attach_socket() {
    local deadline=$(( $(date +%s) + 10 ))  # 10초 상한
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -S "$ATTACH_SOCK" ]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

echo "Phase ${PHASE}: aic-session ${COUNT}개를 tmux session '$SESSION' 에 기동"
echo "  binary: $AIC_SESSION_BIN"

# window 0 — aicd (옵션) 또는 첫 번째 세션
first_idx=1
if [ "$WITH_AICD" -eq 1 ]; then
    if [ ! -x "$AICD_BIN" ]; then
        echo "error: $AICD_BIN 이 없습니다." >&2
        exit 2
    fi
    echo "  window 0: aicd (${ENV_PREFIX}$AICD_BIN)"
    tmux new-session -d -s "$SESSION" -n "aicd" \
        "${ENV_PREFIX}exec '$AICD_BIN'"

    echo -n "  aicd attach socket 대기 ($ATTACH_SOCK) ... "
    if wait_for_attach_socket; then
        echo "ready"
    else
        echo "TIMEOUT"
        echo "error: aicd 가 10초 안에 attach socket 을 바인드하지 못했습니다." >&2
        echo "       'tmux attach -t $SESSION' 로 window 0 의 aicd 로그를 확인하세요." >&2
        exit 1
    fi
else
    # 첫 세션을 window 0 으로
    echo "  window 0: aic-session #1"
    tmux new-session -d -s "$SESSION" -n "sess-1" \
        "${ENV_PREFIX}exec '$AIC_SESSION_BIN'"
    first_idx=2
fi

for i in $(seq "$first_idx" "$COUNT"); do
    echo "  window $((i - (1 - WITH_AICD))): aic-session #${i}"
    tmux new-window -t "$SESSION:" -n "sess-${i}" \
        "${ENV_PREFIX}exec '$AIC_SESSION_BIN'"
done

echo ""
echo "✓ tmux session '$SESSION' 기동 완료"
echo ""
echo "다음 단계:"
echo "  1. 잠깐 대기 (세션들이 raw mode 설정 완료하도록):"
echo "     sleep 5"
echo "  2. 프로세스 수 확인:"
echo "     scripts/pkill-aic.sh --status"
echo "  3. 측정:"
echo "     scripts/measure-rss-phase${PHASE}.sh --processes ${COUNT}"
echo "  4. 정리:"
echo "     tmux kill-session -t $SESSION"
echo "     scripts/pkill-aic.sh"
