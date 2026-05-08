#!/usr/bin/env bash
#
# pkill-aic.sh
# -----------------------------------------------------------------------------
# 현재 실행 중인 `aic-session` / `aicd` 프로세스를 확인하고 종료한다.
# RSS 측정 사이클에서 Phase 3.0 ↔ Phase 3.4 사이를 깨끗하게 전환할 때 쓴다.
#
# 사용법
#   scripts/pkill-aic.sh              # 상태 확인 + SIGTERM + (필요 시) SIGKILL
#   scripts/pkill-aic.sh --status     # 종료 없이 현재 상태만 출력
#   scripts/pkill-aic.sh --force      # SIGTERM 생략하고 바로 SIGKILL
#   scripts/pkill-aic.sh --timeout N  # SIGTERM 후 대기 시간 (초, 기본 3)
# -----------------------------------------------------------------------------

set -u
set -o pipefail

ACTION="term"          # term | force | status
WAIT_SECONDS=3

while [ $# -gt 0 ]; do
    case "$1" in
        --status) ACTION="status" ;;
        --force)  ACTION="force" ;;
        --timeout)
            shift
            WAIT_SECONDS="${1:-}"
            if ! printf '%s' "$WAIT_SECONDS" | grep -Eq '^[0-9]+$'; then
                echo "error: --timeout requires a non-negative integer" >&2
                exit 2
            fi
            ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift || true
done

# ── 프로세스 목록 출력 helper ────────────────────────────────────────
# pgrep + ps 조합으로 pid / rss(KB) / 시작시각 / 커맨드를 한 줄씩 출력.
list_procs() {
    local name="$1"
    local pids
    pids="$(pgrep -x "$name" 2>/dev/null || true)"
    if [ -z "$pids" ]; then
        printf '  %-14s (없음)\n' "$name"
        return 1
    fi
    # shellcheck disable=SC2086
    ps -o pid=,rss=,lstart=,comm= -p $pids 2>/dev/null | awk -v n="$name" '
        {
            pid=$1; rss=$2;
            # lstart 는 "Day Mon DD HH:MM:SS YYYY" 형식으로 5 필드를 차지.
            started=$3" "$4" "$5" "$6" "$7;
            cmd=$8;
            c=split(cmd, parts, "/");
            cmd=parts[c];
            printf "  %-14s pid=%-6s rss=%6sKB  started=%s  cmd=%s\n",
                n, pid, rss, started, cmd;
        }'
    return 0
}

have_proc() {
    pgrep -x "$1" >/dev/null 2>&1
}

show_status() {
    echo "── aic-session / aicd 프로세스 상태 ──"
    local any=0
    list_procs aic-session && any=1
    list_procs aicd && any=1
    if [ $any -eq 0 ]; then
        echo "(실행 중인 프로세스 없음)"
        return 1
    fi
    return 0
}

send_signal() {
    local sig="$1"
    local name="$2"
    local pids
    pids="$(pgrep -x "$name" 2>/dev/null || true)"
    if [ -z "$pids" ]; then
        return 0
    fi
    echo "  → $name 에 $sig 전송: $(echo "$pids" | tr '\n' ' ')"
    # shellcheck disable=SC2086
    kill "-$sig" $pids 2>/dev/null || true
}

# ── 상태만 확인 ─────────────────────────────────────────────────────
if [ "$ACTION" = "status" ]; then
    show_status || exit 0
    exit 0
fi

# ── 현재 상태 보여주고 진행 ─────────────────────────────────────────
if ! show_status; then
    exit 0
fi

# ── --force: 바로 SIGKILL ──────────────────────────────────────────
if [ "$ACTION" = "force" ]; then
    echo ""
    echo "── SIGKILL (--force) ──"
    send_signal KILL aic-session
    send_signal KILL aicd
    sleep 1
    echo ""
    show_status && {
        echo "error: 종료되지 않은 프로세스가 남아 있습니다" >&2
        exit 1
    } || echo "✓ 모두 종료됨"
    exit 0
fi

# ── 기본: SIGTERM → 대기 → 남으면 SIGKILL ───────────────────────────
echo ""
echo "── SIGTERM ──"
send_signal TERM aic-session
send_signal TERM aicd

echo ""
echo "  ${WAIT_SECONDS}초 대기..."
sleep "$WAIT_SECONDS"

# 살아있는 게 있으면 SIGKILL 에스컬레이션
if have_proc aic-session || have_proc aicd; then
    echo ""
    echo "── SIGKILL (escalation) ──"
    send_signal KILL aic-session
    send_signal KILL aicd
    sleep 1
fi

echo ""
if show_status; then
    echo ""
    echo "error: 종료되지 않은 프로세스가 남아 있습니다 (-9 로도 안 죽는 좀비?)" >&2
    exit 1
else
    echo "✓ 모두 종료됨"
fi
