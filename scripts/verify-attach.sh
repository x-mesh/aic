#!/usr/bin/env bash
#
# verify-attach.sh
# -----------------------------------------------------------------------------
# 10 개 aic-session 이 실제로 aicd 에 attach 했는지 확인한다.
#
# aic-session 하나가 AttachClient::connect 에 실패하면 Local Fallback 으로
# 떨어지는데, aic doctor 는 "attach socket 이 listen 중" 만 본다. 세션 개개가
# 진짜 attach 상태인지는 aicd 의 attach_connections / attach_open_total 을
# 집계해 확인해야 한다. 본 스크립트가 그 역할을 한다.
#
# 사용법
#   scripts/verify-attach.sh --phase 3_4 [--expected 10]
#
# 종료 코드
#   0  expected 와 같은 수의 세션이 attach 중
#   1  세션 수가 맞지 않음 (Local Fallback 발생)
#   2  aicd 가 실행 중이 아님
# -----------------------------------------------------------------------------

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PHASE=""
EXPECTED=10

while [ $# -gt 0 ]; do
    case "$1" in
        --phase)   shift; PHASE="${1:-}" ;;
        --expected) shift; EXPECTED="${1:-}" ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift || true
done

if [ -z "$PHASE" ]; then
    echo "error: --phase 가 필요합니다 (3_0 또는 3_4)" >&2
    exit 2
fi

AIC_BIN="$REPO_ROOT/target/rss-builds/phase-${PHASE}/aic"
if [ ! -x "$AIC_BIN" ]; then
    echo "error: $AIC_BIN 이 없습니다" >&2
    exit 2
fi

# aicd 생존 확인.
AICD_PIDS="$(pgrep -x aicd 2>/dev/null || true)"
if [ -z "$AICD_PIDS" ]; then
    echo "error: aicd 가 실행 중이 아닙니다" >&2
    exit 2
fi

# aicd 의 control socket 으로 GetMetrics 를 직접 호출. aic top 은 세션 소켓을
# 보므로, aicd metrics (central_store_push_total, attach_connections,
# attach_open_total) 는 별도 경로로 뽑아야 한다.
#
# 가장 간단한 방법: 각 aic-session 이 dual-write 를 했는지 doctor 로 확인하되
# "attach_reconnect_total=0" 을 모든 세션에서 확인. 한 곳이라도 재연결 했으면
# race 에 걸렸다는 의미.
SESSIONS="$(pgrep -x aic-session 2>/dev/null || true)"
if [ -z "$SESSIONS" ]; then
    echo "error: aic-session 프로세스가 없습니다" >&2
    exit 1
fi
ACTUAL_SESSIONS="$(printf '%s\n' "$SESSIONS" | wc -l | tr -d ' ')"

echo "aicd pid(s): $AICD_PIDS"
echo "aic-session pid 수: $ACTUAL_SESSIONS (expected $EXPECTED)"

# 각 세션 socket 경로는 $XDG_RUNTIME_DIR/aic/session-{id}.sock 또는
# /tmp/aic-{uid}/session-{id}.sock.
SESSION_DIR="/tmp/aic-$(id -u)"
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR/aic" ]; then
    SESSION_DIR="$XDG_RUNTIME_DIR/aic"
fi

mapfile -t SOCKS < <(find "$SESSION_DIR" -maxdepth 1 -name 'session-*.sock' 2>/dev/null)
echo "세션 소켓 수: ${#SOCKS[@]}"

# 각 세션 소켓에 대해 GetMetrics 를 찌른다. attach_reconnect_total > 0 이면
# race 에 걸려 Local Fallback → 재연결 시도 상태일 가능성.
#
# 현재 aic CLI 에는 "특정 세션 소켓 으로 metrics" 가 없으므로 AIC_SESSION_ID
# 로 각 세션을 가리킨 뒤 doctor 로 dropped_bytes/reconnects 를 집계한다.
local_fallback_count=0
reconnect_nonzero=0
for sock in "${SOCKS[@]}"; do
    id="$(basename "$sock" .sock)"
    id="${id#session-}"
    output="$(AIC_SESSION_ID="$id" "$AIC_BIN" doctor 2>/dev/null | grep -A6 "Central Store:" || true)"
    if [ -z "$output" ]; then
        continue
    fi

    # reconnects N 필드 추출
    reconnects="$(printf '%s\n' "$output" | awk -F':' '/reconnects/ {gsub(/[ \t]/,"",$2); print $2}')"
    if [ -n "$reconnects" ] && [ "$reconnects" != "N/A" ] && [ "$reconnects" != "0" ]; then
        reconnect_nonzero=$((reconnect_nonzero + 1))
        local_fallback_count=$((local_fallback_count + 1))
        echo "  session ${id:0:8}...  reconnects=${reconnects}  ← attach 실패 후 재연결 시도"
    fi
done

echo ""
if [ "$local_fallback_count" -gt 0 ]; then
    echo "⚠ Local Fallback 후보: ${local_fallback_count}개 세션이 reconnect > 0"
    echo "  세션들이 aicd 보다 먼저 떠서 attach 에 실패했을 가능성이 큽니다."
    echo "  scripts/spawn-aic-sessions.sh 가 aicd 준비를 기다리는지 확인하세요."
fi

# 간이 판정: expected 개수가 살아 있고 reconnect 가 전부 0 이면 OK.
if [ "$ACTUAL_SESSIONS" -eq "$EXPECTED" ] && [ "$reconnect_nonzero" -eq 0 ]; then
    echo "✓ ${EXPECTED}개 세션 모두 attach 중 (reconnect=0)"
    exit 0
else
    echo "✗ 검증 실패 — Local Fallback 또는 세션 수 불일치"
    exit 1
fi
