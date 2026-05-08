#!/usr/bin/env bash
#
# measure-rss-phase34.sh
# -----------------------------------------------------------------------------
# centralized-record-store spec — Task 4.5
# Phase 3.4 RSS 측정 harness (R6.5, R6.6).
#
# Linux / macOS 공통. POSIX-compliant `ps -o rss,comm -p <pid>`로 KB 단위 RSS
# (RSS = Resident Set Size, kilobytes) 를 모아 target/phase-3_N-rss.json 을
# 생성한다.
#
# 사용법
#   scripts/measure-rss-phase34.sh [OPTIONS]
#
# 옵션
#   --phase 3_0|3_4        측정 대상 빌드의 Phase 라벨. JSON 파일명과
#                          기준값 해석에 쓰인다. 기본값 3_4.
#   --single               aic-session 프로세스 1개만 측정(steady-state).
#                          기본은 multi 모드: 사용자가 미리 기동해 둔 모든
#                          aic-session + aicd 의 total RSS 를 집계.
#   --processes N          multi 모드에서 기대하는 aic-session 프로세스 수.
#                          실제 개수와 달라도 경고만 찍고 계속 진행한다.
#                          기본값 10 (R6.5 시나리오).
#   --wait SECONDS         수집 직전 steady-state 대기 시간. 기본 30.
#   --output PATH          결과 JSON 출력 경로. 기본
#                          target/phase-${PHASE}-rss.json.
#   --help                 도움말.
#
# 전제
#   - 사용자가 이미 별도 터미널(iTerm/tmux 등)에서 `aic-session` 프로세스를
#     N 개 기동해 두었어야 한다. 본 스크립트는 TTY 를 가지지 않으므로
#     직접 aic-session 을 띄우지 않는다.
#   - `aicd` 가 기동 중이어야 Central_Store_Flag=true 경로의 RSS 를 비교할 수
#     있다. `aic doctor` 또는 `pgrep aicd` 로 확인한다.
#
# 해석 기준 (spec requirements.md 참조)
#   R6.5  10 aic-session + 1 aicd 의 total RSS 가 40~60 MB 범위에 들어와야
#         Phase 3.4 목표 달성.
#   R6.6  동일 조건에서 aic-session 평균 RSS 가 Phase 3.0 baseline 대비
#         60% 이상 감소해야 한다. 비교는 두 번 실행(--phase 3_0, --phase 3_4)
#         후 JSON 파일을 대조.
#
# 출력 JSON 스키마는 scripts/README.md 참조.
# -----------------------------------------------------------------------------

set -u
set -o pipefail

PHASE="3_4"
MODE="multi"
EXPECTED_SESSIONS=10
WAIT_SECONDS=30
OUTPUT_PATH=""

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --phase)
            shift
            PHASE="${1:-}"
            if [ -z "$PHASE" ]; then
                echo "error: --phase requires an argument (e.g. 3_0 or 3_4)" >&2
                exit 2
            fi
            ;;
        --single)
            MODE="single"
            EXPECTED_SESSIONS=1
            ;;
        --processes)
            shift
            EXPECTED_SESSIONS="${1:-}"
            if ! printf '%s' "$EXPECTED_SESSIONS" | grep -Eq '^[0-9]+$'; then
                echo "error: --processes requires a non-negative integer" >&2
                exit 2
            fi
            ;;
        --wait)
            shift
            WAIT_SECONDS="${1:-}"
            if ! printf '%s' "$WAIT_SECONDS" | grep -Eq '^[0-9]+$'; then
                echo "error: --wait requires a non-negative integer (seconds)" >&2
                exit 2
            fi
            ;;
        --output)
            shift
            OUTPUT_PATH="${1:-}"
            if [ -z "$OUTPUT_PATH" ]; then
                echo "error: --output requires a path" >&2
                exit 2
            fi
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift || true
done

# --------------------------------------------------------------------------
# 출력 경로 준비
# --------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -z "$OUTPUT_PATH" ]; then
    OUTPUT_PATH="$REPO_ROOT/target/phase-${PHASE}-rss.json"
fi
OUTPUT_DIR="$(dirname "$OUTPUT_PATH")"
mkdir -p "$OUTPUT_DIR"

# --------------------------------------------------------------------------
# steady-state 대기
# --------------------------------------------------------------------------
echo "measure-rss-phase34: phase=${PHASE} mode=${MODE} expected_sessions=${EXPECTED_SESSIONS} wait=${WAIT_SECONDS}s"
echo "measure-rss-phase34: output=${OUTPUT_PATH}"
if [ "$WAIT_SECONDS" -gt 0 ]; then
    echo "measure-rss-phase34: waiting ${WAIT_SECONDS}s for steady state..."
    sleep "$WAIT_SECONDS"
fi

# --------------------------------------------------------------------------
# pgrep wrapper — macOS / Linux 모두에서 동작하는 이름 매칭.
#   - macOS `pgrep` 은 BSD 계열로 프로세스 "이름" 을 부분 매칭한다.
#   - Linux `pgrep` 은 기본으로 comm 필드에 대해 regex 매칭한다.
# 둘 다 "^aic-session$" 류 full-match 는 -x 로 지원.
# --------------------------------------------------------------------------
pgrep_exact() {
    # $1: 프로세스 comm (e.g. "aic-session", "aicd")
    pgrep -x "$1" 2>/dev/null || true
}

collect_rss() {
    # $1: 프로세스 이름. 출력: "pid rss_kb comm" 라인 0+개.
    # ps -o rss,comm -p <pid> 출력은 플랫폼에 상관없이 KB 단위 RSS 를 준다.
    local proc_name="$1"
    local pids
    pids="$(pgrep_exact "$proc_name")"
    if [ -z "$pids" ]; then
        return 0
    fi
    # ps 포맷: rss(KB)  comm. macOS 는 `comm` 필드에 전체 경로가 오는 경우가
    # 있으므로 basename 으로 정규화.
    # shellcheck disable=SC2086
    ps -o pid=,rss=,comm= -p $pids 2>/dev/null | awk '
        {
            pid=$1; rss=$2;
            comm=$3;
            n=split(comm, parts, "/");
            comm=parts[n];
            printf "%s %s %s\n", pid, rss, comm;
        }
    '
}

# --------------------------------------------------------------------------
# 수집
# --------------------------------------------------------------------------
AIC_SESSION_ROWS="$(collect_rss aic-session || true)"
AICD_ROWS="$(collect_rss aicd || true)"

# single 모드: aic-session 이 여러 개면 RSS 가장 큰 1개만 남긴다(steady state
# 가정). aicd 는 집계에서 제외한다.
if [ "$MODE" = "single" ]; then
    if [ -n "$AIC_SESSION_ROWS" ]; then
        AIC_SESSION_ROWS="$(printf '%s\n' "$AIC_SESSION_ROWS" \
            | sort -k2 -n -r | head -n 1)"
    fi
    AICD_ROWS=""
fi

# actual counts
if [ -n "$AIC_SESSION_ROWS" ]; then
    ACTUAL_SESSIONS="$(printf '%s\n' "$AIC_SESSION_ROWS" | wc -l | tr -d ' ')"
else
    ACTUAL_SESSIONS=0
fi
if [ -n "$AICD_ROWS" ]; then
    ACTUAL_AICD="$(printf '%s\n' "$AICD_ROWS" | wc -l | tr -d ' ')"
else
    ACTUAL_AICD=0
fi

# 경고만 찍고 계속 진행(수집 자체는 의미 있다)
if [ "$MODE" = "multi" ] && [ "$ACTUAL_SESSIONS" -ne "$EXPECTED_SESSIONS" ]; then
    echo "measure-rss-phase34: WARN expected ${EXPECTED_SESSIONS} aic-session but found ${ACTUAL_SESSIONS}" >&2
fi
if [ "$MODE" = "multi" ] && [ "$ACTUAL_AICD" -eq 0 ]; then
    echo "measure-rss-phase34: WARN no aicd process detected — central_store path cannot be verified" >&2
fi

# sum
sum_rss() {
    # stdin: "pid rss comm" 라인들. 출력: 총합(KB).
    awk 'BEGIN {s=0} {s+=$2} END {printf "%d\n", s}'
}

TOTAL_AIC_SESSION_RSS_KB="$(printf '%s\n' "$AIC_SESSION_ROWS" | sum_rss)"
TOTAL_AICD_RSS_KB="$(printf '%s\n' "$AICD_ROWS" | sum_rss)"
TOTAL_RSS_KB=$(( TOTAL_AIC_SESSION_RSS_KB + TOTAL_AICD_RSS_KB ))

# --------------------------------------------------------------------------
# JSON 출력 (jq 없이 손으로 조립 — 외부 의존성을 최소화)
# --------------------------------------------------------------------------
TIMESTAMP="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
HOSTNAME_S="$(hostname 2>/dev/null || echo unknown)"
UNAME_S="$(uname -a 2>/dev/null || echo unknown)"

json_escape() {
    # 매우 단순한 문자열 escape — ", \, 제어문자만 처리.
    awk 'BEGIN { ORS="" } {
        gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t");
        gsub(/\r/, "\\r"); gsub(/\n/, "\\n");
        print
    }'
}

emit_rows_json() {
    # stdin: "pid rss comm" 라인들. stdout: JSON array.
    local first=1
    printf '['
    while read -r pid rss comm; do
        if [ -z "${pid:-}" ]; then
            continue
        fi
        if [ $first -eq 0 ]; then
            printf ','
        fi
        local comm_escaped
        comm_escaped="$(printf '%s' "$comm" | json_escape)"
        printf '{"pid":%s,"rss_kb":%s,"command":"%s"}' "$pid" "$rss" "$comm_escaped"
        first=0
    done
    printf ']'
}

AIC_SESSION_JSON="$(printf '%s\n' "$AIC_SESSION_ROWS" | emit_rows_json)"
AICD_JSON="$(printf '%s\n' "$AICD_ROWS" | emit_rows_json)"

HOSTNAME_J="$(printf '%s' "$HOSTNAME_S" | json_escape)"
UNAME_J="$(printf '%s' "$UNAME_S" | json_escape)"

# 해석 기준 판정 (R6.5). R6.6 은 별도 phase 비교가 필요하므로 note 만.
R6_5_PASS="false"
if [ "$MODE" = "multi" ] && [ "$ACTUAL_SESSIONS" -ge 1 ]; then
    # 40MB = 40960KB, 60MB = 61440KB
    if [ "$TOTAL_RSS_KB" -ge 40960 ] && [ "$TOTAL_RSS_KB" -le 61440 ]; then
        R6_5_PASS="true"
    fi
fi

TOTAL_MB="$(awk -v kb="$TOTAL_RSS_KB" 'BEGIN { printf "%.2f", kb/1024 }')"

{
    printf '{\n'
    printf '  "phase": "%s",\n' "$PHASE"
    printf '  "mode": "%s",\n' "$MODE"
    printf '  "timestamp": "%s",\n' "$TIMESTAMP"
    printf '  "hostname": "%s",\n' "$HOSTNAME_J"
    printf '  "uname": "%s",\n' "$UNAME_J"
    printf '  "expected_sessions": %s,\n' "$EXPECTED_SESSIONS"
    printf '  "actual_sessions": %s,\n' "$ACTUAL_SESSIONS"
    printf '  "actual_aicd": %s,\n' "$ACTUAL_AICD"
    printf '  "wait_seconds": %s,\n' "$WAIT_SECONDS"
    printf '  "aic_session_processes": %s,\n' "$AIC_SESSION_JSON"
    printf '  "aicd_processes": %s,\n' "$AICD_JSON"
    printf '  "total_aic_session_rss_kb": %s,\n' "$TOTAL_AIC_SESSION_RSS_KB"
    printf '  "total_aicd_rss_kb": %s,\n' "$TOTAL_AICD_RSS_KB"
    printf '  "total_rss_kb": %s,\n' "$TOTAL_RSS_KB"
    printf '  "total_rss_mb": %s,\n' "$TOTAL_MB"
    printf '  "interpretation": {\n'
    printf '    "R6_5_range_mb": "40-60",\n'
    printf '    "R6_5_pass": %s,\n' "$R6_5_PASS"
    printf '    "R6_6_note": "Run twice (--phase 3_0 and --phase 3_4) and compare aic_session RSS; target is >=60%% reduction."\n'
    printf '  }\n'
    printf '}\n'
} > "$OUTPUT_PATH"

echo "measure-rss-phase34: wrote ${OUTPUT_PATH}"
echo "measure-rss-phase34: total_rss_kb=${TOTAL_RSS_KB} (~${TOTAL_MB} MB), R6.5_pass=${R6_5_PASS}"

# ── 측정 실패 감지 ───────────────────────────────────────────────
# 프로세스가 0 개인 상태로 JSON 을 남기면 사용자는 나중에 compare-rss.sh 에서만
# 알아채게 된다. 측정 시점에 바로 exit 1 로 탈출해 "왜 0 이지" 왕복을 막는다.
if [ "$ACTUAL_SESSIONS" -eq 0 ] && [ "$ACTUAL_AICD" -eq 0 ]; then
    echo "" >&2
    echo "measure-rss-phase34: ERROR aic-session / aicd 프로세스가 하나도 없습니다." >&2
    echo "  측정 전 준비 사항:" >&2
    echo "    1. Phase ${PHASE} 빌드의 aicd 를 띄우세요." >&2
    echo "       예) target/rss-builds/phase-${PHASE}/aicd &" >&2
    echo "    2. 별도 터미널에서 aic-session 을 ${EXPECTED_SESSIONS} 개 띄우세요." >&2
    echo "       (tmux/iTerm 탭마다 target/rss-builds/phase-${PHASE}/aic-session)" >&2
    echo "    3. 띄운 뒤 다시 본 스크립트를 실행하세요." >&2
    echo "" >&2
    echo "  현재 상태 확인: scripts/pkill-aic.sh --status" >&2
    exit 1
fi
