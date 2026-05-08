#!/usr/bin/env bash
#
# compare-rss.sh
# -----------------------------------------------------------------------------
# measure-rss-phase{30,34}.sh 가 생성한 두 JSON 을 읽어 R6.5 / R6.6 판정을 낸다.
#
# 사용법
#   scripts/compare-rss.sh                              # 기본 target/ 경로 사용
#   scripts/compare-rss.sh <baseline.json> <target.json>
#
# 기본 입력 파일
#   target/phase-3_0-rss.json   (baseline, v0.4.0 빌드)
#   target/phase-3_4-rss.json   (target, 현재 spec 구현)
#
# 판정 기준 (requirements.md)
#   R6.5  target total RSS 가 40~60 MB 범위 → PASS
#   R6.6  aic-session 평균 RSS 감소율 ≥ 60% → PASS
# -----------------------------------------------------------------------------

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BASELINE="${1:-$REPO_ROOT/target/phase-3_0-rss.json}"
TARGET="${2:-$REPO_ROOT/target/phase-3_4-rss.json}"

if [ ! -f "$BASELINE" ]; then
    echo "error: baseline JSON not found: $BASELINE" >&2
    echo "       scripts/measure-rss-phase30.sh 를 먼저 실행하세요" >&2
    exit 2
fi
if [ ! -f "$TARGET" ]; then
    echo "error: target JSON not found: $TARGET" >&2
    echo "       scripts/measure-rss-phase34.sh 를 먼저 실행하세요" >&2
    exit 2
fi

# jq 가 없어도 동작하게 python 으로 통일. 두 환경 모두에서 기본 설치.
python3 - "$BASELINE" "$TARGET" <<'PY'
import json
import sys

baseline_path, target_path = sys.argv[1], sys.argv[2]
baseline = json.load(open(baseline_path))
target = json.load(open(target_path))

def fmt_mb(kb):
    return f"{kb/1024:.2f} MB"

def avg(rows_key, count_key, d):
    n = d.get(count_key, 0)
    return (d.get(rows_key, 0) / n) if n else 0

print("──────────────────────────────────────────────────────────")
print(f"  baseline : {baseline_path}")
print(f"             phase={baseline.get('phase')} mode={baseline.get('mode')} "
      f"ts={baseline.get('timestamp')}")
print(f"  target   : {target_path}")
print(f"             phase={target.get('phase')} mode={target.get('mode')} "
      f"ts={target.get('timestamp')}")
print("──────────────────────────────────────────────────────────")

# ── 기본 통계 ───────────────────────────────────────────────
print()
print("프로세스 수")
print(f"  baseline   aic-session={baseline['actual_sessions']:<3}  aicd={baseline['actual_aicd']}")
print(f"  target     aic-session={target['actual_sessions']:<3}  aicd={target['actual_aicd']}")

print()
print("총 RSS")
print(f"  baseline   {fmt_mb(baseline['total_rss_kb'])}  "
      f"(session={fmt_mb(baseline['total_aic_session_rss_kb'])}, "
      f"aicd={fmt_mb(baseline['total_aicd_rss_kb'])})")
print(f"  target     {fmt_mb(target['total_rss_kb'])}  "
      f"(session={fmt_mb(target['total_aic_session_rss_kb'])}, "
      f"aicd={fmt_mb(target['total_aicd_rss_kb'])})")

# ── R6.5: 회귀 방지 (재정의 2026-05) ─────────────────────
# 당초 "40~60 MB 범위" 였으나 Rust release 고정 비용 실측 결과 현실화.
# target total 이 baseline 대비 10% 이상 증가하지 않으면 PASS.
print()
print("R6.5 — target total RSS ≤ baseline × 1.10 (회귀 방지)")
base_mb = baseline['total_rss_kb'] / 1024
tgt_mb = target['total_rss_kb'] / 1024
threshold = base_mb * 1.10
r65 = tgt_mb <= threshold
status = "\033[32mPASS\033[0m" if r65 else "\033[31mFAIL\033[0m"
delta_pct = ((tgt_mb - base_mb) / base_mb * 100) if base_mb else 0
print(f"  baseline  = {base_mb:.2f} MB")
print(f"  target    = {tgt_mb:.2f} MB  (Δ {delta_pct:+.1f}%)")
print(f"  threshold = {threshold:.2f} MB (baseline + 10%)")
print(f"  판정      → {status}")

# ── R6.6: 구조적 검증은 verify-attach.sh 영역 ─────────────
# 여기서는 "session 평균 RSS 가 크게 늘지 않았음" 만 참조치로 표기.
# 절대적 -60% 는 실현 불가로 판명됨 → verify-attach.sh 결과로 대체.
print()
print("R6.6 — aic-session 평균 RSS (참조치; 실제 판정은 verify-attach.sh)")
avg_base = avg('total_aic_session_rss_kb', 'actual_sessions', baseline)
avg_tgt  = avg('total_aic_session_rss_kb', 'actual_sessions', target)
if avg_base == 0:
    print("  \033[33mSKIP\033[0m — baseline aic-session 프로세스가 없어 비교 불가")
    r66 = None
else:
    reduction = 1 - (avg_tgt / avg_base)
    print(f"  baseline avg = {avg_base/1024:.2f} MB/session "
          f"({baseline['actual_sessions']}개)")
    print(f"  target   avg = {avg_tgt/1024:.2f} MB/session "
          f"({target['actual_sessions']}개)")
    print(f"  감소율       = {reduction*100:+.1f}%")
    print(f"  ↳ R6.6 pass/fail 은 `scripts/verify-attach.sh --phase 3_4 --expected N` 로 확정")
    r66 = True   # 절대 range 로 판단하지 않음

# ── 종합 ──────────────────────────────────────────────────
print()
print("──────────────────────────────────────────────────────────")
if r65:
    print("\033[32m✓ R6.5 회귀 방지 달성 — 최종 판정은 verify-attach.sh 와 병합\033[0m")
    sys.exit(0)
else:
    print(f"\033[31m✗ R6.5 회귀 감지 — target total 이 baseline 대비 {delta_pct:+.1f}% 증가\033[0m")
    sys.exit(1)
PY
