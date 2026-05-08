#!/usr/bin/env bash
#
# measure-rss-phase30.sh
# -----------------------------------------------------------------------------
# Phase 3.0 baseline 측정 wrapper. measure-rss-phase34.sh 에 --phase 3_0 을
# 고정해 호출한다. 출력 파일은 target/phase-3_0-rss.json.
#
# 사용 시나리오: 동일 하드웨어에서 Phase 3.0 (central store 미적용) 빌드로
# aic-session N개를 기동한 상태에서 실행하고, Phase 3.4 빌드로 갈아탄 뒤
# measure-rss-phase34.sh 를 다시 돌려 R6.6 (aic-session RSS -60%) 비교를
# 수행한다.
# -----------------------------------------------------------------------------

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/measure-rss-phase34.sh" --phase 3_0 "$@"
