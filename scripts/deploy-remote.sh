#!/usr/bin/env bash
#
# aic 원격 수동 배포 (릴리스 전 검증용)
# ------------------------------------------------------------------------------
# 현재 작업 트리를 linux 타깃으로 cross-build(cargo-zigbuild, 릴리스와 동일한
# `--no-default-features --features phase-3_4`)해서 원격 서버에 aic / aic-session /
# aicd 세 바이너리를 설치하고 aicd 를 재시작한다. GitHub 릴리스를 내기 전에 패치를
# 실서버에서 검증하는 용도다.
#
# 사용법:
#   scripts/deploy-remote.sh <user@host | ssh-alias> [옵션]
#
# 옵션:
#   --install-dir DIR   원격 설치 경로 (기본: 원격의 `command -v aic` 디렉터리,
#                       없으면 ~/.local/bin)
#   --no-restart        설치만 하고 aicd 재시작은 건너뛴다
#   --skip-build        직전 빌드 산출물을 그대로 재사용 (빠른 재배포)
#   --dry-run           실제 변경 없이 수행할 작업만 출력
#
# 예:
#   scripts/deploy-remote.sh ubuntu@okrd-lib-mesh-ingester
#
# 전제: 로컬에 rustup + zig 설치. cargo-zigbuild 와 linux rust 타깃은 이 스크립트가
#       없으면 자동 설치한다(idempotent). 원격은 SSH 키 접속 가능해야 한다.
set -euo pipefail

# --- 인자 파싱 ----------------------------------------------------------------
REMOTE=""
INSTALL_DIR=""
NO_RESTART=0
SKIP_BUILD=0
DRY_RUN=0

usage() { sed -n '2,30p' "$0"; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --no-restart)  NO_RESTART=1; shift ;;
    --skip-build)  SKIP_BUILD=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage 0 ;;
    -*)            echo "알 수 없는 옵션: $1" >&2; usage 1 ;;
    *)             REMOTE="$1"; shift ;;
  esac
done
[[ -n "$REMOTE" ]] || { echo "오류: <user@host | ssh-alias> 가 필요합니다." >&2; usage 1; }

# --- 색상/로그 ----------------------------------------------------------------
if [[ -t 1 ]]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G='' Y='' R='' B='' N=''; fi
log()  { printf '%s▶%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s✔%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s⚠%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
run()  { if [[ $DRY_RUN -eq 1 ]]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FEATURES="phase-3_4"   # .goreleaser.yaml 과 동일 — 릴리스 아티팩트 빌드 조건
BINS=(aic aic-session aicd)

# --- 1. 원격 arch / 설치 경로 감지 -------------------------------------------
log "원격 환경 감지: $REMOTE"
RARCH="$(ssh "$REMOTE" 'uname -m')" || die "SSH 접속 실패: $REMOTE"
case "$RARCH" in
  x86_64|amd64)        TRIPLE="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64)       TRIPLE="aarch64-unknown-linux-gnu" ;;
  *)                   die "지원하지 않는 원격 arch: $RARCH (x86_64/aarch64만 지원)" ;;
esac
ok "원격 arch=$RARCH → target=$TRIPLE"

if [[ -z "$INSTALL_DIR" ]]; then
  INSTALL_DIR="$(ssh "$REMOTE" 'd=$(command -v aic 2>/dev/null) && dirname "$d" || echo "$HOME/.local/bin"')"
fi
ok "원격 설치 경로: $INSTALL_DIR"

CUR_VER="$(ssh "$REMOTE" "'$INSTALL_DIR/aic' --version 2>/dev/null || echo '(미설치)'")"
log "현재 원격 버전: $CUR_VER"

# --- 2. 로컬 cross-build 준비 -------------------------------------------------
if [[ $SKIP_BUILD -eq 0 ]]; then
  command -v zig >/dev/null || die "zig 미설치 — cargo-zigbuild 가 zig 를 필요로 합니다 (brew install zig)."

  if ! command -v cargo-zigbuild >/dev/null; then
    warn "cargo-zigbuild 미설치 — 설치합니다 (cargo install cargo-zigbuild)."
    run cargo install cargo-zigbuild || die "cargo-zigbuild 설치 실패."
  fi

  if ! rustup target list --installed 2>/dev/null | grep -qx "$TRIPLE"; then
    warn "rust 타깃 $TRIPLE 미설치 — 추가합니다."
    run rustup target add "$TRIPLE" || die "rustup target add $TRIPLE 실패."
  fi

  # --- 3. 빌드 (릴리스와 동일 조건) ------------------------------------------
  log "cross-build: target=$TRIPLE, features=$FEATURES"
  run cargo zigbuild --release --target "$TRIPLE" \
      --no-default-features --features "$FEATURES" \
      -p aic-client --bin aic
  run cargo zigbuild --release --target "$TRIPLE" \
      --no-default-features --features "$FEATURES" \
      -p aic-server --bin aic-session --bin aicd
  ok "빌드 완료"
else
  warn "--skip-build: 기존 산출물 재사용"
fi

OUT_DIR="$REPO_ROOT/target/$TRIPLE/release"
for b in "${BINS[@]}"; do
  [[ $DRY_RUN -eq 1 ]] || [[ -x "$OUT_DIR/$b" ]] || die "산출물 없음: $OUT_DIR/$b (--skip-build 를 뺐는지 확인)"
done

# --- 4. 업로드 ----------------------------------------------------------------
STAGE="/tmp/aic-deploy.$$"
log "원격 업로드 → $STAGE"
run ssh "$REMOTE" "mkdir -p '$STAGE'"
for b in "${BINS[@]}"; do
  run scp -q "$OUT_DIR/$b" "$REMOTE:$STAGE/$b"
done
ok "업로드 완료"

# --- 5. 원격 설치 + 재시작 ----------------------------------------------------
# 설치 경로 쓰기 권한 확인 → 없으면 sudo.
WRITABLE="$(ssh "$REMOTE" "test -w '$INSTALL_DIR' && echo yes || echo no")"
SUDO=""
[[ "$WRITABLE" == "yes" ]] || { SUDO="sudo"; warn "$INSTALL_DIR 비쓰기 → sudo 사용"; }

RESTART_BLOCK="echo '  (--no-restart: aicd 재시작 건너뜀)'"
if [[ $NO_RESTART -eq 0 ]]; then
  RESTART_BLOCK="
    if command -v systemctl >/dev/null && systemctl --user is-enabled aicd >/dev/null 2>&1; then
      systemctl --user restart aicd && echo '  aicd 재시작 (systemd --user)'
    else
      ('$INSTALL_DIR/aic' daemon start >/dev/null 2>&1 || '$INSTALL_DIR/aicd' >/dev/null 2>&1 &) && echo '  aicd 재시작 (aic daemon start)'
    fi"
fi

REMOTE_SCRIPT="
set -e
echo '── 기존 aicd 정지'
'$INSTALL_DIR/aic' daemon stop >/dev/null 2>&1 || true
pkill -x aicd >/dev/null 2>&1 || true
sleep 0.5
echo '── 바이너리 설치 → $INSTALL_DIR'
for b in ${BINS[*]}; do
  $SUDO install -m 0755 '$STAGE'/\$b '$INSTALL_DIR'/\$b
done
rm -rf '$STAGE'
echo '── aicd 재시작'
$RESTART_BLOCK
echo '── 설치 후 버전'
'$INSTALL_DIR/aic' --version || true
'$INSTALL_DIR/aicd' --version || true
"

log "원격 설치 + 재시작 실행"
if [[ $DRY_RUN -eq 1 ]]; then
  printf '  [dry-run] ssh %s bash -s <<EOF\n%s\n  EOF\n' "$REMOTE" "$REMOTE_SCRIPT"
else
  ssh "$REMOTE" bash -s <<<"$REMOTE_SCRIPT"
fi

ok "배포 완료: $REMOTE ($TRIPLE, $FEATURES)"
cat <<NOTE

${B}다음 단계${N}
  • aicd zombie 가 이미 떠 있었다면(예: [aicd] defunct), 이번 재시작으로는 사라지지
    않습니다 — zombie 는 그 부모(보통 멈춘 aic-session)가 reap 해야 정리됩니다.
    부모 확인:  ssh $REMOTE 'ps -fp <PPID>'
    부모가 불필요하면:  ssh $REMOTE 'kill <PPID>'  → init 이 zombie 를 reap
  • 새 셸에서 동작 확인 후 문제 없으면 0.16.2 patch 릴리스를 진행하세요.
NOTE
