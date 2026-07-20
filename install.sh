#!/bin/sh
# aic installer — POSIX sh
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/x-mesh/aic/main/install.sh | sh
#
# Env overrides:
#   AIC_VERSION=v0.3.0       특정 버전 고정 (default: latest)
#   AIC_INSTALL_DIR=/path    설치 경로 (default: /usr/local/bin → fallback ~/.local/bin)
#
# RCA one-click enrollment:
#   curl -fsSL https://rca.example/install/aic | sh -s -- \
#     --server https://rca.example --auth-key rca-auth-...
#
# 무엇을 설치하나:
#   - aic           : CLI
#   - aic-session   : PTY wrapper
#   - aicd          : supervisor daemon
#
# 검증:
#   release의 checksums.txt에서 sha256을 확인하고, 일치하지 않으면 즉시 실패.

set -eu

REPO="x-mesh/aic"
BINS="aic aic-session aicd"
enroll_server=""
enroll_key=""

err()  { printf "aic-install: %s\n" "$*" >&2; exit 1; }
info() { printf "aic-install: %s\n" "$*"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server)
      [ "$#" -ge 2 ] || err "--server requires a value"
      enroll_server=$2
      shift 2
      ;;
    --auth-key)
      [ "$#" -ge 2 ] || err "--auth-key requires a value"
      enroll_key=$2
      shift 2
      ;;
    *) err "unknown argument: $1" ;;
  esac
done

if [ -n "$enroll_server" ] && [ -z "$enroll_key" ]; then
  err "--server requires --auth-key"
fi
if [ -n "$enroll_key" ] && [ -z "$enroll_server" ]; then
  err "--auth-key requires --server"
fi

# --- detect os/arch ---------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) err "지원하지 않는 아키텍처: $arch" ;;
esac
case "$os" in
  linux|darwin) ;;
  *) err "지원하지 않는 OS: $os" ;;
esac

command -v curl >/dev/null 2>&1 || err "curl가 필요합니다"
command -v tar  >/dev/null 2>&1 || err "tar가 필요합니다"

# --- pick version -----------------------------------------------------------
version=${AIC_VERSION:-}
if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$version" ] || err "최신 release tag 조회 실패"
fi
case "$version" in v*) ;; *) version="v$version" ;; esac
version_no_v=${version#v}

asset="aic_${version_no_v}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"

# --- download + verify ------------------------------------------------------
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t aic-install)
trap 'rm -rf "$tmp"' EXIT INT TERM

info "downloading ${asset} (${version})"
curl -fsSL "${base}/${asset}"        -o "$tmp/$asset"        || err "다운로드 실패: ${base}/${asset}"
curl -fsSL "${base}/checksums.txt"   -o "$tmp/checksums.txt" || err "다운로드 실패: ${base}/checksums.txt"

expected=$(awk -v f="$asset" '$2 == f {print $1}' "$tmp/checksums.txt")
[ -n "$expected" ] || err "checksums.txt에 $asset 항목이 없음"

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
else
  err "sha256 도구가 없음 (coreutils 또는 shasum 설치 필요)"
fi
[ "$expected" = "$actual" ] || err "checksum 불일치 (expected $expected, got $actual)"

tar -xzf "$tmp/$asset" -C "$tmp" || err "압축 해제 실패"

# --- install ----------------------------------------------------------------
default_dir=/usr/local/bin
target_dir=${AIC_INSTALL_DIR:-$default_dir}

install_one() {
  src=$1
  dst_dir=$2
  bin=$(basename "$src")
  if [ -w "$dst_dir" ]; then
    install -m 0755 "$src" "$dst_dir/$bin"
  elif [ "$dst_dir" = "$default_dir" ] && command -v sudo >/dev/null 2>&1; then
    sudo install -m 0755 "$src" "$dst_dir/$bin"
  else
    return 1
  fi
}

install_all_to() {
  dir=$1
  mkdir -p "$dir" 2>/dev/null || true
  for bin in $BINS; do
    src="$tmp/$bin"
    [ -f "$src" ] || err "archive에 $bin이 없음"
    install_one "$src" "$dir" || return 1
  done
}

if [ "$target_dir" = "$default_dir" ] && [ ! -w "$default_dir" ] && command -v sudo >/dev/null 2>&1; then
  info "$default_dir에 쓰기 권한 없음 — sudo로 설치"
fi

if ! install_all_to "$target_dir"; then
  fallback="$HOME/.local/bin"
  info "$target_dir에 설치 실패 — $fallback로 fallback"
  install_all_to "$fallback" || err "설치 실패 (쓸 수 있는 위치 없음)"
  target_dir=$fallback
fi

info "installed ${version} → $target_dir/{$(echo "$BINS" | tr ' ' ',')}"

if [ -n "$enroll_key" ]; then
  info "enrolling this host with RCA"
  "$target_dir/aic" enroll --server "$enroll_server" --auth-key "$enroll_key"
fi

case ":$PATH:" in
  *":$target_dir:"*) ;;
  *) printf "\n  PATH에 %s 추가:\n    export PATH=\"%s:\$PATH\"\n\n" "$target_dir" "$target_dir" ;;
esac

cat <<'EOF'

다음 단계:
  aic config              # provider/api_key/model 대화형 설정
  aic init zsh            # ~/.zshrc에 hook source 라인 추가 (bash도 가능)
  aic daemon install      # aicd를 launchd/systemd에 등록 (선택)

업데이트: aic update
EOF
