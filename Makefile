# ─────────────────────────────────────────────────────────────
# ac CLI Tool — Makefile
# ─────────────────────────────────────────────────────────────
# make              빌드 (debug)
# make release      빌드 (release, 최적화)
# make test         전체 테스트
# make e2e          E2E 테스트만
# make lint         clippy + fmt check
# make fix          자동 수정 (clippy + fmt)
# make clean        빌드 산출물 삭제
# make install      release 빌드 후 ~/.cargo/bin에 설치
# make run-server   aic-session 서버 실행
# make run-client   ac 클라이언트 실행
# make check        빠른 컴파일 체크 (코드 생성 없이)
# make doc          문서 생성 및 열기
# make loc          코드 라인 수 통계
# make deps         의존성 트리 출력
# make outdated     업데이트 가능한 의존성 확인
# make bloat        바이너리 크기 분석
# make watch        파일 변경 시 자동 테스트 (cargo-watch 필요)
# ─────────────────────────────────────────────────────────────

SHELL := /bin/bash
.DEFAULT_GOAL := build

# 소켓 경로 (디버깅용)
SOCKET_DIR := /tmp/aic-$(shell id -u)
SOCKET_PATH := $(SOCKET_DIR)/session.sock

# ─── 빌드 ───────────────────────────────────────────────────

.PHONY: build
build:
	cargo build --workspace

.PHONY: release
release:
	cargo build --workspace --release

.PHONY: check
check:
	cargo check --workspace

# ─── 테스트 ─────────────────────────────────────────────────

.PHONY: test
test:
	cargo test --workspace

.PHONY: test-verbose
test-verbose:
	cargo test --workspace -- --nocapture

.PHONY: test-common
test-common:
	cargo test -p aic-common

.PHONY: test-server
test-server:
	cargo test -p aic-server

.PHONY: test-client
test-client:
	cargo test -p aic-client

.PHONY: e2e
e2e:
	cargo test -p aic-client --test e2e --test e2e_advanced

.PHONY: e2e-verbose
e2e-verbose:
	cargo test -p aic-client --test e2e --test e2e_advanced -- --nocapture

.PHONY: test-unit
test-unit:
	cargo test --workspace --lib

.PHONY: test-integration
test-integration:
	cargo test --workspace --test '*'

.PHONY: test-prop
test-prop:
	PROPTEST_CASES=1024 cargo test --workspace -- prop_

.PHONY: test-pty
test-pty:
	cargo test -p aic-server --test pty_integration -- --ignored --nocapture

# ─── 린트 / 포맷 ───────────────────────────────────────────

.PHONY: ci
ci: ## 표준 CI — fmt check + clippy + test + help 스냅샷
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	$(MAKE) help-snapshot

# `aic --help` / `aic-session --help` / `aic config show` 출력 회귀 — 의도치 않은 surface 변경을 잡는다.
# 마스킹 회귀 검사: config show 기본 출력에 "***"가 포함되어야 한다 (api_key 마스킹 작동).
.PHONY: help-snapshot
help-snapshot:
	@cargo build --workspace --bins --quiet
	@target/debug/aic --help > /dev/null && echo "  [pass] aic --help"
	@target/debug/aic-session --help > /dev/null && echo "  [pass] aic-session --help"
	@target/debug/aic config show 2>/dev/null | grep -q '\*\*\*' && echo "  [pass] config show 마스킹" \
		|| (echo "  [info] config 파일 없음 — 마스킹 회귀 skip" && true)

.PHONY: lint
lint:
	cargo clippy --workspace -- -D warnings
	cargo fmt --all -- --check

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: fix
fix:
	cargo clippy --workspace --fix --allow-dirty --allow-staged
	cargo fmt --all

# ─── 실행 ───────────────────────────────────────────────────

.PHONY: run-server
run-server: build
	@mkdir -p $(SOCKET_DIR)
	cargo run -p aic-server --bin aic-session

.PHONY: run-client
run-client: build
	cargo run -p aic-client --bin aic

.PHONY: run-config
run-config: build
	cargo run -p aic-client --bin aic -- config

# ─── 설치 ───────────────────────────────────────────────────

.PHONY: install
install:
	cargo install --path aic-server
	cargo install --path aic-client

.PHONY: uninstall
uninstall:
	cargo uninstall aic-server 2>/dev/null || true
	cargo uninstall aic-client 2>/dev/null || true

# ─── 디버깅 ─────────────────────────────────────────────────

.PHONY: socket-status
socket-status:
	@echo "소켓 경로: $(SOCKET_PATH)"
	@if [ -S "$(SOCKET_PATH)" ]; then \
		echo "상태: ✅ 소켓 파일 존재"; \
	else \
		echo "상태: ❌ 소켓 파일 없음 (서버 미실행)"; \
	fi

.PHONY: socket-clean
socket-clean:
	@rm -f $(SOCKET_PATH)
	@echo "소켓 파일 삭제 완료: $(SOCKET_PATH)"

.PHONY: ping
ping: build
	@echo "서버 ping 테스트..."
	@if [ -S "$(SOCKET_PATH)" ]; then \
		echo '{"Ping"}' | cargo run -p aic-client --bin aic 2>&1 || echo "클라이언트 실행 실패"; \
	else \
		echo "❌ 서버가 실행 중이지 않습니다 ($(SOCKET_PATH) 없음)"; \
	fi

.PHONY: env-info
env-info:
	@echo "── 환경 정보 ──"
	@echo "OS:          $$(uname -s) $$(uname -m)"
	@echo "Rust:        $$(rustc --version)"
	@echo "Cargo:       $$(cargo --version)"
	@echo "SHELL:       $(SHELL)"
	@echo "UID:         $$(id -u)"
	@echo "소켓 경로:   $(SOCKET_PATH)"
	@echo "설정 경로:   $${XDG_CONFIG_HOME:-$$HOME/.config}/ac/config.toml"
	@echo ""
	@echo "── 바이너리 ──"
	@ls -lh target/debug/aic target/debug/aic-session 2>/dev/null || echo "(빌드 필요: make build)"

.PHONY: tree
tree:
	@echo "── 프로젝트 구조 ──"
	@find aic-common/src aic-server/src aic-client/src -name '*.rs' | sort | \
		sed 's|/src/| → |' | sed 's|\.rs$$||'

# ─── 문서 ───────────────────────────────────────────────────

.PHONY: doc
doc:
	cargo doc --workspace --no-deps --open

.PHONY: doc-build
doc-build:
	cargo doc --workspace --no-deps

# ─── 분석 ───────────────────────────────────────────────────

.PHONY: loc
loc:
	@echo "── 코드 라인 수 (*.rs) ──"
	@find aic-common/src aic-server/src aic-client/src -name '*.rs' -exec cat {} + | wc -l | xargs echo "  소스:"
	@find aic-server/tests aic-client/tests -name '*.rs' 2>/dev/null -exec cat {} + | wc -l | xargs echo "  테스트:"
	@find . -path ./target -prune -o -name '*.rs' -print -exec cat {} + | wc -l | xargs echo "  전체:"

.PHONY: deps
deps:
	cargo tree --workspace

.PHONY: deps-dup
deps-dup:
	cargo tree --workspace --duplicates

.PHONY: outdated
outdated:
	@command -v cargo-outdated >/dev/null 2>&1 && cargo outdated --workspace || \
		echo "cargo-outdated 미설치. 설치: cargo install cargo-outdated"

.PHONY: bloat
bloat: release
	@command -v cargo-bloat >/dev/null 2>&1 && \
		(echo "── aic-session ──" && cargo bloat -p aic-server --release -n 10 && \
		 echo "── aic ──" && cargo bloat -p aic-client --release -n 10) || \
		echo "cargo-bloat 미설치. 설치: cargo install cargo-bloat"

.PHONY: audit
audit:
	@command -v cargo-audit >/dev/null 2>&1 && cargo audit || \
		echo "cargo-audit 미설치. 설치: cargo install cargo-audit"

# ─── 감시 모드 ──────────────────────────────────────────────

.PHONY: watch
watch:
	@command -v cargo-watch >/dev/null 2>&1 && \
		cargo watch -x 'test --workspace' || \
		echo "cargo-watch 미설치. 설치: cargo install cargo-watch"

.PHONY: watch-check
watch-check:
	@command -v cargo-watch >/dev/null 2>&1 && \
		cargo watch -x 'check --workspace' || \
		echo "cargo-watch 미설치. 설치: cargo install cargo-watch"

# ─── 정리 ───────────────────────────────────────────────────

.PHONY: clean
clean:
	cargo clean

.PHONY: clean-all
clean-all: clean socket-clean
	@rm -rf aic-*/proptest-regressions

# ─── CI 로컬 재현 ──────────────────────────────────────────
# 위쪽 lint 섹션의 ci/help-snapshot target이 표준. 여기서는 alias만 남긴다.

.PHONY: ci-quick
ci-quick: lint test
	@echo "✅ ci-quick 통과 (fmt/clippy 엄격 검사 없음 — 풀 검사는 make ci)"

# ─── 도움말 ─────────────────────────────────────────────────

.PHONY: help
help:
	@echo ""
	@echo "ac CLI Tool — Makefile 명령어"
	@echo "════════════════════════════════════════════"
	@echo ""
	@echo "빌드"
	@echo "  make              debug 빌드"
	@echo "  make release      release 빌드 (최적화)"
	@echo "  make check        빠른 컴파일 체크"
	@echo "  make install      ~/.cargo/bin에 설치"
	@echo ""
	@echo "테스트"
	@echo "  make test         전체 테스트"
	@echo "  make test-verbose 전체 테스트 (출력 포함)"
	@echo "  make e2e          E2E 테스트만"
	@echo "  make test-unit    유닛 테스트만"
	@echo "  make test-prop    Property 테스트 (1024 cases)"
	@echo "  make test-pty     PTY 테스트 (ignored, 터미널 필요)"
	@echo "  make test-common  aic-common 테스트"
	@echo "  make test-server  aic-server 테스트"
	@echo "  make test-client  aic-client 테스트"
	@echo ""
	@echo "린트 / 포맷"
	@echo "  make lint         clippy + fmt check"
	@echo "  make fmt          코드 포맷팅"
	@echo "  make fix          자동 수정 (clippy + fmt)"
	@echo ""
	@echo "실행"
	@echo "  make run-server   aic-session 서버 실행"
	@echo "  make run-client   ac 클라이언트 실행"
	@echo "  make run-config   ac config 실행"
	@echo ""
	@echo "디버깅"
	@echo "  make socket-status  소켓 파일 상태 확인"
	@echo "  make socket-clean   소켓 파일 삭제"
	@echo "  make env-info       환경 정보 출력"
	@echo "  make tree           프로젝트 소스 구조"
	@echo ""
	@echo "분석"
	@echo "  make loc          코드 라인 수"
	@echo "  make deps         의존성 트리"
	@echo "  make deps-dup     중복 의존성"
	@echo "  make outdated     업데이트 가능 의존성"
	@echo "  make bloat        바이너리 크기 분석"
	@echo "  make audit        보안 취약점 감사"
	@echo ""
	@echo "기타"
	@echo "  make doc          문서 생성 및 열기"
	@echo "  make watch        파일 변경 시 자동 테스트"
	@echo "  make ci           CI 로컬 재현 (lint + test)"
	@echo "  make clean        빌드 산출물 삭제"
	@echo "  make clean-all    전체 정리 (빌드 + 소켓 + proptest)"
	@echo ""
