# Releasing aic

> 새 버전을 GitHub Release로 게시하고 [`x-mesh/homebrew-tap`](https://github.com/x-mesh/homebrew-tap)의 Formula를 자동 갱신한다. `x-mesh/gk`와 동일한 GoReleaser 패턴.

## TL;DR

```sh
# 1. CHANGELOG의 [Unreleased] → [X.Y.Z] 로 정리
# 2. Cargo.toml 버전 bump (aic-common/aic-server/aic-client) + Cargo.lock 반영
# 3. main push (tag 없이 먼저) → CI 발화
git commit -am "chore(release): vX.Y.Z"
git push origin main
# 4. CI green 확인 — 실패하면 여기서 멈춘다(tag 만들지 않음)
gh run watch "$(gh run list --workflow=ci.yml --branch main -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
# 5. green 이면 tag push → release.yml(GoReleaser + brew) 발화
git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
```

> **중요 — tag 는 CI green 확인 뒤에 push 한다.** main 에 branch protection 이 없어 직접 push 의 CI 는
> *post-merge* 로 돈다. main 과 tag 를 같이 올리면 CI 가 실패해도 릴리스(GitHub Release + brew)가 그대로
> 나간다. tag 를 분리해 CI green 을 게이트로 쓰면 깨진 릴리스를 막는다(PR/rate-limit 무관).

이 한 번이 다음을 자동으로 트리거한다:
- `.github/workflows/release.yml`이 발화 (Rust toolchain + zig + cargo-zigbuild 설치)
- GoReleaser가 4개 target triple로 binary 빌드:
  - `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
  - `x86_64-apple-darwin`, `aarch64-apple-darwin`
- 각 (os, arch)별로 `aic_<version>_<os>_<arch>.tar.gz`에 `aic` + `aic-session` + `aicd` 세 binary 묶음
- `checksums.txt` SHA256 자동 생성
- GitHub Release 게시 (git log 기반 changelog)
- `x-mesh/homebrew-tap/Formula/aic.rb` 자동 갱신 (4개 OS/arch url + sha256 + bin.install 3개)

## 사전 준비 (1회)

### `HOMEBREW_TAP_GITHUB_TOKEN` secret

`x-mesh` org에 이미 `gk` release용 동일 이름 secret이 등록되어 있다면 **추가 작업 불필요** — org-level secret은 모든 repo에서 접근 가능. 그렇지 않다면:

1. GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens
2. **Resource owner**: `x-mesh`
3. **Repository access**: only `x-mesh/homebrew-tap`
4. **Permissions**: Contents (write), Pull requests (write), Metadata (read, 자동)
5. 등록 위치 (둘 중 하나):
   - **Org level (권장)**: `x-mesh` org Settings → Secrets and variables → Actions → New organization secret. Repository access는 "Selected repositories"로 `x-mesh/aic` (그리고 `x-mesh/gk`)만.
   - **Repo level**: `x-mesh/aic` Settings → Secrets and variables → Actions → New repository secret.
6. **Name**: `HOMEBREW_TAP_GITHUB_TOKEN`

### `x-mesh/homebrew-tap`은 seed 불필요

GoReleaser의 `brews:` block이 첫 release에서 `Formula/aic.rb`를 직접 만든다. tap에 미리 placeholder Formula를 둘 필요 없음 — `gk.rb` 옆에 `aic.rb`가 자동으로 생긴다.

## 정상 흐름

1. 작업 브랜치를 main에 머지.
2. CHANGELOG 정리 — `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD`. (release notes는 GoReleaser git log 기반이라 별개지만, 사람이 읽을 changelog로 유지.)
3. Cargo.toml 버전 bump (`aic-common`/`aic-server`/`aic-client` 동일 버전) + `cargo update -p aic-client -p aic-common -p aic-server --precise X.Y.Z`로 Cargo.lock 반영.
4. **(권장) 로컬 사전 검증** — CI는 phase × OS × central_store 매트릭스를 돌므로 `--lib`만으로는 놓치는 조합이 있다(예: `central_store=1`에서만 깨지는 env-의존 테스트). 최소 CI와 동일한 형태로 한 조합은 돌린다:

   ```sh
   cargo clippy --all-targets -- -D warnings
   cargo test --workspace --no-default-features --features phase-3_5
   AIC_CENTRAL_STORE=1 cargo test --workspace --no-default-features --features phase-3_3
   ```

5. `git commit -am "chore(release): vX.Y.Z" && git push origin main` — **tag 없이 main 먼저.**
6. **CI green 확인** — `gh run watch "$(gh run list --workflow=ci.yml --branch main -L1 --json databaseId --jq '.[0].databaseId')" --exit-status`. 빨강이면 고치고 **5번부터 다시**. tag는 만들지 않는다.
7. green이면 `git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z` — release.yml(GoReleaser + brew) 발화.
8. Actions 탭에서 release workflow가 그린이면 끝. `brew update && brew info x-mesh/tap/aic`로 새 버전 노출 확인.

> tag(7)와 main(5)을 **분리**하는 이유는 TL;DR의 경고와 같다 — CI(6)를 릴리스 게이트로 쓰기 위함. 한 줄로 `git push origin main vX.Y.Z`를 하면 이 게이트가 사라진다.

## 수동 dry-run

태그 없이 발화하려면 Actions → release → "Run workflow"에서 그냥 실행. 이때 GoReleaser는 `--snapshot` 모드가 아니므로 실제 release 시도 — tag가 없으면 실패한다. 진정한 dry-run이 필요하면 `args: release --snapshot --skip=publish --clean`으로 임시 변경 후 실행.

`.goreleaser.yaml` 자체 syntax 검증만 빠르게 하려면 로컬에서:

```sh
brew install goreleaser/tap/goreleaser
goreleaser check
```

## 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `HOMEBREW_TAP_GITHUB_TOKEN: required` | org/repo secret 미등록. 위 사전 준비 섹션 확인. |
| zigbuild 빌드 실패 (`linker not found` 등) | zig 버전 불일치. 워크플로우의 `mlugg/setup-zig` 버전과 `cargo-zigbuild` 버전을 함께 bump. |
| `aarch64-apple-darwin` 빌드만 실패 | macOS SDK 이슈. zigbuild는 SDK 없이 동작하지만 일부 crate(`portable-pty`/`libc` 등)가 native 헤더를 요구할 수 있음. 그 경우 macos-latest runner 별도 matrix로 split. |
| Formula PR이 안 열림 | secret 권한 부족(`Resource not accessible`). PAT scope를 `Contents + Pull requests write`로 다시 발급. |
| Release notes가 휑함 | git log 필터(`docs:`/`test:`/`chore:`/Merge PR)가 너무 광범위. `.goreleaser.yaml`의 `changelog.filters.exclude` 조정. |

## 왜 source-build Formula(cargo install)를 안 쓰는가

이전 commit에서 `packaging/homebrew/aic.rb` (source-build) 초안을 두었다가 GoReleaser 도입과 함께 제거했다. 이유:

- gk와 같은 패턴으로 통일 (팀 한 토큰, 한 워크플로우 마인드).
- `brew install` 시 Rust toolchain 불필요 (binary 다운로드).
- `brew install` 속도가 압도적으로 빠름 (cargo build 30초+ → tar.gz 다운로드 1초).
- multi-arch가 자동 — `Hardware::CPU.intel?` / `Hardware::CPU.arm?` 분기를 GoReleaser가 알아서 만든다.

toolchain만 있는 환경(예: Docker 빌드)에서 binary 없이 빌드하려면 `cargo install --git https://github.com/x-mesh/aic`로 우회.
