# Releasing aic

> 새 버전을 GitHub Release로 게시하고 [`x-mesh/homebrew-tap`](https://github.com/x-mesh/homebrew-tap)의 Formula를 자동 갱신한다. **GoReleaser가 아니라 `.github/workflows/release.yml`의 커스텀 빌드/릴리스 스크립트**를 쓴다(이유는 맨 아래 "왜 GoReleaser가 아닌가" 참고).

## TL;DR

```sh
# 1. CHANGELOG의 [Unreleased] → [X.Y.Z] 로 정리
# 2. Cargo.toml 버전 bump (aic-common/aic-server/aic-client) + Cargo.lock 반영
# 3. 로컬 검증 (아래 "정상 흐름" 4번) — release.yml이 릴리스 게이트다
# 4. bump 커밋에 [skip ci]를 넣지 말 것 — tag가 이 커밋을 가리키는데, [skip ci]는
#    tag push로 트리거될 release.yml까지 스킵한다(v0.29.0에서 release가 안 떴다 → 아래 트러블슈팅).
git commit -am "chore(release): vX.Y.Z"
git push origin develop && git push origin develop:main   # main은 tag가 가리킬 커밋(FF)
# 5. tag push → release.yml(커스텀 빌드 + GitHub Release + brew) 발화
git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
# 6. release run 확인
gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

> **왜 main CI 게이트가 없는가**: release.yml **자체가 4 target을 릴리스 프로파일(phase-3_4)로 빌드**하므로,
> 빌드가 깨지면 release가 실패하고 에셋이 안 나간다(`mode: replace` 멱등이라 재실행도 안전). 즉 release
> run이 곧 게이트다. 코드 회귀 방지는 **로컬 사전 검증(4번)**과 개발 중 PR CI로 잡는다. main FF push로
> ci.yml이 한 번 도는 건 무해하니 그대로 둔다 — **bump 커밋에 `[skip ci]`를 넣지 말 것.** 그 커밋이 곧
> tag 대상이라, `[skip ci]`가 있으면 main CI뿐 아니라 **tag push로 떠야 할 release.yml까지 스킵된다**
> (`[skip ci]`는 이벤트 종류를 안 가리고 그 커밋을 참조하는 모든 push 워크플로를 끈다).

이 tag push가 다음을 자동으로 한다 (`.github/workflows/release.yml`, `macos-latest` runner 단일 job):
- Rust toolchain(4 triple) + zig + cargo-zigbuild 설치
- 4 target triple로 binary 빌드:
  - **linux** `x86_64/aarch64-unknown-linux-gnu` → `cargo zigbuild` (zig cross-compile)
  - **darwin** `x86_64/aarch64-apple-darwin` → `cargo build` (**native, Apple ld** — 프레임워크 링크)
- 각 (os, arch)별 `aic_<version>_<os>_<arch>.tar.gz`에 `aic`·`aic-session`·`aicd` + LICENSE/README/CHANGELOG 묶음
- `checksums.txt` SHA256 생성
- GitHub Release 게시 (`gh release create`; 있으면 `gh release upload --clobber`)
- `x-mesh/homebrew-tap/Formula/aic.rb` 재생성·push (4 OS/arch url + sha256 + bin.install 3개)

## 사전 준비 (1회)

### `HOMEBREW_TAP_GITHUB_TOKEN` secret

`x-mesh` org에 `gk` release용 동일 이름 secret이 있으면 **추가 작업 불필요**(org-level은 모든 repo 접근). 없으면:

1. GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens
2. **Resource owner**: `x-mesh` / **Repository access**: only `x-mesh/homebrew-tap`
3. **Permissions**: Contents (write), Metadata (read, 자동)
4. 등록: org level(권장, `x-mesh` org Secrets → Actions) 또는 repo level(`x-mesh/aic` Secrets → Actions)
5. **Name**: `HOMEBREW_TAP_GITHUB_TOKEN`

> 커스텀 스크립트는 tap을 clone → `Formula/aic.rb` 덮어쓰기 → commit(author `aic-bot <bot@x-mesh.dev>`) → push한다. Contents write면 충분(PR을 열지 않고 main에 직접 push).

### `x-mesh/homebrew-tap`은 seed 불필요

release.yml이 첫 release에서 `Formula/aic.rb`를 통째로 생성한다. placeholder 불필요.

## 정상 흐름

1. 작업(develop)을 릴리스 가능한 상태로.
2. CHANGELOG 정리 — `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` (위에 빈 `## [Unreleased]` 유지).
3. Cargo.toml 버전 bump (`aic-common`/`aic-server`/`aic-client` 동일) + `cargo update -p aic-client -p aic-common -p aic-server --precise X.Y.Z`로 Cargo.lock 반영.
4. **로컬 사전 검증** (release.yml이 게이트라 main CI 대신 여기서 잡는다). CI(`ci.yml`)와 동일 형태로:

   ```sh
   cargo clippy --workspace -- -D warnings   # ci.yml과 동일 (--all-targets 붙이지 말 것 — CI보다 엄격해짐)
   cargo test --workspace --no-default-features --features phase-3_5
   AIC_CENTRAL_STORE=1 cargo test --workspace --no-default-features --features phase-3_3
   ```

5. `git commit -am "chore(release): vX.Y.Z"` — **`[skip ci]`를 넣지 말 것.** 이 커밋이 곧 tag 대상이라, `[skip ci]`가 있으면 tag push로 떠야 할 release.yml까지 스킵된다(v0.29.0 실측).
6. `git push origin develop` 후 `git push origin develop:main` — main은 tag가 가리킬 커밋(FF). main push로 ci.yml이 한 번 도는 건 무해하니 그대로 둔다.
7. `git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z` — release.yml 발화.
8. `gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId --jq '.[0].databaseId')" --exit-status` — 그린이면 끝. `brew update && brew info x-mesh/tap/aic`로 새 버전 노출 확인.

> **재릴리스(같은 버전)**: bump/CHANGELOG는 그대로 두고, 워크플로/빌드 수정만 커밋한 뒤 tag를 그 커밋으로 옮긴다 — `git tag -d vX.Y.Z; git push origin :refs/tags/vX.Y.Z; git tag vX.Y.Z <commit>; git push origin vX.Y.Z`. release.yml의 `mode: replace`(있으면 upload --clobber)라 에셋이 멱등하게 덮어써진다.

## 수동 dry-run

Actions → release → "Run workflow"(`workflow_dispatch`)로 발화 가능. 단 tag 없이 돌면 `GITHUB_REF_NAME`이 브랜치명이라 GitHub Release/tag가 어긋난다 — 실제 dry-run은 로컬에서 빌드 스텝만 재현하는 게 낫다:

```sh
# linux(zig) / darwin(native) 한 target씩 빌드가 통과하는지
cargo build --release --target aarch64-apple-darwin --no-default-features --features phase-3_4 \
  -p aic-client --bin aic -p aic-server --bin aic-session --bin aicd
```

## 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `HOMEBREW_TAP_GITHUB_TOKEN: required` | org/repo secret 미등록. 위 사전 준비 확인. |
| **darwin 빌드 `undefined symbol: _SecKeychain*`/`_IOBSDNameMatching`** | zig 링커가 macOS 프레임워크(Security/CoreFoundation/IOKit)를 못 링크. **darwin은 반드시 native `cargo build`**(release.yml이 이미 그렇게 함). zigbuild로 darwin을 빌드하면 재발한다 — v0.27.0~v0.28.0에서 이걸로 5번 실패했다. |
| linux zigbuild 빌드 실패 (`linker not found` 등) | zig 버전 불일치. `mlugg/setup-zig` 버전과 `cargo-zigbuild --version`을 함께 bump. |
| Formula가 안 갱신됨 | secret 권한 부족(Contents write). tap push 로그 확인. |
| **tag를 push했는데 release.yml이 안 뜬다** | tag가 가리키는 커밋 메시지에 `[skip ci]`가 있다. `[skip ci]`는 branch push뿐 아니라 **그 커밋을 참조하는 tag push 워크플로까지** 스킵한다(v0.29.0 실측). 복구: 히스토리 재작성 없이 tag ref로 수동 dispatch — `gh workflow run release.yml --ref vX.Y.Z`. workflow_dispatch를 **tag ref**로 걸면 `GITHUB_REF_NAME=vX.Y.Z`라 VERSION/Release/brew가 모두 정상 산출된다(브랜치 ref로 걸면 ref_name이 브랜치라 어긋난다). 근본 예방: bump 커밋에 `[skip ci]`를 넣지 않는다(위 "정상 흐름" 5번). |
| Release notes가 휑함 | `--notes-from-tag`가 tag 메시지를 쓴다. 필요하면 release.yml의 notes 소스를 CHANGELOG 섹션 추출로 바꾼다. |

## 왜 GoReleaser가 아닌가

이전엔 `x-mesh/gk`와 같은 GoReleaser 파이프라인(`.goreleaser.yaml`)을 썼으나, **v0.27.0에서 `aic-server`가 `sysinfo`(IOKit/CoreFoundation)·`keyring`(Security)을 쓰기 시작하면서 darwin 빌드가 macOS 프레임워크를 링크해야** 했고, GoReleaser rust builder는 tool과 무관하게 항상 `cargo-zigbuild`(zig 링커)를 쓰는데 zig는 SDKROOT·`-L framework=`를 줘도 프레임워크를 못 링크해 **5번 연속 실패**했다(prebuilt builder는 GoReleaser Pro 전용이라 OSS로 우회 불가). gk가 문제없던 건 **Go(`CGO_ENABLED=0`) 순수 크로스컴파일**이라 프레임워크 링크가 없어서다 — Rust인 aic엔 그 방식을 못 쓴다.

그래서 GoReleaser를 걷어내고(`.goreleaser.yaml` 삭제), `macos-latest` runner에서 **darwin은 native cargo(Apple ld=프레임워크 링크), linux는 cargo-zigbuild**로 직접 빌드·아카이브·릴리스·Formula 갱신을 한다. binary 다운로드 방식(brew에 Rust toolchain 불필요, 빠른 설치)과 multi-arch 분기는 그대로 유지된다.

toolchain만 있는 환경에서 binary 없이 빌드하려면 `cargo install --git https://github.com/x-mesh/aic`로 우회.
