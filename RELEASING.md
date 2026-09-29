# Releasing aic

> 새 버전을 이 repo의 GitHub Release로 게시하고 [`x-mesh/homebrew-tap`](https://github.com/x-mesh/homebrew-tap)의 Formula를 자동 갱신한다. **GoReleaser가 아니라 `.github/workflows/release.yml`의 커스텀 빌드/릴리스 스크립트**를 쓴다(이유는 맨 아래 "왜 GoReleaser가 아닌가" 참고).

## TL;DR

```sh
# 0. 사전 조건: 지금 develop HEAD의 develop CI가 green인지(아래 "정상 흐름" 1번)
# 1. CHANGELOG의 [Unreleased] → [X.Y.Z] 로 정리
# 2. Cargo.toml 버전 bump (aic-common/aic-server/aic-client) + Cargo.lock 반영
# 3. lockfile 확인 — cargo metadata --locked (워크스페이스 + fuzz, "정상 흐름" 4번)
# 4. bump 커밋에 [skip ci]를 넣지 말 것 — tag가 이 커밋을 가리키는데, [skip ci]는
#    tag push로 트리거될 release.yml까지 스킵한다(v0.29.0에서 release가 안 떴다 → 아래 트러블슈팅).
git commit -am "chore(release): vX.Y.Z"
git push origin develop
# 5. 같은 SHA의 develop CI가 green인지 확인한 뒤에만 main FF + tag (ci.yml은 main에서 돌지 않는다)
SHA=$(git rev-parse HEAD); RID=""
for _ in $(seq 60); do   # 최대 5분 — [skip ci]·워크플로 비활성이면 실행이 영영 안 생긴다
  RID=$(gh run list --workflow=ci.yml --branch develop -L10 --json databaseId,headSha \
        --jq ".[] | select(.headSha==\"$SHA\") | .databaseId" | head -1)
  [ -n "$RID" ] && break; sleep 5
done
[ -n "$RID" ] || { echo "develop CI 실행을 찾지 못함: $SHA" >&2; exit 1; }
gh run watch "$RID" --exit-status
git push origin develop:main   # main은 tag가 가리킬 커밋(FF)
# 6. tag push → release.yml(커스텀 빌드 + GitHub Release + brew) 발화
git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
# 7. release run 확인
gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

> **왜 main CI 게이트가 없는가**: release.yml **자체가 4 target을 릴리스 프로파일(phase-3_4)로 빌드**하므로,
> 빌드가 깨지면 release가 실패하고 에셋이 안 나간다(`mode: replace` 멱등이라 재실행도 안전). 코드 회귀
> 방지는 **릴리스할 코드가 이미 통과한 develop CI(1번)**와, tag 대상과 **같은 SHA의 develop push CI**로 잡는다. `ci.yml`은 main에서
> 돌지 않는다 — main은 그 CI를 통과한 develop 커밋의 FF로만 갱신하므로 같은 커밋을 두 번 검사할 이유가
> 없다(두 번 돌리면 macOS runner를 서로 기다려 태그 전 대기가 11~16분으로 늘었다). **main에 직접 커밋하지
> 않는다.** **bump 커밋에 `[skip ci]`를 넣지 말 것.** 그 커밋이 곧 tag 대상이라, `[skip ci]`가 있으면
> develop CI뿐 아니라 **tag push로 떠야 할 release.yml까지 스킵된다**(`[skip ci]`는 이벤트 종류를 안
> 가리고 그 커밋을 참조하는 모든 push 워크플로를 끈다).

이 tag push가 다음을 자동으로 한다 (`.github/workflows/release.yml`). `build` job이 target 4개를 `macos-latest` runner 4대에서 **동시에** 빌드하고, 넷 다 성공하면 `publish` job이 게시한다(하나라도 실패하면 게시하지 않는다). 순차 빌드일 때 33~62분이던 릴리스가 약 11분이다(v0.50.4 기준 dry-run 실측):
- target마다 Rust toolchain 설치, linux target은 zig + cargo-zigbuild도 설치
- 4 target triple로 binary 빌드:
  - **linux** `x86_64/aarch64-unknown-linux-gnu` → `cargo zigbuild` (zig cross-compile)
  - **darwin** `x86_64/aarch64-apple-darwin` → `cargo build` (**native, Apple ld** — 프레임워크 링크)
- 각 (os, arch)별 `aic_<version>_<os>_<arch>.tar.gz`에 `aic`·`aic-session`·`aicd` + LICENSE/README/CHANGELOG 묶음
- (`publish`) 네 tar.gz를 모아 `checksums.txt` SHA256 생성
- GitHub Release 게시 (`gh release create`; 있으면 `upload --clobber`) — 노트는 CHANGELOG의 해당 버전 섹션에서 추출
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

1. 작업(develop)을 릴리스 가능한 상태로. **사전 조건**: 지금 develop HEAD의 develop CI가 `completed/success`여야 한다. 릴리스 커밋은 버전·lockfile·CHANGELOG만 바꾸므로, 그 아래 코드가 전 matrix를 이미 통과했는지를 확인하는 것으로 로컬 재검사를 대신한다(로컬 재검사는 CI의 부분집합이라 새 결함을 거의 잡지 못했고 약 6분이 들었다). 실패했거나 실행이 없으면 멈추고 원인을 확인한다.

   ```sh
   git fetch origin
   [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/develop)" ] || { echo "로컬 develop이 origin/develop과 다름" >&2; exit 1; }
   BASE=$(git rev-parse HEAD)
   STATE=$(gh run list --workflow=ci.yml --branch develop -L20 --json headSha,status,conclusion \
           --jq ".[] | select(.headSha==\"$BASE\") | \"\(.status)/\(.conclusion)\"" | head -1)
   echo "base ${BASE:0:7}: ${STATE:-CI 실행 없음}"   # completed/success 여야 진행
   ```

2. CHANGELOG 정리 — `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` (위에 빈 `## [Unreleased]` 유지).
3. Cargo.toml 버전 bump (`aic-common`/`aic-server`/`aic-client` 동일) + `cargo update -p aic-client -p aic-common -p aic-server --precise X.Y.Z`로 Cargo.lock 반영.
4. **lockfile 확인**. `make bump-version`은 동기화에 실패해도 경고만 내므로, CI(fuzz job은 `--locked`)에서 늦게 깨지기 전에 확인한다:

   ```sh
   cargo metadata --locked --format-version 1 >/dev/null
   cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >/dev/null   # ci.yml fuzz job과 동일
   ```

   1번 사전 조건을 충족할 수 없어 CI 결과 없이 진행해야 한다면, 대신 로컬에서 CI 일부를 돌린다:

   ```sh
   cargo clippy --workspace -- -D warnings
   cargo test --workspace --no-default-features --features phase-3_5
   AIC_CENTRAL_STORE=1 cargo test --workspace --no-default-features --features phase-3_3
   ```

5. `git commit -am "chore(release): vX.Y.Z"` — **`[skip ci]`를 넣지 말 것.** 이 커밋이 곧 tag 대상이라, `[skip ci]`가 있으면 tag push로 떠야 할 release.yml까지 스킵된다(v0.29.0 실측).
6. `git push origin develop` → 같은 SHA의 develop CI가 green인지 확인(위 TL;DR의 `gh run watch`) → `git push origin develop:main`. main은 tag가 가리킬 커밋(FF)이고, `ci.yml`은 main에서 돌지 않는다. CI가 green이 아니면 main FF와 tag를 하지 않는다.
7. `git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z` — release.yml 발화.
8. `gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId --jq '.[0].databaseId')" --exit-status` — 그린이면 끝. `gh release view vX.Y.Z`로 에셋 5개, `brew update && brew info x-mesh/tap/aic`로 새 버전 노출 확인.

> **재릴리스(같은 버전)**: bump/CHANGELOG는 그대로 두고, 워크플로/빌드 수정만 커밋한 뒤 tag를 그 커밋으로 옮긴다 — `git tag -d vX.Y.Z; git push origin :refs/tags/vX.Y.Z; git tag vX.Y.Z <commit>; git push origin vX.Y.Z`. release.yml의 `mode: replace`(있으면 upload --clobber)라 에셋이 멱등하게 덮어써진다.

## 수동 dry-run

브랜치에서 `workflow_dispatch`하면 `build`만 도는 dry-run이다. `publish`는 `v*` 태그 ref에서만 돌므로 GitHub Release와 brew Formula는 건드리지 않는다. 산출물 이름의 버전에는 `-dryrun`이 붙는다(`aic_<Cargo.toml 버전>-dryrun_<os>_<arch>.tar.gz`). release.yml을 바꿨다면 태그 전에 이걸로 확인한다:

```sh
gh workflow run release.yml --ref <branch>
gh run download <run-id> -D /tmp/aic-dryrun   # target별 tar.gz 확인
```

## 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `HOMEBREW_TAP_GITHUB_TOKEN: required` | org/repo secret 미등록. 위 사전 준비 확인. |
| Formula가 안 갱신됨 | secret 권한 부족(Contents write). tap push 로그 확인. |
| **darwin 빌드 `undefined symbol: _SecKeychain*`/`_IOBSDNameMatching`** | zig 링커가 macOS 프레임워크(Security/CoreFoundation/IOKit)를 못 링크. **darwin은 반드시 native `cargo build`**(release.yml이 이미 그렇게 함). zigbuild로 darwin을 빌드하면 재발한다 — v0.27.0~v0.28.0에서 이걸로 5번 실패했다. |
| **linux zigbuild `unsupported linker arg: --fix-cortex-a53-843419`** | rustc가 새 링커 인자를 넘기는데 pin된 zig가 그걸 모른다. release.yml은 `dtolnay/rust-toolchain@stable`(자동 최신)을 쓰면서 zig/cargo-zigbuild만 고정하므로, stable이 올라가면 이 짝이 어긋난다 — rustc 1.98 + zig 0.13.0/cargo-zigbuild 0.20.1에서 실측(v0.36.0). 해결: 두 pin을 함께 올린다(현재 zig 0.16.0 + cargo-zigbuild 0.23.0). 검증은 CI 왕복 대신 로컬에서 `cargo zigbuild --release --target aarch64-unknown-linux-gnu …`로 재현하는 게 빠르다. |
| linux zigbuild 빌드 실패 (`linker not found` 등) | zig 버전 불일치. `mlugg/setup-zig` 버전과 `cargo-zigbuild --version`을 함께 bump. |
| **tag를 push했는데 release.yml이 안 뜬다** | tag가 가리키는 커밋 메시지에 `[skip ci]`가 있다. `[skip ci]`는 branch push뿐 아니라 **그 커밋을 참조하는 tag push 워크플로까지** 스킵한다(v0.29.0 실측). 복구: 히스토리 재작성 없이 tag ref로 수동 dispatch — `gh workflow run release.yml --ref vX.Y.Z`. workflow_dispatch를 **tag ref**로 걸면 `GITHUB_REF_NAME=vX.Y.Z`라 VERSION/Release/brew가 모두 정상 산출된다(브랜치 ref로 걸면 `publish`가 돌지 않는 dry-run이 된다). 근본 예방: bump 커밋에 `[skip ci]`를 넣지 않는다(위 "정상 흐름" 5번). |
| Release notes가 휑함 | notes는 CHANGELOG의 `## [X.Y.Z]` 섹션에서 추출된다. CHANGELOG에 해당 버전 섹션이 있는지 확인. |

## 왜 GoReleaser가 아닌가

이전엔 `x-mesh/gk`와 같은 GoReleaser 파이프라인(`.goreleaser.yaml`)을 썼으나, **v0.27.0에서 `aic-server`가 `sysinfo`(IOKit/CoreFoundation)·`keyring`(Security)을 쓰기 시작하면서 darwin 빌드가 macOS 프레임워크를 링크해야** 했고, GoReleaser rust builder는 tool과 무관하게 항상 `cargo-zigbuild`(zig 링커)를 쓰는데 zig는 SDKROOT·`-L framework=`를 줘도 프레임워크를 못 링크해 **5번 연속 실패**했다(prebuilt builder는 GoReleaser Pro 전용이라 OSS로 우회 불가). gk가 문제없던 건 **Go(`CGO_ENABLED=0`) 순수 크로스컴파일**이라 프레임워크 링크가 없어서다 — Rust인 aic엔 그 방식을 못 쓴다.

그래서 GoReleaser를 걷어내고(`.goreleaser.yaml` 삭제), `macos-latest` runner에서 **darwin은 native cargo(Apple ld=프레임워크 링크), linux는 cargo-zigbuild**로 직접 빌드·아카이브·릴리스·Formula 갱신을 한다. binary 다운로드 방식(brew에 Rust toolchain 불필요, 빠른 설치)과 multi-arch 분기는 그대로 유지된다.

toolchain만 있는 환경에서 binary 없이 빌드하려면 `cargo install --git https://github.com/x-mesh/aic`로 우회(public repo라 별도 권한 불필요).
