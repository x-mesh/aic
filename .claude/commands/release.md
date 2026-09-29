---
description: aic 전체 릴리스 — bump+commit+push(develop) → 같은 커밋의 develop CI green 게이트 → main FF → tag push → GitHub Release + brew 배포 검증
argument-hint: [patch|minor|major]
---

aic를 릴리스한다. `$ARGUMENTS` = bump 종류(`patch`|`minor`|`major`). 생략하면 변경 내용으로 판단한다.

이 커맨드는 `/xm:ship`의 핵심(squash·bump·commit·push)에 **CI green 게이트 → tag → 배포 검증**을 묶은
aic 전용 릴리스 파이프라인이다. **철칙: tag는 반드시 CI green 확인(5단계) 뒤에 push한다.** branch
protection이 없어 CI는 push 뒤에 돌기 때문에, tag를 먼저/같이 올리면 CI가 실패해도 릴리스(GitHub Release
+ brew)가 그대로 나간다. 각 단계가 실패하면 즉시 중단하고 사용자에게 보고한다.

**게이트는 tag 대상 커밋과 같은 SHA의 develop push CI다.** `ci.yml`은 main에서 돌지 않는다 — main은 CI를
통과한 develop 커밋의 fast-forward로만 갱신한다. main에 직접 커밋하지 않는다.

근거·배경: `RELEASING.md`, memory `project-aic-release-workflow`.

## 1. 사전 점검
- `git status --short`로 변경을 확인하고, 미커밋 변경이 이번 릴리스 대상인지 사용자에게 한 줄로 확인.
- 현재 버전: `grep -m1 '^version' aic-client/Cargo.toml`.
- bump 종류 결정: `$ARGUMENTS`가 있으면 그것. 없으면 변경으로 판단(새 기능=minor, 버그/내부=patch,
  호환 깨짐=major). 애매하면 사용자에게 묻는다.
- 릴리스는 `develop`에서 한다. 현재 브랜치가 `develop`이 아니면 사용자에게 어떻게 올릴지 확인.

## 2. 사전 조건: 릴리스할 코드가 이미 CI를 통과했는가
릴리스 커밋은 버전·lockfile·CHANGELOG만 바꾼다. 그 아래 코드는 develop에 머지될 때 이미 CI 전 matrix
(14 job)를 통과했으므로, 로컬에서 그 일부를 다시 돌리지 않고 **그 통과 사실**을 확인한다. 로컬 재검사는
CI의 부분집합이라 새 결함을 거의 잡지 못했고(과거 기록은 flaky·셸 차이 오판뿐) 릴리스마다 약 6분이 들었다.
bump 커밋 자체는 5단계 게이트가 다시 전부 검사한다.

bump 전에, 지금 develop HEAD의 develop CI가 green인지 본다.
```sh
git fetch origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/develop)" ] || { echo "로컬 develop이 origin/develop과 다름" >&2; exit 1; }
BASE=$(git rev-parse HEAD)
STATE=$(gh run list --workflow=ci.yml --branch develop -L20 --json headSha,status,conclusion \
        --jq ".[] | select(.headSha==\"$BASE\") | \"\(.status)/\(.conclusion)\"" | head -1)
echo "base ${BASE:0:7}: ${STATE:-CI 실행 없음}"   # completed/success 여야 진행
```
- `completed/success`면 진행. `in_progress`/`queued`면 `gh run watch`로 끝까지 보고 green이면 진행.
- 실패했거나 실행이 없으면(`[skip ci]`, 워크플로 비활성 등) **중단**하고 원인을 확인한다. 원인을 해결할 수 없어
  CI 결과 없이 진행해야 한다면 사용자에게 확인한 뒤 아래 로컬 검증을 돌린다(실패하면 중단).
```sh
cargo clippy --workspace -- -D warnings
cargo test --workspace --no-default-features --features phase-3_5
AIC_CENTRAL_STORE=1 cargo test --workspace --no-default-features --features phase-3_3
```

## 3. bump + CHANGELOG
- `aic-common`/`aic-server`/`aic-client`의 `Cargo.toml` `version`을 동일하게 bump.
- `cargo update -p aic-client -p aic-common -p aic-server --precise X.Y.Z`로 `Cargo.lock` 반영.
- `CHANGELOG.md`의 `## [Unreleased]` → `## [X.Y.Z] - <오늘 날짜>` (그 위에 빈 `## [Unreleased]` 유지).
- lockfile이 bump를 따라왔는지 확인한다. `make bump-version`은 동기화에 실패해도 경고만 내고 계속하므로,
  CI(fuzz job은 `--locked`)에서 늦게 깨지기 전에 여기서 막는다. 실패하면 **중단**.
```sh
cargo metadata --locked --format-version 1 >/dev/null
cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >/dev/null   # ci.yml fuzz job과 동일
```

## 4. commit + push develop (main·tag는 아직)
- 기존 repo 패턴을 따른다: 기능/문서는 `feat(...)`/`docs(...)`, 버전 bump는 `chore(release): vX.Y.Z`
  커밋으로 분리. scope 밖 파일은 별도 커밋하거나 사용자에게 확인. bump 커밋에 `[skip ci]`를 넣지 않는다.
- `git push origin develop` — **main FF와 tag는 아직 하지 않는다.**

## 5. CI green 게이트 (필수)
방금 push한 develop 커밋과 **같은 SHA**의 CI 실행을 찾아 끝까지 확인한다. `-L1`로 최신 실행을 집으면 다른
커밋의 실행을 볼 수 있고, push 직후에는 실행이 아직 등록되지 않았을 수 있으므로 SHA로 찾을 때까지 기다린다.
```sh
SHA=$(git rev-parse HEAD); RID=""
for _ in $(seq 60); do   # 최대 5분 — [skip ci]·워크플로 비활성이면 실행이 영영 안 생긴다
  RID=$(gh run list --workflow=ci.yml --branch develop -L10 --json databaseId,headSha \
        --jq ".[] | select(.headSha==\"$SHA\") | .databaseId" | head -1)
  [ -n "$RID" ] && break; sleep 5
done
[ -n "$RID" ] || { echo "develop CI 실행을 찾지 못함: $SHA" >&2; exit 1; }
gh run watch "$RID" --exit-status
```
- **green이 아니면 여기서 중단.** 실패 job의 로그(`gh run view --log-failed --job=<id>`)로 원인을 보고하고,
  고친 뒤 4단계부터 다시. **절대 main FF나 tag를 하지 않는다.**
- green이면 main을 같은 커밋으로 FF한다: `git push origin develop:main` (FF가 아니면 거부된다 — 강제하지 않는다).

## 6. tag push → 배포 트리거
```sh
VER=$(grep -m1 '^version' aic-client/Cargo.toml | cut -d'"' -f2)
git tag "v$VER" -m "v$VER" && git push origin "v$VER"
```
이 tag push가 `release.yml`을 발화 → 4 OS/arch 병렬 빌드 + GitHub Release + `x-mesh/homebrew-tap`
Formula 자동 갱신(brew는 여기서 자동, 수동 작업 없음).

## 7. 배포 검증
- release 워크플로우 완료 대기:
  `gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId --jq '.[0].databaseId')" --exit-status`
- GitHub Release 에셋 확인: `gh release view "v$VER" --json assets --jq '.assets[].name'`
  (4개 tar.gz + checksums.txt 기대).
- brew 노출 확인: `brew update >/dev/null && brew info x-mesh/tap/aic | head -3` (새 버전이 stable로 보여야 함).
- 로컬에 brew로 설치돼 있고 사용자가 원하면 `brew upgrade aic`.

완료 후 버전 변화·커밋·tag·Release URL·brew 상태를 요약 보고한다.
