---
description: aic 전체 릴리스 — bump+commit+push(main) → CI green 게이트 → tag push → GitHub Release + brew 배포 검증
argument-hint: [patch|minor|major]
---

aic를 릴리스한다. `$ARGUMENTS` = bump 종류(`patch`|`minor`|`major`). 생략하면 변경 내용으로 판단한다.

이 커맨드는 `/xm:ship`의 핵심(squash·bump·commit·push)에 **CI green 게이트 → tag → 배포 검증**을 묶은
aic 전용 릴리스 파이프라인이다. **철칙: tag는 반드시 CI green 확인(5단계) 뒤에 push한다.** main에
branch protection이 없어 직접 push의 CI는 post-merge로 돌기 때문에, tag를 먼저/같이 올리면 CI가 실패해도
릴리스(GitHub Release + brew)가 그대로 나간다. 각 단계가 실패하면 즉시 중단하고 사용자에게 보고한다.

근거·배경: `RELEASING.md`, memory `project-aic-release-workflow`.

## 1. 사전 점검
- `git status --short`로 변경을 확인하고, 미커밋 변경이 이번 릴리스 대상인지 사용자에게 한 줄로 확인.
- 현재 버전: `grep -m1 '^version' aic-client/Cargo.toml`.
- bump 종류 결정: `$ARGUMENTS`가 있으면 그것. 없으면 변경으로 판단(새 기능=minor, 버그/내부=patch,
  호환 깨짐=major). 애매하면 사용자에게 묻는다.
- 현재 브랜치가 `main`이 아니면 사용자에게 어떻게 올릴지 확인.

## 2. 로컬 검증 (CI 매트릭스 누락 방지)
`--lib`만으로는 CI의 phase × central_store 조합을 놓친다(과거 `central_store=1`에서만 깨진 env-race
사례 있음). 최소 아래를 돌리고, 실패하면 **중단**한다.
```sh
cargo clippy --workspace -- -D warnings   # CI(ci.yml)와 동일 명령 — 게이트는 CI와 일치시킨다
cargo test --workspace --no-default-features --features phase-3_5
AIC_CENTRAL_STORE=1 cargo test --workspace --no-default-features --features phase-3_3
```
> clippy는 CI(`ci.yml`)와 **똑같은** `--workspace -- -D warnings`를 쓴다. `--all-targets`를 붙이면 CI가
> 검사하지 않는 test 타겟 경고까지 잡아, "CI는 통과할 릴리스"를 로컬에서 잘못 막는다(게이트가 CI보다
> 엄격하면 안 된다). test 타겟 lint는 별도 백로그로 다룬다.

## 3. bump + CHANGELOG
- `aic-common`/`aic-server`/`aic-client`의 `Cargo.toml` `version`을 동일하게 bump.
- `cargo update -p aic-client -p aic-common -p aic-server --precise X.Y.Z`로 `Cargo.lock` 반영.
- `CHANGELOG.md`의 `## [Unreleased]` → `## [X.Y.Z] - <오늘 날짜>` (그 위에 빈 `## [Unreleased]` 유지).

## 4. commit + push main (tag 없이)
- 기존 repo 패턴을 따른다: 기능/문서는 `feat(...)`/`docs(...)`, 버전 bump는 `chore(release): vX.Y.Z`
  커밋으로 분리. scope 밖 파일은 별도 커밋하거나 사용자에게 확인.
- `git push origin main` — **tag는 아직 만들지 않는다.**

## 5. CI green 게이트 (필수)
방금 push한 main 커밋의 CI를 끝까지 확인한다.
```sh
gh run watch "$(gh run list --workflow=ci.yml --branch main -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```
- **green이 아니면 여기서 중단.** 실패 job의 로그(`gh run view --log-failed --job=<id>`)로 원인을 보고하고,
  고친 뒤 4단계부터 다시. **절대 tag를 만들지 않는다.**

## 6. tag push → 배포 트리거
```sh
VER=$(grep -m1 '^version' aic-client/Cargo.toml | cut -d'"' -f2)
git tag "v$VER" -m "v$VER" && git push origin "v$VER"
```
이 tag push가 `release.yml`(GoReleaser)을 발화 → 4 OS/arch 빌드 + GitHub Release + `x-mesh/homebrew-tap`
Formula 자동 갱신(brew는 여기서 자동, 수동 작업 없음).

## 7. 배포 검증
- release 워크플로우 완료 대기:
  `gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId --jq '.[0].databaseId')" --exit-status`
- GitHub Release 에셋 확인: `gh release view "v$VER" --json assets --jq '.assets[].name'`
  (4개 tar.gz + checksums.txt 기대).
- brew 노출 확인: `brew update >/dev/null && brew info x-mesh/tap/aic | head -3` (새 버전이 stable로 보여야 함).
- 로컬에 brew로 설치돼 있고 사용자가 원하면 `brew upgrade aic`.

완료 후 버전 변화·커밋·tag·Release URL·brew 상태를 요약 보고한다.
