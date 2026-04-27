# Releasing aic

> 새 버전을 GitHub Release로 게시하고 [`x-mesh/homebrew-tap`](https://github.com/x-mesh/homebrew-tap)의 Formula를 자동 갱신한다.

## TL;DR

```sh
# 1. CHANGELOG의 [Unreleased]를 [vX.Y.Z] 헤더로 닫기 (선택 — 비워둬도 됨)
# 2. Cargo.toml 버전 bump (workspace 멤버 모두) — 스크립트 없으면 수동
# 3. tag + push
git tag v0.3.0 -m "v0.3.0"
git push origin v0.3.0
```

이 한 번이 다음을 자동으로 트리거한다:
- `.github/workflows/release.yml`이 발화
- 소스 tarball SHA256 계산
- CHANGELOG의 `[Unreleased]` 또는 `[v0.3.0]` 섹션을 release notes로 추출 + Homebrew 안내 footer 추가
- `gh release create v0.3.0` (이미 있으면 update)
- `x-mesh/homebrew-tap`에 Formula bump PR 자동 생성

## 사전 준비 (1회)

### `HOMEBREW_TAP_TOKEN` secret 등록

`mislav/bump-homebrew-formula-action`이 다른 repo (`x-mesh/homebrew-tap`)에 PR을 만들려면 별도 PAT이 필요하다. 기본 `GITHUB_TOKEN`은 동일 repo만 접근 가능.

1. GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens
2. **Resource owner**: `x-mesh`
3. **Repository access**: only `x-mesh/homebrew-tap`
4. **Permissions**:
   - Contents: Read and write
   - Pull requests: Read and write
   - Metadata: Read (자동)
5. 생성된 토큰을 `x-mesh/aic` repo의 Settings → Secrets and variables → Actions →
   New repository secret으로 등록:
   - **Name**: `HOMEBREW_TAP_TOKEN`
   - **Value**: `<생성된 토큰>`

### `x-mesh/homebrew-tap`의 초기 Formula

`packaging/homebrew/aic.rb`를 그대로 복사해 `x-mesh/homebrew-tap/Formula/aic.rb`에 둔다. 이후엔 release 워크플로우가 `url` + `sha256`만 자동 bump한다 (`bump-homebrew-formula-action`이 정규식으로 두 줄을 교체).

## 정상 흐름

1. 작업 브랜치를 main에 머지.
2. CHANGELOG 정리 — `## [Unreleased]` 아래 항목들을 점검하고, 필요하면 `## [v0.3.0]` 헤더로 한 번 더 감싼다 (워크플로우는 둘 중 하나를 매칭).
3. workspace Cargo.toml 버전 bump — `aic-common`/`aic-server`/`aic-client` 모두 동일 버전.
4. `git commit -am "release: v0.3.0"`.
5. `git tag v0.3.0 -m "v0.3.0" && git push origin main v0.3.0`.
6. Actions 탭에서 Release workflow가 그린이면 끝.

## 수동 dry-run

태그 없이 발화하려면 Actions → Release → "Run workflow"에서 `tag: v0.3.0-rc1` 같이 넣는다. 같은 tag로 재실행 시 release는 update, Formula PR은 idempotent하게 갱신된다.

## 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `Resource not accessible by integration` (bump-formula step) | `HOMEBREW_TAP_TOKEN` 미등록 또는 권한 부족. 위 사전 준비 확인. |
| Formula PR이 안 열림 | bump-homebrew-formula-action이 url/sha256 정규식 매칭에 실패. `Formula/aic.rb`의 `url "..."` / `sha256 "..."` 줄이 한 줄에 있는지 확인. |
| Release notes가 비어 있음 | CHANGELOG에 `## [Unreleased]` 섹션 자체가 없음. 워크플로우가 `Release <tag>` 한 줄로 fallback. |
| SHA256이 사용자 환경과 다름 | GitHub source tarball은 deterministic하지만 timezone/내용이 바뀌면 달라짐. Formula bump는 워크플로우가 계산한 값을 사용하므로 신경쓰지 않아도 됨. |

## 왜 binary artifact를 빌드하지 않나

Homebrew는 source build (Formula의 `system "cargo", "install", ...`)로도 충분하고, 그 편이 platform별 binary 배포보다 단순하다. Linux/macOS, x86_64/aarch64 모두 자동 처리된다. binary release가 필요해지면 (예: Rust toolchain 없는 환경) `release.yml`에 별도 matrix job을 추가한다.
