# CLAUDE.md

> This file is read by Claude Code at the start of every session.
> Fill in each section — delete placeholder lines when done.
> Commit this file so the whole team benefits.

## Project

<!-- One-paragraph description of what this project does and why it exists. -->
TODO: describe the project

## Commands

<!-- The commands Claude should use to build, test, lint, and run this project. -->

```sh
# Build
TODO: e.g.  go build ./...  |  npm run build  |  make build

# Test (run before every commit)
TODO: e.g.  go test ./...   |  npm test        |  pytest

# Lint / format
TODO: e.g.  golangci-lint run  |  npm run lint  |  ruff check .

# Run locally
TODO: e.g.  go run ./cmd/app  |  npm run dev
```

## Architecture

<!-- High-level layout. What lives where, and why. -->

```
TODO: e.g.
cmd/         CLI entry-points
internal/    private packages (not importable by outside modules)
pkg/         public/shared packages
```

Key design decisions:
- TODO: decision 1
- TODO: decision 2

## Conventions

<!-- Rules Claude must follow when writing or modifying code in this repo. -->

- **Style**: TODO (e.g. gofmt + golangci-lint / eslint + prettier / black + ruff)
- **Naming**: TODO (e.g. snake_case for files, CamelCase for types)
- **Error handling**: TODO (e.g. always wrap with fmt.Errorf / never swallow errors)
- **Tests**: TODO (e.g. table-driven, one assertion per test, no external deps in unit tests)
- **Commits**: TODO (e.g. Conventional Commits — feat/fix/chore/refactor)
- **No magic numbers** — use named constants
- **No commented-out code** — delete it or track it in a ticket

## Key Files

<!-- Point Claude at the files that matter most so it reads them first. -->

| File / Directory | Purpose |
|------------------|---------|
| TODO path        | TODO purpose |
| TODO path        | TODO purpose |

## Environment

<!-- Variables required to run or test the project locally. -->

```sh
# Copy .env.example and fill in values
# TODO: list required env vars, e.g.:
# DATABASE_URL=
# API_KEY=
```

## Out of Scope

<!-- Topics Claude should NOT touch without explicit instruction. -->

- TODO: e.g. "Do not modify the generated protobuf files in pkg/proto/"
- TODO: e.g. "Do not change the public API surface of pkg/ without a design discussion"

<!-- gk:agents:begin v18 — managed by `gk agents install`; edit outside this block -->
## Git workflow (git-kit)

This repository is driven with git-kit, an agent-native git CLI. Always invoke it as `git-kit` — the short name `gk` is the same binary but is commonly shadowed by shell aliases (oh-my-zsh maps `gk` to gitk), so it is not reliable from an agent shell. Prefix every agent tool call with `GK_AGENT=1 git-kit …` — an agent shell does not persist environment between tool calls, so setting it just once would silently lapse to human-readable prose on the next call (a human at an interactive shell can `export GK_AGENT=1` once instead). With it set, every command emits a uniform envelope — `{state, ok, result}` on success, `{state:"error", ok:false, error:{code, message, remedies:[{command,safety}]}}` on failure — so you branch on fields, never parse prose. `state` is the dispatch key: `ok` (done) · `paused` (a conflict/operation is mid-flight — resume or abort it) · `blocked` (a precondition like a diverged base failed — run the remedy) · `error` (the command failed); `ok` is kept as a derived alias (`ok == state=="ok"`). **Quick start — most agent sessions are three turns:** `git-kit context` (orient) → make your edits → `git-kit land` (commit + pull + push in one transaction); add `git-kit ship -y` to cut a release. Prefer git-kit over raw git — each verb below collapses several git calls into one:

- **Orient first**: `git-kit context` — one call returns branch, upstream, ahead/behind, dirty counts, any in-progress rebase/merge (with resume/abort commands), base-branch drift, worktrees, and `next_actions`. Add `--include=diff,log,precheck,remotes,release` (or `--include=all`) to fuse the uncommitted-change digest (untracked included), the last 5 commits, the next-pull conflict forecast, per-remote drift, and the commits since the latest tag (what is still unreleased) into the same document — one call instead of six; a section that cannot be collected degrades to a `notes` entry, never an error. Never chain raw git status/branch/log/diff probes across separate calls — one context call answers them all.
- **Wrap up**: `git-kit land` — commit (AI-grouped), pull --with-base, push as one transaction with per-step results; on failure the result names `failed_step` and the resume command. Add `--to parent|base|<branch>` to also forward-merge the current branch: `parent` = one hop to the gk-parent (base fallback), `base` = straight into the base, `<branch>` = chain-walk the parent links hop by hop up to that branch. Make it the default via `land.promote` config or `GK_LAND_PROMOTE` env (value `parent` or a branch name — for the base use its real name, not the word `base`); `--no-push` makes the run local (commit + pull + local merge, no push). `--cleanup` also reclaims fully-merged branches and their worktrees. (`--promote` is the deprecated alias for `--to`; use `git-kit promote <branch>` for the multi-hop parent-chain walk.)
- **Local wrap-up (no network)**: `git-kit promote` — commit, then forward-merge the current branch into its parent/base (gk-parent metadata, trunk fallback); `git-kit promote <branch>` walks the parent chain hop by hop. Nothing is pushed without `--push` — use it when integration is local and land would push too early. Same per-step result contract as land.
- **Batch any sequence**: `git-kit batch --plan -` — run several git-kit commands as one transaction from a JSON plan on stdin: `{"steps":[{"args":["pull","--with-base"]},{"args":["push"]}]}`, optional per-step `on_failure: "abort"|"continue"`. The result reports per-step outcomes plus `failed_step`/`resume`; a gating failure skip-marks the remaining steps. Draft a plan with `--plan-template`, preview with `--dry-run`. N calls → 1.
- **Sync**: `git-kit pull` (add `--with-base` to also fast-forward the local base branch, FF-only). On conflict the result lists the files plus the exact resume/abort commands. `--from <remote>[/<branch>]` integrates from a secondary remote (mirror, org fork) that the upstream chain never fetches — tracking config stays untouched.
- **Forecast before integrating**: `git-kit precheck [target]` — read-only merge-tree simulation (no target = the next pull). Clean → integrate; conflicts listed → pick a strategy first instead of try→abort.
- **Inspect changes**: `git-kit diff --digest` — per-file change kind, ±lines, hunk count, and the changed symbols, without the patch body. Same ref/path arguments as plain diff (`--staged`, `HEAD~3`, `main..feature`). Read the full patch only for the files the digest makes interesting.
- **Isolated worktree task**: `git-kit worktree run <branch> -- <command>` — create (or reuse) a worktree for `<branch>`, run the command with the worktree as its cwd, and exit with the command's own exit code: the single-shot CLI form of a parallel, isolated task (a new branch is cut off HEAD, gk-parent recorded, `worktree.init` applied). `--cleanup` reclaims the worktree when the command succeeds (and deletes the branch if this call created it); a failing command is left in place for inspection. `--from <ref>` bases a new branch elsewhere, `--init`/`--no-init` force or skip the gitignored-state bootstrap. To find which worktree holds unfinished work without a per-path probe, `git-kit worktree list --json` reports each worktree's branch, ahead/behind, parent, lock state, and dirty counts in one call.
- **Commit / push**: `git-kit commit -f` groups changes into conventional commits; `git-kit push` scans for secrets before pushing.
- **Curated multi-commit**: when YOU decide the grouping instead of the AI, `git-kit commit --plan-template` emits the dirty files as a JSON draft; split it into `{"commits":[{"message":"feat(x): ...","files":[...]}]}` and run `git-kit commit --plan -` — N curated commits in one deterministic call (no AI, secret scan included, backup ref behind `gk commit --abort`). Duplicate/unknown files and malformed messages are rejected up front; files the plan does not cover stay dirty. Use this instead of chaining raw `git add` + `git commit` pairs.
- **History editing**: never open `git rebase -i` (the editor session is unusable for you). Instead: `git-kit rebase --plan-template` emits the commit range as JSON (action/commit/subject/pushed), you decide each commit's fate (pick/squash/fixup/reword/drop), then `git-kit rebase --plan -` validates it (every commit addressed, pushed commits guarded) and drives git's own rebase with a backup ref.
- **Conflicts**: `git-kit resolve --ai` (or `--strategy ours|theirs`) resolves AND finishes the operation — it runs the continue step itself, re-resolves later picks that conflict with the same strategy, auto-skips picks the resolution emptied, and also handles delete/modify and markerless conflicts from the index stages (AI decides keep/delete/merge with a rationale); one call takes a paused rebase to done (`--no-continue` to stop after resolving, `git-kit abort` to give up). `git-kit continue` remains for manually edited resolutions. A paused state is a result — `state:"paused"`, `ok:false`, exit 3 — not an error; resume or abort it rather than running an error remedy.
- **Release**: read the plan first — `git-kit ship --dry-run --json` emits the full release plan (inferred version, CHANGELOG draft, the preflight/watch/verify step lists, and `merge_to_base`). When it looks right, `git-kit ship -y` runs the whole pipeline — preflight (lint/test) → version/CHANGELOG → tag → push → CI watch → artifact verify — and works under GK_AGENT: human progress streams to stderr while stdout stays a clean result envelope `{tag, branch, base, merged_to_base, pushed, shipped_on}` (no `env -u GK_AGENT` dance needed). Preflight (lint/test) gates the release, so validate up front with `git-kit ship --preflight` (runs the configured checks on the working tree — dirty is fine — and never tags or pushes; `{result, steps, failed_step}` under GK_AGENT) and get them green before `-y`; `git-kit commit` also warns on gofmt before it reaches preflight. From a non-base branch (e.g. develop) ship fast-forwards the base (main) and tags there; if history diverged it stops with `state:"blocked"` and the remedy `git-kit sync` (rebase the branch onto its base so base can fast-forward), then ship again. `--wait=false` (or `ship.wait`) skips the CI watch; `ship.auto_confirm` makes `-y` the default. What's still unreleased: `git-kit context --include=release`.
- **Stuck repo** (stale index.lock, orphan merge, prunable worktrees, asymmetric push-only remotes whose merged work never comes down): `git-kit doctor --fix`.
- On any failure run the first entry of `error.remedies` (check `safety` first) instead of retrying variations.
<!-- gk:agents:end -->
