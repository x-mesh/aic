# AGENTS.md

> This file is read by AI coding agents (Jules, GitHub Copilot Workspace,
> Codex, Gemini CLI, etc.) before they start work.
> Keep it short, factual, and always up-to-date.

## Project Overview

<!-- One paragraph: what this project is, what language/runtime it uses,
     and what problem it solves. -->
TODO: describe the project

## Repository Layout

```
TODO: e.g.
cmd/          entry-points / CLI binaries
internal/     private application packages
pkg/          exported/shared packages
docs/         design documents and ADRs
testdata/     fixtures used by tests
```

## Build & Test

<!-- Exact commands an agent must run to verify its changes compile and pass tests. -->

```sh
# Verify everything builds
TODO: e.g.  go build ./...  |  npm ci && npm run build

# Run the full test suite
TODO: e.g.  go test ./...   |  npm test  |  pytest -q

# Lint (must be clean before opening a PR)
TODO: e.g.  golangci-lint run  |  npm run lint  |  ruff check . && mypy .
```

**An agent MUST run build + test + lint and confirm they are clean before
submitting any change.**

## Coding Conventions

- Language/runtime: TODO (e.g. Go 1.24 / Node 22 / Python 3.12)
- Formatter: TODO (e.g. gofmt / prettier / black) — run before every commit
- Error strategy: TODO (e.g. wrap all errors with context; never panic in library code)
- Test style: TODO (e.g. table-driven unit tests; no mocks for pure functions)
- Commit format: TODO (e.g. Conventional Commits — `feat:`, `fix:`, `chore:`)

## Key Interfaces & Entry Points

<!-- The files an agent should read first to understand the codebase. -->

| Path | Role |
|------|------|
| TODO | TODO |
| TODO | TODO |

## Do Not Touch

<!-- Files or directories agents must never modify without explicit human approval. -->

- TODO: e.g. `pkg/proto/` — auto-generated; re-run `make proto` instead
- TODO: e.g. `CHANGELOG.md` — updated by the release script only
- TODO: e.g. `.github/workflows/` — CI config requires team review

## Pull Request Checklist

Before marking a PR ready for review an agent must confirm:

- [ ] `TODO build command` exits 0
- [ ] `TODO test command` exits 0 with no failures
- [ ] `TODO lint command` exits 0
- [ ] No new TODO/FIXME left in changed files (or each is tracked in an issue)
- [ ] Commit messages follow the project convention
