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
