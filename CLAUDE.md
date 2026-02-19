# CLAUDE.md

This file provides project-specific guidance to Claude Code (claude.ai/code) for this repository.

## Current Status

Project phase: Active Development

Known bugs under investigation — see `project_spec.md` "Known Bugs" section.

## About This Project

Go library for NXP PN532 NFC readers. Supports UART/I2C/SPI transports and NTAG21X/MIFARE Classic/FeliCa tags with NDEF read/write.

See `project_spec.md` for technical architecture, milestones, and implementation decisions.
See `docs/polling-architecture-review.md` for polling concurrency architecture, timing model issues, and future refactoring ideas.

## Project-Specific Conventions

### Mutex: Always use `syncutil`

All code must use `syncutil.Mutex` / `syncutil.RWMutex` from `internal/syncutil/`, never `sync.Mutex` directly. Enforced by `forbidigo` linter (exemption only for `internal/syncutil/` itself).

### License Header

Every `.go` file requires the Apache 2.0 header enforced by `goheader`:
```go
// Copyright <YEAR> The Zaparoo Project Contributors.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 ...
```

### Linter Limits

- Cyclomatic/cognitive complexity: 15
- Function length: 80 lines / 50 statements
- Arguments: 5 max, results: 3 max
- Control nesting: 3 max
- Line length: 120 chars
- Variable name min length: 2 (except `err`, `id`, `i`, `j`, `k`, `db`, `tx`, `ctx`, `wg`)
- JSON tags: snake_case
- Formatters: `gofumpt`, `gci`

### Branch Naming

`<type>/<description>` — e.g. `fix/uart-disconnect-reconnection`

### Pre-commit Hooks

Lefthook runs `make lint` and `go mod tidy` check on commit.

### Testing

```bash
make test          # Unit + integration tests with race detection
make test-unit     # Unit tests only (-race, 10m timeout)
make deadlock      # Tests with deadlock detection build tag
make fuzz          # Fuzz tests (30s each, ~3min total)
```

Run a single test:
```bash
go test -v -race -run TestName ./path/to/package/
```

### Build / Run

```bash
make build         # Build all packages
make reader        # Build cmd/reader binary
make lint          # go mod tidy + golangci-lint
make lint-fix      # Lint with auto-fix
make check         # lint + test + deadlock (pre-commit check)
```

### Build Tags

- **`integration`** — tests requiring real hardware or the wire simulator
- **`deadlock`** — swaps `sync.Mutex` for `go-deadlock` equivalents via `internal/syncutil`

## Reference Documentation

Hardware manuals and protocol specs are in `docs/`. Key references:
- `docs/hardware-pn532-manual.md` — PN532 User Manual (frame protocol in section 6.2)
- `docs/hardware-ntag21x-manual.md` — NTAG213/215/216 datasheet
- `docs/hardware-mifare-classic-1k-manual.md` — MIFARE Classic
- `docs/spec-ndef-manual.md` — NFC Forum NDEF specification
- `docs/tag-operation-patterns.md` — Tag operation patterns and flows
