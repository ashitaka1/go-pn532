# Contributing

## Setup

Requires Go 1.24 and [golangci-lint](https://golangci-lint.run/). Install the pre-commit hooks with [lefthook](https://github.com/evilmartians/lefthook):

```bash
lefthook install
```

The pre-commit hook runs `make lint` on staged Go files and fails if `go mod tidy` changes `go.mod` or `go.sum`. `LEFTHOOK=0 git commit` skips it.

## Build

```bash
make build         # Build all packages
make reader        # Build the cmd/reader example binary
```

## Test

```bash
make test          # Unit + integration tests with race detection
make test-unit     # Unit tests only
make test-integration
make deadlock      # Tests with the deadlock build tag
make fuzz          # Fuzz tests, 30s each
make fuzz-quick
make bench
make coverage
make check         # lint + test + deadlock
```

A single test:

```bash
go test -v -race -run TestName ./path/to/package/
```

Build tags:

- `integration` — tests that run against real hardware or the `VirtualPN532` wire simulator in `internal/testing/`.
- `deadlock` — swaps `sync.Mutex` for `go-deadlock` through `internal/syncutil`.

Unit tests cover custom logic: state machines, config validation, error handling. Transport tests exercise the wire protocol through mock buses (`MockI2CBus`, `JitteryMockI2CBus`, `callbackI2CBus`, `closableCallbackBus` in `transport/i2c/i2c_wire_test.go`). `MockI2CBus` prepends the I2C status byte to multi-byte reads, as the hardware does. Fuzz tests target frame validation in `internal/frame/`.

## Lint

```bash
make lint          # go mod tidy + golangci-lint
make lint-fix
```

`.golangci.yml` enforces the license header, the `syncutil` mutex rule, and complexity limits; `CLAUDE.md` summarizes them.

## Release

The module is published as `github.com/ashitaka1/go-pn532`. Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds `cmd/reader` for linux, darwin, and windows and attaches the zips to a GitHub release. Move the `[Unreleased]` entries in `CHANGELOG.md` under the new version before tagging.
