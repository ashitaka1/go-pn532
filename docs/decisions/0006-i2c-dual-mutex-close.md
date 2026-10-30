# 6. Dual mutex for I2C Close and SendCommand

## Status

Accepted, February 2026

## Context

`Close()` closed the bus and set `t.dev` to nil without serialization, so an in-flight `SendCommand` could dereference nil.

Alternative: one mutex for everything. `Close()` would wait on it while `SendCommand` sat blocked inside a long `Tx` ioctl.

## Decision

`closeMu` (outer) serializes teardown; `mu` (inner) guards `dev` and `bus`. `SendCommand` holds `mu` throughout. `Close()` takes `closeMu`, closes the bus fd so a blocked `Tx` returns EBADF, then takes `mu` to clear the fields.

## Consequences

`Close()` is safe during an active command and returns promptly. Lock order is always `closeMu` then `mu`.
