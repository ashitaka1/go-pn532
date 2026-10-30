# 1. I2C Close releases the bus file descriptor

## Status

Accepted, February 2026

## Context

`Transport.Close()` in `transport/i2c/i2c.go` was a no-op that relied on periph.io to clean up. On a Raspberry Pi, rapidly destroying and recreating the transport leaked bus file descriptors and crashed the I2C bus.

Alternative: reference-count transports at the application level. The library cannot control how callers create and drop transports.

## Decision

`Transport` holds the `i2c.BusCloser` it opened, and `Close()` calls `bus.Close()`, which releases the fd and clears kernel driver state.

## Consequences

Each transport owns its bus handle. Closing a transport while another holds the same bus is the caller's problem.
