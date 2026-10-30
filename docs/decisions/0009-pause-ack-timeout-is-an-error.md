# 9. Pause ack timeout is an error

## Status

Accepted, February 2026

## Context

`pauseWithAck` returned nil when the polling loop failed to acknowledge within its timeout, so `PauseAndRun` and `WriteToTag` proceeded while the loop could still be using the device.

Alternative: wait forever. That deadlocks when the loop exits without acknowledging.

## Decision

`pauseWithAck` returns `ErrPauseAckTimeout` when the wait expires and the loop is still running. Callers wrap and propagate it without touching the device.

## Consequences

Callers distinguish "safe to proceed" from "loop may still be running".
