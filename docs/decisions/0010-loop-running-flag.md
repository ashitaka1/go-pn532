# 10. loopRunning flag for poll loop liveness

## Status

Accepted, February 2026

## Context

`pauseWithAck` needs to know whether a poll loop is active. A lock would be deadlock-prone, since the loop holds none, and the `isPaused` and `closed` atomics do not say whether the loop is running.

## Decision

`Session.loopRunning` is an `atomic.Bool`, set true before the poll loop's main `for` and reset by `defer`. `pauseWithAck` reads it to decide whether to expect an ack and rechecks it after a timeout.

## Consequences

A pause with no loop running succeeds at once. A loop that exits during the wait is not reported as a timeout.
