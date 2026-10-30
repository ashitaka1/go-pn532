# 12. Pause ack timeout derived from poll cycle timeout

## Status

Accepted, February 2026

## Context

The ack wait was 100ms. On I2C, `InListPassiveTarget` blocks about 5s per cycle, so `pauseWithAck` returned `ErrPauseAckTimeout` while the loop was working normally.

Alternative: a fixed larger constant such as 10s. It goes stale when `pollCycleTimeout` changes.

## Decision

`defaultPauseAckTimeout = pollCycleTimeout + time.Second`. `pollCycleTimeout` (10s) is the context deadline on every poll cycle, the longest the loop can be away from a pause check; the second covers loop bookkeeping. `NewSession` stores it in `Session.pauseAckTimeout`, which tests override.

## Consequences

A pause can take up to one poll cycle. The timeout tracks `pollCycleTimeout`.
