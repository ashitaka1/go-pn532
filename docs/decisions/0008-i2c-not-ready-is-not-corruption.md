# 8. I2C "not ready" distinct from a corrupted frame

## Status

Accepted, February 2026

## Context

`receiveFrameAttempt` returned `shouldRetry=true` for both "device not ready" and "corrupted frame", and `receiveFrame` sent a NACK in both cases. A NACK to a device that has not transmitted is a protocol violation; on hardware it crashed the bus ("sysfs-i2c: remote I/O error") for any command slower than the `checkReady` backoff.

Alternative: always send NACK. Confirmed to crash the bus.

## Decision

`receiveFrameAttempt` returns `(nil, false, nil)` for not ready (poll again, no NACK) and `(nil, true, nil)` for a corrupted frame (NACK and retry). `receiveFrame` uses the caller's context deadline when one is set and `t.timeout` otherwise.

## Consequences

Long-running commands such as `InListPassiveTarget` complete on I2C.
