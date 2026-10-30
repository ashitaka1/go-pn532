# 4. waitAck classifies NACK frames

## Status

Accepted, February 2026

## Context

`waitAck` recognized only ACK frames. A NACK from the PN532 was ignored until the 100ms timeout, and the caller received `ErrNoACK` instead of `ErrNACKReceived`.

Alternative: compare error strings. Fragile.

## Decision

`readAckKind()` returns an `ackKind` (`ackKindACK`, `ackKindNACK`, `ackKindOther`). `waitAck` returns nil on ACK, `ErrNACKReceived` on NACK, and sleeps 1ms and retries on anything else.

## Consequences

Callers see a NACK immediately and with the correct error.
