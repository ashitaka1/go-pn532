# 5. I2C LCS errors trigger NACK and retry

## Status

Accepted, February 2026

## Context

A bad LCS checksum on a response frame is transient bus noise. The transport returned it to the caller as `ErrFrameCorrupted`, and the caller had no way to request retransmission.

Alternative: return the error to the caller. The caller cannot drive the NACK/retransmit sequence.

## Decision

On a bad LCS, `receiveFrameAttempt` returns `(nil, true, nil)`. `receiveFrame` sends a NACK and retries up to three times, the retransmission protocol in the PN532 manual.

## Consequences

Transient checksum errors recover inside the transport.
