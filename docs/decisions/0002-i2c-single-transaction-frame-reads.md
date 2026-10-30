# 2. I2C frame data read in one transaction

## Status

Accepted, February 2026

## Context

The PN532 restarts its output buffer at each new I2C read transaction. Reading a frame header and body in separate transactions returns the header twice; responses over 32 bytes were corrupted.

Alternative: keep a separate status check and data read per chunk. Hardware testing showed timeouts and corruption.

## Decision

`readFrameData()` reads the full maximum-size frame in one `Tx()` call.

## Consequences

Each read allocates the maximum frame buffer. No I2C stop-start occurs mid-frame.
