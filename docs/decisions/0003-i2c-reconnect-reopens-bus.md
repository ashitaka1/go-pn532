# 3. I2C Reconnect reopens the bus

## Status

Accepted, February 2026

## Context

The PN532 firmware can stop answering any command. The `Reconnecter` interface lets the device layer request recovery.

Alternative: send a software reset command. A locked-up PN532 does not process commands.

## Decision

`Reconnect()` closes the bus fd, sleeps 100ms, reopens the bus, and sends an abort ACK.

## Consequences

Recovery depends on the bus release resetting the firmware. The breakout board does not expose RSTPDN on its headers, so a true power cycle is unavailable to software.
