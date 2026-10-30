# 7. Abort ACK on I2C open and close

## Status

Accepted, February 2026

## Context

A process killed during a command such as `InListPassiveTarget` leaves the PN532 mid-command, and the next process finds it stuck.

Alternative: power-cycle or hardware reset. The breakout board does not expose RSTPDN, and a power cycle cannot be automated.

## Decision

`Close()` sends an ACK frame before closing the bus; per PN532 manual §6.2.1.3, a host-sent ACK aborts the current command. `New()` sends the same abort on startup, ignoring errors.

## Consequences

The normal killed-process case recovers on the next open. A device too stuck to take the abort is left to `Reconnect()`.
