# 11. PauseAndRun takes writeMutex

## Status

Accepted, February 2026

## Context

`PauseAndRun` gives a caller exclusive device access during polling. `WriteToTag` also pauses the loop, under `writeMutex`; without coordination the two race.

Alternative: separate mutexes for device-level and tag-level operations. Both need the same exclusion.

## Decision

`PauseAndRun` acquires `writeMutex`, then calls `pauseWithAck`, runs the function, and resumes.

## Consequences

Every operation that pauses the loop is serialized through `writeMutex`.
