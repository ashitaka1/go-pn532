# Polling Architecture Review

Review of the `polling` package's concurrency architecture, timing model, and transport abstraction gaps. Intended to inform future refactoring decisions.

## Pause/Ack Protocol

The PN532 device is not thread-safe. Only one goroutine can use the serial bus (I2C/UART/SPI) at a time. The polling loop runs continuously in its own goroutine, calling `InListPassiveTarget` every cycle. When another operation needs the device (writing a tag, running diagnostics), the loop must yield.

### Channel Protocol

Three buffered(1) channels coordinate between the caller goroutine and the polling loop goroutine:

- `pauseChan`: caller → loop, "please stop when you can"
- `ackChan`: loop → caller, "I've stopped, device is yours"
- `resumeChan`: caller → loop, "I'm done, continue polling"

Plus one atomic flag:
- `loopRunning`: set by loop on entry, cleared on exit. Read by caller to distinguish "no loop running" (device idle, safe) from "loop running but hasn't acked yet" (device may be in use).

### Why Not Simpler Alternatives

**Mutex on the device:** The polling loop holds the device for seconds at a time (up to ~5s on I2C). A mutex wouldn't tell the loop to stop — the caller would have to race for the lock in the brief gap between cycles. Nondeterministic and potentially unbounded wait.

**Stop/start the loop:** Loses accumulated state — which card is present, removal timers, detection state machine position. Pause/resume preserves all of it.

**Fire-and-forget flag (the old `Pause()`):** Sets `isPaused` but returns immediately. The caller has no way to know when the device is actually free. The loop could be mid-I2C-call and won't see the flag for seconds.

### Loop Structure

The polling loop checks `pauseChan` at two points per iteration:

```
for {
    1. handleContextAndPause()     — non-blocking check (has default case)
    2. executeSinglePollingCycle()  — InListPassiveTarget (BLOCKS: ~5s on I2C)
    3. waitForNextPollOrPause()    — blocking wait on ticker OR pauseChan
}
```

**Why two check points?** Go's `select` with multiple ready channels picks nondeterministically. If a pause signal arrives during step 2 (blocked on I2C), both `ticker.C` and `pauseChan` may be ready when step 3 runs. If `select` picks the ticker, the loop would start another 5s poll without pausing. Step 1's non-blocking check catches this — it reads `pauseChan` before starting new work.

### Ack Timeout

`pauseWithAck` sends to `pauseChan` and waits on `ackChan`. The timeout determines how long to wait before concluding the loop is genuinely stuck (firmware lockup, etc.) vs. just busy with a normal operation.

**Key principle:** The timeout should never fire during normal operation. False positives (timeout during normal work) are far worse than slow detection of genuine failures. The timeout doesn't affect success-path latency — the ack arrives as soon as the current poll cycle completes regardless of the timeout value.

The upper bound on normal operation is `pollCycleTimeout` (10s), which wraps every `InListPassiveTarget` call with a context deadline. After that deadline, the loop is forced out of the blocking call and back to a pause check point.

## Timing Model Issues

### Redundant Timing Controls

Three independent mechanisms control poll timing:

1. **`HardwareTimeoutRetries`** (Config field, default `0x20` = 32): PN532 firmware retries internally, ~150ms each. Controls how long `InListPassiveTarget` blocks before returning "no card." At default, blocks ~4.8s.

2. **`PollInterval`** (Config field, default 250ms): Host-side ticker between poll cycles. The loop waits this long after one cycle before starting the next.

3. **`pollCycleTimeout`** (constant, 10s): Context deadline on each `InListPassiveTarget` call. Safety ceiling to prevent indefinite blocking.

With the default `HardwareTimeoutRetries` of `0x20`, each I2C poll blocks for ~4.8s. The 250ms `PollInterval` ticker fires dozens of times during a single poll — it's entirely redundant. The ticker only matters when hardware retries are low (e.g., `0x00` = immediate return on UART), where polls return instantly and the ticker prevents bus flooding.

These three controls were likely added at different times without a unified timing model. They interact but aren't documented as a system.

### Transport-Agnostic Timing

The `Transport` interface is a byte pipe — it doesn't expose timing characteristics:

```go
type Transport interface {
    SendCommand(command []byte) ([]byte, error)
    SetTimeout(timeout time.Duration)
    IsConnected() bool
    // ...
}
```

The polling session treats all transports identically: same ticker, same timeouts, same config. But transports have fundamentally different timing:

- **I2C**: `InListPassiveTarget` blocks for seconds (hardware retries happen in firmware). The ticker is redundant. The ack timeout must account for multi-second blocking.
- **UART**: `InListPassiveTarget` returns quickly. The ticker provides necessary pacing. The ack timeout can be short.

A transport-aware design could:
- Have the transport report its expected poll duration
- Push pacing responsibility to the transport layer (PN532 hardware retries already do this on I2C)
- Only use the host-side ticker for transports where polls return instantly

## Potential Future Refactoring

### Rationalize Timing

Replace three overlapping timing controls with a coherent model. Options:

1. **Transport-reported timing:** Transport exposes expected poll duration. Session derives all timeouts from it.
2. **Single effective timeout:** Compute one value from `HardwareTimeoutRetries * 150ms` and use it to derive `PollInterval`, ack timeout, and cycle timeout. Remove redundant knobs.
3. **Transport-owned pacing:** The transport controls its own cadence. The session just calls "poll" in a loop and the transport handles rate limiting internally.

### Simplify Pause Check Points

The two-phase pause check (step 1 + step 3) exists to work around Go's nondeterministic `select`. Could be replaced by a priority drain pattern — a non-blocking `pauseChan` read immediately before the ticker `select` in step 3, eliminating step 1 as a separate function.

### Document the Config Contract

If `HardwareTimeoutRetries` and `PollInterval` are both exposed to users, document how they interact and what combinations make sense. Currently there's no guidance — a user could set high hardware retries AND a short poll interval without understanding one makes the other meaningless.
