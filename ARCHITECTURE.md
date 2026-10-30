# Architecture

go-pn532 drives an NXP PN532 NFC controller over UART, I2C, or SPI. The root package speaks the PN532 command set through a byte-pipe `Transport`; tag types build read/write and NDEF on top of it; `polling.Session` runs a continuous detection loop with recovery from sleep, RF errors, and disconnects.

## Layers

```
cmd/reader                 example binary
    |
polling/                   continuous card monitoring session (FSM)
tagops/                    unified tag read/write/detect operations
    |
pn532 (root)               Device, Transport and Tag interfaces, NDEF,
                           retry system, error classification, detection helpers
    |
transport/{uart,i2c,spi}   physical transports
detection/{uart,i2c,spi}   platform device discovery, registered via init()
    |
internal/frame             PN532 frame protocol (manual §6.2): validation, extraction, BufferPool
internal/syncutil          build-tag switchable mutex (sync or go-deadlock)
internal/testing           VirtualPN532 wire-level simulator
    |
pkg/ndef                   standalone NDEF encode/decode (Text, URI, Media records)
```

## Codemap

| Item | Location | Role |
|------|----------|------|
| `Transport` | `transport.go` | sends PN532 commands over a physical link |
| `TransportCapabilityChecker` | `transport.go` | optional feature detection on a transport |
| `Reconnecter` | `transport.go` | recovery when the PN532 firmware locks up |
| `DeviceHealthChecker` | `transport.go` | USB disconnect detection |
| `Device` | `device.go`, `device_context.go` | command layer; `ConnectDevice()` (high level) or `New()` (low level) |
| `Tag`, `BaseTag`, `DetectedTag` | `tag.go` | read/write on a detected tag |
| `tagops.TagOperations` | `tagops/tagops.go` | type-independent tag operations |
| `NTAGTag`, `MIFARETag`, `FeliCaTag` | `ntag.go`, `mifare.go`, `felica.go` | concrete tags, built by `Device.CreateTag()` from a `DetectedTag` (UID, ATQ, SAK) |
| `RetryConfig` | `retry.go`, `retry_constants.go` | exponential backoff with jitter; constants grouped by connection, hardware, tag, NDEF, transport |
| `IsRetryable`, `IsFatal` | `errors.go` | error classification |
| `detection.Detector` | `detection/detector.go` | device discovery registry |
| `polling.Session` | `polling/session.go` | poll loop, pause/resume, `WriteToTag`, `PauseAndRun` |
| `CardDetectionState` | `polling/state.go` | Idle → TagDetected → Reading → PostReadGrace |
| `VirtualPN532` | `internal/testing/wire_simulator.go` | simulated PN532 for integration tests |

## Device lifecycle

1. `ConnectDevice()` or `New()` creates a `Device`.
2. `Init()` checks the firmware version, configures the SAM, and sets up retries.
3. `DetectTag()`, `InListPassiveTarget()`, or `InAutoPoll()` finds a tag. If `InListPassiveTarget` fails, `device_context.go` falls back to `InAutoPoll`, which ACR122U clones handle.
4. Tag operations go through `Tag` or `tagops.TagOperations`.
5. `polling.Session` monitors continuously.

## Invariants

- **All mutexes are `syncutil.Mutex` / `syncutil.RWMutex`.** The `forbidigo` linter enforces it outside `internal/syncutil/`. The `deadlock` build tag works only because every mutex routes through that package.
- **Auto-detection needs blank imports.** `detection/uart`, `detection/i2c`, and `detection/spi` register in `init()`; a binary using auto-detection imports them.
- **`Device` is not thread-safe.** Concurrent callers go through `polling.Session` or their own lock.

### I2C transport (`transport/i2c/i2c.go`)

- Every read transaction starts with a status byte (0x01 when ready, manual §6.2.4). `readI2C()` reads n+1 bytes, checks the status byte, and strips it.
- The address is 7-bit (0x24), as periph.io and the Linux kernel expect.
- Frame data is read in one `Tx()`: a second transaction restarts from the start of the PN532 output buffer.
- `receiveFrameAttempt` returns `(nil, false, nil)` for "not ready" and `(nil, true, nil)` for "corrupted frame". Only the second sends a NACK. A NACK to a device that has sent nothing crashes the bus.
- `closeMu` (outer) serializes teardown; `mu` (inner) guards `dev` and `bus`. `SendCommand` holds `mu` for its whole run. `Close()` takes `closeMu`, sends an abort ACK, closes the bus fd (a blocked `Tx` returns EBADF), then takes `mu` to clear the fields.
- `New()` and `Reconnect()` send an abort ACK (manual §6.2.1.3) to clear a command left in flight by a previous process.

### Polling pause protocol (`polling/session.go`)

`pauseChan`, `ackChan`, and `resumeChan` are each buffered 1. The caller sends on `pauseChan`; the loop answers on `ackChan` and blocks on `resumeChan`. `loopRunning` (`atomic.Bool`) is true from loop start until loop exit.

- `pauseWithAck` drains a stale ack before sending a new pause.
- If `loopRunning` is false before or during the wait, the device is idle and the pause succeeds without an ack.
- If no ack arrives within `pauseAckTimeout` while `loopRunning` is true, it returns `ErrPauseAckTimeout`.
- `pauseAckTimeout` defaults to `pollCycleTimeout + 1s`. `pollCycleTimeout` is the context deadline on every poll cycle, so it bounds how long the loop can be away from a pause check.
- `PauseAndRun` and `WriteToTag` take `writeMutex` before pausing.

`docs/polling-architecture-review.md` covers the protocol in detail and the interaction of `HardwareTimeoutRetries`, `PollInterval`, and `pollCycleTimeout`.

## Reference

Hardware manuals and protocol specs are in `docs/`: `hardware-pn532-manual.md` (frame protocol in §6.2), `hardware-ntag21x-manual.md`, `hardware-mifare-classic-1k-manual.md`, `hardware-mifare-classic-4k-manual.md`, `hardware-felica-manual.md`, `spec-ndef-manual.md`, `tag-operation-patterns.md`. The `acr122u-*` and `dev-acr122u-*` files are research for PC/SC support, which is not implemented.
