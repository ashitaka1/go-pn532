# Project Specification: go-pn532

## Purpose

Go library for communicating with NXP PN532 NFC reader chips over UART, I2C, and SPI. Provides low-level protocol handling, tag detection/identification, NDEF read/write, and a high-level polling session system with sleep/wake recovery.

## User Profile

1. **Library consumers** — Go developers integrating PN532 NFC readers into applications (e.g., Zaparoo project)

## Goals

**Goal:** Reliable NFC tag reading/writing across UART, I2C, and SPI transports
**Goal:** Support NTAG21X, MIFARE Classic (1K/4K), and FeliCa tag families with NDEF
**Goal:** Continuous polling with automatic recovery from sleep, RF errors, and device disconnects

**Non-Goal:** PC/SC (CCID) protocol support (ACR122U clone research exists in docs/ but is not implemented)
**Non-Goal:** Crypto1 key cracking or security-bypassing features

## Features

### Required
- PN532 frame protocol (section 6.2) over UART, I2C, SPI
- Tag detection and identification (ATQ/SAK pattern matching)
- NDEF read/write for NTAG, MIFARE Classic, FeliCa
- Continuous polling session with FSM (Idle, TagDetected, Reading, PostReadGrace)
- Auto-detection of connected PN532 devices
- Retry system with exponential backoff and jitter
- Error classification (retryable vs fatal, RF errors, device-gone detection)

### Milestones

1. ✅ Core library — transport, device lifecycle, tag operations, polling, NDEF
2. ✅ Bug fixes — I2C transport fully functional on hardware: bugs 0, 0a, bus crash, correctness, spurious NACK (Bug 11), and process-kill recovery (Issue #1) all fixed

### Nice-to-Have
- MIFARE Classic 4K large-sector support (currently blocked by bug #6)
- FeliCa block list format cleanup (bug #7)

## Tech Stack

### Language(s)
- Go 1.24

### Frameworks/Libraries
- `go.bug.st/serial` — UART serial communication
- `periph.io/x/conn/v3`, `periph.io/x/host/v3` — I2C and SPI via periph.io
- `github.com/sasha-s/go-deadlock` — opt-in deadlock detection (build tag)
- `github.com/stretchr/testify` — test assertions

### Platform/Deployment
- Library: any Go project importing the module

### Infrastructure
- Hardware: NXP PN532 NFC reader boards
- Tags: NTAG213/215/216, MIFARE Classic 1K/4K, FeliCa

## Technical Architecture

### Layer Diagram

```
cmd/reader (example binary)
    |
polling/         -- Session state machine for continuous card monitoring
tagops/          -- Unified high-level tag read/write/detect operations
    |
pn532 (root)     -- Device, Transport interface, Tag interface, NDEF,
                    retry system, error classification, detection helpers
    |
transport/{uart,i2c,spi}  -- Physical communication implementations
detection/{uart,i2c,spi}  -- Platform-specific device discovery (registered via init())
    |
internal/frame     -- PN532 frame protocol (section 6.2): validation, extraction, BufferPool
internal/syncutil  -- Build-tag switchable mutex (sync vs go-deadlock)
internal/testing   -- VirtualPN532 wire-level simulator for tests
    |
pkg/ndef         -- Standalone NDEF encode/decode library (Text, URI, Media records)
```

### Key Interfaces

| Interface | Location | Purpose |
|-----------|----------|---------|
| `Transport` | `transport.go` | Send commands to PN532 over UART/I2C/SPI |
| `TransportCapabilityChecker` | `transport.go` | Optional feature detection on transport |
| `Reconnecter` | `transport.go` | Recovery when PN532 firmware locks up |
| `DeviceHealthChecker` | `transport.go` | USB disconnect detection |
| `Tag` | `tag.go` | Read/write operations on detected tags |
| `detection.Detector` | `detection/detector.go` | Platform device discovery (registry pattern) |

### Device Lifecycle

1. `ConnectDevice()` (high-level) or `New()` (low-level) creates a `Device`
2. `Init()` — firmware version check, SAM configuration, retry setup
3. `DetectTag()` / `InListPassiveTarget()` / `InAutoPoll()` — tag detection
4. Tag operations via `Tag` interface or `tagops.TagOperations`
5. `polling.Session` for continuous monitoring with FSM: Idle -> TagDetected -> Reading -> PostReadGrace

### Tag Types

Concrete `Tag` implementations: `NTAGTag`, `MIFARETag`, `FeliCaTag` — all extend `BaseTag`. Created via `CreateTag()` factory from `DetectedTag` (UID, ATQ, SAK).

### Retry System

`RetryConfig` with exponential backoff and jitter. Layered retry constants in `retry_constants.go` organized by operation level (connection, hardware, tag, NDEF, transport). Error classification: `IsRetryable()` and `IsFatal()` in `errors.go`.

## Known Bugs

Identified via code review and hardware testing. Ordered by severity.

### Critical

#### Bug 0: ~~I2C transport uses 8-bit address with periph.io (expects 7-bit)~~ FIXED
- **Fixed in:** commit 5e6612d (`fix/address-bug` branch, merged to main)
- **Details:** Changed I2C address from 0x48 (8-bit) to 0x24 (7-bit) for periph.io

#### Bug 0a: ~~I2C transport ignores status byte on read transactions~~ FIXED
- **Fixed in:** commit 3e5a761 (`fix/i2c-ready-byte-framing` branch, merged to main)
- **Details:** The PN532 prepends a status/ready byte (0x01) to every I2C read transaction (datasheet section 6.2.4). The transport did not account for this — ACK reads got `[0x01 0x00 0x00 0xFF 0x00 0xFF]` instead of the expected `[0x00 0x00 0xFF 0x00 0xFF 0x00]`, and frame data was shifted by 1 byte. The test mock (`MockI2CBus`) also did not prepend the status byte, so tests passed while real hardware failed.
- **Fix:** Added `readI2C()` helper that reads n+1 bytes, verifies the status byte, and strips it. Updated mock to prepend 0x01 to multi-byte reads.

#### Bug 11: ~~I2C receiveFrame sends spurious NACK when device is not ready~~ FIXED
- **Fixed in:** commit b652f5d (`claude/fix-pn532-i2c-crash-TbehC` branch)
- **Root cause:** `receiveFrameAttempt` returned `shouldRetry=true` for two distinct situations — "device not ready" and "corrupted frame" — causing `receiveFrame` to send a NACK in both cases. Sending a NACK when the PN532 hasn't sent anything is a protocol violation that crashes the I2C bus ("sysfs-i2c: remote I/O error"), requiring hardware power cycle to recover.
- **Fix:** Split the return signal: `receiveFrameAttempt` now returns `(nil, false, nil)` for "not ready" (poll again without NACK) and `(nil, true, nil)` for "corrupted frame" (send NACK and retry). The `receiveFrame` deadline was also changed to respect the caller's context deadline when present, falling back to `t.timeout` only when no deadline is set.
- **Hardware notes:** PN532 breakout board does NOT expose RSTPDN pin on headers, only on SMD pads. RSTO (reset output) is available but is read-only.

#### Issue #1: ~~I2C PN532 enters unrecoverable hardware fault when process killed during InListPassiveTarget~~ FIXED
- **Fixed in:** commit b652f5d (`claude/fix-pn532-i2c-crash-TbehC` branch), three sub-bugs resolved:
- **Bug A — Nil pointer dereference when Close() races with SendCommand:** `Close()` previously called `bus.Close()` and then nilled `t.dev` without serialization, so an in-flight `SendCommand` holding `mu` could still read `t.dev` after it was nilled. Fixed with a dual-mutex pattern: `closeMu` (outer) guards bus teardown; `mu` (inner) guards `dev`/`bus` field access. `Close()` closes the bus fd under `closeMu` (causing any blocking `Tx` ioctl to fail with EBADF), then acquires `mu` to nil the fields. `SendCommand` holds `mu` throughout, so `dev` cannot become nil while it is in use. Files: `transport/i2c/i2c.go` (`Transport` struct, `Close()`, `SendCommand()`).
- **Bug B — No abort sent to PN532 on Close, leaving device stuck:** `Close()` previously just closed the OS file descriptor, leaving the PN532 mid-transaction. The next opener found a stuck device. Fixed: `Close()` now sends an ACK frame (`[0x00 0x00 0xFF 0x00 0xFF 0x00]`) to the PN532 before closing the bus. Per datasheet §6.2.1.3, a host-sent ACK aborts any in-flight command and returns the device to idle. File: `transport/i2c/i2c.go:Close()`.
- **Bug C — No recovery on connect when PN532 is stuck from previous session:** `New()` previously made no attempt to clear stuck state from a process that was killed mid-transaction. Fixed: `New()` calls `sendAbortACK()` after opening the bus. Errors are ignored (best-effort) since the device may not respond if truly stuck, but this clears the normal case. File: `transport/i2c/i2c.go:New()`.
- **Hardware validation:** 5/5 close-during-infinite-poll cycles pass without crash; normal tag reads unaffected.
- **Regression tests added:** `TestI2C_CloseDuringSendCommand_NoNilDeref` (goroutine channel-handshake ordering test), `TestI2C_Close_SendsAbortACK` (verifies abort frame written before bus.Close). File: `transport/i2c/i2c_wire_test.go`.

#### Bug 1: `skipTLV` does not handle long-format TLV lengths
- **File:** `ndef_validation.go:92-99`
- **Issue:** Only handles single-byte lengths. If the first length byte is `0xFF` (long-format marker), it reads 255 as the length instead of reading the subsequent 2-byte big-endian length. Inconsistent with `parseTLVLength` in the same file which handles both formats correctly.
- **Impact:** Tags with Lock Control or proprietary TLVs using lengths >= 255 will fail NDEF validation.
- **Fix:** Check for `data[i+1] == 0xFF` and read 2-byte length, or reuse `parseTLVLength`.

#### Bug 2: `findNDEFTLV` loop misses entries near data end
- **File:** `ndef_validation.go:123`
- **Issue:** Loop bound `i < len(data)-2` never examines the last 2 bytes. A valid NDEF TLV positioned near the end of the data area will be missed.
- **Impact:** False "no NDEF TLV found" errors on small tags or tags with TLVs near the end.
- **Fix:** Change loop bound to `i < len(data)` with bounds checking inside `processTLVEntry`.

#### Bug 3: SPI transport reads frame in two separate transactions
- **File:** `transport/spi/spi.go:364-445`
- **Issue:** `receiveFrame` reads header (7 bytes) in one SPI transaction, then issues a second `Tx` with `0x03` (SPI Data Read) for the body. The second transaction restarts from the PN532 output buffer beginning instead of continuing where the first left off.
- **Impact:** SPI transport will produce corrupted data or checksum failures. Fundamental protocol violation.
- **Fix:** Read the entire response in a single SPI transaction.

#### Bug 4: Pool buffers allocated but never returned
- **File:** `internal/frame/extraction.go:239-244`
- **Issue:** `ExtractFrameData` allocates from `BufferPool` but the returned data flows up to the application with no mechanism to return it. The pool optimization is effectively dead.
- **Impact:** Unnecessary allocation pressure in high-throughput scenarios. Pool never benefits from reuse.
- **Fix:** Use `make([]byte, dataLen)` in `ExtractFrameData` since data leaves the transport layer, or establish a clear return contract.

### Important

#### Bug 5: MIFARE multi-sector write truncates data
- **File:** `tagops/writer.go:122-159`
- **Issue:** `writeMIFAREBlocks` uses `range numBlocks` but skips trailer blocks with `continue`. The loop counter still advances, consuming iterations without writing data. Multi-sector writes lose the last blocks.
- **Impact:** Data truncation when writing MIFARE data spanning sector boundaries.
- **Fix:** Use a while-loop tracking `block` and `dataOffset` independently, only advancing `dataOffset` on actual writes.

#### Bug 6: MIFARE 4K large-sector calculation is wrong
- **File:** `mifare.go:263, 285, 322, 383`
- **Issue:** Sector calculation `block / 4` is correct for 1K (sectors 0-15, 4 blocks each) but wrong for 4K sectors 32-39 (16 blocks each). Block 144 maps to sector 36 instead of the correct sector 33.
- **Impact:** Authentication failures for blocks 128-255 on MIFARE Classic 4K tags.
- **Fix:** For blocks 0-127: `sector = block/4`. For blocks 128-255: `sector = 32 + (block-128)/16`.

#### Bug 7: FeliCa block list format mismatch
- **File:** `felica.go:170-172, 247-249`
- **Issue:** Block list element sets bit 7 (`0x80`, indicating 2-byte mode) but sends 3 bytes. The third byte will be interpreted as start of additional data, corrupting the command.
- **Impact:** FeliCa Read/Write Without Encryption commands may fail or target wrong blocks.
- **Fix:** Either use 2-byte format (`0x80 | high, low`) or 3-byte format (`0x00 | high, low, service_order`).

#### Bug 8: SPI transport has no concurrency protection
- **File:** `transport/spi/spi.go:55-62`
- **Issue:** No mutex on `currentTrace` or `timeout`, unlike the UART transport which has `mu` and `closeMu`.
- **Impact:** Data races if SPI transport accessed concurrently.
- **Fix:** Add a mutex matching UART's pattern, or document that no transport provides thread safety.

### Low Priority

#### Bug 10: I2C transport uses two transactions where the datasheet specifies one
- **File:** `transport/i2c/i2c.go` (waitAck, readFrameData, checkReady)
- **Issue:** The PN532 datasheet (section 6.2.4) specifies that the status byte and frame data should be read in a single I2C transaction: START → read status → if ready, continue reading frame → STOP. The current implementation uses a separate `checkReady()` transaction followed by a `readI2C()` transaction. The PN532 tolerates this (it prepends a fresh status byte to each transaction), but it doubles the bus traffic and deviates from the documented protocol.
- **Impact:** Low Priority — This is a separate issue from the bus crashes. The two-transaction pattern deviates from the datasheet and adds bus overhead, but is NOT the root cause of the "sysfs-i2c: connection timed out" errors observed on hardware (see Bug 11 for actual cause).
- **Status:** Deferred — Fix approach would combine ready check and data read into a single `Tx()` call per read path, but this is a code quality improvement, not a critical fix.

#### Bug 9: `WaitForTag` returns (nil, nil) on transient errors
- **File:** `detection.go:46-65`
- **Issue:** When `handleDetectionError` returns nil (under max errors), `attemptDetection` returns `(nil, nil)`. `WaitForTag` treats this as success, returning a nil tag with no error.
- **Impact:** Callers interpret transient detection errors as "no tag found, success."
- **Fix:** Treat `(nil, nil)` from `attemptDetection` as a continue-polling condition.

## Implementation Notes

- The `forbidigo` linter enforcing `syncutil.Mutex` is the mechanism that makes the `deadlock` build tag work globally — all mutexes route through `internal/syncutil` which swaps implementations at compile time.
- Detection sub-packages (`detection/uart`, `detection/i2c`, `detection/spi`) register via `init()` blank imports. Any binary using auto-detection must import them.
- The `internal/testing/VirtualPN532` simulates the PN532 at the wire protocol level, enabling integration-style tests without hardware.
- Clone device (ACR122U) fallback: if `InListPassiveTarget` fails, `device_context.go` falls back to `InAutoPoll`, handling protocol quirks of ACR122U clones.

### I2C Transport Fixes (Feb 2026)

Series of commits on `claude/fix-pn532-i2c-crash-TbehC` addressing I2C transport correctness and reliability:

**Commit 7817b06 — Prevent bus crash on rapid destroy/recreate cycles:**
- Fixed file descriptor leaks in `transport/i2c/i2c.go:Close()` — added bus fd tracking (`bus i2c.BusCloser` field) and explicit `bus.Close()` call, clearing kernel driver state
- Made `checkReady()` context-aware to prevent sleep bleeding into next instance lifecycle
- Changed `readFrameData()` to single-transaction reads (reads full max-frame buffer in one `Tx()` call; avoids the PN532 "restart-from-zero" behavior that corrupts multi-transaction frame reads)

**Commit f955d16 — Overhaul transport correctness:**
- Fixed timeout handling — `checkReady()` now uses context-aware `sleepCtx()` instead of `time.Sleep()`; `receiveFrame` respects caller's context deadline when present
- Added `Reconnect()` implementing `Reconnecter` interface — closes and reopens I2C bus, sends abort ACK on reconnect to clear stuck state
- Refactored `waitAck` to use `ackKind` enum (`ackKindACK`, `ackKindNACK`, `ackKindOther`) and detect PN532-sent NACK frames explicitly

**Commit 4c56709 — Regression test coverage:**
- Added `transport/i2c/i2c_wire_test.go:TestI2C_CorruptedLCS_ShouldRetryNotError` — verifies bad LCS sets `shouldRetry=true`, not hard error
- Added `TestI2C_NACKFromDevice_ReturnsErrNACKReceived` — verifies PN532-sent NACK returns `ErrNACKReceived` immediately (not `ErrNoACK` after timeout)
- Added `TestI2C_ImplementsReconnecter` — runtime verification that `*Transport` satisfies `pn532.Reconnecter`

**Commit b652f5d — Fix spurious NACK on "not ready" (Bug 11) and lifecycle crash (Issue #1):**
- Fixed `receiveFrameAttempt` to distinguish "not ready" from "corrupted frame": returns `(nil, false, nil)` for not-ready (no NACK sent), `(nil, true, nil)` for corrupted frame (NACK+retry). Previously both returned `shouldRetry=true`, causing a NACK to be sent to a device that hadn't transmitted anything — a protocol violation that crashed the I2C bus.
- Added dual-mutex pattern (`closeMu` + `mu`) to `Close()` to prevent nil pointer dereference when `Close()` races with `SendCommand()`: `closeMu` serializes teardown and bus fd close; `mu` serializes field access. `Close()` acquires `closeMu` first, closes bus fd (causing any blocking `Tx` ioctl to return EBADF), then acquires `mu` to nil `dev`/`bus`.
- `Close()` now sends an abort ACK frame to the PN532 before closing the bus fd, per datasheet §6.2.1.3, so the device returns to idle and the next opener does not find a stuck device.
- `New()` sends an abort ACK on startup to clear any stuck state left by a previous process that was killed mid-transaction.
- Added lifecycle regression tests: `TestI2C_CloseDuringSendCommand_NoNilDeref` (channel-handshake ordering), `TestI2C_Close_SendsAbortACK` (verifies ACK frame written before bus.Close).

**Hardware validation status (PN532 v1.6, Raspberry Pi 5, /dev/i2c-1):**
- GetFirmwareVersion: reliable
- InListPassiveTarget with concurrent Close(): 5/5 cycles pass without crash or nil deref
- Normal tag reads: unaffected
- PN532 breakout board does not expose RSTPDN pin on headers (only on SMD pads); RSTO is read-only

**Testing methodology:**
- Wire-level regression tests in `transport/i2c/i2c_wire_test.go` using `MockI2CBus`, `JitteryMockI2CBus`, `callbackI2CBus`, and `closableCallbackBus` infrastructure
- `MockI2CBus` prepends I2C status byte (0x01) to multi-byte reads, matching real hardware behavior
- `closableCallbackBus` provides channel-based ordering guarantees for concurrent lifecycle tests

## Milestone Architecture Decisions

### I2C Transport Correctness (Milestone 2, Feb 2026)

**Decision: Track bus fd in Transport struct and close it explicitly in Close()**
- Problem: Raspberry Pi I2C bus crashed on rapid device destroy/recreate cycles; the original `Close()` was a no-op (`// periph.io handles cleanup automatically`)
- Solution: Add `bus i2c.BusCloser` field to `Transport`; `Close()` calls `bus.Close()` to release the OS file descriptor, clearing kernel driver state
- Alternative considered: Reference counting at application level — rejected because library cannot control caller lifecycle patterns
- File: `transport/i2c/i2c.go:Transport` struct, `Close()`

**Decision: Single-transaction reads for frame data where possible**
- Problem: Multiple I2C transactions mid-frame increase bus overhead and potential for timing issues
- Solution: `readFrameData()` reads full frame in single `Tx()` call when size known upfront
- Alternative considered: Keep separate status check + data read — rejected after hardware testing showed potential timeout issues
- Trade-off: Slightly larger initial read buffer allocation, but eliminates I2C stop-start mid-frame
- File: `transport/i2c/i2c.go:readFrameData()`

**Decision: Implement Reconnect() with full bus release/reopen**
- Problem: PN532 firmware can enter unresponsive state requiring power cycle
- Solution: `Reconnect()` closes the bus fd, sleeps 100ms, reopens the bus, and sends an abort ACK to clear stuck state — giving the PN532 time to reset between bus cycles
- Alternative considered: Software reset command — rejected because PN532 may not respond to commands when locked up
- Limitation: Cannot truly power-cycle PN532 without hardware control; relies on I2C bus release triggering firmware reset
- File: `transport/i2c/i2c.go:Reconnect()`

**Decision: Classify PN532-sent NACK using ackKind enum in waitAck**
- Problem: `waitAck` only recognized ACK frames; NACK frames from the PN532 were silently ignored and the loop ran until the 100ms timeout, returning `ErrNoACK` instead of `ErrNACKReceived`
- Solution: Introduced `ackKind` enum (`ackKindACK`, `ackKindNACK`, `ackKindOther`) in `readAckKind()`. `waitAck` switches on the kind: ACK returns nil, NACK returns `ErrNACKReceived` immediately, other sleeps 1ms and retries
- Alternative considered: String comparison on error text — rejected as fragile
- File: `transport/i2c/i2c.go:waitAck()`, `readAckKind()`

**Decision: LCS errors trigger NACK+retry, not hard error**
- Problem: LCS checksum errors on response frames indicate transient bus noise, but were returned as hard `ErrFrameCorrupted` to the caller
- Solution: `receiveFrameAttempt` returns `(nil, true, nil)` (needsNACK=true) on bad LCS; `receiveFrame` sends NACK and retries up to 3 times, matching the PN532 datasheet retransmission protocol
- Alternative considered: Return error to caller — rejected because caller then had no way to trigger the NACK+retransmit sequence
- File: `transport/i2c/i2c.go:receiveFrameAttempt()`, `receiveFrame()`

**Decision: Dual-mutex pattern (closeMu + mu) for Close() / SendCommand() race safety**
- Problem: `Close()` raced with in-flight `SendCommand()`: closing the bus fd and nilling `t.dev` without serialization could cause a nil pointer dereference in a concurrent `Tx()` call
- Solution: `closeMu` (outer) serializes bus teardown; `mu` (inner) serializes all field reads and writes. `Close()` takes `closeMu`, closes the bus fd (causing the blocking `Tx` ioctl in `SendCommand` to return EBADF), then takes `mu` to nil the fields. `SendCommand` holds `mu` throughout its execution, so `t.dev` cannot be nilled while it is in use.
- Alternative considered: Single mutex for everything — rejected because `Close()` would deadlock waiting for `mu` while `SendCommand` was blocked inside a long `Tx` ioctl
- File: `transport/i2c/i2c.go:Transport` struct, `Close()`, `SendCommand()`

**Decision: Send abort ACK from Close() and New() to manage PN532 state across process boundaries**
- Problem: When a process is killed mid-transaction (e.g., during `InListPassiveTarget`), the PN532 is left waiting for the command to complete. The next process opener finds a stuck device.
- Solution: (1) `Close()` sends an ACK frame before closing the bus fd — per datasheet §6.2.1.3, a host-sent ACK aborts any in-flight command and returns the device to idle. (2) `New()` sends an abort ACK on startup (best-effort, errors ignored) to clear stuck state from a previous session.
- Alternative considered: Rely on bus power cycle or hardware reset — rejected because the breakout board doesn't expose RSTPDN, and power cycle is not automatable
- Trade-off: The abort ACK in `New()` may fail silently if the device is truly unresponsive; the `Reconnect()` path is the escalation for that case
- Files: `transport/i2c/i2c.go:Close()`, `New()`, `sendAbortACK()`

**Decision: Separate "not ready" from "corrupted frame" in receiveFrameAttempt return values**
- Problem: `receiveFrameAttempt` returned `shouldRetry=true` for both "device not ready" and "corrupted frame". The caller (`receiveFrame`) sent a NACK in both cases. Sending NACK to a device that hasn't transmitted anything is a protocol violation that crashed the I2C bus.
- Solution: Return `(nil, false, nil)` for "not ready" (caller polls again without NACK) and `(nil, true, nil)` for "corrupted frame" (caller sends NACK and asks for retransmission). The semantics are documented in the function's return-value contract.
- Alternative considered: Send NACK always — rejected; confirmed on hardware to crash the I2C bus ("sysfs-i2c: remote I/O error") for any command taking longer than the checkReady backoff window
- File: `transport/i2c/i2c.go:receiveFrameAttempt()`

## Development Process

**Testing approach:**
- Unit tests: custom logic only (state machines, config validation, error handling)
- Integration tests: `--tags=integration`, uses `VirtualPN532` wire simulator
- Deadlock detection: `--tags=deadlock`, swaps in `go-deadlock` mutexes
- Fuzz tests: frame protocol validation in `internal/frame/`

**Deployment:**
- Library: published as Go module at `github.com/ZaparooProject/go-pn532`
