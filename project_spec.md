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
2. ⏳ Bug fixes — I2C transport fixes complete (bugs 0, 0a, bus crash, correctness), remaining bugs documented below

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
- **Impact:** May be contributing to command failures observed on hardware. On Raspberry Pi 5 with PN532 v1.6 over I2C, GetFirmwareVersion works reliably but diagnostic commands and InListPassiveTarget fail with "sysfs-i2c: connection timed out" errors. This suggests the extra transaction overhead may be more impactful than initially assessed.
- **Status:** Priority elevated due to hardware testing results. May be blocking reliable tag detection on I2C.
- **Fix:** Combine ready check and data read into a single `Tx()` call per read path. Remove `checkReady()` from frame read paths.

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

Series of commits addressing I2C transport correctness and reliability:

**Commit 7817b06 — Prevent bus crash on rapid destroy/recreate cycles:**
- Fixed file descriptor leaks in `transport/i2c/i2c.go:Close()` — added `InRelease()` to properly release I2C bus, clearing kernel driver state
- Made `sleepWithContext()` context-aware to prevent sleep bleeding into next instance lifecycle
- Changed `readFrameData()` to use single-transaction reads where possible (avoids I2C stop-start cycles mid-frame)
- Added `InRelease()` call during `Reconnect()` to ensure clean recovery

**Commit f955d16 — Overhaul transport correctness:**
- Fixed timeout overshoot in `transport/i2c/i2c.go` — transport was sleeping for `timeout + retryInterval` instead of `timeout`, causing operations to block longer than configured
- Added NACK detection in `readI2C()` — checks `conn.Tx()` return value for I2C NACK errors, classifies as `ErrDeviceUnresponsive` (retryable)
- Fixed LCS retry semantics in `SendCommand()` — LCS errors now trigger immediate retry (up to 3 attempts) before returning error to caller, matching UART transport behavior
- Implemented `Reconnect()` for `Reconnecter` interface — calls `Close()` (with `InRelease()`) and re-opens I2C bus, enabling recovery from PN532 firmware lockup

**Commit 4c56709 — Regression test coverage:**
- Added `transport/i2c/i2c_wire_test.go:TestLCSFrameRetry` — validates LCS error triggers internal retry (3 attempts)
- Added `TestNACKDetection` — validates NACK from I2C bus classified as `ErrDeviceUnresponsive`
- Added `TestReconnecterInterface` — validates Reconnect() closes/reopens bus and clears state

**Hardware testing status (PN532 v1.6, Raspberry Pi 5, /dev/i2c-1):**
- GetFirmwareVersion: reliable
- Diagnostic commands and InListPassiveTarget: failing with "sysfs-i2c: connection timed out"
- Root cause suspected: Bug 10 (two-transaction read pattern) may be triggering timing issues or exceeding PN532 tolerance for I2C protocol deviations

**Testing methodology:**
- Wire-level regression tests using `MockI2CBus` in `transport/i2c/i2c_wire_test.go` validate LCS retry, NACK detection, and Reconnect() behavior
- Mock updated to prepend I2C status byte (0x01) to multi-byte reads, matching real hardware behavior
- Integration test validation script `scripts/i2c-validate.sh` performs rapid create/destroy cycles to verify bus stability

## Milestone Architecture Decisions

### I2C Transport Correctness (Milestone 2, Feb 2026)

**Decision: Add InRelease() to Close() to prevent bus crash on rapid cycles**
- Problem: Raspberry Pi I2C bus crashed on rapid device destroy/recreate cycles
- Root cause: periph.io `Conn.Tx()` retains kernel driver state across Close(), causing stale file descriptors or locked I2C addresses
- Solution: Call `InRelease()` after closing device file descriptor, clearing kernel driver state
- Alternative considered: Reference counting at application level — rejected because library cannot control caller lifecycle patterns
- File: `transport/i2c/i2c.go:Close()`

**Decision: Single-transaction reads for frame data where possible**
- Problem: Multiple I2C transactions mid-frame increase bus overhead and potential for timing issues
- Solution: `readFrameData()` reads full frame in single `Tx()` call when size known upfront
- Alternative considered: Keep separate status check + data read — rejected after hardware testing showed potential timeout issues
- Trade-off: Slightly larger initial read buffer allocation, but eliminates I2C stop-start mid-frame
- File: `transport/i2c/i2c.go:readFrameData()`

**Decision: Implement Reconnect() with full bus release/reopen**
- Problem: PN532 firmware can enter unresponsive state requiring power cycle
- Solution: `Reconnect()` calls `Close()` (with `InRelease()`) then reopens I2C bus, clearing both kernel and firmware state
- Alternative considered: Software reset command — rejected because PN532 may not respond to commands when locked up
- Limitation: Cannot truly power-cycle PN532 without hardware control; relies on I2C bus release triggering firmware reset
- File: `transport/i2c/i2c.go:Reconnect()`

**Decision: Classify I2C NACK as retryable ErrDeviceUnresponsive**
- Problem: I2C NACK errors indicate PN532 did not acknowledge transaction, but may be transient
- Solution: Check `conn.Tx()` error for NACK indicator, wrap as `ErrDeviceUnresponsive` (retryable)
- Alternative considered: Treat NACK as fatal — rejected because hardware testing showed transient NACKs during normal operation
- File: `transport/i2c/i2c.go:readI2C()`

**Decision: LCS errors trigger immediate internal retry (up to 3 attempts)**
- Problem: LCS checksum errors on response frames indicate corruption, but were immediately returned to caller
- Solution: `SendCommand()` retries LCS errors up to 3 times before returning error, matching UART transport behavior
- Alternative considered: Let caller handle LCS retry — rejected for consistency across transports and to reduce caller complexity
- File: `transport/i2c/i2c.go:SendCommand()`

## Development Process

**Testing approach:**
- Unit tests: custom logic only (state machines, config validation, error handling)
- Integration tests: `--tags=integration`, uses `VirtualPN532` wire simulator
- Deadlock detection: `--tags=deadlock`, swaps in `go-deadlock` mutexes
- Fuzz tests: frame protocol validation in `internal/frame/`

**Deployment:**
- Library: published as Go module at `github.com/ZaparooProject/go-pn532`
