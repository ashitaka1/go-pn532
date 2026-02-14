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
2. ⏳ Bug fixes — address known issues (see Known Bugs below)

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

Identified via code review. Ordered by severity.

### Critical

#### Bug 0: I2C transport uses 8-bit address with periph.io (expects 7-bit)
- **File:** `transport/i2c/i2c.go:34-37, 96`
- **Issue:** Constants `pn532WriteAddr = 0x48` and `pn532ReadAddr = 0x49` are 8-bit I2C addresses. `periph.io`'s `i2c.Dev.Addr` field expects a 7-bit address (passed directly to Linux `I2C_SLAVE` ioctl). The correct 7-bit address for PN532 is `0x24` (`0x48 >> 1`). With `Addr: 0x48`, the kernel puts `0x90`/`0x91` on the wire — an address nothing responds to.
- **Impact:** I2C transport is completely non-functional. All commands fail with `sysfs-i2c: remote I/O error` (NACK). Confirmed on Raspberry Pi 5 with PN532 on `/dev/i2c-1` — Python (using `0x24`) communicates fine; Go library (using `0x48`) gets NACK on every frame.
- **Fix:** Replace both constants with `pn532Addr = 0x24`. Remove unused `pn532ReadAddr` — periph.io handles the R/W bit automatically. Update line 96: `dev := &i2c.Dev{Addr: pn532Addr, Bus: bus}`.

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

## Development Process

**Testing approach:**
- Unit tests: custom logic only (state machines, config validation, error handling)
- Integration tests: `--tags=integration`, uses `VirtualPN532` wire simulator
- Deadlock detection: `--tags=deadlock`, swaps in `go-deadlock` mutexes
- Fuzz tests: frame protocol validation in `internal/frame/`

**Deployment:**
- Library: published as Go module at `github.com/ZaparooProject/go-pn532`
