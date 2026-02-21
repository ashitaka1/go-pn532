# go-pn532

Go library for [NXP PN532](https://www.nxp.com/products/rfid-nfc/nfc-hf/nfc-readers/pn532-c1-nfc-controller:PN5321A3HN) NFC reader/writer modules. Supports UART, I2C, and SPI transports.

The PN532 is a popular NFC controller found in many hobbyist modules (like the Adafruit PN532 breakout). It can detect and communicate with NFC tags including NTAG213/215/216, MIFARE Classic 1K, and FeliCa.

## What this library does

- Connects to PN532 modules over UART, I2C, or SPI
- Detects NFC tags and identifies their type (NTAG, MIFARE Classic, FeliCa)
- Reads and writes NDEF messages (text, URIs, smart posters)
- Provides a polling session system for continuous tag monitoring with callbacks
- Handles sleep/wake recovery, RF field management, and device reconnection
- Auto-detects connected PN532 devices

## Install

```bash
go get github.com/ZaparooProject/go-pn532
```

Requires Go 1.24+.

## Quick Start

### Connect to a device

```go
package main

import (
    "context"
    "fmt"
    "log"

    pn532 "github.com/ZaparooProject/go-pn532"
    "github.com/ZaparooProject/go-pn532/transport/uart"
)

func main() {
    // Create a UART transport
    transport, err := uart.New("/dev/ttyUSB0")
    if err != nil {
        log.Fatal(err)
    }

    // Create and initialize the device
    device, err := pn532.New(transport)
    if err != nil {
        log.Fatal(err)
    }
    defer device.Close()

    ctx := context.Background()
    if err := device.Init(ctx); err != nil {
        log.Fatal(err)
    }

    // Check firmware
    fw, err := device.GetFirmwareVersion(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("PN532 firmware: %s\n", fw.Version)
}
```

Or use `ConnectDevice` with auto-detection to find the PN532 automatically:

```go
import (
    pn532 "github.com/ZaparooProject/go-pn532"
    // Blank-import detection drivers for the transports you want to scan
    _ "github.com/ZaparooProject/go-pn532/detection/uart"
    _ "github.com/ZaparooProject/go-pn532/detection/i2c"
)

device, err := pn532.ConnectDevice(ctx, "",
    pn532.WithAutoDetection(),
    pn532.WithConnectTimeout(5*time.Second),
)
```

### Detect a tag

```go
tag, err := device.DetectTag(ctx)
if err != nil {
    log.Fatal(err)
}
if tag != nil {
    fmt.Printf("Tag: UID=%s Type=%s\n", tag.UID, tag.Type)
}
```

### Read NDEF data from a tag

Once a tag is detected, create a `Tag` to read its contents:

```go
tag, err := device.DetectTag(ctx)
if err != nil || tag == nil {
    log.Fatal("no tag found")
}

t, err := device.CreateTag(tag)
if err != nil {
    log.Fatal(err)
}

msg, err := t.ReadNDEF(ctx)
if err != nil {
    log.Fatal(err)
}

for _, record := range msg.Records {
    if record.Text != "" {
        fmt.Printf("Text: %s\n", record.Text)
    }
    if record.URI != "" {
        fmt.Printf("URI: %s\n", record.URI)
    }
}
```

### Write NDEF data to a tag

```go
msg := &pn532.NDEFMessage{
    Records: []pn532.NDEFRecord{
        {Type: pn532.NDEFTypeText, Text: "Hello from Go!"},
    },
}

t, err := device.CreateTag(detectedTag)
if err != nil {
    log.Fatal(err)
}

if err := t.WriteNDEF(ctx, msg); err != nil {
    log.Fatal(err)
}
```

## Polling Sessions

For applications that need to continuously monitor for tags (readers, kiosks, access control), use `polling.Session`. It runs a detection loop in a goroutine and calls your functions when tags appear or disappear.

```go
import "github.com/ZaparooProject/go-pn532/polling"

session := polling.NewSession(device, polling.DefaultConfig())

session.SetOnCardDetected(func(ctx context.Context, tag *pn532.DetectedTag) error {
    fmt.Printf("Tag detected: %s (%s)\n", tag.UID, tag.Type)

    t, err := device.CreateTag(tag)
    if err != nil {
        return err
    }
    msg, err := t.ReadNDEF(ctx)
    if err != nil {
        return err
    }
    fmt.Printf("NDEF: %s\n", msg.Records[0].Text)
    return nil
})

session.SetOnCardRemoved(func() {
    fmt.Println("Tag removed")
})

// Start blocks until the context is cancelled
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
go func() { _ = session.Start(ctx) }()
```

### Writing during a polling session

The `Device` is not thread-safe -- polling and writing can't happen at the same time. The session provides methods that pause polling, write, and resume:

```go
// Write to a specific detected tag
err := session.WriteToTag(ctx, ctx, detectedTag, func(ctx context.Context, tag pn532.Tag) error {
    return tag.WriteText(ctx, "Hello!")
})

// Wait for any tag and write to it
err := session.WriteToNextTag(ctx, ctx, 30*time.Second, func(ctx context.Context, tag pn532.Tag) error {
    return tag.WriteNDEF(ctx, message)
})
```

### PauseAndRun

For arbitrary device operations during a polling session (diagnostics, firmware queries, status checks), use `PauseAndRun`. It pauses the polling loop, waits for the current poll cycle to finish, runs your function with exclusive device access, and resumes:

```go
err := session.PauseAndRun(ctx, func(device *pn532.Device) error {
    fw, err := device.GetFirmwareVersion(ctx)
    if err != nil {
        return err
    }
    fmt.Printf("Firmware: %s\n", fw.Version)
    return nil
})
```

`PauseAndRun` returns `polling.ErrPauseAckTimeout` if the polling loop doesn't acknowledge the pause. This typically indicates a firmware lockup, not a normal condition.

### Polling configuration

```go
config := &polling.Config{
    PollInterval:           250 * time.Millisecond, // Host-side poll spacing
    CardRemovalTimeout:     600 * time.Millisecond, // How long before a missing card is "removed"
    HardwareTimeoutRetries: 0x20,                   // PN532 firmware retries per poll (~150ms each)
    SleepRecovery:          polling.DefaultSleepRecoveryConfig(),
}
session := polling.NewSession(device, config)
```

## Transports

The PN532 supports three physical interfaces. Each transport is in its own sub-package:

### UART

```go
import "github.com/ZaparooProject/go-pn532/transport/uart"

transport, err := uart.New("/dev/ttyUSB0")             // Linux
transport, err := uart.New("/dev/tty.usbserial-1420")  // macOS
transport, err := uart.New("COM3")                     // Windows
```

115200 baud, 8N1. Most PN532 breakout boards default to UART mode. Requires a USB-to-serial adapter or direct UART connection.

### I2C

```go
import "github.com/ZaparooProject/go-pn532/transport/i2c"

transport, err := i2c.New("/dev/i2c-1")
```

PN532 I2C address is `0x24`. Requires the I2C bus to be enabled on your platform (e.g., `raspi-config` on Raspberry Pi). Uses [periph.io](https://periph.io/) for bus access.

Note: I2C poll cycles block for several seconds while the PN532 retries tag detection internally. This is normal behavior.

### SPI

```go
import "github.com/ZaparooProject/go-pn532/transport/spi"

transport, err := spi.New("/dev/spidev0.0")
```

1 MHz, SPI Mode 0. Uses [periph.io](https://periph.io/) for bus access.

## Auto-Detection

The `detection` package scans for connected PN532 devices across transports. Import the detection drivers for the transports you want to scan:

```go
import (
    "github.com/ZaparooProject/go-pn532/detection"
    _ "github.com/ZaparooProject/go-pn532/detection/uart"
    _ "github.com/ZaparooProject/go-pn532/detection/i2c"
    _ "github.com/ZaparooProject/go-pn532/detection/spi"
)

devices, err := detection.DetectAll(ctx, nil) // nil = default options
for _, dev := range devices {
    fmt.Printf("Found %s device at %s (confidence: %s)\n",
        dev.Transport, dev.Path, dev.Confidence)
}
```

## Supported Tags

| Type | Constant | Notes |
|------|----------|-------|
| NTAG213/215/216 | `pn532.TagTypeNTAG` | Most common NFC tags. 144/504/888 bytes user memory. |
| MIFARE Classic 1K | `pn532.TagTypeMIFARE` | 16 sectors, 1KB. Requires sector authentication. |
| FeliCa | `pn532.TagTypeFeliCa` | Sony standard, common in Japan and transit systems. |

The library identifies tag types from ATQ/SAK bytes during detection. Use `device.CreateTag(detectedTag)` to get a type-specific `Tag` with the appropriate read/write behavior.

## Error Handling

Errors are classified to help you decide how to respond:

```go
if pn532.IsFatal(err) {
    // Device is gone (unplugged, hardware fault). Reconnect needed.
}
if pn532.IsRetryable(err) {
    // Transient error (RF noise, timing). Safe to retry.
}
if pn532.IsPN532AuthenticationError(err) {
    // MIFARE auth failed (wrong key, wrong sector).
}
```

Key sentinel errors (use `errors.Is`):

- `pn532.ErrNoTagDetected` -- no tag in range
- `pn532.ErrNoACK` -- PN532 firmware lockup (the library attempts hard reset automatically)
- `pn532.ErrTagAuthFailed` -- MIFARE authentication failed
- `pn532.ErrTransportClosed` -- transport was closed
- `pn532.ErrDeviceNotFound` -- device not found during detection
- `polling.ErrPauseAckTimeout` -- polling loop didn't acknowledge pause request

## Diagnostics

The PN532 has built-in self-test capabilities:

```go
// Firmware version
fw, _ := device.GetFirmwareVersion(ctx)
fmt.Printf("v%s ISO14443A=%v\n", fw.Version, fw.SupportIso14443a)

// Self-tests (ROM, RAM, antenna)
result, _ := device.Diagnose(ctx, pn532.DiagnoseROMTest, nil)
fmt.Printf("ROM: %v\n", result.Success)

// General status (RF field, active targets)
status, _ := device.GetGeneralStatus(ctx)
fmt.Printf("RF field active: %v\n", status.FieldPresent)
```

## Example Binary

The `cmd/reader` binary demonstrates the full API:

```bash
go run ./cmd/reader                          # Auto-detect and read tags
go run ./cmd/reader -device /dev/ttyUSB0     # Specify device path
go run ./cmd/reader -write "Hello NFC!"      # Write text to next tag
go run ./cmd/reader -debug                   # Enable debug output
```

## Thread Safety

`Device` is **not** thread-safe. If you need concurrent access:

- Use `polling.Session` -- it manages device access internally
- Use `session.PauseAndRun()` or `session.WriteToTag()` for safe device access during polling
- Or protect the `Device` with your own mutex if not using polling sessions

## License

Apache 2.0. See [LICENSE](LICENSE).
