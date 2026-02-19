# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `PauseAndRun(ctx, fn)` method on `polling.Session` for safe synchronous device access during an active polling loop
- Add `ErrPauseAckTimeout` sentinel error for callers to detect genuine pause timeout vs. other errors
- Add `loopRunning` atomic flag to `polling.Session` to distinguish an idle device from a stuck polling loop
- Add `Reconnect()` method to I2C transport implementing `pn532.Reconnecter` interface for hardware-fault recovery
- Add regression tests for I2C LCS retry behavior, NACK detection, and Reconnecter interface
- Add dual-mutex pattern (`closeMu` + `mu`) to I2C transport for safe concurrent `Close`/`SendCommand` operation
- Add defensive nil guards on all internal I2C transport methods that access the bus device
- Add lifecycle regression tests: `CloseDuringSendCommand_NoNilDeref` and `Close_SendsAbortACK`

### Fixed

- Fix `pauseWithAck` to return `ErrPauseAckTimeout` on genuine timeout instead of silently succeeding
- Fix `handleContextAndPause` to send the pause ack signal (was missing, causing spurious timeouts for callers)
- Fix pre-existing data race in `TestSession_WriteToTagPausesBehavior`
- Fix I2C transport nil pointer dereference when `Close()` is called concurrently with an active `SendCommand`
- Fix I2C transport `Close()` to send abort ACK to PN532 before closing the bus, preventing stuck device state on next session
- Fix I2C transport `New()` to send abort ACK on connect, recovering a PN532 left stuck by a previous process
- Correct I2C address from 8-bit (0x48) to 7-bit (0x24) for periph.io and Linux kernel compatibility
- Strip I2C status byte (0x01) prepended by PN532 to read transactions, fixing ACK frame comparison failures and frame data corruption
- Prevent I2C bus crash on rapid destroy/recreate cycles by properly closing file descriptors and ensuring context-aware cancellation
- Fix I2C transport frame reading for responses larger than 32 bytes by reading full frame in single transaction instead of split reads
- Overhaul I2C transport correctness: fix timeout overshoot in waitAck/receiveFrame, enable LCS-failure retry path, add immediate NACK detection
- Release PN532 target selection before closing transport to prevent stale data on next session initialization
