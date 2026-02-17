# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `Reconnect()` method to I2C transport implementing `pn532.Reconnecter` interface for hardware-fault recovery
- Add regression tests for I2C LCS retry behavior, NACK detection, and Reconnecter interface

### Fixed

- Correct I2C address from 8-bit (0x48) to 7-bit (0x24) for periph.io and Linux kernel compatibility
- Strip I2C status byte (0x01) prepended by PN532 to read transactions, fixing ACK frame comparison failures and frame data corruption
- Prevent I2C bus crash on rapid destroy/recreate cycles by properly closing file descriptors and ensuring context-aware cancellation
- Fix I2C transport frame reading for responses larger than 32 bytes by reading full frame in single transaction instead of split reads
- Overhaul I2C transport correctness: fix timeout overshoot in waitAck/receiveFrame, enable LCS-failure retry path, add immediate NACK detection
- Release PN532 target selection before closing transport to prevent stale data on next session initialization
