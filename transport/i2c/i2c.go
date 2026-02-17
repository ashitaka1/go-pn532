// Copyright 2026 The Zaparoo Project Contributors.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package i2c provides I2C transport implementation for PN532
package i2c

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
	"github.com/ZaparooProject/go-pn532/internal/frame"
	"periph.io/x/conn/v3/i2c"
	"periph.io/x/conn/v3/i2c/i2creg"
	"periph.io/x/conn/v3/physic"
	"periph.io/x/host/v3"
)

const (
	// PN532 7-bit I2C address (datasheet says 0x48, which is the 8-bit write
	// address including the R/W bit; periph.io and the Linux kernel expect the
	// 7-bit form: 0x48 >> 1 = 0x24).
	pn532Addr = 0x24

	// Protocol constants.
	hostToPn532 = 0xD4
	pn532ToHost = 0xD5
	pn532Ready  = 0x01

	// Max clock frequency (400 kHz).
	maxClockFreq = 400 * physic.KiloHertz
)

var (
	ackFrame  = []byte{0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00}
	nackFrame = []byte{0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00}
)

// Transport implements the pn532.Transport interface for I2C communication
type Transport struct {
	dev          *i2c.Dev
	bus          i2c.BusCloser    // Held so Close() can release the OS file descriptor
	currentTrace *pn532.TraceBuffer // Trace buffer for current command (error-only)
	busName      string
	timeout      time.Duration
}

// traceTX records a TX operation if trace buffer is active
func (t *Transport) traceTX(data []byte, note string) {
	if t.currentTrace != nil {
		t.currentTrace.RecordTX(data, note)
	}
}

// traceRX records an RX operation if trace buffer is active
func (t *Transport) traceRX(data []byte, note string) {
	if t.currentTrace != nil {
		t.currentTrace.RecordRX(data, note)
	}
}

// traceTimeout records a timeout if trace buffer is active
func (t *Transport) traceTimeout(note string) {
	if t.currentTrace != nil {
		t.currentTrace.RecordTimeout(note)
	}
}

// parseI2CPath extracts the bus path from a composite detection path.
// Accepts "/dev/i2c-1:0x24" (detection format) or "/dev/i2c-1" (bare bus).
func parseI2CPath(path string) string {
	bus, _, _ := strings.Cut(path, ":")
	return bus
}

// New creates a new I2C transport
func New(busName string) (*Transport, error) {
	// Initialize host
	if _, err := host.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize periph host: %w", err)
	}

	// Open I2C bus (strip address suffix from detection paths)
	bus, err := i2creg.Open(parseI2CPath(busName))
	if err != nil {
		return nil, fmt.Errorf("failed to open I2C bus %s: %w", busName, err)
	}

	// Create device with PN532 7-bit address and max frequency
	dev := &i2c.Dev{Addr: pn532Addr, Bus: bus}

	// Set maximum frequency
	_ = bus.SetSpeed(maxClockFreq) // Ignore error, continue with default speed

	transport := &Transport{
		dev:     dev,
		bus:     bus,
		busName: busName,
		// Match UART's unified timeout - originally 50ms but increased to 100ms
		// for better I2C bus compatibility across different hardware
		timeout: 100 * time.Millisecond,
	}

	return transport, nil
}

// sleepCtx performs a context-aware sleep. Returns ctx.Err() if context is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isTransientACKError returns true if the error is a transient ACK-level error worth retrying.
func isTransientACKError(err error) bool {
	return errors.Is(err, pn532.ErrNoACK) ||
		errors.Is(err, pn532.ErrNACKReceived) ||
		errors.Is(err, pn532.ErrFrameCorrupted)
}

// sendWithACKRetry sends a frame and waits for ACK, retrying on transient errors.
// Returns nil on success, or the last error if all retries are exhausted.
func (t *Transport) sendWithACKRetry(ctx context.Context, cmd byte, args []byte) error {
	delays := []time.Duration{pn532.TransportACKDelay1, pn532.TransportACKDelay2, pn532.TransportACKDelay3}

	var lastErr error
	for attempt := range pn532.TransportACKRetries {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := t.sendFrame(cmd, args); err != nil {
			return err
		}

		err := t.waitAck(ctx)
		if err == nil {
			return nil // ACK received successfully
		}
		if !isTransientACKError(err) {
			return err // Non-transient error, don't retry
		}
		lastErr = err

		// Wait before retry (except on last attempt)
		if attempt < pn532.TransportACKRetries-1 {
			if err := sleepCtx(ctx, delays[attempt]); err != nil {
				return err
			}
		}
	}

	return fmt.Errorf("send command failed after %d ACK retries: %w", pn532.TransportACKRetries, lastErr)
}

// SendCommand sends a command to the PN532 and waits for response.
// Includes automatic retry on ACK failures to prevent device lockup.
// Context is checked at key points during the operation to allow cancellation.
//
//nolint:wrapcheck // WrapError intentionally wraps errors with trace data
func (t *Transport) SendCommand(ctx context.Context, cmd byte, args []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Create trace buffer for this command (only used on error)
	t.currentTrace = pn532.NewTraceBuffer("I2C", t.busName, 16)
	defer func() { t.currentTrace = nil }()

	if err := t.sendWithACKRetry(ctx, cmd, args); err != nil {
		return nil, t.currentTrace.WrapError(err)
	}

	// Small delay for PN532 to process command
	if err := sleepCtx(ctx, 6*time.Millisecond); err != nil {
		return nil, err
	}

	resp, err := t.receiveFrame(ctx)
	if err != nil {
		return nil, t.currentTrace.WrapError(err)
	}
	return resp, nil
}

// SetTimeout sets the read timeout for the transport
func (t *Transport) SetTimeout(timeout time.Duration) error {
	t.timeout = timeout
	return nil
}

// Close closes the transport connection and releases the I2C bus file descriptor.
// Must be called when the transport is no longer needed to prevent file descriptor
// leaks that can corrupt the I2C bus on rapid destroy/recreate cycles.
func (t *Transport) Close() error {
	if t.bus != nil {
		if err := t.bus.Close(); err != nil {
			return fmt.Errorf("failed to close I2C bus: %w", err)
		}
		t.bus = nil
		t.dev = nil // IsConnected() returns false after Close
	}
	return nil
}

// IsConnected returns true if the transport is connected
func (t *Transport) IsConnected() bool {
	return t.dev != nil
}

// Type returns the transport type
func (*Transport) Type() pn532.TransportType {
	return pn532.TransportI2C
}

// checkReady checks if the PN532 is ready by reading the ready status.
// Uses context-aware sleeps so cancellation stops the retry loop promptly,
// preventing in-flight I2C reads from overlapping with a new transport instance.
func (t *Transport) checkReady(ctx context.Context) error {
	baseDelay := time.Millisecond

	var lastErr error
	for attempt := range pn532.TransportI2CFrameRetries {
		if err := ctx.Err(); err != nil {
			return err
		}

		// Use buffer pool for ready status check - small optimization
		ready := frame.GetSmallBuffer(1)

		err := t.dev.Tx(nil, ready)
		if err != nil {
			frame.PutBuffer(ready)
			lastErr = fmt.Errorf("I2C ready check failed: %w", err)
			// Exponential backoff: 1ms, 2ms, 4ms, 8ms, 16ms
			if attempt < pn532.TransportI2CFrameRetries-1 {
				if sleepErr := sleepCtx(ctx, baseDelay*time.Duration(1<<attempt)); sleepErr != nil {
					return sleepErr
				}
				continue
			}
			return lastErr
		}

		if ready[0] == pn532Ready {
			frame.PutBuffer(ready)
			return nil
		}

		frame.PutBuffer(ready)
		// Device not ready yet, wait with context-aware backoff
		if attempt < pn532.TransportI2CFrameRetries-1 {
			if sleepErr := sleepCtx(ctx, baseDelay*time.Duration(1<<attempt)); sleepErr != nil {
				return sleepErr
			}
		}
	}

	return pn532.NewTransportNotReadyError("checkReady", t.busName)
}

// readI2C reads from the PN532, stripping the status byte that the hardware
// prepends to every I2C read transaction (see datasheet section 6.2.4).
func (t *Transport) readI2C(buf []byte) error {
	tmpSize := 1 + len(buf)
	tmpBuf := frame.GetSmallBuffer(tmpSize)
	defer frame.PutBuffer(tmpBuf)

	if err := t.dev.Tx(nil, tmpBuf); err != nil {
		return fmt.Errorf("I2C read failed: %w", err)
	}

	if tmpBuf[0] != pn532Ready {
		return pn532.NewTransportNotReadyError("readI2C", t.busName)
	}

	copy(buf, tmpBuf[1:])
	return nil
}

// sendFrame sends a frame to the PN532 via I2C
func (t *Transport) sendFrame(cmd byte, args []byte) error {
	// Use buffer pool for frame construction - major optimization
	dataLen := 2 + len(args) // hostToPn532 + cmd + args
	if dataLen > 255 {
		// TODO: extended frames are not implemented
		return pn532.NewDataTooLargeError("sendFrame", t.busName)
	}

	// Calculate total frame size: preamble(3) + len+lcs(2) + data + dcs+postamble(2)
	totalFrameSize := 3 + 2 + dataLen + 2

	frm := frame.GetBuffer(totalFrameSize)
	defer frame.PutBuffer(frm)

	// Build frame manually for better performance
	frm[0] = 0x00 // preamble
	frm[1] = 0x00
	frm[2] = 0xFF               // start code
	frm[3] = byte(dataLen)      // length
	frm[4] = ^byte(dataLen) + 1 // length checksum

	// Add data: TFI + command + args
	frm[5] = hostToPn532
	frm[6] = cmd
	copy(frm[7:7+len(args)], args)

	// Calculate and add data checksum
	checksum := hostToPn532 + cmd
	for _, b := range args {
		checksum += b
	}

	frm[7+len(args)] = ^checksum + 1 // data checksum
	frm[8+len(args)] = 0x00          // postamble

	// Send frame via I2C (slice to exact size)
	t.traceTX(frm[:totalFrameSize], fmt.Sprintf("Cmd 0x%02X", cmd))
	if err := t.dev.Tx(frm[:totalFrameSize], nil); err != nil {
		return fmt.Errorf("failed to send I2C frame: %w", err)
	}

	return nil
}

// waitAck waits for an ACK frame from the PN532
func (t *Transport) waitAck(ctx context.Context) error {
	deadline := time.Now().Add(t.timeout)

	// Use buffer pool for ACK frame reading
	ackBuf := frame.GetSmallBuffer(6)
	defer frame.PutBuffer(ackBuf)

	for time.Now().Before(deadline) {
		// Check context
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if PN532 is ready
		if err := t.checkReady(ctx); err != nil {
			if err := sleepCtx(ctx, time.Millisecond); err != nil {
				return err
			}
			continue
		}

		// Read ACK frame, stripping I2C status byte
		if err := t.readI2C(ackBuf); err != nil {
			return fmt.Errorf("I2C ACK read failed: %w", err)
		}

		if bytes.Equal(ackBuf, ackFrame) {
			t.traceRX(ackFrame, "ACK")
			return nil
		}

		if err := sleepCtx(ctx, time.Millisecond); err != nil {
			return err
		}
	}

	t.traceTimeout("No ACK received")
	return pn532.NewNoACKError("waitAck", t.busName)
}

// sendAck sends an ACK frame to the PN532
func (t *Transport) sendAck() error {
	t.traceTX(ackFrame, "ACK")
	if err := t.dev.Tx(ackFrame, nil); err != nil {
		return fmt.Errorf("failed to send ACK: %w", err)
	}
	return nil
}

// sendNack sends a NACK frame to the PN532
func (t *Transport) sendNack() error {
	t.traceTX(nackFrame, "NACK")
	if err := t.dev.Tx(nackFrame, nil); err != nil {
		return fmt.Errorf("failed to send NACK: %w", err)
	}
	return nil
}

// receiveFrame reads a response frame from the PN532
func (t *Transport) receiveFrame(ctx context.Context) ([]byte, error) {
	deadline := time.Now().Add(t.timeout)
	const maxTries = 3

	for range maxTries {
		// Check context
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return nil, &pn532.TransportError{
				Op: "receiveFrame", Port: t.busName,
				Err:       pn532.ErrTransportTimeout,
				Type:      pn532.ErrorTypeTimeout,
				Retryable: true,
			}
		}

		data, shouldRetry, err := t.receiveFrameAttempt(ctx)
		if err != nil {
			return nil, err
		}
		if !shouldRetry {
			return data, nil
		}

		// Send NACK and retry
		if err := t.sendNack(); err != nil {
			return nil, err
		}
	}

	// All retries exhausted
	return nil, &pn532.TransportError{
		Op: "receiveFrame", Port: t.busName,
		Err:       pn532.ErrCommunicationFailed,
		Type:      pn532.ErrorTypeTransient,
		Retryable: true,
	}
}

// receiveFrameAttempt performs a single frame receive attempt
func (t *Transport) receiveFrameAttempt(ctx context.Context) (data []byte, shouldRetry bool, err error) {
	// Check context
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}

	// Check if PN532 is ready
	if readyErr := t.checkReady(ctx); readyErr != nil {
		if sleepErr := sleepCtx(ctx, time.Millisecond); sleepErr != nil {
			return nil, false, sleepErr
		}
		// Device not ready, retry without error
		return nil, true, nil
	}

	buf, actualLen, err := t.readFrameData()
	if err != nil {
		return nil, false, err
	}
	defer frame.PutBuffer(buf) // Ensure buffer is returned to pool

	// Trace the raw response frame
	if actualLen > 0 {
		t.traceRX(buf[:actualLen], "Response")
	}

	off, err := t.findI2CFrameStart(buf, actualLen)
	if err != nil {
		return nil, false, err
	}

	frameLen, shouldRetry, err := t.validateI2CFrameLength(buf, off, actualLen)
	if err != nil || shouldRetry {
		return nil, shouldRetry, err
	}

	shouldRetry, err = t.validateI2CFrameChecksum(buf, off, frameLen)
	if err != nil || shouldRetry {
		return nil, shouldRetry, err
	}

	return t.extractI2CFrameData(buf, off, frameLen)
}

// readFrameData reads a complete PN532 response frame in a single I2C transaction.
//
// Each call to readI2C() is a separate I2C transaction (START → addr+R → bytes → STOP).
// On the PN532, every new read transaction restarts from byte 0 of its output buffer —
// there is no "continue from where you left off" across transactions. A two-transaction
// approach (read header, then read remaining bytes) would therefore re-read from the
// beginning on the second call, producing corrupted frame data.
//
// By reading the maximum possible frame size (frame.MaxFrameDataLength + framing overhead)
// in one transaction, we get the complete frame correctly and avoid a second transaction.
func (t *Transport) readFrameData() (buf []byte, actualLen int, err error) {
	// frame.MaxFrameDataLength = 263; add framing bytes (preamble, start code,
	// LEN, LCS, DCS, postamble) for the largest buffer we may need.
	const maxBufSize = frame.MaxFrameDataLength + 8

	buf = frame.GetBuffer(maxBufSize)

	if err := t.readI2C(buf); err != nil {
		frame.PutBuffer(buf)
		return nil, 0, fmt.Errorf("I2C frame read failed: %w", err)
	}

	// Locate frame start (0x00 0xFF) to determine actual frame length.
	frameStart := -1
	for i := range maxBufSize - 1 {
		if buf[i] == 0x00 && buf[i+1] == 0xFF {
			frameStart = i + 2 // index of LEN byte
			break
		}
	}

	if frameStart == -1 || frameStart+1 >= maxBufSize {
		frame.PutBuffer(buf)
		return nil, 0, &pn532.TransportError{
			Op:        "readFrameData",
			Port:      t.busName,
			Err:       pn532.ErrFrameCorrupted,
			Type:      pn532.ErrorTypeTransient,
			Retryable: true,
		}
	}

	frameLen := int(buf[frameStart])
	lcs := int(buf[frameStart+1])

	if (frameLen+lcs)&0xFF != 0 {
		frame.PutBuffer(buf)
		return nil, 0, &pn532.TransportError{
			Op:        "readFrameData",
			Port:      t.busName,
			Err:       pn532.ErrFrameCorrupted,
			Type:      pn532.ErrorTypeTransient,
			Retryable: true,
		}
	}

	// Total: bytes up to and including LCS, plus LEN data bytes, plus DCS + postamble
	totalFrameSize := frameStart + 2 + frameLen + 2
	if totalFrameSize > maxBufSize {
		frame.PutBuffer(buf)
		return nil, 0, &pn532.TransportError{
			Op:        "readFrameData",
			Port:      t.busName,
			Err:       pn532.ErrFrameCorrupted,
			Type:      pn532.ErrorTypeTransient,
			Retryable: true,
		}
	}

	return buf, totalFrameSize, nil
}

// findI2CFrameStart locates the frame start marker (0x00 0xFF)
// CRITICAL FIX: Now accepts actualLen to only search through actual received data
// This prevents false positives from searching uninitialized buffer space
func (t *Transport) findI2CFrameStart(buf []byte, actualLen int) (int, error) {
	// Only search through actual data received, not entire buffer
	searchLen := actualLen
	if searchLen > len(buf) {
		searchLen = len(buf)
	}

	for off := range searchLen - 1 {
		if buf[off] == 0x00 && buf[off+1] == 0xFF {
			return off + 2, nil // Skip to length byte
		}
	}

	return 0, &pn532.TransportError{
		Op: "receiveFrame", Port: t.busName,
		Err:       pn532.ErrFrameCorrupted,
		Type:      pn532.ErrorTypeTransient,
		Retryable: true,
	}
}

// validateI2CFrameLength validates the frame length and its checksum
// CRITICAL FIX: Now uses actualLen instead of len(buf) to avoid reading beyond actual data
func (t *Transport) validateI2CFrameLength(buf []byte, off, actualLen int) (frameLen int, shouldRetry bool, err error) {
	frameLen, shouldRetry, err = frame.ValidateFrameLength(buf, off-1, actualLen, "receiveFrame", t.busName)
	if err != nil {
		return frameLen, shouldRetry, fmt.Errorf("I2C frame length validation failed: %w", err)
	}
	return frameLen, shouldRetry, nil
}

// validateI2CFrameChecksum validates the frame data checksum
func (t *Transport) validateI2CFrameChecksum(buf []byte, off, frameLen int) (bool, error) {
	if off+2+frameLen+1 > len(buf) {
		return false, pn532.NewFrameCorruptedError("receiveFrame", t.busName)
	}

	start := off + 2
	end := off + 2 + frameLen + 1
	return frame.ValidateFrameChecksum(buf, start, end), nil
}

// extractI2CFrameData extracts and validates the final frame data
func (t *Transport) extractI2CFrameData(buf []byte, off, frameLen int) (data []byte, shouldRetry bool, err error) {
	// Extract frame data using shared utility
	data, shouldRetry, err = frame.ExtractFrameData(buf, off, frameLen, pn532ToHost)
	if err != nil {
		return data, shouldRetry, fmt.Errorf("I2C frame data extraction failed: %w", err)
	}
	if shouldRetry {
		return data, shouldRetry, nil
	}

	// I2C-specific: Send ACK for successful frame
	if err := t.sendAck(); err != nil {
		return nil, false, err
	}

	return data, false, nil
}

// Ensure Transport implements pn532.Transport
var _ pn532.Transport = (*Transport)(nil)
