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
	"github.com/ZaparooProject/go-pn532/internal/syncutil"
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
	bus          i2c.BusCloser      // Held so Close() can release the OS file descriptor
	currentTrace *pn532.TraceBuffer // Trace buffer for current command (error-only)
	mu           syncutil.Mutex     // Serializes SendCommand, SetTimeout, IsConnected, Reconnect
	closeMu      syncutil.Mutex     // Serializes Close; taken before mu during teardown
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

	// Send an abort ACK to clear any in-flight command left by a previous
	// process that was killed mid-transaction (issue #1, bug C).
	_ = transport.sendAbortACK()

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

// sendAbortACK sends an ACK frame to the PN532 to abort any in-flight command.
// Per datasheet §6.2.1.3, a host-sent ACK causes the PN532 to abandon the
// current command and return to idle. Best-effort: errors are returned but
// callers typically ignore them.
func (t *Transport) sendAbortACK() error {
	if t.dev == nil {
		return pn532.ErrTransportClosed
	}
	return t.dev.Tx(ackFrame, nil)
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

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.dev == nil {
		return nil, pn532.ErrTransportClosed
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
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeout = timeout
	return nil
}

// Close closes the transport connection and releases the I2C bus file descriptor.
// Uses a separate mutex (closeMu) so it can interrupt an in-flight SendCommand
// without deadlocking: closing the bus fd causes any blocking Tx ioctl to fail
// with EBADF, allowing SendCommand to release mu promptly.
func (t *Transport) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()

	dev := t.dev
	bus := t.bus
	if bus != nil {
		// Best-effort abort: tell PN532 to drop any in-flight command so the
		// next opener doesn't find a stuck device.
		if dev != nil {
			_ = dev.Tx(ackFrame, nil)
		}
		// Close the bus fd — this interrupts any blocking Tx ioctl in SendCommand
		if err := bus.Close(); err != nil {
			return fmt.Errorf("failed to close I2C bus: %w", err)
		}
	}

	// Acquire mu to nil state (still holding closeMu). This blocks until any
	// in-flight SendCommand finishes (immediate now that the bus fd is closed).
	t.mu.Lock()
	t.bus = nil
	t.dev = nil
	t.mu.Unlock()

	return nil
}

// Reconnect closes and reopens the I2C bus connection. This is used for
// "nuclear" recovery when the PN532 enters a lockup state (no ACKs to any
// command). The PN532 I2C wakeup is implicit: the device recognises its
// address on the next START condition and uses clock-stretching to
// synchronise, so no special wakeup byte sequence is required (unlike UART).
//
// Note: if the PN532 is physically stuck mid-transaction (e.g. holding SDA
// low), a software reconnect alone may not recover it. In that case a
// hardware reset via a GPIO RST line, or a power-cycle, is required.
func (t *Transport) Reconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.bus != nil {
		_ = t.bus.Close()
		t.bus = nil
		t.dev = nil
	}

	time.Sleep(100 * time.Millisecond)

	if _, err := host.Init(); err != nil {
		return fmt.Errorf("reconnect: failed to initialize periph host: %w", err)
	}

	bus, err := i2creg.Open(parseI2CPath(t.busName))
	if err != nil {
		return fmt.Errorf("reconnect: failed to open I2C bus %s: %w", t.busName, err)
	}

	_ = bus.SetSpeed(maxClockFreq)
	t.bus = bus
	t.dev = &i2c.Dev{Addr: pn532Addr, Bus: bus}

	// Clear any stuck state from the previous session
	_ = t.sendAbortACK()

	return nil
}

// IsConnected returns true if the transport is connected
func (t *Transport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dev != nil
}

// Type returns the transport type
func (*Transport) Type() pn532.TransportType {
	return pn532.TransportI2C
}

// checkReadyOnce performs a single I2C ready-status read.
// Returns (true, nil) if ready, (false, nil) if not yet ready, (false, err) on bus error.
func (t *Transport) checkReadyOnce() (bool, error) {
	if t.dev == nil {
		return false, pn532.ErrTransportClosed
	}
	ready := frame.GetSmallBuffer(1)
	err := t.dev.Tx(nil, ready)
	isReady := err == nil && ready[0] == pn532Ready
	frame.PutBuffer(ready)
	if err != nil {
		return false, fmt.Errorf("I2C ready check failed: %w", err)
	}
	return isReady, nil
}

// checkReady polls the PN532 ready status with exponential backoff.
// Uses context-aware sleeps so cancellation stops the retry loop promptly,
// preventing in-flight I2C reads from overlapping with a new transport instance.
func (t *Transport) checkReady(ctx context.Context) error {
	baseDelay := time.Millisecond

	var lastErr error
	for attempt := range pn532.TransportI2CFrameRetries {
		if err := ctx.Err(); err != nil {
			return err
		}

		isReady, err := t.checkReadyOnce()
		if err != nil {
			lastErr = err
		} else if isReady {
			return nil
		}

		// Not ready or bus error: backoff then retry (skip sleep on last attempt)
		if attempt < pn532.TransportI2CFrameRetries-1 {
			if sleepErr := sleepCtx(ctx, baseDelay*time.Duration(1<<attempt)); sleepErr != nil {
				return sleepErr
			}
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return pn532.NewTransportNotReadyError("checkReady", t.busName)
}

// readI2C reads from the PN532, stripping the status byte that the hardware
// prepends to every I2C read transaction (see datasheet section 6.2.4).
func (t *Transport) readI2C(buf []byte) error {
	if t.dev == nil {
		return pn532.ErrTransportClosed
	}
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

	if t.dev == nil {
		return pn532.ErrTransportClosed
	}

	// Send frame via I2C (slice to exact size)
	t.traceTX(frm[:totalFrameSize], fmt.Sprintf("Cmd 0x%02X", cmd))
	if err := t.dev.Tx(frm[:totalFrameSize], nil); err != nil {
		return fmt.Errorf("failed to send I2C frame: %w", err)
	}

	return nil
}

// ackKind classifies a 6-byte I2C read as ACK, NACK, or something else.
type ackKind int

const (
	ackKindACK   ackKind = iota
	ackKindNACK          // PN532 requests retransmission
	ackKindOther         // unknown — caller should loop
)

// readAckKind performs one readI2C(buf) and classifies the result.
func (t *Transport) readAckKind(buf []byte) (ackKind, error) {
	if err := t.readI2C(buf); err != nil {
		return ackKindOther, fmt.Errorf("I2C ACK read failed: %w", err)
	}
	if bytes.Equal(buf, ackFrame) {
		t.traceRX(ackFrame, "ACK")
		return ackKindACK, nil
	}
	if bytes.Equal(buf, nackFrame) {
		t.traceRX(nackFrame, "NACK")
		return ackKindNACK, nil
	}
	return ackKindOther, nil
}

// pollReady checks readiness once and handles the error cases inline.
// Returns (true, nil) when the device is ready to be read.
// Returns (false, nil) when not yet ready (caller should loop).
// Returns (false, err) on context expiry or unrecoverable error.
func (t *Transport) pollReady(ackCtx context.Context) (bool, error) {
	if err := t.checkReady(ackCtx); err != nil {
		if ackCtx.Err() != nil {
			t.traceTimeout("No ACK received")
			return false, pn532.NewNoACKError("waitAck", t.busName)
		}
		if sleepErr := sleepCtx(ackCtx, time.Millisecond); sleepErr != nil {
			t.traceTimeout("No ACK received")
			return false, pn532.NewNoACKError("waitAck", t.busName)
		}
		return false, nil
	}
	return true, nil
}

// waitAck waits for an ACK frame from the PN532.
// A deadline-bounded context is created so that checkReady's internal retry
// loop cannot overshoot the transport timeout.
func (t *Transport) waitAck(ctx context.Context) error {
	ackCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	ackBuf := frame.GetSmallBuffer(6)
	defer frame.PutBuffer(ackBuf)

	for {
		select {
		case <-ackCtx.Done():
			t.traceTimeout("No ACK received")
			return pn532.NewNoACKError("waitAck", t.busName)
		default:
		}

		ready, err := t.pollReady(ackCtx)
		if err != nil {
			return err
		}
		if !ready {
			continue
		}

		kind, err := t.readAckKind(ackBuf)
		if err != nil {
			return err
		}
		switch kind {
		case ackKindACK:
			return nil
		case ackKindNACK:
			return pn532.NewNACKReceivedError("waitAck", t.busName)
		case ackKindOther: // unknown frame, sleep and retry
		}

		if sleepErr := sleepCtx(ackCtx, time.Millisecond); sleepErr != nil {
			t.traceTimeout("No ACK received")
			return pn532.NewNoACKError("waitAck", t.busName)
		}
	}
}

// sendAck sends an ACK frame to the PN532
func (t *Transport) sendAck() error {
	if t.dev == nil {
		return pn532.ErrTransportClosed
	}
	t.traceTX(ackFrame, "ACK")
	if err := t.dev.Tx(ackFrame, nil); err != nil {
		return fmt.Errorf("failed to send ACK: %w", err)
	}
	return nil
}

// sendNack sends a NACK frame to the PN532
func (t *Transport) sendNack() error {
	if t.dev == nil {
		return pn532.ErrTransportClosed
	}
	t.traceTX(nackFrame, "NACK")
	if err := t.dev.Tx(nackFrame, nil); err != nil {
		return fmt.Errorf("failed to send NACK: %w", err)
	}
	return nil
}

// receiveFrame reads a response frame from the PN532.
//
// If the caller's context already carries a deadline (e.g. the command-specific
// timeout set by the device layer), that deadline is honoured directly.
// Otherwise a sub-context bounded by t.timeout is created so the polling loop
// does not run forever.
//
// Only corrupted frames (LCS/DCS failure) trigger a NACK+retry. When the
// device is simply not ready yet, we poll again without sending a NACK —
// sending a NACK to a device that hasn't transmitted anything is a protocol
// violation that can crash the I2C bus.
func (t *Transport) receiveFrame(ctx context.Context) ([]byte, error) {
	frameCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		frameCtx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}

	const maxNACKRetries = 3
	nackRetries := 0

	for {
		select {
		case <-frameCtx.Done():
			t.traceTimeout("receiveFrame deadline exceeded")
			return nil, &pn532.TransportError{
				Op: "receiveFrame", Port: t.busName,
				Err:       pn532.ErrTransportTimeout,
				Type:      pn532.ErrorTypeTimeout,
				Retryable: true,
			}
		default:
		}

		data, needsNACK, err := t.receiveFrameAttempt(frameCtx)
		if err != nil {
			return nil, err
		}
		if data != nil {
			return data, nil
		}

		if needsNACK {
			if nackRetries >= maxNACKRetries {
				return nil, &pn532.TransportError{
					Op: "receiveFrame", Port: t.busName,
					Err:       pn532.ErrCommunicationFailed,
					Type:      pn532.ErrorTypeTransient,
					Retryable: true,
				}
			}
			if err := t.sendNack(); err != nil {
				return nil, err
			}
			nackRetries++
		}
	}
}

// receiveFrameAttempt performs a single frame receive attempt.
//
// Returns (data, needsNACK, err):
//   - (data, false, nil) — valid frame received
//   - (nil, false, nil)  — device not ready; caller should poll again (no NACK)
//   - (nil, true, nil)   — corrupted frame; caller should send NACK and retry
//   - (nil, false, err)  — unrecoverable error
func (t *Transport) receiveFrameAttempt(ctx context.Context) (data []byte, needsNACK bool, err error) {
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}

	// Poll readiness with a 1-byte transaction (efficient: avoids reading the
	// full 271-byte response on every poll while the PN532 is still processing).
	if readyErr := t.checkReady(ctx); readyErr != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if sleepErr := sleepCtx(ctx, time.Millisecond); sleepErr != nil {
			return nil, false, sleepErr
		}
		return nil, false, nil
	}

	// Read the complete frame in one I2C transaction. off is the index of the
	// LEN byte; the PN532 restart-from-zero behaviour makes a second transaction
	// impossible to use correctly for the remaining bytes.
	buf, off, err := t.readFrameData()
	if err != nil {
		return nil, false, err
	}
	defer frame.PutBuffer(buf)

	frameLen := int(buf[off])
	lcs := int(buf[off+1])
	totalFrameSize := off + 2 + frameLen + 2

	t.traceRX(buf[:totalFrameSize], "Response")

	// LCS is a transient bus-noise failure: trigger NACK+retry rather than
	// returning a hard error so the PN532 gets a chance to retransmit.
	if (frameLen+lcs)&0xFF != 0 {
		return nil, true, nil
	}

	needsNACK, err = t.validateI2CFrameChecksum(buf, off, frameLen)
	if err != nil || needsNACK {
		return nil, needsNACK, err
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
//
// Returns (buf, off, err) where off is the index of the LEN byte within buf (i.e. the
// two bytes at buf[off] and buf[off+1] are LEN and LCS). The caller is responsible for
// returning buf to the pool via frame.PutBuffer.
func (t *Transport) readFrameData() (buf []byte, off int, err error) {
	// frame.MaxFrameDataLength = 263; add framing bytes (preamble, start code,
	// LEN, LCS, DCS, postamble) for the largest buffer we may need. = 271
	const maxBufSize = frame.MaxFrameDataLength + 8

	buf = frame.GetBuffer(maxBufSize)

	if err := t.readI2C(buf); err != nil {
		frame.PutBuffer(buf)
		return nil, 0, fmt.Errorf("I2C frame read failed: %w", err)
	}

	// Locate the start code (0x00 0xFF) to find the LEN byte.
	off = -1
	for i := range maxBufSize - 1 {
		if buf[i] == 0x00 && buf[i+1] == 0xFF {
			off = i + 2 // index of LEN byte
			break
		}
	}

	if off < 0 || off+1 >= maxBufSize {
		frame.PutBuffer(buf)
		return nil, 0, &pn532.TransportError{
			Op:        "readFrameData",
			Port:      t.busName,
			Err:       pn532.ErrFrameCorrupted,
			Type:      pn532.ErrorTypeTransient,
			Retryable: true,
		}
	}

	// Validate that the declared frame fits within the buffer we read.
	// LCS validation (transient) is left to the caller for proper retry semantics.
	frameLen := int(buf[off])
	totalFrameSize := off + 2 + frameLen + 2
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

	return buf, off, nil
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

// Ensure Transport implements pn532.Transport and pn532.Reconnecter
var (
	_ pn532.Transport   = (*Transport)(nil)
	_ pn532.Reconnecter = (*Transport)(nil)
)
