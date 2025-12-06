// go-pn532
// Copyright (c) 2025 The Zaparoo Project Contributors.
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This file is part of go-pn532.
//
// go-pn532 is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// go-pn532 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with go-pn532; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// Package i2c provides I2C transport implementation for PN532
package i2c

import (
	"bytes"
	"context"
	"fmt"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
	"github.com/ZaparooProject/go-pn532/internal/frame"
	"periph.io/x/conn/v3/i2c"
	"periph.io/x/conn/v3/i2c/i2creg"
	"periph.io/x/conn/v3/physic"
	"periph.io/x/host/v3"
)

const (
	// PN532 I2C address.
	pn532WriteAddr = 0x48 // Write operation
	pn532ReadAddr  = 0x49 // Read operation

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

// New creates a new I2C transport
func New(busName string) (*Transport, error) {
	// Initialize host
	if _, err := host.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize periph host: %w", err)
	}

	// Open I2C bus
	bus, err := i2creg.Open(busName)
	if err != nil {
		return nil, fmt.Errorf("failed to open I2C bus %s: %w", busName, err)
	}

	// Create device with PN532 address and max frequency
	dev := &i2c.Dev{Addr: pn532WriteAddr, Bus: bus}

	// Set maximum frequency
	_ = bus.SetSpeed(maxClockFreq) // Ignore error, continue with default speed

	transport := &Transport{
		dev:     dev,
		busName: busName,
		// Match UART's unified timeout - originally 50ms but increased to 100ms
		// for better I2C bus compatibility across different hardware
		timeout: 100 * time.Millisecond,
	}

	return transport, nil
}

// SendCommand sends a command to the PN532 and waits for response
//
//nolint:wrapcheck // WrapError intentionally wraps errors with trace data
func (t *Transport) SendCommand(cmd byte, args []byte) ([]byte, error) {
	// Create trace buffer for this command (only used on error)
	t.currentTrace = pn532.NewTraceBuffer("I2C", t.busName, 16)
	defer func() { t.currentTrace = nil }() // Clear after command completes

	if err := t.sendFrame(cmd, args); err != nil {
		return nil, t.currentTrace.WrapError(err)
	}

	if err := t.waitAck(); err != nil {
		return nil, t.currentTrace.WrapError(err)
	}

	// Small delay for PN532 to process command
	time.Sleep(6 * time.Millisecond)

	resp, err := t.receiveFrame()
	if err != nil {
		return nil, t.currentTrace.WrapError(err)
	}
	return resp, nil
}

// SendCommandWithContext sends a command to the PN532 with context support
func (t *Transport) SendCommandWithContext(ctx context.Context, cmd byte, args []byte) ([]byte, error) {
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// For now, delegate to existing implementation
	// TODO: Add context-aware operations
	return t.SendCommand(cmd, args)
}

// SetTimeout sets the read timeout for the transport
func (t *Transport) SetTimeout(timeout time.Duration) error {
	t.timeout = timeout
	return nil
}

// Close closes the transport connection
func (*Transport) Close() error {
	// periph.io handles cleanup automatically
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

// checkReady checks if the PN532 is ready by reading the ready status
// Now includes retry logic with exponential backoff for better hardware compatibility
func (t *Transport) checkReady() error {
	const maxRetries = 5
	baseDelay := time.Millisecond

	var lastErr error
	for attempt := range maxRetries {
		// Use buffer pool for ready status check - small optimization
		ready := frame.GetSmallBuffer(1)

		err := t.dev.Tx(nil, ready)
		if err != nil {
			frame.PutBuffer(ready)
			lastErr = fmt.Errorf("I2C ready check failed: %w", err)
			// Exponential backoff: 1ms, 2ms, 4ms, 8ms, 16ms
			if attempt < maxRetries-1 {
				time.Sleep(baseDelay * time.Duration(1<<attempt))
				continue
			}
			return lastErr
		}

		if ready[0] == pn532Ready {
			frame.PutBuffer(ready)
			return nil
		}

		frame.PutBuffer(ready)
		// Device not ready yet, wait with backoff
		if attempt < maxRetries-1 {
			time.Sleep(baseDelay * time.Duration(1<<attempt))
		}
	}

	return pn532.NewTransportNotReadyError("checkReady", t.busName)
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
func (t *Transport) waitAck() error {
	deadline := time.Now().Add(t.timeout)

	// Use buffer pool for ACK frame reading
	ackBuf := frame.GetSmallBuffer(6)
	defer frame.PutBuffer(ackBuf)

	for time.Now().Before(deadline) {
		// Check if PN532 is ready
		if err := t.checkReady(); err != nil {
			time.Sleep(time.Millisecond)
			continue
		}

		// Read ACK frame into pooled buffer
		if err := t.dev.Tx(nil, ackBuf); err != nil {
			return fmt.Errorf("I2C ACK read failed: %w", err)
		}

		if bytes.Equal(ackBuf, ackFrame) {
			t.traceRX(ackFrame, "ACK")
			return nil
		}

		time.Sleep(time.Millisecond)
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
func (t *Transport) receiveFrame() ([]byte, error) {
	deadline := time.Now().Add(t.timeout)
	const maxTries = 3

	for range maxTries {
		if time.Now().After(deadline) {
			return nil, &pn532.TransportError{
				Op: "receiveFrame", Port: t.busName,
				Err:       pn532.ErrTransportTimeout,
				Type:      pn532.ErrorTypeTimeout,
				Retryable: true,
			}
		}

		data, shouldRetry, err := t.receiveFrameAttempt()
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
func (t *Transport) receiveFrameAttempt() (data []byte, shouldRetry bool, err error) {
	// Check if PN532 is ready
	if readyErr := t.checkReady(); readyErr != nil {
		time.Sleep(time.Millisecond)
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

// readFrameData reads frame data from I2C using incremental reads
// This fixes the critical bug where we were reading a fixed-size buffer without
// knowing how much data was actually received from the PN532
func (t *Transport) readFrameData() (buf []byte, actualLen int, err error) {
	// PHASE 1: Read frame header to determine frame size
	// Frame header structure: [preamble] [0x00] [0xFF] [LEN] [LCS] = 5 bytes minimum
	// We read a bit more to get the TFI byte and start of data
	headerSize := 32 // Read enough to get header + some data
	headerBuf := frame.GetSmallBuffer(headerSize)

	if err := t.dev.Tx(nil, headerBuf); err != nil {
		frame.PutBuffer(headerBuf)
		return nil, 0, fmt.Errorf("I2C frame header read failed: %w", err)
	}

	// Find frame start in header
	frameStart := -1
	for i := range headerSize - 1 {
		if headerBuf[i] == 0x00 && headerBuf[i+1] == 0xFF {
			frameStart = i + 2 // Point to length byte
			break
		}
	}

	if frameStart == -1 || frameStart+1 >= headerSize {
		frame.PutBuffer(headerBuf)
		return nil, 0, &pn532.TransportError{
			Op:        "readFrameData",
			Port:      t.busName,
			Err:       pn532.ErrFrameCorrupted,
			Type:      pn532.ErrorTypeTransient,
			Retryable: true,
		}
	}

	// Parse frame length
	frameLen := int(headerBuf[frameStart])
	lengthChecksum := headerBuf[frameStart+1]

	// Validate length checksum
	if ((frameLen + int(lengthChecksum)) & 0xFF) != 0 {
		frame.PutBuffer(headerBuf)
		return nil, 0, &pn532.TransportError{
			Op:        "readFrameData",
			Port:      t.busName,
			Err:       pn532.ErrFrameCorrupted,
			Type:      pn532.ErrorTypeTransient,
			Retryable: true,
		}
	}

	// PHASE 2: Calculate total frame size and check if we need more data
	// Total frame: [preamble] [0x00] [0xFF] [LEN] [LCS] [TFI] [data...] [DCS] [postamble]
	// = frameStart + 2 (LEN+LCS) + frameLen + 1 (DCS) + 1 (postamble)
	totalFrameSize := frameStart + 2 + frameLen + 2

	// If header buffer has all the data, use it
	if totalFrameSize <= headerSize {
		return headerBuf, totalFrameSize, nil
	}

	// PHASE 3: Need to read more data - allocate bigger buffer and copy header
	buf = frame.GetBuffer(totalFrameSize)
	copy(buf, headerBuf[:headerSize])
	frame.PutBuffer(headerBuf) // Return small buffer to pool

	// Read remaining data
	remainingSize := totalFrameSize - headerSize
	remainingBuf := frame.GetSmallBuffer(remainingSize)
	defer frame.PutBuffer(remainingBuf)

	if err := t.dev.Tx(nil, remainingBuf); err != nil {
		frame.PutBuffer(buf)
		return nil, 0, fmt.Errorf("I2C remaining frame data read failed: %w", err)
	}

	// Copy remaining data to main buffer
	copy(buf[headerSize:], remainingBuf[:remainingSize])

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
