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

package pn532

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Error categories for better error handling and retry logic
var (
	// Transport errors - potentially retryable
	ErrTransportTimeout  = errors.New("transport timeout")
	ErrTransportWrite    = errors.New("transport write failed")
	ErrTransportRead     = errors.New("transport read failed")
	ErrTransportClosed   = errors.New("transport is closed")
	ErrTransportNotReady = errors.New("transport not ready")

	// Communication errors - potentially retryable
	ErrCommunicationFailed = errors.New("communication failed")
	ErrNoACK               = errors.New("no ACK received")
	ErrNACKReceived        = errors.New("NACK received")
	ErrFrameCorrupted      = errors.New("frame corrupted")
	ErrChecksumMismatch    = errors.New("checksum mismatch")

	// Device errors - generally not retryable
	ErrDeviceNotFound      = errors.New("device not found")
	ErrDeviceNotSupported  = errors.New("device not supported")
	ErrCommandFailed       = errors.New("command execution failed")
	ErrInvalidResponse     = errors.New("invalid response format")
	ErrCommandNotSupported = errors.New("command not supported by device")

	// Tag errors - generally not retryable
	ErrTagNotFound    = errors.New("tag not found")
	ErrTagAuthFailed  = errors.New("tag authentication failed")
	ErrTagReadFailed  = errors.New("tag read failed")
	ErrTagWriteFailed = errors.New("tag write failed")
	ErrTagUnsupported = errors.New("tag type not supported")
	ErrTagEmptyData   = errors.New("tag detected but returned empty data")
	ErrTagDataCorrupt = errors.New("tag data appears corrupted")
	ErrTagUnreliable  = errors.New("tag readings are inconsistent")

	// Data errors - not retryable
	ErrInvalidParameter = errors.New("invalid parameter")
	ErrDataTooLarge     = errors.New("data too large")
	ErrInvalidFormat    = errors.New("invalid data format")
)

// ErrorType represents the category of error for retry logic
type ErrorType int

const (
	// ErrorTypeTransient indicates a potentially retryable error
	ErrorTypeTransient ErrorType = iota
	// ErrorTypePermanent indicates a non-retryable error
	ErrorTypePermanent
	// ErrorTypeTimeout indicates a timeout error (special handling)
	ErrorTypeTimeout
)

// TransportError wraps transport-level errors with additional context
type TransportError struct {
	Err       error     // Underlying error
	Op        string    // Operation that failed
	Port      string    // Port or device identifier
	Type      ErrorType // Error category
	Retryable bool      // Whether the error is retryable
}

func (e *TransportError) Error() string {
	if e.Port != "" {
		return fmt.Sprintf("%s %s: %v", e.Op, e.Port, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *TransportError) Unwrap() error {
	return e.Err
}

// PN532Error wraps PN532 device errors with error code context.
// This provides detailed information for debugging protocol-level failures.
type PN532Error struct {
	Command   string
	Context   string
	BytesSent int
	ErrorCode byte
	Target    byte
}

func (e *PN532Error) Error() string {
	meaning := pn532ErrorCodeMeaning(e.ErrorCode)
	base := fmt.Sprintf("%s error 0x%02X (%s)", e.Command, e.ErrorCode, meaning)
	if e.Context != "" {
		base += ": " + e.Context
	}
	if e.BytesSent > 0 {
		base += fmt.Sprintf(" [sent %d bytes, target %d]", e.BytesSent, e.Target)
	}
	return base
}

// pn532ErrorCodeMeaning returns a human-readable meaning for PN532 error codes
// Error codes are from the PN532 User Manual section 7.1
func pn532ErrorCodeMeaning(code byte) string {
	meanings := map[byte]string{
		0x00: "success",
		0x01: "timeout",
		0x02: "CRC error",
		0x03: "parity error",
		0x04: "erroneous bit count during anti-collision",
		0x05: "framing error during mifare operation",
		0x06: "abnormal bit collision",
		0x07: "communication buffer size insufficient",
		0x09: "RF buffer overflow",
		0x0A: "RF field not activated in time",
		0x0B: "RF protocol error",
		0x0D: "overheating",
		0x0E: "internal buffer overflow",
		0x10: "invalid parameter",
		0x12: "DEP protocol not supported",
		0x13: "dataformat does not match",
		0x14: "authentication error",
		0x23: "UID check byte is wrong",
		0x25: "DEP invalid state",
		0x26: "operation not allowed",
		0x27: "wrong context for command",
		0x29: "target released by initiator",
		0x2A: "card ID mismatch",
		0x2B: "card disappeared",
		0x2C: "NFCID3 initiator/target mismatch",
		0x2D: "over-current event",
		0x2E: "NAD missing in DEP frame",
		0x81: "command not supported",
	}
	if m, ok := meanings[code]; ok {
		return m
	}
	return "unknown error"
}

// IsCommandNotSupported returns true if the error indicates the command is not supported
func (e *PN532Error) IsCommandNotSupported() bool {
	// Error code 0x81 indicates "Invalid command"
	return e.ErrorCode == 0x81
}

// IsAuthenticationError returns true if the error is authentication-related
func (e *PN532Error) IsAuthenticationError() bool {
	// Error code 0x14 indicates authentication failure
	return e.ErrorCode == 0x14
}

// IsTimeoutError returns true if the error is timeout-related
func (e *PN532Error) IsTimeoutError() bool {
	// Error code 0x01 indicates timeout
	return e.ErrorCode == 0x01
}

// IsRetryable returns true if the error is potentially retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	var te *TransportError
	if errors.As(err, &te) {
		return te.Retryable
	}

	// Check for PN532 errors
	var pe *PN532Error
	if errors.As(err, &pe) {
		// Timeouts and authentication errors are retryable
		// Command not supported errors are not retryable
		return pe.IsTimeoutError() || pe.IsAuthenticationError()
	}

	// Check for known retryable errors
	switch {
	case errors.Is(err, ErrTransportTimeout),
		errors.Is(err, ErrTransportRead),
		errors.Is(err, ErrTransportWrite),
		errors.Is(err, ErrCommunicationFailed),
		errors.Is(err, ErrNoACK),
		errors.Is(err, ErrFrameCorrupted),
		errors.Is(err, ErrChecksumMismatch):
		return true
	default:
		return false
	}
}

// IsCommandNotSupported checks if an error indicates a command is not supported
func IsCommandNotSupported(err error) bool {
	var pe *PN532Error
	if errors.As(err, &pe) {
		return pe.IsCommandNotSupported()
	}
	return errors.Is(err, ErrCommandNotSupported)
}

// IsPN532AuthenticationError checks if an error is a PN532 authentication failure
func IsPN532AuthenticationError(err error) bool {
	var pe *PN532Error
	if errors.As(err, &pe) {
		return pe.IsAuthenticationError()
	}
	return false
}

// IsPN532TimeoutError checks if an error is a PN532 timeout
func IsPN532TimeoutError(err error) bool {
	var pe *PN532Error
	if errors.As(err, &pe) {
		return pe.IsTimeoutError()
	}
	return false
}

// Error constructors for consistent error creation

// NewPN532Error creates a PN532 error with the specified error code and context
func NewPN532Error(errorCode byte, command, context string) *PN532Error {
	return &PN532Error{
		ErrorCode: errorCode,
		Command:   command,
		Context:   context,
	}
}

// NewPN532ErrorWithDetails creates a PN532 error with full debugging context.
// Use this for protocol-level errors where knowing bytes sent and target helps debugging.
func NewPN532ErrorWithDetails(errorCode byte, command string, bytesSent int, target byte) *PN532Error {
	return &PN532Error{
		ErrorCode: errorCode,
		Command:   command,
		BytesSent: bytesSent,
		Target:    target,
	}
}

// NewTransportError creates a standard transport error with consistent formatting
func NewTransportError(op, port string, err error, errType ErrorType) *TransportError {
	return &TransportError{
		Op:        op,
		Port:      port,
		Err:       err,
		Type:      errType,
		Retryable: errType == ErrorTypeTransient || errType == ErrorTypeTimeout,
	}
}

// NewTimeoutError creates a timeout error for transport operations
func NewTimeoutError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrTransportTimeout, ErrorTypeTimeout)
}

// NewFrameCorruptedError creates a frame corruption error
func NewFrameCorruptedError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrFrameCorrupted, ErrorTypeTransient)
}

// NewDataTooLargeError creates a data too large error (permanent)
func NewDataTooLargeError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrDataTooLarge, ErrorTypePermanent)
}

// NewTransportWriteError creates a write error (transient)
func NewTransportWriteError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrTransportWrite, ErrorTypeTransient)
}

// NewTransportReadError creates a read error (transient)
func NewTransportReadError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrTransportRead, ErrorTypeTransient)
}

// NewNoACKError creates a "no ACK received" error (timeout)
func NewNoACKError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrNoACK, ErrorTypeTimeout)
}

// NewNACKReceivedError creates a "NACK received" error (transient)
func NewNACKReceivedError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrNACKReceived, ErrorTypeTransient)
}

// NewInvalidResponseError creates an invalid response error (permanent)
func NewInvalidResponseError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrInvalidResponse, ErrorTypePermanent)
}

// NewChecksumMismatchError creates a checksum mismatch error (transient)
func NewChecksumMismatchError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrChecksumMismatch, ErrorTypeTransient)
}

// NewTransportNotReadyError creates a transport not ready error (timeout)
func NewTransportNotReadyError(op, port string) *TransportError {
	return NewTransportError(op, port, ErrTransportNotReady, ErrorTypeTimeout)
}

// =============================================================================
// Wire Trace Logging
// =============================================================================
// TraceableError embeds wire-level trace data in errors, allowing consumer
// applications to access debug information when operations fail.

// TraceDirection indicates the direction of wire data
type TraceDirection string

const (
	// TraceTX indicates data sent to the PN532
	TraceTX TraceDirection = "TX"
	// TraceRX indicates data received from the PN532
	TraceRX TraceDirection = "RX"
)

// TraceEntry represents a single wire-level operation
type TraceEntry struct {
	Timestamp time.Time
	Direction TraceDirection
	Note      string
	Data      []byte
}

// String formats a trace entry for display
func (e TraceEntry) String() string {
	hexData := formatHexBytes(e.Data)
	if e.Note != "" {
		return fmt.Sprintf("[%s] %s: %s (%s)", e.Timestamp.Format("15:04:05.000"), e.Direction, hexData, e.Note)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Timestamp.Format("15:04:05.000"), e.Direction, hexData)
}

// TraceableError wraps an error with wire-level trace data for debugging.
// Consumer applications can use errors.As() to extract trace information:
//
//	var te *pn532.TraceableError
//	if errors.As(err, &te) {
//	    log.Printf("Wire trace:\n%s", te.FormatTrace())
//	}
type TraceableError struct {
	Err       error
	Transport string
	Port      string
	Trace     []TraceEntry
}

// Error implements the error interface
func (e *TraceableError) Error() string {
	return e.Err.Error()
}

// Unwrap returns the underlying error for errors.Is/As compatibility
func (e *TraceableError) Unwrap() error {
	return e.Err
}

// FormatTrace returns a human-readable formatted trace log
func (e *TraceableError) FormatTrace() string {
	if len(e.Trace) == 0 {
		return fmt.Sprintf("[%s:%s] (no trace data)", e.Transport, e.Port)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s:%s] Wire trace (%d entries):\n", e.Transport, e.Port, len(e.Trace)))

	for _, entry := range e.Trace {
		direction := ">"
		if entry.Direction == TraceRX {
			direction = "<"
		}
		hexData := formatHexBytes(entry.Data)
		if entry.Note != "" {
			sb.WriteString(fmt.Sprintf("  %s %s (%s)\n", direction, hexData, entry.Note))
		} else {
			sb.WriteString(fmt.Sprintf("  %s %s\n", direction, hexData))
		}
	}

	return sb.String()
}

// formatHexBytes formats a byte slice as space-separated hex values
func formatHexBytes(data []byte) string {
	if len(data) == 0 {
		return "(empty)"
	}
	if len(data) > 32 {
		// Truncate long data with ellipsis
		parts := make([]string, 32)
		for i := range 32 {
			parts[i] = fmt.Sprintf("%02X", data[i])
		}
		return strings.Join(parts, " ") + fmt.Sprintf(" ... (%d bytes total)", len(data))
	}
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, " ")
}

// TraceBuffer collects trace entries during a command operation.
// It uses a fixed-size circular buffer to limit memory usage.
type TraceBuffer struct {
	transport string
	port      string
	entries   []TraceEntry
	maxSize   int
}

// NewTraceBuffer creates a new trace buffer with the specified capacity
func NewTraceBuffer(transport, port string, maxSize int) *TraceBuffer {
	if maxSize <= 0 {
		maxSize = 16 // Default to 16 entries
	}
	return &TraceBuffer{
		entries:   make([]TraceEntry, 0, maxSize),
		maxSize:   maxSize,
		transport: transport,
		port:      port,
	}
}

// RecordTX records a transmission to the PN532
func (tb *TraceBuffer) RecordTX(data []byte, note string) {
	tb.record(TraceTX, data, note)
}

// RecordRX records data received from the PN532
func (tb *TraceBuffer) RecordRX(data []byte, note string) {
	tb.record(TraceRX, data, note)
}

// RecordTimeout records a timeout event
func (tb *TraceBuffer) RecordTimeout(note string) {
	tb.record(TraceRX, nil, "TIMEOUT: "+note)
}

// record adds an entry to the buffer, evicting oldest if full
func (tb *TraceBuffer) record(dir TraceDirection, data []byte, note string) {
	// Make a copy of data to avoid aliasing issues
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	entry := TraceEntry{
		Direction: dir,
		Data:      dataCopy,
		Timestamp: time.Now(),
		Note:      note,
	}

	if len(tb.entries) >= tb.maxSize {
		// Shift entries to make room (evict oldest)
		copy(tb.entries, tb.entries[1:])
		tb.entries[len(tb.entries)-1] = entry
	} else {
		tb.entries = append(tb.entries, entry)
	}
}

// WrapError wraps an error with the collected trace data.
// Returns nil if err is nil.
func (tb *TraceBuffer) WrapError(err error) error {
	if err == nil {
		return nil
	}

	// Make a copy of entries
	entriesCopy := make([]TraceEntry, len(tb.entries))
	copy(entriesCopy, tb.entries)

	return &TraceableError{
		Err:       err,
		Trace:     entriesCopy,
		Transport: tb.transport,
		Port:      tb.port,
	}
}

// Clear resets the trace buffer
func (tb *TraceBuffer) Clear() {
	tb.entries = tb.entries[:0]
}

// HasTrace checks if an error contains trace data
func HasTrace(err error) bool {
	var te *TraceableError
	return errors.As(err, &te)
}

// GetTrace extracts trace data from an error, returning nil if not present
func GetTrace(err error) *TraceableError {
	var te *TraceableError
	if errors.As(err, &te) {
		return te
	}
	return nil
}
