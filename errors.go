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

// PN532Error wraps PN532 device errors with error code context
type PN532Error struct {
	Command   string
	Context   string
	ErrorCode byte
}

func (e *PN532Error) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("PN532 error 0x%02X (%s): %s", e.ErrorCode, e.Command, e.Context)
	}
	return fmt.Sprintf("PN532 error 0x%02X: %s", e.ErrorCode, e.Command)
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

// GetErrorType categorizes an error
func GetErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypePermanent
	}

	var te *TransportError
	if errors.As(err, &te) {
		return te.Type
	}

	// Categorize known errors
	switch {
	case errors.Is(err, ErrTransportTimeout):
		return ErrorTypeTimeout
	case IsRetryable(err):
		return ErrorTypeTransient
	default:
		return ErrorTypePermanent
	}
}

// IsRecoverable checks if an error indicates the device might be in a stuck state
// that could potentially be recovered with a soft reset sequence
func IsRecoverable(err error) bool {
	// Only attempt recovery for severe transport/communication errors
	// that suggest the device might be unresponsive
	switch {
	case errors.Is(err, ErrTransportTimeout),
		errors.Is(err, ErrNoACK),
		errors.Is(err, ErrFrameCorrupted):
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
