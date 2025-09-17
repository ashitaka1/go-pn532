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
	"strings"
	"testing"
)

func TestIsRetryable(t *testing.T) {
	t.Parallel()
	tests := getIsRetryableTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsRetryable(tt.err)
			if got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getIsRetryableTestCases() []struct {
	err  error
	name string
	want bool
} {
	return []struct {
		err  error
		name string
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "transport timeout retryable",
			err:  ErrTransportTimeout,
			want: true,
		},
		{
			name: "transport read retryable",
			err:  ErrTransportRead,
			want: true,
		},
		{
			name: "transport write retryable",
			err:  ErrTransportWrite,
			want: true,
		},
		{
			name: "communication failed retryable",
			err:  ErrCommunicationFailed,
			want: true,
		},
		{
			name: "no ACK retryable",
			err:  ErrNoACK,
			want: true,
		},
		{
			name: "frame corrupted retryable",
			err:  ErrFrameCorrupted,
			want: true,
		},
		{
			name: "checksum mismatch retryable",
			err:  ErrChecksumMismatch,
			want: true,
		},
		{
			name: "device not found not retryable",
			err:  ErrDeviceNotFound,
			want: false,
		},
		{
			name: "tag not found not retryable",
			err:  ErrTagNotFound,
			want: false,
		},
		{
			name: "data too large not retryable",
			err:  ErrDataTooLarge,
			want: false,
		},
		{
			name: "invalid parameter not retryable",
			err:  ErrInvalidParameter,
			want: false,
		},
		{
			name: "wrapped retryable error",
			err:  errors.New("outer: " + ErrTransportTimeout.Error()),
			want: false,
		},
	}
}

func TestIsRetryable_TransportError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		transport *TransportError
		name      string
		want      bool
	}{
		{
			name: "transport error retryable=true",
			transport: &TransportError{
				Err:       errors.New("test error"),
				Op:        "read",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypeTransient,
				Retryable: true,
			},
			want: true,
		},
		{
			name: "transport error retryable=false",
			transport: &TransportError{
				Err:       errors.New("test error"),
				Op:        "write",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypeTransient,
				Retryable: false,
			},
			want: false,
		},
		{
			name: "transport error with retryable underlying error but retryable=false",
			transport: &TransportError{
				Err:       ErrTransportTimeout,
				Op:        "read",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypeTimeout,
				Retryable: false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsRetryable(tt.transport)
			if got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetErrorType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		name string
		want ErrorType
	}{
		{
			name: "nil error",
			err:  nil,
			want: ErrorTypePermanent,
		},
		{
			name: "transport timeout",
			err:  ErrTransportTimeout,
			want: ErrorTypeTimeout,
		},
		{
			name: "transport read",
			err:  ErrTransportRead,
			want: ErrorTypeTransient,
		},
		{
			name: "transport write",
			err:  ErrTransportWrite,
			want: ErrorTypeTransient,
		},
		{
			name: "communication failed",
			err:  ErrCommunicationFailed,
			want: ErrorTypeTransient,
		},
		{
			name: "no ACK",
			err:  ErrNoACK,
			want: ErrorTypeTransient,
		},
		{
			name: "frame corrupted",
			err:  ErrFrameCorrupted,
			want: ErrorTypeTransient,
		},
		{
			name: "checksum mismatch",
			err:  ErrChecksumMismatch,
			want: ErrorTypeTransient,
		},
		{
			name: "device not found",
			err:  ErrDeviceNotFound,
			want: ErrorTypePermanent,
		},
		{
			name: "tag not found",
			err:  ErrTagNotFound,
			want: ErrorTypePermanent,
		},
		{
			name: "unknown error",
			err:  errors.New("unknown error"),
			want: ErrorTypePermanent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetErrorType(tt.err)
			if got != tt.want {
				t.Errorf("GetErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetErrorType_TransportError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		transport *TransportError
		name      string
		want      ErrorType
	}{
		{
			name: "transport error transient",
			transport: &TransportError{
				Err:       errors.New("test error"),
				Op:        "read",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypeTransient,
				Retryable: true,
			},
			want: ErrorTypeTransient,
		},
		{
			name: "transport error timeout",
			transport: &TransportError{
				Err:       errors.New("test error"),
				Op:        "read",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypeTimeout,
				Retryable: true,
			},
			want: ErrorTypeTimeout,
		},
		{
			name: "transport error permanent",
			transport: &TransportError{
				Err:       errors.New("test error"),
				Op:        "open",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypePermanent,
				Retryable: false,
			},
			want: ErrorTypePermanent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetErrorType(tt.transport)
			if got != tt.want {
				t.Errorf("GetErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTransportError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err     error
		name    string
		op      string
		port    string
		errType ErrorType
	}{
		{
			name:    "basic transport error",
			op:      "read",
			port:    "/dev/ttyUSB0",
			err:     errors.New("permission denied"),
			errType: ErrorTypePermanent,
		},
		{
			name:    "empty port",
			op:      "write",
			port:    "",
			err:     errors.New("connection lost"),
			errType: ErrorTypeTransient,
		},
		{
			name:    "timeout error",
			op:      "command",
			port:    "ACR122U",
			err:     ErrTransportTimeout,
			errType: ErrorTypeTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			transportErr := NewTransportError(tt.op, tt.port, tt.err, tt.errType)

			if transportErr.Op != tt.op {
				t.Errorf("Op = %q, want %q", transportErr.Op, tt.op)
			}
			if transportErr.Port != tt.port {
				t.Errorf("Port = %q, want %q", transportErr.Port, tt.port)
			}
			if !errors.Is(transportErr.Err, tt.err) {
				t.Errorf("Err = %v, want %v", transportErr.Err, tt.err)
			}
			if transportErr.Type != tt.errType {
				t.Errorf("Type = %v, want %v", transportErr.Type, tt.errType)
			}
		})
	}
}

func TestTransportError_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		te   *TransportError
		want []string // Substrings that should be present
	}{
		{
			name: "with port",
			te: &TransportError{
				Err:  errors.New("connection failed"),
				Op:   "read",
				Port: "/dev/ttyUSB0",
			},
			want: []string{"read", "/dev/ttyUSB0", "connection failed"},
		},
		{
			name: "without port",
			te: &TransportError{
				Err:  errors.New("device busy"),
				Op:   "write",
				Port: "",
			},
			want: []string{"write", "device busy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.te.Error()
			for _, substr := range tt.want {
				if !strings.Contains(got, substr) {
					t.Errorf("Error() = %q, should contain %q", got, substr)
				}
			}
		})
	}
}

func TestTransportError_Unwrap(t *testing.T) {
	t.Parallel()
	originalErr := errors.New("original error")
	transportErr := &TransportError{
		Err:  originalErr,
		Op:   "test",
		Port: "/dev/test",
	}

	unwrapped := transportErr.Unwrap()
	if !errors.Is(unwrapped, originalErr) {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, originalErr)
	}
}

func TestNewTimeoutError(t *testing.T) {
	t.Parallel()
	te := NewTimeoutError("read", "/dev/ttyUSB0")

	if te.Op != "read" {
		t.Errorf("Op = %q, want %q", te.Op, "read")
	}
	if te.Port != "/dev/ttyUSB0" {
		t.Errorf("Port = %q, want %q", te.Port, "/dev/ttyUSB0")
	}
	if te.Type != ErrorTypeTimeout {
		t.Errorf("Type = %v, want %v", te.Type, ErrorTypeTimeout)
	}
	if !te.Retryable {
		t.Error("Retryable should be true for timeout errors")
	}
}

func TestNewFrameCorruptedError(t *testing.T) {
	t.Parallel()
	te := NewFrameCorruptedError("read", "/dev/ttyUSB0")

	if te.Op != "read" {
		t.Errorf("Op = %q, want %q", te.Op, "read")
	}
	if te.Port != "/dev/ttyUSB0" {
		t.Errorf("Port = %q, want %q", te.Port, "/dev/ttyUSB0")
	}
	if te.Type != ErrorTypeTransient {
		t.Errorf("Type = %v, want %v", te.Type, ErrorTypeTransient)
	}
	if !te.Retryable {
		t.Error("Retryable should be true for frame corrupted errors")
	}
}

func TestNewDataTooLargeError(t *testing.T) {
	t.Parallel()
	te := NewDataTooLargeError("write", "/dev/ttyUSB0")

	if te.Op != "write" {
		t.Errorf("Op = %q, want %q", te.Op, "write")
	}
	if te.Port != "/dev/ttyUSB0" {
		t.Errorf("Port = %q, want %q", te.Port, "/dev/ttyUSB0")
	}
	if te.Type != ErrorTypePermanent {
		t.Errorf("Type = %v, want %v", te.Type, ErrorTypePermanent)
	}
	if te.Retryable {
		t.Error("Retryable should be false for data too large errors")
	}
}

// PN532Error Tests

func TestNewPN532Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		command     string
		context     string
		wantMessage string
		errorCode   byte
	}{
		{
			name:        "timeout error without context",
			errorCode:   0x01,
			command:     "InDataExchange",
			context:     "",
			wantMessage: "PN532 error 0x01: InDataExchange",
		},
		{
			name:        "authentication error with context",
			errorCode:   0x14,
			command:     "InDataExchange",
			context:     "authentication failure",
			wantMessage: "PN532 error 0x14 (InDataExchange): authentication failure",
		},
		{
			name:        "command not supported",
			errorCode:   0x81,
			command:     "InCommunicateThru",
			context:     "",
			wantMessage: "PN532 error 0x81: InCommunicateThru",
		},
		{
			name:        "error with detailed context",
			errorCode:   0x02,
			command:     "InListPassiveTarget",
			context:     "no targets found in field",
			wantMessage: "PN532 error 0x02 (InListPassiveTarget): no targets found in field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := NewPN532Error(tt.errorCode, tt.command, tt.context)

			if err.ErrorCode != tt.errorCode {
				t.Errorf("ErrorCode = 0x%02X, want 0x%02X", err.ErrorCode, tt.errorCode)
			}
			if err.Command != tt.command {
				t.Errorf("Command = %q, want %q", err.Command, tt.command)
			}
			if err.Context != tt.context {
				t.Errorf("Context = %q, want %q", err.Context, tt.context)
			}
			if err.Error() != tt.wantMessage {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.wantMessage)
			}
		})
	}
}

func TestPN532Error_ErrorTypeChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                      string
		errorCode                 byte
		wantIsCommandNotSupported bool
		wantIsAuthenticationError bool
		wantIsTimeoutError        bool
	}{
		{
			name:                      "command not supported",
			errorCode:                 0x81,
			wantIsCommandNotSupported: true,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
		},
		{
			name:                      "authentication error",
			errorCode:                 0x14,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: true,
			wantIsTimeoutError:        false,
		},
		{
			name:                      "timeout error",
			errorCode:                 0x01,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        true,
		},
		{
			name:                      "other error",
			errorCode:                 0xFF,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := NewPN532Error(tt.errorCode, "TestCommand", "")

			if got := err.IsCommandNotSupported(); got != tt.wantIsCommandNotSupported {
				t.Errorf("IsCommandNotSupported() = %v, want %v", got, tt.wantIsCommandNotSupported)
			}
			if got := err.IsAuthenticationError(); got != tt.wantIsAuthenticationError {
				t.Errorf("IsAuthenticationError() = %v, want %v", got, tt.wantIsAuthenticationError)
			}
			if got := err.IsTimeoutError(); got != tt.wantIsTimeoutError {
				t.Errorf("IsTimeoutError() = %v, want %v", got, tt.wantIsTimeoutError)
			}
		})
	}
}

func TestIsRetryable_PN532Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		errorCode byte
		want      bool
	}{
		{name: "timeout error is retryable", errorCode: 0x01, want: true},
		{name: "authentication error is retryable", errorCode: 0x14, want: true},
		{name: "command not supported is not retryable", errorCode: 0x81, want: false},
		{name: "unknown error is not retryable", errorCode: 0xFF, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := NewPN532Error(tt.errorCode, "TestCommand", "")
			got := IsRetryable(err)
			if got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCommandNotSupported(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		name string
		want bool
	}{
		{
			name: "PN532Error command not supported",
			err:  NewPN532Error(0x81, "TestCommand", ""),
			want: true,
		},
		{
			name: "PN532Error timeout",
			err:  NewPN532Error(0x01, "TestCommand", ""),
			want: false,
		},
		{
			name: "ErrCommandNotSupported",
			err:  ErrCommandNotSupported,
			want: true,
		},
		{
			name: "wrapped ErrCommandNotSupported",
			err:  errors.New("failed: " + ErrCommandNotSupported.Error()),
			want: false, // errors.Is won't match wrapped string
		},
		{
			name: "other error",
			err:  errors.New("some other error"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsCommandNotSupported(tt.err)
			if got != tt.want {
				t.Errorf("IsCommandNotSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPN532ErrorHelperFunctions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err                            error
		name                           string
		wantIsPN532AuthenticationError bool
		wantIsPN532TimeoutError        bool
	}{
		{
			name:                           "PN532Error authentication",
			err:                            NewPN532Error(0x14, "InDataExchange", ""),
			wantIsPN532AuthenticationError: true,
			wantIsPN532TimeoutError:        false,
		},
		{
			name:                           "PN532Error timeout",
			err:                            NewPN532Error(0x01, "InDataExchange", ""),
			wantIsPN532AuthenticationError: false,
			wantIsPN532TimeoutError:        true,
		},
		{
			name:                           "other error",
			err:                            errors.New("some error"),
			wantIsPN532AuthenticationError: false,
			wantIsPN532TimeoutError:        false,
		},
		{
			name:                           "nil error",
			err:                            nil,
			wantIsPN532AuthenticationError: false,
			wantIsPN532TimeoutError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsPN532AuthenticationError(tt.err); got != tt.wantIsPN532AuthenticationError {
				t.Errorf("IsPN532AuthenticationError() = %v, want %v", got, tt.wantIsPN532AuthenticationError)
			}
			if got := IsPN532TimeoutError(tt.err); got != tt.wantIsPN532TimeoutError {
				t.Errorf("IsPN532TimeoutError() = %v, want %v", got, tt.wantIsPN532TimeoutError)
			}
		})
	}
}
