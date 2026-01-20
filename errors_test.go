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

package pn532

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"
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

//nolint:funlen // Test data table - length is acceptable for test cases
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
			name: "no ACK not retryable",
			err:  ErrNoACK,
			want: false,
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
		// New retryable error types added for sliding card use case
		{
			name: "tag read failed is retryable",
			err:  ErrTagReadFailed,
			want: true,
		},
		{
			name: "tag data corrupt is retryable",
			err:  ErrTagDataCorrupt,
			want: true,
		},
		{
			name: "wrapped tag read failed is retryable",
			err:  fmt.Errorf("block 4: %w", ErrTagReadFailed),
			want: true,
		},
		{
			name: "wrapped tag data corrupt is retryable",
			err:  fmt.Errorf("invalid CC: %w", ErrTagDataCorrupt),
			want: true,
		},
	}
}

func TestIsFatal(t *testing.T) {
	t.Parallel()
	tests := []struct {
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
			name: "transport closed is fatal",
			err:  ErrTransportClosed,
			want: true,
		},
		{
			name: "device not found is fatal",
			err:  ErrDeviceNotFound,
			want: true,
		},
		{
			name: "device not supported is fatal",
			err:  ErrDeviceNotSupported,
			want: true,
		},
		{
			name: "transport timeout is not fatal",
			err:  ErrTransportTimeout,
			want: false,
		},
		{
			name: "transport read is not fatal",
			err:  ErrTransportRead,
			want: false,
		},
		{
			name: "transport write is not fatal",
			err:  ErrTransportWrite,
			want: false,
		},
		{
			name: "tag auth failed is not fatal",
			err:  ErrTagAuthFailed,
			want: false,
		},
		{
			name: "command not supported is not fatal",
			err:  ErrCommandNotSupported,
			want: false,
		},
		{
			name: "random error is not fatal",
			err:  errors.New("random error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsFatal(tt.err)
			if got != tt.want {
				t.Errorf("IsFatal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFatal_TransportError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		transport *TransportError
		name      string
		want      bool
	}{
		{
			name: "transport error with permanent type is fatal",
			transport: &TransportError{
				Err:       errors.New("device disconnected"),
				Op:        "read",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypePermanent,
				Retryable: false,
			},
			want: true,
		},
		{
			name: "transport error with transient type is not fatal",
			transport: &TransportError{
				Err:       errors.New("timeout"),
				Op:        "read",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypeTransient,
				Retryable: true,
			},
			want: false,
		},
		{
			name: "transport error with timeout type is not fatal",
			transport: &TransportError{
				Err:       errors.New("timeout"),
				Op:        "read",
				Port:      "/dev/ttyUSB0",
				Type:      ErrorTypeTimeout,
				Retryable: true,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsFatal(tt.transport)
			if got != tt.want {
				t.Errorf("IsFatal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFatal_SyscallErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		name string
		want bool
	}{
		// Unix errors that indicate device disconnection
		{
			name: "EIO (input/output error) is fatal",
			err:  syscall.EIO,
			want: true,
		},
		{
			name: "ENXIO (no such device or address) is fatal",
			err:  syscall.ENXIO,
			want: true,
		},
		{
			name: "ENODEV (no such device) is fatal",
			err:  syscall.ENODEV,
			want: true,
		},
		// Wrapped syscall errors should also be detected
		{
			name: "wrapped EIO is fatal",
			err:  fmt.Errorf("write failed: %w", syscall.EIO),
			want: true,
		},
		{
			name: "double-wrapped ENXIO is fatal",
			err:  fmt.Errorf("operation failed: %w", fmt.Errorf("write: %w", syscall.ENXIO)),
			want: true,
		},
		// Non-fatal syscall errors
		{
			name: "EAGAIN is not fatal",
			err:  syscall.EAGAIN,
			want: false,
		},
		{
			name: "EINTR is not fatal",
			err:  syscall.EINTR,
			want: false,
		},
		{
			name: "ETIMEDOUT is not fatal",
			err:  syscall.ETIMEDOUT,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsFatal(tt.err)
			if got != tt.want {
				t.Errorf("IsFatal(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
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
			wantMessage: "InDataExchange error 0x01 (timeout)",
		},
		{
			name:        "authentication error with context",
			errorCode:   0x14,
			command:     "InDataExchange",
			context:     "authentication failure",
			wantMessage: "InDataExchange error 0x14 (authentication error): authentication failure",
		},
		{
			name:        "command not supported",
			errorCode:   0x81,
			command:     "InCommunicateThru",
			context:     "",
			wantMessage: "InCommunicateThru error 0x81 (command not supported)",
		},
		{
			name:        "error with detailed context",
			errorCode:   0x02,
			command:     "InListPassiveTarget",
			context:     "no targets found in field",
			wantMessage: "InListPassiveTarget error 0x02 (CRC error): no targets found in field",
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

//nolint:gocognit,revive // Test function with multiple field validations
func TestNewPN532ErrorWithDetails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		command     string
		wantMessage string
		bytesSent   int
		errorCode   byte
		target      byte
	}{
		{
			name:        "timeout error with bytes sent and target",
			errorCode:   0x01,
			command:     "InDataExchange",
			bytesSent:   16,
			target:      1,
			wantMessage: "InDataExchange error 0x01 (timeout) [sent 16 bytes, target 1]",
		},
		{
			name:        "authentication error with protocol details",
			errorCode:   0x14,
			command:     "InCommunicateThru",
			bytesSent:   32,
			target:      2,
			wantMessage: "InCommunicateThru error 0x14 (authentication error) [sent 32 bytes, target 2]",
		},
		{
			name:        "CRC error with many bytes",
			errorCode:   0x02,
			command:     "InDataExchange",
			bytesSent:   255,
			target:      1,
			wantMessage: "InDataExchange error 0x02 (CRC error) [sent 255 bytes, target 1]",
		},
		{
			name:        "error with zero bytes sent (omits details)",
			errorCode:   0x03,
			command:     "InDataExchange",
			bytesSent:   0,
			target:      1,
			wantMessage: "InDataExchange error 0x03 (parity error)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := NewPN532ErrorWithDetails(tt.errorCode, tt.command, tt.bytesSent, tt.target)

			if err.ErrorCode != tt.errorCode {
				t.Errorf("ErrorCode = 0x%02X, want 0x%02X", err.ErrorCode, tt.errorCode)
			}
			if err.Command != tt.command {
				t.Errorf("Command = %q, want %q", err.Command, tt.command)
			}
			if err.BytesSent != tt.bytesSent {
				t.Errorf("BytesSent = %d, want %d", err.BytesSent, tt.bytesSent)
			}
			if err.Target != tt.target {
				t.Errorf("Target = %d, want %d", err.Target, tt.target)
			}
			if err.Error() != tt.wantMessage {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.wantMessage)
			}
		})
	}
}

//nolint:funlen // Test data table - length is acceptable for comprehensive error type coverage
func TestPN532Error_ErrorTypeChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                      string
		errorCode                 byte
		wantIsCommandNotSupported bool
		wantIsAuthenticationError bool
		wantIsTimeoutError        bool
		wantIsRFError             bool
	}{
		{
			name:                      "command not supported",
			errorCode:                 0x81,
			wantIsCommandNotSupported: true,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             false,
		},
		{
			name:                      "authentication error",
			errorCode:                 0x14,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: true,
			wantIsTimeoutError:        false,
			wantIsRFError:             false,
		},
		{
			name:                      "timeout error",
			errorCode:                 0x01,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        true,
			wantIsRFError:             false,
		},
		{
			name:                      "other error",
			errorCode:                 0xFF,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             false,
		},
		// RF error codes
		{
			name:                      "CRC error",
			errorCode:                 0x02,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
		},
		{
			name:                      "parity error",
			errorCode:                 0x03,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
		},
		{
			name:                      "framing error",
			errorCode:                 0x05,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
		},
		{
			name:                      "RF field not activated",
			errorCode:                 0x0A,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
		},
		{
			name:                      "RF protocol error",
			errorCode:                 0x0B,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
		},
		{
			name:                      "wrong context - target selection lost",
			errorCode:                 0x27,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
		},
		{
			name:                      "target released by initiator",
			errorCode:                 0x29,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
		},
		{
			name:                      "card disappeared",
			errorCode:                 0x2B,
			wantIsCommandNotSupported: false,
			wantIsAuthenticationError: false,
			wantIsTimeoutError:        false,
			wantIsRFError:             true,
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
			if got := err.IsRFError(); got != tt.wantIsRFError {
				t.Errorf("IsRFError() = %v, want %v", got, tt.wantIsRFError)
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
		// RF errors are retryable (common during card sliding)
		{name: "CRC error is retryable", errorCode: 0x02, want: true},
		{name: "parity error is retryable", errorCode: 0x03, want: true},
		{name: "framing error is retryable", errorCode: 0x05, want: true},
		{name: "RF field not activated is retryable", errorCode: 0x0A, want: true},
		{name: "RF protocol error is retryable", errorCode: 0x0B, want: true},
		{name: "target released is retryable", errorCode: 0x29, want: true},
		{name: "card disappeared is retryable", errorCode: 0x2B, want: true},
		// Non-RF errors remain not retryable
		{name: "erroneous bit count is not retryable", errorCode: 0x04, want: false},
		{name: "buffer overflow is not retryable", errorCode: 0x09, want: false},
		{name: "invalid parameter is not retryable", errorCode: 0x10, want: false},
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

// =============================================================================
// Trace Tests
// =============================================================================

func TestTraceBuffer_BasicOperations(t *testing.T) {
	t.Parallel()

	tb := NewTraceBuffer("UART", "/dev/ttyUSB0", 10)

	// Record TX and RX
	tb.RecordTX([]byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00}, "Cmd 0x02")
	tb.RecordRX([]byte{0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00}, "ACK")
	tb.RecordRX([]byte{0x00, 0x00, 0xFF, 0x06, 0xFA, 0xD5, 0x03, 0x32, 0x01, 0x06, 0x07, 0xE8, 0x00}, "Response")

	// Wrap an error
	originalErr := errors.New("test error")
	wrappedErr := tb.WrapError(originalErr)

	// Verify it's a TraceableError
	var te *TraceableError
	if !errors.As(wrappedErr, &te) {
		t.Fatal("WrapError should return a TraceableError")
	}

	// Verify trace entries
	if len(te.Trace) != 3 {
		t.Errorf("Expected 3 trace entries, got %d", len(te.Trace))
	}

	// Verify first entry is TX
	if te.Trace[0].Direction != TraceTX {
		t.Errorf("First entry should be TX, got %v", te.Trace[0].Direction)
	}

	// Verify transport and port
	if te.Transport != "UART" {
		t.Errorf("Transport = %q, want %q", te.Transport, "UART")
	}
	if te.Port != "/dev/ttyUSB0" {
		t.Errorf("Port = %q, want %q", te.Port, "/dev/ttyUSB0")
	}
}

func TestTraceableError_Unwrap(t *testing.T) {
	t.Parallel()

	originalErr := ErrNoACK
	tb := NewTraceBuffer("I2C", "/dev/i2c-1", 10)
	tb.RecordTX([]byte{0x01, 0x02}, "test")
	wrappedErr := tb.WrapError(originalErr)

	// errors.Is should work through TraceableError
	if !errors.Is(wrappedErr, ErrNoACK) {
		t.Error("errors.Is should match underlying error through TraceableError")
	}

	// Unwrap should return original error
	var te *TraceableError
	if errors.As(wrappedErr, &te) {
		if !errors.Is(te.Unwrap(), originalErr) {
			t.Error("Unwrap should return the original error")
		}
	}
}

func TestTraceableError_FormatTrace(t *testing.T) {
	t.Parallel()

	tb := NewTraceBuffer("SPI", "/dev/spidev0.0", 10)
	tb.RecordTX([]byte{0xD4, 0x02}, "GetFirmware")
	tb.RecordRX([]byte{0xD5, 0x03, 0x32}, "Response")
	tb.RecordTimeout("No ACK")

	wrappedErr := tb.WrapError(errors.New("timeout"))

	var te *TraceableError
	if !errors.As(wrappedErr, &te) {
		t.Fatal("Expected TraceableError")
	}

	formatted := te.FormatTrace()

	// Should contain transport info
	if !strings.Contains(formatted, "SPI") {
		t.Error("FormatTrace should contain transport type")
	}

	// Should contain port
	if !strings.Contains(formatted, "/dev/spidev0.0") {
		t.Error("FormatTrace should contain port name")
	}

	// Should contain direction markers
	if !strings.Contains(formatted, ">") && !strings.Contains(formatted, "<") {
		t.Error("FormatTrace should contain direction markers")
	}

	// Should contain hex data
	if !strings.Contains(formatted, "D4") {
		t.Error("FormatTrace should contain hex-formatted data")
	}
}

func TestTraceBuffer_CircularBuffer(t *testing.T) {
	t.Parallel()

	// Create a small buffer
	tb := NewTraceBuffer("UART", "test", 3)

	// Add more entries than capacity
	tb.RecordTX([]byte{0x01}, "first")
	tb.RecordTX([]byte{0x02}, "second")
	tb.RecordTX([]byte{0x03}, "third")
	tb.RecordTX([]byte{0x04}, "fourth")

	wrappedErr := tb.WrapError(errors.New("test"))
	var te *TraceableError
	if !errors.As(wrappedErr, &te) {
		t.Fatal("Expected TraceableError")
	}

	// Should only have 3 entries (oldest evicted)
	if len(te.Trace) != 3 {
		t.Errorf("Expected 3 entries in circular buffer, got %d", len(te.Trace))
	}

	// First entry should be "second" (oldest non-evicted)
	if te.Trace[0].Note != "second" {
		t.Errorf("First entry should be 'second', got %q", te.Trace[0].Note)
	}

	// Last entry should be "fourth" (newest)
	if te.Trace[2].Note != "fourth" {
		t.Errorf("Last entry should be 'fourth', got %q", te.Trace[2].Note)
	}
}

func TestTraceBuffer_WrapNilError(t *testing.T) {
	t.Parallel()

	tb := NewTraceBuffer("UART", "test", 10)
	tb.RecordTX([]byte{0x01}, "test")

	// WrapError should return nil for nil error
	result := tb.WrapError(nil)
	if result != nil {
		t.Error("WrapError(nil) should return nil")
	}
}

func TestTraceBuffer_Clear(t *testing.T) {
	t.Parallel()

	tb := NewTraceBuffer("UART", "test", 10)
	tb.RecordTX([]byte{0x01}, "first")
	tb.RecordTX([]byte{0x02}, "second")

	tb.Clear()

	wrappedErr := tb.WrapError(errors.New("test"))
	var te *TraceableError
	if !errors.As(wrappedErr, &te) {
		t.Fatal("Expected TraceableError")
	}

	if len(te.Trace) != 0 {
		t.Errorf("Expected 0 entries after Clear, got %d", len(te.Trace))
	}
}

func TestHasTrace(t *testing.T) {
	t.Parallel()

	// Error with trace
	tb := NewTraceBuffer("UART", "test", 10)
	tb.RecordTX([]byte{0x01}, "test")
	withTrace := tb.WrapError(errors.New("test"))

	if !HasTrace(withTrace) {
		t.Error("HasTrace should return true for TraceableError")
	}

	// Error without trace
	withoutTrace := errors.New("plain error")
	if HasTrace(withoutTrace) {
		t.Error("HasTrace should return false for plain error")
	}

	// Nil error
	if HasTrace(nil) {
		t.Error("HasTrace should return false for nil")
	}
}

func TestGetTrace(t *testing.T) {
	t.Parallel()

	// Error with trace
	tb := NewTraceBuffer("UART", "test", 10)
	tb.RecordTX([]byte{0x01}, "test")
	withTrace := tb.WrapError(errors.New("test"))

	te := GetTrace(withTrace)
	if te == nil {
		t.Fatal("GetTrace should return TraceableError")
	}
	if te.Transport != "UART" {
		t.Errorf("Transport = %q, want %q", te.Transport, "UART")
	}

	// Error without trace
	withoutTrace := errors.New("plain error")
	if GetTrace(withoutTrace) != nil {
		t.Error("GetTrace should return nil for plain error")
	}

	// Nil error
	if GetTrace(nil) != nil {
		t.Error("GetTrace should return nil for nil")
	}
}

func TestTraceEntry_String(t *testing.T) {
	t.Parallel()

	entry := TraceEntry{
		Direction: TraceTX,
		Data:      []byte{0xD4, 0x02},
		Timestamp: time.Now(),
		Note:      "GetFirmware",
	}

	str := entry.String()

	if !strings.Contains(str, "TX") {
		t.Error("TraceEntry.String should contain direction")
	}
	if !strings.Contains(str, "D4") {
		t.Error("TraceEntry.String should contain hex data")
	}
	if !strings.Contains(str, "GetFirmware") {
		t.Error("TraceEntry.String should contain note")
	}
}

func TestFormatHexBytes_LongData(t *testing.T) {
	t.Parallel()

	// Create data longer than 32 bytes
	longData := make([]byte, 50)
	for i := range longData {
		longData[i] = byte(i)
	}

	formatted := formatHexBytes(longData)

	// Should be truncated
	if !strings.Contains(formatted, "...") {
		t.Error("Long data should be truncated with ellipsis")
	}
	if !strings.Contains(formatted, "50 bytes total") {
		t.Error("Should indicate total bytes")
	}
}

func TestFormatHexBytes_EmptyData(t *testing.T) {
	t.Parallel()

	formatted := formatHexBytes([]byte{})
	if formatted != "(empty)" {
		t.Errorf("Expected '(empty)', got %q", formatted)
	}
}

func TestTraceableError_Error(t *testing.T) {
	t.Parallel()

	originalErr := errors.New("original error message")
	tb := NewTraceBuffer("UART", "test", 10)
	wrappedErr := tb.WrapError(originalErr)

	// Error() should return the underlying error message
	if wrappedErr.Error() != originalErr.Error() {
		t.Errorf("Error() = %q, want %q", wrappedErr.Error(), originalErr.Error())
	}
}

func TestTraceableError_FormatTrace_Empty(t *testing.T) {
	t.Parallel()

	tb := NewTraceBuffer("UART", "/dev/ttyUSB0", 10)
	// Don't add any entries

	wrappedErr := tb.WrapError(errors.New("test"))
	var te *TraceableError
	if !errors.As(wrappedErr, &te) {
		t.Fatal("Expected TraceableError")
	}

	formatted := te.FormatTrace()
	if !strings.Contains(formatted, "no trace data") {
		t.Error("FormatTrace with empty trace should indicate no data")
	}
}

// =============================================================================
// IsPN532RFError Helper Tests
// =============================================================================

func TestIsPN532RFError_WithPN532Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		errorCode byte
		wantRF    bool
	}{
		// RF error codes - should return true
		{name: "CRC error", errorCode: 0x02, wantRF: true},
		{name: "parity error", errorCode: 0x03, wantRF: true},
		{name: "framing error", errorCode: 0x05, wantRF: true},
		{name: "RF field not activated", errorCode: 0x0A, wantRF: true},
		{name: "RF protocol error", errorCode: 0x0B, wantRF: true},
		{name: "target released by initiator", errorCode: 0x29, wantRF: true},
		{name: "card disappeared", errorCode: 0x2B, wantRF: true},

		// Non-RF error codes - should return false
		{name: "timeout error", errorCode: 0x01, wantRF: false},
		{name: "erroneous bit count", errorCode: 0x04, wantRF: false},
		{name: "buffer overflow", errorCode: 0x09, wantRF: false},
		{name: "invalid parameter", errorCode: 0x10, wantRF: false},
		{name: "authentication error", errorCode: 0x14, wantRF: false},
		{name: "command not supported", errorCode: 0x81, wantRF: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := NewPN532Error(tt.errorCode, "TestCommand", "")
			got := IsPN532RFError(err)
			if got != tt.wantRF {
				t.Errorf("IsPN532RFError() = %v, want %v", got, tt.wantRF)
			}
		})
	}
}

func TestIsPN532RFError_WithWrappedError(t *testing.T) {
	t.Parallel()

	// Create an RF error and wrap it
	rfErr := NewPN532Error(0x02, "InDataExchange", "CRC check failed")
	wrappedErr := fmt.Errorf("operation failed: %w", rfErr)
	doubleWrapped := fmt.Errorf("tag read: %w", wrappedErr)

	// Should work through error wrapping
	if !IsPN532RFError(wrappedErr) {
		t.Error("IsPN532RFError should detect wrapped RF error")
	}
	if !IsPN532RFError(doubleWrapped) {
		t.Error("IsPN532RFError should detect double-wrapped RF error")
	}
}

func TestIsPN532RFError_WithNonPN532Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err  error
		name string
	}{
		{name: "transport timeout", err: ErrTransportTimeout},
		{name: "transport read", err: ErrTransportRead},
		{name: "frame corrupted", err: ErrFrameCorrupted},
		{name: "generic error", err: errors.New("some error")},
		{name: "wrapped generic error", err: fmt.Errorf("context: %w", errors.New("inner"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if IsPN532RFError(tt.err) {
				t.Errorf("IsPN532RFError should return false for %s", tt.name)
			}
		})
	}
}

func TestIsPN532RFError_NilError(t *testing.T) {
	t.Parallel()

	if IsPN532RFError(nil) {
		t.Error("IsPN532RFError should return false for nil error")
	}
}
