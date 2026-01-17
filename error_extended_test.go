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
	"testing"
)

func TestErrorWrapping(t *testing.T) {
	t.Parallel()
	baseErr := ErrTransportTimeout

	tests := []struct {
		wrapFunc      func(error) error
		name          string
		wantRetryable bool
	}{
		{
			name: "fmt.Errorf wrapping",
			wrapFunc: func(err error) error {
				return fmt.Errorf("operation failed: %w", err)
			},
			wantRetryable: true,
		},
		{
			name: "double wrapping",
			wrapFunc: func(err error) error {
				wrapped := fmt.Errorf("inner error: %w", err)
				return fmt.Errorf("outer error: %w", wrapped)
			},
			wantRetryable: true,
		},
		{
			name: "custom wrapper",
			wrapFunc: func(err error) error {
				return &customError{msg: "custom wrapper", cause: err}
			},
			wantRetryable: true, // Should still detect wrapped retryable error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			wrappedErr := tt.wrapFunc(baseErr)

			// Test retryable detection
			gotRetryable := IsRetryable(wrappedErr)
			if gotRetryable != tt.wantRetryable {
				t.Errorf("IsRetryable() = %v, want %v", gotRetryable, tt.wantRetryable)
			}

			// Test that original error is still accessible
			if !errors.Is(wrappedErr, baseErr) {
				t.Error("errors.Is() = false, want true for base error")
			}
		})
	}
}

type customError struct {
	cause error
	msg   string
}

func (e *customError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.msg, e.cause)
	}
	return e.msg
}

func (e *customError) Unwrap() error {
	return e.cause
}

func TestErrorUnwrapping(t *testing.T) {
	t.Parallel()
	original := ErrFrameCorrupted
	wrapped := fmt.Errorf("context: %w", original)
	doubleWrapped := fmt.Errorf("more context: %w", wrapped)

	tests := []struct {
		err      error
		expected error
		name     string
	}{
		{
			name:     "unwrap once",
			err:      wrapped,
			expected: original,
		},
		{
			name:     "unwrap twice",
			err:      doubleWrapped,
			expected: original, // Should find the original through chain
		},
		{
			name:     "no wrapping",
			err:      original,
			expected: original,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Test errors.Is traverses the chain
			if !errors.Is(tt.err, tt.expected) {
				t.Error("errors.Is() = false, want true")
			}
		})
	}
}

func TestTransportErrorWrapping(t *testing.T) {
	t.Parallel()
	baseErr := errors.New("connection refused")
	transportErr := &TransportError{
		Err:       baseErr,
		Op:        "connect",
		Port:      "/dev/ttyUSB0",
		Type:      ErrorTypePermanent,
		Retryable: false,
	}

	wrappedErr := fmt.Errorf("device initialization failed: %w", transportErr)

	// Test that transport error is still detectable
	var te *TransportError
	if !errors.As(wrappedErr, &te) {
		t.Fatal("errors.As() failed to find TransportError")
	}

	// Test transport error properties are preserved
	if te.Op != "connect" {
		t.Errorf("Op = %q, want %q", te.Op, "connect")
	}
	if te.Port != "/dev/ttyUSB0" {
		t.Errorf("Port = %q, want %q", te.Port, "/dev/ttyUSB0")
	}
	if te.Type != ErrorTypePermanent {
		t.Errorf("Type = %v, want %v", te.Type, ErrorTypePermanent)
	}

	// Test that the original base error is still accessible
	if !errors.Is(wrappedErr, baseErr) {
		t.Error("errors.Is() failed to find base error")
	}
}

func TestErrorChainRetryability(t *testing.T) {
	t.Parallel()
	tests := []struct {
		errorChain    func() error
		name          string
		wantRetryable bool
	}{
		{
			name: "retryable at root",
			errorChain: func() error {
				return fmt.Errorf("context: %w", ErrTransportRead)
			},
			wantRetryable: true,
		},
		{
			name: "non-retryable at root",
			errorChain: func() error {
				return fmt.Errorf("context: %w", ErrDeviceNotFound)
			},
			wantRetryable: false,
		},
		{
			name: "mixed chain with retryable",
			errorChain: func() error {
				base := ErrFrameCorrupted
				wrapped := fmt.Errorf("command failed: %w", base)
				return fmt.Errorf("operation failed: %w", wrapped)
			},
			wantRetryable: true,
		},
		{
			name: "transport error in chain",
			errorChain: func() error {
				transportErr := &TransportError{
					Err:       ErrTransportTimeout,
					Op:        "read",
					Port:      "/dev/ttyUSB0",
					Type:      ErrorTypeTimeout,
					Retryable: true,
				}
				return fmt.Errorf("device error: %w", transportErr)
			},
			wantRetryable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.errorChain()
			got := IsRetryable(err)
			if got != tt.wantRetryable {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.wantRetryable)
			}
		})
	}
}

func TestErrorStringPropagation(t *testing.T) {
	t.Parallel()
	baseErr := ErrTransportRead
	contextErr := fmt.Errorf("failed to read from device: %w", baseErr)
	outerErr := fmt.Errorf("tag detection failed: %w", contextErr)

	errorStr := outerErr.Error()

	// Check that all context is preserved in the error string
	expectedParts := []string{
		"tag detection failed",
		"failed to read from device",
		"transport read failed",
	}

	for _, part := range expectedParts {
		if !strings.Contains(errorStr, part) {
			t.Errorf("Error string %q should contain %q", errorStr, part)
		}
	}
}

func TestComplexErrorScenarios(t *testing.T) {
	t.Parallel()

	tests := getComplexErrorTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.buildError()

			validateErrorExpectations(t, err, tt.expectIs)
			logErrorTypes(t, err)
			validateErrorProperties(t, errorProperties{
				err:       err,
				retryable: tt.retryable,
			})
		})
	}
}

func getComplexErrorTestCases() []struct {
	name       string
	buildError func() error
	expectIs   []error
	expectAs   []any
	retryable  bool
} {
	return []struct {
		name       string
		buildError func() error
		expectIs   []error
		expectAs   []any
		retryable  bool
	}{
		{
			name: "transport error wrapped multiple times",
			buildError: func() error {
				te := NewTimeoutError("read", "/dev/ttyUSB0")
				wrapped := fmt.Errorf("command timeout: %w", te)
				return fmt.Errorf("device communication failed: %w", wrapped)
			},
			expectIs:  []error{},
			expectAs:  []any{},
			retryable: true,
		},
		{
			name: "custom error with transport error",
			buildError: func() error {
				te := NewFrameCorruptedError("read", "/dev/ttyUSB0")
				custom := &customError{msg: "custom error", cause: te}
				return fmt.Errorf("operation failed: %w", custom)
			},
			expectIs:  []error{},
			expectAs:  []any{},
			retryable: true,
		},
	}
}

func validateErrorExpectations(t *testing.T, err error, expectedErrors []error) {
	for _, expectedErr := range expectedErrors {
		if !errors.Is(err, expectedErr) {
			t.Errorf("errors.Is() = false for %v", expectedErr)
		}
	}
}

func logErrorTypes(t *testing.T, err error) {
	var te *TransportError
	if errors.As(err, &te) {
		t.Logf("Found TransportError: %v", te)
	}

	var ce *customError
	if errors.As(err, &ce) {
		t.Logf("Found customError: %v", ce)
	}
}

type errorProperties struct {
	err       error
	retryable bool
}

func validateErrorProperties(t *testing.T, props errorProperties) {
	if IsRetryable(props.err) != props.retryable {
		t.Errorf("IsRetryable() = %v, want %v", IsRetryable(props.err), props.retryable)
	}
}
