// Copyright 2025 The Zaparoo Project Contributors.
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

package uart

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestUARTContextCancellationDuringDelay tests that UART transport
// properly handles context cancellation during hardware delays
func TestUARTContextCancellationDuringDelay(t *testing.T) {
	t.Parallel()
	// This test verifies that context cancellation is checked before operations

	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Create a transport instance
	transport := &Transport{}

	cmd := byte(0x02) // GetFirmwareVersion
	args := []byte{}

	start := time.Now()
	_, err := transport.SendCommandWithContext(ctx, cmd, args)
	elapsed := time.Since(start)

	// We expect this to return context.Canceled immediately
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}

	// The operation should return immediately (< 10ms)
	if elapsed > 10*time.Millisecond {
		t.Errorf("Operation took too long: %v, expected < 10ms for immediate cancellation", elapsed)
	}
}

// TestUARTContextTimeoutDuringOperation tests that context timeout
// interrupts operations that would normally take longer
func TestUARTContextTimeoutDuringOperation(t *testing.T) {
	t.Parallel()
	// This test verifies that context timeout interrupts long-running operations
	// The goal is to ensure delays and timeouts in UART operations respect context

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Create a transport instance
	transport := &Transport{}

	cmd := byte(0x02) // GetFirmwareVersion
	args := []byte{}

	start := time.Now()
	_, err := transport.SendCommandWithContext(ctx, cmd, args)
	elapsed := time.Since(start)

	// We expect this to return context.DeadlineExceeded due to timeout
	if err == nil {
		t.Error("Expected context timeout error, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded error, got: %v", err)
	}

	// The operation should timeout within reasonable time of the context deadline
	// (should be ~50ms, but allow some margin for test execution time)
	if elapsed < 40*time.Millisecond || elapsed > 150*time.Millisecond {
		t.Errorf("Operation timing unexpected: %v, expected ~50ms ± 50ms for context timeout", elapsed)
	}
}
