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

package i2c

import (
	"context"
	"errors"
	"testing"
)

// TestI2CContextCancellation tests that I2C transport
// properly handles context cancellation
func TestI2CContextCancellation(t *testing.T) {
	t.Parallel()
	// This test verifies that context cancellation is checked before operations

	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Create a transport instance
	transport := &Transport{}

	cmd := byte(0x02) // GetFirmwareVersion
	args := []byte{}

	_, err := transport.SendCommandWithContext(ctx, cmd, args)

	// We expect this to return context.Canceled immediately
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}
}
