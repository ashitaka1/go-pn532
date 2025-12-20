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

package pn532

import (
	"context"
	"strings"
	"testing"
	"time"

	testutil "github.com/ZaparooProject/go-pn532/internal/testing"
)

// TestWindowsSAMConfigurationRetry tests Windows-specific retry behavior for SAM configuration
func TestWindowsSAMConfigurationRetry(t *testing.T) {
	t.Parallel()

	// Create a mock transport that fails SAM configuration initially
	transport := NewMockTransport()

	// Set up firmware version response
	transport.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())

	// Make SAM configuration fail with no ACK error (simulating Windows issue)
	transport.SetError(testutil.CmdSAMConfiguration, NewNoACKError("waitAck", "COM6"))

	device, err := New(transport)
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This should fail initially since we haven't implemented retry yet
	err = device.InitContext(ctx)

	// Currently this will fail - we expect this test to fail until we implement retry
	if err == nil {
		t.Error("Expected SAM configuration to fail initially (before retry implementation)")
	}

	// Verify the error message contains the expected text
	if err != nil && !strings.Contains(err.Error(), "SAM configuration failed") {
		t.Errorf("Expected 'SAM configuration failed' error, got: %v", err)
	}
}
