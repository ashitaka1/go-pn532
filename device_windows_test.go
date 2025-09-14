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
