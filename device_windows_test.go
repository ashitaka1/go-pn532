// go-pn532
// Copyright (c) 2025 The Zaparoo Project Contributors.
// SPDX-License-Identifier: LGPL-3.0-or-later

package pn532

import (
	"context"
	"runtime"
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

	device := NewDevice(transport)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This should fail initially since we haven't implemented retry yet
	err := device.InitContext(ctx)

	// Currently this will fail - we expect this test to fail until we implement retry
	if err == nil {
		t.Errorf("Expected SAM configuration to fail initially (before retry implementation)")
	}

	// Verify the error message contains the expected text
	if err != nil && !strings.Contains(err.Error(), "SAM configuration failed") {
		t.Errorf("Expected 'SAM configuration failed' error, got: %v", err)
	}
}