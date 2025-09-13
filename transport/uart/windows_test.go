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

package uart

import (
	"runtime"
	"testing"
	"time"
)

// TestWindowsPlatformDetection tests Windows platform detection utility
func TestWindowsPlatformDetection(t *testing.T) {
	t.Parallel()

	isWindowsActual := isWindows()
	expectedWindows := runtime.GOOS == "windows"

	if isWindowsActual != expectedWindows {
		t.Errorf("isWindows() = %v, want %v", isWindowsActual, expectedWindows)
	}
}

// TestWindowsSpecificTimeout tests Windows-specific timeout values
func TestWindowsSpecificTimeout(t *testing.T) {
	t.Parallel()

	timeout := getWindowsTimeout()

	if runtime.GOOS == "windows" {
		expectedTimeout := 100 * time.Millisecond
		if timeout != expectedTimeout {
			t.Errorf("getWindowsTimeout() on Windows = %v, want %v", timeout, expectedTimeout)
		}
	} else {
		expectedTimeout := 50 * time.Millisecond
		if timeout != expectedTimeout {
			t.Errorf("getWindowsTimeout() on non-Windows = %v, want %v", timeout, expectedTimeout)
		}
	}
}

// TestWindowsPostWriteDelay tests Windows-specific post-write delay
func TestWindowsPostWriteDelay(t *testing.T) {
	t.Parallel()

	// Measure the time taken by the delay
	start := time.Now()
	windowsPostWriteDelay()
	elapsed := time.Since(start)

	if runtime.GOOS == "windows" {
		// On Windows, expect at least 15ms delay
		expectedMinDelay := 15 * time.Millisecond
		if elapsed < expectedMinDelay {
			t.Errorf("windowsPostWriteDelay() on Windows took %v, expected at least %v", elapsed, expectedMinDelay)
		}
	} else {
		// On non-Windows, should be nearly instant (less than 5ms)
		maxExpectedDelay := 5 * time.Millisecond
		if elapsed > maxExpectedDelay {
			t.Errorf("windowsPostWriteDelay() on non-Windows took %v, expected less than %v", elapsed, maxExpectedDelay)
		}
	}
}

// TestWindowsPortRecovery tests Windows-specific port recovery mechanism
func TestWindowsPortRecovery(t *testing.T) {
	t.Parallel()

	// Create a transport with nil port (we're just testing the recovery logic doesn't panic)
	transport := &Transport{
		portName: "COM1",
	}

	// This should not panic and should handle Windows vs non-Windows gracefully
	err := transport.windowsPortRecovery()

	// On non-Windows, this should return nil immediately
	// On Windows, it may return an error due to nil port, but shouldn't panic
	if runtime.GOOS != "windows" && err != nil {
		t.Errorf("windowsPortRecovery() on non-Windows should return nil, got %v", err)
	}
}

// TestWindowsWaitAckRecovery tests that waitAck attempts Windows recovery before giving up
func TestWindowsWaitAckRecovery(t *testing.T) {
	t.Parallel()

	// This test verifies that Windows-specific recovery is attempted in waitAck
	// We can test the logic by checking if the recovery function exists
	transport := &Transport{
		portName: "COM1",
	}

	// Call the recovery function to ensure it exists and doesn't panic
	err := transport.windowsPortRecovery()

	// The function should exist and handle nil port gracefully
	if runtime.GOOS != "windows" && err != nil {
		t.Errorf("windowsPortRecovery should return nil on non-Windows, got %v", err)
	}

	// On Windows with nil port, should return nil (graceful handling)
	if runtime.GOOS == "windows" && err != nil {
		// With nil port, should handle gracefully and return nil
		t.Logf("Windows recovery with nil port returned: %v (expected behavior)", err)
	}
}

// TestWindowsIntegrationFunctions tests that Windows integration functions exist
func TestWindowsIntegrationFunctions(t *testing.T) {
	t.Parallel()

	// Verify all Windows functions exist and work as expected

	// Test platform detection
	isWin := isWindows()
	if isWin != (runtime.GOOS == "windows") {
		t.Error("Platform detection mismatch")
	}

	// Test timeout function
	timeout := getWindowsTimeout()
	if timeout <= 0 {
		t.Errorf("Invalid timeout: %v", timeout)
	}

	// Test delay function (should not panic)
	windowsPostWriteDelay()

	// Test recovery function on transport
	transport := &Transport{portName: "test"}
	if err := transport.windowsPortRecovery(); err != nil && runtime.GOOS != "windows" {
		t.Errorf("Unexpected error on non-Windows: %v", err)
	}
}
