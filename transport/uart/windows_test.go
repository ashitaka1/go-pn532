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
}
