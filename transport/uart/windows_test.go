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

// TestUnifiedTimeout tests the unified timeout value for all platforms
func TestUnifiedTimeout(t *testing.T) {
	t.Parallel()

	timeout := getReadTimeout()
	expectedTimeout := 100 * time.Millisecond

	if timeout != expectedTimeout {
		t.Errorf("getReadTimeout() = %v, want %v", timeout, expectedTimeout)
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
	timeout := getReadTimeout()
	if timeout <= 0 {
		t.Errorf("Invalid timeout: %v", timeout)
	}

	// Test delay function (should not panic)
	windowsPostWriteDelay()
}
