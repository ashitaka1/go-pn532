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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRetryConstants_ConnectionValues verifies connection retry constants
// are within reasonable bounds for NFC operations.
func TestRetryConstants_ConnectionValues(t *testing.T) {
	t.Parallel()

	// DefaultConnectionRetries should be at least 1, at most 10
	assert.GreaterOrEqual(t, DefaultConnectionRetries, 1,
		"DefaultConnectionRetries should be at least 1")
	assert.LessOrEqual(t, DefaultConnectionRetries, 10,
		"DefaultConnectionRetries should not exceed 10")

	// ConnectionInitialBackoff should be between 50ms and 500ms
	// Per NFC industry standards, 100ms is typical baseline
	assert.GreaterOrEqual(t, ConnectionInitialBackoff, 50*time.Millisecond,
		"ConnectionInitialBackoff should be at least 50ms")
	assert.LessOrEqual(t, ConnectionInitialBackoff, 500*time.Millisecond,
		"ConnectionInitialBackoff should not exceed 500ms")

	// ConnectionMaxBackoff should be greater than initial backoff
	assert.Greater(t, ConnectionMaxBackoff, ConnectionInitialBackoff,
		"ConnectionMaxBackoff should be greater than initial backoff")

	// ConnectionBackoffMultiplier should be between 1.5 and 3.0
	assert.GreaterOrEqual(t, ConnectionBackoffMultiplier, 1.5,
		"ConnectionBackoffMultiplier should be at least 1.5")
	assert.LessOrEqual(t, ConnectionBackoffMultiplier, 3.0,
		"ConnectionBackoffMultiplier should not exceed 3.0")

	// ConnectionJitter should be between 0 and 0.5
	assert.GreaterOrEqual(t, ConnectionJitter, 0.0,
		"ConnectionJitter should be non-negative")
	assert.LessOrEqual(t, ConnectionJitter, 0.5,
		"ConnectionJitter should not exceed 0.5")

	// ConnectionRetryTimeout should allow for multiple retry attempts
	minExpectedTimeout := time.Duration(DefaultConnectionRetries) * ConnectionInitialBackoff
	assert.Greater(t, ConnectionRetryTimeout, minExpectedTimeout,
		"ConnectionRetryTimeout should allow for multiple attempts")
}

// TestRetryConstants_PN532Hardware verifies PN532 hardware retry parameters
// match expected values per PN532 datasheet.
func TestRetryConstants_PN532Hardware(t *testing.T) {
	t.Parallel()

	// DefaultPassiveActivationRetries: Each retry is ~100ms per datasheet
	// 0x0A (10) provides ~1 second timeout
	assert.Equal(t, DefaultPassiveActivationRetries, byte(0x0A),
		"DefaultPassiveActivationRetries should be 0x0A (10) for ~1s timeout")

	// DefaultPollingRetries: 0x20 (32) provides approximately 4.8 seconds
	// (32 * 150ms per retry per datasheet)
	assert.Equal(t, DefaultPollingRetries, byte(0x20),
		"DefaultPollingRetries should be 0x20 (32) for ~4.8s polling timeout")

	// Verify values are non-zero (disabled would be 0xFF)
	assert.NotEqual(t, DefaultPassiveActivationRetries, byte(0xFF),
		"DefaultPassiveActivationRetries should not be disabled (0xFF)")
	assert.NotEqual(t, DefaultPollingRetries, byte(0xFF),
		"DefaultPollingRetries should not be disabled (0xFF)")
}

// TestRetryConstants_NTAGOperations verifies NTAG read/write retry constants.
func TestRetryConstants_NTAGOperations(t *testing.T) {
	t.Parallel()

	// Block read retries should be at least 2
	assert.GreaterOrEqual(t, NTAGBlockReadRetries, 2,
		"NTAGBlockReadRetries should be at least 2 for reliability")
	assert.LessOrEqual(t, NTAGBlockReadRetries, 10,
		"NTAGBlockReadRetries should not exceed 10")

	// Fallback retries should be at least 2
	assert.GreaterOrEqual(t, NTAGFallbackRetries, 2,
		"NTAGFallbackRetries should be at least 2")
	assert.LessOrEqual(t, NTAGFallbackRetries, 10,
		"NTAGFallbackRetries should not exceed 10")

	// Timeout retry delay should be between 50ms and 500ms
	assert.GreaterOrEqual(t, NTAGTimeoutRetryDelay, 50*time.Millisecond,
		"NTAGTimeoutRetryDelay should be at least 50ms")
	assert.LessOrEqual(t, NTAGTimeoutRetryDelay, 500*time.Millisecond,
		"NTAGTimeoutRetryDelay should not exceed 500ms")
}

// TestRetryConstants_NDEFBackoff verifies NDEF exponential backoff pattern.
func TestRetryConstants_NDEFBackoff(t *testing.T) {
	t.Parallel()

	// Max retries should be at least 2
	assert.GreaterOrEqual(t, NDEFMaxRetries, 2,
		"NDEFMaxRetries should be at least 2")
	assert.LessOrEqual(t, NDEFMaxRetries, 10,
		"NDEFMaxRetries should not exceed 10")

	// Verify exponential backoff pattern: each delay should be >= previous
	assert.LessOrEqual(t, NDEFRetryDelay1, NDEFRetryDelay2,
		"NDEFRetryDelay2 should be >= NDEFRetryDelay1 (exponential backoff)")
	assert.LessOrEqual(t, NDEFRetryDelay2, NDEFRetryDelay3,
		"NDEFRetryDelay3 should be >= NDEFRetryDelay2 (exponential backoff)")

	// Verify 2x exponential backoff pattern: 100ms → 200ms → 400ms
	assert.Equal(t, 100*time.Millisecond, NDEFRetryDelay1,
		"NDEFRetryDelay1 should be 100ms")
	assert.Equal(t, 200*time.Millisecond, NDEFRetryDelay2,
		"NDEFRetryDelay2 should be 200ms (2x delay1)")
	assert.Equal(t, 400*time.Millisecond, NDEFRetryDelay3,
		"NDEFRetryDelay3 should be 400ms (2x delay2)")
}

// TestRetryConstants_TransportValues verifies low-level transport retry limits.
func TestRetryConstants_TransportValues(t *testing.T) {
	t.Parallel()

	// ACK retries should be at least 2
	assert.GreaterOrEqual(t, TransportACKRetries, 2,
		"TransportACKRetries should be at least 2")
	assert.LessOrEqual(t, TransportACKRetries, 10,
		"TransportACKRetries should not exceed 10")

	// Drain retries should be at least 2
	assert.GreaterOrEqual(t, TransportDrainRetries, 2,
		"TransportDrainRetries should be at least 2")

	// Wakeup retries should be at least 2
	assert.GreaterOrEqual(t, TransportWakeupRetries, 2,
		"TransportWakeupRetries should be at least 2")

	// I2C needs more retries due to clock stretching
	assert.GreaterOrEqual(t, TransportI2CFrameRetries, TransportACKRetries,
		"TransportI2CFrameRetries should be >= TransportACKRetries")
}

// TestRetryConstants_UARTWakeupProgression verifies UART wakeup delays
// use progressive timing for different sleep states.
func TestRetryConstants_UARTWakeupProgression(t *testing.T) {
	t.Parallel()

	// Verify progressive timing pattern: each delay should be > previous
	assert.Less(t, UARTWakeupDelay1, UARTWakeupDelay2,
		"UARTWakeupDelay2 should be > UARTWakeupDelay1 (progressive)")
	assert.Less(t, UARTWakeupDelay2, UARTWakeupDelay3,
		"UARTWakeupDelay3 should be > UARTWakeupDelay2 (progressive)")

	// Verify expected values: 10ms → 50ms → 100ms
	assert.Equal(t, 10*time.Millisecond, UARTWakeupDelay1,
		"UARTWakeupDelay1 should be 10ms")
	assert.Equal(t, 50*time.Millisecond, UARTWakeupDelay2,
		"UARTWakeupDelay2 should be 50ms")
	assert.Equal(t, 100*time.Millisecond, UARTWakeupDelay3,
		"UARTWakeupDelay3 should be 100ms")

	// ACK delays should also be progressive
	assert.Less(t, TransportACKDelay1, TransportACKDelay2,
		"TransportACKDelay2 should be > TransportACKDelay1")
	assert.Less(t, TransportACKDelay2, TransportACKDelay3,
		"TransportACKDelay3 should be > TransportACKDelay2")

	// Verify ACK delay values: 50ms → 100ms → 200ms
	assert.Equal(t, 50*time.Millisecond, TransportACKDelay1,
		"TransportACKDelay1 should be 50ms")
	assert.Equal(t, 100*time.Millisecond, TransportACKDelay2,
		"TransportACKDelay2 should be 100ms")
	assert.Equal(t, 200*time.Millisecond, TransportACKDelay3,
		"TransportACKDelay3 should be 200ms")
}
