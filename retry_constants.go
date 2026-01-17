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

import "time"

// Connection retry constants control device connection behavior.
const (
	// DefaultConnectionRetries is the number of attempts to connect to a device.
	DefaultConnectionRetries = 3
	// ConnectionInitialBackoff is the initial delay between connection attempts.
	// Industry standard is 100ms baseline for NFC operations.
	ConnectionInitialBackoff = 100 * time.Millisecond
	// ConnectionMaxBackoff is the maximum delay between connection attempts.
	ConnectionMaxBackoff = 500 * time.Millisecond
	// ConnectionBackoffMultiplier is the exponential backoff multiplier.
	ConnectionBackoffMultiplier = 2.0
	// ConnectionJitter is the random jitter factor (0.0-1.0) to prevent thundering herd.
	ConnectionJitter = 0.1
	// ConnectionRetryTimeout is the overall timeout for all connection attempts.
	ConnectionRetryTimeout = 10 * time.Second
)

// PN532 hardware retry constants (MxRty parameters) control the PN532 chip's
// internal retry behavior for RF operations.
const (
	// DefaultPassiveActivationRetries controls InListPassiveTarget internal retries.
	// Each retry is approximately 100ms per PN532 datasheet.
	// 0x0A (10) provides ~1 second timeout before giving up.
	DefaultPassiveActivationRetries byte = 0x0A

	// DefaultPollingRetries controls MxRtyATR for polling loops.
	// 0x20 (32) provides approximately 4.8 seconds (32 * 150ms per retry).
	DefaultPollingRetries byte = 0x20
)

// Tag operation retry constants control NTAG read/write retry behavior.
const (
	// NTAGBlockReadRetries is the number of attempts for block read operations.
	NTAGBlockReadRetries = 3
	// NTAGFallbackRetries is the number of attempts when using InCommunicateThru fallback.
	NTAGFallbackRetries = 3
	// NTAGTimeoutRetryDelay is the delay before retrying after a timeout error.
	NTAGTimeoutRetryDelay = 100 * time.Millisecond
)

// NDEF operation retry constants control NDEF read/write retry behavior.
// Uses 2x exponential backoff: 100ms → 200ms → 400ms.
const (
	// NDEFMaxRetries is the number of attempts for NDEF operations.
	NDEFMaxRetries = 3
	// NDEFRetryDelay1 is the delay before the first retry (after initial attempt).
	NDEFRetryDelay1 = 100 * time.Millisecond
	// NDEFRetryDelay2 is the delay before the second retry.
	NDEFRetryDelay2 = 200 * time.Millisecond
	// NDEFRetryDelay3 is the delay before the third retry.
	NDEFRetryDelay3 = 400 * time.Millisecond
)

// Transport retry constants control low-level transport communication.
const (
	// TransportACKRetries is the number of attempts to receive ACK from PN532.
	TransportACKRetries = 3
	// TransportDrainRetries is the number of attempts to drain stale data from buffer.
	TransportDrainRetries = 3
	// TransportWakeupRetries is the number of attempts to wake the PN532 from sleep.
	TransportWakeupRetries = 3
	// TransportI2CFrameRetries is the number of attempts for I2C frame reception.
	// I2C needs more retries due to clock stretching and bus arbitration.
	TransportI2CFrameRetries = 5
)

// UART wakeup delays use progressive timing to handle different sleep states.
const (
	// UARTWakeupDelay1 is the initial wakeup delay.
	UARTWakeupDelay1 = 10 * time.Millisecond
	// UARTWakeupDelay2 is the second wakeup delay (deeper sleep).
	UARTWakeupDelay2 = 50 * time.Millisecond
	// UARTWakeupDelay3 is the final wakeup delay (deepest sleep).
	UARTWakeupDelay3 = 100 * time.Millisecond
)

// Transport ACK delays for I2C and SPI use progressive timing.
const (
	// TransportACKDelay1 is the initial ACK wait delay.
	TransportACKDelay1 = 50 * time.Millisecond
	// TransportACKDelay2 is the second ACK wait delay.
	TransportACKDelay2 = 100 * time.Millisecond
	// TransportACKDelay3 is the final ACK wait delay.
	TransportACKDelay3 = 200 * time.Millisecond

	// TransportACKTimeout is the maximum time to wait for an ACK response.
	// ACKs should arrive quickly - this timeout catches device lockups fast.
	// Note: This caps the per-retry ACK wait; total time = ACKTimeout * ACKRetries.
	TransportACKTimeout = 500 * time.Millisecond
)
