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

package polling

import "time"

// Config holds polling configuration options
type Config struct {
	PollInterval       time.Duration
	CardRemovalTimeout time.Duration
	// HardwareTimeoutRetries controls how long PN532 waits for card detection
	// 0x00 = immediate return, 0x01-0xFE = retry count (~150ms each), 0xFF = infinite
	// Higher values reduce LED blinking frequency but increase detection latency
	HardwareTimeoutRetries byte
}

// DefaultConfig returns the default polling configuration
func DefaultConfig() *Config {
	return &Config{
		PollInterval:           250 * time.Millisecond,
		CardRemovalTimeout:     600 * time.Millisecond,
		HardwareTimeoutRetries: 0x20, // ~4.8s timeout (32 * 150ms) for reduced LED blinking
	}
}
