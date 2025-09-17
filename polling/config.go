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
