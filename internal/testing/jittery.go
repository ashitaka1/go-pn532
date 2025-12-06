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

package testing

import (
	"io"
	"math/rand/v2"
	"time"
)

// JitterConfig configures the behavior of JitteryConnection.
type JitterConfig struct {
	MaxLatencyMs      int
	FragmentMinBytes  int
	StallAfterBytes   int
	StallDuration     time.Duration
	Seed              uint64
	FragmentReads     bool
	USBBoundaryStress bool
}

// DefaultJitterConfig returns a sensible default configuration for testing.
func DefaultJitterConfig() JitterConfig {
	return JitterConfig{
		MaxLatencyMs:     20,
		FragmentReads:    true,
		FragmentMinBytes: 1,
	}
}

// JitteryConnection wraps an io.ReadWriter to simulate real-world transport
// conditions like USB-UART bridges (FTDI, CH340) with unpredictable latency
// and fragmented data delivery.
//
// This is useful for testing parser robustness, timeout handling, and race
// conditions that only manifest with realistic timing.
type JitteryConnection struct {
	backend             io.ReadWriter
	rng                 *rand.Rand
	config              JitterConfig
	bytesReadSinceStall int
	stallTriggered      bool
}

// NewJitteryConnection wraps a backend io.ReadWriter with jitter simulation.
func NewJitteryConnection(backend io.ReadWriter, config JitterConfig) *JitteryConnection {
	var rng *rand.Rand
	if config.Seed != 0 {
		rng = rand.New(rand.NewPCG(config.Seed, config.Seed^0xDEADBEEF)) //nolint:gosec // Test code, not crypto
	} else {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())) //nolint:gosec // Test code, not crypto
	}

	if config.FragmentMinBytes < 1 {
		config.FragmentMinBytes = 1
	}

	return &JitteryConnection{
		backend: backend,
		config:  config,
		rng:     rng,
	}
}

// Write passes writes through to the backend without modification.
// Jitter only affects reads to simulate realistic UART/USB behavior.
func (j *JitteryConnection) Write(data []byte) (int, error) {
	return j.backend.Write(data) //nolint:wrapcheck // Pass-through wrapper
}

// Read reads from the backend with simulated jitter and fragmentation.
//
//nolint:gocognit,gocyclo,cyclop,revive // Jitter simulation inherently requires multiple conditions
func (j *JitteryConnection) Read(buf []byte) (int, error) {
	// Add random latency before reading
	if j.config.MaxLatencyMs > 0 {
		delay := time.Duration(j.rng.IntN(j.config.MaxLatencyMs+1)) * time.Millisecond
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	// Check if we need to stall (buffer boundary stress)
	if j.config.StallAfterBytes > 0 && !j.stallTriggered &&
		j.bytesReadSinceStall >= j.config.StallAfterBytes {
		j.stallTriggered = true
		if j.config.StallDuration > 0 {
			time.Sleep(j.config.StallDuration)
		}
	}

	// Read from backend
	bytesRead, err := j.backend.Read(buf)
	if err != nil || bytesRead == 0 {
		return bytesRead, err //nolint:wrapcheck // Pass-through wrapper
	}

	// Apply fragmentation strategies
	actualN := bytesRead

	// USB boundary stress: fragment at 64-byte boundaries
	if j.config.USBBoundaryStress && bytesRead > 64 {
		// Return up to the next 64-byte boundary
		boundary := ((j.bytesReadSinceStall + 64) / 64) * 64
		remaining := boundary - j.bytesReadSinceStall
		if remaining > 0 && remaining < bytesRead {
			actualN = remaining
		}
	}

	// Random fragmentation
	if j.config.FragmentReads && actualN > j.config.FragmentMinBytes {
		// Return between FragmentMinBytes and actualN bytes
		maxReturn := actualN
		minReturn := j.config.FragmentMinBytes
		if minReturn >= maxReturn {
			actualN = maxReturn
		} else {
			actualN = minReturn + j.rng.IntN(maxReturn-minReturn+1)
		}
	}

	// Track bytes for stall logic
	j.bytesReadSinceStall += actualN

	// If we're returning fewer bytes than we read, we need to handle this
	// Since the backend already returned the data, we need a buffer approach
	// For simplicity in this implementation, we'll just limit what we return
	// The next Read() will get more data from the backend
	return actualN, nil
}

// ResetStallState resets the stall tracking state.
// Call this between test operations if needed.
func (j *JitteryConnection) ResetStallState() {
	j.bytesReadSinceStall = 0
	j.stallTriggered = false
}

// BufferedJitteryConnection is a more sophisticated jittery connection that
// properly buffers data from the backend to support fragmentation without
// data loss.
type BufferedJitteryConnection struct {
	backend             io.ReadWriter
	rng                 *rand.Rand
	readBuf             []byte
	config              JitterConfig
	bytesReadSinceStall int
	stallTriggered      bool
}

// NewBufferedJitteryConnection creates a jittery connection with proper buffering.
// This version correctly handles fragmentation by buffering backend reads.
func NewBufferedJitteryConnection(backend io.ReadWriter, config JitterConfig) *BufferedJitteryConnection {
	var rng *rand.Rand
	if config.Seed != 0 {
		rng = rand.New(rand.NewPCG(config.Seed, config.Seed^0xDEADBEEF)) //nolint:gosec // Test code, not crypto
	} else {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())) //nolint:gosec // Test code, not crypto
	}

	if config.FragmentMinBytes < 1 {
		config.FragmentMinBytes = 1
	}

	return &BufferedJitteryConnection{
		backend: backend,
		config:  config,
		rng:     rng,
		readBuf: make([]byte, 0, 1024),
	}
}

// Write passes writes through to the backend without modification.
func (j *BufferedJitteryConnection) Write(data []byte) (int, error) {
	return j.backend.Write(data) //nolint:wrapcheck // Pass-through wrapper
}

// Read reads from the backend with simulated jitter and fragmentation.
//
//nolint:gocognit,gocyclo,cyclop,nestif,revive // Jitter simulation inherently requires multiple conditions
func (j *BufferedJitteryConnection) Read(buf []byte) (int, error) {
	// Add random latency before reading
	if j.config.MaxLatencyMs > 0 {
		delay := time.Duration(j.rng.IntN(j.config.MaxLatencyMs+1)) * time.Millisecond
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	// If buffer is empty, read from backend
	if len(j.readBuf) == 0 {
		tempBuf := make([]byte, 1024)
		bytesRead, err := j.backend.Read(tempBuf)
		if err != nil {
			return 0, err //nolint:wrapcheck // Pass-through wrapper
		}
		if bytesRead == 0 {
			return 0, nil
		}
		j.readBuf = append(j.readBuf, tempBuf[:bytesRead]...)
	}

	// Determine how many bytes to return
	available := len(j.readBuf)
	requested := len(buf)
	toReturn := min(available, requested)

	// Apply stall logic: limit data before stall, then stall on next read
	if j.config.StallAfterBytes > 0 && !j.stallTriggered {
		if j.bytesReadSinceStall >= j.config.StallAfterBytes {
			// We've already returned enough bytes, stall now
			j.stallTriggered = true
			if j.config.StallDuration > 0 {
				time.Sleep(j.config.StallDuration)
			}
		} else {
			// Limit this read to not exceed StallAfterBytes
			remaining := j.config.StallAfterBytes - j.bytesReadSinceStall
			if toReturn > remaining {
				toReturn = remaining
			}
		}
	}

	// Apply USB boundary stress: fragment at 64-byte boundaries
	if j.config.USBBoundaryStress && toReturn > 0 {
		// Calculate bytes until next 64-byte boundary
		currentPos := j.bytesReadSinceStall
		nextBoundary := ((currentPos / 64) + 1) * 64
		untilBoundary := nextBoundary - currentPos
		if untilBoundary > 0 && untilBoundary < toReturn {
			toReturn = untilBoundary
		}
	}

	// Apply random fragmentation
	if j.config.FragmentReads && toReturn > j.config.FragmentMinBytes {
		minReturn := j.config.FragmentMinBytes
		maxReturn := toReturn
		toReturn = minReturn + j.rng.IntN(maxReturn-minReturn+1)
	}

	// Copy data to output buffer
	copy(buf, j.readBuf[:toReturn])

	// Remove returned data from buffer
	j.readBuf = j.readBuf[toReturn:]

	// Track bytes for stall logic
	j.bytesReadSinceStall += toReturn

	return toReturn, nil
}

// ResetStallState resets the stall tracking state.
func (j *BufferedJitteryConnection) ResetStallState() {
	j.bytesReadSinceStall = 0
	j.stallTriggered = false
}

// ClearBuffer clears any buffered read data.
func (j *BufferedJitteryConnection) ClearBuffer() {
	j.readBuf = j.readBuf[:0]
}
