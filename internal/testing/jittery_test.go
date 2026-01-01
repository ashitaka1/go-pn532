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

package testing

import (
	"bytes"
	"testing"
	"time"
)

func TestJitteryConnection_BasicReadWrite(t *testing.T) {
	t.Parallel()

	sim := NewVirtualPN532()
	jittery := NewBufferedJitteryConnection(sim, JitterConfig{
		MaxLatencyMs:  0, // No latency for faster tests
		FragmentReads: false,
		Seed:          12345,
	})

	// Send GetFirmwareVersion command
	// Frame: 00 00 FF 02 FE D4 02 2A 00
	cmd := []byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00}
	written, err := jittery.Write(cmd)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if written != len(cmd) {
		t.Fatalf("Write returned wrong count: got %d, want %d", written, len(cmd))
	}

	// Read response (should get ACK + firmware response)
	buf := make([]byte, 256)
	totalRead := 0
	for totalRead < 6 { // At least ACK frame
		bytesRead, readErr := jittery.Read(buf[totalRead:])
		if readErr != nil {
			t.Fatalf("Read failed: %v", readErr)
		}
		totalRead += bytesRead
	}

	// Verify ACK frame
	ack := buf[:6]
	if !bytes.Equal(ack, ACKFrame) {
		t.Errorf("Expected ACK frame %X, got %X", ACKFrame, ack)
	}
}

func TestJitteryConnection_Fragmentation(t *testing.T) {
	t.Parallel()

	sim := NewVirtualPN532()
	jittery := NewBufferedJitteryConnection(sim, JitterConfig{
		MaxLatencyMs:     0,
		FragmentReads:    true,
		FragmentMinBytes: 1,
		Seed:             42,
	})

	// Send GetFirmwareVersion command
	cmd := []byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00}
	_, err := jittery.Write(cmd)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read response with fragmentation enabled
	// We should receive data in multiple small chunks
	buf := make([]byte, 256)
	totalRead := 0
	readCount := 0
	maxReads := 100 // Safety limit

	// Read until we have the full response (ACK + response frame)
	expectedMinBytes := 6 + 10 // ACK (6) + minimum response frame
	for totalRead < expectedMinBytes && readCount < maxReads {
		n, err := jittery.Read(buf[totalRead:])
		if err != nil {
			t.Fatalf("Read %d failed: %v", readCount, err)
		}
		if n > 0 {
			totalRead += n
			readCount++
		}
	}

	if readCount >= maxReads {
		t.Fatal("Too many reads required, possible issue with fragmentation")
	}

	// With fragmentation, we should have needed multiple reads
	// (unless we got lucky with the RNG)
	t.Logf("Read complete response in %d read calls (%d bytes)", readCount, totalRead)

	// Verify ACK frame
	if !bytes.Equal(buf[:6], ACKFrame) {
		t.Errorf("Expected ACK frame %X, got %X", ACKFrame, buf[:6])
	}
}

func TestJitteryConnection_Latency(t *testing.T) {
	t.Parallel()

	sim := NewVirtualPN532()
	jittery := NewBufferedJitteryConnection(sim, JitterConfig{
		MaxLatencyMs:  10,
		FragmentReads: false,
		Seed:          99,
	})

	// Send command
	cmd := []byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00}
	_, err := jittery.Write(cmd)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Measure read time - should have some latency
	start := time.Now()
	buf := make([]byte, 256)
	totalRead := 0
	for totalRead < 6 {
		n, _ := jittery.Read(buf[totalRead:])
		totalRead += n
	}
	elapsed := time.Since(start)

	// With 10ms max latency and multiple reads, should take some time
	// But this is probabilistic, so we just log it
	t.Logf("Read took %v with max latency %dms", elapsed, jittery.config.MaxLatencyMs)
}

func TestJitteryConnection_USBBoundaryStress(t *testing.T) {
	t.Parallel()

	sim := NewVirtualPN532()
	jittery := NewBufferedJitteryConnection(sim, JitterConfig{
		MaxLatencyMs:      0,
		FragmentReads:     false,
		USBBoundaryStress: true,
		Seed:              12345,
	})

	// Send command
	cmd := []byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00}
	_, err := jittery.Write(cmd)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read response - USB boundary stress should fragment at 64-byte boundaries
	buf := make([]byte, 256)
	totalRead := 0
	reads := []int{}
	for totalRead < 16 {
		bytesRead, readErr := jittery.Read(buf[totalRead:])
		if readErr != nil {
			t.Fatalf("Read failed: %v", readErr)
		}
		if bytesRead > 0 {
			reads = append(reads, bytesRead)
			totalRead += bytesRead
		}
	}

	t.Logf("USB boundary stress reads: %v (total: %d)", reads, totalRead)
}

func TestJitteryConnection_StallAfterBytes(t *testing.T) {
	t.Parallel()

	sim := NewVirtualPN532()
	stallDuration := 50 * time.Millisecond
	jittery := NewBufferedJitteryConnection(sim, JitterConfig{
		MaxLatencyMs:    0,
		FragmentReads:   false,
		StallAfterBytes: 3, // Stall after reading 3 bytes (header-ish)
		StallDuration:   stallDuration,
		Seed:            12345,
	})

	// Send command
	cmd := []byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00}
	_, err := jittery.Write(cmd)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read response - should stall after 3 bytes
	buf := make([]byte, 256)
	totalRead := 0
	start := time.Now()
	for totalRead < 10 {
		n, err := jittery.Read(buf[totalRead:])
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if n > 0 {
			totalRead += n
		}
	}
	elapsed := time.Since(start)

	// Should have stalled for at least stallDuration
	if elapsed < stallDuration {
		t.Errorf("Expected stall of at least %v, but only took %v", stallDuration, elapsed)
	}
	t.Logf("Read with stall took %v (expected stall: %v)", elapsed, stallDuration)
}

func TestJitteryConnection_ResetStallState(t *testing.T) {
	t.Parallel()

	sim := NewVirtualPN532()
	jittery := NewBufferedJitteryConnection(sim, JitterConfig{
		MaxLatencyMs:    0,
		FragmentReads:   false,
		StallAfterBytes: 100,
		StallDuration:   100 * time.Millisecond,
		Seed:            12345,
	})

	// Track some bytes
	jittery.bytesReadSinceStall = 50

	// Reset
	jittery.ResetStallState()

	if jittery.bytesReadSinceStall != 0 {
		t.Errorf("Expected bytesReadSinceStall to be 0 after reset, got %d", jittery.bytesReadSinceStall)
	}
	if jittery.stallTriggered {
		t.Error("Expected stallTriggered to be false after reset")
	}
}

func TestDefaultJitterConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultJitterConfig()

	if cfg.MaxLatencyMs != 20 {
		t.Errorf("Expected MaxLatencyMs=20, got %d", cfg.MaxLatencyMs)
	}
	if !cfg.FragmentReads {
		t.Error("Expected FragmentReads=true")
	}
	if cfg.FragmentMinBytes != 1 {
		t.Errorf("Expected FragmentMinBytes=1, got %d", cfg.FragmentMinBytes)
	}
}

//nolint:gocognit,nestif,revive // Integration test requires multiple conditions
func TestJitteryConnection_WithVirtualPN532Integration(t *testing.T) {
	t.Parallel()

	// Full integration test: jittery connection with simulator and tag detection
	sim := NewVirtualPN532()

	// Add a virtual tag
	tag := NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	// Wrap with jitter
	jittery := NewBufferedJitteryConnection(sim, JitterConfig{
		MaxLatencyMs:     5,
		FragmentReads:    true,
		FragmentMinBytes: 2,
		Seed:             54321,
	})

	// Send SAMConfiguration command
	// Frame: 00 00 FF 03 FD D4 14 01 17 00
	samCmd := []byte{0x00, 0x00, 0xFF, 0x03, 0xFD, 0xD4, 0x14, 0x01, 0x17, 0x00}
	_, err := jittery.Write(samCmd)
	if err != nil {
		t.Fatalf("Write SAMConfiguration failed: %v", err)
	}

	// Read SAMConfiguration response
	buf := make([]byte, 256)
	totalRead := 0
	for totalRead < 10 {
		n, _ := jittery.Read(buf[totalRead:])
		totalRead += n
	}

	// Clear buffer for next command
	jittery.ClearBuffer()
	jittery.ResetStallState()

	// Send InListPassiveTarget command
	// MaxTg=1, BrTy=0x00 (106 kbps Type A)
	// Frame: 00 00 FF 04 FC D4 4A 01 00 E1 00
	inListCmd := []byte{0x00, 0x00, 0xFF, 0x04, 0xFC, 0xD4, 0x4A, 0x01, 0x00, 0xE1, 0x00}
	_, err = jittery.Write(inListCmd)
	if err != nil {
		t.Fatalf("Write InListPassiveTarget failed: %v", err)
	}

	// Read response
	totalRead = 0
	for totalRead < 20 {
		n, _ := jittery.Read(buf[totalRead:])
		totalRead += n
	}

	// Verify we got the tag in the response
	// ACK (6 bytes) + Response frame header + NbTg should be 1
	t.Logf("InListPassiveTarget response (%d bytes): %X", totalRead, buf[:totalRead])

	// Find the response data (after ACK frame)
	if totalRead >= 6 && bytes.Equal(buf[:6], ACKFrame) {
		responseStart := 6
		// Look for response command 0x4B (InListPassiveTarget + 1)
		found := false
		for i := responseStart; i < totalRead-2; i++ {
			if buf[i] == 0xD5 && buf[i+1] == 0x4B {
				nbTg := buf[i+2]
				if nbTg == 1 {
					found = true
					t.Logf("Successfully detected %d tag(s) through jittery connection", nbTg)
				}
				break
			}
		}
		if !found {
			t.Error("Expected to find 1 tag in response")
		}
	}
}
