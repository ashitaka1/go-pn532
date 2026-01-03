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

package polling

import (
	"context"
	"errors"
	"testing"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
)

// createMockDeviceWithTransportForBench creates a device with mock transport for benchmarks
func createMockDeviceWithTransportForBench(b *testing.B) (*pn532.Device, *pn532.MockTransport) {
	mockTransport := pn532.NewMockTransport()
	device, err := pn532.New(mockTransport)
	if err != nil {
		b.Fatalf("Failed to create device: %v", err)
	}
	return device, mockTransport
}

// BenchmarkSession_Start measures Session.Start() performance
func BenchmarkSession_Start(b *testing.B) {
	device, mockTransport := createMockDeviceWithTransportForBench(b)

	// Setup mock to return a card on poll
	mockTransport.SetResponse(0x4A, []byte{
		0xD5, 0x4B, 0x01, 0x01, 0x00, 0x04, 0x00, 0x07, 0x04,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
	})

	config := &Config{
		PollInterval:       1 * time.Millisecond, // Fast polling for benchmark
		CardRemovalTimeout: 10 * time.Millisecond,
	}

	session := NewSession(device, config)

	// Pre-allocate context for benchmark accuracy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	b.ResetTimer() // Start timing after setup

	for range b.N {
		// Measure Session.Start() call latency
		err := session.Start(ctx)
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			b.Fatalf("Session.Start() failed: %v", err)
		}
	}

	_ = session.Close()
}

// BenchmarkSession_WriteLatency measures write operation latency
func BenchmarkSession_WriteLatency(b *testing.B) {
	device, mockTransport := createMockDeviceWithTransportForBench(b)

	// Setup successful write responses
	mockTransport.SetResponse(0x4A, []byte{
		0xD5, 0x4B, 0x01, 0x01, 0x00, 0x04, 0x00, 0x07, 0x04,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
	})
	mockTransport.SetResponse(0x40, []byte{0xD5, 0x41, 0x00}) // Successful write

	config := &Config{
		PollInterval:       10 * time.Millisecond,
		CardRemovalTimeout: 100 * time.Millisecond,
	}

	session := NewSession(device, config)

	// Create mock detected tag
	detectedTag := &pn532.DetectedTag{
		UID:  "12345678",
		Type: pn532.TagTypeNTAG,
	}

	ctx := context.Background()

	// Simple write function
	writeFn := func(_ context.Context, _ pn532.Tag) error {
		return nil // Mock successful write
	}

	b.ResetTimer()

	for range b.N {
		err := session.WriteToTag(ctx, ctx, detectedTag, writeFn)
		if err != nil {
			b.Fatalf("WriteToTag failed: %v", err)
		}
	}

	_ = session.Close()
}

// BenchmarkSession_Allocation measures memory efficiency
func BenchmarkSession_Allocation(b *testing.B) {
	device, mockTransport := createMockDeviceWithTransportForBench(b)
	mockTransport.SetResponse(0x4A, []byte{
		0xD5, 0x4B, 0x01, 0x01, 0x00, 0x04, 0x00, 0x07, 0x04,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
	})

	config := &Config{
		PollInterval:       10 * time.Millisecond,
		CardRemovalTimeout: 100 * time.Millisecond,
	}

	b.ReportAllocs()
	for range b.N {
		session := NewSession(device, config)
		_ = session.Close()
	}
}
