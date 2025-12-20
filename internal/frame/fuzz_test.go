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

package frame

import (
	"testing"
)

// =============================================================================
// Fuzz Tests for Frame Parsing
// =============================================================================
// These fuzz tests are designed to catch panics, buffer overflows, and other
// edge cases in the frame parsing code. Malformed input from hardware (especially
// clone chips or damaged devices) could cause crashes if not handled properly.
//
// Run with: go test -fuzz=FuzzValidateFrameLength -fuzztime=30s ./internal/frame/
// Run all: go test -fuzz=Fuzz -fuzztime=10s ./internal/frame/

// FuzzValidateFrameLength tests the frame length validation with arbitrary input.
// This is critical because it's the first parsing step and determines buffer bounds.
func FuzzValidateFrameLength(f *testing.F) {
	// Add seed corpus: valid frames
	// Format: [preamble...][length][length_checksum][data...]
	f.Add([]byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD5, 0x03}, 2, 7) // Valid GetFirmware response
	f.Add([]byte{0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00}, 2, 6)       // ACK frame
	f.Add([]byte{0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00}, 2, 6)       // NACK frame

	// Add seed corpus: edge cases
	f.Add([]byte{}, 0, 0)                                   // Empty
	f.Add([]byte{0x00}, 0, 1)                               // Single byte
	f.Add([]byte{0x00, 0x00}, 0, 2)                         // Two bytes
	f.Add([]byte{0x00, 0x00, 0xFF}, 2, 3)                   // Just preamble
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0, 6) // All 0xFF

	// Add seed corpus: invalid checksums
	f.Add([]byte{0x00, 0x00, 0xFF, 0x02, 0x00, 0xD5, 0x03}, 2, 7) // Bad length checksum
	f.Add([]byte{0x00, 0x00, 0xFF, 0xFF, 0xFF}, 2, 5)             // Max length

	f.Fuzz(func(_ *testing.T, buf []byte, off, totalLen int) {
		// Sanitize inputs to reasonable ranges
		if off < 0 {
			off = 0
		}
		if off >= len(buf) && len(buf) > 0 {
			off = len(buf) - 1
		}
		if totalLen < 0 {
			totalLen = 0
		}
		if totalLen > len(buf) {
			totalLen = len(buf)
		}

		// Should not panic regardless of input
		_, _, _ = ValidateFrameLength(buf, off, totalLen, "test", "test")
	})
}

// FuzzValidateFrameChecksum tests the checksum validation with arbitrary input.
// Ensures the function handles all slice bounds correctly without panicking.
func FuzzValidateFrameChecksum(f *testing.F) {
	// Valid checksum sequences (checksum byte is included and should sum to 0)
	f.Add([]byte{0xD5, 0x03, 0x28}, 0, 3) // Example with valid checksum
	f.Add([]byte{0x00}, 0, 1)             // Single zero
	f.Add([]byte{0x01, 0xFF}, 0, 2)       // Sums to 0 (mod 256)
	f.Add([]byte{0xD5, 0x4B, 0x01, 0x00, 0x04, 0x08, 0x04}, 0, 7)

	// Edge cases
	f.Add([]byte{}, 0, 0)           // Empty
	f.Add([]byte{0xFF}, 0, 1)       // Single 0xFF
	f.Add([]byte{0x00, 0x00}, 0, 2) // All zeros

	// Invalid bounds
	f.Add([]byte{0x01, 0x02, 0x03}, 1, 5) // End beyond buffer
	f.Add([]byte{0x01, 0x02, 0x03}, 5, 7) // Start beyond buffer

	f.Fuzz(func(_ *testing.T, buf []byte, start, end int) {
		// Should not panic regardless of input - function should handle bounds
		_ = ValidateFrameChecksum(buf, start, end)
	})
}

// FuzzExtractFrameData tests the full frame data extraction with arbitrary input.
// This is the most complex parsing function and most likely to have edge cases.
func FuzzExtractFrameData(f *testing.F) {
	// Valid frames
	// Format: [preamble][start_code][length][lcs][tfi][data...][dcs][postamble]
	f.Add([]byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD5, 0x03, 0x28, 0x00}, 3, 2, byte(0xD5)) // Minimal valid
	f.Add([]byte{0x00, 0x00, 0xFF, 0x06, 0xFA, 0xD5, 0x4B, 0x01, 0x00, 0x04, 0x08, 0x2D, 0x00}, 3, 6, byte(0xD5))

	// Error frame (TFI = 0x7F)
	f.Add([]byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0x7F, 0x01, 0x80, 0x00}, 3, 2, byte(0xD5))

	// Edge cases
	f.Add([]byte{}, 0, 0, byte(0xD5))           // Empty
	f.Add([]byte{0x00}, 0, 0, byte(0xD5))       // Single byte
	f.Add([]byte{0xD5}, 0, 1, byte(0xD5))       // Just TFI
	f.Add([]byte{0x7F, 0x01}, 0, 2, byte(0xD5)) // Just error frame data

	// Wrong TFI
	f.Add([]byte{0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x03, 0x28, 0x00}, 3, 2, byte(0xD5)) // D4 instead of D5

	f.Fuzz(func(_ *testing.T, buf []byte, off, frameLen int, tfi byte) {
		// Sanitize inputs
		if off < 0 {
			off = 0
		}
		if frameLen < 0 {
			frameLen = 0
		}

		// Should not panic regardless of input
		data, _, _ := ExtractFrameData(buf, off, frameLen, tfi)

		// If we got data back, make sure to return it to the pool
		if data != nil {
			PutBuffer(data)
		}
	})
}

// FuzzHandleErrorFrame tests error frame handling with arbitrary input.
func FuzzHandleErrorFrame(f *testing.F) {
	// Valid error frames
	f.Add([]byte{0x7F, 0x01}, 0) // Timeout error
	f.Add([]byte{0x7F, 0x14}, 0) // Auth error
	f.Add([]byte{0x7F, 0x81}, 0) // Invalid command

	// Edge cases
	f.Add([]byte{}, 0)                       // Empty
	f.Add([]byte{0x7F}, 0)                   // Just TFI, no error code
	f.Add([]byte{0x00}, 0)                   // Wrong TFI
	f.Add([]byte{0x7F, 0x00, 0x00, 0x00}, 0) // Extra data

	f.Fuzz(func(_ *testing.T, buf []byte, off int) {
		// Sanitize input
		if off < 0 {
			off = 0
		}

		// Should not panic regardless of input
		_, _, _ = HandleErrorFrame(buf, off)
	})
}

// FuzzCalculateChecksum tests checksum calculation with arbitrary input.
// While simpler, this ensures the function handles all inputs safely.
func FuzzCalculateChecksum(f *testing.F) {
	// Normal inputs
	f.Add([]byte{0xD5, 0x03})
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	// Edge cases
	f.Add([]byte{})     // Empty
	f.Add([]byte{0x00}) // Single zero
	f.Add([]byte{0xFF}) // Single max

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic and should be deterministic
		result1 := CalculateChecksum(data)
		result2 := CalculateChecksum(data)

		if result1 != result2 {
			t.Errorf("CalculateChecksum is not deterministic: %v != %v", result1, result2)
		}

		// Manual verification for small inputs
		if len(data) > 0 && len(data) <= 256 {
			var expected byte
			for _, b := range data {
				expected += b
			}
			if result1 != expected {
				t.Errorf("CalculateChecksum(%v) = %v, want %v", data, result1, expected)
			}
		}
	})
}

// FuzzBufferPool tests the buffer pool with arbitrary sizes.
// Ensures the pool handles edge cases and doesn't panic.
func FuzzBufferPool(f *testing.F) {
	// Normal sizes
	f.Add(1)
	f.Add(16)
	f.Add(255)
	f.Add(270)
	f.Add(512)

	// Edge cases
	f.Add(0)
	f.Add(-1)
	f.Add(10000)

	f.Fuzz(func(t *testing.T, size int) {
		if size < 0 {
			// Negative sizes could cause issues
			return
		}
		if size > 1_000_000 {
			// Don't allocate huge buffers in fuzz tests
			return
		}

		// Should not panic
		buf := GetBuffer(size)
		if buf == nil && size > 0 {
			t.Error("GetBuffer returned nil for positive size")
		}

		if size > 0 {
			// Verify buffer is usable
			if len(buf) != size {
				t.Errorf("GetBuffer(%d) returned buffer of length %d", size, len(buf))
			}

			// Write to buffer to verify it's writable
			for i := range buf {
				buf[i] = byte(i)
			}

			// Return to pool
			PutBuffer(buf)
		}
	})
}
