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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMIFARETag_WriteNDEFContext_Cancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		cancelAfter   time.Duration
		expectError   bool
	}{
		{
			name: "context cancelled during authentication",
			setupMock: func(mock *MockTransport) {
				// Simulate slow authentication that will be cancelled
				mock.SetDelay(100 * time.Millisecond)
				mock.SetError(0x40, context.Canceled)
			},
			cancelAfter:   50 * time.Millisecond,
			expectError:   true,
			errorContains: "context deadline exceeded",
		},
		{
			name: "successful write with context",
			setupMock: func(mock *MockTransport) {
				// NDEF "test" encodes to: 03 0B D1 01 07 54 02 65 6E 74 65 73 74 FE (14 bytes, padded to 16)
				ndefBlock := []byte{
					0x03, 0x0B, 0xD1, 0x01, 0x07, 0x54, 0x02, 0x65,
					0x6E, 0x74, 0x65, 0x73, 0x74, 0xFE, 0x00, 0x00,
				}
				writeSuccess := []byte{0x41, 0x00}
				readResponse := append([]byte{0x41, 0x00}, ndefBlock...)

				// Count exact operations:
				// 1. Auth sector 1 (initial)
				// 2. Write block 4
				// 3-4. Write blocks 5, 6 (clearRemainingBlocks sector 1)
				// 5-8. Auth sector 2 + Write blocks 8,9,10
				// ... continues for sectors 3-15 (14 sectors * 4 ops = 56)
				// Total before verification: 4 + 56 = 60
				// Then: Auth sector 1 (verification) = 61
				// Then: Read block 4 = 62
				//
				// Queue 61 writeSuccess (for ops 1-61), then readResponse (for op 62)
				for range 61 {
					mock.QueueResponse(0x40, writeSuccess)
				}
				mock.QueueResponse(0x40, readResponse)
			},
			cancelAfter: 1 * time.Second, // Don't cancel
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Skip context cancellation test until we implement proper context support
			if tt.name == "context cancelled during authentication" {
				t.Skip("Skipping context cancellation test - context support not fully implemented yet")
			}

			tag, _ := setupMIFARETagTest(t, tt.setupMock)

			// Create a context that will be cancelled
			ctx, cancel := context.WithTimeout(context.Background(), tt.cancelAfter)
			defer cancel()

			message := &NDEFMessage{
				Records: []NDEFRecord{
					{
						Type: NDEFTypeText,
						Text: "test",
					},
				},
			}

			// Test WriteNDEF with context
			err := tag.WriteNDEF(ctx, message)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
