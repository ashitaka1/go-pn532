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

package pn532

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNTAGTag_WriteNDEFContext_Cancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		cancelAfter   time.Duration
		expectError   bool
	}{
		{
			name: "context cancelled during write",
			setupMock: func(mock *MockTransport) {
				// Simulate slow write that will be cancelled
				mock.SetDelay(100 * time.Millisecond)
				mock.SetError(0x40, context.DeadlineExceeded)
			},
			cancelAfter:   50 * time.Millisecond,
			expectError:   true,
			errorContains: "deadline exceeded",
		},
		{
			name: "successful write with context",
			setupMock: func(mock *MockTransport) {
				// NDEF "test" is 14 bytes, which is 4 NTAG pages (4 bytes each)
				// Block 4: 03 0B D1 01
				// Block 5: 07 54 02 65
				// Block 6: 6E 74 65 73
				// Block 7: 74 FE 00 00
				writeSuccess := []byte{0x41, 0x00}

				// Queue 4 write responses + 4 read responses for verification
				mock.QueueResponses(0x40,
					writeSuccess, writeSuccess, writeSuccess, writeSuccess, // 4 writes
					[]byte{0x41, 0x00, 0x03, 0x0B, 0xD1, 0x01}, // read block 4
					[]byte{0x41, 0x00, 0x07, 0x54, 0x02, 0x65}, // read block 5
					[]byte{0x41, 0x00, 0x6E, 0x74, 0x65, 0x73}, // read block 6
					[]byte{0x41, 0x00, 0x74, 0xFE, 0x00, 0x00}, // read block 7
				)
			},
			cancelAfter: 1 * time.Second, // Don't cancel
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = NTAGType213 // Set explicitly to skip DetectType

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
