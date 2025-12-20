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

package pn532

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMIFARETag_AuthenticateRobustContext_ActuallyRobust(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		expectError   bool
	}{
		{
			name: "should fail immediately without retry logic (demonstrating current limitation)",
			setupMock: func(mock *MockTransport) {
				// Set error - current implementation won't retry, robust version would
				mock.SetError(0x40, errors.New("auth failed"))
			},
			expectError:   true,
			errorContains: "auth failed", // Current implementation fails immediately
		},
		{
			name: "context cancellation should work",
			setupMock: func(mock *MockTransport) {
				// Add delay to allow context cancellation
				mock.SetDelay(200 * time.Millisecond)
				mock.SetError(0x40, context.Canceled)
			},
			expectError:   true,
			errorContains: "context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag, mockTransport := setupMIFARETagTest(t, tt.setupMock)

			// Use short timeout for cancellation test
			timeout := 1 * time.Second
			if tt.errorContains == "context" {
				timeout = 100 * time.Millisecond
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			err := tag.AuthenticateRobustContext(ctx, 1, 0x00, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}

			// Verify that robust context doesn't retry like it should
			// The current implementation only makes 1 call, robust should make multiple
			if tt.name == "should fail immediately without retry logic (demonstrating current limitation)" {
				// Current implementation makes only 1 call (no retry)
				// A proper robust implementation should make multiple calls
				callCount := mockTransport.GetCallCount(0x40)

				// This should fail because current AuthenticateRobustContext doesn't retry
				// When we implement proper robust context authentication, this assertion should pass
				require.Greater(t, callCount, 1,
					"AuthenticateRobustContext should retry multiple times like AuthenticateRobust, "+
						"but currently only makes %d call(s). This demonstrates the current "+
						"implementation is not actually robust.",
					callCount)
			}
		})
	}
}
