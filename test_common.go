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

//go:build !prod

package pn532

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// createMockDeviceWithTransport creates a device with a mock transport for testing.
// By default, it simulates that a target has been selected (as if InListPassiveTarget succeeded).
// This is appropriate for tag operation tests (read/write/auth).
// Tests that specifically need to test polling/selection behavior should call
// mockTransport.DeselectTarget() after setup.
func createMockDeviceWithTransport(t *testing.T) (*Device, *MockTransport) {
	mockTransport := NewMockTransport()
	device, err := New(mockTransport)
	require.NoError(t, err)
	// Select target by default - most tests are for tag operations
	mockTransport.SelectTarget()
	return device, mockTransport
}
