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
