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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNTAGTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		device   *Device
		expected *NTAGTag
		name     string
		uid      []byte
		sak      byte
	}{
		{
			name:   "Valid_NTAG_Creation",
			device: createMockDevice(t),
			uid:    []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			sak:    0x00,
		},
		{
			name:   "Empty_UID",
			device: createMockDevice(t),
			uid:    []byte{},
			sak:    0x00,
		},
		{
			name:   "Nil_UID",
			device: createMockDevice(t),
			uid:    nil,
			sak:    0x00,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := NewNTAGTag(tt.device, tt.uid, tt.sak)

			assert.NotNil(t, result)
			assert.Equal(t, TagTypeNTAG, result.Type())
			assert.Equal(t, tt.uid, result.UIDBytes())
			assert.Equal(t, tt.device, result.device)
			assert.Equal(t, tt.sak, result.sak)
		})
	}
}

// Helper function for testing read block error handling
func checkReadBlockError(t *testing.T, err error, errorContains string, data []byte) {
	t.Helper()
	require.Error(t, err)
	if errorContains != "" {
		assert.Contains(t, err.Error(), errorContains)
	}
	assert.Nil(t, data)
}

func checkReadBlockSuccess(t *testing.T, err error, data, expectedData []byte) {
	t.Helper()
	require.NoError(t, err)
	assert.Equal(t, expectedData, data)
}

func TestNTAGTag_ReadBlock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		expectedData  []byte
		block         uint8
		expectError   bool
	}{
		{
			name: "Successful_Block_Read",
			setupMock: func(mt *MockTransport) {
				// NTAG ReadBlock returns 16 bytes (4 blocks) but only first 4 are used
				// Response format: 0x41 (InDataExchange response), 0x00 (success status), 16 bytes of data
				mt.SetResponse(0x40, []byte{
					0x41, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
					0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				})
			},
			block:        4,
			expectError:  false,
			expectedData: []byte{0x01, 0x02, 0x03, 0x04}, // Only first 4 bytes (1 block)
		},
		{
			name: "Transport_Error",
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x40, errors.New("transport error"))
			},
			block:         4,
			expectError:   true,
			errorContains: "tag read failed",
		},
		{
			name: "PN532_Error_Response",
			setupMock: func(mt *MockTransport) {
				mt.SetResponse(0x40, []byte{0x41, 0x01}) // Error status = 0x01
			},
			block:         4,
			expectError:   true,
			errorContains: "tag read failed",
		},
		{
			name: "Short_Response",
			setupMock: func(mt *MockTransport) {
				mt.SetResponse(0x40, []byte{0x41, 0x00, 0x01, 0x02}) // Only 2 bytes data (< 4 bytes required)
			},
			block:         4,
			expectError:   true,
			errorContains: "invalid read response length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

			data, err := tag.ReadBlock(tt.block)

			if tt.expectError {
				checkReadBlockError(t, err, tt.errorContains, data)
			} else {
				checkReadBlockSuccess(t, err, data, tt.expectedData)
			}
		})
	}
}

func TestNTAGTag_WriteBlock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		data          []byte
		block         uint8
		expectError   bool
	}{
		{
			name: "Successful_Block_Write",
			setupMock: func(mt *MockTransport) {
				// Mock response for InDataExchange with WRITE command
				mt.SetResponse(0x40, []byte{0x41, 0x00}) // Success status
			},
			block:       4,
			data:        []byte{0x01, 0x02, 0x03, 0x04},
			expectError: false,
		},
		{
			name: "Transport_Error",
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x40, errors.New("transport error"))
			},
			block:         4,
			data:          []byte{0x01, 0x02, 0x03, 0x04},
			expectError:   true,
			errorContains: "tag write failed",
		},
		{
			name: "PN532_Error_Response",
			setupMock: func(mt *MockTransport) {
				mt.SetResponse(0x40, []byte{0x41, 0x01}) // Error status = 0x01
			},
			block:         4,
			data:          []byte{0x01, 0x02, 0x03, 0x04},
			expectError:   true,
			errorContains: "tag write failed",
		},
		{
			name: "Data_Too_Large",
			setupMock: func(_ *MockTransport) {
				// No command expected as validation should fail early
			},
			block:         4,
			data:          []byte{0x01, 0x02, 0x03, 0x04, 0x05}, // 5 bytes > 4 byte max
			expectError:   true,
			errorContains: "invalid block size",
		},
		{
			name: "Data_Too_Small",
			setupMock: func(_ *MockTransport) {
				// No command expected as validation should fail early
			},
			block:         4,
			data:          []byte{0x01, 0x02, 0x03}, // 3 bytes < 4 byte requirement
			expectError:   true,
			errorContains: "invalid block size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

			err := tag.WriteBlock(tt.block, tt.data)

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

func TestNTAGTag_GetVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		expectError   bool
		expectedType  NTAGType
	}{
		{
			name: "NTAG213_Version",
			setupMock: func(mt *MockTransport) {
				// Mock GET_VERSION response for NTAG213 using InCommunicateThru (0x42)
				// Response format: 0x43 (InCommunicateThru response), 0x00 (success status), 8 bytes version data
				mt.SetResponse(0x42, []byte{0x43, 0x00, 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03})
			},
			expectError:  false,
			expectedType: NTAGType213,
		},
		{
			name: "NTAG215_Version",
			setupMock: func(mt *MockTransport) {
				mt.SetResponse(0x42, []byte{0x43, 0x00, 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03})
			},
			expectError:  false,
			expectedType: NTAGType215,
		},
		{
			name: "NTAG216_Version",
			setupMock: func(mt *MockTransport) {
				mt.SetResponse(0x42, []byte{0x43, 0x00, 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03})
			},
			expectError:  false,
			expectedType: NTAGType216,
		},
		{
			name: "Transport_Error_With_Fallback",
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x42, errors.New("transport error"))
			},
			expectError:   true, // Error returned but with fallback version
			errorContains: "transport error",
		},
		{
			name: "Invalid_Response_With_Fallback",
			setupMock: func(mt *MockTransport) {
				mt.SetResponse(0x42, []byte{0x43, 0x00, 0x01, 0x02}) // Invalid short response
			},
			expectError: false, // Should succeed with fallback version
		},
		{
			name: "Invalid_Vendor_With_Fallback",
			setupMock: func(mt *MockTransport) {
				// Invalid vendor ID (not 0x04) - should use fallback
				mt.SetResponse(0x42, []byte{0x43, 0x00, 0x00, 0xFF, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03})
			},
			expectError: false, // Should succeed with fallback version
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

			version, err := tag.GetVersion()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				// Even with error, should still return a fallback version
				assert.NotNil(t, version)
			} else {
				// For successful cases or fallback cases
				assert.NotNil(t, version)
				if tt.expectedType != NTAGTypeUnknown {
					assert.Equal(t, tt.expectedType, version.GetNTAGType())
				}
			}
		})
	}
}

func TestNTAGTag_FastRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		expectedData  []byte
		startBlock    uint8
		endBlock      uint8
		expectError   bool
	}{
		{
			name: "Successful_FastRead",
			setupMock: func(mt *MockTransport) {
				// Mock FAST_READ response for blocks 4-7 (4 blocks * 4 bytes = 16 bytes)
				// FastRead uses SendRawCommand (InCommunicateThru 0x42)
				// SendRawCommand strips the 0x43 header and 0x00 status, returning only data
				// So we need to provide: 0x43, 0x00, then 16 bytes of actual data
				data := make([]byte, 18) // Header + Status + 16 bytes data
				data[0] = 0x43           // InCommunicateThru response
				data[1] = 0x00           // Success status
				for i := 2; i < 18; i++ {
					data[i] = byte(i - 2) // Fill with test data (0x00 to 0x0F)
				}
				mt.SetResponse(0x42, data)
			},
			startBlock:  4,
			endBlock:    7,
			expectError: false,
			expectedData: func() []byte {
				// FastRead should return (7-4+1) * 4 = 16 bytes
				data := make([]byte, 16)
				for i := 0; i < 16; i++ {
					data[i] = byte(i)
				}
				return data
			}(),
		},
		{
			name: "Transport_Error",
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x42, errors.New("transport error"))
			},
			startBlock:    4,
			endBlock:      7,
			expectError:   true,
			errorContains: "transport error",
		},
		{
			name: "PN532_Error_Response",
			setupMock: func(mt *MockTransport) {
				mt.SetResponse(0x42, []byte{0x43, 0x01}) // Error status
			},
			startBlock:    4,
			endBlock:      7,
			expectError:   true,
			errorContains: "error: 01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

			data, err := tag.FastRead(tt.startBlock, tt.endBlock)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, data)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedData, data)
			}
		})
	}
}

// Helper functions for NTAG tests

func createMockDevice(t *testing.T) *Device {
	mockTransport := NewMockTransport()
	device, err := New(mockTransport)
	require.NoError(t, err)
	return device
}

// Removed duplicate - using the one from mifare_test.go

// TestNTAG215LargeDataCrash reproduces the crash reported by user with large NDEF data
func TestNTAG215LargeDataCrash(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)
	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
	tag.tagType = NTAGType215 // Force NTAG215 type

	// Create large NDEF message that approaches NTAG215's 504-byte user memory limit
	largeText := make([]byte, 480) // Large text payload
	for i := range largeText {
		largeText[i] = byte('A' + (i % 26)) // Fill with repeating alphabet
	}

	// Mock the NDEF header read (block 4) with extended length format
	// Format: [0x03] [0xFF] [high_byte] [low_byte] for extended length
	headerData := []byte{
		0x03,       // NDEF TLV type
		0xFF,       // Extended length indicator
		0x02, 0x00, // Length = 512 bytes (0x0200) - exceeds NTAG215 capacity
		// Rest of block would contain start of NDEF data
	}
	// Pad to 16 bytes (4 blocks returned by READ command)
	headerBlock := make([]byte, 16)
	copy(headerBlock, headerData)

	// Mock the block read for header
	mockTransport.SetResponse(0x40, append([]byte{0x41, 0x00}, headerBlock...))

	// This should trigger the crash due to:
	// 1. Integer overflow when calculating totalBytes = headerSize + ndefLength + 1
	// 2. Attempting to read beyond the hardcoded 64-block limit in block-by-block fallback
	// 3. Potential buffer overflow when totalBytes exceeds expected bounds

	// With our fixes, this should now fail gracefully with proper error handling
	_, err := tag.ReadNDEF()

	// Verify our fixes work:
	// 1. No crash occurs (test completes)
	// 2. Proper error handling for oversized NDEF data
	// 3. Error message indicates the specific problem
	require.Error(t, err, "Should reject oversized NDEF data")
	assert.Contains(t, err.Error(), "exceeds tag capacity", "Error should indicate capacity exceeded")
	assert.Contains(t, err.Error(), "NTAG215", "Error should identify tag type")

	t.Logf("✓ ReadNDEF properly rejected oversized data: %v", err)
}

// TestNTAG215BlockByBlockBufferOverflow tests the specific buffer overflow in block-by-block reading
func TestNTAG215BlockByBlockBufferOverflow(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)
	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
	tag.tagType = NTAGType215

	// Force FastRead to be disabled to trigger block-by-block fallback
	fastReadDisabled := false
	tag.fastReadSupported = &fastReadDisabled

	// Create NDEF header that indicates more data than the 64-block limit can handle
	headerData := []byte{
		0x03,       // NDEF TLV type
		0xFF,       // Extended length indicator
		0x02, 0x00, // Length = 512 bytes (more than 64*4=256 byte limit)
	}
	headerBlock := make([]byte, 16)
	copy(headerBlock, headerData)

	// Mock responses for block reads
	mockTransport.SetResponse(0x40, append([]byte{0x41, 0x00}, headerBlock...))

	// Mock subsequent block reads (blocks 5-67) with test data
	for block := uint8(5); block < 68; block++ {
		blockData := make([]byte, 18) // Response header + 16 bytes data
		blockData[0] = 0x41           //nolint:gosec // G602: slice has fixed size 18
		blockData[1] = 0x00           //nolint:gosec // G602: slice has fixed size 18
		for i := 2; i < 18; i++ {
			blockData[i] = block // Fill with block number for testing
		}
		mockTransport.SetResponse(0x40, blockData)
	}

	// With our fixes, this should now use proper tag capacity bounds instead of hardcoded limits
	_, err := tag.ReadNDEF()

	// With our fixes, this could either:
	// 1. Succeed by properly reading within tag bounds (if mock data is valid)
	// 2. Fail gracefully with proper error handling (expected for this test setup)

	// The key verification is that it doesn't crash due to buffer overflow
	// Since we're forcing block-by-block reading with insufficient mock data,
	// we expect a graceful failure rather than success
	if err != nil {
		t.Logf("✓ Block-by-block reading failed gracefully (no crash): %v", err)
		// Verify it's a proper NDEF parsing error, not a crash/panic
		assert.NotContains(t, err.Error(), "panic", "Should not contain panic messages")
		assert.NotContains(t, err.Error(), "runtime error", "Should not contain runtime errors")
	} else {
		t.Log("✓ Block-by-block reading succeeded (proper bounds checking)")
	}
}

// TestNTAGFastReadConfigLimits tests the FastRead configuration limits
func TestNTAGFastReadConfigLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		maxFastReadPages int
		expectedResult   uint8
	}{
		{
			name:             "Custom config normal value",
			maxFastReadPages: 32,
			expectedResult:   32,
		},
		{
			name:             "Custom config bounds check - exceeds uint8",
			maxFastReadPages: 300,
			expectedResult:   255, // Capped to uint8 max
		},
		{
			name:             "Custom config at uint8 boundary",
			maxFastReadPages: 255,
			expectedResult:   255,
		},
		{
			name:             "Custom config small value",
			maxFastReadPages: 1,
			expectedResult:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create device with test config
			config := &DeviceConfig{
				MaxFastReadPages: tt.maxFastReadPages,
			}
			device := &Device{
				transport: &MockTransport{},
				config:    config,
			}

			// Create NTAG tag
			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

			// Test the getMaxFastReadPages method
			maxPages := tag.getMaxFastReadPages()

			// Verify the result matches expected bounds checking
			assert.Equal(t, tt.expectedResult, maxPages,
				"MaxFastReadPages should respect config with proper bounds checking")
		})
	}
}

// TestNTAGFastReadDefaultLimits tests that default limits are reasonable
func TestNTAGFastReadDefaultLimits(t *testing.T) {
	t.Parallel()
	// Create device with default config (0 = use platform defaults)
	config := &DeviceConfig{
		MaxFastReadPages: 0,
	}
	device := &Device{
		transport: &MockTransport{},
		config:    config,
	}

	// Create NTAG tag
	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

	// Test the getMaxFastReadPages method
	maxPages := tag.getMaxFastReadPages()

	// Verify the result is reasonable for any platform
	// (should be either Windows UART limit of 16 or default of 60)
	assert.True(t, maxPages == 16 || maxPages == 60,
		"Default MaxFastReadPages should be either Windows UART limit (16) or default (60), got %d", maxPages)
}

// NDEF Message Tests
