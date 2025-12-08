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

//nolint:dupl // Test file - similar test patterns are acceptable
package pn532

import (
	"context"
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

			data, err := tag.ReadBlock(context.Background(), tt.block)

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

			err := tag.WriteBlock(context.Background(), tt.block, tt.data)

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
				for i := range 16 {
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
			errorContains: "error 0x01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

			data, err := tag.FastRead(context.Background(), tt.startBlock, tt.endBlock)

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
	_, err := tag.ReadNDEF(context.Background())

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
		blockData[0] = 0x41           //nolint:gosec // Fixed size slice, index is safe
		blockData[1] = 0x00           //nolint:gosec // Fixed size slice, index is safe
		for i := 2; i < 18; i++ {
			blockData[i] = block // Fill with block number for testing
		}
		mockTransport.SetResponse(0x40, blockData)
	}

	// With our fixes, this should now use proper tag capacity bounds instead of hardcoded limits
	_, err := tag.ReadNDEF(context.Background())

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

// TestNTAG_GetVersionDoesNotBreakSubsequentReads is a regression test for the
// v0.8.1 → v0.8.3 NTAG read regression. The issue was that GetVersion() uses
// InCommunicateThru (0x42) which doesn't maintain the PN532's target selection
// state. Without re-selecting the target after GetVersion, subsequent
// InDataExchange calls would fail with timeout error 01.
//
// See PN532 User Manual §7.3.9: "The host controller has to take care of the
// selection of the target it wants to reach (whereas when using the
// InDataExchange command, it is done automatically)."
func TestNTAG_GetVersionDoesNotBreakSubsequentReads(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// Setup mock responses for the full DetectType() + ReadBlock() flow:
	// 1. ReadBlock(3) for CC - InDataExchange (0x40)
	//    Response: valid NTAG CC with magic byte 0xE1
	mockTransport.SetResponse(0x40, []byte{
		0x41, 0x00, // InDataExchange response header + success status
		0xE1, 0x10, 0x3E, 0x00, // CC: magic, version, size (NTAG215), access
		0x00, 0x00, 0x00, 0x00, // Padding (NTAG returns 16 bytes)
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	})

	// 2. GetVersion() - InCommunicateThru (0x42)
	//    Response: valid NTAG215 version info
	mockTransport.SetResponse(0x42, []byte{
		0x43, 0x00, // InCommunicateThru response header + success status
		0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03, // NTAG215 version
	})

	// 3. InSelect (0x54) - re-select target after GetVersion
	//    This is the fix for the regression - without this, subsequent reads fail
	mockTransport.SetResponse(0x54, []byte{
		0x55, 0x00, // InSelect response header + success status
	})

	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, 0x00)

	// Call DetectType which internally calls GetVersion (via InCommunicateThru)
	// and then InSelect to restore target selection state
	err := tag.DetectType(context.Background())
	require.NoError(t, err, "DetectType should succeed")
	assert.Equal(t, NTAGType215, tag.tagType, "Should detect NTAG215 from version info")

	// Now verify that subsequent reads work (this would fail without the InSelect fix)
	// ReadBlock uses InDataExchange which requires proper target selection
	data, err := tag.ReadBlock(context.Background(), 4)
	require.NoError(t, err, "ReadBlock after DetectType should succeed - "+
		"if this fails with timeout error 01, the InSelect fix is not working")
	assert.NotNil(t, data, "ReadBlock should return data")
}

// TestNTAG_GetVersionFailureStillAllowsReads verifies that even when GetVersion
// fails (e.g., clone device), subsequent reads still work because we call
// InSelect regardless of GetVersion success/failure.
func TestNTAG_GetVersionFailureStillAllowsReads(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// Setup mock responses:
	// 1. ReadBlock(3) for CC - InDataExchange (0x40)
	mockTransport.SetResponse(0x40, []byte{
		0x41, 0x00,
		0xE1, 0x10, 0x12, 0x00, // CC: magic, version, size (NTAG213), access
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	})

	// 2. GetVersion() fails - InCommunicateThru (0x42) returns error
	mockTransport.SetError(0x42, errors.New("clone device: GET_VERSION not supported"))

	// 3. InSelect (0x54) - should still be called after GetVersion failure
	mockTransport.SetResponse(0x54, []byte{0x55, 0x00})

	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, 0x00)

	// DetectType should succeed using CC-based fallback
	err := tag.DetectType(context.Background())
	require.NoError(t, err, "DetectType should succeed with CC-based fallback")
	assert.Equal(t, NTAGType213, tag.tagType, "Should detect NTAG213 from CC size field")

	// Subsequent reads should still work
	data, err := tag.ReadBlock(context.Background(), 4)
	require.NoError(t, err, "ReadBlock after failed GetVersion should succeed")
	assert.NotNil(t, data)
}

// TestNTAGTag_ContextCancellation tests that context cancellation is respected
func TestNTAGTag_ContextCancellation(t *testing.T) {
	t.Parallel()

	device, _ := createMockDeviceWithTransport(t)
	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("ReadBlock_CancelledContext", func(t *testing.T) {
		t.Parallel()
		_, err := tag.ReadBlock(ctx, 4)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("WriteBlock_CancelledContext", func(t *testing.T) {
		t.Parallel()
		err := tag.WriteBlock(ctx, 4, []byte{0x01, 0x02, 0x03, 0x04})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("ReadNDEF_CancelledContext", func(t *testing.T) {
		t.Parallel()
		_, err := tag.ReadNDEF(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("FastRead_CancelledContext", func(t *testing.T) {
		t.Parallel()
		_, err := tag.FastRead(ctx, 4, 10)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("DetectType_CancelledContext", func(t *testing.T) {
		t.Parallel()
		err := tag.DetectType(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// TestNTAGTag_WriteNDEF tests NDEF writing functionality
func TestNTAGTag_WriteNDEF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		message       *NDEFMessage
		name          string
		errorContains string
		expectError   bool
	}{
		{
			name: "Empty_Message",
			setupMock: func(_ *MockTransport) {
				// No setup needed - validation happens before transport call
			},
			message: &NDEFMessage{
				Records: []NDEFRecord{},
			},
			expectError:   true,
			errorContains: "no NDEF records to write",
		},
		{
			name: "Write_Failure",
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x40, errors.New("write failed"))
			},
			message: &NDEFMessage{
				Records: []NDEFRecord{
					{Type: NDEFTypeText, Text: "Test"},
				},
			},
			expectError:   true,
			errorContains: "tag write failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = NTAGType215

			err := tag.WriteNDEF(context.Background(), tt.message)

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

// TestNTAGTag_WriteText tests the convenience WriteText method - error case
func TestNTAGTag_WriteText(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// Mock write error
	mockTransport.SetError(0x40, errors.New("write failed"))

	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
	tag.tagType = NTAGType215

	err := tag.WriteText(context.Background(), "Hi")
	assert.Error(t, err)
}

// TestNTAGTag_FastRead_InvalidRange tests FastRead with invalid address range
func TestNTAGTag_FastRead_InvalidRange(t *testing.T) {
	t.Parallel()

	device, _ := createMockDeviceWithTransport(t)
	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

	// Test invalid range (start > end)
	_, err := tag.FastRead(context.Background(), 10, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address range")
}

// TestNTAGTag_GetUserMemoryRange tests the memory range calculation for different tag types
func TestNTAGTag_GetUserMemoryRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tagType       NTAGType
		expectedStart uint8
		expectedEnd   uint8
	}{
		{"NTAG213", NTAGType213, 4, 39},
		{"NTAG215", NTAGType215, 4, 129},
		{"NTAG216", NTAGType216, 4, 225},
		{"Unknown", NTAGTypeUnknown, 4, 39}, // Defaults to smallest
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := createMockDeviceWithTransport(t)
			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = tt.tagType

			start, end := tag.GetUserMemoryRange()
			assert.Equal(t, tt.expectedStart, start)
			assert.Equal(t, tt.expectedEnd, end)
		})
	}
}

// TestNTAGTag_GetConfigPage tests configuration page addresses
func TestNTAGTag_GetConfigPage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		tagType      NTAGType
		expectedPage uint8
	}{
		{"NTAG213", NTAGType213, 41},
		{"NTAG215", NTAGType215, 131},
		{"NTAG216", NTAGType216, 227},
		{"Unknown", NTAGTypeUnknown, 41}, // Defaults to NTAG213
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := createMockDeviceWithTransport(t)
			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = tt.tagType

			page := tag.GetConfigPage()
			assert.Equal(t, tt.expectedPage, page)
		})
	}
}

// TestNTAGTag_GetPasswordPage tests password page addresses
func TestNTAGTag_GetPasswordPage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		tagType      NTAGType
		expectedPage uint8
	}{
		{"NTAG213", NTAGType213, 43},
		{"NTAG215", NTAGType215, 133},
		{"NTAG216", NTAGType216, 229},
		{"Unknown", NTAGTypeUnknown, 43},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := createMockDeviceWithTransport(t)
			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = tt.tagType

			page := tag.GetPasswordPage()
			assert.Equal(t, tt.expectedPage, page)
		})
	}
}

// TestNTAGTag_GetTotalPages tests total page count
func TestNTAGTag_GetTotalPages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tagType       NTAGType
		expectedPages uint8
	}{
		{"NTAG213", NTAGType213, 45},
		{"NTAG215", NTAGType215, 135},
		{"NTAG216", NTAGType216, 231},
		{"Unknown", NTAGTypeUnknown, 45},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := createMockDeviceWithTransport(t)
			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = tt.tagType

			pages := tag.GetTotalPages()
			assert.Equal(t, tt.expectedPages, pages)
		})
	}
}

// TestNTAGVersion_GetStorageSize tests storage size calculation
func TestNTAGVersion_GetStorageSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		storageSize  uint8
		expectedSize int
	}{
		{"NTAG213", 0x0F, 144},
		{"NTAG215", 0x11, 504},
		{"NTAG216", 0x13, 888},
		{"Unknown_Even", 0x10, 256}, // 2^8
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			version := &NTAGVersion{StorageSize: tt.storageSize}
			size := version.GetStorageSize()
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}

// TestNTAGVersion_GetNTAGType tests NTAG type detection from version
func TestNTAGVersion_GetNTAGType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version      *NTAGVersion
		name         string
		expectedType NTAGType
	}{
		{
			name:         "NTAG213",
			version:      &NTAGVersion{VendorID: 0x04, ProductType: 0x04, StorageSize: 0x0F},
			expectedType: NTAGType213,
		},
		{
			name:         "NTAG215",
			version:      &NTAGVersion{VendorID: 0x04, ProductType: 0x04, StorageSize: 0x11},
			expectedType: NTAGType215,
		},
		{
			name:         "NTAG216",
			version:      &NTAGVersion{VendorID: 0x04, ProductType: 0x04, StorageSize: 0x13},
			expectedType: NTAGType216,
		},
		{
			name:         "Invalid_Vendor",
			version:      &NTAGVersion{VendorID: 0x00, ProductType: 0x04, StorageSize: 0x11},
			expectedType: NTAGTypeUnknown,
		},
		{
			name:         "Invalid_Product",
			version:      &NTAGVersion{VendorID: 0x04, ProductType: 0x00, StorageSize: 0x11},
			expectedType: NTAGTypeUnknown,
		},
		{
			name:         "Unknown_Storage",
			version:      &NTAGVersion{VendorID: 0x04, ProductType: 0x04, StorageSize: 0x20},
			expectedType: NTAGTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ntagType := tt.version.GetNTAGType()
			assert.Equal(t, tt.expectedType, ntagType)
		})
	}
}

// TestNTAGTag_PwdAuth tests password authentication
func TestNTAGTag_PwdAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		password      []byte
		expectError   bool
	}{
		{
			name: "Successful_Auth",
			setupMock: func(mt *MockTransport) {
				// PWD_AUTH returns 2-byte PACK on success
				mt.SetResponse(0x40, []byte{0x41, 0x00, 0xAB, 0xCD})
			},
			password:    []byte{0x01, 0x02, 0x03, 0x04},
			expectError: false,
		},
		{
			name: "Invalid_Password_Length",
			setupMock: func(_ *MockTransport) {
				// No setup needed
			},
			password:      []byte{0x01, 0x02, 0x03}, // Only 3 bytes
			expectError:   true,
			errorContains: "password must be 4 bytes",
		},
		{
			name: "Auth_Failure",
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x40, errors.New("authentication failed"))
			},
			password:      []byte{0x01, 0x02, 0x03, 0x04},
			expectError:   true,
			errorContains: "PWD_AUTH failed",
		},
		{
			name: "Invalid_PACK_Response",
			setupMock: func(mt *MockTransport) {
				// Response with only 1 byte PACK (should be 2)
				mt.SetResponse(0x40, []byte{0x41, 0x00, 0xAB})
			},
			password:      []byte{0x01, 0x02, 0x03, 0x04},
			expectError:   true,
			errorContains: "invalid PACK response length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

			pack, err := tag.PwdAuth(tt.password)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, pack)
			} else {
				require.NoError(t, err)
				assert.Len(t, pack, 2)
			}
		})
	}
}

// TestNTAGTag_SetPasswordProtection tests password protection configuration
func TestNTAGTag_SetPasswordProtection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		password      []byte
		pack          []byte
		tagType       NTAGType
		auth0         uint8
		expectError   bool
	}{
		{
			name: "Invalid_Password_Length",
			setupMock: func(_ *MockTransport) {
				// No setup needed
			},
			password:      []byte{0x01, 0x02, 0x03}, // Only 3 bytes
			pack:          []byte{0x00, 0x00},
			auth0:         0x04,
			tagType:       NTAGType215,
			expectError:   true,
			errorContains: "password must be 4 bytes",
		},
		{
			name: "Invalid_PACK_Length",
			setupMock: func(_ *MockTransport) {
				// No setup needed
			},
			password:      []byte{0x01, 0x02, 0x03, 0x04},
			pack:          []byte{0x00}, // Only 1 byte
			auth0:         0x04,
			tagType:       NTAGType215,
			expectError:   true,
			errorContains: "pack must be 2 bytes",
		},
		{
			name: "Unknown_Tag_Type",
			setupMock: func(_ *MockTransport) {
				// No setup needed
			},
			password:      []byte{0x01, 0x02, 0x03, 0x04},
			pack:          []byte{0x00, 0x00},
			auth0:         0x04,
			tagType:       NTAGTypeUnknown,
			expectError:   true,
			errorContains: "unknown NTAG type",
		},
		{
			name: "Write_Password_Fails",
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x40, errors.New("write failed"))
			},
			password:      []byte{0x01, 0x02, 0x03, 0x04},
			pack:          []byte{0xAB, 0xCD},
			auth0:         0x04,
			tagType:       NTAGType213, // Use NTAG213 for smaller address space
			expectError:   true,
			errorContains: "failed to set password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = tt.tagType

			err := tag.SetPasswordProtection(context.Background(), tt.password, tt.pack, tt.auth0)

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

// TestNTAGTag_LockPage tests page locking
func TestNTAGTag_LockPage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		tagType       NTAGType
		page          uint8
		expectError   bool
	}{
		{
			name:          "Cannot_Lock_System_Page",
			setupMock:     func(_ *MockTransport) {},
			page:          2, // System page
			tagType:       NTAGType213,
			expectError:   true,
			errorContains: "cannot lock system pages",
		},
		{
			name: "Lock_Static_Page_Read_Fails",
			setupMock: func(mt *MockTransport) {
				// Read current lock bytes fails
				mt.SetError(0x40, errors.New("read failed"))
			},
			page:          5,
			tagType:       NTAGType213,
			expectError:   true,
			errorContains: "tag read failed",
		},
		{
			name:          "Unknown_Tag_Type_Dynamic",
			setupMock:     func(_ *MockTransport) {},
			page:          20,
			tagType:       NTAGTypeUnknown,
			expectError:   true,
			errorContains: "unknown NTAG type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = tt.tagType

			err := tag.LockPage(context.Background(), tt.page)

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

// TestNTAGTag_SetAccessControl tests access control configuration
func TestNTAGTag_SetAccessControl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		config        AccessControlConfig
		tagType       NTAGType
		expectError   bool
	}{
		{
			name:    "Invalid_AuthFailureLimit",
			config:  AccessControlConfig{AuthFailureLimit: 10},
			tagType: NTAGType213,
			setupMock: func(_ *MockTransport) {
				// No setup needed
			},
			expectError:   true,
			errorContains: "authFailureLimit must be 0-7",
		},
		{
			name:    "Unknown_Tag_Type",
			config:  AccessControlConfig{},
			tagType: NTAGTypeUnknown,
			setupMock: func(_ *MockTransport) {
				// No setup needed
			},
			expectError:   true,
			errorContains: "unknown NTAG type",
		},
		{
			name: "Read_CFG0_Fails",
			config: AccessControlConfig{
				Protection:       true,
				ConfigLock:       true,
				AuthFailureLimit: 3,
			},
			tagType: NTAGType213,
			setupMock: func(mt *MockTransport) {
				mt.SetError(0x40, errors.New("read failed"))
			},
			expectError:   true,
			errorContains: "tag read failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mockTransport := createMockDeviceWithTransport(t)
			tt.setupMock(mockTransport)

			tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
			tag.tagType = tt.tagType

			err := tag.SetAccessControl(context.Background(), tt.config)

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

// TestNTAGTag_detectTypeFromCapabilityContainer tests CC-based type detection
func TestNTAGTag_detectTypeFromCapabilityContainer(t *testing.T) {
	t.Parallel()

	device, _ := createMockDeviceWithTransport(t)
	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)

	tests := []struct {
		name         string
		ccData       []byte
		expectedType NTAGType
	}{
		{"NTAG213_CC", []byte{0xE1, 0x10, 0x12, 0x00}, NTAGType213},
		{"NTAG215_CC", []byte{0xE1, 0x10, 0x3E, 0x00}, NTAGType215},
		{"NTAG216_CC", []byte{0xE1, 0x10, 0x6D, 0x00}, NTAGType216},
		{"Unknown_Small", []byte{0xE1, 0x10, 0x15, 0x00}, NTAGType213},  // <= 0x20
		{"Unknown_Medium", []byte{0xE1, 0x10, 0x40, 0x00}, NTAGType215}, // 0x20 < x <= 0x50
		{"Unknown_Large", []byte{0xE1, 0x10, 0x70, 0x00}, NTAGType216},  // > 0x50
		{"Too_Short", []byte{0xE1, 0x10}, NTAGTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tag.detectTypeFromCapabilityContainer(tt.ccData)
			assert.Equal(t, tt.expectedType, result)
		})
	}
}

// TestNTAGTag_DebugInfo tests debug info generation
func TestNTAGTag_DebugInfo(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// Mock for ReadNDEFRobust called by DebugInfoWithNDEF
	mockTransport.SetError(0x40, errors.New("read error"))

	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
	tag.tagType = NTAGType215

	info := tag.DebugInfo()
	assert.NotEmpty(t, info)
	assert.Contains(t, info, "NTAG")
}

// TestNTAGTag_calculateReadRange tests read range calculation edge cases
func TestNTAGTag_calculateReadRange(t *testing.T) {
	t.Parallel()

	device, _ := createMockDeviceWithTransport(t)
	tag := NewNTAGTag(device, []byte{0x04, 0x12, 0x34, 0x56}, 0x00)
	tag.tagType = NTAGType215

	tests := []struct {
		name          string
		totalBytes    int
		expectedStart uint8
	}{
		{"Normal_Range", 100, 4},
		{"Negative_Bytes", -10, 4},
		{"Excessive_Bytes", 20000, 4},
		{"Zero_Bytes", 0, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tag.calculateReadRange(tt.totalBytes)
			assert.Equal(t, tt.expectedStart, result.startPage)
			// Just verify it doesn't panic and returns reasonable values
			assert.True(t, result.endPage >= result.startPage || tt.totalBytes <= 0)
		})
	}
}

// TestNTAGTag_isRetryableError tests retry logic
func TestNTAGTag_isRetryableError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err           error
		name          string
		expectedRetry bool
	}{
		{name: "Nil_Error", err: nil, expectedRetry: false},
		{name: "TagReadFailed", err: ErrTagReadFailed, expectedRetry: true},
		{name: "Generic_Error", err: errors.New("some error"), expectedRetry: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isRetryableError(tt.err)
			assert.Equal(t, tt.expectedRetry, result)
		})
	}
}

// TestCalculateStaticLockPosition tests lock bit position calculation
func TestCalculateStaticLockPosition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		page         uint8
		expectedByte byte
		expectedBit  byte
	}{
		{"Page_3", 3, 2, 0},
		{"Page_9", 9, 2, 6},
		{"Page_15", 15, 2, 7},
		{"Page_10", 10, 3, 0},
		{"Page_14", 14, 3, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lockByte, lockBit := calculateStaticLockPosition(tt.page)
			assert.Equal(t, tt.expectedByte, lockByte)
			assert.Equal(t, tt.expectedBit, lockBit)
		})
	}
}

// NDEF Message Tests
