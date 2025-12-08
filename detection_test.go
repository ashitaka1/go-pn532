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
	"errors"
	"testing"
	"time"

	testutil "github.com/ZaparooProject/go-pn532/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevice_DetectTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock   func(*MockTransport)
		name        string
		expectTag   bool
		expectError bool
	}{
		{
			name: "Successful_Tag_Detection",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
				mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
				mock.SetResponse(testutil.CmdInListPassiveTarget,
					testutil.BuildTagDetectionResponse("NTAG213", testutil.TestNTAG213UID))
			},
			expectTag: true,
		},
		{
			name: "No_Tag_Found",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
				mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
				mock.SetResponse(testutil.CmdInListPassiveTarget, testutil.BuildNoTagResponse())
			},
			expectTag:   false,
			expectError: true, // Should return ErrNoTagDetected
		},
		{
			name: "Detection_Error",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
				mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
				mock.SetError(testutil.CmdInListPassiveTarget, errors.New("detection failed"))
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup mock transport
			mock := NewMockTransport()
			tt.setupMock(mock)

			// Create and initialize device
			device, err := New(mock)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err = device.InitContext(ctx)
			require.NoError(t, err)

			// Test tag detection
			tag, err := device.DetectTag(ctx)

			switch {
			case tt.expectError:
				require.Error(t, err)
				assert.Nil(t, tag)
			case tt.expectTag:
				require.NoError(t, err)
				assert.NotNil(t, tag)
				assert.NotEmpty(t, tag.UID)
			default:
				require.NoError(t, err)
				assert.Nil(t, tag)
			}
		})
	}
}

func TestDevice_WaitForTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock   func(*MockTransport)
		name        string
		timeout     time.Duration
		expectError bool
		expectTag   bool
	}{
		{
			name: "Tag_Found_Quickly",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
				mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
				mock.SetResponse(testutil.CmdInListPassiveTarget,
					testutil.BuildTagDetectionResponse("NTAG213", testutil.TestNTAG213UID))
			},
			timeout:     time.Second,
			expectError: false,
			expectTag:   true,
		},
		{
			name: "Timeout_No_Tag",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
				mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
				// The mock will return the same "no tag" response for multiple calls
				mock.SetResponse(testutil.CmdInListPassiveTarget, testutil.BuildNoTagResponse())
			},
			timeout:     300 * time.Millisecond, // Give enough time for multiple polling cycles
			expectError: true,
			expectTag:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup mock transport
			mock := NewMockTransport()
			tt.setupMock(mock)

			// Create and initialize device
			device, err := New(mock)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err = device.InitContext(ctx)
			require.NoError(t, err)

			// Test waiting for tag with timeout context
			waitCtx, waitCancel := context.WithTimeout(context.Background(), tt.timeout)
			defer waitCancel()

			start := time.Now()
			tag, err := device.WaitForTag(waitCtx)
			elapsed := time.Since(start)

			switch {
			case tt.expectError:
				require.Error(t, err)
				assert.Nil(t, tag)
				// For timeout test, verify we get context deadline exceeded and that it actually waited
				if tt.name == "Timeout_No_Tag" {
					require.ErrorIs(t, err, context.DeadlineExceeded,
						"Expected context deadline exceeded error, got: %v", err)
					// Verify it actually waited close to the timeout duration
					assert.GreaterOrEqual(t, elapsed, tt.timeout-50*time.Millisecond,
						"Should have waited close to timeout duration")
					// Verify polling happened multiple times
					callCount := mock.GetCallCount(testutil.CmdInListPassiveTarget)
					assert.Greater(t, callCount, 1, "Should have made multiple polling attempts")
				}
			case tt.expectTag:
				require.NoError(t, err)
				assert.NotNil(t, tag)
				assert.NotEmpty(t, tag.UID)
			default:
				require.NoError(t, err)
				assert.Nil(t, tag)
			}
		})
	}
}

func TestDevice_SimplePoll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		pollingPeriod time.Duration
		timeout       time.Duration
		expectTag     bool
		expectError   bool
	}{
		{
			name: "Successful_Polling",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
				mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
				mock.SetResponse(testutil.CmdInListPassiveTarget,
					testutil.BuildTagDetectionResponse("NTAG213", testutil.TestNTAG213UID))
			},
			pollingPeriod: 50 * time.Millisecond,
			timeout:       time.Second,
			expectTag:     true,
		},
		{
			name: "Polling_Timeout",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
				mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
				mock.SetResponse(testutil.CmdInListPassiveTarget, testutil.BuildNoTagResponse())
			},
			pollingPeriod: 20 * time.Millisecond,
			timeout:       100 * time.Millisecond,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup mock transport
			mock := NewMockTransport()
			tt.setupMock(mock)

			// Create and initialize device
			device, err := New(mock)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err = device.InitContext(ctx)
			require.NoError(t, err)

			// Test simple polling with timeout context
			pollCtx, pollCancel := context.WithTimeout(context.Background(), tt.timeout)
			defer pollCancel()

			tag, err := device.SimplePoll(pollCtx, tt.pollingPeriod)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, tag)
			} else if tt.expectTag {
				require.NoError(t, err)
				assert.NotNil(t, tag)
				assert.NotEmpty(t, tag.UID)
			}

			// Verify polling was attempted multiple times for timeout cases
			if tt.expectError {
				// Should have made multiple attempts during the polling period
				callCount := mock.GetCallCount(testutil.CmdInListPassiveTarget)
				assert.Greater(t, callCount, 1, "Should have made multiple polling attempts")
			}
		})
	}
}

func TestDevice_DetectTags_WithFilters(t *testing.T) {
	t.Parallel()

	// Setup mock with multiple tag types
	mock := NewMockTransport()
	mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
	mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
	mock.SetResponse(testutil.CmdInListPassiveTarget,
		testutil.BuildTagDetectionResponse("NTAG213", testutil.TestNTAG213UID))

	device, err := New(mock)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = device.InitContext(ctx)
	require.NoError(t, err)

	// Test detection with basic parameters (maxTags=1, baudRate=0)
	tags, err := device.DetectTags(ctx, 1, 0)
	require.NoError(t, err)
	assert.Len(t, tags, 1)

	// Test detection with multiple targets
	tags, err = device.DetectTags(ctx, 2, 0)
	require.NoError(t, err)
	// Should still return just 1 tag since mock only provides 1
	assert.LessOrEqual(t, len(tags), 1)
}

func TestFilterDetectedTags(t *testing.T) {
	t.Parallel()

	// Create test tags
	testTags := []*DetectedTag{
		{
			Type:     TagTypeNTAG,
			UID:      "04abcdef123456",
			UIDBytes: testutil.TestNTAG213UID,
		},
		{
			Type:     TagTypeMIFARE,
			UID:      "12345678",
			UIDBytes: testutil.TestMIFARE1KUID,
		},
	}

	tests := []struct {
		name        string
		tags        []*DetectedTag
		tagType     TagType
		uidFilter   []byte
		expectedLen int
	}{
		{
			name:        "No_Filter",
			tags:        testTags,
			tagType:     TagTypeAny,
			uidFilter:   nil,
			expectedLen: 2,
		},
		{
			name:        "NTAG_Filter",
			tags:        testTags,
			tagType:     TagTypeNTAG,
			uidFilter:   nil,
			expectedLen: 1,
		},
		{
			name:        "MIFARE_Filter",
			tags:        testTags,
			tagType:     TagTypeMIFARE,
			uidFilter:   nil,
			expectedLen: 1,
		},
		{
			name:        "UID_Bytes_Filter",
			tags:        testTags,
			tagType:     TagTypeAny,
			uidFilter:   testutil.TestNTAG213UID,
			expectedLen: 1,
		},
		{
			name:        "No_Match_Filter",
			tags:        testTags,
			tagType:     TagTypeFeliCa,
			uidFilter:   nil,
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filtered := filterDetectedTags(tt.tags, tt.tagType, tt.uidFilter)
			assert.Len(t, filtered, tt.expectedLen)

			// Verify filtering logic
			for _, tag := range filtered {
				if tt.tagType != TagTypeAny {
					assert.Equal(t, tt.tagType, tag.Type)
				}
				if tt.uidFilter != nil {
					assert.Equal(t, tt.uidFilter, tag.UIDBytes)
				}
			}
		})
	}
}

// Helper function for testing In commands (InRelease/InSelect)
func testInCommand(t *testing.T, testName string, cmd byte, deviceFunc func(*Device, context.Context, byte) error) {
	t.Helper()

	tests := []struct {
		setupMock   func(*MockTransport)
		name        string
		targetID    byte
		expectError bool
	}{
		{
			name: "Successful_" + testName,
			setupMock: func(mock *MockTransport) {
				// Correct format: cmd response + success status
				mock.SetResponse(cmd, []byte{cmd + 1, 0x00})
			},
			targetID:    1,
			expectError: false,
		},
		{
			name: testName + "_Error",
			setupMock: func(mock *MockTransport) {
				mock.SetError(cmd, errors.New(testName+" failed"))
			},
			targetID:    1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup mock transport
			mock := NewMockTransport()
			mock.SelectTarget() // InRelease/InSelect require a target to be selected
			tt.setupMock(mock)

			// Create device
			device, err := New(mock)
			require.NoError(t, err)

			// Test the command
			err = deviceFunc(device, context.Background(), tt.targetID)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, 1, mock.GetCallCount(cmd))
			}
		})
	}
}

func TestDevice_InRelease(t *testing.T) {
	t.Parallel()
	testInCommand(t, "Release", testutil.CmdInRelease, (*Device).InRelease)
}

func TestDevice_InSelect(t *testing.T) {
	t.Parallel()
	testInCommand(t, "Select", testutil.CmdInSelect, (*Device).InSelect)
}

func TestDevice_SelectTag(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := NewMockTransport()
		defer func() { _ = mock.Close() }()

		mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
		mock.SetResponse(testutil.CmdInSelect, []byte{0x55, 0x00}) // Success
		mock.SelectTarget()                                        // Simulate a tag was detected

		device, err := New(mock)
		require.NoError(t, err)

		tag := &DetectedTag{TargetNumber: 1}
		err = device.SelectTag(context.Background(), tag)
		assert.NoError(t, err)
	})

	t.Run("NilTag", func(t *testing.T) {
		t.Parallel()
		mock := NewMockTransport()
		defer func() { _ = mock.Close() }()

		mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())

		device, err := New(mock)
		require.NoError(t, err)

		err = device.SelectTag(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})
}

// TestHandleDetectionError tests the error counting and threshold behavior
func TestHandleDetectionError(t *testing.T) {
	t.Parallel()

	device := &Device{}

	t.Run("First_Few_Errors_Logged", func(t *testing.T) {
		t.Parallel()
		errorCount := 0
		for i := range 3 {
			err := device.handleDetectionError(&errorCount, errors.New("test error"))
			require.NoError(t, err)
			assert.Equal(t, i+1, errorCount)
		}
	})

	t.Run("Too_Many_Errors_Returns_Error", func(t *testing.T) {
		t.Parallel()
		errorCount := 10 // Start at max
		err := device.handleDetectionError(&errorCount, errors.New("final error"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many detection errors")
	})
}

// TestPauseWithContext tests the pauseWithContext function
func TestPauseWithContext(t *testing.T) {
	t.Parallel()

	device := &Device{}

	t.Run("Normal_Pause", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		start := time.Now()
		err := device.pauseWithContext(ctx, 50*time.Millisecond)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, elapsed, 45*time.Millisecond)
	})

	t.Run("Context_Cancelled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := device.pauseWithContext(ctx, 1*time.Second)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// TestMatchesUIDFilter tests the UID filtering logic
func TestMatchesUIDFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tagUID     []byte
		filterUID  []byte
		shouldPass bool
	}{
		{
			name:       "Empty_Filter_Always_Matches",
			tagUID:     []byte{0x04, 0x12, 0x34, 0x56},
			filterUID:  nil,
			shouldPass: true,
		},
		{
			name:       "Exact_Match",
			tagUID:     []byte{0x04, 0x12, 0x34, 0x56},
			filterUID:  []byte{0x04, 0x12, 0x34, 0x56},
			shouldPass: true,
		},
		{
			name:       "Partial_Prefix_Match",
			tagUID:     []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			filterUID:  []byte{0x04, 0x12},
			shouldPass: true,
		},
		{
			name:       "Partial_No_Match",
			tagUID:     []byte{0x04, 0x12, 0x34, 0x56},
			filterUID:  []byte{0x04, 0x99},
			shouldPass: false,
		},
		{
			name:       "Filter_Longer_Than_UID",
			tagUID:     []byte{0x04, 0x12},
			filterUID:  []byte{0x04, 0x12, 0x34, 0x56},
			shouldPass: false,
		},
		{
			name:       "Single_Byte_Filter_Match",
			tagUID:     []byte{0x04, 0x12, 0x34, 0x56},
			filterUID:  []byte{0x04},
			shouldPass: true,
		},
		{
			name:       "Single_Byte_Filter_No_Match",
			tagUID:     []byte{0x04, 0x12, 0x34, 0x56},
			filterUID:  []byte{0x05},
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag := &DetectedTag{UIDBytes: tt.tagUID}
			result := matchesUIDFilter(tag, tt.filterUID)
			assert.Equal(t, tt.shouldPass, result)
		})
	}
}

// TestShouldIncludeTag tests the combined tag filtering logic
func TestShouldIncludeTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tag        *DetectedTag
		tagType    TagType
		uid        []byte
		shouldPass bool
	}{
		{
			name:       "Any_Type_No_UID_Filter",
			tag:        &DetectedTag{Type: TagTypeNTAG, UIDBytes: []byte{0x04, 0x12}},
			tagType:    TagTypeAny,
			uid:        nil,
			shouldPass: true,
		},
		{
			name:       "Matching_Type_No_UID_Filter",
			tag:        &DetectedTag{Type: TagTypeNTAG, UIDBytes: []byte{0x04, 0x12}},
			tagType:    TagTypeNTAG,
			uid:        nil,
			shouldPass: true,
		},
		{
			name:       "Non_Matching_Type",
			tag:        &DetectedTag{Type: TagTypeMIFARE, UIDBytes: []byte{0x04, 0x12}},
			tagType:    TagTypeNTAG,
			uid:        nil,
			shouldPass: false,
		},
		{
			name:       "Matching_Type_And_UID",
			tag:        &DetectedTag{Type: TagTypeNTAG, UIDBytes: []byte{0x04, 0x12, 0x34}},
			tagType:    TagTypeNTAG,
			uid:        []byte{0x04, 0x12},
			shouldPass: true,
		},
		{
			name:       "Matching_Type_Non_Matching_UID",
			tag:        &DetectedTag{Type: TagTypeNTAG, UIDBytes: []byte{0x04, 0x12, 0x34}},
			tagType:    TagTypeNTAG,
			uid:        []byte{0x99, 0x99},
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := shouldIncludeTag(tt.tag, tt.tagType, tt.uid)
			assert.Equal(t, tt.shouldPass, result)
		})
	}
}

// TestIdentifyTagType tests tag type identification from ATQ and SAK
func TestIdentifyTagType(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
	mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
	device, _ := New(mock)

	tests := []struct {
		name         string
		expectedType TagType
		atq          []byte
		sak          byte
	}{
		// NTAG patterns
		{name: "NTAG_Standard_SAK00", expectedType: TagTypeNTAG, atq: []byte{0x00, 0x44}, sak: 0x00},
		{name: "NTAG_Swapped_SAK00", expectedType: TagTypeNTAG, atq: []byte{0x44, 0x00}, sak: 0x00},
		{name: "NTAG_Standard_SAK04", expectedType: TagTypeNTAG, atq: []byte{0x00, 0x44}, sak: 0x04},
		{name: "NTAG_Alternative_0101", expectedType: TagTypeNTAG, atq: []byte{0x01, 0x01}, sak: 0x00},
		{name: "NTAG_Additional_0100_44", expectedType: TagTypeNTAG, atq: []byte{0x01, 0x00}, sak: 0x44},
		{name: "NTAG_Additional_0004_00", expectedType: TagTypeNTAG, atq: []byte{0x00, 0x04}, sak: 0x00},
		{name: "NTAG_Additional_0400_00", expectedType: TagTypeNTAG, atq: []byte{0x04, 0x00}, sak: 0x00},

		// MIFARE patterns
		{name: "MIFARE_Classic_1K", expectedType: TagTypeMIFARE, atq: []byte{0x00, 0x04}, sak: 0x08},
		{name: "MIFARE_Classic_4K", expectedType: TagTypeMIFARE, atq: []byte{0x00, 0x02}, sak: 0x18},
		{name: "MIFARE_Compatible", expectedType: TagTypeMIFARE, atq: []byte{0x01, 0x00}, sak: 0x04},

		// Unknown patterns
		{name: "Unknown_Invalid_ATQ", expectedType: TagTypeUnknown, atq: []byte{0x00}, sak: 0x00},
		{name: "Unknown_No_Match", expectedType: TagTypeUnknown, atq: []byte{0x99, 0x99}, sak: 0x99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := device.identifyTagType(tt.atq, tt.sak)
			assert.Equal(t, tt.expectedType, result)
		})
	}
}

// TestCreateTag tests tag creation for different tag types
//
//nolint:funlen // Table-driven test with multiple test cases
func TestCreateTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		detected      *DetectedTag
		expectedType  string
		expectError   bool
	}{
		{
			name: "Create_NTAG",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInSelect, []byte{0x55, 0x00})
			},
			detected: &DetectedTag{
				Type:         TagTypeNTAG,
				UIDBytes:     []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
				SAK:          0x00,
				TargetNumber: 1,
			},
			expectedType: "*pn532.NTAGTag",
			expectError:  false,
		},
		{
			name: "Create_MIFARE",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInSelect, []byte{0x55, 0x00})
			},
			detected: &DetectedTag{
				Type:         TagTypeMIFARE,
				UIDBytes:     []byte{0x12, 0x34, 0x56, 0x78},
				SAK:          0x08,
				TargetNumber: 1,
			},
			expectedType: "*pn532.MIFARETag",
			expectError:  false,
		},
		{
			name:      "Create_Unknown_Tag_Fails",
			setupMock: func(_ *MockTransport) {},
			detected: &DetectedTag{
				Type:         TagTypeUnknown,
				UIDBytes:     []byte{0x12, 0x34, 0x56, 0x78},
				TargetNumber: 1,
			},
			expectError:   true,
			errorContains: "",
		},
		{
			name:      "Create_TagTypeAny_Fails",
			setupMock: func(_ *MockTransport) {},
			detected: &DetectedTag{
				Type:         TagTypeAny,
				UIDBytes:     []byte{0x12, 0x34, 0x56, 0x78},
				TargetNumber: 1,
			},
			expectError:   true,
			errorContains: "",
		},
		{
			name: "Create_From_InAutoPoll_Skips_Select",
			setupMock: func(_ *MockTransport) {
				// No InSelect call expected
			},
			detected: &DetectedTag{
				Type:           TagTypeNTAG,
				UIDBytes:       []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
				SAK:            0x00,
				TargetNumber:   1,
				FromInAutoPoll: true, // This skips InSelect
			},
			expectedType: "*pn532.NTAGTag",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
			mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
			tt.setupMock(mock)
			mock.SelectTarget()

			device, err := New(mock)
			require.NoError(t, err)

			tag, err := device.CreateTag(tt.detected)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, tag)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tag)
				// Verify tag type matches expected
				tagTypeName := typeName(tag)
				assert.Equal(t, tt.expectedType, tagTypeName)
			}
		})
	}
}

// typeName returns the type name of any value
func typeName(v any) string {
	if v == nil {
		return "nil"
	}
	return "*pn532." + string(v.(Tag).Type()) + "Tag"
}

// TestHandleTargetSelection tests target selection handling
func TestHandleTargetSelection(t *testing.T) {
	t.Parallel()

	t.Run("FromInAutoPoll_Skips_InSelect", func(t *testing.T) {
		t.Parallel()

		mock := NewMockTransport()
		mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
		mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
		mock.SelectTarget()

		device, _ := New(mock)

		detected := &DetectedTag{
			Type:           TagTypeNTAG,
			TargetNumber:   1,
			FromInAutoPoll: true,
		}

		err := device.handleTargetSelection(detected)
		require.NoError(t, err)
		// Verify InSelect was NOT called
		assert.Equal(t, 0, mock.GetCallCount(testutil.CmdInSelect))
	})

	t.Run("Standard_Detection_Calls_InSelect", func(t *testing.T) {
		t.Parallel()

		mock := NewMockTransport()
		mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
		mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
		mock.SetResponse(testutil.CmdInSelect, []byte{0x55, 0x00})
		mock.SelectTarget()

		device, _ := New(mock)

		detected := &DetectedTag{
			Type:           TagTypeNTAG,
			TargetNumber:   1,
			FromInAutoPoll: false, // Standard detection
		}

		err := device.handleTargetSelection(detected)
		require.NoError(t, err)
		// Verify InSelect WAS called
		assert.Equal(t, 1, mock.GetCallCount(testutil.CmdInSelect))
	})
}

// TestInitiatorListPassiveTargets tests the InitiatorListPassiveTargets method
func TestInitiatorListPassiveTargets(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	mock.SetResponse(testutil.CmdGetFirmwareVersion, testutil.BuildFirmwareVersionResponse())
	mock.SetResponse(testutil.CmdSAMConfiguration, testutil.BuildSAMConfigurationResponse())
	mock.SetResponse(testutil.CmdInListPassiveTarget,
		testutil.BuildTagDetectionResponse("NTAG213", testutil.TestNTAG213UID))

	device, err := New(mock)
	require.NoError(t, err)

	ctx := context.Background()

	// Test with no filters
	tags, err := device.InitiatorListPassiveTargets(ctx, 1, TagTypeAny, nil)
	require.NoError(t, err)
	assert.Len(t, tags, 1)

	// Test with type filter that doesn't match
	tags, err = device.InitiatorListPassiveTargets(ctx, 1, TagTypeFeliCa, nil)
	require.NoError(t, err)
	assert.Empty(t, tags)
}
