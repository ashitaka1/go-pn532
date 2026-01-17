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

//nolint:dupl // Test file - similar test patterns are acceptable
package pn532

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFirmwareVersionCancellation(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	// Configure mock to simulate a delay that allows cancellation
	mock.SetDelay(100 * time.Millisecond)

	device, err := New(mock)
	require.NoError(t, err)

	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// This should fail due to context cancellation before the mock delay completes
	_, err = device.GetFirmwareVersion(ctx)

	// Verify that context cancellation is propagated
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded,
		"Expected context.DeadlineExceeded, got: %v", err)
}

func TestGetGeneralStatusCancellation(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	mock.SetDelay(50 * time.Millisecond)

	device, err := New(mock)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = device.GetGeneralStatus(ctx)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded,
		"Expected context.DeadlineExceeded, got: %v", err)
}

func TestDiagnoseCancellation(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	mock.SetDelay(50 * time.Millisecond)

	device, err := New(mock)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = device.Diagnose(ctx, 0x00, []byte{0x01, 0x02})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded,
		"Expected context.DeadlineExceeded, got: %v", err)
}

func TestDevice_Reset(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	defer func() { _ = mock.Close() }()

	// Set up responses for initialization
	mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07}) // GetFirmwareVersion
	mock.SetResponse(0x14, []byte{0x15})                         // SAMConfiguration
	mock.SetResponse(0x32, []byte{0x33})                         // RFConfiguration

	device, err := New(mock)
	require.NoError(t, err)

	// Reset should reinitialize
	err = device.Reset(context.Background())
	require.NoError(t, err)

	// Verify firmware version was fetched (at least 2 calls - init + reset)
	assert.GreaterOrEqual(t, mock.GetCallCount(0x02), 2, "GetFirmwareVersion should be called during reset")
}

// TestHandleSAMConfiguration_CloneDevice tests clone device detection during SAM config
func TestHandleSAMConfiguration_CloneDevice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock   func(*MockTransport)
		name        string
		expectError bool
	}{
		{
			name: "Clone_Device_Wrong_Response_Code",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07}) // GetFirmwareVersion
				mock.SetResponse(0x32, []byte{0x33})                         // RFConfiguration
				// SAM config returns unexpected response code 03 (clone device behavior)
				mock.SetResponse(0x14, []byte{0x03})
			},
			expectError: false, // Should continue despite clone device quirk
		},
		{
			name: "Clone_Device_Empty_Response",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07}) // GetFirmwareVersion
				mock.SetResponse(0x32, []byte{0x33})                         // RFConfiguration
				// SAM config returns empty (handled as clone device)
				mock.SetResponse(0x14, []byte{})
			},
			expectError: false, // Should continue despite clone device quirk
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			defer func() { _ = mock.Close() }()

			tt.setupMock(mock)

			_, err := New(mock)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestParseFirmwareResponse_Variations tests firmware response parsing for different device types
func TestParseFirmwareResponse_Variations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock      func(*MockTransport)
		name           string
		expectedVer    string
		expectedISO14A bool
	}{
		{
			name: "Standard_PN532_Response",
			setupMock: func(mock *MockTransport) {
				// Standard format: 0x03 + IC(0x32) + Version(1,6) + Support
				mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
				mock.SetResponse(0x14, []byte{0x15})
				mock.SetResponse(0x32, []byte{0x33})
			},
			expectedVer:    "1.6",
			expectedISO14A: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			defer func() { _ = mock.Close() }()

			tt.setupMock(mock)

			device, err := New(mock)
			require.NoError(t, err)

			// Verify GetFirmwareVersion returns expected result
			fw, err := device.GetFirmwareVersion(context.Background())
			require.NoError(t, err)
			require.NotNil(t, fw)
			assert.Equal(t, tt.expectedVer, fw.Version)
			assert.Equal(t, tt.expectedISO14A, fw.SupportIso14443a)
		})
	}
}

// TestDiagnose_TestTypes tests different diagnostic test types
func TestDiagnose_TestTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		data          []byte
		testNumber    byte
		expectSuccess bool
	}{
		{
			name: "ROM_Test_Success",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(0x00, []byte{0x01, 0x00}) // ROM test OK
			},
			testNumber:    DiagnoseROMTest,
			data:          []byte{},
			expectSuccess: true,
		},
		{
			name: "ROM_Test_Failure",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(0x00, []byte{0x01, 0xFF}) // ROM test failed
			},
			testNumber:    DiagnoseROMTest,
			data:          []byte{},
			expectSuccess: false,
		},
		{
			name: "Communication_Test_Echo",
			setupMock: func(mock *MockTransport) {
				// Echo back: 0x01 header + command payload (test number + data)
				mock.SetResponse(0x00, []byte{0x01, 0x00, 0xAA, 0xBB})
			},
			testNumber:    DiagnoseCommunicationTest,
			data:          []byte{0xAA, 0xBB},
			expectSuccess: true,
		},
		{
			name: "Polling_Test_Success",
			setupMock: func(mock *MockTransport) {
				// Polling test: 0x01 header + failure count (0 = success)
				mock.SetResponse(0x00, []byte{0x01, 0x00})
			},
			testNumber:    DiagnosePollingTest,
			data:          []byte{0x06, 0x01, 0x00, 0x00},
			expectSuccess: true,
		},
		{
			name: "Attention_Test",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(0x00, []byte{0x01})
			},
			testNumber:    DiagnoseAttentionTest,
			data:          []byte{},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			defer func() { _ = mock.Close() }()

			// Set up initialization responses
			mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
			mock.SetResponse(0x14, []byte{0x15})
			mock.SetResponse(0x32, []byte{0x33})

			tt.setupMock(mock)

			device, err := New(mock)
			require.NoError(t, err)

			result, err := device.Diagnose(context.Background(), tt.testNumber, tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.expectSuccess, result.Success)
		})
	}
}

// TestInRelease tests InRelease command
func TestInRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		expectError   bool
	}{
		{
			name: "Success",
			setupMock: func(mock *MockTransport) {
				mock.SelectTarget()
				mock.SetResponse(0x52, []byte{0x53, 0x00})
			},
			expectError: false,
		},
		{
			name: "Failure_Status",
			setupMock: func(mock *MockTransport) {
				mock.SelectTarget()
				mock.SetResponse(0x52, []byte{0x53, 0x01})
			},
			expectError:   true,
			errorContains: "failed with status",
		},
		{
			name: "Invalid_Response",
			setupMock: func(mock *MockTransport) {
				mock.SelectTarget()
				mock.SetResponse(0x52, []byte{0x99, 0x00})
			},
			expectError:   true,
			errorContains: "unexpected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			defer func() { _ = mock.Close() }()

			// Set up initialization responses
			mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
			mock.SetResponse(0x14, []byte{0x15})
			mock.SetResponse(0x32, []byte{0x33})

			tt.setupMock(mock)

			device, err := New(mock)
			require.NoError(t, err)

			err = device.InRelease(context.Background())

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

// TestInSelect tests InSelect command
func TestInSelect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		expectError   bool
	}{
		{
			name: "Success",
			setupMock: func(mock *MockTransport) {
				mock.SelectTarget()
				mock.SetResponse(0x54, []byte{0x55, 0x00})
			},
			expectError: false,
		},
		{
			name: "Wrong_Context_Treated_As_Success",
			setupMock: func(mock *MockTransport) {
				mock.SelectTarget()
				mock.SetResponse(0x54, []byte{0x55, 0x27})
			},
			expectError: false, // 0x27 treated as "already selected"
		},
		{
			name: "Other_Failure",
			setupMock: func(mock *MockTransport) {
				mock.SelectTarget()
				mock.SetResponse(0x54, []byte{0x55, 0x01})
			},
			expectError:   true,
			errorContains: "failed with status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			defer func() { _ = mock.Close() }()

			// Set up initialization responses
			mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
			mock.SetResponse(0x14, []byte{0x15})
			mock.SetResponse(0x32, []byte{0x33})

			tt.setupMock(mock)

			device, err := New(mock)
			require.NoError(t, err)

			err = device.InSelect(context.Background())

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

// TestPowerDown tests the PowerDown command
func TestPowerDown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setupMock     func(*MockTransport)
		name          string
		errorContains string
		expectError   bool
	}{
		{
			name: "Success",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(0x16, []byte{0x17})
			},
			expectError: false,
		},
		{
			name: "Invalid_Response",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(0x16, []byte{0x99})
			},
			expectError:   true,
			errorContains: "unexpected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			defer func() { _ = mock.Close() }()

			// Set up initialization responses
			mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
			mock.SetResponse(0x14, []byte{0x15})
			mock.SetResponse(0x32, []byte{0x33})

			tt.setupMock(mock)

			device, err := New(mock)
			require.NoError(t, err)

			err = device.PowerDown(context.Background(), 0x00, 0x00)

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

// TestInAutoPoll_Validation tests input validation for InAutoPoll
func TestInAutoPoll_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		errorContains string
		targets       []AutoPollTarget
		pollPeriod    byte
	}{
		{
			name:          "Invalid_Poll_Period_Zero",
			pollPeriod:    0,
			targets:       []AutoPollTarget{AutoPollMifare},
			errorContains: "poll period",
		},
		{
			name:          "Invalid_Poll_Period_Too_High",
			pollPeriod:    16,
			targets:       []AutoPollTarget{AutoPollMifare},
			errorContains: "poll period",
		},
		{
			name:          "Empty_Target_Types",
			pollPeriod:    3,
			targets:       []AutoPollTarget{},
			errorContains: "must specify",
		},
		{
			name:          "Too_Many_Target_Types",
			pollPeriod:    3,
			targets:       make([]AutoPollTarget, 16),
			errorContains: "must specify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockTransport()
			defer func() { _ = mock.Close() }()

			mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
			mock.SetResponse(0x14, []byte{0x15})
			mock.SetResponse(0x32, []byte{0x33})

			device, err := New(mock)
			require.NoError(t, err)

			_, err = device.InAutoPoll(context.Background(), 1, tt.pollPeriod, tt.targets)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

// Regression tests for HardReset - fixes firmware lockup recovery

func TestDevice_HardReset_Success(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	defer func() { _ = mock.Close() }()

	// Set up initialization responses
	mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07}) // GetFirmwareVersion
	mock.SetResponse(0x14, []byte{0x15})                         // SAMConfiguration
	mock.SetResponse(0x32, []byte{0x33})                         // RFConfiguration

	device, err := New(mock)
	require.NoError(t, err)

	// Record SAM call count before HardReset
	samCountBefore := mock.GetCallCount(0x14)

	// HardReset should succeed - mock implements Reconnecter
	err = device.HardReset(context.Background())
	require.NoError(t, err)

	// Verify SAMConfiguration was called during recovery (at least once more)
	samCountAfter := mock.GetCallCount(0x14)
	assert.Greater(t, samCountAfter, samCountBefore,
		"SAMConfiguration should be called during HardReset")
}

func TestDevice_HardReset_TransportNotReconnecter(t *testing.T) {
	t.Parallel()

	// Create a transport that doesn't implement Reconnecter by embedding
	// MockTransport but not exposing Reconnect (embedding pointer won't work here)
	// Instead, we create a minimal wrapper

	mock := NewMockTransport()
	mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
	mock.SetResponse(0x14, []byte{0x15})
	mock.SetResponse(0x32, []byte{0x33})

	// Wrap in a type that only exposes Transport interface, not Reconnecter
	wrapper := &transportWrapper{Transport: mock}

	device, err := New(wrapper)
	require.NoError(t, err)

	err = device.HardReset(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support reconnection")
}

// transportWrapper wraps a Transport to hide the Reconnecter interface
type transportWrapper struct {
	Transport
}

func TestDevice_HardReset_ReconnectFails(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	defer func() { _ = mock.Close() }()

	mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
	mock.SetResponse(0x14, []byte{0x15})
	mock.SetResponse(0x32, []byte{0x33})

	device, err := New(mock)
	require.NoError(t, err)

	// Configure mock to fail on Reconnect
	mock.SetReconnectError(errors.New("USB device disconnected"))

	err = device.HardReset(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reconnect failed")
	assert.Contains(t, err.Error(), "USB device disconnected")
}

func TestDevice_HardReset_SAMConfigFails(t *testing.T) {
	t.Parallel()

	mock := NewMockTransport()
	defer func() { _ = mock.Close() }()

	mock.SetResponse(0x02, []byte{0x03, 0x32, 0x01, 0x06, 0x07})
	mock.SetResponse(0x14, []byte{0x15}) // SAM success for initial device creation
	mock.SetResponse(0x32, []byte{0x33})

	device, err := New(mock)
	require.NoError(t, err)

	// Now configure SAMConfiguration to fail for the recovery attempt
	mock.SetError(0x14, errors.New("SAM configuration timeout"))

	err = device.HardReset(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SAMConfiguration failed")
}
