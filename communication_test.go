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
	"errors"
	"testing"

	testutil "github.com/ZaparooProject/go-pn532/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to setup device with mock transport
func setupDeviceWithMock(t *testing.T, setupMock func(*MockTransport)) (*Device, *MockTransport) {
	t.Helper()
	mock := NewMockTransport()
	mock.SelectTarget() // Most communication tests need a target selected
	setupMock(mock)
	device, err := New(mock)
	require.NoError(t, err)
	return device, mock
}

// Helper function for standard error checking pattern
func checkTestError(t *testing.T, err error, errorSubstring string, result []byte) {
	t.Helper()
	require.Error(t, err)
	if errorSubstring != "" {
		assert.Contains(t, err.Error(), errorSubstring)
	}
	assert.Nil(t, result)
}

func checkTestSuccess(t *testing.T, err error, result, expectedData []byte) {
	t.Helper()
	require.NoError(t, err)
	assert.Equal(t, expectedData, result)
}

// Helper function for PowerDown test error checking
func checkPowerDownError(t *testing.T, err error, errorSubstring string) {
	t.Helper()
	require.Error(t, err)
	if errorSubstring != "" {
		assert.Contains(t, err.Error(), errorSubstring)
	}
}

func checkPowerDownSuccess(t *testing.T, err error, mock *MockTransport, cmdPowerDown byte) {
	t.Helper()
	require.NoError(t, err)
	assert.Equal(t, 1, mock.GetCallCount(cmdPowerDown))
}

func getDataExchangeTestCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	inputData      []byte
	expectedData   []byte
	expectError    bool
} {
	cases := []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		inputData      []byte
		expectedData   []byte
		expectError    bool
	}{}

	cases = append(cases, getDataExchangeSuccessCases()...)
	cases = append(cases, getDataExchangeErrorCases()...)

	return cases
}

func getDataExchangeSuccessCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	inputData      []byte
	expectedData   []byte
	expectError    bool
} {
	return []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		inputData      []byte
		expectedData   []byte
		expectError    bool
	}{
		{
			name: "Successful_Data_Exchange",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInDataExchange, []byte{0x41, 0x00, 0xAA, 0xBB})
			},
			inputData:    []byte{0x00, 0x01, 0x02},
			expectedData: []byte{0xAA, 0xBB},
			expectError:  false,
		},
		{
			name: "Empty_Input_Data",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInDataExchange, []byte{0x41, 0x00})
			},
			inputData:    []byte{},
			expectedData: []byte{},
			expectError:  false,
		},
		{
			name: "Large_Data_Exchange",
			setupMock: func(mock *MockTransport) {
				largeResponse := make([]byte, 200)
				for i := range largeResponse {
					largeResponse[i] = byte(i % 256)
				}
				response := []byte{0x41, 0x00}
				response = append(response, largeResponse...)
				mock.SetResponse(testutil.CmdInDataExchange, response)
			},
			inputData: make([]byte, 100),
			expectedData: func() []byte {
				data := make([]byte, 200)
				for i := range data {
					data[i] = byte(i % 256)
				}
				return data
			}(),
			expectError: false,
		},
	}
}

func getDataExchangeErrorCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	inputData      []byte
	expectedData   []byte
	expectError    bool
} {
	return []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		inputData      []byte
		expectedData   []byte
		expectError    bool
	}{
		{
			name: "Transport_Command_Error",
			setupMock: func(mock *MockTransport) {
				mock.SetError(testutil.CmdInDataExchange, errors.New("transport failure"))
			},
			inputData:      []byte{0x01, 0x02},
			expectError:    true,
			errorSubstring: "failed to send data exchange command",
		},
		{
			name: "PN532_Error_Frame",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInDataExchange, []byte{0x7F, 0x01})
			},
			inputData:      []byte{0x01, 0x02},
			expectError:    true,
			errorSubstring: "InDataExchange error 0x01",
		},
		{
			name: "Invalid_Response_Format",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInDataExchange, []byte{0x99, 0x00})
			},
			inputData:      []byte{0x01, 0x02},
			expectError:    true,
			errorSubstring: "unexpected data exchange response",
		},
		{
			name: "Data_Exchange_Status_Error",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInDataExchange, []byte{0x41, 0x01})
			},
			inputData:      []byte{0x01, 0x02},
			expectError:    true,
			errorSubstring: "InDataExchange error 0x01",
		},
		{
			name: "Short_Response",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(testutil.CmdInDataExchange, []byte{0x41})
			},
			inputData:      []byte{0x01, 0x02},
			expectError:    true,
			errorSubstring: "unexpected data exchange response",
		},
	}
}

func getRawCommandTestCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	inputData      []byte
	expectedData   []byte
	expectError    bool
} {
	cases := []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		inputData      []byte
		expectedData   []byte
		expectError    bool
	}{}

	cases = append(cases, getRawCommandSuccessCases()...)
	cases = append(cases, getRawCommandErrorCases()...)

	return cases
}

func getRawCommandSuccessCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	inputData      []byte
	expectedData   []byte
	expectError    bool
} {
	const cmdInCommunicateThru = 0x42

	return []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		inputData      []byte
		expectedData   []byte
		expectError    bool
	}{
		{
			name: "Successful_Raw_Command",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdInCommunicateThru, []byte{0x43, 0x00, 0xDE, 0xAD, 0xBE, 0xEF})
			},
			inputData:    []byte{0x30, 0x00},
			expectedData: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expectError:  false,
		},
		{
			name: "Empty_Raw_Command",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdInCommunicateThru, []byte{0x43, 0x00})
			},
			inputData:    []byte{},
			expectedData: []byte{},
			expectError:  false,
		},
		{
			name: "Complex_Raw_Command",
			setupMock: func(mock *MockTransport) {
				complexResponse := []byte{0x43, 0x00}
				versionData := []byte{0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03}
				complexResponse = append(complexResponse, versionData...)
				mock.SetResponse(cmdInCommunicateThru, complexResponse)
			},
			inputData:    []byte{0x60},
			expectedData: []byte{0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03},
			expectError:  false,
		},
	}
}

func getRawCommandErrorCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	inputData      []byte
	expectedData   []byte
	expectError    bool
} {
	const cmdInCommunicateThru = 0x42

	return []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		inputData      []byte
		expectedData   []byte
		expectError    bool
	}{
		{
			name: "Transport_Command_Error",
			setupMock: func(mock *MockTransport) {
				mock.SetError(cmdInCommunicateThru, errors.New("communicate through failed"))
			},
			inputData:      []byte{0x30, 0x00},
			expectError:    true,
			errorSubstring: "failed to send communicate through command",
		},
		{
			name: "PN532_Error_Frame",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdInCommunicateThru, []byte{0x7F, 0x02})
			},
			inputData:      []byte{0x30, 0x00},
			expectError:    true,
			errorSubstring: "InCommunicateThru error 0x02",
		},
		{
			name: "Invalid_Response_Format",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdInCommunicateThru, []byte{0x99, 0x00})
			},
			inputData:      []byte{0x30, 0x00},
			expectError:    true,
			errorSubstring: "unexpected InCommunicateThru response",
		},
		{
			name: "InCommunicateThru_Status_Error",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdInCommunicateThru, []byte{0x43, 0x01})
			},
			inputData:      []byte{0x30, 0x00},
			expectError:    true,
			errorSubstring: "InCommunicateThru error 0x01",
		},
		{
			name: "Short_Response",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdInCommunicateThru, []byte{0x43})
			},
			inputData:      []byte{0x30, 0x00},
			expectError:    true,
			errorSubstring: "unexpected InCommunicateThru response",
		},
	}
}

func getPowerDownTestCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	description    string
	wakeupEnable   byte
	irqEnable      byte
	expectError    bool
} {
	cases := []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		description    string
		wakeupEnable   byte
		irqEnable      byte
		expectError    bool
	}{}

	cases = append(cases, getPowerDownSuccessCases()...)
	cases = append(cases, getPowerDownErrorCases()...)

	return cases
}

func getPowerDownSuccessCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	description    string
	wakeupEnable   byte
	irqEnable      byte
	expectError    bool
} {
	const cmdPowerDown = 0x16

	return []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		description    string
		wakeupEnable   byte
		irqEnable      byte
		expectError    bool
	}{
		{
			name: "Successful_PowerDown_HSU_Wake",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{0x17})
			},
			wakeupEnable: 0x01,
			irqEnable:    0x01,
			expectError:  false,
			description:  "HSU wake-up enabled with IRQ",
		},
		{
			name: "Successful_PowerDown_RF_Wake",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{0x17})
			},
			wakeupEnable: 0x20,
			irqEnable:    0x00,
			expectError:  false,
			description:  "RF wake-up enabled without IRQ",
		},
		{
			name: "Successful_PowerDown_Multiple_Wake",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{0x17})
			},
			wakeupEnable: 0x27,
			irqEnable:    0x01,
			expectError:  false,
			description:  "Multiple wake-up sources enabled",
		},
		{
			name: "Successful_PowerDown_GPIO_Wake",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{0x17})
			},
			wakeupEnable: 0x98,
			irqEnable:    0x01,
			expectError:  false,
			description:  "GPIO wake-up sources enabled",
		},
		{
			name: "PowerDown_No_Wake_Sources",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{0x17})
			},
			wakeupEnable: 0x00,
			irqEnable:    0x00,
			expectError:  false,
			description:  "No wake-up sources (deep sleep)",
		},
	}
}

func getPowerDownErrorCases() []struct {
	setupMock      func(*MockTransport)
	name           string
	errorSubstring string
	description    string
	wakeupEnable   byte
	irqEnable      byte
	expectError    bool
} {
	const cmdPowerDown = 0x16

	return []struct {
		setupMock      func(*MockTransport)
		name           string
		errorSubstring string
		description    string
		wakeupEnable   byte
		irqEnable      byte
		expectError    bool
	}{
		{
			name: "Transport_Command_Error",
			setupMock: func(mock *MockTransport) {
				mock.SetError(cmdPowerDown, errors.New("power down transport error"))
			},
			wakeupEnable:   0x01,
			irqEnable:      0x01,
			expectError:    true,
			errorSubstring: "PowerDown command failed",
			description:    "Transport layer error",
		},
		{
			name: "Invalid_PowerDown_Response",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{0x99})
			},
			wakeupEnable:   0x01,
			irqEnable:      0x01,
			expectError:    true,
			errorSubstring: "unexpected PowerDown response",
			description:    "Invalid response code",
		},
		{
			name: "Empty_PowerDown_Response",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{})
			},
			wakeupEnable:   0x01,
			irqEnable:      0x01,
			expectError:    true,
			errorSubstring: "unexpected PowerDown response",
			description:    "Empty response",
		},
		{
			name: "Long_PowerDown_Response",
			setupMock: func(mock *MockTransport) {
				mock.SetResponse(cmdPowerDown, []byte{0x17, 0x00, 0x01})
			},
			wakeupEnable:   0x01,
			irqEnable:      0x01,
			expectError:    true,
			errorSubstring: "unexpected PowerDown response",
			description:    "Response too long",
		},
	}
}

func TestDevice_SendDataExchange(t *testing.T) {
	t.Parallel()

	tests := getDataExchangeTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mock := setupDeviceWithMock(t, tt.setupMock)

			// Test data exchange
			result, err := device.SendDataExchange(context.Background(), tt.inputData)

			if tt.expectError {
				checkTestError(t, err, tt.errorSubstring, result)
			} else {
				checkTestSuccess(t, err, result, tt.expectedData)
				assert.Equal(t, 1, mock.GetCallCount(testutil.CmdInDataExchange))
			}
		})
	}
}

func TestDevice_SendRawCommand(t *testing.T) {
	t.Parallel()

	const cmdInCommunicateThru = 0x42
	tests := getRawCommandTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mock := setupDeviceWithMock(t, tt.setupMock)

			// Test raw command
			result, err := device.SendRawCommand(context.Background(), tt.inputData)

			if tt.expectError {
				checkTestError(t, err, tt.errorSubstring, result)
			} else {
				checkTestSuccess(t, err, result, tt.expectedData)
				assert.Equal(t, 1, mock.GetCallCount(cmdInCommunicateThru))
			}
		})
	}
}

func TestDevice_SendDataExchangeWithRetry(t *testing.T) {
	t.Parallel()

	t.Run("Success_FirstAttempt", func(t *testing.T) {
		t.Parallel()

		device, mock := createMockDeviceWithTransport(t)

		// Configure successful response
		mock.SetResponse(testutil.CmdInDataExchange, []byte{0x41, 0x00, 0xDE, 0xAD, 0xBE, 0xEF})

		result, err := device.SendDataExchangeWithRetry(context.Background(), []byte{0x30, 0x04})

		require.NoError(t, err)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, result)
		assert.Equal(t, 1, mock.GetCallCount(testutil.CmdInDataExchange))
	})

	t.Run("Success_AfterTimeoutRetry", func(t *testing.T) {
		t.Parallel()

		device, mock := createMockDeviceWithTransport(t)

		// Queue: first call returns timeout (0x01), second call succeeds
		// Timeout error is encoded as protocol error in response byte 1
		mock.QueueResponses(testutil.CmdInDataExchange,
			[]byte{0x41, 0x01},                         // First call: timeout error
			[]byte{0x41, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}, // Second call: success
		)

		result, err := device.SendDataExchangeWithRetry(context.Background(), []byte{0x30, 0x04})

		require.NoError(t, err)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, result)
		assert.Equal(t, 2, mock.GetCallCount(testutil.CmdInDataExchange), "Should have retried once")
	})

	t.Run("Success_AfterTwoTimeoutRetries", func(t *testing.T) {
		t.Parallel()

		device, mock := createMockDeviceWithTransport(t)

		// Queue: first two calls timeout, third succeeds
		mock.QueueResponses(testutil.CmdInDataExchange,
			[]byte{0x41, 0x01},                         // First call: timeout error
			[]byte{0x41, 0x01},                         // Second call: timeout error
			[]byte{0x41, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}, // Third call: success
		)

		result, err := device.SendDataExchangeWithRetry(context.Background(), []byte{0x30, 0x04})

		require.NoError(t, err)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, result)
		assert.Equal(t, 3, mock.GetCallCount(testutil.CmdInDataExchange), "Should have retried twice")
	})

	t.Run("Failure_AllThreeTimeoutsExhausted", func(t *testing.T) {
		t.Parallel()

		device, mock := createMockDeviceWithTransport(t)

		// Queue: all three calls timeout
		mock.QueueResponses(testutil.CmdInDataExchange,
			[]byte{0x41, 0x01}, // First call: timeout error
			[]byte{0x41, 0x01}, // Second call: timeout error
			[]byte{0x41, 0x01}, // Third call: timeout error
		)

		result, err := device.SendDataExchangeWithRetry(context.Background(), []byte{0x30, 0x04})

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, 3, mock.GetCallCount(testutil.CmdInDataExchange), "Should have tried 3 times")

		// Verify it's a timeout error
		var pn532Err *PN532Error
		require.ErrorAs(t, err, &pn532Err)
		assert.True(t, pn532Err.IsTimeoutError())
	})

	t.Run("NoRetry_NonTimeoutError", func(t *testing.T) {
		t.Parallel()

		device, mock := createMockDeviceWithTransport(t)

		// Configure non-timeout error (0x14 = authentication error)
		mock.SetResponse(testutil.CmdInDataExchange, []byte{0x41, 0x14})

		result, err := device.SendDataExchangeWithRetry(context.Background(), []byte{0x30, 0x04})

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, 1, mock.GetCallCount(testutil.CmdInDataExchange), "Should NOT retry non-timeout errors")
	})
}

func TestDevice_PowerDown(t *testing.T) {
	t.Parallel()

	const cmdPowerDown = 0x16
	tests := getPowerDownTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, mock := setupDeviceWithMock(t, tt.setupMock)

			// Test power down
			err := device.PowerDown(context.Background(), tt.wakeupEnable, tt.irqEnable)

			if tt.expectError {
				checkPowerDownError(t, err, tt.errorSubstring)
			} else {
				checkPowerDownSuccess(t, err, mock, cmdPowerDown)
			}
		})
	}
}
