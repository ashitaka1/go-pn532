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
	"fmt"
	"time"

	"github.com/ZaparooProject/go-pn532/internal/syncutil"
)

// Transport defines the interface for communication with PN532 devices.
// This can be implemented by UART, I2C, or SPI backends.
type Transport interface {
	// SendCommand sends a command to the PN532 and waits for response
	SendCommand(cmd byte, args []byte) ([]byte, error)

	// SendCommandWithContext sends a command to the PN532 with context support
	SendCommandWithContext(ctx context.Context, cmd byte, args []byte) ([]byte, error)

	// Close closes the transport connection
	Close() error

	// SetTimeout sets the read timeout for the transport
	SetTimeout(timeout time.Duration) error

	// IsConnected returns true if the transport is connected
	IsConnected() bool

	// Type returns the transport type
	Type() TransportType
}

// TransportType represents the type of transport
type TransportType string

const (
	// TransportUART represents UART/serial transport.
	TransportUART TransportType = "uart"
	// TransportI2C represents I2C bus transport.
	TransportI2C TransportType = "i2c"
	// TransportSPI represents SPI bus transport.
	TransportSPI TransportType = "spi"
	// TransportMock represents a mock transport for testing
	TransportMock TransportType = "mock"
)

// TransportCapability represents specific capabilities or behaviors of a transport
type TransportCapability string

const (
	// CapabilityRequiresInSelect indicates the transport requires explicit InSelect
	CapabilityRequiresInSelect TransportCapability = "requires_in_select"

	// CapabilityAutoPollNative indicates the transport supports native InAutoPoll
	// with full command set and reliable operation (e.g., UART, I2C, SPI)
	CapabilityAutoPollNative TransportCapability = "autopoll_native"

	// CapabilityUART indicates the transport uses UART communication
	// UART transport is prone to PN532 firmware lockups with large InCommunicateThru payloads
	CapabilityUART TransportCapability = "uart"
)

// TransportCapabilityChecker defines an interface for querying transport capabilities
// This provides a clean, type-safe alternative to reflection-based mode detection
type TransportCapabilityChecker interface {
	// HasCapability returns true if the transport has the specified capability
	HasCapability(capability TransportCapability) bool
}

// PN532PowerMode represents the power mode state of the PN532
type PN532PowerMode int

const (
	// PN532PowerModeNormal is the normal operating mode
	PN532PowerModeNormal PN532PowerMode = iota
	// PN532PowerModeSleep is the sleep mode (low power)
	PN532PowerModeSleep
	// PN532PowerModePowerDown is the power down mode (lowest power)
	PN532PowerModePowerDown
)

// MockTransport provides a mock implementation of Transport for testing
type MockTransport struct {
	responses      map[byte][]byte
	responseQueue  map[byte][][]byte // Queue of responses for sequential calls
	callCount      map[byte]int
	errorMap       map[byte]error
	timeout        time.Duration
	delay          time.Duration
	powerMode      PN532PowerMode
	mu             syncutil.RWMutex
	connected      bool
	rfFieldOn      bool
	targetSelected bool
}

// NewMockTransport creates a new mock transport
func NewMockTransport() *MockTransport {
	return &MockTransport{
		connected:      true,
		timeout:        time.Second,
		responses:      make(map[byte][]byte),
		responseQueue:  make(map[byte][][]byte),
		callCount:      make(map[byte]int),
		delay:          0,
		errorMap:       make(map[byte]error),
		powerMode:      PN532PowerModeNormal,
		rfFieldOn:      false,
		targetSelected: false,
	}
}

// SendCommand implements Transport interface
func (m *MockTransport) SendCommand(cmd byte, data []byte) ([]byte, error) {
	m.mu.RLock()
	connected := m.connected
	delay := m.delay
	m.mu.RUnlock()

	if !connected {
		return nil, errors.New("transport not connected")
	}

	// Validate PN532 state machine
	if err := m.validateState(cmd); err != nil {
		return nil, err
	}

	// Simulate hardware delay if configured
	if delay > 0 {
		time.Sleep(delay)
	}

	m.mu.Lock()
	// Track call count
	m.callCount[cmd]++

	// Check for injected error
	if err, exists := m.errorMap[cmd]; exists {
		m.mu.Unlock()
		return nil, err
	}

	// Update state based on command
	m.updateState(cmd, data)

	// Check queue first (for sequential different responses)
	if queue, exists := m.responseQueue[cmd]; exists && len(queue) > 0 {
		response := queue[0]
		m.responseQueue[cmd] = queue[1:] // Pop from queue
		m.mu.Unlock()
		return response, nil
	}

	// Return configured response (fallback/default)
	if response, exists := m.responses[cmd]; exists {
		m.mu.Unlock()
		return response, nil
	}
	m.mu.Unlock()

	// Default response for unknown commands
	return []byte{0xD5, cmd + 1, 0x00}, nil // Basic ACK response
}

// SendCommandWithContext implements Transport interface with context support
func (m *MockTransport) SendCommandWithContext(ctx context.Context, cmd byte, data []byte) ([]byte, error) {
	// Check context cancellation first
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	connected := m.connected
	delay := m.delay
	m.mu.RUnlock()

	if !connected {
		return nil, errors.New("transport not connected")
	}

	// Validate PN532 state machine
	if err := m.validateState(cmd); err != nil {
		return nil, err
	}

	// Simulate hardware delay if configured with context awareness
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.mu.Lock()
	// Track call count
	m.callCount[cmd]++

	// Check for injected error
	if err, exists := m.errorMap[cmd]; exists {
		m.mu.Unlock()
		return nil, err
	}

	// Update state based on command
	m.updateState(cmd, data)

	// Check queue first (for sequential different responses)
	if queue, exists := m.responseQueue[cmd]; exists && len(queue) > 0 {
		response := queue[0]
		m.responseQueue[cmd] = queue[1:] // Pop from queue
		m.mu.Unlock()
		return response, nil
	}

	// Return configured response (fallback/default)
	if response, exists := m.responses[cmd]; exists {
		m.mu.Unlock()
		return response, nil
	}
	m.mu.Unlock()

	// Default response for unknown commands
	return []byte{0xD5, cmd + 1, 0x00}, nil // Basic ACK response
}

// Close implements Transport interface
func (m *MockTransport) Close() error {
	m.mu.Lock()
	m.connected = false
	m.mu.Unlock()
	return nil
}

// SetTimeout implements Transport interface
func (m *MockTransport) SetTimeout(timeout time.Duration) error {
	m.mu.Lock()
	m.timeout = timeout
	m.mu.Unlock()
	return nil
}

// IsConnected implements Transport interface
func (m *MockTransport) IsConnected() bool {
	m.mu.RLock()
	connected := m.connected
	m.mu.RUnlock()
	return connected
}

// Type implements Transport interface
func (*MockTransport) Type() TransportType {
	return TransportMock
}

// Test helper methods

// SetResponse configures a response for a specific command
func (m *MockTransport) SetResponse(cmd byte, response []byte) {
	m.mu.Lock()
	m.responses[cmd] = response
	m.mu.Unlock()
}

// QueueResponse adds a response to the queue for a specific command.
// Queued responses are returned in FIFO order for sequential calls to the same command.
// Once the queue is empty, SetResponse fallback is used.
func (m *MockTransport) QueueResponse(cmd byte, response []byte) {
	m.mu.Lock()
	m.responseQueue[cmd] = append(m.responseQueue[cmd], response)
	m.mu.Unlock()
}

// QueueResponses adds multiple responses to the queue for a specific command.
func (m *MockTransport) QueueResponses(cmd byte, responses ...[]byte) {
	m.mu.Lock()
	m.responseQueue[cmd] = append(m.responseQueue[cmd], responses...)
	m.mu.Unlock()
}

// SetError configures an error to be returned for a specific command
func (m *MockTransport) SetError(cmd byte, err error) {
	m.mu.Lock()
	m.errorMap[cmd] = err
	m.mu.Unlock()
}

// ClearError removes error injection for a command
func (m *MockTransport) ClearError(cmd byte) {
	m.mu.Lock()
	delete(m.errorMap, cmd)
	m.mu.Unlock()
}

// SetDelay configures a delay to simulate hardware response time
func (m *MockTransport) SetDelay(delay time.Duration) {
	m.mu.Lock()
	m.delay = delay
	m.mu.Unlock()
}

// GetCallCount returns how many times a command was called
func (m *MockTransport) GetCallCount(cmd byte) int {
	m.mu.RLock()
	count := m.callCount[cmd]
	m.mu.RUnlock()
	return count
}

// Reset clears all call counts and resets state
func (m *MockTransport) Reset() {
	m.mu.Lock()
	m.callCount = make(map[byte]int)
	m.connected = true
	m.powerMode = PN532PowerModeNormal
	m.rfFieldOn = false
	m.targetSelected = false
	m.mu.Unlock()
}

// PN532 state machine methods

// validateState checks if the current state allows the command
func (m *MockTransport) validateState(cmd byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check power mode first
	if m.powerMode != PN532PowerModeNormal {
		// Only SAMConfiguration and GetFirmwareVersion can wake up the device
		if cmd != cmdSamConfiguration && cmd != cmdGetFirmwareVersion {
			return fmt.Errorf("PN532 in power down mode, cannot execute command 0x%02X", cmd)
		}
	}

	// Commands that require RF field to be on
	switch cmd {
	case cmdInListPassiveTarget:
		// InListPassiveTarget needs RF field on (it will be turned on by the command itself)
		// No additional validation needed
	case cmdInDataExchange, cmdInCommunicateThru:
		// These require a target to be selected
		if !m.targetSelected {
			return fmt.Errorf("no target selected, cannot execute command 0x%02X (call InListPassiveTarget first)", cmd)
		}
	case cmdInRelease, cmdInSelect:
		// These require a target to be selected
		if !m.targetSelected {
			return fmt.Errorf("no target selected, cannot execute command 0x%02X", cmd)
		}
	}

	return nil
}

// updateState updates the PN532 state based on the command
// Must be called with m.mu held
func (m *MockTransport) updateState(cmd byte, _ []byte) {
	switch cmd {
	case cmdSamConfiguration:
		// SAMConfiguration wakes up the device
		m.powerMode = PN532PowerModeNormal
	case cmdPowerDown:
		// PowerDown puts device to sleep
		m.powerMode = PN532PowerModePowerDown
		m.targetSelected = false // Target lost when powering down
	case cmdRFConfiguration:
		// RF configuration can turn field on/off
		// For simplicity, assume RF is turned on when this command is sent
		m.rfFieldOn = true
	case cmdInListPassiveTarget:
		// When a target is successfully polled, RF field is on and target is selected
		m.rfFieldOn = true
		m.targetSelected = true
	case cmdInRelease:
		// Release deselects the target
		m.targetSelected = false
	}
}

// EnableRFField turns on the RF field for testing
func (m *MockTransport) EnableRFField() {
	m.mu.Lock()
	m.rfFieldOn = true
	m.mu.Unlock()
}

// DisableRFField turns off the RF field for testing (also deselects target)
func (m *MockTransport) DisableRFField() {
	m.mu.Lock()
	m.rfFieldOn = false
	m.targetSelected = false // Target lost when RF field is off
	m.mu.Unlock()
}

// SelectTarget simulates a target being selected (as if InListPassiveTarget succeeded)
func (m *MockTransport) SelectTarget() {
	m.mu.Lock()
	m.rfFieldOn = true
	m.targetSelected = true
	m.mu.Unlock()
}

// DeselectTarget clears the target selection
func (m *MockTransport) DeselectTarget() {
	m.mu.Lock()
	m.targetSelected = false
	m.mu.Unlock()
}

// SetPowerMode sets the power mode for testing
func (m *MockTransport) SetPowerMode(mode PN532PowerMode) {
	m.mu.Lock()
	m.powerMode = mode
	if mode != PN532PowerModeNormal {
		m.targetSelected = false
	}
	m.mu.Unlock()
}

// GetState returns the current PN532 state (for test assertions)
func (m *MockTransport) GetState() (powerMode PN532PowerMode, rfFieldOn, targetSelected bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.powerMode, m.rfFieldOn, m.targetSelected
}
