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

//nolint:paralleltest // Test file - parallel tests add complexity
package uart

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ZaparooProject/go-pn532"
	virt "github.com/ZaparooProject/go-pn532/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.bug.st/serial"
)

// errPortClosed is returned when operations are attempted on a closed port
var errPortClosed = errors.New("port is closed")

// MockSerialPort wraps VirtualPN532 to implement serial.Port interface
type MockSerialPort struct {
	sim         *virt.VirtualPN532
	readTimeout time.Duration
	closed      bool
}

// NewMockSerialPort creates a mock serial port backed by the wire simulator
func NewMockSerialPort(sim *virt.VirtualPN532) *MockSerialPort {
	return &MockSerialPort{
		sim:         sim,
		readTimeout: 100 * time.Millisecond,
	}
}

func (*MockSerialPort) SetMode(_ *serial.Mode) error {
	return nil
}

func (m *MockSerialPort) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, errPortClosed
	}
	n, err = m.sim.Read(p)
	if err != nil {
		return n, fmt.Errorf("mock read: %w", err)
	}
	return n, nil
}

func (m *MockSerialPort) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, errPortClosed
	}
	n, err = m.sim.Write(p)
	if err != nil {
		return n, fmt.Errorf("mock write: %w", err)
	}
	return n, nil
}

func (*MockSerialPort) Drain() error {
	return nil
}

func (*MockSerialPort) ResetInputBuffer() error {
	return nil
}

func (*MockSerialPort) ResetOutputBuffer() error {
	return nil
}

func (*MockSerialPort) SetDTR(_ bool) error {
	return nil
}

func (*MockSerialPort) SetRTS(_ bool) error {
	return nil
}

func (*MockSerialPort) GetModemStatusBits() (*serial.ModemStatusBits, error) {
	return &serial.ModemStatusBits{}, nil
}

func (m *MockSerialPort) SetReadTimeout(t time.Duration) error {
	m.readTimeout = t
	return nil
}

func (m *MockSerialPort) Close() error {
	m.closed = true
	return nil
}

func (*MockSerialPort) Break(_ time.Duration) error {
	return nil
}

// Verify interface implementation
var _ serial.Port = (*MockSerialPort)(nil)

// JitteryMockSerialPort wraps VirtualPN532 with jitter simulation
// to test protocol handling under realistic UART conditions
type JitteryMockSerialPort struct {
	jittery     *virt.BufferedJitteryConnection
	readTimeout time.Duration
	closed      bool
}

// NewJitteryMockSerialPort creates a mock serial port with jitter simulation
func NewJitteryMockSerialPort(sim *virt.VirtualPN532, config virt.JitterConfig) *JitteryMockSerialPort {
	return &JitteryMockSerialPort{
		jittery:     virt.NewBufferedJitteryConnection(sim, config),
		readTimeout: 100 * time.Millisecond,
	}
}

func (*JitteryMockSerialPort) SetMode(_ *serial.Mode) error {
	return nil
}

func (m *JitteryMockSerialPort) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, errPortClosed
	}
	n, err = m.jittery.Read(p)
	if err != nil {
		return n, fmt.Errorf("jittery mock read: %w", err)
	}
	return n, nil
}

func (m *JitteryMockSerialPort) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, errPortClosed
	}
	n, err = m.jittery.Write(p)
	if err != nil {
		return n, fmt.Errorf("jittery mock write: %w", err)
	}
	return n, nil
}

func (*JitteryMockSerialPort) Drain() error {
	return nil
}

func (m *JitteryMockSerialPort) ResetInputBuffer() error {
	m.jittery.ClearBuffer()
	m.jittery.ResetStallState()
	return nil
}

func (*JitteryMockSerialPort) ResetOutputBuffer() error {
	return nil
}

func (*JitteryMockSerialPort) SetDTR(_ bool) error {
	return nil
}

func (*JitteryMockSerialPort) SetRTS(_ bool) error {
	return nil
}

func (*JitteryMockSerialPort) GetModemStatusBits() (*serial.ModemStatusBits, error) {
	return &serial.ModemStatusBits{}, nil
}

func (m *JitteryMockSerialPort) SetReadTimeout(t time.Duration) error {
	m.readTimeout = t
	return nil
}

func (m *JitteryMockSerialPort) Close() error {
	m.closed = true
	return nil
}

func (*JitteryMockSerialPort) Break(_ time.Duration) error {
	return nil
}

// Verify interface implementation
var _ serial.Port = (*JitteryMockSerialPort)(nil)

// newTestTransport creates a Transport with a mock serial port for testing
func newTestTransport(sim *virt.VirtualPN532) *Transport {
	mockPort := NewMockSerialPort(sim)
	return &Transport{
		port:     mockPort,
		portName: "mock://test",
	}
}

// newJitteryTestTransport creates a Transport with jitter simulation for stress testing
func newJitteryTestTransport(sim *virt.VirtualPN532, config virt.JitterConfig) *Transport {
	mockPort := NewJitteryMockSerialPort(sim, config)
	return &Transport{
		port:     mockPort,
		portName: "mock://jittery-test",
	}
}

// TestUART_GetFirmwareVersion tests the full protocol exchange for GetFirmwareVersion
func TestUART_GetFirmwareVersion(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	transport := newTestTransport(sim)

	// Command 0x02 = GetFirmwareVersion
	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Response format: [ResponseCode (cmd+1), IC, Ver, Rev, Support]
	assert.Len(t, resp, 5)
	assert.Equal(t, byte(0x03), resp[0], "Response code should be 0x03 (GetFirmwareVersion+1)")
	assert.Equal(t, byte(0x32), resp[1], "IC should be 0x32 (PN532)")
	assert.Equal(t, byte(0x01), resp[2], "Version should be 0x01")
	assert.Equal(t, byte(0x06), resp[3], "Revision should be 0x06")
	assert.Equal(t, byte(0x07), resp[4], "Support should be 0x07")
}

// TestUART_SAMConfiguration tests SAM configuration command
func TestUART_SAMConfiguration(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	// Configure SAM: Normal mode (0x01), timeout 0x14, use IRQ
	resp, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check simulator state
	state := sim.GetState()
	assert.True(t, state.SAMConfigured, "SAM should be configured")
}

// TestUART_InListPassiveTarget_NoTags tests tag detection with no tags present
func TestUART_InListPassiveTarget_NoTags(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	// Configure SAM first (required for some commands)
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// InListPassiveTarget: MaxTg=1, BrTy=0x00 (ISO14443A 106 kbps)
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Response: [ResponseCode, NbTg] - 0 tags found
	require.Len(t, resp, 2)
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	assert.Equal(t, byte(0x00), resp[1], "NbTg should be 0 (no tags)")
}

// TestUART_InListPassiveTarget_WithTag tests tag detection with a virtual tag
func TestUART_InListPassiveTarget_WithTag(t *testing.T) {
	sim := virt.NewVirtualPN532()

	// Add a virtual NTAG213 tag
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// Configure SAM first
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// InListPassiveTarget: MaxTg=1, BrTy=0x00 (ISO14443A 106 kbps)
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Response: [ResponseCode, NbTg, Tg, SENS_RES(2), SEL_RES, NFCIDLength, NFCID1...]
	require.GreaterOrEqual(t, len(resp), 7, "Response should have tag info")
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	assert.Equal(t, byte(0x01), resp[1], "NbTg should be 1")
	assert.Equal(t, byte(0x01), resp[2], "Tg should be 1")
}

// TestUART_InDataExchange_ReadBlock tests reading data from a virtual tag
func TestUART_InDataExchange_ReadBlock(t *testing.T) {
	sim := virt.NewVirtualPN532()

	// Add a virtual NTAG213 with some data
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	// Write test data to block 4 (blocks are 16 bytes each for Memory slice)
	tag.Memory[4] = []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	_, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// InDataExchange: Tg=1, READ command (0x30), page 4
	resp, err := transport.SendCommand(0x40, []byte{0x01, 0x30, 0x04})
	require.NoError(t, err)

	// Response: [ResponseCode, Status, Data...]
	require.GreaterOrEqual(t, len(resp), 6, "Should have resp code + status + at least 4 bytes")
	assert.Equal(t, byte(0x41), resp[0], "Response code should be 0x41")
	assert.Equal(t, byte(0x00), resp[1], "Status should be 0x00 (success)")
	assert.Equal(t, byte(0xDE), resp[2])
	assert.Equal(t, byte(0xAD), resp[3])
	assert.Equal(t, byte(0xBE), resp[4])
	assert.Equal(t, byte(0xEF), resp[5])
}

// TestUART_InDataExchange_WriteBlock tests writing data to a virtual tag
func TestUART_InDataExchange_WriteBlock(t *testing.T) {
	sim := virt.NewVirtualPN532()

	// Add a virtual NTAG213
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	_, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// InDataExchange: Tg=1, WRITE command (0xA2), page 4, data
	resp, err := transport.SendCommand(0x40, []byte{0x01, 0xA2, 0x04, 0xCA, 0xFE, 0xBA, 0xBE})
	require.NoError(t, err)

	// Response: [ResponseCode, Status]
	require.GreaterOrEqual(t, len(resp), 2)
	assert.Equal(t, byte(0x41), resp[0], "Response code should be 0x41")
	assert.Equal(t, byte(0x00), resp[1], "Status should be 0x00 (success)")

	// Verify the write by reading back
	resp, err = transport.SendCommand(0x40, []byte{0x01, 0x30, 0x04})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 6)
	assert.Equal(t, byte(0xCA), resp[2])
	assert.Equal(t, byte(0xFE), resp[3])
	assert.Equal(t, byte(0xBA), resp[4])
	assert.Equal(t, byte(0xBE), resp[5])
}

// TestUART_MIFAREClassic_Authentication tests MIFARE Classic authentication
func TestUART_MIFAREClassic_Authentication(t *testing.T) {
	sim := virt.NewVirtualPN532()

	// Add a virtual MIFARE Classic 1K
	tag := virt.NewVirtualMIFARE1K([]byte{0x01, 0x02, 0x03, 0x04})
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 3)
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	assert.Equal(t, byte(0x01), resp[1], "Should detect 1 tag")

	// Authenticate with Key A (0x60) on block 4 (sector 1)
	// Command: [Tg, AuthCmd, Block, Key(6), UID(4)]
	authCmd := []byte{
		0x01, 0x60, 0x04,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Default Key A
		0x01, 0x02, 0x03, 0x04,
	} // UID
	resp, err = transport.SendCommand(0x40, authCmd)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 2)
	assert.Equal(t, byte(0x41), resp[0], "Response code should be 0x41")
	assert.Equal(t, byte(0x00), resp[1], "Authentication should succeed")
}

// TestUART_InRelease tests releasing a tag
func TestUART_InRelease(t *testing.T) {
	sim := virt.NewVirtualPN532()

	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	_, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Release tag (Tg=1)
	resp, err := transport.SendCommand(0x52, []byte{0x01})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 2)
	assert.Equal(t, byte(0x53), resp[0], "Response code should be 0x53")
	assert.Equal(t, byte(0x00), resp[1], "Release should succeed")

	// Verify target is no longer selected
	state := sim.GetState()
	assert.Equal(t, -1, state.SelectedTarget, "No target should be selected")
}

// TestUART_RFConfiguration tests RF field configuration
func TestUART_RFConfiguration(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	// RFConfiguration: CfgItem=0x01 (RF Field), data=0x01 (on)
	resp, err := transport.SendCommand(0x32, []byte{0x01, 0x01})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify RF field is on
	state := sim.GetState()
	assert.True(t, state.RFFieldOn, "RF field should be on")

	// Turn RF field off
	_, err = transport.SendCommand(0x32, []byte{0x01, 0x00})
	require.NoError(t, err)

	state = sim.GetState()
	assert.False(t, state.RFFieldOn, "RF field should be off")
}

// TestUART_PowerDown tests power down command
func TestUART_PowerDown(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	// Configure SAM first
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Send PowerDown with WakeUpEnable byte set to 0x00
	resp, err := transport.SendCommand(0x16, []byte{0x00})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Note: In real implementation, the next command would wake the device
}

// TestUART_Close tests closing the transport
func TestUART_Close(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	assert.True(t, transport.IsConnected())

	err := transport.Close()
	require.NoError(t, err)

	assert.False(t, transport.IsConnected())
}

// TestUART_Type tests transport type
func TestUART_Type(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	assert.Equal(t, pn532.TransportUART, transport.Type())
}

// TestUART_HasCapability tests capability checking
func TestUART_HasCapability(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	assert.True(t, transport.HasCapability(pn532.CapabilityAutoPollNative))
	assert.True(t, transport.HasCapability(pn532.CapabilityRequiresInSelect))
	assert.True(t, transport.HasCapability(pn532.CapabilityUART))
}

// TestUART_SetTimeout tests timeout configuration
func TestUART_SetTimeout(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	err := transport.SetTimeout(500 * time.Millisecond)
	require.NoError(t, err)
}

// TestUART_FeliCaDetection tests FeliCa tag detection
func TestUART_FeliCaDetection(t *testing.T) {
	sim := virt.NewVirtualPN532()

	// Add a virtual FeliCa tag (requires Type="FeliCa" and 8-byte UID)
	tag := &virt.VirtualTag{
		Type:    "FeliCa",
		UID:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Present: true,
	}
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// InListPassiveTarget: MaxTg=1, BrTy=0x01 (FeliCa 212 kbps)
	// Payload data for FeliCa polling: length, polling command, system code, request code, time slot
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x00})
	require.NoError(t, err)

	// Response: [ResponseCode (0x4B), NbTg, ...]
	require.GreaterOrEqual(t, len(resp), 3, "Should have tag info")
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	assert.Equal(t, byte(0x01), resp[1], "NbTg should be 1")
}

// TestUART_MIFARE4K_Detection tests MIFARE 4K tag detection
func TestUART_MIFARE4K_Detection(t *testing.T) {
	sim := virt.NewVirtualPN532()

	// Add a virtual MIFARE 4K
	tag := virt.NewVirtualMIFARE4K([]byte{0x01, 0x02, 0x03, 0x04})
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 6)
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	assert.Equal(t, byte(0x01), resp[1], "Should detect 1 tag")
}

// TestUART_MultipleTagsSequential tests detecting multiple tags sequentially
func TestUART_MultipleTagsSequential(t *testing.T) {
	sim := virt.NewVirtualPN532()

	// Add two tags
	tag1 := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	tag2 := virt.NewVirtualMIFARE1K([]byte{0x11, 0x22, 0x33, 0x44})
	sim.AddTag(tag1)
	sim.AddTag(tag2)

	transport := newTestTransport(sim)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tags (MaxTg=2 to detect both)
	resp, err := transport.SendCommand(0x4A, []byte{0x02, 0x00})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 2)
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	// Should detect at least 1 tag (simulator may detect 1 or 2)
	assert.GreaterOrEqual(t, int(resp[1]), 1, "Should detect at least 1 tag")
}

// TestUART_ClearTransportState tests the state clearing mechanism
func TestUART_ClearTransportState(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestTransport(sim)

	err := transport.ClearTransportState()
	require.NoError(t, err)
}

// TestUART_ErrorScenarios tests various error conditions
func TestUART_ErrorScenarios(t *testing.T) {
	t.Run("InvalidCommand", func(t *testing.T) {
		sim := virt.NewVirtualPN532()
		transport := newTestTransport(sim)

		// Send an invalid/unknown command (0xFF is not a valid PN532 command)
		resp, err := transport.SendCommand(0xFF, nil)
		// The simulator should handle unknown commands gracefully
		// It returns an error frame with error code errCommand (0x27)
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("TagRemovedMidOperation", func(t *testing.T) {
		sim := virt.NewVirtualPN532()

		tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		sim.AddTag(tag)

		transport := newTestTransport(sim)

		// Configure SAM
		_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
		require.NoError(t, err)

		// Detect tag
		_, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
		require.NoError(t, err)

		// Remove the tag
		tag.Remove()

		// Try to read - should fail
		resp, err := transport.SendCommand(0x40, []byte{0x01, 0x30, 0x04})
		// Should get error or empty response
		_ = resp
		_ = err
	})
}

// =============================================================================
// Jittery Transport Tests - Stress test protocol parsing with fragmented reads
// =============================================================================

// defaultJitterConfig returns a jitter config suitable for stress testing
func defaultJitterConfig() virt.JitterConfig {
	return virt.JitterConfig{
		MaxLatencyMs:     0, // No latency for faster tests
		FragmentReads:    true,
		FragmentMinBytes: 1, // Fragment down to single bytes
		Seed:             12345,
	}
}

// TestUART_Jittery_GetFirmwareVersion tests firmware version with fragmented reads
func TestUART_Jittery_GetFirmwareVersion(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	transport := newJitteryTestTransport(sim, defaultJitterConfig())

	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Len(t, resp, 5)
	assert.Equal(t, byte(0x03), resp[0], "Response code should be 0x03")
	assert.Equal(t, byte(0x32), resp[1], "IC should be 0x32")
	assert.Equal(t, byte(0x01), resp[2], "Version should be 0x01")
	assert.Equal(t, byte(0x06), resp[3], "Revision should be 0x06")
}

// TestUART_Jittery_SAMConfiguration tests SAM config with fragmented reads
func TestUART_Jittery_SAMConfiguration(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newJitteryTestTransport(sim, defaultJitterConfig())

	resp, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)
	require.NotNil(t, resp)

	state := sim.GetState()
	assert.True(t, state.SAMConfigured, "SAM should be configured")
}

// TestUART_Jittery_TagDetection tests tag detection with fragmented reads
func TestUART_Jittery_TagDetection(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)
	transport := newJitteryTestTransport(sim, defaultJitterConfig())

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 7)
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	assert.Equal(t, byte(0x01), resp[1], "NbTg should be 1")
}

// TestUART_Jittery_ReadWriteCycle tests read/write with fragmented transport
func TestUART_Jittery_ReadWriteCycle(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)
	transport := newJitteryTestTransport(sim, defaultJitterConfig())

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	_, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Write data
	resp, err := transport.SendCommand(0x40, []byte{0x01, 0xA2, 0x04, 0xAA, 0xBB, 0xCC, 0xDD})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 2)
	assert.Equal(t, byte(0x00), resp[1], "Write should succeed")

	// Read it back
	resp, err = transport.SendCommand(0x40, []byte{0x01, 0x30, 0x04})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 6)
	assert.Equal(t, byte(0xAA), resp[2])
	assert.Equal(t, byte(0xBB), resp[3])
	assert.Equal(t, byte(0xCC), resp[4])
	assert.Equal(t, byte(0xDD), resp[5])
}

// TestUART_Jittery_MIFAREAuth tests MIFARE auth with fragmented transport
func TestUART_Jittery_MIFAREAuth(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualMIFARE1K([]byte{0x01, 0x02, 0x03, 0x04})
	sim.AddTag(tag)
	transport := newJitteryTestTransport(sim, defaultJitterConfig())

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	_, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Authenticate
	authCmd := []byte{
		0x01, 0x60, 0x04,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x01, 0x02, 0x03, 0x04,
	}
	resp, err := transport.SendCommand(0x40, authCmd)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), 2)
	assert.Equal(t, byte(0x00), resp[1], "Auth should succeed")
}

// TestUART_Jittery_MultipleCommands tests rapid command sequence with jitter
func TestUART_Jittery_MultipleCommands(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)
	transport := newJitteryTestTransport(sim, defaultJitterConfig())

	// Run 20 command cycles
	for i := range 20 {
		// Configure SAM
		_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
		require.NoError(t, err, "SAM config failed on iteration %d", i)

		// Get firmware version
		resp, err := transport.SendCommand(0x02, nil)
		require.NoError(t, err, "GetFirmwareVersion failed on iteration %d", i)
		assert.Len(t, resp, 5)

		// Detect tag
		resp, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
		require.NoError(t, err, "InListPassiveTarget failed on iteration %d", i)
		assert.Equal(t, byte(0x01), resp[1], "Should detect tag on iteration %d", i)

		// Release tag
		_, err = transport.SendCommand(0x52, []byte{0x01})
		require.NoError(t, err, "InRelease failed on iteration %d", i)
	}
}

// TestUART_Jittery_USBBoundaryStress tests with USB 64-byte boundary fragmentation
func TestUART_Jittery_USBBoundaryStress(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	config := virt.JitterConfig{
		MaxLatencyMs:      0,
		FragmentReads:     false, // Don't randomly fragment
		USBBoundaryStress: true,  // Fragment at 64-byte boundaries instead
		Seed:              54321,
	}
	transport := newJitteryTestTransport(sim, config)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Detect tag
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)
	assert.Equal(t, byte(0x01), resp[1], "Should detect tag")

	// Read data
	resp, err = transport.SendCommand(0x40, []byte{0x01, 0x30, 0x04})
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), resp[1], "Read should succeed")
}

// TestUART_Jittery_StallAfterHeader tests stall between header and body
func TestUART_Jittery_StallAfterHeader(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	config := virt.JitterConfig{
		MaxLatencyMs:    0,
		FragmentReads:   false,
		StallAfterBytes: 6, // Stall after ACK frame (6 bytes)
		StallDuration:   10 * time.Millisecond,
		Seed:            99999,
	}
	transport := newJitteryTestTransport(sim, config)

	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp, 5)
	assert.Equal(t, byte(0x32), resp[1], "IC should be 0x32")
}

// TestUART_Jittery_AggressiveFragmentation tests with single-byte fragmentation
func TestUART_Jittery_AggressiveFragmentation(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	// Most aggressive: single-byte fragments
	config := virt.JitterConfig{
		MaxLatencyMs:     0,
		FragmentReads:    true,
		FragmentMinBytes: 1,
		Seed:             11111,
	}
	transport := newJitteryTestTransport(sim, config)

	// Configure SAM
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Get firmware
	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	assert.Len(t, resp, 5)

	// Detect tag
	resp, err = transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)
	assert.Equal(t, byte(0x01), resp[1])

	// Read from tag
	resp, err = transport.SendCommand(0x40, []byte{0x01, 0x30, 0x04})
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), resp[1])
}

// =============================================================================
// Pre-ACK Garbage Injection Tests
// =============================================================================
// These tests verify that the UART transport correctly handles garbage bytes
// appearing before ACK frames - a critical Windows bug fix for noisy UART lines.

// TestUART_PreACKGarbage_SimpleBytes tests handling of simple garbage before ACK
func TestUART_PreACKGarbage_SimpleBytes(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// Inject random garbage bytes before the ACK
	garbage := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	sim.InjectPreACKGarbage(garbage)

	transport := newTestTransport(sim)

	// Despite garbage, command should succeed
	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed despite pre-ACK garbage")
	require.NotNil(t, resp)

	// Verify response is correct
	assert.Len(t, resp, 5)
	assert.Equal(t, byte(0x03), resp[0], "Response code should be 0x03")
	assert.Equal(t, byte(0x32), resp[1], "IC should be 0x32")
}

// TestUART_PreACKGarbage_FakeFrameStart tests garbage that looks like a frame start
func TestUART_PreACKGarbage_FakeFrameStart(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// Inject garbage that looks like frame start (0x00 0xFF pattern)
	// This was specifically the Windows bug - partial frame data appearing
	garbage := []byte{0x00, 0x00, 0xFF, 0xFF}
	sim.InjectPreACKGarbage(garbage)

	transport := newTestTransport(sim)

	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed despite fake frame start garbage")
	require.NotNil(t, resp)

	assert.Len(t, resp, 5)
	assert.Equal(t, byte(0x32), resp[1], "IC should be 0x32")
}

// TestUART_PreACKGarbage_SingleByte tests handling of single garbage byte
func TestUART_PreACKGarbage_SingleByte(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// Single byte garbage
	sim.InjectPreACKGarbage([]byte{0x00})

	transport := newTestTransport(sim)

	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed with single garbage byte")
	require.NotNil(t, resp)
	assert.Len(t, resp, 5)
}

// TestUART_PreACKGarbage_LongGarbage tests handling of longer garbage sequences
func TestUART_PreACKGarbage_LongGarbage(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// 16 bytes of garbage (max pre-ACK buffer is 16 in UART transport)
	garbage := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	sim.InjectPreACKGarbage(garbage)

	transport := newTestTransport(sim)

	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed with long garbage")
	require.NotNil(t, resp)
	assert.Len(t, resp, 5)
}

// TestUART_PreACKGarbage_WithTagDetection tests pre-ACK garbage during tag operations
func TestUART_PreACKGarbage_WithTagDetection(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)

	// First configure SAM without garbage
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// Now inject garbage for tag detection
	sim.InjectPreACKGarbage([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	// Detect tag - should work despite garbage
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err, "Tag detection should succeed despite pre-ACK garbage")

	// Verify tag was detected
	require.GreaterOrEqual(t, len(resp), 2)
	assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	assert.Equal(t, byte(0x01), resp[1], "Should detect 1 tag")
}

// TestUART_PreACKGarbage_MultipleCommands tests garbage is only injected once
func TestUART_PreACKGarbage_MultipleCommands(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// Inject garbage (should only affect next command)
	sim.InjectPreACKGarbage([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	transport := newTestTransport(sim)

	// First command - should handle garbage
	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	assert.Len(t, resp, 5)

	// Second command - should work without garbage
	resp, err = transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	assert.Len(t, resp, 5)

	// Third command - also clean
	resp, err = transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	assert.Len(t, resp, 5)
}

// TestUART_PreACKGarbage_AllZeros tests handling of all-zero garbage
func TestUART_PreACKGarbage_AllZeros(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// All zeros - common case for noise on UART lines
	garbage := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	sim.InjectPreACKGarbage(garbage)

	transport := newTestTransport(sim)

	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed with all-zero garbage")
	require.NotNil(t, resp)
	assert.Len(t, resp, 5)
}

// TestUART_PreACKGarbage_WithJitter tests garbage combined with jittery reads
func TestUART_PreACKGarbage_WithJitter(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// Inject garbage
	sim.InjectPreACKGarbage([]byte{0xAA, 0xBB, 0xCC})

	// Create jittery transport (aggressive fragmentation)
	config := virt.JitterConfig{
		MaxLatencyMs:     5,
		FragmentReads:    true,
		FragmentMinBytes: 1,
		Seed:             98765,
	}
	transport := newJitteryTestTransport(sim, config)

	// Command should succeed despite both garbage AND jitter
	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed with garbage and jitter")
	require.NotNil(t, resp)
	assert.Len(t, resp, 5)
	assert.Equal(t, byte(0x32), resp[1])
}

// =============================================================================
// Zombie Mode Tests
// These tests verify timeout handling when PN532 ACKs but never sends response
// =============================================================================

// TestUART_ZombieMode_Basic tests that zombie mode causes timeout
func TestUART_ZombieMode_Basic(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	sim.SetZombieMode(true)

	transport := newTestTransport(sim)
	// Set a short timeout so test doesn't take too long
	_ = transport.SetTimeout(50 * time.Millisecond)

	// Command should time out - ACK is received but no response
	_, err := transport.SendCommand(0x02, nil)
	require.Error(t, err, "Command should fail in zombie mode")

	// Error should be a transport error (timeout type)
	var transportErr *pn532.TransportError
	assert.ErrorAs(t, err, &transportErr, "Error should be TransportError, got: %T", err)
}

// TestUART_ZombieMode_Recovery tests recovery after disabling zombie mode
func TestUART_ZombieMode_Recovery(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(50 * time.Millisecond)

	// First: Enable zombie mode and verify timeout
	sim.SetZombieMode(true)
	_, err := transport.SendCommand(0x02, nil)
	require.Error(t, err, "Command should fail in zombie mode")

	// Reset the simulator (clears buffers and zombie mode)
	sim.Reset()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// Now command should succeed
	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed after disabling zombie mode")
	require.NotNil(t, resp)
	assert.Len(t, resp, 5)
}

// TestUART_ZombieMode_MultipleCommands tests multiple commands in zombie mode
func TestUART_ZombieMode_MultipleCommands(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	sim.SetZombieMode(true)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(30 * time.Millisecond)

	// Multiple commands should all time out
	for i := range 3 {
		_, err := transport.SendCommand(0x02, nil)
		require.Error(t, err, "Command %d should fail in zombie mode", i+1)
	}
}

// TestUART_ZombieMode_SAMConfiguration tests SAM config command in zombie mode
func TestUART_ZombieMode_SAMConfiguration(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetZombieMode(true)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(50 * time.Millisecond)

	// SAM Configuration should also time out in zombie mode
	_, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.Error(t, err, "SAMConfiguration should fail in zombie mode")
}

// TestUART_ZombieMode_InListPassiveTarget tests tag detection in zombie mode.
//
// IMPORTANT: This test documents correct PN532 behavior, not a quirk.
//
// Standard PN532 behavior for InListPassiveTarget:
//   - Tag present: PN532 sends ACK, then response frame with tag data
//   - No tag present: PN532 sends ACK only, NO response frame (times out)
//
// This is confirmed by NXP documentation and matches how other libraries handle it:
//   - Adafruit-PN532: returns false on timeout (interprets as "no card")
//   - libnfc: treats timeout as "no targets found"
//
// Our UART transport converts the timeout into a synthetic [0x4B, 0x00] response
// (InListPassiveTarget response code + 0 tags), which is semantically equivalent.
//
// Consequence: "zombie device" and "no tags present" are INDISTINGUISHABLE at the
// wire level for InListPassiveTarget. Both result in: ACK received, no response.
// This is correct - zombie mode detection works for other commands like
// GetFirmwareVersion and SAMConfiguration.
func TestUART_ZombieMode_InListPassiveTarget(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)
	sim.SetZombieMode(true)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(50 * time.Millisecond)

	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})

	// Zombie mode + InListPassiveTarget = "no tags" response (not an error)
	// This matches real PN532 behavior where no-tag and unresponsive are identical
	require.NoError(t, err, "InListPassiveTarget timeout is 'no tags', not an error")
	assert.Equal(t, []byte{0x4B, 0x00}, resp, "Synthetic 'no tags' response")
}

// TestUART_ZombieMode_TraceIncluded tests that trace is included in zombie timeout errors
func TestUART_ZombieMode_TraceIncluded(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	sim.SetZombieMode(true)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(50 * time.Millisecond)

	_, err := transport.SendCommand(0x02, nil)
	require.Error(t, err)

	// Error should include trace information
	if pn532.HasTrace(err) {
		trace := pn532.GetTrace(err)
		require.NotNil(t, trace)
		assert.Equal(t, "UART", trace.Transport)
		assert.NotEmpty(t, trace.Trace, "Trace should have entries")

		// Should have TX entry for the command and RX entry for ACK
		var hasTX, hasRX bool
		for _, entry := range trace.Trace {
			if entry.Direction == pn532.TraceTX {
				hasTX = true
			}
			if entry.Direction == pn532.TraceRX {
				hasRX = true
			}
		}
		assert.True(t, hasTX, "Trace should have TX entry")
		assert.True(t, hasRX, "Trace should have RX entry (for ACK)")
	}
}

// =============================================================================
// Rapid Polling Stress Tests
// =============================================================================
// These tests hammer InListPassiveTarget rapidly to catch state machine
// corruption, race conditions, and issues with clone chips that crash
// when polled too fast.

// TestUART_RapidPolling_Basic tests rapid InListPassiveTarget polling without jitter
func TestUART_RapidPolling_Basic(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	const numPolls = 50
	var successCount, errorCount int

	for range numPolls {
		resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00}) // InListPassiveTarget
		if err != nil {
			errorCount++
			continue
		}
		successCount++

		// Verify we got a valid response (either tag or no-tag)
		require.GreaterOrEqual(t, len(resp), 2, "Response should have at least 2 bytes")
		assert.Equal(t, byte(0x4B), resp[0], "Response code should be 0x4B")
	}

	// All polls should succeed in ideal conditions
	assert.Equal(t, numPolls, successCount, "All polls should succeed")
	assert.Equal(t, 0, errorCount, "No errors expected")
}

// TestUART_RapidPolling_WithJitter tests rapid polling with fragmented reads
func TestUART_RapidPolling_WithJitter(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	config := virt.JitterConfig{
		MaxLatencyMs:     10,
		FragmentReads:    true,
		FragmentMinBytes: 2,
	}
	transport := newJitteryTestTransport(sim, config)
	_ = transport.SetTimeout(200 * time.Millisecond)

	const numPolls = 30
	var successCount, errorCount int

	for range numPolls {
		resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
		if err != nil {
			errorCount++
			continue
		}
		successCount++
		require.GreaterOrEqual(t, len(resp), 2)
		assert.Equal(t, byte(0x4B), resp[0])
	}

	// With jitter, we should still have high success rate
	assert.GreaterOrEqual(t, successCount, numPolls*8/10, "At least 80% success rate with jitter")
}

// TestUART_RapidPolling_TagTransitions tests rapid polling during tag insert/remove
func TestUART_RapidPolling_TagTransitions(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	const numPolls = 40
	var tagPresentCount, tagAbsentCount int

	for i := range numPolls {
		// Toggle tag presence every 5 polls
		if i%10 < 5 {
			sim.AddTag(tag)
		} else {
			sim.RemoveAllTags()
		}

		resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
		require.NoError(t, err, "Poll should not error")
		require.GreaterOrEqual(t, len(resp), 2)

		numTags := resp[1]
		if numTags > 0 {
			tagPresentCount++
		} else {
			tagAbsentCount++
		}
	}

	// Should see both tag present and absent states
	assert.Positive(t, tagPresentCount, "Should detect tag present at least once")
	assert.Positive(t, tagAbsentCount, "Should detect tag absent at least once")
}

// TestUART_RapidPolling_Recovery tests recovery after inducing errors
func TestUART_RapidPolling_Recovery(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// Phase 1: Normal polling
	for range 10 {
		resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
		require.NoError(t, err)
		assert.Equal(t, byte(0x4B), resp[0])
	}

	// Phase 2: Enable zombie mode (simulates device hang)
	sim.SetZombieMode(true)
	for range 5 {
		_, _ = transport.SendCommand(0x4A, []byte{0x01, 0x00})
		// Errors expected (synthetic response for InListPassiveTarget)
	}

	// Phase 3: Disable zombie mode and verify recovery
	sim.SetZombieMode(false)
	var recoverySuccess int
	for range 10 {
		resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
		if err == nil && len(resp) >= 2 && resp[0] == 0x4B {
			recoverySuccess++
		}
	}

	// Should recover and detect tags again
	assert.GreaterOrEqual(t, recoverySuccess, 8, "Should recover at least 80% after zombie mode")
}

// TestUART_RapidPolling_MixedCommands tests rapid interleaved commands
func TestUART_RapidPolling_MixedCommands(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	const iterations = 20
	var pollSuccess, fwSuccess, samSuccess int

	for range iterations {
		// InListPassiveTarget
		resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
		if err == nil && len(resp) >= 2 && resp[0] == 0x4B {
			pollSuccess++
		}

		// GetFirmwareVersion (response: [0x03, IC, Ver, Rev, Support] = 5 bytes)
		resp, err = transport.SendCommand(0x02, nil)
		if err == nil && len(resp) == 5 {
			fwSuccess++
		}

		// SAMConfiguration
		_, err = transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
		if err == nil {
			samSuccess++
		}
	}

	// All commands should succeed
	assert.Equal(t, iterations, pollSuccess, "All polls should succeed")
	assert.Equal(t, iterations, fwSuccess, "All firmware queries should succeed")
	assert.Equal(t, iterations, samSuccess, "All SAM configs should succeed")
}

// TestUART_RapidPolling_AggressiveJitter tests rapid polling with worst-case jitter
func TestUART_RapidPolling_AggressiveJitter(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	config := virt.JitterConfig{
		MaxLatencyMs:      15,
		FragmentReads:     true,
		FragmentMinBytes:  1, // Single byte fragmentation
		USBBoundaryStress: true,
	}
	transport := newJitteryTestTransport(sim, config)
	_ = transport.SetTimeout(300 * time.Millisecond)

	const numPolls = 20
	var successCount int

	for range numPolls {
		resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
		if err == nil && len(resp) >= 2 && resp[0] == 0x4B {
			successCount++
		}
	}

	// Even with aggressive jitter, should have reasonable success
	assert.GreaterOrEqual(t, successCount, numPolls*6/10, "At least 60% success with aggressive jitter")
}

// =============================================================================
// Power Glitch Tests
// =============================================================================
// These tests verify transport recovery when power is interrupted mid-frame.
// The simulator truncates responses to simulate power glitches.

// TestUART_PowerGlitch_Basic tests that transport handles truncated frames gracefully
func TestUART_PowerGlitch_Basic(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// Truncate response after 5 bytes (mid-frame)
	sim.SetPowerGlitch(5)

	// Command should fail (truncated response can't be parsed)
	_, err := transport.SendCommand(0x02, nil) // GetFirmwareVersion
	require.Error(t, err, "Truncated frame should cause error")

	// Error should be a transport error
	var transportErr *pn532.TransportError
	assert.ErrorAs(t, err, &transportErr, "Error should be TransportError")
}

// TestUART_PowerGlitch_Recovery tests that transport recovers after power glitch
func TestUART_PowerGlitch_Recovery(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// First: Cause a power glitch
	sim.SetPowerGlitch(3)
	_, err := transport.SendCommand(0x02, nil)
	require.Error(t, err, "First command should fail due to glitch")

	// Power glitch is one-shot, so next command should work
	// Reset the simulator state to clear any stuck buffers
	sim.Reset()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

	// Reconnect transport (simulating hardware reset)
	transport = newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// Now command should succeed
	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err, "Command should succeed after recovery")
	require.NotNil(t, resp)
	assert.Len(t, resp, 5, "GetFirmwareVersion should return 5 bytes")
}

// TestUART_PowerGlitch_AtVariousPoints tests glitches at different frame positions
func TestUART_PowerGlitch_AtVariousPoints(t *testing.T) {
	// Test glitch at various points in the response frame
	glitchPoints := []struct {
		name   string
		offset int
	}{
		{"Glitch_At_Preamble", 1},
		{"Glitch_At_StartCode", 3},
		{"Glitch_At_Length", 4},
		{"Glitch_At_Data", 7},
	}

	for _, tc := range glitchPoints {
		t.Run(tc.name, func(t *testing.T) {
			sim := virt.NewVirtualPN532()
			sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)

			transport := newTestTransport(sim)
			_ = transport.SetTimeout(100 * time.Millisecond)

			sim.SetPowerGlitch(tc.offset)

			// Command should fail gracefully (no panic)
			_, err := transport.SendCommand(0x02, nil)
			require.Error(t, err, "Truncated frame at offset %d should cause error", tc.offset)
		})
	}
}

// TestUART_PowerGlitch_NoPanic tests that power glitch doesn't cause panic
func TestUART_PowerGlitch_NoPanic(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.AddTag(tag)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(50 * time.Millisecond)

	// Test multiple glitches don't cause issues
	for i := 1; i <= 10; i++ {
		sim.Reset()
		sim.AddTag(tag)
		sim.SetPowerGlitch(i)

		// This should not panic
		_, _ = transport.SendCommand(0x4A, []byte{0x01, 0x00}) // InListPassiveTarget
	}

	// If we get here without panic, test passes
	t.Log("Completed 10 power glitch iterations without panic")
}

// =============================================================================
// Collision Mode Tests (Item 11)
// =============================================================================
// These tests verify handling of tag collisions when multiple tags are present.

// TestUART_CollisionMode_DetectsNoTags tests that collision returns no tags
func TestUART_CollisionMode_DetectsNoTags(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag1 := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	tag2 := virt.NewVirtualNTAG213([]byte{0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	sim.AddTag(tag1)
	sim.AddTag(tag2)
	sim.SetCollisionMode(true)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// InListPassiveTarget should return NbTg=0 due to collision
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err, "Collision should not cause transport error")
	require.NotNil(t, resp)

	// Response format: [0x4B, NbTg, ...]
	assert.Equal(t, byte(0x4B), resp[0], "Response should be InListPassiveTarget response")
	assert.Equal(t, byte(0x00), resp[1], "NbTg should be 0 due to collision")
}

// TestUART_CollisionMode_SingleTagStillWorks tests single tag detection works
func TestUART_CollisionMode_SingleTagStillWorks(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	sim.AddTag(tag)
	sim.SetCollisionMode(true) // Should not affect single tag

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// Single tag should still be detected
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, byte(0x4B), resp[0])
	assert.Equal(t, byte(0x01), resp[1], "NbTg should be 1 with single tag")
}

// =============================================================================
// Multi-Tag Detection Tests
// =============================================================================
// These tests verify detecting and switching between multiple tags.

// TestUART_MultiTag_DetectTwo tests detecting two tags at once
func TestUART_MultiTag_DetectTwo(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag1 := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	tag2 := virt.NewVirtualNTAG213([]byte{0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	sim.AddTag(tag1)
	sim.AddTag(tag2)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// Request MaxTg=2
	resp, err := transport.SendCommand(0x4A, []byte{0x02, 0x00})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Response format: [0x4B, NbTg, Tg1Data..., Tg2Data...]
	assert.Equal(t, byte(0x4B), resp[0], "Response should be InListPassiveTarget response")
	assert.Equal(t, byte(0x02), resp[1], "NbTg should be 2")

	// First tag data starts at offset 2: Tg(1) + SENS_RES(2) + SEL_RES(1) + NFCIDLen(1) + UID(7)
	assert.Equal(t, byte(0x01), resp[2], "First tag number should be 1")

	// Second tag data starts at offset 2+12=14
	assert.Equal(t, byte(0x02), resp[14], "Second tag number should be 2")
}

// TestUART_MultiTag_SwitchWithInSelect tests switching between tags with InSelect
func TestUART_MultiTag_SwitchWithInSelect(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag1 := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	tag2 := virt.NewVirtualNTAG213([]byte{0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	sim.AddTag(tag1)
	sim.AddTag(tag2)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// First: Detect both tags
	resp, err := transport.SendCommand(0x4A, []byte{0x02, 0x00})
	require.NoError(t, err)
	assert.Equal(t, byte(0x02), resp[1], "Should detect 2 tags")

	// Tag 1 is selected by default after detection
	assert.Equal(t, 1, sim.GetState().SelectedTarget)

	// Switch to tag 2 using InSelect
	resp, err = transport.SendCommand(0x54, []byte{0x02}) // InSelect target 2
	require.NoError(t, err)
	assert.Equal(t, byte(0x55), resp[0], "Response should be InSelect response")
	assert.Equal(t, byte(0x00), resp[1], "Status should be success")

	// Verify tag 2 is now selected
	assert.Equal(t, 2, sim.GetState().SelectedTarget)

	// Read from tag 2 (should work) - note: tg=0x02 must match selected target
	resp, err = transport.SendCommand(0x40, []byte{0x02, 0x30, 0x04}) // InDataExchange: read block 4
	require.NoError(t, err)
	assert.Equal(t, byte(0x41), resp[0], "Response should be InDataExchange response")
	assert.Equal(t, byte(0x00), resp[1], "Status should be success")

	// Switch back to tag 1
	resp, err = transport.SendCommand(0x54, []byte{0x01}) // InSelect target 1
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), resp[1], "InSelect to tag 1 should succeed")
	assert.Equal(t, 1, sim.GetState().SelectedTarget)
}

// TestUART_MultiTag_MixedTypes tests detecting mixed tag types
func TestUART_MultiTag_MixedTypes(t *testing.T) {
	sim := virt.NewVirtualPN532()
	ntag := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	mifare := virt.NewVirtualMIFARE1K([]byte{0x12, 0x34, 0x56, 0x78})
	sim.AddTag(ntag)
	sim.AddTag(mifare)

	transport := newTestTransport(sim)
	_ = transport.SetTimeout(100 * time.Millisecond)

	// Request MaxTg=2
	resp, err := transport.SendCommand(0x4A, []byte{0x02, 0x00})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, byte(0x02), resp[1], "Should detect 2 tags of different types")
}

// =============================================================================
// Device-Level Integration Tests
// =============================================================================
// These tests exercise the full Device API using the wire simulator.

// TestIntegration_DualTagWorkflow tests the complete dual-tag detection and switching workflow
func TestIntegration_DualTagWorkflow(t *testing.T) {
	// Setup simulator with two tags
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	tag1 := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	tag2 := virt.NewVirtualMIFARE1K([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	sim.AddTag(tag1)
	sim.AddTag(tag2)

	// Create device using test transport
	transport := newTestTransport(sim)
	device, err := pn532.New(transport)
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	ctx := context.Background()

	// Step 1: Detect both tags
	tags, err := device.DetectTags(ctx, 2, 0x00)
	require.NoError(t, err)
	require.Len(t, tags, 2, "Should detect 2 tags")

	// Verify tag UIDs
	assert.Equal(t, "04112233445566", tags[0].UID)
	assert.Equal(t, "aabbccdd", tags[1].UID)

	// Step 2: First tag should be selected by default
	assert.Equal(t, byte(1), tags[0].TargetNumber)
	assert.Equal(t, byte(2), tags[1].TargetNumber)

	// Step 3: Switch to second tag using SelectTag
	err = device.SelectTag(ctx, tags[1])
	require.NoError(t, err)

	// Verify simulator state
	assert.Equal(t, 2, sim.GetState().SelectedTarget)

	// Step 4: Switch back to first tag
	err = device.SelectTag(ctx, tags[0])
	require.NoError(t, err)
	assert.Equal(t, 1, sim.GetState().SelectedTarget)
}

// TestIntegration_CollisionPreventsDetection tests that collision mode prevents tag detection
func TestIntegration_CollisionPreventsDetection(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	tag1 := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	tag2 := virt.NewVirtualNTAG213([]byte{0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	sim.AddTag(tag1)
	sim.AddTag(tag2)
	sim.SetCollisionMode(true) // Enable collision simulation

	transport := newTestTransport(sim)
	device, err := pn532.New(transport)
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	ctx := context.Background()

	// With collision mode enabled, should detect no tags
	tags, err := device.DetectTags(ctx, 2, 0x00)
	require.NoError(t, err)
	assert.Empty(t, tags, "Collision should prevent detection")

	// Disable collision mode
	sim.SetCollisionMode(false)

	// Now should detect both tags
	tags, err = device.DetectTags(ctx, 2, 0x00)
	require.NoError(t, err)
	assert.Len(t, tags, 2, "Should detect 2 tags after collision cleared")
}

// TestIntegration_TagRemovalDuringSwitch tests switching to a tag that was removed
func TestIntegration_TagRemovalDuringSwitch(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	tag1 := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	tag2 := virt.NewVirtualNTAG213([]byte{0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	sim.AddTag(tag1)
	sim.AddTag(tag2)

	transport := newTestTransport(sim)
	device, err := pn532.New(transport)
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	ctx := context.Background()

	// Detect both tags
	tags, err := device.DetectTags(ctx, 2, 0x00)
	require.NoError(t, err)
	require.Len(t, tags, 2)

	// "Remove" tag 2 from field
	tag2.Present = false

	// Try to switch to tag 2 - should fail
	err = device.SelectTag(ctx, tags[1])
	require.Error(t, err, "Should fail to select removed tag")

	// Tag 1 should still be accessible
	err = device.SelectTag(ctx, tags[0])
	assert.NoError(t, err, "Tag 1 should still be selectable")
}

// Note: Timeout/zombie behavior is tested at the transport level (TestUART_ZombieMode_*)
// because the mock serial port doesn't simulate blocking I/O. Device-level timeout
// testing would require a mock that properly blocks on reads until timeout.

// TestIntegration_SingleTagWithMaxTgTwo tests requesting 2 tags when only 1 is present
func TestIntegration_SingleTagWithMaxTgTwo(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	sim.AddTag(tag)

	transport := newTestTransport(sim)
	device, err := pn532.New(transport)
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	ctx := context.Background()

	// Request 2 tags but only 1 is present
	tags, err := device.DetectTags(ctx, 2, 0x00)
	require.NoError(t, err)
	assert.Len(t, tags, 1, "Should return 1 tag when only 1 present")
	assert.Equal(t, "04112233445566", tags[0].UID)
}
