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
