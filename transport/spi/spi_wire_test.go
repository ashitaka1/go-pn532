//nolint:paralleltest // Test file - parallel tests add complexity
package spi

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ZaparooProject/go-pn532"
	virt "github.com/ZaparooProject/go-pn532/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"periph.io/x/conn/v3"
	"periph.io/x/conn/v3/physic"
	"periph.io/x/conn/v3/spi"
)

var errPortClosed = errors.New("port is closed")

// mockReverseBit reverses the bits in a byte (for LSB <-> MSB conversion).
func mockReverseBit(b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		result <<= 1
		result |= b & 1
		b >>= 1
	}
	return result
}

// mockReverseBytes reverses bits in all bytes of a slice.
func mockReverseBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = mockReverseBit(b)
	}
	return result
}

// MockSPIConn implements spi.Conn interface backed by VirtualPN532.
// The mock handles the SPI protocol's quirky read behavior where:
// 1. ACK is read first (6 bytes)
// 2. Header read gets preamble + length info
// 3. Data read restarts from TFI position (not continuing from header)
type MockSPIConn struct {
	sim           *virt.VirtualPN532
	responseFrame []byte
	readPos       int
	closed        bool
	headerRead    bool
}

// NewMockSPIConn creates a new mock SPI connection.
func NewMockSPIConn(sim *virt.VirtualPN532) *MockSPIConn {
	return &MockSPIConn{
		sim: sim,
	}
}

// isACKFrame checks if the buffer contains an ACK frame.
func isACKFrame(buf []byte, length int) bool {
	return length >= 6 && buf[0] == 0x00 && buf[1] == 0x00 &&
		buf[2] == 0xFF && buf[3] == 0x00 && buf[4] == 0xFF
}

// handleStatusRead handles SPI status read command.
func (m *MockSPIConn) handleStatusRead(readBuf []byte) {
	if len(readBuf) < 2 {
		return
	}
	readBuf[0] = 0 // First byte is echoed command
	if m.sim.HasPendingResponse() || len(m.responseFrame) > 0 {
		readBuf[1] = mockReverseBit(spiReady) // Ready
	} else {
		readBuf[1] = 0x00 // Not ready
	}
}

// handleDataWrite handles SPI data write command.
func (m *MockSPIConn) handleDataWrite(w []byte) error {
	if len(w) <= 1 {
		return nil
	}
	// Reverse the data bytes before sending to simulator
	dataToWrite := mockReverseBytes(w[1:])
	_, err := m.sim.Write(dataToWrite)
	if err != nil {
		return fmt.Errorf("mock spi write: %w", err)
	}
	// Reset state for new command
	m.responseFrame = nil
	m.readPos = 0
	m.headerRead = false
	return nil
}

// handleDataRead handles SPI data read command.
func (m *MockSPIConn) handleDataRead(readBuf []byte) error {
	if len(readBuf) <= 1 {
		return nil
	}

	// First byte is status/command echo
	readBuf[0] = 0

	// If no cached response, read from simulator (this gets ACK + response)
	if m.responseFrame == nil {
		ackHandled, err := m.readFromSimulator(readBuf)
		if err != nil {
			return err
		}
		// If we just returned an ACK, we're done
		if ackHandled {
			return nil
		}
	}

	if len(m.responseFrame) == 0 {
		return nil
	}

	m.fillResponseBuffer(readBuf)
	return nil
}

// readFromSimulator reads data from the simulator and handles ACK frames.
// Returns true if an ACK was handled (caller should return immediately).
func (m *MockSPIConn) readFromSimulator(readBuf []byte) (ackHandled bool, err error) {
	tempBuf := make([]byte, 256)
	bytesRead, _ := m.sim.Read(tempBuf)
	if bytesRead == 0 {
		return false, nil
	}

	// Check if this is an ACK frame
	if isACKFrame(tempBuf, bytesRead) {
		ackLen := 6
		for i := 0; i < len(readBuf)-1 && i < ackLen; i++ {
			readBuf[i+1] = mockReverseBit(tempBuf[i])
		}
		// Cache the response frame (after ACK)
		if bytesRead > ackLen {
			m.responseFrame = make([]byte, bytesRead-ackLen)
			copy(m.responseFrame, tempBuf[ackLen:bytesRead])
		}
		m.readPos = 0
		m.headerRead = false
		return true, nil // ACK handled
	}

	// Not an ACK, treat as response
	m.responseFrame = make([]byte, bytesRead)
	copy(m.responseFrame, tempBuf[:bytesRead])
	m.readPos = 0
	m.headerRead = false
	return false, nil
}

// fillResponseBuffer fills the response buffer based on current read phase.
func (m *MockSPIConn) fillResponseBuffer(readBuf []byte) {
	dataLen := len(readBuf) - 1

	if !m.headerRead {
		// Header read: return from beginning of response frame
		m.headerRead = true
		for i := 0; i < dataLen && i < len(m.responseFrame); i++ {
			readBuf[i+1] = mockReverseBit(m.responseFrame[i])
		}
		// Zero out remaining
		for i := len(m.responseFrame) + 1; i < len(readBuf); i++ {
			readBuf[i] = 0
		}
	} else {
		// Data read: return from TFI position (index 5 in frame)
		// Frame: [00][00][FF][len][lcs][TFI][cmd][data...][DCS][00]
		const tfiPos = 5
		for i := 0; i < dataLen && tfiPos+i < len(m.responseFrame); i++ {
			readBuf[i+1] = mockReverseBit(m.responseFrame[tfiPos+i])
		}
		// Zero out remaining
		remaining := len(m.responseFrame) - tfiPos + 1
		for i := remaining; i < len(readBuf); i++ {
			readBuf[i] = 0
		}
		// Reset for next command
		m.responseFrame = nil
		m.headerRead = false
	}
}

// Tx implements spi.Conn.Tx - performs SPI transaction.
// This must handle the bit reversal since PN532 uses LSB-first.
//
//nolint:varnamelen // Interface compliance requires these parameter names
func (m *MockSPIConn) Tx(w, r []byte) error {
	if m.closed {
		return errPortClosed
	}

	if len(w) == 0 {
		return nil
	}

	// Get the SPI command byte (reversed)
	cmdByte := mockReverseBit(w[0])

	switch cmdByte {
	case spiStatRead:
		m.handleStatusRead(r)
		return nil
	case spiDataWrite:
		return m.handleDataWrite(w)
	case spiDataRead:
		return m.handleDataRead(r)
	}

	return nil
}

// Duplex implements conn.Conn.
func (*MockSPIConn) Duplex() conn.Duplex {
	return conn.Full
}

// String returns connection name.
func (*MockSPIConn) String() string {
	return "mock://spi"
}

// TxPackets implements spi.Conn.
func (m *MockSPIConn) TxPackets(p []spi.Packet) error {
	for _, pkt := range p {
		if err := m.Tx(pkt.W, pkt.R); err != nil {
			return err
		}
	}
	return nil
}

// MockSPIPort implements spi.PortCloser interface.
type MockSPIPort struct {
	conn   *MockSPIConn
	closed bool
}

// NewMockSPIPort creates a mock SPI port.
func NewMockSPIPort(sim *virt.VirtualPN532) *MockSPIPort {
	return &MockSPIPort{
		conn: NewMockSPIConn(sim),
	}
}

// Connect implements spi.Port.
func (p *MockSPIPort) Connect(_ physic.Frequency, _ spi.Mode, _ int) (spi.Conn, error) {
	return p.conn, nil
}

// Close implements io.Closer.
func (p *MockSPIPort) Close() error {
	p.closed = true
	p.conn.closed = true
	return nil
}

// String returns port name.
func (*MockSPIPort) String() string {
	return "mock://spi"
}

// LimitSpeed implements spi.Port.
func (*MockSPIPort) LimitSpeed(_ physic.Frequency) error {
	return nil
}

var (
	_ spi.Conn       = (*MockSPIConn)(nil)
	_ spi.PortCloser = (*MockSPIPort)(nil)
)

// newTestSPITransport creates a Transport using the mock SPI port.
func newTestSPITransport(sim *virt.VirtualPN532) *Transport {
	mockPort := NewMockSPIPort(sim)
	spiConn, _ := mockPort.Connect(defaultFreq, mode, 8)
	return &Transport{
		port:     mockPort,
		conn:     spiConn,
		portName: "mock://spi",
		timeout:  100 * time.Millisecond,
	}
}

// --- Basic Protocol Tests ---

func TestSPI_GetFirmwareVersion(t *testing.T) {
	sim := virt.NewVirtualPN532()
	sim.SetFirmwareVersion(0x32, 0x01, 0x06, 0x07)
	transport := newTestSPITransport(sim)

	resp, err := transport.SendCommand(0x02, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// SPI transport strips the response code and TFI in receiveFrame
	// So we get: [IC, Ver, Rev, Support] without the response code
	// Let me verify what we actually get
	t.Logf("Response: %x", resp)

	// Based on SPI implementation (line 339-347), it skips TFI and response code
	// So the response should be: IC, Ver, Rev, Support
	assert.GreaterOrEqual(t, len(resp), 4)
	assert.Equal(t, byte(0x32), resp[0], "IC should be 0x32 (PN532)")
	assert.Equal(t, byte(0x01), resp[1], "Version should be 0x01")
	assert.Equal(t, byte(0x06), resp[2], "Revision should be 0x06")
	assert.Equal(t, byte(0x07), resp[3], "Support should be 0x07")
}

func TestSPI_SAMConfiguration(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	// SAMConfiguration: Mode=0x01 (Normal), Timeout=0x14, IRQ=0x01
	resp, err := transport.SendCommand(0x14, []byte{0x01, 0x14, 0x01})
	require.NoError(t, err)

	// SPI strips response code, so response should be empty for SAMConfiguration
	assert.Empty(t, resp)
}

func TestSPI_InListPassiveTarget_NoTags(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	// InListPassiveTarget: MaxTg=1, BrTy=0x00 (106kbps Type A)
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Response: [NbTg=0] (response code is stripped)
	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x00), resp[0], "NbTg should be 0 (no tags)")
}

func TestSPI_InListPassiveTarget_WithTag(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.SetTag(tag)
	transport := newTestSPITransport(sim)

	// InListPassiveTarget: MaxTg=1, BrTy=0x00 (106kbps Type A)
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Response: [NbTg, Tg, SENS_RES(2), SEL_RES, NFCIDLength, NFCID...]
	assert.GreaterOrEqual(t, len(resp), 7)
	assert.Equal(t, byte(0x01), resp[0], "NbTg should be 1")
	assert.Equal(t, byte(0x01), resp[1], "Tg should be 1")
}

func TestSPI_InDataExchange_Read(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.SetTag(tag)
	transport := newTestSPITransport(sim)

	// First select the tag
	_, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// InDataExchange: Tg=1, READ command (0x30), page 0
	resp, err := transport.SendCommand(0x40, []byte{0x01, 0x30, 0x00})
	require.NoError(t, err)

	// Response: [Status, Data...] (response code is stripped)
	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x00), resp[0], "Status should be 0x00 (success)")
}

func TestSPI_InDataExchange_Write(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.SetTag(tag)
	transport := newTestSPITransport(sim)

	// Select tag
	_, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// InDataExchange: Tg=1, WRITE command (0xA2), page 4, data
	resp, err := transport.SendCommand(0x40, []byte{0x01, 0xA2, 0x04, 0xDE, 0xAD, 0xBE, 0xEF})
	require.NoError(t, err)

	// Response: [Status]
	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x00), resp[0], "Write should succeed")
}

// --- MIFARE Tests ---

func TestSPI_MIFARE_Authentication(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualMIFARE1K([]byte{0x01, 0x02, 0x03, 0x04})
	sim.SetTag(tag)
	transport := newTestSPITransport(sim)

	// Select tag
	_, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// InDataExchange: MIFARE Auth with Key A
	authCmd := []byte{
		0x01,                               // Tg
		0x60,                               // Auth Key A
		0x04,                               // Block number
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key (default)
		0x01, 0x02, 0x03, 0x04, // UID
	}
	resp, err := transport.SendCommand(0x40, authCmd)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x00), resp[0], "Auth should succeed")
}

func TestSPI_MIFARE_ReadAfterAuth(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualMIFARE1K([]byte{0x01, 0x02, 0x03, 0x04})
	sim.SetTag(tag)
	transport := newTestSPITransport(sim)

	// Select tag
	_, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// Authenticate
	authCmd := []byte{
		0x01, 0x60, 0x04,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x01, 0x02, 0x03, 0x04,
	}
	_, err = transport.SendCommand(0x40, authCmd)
	require.NoError(t, err)

	// Read block 4
	resp, err := transport.SendCommand(0x40, []byte{0x01, 0x30, 0x04})
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x00), resp[0])
}

// --- FeliCa Tests ---

func TestSPI_FeliCa_Detection(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := &virt.VirtualTag{
		Type:    "FeliCa",
		UID:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Present: true,
	}
	sim.SetTag(tag)
	transport := newTestSPITransport(sim)

	// InListPassiveTarget for FeliCa: BrTy=0x01 (212kbps FeliCa)
	resp, err := transport.SendCommand(0x4A, []byte{0x01, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x00})
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x01), resp[0], "Should detect FeliCa tag")
}

// --- Control Commands ---

func TestSPI_RFConfiguration(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	// RFConfiguration: MaxRetries
	resp, err := transport.SendCommand(0x32, []byte{0x05, 0xFF, 0x01, 0x01})
	require.NoError(t, err)

	// Response should be empty (response code stripped)
	assert.Empty(t, resp)
}

func TestSPI_InRelease(t *testing.T) {
	sim := virt.NewVirtualPN532()
	tag := virt.NewVirtualNTAG213([]byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	sim.SetTag(tag)
	transport := newTestSPITransport(sim)

	// Select tag first
	_, err := transport.SendCommand(0x4A, []byte{0x01, 0x00})
	require.NoError(t, err)

	// InRelease: Tg=0 (release all)
	resp, err := transport.SendCommand(0x52, []byte{0x00})
	require.NoError(t, err)

	// Response: [Status] (response code stripped)
	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x00), resp[0])
}

func TestSPI_PowerDown(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	// Send PowerDown with WakeUpEnable byte set to 0x00
	resp, err := transport.SendCommand(0x16, []byte{0x00})
	require.NoError(t, err)

	// Response: [Status] (response code stripped)
	assert.GreaterOrEqual(t, len(resp), 1)
	assert.Equal(t, byte(0x00), resp[0])
}

// --- Error Handling Tests ---

func TestSPI_PortClosed(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	// Close the underlying port
	_ = transport.port.Close()

	_, err := transport.SendCommand(0x02, nil)
	require.Error(t, err)
}

func TestSPI_IsConnected(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	assert.True(t, transport.IsConnected())
}

func TestSPI_Type(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	assert.Equal(t, pn532.TransportSPI, transport.Type())
}

func TestSPI_SetTimeout(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	err := transport.SetTimeout(200 * time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, 200*time.Millisecond, transport.timeout)
}

func TestSPI_Close(t *testing.T) {
	sim := virt.NewVirtualPN532()
	transport := newTestSPITransport(sim)

	err := transport.Close()
	require.NoError(t, err)
}
