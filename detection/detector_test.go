//nolint:paralleltest // Test file - not using parallel tests
package detection

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mode and Confidence Tests ---

func TestMode_Constants(t *testing.T) {
	// Verify mode constants are distinct
	assert.NotEqual(t, Passive, Safe)
	assert.NotEqual(t, Passive, Full)
	assert.NotEqual(t, Safe, Full)

	// Verify Passive is 0 (iota starts at 0)
	assert.Equal(t, Passive, Mode(0))
}

func TestConfidence_Constants(t *testing.T) {
	// Verify confidence constants are distinct
	assert.NotEqual(t, Low, Medium)
	assert.NotEqual(t, Low, High)
	assert.NotEqual(t, Medium, High)

	// Verify Low is 0 (iota starts at 0)
	assert.Equal(t, Low, Confidence(0))
}

// --- DeviceInfo Tests ---

func TestDeviceInfo_String(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		device   DeviceInfo
	}{
		{
			name: "Low confidence UART device",
			device: DeviceInfo{
				Transport:  "uart",
				Path:       "/dev/ttyUSB0",
				Confidence: Low,
			},
			expected: "uart device at /dev/ttyUSB0 (confidence: low)",
		},
		{
			name: "Medium confidence I2C device",
			device: DeviceInfo{
				Transport:  "i2c",
				Path:       "/dev/i2c-1",
				Confidence: Medium,
			},
			expected: "i2c device at /dev/i2c-1 (confidence: medium)",
		},
		{
			name: "High confidence SPI device",
			device: DeviceInfo{
				Transport:  "spi",
				Path:       "/dev/spidev0.0",
				Confidence: High,
			},
			expected: "spi device at /dev/spidev0.0 (confidence: high)",
		},
		{
			name: "Unknown confidence device",
			device: DeviceInfo{
				Transport:  "uart",
				Path:       "/dev/ttyUSB1",
				Confidence: Confidence(99),
			},
			expected: "uart device at /dev/ttyUSB1 (confidence: unknown)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.device.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

// --- Options Tests ---

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	assert.Equal(t, Safe, opts.Mode)
	assert.Equal(t, 5*time.Second, opts.Timeout)
	assert.True(t, opts.EnableCache)
	assert.Equal(t, 30*time.Second, opts.CacheTTL)
	assert.NotNil(t, opts.Blocklist)
}

// --- Cache Tests ---

func TestCache_GetSet(t *testing.T) {
	// Clear cache before test
	clearCache()
	defer clearCache()

	devices := []DeviceInfo{
		{Transport: "uart", Path: "/dev/ttyUSB0", Confidence: High},
	}

	// Initially cache should be empty
	cached, found := getCached("uart", time.Minute)
	assert.False(t, found)
	assert.Nil(t, cached)

	// Set cache
	setCached("uart", devices)

	// Now cache should have the devices
	cached, found = getCached("uart", time.Minute)
	assert.True(t, found)
	assert.Len(t, cached, 1)
	assert.Equal(t, "/dev/ttyUSB0", cached[0].Path)
}

func TestCache_TTLExpiry(t *testing.T) {
	clearCache()
	defer clearCache()

	devices := []DeviceInfo{
		{Transport: "uart", Path: "/dev/ttyUSB0", Confidence: High},
	}

	setCached("uart", devices)

	// With very short TTL, cache should expire after waiting
	time.Sleep(time.Millisecond)
	cached, found := getCached("uart", time.Nanosecond)
	assert.False(t, found)
	assert.Nil(t, cached)
}

func TestCache_IsolationBetweenTransports(t *testing.T) {
	clearCache()
	defer clearCache()

	uartDevices := []DeviceInfo{
		{Transport: "uart", Path: "/dev/ttyUSB0"},
	}
	i2cDevices := []DeviceInfo{
		{Transport: "i2c", Path: "/dev/i2c-1"},
	}

	setCached("uart", uartDevices)
	setCached("i2c", i2cDevices)

	// Each transport should return its own devices
	uartCached, found := getCached("uart", time.Minute)
	assert.True(t, found)
	assert.Equal(t, "uart", uartCached[0].Transport)

	i2cCached, found := getCached("i2c", time.Minute)
	assert.True(t, found)
	assert.Equal(t, "i2c", i2cCached[0].Transport)
}

func TestCache_ClearForTransport(t *testing.T) {
	clearCache()
	defer clearCache()

	setCached("uart", []DeviceInfo{{Transport: "uart"}})
	setCached("i2c", []DeviceInfo{{Transport: "i2c"}})

	// Clear only UART cache
	clearCacheForTransport("uart")

	// UART should be cleared
	_, found := getCached("uart", time.Minute)
	assert.False(t, found)

	// I2C should still exist
	_, found = getCached("i2c", time.Minute)
	assert.True(t, found)
}

func TestCache_CopyBehavior(t *testing.T) {
	clearCache()
	defer clearCache()

	devices := []DeviceInfo{
		{Transport: "uart", Path: "/dev/ttyUSB0"},
	}
	setCached("uart", devices)

	// Modify original after caching
	devices[0].Path = "/dev/ttyUSB1"

	// Cache should have original value
	cached, found := getCached("uart", time.Minute)
	assert.True(t, found)
	assert.Equal(t, "/dev/ttyUSB0", cached[0].Path)

	// Modify returned copy
	cached[0].Path = "/dev/ttyUSB2"

	// Cache should still have original value
	cached2, found := getCached("uart", time.Minute)
	assert.True(t, found)
	assert.Equal(t, "/dev/ttyUSB0", cached2[0].Path)
}

// --- Blocklist Tests ---

func TestIsBlocked(t *testing.T) {
	blocklist := []string{"1234:5678", "ABCD:EF01"}

	tests := []struct {
		name    string
		vidpid  string
		blocked bool
	}{
		{"Exact match lowercase", "1234:5678", true},
		{"Exact match uppercase", "ABCD:EF01", true},
		{"Case insensitive", "abcd:ef01", true},
		{"Not in blocklist", "9999:9999", false},
		{"Empty string", "", false},
		{"Partial match", "1234:", false},
		{"With whitespace", "  1234:5678  ", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsBlocked(tc.vidpid, blocklist)
			assert.Equal(t, tc.blocked, result)
		})
	}
}

func TestParseVIDPID(t *testing.T) {
	tests := []struct {
		name       string
		descriptor string
		expected   string
	}{
		{"Simple format", "1234:5678", "1234:5678"},
		{"VID:PID format", "VID:1234 PID:5678", "1234:5678"},
		{"VID=PID= format", "VID=1234 PID=5678", "1234:5678"},
		{"Vendor Product format", "vendor=1234 product=5678", "1234:5678"},
		{"Mixed case", "vid:abcd pid:ef01", "ABCD:EF01"},
		{"Invalid format", "not a valid descriptor", ""},
		{"Empty string", "", ""},
		{"Only VID", "VID:1234", ""},
		{"Only PID", "PID:5678", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseVIDPID(tc.descriptor)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Simple hex", "1234", "1234"},
		{"Hex with prefix 0x", "0x1234 abc", "0"}, // Stops at 'x' since it's not hex
		{"Hex after space", " 1234 abc", "1234"},
		{"Hex with suffix", "1234ABC", "1234ABC"},
		{"No hex", "xyz", ""},
		{"Empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractHex(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid hex digits", "1234ABCD", true},
		{"Valid hex lowercase", "abcdef", true},
		{"Valid hex mixed", "1a2b3c", true},
		{"Invalid with G", "123G", false},
		{"Empty string", "", false},
		{"With spaces", "12 34", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isHex(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// --- getDetectors Tests ---

// MockDetector implements Detector interface for testing.
type MockDetector struct {
	transport string
}

func (*MockDetector) Detect(_ context.Context, _ *Options) ([]DeviceInfo, error) {
	return nil, ErrNoDevicesFound
}

func (m *MockDetector) Transport() string {
	return m.transport
}

func TestGetDetectors_FilterByTransport(t *testing.T) {
	// Save and restore original registry
	originalRegistry := registry
	defer func() { registry = originalRegistry }()

	// Clear and setup test registry
	registry = nil
	RegisterDetector(&MockDetector{transport: "uart"})
	RegisterDetector(&MockDetector{transport: "i2c"})
	RegisterDetector(&MockDetector{transport: "spi"})

	tests := []struct {
		name       string
		transports []string
		expected   int
	}{
		{"All transports", nil, 3},
		{"Empty transports", []string{}, 3},
		{"Single transport", []string{"uart"}, 1},
		{"Two transports", []string{"uart", "i2c"}, 2},
		{"Non-existent transport", []string{"usb"}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := getDetectors(tc.transports)
			assert.Len(t, result, tc.expected)
		})
	}
}

// --- DetectAll Error Cases ---

func TestDetectAllContext_NoDetectors(t *testing.T) {
	originalRegistry := registry
	defer func() { registry = originalRegistry }()

	registry = nil

	opts := DefaultOptions()
	opts.Transports = []string{"nonexistent"}
	opts.Timeout = 100 * time.Millisecond

	ctx := context.Background()
	_, err := DetectAllContext(ctx, &opts)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no detectors available")
}

func TestDetectAllContext_Timeout(t *testing.T) {
	originalRegistry := registry
	defer func() { registry = originalRegistry }()

	// Create a detector that blocks
	registry = nil
	RegisterDetector(&BlockingDetector{})

	opts := DefaultOptions()
	opts.Timeout = 10 * time.Millisecond
	opts.EnableCache = false

	_, err := DetectAll(&opts)
	require.Error(t, err)
	assert.Equal(t, ErrDetectionTimeout, err)
}

// BlockingDetector is a detector that never returns.
type BlockingDetector struct{}

func (*BlockingDetector) Detect(ctx context.Context, _ *Options) ([]DeviceInfo, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*BlockingDetector) Transport() string {
	return "blocking"
}

// --- Public Cache Functions ---

func TestClearDetectionCache(t *testing.T) {
	setCached("uart", []DeviceInfo{{Transport: "uart"}})
	setCached("i2c", []DeviceInfo{{Transport: "i2c"}})

	ClearDetectionCache()

	_, found := getCached("uart", time.Minute)
	assert.False(t, found)

	_, found = getCached("i2c", time.Minute)
	assert.False(t, found)
}

func TestClearDetectionCacheForTransport(t *testing.T) {
	clearCache()
	defer clearCache()

	setCached("uart", []DeviceInfo{{Transport: "uart"}})
	setCached("i2c", []DeviceInfo{{Transport: "i2c"}})

	ClearDetectionCacheForTransport("uart")

	_, found := getCached("uart", time.Minute)
	assert.False(t, found)

	_, found = getCached("i2c", time.Minute)
	assert.True(t, found)
}
