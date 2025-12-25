//nolint:paralleltest // Test file - not using parallel tests
package tagops

import (
	"context"
	"testing"

	"github.com/ZaparooProject/go-pn532"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TagType Tests ---

func TestTagTypeDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		tagType  pn532.TagType
	}{
		{"Unknown tag type", "Unknown", pn532.TagTypeUnknown},
		{"NTAG tag type", "NTAG", pn532.TagTypeNTAG},
		{"MIFARE tag type", "MIFARE Classic", pn532.TagTypeMIFARE},
		{"Any tag type", "Unknown", pn532.TagTypeAny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := TagTypeDisplayName(tc.tagType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTagType_Constants(t *testing.T) {
	// Verify constants are distinct (pn532.TagType is a string type)
	assert.NotEqual(t, pn532.TagTypeUnknown, pn532.TagTypeNTAG)
	assert.NotEqual(t, pn532.TagTypeUnknown, pn532.TagTypeMIFARE)
	assert.NotEqual(t, pn532.TagTypeNTAG, pn532.TagTypeMIFARE)

	// Verify TagType values
	assert.Equal(t, pn532.TagTypeUnknown, pn532.TagType("UNKNOWN"))
	assert.Equal(t, pn532.TagTypeNTAG, pn532.TagType("NTAG"))
	assert.Equal(t, pn532.TagTypeMIFARE, pn532.TagType("MIFARE"))
}

// --- DetectTagTypeFromUID Tests ---

func TestDetectTagTypeFromUID(t *testing.T) {
	tests := []struct {
		name     string
		expected pn532.TagType
		uid      []byte
	}{
		{
			name:     "7-byte UID starting with 0x04 (NTAG)",
			uid:      []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expected: pn532.TagTypeNTAG,
		},
		{
			name:     "4-byte UID (MIFARE)",
			uid:      []byte{0x01, 0x02, 0x03, 0x04},
			expected: pn532.TagTypeMIFARE,
		},
		{
			name:     "7-byte UID not starting with 0x04",
			uid:      []byte{0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expected: pn532.TagTypeUnknown,
		},
		{
			name:     "Empty UID",
			uid:      []byte{},
			expected: pn532.TagTypeUnknown,
		},
		{
			name:     "Single byte UID",
			uid:      []byte{0x04},
			expected: pn532.TagTypeUnknown,
		},
		{
			name:     "10-byte UID",
			uid:      []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
			expected: pn532.TagTypeUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := DetectTagTypeFromUID(tc.uid)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// --- CompareUID Tests ---

func TestCompareUID(t *testing.T) {
	tests := []struct {
		name     string
		uid1     []byte
		uid2     []byte
		expected bool
	}{
		{
			name:     "Identical UIDs",
			uid1:     []byte{0x04, 0x01, 0x02, 0x03},
			uid2:     []byte{0x04, 0x01, 0x02, 0x03},
			expected: true,
		},
		{
			name:     "Different UIDs same length",
			uid1:     []byte{0x04, 0x01, 0x02, 0x03},
			uid2:     []byte{0x04, 0x01, 0x02, 0x04},
			expected: false,
		},
		{
			name:     "Different lengths",
			uid1:     []byte{0x04, 0x01, 0x02},
			uid2:     []byte{0x04, 0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "Both empty",
			uid1:     []byte{},
			uid2:     []byte{},
			expected: true,
		},
		{
			name:     "One empty",
			uid1:     []byte{0x04},
			uid2:     []byte{},
			expected: false,
		},
		{
			name:     "Both nil",
			uid1:     nil,
			uid2:     nil,
			expected: true,
		},
		{
			name:     "Nil vs empty",
			uid1:     nil,
			uid2:     []byte{},
			expected: true, // bytes.Equal treats nil and empty as equal
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := CompareUID(tc.uid1, tc.uid2)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// --- TagInfo Tests ---

func TestTagInfo_NTAGTypes(t *testing.T) {
	tests := []struct {
		name         string
		expectedType string
		totalPages   int
	}{
		{"NTAG213", "NTAG213", 45},
		{"NTAG215", "NTAG215", 135},
		{"NTAG216", "NTAG216", 231},
		{"Unknown NTAG", "NTAG (unknown, 100 pages)", 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create TagOperations with NTAG type and specified pages
			ops := &TagOperations{
				tagType:    pn532.TagTypeNTAG,
				totalPages: tc.totalPages,
				tag:        &pn532.DetectedTag{UIDBytes: []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}},
			}

			info, err := ops.GetTagInfo()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedType, info.NTAGType)
			assert.Equal(t, ntagTypeName, info.TypeName)
		})
	}
}

func TestTagInfo_MIFARE(t *testing.T) {
	// 4-byte UID indicates 1K
	ops := &TagOperations{
		tagType: pn532.TagTypeMIFARE,
		tag:     &pn532.DetectedTag{UIDBytes: []byte{0x01, 0x02, 0x03, 0x04}},
	}

	info, err := ops.GetTagInfo()
	require.NoError(t, err)
	assert.Equal(t, mifareClassicName, info.TypeName)
	assert.Equal(t, "MIFARE Classic 1K", info.MIFAREType)
	assert.Equal(t, 16, info.Sectors)
	assert.Equal(t, 1024, info.TotalMemory)
}

func TestTagInfo_Unknown(t *testing.T) {
	ops := &TagOperations{
		tagType: pn532.TagTypeUnknown,
		tag:     &pn532.DetectedTag{UIDBytes: []byte{0x01}},
	}

	info, err := ops.GetTagInfo()
	require.NoError(t, err)
	assert.Equal(t, unknownTagName, info.TypeName)
}

func TestTagInfo_NoTag(t *testing.T) {
	ops := &TagOperations{}

	info, err := ops.GetTagInfo()
	require.Error(t, err)
	assert.Equal(t, ErrNoTag, err)
	assert.Nil(t, info)
}

// --- TagOperations Tests ---

func TestTagOperations_GetUID(t *testing.T) {
	expectedUID := []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	ops := &TagOperations{
		tag: &pn532.DetectedTag{UIDBytes: expectedUID},
	}

	uid := ops.GetUID()
	assert.Equal(t, expectedUID, uid)
}

func TestTagOperations_GetUID_NoTag(t *testing.T) {
	ops := &TagOperations{}

	uid := ops.GetUID()
	assert.Nil(t, uid)
}

func TestTagOperations_GetTagType(t *testing.T) {
	ops := &TagOperations{
		tagType: pn532.TagTypeNTAG,
	}

	assert.Equal(t, pn532.TagTypeNTAG, ops.GetTagType())
	assert.Equal(t, pn532.TagTypeNTAG, ops.TagType()) // Alias method
}

func TestNew(t *testing.T) {
	// New should create a TagOperations with nil tag and empty type
	ops := New(nil)

	assert.NotNil(t, ops)
	assert.Nil(t, ops.tag)
	// Empty string is the zero value for pn532.TagType (which is a string type)
	assert.Equal(t, pn532.TagType(""), ops.tagType)
}

// --- Error Constants ---

func TestErrors(t *testing.T) {
	// Verify error messages
	assert.Equal(t, "no tag detected", ErrNoTag.Error())
	assert.Equal(t, "unsupported tag type", ErrUnsupportedTag.Error())
	assert.Equal(t, "authentication failed with all known keys", ErrAuthFailed.Error())
}

// --- detectAndInitializeTag Tests ---

func TestTagOperations_detectAndInitializeTag_NoTag(t *testing.T) {
	ops := &TagOperations{
		tag: nil,
	}

	err := ops.detectAndInitializeTag(context.TODO())
	assert.Equal(t, ErrNoTag, err)
}

// --- TagInfo MIFARE Variants ---

func TestTagInfo_MIFARE_UnknownSize(t *testing.T) {
	// 7-byte UID results in unknown size (UID length doesn't determine card type)
	ops := &TagOperations{
		tagType: pn532.TagTypeMIFARE,
		tag:     &pn532.DetectedTag{UIDBytes: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
	}

	info, err := ops.GetTagInfo()
	require.NoError(t, err)
	assert.Equal(t, mifareClassicName, info.TypeName)
	// 7-byte UIDs result in unknown size since we can't determine from UID alone
	assert.Contains(t, info.MIFAREType, "MIFARE Classic")
}

// --- Reader Tests ---

func TestTagOperations_ReadBlocks_NoTag(t *testing.T) {
	ops := &TagOperations{
		tag: nil,
	}

	blocks, err := ops.ReadBlocks(context.TODO(), 0, 5)
	require.Error(t, err)
	assert.Nil(t, blocks)
}

func TestTagOperations_ReadBlocks_UnsupportedType(t *testing.T) {
	ops := &TagOperations{
		tag:     &pn532.DetectedTag{UIDBytes: []byte{0x01}},
		tagType: pn532.TagTypeUnknown,
	}

	blocks, err := ops.ReadBlocks(context.TODO(), 0, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported tag type")
	assert.Nil(t, blocks)
}

func TestTagOperations_ReadNDEF_NoTag(t *testing.T) {
	ops := &TagOperations{
		tag: nil,
	}

	message, err := ops.ReadNDEF(context.TODO())
	require.Error(t, err)
	assert.Nil(t, message)
}

func TestTagOperations_ReadNDEF_UnsupportedType(t *testing.T) {
	ops := &TagOperations{
		tag:     &pn532.DetectedTag{UIDBytes: []byte{0x01}},
		tagType: pn532.TagTypeUnknown,
	}

	message, err := ops.ReadNDEF(context.TODO())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported tag type")
	assert.Nil(t, message)
}

// --- Writer Tests ---

func TestTagOperations_WriteBlocks_NoTag(t *testing.T) {
	ops := &TagOperations{
		tag: nil,
	}

	err := ops.WriteBlocks(context.TODO(), 0, []byte{0x01})
	require.Error(t, err)
}

func TestTagOperations_WriteBlocks_UnsupportedType(t *testing.T) {
	ops := &TagOperations{
		tag:     &pn532.DetectedTag{UIDBytes: []byte{0x01}},
		tagType: pn532.TagTypeUnknown,
	}

	err := ops.WriteBlocks(context.TODO(), 0, []byte{0x01})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestTagOperations_WriteNDEF_NoTag(t *testing.T) {
	ops := &TagOperations{
		tag: nil,
	}

	err := ops.WriteNDEF(context.TODO(), &pn532.NDEFMessage{})
	require.Error(t, err)
}

func TestTagOperations_WriteNDEF_UnsupportedType(t *testing.T) {
	ops := &TagOperations{
		tag:     &pn532.DetectedTag{UIDBytes: []byte{0x01}},
		tagType: pn532.TagTypeUnknown,
	}

	err := ops.WriteNDEF(context.TODO(), &pn532.NDEFMessage{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported tag type")
}

// --- UserMemory Tests (Regression) ---
// These tests verify the corrected UserMemory calculations in GetTagInfo()

func TestTagInfo_NTAGUserMemory(t *testing.T) {
	tests := []struct {
		name               string
		totalPages         int
		expectedUserMemory int
	}{
		{
			name:               "NTAG213_UserMemory",
			totalPages:         45,
			expectedUserMemory: 144, // 36 pages * 4 bytes
		},
		{
			name:               "NTAG215_UserMemory",
			totalPages:         135,
			expectedUserMemory: 504, // 126 pages * 4 bytes
		},
		{
			name:               "NTAG216_UserMemory",
			totalPages:         231,
			expectedUserMemory: 888, // 222 pages * 4 bytes
		},
		{
			name:               "Unknown_NTAG_UserMemory",
			totalPages:         100,
			expectedUserMemory: 364, // (100 - 9) * 4 = 91 * 4 = 364
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := &TagOperations{
				tagType:    pn532.TagTypeNTAG,
				totalPages: tc.totalPages,
				tag:        &pn532.DetectedTag{UIDBytes: []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}},
			}

			info, err := ops.GetTagInfo()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedUserMemory, info.UserMemory,
				"UserMemory should be calculated correctly for %s", tc.name)
		})
	}
}

func TestTagInfo_MIFAREUserMemory(t *testing.T) {
	tests := []struct {
		name               string
		uid                []byte
		expectedUserMemory int
	}{
		{
			name:               "MIFARE_Classic_1K_UserMemory",
			uid:                []byte{0x01, 0x02, 0x03, 0x04}, // 4-byte UID = 1K
			expectedUserMemory: 720,                            // 15 sectors * 3 blocks * 16 bytes
		},
		{
			name:               "MIFARE_Unknown_Size_UserMemory",
			uid:                []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, // 7-byte UID = unknown
			expectedUserMemory: 720,                                              // defaults to 720
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := &TagOperations{
				tagType: pn532.TagTypeMIFARE,
				tag:     &pn532.DetectedTag{UIDBytes: tc.uid},
			}

			info, err := ops.GetTagInfo()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedUserMemory, info.UserMemory,
				"UserMemory should be calculated correctly for %s", tc.name)
		})
	}
}

// --- Detection Fallback Logic Tests (Regression) ---
// These tests verify the refactored detectAndInitializeTag that avoids
// redundant detection attempts when one type fails.

func TestDetectAndInitializeTag_NoTag_ReturnsError(t *testing.T) {
	ops := &TagOperations{
		tag: nil,
	}

	err := ops.detectAndInitializeTag(context.Background())

	require.Error(t, err)
	assert.Equal(t, ErrNoTag, err)
}

func TestTryInitNTAG_FailsOn4ByteUID(t *testing.T) {
	// Verify that tryInitNTAG correctly fails for non-7-byte UIDs
	// This is important because the UID length check happens before
	// any device I/O, so we can test it without mocking device responses

	mockTransport := pn532.NewMockTransport()
	device, err := pn532.New(mockTransport)
	require.NoError(t, err)
	mockTransport.SelectTarget()

	ops := New(device)
	ops.tag = &pn532.DetectedTag{
		UIDBytes: []byte{0x01, 0x02, 0x03, 0x04}, // 4-byte UID - invalid for NTAG
	}

	result := ops.tryInitNTAG(context.Background())

	assert.False(t, result, "tryInitNTAG should fail for 4-byte UID")
}

func TestTryInitNTAG_SucceedsWithValidTag(t *testing.T) {
	// Verify tryInitNTAG succeeds with a valid 7-byte UID and proper mocking

	mockTransport := pn532.NewMockTransport()
	device, err := pn532.New(mockTransport)
	require.NoError(t, err)
	mockTransport.SelectTarget()

	// Mock valid CC read
	ccData := make([]byte, 16)
	ccData[0] = 0xE1 // NDEF magic
	ccData[1] = 0x10 // Version
	ccData[2] = 0x12 // Size
	mockTransport.QueueResponses(0x40,
		append([]byte{0x41, 0x00}, ccData...),                              // CC read succeeds
		[]byte{0x41, 0x00, 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03}, // GET_VERSION response for NTAG213
	)

	ops := New(device)
	ops.tag = &pn532.DetectedTag{
		UIDBytes: []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, // 7-byte NXP UID
	}

	result := ops.tryInitNTAG(context.Background())

	assert.True(t, result, "tryInitNTAG should succeed with valid 7-byte UID")
	assert.Equal(t, pn532.TagTypeNTAG, ops.tagType)
}

func TestTryInitMIFARE_SucceedsWithValidAuth(t *testing.T) {
	// Verify that tryInitMIFARE succeeds when auth works

	mockTransport := pn532.NewMockTransport()
	device, err := pn532.New(mockTransport)
	require.NoError(t, err)
	mockTransport.SelectTarget()

	// Mock successful auth and read response
	mockTransport.SetResponse(0x40, append([]byte{0x41, 0x00}, make([]byte, 16)...))

	ops := New(device)
	ops.tag = &pn532.DetectedTag{
		UIDBytes: []byte{0x01, 0x02, 0x03, 0x04},
		SAK:      0x08, // MIFARE Classic 1K SAK
	}

	result := ops.tryInitMIFARE(context.Background())

	assert.True(t, result, "tryInitMIFARE should succeed with valid auth")
	assert.Equal(t, pn532.TagTypeMIFARE, ops.tagType)
}

func TestDetectAndInitializeTag_NTAG_FallsBackToMIFARE(t *testing.T) {
	// Test that when pre-detected as NTAG with invalid UID,
	// the code falls back to MIFARE detection

	mockTransport := pn532.NewMockTransport()
	device, err := pn532.New(mockTransport)
	require.NoError(t, err)
	mockTransport.SelectTarget()

	// Mock successful MIFARE auth (NTAG will fail on 4-byte UID check)
	mockTransport.SetResponse(0x40, append([]byte{0x41, 0x00}, make([]byte, 16)...))

	ops := New(device)
	ops.tag = &pn532.DetectedTag{
		Type:     pn532.TagTypeNTAG,              // Pre-detected as NTAG
		UIDBytes: []byte{0x01, 0x02, 0x03, 0x04}, // But 4-byte UID = invalid for NTAG
		SAK:      0x08,
	}

	err = ops.detectAndInitializeTag(context.Background())

	// Should succeed with MIFARE (fallback from NTAG)
	require.NoError(t, err)
	assert.Equal(t, pn532.TagTypeMIFARE, ops.tagType, "Should fall back to MIFARE when NTAG fails")
}
