//nolint:paralleltest // Test file - not using parallel tests
package tagops

import (
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
