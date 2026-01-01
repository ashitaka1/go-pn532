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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseTag_Type(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tagType  TagType
		expected TagType
	}{
		{
			name:     "NTAG_Type",
			tagType:  TagTypeNTAG,
			expected: TagTypeNTAG,
		},
		{
			name:     "MIFARE_Type",
			tagType:  TagTypeMIFARE,
			expected: TagTypeMIFARE,
		},
		{
			name:     "FeliCa_Type",
			tagType:  TagTypeFeliCa,
			expected: TagTypeFeliCa,
		},
		{
			name:     "Unknown_Type",
			tagType:  TagTypeUnknown,
			expected: TagTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag := &BaseTag{
				tagType: tt.tagType,
			}

			result := tag.Type()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBaseTag_UID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected string
		uid      []byte
	}{
		{
			name:     "4_byte_UID",
			uid:      []byte{0x04, 0x56, 0x78, 0x9A},
			expected: "0456789a",
		},
		{
			name:     "7_byte_UID_NTAG",
			uid:      []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: "04123456789abc",
		},
		{
			name:     "Empty_UID",
			uid:      []byte{},
			expected: "",
		},
		{
			name:     "Single_byte_UID",
			uid:      []byte{0xFF},
			expected: "ff",
		},
		{
			name:     "Zero_UID",
			uid:      []byte{0x00, 0x00, 0x00, 0x00},
			expected: "00000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag := &BaseTag{
				uid: tt.uid,
			}

			result := tag.UID()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBaseTag_UIDBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		uid      []byte
		expected []byte
	}{
		{
			name:     "4_byte_UID",
			uid:      []byte{0x04, 0x56, 0x78, 0x9A},
			expected: []byte{0x04, 0x56, 0x78, 0x9A},
		},
		{
			name:     "7_byte_UID_NTAG",
			uid:      []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		},
		{
			name:     "Empty_UID",
			uid:      []byte{},
			expected: []byte{},
		},
		{
			name:     "Nil_UID",
			uid:      nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag := &BaseTag{
				uid: tt.uid,
			}

			result := tag.UIDBytes()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBaseTag_IsMIFARE4K(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sak      byte
		expected bool
	}{
		{
			name:     "MIFARE_Classic_4K",
			sak:      0x18,
			expected: true,
		},
		{
			name:     "MIFARE_Classic_1K",
			sak:      0x08,
			expected: false,
		},
		{
			name:     "NTAG_SAK",
			sak:      0x00,
			expected: false,
		},
		{
			name:     "Unknown_SAK",
			sak:      0xFF,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag := &BaseTag{
				sak: tt.sak,
			}

			result := tag.IsMIFARE4K()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBaseTag_ReadBlock(t *testing.T) {
	t.Parallel()

	tag := &BaseTag{}
	data, err := tag.ReadBlock(context.Background(), 4)

	require.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, ErrNotImplemented, err)
}

func TestBaseTag_WriteBlock(t *testing.T) {
	t.Parallel()

	tag := &BaseTag{}
	err := tag.WriteBlock(context.Background(), 4, []byte{0x01, 0x02, 0x03, 0x04})

	require.Error(t, err)
	assert.Equal(t, ErrNotImplemented, err)
}

func TestBaseTag_ReadNDEF(t *testing.T) {
	t.Parallel()

	tag := &BaseTag{}
	data, err := tag.ReadNDEF(context.Background())

	require.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, ErrNotImplemented, err)
}

func TestBaseTag_WriteNDEF(t *testing.T) {
	t.Parallel()

	tag := &BaseTag{}
	message := &NDEFMessage{
		Records: []NDEFRecord{
			{Type: NDEFTypeText, Text: "Hello"},
		},
	}
	err := tag.WriteNDEF(context.Background(), message)

	require.Error(t, err)
	assert.Equal(t, ErrNotImplemented, err)
}

func TestBaseTag_ReadText(t *testing.T) {
	t.Parallel()

	// Create a BaseTag with mock device to test ReadText logic
	mockTransport := NewMockTransport()
	device, err := New(mockTransport)
	require.NoError(t, err)

	tag := &BaseTag{
		device:  device,
		tagType: TagTypeNTAG,
		uid:     []byte{0x04, 0x12, 0x34, 0x56},
	}

	// Test ReadText calls ReadNDEF (which will return ErrNotImplemented)
	text, err := tag.ReadText(context.Background())
	require.Error(t, err)
	assert.Empty(t, text)
	assert.Equal(t, ErrNotImplemented, err)
}

func TestBaseTag_WriteText(t *testing.T) {
	t.Parallel()

	// Create a BaseTag with mock device
	mockTransport := NewMockTransport()
	device, err := New(mockTransport)
	require.NoError(t, err)

	tag := &BaseTag{
		device:  device,
		tagType: TagTypeNTAG,
		uid:     []byte{0x04, 0x12, 0x34, 0x56},
	}

	// Test WriteText calls WriteNDEF (which will return ErrNotImplemented)
	err = tag.WriteText(context.Background(), "Hello, World!")
	require.Error(t, err)
	assert.Equal(t, ErrNotImplemented, err)
}

func TestBaseTag_Summary(t *testing.T) {
	t.Parallel()

	tag := &BaseTag{
		tagType: TagTypeNTAG,
		uid:     []byte{0x04, 0x12, 0x34, 0x56},
	}
	summary := tag.Summary()

	assert.NotEmpty(t, summary)
	assert.Contains(t, summary, "NTAG")
	assert.Contains(t, summary, "04123456")
}

func TestBaseTag_DebugInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tagType TagType
		uid     []byte
		sak     byte
	}{
		{
			name:    "NTAG_Tag",
			tagType: TagTypeNTAG,
			uid:     []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			sak:     0x00,
		},
		{
			name:    "MIFARE_4K_Tag",
			tagType: TagTypeMIFARE,
			uid:     []byte{0x04, 0x56, 0x78, 0x9A},
			sak:     0x18,
		},
		{
			name:    "MIFARE_1K_Tag",
			tagType: TagTypeMIFARE,
			uid:     []byte{0x04, 0x56, 0x78, 0x9A},
			sak:     0x08,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag := &BaseTag{
				tagType: tt.tagType,
				uid:     tt.uid,
				sak:     tt.sak,
			}

			result := tag.DebugInfo()

			// Verify the debug info contains expected information
			assert.Contains(t, result, string(tt.tagType))
			assert.Contains(t, result, tag.UID())
			assert.Contains(t, result, "SAK:")
		})
	}
}

func TestBaseTag_DebugInfoWithNDEF(t *testing.T) {
	t.Parallel()

	// Create a BaseTag with mock device
	mockTransport := NewMockTransport()
	device, err := New(mockTransport)
	require.NoError(t, err)

	tag := &BaseTag{
		device:  device,
		tagType: TagTypeNTAG,
		uid:     []byte{0x04, 0x12, 0x34, 0x56},
		sak:     0x00,
	}

	// Pass the tag itself as the NDEF reader interface (it implements ReadNDEF)
	result := tag.DebugInfoWithNDEF(tag)

	// Should contain basic debug info
	assert.Contains(t, result, "NTAG")
	assert.Contains(t, result, tag.UID())
	// Should also indicate NDEF read failed (since BaseTag doesn't implement ReadNDEF)
	assert.Contains(t, result, "NDEF:")
}

func TestDetectedTag_Structure(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tag := DetectedTag{
		DetectedAt: now,
		UID:        "04123456",
		Type:       TagTypeNTAG,
		UIDBytes:   []byte{0x04, 0x12, 0x34, 0x56},
		ATQ:        []byte{0x00, 0x44},
		TargetData: []byte{0x04, 0x12, 0x34, 0x56, 0x78},
		SAK:        0x00,
	}

	// Verify all fields are properly set
	assert.Equal(t, now, tag.DetectedAt)
	assert.Equal(t, "04123456", tag.UID)
	assert.Equal(t, TagTypeNTAG, tag.Type)
	assert.Equal(t, []byte{0x04, 0x12, 0x34, 0x56}, tag.UIDBytes)
	assert.Equal(t, []byte{0x00, 0x44}, tag.ATQ)
	assert.Equal(t, []byte{0x04, 0x12, 0x34, 0x56, 0x78}, tag.TargetData)
	assert.Equal(t, byte(0x00), tag.SAK)
}

func TestTagType_Constants(t *testing.T) {
	t.Parallel()

	// Verify tag type constants are defined and unique
	assert.NotEmpty(t, TagTypeNTAG)
	assert.NotEmpty(t, TagTypeMIFARE)
	assert.NotEmpty(t, TagTypeFeliCa)
	assert.NotEmpty(t, TagTypeUnknown)
	assert.NotEmpty(t, TagTypeAny)

	// Verify they are all different
	types := []TagType{TagTypeNTAG, TagTypeMIFARE, TagTypeFeliCa, TagTypeUnknown, TagTypeAny}
	for i, t1 := range types {
		for j, t2 := range types {
			if i != j {
				assert.NotEqual(t, t1, t2, "Tag types should be unique: %s vs %s", t1, t2)
			}
		}
	}
}

// Manufacturer Tests

func TestGetManufacturer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected Manufacturer
		uid      []byte
	}{
		{
			name:     "NXP_UID_0x04",
			uid:      []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerNXP,
		},
		{
			name:     "STMicroelectronics_UID_0x02",
			uid:      []byte{0x02, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerST,
		},
		{
			name:     "Infineon_UID_0x05",
			uid:      []byte{0x05, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerInfineon,
		},
		{
			name:     "Texas_Instruments_UID_0x07",
			uid:      []byte{0x07, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerTI,
		},
		{
			name:     "Fudan_Microelectronics_UID_0x1D",
			uid:      []byte{0x1D, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerFudan,
		},
		{
			name:     "Unknown_UID_0x08",
			uid:      []byte{0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerUnknown,
		},
		{
			name:     "Unknown_UID_0x00",
			uid:      []byte{0x00, 0x12, 0x34, 0x56},
			expected: ManufacturerUnknown,
		},
		{
			name:     "Empty_UID",
			uid:      []byte{},
			expected: ManufacturerUnknown,
		},
		{
			name:     "Nil_UID",
			uid:      nil,
			expected: ManufacturerUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := GetManufacturer(tt.uid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsGenuineNXP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		uid      []byte
		expected bool
	}{
		{
			name:     "NXP_UID_0x04",
			uid:      []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: true,
		},
		{
			name:     "Non_NXP_UID_0x08",
			uid:      []byte{0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: false,
		},
		{
			name:     "STMicroelectronics_UID",
			uid:      []byte{0x02, 0x12, 0x34, 0x56},
			expected: false,
		},
		{
			name:     "Empty_UID",
			uid:      []byte{},
			expected: false,
		},
		{
			name:     "Nil_UID",
			uid:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsGenuineNXP(tt.uid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBaseTag_Manufacturer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected Manufacturer
		uid      []byte
	}{
		{
			name:     "NXP_Tag",
			uid:      []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerNXP,
		},
		{
			name:     "Clone_Tag",
			uid:      []byte{0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: ManufacturerUnknown,
		},
	}

	for _, tt := range tests {
		t.Run("BaseTag_"+tt.name, func(t *testing.T) {
			t.Parallel()
			tag := &BaseTag{uid: tt.uid}
			assert.Equal(t, tt.expected, tag.Manufacturer())
		})
		t.Run("DetectedTag_"+tt.name, func(t *testing.T) {
			t.Parallel()
			tag := &DetectedTag{UIDBytes: tt.uid}
			assert.Equal(t, tt.expected, tag.Manufacturer())
		})
	}
}

func TestBaseTag_IsGenuine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		uid      []byte
		expected bool
	}{
		{
			name:     "NXP_Tag_Is_Genuine",
			uid:      []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: true,
		},
		{
			name:     "ST_Tag_Is_Genuine",
			uid:      []byte{0x02, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: true,
		},
		{
			name:     "Infineon_Tag_Is_Genuine",
			uid:      []byte{0x05, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: true,
		},
		{
			name:     "Clone_Tag_Not_Genuine",
			uid:      []byte{0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: false,
		},
		{
			name:     "Empty_UID_Not_Genuine",
			uid:      []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tag := &BaseTag{uid: tt.uid}
			result := tag.IsGenuine()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectedTag_IsGenuine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		uid      []byte
		expected bool
	}{
		{
			name:     "NXP_Tag_Is_Genuine",
			uid:      []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: true,
		},
		{
			name:     "Clone_Tag_Not_Genuine",
			uid:      []byte{0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tag := &DetectedTag{UIDBytes: tt.uid}
			result := tag.IsGenuine()
			assert.Equal(t, tt.expected, result)
		})
	}
}
