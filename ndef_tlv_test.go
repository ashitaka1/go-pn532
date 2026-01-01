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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanForNDEFTLV_SimpleNDEF tests the simple case of NDEF TLV at byte 0
func TestScanForNDEFTLV_SimpleNDEF(t *testing.T) {
	t.Parallel()

	// NDEF TLV: type=0x03, length=0x10, followed by 16 bytes of payload
	data := []byte{
		0x03, 0x10, 0xD1, 0x01, 0x0C, 0x54, 0x02, 0x65, 0x6E,
		0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0xFE,
	}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	assert.Equal(t, 2, loc.Offset, "NDEF payload should start at offset 2")
	assert.Equal(t, 16, loc.Length, "NDEF length should be 16")
	assert.Equal(t, 2, loc.HeaderSize, "Header size should be 2 (short format)")
}

// TestScanForNDEFTLV_NULLPadding tests NDEF TLV after NULL TLV padding bytes
func TestScanForNDEFTLV_NULLPadding(t *testing.T) {
	t.Parallel()

	// 3 NULL TLVs (0x00) followed by NDEF TLV
	data := []byte{0x00, 0x00, 0x00, 0x03, 0x05, 0xD1, 0x01, 0x01, 0x54, 0x00, 0xFE}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	assert.Equal(t, 5, loc.Offset, "NDEF payload should start at offset 5 (after 3 NULLs + header)")
	assert.Equal(t, 5, loc.Length, "NDEF length should be 5")
	assert.Equal(t, 2, loc.HeaderSize, "Header size should be 2")
}

// TestScanForNDEFTLV_LockControlTLV tests NDEF TLV after Lock Control TLV (0x01)
// This is a regression test for clone tags that have Lock Control TLVs before NDEF
func TestScanForNDEFTLV_LockControlTLV(t *testing.T) {
	t.Parallel()

	// Lock Control TLV (0x01, length 3, value A0 0C 34) followed by NDEF TLV
	// This matches real-world data from clone tags with UID prefix 0x53
	data := []byte{
		0x01, 0x03, 0xA0, 0x0C, 0x34, 0x03, 0x20,
		0xD1, 0x01, 0x1C, 0x55, 0x04, 0x6D, 0x79, 0x77, 0x65,
		0x62, 0x73, 0x69, 0x74, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
		0x2F, 0x70, 0x61, 0x74, 0x68, 0x2F, 0x74, 0x6F, 0x2F,
		0x72, 0x65, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65, 0xFE,
	}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	// Lock Control TLV: 1 (type) + 1 (len) + 3 (value) = 5 bytes
	// NDEF TLV: starts at offset 5, header size 2, payload at offset 7
	assert.Equal(t, 7, loc.Offset, "NDEF payload should start at offset 7")
	assert.Equal(t, 32, loc.Length, "NDEF length should be 32 (0x20)")
	assert.Equal(t, 2, loc.HeaderSize, "Header size should be 2")
}

// TestScanForNDEFTLV_MemoryControlTLV tests NDEF TLV after Memory Control TLV (0x02)
func TestScanForNDEFTLV_MemoryControlTLV(t *testing.T) {
	t.Parallel()

	// Memory Control TLV (0x02, length 3, value F0 FF EE) followed by NDEF TLV
	data := []byte{0x02, 0x03, 0xF0, 0xFF, 0xEE, 0x03, 0x05, 0xD1, 0x01, 0x01, 0x54, 0x00, 0xFE}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	// Memory Control TLV: 5 bytes, NDEF header at 5, payload at 7
	assert.Equal(t, 7, loc.Offset, "NDEF payload should start at offset 7")
	assert.Equal(t, 5, loc.Length, "NDEF length should be 5")
}

// TestScanForNDEFTLV_MultipleTLVs tests NDEF TLV after multiple preceding TLVs
func TestScanForNDEFTLV_MultipleTLVs(t *testing.T) {
	t.Parallel()

	// NULL + Lock Control + NULL + Memory Control + NULL + NDEF
	data := []byte{
		0x00,                         // NULL TLV
		0x01, 0x03, 0xA0, 0x0C, 0x34, // Lock Control TLV (5 bytes)
		0x00,                         // NULL TLV
		0x02, 0x03, 0xF0, 0xFF, 0xEE, // Memory Control TLV (5 bytes)
		0x00,                               // NULL TLV
		0x03, 0x04, 0xD1, 0x01, 0x00, 0x54, // NDEF TLV
		0xFE, // Terminator
	}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	// Offset calculation: 1 + 5 + 1 + 5 + 1 + 2 (header) = 15
	assert.Equal(t, 15, loc.Offset, "NDEF payload should start at offset 15")
	assert.Equal(t, 4, loc.Length, "NDEF length should be 4")
}

// TestScanForNDEFTLV_LongFormat tests NDEF TLV with long format length (0xFF marker)
func TestScanForNDEFTLV_LongFormat(t *testing.T) {
	t.Parallel()

	// NDEF TLV with long format: 0x03, 0xFF, 0x01, 0x00 (length = 256)
	// We only include partial payload for test brevity
	data := make([]byte, 270)
	data[0] = 0x03   // NDEF TLV type
	data[1] = 0xFF   // Long format marker
	data[2] = 0x01   // Length high byte
	data[3] = 0x00   // Length low byte (256)
	data[4] = 0xD1   // Start of NDEF record
	data[5] = 0x01   // Type length
	data[6] = 0xFB   // Payload length (251)
	data[7] = 0x54   // Type = 'T'
	data[268] = 0xFE // Terminator

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	assert.Equal(t, 4, loc.Offset, "NDEF payload should start at offset 4 (long format)")
	assert.Equal(t, 256, loc.Length, "NDEF length should be 256")
	assert.Equal(t, 4, loc.HeaderSize, "Header size should be 4 (long format)")
}

// TestScanForNDEFTLV_TerminatorFirst tests error when terminator appears before NDEF
func TestScanForNDEFTLV_TerminatorFirst(t *testing.T) {
	t.Parallel()

	// Terminator TLV before any NDEF
	data := []byte{0x00, 0x00, 0xFE}

	loc, err := ScanForNDEFTLV(data)
	require.Error(t, err)
	assert.Nil(t, loc)
	assert.ErrorIs(t, err, ErrTLVNDEFNotFound)
}

// TestScanForNDEFTLV_EmptyData tests error on empty data
func TestScanForNDEFTLV_EmptyData(t *testing.T) {
	t.Parallel()

	loc, err := ScanForNDEFTLV([]byte{})
	require.Error(t, err)
	assert.Nil(t, loc)
	assert.ErrorIs(t, err, ErrTLVDataTooShort)
}

// TestScanForNDEFTLV_SingleByte tests error on single byte
func TestScanForNDEFTLV_SingleByte(t *testing.T) {
	t.Parallel()

	loc, err := ScanForNDEFTLV([]byte{0x03})
	require.Error(t, err)
	assert.Nil(t, loc)
	assert.ErrorIs(t, err, ErrTLVDataTooShort)
}

// TestScanForNDEFTLV_TruncatedLongFormat tests error on truncated long format
func TestScanForNDEFTLV_TruncatedLongFormat(t *testing.T) {
	t.Parallel()

	// Long format marker but not enough bytes for length
	data := []byte{0x03, 0xFF, 0x01}

	loc, err := ScanForNDEFTLV(data)
	require.Error(t, err)
	assert.Nil(t, loc)
	assert.ErrorIs(t, err, ErrTLVInvalidLength)
}

// TestScanForNDEFTLV_ProprietaryTLV tests skipping proprietary TLVs (0x04-0xFD)
func TestScanForNDEFTLV_ProprietaryTLV(t *testing.T) {
	t.Parallel()

	// Proprietary TLV (0x50, length 4) followed by NDEF TLV
	data := []byte{
		0x50, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x03, 0x05,
		0xD1, 0x01, 0x01, 0x54, 0x00, 0xFE,
	}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	// Proprietary TLV: 6 bytes, NDEF header at 6, payload at 8
	assert.Equal(t, 8, loc.Offset, "NDEF payload should start at offset 8")
	assert.Equal(t, 5, loc.Length, "NDEF length should be 5")
}

// TestScanForNDEFTLV_NoNDEF tests error when no NDEF TLV is found
func TestScanForNDEFTLV_NoNDEF(t *testing.T) {
	t.Parallel()

	// Only NULL TLVs, no NDEF
	data := []byte{0x00, 0x00, 0x00, 0x00}

	loc, err := ScanForNDEFTLV(data)
	require.Error(t, err)
	assert.Nil(t, loc)
	assert.ErrorIs(t, err, ErrTLVNDEFNotFound)
}

// TestScanForNDEFTLV_ZeroLengthNDEF tests NDEF TLV with zero length (empty message)
func TestScanForNDEFTLV_ZeroLengthNDEF(t *testing.T) {
	t.Parallel()

	// NDEF TLV with zero length
	data := []byte{0x03, 0x00, 0xFE}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	assert.Equal(t, 2, loc.Offset)
	assert.Equal(t, 0, loc.Length)
	assert.Equal(t, 2, loc.HeaderSize)
}

// TestExtractNDEFFromTLV tests the convenience extraction function
func TestExtractNDEFFromTLV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		errorContains string
		data          []byte
		wantPayload   []byte
		wantErr       bool
	}{
		{
			name:        "simple NDEF",
			data:        []byte{0x03, 0x04, 0xD1, 0x01, 0x00, 0x54, 0xFE},
			wantPayload: []byte{0xD1, 0x01, 0x00, 0x54},
		},
		{
			name:        "NDEF after Lock Control",
			data:        []byte{0x01, 0x03, 0xA0, 0x0C, 0x34, 0x03, 0x02, 0xD1, 0x00, 0xFE},
			wantPayload: []byte{0xD1, 0x00},
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "truncated payload",
			data:    []byte{0x03, 0x10, 0xD1, 0x01}, // Claims 16 bytes but only has 2
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			payload, err := ExtractNDEFFromTLV(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantPayload, payload)
		})
	}
}

// TestTLVDebugInfo tests the debug information output
func TestTLVDebugInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		contains []string
	}{
		{
			name:     "empty",
			data:     []byte{},
			contains: []string{"empty data"},
		},
		{
			name:     "simple NDEF",
			data:     []byte{0x03, 0x04, 0xD1, 0x01, 0x00, 0x54, 0xFE},
			contains: []string{"NDEF", "len=4", "TERMINATOR"},
		},
		{
			name:     "multiple TLVs",
			data:     []byte{0x00, 0x01, 0x03, 0xA0, 0x0C, 0x34, 0x03, 0x02, 0xD1, 0x00, 0xFE},
			contains: []string{"NULL", "LOCK_CONTROL", "NDEF", "TERMINATOR"},
		},
		{
			name:     "proprietary TLV",
			data:     []byte{0x50, 0x02, 0xAA, 0xBB, 0xFE},
			contains: []string{"PROPRIETARY", "0x50"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := TLVDebugInfo(tt.data)
			for _, want := range tt.contains {
				assert.Contains(t, result, want,
					"expected debug output to contain %q, got: %s", want, result)
			}
		})
	}
}

// TestScanForNDEFTLV_RealWorldCloneTag is a regression test using real data
// from a clone tag with UID prefix 0x53 that was previously failing
func TestScanForNDEFTLV_RealWorldCloneTag(t *testing.T) {
	t.Parallel()

	// Real-world data from a clone tag:
	// Lock Control TLV (01 03 A0 0C 34) + NDEF TLV with text record
	data := []byte{
		0x01, 0x03, 0xA0, 0x0C, 0x34, // Lock Control TLV
		0x03, 0x20, // NDEF TLV header (length 32)
		0xD1, 0x01, 0x1C, 0x54, 0x02, 0x65, 0x6E, // NDEF record header + "en" lang
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, // "This is "
		0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, // "a test m"
		0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x21, 0x21, // "essage!!"
		0xFE, // Terminator
	}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err, "should find NDEF after Lock Control TLV")
	require.NotNil(t, loc)

	assert.Equal(t, 7, loc.Offset)
	assert.Equal(t, 32, loc.Length)
	assert.Equal(t, 2, loc.HeaderSize)

	// Verify we can extract the payload
	payload, err := ExtractNDEFFromTLV(data)
	require.NoError(t, err)
	assert.Len(t, payload, 32)
	assert.Equal(t, byte(0xD1), payload[0], "first byte should be NDEF record header")
}

// TestScanForNDEFTLV_AllNULLsBeforeNDEF tests many NULL padding bytes
func TestScanForNDEFTLV_AllNULLsBeforeNDEF(t *testing.T) {
	t.Parallel()

	// 10 NULL bytes followed by NDEF
	data := make([]byte, 18)
	for i := range 10 {
		data[i] = 0x00
	}
	data[10] = 0x03 // NDEF type
	data[11] = 0x04 // Length
	data[12] = 0xD1
	data[13] = 0x01
	data[14] = 0x00
	data[15] = 0x54
	data[16] = 0xFE

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	assert.Equal(t, 12, loc.Offset, "NDEF payload should start at offset 12")
	assert.Equal(t, 4, loc.Length)
}

// TestScanForNDEFTLV_LockAndMemoryControlBothPresent tests both control TLVs
func TestScanForNDEFTLV_LockAndMemoryControlBothPresent(t *testing.T) {
	t.Parallel()

	// Lock Control + Memory Control + NDEF
	data := []byte{
		0x01, 0x03, 0x10, 0x20, 0x30, // Lock Control TLV (5 bytes)
		0x02, 0x03, 0x40, 0x50, 0x60, // Memory Control TLV (5 bytes)
		0x03, 0x04, 0xD1, 0x01, 0x00, 0x54, // NDEF TLV
		0xFE, // Terminator
	}

	loc, err := ScanForNDEFTLV(data)
	require.NoError(t, err)
	require.NotNil(t, loc)

	// Lock Control (5 bytes) + Memory Control (5 bytes) + NDEF header (2 bytes) = offset 12
	assert.Equal(t, 12, loc.Offset)
	assert.Equal(t, 4, loc.Length)
}
