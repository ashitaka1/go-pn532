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
	"encoding/hex"
	"testing"
	"time"
)

func TestBaseTagUID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		expectedHex string
		uid         []byte
	}{
		{
			name:        "empty UID",
			uid:         []byte{},
			expectedHex: "",
		},
		{
			name:        "4-byte UID",
			uid:         []byte{0x12, 0x34, 0x56, 0x78},
			expectedHex: "12345678",
		},
		{
			name:        "7-byte UID (NTAG)",
			uid:         []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			expectedHex: "04123456789abc",
		},
		{
			name:        "single byte UID",
			uid:         []byte{0xFF},
			expectedHex: "ff",
		},
		{
			name:        "zero UID",
			uid:         []byte{0x00, 0x00, 0x00, 0x00},
			expectedHex: "00000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tag := &BaseTag{
				uid:     tt.uid,
				tagType: TagTypeUnknown,
			}

			// Test hex string representation
			gotHex := tag.UID()
			if gotHex != tt.expectedHex {
				t.Errorf("UID() = %q, want %q", gotHex, tt.expectedHex)
			}

			// Test byte representation
			gotBytes := tag.UIDBytes()
			if !equalBytes(gotBytes, tt.uid) {
				t.Errorf("UIDBytes() = %v, want %v", gotBytes, tt.uid)
			}
		})
	}
}

func TestTagTypeConstants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tagType  TagType
		expected string
	}{
		{"NTAG", TagTypeNTAG, "NTAG"},
		{"MIFARE", TagTypeMIFARE, "MIFARE"},
		{"FeliCa", TagTypeFeliCa, "FELICA"},
		{"Unknown", TagTypeUnknown, "UNKNOWN"},
		{"Any", TagTypeAny, "ANY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.tagType) != tt.expected {
				t.Errorf("TagType %s = %q, want %q", tt.name, string(tt.tagType), tt.expected)
			}
		})
	}
}

func TestMIFARE4KDetection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		sak      byte
		expected bool
	}{
		{
			name:     "MIFARE Classic 4K",
			sak:      0x18,
			expected: true,
		},
		{
			name:     "MIFARE Classic 1K",
			sak:      0x08,
			expected: false,
		},
		{
			name:     "NTAG SAK",
			sak:      0x00,
			expected: false,
		},
		{
			name:     "Unknown SAK",
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

			got := tag.IsMIFARE4K()
			if got != tt.expected {
				t.Errorf("IsMIFARE4K() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Note: tagops-specific tests moved to avoid import cycle

func TestDetectedTagStructure(t *testing.T) {
	t.Parallel()
	now := time.Now()
	uid := []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	uidStr := "04123456789abc"
	atq := []byte{0x00, 0x04}
	targetData := []byte{0x01, 0x02, 0x03, 0x04}

	tag := &DetectedTag{
		DetectedAt: now,
		UID:        uidStr,
		Type:       TagTypeNTAG,
		UIDBytes:   uid,
		ATQ:        atq,
		TargetData: targetData,
		SAK:        0x00,
	}

	// Test all fields are properly set
	if !tag.DetectedAt.Equal(now) {
		t.Errorf("DetectedAt = %v, want %v", tag.DetectedAt, now)
	}
	if tag.UID != uidStr {
		t.Errorf("UID = %q, want %q", tag.UID, uidStr)
	}
	if tag.Type != TagTypeNTAG {
		t.Errorf("Type = %v, want %v", tag.Type, TagTypeNTAG)
	}
	if !equalBytes(tag.UIDBytes, uid) {
		t.Errorf("UIDBytes = %v, want %v", tag.UIDBytes, uid)
	}
	if !equalBytes(tag.ATQ, atq) {
		t.Errorf("ATQ = %v, want %v", tag.ATQ, atq)
	}
	if !equalBytes(tag.TargetData, targetData) {
		t.Errorf("TargetData = %v, want %v", tag.TargetData, targetData)
	}
	if tag.SAK != 0x00 {
		t.Errorf("SAK = 0x%02X, want 0x00", tag.SAK)
	}
}

func TestUIDHexValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		hexStr  string
		wantErr bool
	}{
		{
			name:    "valid hex string",
			hexStr:  "04123456789abc",
			wantErr: false,
		},
		{
			name:    "empty hex string",
			hexStr:  "",
			wantErr: false,
		},
		{
			name:    "invalid hex characters",
			hexStr:  "04123456789xyz",
			wantErr: true,
		},
		{
			name:    "odd length hex string",
			hexStr:  "0412345",
			wantErr: true,
		},
		{
			name:    "uppercase hex",
			hexStr:  "04123456789ABC",
			wantErr: false,
		},
		{
			name:    "mixed case hex",
			hexStr:  "04123456789AbC",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := hex.DecodeString(tt.hexStr)
			gotErr := err != nil
			if gotErr != tt.wantErr {
				t.Errorf("hex.DecodeString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper function to compare byte slices
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
