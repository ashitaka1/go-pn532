// Copyright 2025 The Zaparoo Project Contributors.
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

package tagops

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ZaparooProject/go-pn532"
)

const (
	unknownTagName    = "Unknown"
	ntagTypeName      = "NTAG"
	mifareClassicName = "MIFARE Classic"
)

// TagInfo contains detailed information about a detected tag
type TagInfo struct {
	TypeName    string
	NTAGType    string
	MIFAREType  string
	Type        pn532.TagType
	UID         []byte
	TotalPages  int
	UserMemory  int
	Sectors     int
	TotalMemory int
}

// GetTagInfo returns detailed information about the currently detected tag
func (t *TagOperations) GetTagInfo() (*TagInfo, error) {
	if t.tag == nil {
		return nil, ErrNoTag
	}

	info := &TagInfo{
		Type: t.tagType,
		UID:  t.tag.UIDBytes,
	}

	switch t.tagType {
	case pn532.TagTypeNTAG:
		info.TypeName = ntagTypeName
		info.TotalPages = t.totalPages

		// Determine specific NTAG type and NDEF-usable memory based on total pages
		// User memory excludes: first 4 pages (UID/CC) and last 5 pages (config/password)
		switch t.totalPages {
		case 45:
			info.NTAGType = "NTAG213"
			info.UserMemory = 144 // 36 pages * 4 bytes
		case 135:
			info.NTAGType = "NTAG215"
			info.UserMemory = 504 // 126 pages * 4 bytes
		case 231:
			info.NTAGType = "NTAG216"
			info.UserMemory = 888 // 222 pages * 4 bytes
		default:
			info.NTAGType = fmt.Sprintf("NTAG (unknown, %d pages)", t.totalPages)
			info.UserMemory = (t.totalPages - 9) * 4 // Conservative: exclude 4 header + 5 config pages
		}

	case pn532.TagTypeMIFARE:
		info.TypeName = mifareClassicName
		// Try to determine if it's 1K or 4K
		// This is a simplified check - real detection would need SAK analysis
		if len(t.tag.UIDBytes) == 4 {
			info.MIFAREType = "MIFARE Classic 1K"
			info.Sectors = 16
			info.TotalMemory = 1024
			// NDEF usable: sectors 1-15, 3 data blocks each, 16 bytes per block
			// = 15 sectors × 3 blocks × 16 bytes = 720 bytes
			info.UserMemory = 720
		} else {
			// Could be 4K, but need more checks
			info.MIFAREType = "MIFARE Classic (unknown size)"
			info.Sectors = 16 // Default to 1K
			info.TotalMemory = 1024
			info.UserMemory = 720
		}

	case pn532.TagTypeUnknown, pn532.TagTypeFeliCa, pn532.TagTypeAny:
		info.TypeName = unknownTagName
	}

	return info, nil
}

// TagTypeDisplayName returns a human-readable display name for a tag type
// This provides more descriptive names than the raw pn532.TagType string values
func TagTypeDisplayName(t pn532.TagType) string {
	switch t {
	case pn532.TagTypeNTAG:
		return ntagTypeName
	case pn532.TagTypeMIFARE:
		return mifareClassicName
	case pn532.TagTypeUnknown, pn532.TagTypeFeliCa, pn532.TagTypeAny:
		return unknownTagName
	}
	return unknownTagName
}

// DetectTagTypeFromUID attempts to determine tag type from UID characteristics
// This is a helper function that can be used before full tag initialization
func DetectTagTypeFromUID(uid []byte) pn532.TagType {
	// This is a simplified detection based on UID patterns
	// Real detection should use SAK and ATQA values

	if len(uid) == 7 {
		// 7-byte UID often indicates NTAG
		if uid[0] == 0x04 {
			return pn532.TagTypeNTAG
		}
	} else if len(uid) == 4 {
		// 4-byte UID often indicates MIFARE Classic
		return pn532.TagTypeMIFARE
	}

	return pn532.TagTypeUnknown
}

// IsNDEFCapable returns whether the tag supports NDEF
func (t *TagOperations) IsNDEFCapable(ctx context.Context) bool {
	switch t.tagType {
	case pn532.TagTypeNTAG:
		return true // All NTAG variants support NDEF
	case pn532.TagTypeMIFARE:
		// MIFARE Classic can support NDEF if formatted properly
		// Try to read block 4 (sector 1) to test NDEF capability
		_, err := t.mifareInstance.ReadBlockAuto(ctx, 4)
		return err == nil
	case pn532.TagTypeUnknown, pn532.TagTypeFeliCa, pn532.TagTypeAny:
		return false
	}
	return false
}

// CompareUID compares two UIDs for equality
func CompareUID(uid1, uid2 []byte) bool {
	return bytes.Equal(uid1, uid2)
}
