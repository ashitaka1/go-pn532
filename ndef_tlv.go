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
	"encoding/binary"
	"errors"
	"fmt"
)

// TLV type constants per NFC Forum Type 2 Tag specification
const (
	TLVTypeNull          = 0x00 // NULL TLV - padding byte, no length field
	TLVTypeLockControl   = 0x01 // Lock Control TLV - defines lock bit positions
	TLVTypeMemoryControl = 0x02 // Memory Control TLV - defines reserved memory
	TLVTypeNDEF          = 0x03 // NDEF Message TLV - contains NDEF data
	TLVTypeTerminator    = 0xFE // Terminator TLV - end of data area, no length field
)

// TLV parsing errors
var (
	ErrTLVDataTooShort    = errors.New("TLV data too short")
	ErrTLVInvalidLength   = errors.New("TLV invalid length format")
	ErrTLVNDEFNotFound    = errors.New("NDEF TLV not found")
	ErrTLVTerminatorFirst = errors.New("terminator TLV before NDEF")
)

// NDEFLocation represents the location and size of NDEF data within TLV structure
type NDEFLocation struct {
	// Offset is the byte offset where NDEF payload data starts (after TLV header)
	Offset int
	// Length is the length of the NDEF payload in bytes
	Length int
	// HeaderSize is the size of the TLV header (2 for short format, 4 for long format)
	HeaderSize int
}

// ScanForNDEFTLV scans through TLV blocks to find the NDEF Message TLV (0x03).
// It properly skips NULL (0x00), Lock Control (0x01), Memory Control (0x02),
// and other proprietary TLVs per NFC Forum Type 2 Tag specification.
//
// Returns the location of the NDEF data or an error if not found.
func ScanForNDEFTLV(data []byte) (*NDEFLocation, error) {
	if len(data) < 2 {
		return nil, ErrTLVDataTooShort
	}

	offset := 0
	for offset < len(data) {
		loc, newOffset, err := processTLVAtOffset(data, offset)
		if err != nil {
			return nil, err
		}
		if loc != nil {
			return loc, nil
		}
		if newOffset < 0 {
			// Terminator found
			return nil, ErrTLVNDEFNotFound
		}
		offset = newOffset
	}

	return nil, ErrTLVNDEFNotFound
}

// processTLVAtOffset processes a single TLV at the given offset.
// Returns:
//   - (loc, _, nil) if NDEF found
//   - (nil, newOffset, nil) to continue scanning
//   - (nil, -1, nil) if terminator found
//   - (nil, _, err) on error
func processTLVAtOffset(data []byte, offset int) (*NDEFLocation, int, error) {
	tlvType := data[offset]

	switch tlvType {
	case TLVTypeNull:
		return nil, offset + 1, nil

	case TLVTypeTerminator:
		return nil, -1, nil

	case TLVTypeNDEF:
		loc, err := parseNDEFTLVHeader(data, offset)
		if err != nil {
			return nil, 0, err
		}
		return loc, 0, nil

	case TLVTypeLockControl, TLVTypeMemoryControl:
		newOffset, err := skipTLVBlock(data, offset)
		if err != nil {
			return nil, 0, err
		}
		return nil, newOffset, nil

	default:
		return handleUnknownTLV(data, offset, tlvType)
	}
}

// handleUnknownTLV handles proprietary and unknown TLV types.
func handleUnknownTLV(data []byte, offset int, tlvType byte) (*NDEFLocation, int, error) {
	if tlvType >= 0x04 && tlvType <= 0xFD {
		newOffset, err := skipTLVBlock(data, offset)
		if err != nil {
			return nil, 0, err
		}
		return nil, newOffset, nil
	}
	// Unknown type - skip single byte
	return nil, offset + 1, nil
}

// parseNDEFTLVHeader parses the NDEF TLV header at the given offset
// and returns the location of the NDEF payload.
func parseNDEFTLVHeader(data []byte, offset int) (*NDEFLocation, error) {
	if offset+1 >= len(data) {
		return nil, ErrTLVDataTooShort
	}

	lengthByte := data[offset+1]

	if lengthByte != 0xFF {
		// Short format: 1-byte length (0x00-0xFE)
		return &NDEFLocation{
			Offset:     offset + 2,
			Length:     int(lengthByte),
			HeaderSize: 2,
		}, nil
	}

	// Long format: 0xFF followed by 2-byte big-endian length
	if offset+3 >= len(data) {
		return nil, fmt.Errorf("%w: incomplete long length at offset %d", ErrTLVInvalidLength, offset)
	}

	length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	return &NDEFLocation{
		Offset:     offset + 4,
		Length:     length,
		HeaderSize: 4,
	}, nil
}

// skipTLVBlock skips over a TLV block (with length field) and returns the new offset.
// Used for Lock Control, Memory Control, and proprietary TLVs.
func skipTLVBlock(data []byte, offset int) (int, error) {
	if offset+1 >= len(data) {
		return 0, ErrTLVDataTooShort
	}

	lengthByte := data[offset+1]

	if lengthByte != 0xFF {
		// Short format
		return offset + 2 + int(lengthByte), nil
	}

	// Long format
	if offset+3 >= len(data) {
		return 0, fmt.Errorf("%w: incomplete long length at offset %d", ErrTLVInvalidLength, offset)
	}

	length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	return offset + 4 + length, nil
}

// ExtractNDEFFromTLV extracts the NDEF payload from TLV-encoded data.
// This is a convenience function that combines ScanForNDEFTLV with payload extraction.
func ExtractNDEFFromTLV(data []byte) ([]byte, error) {
	loc, err := ScanForNDEFTLV(data)
	if err != nil {
		return nil, err
	}

	// Validate bounds
	if loc.Offset+loc.Length > len(data) {
		return nil, fmt.Errorf("%w: NDEF length %d exceeds data size %d",
			ErrTLVInvalidLength, loc.Length, len(data)-loc.Offset)
	}

	return data[loc.Offset : loc.Offset+loc.Length], nil
}

// TLVDebugInfo returns a human-readable description of TLV blocks in the data.
// Useful for debugging tag contents.
func TLVDebugInfo(data []byte) string {
	if len(data) == 0 {
		return "empty data"
	}

	var result string
	offset := 0

	for offset < len(data) {
		info, newOffset, done := formatTLVAtOffset(data, offset)
		result += info
		if done {
			return result
		}
		offset = newOffset
	}

	return result
}

// formatTLVAtOffset formats a single TLV entry for debug output.
// Returns the formatted string, new offset, and whether to stop processing.
func formatTLVAtOffset(data []byte, offset int) (info string, newOffset int, done bool) {
	tlvType := data[offset]

	switch tlvType {
	case TLVTypeNull:
		return fmt.Sprintf("[%d] NULL\n", offset), offset + 1, false

	case TLVTypeTerminator:
		return fmt.Sprintf("[%d] TERMINATOR\n", offset), 0, true

	case TLVTypeNDEF:
		return formatNDEFTLV(data, offset)

	case TLVTypeLockControl:
		return formatControlTLV(data, offset, "LOCK_CONTROL")

	case TLVTypeMemoryControl:
		return formatControlTLV(data, offset, "MEMORY_CONTROL")

	default:
		return formatProprietaryOrUnknown(data, offset, tlvType)
	}
}

// formatNDEFTLV formats an NDEF TLV for debug output.
func formatNDEFTLV(data []byte, offset int) (info string, newOffset int, done bool) {
	loc, err := parseNDEFTLVHeader(data, offset)
	if err != nil {
		return fmt.Sprintf("[%d] NDEF (parse error: %v)\n", offset, err), 0, true
	}
	return fmt.Sprintf("[%d] NDEF len=%d headerSize=%d\n", offset, loc.Length, loc.HeaderSize),
		loc.Offset + loc.Length, false
}

// formatControlTLV formats a Lock/Memory Control TLV for debug output.
func formatControlTLV(data []byte, offset int, name string) (info string, nextOffset int, done bool) {
	nextOffset, err := skipTLVBlock(data, offset)
	if err != nil {
		return fmt.Sprintf("[%d] %s (parse error: %v)\n", offset, name, err), 0, true
	}
	length := nextOffset - offset - 2
	return fmt.Sprintf("[%d] %s len=%d\n", offset, name, length), nextOffset, false
}

// formatProprietaryOrUnknown formats a proprietary or unknown TLV for debug output.
func formatProprietaryOrUnknown(data []byte, offset int, tlvType byte) (info string, nextOffset int, done bool) {
	if tlvType >= 0x04 && tlvType <= 0xFD {
		var err error
		nextOffset, err = skipTLVBlock(data, offset)
		if err != nil {
			return fmt.Sprintf("[%d] PROPRIETARY(0x%02X) (parse error: %v)\n", offset, tlvType, err), 0, true
		}
		length := nextOffset - offset - 2
		return fmt.Sprintf("[%d] PROPRIETARY(0x%02X) len=%d\n", offset, tlvType, length), nextOffset, false
	}
	return fmt.Sprintf("[%d] UNKNOWN(0x%02X)\n", offset, tlvType), offset + 1, false
}
