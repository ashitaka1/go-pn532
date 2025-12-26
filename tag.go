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

package pn532

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// TagType represents the type of NFC tag
type TagType string

const (
	// TagTypeNTAG represents NTAG tag types.
	TagTypeNTAG TagType = "NTAG"
	// TagTypeMIFARE represents MIFARE tag types.
	TagTypeMIFARE TagType = "MIFARE"
	// TagTypeFeliCa represents FeliCa tag types.
	TagTypeFeliCa TagType = "FELICA"
	// TagTypeUnknown represents unknown tag types.
	TagTypeUnknown TagType = "UNKNOWN"
	// TagTypeAny represents any tag type (for detection)
	TagTypeAny TagType = "ANY"
)

// Manufacturer represents the chip manufacturer identified from the UID.
// The first byte of a 7-byte UID contains the manufacturer code per ISO/IEC 7816-6.
type Manufacturer string

const (
	// ManufacturerNXP is NXP Semiconductors (0x04) - maker of genuine NTAG chips.
	ManufacturerNXP Manufacturer = "NXP"
	// ManufacturerST is STMicroelectronics (0x02) - maker of ST25TN chips.
	ManufacturerST Manufacturer = "STMicroelectronics"
	// ManufacturerInfineon is Infineon Technologies (0x05) - maker of MIFARE-compatible chips.
	ManufacturerInfineon Manufacturer = "Infineon"
	// ManufacturerTI is Texas Instruments (0x07).
	ManufacturerTI Manufacturer = "Texas Instruments"
	// ManufacturerUnknown indicates an unrecognized manufacturer code.
	// This typically indicates a clone or counterfeit chip.
	ManufacturerUnknown Manufacturer = "Unknown"
)

// GetManufacturer returns the chip manufacturer based on the UID's first byte.
// For 7-byte UIDs (NTAG, ST25TN, etc.), the first byte is the manufacturer code.
// For 4-byte UIDs (MIFARE Classic), manufacturer detection is less reliable.
func GetManufacturer(uid []byte) Manufacturer {
	if len(uid) == 0 {
		return ManufacturerUnknown
	}

	switch uid[0] {
	case 0x04:
		return ManufacturerNXP
	case 0x02:
		return ManufacturerST
	case 0x05:
		return ManufacturerInfineon
	case 0x07:
		return ManufacturerTI
	default:
		return ManufacturerUnknown
	}
}

// IsGenuineNXP returns true if the UID indicates a genuine NXP chip.
// Clone tags typically have non-0x04 first bytes.
func IsGenuineNXP(uid []byte) bool {
	return len(uid) > 0 && uid[0] == 0x04
}

// Tag represents an NFC tag interface
type Tag interface {
	// Type returns the tag type
	Type() TagType

	// UID returns the tag's unique identifier as hex string
	UID() string

	// UIDBytes returns the tag's unique identifier as bytes
	UIDBytes() []byte

	// ReadBlock reads a block of data from the tag
	ReadBlock(ctx context.Context, block uint8) ([]byte, error)

	// WriteBlock writes a block of data to the tag
	WriteBlock(ctx context.Context, block uint8, data []byte) error

	// ReadNDEF reads NDEF data from the tag
	ReadNDEF(ctx context.Context) (*NDEFMessage, error)

	// WriteNDEF writes NDEF data to the tag
	WriteNDEF(ctx context.Context, message *NDEFMessage) error

	// ReadText reads the first text record from the tag's NDEF data
	ReadText(ctx context.Context) (string, error)

	// WriteText writes a simple text record to the tag
	WriteText(ctx context.Context, text string) error

	// DebugInfo returns detailed debug information about the tag
	DebugInfo() string

	// Summary returns a brief summary of the tag
	Summary() string
}

// BaseTag provides common tag functionality
type BaseTag struct {
	device  *Device
	tagType TagType
	uid     []byte
	sak     byte // SAK (Select Acknowledge) response for card type detection
}

// Type returns the tag type
func (t *BaseTag) Type() TagType {
	return t.tagType
}

// UID returns the tag's unique identifier as hex string
func (t *BaseTag) UID() string {
	return hex.EncodeToString(t.uid)
}

// UIDBytes returns the tag's unique identifier as bytes
func (t *BaseTag) UIDBytes() []byte {
	return t.uid
}

// IsMIFARE4K returns true if this is a MIFARE Classic 4K card
func (t *BaseTag) IsMIFARE4K() bool {
	// MIFARE Classic 4K cards have SAK = 0x18
	// MIFARE Classic 1K cards have SAK = 0x08
	return t.sak == 0x18
}

// Manufacturer returns the chip manufacturer identified from the UID.
func (t *BaseTag) Manufacturer() Manufacturer {
	return GetManufacturer(t.uid)
}

// IsGenuine returns true if the chip appears to be from a known manufacturer.
// Returns false for unknown/clone chips.
func (t *BaseTag) IsGenuine() bool {
	return t.Manufacturer() != ManufacturerUnknown
}

// ReadBlock provides a default implementation that returns an error
// Specific tag types should override this method
func (*BaseTag) ReadBlock(_ context.Context, _ uint8) ([]byte, error) {
	return nil, ErrNotImplemented
}

// WriteBlock provides a default implementation that returns an error
// Specific tag types should override this method
func (*BaseTag) WriteBlock(_ context.Context, _ uint8, _ []byte) error {
	return ErrNotImplemented
}

// ReadNDEF provides a default implementation that returns an error
// Specific tag types should override this method
func (*BaseTag) ReadNDEF(_ context.Context) (*NDEFMessage, error) {
	return nil, ErrNotImplemented
}

// WriteNDEF provides a default implementation that returns an error
// Specific tag types should override this method
func (*BaseTag) WriteNDEF(_ context.Context, _ *NDEFMessage) error {
	return ErrNotImplemented
}

// ReadText reads the first text record from the tag's NDEF data
// This is a convenience method that handles the common case of reading simple text
func (t *BaseTag) ReadText(ctx context.Context) (string, error) {
	ndef, err := t.ReadNDEF(ctx)
	if err != nil {
		return "", err
	}

	if ndef == nil || len(ndef.Records) == 0 {
		return "", ErrNoTagDetected
	}

	for _, record := range ndef.Records {
		if record.Type == NDEFTypeText && record.Text != "" {
			return record.Text, nil
		}
	}

	return "", errors.New("no text record found")
}

// WriteText writes a simple text record to the tag
// This is a convenience method that handles the common case of writing simple text
func (t *BaseTag) WriteText(ctx context.Context, text string) error {
	message := &NDEFMessage{
		Records: []NDEFRecord{
			{
				Type: NDEFTypeText,
				Text: text,
			},
		},
	}

	return t.WriteNDEF(ctx, message)
}

// Summary returns a brief summary of the tag
func (t *BaseTag) Summary() string {
	return fmt.Sprintf("Tag: %s, UID: %s", t.tagType, t.UID())
}

// DebugInfo returns detailed debug information about the tag
func (t *BaseTag) DebugInfo() string {
	info := "=== Tag Debug Info ===\n"
	info += fmt.Sprintf("Type: %v\n", t.tagType)
	info += fmt.Sprintf("UID: %s\n", t.UID())
	info += fmt.Sprintf("UID Bytes: %X\n", t.uid)
	info += fmt.Sprintf("SAK: %02X\n", t.sak)
	info += "NDEF: not supported for base tag type\n"

	return info
}

// DebugInfoWithNDEF returns detailed debug information about the tag with NDEF support
func (t *BaseTag) DebugInfoWithNDEF(ndefReader interface {
	ReadNDEF(context.Context) (*NDEFMessage, error)
},
) string {
	info := "=== Tag Debug Info ===\n"
	info += fmt.Sprintf("Type: %v\n", t.tagType)
	info += fmt.Sprintf("UID: %s\n", t.UID())
	info += fmt.Sprintf("UID Bytes: %X\n", t.uid)
	info += fmt.Sprintf("SAK: %02X\n", t.sak)

	// Try to read NDEF for additional info
	if ndef, err := ndefReader.ReadNDEF(context.Background()); err == nil && ndef != nil {
		info += fmt.Sprintf("NDEF Records: %d\n", len(ndef.Records))
		for i, record := range ndef.Records {
			info += fmt.Sprintf("  Record %d: Type=%s", i+1, record.Type)
			if record.Text != "" {
				info += fmt.Sprintf(", Text='%s'", record.Text)
			}
			info += fmt.Sprintf(", Payload=%d bytes\n", len(record.Payload))
		}
	} else {
		info += fmt.Sprintf("NDEF: %v\n", err)
	}

	return info
}

// DetectedTag represents a tag that was detected by the reader
type DetectedTag struct {
	DetectedAt time.Time // When the tag was detected
	UID        string    // UID as hex string
	Type       TagType   // Tag type
	UIDBytes   []byte    // UID as raw bytes
	ATQ        []byte    // Answer to Request bytes
	TargetData []byte    // Full target response data (needed for FeliCa)
	SAK        byte      // Select Acknowledge byte
}

// Manufacturer returns the chip manufacturer identified from the UID.
func (t *DetectedTag) Manufacturer() Manufacturer {
	return GetManufacturer(t.UIDBytes)
}

// IsGenuine returns true if the chip appears to be from a known manufacturer.
// Returns false for unknown/clone chips.
func (t *DetectedTag) IsGenuine() bool {
	return t.Manufacturer() != ManufacturerUnknown
}
