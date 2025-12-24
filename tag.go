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

// Tag represents an NFC tag interface
type Tag interface {
	// Type returns the tag type
	Type() TagType

	// UID returns the tag's unique identifier as hex string
	UID() string

	// UIDBytes returns the tag's unique identifier as bytes
	UIDBytes() []byte

	// TargetNumber returns the PN532 target number assigned during detection.
	// This is used for InSelect when multiple tags are in the field.
	TargetNumber() byte

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
	device       *Device
	tagType      TagType
	uid          []byte
	sak          byte // SAK (Select Acknowledge) response for card type detection
	targetNumber byte // PN532 target number assigned during detection (for InSelect)
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

// TargetNumber returns the PN532 target number assigned during detection.
// This is used for InSelect when multiple tags are in the field.
func (t *BaseTag) TargetNumber() byte {
	return t.targetNumber
}

// IsMIFARE4K returns true if this is a MIFARE Classic 4K card
func (t *BaseTag) IsMIFARE4K() bool {
	// MIFARE Classic 4K cards have SAK = 0x18
	// MIFARE Classic 1K cards have SAK = 0x08
	return t.sak == 0x18
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
// Field ordering optimized for memory alignment to reduce struct size from 120 to 112 bytes
type DetectedTag struct {
	// 8-byte aligned fields first (largest to smallest)
	DetectedAt time.Time // 24 bytes (time.Time contains wall, ext, loc)
	UID        string    // 16 bytes (string header: pointer + length)
	Type       TagType   // 16 bytes (string header: pointer + length)
	UIDBytes   []byte    // 24 bytes (slice header: pointer + len + cap)
	ATQ        []byte    // 24 bytes (slice header: pointer + len + cap)
	TargetData []byte    // 24 bytes (slice header: pointer + len + cap) - Full target response data (needed for FeliCa)
	// 1-byte fields grouped together to minimize padding
	SAK            byte // 1 byte
	TargetNumber   byte // 1 byte
	FromInAutoPoll bool // 1 byte - indicates this tag was detected via InAutoPoll (skip InSelect)
	// 5 bytes padding to align to 8-byte boundary
	// Total: 112 bytes (previously 120 bytes, saved 8 bytes)
}
