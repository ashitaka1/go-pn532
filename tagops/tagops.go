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
	"context"
	"errors"
	"fmt"

	"github.com/ZaparooProject/go-pn532"
)

var (
	// ErrNoTag indicates no tag was detected
	ErrNoTag = errors.New("no tag detected")
	// ErrUnsupportedTag indicates the tag type is not supported
	ErrUnsupportedTag = errors.New("unsupported tag type")
	// ErrAuthFailed indicates all authentication attempts failed
	ErrAuthFailed = errors.New("authentication failed with all known keys")
)

// TagOperations provides unified high-level tag operations
type TagOperations struct {
	device         *pn532.Device
	tag            *pn532.DetectedTag
	ntagInstance   *pn532.NTAGTag
	mifareInstance *pn532.MIFARETag
	tagType        pn532.TagType
	totalPages     int
}

// New creates a new TagOperations instance
func New(device *pn532.Device) *TagOperations {
	return &TagOperations{
		device: device,
	}
}

// DetectTag detects and initializes a tag for operations.
// This must be called before any read/write operations.
func (t *TagOperations) DetectTag(ctx context.Context) error {
	// Detect tag
	tag, err := t.device.DetectTag(ctx)
	if err != nil {
		return fmt.Errorf("failed to detect tag: %w", err)
	}
	if tag == nil {
		return ErrNoTag
	}

	t.tag = tag

	// Determine tag type and initialize appropriate handler
	return t.detectAndInitializeTag(ctx)
}

// InitFromDetectedTag initializes operations from an already-detected tag.
// Use this when the tag was detected via polling and you want to avoid
// re-detection which can put the tag in a different state.
func (t *TagOperations) InitFromDetectedTag(ctx context.Context, tag *pn532.DetectedTag) error {
	if tag == nil {
		return ErrNoTag
	}

	t.tag = tag

	// Determine tag type and initialize appropriate handler
	return t.detectAndInitializeTag(ctx)
}

// GetTagType returns the detected tag type
func (t *TagOperations) GetTagType() pn532.TagType {
	return t.tagType
}

// TagType returns the detected tag type (alias for GetTagType)
func (t *TagOperations) TagType() pn532.TagType {
	return t.tagType
}

// GetUID returns the tag's UID
func (t *TagOperations) GetUID() []byte {
	if t.tag == nil {
		return nil
	}
	return t.tag.UIDBytes
}

// detectAndInitializeTag determines the tag type and sets up the appropriate handler
func (t *TagOperations) detectAndInitializeTag(ctx context.Context) error {
	if t.tag == nil {
		return ErrNoTag
	}

	// If tag type is already known from detection, try that first then fallback.
	// Each case tries the expected type, then the alternative - no redundant attempts.
	switch t.tag.Type {
	case pn532.TagTypeMIFARE:
		if t.tryInitMIFARE(ctx) {
			return nil
		}
		if t.tryInitNTAG(ctx) {
			return nil
		}
		return ErrUnsupportedTag

	case pn532.TagTypeNTAG:
		if t.tryInitNTAG(ctx) {
			return nil
		}
		if t.tryInitMIFARE(ctx) {
			return nil
		}
		return ErrUnsupportedTag

	case pn532.TagTypeFeliCa, pn532.TagTypeUnknown, pn532.TagTypeAny:
		// Unknown or other types - try both in order
		if t.tryInitNTAG(ctx) {
			return nil
		}
		if t.tryInitMIFARE(ctx) {
			return nil
		}
		return ErrUnsupportedTag
	}

	// Unreachable - all TagType values handled above
	return ErrUnsupportedTag
}

// tryInitNTAG attempts to initialize as an NTAG tag. Returns true on success.
func (t *TagOperations) tryInitNTAG(ctx context.Context) bool {
	ntag := pn532.NewNTAGTag(t.device, t.tag.UIDBytes, t.tag.SAK)
	if err := ntag.DetectType(ctx); err != nil {
		return false
	}
	t.tagType = pn532.TagTypeNTAG
	t.ntagInstance = ntag
	t.totalPages = int(ntag.GetTotalPages())
	return true
}

// tryInitMIFARE attempts to initialize as a MIFARE tag. Returns true on success.
func (t *TagOperations) tryInitMIFARE(ctx context.Context) bool {
	mifare := pn532.NewMIFARETag(t.device, t.tag.UIDBytes, t.tag.SAK)
	if !t.tryMIFAREAuth(ctx, mifare) {
		return false
	}
	t.tagType = pn532.TagTypeMIFARE
	t.mifareInstance = mifare
	return true
}

// tryMIFAREAuth attempts to read a block to verify MIFARE functionality
func (*TagOperations) tryMIFAREAuth(ctx context.Context, mifare *pn532.MIFARETag) bool {
	// Try to read block 4 (first block of sector 1) using automatic authentication
	// This will use the built-in NDEF key authentication
	_, err := mifare.ReadBlockAuto(ctx, 4)
	return err == nil
}
