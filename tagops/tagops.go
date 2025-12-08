// go-pn532
// Copyright (c) 2025 The Zaparoo Project Contributors.
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This file is part of go-pn532.
//
// go-pn532 is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// go-pn532 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with go-pn532; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

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

	// Try NTAG detection first
	ntag := pn532.NewNTAGTag(t.device, t.tag.UIDBytes, t.tag.SAK)
	if err := ntag.DetectType(ctx); err == nil {
		t.tagType = pn532.TagTypeNTAG
		t.ntagInstance = ntag
		t.totalPages = int(ntag.GetTotalPages())
		return nil
	}

	// Try MIFARE detection
	mifare := pn532.NewMIFARETag(t.device, t.tag.UIDBytes, t.tag.SAK)
	// Try to authenticate with common keys to verify it's MIFARE
	if t.tryMIFAREAuth(ctx, mifare) {
		t.tagType = pn532.TagTypeMIFARE
		t.mifareInstance = mifare
		return nil
	}

	return ErrUnsupportedTag
}

// tryMIFAREAuth attempts to read a block to verify MIFARE functionality
func (*TagOperations) tryMIFAREAuth(ctx context.Context, mifare *pn532.MIFARETag) bool {
	// Try to read block 4 (first block of sector 1) using automatic authentication
	// This will use the built-in NDEF key authentication
	_, err := mifare.ReadBlockAuto(ctx, 4)
	return err == nil
}
