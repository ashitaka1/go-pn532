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

// WriteBlocks writes data to the tag starting at the specified block.
// For NTAG tags, it writes directly.
// For MIFARE tags, it handles authentication transparently.
// The data will be written in chunks appropriate to the tag type.
func (t *TagOperations) WriteBlocks(ctx context.Context, startBlock byte, data []byte) error {
	if t.tag == nil {
		return ErrNoTag
	}

	switch t.tagType {
	case pn532.TagTypeNTAG:
		return t.writeNTAGBlocks(ctx, startBlock, data)
	case pn532.TagTypeMIFARE:
		return t.writeMIFAREBlocks(ctx, startBlock, data)
	case pn532.TagTypeUnknown, pn532.TagTypeFeliCa, pn532.TagTypeAny:
		return ErrUnsupportedTag
	}
	return ErrUnsupportedTag
}

// WriteNDEF writes an NDEF message to the tag
func (t *TagOperations) WriteNDEF(_ context.Context, msg *pn532.NDEFMessage) error {
	if t.tag == nil {
		return ErrNoTag
	}

	switch t.tagType {
	case pn532.TagTypeNTAG:
		if err := t.ntagInstance.WriteNDEF(msg); err != nil {
			return fmt.Errorf("failed to write NDEF to NTAG: %w", err)
		}
		return nil
	case pn532.TagTypeMIFARE:
		if err := t.mifareInstance.WriteNDEF(msg); err != nil {
			return fmt.Errorf("failed to write NDEF to MIFARE: %w", err)
		}
		return nil
	case pn532.TagTypeUnknown, pn532.TagTypeFeliCa, pn532.TagTypeAny:
		return ErrUnsupportedTag
	}
	return ErrUnsupportedTag
}

// writeNTAGBlocks writes blocks to NTAG
func (t *TagOperations) writeNTAGBlocks(_ context.Context, startBlock byte, data []byte) error {
	// Convert block to page
	startPage := startBlock

	// Validate we're not writing to restricted pages
	if startPage < 4 {
		return errors.New("cannot write to restricted pages (0-3)")
	}

	// Calculate how many pages we need to write
	numPages := (len(data) + 3) / 4 // Round up to nearest page

	// Validate we don't exceed tag capacity
	if int(startPage)+numPages > t.totalPages {
		return errors.New("write would exceed tag capacity")
	}

	// Write page by page (NTAG doesn't support multi-page write)
	for i := range numPages {
		page := startPage + byte(i)

		// Get 4 bytes for this page (pad with zeros if necessary)
		pageData := make([]byte, 4)
		dataStart := i * 4
		dataEnd := dataStart + 4
		if dataEnd > len(data) {
			dataEnd = len(data)
		}
		copy(pageData, data[dataStart:dataEnd])

		// Write command: 0xA2 page data[4]
		cmd := append([]byte{0xA2, page}, pageData...)
		_, err := t.device.SendDataExchange(context.Background(), cmd)
		if err != nil {
			return fmt.Errorf("failed to write page %d: %w", page, err)
		}
	}

	return nil
}

// writeMIFAREBlocks writes blocks to MIFARE Classic with automatic authentication
func (t *TagOperations) writeMIFAREBlocks(_ context.Context, startBlock byte, data []byte) error {
	// Authentication is handled automatically by WriteBlockAuto

	// Ensure key provider is set

	// Validate we're not writing to restricted blocks
	if startBlock == 0 {
		return errors.New("cannot write to manufacturer block (0)")
	}

	// Calculate how many blocks we need to write
	numBlocks := (len(data) + 15) / 16 // Round up to nearest block

	// Write block by block
	for i := range numBlocks {
		block := startBlock + byte(i)

		// Skip trailer blocks (every 4th block in each sector)
		if (block+1)%4 == 0 && block != 0 {
			continue
		}

		// Get 16 bytes for this block (pad with zeros if necessary)
		blockData := make([]byte, 16)
		dataStart := i * 16
		dataEnd := dataStart + 16
		if dataEnd > len(data) {
			dataEnd = len(data)
		}
		copy(blockData, data[dataStart:dataEnd])

		// WriteBlockAuto handles authentication automatically
		err := t.mifareInstance.WriteBlockAuto(block, blockData)
		if err != nil {
			return fmt.Errorf("failed to write block %d: %w", block, err)
		}
	}

	return nil
}

// EraseBlocks writes zeros to the specified block range
func (t *TagOperations) EraseBlocks(ctx context.Context, startBlock, endBlock byte) error {
	numBlocks := int(endBlock - startBlock + 1)
	blockSize := 16 // MIFARE block size, NTAG pages are smaller but we'll use max

	if t.tagType == pn532.TagTypeNTAG {
		blockSize = 4
	}

	zeros := make([]byte, numBlocks*blockSize)
	return t.WriteBlocks(ctx, startBlock, zeros)
}

// Format prepares the tag for NDEF use
func (t *TagOperations) Format(ctx context.Context) error {
	if t.tag == nil {
		return ErrNoTag
	}

	// Create an empty NDEF message for formatting
	emptyNDEF := &pn532.NDEFMessage{
		Records: []pn532.NDEFRecord{},
	}

	switch t.tagType {
	case pn532.TagTypeNTAG:
		// NTAG tags don't need explicit formatting
		// Just write an empty NDEF message
		return t.WriteNDEF(ctx, emptyNDEF)

	case pn532.TagTypeMIFARE:
		// For MIFARE, formatting means writing an empty NDEF message
		// The WriteNDEF method handles formatting if needed
		return t.WriteNDEF(ctx, emptyNDEF)

	case pn532.TagTypeUnknown, pn532.TagTypeFeliCa, pn532.TagTypeAny:
		return ErrUnsupportedTag
	}
	return ErrUnsupportedTag
}
