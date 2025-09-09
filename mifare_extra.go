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

package pn532

import (
	"errors"
	"fmt"
	"time"
)

const (
	// Maximum number of sectors on a MIFARE Classic 1K tag
	maxSectors = uint8(16)
	// Maximum number of blocks on a MIFARE Classic 1K tag
	maxBlocks = uint8(64)
)

var (
	// Standard MIFARE factory key (all 0xFF)
	factoryKey = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// MAD (MIFARE Application Directory) key for sector 0
	// This is the standard key used for the MAD sector according to ISO/IEC 14443-4
	madKey = []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}

	// Standard NDEF key used for NDEF-formatted sectors
	ndefKey = []byte{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}

	// MAD sector block 1 data - contains MAD directory structure
	madBlock1 = []byte{0x0F, 0x00, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1}

	// MAD sector block 2 data - continuation of MAD directory
	madBlock2 = []byte{0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1}

	// MAD sector trailer block with MAD key and access control bits
	madTrailerBlock = []byte{
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, // MAD key
		0x78, 0x77, 0x88, 0xC1, // Access control bits
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key B
	}

	// NDEF sector header block - marks sector as containing NDEF data
	ndefHeaderBlock = []byte{
		0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// NDEF sector trailer block with NDEF key and access control bits
	ndefTrailerBlock = []byte{
		0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, // NDEF key
		0x7F, 0x07, 0x88, 0x40, // Access control bits
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key B
	}
)

// IsNDEFFormatted checks if the tag is NDEF formatted by attempting to authenticate
// with the MAD key on sector 0. This is a fast check that takes approximately 60ms
// compared to 550ms for a full NDEF read attempt on a blank tag.
//
// Returns true if the tag appears to be NDEF formatted, false otherwise.
// This method checks sector 0 with the MAD key as per MIFARE Application Directory
// standards rather than sector 1 with the NDEF key.
func (t *MIFARETag) IsNDEFFormatted() bool {
	madKeyBytes := make([]byte, len(madKey))
	copy(madKeyBytes, madKey)
	defer clear(madKeyBytes)

	return t.Authenticate(0, MIFAREKeyA, madKeyBytes) == nil
}

// FormatForNDEF formats a blank MIFARE Classic tag for NDEF data storage.
// This process takes approximately 2 seconds and sets up:
// - Sector 0 with MAD (MIFARE Application Directory) structure
// - Remaining sectors with NDEF keys and access control bits
//
// The tag must be in factory state (using factory keys) before calling this method.
// After formatting, the tag will be ready for NDEF data storage using standard
// NDEF read/write operations.
//
// Returns an error if formatting fails at any step.
func (t *MIFARETag) FormatForNDEF() error {
	// Authenticate with sector 0 using factory key
	if err := t.AuthenticateRobust(0, MIFAREKeyA, factoryKey); err != nil {
		return fmt.Errorf("failed to authenticate sector 0: %w", err)
	}

	// Write MAD directory structure to sector 0
	if err := t.WriteBlock(1, madBlock1); err != nil {
		return fmt.Errorf("failed to write MAD block 1: %w", err)
	}
	if err := t.WriteBlock(2, madBlock2); err != nil {
		return fmt.Errorf("failed to write MAD block 2: %w", err)
	}
	if err := t.WriteBlock(3, madTrailerBlock); err != nil {
		return fmt.Errorf("failed to write MAD trailer block: %w", err)
	}

	// Format remaining sectors for NDEF
	for sector := uint8(1); sector < maxSectors; sector++ {
		// Try to authenticate with factory key - skip if not accessible
		if err := t.AuthenticateRobust(sector, MIFAREKeyA, factoryKey); err != nil {
			continue
		}

		// Write NDEF header to first block of sector
		headerBlock := sector * 4
		if err := t.WriteBlock(headerBlock, ndefHeaderBlock); err != nil {
			return fmt.Errorf("failed to write NDEF header block %d: %w", headerBlock, err)
		}

		// Write NDEF trailer with keys and access control bits
		trailerBlock := sector*4 + 3
		if err := t.WriteBlock(trailerBlock, ndefTrailerBlock); err != nil {
			return fmt.Errorf("failed to write NDEF trailer block %d: %w", trailerBlock, err)
		}
	}

	// Hardware delay to ensure writes are complete
	time.Sleep(t.config.HardwareDelay)
	return nil
}

// authenticateForNDEFAlternative checks if the tag is NDEF formatted using the
// specific formatting scheme created by FormatForNDEF. This is used internally
// by the alternative NDEF writing methods.
func (t *MIFARETag) authenticateForNDEFAlternative() (*authenticationResult, error) {
	result := &authenticationResult{}

	// Try to authenticate with NDEF key on sector 1
	err := t.AuthenticateRobust(1, MIFAREKeyA, ndefKey)
	if err == nil {
		result.isNDEFFormatted = true
		return result, nil
	}

	return result, nil
}

// WriteNDEFAlternative provides an optimized NDEF writing implementation for
// tags formatted with FormatForNDEF. This method skips some validation steps
// and uses pre-known sector layouts for improved performance.
//
// WARNING: This method is optimized for specific use cases where performance
// is critical. It assumes the tag was formatted using FormatForNDEF and may
// not work correctly with tags formatted by other applications.
//
// Use the standard WriteNDEF method for general compatibility.
func (t *MIFARETag) WriteNDEFAlternative(message *NDEFMessage) error {
	if len(message.Records) == 0 {
		return errors.New("no NDEF records to write")
	}

	// Build NDEF message data
	data, err := BuildNDEFMessageEx(message.Records)
	if err != nil {
		return fmt.Errorf("failed to build NDEF message: %w", err)
	}

	// Verify tag is formatted correctly
	_, err = t.authenticateForNDEFAlternative()
	if err != nil {
		return err
	}

	// Write NDEF data using optimized method
	return t.writeNDEFDataAlternative(data)
}

// writeNDEFDataAlternative writes NDEF data to the tag starting from block 4,
// skipping trailer blocks and handling sector boundaries.
func (t *MIFARETag) writeNDEFDataAlternative(data []byte) error {
	block := uint8(4) // Start after MAD sector

	for i := 0; i < len(data); i += mifareBlockSize {
		// Skip trailer blocks (every 4th block)
		if block%4 == 3 {
			block++
		}

		// Check capacity limits
		if block >= maxBlocks {
			return errors.New("NDEF data exceeds tag capacity")
		}

		if err := t.writeDataBlockAlternative(block, data, i); err != nil {
			return err
		}
		block++
	}
	return nil
}

// writeDataBlockAlternative handles writing a single block of NDEF data,
// including padding for partial blocks at the end of the message.
func (t *MIFARETag) writeDataBlockAlternative(block uint8, data []byte, offset int) error {
	end := offset + mifareBlockSize
	if end > len(data) {
		// Pad partial block with zeros
		blockData := make([]byte, mifareBlockSize)
		copy(blockData, data[offset:])
		return t.writeBlockWithErrorAlternative(block, blockData)
	}
	return t.writeBlockWithErrorAlternative(block, data[offset:end])
}

// writeBlockWithErrorAlternative wraps block writing with error handling.
func (t *MIFARETag) writeBlockWithErrorAlternative(block uint8, data []byte) error {
	if err := t.WriteBlockAutoAlternative(block, data); err != nil {
		return fmt.Errorf("failed to write block %d: %w", block, err)
	}
	return nil
}

// WriteBlockAutoAlternative writes a block with automatic sector authentication.
// It handles authentication caching and tries both Key A and Key B as needed.
func (t *MIFARETag) WriteBlockAutoAlternative(block uint8, data []byte) error {
	sector := block / mifareSectorSize

	// Check if we need to authenticate to this sector
	if t.lastAuthSector != int(sector) {
		// For write operations, try Key B first (typically required for writes)
		err := t.authenticateNDEFAlternative(sector, MIFAREKeyB)
		if err != nil {
			// Fallback to Key A
			err = t.authenticateNDEFAlternative(sector, MIFAREKeyA)
			if err != nil {
				return fmt.Errorf("failed to authenticate to sector %d: %w", sector, err)
			}
		}
	}

	return t.WriteBlock(block, data)
}

// authenticateNDEFAlternative handles authentication for the alternative NDEF methods.
// It uses the known key layout from FormatForNDEF to optimize authentication.
func (t *MIFARETag) authenticateNDEFAlternative(sector uint8, keyType byte) error {
	switch keyType {
	case MIFAREKeyA:
		return t.AuthenticateRobust(sector, keyType, ndefKey)
	case MIFAREKeyB:
		return t.AuthenticateRobust(sector, keyType, factoryKey)
	}
	return nil
}

