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

package testing

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// VirtualTag represents a simulated NFC tag for testing
type VirtualTag struct {
	sectorKeys          map[int][]byte
	Type                string
	UID                 []byte
	Memory              [][]byte
	ndefData            []byte
	authenticatedSector int
	Present             bool
	authenticatedKey    byte
}

// NewVirtualNTAG213 creates a virtual NTAG213 tag with default content
func NewVirtualNTAG213(uid []byte) *VirtualTag {
	if uid == nil {
		uid = TestNTAG213UID
	}

	tag := &VirtualTag{
		Type:    "NTAG213",
		UID:     uid,
		Memory:  make([][]byte, 45), // NTAG213 has 45 blocks (180 bytes)
		Present: true,
	}

	// Initialize with default NTAG213 memory layout
	tag.initNTAG213Memory()

	// Set default NDEF message: "Hello World"
	// Ignore error since this is test setup with known good data
	_ = tag.SetNDEFText("Hello World")

	return tag
}

// NewVirtualMIFARE1K creates a virtual MIFARE Classic 1K tag
func NewVirtualMIFARE1K(uid []byte) *VirtualTag {
	if uid == nil {
		uid = TestMIFARE1KUID
	}

	tag := &VirtualTag{
		Type:                "MIFARE1K",
		UID:                 uid,
		Memory:              make([][]byte, 64), // MIFARE 1K has 64 blocks (1024 bytes)
		Present:             true,
		authenticatedSector: -1, // Not authenticated initially
		sectorKeys:          make(map[int][]byte),
	}

	// Initialize with default MIFARE memory layout and keys
	tag.initMIFARE1KMemory()

	return tag
}

// NewVirtualMIFARE4K creates a virtual MIFARE Classic 4K tag
func NewVirtualMIFARE4K(uid []byte) *VirtualTag {
	if uid == nil {
		uid = TestMIFARE4KUID
	}

	tag := &VirtualTag{
		Type:                "MIFARE4K",
		UID:                 uid,
		Memory:              make([][]byte, 256), // MIFARE 4K has 256 blocks (4096 bytes)
		Present:             true,
		authenticatedSector: -1, // Not authenticated initially
		sectorKeys:          make(map[int][]byte),
	}

	// Initialize with default MIFARE memory layout and keys
	tag.initMIFARE4KMemory()

	return tag
}

// GetUIDString returns the UID as a hex string
func (v *VirtualTag) GetUIDString() string {
	return hex.EncodeToString(v.UID)
}

// ReadBlock reads a specific memory block
func (v *VirtualTag) ReadBlock(block int) ([]byte, error) {
	if !v.Present {
		return nil, errors.New("tag not present")
	}

	if block < 0 || block >= len(v.Memory) {
		return nil, fmt.Errorf("block %d out of range", block)
	}

	// MIFARE tags require authentication before reading
	if v.isMIFARE() {
		sector := v.blockToSector(block)
		if v.authenticatedSector != sector {
			return nil, fmt.Errorf("not authenticated to sector %d (block %d)", sector, block)
		}
	}

	if v.Memory[block] == nil {
		// Return zeros for uninitialized blocks
		return make([]byte, 16), nil
	}

	// Return a copy to prevent modification
	data := make([]byte, len(v.Memory[block]))
	copy(data, v.Memory[block])
	return data, nil
}

// WriteBlock writes data to a specific memory block
func (v *VirtualTag) WriteBlock(block int, data []byte) error {
	if !v.Present {
		return errors.New("tag not present")
	}

	if block < 0 || block >= len(v.Memory) {
		return fmt.Errorf("block %d out of range", block)
	}

	// MIFARE tags require authentication before writing
	if v.isMIFARE() {
		sector := v.blockToSector(block)
		if v.authenticatedSector != sector {
			return fmt.Errorf("not authenticated to sector %d (block %d)", sector, block)
		}
	}

	// Check for write protection based on tag type
	if v.isBlockWriteProtected(block) {
		return fmt.Errorf("block %d is write protected", block)
	}

	// Ensure data is exactly 16 bytes (NFC block size)
	if len(data) != 16 {
		return fmt.Errorf("data must be exactly 16 bytes, got %d", len(data))
	}

	// Copy data to prevent external modification
	v.Memory[block] = make([]byte, 16)
	copy(v.Memory[block], data)

	return nil
}

// SetNDEFText sets a simple text NDEF message
func (v *VirtualTag) SetNDEFText(text string) error {
	// Build simple NDEF text record
	// This is a simplified implementation - real NDEF is more complex
	textBytes := []byte(text)

	// NDEF Text Record format (simplified):
	// [Header][Type Length][Payload Length][Type][Language][Text]
	ndefRecord := []byte{
		0xD1,                     // Header: MB=1, ME=1, CF=0, SR=1, IL=0, TNF=1 (Well Known)
		0x01,                     // Type Length: 1 byte
		byte(len(textBytes) + 3), // Payload Length: language code (2) + encoding (1) + text
		0x54,                     // Type: "T" for Text
		0x02,                     // Language code length
		0x65, 0x6E,               // Language code: "en"
		// Text follows
	}
	ndefRecord = append(ndefRecord, textBytes...)

	// NDEF message wrapper
	ndefMessage := []byte{
		0x03,                  // NDEF Message TLV
		byte(len(ndefRecord)), // Length
	}
	ndefMessage = append(ndefMessage, ndefRecord...)
	ndefMessage = append(ndefMessage, 0xFE) // Terminator TLV

	v.ndefData = ndefMessage

	// For NTAG cards, write NDEF to blocks 4-39 (user data area)
	if v.Type == "NTAG213" {
		return v.writeNDEFToNTAG()
	}

	return nil
}

// GetNDEFText extracts text from the NDEF message (simplified)
func (v *VirtualTag) GetNDEFText() string {
	if v.Type == "NTAG213" {
		return v.extractNDEFTextFromNTAG()
	}
	return ""
}

// Remove sets the tag as not present
func (v *VirtualTag) Remove() {
	v.Present = false
}

// Insert sets the tag as present
func (v *VirtualTag) Insert() {
	v.Present = true
}

// Internal helper methods

func (v *VirtualTag) initNTAG213Memory() {
	// Block 0: UID and BCC (read-only)
	v.Memory[0] = make([]byte, 16)
	copy(v.Memory[0][:len(v.UID)], v.UID)

	// Block 1: More UID (read-only)
	v.Memory[1] = make([]byte, 16)

	// Block 2: Lock bytes and CC (Capability Container)
	v.Memory[2] = []byte{0x00, 0x00, 0xE1, 0x10, 0x12, 0x00, 0x01, 0x03, 0xA0, 0x10, 0x44, 0x03, 0x00, 0x00, 0x00, 0x00}

	// Block 3: CC continued
	v.Memory[3] = make([]byte, 16)

	// Blocks 4-39: User data (where NDEF goes)
	for i := 4; i < 40; i++ {
		v.Memory[i] = make([]byte, 16)
	}

	// Blocks 40-44: Configuration and lock (read-only for most)
	for i := 40; i < 45; i++ {
		v.Memory[i] = make([]byte, 16)
	}
}

func (v *VirtualTag) initMIFARE1KMemory() {
	// Block 0: UID and BCC (read-only)
	v.Memory[0] = make([]byte, 16)
	copy(v.Memory[0][:len(v.UID)], v.UID)

	// Initialize all other blocks as empty
	for i := 1; i < 64; i++ {
		v.Memory[i] = make([]byte, 16)
	}

	// Default MIFARE key: FF FF FF FF FF FF
	defaultKey := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// Set default keys and access bits for sector trailers
	for sector := 0; sector < 16; sector++ {
		trailerBlock := sector*4 + 3
		v.Memory[trailerBlock] = []byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key A
			0xFF, 0x07, 0x80, 0x69, // Access bits
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key B
		}
		// Store keys in sectorKeys map (Key A + Key B)
		v.sectorKeys[sector] = append(append([]byte{}, defaultKey...), defaultKey...)
	}
}

func (v *VirtualTag) initMIFARE4KMemory() {
	// Similar to 1K but with more sectors
	v.Memory[0] = make([]byte, 16)
	copy(v.Memory[0][:len(v.UID)], v.UID)

	for i := 1; i < 256; i++ {
		v.Memory[i] = make([]byte, 16)
	}

	// Default MIFARE key: FF FF FF FF FF FF
	defaultKey := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// Set default keys for all sector trailers
	// Sectors 0-31 have 4 blocks each, sectors 32-39 have 16 blocks each
	for sector := 0; sector < 32; sector++ {
		trailerBlock := sector*4 + 3
		v.Memory[trailerBlock] = []byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key A
			0xFF, 0x07, 0x80, 0x69, // Access bits
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key B
		}
		// Store keys in sectorKeys map (Key A + Key B)
		v.sectorKeys[sector] = append(append([]byte{}, defaultKey...), defaultKey...)
	}
	for sector := 32; sector < 40; sector++ {
		trailerBlock := 128 + (sector-32)*16 + 15
		v.Memory[trailerBlock] = []byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key A
			0xFF, 0x07, 0x80, 0x69, // Access bits
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Key B
		}
		// Store keys in sectorKeys map (Key A + Key B)
		v.sectorKeys[sector] = append(append([]byte{}, defaultKey...), defaultKey...)
	}
}

func (v *VirtualTag) isBlockWriteProtected(block int) bool {
	switch v.Type {
	case "NTAG213":
		// Blocks 0-2 are read-only
		return block < 3 || block >= 40
	case "MIFARE1K":
		// Sector trailers are write-protected without proper authentication
		return (block+1)%4 == 0
	case "MIFARE4K":
		// Sector trailers are write-protected
		if block < 128 {
			return (block+1)%4 == 0
		}
		return (block-128)%16 == 15
	}
	return false
}

func (v *VirtualTag) writeNDEFToNTAG() error {
	if len(v.ndefData) > 144 { // 36 blocks * 4 bytes usable per block
		return errors.New("NDEF data too large for NTAG213")
	}

	// Write NDEF data starting at block 4
	dataOffset := 0
	for block := 4; block < 40 && dataOffset < len(v.ndefData); block++ {
		blockData := make([]byte, 16)
		endOffset := dataOffset + 16
		if endOffset > len(v.ndefData) {
			endOffset = len(v.ndefData)
		}
		copy(blockData, v.ndefData[dataOffset:endOffset])
		v.Memory[block] = blockData
		dataOffset += 16
	}

	return nil
}

func (v *VirtualTag) extractNDEFTextFromNTAG() string {
	// Simple NDEF text extraction - look for text record in user data area
	for block := 4; block < 40; block++ {
		if v.Memory[block] == nil {
			continue
		}

		if text := v.findNDEFTextInBlock(block); text != "" {
			return text
		}
	}

	return ""
}

func (v *VirtualTag) findNDEFTextInBlock(block int) string {
	// Look for NDEF Text record header (0xD1, 0x01)
	for i := 0; i < len(v.Memory[block])-1; i++ {
		if v.Memory[block][i] == 0xD1 && v.Memory[block][i+1] == 0x01 {
			return v.extractTextFromNDEFRecord(block, i)
		}
	}
	return ""
}

func (v *VirtualTag) extractTextFromNDEFRecord(startBlock, recordStart int) string {
	// Found text record, try to extract text
	if recordStart+7 >= len(v.Memory[startBlock]) {
		return ""
	}

	// Skip header, type length, payload length, type, language encoding byte, language code (2 bytes)
	// Structure: [0xD1][0x01][payload_len][0x54][0x02][0x65][0x6E][text...]
	textStart := recordStart + 7
	return v.collectTextData(startBlock, textStart)
}

func (v *VirtualTag) collectTextData(startBlock, textStart int) string {
	var textData []byte

	// Collect text bytes from this and subsequent blocks
	for blockIndex := startBlock; blockIndex < 40; blockIndex++ {
		if v.Memory[blockIndex] == nil {
			break
		}

		start := 0
		if blockIndex == startBlock {
			start = textStart
		}

		for j := start; j < len(v.Memory[blockIndex]); j++ {
			if v.Memory[blockIndex][j] == 0xFE || v.Memory[blockIndex][j] == 0x00 {
				// End of NDEF or null terminator
				return string(textData)
			}
			textData = append(textData, v.Memory[blockIndex][j])
		}
	}

	return string(textData)
}

// MIFARE authentication methods

// MIFAREKeyA is the key type constant for Key A
const MIFAREKeyA = 0x00

// MIFAREKeyB is the key type constant for Key B
const MIFAREKeyB = 0x01

// Authenticate authenticates a sector with the given key
// keyType: 0x00 for Key A, 0x01 for Key B
func (v *VirtualTag) Authenticate(sector int, keyType byte, key []byte) error {
	if !v.Present {
		return errors.New("tag not present")
	}

	if !v.isMIFARE() {
		return errors.New("authentication only supported for MIFARE tags")
	}

	if len(key) != 6 {
		return errors.New("MIFARE key must be 6 bytes")
	}

	// Check sector bounds
	maxSector := v.getMaxSector()
	if sector < 0 || sector >= maxSector {
		return fmt.Errorf("sector %d out of range (max %d)", sector, maxSector-1)
	}

	// Validate key against stored keys
	storedKeys, exists := v.sectorKeys[sector]
	if !exists {
		return fmt.Errorf("no keys configured for sector %d", sector)
	}

	var expectedKey []byte
	switch keyType {
	case MIFAREKeyA:
		expectedKey = storedKeys[0:6]
	case MIFAREKeyB:
		expectedKey = storedKeys[6:12]
	default:
		return fmt.Errorf("invalid key type: 0x%02X", keyType)
	}

	// Compare keys
	if !bytesEqual(key, expectedKey) {
		v.authenticatedSector = -1 // Clear authentication on failure
		return errors.New("authentication failed: incorrect key")
	}

	v.authenticatedSector = sector
	v.authenticatedKey = keyType
	return nil
}

// ResetAuthentication clears the authentication state
func (v *VirtualTag) ResetAuthentication() {
	v.authenticatedSector = -1
	v.authenticatedKey = 0
}

// IsAuthenticated returns true if authenticated to the given sector
func (v *VirtualTag) IsAuthenticated(sector int) bool {
	return v.authenticatedSector == sector
}

// GetAuthenticatedSector returns the currently authenticated sector (-1 if none)
func (v *VirtualTag) GetAuthenticatedSector() int {
	return v.authenticatedSector
}

// SetSectorKey sets custom keys for a sector
// keys should be 12 bytes: 6 bytes Key A + 6 bytes Key B
func (v *VirtualTag) SetSectorKey(sector int, keys []byte) error {
	if !v.isMIFARE() {
		return errors.New("sector keys only apply to MIFARE tags")
	}
	if len(keys) != 12 {
		return errors.New("keys must be 12 bytes (Key A + Key B)")
	}
	maxSector := v.getMaxSector()
	if sector < 0 || sector >= maxSector {
		return fmt.Errorf("sector %d out of range (max %d)", sector, maxSector-1)
	}
	v.sectorKeys[sector] = append([]byte{}, keys...)
	return nil
}

// Helper methods

func (v *VirtualTag) isMIFARE() bool {
	return v.Type == "MIFARE1K" || v.Type == "MIFARE4K"
}

func (v *VirtualTag) getMaxSector() int {
	switch v.Type {
	case "MIFARE1K":
		return 16
	case "MIFARE4K":
		return 40
	default:
		return 0
	}
}

func (v *VirtualTag) blockToSector(block int) int {
	switch v.Type {
	case "MIFARE1K":
		return block / 4
	case "MIFARE4K":
		if block < 128 {
			return block / 4
		}
		// Sectors 32-39 have 16 blocks each
		return 32 + (block-128)/16
	default:
		return 0
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
