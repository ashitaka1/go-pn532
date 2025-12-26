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
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ZaparooProject/go-pn532/internal/syncutil"
)

// By default we only support MIFARE Classic tags with NDEF formatted data
// which uses a pre-shared standard auth key:
// [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7]
//
// This key is used on sector 1 and/or greater. Sector 0 is reserved for the
// MAD (MIFARE Application Directory) and uses a different shared key, but we
// don't care about implementing this.
//
// Additionally that means we should only use sector 1 and above for reading
// and writing our own data.
//
// MIFARE Classic tags may ship blank using the default key:
// [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
//
// Before they work with NDEF data, the tag must also be intialized to use
// the standard NDEF auth key.

var (
	// NDEF standard key for sector 1 and above
	ndefKeyTemplate = []byte{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}

	// Common alternative keys to try
	commonKeys = [][]byte{
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // Default transport key
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // All zeros
		{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}, // MAD key
		{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}, // Common alternative
		{0xA3, 0x96, 0xEF, 0xA4, 0xE2, 0x4F}, // FM11RF08S universal backdoor key
	}

	// Chinese clone unlock commands
	chineseCloneUnlock7Bit = byte(0x40)
	chineseCloneUnlock8Bit = byte(0x43)
)

// MIFARE commands
const (
	mifareCmdAuth  = 0x60
	mifareCmdRead  = 0x30
	mifareCmdWrite = 0xA0
)

// MIFARE memory structure
const (
	mifareBlockSize         = 16 // 16 bytes per block
	mifareSectorSize        = 4  // 4 blocks per sector
	mifareManufacturerBlock = 0  // Manufacturer block
	mifareKeySize           = 6  // 6 bytes per key
)

// Key types
const (
	MIFAREKeyA = 0x00
	MIFAREKeyB = 0x01
)

// Retry levels (progressive recovery)
type retryLevel int

const (
	retryLight    retryLevel = iota // Simple retry with delay
	retryModerate                   // Halt/wake sequence
	retryHeavy                      // RF field reset
	retryNuclear                    // Complete PN532 reinitialization
)

// Authentication timing metrics
type authTiming struct {
	attempts []time.Duration
	mutex    syncutil.RWMutex
}

func (at *authTiming) add(duration time.Duration) {
	at.mutex.Lock()
	defer at.mutex.Unlock()
	at.attempts = append(at.attempts, duration)
	if len(at.attempts) > 20 {
		at.attempts = at.attempts[1:]
	}
}

func (at *authTiming) getVariance() time.Duration {
	at.mutex.RLock()
	defer at.mutex.RUnlock()
	if len(at.attempts) < 2 {
		return 0
	}

	minVal, maxVal := at.attempts[0], at.attempts[0]
	for _, d := range at.attempts[1:] {
		if d < minVal {
			minVal = d
		}
		if d > maxVal {
			maxVal = d
		}
	}
	return maxVal - minVal
}

// secureKey manages MIFARE keys with automatic zeroing
type secureKey struct {
	data [6]byte
}

// newSecureKey creates a secure key from template
func newSecureKey(template []byte) *secureKey {
	if len(template) != 6 {
		return nil
	}
	sk := &secureKey{}
	copy(sk.data[:], template)
	return sk
}

// bytes returns a copy of the key data (caller must zero it)
func (sk *secureKey) bytes() []byte {
	result := make([]byte, 6)
	copy(result, sk.data[:])
	return result
}

// MIFAREConfig holds all configurable timing parameters for MIFARE operations
type MIFAREConfig struct {
	RetryConfig   *RetryConfig  // Retry backoff configuration
	HardwareDelay time.Duration // Hardware timing delays (reinitialization, tag processing)
}

// DefaultMIFAREConfig returns production-safe MIFARE configuration
// These values are optimized based on real-world testing and provide
// a good balance between speed and reliability for most hardware setups.
func DefaultMIFAREConfig() *MIFAREConfig {
	return &MIFAREConfig{
		RetryConfig: &RetryConfig{
			MaxAttempts:       3,
			InitialBackoff:    10 * time.Millisecond,
			MaxBackoff:        1 * time.Second,
			BackoffMultiplier: 2.0,
			Jitter:            0.1,
			RetryTimeout:      5 * time.Second,
		},
		HardwareDelay: 10 * time.Millisecond,
	}
}

// MIFARETag represents a MIFARE Classic tag
type MIFARETag struct {
	ndefKey *secureKey
	config  *MIFAREConfig
	BaseTag
	timing          authTiming
	lastAuthSector  int
	authMutex       syncutil.RWMutex
	lastAuthKeyType byte
}

// NewMIFARETag creates a new MIFARE tag instance
func NewMIFARETag(device *Device, uid []byte, sak byte) *MIFARETag {
	tag := &MIFARETag{
		ndefKey: newSecureKey(ndefKeyTemplate),
		BaseTag: BaseTag{
			tagType: TagTypeMIFARE,
			uid:     uid,
			device:  device,
			sak:     sak,
		},
		lastAuthSector: -1, // Not authenticated initially
		config:         DefaultMIFAREConfig(),
	}

	return tag
}

// SetConfig allows runtime configuration of MIFARE behavior for testing
func (t *MIFARETag) SetConfig(config *MIFAREConfig) {
	if config != nil {
		t.config = config
	}
}

// SetRetryConfig allows runtime configuration of retry behavior for testing
func (t *MIFARETag) SetRetryConfig(config *RetryConfig) {
	if config != nil {
		t.config.RetryConfig = config
	}
}

// authenticateNDEF authenticates to a sector using NDEF standard key with robust retry
func (t *MIFARETag) authenticateNDEF(ctx context.Context, sector uint8, keyType byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if t.ndefKey == nil {
		return errors.New("NDEF key not available")
	}

	key := t.ndefKey.bytes()
	err := t.AuthenticateRobust(ctx, sector, keyType, key)

	// SECURITY: Zero key copy after use
	for i := range key {
		key[i] = 0
	}

	return err
}

// ReadBlockAuto reads a block with automatic authentication using the key provider
func (t *MIFARETag) ReadBlockAuto(ctx context.Context, block uint8) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sector := block / mifareSectorSize

	// SECURITY: Thread-safe authentication state checking
	t.authMutex.RLock()
	needAuth := t.lastAuthSector != int(sector)
	t.authMutex.RUnlock()

	if needAuth {
		// Try Key A first, then Key B
		err := t.authenticateNDEF(ctx, sector, MIFAREKeyA)
		if err != nil {
			// Re-select tag before trying Key B - failed auth leaves tag in HALT state
			_, _ = t.device.InListPassiveTarget(ctx, 0x00)
			err = t.authenticateNDEF(ctx, sector, MIFAREKeyB)
			if err != nil {
				return nil, fmt.Errorf("failed to authenticate to sector %d: %w", sector, err)
			}
		}
	}

	return t.ReadBlock(ctx, block)
}

// WriteBlockAuto writes a block with automatic authentication using the key provider
func (t *MIFARETag) WriteBlockAuto(ctx context.Context, block uint8, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sector := block / mifareSectorSize

	// Check if we need to authenticate
	if t.lastAuthSector != int(sector) {
		// For write operations, typically Key B is required (but this depends on access bits)
		// Try Key B first, then Key A
		err := t.authenticateNDEF(ctx, sector, MIFAREKeyB)
		if err != nil {
			// Re-select tag before trying Key A - failed auth leaves tag in HALT state
			_, _ = t.device.InListPassiveTarget(ctx, 0x00)
			err = t.authenticateNDEF(ctx, sector, MIFAREKeyA)
			if err != nil {
				return fmt.Errorf("failed to authenticate to sector %d: %w", sector, err)
			}
		}
	}

	return t.WriteBlock(ctx, block, data)
}

// ReadBlock reads a block from the MIFARE tag
func (t *MIFARETag) ReadBlock(ctx context.Context, block uint8) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Check if we need to authenticate to this sector
	sector := int(block / mifareSectorSize)
	t.authMutex.RLock()
	authenticated := t.lastAuthSector == sector
	t.authMutex.RUnlock()

	if !authenticated {
		return nil, fmt.Errorf("not authenticated to sector %d (block %d)", sector, block)
	}

	// Send read command
	data, err := t.device.SendDataExchange(ctx, []byte{mifareCmdRead, block})
	if err != nil {
		return nil, fmt.Errorf("%w (block %d): %w", ErrTagReadFailed, block, err)
	}

	// MIFARE Classic returns 16 bytes on read
	if len(data) < mifareBlockSize {
		return nil, fmt.Errorf("invalid read response length: %d", len(data))
	}

	return data[:mifareBlockSize], nil
}

// ReadBlockDirect reads a block directly without authentication (for clone tags)
//
//nolint:dupl // Similar pattern to NTAGTag.ReadBlock but different error handling and block sizes
func (t *MIFARETag) ReadBlockDirect(ctx context.Context, block uint8) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Send read command directly
	data, err := t.device.SendDataExchange(ctx, []byte{mifareCmdRead, block})
	if err != nil {
		// If we get a timeout error, try InCommunicateThru as fallback
		if IsPN532TimeoutError(err) {
			return t.readBlockCommunicateThru(ctx, block)
		}
		return nil, fmt.Errorf("%w (block %d): %w", ErrTagReadFailed, block, err)
	}

	// MIFARE Classic returns 16 bytes on read
	if len(data) < mifareBlockSize {
		return nil, fmt.Errorf("invalid read response length: %d", len(data))
	}

	return data[:mifareBlockSize], nil
}

// WriteBlock writes a block to the MIFARE tag
func (t *MIFARETag) WriteBlock(ctx context.Context, block uint8, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Validate data size
	if len(data) != mifareBlockSize {
		return fmt.Errorf("invalid block size: expected %d, got %d", mifareBlockSize, len(data))
	}

	// Check if we need to authenticate to this sector
	sector := int(block / mifareSectorSize)
	if t.lastAuthSector != sector {
		return fmt.Errorf("not authenticated to sector %d (block %d)", sector, block)
	}

	// Don't allow writing to manufacturer block
	if block == mifareManufacturerBlock {
		return errors.New("cannot write to manufacturer block")
	}

	// Send write command
	cmd := []byte{mifareCmdWrite, block}
	cmd = append(cmd, data...)

	_, err := t.device.SendDataExchange(ctx, cmd)
	if err != nil {
		return fmt.Errorf("%w (block %d): %w", ErrTagWriteFailed, block, err)
	}

	return nil
}

// WriteBlockDirect writes a block directly without authentication (for clone tags)
func (t *MIFARETag) WriteBlockDirect(ctx context.Context, block uint8, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Validate data size
	if len(data) != mifareBlockSize {
		return fmt.Errorf("invalid block size: expected %d, got %d", mifareBlockSize, len(data))
	}

	// Don't allow writing to manufacturer block
	if block == mifareManufacturerBlock {
		return errors.New("cannot write to manufacturer block")
	}

	// First, try to read the block to see if the tag is responsive
	_, err := t.ReadBlockDirect(ctx, block)
	if err != nil {
		// If we can't even read, the tag might not support direct access at all
		return fmt.Errorf("clone tag does not support direct block access: %w", err)
	}

	// Send write command directly
	cmd := []byte{mifareCmdWrite, block}
	cmd = append(cmd, data...)

	_, err = t.device.SendDataExchange(ctx, cmd)
	if err != nil {
		// Try alternative approach - some clones might need different handling
		return t.writeBlockDirectAlternative(ctx, block, data, err)
	}

	return nil
}

// writeBlockDirectAlternative tries alternative methods for clone tags that don't respond to
// standard writes
func (t *MIFARETag) writeBlockDirectAlternative(
	ctx context.Context, block uint8, data []byte, originalErr error,
) error {
	// Check if the original error was a timeout (0x01)
	if IsPN532TimeoutError(originalErr) {
		// Try using InCommunicateThru instead of InDataExchange
		// Some clone tags might respond better to raw communication
		err := t.writeBlockCommunicateThru(ctx, block, data)
		if err == nil {
			return nil
		}

		// If InCommunicateThru also fails, this tag may not support writing
		return errors.New("tag does not support writing: this tag may be read-only or have limited write functionality")
	}

	// For other errors, return the original error
	return fmt.Errorf("%w (block %d): %w", ErrTagWriteFailed, block, originalErr)
}

// writeBlockCommunicateThru tries to write a block using InCommunicateThru instead of InDataExchange
func (t *MIFARETag) writeBlockCommunicateThru(ctx context.Context, block uint8, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Validate data size
	if len(data) != mifareBlockSize {
		return fmt.Errorf("invalid block size: expected %d, got %d", mifareBlockSize, len(data))
	}

	// Don't allow writing to manufacturer block
	if block == mifareManufacturerBlock {
		return errors.New("cannot write to manufacturer block")
	}

	// Build MIFARE write command
	cmd := []byte{mifareCmdWrite, block}
	cmd = append(cmd, data...)

	// Use SendRawCommand instead of SendDataExchange
	_, err := t.device.SendRawCommand(ctx, cmd)

	// Re-select target after SendRawCommand to restore PN532 internal state
	if selectErr := t.device.InSelect(ctx); selectErr != nil {
		Debugln("MIFARE writeBlockCommunicateThru: InSelect failed:", selectErr)
	}

	if err != nil {
		return fmt.Errorf("raw write command failed: %w", err)
	}

	return nil
}

// readBlockCommunicateThru tries to read a block using InCommunicateThru instead of InDataExchange
func (t *MIFARETag) readBlockCommunicateThru(ctx context.Context, block uint8) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Build MIFARE read command
	cmd := []byte{mifareCmdRead, block}

	// Use SendRawCommand instead of SendDataExchange
	data, err := t.device.SendRawCommand(ctx, cmd)

	// Re-select target after SendRawCommand to restore PN532 internal state
	if selectErr := t.device.InSelect(ctx); selectErr != nil {
		Debugln("MIFARE readBlockCommunicateThru: InSelect failed:", selectErr)
	}

	if err != nil {
		return nil, fmt.Errorf("raw read command failed: %w", err)
	}

	// MIFARE Classic returns 16 bytes on read
	if len(data) < mifareBlockSize {
		return nil, fmt.Errorf("invalid read response length: %d", len(data))
	}

	return data[:mifareBlockSize], nil
}

// ReadNDEFRobust reads NDEF data with retry logic to handle intermittent empty data issues
// This addresses the "empty valid tag" problem where tags are detected but return no data
func (t *MIFARETag) ReadNDEFRobust(ctx context.Context) (*NDEFMessage, error) {
	return readNDEFWithRetry(func() (*NDEFMessage, error) {
		return t.ReadNDEF(ctx)
	}, isMifareRetryableError, "MIFARE")
}

// isMifareRetryableError determines if a MIFARE error is worth retrying
func isMifareRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Use the centralized retry logic from errors.go
	// This handles authentication failures, timeouts, read failures, and communication errors
	return IsRetryable(err) ||
		errors.Is(err, ErrTagAuthFailed) ||
		errors.Is(err, ErrTagReadFailed)
}

// ReadNDEF reads NDEF data from the MIFARE tag using bulk sector reads
func (t *MIFARETag) ReadNDEF(ctx context.Context) (*NDEFMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	maxSectors, initialCapacity := t.getTagCapacityParams()
	data := make([]byte, 0, initialCapacity)

	for sector := uint8(1); sector < maxSectors; sector++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := t.authenticateSector(ctx, sector); err != nil {
			if sector == 1 {
				return nil, fmt.Errorf("%w: tag may not be NDEF formatted: %w", ErrTagReadFailed, err)
			}
			break
		}

		sectorData, foundEnd := t.readSectorData(ctx, sector)
		if len(sectorData) > 0 {
			data = append(data, sectorData...)
		}

		readState := ndefReadContinue
		if foundEnd {
			readState = ndefReadFoundEnd
		}
		if t.shouldStopReading(sectorData, readState, data) {
			break
		}
	}

	return ParseNDEFMessage(data)
}

func (t *MIFARETag) getTagCapacityParams() (maxSectors uint8, initialCapacity int) {
	if t.IsMIFARE4K() {
		return 40, 255 * mifareBlockSize // 4K tag has 40 sectors
	}
	return 16, 64 * mifareBlockSize // 1K tag has 16 sectors
}

func (t *MIFARETag) authenticateSector(ctx context.Context, sector uint8) error {
	// Try to authenticate to the sector with Key A
	if err := t.authenticateNDEF(ctx, sector, MIFAREKeyA); err != nil {
		// Try Key B if Key A failed
		return t.authenticateNDEF(ctx, sector, MIFAREKeyB)
	}
	return nil
}

type ndefReadState int

const (
	ndefReadContinue ndefReadState = iota
	ndefReadFoundEnd
)

func (*MIFARETag) shouldStopReading(sectorData []byte, readState ndefReadState, allData []byte) bool {
	// Check if we found the NDEF end marker
	if readState == ndefReadFoundEnd || bytes.Contains(allData, ndefEnd) {
		return true
	}
	// Stop if sector was empty
	return len(sectorData) == 0 || isEmptyData(sectorData)
}

// readSectorData reads all data blocks in a sector (excluding the trailer)
// Returns the data and whether an NDEF end marker was found
func (t *MIFARETag) readSectorData(ctx context.Context, sector uint8) ([]byte, bool) {
	startBlock := sector * mifareSectorSize
	endBlock := startBlock + mifareSectorSize - 1 // -1 to exclude trailer

	data := make([]byte, 0, (mifareSectorSize-1)*mifareBlockSize)
	foundEnd := false

	for block := startBlock; block < endBlock; block++ {
		if ctx.Err() != nil {
			break
		}

		blockData, err := t.ReadBlock(ctx, block)
		if err != nil {
			break
		}

		data = append(data, blockData...)

		// Check for NDEF end marker
		if bytes.Contains(blockData, ndefEnd) {
			foundEnd = true
			break
		}
	}

	return data, foundEnd
}

// isEmptyData checks if the data is all zeros
func isEmptyData(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// WriteNDEF writes NDEF data to the MIFARE tag with final verification
func (t *MIFARETag) WriteNDEF(ctx context.Context, message *NDEFMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(message.Records) == 0 {
		return errors.New("no NDEF records to write")
	}

	data, err := BuildNDEFMessageEx(message.Records)
	if err != nil {
		return fmt.Errorf("failed to build NDEF message: %w", err)
	}

	authResult, err := t.authenticateForNDEF(ctx)
	if err != nil {
		return err
	}

	if err := t.validateNDEFSize(data); err != nil {
		return err
	}

	if authResult.isBlank {
		if err := t.formatForNDEFWithKey(ctx, authResult.blankKey); err != nil {
			return fmt.Errorf("failed to format tag for NDEF: %w", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := t.writeNDEFData(ctx, data); err != nil {
		return err
	}

	if err := t.clearRemainingBlocks(ctx, t.calculateNextBlock(len(data))); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// Verify write by reading back and comparing
	return t.verifyWrittenNDEFData(ctx, data)
}

type authenticationResult struct {
	blankKey        []byte
	isBlank         bool
	isNDEFFormatted bool
}

// tryAuthWithBothKeys attempts authentication with both Key A and Key B.
// Returns true if either key succeeds.
func (t *MIFARETag) tryAuthWithBothKeys(ctx context.Context, sector uint8, key []byte) bool {
	if t.AuthenticateRobust(ctx, sector, MIFAREKeyA, key) == nil {
		return true
	}
	return t.AuthenticateRobust(ctx, sector, MIFAREKeyB, key) == nil
}

func (t *MIFARETag) authenticateForNDEF(ctx context.Context) (*authenticationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// First try NDEF key for already-formatted tags to avoid state corruption
	ndefKeyBytes := t.ndefKey.bytes()
	defer clearKey(ndefKeyBytes)

	if t.tryAuthWithBothKeys(ctx, 1, ndefKeyBytes) {
		return &authenticationResult{isNDEFFormatted: true}, nil
	}

	// If NDEF key failed, try common keys for blank tags
	for _, key := range commonKeys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if t.tryAuthWithBothKeys(ctx, 1, key) {
			return &authenticationResult{isBlank: true, blankKey: key}, nil
		}
	}

	return nil, errors.New("cannot authenticate to tag - it may use custom keys, be protected, " +
		"or be a non-standard tag. Supported keys: default (blank), NDEF standard")
}

// clearKey securely clears sensitive key data.
func clearKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}

func (t *MIFARETag) validateNDEFSize(data []byte) error {
	// Determine max blocks based on card type
	var maxBlocks int
	if t.IsMIFARE4K() {
		maxBlocks = 255 // 4K card has 255 blocks (0-254)
	} else {
		maxBlocks = 64 // 1K card has 64 blocks (0-63)
	}

	dataBlocks := 0
	for i := 4; i < maxBlocks; i++ {
		if i%4 != 3 { // Skip sector trailers
			dataBlocks++
		}
	}
	maxDataSize := dataBlocks * mifareBlockSize

	if len(data) > maxDataSize {
		return fmt.Errorf("NDEF message too large: %d bytes, max %d bytes", len(data), maxDataSize)
	}
	return nil
}

func (t *MIFARETag) writeNDEFData(ctx context.Context, data []byte) error {
	// Determine max blocks based on card type
	var maxBlocks uint8
	if t.IsMIFARE4K() {
		maxBlocks = 255 // 4K card has 255 blocks (0-254)
	} else {
		maxBlocks = 64 // 1K card has 64 blocks (0-63)
	}

	block := uint8(4)
	for i := 0; i < len(data); i += mifareBlockSize {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if block%4 == 3 {
			block++
		}

		if block >= maxBlocks {
			return errors.New("NDEF data exceeds tag capacity")
		}

		if err := t.writeDataBlock(ctx, block, data, i); err != nil {
			return err
		}
		block++
	}
	return nil
}

func (t *MIFARETag) writeDataBlock(ctx context.Context, block uint8, data []byte, offset int) error {
	end := offset + mifareBlockSize
	if end > len(data) {
		blockData := make([]byte, mifareBlockSize)
		copy(blockData, data[offset:])
		return t.writeBlockWithError(ctx, block, blockData)
	}
	return t.writeBlockWithError(ctx, block, data[offset:end])
}

func (t *MIFARETag) writeBlockWithError(ctx context.Context, block uint8, data []byte) error {
	if err := t.WriteBlockAuto(ctx, block, data); err != nil {
		return fmt.Errorf("%w (block %d): %w", ErrTagWriteFailed, block, err)
	}
	return nil
}

func (*MIFARETag) calculateNextBlock(dataLen int) uint8 {
	block := uint8(4)
	for i := 0; i < dataLen; i += mifareBlockSize {
		if block%4 == 3 {
			block++
		}
		block++
	}
	return block
}

// clearRemainingBlocks clears data blocks after NDEF data (best-effort).
// Write failures to non-essential blocks are intentionally ignored.
//
//nolint:nilerr // Intentional: write errors are ignored for best-effort clearing
func (t *MIFARETag) clearRemainingBlocks(ctx context.Context, startBlock uint8) error {
	// Determine max blocks based on card type
	var maxBlocks uint8
	if t.IsMIFARE4K() {
		maxBlocks = 255 // 4K card has 255 blocks (0-254)
	} else {
		maxBlocks = 64 // 1K card has 64 blocks (0-63)
	}

	block := startBlock
	for block < maxBlocks {
		if err := ctx.Err(); err != nil {
			return err
		}

		if block%4 == 3 {
			block++
			continue
		}

		emptyBlock := make([]byte, mifareBlockSize)
		if err := t.WriteBlockAuto(ctx, block, emptyBlock); err != nil {
			// It's okay if we can't clear all blocks - this is best effort
			break
		}
		block++
	}
	return nil
}

// verifyWrittenNDEFData reads back written NDEF data and compares it to the original
func (t *MIFARETag) verifyWrittenNDEFData(ctx context.Context, expectedData []byte) error {
	block := uint8(4)
	dataOffset := 0

	for dataOffset < len(expectedData) {
		// Check context before each read
		if err := ctx.Err(); err != nil {
			return err
		}

		// Skip sector trailers
		if block%4 == 3 {
			block++
			continue
		}

		readData, err := t.ReadBlockAuto(ctx, block)
		if err != nil {
			return fmt.Errorf("verification read failed (block %d): %w", block, err)
		}

		// Calculate expected data for this block
		end := dataOffset + mifareBlockSize
		if end > len(expectedData) {
			end = len(expectedData)
		}

		expectedBlock := make([]byte, mifareBlockSize)
		copy(expectedBlock, expectedData[dataOffset:end])

		// Compare
		if !bytes.Equal(readData[:mifareBlockSize], expectedBlock) {
			Debugf("MIFARE write verification failed at block %d: expected %X, got %X",
				block, expectedBlock, readData[:mifareBlockSize])
			return fmt.Errorf("%w at block %d", ErrWriteVerificationFailed, block)
		}

		dataOffset += mifareBlockSize
		block++
	}

	Debugf("MIFARE write verification successful: %d bytes verified", len(expectedData))
	return nil
}

// ResetAuthState resets the PN532's internal authentication state
// This can help when previous failed authentication attempts have polluted the state
func (t *MIFARETag) ResetAuthState(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// SECURITY: Thread-safe state clearing
	t.authMutex.Lock()
	t.lastAuthSector = -1
	t.lastAuthKeyType = 0
	t.authMutex.Unlock()

	// Force PN532 to reset by attempting to re-detect the tag
	// This clears any internal authentication state in the PN532 chip
	_, err := t.device.InListPassiveTarget(ctx, 0x00)
	return err
}

// Authenticate authenticates a sector on the MIFARE tag
func (t *MIFARETag) Authenticate(ctx context.Context, sector uint8, keyType byte, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(key) != 6 {
		return errors.New("MIFARE key must be 6 bytes")
	}

	// SECURITY: Create secure copy of key for protocol operations
	secureKeyCopy := make([]byte, 6)
	copy(secureKeyCopy, key)
	defer func() {
		for i := range secureKeyCopy {
			secureKeyCopy[i] = 0
		}
	}()

	// Validate key type
	if keyType != 0x00 && keyType != 0x01 {
		return fmt.Errorf("invalid key type: 0x%02X (must be 0x00 for Key A or 0x01 for Key B)", keyType)
	}

	// Calculate block number for the sector
	block := sector * mifareSectorSize

	// Build authentication command
	// CRITICAL: Protocol requires key first, then UID (per PN532 manual and working implementations)
	cmd := []byte{mifareCmdAuth + keyType, block}
	cmd = append(cmd, secureKeyCopy...) // Key must come first
	cmd = append(cmd, t.uid[:4]...)     // UID comes second

	_, err := t.device.SendDataExchange(ctx, cmd)
	if err != nil {
		// SECURITY: Thread-safe state clearing on failure
		t.authMutex.Lock()
		t.lastAuthSector = -1
		t.lastAuthKeyType = 0
		t.authMutex.Unlock()
		return fmt.Errorf("%w: %w", ErrTagAuthFailed, err)
	}

	// SECURITY: Thread-safe state update on success
	t.authMutex.Lock()
	t.lastAuthSector = int(sector)
	t.lastAuthKeyType = keyType
	t.authMutex.Unlock()

	return nil
}

// AuthenticateContext performs authentication with context support
func (t *MIFARETag) AuthenticateContext(ctx context.Context, sector uint8, keyType byte, key []byte) error {
	if len(key) != 6 {
		return errors.New("MIFARE key must be 6 bytes")
	}

	// Calculate block number for the sector
	block := sector * mifareSectorSize

	// Build authentication command
	cmd := []byte{mifareCmdAuth + keyType, block}
	cmd = append(cmd, key...)
	cmd = append(cmd, t.uid[:4]...)

	_, err := t.device.SendDataExchange(ctx, cmd)
	return err
}

// AuthenticateRobust performs robust authentication with retry logic and Chinese clone support
// This is the recommended method for authenticating with unreliable tags
func (t *MIFARETag) AuthenticateRobust(ctx context.Context, sector uint8, keyType byte, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	start := time.Now()
	defer func() {
		t.timing.add(time.Since(start))
	}()

	// Try standard authentication first
	err := t.authenticateWithRetry(ctx, sector, keyType, key)
	if err == nil {
		return nil
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	// If standard auth failed, try Chinese clone unlock sequences
	if t.tryChineseCloneUnlock(ctx, sector) {
		// Clone unlock successful, tag is accessible without auth
		t.authMutex.Lock()
		t.lastAuthSector = int(sector)
		t.lastAuthKeyType = keyType
		t.authMutex.Unlock()
		return nil
	}

	return fmt.Errorf("%w after all attempts: %w", ErrTagAuthFailed, err)
}

// AuthenticateRobustContext performs robust authentication with context support
func (t *MIFARETag) AuthenticateRobustContext(ctx context.Context, sector uint8, keyType byte, key []byte) error {
	start := time.Now()
	defer func() {
		t.timing.add(time.Since(start))
	}()

	// Check context before starting
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	// Try standard authentication first with context-aware retry
	err := t.authenticateWithRetryContext(ctx, sector, keyType, key)
	if err == nil {
		return nil
	}

	// Check context before trying Chinese clone unlock
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	// If standard auth failed, try Chinese clone unlock sequences
	if t.tryChineseCloneUnlock(ctx, sector) {
		// Clone unlock successful, tag is accessible without auth
		t.authMutex.Lock()
		t.lastAuthSector = int(sector)
		t.lastAuthKeyType = keyType
		t.authMutex.Unlock()
		return nil
	}

	return fmt.Errorf("%w after all attempts: %w", ErrTagAuthFailed, err)
}

// authenticateWithRetry implements progressive retry strategy
func (t *MIFARETag) authenticateWithRetry(ctx context.Context, sector uint8, keyType byte, key []byte) error {
	var lastErr error

	for attempt := range t.config.RetryConfig.MaxAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}

		level := t.getRetryLevel(attempt)

		// Apply recovery strategy based on level
		if err := t.applyRetryStrategy(ctx, level, lastErr); err != nil {
			return fmt.Errorf("recovery strategy failed: %w", err)
		}

		// Attempt authentication
		err := t.Authenticate(ctx, sector, keyType, key)
		if err == nil {
			return nil
		}

		lastErr = err

		// Check for specific error patterns that indicate permanent failure
		if t.isPermanentFailure(err) {
			return fmt.Errorf("permanent authentication failure: %w", err)
		}

		// Apply exponential backoff with jitter, but respect context deadline
		delay := t.calculateRetryDelay(attempt)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return fmt.Errorf("%w after %d attempts: %w", ErrTagAuthFailed, t.config.RetryConfig.MaxAttempts, lastErr)
}

// authenticateWithRetryContext implements progressive retry strategy with context support
func (t *MIFARETag) authenticateWithRetryContext(ctx context.Context, sector uint8, keyType byte, key []byte) error {
	var lastErr error

	for attempt := range t.config.RetryConfig.MaxAttempts {
		// Check for context cancellation before each attempt
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		level := t.getRetryLevel(attempt)

		// Apply recovery strategy based on level
		if err := t.applyRetryStrategy(ctx, level, lastErr); err != nil {
			return fmt.Errorf("recovery strategy failed: %w", err)
		}

		// Check context after recovery strategy
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		// Attempt authentication with context
		err := t.Authenticate(ctx, sector, keyType, key)
		if err == nil {
			return nil
		}

		lastErr = err

		// Check for specific error patterns that indicate permanent failure
		if t.isPermanentFailure(err) {
			return fmt.Errorf("permanent authentication failure: %w", err)
		}

		// Apply exponential backoff with jitter, but respect context deadline
		delay := t.calculateRetryDelay(attempt)

		// Create a timer for the delay, but also watch for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return fmt.Errorf("%w after %d attempts: %w", ErrTagAuthFailed, t.config.RetryConfig.MaxAttempts, lastErr)
}

// getRetryLevel determines the retry level based on attempt number
func (*MIFARETag) getRetryLevel(attempt int) retryLevel {
	switch {
	case attempt < 2:
		return retryLight
	case attempt < 3:
		return retryModerate
	case attempt < 4:
		return retryHeavy
	default:
		return retryNuclear
	}
}

// applyRetryStrategy implements the progressive recovery strategy
func (t *MIFARETag) applyRetryStrategy(ctx context.Context, level retryLevel, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	switch level {
	case retryLight:
		// Light: Just a small delay, no special action needed
		return nil

	case retryModerate:
		// Moderate: Card reinitialization (critical fix from research)
		// InRelease clears HALT/auth states before re-detection
		_ = t.device.InRelease(ctx)
		_, err := t.device.InListPassiveTarget(ctx, 0x00)
		if err != nil {
			return fmt.Errorf("card reinitialization failed: %w", err)
		}

		// Clear authentication state
		t.authMutex.Lock()
		t.lastAuthSector = -1
		t.lastAuthKeyType = 0
		t.authMutex.Unlock()

		return nil

	case retryHeavy:
		// Heavy: RF field reset sequence (if device supports it)
		// Note: This would require device-level support for field control
		// For now, we do a longer reinitialization sequence
		for range 3 {
			if err := ctx.Err(); err != nil {
				return err
			}
			// InRelease clears HALT/auth states before re-detection
			_ = t.device.InRelease(ctx)
			_, err := t.device.InListPassiveTarget(ctx, 0x00)
			if err == nil {
				break
			}
			time.Sleep(t.config.HardwareDelay)
		}

		t.authMutex.Lock()
		t.lastAuthSector = -1
		t.lastAuthKeyType = 0
		t.authMutex.Unlock()

		return nil

	case retryNuclear:
		// Nuclear: Complete reinitialization
		return t.ResetAuthState(ctx)

	default:
		return nil
	}
}

// calculateRetryDelay implements exponential backoff with jitter
func (t *MIFARETag) calculateRetryDelay(attempt int) time.Duration {
	// Exponential backoff: baseDelay * 2^attempt
	if attempt > 30 { // Prevent overflow
		attempt = 30
	}
	shiftAmount := uint(attempt) //nolint:gosec // Already bounds-checked above (0-30)
	delay := t.config.RetryConfig.InitialBackoff * time.Duration(1<<shiftAmount)
	if delay > t.config.RetryConfig.MaxBackoff {
		delay = t.config.RetryConfig.MaxBackoff
	}

	// Add random jitter based on configured factor
	if t.config.RetryConfig.Jitter > 0 {
		jitterAmount := float64(delay) * t.config.RetryConfig.Jitter
		jitterMax := big.NewInt(int64(jitterAmount))
		if jitterMax.Int64() > 0 {
			jitterBig, _ := rand.Int(rand.Reader, jitterMax)
			jitter := time.Duration(jitterBig.Int64())
			return delay + jitter
		}
	}
	return delay
}

// isPermanentFailure checks if an error indicates a permanent failure
func (*MIFARETag) isPermanentFailure(err error) bool {
	errStr := strings.ToLower(err.Error())

	// Check for specific error patterns that indicate permanent issues
	permanentPatterns := []string{
		"invalid key type",
		"mifare key must be 6 bytes",
		"cannot write to manufacturer block",
	}

	for _, pattern := range permanentPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// tryChineseCloneUnlock attempts Chinese clone unlock sequences
func (t *MIFARETag) tryChineseCloneUnlock(ctx context.Context, _ uint8) bool {
	if ctx.Err() != nil {
		return false
	}

	// Try Gen1 unlock sequence (0x40 for 7-bit, 0x43 for 8-bit)
	commands := []byte{chineseCloneUnlock7Bit, chineseCloneUnlock8Bit}

	for _, cmd := range commands {
		if ctx.Err() != nil {
			return false
		}
		_, err := t.device.SendDataExchange(ctx, []byte{cmd})
		if err == nil {
			// Unlock successful - this is a Gen1 clone tag
			return true
		}
	}

	return false
}

// GetTimingVariance returns the timing variance for hardware issue detection
func (t *MIFARETag) GetTimingVariance() time.Duration {
	return t.timing.getVariance()
}

// GetDevice returns the underlying PN532 device for direct access
func (t *MIFARETag) GetDevice() *Device {
	return t.device
}

// IsTimingUnstable checks if timing variance indicates hardware issues
func (t *MIFARETag) IsTimingUnstable() bool {
	variance := t.timing.getVariance()
	// High variance (>1000ms) indicates hardware issues per research
	return variance > 1000*time.Millisecond
}

// AnalyzeLastError provides detailed error analysis based on research findings
func (*MIFARETag) AnalyzeLastError(err error) string {
	if err == nil {
		return "No error"
	}

	errStr := err.Error()

	// Pattern analysis based on research document
	if strings.Contains(errStr, "14") {
		return "Error 0x14: Wrong key or compatibility issues with Chinese clone"
	}
	if strings.Contains(errStr, "01") {
		return "Error 0x01: Timeout - insufficient retries or timing issues"
	}
	if strings.Contains(errStr, "27") {
		return "Error 0x27: Improper state management"
	}
	if strings.Contains(errStr, "80 80 80") {
		return "PN532 firmware bug: successful auth but read failure (sectors 1-15 after sector 0)"
	}
	if strings.Contains(errStr, "data exchange error") {
		return "Communication error - may benefit from InCommunicateThru fallback"
	}

	return fmt.Sprintf("Generic error: %s", errStr)
}

// formatForNDEFWithKey formats a blank MIFARE Classic tag for NDEF use with a specific blank key
func (t *MIFARETag) determineMaxSectors() uint8 {
	if t.IsMIFARE4K() {
		return 40 // MIFARE Classic 4K has 40 sectors (0-39)
	}
	return 16 // MIFARE Classic 1K has 16 sectors (0-15)
}

func (t *MIFARETag) updateSectorKeys(ctx context.Context, sector uint8, ndefKeyBytes []byte) error {
	// Calculate sector trailer block
	trailerBlock := sector*4 + 3

	// Read current sector trailer to preserve access bits
	trailerData, err := t.ReadBlock(ctx, trailerBlock)
	if err != nil {
		return fmt.Errorf("%w (sector %d trailer): %w", ErrTagReadFailed, sector, err)
	}

	// Update keys in trailer (keep access bits unchanged)
	// Trailer format: Key A (6 bytes) + Access Bits (4 bytes) + Key B (6 bytes)
	copy(trailerData[0:6], ndefKeyBytes)   // Key A
	copy(trailerData[10:16], ndefKeyBytes) // Key B

	// Write updated trailer
	if err := t.WriteBlock(ctx, trailerBlock, trailerData); err != nil {
		return fmt.Errorf("%w (sector %d trailer): %w", ErrTagWriteFailed, sector, err)
	}

	return nil
}

func (t *MIFARETag) reAuthenticateWithNDEFKey(ctx context.Context, sector uint8, ndefKeyBytes []byte) error {
	// CRITICAL FIX: Re-authenticate with the new NDEF key
	// This ensures the PN532 authentication state matches the new keys on the tag
	if err := t.AuthenticateRobust(ctx, sector, MIFAREKeyA, ndefKeyBytes); err != nil {
		return fmt.Errorf("failed to re-authenticate sector %d with new NDEF key: %w", sector, err)
	}
	return nil
}

func clearKeyBytes(keyBytes []byte) {
	for i := range keyBytes {
		keyBytes[i] = 0
	}
}

func (t *MIFARETag) formatForNDEFWithKey(ctx context.Context, blankKey []byte) error {
	maxSectors := t.determineMaxSectors()
	ndefKeyBytes := t.ndefKey.bytes()

	for sector := uint8(1); sector < maxSectors; sector++ {
		// First authenticate with the blank key
		if err := t.AuthenticateRobust(ctx, sector, MIFAREKeyA, blankKey); err != nil {
			// If we can't authenticate, assume this sector is already formatted or protected
			continue
		}

		if err := t.updateSectorKeys(ctx, sector, ndefKeyBytes); err != nil {
			return err
		}

		if err := t.reAuthenticateWithNDEFKey(ctx, sector, ndefKeyBytes); err != nil {
			clearKeyBytes(ndefKeyBytes)
			return err
		}
	}

	clearKeyBytes(ndefKeyBytes)

	// Add a small delay to let the tag process the key changes
	time.Sleep(t.config.HardwareDelay)

	return nil
}

// DebugInfo returns detailed debug information about the MIFARE tag
func (t *MIFARETag) DebugInfo() string {
	return t.DebugInfoWithNDEF(t)
}

// WriteText writes a simple text record to the MIFARE tag
func (t *MIFARETag) WriteText(ctx context.Context, text string) error {
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
