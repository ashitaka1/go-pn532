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

package tagops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ZaparooProject/go-pn532"
)

// Retry constants for tag initialization.
// These values are tuned for the "sliding card into slot" use case where
// RF communication may be unstable during the slide (~1 second duration).
const (
	// stabilizationDelay is the time to wait after initial detection before
	// attempting initialization. This allows the card to settle in position.
	stabilizationDelay = 75 * time.Millisecond

	// initMaxRetries is the number of initialization attempts per detection cycle.
	initMaxRetries = 2

	// initRetryDelay is the time to wait between initialization retries.
	initRetryDelay = 50 * time.Millisecond

	// maxRedetectAttempts is the number of times to re-poll for the tag if
	// initialization keeps failing. This handles cases where the initial
	// detection caught the card mid-slide with corrupt data.
	maxRedetectAttempts = 3
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
//
// This function implements a robust initialization strategy for the "sliding
// card into slot" use case:
//  1. Stabilization delay - wait for card to settle after detection
//  2. Multiple init retries - handle transient RF communication failures
//  3. Re-detection loop - if init keeps failing, re-poll for the tag
//     (the initial detection may have caught the card mid-slide)
func (t *TagOperations) InitFromDetectedTag(ctx context.Context, tag *pn532.DetectedTag) error {
	if tag == nil {
		return ErrNoTag
	}

	t.tag = tag
	originalUID := tag.UID

	// Stabilization delay - let the card settle in position before reading
	if err := t.waitForStabilization(ctx); err != nil {
		return err
	}

	// Try initialization with re-detection fallback
	for redetect := range maxRedetectAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}

		// Attempt to initialize the tag
		if err := t.detectAndInitializeTag(ctx); err == nil {
			return nil
		}

		// If this isn't the last redetect attempt, try re-polling for the tag
		if redetect < maxRedetectAttempts-1 {
			t.attemptRedetection(ctx, originalUID, redetect)
		}
	}

	return ErrUnsupportedTag
}

// waitForStabilization waits for the stabilization delay to let the card settle.
func (*TagOperations) waitForStabilization(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(stabilizationDelay):
		return nil
	}
}

// attemptRedetection tries to re-detect the same tag after init failure.
func (t *TagOperations) attemptRedetection(ctx context.Context, originalUID string, attempt int) {
	pn532.Debugf("Tag init failed, attempting re-detection (attempt %d/%d)", attempt+1, maxRedetectAttempts)

	newTag, err := t.device.DetectTag(ctx)
	if err != nil {
		pn532.Debugf("Re-detection failed: %v", err)
		return
	}
	if newTag == nil {
		pn532.Debugln("Re-detection returned no tag")
		return
	}

	// Verify it's the same tag (same UID)
	if newTag.UID != originalUID {
		pn532.Debugf("Re-detected different tag (got %s, expected %s)", newTag.UID, originalUID)
		return
	}

	t.tag = newTag
	pn532.Debugf("Re-detection successful, retrying initialization")
}

// GetTagType returns the detected tag type
func (t *TagOperations) GetTagType() pn532.TagType {
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
		// Tag was identified as MIFARE based on SAK pattern.
		// NTAG uses SAK=0x00, so no fallback needed.
		if t.tryInitMIFARE(ctx) {
			return nil
		}
		return ErrUnsupportedTag

	case pn532.TagTypeNTAG:
		// Tag was identified as NTAG based on SAK pattern (SAK=0x00).
		// MIFARE Classic uses different SAK values, so no fallback needed.
		if t.tryInitNTAG(ctx) {
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
// Uses retry logic to handle transient RF communication failures.
//
// This retries on ANY error from DetectType(), not just IsRetryable() errors.
// During card sliding, we may get garbage data that causes validation failures
// (e.g., "invalid capability container") which are worth retrying as the card
// may have settled by the next attempt.
func (t *TagOperations) tryInitNTAG(ctx context.Context) bool {
	ntag := pn532.NewNTAGTag(t.device, t.tag.UIDBytes, t.tag.SAK)

	var lastErr error
	for i := range initMaxRetries {
		if err := ctx.Err(); err != nil {
			return false
		}

		err := ntag.DetectType(ctx)
		if err == nil {
			t.tagType = pn532.TagTypeNTAG
			t.ntagInstance = ntag
			t.totalPages = int(ntag.GetTotalPages())
			return true
		}

		lastErr = err

		// Check if this is a definitive "not an NTAG" error (real 4-byte UID = MIFARE)
		// vs a transient error worth retrying
		if isDefinitivelyNotNTAG(err) {
			pn532.Debugf("NTAG init: definitively not an NTAG tag: %v", err)
			break
		}

		if i < initMaxRetries-1 {
			pn532.Debugf("NTAG init attempt %d/%d failed (retrying): %v", i+1, initMaxRetries, err)
			time.Sleep(initRetryDelay)
		}
	}

	if lastErr != nil {
		pn532.Debugf("NTAG init failed after %d attempts: %v", initMaxRetries, lastErr)
	}
	return false
}

// isDefinitivelyNotNTAG returns true if the error indicates this is definitely
// not an NTAG tag (e.g., a MIFARE Classic with a real 4-byte UID), as opposed
// to a transient error that might succeed on retry.
func isDefinitivelyNotNTAG(err error) bool {
	if err == nil {
		return false
	}
	// A real 4-byte UID (not the zero fallback) means MIFARE Classic
	// This is detected by the error message not containing "parse failed"
	// which indicates the zero-UID fallback from corrupt detection data
	errMsg := err.Error()
	return strings.Contains(errMsg, "UID must be 7 bytes") &&
		!strings.Contains(errMsg, "parse failed")
}

// tryInitMIFARE attempts to initialize as a MIFARE tag. Returns true on success.
// Uses retry logic to handle transient RF communication failures.
//
// Like tryInitNTAG, this retries on any error to handle transient RF issues
// during card sliding.
func (t *TagOperations) tryInitMIFARE(ctx context.Context) bool {
	mifare := pn532.NewMIFARETag(t.device, t.tag.UIDBytes, t.tag.SAK)

	var lastErr error
	for i := range initMaxRetries {
		if err := ctx.Err(); err != nil {
			return false
		}

		// Try to read block 4 (first block of sector 1) using automatic authentication
		// This will use the built-in NDEF key authentication
		_, err := mifare.ReadBlockAuto(ctx, 4)
		if err == nil {
			t.tagType = pn532.TagTypeMIFARE
			t.mifareInstance = mifare
			return true
		}

		lastErr = err

		if i < initMaxRetries-1 {
			pn532.Debugf("MIFARE init attempt %d/%d failed (retrying): %v", i+1, initMaxRetries, err)
			time.Sleep(initRetryDelay)
		}
	}

	if lastErr != nil {
		pn532.Debugf("MIFARE init failed after %d attempts: %v", initMaxRetries, lastErr)
	}
	return false
}
