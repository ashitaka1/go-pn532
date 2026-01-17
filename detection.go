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
	"context"
	"errors"
	"fmt"
	"time"
)

// WaitForTag waits for a tag to be detected with the given context.
// This is a high-level convenience function that handles the async tag detection
// pattern with error handling and timeout management.
//
// It automatically manages the polling loop, error recovery, and provides
// clean timeout handling through the context.
//
// Example usage:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	tag, err := device.WaitForTag(ctx)
//	if err != nil {
//	    if errors.Is(err, context.DeadlineExceeded) {
//	        fmt.Println("Timeout: no tag detected")
//	    }
//	    return err
//	}
//
//	fmt.Printf("Tag detected: %s\n", tag.UID)
func (*Device) handleDetectionError(errorCount *int, err error) error {
	const (
		maxErrors      = 10
		errorThreshold = 3
	)

	*errorCount++

	// Log first few errors for debugging
	if *errorCount <= errorThreshold {
		Debugf("Tag detection error #%d: %v", *errorCount, err)
	}

	// Give up after too many errors
	if *errorCount > maxErrors {
		return fmt.Errorf("too many detection errors (%d), last error: %w", *errorCount, err)
	}

	return nil
}

func (*Device) pause(ctx context.Context, interval time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(interval):
		return nil
	}
}

func (d *Device) attemptDetection(ctx context.Context, errorCount *int) (*DetectedTag, error) {
	detectedTag, err := d.DetectTag(ctx)
	if err != nil {
		// ErrNoTagDetected is expected during polling, not a real error
		if errors.Is(err, ErrNoTagDetected) {
			if *errorCount == 0 {
				Debugln("No tag detected, continuing to poll...")
			}
			return nil, ErrNoTagDetected
		}
		// Handle other errors through the error counting mechanism
		return nil, d.handleDetectionError(errorCount, err)
	}

	if detectedTag != nil {
		Debugf("Tag detected successfully: UID=%s Type=%s", detectedTag.UID, detectedTag.Type)
		return detectedTag, nil
	}

	// This shouldn't happen - DetectTag should return ErrNoTagDetected when no tag found
	if *errorCount == 0 {
		Debugln("No tag detected, continuing to poll...")
	}
	return nil, ErrNoTagDetected
}

func (d *Device) WaitForTag(ctx context.Context) (*DetectedTag, error) {
	const pollInterval = 100 * time.Millisecond
	errorCount := 0

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		detectedTag, err := d.attemptDetection(ctx, &errorCount)
		if err != nil {
			// For any error (including ErrNoTagDetected), pause and continue
			if pauseErr := d.pause(ctx, pollInterval); pauseErr != nil {
				return nil, pauseErr
			}
			continue
		}

		return detectedTag, nil
	}
}

// SimplePoll performs straightforward polling with InListPassiveTarget on a regular schedule
// This is a simplified alternative to WaitForTag that removes complex error handling and
// strategy selection, providing predictable poll-poll-poll behavior at regular intervals.
func (d *Device) SimplePoll(ctx context.Context, interval time.Duration) (*DetectedTag, error) {
	// Set transport timeout for individual polling attempts
	if err := d.transport.SetTimeout(interval); err != nil {
		return nil, fmt.Errorf("failed to set transport timeout: %w", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			// Try to detect a tag
			tag, err := d.InListPassiveTarget(ctx, 0x00)
			if err != nil {
				// Continue polling on errors (device might be temporarily busy)
				Debugf("Polling error (continuing): %v", err)
				continue
			}

			if tag != nil {
				return tag, nil
			}
			// No tag detected this cycle, continue polling
		}
	}
}

// selectDetectionStrategy chooses the appropriate detection strategy
// Integrates with the polling strategy system for intelligent strategy selection

// InitiatorListPassiveTargets detects a passive target with optional filtering
// This is a compatibility method for the PN532 InListPassiveTarget command
func (d *Device) InitiatorListPassiveTargets(
	ctx context.Context, tagType TagType, uid []byte,
) (*DetectedTag, error) {
	// Detect tag using standard detection (baudRate 0x00 for 106 kbps Type A)
	tag, err := d.DetectTag(ctx)
	if err != nil {
		return nil, err
	}

	if tag == nil {
		return nil, nil //nolint:nilnil // nil tag, nil error is valid "no tag found" response
	}

	// Apply filtering
	if !shouldIncludeTag(tag, tagType, uid) {
		return nil, nil //nolint:nilnil // nil tag, nil error is valid "tag filtered out" response
	}

	return tag, nil
}

// shouldIncludeTag determines if a tag should be included based on filters
func shouldIncludeTag(tag *DetectedTag, tagType TagType, uid []byte) bool {
	if !matchesTagTypeFilter(tag, tagType) {
		return false
	}
	return matchesUIDFilter(tag, uid)
}

// matchesTagTypeFilter checks if tag matches the tag type filter
func matchesTagTypeFilter(tag *DetectedTag, tagType TagType) bool {
	return tagType == TagTypeAny || tag.Type == tagType
}

// matchesUIDFilter checks if tag UID matches the UID filter
func matchesUIDFilter(tag *DetectedTag, uid []byte) bool {
	if len(uid) == 0 {
		return true // No UID filter
	}

	if len(tag.UIDBytes) < len(uid) {
		return false
	}

	// Check if the beginning of the tag UID matches the filter
	for i, b := range uid {
		if tag.UIDBytes[i] != b {
			return false
		}
	}
	return true
}

// identifyTagType identifies the tag type based on ATQ and SAK values
func (d *Device) identifyTagType(atq []byte, sak byte) TagType {
	if len(atq) != 2 {
		return TagTypeUnknown
	}

	// NTAG identification patterns
	if d.isNTAGPattern(atq, sak) {
		return TagTypeNTAG
	}

	// MIFARE Classic identification patterns
	if d.isMIFAREPattern(atq, sak) {
		return TagTypeMIFARE
	}

	return TagTypeUnknown
}

// isNTAGPattern checks if the ATQ and SAK match known NTAG patterns
func (*Device) isNTAGPattern(atq []byte, sak byte) bool {
	Debugf("isNTAGPattern - checking ATQ=%X, SAK=0x%02X", atq, sak)

	if isStandardNTAGPattern(atq, sak) {
		return true
	}

	if isAdditionalNTAGPattern(atq, sak) {
		return true
	}

	Debugln("No NTAG pattern matched")
	return false
}

// isStandardNTAGPattern checks standard NTAG patterns (ISO14443-3A compliant)
func isStandardNTAGPattern(atq []byte, sak byte) bool {
	if sak == 0x00 && isStandardNTAGATQPattern(atq) {
		Debugln("NTAG pattern matched (SAK=0x00)")
		return true
	}

	if sak == 0x04 && isStandardATQPattern(atq) {
		Debugln("NTAG pattern matched (SAK=0x04)")
		return true
	}

	return false
}

// isStandardNTAGATQPattern checks for standard NTAG ATQ patterns including byte-swapped variants
func isStandardNTAGATQPattern(atq []byte) bool {
	return (atq[0] == 0x00 && atq[1] == 0x44) ||
		(atq[0] == 0x44 && atq[1] == 0x00) || // Byte-swapped (common in clones)
		(atq[0] == 0x01 && atq[1] == 0x01) // Alternative NTAG215 pattern
}

// isStandardATQPattern checks for standard ATQ patterns
func isStandardATQPattern(atq []byte) bool {
	return (atq[0] == 0x00 && atq[1] == 0x44) ||
		(atq[0] == 0x44 && atq[1] == 0x00)
}

// isAdditionalNTAGPattern checks additional NTAG215-specific patterns observed in field testing
func isAdditionalNTAGPattern(atq []byte, sak byte) bool {
	if (atq[0] == 0x01 && atq[1] == 0x00 && sak == 0x44) ||
		(atq[0] == 0x00 && atq[1] == 0x04 && sak == 0x00) || // Some NTAG215 variants
		(atq[0] == 0x04 && atq[1] == 0x00 && sak == 0x00) { // Byte-swapped variant
		Debugln("NTAG pattern matched (additional patterns)")
		return true
	}
	return false
}

// isMIFAREPattern checks if the ATQ and SAK match known MIFARE patterns
func (*Device) isMIFAREPattern(atq []byte, sak byte) bool {
	Debugf("isMIFAREPattern - checking ATQ=%X, SAK=0x%02X", atq, sak)

	// MIFARE Classic 1K identification
	if atq[0] == 0x00 && atq[1] == 0x04 && sak == 0x08 {
		Debugln("MIFARE pattern matched (Classic 1K)")
		return true
	}
	// MIFARE Classic 4K identification
	if atq[0] == 0x00 && atq[1] == 0x02 && sak == 0x18 {
		Debugln("MIFARE pattern matched (Classic 4K)")
		return true
	}

	// Additional MIFARE-compatible patterns that may work with MIFARE commands
	// ATQ=0100, SAK=0x04 - seen on some MIFARE-compatible cards
	if atq[0] == 0x01 && atq[1] == 0x00 && sak == 0x04 {
		Debugln("MIFARE pattern matched (compatible variant)")
		return true
	}

	Debugln("No MIFARE pattern matched")
	return false
}

// CreateTag creates a Tag instance based on the detected tag
func (d *Device) CreateTag(detected *DetectedTag) (Tag, error) {
	switch detected.Type {
	case TagTypeNTAG:
		return NewNTAGTag(d, detected.UIDBytes, detected.SAK), nil
	case TagTypeMIFARE:
		return NewMIFARETag(d, detected.UIDBytes, detected.SAK), nil
	case TagTypeFeliCa:
		return NewFeliCaTag(d, detected.TargetData)
	case TagTypeUnknown:
		return nil, ErrInvalidTag
	case TagTypeAny:
		return nil, ErrInvalidTag
	default:
		return nil, ErrInvalidTag
	}
}
