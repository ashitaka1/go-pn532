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
	"context"
	"fmt"
	"time"
)

// ReadNDEFFunc defines a function that reads NDEF data from a tag
type ReadNDEFFunc func() (*NDEFMessage, error)

// WriteNDEFFunc defines a function that writes NDEF data to a tag
type WriteNDEFFunc func(ctx context.Context) error

// IsRetryableFunc defines a function that determines if an error is retryable
type IsRetryableFunc func(error) bool

// readNDEFWithRetry implements the common retry logic for both NTAG and MIFARE tags
// This addresses the "empty valid tag" problem where tags are detected but return no data
func readNDEFWithRetry(readFunc ReadNDEFFunc, isRetryable IsRetryableFunc, tagType string) (*NDEFMessage, error) {
	const maxRetries = 3
	const retryDelay = 10 * time.Millisecond

	for i := range maxRetries {
		// Try to read NDEF data
		msg, err := readFunc()
		if err != nil {
			// Hard error during read - check if we should retry
			if i < maxRetries-1 && isRetryable(err) {
				Debugf("%s NDEF read attempt %d failed (retrying): %v", tagType, i+1, err)
				time.Sleep(retryDelay)
				continue
			}
			return nil, err
		}

		// Check if we got valid, non-empty data
		if msg != nil && len(msg.Records) > 0 {
			// Success! We got valid data
			Debugf("%s NDEF read successful on attempt %d", tagType, i+1)
			return msg, nil
		}

		// We got a valid response but it's empty - this is the "empty valid tag" issue
		if i < maxRetries-1 {
			Debugf("%s NDEF read attempt %d returned empty data (retrying)", tagType, i+1)
			time.Sleep(retryDelay)
			continue
		}

		// All retries exhausted with empty data - this is the "empty valid tag" issue
		Debugf("%s NDEF read exhausted retries with empty data", tagType)
		if msg == nil || len(msg.Records) == 0 {
			return nil, ErrTagEmptyData
		}
		return msg, nil
	}

	// This should never be reached, but just in case
	return nil, fmt.Errorf("failed to read %s NDEF data after %d retries", tagType, maxRetries)
}

// WriteNDEFWithRetry wraps NDEF write operations with retry logic.
// This addresses intermittent write failures due to card placement issues or timing problems.
// The entire write operation is retried on failure (operation-level retry).
//
//nolint:gocognit,revive // Retry logic inherently requires multiple branches for proper error handling
func WriteNDEFWithRetry(ctx context.Context, writeFunc WriteNDEFFunc, maxRetries int, tagType string) error {
	if maxRetries <= 0 {
		maxRetries = 3
	}

	// Use exponential backoff with shorter initial delays for writes
	// since card placement is usually the issue
	retryDelays := []time.Duration{
		100 * time.Millisecond,
		150 * time.Millisecond,
		250 * time.Millisecond,
	}

	var lastErr error
	for i := range maxRetries {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := writeFunc(ctx)
		if err == nil {
			if i > 0 {
				Debugf("%s NDEF write successful on attempt %d", tagType, i+1)
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !IsRetryable(err) {
			Debugf("%s NDEF write failed with non-retryable error: %v", tagType, err)
			return err
		}

		// Don't retry on last attempt
		if i >= maxRetries-1 {
			break
		}

		Debugf("%s NDEF write attempt %d failed (retrying): %v", tagType, i+1, err)

		// Wait before retry with exponential backoff
		// Use the last delay value if we've exceeded the array length
		delay := retryDelays[len(retryDelays)-1]
		if i < len(retryDelays) {
			delay = retryDelays[i]
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("failed to write %s NDEF data after %d retries: %w", tagType, maxRetries, lastErr)
}
