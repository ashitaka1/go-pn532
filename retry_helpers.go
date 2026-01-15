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
	"fmt"
	"time"
)

// ReadNDEFFunc defines a function that reads NDEF data from a tag
type ReadNDEFFunc func() (*NDEFMessage, error)

// WriteNDEFFunc defines a function that writes NDEF data to a tag
type WriteNDEFFunc func(ctx context.Context) error

// IsRetryableFunc defines a function that determines if an error is retryable
type IsRetryableFunc func(error) bool

// readNDEFWithRetry implements the common retry logic for both NTAG and MIFARE tags.
// This addresses the "empty valid tag" problem where tags are detected but return no data,
// and handles RF instability during card sliding into a reader slot.
// Uses exponential backoff delays to allow RF field stabilization.
func readNDEFWithRetry(readFunc ReadNDEFFunc, isRetryable IsRetryableFunc, tagType string) (*NDEFMessage, error) {
	const maxRetries = 3

	// Use exponential backoff matching WriteNDEFWithRetry - gives time for RF to stabilize
	// during card sliding scenarios where communication is initially unreliable
	retryDelays := []time.Duration{
		100 * time.Millisecond,
		150 * time.Millisecond,
		250 * time.Millisecond,
	}

	for i := range maxRetries {
		// Try to read NDEF data
		msg, err := readFunc()
		if err != nil {
			// Hard error during read - check if we should retry
			if i < maxRetries-1 && isRetryable(err) {
				delay := retryDelays[i]
				Debugf("%s NDEF read attempt %d failed (retrying after %v): %v", tagType, i+1, delay, err)
				time.Sleep(delay)
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
			delay := retryDelays[i]
			Debugf("%s NDEF read attempt %d returned empty data (retrying after %v)", tagType, i+1, delay)
			time.Sleep(delay)
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
