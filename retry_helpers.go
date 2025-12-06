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
	"fmt"
	"time"
)

// ReadNDEFFunc defines a function that reads NDEF data from a tag
type ReadNDEFFunc func() (*NDEFMessage, error)

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
				debugf("%s NDEF read attempt %d failed (retrying): %v", tagType, i+1, err)
				time.Sleep(retryDelay)
				continue
			}
			return nil, err
		}

		// Check if we got valid, non-empty data
		if msg != nil && len(msg.Records) > 0 {
			// Success! We got valid data
			debugf("%s NDEF read successful on attempt %d", tagType, i+1)
			return msg, nil
		}

		// We got a valid response but it's empty - this is the "empty valid tag" issue
		if i < maxRetries-1 {
			debugf("%s NDEF read attempt %d returned empty data (retrying)", tagType, i+1)
			time.Sleep(retryDelay)
			continue
		}

		// All retries exhausted with empty data - this is the "empty valid tag" issue
		debugf("%s NDEF read exhausted retries with empty data", tagType)
		if msg == nil || len(msg.Records) == 0 {
			return nil, ErrTagEmptyData
		}
		return msg, nil
	}

	// This should never be reached, but just in case
	return nil, fmt.Errorf("failed to read %s NDEF data after %d retries", tagType, maxRetries)
}
