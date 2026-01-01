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

package frame

import (
	"github.com/ZaparooProject/go-pn532"
)

// ValidateFrameLength validates the frame length field and length checksum
// Returns the validated frame length and whether a retry is needed (NACK should be sent)
// This consolidates the validateFrameLength logic from UART and I2C transports
func ValidateFrameLength(
	buf []byte, off, totalLen int, operation, port string,
) (frameLen int, shouldRetry bool, err error) {
	// Increment offset to point to length byte (matching original behavior)
	off++

	// Check we have enough bytes for length and length checksum
	if off+1 >= totalLen {
		return 0, false, &pn532.TransportError{
			Op:        operation,
			Port:      port,
			Err:       pn532.ErrFrameCorrupted,
			Type:      pn532.ErrorTypeTransient,
			Retryable: true,
		}
	}

	frameLen = int(buf[off])
	lengthChecksum := buf[off+1]

	// Validate length checksum (LEN + LCS should equal 0)
	if ((frameLen + int(lengthChecksum)) & 0xFF) != 0 {
		return 0, true, nil
	}

	return frameLen, false, nil
}

// ValidateFrameChecksum validates the frame data checksum
// Returns true if checksum is invalid (requiring NACK), false if valid
// This consolidates the validateFrameChecksum logic from UART and I2C transports
func ValidateFrameChecksum(buf []byte, start, end int) bool {
	// Handle invalid slice bounds - negative indices or out of range
	if start < 0 || end < 0 || start > end || end > len(buf) {
		return true
	}

	chk := byte(0)
	for _, b := range buf[start:end] {
		chk += b
	}

	return chk != 0
}
