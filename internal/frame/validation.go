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
