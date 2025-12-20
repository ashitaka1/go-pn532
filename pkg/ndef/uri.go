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

package ndef

import (
	"errors"
	"strings"
)

// URI record constants.
const URIRecordType = "U"

// URI record errors.
var (
	ErrURIPayloadTooShort   = errors.New("ndef: URI payload too short")
	ErrURIInvalidPrefixCode = errors.New("ndef: invalid URI prefix code")
)

// URI prefix codes as defined by NFC Forum URI RTD specification.
// Index 0 means no prefix (raw URI).
var uriPrefixes = []string{
	"",                           // 0x00 - No prepending
	"http://www.",                // 0x01
	"https://www.",               // 0x02
	"http://",                    // 0x03
	"https://",                   // 0x04
	"tel:",                       // 0x05
	"mailto:",                    // 0x06
	"ftp://anonymous:anonymous@", // 0x07
	"ftp://ftp.",                 // 0x08
	"ftps://",                    // 0x09
	"sftp://",                    // 0x0A
	"smb://",                     // 0x0B
	"nfs://",                     // 0x0C
	"ftp://",                     // 0x0D
	"dav://",                     // 0x0E
	"news:",                      // 0x0F
	"telnet://",                  // 0x10
	"imap:",                      // 0x11
	"rtsp://",                    // 0x12
	"urn:",                       // 0x13
	"pop:",                       // 0x14
	"sip:",                       // 0x15
	"sips:",                      // 0x16
	"tftp:",                      // 0x17
	"btspp://",                   // 0x18
	"btl2cap://",                 // 0x19
	"btgoep://",                  // 0x1A
	"tcpobex://",                 // 0x1B
	"irdaobex://",                // 0x1C
	"file://",                    // 0x1D
	"urn:epc:id:",                // 0x1E
	"urn:epc:tag:",               // 0x1F
	"urn:epc:pat:",               // 0x20
	"urn:epc:raw:",               // 0x21
	"urn:epc:",                   // 0x22
	"urn:nfc:",                   // 0x23
}

// NewURIRecord creates a new NDEF URI record.
// The URI is automatically compressed using the NFC Forum URI prefix table
// if a matching prefix is found.
func NewURIRecord(uri string) *Record {
	payload := EncodeURIPayload(uri)
	return &Record{
		TNF:     TNFWellKnown,
		Type:    URIRecordType,
		Payload: payload,
	}
}

// ParseURIRecord extracts the full URI from a URI record payload.
func ParseURIRecord(payload []byte) (string, error) {
	if len(payload) < 1 {
		return "", ErrURIPayloadTooShort
	}

	prefixCode := int(payload[0])
	if prefixCode >= len(uriPrefixes) {
		return "", ErrURIInvalidPrefixCode
	}

	prefix := uriPrefixes[prefixCode]
	suffix := string(payload[1:])

	return prefix + suffix, nil
}

// DecodeURIPayload is an alias for ParseURIRecord for API consistency.
func DecodeURIPayload(payload []byte) (string, error) {
	return ParseURIRecord(payload)
}

// EncodeURIPayload creates a URI record payload with optimal prefix compression.
func EncodeURIPayload(uri string) []byte {
	// Find the longest matching prefix
	bestMatch := 0
	bestLen := 0

	// Search in reverse order to prefer longer prefixes
	// (e.g., "https://www." over "https://")
	for i := len(uriPrefixes) - 1; i >= 1; i-- {
		prefix := uriPrefixes[i]
		if strings.HasPrefix(uri, prefix) && len(prefix) > bestLen {
			bestMatch = i
			bestLen = len(prefix)
		}
	}

	// Build payload
	suffix := uri[bestLen:]
	payload := make([]byte, 1+len(suffix))
	payload[0] = byte(bestMatch)
	copy(payload[1:], suffix)

	return payload
}

// URIPrefixCode returns the prefix code for a given URI prefix string.
// Returns 0 if no match is found.
func URIPrefixCode(prefix string) byte {
	for i, p := range uriPrefixes {
		if p == prefix {
			return byte(i)
		}
	}
	return 0
}

// URIPrefixString returns the prefix string for a given code.
// Returns empty string for invalid codes.
func URIPrefixString(code byte) string {
	if int(code) < len(uriPrefixes) {
		return uriPrefixes[code]
	}
	return ""
}
