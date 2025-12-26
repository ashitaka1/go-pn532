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
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/ZaparooProject/go-pn532/pkg/ndef"
)

// ParseNDEFMessage parses a complete NDEF message using go-ndef
func ParseNDEFMessage(data []byte) (*NDEFMessage, error) {
	// Validate NDEF message structure first
	if err := ValidateNDEFMessage(data); err != nil {
		return nil, fmt.Errorf("invalid NDEF message: %w", err)
	}

	// Strip TLV wrapper if present
	payload := extractNDEFPayload(data)
	if payload == nil {
		return nil, ErrNoNDEF
	}

	// Parse NDEF message
	msg := &ndef.Message{}
	if _, err := msg.Unmarshal(payload); err != nil {
		return nil, fmt.Errorf("failed to parse NDEF message: %w", err)
	}

	// Convert to our format
	result := &NDEFMessage{
		Records: make([]NDEFRecord, 0, len(msg.Records)),
	}

	for _, rec := range msg.Records {
		ndefRec, err := convertRecord(rec)
		if err != nil {
			// Skip records we can't parse
			continue
		}
		result.Records = append(result.Records, *ndefRec)
	}

	if len(result.Records) == 0 {
		return nil, ErrNoNDEF
	}

	return result, nil
}

// extractNDEFPayload extracts the NDEF message from TLV format
func extractNDEFPayload(data []byte) []byte {
	// Look for NDEF TLV (0x03)
	for i := range len(data) - 2 {
		if data[i] != 0x03 {
			continue
		}

		payload := extractTLVPayload(data, i)
		if payload != nil {
			return payload
		}
	}
	return nil
}

// extractTLVPayload extracts the payload from a TLV structure at the given offset
func extractTLVPayload(data []byte, offset int) []byte {
	if offset+1 >= len(data) {
		return nil
	}

	// Short format
	if data[offset+1] != 0xFF {
		return extractShortFormatPayload(data, offset)
	}

	// Long format
	return extractLongFormatPayload(data, offset)
}

// extractShortFormatPayload extracts payload from short format TLV
func extractShortFormatPayload(data []byte, offset int) []byte {
	length := int(data[offset+1])
	if offset+2+length <= len(data) {
		return data[offset+2 : offset+2+length]
	}
	return nil
}

// extractLongFormatPayload extracts payload from long format TLV
func extractLongFormatPayload(data []byte, offset int) []byte {
	if offset+4 > len(data) {
		return nil
	}

	length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	if offset+4+length <= len(data) {
		return data[offset+4 : offset+4+length]
	}
	return nil
}

// convertRecord converts a go-ndef record to our format
func convertRecord(rec *ndef.Record) (*NDEFRecord, error) {
	payloadBytes, err := extractPayloadBytes(rec)
	if err != nil {
		return nil, err
	}

	result := &NDEFRecord{
		Payload: payloadBytes,
	}

	return populateRecordByTNF(rec, result, payloadBytes)
}

// extractPayloadBytes extracts the payload bytes from an NDEF record
func extractPayloadBytes(rec *ndef.Record) ([]byte, error) {
	return rec.Payload, nil
}

// populateRecordByTNF populates the NDEF record based on TNF type
func populateRecordByTNF(rec *ndef.Record, result *NDEFRecord, payloadBytes []byte) (*NDEFRecord, error) {
	switch rec.TNF {
	case ndef.TNFWellKnown:
		return handleWellKnownType(rec, result, payloadBytes)
	case ndef.TNFMedia:
		return handleMediaType(rec, result, payloadBytes)
	case ndef.TNFAbsoluteURI:
		result.Type = NDEFRecordType("uri:" + rec.Type)
		return result, nil
	case ndef.TNFExternal:
		result.Type = NDEFRecordType("ext:" + rec.Type)
		return result, nil
	default:
		return nil, errors.New("unsupported TNF")
	}
}

// handleWellKnownType processes NFC Forum well-known types
func handleWellKnownType(rec *ndef.Record, result *NDEFRecord, payloadBytes []byte) (*NDEFRecord, error) {
	switch rec.Type {
	case "T": // Text
		result.Type = NDEFTypeText
		text, err := parseTextPayload(payloadBytes)
		if err != nil {
			Debugf("NDEF: failed to parse text payload (%d bytes): %v", len(payloadBytes), err)
			result.Text = "" // Return empty string for malformed payload
		} else {
			result.Text = text
		}
	case "U": // URI
		result.Type = NDEFTypeURI
		uri, err := parseURIPayload(payloadBytes)
		if err != nil {
			Debugf("NDEF: failed to parse URI payload (%d bytes): %v", len(payloadBytes), err)
			result.URI = "" // Return empty string for malformed payload
		} else {
			result.URI = uri
		}
	case "Sp": // Smart Poster
		result.Type = NDEFTypeSmartPoster
	default:
		return nil, fmt.Errorf("unknown well-known type: %s", rec.Type)
	}
	return result, nil
}

// handleMediaType processes media type records
func handleMediaType(rec *ndef.Record, result *NDEFRecord, payloadBytes []byte) (*NDEFRecord, error) {
	switch rec.Type {
	case "application/vnd.wfa.wsc":
		result.Type = NDEFTypeWiFi
		wifi, err := parseWiFiCredential(payloadBytes)
		if err != nil {
			Debugf("NDEF: failed to parse WiFi credential (%d bytes): %v", len(payloadBytes), err)
			result.WiFi = nil // Return nil for malformed payload
		} else {
			result.WiFi = wifi
		}
	case "text/vcard", "text/x-vcard":
		result.Type = NDEFTypeVCard
		vcard, err := parseVCard(string(payloadBytes))
		if err != nil {
			Debugf("NDEF: failed to parse vCard (%d bytes): %v", len(payloadBytes), err)
			result.VCard = nil // Return nil for malformed payload
		} else {
			result.VCard = vcard
		}
	default:
		// Generic media type
		result.Type = NDEFRecordType("media:" + rec.Type)
	}
	return result, nil
}

// parseTextPayload parses a text record payload
func parseTextPayload(payload []byte) (string, error) {
	if len(payload) < 1 {
		return "", errors.New("text payload too short")
	}

	// First byte contains status
	status := payload[0]
	langLen := int(status & 0x3F)

	if len(payload) < 1+langLen {
		return "", errors.New("invalid text payload length")
	}

	// Skip language code and return text
	return string(payload[1+langLen:]), nil
}

// parseURIPayload parses a URI record payload
func parseURIPayload(payload []byte) (string, error) {
	if len(payload) < 1 {
		return "", errors.New("URI payload too short")
	}

	// URI prefixes as defined in NFC Forum URI RTD
	prefixes := []string{
		"",
		"http://www.",
		"https://www.",
		"http://",
		"https://",
		"tel:",
		"mailto:",
		"ftp://anonymous:anonymous@",
		"ftp://ftp.",
		"ftps://",
		"sftp://",
		"smb://",
		"nfs://",
		"ftp://",
		"dav://",
		"news:",
		"telnet://",
		"imap:",
		"rtsp://",
		"urn:",
		"pop:",
		"sip:",
		"sips:",
		"tftp:",
		"btspp://",
		"btl2cap://",
		"btgoep://",
		"tcpobex://",
		"irdaobex://",
		"file://",
		"urn:epc:id:",
		"urn:epc:tag:",
		"urn:epc:pat:",
		"urn:epc:raw:",
		"urn:epc:",
		"urn:nfc:",
	}

	prefixCode := int(payload[0])
	if prefixCode >= len(prefixes) {
		return "", fmt.Errorf("invalid URI prefix code: %d", prefixCode)
	}

	return prefixes[prefixCode] + string(payload[1:]), nil
}

// BuildNDEFMessageEx creates NDEF data from multiple records
func BuildNDEFMessageEx(records []NDEFRecord) ([]byte, error) {
	// SECURITY: Validate record count
	if len(records) > MaxNDEFRecordCount {
		return nil, fmt.Errorf("%w: record count %d exceeds maximum %d",
			ErrSecurityViolation, len(records), MaxNDEFRecordCount)
	}

	if len(records) == 0 {
		return nil, errors.New("no records to build")
	}

	msg := &ndef.Message{
		Records: make([]*ndef.Record, 0, len(records)),
	}

	totalSize := 0

	for i := range records {
		// SECURITY: Validate individual record payload size
		if len(records[i].Payload) > MaxNDEFPayloadSize {
			return nil, fmt.Errorf("%w: record %d payload size %d exceeds maximum %d",
				ErrSecurityViolation, i, len(records[i].Payload), MaxNDEFPayloadSize)
		}

		totalSize += len(records[i].Payload) + 16 // Account for headers
		if totalSize > MaxNDEFMessageSize {
			return nil, fmt.Errorf("%w: total message size would exceed maximum", ErrSecurityViolation)
		}
		ndefRec, err := buildRecord(&records[i])
		if err != nil {
			return nil, fmt.Errorf("failed to build record: %w", err)
		}
		msg.Records = append(msg.Records, ndefRec)
	}

	// Set message flags on first and last records
	if len(msg.Records) > 0 {
		msg.Records[0].SetMB(true)
		msg.Records[len(msg.Records)-1].SetME(true)
	}

	// Marshal the message
	payload, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal NDEF message: %w", err)
	}

	// SECURITY: Final size validation
	if len(payload) > MaxNDEFMessageSize {
		return nil, fmt.Errorf("%w: marshaled payload size %d exceeds maximum", ErrSecurityViolation, len(payload))
	}

	// Add TLV wrapper
	header, err := calculateNDEFHeader(payload)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, len(header)+len(payload)+1)
	result = append(result, header...)
	result = append(result, payload...)
	result = append(result, ndefEnd...)

	// Validate the final message
	if err := ValidateNDEFMessage(result); err != nil {
		return nil, fmt.Errorf("generated invalid NDEF message: %w", err)
	}

	return result, nil
}

// buildRecord converts our record format to go-ndef format
func buildRecord(rec *NDEFRecord) (*ndef.Record, error) {
	switch rec.Type {
	case NDEFTypeText:
		return buildTextRecord(rec.Text), nil

	case NDEFTypeURI:
		return buildURIRecord(rec.URI), nil

	case NDEFTypeWiFi:
		if rec.WiFi == nil {
			return nil, errors.New("WiFi record missing credential data")
		}
		return BuildWiFiRecord(*rec.WiFi)

	case NDEFTypeVCard:
		if rec.VCard == nil {
			return nil, errors.New("vCard record missing contact data")
		}
		return BuildVCardRecord(rec.VCard)

	case NDEFTypeSmartPoster:
		// Smart poster records are not yet implemented
		return nil, errors.New("smart poster records not yet supported")

	case NDEFTypeBluetooth:
		// Bluetooth records are not yet implemented
		return nil, errors.New("bluetooth records not yet supported")

	default:
		// Handle media types, external types, etc.
		if strings.HasPrefix(string(rec.Type), "media:") {
			mediaType := strings.TrimPrefix(string(rec.Type), "media:")
			r := ndef.NewMediaRecord(mediaType, rec.Payload)
			// Clear message flags - they will be set by the message builder
			r.SetMB(false)
			r.SetME(false)
			return r, nil
		}

		return nil, fmt.Errorf("unsupported record type: %s", rec.Type)
	}
}

// buildTextRecord creates a text record
func buildTextRecord(text string) *ndef.Record {
	rec := ndef.NewTextRecord(text, "en")
	// Clear message flags - they will be set by the message builder
	rec.SetMB(false)
	rec.SetME(false)
	return rec
}

// buildURIRecord creates a URI record
func buildURIRecord(uri string) *ndef.Record {
	rec := ndef.NewURIRecord(uri)
	// Clear message flags - they will be set by the message builder
	rec.SetMB(false)
	rec.SetME(false)
	return rec
}
