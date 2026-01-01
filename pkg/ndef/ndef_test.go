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

package ndef

import (
	"bytes"
	"errors"
	"testing"
)

// TestRecordMarshalUnmarshal tests basic record serialization round-trip.
//
//nolint:gocognit,funlen,revive // table-driven test with comprehensive assertions
func TestRecordMarshalUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		record  Record
		wantErr bool
	}{
		{
			name: "simple text record",
			record: Record{
				TNF:     TNFWellKnown,
				Type:    "T",
				Payload: []byte{0x02, 'e', 'n', 'H', 'e', 'l', 'l', 'o'},
			},
		},
		{
			name: "URI record",
			record: Record{
				TNF:     TNFWellKnown,
				Type:    "U",
				Payload: []byte{0x04, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			},
		},
		{
			name: "media record with long payload",
			record: Record{
				TNF:     TNFMedia,
				Type:    "application/json",
				Payload: bytes.Repeat([]byte("x"), 300), // Longer than 255 to test long format
			},
		},
		{
			name: "record with ID",
			record: Record{
				TNF:     TNFWellKnown,
				Type:    "T",
				ID:      "record-1",
				Payload: []byte{0x02, 'e', 'n', 'T', 'e', 's', 't'},
			},
		},
		{
			name: "empty payload",
			record: Record{
				TNF:     TNFWellKnown,
				Type:    "T",
				Payload: nil,
			},
		},
		{
			name: "external type",
			record: Record{
				TNF:     TNFExternal,
				Type:    "example.com:mytype",
				Payload: []byte{0x01, 0x02, 0x03},
			},
		},
		{
			name:    "invalid TNF",
			record:  Record{TNF: 0xFF, Type: "X", Payload: []byte{0x00}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := tt.record.Marshal()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			var parsed Record
			n, err := parsed.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if n != len(data) {
				t.Errorf("consumed %d bytes, expected %d", n, len(data))
			}

			if parsed.TNF != tt.record.TNF {
				t.Errorf("TNF = %d, want %d", parsed.TNF, tt.record.TNF)
			}
			if parsed.Type != tt.record.Type {
				t.Errorf("Type = %q, want %q", parsed.Type, tt.record.Type)
			}
			if parsed.ID != tt.record.ID {
				t.Errorf("ID = %q, want %q", parsed.ID, tt.record.ID)
			}
			if !bytes.Equal(parsed.Payload, tt.record.Payload) {
				t.Errorf("Payload mismatch: got %v, want %v", parsed.Payload, tt.record.Payload)
			}
		})
	}
}

// TestMessageMarshalUnmarshal tests message serialization round-trip.
//
//nolint:gocognit,gocyclo,cyclop,funlen,revive // table-driven test with comprehensive assertions
func TestMessageMarshalUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		records []*Record
		wantErr bool
	}{
		{
			name: "single record",
			records: []*Record{
				{TNF: TNFWellKnown, Type: "T", Payload: []byte{0x02, 'e', 'n', 'H', 'i'}},
			},
		},
		{
			name: "two records",
			records: []*Record{
				{TNF: TNFWellKnown, Type: "T", Payload: []byte{0x02, 'e', 'n', 'H', 'i'}},
				{TNF: TNFWellKnown, Type: "U", Payload: uriPayload()},
			},
		},
		{
			name: "three records mixed types",
			records: []*Record{
				{TNF: TNFWellKnown, Type: "T", Payload: []byte{0x02, 'e', 'n', 'O', 'n', 'e'}},
				{TNF: TNFMedia, Type: "text/plain", Payload: []byte("Two")},
				{TNF: TNFExternal, Type: "example.com:test", Payload: []byte{0x03}},
			},
		},
		{
			name:    "empty message",
			records: []*Record{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			msg := &Message{Records: tt.records}
			data, err := msg.Marshal()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			var parsed Message
			n, err := parsed.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if n != len(data) {
				t.Errorf("consumed %d bytes, expected %d", n, len(data))
			}

			if len(parsed.Records) != len(tt.records) {
				t.Fatalf("got %d records, want %d", len(parsed.Records), len(tt.records))
			}

			// First record should have MB set
			if len(parsed.Records) > 0 && !parsed.Records[0].MB() {
				t.Error("first record should have MB flag set")
			}
			// Last record should have ME set
			if len(parsed.Records) > 0 && !parsed.Records[len(parsed.Records)-1].ME() {
				t.Error("last record should have ME flag set")
			}

			for i, rec := range parsed.Records {
				if rec.TNF != tt.records[i].TNF {
					t.Errorf("record %d: TNF = %d, want %d", i, rec.TNF, tt.records[i].TNF)
				}
				if rec.Type != tt.records[i].Type {
					t.Errorf("record %d: Type = %q, want %q", i, rec.Type, tt.records[i].Type)
				}
				if !bytes.Equal(rec.Payload, tt.records[i].Payload) {
					t.Errorf("record %d: Payload mismatch", i)
				}
			}
		})
	}
}

// TestRecordFlags tests MB/ME flag handling.
func TestRecordFlags(t *testing.T) {
	t.Parallel()

	msg := &Message{
		Records: []*Record{
			{TNF: TNFWellKnown, Type: "T", Payload: []byte{0x02, 'e', 'n', '1'}},
			{TNF: TNFWellKnown, Type: "T", Payload: []byte{0x02, 'e', 'n', '2'}},
			{TNF: TNFWellKnown, Type: "T", Payload: []byte{0x02, 'e', 'n', '3'}},
		},
	}

	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed Message
	_, err = parsed.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Check flags
	if !parsed.Records[0].MB() {
		t.Error("record 0 should have MB")
	}
	if parsed.Records[0].ME() {
		t.Error("record 0 should NOT have ME")
	}

	if parsed.Records[1].MB() {
		t.Error("record 1 should NOT have MB")
	}
	if parsed.Records[1].ME() {
		t.Error("record 1 should NOT have ME")
	}

	if parsed.Records[2].MB() {
		t.Error("record 2 should NOT have MB")
	}
	if !parsed.Records[2].ME() {
		t.Error("record 2 should have ME")
	}
}

// TestShortVsLongPayload tests the SR (Short Record) flag behavior.
func TestShortVsLongPayload(t *testing.T) {
	t.Parallel()

	// Short payload (≤255 bytes)
	shortRec := Record{
		TNF:     TNFMedia,
		Type:    "text/plain",
		Payload: bytes.Repeat([]byte("x"), 100),
	}
	shortData, err := shortRec.Marshal()
	if err != nil {
		t.Fatalf("short record Marshal error: %v", err)
	}
	// Check SR flag is set
	if shortData[0]&flagSR == 0 {
		t.Error("short record should have SR flag set")
	}

	// Long payload (>255 bytes)
	longRec := Record{
		TNF:     TNFMedia,
		Type:    "text/plain",
		Payload: bytes.Repeat([]byte("x"), 300),
	}
	longData, err := longRec.Marshal()
	if err != nil {
		t.Fatalf("long record Marshal error: %v", err)
	}
	// Check SR flag is NOT set
	if longData[0]&flagSR != 0 {
		t.Error("long record should NOT have SR flag set")
	}

	// Verify round-trip
	var parsedShort, parsedLong Record
	if _, err := parsedShort.Unmarshal(shortData); err != nil {
		t.Fatalf("short record Unmarshal error: %v", err)
	}
	if _, err := parsedLong.Unmarshal(longData); err != nil {
		t.Fatalf("long record Unmarshal error: %v", err)
	}

	if len(parsedShort.Payload) != 100 {
		t.Errorf("short payload len = %d, want 100", len(parsedShort.Payload))
	}
	if len(parsedLong.Payload) != 300 {
		t.Errorf("long payload len = %d, want 300", len(parsedLong.Payload))
	}
}

// TestUnmarshalErrors tests error handling for malformed data.
func TestUnmarshalErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"truncated header", []byte{0xD1}},
		{"truncated type length", []byte{0xD1, 0x01}},
		{"missing payload", []byte{0xD1, 0x01, 0x05, 'T'}},  // Claims 5 bytes payload but has none
		{"truncated long length", []byte{0xC1, 0x01, 0x00}}, // Long format but only 1 length byte
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rec Record
			_, err := rec.Unmarshal(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestChunkedRecordError verifies chunked records are rejected.
func TestChunkedRecordError(t *testing.T) {
	t.Parallel()

	// CF flag set (bit 5) - MB|ME|CF|SR + TNF=1
	data := []byte{0xF1, 0x01, 0x01, 'T', 'x'}
	var rec Record
	_, err := rec.Unmarshal(data)
	if !errors.Is(err, ErrChunkedRecord) {
		t.Errorf("expected ErrChunkedRecord, got %v", err)
	}
}

// TestRecordWithID tests the ID field handling.
func TestRecordWithID(t *testing.T) {
	t.Parallel()

	rec := Record{
		TNF:     TNFWellKnown,
		Type:    "T",
		ID:      "my-record-id",
		Payload: []byte{0x02, 'e', 'n', 'H', 'i'},
	}

	data, err := rec.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Check IL flag is set
	if data[0]&flagIL == 0 {
		t.Error("IL flag should be set when ID is present")
	}

	var parsed Record
	_, err = parsed.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.ID != rec.ID {
		t.Errorf("ID = %q, want %q", parsed.ID, rec.ID)
	}
}

// TestAllTNFValues tests all valid TNF values.
func TestAllTNFValues(t *testing.T) {
	t.Parallel()

	tnfCases := []struct {
		typeName string
		tnf      byte
	}{
		{tnf: TNFEmpty, typeName: ""},
		{tnf: TNFWellKnown, typeName: "T"},
		{tnf: TNFMedia, typeName: "text/plain"},
		{tnf: TNFAbsoluteURI, typeName: "http://example.com"},
		{tnf: TNFExternal, typeName: "example.com:mytype"},
		{tnf: TNFUnknown, typeName: ""},
		{tnf: TNFUnchanged, typeName: ""},
	}

	for _, tc := range tnfCases {
		t.Run("TNF_"+string(rune('0'+tc.tnf)), func(t *testing.T) {
			t.Parallel()

			rec := Record{
				TNF:     tc.tnf,
				Type:    tc.typeName,
				Payload: []byte{0x01},
			}

			data, err := rec.Marshal()
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			var parsed Record
			_, err = parsed.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			if parsed.TNF != tc.tnf {
				t.Errorf("TNF = %d, want %d", parsed.TNF, tc.tnf)
			}
		})
	}
}

// TestKnownGoodNDEFData tests parsing of known-good NDEF data.
// These are real-world examples to ensure compatibility.
//
//nolint:gocognit,revive // table-driven test with callback-based validation
func TestKnownGoodNDEFData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		checkFirst  func(t *testing.T, rec *Record)
		name        string
		data        []byte
		wantRecords int
	}{
		{
			name: "simple text record MB|ME|SR",
			// Flags: 0xD1 = 11010001 = MB|ME|SR|TNF=1 (well-known)
			// Type len: 1 ("T")
			// Payload len: 5
			// Type: "T"
			// Payload: 0x02 "en" "Hi"
			data:        []byte{0xD1, 0x01, 0x05, 'T', 0x02, 'e', 'n', 'H', 'i'},
			wantRecords: 1,
			checkFirst: func(t *testing.T, rec *Record) {
				if rec.TNF != TNFWellKnown {
					t.Errorf("TNF = %d, want %d", rec.TNF, TNFWellKnown)
				}
				if rec.Type != "T" {
					t.Errorf("Type = %q, want 'T'", rec.Type)
				}
				text, err := DecodeTextPayload(rec.Payload)
				if err != nil {
					t.Fatalf("DecodeTextPayload error: %v", err)
				}
				if text != "Hi" {
					t.Errorf("text = %q, want 'Hi'", text)
				}
			},
		},
		{
			name: "URI record https://example.com",
			// Flags: 0xD1 = MB|ME|SR|TNF=1
			// Type len: 1 ("U")
			// Payload len: 12
			// Type: "U"
			// Payload: 0x04 (https://) + "example.com"
			data:        []byte{0xD1, 0x01, 0x0C, 'U', 0x04, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			wantRecords: 1,
			checkFirst: func(t *testing.T, rec *Record) {
				if rec.Type != "U" {
					t.Errorf("Type = %q, want 'U'", rec.Type)
				}
				uri, err := DecodeURIPayload(rec.Payload)
				if err != nil {
					t.Fatalf("DecodeURIPayload error: %v", err)
				}
				if uri != "https://example.com" {
					t.Errorf("uri = %q, want 'https://example.com'", uri)
				}
			},
		},
		{
			name: "two records (text + URI)",
			// First: 0x91 = 10010001 = MB|SR|TNF=1
			// Second: 0x51 = 01010001 = ME|SR|TNF=1
			data: []byte{
				0x91, 0x01, 0x05, 'T', 0x02, 'e', 'n', 'H', 'i', // First record
				0x51, 0x01, 0x0C, 'U', 0x04, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', // Second record
			},
			wantRecords: 2,
			checkFirst: func(t *testing.T, rec *Record) {
				if !rec.MB() {
					t.Error("first record should have MB")
				}
				if rec.ME() {
					t.Error("first record should NOT have ME")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var msg Message
			_, err := msg.Unmarshal(tt.data)
			if err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			if len(msg.Records) != tt.wantRecords {
				t.Fatalf("got %d records, want %d", len(msg.Records), tt.wantRecords)
			}

			if tt.checkFirst != nil {
				tt.checkFirst(t, msg.Records[0])
			}
		})
	}
}

// TestRoundTripRealWorldRecords tests round-trip of realistic record combinations.
func TestRoundTripRealWorldRecords(t *testing.T) {
	t.Parallel()

	// Create a realistic multi-record message
	textRec := NewTextRecord("Hello, NFC!", "en")
	uriRec := NewURIRecord("https://zaparoo.org")
	mediaRec := NewMediaRecord("application/json", []byte(`{"version":1}`))

	msg := &Message{
		Records: []*Record{textRec, uriRec, mediaRec},
	}

	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed Message
	_, err = parsed.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if len(parsed.Records) != 3 {
		t.Fatalf("got %d records, want 3", len(parsed.Records))
	}

	// Check text record
	text, err := DecodeTextPayload(parsed.Records[0].Payload)
	if err != nil {
		t.Fatalf("DecodeTextPayload error: %v", err)
	}
	if text != "Hello, NFC!" {
		t.Errorf("text = %q, want 'Hello, NFC!'", text)
	}

	// Check URI record
	uri, err := DecodeURIPayload(parsed.Records[1].Payload)
	if err != nil {
		t.Fatalf("DecodeURIPayload error: %v", err)
	}
	if uri != "https://zaparoo.org" {
		t.Errorf("uri = %q, want 'https://zaparoo.org'", uri)
	}

	// Check media record
	if parsed.Records[2].Type != "application/json" {
		t.Errorf("media type = %q, want 'application/json'", parsed.Records[2].Type)
	}
	if string(parsed.Records[2].Payload) != `{"version":1}` {
		t.Errorf("media payload = %q, want '{\"version\":1}'", parsed.Records[2].Payload)
	}
}

// uriPayload returns a test URI payload for https://example.com.
func uriPayload() []byte {
	return []byte{0x04, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}
}
