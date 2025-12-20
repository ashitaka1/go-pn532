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
	"testing"
)

func TestNewURIRecord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string
	}{
		{"https www", "https://www.example.com"},
		{"https", "https://example.com"},
		{"http www", "http://www.example.com"},
		{"http", "http://example.com"},
		{"tel", "tel:+1234567890"},
		{"mailto", "mailto:test@example.com"},
		{"custom scheme", "myapp://action"},
		{"no scheme", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := NewURIRecord(tt.uri)

			if rec.TNF != TNFWellKnown {
				t.Errorf("TNF = %d, want %d", rec.TNF, TNFWellKnown)
			}
			if rec.Type != URIRecordType {
				t.Errorf("Type = %q, want %q", rec.Type, URIRecordType)
			}

			parsed, err := ParseURIRecord(rec.Payload)
			if err != nil {
				t.Fatalf("ParseURIRecord error: %v", err)
			}

			if parsed != tt.uri {
				t.Errorf("URI = %q, want %q", parsed, tt.uri)
			}
		})
	}
}

//nolint:funlen // comprehensive table-driven test
func TestParseURIRecord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		wantURI string
		payload []byte
		wantErr bool
	}{
		{
			name:    "no prefix",
			payload: []byte{0x00, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			wantURI: "example.com",
		},
		{
			name:    "http://www.",
			payload: []byte{0x01, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			wantURI: "http://www.example.com",
		},
		{
			name:    "https://www.",
			payload: []byte{0x02, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			wantURI: "https://www.example.com",
		},
		{
			name:    "http://",
			payload: []byte{0x03, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			wantURI: "http://example.com",
		},
		{
			name:    "https://",
			payload: []byte{0x04, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			wantURI: "https://example.com",
		},
		{
			name:    "tel:",
			payload: []byte{0x05, '+', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'},
			wantURI: "tel:+1234567890",
		},
		{
			name:    "mailto:",
			payload: []byte{0x06, 't', 'e', 's', 't', '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			wantURI: "mailto:test@example.com",
		},
		{
			name:    "file://",
			payload: []byte{0x1D, '/', 'p', 'a', 't', 'h', '/', 'f', 'i', 'l', 'e'},
			wantURI: "file:///path/file",
		},
		{
			name:    "urn:nfc:",
			payload: []byte{0x23, 's', 'n', ':', '1', '2', '3'},
			wantURI: "urn:nfc:sn:123",
		},
		{
			name:    "empty payload",
			payload: []byte{},
			wantErr: true,
		},
		{
			name:    "invalid prefix code",
			payload: []byte{0x50, 'x'}, // 0x50 is beyond valid prefixes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			uri, err := ParseURIRecord(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if uri != tt.wantURI {
				t.Errorf("URI = %q, want %q", uri, tt.wantURI)
			}
		})
	}
}

func TestURIPrefixCompression(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri            string
		wantSuffix     string
		wantPrefixCode byte
	}{
		{uri: "https://www.example.com", wantPrefixCode: 0x02, wantSuffix: "example.com"},
		{uri: "https://example.com", wantPrefixCode: 0x04, wantSuffix: "example.com"},
		{uri: "http://www.example.com", wantPrefixCode: 0x01, wantSuffix: "example.com"},
		{uri: "http://example.com", wantPrefixCode: 0x03, wantSuffix: "example.com"},
		{uri: "tel:+1234567890", wantPrefixCode: 0x05, wantSuffix: "+1234567890"},
		{uri: "mailto:test@example.com", wantPrefixCode: 0x06, wantSuffix: "test@example.com"},
		{uri: "ftp://ftp.example.com", wantPrefixCode: 0x08, wantSuffix: "example.com"},
		{uri: "file:///path/file", wantPrefixCode: 0x1D, wantSuffix: "/path/file"},
		{uri: "custom://something", wantPrefixCode: 0x00, wantSuffix: "custom://something"},
		{uri: "example.com", wantPrefixCode: 0x00, wantSuffix: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			t.Parallel()

			payload := EncodeURIPayload(tt.uri)

			if payload[0] != tt.wantPrefixCode {
				t.Errorf("prefix code = 0x%02X, want 0x%02X", payload[0], tt.wantPrefixCode)
			}

			suffix := string(payload[1:])
			if suffix != tt.wantSuffix {
				t.Errorf("suffix = %q, want %q", suffix, tt.wantSuffix)
			}

			// Verify round-trip
			decoded, err := ParseURIRecord(payload)
			if err != nil {
				t.Fatalf("ParseURIRecord error: %v", err)
			}
			if decoded != tt.uri {
				t.Errorf("decoded = %q, want %q", decoded, tt.uri)
			}
		})
	}
}

func TestURIPrefixHelpers(t *testing.T) {
	t.Parallel()

	// Test URIPrefixCode
	if code := URIPrefixCode("https://"); code != 0x04 {
		t.Errorf("URIPrefixCode('https://') = 0x%02X, want 0x04", code)
	}
	if code := URIPrefixCode("unknown://"); code != 0x00 {
		t.Errorf("URIPrefixCode('unknown://') = 0x%02X, want 0x00", code)
	}

	// Test URIPrefixString
	if prefix := URIPrefixString(0x04); prefix != "https://" {
		t.Errorf("URIPrefixString(0x04) = %q, want 'https://'", prefix)
	}
	if prefix := URIPrefixString(0xFF); prefix != "" {
		t.Errorf("URIPrefixString(0xFF) = %q, want ''", prefix)
	}
}

func TestAllURIPrefixes(t *testing.T) {
	t.Parallel()

	// Test that all defined prefixes round-trip correctly
	testURIs := []string{
		"http://www.example.com",
		"https://www.example.com",
		"http://example.com",
		"https://example.com",
		"tel:+1234567890",
		"mailto:test@example.com",
		"ftp://anonymous:anonymous@ftp.example.com",
		"ftp://ftp.example.com",
		"ftps://secure.example.com",
		"sftp://secure.example.com",
		"smb://server/share",
		"nfs://server/path",
		"ftp://example.com",
		"dav://server/path",
		"news:comp.lang.go",
		"telnet://host:23",
		"imap:mailbox",
		"rtsp://stream.example.com",
		"urn:isbn:0451450523",
		"pop:mailbox",
		"sip:user@example.com",
		"sips:user@example.com",
		"tftp://server/file",
		"btspp://device",
		"btl2cap://device",
		"btgoep://device",
		"tcpobex://device",
		"irdaobex://device",
		"file:///path/to/file",
		"urn:epc:id:sgtin:123",
		"urn:epc:tag:sgtin:123",
		"urn:epc:pat:sgtin:123",
		"urn:epc:raw:123",
		"urn:epc:class:123",
		"urn:nfc:sn:12345678",
	}

	for _, uri := range testURIs {
		t.Run(uri[:min(30, len(uri))], func(t *testing.T) {
			t.Parallel()

			rec := NewURIRecord(uri)
			data, err := rec.Marshal()
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			var parsed Record
			_, err = parsed.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			result, err := ParseURIRecord(parsed.Payload)
			if err != nil {
				t.Fatalf("ParseURIRecord error: %v", err)
			}

			if result != uri {
				t.Errorf("round-trip failed: got %q, want %q", result, uri)
			}
		})
	}
}

func TestURIRecordRoundTrip(t *testing.T) {
	t.Parallel()

	uris := []string{
		"https://example.com",
		"https://example.com/path?query=value#fragment",
		"mailto:user@example.com?subject=Hello",
		"tel:+1-800-555-1234",
		"custom-scheme://host/path",
		"https://example.com/" + string(make([]byte, 500)), // Long URI
	}

	for _, uri := range uris {
		t.Run(uri[:min(30, len(uri))], func(t *testing.T) {
			t.Parallel()

			rec := NewURIRecord(uri)
			data, err := rec.Marshal()
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			var parsed Record
			_, err = parsed.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			result, err := ParseURIRecord(parsed.Payload)
			if err != nil {
				t.Fatalf("ParseURIRecord error: %v", err)
			}

			if result != uri {
				t.Errorf("round-trip failed: got length %d, want length %d", len(result), len(uri))
			}
		})
	}
}
