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
	"bytes"
	"testing"
)

//nolint:gocognit,revive // table-driven test
func TestNewTextRecord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		text     string
		language string
		wantLang string
	}{
		{"simple", "Hello", "en", "en"},
		{"empty language defaults to en", "Hello", "", "en"},
		{"with locale", "Bonjour", "fr-FR", "fr-FR"},
		{"unicode text", "\u4f60\u597d\u4e16\u754c", "zh", "zh"},
		{"empty text", "", "en", "en"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := NewTextRecord(tt.text, tt.language)

			if rec.TNF != TNFWellKnown {
				t.Errorf("TNF = %d, want %d", rec.TNF, TNFWellKnown)
			}
			if rec.Type != TextRecordType {
				t.Errorf("Type = %q, want %q", rec.Type, TextRecordType)
			}

			parsed, err := ParseTextRecord(rec.Payload)
			if err != nil {
				t.Fatalf("ParseTextRecord error: %v", err)
			}

			if parsed.Text != tt.text {
				t.Errorf("Text = %q, want %q", parsed.Text, tt.text)
			}
			if parsed.Language != tt.wantLang {
				t.Errorf("Language = %q, want %q", parsed.Language, tt.wantLang)
			}
			if parsed.UTF16 {
				t.Error("UTF16 should be false")
			}
		})
	}
}

//nolint:gocognit,revive // table-driven test
func TestParseTextRecord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		wantText  string
		wantLang  string
		payload   []byte
		wantUTF16 bool
		wantErr   bool
	}{
		{
			name:     "valid UTF-8 english",
			payload:  []byte{0x02, 'e', 'n', 'H', 'e', 'l', 'l', 'o'},
			wantText: "Hello",
			wantLang: "en",
		},
		{
			name:     "valid with locale",
			payload:  []byte{0x05, 'e', 'n', '-', 'U', 'S', 'H', 'i'},
			wantText: "Hi",
			wantLang: "en-US",
		},
		{
			name:     "empty text",
			payload:  []byte{0x02, 'e', 'n'},
			wantText: "",
			wantLang: "en",
		},
		{
			name:      "UTF-16 flag set",
			payload:   []byte{0x82, 'e', 'n', 'X'}, // 0x82 = 10000010 = UTF16 flag + lang len 2
			wantText:  "X",
			wantLang:  "en",
			wantUTF16: true,
		},
		{
			name:    "empty payload",
			payload: []byte{},
			wantErr: true,
		},
		{
			name:    "truncated language",
			payload: []byte{0x05, 'e', 'n'}, // Claims 5 byte lang but only has 2
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := ParseTextRecord(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if parsed.Text != tt.wantText {
				t.Errorf("Text = %q, want %q", parsed.Text, tt.wantText)
			}
			if parsed.Language != tt.wantLang {
				t.Errorf("Language = %q, want %q", parsed.Language, tt.wantLang)
			}
			if parsed.UTF16 != tt.wantUTF16 {
				t.Errorf("UTF16 = %v, want %v", parsed.UTF16, tt.wantUTF16)
			}
		})
	}
}

func TestDecodeTextPayload(t *testing.T) {
	t.Parallel()

	payload := []byte{0x02, 'e', 'n', 'T', 'e', 's', 't'}
	text, err := DecodeTextPayload(payload)
	if err != nil {
		t.Fatalf("DecodeTextPayload error: %v", err)
	}
	if text != "Test" {
		t.Errorf("text = %q, want 'Test'", text)
	}
}

//nolint:gocognit,revive // table-driven test
func TestEncodeTextPayload(t *testing.T) {
	t.Parallel()

	longLang := "this-is-a-very-long-language-code-that-exceeds-63-bytes-which-is-max"
	tests := []struct {
		name     string
		text     string
		language string
		wantErr  bool
	}{
		{"simple", "Hello", "en", false},
		{"empty language defaults", "Hello", "", false},
		{"language too long", "Hello", longLang, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			payload, err := EncodeTextPayload(tt.text, tt.language)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("EncodeTextPayload error: %v", err)
			}

			// Verify round-trip
			text, err := DecodeTextPayload(payload)
			if err != nil {
				t.Fatalf("DecodeTextPayload error: %v", err)
			}
			if text != tt.text {
				t.Errorf("text = %q, want %q", text, tt.text)
			}
		})
	}
}

func TestTextRecordRoundTrip(t *testing.T) {
	t.Parallel()

	texts := []string{
		"Hello, World!",
		"",
		"Special chars: @#$%^&*()",
		"Unicode: \u65e5\u672c\u8a9e \U0001F3AE \u00d1o\u00f1o",
		string(bytes.Repeat([]byte("x"), 1000)), // Long text
	}

	for _, text := range texts {
		rec := NewTextRecord(text, "en")
		data, err := rec.Marshal()
		if err != nil {
			t.Fatalf("Marshal error for %q: %v", text[:min(20, len(text))], err)
		}

		var parsed Record
		_, err = parsed.Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		result, err := DecodeTextPayload(parsed.Payload)
		if err != nil {
			t.Fatalf("DecodeTextPayload error: %v", err)
		}
		if result != text {
			t.Errorf("round-trip failed: got %q, want %q", result[:min(20, len(result))], text[:min(20, len(text))])
		}
	}
}
