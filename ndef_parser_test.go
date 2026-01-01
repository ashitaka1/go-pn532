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
	"reflect"
	"testing"
)

func TestExtractNDEFPayload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{
			name: "empty data",
			data: []byte{},
			want: nil,
		},
		{
			name: "no NDEF TLV - only terminator",
			data: []byte{0xFE},
			want: nil,
		},
		{
			name: "simple NDEF TLV with short form",
			data: []byte{0x03, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFE},
			want: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name: "NDEF TLV after NULL padding",
			data: []byte{0x00, 0x00, 0x03, 0x03, 0xAA, 0xBB, 0xCC, 0xFE},
			want: []byte{0xAA, 0xBB, 0xCC},
		},
		{
			name: "NDEF TLV after Lock Control TLV",
			// Lock Control: 0x01, length 0x03, value (3 bytes)
			// NDEF: 0x03, length 0x04, payload (4 bytes)
			data: []byte{0x01, 0x03, 0xA0, 0x0C, 0x34, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44, 0xFE},
			want: []byte{0x11, 0x22, 0x33, 0x44},
		},
		{
			name: "NDEF TLV with zero length",
			data: []byte{0x03, 0x00, 0xFE},
			want: []byte{},
		},
		{
			name: "NDEF TLV after Memory Control TLV",
			// Memory Control: 0x02, length 0x03, value (3 bytes)
			// NDEF: 0x03, length 0x02, payload (2 bytes)
			data: []byte{0x02, 0x03, 0xF0, 0xFF, 0xEE, 0x03, 0x02, 0xAA, 0xBB, 0xFE},
			want: []byte{0xAA, 0xBB},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := extractNDEFPayload(tt.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractNDEFPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}
