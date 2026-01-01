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

import "testing"

func TestCalculateChecksum(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		want byte
	}{
		{
			name: "empty data",
			data: []byte{},
			want: 0,
		},
		{
			name: "single byte",
			data: []byte{0x42},
			want: 0x42,
		},
		{
			name: "two bytes",
			data: []byte{0x10, 0x20},
			want: 0x30,
		},
		{
			name: "overflow handling",
			data: []byte{0xFF, 0x01},
			want: 0x00, // 255 + 1 = 256, truncated to 0
		},
		{
			name: "multiple bytes",
			data: []byte{0x01, 0x02, 0x03, 0x04},
			want: 0x0A,
		},
		{
			name: "real frame data",
			data: []byte{0xD4, 0x03, 0x32, 0x01, 0x00, 0x6B, 0x02, 0x4A, 0x65, 0x6C, 0x6C, 0x6F},
			want: 0x6D, // Sum of all bytes (corrected value)
		},
	}

	for _, tt := range tests {
		// capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CalculateChecksum(tt.data); got != tt.want {
				t.Errorf("CalculateChecksum() = %v, want %v", got, tt.want)
			}
		})
	}
}
