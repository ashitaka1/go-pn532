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
