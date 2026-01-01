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

package detection

import (
	"testing"
)

func TestIsPathIgnored(t *testing.T) {
	t.Parallel()

	tests := getPathIgnoredTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsPathIgnored(tt.devicePath, tt.ignorePaths)
			if result != tt.expected {
				t.Errorf("IsPathIgnored(%q, %v) = %v, want %v",
					tt.devicePath, tt.ignorePaths, result, tt.expected)
			}
		})
	}
}

type pathIgnoredTest struct {
	name        string
	devicePath  string
	ignorePaths []string
	expected    bool
}

//nolint:funlen // Test data function, acceptable to be longer
func getPathIgnoredTests() []pathIgnoredTest {
	basicTests := []pathIgnoredTest{
		{
			name:        "empty ignore list",
			devicePath:  "/dev/ttyUSB0",
			ignorePaths: []string{},
			expected:    false,
		},
		{
			name:        "empty device path",
			devicePath:  "",
			ignorePaths: []string{"/dev/ttyUSB0"},
			expected:    false,
		},
		{
			name:        "exact match unix path",
			devicePath:  "/dev/ttyUSB0",
			ignorePaths: []string{"/dev/ttyUSB0"},
			expected:    true,
		},
		{
			name:        "exact match windows path",
			devicePath:  "COM2",
			ignorePaths: []string{"COM2"},
			expected:    true,
		},
	}

	caseTests := []pathIgnoredTest{
		{
			name:        "case insensitive match",
			devicePath:  "/dev/ttyUSB0",
			ignorePaths: []string{"/DEV/TTYUSB0"},
			expected:    true,
		},
		{
			name:        "windows case insensitive",
			devicePath:  "com2",
			ignorePaths: []string{"COM2"},
			expected:    true,
		},
	}

	multipleTests := []pathIgnoredTest{
		{
			name:        "no match",
			devicePath:  "/dev/ttyUSB1",
			ignorePaths: []string{"/dev/ttyUSB0"},
			expected:    false,
		},
		{
			name:        "multiple paths with match",
			devicePath:  "/dev/ttyUSB1",
			ignorePaths: []string{"/dev/ttyUSB0", "/dev/ttyUSB1", "COM2"},
			expected:    true,
		},
		{
			name:        "multiple paths no match",
			devicePath:  "/dev/ttyUSB2",
			ignorePaths: []string{"/dev/ttyUSB0", "/dev/ttyUSB1", "COM2"},
			expected:    false,
		},
	}

	specialTests := []pathIgnoredTest{
		{
			name:        "i2c path format",
			devicePath:  "/dev/i2c-1:0x24",
			ignorePaths: []string{"/dev/i2c-1:0x24"},
			expected:    true,
		},
		{
			name:        "spi path format",
			devicePath:  "/dev/spidev0.0",
			ignorePaths: []string{"/dev/spidev0.0"},
			expected:    true,
		},
		{
			name:        "path with relative components",
			devicePath:  "/dev/../dev/ttyUSB0",
			ignorePaths: []string{"/dev/ttyUSB0"},
			expected:    true,
		},
		{
			name:        "empty strings in ignore list",
			devicePath:  "/dev/ttyUSB0",
			ignorePaths: []string{"", "/dev/ttyUSB0", ""},
			expected:    true,
		},
	}

	result := make([]pathIgnoredTest, 0, len(basicTests)+len(caseTests)+len(multipleTests)+len(specialTests))
	result = append(result, basicTests...)
	result = append(result, caseTests...)
	result = append(result, multipleTests...)
	result = append(result, specialTests...)
	return result
}

func TestOptionsWithIgnorePaths(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	if opts.IgnorePaths != nil {
		t.Errorf("DefaultOptions().IgnorePaths should be nil, got %v", opts.IgnorePaths)
	}

	// Test that we can set ignore paths
	opts.IgnorePaths = []string{"/dev/ttyUSB0", "COM2"}
	if len(opts.IgnorePaths) != 2 {
		t.Errorf("Expected 2 ignore paths, got %d", len(opts.IgnorePaths))
	}
}
