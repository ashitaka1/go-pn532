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
	"testing"
)

// TestAutoPollResultToDetectedTag tests the ToDetectedTag method
func TestAutoPollResultToDetectedTag(t *testing.T) {
	t.Parallel()
	testCases := getAutoPollTestCases()

	for _, tc := range testCases {
		// capture loop variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			detected := tc.result.ToDetectedTag()

			verifyDetectedTag(t, detected, &tc)
		})
	}
}

type autoPollTestCase struct {
	name           string
	expectedType   TagType
	expectedUID    string
	result         AutoPollResult
	expectedLength int
}

func getAutoPollTestCases() []autoPollTestCase {
	return []autoPollTestCase{
		{
			name: "NTAG card with 7-byte UID",
			result: AutoPollResult{
				Type:       AutoPollGeneric106kbps,
				TargetData: []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
			},
			expectedType:   TagTypeNTAG,
			expectedUID:    "04123456789abc",
			expectedLength: 7,
		},
		{
			name: "MIFARE card with 4-byte UID",
			result: AutoPollResult{
				Type:       AutoPollMifare,
				TargetData: []byte{0x01, 0x23, 0x45, 0x67, 0x89},
			},
			expectedType:   TagTypeMIFARE,
			expectedUID:    "01234567",
			expectedLength: 4,
		},
		{
			name: "FeliCa card with typical data",
			result: AutoPollResult{
				Type:       AutoPollFeliCa212,
				TargetData: []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18},
			},
			expectedType:   TagTypeFeliCa,
			expectedUID:    "a1b2c3d4e5f607",
			expectedLength: 7,
		},
		{
			name: "Short UID data (edge case)",
			result: AutoPollResult{
				Type:       AutoPollGeneric106kbps,
				TargetData: []byte{0xFF, 0xEE},
			},
			expectedType:   TagTypeNTAG,
			expectedUID:    "ffee",
			expectedLength: 2,
		},
		{
			name: "ISO14443A mapped to NTAG",
			result: AutoPollResult{
				Type:       AutoPollISO14443A,
				TargetData: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
			},
			expectedType:   TagTypeNTAG,
			expectedUID:    "11223344556677",
			expectedLength: 7,
		},
		{
			name: "Unknown type",
			result: AutoPollResult{
				Type:       AutoPollTarget(0xFF), // Invalid type
				TargetData: []byte{0xAA, 0xBB, 0xCC, 0xDD},
			},
			expectedType:   TagTypeUnknown,
			expectedUID:    "aabbccdd",
			expectedLength: 4,
		},
	}
}

func verifyDetectedTag(t *testing.T, detected *DetectedTag, testCase *autoPollTestCase) {
	if detected == nil {
		t.Fatal("ToDetectedTag returned nil")
	}

	verifyBasicFields(t, detected, testCase)
	verifyInAutoPollFields(t, detected, testCase)
}

func verifyBasicFields(t *testing.T, detected *DetectedTag, testCase *autoPollTestCase) {
	if detected.Type != testCase.expectedType {
		t.Errorf("Expected Type %s, got %s", testCase.expectedType, detected.Type)
	}

	if detected.UID != testCase.expectedUID {
		t.Errorf("Expected UID %s, got %s", testCase.expectedUID, detected.UID)
	}

	if len(detected.UIDBytes) != testCase.expectedLength {
		t.Errorf("Expected UIDBytes length %d, got %d", testCase.expectedLength, len(detected.UIDBytes))
	}
}

func verifyInAutoPollFields(t *testing.T, detected *DetectedTag, testCase *autoPollTestCase) {
	if len(detected.TargetData) != len(testCase.result.TargetData) {
		t.Errorf("Expected TargetData length %d, got %d",
			len(testCase.result.TargetData), len(detected.TargetData))
	}

	if detected.DetectedAt.IsZero() {
		t.Error("Expected DetectedAt to be set")
	}
}

// TestMapToTagType tests the mapToTagType method indirectly through ToDetectedTag
func TestMapToTagType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		expectedType TagType
		autoPollType AutoPollTarget
	}{
		{expectedType: TagTypeNTAG, autoPollType: AutoPollGeneric106kbps},
		{expectedType: TagTypeNTAG, autoPollType: AutoPollISO14443A},
		{expectedType: TagTypeMIFARE, autoPollType: AutoPollMifare},
		{expectedType: TagTypeFeliCa, autoPollType: AutoPollFeliCa212},
		{expectedType: TagTypeFeliCa, autoPollType: AutoPollFeliCa424},
		{expectedType: TagTypeFeliCa, autoPollType: AutoPollGeneric212kbps},
		{expectedType: TagTypeFeliCa, autoPollType: AutoPollGeneric424kbps},
		{expectedType: TagTypeNTAG, autoPollType: AutoPollISO14443B},
		{expectedType: TagTypeNTAG, autoPollType: AutoPollISO14443B4},
		{expectedType: TagTypeNTAG, autoPollType: AutoPollJewel},
		{expectedType: TagTypeUnknown, autoPollType: AutoPollTarget(0xFF)}, // Unknown type
	}

	for _, tt := range tests {
		// capture loop variable
		t.Run(string(rune(tt.autoPollType)), func(t *testing.T) {
			t.Parallel()
			result := AutoPollResult{
				Type:       tt.autoPollType,
				TargetData: []byte{0x01, 0x02, 0x03, 0x04},
			}

			detected := result.ToDetectedTag()
			if detected.Type != tt.expectedType {
				t.Errorf("AutoPollType %v: expected TagType %s, got %s",
					tt.autoPollType, tt.expectedType, detected.Type)
			}
		})
	}
}

// TestToDetectedTagWithEmptyData tests edge case handling
func TestToDetectedTagWithEmptyData(t *testing.T) {
	t.Parallel()
	result := AutoPollResult{
		Type:       AutoPollGeneric106kbps,
		TargetData: []byte{},
	}

	detected := result.ToDetectedTag()
	if detected == nil {
		t.Fatal("ToDetectedTag returned nil for empty data")
	}

	if detected.UID != "" {
		t.Errorf("Expected empty UID, got %s", detected.UID)
	}

	if len(detected.UIDBytes) != 0 {
		t.Errorf("Expected empty UIDBytes, got length %d", len(detected.UIDBytes))
	}

	// DetectedAt should still be set correctly
	if detected.DetectedAt.IsZero() {
		t.Error("DetectedAt should be set even with empty data")
	}
}

// TestToDetectedTagCompatibilityWithExistingLogic tests compatibility with the
// existing convertAutoPollToDetectedTag logic from cmd/nfctest/main.go
func TestToDetectedTagCompatibilityWithExistingLogic(t *testing.T) {
	t.Parallel()
	// Test case that mimics real NTAG detection
	result := AutoPollResult{
		Type:       AutoPollGeneric106kbps,
		TargetData: []byte{0x04, 0x00, 0x44, 0x00, 0x07, 0x04, 0x29, 0x80},
	}

	detected := result.ToDetectedTag()

	// Should extract 7-byte UID
	expectedUID := "04004400070429"
	if detected.UID != expectedUID {
		t.Errorf("Expected UID %s, got %s", expectedUID, detected.UID)
	}

	// Should be NTAG type
	if detected.Type != TagTypeNTAG {
		t.Errorf("Expected TagTypeNTAG, got %s", detected.Type)
	}

	// Should have DetectedAt set
	if detected.DetectedAt.IsZero() {
		t.Error("DetectedAt must be set for InAutoPoll results")
	}
}

// BenchmarkToDetectedTag benchmarks the ToDetectedTag method performance
func BenchmarkToDetectedTag(b *testing.B) {
	result := AutoPollResult{
		Type:       AutoPollGeneric106kbps,
		TargetData: []byte{0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
	}

	b.ResetTimer()
	for range b.N {
		_ = result.ToDetectedTag()
	}
}
