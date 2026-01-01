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

//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
)

func TestRunWriteMode_SimplifiedErrorHandling(t *testing.T) {
	t.Parallel()
	// Create mock device and transport
	mockTransport := pn532.NewMockTransport()
	device, err := pn532.New(mockTransport)
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	// Setup mock responses for WriteToNextTag flow
	mockTransport.SetResponse(0x4A, []byte{
		0xD5, 0x4B, 0x01, 0x01, 0x00, 0x04, 0x00, 0x07, 0x04,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
	}) // InListPassiveTarget response
	mockTransport.SetResponse(0x54, []byte{0x55, 0x00}) // InSelect response (cmd 0x54, response 0x55, status 0x00)

	// NDEF "test text" encodes to approximately 19 bytes = 5 blocks (4 bytes each)
	// Block 4: 03 10 D1 01 (NDEF header)
	// Block 5: 0C 54 02 65 (text record header + 'e')
	// Block 6: 6E 74 65 73 ('ntes')
	// Block 7: 74 20 74 65 ('t te')
	// Block 8: 78 74 FE 00 ('xt' + terminator)
	ndefBlocks := [][]byte{
		{0x03, 0x10, 0xD1, 0x01},
		{0x0C, 0x54, 0x02, 0x65},
		{0x6E, 0x74, 0x65, 0x73},
		{0x74, 0x20, 0x74, 0x65},
		{0x78, 0x74, 0xFE, 0x00},
	}

	// Queue responses for DetectType flow:
	// 1. Read CC page 3 for NTAG detection (returns valid NTAG CC)
	ccResponse := []byte{0x41, 0x00, 0xE1, 0x10, 0x06, 0x00} // Valid NTAG213 CC
	mockTransport.QueueResponse(0x40, ccResponse)

	// Setup 0x42 (InCommunicateThru) for GetVersion command
	// GetVersion response (NTAG213)
	mockTransport.SetResponse(0x42, []byte{0x43, 0x00, 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03})

	// Queue write success responses for 5 blocks
	writeSuccess := []byte{0x41, 0x00}
	for range 5 {
		mockTransport.QueueResponse(0x40, writeSuccess)
	}

	// Queue verification read responses - returns the written block data
	for _, block := range ndefBlocks {
		readResponse := append([]byte{0x41, 0x00}, block...)
		mockTransport.QueueResponse(0x40, readResponse)
	}

	// Test config
	cfg := &config{
		writeText: "test text",
		debug:     false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test should demonstrate that the current error handling is too complex
	// We expect this to work, but want to simplify the error handling logic
	err = runWriteMode(ctx, device, cfg)
	if err != nil {
		t.Errorf("runWriteMode failed: %v", err)
	}
}
