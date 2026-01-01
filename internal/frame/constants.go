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

// Frame direction constants - these indicate the direction of data flow
const (
	HostToPn532 = 0xD4 // Commands from host to PN532
	Pn532ToHost = 0xD5 // Responses from PN532 to host
)

// Frame markers and control bytes
const (
	Preamble   = 0x00 // Frame preamble byte
	StartCode1 = 0x00 // Start code byte 1
	StartCode2 = 0xFF // Start code byte 2
	Postamble  = 0x00 // Frame postamble byte
)

// Frame size limits
const (
	MaxFrameDataLength = 263 // Maximum data length in frame (PN532 spec)
	MinFrameLength     = 6   // Minimum frame length (preamble + startcode + len + lcs + tfi + dcs)
)

// ACK and NACK frames - these are used for flow control
var (
	AckFrame  = []byte{0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00}
	NackFrame = []byte{0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00}
)
