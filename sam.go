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

// SAMMode represents the SAM configuration mode
type SAMMode byte

const (
	// SAMModeNormal - normal mode (default)
	SAMModeNormal SAMMode = 0x01
	// SAMModeVirtualCard - Virtual Card mode
	SAMModeVirtualCard SAMMode = 0x02
	// SAMModeWiredCard - Wired Card mode
	SAMModeWiredCard SAMMode = 0x03
	// SAMModeDualCard - Dual Card mode
	SAMModeDualCard SAMMode = 0x04

	// SAMNormal is an alias for SAMModeNormal for backward compatibility
	SAMNormal = SAMModeNormal
)
