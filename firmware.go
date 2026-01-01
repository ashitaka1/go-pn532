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

// FirmwareVersion contains PN532 firmware information
type FirmwareVersion struct {
	Version          string
	SupportIso14443a bool
	SupportIso14443b bool
	SupportIso18092  bool
}

// GeneralStatus contains PN532 general status information
type GeneralStatus struct {
	LastError    byte
	FieldPresent bool
	Targets      byte
}

// DiagnoseResult contains the result of a diagnose test
type DiagnoseResult struct {
	Data       []byte
	TestNumber byte
	Success    bool
}

// DiagnoseTestNumber constants
const (
	DiagnoseCommunicationTest = 0x00
	DiagnoseROMTest           = 0x01
	DiagnoseRAMTest           = 0x02
	// 0x03 is not used
	DiagnosePollingTest     = 0x04
	DiagnoseEchoBackTest    = 0x05
	DiagnoseAttentionTest   = 0x06
	DiagnoseSelfAntennaTest = 0x07
)
