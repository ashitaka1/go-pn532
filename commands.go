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

// PN532 Command codes
const (
	cmdDiagnose            = 0x00
	cmdSamConfiguration    = 0x14
	cmdGetFirmwareVersion  = 0x02
	cmdGetGeneralStatus    = 0x04
	cmdInListPassiveTarget = 0x4A
	cmdInDataExchange      = 0x40
	cmdInRelease           = 0x52
	cmdInSelect            = 0x54
	cmdInAutoPoll          = 0x60
	cmdPowerDown           = 0x16
	cmdInCommunicateThru   = 0x42
	cmdRFConfiguration     = 0x32
)

// PowerDownWakeupFlags provides constants for PowerDown wake-up sources
const (
	WakeupHSU     byte = 0x01 // Wake-up by High Speed UART
	WakeupSPI     byte = 0x02 // Wake-up by SPI
	WakeupI2C     byte = 0x04 // Wake-up by I2C
	WakeupGPIOP32 byte = 0x08 // Wake-up by GPIO P32
	WakeupGPIOP34 byte = 0x10 // Wake-up by GPIO P34
	WakeupRF      byte = 0x20 // Wake-up by RF field
	WakeupINT1    byte = 0x80 // Wake-up by GPIO P72/INT1
)
