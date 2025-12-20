// Copyright 2025 The Zaparoo Project Contributors.
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

package i2c

import (
	"context"
	"runtime"

	"github.com/ZaparooProject/go-pn532/detection"
)

const (
	// DefaultPN532Address is the standard I2C address for PN532 (0x48 >> 1)
	DefaultPN532Address = 0x24
)

// detector implements the Detector interface for I2C devices
type detector struct{}

// New creates a new I2C detector
func New() detection.Detector {
	return &detector{}
}

// init registers the detector on package import
func init() {
	detection.RegisterDetector(New())
}

// Transport returns the transport type
func (*detector) Transport() string {
	return "i2c"
}

// Detect searches for PN532 devices on I2C buses
func (*detector) Detect(ctx context.Context, opts *detection.Options) ([]detection.DeviceInfo, error) {
	// I2C detection is platform-specific
	switch runtime.GOOS {
	case "linux":
		return detectLinux(ctx, opts)
	case "windows", "darwin":
		// Limited I2C support on Windows and macOS
		return nil, detection.ErrUnsupportedPlatform
	default:
		return nil, detection.ErrUnsupportedPlatform
	}
}
