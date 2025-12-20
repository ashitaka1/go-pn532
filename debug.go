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

package pn532

import (
	"fmt"
	"os"
)

// debugEnabled controls whether debug logging is active
// This can be controlled via build tags or environment variables
var debugEnabled = false

func init() {
	// Enable debug logging if DEBUG environment variable is set
	if os.Getenv("PN532_DEBUG") != "" || os.Getenv("DEBUG") != "" {
		debugEnabled = true
	}
}

// Debugf prints debug information only when debug mode is enabled
// This eliminates the performance overhead of fmt.Printf in production
func Debugf(format string, args ...any) {
	if debugEnabled {
		_, _ = fmt.Printf("DEBUG: "+format+"\n", args...)
	}
}

// Debugln prints debug information only when debug mode is enabled
// This eliminates the performance overhead of fmt.Printf in production
func Debugln(args ...any) {
	if debugEnabled {
		_, _ = fmt.Print("DEBUG: ")
		_, _ = fmt.Println(args...)
	}
}

// SetDebugEnabled allows programmatic control of debug logging
// Useful for testing or application-controlled debug modes
func SetDebugEnabled(enabled bool) {
	debugEnabled = enabled
}
