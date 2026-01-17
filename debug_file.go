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
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"
)

// Session log state
var (
	sessionLogFile   *os.File
	sessionLogPath   string
	sessionLogWriter io.Writer
)

// InitSessionLog creates a new session log file in the current directory.
// Returns the log file path for display to the user.
func InitSessionLog() (string, error) {
	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("pn532_%s.log", timestamp)

	// Create log file in current directory
	logFile, err := os.Create(filename) //nolint:gosec // filename is constructed internally, not user input
	if err != nil {
		return "", fmt.Errorf("failed to create session log: %w", err)
	}

	sessionLogFile = logFile
	sessionLogPath = filename
	sessionLogWriter = logFile

	// Write session header
	writeSessionHeader(logFile)

	return filename, nil
}

// CloseSessionLog closes the current session log file.
func CloseSessionLog() error {
	if sessionLogFile != nil {
		// Write session footer
		timestamp := time.Now().Format("15:04:05.000")
		_, _ = fmt.Fprintf(sessionLogWriter, "\n%s === Session ended ===\n", timestamp)

		err := sessionLogFile.Close()
		sessionLogFile = nil
		sessionLogPath = ""
		sessionLogWriter = nil
		if err != nil {
			return fmt.Errorf("failed to close session log: %w", err)
		}
	}
	return nil
}

// GetSessionLogPath returns the current session log file path.
func GetSessionLogPath() string {
	return sessionLogPath
}

// writeSessionHeader writes metadata about the session to the log file.
func writeSessionHeader(writer io.Writer) {
	_, _ = fmt.Fprint(writer, "=== PN532 Debug Session Log ===\n")
	_, _ = fmt.Fprintf(writer, "Started: %s\n", time.Now().Format(time.RFC3339))
	_, _ = fmt.Fprintf(writer, "PID: %d\n", os.Getpid())
	_, _ = fmt.Fprintf(writer, "OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	_, _ = fmt.Fprintf(writer, "Go Version: %s\n", runtime.Version())
	if exe, err := os.Executable(); err == nil {
		_, _ = fmt.Fprintf(writer, "Executable: %s\n", exe)
	}
	_, _ = fmt.Fprintf(writer, "Command Line: %s\n", strings.Join(os.Args, " "))
	_, _ = fmt.Fprint(writer, "================================\n\n")
}
