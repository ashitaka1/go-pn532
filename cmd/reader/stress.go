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

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
	"github.com/ZaparooProject/go-pn532/internal/syncutil"
	"github.com/ZaparooProject/go-pn532/polling"
	"github.com/ZaparooProject/go-pn532/tagops"
)

const (
	stressTestCycles        = 10
	stressTestNDEFPrefix    = "Test #"
	stressTestRawBlockStart = 4
	stressTestRawBlockCount = 2
)

// StressTestResult holds the final result for a tag test.
type StressTestResult struct {
	UID         string
	TagType     string
	CrashFile   string
	TotalCycles int
	PassedNDEF  int
	FailedNDEF  int
	PassedRaw   int
	FailedRaw   int
	Duration    time.Duration
	Success     bool
}

// TagTestState tracks the testing state for a single tag.
type TagTestState struct {
	Started      time.Time
	UID          string
	TagType      pn532.TagType
	TagTypeName  string
	OpLog        []LogEntry
	OriginalData []byte
	PassedNDEF   int
	FailedNDEF   int
	PassedRaw    int
	FailedRaw    int
	TotalCycles  int
	CurrentCycle int
	TargetNumber byte
}

// CrashReport contains all information for debugging a failure.
type CrashReport struct {
	Timestamp    time.Time  `json:"timestamp"`
	TagUID       string     `json:"tag_uid"`
	TagType      string     `json:"tag_type"`
	Operation    string     `json:"operation"`
	Error        string     `json:"error"`
	ExpectedHex  string     `json:"expected_hex,omitempty"`
	ActualHex    string     `json:"actual_hex,omitempty"`
	RawTagDump   []string   `json:"raw_tag_dump,omitempty"`
	OperationLog []LogEntry `json:"operation_log"`
	Cycle        int        `json:"cycle"`
	TargetNumber byte       `json:"target_number"`
}

// LogEntry represents a single operation in the log.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	DataHex   string    `json:"data_hex,omitempty"`
	Error     string    `json:"error,omitempty"`
	Success   bool      `json:"success"`
}

// testFailureInfo holds information about a test failure.
type testFailureInfo struct {
	err       error
	state     *TagTestState
	ops       *tagops.TagOperations
	operation string
	expected  []byte
	actual    []byte
}

// tagTestContext holds common parameters for tag testing functions.
type tagTestContext struct {
	device *pn532.Device
	ops    *tagops.TagOperations
	tag    *pn532.DetectedTag
	state  *TagTestState
	result *StressTestResult
}

func printStressTestBanner() {
	_, _ = fmt.Println("================================================================================")
	_, _ = fmt.Println("                         PN532 NFC Tag Stress Test Mode")
	_, _ = fmt.Println("================================================================================")
	_, _ = fmt.Println("Debug mode: ENABLED")
	_, _ = fmt.Printf("Test cycles: %d\n", stressTestCycles)
	_, _ = fmt.Println("Multi-tag mode: ENABLED (up to 2 tags)")
}

func runStressTestMode(ctx context.Context, device *pn532.Device, _ *config) error {
	printStressTestBanner()

	sessionConfig := polling.DefaultConfig()
	session := polling.NewSession(device, sessionConfig)

	defer func() {
		if err := session.Close(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to close session: %v\n", err)
		}
	}()

	var results []*StressTestResult
	var resultsMu syncutil.Mutex

	session.SetOnMultiTagDetected(func(tags []*pn532.DetectedTag) error {
		for i, tag := range tags {
			printTagHeader(i+1, tag)
			result := runStressTestForTag(ctx, device, tag)
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}
		return nil
	})

	session.SetOnMultiTagRemoved(func() {
		_, _ = fmt.Println()
		printFinalSummary(results)
		_, _ = fmt.Println("\nTags removed - ready for next test...")
		resultsMu.Lock()
		results = nil
		resultsMu.Unlock()
	})

	_, _ = fmt.Println("\nWaiting for tags... (Press Ctrl+C to exit)")

	done := make(chan error, 1)
	go func() {
		done <- session.StartMultiTag(ctx)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func printTagHeader(tagNum int, tag *pn532.DetectedTag) {
	_, _ = fmt.Println()
	_, _ = fmt.Println("--------------------------------------------------------------------------------")
	_, _ = fmt.Printf("[TAG %d] UID=%s  Type=%s  Target=%d\n",
		tagNum, tag.UID, tagops.TagTypeDisplayName(tag.Type), tag.TargetNumber)
	_, _ = fmt.Println("--------------------------------------------------------------------------------")
}

func runStressTestForTag(
	ctx context.Context,
	device *pn532.Device,
	tag *pn532.DetectedTag,
) *StressTestResult {
	state := &TagTestState{
		UID:          tag.UID,
		TargetNumber: tag.TargetNumber,
		TagType:      tag.Type,
		TagTypeName:  tagops.TagTypeDisplayName(tag.Type),
		TotalCycles:  stressTestCycles,
		Started:      time.Now(),
		OpLog:        make([]LogEntry, 0, 64),
	}

	result := &StressTestResult{
		UID:         tag.UID,
		TagType:     state.TagTypeName,
		TotalCycles: stressTestCycles,
	}

	tc := &tagTestContext{
		device: device,
		ops:    tagops.New(device),
		tag:    tag,
		state:  state,
		result: result,
	}

	if !initializeTag(ctx, tc) {
		return result
	}

	testErr := runTestCycles(ctx, tc)

	restoreOriginalData(ctx, tc)

	result.PassedNDEF = state.PassedNDEF
	result.FailedNDEF = state.FailedNDEF
	result.PassedRaw = state.PassedRaw
	result.FailedRaw = state.FailedRaw
	result.Duration = time.Since(state.Started)
	result.Success = testErr == nil

	printTagTestSummary(result)
	return result
}

func initializeTag(ctx context.Context, tc *tagTestContext) bool {
	if err := tc.device.InSelect(ctx, tc.tag.TargetNumber); err != nil {
		_, _ = fmt.Printf("  [!] Failed to select tag: %v\n", err)
		tc.result.FailedNDEF = stressTestCycles
		tc.result.FailedRaw = stressTestCycles
		return false
	}

	if err := tc.ops.DetectTag(ctx); err != nil {
		_, _ = fmt.Printf("  [!] Failed to detect tag type: %v\n", err)
		tc.result.FailedNDEF = stressTestCycles
		tc.result.FailedRaw = stressTestCycles
		return false
	}

	tc.state.TagType = tc.ops.GetTagType()
	tc.state.TagTypeName = tagops.TagTypeDisplayName(tc.state.TagType)

	originalData, backupErr := backupTagData(ctx, tc.ops)
	if backupErr != nil {
		_, _ = fmt.Printf("  [!] Warning: Could not backup data: %v\n", backupErr)
	} else {
		tc.state.OriginalData = originalData
		_, _ = fmt.Printf("  Backing up original data... OK (%d bytes)\n", len(originalData))
	}

	return true
}

func runTestCycles(ctx context.Context, tc *tagTestContext) error {
	for cycle := 1; cycle <= stressTestCycles; cycle++ {
		tc.state.CurrentCycle = cycle
		_, _ = fmt.Printf("\n  Cycle %02d/%02d:\n", cycle, stressTestCycles)

		if err := tc.device.InSelect(ctx, tc.tag.TargetNumber); err != nil {
			testErr := fmt.Errorf("failed to select tag: %w", err)
			handleTestFailure(ctx, &testFailureInfo{
				ops: tc.ops, state: tc.state, operation: "select", err: testErr,
			}, tc.result)
			return testErr
		}

		if err := runNDEFTestCycle(ctx, tc.ops, tc.state, cycle); err != nil {
			tc.state.FailedNDEF++
			handleTestFailure(ctx, &testFailureInfo{
				ops: tc.ops, state: tc.state, operation: "ndef", err: err,
			}, tc.result)
			return err
		}
		tc.state.PassedNDEF++

		expectedData, actualData, err := runRawBlockTestCycle(ctx, tc.ops, tc.state)
		if err != nil {
			tc.state.FailedRaw++
			handleTestFailure(ctx, &testFailureInfo{
				ops: tc.ops, state: tc.state, operation: "raw",
				expected: expectedData, actual: actualData, err: err,
			}, tc.result)
			return err
		}
		tc.state.PassedRaw++
	}
	return nil
}

func restoreOriginalData(ctx context.Context, tc *tagTestContext) {
	if len(tc.state.OriginalData) == 0 {
		return
	}

	if err := tc.device.InSelect(ctx, tc.tag.TargetNumber); err != nil {
		return
	}

	if restoreErr := restoreTagData(ctx, tc.ops, tc.state.OriginalData); restoreErr != nil {
		_, _ = fmt.Printf("\n  [!] Warning: Could not restore data: %v\n", restoreErr)
	} else {
		_, _ = fmt.Println("\n  Restoring original data... OK")
	}
}

func handleTestFailure(ctx context.Context, info *testFailureInfo, result *StressTestResult) {
	_, _ = fmt.Printf("\n  [!] FAILURE at cycle %d, %s: %v\n",
		info.state.CurrentCycle, info.operation, info.err)

	rawDump, _ := dumpEntireTag(ctx, info.ops)

	report := createCrashReport(info, rawDump)
	filename, writeErr := writeCrashReportToFile(report)
	if writeErr != nil {
		_, _ = fmt.Printf("  [!] Failed to write crash report: %v\n", writeErr)
	} else {
		_, _ = fmt.Printf("  Creating crash report... %s\n", filename)
		result.CrashFile = filename
	}
}

func runNDEFTestCycle(
	ctx context.Context,
	ops *tagops.TagOperations,
	state *TagTestState,
	cycle int,
) error {
	testText := fmt.Sprintf("%s%d", stressTestNDEFPrefix, cycle)
	msg := &pn532.NDEFMessage{
		Records: []pn532.NDEFRecord{
			{Type: pn532.NDEFTypeText, Text: testText},
		},
	}

	_, _ = fmt.Printf("    [NDEF]  Write %q... ", testText)
	state.OpLog = append(state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: "ndef_write",
		DataHex:   testText,
	})

	if err := ops.WriteNDEF(ctx, msg); err != nil {
		_, _ = fmt.Println("FAIL")
		state.OpLog[len(state.OpLog)-1].Success = false
		state.OpLog[len(state.OpLog)-1].Error = err.Error()
		return fmt.Errorf("NDEF write failed: %w", err)
	}
	state.OpLog[len(state.OpLog)-1].Success = true
	_, _ = fmt.Print("OK  ")

	_, _ = fmt.Print("Read... ")
	state.OpLog = append(state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: "ndef_read",
	})

	readMsg, err := ops.ReadNDEF(ctx)
	if err != nil {
		_, _ = fmt.Println("FAIL")
		state.OpLog[len(state.OpLog)-1].Success = false
		state.OpLog[len(state.OpLog)-1].Error = err.Error()
		return fmt.Errorf("NDEF read failed: %w", err)
	}
	state.OpLog[len(state.OpLog)-1].Success = true
	_, _ = fmt.Print("OK  ")

	_, _ = fmt.Print("Verify... ")
	state.OpLog = append(state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: "ndef_verify",
	})

	if err := verifyNDEFContent(msg, readMsg); err != nil {
		_, _ = fmt.Println("FAIL")
		state.OpLog[len(state.OpLog)-1].Success = false
		state.OpLog[len(state.OpLog)-1].Error = err.Error()
		return err
	}
	state.OpLog[len(state.OpLog)-1].Success = true
	_, _ = fmt.Println("OK")

	return nil
}

func runRawBlockTestCycle(
	ctx context.Context,
	ops *tagops.TagOperations,
	state *TagTestState,
) (expected, actual []byte, err error) {
	testData := generateRandomTestData(stressTestRawBlockCount * 4)
	startBlock := byte(stressTestRawBlockStart)
	endBlock := startBlock + byte(stressTestRawBlockCount) - 1

	_, _ = fmt.Printf("    [RAW]   Write blocks %d-%d... ", startBlock, endBlock)
	state.OpLog = append(state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: "raw_write",
		DataHex:   hex.EncodeToString(testData),
	})

	if writeErr := ops.WriteBlocks(ctx, startBlock, testData); writeErr != nil {
		_, _ = fmt.Println("FAIL")
		state.OpLog[len(state.OpLog)-1].Success = false
		state.OpLog[len(state.OpLog)-1].Error = writeErr.Error()
		return testData, nil, fmt.Errorf("raw write failed: %w", writeErr)
	}
	state.OpLog[len(state.OpLog)-1].Success = true
	_, _ = fmt.Print("OK  ")

	_, _ = fmt.Print("Read... ")
	state.OpLog = append(state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: "raw_read",
	})

	readData, readErr := ops.ReadBlocks(ctx, startBlock, endBlock)
	if readErr != nil {
		_, _ = fmt.Println("FAIL")
		state.OpLog[len(state.OpLog)-1].Success = false
		state.OpLog[len(state.OpLog)-1].Error = readErr.Error()
		return testData, nil, fmt.Errorf("raw read failed: %w", readErr)
	}
	state.OpLog[len(state.OpLog)-1].Success = true
	state.OpLog[len(state.OpLog)-1].DataHex = hex.EncodeToString(readData)
	_, _ = fmt.Print("OK  ")

	_, _ = fmt.Print("Verify... ")
	state.OpLog = append(state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: "raw_verify",
	})

	compareLen := len(testData)
	if len(readData) < compareLen {
		compareLen = len(readData)
	}

	if !bytes.Equal(testData, readData[:compareLen]) {
		_, _ = fmt.Println("FAIL")
		errMsg := fmt.Sprintf("data mismatch: expected %s, got %s",
			hex.EncodeToString(testData), hex.EncodeToString(readData[:compareLen]))
		state.OpLog[len(state.OpLog)-1].Success = false
		state.OpLog[len(state.OpLog)-1].Error = errMsg
		return testData, readData[:compareLen], errors.New("raw data mismatch")
	}
	state.OpLog[len(state.OpLog)-1].Success = true
	_, _ = fmt.Println("OK")

	return nil, nil, nil
}

func verifyNDEFContent(expected, actual *pn532.NDEFMessage) error {
	if actual == nil {
		return errors.New("NDEF read returned nil")
	}
	if len(actual.Records) == 0 {
		return errors.New("NDEF read returned empty records")
	}
	if len(expected.Records) != len(actual.Records) {
		return fmt.Errorf("record count mismatch: expected %d, got %d",
			len(expected.Records), len(actual.Records))
	}

	for i := range expected.Records {
		if expected.Records[i].Text != actual.Records[i].Text {
			return fmt.Errorf("NDEF text mismatch at record %d: expected %q, got %q",
				i, expected.Records[i].Text, actual.Records[i].Text)
		}
	}
	return nil
}

func generateRandomTestData(size int) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		for i := range data {
			data[i] = byte(i ^ 0xAA)
		}
	}
	return data
}

func backupTagData(ctx context.Context, ops *tagops.TagOperations) ([]byte, error) {
	startBlock := byte(stressTestRawBlockStart)
	endBlock := startBlock + byte(stressTestRawBlockCount) - 1
	data, err := ops.ReadBlocks(ctx, startBlock, endBlock)
	if err != nil {
		return nil, fmt.Errorf("backup read failed: %w", err)
	}
	return data, nil
}

func restoreTagData(ctx context.Context, ops *tagops.TagOperations, data []byte) error {
	if err := ops.WriteBlocks(ctx, stressTestRawBlockStart, data); err != nil {
		return fmt.Errorf("restore write failed: %w", err)
	}
	return nil
}

func dumpEntireTag(ctx context.Context, ops *tagops.TagOperations) ([]byte, error) {
	data, err := ops.ReadAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("tag dump failed: %w", err)
	}
	return data, nil
}

func createCrashReport(info *testFailureInfo, rawDump []byte) *CrashReport {
	report := &CrashReport{
		Timestamp:    time.Now(),
		TagUID:       info.state.UID,
		TagType:      info.state.TagTypeName,
		TargetNumber: info.state.TargetNumber,
		Operation:    info.operation,
		Cycle:        info.state.CurrentCycle,
		Error:        info.err.Error(),
		OperationLog: info.state.OpLog,
	}

	if len(info.expected) > 0 {
		report.ExpectedHex = formatHexString(info.expected)
	}
	if len(info.actual) > 0 {
		report.ActualHex = formatHexString(info.actual)
	}
	if len(rawDump) > 0 {
		report.RawTagDump = formatHexDump(rawDump)
	}

	return report
}

func writeCrashReportToFile(report *CrashReport) (string, error) {
	uidSafe := strings.ReplaceAll(report.TagUID, ":", "")
	timestamp := report.Timestamp.Format("20060102_150405")
	filename := fmt.Sprintf("stress_test_crash_%s_%s.json", uidSafe, timestamp)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal crash report: %w", err)
	}

	if err := os.WriteFile(filename, data, 0o600); err != nil {
		return "", fmt.Errorf("failed to write crash report: %w", err)
	}

	return filename, nil
}

func formatHexString(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, " ")
}

func formatHexDump(data []byte) []string {
	pageSize := 4
	numPages := (len(data) + pageSize - 1) / pageSize
	lines := make([]string, 0, numPages)

	for i := 0; i < len(data); i += pageSize {
		end := i + pageSize
		if end > len(data) {
			end = len(data)
		}

		pageData := data[i:end]
		hexParts := make([]string, len(pageData))
		for j, b := range pageData {
			hexParts[j] = fmt.Sprintf("%02X", b)
		}

		line := fmt.Sprintf("Page %02d: %s", i/pageSize, strings.Join(hexParts, " "))
		lines = append(lines, line)
	}

	return lines
}

func printTagTestSummary(result *StressTestResult) {
	status := "PASS"
	if !result.Success {
		status = "FAIL"
	}

	completedCycles := result.PassedNDEF
	if result.PassedRaw < completedCycles {
		completedCycles = result.PassedRaw
	}

	_, _ = fmt.Printf("\n  [%s] %s - %d/%d cycles (NDEF: %d/%d, Raw: %d/%d) - %s\n",
		status,
		result.UID,
		completedCycles,
		result.TotalCycles,
		result.PassedNDEF,
		result.PassedNDEF+result.FailedNDEF,
		result.PassedRaw,
		result.PassedRaw+result.FailedRaw,
		result.Duration.Round(100*time.Millisecond),
	)
}

func printFinalSummary(results []*StressTestResult) {
	if len(results) == 0 {
		return
	}

	_, _ = fmt.Println("================================================================================")
	_, _ = fmt.Println("                              STRESS TEST SUMMARY")
	_, _ = fmt.Println("================================================================================")

	passCount := 0
	failCount := 0
	crashCount := 0

	_, _ = fmt.Printf("Tags tested: %d\n", len(results))
	for _, tagResult := range results {
		status := "PASS"
		if !tagResult.Success {
			status = "FAIL"
			failCount++
			if tagResult.CrashFile != "" {
				crashCount++
			}
		} else {
			passCount++
		}

		completedCycles := tagResult.PassedNDEF
		if tagResult.PassedRaw < completedCycles {
			completedCycles = tagResult.PassedRaw
		}

		_, _ = fmt.Printf("  [%s] %s (%s) - %d/%d cycles\n",
			status, tagResult.UID, tagResult.TagType, completedCycles, tagResult.TotalCycles)
	}

	_, _ = fmt.Printf("\nOverall: %d PASS, %d FAIL\n", passCount, failCount)
	if crashCount > 0 {
		_, _ = fmt.Printf("Crash reports written: %d\n", crashCount)
	}
	_, _ = fmt.Println("================================================================================")
}
