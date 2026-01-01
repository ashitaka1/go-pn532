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

package main

import (
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
	// NDEF capacity overhead (TLV headers, language code, record headers, terminator)
	// Measured: ~15 bytes, using 20 for safety margin
	ndefOverheadBytes = 20
)

// allTestChars is the complete pool of test characters for random generation.
// Combines ASCII, international, emoji, and edge case characters.
//
//nolint:gosmopolitan // Intentionally using non-Latin scripts for stress testing
var allTestChars = []rune(
	// ASCII printable
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~ " +
		// International - accented, Cyrillic, Greek, CJK
		"àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ" +
		"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞ" +
		"αβγδεζηθικλμνξοπρστυφχψω" +
		"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ" +
		"абвгдеёжзийклмнопрстуфхцчшщъыьэюя" +
		"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ" +
		"中文日本語한국어العربية" +
		// Emojis - 2-byte, 3-byte, and 4-byte UTF-8 sequences
		"🎮📱💻🔥⚡🚀🎯🏆🎲🃏" +
		"😀😎🤖👾👻💀☠️🤡👽🎃" +
		"❤️💔💯✨🌟⭐🔴🟢🔵🟡" +
		"🐱🐶🦊🐻🐼🐨🐯🦁🐮🐷" +
		// Edge cases - control chars, zero-width, complex emoji
		"\u0000\u001F\u007F\u0080\u00FF" +
		"\u200B\u200C\u200D\u00AD\u2028\u2029" +
		"🏳️\u200D🌈👨\u200D👩\u200D👧\u200D👦",
)

// StressTestResult holds the final result for a tag test.
type StressTestResult struct {
	UID       string
	TagType   string
	CrashFile string
	Passed    int
	Failed    int
	Duration  time.Duration
	Skipped   bool
	Success   bool
}

// TagTestState tracks the testing state for a single tag.
type TagTestState struct {
	Started      time.Time
	UID          string
	TagType      pn532.TagType
	TagTypeName  string
	CurrentTest  string
	CCData       []byte
	OriginalData []byte
	OpLog        []LogEntry
	ClaimedSize  int
	ActualSize   int
	Passed       int
	Failed       int
}

// CrashReport contains all information for debugging a failure.
type CrashReport struct {
	Timestamp           time.Time  `json:"timestamp"`
	TagUID              string     `json:"tag_uid"`
	TagType             string     `json:"tag_type"`
	Operation           string     `json:"operation"`
	Error               string     `json:"error"`
	ExpectedHex         string     `json:"expected_hex,omitempty"`
	ActualHex           string     `json:"actual_hex,omitempty"`
	CapabilityContainer string     `json:"capability_container,omitempty"`
	TestSize            string     `json:"test_size"`
	RawTagDump          []string   `json:"raw_tag_dump,omitempty"`
	OperationLog        []LogEntry `json:"operation_log"`
	ClaimedSize         int        `json:"claimed_size,omitempty"`
	ActualSize          int        `json:"actual_size,omitempty"`
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
	_, _ = fmt.Println("Tests: tiny, medium, full (3 total per tag)")
	// Note: Using single-tag mode due to multi-tag MIFARE auth issues
	// See docs/investigation-multitag-mifare-issue.md
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

	// Use single-tag mode - multi-tag has MIFARE auth issues
	// See docs/investigation-multitag-mifare-issue.md
	session.OnCardDetected = func(tag *pn532.DetectedTag) error {
		printTagHeader(1, tag)
		result := runStressTestForTag(ctx, device, tag)
		resultsMu.Lock()
		results = append(results, result)
		resultsMu.Unlock()
		return nil
	}

	session.OnCardRemoved = func() {
		_, _ = fmt.Println()
		printFinalSummary(results)
		_, _ = fmt.Println("\nTag removed - ready for next test...")
		resultsMu.Lock()
		results = nil
		resultsMu.Unlock()
	}

	_, _ = fmt.Println("\nWaiting for tag... (Press Ctrl+C to exit)")

	done := make(chan error, 1)
	go func() {
		done <- session.Start(ctx)
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
	mfr := tag.Manufacturer()
	_, _ = fmt.Printf("[TAG %d] UID=%s  Type=%s  Manufacturer=%s\n",
		tagNum, tag.UID, tagops.TagTypeDisplayName(tag.Type), mfr)
	_, _ = fmt.Println("--------------------------------------------------------------------------------")
}

func runStressTestForTag(
	ctx context.Context,
	device *pn532.Device,
	tag *pn532.DetectedTag,
) *StressTestResult {
	state := &TagTestState{
		UID:         tag.UID,
		TagType:     tag.Type,
		TagTypeName: tagops.TagTypeDisplayName(tag.Type),
		Started:     time.Now(),
		OpLog:       make([]LogEntry, 0, 32),
	}

	result := &StressTestResult{
		UID:     tag.UID,
		TagType: state.TagTypeName,
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

	testErr := runTests(ctx, tc)

	result.Passed = state.Passed
	result.Failed = state.Failed
	result.Duration = time.Since(state.Started)
	result.Success = testErr == nil && state.Failed == 0

	printTagTestSummary(result)
	return result
}

func initializeTag(ctx context.Context, tc *tagTestContext) bool {
	// Initialize operations from the detected tag directly.
	// We avoid calling DetectTag() here because it performs a second InListPassiveTarget
	// (with an InRelease(0) beforehand) which can corrupt the tag state for subsequent
	// authentication attempts, specifically causing Key B authentication to fail.
	if err := tc.ops.InitFromDetectedTag(ctx, tc.tag); err != nil {
		_, _ = fmt.Printf("  [!] Failed to initialize tag: %v\n", err)
		tc.result.Failed = 3
		return false
	}

	tc.state.TagType = tc.ops.GetTagType()
	tc.state.TagTypeName = tagops.TagTypeDisplayName(tc.state.TagType)

	// Read capability container for diagnostics (NTAG only)
	if tc.state.TagType == pn532.TagTypeNTAG {
		if ccData, err := tc.ops.ReadCapabilityContainer(ctx); err == nil {
			tc.state.CCData = ccData
			tc.state.ClaimedSize = tagops.GetClaimedSizeFromCC(ccData)
			_, _ = fmt.Printf("  Capability container: %02X (claims %d bytes)\n",
				ccData, tc.state.ClaimedSize)
		}
		// Use claimed size as actual size - if writes fail, we'll report with manufacturer info
		tc.state.ActualSize = tc.state.ClaimedSize
	}

	return true
}

func runTests(ctx context.Context, tc *tagTestContext) error {
	// Note: We deliberately skip InSelect here. The tag is already selected by the
	// polling loop's InListPassiveTarget. Calling InSelect (0x54) on an already
	// active target can desynchronize the PN532's internal authentication state,
	// leading to failures when switching keys (e.g., Key A -> Key B) or sectors.
	//
	// Run all 3 tests: tiny, medium, full
	sizes := []testSize{testSizeTiny, testSizeMedium, testSizeFull}
	maxBytes := getMaxNDEFTextBytes(tc.ops, tc.state.ActualSize)

	for _, size := range sizes {
		tc.state.CurrentTest = size.String()
		if err := runSingleTest(ctx, tc, size, maxBytes); err != nil {
			tc.state.Failed++
			handleTestFailure(ctx, &testFailureInfo{
				ops: tc.ops, state: tc.state, operation: size.String(), err: err,
			}, tc.result)
			return err
		}
		tc.state.Passed++
	}
	return nil
}

// runSingleTest runs a single write/read/verify test for the given size
func runSingleTest(ctx context.Context, tc *tagTestContext, size testSize, maxBytes int) error {
	testText := generateTestText(size, maxBytes)

	msg := &pn532.NDEFMessage{
		Records: []pn532.NDEFRecord{
			{Type: pn532.NDEFTypeText, Text: testText},
		},
	}

	textBytes := len(testText)
	_, _ = fmt.Printf("  [%s] Write (%d bytes)... ", size, textBytes)
	tc.state.OpLog = append(tc.state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: fmt.Sprintf("write_%s", size),
		DataHex:   hex.EncodeToString([]byte(testText)),
	})

	if err := tc.ops.WriteNDEF(ctx, msg); err != nil {
		_, _ = fmt.Println("FAIL")
		tc.state.OpLog[len(tc.state.OpLog)-1].Success = false
		tc.state.OpLog[len(tc.state.OpLog)-1].Error = err.Error()
		return fmt.Errorf("write failed: %w", err)
	}
	tc.state.OpLog[len(tc.state.OpLog)-1].Success = true
	_, _ = fmt.Print("OK  Read... ")

	tc.state.OpLog = append(tc.state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: fmt.Sprintf("read_%s", size),
	})

	readMsg, err := tc.ops.ReadNDEF(ctx)
	if err != nil {
		_, _ = fmt.Println("FAIL")
		tc.state.OpLog[len(tc.state.OpLog)-1].Success = false
		tc.state.OpLog[len(tc.state.OpLog)-1].Error = err.Error()
		return fmt.Errorf("read failed: %w", err)
	}
	tc.state.OpLog[len(tc.state.OpLog)-1].Success = true
	_, _ = fmt.Print("OK  Verify... ")

	tc.state.OpLog = append(tc.state.OpLog, LogEntry{
		Timestamp: time.Now(),
		Operation: fmt.Sprintf("verify_%s", size),
	})

	if err := verifyNDEFContent(msg, readMsg); err != nil {
		_, _ = fmt.Println("FAIL")
		tc.state.OpLog[len(tc.state.OpLog)-1].Success = false
		tc.state.OpLog[len(tc.state.OpLog)-1].Error = err.Error()
		return err
	}
	tc.state.OpLog[len(tc.state.OpLog)-1].Success = true
	_, _ = fmt.Println("OK")

	return nil
}

func handleTestFailure(ctx context.Context, info *testFailureInfo, result *StressTestResult) {
	_, _ = fmt.Printf("\n  [!] FAILURE at %s test: %v\n",
		info.state.CurrentTest, info.err)

	// Show manufacturer hint for clone tag issues
	if info.ops != nil {
		uid := info.ops.GetUID()
		mfr := pn532.GetManufacturer(uid)
		if mfr == pn532.ManufacturerUnknown {
			_, _ = fmt.Println("  [!] Unknown manufacturer - likely a clone tag with limited memory")
		}
	}

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

// testSize represents the three test sizes per cycle
type testSize int

const (
	testSizeTiny   testSize = iota // 1-4 bytes
	testSizeMedium                 // 50% of capacity
	testSizeFull                   // 100% of capacity
)

func (s testSize) String() string {
	switch s {
	case testSizeTiny:
		return "tiny"
	case testSizeMedium:
		return "medium"
	case testSizeFull:
		return "full"
	default:
		return "unknown"
	}
}

// generateTestText creates random text for the given size and capacity.
// Uses the full character pool (ASCII, international, emoji, edge cases).
func generateTestText(size testSize, maxBytes int) string {
	var targetBytes int
	switch size {
	case testSizeTiny:
		targetBytes = randomInt(1, 4)
	case testSizeMedium:
		targetBytes = maxBytes / 2
	case testSizeFull:
		targetBytes = maxBytes
	}

	if targetBytes > maxBytes {
		targetBytes = maxBytes
	}
	if targetBytes < 1 {
		targetBytes = 1
	}

	return generateRandomText(targetBytes)
}

// generateRandomText creates random text from the full character pool up to maxBytes
func generateRandomText(maxBytes int) string {
	// Pre-allocate assuming average ~2 bytes per rune (conservative for mixed content)
	result := make([]rune, 0, maxBytes/2)
	currentBytes := 0

	for currentBytes < maxBytes {
		idx := randomInt(0, len(allTestChars)-1)
		char := allTestChars[idx]
		charBytes := len(string(char))

		if currentBytes+charBytes > maxBytes {
			break
		}

		result = append(result, char)
		currentBytes += charBytes
	}

	return string(result)
}

// randomInt returns a random int in [low, high] inclusive
func randomInt(low, high int) int {
	if low >= high {
		return low
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	// Simple modulo - not crypto-secure but fine for testing
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	return low + (n % (high - low + 1))
}

// getMaxNDEFTextBytes calculates max text bytes for the tag.
// If probedSize > 0, it uses that instead of the claimed size (for clone tags).
func getMaxNDEFTextBytes(ops *tagops.TagOperations, probedSize int) int {
	var userMemory int

	// Prefer probed size if available (catches clone tags that lie)
	if probedSize > 0 {
		userMemory = probedSize
	} else {
		info, err := ops.GetTagInfo()
		if err != nil || info == nil {
			return 100 // Conservative fallback
		}
		userMemory = info.UserMemory
	}

	maxBytes := userMemory - ndefOverheadBytes
	if maxBytes < 10 {
		maxBytes = 10
	}

	return maxBytes
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
		Operation:    info.operation,
		TestSize:     info.state.CurrentTest,
		Error:        info.err.Error(),
		OperationLog: info.state.OpLog,
		ClaimedSize:  info.state.ClaimedSize,
		ActualSize:   info.state.ActualSize,
	}

	if len(info.state.CCData) > 0 {
		report.CapabilityContainer = formatHexString(info.state.CCData)
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
	if result.Skipped {
		return // Already printed skip message
	}

	status := "PASS"
	if !result.Success {
		status = "FAIL"
	}

	_, _ = fmt.Printf("\n  [%s] %s - %d/3 tests passed - %s\n",
		status,
		result.UID,
		result.Passed,
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
	skipCount := 0
	crashCount := 0

	_, _ = fmt.Printf("Tags tested: %d\n", len(results))
	for _, tagResult := range results {
		var status string
		switch {
		case tagResult.Skipped:
			status = "SKIP"
			skipCount++
		case tagResult.Success:
			status = "PASS"
			passCount++
		default:
			status = "FAIL"
			failCount++
			if tagResult.CrashFile != "" {
				crashCount++
			}
		}

		_, _ = fmt.Printf("  [%s] %s (%s) - %d/3 tests\n",
			status, tagResult.UID, tagResult.TagType, tagResult.Passed)
	}

	_, _ = fmt.Printf("\nOverall: %d PASS, %d FAIL, %d SKIP\n", passCount, failCount, skipCount)
	if crashCount > 0 {
		_, _ = fmt.Printf("Crash reports written: %d\n", crashCount)
	}
	_, _ = fmt.Println("================================================================================")
}
