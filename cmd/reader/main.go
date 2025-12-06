// go-pn532
// Copyright (c) 2025 The Zaparoo Project Contributors.
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This file is part of go-pn532.
//
// go-pn532 is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// go-pn532 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with go-pn532; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
	"github.com/ZaparooProject/go-pn532/detection"
	_ "github.com/ZaparooProject/go-pn532/detection/i2c"
	_ "github.com/ZaparooProject/go-pn532/detection/spi"
	_ "github.com/ZaparooProject/go-pn532/detection/uart"
	"github.com/ZaparooProject/go-pn532/polling"
	"github.com/ZaparooProject/go-pn532/transport/i2c"
	"github.com/ZaparooProject/go-pn532/transport/spi"
	"github.com/ZaparooProject/go-pn532/transport/uart"
)

type config struct {
	writeText  string
	devicePath string
	debug      bool
}

// Package-level flag variables
var (
	flagWriteText  string
	flagDevicePath string
	flagDebug      bool
)

func init() {
	flag.StringVar(&flagWriteText, "write", "", "Text to write to the next scanned tag (exits after write)")
	flag.StringVar(&flagDevicePath, "device", "", "Device path (auto-detect if empty)")
	flag.BoolVar(&flagDebug, "debug", false, "Enable debug output")
}

func parseConfig() *config {
	cfg := &config{
		writeText:  flagWriteText,
		devicePath: flagDevicePath,
		debug:      flagDebug,
	}

	// Enable debug output if --debug flag is set
	if cfg.debug {
		pn532.SetDebugEnabled(true)
	}

	return cfg
}

// newTransportFromDevice creates a new transport from a detected device.
func newTransportFromDevice(device detection.DeviceInfo) (pn532.Transport, error) {
	switch strings.ToLower(device.Transport) {
	case "uart":
		transport, err := uart.New(device.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to create UART transport: %w", err)
		}
		return transport, nil
	case "i2c":
		transport, err := i2c.New(device.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to create I2C transport: %w", err)
		}
		return transport, nil
	case "spi":
		transport, err := spi.New(device.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to create SPI transport: %w", err)
		}
		return transport, nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", device.Transport)
	}
}

// newTransport creates a new transport from a device path by trying different transports.
func newTransport(path string) (pn532.Transport, error) {
	if path == "" {
		return nil, errors.New("empty device path")
	}

	pathLower := strings.ToLower(path)

	// Check for I2C pattern
	if strings.Contains(pathLower, "i2c") {
		transport, err := i2c.New(path)
		if err != nil {
			return nil, fmt.Errorf("failed to create I2C transport for %s: %w", path, err)
		}
		return transport, nil
	}

	// Check for SPI pattern
	if strings.Contains(pathLower, "spi") {
		transport, err := spi.New(path)
		if err != nil {
			return nil, fmt.Errorf("failed to create SPI transport for %s: %w", path, err)
		}
		return transport, nil
	}

	// Default to UART for serial ports
	transport, err := uart.New(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create UART transport for %s: %w", path, err)
	}
	return transport, nil
}

func connectToDevice(ctx context.Context, cfg *config) (*pn532.Device, error) {
	var connectOpts []pn532.ConnectOption

	if cfg.devicePath == "" {
		// Auto-detection case
		connectOpts = append(connectOpts,
			pn532.WithAutoDetection(),
			pn532.WithTransportFromDeviceFactory(newTransportFromDevice))
		if cfg.debug {
			_, _ = fmt.Println("Auto-detecting PN532 devices...")
		}
	} else {
		// Specific device path
		connectOpts = append(connectOpts, pn532.WithTransportFactory(newTransport))
		if cfg.debug {
			_, _ = fmt.Printf("Opening device: %s\n", cfg.devicePath)
		}
	}

	// Set reasonable timeout
	connectOpts = append(connectOpts, pn532.WithConnectTimeout(5*time.Second))

	device, err := pn532.ConnectDevice(cfg.devicePath, connectOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PN532 device: %w", err)
	}

	// Show firmware version if debug enabled
	if cfg.debug {
		if version, versionErr := device.GetFirmwareVersion(ctx); versionErr == nil {
			_, _ = fmt.Printf("PN532 Firmware: %s\n", version.Version)
		}
	}

	return device, nil
}

func runReadMode(ctx context.Context, device *pn532.Device, _ *config) error {
	// Create session with default configuration
	sessionConfig := polling.DefaultConfig()
	session := polling.NewSession(device, sessionConfig)

	// Ensure session cleanup for fast shutdown
	defer func() {
		if err := session.Close(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to close session: %v\n", err)
		}
	}()

	_, _ = fmt.Println("Starting continuous tag monitoring. Press Ctrl+C to stop...")

	// Set up tag detection callback
	session.OnCardDetected = func(detectedTag *pn532.DetectedTag) error {
		// Create tag interface to get detailed information
		tag, err := device.CreateTag(detectedTag)
		if err != nil {
			_, _ = fmt.Printf("Failed to create tag interface: %v\n", err)
			return nil // Continue monitoring
		}

		// Print tag information
		_, _ = fmt.Printf("Tag detected: UID=%s Type=%s\n", detectedTag.UID, detectedTag.Type)
		_, _ = fmt.Print(tag.DebugInfo())

		return nil
	}

	// Set up tag removal callback
	session.OnCardRemoved = func() {
		_, _ = fmt.Println("Tag removed - ready for next tag...")
	}

	// Start the session in a goroutine to allow for immediate cancellation
	done := make(chan error, 1)
	go func() {
		done <- session.Start(ctx)
	}()

	// Wait for either session completion or context cancellation
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("failed to start session: %w", err)
		}
		return nil
	case <-ctx.Done():
		// Context cancelled - session.Close() will be called by defer
		return ctx.Err()
	}
}

func runWriteMode(ctx context.Context, device *pn532.Device, cfg *config) error {
	if device == nil {
		return errors.New("device cannot be nil for write mode")
	}

	if cfg.writeText == "" {
		return errors.New("writeText cannot be empty for write mode")
	}

	// Create session with default configuration for write operations
	sessionConfig := polling.DefaultConfig()
	session := polling.NewSession(device, sessionConfig)

	// Ensure session cleanup for fast shutdown
	defer func() {
		if err := session.Close(); err != nil && cfg.debug {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to close session: %v\n", err)
		}
	}()

	_, _ = fmt.Printf("Waiting for tag to write text: %q\n", cfg.writeText)
	_, _ = fmt.Println("Please place a tag near the reader...")

	// Set a reasonable timeout for tag detection (30 seconds)
	timeout := 30 * time.Second

	// Use WriteToNextTag to wait for a tag and write to it
	// Note: Using the same context for both session and write operations in this simple example.
	// For concurrent scenarios where you want independent cancellation control, create separate contexts:
	//   sessionCtx := ctx
	//   writeCtx, cancelWrite := context.WithCancel(ctx)
	//   defer cancelWrite()
	err := session.WriteToNextTag(ctx, ctx, timeout, func(ctx context.Context, tag pn532.Tag) error {
		_, _ = fmt.Println("Tag detected! Writing text...")

		// Create NDEF message with text record
		message := &pn532.NDEFMessage{
			Records: []pn532.NDEFRecord{
				{
					Type: pn532.NDEFTypeText,
					Text: cfg.writeText,
				},
			},
		}

		// Write the NDEF message to the tag with context support
		if err := tag.WriteNDEFWithContext(ctx, message); err != nil {
			return fmt.Errorf("failed to write NDEF message: %w", err)
		}

		_, _ = fmt.Printf("Successfully wrote text to tag: %q\n", cfg.writeText)
		return nil
	})
	// Handle any errors from the write operation
	if err != nil {
		if errors.Is(err, context.Canceled) {
			_, _ = fmt.Println("Write operation cancelled.")
		}
		return fmt.Errorf("write operation failed: %w", err)
	}

	return nil
}

func diagnoseFirmware(ctx context.Context, device *pn532.Device) {
	version, err := device.GetFirmwareVersion(ctx)
	if err != nil {
		_, _ = fmt.Printf("[✗] Firmware: %v\n", err)
		return
	}
	var protocols []string
	if version.SupportIso14443a {
		protocols = append(protocols, "ISO14443A")
	}
	if version.SupportIso14443b {
		protocols = append(protocols, "ISO14443B")
	}
	if version.SupportIso18092 {
		protocols = append(protocols, "ISO18092")
	}
	_, _ = fmt.Printf("[✓] Firmware: v%s (%s)\n", version.Version, strings.Join(protocols, ", "))
}

func diagnoseRTT(ctx context.Context, device *pn532.Device) {
	const samples = 10
	var rtts []time.Duration
	for range samples {
		start := time.Now()
		_, err := device.GetFirmwareVersion(ctx)
		if err == nil {
			rtts = append(rtts, time.Since(start))
		}
	}
	if len(rtts) == 0 {
		_, _ = fmt.Println("[✗] Communication: Failed to measure RTT")
		return
	}
	minRTT, maxRTT, sumRTT := rtts[0], rtts[0], time.Duration(0)
	for _, rtt := range rtts {
		sumRTT += rtt
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}
	avgRTT := sumRTT / time.Duration(len(rtts))
	_, _ = fmt.Printf("[✓] Communication: RTT min=%s avg=%s max=%s (%d samples)\n",
		minRTT.Round(time.Millisecond), avgRTT.Round(time.Millisecond), maxRTT.Round(time.Millisecond), len(rtts))
}

func diagnoseTest(ctx context.Context, device *pn532.Device, testNum byte, name string) {
	result, err := device.Diagnose(ctx, testNum, nil)
	switch {
	case err != nil:
		_, _ = fmt.Printf("[✗] %s: %v\n", name, err)
	case result.Success:
		_, _ = fmt.Printf("[✓] %s: OK\n", name)
	default:
		_, _ = fmt.Printf("[✗] %s: FAILED\n", name)
	}
}

func diagnoseRFField(ctx context.Context, device *pn532.Device) {
	status, err := device.GetGeneralStatus(ctx)
	switch {
	case err != nil:
		_, _ = fmt.Printf("[✗] RF field: %v\n", err)
	case status.FieldPresent:
		_, _ = fmt.Println("[✓] RF field: Active")
	default:
		_, _ = fmt.Println("[✓] RF field: Inactive (will activate on poll)")
	}
}

func diagnoseTagDetection(ctx context.Context, device *pn532.Device) {
	detectCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	tag, err := device.DetectTag(detectCtx)
	if err != nil {
		_, _ = fmt.Println("[✓] Tag detection: Ready (no tag present)")
	} else {
		_, _ = fmt.Printf("[✓] Tag detection: %s (UID: %s)\n", tag.Type, tag.UID)
	}
}

func runDiagnostics(ctx context.Context, device *pn532.Device) {
	_, _ = fmt.Println("\nPN532 Diagnostics")
	_, _ = fmt.Println("=================")

	diagnoseFirmware(ctx, device)
	diagnoseRTT(ctx, device)
	diagnoseTest(ctx, device, pn532.DiagnoseROMTest, "ROM test")
	diagnoseTest(ctx, device, pn532.DiagnoseRAMTest, "RAM test")
	diagnoseTest(ctx, device, pn532.DiagnoseSelfAntennaTest, "Antenna test")
	diagnoseRFField(ctx, device)
	diagnoseTagDetection(ctx, device)

	_, _ = fmt.Println()
}

func run(ctx context.Context, cfg *config) error {
	// Connect to device
	device, err := connectToDevice(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := device.Close(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to close device: %v\n", err)
		}
	}()

	// Run diagnostics on startup
	runDiagnostics(ctx, device)

	// Mode selection based on writeText parameter
	if cfg.writeText != "" {
		// Write mode - write text to next scanned tag and exit
		return runWriteMode(ctx, device, cfg)
	}
	// Read mode - continuously monitor for tags
	return runReadMode(ctx, device, cfg)
}

func main() {
	flag.Parse()
	os.Exit(mainWithExitCode())
}

func mainWithExitCode() int {
	// Parse command-line flags
	cfg := parseConfig()

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		_, _ = fmt.Print("\nShutting down gracefully...\n")
		cancel()
	}()

	// Run the main application logic
	if err := run(ctx, cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			// User requested shutdown, exit cleanly
			return 0
		}
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
