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

package polling

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ZaparooProject/go-pn532"
	"github.com/ZaparooProject/go-pn532/internal/syncutil"
)

// Session handles continuous card monitoring with state machine
type Session struct {
	lastPollTime         time.Time
	recoverer            DeviceRecoverer
	device               *pn532.Device
	OnSleepDetected      func()
	OnDeviceDisconnected func(err error)
	pauseChan            chan struct{}
	resumeChan           chan struct{}
	ackChan              chan struct{}
	config               *Config
	OnCardChanged        func(tag *pn532.DetectedTag) error
	OnCardDetected       func(tag *pn532.DetectedTag) error
	OnCardRemoved        func()
	state                CardState
	stateMutex           syncutil.RWMutex
	writeMutex           syncutil.Mutex
	closed               atomic.Bool
	isPaused             atomic.Bool
}

// NewSession creates a new card monitoring session.
// If sleep recovery is enabled in config, a DefaultRecoverer is automatically
// created for soft reset recovery. Use SetRecoverer to provide a custom
// recoverer with full reconnection capability via ReopenFunc.
func NewSession(device *pn532.Device, config *Config) *Session {
	if config == nil {
		config = DefaultConfig()
	}

	session := &Session{
		device:     device,
		config:     config,
		state:      CardState{},
		pauseChan:  make(chan struct{}, 1),
		resumeChan: make(chan struct{}, 1),
		ackChan:    make(chan struct{}, 1),
	}

	// Auto-create recoverer when sleep recovery is enabled
	if config.SleepRecovery.Enabled {
		session.recoverer = NewDefaultRecoverer(
			device,
			nil, // No reopen func by default, only soft reset
			config.SleepRecovery.RecoveryBackoff,
			config.SleepRecovery.MaxRecoveryAttempts,
		)
	}

	return session
}

// Start begins continuous monitoring for cards
func (s *Session) Start(ctx context.Context) error {
	return s.continuousPolling(ctx)
}

// GetState returns the current card state
func (s *Session) GetState() CardState {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.state
}

// GetDevice returns the underlying PN532 device.
// This may return a different device after sleep/wake recovery.
func (s *Session) GetDevice() *pn532.Device {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.device
}

// SetOnCardDetected sets the callback for when a card is detected.
func (s *Session) SetOnCardDetected(callback func(*pn532.DetectedTag) error) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnCardDetected = callback
}

// SetOnCardRemoved sets the callback for when a card is removed.
func (s *Session) SetOnCardRemoved(callback func()) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnCardRemoved = callback
}

// SetOnCardChanged sets the callback for when the card changes.
func (s *Session) SetOnCardChanged(callback func(*pn532.DetectedTag) error) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnCardChanged = callback
}

// SetOnSleepDetected sets the callback for when system sleep/wake is detected.
func (s *Session) SetOnSleepDetected(callback func()) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnSleepDetected = callback
}

// SetOnDeviceDisconnected sets the callback for when the device is disconnected.
// This is called when a fatal error indicates the device is no longer available
// (e.g., USB unplugged). The error parameter contains the underlying cause.
func (s *Session) SetOnDeviceDisconnected(callback func(err error)) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnDeviceDisconnected = callback
}

// SetRecoverer configures a custom device recoverer for sleep/wake handling.
// Use this to provide a recoverer with ReopenFunc for full reconnection
// capability beyond the default soft reset behavior.
func (s *Session) SetRecoverer(r DeviceRecoverer) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.recoverer = r
}

// Close cleans up the monitor resources
func (s *Session) Close() error {
	// Mark session as closed to prevent timer callbacks from executing
	s.closed.Store(true)

	// Stop any running removal timer
	s.stateMutex.Lock()
	if s.state.RemovalTimer != nil {
		safeTimerStop(s.state.RemovalTimer)
		s.state.RemovalTimer = nil
	}
	s.stateMutex.Unlock()

	// Reset pause state and drain channels to prevent corruption
	s.isPaused.Store(false)

	// Drain pause/resume channels to prevent future state corruption
	select {
	case <-s.pauseChan:
	default:
	}
	select {
	case <-s.resumeChan:
	default:
	}

	return nil
}

// Pause temporarily stops the polling loop
// This is used to coordinate with write operations
func (s *Session) Pause() {
	if s.isPaused.CompareAndSwap(false, true) {
		// Signal pause to the polling loop - use non-blocking send for when no loop is running
		select {
		case s.pauseChan <- struct{}{}:
			// Successfully sent pause signal
		default:
			// Channel full or no receiver - that's OK, isPaused flag is set
		}
	}
}

// Resume restarts the polling loop after a pause
func (s *Session) Resume() {
	if s.isPaused.CompareAndSwap(true, false) {
		// Signal resume to the polling loop - use non-blocking send for when no loop is running
		select {
		case s.resumeChan <- struct{}{}:
			// Successfully sent resume signal
		default:
			// Channel full or no receiver - that's OK, isPaused flag is cleared
		}
	}
}

// pauseWithAck pauses polling and waits for acknowledgment
func (s *Session) pauseWithAck(ctx context.Context) error {
	// Check if context is already cancelled
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check if already paused to avoid redundant operations
	if s.isPaused.Load() {
		return nil
	}

	// Use atomic operation to set pause state safely
	if !s.isPaused.CompareAndSwap(false, true) {
		return nil // Another goroutine beat us to it
	}

	// Send pause signal with context-aware non-blocking send
	select {
	case s.pauseChan <- struct{}{}:
		// Successfully sent pause signal, now wait for acknowledgment with timeout
		select {
		case <-s.ackChan:
			// Polling goroutine has acknowledged the pause
			return nil
		case <-time.After(100 * time.Millisecond):
			// No acknowledgment received - likely no polling loop running
			// This is OK for testing scenarios, pause state is already set
			return nil
		case <-ctx.Done():
			// Context cancelled, restore pause state and return error
			s.isPaused.Store(false)
			return ctx.Err()
		}
	case <-ctx.Done():
		// Context cancelled, restore pause state and return error
		s.isPaused.Store(false)
		return ctx.Err()
	default:
		// Channel full or no receiver - that's OK since isPaused flag is set
		return nil
	}
}

// executeWriteToTag creates a tag from detected tag and executes the write function.
// Clears transport state on write error for recovery.
func (s *Session) executeWriteToTag(
	writeCtx context.Context,
	detectedTag *pn532.DetectedTag,
	writeFn func(context.Context, pn532.Tag) error,
) error {
	// Use GetDevice() to get the current device reference (may be updated after recovery)
	device := s.GetDevice()
	if device == nil {
		return errors.New("device not available")
	}
	tag, tagErr := device.CreateTag(detectedTag)
	if tagErr != nil {
		return fmt.Errorf("failed to create tag: %w", tagErr)
	}
	writeErr := writeFn(writeCtx, tag)
	if writeErr != nil {
		_ = device.ClearTransportState()
	}
	return writeErr
}

// WriteToNextTag waits for the next tag detection and performs a write operation
// This method blocks until a tag is detected or timeout occurs
// sessionCtx controls session lifetime, writeCtx controls write operation lifetime
func (s *Session) WriteToNextTag(
	sessionCtx context.Context,
	writeCtx context.Context,
	timeout time.Duration,
	writeFn func(context.Context, pn532.Tag) error,
) error {
	// Acquire write mutex to prevent concurrent writes
	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()

	// Pause polling to prevent interference with our write operation
	if err := s.pauseWithAck(sessionCtx); err != nil {
		return fmt.Errorf("failed to pause polling: %w", err)
	}
	defer s.Resume()

	// Create a timeout context that cancels if either session or timeout expires
	timeoutCtx, cancel := context.WithTimeout(sessionCtx, timeout)
	defer cancel()

	// Poll continuously until we find a tag or timeout
	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()

	for {
		// Attempt to detect a tag
		detectedTag, err := s.performSinglePoll(timeoutCtx)
		if err == nil {
			return s.executeWriteToTag(writeCtx, detectedTag, writeFn)
		}

		if !errors.Is(err, ErrNoTagInPoll) {
			return fmt.Errorf("tag detection failed: %w", err)
		}

		// Wait for next poll interval or timeout
		select {
		case <-ticker.C:
			continue
		case <-timeoutCtx.Done():
			if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
				return errors.New("timeout waiting for tag")
			}
			return timeoutCtx.Err()
		}
	}
}

// WriteToTag performs a thread-safe write operation to a detected tag
// This method pauses polling during the write to prevent interference
// sessionCtx controls session lifetime, writeCtx controls write operation lifetime
func (s *Session) WriteToTag(
	sessionCtx context.Context,
	writeCtx context.Context,
	detectedTag *pn532.DetectedTag,
	writeFn func(context.Context, pn532.Tag) error,
) error {
	// Acquire write mutex to prevent concurrent writes
	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()

	// Enhanced pause with acknowledgment - now requires context
	if err := s.pauseWithAck(sessionCtx); err != nil {
		return fmt.Errorf("failed to pause polling: %w", err)
	}
	defer s.Resume()

	return s.executeWriteToTag(writeCtx, detectedTag, writeFn)
}

// WriteToNextTagWithRetry waits for the next tag detection and performs a write operation
// with automatic retry on transient errors. This is useful for handling intermittent
// write failures due to card placement issues or timing problems.
// sessionCtx controls session lifetime, writeCtx controls write operation lifetime.
// maxRetries specifies how many times to retry the write operation (default 3 if <= 0).
func (s *Session) WriteToNextTagWithRetry(
	sessionCtx context.Context,
	writeCtx context.Context,
	timeout time.Duration,
	maxRetries int,
	writeFn func(context.Context, pn532.Tag) error,
) error {
	// Wrap the write function with retry logic
	wrappedFn := func(ctx context.Context, tag pn532.Tag) error {
		return pn532.WriteNDEFWithRetry(ctx, func(innerCtx context.Context) error {
			return writeFn(innerCtx, tag)
		}, maxRetries, string(tag.Type()))
	}

	return s.WriteToNextTag(sessionCtx, writeCtx, timeout, wrappedFn)
}

// WriteToTagWithRetry performs a thread-safe write operation to a detected tag
// with automatic retry on transient errors. This is useful for handling intermittent
// write failures due to card placement issues or timing problems.
// sessionCtx controls session lifetime, writeCtx controls write operation lifetime.
// maxRetries specifies how many times to retry the write operation (default 3 if <= 0).
func (s *Session) WriteToTagWithRetry(
	sessionCtx context.Context,
	writeCtx context.Context,
	detectedTag *pn532.DetectedTag,
	maxRetries int,
	writeFn func(context.Context, pn532.Tag) error,
) error {
	// Wrap the write function with retry logic
	wrappedFn := func(ctx context.Context, tag pn532.Tag) error {
		return pn532.WriteNDEFWithRetry(ctx, func(innerCtx context.Context) error {
			return writeFn(innerCtx, tag)
		}, maxRetries, string(tag.Type()))
	}

	return s.WriteToTag(sessionCtx, writeCtx, detectedTag, wrappedFn)
}

// continuousPolling runs continuous InAutoPoll monitoring
func (s *Session) continuousPolling(ctx context.Context) error {
	return s.runPollingLoop(ctx, s.executeSinglePollingCycle)
}

// runPollingLoop is the generic polling loop used by both single and multi-tag modes
func (s *Session) runPollingLoop(ctx context.Context, cycleFunc func(context.Context) error) error {
	// Configure PN532 hardware polling retries to reduce host-side polling frequency
	// This tells the PN532 to retry detection internally before returning to the host
	if err := s.device.SetPollingRetries(s.config.HardwareTimeoutRetries); err != nil {
		return fmt.Errorf("failed to configure hardware polling retries: %w", err)
	}

	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()

	for {
		if err := s.handleContextAndPause(ctx); err != nil {
			return err
		}

		if err := cycleFunc(ctx); err != nil {
			return err
		}

		if err := s.waitForNextPollOrPause(ctx, ticker); err != nil {
			return err
		}
	}
}

// executeSinglePollingCycle performs one polling cycle and processes results
func (s *Session) executeSinglePollingCycle(ctx context.Context) error {
	// Check for time discontinuity (sleep detection)
	if err := s.checkSleepAndRecover(ctx); err != nil {
		return err // Recovery failed - exit polling loop
	}

	detectedTag, err := s.performSinglePoll(ctx)
	if err != nil {
		if !errors.Is(err, ErrNoTagInPoll) {
			s.handlePollingError(err)
			if pn532.IsFatal(err) {
				return err // Fatal error - exit polling loop
			}
		}
		return nil // Transient error or no tag - continue polling
	}

	if err := s.processPollingResults(detectedTag); err != nil {
		return fmt.Errorf("callback error during polling: %w", err)
	}
	return nil
}

// checkSleepAndRecover detects time discontinuity (system sleep) and attempts recovery
func (s *Session) checkSleepAndRecover(ctx context.Context) error {
	cfg := s.config.SleepRecovery
	if !cfg.Enabled {
		s.lastPollTime = time.Now()
		return nil
	}

	if err := s.handleTimeDiscontinuity(ctx, cfg); err != nil {
		return err
	}

	s.lastPollTime = time.Now()
	return nil
}

// handleTimeDiscontinuity checks for and handles time discontinuity (sleep detection)
func (s *Session) handleTimeDiscontinuity(ctx context.Context, cfg SleepRecoveryConfig) error {
	if s.lastPollTime.IsZero() {
		return nil
	}

	elapsed := time.Since(s.lastPollTime)
	if !cfg.DetectSleep(elapsed, s.config.PollInterval) {
		return nil
	}

	// Sleep detected - call callback and attempt recovery
	s.stateMutex.RLock()
	onSleep := s.OnSleepDetected
	recoverer := s.recoverer
	s.stateMutex.RUnlock()

	if onSleep != nil {
		onSleep()
	}

	return s.attemptSleepRecovery(ctx, recoverer)
}

// attemptSleepRecovery attempts to recover the device after sleep
func (s *Session) attemptSleepRecovery(ctx context.Context, recoverer DeviceRecoverer) error {
	if recoverer == nil {
		return nil
	}

	if err := recoverer.AttemptRecovery(ctx); err != nil {
		return fmt.Errorf("sleep recovery failed: %w", err)
	}

	// Update device reference if it changed during recovery
	if newDevice := recoverer.GetDevice(); newDevice != nil {
		s.stateMutex.Lock()
		if newDevice != s.device {
			s.device = newDevice
		}
		s.stateMutex.Unlock()
	}
	return nil
}

// waitForNextPollOrPause waits for the next poll interval or handles pause signals
func (s *Session) waitForNextPollOrPause(ctx context.Context, ticker *time.Ticker) error {
	select {
	case <-ticker.C:
		return nil
	case <-s.pauseChan:
		return s.handlePauseSignal(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handlePauseSignal sends acknowledgment and waits for resume
func (s *Session) handlePauseSignal(ctx context.Context) error {
	// Send acknowledgment to indicate polling is paused
	select {
	case s.ackChan <- struct{}{}:
		// Successfully sent acknowledgment
	default:
		// Channel full or no receiver - continue anyway
	}
	// Wait for resume
	return s.waitForResume(ctx)
}

func (s *Session) handleContextAndPause(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.pauseChan:
		return s.waitForResume(ctx)
	default:
		return nil
	}
}

func (s *Session) waitForResume(ctx context.Context) error {
	select {
	case <-s.resumeChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// performSinglePoll performs a single tag detection cycle using direct InListPassiveTarget
func (s *Session) performSinglePoll(ctx context.Context) (*pn532.DetectedTag, error) {
	// Use standard InListPassiveTarget with PN532 hardware handling retries
	// The hardware retry count was configured via SetPollingRetries() during session start
	tag, err := s.device.InListPassiveTarget(ctx, 0x00)
	if err != nil {
		return nil, fmt.Errorf("tag detection failed: %w", err)
	}

	// Check if a tag was found
	if tag == nil {
		return nil, ErrNoTagInPoll // No tag detected, but not an error
	}

	return tag, nil
}

// handlePollingError handles errors from polling operations
func (s *Session) handlePollingError(err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		// Timeout is normal - timer will handle removal detection
		return
	}

	if errors.Is(err, context.Canceled) {
		return
	}

	// For serious device errors, trigger immediate card removal
	// This handles cases like device disconnection
	s.handleCardRemoval()

	// If this is a fatal error (device disconnected), notify via callback
	if pn532.IsFatal(err) {
		s.stateMutex.RLock()
		onDisconnected := s.OnDeviceDisconnected
		s.stateMutex.RUnlock()

		if onDisconnected != nil {
			onDisconnected(err)
		}
	}
}

// handleCardRemoval handles card removal state changes
func (s *Session) handleCardRemoval() {
	// Bail out if session is closed to prevent timer callbacks from executing after cleanup
	if s.closed.Load() {
		return
	}

	s.stateMutex.Lock()
	// If we're in reading state, a new poll cycle is actively processing - ignore stale timer
	// This handles the edge case where timer.Stop() returned false (callback already spawned)
	// but the callback runs after TransitionToReading() released the lock
	if s.state.DetectionState == StateReading {
		s.stateMutex.Unlock()
		return
	}
	wasPresent := s.state.Present
	if wasPresent {
		s.state.TransitionToIdle()
	}
	onRemoved := s.OnCardRemoved
	s.stateMutex.Unlock()

	// Call callback outside the lock to avoid potential deadlocks
	if wasPresent && onRemoved != nil {
		onRemoved()
	}
}

// maxStableFailuresBeforeError is how many times a callback can fail with stable RF
// before we consider it a "real" error worth reporting. This prevents error spam
// during card slide-in when RF is marginal.
const maxStableFailuresBeforeError = 3

// processPollingResults processes the detected tag and returns any callback errors.
func (s *Session) processPollingResults(detectedTag *pn532.DetectedTag) error {
	if detectedTag == nil {
		// No tag detected - removal handled by timer, nothing to do here
		return nil
	}

	// LAYER 1: Verify RF stability before processing
	// This catches marginal RF connections (e.g., card sliding in from the side)
	// before we run callbacks that might fail and leave the card in a stuck state.
	if !s.verifyTagStable() {
		// RF unstable - skip this cycle silently, reset failure counter
		// The card will be re-detected on the next poll if still present
		s.stateMutex.Lock()
		s.state.ConsecutiveStableFailures = 0
		s.stateMutex.Unlock()
		return nil // Silent skip - not a real failure
	}

	// RF is stable - proceed with callback processing
	// Stop any existing removal timer and transition to reading state BEFORE
	// calling callbacks. This prevents the old timer from firing during callback
	// execution (e.g., during NDEF reading which can take significant time).
	s.stateMutex.Lock()
	s.state.TransitionToReading()
	s.stateMutex.Unlock()

	// Card present - handle state transitions (calls OnCardDetected/OnCardChanged)
	cardChanged, err := s.updateCardState(detectedTag)
	// LAYER 2: Handle callback failure without killing polling loop
	// If callback fails, don't mark as tested and allow retry on next poll
	if err != nil {
		s.stateMutex.Lock()
		s.state.ConsecutiveStableFailures++
		failures := s.state.ConsecutiveStableFailures
		s.stateMutex.Unlock()

		// LAYER 3: Only report error after multiple stable failures
		// This prevents error spam when RF just stabilized but reads still fail
		if failures >= maxStableFailuresBeforeError {
			// This is a "real" error - RF is stable but callback keeps failing
			return fmt.Errorf("callback failed %d times with stable RF: %w", failures, err)
		}

		// Not enough failures yet - skip silently, will retry next poll
		pn532.Debugf("Callback failed (attempt %d/%d, will retry): %v",
			failures, maxStableFailuresBeforeError, err)
		return nil // Don't exit polling, don't set TestedUID
	}

	// Callback succeeded - reset failure counter
	s.stateMutex.Lock()
	s.state.ConsecutiveStableFailures = 0
	s.stateMutex.Unlock()

	// After callback completes, set up the appropriate timer for this card
	if cardChanged || s.shouldTestCard(detectedTag.UID) {
		s.testAndRecordCard(detectedTag)
	} else {
		// Card unchanged and already tested - just reset the removal timer
		s.stateMutex.Lock()
		s.state.TransitionToDetected(s.config.CardRemovalTimeout, func() {
			s.handleCardRemoval()
		})
		s.stateMutex.Unlock()
	}

	return nil
}

// verifyTagStable confirms the detected tag has stable RF contact by attempting
// an InSelect command. This catches marginal RF connections before we run
// callbacks that might fail and leave the card in a "stuck" state.
//
// Returns true if tag responds to InSelect, false if RF appears unstable.
func (s *Session) verifyTagStable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// InSelect verifies the target is still valid and responsive
	// If RF is marginal (e.g., card sliding in), this will fail
	err := s.device.InSelect(ctx)
	if err != nil {
		pn532.Debugf("RF unstable (InSelect failed): %v", err)
		return false
	}
	return true
}

// safeCallCallback executes a callback with panic recovery
func (*Session) safeCallCallback(
	callback func(*pn532.DetectedTag) error,
	tag *pn532.DetectedTag,
	callbackName string,
) error {
	var callbackErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				callbackErr = fmt.Errorf("%s callback panicked: %v", callbackName, r)
			}
		}()
		callbackErr = callback(tag)
	}()
	if callbackErr != nil {
		return fmt.Errorf("%s callback failed: %w", callbackName, callbackErr)
	}
	return nil
}

// updateCardState updates the card state and returns whether the card changed and any callback error
func (s *Session) updateCardState(detectedTag *pn532.DetectedTag) (bool, error) {
	currentUID := detectedTag.UID
	cardType := string(detectedTag.Type)

	// Capture state and callbacks under lock to avoid races
	s.stateMutex.RLock()
	wasPresent := s.state.Present
	wasChanged := wasPresent && s.state.LastUID != currentUID
	onDetected := s.OnCardDetected
	onChanged := s.OnCardChanged
	s.stateMutex.RUnlock()

	// Call callbacks outside of lock with panic recovery
	if !wasPresent && onDetected != nil {
		if err := s.safeCallCallback(onDetected, detectedTag, "OnCardDetected"); err != nil {
			return false, err
		}
	} else if wasChanged && onChanged != nil {
		if err := s.safeCallCallback(onChanged, detectedTag, "OnCardChanged"); err != nil {
			return false, err
		}
	}

	// Update state under lock
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()

	if !wasPresent {
		s.state.Present = true
		s.state.LastUID = currentUID
		s.state.LastType = cardType
		s.state.TestedUID = ""
		return true, nil
	}

	if wasChanged {
		s.state.LastUID = currentUID
		s.state.LastType = cardType
		s.state.TestedUID = ""
		return true, nil
	}

	return false, nil
}

// shouldTestCard determines if we should test the card
func (s *Session) shouldTestCard(currentUID string) bool {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.state.TestedUID != currentUID
}

// testAndRecordCard tests the card and records the result
func (s *Session) testAndRecordCard(detectedTag *pn532.DetectedTag) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()

	// Transition to reading state to prevent removal timer from firing during long reads
	s.state.TransitionToReading()

	// Mark as tested to prevent repeated testing
	s.state.TestedUID = detectedTag.UID

	// Transition to post-read grace period with shorter timeout
	s.state.TransitionToPostReadGrace(s.config.CardRemovalTimeout, func() {
		s.handleCardRemoval()
	})
}
