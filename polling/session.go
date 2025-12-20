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

package polling

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/ZaparooProject/go-pn532"
	"github.com/ZaparooProject/go-pn532/internal/syncutil"
)

// Session handles continuous card monitoring with state machine
type Session struct {
	OnMultiTagRemoved  func()
	config             *Config
	OnCardDetected     func(tag *pn532.DetectedTag) error
	OnCardRemoved      func()
	OnCardChanged      func(tag *pn532.DetectedTag) error
	pauseChan          chan struct{}
	resumeChan         chan struct{}
	ackChan            chan struct{}
	OnMultiTagChanged  func(tags []*pn532.DetectedTag) error
	actor              *DeviceActor
	device             *pn532.Device
	OnMultiTagDetected func(tags []*pn532.DetectedTag) error
	lastUIDs           []string
	state              CardState
	stateMutex         syncutil.RWMutex
	writeMutex         syncutil.Mutex
	closed             atomic.Bool
	isPaused           atomic.Bool
	multiTagMode       bool
	multiTagTested     bool
}

// NewSession creates a new card monitoring session
func NewSession(device *pn532.Device, config *Config) *Session {
	if config == nil {
		config = DefaultConfig()
	}
	return &Session{
		device:     device,
		config:     config,
		state:      CardState{},
		pauseChan:  make(chan struct{}, 1),
		resumeChan: make(chan struct{}, 1),
		ackChan:    make(chan struct{}, 1),
	}
}

// NewActorBasedSession creates a session using DeviceActor underneath
func NewActorBasedSession(device *pn532.Device, config *Config) *Session {
	session := NewSession(device, config)

	// Create DeviceActor with callbacks that delegate to session callbacks
	callbacks := DeviceCallbacks{
		OnCardDetected: func(tag *pn532.DetectedTag) error {
			session.stateMutex.RLock()
			cb := session.OnCardDetected
			session.stateMutex.RUnlock()
			if cb != nil {
				return cb(tag)
			}
			return nil
		},
		OnCardRemoved: func() {
			session.stateMutex.RLock()
			cb := session.OnCardRemoved
			session.stateMutex.RUnlock()
			if cb != nil {
				cb()
			}
		},
		OnCardChanged: func(tag *pn532.DetectedTag) error {
			session.stateMutex.RLock()
			cb := session.OnCardChanged
			session.stateMutex.RUnlock()
			if cb != nil {
				return cb(tag)
			}
			return nil
		},
	}

	session.actor = NewDeviceActor(device, config, callbacks)
	return session
}

// Start begins continuous monitoring for cards
func (s *Session) Start(ctx context.Context) error {
	// If we have an actor, delegate to it instead of using direct polling
	if s.actor != nil {
		return s.actor.Start(ctx)
	}
	// Fall back to direct polling for regular sessions
	return s.continuousPolling(ctx)
}

// StartMultiTag begins continuous monitoring for up to 2 cards simultaneously.
// Uses OnMultiTagDetected/OnMultiTagRemoved/OnMultiTagChanged callbacks instead
// of the single-tag callbacks.
func (s *Session) StartMultiTag(ctx context.Context) error {
	s.stateMutex.Lock()
	s.multiTagMode = true
	s.lastUIDs = nil
	s.multiTagTested = false
	s.stateMutex.Unlock()

	return s.continuousPollingMultiTag(ctx)
}

// GetState returns the current card state
func (s *Session) GetState() CardState {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.state
}

// GetDevice returns the underlying PN532 device
func (s *Session) GetDevice() *pn532.Device {
	return s.device
}

// GetDeviceActor returns the underlying DeviceActor for actor-based sessions
func (s *Session) GetDeviceActor() *DeviceActor {
	return s.actor
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

// SetOnMultiTagDetected sets the callback for when tags are first detected in multi-tag mode.
func (s *Session) SetOnMultiTagDetected(callback func([]*pn532.DetectedTag) error) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnMultiTagDetected = callback
}

// SetOnMultiTagRemoved sets the callback for when all tags are removed in multi-tag mode.
func (s *Session) SetOnMultiTagRemoved(callback func()) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnMultiTagRemoved = callback
}

// SetOnMultiTagChanged sets the callback for when the set of tags changes in multi-tag mode.
func (s *Session) SetOnMultiTagChanged(callback func([]*pn532.DetectedTag) error) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.OnMultiTagChanged = callback
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

	// If we have an actor, stop it first to stop the polling goroutine
	if s.actor != nil {
		ctx := context.Background() // Use background context for cleanup
		if err := s.actor.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop device actor: %w", err)
		}
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
		ackTimeout := time.NewTimer(100 * time.Millisecond)
		defer ackTimeout.Stop()

		select {
		case <-s.ackChan:
			// Polling goroutine has acknowledged the pause
			return nil
		case <-ackTimeout.C:
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
	tag, tagErr := s.device.CreateTag(detectedTag)
	if tagErr != nil {
		return fmt.Errorf("failed to create tag: %w", tagErr)
	}
	writeErr := writeFn(writeCtx, tag)
	if writeErr != nil {
		_ = s.device.ClearTransportState()
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
	detectedTag, err := s.performSinglePoll(ctx)
	if err != nil {
		if !errors.Is(err, ErrNoTagInPoll) {
			s.handlePollingError(err)
		}
		return nil
	}

	if err := s.processPollingResults(detectedTag); err != nil {
		return fmt.Errorf("callback error during polling: %w", err)
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
	tags, err := s.device.InListPassiveTarget(ctx, 1, 0x00)
	if err != nil {
		return nil, fmt.Errorf("tag detection failed: %w", err)
	}

	// Check if any tags were found
	if len(tags) == 0 {
		return nil, ErrNoTagInPoll // No tag detected, but not an error
	}

	return tags[0], nil
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

// processPollingResults processes the detected tag and returns any callback errors
func (s *Session) processPollingResults(detectedTag *pn532.DetectedTag) error {
	if detectedTag == nil {
		// No tag detected - removal handled by timer, nothing to do here
		return nil
	}

	// Stop any existing removal timer and transition to reading state BEFORE
	// calling callbacks. This prevents the old timer from firing during callback
	// execution (e.g., during NDEF reading which can take significant time).
	s.stateMutex.Lock()
	s.state.TransitionToReading()
	s.stateMutex.Unlock()

	// Card present - handle state transitions (calls OnCardDetected/OnCardChanged)
	cardChanged, err := s.updateCardState(detectedTag)
	if err != nil {
		return err
	}

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

// ============================================================================
// Multi-Tag Polling Support
// ============================================================================

// continuousPollingMultiTag runs continuous polling for up to 2 tags
func (s *Session) continuousPollingMultiTag(ctx context.Context) error {
	return s.runPollingLoop(ctx, s.executeMultiTagPollingCycle)
}

// executeMultiTagPollingCycle performs one multi-tag polling cycle
func (s *Session) executeMultiTagPollingCycle(ctx context.Context) error {
	tags, err := s.performMultiTagPoll(ctx)
	if err != nil {
		if !errors.Is(err, ErrNoTagInPoll) {
			s.handleMultiTagPollingError(err)
		} else {
			// No tags detected - check if we need to trigger removal
			s.checkMultiTagRemoval()
		}
		return nil
	}

	if err := s.processMultiTagResults(tags); err != nil {
		return fmt.Errorf("callback error during multi-tag polling: %w", err)
	}
	return nil
}

// performMultiTagPoll polls for up to 2 tags
func (s *Session) performMultiTagPoll(ctx context.Context) ([]*pn532.DetectedTag, error) {
	tags, err := s.device.InListPassiveTarget(ctx, 2, 0x00)
	if err != nil {
		return nil, fmt.Errorf("tag detection failed: %w", err)
	}

	if len(tags) == 0 {
		return nil, ErrNoTagInPoll
	}

	return tags, nil
}

// processMultiTagResults processes detected tags and triggers appropriate callbacks
func (s *Session) processMultiTagResults(tags []*pn532.DetectedTag) error {
	// Extract and sort UIDs for comparison
	currentUIDs := extractSortedUIDs(tags)

	// Stop any existing removal timer and transition to reading state BEFORE
	// calling callbacks. This prevents the old timer from firing during callback
	// execution (e.g., during NDEF reading which can take significant time).
	s.stateMutex.Lock()
	s.state.TransitionToReading()
	s.stateMutex.Unlock()

	// Capture state and callbacks under lock
	s.stateMutex.RLock()
	previousUIDs := s.lastUIDs
	wasPresent := len(previousUIDs) > 0
	uidsChanged := !slices.Equal(previousUIDs, currentUIDs)
	onDetected := s.OnMultiTagDetected
	onChanged := s.OnMultiTagChanged
	tested := s.multiTagTested
	s.stateMutex.RUnlock()

	// Determine which callback to call (callbacks run with timer stopped)
	if !wasPresent && onDetected != nil {
		// First detection
		if err := s.safeCallMultiTagCallback(onDetected, tags, "OnMultiTagDetected"); err != nil {
			return err
		}
	} else if wasPresent && uidsChanged && onChanged != nil {
		// Tag set changed
		if err := s.safeCallMultiTagCallback(onChanged, tags, "OnMultiTagChanged"); err != nil {
			return err
		}
	}

	// After callbacks complete, update state and set up appropriate timer
	s.stateMutex.Lock()
	s.lastUIDs = currentUIDs
	s.state.Present = true

	// Mark as tested if this is a new tag set
	if !wasPresent || uidsChanged || !tested {
		s.multiTagTested = true
		s.state.TransitionToPostReadGrace(s.config.CardRemovalTimeout, func() {
			s.handleMultiTagRemoval()
		})
	} else {
		// Tags unchanged and already tested - just reset the removal timer
		s.state.TransitionToDetected(s.config.CardRemovalTimeout, func() {
			s.handleMultiTagRemoval()
		})
	}
	s.stateMutex.Unlock()

	return nil
}

// checkMultiTagRemoval checks if tags were removed and triggers removal if needed
func (*Session) checkMultiTagRemoval() {
	// This is called when no tags are detected - the removal timer handles the actual removal
	// Nothing to do here, just let the timer fire
}

// handleMultiTagPollingError handles errors from multi-tag polling
func (s *Session) handleMultiTagPollingError(err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	// For serious device errors, trigger immediate removal
	s.handleMultiTagRemoval()
}

// handleMultiTagRemoval handles removal of all tags in multi-tag mode
func (s *Session) handleMultiTagRemoval() {
	if s.closed.Load() {
		return
	}

	s.stateMutex.Lock()
	// If we're in reading state, a new poll cycle is actively processing - ignore stale timer
	if s.state.DetectionState == StateReading {
		s.stateMutex.Unlock()
		return
	}
	wasPresent := len(s.lastUIDs) > 0
	if wasPresent {
		s.lastUIDs = nil
		s.multiTagTested = false
		s.state.TransitionToIdle()
	}
	onRemoved := s.OnMultiTagRemoved
	s.stateMutex.Unlock()

	if wasPresent && onRemoved != nil {
		onRemoved()
	}
}

// safeCallMultiTagCallback executes a multi-tag callback with panic recovery
func (*Session) safeCallMultiTagCallback(
	callback func([]*pn532.DetectedTag) error,
	tags []*pn532.DetectedTag,
	callbackName string,
) error {
	var callbackErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				callbackErr = fmt.Errorf("%s callback panicked: %v", callbackName, r)
			}
		}()
		callbackErr = callback(tags)
	}()
	if callbackErr != nil {
		return fmt.Errorf("%s callback failed: %w", callbackName, callbackErr)
	}
	return nil
}

// extractSortedUIDs extracts UIDs from tags and returns them sorted
func extractSortedUIDs(tags []*pn532.DetectedTag) []string {
	uids := make([]string, len(tags))
	for i, tag := range tags {
		uids[i] = tag.UID
	}
	slices.Sort(uids)
	return uids
}
