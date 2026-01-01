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
	"errors"
	"time"
)

// CardDetectionState represents the finite state machine for card detection
type CardDetectionState int

const (
	StateIdle CardDetectionState = iota
	StateTagDetected
	StateReading
	StatePostReadGrace
)

// CardState tracks the state of a card on a reader
type CardState struct {
	LastSeenTime   time.Time
	ReadStartTime  time.Time
	RemovalTimer   *time.Timer
	LastUID        string
	LastType       string
	TestedUID      string
	DetectionState CardDetectionState
	Present        bool
}

// ErrNoTagInPoll indicates no tag was detected during polling (not an error condition)
var ErrNoTagInPoll = errors.New("no tag detected in polling cycle")

// safeTimerStop safely stops a timer and drains its channel to prevent resource leaks
func safeTimerStop(timer *time.Timer) {
	if timer != nil {
		// Stop the timer first
		stopped := timer.Stop()
		// If Stop() returned false, the timer already fired and the value was sent to C
		// In that case, we need to drain the channel to prevent blocking
		if !stopped {
			select {
			case <-timer.C:
				// Timer fired, drained the channel
			default:
				// Timer was already drained or never fired
			}
		}
	}
}

// TransitionToReading moves to reading state and suspends removal timer
func (cs *CardState) TransitionToReading() {
	cs.DetectionState = StateReading
	cs.ReadStartTime = time.Now()
	safeTimerStop(cs.RemovalTimer)
	cs.RemovalTimer = nil
}

// TransitionToPostReadGrace moves to post-read grace period with short timeout
func (cs *CardState) TransitionToPostReadGrace(timeout time.Duration, callback func()) {
	cs.DetectionState = StatePostReadGrace
	safeTimerStop(cs.RemovalTimer)
	// Short grace period after read completion
	cs.RemovalTimer = time.AfterFunc(timeout/2, callback)
}

// TransitionToDetected moves to tag detected state with normal removal timeout
func (cs *CardState) TransitionToDetected(timeout time.Duration, callback func()) {
	cs.DetectionState = StateTagDetected
	cs.LastSeenTime = time.Now()
	safeTimerStop(cs.RemovalTimer)
	cs.RemovalTimer = time.AfterFunc(timeout, callback)
}

// TransitionToIdle resets to idle state
func (cs *CardState) TransitionToIdle() {
	cs.DetectionState = StateIdle
	cs.Present = false
	cs.LastUID = ""
	cs.LastType = ""
	cs.TestedUID = ""
	cs.LastSeenTime = time.Time{}
	cs.ReadStartTime = time.Time{}
	safeTimerStop(cs.RemovalTimer)
	cs.RemovalTimer = nil
}

// CanStartRemovalTimer returns true if the state allows removal timer to run
func (cs *CardState) CanStartRemovalTimer() bool {
	return cs.DetectionState == StateTagDetected || cs.DetectionState == StatePostReadGrace
}
