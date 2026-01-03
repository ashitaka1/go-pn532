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
	"testing"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultRecoverer(t *testing.T) {
	t.Parallel()

	device, _ := createMockDeviceWithTransport(t)

	t.Run("WithDefaults", func(t *testing.T) {
		t.Parallel()
		r := NewDefaultRecoverer(device, nil, 0, 0)
		assert.NotNil(t, r)
		assert.Equal(t, 3, r.maxAttempts)
		assert.Equal(t, 500*time.Millisecond, r.backoff)
	})

	t.Run("WithCustomValues", func(t *testing.T) {
		t.Parallel()
		r := NewDefaultRecoverer(device, nil, 100*time.Millisecond, 5)
		assert.Equal(t, 5, r.maxAttempts)
		assert.Equal(t, 100*time.Millisecond, r.backoff)
	})
}

func TestDefaultRecoverer_SoftResetSuccess(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// SAMConfiguration succeeds
	mockTransport.SetResponse(0x14, []byte{0x15})

	r := NewDefaultRecoverer(device, nil, 10*time.Millisecond, 3)

	err := r.AttemptRecovery(context.Background())
	require.NoError(t, err)
	assert.Equal(t, device, r.GetDevice())
}

func TestDefaultRecoverer_SoftResetFailsNoReopen(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// SAMConfiguration fails
	mockTransport.SetError(0x14, errors.New("soft reset failed"))

	r := NewDefaultRecoverer(device, nil, 10*time.Millisecond, 2)

	err := r.AttemptRecovery(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "soft reset failed")
}

func TestDefaultRecoverer_FullReconnectSuccess(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)
	newDevice, newMockTransport := createMockDeviceWithTransport(t)

	// SAMConfiguration fails on old device
	mockTransport.SetError(0x14, errors.New("soft reset failed"))

	// New device works
	newMockTransport.SetResponse(0x14, []byte{0x15})

	reopenCalled := false
	reopenFunc := func() (*pn532.Device, error) {
		reopenCalled = true
		return newDevice, nil
	}

	r := NewDefaultRecoverer(device, reopenFunc, 10*time.Millisecond, 3)

	err := r.AttemptRecovery(context.Background())
	require.NoError(t, err)
	assert.True(t, reopenCalled)
	assert.Equal(t, newDevice, r.GetDevice())
}

func TestDefaultRecoverer_AllAttemptsFail(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// SAMConfiguration fails
	mockTransport.SetError(0x14, errors.New("soft reset failed"))

	reopenErr := errors.New("reopen failed")
	reopenFunc := func() (*pn532.Device, error) {
		return nil, reopenErr
	}

	r := NewDefaultRecoverer(device, reopenFunc, 10*time.Millisecond, 2)

	err := r.AttemptRecovery(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reopen failed")
}

func TestDefaultRecoverer_ContextCancellation(t *testing.T) {
	t.Parallel()

	device, mockTransport := createMockDeviceWithTransport(t)

	// SAMConfiguration fails to force retry
	mockTransport.SetError(0x14, errors.New("soft reset failed"))

	r := NewDefaultRecoverer(device, nil, 100*time.Millisecond, 5)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := r.AttemptRecovery(ctx)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestDefaultRecoverer_GetDevice(t *testing.T) {
	t.Parallel()

	device, _ := createMockDeviceWithTransport(t)

	r := NewDefaultRecoverer(device, nil, 10*time.Millisecond, 3)

	assert.Equal(t, device, r.GetDevice())
}
