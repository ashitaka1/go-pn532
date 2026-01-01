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

package detection

import (
	"time"

	"github.com/ZaparooProject/go-pn532/internal/syncutil"
)

// cacheEntry holds cached detection results.
type cacheEntry struct {
	timestamp time.Time
	devices   []DeviceInfo
}

// detectionCache provides thread-safe caching of detection results.
type detectionCache struct {
	entries map[string]cacheEntry
	mu      syncutil.RWMutex
}

// global cache instance.
var cache = &detectionCache{
	entries: make(map[string]cacheEntry),
}

// getCached returns cached devices if available and not expired
func getCached(transport string, ttl time.Duration) ([]DeviceInfo, bool) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	entry, exists := cache.entries[transport]
	if !exists {
		return nil, false
	}

	if time.Since(entry.timestamp) > ttl {
		return nil, false
	}

	// Return a copy to prevent modification
	devices := make([]DeviceInfo, len(entry.devices))
	copy(devices, entry.devices)
	return devices, true
}

// setCached stores detection results in cache
func setCached(transport string, devices []DeviceInfo) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Store a copy to prevent external modification
	devicesCopy := make([]DeviceInfo, len(devices))
	copy(devicesCopy, devices)

	cache.entries[transport] = cacheEntry{
		devices:   devicesCopy,
		timestamp: time.Now(),
	}
}

// clearCache removes all cached entries
func clearCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.entries = make(map[string]cacheEntry)
}

// clearCacheForTransport removes cached entries for a specific transport
func clearCacheForTransport(transport string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	delete(cache.entries, transport)
}
