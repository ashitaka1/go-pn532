//go:build !deadlock

// Package syncutil provides mutex types that can optionally use deadlock detection.
// By default, standard sync.Mutex and sync.RWMutex are used with zero overhead.
// Build with -tags=deadlock to enable deadlock detection via github.com/sasha-s/go-deadlock.
package syncutil

import "sync"

// Mutex wraps sync.Mutex. Build with -tags=deadlock for deadlock detection.
//
//nolint:gocritic // Intentionally embedding sync.Mutex to expose its interface
type Mutex struct {
	sync.Mutex
}

// RWMutex wraps sync.RWMutex. Build with -tags=deadlock for deadlock detection.
//
//nolint:gocritic // Intentionally embedding sync.RWMutex to expose its interface
type RWMutex struct {
	sync.RWMutex
}
