//go:build deadlock

// Package syncutil provides mutex types that can optionally use deadlock detection.
// This file is compiled when building with -tags=deadlock.
package syncutil

import deadlock "github.com/sasha-s/go-deadlock"

// Mutex wraps deadlock.Mutex for deadlock detection.
type Mutex struct {
	deadlock.Mutex
}

// RWMutex wraps deadlock.RWMutex for deadlock detection.
type RWMutex struct {
	deadlock.RWMutex
}
