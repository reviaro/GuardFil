package main

import (
	"io"
	"sync"
)

// lockedWriter serializes whole lines from the client copier and the
// proxy's replies to server requests onto the server's stdin.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}
