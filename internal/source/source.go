// Package source provides runtime clock and identifier abstractions.
package source

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"
)

// Clock provides the current time.
type Clock interface {
	Now() time.Time
}

// System implements Clock using the system clock, preserving monotonic readings.
type System struct{}

// Now returns time.Now() unmodified (preserving monotonic clock reading).
func (System) Now() time.Time {
	return time.Now()
}

// IDSource generates unique identifiers.
type IDSource interface {
	NewID() (string, error)
}

var randReader io.Reader = rand.Reader

// Random implements IDSource returning 16 crypto/rand bytes hex-encoded.
type Random struct{}

// NewID returns a 32-character lowercase hex string from 16 crypto/rand bytes.
// A rand failure returns an error, never a fallback ID.
func (Random) NewID() (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(randReader, buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
