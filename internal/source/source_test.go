package source

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestSystemClockMonotonic(t *testing.T) {
	var c Clock = System{}
	now := c.Now()
	// Monotonic reading in Go time.Time string format contains " m=".
	// If .UTC(), .Round(0), or .Truncate() were called, the monotonic reading would be stripped.
	str := now.String()
	if !strings.Contains(str, " m=") {
		t.Fatalf("expected System.Now() to carry monotonic reading containing \" m=\", got %q", str)
	}
}

func TestRandomIDSource(t *testing.T) {
	var ids IDSource = Random{}
	reHex := regexp.MustCompile(`^[0-9a-f]{32}$`)

	id1, err := ids.NewID()
	if err != nil {
		t.Fatalf("Random.NewID() failed: %v", err)
	}
	if !reHex.MatchString(id1) {
		t.Fatalf("expected 32 lowercase hex characters, got %q", id1)
	}

	id2, err := ids.NewID()
	if err != nil {
		t.Fatalf("Random.NewID() second call failed: %v", err)
	}
	if !reHex.MatchString(id2) {
		t.Fatalf("expected 32 lowercase hex characters, got %q", id2)
	}

	if id1 == id2 {
		t.Fatalf("expected two calls to Random.NewID() to return different IDs, got %q == %q", id1, id2)
	}
}

type failingReader struct {
	err error
}

func (f failingReader) Read(p []byte) (n int, err error) {
	return 0, f.err
}

func TestRandomIDSourceWithFailingReader(t *testing.T) {
	injectedErr := errors.New("entropy source depleted")
	orig := randReader
	t.Cleanup(func() {
		randReader = orig
	})
	randReader = failingReader{err: injectedErr}

	id, err := Random{}.NewID()
	if err == nil {
		t.Fatalf("expected error from Random{}.NewID(), got id %q", id)
	}
	if !errors.Is(err, injectedErr) {
		t.Fatalf("expected injected error %v, got %v", injectedErr, err)
	}
	if id != "" {
		t.Fatalf("expected empty ID on error, got %q", id)
	}
}
