//go:build linux

package approval

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestHalfClosePreservesHoldFullDisconnectCancels(t *testing.T) {
	s, _ := askService(t, 5*time.Second)
	defer s.Close()
	path := filepath.Join(shortTempDir(t), "approval.sock")
	l, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go s.Serve(l)
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, shellReq)
	_ = c.CloseWrite()
	waitPendingCount(t, s, 1)
	time.Sleep(100 * time.Millisecond)
	if len(s.Pending()) != 1 {
		t.Fatal("half-close cancelled valid hold")
	}
	_ = c.Close()
	waitPendingCount(t, s, 0)
}
