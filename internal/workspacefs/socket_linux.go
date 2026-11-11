package workspacefs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/reviaro/guardfil/internal/approval"
)

// SocketAuthorizer uses the session's existing approval socket, preserving
// per-agent identity, live policy updates, owner approvals and decision logs.
func SocketAuthorizer(socket string) Authorize {
	return func(ctx context.Context, write bool, paths ...string) error {
		if len(paths) == 0 || len(paths) > 16 {
			return errors.New("invalid workspace path batch")
		}
		var request any = struct {
			Kind  string   `json:"kind"`
			Paths []string `json:"paths"`
		}{"file_read", paths}
		if write {
			changes := []map[string]string{}
			for _, p := range paths {
				changes = append(changes, map[string]string{"path": p, "change": "update"})
			}
			request = struct {
				Kind    string              `json:"kind"`
				Changes []map[string]string `json:"changes"`
			}{"file_write", changes}
		}
		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
		if err != nil {
			return err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		// The owner protocol permits holds up to 600 seconds. The service
		// bounds each hold; this also bounds a stalled or malformed peer.
		deadline := time.Now().Add(605 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err = conn.SetDeadline(deadline); err != nil {
			return err
		}
		if err = json.NewEncoder(conn).Encode(request); err != nil {
			return err
		}
		scan := bufio.NewScanner(conn)
		scan.Buffer(make([]byte, 4096), approval.MaxRequestBytes)
		if !scan.Scan() {
			return errors.New("workspace decision unavailable")
		}
		var out approval.Output
		if err = json.Unmarshal(scan.Bytes(), &out); err != nil {
			return err
		}
		if out.Effect != "ALLOW" || out.PolicyDigest == "" || out.PolicyDigest == "-" || len(out.Filter) != 0 {
			return fmt.Errorf("workspace access denied: %s %v", out.Effect, out.Reasons)
		}
		return nil
	}
}
