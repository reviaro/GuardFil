package mcpproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// DecideFunc authorizes the actual tools/call, before any bytes reach the server.
// The arguments are canonical JSON, also used in the forwarded request.
type DecideFunc func(server, tool string, arguments json.RawMessage) error

// DecisionTimeout covers the owner's maximum ten-minute approval hold.
const DecisionTimeout = 630 * time.Second

// SocketDecider uses the session's approval socket, preserving agent identity.
func SocketDecider(path string) DecideFunc {
	return func(server, tool string, arguments json.RawMessage) error {
		conn, err := net.DialTimeout("unix", path, FilterTimeout)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(DecisionTimeout))
		req, err := json.Marshal(map[string]any{"server": server, "tool": tool,
			"arguments": arguments, "can_filter": true})
		if err != nil {
			return err
		}
		if _, err = conn.Write(append(req, '\n')); err != nil {
			return err
		}
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
		buf, err := io.ReadAll(io.LimitReader(conn, (64<<10)+1))
		if err != nil {
			return err
		}
		var out struct {
			Effect string `json:"effect"`
		}
		if len(buf) > 64<<10 || json.Unmarshal(buf, &out) != nil || out.Effect != "ALLOW" {
			return errors.New("tool call was not allowed")
		}
		return nil
	}
}

// canonicalObject removes duplicate keys before both policy and server parsing,
// while retaining exact numbers (tool amounts must not round through float64).
func canonicalObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil || v == nil {
		return nil, errors.New("expected JSON object")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	var out map[string]json.RawMessage
	err := json.Unmarshal(marshal(v), &out)
	return out, err
}
