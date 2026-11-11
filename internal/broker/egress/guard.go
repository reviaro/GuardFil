// Package egress binds a host broker to the owner's session privacy state.
package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Guard func() error

func (g Guard) Check() error {
	if g == nil {
		return nil // standalone broker; executor launchers always bind a session
	}
	return g()
}

func ErrorBody(err error) []byte {
	b, _ := json.Marshal(map[string]any{"error": map[string]string{
		"type": "guardfil_privacy_error", "message": err.Error(), "code": "CLOUD_REQUEST_BLOCKED",
	}})
	return b
}

// FromEnv reads host-only launcher settings. These are never supplied to the
// agent container. Partially configured or malformed bindings fail closed.
func FromEnv() (Guard, error) {
	socket, session := os.Getenv("GUARDFIL_OWNER_SOCKET"), os.Getenv("GUARDFIL_SESSION_ID")
	if socket == "" && session == "" {
		return nil, nil
	}
	return New(socket, session)
}

func New(socket, session string) (Guard, error) {
	if !filepath.IsAbs(socket) || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(session) {
		return nil, errors.New("invalid host privacy session binding")
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func() error {
		resp, err := client.Get("http://owner/sessions/" + session + "/cloud")
		if err != nil {
			return errors.New("GuardFil privacy check unavailable; cloud request blocked")
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			return nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = "session privacy check refused"
		}
		return fmt.Errorf("GuardFil blocked cloud request: %s", message)
	}, nil
}
