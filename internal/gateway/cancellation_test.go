package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/config"
	"github.com/reviaro/guardfil/internal/content"
	"github.com/reviaro/guardfil/internal/filter"
)

type cancellationTransport func(*http.Request) (*http.Response, error)

func (f cancellationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGatewayCancelsRequestAndResultHolds(t *testing.T) {
	for _, resultHold := range []bool{false, true} {
		for _, revoke := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "request", true: "result"}[resultHold], map[bool]string{false: "disconnect", true: "revoke"}[revoke]}, "/"), func(t *testing.T) {
				effect := "require_approval"
				if resultHold {
					effect = "allow"
				}
				pol := `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: quote
    effect: ` + effect + `
    match:
      principals: [agent.a]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.get_quote}]
`
				svc, err := approval.NewService([]byte(pol), io.Discard)
				if err != nil {
					t.Fatal(err)
				}
				defer svc.Close()
				_ = svc.EnableAsk(5 * time.Second)
				catBytes, err := os.ReadFile("../../deployments/example/approval/stockapp-catalog.yaml")
				if err != nil {
					t.Fatal(err)
				}
				cat, err := approval.ParseCatalog(catBytes)
				if err != nil {
					t.Fatal(err)
				}
				if err = svc.SetCatalog(cat); err != nil {
					t.Fatal(err)
				}
				if resultHold {
					cr, err := content.ParseRules([]byte(`{"schema_version":1,"lists":[{"id":"ask","name":"Ask","action":"ask","direction":"response","tools":["*"],"words":["review"]}]}`))
					if err != nil {
						t.Fatal(err)
					}
					svc.SetContentRules(cr)
				}
				tokfile := filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(tokfile, []byte(agentToken), 0600); err != nil {
					t.Fatal(err)
				}
				g, err := New(config.Gateway{AgentTokenFile: tokfile, Upstreams: []config.Upstream{{Name: "stockapp", BaseURL: "http://127.0.0.1:1", Routes: []config.Route{{Method: "GET", Path: "/quote/{symbol}", Tool: "stockapp.get_quote"}}}}}, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
				if err != nil {
					t.Fatal(err)
				}
				filterCalled := false
				defaultFilter := g.FilterResult
				g.FilterResult = func(ctx context.Context, tool, body string, principals ...string) filter.Result {
					filterCalled = true
					return defaultFilter(ctx, tool, body, principals...)
				}
				g.client.Transport = cancellationTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("please review"))}, nil
				})
				const sessionToken = "session-test-token-0123456789"
				g.RegisterSession(sessionToken, "agent.a")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				r := httptest.NewRequest("GET", "/stockapp/quote/ACME", nil).WithContext(ctx)
				r.Header.Set("Authorization", "Bearer "+sessionToken)
				w := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); g.ServeHTTP(w, r) }()
				deadline := time.Now().Add(time.Second)
				for len(svc.Pending()) == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if len(svc.Pending()) != 1 {
					t.Fatal("no pending approval")
				}
				if revoke {
					g.RevokeSession(sessionToken)
				} else {
					cancel()
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("cancelled hold did not finish")
				}
				if resultHold && !filterCalled {
					t.Fatal("configured response filter was bypassed")
				}
				if len(svc.Pending()) != 0 || w.Code != http.StatusForbidden {
					t.Fatalf("pending=%d status=%d body=%s", len(svc.Pending()), w.Code, w.Body)
				}
			})
		}
	}
}
