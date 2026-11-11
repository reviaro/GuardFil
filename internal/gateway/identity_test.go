package gateway

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/config"
)

const agentGatewayPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-orders-for-a
    effect: allow
    match:
      principals: [agent.a]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: stockapp.place_order
  - id: allow-quote-for-main
    effect: allow
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: stockapp.get_quote
`

func TestGatewayPerAgentIdentity(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	app := &seen{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		app.mu.Lock()
		app.reqs, app.body = append(app.reqs, r), append(app.body, b)
		app.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"path":"` + r.URL.Path + `"}`))
	}))
	t.Cleanup(upstream.Close)

	catBytes, err := os.ReadFile("../../deployments/example/approval/stockapp-catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := approval.ParseCatalog(catBytes)
	if err != nil {
		t.Fatal(err)
	}

	var log bytes.Buffer
	svc, err := approval.NewService([]byte(agentGatewayPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCatalog(c); err != nil {
		t.Fatal(err)
	}

	mainTok := "main-agent-token-0123456789abcdef"
	cfg := config.Gateway{
		Address:        "127.0.0.1:0",
		AgentTokenFile: write("agent", mainTok+"\n"),
		Upstreams: []config.Upstream{{
			Name:             "stockapp",
			BaseURL:          upstream.URL,
			CredentialFile:   write("key", "test-key"),
			CredentialHeader: "X-Api-Key",
			Routes: []config.Route{
				{Method: "GET", Path: "/api/quote/{symbol}", Tool: "stockapp.get_quote"},
				{Method: "POST", Path: "/api/orders", Tool: "stockapp.place_order"},
			},
		}},
	}

	g, err := New(cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	gwServer := httptest.NewServer(g)
	t.Cleanup(gwServer.Close)

	tokA := "sess-tok-a-0123456789abcdef0123456789abcdef"
	tokB := "sess-tok-b-0123456789abcdef0123456789abcdef"

	g.RegisterSession(tokA, "agent.a")
	g.RegisterSession(tokB, "agent.b")

	callWithToken := func(method, path, body, bearer string) (int, string) {
		req, _ := http.NewRequest(method, gwServer.URL+path, strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	orderBody := `{"symbol":"ACME","side":"buy","quantity":10}`

	// 1. Agent A's token: decided as agent.a -> allowed on stockapp.place_order (200 OK)
	code, body := callWithToken("POST", "/stockapp/api/orders", orderBody, tokA)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for agent A on place_order, got %d %s", code, body)
	}

	// 2. Agent B's token: cannot be used for agent A's allowed route -> 403 Forbidden (POLICY_DENIED)
	code, body = callWithToken("POST", "/stockapp/api/orders", orderBody, tokB)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent B on place_order, got %d %s", code, body)
	}
	if !strings.Contains(body, "POLICY_DENIED") {
		t.Fatalf("expected POLICY_DENIED for agent B, got %s", body)
	}

	// 3. Main token on place_order -> 403 Forbidden (codex-agent not allowed)
	code, body = callWithToken("POST", "/stockapp/api/orders", orderBody, mainTok)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for main token on place_order, got %d %s", code, body)
	}

	// 4. Main token on get_quote -> 200 OK (codex-agent allowed)
	code, body = callWithToken("GET", "/stockapp/api/quote/ACME", "", mainTok)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for main token on get_quote, got %d %s", code, body)
	}

	// 5. Revoke Agent A's token
	g.RevokeSession(tokA)

	// 6. Revoked token gets 401 Unauthorized
	code, body = callWithToken("POST", "/stockapp/api/orders", orderBody, tokA)
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked token, got %d %s", code, body)
	}

	// 7. Main token still works after session revocation
	code, body = callWithToken("GET", "/stockapp/api/quote/ACME", "", mainTok)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for main token after agent revocation, got %d %s", code, body)
	}
}
