package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/config"
)

// Real TLS requests prove the host-selected upstream URL is checked before
// dispatch. Browser/agent Host headers and query arguments cannot replace it.
func TestWebsiteEnforcementBeforeUpstream(t *testing.T) {
	var hits atomic.Int32
	app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, "/REDIR") {
			http.Redirect(w, r, "/api/quote/DENIED", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer app.Close()
	pol, err := os.ReadFile("../../deployments/example/approval/stockapp-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	withRule := func(effect, principal string) []byte {
		return []byte(string(pol) + fmt.Sprintf(`
  - id: website
    effect: %s
    match:
      principals: [%s]
      operations: [http.request]
      resources: [{kind: url, value: '%s/api/quote/DENIED'}]
`, effect, principal, app.URL))
	}
	svc, err := approval.NewService(withRule("deny", "codex-agent"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	catBytes, err := os.ReadFile("../../deployments/example/approval/stockapp-catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := approval.ParseCatalog(catBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCatalog(cat); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableAsk(time.Second); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(tokenFile, []byte(agentToken), 0600); err != nil {
		t.Fatal(err)
	}
	g, err := New(config.Gateway{AgentTokenFile: tokenFile, Upstreams: []config.Upstream{{Name: "stockapp", BaseURL: app.URL,
		Routes: []config.Route{{Method: "GET", Path: "/api/quote/{symbol}", Tool: "stockapp.get_quote"}}}}}, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	g.client.Transport = app.Client().Transport // trust only this local TLS fixture
	gw := httptest.NewServer(g)
	defer gw.Close()
	for _, path := range []string{"DENIED", "DENIED?symbol=ALLOWED", "%44ENIED"} {
		code, body := call(t, gw, "GET", "/stockapp/api/quote/"+path, "", map[string]string{"Host": "public.example"})
		if code != 403 || hits.Load() != 0 {
			t.Fatalf("denied request executed: %d %s hits=%d", code, body, hits.Load())
		}
	}
	if code, body := call(t, gw, "GET", "/stockapp/api/quote/ALLOWED", "", nil); code != 200 || hits.Load() != 1 {
		t.Fatal(code, body, hits.Load())
	}
	// The gateway never follows redirects; no second request reaches DENIED.
	req := httptest.NewRequest("GET", "/stockapp/api/quote/REDIR", nil)
	req.Header.Set("Authorization", "Bearer "+agentToken)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 302 || hits.Load() != 2 {
		t.Fatal("redirect followed", w.Code, hits.Load())
	}
	for _, answer := range []bool{false, true} {
		if _, err := svc.SetPolicy(withRule("require_approval", "codex-agent")); err != nil {
			t.Fatal(err)
		}
		before := hits.Load()
		done := make(chan int, 1)
		go func() {
			r := httptest.NewRequest("GET", "/stockapp/api/quote/DENIED", nil)
			r.Header.Set("Authorization", "Bearer "+agentToken)
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			done <- w.Code
		}()
		deadline := time.Now().Add(time.Second)
		for len(svc.Pending()) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		p := svc.Pending()
		if len(p) != 1 || hits.Load() != before || !strings.Contains(p[0].Detail, app.URL+"/api/quote/DENIED") {
			t.Fatal("not held before dispatch", p, hits.Load())
		}
		if err := svc.Answer(p[0].ID, answer); err != nil {
			t.Fatal(err)
		}
		code := <-done
		if answer && (code != 200 || hits.Load() != before+1) || !answer && (code != 403 || hits.Load() != before) {
			t.Fatal(answer, code, hits.Load())
		}
	}
	// A rule for another principal does not affect the default token.
	if _, err := svc.SetPolicy(withRule("deny", "agent.other")); err != nil {
		t.Fatal(err)
	}
	if code, body := call(t, gw, "GET", "/stockapp/api/quote/DENIED", "", nil); code != 200 {
		t.Fatal(code, body)
	}
	// Give the named principal a tool grant; its Website deny still takes
	// precedence when the same gateway route is reached with its session token.
	other := string(withRule("deny", "agent.other")) + `
  - id: other-quotes
    effect: allow
    match:
      principals: [agent.other]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.get_quote}]
`
	if _, err := svc.SetPolicy([]byte(other)); err != nil {
		t.Fatal(err)
	}
	g.RegisterSession("other-session-token", "agent.other")
	before := hits.Load()
	headers := map[string]string{"Authorization": "Bearer other-session-token"}
	if code, body := call(t, gw, "GET", "/stockapp/api/quote/DENIED", "", headers); code != 403 || !strings.Contains(body, "website") || hits.Load() != before {
		t.Fatal("session website deny", code, body, hits.Load())
	}
	if code, body := call(t, gw, "GET", "/stockapp/api/quote/ALLOWED", "", headers); code != 200 || hits.Load() != before+1 {
		t.Fatal("session positive control", code, body, hits.Load())
	}
}
