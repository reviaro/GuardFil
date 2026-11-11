package gateway

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/config"
)

// Audit finding 3: the injected credential reached the agent when the app
// reflected it JSON-escaped, or in a Location header containing '+'.
func TestCredentialNeverReachesAgentInAnyForm(t *testing.T) {
	const cred = "zq9/Ab+cd/EfGh7Kp2Lm" // no recognizable prefix; '/' and '+'
	escSlash := strings.ReplaceAll(cred, "/", `\/`)
	escU := strings.ReplaceAll(cred, "/", `\u002f`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/quote/SLASH":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"debug_auth":"` + escSlash + `"}`))
		case "/api/quote/UNI":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"debug_auth":"` + escU + `"}`))
		case "/api/quote/NDJSON":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"debug_auth":"` + escSlash + `"}` + "\n{}"))
		case "/api/quote/PREFIX":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`prefix {"debug_auth":"` + escU + `"} end`))
		case "/api/quote/LOWERPCT":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("k=" + strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(cred), "%2F", "%2f"), "%2B", "%2b")))
		case "/api/quote/URLENC":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("k=" + url.QueryEscape(cred)))
		case "/api/quote/REDIR":
			w.Header().Set("Location", "https://example.com/cb?k="+cred)
			w.WriteHeader(http.StatusFound)
		case "/api/quote/REDIRENC":
			w.Header().Set("Location", "https://example.com/cb?k="+url.QueryEscape(cred)+"&bad=%zz")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cat, err := os.ReadFile("../../deployments/example/approval/stockapp-catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := os.ReadFile("../../deployments/example/approval/stockapp-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approval.NewService(pol, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := approval.ParseCatalog(cat)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCatalog(c); err != nil {
		t.Fatal(err)
	}
	cfg := config.Gateway{Address: "127.0.0.1:0", AgentTokenFile: write("agent", agentToken+"\n"),
		Upstreams: []config.Upstream{{Name: "stockapp", BaseURL: upstream.URL, CredentialFile: write("key", cred),
			CredentialHeader: "X-Api-Key", Routes: []config.Route{
				{Method: "GET", Path: "/api/quote/{symbol}", Tool: "stockapp.get_quote"}}}}}
	g, err := New(cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(g)
	t.Cleanup(gw.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	forms := []string{cred, escSlash, escU, url.QueryEscape(cred), url.PathEscape(cred), strings.ReplaceAll(cred, "+", " ")}
	forms = append(forms, strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(cred), "%2F", "%2f"), "%2B", "%2b"))
	for _, sym := range []string{"SLASH", "UNI", "URLENC", "REDIR", "REDIRENC", "NDJSON", "PREFIX", "LOWERPCT"} {
		req, _ := http.NewRequest("GET", gw.URL+"/stockapp/api/quote/"+sym, nil)
		req.Header.Set("Authorization", "Bearer "+agentToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		for _, f := range forms {
			if bytes.Contains(body, []byte(f)) || strings.Contains(loc, f) {
				t.Errorf("%s: credential form %q reached the agent: status=%d body=%s location=%q", sym, f, resp.StatusCode, body, loc)
			}
		}
	}
}
