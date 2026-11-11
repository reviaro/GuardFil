package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/config"
)

func TestOwnerSessionPrivacyStopsActualGatewayRequests(t *testing.T) {
	var hits atomic.Int32
	app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); io.WriteString(w, `{"ok":true}`) }))
	defer app.Close()
	pol := agentGatewayPolicy + `  - id: files
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/**}]}
local_only_paths: [/workspace/private/**]
`
	svc, err := approval.NewService([]byte(pol), io.Discard)
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
	dir, err := os.MkdirTemp("", "gf-gateway-privacy-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(agentToken), 0600); err != nil {
		t.Fatal(err)
	}
	g, err := New(config.Gateway{AgentTokenFile: tokenFile, Upstreams: []config.Upstream{{Name: "stockapp", BaseURL: app.URL,
		Routes: []config.Route{{Method: "GET", Path: "/api/quote/{symbol}", Tool: "stockapp.get_quote"}}}}}, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	g.client.Transport = app.Client().Transport
	svc.SetGatewayRegistrar(g)
	svc.SetApprovalSocket(filepath.Join(dir, "approval.sock"))
	w := httptest.NewRecorder()
	svc.ApproverHandler().ServeHTTP(w, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"default":true,"workspace_mediated":true}`)))
	var sess approval.SessionInfo
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &sess) != nil {
		t.Fatal(w.Body.String())
	}
	call := func() int {
		r := httptest.NewRequest("GET", "/stockapp/api/quote/ZW5jb2RlZA", nil)
		r.Header.Set("Authorization", "Bearer "+sess.GatewayToken)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w.Code
	}
	if code := call(); code != 200 || hits.Load() != 1 {
		t.Fatalf("public gateway positive control: %d hits=%d", code, hits.Load())
	}
	conn, err := net.Dial("unix", sess.ApprovalSocket)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, `{"kind":"file_read","paths":["/workspace/private/file"]}`+"\n")
	var out approval.Output
	err = json.NewDecoder(conn).Decode(&out)
	conn.Close()
	if err != nil || out.Effect != "ALLOW" {
		t.Fatal(out, err)
	}
	if code := call(); code != 403 || hits.Load() != 1 {
		t.Fatalf("private session reached real upstream: %d hits=%d", code, hits.Load())
	}
}
