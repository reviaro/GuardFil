package egress_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/broker/adapters"
	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/egress"
	"github.com/reviaro/guardfil/internal/broker/messages"
	"github.com/reviaro/guardfil/internal/broker/neutral"
	"github.com/reviaro/guardfil/internal/broker/responses"
)

func TestAllBrokersStopBeforeTokenCountingAfterLocalOnlyAccess(t *testing.T) {
	pol := []byte(`schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
local_only_paths: [/workspace/private/**]
rules:
 - id: read
   effect: allow
   match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/**}]}
`)
	svc, err := approval.NewService(pol, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	dir, err := os.MkdirTemp("", "gfprivacy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	svc.SetApprovalSocket(filepath.Join(dir, "approval.sock"))
	owner := svc.ApproverHandler()
	w := httptest.NewRecorder()
	owner.ServeHTTP(w, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"default":true,"workspace_mediated":true,"workspace":{"mounts":[{"virtual":"/workspace","filesystem":"1","root":"/test"}]}}`)))
	var session approval.SessionInfo
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &session) != nil {
		t.Fatal(w.Body.String())
	}
	ownerSocket := filepath.Join(dir, "owner.sock")
	l, err := net.Listen("unix", ownerSocket)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: owner}
	go httpServer.Serve(l)
	t.Cleanup(func() { httpServer.Close() })
	guard, err := egress.New(ownerSocket, session.Session)
	if err != nil {
		t.Fatal(err)
	}
	ledgers := map[string]*budget.BudgetLedger{}
	for _, provider := range []string{"openai", "anthropic", "gemini"} {
		ledger, err := budget.Initialize(filepath.Join(dir, provider), "privacy-"+provider)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ledger.Close() })
		ledgers[provider] = ledger
	}
	// These transports are the provider boundary. All replies deliberately
	// refuse the synthetic request without spend; no real keys or APIs are used.
	sent := 0
	rejected := []byte(`{"error":{"message":"synthetic refusal"}}`)
	resp, err := responses.NewResponsesBrokerServer(ledgers["openai"], "synthetic", "privacy", 8, dir, dir, nil,
		func([]byte, string) (int, map[string]string, []byte, error) { sent++; return 400, nil, rejected, nil },
		func([]byte, string) (int, map[string]string, []byte, error) { sent++; return 400, nil, rejected, nil })
	if err != nil {
		t.Fatal(err)
	}
	resp.CloudGuard = guard
	msg, err := messages.NewMessagesBrokerServer(ledgers["anthropic"], "synthetic", "privacy", 8,
		func(string, map[string]string, []byte) (int, []byte, error) { sent++; return 400, rejected, nil }, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	msg.CloudGuard = guard
	neu, err := neutral.NewNeutralBrokerServer(ledgers, "privacy", 8,
		map[string]string{"openai": "synthetic", "anthropic": "synthetic", "gemini": "synthetic"},
		func(*adapters.HTTPRequest, map[string]string) (int, []byte, error) { sent++; return 400, rejected, nil }, "",
		map[string]bool{"openai": true, "anthropic": true, "gemini": true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	neu.CloudGuard = guard
	encoded := base64.StdEncoding.EncodeToString([]byte("private file contents"))
	calls := []struct {
		name string
		call func() bool
	}{
		{"responses", func() bool {
			status, _ := resp.HandleFrameBytes([]byte(`{"model":"gpt-6-luna","stream":true,"input":"` + encoded + `"}`))
			return status == 403
		}},
		{"messages", func() bool {
			status, _ := msg.HandleFrame([]byte(`{"model":"claude-sonnet-5-5","max_tokens":16,"messages":[{"role":"user","content":"` + encoded + `"}]}`))
			return status == 403
		}},
	}
	for _, model := range []string{"openai:gpt-6-luna", "anthropic:claude-sonnet-5-5", "gemini:gemini-3.6-flash"} {
		calls = append(calls, struct {
			name string
			call func() bool
		}{model, func() bool {
			out := neu.Handle([]byte(`{"model":"` + model + `","messages":[{"role":"user","content":"` + encoded + `"}],"max_output_tokens":16}`))
			return out["code"] == "CLOUD_REQUEST_BLOCKED"
		}})
	}
	for _, call := range calls {
		before := sent
		if call.call() || sent != before+1 {
			t.Fatalf("%s positive control did not reach its provider transport (sent %d -> %d)", call.name, before, sent)
		}
	}
	conn, err := net.Dial("unix", session.ApprovalSocket)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(conn, `{"kind":"file_read","paths":["/workspace/private/key"]}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	var out approval.Output
	err = json.NewDecoder(conn).Decode(&out)
	conn.Close()
	if err != nil || out.Effect != "ALLOW" {
		t.Fatalf("private local access: %+v %v", out, err)
	}
	before := sent
	for _, call := range calls {
		if !call.call() {
			t.Errorf("%s did not return a privacy refusal", call.name)
		}
	}
	if sent != before {
		t.Fatalf("private/encoded content reached a provider, including token counting: %d -> %d", before, sent)
	}
	for provider, ledger := range ledgers {
		status, err := ledger.GetStatus()
		if err != nil || status.TotalEncumberedMicros != 0 {
			t.Fatalf("%s privacy test reserved/spent money: %+v %v", provider, status, err)
		}
	}
	httpServer.Close()
	if guard.Check() == nil {
		t.Fatal("owner service loss allowed cloud access")
	}
}

func TestIncompleteBrokerSessionBindingFailsClosed(t *testing.T) {
	for _, tc := range []struct{ socket, session string }{
		{"", "0123456789abcdef"}, {"/tmp/owner.sock", ""}, {"relative", "0123456789abcdef"}, {"/tmp/owner.sock", "../session"},
	} {
		if _, err := egress.New(tc.socket, tc.session); err == nil {
			t.Fatalf("accepted bad binding: %+v", tc)
		}
	}
}
