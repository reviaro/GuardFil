package approval

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const agentPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-shell-for-a
    effect: allow
    match:
      principals: [agent.a]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: codex.exec_command
`

type fakeGWRegistrar struct {
	mu         sync.Mutex
	registered map[string]string
	revoked    []string
}

func newFakeGWRegistrar() *fakeGWRegistrar {
	return &fakeGWRegistrar{registered: make(map[string]string)}
}

func (f *fakeGWRegistrar) RegisterSession(token, principal string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered[token] = principal
}

func (f *fakeGWRegistrar) RevokeSession(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, token)
	delete(f.registered, token)
}

func parseAllLogEntries(t *testing.T, log *bytes.Buffer) []LogEntry {
	t.Helper()
	trimmed := strings.TrimSpace(log.String())
	if trimmed == "" {
		return nil
	}
	lines := strings.Split(trimmed, "\n")
	entries := make([]LogEntry, len(lines))
	for i, l := range lines {
		if err := json.Unmarshal([]byte(l), &entries[i]); err != nil {
			t.Fatalf("unmarshal log line %q: %v", l, err)
		}
	}
	return entries
}

func TestAgentIdentitySessionsAllowDenyLog(t *testing.T) {
	dir := shortTempDir(t)
	mainSock := filepath.Join(dir, "approval.sock")

	var log bytes.Buffer
	svc, err := NewService([]byte(agentPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	svc.SetApprovalSocket(mainSock)
	gw := newFakeGWRegistrar()
	svc.SetGatewayRegistrar(gw)

	mainListener, err := ListenUnix(mainSock)
	if err != nil {
		t.Fatal(err)
	}
	defer mainListener.Close()
	go func() { _ = svc.Serve(mainListener) }()

	handler := svc.ApproverHandler()

	// Create session for agent.a
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"agent":"a"}`)))
	if recA.Code != http.StatusCreated {
		t.Fatalf("create session a: %d %s", recA.Code, recA.Body)
	}
	var sessA SessionInfo
	if err := json.Unmarshal(recA.Body.Bytes(), &sessA); err != nil {
		t.Fatal(err)
	}
	if sessA.Principal != "agent.a" || sessA.ApprovalSocket == "" || sessA.GatewayToken == "" {
		t.Fatalf("sessA info: %+v", sessA)
	}

	// Create session for agent.b
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"agent":"b"}`)))
	if recB.Code != http.StatusCreated {
		t.Fatalf("create session b: %d %s", recB.Code, recB.Body)
	}
	var sessB SessionInfo
	if err := json.Unmarshal(recB.Body.Bytes(), &sessB); err != nil {
		t.Fatal(err)
	}
	if sessB.Principal != "agent.b" || sessB.ApprovalSocket == "" || sessB.GatewayToken == "" {
		t.Fatalf("sessB info: %+v", sessB)
	}

	// Verify gateway registration
	gw.mu.Lock()
	if gw.registered[sessA.GatewayToken] != "agent.a" {
		t.Fatalf("gw token A principal: %q", gw.registered[sessA.GatewayToken])
	}
	if gw.registered[sessB.GatewayToken] != "agent.b" {
		t.Fatalf("gw token B principal: %q", gw.registered[sessB.GatewayToken])
	}
	gw.mu.Unlock()

	req := `{"kind":"shell","command":["echo","hello"],"cwd":"/workspace"}`

	// 1. Session A (agent.a) -> ALLOWED
	outA := ask(t, sessA.ApprovalSocket, req)
	if outA.Effect != "ALLOW" || len(outA.Reasons) == 0 || outA.Reasons[0] != "POLICY_ALLOWED" {
		t.Fatalf("session A expected ALLOW: %+v", outA)
	}

	// 2. Session B (agent.b) -> BLOCKED (POLICY_DENIED)
	outB := ask(t, sessB.ApprovalSocket, req)
	if outB.Effect != "BLOCK" || len(outB.Reasons) == 0 || outB.Reasons[0] != "POLICY_DENIED" {
		t.Fatalf("session B expected BLOCK POLICY_DENIED: %+v", outB)
	}

	// 3. Shared socket (codex-agent) -> BLOCKED (POLICY_DENIED)
	outMain := ask(t, mainSock, req)
	if outMain.Effect != "BLOCK" || len(outMain.Reasons) == 0 || outMain.Reasons[0] != "POLICY_DENIED" {
		t.Fatalf("main socket expected BLOCK POLICY_DENIED: %+v", outMain)
	}

	// 4. Decision log names each principal
	entries := parseAllLogEntries(t, &log)
	if len(entries) != 3 {
		t.Fatalf("expected 3 log entries, got %d", len(entries))
	}
	if entries[0].Principal != "agent.a" || entries[0].Effect != "ALLOW" {
		t.Errorf("entry 0: expected agent.a ALLOW, got %+v", entries[0])
	}
	if entries[1].Principal != "agent.b" || entries[1].Effect != "BLOCK" {
		t.Errorf("entry 1: expected agent.b BLOCK, got %+v", entries[1])
	}
	if entries[2].Principal != "codex-agent" || entries[2].Effect != "BLOCK" {
		t.Errorf("entry 2: expected codex-agent BLOCK, got %+v", entries[2])
	}
}

func TestAgentIdentitySessionLimitsAndValidation(t *testing.T) {
	dir := shortTempDir(t)
	mainSock := filepath.Join(dir, "approval.sock")

	var log bytes.Buffer
	svc, err := NewService([]byte(agentPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	svc.SetApprovalSocket(mainSock)
	gw := newFakeGWRegistrar()
	svc.SetGatewayRegistrar(gw)
	handler := svc.ApproverHandler()

	// Bad agent names
	badNames := []string{
		"",
		"Agent",
		"-agent",
		".agent",
		"_agent",
		"agent/sub",
		"agent space",
		"agent@domain",
		strings.Repeat("a", 57),
	}
	for _, name := range badNames {
		b, _ := json.Marshal(map[string]string{"agent": name})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", bytes.NewReader(b)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for bad name %q, got %d", name, rec.Code)
		}
	}

	// Unknown session DELETE gives 404
	recDelUnknown := httptest.NewRecorder()
	handler.ServeHTTP(recDelUnknown, httptest.NewRequest("DELETE", "/sessions/0123456789abcdef", nil))
	if recDelUnknown.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown session DELETE, got %d", recDelUnknown.Code)
	}

	// Create 64 sessions (the maximum)
	var sessions []SessionInfo
	for i := 0; i < 64; i++ {
		name := "agent" + string(rune('a'+(i%26))) + string(rune('0'+(i/26)))
		b, _ := json.Marshal(map[string]string{"agent": name})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", bytes.NewReader(b)))
		if rec.Code != http.StatusCreated {
			t.Fatalf("create session %d: %d %s", i, rec.Code, rec.Body)
		}
		var si SessionInfo
		if err := json.Unmarshal(rec.Body.Bytes(), &si); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, si)
	}

	// 65th session must be refused (503 Service Unavailable)
	rec65 := httptest.NewRecorder()
	handler.ServeHTTP(rec65, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"agent":"agent65"}`)))
	if rec65.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for 65th session, got %d %s", rec65.Code, rec65.Body)
	}

	// DELETE session 0
	target := sessions[0]
	recDel := httptest.NewRecorder()
	handler.ServeHTTP(recDel, httptest.NewRequest("DELETE", "/sessions/"+target.Session, nil))
	if recDel.Code != http.StatusNoContent {
		t.Fatalf("delete session: %d %s", recDel.Code, recDel.Body)
	}

	// After DELETE: socket file is gone
	if _, err := os.Stat(target.ApprovalSocket); !os.IsNotExist(err) {
		t.Fatalf("socket file still exists after DELETE: %v", err)
	}

	// Connecting to deleted socket fails
	if _, err := net.DialTimeout("unix", target.ApprovalSocket, 100*time.Millisecond); err == nil {
		t.Fatal("connect to deleted socket succeeded")
	}

	// Gateway token revoked
	gw.mu.Lock()
	if _, ok := gw.registered[target.GatewayToken]; ok {
		t.Fatal("gateway token still registered after DELETE")
	}
	foundRevoked := false
	for _, tok := range gw.revoked {
		if tok == target.GatewayToken {
			foundRevoked = true
			break
		}
	}
	gw.mu.Unlock()
	if !foundRevoked {
		t.Fatal("gateway token was not recorded in revoked list")
	}

	// Now that 1 session was deleted, creating a 64th session succeeds again
	recNew := httptest.NewRecorder()
	handler.ServeHTTP(recNew, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"agent":"agentrepl"}`)))
	if recNew.Code != http.StatusCreated {
		t.Fatalf("expected 201 after deleting one session, got %d %s", recNew.Code, recNew.Body)
	}
}

func TestAgentIdentitySchemaRejectsPrincipalFields(t *testing.T) {
	var log bytes.Buffer
	svc, err := NewService([]byte(agentPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	badRequests := []string{
		`{"kind":"shell","command":["echo","hi"],"cwd":"/workspace","principal":"agent.a"}`,
		`{"kind":"shell","command":["echo","hi"],"cwd":"/workspace","agent":"a"}`,
		`{"kind":"shell","command":["echo","hi"],"cwd":"/workspace","actor":"agent.a"}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a","change":"add"}],"principal":"agent.a"}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a","change":"add"}],"agent":"a"}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a","change":"add"}],"actor":"agent.a"}`,
		`{"server":"codex","tool":"exec_command","arguments":{},"principal":"agent.a"}`,
		`{"server":"codex","tool":"exec_command","arguments":{},"agent":"a"}`,
		`{"server":"codex","tool":"exec_command","arguments":{},"actor":"agent.a"}`,
	}

	for _, req := range badRequests {
		out := svc.Decide([]byte(req))
		if out.Effect != "BLOCK" {
			t.Errorf("req %s was not BLOCKed: %+v", req, out)
		}
		if len(out.Reasons) == 0 || out.Reasons[0] != "SCHEMA_INVALID" {
			t.Errorf("req %s expected SCHEMA_INVALID, got %+v", req, out)
		}
	}

	// Approver handler schema rejection of unknown fields
	handler := svc.ApproverHandler()

	recPostSession := httptest.NewRecorder()
	handler.ServeHTTP(recPostSession, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"agent":"test","principal":"agent.spoof"}`)))
	if recPostSession.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for session request with extra principal, got %d", recPostSession.Code)
	}

	recPostApproval := httptest.NewRecorder()
	handler.ServeHTTP(recPostApproval, httptest.NewRequest("POST", "/v1/approvals/0123456789abcdef01234567", strings.NewReader(`{"decision":"allow","principal":"agent.spoof"}`)))
	if recPostApproval.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for approval request with extra principal, got %d", recPostApproval.Code)
	}
}

func TestAgentIdentityAskMePrincipal(t *testing.T) {
	const askPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: ask-shell-a
    effect: require_approval
    match:
      principals: [agent.a]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: codex.exec_command
`
	var log bytes.Buffer
	svc, err := NewService([]byte(askPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if err := svc.EnableAsk(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Output, 1)
	go func() {
		ch <- svc.Decide([]byte(`{"kind":"shell","command":["echo","hi"],"cwd":"/workspace"}`), "agent.a")
	}()

	var info PendingInfo
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p := svc.Pending(); len(p) == 1 {
			info = p[0]
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if info.ID == "" {
		t.Fatal("call was not held")
	}
	if info.Principal != "agent.a" {
		t.Fatalf("pending info principal: %q", info.Principal)
	}

	if err := svc.Answer(info.ID, true); err != nil {
		t.Fatal(err)
	}
	out := <-ch
	if out.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW: %+v", out)
	}

	e := lastEntry(t, &log)
	if e.Principal != "agent.a" || e.Asked != "allowed" {
		t.Fatalf("log entry: %+v", e)
	}
}
