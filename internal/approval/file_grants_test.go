package approval

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fileAskPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: ask-files
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [filesystem.read, filesystem.write]
      resources: [{kind: path, value: /workspace/**}]
`

func fileGrantService(t *testing.T) (*Service, SessionInfo) {
	t.Helper()
	s, err := NewService([]byte(fileAskPolicy), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err = s.EnableAsk(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	s.SetApprovalSocket(filepath.Join(shortTempDir(t), "approval.sock"))
	return s, defaultFileSession(t, s)
}

func defaultFileSession(t *testing.T, s *Service) SessionInfo {
	t.Helper()
	w := httptest.NewRecorder()
	s.ApproverHandler().ServeHTTP(w, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"default":true,"workspace":{"mounts":[{"virtual":"/workspace","filesystem":"1","root":"/test"}]}}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("create default session: %d %s", w.Code, w.Body.String())
	}
	var info SessionInfo
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil || info.Principal != syntheticPrinc {
		t.Fatalf("session: %+v %v", info, err)
	}
	return info
}

func pendingFiles(t *testing.T, s *Service, count int) []PendingInfo {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p := s.Pending(); len(p) == count {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected %d pending calls, got %+v", count, s.Pending())
	return nil
}

func fileCall(t *testing.T, socket, request string) <-chan Output {
	t.Helper()
	ch := make(chan Output, 1)
	go func() { ch <- ask(t, socket, request) }()
	return ch
}

func fileAnswer(t *testing.T, s *Service, id, scope string) {
	t.Helper()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"decision": "allow", "scope": scope})
	s.ApproverHandler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/approvals/"+id, strings.NewReader(string(body))))
	if w.Code != http.StatusNoContent {
		t.Fatalf("answer: %d %s", w.Code, w.Body.String())
	}
}

const fileReadA = `{"kind":"file_read","paths":["/workspace/a"]}`

func TestSessionFileApprovalReusesOnlyReviewedAccess(t *testing.T) {
	s, sess := fileGrantService(t)
	ch := fileCall(t, sess.ApprovalSocket, fileReadA)
	p := pendingFiles(t, s, 1)[0]
	if !p.SessionGrant || p.Session != sess.Session {
		t.Fatalf("file session scope not shown: %+v", p)
	}
	fileAnswer(t, s, p.ID, "session")
	if out := <-ch; out.Effect != "ALLOW" {
		t.Fatalf("owner grant: %+v", out)
	}
	for i := 0; i < 20; i++ {
		if out := ask(t, sess.ApprovalSocket, fileReadA); out.Effect != "ALLOW" {
			t.Fatalf("repeated read needs another answer: %+v", out)
		}
	}
	other := defaultFileSession(t, s)
	for _, probe := range []struct{ socket, request string }{
		{sess.ApprovalSocket, `{"kind":"file_read","paths":["/workspace/a-child"]}`},
		{sess.ApprovalSocket, `{"kind":"file_write","changes":[{"path":"/workspace/a","change":"update"}]}`},
		{other.ApprovalSocket, fileReadA},
	} {
		ch = fileCall(t, probe.socket, probe.request)
		p = pendingFiles(t, s, 1)[0]
		if err := s.Answer(p.ID, false); err != nil {
			t.Fatal(err)
		}
		if out := <-ch; out.Effect != "BLOCK" {
			t.Fatalf("grant escaped its exact path, operation or session: %+v", out)
		}
	}
}

func TestSessionFileGrantRevocationAndPolicyEdits(t *testing.T) {
	s, sess := fileGrantService(t)
	for _, revoke := range []func(){
		func() {
			w := httptest.NewRecorder()
			s.ApproverHandler().ServeHTTP(w, httptest.NewRequest("DELETE", "/sessions/"+sess.Session+"/file-grants", nil))
			if w.Code != http.StatusNoContent {
				t.Fatal(w.Code)
			}
		},
		func() {
			if _, err := s.SetPolicy([]byte(fileAskPolicy)); err != nil {
				t.Fatal(err)
			}
		},
		func() { s.SetContentRules(nil) },
	} {
		ch := fileCall(t, sess.ApprovalSocket, fileReadA)
		p := pendingFiles(t, s, 1)[0]
		fileAnswer(t, s, p.ID, "session")
		if out := <-ch; out.Effect != "ALLOW" {
			t.Fatal(out)
		}
		revoke()
	}
	ch := fileCall(t, sess.ApprovalSocket, fileReadA)
	p := pendingFiles(t, s, 1)[0]
	fileAnswer(t, s, p.ID, "session")
	<-ch
	if _, err := s.SetPolicy([]byte(strings.Replace(fileAskPolicy, "require_approval", "deny", 1))); err != nil {
		t.Fatal(err)
	}
	if out := ask(t, sess.ApprovalSocket, fileReadA); out.Effect != "BLOCK" || len(s.Pending()) != 0 {
		t.Fatalf("grant overrode a policy deny: %+v", out)
	}
}

func TestSessionGrantReleasesMatchingConcurrentHolds(t *testing.T) {
	s, sess := fileGrantService(t)
	a := fileCall(t, sess.ApprovalSocket, fileReadA)
	b := fileCall(t, sess.ApprovalSocket, fileReadA)
	p := pendingFiles(t, s, 2)
	fileAnswer(t, s, p[0].ID, "session")
	for _, ch := range []<-chan Output{a, b} {
		select {
		case out := <-ch:
			if out.Effect != "ALLOW" {
				t.Fatal(out)
			}
		case <-time.After(time.Second):
			t.Fatal("matching hold needed another owner answer")
		}
	}
}

func TestOnceApprovalAndAgentCannotCreateSessionGrants(t *testing.T) {
	s, sess := fileGrantService(t)
	for i := 0; i < 2; i++ {
		ch := fileCall(t, sess.ApprovalSocket, fileReadA)
		p := pendingFiles(t, s, 1)[0]
		fileAnswer(t, s, p.ID, "once")
		<-ch
	}
	for _, raw := range []string{
		`{"kind":"file_read","paths":["/workspace/a"],"scope":"session"}`,
		`{"kind":"file_read","paths":["/workspace/a"],"session":"` + sess.Session + `"}`,
	} {
		if out := ask(t, sess.ApprovalSocket, raw); out.Effect != "BLOCK" || len(s.Pending()) != 0 {
			t.Fatalf("agent asserted its own grant: %+v", out)
		}
	}
	ch, p := decideAsync(t, s, fileReadA)
	if p.SessionGrant || s.AnswerWithScope(p.ID, true, "session") != ErrApprovalScope {
		t.Fatal("shared approval socket acquired a reusable grant")
	}
	s.Answer(p.ID, false)
	<-ch
}

func TestMediatedNativeReadDefersOnlyWorkspaceChecksToFilesystem(t *testing.T) {
	s, plain := fileGrantService(t)
	if err := s.SetCatalog(executorCatalog(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetPolicy([]byte(fileAskPolicy + `
  - id: allow-read-tool
    effect: allow
    match: {principals: [codex-agent], operations: [tool.invoke], resources: [{kind: tool, value: claude.read}]}
  - id: outside-workspace
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /tmp/private}]}
`)); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ApproverHandler().ServeHTTP(w, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"default":true,"workspace_mediated":true}`)))
	var mediated SessionInfo
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &mediated) != nil {
		t.Fatalf("mediated session: %d %s", w.Code, w.Body.String())
	}
	request := `{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/a"}}`
	if out := ask(t, mediated.ApprovalSocket, request); out.Effect != "ALLOW" {
		t.Fatalf("native hook adds a duplicate filesystem prompt: %+v", out)
	}
	for _, probe := range []struct{ socket, request string }{
		{plain.ApprovalSocket, request},
		{mediated.ApprovalSocket, fileReadA},
	} {
		ch := fileCall(t, probe.socket, probe.request)
		p := pendingFiles(t, s, 1)[0]
		s.Answer(p.ID, false)
		if out := <-ch; out.Effect != "BLOCK" {
			t.Fatalf("unmediated tool or actual filesystem bypassed approval: %+v", out)
		}
	}
	outside := strings.Replace(request, "/workspace/a", "/tmp/private", 1)
	if out := ask(t, mediated.ApprovalSocket, outside); out.Effect != "BLOCK" {
		t.Fatalf("mediated declaration removed an unrelated path rule: %+v", out)
	}
	forged := strings.TrimSuffix(request, "}") + `,"workspace_mediated":true}`
	if out := ask(t, plain.ApprovalSocket, forged); out.Effect != "BLOCK" || len(s.Pending()) > 0 {
		t.Fatalf("agent forged the owner's mediation declaration: %+v", out)
	}
}
