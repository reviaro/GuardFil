package approval

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const askPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: ask-shell
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: codex.exec_command
  - id: ask-notes
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources:
        - kind: path
          value: /workspace/notes/**
  - id: never-secret
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources:
        - kind: path
          value: /workspace/notes/secret/**
`

const shellReq = `{"kind":"shell","command":["bash","-lc","echo SECRET-CMD"],"cwd":"/workspace"}`

func askService(t *testing.T, timeout time.Duration) (*Service, *bytes.Buffer) {
	t.Helper()
	var log bytes.Buffer
	s, err := NewService([]byte(askPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	if timeout > 0 {
		if err := s.EnableAsk(timeout); err != nil {
			t.Fatal(err)
		}
	}
	return s, &log
}

// decideAsync runs Decide in the background and waits until the call is held.
func decideAsync(t *testing.T, s *Service, req string) (chan Output, PendingInfo) {
	t.Helper()
	ch := make(chan Output, 1)
	go func() { ch <- s.Decide([]byte(req)) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p := s.Pending(); len(p) == 1 {
			return ch, p[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("call was not held")
	return nil, PendingInfo{}
}

func TestHeadlessAskIsBlocked(t *testing.T) {
	s, _ := askService(t, 0)
	out := s.Decide([]byte(shellReq))
	if out.Effect != "BLOCK" || out.Reasons[0] != ReasonApprovalNeeded || s.AskEnabled() || len(s.Pending()) != 0 {
		t.Fatalf("headless ask: %+v", out)
	}
	if err := s.Answer(strings.Repeat("a", 24), true); err == nil {
		t.Fatal("answer accepted while headless")
	}
}

func TestAskAllowDenyAndLog(t *testing.T) {
	s, log := askService(t, 5*time.Second)
	ch, info := decideAsync(t, s, shellReq)
	if info.Kind != "shell" || info.Tool != "codex.exec_command" || len(info.ID) != 24 ||
		len(info.RuleIDs) != 1 || info.RuleIDs[0] != "ask-shell" || info.ExpiresAt == "" {
		t.Fatalf("pending info: %+v", info)
	}
	// The owner sees the command while it is held (memory only), so they can judge it.
	if !strings.Contains(info.Detail, "SECRET-CMD") || !strings.Contains(info.Detail, "(in /workspace)") {
		t.Fatalf("held command not shown to the owner: %q", info.Detail)
	}
	if err := s.Answer(info.ID, true); err != nil {
		t.Fatal(err)
	}
	out := <-ch
	if out.Effect != "ALLOW" || out.Reasons[0] != ReasonApprovalGranted || out.RuleIDs[0] != "ask-shell" {
		t.Fatalf("allowed: %+v", out)
	}
	if e := lastEntry(t, log); e.Asked != "allowed" || e.Effect != "ALLOW" {
		t.Fatalf("log: %+v", e)
	}
	if err := s.Answer(info.ID, false); err != ErrUnknownApproval {
		t.Fatalf("second answer: %v", err)
	}

	ch, info = decideAsync(t, s, `{"kind":"file_write","changes":[{"path":"/workspace/notes/a","change":"add"}]}`)
	if info.Kind != "file_write" || len(info.Paths) != 1 || info.Paths[0] != "/workspace/notes/a" {
		t.Fatalf("write pending: %+v", info)
	}
	_ = s.Answer(info.ID, false)
	if out = <-ch; out.Effect != "BLOCK" || out.Reasons[0] != ReasonApprovalRejected {
		t.Fatalf("denied: %+v", out)
	}
	if e := lastEntry(t, log); e.Asked != "denied" {
		t.Fatalf("log: %+v", e)
	}
	if info.Detail != "" {
		t.Fatalf("file write detail: %q", info.Detail)
	}
	if strings.Contains(log.String(), "SECRET-CMD") {
		t.Fatal("command text in decision log")
	}
}

func TestAskTimeoutAndClose(t *testing.T) {
	s, log := askService(t, time.Second)
	start := time.Now()
	out := s.Decide([]byte(shellReq))
	if out.Effect != "BLOCK" || out.Reasons[0] != ReasonApprovalExpired || time.Since(start) < time.Second {
		t.Fatalf("timeout: %+v after %v", out, time.Since(start))
	}
	if e := lastEntry(t, log); e.Asked != "expired" {
		t.Fatalf("log: %+v", e)
	}
	s2, _ := askService(t, time.Minute)
	ch, _ := decideAsync(t, s2, shellReq)
	s2.Close()
	select {
	case out = <-ch:
		if out.Effect != "BLOCK" || out.Reasons[0] != ReasonApprovalExpired {
			t.Fatalf("closed: %+v", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not release the held call")
	}
	if out = s2.Decide([]byte(shellReq)); out.Effect != "BLOCK" { // after Close: immediate BLOCK
		t.Fatalf("after close: %+v", out)
	}
}

func TestDenyIsNeverAsked(t *testing.T) {
	s, _ := askService(t, 5*time.Second)
	out := s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/notes/secret/k","change":"add"}]}`))
	if out.Effect != "BLOCK" || len(s.Pending()) != 0 {
		t.Fatalf("deny was held or allowed: %+v", out)
	}
	for _, r := range out.Reasons {
		if r == ReasonApprovalGranted {
			t.Fatal("deny granted")
		}
	}
	// An unmatched call (default deny) is not askable either.
	if out = s.Decide([]byte(`{"server":"x","tool":"y","arguments":{}}`)); out.Effect != "BLOCK" || len(s.Pending()) != 0 {
		t.Fatalf("default deny held: %+v", out)
	}
}

func TestEnableAskRange(t *testing.T) {
	s, _ := askService(t, 0)
	if s.EnableAsk(0) == nil || s.EnableAsk(MaxAskTimeout+time.Second) == nil {
		t.Fatal("out-of-range timeout accepted")
	}
}

func TestApproverHTTP(t *testing.T) {
	s, _ := askService(t, 5*time.Second)
	h := s.ApproverHandler()
	ch, info := decideAsync(t, s, shellReq)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/approvals", nil))
	var list []PendingInfo
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 1 || list[0].ID != info.ID {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	for body, code := range map[string]int{`{"decision":"maybe"}`: 400, `{"decision":"allow","x":1}`: 400, `not json`: 400} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/approvals/"+info.ID, strings.NewReader(body)))
		if rec.Code != code {
			t.Fatalf("body %q: %d", body, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/approvals/"+strings.Repeat("0", 24), strings.NewReader(`{"decision":"allow"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/approvals/../x", strings.NewReader(`{"decision":"allow"}`)))
	if rec.Code == http.StatusNoContent {
		t.Fatal("bad id answered")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/approvals/"+info.ID, strings.NewReader(`{"decision":"allow"}`)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("answer: %d %s", rec.Code, rec.Body)
	}
	if out := <-ch; out.Effect != "ALLOW" {
		t.Fatalf("http allow: %+v", out)
	}
}
