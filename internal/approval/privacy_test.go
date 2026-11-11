package approval

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestLocalOnlyAccessIsStickyAndConfinesOutputs(t *testing.T) {
	base := strings.Replace(fileAskPolicy, "require_approval", "allow", 1)
	private := strings.Replace(base, "rules:", "local_only_paths: [/workspace/private/**]\nrules:", 1)
	s, err := NewService([]byte(private), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.SetApprovalSocket(shortTempDir(t) + "/approval.sock")
	first, second := defaultFileSession(t, s), defaultFileSession(t, s)
	if err := s.CheckCloudSession(first.Session); err != nil {
		t.Fatal(err)
	}
	read := `{"kind":"file_read","paths":["/workspace/private/key"]}`
	if out := s.Decide([]byte(read)); out.Effect != "BLOCK" {
		t.Fatalf("anonymous private access: %+v", out)
	}
	if out := ask(t, first.ApprovalSocket, read); out.Effect != "ALLOW" {
		t.Fatal(out)
	}
	if !errors.Is(s.CheckCloudSession(first.Session), ErrLocalOnly) {
		t.Fatal("local-only read did not block cloud")
	}
	if err := s.CheckCloudSession(second.Session); err != nil {
		t.Fatalf("unrelated session blocked: %v", err)
	}
	for _, p := range []string{"/workspace/encoded-copy", "/workspace/private/../public", "/workspace/private-neighbor/copy"} {
		out := ask(t, first.ApprovalSocket, `{"kind":"file_write","changes":[{"path":"`+p+`","change":"add"}]}`)
		if out.Effect != "BLOCK" {
			t.Fatalf("private output escaped to %s: %+v", p, out)
		}
	}
	if out := ask(t, first.ApprovalSocket, `{"kind":"file_write","changes":[{"path":"/workspace/private/report","change":"add"}]}`); out.Effect != "ALLOW" {
		t.Fatal(out)
	}
	if out := ask(t, second.ApprovalSocket, `{"kind":"file_read","paths":["/workspace/private/report"]}`); out.Effect != "ALLOW" {
		t.Fatal(out)
	}
	if !errors.Is(s.CheckCloudSession(second.Session), ErrLocalOnly) {
		t.Fatal("second reader did not inherit local-only classification")
	}
	if err := s.RevokeFileGrants(first.Session); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetPolicy([]byte(base)); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.CheckCloudSession(first.Session), ErrLocalOnly) {
		t.Fatal("rule edits or grant clearing reset private knowledge")
	}
	if err := s.deleteSession(first.Session); err != nil {
		t.Fatal(err)
	}
	if s.CheckCloudSession(first.Session) == nil {
		t.Fatal("ended session could use cloud")
	}
}

func TestPrivacyClassificationChangesCoverPreviouslyReadRenamedFiles(t *testing.T) {
	base := strings.Replace(fileAskPolicy, "require_approval", "allow", 1)
	s, err := NewService([]byte(base), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.SetApprovalSocket(shortTempDir(t) + "/approval.sock")
	first, fresh := defaultFileSession(t, s), defaultFileSession(t, s)
	if out := ask(t, first.ApprovalSocket, fileReadA); out.Effect != "ALLOW" {
		t.Fatal(out)
	}
	private := strings.Replace(base, "rules:", "local_only_paths: [/workspace/renamed-a]\nrules:", 1)
	if _, err := s.SetPolicy([]byte(private)); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.CheckCloudSession(first.Session), ErrLocalOnly) {
		t.Fatal("classification change forgot previously read data")
	}
	if err := s.CheckCloudSession(fresh.Session); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateSessionCannotUseGatewayOrForgeLocalToolCalls(t *testing.T) {
	pol := strings.Replace(fileAskPolicy, "require_approval", "allow", 1)
	s, err := NewService([]byte(pol), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a := newSessionAccess("test")
	a.mediated, a.localOnly = true, true
	ctx := context.WithValue(context.Background(), sessionAccessKey{}, a)
	allowed := Output{Effect: "ALLOW", PolicyDigest: "test"}
	for _, req := range []struct{ raw, target string }{
		{`{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/a"},"can_filter":true}`, ""},
		{`{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/a"}}`, "https://example.com/upload"},
		{`{"server":"cloud","tool":"save","arguments":{"data":"ZW5jb2RlZA=="}}`, ""},
	} {
		if out := s.privacyDecision(ctx, []byte(req.raw), []byte(pol), req.target, allowed); out.Effect != "BLOCK" {
			t.Fatal(out)
		}
	}
}
