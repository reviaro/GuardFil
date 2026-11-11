package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func websitePolicy(toolEffect, webEffect, principal string) []byte {
	return []byte(fmt.Sprintf(`schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: tool
    effect: %s
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: claude.webfetch}]
  - id: website
    effect: %s
    match:
      principals: [%s]
      operations: [http.request]
      resources: [{kind: url, value: 'https://example.com/private/**'}]
`, toolEffect, webEffect, principal))
}

func fetchRequest(target string, canFilter bool) []byte {
	req := map[string]any{"server": "claude", "tool": "webfetch", "arguments": map[string]string{"url": target}}
	if canFilter {
		req["can_filter"] = true
	}
	b, _ := json.Marshal(req)
	return b
}

func TestWebsiteRulesOnNativeFetch(t *testing.T) {
	cat := executorCatalog(t)
	for _, tc := range []struct {
		name, toolEffect, webEffect, target, principal, effect, reason string
		filter                                                         bool
	}{
		{"deny", "allow", "deny", "https://example.com/private/key", "codex-agent", "BLOCK", "POLICY_DENIED", false},
		{"query cannot evade", "allow", "deny", "https://example.com/private/key?download=1#part", "codex-agent", "BLOCK", "POLICY_DENIED", false},
		{"other path", "allow", "deny", "https://example.com/public", "codex-agent", "ALLOW", "POLICY_ALLOWED", false},
		{"segment boundary", "allow", "deny", "https://example.com/private-other", "codex-agent", "ALLOW", "POLICY_ALLOWED", false},
		{"other principal", "allow", "deny", "https://example.com/private/key", "agent.other", "ALLOW", "POLICY_ALLOWED", false},
		{"ask", "allow", "require_approval", "https://example.com/private/key", "codex-agent", "BLOCK", ReasonApprovalNeeded, false},
		{"deny beats tool ask", "require_approval", "deny", "https://example.com/private/key", "codex-agent", "BLOCK", "POLICY_DENIED", false},
		{"website allow cannot grant tool", "deny", "allow", "https://example.com/private/key", "codex-agent", "BLOCK", "POLICY_DENIED", false},
		{"allow preserves tool ask", "require_approval", "allow", "https://example.com/private/key", "codex-agent", "BLOCK", ReasonApprovalNeeded, false},
		{"monitor", "allow", "monitor", "https://example.com/private/key", "codex-agent", "ALLOW", "POLICY_ALLOWED", false},
		{"filter unsupported", "allow", "sanitize", "https://example.com/private/key", "codex-agent", "BLOCK", "TRANSFORM_UNAVAILABLE", false},
		{"filter supported", "allow", "sanitize", "https://example.com/private/key", "codex-agent", "ALLOW", "POLICY_ALLOWED", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := EvaluateWithCatalog(websitePolicy(tc.toolEffect, tc.webEffect, tc.principal), cat, fetchRequest(tc.target, tc.filter))
			if out.Effect != tc.effect || !hasString(out.Reasons, tc.reason) {
				t.Fatalf("got %+v", out)
			}
			if tc.webEffect == "monitor" && !Monitored(out) {
				t.Fatalf("not monitored: %+v", out)
			}
			if tc.filter && !hasString(out.Filter, "website") {
				t.Fatalf("lost filter: %+v", out)
			}
		})
	}
	for _, target := range []string{"", "http://example.com/private/a", "https://EXAMPLE.com/private/a",
		"https://example.com.:443/private/a", "https://example.com:443/private/a", "https://example.com./private/a",
		"https://example.com:0443/private/a", "https://example.com:08443/private/a", "https://example.com:/private/a",
		"https://example.com/public/../private/a", "https://example.com/%70rivate/a",
		"https://example.com/private%2fa", "https://example.com//private/a", "https://user:pass@example.com/private/a",
		"https://example.com/privaté/a", "https://example.com/private\\a"} {
		out := EvaluateWithCatalog(websitePolicy("allow", "deny", "codex-agent"), cat, fetchRequest(target, false))
		if out.Effect != "BLOCK" || !hasString(out.Reasons, "WEBSITE_URL_UNSUPPORTED") {
			t.Errorf("%q: %+v", target, out)
		}
	}
}

func TestWebsiteAskBindsTransportURLAndInvalidates(t *testing.T) {
	var log bytes.Buffer
	s, err := NewService(websitePolicy("allow", "require_approval", "codex-agent"), &log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetCatalog(executorCatalog(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableAsk(time.Second); err != nil {
		t.Fatal(err)
	}
	// The URL in the tool arguments is not the actual gateway transport target.
	raw := fetchRequest("https://public.example/", true)
	for _, answer := range []string{"allow", "deny", "change"} {
		done := make(chan Output, 1)
		go func() {
			done <- s.DecideHTTPContext(context.Background(), raw, "https://example.com/private/a?token=synthetic")
		}()
		deadline := time.Now().Add(time.Second)
		for len(s.Pending()) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		pending := s.Pending()
		if len(pending) != 1 || !strings.Contains(pending[0].Detail, "https://example.com/private/a?token=synthetic; arguments: {") {
			t.Fatalf("missing actual target: %+v", pending)
		}
		if answer == "change" {
			if _, err := s.SetPolicy(websitePolicy("allow", "deny", "codex-agent")); err != nil {
				t.Fatal(err)
			}
		} else if err := s.Answer(pending[0].ID, answer == "allow"); err != nil {
			t.Fatal(err)
		}
		out := <-done
		if (out.Effect == "ALLOW") != (answer == "allow") {
			t.Fatalf("%s: %+v", answer, out)
		}
		if strings.Contains(log.String(), "token=synthetic") {
			t.Fatal("target leaked into log")
		}
	}
	// Transport URL participates in both the action digest and request hash.
	s2, err := NewService(websitePolicy("allow", "monitor", "codex-agent"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.SetCatalog(executorCatalog(t)); err != nil {
		t.Fatal(err)
	}
	a := s2.DecideHTTPContext(context.Background(), raw, "https://example.com/private/a")
	b := s2.DecideHTTPContext(context.Background(), raw, "https://example.com/private/b")
	if a.ActionDigest == b.ActionDigest || !Monitored(a) {
		t.Fatalf("unbound URL: %+v %+v", a, b)
	}
}

func TestToolApprovalCannotBypassReadDenial(t *testing.T) {
	pol := strings.Replace(readRulePolicy, "effect: allow", "effect: require_approval", 1)
	out := EvaluateWithCatalog([]byte(pol), executorCatalog(t), []byte(`{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/secrets/key"}}`))
	if out.Effect != "BLOCK" || askable(out) {
		t.Fatalf("tool approval bypasses read deny: %+v", out)
	}
}
