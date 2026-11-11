package policy

import (
	"errors"
	"testing"
)

func TestDenyFirst(t *testing.T) {
	raw := []byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n - id: deny\n   effect: deny\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/private/**}]}\n")
	s, e := Compile(raw)
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.Evaluate(Input{"acme", "app", "filesystem.read", "path", "/work/private/key"})
	if e != nil || !r.Denied || r.Allowed {
		t.Fatal(r, e)
	}
}

func TestTypedResourceKindCannotMatchSameValue(t *testing.T) {
	raw := []byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/file}]}\n")
	s, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Evaluate(Input{"acme", "app", "filesystem.read", "url", "/work/file"})
	if err != nil || r.Allowed {
		t.Fatalf("resource kind mismatch granted: %+v %v", r, err)
	}
}

func TestApprovalObligationAndClosedYAMLFailClosed(t *testing.T) {
	raw := []byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n - id: approval\n   effect: require_approval\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n")
	s, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Evaluate(Input{"acme", "app", "filesystem.read", "path", "/work/file"})
	if err != nil || r.Allowed || !r.RequiresApproval {
		t.Fatalf("unmet approval result: %+v, %v", r, err)
	}

	for _, invalid := range [][]byte{
		append(append([]byte(nil), raw...), []byte("---\nschema_version: 1\ntenant_id: other\nrevision: 1\ndefault: deny\nrules: []\n")...),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   unexpected: true\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**, extra: true}]}\n"),
		[]byte("schema_version: 1\ntenant_id: &tenant acme\nrevision: 1\ndefault: deny\nrules: []\n"),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - &rule\n   id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: &match {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [&resource {kind: path, value: /work/**}]}\n"),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/../private/**}]}\n"),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [http.request], resources: [{kind: url, value: 'https://example.com/a?'}]}\n"),
		[]byte("schema_version: 1\ntenant_id: acme\ntenant_id: other\nrevision: 1\ndefault: deny\nrules: []\n"),
		[]byte("schema_version: 1\ntenant_id: !untrusted acme\nrevision: 1\ndefault: deny\nrules: []\n"),
		[]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - &base {id: allow, effect: allow, match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}}\n - <<: *base\n"),
	} {
		if _, err := Compile(invalid); err == nil {
			t.Fatal("closed policy parser accepted unsupported YAML")
		}
	}
}

func TestEveryNonAllowPolicyStateFailsClosed(t *testing.T) {
	base := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"
	for name, suffix := range map[string]string{
		"deny":     " - id: deny\n   effect: deny\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n",
		"approval": " - id: approval\n   effect: require_approval\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n",
		"sanitize": " - id: sanitize\n   effect: sanitize\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n",
		"check":    " - id: checked\n   effect: allow\n   checks: [required-check]\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n",
	} {
		t.Run(name, func(t *testing.T) {
			s, err := Compile([]byte(base + suffix))
			if err != nil {
				t.Fatal(err)
			}
			r, err := s.Evaluate(Input{"acme", "app", "filesystem.read", "path", "/work/file"})
			if err != nil || r.Allowed {
				t.Fatalf("non-allow state granted: %+v %v", r, err)
			}
		})
	}
	s, err := Compile([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Evaluate(Input{"acme", "other", "filesystem.read", "path", "/work/file"})
	if err != nil || r.Allowed {
		t.Fatalf("no-match granted: %+v %v", r, err)
	}
}

func TestCompileOperationRejections(t *testing.T) {
	rejectedOps := []string{
		"fs.write",
		"http.get",
		"Filesystem.read",
		"tool.read",
		"llm.request",
		"shell.execute",
	}
	for _, op := range rejectedOps {
		p := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: test-rule\n   effect: allow\n   match: {principals: [app], operations: [" + op + "], resources: [{kind: path, value: /work/**}]}\n"
		if _, err := Compile([]byte(p)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Compile with operation %q expected ErrInvalid, got %v", op, err)
		}
	}

	acceptedCases := []struct {
		op         string
		operations string
		resources  string
	}{
		{"filesystem.read", "[filesystem.read]", "[{kind: path, value: /work/**}]"},
		{"filesystem.write", "[filesystem.write]", "[{kind: path, value: /work/**}]"},
		{"tool.invoke", "[tool.invoke]", "[{kind: tool, value: test-tool}]"},
		{"http.request", "[http.request]", "[{kind: url, value: 'https://example.com/a'}]"},
	}
	for _, tc := range acceptedCases {
		p := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: test-rule\n   effect: allow\n   match: {principals: [app], operations: " + tc.operations + ", resources: " + tc.resources + "}\n"
		if _, err := Compile([]byte(p)); err != nil {
			t.Fatalf("Compile with accepted operation %q failed: %v", tc.op, err)
		}
	}

	rejectedPairs := []struct {
		op         string
		operations string
		resources  string
	}{
		{"llm.request", "[filesystem.read, llm.request]", "[{kind: path, value: /work/**}]"},
		{"shell.execute", "[filesystem.read, shell.execute]", "[{kind: path, value: /work/**}]"},
	}
	for _, tc := range rejectedPairs {
		p := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: test-rule\n   effect: allow\n   match: {principals: [app], operations: " + tc.operations + ", resources: " + tc.resources + "}\n"
		if _, err := Compile([]byte(p)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Compile with rejected operation pair %q expected ErrInvalid, got %v", tc.op, err)
		}
	}
}

func TestCompileOperationResourceKindMatching(t *testing.T) {
	rejected := []struct {
		name string
		yaml string
	}{
		{
			name: "filesystem.write+url",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [filesystem.write], resources: [{kind: url, value: 'https://example.com/a'}]}\n",
		},
		{
			name: "http.request+path",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [http.request], resources: [{kind: path, value: /work/**}]}\n",
		},
		{
			name: "tool.invoke+path",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [tool.invoke], resources: [{kind: path, value: /work/**}]}\n",
		},
		{
			name: "filesystem.read+tool",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: tool, value: test-tool}]}\n",
		},
		{
			name: "[shell.execute] + path",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [shell.execute], resources: [{kind: path, value: /work/**}]}\n",
		},
		{
			name: "[llm.request] + tool",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [llm.request], resources: [{kind: tool, value: test-tool}]}\n",
		},
		{
			name: "[filesystem.read, llm.request] + path",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read, llm.request], resources: [{kind: path, value: /work/**}]}\n",
		},
		{
			name: "[filesystem.read, shell.execute] + path",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read, shell.execute], resources: [{kind: path, value: /work/**}]}\n",
		},
		{
			name: "[tool.invoke, llm.request] + tool",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [tool.invoke, llm.request], resources: [{kind: tool, value: test-tool}]}\n",
		},
		{
			name: "mixed [filesystem.read, http.request] with only path",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read, http.request], resources: [{kind: path, value: /work/**}]}\n",
		},
	}
	for _, tc := range rejected {
		t.Run("reject "+tc.name, func(t *testing.T) {
			if _, err := Compile([]byte(tc.yaml)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Compile expected ErrInvalid for %s, got %v", tc.name, err)
			}
		})
	}

	accepted := []struct {
		name string
		yaml string
	}{
		{
			name: "filesystem.read+path",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n",
		},
		{
			name: "http.request+url",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [http.request], resources: [{kind: url, value: 'https://example.com/a'}]}\n",
		},
		{
			name: "tool.invoke+tool",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [tool.invoke], resources: [{kind: tool, value: test-tool}]}\n",
		},
		{
			name: "mixed [filesystem.read, http.request] with path+url",
			yaml: "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: r1\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read, http.request], resources: [{kind: path, value: /work/**}, {kind: url, value: 'https://example.com/a'}]}\n",
		},
	}
	for _, tc := range accepted {
		t.Run("accept "+tc.name, func(t *testing.T) {
			if _, err := Compile([]byte(tc.yaml)); err != nil {
				t.Fatalf("Compile failed for %s: %v", tc.name, err)
			}
		})
	}
}

func TestCompileDeadDenyRegression(t *testing.T) {
	// A policy with an allow rule on filesystem.write and a deny rule on "fs.write"
	// previously compiled and silently failed to enforce the deny rule at runtime.
	// It must now fail to compile with ErrInvalid.
	deadDenyPolicy := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: broad-allow
    effect: allow
    match:
      principals: [app]
      operations: [filesystem.write]
      resources: [{kind: path, value: /work/**}]
  - id: narrow-deny
    effect: deny
    match:
      principals: [app]
      operations: [fs.write]
      resources: [{kind: path, value: /work/narrow/**}]
`
	if _, err := Compile([]byte(deadDenyPolicy)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Compile dead-deny policy expected ErrInvalid, got %v", err)
	}
}

func TestResultRuleIDLists(t *testing.T) {
	policyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: allow-1
    effect: allow
    match:
      principals: [app]
      operations: [filesystem.read]
      resources: [{kind: path, value: /work/**}]
    checks: [secret_scanner]
  - id: allow-2
    effect: allow
    match:
      principals: [app]
      operations: [filesystem.read]
      resources: [{kind: path, value: /work/**}]
  - id: deny-1
    effect: deny
    match:
      principals: [app]
      operations: [filesystem.read]
      resources: [{kind: path, value: /work/**}]
  - id: approval-1
    effect: require_approval
    match:
      principals: [app]
      operations: [filesystem.read]
      resources: [{kind: path, value: /work/**}]
  - id: sanitize-1
    effect: sanitize
    match:
      principals: [app]
      operations: [filesystem.read]
      resources: [{kind: path, value: /work/**}]
`
	s, err := Compile([]byte(policyYAML))
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	res, err := s.Evaluate(Input{
		TenantID:     "acme",
		PrincipalID:  "app",
		Operation:    "filesystem.read",
		ResourceKind: "path",
		Resource:     "/work/test.txt",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(res.DenyRules) != 1 || res.DenyRules[0] != "deny-1" {
		t.Fatalf("unexpected DenyRules: %v", res.DenyRules)
	}
	if len(res.ApprovalRules) != 1 || res.ApprovalRules[0] != "approval-1" {
		t.Fatalf("unexpected ApprovalRules: %v", res.ApprovalRules)
	}
	if len(res.SanitizeRules) != 1 || res.SanitizeRules[0] != "sanitize-1" {
		t.Fatalf("unexpected SanitizeRules: %v", res.SanitizeRules)
	}
	if len(res.CheckRules) != 1 || res.CheckRules[0] != "allow-1" {
		t.Fatalf("unexpected CheckRules (rule IDs only): %v", res.CheckRules)
	}
	if len(res.AllowRules) != 2 || res.AllowRules[0] != "allow-1" || res.AllowRules[1] != "allow-2" {
		t.Fatalf("unexpected AllowRules: %v", res.AllowRules)
	}

	// Tenant mismatch
	resMismatch, err := s.Evaluate(Input{
		TenantID:     "other",
		PrincipalID:  "app",
		Operation:    "filesystem.read",
		ResourceKind: "path",
		Resource:     "/work/test.txt",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !resMismatch.Denied {
		t.Fatal("expected tenant mismatch to be Denied")
	}
	if len(resMismatch.DenyRules) != 0 || len(resMismatch.AllowRules) != 0 {
		t.Fatalf("expected tenant mismatch to have no rules, got deny=%v allow=%v", resMismatch.DenyRules, resMismatch.AllowRules)
	}
}

func TestPerCauseListsSortedAndUnique(t *testing.T) {
	assertSlice := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: expected len %d (%v), got len %d (%v)", name, len(want), want, len(got), got)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s[%d]: expected %q, got %q (full got: %v, want: %v)", name, i, want[i], got[i], got, want)
			}
		}
	}

	policyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: z-deny
    effect: deny
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: a-deny
    effect: deny
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: m-deny
    effect: deny
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: z-approval
    effect: require_approval
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: a-approval
    effect: require_approval
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: m-approval
    effect: require_approval
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: z-sanitize
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: a-sanitize
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: m-sanitize
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: z-check
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
    checks: [z-check-op, a-check-op, m-check-op, a-check-op]
  - id: a-check
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
    checks: [m-check-op, a-check-op]
  - id: m-check
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
    checks: [z-check-op, m-check-op]
  - id: z-allow
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: a-allow
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: m-allow
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	s, err := Compile([]byte(policyYAML))
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	res, err := s.Evaluate(Input{
		TenantID:     "acme",
		PrincipalID:  "app",
		Operation:    "filesystem.read",
		ResourceKind: "path",
		Resource:     "/work/file",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	assertSlice("DenyRules", res.DenyRules, []string{"a-deny", "m-deny", "z-deny"})
	assertSlice("ApprovalRules", res.ApprovalRules, []string{"a-approval", "m-approval", "z-approval"})
	assertSlice("SanitizeRules", res.SanitizeRules, []string{"a-check", "a-sanitize", "m-check", "m-sanitize", "z-check", "z-sanitize"})
	assertSlice("CheckRules", res.CheckRules, []string{"a-check", "m-check", "z-check"})
	assertSlice("Checks", res.Checks, []string{"a-check-op", "m-check-op", "z-check-op"})
	assertSlice("AllowRules", res.AllowRules, []string{"a-allow", "m-allow", "z-allow"})
}

func TestMonitorPermitsButNeverBeatsABlock(t *testing.T) {
	head := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n"
	rule := func(id, effect string) string {
		return " - id: " + id + "\n   effect: " + effect + "\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"
	}
	in := Input{"acme", "app", "filesystem.read", "path", "/work/file"}
	eval := func(t *testing.T, rules string) Result {
		t.Helper()
		s, err := Compile([]byte(head + rules))
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.Evaluate(in)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := eval(t, rule("watch", "monitor"))
	if !r.Allowed || !r.Monitored || len(r.MonitorRules) != 1 || r.MonitorRules[0] != "watch" || len(r.AllowRules) != 0 {
		t.Fatalf("monitor alone: %+v", r)
	}
	r = eval(t, rule("allow", "allow")+rule("watch", "monitor"))
	if !r.Allowed || !r.Monitored || r.AllowRules[0] != "allow" || r.MonitorRules[0] != "watch" {
		t.Fatalf("allow+monitor: %+v", r)
	}
	for _, blocker := range []string{"deny", "require_approval", "sanitize"} {
		r = eval(t, rule("watch", "monitor")+rule("b", blocker))
		if r.Allowed || r.Monitored {
			t.Fatalf("monitor beat %s: %+v", blocker, r)
		}
	}
	r = eval(t, " - id: watch\n   effect: monitor\n   checks: [required-check]\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n")
	if r.Allowed || r.Monitored {
		t.Fatalf("monitor beat a check: %+v", r)
	}
	r = eval(t, rule("watch", "monitor"))
	other, _ := Compile([]byte(head + rule("watch", "monitor")))
	if res, _ := other.Evaluate(Input{"acme", "app", "filesystem.read", "path", "/elsewhere"}); res.Allowed || res.Monitored {
		t.Fatalf("monitor matched outside its resources: %+v", res)
	}
}
