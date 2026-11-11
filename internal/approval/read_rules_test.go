package approval

import (
	"os"
	"strings"
	"testing"
)

// Audit finding 2: "File reads in folder" rules (filesystem.read on a path)
// must be enforced on Claude Code's path-taking tools, which arrive as tool calls.
const readRulePolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-claude-tools
    effect: allow
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources:
        - {kind: tool, value: claude.read}
        - {kind: tool, value: claude.grep}
        - {kind: tool, value: claude.glob}
        - {kind: tool, value: claude.ls}
  - id: deny-secret-reads
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.read]
      resources: [{kind: path, value: /workspace/secrets/**}]
  - id: deny-env-reads
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.read]
      resources: [{kind: path, value: /workspace/app/.env}]
`

func executorCatalog(t *testing.T) *Catalog {
	t.Helper()
	b, err := os.ReadFile("../../deployments/local/executor-catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFileReadRulesApplyToReadTools(t *testing.T) {
	cat := executorCatalog(t)
	cases := []struct{ name, req, effect, reason string }{
		{"read denied file", `{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/secrets/k"}}`, "BLOCK", "POLICY_DENIED"},
		{"read other file", `{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/app/main.go"}}`, "ALLOW", "POLICY_ALLOWED"},
		{"read denied single file", `{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/app/.env"}}`, "BLOCK", "POLICY_DENIED"},
		{"read unclean path", `{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/app/../secrets/k"}}`, "BLOCK", "READ_PATH_REQUIRED"},
		{"read relative path", `{"server":"claude","tool":"read","arguments":{"file_path":"secrets/k"}}`, "BLOCK", "READ_PATH_REQUIRED"},
		{"read no path", `{"server":"claude","tool":"read","arguments":{}}`, "BLOCK", "READ_PATH_REQUIRED"},
		{"grep parent dir", `{"server":"claude","tool":"grep","arguments":{"pattern":"k","path":"/workspace"}}`, "BLOCK", "READ_SEARCH_COVERS_RESTRICTED_PATH"},
		{"grep inside denied", `{"server":"claude","tool":"grep","arguments":{"pattern":"k","path":"/workspace/secrets/sub"}}`, "BLOCK", "POLICY_DENIED"},
		{"grep sibling", `{"server":"claude","tool":"grep","arguments":{"pattern":"k","path":"/workspace/docs"}}`, "ALLOW", "POLICY_ALLOWED"},
		{"grep dir holding denied file", `{"server":"claude","tool":"grep","arguments":{"pattern":"k","path":"/workspace/app"}}`, "BLOCK", "READ_SEARCH_COVERS_RESTRICTED_PATH"},
		{"ls root", `{"server":"claude","tool":"ls","arguments":{"path":"/"}}`, "BLOCK", "READ_SEARCH_COVERS_RESTRICTED_PATH"},
		{"glob absolute pattern", `{"server":"claude","tool":"glob","arguments":{"pattern":"/workspace/secrets/*","path":"/workspace/docs"}}`, "BLOCK", "READ_PATTERN_LEAVES_PATH"},
		{"glob dotdot pattern", `{"server":"claude","tool":"glob","arguments":{"pattern":"../secrets/*","path":"/workspace/docs"}}`, "BLOCK", "READ_PATTERN_LEAVES_PATH"},
		{"glob inside", `{"server":"claude","tool":"glob","arguments":{"pattern":"**/*.md","path":"/workspace/docs"}}`, "ALLOW", "POLICY_ALLOWED"},
		{"grep similar name", `{"server":"claude","tool":"grep","arguments":{"pattern":"k","path":"/workspace/secretsx"}}`, "ALLOW", "POLICY_ALLOWED"},
	}
	for _, c := range cases {
		out := EvaluateWithCatalog([]byte(readRulePolicy), cat, []byte(c.req))
		if out.Effect != c.effect || len(out.Reasons) == 0 || out.Reasons[0] != c.reason {
			t.Errorf("%s: got %s %v %v, want %s %s", c.name, out.Effect, out.Reasons, out.RuleIDs, c.effect, c.reason)
		}
	}
}

// Without a read deny or ask-me rule, read tools are decided by the tool rules
// alone (a Grep or Glob without a path keeps working).
func TestReadToolsUnchangedWithoutReadRules(t *testing.T) {
	cat := executorCatalog(t)
	pol := readRulePolicy[:strings.Index(readRulePolicy, "  - id: deny-secret-reads")]
	for _, req := range []string{
		`{"server":"claude","tool":"grep","arguments":{"pattern":"k"}}`,
		`{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/secrets/k"}}`,
		`{"server":"claude","tool":"glob","arguments":{"pattern":"/etc/*"}}`,
	} {
		if out := EvaluateWithCatalog([]byte(pol), cat, []byte(req)); out.Effect != "ALLOW" {
			t.Errorf("%s: %+v", req, out)
		}
	}
	// A read deny rule for another principal does not affect codex-agent.
	other := readRulePolicy + `  - id: deny-other
    effect: deny
    match:
      principals: [agent.other]
      operations: [filesystem.read]
      resources: [{kind: path, value: /workspace/docs/**}]
`
	req := `{"server":"claude","tool":"grep","arguments":{"pattern":"k","path":"/workspace/docs"}}`
	if out := EvaluateWithCatalog([]byte(other), cat, []byte(req)); out.Effect != "ALLOW" {
		t.Errorf("other principal's rule applied: %+v", out)
	}
}

func TestPathsOverlap(t *testing.T) {
	cases := []struct {
		dir, pat string
		want     bool
	}{
		{"/workspace", "/workspace/secrets/**", true},
		{"/workspace/secrets", "/workspace/secrets/**", true},
		{"/workspace/secrets/a", "/workspace/secrets/**", true},
		{"/workspace/secretsx", "/workspace/secrets/**", false},
		{"/workspace/docs", "/workspace/secrets/**", false},
		{"/workspace", "/workspace/key.pem", true},
		{"/workspace/key.pem", "/workspace/key.pem", true},
		{"/workspace/key.pem/sub", "/workspace/key.pem", false},
		{"/workspace", "/", false},
		{"/", "/", true},
		{"/workspace/key", "/workspace/key.pem", false},
		{"/", "/etc/shadow", true},
		{"/workspace/docs", "/**", true},
		{"/workspace/docs", "/workspace/**/.env", true},
		{"/workspace", "/workspace/**/.env", true},
		{"/srv", "/workspace/**/.env", false},
		{"/", "/**/.env", true},
	}
	for _, c := range cases {
		if got := pathsOverlap(c.dir, c.pat); got != c.want {
			t.Errorf("pathsOverlap(%q, %q) = %v", c.dir, c.pat, got)
		}
	}
}

// An ask-me read rule holds a Read of that file for the owner's answer; a
// search that covers it is blocked outright.
func TestAskMeReadRule(t *testing.T) {
	cat := executorCatalog(t)
	pol := readRulePolicy + `  - id: ask-key-reads
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [filesystem.read]
      resources: [{kind: path, value: /workspace/keys/**}]
`
	out := EvaluateWithCatalog([]byte(pol), cat, []byte(`{"server":"claude","tool":"read","arguments":{"file_path":"/workspace/keys/a"}}`))
	if !askable(out) {
		t.Fatalf("ask-me read not askable: %+v", out)
	}
	out = EvaluateWithCatalog([]byte(pol), cat, []byte(`{"server":"claude","tool":"ls","arguments":{"path":"/workspace"}}`))
	if out.Effect != "BLOCK" || askable(out) {
		t.Fatalf("search over ask-me path: %+v", out)
	}
}
