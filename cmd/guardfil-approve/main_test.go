package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "deployments", "example", "approval", name)
}

func runCLI(t *testing.T, args []string, stdin string) (int, Output, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	var out Output
	if stdout.Len() > 0 {
		lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("expected exactly 1 stdout line, got %d: %q", len(lines), stdout.String())
		}
		if err := json.Unmarshal([]byte(lines[0]), &out); err != nil {
			t.Fatalf("unmarshal stdout %q: %v", lines[0], err)
		}
	}
	return code, out, stdout.String(), stderr.String()
}

func TestAllowCanaryFixture(t *testing.T) {
	code, out, _, stderr := runCLI(
		t,
		[]string{"--policy", fixturePath(t, "allow-canary.yaml")},
		`{"server":"testmcp","tool":"write_canary","arguments":{"content":"CANARY_MCP_PREFLIGHT"}}`,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr)
	}
	if out.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW, got %+v", out)
	}
	if len(out.Reasons) != 1 || out.Reasons[0] != "POLICY_ALLOWED" {
		t.Fatalf("expected reasons [POLICY_ALLOWED], got %v", out.Reasons)
	}
	if len(out.RuleIDs) != 1 || out.RuleIDs[0] != "allow-canary" {
		t.Fatalf("expected rule_ids [allow-canary], got %v", out.RuleIDs)
	}
	if !strings.HasPrefix(out.PolicyDigest, "sha256:") || len(out.PolicyDigest) != 71 {
		t.Fatalf("unexpected policy_digest %q", out.PolicyDigest)
	}
	if !strings.HasPrefix(out.ActionDigest, "sha256:") || len(out.ActionDigest) != 71 {
		t.Fatalf("unexpected action_digest %q", out.ActionDigest)
	}
}

func TestDenyAllFixture(t *testing.T) {
	code, out, _, stderr := runCLI(
		t,
		[]string{"--policy", fixturePath(t, "deny-all.yaml")},
		`{"server":"testmcp","tool":"write_canary","arguments":{"content":"CANARY_MCP_PREFLIGHT"}}`,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr)
	}
	if out.Effect != "BLOCK" {
		t.Fatalf("expected BLOCK, got %+v", out)
	}
	if len(out.Reasons) != 1 || out.Reasons[0] != "POLICY_DENIED" {
		t.Fatalf("expected reasons [POLICY_DENIED], got %v", out.Reasons)
	}
	if len(out.RuleIDs) != 0 {
		t.Fatalf("expected empty rule_ids on default deny, got %v", out.RuleIDs)
	}
	if !strings.HasPrefix(out.PolicyDigest, "sha256:") || len(out.PolicyDigest) != 71 {
		t.Fatalf("unexpected policy_digest %q", out.PolicyDigest)
	}
	if !strings.HasPrefix(out.ActionDigest, "sha256:") || len(out.ActionDigest) != 71 {
		t.Fatalf("unexpected action_digest %q", out.ActionDigest)
	}
}

func TestUnknownToolOrServerBlocks(t *testing.T) {
	cases := []struct {
		name       string
		stdin      string
		wantReason string
	}{
		{
			name:       "unknown-tool",
			stdin:      `{"server":"testmcp","tool":"other_tool","arguments":{"content":"CANARY_MCP_PREFLIGHT"}}`,
			wantReason: "TOOL_REVISION_UNKNOWN",
		},
		{
			name:       "unknown-server",
			stdin:      `{"server":"otherserver","tool":"write_canary","arguments":{"content":"CANARY_MCP_PREFLIGHT"}}`,
			wantReason: "TOOL_REVISION_UNKNOWN",
		},
		{
			name:       "uppercase-tool-selector",
			stdin:      `{"server":"testmcp","tool":"Write_canary","arguments":{"content":"CANARY_MCP_PREFLIGHT"}}`,
			wantReason: "SCHEMA_INVALID",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, _, stderr := runCLI(
				t,
				[]string{"--policy", fixturePath(t, "allow-canary.yaml")},
				tc.stdin,
			)
			if code != 0 {
				t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr)
			}
			if out.Effect != "BLOCK" {
				t.Fatalf("expected BLOCK, got %+v", out)
			}
			if len(out.Reasons) != 1 || out.Reasons[0] != tc.wantReason {
				t.Fatalf("expected reason %q, got %v", tc.wantReason, out.Reasons)
			}
			if out.ActionDigest != "-" {
				t.Fatalf("expected action_digest '-', got %q", out.ActionDigest)
			}
		})
	}
}

// TestMalformedStdinBlocks verifies that malformed stdin inputs produce a decided
// BLOCK JSON line (exit 0) with the kernel's parse/schema/limit reason code, while
// missing CLI flags return a nonzero usage exit code (2).
func TestMalformedStdinBlocks(t *testing.T) {
	cases := []struct {
		name       string
		stdin      string
		wantReason string
	}{
		{
			name:       "empty-stdin",
			stdin:      "",
			wantReason: "PARSE_INVALID",
		},
		{
			name:       "truncated-json",
			stdin:      `{"server":"testmcp"`,
			wantReason: "PARSE_INVALID",
		},
		{
			name:       "trailing-json",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":"x"}}{"extra":1}`,
			wantReason: "PARSE_INVALID",
		},
		{
			name:       "duplicate-top-key",
			stdin:      `{"server":"testmcp","server":"evil","tool":"write_canary","arguments":{"content":"x"}}`,
			wantReason: "PARSE_INVALID",
		},
		{
			name:       "duplicate-arg-key",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":"a","content":"b"}}`,
			wantReason: "PARSE_INVALID",
		},
		{
			name:       "unknown-top-key",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":"x"},"extra":true}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "missing-arguments-key",
			stdin:      `{"server":"testmcp","tool":"write_canary"}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "oversized-stdin",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":"` + strings.Repeat("a", maxStdinBytes) + `"}}`,
			wantReason: "LIMIT_EXCEEDED",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, _, stderr := runCLI(
				t,
				[]string{"--policy", fixturePath(t, "allow-canary.yaml")},
				tc.stdin,
			)
			if code != 0 {
				t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr)
			}
			if out.Effect != "BLOCK" {
				t.Fatalf("expected BLOCK, got %+v", out)
			}
			if len(out.Reasons) != 1 || out.Reasons[0] != tc.wantReason {
				t.Fatalf("expected reason %q, got %v", tc.wantReason, out.Reasons)
			}
			if out.ActionDigest != "-" {
				t.Fatalf("expected action_digest '-', got %q", out.ActionDigest)
			}
		})
	}

	t.Run("missing-policy-flag-exits-nonzero", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run(nil, strings.NewReader(`{}`), &stdout, &stderr)
		if code == 0 {
			t.Fatalf("expected nonzero exit code when --policy is omitted")
		}
	})
}

func TestWrongArgumentTypesAndBoundsBlock(t *testing.T) {
	cases := []struct {
		name       string
		stdin      string
		wantReason string
	}{
		{
			name:       "content-integer",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":123}}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "content-boolean",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":true}}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "content-object",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":{"nested":"x"}}}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "missing-content-field",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{}}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "unexpected-argument-field",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":"x","extra":"y"}}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "arguments-not-object",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":["x"]}`,
			wantReason: "SCHEMA_INVALID",
		},
		{
			name:       "arguments-over-4kib",
			stdin:      `{"server":"testmcp","tool":"write_canary","arguments":{"content":"` + strings.Repeat("a", maxPayloadBytes) + `"}}`,
			wantReason: "LIMIT_EXCEEDED",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, _, stderr := runCLI(
				t,
				[]string{"--policy", fixturePath(t, "allow-canary.yaml")},
				tc.stdin,
			)
			if code != 0 {
				t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr)
			}
			if out.Effect != "BLOCK" {
				t.Fatalf("expected BLOCK, got %+v", out)
			}
			if len(out.Reasons) != 1 || out.Reasons[0] != tc.wantReason {
				t.Fatalf("expected reason %q, got %v", tc.wantReason, out.Reasons)
			}
			if out.ActionDigest != "-" {
				t.Fatalf("expected action_digest '-', got %q", out.ActionDigest)
			}
		})
	}
}

func TestInvalidPolicyFileBlocks(t *testing.T) {
	code, out, _, stderr := runCLI(
		t,
		[]string{"--policy", filepath.Join(t.TempDir(), "nonexistent.yaml")},
		`{"server":"testmcp","tool":"write_canary","arguments":{"content":"CANARY_MCP_PREFLIGHT"}}`,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr)
	}
	if out.Effect != "BLOCK" || len(out.Reasons) != 1 || out.Reasons[0] != "POLICY_UNAVAILABLE" {
		t.Fatalf("expected BLOCK POLICY_UNAVAILABLE, got %+v", out)
	}
	if out.PolicyDigest != "-" || out.ActionDigest != "-" {
		t.Fatalf("expected '-' digests on compile failure, got %+v", out)
	}
}

const shellStdin = `{"kind":"shell","command":["/bin/sh","-c","echo CANARY_PREFLIGHT > /workspace/EXECOBS-ACCEPT.canary"],"cwd":"/workspace"}`

func TestShellFormAllowAndDeny(t *testing.T) {
	_, out, _, _ := runCLI(t, []string{"--policy", fixturePath(t, "allow-canary-shell.yaml")}, shellStdin)
	if out.Effect != "ALLOW" || len(out.RuleIDs) != 1 || out.RuleIDs[0] != "allow-codex-shell" {
		t.Fatalf("expected ALLOW by allow-codex-shell, got %+v", out)
	}
	if !strings.HasPrefix(out.ActionDigest, "sha256:") {
		t.Fatalf("unexpected action_digest %q", out.ActionDigest)
	}
	_, out, _, _ = runCLI(t, []string{"--policy", fixturePath(t, "deny-all.yaml")}, shellStdin)
	if out.Effect != "BLOCK" || len(out.Reasons) != 1 || out.Reasons[0] != "POLICY_DENIED" {
		t.Fatalf("expected BLOCK POLICY_DENIED, got %+v", out)
	}
	// The MCP-only allow policy does not allow shell, and the shell policy does not allow MCP.
	_, out, _, _ = runCLI(t, []string{"--policy", fixturePath(t, "allow-canary.yaml")}, shellStdin)
	if out.Effect != "BLOCK" {
		t.Fatalf("allow-canary must not allow shell, got %+v", out)
	}
	_, out, _, _ = runCLI(t, []string{"--policy", fixturePath(t, "allow-canary-shell.yaml")},
		`{"server":"testmcp","tool":"write_canary","arguments":{"content":"x"}}`)
	if out.Effect != "BLOCK" {
		t.Fatalf("allow-canary-shell must not allow MCP, got %+v", out)
	}
}

func TestShellFormMalformedBlocks(t *testing.T) {
	cases := []string{
		`{"kind":"shell","command":[],"cwd":"/workspace"}`,
		`{"kind":"shell","command":"echo hi","cwd":"/workspace"}`,
		`{"kind":"shell","command":["echo",1],"cwd":"/workspace"}`,
		`{"kind":"shell","command":["echo"],"cwd":""}`,
		`{"kind":"shell","command":["echo"]}`,
		`{"kind":"shell","command":["echo"],"cwd":"/w","extra":1}`,
		`{"kind":"other","command":["echo"],"cwd":"/w"}`,
		`{"kind":"shell","kind":"shell","command":["echo"],"cwd":"/w"}`,
		// The MCP form cannot reach the shell tool by name.
		`{"server":"codex","tool":"exec_command","arguments":{"command":["echo"],"cwd":"/w"}}`,
	}
	for _, in := range cases {
		_, out, _, _ := runCLI(t, []string{"--policy", fixturePath(t, "allow-canary-shell.yaml")}, in)
		if out.Effect != "BLOCK" {
			t.Fatalf("input %s: expected BLOCK, got %+v", in, out)
		}
	}
}

func TestFileWriteForm(t *testing.T) {
	allow := fixturePath(t, "allow-workspace-writes.yaml")
	in := `{"kind":"file_write","changes":[{"path":"/workspace/a.txt","change":"add"},{"path":"/workspace/sub/b.txt","change":"update"}]}`
	_, out, _, _ := runCLI(t, []string{"--policy", allow}, in)
	if out.Effect != "ALLOW" || len(out.RuleIDs) != 1 || out.RuleIDs[0] != "allow-workspace-writes" {
		t.Fatalf("expected ALLOW by allow-workspace-writes, got %+v", out)
	}
	// Any path outside the allowed root blocks the whole change.
	in = `{"kind":"file_write","changes":[{"path":"/workspace/a.txt","change":"add"},{"path":"/etc/passwd","change":"update"}]}`
	_, out, _, _ = runCLI(t, []string{"--policy", allow}, in)
	if out.Effect != "BLOCK" {
		t.Fatalf("expected BLOCK for a path outside /workspace, got %+v", out)
	}
	_, out, _, _ = runCLI(t, []string{"--policy", fixturePath(t, "deny-all.yaml")},
		`{"kind":"file_write","changes":[{"path":"/workspace/a.txt","change":"add"}]}`)
	if out.Effect != "BLOCK" || len(out.Reasons) != 1 || out.Reasons[0] != "POLICY_DENIED" {
		t.Fatalf("expected BLOCK POLICY_DENIED, got %+v", out)
	}
	// Shell and MCP allow policies never allow writes.
	for _, pol := range []string{"allow-canary.yaml", "allow-canary-shell.yaml"} {
		_, out, _, _ = runCLI(t, []string{"--policy", fixturePath(t, pol)},
			`{"kind":"file_write","changes":[{"path":"/workspace/a.txt","change":"add"}]}`)
		if out.Effect != "BLOCK" {
			t.Fatalf("%s must not allow writes, got %+v", pol, out)
		}
	}
	bad := []string{
		`{"kind":"file_write","changes":[]}`,
		`{"kind":"file_write","changes":[{"path":"workspace/a.txt","change":"add"}]}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/../etc/passwd","change":"add"}]}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a.txt","change":"chmod"}]}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a.txt"}]}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a.txt","change":"add","x":1}]}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a.txt","change":"add"}],"extra":1}`,
	}
	for _, in := range bad {
		_, out, _, _ := runCLI(t, []string{"--policy", allow}, in)
		if out.Effect != "BLOCK" {
			t.Fatalf("input %s: expected BLOCK, got %+v", in, out)
		}
	}
}
