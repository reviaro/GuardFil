package approval

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const workspacePolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: read-workspace
    effect: allow
    match:
      principals: [codex-agent]
      operations: [filesystem.read]
      resources: [{kind: path, value: /workspace/**}]
  - id: secret
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.read]
      resources: [{kind: path, value: /workspace/secrets/**}]
`

func TestWorkspaceReadRequiresGrant(t *testing.T) {
	for _, tc := range []struct{ name, raw, effect string }{
		{"allowed", `{"kind":"file_read","paths":["/workspace/src/main.go"]}`, "ALLOW"},
		{"secret", `{"kind":"file_read","paths":["/workspace/secrets/token"]}`, "BLOCK"},
		{"batch secret", `{"kind":"file_read","paths":["/workspace/src/main.go","/workspace/secrets/token"]}`, "BLOCK"},
		{"outside", `{"kind":"file_read","paths":["/etc/passwd"]}`, "BLOCK"},
		{"unclean", `{"kind":"file_read","paths":["/workspace/../secrets/token"]}`, "BLOCK"},
		{"empty", `{"kind":"file_read","paths":[]}`, "BLOCK"},
		{"null", `{"kind":"file_read","paths":null}`, "BLOCK"},
		{"invalid path", `{"kind":"file_read","paths":[""]}`, "BLOCK"},
		{"spoof", `{"kind":"file_read","paths":["/workspace/a"],"principal":"codex-agent"}`, "BLOCK"},
		{"duplicate", `{"kind":"file_read","paths":["/workspace/a"],"paths":["/workspace/secrets/token"]}`, "BLOCK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Evaluate([]byte(workspacePolicy), []byte(tc.raw))
			if out.Effect != tc.effect {
				t.Fatalf("got %+v, want %s", out, tc.effect)
			}
		})
	}
	raw := []byte(`{"kind":"file_read","paths":["/workspace/a"]}`)
	if out := EvaluateWithCatalog([]byte(workspacePolicy), nil, raw, "agent.other"); out.Effect != "BLOCK" {
		t.Fatalf("another principal inherited a read grant: %+v", out)
	}
	noReadGrant := strings.Replace(workspacePolicy, "operations: [filesystem.read]", "operations: [filesystem.write]", 1)
	if out := Evaluate([]byte(noReadGrant), raw); out.Effect != "BLOCK" {
		t.Fatalf("unmatched read bypassed default deny: %+v", out)
	}
}

func TestWorkspaceReadLoggedAndFailsOnLogError(t *testing.T) {
	var log bytes.Buffer
	s, err := NewService([]byte(workspacePolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"kind":"file_read","paths":["/workspace/a"]}`)
	if out := s.Decide(raw); out.Effect != "ALLOW" {
		t.Fatalf("%+v", out)
	}
	var entry LogEntry
	if err := json.Unmarshal(log.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Kind != "file_read" || len(entry.Paths) != 1 || entry.Paths[0] != "/workspace/a" {
		t.Fatalf("missing filesystem read log: %+v", entry)
	}
	s.log = workspaceBadLog{}
	if out := s.Decide(raw); out.Effect != "BLOCK" {
		t.Fatalf("unlogged read allowed: %+v", out)
	}
}

type workspaceBadLog struct{}

func (workspaceBadLog) Write([]byte) (int, error) { return 0, nil }
