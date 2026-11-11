package approval

import (
	"encoding/json"
	"strings"
	"testing"
)

const commandsPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: status
    effect: allow
    match:
      principals: [codex-agent]
      operations: [shell.execute]
      resources: [{kind: command, value: '["git","status"]/**'}]
  - id: cat
    effect: monitor
    match:
      principals: [codex-agent]
      operations: [shell.execute]
      resources: [{kind: command, value: '["cat","notes"]'}]
  - id: delete
    effect: deny
    match:
      principals: [codex-agent]
      operations: [shell.execute]
      resources: [{kind: command, value: '["rm"]/**'}]
`

func shellJSON(script string) []byte {
	raw, _ := json.Marshal(map[string]any{"kind": "shell", "command": []string{"bash", "-lc", script}, "cwd": "/workspace"})
	return raw
}

func TestSpecificCommandsAndHiddenStages(t *testing.T) {
	for _, tc := range []struct{ script, effect string }{
		{"git status", "ALLOW"}, {"git status --short", "ALLOW"}, {"cat notes", "ALLOW"},
		{"git status && cat notes", "ALLOW"}, {"bash -c 'git status'", "ALLOW"},
		{"rm notes", "BLOCK"}, {"git status; rm notes", "BLOCK"}, {"git status || rm notes", "BLOCK"},
		{"git status | rm notes", "BLOCK"}, {"git status && bash -c 'rm notes'", "BLOCK"},
		{"git status $(rm notes)", "BLOCK"}, {"git status > $(rm notes)", "BLOCK"},
		{"git status-bad", "BLOCK"}, {"git log", "BLOCK"}, {"git status; python3 -c 'print(1)'", "BLOCK"},
		{"PATH=/workspace git status", "BLOCK"}, {"/workspace/git status", "BLOCK"},
	} {
		t.Run(tc.script, func(t *testing.T) {
			out := Evaluate([]byte(commandsPolicy), shellJSON(tc.script))
			if out.Effect != tc.effect {
				t.Fatalf("%+v; want %s", out, tc.effect)
			}
		})
	}
	if out := Evaluate([]byte(commandsPolicy), shellJSON("cat notes")); !Monitored(out) {
		t.Fatalf("monitor lost: %+v", out)
	}
	if out := EvaluateWithCatalog([]byte(commandsPolicy), nil, shellJSON("git status"), "agent.other"); out.Effect != "BLOCK" {
		t.Fatal("command grant crossed principals")
	}
}

func TestCommandRulesCannotOverrideWholeShellRestrictions(t *testing.T) {
	for _, effect := range []string{"deny", "require_approval"} {
		pol := commandsPolicy + `  - id: whole-shell
    effect: ` + effect + `
    match: {principals: [codex-agent], operations: [tool.invoke], resources: [{kind: tool, value: codex.exec_command}]}
`
		out := Evaluate([]byte(pol), shellJSON("git status"))
		if out.Effect != "BLOCK" || (effect == "require_approval") != askable(out) {
			t.Fatalf("whole-shell %s lost: %+v", effect, out)
		}
		if out = Evaluate([]byte(pol), shellJSON("git status; rm notes")); out.Effect != "BLOCK" || askable(out) {
			t.Fatalf("delete became approvable: %+v", out)
		}
	}
}

func TestCommandApprovalAndBinding(t *testing.T) {
	pol := strings.Replace(commandsPolicy, "effect: allow", "effect: require_approval", 1)
	allowed := Evaluate([]byte(pol), shellJSON("git status"))
	if !askable(allowed) {
		t.Fatalf("exact command cannot be approved: %+v", allowed)
	}
	if out := Evaluate([]byte(pol), shellJSON("git status; unknown")); askable(out) {
		t.Fatalf("unknown command can be approved: %+v", out)
	}
	other := Evaluate([]byte(pol), shellJSON("bash -c 'git status'"))
	if other.ActionDigest == allowed.ActionDigest {
		t.Fatal("different submitted scripts share the action binding")
	}
}
