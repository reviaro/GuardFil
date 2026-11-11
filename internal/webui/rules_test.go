package webui

import (
	"os"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/policy"
)

const basePolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-codex-shell
    effect: allow
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: codex.exec_command
  - id: odd
    effect: allow
    match:
      principals: [someone-else]
      operations: [filesystem.write]
      resources:
        - kind: path
          value: /tmp/**
`

func TestCommandFormChangesRuntimeAuthority(t *testing.T) {
	for _, target := range []string{"command", "command-prefix"} {
		raw, _, err := EditRules([]byte(basePolicy), RuleRequest{Op: "add", Target: target, Action: "allow", Value: "git status"})
		if err != nil {
			t.Fatal(err)
		}
		views, err := PlainRules(raw)
		if err != nil || views[len(views)-1].Custom || views[len(views)-1].Value != "git status" {
			t.Fatalf("command view: %+v %v", views, err)
		}
		for _, tc := range []struct {
			request string
			allow   bool
		}{
			{`{"kind":"shell","command":["bash","-c","git status"],"cwd":"/workspace"}`, true},
			{`{"kind":"shell","command":["bash","-c","git status --short"],"cwd":"/workspace"}`, target == "command-prefix"},
			{`{"kind":"shell","command":["bash","-c","git status; rm notes"],"cwd":"/workspace"}`, false},
			{`{"kind":"shell","command":["bash","-c","git status-extra"],"cwd":"/workspace"}`, false},
		} {
			result := approval.Evaluate(raw, []byte(tc.request))
			if (result.Effect == "ALLOW") != tc.allow {
				t.Fatalf("%s %s: %+v", target, tc.request, result)
			}
		}
	}
}

func TestPlainRules(t *testing.T) {
	rules, err := PlainRules([]byte(basePolicy))
	if err != nil || len(rules) != 2 {
		t.Fatalf("%v %+v", err, rules)
	}
	if r := rules[0]; r.Action != "Allow" || r.Target != "Shell commands" || r.Custom {
		t.Fatalf("shell rule: %+v", r)
	}
	if r := rules[1]; !r.Custom || r.Target != "Custom" || !strings.Contains(r.Value, "/tmp/**") {
		t.Fatalf("custom rule: %+v", r)
	}
}

func TestEditRulesAddDeleteCompile(t *testing.T) {
	raw := []byte(basePolicy)
	adds := []RuleRequest{
		{Op: "add", Action: "block", Target: "files", Value: "/workspace/secret/"},
		{Op: "add", Action: "monitor", Target: "tool", Value: "testmcp.write_canary"},
		{Op: "add", Action: "ask", Target: "shell"},
		{Op: "add", Action: "allow", Target: "reads", Value: "/workspace/docs"},
		{Op: "add", Action: "block", Target: "website", Value: "https://example.com/api/**"},
		{Op: "add", Action: "block", Target: "files", Value: "/workspace/other"},
	}
	for _, req := range adds {
		next, note, err := EditRules(raw, req)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		if _, err := policy.Compile(next); err != nil {
			t.Fatalf("%+v produced an invalid policy: %v\n%s", req, err, next)
		}
		if note == "" {
			t.Fatal("no note")
		}
		raw = next
	}
	rules, _ := PlainRules(raw)
	if len(rules) != 8 {
		t.Fatalf("rules: %+v", rules)
	}
	want := map[string][3]string{
		"ui-block-files-1":   {"Block", "File writes", "/workspace/secret/**"},
		"ui-monitor-tool-1":  {"Monitor", "Tool", "testmcp.write_canary"},
		"ui-ask-shell-1":     {"Ask me", "Shell commands", "all"},
		"ui-allow-reads-1":   {"Allow", "File reads", "/workspace/docs/**"},
		"ui-block-website-1": {"Block", "Website", "https://example.com/api/**"},
		"ui-block-files-2":   {"Block", "File writes", "/workspace/other/**"},
		"allow-codex-shell":  {"Allow", "Shell commands", "all"},
	}
	for _, r := range rules {
		if w, ok := want[r.ID]; ok && (r.Action != w[0] || r.Target != w[1] || r.Value != w[2]) {
			t.Fatalf("%s: %+v", r.ID, r)
		}
	}
	if !strings.Contains(string(raw), "revision: 7") {
		t.Fatalf("revision not bumped:\n%s", raw)
	}
	raw, note, err := EditRules(raw, RuleRequest{Op: "delete", ID: "ui-ask-shell-1"})
	if err != nil || note != "deleted rule ui-ask-shell-1" {
		t.Fatal(err)
	}
	if rules, _ = PlainRules(raw); len(rules) != 7 {
		t.Fatalf("after delete: %d", len(rules))
	}
	if _, err := policy.Compile(raw); err != nil {
		t.Fatal(err)
	}
	// The custom rule survives edits unchanged.
	if !strings.Contains(string(raw), "someone-else") {
		t.Fatal("custom rule lost")
	}
}

func TestEditRulesRejectsBadInput(t *testing.T) {
	for _, req := range []RuleRequest{
		{Op: "add", Action: "permit", Target: "shell"},
		{Op: "add", Action: "allow", Target: "tool", Value: "codex.exec_command"},
		{Op: "add", Action: "allow", Target: "tool", Value: "no-dot"},
		{Op: "add", Action: "allow", Target: "files", Value: "relative/dir"},
		{Op: "add", Action: "allow", Target: "website", Value: "example.com"},
		{Op: "add", Action: "allow", Target: "website", Value: "http://example.com/api/**"},
		{Op: "add", Action: "allow", Target: "files", Value: "/workspace/../etc"},
		{Op: "add", Action: "allow", Target: "printer"},
		{Op: "delete", ID: "missing"},
		{Op: "rename"},
	} {
		if _, _, err := EditRules([]byte(basePolicy), req); err == nil {
			t.Errorf("%+v accepted", req)
		}
	}
	if _, _, err := EditRules([]byte("schema_version: 1\nextra: x\n"), RuleRequest{Op: "add", Action: "allow", Target: "shell"}); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestAmountRule(t *testing.T) {
	raw, note, err := EditRules([]byte(basePolicy), RuleRequest{Op: "add", Action: "ask", Target: "tool",
		Value: "stockapp.place_order", Field: "quantity × limit_price", Operator: ">", Amount: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "when quantity × limit_price > 1000") {
		t.Fatal(note)
	}
	if _, err := policy.Compile(raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), `value: "1000"`) {
		t.Fatalf("amount must stay a quoted string:\n%s", raw)
	}
	rules, _ := PlainRules(raw)
	r := rules[len(rules)-1]
	if r.Custom || r.Action != "Ask me" || r.Value != "stockapp.place_order" || r.When != "quantity × limit_price > 1000" {
		t.Fatalf("%+v", r)
	}
	for _, bad := range []RuleRequest{
		{Field: "quantity", Operator: ">", Amount: "1,000"},
		{Field: "quantity", Operator: ">", Amount: "$5"},
		{Field: "quantity", Operator: "=>", Amount: "5"},
		{Field: "a*b*c", Operator: ">", Amount: "5"},
		{Field: "quantity", Operator: ">", Amount: "5", Target: "shell"},
	} {
		bad.Op, bad.Action, bad.Value = "add", "ask", "stockapp.place_order"
		if bad.Target == "" {
			bad.Target = "tool"
		}
		if _, _, err := EditRules([]byte(basePolicy), bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestFilterRule(t *testing.T) {
	raw, note, err := EditRules([]byte(basePolicy), RuleRequest{Op: "add", Action: "filter", Target: "tool", Value: "notes.read_note"})
	if err != nil || !strings.Contains(note, "Filter tool notes.read_note") {
		t.Fatal(err, note)
	}
	if _, err := policy.Compile(raw); err != nil {
		t.Fatal(err)
	}
	rules, _ := PlainRules(raw)
	if r := rules[len(rules)-1]; r.Action != "Filter" || r.Target != "Tool" || r.Custom {
		t.Fatalf("%+v", r)
	}
	if _, _, err := EditRules([]byte(basePolicy), RuleRequest{Op: "add", Action: "filter", Target: "files", Value: "/w"}); err == nil {
		t.Fatal("filter on files accepted")
	}
}

func TestRulePrincipalSupport(t *testing.T) {
	raw := []byte(basePolicy)
	// Initially only codex-agent
	princs := PrincipalsInPolicy(raw)
	if len(princs) != 1 || princs[0] != "codex-agent" {
		t.Fatalf("initial principals: %v", princs)
	}

	// Add rule for agent.notes-bot
	raw2, note, err := EditRules(raw, RuleRequest{
		Op:        "add",
		Action:    "allow",
		Target:    "shell",
		Principal: "agent.notes-bot",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "for agent.notes-bot") {
		t.Fatalf("note missing principal: %s", note)
	}

	// Now PrincipalsInPolicy includes both
	princs2 := PrincipalsInPolicy(raw2)
	if len(princs2) != 2 || princs2[0] != "agent.notes-bot" || princs2[1] != "codex-agent" {
		t.Fatalf("principals after add: %v", princs2)
	}

	// PlainRules describes the rule with principal
	rules, err := PlainRules(raw2)
	if err != nil {
		t.Fatal(err)
	}
	last := rules[len(rules)-1]
	if last.Principal != "agent.notes-bot" || last.Custom {
		t.Fatalf("rule view: %+v", last)
	}

	// Adding with invalid principal is rejected
	for _, bad := range []string{"InvalidPrincipal", "agent.BAD/NAME", "agent." + strings.Repeat("a", 57)} {
		if _, _, err := EditRules(raw, RuleRequest{
			Op:        "add",
			Action:    "allow",
			Target:    "shell",
			Principal: bad,
		}); err == nil {
			t.Fatalf("bad principal %q accepted", bad)
		}
	}
}

// The starter policy's host-run-file blocks show as plain rules the owner
// can delete one by one.
func TestStarterHostRunBlocksArePlainAndDeletable(t *testing.T) {
	raw, err := os.ReadFile("../../deployments/local/starter-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := PlainRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rules {
		if strings.HasPrefix(r.ID, "block-host-run-") {
			n++
			if r.Custom || r.Action != "Block" || r.Target != "File writes" {
				t.Errorf("%+v", r)
			}
		}
	}
	if n == 0 {
		t.Fatal("no host-run blocks in the starter policy")
	}
	out, _, err := EditRules(raw, RuleRequest{Op: "delete", ID: "block-host-run-vscode"})
	if err != nil || strings.Contains(string(out), "block-host-run-vscode") || !strings.Contains(string(out), "block-host-run-git") {
		t.Fatalf("delete one: %v", err)
	}
}

func TestAddAnyFolderRule(t *testing.T) {
	out, _, err := EditRules([]byte(basePolicy), RuleRequest{Op: "add", Action: "block", Target: "files", Value: "/workspace/**/.envrc"})
	if err != nil || !strings.Contains(string(out), "/workspace/**/.envrc") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if _, _, err := EditRules([]byte(basePolicy), RuleRequest{Op: "add", Action: "block", Target: "files", Value: "/workspace/**/*.env"}); err == nil {
		t.Fatal("accepted a wildcard name")
	}
}
