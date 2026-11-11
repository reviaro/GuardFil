package webui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/resource"
	"github.com/reviaro/guardfil/internal/shellparse"
)

// The owner edits rules in plain terms: an action (allow, block, monitor, ask
// me) on a target (shell commands, a tool, file writes in a folder, file reads
// in a folder, a website).  Each maps to exactly one policy rule for the agent
// principal.  Anything else in the policy is shown as "custom" and can only be
// changed in the YAML editor.

const agentPrincipal = "codex-agent"

// shellTool is how a native Codex shell command reaches the kernel (see cmd/guardfil-approve).
const shellTool = "codex.exec_command"

var effectLabels = map[string]string{
	"allow": "Allow", "deny": "Block", "monitor": "Monitor", "require_approval": "Ask me", "sanitize": "Filter",
}

var actionEffects = map[string]string{"allow": "allow", "block": "deny", "monitor": "monitor", "ask": "require_approval",
	"filter": "sanitize"}

// RuleView is one rule as the owner sees it.
type RuleView struct {
	ID        string `json:"id"`
	Principal string `json:"principal"`
	Action    string `json:"action"` // Allow | Block | Monitor | Ask me | Filter
	Target    string `json:"target"` // Shell commands | Tool | File writes | File reads | Website | Custom
	Value     string `json:"value"`
	When      string `json:"when,omitempty"` // amount condition, e.g. "quantity × limit_price > 1000"
	Custom    bool   `json:"custom"`
}

// RuleRequest adds or deletes one rule.
type RuleRequest struct {
	Op        string `json:"op"`        // add | delete
	Principal string `json:"principal"` // codex-agent or agent.<name> (add)
	Action    string `json:"action"`    // allow | block | monitor | ask | filter  (add; filter: tool only)
	Target    string `json:"target"`    // shell | tool | files | reads | website  (add)
	Value     string `json:"value"`     // tool name, folder, or URL pattern         (add)
	ID        string `json:"id"`        // rule to delete                           (delete)
	// Optional amount condition for a tool rule: argument (or a*b), operator, amount.
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Amount   string `json:"amount"`
}

// outRule mirrors policy.Rule but omits empty checks when written back.
type outRule struct {
	ID     string       `yaml:"id"`
	Effect string       `yaml:"effect"`
	Match  policy.Match `yaml:"match"`
	Checks []string     `yaml:"checks,omitempty,flow"`
}

type outDoc struct {
	SchemaVersion  int       `yaml:"schema_version"`
	TenantID       string    `yaml:"tenant_id"`
	Revision       uint64    `yaml:"revision"`
	Default        string    `yaml:"default"`
	Rules          []outRule `yaml:"rules"`
	LocalOnlyPaths []string  `yaml:"local_only_paths,omitempty"`
}

func parseDoc(raw []byte) (policy.Document, error) {
	var d policy.Document
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return d, errors.New("the policy cannot be edited as rules (edit the YAML instead)")
	}
	return d, nil
}

func describe(r policy.Rule) RuleView {
	v := RuleView{ID: r.ID, Action: effectLabels[r.Effect], Target: "Custom", Custom: true}
	if v.Action == "" {
		v.Action = r.Effect
	}
	m := r.Match
	if len(m.Principals) == 1 {
		v.Principal = m.Principals[0]
	}
	if len(m.Principals) != 1 || len(m.Operations) != 1 ||
		len(m.Resources) != 1 || len(r.Checks) != 0 {
		v.Value = summarize(r)
		return v
	}
	princ := m.Principals[0]
	if princ != agentPrincipal && !strings.HasPrefix(princ, "agent.") {
		v.Value = summarize(r)
		return v
	}
	v.Principal = princ
	res := m.Resources[0]
	switch {
	case m.Operations[0] == "tool.invoke" && res.Kind == "tool" && res.Value == shellTool:
		v.Target, v.Value = "Shell commands", "all"
	case m.Operations[0] == "shell.execute" && res.Kind == "command":
		v.Target = "Shell command"
		if res.Value == "*" {
			v.Value = "all"
			break
		}
		encoded := strings.TrimSuffix(res.Value, "/**")
		var args []string
		if resource.ValidatePattern("command", res.Value) != nil || json.Unmarshal([]byte(encoded), &args) != nil {
			v.Value = summarize(r)
			return v
		}
		v.Value = shellparse.Display(args)
		if strings.HasSuffix(res.Value, "/**") {
			v.Target = "Shell command prefix"
		}
	case m.Operations[0] == "tool.invoke" && res.Kind == "tool":
		v.Target, v.Value, v.When = "Tool", res.Value, describeWhen(m.Decimal)
	case m.Operations[0] == "filesystem.write" && res.Kind == "path":
		v.Target, v.Value = "File writes", res.Value
	case m.Operations[0] == "filesystem.read" && res.Kind == "path":
		v.Target, v.Value = "File reads", res.Value
	case m.Operations[0] == "http.request" && res.Kind == "url":
		v.Target, v.Value = "Website", res.Value
	default:
		v.Value = summarize(r)
		return v
	}
	v.Custom = false
	return v
}

func describeWhen(preds []policy.DecimalPredicate) string {
	parts := make([]string, 0, len(preds))
	for _, p := range preds {
		parts = append(parts, strings.Join(p.Factors(), " × ")+" "+p.Operator+" "+p.Value)
	}
	return strings.Join(parts, " and ")
}

var amountOperators = map[string]bool{"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true}

// amountCondition builds the rule's optional amount condition from the form.
func amountCondition(req RuleRequest) ([]policy.DecimalPredicate, string, error) {
	field := strings.TrimSpace(req.Field)
	if field == "" && strings.TrimSpace(req.Amount) == "" {
		return nil, "", nil
	}
	if req.Target != "tool" {
		return nil, "", errors.New("an amount condition applies to a tool rule")
	}
	field = strings.NewReplacer("×", "*", " ", "").Replace(field)
	op := strings.TrimSpace(req.Operator)
	amount := strings.TrimSpace(req.Amount)
	p := policy.DecimalPredicate{Field: field, Operator: op, Value: amount}
	switch {
	case !amountField.MatchString(field):
		return nil, "", errors.New("the amount is an argument name, or two multiplied, for example quantity * limit_price")
	case !amountOperators[op]:
		return nil, "", errors.New("the comparison must be >, >=, <, <=, == or !=")
	case !action.ValidDecimal(amount):
		return nil, "", errors.New("the amount is a plain number, for example 1000 or 12.50 (no commas or currency signs)")
	}
	preds := []policy.DecimalPredicate{p}
	return preds, " when " + describeWhen(preds), nil
}

var amountField = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}(\*[a-z][a-z0-9_]{0,63})?$`)

func summarize(r policy.Rule) string {
	var parts []string
	for _, x := range r.Match.Resources {
		parts = append(parts, x.Kind+" "+x.Value)
	}
	s := strings.Join(r.Match.Operations, ",") + " on " + strings.Join(parts, ", ")
	if len(r.Checks) > 0 {
		s += " (checks: " + strings.Join(r.Checks, ",") + ")"
	}
	return s
}

// PlainRules lists the policy's rules in plain terms.
func PlainRules(raw []byte) ([]RuleView, error) {
	d, err := parseDoc(raw)
	if err != nil {
		return []RuleView{}, err
	}
	out := make([]RuleView, 0, len(d.Rules))
	for _, r := range d.Rules {
		out = append(out, describe(r))
	}
	return out, nil
}

var toolName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{1,64}$`)

func targetFor(target, value string) (op string, res policy.Resource, label string, err error) {
	value = strings.TrimSpace(value)
	switch target {
	case "shell":
		return "tool.invoke", policy.Resource{Kind: "tool", Value: shellTool}, "shell commands", nil
	case "command", "command-prefix":
		args, e := shellparse.LiteralCommand(value)
		if e != nil {
			return "", policy.Resource{}, "", errors.New("enter one command, such as git status; quote literal arguments with spaces. Expansions, shell wrappers, redirects and command chains are not supported in a rule")
		}
		encoded, _ := json.Marshal(args)
		selector := string(encoded)
		label = "shell command " + shellparse.Display(args)
		if target == "command-prefix" {
			selector += "/**"
			label += " with any following arguments"
		}
		return "shell.execute", policy.Resource{Kind: "command", Value: selector}, label, nil
	case "tool":
		if value == shellTool || !toolName.MatchString(value) {
			return "", policy.Resource{}, "", errors.New("a tool is named server.tool, for example testmcp.write_canary")
		}
		return "tool.invoke", policy.Resource{Kind: "tool", Value: value}, "tool " + value, nil
	case "files", "reads":
		if !strings.HasPrefix(value, "/") {
			return "", policy.Resource{}, "", errors.New("a folder is an absolute path, for example /workspace/notes")
		}
		if !strings.Contains(value, "*") {
			if trimmed := strings.TrimSuffix(value, "/"); trimmed != "" && path.Clean(trimmed) != trimmed {
				return "", policy.Resource{}, "", errors.New("write the folder without . or .. parts")
			}
			value = strings.TrimSuffix(path.Clean(value), "/") + "/**"
		}
		if resource.ValidatePattern("path", value) != nil {
			return "", policy.Resource{}, "", errors.New("that folder is not a clean absolute path (wildcards: a final /**, or /**/NAME for NAME in any folder below)")
		}
		op, label = "filesystem.write", "file writes in "
		if target == "reads" {
			op, label = "filesystem.read", "file reads in "
		}
		return op, policy.Resource{Kind: "path", Value: value}, label + value, nil
	case "website":
		if resource.ValidatePattern("url", value) != nil {
			return "", policy.Resource{}, "", errors.New("a website is an https URL with a path, for example " +
				"https://example.com/api/** (a whole-site wildcard is not supported yet)")
		}
		return "http.request", policy.Resource{Kind: "url", Value: value}, "website " + value, nil
	}
	return "", policy.Resource{}, "", errors.New("unknown target")
}

func nextID(d policy.Document, action, target string) string {
	used := map[string]bool{}
	for _, r := range d.Rules {
		used[r.ID] = true
	}
	for i := 1; ; i++ {
		id := fmt.Sprintf("ui-%s-%s-%d", action, target, i)
		if !used[id] {
			return id
		}
	}
}

// EditRules applies one add or delete and returns the new policy YAML (revision
// bumped) and a one-line note for the version history.  The caller compiles it.
func EditRules(raw []byte, req RuleRequest) ([]byte, string, error) {
	d, err := parseDoc(raw)
	if err != nil {
		return nil, "", err
	}
	var note string
	switch req.Op {
	case "add":
		effect, ok := actionEffects[req.Action]
		if !ok {
			return nil, "", errors.New("action must be allow, block, monitor, ask or filter")
		}
		if req.Action == "filter" && req.Target != "tool" {
			return nil, "", errors.New("filter applies to a tool: its results have secrets removed before the agent sees them")
		}
		op, res, label, err := targetFor(req.Target, req.Value)
		if err != nil {
			return nil, "", err
		}
		preds, when, err := amountCondition(req)
		if err != nil {
			return nil, "", err
		}
		princ := strings.TrimSpace(req.Principal)
		if princ == "" {
			princ = agentPrincipal
		} else if princ != agentPrincipal && !strings.HasPrefix(princ, "agent.") {
			princ = "agent." + princ
		}
		if princ != agentPrincipal {
			if !strings.HasPrefix(princ, "agent.") || !approval.ValidAgentName(strings.TrimPrefix(princ, "agent.")) {
				return nil, "", errors.New("principal must be codex-agent or agent.<name>")
			}
		}
		id := nextID(d, req.Action, req.Target)
		d.Rules = append(d.Rules, policy.Rule{ID: id, Effect: effect,
			Match: policy.Match{Principals: []string{princ}, Operations: []string{op}, Resources: []policy.Resource{res}, Decimal: preds}})
		forClause := ""
		if princ != agentPrincipal {
			forClause = " for " + princ
		}
		note = fmt.Sprintf("added rule %s: %s %s%s%s", id, effectLabels[effect], label, forClause, when)
	case "delete":
		kept := d.Rules[:0]
		found := false
		for _, r := range d.Rules {
			if r.ID == req.ID {
				found = true
				continue
			}
			kept = append(kept, r)
		}
		if !found {
			return nil, "", errors.New("no rule with that id")
		}
		d.Rules = kept
		note = "deleted rule " + req.ID
	default:
		return nil, "", errors.New("op must be add or delete")
	}
	d.Revision++
	out := outDoc{SchemaVersion: d.SchemaVersion, TenantID: d.TenantID, Revision: d.Revision, Default: d.Default,
		Rules: make([]outRule, 0, len(d.Rules)), LocalOnlyPaths: d.LocalOnlyPaths}
	for _, r := range d.Rules {
		out.Rules = append(out.Rules, outRule{ID: r.ID, Effect: r.Effect, Match: r.Match, Checks: r.Checks})
	}
	b, err := yaml.Marshal(out)
	if err != nil {
		return nil, "", err
	}
	return b, note, nil
}

// PrincipalsInPolicy returns all distinct agent principals in the policy, always including codex-agent.
func PrincipalsInPolicy(raw []byte) []string {
	seen := map[string]bool{agentPrincipal: true}
	list := []string{agentPrincipal}
	d, err := parseDoc(raw)
	if err != nil {
		return list
	}
	for _, r := range d.Rules {
		for _, p := range r.Match.Principals {
			if (p == agentPrincipal || strings.HasPrefix(p, "agent.")) && !seen[p] {
				seen[p] = true
				list = append(list, p)
			}
		}
	}
	sort.Strings(list)
	return list
}
