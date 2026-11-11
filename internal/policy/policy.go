// Package policy compiles the restricted policy YAML into immutable snapshots.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go.yaml.in/yaml/v3"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strings"

	"github.com/reviaro/guardfil/internal/action"
	resourceid "github.com/reviaro/guardfil/internal/resource"
)

var (
	ErrInvalid    = errors.New("POLICY_UNAVAILABLE")
	ErrEvaluation = errors.New("POLICY_EVALUATION_FAILED")
)

type Rule struct {
	ID     string   `yaml:"id"`
	Effect string   `yaml:"effect"`
	Match  Match    `yaml:"match"`
	Checks []string `yaml:"checks,flow"`
}
type Match struct {
	Principals []string           `yaml:"principals"`
	Operations []string           `yaml:"operations"`
	Resources  []Resource         `yaml:"resources"`
	Decimal    []DecimalPredicate `yaml:"decimal,omitempty"`
}

// DecimalPredicate is an amount condition on a tool call's numeric argument,
// or on the product of two (for example quantity*limit_price, an order's
// value).  Value is a quoted decimal literal; comparison is exact.
//
// If the call lacks a named argument the predicate is unknown, and GuardFil
// fails closed: a deny, ask-me or filter rule then matches, an allow or
// monitor rule does not. Treating a missing argument as false would let a
// call without a price skip an ask-me rule, so unknown is closed instead.
type DecimalPredicate struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}
type Resource struct {
	Kind  string `yaml:"kind"`
	Value string `yaml:"value"`
}
type Document struct {
	SchemaVersion int    `yaml:"schema_version"`
	TenantID      string `yaml:"tenant_id"`
	Revision      uint64 `yaml:"revision"`
	Default       string `yaml:"default"`
	Rules         []Rule `yaml:"rules"`
	// LocalOnlyPaths classify data for every principal. They do not grant
	// filesystem access; ordinary allow/deny rules still decide that access.
	LocalOnlyPaths []string `yaml:"local_only_paths,omitempty"`
}
type Snapshot struct {
	tenant         string
	revision       uint64
	digest         string
	rules          []Rule
	localOnlyPaths []string
}
type Input struct{ TenantID, PrincipalID, Operation, ResourceKind, Resource string }
type Result struct {
	Denied               bool
	Allowed              bool
	RequiresApproval     bool
	RequiresSanitization bool
	// SanitizationGrants is true only for a sanitize rule whose predicates are
	// known true. Unknown amounts can impose filtering, but cannot grant a call.
	SanitizationGrants bool
	Checks             []string
	Matched            []string
	DenyRules          []string
	ApprovalRules      []string
	SanitizeRules      []string
	CheckRules         []string
	AllowRules         []string
	// Monitored is set when a matching monitor rule permitted the call: it is
	// allowed (unless something else blocks it) and must be recorded as monitored.
	Monitored    bool
	MonitorRules []string
}

// Compile permits only the bounded closed YAML subset. It rejects aliases,
// duplicate/unknown keys and every non-deny default before publication.
func Compile(raw []byte) (Snapshot, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return Snapshot{}, ErrInvalid
	}
	var n yaml.Node
	d := yaml.NewDecoder(strings.NewReader(string(raw)))
	if d.Decode(&n) != nil || len(n.Content) != 1 || hasBad(&n, 0) || !validShape(n.Content[0]) {
		return Snapshot{}, ErrInvalid
	}
	var trailing yaml.Node
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Snapshot{}, ErrInvalid
	}
	var p Document
	known := yaml.NewDecoder(strings.NewReader(string(raw)))
	known.KnownFields(true)
	if known.Decode(&p) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := known.Decode(&trailing); !errors.Is(err, io.EOF) || p.SchemaVersion != 1 || p.Default != "deny" || !validID(p.TenantID) || p.Revision == 0 || len(p.Rules) > 1000 {
		return Snapshot{}, ErrInvalid
	}
	ids := make(map[string]struct{}, len(p.Rules))
	if len(p.LocalOnlyPaths) > 256 {
		return Snapshot{}, ErrInvalid
	}
	for _, pattern := range p.LocalOnlyPaths {
		if resourceid.ValidatePattern("path", pattern) != nil {
			return Snapshot{}, ErrInvalid
		}
	}
	for _, r := range p.Rules {
		if !validID(r.ID) || !oneOf(r.Effect, "allow", "deny", "require_approval", "sanitize", "monitor") || len(r.Match.Principals) == 0 || len(r.Match.Principals) > 64 || len(r.Match.Operations) == 0 || len(r.Match.Operations) > 64 || len(r.Match.Resources) == 0 || len(r.Match.Resources) > 64 {
			return Snapshot{}, ErrInvalid
		}
		if _, duplicate := ids[r.ID]; duplicate {
			return Snapshot{}, ErrInvalid
		}
		ids[r.ID] = struct{}{}
		for _, principal := range r.Match.Principals {
			if !validID(principal) {
				return Snapshot{}, ErrInvalid
			}
		}
		for _, operation := range r.Match.Operations {
			if !validID(operation) || !resourceid.SecurityOperation(operation) {
				return Snapshot{}, ErrInvalid
			}
			// Such operations have no resource projection yet (model requires an explicitly
			// registered tool resource mapping; no shell projection), so a rule naming
			// them could never match; they become writable when a projection is added.
			if resourceid.KindForSecurityOperation(operation) == "" {
				return Snapshot{}, ErrInvalid
			}
		}
		for _, x := range r.Match.Resources {
			if resourceid.ValidatePattern(x.Kind, x.Value) != nil {
				return Snapshot{}, ErrInvalid
			}
			matched := false
			for _, operation := range r.Match.Operations {
				if resourceid.KindForSecurityOperation(operation) == x.Kind {
					matched = true
					break
				}
			}
			if !matched {
				return Snapshot{}, ErrInvalid
			}
		}
		for _, operation := range r.Match.Operations {
			expectedKind := resourceid.KindForSecurityOperation(operation)
			found := false
			for _, x := range r.Match.Resources {
				if x.Kind == expectedKind {
					found = true
					break
				}
			}
			if !found {
				return Snapshot{}, ErrInvalid
			}
		}
		for _, check := range r.Checks {
			if !validID(check) {
				return Snapshot{}, ErrInvalid
			}
		}
		if r.Match.Decimal != nil && !validDecimalMatch(r.Match) {
			return Snapshot{}, ErrInvalid
		}
	}
	h := sha256.Sum256(raw)
	return Snapshot{p.TenantID, p.Revision, "sha256:" + hex.EncodeToString(h[:]), append([]Rule(nil), p.Rules...), append([]string(nil), p.LocalOnlyPaths...)}, nil
}

func (s Snapshot) LocalOnly(path string) bool {
	for _, pattern := range s.localOnlyPaths {
		if resourceid.Match("path", pattern, path) {
			return true
		}
	}
	return false
}

// PrivacyVersion changes whenever the owner's data classification changes.
// Empty means no paths are classified local-only.
func (s Snapshot) PrivacyVersion() string {
	if len(s.localOnlyPaths) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(strings.Join(s.localOnlyPaths, "\x00")))
	return hex.EncodeToString(h[:])
}
func keysOnly(n *yaml.Node, allowed ...string) bool {
	if n == nil {
		return false
	}
	if n.Kind != yaml.MappingNode {
		return false
	}
	ok := map[string]bool{}
	for _, k := range allowed {
		ok[k] = true
	}
	for i := 0; i < len(n.Content); i += 2 {
		if !ok[n.Content[i].Value] {
			return false
		}
	}
	return true
}

func validShape(root *yaml.Node) bool {
	if !keysOnly(root, "schema_version", "tenant_id", "revision", "default", "rules", "local_only_paths") {
		return false
	}
	if local := mappingValue(root, "local_only_paths"); local != nil {
		if local.Kind != yaml.SequenceNode {
			return false
		}
		for _, p := range local.Content {
			if p.Kind != yaml.ScalarNode || p.Tag != "!!str" {
				return false
			}
		}
	}
	rules := mappingValue(root, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	for _, rule := range rules.Content {
		if !keysOnly(rule, "id", "effect", "match", "checks") {
			return false
		}
		match := mappingValue(rule, "match")
		if !keysOnly(match, "principals", "operations", "resources", "decimal") {
			return false
		}
		if preds := mappingValue(match, "decimal"); preds != nil {
			if preds.Kind != yaml.SequenceNode {
				return false
			}
			for _, p := range preds.Content {
				// The amount must be a quoted string, so YAML never picks a numeric type.
				if v := mappingValue(p, "value"); !keysOnly(p, "field", "operator", "value") || v == nil ||
					v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
					return false
				}
			}
		}
		resources := mappingValue(match, "resources")
		if resources == nil || resources.Kind != yaml.SequenceNode {
			return false
		}
		for _, resource := range resources.Content {
			if !keysOnly(resource, "kind", "value") {
				return false
			}
		}
	}
	return true
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func hasBad(n *yaml.Node, depth int) bool {
	if depth > 16 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag != "" && n.Tag != "!!map" && n.Tag != "!!seq" && n.Tag != "!!str" && n.Tag != "!!int" && n.Tag != "!!bool" && n.Tag != "!!null" {
		return true
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Value == "<<" || seen[k.Value] {
				return true
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if hasBad(c, depth+1) {
			return true
		}
	}
	return false
}
func oneOf(s string, x ...string) bool {
	for _, z := range x {
		if s == z {
			return true
		}
	}
	return false
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') || i == 0 && !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (s Snapshot) Digest() string   { return s.digest }
func (s Snapshot) Revision() uint64 { return s.revision }

// Evaluate exhaustively applies deny-first semantics; rule order cannot alter a deny.
// Amount conditions see no arguments here, so they are unknown (fail closed).
func (s Snapshot) Evaluate(in Input) (Result, error) { return s.EvaluateArgs(in, nil) }

// EvaluateArgs is Evaluate with the call's top-level numeric arguments, as
// exact decimal tokens, for amount conditions.
func (s Snapshot) EvaluateArgs(in Input, numbers map[string]string) (Result, error) {
	if in.TenantID != s.tenant {
		return Result{Denied: true}, nil
	}
	r := Result{}
	for _, rule := range s.rules {
		if matches(rule, in, numbers) {
			r.Matched = append(r.Matched, rule.ID)
			switch rule.Effect {
			case "deny":
				r.Denied = true
				r.DenyRules = append(r.DenyRules, rule.ID)
			case "allow":
				r.Allowed = true
				r.AllowRules = append(r.AllowRules, rule.ID)
			case "require_approval":
				r.RequiresApproval = true
				r.ApprovalRules = append(r.ApprovalRules, rule.ID)
			case "sanitize":
				r.RequiresSanitization = true
				r.SanitizeRules = append(r.SanitizeRules, rule.ID)
				known := true
				for _, p := range rule.Match.Decimal {
					if p.eval(numbers) != predTrue {
						known = false
					}
				}
				r.SanitizationGrants = r.SanitizationGrants || known
			case "monitor":
				r.Monitored = true
				r.MonitorRules = append(r.MonitorRules, rule.ID)
			}
			if len(rule.Checks) > 0 {
				r.CheckRules = append(r.CheckRules, rule.ID)
				r.Checks = append(r.Checks, rule.Checks...)
			}
		}
	}
	sort.Strings(r.Checks)
	r.Checks = unique(r.Checks)
	sort.Strings(r.DenyRules)
	r.DenyRules = unique(r.DenyRules)
	sort.Strings(r.ApprovalRules)
	r.ApprovalRules = unique(r.ApprovalRules)
	sort.Strings(r.SanitizeRules)
	r.SanitizeRules = unique(r.SanitizeRules)
	sort.Strings(r.CheckRules)
	r.CheckRules = unique(r.CheckRules)
	sort.Strings(r.AllowRules)
	r.AllowRules = unique(r.AllowRules)
	sort.Strings(r.MonitorRules)
	r.MonitorRules = unique(r.MonitorRules)
	// A monitor rule permits like allow; every blocking effect still wins over it.
	r.Allowed = (r.Allowed || r.Monitored) && !(r.Denied || r.RequiresApproval || r.RequiresSanitization || len(r.Checks) > 0)
	if !r.Allowed {
		r.Monitored = false
	}
	return r, nil
}
func matches(rule Rule, in Input, numbers map[string]string) bool {
	m := rule.Match
	if !(contains(m.Principals, in.PrincipalID) && contains(m.Operations, in.Operation) && resourceMatch(m.Resources, in.ResourceKind, in.Resource)) {
		return false
	}
	for _, p := range m.Decimal {
		switch p.eval(numbers) {
		case predFalse:
			return false
		case predUnknown:
			// Fail closed: an unknown amount triggers restrictions, never grants.
			if rule.Effect == "allow" || rule.Effect == "monitor" {
				return false
			}
		}
	}
	return true
}

const maxDecimalPredicates = 16

const (
	predFalse = iota
	predTrue
	predUnknown
)

var decimalField = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}(\*[a-z][a-z0-9_]{0,63})?$`)

func validDecimalMatch(m Match) bool {
	if len(m.Decimal) == 0 || len(m.Decimal) > maxDecimalPredicates {
		return false
	}
	// Amount conditions apply to tool arguments only.
	for _, op := range m.Operations {
		if op != "tool.invoke" {
			return false
		}
	}
	for _, p := range m.Decimal {
		if !decimalField.MatchString(p.Field) || !oneOf(p.Operator, "==", "!=", "<", "<=", ">", ">=") || !action.ValidDecimal(p.Value) {
			return false
		}
	}
	return true
}

// Factors are the argument names a predicate's field multiplies (one or two).
func (p DecimalPredicate) Factors() []string { return strings.Split(p.Field, "*") }

func (p DecimalPredicate) eval(numbers map[string]string) int {
	product := new(big.Rat).SetInt64(1)
	for _, f := range p.Factors() {
		tok, ok := numbers[f]
		if !ok || !action.ValidDecimal(tok) {
			return predUnknown
		}
		x, ok := new(big.Rat).SetString(tok)
		if !ok {
			return predUnknown
		}
		product.Mul(product, x)
	}
	limit, ok := new(big.Rat).SetString(p.Value)
	if !ok {
		return predUnknown
	}
	c := product.Cmp(limit)
	var r bool
	switch p.Operator {
	case "==":
		r = c == 0
	case "!=":
		r = c != 0
	case "<":
		r = c < 0
	case "<=":
		r = c <= 0
	case ">":
		r = c > 0
	case ">=":
		r = c >= 0
	}
	if r {
		return predTrue
	}
	return predFalse
}

// ToolField is a tool argument a decimal predicate names.
type ToolField struct{ Rule, Tool, Field string }

// DecimalFields lists, for every rule with amount conditions, each tool it
// names and each argument its predicates use, so the caller can check them
// against the tool catalog.
func (s Snapshot) DecimalFields() []ToolField {
	var out []ToolField
	for _, r := range s.rules {
		for _, res := range r.Match.Resources {
			if res.Kind != "tool" {
				continue
			}
			for _, p := range r.Match.Decimal {
				for _, f := range p.Factors() {
					out = append(out, ToolField{r.ID, res.Value, f})
				}
			}
		}
	}
	return out
}
func contains(a []string, x string) bool {
	for _, z := range a {
		if z == x {
			return true
		}
	}
	return false
}
func resourceMatch(rs []Resource, kind, x string) bool {
	for _, r := range rs {
		if r.Kind == kind && resourceid.Match(kind, r.Value, x) {
			return true
		}
	}
	return false
}
func unique(a []string) []string {
	if len(a) == 0 {
		return nil
	}
	o := a[:1]
	for _, x := range a[1:] {
		if x != o[len(o)-1] {
			o = append(o, x)
		}
	}
	return o
}
