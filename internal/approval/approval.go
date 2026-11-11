// Package approval decides native agent approval requests (MCP tool calls, shell
// commands, file writes) with GuardFil's policy kernel.  It is used by the
// guardfil-approve CLI (one request per process) and by the guardfil approval
// service (Unix socket, one request per connection).
//
// Boundary note: action.Registry.Context in the P1.2 kernel rejects
// action.ExecutionGateway with ErrSchema (dispatch capability receipts are
// deferred to P1.4), so this bridge uses action.Advisory — the same boundary
// used by internal/advisorydemo/demo.go.
package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/identity"
	"github.com/reviaro/guardfil/internal/policy"
)

const (
	canaryToolID      = "testmcp.write_canary"
	shellToolID       = "codex.exec_command"
	maxShellArgs      = 64
	maxWritePaths     = 16
	fsWriteOperation  = "fs.write"
	fsWriteRouteID    = "route-fs-write"
	fsReadOperation   = "fs.read"
	fsReadRouteID     = "route-fs-read"
	commandRouteID    = "route-shell-command"
	toolRouteID       = "route-tool-invoke"
	canaryOperation   = "tool.invoke"
	syntheticTenant   = "synthetic"
	syntheticPrinc    = "codex-agent"
	syntheticResource = "canary"
	syntheticSecret   = "0123456789012345678901234567890123456789012"
	credentialWindow  = 24 * time.Hour
	MaxRequestBytes   = 64 * 1024
	MaxPayloadBytes   = 4 * 1024
	authorizeTimeout  = 500 * time.Millisecond
	failClosedReason  = "INTERNAL_ERROR"
)

var canarySchema = action.Schema{
	Fields: map[string]action.FieldType{
		"content": action.String,
	},
}

// shellSchema carries a native Codex builtin command approval.  P1.2's kernel has no
// resource selector for shell.execute (NormalizeAction returns ErrSchema), so a shell
// approval is evaluated as tool.invoke of the registered tool codex.exec_command.
var shellSchema = action.Schema{
	Fields: map[string]action.FieldType{
		"cwd": action.String,
	},
	RecursiveFields: map[string]action.Field{
		"command": {Type: action.Array, Items: &action.Field{Type: action.String}},
	},
}

type approveClock struct {
	now time.Time
}

func (c approveClock) Now() time.Time {
	return c.now
}

type approveIDSource struct {
	id string
}

func (s approveIDSource) NewID() (string, error) {
	return s.id, nil
}

// Output is the single-line JSON verdict for every decided outcome.
type Output struct {
	Effect       string   `json:"effect"`
	Reasons      []string `json:"reasons"`
	RuleIDs      []string `json:"rule_ids"`
	PolicyDigest string   `json:"policy_digest"`
	ActionDigest string   `json:"action_digest"`
	// Filter is set on an ALLOW with a filter obligation (sanitize rules): the
	// caller must pass the call's result through GuardFil's filter.  Only
	// requests that declare "can_filter": true get one; others are blocked.
	Filter []string `json:"filter,omitempty"`
}

type approvalInput struct {
	Server    string
	Tool      string
	Arguments []byte
	Shell     bool
	// WritePaths is set for {"kind":"file_write"}: each path is authorized as fs.write.
	WritePaths []string
	WriteKinds []string
	// ReadPaths are actual filesystem reads submitted by the workspace mediator.
	// Unlike the legacy tool-read check, they require an explicit policy grant.
	ReadPaths []string
	// CanFilter: the caller filters the result if a sanitize rule applies.
	CanFilter bool
}

// fs.read payload: the tool that reads (read, grep, glob, ls).
var fsReadSchema = action.Schema{Fields: map[string]action.FieldType{"tool": action.String}}

var commandSchema = action.Schema{Fields: map[string]action.FieldType{"cwd": action.String}}

var fsWriteSchema = action.Schema{
	Fields: map[string]action.FieldType{
		"change": action.String,
	},
}

func buildActionRegistry(cat *Catalog) (*action.Registry, error) {
	profiles := []action.Profile{
		{
			Protocol:        "decision_api",
			ProfileID:       "synthetic-profile",
			AdapterRevision: "sha256:" + strings.Repeat("0", 64),
		},
	}
	tools := []action.Tool{
		{
			ToolID:        canaryToolID,
			UpstreamID:    "up-testmcp-write-canary",
			UpstreamName:  canaryToolID,
			PayloadSchema: "ps-testmcp-write-canary",
			Schema:        canarySchema,
		},
		{
			ToolID:        shellToolID,
			UpstreamID:    "up-codex-exec-command",
			UpstreamName:  shellToolID,
			PayloadSchema: "ps-codex-exec-command",
			Schema:        shellSchema,
		},
	}
	routeTools := []string{canaryToolID, shellToolID}
	for _, t := range cat.Tools() {
		tools = append(tools, action.Tool{
			ToolID:        t.ID,
			UpstreamID:    "up-catalog-" + t.ID,
			UpstreamName:  t.ID,
			PayloadSchema: "ps-catalog-" + t.ID,
			Schema:        cat.schema(t.ID),
		})
		routeTools = append(routeTools, t.ID)
	}
	routes := []action.Route{
		{
			RouteID: commandRouteID, ExecutorID: "synthetic-executor", Operation: "shell.execute",
			ResolutionProfile: "synthetic-profile", PayloadSchema: "ps-shell-command", Schema: commandSchema,
		},
		{
			RouteID:           "route-tool-invoke",
			ExecutorID:        "synthetic-executor",
			Operation:         canaryOperation,
			ResolutionProfile: "synthetic-profile",
			Tools:             routeTools,
		},
		{
			RouteID:           fsWriteRouteID,
			ExecutorID:        "synthetic-executor",
			Operation:         fsWriteOperation,
			ResolutionProfile: "synthetic-profile",
			PayloadSchema:     "ps-fs-write",
			Schema:            fsWriteSchema,
		},
		{
			RouteID:           fsReadRouteID,
			ExecutorID:        "synthetic-executor",
			Operation:         fsReadOperation,
			ResolutionProfile: "synthetic-profile",
			PayloadSchema:     "ps-fs-read",
			Schema:            fsReadSchema,
		},
	}
	return action.NewRegistry(profiles, routes, tools, nil)
}

func buildIdentityRegistry(now time.Time, cat *Catalog, principal ...string) (*identity.Registry, error) {
	princ := syntheticPrinc
	if len(principal) > 0 && principal[0] != "" {
		princ = principal[0]
	}
	key := bytes.Repeat([]byte{0x53}, 32)
	credentials := []identity.Credential{
		{
			ID:          "synthetic-credential",
			TenantID:    syntheticTenant,
			PrincipalID: princ,
			Audience:    "data",
			Scopes: []identity.Scope{
				{Operation: canaryOperation, ResourceSet: syntheticResource},
				// The credential ceiling covers every path; the policy decides which writes are allowed.
				{Operation: "filesystem.write", ResourceSet: "any-path"},
				{Operation: "filesystem.read", ResourceSet: "any-path"},
				{Operation: "shell.execute", ResourceSet: "any-command"},
			},
			IssuedAt:  now.Add(-credentialWindow),
			ExpiresAt: now.Add(credentialWindow),
			Revision:  1,
			Verifier:  identity.Verifier(key, []byte(syntheticSecret)),
		},
	}
	toolSet := []identity.Resource{
		{Kind: "tool", Value: canaryToolID},
		{Kind: "tool", Value: shellToolID},
	}
	for _, t := range cat.Tools() {
		toolSet = append(toolSet, identity.Resource{Kind: "tool", Value: t.ID})
	}
	resourceSets := map[string][]identity.Resource{
		syntheticResource: toolSet,
		"any-path": {
			{Kind: "path", Value: "/**"},
		},
		"any-command": {{Kind: "command", Value: "*"}},
	}
	return identity.NewRegistryWithResourceSets(key, credentials, resourceSets)
}

// BlockedOutput is the fail-closed verdict used when no decision could be made.
func BlockedOutput(reason, policyDigest, actionDigest string, ruleIDs []string) Output {
	if reason == "" {
		reason = failClosedReason
	}
	if policyDigest == "" {
		policyDigest = "-"
	}
	if actionDigest == "" {
		actionDigest = "-"
	}
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	return Output{
		Effect:       string(decision.BLOCK),
		Reasons:      []string{reason},
		RuleIDs:      ruleIDs,
		PolicyDigest: policyDigest,
		ActionDigest: actionDigest,
	}
}

func checkNoDuplicateKeys(d *json.Decoder, depth int) error {
	if depth > 32 {
		return action.ErrLimit
	}
	t, err := d.Token()
	if err != nil {
		return action.ErrParse
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return action.ErrParse
			}
			ks, ok := kt.(string)
			if !ok {
				return action.ErrParse
			}
			if _, dup := seen[ks]; dup {
				return action.ErrParse
			}
			seen[ks] = struct{}{}
			if err := checkNoDuplicateKeys(d, depth+1); err != nil {
				return err
			}
		}
		if _, err := d.Token(); err != nil {
			return action.ErrParse
		}
	case '[':
		for d.More() {
			if err := checkNoDuplicateKeys(d, depth+1); err != nil {
				return err
			}
		}
		if _, err := d.Token(); err != nil {
			return action.ErrParse
		}
	}
	return nil
}

func parseStdinRequest(raw []byte) (approvalInput, error) {
	if len(raw) > MaxRequestBytes {
		return approvalInput{}, action.ErrLimit
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || !utf8.Valid(raw) || !json.Valid(raw) {
		return approvalInput{}, action.ErrParse
	}
	if trimmed[0] != '{' {
		return approvalInput{}, action.ErrSchema
	}

	dupDec := json.NewDecoder(bytes.NewReader(raw))
	dupDec.UseNumber()
	if err := checkNoDuplicateKeys(dupDec, 0); err != nil {
		return approvalInput{}, err
	}
	if dupDec.More() {
		return approvalInput{}, action.ErrParse
	}
	if _, err := dupDec.Token(); err != io.EOF {
		return approvalInput{}, action.ErrParse
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return approvalInput{}, action.ErrParse
	}
	if rawKind, hasKind := top["kind"]; hasKind {
		var kind string
		if err := json.Unmarshal(rawKind, &kind); err != nil {
			return approvalInput{}, action.ErrSchema
		}
		if kind == "file_write" {
			return parseFileWriteRequest(top)
		}
		if kind == "file_read" {
			return parseFileReadRequest(top)
		}
		return parseShellRequest(top)
	}
	canFilter := false
	if raw, ok := top["can_filter"]; ok {
		if string(bytes.TrimSpace(raw)) != "true" {
			return approvalInput{}, action.ErrSchema
		}
		canFilter = true
	}
	if len(top) != 3 && !(canFilter && len(top) == 4) {
		return approvalInput{}, action.ErrSchema
	}
	rawServer, okServer := top["server"]
	rawTool, okTool := top["tool"]
	rawArgs, okArgs := top["arguments"]
	if !okServer || !okTool || !okArgs {
		return approvalInput{}, action.ErrSchema
	}

	var server string
	if err := json.Unmarshal(rawServer, &server); err != nil {
		return approvalInput{}, action.ErrSchema
	}
	var tool string
	if err := json.Unmarshal(rawTool, &tool); err != nil {
		return approvalInput{}, action.ErrSchema
	}
	argsTrimmed := bytes.TrimSpace(rawArgs)
	if len(argsTrimmed) == 0 || argsTrimmed[0] != '{' {
		return approvalInput{}, action.ErrSchema
	}
	if server == "" || tool == "" || strings.Contains(server, ".") || strings.Contains(tool, ".") {
		return approvalInput{}, action.ErrSchema
	}

	return approvalInput{
		Server:    server,
		Tool:      tool,
		Arguments: argsTrimmed,
		CanFilter: canFilter,
	}, nil
}

// parseShellRequest accepts exactly {"kind":"shell","command":[argv...],"cwd":str}.
func parseShellRequest(top map[string]json.RawMessage) (approvalInput, error) {
	if len(top) != 3 {
		return approvalInput{}, action.ErrSchema
	}
	var kind, cwd string
	var argv []string
	if err := json.Unmarshal(top["kind"], &kind); err != nil || kind != "shell" {
		return approvalInput{}, action.ErrSchema
	}
	rawCmd, okCmd := top["command"]
	rawCwd, okCwd := top["cwd"]
	if !okCmd || !okCwd {
		return approvalInput{}, action.ErrSchema
	}
	if t := bytes.TrimSpace(rawCmd); len(t) == 0 || t[0] != '[' {
		return approvalInput{}, action.ErrSchema
	}
	if err := json.Unmarshal(rawCmd, &argv); err != nil || len(argv) == 0 || len(argv) > maxShellArgs {
		return approvalInput{}, action.ErrSchema
	}
	if err := json.Unmarshal(rawCwd, &cwd); err != nil || cwd == "" {
		return approvalInput{}, action.ErrSchema
	}
	payload, err := json.Marshal(struct {
		Command []string `json:"command"`
		Cwd     string   `json:"cwd"`
	}{argv, cwd})
	if err != nil {
		return approvalInput{}, action.ErrSchema
	}
	return approvalInput{Server: "codex", Tool: "exec_command", Arguments: payload, Shell: true}, nil
}

// parseFileWriteRequest accepts exactly {"kind":"file_write","changes":[{"path":str,"change":"add|update|delete"}...]}.
func parseFileWriteRequest(top map[string]json.RawMessage) (approvalInput, error) {
	if len(top) != 2 {
		return approvalInput{}, action.ErrSchema
	}
	rawChanges, ok := top["changes"]
	if !ok {
		return approvalInput{}, action.ErrSchema
	}
	if t := bytes.TrimSpace(rawChanges); len(t) == 0 || t[0] != '[' {
		return approvalInput{}, action.ErrSchema
	}
	var changes []map[string]json.RawMessage
	if err := json.Unmarshal(rawChanges, &changes); err != nil || len(changes) == 0 || len(changes) > maxWritePaths {
		return approvalInput{}, action.ErrSchema
	}
	in := approvalInput{}
	for _, ch := range changes {
		if len(ch) != 2 {
			return approvalInput{}, action.ErrSchema
		}
		var path, change string
		if err := json.Unmarshal(ch["path"], &path); err != nil || path == "" {
			return approvalInput{}, action.ErrSchema
		}
		if err := json.Unmarshal(ch["change"], &change); err != nil {
			return approvalInput{}, action.ErrSchema
		}
		switch change {
		case "add", "update", "delete":
		default:
			return approvalInput{}, action.ErrSchema
		}
		in.WritePaths = append(in.WritePaths, path)
		in.WriteKinds = append(in.WriteKinds, change)
	}
	return in, nil
}

// parseFileReadRequest accepts only {"kind":"file_read","paths":[absolute paths]}.
// Identity comes from the session socket, never from this request.
func parseFileReadRequest(top map[string]json.RawMessage) (approvalInput, error) {
	if len(top) != 2 {
		return approvalInput{}, action.ErrSchema
	}
	var paths []string
	if err := json.Unmarshal(top["paths"], &paths); err != nil || len(paths) == 0 || len(paths) > maxWritePaths {
		return approvalInput{}, action.ErrSchema
	}
	return approvalInput{ReadPaths: paths}, nil
}

// Evaluate decides one request (raw JSON) under the policy (raw YAML).  Anything
// other than a clean kernel ALLOW is BLOCK.
func Evaluate(policyBytes []byte, stdinBytes []byte) Output {
	return EvaluateWithCatalog(policyBytes, nil, stdinBytes)
}

// EvaluateWithCatalog is Evaluate with an application tool catalog: calls to a
// catalog tool are checked against its argument list, then decided by the policy.
// If principal is specified, decisions are made for that principal; otherwise codex-agent.
func EvaluateWithCatalog(policyBytes []byte, cat *Catalog, stdinBytes []byte, targetPrincipal ...string) Output {
	return evaluateWithCatalog(policyBytes, cat, stdinBytes, false, targetPrincipal...)
}

func evaluateWithCatalog(policyBytes []byte, cat *Catalog, stdinBytes []byte, mediated bool, targetPrincipal ...string) Output {
	out := evaluateTool(policyBytes, cat, stdinBytes, targetPrincipal...)
	if req, err := parseStdinRequest(stdinBytes); err == nil && req.Shell {
		return checkCommands(policyBytes, cat, stdinBytes, req, out, targetPrincipal...)
	}
	if out.Effect != string(decision.ALLOW) && !askable(out) {
		return out
	}
	// The owner-created executor session vouches for the mediated workspace.
	// Its actual reads are authorized by the filesystem; a native Read hook
	// must not ask a second time or reject safe searches preemptively.
	if !mediated || !mediatedReadRequest(stdinBytes) {
		out = checkReadPath(policyBytes, cat, stdinBytes, out, targetPrincipal...)
	}
	req, err := parseStdinRequest(stdinBytes)
	if err == nil && req.Server == "claude" && req.Tool == "webfetch" {
		var args struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(req.Arguments, &args)
		return checkWebsite(policyBytes, args.URL, req.CanFilter, out, targetPrincipal...)
	}
	return out
}

func evaluateTool(policyBytes []byte, cat *Catalog, stdinBytes []byte, targetPrincipal ...string) Output {
	princ := syntheticPrinc
	if len(targetPrincipal) > 0 && targetPrincipal[0] != "" {
		princ = targetPrincipal[0]
	}
	snapshot, err := policy.Compile(policyBytes)
	if err != nil {
		return BlockedOutput(err.Error(), "-", "-", nil)
	}
	policyDigest := snapshot.Digest()

	req, err := parseStdinRequest(stdinBytes)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	if req.WritePaths != nil {
		return evaluateFileWrites(snapshot, policyDigest, req, cat, princ)
	}
	if req.ReadPaths != nil {
		return evaluatePaths(snapshot, policyDigest, cat, princ, fsReadOperation, fsReadRouteID, req.ReadPaths,
			func(int) map[string]string { return map[string]string{"tool": "workspace"} })
	}

	if len(req.Arguments) > MaxPayloadBytes {
		return BlockedOutput(action.ErrLimit.Error(), policyDigest, "-", nil)
	}

	toolName := req.Server + "." + req.Tool
	if req.Shell {
		if _, err := action.NormalizeRequest(canaryOperation, toolName, req.Arguments, shellSchema); err != nil {
			return BlockedOutput(err.Error(), policyDigest, "-", nil)
		}
	} else if toolName == shellToolID {
		// The MCP form can never name the shell tool.
		return BlockedOutput(action.ErrSchema.Error(), policyDigest, "-", nil)
	} else if toolName == canaryToolID {
		if _, err := action.NormalizeRequest(canaryOperation, toolName, req.Arguments, canarySchema); err != nil {
			return BlockedOutput(err.Error(), policyDigest, "-", nil)
		}
		var argMap map[string]json.RawMessage
		if err := json.Unmarshal(req.Arguments, &argMap); err != nil {
			return BlockedOutput(action.ErrParse.Error(), policyDigest, "-", nil)
		}
		rawContent, hasContent := argMap["content"]
		if !hasContent || len(argMap) != 1 {
			return BlockedOutput(action.ErrSchema.Error(), policyDigest, "-", nil)
		}
		var contentStr string
		if err := json.Unmarshal(rawContent, &contentStr); err != nil {
			return BlockedOutput(action.ErrSchema.Error(), policyDigest, "-", nil)
		}
		if len(contentStr) > MaxPayloadBytes {
			return BlockedOutput(action.ErrLimit.Error(), policyDigest, "-", nil)
		}
	} else if cat.Has(toolName) {
		schema, err := cat.check(toolName, req.Arguments)
		if err != nil {
			return BlockedOutput(err.Error(), policyDigest, "-", nil)
		}
		if _, err := action.NormalizeRequest(canaryOperation, toolName, req.Arguments, schema); err != nil {
			return BlockedOutput(err.Error(), policyDigest, "-", nil)
		}
	} else {
		if _, err := action.NormalizeRequest(canaryOperation, toolName, []byte("{}"), action.Schema{}); err != nil {
			return BlockedOutput(err.Error(), policyDigest, "-", nil)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	idRegistry, err := buildIdentityRegistry(now, cat, princ)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}
	var engineOpts []decision.Option
	if req.CanFilter {
		engineOpts = append(engineOpts, decision.WithFilterSupport())
	}
	engine, err := decision.NewEngine(snapshot, idRegistry, engineOpts...)
	if err != nil {
		return BlockedOutput(failClosedReason, policyDigest, "-", nil)
	}

	secOp, ok := action.SecurityOperation(canaryOperation)
	if !ok {
		return BlockedOutput(action.ErrSchema.Error(), policyDigest, "-", nil)
	}
	principal, err := idRegistry.Authenticate(syntheticSecret, "data", syntheticTenant, secOp, now)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	actor, err := action.ProjectActor(principal)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	actRegistry, err := buildActionRegistry(cat)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	// Uses action.Advisory because action.ExecutionGateway is rejected by
	// Registry.Context in P1.2 (same boundary as internal/advisorydemo/demo.go).
	actCtx, err := actRegistry.Context(action.Advisory, "synthetic-profile", toolRouteID)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	env, err := action.NewEnvelope(
		approveClock{now: now},
		approveIDSource{id: "synthetic-action-id"},
		"synthetic-request-id",
		"",
		"",
		30*time.Second,
	)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	normalizedAction, err := action.NormalizeAction(actCtx, actor, toolName, req.Arguments, env, nil)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), authorizeTimeout)
	defer cancel()
	verdict, authErr := engine.Authorize(ctx, normalizedAction, principal)

	actionDigest := verdict.ActionDigest
	if actionDigest == "" {
		actionDigest = "-"
	}

	reasons := make([]string, 0, len(verdict.Reasons))
	seenReasons := make(map[string]struct{}, len(verdict.Reasons))
	ruleIDs := make([]string, 0, len(verdict.Reasons))
	seenRules := make(map[string]struct{}, len(verdict.Reasons))
	for _, r := range verdict.Reasons {
		code := string(r.Code)
		if code != "" {
			if _, ok := seenReasons[code]; !ok {
				seenReasons[code] = struct{}{}
				reasons = append(reasons, code)
			}
		}
		if r.RuleID != "" {
			if _, ok := seenRules[r.RuleID]; !ok {
				seenRules[r.RuleID] = struct{}{}
				ruleIDs = append(ruleIDs, r.RuleID)
			}
		}
	}

	if verdict.Effect == decision.ALLOW && authErr == nil && !verdict.DispatchEligible() {
		return Output{
			Effect:       string(decision.ALLOW),
			Reasons:      reasons,
			RuleIDs:      ruleIDs,
			PolicyDigest: policyDigest,
			ActionDigest: actionDigest,
			Filter:       verdict.Filter,
		}
	}
	if len(verdict.Filter) > 0 && len(reasons) == 1 && reasons[0] == "APPROVAL_UNAVAILABLE" {
		// Held for the owner: if allowed, the result is still filtered.
		return Output{Effect: string(decision.BLOCK), Reasons: reasons, RuleIDs: ruleIDs,
			PolicyDigest: policyDigest, ActionDigest: actionDigest, Filter: verdict.Filter}
	}

	if len(reasons) == 0 {
		reasons = []string{failClosedReason}
	}
	return Output{
		Effect:       string(decision.BLOCK),
		Reasons:      reasons,
		RuleIDs:      ruleIDs,
		PolicyDigest: policyDigest,
		ActionDigest: actionDigest,
	}
}

// evaluateFileWrites authorizes every path as fs.write; the result is ALLOW only if every path is allowed.
func evaluateFileWrites(snapshot policy.Snapshot, policyDigest string, req approvalInput, cat *Catalog, princ string) Output {
	return evaluatePaths(snapshot, policyDigest, cat, princ, fsWriteOperation, fsWriteRouteID, req.WritePaths,
		func(i int) map[string]string { return map[string]string{"change": req.WriteKinds[i]} })
}

// evaluatePaths decides operation op on each path (a path-resource route);
// every path must be allowed.
func evaluatePaths(snapshot policy.Snapshot, policyDigest string, cat *Catalog, princ, op, routeID string,
	paths []string, payloadFor func(int) map[string]string) Output {
	now := time.Now().UTC().Truncate(time.Second)
	idRegistry, err := buildIdentityRegistry(now, cat, princ)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}
	engine, err := decision.NewEngine(snapshot, idRegistry)
	if err != nil {
		return BlockedOutput(failClosedReason, policyDigest, "-", nil)
	}
	secOp, ok := action.SecurityOperation(op)
	if !ok {
		return BlockedOutput(action.ErrSchema.Error(), policyDigest, "-", nil)
	}
	principal, err := idRegistry.Authenticate(syntheticSecret, "data", syntheticTenant, secOp, now)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}
	actor, err := action.ProjectActor(principal)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}
	actRegistry, err := buildActionRegistry(cat)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}
	actCtx, err := actRegistry.Context(action.Advisory, "synthetic-profile", routeID)
	if err != nil {
		return BlockedOutput(err.Error(), policyDigest, "-", nil)
	}

	allAllowed := true
	var reasons, ruleIDs, digests []string
	seen := map[string]struct{}{}
	add := func(list *[]string, v string) {
		if v == "" {
			return
		}
		key := fmt.Sprintf("%p|%s", list, v)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		*list = append(*list, v)
	}
	for i, path := range paths {
		env, err := action.NewEnvelope(approveClock{now: now}, approveIDSource{id: fmt.Sprintf("synthetic-action-%d", i)},
			fmt.Sprintf("synthetic-request-%d", i), "", "", 30*time.Second)
		if err != nil {
			return BlockedOutput(err.Error(), policyDigest, "-", nil)
		}
		payload, err := json.Marshal(payloadFor(i))
		if err != nil {
			return BlockedOutput(action.ErrSchema.Error(), policyDigest, "-", nil)
		}
		act, err := action.NormalizeAction(actCtx, actor, path, payload, env, nil)
		if err != nil {
			allAllowed = false
			add(&reasons, err.Error())
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), authorizeTimeout)
		verdict, authErr := engine.Authorize(ctx, act, principal)
		cancel()
		add(&digests, verdict.ActionDigest)
		for _, r := range verdict.Reasons {
			add(&reasons, string(r.Code))
			add(&ruleIDs, r.RuleID)
		}
		if verdict.Effect != decision.ALLOW || authErr != nil || verdict.DispatchEligible() {
			allAllowed = false
		}
	}
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	actionDigest := "-"
	if len(digests) == 1 {
		actionDigest = digests[0]
	} else if len(digests) > 1 {
		actionDigest = strings.Join(digests, ",")
	}
	if allAllowed {
		return Output{Effect: string(decision.ALLOW), Reasons: reasons, RuleIDs: ruleIDs,
			PolicyDigest: policyDigest, ActionDigest: actionDigest}
	}
	if len(reasons) == 0 {
		reasons = []string{failClosedReason}
	}
	return Output{Effect: string(decision.BLOCK), Reasons: reasons, RuleIDs: ruleIDs,
		PolicyDigest: policyDigest, ActionDigest: actionDigest}
}
