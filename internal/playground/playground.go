package playground

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/advisorydemo"
	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/identity"
	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/source"
	"github.com/reviaro/guardfil/internal/telemetry"
)

// clock is the wall clock; tests pin it.
var clock = time.Now

// ToolSet specifies which tool catalog and policy rules are active.
type ToolSet string

const (
	ToolSetDemo       ToolSet = "demo"
	ToolSetClaudeCode ToolSet = "claude-code"
)

var claudeCodeToolMap = []ToolMapEntry{
	{Name: "Bash", ID: "cc.bash"},
	{Name: "PowerShell", ID: "cc.powershell"},
	{Name: "Read", ID: "cc.read"},
	{Name: "Write", ID: "cc.write"},
	{Name: "Edit", ID: "cc.edit"},
	{Name: "MultiEdit", ID: "cc.multi_edit"},
	{Name: "Glob", ID: "cc.glob"},
	{Name: "Grep", ID: "cc.grep"},
	{Name: "WebFetch", ID: "cc.web_fetch"},
	{Name: "WebSearch", ID: "cc.web_search"},
	{Name: "Task", ID: "cc.task"},
	{Name: "Agent", ID: "cc.agent"},
	{Name: "TodoWrite", ID: "cc.todo_write"},
	{Name: "NotebookEdit", ID: "cc.notebook_edit"},
}

const defaultPolicySource = "schema_version: 1\ntenant_id: synthetic\nrevision: 1\ndefault: deny\nrules:\n - id: allow-read\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n - id: deny-delete\n   effect: deny\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.delete_record}]}\n"

const claudeCodePolicyRules = " - id: allow-cc-low-risk\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: cc.read}, {kind: tool, value: cc.glob}, {kind: tool, value: cc.grep}, {kind: tool, value: cc.todo_write}]}\n - id: deny-cc-mutating\n   effect: deny\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: cc.bash}, {kind: tool, value: cc.powershell}, {kind: tool, value: cc.write}, {kind: tool, value: cc.edit}, {kind: tool, value: cc.multi_edit}]}\n"

const defaultClaudeCodePolicySource = defaultPolicySource + claudeCodePolicyRules

const unknownCredentialSecret = "unknown-synthetic-credential-012345678901234"

type fakeTool struct {
	operation  string
	schema     action.Schema
	inRegistry bool
}

var fakeTools = map[string]fakeTool{
	"fake.read_note":     {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"note_id": action.String}}, true},
	"fake.send_message":  {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"body": action.String, "recipient": action.String}}, true},
	"fake.delete_record": {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"record_id": action.String}}, true},
	"fake.numeric_note":  {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"note_id": action.Integer}}, false},
}

func demoScopes() []identity.Scope {
	return []identity.Scope{
		{Operation: "tool.invoke", ResourceSet: "read"},
		{Operation: "tool.invoke", ResourceSet: "send"},
		{Operation: "tool.invoke", ResourceSet: "delete"},
	}
}

func demoResourceSets() map[string][]identity.Resource {
	return map[string][]identity.Resource{
		"read":   {{Kind: "tool", Value: "fake.read_note"}},
		"send":   {{Kind: "tool", Value: "fake.send_message"}},
		"delete": {{Kind: "tool", Value: "fake.delete_record"}},
	}
}

func buildActionRegistry(toolSet ToolSet) (*action.Registry, error) {
	profiles := []action.Profile{
		{
			Protocol:        "decision_api",
			ProfileID:       "synthetic-profile",
			AdapterRevision: "sha256:" + strings.Repeat("0", 64),
		},
	}
	tools := []action.Tool{
		{
			ToolID:        "fake.read_note",
			UpstreamID:    "up-fake-read-note",
			UpstreamName:  "fake.read_note",
			PayloadSchema: "ps-fake-read-note",
			Schema:        fakeTools["fake.read_note"].schema,
		},
		{
			ToolID:        "fake.send_message",
			UpstreamID:    "up-fake-send-message",
			UpstreamName:  "fake.send_message",
			PayloadSchema: "ps-fake-send-message",
			Schema:        fakeTools["fake.send_message"].schema,
		},
		{
			ToolID:        "fake.delete_record",
			UpstreamID:    "up-fake-delete-record",
			UpstreamName:  "fake.delete_record",
			PayloadSchema: "ps-fake-delete-record",
			Schema:        fakeTools["fake.delete_record"].schema,
		},
	}
	routeTools := []string{"fake.read_note", "fake.send_message", "fake.delete_record"}

	if toolSet == ToolSetClaudeCode {
		for _, entry := range claudeCodeToolMap {
			tools = append(tools, action.Tool{
				ToolID:        entry.ID,
				UpstreamID:    "claude-code",
				UpstreamName:  entry.Name,
				PayloadSchema: "ps-" + strings.ReplaceAll(entry.ID, ".", "-"),
				Schema:        action.Schema{},
			})
			routeTools = append(routeTools, entry.ID)
		}
	}

	routes := []action.Route{
		{
			RouteID:           "route-tool-invoke",
			ExecutorID:        "synthetic-executor",
			Operation:         "tool.invoke",
			ResolutionProfile: "synthetic-profile",
			Tools:             routeTools,
		},
	}
	return action.NewRegistry(profiles, routes, tools, nil)
}

type currentPolicyEngine struct {
	policySource string
	snapshot     policy.Snapshot
	engine       decision.Engine
}

type pastClock struct {
	now time.Time
}

func (c pastClock) Now() time.Time {
	return c.now
}

// ErrPolicySize is returned when policy source is empty or exceeds 65536 bytes.
var ErrPolicySize = errors.New("policy source must be 1..65536 bytes")

func codeFor(err error) failure.Code {
	if err == nil {
		return failure.INTERNAL_ERROR
	}
	code := failure.Code(err.Error())
	if !code.Valid() {
		return failure.INTERNAL_ERROR
	}
	return code
}

// Option configures Playground construction.
type Option func(*playgroundConfig)

type playgroundConfig struct {
	toolSet ToolSet
}

// WithToolSet configures the active tool set (ToolSetDemo or ToolSetClaudeCode).
func WithToolSet(ts ToolSet) Option {
	return func(c *playgroundConfig) {
		c.toolSet = ts
	}
}

// ParseToolSet validates and returns a known ToolSet or an error.
func ParseToolSet(s string) (ToolSet, error) {
	switch ToolSet(s) {
	case ToolSetDemo:
		return ToolSetDemo, nil
	case ToolSetClaudeCode:
		return ToolSetClaudeCode, nil
	default:
		return "", fmt.Errorf("invalid tool set %q: must be 'demo' or 'claude-code'", s)
	}
}

// Playground encapsulates the advisory evaluation pipeline and its mutable policy state.
type Playground struct {
	mu                  sync.RWMutex
	current             currentPolicyEngine
	identityRegistry    *identity.Registry
	actionRegistry      *action.Registry
	counters            *telemetry.Counters
	history             *historyRing
	toolSet             ToolSet
	tools               map[string]fakeTool
	defaultPolicySource string

	validSecret   string
	expiredSecret string
}

// New constructs a Playground with synthetic credentials, default policy, and telemetry.
func New(opts ...Option) (*Playground, error) {
	cfg := playgroundConfig{
		toolSet: ToolSetDemo,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	switch cfg.toolSet {
	case ToolSetDemo, ToolSetClaudeCode:
	default:
		return nil, fmt.Errorf("invalid tool set: %q", cfg.toolSet)
	}

	tools := make(map[string]fakeTool, len(fakeTools)+len(claudeCodeToolMap))
	for k, v := range fakeTools {
		tools[k] = v
	}
	if cfg.toolSet == ToolSetClaudeCode {
		for _, entry := range claudeCodeToolMap {
			tools[entry.ID] = fakeTool{
				operation:  "tool.invoke",
				schema:     action.Schema{},
				inRegistry: true,
			}
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	validSecretBytes := make([]byte, 32)
	if _, err := rand.Read(validSecretBytes); err != nil {
		return nil, err
	}
	expiredSecretBytes := make([]byte, 32)
	if _, err := rand.Read(expiredSecretBytes); err != nil {
		return nil, err
	}
	validSecret := hex.EncodeToString(validSecretBytes)
	expiredSecret := hex.EncodeToString(expiredSecretBytes)

	now := clock().UTC().Truncate(time.Second)
	nowWindow := 24 * time.Hour

	scopes := demoScopes()
	resourceSets := demoResourceSets()
	if cfg.toolSet == ToolSetClaudeCode {
		for _, entry := range claudeCodeToolMap {
			resourceSets[entry.ID] = []identity.Resource{{Kind: "tool", Value: entry.ID}}
			scopes = append(scopes, identity.Scope{Operation: "tool.invoke", ResourceSet: entry.ID})
		}
	}

	credentials := []identity.Credential{
		{
			ID:          "synthetic-credential-valid",
			TenantID:    "synthetic",
			PrincipalID: "demo",
			Audience:    "data",
			Scopes:      scopes,
			IssuedAt:    now.Add(-nowWindow),
			ExpiresAt:   now.Add(nowWindow),
			Revision:    1,
			Verifier:    identity.Verifier(key, []byte(validSecret)),
		},
		{
			ID:          "synthetic-credential-expired",
			TenantID:    "synthetic",
			PrincipalID: "demo",
			Audience:    "data",
			Scopes:      scopes,
			IssuedAt:    now.Add(-2 * nowWindow),
			ExpiresAt:   now.Add(-nowWindow),
			Revision:    1,
			Verifier:    identity.Verifier(key, []byte(expiredSecret)),
		},
	}
	idReg, err := identity.NewRegistryWithResourceSets(key, credentials, resourceSets)
	if err != nil {
		return nil, err
	}

	actReg, err := buildActionRegistry(cfg.toolSet)
	if err != nil {
		return nil, err
	}

	defaultPolicy := defaultPolicySource
	if cfg.toolSet == ToolSetClaudeCode {
		defaultPolicy = defaultClaudeCodePolicySource
	}

	counters := &telemetry.Counters{}
	snapshot, err := policy.Compile([]byte(defaultPolicy))
	if err != nil {
		return nil, err
	}
	eng, err := decision.NewEngineWithTelemetry(snapshot, idReg, counters)
	if err != nil {
		return nil, err
	}

	return &Playground{
		current: currentPolicyEngine{
			policySource: defaultPolicy,
			snapshot:     snapshot,
			engine:       eng,
		},
		identityRegistry:    idReg,
		actionRegistry:      actReg,
		counters:            counters,
		history:             newHistoryRing(),
		toolSet:             cfg.toolSet,
		tools:               tools,
		defaultPolicySource: defaultPolicy,
		validSecret:         validSecret,
		expiredSecret:       expiredSecret,
	}, nil
}

func (p *Playground) fail(res *Result, trace []TraceStep, idx int, stage failure.Stage, err error) Result {
	code := codeFor(err)
	res.Stage = string(stage)
	res.Code = string(code)
	res.Reasons = []decision.Reason{{Code: decision.ReasonCode(code)}}
	if idx >= 0 && idx < len(trace) {
		trace[idx].Status = "failed"
		trace[idx].Code = string(code)
	}
	res.Trace = trace
	p.finalizeResult(res)
	p.history.Add(*res)
	return *res
}

func truncateTool(name string) string {
	if len(name) <= 256 {
		return name
	}
	end := 0
	for i, r := range name {
		runeLen := len(string(r))
		if i+runeLen > 256 {
			break
		}
		end = i + runeLen
	}
	return name[:end] + "..."
}

func mapProjectActorError(err error) (failure.Code, failure.Stage) {
	return failure.IDENTITY_UNTRUSTED, failure.StageAuth
}

// Evaluate runs untrusted input through the advisory pipeline without executing anything.
func (p *Playground) Evaluate(ctx context.Context, in Input) Result {
	trace := []TraceStep{
		{Step: "admit", Status: "skipped"},
		{Step: "authenticate", Status: "skipped"},
		{Step: "project", Status: "skipped"},
		{Step: "context", Status: "skipped"},
		{Step: "envelope", Status: "skipped"},
		{Step: "normalize", Status: "skipped"},
		{Step: "authorize", Status: "skipped"},
	}

	p.mu.RLock()
	currentDigest := p.current.snapshot.Digest()
	currentRevision := p.current.snapshot.Revision()
	engine := p.current.engine
	p.mu.RUnlock()

	res := Result{
		Synthetic:        true,
		Tool:             truncateTool(in.Tool),
		Credential:       in.Credential,
		PolicyDigest:     currentDigest,
		PolicyRevision:   currentRevision,
		DispatchEligible: decision.Decision{}.DispatchEligible(),
		Effect:           "BLOCK",
	}

	tool, known := p.tools[in.Tool]
	res.FakeToolKnown = known
	if !known {
		tool = fakeTool{"tool.invoke", action.Schema{}, false}
	}

	reqID, err := source.Random{}.NewID()
	if err != nil {
		res.RequestID = ""
		// Stage policy matches kernel ID-generation failure (decision.go INTERNAL_ERROR/policy).
		return p.fail(&res, trace, -1, failure.StagePolicy, errors.New(string(failure.INTERNAL_ERROR)))
	}
	res.RequestID = reqID

	// (1) NormalizeRequest
	_, err = action.NormalizeRequest(tool.operation, in.Tool, in.Payload, tool.schema)
	if err != nil {
		stage := failure.StageNormalize
		if errors.Is(err, action.ErrParse) || errors.Is(err, action.ErrControl) || errors.Is(err, action.ErrLimit) {
			stage = failure.StageParse
		}
		return p.fail(&res, trace, 0, stage, err)
	}
	trace[0] = TraceStep{Step: "admit", Status: "ok"}

	// (2) Authenticate
	var secret string
	switch in.Credential {
	case "valid":
		secret = p.validSecret
	case "expired":
		secret = p.expiredSecret
	case "unknown":
		secret = unknownCredentialSecret
	case "none":
		secret = ""
	default:
		return p.fail(&res, trace, 1, failure.StageAuth, errors.New(string(failure.INTERNAL_ERROR)))
	}
	secOp, _ := action.SecurityOperation(tool.operation)
	now := clock().UTC().Truncate(time.Second)
	principal, authErr := p.identityRegistry.Authenticate(secret, "data", "synthetic", secOp, now)
	if authErr != nil {
		return p.fail(&res, trace, 1, failure.StageAuth, authErr)
	}
	trace[1] = TraceStep{Step: "authenticate", Status: "ok"}

	// (3) ProjectActor
	actor, err := action.ProjectActor(principal)
	if err != nil {
		code, stage := mapProjectActorError(err)
		return p.fail(&res, trace, 2, stage, errors.New(string(code)))
	}
	trace[2] = TraceStep{Step: "project", Status: "ok"}

	// (4) Context
	actCtx, err := p.actionRegistry.Context(action.Advisory, "synthetic-profile", "route-tool-invoke")
	if err != nil {
		return p.fail(&res, trace, 3, failure.StageNormalize, err)
	}
	trace[3] = TraceStep{Step: "context", Status: "ok"}

	// (5) NewEnvelope
	ttl := time.Duration(in.TTLMillis) * time.Millisecond
	var baseClock source.Clock = source.System{}
	if in.ExpiredEnvelope {
		baseClock = pastClock{now: now.Add(-time.Minute)}
		ttl = time.Second
	}
	env, err := action.NewEnvelope(baseClock, source.Random{}, reqID, "", "", ttl)
	if err != nil {
		return p.fail(&res, trace, 4, failure.StageNormalize, err)
	}
	trace[4] = TraceStep{Step: "envelope", Status: "ok"}

	// (6) NormalizeAction
	normalizedAction, err := action.NormalizeAction(actCtx, actor, in.Tool, in.Payload, env, nil)
	if err != nil {
		return p.fail(&res, trace, 5, failure.StageNormalize, err)
	}
	if te, ok := normalizedAction.TrustedEnvelope(); ok {
		res.ReceivedAt = te.ReceivedAt
		res.DeadlineAt = te.DeadlineAt
		res.ActionID = te.ActionID
	}
	trace[5] = TraceStep{Step: "normalize", Status: "ok"}

	// (7) Authorize
	evalCtx := ctx
	if in.Cancelled {
		var cancel context.CancelFunc
		evalCtx, cancel = context.WithCancel(evalCtx)
		cancel()
	}

	verdict, err := engine.Authorize(evalCtx, normalizedAction, principal)
	if err != nil && verdict.Effect == decision.ALLOW {
		// Fail-closed fallback: force BLOCK/INTERNAL_ERROR
		return p.fail(&res, trace, 6, failure.StagePolicy, errors.New(string(failure.INTERNAL_ERROR)))
	}

	res.Effect = string(verdict.Effect)
	res.DispatchEligible = verdict.DispatchEligible()
	res.ActionDigest = verdict.ActionDigest
	res.DecisionID = verdict.DecisionID
	res.ToolRevision = verdict.ToolRevision
	res.Boundary = verdict.Boundary
	res.RevocationEpoch = verdict.RevocationEpoch
	res.PolicyDigest = verdict.PolicyDigest
	res.PolicyRevision = verdict.PolicyRevision
	if !verdict.EvaluatedAt.IsZero() {
		res.EvaluatedAt = verdict.EvaluatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !verdict.ExpiresAt.IsZero() {
		res.ExpiresAt = verdict.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	res.Reasons = verdict.Reasons

	if verdict.Effect == decision.ALLOW {
		res.Stage = ""
		res.Code = "POLICY_ALLOWED"
		if len(verdict.Reasons) > 0 {
			res.Code = string(verdict.Reasons[0].Code)
		}
		trace[6] = TraceStep{Step: "authorize", Status: "ok", Code: res.Code}
	} else {
		res.Stage = string(verdict.Stage)
		res.Code = string(verdict.Code())
		trace[6] = TraceStep{Step: "authorize", Status: "failed", Code: res.Code}
	}

	res.Trace = trace
	p.finalizeResult(&res)
	p.history.Add(res)
	return res
}

func (p *Playground) finalizeResult(res *Result) {
	if res.Effect != "BLOCK" {
		return
	}
	code := failure.Code(res.Code)
	stage := failure.Stage(res.Stage)
	env, err := failure.PreDispatch(code, stage, res.RequestID)
	if err != nil {
		res.EnvelopeError = err.Error()
		return
	}
	if res.ActionID != "" {
		env.ActionID = res.ActionID
	}
	if res.DecisionID != "" {
		env.DecisionID = res.DecisionID
	}
	b, err := env.MarshalJSON()
	if err != nil {
		res.EnvelopeError = err.Error()
		return
	}
	res.ErrorEnvelope = json.RawMessage(b)
}

// SetPolicy replaces the active policy document with src, validating under limits.
func (p *Playground) SetPolicy(src []byte) (PolicyInfo, error) {
	if len(src) < 1 || len(src) > 64*1024 {
		return PolicyInfo{}, ErrPolicySize
	}
	snapshot, err := policy.Compile(src)
	if err != nil {
		return PolicyInfo{}, err
	}
	engine, err := decision.NewEngineWithTelemetry(snapshot, p.identityRegistry, p.counters)
	if err != nil {
		return PolicyInfo{}, err
	}

	p.mu.Lock()
	p.current.policySource = string(src)
	p.current.snapshot = snapshot
	p.current.engine = engine
	p.mu.Unlock()

	return PolicyInfo{
		Source:   string(src),
		Digest:   snapshot.Digest(),
		Revision: snapshot.Revision(),
	}, nil
}

// ResetPolicy restores the default policy configuration for the active tool set.
func (p *Playground) ResetPolicy() (PolicyInfo, error) {
	return p.SetPolicy([]byte(p.defaultPolicySource))
}

// ToolSet returns the active tool set name ("demo" or "claude-code").
func (p *Playground) ToolSet() string {
	return string(p.toolSet)
}

// ToolMap returns the Claude Code name->ID mappings, or an empty slice for demo mode.
func (p *Playground) ToolMap() []ToolMapEntry {
	if p.toolSet != ToolSetClaudeCode {
		return []ToolMapEntry{}
	}
	out := make([]ToolMapEntry, len(claudeCodeToolMap))
	copy(out, claudeCodeToolMap)
	return out
}

// RunFixtures executes all red-team advisory fixtures using the exported advisorydemo API.
func (p *Playground) RunFixtures() ([]FixtureRow, error) {
	results, err := advisorydemo.EvaluateAll()
	if err != nil {
		return nil, err
	}
	rows := make([]FixtureRow, len(results))
	for i, r := range results {
		rows[i] = FixtureRow{
			FixtureID:        r.FixtureID,
			Tool:             r.Tool,
			Effect:           r.Effect,
			Stage:            r.Stage,
			Auth:             r.Auth,
			Reason:           r.Reason,
			ActionDigest:     r.ActionDigest,
			DispatchEligible: r.DispatchEligible,
		}
	}
	return rows, nil
}
