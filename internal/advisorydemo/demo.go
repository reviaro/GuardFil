// Package advisorydemo runs a standalone synthetic, advisory-only kernel demo.
package advisorydemo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/identity"
	"github.com/reviaro/guardfil/internal/policy"
)

// Clock is the wall clock; tests pin it so two evaluations see the same instant.
var Clock = time.Now

const policySource = "schema_version: 1\ntenant_id: synthetic\nrevision: 1\ndefault: deny\nrules:\n - id: allow-read\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n - id: deny-delete\n   effect: deny\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.delete_record}]}\n"

const (
	validSecret    = "0123456789012345678901234567890123456789012"
	expiredSecret  = "expired-synthetic-credential-012345678901234"
	nowWindow      = 24 * time.Hour
	demoFailClosed = "DEMO_FAIL_CLOSED"
)

type demoClock struct {
	now time.Time
}

func (c demoClock) Now() time.Time {
	return c.now
}

type demoIDSource struct {
	id string
}

func (d demoIDSource) NewID() (string, error) {
	return d.id, nil
}

type fakeTool struct {
	Operation string
	Schema    action.Schema
}

var fakeTools = map[string]fakeTool{
	"fake.read_note":     {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"note_id": action.String}}},
	"fake.send_message":  {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"body": action.String, "recipient": action.String}}},
	"fake.delete_record": {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"record_id": action.String}}},
	"fake.numeric_note":  {"tool.invoke", action.Schema{Fields: map[string]action.FieldType{"note_id": action.Integer}}},
}

var demoRegistry = mustBuildDemoRegistry()

func mustBuildDemoRegistry() *action.Registry {
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
			Schema:        fakeTools["fake.read_note"].Schema,
		},
		{
			ToolID:        "fake.send_message",
			UpstreamID:    "up-fake-send-message",
			UpstreamName:  "fake.send_message",
			PayloadSchema: "ps-fake-send-message",
			Schema:        fakeTools["fake.send_message"].Schema,
		},
		{
			ToolID:        "fake.delete_record",
			UpstreamID:    "up-fake-delete-record",
			UpstreamName:  "fake.delete_record",
			PayloadSchema: "ps-fake-delete-record",
			Schema:        fakeTools["fake.delete_record"].Schema,
		},
	}
	routes := []action.Route{
		{
			RouteID:           "route-tool-invoke",
			ExecutorID:        "synthetic-executor",
			Operation:         "tool.invoke",
			ResolutionProfile: "synthetic-profile",
			Tools:             []string{"fake.read_note", "fake.send_message", "fake.delete_record"},
		},
	}
	reg, err := action.NewRegistry(profiles, routes, tools, nil)
	if err != nil {
		panic(err)
	}
	return reg
}

type fixture struct {
	Synthetic                                                    bool
	ID, Tool, Payload                                            string
	RawPayload                                                   []byte
	UnknownIdentity, ExpiredIdentity, Cancelled, ExpiredEnvelope bool
	ExpectedEffect                                               decision.Effect
	ExpectedStage, ExpectedAuth, ExpectedReason                  string
}

func fixtureSet() []fixture {
	return []fixture{
		{true, "allow-read", "fake.read_note", `{"note_id":"synthetic-note-001"}`, nil, false, false, false, false, decision.ALLOW, "-", "ok", "POLICY_ALLOWED"},
		{true, "block-delete", "fake.delete_record", `{"record_id":"synthetic-record-001"}`, nil, false, false, false, false, decision.BLOCK, "policy", "ok", "POLICY_DENIED"},
		{true, "unknown-tool", "fake.unknown_tool", `{}`, nil, false, false, false, false, decision.BLOCK, "normalize", "ok", "TOOL_REVISION_UNKNOWN"},
		{true, "malformed-payload", "fake.read_note", `{"note_id":`, nil, false, false, false, false, decision.BLOCK, "parse", "not_attempted", "PARSE_INVALID"},
		{true, "schema-violation", "fake.read_note", `{"unexpected":true}`, nil, false, false, false, false, decision.BLOCK, "normalize", "not_attempted", "SCHEMA_INVALID"},
		{true, "unknown-identity", "fake.send_message", `{"body":"synthetic body","recipient":"synthetic-recipient"}`, nil, true, false, false, false, decision.BLOCK, "auth", "AUTH_INVALID", "AUTH_INVALID"},
		{true, "engine-cancelled", "fake.read_note", `{"note_id":"synthetic-note-002"}`, nil, false, false, true, false, decision.BLOCK, "policy", "ok", "CANCELLED"},
		{true, "empty-payload", "fake.read_note", "", nil, false, false, false, false, decision.BLOCK, "parse", "not_attempted", "PARSE_INVALID"},
		{true, "oversized-payload", "fake.read_note", strings.Repeat(" ", 1<<20+1), nil, false, false, false, false, decision.BLOCK, "parse", "not_attempted", "LIMIT_EXCEEDED"},
		{true, "duplicate-json-key", "fake.read_note", `{"note_id":"one","note_id":"two"}`, nil, false, false, false, false, decision.BLOCK, "parse", "not_attempted", "PARSE_INVALID"},
		{true, "non-utf8-payload", "fake.read_note", "", []byte{'{', '"', 'n', 'o', 't', 'e', '_', 'i', 'd', '"', ':', '"', 0xff, '"', '}'}, false, false, false, false, decision.BLOCK, "parse", "not_attempted", "PARSE_INVALID"},
		{true, "nesting-over-limit", "fake.read_note", strings.Repeat(`{"a":`, 33) + `0` + strings.Repeat(`}`, 33), nil, false, false, false, false, decision.BLOCK, "parse", "not_attempted", "LIMIT_EXCEEDED"},
		{true, "numeric-negative-zero", "fake.numeric_note", `{"note_id":-0}`, nil, false, false, false, false, decision.BLOCK, "normalize", "not_attempted", "DECIMAL_LITERAL_INVALID"},
		{true, "numeric-exponent-out-of-range", "fake.numeric_note", `{"note_id":1e33}`, nil, false, false, false, false, decision.BLOCK, "normalize", "not_attempted", "DECIMAL_LITERAL_INVALID"},
		{true, "numeric-unsafe-integer", "fake.numeric_note", `{"note_id":9007199254740992}`, nil, false, false, false, false, decision.BLOCK, "normalize", "not_attempted", "SCHEMA_INVALID"},
		{true, "case-variant-tool", "fake.Read_note", `{}`, nil, false, false, false, false, decision.BLOCK, "normalize", "not_attempted", "SCHEMA_INVALID"},
		{true, "unicode-lookalike-tool", "fake.reаd_note", `{}`, nil, false, false, false, false, decision.BLOCK, "normalize", "not_attempted", "SCHEMA_INVALID"},
		{true, "no-matching-policy", "fake.send_message", `{"body":"synthetic body","recipient":"synthetic-recipient"}`, nil, false, false, false, false, decision.BLOCK, "policy", "ok", "POLICY_DENIED"},
		{true, "expired-credential", "fake.read_note", `{"note_id":"synthetic-note-003"}`, nil, false, true, false, false, decision.BLOCK, "auth", "AUTH_INVALID", "AUTH_INVALID"},
		{true, "zero-deadline", "fake.read_note", `{"note_id":"synthetic-note-004"}`, nil, false, false, false, true, decision.BLOCK, "policy", "ok", "DEADLINE_EXCEEDED"},
	}
}

type Result struct {
	FixtureID, Tool                    string
	FakeToolKnown                      bool
	Auth, Stage                        string
	Effect                             decision.Effect
	Reason, ActionDigest, PolicyDigest string
	PolicyRevision                     uint64
	DispatchEligible, Synthetic        bool
}

func kernel() (decision.Engine, *identity.Registry, policy.Snapshot, error) {
	snapshot, err := policy.Compile([]byte(policySource))
	if err != nil {
		return decision.Engine{}, nil, policy.Snapshot{}, err
	}
	now := Clock().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x53}, 32)
	credentials := []identity.Credential{
		{ID: "synthetic-credential-valid", TenantID: "synthetic", PrincipalID: "demo", Audience: "data", Scopes: demoScopes(), IssuedAt: now.Add(-nowWindow), ExpiresAt: now.Add(nowWindow), Revision: 1, Verifier: identity.Verifier(key, []byte(validSecret))},
		{ID: "synthetic-credential-expired", TenantID: "synthetic", PrincipalID: "demo", Audience: "data", Scopes: demoScopes(), IssuedAt: now.Add(-2 * nowWindow), ExpiresAt: now.Add(-nowWindow), Revision: 1, Verifier: identity.Verifier(key, []byte(expiredSecret))},
	}
	registry, err := identity.NewRegistryWithResourceSets(key, credentials, demoResourceSets())
	if err != nil {
		return decision.Engine{}, nil, policy.Snapshot{}, err
	}
	engine, err := decision.NewEngine(snapshot, registry)
	return engine, registry, snapshot, err
}

func demoScopes() []identity.Scope {
	return []identity.Scope{{Operation: "tool.invoke", ResourceSet: "read"}, {Operation: "tool.invoke", ResourceSet: "send"}, {Operation: "tool.invoke", ResourceSet: "delete"}}
}

func demoResourceSets() map[string][]identity.Resource {
	return map[string][]identity.Resource{"read": {{Kind: "tool", Value: "fake.read_note"}}, "send": {{Kind: "tool", Value: "fake.send_message"}}, "delete": {{Kind: "tool", Value: "fake.delete_record"}}}
}

func evaluate(f fixture, engine decision.Engine, registry *identity.Registry, snapshot policy.Snapshot) Result {
	result := Result{FixtureID: f.ID, Tool: f.Tool, Auth: "not_attempted", Stage: "demo", Effect: decision.BLOCK, Reason: demoFailClosed, PolicyDigest: snapshot.Digest(), PolicyRevision: snapshot.Revision(), Synthetic: f.Synthetic}
	tool, known := fakeTools[f.Tool]
	result.FakeToolKnown = known
	if !known {
		tool = fakeTool{"tool.invoke", action.Schema{}}
	}
	payload := []byte(f.Payload)
	if f.RawPayload != nil {
		payload = f.RawPayload
	}

	// (a) parse/admit the raw payload through NormalizeRequest/NormalizePayload as today (keeps the existing syntax/schema error behavior, action_digest = "-")
	_, err := action.NormalizeRequest(tool.Operation, f.Tool, payload, tool.Schema)
	if err != nil {
		stage := "normalize"
		// Kept == instead of errors.Is: adding "errors" to advisorydemo would require modifying
		// the import allowlist in TestStaticSafetyGuards, which is a protected PR #19 guard region.
		if err == action.ErrParse || err == action.ErrControl || err == action.ErrLimit {
			stage = "parse"
		}
		result.Stage, result.Reason = stage, err.Error()
		return result
	}

	// (b) authenticate the credential as today; if authentication fails -> auth stage, reason AUTH_INVALID, Auth error preserved, action_digest = "-" (action never existed)
	secret := validSecret
	if f.UnknownIdentity {
		secret = "not-a-synthetic-credential"
	}
	if f.ExpiredIdentity {
		secret = expiredSecret
	}
	secOp, _ := action.SecurityOperation(tool.Operation)
	now := Clock().UTC().Truncate(time.Second)
	principal, authErr := registry.Authenticate(secret, "data", "synthetic", secOp, now)
	if authErr != nil {
		result.Auth = authErr.Error()
		result.Stage = "auth"
		result.Reason = authErr.Error()
		return result
	}
	result.Auth = "ok"

	// (c) build Context and actor from ProjectActor, then NormalizeAction. If the tool is not in the registry -> normalize stage, TOOL_REVISION_UNKNOWN, action_digest = "-".
	actor, err := action.ProjectActor(principal)
	if err != nil {
		// unreachable for registry-issued principals; the demo never mints kernel reason codes
		result.Stage, result.Reason = "auth", demoFailClosed
		return result
	}

	actCtx, err := demoRegistry.Context(action.Advisory, "synthetic-profile", "route-tool-invoke")
	if err != nil {
		result.Stage, result.Reason = "normalize", err.Error()
		return result
	}

	clk := demoClock{now: now}
	ttl := 30 * time.Second
	if f.ExpiredEnvelope {
		clk = demoClock{now: now.Add(-time.Minute)}
		ttl = time.Second
	}
	env, err := action.NewEnvelope(clk, demoIDSource{id: "synthetic-action-id"}, "synthetic-request-id", "", "", ttl)
	if err != nil {
		result.Stage, result.Reason = "normalize", err.Error()
		return result
	}

	normalizedAction, err := action.NormalizeAction(actCtx, actor, f.Tool, payload, env, nil)
	if err != nil {
		result.Stage, result.Reason = "normalize", err.Error()
		return result
	}

	// (d) Authorize with the NormalizeAction Action; action_digest is verdict.ActionDigest (real rule-5 action_digest).
	ctx := context.Background()
	if f.Cancelled {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}
	verdict, err := engine.Authorize(ctx, normalizedAction, principal)
	result.ActionDigest = verdict.ActionDigest
	result.Effect = verdict.Effect
	result.DispatchEligible = verdict.DispatchEligible()
	if verdict.Effect == decision.ALLOW {
		result.Stage = "-"
		result.Reason = string(verdict.Reasons[0].Code)
	} else {
		result.Stage = string(verdict.Stage)
		result.Reason = string(verdict.Code())
	}
	if err != nil && result.Effect == decision.ALLOW {
		result.Stage, result.Effect, result.Reason, result.DispatchEligible = "demo", decision.BLOCK, demoFailClosed, false
	}
	return result
}

func EvaluateAll() ([]Result, error) {
	engine, registry, snapshot, err := kernel()
	if err != nil {
		return nil, err
	}
	fixtures := fixtureSet()
	results := make([]Result, 0, len(fixtures))
	for _, f := range fixtures {
		result := evaluate(f, engine, registry, snapshot)
		if result.Effect != f.ExpectedEffect || result.Stage != f.ExpectedStage || result.Auth != f.ExpectedAuth || result.Reason != f.ExpectedReason || result.DispatchEligible {
			return nil, fmt.Errorf("synthetic fixture %s deviated: effect=%s stage=%s auth=%s reason=%s dispatch_eligible=%t", f.ID, result.Effect, result.Stage, result.Auth, result.Reason, result.DispatchEligible)
		}
		results = append(results, result)
	}
	return results, nil
}

func Run(writer io.Writer) error {
	results, err := EvaluateAll()
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintln(writer, "SYNTHETIC FIXTURES - NOT REAL AGENT TRAFFIC"); err != nil {
		return err
	}
	if _, err = fmt.Fprintln(writer, "ADVISORY ONLY - ALLOW IS DIAGNOSTIC; NOTHING IS DISPATCHED"); err != nil {
		return err
	}
	for _, result := range results {
		if _, err = fmt.Fprintf(writer, "\"synthetic\": %t fixture=%s fake_tool=%s fake_tool_known=%t auth=%s stage=%s effect=%s kernel_reason=%s action_digest=%s policy_digest=%s policy_revision=%d dispatch_eligible=%t\n", result.Synthetic, result.FixtureID, result.Tool, result.FakeToolKnown, result.Auth, result.Stage, result.Effect, result.Reason, valueOrDash(result.ActionDigest), result.PolicyDigest, result.PolicyRevision, result.DispatchEligible); err != nil {
			return err
		}
	}
	return nil
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
