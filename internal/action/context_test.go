package action_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/identity"
)

const (
	testValidDigest             = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	defaultTestEnvelopeActionID = "act-test-01"
)

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}

type fakeIDSource struct {
	id  string
	err error
}

func (f fakeIDSource) NewID() (string, error) {
	return f.id, f.err
}

var defaultTestEnvelope = func() action.MintedEnvelope {
	c := fakeClock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	ids := fakeIDSource{id: "act-test-01"}
	env, err := action.NewEnvelope(c, ids, "req-test-01", "", "", time.Second)
	if err != nil {
		panic(err)
	}
	return env
}()

var defaultTestActor = func() action.Actor {
	key := []byte("01234567890123456789012345678901")
	secret := "0123456789012345678901234567890123456789012"
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)
	cred := identity.Credential{
		ID:              "app-key-2",
		TenantID:        "acme",
		PrincipalID:     "coding-app",
		Audience:        "data",
		Scopes:          []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:        time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 9, 25, 17, 0, 0, 0, time.UTC),
		Revision:        2,
		RevocationEpoch: 8,
		Verifier:        identity.Verifier(key, []byte(secret)),
	}
	reg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	})
	if err != nil {
		panic(err)
	}
	ctx, err := reg.Authenticate(secret, "data", "acme", "filesystem.read", now)
	if err != nil {
		panic(err)
	}
	actor, err := action.ProjectActor(ctx)
	if err != nil {
		panic(err)
	}
	return actor
}()

func validProfile(id string) action.Profile {
	return action.Profile{
		Protocol:        "decision_api",
		ProfileID:       id,
		AdapterRevision: testValidDigest,
	}
}

func validToolRoute(id string, tools ...string) action.Route {
	var toolList []string
	if len(tools) > 0 {
		toolList = tools
	} else {
		toolList = []string{"tool.a"}
	}
	return action.Route{
		RouteID:           id,
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             toolList,
	}
}

func validNonToolRoute(id, op string) action.Route {
	return action.Route{
		RouteID:           id,
		ExecutorID:        "exec-1",
		Operation:         op,
		ResolutionProfile: "res-1",
		PayloadSchema:     "schema-v1",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"path": action.String,
			},
		},
	}
}

func validTool(id string) action.Tool {
	return action.Tool{
		ToolID:        id,
		UpstreamID:    "upstream-1",
		UpstreamName:  "tool_name",
		PayloadSchema: "schema-tool",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"arg": action.String,
			},
		},
	}
}

func TestRegistryValidation(t *testing.T) {
	tests := []struct {
		name     string
		profiles []action.Profile
		routes   []action.Route
		tools    []action.Tool
		wantErr  error
	}{
		{
			name:     "valid minimal registry",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools:    []action.Tool{validTool("tool.a")},
			wantErr:  nil,
		},
		{
			name:     "valid registry zero tools",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validNonToolRoute("route-1", "fs.read")},
			tools:    nil,
			wantErr:  nil,
		},
		{
			name:     "bounds 0 profiles rejected",
			profiles: []action.Profile{},
			routes:   []action.Route{validToolRoute("route-1")},
			tools:    nil,
			wantErr:  action.ErrSchema,
		},
		{
			name: "bounds 65 profiles rejected",
			profiles: func() []action.Profile {
				p := make([]action.Profile, 65)
				for i := range p {
					p[i] = validProfile(fmt.Sprintf("prof-%d", i))
				}
				return p
			}(),
			routes:  []action.Route{validToolRoute("route-1")},
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "bounds 0 routes rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{},
			tools:    nil,
			wantErr:  action.ErrSchema,
		},
		{
			name:     "bounds 1025 routes rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := make([]action.Route, 1025)
				for i := range r {
					r[i] = validToolRoute(fmt.Sprintf("route-%d", i))
				}
				return r
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "bounds 1025 tools rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools: func() []action.Tool {
				tools := make([]action.Tool, 1025)
				for i := range tools {
					tools[i] = validTool(fmt.Sprintf("tool.%d", i))
				}
				return tools
			}(),
			wantErr: action.ErrSchema,
		},
		{
			name:     "invalid profile id empty",
			profiles: []action.Profile{validProfile("")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools:    nil,
			wantErr:  action.ErrSchema,
		},
		{
			name:     "invalid profile id characters",
			profiles: []action.Profile{validProfile("prof space")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools:    nil,
			wantErr:  action.ErrSchema,
		},
		{
			name:     "invalid profile id too long",
			profiles: []action.Profile{validProfile(strings.Repeat("a", 129))},
			routes:   []action.Route{validToolRoute("route-1")},
			tools:    nil,
			wantErr:  action.ErrSchema,
		},
		{
			name: "invalid adapter revision not sha256",
			profiles: []action.Profile{{
				Protocol:        "decision_api",
				ProfileID:       "prof-1",
				AdapterRevision: "md5:0123456789abcdef0123456789abcdef",
			}},
			routes:  []action.Route{validToolRoute("route-1")},
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name: "invalid adapter revision uppercase hex",
			profiles: []action.Profile{{
				Protocol:        "decision_api",
				ProfileID:       "prof-1",
				AdapterRevision: "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
			}},
			routes:  []action.Route{validToolRoute("route-1")},
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name: "duplicate profile id",
			profiles: []action.Profile{
				validProfile("prof-1"),
				validProfile("prof-1"),
			},
			routes:  []action.Route{validToolRoute("route-1")},
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name: "protocol openai_compatible rejected",
			profiles: []action.Profile{{
				Protocol:        "openai_compatible",
				ProfileID:       "prof-1",
				AdapterRevision: testValidDigest,
			}},
			routes:  []action.Route{validToolRoute("route-1")},
			tools:   nil,
			wantErr: action.ErrProtocolUnsupported,
		},
		{
			name: "protocol mcp rejected",
			profiles: []action.Profile{{
				Protocol:        "mcp",
				ProfileID:       "prof-1",
				AdapterRevision: testValidDigest,
			}},
			routes:  []action.Route{validToolRoute("route-1")},
			tools:   nil,
			wantErr: action.ErrProtocolUnsupported,
		},
		{
			name: "protocol unknown rejected",
			profiles: []action.Profile{{
				Protocol:        "custom_proto",
				ProfileID:       "prof-1",
				AdapterRevision: testValidDigest,
			}},
			routes:  []action.Route{validToolRoute("route-1")},
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "duplicate route id",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: []action.Route{
				validToolRoute("route-1"),
				validToolRoute("route-1"),
			},
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "invalid route id empty",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validToolRoute("")
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "invalid executor id",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validToolRoute("route-1")
				r.ExecutorID = "invalid char @"
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "invalid resolution profile",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validToolRoute("route-1")
				r.ResolutionProfile = ""
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "operation llm.request rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validNonToolRoute("route-1", "llm.request")},
			tools:    nil,
			wantErr:  action.ErrSchema,
		},
		{
			name:     "operation shell.execute has a command projection",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validNonToolRoute("route-1", "shell.execute")},
			tools:    nil,
			wantErr:  nil,
		},
		{
			name:     "valid non-tool route fs.read positive control",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validNonToolRoute("route-1", "fs.read")},
			tools:    nil,
			wantErr:  nil,
		},
		{
			name:     "operation unknown rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validToolRoute("route-1")
				r.Operation = "invalid.op"
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "tool route with payload schema rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validToolRoute("route-1")
				r.PayloadSchema = "schema-not-allowed"
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "tool route with schema rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validToolRoute("route-1")
				r.Schema = action.Schema{Fields: map[string]action.FieldType{"a": action.String}}
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "non-tool route without payload schema rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validNonToolRoute("route-fs", "fs.read")
				r.PayloadSchema = ""
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "non-tool route without schema rejected",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: func() []action.Route {
				r := validNonToolRoute("route-fs", "fs.read")
				r.Schema = action.Schema{}
				return []action.Route{r}
			}(),
			tools:   nil,
			wantErr: action.ErrSchema,
		},
		{
			name:     "tool ID invalid uppercase",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools: []action.Tool{{
				ToolID:        "ToolA",
				PayloadSchema: "ps-1",
				Schema:        action.Schema{Fields: map[string]action.FieldType{"a": action.String}},
			}},
			wantErr: action.ErrSchema,
		},
		{
			name:     "tool ID invalid wildcard",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools: []action.Tool{{
				ToolID:        "tool/**",
				PayloadSchema: "ps-1",
				Schema:        action.Schema{Fields: map[string]action.FieldType{"a": action.String}},
			}},
			wantErr: action.ErrSchema,
		},
		{
			name:     "tool invalid payload schema",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools: []action.Tool{{
				ToolID:        "tool-1",
				PayloadSchema: "",
				Schema:        action.Schema{Fields: map[string]action.FieldType{"a": action.String}},
			}},
			wantErr: action.ErrSchema,
		},
		{
			name:     "duplicate tool ID",
			profiles: []action.Profile{validProfile("prof-1")},
			routes:   []action.Route{validToolRoute("route-1")},
			tools: []action.Tool{
				validTool("tool-1"),
				validTool("tool-1"),
			},
			wantErr: action.ErrSchema,
		},
		{
			name:     "valid non-tool routes fs.read, fs.write, http.request",
			profiles: []action.Profile{validProfile("prof-1")},
			routes: []action.Route{
				validNonToolRoute("r-read", "fs.read"),
				validNonToolRoute("r-write", "fs.write"),
				validNonToolRoute("r-http", "http.request"),
				validToolRoute("r-tool", "tool-1"),
			},
			tools:   []action.Tool{validTool("tool-1")},
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := action.NewRegistry(tc.profiles, tc.routes, tc.tools, nil)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
			}
		})
	}
}

func TestContextCreationAndAccessors(t *testing.T) {
	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{
			validToolRoute("route-tool", "tool-a"),
			validNonToolRoute("route-fs", "fs.read"),
		},
		[]action.Tool{validTool("tool-a")},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	// proposal_filter ok
	ctxPF, err := reg.Context(action.ProposalFilter, "prof-1", "route-tool")
	if err != nil {
		t.Fatalf("Context(ProposalFilter) failed: %v", err)
	}
	if ctxPF.Boundary() != action.ProposalFilter {
		t.Fatalf("unexpected boundary: %s", ctxPF.Boundary())
	}
	if ctxPF.Protocol() != "decision_api" {
		t.Fatalf("unexpected protocol: %s", ctxPF.Protocol())
	}
	if ctxPF.Profile() != "prof-1" {
		t.Fatalf("unexpected profile: %s", ctxPF.Profile())
	}
	if ctxPF.AdapterRevision() != testValidDigest {
		t.Fatalf("unexpected adapter revision: %s", ctxPF.AdapterRevision())
	}
	if ctxPF.RouteID() != "route-tool" {
		t.Fatalf("unexpected route id: %s", ctxPF.RouteID())
	}
	if ctxPF.ExecutorID() != "exec-1" {
		t.Fatalf("unexpected executor id: %s", ctxPF.ExecutorID())
	}
	if ctxPF.TargetResourceKind() != "tool" {
		t.Fatalf("unexpected target kind: %s", ctxPF.TargetResourceKind())
	}
	if ctxPF.ResolutionProfile() != "res-1" {
		t.Fatalf("unexpected res profile: %s", ctxPF.ResolutionProfile())
	}

	// advisory ok
	ctxAdv, err := reg.Context(action.Advisory, "prof-1", "route-fs")
	if err != nil {
		t.Fatalf("Context(Advisory) failed: %v", err)
	}
	if ctxAdv.Boundary() != action.Advisory {
		t.Fatalf("unexpected boundary: %s", ctxAdv.Boundary())
	}
	if ctxAdv.TargetResourceKind() != "filesystem" {
		t.Fatalf("unexpected target kind: %s", ctxAdv.TargetResourceKind())
	}

	// execution_gateway rejected with ErrSchema
	_, err = reg.Context(action.ExecutionGateway, "prof-1", "route-tool")
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for ExecutionGateway, got %v", err)
	}

	// empty boundary rejected
	_, err = reg.Context("", "prof-1", "route-tool")
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for empty boundary, got %v", err)
	}

	// case-sensitive check ("Advisory") rejected
	_, err = reg.Context("Advisory", "prof-1", "route-tool")
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for 'Advisory', got %v", err)
	}

	// unknown profile ErrProtocolUnsupported
	_, err = reg.Context(action.ProposalFilter, "unknown-prof", "route-tool")
	if !errors.Is(err, action.ErrProtocolUnsupported) {
		t.Fatalf("expected ErrProtocolUnsupported for unknown profile, got %v", err)
	}

	// unknown route ErrSchema
	_, err = reg.Context(action.ProposalFilter, "prof-1", "unknown-route")
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for unknown route, got %v", err)
	}

	// zero Context rejected by NormalizeAction
	var zeroCtx action.Context
	_, err = action.NormalizeAction(zeroCtx, defaultTestActor, "tool-a", []byte(`{"arg":"val"}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for zero Context, got %v", err)
	}
}

func TestCrossTool(t *testing.T) {
	// CROSS-TOOL (must fail against a route-pinned schema design):
	// registry with tools A (schema {a: string}) and B (schema {b: integer}) behind ONE tool.invoke route.
	toolA := action.Tool{
		ToolID:        "tool-a",
		UpstreamID:    "upstream-a",
		UpstreamName:  "tool_a",
		PayloadSchema: "schema-tool-a",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"a": action.String,
			},
		},
	}
	toolB := action.Tool{
		ToolID:        "tool-b",
		UpstreamID:    "upstream-b",
		UpstreamName:  "tool_b",
		PayloadSchema: "schema-tool-b",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"b": action.Integer,
			},
		},
	}

	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-invoke", "tool-a", "tool-b")},
		[]action.Tool{toolA, toolB},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-invoke")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	// NormalizeAction(ctx, "tool-a", {"a":"x"}) ok with tool A's payload_schema and revision
	actA, err := action.NormalizeAction(ctx, defaultTestActor, "tool-a", []byte(`{"a":"x"}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction tool-a failed: %v", err)
	}
	tcA, ok := actA.TrustedContext()
	if !ok {
		t.Fatalf("expected TrustedContext to be true for tool-a")
	}
	if tcA.PayloadSchema() != "schema-tool-a" {
		t.Fatalf("expected schema-tool-a, got %s", tcA.PayloadSchema())
	}
	if tcA.ToolRevision() == "" {
		t.Fatalf("expected non-empty tool revision")
	}

	// NormalizeAction(ctx, "tool-b", {"a":"x"}) rejects (schema B requires integer "b")
	_, err = action.NormalizeAction(ctx, defaultTestActor, "tool-b", []byte(`{"a":"x"}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for tool-b with invalid payload, got %v", err)
	}

	// NormalizeAction(ctx, "tool-b", {"b":1}) ok with B's revision != A's
	actB, err := action.NormalizeAction(ctx, defaultTestActor, "tool-b", []byte(`{"b":1}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction tool-b failed: %v", err)
	}
	tcB, ok := actB.TrustedContext()
	if !ok {
		t.Fatalf("expected TrustedContext to be true for tool-b")
	}
	if tcB.PayloadSchema() != "schema-tool-b" {
		t.Fatalf("expected schema-tool-b, got %s", tcB.PayloadSchema())
	}
	if tcB.ToolRevision() == "" {
		t.Fatalf("expected non-empty tool revision")
	}
	if tcB.ToolRevision() == tcA.ToolRevision() {
		t.Fatalf("expected B's revision != A's revision, but both are %s", tcA.ToolRevision())
	}

	// unknown "tool-c" -> ErrToolRevisionUnknown
	_, err = action.NormalizeAction(ctx, defaultTestActor, "tool-c", []byte(`{"a":"x"}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrToolRevisionUnknown) {
		t.Fatalf("expected ErrToolRevisionUnknown for tool-c, got %v", err)
	}
}

func TestToolRevisionPropertiesAndPinnedVector(t *testing.T) {
	// Pinned vector computation:
	// Small tool:
	// ToolID: "my-tool", UpstreamID: "upstream-a", UpstreamName: "search"
	// PayloadSchema: "schema-v1"
	// Schema: Fields: {"query": String}
	pinnedTool := action.Tool{
		ToolID:        "my-tool",
		UpstreamID:    "upstream-a",
		UpstreamName:  "search",
		PayloadSchema: "schema-v1",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"query": action.String,
			},
		},
	}

	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "my-tool")},
		[]action.Tool{pinnedTool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-tool")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	act, err := action.NormalizeAction(ctx, defaultTestActor, "my-tool", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	tc, ok := act.TrustedContext()
	if !ok {
		t.Fatalf("TrustedContext failed")
	}

	// Literal hand-written preimage string (not calling encoder):
	literalPreimage := "GuardFil.ToolRevision.v1\n" + `{"payload_schema":"schema-v1","schema":{"fields":{"query":"string"},"recursive_fields":{}},"tool_id":"my-tool","upstream_id":"upstream-a","upstream_name":"search"}`
	h := sha256.Sum256([]byte(literalPreimage))
	expectedDigest := "sha256:" + hex.EncodeToString(h[:])

	// Assert the hand-computed vector matches literal expected SHA-256:
	const pinnedDigest = "sha256:dbfd328c301d10025a5205466a275f3c4b7d4a981e573c5396ce4a81ea1b8bd2"
	if expectedDigest != pinnedDigest {
		t.Fatalf("hand-computed digest mismatch: got %s, expected %s", expectedDigest, pinnedDigest)
	}
	if tc.ToolRevision() != pinnedDigest {
		t.Fatalf("registered tool revision mismatch: got %s, expected pinned %s", tc.ToolRevision(), pinnedDigest)
	}

	// Pinned vector covering recursive_fields:
	pinnedRecursiveTool := action.Tool{
		ToolID:        "deep-tool",
		UpstreamID:    "upstream-b",
		UpstreamName:  "deep_search",
		PayloadSchema: "schema-v2",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"q": action.String,
			},
			RecursiveFields: map[string]action.Field{
				"opts": {
					Type: action.Object,
					Properties: map[string]action.Field{
						"n": {Type: action.Integer},
						"tags": {
							Type:  action.Array,
							Items: &action.Field{Type: action.String},
						},
					},
				},
			},
		},
	}

	regRec, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "deep-tool")},
		[]action.Tool{pinnedRecursiveTool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed for recursive tool: %v", err)
	}

	ctxRec, err := regRec.Context(action.ProposalFilter, "prof-1", "route-tool")
	if err != nil {
		t.Fatalf("Context failed for recursive tool: %v", err)
	}

	actRec, err := action.NormalizeAction(ctxRec, defaultTestActor, "deep-tool", []byte(`{"q":"x","opts":{"n":1,"tags":["a"]}}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed for recursive tool: %v", err)
	}
	tcRec, ok := actRec.TrustedContext()
	if !ok {
		t.Fatalf("TrustedContext failed for recursive tool")
	}

	literalRecPreimage := "GuardFil.ToolRevision.v1\n" + `{"payload_schema":"schema-v2","schema":{"fields":{"q":"string"},"recursive_fields":{"opts":{"properties":{"n":{"type":"integer"},"tags":{"items":{"type":"string"},"type":"array"}},"type":"object"}}},"tool_id":"deep-tool","upstream_id":"upstream-b","upstream_name":"deep_search"}`
	hRec := sha256.Sum256([]byte(literalRecPreimage))
	expectedRecDigest := "sha256:" + hex.EncodeToString(hRec[:])

	const pinnedRecDigest = "sha256:137c96f40660b0ea9e8561c310e2ce324cbf5361de43f0120d4126751dab51c7"
	if expectedRecDigest != pinnedRecDigest {
		t.Fatalf("hand-computed recursive digest mismatch: got %s, expected %s", expectedRecDigest, pinnedRecDigest)
	}
	if tcRec.ToolRevision() != pinnedRecDigest {
		t.Fatalf("registered recursive tool revision mismatch: got %s, expected pinned %s", tcRec.ToolRevision(), pinnedRecDigest)
	}

	// Pinned vector 3: Non-tool route:
	pinnedRoute := action.Route{
		RouteID:           "route-fs",
		ExecutorID:        "exec-fs",
		Operation:         "fs.read",
		ResolutionProfile: "res-1",
		PayloadSchema:     "schema-fs",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"path": action.String,
			},
		},
	}
	regRoute, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{pinnedRoute},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed for pinned route: %v", err)
	}
	ctxRoute, err := regRoute.Context(action.ProposalFilter, "prof-1", "route-fs")
	if err != nil {
		t.Fatalf("Context failed for pinned route: %v", err)
	}
	actRoute, err := action.NormalizeAction(ctxRoute, defaultTestActor, "/test/path", []byte(`{"path":"/some/file"}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed for pinned route: %v", err)
	}
	tcRoute, ok := actRoute.TrustedContext()
	if !ok {
		t.Fatalf("TrustedContext failed for pinned route")
	}

	literalRoutePreimage := "GuardFil.ToolRevision.v1\n" + `{"executor_id":"exec-fs","operation":"fs.read","payload_schema":"schema-fs","resolution_profile":"res-1","route_id":"route-fs","schema":{"fields":{"path":"string"},"recursive_fields":{}}}`
	hRoute := sha256.Sum256([]byte(literalRoutePreimage))
	expectedRouteDigest := "sha256:" + hex.EncodeToString(hRoute[:])

	const pinnedRouteDigest = "sha256:379bcaf9f4b948991e54087fefd9104bd8f836a60b4770e150e3fbc46c9d9817"
	if expectedRouteDigest != pinnedRouteDigest {
		t.Fatalf("hand-computed route digest mismatch: got %s, expected %s", expectedRouteDigest, pinnedRouteDigest)
	}
	if tcRoute.ToolRevision() != pinnedRouteDigest {
		t.Fatalf("registered route revision mismatch: got %s, expected pinned %s", tcRoute.ToolRevision(), pinnedRouteDigest)
	}

	// Pinned vector 4: Non-ASCII upstream_name ("búsqueda"):
	pinnedIntlTool := action.Tool{
		ToolID:        "intl-tool",
		UpstreamID:    "upstream-c",
		UpstreamName:  "búsqueda",
		PayloadSchema: "schema-v1",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"query": action.String,
			},
		},
	}
	regIntl, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-intl", "intl-tool")},
		[]action.Tool{pinnedIntlTool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed for pinned intl tool: %v", err)
	}
	ctxIntl, err := regIntl.Context(action.ProposalFilter, "prof-1", "route-intl")
	if err != nil {
		t.Fatalf("Context failed for pinned intl tool: %v", err)
	}
	actIntl, err := action.NormalizeAction(ctxIntl, defaultTestActor, "intl-tool", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed for pinned intl tool: %v", err)
	}
	tcIntl, ok := actIntl.TrustedContext()
	if !ok {
		t.Fatalf("TrustedContext failed for pinned intl tool")
	}

	literalIntlPreimage := "GuardFil.ToolRevision.v1\n" + `{"payload_schema":"schema-v1","schema":{"fields":{"query":"string"},"recursive_fields":{}},"tool_id":"intl-tool","upstream_id":"upstream-c","upstream_name":"búsqueda"}`
	hIntl := sha256.Sum256([]byte(literalIntlPreimage))
	expectedIntlDigest := "sha256:" + hex.EncodeToString(hIntl[:])

	const pinnedIntlDigest = "sha256:275fb65ffd1d25ef44e5a20209a0c5e7e88350c6a5a708b63e8fd7eee8f8a3c3"
	if expectedIntlDigest != pinnedIntlDigest {
		t.Fatalf("hand-computed intl digest mismatch: got %s, expected %s", expectedIntlDigest, pinnedIntlDigest)
	}
	if tcIntl.ToolRevision() != pinnedIntlDigest {
		t.Fatalf("registered intl tool revision mismatch: got %s, expected pinned %s", tcIntl.ToolRevision(), pinnedIntlDigest)
	}

	// Determinism: equal for two registries built from identical input
	reg2, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "my-tool")},
		[]action.Tool{pinnedTool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry 2 failed: %v", err)
	}
	ctx2, _ := reg2.Context(action.ProposalFilter, "prof-1", "route-tool")
	act2, _ := action.NormalizeAction(ctx2, defaultTestActor, "my-tool", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	tc2, _ := act2.TrustedContext()
	if tc.ToolRevision() != tc2.ToolRevision() {
		t.Fatalf("expected identical tool_revision across registries, got %s vs %s", tc.ToolRevision(), tc2.ToolRevision())
	}

	// Coordinator-requested test: Schema with nil maps and one with empty non-nil maps produce the same tool_revision
	toolNilMaps := action.Tool{
		ToolID:        "tool-nil-maps",
		UpstreamID:    "upstream-1",
		UpstreamName:  "nil_maps",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			Fields:          nil,
			RecursiveFields: nil,
		},
	}
	toolEmptyMaps := action.Tool{
		ToolID:        "tool-nil-maps",
		UpstreamID:    "upstream-1",
		UpstreamName:  "nil_maps",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			Fields:          map[string]action.FieldType{},
			RecursiveFields: map[string]action.Field{},
		},
	}
	regNil, err := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "tool-nil-maps")}, []action.Tool{toolNilMaps}, nil)
	if err != nil {
		t.Fatalf("regNil failed: %v", err)
	}
	regEmpty, err := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "tool-nil-maps")}, []action.Tool{toolEmptyMaps}, nil)
	if err != nil {
		t.Fatalf("regEmpty failed: %v", err)
	}
	ctxNil, _ := regNil.Context(action.ProposalFilter, "p", "r")
	ctxEmpty, _ := regEmpty.Context(action.ProposalFilter, "p", "r")
	actNil, _ := action.NormalizeAction(ctxNil, defaultTestActor, "tool-nil-maps", []byte(`{}`), defaultTestEnvelope, nil)
	actEmpty, _ := action.NormalizeAction(ctxEmpty, defaultTestActor, "tool-nil-maps", []byte(`{}`), defaultTestEnvelope, nil)
	tcNil, _ := actNil.TrustedContext()
	tcEmpty, _ := actEmpty.TrustedContext()
	if tcNil.ToolRevision() != tcEmpty.ToolRevision() {
		t.Fatalf("nil maps vs empty maps produced different revisions: %s vs %s", tcNil.ToolRevision(), tcEmpty.ToolRevision())
	}

	// tool_revision changes when field type changes
	toolChangedType := pinnedTool
	toolChangedType.Schema = action.Schema{Fields: map[string]action.FieldType{"query": action.Integer}}
	regChangedType, _ := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "my-tool")}, []action.Tool{toolChangedType}, nil)
	ctxCT, _ := regChangedType.Context(action.ProposalFilter, "p", "r")
	actCT, _ := action.NormalizeAction(ctxCT, defaultTestActor, "my-tool", []byte(`{"query":123}`), defaultTestEnvelope, nil)
	tcCT, _ := actCT.TrustedContext()
	if tcCT.ToolRevision() == tc.ToolRevision() {
		t.Fatalf("tool revision did not change when field type changed")
	}

	// tool_revision changes when payload_schema changes
	toolChangedPS := pinnedTool
	toolChangedPS.PayloadSchema = "schema-v2"
	regChangedPS, _ := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "my-tool")}, []action.Tool{toolChangedPS}, nil)
	ctxCPS, _ := regChangedPS.Context(action.ProposalFilter, "p", "r")
	actCPS, _ := action.NormalizeAction(ctxCPS, defaultTestActor, "my-tool", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	tcCPS, _ := actCPS.TrustedContext()
	if tcCPS.ToolRevision() == tc.ToolRevision() {
		t.Fatalf("tool revision did not change when payload_schema changed")
	}

	// tool_revision changes when tool_id changes
	toolChangedID := pinnedTool
	toolChangedID.ToolID = "my-tool-2"
	regChangedID, _ := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "my-tool-2")}, []action.Tool{toolChangedID}, nil)
	ctxCID, _ := regChangedID.Context(action.ProposalFilter, "p", "r")
	actCID, _ := action.NormalizeAction(ctxCID, defaultTestActor, "my-tool-2", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	tcCID, _ := actCID.TrustedContext()
	if tcCID.ToolRevision() == tc.ToolRevision() {
		t.Fatalf("tool revision did not change when tool_id changed")
	}

	// tool_revision changes when recursive properties/items change
	toolNested := action.Tool{
		ToolID:        "nested-tool",
		UpstreamID:    "upstream-1",
		UpstreamName:  "nested",
		PayloadSchema: "ps-nested",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"obj": {
					Type: action.Object,
					Properties: map[string]action.Field{
						"sub": {Type: action.String},
					},
				},
			},
		},
	}
	toolNestedMod := action.Tool{
		ToolID:        "nested-tool",
		UpstreamID:    "upstream-1",
		UpstreamName:  "nested",
		PayloadSchema: "ps-nested",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"obj": {
					Type: action.Object,
					Properties: map[string]action.Field{
						"sub": {Type: action.Integer},
					},
				},
			},
		},
	}
	toolArray := action.Tool{
		ToolID:        "nested-tool",
		UpstreamID:    "upstream-1",
		UpstreamName:  "nested",
		PayloadSchema: "ps-nested",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"arr": {
					Type:  action.Array,
					Items: &action.Field{Type: action.String},
				},
			},
		},
	}
	regN1, _ := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "nested-tool")}, []action.Tool{toolNested}, nil)
	regN2, _ := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "nested-tool")}, []action.Tool{toolNestedMod}, nil)
	regArr, _ := action.NewRegistry([]action.Profile{validProfile("p")}, []action.Route{validToolRoute("r", "nested-tool")}, []action.Tool{toolArray}, nil)
	ctxN1, _ := regN1.Context(action.ProposalFilter, "p", "r")
	ctxN2, _ := regN2.Context(action.ProposalFilter, "p", "r")
	ctxArr, _ := regArr.Context(action.ProposalFilter, "p", "r")
	actN1, _ := action.NormalizeAction(ctxN1, defaultTestActor, "nested-tool", []byte(`{"obj":{"sub":"hi"}}`), defaultTestEnvelope, nil)
	actN2, _ := action.NormalizeAction(ctxN2, defaultTestActor, "nested-tool", []byte(`{"obj":{"sub":42}}`), defaultTestEnvelope, nil)
	actArr, _ := action.NormalizeAction(ctxArr, defaultTestActor, "nested-tool", []byte(`{"arr":["a"]}`), defaultTestEnvelope, nil)
	tcN1, _ := actN1.TrustedContext()
	tcN2, _ := actN2.TrustedContext()
	tcArr, _ := actArr.TrustedContext()
	if tcN1.ToolRevision() == tcN2.ToolRevision() {
		t.Fatalf("tool revision did not change when nested property changed")
	}
	if tcN1.ToolRevision() == tcArr.ToolRevision() {
		t.Fatalf("tool revision did not change when object became array")
	}
}

func TestDeepCopyRegistrySchema(t *testing.T) {
	// Deep copy: mutate the input Schema maps/nested fields after NewRegistry ->
	// registered schema/revision unchanged (assert via NormalizeAction admission and TrustedContext().ToolRevision()).
	fields := map[string]action.FieldType{
		"orig": action.String,
	}
	props := map[string]action.Field{
		"inner": {Type: action.String},
	}
	recFields := map[string]action.Field{
		"nested": {
			Type:       action.Object,
			Properties: props,
		},
	}
	inputSchema := action.Schema{
		Fields:          fields,
		RecursiveFields: recFields,
	}
	tool := action.Tool{
		ToolID:        "mutate-tool",
		UpstreamID:    "upstream-1",
		UpstreamName:  "mutate",
		PayloadSchema: "ps-mutate",
		Schema:        inputSchema,
	}

	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "mutate-tool")},
		[]action.Tool{tool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-tool")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	// Capture initial baseline
	actBefore, err := action.NormalizeAction(ctx, defaultTestActor, "mutate-tool", []byte(`{"orig":"ok","nested":{"inner":"val"}}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction before mutation failed: %v", err)
	}
	tcBefore, _ := actBefore.TrustedContext()
	initRevision := tcBefore.ToolRevision()

	// Mutate caller input maps after NewRegistry
	fields["added"] = action.Integer
	fields["orig"] = action.Integer
	props["inner"] = action.Field{Type: action.Integer}
	props["extra"] = action.Field{Type: action.Boolean}
	recFields["injected"] = action.Field{Type: action.String}

	// Assert registered schema is unchanged:
	// 1) The original payload must still admit
	actAfter, err := action.NormalizeAction(ctx, defaultTestActor, "mutate-tool", []byte(`{"orig":"ok","nested":{"inner":"val"}}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction after caller mutation rejected original payload: %v", err)
	}
	tcAfter, _ := actAfter.TrustedContext()
	if tcAfter.ToolRevision() != initRevision {
		t.Fatalf("ToolRevision changed after caller mutation: was %s, now %s", initRevision, tcAfter.ToolRevision())
	}

	// 2) Mutated payload types must reject
	_, err = action.NormalizeAction(ctx, defaultTestActor, "mutate-tool", []byte(`{"orig":123,"nested":{"inner":"val"}}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema when passing integer for orig string field, got %v", err)
	}
	_, err = action.NormalizeAction(ctx, defaultTestActor, "mutate-tool", []byte(`{"orig":"ok","nested":{"inner":123}}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema when passing integer for inner string property, got %v", err)
	}
	_, err = action.NormalizeAction(ctx, defaultTestActor, "mutate-tool", []byte(`{"added":1}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema when passing injected field, got %v", err)
	}
}

func TestNormalizeActionHasDigestAndNormalizeRequestDoesNot(t *testing.T) {
	// NormalizeAction produces an authorizable action with non-empty digest, while NormalizeRequest produces a valid non-authorizable action with empty digest.
	schema := action.Schema{
		Fields: map[string]action.FieldType{
			"param": action.String,
		},
	}
	tool := action.Tool{
		ToolID:        "digest-tool",
		UpstreamID:    "upstream-1",
		UpstreamName:  "digest",
		PayloadSchema: "ps-digest",
		Schema:        schema,
	}
	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "digest-tool")},
		[]action.Tool{tool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-tool")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	payload := []byte(`{"param":"hello-world"}`)
	actFromAction, err := action.NormalizeAction(ctx, defaultTestActor, "digest-tool", payload, defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}

	actFromRequest, err := action.NormalizeRequest("tool.invoke", "digest-tool", payload, schema)
	if err != nil {
		t.Fatalf("NormalizeRequest failed: %v", err)
	}

	if actFromRequest.Digest != "" || actFromRequest.Authorizable() {
		t.Fatalf("expected NormalizeRequest digest to be empty and Authorizable false, got digest=%s", actFromRequest.Digest)
	}
	if actFromAction.Digest == "" || !actFromAction.Authorizable() {
		t.Fatalf("expected NormalizeAction digest non-empty and Authorizable true, got digest=%s", actFromAction.Digest)
	}
	if string(actFromAction.Payload) != string(actFromRequest.Payload) {
		t.Fatalf("payload mismatch")
	}

	// Also check for non-tool route (fs.read)
	fsRoute := action.Route{
		RouteID:           "route-fs",
		ExecutorID:        "exec-fs",
		Operation:         "fs.read",
		ResolutionProfile: "res-fs",
		PayloadSchema:     "ps-fs",
		Schema:            schema,
	}
	regFS, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{fsRoute},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry FS failed: %v", err)
	}
	ctxFS, err := regFS.Context(action.Advisory, "prof-1", "route-fs")
	if err != nil {
		t.Fatalf("Context FS failed: %v", err)
	}

	fsPayload := []byte(`{"param":"/some/data"}`)
	actFSFromAction, err := action.NormalizeAction(ctxFS, defaultTestActor, "/some/path", fsPayload, defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction FS failed: %v", err)
	}
	actFSFromRequest, err := action.NormalizeRequest("fs.read", "/some/path", fsPayload, schema)
	if err != nil {
		t.Fatalf("NormalizeRequest FS failed: %v", err)
	}
	if actFSFromRequest.Digest != "" || actFSFromRequest.Authorizable() {
		t.Fatalf("expected NormalizeRequest FS digest to be empty and Authorizable false, got digest=%s", actFSFromRequest.Digest)
	}
	if actFSFromAction.Digest == "" || !actFSFromAction.Authorizable() {
		t.Fatalf("expected NormalizeAction FS digest non-empty and Authorizable true, got digest=%s", actFSFromAction.Digest)
	}
}

func TestTrustedContextPresenceAndInvalidation(t *testing.T) {
	schema := action.Schema{
		Fields: map[string]action.FieldType{
			"x": action.String,
		},
	}
	tool := action.Tool{
		ToolID:        "tc-tool",
		UpstreamID:    "upstream-1",
		UpstreamName:  "tc",
		PayloadSchema: "ps-tc",
		Schema:        schema,
	}
	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tc", "tc-tool")},
		[]action.Tool{tool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-tc")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	payload := []byte(`{"x":"valid"}`)

	// NormalizeAction: present with all ten values
	act, err := action.NormalizeAction(ctx, defaultTestActor, "tc-tool", payload, defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	tc, ok := act.TrustedContext()
	if !ok {
		t.Fatalf("expected TrustedContext to be true for NormalizeAction")
	}
	if tc.Boundary() != action.ProposalFilter {
		t.Fatalf("unexpected Boundary: %s", tc.Boundary())
	}
	if tc.Protocol() != "decision_api" {
		t.Fatalf("unexpected Protocol: %s", tc.Protocol())
	}
	if tc.Profile() != "prof-1" {
		t.Fatalf("unexpected Profile: %s", tc.Profile())
	}
	if tc.AdapterRevision() != testValidDigest {
		t.Fatalf("unexpected AdapterRevision: %s", tc.AdapterRevision())
	}
	if tc.RouteID() != "route-tc" {
		t.Fatalf("unexpected RouteID: %s", tc.RouteID())
	}
	if tc.ExecutorID() != "exec-1" {
		t.Fatalf("unexpected ExecutorID: %s", tc.ExecutorID())
	}
	if tc.TargetResourceKind() != "tool" {
		t.Fatalf("unexpected TargetResourceKind: %s", tc.TargetResourceKind())
	}
	if tc.ResolutionProfile() != "res-1" {
		t.Fatalf("unexpected ResolutionProfile: %s", tc.ResolutionProfile())
	}
	if tc.PayloadSchema() != "ps-tc" {
		t.Fatalf("unexpected PayloadSchema: %s", tc.PayloadSchema())
	}
	if tc.ToolRevision() == "" {
		t.Fatalf("unexpected empty ToolRevision")
	}

	// NormalizeRequest: absent (false)
	actReq, err := action.NormalizeRequest("tool.invoke", "tc-tool", payload, schema)
	if err != nil {
		t.Fatalf("NormalizeRequest failed: %v", err)
	}
	if _, ok := actReq.TrustedContext(); ok {
		t.Fatalf("expected TrustedContext to be false for NormalizeRequest")
	}

	// NormalizePayload: absent (false)
	actPayload, err := action.NormalizePayload("tool.invoke", payload, schema)
	if err != nil {
		t.Fatalf("NormalizePayload failed: %v", err)
	}
	if _, ok := actPayload.TrustedContext(); ok {
		t.Fatalf("expected TrustedContext to be false for NormalizePayload")
	}

	// Mutating any exported field invalidates the seal and TrustedContext() returns false
	mutations := []func(a action.Action) action.Action{
		func(a action.Action) action.Action { a.SchemaVersion = "guardfil.action/other"; return a },
		func(a action.Action) action.Action { a.Operation = "other.op"; return a },
		func(a action.Action) action.Action { a.ResourceKind = "filesystem"; return a },
		func(a action.Action) action.Action { a.Resource = "other-tool"; return a },
		func(a action.Action) action.Action { a.Payload = []byte(`{"x":"mutated"}`); return a },
		func(a action.Action) action.Action {
			a.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			return a
		},
	}
	for i, mutate := range mutations {
		mutated := mutate(act)
		if _, ok := mutated.TrustedContext(); ok {
			t.Fatalf("mutation %d: expected TrustedContext to be false after mutation", i)
		}
	}
}

func TestCrossRegistry(t *testing.T) {
	// A Context from registry R1 with a tool only registered in R2 -> ErrToolRevisionUnknown
	tool1 := action.Tool{
		ToolID:        "tool-r1",
		UpstreamID:    "upstream-1",
		UpstreamName:  "tool_r1",
		PayloadSchema: "ps-1",
		Schema:        action.Schema{Fields: map[string]action.FieldType{"a": action.String}},
	}
	tool2 := action.Tool{
		ToolID:        "tool-r2",
		UpstreamID:    "upstream-1",
		UpstreamName:  "tool_r2",
		PayloadSchema: "ps-2",
		Schema:        action.Schema{Fields: map[string]action.FieldType{"b": action.String}},
	}

	r1, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "tool-r1")},
		[]action.Tool{tool1},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry R1 failed: %v", err)
	}

	_, err = action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "tool-r2")},
		[]action.Tool{tool2},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry R2 failed: %v", err)
	}

	ctx1, err := r1.Context(action.ProposalFilter, "prof-1", "route-tool")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	// Tool-r2 exists in R2, but Context is from R1
	_, err = action.NormalizeAction(ctx1, defaultTestActor, "tool-r2", []byte(`{"b":"x"}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrToolRevisionUnknown) {
		t.Fatalf("expected ErrToolRevisionUnknown for tool only registered in R2, got %v", err)
	}
}

func TestRouteAllowlistQA(t *testing.T) {
	// 4. Allowlist: tools a, b registered; route r1 allowlists [a], route r2 allowlists [b].
	// Via r1: "tool-a"-style resource ok; b -> ErrToolRevisionUnknown.
	// Tool route with empty Tools, with an unregistered entry, with duplicates, and a non-tool route with Tools -> ErrSchema.
	toolA := action.Tool{
		ToolID:        "tool-a",
		UpstreamID:    "up-a",
		UpstreamName:  "name_a",
		PayloadSchema: "ps-a",
		Schema:        action.Schema{Fields: map[string]action.FieldType{"x": action.String}},
	}
	toolB := action.Tool{
		ToolID:        "tool-b",
		UpstreamID:    "up-b",
		UpstreamName:  "name_b",
		PayloadSchema: "ps-b",
		Schema:        action.Schema{Fields: map[string]action.FieldType{"x": action.String}},
	}

	r1 := action.Route{
		RouteID:           "r1",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             []string{"tool-a"},
	}
	r2 := action.Route{
		RouteID:           "r2",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             []string{"tool-b"},
	}

	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{r1, r2},
		[]action.Tool{toolA, toolB},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	ctx1, err := reg.Context(action.ProposalFilter, "prof-1", "r1")
	if err != nil {
		t.Fatalf("Context r1 failed: %v", err)
	}
	ctx2, err := reg.Context(action.ProposalFilter, "prof-1", "r2")
	if err != nil {
		t.Fatalf("Context r2 failed: %v", err)
	}

	// Via r1: tool-a ok
	act1A, err := action.NormalizeAction(ctx1, defaultTestActor, "tool-a", []byte(`{"x":"hello"}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction r1 tool-a failed: %v", err)
	}
	if act1A.Digest == "" {
		t.Fatalf("expected non-empty digest")
	}

	// Via r1: tool-b -> ErrToolRevisionUnknown
	_, err = action.NormalizeAction(ctx1, defaultTestActor, "tool-b", []byte(`{"x":"hello"}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrToolRevisionUnknown) {
		t.Fatalf("expected ErrToolRevisionUnknown for tool-b via r1, got %v", err)
	}

	// Via r2: tool-b ok
	act2B, err := action.NormalizeAction(ctx2, defaultTestActor, "tool-b", []byte(`{"x":"hello"}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction r2 tool-b failed: %v", err)
	}
	if act2B.Digest == "" {
		t.Fatalf("expected non-empty digest")
	}

	// Via r2: tool-a -> ErrToolRevisionUnknown
	_, err = action.NormalizeAction(ctx2, defaultTestActor, "tool-a", []byte(`{"x":"hello"}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrToolRevisionUnknown) {
		t.Fatalf("expected ErrToolRevisionUnknown for tool-a via r2, got %v", err)
	}

	// Tool route with empty Tools -> ErrSchema
	rEmptyTools := action.Route{
		RouteID:           "r-empty",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             nil,
	}
	_, err = action.NewRegistry([]action.Profile{validProfile("prof-1")}, []action.Route{rEmptyTools}, []action.Tool{toolA}, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for tool route with empty Tools, got %v", err)
	}

	rEmptySlice := action.Route{
		RouteID:           "r-empty-slice",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             []string{},
	}
	_, err = action.NewRegistry([]action.Profile{validProfile("prof-1")}, []action.Route{rEmptySlice}, []action.Tool{toolA}, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for tool route with empty Tools slice, got %v", err)
	}

	// Tool route with unregistered entry -> ErrSchema
	rUnregistered := action.Route{
		RouteID:           "r-unreg",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             []string{"tool-unregistered"},
	}
	_, err = action.NewRegistry([]action.Profile{validProfile("prof-1")}, []action.Route{rUnregistered}, []action.Tool{toolA}, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for tool route with unregistered entry, got %v", err)
	}

	// Tool route with duplicates -> ErrSchema
	rDup := action.Route{
		RouteID:           "r-dup",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             []string{"tool-a", "tool-a"},
	}
	_, err = action.NewRegistry([]action.Profile{validProfile("prof-1")}, []action.Route{rDup}, []action.Tool{toolA}, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for tool route with duplicate tool IDs, got %v", err)
	}

	// Non-tool route with Tools -> ErrSchema
	rNonToolWithTools := action.Route{
		RouteID:           "r-non-tool",
		ExecutorID:        "exec-1",
		Operation:         "fs.read",
		ResolutionProfile: "res-1",
		PayloadSchema:     "ps-fs",
		Schema:            action.Schema{Fields: map[string]action.FieldType{"path": action.String}},
		Tools:             []string{"tool-a"},
	}
	_, err = action.NewRegistry([]action.Profile{validProfile("prof-1")}, []action.Route{rNonToolWithTools}, []action.Tool{toolA}, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for non-tool route with Tools, got %v", err)
	}
}

func TestToolAndRouteRevisionVariantsQA(t *testing.T) {
	// 5. Each of upstream_id, upstream_name changes the tool revision;
	// each of executor_id, operation (fs.read vs fs.write), resolution_profile changes the non-tool route revision.
	// UpstreamName with "\n" or 0x7F or 257 bytes -> ErrSchema.
	baseTool := action.Tool{
		ToolID:        "my-tool",
		UpstreamID:    "upstream-base",
		UpstreamName:  "search_base",
		PayloadSchema: "schema-v1",
		Schema:        action.Schema{Fields: map[string]action.FieldType{"query": action.String}},
	}
	regBase, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "my-tool")},
		[]action.Tool{baseTool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry baseTool failed: %v", err)
	}
	ctxBase, _ := regBase.Context(action.ProposalFilter, "prof-1", "route-tool")
	actBase, _ := action.NormalizeAction(ctxBase, defaultTestActor, "my-tool", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	tcBase, _ := actBase.TrustedContext()
	baseToolRev := tcBase.ToolRevision()

	// UpstreamID change -> changes tool revision
	toolUpID := baseTool
	toolUpID.UpstreamID = "upstream-changed"
	regUpID, _ := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "my-tool")},
		[]action.Tool{toolUpID},
		nil,
	)
	ctxUpID, _ := regUpID.Context(action.ProposalFilter, "prof-1", "route-tool")
	actUpID, _ := action.NormalizeAction(ctxUpID, defaultTestActor, "my-tool", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	tcUpID, _ := actUpID.TrustedContext()
	if tcUpID.ToolRevision() == baseToolRev {
		t.Fatalf("expected tool revision to change when upstream_id changes")
	}

	// UpstreamName change -> changes tool revision
	toolUpName := baseTool
	toolUpName.UpstreamName = "search_changed"
	regUpName, _ := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-tool", "my-tool")},
		[]action.Tool{toolUpName},
		nil,
	)
	ctxUpName, _ := regUpName.Context(action.ProposalFilter, "prof-1", "route-tool")
	actUpName, _ := action.NormalizeAction(ctxUpName, defaultTestActor, "my-tool", []byte(`{"query":"test"}`), defaultTestEnvelope, nil)
	tcUpName, _ := actUpName.TrustedContext()
	if tcUpName.ToolRevision() == baseToolRev {
		t.Fatalf("expected tool revision to change when upstream_name changes")
	}

	// Non-tool route: each of executor_id, operation (fs.read vs fs.write), resolution_profile changes revision
	baseRoute := action.Route{
		RouteID:           "route-test",
		ExecutorID:        "exec-base",
		Operation:         "fs.read",
		ResolutionProfile: "res-base",
		PayloadSchema:     "ps-base",
		Schema:            action.Schema{Fields: map[string]action.FieldType{"path": action.String}},
	}
	regRouteBase, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{baseRoute},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry baseRoute failed: %v", err)
	}
	ctxRouteBase, _ := regRouteBase.Context(action.ProposalFilter, "prof-1", "route-test")
	actRouteBase, _ := action.NormalizeAction(ctxRouteBase, defaultTestActor, "/test", []byte(`{"path":"/a"}`), defaultTestEnvelope, nil)
	tcRouteBase, _ := actRouteBase.TrustedContext()
	baseRouteRev := tcRouteBase.ToolRevision()

	// ExecutorID change -> changes route revision
	routeExec := baseRoute
	routeExec.ExecutorID = "exec-changed"
	regRouteExec, _ := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{routeExec},
		nil,
		nil,
	)
	ctxRouteExec, _ := regRouteExec.Context(action.ProposalFilter, "prof-1", "route-test")
	actRouteExec, _ := action.NormalizeAction(ctxRouteExec, defaultTestActor, "/test", []byte(`{"path":"/a"}`), defaultTestEnvelope, nil)
	tcRouteExec, _ := actRouteExec.TrustedContext()
	if tcRouteExec.ToolRevision() == baseRouteRev {
		t.Fatalf("expected route revision to change when executor_id changes")
	}

	// Operation change (fs.read vs fs.write) -> changes route revision
	routeOp := baseRoute
	routeOp.Operation = "fs.write"
	regRouteOp, _ := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{routeOp},
		nil,
		nil,
	)
	ctxRouteOp, _ := regRouteOp.Context(action.ProposalFilter, "prof-1", "route-test")
	actRouteOp, _ := action.NormalizeAction(ctxRouteOp, defaultTestActor, "/test", []byte(`{"path":"/a"}`), defaultTestEnvelope, nil)
	tcRouteOp, _ := actRouteOp.TrustedContext()
	if tcRouteOp.ToolRevision() == baseRouteRev {
		t.Fatalf("expected route revision to change when operation changes (fs.read vs fs.write)")
	}

	// ResolutionProfile change -> changes route revision
	routeRes := baseRoute
	routeRes.ResolutionProfile = "res-changed"
	regRouteRes, _ := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{routeRes},
		nil,
		nil,
	)
	ctxRouteRes, _ := regRouteRes.Context(action.ProposalFilter, "prof-1", "route-test")
	actRouteRes, _ := action.NormalizeAction(ctxRouteRes, defaultTestActor, "/test", []byte(`{"path":"/a"}`), defaultTestEnvelope, nil)
	tcRouteRes, _ := actRouteRes.TrustedContext()
	if tcRouteRes.ToolRevision() == baseRouteRev {
		t.Fatalf("expected route revision to change when resolution_profile changes")
	}

	// UpstreamName invalid tests: \n, 0x7F, 257 bytes
	invalidNames := []string{
		"has\nnewline",
		"has\x7fdel",
		strings.Repeat("x", 257),
		"",
	}
	for _, badName := range invalidNames {
		badTool := baseTool
		badTool.UpstreamName = badName
		_, err := action.NewRegistry(
			[]action.Profile{validProfile("prof-1")},
			[]action.Route{validToolRoute("route-tool", "my-tool")},
			[]action.Tool{badTool},
			nil,
		)
		if !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for UpstreamName %q, got %v", badName, err)
		}
	}
}

func TestTargetResourceKindQA(t *testing.T) {
	// 6. TargetResourceKind for fs.read, fs.write, http.request, tool.invoke routes
	// = filesystem, filesystem, http, tool (both on Context and on TrustedContext).
	schema := action.Schema{Fields: map[string]action.FieldType{"x": action.String}}
	tool := action.Tool{
		ToolID:        "my-tool",
		UpstreamID:    "up-1",
		UpstreamName:  "tool_1",
		PayloadSchema: "ps-1",
		Schema:        schema,
	}
	rRead := action.Route{
		RouteID:           "r-read",
		ExecutorID:        "exec-1",
		Operation:         "fs.read",
		ResolutionProfile: "res-1",
		PayloadSchema:     "ps-read",
		Schema:            schema,
	}
	rWrite := action.Route{
		RouteID:           "r-write",
		ExecutorID:        "exec-1",
		Operation:         "fs.write",
		ResolutionProfile: "res-1",
		PayloadSchema:     "ps-write",
		Schema:            schema,
	}
	rHTTP := action.Route{
		RouteID:           "r-http",
		ExecutorID:        "exec-1",
		Operation:         "http.request",
		ResolutionProfile: "res-1",
		PayloadSchema:     "ps-http",
		Schema:            schema,
	}
	rTool := action.Route{
		RouteID:           "r-tool",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             []string{"my-tool"},
	}

	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{rRead, rWrite, rHTTP, rTool},
		[]action.Tool{tool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	cases := []struct {
		routeID      string
		resource     string
		payload      string
		expectedKind string
	}{
		{"r-read", "/var/log", `{"x":"val"}`, "filesystem"},
		{"r-write", "/var/log", `{"x":"val"}`, "filesystem"},
		{"r-http", "https://api.example.com/v1", `{"x":"val"}`, "http"},
		{"r-tool", "my-tool", `{"x":"val"}`, "tool"},
	}

	for _, tc := range cases {
		ctx, err := reg.Context(action.ProposalFilter, "prof-1", tc.routeID)
		if err != nil {
			t.Fatalf("Context failed for %s: %v", tc.routeID, err)
		}
		if ctx.TargetResourceKind() != tc.expectedKind {
			t.Fatalf("Context %s: expected TargetResourceKind=%s, got %s", tc.routeID, tc.expectedKind, ctx.TargetResourceKind())
		}
		act, err := action.NormalizeAction(ctx, defaultTestActor, tc.resource, []byte(tc.payload), defaultTestEnvelope, nil)
		if err != nil {
			t.Fatalf("NormalizeAction %s failed: %v", tc.routeID, err)
		}
		tCtx, ok := act.TrustedContext()
		if !ok {
			t.Fatalf("TrustedContext failed for %s", tc.routeID)
		}
		if tCtx.TargetResourceKind() != tc.expectedKind {
			t.Fatalf("TrustedContext %s: expected TargetResourceKind=%s, got %s", tc.routeID, tc.expectedKind, tCtx.TargetResourceKind())
		}
	}
}

func TestProtocolCodesQA(t *testing.T) {
	// 7. Protocols: "mcp" and "openai_compatible" -> ErrProtocolUnsupported; "foo" and "" -> ErrSchema.
	unsupportedProtos := []string{"mcp", "openai_compatible"}
	for _, proto := range unsupportedProtos {
		p := action.Profile{
			Protocol:        proto,
			ProfileID:       "prof-1",
			AdapterRevision: testValidDigest,
		}
		_, err := action.NewRegistry([]action.Profile{p}, []action.Route{validNonToolRoute("r", "fs.read")}, nil, nil)
		if !errors.Is(err, action.ErrProtocolUnsupported) {
			t.Fatalf("expected ErrProtocolUnsupported for %s, got %v", proto, err)
		}
	}

	schemaInvalidProtos := []string{"foo", "", "custom", "unknown_protocol"}
	for _, proto := range schemaInvalidProtos {
		p := action.Profile{
			Protocol:        proto,
			ProfileID:       "prof-1",
			AdapterRevision: testValidDigest,
		}
		_, err := action.NewRegistry([]action.Profile{p}, []action.Route{validNonToolRoute("r", "fs.read")}, nil, nil)
		if !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for protocol %q, got %v", proto, err)
		}
	}
}

func buildNestedField(depth int) action.Field {
	f := action.Field{Type: action.String}
	for i := 0; i < depth; i++ {
		f = action.Field{
			Type: action.Object,
			Properties: map[string]action.Field{
				"nested": f,
			},
		}
	}
	return f
}

func TestCanonicalSchemaFormAndDepthQA(t *testing.T) {
	// 8. Scalar RecursiveFields entry -> ErrSchema; Fields/RecursiveFields overlap -> ErrSchema;
	// schema depth 17 -> ErrSchema while depth 16 builds.
	scalarTypes := []action.FieldType{action.String, action.Integer, action.Number, action.Boolean}
	for _, st := range scalarTypes {
		toolScalar := action.Tool{
			ToolID:        "tool-scalar",
			UpstreamID:    "up-1",
			UpstreamName:  "name",
			PayloadSchema: "ps-1",
			Schema: action.Schema{
				RecursiveFields: map[string]action.Field{
					"scalar": {Type: st},
				},
			},
		}
		_, err := action.NewRegistry(
			[]action.Profile{validProfile("prof-1")},
			[]action.Route{validToolRoute("r", "tool-scalar")},
			[]action.Tool{toolScalar},
			nil,
		)
		if !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for scalar RecursiveFields entry of type %s, got %v", st, err)
		}
	}

	// Fields / RecursiveFields key overlap -> ErrSchema
	toolOverlap := action.Tool{
		ToolID:        "tool-overlap",
		UpstreamID:    "up-1",
		UpstreamName:  "name",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"common": action.String,
			},
			RecursiveFields: map[string]action.Field{
				"common": {
					Type:       action.Object,
					Properties: map[string]action.Field{"sub": {Type: action.String}},
				},
			},
		},
	}
	_, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool-overlap")},
		[]action.Tool{toolOverlap},
		nil,
	)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for Fields/RecursiveFields key overlap, got %v", err)
	}

	// Schema depth 16 builds
	field16 := buildNestedField(16)
	tool16 := action.Tool{
		ToolID:        "tool-16",
		UpstreamID:    "up-1",
		UpstreamName:  "name",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"root": field16,
			},
		},
	}
	_, err = action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool-16")},
		[]action.Tool{tool16},
		nil,
	)
	if err != nil {
		t.Fatalf("expected schema depth 16 to build without error, got %v", err)
	}

	// Schema depth 17 -> ErrSchema
	field17 := buildNestedField(17)
	tool17 := action.Tool{
		ToolID:        "tool-17",
		UpstreamID:    "up-1",
		UpstreamName:  "name",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"root": field17,
			},
		},
	}
	_, err = action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool-17")},
		[]action.Tool{tool17},
		nil,
	)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for schema depth 17, got %v", err)
	}
}

func TestDeepCopyItemsAndToolsMutationQA(t *testing.T) {
	// 9. Deep copy of Items: mutate *Items (and Route.Tools slice) after NewRegistry ->
	// registered behavior and revision unchanged.
	itemField := action.Field{Type: action.String}
	arrayField := action.Field{Type: action.Array, Items: &itemField}
	tool := action.Tool{
		ToolID:        "tool-arr-mut",
		UpstreamID:    "up-1",
		UpstreamName:  "arr_mut",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"arr": arrayField,
			},
		},
	}
	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("route-arr", "tool-arr-mut")},
		[]action.Tool{tool},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-arr")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	actBefore, err := action.NormalizeAction(ctx, defaultTestActor, "tool-arr-mut", []byte(`{"arr":["hello"]}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction before mutation failed: %v", err)
	}
	tcBefore, _ := actBefore.TrustedContext()
	initRev := tcBefore.ToolRevision()

	// Mutate the original *Items pointer
	itemField.Type = action.Integer

	// Assert registered behavior and revision are unchanged
	actAfter, err := action.NormalizeAction(ctx, defaultTestActor, "tool-arr-mut", []byte(`{"arr":["hello"]}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction after Items mutation rejected valid string: %v", err)
	}
	tcAfter, _ := actAfter.TrustedContext()
	if tcAfter.ToolRevision() != initRev {
		t.Fatalf("ToolRevision changed after *Items mutation")
	}

	// Integer element must still be rejected because registered item type is String
	_, err = action.NormalizeAction(ctx, defaultTestActor, "tool-arr-mut", []byte(`{"arr":[123]}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema when passing integer to array with string items, got %v", err)
	}

	// 2. Mutate Route.Tools slice after NewRegistry -> registered behavior unchanged
	tool2 := action.Tool{
		ToolID:        "tool-slice-mut",
		UpstreamID:    "up-1",
		UpstreamName:  "slice_mut",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{"x": action.String},
		},
	}
	toolsSlice := []string{"tool-slice-mut"}
	routeTools := action.Route{
		RouteID:           "r-tools-mut",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             toolsSlice,
	}
	regTools, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{routeTools},
		[]action.Tool{tool2},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry with routeTools failed: %v", err)
	}
	ctxTools, err := regTools.Context(action.ProposalFilter, "prof-1", "r-tools-mut")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	// Mutate original slice
	toolsSlice[0] = "mutated-tool-id"
	routeTools.Tools[0] = "mutated-tool-id"

	// Assert tool-slice-mut still allowed and admitted
	actTools, err := action.NormalizeAction(ctxTools, defaultTestActor, "tool-slice-mut", []byte(`{"x":"hello"}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction after Tools slice mutation rejected allowed tool: %v", err)
	}
	if actTools.Digest == "" {
		t.Fatalf("expected non-empty digest")
	}

	// Assert mutated tool is rejected with ErrToolRevisionUnknown
	_, err = action.NormalizeAction(ctxTools, defaultTestActor, "mutated-tool-id", []byte(`{"x":"hello"}`), defaultTestEnvelope, nil)
	if !errors.Is(err, action.ErrToolRevisionUnknown) {
		t.Fatalf("expected ErrToolRevisionUnknown for mutated-tool-id, got %v", err)
	}
}

func TestValidDigestHexCharsQA(t *testing.T) {
	// 10. validDigest: a digest whose FIRST hex char is invalid ("sha256:g" + 63 hex) and one with an uppercase first char -> ErrSchema.
	badHexProf := action.Profile{
		Protocol:        "decision_api",
		ProfileID:       "prof-1",
		AdapterRevision: "sha256:g" + strings.Repeat("0", 63),
	}
	_, err := action.NewRegistry(
		[]action.Profile{badHexProf},
		[]action.Route{validNonToolRoute("route-1", "fs.read")},
		nil,
		nil,
	)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for first hex char 'g', got %v", err)
	}

	upperHexProf := action.Profile{
		Protocol:        "decision_api",
		ProfileID:       "prof-1",
		AdapterRevision: "sha256:A" + strings.Repeat("0", 63),
	}
	_, err = action.NewRegistry(
		[]action.Profile{upperHexProf},
		[]action.Route{validNonToolRoute("route-1", "fs.read")},
		nil,
		nil,
	)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for first hex char 'A', got %v", err)
	}
}

func TestScalarEmptyNonNilPropertiesQA(t *testing.T) {
	// 11. A scalar field with an empty non-nil Properties map (in a nested Object property) encodes
	// identically to nil Properties (same revision) - or, if validation rejects non-empty Properties
	// on scalars only, assert empty-non-nil is accepted and equal.
	toolNilProps := action.Tool{
		ToolID:        "tool-scalar-props",
		UpstreamID:    "up-1",
		UpstreamName:  "scalar_props",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"obj": {
					Type: action.Object,
					Properties: map[string]action.Field{
						"scalar": {Type: action.String, Properties: nil},
					},
				},
			},
		},
	}
	toolEmptyProps := action.Tool{
		ToolID:        "tool-scalar-props",
		UpstreamID:    "up-1",
		UpstreamName:  "scalar_props",
		PayloadSchema: "ps-1",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"obj": {
					Type: action.Object,
					Properties: map[string]action.Field{
						"scalar": {Type: action.String, Properties: map[string]action.Field{}},
					},
				},
			},
		},
	}

	regNil, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool-scalar-props")},
		[]action.Tool{toolNilProps},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry regNil failed: %v", err)
	}

	regEmpty, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool-scalar-props")},
		[]action.Tool{toolEmptyProps},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry regEmpty failed: %v", err)
	}

	ctxNil, _ := regNil.Context(action.ProposalFilter, "prof-1", "r")
	ctxEmpty, _ := regEmpty.Context(action.ProposalFilter, "prof-1", "r")

	actNil, err := action.NormalizeAction(ctxNil, defaultTestActor, "tool-scalar-props", []byte(`{"obj":{"scalar":"abc"}}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction actNil failed: %v", err)
	}
	actEmpty, err := action.NormalizeAction(ctxEmpty, defaultTestActor, "tool-scalar-props", []byte(`{"obj":{"scalar":"abc"}}`), defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction actEmpty failed: %v", err)
	}

	tcNil, _ := actNil.TrustedContext()
	tcEmpty, _ := actEmpty.TrustedContext()

	if tcNil.ToolRevision() != tcEmpty.ToolRevision() {
		t.Fatalf("expected nil Properties and empty non-nil Properties to yield identical revision, got %s vs %s", tcNil.ToolRevision(), tcEmpty.ToolRevision())
	}
}

func TestUpstreamNameRuneRestrictions(t *testing.T) {
	// First and last code point of each rejected range:
	// U+0080-U+009F, U+200B-U+200F, U+202A-U+202E, U+2066-U+2069, U+FEFF.
	rejectedRunes := []rune{
		0x0080, 0x009F, // U+0080-U+009F
		0x200B, 0x200F, // U+200B-U+200F
		0x202A, 0x202E, // U+202A-U+202E
		0x2066, 0x2069, // U+2066-U+2069
		0xFEFF, // U+FEFF
	}

	for _, r := range rejectedRunes {
		t.Run(fmt.Sprintf("rune_%U", r), func(t *testing.T) {
			tool := action.Tool{
				ToolID:        "tool-bad-rune",
				UpstreamID:    "upstream-1",
				UpstreamName:  fmt.Sprintf("tool%cname", r),
				PayloadSchema: "schema-1",
				Schema: action.Schema{
					Fields: map[string]action.FieldType{
						"arg": action.String,
					},
				},
			}
			_, err := action.NewRegistry(
				[]action.Profile{validProfile("prof-1")},
				[]action.Route{validToolRoute("route-1", "tool-bad-rune")},
				[]action.Tool{tool},
				nil,
			)
			if !errors.Is(err, action.ErrSchema) {
				t.Fatalf("expected ErrSchema for UpstreamName containing rune U+%04X, got %v", r, err)
			}
		})
	}

	// Confirm "búsqueda" is accepted
	t.Run("accepts_busqueda", func(t *testing.T) {
		tool := action.Tool{
			ToolID:        "tool-busqueda",
			UpstreamID:    "upstream-1",
			UpstreamName:  "búsqueda",
			PayloadSchema: "schema-1",
			Schema: action.Schema{
				Fields: map[string]action.FieldType{
					"query": action.String,
				},
			},
		}
		_, err := action.NewRegistry(
			[]action.Profile{validProfile("prof-1")},
			[]action.Route{validToolRoute("route-1", "tool-busqueda")},
			[]action.Tool{tool},
			nil,
		)
		if err != nil {
			t.Fatalf("expected NewRegistry to accept 'búsqueda', got %v", err)
		}
	})
}

func TestNewRegistryDuplicateUpstreamTool(t *testing.T) {
	// Reject two tools sharing the same (UpstreamID, UpstreamName) pair, even with different ToolIDs or schemas.
	toolA := action.Tool{
		ToolID:        "tool.a",
		UpstreamID:    "up-shared",
		UpstreamName:  "name-shared",
		PayloadSchema: "schema-1",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{"x": action.String},
		},
	}
	toolB := action.Tool{
		ToolID:        "tool.b",
		UpstreamID:    "up-shared",
		UpstreamName:  "name-shared",
		PayloadSchema: "schema-2",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{"y": action.Integer},
		},
	}
	_, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool.a", "tool.b")},
		[]action.Tool{toolA, toolB},
		nil,
	)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for duplicate (UpstreamID, UpstreamName), got %v", err)
	}

	// Same UpstreamID with different UpstreamName -> ok
	toolBDifferentName := action.Tool{
		ToolID:        "tool.b",
		UpstreamID:    "up-shared",
		UpstreamName:  "name-different",
		PayloadSchema: "schema-2",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{"y": action.Integer},
		},
	}
	_, err = action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool.a", "tool.b")},
		[]action.Tool{toolA, toolBDifferentName},
		nil,
	)
	if err != nil {
		t.Fatalf("expected NewRegistry to succeed for same UpstreamID with different UpstreamName, got %v", err)
	}
}

func TestSchemaFieldNodeCountCap(t *testing.T) {
	// Cap total number of copied Field nodes per Schema at 4096; more -> ErrSchema.
	// Object with 4095 scalar children = 4096 Field nodes total -> builds ok.
	props4095 := make(map[string]action.Field, 4095)
	for i := 0; i < 4095; i++ {
		props4095[fmt.Sprintf("k%d", i)] = action.Field{Type: action.String}
	}
	tool4096 := action.Tool{
		ToolID:        "tool.cap",
		UpstreamID:    "up-1",
		UpstreamName:  "cap_tool",
		PayloadSchema: "schema-1",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"root": {Type: action.Object, Properties: props4095},
			},
		},
	}
	_, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool.cap")},
		[]action.Tool{tool4096},
		nil,
	)
	if err != nil {
		t.Fatalf("expected schema with 4096 Field nodes to build, got %v", err)
	}

	// Object with 4096 scalar children = 4097 Field nodes total -> rejected ErrSchema.
	props4096 := make(map[string]action.Field, 4096)
	for i := 0; i < 4096; i++ {
		props4096[fmt.Sprintf("k%d", i)] = action.Field{Type: action.String}
	}
	tool4097 := action.Tool{
		ToolID:        "tool.cap",
		UpstreamID:    "up-1",
		UpstreamName:  "cap_tool",
		PayloadSchema: "schema-1",
		Schema: action.Schema{
			RecursiveFields: map[string]action.Field{
				"root": {Type: action.Object, Properties: props4096},
			},
		},
	}
	_, err = action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{validToolRoute("r", "tool.cap")},
		[]action.Tool{tool4097},
		nil,
	)
	if !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected schema with 4097 Field nodes to be rejected with ErrSchema, got %v", err)
	}
}

func TestNormalizeActionNonCanonicalResourceWithholdsDigest(t *testing.T) {
	fsRoute := action.Route{
		RouteID:           "route-fs",
		ExecutorID:        "exec-fs",
		Operation:         "fs.read",
		ResolutionProfile: "res-1",
		PayloadSchema:     "ps-fs",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{"n": action.Integer},
		},
	}
	reg, err := action.NewRegistry(
		[]action.Profile{validProfile("prof-1")},
		[]action.Route{fsRoute},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}
	ctx, err := reg.Context(action.Advisory, "prof-1", "route-fs")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	payload := []byte(`{"n":1}`)
	act, err := action.NormalizeAction(ctx, defaultTestActor, "/work/./file", payload, defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction unexpectedly returned error for non-canonical resource: %v", err)
	}
	if act.Digest != "" {
		t.Fatalf("expected Action.Digest to be empty, got %q", act.Digest)
	}
	if act.TrustedDigest() != "" {
		t.Fatalf("expected TrustedDigest() to be empty, got %q", act.TrustedDigest())
	}
	if act.Authorizable() {
		t.Fatalf("expected Authorizable() to be false for non-canonical resource")
	}
	if !act.Valid() {
		t.Fatalf("expected Action to still be Valid()")
	}
}
