package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/identity"
	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/source"
	"github.com/reviaro/guardfil/internal/telemetry"
)

func testNormalizeAction(t testing.TB, principal identity.PrincipalContext, op, resource string, raw []byte, schema action.Schema) action.Action {
	return testNormalizeActionWithClock(t, principal, op, resource, raw, schema, fakeClock{now: time.Now().Add(-100 * time.Millisecond)}, 30*time.Second)
}

func testNormalizeActionWithClock(t testing.TB, principal identity.PrincipalContext, op, resource string, raw []byte, schema action.Schema, clk source.Clock, ttl time.Duration) action.Action {
	t.Helper()
	actor, err := action.ProjectActor(principal)
	if err != nil {
		t.Fatalf("ProjectActor failed: %v", err)
	}

	var routes []action.Route
	var tools []action.Tool
	if op == "tool.invoke" {
		tools = []action.Tool{{
			ToolID:        resource,
			UpstreamID:    "up-1",
			UpstreamName:  resource,
			PayloadSchema: "ps-1",
			Schema:        schema,
		}}
		routes = []action.Route{{
			RouteID:           "route-1",
			ExecutorID:        "exec-1",
			Operation:         op,
			ResolutionProfile: "res-1",
			Tools:             []string{resource},
		}}
	} else {
		routes = []action.Route{{
			RouteID:           "route-1",
			ExecutorID:        "exec-1",
			Operation:         op,
			ResolutionProfile: "res-1",
			PayloadSchema:     "ps-1",
			Schema:            schema,
		}}
	}

	reg, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "prof-1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		routes,
		tools,
		nil,
	)
	if err != nil {
		t.Fatalf("action.NewRegistry failed: %v", err)
	}

	ctx, err := reg.Context(action.Advisory, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	ids := fakeIDSource{id: "act-1"}
	env, err := action.NewEnvelope(clk, ids, "req-1", "", "", ttl)
	if err != nil {
		t.Fatalf("action.NewEnvelope failed: %v", err)
	}

	a, err := action.NormalizeAction(ctx, actor, resource, raw, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	return a
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}

type fakeIDSource struct {
	id string
}

func (s fakeIDSource) NewID() (string, error) {
	return s.id, nil
}

type errorIDSource struct {
	err error
}

func (s errorIDSource) NewID() (string, error) {
	return "", s.err
}

type validIDWithErrorSource struct {
	id  string
	err error
}

func (s validIDWithErrorSource) NewID() (string, error) {
	return s.id, s.err
}

type scriptClock struct {
	times []time.Time
	idx   int
	calls int
}

func (c *scriptClock) Now() time.Time {
	c.calls++
	if c.idx < len(c.times) {
		t := c.times[c.idx]
		c.idx++
		return t
	}
	if len(c.times) > 0 {
		return c.times[len(c.times)-1]
	}
	return time.Time{}
}

func TestNoMatchFailsClosed(t *testing.T) {
	s, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Engine{Policy: s}.Decide(context.Background(), action.Action{SchemaVersion: action.Version, Digest: "sha256:test"}, "acme", "app", "filesystem.read", "/x", time.Now().Add(time.Second))
	if err == nil || d.Effect != BLOCK || d.DispatchEligible() || d.Code() != failure.IDENTITY_UNTRUSTED || d.Stage != failure.StageAuth {
		t.Fatalf("unexpected decision: %+v, %v", d, err)
	}
}

func TestAuthorizeUsesSealedActionAndLiveIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{{
		ID:          "key-1",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(time.Hour),
		Revision:    1,
		Verifier:    identity.Verifier(key, secret),
	}}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}
	a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	d, err := engine.Authorize(context.Background(), a, principal)
	if err != nil || d.Effect != ALLOW || d.DispatchEligible() || d.Code() != "" || d.Stage != "" {
		t.Fatalf("trusted authorization: %+v, %v", d, err)
	}

	outOfScope := testNormalizeAction(t, principal, "fs.read", "/other/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	d, err = engine.Authorize(context.Background(), outOfScope, principal)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.AUTH_FORBIDDEN || d.Stage != failure.StageAuth {
		t.Fatalf("resource-set escape: %+v, %v", d, err)
	}

	mutated := a
	mutated.Resource = "/work/private/key"
	d, err = engine.Authorize(context.Background(), mutated, principal)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.BINDING_MISMATCH || d.Stage != failure.StageNormalize {
		t.Fatalf("mutated action: %+v, %v", d, err)
	}

	if err := registry.Revoke("key-1", 2); err != nil {
		t.Fatal(err)
	}
	d, err = engine.Authorize(context.Background(), a, principal)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.AUTHORIZATION_STALE || d.Stage != failure.StageAuth {
		t.Fatalf("revoked context: %+v, %v", d, err)
	}
}

func TestAuthorizeBlocksUnmetApprovalAndLegacyCallerAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{{ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data", Scopes: []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1, Verifier: identity.Verifier(key, secret)}}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n - id: approval\n   effect: require_approval\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	counters := &telemetry.Counters{}
	engine, err := NewEngineWithTelemetry(snapshot, registry, counters)
	if err != nil {
		t.Fatal(err)
	}
	a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	d, err := engine.Authorize(context.Background(), a, principal)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.APPROVAL_UNAVAILABLE || d.Stage != failure.StageApproval {
		t.Fatalf("unmet approval: %+v, %v", d, err)
	}
	if !strings.Contains(counters.Prometheus(), "guardfil_decision_obligation_blocks_total 1\n") {
		t.Fatal("unmet obligation was not recorded in bounded telemetry")
	}

	d, err = engine.Decide(context.Background(), a, "acme", "app", "filesystem.read", "/work/file", now.Add(time.Minute))
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() {
		t.Fatalf("legacy caller-selected authority: %+v, %v", d, err)
	}
}

func TestP12DecisionIsNotAnExecutorCapability(t *testing.T) {
	// P1.2 intentionally has no executor. This represents a future consumer
	// that correctly refuses anything except a P1.4 admission capability.
	fakeSend := func(d Decision) bool { return d.DispatchEligible() }
	if fakeSend(Decision{Effect: ALLOW}) {
		t.Fatal("a P1.2 Decision became a dispatch capability")
	}
}

func TestCancellationFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := (Engine{}).Decide(ctx, action.Action{}, "", "", "", "", time.Now().Add(time.Second))
	if err == nil || d.Code() != failure.CANCELLED || d.Stage != failure.StagePolicy || d.DispatchEligible() {
		t.Fatalf("unexpected decision: %+v, %v", d, err)
	}
}

func TestSecurityOperationProjectionEndToEnd(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{{
		ID:          "key-1",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(time.Hour),
		Revision:    1,
		Verifier:    identity.Verifier(key, secret),
	}}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}
	a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	d, err := engine.Authorize(context.Background(), a, principal)
	if err != nil || d.Effect != ALLOW || d.DispatchEligible() || d.Code() != "" || d.Stage != "" {
		t.Fatalf("fs.read end-to-end projection failed: decision=%+v error=%v", d, err)
	}
}

func TestAuthorizeBoundActorMismatchAndChecks(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret1 := []byte("0123456789012345678901234567890123456789012")
	secret2 := []byte("9876543210987654321098765432109876543210987")
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{
		{
			ID:          "key-1",
			TenantID:    "acme",
			PrincipalID: "app1",
			Audience:    "data",
			Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
			IssuedAt:    now.Add(-time.Hour),
			ExpiresAt:   now.Add(time.Hour),
			Revision:    1,
			Verifier:    identity.Verifier(key, secret1),
		},
		{
			ID:          "key-2",
			TenantID:    "acme",
			PrincipalID: "app2",
			Audience:    "data",
			Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
			IssuedAt:    now.Add(-time.Hour),
			ExpiresAt:   now.Add(time.Hour),
			Revision:    1,
			Verifier:    identity.Verifier(key, secret2),
		},
	}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}

	principal1, err := registry.Authenticate(string(secret1), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	principal2, err := registry.Authenticate(string(secret2), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app1, app2], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}

	a1 := testNormalizeAction(t, principal1, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})

	// 1. Same principal -> ALLOW
	d, err := engine.Authorize(context.Background(), a1, principal1)
	if err != nil || d.Effect != ALLOW || d.DispatchEligible() || d.Code() != "" || d.Stage != "" {
		t.Fatalf("expected ALLOW for matching principal, got decision=%+v err=%v", d, err)
	}

	// 2. Different credential principal -> BINDING_MISMATCH
	d, err = engine.Authorize(context.Background(), a1, principal2)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.BINDING_MISMATCH || d.Stage != failure.StageNormalize {
		t.Fatalf("expected BINDING_MISMATCH for principal mismatch, got decision=%+v err=%v", d, err)
	}

	// 3. Zero principal -> IDENTITY_UNTRUSTED
	d, err = engine.Authorize(context.Background(), a1, identity.PrincipalContext{})
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.IDENTITY_UNTRUSTED || d.Stage != failure.StageAuth {
		t.Fatalf("expected IDENTITY_UNTRUSTED for zero principal, got decision=%+v err=%v", d, err)
	}

	// 4. Legacy NormalizeRequest Action through Authorize -> BINDING_MISMATCH
	legacyAction, err := action.NormalizeRequest("fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	if err != nil {
		t.Fatal(err)
	}
	d, err = engine.Authorize(context.Background(), legacyAction, principal1)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.BINDING_MISMATCH || d.Stage != failure.StageNormalize {
		t.Fatalf("expected BINDING_MISMATCH for legacy NormalizeRequest action, got decision=%+v err=%v", d, err)
	}

	// 5. Non-canonical resource NormalizeAction Action through Authorize -> BINDING_MISMATCH
	nonCanonicalAction := testNormalizeAction(t, principal1, "fs.read", "/work/./file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	if nonCanonicalAction.Digest != "" || nonCanonicalAction.Authorizable() {
		t.Fatalf("expected non-canonical Action to have empty digest and Authorizable() == false")
	}
	d, err = engine.Authorize(context.Background(), nonCanonicalAction, principal1)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.BINDING_MISMATCH || d.Stage != failure.StageNormalize {
		t.Fatalf("expected BINDING_MISMATCH for non-canonical resource action, got decision=%+v err=%v", d, err)
	}
}

func TestAuthorizeActorMismatchVariants(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-1",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(time.Hour),
		Revision:    1,
		Verifier:    identity.Verifier(key, secret),
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}

	pNow, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	pNowPlus1, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	a := testNormalizeAction(t, pNow, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})

	d, err := engine.Authorize(context.Background(), a, pNowPlus1)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.BINDING_MISMATCH || d.Stage != failure.StageNormalize {
		t.Fatalf("expected BINDING_MISMATCH on authenticated_at mismatch alone, got %+v, %v", d, err)
	}

	pNowAgain, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	d, err = engine.Authorize(context.Background(), a, pNowAgain)
	if err != nil || d.Effect != ALLOW || d.DispatchEligible() {
		t.Fatalf("expected ALLOW for re-authentication at same second, got %+v, %v", d, err)
	}

	credRev2 := cred
	credRev2.Revision = 2
	credRev2.Verifier = identity.Verifier(key, secret)
	registryRev2, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credRev2}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	pRev2, err := registryRev2.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	engineRev2, err := NewEngine(snapshot, registryRev2)
	if err != nil {
		t.Fatal(err)
	}
	d, err = engineRev2.Authorize(context.Background(), a, pRev2)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.BINDING_MISMATCH || d.Stage != failure.StageNormalize {
		t.Fatalf("expected BINDING_MISMATCH for credential revision change, got %+v, %v", d, err)
	}

	keyOther := make([]byte, 32)
	keyOther[0] = 0xff
	credOther := cred
	credOther.Verifier = identity.Verifier(keyOther, secret)
	registryOther, err := identity.NewRegistryWithResourceSets(keyOther, []identity.Credential{credOther}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	pOther, err := registryOther.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	d, err = engine.Authorize(context.Background(), a, pOther)
	if err == nil || d.Effect == ALLOW || d.DispatchEligible() || d.Code() != failure.AUTH_INVALID || d.Stage != failure.StageAuth {
		t.Fatalf("expected AUTH_INVALID for principal from different registry, got %+v, %v", d, err)
	}
}

func TestAuthorizeFullMappingTable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x23}, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-valid",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes: []identity.Scope{
			{Operation: "filesystem.read", ResourceSet: "workspace-read"},
			{Operation: "filesystem.write", ResourceSet: "workspace-write"},
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
		Revision:  1,
		Verifier:  identity.Verifier(key, secret),
	}
	resSets := map[string][]identity.Resource{
		"workspace-read":  {{Kind: "path", Value: "/work/**"}},
		"workspace-write": {{Kind: "path", Value: "/work/**"}},
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}

	validPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: allow-rule-1
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	validSnapshot, err := policy.Compile([]byte(validPolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	validEngine, err := NewEngine(validSnapshot, registry)
	if err != nil {
		t.Fatal(err)
	}

	validAction := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})

	// 1. ctx.Err() context.Canceled -> CANCELLED/policy
	{
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		d, err := validEngine.Authorize(ctx, validAction, principal)
		assertDecisionBlock(t, "canceled context", d, err, failure.CANCELLED, failure.StagePolicy)
	}

	// 2. ctx.Err() context.DeadlineExceeded -> DEADLINE_EXCEEDED/policy
	{
		ctx, cancel := context.WithDeadline(context.Background(), now.Add(-time.Second))
		defer cancel()
		d, err := validEngine.Authorize(ctx, validAction, principal)
		assertDecisionBlock(t, "deadline exceeded context", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}

	// 3. Unsealed engine or nil registry -> POLICY_UNAVAILABLE/policy
	{
		unsealed := Engine{Policy: validSnapshot}
		d, err := unsealed.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "unsealed engine", d, err, failure.POLICY_UNAVAILABLE, failure.StagePolicy)
	}

	// 4. !Authorizable -> BINDING_MISMATCH/normalize
	{
		notAuthAction := validAction
		notAuthAction.Digest = ""
		d, err := validEngine.Authorize(context.Background(), notAuthAction, principal)
		assertDecisionBlock(t, "not authorizable action", d, err, failure.BINDING_MISMATCH, failure.StageNormalize)
	}

	// 4b. Missing or unminted envelope -> BINDING_MISMATCH/normalize
	{
		unmintedAction := action.Action{SchemaVersion: action.Version, Digest: "sha256:custom"}
		d, err := validEngine.Authorize(context.Background(), unmintedAction, principal)
		assertDecisionBlock(t, "unminted action", d, err, failure.BINDING_MISMATCH, failure.StageNormalize)
	}

	// 5. Clock rollback or past deadline -> DEADLINE_EXCEEDED/policy
	{
		rollbackEngine, err := NewEngine(validSnapshot, registry, WithClock(fakeClock{now: now.Add(-time.Second)}))
		if err != nil {
			t.Fatal(err)
		}
		d, err := rollbackEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "clock rollback", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)

		pastAction := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}}, fakeClock{now: now.Add(-time.Minute)}, time.Second)
		d, err = validEngine.Authorize(context.Background(), pastAction, principal)
		assertDecisionBlock(t, "past deadline", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}

	// 6. ProjectActor error -> IDENTITY_UNTRUSTED/auth
	{
		d, err := validEngine.Authorize(context.Background(), validAction, identity.PrincipalContext{})
		assertDecisionBlock(t, "zero principal ProjectActor", d, err, failure.IDENTITY_UNTRUSTED, failure.StageAuth)
	}

	// 7. Actor mismatch -> BINDING_MISMATCH/normalize
	{
		secretOther := []byte("other-secret-012345678901234567890123456789012")
		credOther := cred
		credOther.ID = "key-other"
		credOther.PrincipalID = "app-other"
		credOther.Verifier = identity.Verifier(key, secretOther)
		regOther, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred, credOther}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		pOther, err := regOther.Authenticate(string(secretOther), "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatal(err)
		}
		engOther, err := NewEngine(validSnapshot, regOther)
		if err != nil {
			t.Fatal(err)
		}

		d, err := engOther.Authorize(context.Background(), validAction, pOther)
		assertDecisionBlock(t, "actor mismatch", d, err, failure.BINDING_MISMATCH, failure.StageNormalize)
	}

	// 8. Empty trusted operation -> PROTOCOL_UNSUPPORTED/normalize
	// (Guarded by Authorize when a.TrustedSecurityOperation() == "")

	// 9. Validate: ErrForbidden -> AUTH_FORBIDDEN/auth
	{
		outOfScopeAction := testNormalizeAction(t, principal, "fs.read", "/other/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
		d, err := validEngine.Authorize(context.Background(), outOfScopeAction, principal)
		assertDecisionBlock(t, "Validate ErrForbidden", d, err, failure.AUTH_FORBIDDEN, failure.StageAuth)
	}

	// 10. Validate: ErrStale -> AUTHORIZATION_STALE/auth
	{
		regStale, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		pStale, err := regStale.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatal(err)
		}
		engStale, err := NewEngine(validSnapshot, regStale)
		if err != nil {
			t.Fatal(err)
		}
		if err := regStale.Revoke("key-valid", 1); err != nil {
			t.Fatal(err)
		}
		d, err := engStale.Authorize(context.Background(), validAction, pStale)
		assertDecisionBlock(t, "Validate ErrStale", d, err, failure.AUTHORIZATION_STALE, failure.StageAuth)

		// Principal authenticated, then Authorize/Validate with now past ExpiresAt -> AUTHORIZATION_STALE/auth
		credPastExpiry := cred
		credPastExpiry.ID = "key-expired-after-auth"
		credPastExpiry.IssuedAt = now.Add(-2 * time.Hour)
		credPastExpiry.ExpiresAt = now.Add(-10 * time.Minute)
		credPastExpiry.Verifier = identity.Verifier(key, secret)
		regPastExpiry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credPastExpiry}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		pPastExpiry, err := regPastExpiry.Authenticate(string(secret), "data", "acme", "filesystem.read", now.Add(-90*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		engPastExpiry, err := NewEngine(validSnapshot, regPastExpiry)
		if err != nil {
			t.Fatal(err)
		}
		actionPastExpiry := testNormalizeAction(t, pPastExpiry, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
		dPastExpiry, err := engPastExpiry.Authorize(context.Background(), actionPastExpiry, pPastExpiry)
		assertDecisionBlock(t, "Validate ErrStale expired after auth", dPastExpiry, err, failure.AUTHORIZATION_STALE, failure.StageAuth)

		if err := regPastExpiry.Validate(pPastExpiry, "filesystem.read", "path", "/work/file", now); !errors.Is(err, identity.ErrStale) {
			t.Fatalf("Validate with now past ExpiresAt expected ErrStale, got %v", err)
		}
		if err := registry.Validate(principal, "filesystem.read", "path", "/work/file", principal.ExpiresAt().Add(time.Second)); !errors.Is(err, identity.ErrStale) {
			t.Fatalf("Validate with now past principal.ExpiresAt expected ErrStale, got %v", err)
		}
	}

	// 11. Validate: anything else -> AUTH_INVALID/auth
	{
		foreignKey := bytes.Repeat([]byte{0x99}, 32)
		credForeign := cred
		credForeign.Verifier = identity.Verifier(foreignKey, secret)
		regForeign, err := identity.NewRegistryWithResourceSets(foreignKey, []identity.Credential{credForeign}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		pForeign, err := regForeign.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatal(err)
		}
		actionForeign := testNormalizeAction(t, pForeign, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
		// principal from foreign registry passed to validEngine
		d, err := validEngine.Authorize(context.Background(), actionForeign, pForeign)
		assertDecisionBlock(t, "Validate foreign registry AUTH_INVALID", d, err, failure.AUTH_INVALID, failure.StageAuth)
	}

	// 12. Denied -> POLICY_DENIED/policy with one reason per DenyRules id
	{
		denyPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: deny-rule-10
    effect: deny
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
		denySnapshot, err := policy.Compile([]byte(denyPolicyYAML))
		if err != nil {
			t.Fatal(err)
		}
		denyEngine, err := NewEngine(denySnapshot, registry)
		if err != nil {
			t.Fatal(err)
		}
		d, err := denyEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "Denied policy", d, err, failure.POLICY_DENIED, failure.StagePolicy, "deny-rule-10")
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "deny-rule-10" {
			t.Fatalf("expected 1 reason with rule_id 'deny-rule-10', got: %+v", d.Reasons)
		}
	}

	// Tenant mismatch in policy -> POLICY_DENIED/policy with no rule_id
	{
		tenantMismatchPolicy := `schema_version: 1
tenant_id: other-tenant
revision: 1
default: deny
rules: []
`
		tmSnapshot, err := policy.Compile([]byte(tenantMismatchPolicy))
		if err != nil {
			t.Fatal(err)
		}
		tmEngine, err := NewEngine(tmSnapshot, registry)
		if err != nil {
			t.Fatal(err)
		}
		d, err := tmEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "Tenant mismatch policy", d, err, failure.POLICY_DENIED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty rule_id, got: %+v", d.Reasons)
		}
	}

	// 13. len(Checks)>0 -> CHECK_UNSUPPORTED/analysis, one reason per CheckRules id
	{
		checkPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: check-rule-1
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
    checks: [pii_check]
`
		checkSnapshot, err := policy.Compile([]byte(checkPolicyYAML))
		if err != nil {
			t.Fatal(err)
		}
		checkEngine, err := NewEngine(checkSnapshot, registry)
		if err != nil {
			t.Fatal(err)
		}
		d, err := checkEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "Checks policy", d, err, failure.CHECK_UNSUPPORTED, failure.StageAnalysis, "check-rule-1")
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "check-rule-1" {
			t.Fatalf("expected 1 reason with rule_id 'check-rule-1', got: %+v", d.Reasons)
		}
	}

	// 14. RequiresSanitization -> TRANSFORM_UNAVAILABLE/policy, per SanitizeRules id
	{
		sanitizePolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: sanitize-rule-1
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
		sanitizeSnapshot, err := policy.Compile([]byte(sanitizePolicyYAML))
		if err != nil {
			t.Fatal(err)
		}
		sanitizeEngine, err := NewEngine(sanitizeSnapshot, registry)
		if err != nil {
			t.Fatal(err)
		}
		d, err := sanitizeEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "Sanitization policy", d, err, failure.TRANSFORM_UNAVAILABLE, failure.StagePolicy, "sanitize-rule-1")
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "sanitize-rule-1" {
			t.Fatalf("expected 1 reason with rule_id 'sanitize-rule-1', got: %+v", d.Reasons)
		}
	}

	// 15. RequiresApproval -> APPROVAL_UNAVAILABLE/approval, per ApprovalRules id
	{
		approvalPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: approval-rule-1
    effect: require_approval
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
		approvalSnapshot, err := policy.Compile([]byte(approvalPolicyYAML))
		if err != nil {
			t.Fatal(err)
		}
		approvalEngine, err := NewEngine(approvalSnapshot, registry)
		if err != nil {
			t.Fatal(err)
		}
		d, err := approvalEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "Approval policy", d, err, failure.APPROVAL_UNAVAILABLE, failure.StageApproval, "approval-rule-1")
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "approval-rule-1" {
			t.Fatalf("expected 1 reason with rule_id 'approval-rule-1', got: %+v", d.Reasons)
		}
	}

	// 15b. Both sanitize and approval required for same input -> TRANSFORM_UNAVAILABLE (sanitize before approval)
	{
		bothPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: approval-rule-1
    effect: require_approval
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: sanitize-rule-1
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
		bothSnapshot, err := policy.Compile([]byte(bothPolicyYAML))
		if err != nil {
			t.Fatalf("Compile failed: %v", err)
		}
		bothEngine, err := NewEngine(bothSnapshot, registry)
		if err != nil {
			t.Fatal(err)
		}
		d, err := bothEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "Sanitize before approval policy", d, err, failure.TRANSFORM_UNAVAILABLE, failure.StagePolicy, "sanitize-rule-1")
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "sanitize-rule-1" {
			t.Fatalf("expected 1 reason with rule_id 'sanitize-rule-1', got: %+v", d.Reasons)
		}
	}

	// 16. !Allowed -> POLICY_DENIED/policy, no rule_id
	{
		noMatchPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: other-allow
    effect: allow
    match: {principals: [app], operations: [filesystem.write], resources: [{kind: path, value: /work/**}]}
`
		noMatchSnapshot, err := policy.Compile([]byte(noMatchPolicyYAML))
		if err != nil {
			t.Fatal(err)
		}
		noMatchEngine, err := NewEngine(noMatchSnapshot, registry)
		if err != nil {
			t.Fatal(err)
		}
		d, err := noMatchEngine.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "No matching policy rule", d, err, failure.POLICY_DENIED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty rule_id, got: %+v", d.Reasons)
		}
	}

	// 17. Post-evaluation ctx canceled -> CANCELLED/policy
	{
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(func() { testPostEvaluateHook = nil })
		testPostEvaluateHook = func() { cancel() }
		d, err := validEngine.Authorize(ctx, validAction, principal)
		testPostEvaluateHook = nil
		assertDecisionBlock(t, "post-evaluate ctx canceled", d, err, failure.CANCELLED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got: %+v", d.Reasons)
		}
	}

	// 18. Post-evaluation deadline passed -> DEADLINE_EXCEEDED/policy
	{
		clk := &scriptClock{times: []time.Time{now, now.Add(2 * time.Minute)}}
		engPostDeadline, err := NewEngine(validSnapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		d, err := engPostDeadline.Authorize(context.Background(), validAction, principal)
		assertDecisionBlock(t, "post-evaluate clock passed deadline", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got: %+v", d.Reasons)
		}
	}

	// 19. ALLOW path:
	{
		d, err := validEngine.Authorize(context.Background(), validAction, principal)
		if err != nil {
			t.Fatalf("expected ALLOW, got error: %v", err)
		}
		if d.Effect != ALLOW {
			t.Fatalf("expected Effect ALLOW, got %s", d.Effect)
		}
		if d.Code() != "" {
			t.Fatalf("expected Code() == \"\" on ALLOW, got %q", d.Code())
		}
		if d.Stage != "" {
			t.Fatalf("expected Stage == \"\" on ALLOW, got %q", d.Stage)
		}
		if len(d.Reasons) != 1 || d.Reasons[0].Code != "POLICY_ALLOWED" || d.Reasons[0].RuleID != "allow-rule-1" {
			t.Fatalf("unexpected Reasons on ALLOW: %+v", d.Reasons)
		}
	}
}

func assertDecisionBlock(t *testing.T, name string, d Decision, err error, wantCode failure.Code, wantStage failure.Stage, wantRuleIDs ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected non-nil error, got nil (decision: %+v)", name, d)
	}
	if !errors.Is(err, ErrNonAllow) {
		t.Fatalf("%s: expected ErrNonAllow, got %v", name, err)
	}
	if d.Effect != BLOCK {
		t.Fatalf("%s: expected Effect BLOCK, got %s", name, d.Effect)
	}
	if d.Code() != wantCode {
		t.Fatalf("%s: expected code %q, got %q", name, wantCode, d.Code())
	}
	if !d.Code().Valid() {
		t.Fatalf("%s: expected valid code, got %q", name, d.Code())
	}
	if d.Stage != wantStage {
		t.Fatalf("%s: expected stage %q, got %q", name, wantStage, d.Stage)
	}
	if !d.Stage.Valid() {
		t.Fatalf("%s: expected valid stage, got %q", name, d.Stage)
	}
	if len(d.Reasons) < 1 || len(d.Reasons) > 32 {
		t.Fatalf("%s: expected 1..32 reasons, got %d", name, len(d.Reasons))
	}
	for i, r := range d.Reasons {
		c := failure.Code(r.Code)
		if !c.Valid() {
			t.Fatalf("%s: reason %d has invalid code %q", name, i, r.Code)
		}
	}
	if len(wantRuleIDs) == 0 {
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("%s: expected 1 reason with empty RuleID for non-policy rejection, got: %+v", name, d.Reasons)
		}
	} else {
		if len(d.Reasons) != len(wantRuleIDs) {
			t.Fatalf("%s: expected %d reasons, got %d: %+v", name, len(wantRuleIDs), len(d.Reasons), d.Reasons)
		}
		for i, wantID := range wantRuleIDs {
			if d.Reasons[i].RuleID != wantID {
				t.Fatalf("%s: reason %d expected RuleID %q, got %q", name, i, wantID, d.Reasons[i].RuleID)
			}
		}
	}
}

func TestReasonsSortingUniquenessAndCap(t *testing.T) {
	// Test makeReasons sorting, uniqueness and cap at 32
	var ruleIDs []string
	for i := 40; i >= 1; i-- {
		ruleIDs = append(ruleIDs, fmt.Sprintf("rule-%02d", i))
		ruleIDs = append(ruleIDs, fmt.Sprintf("rule-%02d", i)) // duplicates
	}
	reasons := makeReasons(ReasonCode(failure.POLICY_DENIED), ruleIDs)
	if len(reasons) != 32 {
		t.Fatalf("expected capped at 32 reasons, got %d", len(reasons))
	}
	for i := 0; i < len(reasons)-1; i++ {
		if reasons[i].RuleID >= reasons[i+1].RuleID {
			t.Fatalf("reasons not sorted/unique: %s >= %s", reasons[i].RuleID, reasons[i+1].RuleID)
		}
	}
	if reasons[0].RuleID != "rule-01" {
		t.Fatalf("expected first reason rule-01, got %s", reasons[0].RuleID)
	}
	if reasons[31].RuleID != "rule-32" {
		t.Fatalf("expected 32nd reason rule-32, got %s", reasons[31].RuleID)
	}
}

func TestMutationChecksOrder(t *testing.T) {
	// Mutation check: checks branch after sanitize
	// A policy matching BOTH a check and a sanitize rule MUST hit CHECK_UNSUPPORTED/analysis
	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x23}, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-valid",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes: []identity.Scope{
			{Operation: "filesystem.read", ResourceSet: "workspace-read"},
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
		Revision:  1,
		Verifier:  identity.Verifier(key, secret),
	}
	resSets := map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}

	policyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: sanitize-rule
    effect: sanitize
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: check-rule
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
    checks: [scanner]
`
	s, err := policy.Compile([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(s, registry)
	if err != nil {
		t.Fatal(err)
	}
	a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})

	d, err := eng.Authorize(context.Background(), a, principal)
	if d.Code() != failure.CHECK_UNSUPPORTED || d.Stage != failure.StageAnalysis {
		t.Fatalf("checks MUST be evaluated before sanitize: got code=%q stage=%q", d.Code(), d.Stage)
	}
}

func TestMutationSwapCancelledDeadlineExceeded(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x23}, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-valid",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes: []identity.Scope{
			{Operation: "filesystem.read", ResourceSet: "workspace-read"},
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
		Revision:  1,
		Verifier:  identity.Verifier(key, secret),
	}
	resSets := map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	policyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: allow-1
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	s, err := policy.Compile([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(s, registry)
	if err != nil {
		t.Fatal(err)
	}
	a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})

	// In Decide: Canceled vs DeadlineExceeded
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	dDecideCancel, errCancel := eng.Decide(ctxCancel, a, "acme", "app", "filesystem.read", "/work/file", now.Add(time.Minute))
	if errCancel == nil || dDecideCancel.Code() != failure.CANCELLED || dDecideCancel.Stage != failure.StagePolicy {
		t.Fatalf("Decide: expected CANCELLED/policy, got %q/%q", dDecideCancel.Code(), dDecideCancel.Stage)
	}
	ctxTimeout, cancelTimeout := context.WithDeadline(context.Background(), now.Add(-time.Second))
	defer cancelTimeout()
	dDecideTimeout, errTimeout := eng.Decide(ctxTimeout, a, "acme", "app", "filesystem.read", "/work/file", now.Add(time.Minute))
	if errTimeout == nil || dDecideTimeout.Code() != failure.DEADLINE_EXCEEDED || dDecideTimeout.Stage != failure.StagePolicy {
		t.Fatalf("Decide: expected DEADLINE_EXCEEDED/policy, got %q/%q", dDecideTimeout.Code(), dDecideTimeout.Stage)
	}

	// In Decide: zero or past deadline must give DEADLINE_EXCEEDED/policy
	dDecideZero, errZero := eng.Decide(context.Background(), a, "acme", "app", "filesystem.read", "/work/file", time.Time{})
	if errZero == nil || dDecideZero.Code() != failure.DEADLINE_EXCEEDED || dDecideZero.Stage != failure.StagePolicy {
		t.Fatalf("Decide zero deadline: expected DEADLINE_EXCEEDED/policy, got code=%q stage=%q err=%v", dDecideZero.Code(), dDecideZero.Stage, errZero)
	}
	dDecidePast, errPast := eng.Decide(context.Background(), a, "acme", "app", "filesystem.read", "/work/file", now.Add(-time.Second))
	if errPast == nil || dDecidePast.Code() != failure.DEADLINE_EXCEEDED || dDecidePast.Stage != failure.StagePolicy {
		t.Fatalf("Decide past deadline: expected DEADLINE_EXCEEDED/policy, got code=%q stage=%q err=%v", dDecidePast.Code(), dDecidePast.Stage, errPast)
	}
	dDecideEqual, errEqual := eng.Decide(context.Background(), a, "acme", "app", "filesystem.read", "/work/file", now)
	if errEqual == nil || dDecideEqual.Code() != failure.DEADLINE_EXCEEDED || dDecideEqual.Stage != failure.StagePolicy {
		t.Fatalf("Decide equal deadline: expected DEADLINE_EXCEEDED/policy, got code=%q stage=%q err=%v", dDecideEqual.Code(), dDecideEqual.Stage, errEqual)
	}
}

func TestAuthorizeMultipleDenyAndAllowRulesSorted(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x23}, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-valid",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes: []identity.Scope{
			{Operation: "filesystem.read", ResourceSet: "workspace-read"},
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
		Revision:  1,
		Verifier:  identity.Verifier(key, secret),
	}
	resSets := map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	validAction := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})

	// 1. Two deny rules declared in non-sorted order (e.g. z-deny, a-deny)
	denyPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: z-deny
    effect: deny
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: a-deny
    effect: deny
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	denySnapshot, err := policy.Compile([]byte(denyPolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	denyEngine, err := NewEngine(denySnapshot, registry)
	if err != nil {
		t.Fatal(err)
	}
	dDeny, err := denyEngine.Authorize(context.Background(), validAction, principal)
	assertDecisionBlock(t, "two deny rules", dDeny, err, failure.POLICY_DENIED, failure.StagePolicy, "a-deny", "z-deny")
	if len(dDeny.Reasons) != 2 || dDeny.Reasons[0].RuleID != "a-deny" || dDeny.Reasons[1].RuleID != "z-deny" {
		t.Fatalf("expected reasons [a-deny, z-deny], got: %+v", dDeny.Reasons)
	}

	// 2. Two allow rules declared in non-sorted order (e.g. z-allow, a-allow)
	allowPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: z-allow
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: a-allow
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	allowSnapshot, err := policy.Compile([]byte(allowPolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	allowEngine, err := NewEngine(allowSnapshot, registry)
	if err != nil {
		t.Fatal(err)
	}
	dAllow, err := allowEngine.Authorize(context.Background(), validAction, principal)
	if err != nil {
		t.Fatalf("expected ALLOW, got error: %v", err)
	}
	if dAllow.Effect != ALLOW {
		t.Fatalf("expected Effect ALLOW, got %s", dAllow.Effect)
	}
	if len(dAllow.Reasons) != 2 || dAllow.Reasons[0].RuleID != "a-allow" || dAllow.Reasons[1].RuleID != "z-allow" {
		t.Fatalf("expected reasons [a-allow, z-allow], got: %+v", dAllow.Reasons)
	}
	if dAllow.Reasons[0].Code != "POLICY_ALLOWED" || dAllow.Reasons[1].Code != "POLICY_ALLOWED" {
		t.Fatalf("expected reason codes POLICY_ALLOWED, got: %+v", dAllow.Reasons)
	}
}

func TestContextCancellationPrecedenceAndDecideOrder(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x23}, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-valid",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes: []identity.Scope{
			{Operation: "filesystem.read", ResourceSet: "workspace-read"},
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
		Revision:  1,
		Verifier:  identity.Verifier(key, secret),
	}
	resSets := map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	policyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: allow-1
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	s, err := policy.Compile([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(s, registry)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Authorize with cancelled ctx AND unauthorizable action returns CANCELLED (ctx first)
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()

	unauthorizableAction := action.Action{}
	if unauthorizableAction.Authorizable() {
		t.Fatal("expected unauthorizable action")
	}

	dAuth, err := eng.Authorize(ctxCancel, unauthorizableAction, principal)
	assertDecisionBlock(t, "Authorize cancelled ctx with unauthorizable action", dAuth, err, failure.CANCELLED, failure.StagePolicy)

	// 2. Decide with cancelled ctx returns CANCELLED/policy
	validAction := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	dDecide, errDecide := eng.Decide(ctxCancel, validAction, "acme", "app", "filesystem.read", "/work/file", now.Add(time.Minute))
	if errDecide == nil || !errors.Is(errDecide, ErrNonAllow) {
		t.Fatalf("Decide: expected ErrNonAllow, got %v", errDecide)
	}
	if dDecide.Code() != failure.CANCELLED || dDecide.Stage != failure.StagePolicy {
		t.Fatalf("Decide: expected CANCELLED/policy, got code=%q stage=%q", dDecide.Code(), dDecide.Stage)
	}
}

func TestAllowReasonSemanticsAndSortedUniqueRuleIDs(t *testing.T) {
	if allowReason != "POLICY_ALLOWED" {
		t.Fatalf("expected allowReason == %q, got %q", "POLICY_ALLOWED", allowReason)
	}
	if failure.Code(allowReason).Valid() {
		t.Fatalf("expected failure.Code(allowReason).Valid() == false, got true for %q", allowReason)
	}

	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x23}, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-valid",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes: []identity.Scope{
			{Operation: "filesystem.read", ResourceSet: "workspace-read"},
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
		Revision:  1,
		Verifier:  identity.Verifier(key, secret),
	}
	resSets := map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	validAction := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})

	allowPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: rule-z
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: rule-a
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
  - id: rule-m
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	snapshot, err := policy.Compile([]byte(allowPolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}

	d, err := eng.Authorize(context.Background(), validAction, principal)
	if err != nil {
		t.Fatalf("expected ALLOW, got error: %v", err)
	}
	if d.Effect != ALLOW {
		t.Fatalf("expected Effect ALLOW, got %s", d.Effect)
	}
	if len(d.Reasons) != 3 {
		t.Fatalf("expected 3 reasons, got %d: %+v", len(d.Reasons), d.Reasons)
	}
	wantRules := []string{"rule-a", "rule-m", "rule-z"}
	for i, r := range d.Reasons {
		if r.Code != allowReason {
			t.Fatalf("reason %d: expected code %q, got %q", i, allowReason, r.Code)
		}
		if r.RuleID != wantRules[i] {
			t.Fatalf("reason %d: expected RuleID %q, got %q", i, wantRules[i], r.RuleID)
		}
	}
	for i := 0; i < len(d.Reasons)-1; i++ {
		if d.Reasons[i].RuleID >= d.Reasons[i+1].RuleID {
			t.Fatalf("reasons not sorted/unique: %q >= %q", d.Reasons[i].RuleID, d.Reasons[i+1].RuleID)
		}
	}

	single := makeReasons(allowReason, []string{"single-rule"})
	if len(single) != 1 || single[0].Code != allowReason || single[0].RuleID != "single-rule" {
		t.Fatalf("single reason unexpected: %+v", single)
	}
	empty := makeReasons(allowReason, nil)
	if len(empty) != 1 || empty[0].Code != allowReason || empty[0].RuleID != "" {
		t.Fatalf("empty rule_id reason unexpected: %+v", empty)
	}
}

func TestEnvelopeDerivedDeadlineAndEvaluationBudget(t *testing.T) {
	baseTime := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x42}, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:          "key-1",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:    baseTime.Add(-time.Hour),
		ExpiresAt:   baseTime.Add(time.Hour),
		Revision:    1,
		Verifier:    identity.Verifier(key, secret),
	}
	resSets := map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", baseTime)
	if err != nil {
		t.Fatal(err)
	}
	policyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: allow-work
    effect: allow
    match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}
`
	snapshot, err := policy.Compile([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	schema := action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}}

	t.Run("WithClock(nil) returns constructor error", func(t *testing.T) {
		_, err := NewEngine(snapshot, registry, WithClock(nil))
		if !errors.Is(err, ErrNonAllow) {
			t.Fatalf("expected ErrNonAllow from NewEngine with nil clock, got %v", err)
		}
		counters := &telemetry.Counters{}
		_, err = NewEngineWithTelemetry(snapshot, registry, counters, WithClock(nil))
		if !errors.Is(err, ErrNonAllow) {
			t.Fatalf("expected ErrNonAllow from NewEngineWithTelemetry with nil clock, got %v", err)
		}
	})

	t.Run("Action not from NormalizeAction returns BINDING_MISMATCH", func(t *testing.T) {
		engine, err := NewEngine(snapshot, registry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		d1, err := engine.Authorize(context.Background(), action.Action{}, principal)
		assertDecisionBlock(t, "empty action", d1, err, failure.BINDING_MISMATCH, failure.StageNormalize)
		if len(d1.Reasons) != 1 || d1.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d1.Reasons)
		}

		synthetic := action.Action{SchemaVersion: action.Version, Digest: "sha256:" + strings.Repeat("a", 64)}
		d2, err := engine.Authorize(context.Background(), synthetic, principal)
		assertDecisionBlock(t, "synthetic action", d2, err, failure.BINDING_MISMATCH, failure.StageNormalize)
		if len(d2.Reasons) != 1 || d2.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d2.Reasons)
		}
	})

	t.Run("deadline already passed at entry", func(t *testing.T) {
		engine, err := NewEngine(snapshot, registry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		pastAction := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-time.Minute)}, time.Second)
		d, err := engine.Authorize(context.Background(), pastAction, principal)
		assertDecisionBlock(t, "deadline passed at entry", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("clock rollback Now < receivedAt", func(t *testing.T) {
		rollbackClock := fakeClock{now: baseTime.Add(-time.Second)}
		engine, err := NewEngine(snapshot, registry, WithClock(rollbackClock))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "clock rollback", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("boundary engine now == deadline at entry", func(t *testing.T) {
		engine, err := NewEngine(snapshot, registry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		boundaryAction := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-10 * time.Second)}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), boundaryAction, principal)
		assertDecisionBlock(t, "engine now == deadline at entry", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("entry deadline passed with Validate failure (AUTH_FORBIDDEN) returns DEADLINE_EXCEEDED", func(t *testing.T) {
		engine, err := NewEngine(snapshot, registry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		// /forbidden/path is outside principal's scope (/work/**).
		// If entry deadline check were missing, Validate would reject earlier with AUTH_FORBIDDEN/auth.
		pastAction := testNormalizeActionWithClock(t, principal, "fs.read", "/forbidden/path", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-time.Minute)}, time.Second)
		d, err := engine.Authorize(context.Background(), pastAction, principal)
		assertDecisionBlock(t, "deadline passed at entry with AUTH_FORBIDDEN candidate", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("boundary engine now == deadline with Validate failure (AUTH_FORBIDDEN) returns DEADLINE_EXCEEDED", func(t *testing.T) {
		engine, err := NewEngine(snapshot, registry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		// If !now.Before(deadline) were mutated to now.After(deadline), this boundary case would bypass the entry check and return AUTH_FORBIDDEN.
		boundaryAction := testNormalizeActionWithClock(t, principal, "fs.read", "/forbidden/path", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-10 * time.Second)}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), boundaryAction, principal)
		assertDecisionBlock(t, "boundary engine now == deadline with AUTH_FORBIDDEN candidate", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("entry deadline passed with Validate failure (AUTH_INVALID) returns DEADLINE_EXCEEDED", func(t *testing.T) {
		otherRegistry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		// Engine uses otherRegistry, so principal.registry != engine.sealed.registry -> Validate returns ErrAuthentication (AUTH_INVALID).
		engine, err := NewEngine(snapshot, otherRegistry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		pastAction := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-time.Minute)}, time.Second)
		d, err := engine.Authorize(context.Background(), pastAction, principal)
		assertDecisionBlock(t, "deadline passed at entry with AUTH_INVALID candidate", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("boundary engine now == deadline with Validate failure (AUTH_INVALID) returns DEADLINE_EXCEEDED", func(t *testing.T) {
		otherRegistry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngine(snapshot, otherRegistry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		boundaryAction := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-10 * time.Second)}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), boundaryAction, principal)
		assertDecisionBlock(t, "boundary engine now == deadline with AUTH_INVALID candidate", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("entry deadline passed with policy deny returns DEADLINE_EXCEEDED", func(t *testing.T) {
		denyPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules: []
`
		denySnapshot, err := policy.Compile([]byte(denyPolicyYAML))
		if err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngine(denySnapshot, registry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		// Action is permitted by Validate (/work/file), but policy denies.
		// If entry deadline check were missing, snapshot.Evaluate would return POLICY_DENIED.
		pastAction := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-time.Minute)}, time.Second)
		d, err := engine.Authorize(context.Background(), pastAction, principal)
		assertDecisionBlock(t, "deadline passed at entry with policy deny", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("boundary engine now == deadline with policy deny returns DEADLINE_EXCEEDED", func(t *testing.T) {
		denyPolicyYAML := `schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules: []
`
		denySnapshot, err := policy.Compile([]byte(denyPolicyYAML))
		if err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngine(denySnapshot, registry, WithClock(fakeClock{now: baseTime}))
		if err != nil {
			t.Fatal(err)
		}
		boundaryAction := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime.Add(-10 * time.Second)}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), boundaryAction, principal)
		assertDecisionBlock(t, "boundary engine now == deadline with policy deny", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("deadline passes during evaluation", func(t *testing.T) {
		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(time.Second)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 500*time.Millisecond)
		d, err := engine.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "deadline passes during evaluation", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("budget exceeded while deadline in future", func(t *testing.T) {
		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(501 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "budget exceeded while deadline in future", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("boundary freshNow == budget (+500ms)", func(t *testing.T) {
		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(500 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "boundary freshNow == budget", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("ttl 100ms fresh read 200ms past deadline inside budget returns DEADLINE_EXCEEDED", func(t *testing.T) {
		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(200 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 100*time.Millisecond)
		d, err := engine.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "fresh read 200ms past deadline inside budget", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("boundary fresh read == deadline exactly with ttl 100ms returns DEADLINE_EXCEEDED", func(t *testing.T) {
		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(100 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 100*time.Millisecond)
		d, err := engine.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "boundary fresh read == deadline exactly with ttl 100ms", d, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
		if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "" {
			t.Fatalf("expected 1 reason with empty RuleID, got %+v", d.Reasons)
		}
	})

	t.Run("post-eval now+499ms returns ALLOW and pins exactly 2 clock calls", func(t *testing.T) {
		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(499 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 10*time.Second)
		d, err := engine.Authorize(context.Background(), a, principal)
		if err != nil {
			t.Fatalf("expected ALLOW, got error: %v", err)
		}
		if d.Effect != ALLOW {
			t.Fatalf("expected ALLOW effect, got %s", d.Effect)
		}
		if clk.calls != 2 {
			t.Fatalf("expected Authorize to call engine clock exactly 2 times on ALLOW path, got %d", clk.calls)
		}
	})

	t.Run("ALLOW with ttl 10s and credential valid 1h", func(t *testing.T) {
		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(10 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 10*time.Second)
		receivedAt, deadline, ok := a.TrustedDeadline()
		if !ok {
			t.Fatal("expected ok from TrustedDeadline")
		}
		expectedDeadline := receivedAt.Add(10 * time.Second)
		if !deadline.Equal(expectedDeadline) {
			t.Fatalf("expected deadline %v, got %v", expectedDeadline, deadline)
		}

		d, err := engine.Authorize(context.Background(), a, principal)
		if err != nil {
			t.Fatalf("expected ALLOW, got error: %v", err)
		}
		if d.Effect != ALLOW {
			t.Fatalf("expected ALLOW, got %s", d.Effect)
		}
		if !d.EvaluatedAt.Equal(baseTime.UTC()) {
			t.Fatalf("expected EvaluatedAt %v, got %v", baseTime.UTC(), d.EvaluatedAt)
		}
		if !d.ExpiresAt.Equal(deadline) {
			t.Fatalf("expected d.ExpiresAt == deadline exactly (%v vs %v)", d.ExpiresAt, deadline)
		}
	})

	t.Run("ALLOW with ttl 30s and credential valid 30s", func(t *testing.T) {
		cred30s := cred
		cred30s.ID = "key-30s"
		cred30s.ExpiresAt = baseTime.Add(30 * time.Second)
		cred30s.Verifier = identity.Verifier(key, secret)
		reg30s, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred30s}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		p30s, err := reg30s.Authenticate(string(secret), "data", "acme", "filesystem.read", baseTime)
		if err != nil {
			t.Fatal(err)
		}

		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(10 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, reg30s, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, p30s, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 30*time.Second)
		_, deadline, ok := a.TrustedDeadline()
		if !ok {
			t.Fatal("expected ok from TrustedDeadline")
		}

		d, err := engine.Authorize(context.Background(), a, p30s)
		if err != nil {
			t.Fatalf("expected ALLOW, got error: %v", err)
		}
		if d.Effect != ALLOW {
			t.Fatalf("expected ALLOW, got %s", d.Effect)
		}
		if !d.ExpiresAt.Equal(deadline) {
			t.Fatalf("expected d.ExpiresAt.Equal(deadline), got d.ExpiresAt=%v deadline=%v", d.ExpiresAt, deadline)
		}
	})

	t.Run("ALLOW with ttl 30s and credential valid 1h, engine entry now == receivedAt + 5s", func(t *testing.T) {
		// receivedAt = baseTime, ttl = 30s -> deadline = baseTime + 30s.
		// Credential valid 1h -> principal.ExpiresAt() = baseTime + 1h.
		// Entry now = baseTime + 5s -> now + 30s = baseTime + 35s.
		// min(now+30s, deadline, principal.ExpiresAt()) == deadline (baseTime + 30s).
		clk := &scriptClock{times: []time.Time{baseTime.Add(5 * time.Second), baseTime.Add(5*time.Second + 10*time.Millisecond)}}
		engine, err := NewEngine(snapshot, registry, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 30*time.Second)
		_, deadline, ok := a.TrustedDeadline()
		if !ok {
			t.Fatal("expected ok from TrustedDeadline")
		}
		d, err := engine.Authorize(context.Background(), a, principal)
		if err != nil {
			t.Fatalf("expected ALLOW, got error: %v", err)
		}
		if d.Effect != ALLOW {
			t.Fatalf("expected ALLOW, got %s", d.Effect)
		}
		if !d.ExpiresAt.Equal(deadline) {
			t.Fatalf("expected d.ExpiresAt.Equal(deadline), got d.ExpiresAt=%v deadline=%v", d.ExpiresAt, deadline)
		}
	})

	t.Run("ALLOW with ttl 30s and credential valid 15s (credential binding)", func(t *testing.T) {
		// Credential expiry is 15s, which is strictly smaller than deadline (30s) and now+30s (30s).
		cred15s := cred
		cred15s.ID = "key-15s"
		cred15s.ExpiresAt = baseTime.Add(15 * time.Second)
		cred15s.Verifier = identity.Verifier(key, secret)
		reg15s, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred15s}, resSets)
		if err != nil {
			t.Fatal(err)
		}
		p15s, err := reg15s.Authenticate(string(secret), "data", "acme", "filesystem.read", baseTime)
		if err != nil {
			t.Fatal(err)
		}

		clk := &scriptClock{times: []time.Time{baseTime, baseTime.Add(10 * time.Millisecond)}}
		engine, err := NewEngine(snapshot, reg15s, WithClock(clk))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeActionWithClock(t, p15s, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 30*time.Second)
		d, err := engine.Authorize(context.Background(), a, p15s)
		if err != nil {
			t.Fatalf("expected ALLOW, got error: %v", err)
		}
		if d.Effect != ALLOW {
			t.Fatalf("expected ALLOW, got %s", d.Effect)
		}
		// Every ExpiresAt term has a test where it is the binding one EXCEPT now+30s:
		// - deadline binding: ttl 10s with credential valid 1h; or ttl 30s, cred 1h, entry now == receivedAt + 5s (where now+30s would be later than deadline).
		// - principal.ExpiresAt() binding: this case, ttl 30s with credential valid 15s.
		// - now+30s: because now >= receivedAt and ttl <= 30s, now+30s is mathematically >= receivedAt+30s >= deadline.
		//   Thus now+30s is never strictly smaller than deadline (expected equivalent when now == receivedAt and ttl == 30s).
		if !d.ExpiresAt.Equal(p15s.ExpiresAt()) {
			t.Fatalf("expected d.ExpiresAt.Equal(principal.ExpiresAt()), got d.ExpiresAt=%v principal=%v", d.ExpiresAt, p15s.ExpiresAt())
		}
	})

	t.Run("minting clock with sub-millisecond nanos floors deadline to millisecond", func(t *testing.T) {
		mintTime := baseTime.Add(123456789 * time.Nanosecond)
		mintClock := fakeClock{now: mintTime}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, mintClock, 10*time.Second)

		_, deadline, ok := a.TrustedDeadline()
		if !ok {
			t.Fatal("expected ok from TrustedDeadline")
		}
		env, ok := a.TrustedEnvelope()
		if !ok {
			t.Fatal("expected ok from TrustedEnvelope")
		}

		const layout = "2006-01-02T15:04:05.000Z"
		if deadline.UTC().Format(layout) != env.DeadlineAt {
			t.Fatalf("expected deadline formatted %q == env.DeadlineAt %q", deadline.UTC().Format(layout), env.DeadlineAt)
		}
		parsedDeadlineAt, err := time.Parse(layout, env.DeadlineAt)
		if err != nil {
			t.Fatalf("failed to parse env.DeadlineAt: %v", err)
		}
		if !deadline.Equal(parsedDeadlineAt) {
			t.Fatalf("expected deadline %v to roundtrip parsed env.DeadlineAt %v", deadline, parsedDeadlineAt)
		}

		// Engine clock reading == published deadline_at parsed back (or deadline exactly) -> DEADLINE_EXCEEDED
		clkAtDeadline := &scriptClock{times: []time.Time{parsedDeadlineAt, parsedDeadlineAt.Add(10 * time.Millisecond)}}
		engineAtDeadline, err := NewEngine(snapshot, registry, WithClock(clkAtDeadline))
		if err != nil {
			t.Fatal(err)
		}
		dAt, err := engineAtDeadline.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "engine clock == deadline exactly", dAt, err, failure.DEADLINE_EXCEEDED, failure.StagePolicy)

		// Reading 1 ns before deadline -> passes deadline check (ALLOW)
		beforeDeadline := deadline.Add(-1 * time.Nanosecond)
		clkBefore := &scriptClock{times: []time.Time{beforeDeadline, beforeDeadline}}
		engineBefore, err := NewEngine(snapshot, registry, WithClock(clkBefore))
		if err != nil {
			t.Fatal(err)
		}
		dBefore, err := engineBefore.Authorize(context.Background(), a, principal)
		if err != nil {
			t.Fatalf("expected ALLOW for reading 1 ns before deadline, got error: %v", err)
		}
		if dBefore.Effect != ALLOW {
			t.Fatalf("expected ALLOW effect, got %s (code=%s stage=%s)", dBefore.Effect, dBefore.Code(), dBefore.Stage)
		}
	})

	t.Run("engine whose sealed config has nil clock returns POLICY_UNAVAILABLE/policy", func(t *testing.T) {
		eng := Engine{
			sealed: &engineConfiguration{
				policy:   snapshot,
				registry: registry,
				counters: &telemetry.Counters{},
				clock:    nil,
			},
		}
		a := testNormalizeActionWithClock(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema, fakeClock{now: baseTime}, 10*time.Second)
		d, err := eng.Authorize(context.Background(), a, principal)
		assertDecisionBlock(t, "sealed config with nil clock", d, err, failure.POLICY_UNAVAILABLE, failure.StagePolicy)
	})

	t.Run("early rejection timestamp from sealed clock on cancelled context", func(t *testing.T) {
		fakeNow := time.Date(2025, 5, 20, 9, 30, 0, 0, time.UTC)
		engine, err := NewEngine(snapshot, registry, WithClock(fakeClock{now: fakeNow}))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		d, err := engine.Authorize(ctx, action.Action{}, principal)
		if !errors.Is(err, ErrNonAllow) {
			t.Fatalf("expected ErrNonAllow, got %v", err)
		}
		if d.Effect != BLOCK {
			t.Fatalf("expected BLOCK, got %v", d.Effect)
		}
		if d.Code() != failure.CANCELLED {
			t.Fatalf("expected CANCELLED, got %v", d.Code())
		}
		if d.Stage != failure.StagePolicy {
			t.Fatalf("expected StagePolicy, got %v", d.Stage)
		}
		if !d.EvaluatedAt.Equal(fakeNow.UTC()) {
			t.Fatalf("expected EvaluatedAt %v, got %v", fakeNow.UTC(), d.EvaluatedAt)
		}
		if !d.ExpiresAt.Equal(fakeNow.UTC()) {
			t.Fatalf("expected ExpiresAt %v, got %v", fakeNow.UTC(), d.ExpiresAt)
		}
	})
}

func TestReasonJSONMarshaling(t *testing.T) {
	// Reason without RuleID marshals as {"code":"..."} with no rule_id key
	rNoRule := Reason{Code: "POLICY_DENIED"}
	bNoRule, err := json.Marshal(rNoRule)
	if err != nil {
		t.Fatal(err)
	}
	if string(bNoRule) != `{"code":"POLICY_DENIED"}` {
		t.Errorf("got %s, want %s", string(bNoRule), `{"code":"POLICY_DENIED"}`)
	}
	if strings.Contains(string(bNoRule), "rule_id") {
		t.Errorf("expected rule_id to be omitted when empty, got %s", string(bNoRule))
	}

	// Reason with RuleID marshals as {"code":"...","rule_id":"..."}
	rWithRule := Reason{Code: "POLICY_DENIED", RuleID: "rule-1"}
	bWithRule, err := json.Marshal(rWithRule)
	if err != nil {
		t.Fatal(err)
	}
	if string(bWithRule) != `{"code":"POLICY_DENIED","rule_id":"rule-1"}` {
		t.Errorf("got %s, want %s", string(bWithRule), `{"code":"POLICY_DENIED","rule_id":"rule-1"}`)
	}
}

func TestCorrelationFieldsAndIDSource(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	cred := identity.Credential{
		ID:              "key-1",
		TenantID:        "acme",
		PrincipalID:     "app",
		Audience:        "data",
		Scopes:          []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:        now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		Revision:        1,
		RevocationEpoch: 7,
		Verifier:        identity.Verifier(key, secret),
	}
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow-rule\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	schema := action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}}

	// WithIDSource(nil) -> constructor ErrNonAllow
	t.Run("WithIDSource(nil) returns ErrNonAllow", func(t *testing.T) {
		_, err := NewEngine(snapshot, registry, WithIDSource(nil))
		if !errors.Is(err, ErrNonAllow) {
			t.Fatalf("expected ErrNonAllow for WithIDSource(nil), got %v", err)
		}
	})

	// deterministic fake IDSource -> DecisionID equals it on ALLOW and on POLICY_DENIED
	t.Run("deterministic fake IDSource matches DecisionID on ALLOW and POLICY_DENIED", func(t *testing.T) {
		const fakeID = "dec-12345"
		engine, err := NewEngine(snapshot, registry, WithIDSource(fakeIDSource{id: fakeID}))
		if err != nil {
			t.Fatal(err)
		}

		// ALLOW case
		aAllow := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema)
		dAllow, err := engine.Authorize(context.Background(), aAllow, principal)
		if err != nil || dAllow.Effect != ALLOW {
			t.Fatalf("expected ALLOW, got %v (%+v)", err, dAllow)
		}
		if dAllow.DecisionID != fakeID {
			t.Fatalf("expected DecisionID %q on ALLOW, got %q", fakeID, dAllow.DecisionID)
		}

		// Check correlation fields on ALLOW:
		// ALLOW carries ActionID == envelope action_id, ToolRevision == TrustedContext().ToolRevision(), Boundary == TrustedContext().Boundary(), RevocationEpoch == principal's
		te, ok := aAllow.TrustedEnvelope()
		if !ok || te.ActionID == "" {
			t.Fatal("expected trusted envelope on authorizable action")
		}
		tc, ok := aAllow.TrustedContext()
		if !ok || tc.ToolRevision() == "" {
			t.Fatal("expected trusted context on authorizable action")
		}
		if dAllow.ActionID != te.ActionID {
			t.Errorf("expected ActionID %q, got %q", te.ActionID, dAllow.ActionID)
		}
		if dAllow.ToolRevision != tc.ToolRevision() {
			t.Errorf("expected ToolRevision %q, got %q", tc.ToolRevision(), dAllow.ToolRevision)
		}
		if dAllow.Boundary != string(tc.Boundary()) {
			t.Errorf("expected Boundary %q, got %q", string(tc.Boundary()), dAllow.Boundary)
		}
		if dAllow.RevocationEpoch != principal.RevocationEpoch() {
			t.Errorf("expected RevocationEpoch %d, got %d", principal.RevocationEpoch(), dAllow.RevocationEpoch)
		}
		if dAllow.RevocationEpoch != 7 {
			t.Errorf("expected non-zero RevocationEpoch 7, got %d", dAllow.RevocationEpoch)
		}

		// POLICY_DENIED case
		denySnapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules: []\n"))
		if err != nil {
			t.Fatal(err)
		}
		denyEngine, err := NewEngine(denySnapshot, registry, WithIDSource(fakeIDSource{id: fakeID}))
		if err != nil {
			t.Fatal(err)
		}
		dDeny, err := denyEngine.Authorize(context.Background(), aAllow, principal)
		if !errors.Is(err, ErrNonAllow) || dDeny.Effect != BLOCK || dDeny.Code() != failure.POLICY_DENIED {
			t.Fatalf("expected POLICY_DENIED block, got %v (%+v)", err, dDeny)
		}
		if dDeny.DecisionID != fakeID {
			t.Fatalf("expected DecisionID %q on POLICY_DENIED, got %q", fakeID, dDeny.DecisionID)
		}
	})

	// IDSource error -> INTERNAL_ERROR/policy, DecisionID ""; telemetry counts authority block
	t.Run("IDSource error yields INTERNAL_ERROR and empty DecisionID, classified authority", func(t *testing.T) {
		counters := &telemetry.Counters{}
		engine, err := NewEngineWithTelemetry(snapshot, registry, counters, WithIDSource(errorIDSource{err: errors.New("entropy exhausted")}))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema)
		d, err := engine.Authorize(context.Background(), a, principal)
		if !errors.Is(err, ErrNonAllow) {
			t.Fatalf("expected ErrNonAllow, got %v", err)
		}
		if d.Effect != BLOCK || d.Code() != failure.INTERNAL_ERROR || d.Stage != failure.StagePolicy {
			t.Fatalf("expected INTERNAL_ERROR/policy, got %+v", d)
		}
		if d.DecisionID != "" {
			t.Fatalf("expected empty DecisionID on IDSource error, got %q", d.DecisionID)
		}
		// Assert authority block telemetry incremented
		prom := counters.Prometheus()
		if !strings.Contains(prom, "guardfil_decision_authority_blocks_total 1") {
			t.Fatalf("expected authority blocks counter incremented, got:\n%s", prom)
		}
	})

	// Fake IDSource returning a VALID id together with a non-nil error -> Authorize returns INTERNAL_ERROR/policy with DecisionID ""
	t.Run("IDSource returning valid ID with non-nil error yields INTERNAL_ERROR and empty DecisionID", func(t *testing.T) {
		counters := &telemetry.Counters{}
		engine, err := NewEngineWithTelemetry(snapshot, registry, counters, WithIDSource(validIDWithErrorSource{id: "dec-valid-err", err: errors.New("entropy failure")}))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema)
		d, err := engine.Authorize(context.Background(), a, principal)
		if !errors.Is(err, ErrNonAllow) {
			t.Fatalf("expected ErrNonAllow, got %v", err)
		}
		if d.Effect != BLOCK || d.Code() != failure.INTERNAL_ERROR || d.Stage != failure.StagePolicy {
			t.Fatalf("expected INTERNAL_ERROR/policy, got %+v", d)
		}
		if d.DecisionID != "" {
			t.Fatalf("expected empty DecisionID on IDSource error even with valid ID, got %q", d.DecisionID)
		}
		// Assert authority block telemetry incremented
		prom := counters.Prometheus()
		if !strings.Contains(prom, "guardfil_decision_authority_blocks_total 1") {
			t.Fatalf("expected authority blocks counter incremented, got:\n%s", prom)
		}
	})

	// If minting fails, INTERNAL_ERROR wins over CANCELLED
	t.Run("if minting fails INTERNAL_ERROR wins over CANCELLED", func(t *testing.T) {
		engine, err := NewEngine(snapshot, registry, WithIDSource(validIDWithErrorSource{id: "dec-valid-mint-err", err: errors.New("entropy error")}))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // context is cancelled before call
		a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema)
		d, err := engine.Authorize(ctx, a, principal)
		if !errors.Is(err, ErrNonAllow) {
			t.Fatalf("expected ErrNonAllow, got %v", err)
		}
		if d.Code() != failure.INTERNAL_ERROR {
			t.Fatalf("expected INTERNAL_ERROR to win over CANCELLED, got code %q", d.Code())
		}
		if d.Stage != failure.StagePolicy {
			t.Fatalf("expected StagePolicy, got %q", d.Stage)
		}
		if d.DecisionID != "" {
			t.Fatalf("expected empty DecisionID, got %q", d.DecisionID)
		}
	})

	// ID "" or containing a space -> INTERNAL_ERROR
	t.Run("invalid ID yields INTERNAL_ERROR and empty DecisionID", func(t *testing.T) {
		for _, invalidID := range []string{"", "has space", "@badchar", strings.Repeat("x", 129)} {
			engine, err := NewEngine(snapshot, registry, WithIDSource(fakeIDSource{id: invalidID}))
			if err != nil {
				t.Fatal(err)
			}
			a := testNormalizeAction(t, principal, "fs.read", "/work/file", []byte(`{"n":1}`), schema)
			d, err := engine.Authorize(context.Background(), a, principal)
			if !errors.Is(err, ErrNonAllow) || d.Effect != BLOCK || d.Code() != failure.INTERNAL_ERROR || d.Stage != failure.StagePolicy {
				t.Fatalf("id %q: expected INTERNAL_ERROR/policy, got %+v, %v", invalidID, d, err)
			}
			if d.DecisionID != "" {
				t.Fatalf("id %q: expected empty DecisionID, got %q", invalidID, d.DecisionID)
			}
		}
	})

	// BINDING_MISMATCH (non-authorizable action):
	// DecisionID set but ActionID/ToolRevision/Boundary empty
	t.Run("non-authorizable action has DecisionID set but ActionID/ToolRevision/Boundary empty", func(t *testing.T) {
		const fakeID = "dec-non-auth-1"
		engine, err := NewEngine(snapshot, registry, WithIDSource(fakeIDSource{id: fakeID}))
		if err != nil {
			t.Fatal(err)
		}
		nonAuthorizable := action.Action{} // zero action is not authorizable
		d, err := engine.Authorize(context.Background(), nonAuthorizable, principal)
		if !errors.Is(err, ErrNonAllow) || d.Effect != BLOCK || d.Code() != failure.BINDING_MISMATCH {
			t.Fatalf("expected BINDING_MISMATCH, got %+v, %v", d, err)
		}
		if d.DecisionID != fakeID {
			t.Fatalf("expected DecisionID %q, got %q", fakeID, d.DecisionID)
		}
		if d.ActionID != "" {
			t.Fatalf("expected empty ActionID on non-authorizable action, got %q", d.ActionID)
		}
		if d.ToolRevision != "" {
			t.Fatalf("expected empty ToolRevision on non-authorizable action, got %q", d.ToolRevision)
		}
		if d.Boundary != "" {
			t.Fatalf("expected empty Boundary on non-authorizable action, got %q", d.Boundary)
		}
	})

	// AUTH_INVALID decision has ActionID set but RevocationEpoch 0
	t.Run("AUTH_INVALID decision has ActionID set but RevocationEpoch 0", func(t *testing.T) {
		const fakeID = "dec-auth-invalid"
		engine, err := NewEngine(snapshot, registry, WithIDSource(fakeIDSource{id: fakeID}))
		if err != nil {
			t.Fatal(err)
		}

		keyOther := make([]byte, 32)
		keyOther[0] = 0xff
		credOther := cred
		credOther.Verifier = identity.Verifier(keyOther, secret)
		registryOther, err := identity.NewRegistryWithResourceSets(keyOther, []identity.Credential{credOther}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
		if err != nil {
			t.Fatal(err)
		}
		pOther, err := registryOther.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatal(err)
		}
		if pOther.RevocationEpoch() != 7 {
			t.Fatalf("expected pOther RevocationEpoch 7, got %d", pOther.RevocationEpoch())
		}

		a := testNormalizeAction(t, pOther, "fs.read", "/work/file", []byte(`{"n":1}`), schema)
		te, ok := a.TrustedEnvelope()
		if !ok || te.ActionID == "" {
			t.Fatal("expected trusted envelope on authorizable action")
		}

		d, err := engine.Authorize(context.Background(), a, pOther)
		if !errors.Is(err, ErrNonAllow) || d.Effect != BLOCK || d.Code() != failure.AUTH_INVALID || d.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_INVALID/auth, got %+v, %v", d, err)
		}
		if d.DecisionID != fakeID {
			t.Fatalf("expected DecisionID %q, got %q", fakeID, d.DecisionID)
		}
		if d.ActionID != te.ActionID {
			t.Fatalf("expected ActionID %q on AUTH_INVALID, got %q", te.ActionID, d.ActionID)
		}
		if d.RevocationEpoch != 0 {
			t.Fatalf("expected RevocationEpoch 0 on AUTH_INVALID, got %d", d.RevocationEpoch)
		}
	})

	// Non-zero RevocationEpoch principal rejected with AUTHORIZATION_STALE has ActionID set but RevocationEpoch 0
	t.Run("non-zero RevocationEpoch principal rejected with AUTHORIZATION_STALE has ActionID set but RevocationEpoch 0", func(t *testing.T) {
		const fakeID = "dec-auth-stale"
		credStale := identity.Credential{
			ID:              "key-stale",
			TenantID:        "acme",
			PrincipalID:     "app",
			Audience:        "data",
			Scopes:          []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
			IssuedAt:        now.Add(-time.Hour),
			ExpiresAt:       now.Add(time.Hour),
			Revision:        1,
			RevocationEpoch: 7,
			Verifier:        identity.Verifier(key, secret),
		}
		regStale, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credStale}, map[string][]identity.Resource{"workspace-read": {{Kind: "path", Value: "/work/**"}}})
		if err != nil {
			t.Fatal(err)
		}
		pStale, err := regStale.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatal(err)
		}
		if pStale.RevocationEpoch() != 7 {
			t.Fatalf("expected principal RevocationEpoch 7, got %d", pStale.RevocationEpoch())
		}

		engineStale, err := NewEngine(snapshot, regStale, WithIDSource(fakeIDSource{id: fakeID}))
		if err != nil {
			t.Fatal(err)
		}
		a := testNormalizeAction(t, pStale, "fs.read", "/work/file", []byte(`{"n":1}`), schema)
		te, ok := a.TrustedEnvelope()
		if !ok || te.ActionID == "" {
			t.Fatal("expected trusted envelope on authorizable action")
		}

		// Revoke the credential to bump the epoch and revoke it in the live registry
		if err := regStale.Revoke("key-stale", 8); err != nil {
			t.Fatal(err)
		}

		d, err := engineStale.Authorize(context.Background(), a, pStale)
		if !errors.Is(err, ErrNonAllow) || d.Effect != BLOCK || d.Code() != failure.AUTHORIZATION_STALE || d.Stage != failure.StageAuth {
			t.Fatalf("expected AUTHORIZATION_STALE/auth, got %+v, %v", d, err)
		}
		if d.DecisionID != fakeID {
			t.Fatalf("expected DecisionID %q, got %q", fakeID, d.DecisionID)
		}
		if d.ActionID != te.ActionID {
			t.Fatalf("expected ActionID %q on AUTHORIZATION_STALE, got %q", te.ActionID, d.ActionID)
		}
		if d.RevocationEpoch != 0 {
			t.Fatalf("expected RevocationEpoch 0 on AUTHORIZATION_STALE, got %d", d.RevocationEpoch)
		}
	})

	// Non-zero RevocationEpoch principal rejected with AUTH_FORBIDDEN has ActionID set but RevocationEpoch 0
	t.Run("non-zero RevocationEpoch principal rejected with AUTH_FORBIDDEN has ActionID set but RevocationEpoch 0", func(t *testing.T) {
		const fakeID = "dec-auth-forbidden"
		engineForbidden, err := NewEngine(snapshot, registry, WithIDSource(fakeIDSource{id: fakeID}))
		if err != nil {
			t.Fatal(err)
		}
		if principal.RevocationEpoch() != 7 {
			t.Fatalf("expected principal RevocationEpoch 7, got %d", principal.RevocationEpoch())
		}

		// Action requesting a resource outside the credential's workspace-read scope (/work/**)
		aForbidden := testNormalizeAction(t, principal, "fs.read", "/other/forbidden", []byte(`{"n":1}`), schema)
		te, ok := aForbidden.TrustedEnvelope()
		if !ok || te.ActionID == "" {
			t.Fatal("expected trusted envelope on authorizable action")
		}

		d, err := engineForbidden.Authorize(context.Background(), aForbidden, principal)
		if !errors.Is(err, ErrNonAllow) || d.Effect != BLOCK || d.Code() != failure.AUTH_FORBIDDEN || d.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_FORBIDDEN/auth, got %+v, %v", d, err)
		}
		if d.DecisionID != fakeID {
			t.Fatalf("expected DecisionID %q, got %q", fakeID, d.DecisionID)
		}
		if d.ActionID != te.ActionID {
			t.Fatalf("expected ActionID %q on AUTH_FORBIDDEN, got %q", te.ActionID, d.ActionID)
		}
		if d.RevocationEpoch != 0 {
			t.Fatalf("expected RevocationEpoch 0 on AUTH_FORBIDDEN, got %d", d.RevocationEpoch)
		}
	})
}

func TestUnsealedEngineCancelledContextOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := (Engine{}).Authorize(ctx, action.Action{}, identity.PrincipalContext{})
	assertDecisionBlock(t, "unsealed engine with cancelled context", d, err, failure.POLICY_UNAVAILABLE, failure.StagePolicy)
}
