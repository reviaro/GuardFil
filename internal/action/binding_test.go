package action_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/identity"
)

func fixtureActor(t testing.TB) (action.Actor, identity.PrincipalContext) {
	t.Helper()
	key, secret := testKeyAndSecret()
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

	reg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, validTestResourceSets())
	if err != nil {
		t.Fatalf("NewRegistryWithResourceSets failed: %v", err)
	}

	ctx, err := reg.Authenticate(secret, "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	actor, err := action.ProjectActor(ctx)
	if err != nil {
		t.Fatalf("ProjectActor failed: %v", err)
	}
	return actor, ctx
}

func fixtureRegistry(t testing.TB) *action.Registry {
	t.Helper()
	reg, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}
	return reg
}

func testEnvelope1(t testing.TB) action.MintedEnvelope {
	t.Helper()
	c := fakeClock{now: time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)}
	ids := fakeIDSource{id: "act-1"}
	env, err := action.NewEnvelope(c, ids, "req-1", "parent-1", "idem-1", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func testEnvelope2(t testing.TB) action.MintedEnvelope {
	t.Helper()
	c := fakeClock{now: time.Date(2026, 9, 24, 17, 1, 0, 0, time.UTC)}
	ids := fakeIDSource{id: "act-2"}
	env, err := action.NewEnvelope(c, ids, "req-2", "parent-2", "idem-2", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func TestBindingVectorsV0V1V2(t *testing.T) {
	actor, _ := fixtureActor(t)
	reg := fixtureRegistry(t)
	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	env := testEnvelope1(t)
	rawPayload := []byte(`{"n":1}`)
	resource := "/work/file"

	// V1: No evidence
	act1, err := action.NormalizeAction(ctx, actor, resource, rawPayload, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}

	// V0 tool_revision check
	tc, ok := act1.TrustedContext()
	if !ok {
		t.Fatal("TrustedContext failed")
	}
	const wantV0ToolRevision = "sha256:fc37ac61e9aebccdd8c878ecd71df5211d2f6b597ff41147e12e9f33325e4384"
	if tc.ToolRevision() != wantV0ToolRevision {
		t.Fatalf("V0 tool_revision mismatch: got %s, want %s", tc.ToolRevision(), wantV0ToolRevision)
	}

	const v1Preimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"fs.read","payload":{"n":1},"payload_schema":"schema-fs","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-fs","resolution_profile":"res-1","resource":"/work/file","resource_kind":"filesystem","route_id":"route-fs"},"tool_revision":"sha256:fc37ac61e9aebccdd8c878ecd71df5211d2f6b597ff41147e12e9f33325e4384"}`
	const wantV1Digest = "sha256:d9a521aabcf523dd77d47d35a45e428a38f8641f39ef0d1d0d1e3f50b9164f1d"

	if digest := sha256Hex(v1Preimage); digest != wantV1Digest {
		t.Fatalf("V1 literal preimage hash mismatch: got %s, want %s", digest, wantV1Digest)
	}
	if act1.TrustedDigest() != wantV1Digest {
		t.Fatalf("V1 NormalizeAction digest mismatch: got %s, want %s", act1.TrustedDigest(), wantV1Digest)
	}

	// V2: One evidence with parent
	evidence1 := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-0"},
	}}
	act2, err := action.NormalizeAction(ctx, actor, resource, rawPayload, env, evidence1)
	if err != nil {
		t.Fatalf("NormalizeAction V2 failed: %v", err)
	}

	const v2Preimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"fs.read","payload":{"n":1},"payload_schema":"schema-fs","provenance":[{"content_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","id":"ev-1","location":"/n","observed_at":"2026-09-24T17:00:00.000Z","origin":"transport","parent_evidence_ids":["ev-0"],"producer_id":"transport-1","producer_revision":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","trust":"authenticated_source"}],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-fs","resolution_profile":"res-1","resource":"/work/file","resource_kind":"filesystem","route_id":"route-fs"},"tool_revision":"sha256:fc37ac61e9aebccdd8c878ecd71df5211d2f6b597ff41147e12e9f33325e4384"}`
	const wantV2Digest = "sha256:5b57c2677d92b358c24d88516936bf34ecdbc85ac44a25f16eec3d8cabd76d53"

	if digest := sha256Hex(v2Preimage); digest != wantV2Digest {
		t.Fatalf("V2 literal preimage hash mismatch: got %s, want %s", digest, wantV2Digest)
	}
	if act2.TrustedDigest() != wantV2Digest {
		t.Fatalf("V2 NormalizeAction digest mismatch: got %s, want %s", act2.TrustedDigest(), wantV2Digest)
	}
}

func TestProvenanceWithoutParentsOmitsKey(t *testing.T) {
	actor, _ := fixtureActor(t)
	reg := fixtureRegistry(t)
	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	evidenceNoParents := []action.Evidence{{
		ID:            "ev-1",
		ProducerID:    "transport-1",
		ContentDigest: "sha256:" + strings.Repeat("c", 64),
		Location:      "/n",
		ObservedAt:    "2026-09-24T17:00:00.000Z",
	}}
	act, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evidenceNoParents)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}

	// Literal preimage WITHOUT "parent_evidence_ids" key
	const wantPreimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"fs.read","payload":{"n":1},"payload_schema":"schema-fs","provenance":[{"content_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","id":"ev-1","location":"/n","observed_at":"2026-09-24T17:00:00.000Z","origin":"transport","producer_id":"transport-1","producer_revision":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","trust":"authenticated_source"}],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-fs","resolution_profile":"res-1","resource":"/work/file","resource_kind":"filesystem","route_id":"route-fs"},"tool_revision":"sha256:fc37ac61e9aebccdd8c878ecd71df5211d2f6b597ff41147e12e9f33325e4384"}`
	wantDigest := sha256Hex(wantPreimage)

	if act.TrustedDigest() != wantDigest {
		t.Fatalf("digest mismatch for evidence without parents: got %s, want %s", act.TrustedDigest(), wantDigest)
	}
}

func TestBindingVectorsV3V4ToolRoute(t *testing.T) {
	actor, _ := fixtureActor(t)
	profile := action.Profile{
		Protocol:        "decision_api",
		ProfileID:       "decision-v1",
		AdapterRevision: "sha256:" + strings.Repeat("a", 64),
	}
	tool := action.Tool{
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
	route := action.Route{
		RouteID:           "route-tool",
		ExecutorID:        "exec-tool",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-t",
		Tools:             []string{"my-tool"},
	}
	reg, err := action.NewRegistry([]action.Profile{profile}, []action.Route{route}, []action.Tool{tool}, nil)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	env := testEnvelope1(t)
	rawPayload := []byte(`{"query":"x"}`)
	resource := "my-tool"
	const wantToolRevision = "sha256:dbfd328c301d10025a5205466a275f3c4b7d4a981e573c5396ce4a81ea1b8bd2"

	// V3: boundary advisory
	ctxV3, err := reg.Context(action.Advisory, "decision-v1", "route-tool")
	if err != nil {
		t.Fatalf("Context V3 failed: %v", err)
	}
	actV3, err := action.NormalizeAction(ctxV3, actor, resource, rawPayload, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction V3 failed: %v", err)
	}
	tcV3, ok := actV3.TrustedContext()
	if !ok {
		t.Fatal("TrustedContext V3 failed")
	}
	if tcV3.ToolRevision() != wantToolRevision {
		t.Fatalf("V3 tool_revision mismatch: got %s, want %s", tcV3.ToolRevision(), wantToolRevision)
	}

	const v3Preimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"tool.invoke","payload":{"query":"x"},"payload_schema":"schema-v1","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-tool","resolution_profile":"res-t","resource":"my-tool","resource_kind":"tool","route_id":"route-tool"},"tool_revision":"sha256:dbfd328c301d10025a5205466a275f3c4b7d4a981e573c5396ce4a81ea1b8bd2"}`
	const wantV3Digest = "sha256:2bfb4d46853d586f71374f0cd9058aa0f3ad604da8a7b3674de48e030059d685"

	if digest := sha256Hex(v3Preimage); digest != wantV3Digest {
		t.Fatalf("V3 literal preimage hash mismatch: got %s, want %s", digest, wantV3Digest)
	}
	if actV3.TrustedDigest() != wantV3Digest {
		t.Fatalf("V3 NormalizeAction digest mismatch: got %s, want %s", actV3.TrustedDigest(), wantV3Digest)
	}

	// V4: identical but boundary proposal_filter
	ctxV4, err := reg.Context(action.ProposalFilter, "decision-v1", "route-tool")
	if err != nil {
		t.Fatalf("Context V4 failed: %v", err)
	}
	actV4, err := action.NormalizeAction(ctxV4, actor, resource, rawPayload, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction V4 failed: %v", err)
	}
	tcV4, ok := actV4.TrustedContext()
	if !ok {
		t.Fatal("TrustedContext V4 failed")
	}
	if tcV4.ToolRevision() != wantToolRevision {
		t.Fatalf("V4 tool_revision mismatch: got %s, want %s", tcV4.ToolRevision(), wantToolRevision)
	}

	const v4Preimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"proposal_filter","operation":"tool.invoke","payload":{"query":"x"},"payload_schema":"schema-v1","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-tool","resolution_profile":"res-t","resource":"my-tool","resource_kind":"tool","route_id":"route-tool"},"tool_revision":"sha256:dbfd328c301d10025a5205466a275f3c4b7d4a981e573c5396ce4a81ea1b8bd2"}`
	const wantV4Digest = "sha256:108ef445a6f461ee32ea71b921b247f238964630c40eb22a5520496ab6503daa"

	if digest := sha256Hex(v4Preimage); digest != wantV4Digest {
		t.Fatalf("V4 literal preimage hash mismatch: got %s, want %s", digest, wantV4Digest)
	}
	if actV4.TrustedDigest() != wantV4Digest {
		t.Fatalf("V4 NormalizeAction digest mismatch: got %s, want %s", actV4.TrustedDigest(), wantV4Digest)
	}
}

func TestBindingVectorV5HTTPRoute(t *testing.T) {
	actor, _ := fixtureActor(t)
	profile := action.Profile{
		Protocol:        "decision_api",
		ProfileID:       "decision-v1",
		AdapterRevision: "sha256:" + strings.Repeat("a", 64),
	}
	route := action.Route{
		RouteID:           "route-http",
		ExecutorID:        "exec-http",
		Operation:         "http.request",
		ResolutionProfile: "res-h",
		PayloadSchema:     "schema-http",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"n": action.Integer,
			},
		},
	}
	reg, err := action.NewRegistry([]action.Profile{profile}, []action.Route{route}, nil, nil)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	env := testEnvelope1(t)
	rawPayload := []byte(`{"n":1}`)
	resource := "https://example.com/a"
	const wantToolRevision = "sha256:0706e562dab6141e3cfde58fb406ba0288602a2ce943a09050a2bc42727baf87"
	const wantV5Digest = "sha256:648921ff3a01cba59df4c4a58c21ce572de3d730771c8fabbb4080ee15e30b1e"
	const v5Preimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"http.request","payload":{"n":1},"payload_schema":"schema-http","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-http","resolution_profile":"res-h","resource":"https://example.com/a","resource_kind":"http","route_id":"route-http"},"tool_revision":"sha256:0706e562dab6141e3cfde58fb406ba0288602a2ce943a09050a2bc42727baf87"}`

	if digest := sha256Hex(v5Preimage); digest != wantV5Digest {
		t.Fatalf("V5 literal preimage hash mismatch: got %s, want %s", digest, wantV5Digest)
	}

	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-http")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}
	act, err := action.NormalizeAction(ctx, actor, resource, rawPayload, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	tc, ok := act.TrustedContext()
	if !ok {
		t.Fatal("TrustedContext failed")
	}
	if tc.ToolRevision() != wantToolRevision {
		t.Fatalf("V5 tool_revision mismatch: got %s, want %s", tc.ToolRevision(), wantToolRevision)
	}
	if act.TrustedDigest() != wantV5Digest {
		t.Fatalf("V5 NormalizeAction digest mismatch: got %s, want %s", act.TrustedDigest(), wantV5Digest)
	}

	// Also: a second URL "https://example.com/b" on the same route gives a different digest.
	actB, err := action.NormalizeAction(ctx, actor, "https://example.com/b", rawPayload, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction for URL b failed: %v", err)
	}
	if actB.TrustedDigest() == wantV5Digest {
		t.Fatalf("expected different digest for second URL, got identical: %s", actB.TrustedDigest())
	}
}

func TestBindingVectorV6SecondTool(t *testing.T) {
	actor, _ := fixtureActor(t)
	profile := action.Profile{
		Protocol:        "decision_api",
		ProfileID:       "decision-v1",
		AdapterRevision: "sha256:" + strings.Repeat("a", 64),
	}
	tool1 := action.Tool{
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
	tool2 := action.Tool{
		ToolID:        "other-tool",
		UpstreamID:    "upstream-a",
		UpstreamName:  "list",
		PayloadSchema: "schema-v2",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"limit": action.Integer,
			},
		},
	}
	route := action.Route{
		RouteID:           "route-tool",
		ExecutorID:        "exec-tool",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-t",
		Tools:             []string{"my-tool", "other-tool"},
	}
	reg, err := action.NewRegistry([]action.Profile{profile}, []action.Route{route}, []action.Tool{tool1, tool2}, nil)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	env := testEnvelope1(t)
	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-tool")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	// V6: second tool on the V3 tool route
	const wantV6ToolRevision = "sha256:70ba867d765549477e19e1f0f6e95bab98845e70e92f9b567535f8cb4bd9f6a0"
	const wantV6Digest = "sha256:7a5b16bef23482d726822d5283df86b6f53f3d42f245c4a66170d89fdabf5791"
	const v6Preimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"tool.invoke","payload":{"limit":3},"payload_schema":"schema-v2","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-tool","resolution_profile":"res-t","resource":"other-tool","resource_kind":"tool","route_id":"route-tool"},"tool_revision":"sha256:70ba867d765549477e19e1f0f6e95bab98845e70e92f9b567535f8cb4bd9f6a0"}`

	if digest := sha256Hex(v6Preimage); digest != wantV6Digest {
		t.Fatalf("V6 literal preimage hash mismatch: got %s, want %s", digest, wantV6Digest)
	}

	rawPayload6 := []byte(`{"limit":3}`)
	act6, err := action.NormalizeAction(ctx, actor, "other-tool", rawPayload6, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction V6 failed: %v", err)
	}
	tc6, ok := act6.TrustedContext()
	if !ok {
		t.Fatal("TrustedContext V6 failed")
	}
	if tc6.ToolRevision() != wantV6ToolRevision {
		t.Fatalf("V6 tool_revision mismatch: got %s, want %s", tc6.ToolRevision(), wantV6ToolRevision)
	}
	if act6.TrustedDigest() != wantV6Digest {
		t.Fatalf("V6 NormalizeAction digest mismatch: got %s, want %s", act6.TrustedDigest(), wantV6Digest)
	}

	// (V3 must still hold in this two-tool registry for "my-tool" — assert it.)
	const wantV3ToolRevision = "sha256:dbfd328c301d10025a5205466a275f3c4b7d4a981e573c5396ce4a81ea1b8bd2"
	const wantV3Digest = "sha256:2bfb4d46853d586f71374f0cd9058aa0f3ad604da8a7b3674de48e030059d685"
	rawPayload3 := []byte(`{"query":"x"}`)
	act3, err := action.NormalizeAction(ctx, actor, "my-tool", rawPayload3, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction V3 on two-tool registry failed: %v", err)
	}
	tc3, ok := act3.TrustedContext()
	if !ok {
		t.Fatal("TrustedContext V3 failed")
	}
	if tc3.ToolRevision() != wantV3ToolRevision {
		t.Fatalf("V3 tool_revision mismatch on two-tool registry: got %s, want %s", tc3.ToolRevision(), wantV3ToolRevision)
	}
	if act3.TrustedDigest() != wantV3Digest {
		t.Fatalf("V3 NormalizeAction digest mismatch on two-tool registry: got %s, want %s", act3.TrustedDigest(), wantV3Digest)
	}
}

func TestBindingVectorV7FSWriteRoute(t *testing.T) {
	actor, _ := fixtureActor(t)
	profile := action.Profile{
		Protocol:        "decision_api",
		ProfileID:       "decision-v1",
		AdapterRevision: "sha256:" + strings.Repeat("a", 64),
	}
	route := action.Route{
		RouteID:           "route-fs-w",
		ExecutorID:        "exec-fs-w",
		Operation:         "fs.write",
		ResolutionProfile: "res-w",
		PayloadSchema:     "schema-fs-w",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"n": action.Integer,
			},
		},
	}
	reg, err := action.NewRegistry([]action.Profile{profile}, []action.Route{route}, nil, nil)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	env := testEnvelope1(t)
	rawPayload := []byte(`{"n":1}`)
	resource := "/work/out"
	const wantToolRevision = "sha256:518f44c5d7eae473cfe5b58261d5ce09fdf526a2a692d446814104b8be417e3c"
	const wantV7Digest = "sha256:2742b23fb878a5ce3ae4190b6012b4288133133fff74bcb51d93a236bc18100e"
	const v7Preimage = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"fs.write","payload":{"n":1},"payload_schema":"schema-fs-w","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-fs-w","resolution_profile":"res-w","resource":"/work/out","resource_kind":"filesystem","route_id":"route-fs-w"},"tool_revision":"sha256:518f44c5d7eae473cfe5b58261d5ce09fdf526a2a692d446814104b8be417e3c"}`

	if digest := sha256Hex(v7Preimage); digest != wantV7Digest {
		t.Fatalf("V7 literal preimage hash mismatch: got %s, want %s", digest, wantV7Digest)
	}

	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-fs-w")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}
	act, err := action.NormalizeAction(ctx, actor, resource, rawPayload, env, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	tc, ok := act.TrustedContext()
	if !ok {
		t.Fatal("TrustedContext failed")
	}
	if tc.ToolRevision() != wantToolRevision {
		t.Fatalf("V7 tool_revision mismatch: got %s, want %s", tc.ToolRevision(), wantToolRevision)
	}
	if act.TrustedDigest() != wantV7Digest {
		t.Fatalf("V7 NormalizeAction digest mismatch: got %s, want %s", act.TrustedDigest(), wantV7Digest)
	}
}

func TestNormalizeActionRawUTF8Preimage(t *testing.T) {
	actor, _ := fixtureActor(t)
	reg := fixtureRegistry(t)
	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	env := testEnvelope1(t)
	rawPayload := []byte(`{"n":1}`)

	const preimageNBSP = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"fs.read","payload":{"n":1},"payload_schema":"schema-fs","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-fs","resolution_profile":"res-1","resource":"/work/` + "\u00a0" + `","resource_kind":"filesystem","route_id":"route-fs"},"tool_revision":"sha256:fc37ac61e9aebccdd8c878ecd71df5211d2f6b597ff41147e12e9f33325e4384"}`

	const preimageLS = "GuardFil.Action.v1\n" + `{"actor":{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"},"boundary":"advisory","operation":"fs.read","payload":{"n":1},"payload_schema":"schema-fs","provenance":[],"schema_version":"guardfil.action/1.1","source":{"adapter_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"decision-v1","protocol":"decision_api"},"target":{"executor_id":"exec-fs","resolution_profile":"res-1","resource":"/work/` + "\u2028" + `","resource_kind":"filesystem","route_id":"route-fs"},"tool_revision":"sha256:fc37ac61e9aebccdd8c878ecd71df5211d2f6b597ff41147e12e9f33325e4384"}`

	cases := []struct {
		name             string
		resource         string
		expectedPreimage string
	}{
		{
			name:             "U+00A0 non-breaking space",
			resource:         "/work/\u00a0",
			expectedPreimage: preimageNBSP,
		},
		{
			name:             "U+2028 line separator",
			resource:         "/work/\u2028",
			expectedPreimage: preimageLS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			act, err := action.NormalizeAction(ctx, actor, tc.resource, rawPayload, env, nil)
			if err != nil {
				t.Fatalf("NormalizeAction failed: %v", err)
			}
			if !act.Authorizable() {
				t.Fatalf("expected action to be authorizable")
			}
			expectedDigest := sha256Hex(tc.expectedPreimage)
			if act.TrustedDigest() != expectedDigest {
				t.Fatalf("TrustedDigest mismatch for %s:\n got: %s\nwant: %s", tc.name, act.TrustedDigest(), expectedDigest)
			}
		})
	}
}

func TestBindingSensitivity(t *testing.T) {
	actor, _ := fixtureActor(t)
	reg := fixtureRegistry(t)
	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}

	baseEvidence := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-0"},
	}}

	baseAct, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatalf("base NormalizeAction failed: %v", err)
	}
	baseDigest := baseAct.TrustedDigest()

	// 1. Envelope invariance: all 6 fields differ -> digest UNCHANGED
	env2Act, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope2(t), baseEvidence)
	if err != nil {
		t.Fatalf("env2 NormalizeAction failed: %v", err)
	}
	if env2Act.TrustedDigest() != baseDigest {
		t.Fatalf("digest changed across envelopes: got %s, want %s", env2Act.TrustedDigest(), baseDigest)
	}

	// 2. Evidence input order invariance: entries passed in reverse order -> digest UNCHANGED
	evA := action.Evidence{
		ID:            "ev-1",
		ProducerID:    "transport-1",
		ContentDigest: "sha256:" + strings.Repeat("c", 64),
		Location:      "/n",
		ObservedAt:    "2026-09-24T17:00:00.000Z",
	}
	evB := action.Evidence{
		ID:            "ev-2",
		ProducerID:    "transport-1",
		ContentDigest: "sha256:" + strings.Repeat("c", 64),
		Location:      "/n",
		ObservedAt:    "2026-09-24T17:00:00.000Z",
	}
	actOrder1, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), []action.Evidence{evA, evB})
	if err != nil {
		t.Fatalf("actOrder1 failed: %v", err)
	}
	actOrder2, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), []action.Evidence{evB, evA})
	if err != nil {
		t.Fatalf("actOrder2 failed: %v", err)
	}
	if actOrder1.TrustedDigest() != actOrder2.TrustedDigest() {
		t.Fatalf("digest changed across evidence input order: %s vs %s", actOrder1.TrustedDigest(), actOrder2.TrustedDigest())
	}

	// 2b. Parent-ID input order invariance: parent IDs passed in reverse order -> digest UNCHANGED
	evParents1 := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-a", "ev-b"},
	}}
	evParents2 := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-b", "ev-a"},
	}}
	actP1, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evParents1)
	if err != nil {
		t.Fatalf("actP1 failed: %v", err)
	}
	actP2, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evParents2)
	if err != nil {
		t.Fatalf("actP2 failed: %v", err)
	}
	if actP1.TrustedDigest() != actP2.TrustedDigest() {
		t.Fatalf("parent-ID order invariance failed on digest: %s vs %s", actP1.TrustedDigest(), actP2.TrustedDigest())
	}

	// 3. Sensitivity: boundary (advisory vs proposal_filter)
	ctxProposal, err := reg.Context(action.ProposalFilter, "decision-v1", "route-fs")
	if err != nil {
		t.Fatalf("ctxProposal failed: %v", err)
	}
	actProposal, err := action.NormalizeAction(ctxProposal, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatalf("actProposal failed: %v", err)
	}
	if actProposal.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on boundary change")
	}

	// 4. Sensitivity: profile/adapter_revision
	regAltProfile, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("e", 64), // changed
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxAltProfile, err := regAltProfile.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actAltProfile, err := action.NormalizeAction(ctxAltProfile, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltProfile.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on adapter_revision change")
	}

	// 5. Sensitivity: route_id
	regAltRoute, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs-2", // changed
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxAltRoute, err := regAltRoute.Context(action.Advisory, "decision-v1", "route-fs-2")
	if err != nil {
		t.Fatal(err)
	}
	actAltRoute, err := action.NormalizeAction(ctxAltRoute, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltRoute.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on route_id change")
	}

	// 6. Sensitivity: executor_id
	regAltExec, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs-2", // changed
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxAltExec, err := regAltExec.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actAltExec, err := action.NormalizeAction(ctxAltExec, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltExec.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on executor_id change")
	}

	// 7. Sensitivity: resolution_profile
	regAltRes, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-2", // changed
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxAltRes, err := regAltRes.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actAltRes, err := action.NormalizeAction(ctxAltRes, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltRes.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on resolution_profile change")
	}

	// 8. Sensitivity: tool_revision (schema change)
	regAltSchema, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer, "m": action.String}}, // changed
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxAltSchema, err := regAltSchema.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actAltSchema, err := action.NormalizeAction(ctxAltSchema, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltSchema.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on tool_revision schema change")
	}

	// 9. Sensitivity: payload_schema
	regAltPayloadSchema, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs-2", // changed
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxAltPayloadSchema, err := regAltPayloadSchema.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actAltPayloadSchema, err := action.NormalizeAction(ctxAltPayloadSchema, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltPayloadSchema.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on payload_schema change")
	}

	// 10. Sensitivity: actor (different credential)
	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)
	altCred := identity.Credential{
		ID:              "app-key-alt",
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
	altReg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{altCred}, validTestResourceSets())
	if err != nil {
		t.Fatal(err)
	}
	altCtx, err := altReg.Authenticate(secret, "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	altActor, err := action.ProjectActor(altCtx)
	if err != nil {
		t.Fatal(err)
	}
	actAltActor, err := action.NormalizeAction(ctx, altActor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltActor.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on actor change")
	}

	// 11. Sensitivity: provenance fields and parent changes
	// Different content digest
	evDiffContent := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("d", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-0"},
	}}
	actDiffContent, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evDiffContent)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffContent.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance content_digest change")
	}

	// Different ID
	evDiffID := []action.Evidence{{
		ID:                "ev-2",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-0"},
	}}
	actDiffID, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evDiffID)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffID.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance ID change")
	}

	// Different Location
	evDiffLoc := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-0"},
	}}
	actDiffLoc, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evDiffLoc)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffLoc.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance location change")
	}

	// Different ObservedAt
	evDiffTime := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:01.000Z",
		ParentEvidenceIDs: []string{"ev-0"},
	}}
	actDiffTime, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evDiffTime)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffTime.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance observed_at change")
	}

	// Adding/removing a parent
	evNoParent := []action.Evidence{{
		ID:            "ev-1",
		ProducerID:    "transport-1",
		ContentDigest: "sha256:" + strings.Repeat("c", 64),
		Location:      "/n",
		ObservedAt:    "2026-09-24T17:00:00.000Z",
	}}
	actNoParent, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evNoParent)
	if err != nil {
		t.Fatal(err)
	}
	if actNoParent.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change when removing parent")
	}

	evTwoParents := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-1",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-0", "ev-extra"},
	}}
	actTwoParents, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evTwoParents)
	if err != nil {
		t.Fatal(err)
	}
	if actTwoParents.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change when adding parent")
	}

	// 12. Sensitivity: payload
	actAltPayload, err := action.NormalizeAction(ctx, actor, "/work/file", []byte(`{"n":2}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltPayload.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on payload change")
	}

	// 13. Sensitivity: target.resource
	actAltResource, err := action.NormalizeAction(ctx, actor, "/work/file2", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltResource.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on target.resource change")
	}

	// 14. Sensitivity: source.profile
	// Note: source.protocol is only "decision_api" today because NewRegistry rejects
	// openai_compatible/mcp with PROTOCOL_UNSUPPORTED; a protocol-sensitivity test must be added
	// when a second protocol is admitted.
	regAltProfileName, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v2", // changed
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v2"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxAltProfileName, err := regAltProfileName.Context(action.Advisory, "decision-v2", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actAltProfileName, err := action.NormalizeAction(ctxAltProfileName, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actAltProfileName.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on source.profile change")
	}

	// 15. Sensitivity: provenance producer_id (single field changed in registered producer and evidence)
	regDiffProdID, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-2", // changed
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxDiffProdID, err := regDiffProdID.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	evDiffProdID := []action.Evidence{{
		ID:                "ev-1",
		ProducerID:        "transport-2",
		ContentDigest:     "sha256:" + strings.Repeat("c", 64),
		Location:          "/n",
		ObservedAt:        "2026-09-24T17:00:00.000Z",
		ParentEvidenceIDs: []string{"ev-0"},
	}}
	actDiffProdID, err := action.NormalizeAction(ctxDiffProdID, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), evDiffProdID)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffProdID.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance producer_id change")
	}

	// 16. Sensitivity: provenance producer_revision (single field changed in registered producer)
	regDiffProdRev, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("f", 64), // changed
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxDiffProdRev, err := regDiffProdRev.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actDiffProdRev, err := action.NormalizeAction(ctxDiffProdRev, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffProdRev.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance producer_revision change")
	}

	// 17. Sensitivity: provenance origin (single field changed in registered producer)
	regDiffOrigin, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginDetector, // changed
			Trust:            action.TrustAuthenticatedSource,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxDiffOrigin, err := regDiffOrigin.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actDiffOrigin, err := action.NormalizeAction(ctxDiffOrigin, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffOrigin.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance origin change")
	}

	// 18. Sensitivity: provenance trust (single field changed in registered producer)
	regDiffTrust, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs",
			ExecutorID:        "exec-fs",
			Operation:         "fs.read",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		[]action.Producer{{
			ProducerID:       "transport-1",
			ProducerRevision: "sha256:" + strings.Repeat("b", 64),
			Profiles:         []string{"decision-v1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustUntrusted, // changed
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxDiffTrust, err := regDiffTrust.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	actDiffTrust, err := action.NormalizeAction(ctxDiffTrust, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), baseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if actDiffTrust.TrustedDigest() == baseDigest {
		t.Fatal("digest did not change on provenance trust change")
	}

	// 19. fs.write route NormalizeAction is Authorizable
	regWrite, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "decision-v1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		[]action.Route{{
			RouteID:           "route-fs-write",
			ExecutorID:        "exec-fs",
			Operation:         "fs.write",
			ResolutionProfile: "res-1",
			PayloadSchema:     "schema-fs",
			Schema:            action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}},
		}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctxWrite, err := regWrite.Context(action.Advisory, "decision-v1", "route-fs-write")
	if err != nil {
		t.Fatal(err)
	}
	actWrite, err := action.NormalizeAction(ctxWrite, actor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), nil)
	if err != nil {
		t.Fatalf("NormalizeAction fs.write failed: %v", err)
	}
	if !actWrite.Authorizable() {
		t.Fatal("expected fs.write route NormalizeAction to be authorizable")
	}
	if actWrite.TrustedDigest() == "" {
		t.Fatal("expected fs.write route NormalizeAction to have non-empty digest")
	}
}

func TestNormalizeActionRejectsZeroActor(t *testing.T) {
	reg := fixtureRegistry(t)
	ctx, err := reg.Context(action.Advisory, "decision-v1", "route-fs")
	if err != nil {
		t.Fatalf("Context failed: %v", err)
	}
	zeroActor := action.Actor{}
	if _, err := action.NormalizeAction(ctx, zeroActor, "/work/file", []byte(`{"n":1}`), testEnvelope1(t), nil); err != action.ErrSchema {
		t.Fatalf("expected ErrSchema for zero actor, got %v", err)
	}
}
