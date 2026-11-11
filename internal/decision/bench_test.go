package decision

import (
	"context"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/identity"
	"github.com/reviaro/guardfil/internal/policy"
)

// BenchmarkAuthorize measures only the in-process P1.2 authorization kernel.
// It is a regression signal, not the policy-only request SLO: durable audit,
// protocol parsing, admission, and dispatch fencing are intentionally absent.
func BenchmarkAuthorize(b *testing.B) {
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
	}}, map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	})
	if err != nil {
		b.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		b.Fatal(err)
	}
	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		b.Fatal(err)
	}
	engine, err := NewEngine(snapshot, registry)
	if err != nil {
		b.Fatal(err)
	}
	a := testNormalizeAction(b, principal, "fs.read", "/work/file", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, err := engine.Authorize(context.Background(), a, principal)
		if err != nil || d.Effect != ALLOW || d.DispatchEligible() {
			b.Fatalf("unexpected authorization: %+v, %v", d, err)
		}
	}
}
