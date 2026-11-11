// Package security_test contains independent adversarial retests for P1.2.
package security_test

import (
	"context"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/identity"
	"github.com/reviaro/guardfil/internal/policy"
)

// TestP12IndependentRejectsPathTraversalResourceSetEscape verifies that an
// in-scope lexical prefix cannot authorize a filesystem path escaping its set.
func TestP12IndependentRejectsPathTraversalResourceSetEscape(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{{
		ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data",
		Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
		Verifier: identity.Verifier(key, secret),
	}}, map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.Compile([]byte("schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := decision.NewEngine(snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	escaped, err := normalizeActionForTest(t, principal, "fs.read", "/work/../private/key", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := engine.Authorize(context.Background(), escaped, principal)
	if err == nil || d.Effect == decision.ALLOW || d.DispatchEligible() {
		t.Fatalf("path traversal escaped /work/**: decision=%+v error=%v", d, err)
	}
}
