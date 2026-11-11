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

func TestP12RejectsEmptyQueryURLSelectors(t *testing.T) {
	const (
		canonical = "https://example.com/a"
		ambiguous = canonical + "?"
	)
	schema := action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}}
	if _, err := action.NormalizeRequest("http.request", ambiguous, []byte(`{"n":1}`), schema); err == nil {
		t.Fatal("empty-query URL entered Action")
	}

	now := time.Now().UTC().Truncate(time.Second)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	record := identity.Credential{
		ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data",
		Scopes:   []identity.Scope{{Operation: "http.request", ResourceSet: "allowed-urls"}},
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
		Verifier: identity.Verifier(key, secret),
	}
	if _, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{record}, map[string][]identity.Resource{
		"allowed-urls": {{Kind: "url", Value: ambiguous}},
	}); err == nil {
		t.Fatal("credential resource set admitted empty-query URL")
	}
	badPolicy := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [http.request], resources: [{kind: url, value: '" + ambiguous + "'}]}\n"
	if _, err := policy.Compile([]byte(badPolicy)); err == nil {
		t.Fatal("policy admitted empty-query URL")
	}

	registry, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{record}, map[string][]identity.Resource{
		"allowed-urls": {{Kind: "url", Value: canonical}},
	})
	if err != nil {
		t.Fatal(err)
	}
	goodPolicy := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [http.request], resources: [{kind: url, value: '" + canonical + "'}]}\n"
	snapshot, err := policy.Compile([]byte(goodPolicy))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := decision.NewEngine(snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.Authenticate(string(secret), "data", "acme", "http.request", now)
	if err != nil {
		t.Fatal(err)
	}
	formed, err := normalizeActionForTest(t, principal, "http.request", canonical, []byte(`{"n":1}`), schema)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Authorize(context.Background(), formed, principal)
	if err != nil || got.Effect != decision.ALLOW || got.DispatchEligible() {
		t.Fatalf("canonical URL was not authorized: decision=%+v error=%v", got, err)
	}
}
