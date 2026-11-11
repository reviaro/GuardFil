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

// TestP12URLSelectorAdversarialBoundaries verifies independently that selector
// ambiguity cannot cross Action, credential, or policy into dispatch.
func TestP12URLSelectorAdversarialBoundaries(t *testing.T) {
	const canonical = "https://example.com/a"
	// Engine authorization uses the process clock, so the credential and
	// deadline must be live while preserving a bounded test window.
	now := time.Now().UTC().Truncate(time.Second)
	schema := action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}}
	engine, principal := p12URLAuthorizer(t, canonical, canonical, now)

	formed, err := normalizeActionForTest(t, principal, "http.request", canonical, []byte(`{"n":1}`), schema)
	if err != nil {
		t.Fatalf("Action rejected explicitly granted canonical URL: %v", err)
	}
	got, err := engine.Authorize(context.Background(), formed, principal)
	if err != nil || got.Effect != decision.ALLOW || got.DispatchEligible() {
		t.Fatalf("explicit canonical grant failed: decision=%+v error=%v", got, err)
	}

	for _, selector := range []string{
		canonical + "?", // empty query ambiguity
		canonical + "?redirect=https://evil.invalid",
		canonical + "#fragment",
		"https://example.com/%61",    // percent encoding
		"https://EXAMPLE.COM/a",      // host case normalization
		"HTTPS://example.com/a",      // scheme case normalization
		"https://example.com/a/../a", // path normalization
		"https://example.com/a/**",   // selector presented as a pattern
		"https://example.com/ab",     // sibling lexical prefix
	} {
		t.Run(selector, func(t *testing.T) {
			a, formErr := normalizeActionForTest(t, principal, "http.request", selector, []byte(`{"n":1}`), schema)
			if formErr != nil {
				return // cannot cross the Action boundary
			}
			d, authorizeErr := engine.Authorize(context.Background(), a, principal)
			if authorizeErr == nil || d.Effect == decision.ALLOW || d.DispatchEligible() {
				t.Fatalf("selector crossed into executable authority: action=%+v decision=%+v error=%v", a, d, authorizeErr)
			}
		})
	}

	for _, pattern := range []string{
		canonical + "?", canonical + "?q=1", canonical + "#x", "https://example.com/%61", "https://EXAMPLE.COM/a", "https://example.com/a/../a",
	} {
		t.Run("credential-pattern/"+pattern, func(t *testing.T) {
			if _, err := p12URLRegistry(pattern, now); err == nil {
				t.Fatal("credential resource set admitted ambiguous URL pattern")
			}
		})
		t.Run("policy-pattern/"+pattern, func(t *testing.T) {
			if _, err := policy.Compile([]byte(p12URLPolicy(pattern))); err == nil {
				t.Fatal("policy admitted ambiguous URL pattern")
			}
		})
	}

	// Both pattern boundaries must be segment-aware: an allowed /a subtree does
	// not turn its sibling /ab into a resource under the wildcard.
	wildEngine, wildPrincipal := p12URLAuthorizer(t, canonical+"/**", canonical+"/**", now)
	for _, selector := range []string{canonical, canonical + "/child", "https://example.com/ab"} {
		t.Run("wildcard/"+selector, func(t *testing.T) {
			a, err := normalizeActionForTest(t, wildPrincipal, "http.request", selector, []byte(`{"n":1}`), schema)
			if err != nil {
				t.Fatalf("form action: %v", err)
			}
			d, err := wildEngine.Authorize(context.Background(), a, wildPrincipal)
			if selector == "https://example.com/ab" {
				if err == nil || d.Effect == decision.ALLOW || d.DispatchEligible() {
					t.Fatalf("wildcard authorized sibling prefix: decision=%+v error=%v", d, err)
				}
				return
			}
			if err != nil || d.Effect != decision.ALLOW || d.DispatchEligible() {
				t.Fatalf("wildcard failed expected descendant: decision=%+v error=%v", d, err)
			}
		})
	}
}

func p12URLAuthorizer(t *testing.T, resourcePattern, policyPattern string, now time.Time) (decision.Engine, identity.PrincipalContext) {
	t.Helper()
	registry, err := p12URLRegistry(resourcePattern, now)
	if err != nil {
		t.Fatalf("credential resource set: %v", err)
	}
	snapshot, err := policy.Compile([]byte(p12URLPolicy(policyPattern)))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	engine, err := decision.NewEngine(snapshot, registry)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	principal, err := registry.Authenticate("0123456789012345678901234567890123456789012", "data", "acme", "http.request", now)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return engine, principal
}

func p12URLRegistry(pattern string, now time.Time) (*identity.Registry, error) {
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	record := identity.Credential{
		ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data",
		Scopes:   []identity.Scope{{Operation: "http.request", ResourceSet: "allowed-urls"}},
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
		Verifier: identity.Verifier(key, secret),
	}
	return identity.NewRegistryWithResourceSets(key, []identity.Credential{record}, map[string][]identity.Resource{
		"allowed-urls": {{Kind: "url", Value: pattern}},
	})
}

func p12URLPolicy(pattern string) string {
	return "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [http.request], resources: [{kind: url, value: '" + pattern + "'}]}\n"
}
