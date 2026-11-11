// Package security_test contains independent release-gate regressions.
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

func TestActionAndPrincipalForgeryBoundaries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	engine, principal := p12URLAuthorizer(t, "https://example.com/a", "https://example.com/a", now)
	formed, err := normalizeActionForTest(t, principal, "http.request", "https://example.com/a", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		a    action.Action
		p    identity.PrincipalContext
	}{
		{"forged-action", action.Action{SchemaVersion: action.Version, Operation: "http.request", ResourceKind: "url", Resource: "https://example.com/a", Payload: []byte(`{"n":1}`), Digest: "sha256:attacker-controlled"}, principal},
		{"forged-principal", formed, identity.PrincipalContext{}},
		{"mutated-resource-kind", mutateAction(formed, func(a *action.Action) { a.ResourceKind = "path" }), principal},
		{"mutated-resource", mutateAction(formed, func(a *action.Action) { a.Resource = "https://evil.invalid/a" }), principal},
		{"mutated-payload", mutateAction(formed, func(a *action.Action) { a.Payload = []byte(`{"n":2}`) }), principal},
		{"replaced-digest", mutateAction(formed, func(a *action.Action) { a.Digest = "sha256:attacker-controlled" }), principal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := engine.Authorize(context.Background(), tc.a, tc.p)
			if err == nil || d.Effect == decision.ALLOW || d.DispatchEligible() {
				t.Fatalf("forged or mutated authority was accepted: decision=%+v error=%v", d, err)
			}
		})
	}
}

func mutateAction(a action.Action, mutate func(*action.Action)) action.Action {
	mutate(&a)
	return a
}

func TestClosedPolicyYAMLAndDeterministicDeny(t *testing.T) {
	const valid = "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"
	for name, raw := range map[string]string{
		"trailing-document": valid + "---\nschema_version: 1\ntenant_id: other\nrevision: 2\ndefault: deny\nrules: []\n",
		"duplicate-key":     "schema_version: 1\ntenant_id: acme\ntenant_id: other\nrevision: 1\ndefault: deny\nrules: []\n",
		"alias":             "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules: &rules []\n",
		"unknown-nested":    "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules: [{id: allow, effect: allow, match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**, extra: true}]}}]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.Compile([]byte(raw)); err == nil {
				t.Fatal("closed policy parser admitted ambiguous or unknown YAML")
			}
		})
	}

	deny := valid + " - id: deny\n   effect: deny\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"
	snapshot, err := policy.Compile([]byte(deny))
	if err != nil {
		t.Fatal(err)
	}
	in := policy.Input{TenantID: "acme", PrincipalID: "app", Operation: "filesystem.read", ResourceKind: "path", Resource: "/work/secret"}
	for i := 0; i < 100; i++ {
		got, err := snapshot.Evaluate(in)
		if err != nil || !got.Denied || got.Allowed {
			t.Fatalf("allow+deny was not deterministically deny-first: result=%+v error=%v", got, err)
		}
	}
}

func TestCredentialAdmissionAndLifecycleBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	base := identity.Credential{ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data", Scopes: []identity.Scope{{Operation: "filesystem.read", ResourceSet: "set-1"}}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1, Verifier: identity.Verifier(key, secret)}
	for name, records := range map[string][]identity.Credential{
		"duplicate-id":       {base, base},
		"duplicate-verifier": {base, func() identity.Credential { c := base; c.ID = "key-2"; return c }()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := identity.NewRegistry(key, records); err == nil {
				t.Fatal("duplicate credential was admitted")
			}
		})
	}

	registry, err := identity.NewRegistry(key, []identity.Credential{base})
	if err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string]time.Time{"not-yet-valid": base.IssuedAt.Add(-time.Nanosecond), "expiry-boundary": base.ExpiresAt, "stale": base.ExpiresAt.Add(time.Nanosecond)} {
		t.Run(name, func(t *testing.T) {
			if _, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", at); err == nil {
				t.Fatal("credential lifecycle boundary authenticated")
			}
		})
	}
	if err := registry.Revoke(base.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now); err == nil {
		t.Fatal("revoked credential authenticated")
	}
}
