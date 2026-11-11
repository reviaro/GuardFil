// Package security_test contains independent adversarial regressions for P1.2.
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

func TestP12RegistryRejectsPreIssueCredentialsAndCopiesCallerScopes(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	scopes := []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}}

	future := identity.Credential{
		ID:          "future-key",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes:      scopes,
		IssuedAt:    now.Add(time.Hour),
		ExpiresAt:   now.Add(2 * time.Hour),
		Revision:    1,
		Verifier:    identity.Verifier(key, secret),
	}
	t.Run("pre-issue", func(t *testing.T) {
		registry, err := identity.NewRegistry(key, []identity.Credential{future})
		if err != nil {
			t.Fatalf("provisioning test registry: %v", err)
		}
		if _, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.read", now); err == nil {
			t.Fatal("credential authenticated before issued_at")
		}
	})
	t.Run("caller-scope-mutation", func(t *testing.T) {
		valid := future
		valid.ID = "valid-key"
		valid.IssuedAt = now.Add(-time.Hour)
		valid.ExpiresAt = now.Add(time.Hour)
		registry, err := identity.NewRegistry(key, []identity.Credential{valid})
		if err != nil {
			t.Fatalf("provisioning test registry: %v", err)
		}
		scopes[0].Operation = "filesystem.write"
		if _, err := registry.Authenticate(string(secret), "data", "acme", "filesystem.write", now); err == nil {
			t.Fatal("caller mutation changed a provisioned credential scope")
		}
	})
}

func TestP12DecisionRejectsForgedActionIdentityAndUnmetApproval(t *testing.T) {
	const policyPrefix = "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: broad-allow\n   effect: allow\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n"
	newEngine := func(t *testing.T, policyText string) decision.Engine {
		t.Helper()
		snapshot, err := policy.Compile([]byte(policyText))
		if err != nil {
			t.Fatalf("compile policy: %v", err)
		}
		return decision.Engine{Policy: snapshot, Now: func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) }}
	}
	deadline := time.Date(2026, 9, 26, 12, 1, 0, 0, time.UTC)
	t.Run("forged-action-and-principal", func(t *testing.T) {
		engine := newEngine(t, policyPrefix)
		forged := action.Action{SchemaVersion: action.Version, Digest: "sha256:attacker-controlled"}
		got, err := engine.Decide(context.Background(), forged, "acme", "app", "filesystem.read", "/work/secret", deadline)
		if err == nil || got.Effect == decision.ALLOW || got.DispatchEligible() {
			t.Fatalf("caller-supplied Action/identity produced executable result: %+v, %v", got, err)
		}
	})
	t.Run("approval-obligation", func(t *testing.T) {
		engine := newEngine(t, policyPrefix+" - id: approval-required\n   effect: require_approval\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n")
		formed, err := action.NormalizePayload("fs.read", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
		if err != nil {
			t.Fatalf("form Action: %v", err)
		}
		got, err := engine.Decide(context.Background(), formed, "acme", "app", "filesystem.read", "/work/secret", deadline)
		if err == nil || got.Effect == decision.ALLOW || got.DispatchEligible() {
			t.Fatalf("unmet approval obligation produced executable result: %+v, %v", got, err)
		}
	})
}

func TestP12PolicyRejectsTrailingDocumentsAndNestedUnknownFields(t *testing.T) {
	valid := "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules: []\n"
	for name, source := range map[string]string{
		"trailing-document": valid + "---\nschema_version: 1\ntenant_id: other\nrevision: 1\ndefault: deny\nrules: []\n",
		"nested-unknown":    "schema_version: 1\ntenant_id: acme\nrevision: 1\ndefault: deny\nrules:\n - id: allow\n   effect: allow\n   unexpected: true\n   match: {principals: [app], operations: [filesystem.read], resources: [{kind: path, value: /work/**}]}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.Compile([]byte(source)); err == nil {
				t.Fatal("closed policy parser accepted unsupported YAML input")
			}
		})
	}
}

func TestP12PublishedNumericDigestVectors(t *testing.T) {
	vectors := []struct{ field, token, want string }{
		{"temperature", "0.1", "sha256:237407449faed5fcb3bc5714c54767d505f47836a8dcafdf14529f90b93e77a0"},
		{"temperature", "0.10", "sha256:06f932bc398cc10f3d97a374d808d30f85c8446673017b99f689acb19ea60548"},
		{"temperature", "0.100", "sha256:e01b8898a0075c9231a9425ba0d0c5da97e9e0bf2b0991f7cd2a42423a93875f"},
		{"temperature", "1.5", "sha256:466b43b1be6292a8ef5afe9fcdd792f5bd4d1eea18df28106f2aae0a783c4e44"},
		{"seed", "9007199254740991", "sha256:f1c1c76f6712faa74b1bfeb860a774a5e5ad93859007084739be6cee242c5aea"},
		{"seed", "9007199254740993", "sha256:db8e4393143bf84f67e2325224fb1208bb8fd615901dcfd9fbc61dde706c41ef"},
		{"penalty", "-2.00", "sha256:de2ba140a725d50d0caa376acb461907cef999ff88118919341391b92b3a4902"},
		{"penalty", "-2.0", "sha256:8d11fd665d2699b084c3bb2210825da91e3c8066262acda4af321a2dbe14601a"},
	}
	for _, vector := range vectors {
		t.Run(vector.field+"/"+vector.token, func(t *testing.T) {
			got, err := action.NumericFieldDigest(vector.field, vector.token)
			if err != nil || got != vector.want {
				t.Fatalf("digest(%s, %q) = %q, %v; want %q", vector.field, vector.token, got, err, vector.want)
			}
		})
	}
}
