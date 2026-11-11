package action_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/identity"
)

func validTestResourceSets() map[string][]identity.Resource {
	return map[string][]identity.Resource{
		"workspace-read":  {{Kind: "path", Value: "/work/**"}},
		"workspace-write": {{Kind: "path", Value: "/work/**"}},
	}
}

func testKeyAndSecret() ([]byte, string) {
	key := []byte("01234567890123456789012345678901")       // 32 bytes
	secret := "0123456789012345678901234567890123456789012" // 43 bytes
	return key, secret
}

// Test 1: exact match against the canonical actor digest vector
func TestActorSpecVector(t *testing.T) {
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

	expectedAuthority := `{"audience":"data","auth_method":"opaque_bearer","credential_expires_at":"2026-09-25T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"schema_version":"guardfil.authority/1","scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"}`
	if !bytes.Equal(actor.AuthorityCanonical(), []byte(expectedAuthority)) {
		t.Fatalf("AuthorityCanonical mismatch:\n got: %s\nwant: %s", string(actor.AuthorityCanonical()), expectedAuthority)
	}

	expectedDigest := "sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f"
	if actor.AuthContextDigest() != expectedDigest {
		t.Fatalf("AuthContextDigest mismatch:\n got: %s\nwant: %s", actor.AuthContextDigest(), expectedDigest)
	}

	expectedCanonicalActor := `{"auth_context_digest":"sha256:d72c6239329a499e654acfc1b0a123e95ea9b45c0883f98fb3691ac3e59d187f","credential_expires_at":"2026-09-25T17:00:00Z","principal_context":{"audience":"data","auth_method":"opaque_bearer","authenticated_at":"2026-09-24T17:00:00Z","credential_id":"app-key-2","credential_revision":2,"principal_id":"coding-app","revocation_epoch":8,"scopes":[{"operation":"filesystem.read","resource_set":"workspace-read"}],"tenant_id":"acme"},"schema_version":"guardfil.actor/1"}`
	if !bytes.Equal(actor.Canonical(), []byte(expectedCanonicalActor)) {
		t.Fatalf("Canonical mismatch:\n got: %s\nwant: %s", string(actor.Canonical()), expectedCanonicalActor)
	}
}

// Test 2: Second credential vector (spec): app-key-3, revision 1, sole scope {filesystem.write, workspace-write}
func TestActorSecondCredentialVector(t *testing.T) {
	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)
	cred1 := identity.Credential{
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

	secret2 := "0123456789012345678901234567890123456789013"
	cred2 := identity.Credential{
		ID:              "app-key-3",
		TenantID:        "acme",
		PrincipalID:     "coding-app",
		Audience:        "data",
		Scopes:          []identity.Scope{{Operation: "filesystem.write", ResourceSet: "workspace-write"}},
		IssuedAt:        time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 9, 25, 17, 0, 0, 0, time.UTC),
		Revision:        1,
		RevocationEpoch: 8,
		Verifier:        identity.Verifier(key, []byte(secret2)),
	}

	reg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred1, cred2}, validTestResourceSets())
	if err != nil {
		t.Fatalf("NewRegistryWithResourceSets failed: %v", err)
	}

	ctx1, err := reg.Authenticate(secret, "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatalf("Authenticate 1 failed: %v", err)
	}
	actor1, err := action.ProjectActor(ctx1)
	if err != nil {
		t.Fatalf("ProjectActor 1 failed: %v", err)
	}

	ctx2, err := reg.Authenticate(secret2, "data", "acme", "filesystem.write", now)
	if err != nil {
		t.Fatalf("Authenticate 2 failed: %v", err)
	}
	actor2, err := action.ProjectActor(ctx2)
	if err != nil {
		t.Fatalf("ProjectActor 2 failed: %v", err)
	}

	const expectedDigest2 = "sha256:a6f319915ac93c2cda889e307a41125b39fb7f43bdaab1728893ec7c31109dd3"
	if actor2.AuthContextDigest() != expectedDigest2 {
		t.Fatalf("AuthContextDigest for vector 2 mismatch:\n got: %s\nwant: %s", actor2.AuthContextDigest(), expectedDigest2)
	}

	if bytes.Equal(actor1.AuthorityCanonical(), actor2.AuthorityCanonical()) {
		t.Fatal("expected different AuthorityCanonical for vector 1 and vector 2")
	}
	if actor1.AuthContextDigest() == actor2.AuthContextDigest() {
		t.Fatal("expected different AuthContextDigest for vector 1 and vector 2")
	}
}

// Test 3: authenticated_at change only -> same AuthContextDigest, different Canonical()
func TestActorAuthenticatedAtChangeOnly(t *testing.T) {
	key, secret := testKeyAndSecret()
	now1 := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)
	now2 := time.Date(2026, 9, 24, 18, 0, 0, 0, time.UTC)

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

	ctx1, err := reg.Authenticate(secret, "data", "acme", "filesystem.read", now1)
	if err != nil {
		t.Fatalf("Authenticate now1 failed: %v", err)
	}
	actor1, err := action.ProjectActor(ctx1)
	if err != nil {
		t.Fatalf("ProjectActor 1 failed: %v", err)
	}

	ctx2, err := reg.Authenticate(secret, "data", "acme", "filesystem.read", now2)
	if err != nil {
		t.Fatalf("Authenticate now2 failed: %v", err)
	}
	actor2, err := action.ProjectActor(ctx2)
	if err != nil {
		t.Fatalf("ProjectActor 2 failed: %v", err)
	}

	if actor1.AuthContextDigest() != actor2.AuthContextDigest() {
		t.Fatalf("AuthContextDigest changed upon authenticated_at change: %s vs %s", actor1.AuthContextDigest(), actor2.AuthContextDigest())
	}
	if bytes.Equal(actor1.Canonical(), actor2.Canonical()) {
		t.Fatal("Canonical actor should differ when authenticated_at differs")
	}
}

// Test 4: Each single-field change changes the digest
func TestActorSingleFieldMutationsChangeDigest(t *testing.T) {
	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)

	baseCred := identity.Credential{
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

	reg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{baseCred}, validTestResourceSets())
	if err != nil {
		t.Fatalf("base NewRegistry failed: %v", err)
	}
	baseCtx, err := reg.Authenticate(secret, "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatalf("base Authenticate failed: %v", err)
	}
	baseActor, err := action.ProjectActor(baseCtx)
	if err != nil {
		t.Fatalf("base ProjectActor failed: %v", err)
	}
	baseDigest := baseActor.AuthContextDigest()

	mutations := []struct {
		name   string
		modify func(c *identity.Credential)
		authOp string
		tenant string
	}{
		{
			name:   "tenant_id change",
			modify: func(c *identity.Credential) { c.TenantID = "acme-corp" },
			authOp: "filesystem.read",
			tenant: "acme-corp",
		},
		{
			name:   "principal_id change",
			modify: func(c *identity.Credential) { c.PrincipalID = "other-app" },
			authOp: "filesystem.read",
			tenant: "acme",
		},
		{
			name:   "credential_id change",
			modify: func(c *identity.Credential) { c.ID = "app-key-diff" },
			authOp: "filesystem.read",
			tenant: "acme",
		},
		{
			name:   "credential_revision change",
			modify: func(c *identity.Credential) { c.Revision = 3 },
			authOp: "filesystem.read",
			tenant: "acme",
		},
		{
			name:   "revocation_epoch change",
			modify: func(c *identity.Credential) { c.RevocationEpoch = 9 },
			authOp: "filesystem.read",
			tenant: "acme",
		},
		{
			name:   "credential_expires_at change",
			modify: func(c *identity.Credential) { c.ExpiresAt = time.Date(2026, 9, 25, 18, 0, 0, 0, time.UTC) },
			authOp: "filesystem.read",
			tenant: "acme",
		},
		{
			name: "scope change",
			modify: func(c *identity.Credential) {
				c.Scopes = []identity.Scope{{Operation: "filesystem.write", ResourceSet: "workspace-write"}}
			},
			authOp: "filesystem.write",
			tenant: "acme",
		},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			mutCred := baseCred
			m.modify(&mutCred)
			mutCred.Verifier = identity.Verifier(key, []byte(secret))

			mReg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{mutCred}, validTestResourceSets())
			if err != nil {
				t.Fatalf("NewRegistry failed for %s: %v", m.name, err)
			}
			mCtx, err := mReg.Authenticate(secret, "data", m.tenant, m.authOp, now)
			if err != nil {
				t.Fatalf("Authenticate failed for %s: %v", m.name, err)
			}
			mActor, err := action.ProjectActor(mCtx)
			if err != nil {
				t.Fatalf("ProjectActor failed for %s: %v", m.name, err)
			}
			if mActor.AuthContextDigest() == baseDigest {
				t.Fatalf("field mutation %s did not change digest: %s", m.name, baseDigest)
			}
		})
	}
}

// Test 5: Rejections with ErrActor
func TestActorRejections(t *testing.T) {
	// 5.1 Zero identity.PrincipalContext{}
	if _, err := action.ProjectActor(identity.PrincipalContext{}); err != identity.ErrAuthentication {
		t.Fatalf("zero PrincipalContext expected ErrAuthentication, got %v", err)
	}

	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)

	// 5.2 Management-audience context
	mgmtCred := identity.Credential{
		ID:          "mgmt-key",
		TenantID:    "acme",
		PrincipalID: "admin-app",
		Audience:    "management",
		Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(time.Hour),
		Revision:    1,
		Verifier:    identity.Verifier(key, []byte(secret)),
	}
	mgmtReg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{mgmtCred}, validTestResourceSets())
	if err != nil {
		t.Fatalf("NewRegistry for mgmt failed: %v", err)
	}
	mgmtCtx, err := mgmtReg.Authenticate(secret, "management", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatalf("Authenticate for mgmt failed: %v", err)
	}
	if _, err := action.ProjectActor(mgmtCtx); err != identity.ErrAuthentication {
		t.Fatalf("management audience expected ErrAuthentication, got %v", err)
	}

	// 5.3 Credential ExpiresAt with nonzero nanoseconds (+1ms) is rejected by registry admission
	subsecondCred := identity.Credential{
		ID:          "subsecond-key",
		TenantID:    "acme",
		PrincipalID: "coding-app",
		Audience:    "data",
		Scopes:      []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(time.Hour).Add(time.Millisecond),
		Revision:    1,
		Verifier:    identity.Verifier(key, []byte(secret)),
	}
	if _, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{subsecondCred}, validTestResourceSets()); !errors.Is(err, identity.ErrAuthentication) {
		t.Fatalf("NewRegistryWithResourceSets for subsecond expected ErrAuthentication, got: %v", err)
	}

	// 5.4 Assert that uppercase/invalid IDs and duplicate scopes cannot be produced through
	// the Registry because NewRegistry rejects them.
	// Uppercase and invalid Security IDs, as well as duplicate scopes, are rejected at Registry
	// construction time; we verify that NewRegistry rejects them here.
	invalidIDCreds := []struct {
		name string
		cred identity.Credential
	}{
		{
			name: "Uppercase TenantID",
			cred: identity.Credential{
				ID: "app-key", TenantID: "Acme", PrincipalID: "app", Audience: "data",
				Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
				IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
				Verifier: identity.Verifier(key, []byte(secret)),
			},
		},
		{
			name: "Uppercase PrincipalID",
			cred: identity.Credential{
				ID: "app-key", TenantID: "acme", PrincipalID: "Coding-App", Audience: "data",
				Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
				IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
				Verifier: identity.Verifier(key, []byte(secret)),
			},
		},
		{
			name: "Uppercase CredentialID",
			cred: identity.Credential{
				ID: "App-Key-1", TenantID: "acme", PrincipalID: "app", Audience: "data",
				Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
				IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
				Verifier: identity.Verifier(key, []byte(secret)),
			},
		},
		{
			name: "Invalid scope operation",
			cred: identity.Credential{
				ID: "app-key", TenantID: "acme", PrincipalID: "app", Audience: "data",
				Scopes:   []identity.Scope{{Operation: "Filesystem.read", ResourceSet: "workspace-read"}},
				IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
				Verifier: identity.Verifier(key, []byte(secret)),
			},
		},
		{
			name: "Duplicate scope",
			cred: identity.Credential{
				ID: "app-key", TenantID: "acme", PrincipalID: "app", Audience: "data",
				Scopes: []identity.Scope{
					{Operation: "filesystem.read", ResourceSet: "workspace-read"},
					{Operation: "filesystem.read", ResourceSet: "workspace-read"},
				},
				IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
				Verifier: identity.Verifier(key, []byte(secret)),
			},
		},
	}

	for _, tc := range invalidIDCreds {
		t.Run(tc.name, func(t *testing.T) {
			_, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{tc.cred}, validTestResourceSets())
			if err == nil {
				t.Fatalf("expected NewRegistry to reject %s, but it succeeded", tc.name)
			}
		})
	}
}

// Test 6: Time conversion table
func TestTimeConversions(t *testing.T) {
	// Valid conversion and round trip
	for _, tc := range []struct {
		sec     string
		runtime string
	}{
		{"2026-09-24T17:00:00Z", "2026-09-24T17:00:00.000Z"},
		{"2024-02-29T00:00:00Z", "2024-02-29T00:00:00.000Z"}, // leap year accepted
	} {
		rt, err := action.SecurityTimeToRuntime(tc.sec)
		if err != nil {
			t.Fatalf("SecurityTimeToRuntime(%q) unexpected error: %v", tc.sec, err)
		}
		if rt != tc.runtime {
			t.Fatalf("SecurityTimeToRuntime(%q) = %q, want %q", tc.sec, rt, tc.runtime)
		}

		secRoundtrip, err := action.RuntimeToSecurityTime(rt)
		if err != nil {
			t.Fatalf("RuntimeToSecurityTime(%q) unexpected error: %v", rt, err)
		}
		if secRoundtrip != tc.sec {
			t.Fatalf("RuntimeToSecurityTime(%q) = %q, want %q", rt, secRoundtrip, tc.sec)
		}
	}

	// RuntimeToSecurityTime rejects
	runtimeRejections := []string{
		"2026-09-24T17:00:00.001Z",
		"2026-09-24T17:00:00Z",
		"2026-09-24T17:00:00+00:00",
		"2026-09-24 17:00:00Z",
		"2026-13-01T00:00:00Z",
		"2026-09-24T17:00:00.0Z",
		"2026-02-29T00:00:00.000Z", // non-leap year Feb 29 rejected
		"2026-04-31T00:00:00.000Z", // April has 30 days rejected
		"2026-09-24T23:59:60.000Z", // leap second rejected
		"2026-09-24T24:00:00.000Z", // hour 24 rejected
		"",
	}
	for _, in := range runtimeRejections {
		if _, err := action.RuntimeToSecurityTime(in); !errors.Is(err, identity.ErrAuthentication) {
			t.Fatalf("RuntimeToSecurityTime(%q) expected ErrAuthentication, got %v", in, err)
		}
	}

	// SecurityTimeToRuntime rejects
	securityRejections := []string{
		"2026-09-24T17:00:00.000Z",
		"2026-09-24T17:00:00.001Z",
		"2026-09-24T17:00:00+00:00",
		"2026-09-24 17:00:00Z",
		"2026-13-01T00:00:00Z",
		"2026-09-24T17:00:00.0Z",
		"2026-02-29T00:00:00Z", // non-leap year Feb 29 rejected
		"2026-04-31T00:00:00Z", // April has 30 days rejected
		"2026-09-24T23:59:60Z", // leap second rejected
		"2026-09-24T24:00:00Z", // hour 24 rejected
		"",
	}
	for _, in := range securityRejections {
		if _, err := action.SecurityTimeToRuntime(in); !errors.Is(err, identity.ErrAuthentication) {
			t.Fatalf("SecurityTimeToRuntime(%q) expected ErrAuthentication, got %v", in, err)
		}
	}
}

// Test 7: Returned Canonical()/AuthorityCanonical() slices are copies
func TestActorSlicesAreCopies(t *testing.T) {
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

	// Mutate Canonical() copy
	c1 := actor.Canonical()
	c1[0] = 'X'
	c2 := actor.Canonical()
	if c2[0] == 'X' {
		t.Fatal("Canonical() did not return an isolated copy")
	}

	// Mutate AuthorityCanonical() copy
	a1 := actor.AuthorityCanonical()
	a1[0] = 'X'
	a2 := actor.AuthorityCanonical()
	if a2[0] == 'X' {
		t.Fatal("AuthorityCanonical() did not return an isolated copy")
	}
}

// Test 8: Safe integer limit validation (Revision and RevocationEpoch)
func TestActorRevisionAndEpochSafeIntegerLimits(t *testing.T) {
	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)
	const maxSafe = uint64(1<<53 - 1)
	const unsafe = uint64(1 << 53)

	// Revision: 1<<53-1 projects OK, 1<<53 rejects (registry accepts 1<<53)
	{
		credSafe := identity.Credential{
			ID: "app-key-rev-safe", TenantID: "acme", PrincipalID: "coding-app", Audience: "data",
			Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			Revision: maxSafe, RevocationEpoch: 1,
			Verifier: identity.Verifier(key, []byte(secret)),
		}
		regSafe, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credSafe}, validTestResourceSets())
		if err != nil {
			t.Fatalf("NewRegistry for Revision maxSafe failed: %v", err)
		}
		ctxSafe, err := regSafe.Authenticate(secret, "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatalf("Authenticate for Revision maxSafe failed: %v", err)
		}
		if _, err := action.ProjectActor(ctxSafe); err != nil {
			t.Fatalf("ProjectActor for Revision maxSafe expected OK, got: %v", err)
		}

		credUnsafe := identity.Credential{
			ID: "app-key-rev-unsafe", TenantID: "acme", PrincipalID: "coding-app", Audience: "data",
			Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			Revision: unsafe, RevocationEpoch: 1,
			Verifier: identity.Verifier(key, []byte(secret)),
		}
		// Registry accepts Revision = 1<<53
		regUnsafe, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credUnsafe}, validTestResourceSets())
		if err != nil {
			t.Fatalf("NewRegistry for Revision unsafe failed (registry should accept): %v", err)
		}
		ctxUnsafe, err := regUnsafe.Authenticate(secret, "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatalf("Authenticate for Revision unsafe failed: %v", err)
		}
		if _, err := action.ProjectActor(ctxUnsafe); !errors.Is(err, identity.ErrAuthentication) {
			t.Fatalf("ProjectActor for Revision unsafe expected ErrAuthentication, got: %v", err)
		}
	}

	// RevocationEpoch: 1<<53-1 projects OK, 1<<53 rejects (registry accepts 1<<53)
	{
		credSafe := identity.Credential{
			ID: "app-key-epoch-safe", TenantID: "acme", PrincipalID: "coding-app", Audience: "data",
			Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			Revision: 1, RevocationEpoch: maxSafe,
			Verifier: identity.Verifier(key, []byte(secret)),
		}
		regSafe, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credSafe}, validTestResourceSets())
		if err != nil {
			t.Fatalf("NewRegistry for RevocationEpoch maxSafe failed: %v", err)
		}
		ctxSafe, err := regSafe.Authenticate(secret, "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatalf("Authenticate for RevocationEpoch maxSafe failed: %v", err)
		}
		if _, err := action.ProjectActor(ctxSafe); err != nil {
			t.Fatalf("ProjectActor for RevocationEpoch maxSafe expected OK, got: %v", err)
		}

		credUnsafe := identity.Credential{
			ID: "app-key-epoch-unsafe", TenantID: "acme", PrincipalID: "coding-app", Audience: "data",
			Scopes:   []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			Revision: 1, RevocationEpoch: unsafe,
			Verifier: identity.Verifier(key, []byte(secret)),
		}
		// Registry accepts RevocationEpoch = 1<<53
		regUnsafe, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credUnsafe}, validTestResourceSets())
		if err != nil {
			t.Fatalf("NewRegistry for RevocationEpoch unsafe failed (registry should accept): %v", err)
		}
		ctxUnsafe, err := regUnsafe.Authenticate(secret, "data", "acme", "filesystem.read", now)
		if err != nil {
			t.Fatalf("Authenticate for RevocationEpoch unsafe failed: %v", err)
		}
		if _, err := action.ProjectActor(ctxUnsafe); !errors.Is(err, identity.ErrAuthentication) {
			t.Fatalf("ProjectActor for RevocationEpoch unsafe expected ErrAuthentication, got: %v", err)
		}
	}
}

// Test 9: Edge case - exactly 64 scopes projects and sorts correctly
func TestActorExactly64Scopes(t *testing.T) {
	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)

	// Create 64 unique scopes in reverse order across two operations
	// 32 for filesystem.write and 32 for filesystem.read
	var scopes []identity.Scope
	rSets := make(map[string][]identity.Resource, 64)
	for i := 31; i >= 0; i-- {
		setID := fmt.Sprintf("set-w-%02d", i)
		rSets[setID] = []identity.Resource{{Kind: "path", Value: "/work/**"}}
		scopes = append(scopes, identity.Scope{Operation: "filesystem.write", ResourceSet: setID})
	}
	for i := 31; i >= 0; i-- {
		setID := fmt.Sprintf("set-r-%02d", i)
		rSets[setID] = []identity.Resource{{Kind: "path", Value: "/work/**"}}
		scopes = append(scopes, identity.Scope{Operation: "filesystem.read", ResourceSet: setID})
	}
	if len(scopes) != 64 {
		t.Fatalf("expected 64 scopes, got %d", len(scopes))
	}

	cred := identity.Credential{
		ID:              "app-key-64",
		TenantID:        "acme",
		PrincipalID:     "coding-app",
		Audience:        "data",
		Scopes:          scopes,
		IssuedAt:        now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		Revision:        1,
		RevocationEpoch: 1,
		Verifier:        identity.Verifier(key, []byte(secret)),
	}

	reg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, rSets)
	if err != nil {
		t.Fatalf("NewRegistryWithResourceSets for 64 scopes failed: %v", err)
	}

	ctx, err := reg.Authenticate(secret, "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatalf("Authenticate for 64 scopes failed: %v", err)
	}

	actor, err := action.ProjectActor(ctx)
	if err != nil {
		t.Fatalf("ProjectActor for 64 scopes failed: %v", err)
	}

	// Verify that in the authority canonical bytes, scopes are sorted:
	// filesystem.read comes before filesystem.write, and within each, set-r-00..31 / set-w-00..31
	authStr := string(actor.AuthorityCanonical())
	var expectedScopesOrder []string
	for i := 0; i < 32; i++ {
		expectedScopesOrder = append(expectedScopesOrder, fmt.Sprintf(`{"operation":"filesystem.read","resource_set":"set-r-%02d"}`, i))
	}
	for i := 0; i < 32; i++ {
		expectedScopesOrder = append(expectedScopesOrder, fmt.Sprintf(`{"operation":"filesystem.write","resource_set":"set-w-%02d"}`, i))
	}
	expectedScopesJSON := `"scopes":[` + strings.Join(expectedScopesOrder, ",") + `]`
	if !strings.Contains(authStr, expectedScopesJSON) {
		t.Fatalf("AuthorityCanonical did not contain correctly sorted 64 scopes")
	}
}

// Test 10: Edge case - 64-char Security IDs project
func TestActor64CharSecurityIDs(t *testing.T) {
	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)

	// Valid 64-char Security IDs (1 + 63 = 64 characters)
	tenant64 := "t" + strings.Repeat("x", 63)
	principal64 := "p" + strings.Repeat("x", 63)
	credID64 := "c" + strings.Repeat("x", 63)
	set64 := "s" + strings.Repeat("x", 63)

	if len(tenant64) != 64 || len(principal64) != 64 || len(credID64) != 64 || len(set64) != 64 {
		t.Fatalf("IDs not 64 chars")
	}

	cred := identity.Credential{
		ID:              credID64,
		TenantID:        tenant64,
		PrincipalID:     principal64,
		Audience:        "data",
		Scopes:          []identity.Scope{{Operation: "filesystem.read", ResourceSet: set64}},
		IssuedAt:        now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		Revision:        1,
		RevocationEpoch: 1,
		Verifier:        identity.Verifier(key, []byte(secret)),
	}

	rSets := map[string][]identity.Resource{
		set64: {{Kind: "path", Value: "/work/**"}},
	}

	reg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, rSets)
	if err != nil {
		t.Fatalf("NewRegistryWithResourceSets with 64-char IDs failed: %v", err)
	}

	ctx, err := reg.Authenticate(secret, "data", tenant64, "filesystem.read", now)
	if err != nil {
		t.Fatalf("Authenticate with 64-char IDs failed: %v", err)
	}

	actor, err := action.ProjectActor(ctx)
	if err != nil {
		t.Fatalf("ProjectActor with 64-char IDs failed: %v", err)
	}

	authStr := string(actor.AuthorityCanonical())
	if !strings.Contains(authStr, tenant64) || !strings.Contains(authStr, principal64) || !strings.Contains(authStr, credID64) {
		t.Fatal("AuthorityCanonical missing 64-char IDs")
	}
}

// Test 11: Credential with ExpiresAt in year 10000 rejected by ProjectActor with identity.ErrAuthentication.
// Kills mutation removing len(s) != 20 in toSecurityTime.
func TestActorYear10000ExpiryRejected(t *testing.T) {
	key, secret := testKeyAndSecret()

	// Both IssuedAt and ExpiresAt are in year 10000 with window <= 90 days so NewRegistryWithResourceSets permits it.
	issuedAt := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(10000, 1, 2, 0, 0, 0, 0, time.UTC)
	now := time.Date(10000, 1, 1, 12, 0, 0, 0, time.UTC)

	cred := identity.Credential{
		ID:              "app-key-10k",
		TenantID:        "acme",
		PrincipalID:     "coding-app",
		Audience:        "data",
		Scopes:          []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		Revision:        1,
		RevocationEpoch: 1,
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

	_, err = action.ProjectActor(ctx)
	if !errors.Is(err, identity.ErrAuthentication) {
		t.Fatalf("ProjectActor with year 10000 expected identity.ErrAuthentication, got %v", err)
	}
}

// Test 12: 65 scopes and 65-char Security ID rejection.
func TestActor65ScopesAnd65CharIDRejected(t *testing.T) {
	key, secret := testKeyAndSecret()
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)

	// Case 1: 65 scopes
	var scopes65 []identity.Scope
	rSets := make(map[string][]identity.Resource)
	for i := 0; i < 65; i++ {
		rsName := fmt.Sprintf("set-%02d", i)
		scopes65 = append(scopes65, identity.Scope{Operation: "filesystem.read", ResourceSet: rsName})
		rSets[rsName] = []identity.Resource{{Kind: "path", Value: "/work/**"}}
	}
	cred65Scopes := identity.Credential{
		ID:              "key-65-scopes",
		TenantID:        "acme",
		PrincipalID:     "app",
		Audience:        "data",
		Scopes:          scopes65,
		IssuedAt:        now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		Revision:        1,
		RevocationEpoch: 1,
		Verifier:        identity.Verifier(key, []byte(secret)),
	}
	// Note: 65 scopes are rejected through NewRegistryWithResourceSets; assert that.
	if _, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred65Scopes}, rSets); err == nil {
		t.Fatal("expected NewRegistryWithResourceSets to reject credential with 65 scopes, got nil")
	}

	// Case 2: 65-char Security ID
	credID65 := "c" + strings.Repeat("x", 64) // 65 chars
	cred65ID := identity.Credential{
		ID:              credID65,
		TenantID:        "acme",
		PrincipalID:     "app",
		Audience:        "data",
		Scopes:          []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:        now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		Revision:        1,
		RevocationEpoch: 1,
		Verifier:        identity.Verifier(key, []byte(secret)),
	}
	// Note: 65-char Security ID is rejected through NewRegistryWithResourceSets; assert that.
	if _, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred65ID}, validTestResourceSets()); err == nil {
		t.Fatal("expected NewRegistryWithResourceSets to reject credential with 65-char ID, got nil")
	}
}
