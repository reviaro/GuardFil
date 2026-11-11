package identity

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAuthRevocation(t *testing.T) {
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	now := time.Now().UTC().Truncate(time.Second)
	v := Verifier(key, secret)
	r, e := NewRegistry(key, []Credential{{ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data", Scopes: []Scope{{Operation: "filesystem.read", ResourceSet: "all"}}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1, Verifier: v}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Authenticate(string(secret), "data", "acme", "filesystem.read", now); e != nil {
		t.Fatal(e)
	}
	r.Revoke("key-1", 2)
	if _, e = r.Authenticate(string(secret), "data", "acme", "filesystem.read", now); e != ErrAuthentication {
		t.Fatal(e)
	}
}

func TestRegistryRejectsDuplicateVerifierAndIssuedAtBoundary(t *testing.T) {
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	now := time.Now().UTC().Truncate(time.Second)
	base := Credential{ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data", Scopes: []Scope{{Operation: "filesystem.read", ResourceSet: "all"}}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1, Verifier: Verifier(key, secret)}
	duplicateID := base
	duplicateID.Verifier = Verifier(key, []byte("different-valid-bearer-secret-012345678901234"))
	if _, err := NewRegistry(key, []Credential{base, duplicateID}); err == nil {
		t.Fatal("duplicate credential ID admitted")
	}
	duplicateVerifier := base
	duplicateVerifier.ID = "key-2"
	if _, err := NewRegistry(key, []Credential{base, duplicateVerifier}); err == nil {
		t.Fatal("duplicate verifier admitted")
	}
	r, err := NewRegistry(key, []Credential{base})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authenticate(string(secret), "data", "acme", "filesystem.read", now); err != nil {
		t.Fatalf("issued_at equality rejected: %v", err)
	}
}

func TestConcurrentAuthenticateAndRevoke(t *testing.T) {
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	now := time.Now().UTC().Truncate(time.Second)
	r, err := NewRegistry(key, []Credential{{ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data", Scopes: []Scope{{Operation: "filesystem.read", ResourceSet: "all"}}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1, Verifier: Verifier(key, secret)}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = r.Authenticate(string(secret), "data", "acme", "filesystem.read", now) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = r.Revoke("key-1", 2) }()
	wg.Wait()
	if _, err := r.Authenticate(string(secret), "data", "acme", "filesystem.read", now); err == nil {
		t.Fatal("revocation lost after concurrent traffic")
	}
}

func TestAuthenticateRejectsPreIssueAndCopiesScopes(t *testing.T) {
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	now := time.Now().UTC().Truncate(time.Second)
	scopes := []Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}}
	record := Credential{ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data", Scopes: scopes, IssuedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), Revision: 1, Verifier: Verifier(key, secret)}
	r, err := NewRegistry(key, []Credential{record})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authenticate(string(secret), "data", "acme", "filesystem.read", now); err == nil {
		t.Fatal("pre-issue credential authenticated")
	}

	record.IssuedAt = now.Add(-time.Hour)
	record.ExpiresAt = now.Add(time.Hour)
	r, err = NewRegistryWithResourceSets(key, []Credential{record}, map[string][]Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	scopes[0].Operation = "filesystem.write"
	if _, err := r.Authenticate(string(secret), "data", "acme", "filesystem.write", now); err == nil {
		t.Fatal("caller scope mutation changed registry authority")
	}
	p, err := r.Authenticate(string(secret), "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	returned := p.Scopes()
	returned[0].Operation = "filesystem.write"
	if err := r.Validate(p, "filesystem.read", "path", "/work/file", now); err != nil {
		t.Fatal("mutation of returned scope copy changed context", err)
	}
}

func TestRegistryRejectsEmptyQueryURLPattern(t *testing.T) {
	key := make([]byte, 32)
	now := time.Now().UTC().Truncate(time.Second)
	record := Credential{
		ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data",
		Scopes:   []Scope{{Operation: "http.request", ResourceSet: "allowed-urls"}},
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
		Verifier: Verifier(key, []byte("0123456789012345678901234567890123456789012")),
	}
	if _, err := NewRegistryWithResourceSets(key, []Credential{record}, map[string][]Resource{
		"allowed-urls": {{Kind: "url", Value: "https://example.com/a?"}},
	}); err == nil {
		t.Fatal("registry admitted empty-query URL pattern")
	}
	if _, err := NewRegistryWithResourceSets(key, []Credential{record}, map[string][]Resource{
		"allowed-urls": {{Kind: "url", Value: "https://example.com/a"}},
	}); err != nil {
		t.Fatal("registry rejected canonical URL pattern", err)
	}
}

func TestNewRegistryScopeOperationValidation(t *testing.T) {
	key := make([]byte, 32)
	now := time.Now().UTC().Truncate(time.Second)

	rejectedOps := []string{
		"fs.read",
		"http.get",
		"tool.execute",
		"Filesystem.read",
		" filesystem.read",
		"filesystem.read ",
		"FILESYSTEM.READ",
	}
	for _, op := range rejectedOps {
		cred := Credential{
			ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data",
			Scopes:   []Scope{{Operation: op, ResourceSet: "all"}},
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
			Verifier: Verifier(key, []byte("0123456789012345678901234567890123456789012")),
		}
		if _, err := NewRegistry(key, []Credential{cred}); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("NewRegistry with scope operation %q expected ErrAuthentication, got %v", op, err)
		}
	}

	acceptedOps := []string{
		"filesystem.read",
		"filesystem.write",
		"llm.request",
		"tool.invoke",
		"shell.execute",
		"http.request",
	}
	for _, op := range acceptedOps {
		cred := Credential{
			ID: "key-1", TenantID: "acme", PrincipalID: "app", Audience: "data",
			Scopes:   []Scope{{Operation: op, ResourceSet: "all"}},
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1,
			Verifier: Verifier(key, []byte("0123456789012345678901234567890123456789012")),
		}
		if _, err := NewRegistry(key, []Credential{cred}); err != nil {
			t.Fatalf("NewRegistry with accepted scope operation %q failed: %v", op, err)
		}
	}
}

func TestRegistryRejectsSubsecondCredentialTimes(t *testing.T) {
	key := make([]byte, 32)
	secret := []byte("0123456789012345678901234567890123456789012")
	now := time.Now().UTC().Truncate(time.Second)

	// Non-zero nanoseconds on IssuedAt
	credSubIssued := Credential{
		ID:          "key-sub-issued",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes:      []Scope{{Operation: "filesystem.read", ResourceSet: "all"}},
		IssuedAt:    now.Add(-time.Hour).Add(time.Nanosecond),
		ExpiresAt:   now.Add(time.Hour),
		Revision:    1,
		Verifier:    Verifier(key, secret),
	}
	if _, err := NewRegistry(key, []Credential{credSubIssued}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication for sub-second IssuedAt, got %v", err)
	}

	// Non-zero nanoseconds on ExpiresAt
	credSubExpires := Credential{
		ID:          "key-sub-expires",
		TenantID:    "acme",
		PrincipalID: "app",
		Audience:    "data",
		Scopes:      []Scope{{Operation: "filesystem.read", ResourceSet: "all"}},
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(time.Hour).Add(time.Nanosecond),
		Revision:    1,
		Verifier:    Verifier(key, secret),
	}
	if _, err := NewRegistry(key, []Credential{credSubExpires}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication for sub-second ExpiresAt, got %v", err)
	}
}

func assertExactError(t *testing.T, name string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: expected %v, got %v", name, want, err)
	}
	sentinels := []error{ErrRequired, ErrAuthentication, ErrForbidden, ErrStale}
	for _, s := range sentinels {
		if s != want && errors.Is(err, s) {
			t.Fatalf("%s: expected %v, but also matched %v", name, want, s)
		}
	}
}

func TestErrorSentinelBranches(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	now := time.Now().UTC().Truncate(time.Second)
	secret := []byte("0123456789012345678901234567890123456789012")
	v := Verifier(key, secret)

	baseCred := Credential{
		ID:              "cred-1",
		TenantID:        "tenant-a",
		PrincipalID:     "principal-1",
		Audience:        "data",
		Scopes:          []Scope{{Operation: "filesystem.read", ResourceSet: "set-1"}},
		IssuedAt:        now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		Revision:        1,
		RevocationEpoch: 0,
		Verifier:        v,
	}

	resSets := map[string][]Resource{
		"set-1": {{Kind: "path", Value: "/allowed/**"}},
	}

	reg, err := NewRegistryWithResourceSets(key, []Credential{baseCred}, resSets)
	if err != nil {
		t.Fatalf("setup NewRegistryWithResourceSets failed: %v", err)
	}

	// 1. NewRegistry config errors
	if _, err := NewRegistry([]byte("too-short"), []Credential{baseCred}); true {
		assertExactError(t, "NewRegistry key too short", err, ErrAuthentication)
	}
	if _, err := NewRegistryWithResourceSets(key, []Credential{baseCred}, map[string][]Resource{"invalid set": {{Kind: "path", Value: "/allowed/**"}}}); true {
		assertExactError(t, "NewRegistry invalid resource set id", err, ErrAuthentication)
	}

	// 2. Authenticate branches
	// Pre-match / invalid bearer
	if _, err := reg.Authenticate("", "data", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate empty bearer", err, ErrRequired)
	}
	if _, err := reg.Authenticate("short", "data", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate bearer < 43", err, ErrAuthentication)
	}
	if _, err := reg.Authenticate(string(secret), "unknown-aud", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate unknown audience", err, ErrAuthentication)
	}
	// Unknown credential (verifier mismatch)
	diffSecret := []byte("different-secret-012345678901234567890123456789")
	if _, err := reg.Authenticate(string(diffSecret), "data", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate verifier mismatch", err, ErrAuthentication)
	}
	// Matched but revoked
	revCred := baseCred
	revCred.Revoked = true
	regRev, _ := NewRegistryWithResourceSets(key, []Credential{revCred}, resSets)
	if _, err := regRev.Authenticate(string(secret), "data", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate revoked", err, ErrAuthentication)
	}
	// Matched but now < IssuedAt
	preCred := baseCred
	preCred.IssuedAt = now.Add(time.Hour)
	preCred.ExpiresAt = now.Add(2 * time.Hour)
	regPre, _ := NewRegistryWithResourceSets(key, []Credential{preCred}, resSets)
	if _, err := regPre.Authenticate(string(secret), "data", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate pre-issue", err, ErrAuthentication)
	}
	// Matched but now >= ExpiresAt
	expCred := baseCred
	expCred.IssuedAt = now.Add(-2 * time.Hour)
	expCred.ExpiresAt = now.Add(-time.Hour)
	regExp, _ := NewRegistryWithResourceSets(key, []Credential{expCred}, resSets)
	if _, err := regExp.Authenticate(string(secret), "data", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate expired", err, ErrAuthentication)
	}
	// Matched but requested audience != cred.Audience (e.g. management on data cred)
	if _, err := reg.Authenticate(string(secret), "management", "tenant-a", "filesystem.read", now); true {
		assertExactError(t, "Authenticate audience mismatch", err, ErrAuthentication)
	}

	// Existence/validity oracle prevention: invalid credentials with wrong tenant or missing scope
	// must return ErrAuthentication, never ErrForbidden.
	oracleCases := []struct {
		name      string
		cred      Credential
		reqAud    string
		reqTenant string
		reqOp     string
	}{
		{
			name:      "revoked+wrong tenant",
			cred:      func() Credential { c := baseCred; c.Revoked = true; return c }(),
			reqAud:    "data",
			reqTenant: "wrong-tenant",
			reqOp:     "filesystem.read",
		},
		{
			name: "expired+missing scope",
			cred: func() Credential {
				c := baseCred
				c.IssuedAt = now.Add(-2 * time.Hour)
				c.ExpiresAt = now.Add(-time.Hour)
				return c
			}(),
			reqAud:    "data",
			reqTenant: "tenant-a",
			reqOp:     "filesystem.write",
		},
		{
			name: "not-yet-valid+wrong tenant",
			cred: func() Credential {
				c := baseCred
				c.IssuedAt = now.Add(time.Hour)
				c.ExpiresAt = now.Add(2 * time.Hour)
				return c
			}(),
			reqAud:    "data",
			reqTenant: "wrong-tenant",
			reqOp:     "filesystem.read",
		},
		{
			name:      "wrong audience+missing scope",
			cred:      baseCred,
			reqAud:    "management",
			reqTenant: "tenant-a",
			reqOp:     "filesystem.write",
		},
	}
	for _, tc := range oracleCases {
		r, err := NewRegistryWithResourceSets(key, []Credential{tc.cred}, resSets)
		if err != nil {
			t.Fatalf("setup registry for %s failed: %v", tc.name, err)
		}
		_, authErr := r.Authenticate(string(secret), tc.reqAud, tc.reqTenant, tc.reqOp, now)
		assertExactError(t, "Authenticate oracle: "+tc.name, authErr, ErrAuthentication)
	}

	// Matched, not revoked, valid window, requested audience, but tenant != requested
	if _, err := reg.Authenticate(string(secret), "data", "wrong-tenant", "filesystem.read", now); true {
		assertExactError(t, "Authenticate tenant mismatch", err, ErrForbidden)
	}
	// Matched, not revoked, valid window, requested audience, valid tenant, but lacks scope
	if _, err := reg.Authenticate(string(secret), "data", "tenant-a", "filesystem.write", now); true {
		assertExactError(t, "Authenticate missing scope", err, ErrForbidden)
	}
	// Valid Authenticate
	pctx, err := reg.Authenticate(string(secret), "data", "tenant-a", "filesystem.read", now)
	if err != nil {
		t.Fatalf("valid Authenticate failed: %v", err)
	}

	// 3. Validate branches
	// Nil registry
	var nilReg *Registry
	assertExactError(t, "Validate nil registry", nilReg.Validate(pctx, "filesystem.read", "path", "/allowed/file", now), ErrAuthentication)

	// Foreign registry
	foreignKey := bytes.Repeat([]byte{0x77}, 32)
	foreignReg, _ := NewRegistryWithResourceSets(foreignKey, []Credential{baseCred}, resSets)
	assertExactError(t, "Validate foreign registry", foreignReg.Validate(pctx, "filesystem.read", "path", "/allowed/file", now), ErrAuthentication)

	// Wrong audience on context
	badAudCtx := pctx
	badAudCtx.audience = "management"
	assertExactError(t, "Validate bad audience on ctx", reg.Validate(badAudCtx, "filesystem.read", "path", "/allowed/file", now), ErrAuthentication)

	// Wrong authMethod on context
	badMethodCtx := pctx
	badMethodCtx.authMethod = "mutual_tls"
	assertExactError(t, "Validate bad authMethod on ctx", reg.Validate(badMethodCtx, "filesystem.read", "path", "/allowed/file", now), ErrAuthentication)

	// Window validation: pre-issue window -> ErrAuthentication; expired after authentication -> ErrStale
	assertExactError(t, "Validate before ctx issuedAt", reg.Validate(pctx, "filesystem.read", "path", "/allowed/file", pctx.issuedAt.Add(-time.Hour)), ErrAuthentication)
	assertExactError(t, "Validate at/after ctx expiresAt", reg.Validate(pctx, "filesystem.read", "path", "/allowed/file", pctx.expiresAt.Add(time.Second)), ErrStale)
	assertExactError(t, "Validate at ctx expiresAt exact boundary", reg.Validate(pctx, "filesystem.read", "path", "/allowed/file", pctx.expiresAt), ErrStale)

	for _, tc := range []struct {
		name    string
		now     time.Time
		wantErr error
	}{
		{name: "pre-issue window", now: pctx.issuedAt.Add(-time.Hour), wantErr: ErrAuthentication},
		{name: "expired after authentication", now: pctx.expiresAt.Add(time.Second), wantErr: ErrStale},
	} {
		assertExactError(t, tc.name, reg.Validate(pctx, "filesystem.read", "path", "/allowed/file", tc.now), tc.wantErr)
	}

	// Live record missing
	emptyReg, _ := NewRegistryWithResourceSets(key, []Credential{}, resSets)
	missingCtx := pctx
	missingCtx.registry = emptyReg
	assertExactError(t, "Validate live record missing", emptyReg.Validate(missingCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record revoked (different epoch)
	regToRevoke, _ := NewRegistryWithResourceSets(key, []Credential{baseCred}, resSets)
	revCtx, _ := regToRevoke.Authenticate(string(secret), "data", "tenant-a", "filesystem.read", now)
	_ = regToRevoke.Revoke("cred-1", 1)
	assertExactError(t, "Validate live record revoked", regToRevoke.Validate(revCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record revoked with SAME revocation epoch the PrincipalContext already carries
	regToRevokeSameEpoch, _ := NewRegistryWithResourceSets(key, []Credential{baseCred}, resSets)
	revCtxSameEpoch, _ := regToRevokeSameEpoch.Authenticate(string(secret), "data", "tenant-a", "filesystem.read", now)
	_ = regToRevokeSameEpoch.Revoke("cred-1", revCtxSameEpoch.RevocationEpoch())
	assertExactError(t, "Validate live record revoked with same epoch", regToRevokeSameEpoch.Validate(revCtxSameEpoch, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (tenant)
	diffTenantCred := baseCred
	diffTenantCred.TenantID = "tenant-b"
	regDiffTenant, _ := NewRegistryWithResourceSets(key, []Credential{diffTenantCred}, resSets)
	diffTenantCtx := pctx
	diffTenantCtx.registry = regDiffTenant
	assertExactError(t, "Validate live tenant differs", regDiffTenant.Validate(diffTenantCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (principal)
	diffPrinCred := baseCred
	diffPrinCred.PrincipalID = "principal-2"
	regDiffPrin, _ := NewRegistryWithResourceSets(key, []Credential{diffPrinCred}, resSets)
	diffPrinCtx := pctx
	diffPrinCtx.registry = regDiffPrin
	assertExactError(t, "Validate live principal differs", regDiffPrin.Validate(diffPrinCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (audience)
	diffAudCred := baseCred
	diffAudCred.Audience = "management"
	regDiffAud, _ := NewRegistryWithResourceSets(key, []Credential{diffAudCred}, resSets)
	diffAudCtx := pctx
	diffAudCtx.registry = regDiffAud
	assertExactError(t, "Validate live audience differs", regDiffAud.Validate(diffAudCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (revision)
	diffRevCred := baseCred
	diffRevCred.Revision = 2
	regDiffRev, _ := NewRegistryWithResourceSets(key, []Credential{diffRevCred}, resSets)
	diffRevCtx := pctx
	diffRevCtx.registry = regDiffRev
	assertExactError(t, "Validate live revision differs", regDiffRev.Validate(diffRevCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (revocation epoch)
	diffEpochCred := baseCred
	diffEpochCred.RevocationEpoch = 5
	regDiffEpoch, _ := NewRegistryWithResourceSets(key, []Credential{diffEpochCred}, resSets)
	diffEpochCtx := pctx
	diffEpochCtx.registry = regDiffEpoch
	assertExactError(t, "Validate live revocation epoch differs", regDiffEpoch.Validate(diffEpochCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (issuedAt)
	diffIssuedCred := baseCred
	diffIssuedCred.IssuedAt = baseCred.IssuedAt.Add(-30 * time.Minute)
	regDiffIssued, _ := NewRegistryWithResourceSets(key, []Credential{diffIssuedCred}, resSets)
	diffIssuedCtx := pctx
	diffIssuedCtx.registry = regDiffIssued
	assertExactError(t, "Validate live issuedAt differs", regDiffIssued.Validate(diffIssuedCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (expiresAt)
	diffExpiresCred := baseCred
	diffExpiresCred.ExpiresAt = baseCred.ExpiresAt.Add(30 * time.Minute)
	regDiffExpires, _ := NewRegistryWithResourceSets(key, []Credential{diffExpiresCred}, resSets)
	diffExpiresCtx := pctx
	diffExpiresCtx.registry = regDiffExpires
	assertExactError(t, "Validate live expiresAt differs", regDiffExpires.Validate(diffExpiresCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Live record differs (scopes)
	diffScopeCred := baseCred
	diffScopeCred.Scopes = []Scope{{Operation: "filesystem.read", ResourceSet: "set-2"}}
	resSetsMulti := map[string][]Resource{
		"set-1": {{Kind: "path", Value: "/allowed/**"}},
		"set-2": {{Kind: "path", Value: "/other/**"}},
	}
	regDiffScope, _ := NewRegistryWithResourceSets(key, []Credential{diffScopeCred}, resSetsMulti)
	diffScopeCtx := pctx
	diffScopeCtx.registry = regDiffScope
	assertExactError(t, "Validate live scopes differ", regDiffScope.Validate(diffScopeCtx, "filesystem.read", "path", "/allowed/file", now), ErrStale)

	// Context and live record agree, but scopeAllows fails (wrong operation, wrong kind, wrong value)
	assertExactError(t, "Validate scope operation denial", reg.Validate(pctx, "filesystem.write", "path", "/allowed/file", now), ErrForbidden)
	assertExactError(t, "Validate scope resource kind denial", reg.Validate(pctx, "filesystem.read", "url", "https://example.com", now), ErrForbidden)
	assertExactError(t, "Validate scope path pattern denial", reg.Validate(pctx, "filesystem.read", "path", "/forbidden/file", now), ErrForbidden)

	// Context and live record agree, scopeAllows succeeds
	if err := reg.Validate(pctx, "filesystem.read", "path", "/allowed/file", now); err != nil {
		t.Fatalf("valid Validate expected nil, got %v", err)
	}
}
