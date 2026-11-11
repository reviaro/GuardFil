// Package identity authenticates provisioned opaque bearer credentials.  Its
// output is immutable data; caller-provided labels never contribute authority.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sort"
	"sync"
	"time"

	resourceid "github.com/reviaro/guardfil/internal/resource"
)

var (
	ErrRequired       = errors.New("AUTH_REQUIRED")
	ErrAuthentication = errors.New("AUTH_INVALID")
	ErrForbidden      = errors.New("AUTH_FORBIDDEN")
	ErrStale          = errors.New("AUTHORIZATION_STALE")
)

type Scope struct{ Operation, ResourceSet string }
type Resource struct{ Kind, Value string }
type Credential struct {
	ID, TenantID, PrincipalID, Audience string
	Scopes                              []Scope
	IssuedAt, ExpiresAt                 time.Time
	Revoked                             bool
	Revision, RevocationEpoch           uint64
	Verifier                            [32]byte // HMAC-SHA-256(secret), never the secret or a lookup key.
}

// PrincipalContext has no exported authority fields by design. It can only be
// obtained from Registry.Authenticate, and its Registry binding is rechecked
// immediately before a positive authorization decision.
type PrincipalContext struct {
	tenantID, principalID, credentialID, audience string
	scopes                                        []Scope
	credentialRevision, revocationEpoch           uint64
	issuedAt, expiresAt, authenticatedAt          time.Time
	authMethod                                    string
	registry                                      *Registry
}
type Registry struct {
	mu           sync.RWMutex
	credentials  []Credential
	resourceSets map[string][]Resource
	key          []byte
}

// NewRegistry installs a bounded immutable-by-copy registry. key is a process
// secret used for keyed credential verification and must be at least 32 bytes.
func NewRegistry(key []byte, records []Credential) (*Registry, error) {
	return newRegistry(key, records, nil, false)
}

// NewRegistryWithResourceSets installs the operation and finite resource
// ceilings needed for positive authorization. NewRegistry remains suitable for
// authentication-only consumers but deliberately cannot validate a resource.
func NewRegistryWithResourceSets(key []byte, records []Credential, resourceSets map[string][]Resource) (*Registry, error) {
	return newRegistry(key, records, resourceSets, true)
}

func newRegistry(key []byte, records []Credential, resourceSets map[string][]Resource, requireSets bool) (*Registry, error) {
	if len(key) < 32 || len(records) > 10000 {
		return nil, ErrAuthentication
	}
	credentials := make([]Credential, len(records))
	for i, record := range records {
		credentials[i] = record
		credentials[i].Scopes = cloneScopes(record.Scopes)
	}
	sets := make(map[string][]Resource, len(resourceSets))
	for id, resources := range resourceSets {
		if !validID(id) || len(resources) == 0 || len(resources) > 256 {
			return nil, ErrAuthentication
		}
		sets[id] = append([]Resource(nil), resources...)
		for _, resource := range sets[id] {
			if !validResource(resource) {
				return nil, ErrAuthentication
			}
		}
	}
	r := &Registry{key: append([]byte(nil), key...), credentials: credentials, resourceSets: sets}
	ids := make(map[string]struct{}, len(r.credentials))
	verifiers := make(map[[32]byte]struct{}, len(r.credentials))
	for _, c := range r.credentials {
		if !validCredential(c) {
			return nil, ErrAuthentication
		}
		if _, duplicate := ids[c.ID]; duplicate {
			return nil, ErrAuthentication
		}
		if _, duplicate := verifiers[c.Verifier]; duplicate {
			return nil, ErrAuthentication
		}
		ids[c.ID] = struct{}{}
		verifiers[c.Verifier] = struct{}{}
		if requireSets {
			for _, scope := range c.Scopes {
				if _, present := sets[scope.ResourceSet]; !present {
					return nil, ErrAuthentication
				}
			}
		}
	}
	return r, nil
}
func Verifier(key, secret []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write(secret)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func validCredential(c Credential) bool {
	if !validID(c.ID) || !validID(c.TenantID) || !validID(c.PrincipalID) || c.Audience != "data" && c.Audience != "management" || len(c.Scopes) == 0 || len(c.Scopes) > 64 || c.Revision == 0 || c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 90*24*time.Hour || c.IssuedAt.Nanosecond() != 0 || c.ExpiresAt.Nanosecond() != 0 {
		return false
	}
	seen := make(map[Scope]struct{}, len(c.Scopes))
	for _, scope := range c.Scopes {
		if !validID(scope.Operation) || !resourceid.SecurityOperation(scope.Operation) || !validID(scope.ResourceSet) {
			return false
		}
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}
func validID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') || (i == 0 && !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// Authenticate returns ErrRequired (AUTH_REQUIRED) when no credential is
// presented (bearer == ""). Malformed, too-short, unknown, expired, revoked,
// or wrong-audience credentials return ErrAuthentication (AUTH_INVALID)
// without revealing credential existence. Authenticated tenant or scope
// failures return ErrForbidden (AUTH_FORBIDDEN); AUTH_FORBIDDEN is returned
// only after the presented credential has verified and is unrevoked, inside its
// validity window, and for the requested audience.
func (r *Registry) Authenticate(bearer, audience, tenant, operation string, now time.Time) (PrincipalContext, error) {
	if bearer == "" {
		return PrincipalContext{}, ErrRequired
	}
	if len(bearer) < 43 || audience != "data" && audience != "management" {
		return PrincipalContext{}, ErrAuthentication
	}
	v := Verifier(r.key, []byte(bearer))
	r.mu.RLock()
	defer r.mu.RUnlock()
	var selected *Credential
	for i := range r.credentials { // full scan prevents credential-ID existence timing.
		match := hmac.Equal(v[:], r.credentials[i].Verifier[:])
		if match {
			selected = &r.credentials[i]
		}
	}
	if selected == nil || selected.Revoked || now.Before(selected.IssuedAt) || !now.Before(selected.ExpiresAt) || selected.Audience != audience {
		return PrincipalContext{}, ErrAuthentication
	}
	if selected.TenantID != tenant || !hasScope(selected.Scopes, operation) {
		return PrincipalContext{}, ErrForbidden
	}
	s := cloneScopes(selected.Scopes)
	sort.Slice(s, func(i, j int) bool {
		if s[i].Operation != s[j].Operation {
			return s[i].Operation < s[j].Operation
		}
		return s[i].ResourceSet < s[j].ResourceSet
	})
	return PrincipalContext{
		tenantID:           selected.TenantID,
		principalID:        selected.PrincipalID,
		credentialID:       selected.ID,
		audience:           selected.Audience,
		scopes:             s,
		credentialRevision: selected.Revision,
		revocationEpoch:    selected.RevocationEpoch,
		issuedAt:           selected.IssuedAt,
		expiresAt:          selected.ExpiresAt,
		authenticatedAt:    now.UTC().Truncate(time.Second),
		authMethod:         "opaque_bearer",
		registry:           r,
	}, nil
}
func hasScope(scopes []Scope, op string) bool {
	for _, s := range scopes {
		if s.Operation == op {
			return true
		}
	}
	return false
}
func (r *Registry) Revoke(id string, epoch uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.credentials {
		if r.credentials[i].ID == id {
			r.credentials[i].Revoked = true
			r.credentials[i].RevocationEpoch = epoch
			return nil
		}
	}
	return ErrAuthentication
}

// Validate rechecks a context against the live registry under the registry lock.
// Nil or foreign registries, invalid context audience or auth method, and
// pre-issue context windows return ErrAuthentication (AUTH_INVALID).
// Expired context windows (now at or after expiresAt), missing live records,
// revoked credentials, or mismatched credentials (revisions, epochs, tenant,
// principal, audience, validity window, or scopes) return ErrStale
// (AUTHORIZATION_STALE). Valid credentials whose scopes do not permit the
// requested operation on the target resource return ErrForbidden (AUTH_FORBIDDEN).
func (r *Registry) Validate(p PrincipalContext, operation, resourceKind, resource string, now time.Time) error {
	if r == nil || p.registry != r || p.audience != "data" || p.authMethod != "opaque_bearer" || now.Before(p.issuedAt) {
		return ErrAuthentication
	}
	if !now.Before(p.expiresAt) {
		return ErrStale
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matched *Credential
	for i := range r.credentials {
		if r.credentials[i].ID == p.credentialID {
			matched = &r.credentials[i]
			break
		}
	}
	if matched == nil {
		return ErrStale
	}
	if matched.Revoked ||
		matched.TenantID != p.tenantID ||
		matched.PrincipalID != p.principalID ||
		matched.Audience != p.audience ||
		matched.Revision != p.credentialRevision ||
		matched.RevocationEpoch != p.revocationEpoch ||
		!matched.IssuedAt.Equal(p.issuedAt) ||
		!matched.ExpiresAt.Equal(p.expiresAt) ||
		!equalScopes(matched.Scopes, p.scopes) {
		return ErrStale
	}
	if !scopeAllows(matched.Scopes, r.resourceSets, operation, resourceKind, resource) {
		return ErrForbidden
	}
	return nil
}

func validResource(resource Resource) bool {
	return resourceid.ValidatePattern(resource.Kind, resource.Value) == nil
}

func scopeAllows(scopes []Scope, sets map[string][]Resource, operation, kind, value string) bool {
	for _, scope := range scopes {
		if scope.Operation != operation {
			continue
		}
		for _, resource := range sets[scope.ResourceSet] {
			if resource.Kind == kind && resourceid.Match(kind, resource.Value, value) {
				return true
			}
		}
	}
	return false
}

func (p PrincipalContext) TenantID() string           { return p.tenantID }
func (p PrincipalContext) PrincipalID() string        { return p.principalID }
func (p PrincipalContext) CredentialID() string       { return p.credentialID }
func (p PrincipalContext) Audience() string           { return p.audience }
func (p PrincipalContext) CredentialRevision() uint64 { return p.credentialRevision }
func (p PrincipalContext) RevocationEpoch() uint64    { return p.revocationEpoch }
func (p PrincipalContext) AuthenticatedAt() time.Time { return p.authenticatedAt }
func (p PrincipalContext) ExpiresAt() time.Time       { return p.expiresAt }
func (p PrincipalContext) Scopes() []Scope            { return cloneScopes(p.scopes) }
func (p PrincipalContext) AuthMethod() string         { return p.authMethod }

func cloneScopes(scopes []Scope) []Scope { return append([]Scope(nil), scopes...) }

func equalScopes(a, b []Scope) bool {
	if len(a) != len(b) {
		return false
	}
	ac := cloneScopes(a)
	bc := cloneScopes(b)
	sort.Slice(ac, func(i, j int) bool {
		if ac[i].Operation != ac[j].Operation {
			return ac[i].Operation < ac[j].Operation
		}
		return ac[i].ResourceSet < ac[j].ResourceSet
	})
	sort.Slice(bc, func(i, j int) bool {
		if bc[i].Operation != bc[j].Operation {
			return bc[i].Operation < bc[j].Operation
		}
		return bc[i].ResourceSet < bc[j].ResourceSet
	})
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
