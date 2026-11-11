package action

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/reviaro/guardfil/internal/identity"
)

const (
	actorSchemaVersion     = "guardfil.actor/1"
	authoritySchemaVersion = "guardfil.authority/1"
	authMethodBearer       = "opaque_bearer"
	audienceData           = "data"
	authContextPrefix      = "GuardFil.AuthContext.v1\n"
	maxSafeInteger         = uint64(1<<53 - 1)
)

// Actor represents the immutable canonical projection of an authenticated identity.PrincipalContext.
type Actor struct {
	canonical          []byte
	authorityCanonical []byte
	authContextDigest  string
	// obj must never be mutated or exposed; shared with the seal by design.
	obj obj
}

// Canonical returns a copy of the canonical actor JSON bytes.
func (a Actor) Canonical() []byte {
	return append([]byte(nil), a.canonical...)
}

// AuthorityCanonical returns a copy of the canonical authority JSON bytes.
func (a Actor) AuthorityCanonical() []byte {
	return append([]byte(nil), a.authorityCanonical...)
}

// AuthContextDigest returns the "sha256:"-prefixed lowercase hex SHA-256 digest of the canonical authority.
func (a Actor) AuthContextDigest() string {
	return a.authContextDigest
}

// SecurityTimeToRuntime converts a UTC Security Time string (YYYY-MM-DDTHH:MM:SSZ)
// into runtime format by appending ".000" before "Z" (YYYY-MM-DDTHH:MM:SS.000Z).
func SecurityTimeToRuntime(s string) (string, error) {
	if len(s) != 20 {
		return "", identity.ErrAuthentication
	}
	const layout = "2006-01-02T15:04:05Z"
	t, err := time.Parse(layout, s)
	if err != nil || t.Nanosecond() != 0 {
		return "", identity.ErrAuthentication
	}
	if t.UTC().Format(layout) != s {
		return "", identity.ErrAuthentication
	}
	return s[:19] + ".000Z", nil
}

// RuntimeToSecurityTime converts a runtime time string (YYYY-MM-DDTHH:MM:SS.mmmZ)
// into a Security Time string, requiring exactly ".000Z" fractional milliseconds.
func RuntimeToSecurityTime(s string) (string, error) {
	if len(s) != 24 {
		return "", identity.ErrAuthentication
	}
	if !strings.HasSuffix(s, ".000Z") {
		return "", identity.ErrAuthentication
	}
	const layout = "2006-01-02T15:04:05.000Z"
	t, err := time.Parse(layout, s)
	if err != nil || t.Nanosecond() != 0 {
		return "", identity.ErrAuthentication
	}
	if t.UTC().Format(layout) != s {
		return "", identity.ErrAuthentication
	}
	return s[:19] + "Z", nil
}

func validSecurityID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				return false
			}
		} else {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

func toSecurityTime(t time.Time) (string, error) {
	if t.IsZero() {
		return "", identity.ErrAuthentication
	}
	u := t.UTC()
	if u.Nanosecond() != 0 {
		return "", identity.ErrAuthentication
	}
	s := u.Format("2006-01-02T15:04:05Z")
	if len(s) != 20 {
		return "", identity.ErrAuthentication
	}
	return s, nil
}

// ProjectActor projects an authenticated identity.PrincipalContext into an immutable Actor.
// It is a projection only: it does not consult the live registry or clock, and its digest is
// not authority (callers must still run identity.Registry.Validate).
// It fails closed and returns identity.ErrAuthentication on any validation failure.
func ProjectActor(p identity.PrincipalContext) (Actor, error) {
	if p.Audience() != audienceData {
		return Actor{}, identity.ErrAuthentication
	}
	if p.AuthMethod() != authMethodBearer {
		return Actor{}, identity.ErrAuthentication
	}
	if !validSecurityID(p.TenantID()) || !validSecurityID(p.PrincipalID()) || !validSecurityID(p.CredentialID()) {
		return Actor{}, identity.ErrAuthentication
	}

	rev := p.CredentialRevision()
	if rev == 0 || rev > maxSafeInteger {
		return Actor{}, identity.ErrAuthentication
	}
	epoch := p.RevocationEpoch()
	if epoch > maxSafeInteger {
		return Actor{}, identity.ErrAuthentication
	}

	authAt := p.AuthenticatedAt()
	expAt := p.ExpiresAt()
	if authAt.IsZero() || expAt.IsZero() {
		return Actor{}, identity.ErrAuthentication
	}
	// Defence in depth: identity rejects sub-second credential times at registry load,
	// but ProjectActor independently enforces whole-second precision.
	if authAt.Nanosecond() != 0 || expAt.Nanosecond() != 0 {
		return Actor{}, identity.ErrAuthentication
	}
	if !expAt.After(authAt) {
		return Actor{}, identity.ErrAuthentication
	}
	authTimeStr, err := toSecurityTime(authAt)
	if err != nil {
		return Actor{}, identity.ErrAuthentication
	}
	expTimeStr, err := toSecurityTime(expAt)
	if err != nil {
		return Actor{}, identity.ErrAuthentication
	}

	rawScopes := p.Scopes()
	if len(rawScopes) == 0 || len(rawScopes) > 64 {
		return Actor{}, identity.ErrAuthentication
	}
	for _, sc := range rawScopes {
		if !validSecurityID(sc.Operation) || !validSecurityID(sc.ResourceSet) {
			return Actor{}, identity.ErrAuthentication
		}
	}

	sortedScopes := make([]identity.Scope, len(rawScopes))
	copy(sortedScopes, rawScopes)
	sort.Slice(sortedScopes, func(i, j int) bool {
		if sortedScopes[i].Operation != sortedScopes[j].Operation {
			return sortedScopes[i].Operation < sortedScopes[j].Operation
		}
		return sortedScopes[i].ResourceSet < sortedScopes[j].ResourceSet
	})
	for i := 1; i < len(sortedScopes); i++ {
		if sortedScopes[i].Operation == sortedScopes[i-1].Operation &&
			sortedScopes[i].ResourceSet == sortedScopes[i-1].ResourceSet {
			return Actor{}, identity.ErrAuthentication
		}
	}

	scopesArray := make([]any, len(sortedScopes))
	for i, sc := range sortedScopes {
		scopesArray[i] = obj{
			"operation":    sc.Operation,
			"resource_set": sc.ResourceSet,
		}
	}

	authorityObj := obj{
		"audience":              p.Audience(),
		"auth_method":           p.AuthMethod(),
		"credential_expires_at": expTimeStr,
		"credential_id":         p.CredentialID(),
		"credential_revision":   num(strconv.FormatUint(rev, 10)),
		"principal_id":          p.PrincipalID(),
		"revocation_epoch":      num(strconv.FormatUint(epoch, 10)),
		"schema_version":        authoritySchemaVersion,
		"scopes":                scopesArray,
		"tenant_id":             p.TenantID(),
	}
	authorityCanonical := canonical(authorityObj)

	h := sha256.Sum256(append([]byte(authContextPrefix), authorityCanonical...))
	digest := "sha256:" + hex.EncodeToString(h[:])

	principalContextObj := obj{
		"audience":            p.Audience(),
		"auth_method":         p.AuthMethod(),
		"authenticated_at":    authTimeStr,
		"credential_id":       p.CredentialID(),
		"credential_revision": num(strconv.FormatUint(rev, 10)),
		"principal_id":        p.PrincipalID(),
		"revocation_epoch":    num(strconv.FormatUint(epoch, 10)),
		"scopes":              scopesArray,
		"tenant_id":           p.TenantID(),
	}
	actorObj := obj{
		"auth_context_digest":   digest,
		"credential_expires_at": expTimeStr,
		"principal_context":     principalContextObj,
		"schema_version":        actorSchemaVersion,
	}
	actorCanonical := canonical(actorObj)

	return Actor{
		canonical:          actorCanonical,
		authorityCanonical: authorityCanonical,
		authContextDigest:  digest,
		obj:                actorObj,
	}, nil
}
