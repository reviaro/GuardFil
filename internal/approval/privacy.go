package approval

import (
	"context"
	"errors"
	"sort"

	"github.com/reviaro/guardfil/internal/policy"
)

var ErrLocalOnly = errors.New("LOCAL_ONLY_SESSION: this session accessed local-only files; cloud requests are blocked")

// refreshPrivacyLocked covers rule changes after a file was read. Grants can
// be cleared, but knowledge cannot: session privacy never resets to public.
func (a *sessionAccess) refreshPrivacyLocked(snapshot policy.Snapshot) {
	if a.localOnly {
		return
	}
	version := snapshot.PrivacyVersion()
	// Names may have changed since access. Conservatively stop cloud use for
	// sessions that already read files when classification changes, instead
	// of mistaking a renamed file for previously unseen data.
	if a.hasRead && version != "" && a.privacyVersion != version {
		a.localOnly = true
	}
	a.privacyVersion = version
}

func (s *Service) privacyDecision(ctx context.Context, raw, pol []byte, target string, out Output) Output {
	if out.Effect != "ALLOW" {
		return out
	}
	in, err := parseStdinRequest(raw)
	if err != nil {
		return BlockedOutput("PRIVACY_REQUEST_INVALID", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	snapshot, err := policy.Compile(pol)
	if err != nil {
		return BlockedOutput("POLICY_UNAVAILABLE", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	a := accessFor(ctx)
	if a == nil {
		for _, p := range in.ReadPaths {
			if snapshot.LocalOnly(p) {
				return BlockedOutput("LOCAL_ONLY_REQUIRES_SESSION", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
			}
		}
		return out
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshPrivacyLocked(snapshot)
	for _, p := range in.ReadPaths {
		a.hasRead = true
		if s.localOnly(snapshot, a.scope, p) {
			a.localOnly = true
		}
	}
	if !a.localOnly {
		return out
	}
	// A private session may continue local computation, but its outputs must
	// stay in paths classified local-only for all sessions. This closes the
	// copy/encode -> shared public file -> second cloud session route without
	// relying on content matching or an agent-supplied disclosure flag.
	for _, p := range in.WritePaths {
		if !s.localOnly(snapshot, a.scope, p) {
			return BlockedOutput("LOCAL_ONLY_OUTPUT_REQUIRED", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
		}
	}
	local := in.Shell || len(in.ReadPaths) > 0 || len(in.WritePaths) > 0 || (a.mediated && !in.CanFilter && mediatedReadRequest(raw))
	if target != "" || !local {
		return BlockedOutput("LOCAL_ONLY_EGRESS_BLOCKED", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	return out
}

// CheckCloudSession is used by host brokers through the owner socket. Missing
// or ended sessions fail closed. The agent has no API that clears this state.
func (s *Service) CheckCloudSession(id string) error {
	snapshot, err := policy.Compile(s.Policy())
	if err != nil {
		return err
	}
	s.sessionMu.Lock()
	sess := s.sessions[id]
	s.sessionMu.Unlock()
	if sess == nil {
		return errUnknownSession
	}
	sess.access.mu.Lock()
	defer sess.access.mu.Unlock()
	sess.access.refreshPrivacyLocked(snapshot)
	if sess.access.localOnly {
		return ErrLocalOnly
	}
	if snapshot.PrivacyVersion() != "" && sess.access.scope == nil {
		return errors.New("local-only rules require a session bound to its host workspace")
	}
	return nil
}

type PrivateSession struct {
	Session   string `json:"session"`
	Principal string `json:"principal"`
}

func (s *Service) PrivateSessions() []PrivateSession {
	snapshot, err := policy.Compile(s.Policy())
	if err != nil {
		return nil
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	result := []PrivateSession{}
	for id, sess := range s.sessions {
		sess.access.mu.Lock()
		sess.access.refreshPrivacyLocked(snapshot)
		if sess.access.localOnly {
			result = append(result, PrivateSession{id, sess.principal})
		}
		sess.access.mu.Unlock()
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Session < result[j].Session })
	return result
}
