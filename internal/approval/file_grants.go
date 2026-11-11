package approval

import (
	"context"
	"errors"
	"sort"
	"sync"
)

const MaxSessionFileGrants = 4096

var ErrApprovalScope = errors.New("session approval is available only for file access in an active session")

type sessionAccessKey struct{}
type fileGrant struct{ kind, path string }

// A session's identity comes from its owner-created socket, never request JSON.
// Grants cover exact paths and one operation only. Policy/content/catalog edits
// invalidate the epoch; a grant cannot override a newly evaluated deny.
type sessionAccess struct {
	id             string
	mediated       bool
	mu             sync.Mutex
	epoch          <-chan struct{}
	grants         map[fileGrant]bool
	changed        chan struct{}
	localOnly      bool
	hasRead        bool
	privacyVersion string
	scope          *WorkspaceScope
}

func newSessionAccess(id string) *sessionAccess {
	return &sessionAccess{id: id, grants: map[fileGrant]bool{}, changed: make(chan struct{})}
}

func accessFor(ctx context.Context) *sessionAccess {
	a, _ := ctx.Value(sessionAccessKey{}).(*sessionAccess)
	return a
}

func (a *sessionAccess) matchesLocked(kind string, paths []string) bool {
	if len(paths) == 0 || (kind != "file_read" && kind != "file_write") {
		return false
	}
	for _, p := range paths {
		if !a.grants[fileGrant{kind, p}] {
			return false
		}
	}
	return true
}

func (a *sessionAccess) check(epoch <-chan struct{}, kind string, paths []string) (bool, <-chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-epoch:
		return false, a.changed
	default:
	}
	if a.epoch != epoch {
		a.grants = map[fileGrant]bool{}
		a.epoch = epoch
	}
	return a.matchesLocked(kind, paths), a.changed
}

func (a *sessionAccess) grant(epoch <-chan struct{}, kind string, paths []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-epoch:
		return ErrUnknownApproval
	default:
	}
	if a.epoch != epoch {
		a.grants = map[fileGrant]bool{}
		a.epoch = epoch
	}
	if len(a.grants)+len(paths) > MaxSessionFileGrants {
		return errors.New("session file approval limit reached")
	}
	for _, p := range paths {
		a.grants[fileGrant{kind, p}] = true
	}
	close(a.changed)
	a.changed = make(chan struct{})
	return nil
}

func (a *sessionAccess) revoke() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants = map[fileGrant]bool{}
	close(a.changed)
	a.changed = make(chan struct{})
}

type SessionFileGrants struct {
	Session   string `json:"session"`
	Principal string `json:"principal"`
	Reads     int    `json:"reads"`
	Writes    int    `json:"writes"`
}

// FileGrants exposes bounded session summaries to the owner for revocation.
func (s *Service) FileGrants() []SessionFileGrants {
	epoch := s.ruleEpoch()
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	result := []SessionFileGrants{}
	for id, sess := range s.sessions {
		info := SessionFileGrants{Session: id, Principal: sess.principal}
		sess.access.mu.Lock()
		if sess.access.epoch == epoch {
			for grant := range sess.access.grants {
				if grant.kind == "file_read" {
					info.Reads++
				} else {
					info.Writes++
				}
			}
		}
		sess.access.mu.Unlock()
		if info.Reads+info.Writes > 0 {
			result = append(result, info)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Session < result[j].Session })
	return result
}

func (s *Service) RevokeFileGrants(session string) error {
	s.sessionMu.Lock()
	sess := s.sessions[session]
	s.sessionMu.Unlock()
	if sess == nil {
		return errUnknownSession
	}
	sess.access.revoke()
	return nil
}
