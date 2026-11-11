package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// "Ask me": a call whose only obstacle is a require_approval rule is held until
// the owner answers.  Allow → ALLOW (APPROVAL_GRANTED); deny → BLOCK
// (APPROVAL_REJECTED); no answer before the timeout → BLOCK (APPROVAL_EXPIRED).
// With asking disabled (headless) the kernel's BLOCK APPROVAL_UNAVAILABLE stands.

const (
	ReasonApprovalNeeded   = "APPROVAL_UNAVAILABLE"
	ReasonApprovalGranted  = "APPROVAL_GRANTED"
	ReasonApprovalRejected = "APPROVAL_REJECTED"
	ReasonApprovalExpired  = "APPROVAL_EXPIRED"
	// MaxPending bounds calls held at once; further askable calls are BLOCKed.
	MaxPending = 32
	// One principal cannot occupy the shared approval queue.
	MaxPendingPerPrincipal = 8
	// MaxAskTimeout caps how long one call may be held.
	MaxAskTimeout = 10 * time.Minute
)

var (
	ErrUnknownApproval = errors.New("unknown or already answered approval")
	errAskDisabled     = errors.New("asking disabled")
)

// PendingInfo is what the owner sees for a held call.  Detail (the shell command
// or the tool arguments) exists only in memory while the call is held, so the
// owner can judge it; it never reaches the decision log.
type PendingInfo struct {
	rulesChanged  <-chan struct{} // snapshot invalidated while the call is held
	session       *sessionAccess
	grantPaths    []string
	Session       string   `json:"session,omitempty"`
	SessionGrant  bool     `json:"session_grant,omitempty"`
	ID            string   `json:"id"`
	Principal     string   `json:"principal"`
	Kind          string   `json:"kind"`
	Tool          string   `json:"tool,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	RuleIDs       []string `json:"rule_ids"`
	RequestSHA256 string   `json:"request_sha256"`
	Since         string   `json:"since"`
	ExpiresAt     string   `json:"expires_at"`
}

type pending struct {
	info     PendingInfo
	answer   chan bool
	ctx      context.Context
	deadline time.Time
}

type asker struct {
	timeout   time.Duration
	mu        sync.Mutex
	held      map[string]*pending
	closed    chan struct{}
	closeOnce sync.Once
}

// EnableAsk turns on "ask me" with the given hold timeout (1 s .. MaxAskTimeout).
func (s *Service) EnableAsk(timeout time.Duration) error {
	if timeout < time.Second || timeout > MaxAskTimeout {
		return errors.New("ask timeout out of range")
	}
	s.ask = &asker{timeout: timeout, held: map[string]*pending{}, closed: make(chan struct{})}
	return nil
}

// Close expires every held call (BLOCK, APPROVAL_EXPIRED) and every later one
// immediately, and closes all active agent sessions. Used at shutdown so held
// calls never delay it.
func (s *Service) Close() {
	if s.ask != nil {
		s.ask.closeOnce.Do(func() { close(s.ask.closed) })
	}
	s.closeSessions()
}

// AskEnabled reports whether calls needing approval are held for an answer.
func (s *Service) AskEnabled() bool { return s.ask != nil }

// askable: BLOCKed only because approval is required (every reason is the
// approval obligation, or a grant for another path of the same write).
func askable(out Output) bool {
	if out.Effect != "BLOCK" {
		return false
	}
	needs := false
	for _, r := range out.Reasons {
		switch r {
		case ReasonApprovalNeeded:
			needs = true
		case "POLICY_ALLOWED", MonitoredReason:
		default:
			return false
		}
	}
	return needs
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hold returns ALLOW only after an explicit answer for a fully reviewable call.
func (s *Service) hold(ctx context.Context, out Output, info PendingInfo) (Output, string) {
	allow, status := s.waitApproval(ctx, info)
	reason := ReasonApprovalExpired
	if allow {
		reason = ReasonApprovalGranted
	} else if status == "denied" {
		reason = ReasonApprovalRejected
	} else if status == "detail_too_large" {
		reason = "APPROVAL_DETAIL_TOO_LARGE"
	} else if status == "rules_changed" {
		reason = "POLICY_CHANGED"
	} else if status == "too_many_pending" || status == "principal_limit" || status == "headless" || status == "error" {
		reason = ReasonApprovalNeeded
	}
	effect := "BLOCK"
	if allow {
		effect = "ALLOW"
	}
	result := Output{Effect: effect, Reasons: []string{reason}, RuleIDs: out.RuleIDs, PolicyDigest: out.PolicyDigest, ActionDigest: out.ActionDigest}
	if allow {
		result.Filter = out.Filter
	}
	return result, status
}

func (s *Service) holdResult(ctx context.Context, info PendingInfo) (bool, string) {
	return s.waitApproval(ctx, info)
}

func (s *Service) waitApproval(ctx context.Context, info PendingInfo) (bool, string) {
	if s.ask == nil {
		return false, "headless"
	}
	info.Detail = visiblePreview(info.Detail)
	info.Paths = append([]string(nil), info.Paths...)
	size := len([]rune(info.Detail))
	for i, path := range info.Paths {
		info.Paths[i] = visiblePreview(path)
		size += len([]rune(info.Paths[i]))
	}
	if size > MaxDetailRunes {
		return false, "detail_too_large"
	}
	if ctx.Err() != nil {
		return false, "cancelled"
	}
	var grantsChanged <-chan struct{}
	if info.SessionGrant {
		var granted bool
		granted, grantsChanged = info.session.check(info.rulesChanged, info.Kind, info.grantPaths)
		if granted {
			select {
			case <-info.rulesChanged:
				return false, "rules_changed"
			case <-ctx.Done():
				return false, "cancelled"
			case <-s.ask.closed:
				return false, "expired"
			default:
			}
			return true, "session_grant"
		}
	}
	a := s.ask
	id, err := newID()
	if err != nil {
		return false, "error"
	}
	if info.Principal == "" {
		info.Principal = syntheticPrinc
	}
	now := s.now()
	info.ID, info.Since, info.ExpiresAt = id, now.UTC().Format(time.RFC3339Nano), now.Add(a.timeout).UTC().Format(time.RFC3339Nano)
	p := &pending{info: info, answer: make(chan bool, 1), ctx: ctx, deadline: now.Add(a.timeout)}
	a.mu.Lock()
	select {
	case <-a.closed:
		a.mu.Unlock()
		return false, "expired"
	default:
	}
	if len(a.held) >= MaxPending {
		a.mu.Unlock()
		return false, "too_many_pending"
	}
	count := 0
	for _, held := range a.held {
		if held.info.Principal == info.Principal {
			count++
		}
	}
	if count >= MaxPendingPerPrincipal {
		a.mu.Unlock()
		return false, "principal_limit"
	}
	a.held[id] = p
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.held, id); a.mu.Unlock() }()
	timer := time.NewTimer(a.timeout)
	defer timer.Stop()
	var allow bool
	waiting := true
	for waiting {
		select {
		case allow = <-p.answer:
			waiting = false
		case <-grantsChanged:
			allow, grantsChanged = info.session.check(info.rulesChanged, info.Kind, info.grantPaths)
			if allow {
				waiting = false
			}
		case <-info.rulesChanged:
			return false, "rules_changed"
		case <-ctx.Done():
			return false, "cancelled"
		case <-a.closed:
			return false, "expired"
		case <-timer.C:
			return false, "expired"
		}
	}
	// A direct answer wins over a grant notification for a concurrently held
	// call. Remove it under the same mutex used by Answer before returning, so
	// a successful owner denial cannot race with a reusable grant.
	a.mu.Lock()
	select {
	case answered := <-p.answer:
		allow = answered
	default:
	}
	delete(a.held, id)
	a.mu.Unlock()
	// Cancellation/revocation wins even if an answer was queued concurrently.
	if ctx.Err() != nil {
		return false, "cancelled"
	}
	select {
	case <-info.rulesChanged:
		return false, "rules_changed"
	default:
	}
	select {
	case <-a.closed:
		return false, "expired"
	default:
	}
	if allow {
		return true, "allowed"
	}
	return false, "denied"
}

// visiblePreview makes terminal controls, bidi formatting and invisible text
// explicit in every approval client, including the CLI. Escape literal
// backslashes too so a typed escape cannot impersonate an actual control.
func visiblePreview(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case !unicode.IsGraphic(r) || r == '\u034f' || (r >= '\ufe00' && r <= '\ufe0f') ||
			(r >= 0xe0100 && r <= 0xe01ef) || (unicode.IsSpace(r) && r != ' '):
			if r <= 0xffff {
				b.WriteString(`\u`)
				for shift := 12; shift >= 0; shift -= 4 {
					b.WriteByte("0123456789abcdef"[(r>>shift)&15])
				}
			} else {
				b.WriteString(`\U`)
				for shift := 28; shift >= 0; shift -= 4 {
					b.WriteByte("0123456789abcdef"[(r>>shift)&15])
				}
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Pending lists held calls, oldest first.
func (s *Service) Pending() []PendingInfo {
	if s.ask == nil {
		return []PendingInfo{}
	}
	s.ask.mu.Lock()
	out := make([]PendingInfo, 0, len(s.ask.held))
	for _, p := range s.ask.held {
		out = append(out, p.info)
	}
	s.ask.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Since < out[j].Since })
	return out
}

// Answer resolves one held call.  Each call can be answered once.
func (s *Service) Answer(id string, allow bool) error {
	return s.AnswerWithScope(id, allow, "once")
}

// AnswerWithScope is owner-only. A session grant never changes policy and is
// unavailable for commands, content approvals or calls on the shared socket.
func (s *Service) AnswerWithScope(id string, allow bool, scope string) error {
	if scope == "" {
		scope = "once"
	}
	if scope != "once" && (scope != "session" || !allow) {
		return ErrApprovalScope
	}
	if s.ask == nil {
		return errAskDisabled
	}
	s.ask.mu.Lock()
	defer s.ask.mu.Unlock()
	p, ok := s.ask.held[id]
	if !ok || p.ctx.Err() != nil || !s.now().Before(p.deadline) {
		delete(s.ask.held, id)
		return ErrUnknownApproval
	}
	select {
	case <-p.info.rulesChanged:
		return ErrUnknownApproval
	default:
	}
	if scope == "session" {
		if !p.info.SessionGrant || p.info.session == nil {
			return ErrApprovalScope
		}
		if err := p.info.session.grant(p.info.rulesChanged, p.info.Kind, p.info.grantPaths); err != nil {
			return err
		}
	}
	delete(s.ask.held, id) // answered once
	p.answer <- allow      // buffered (cap 1): never blocks
	return nil
}

// ApproverHandler is the owner's HTTP API for held calls:
//
//	GET  /v1/approvals            → JSON list of PendingInfo
//	POST /v1/approvals/{id}       body {"decision":"allow"|"deny"} → 204, 404 unknown/answered, 400 bad body
//
// It is served on the owner-only approver socket; access to that socket is the authority.
func (s *Service) ApproverHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Pending())
	})
	mux.HandleFunc("POST /v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if len(id) != 24 || strings.Trim(id, "0123456789abcdef") != "" {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		var body struct {
			Decision string `json:"decision"`
			Scope    string `json:"scope,omitempty"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil || (body.Decision != "allow" && body.Decision != "deny") {
			http.Error(w, "body must be {\"decision\":\"allow\"|\"deny\"}", http.StatusBadRequest)
			return
		}
		if err := s.AnswerWithScope(id, body.Decision == "allow", body.Scope); err != nil {
			status := http.StatusNotFound
			if errors.Is(err, ErrApprovalScope) {
				status = http.StatusBadRequest
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Agent             string          `json:"agent"`
			Default           bool            `json:"default,omitempty"`
			WorkspaceMediated bool            `json:"workspace_mediated,omitempty"`
			Workspace         *WorkspaceScope `json:"workspace,omitempty"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if (!body.Default && !ValidAgentName(body.Agent)) || (body.Default && body.Agent != "") {
			http.Error(w, "bad agent name", http.StatusBadRequest)
			return
		}
		info, err := s.createWorkspaceSession(body.Agent, body.WorkspaceMediated, body.Workspace)
		if err != nil {
			if errors.Is(err, errTooManySessions) {
				http.Error(w, "too many sessions", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(info)
	})
	mux.HandleFunc("DELETE /sessions/{session}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("session")
		if err := s.deleteSession(id); err != nil {
			if errors.Is(err, errUnknownSession) {
				http.Error(w, "unknown session", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /sessions/{session}/file-grants", func(w http.ResponseWriter, r *http.Request) {
		if err := s.RevokeFileGrants(r.PathValue("session")); err != nil {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/file-grants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.FileGrants())
	})
	mux.HandleFunc("GET /sessions/{session}/cloud", func(w http.ResponseWriter, r *http.Request) {
		if err := s.CheckCloudSession(r.PathValue("session")); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
