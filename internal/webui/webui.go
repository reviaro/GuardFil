// Package webui is GuardFil's owner web UI: it shows calls held for approval
// (Allow / Deny), recent decisions, and the policy in plain terms, and edits
// the policy (add / delete rules, raw YAML, restore an earlier version).  It
// runs inside the guardfil process on a loopback listener and talks to the
// approval service in-process.
package webui

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/content"
	"github.com/reviaro/guardfil/internal/policy"
	"go.yaml.in/yaml/v3"
)

//go:embed web/index.html
var indexHTML []byte

//go:embed web/app.js
var appJS []byte

//go:embed web/app.css
var appCSS []byte

const (
	cspHeader       = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	sessionCookie   = "gf_session"
	sessionHeader   = "X-GuardFil-Session"
	sessionTTL      = 12 * time.Hour
	maxSessions     = 64
	maxBodyBytes    = 1 << 20
	maxLoginFails   = 10
	loginFailWindow = time.Minute
	decisionTail    = 256 << 10
	maxDecisions    = 100
	maxVersionsList = 30
)

// Server is one UI instance.
type Server struct {
	svc          *approval.Service
	store        *approval.PolicyStore
	contentStore *content.ContentStore
	decisionLog  string
	token        []byte
	now          func() time.Time

	mu         sync.Mutex
	sessions   map[string]uiSession
	loginFails []time.Time
	editMu     sync.Mutex
}

type uiSession struct {
	expires time.Time
	proof   string
}

// New builds the UI.  The token is the login secret (read from the configured token file).
func New(svc *approval.Service, store *approval.PolicyStore, decisionLog string, token []byte, contentStore ...*content.ContentStore) (*Server, error) {
	token = bytes.TrimSpace(token)
	if svc == nil || store == nil {
		return nil, errors.New("webui needs the approval service and policy store")
	}
	if len(token) < 16 || len(token) > 4096 {
		return nil, errors.New("ui token must be 16-4096 bytes")
	}
	var cs *content.ContentStore
	if len(contentStore) > 0 {
		cs = contentStore[0]
	}
	return &Server{svc: svc, store: store, contentStore: cs, decisionLog: decisionLog, token: token, now: time.Now,
		sessions: map[string]uiSession{}}, nil
}

// SetContentStore configures the content rules store.
func (s *Server) SetContentStore(cs *content.ContentStore) {
	s.contentStore = cs
}

// Handler is the UI's HTTP handler with all hardening applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static := func(body []byte, ctype string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ctype)
			_, _ = w.Write(body)
		}
	}
	mux.HandleFunc("GET /{$}", static(indexHTML, "text/html; charset=utf-8"))
	mux.HandleFunc("GET /app.js", static(appJS, "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /app.css", static(appCSS, "text/css; charset=utf-8"))
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.authed(s.logout))
	mux.HandleFunc("GET /api/state", s.authed(s.state))
	mux.HandleFunc("POST /api/approvals/{id}", s.authed(s.answer))
	mux.HandleFunc("POST /api/file-grants/{session}/revoke", s.authed(s.revokeFileGrants))
	mux.HandleFunc("POST /api/rules", s.authed(s.rules))
	mux.HandleFunc("POST /api/policy", s.authed(s.savePolicy))
	mux.HandleFunc("POST /api/privacy", s.authed(s.savePrivacy))
	mux.HandleFunc("POST /api/policy/restore", s.authed(s.restore))
	mux.HandleFunc("GET /api/content", s.authed(s.getContent))
	mux.HandleFunc("PUT /api/content", s.authed(s.saveContent))
	mux.HandleFunc("POST /api/content/try", s.authed(s.tryContent))
	mux.HandleFunc("POST /api/content/restore", s.authed(s.restoreContent))
	return harden(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func loopbackHost(h string) bool {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// harden: security headers, loopback Host (DNS rebinding), body limit, and for
// POST: JSON only and a same-origin Origin (or no cross-site fetch).
func harden(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspHeader)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if !loopbackHost(r.Host) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				writeErr(w, http.StatusUnsupportedMediaType, "unsupported media type")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
					writeErr(w, http.StatusForbidden, "forbidden")
					return
				}
			} else if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ---- sessions

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	s.mu.Lock()
	recent := s.loginFails[:0]
	for _, t := range s.loginFails {
		if now.Sub(t) < loginFailWindow {
			recent = append(recent, t)
		}
	}
	s.loginFails = recent
	limited := len(recent) >= maxLoginFails
	s.mu.Unlock()
	if limited {
		writeErr(w, http.StatusTooManyRequests, "too many failed logins; wait a minute")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Token)), s.token) != 1 {
		s.mu.Lock()
		s.loginFails = append(s.loginFails, now)
		s.mu.Unlock()
		writeErr(w, http.StatusUnauthorized, "wrong token")
		return
	}
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		writeErr(w, http.StatusInternalServerError, "no randomness")
		return
	}
	id, proof := hex.EncodeToString(b[:32]), hex.EncodeToString(b[32:])
	s.mu.Lock()
	for k, session := range s.sessions {
		if now.After(session.expires) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= maxSessions {
		s.mu.Unlock()
		writeErr(w, http.StatusServiceUnavailable, "too many sessions")
		return
	}
	s.sessions[id] = uiSession{expires: now.Add(sessionTTL), proof: proof}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	// Cookies are not port-scoped. Keep a second, independent secret in the
	// page's origin-scoped sessionStorage; never deliver it in a cookie.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session_token": proof})
}

func (s *Server) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || len(c.Value) != 64 {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[c.Value]
	if !ok || s.now().After(session.expires) {
		delete(s.sessions, c.Value)
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(sessionHeader)), []byte(session.proof)) != 1 {
		return "", false
	}
	return c.Value, true
}

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		h(w, r)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.session(r); ok {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- state

type stateView struct {
	PolicyDigest    string                       `json:"policy_digest"`
	PolicyVersion   int                          `json:"policy_version"`
	PolicyYAML      string                       `json:"policy_yaml"`
	Rules           []RuleView                   `json:"rules"`
	Principals      []string                     `json:"principals"`
	AskEnabled      bool                         `json:"ask_enabled"`
	Pending         []approval.PendingInfo       `json:"pending"`
	FileGrants      []approval.SessionFileGrants `json:"file_grants"`
	LocalOnlyPaths  []string                     `json:"local_only_paths"`
	PrivateSessions []approval.PrivateSession    `json:"private_sessions"`
	Decisions       []map[string]any             `json:"decisions"`
	Versions        []approval.PolicyVersion     `json:"versions"`
	Tools           []approval.ToolSpec          `json:"tools"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	raw := s.svc.Policy()
	rules, _ := PlainRules(raw)
	doc, _ := parseDoc(raw)
	writeJSON(w, http.StatusOK, stateView{
		PolicyDigest: s.svc.PolicyDigest(), PolicyVersion: s.store.Current(), PolicyYAML: string(raw),
		Rules: rules, Principals: PrincipalsInPolicy(raw), AskEnabled: s.svc.AskEnabled(), Pending: s.svc.Pending(),
		FileGrants:     s.svc.FileGrants(),
		LocalOnlyPaths: doc.LocalOnlyPaths, PrivateSessions: s.svc.PrivateSessions(),
		Decisions: s.recentDecisions(), Versions: s.store.Versions(maxVersionsList),
		Tools: s.svc.Catalog().Tools(),
	})
}

var decisionFields = []string{"time", "principal", "session", "kind", "tool", "paths", "effect", "monitored", "asked", "reasons", "rule_ids", "latency_us",
	"redactions", "content"}

// recentDecisions tails the decision log: newest first, non-secret fields only.
func (s *Server) recentDecisions() []map[string]any {
	out := []map[string]any{}
	f, err := os.Open(s.decisionLog)
	if err != nil {
		return out
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return out
	}
	start := fi.Size() - decisionTail
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return out
	}
	sc := bufio.NewScanner(io.LimitReader(f, decisionTail))
	sc.Buffer(make([]byte, 4096), 256<<10)
	var lines [][]byte
	first := start > 0
	for sc.Scan() {
		if first { // a partial line at the cut
			first = false
			continue
		}
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	for i := len(lines) - 1; i >= 0 && len(out) < maxDecisions; i-- {
		var rec map[string]any
		if json.Unmarshal(lines[i], &rec) != nil {
			continue
		}
		view := map[string]any{}
		for _, k := range decisionFields {
			if v, ok := rec[k]; ok {
				view[k] = v
			}
		}
		out = append(out, view)
	}
	return out
}

// ---- actions

func (s *Server) answer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Decision string `json:"decision"`
		Scope    string `json:"scope,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil || (body.Decision != "allow" && body.Decision != "deny") {
		writeErr(w, http.StatusBadRequest, "decision must be allow or deny")
		return
	}
	if err := s.svc.AnswerWithScope(r.PathValue("id"), body.Decision == "allow", body.Scope); err != nil {
		if errors.Is(err, approval.ErrApprovalScope) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusNotFound, "this call is no longer waiting")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) revokeFileGrants(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.RevokeFileGrants(r.PathValue("session")); err != nil {
		writeErr(w, http.StatusNotFound, "this session has ended")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// apply puts raw in force and records it as a new version.  If recording
// fails the previous policy is put back, so what is enforced is always saved.
func (s *Server) apply(raw []byte, note string) (approval.PolicyVersion, error) {
	prev := s.svc.Policy()
	digest, err := s.svc.SetPolicy(raw)
	if err != nil {
		var amount approval.AmountError
		if errors.As(err, &amount) {
			return approval.PolicyVersion{}, errors.New("the policy is not valid: " + amount.Msg)
		}
		return approval.PolicyVersion{}, errors.New("the policy is not valid: GuardFil's policy compiler rejected it")
	}
	v, err := s.store.Save(raw, digest, note)
	if err != nil {
		_, _ = s.svc.SetPolicy(prev)
		return approval.PolicyVersion{}, errors.New("could not save the policy version: " + err.Error())
	}
	return v, nil
}

func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	var req RuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s.editMu.Lock()
	defer s.editMu.Unlock()
	raw, note, err := EditRules(s.svc.Policy(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := s.apply(raw, note)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) savePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML string `json:"yaml"`
		Note string `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s.editMu.Lock()
	defer s.editMu.Unlock()
	note := strings.TrimSpace(body.Note)
	if note == "" {
		note = "edited the policy YAML"
	}
	v, err := s.apply([]byte(body.YAML), note)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) savePrivacy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Paths []string `json:"paths"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Paths == nil {
		writeErr(w, http.StatusBadRequest, "Supply a list of local-only paths; use an empty list to clear it.")
		return
	}
	s.editMu.Lock()
	defer s.editMu.Unlock()
	doc, err := parseDoc(s.svc.Policy())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	doc.LocalOnlyPaths = body.Paths
	doc.Revision++
	raw, err := yaml.Marshal(doc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := policy.Compile(raw); err != nil {
		writeErr(w, http.StatusBadRequest, "Use up to 256 absolute paths or path patterns, such as /workspace/private/**. Do not use .. in a path.")
		return
	}
	v, err := s.apply(raw, "updated local-only file paths")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version int `json:"version"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s.editMu.Lock()
	defer s.editMu.Unlock()
	raw, err := s.store.Load(body.Version)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown version")
		return
	}
	label := "the policy file"
	if body.Version > 0 {
		label = "version " + strconv.Itoa(body.Version)
	}
	v, err := s.apply(raw, "restored "+label)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ---- content rules

type contentView struct {
	Rules    *content.Rules           `json:"rules"`
	Version  int                      `json:"version"`
	Versions []content.ContentVersion `json:"versions"`
	Digest   string                   `json:"digest"`
}

func (s *Server) getContent(w http.ResponseWriter, r *http.Request) {
	rules := s.svc.ContentRules()
	if rules == nil {
		rules = &content.Rules{SchemaVersion: content.CurrentSchemaVersion}
	}
	var versions []content.ContentVersion
	var curVersion int
	if s.contentStore != nil {
		versions = s.contentStore.Versions(maxVersionsList)
		curVersion = s.contentStore.Current()
	}
	writeJSON(w, http.StatusOK, contentView{
		Rules:    rules,
		Version:  curVersion,
		Versions: versions,
		Digest:   rules.Digest(),
	})
}

func (s *Server) saveContent(w http.ResponseWriter, r *http.Request) {
	s.editMu.Lock()
	defer s.editMu.Unlock()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}

	var wrapper struct {
		Rules json.RawMessage `json:"rules"`
		Note  string          `json:"note"`
	}
	var rawRules []byte
	note := ""
	if err := json.Unmarshal(bodyBytes, &wrapper); err == nil && len(wrapper.Rules) > 0 {
		rawRules = wrapper.Rules
		note = strings.TrimSpace(wrapper.Note)
	} else {
		rawRules = bodyBytes
	}
	if note == "" {
		note = "edited content rules"
	}

	parsed, err := content.ParseRules(rawRules)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "content rules invalid: "+err.Error())
		return
	}

	canonicalJSON, err := json.Marshal(parsed)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "content rules encoding error: "+err.Error())
		return
	}

	// Saved first, then put in force: a failed save leaves the rules in force unchanged.
	if s.contentStore != nil {
		v, err := s.contentStore.Save(canonicalJSON, parsed.Digest(), note)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not save content rules version: "+err.Error())
			return
		}
		s.svc.SetContentRules(parsed)
		writeJSON(w, http.StatusOK, v)
		return
	}

	s.svc.SetContentRules(parsed)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "digest": parsed.Digest()})
}

func (s *Server) tryContent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tool      string `json:"tool"`
		Direction string `json:"direction"`
		Text      string `json:"text"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	tool := body.Tool
	if tool == "" {
		tool = "*"
	}
	dir := content.Direction(body.Direction)
	if dir == "" {
		dir = content.DirectionResponse
	}
	rules := s.svc.ContentRules()
	if rules == nil {
		rules = &content.Rules{SchemaVersion: content.CurrentSchemaVersion}
	}
	outcome := rules.Scan(tool, dir, body.Text)
	writeJSON(w, http.StatusOK, outcome)
}

func (s *Server) restoreContent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version int `json:"version"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if s.contentStore == nil {
		writeErr(w, http.StatusNotFound, "content store unavailable")
		return
	}
	s.editMu.Lock()
	defer s.editMu.Unlock()
	raw, err := s.contentStore.Load(body.Version)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown content version")
		return
	}
	parsed, err := content.ParseRules(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid content rules in version: "+err.Error())
		return
	}
	label := "base rules"
	if body.Version > 0 {
		label = fmt.Sprintf("version %d", body.Version)
	}
	v, err := s.contentStore.Save(raw, parsed.Digest(), "restored "+label)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.svc.SetContentRules(parsed)
	writeJSON(w, http.StatusOK, v)
}
