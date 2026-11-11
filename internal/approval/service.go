package approval

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/reviaro/guardfil/internal/content"
	"github.com/reviaro/guardfil/internal/filter"
	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/textview"
)

const (
	// RequestTimeout bounds reading one request and writing its verdict.
	RequestTimeout = 2 * time.Second
	// MaxConcurrent bounds connections decided at once; further accepts wait.
	MaxConcurrent = 16
)

// ContentMatch records a content rule match in the decision log without matched text.
type ContentMatch struct {
	List     string `json:"list"`
	Category string `json:"category,omitempty"` // injection only
	Count    int    `json:"count"`
	Action   string `json:"action"`
}

// LogEntry is one line of the decision log.  It never holds command text or
// tool arguments: shell commands and arguments are represented by the request hash.
type LogEntry struct {
	Time          string         `json:"time"`
	Principal     string         `json:"principal"`
	Session       string         `json:"session,omitempty"`
	Kind          string         `json:"kind"`
	Tool          string         `json:"tool,omitempty"`
	Paths         []string       `json:"paths,omitempty"`
	RequestSHA256 string         `json:"request_sha256"`
	Effect        string         `json:"effect"`
	Monitored     bool           `json:"monitored,omitempty"`
	Asked         string         `json:"asked,omitempty"` // allowed | denied | expired | too_many_pending
	Reasons       []string       `json:"reasons"`
	RuleIDs       []string       `json:"rule_ids"`
	PolicyDigest  string         `json:"policy_digest"`
	ActionDigest  string         `json:"action_digest"`
	LatencyMicros int64          `json:"latency_us"`
	Redactions    int            `json:"redactions,omitempty"`
	Content       []ContentMatch `json:"content,omitempty"`
}

var filterToolID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_/.-]{1,128}$`)

// parseFilterRequest recognizes {"kind":"filter","tool":"app.tool","content":"..."}.
// tool is "!" when the request names kind "filter" but is malformed.
func parseFilterRequest(raw []byte) (content, tool string, ok bool) {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || string(top["kind"]) != `"filter"` {
		return "", "", false
	}
	var r struct {
		Kind    string `json:"kind"`
		Tool    string `json:"tool"`
		Content string `json:"content"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(top) != 3 || d.Decode(&r) != nil || !filterToolID.MatchString(r.Tool) {
		return "", "!", false
	}
	return r.Content, r.Tool, true
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// decodeJSONDocument parses text as one JSON document (numbers kept exact).
func decodeJSONDocument(text string) (any, bool) {
	if !json.Valid([]byte(text)) {
		return nil, false
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

func encodeJSONDocument(v any) (string, bool) {
	var out strings.Builder
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return "", false
	}
	return strings.TrimSuffix(out.String(), "\n"), true
}

// normalizeResultJSON decodes and re-encodes valid JSON (escapes resolved,
// numbers exact); other text is returned unchanged.
func normalizeResultJSON(text string) string {
	v, ok := decodeJSONDocument(text)
	if !ok {
		return text
	}
	out, ok := encodeJSONDocument(v)
	if !ok {
		return text
	}
	return out
}

// mapJSONStrings returns v with every string (object keys and values) replaced
// by f(string). JSON is filtered string by string, never as encoded text: in
// encoded JSON a newline is the two characters backslash-n, so a secret or a
// listed word right after it has no word boundary, and escapes such as \u0050
// could hide a word. Each string is scanned exactly as the reader will see it.
func mapJSONStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = mapJSONStrings(e, f)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[f(k)] = mapJSONStrings(e, f)
		}
		return out
	default:
		return v
	}
}

// Filter removes secrets from a tool result or API response, then runs
// response content rules and injection scanning.
func (s *Service) Filter(tool, text string, principal ...string) filter.Result {
	return s.FilterContext(context.Background(), tool, text, principal...)
}

func (s *Service) FilterContext(ctx context.Context, tool, text string, principal ...string) filter.Result {
	epoch := s.ruleEpoch()
	princ := syntheticPrinc
	if len(principal) > 0 && principal[0] != "" {
		princ = principal[0]
	}
	start := s.now()
	cr := s.ContentRules()
	res, outcome, text := scanResult(cr, tool, text)
	sum := sha256.Sum256([]byte(text))
	var contentMatches []ContentMatch
	asked := ""

	if cr != nil {
		var listIDs []string
		for _, m := range outcome.Matches {
			contentMatches = append(contentMatches, ContentMatch{
				List:     m.List,
				Category: m.Category,
				Count:    m.Count,
				Action:   m.Action,
			})
			listIDs = append(listIDs, m.List)
		}
		uniqueLists := dedupeStrings(listIDs)
		idsStr := strings.Join(uniqueLists, ", ")

		switch outcome.Action {
		case content.ActionFilter:
			res.Text = outcome.Text
		case content.ActionBlock:
			res.Text = "GuardFil withheld this result: " + idsStr
			res.Blocked = true
		case content.ActionAsk:
			detail := text
			var askRuleIDs []string
			for _, l := range uniqueLists {
				askRuleIDs = append(askRuleIDs, "content:"+l)
			}
			allowed, askStatus := s.holdResult(ctx, PendingInfo{
				rulesChanged:  epoch,
				Kind:          "result",
				Principal:     princ,
				Tool:          tool,
				Detail:        detail,
				RuleIDs:       askRuleIDs,
				RequestSHA256: hex.EncodeToString(sum[:]),
			})
			asked = askStatus
			if allowed {
				if outcome.Text != "" {
					res.Text = outcome.Text
				}
			} else {
				res.Text = "GuardFil withheld this result: " + idsStr
				res.Blocked = true
			}
		}
	}
	if !s.rulesCurrent(epoch) {
		res = withheldResult()
		asked = "rules_changed"
	}

	effect := "FILTERED"
	if res.Blocked {
		effect = "BLOCKED"
	}
	entry := LogEntry{
		Time:          start.UTC().Format(time.RFC3339Nano),
		Principal:     princ,
		Kind:          "filter",
		Tool:          tool,
		RequestSHA256: hex.EncodeToString(sum[:]),
		Effect:        effect,
		Reasons:       []string{},
		RuleIDs:       []string{},
		PolicyDigest:  s.PolicyDigest(),
		ActionDigest:  "-",
		Redactions:    res.Redactions,
		Content:       contentMatches,
		Asked:         asked,
		LatencyMicros: s.now().Sub(start).Microseconds(),
	}
	line, err := json.Marshal(entry)
	if err == nil {
		line = append(line, '\n')
		s.logMu.Lock()
		var n int
		n, err = s.log.Write(line)
		s.logMu.Unlock()
		if n != len(line) && err == nil {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		return withheldResult()
	}
	return res
}

// scanResult redacts secrets and runs the response content rules (and the
// injection scan) over text. A JSON document is scanned string by string (see
// mapJSONStrings); the matches are merged and the strongest action wins. It
// returns the redacted result, the content outcome (whose Text is the redacted
// and content-filtered document) and the text as the owner should see it
// (decoded JSON re-encoded, or the original text).
func scanResult(cr *content.Rules, tool, text string) (filter.Result, content.Outcome, string) {
	res, outcome, preview := scanResultDocument(cr, tool, text)
	// Keep the existing safe JSON rewrite. Then inspect alternate decoded
	// representations of what would actually leave the filter. A match whose
	// source span cannot be safely rewritten withholds the whole result.
	views, complete := textview.Views(outcome.Text, false)
	if !complete {
		return withheldResult(), content.Outcome{Action: content.ActionBlock}, preview
	}
	for _, view := range views[1:] {
		r, o, _ := scanResultDocument(cr, tool, view)
		outcome.Matches = append(outcome.Matches, o.Matches...)
		if r.Redactions > 0 || o.Action == content.ActionBlock || o.Action == content.ActionFilter || o.Action == content.ActionAsk {
			return withheldResult(), content.Outcome{Action: content.ActionBlock, Matches: outcome.Matches}, preview
		}
		outcome.Action = content.MaxAction(outcome.Action, o.Action)
	}
	return res, outcome, preview
}

func scanResultDocument(cr *content.Rules, tool, text string) (filter.Result, content.Outcome, string) {
	v, isJSON := decodeJSONDocument(text)
	if !isJSON {
		res := filter.Redact(text)
		outcome := content.Outcome{Action: content.ActionNone, Text: res.Text}
		if cr != nil {
			outcome = cr.Scan(tool, content.DirectionResponse, res.Text)
		}
		return res, outcome, text
	}
	res := filter.Result{Kinds: map[string]int{}}
	strongest := content.ActionNone
	type key struct{ list, category, action string }
	counts := map[key]int{}
	var order []key
	add := func(r filter.Result) {
		res.Redactions += r.Redactions
		for k, n := range r.Kinds {
			res.Kinds[k] += n
		}
	}
	perString := mapJSONStrings(v, func(str string) string {
		r := filter.Redact(str)
		add(r)
		return r.Text
	})
	// A second pass over the encoded document catches secrets known by their
	// field name ("password": "..."), which need the key and value together.
	// Its replacements stay inside string values, so the JSON stays valid.
	enc, ok := encodeJSONDocument(perString)
	if !ok {
		return withheldResult(), content.Outcome{Action: content.ActionNone}, text
	}
	fieldPass := filter.Redact(enc)
	add(fieldPass)
	redacted, ok := decodeJSONDocument(fieldPass.Text)
	if !ok {
		return withheldResult(), content.Outcome{Action: content.ActionNone}, text
	}
	filtered := mapJSONStrings(redacted, func(str string) string {
		if cr == nil {
			return str
		}
		o := cr.Scan(tool, content.DirectionResponse, str)
		strongest = content.MaxAction(strongest, o.Action)
		for _, m := range o.Matches {
			k := key{m.List, m.Category, m.Action}
			if _, seen := counts[k]; !seen {
				order = append(order, k)
			}
			counts[k] += m.Count
		}
		return o.Text
	})
	if len(res.Kinds) == 0 {
		res.Kinds = nil
	}
	plain, ok1 := encodeJSONDocument(v)
	redactedText, ok2 := encodeJSONDocument(redacted)
	filteredText, ok3 := encodeJSONDocument(filtered)
	if !ok1 || !ok2 || !ok3 {
		// Cannot re-encode: withhold rather than pass anything unscanned.
		return withheldResult(), content.Outcome{Action: content.ActionNone}, text
	}
	res.Text = redactedText
	outcome := content.Outcome{Action: strongest, Text: filteredText}
	for _, k := range order {
		outcome.Matches = append(outcome.Matches, content.Match{List: k.list, Category: k.category, Action: k.action, Count: counts[k]})
	}
	return res, outcome, plain
}

func withheldResult() filter.Result {
	return filter.Result{Text: "GuardFil withheld this result: it could not be filtered", Blocked: true}
}

// Describe classifies a request for the decision log without exposing its payload.
func Describe(raw []byte) (kind, tool string, paths []string) {
	in, err := parseStdinRequest(raw)
	switch {
	case err != nil:
		return "invalid", "", nil
	case in.WritePaths != nil:
		return "file_write", "", in.WritePaths
	case in.ReadPaths != nil:
		return "file_read", "", in.ReadPaths
	case in.Shell:
		return "shell", shellToolID, nil
	default:
		return "mcp", in.Server + "." + in.Tool, nil
	}
}

// SetCatalog installs the application tool catalog (nil: none).  It is refused
// if the policy in force has an amount condition the catalog cannot back.
func (s *Service) SetCatalog(c *Catalog) error {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	snap, err := policy.Compile(s.policy)
	if err != nil {
		return fmt.Errorf("approval policy: %w", err)
	}
	if err := CheckAmountFields(snap, c); err != nil {
		return err
	}
	s.catalog = c
	s.invalidateRules()
	return nil
}

// AmountError is a policy amount condition the tool catalog cannot back.  Its
// message is safe to show the owner.
type AmountError struct{ Msg string }

func (e AmountError) Error() string { return e.Msg }

// CheckAmountFields checks that every amount condition names tools in the
// catalog and numeric (integer or decimal) arguments of each.
func CheckAmountFields(snap policy.Snapshot, c *Catalog) error {
	for _, f := range snap.DecimalFields() {
		if !c.Has(f.Tool) {
			return AmountError{fmt.Sprintf("rule %s: an amount condition needs %s in the tool catalog", f.Rule, f.Tool)}
		}
		a, ok := c.tools[f.Tool].Arguments[f.Field]
		if !ok || (a.Type != "integer" && a.Type != "decimal") {
			return AmountError{fmt.Sprintf("rule %s: %s has no integer or decimal argument %q", f.Rule, f.Tool, f.Field)}
		}
	}
	return nil
}

// Catalog returns the tool catalog in force, or nil.
func (s *Service) Catalog() *Catalog {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.catalog
}

// MaxDetailRunes bounds the held-call detail shown to the owner.
const MaxDetailRunes = 1000

// Detail is the shell command or the tool arguments of a request, for the owner
// deciding a held call.  It is never logged.
func Detail(raw []byte) string {
	d := fullDetail(raw)
	if r := []rune(d); len(r) > MaxDetailRunes {
		d = string(r[:MaxDetailRunes]) + "…"
	}
	return d
}

// fullDetail must be used for holds: a truncated preview is never approvable.
func fullDetail(raw []byte) string {
	in, err := parseStdinRequest(raw)
	if err != nil || in.WritePaths != nil || in.ReadPaths != nil {
		return ""
	}
	var d string
	if in.Shell {
		var p struct {
			Command []string `json:"command"`
			Cwd     string   `json:"cwd"`
		}
		if json.Unmarshal(in.Arguments, &p) != nil {
			return ""
		}
		parts := make([]string, len(p.Command))
		for i, a := range p.Command {
			if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`;&|<>(){}*?!#~") {
				a = "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
			}
			parts[i] = a
		}
		d = strings.Join(parts, " ") + "   (in " + p.Cwd + ")"
	} else {
		d = string(in.Arguments)
	}
	return d
}

// MonitoredReason is the kernel reason on an ALLOW that a monitor rule permitted.
const MonitoredReason = "POLICY_MONITORED"

// Monitored reports whether an ALLOW verdict came from a monitor rule.
func Monitored(out Output) bool {
	if out.Effect != "ALLOW" {
		return false
	}
	for _, r := range out.Reasons {
		if r == MonitoredReason || r == "CONTENT_MONITORED" {
			return true
		}
	}
	return false
}

// GatewayRegistrar registers and revokes per-agent session tokens at the gateway.
type GatewayRegistrar interface {
	RegisterSession(token, principal string)
	RevokeSession(token string)
}

type agentSession struct {
	id           string
	agentName    string
	principal    string
	sockPath     string
	gatewayToken string
	listener     net.Listener
	cancel       context.CancelFunc
	access       *sessionAccess
}

// SessionInfo is returned to the owner when an agent session is created.
type SessionInfo struct {
	Session        string `json:"session"`
	Principal      string `json:"principal"`
	ApprovalSocket string `json:"approval_socket"`
	GatewayToken   string `json:"gateway_token,omitempty"`
}

var (
	errTooManySessions = errors.New("too many sessions")
	errUnknownSession  = errors.New("unknown session")
)

// ValidAgentName reports whether name matches [a-z0-9][a-z0-9._-]{0,55}.
func ValidAgentName(name string) bool {
	if len(name) < 1 || len(name) > 56 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
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

// Service decides requests under one compiled-at-start policy and logs every decision.
type Service struct {
	rulesMu      sync.Mutex // serializes rule publication and approval invalidation
	rulesChanged chan struct{}
	policyMu     sync.RWMutex
	policy       []byte
	digest       string
	catalog      *Catalog
	now          func() time.Time

	logMu sync.Mutex
	log   io.Writer

	ask *asker // nil: headless, calls needing approval stay BLOCKed

	contentMu    sync.RWMutex
	contentRules *content.Rules

	sessionMu       sync.Mutex
	sessions        map[string]*agentSession
	approvalSocket  string
	gwRegistrar     GatewayRegistrar
	scopeMu         sync.RWMutex
	workspaceScopes map[string]*WorkspaceScope
	scopeStore      string
}

// ContentRules returns the content rules in force.
func (s *Service) ContentRules() *content.Rules {
	s.contentMu.RLock()
	defer s.contentMu.RUnlock()
	return s.contentRules
}

// SetContentRules replaces the content rules for later decisions and filtering.
func (s *Service) SetContentRules(r *content.Rules) {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	s.contentMu.Lock()
	defer s.contentMu.Unlock()
	s.contentRules = r
	s.invalidateRules()
}

// SetApprovalSocket records the main approval socket path, used to place agent session sockets.
func (s *Service) SetApprovalSocket(path string) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.approvalSocket = path
}

// SetGatewayRegistrar wires the API gateway for issuing and revoking per-agent tokens.
func (s *Service) SetGatewayRegistrar(gw GatewayRegistrar) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.gwRegistrar = gw
}

func (s *Service) createSession(agentName string, mediated ...bool) (SessionInfo, error) {
	return s.createWorkspaceSession(agentName, len(mediated) > 0 && mediated[0], nil)
}

func (s *Service) createWorkspaceSession(agentName string, mediated bool, workspace *WorkspaceScope) (SessionInfo, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if len(s.sessions) >= 64 {
		return SessionInfo{}, errTooManySessions
	}
	if s.approvalSocket == "" {
		return SessionInfo{}, errors.New("approval socket not set")
	}
	scope, err := s.registerWorkspace(workspace)
	if err != nil {
		return SessionInfo{}, err
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return SessionInfo{}, fmt.Errorf("session id rand: %w", err)
	}
	sessID := hex.EncodeToString(b)
	principal := syntheticPrinc
	if agentName != "" {
		principal = "agent." + agentName
	}

	sockDir := filepath.Dir(s.approvalSocket)
	agentsDir := filepath.Join(sockDir, "agents")
	if err := os.MkdirAll(agentsDir, 0o700); err != nil {
		return SessionInfo{}, fmt.Errorf("mkdir agents dir: %w", err)
	}
	_ = os.Chmod(agentsDir, 0o700)
	sockPath := filepath.Join(agentsDir, sessID+".sock")

	l, err := ListenUnix(sockPath)
	if err != nil {
		return SessionInfo{}, fmt.Errorf("listen agent socket: %w", err)
	}

	var gwToken string
	ctx, cancel := context.WithCancel(context.Background())
	access := newSessionAccess(sessID)
	access.mediated = mediated
	access.scope = scope
	ctx = context.WithValue(ctx, sessionAccessKey{}, access)
	if s.gwRegistrar != nil {
		tb := make([]byte, 32)
		if _, err := rand.Read(tb); err != nil {
			cancel()
			_ = l.Close()
			_ = os.Remove(sockPath)
			return SessionInfo{}, fmt.Errorf("gateway token rand: %w", err)
		}
		gwToken = hex.EncodeToString(tb)
		if registrar, ok := s.gwRegistrar.(interface {
			RegisterSessionContext(string, string, context.Context)
		}); ok {
			registrar.RegisterSessionContext(gwToken, principal, ctx)
		} else {
			s.gwRegistrar.RegisterSession(gwToken, principal)
		}
	}
	sess := &agentSession{
		access:       access,
		cancel:       cancel,
		id:           sessID,
		agentName:    agentName,
		principal:    principal,
		sockPath:     sockPath,
		gatewayToken: gwToken,
		listener:     l,
	}
	s.sessions[sessID] = sess

	go func() {
		_ = s.serveWithContext(ctx, l, principal)
	}()

	return SessionInfo{
		Session:        sessID,
		Principal:      principal,
		ApprovalSocket: sockPath,
		GatewayToken:   gwToken,
	}, nil
}

func (s *Service) deleteSession(sessID string) error {
	s.sessionMu.Lock()
	sess, ok := s.sessions[sessID]
	if !ok {
		s.sessionMu.Unlock()
		return errUnknownSession
	}
	delete(s.sessions, sessID)
	gwReg := s.gwRegistrar
	s.sessionMu.Unlock()

	sess.cancel()
	_ = sess.listener.Close()
	_ = os.Remove(sess.sockPath)
	if gwReg != nil && sess.gatewayToken != "" {
		gwReg.RevokeSession(sess.gatewayToken)
	}
	return nil
}

func (s *Service) closeSessions() {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for id, sess := range s.sessions {
		sess.cancel()
		_ = sess.listener.Close()
		_ = os.Remove(sess.sockPath)
		if s.gwRegistrar != nil && sess.gatewayToken != "" {
			s.gwRegistrar.RevokeSession(sess.gatewayToken)
		}
		delete(s.sessions, id)
	}
}

// NewService admits the policy (it must compile) and the decision log writer.
func NewService(policyBytes []byte, log io.Writer) (*Service, error) {
	snap, err := policy.Compile(policyBytes)
	if err != nil {
		return nil, fmt.Errorf("approval policy: %w", err)
	}
	if log == nil {
		return nil, errors.New("approval decision log required")
	}
	return &Service{
		rulesChanged:    make(chan struct{}),
		policy:          append([]byte(nil), policyBytes...),
		digest:          snap.Digest(),
		now:             time.Now,
		log:             log,
		sessions:        make(map[string]*agentSession),
		workspaceScopes: make(map[string]*WorkspaceScope),
	}, nil
}

// PolicyDigest is the digest of the policy in force.
func (s *Service) PolicyDigest() string {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.digest
}

// Policy returns a copy of the policy in force.
func (s *Service) Policy() []byte {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return append([]byte(nil), s.policy...)
}

// SetPolicy replaces the policy for every later decision.  A policy that does
// not compile is refused and the current one stays in force.
func (s *Service) SetPolicy(raw []byte) (string, error) {
	snap, err := policy.Compile(raw)
	if err != nil {
		return "", fmt.Errorf("approval policy: %w", err)
	}
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if err := CheckAmountFields(snap, s.catalog); err != nil {
		return "", err
	}
	s.policy, s.digest = append([]byte(nil), raw...), snap.Digest()
	s.invalidateRules()
	return snap.Digest(), nil
}

// requestText is what request rules scan: the decoded string values of the
// arguments (so a JSON escape such as \u002d cannot hide a listed word), one
// per line, or the shell command joined with spaces.
func requestText(raw []byte) string {
	in, err := parseStdinRequest(raw)
	if err != nil || len(in.Arguments) == 0 {
		return ""
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(in.Arguments))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return string(in.Arguments)
	}
	if in.Shell {
		if m, ok := v.(map[string]any); ok {
			if argv, ok := m["command"].([]any); ok {
				parts := make([]string, 0, len(argv))
				for _, a := range argv {
					if s, ok := a.(string); ok {
						parts = append(parts, s)
					}
				}
				return strings.Join(parts, " ")
			}
		}
	}
	var lines []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			lines = append(lines, t)
		case json.Number:
			lines = append(lines, t.String())
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return strings.Join(lines, "\n")
}

// Decide evaluates one request and appends its log entry.  If the log cannot be
// written the verdict becomes BLOCK: no decision is acted on without a record.
func (s *Service) Decide(raw []byte, principal ...string) Output {
	return s.DecideContext(context.Background(), raw, principal...)
}

func (s *Service) DecideContext(ctx context.Context, raw []byte, principal ...string) Output {
	return s.decideContext(ctx, raw, "", principal...)
}

// DecideHTTPContext binds the gateway's actual transport URL to the same
// decision, approval and log record as the tool call. This is a host-only Go
// API: an agent cannot assert a different URL in its approval JSON.
func (s *Service) DecideHTTPContext(ctx context.Context, raw []byte, target string, principal ...string) Output {
	if target == "" {
		return BlockedOutput("WEBSITE_URL_UNSUPPORTED", s.PolicyDigest(), "-", nil)
	}
	return s.decideContext(ctx, raw, target, principal...)
}

func (s *Service) decideContext(ctx context.Context, raw []byte, target string, principal ...string) Output {
	epoch := s.ruleEpoch()
	princ := syntheticPrinc
	if len(principal) > 0 && principal[0] != "" {
		princ = principal[0]
	}
	start := s.now()
	pol := s.Policy()
	access := accessFor(ctx)
	out := evaluateWithCatalog(pol, s.Catalog(), raw, access != nil && access.mediated, princ)
	detail := fullDetail(raw)
	boundRequest := raw
	if target != "" {
		in, err := parseStdinRequest(raw)
		out = checkWebsite(pol, target, err == nil && in.CanFilter, out, princ)
		boundRequest, _ = json.Marshal(struct {
			Request json.RawMessage `json:"request"`
			URL     string          `json:"url"`
		}{raw, target})
		binding := sha256.Sum256(append([]byte(out.ActionDigest+"\n"), boundRequest...))
		out.ActionDigest = "sha256:" + hex.EncodeToString(binding[:])
		detail = "URL: " + target + "; arguments: " + detail
	}
	kind, tool, paths := Describe(raw)
	if len(paths) > maxWritePaths {
		paths = paths[:maxWritePaths]
	}
	sum := sha256.Sum256(boundRequest)
	asked := ""
	if s.ask != nil && askable(out) {
		access := accessFor(ctx)
		sessionID := ""
		canGrant := access != nil && (kind == "file_read" || kind == "file_write")
		if canGrant {
			sessionID = access.id
		}
		out, asked = s.hold(ctx, out, PendingInfo{
			session:       access,
			grantPaths:    append([]string(nil), paths...),
			Session:       sessionID,
			SessionGrant:  canGrant,
			rulesChanged:  epoch,
			Kind:          kind,
			Principal:     princ,
			Tool:          tool,
			Detail:        detail,
			Paths:         paths,
			RuleIDs:       out.RuleIDs,
			RequestSHA256: hex.EncodeToString(sum[:]),
		})
	}

	var contentMatches []ContentMatch
	if out.Effect == "ALLOW" {
		if cr := s.ContentRules(); cr != nil {
			in, err := parseStdinRequest(raw)
			if cr.ScansResponses(tool) && (err != nil || !in.CanFilter) {
				out = BlockedOutput("TRANSFORM_UNAVAILABLE", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
			} else {
				// Response rules or the injection scan cover this tool: a caller that
				// filters results gets the obligation, so the result reaches the filter.
				if in, err := parseStdinRequest(raw); err == nil && in.CanFilter && cr.ScansResponses(tool) && !hasString(out.Filter, "content") {
					out.Filter = append(out.Filter, "content")
				}
				reqTxt := requestText(raw)
				outcome := cr.Scan(tool, content.DirectionRequest, reqTxt)
				// This path cannot rewrite requests. A filter match is therefore a
				// block even when a separate ask rule is the scanner's strongest action.
				for _, m := range outcome.Matches {
					if m.Action == string(content.ActionFilter) {
						outcome.Action = content.ActionBlock
					}
				}
				for _, m := range outcome.Matches {
					contentMatches = append(contentMatches, ContentMatch{
						List:   m.List,
						Count:  m.Count,
						Action: m.Action,
					})
				}
				switch outcome.Action {
				case content.ActionBlock, content.ActionFilter:
					var cRuleIDs []string
					for _, m := range outcome.Matches {
						if m.Action == string(content.ActionBlock) || m.Action == string(content.ActionFilter) {
							cRuleIDs = append(cRuleIDs, "content:"+m.List)
						}
					}
					if len(cRuleIDs) == 0 && len(outcome.Matches) > 0 {
						cRuleIDs = append(cRuleIDs, "content:"+outcome.Matches[0].List)
					}
					out = BlockedOutput("CONTENT_BLOCKED", out.PolicyDigest, out.ActionDigest, cRuleIDs)
				case content.ActionAsk:
					var askRuleIDs []string
					for _, m := range outcome.Matches {
						if m.Action == string(content.ActionAsk) {
							askRuleIDs = append(askRuleIDs, "content:"+m.List)
						}
					}
					if len(askRuleIDs) == 0 && len(outcome.Matches) > 0 {
						askRuleIDs = append(askRuleIDs, "content:"+outcome.Matches[0].List)
					}
					if s.ask != nil {
						out, asked = s.hold(ctx, out, PendingInfo{
							rulesChanged:  epoch,
							Kind:          kind,
							Principal:     princ,
							Tool:          tool,
							Detail:        detail,
							Paths:         paths,
							RuleIDs:       askRuleIDs,
							RequestSHA256: hex.EncodeToString(sum[:]),
						})
					} else {
						out = BlockedOutput(ReasonApprovalNeeded, out.PolicyDigest, out.ActionDigest, askRuleIDs)
					}
				case content.ActionMonitor:
					out.Reasons = append(out.Reasons, "CONTENT_MONITORED")
					for _, m := range outcome.Matches {
						if m.Action == string(content.ActionMonitor) {
							out.RuleIDs = append(out.RuleIDs, "content:"+m.List)
						}
					}
				}
			}
		}
	}

	if !s.rulesCurrent(epoch) {
		out = BlockedOutput("POLICY_CHANGED", s.PolicyDigest(), out.ActionDigest, out.RuleIDs)
		asked = "rules_changed"
	}
	out = s.privacyDecision(ctx, raw, pol, target, out)
	entry := LogEntry{
		Time:          start.UTC().Format(time.RFC3339Nano),
		Principal:     princ,
		Kind:          kind,
		Tool:          tool,
		Paths:         paths,
		RequestSHA256: hex.EncodeToString(sum[:]),
		Effect:        out.Effect,
		Monitored:     Monitored(out),
		Asked:         asked,
		Reasons:       out.Reasons,
		RuleIDs:       out.RuleIDs,
		PolicyDigest:  out.PolicyDigest,
		ActionDigest:  out.ActionDigest,
		LatencyMicros: s.now().Sub(start).Microseconds(),
		Content:       contentMatches,
	}
	if access != nil {
		entry.Session = access.id
	}
	line, err := json.Marshal(entry)
	if err == nil {
		line = append(line, '\n')
		s.logMu.Lock()
		var n int
		n, err = s.log.Write(line)
		s.logMu.Unlock()
		if n != len(line) && err == nil {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		return BlockedOutput("DECISION_LOG_UNAVAILABLE", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	return out
}

func (s *Service) ruleEpoch() <-chan struct{} {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	return s.rulesChanged
}

// Called with rulesMu held, after publishing a policy, catalog or content edit.
func (s *Service) invalidateRules() {
	close(s.rulesChanged)
	s.rulesChanged = make(chan struct{})
}

func (s *Service) rulesCurrent(epoch <-chan struct{}) bool {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	return epoch == s.rulesChanged
}

// HandleFilter serves one connection on the filter-only socket: a filter
// request gets its filtered content; anything else gets an error, never a
// decision.
func (s *Service) HandleFilter(conn net.Conn) {
	ctx, cancel := connectionContext(context.Background(), conn)
	defer cancel()
	defer conn.Close()
	_ = conn.SetReadDeadline(s.now().Add(RequestTimeout))
	b, err := io.ReadAll(io.LimitReader(conn, MaxRequestBytes+1))
	_ = conn.SetWriteDeadline(s.now().Add(RequestTimeout))
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) || len(b) > MaxRequestBytes {
		_, _ = conn.Write([]byte(`{"error":"request too large or unreadable"}` + "\n"))
		return
	}
	content, tool, ok := parseFilterRequest(bytes.TrimSpace(b))
	if !ok {
		_, _ = conn.Write([]byte(`{"error":"this socket only filters: {\"kind\":\"filter\",\"tool\":\"app.tool\",\"content\":\"...\"}"}` + "\n"))
		return
	}
	out, err := json.Marshal(s.FilterContext(ctx, tool, content))
	if err == nil {
		_, _ = conn.Write(append(out, '\n'))
	}
}

// ServeFilter accepts filter-only connections until the listener closes.
func (s *Service) ServeFilter(l net.Listener) error {
	sem := make(chan struct{}, MaxConcurrent)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			s.HandleFilter(c)
		}()
	}
}

// Handle serves one connection: read one JSON request terminated by a newline
// (or EOF), write one JSON verdict line, close.
func (s *Service) Handle(conn net.Conn) {
	s.HandleWithPrincipal(conn, syntheticPrinc)
}

// HandleWithPrincipal serves one connection for the given principal.
func (s *Service) HandleWithPrincipal(conn net.Conn, principal string) {
	s.handleWithContext(context.Background(), conn, principal)
}

func (s *Service) handleWithContext(parent context.Context, conn net.Conn, principal string) {
	ctx, cancel := connectionContext(parent, conn)
	defer cancel()
	defer conn.Close()
	_ = conn.SetReadDeadline(s.now().Add(RequestTimeout))
	r := bufio.NewReaderSize(io.LimitReader(conn, MaxRequestBytes+1), 4096)
	var buf bytes.Buffer
	for {
		chunk, err := r.ReadSlice('\n')
		buf.Write(chunk)
		if buf.Len() > MaxRequestBytes {
			s.reply(conn, BlockedOutput("REQUEST_TOO_LARGE", s.PolicyDigest(), "-", nil))
			return
		}
		if err == nil || errors.Is(err, io.EOF) {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return // timeout or reset: nothing to answer
		}
	}
	req := bytes.TrimRight(buf.Bytes(), "\n")
	if len(bytes.TrimSpace(req)) == 0 {
		return
	}
	if content, tool, ok := parseFilterRequest(req); ok {
		res := s.FilterContext(ctx, tool, content, principal)
		_ = conn.SetWriteDeadline(s.now().Add(RequestTimeout))
		b, err := json.Marshal(res)
		if err == nil {
			_, _ = conn.Write(append(b, '\n'))
		}
		return
	} else if tool == "!" {
		_ = conn.SetWriteDeadline(s.now().Add(RequestTimeout))
		_, _ = conn.Write([]byte(`{"error":"bad filter request"}` + "\n"))
		return
	}
	out := s.DecideContext(ctx, req, principal) // may be held for an answer ("ask me"); the read deadline no longer applies
	_ = conn.SetWriteDeadline(s.now().Add(RequestTimeout))
	s.reply(conn, out)
}

func (s *Service) reply(conn net.Conn, out Output) {
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(b, '\n'))
}

// Serve accepts connections until the listener is closed.
func (s *Service) Serve(l net.Listener) error {
	return s.ServeWithPrincipal(l, syntheticPrinc)
}

// ServeWithPrincipal accepts connections deciding as principal until the listener is closed.
func (s *Service) ServeWithPrincipal(l net.Listener, principal string) error {
	return s.serveWithContext(context.Background(), l, principal)
}

func (s *Service) serveWithContext(ctx context.Context, l net.Listener, principal string) error {
	sem := make(chan struct{}, MaxConcurrent)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			s.handleWithContext(ctx, conn, principal)
		}()
	}
}

// ListenUnix creates the approval socket with mode 0600.  Its parent directory
// must be owner-only (checked by config), so no other user can reach it before
// the chmod.  A stale socket at the path is replaced; any other file is refused.
func ListenUnix(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("approval socket path exists and is not a socket: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("approval socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("approval socket: %w", err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("approval socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("approval socket: %w", err)
	}
	return l, nil
}

// OpenDecisionLog opens the append-only decision log (created 0600, never through a symlink).
func OpenDecisionLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("approval decision log: %w", err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		return nil, errors.New("approval decision log must be an owner-only regular file")
	}
	return f, nil
}
