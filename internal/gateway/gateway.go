// Package gateway is GuardFil's HTTP API gateway.  An outside agent calls an
// app's API through it with a GuardFil token.  Each request is mapped by its
// method and path to a catalog tool, with path segments, query parameters and
// the JSON body as the arguments, and decided by the approval service like any
// other tool call (allow, block, monitor, ask me, amount rules).  Only allowed
// requests are forwarded, rebuilt from the decided arguments, with the app's
// real credential added here; the agent never holds it.  Anything else gets
// 403 and never reaches the app.
package gateway

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/config"
	"github.com/reviaro/guardfil/internal/content"
	"github.com/reviaro/guardfil/internal/filter"
	"github.com/reviaro/guardfil/internal/textview"
)

const (
	maxBodyBytes     = 64 << 10
	maxResponseBytes = 1 << 20
	upstreamTimeout  = 30 * time.Second
	redacted         = "[REDACTED-BY-GUARDFIL]"
)

// Decider is the approval service as the gateway uses it.
type Decider interface {
	DecideHTTPContext(context.Context, []byte, string, ...string) approval.Output
	Catalog() *approval.Catalog
}
type contextFilter interface {
	FilterContext(context.Context, string, string, ...string) filter.Result
}

type serviceFilter interface {
	Filter(tool, content string, principal ...string) filter.Result
}

// ResponseFilter removes secrets from a response body (a Filter rule's obligation).
type ResponseFilter func(tool, body string, principal ...string) string

// ResponseFilterResult evaluates content rules and redactions on a response.
type ResponseFilterResult func(context.Context, string, string, ...string) filter.Result

type route struct {
	method   string
	segments []string // literal, or "{name}"
	tool     string
	server   string
	name     string
}

type upstream struct {
	name       string
	base       *url.URL
	header     string
	credential string // header value, prefix included; never logged or returned
	secret     string // the bare credential, redacted from responses
	routes     []route
}

type contentProvider interface {
	ContentRules() *content.Rules
}

type gatewaySession struct {
	principal string
	ctx       context.Context
	cancel    context.CancelFunc
}

// Gateway serves the agent-facing HTTP API.
type Gateway struct {
	svc           Decider
	token         []byte
	tokenMu       sync.RWMutex
	sessionTokens map[string]gatewaySession // token -> cancellable session
	upstreams     map[string]*upstream
	client        *http.Client
	log           *slog.Logger
	Filter        ResponseFilter
	FilterResult  ResponseFilterResult
	ContentRules  func() *content.Rules
}

// New builds the gateway from validated config.  Every route's tool must be in
// the catalog, and every credential file must be readable.
func New(cfg config.Gateway, svc Decider, log *slog.Logger) (*Gateway, error) {
	tok, err := readSecret(cfg.AgentTokenFile)
	if err != nil {
		return nil, fmt.Errorf("gateway agent token: %w", err)
	}
	if len(tok) < 16 {
		return nil, errors.New("gateway agent token must be at least 16 bytes")
	}
	g := &Gateway{
		svc:           svc,
		token:         []byte(tok),
		sessionTokens: make(map[string]gatewaySession),
		upstreams:     map[string]*upstream{},
		log:           log,
		client: &http.Client{
			Timeout: upstreamTimeout,
			// Redirects would leave the decided request; the agent gets the 3xx instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if f, ok := svc.(serviceFilter); ok {
		g.FilterResult = func(_ context.Context, tool, body string, principal ...string) filter.Result {
			return f.Filter(tool, body, principal...)
		}
		g.Filter = func(tool, body string, principal ...string) string { return f.Filter(tool, body, principal...).Text }
	}
	if f, ok := svc.(contextFilter); ok {
		g.FilterResult = f.FilterContext
	}
	if cp, ok := svc.(contentProvider); ok {
		g.ContentRules = cp.ContentRules
	}
	cat := svc.Catalog()
	for _, u := range cfg.Upstreams {
		base, err := url.Parse(u.BaseURL)
		if err != nil {
			return nil, err
		}
		up := &upstream{name: u.Name, base: base, header: u.CredentialHeader}
		if u.CredentialFile != "" {
			sec, err := readSecret(u.CredentialFile)
			if err != nil || sec == "" {
				return nil, fmt.Errorf("gateway %s credential: unreadable or empty", u.Name)
			}
			up.secret, up.credential = sec, u.CredentialPrefix+sec
		}
		for _, r := range u.Routes {
			if !cat.Has(r.Tool) {
				return nil, fmt.Errorf("gateway %s route %s %s: tool %s is not in the tool catalog", u.Name, r.Method, r.Path, r.Tool)
			}
			up.routes = append(up.routes, route{method: r.Method, segments: strings.Split(r.Path[1:], "/"),
				tool: r.Tool, server: strings.SplitN(r.Tool, ".", 2)[0], name: strings.SplitN(r.Tool, ".", 2)[1]})
		}
		g.upstreams[u.Name] = up
	}
	return g, nil
}

func readSecret(path string) (string, error) {
	b, err := readFileLimited(path, 4096)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if strings.ContainsAny(s, "\r\n") || !utf8.ValidString(s) {
		return "", errors.New("must be one line")
	}
	return s, nil
}

// Verdict is the 403 body for a refused request.
type Verdict struct {
	Error   string   `json:"error"`
	Effect  string   `json:"effect,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	RuleIDs []string `json:"rule_ids,omitempty"`
}

func refuse(w http.ResponseWriter, status int, v Verdict) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// filtered reports whether any filter list matched, so the text was rewritten.
func filtered(out content.Outcome) bool {
	for _, m := range out.Matches {
		if m.Action == string(content.ActionFilter) {
			return true
		}
	}
	return false
}

func scanAndRewriteJSON(v any, scan func(string) (content.Outcome, string)) (content.Outcome, any) {
	combined := content.Outcome{Action: content.ActionNone}
	switch val := v.(type) {
	case string:
		out, rewritten := scan(val)
		combined = out
		return combined, rewritten
	case map[string]any:
		newMap := make(map[string]any, len(val))
		for k, item := range val {
			out, newItem := scanAndRewriteJSON(item, scan)
			if content.Stronger(out.Action, combined.Action) {
				combined.Action = out.Action
			}
			combined.Matches = append(combined.Matches, out.Matches...)
			newMap[k] = newItem
		}
		return combined, newMap
	case []any:
		newSlice := make([]any, len(val))
		for i, item := range val {
			out, newItem := scanAndRewriteJSON(item, scan)
			if content.Stronger(out.Action, combined.Action) {
				combined.Action = out.Action
			}
			combined.Matches = append(combined.Matches, out.Matches...)
			newSlice[i] = newItem
		}
		return combined, newSlice
	default:
		return combined, v
	}
}

// RegisterSession records a per-agent session token and maps it to principal.
func (g *Gateway) RegisterSession(token, principal string) {
	g.RegisterSessionContext(token, principal, context.Background())
}

// RegisterSessionContext retains the owner-created privacy state as well as
// identity. A bearer can select its own session but cannot clear that state.
func (g *Gateway) RegisterSessionContext(token, principal string, parent context.Context) {
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()
	if old, ok := g.sessionTokens[token]; ok {
		old.cancel()
	}
	ctx, cancel := context.WithCancel(parent)
	g.sessionTokens[token] = gatewaySession{principal, ctx, cancel}
}

// RevokeSession revokes a per-agent session token.
func (g *Gateway) RevokeSession(token string) {
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()
	if sess, ok := g.sessionTokens[token]; ok {
		sess.cancel()
	}
	delete(g.sessionTokens, token)
}

func (g *Gateway) authenticate(bearer string) (string, bool) {
	p, _, ok := g.authenticateContext(bearer)
	return p, ok
}

func (g *Gateway) authenticateContext(bearer string) (string, context.Context, bool) {
	g.tokenMu.RLock()
	defer g.tokenMu.RUnlock()

	bearerBytes := []byte(bearer)
	matchedPrinc := ""
	matchedCtx := context.Background()
	matched := 0

	if subtle.ConstantTimeCompare(bearerBytes, g.token) == 1 {
		matched = 1
		matchedPrinc = "codex-agent"
	}

	for tok, session := range g.sessionTokens {
		if subtle.ConstantTimeCompare(bearerBytes, []byte(tok)) == 1 {
			matched = 1
			matchedPrinc = session.principal
			matchedCtx = session.ctx
		}
	}

	if matched == 1 {
		return matchedPrinc, matchedCtx, true
	}
	return "", matchedCtx, false
}

// ServeHTTP decides and, if allowed, forwards one request.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="guardfil"`)
		refuse(w, http.StatusUnauthorized, Verdict{Error: "a GuardFil gateway token is required"})
		return
	}
	principal, sessionCtx, ok := g.authenticateContext(tok)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="guardfil"`)
		refuse(w, http.StatusUnauthorized, Verdict{Error: "a GuardFil gateway token is required"})
		return
	}
	ctx, cancel := context.WithCancel(sessionCtx)
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()
	if sessionCtx.Err() != nil || r.Context().Err() != nil {
		cancel()
	}
	r = r.WithContext(ctx)
	up, rt, params, ok := g.match(r)
	if !ok {
		g.log.Warn("gateway request matches no route", "method", r.Method)
		refuse(w, http.StatusForbidden, Verdict{Error: "blocked by GuardFil: no route for this request",
			Effect: "BLOCK", Reasons: []string{"GATEWAY_NO_ROUTE"}})
		return
	}
	args, body, query, err := g.arguments(r, rt, params)
	if err != nil {
		refuse(w, http.StatusForbidden, Verdict{Error: "blocked by GuardFil: " + err.Error(),
			Effect: "BLOCK", Reasons: []string{"GATEWAY_BAD_REQUEST"}})
		return
	}
	// The gateway filters responses, so a Filter (sanitize) rule can permit a request.
	req := []byte(`{"server":` + jsonString(rt.server) + `,"tool":` + jsonString(rt.name) + `,"arguments":` + string(args) +
		`,"can_filter":true}`)
	target := upstreamURL(up, rt, params, query)
	out := g.svc.DecideHTTPContext(ctx, req, target, principal)
	if out.Effect != "ALLOW" {
		refuse(w, http.StatusForbidden, Verdict{Error: "blocked by GuardFil", Effect: out.Effect,
			Reasons: out.Reasons, RuleIDs: out.RuleIDs})
		return
	}
	g.forward(w, r.Context(), up, rt, target, body, len(out.Filter) > 0, principal)
}

func (g *Gateway) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return false
	}
	_, ok = g.authenticate(tok)
	return ok
}

// match finds the route: /<upstream>/<path...>.  Segments are compared after
// unescaping; a segment that unescapes to contain "/" or is "." or ".." never
// matches, so the forwarded path is the matched one.
func (g *Gateway) match(r *http.Request) (*upstream, route, map[string]string, bool) {
	raw := r.URL.EscapedPath()
	if !strings.HasPrefix(raw, "/") || len(raw) > 2048 {
		return nil, route{}, nil, false
	}
	parts := strings.Split(raw[1:], "/")
	segs := make([]string, len(parts))
	for i, p := range parts {
		s, err := url.PathUnescape(p)
		if err != nil || s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\\x00") || !utf8.ValidString(s) {
			return nil, route{}, nil, false
		}
		segs[i] = s
	}
	up, ok := g.upstreams[segs[0]]
	if !ok {
		return nil, route{}, nil, false
	}
	segs = segs[1:]
	for _, rt := range up.routes {
		if rt.method != r.Method || len(rt.segments) != len(segs) {
			continue
		}
		params := map[string]string{}
		matched := true
		for i, want := range rt.segments {
			if strings.HasPrefix(want, "{") {
				params[want[1:len(want)-1]] = segs[i]
			} else if want != segs[i] {
				matched = false
				break
			}
		}
		if matched {
			return up, rt, params, true
		}
	}
	return nil, route{}, nil, false
}

var numberLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// arguments merges path arguments, query parameters and the JSON body object.
// It returns the decided arguments, the body to forward (re-encoded from the
// decided values) and the query to forward.
func (g *Gateway) arguments(r *http.Request, rt route, params map[string]string) ([]byte, []byte, url.Values, error) {
	args := map[string]json.RawMessage{}
	spec := map[string]approval.ArgSpec{}
	for _, t := range g.svc.Catalog().Tools() {
		if t.ID == rt.tool {
			spec = t.Arguments
		}
	}
	// Path and query values are text; a catalog integer or decimal gets a number.
	scalar := func(name, v string) json.RawMessage {
		if a := spec[name]; (a.Type == "integer" || a.Type == "decimal") && numberLiteral.MatchString(v) {
			return json.RawMessage(v)
		}
		if a := spec[name]; a.Type == "boolean" && (v == "true" || v == "false") {
			return json.RawMessage(v)
		}
		return json.RawMessage(jsonString(v))
	}
	var cr *content.Rules
	if g.ContentRules != nil {
		cr = g.ContentRules()
	}

	for k, v := range params {
		args[k] = scalar(k, v)
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, nil, nil, errors.New("malformed query")
	}
	for k, vs := range query {
		if len(vs) != 1 {
			return nil, nil, nil, fmt.Errorf("query parameter %q repeated", k)
		}
		if _, dup := args[k]; dup {
			return nil, nil, nil, fmt.Errorf("argument %q given twice", k)
		}
		val := vs[0]
		if cr != nil {
			// Only filter matches are rewritten here.  Block, ask and monitor
			// matches stay in the arguments, so Decide applies them and logs it.
			if out := cr.Scan(rt.tool, content.DirectionRequest, val); filtered(out) {
				val = out.Text
				query[k][0] = val
			}
		}
		args[k] = scalar(k, val)
	}
	var fwdBody []byte
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(raw) > maxBodyBytes {
		return nil, nil, nil, errors.New("body too large or unreadable")
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		if mt := strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]); mt != "application/json" {
			return nil, nil, nil, errors.New("the body must be application/json")
		}
		body, err := jsonObject(raw)
		if err != nil {
			return nil, nil, nil, err
		}
		if cr != nil {
			for k, v := range body {
				var parsed any
				dec := json.NewDecoder(bytes.NewReader(v))
				dec.UseNumber() // a rewritten body keeps its exact decimals
				if err := dec.Decode(&parsed); err == nil {
					out, rewritten := scanAndRewriteJSON(parsed, func(s string) (content.Outcome, string) {
						res := cr.Scan(rt.tool, content.DirectionRequest, s)
						return res, res.Text
					})
					if filtered(out) {
						if b, err := json.Marshal(rewritten); err == nil {
							body[k] = json.RawMessage(b)
						}
					}
				}
			}
		}
		for k, v := range body {
			if _, dup := args[k]; dup {
				return nil, nil, nil, fmt.Errorf("argument %q given twice", k)
			}
			args[k] = v
		}
		if fwdBody, err = json.Marshal(body); err != nil {
			return nil, nil, nil, errors.New("body cannot be re-encoded")
		}
	}
	out, err := json.Marshal(args)
	if err != nil {
		return nil, nil, nil, errors.New("arguments cannot be encoded")
	}
	return out, fwdBody, query, nil
}

// jsonObject parses one JSON object, refusing duplicate keys (the app might
// read a different copy than GuardFil decided on) and trailing data.
func jsonObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("the body must be a JSON object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		kt, err := d.Token()
		if err != nil {
			return nil, errors.New("malformed JSON body")
		}
		k := kt.(string)
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("body key %q repeated", k)
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, errors.New("malformed JSON body")
		}
		out[k] = v
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.New("malformed JSON body")
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON body")
	}
	return out, nil
}

func upstreamURL(up *upstream, rt route, params map[string]string, query url.Values) string {
	segs := make([]string, len(rt.segments))
	for i, s := range rt.segments {
		if strings.HasPrefix(s, "{") {
			s = params[s[1:len(s)-1]]
		}
		segs[i] = url.PathEscape(s)
	}
	target := *up.base
	target.Path = ""
	target.RawPath = ""
	u := target.String() + "/" + strings.Join(segs, "/")
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

func (g *Gateway) forward(w http.ResponseWriter, ctx context.Context, up *upstream, rt route,
	target string, body []byte, mustFilter bool, principal string) {
	var rb io.Reader
	if body != nil {
		rb = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, rt.method, target, rb)
	if err != nil {
		refuse(w, http.StatusBadGateway, Verdict{Error: "GuardFil could not build the upstream request"})
		return
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if up.credential != "" {
		req.Header.Set(up.header, up.credential)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		g.log.Warn("gateway upstream unreachable", "upstream", up.name)
		refuse(w, http.StatusBadGateway, Verdict{Error: "the app did not answer"})
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		refuse(w, http.StatusBadGateway, Verdict{Error: "the app's response was unreadable or too large"})
		return
	}
	ct := resp.Header.Get("Content-Type")
	if up.secret != "" {
		data = bytes.ReplaceAll(data, []byte(up.secret), []byte(redacted))
	}
	if textual(ct) && (g.FilterResult != nil || g.Filter != nil) {
		if g.FilterResult != nil {
			res := g.FilterResult(ctx, rt.tool, string(data), principal)
			if res.Blocked {
				refuse(w, http.StatusForbidden, Verdict{
					Error:   "blocked by GuardFil: " + res.Text,
					Effect:  "BLOCK",
					Reasons: []string{"CONTENT_BLOCKED"},
				})
				return
			}
			data = []byte(res.Text)
		} else if mustFilter {
			data = []byte(g.Filter(rt.tool, string(data), principal))
		}
	} else if mustFilter {
		// A filter rule applies but this response cannot be inspected: withhold it.
		refuse(w, http.StatusForbidden, Verdict{Error: "blocked by GuardFil: the response cannot be filtered",
			Effect: "BLOCK", Reasons: []string{"FILTER_UNSUPPORTED_CONTENT"}})
		return
	}
	// Filtering may decode escapes (JSON \/ or \u00XX) that hid the
	// credential from the first replacement, so redact the bytes actually sent.
	data = redactSecretForms(data, up.secret)
	// An encoded credential in mixed text cannot always be safely rewritten.
	// Never release a response that still reveals it in a decoded view.
	if containsSecretForm(string(data), up.secret) {
		refuse(w, http.StatusForbidden, Verdict{Error: "blocked by GuardFil: credential in response",
			Effect: "BLOCK", Reasons: []string{"CREDENTIAL_IN_RESPONSE"}})
		return
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if loc := resp.Header.Get("Location"); loc != "" && !containsSecretForm(loc, up.secret) {
		decoded := loc
		if unesc, err := url.QueryUnescape(loc); err == nil {
			decoded = unesc
		}
		safe := decoded
		if up.secret != "" {
			safe = strings.ReplaceAll(safe, up.secret, redacted)
		}
		if g.FilterResult != nil {
			res := g.FilterResult(ctx, rt.tool, safe, principal)
			if res.Blocked {
				refuse(w, http.StatusForbidden, Verdict{
					Error:   "blocked by GuardFil: " + res.Text,
					Effect:  "BLOCK",
					Reasons: []string{"CONTENT_BLOCKED"},
				})
				return
			}
			safe = res.Text
		} else if mustFilter && g.Filter != nil {
			safe = g.Filter(rt.tool, safe, principal)
		}
		// A redacted URL is not a usable redirect. Withhold it, and preserve
		// the exact original encoding of an unchanged, safe redirect.
		if safe == decoded {
			w.Header().Set("Location", loc)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

// secretForms is the credential as it may appear in a response: as is, JSON
// string-escaped, and URL-encoded.
func secretForms(secret string) []string {
	if secret == "" {
		return nil
	}
	forms := []string{secret, url.QueryEscape(secret), url.PathEscape(secret)}
	if j := jsonString(secret); len(j) >= 2 {
		forms = append(forms, j[1:len(j)-1])
	}
	return forms
}

// redactSecretForms replaces every form of the credential in data.
func redactSecretForms(data []byte, secret string) []byte {
	for _, f := range secretForms(secret) {
		if f != "" {
			data = bytes.ReplaceAll(data, []byte(f), []byte(redacted))
		}
	}
	return data
}

// containsSecretForm reports whether a header value carries the credential in
// any form, raw or after path or query unescaping ('+' is a space only in the
// query form).
func containsSecretForm(v, secret string) bool {
	if secret == "" {
		return false
	}
	candidates, complete := textview.Views(v, true)
	if !complete {
		return true
	}
	for _, c := range candidates {
		for _, f := range secretForms(secret) {
			if f != "" && strings.Contains(c, f) {
				return true
			}
		}
	}
	return false
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func readFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file too large")
	}
	return b, nil
}

// textual reports whether a response can be filtered as text.
func textual(contentType string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	return mt == "" || strings.HasPrefix(mt, "text/") || mt == "application/json" || strings.HasSuffix(mt, "+json") ||
		mt == "application/xml" || strings.HasSuffix(mt, "+xml") || mt == "application/x-www-form-urlencoded"
}
