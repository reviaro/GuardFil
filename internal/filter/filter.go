// Package filter removes secrets from text before an agent sees it: tool
// results and API responses that a sanitize ("Filter") rule covers.
//
// Detection is pattern based: well-known credential formats (private keys,
// cloud and SaaS API keys, JWTs, bearer tokens, URL passwords) and values of
// secret-named fields (password, api_key, token, ...).  Each match is
// replaced by [REDACTED:<kind>].  It is a best effort against accidental
// disclosure, not a guarantee against an app that encodes a secret on purpose.
package filter

import (
	"regexp"
	"sort"
	"strings"
)

type detector struct {
	kind string
	re   *regexp.Regexp
	// group is the submatch to redact (0: the whole match).
	group int
}

var detectors = []detector{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`), 0},
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), 0},
	{"github_token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`), 0},
	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), 0},
	{"openai_key", regexp.MustCompile(`\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`), 0},
	{"stripe_key", regexp.MustCompile(`\b[sr]k_(live|test)_[A-Za-z0-9]{16,}`), 0},
	{"slack_token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), 0},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), 0},
	{"url_password", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@"']+:([^\s/@"']+)@`), 1},
	{"bearer_token", regexp.MustCompile(`(?i)\b(?:bearer|token)\s+([A-Za-z0-9._~+/=-]{16,})`), 1},
	// "password": "x", api_key=x, SECRET: x, client-secret = 'x' ...
	{"secret_field", regexp.MustCompile(`(?i)["']?\b[a-z0-9_.-]*(password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|credential)s?\b["']?\s*[:=]\s*["']?([^\s"',;}&]{6,})`), 2},
}

// Result is the filtered text and what was removed (kinds and counts only).
type Result struct {
	Text       string         `json:"content"`
	Redactions int            `json:"redactions"`
	Kinds      map[string]int `json:"kinds,omitempty"`
	Blocked    bool           `json:"blocked,omitempty"`
}

// Redact removes every detected secret and each of the literal secrets given
// (for example the app's own API key).
func Redact(text string, literals ...string) Result {
	out := Result{Kinds: map[string]int{}}
	for _, lit := range literals {
		if len(lit) >= 6 && strings.Contains(text, lit) {
			n := strings.Count(text, lit)
			text = strings.ReplaceAll(text, lit, "[REDACTED:credential]")
			out.Kinds["credential"] += n
			out.Redactions += n
		}
	}
	for _, d := range detectors {
		type span struct{ a, b int }
		var spans []span
		for _, m := range d.re.FindAllStringSubmatchIndex(text, -1) {
			a, b := m[2*d.group], m[2*d.group+1]
			if a < 0 || strings.HasPrefix(text[a:b], "[REDACTED:") {
				continue
			}
			spans = append(spans, span{a, b})
		}
		if len(spans) == 0 {
			continue
		}
		sort.Slice(spans, func(i, j int) bool { return spans[i].a < spans[j].a })
		var sb strings.Builder
		last := 0
		for _, sp := range spans {
			if sp.a < last {
				continue
			}
			sb.WriteString(text[last:sp.a])
			sb.WriteString("[REDACTED:" + d.kind + "]")
			last = sp.b
			out.Kinds[d.kind]++
			out.Redactions++
		}
		sb.WriteString(text[last:])
		text = sb.String()
	}
	out.Text = text
	if len(out.Kinds) == 0 {
		out.Kinds = nil
	}
	return out
}
