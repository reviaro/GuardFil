// Package content evaluates company word and pattern lists and scans tool
// results and API responses for prompt injection.
package content

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	CurrentSchemaVersion = 1
	MaxLists             = 200
	MaxWordsPerList      = 1000
	MaxPatternsPerList   = 1000
	MaxRulesBytes        = 1 << 20
)

var idRegexp = regexp.MustCompile(`^[a-z0-9-]{1,48}$`)

// Action is one content rule action.
type Action string

const (
	ActionNone    Action = "none"
	ActionMonitor Action = "monitor"
	ActionFilter  Action = "filter"
	ActionAsk     Action = "ask"
	ActionBlock   Action = "block"
)

// Direction is where a rule applies: request, response, or both.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
	DirectionBoth     Direction = "both"
)

// ListRule is one company word or pattern list.
type ListRule struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Action        Action    `json:"action"`
	Direction     Direction `json:"direction"`
	Tools         []string  `json:"tools"`
	Words         []string  `json:"words,omitempty"`
	Patterns      []string  `json:"patterns,omitempty"`
	CaseSensitive bool      `json:"case_sensitive,omitempty"`

	// compiled matchers
	wordRegexps    []*regexp.Regexp
	patternRegexps []*regexp.Regexp
}

// InjectionRule configures prompt-injection scanning on tool results and API responses.
type InjectionRule struct {
	Action Action   `json:"action"`
	Tools  []string `json:"tools"`
}

// Rules is the complete content rules document.
type Rules struct {
	SchemaVersion int           `json:"schema_version"`
	Lists         []ListRule    `json:"lists"`
	Injection     InjectionRule `json:"injection"`
	digest        string
}

// Digest returns the sha256 digest of the canonical rules JSON.
func (r *Rules) Digest() string {
	if r == nil {
		return ""
	}
	return r.digest
}

// Match is one finding from scanning text against rules.
type Match struct {
	List     string `json:"list"`
	Count    int    `json:"count"`
	Category string `json:"category,omitempty"`
	Action   string `json:"action"`
}

// Outcome is the result of scanning text.
type Outcome struct {
	Action  Action  `json:"action"`
	Text    string  `json:"text,omitempty"`
	Matches []Match `json:"matches,omitempty"`
}

// ActionRank orders actions by strength: block > ask > filter > monitor > none.
func ActionRank(a Action) int {
	switch a {
	case ActionBlock:
		return 4
	case ActionAsk:
		return 3
	case ActionFilter:
		return 2
	case ActionMonitor:
		return 1
	default:
		return 0
	}
}

// Stronger reports whether a is strictly stronger than b.
func Stronger(a, b Action) bool {
	return ActionRank(a) > ActionRank(b)
}

// MaxAction returns the strongest of the two actions.
func MaxAction(a, b Action) Action {
	if Stronger(a, b) {
		return a
	}
	return b
}

func isValidAction(a Action, allowNone bool) bool {
	switch a {
	case ActionBlock, ActionAsk, ActionFilter, ActionMonitor:
		return true
	case ActionNone, "":
		return allowNone
	default:
		return false
	}
}

func isValidDirection(d Direction) bool {
	switch d {
	case DirectionRequest, DirectionResponse, DirectionBoth:
		return true
	default:
		return false
	}
}

// MatchTool checks if a tool matches a pattern (exact, prefix.*, or *).
func MatchTool(pattern, tool string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(tool, prefix)
	}
	return pattern == tool
}

// MatchesAnyTool reports whether tool matches at least one tool pattern.
func MatchesAnyTool(patterns []string, tool string) bool {
	for _, p := range patterns {
		if MatchTool(p, tool) {
			return true
		}
	}
	return false
}

func validateToolPattern(p string) bool {
	if p == "*" {
		return true
	}
	if strings.HasSuffix(p, ".*") {
		prefix := strings.TrimSuffix(p, ".*")
		return len(prefix) > 0 && !strings.Contains(prefix, "*")
	}
	return len(p) > 0 && !strings.Contains(p, "*")
}

func wordRegex(word string, caseSensitive bool) (*regexp.Regexp, error) {
	if len(word) == 0 {
		return nil, errors.New("empty word")
	}
	expr := regexp.QuoteMeta(word)
	rFirst, _ := utf8.DecodeRuneInString(word)
	rLast, _ := utf8.DecodeLastRuneInString(word)
	if isWordRune(rFirst) {
		expr = `\b` + expr
	}
	if isWordRune(rLast) {
		expr = expr + `\b`
	}
	if !caseSensitive {
		expr = `(?i)` + expr
	}
	return regexp.Compile(expr)
}

func isWordRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
}

// ParseRules parses and strictly validates content rules JSON.
func ParseRules(raw []byte) (*Rules, error) {
	if len(raw) == 0 {
		return &Rules{SchemaVersion: CurrentSchemaVersion}, nil
	}
	if len(raw) > MaxRulesBytes {
		return nil, errors.New("content rules too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Rules
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("content rules syntax: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after content rules JSON")
	}
	if r.SchemaVersion != CurrentSchemaVersion {
		return nil, fmt.Errorf("unsupported schema_version %d (want %d)", r.SchemaVersion, CurrentSchemaVersion)
	}
	if len(r.Lists) > MaxLists {
		return nil, fmt.Errorf("too many lists (%d, max %d)", len(r.Lists), MaxLists)
	}

	seenIDs := make(map[string]bool, len(r.Lists))
	for i := range r.Lists {
		l := &r.Lists[i]
		if !idRegexp.MatchString(l.ID) {
			return nil, fmt.Errorf("list %q: invalid id (must match ^[a-z0-9-]{1,48}$)", l.ID)
		}
		if seenIDs[l.ID] {
			return nil, fmt.Errorf("duplicate list id %q", l.ID)
		}
		seenIDs[l.ID] = true

		if len(l.Name) == 0 || len(l.Name) > 200 {
			return nil, fmt.Errorf("list %q: name must be 1-200 characters", l.ID)
		}
		if !isValidAction(l.Action, false) {
			return nil, fmt.Errorf("list %q: invalid action %q (want filter, block, monitor, ask)", l.ID, l.Action)
		}
		if !isValidDirection(l.Direction) {
			return nil, fmt.Errorf("list %q: invalid direction %q (want request, response, both)", l.ID, l.Direction)
		}
		if len(l.Tools) == 0 {
			return nil, fmt.Errorf("list %q: tools must not be empty", l.ID)
		}
		for _, t := range l.Tools {
			if !validateToolPattern(t) {
				return nil, fmt.Errorf("list %q: invalid tool pattern %q", l.ID, t)
			}
		}
		if len(l.Words) > MaxWordsPerList {
			return nil, fmt.Errorf("list %q: too many words (%d, max %d)", l.ID, len(l.Words), MaxWordsPerList)
		}
		if len(l.Patterns) > MaxPatternsPerList {
			return nil, fmt.Errorf("list %q: too many patterns (%d, max %d)", l.ID, len(l.Patterns), MaxPatternsPerList)
		}
		if len(l.Words) == 0 && len(l.Patterns) == 0 {
			return nil, fmt.Errorf("list %q: must contain at least one word or pattern", l.ID)
		}

		for _, w := range l.Words {
			if len(w) == 0 || len(w) > 500 {
				return nil, fmt.Errorf("list %q: word must be 1-500 characters", l.ID)
			}
			re, err := wordRegex(w, l.CaseSensitive)
			if err != nil {
				return nil, fmt.Errorf("list %q word %q: %w", l.ID, w, err)
			}
			l.wordRegexps = append(l.wordRegexps, re)
		}

		for _, p := range l.Patterns {
			if len(p) == 0 || len(p) > 2000 {
				return nil, fmt.Errorf("list %q: pattern must be 1-2000 characters", l.ID)
			}
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("list %q invalid pattern %q: %w", l.ID, p, err)
			}
			l.patternRegexps = append(l.patternRegexps, re)
		}
	}

	if r.Injection.Action != "" && r.Injection.Action != ActionNone {
		if !isValidAction(r.Injection.Action, true) {
			return nil, fmt.Errorf("injection: invalid action %q", r.Injection.Action)
		}
		if len(r.Injection.Tools) == 0 {
			return nil, errors.New("injection: tools must not be empty when active")
		}
		for _, t := range r.Injection.Tools {
			if !validateToolPattern(t) {
				return nil, fmt.Errorf("injection: invalid tool pattern %q", t)
			}
		}
	}

	h := sha256.Sum256(raw)
	r.digest = "sha256:" + hex.EncodeToString(h[:])
	return &r, nil
}
