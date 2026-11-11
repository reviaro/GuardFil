// Package resource defines the single trusted selector grammar shared by
// Action formation, credential resource ceilings, and policy matching.
package resource

import (
	"encoding/json"
	"errors"
	"net/url"
	pathpkg "path"
	"strings"
	"unicode/utf8"
)

const (
	Path    = "path"
	URL     = "url"
	Tool    = "tool"
	Command = "command"
)

var ErrInvalid = errors.New("invalid resource selector")

// SecurityOperation reports whether op is an installed Security registered
// operation name.
func SecurityOperation(op string) bool {
	switch op {
	case "filesystem.read",
		"filesystem.write",
		"llm.request",
		"tool.invoke",
		"shell.execute",
		"http.request":
		return true
	default:
		return false
	}
}

// KindForSecurityOperation maps an installed Security registered operation to
// its single trusted resource selector kind. Operations with no selector
// projection return the empty string.
func KindForSecurityOperation(op string) string {
	switch op {
	case "filesystem.read", "filesystem.write":
		return Path
	case "http.request":
		return URL
	case "tool.invoke":
		return Tool
	case "shell.execute":
		return Command
	default:
		return ""
	}
}

// KindForOperation is the closed operation-to-selector mapping implemented by
// the P1.2 kernel. Unsupported operation families have no safe fallback.
func KindForOperation(operation string) string {
	switch operation {
	case "fs.read", "fs.write":
		return Path
	case "http.request":
		return URL
	case "tool.invoke":
		return Tool
	case "shell.execute":
		return Command
	default:
		return ""
	}
}

// NormalizeSelector returns the canonical selector and whether the supplied
// representation was already canonical. A non-canonical absolute path can be
// retained for rejection evidence, but it must never become authorizable.
func NormalizeSelector(kind, value string) (normalized string, canonical bool, err error) {
	if !validText(value, 4096) {
		return "", false, ErrInvalid
	}
	switch kind {
	case Path:
		if value[0] != '/' || strings.ContainsAny(value, `\%`) {
			return "", false, ErrInvalid
		}
		clean := pathpkg.Clean(value)
		if clean == "." || clean == "" || clean[0] != '/' {
			return "", false, ErrInvalid
		}
		return clean, clean == value, nil
	case URL:
		return normalizeURL(value)
	case Tool:
		if !validID(value) {
			return "", false, ErrInvalid
		}
		return value, true, nil
	case Command:
		var argv []string
		if json.Unmarshal([]byte(value), &argv) != nil || len(argv) == 0 || len(argv) > 64 || argv[0] == "" {
			return "", false, ErrInvalid
		}
		for _, arg := range argv {
			if arg != "" && !validText(arg, 4096) {
				return "", false, ErrInvalid
			}
		}
		canonical, _ := json.Marshal(argv)
		return string(canonical), string(canonical) == value, nil
	default:
		return "", false, ErrInvalid
	}
}

// ValidatePattern admits exact selectors and a single terminal /** wildcard
// over a canonical path or URL base. Wildcards never apply to tool IDs.
// Paths also admit BASE/**/NAME and BASE/**/NAME/** (see anyFolderPattern).
func ValidatePattern(kind, pattern string) error {
	if kind == Command {
		if pattern == "*" {
			return nil
		}
		base := strings.TrimSuffix(pattern, "/**")
		normalized, canonical, err := NormalizeSelector(kind, base)
		if err != nil || !canonical || normalized != base {
			return ErrInvalid
		}
		return nil
	}
	if kind == Path && strings.Contains(pattern, "/**/") {
		if _, ok := parseAnyFolder(pattern); !ok {
			return ErrInvalid
		}
		return nil
	}
	base, wildcard := patternBase(kind, pattern)
	if base == "" {
		return ErrInvalid
	}
	normalized, canonical, err := NormalizeSelector(kind, base)
	if err != nil || !canonical || normalized != base {
		return ErrInvalid
	}
	if wildcard && kind == Tool {
		return ErrInvalid
	}
	return nil
}

// Match compares only canonical selectors against validated patterns. It is
// segment-aware, so /work/** never matches /work-other or a lexical escape.
func Match(kind, pattern, value string) bool {
	normalized, canonical, err := NormalizeSelector(kind, value)
	if err != nil || !canonical || normalized != value || ValidatePattern(kind, pattern) != nil {
		return false
	}
	if kind == Command {
		if pattern == "*" || pattern == value {
			return true
		}
		if !strings.HasSuffix(pattern, "/**") {
			return false
		}
		var prefix, argv []string
		_ = json.Unmarshal([]byte(strings.TrimSuffix(pattern, "/**")), &prefix)
		_ = json.Unmarshal([]byte(value), &argv)
		if len(prefix) > len(argv) {
			return false
		}
		for i, arg := range prefix {
			if argv[i] != arg {
				return false
			}
		}
		return true
	}
	if kind == Path && strings.Contains(pattern, "/**/") {
		af, _ := parseAnyFolder(pattern)
		return af.match(value)
	}
	base, wildcard := patternBase(kind, pattern)
	if !wildcard {
		return value == base
	}
	if kind == Path && base == "/" {
		return strings.HasPrefix(value, "/")
	}
	return value == base || strings.HasPrefix(value, base+"/")
}

// anyFolderPattern is a path pattern BASE/**/NAME: a file or folder named NAME
// directly in BASE or in any folder below it. With a trailing /**
// (BASE/**/NAME/**) it also covers everything inside such a folder. BASE is a
// canonical path ("/" is written as /**/NAME); NAME is one literal segment.
type anyFolderPattern struct {
	prefix string // BASE with a trailing "/"
	name   string
	under  bool
}

func parseAnyFolder(pattern string) (anyFolderPattern, bool) {
	i := strings.Index(pattern, "/**/")
	if i < 0 || !validText(pattern, 4096) {
		return anyFolderPattern{}, false
	}
	base, rest := pattern[:i], pattern[i+len("/**/"):]
	if base == "/" {
		return anyFolderPattern{}, false
	}
	if base == "" {
		base = "/"
	}
	if n, canonical, err := NormalizeSelector(Path, base); err != nil || !canonical || n != base {
		return anyFolderPattern{}, false
	}
	under := strings.HasSuffix(rest, "/**")
	name := strings.TrimSuffix(rest, "/**")
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/*\%`) {
		return anyFolderPattern{}, false
	}
	return anyFolderPattern{prefix: strings.TrimSuffix(base, "/") + "/", name: name, under: under}, true
}

// match: value (canonical) lies below the base and has a segment equal to
// name, which must be the last segment unless the pattern ends in /**.
func (p anyFolderPattern) match(value string) bool {
	if p.prefix == "" || !strings.HasPrefix(value, p.prefix) {
		return false
	}
	segs := strings.Split(value[len(p.prefix):], "/")
	for i, seg := range segs {
		if seg == p.name && (p.under || i == len(segs)-1) {
			return true
		}
	}
	return false
}

func patternBase(kind, pattern string) (string, bool) {
	if !strings.HasSuffix(pattern, "/**") {
		return pattern, false
	}
	if pattern == "/**" && kind == Path {
		return "/", true
	}
	return strings.TrimSuffix(pattern, "/**"), true
}

func normalizeURL(value string) (string, bool, error) {
	if strings.ContainsAny(value, `%\`) {
		return "", false, ErrInvalid
	}
	for _, r := range value {
		if r > 0x7f {
			return "", false, ErrInvalid
		}
	}
	u, err := url.ParseRequestURI(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", false, ErrInvalid
	}
	cleanPath := u.Path
	if cleanPath == "" {
		cleanPath = "/"
	} else {
		cleanPath = pathpkg.Clean(cleanPath)
	}
	if cleanPath == "." || cleanPath == "" || cleanPath[0] != '/' {
		return "", false, ErrInvalid
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	u.Path = cleanPath
	normalized := u.String()
	return normalized, normalized == value, nil
}

func validText(value string, max int) bool {
	if len(value) == 0 || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validID(value string) bool {
	if !validText(value, 64) {
		return false
	}
	for i, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') || i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
