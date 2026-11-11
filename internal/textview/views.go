// Package textview exposes bounded decoded views for security scanning. Views
// are never forwarded: decoding arbitrary text is not a safe way to rewrite it.
package textview

import (
	"encoding/json"
	"strings"
)

const maxViews = 24

// Views includes text and its JSON/repr escape-resolved forms. With percent,
// URL path and query encodings are also inspected. complete is false when the
// decoding budget is exhausted; callers must withhold such input.
func Views(text string, percent bool) (views []string, complete bool) {
	views = []string{text}
	seen := map[string]bool{text: true}
	for i := 0; i < len(views); i++ {
		candidates := []string{unescape(views[i])}
		if percent {
			decoded := unescapePercent(views[i])
			candidates = append(candidates, decoded, strings.ReplaceAll(decoded, "+", " "))
		}
		for _, s := range candidates {
			if seen[s] {
				continue
			}
			if len(views) == maxViews {
				return views, false
			}
			seen[s] = true
			views = append(views, s)
		}
	}
	return views, true
}

// Decode valid escapes even if unrelated text contains a malformed percent
// sequence. An invalid suffix must not hide an otherwise encoded credential.
func unescapePercent(s string) string {
	hex := func(b byte) int {
		switch {
		case b >= '0' && b <= '9':
			return int(b - '0')
		case b >= 'a' && b <= 'f':
			return int(b-'a') + 10
		case b >= 'A' && b <= 'F':
			return int(b-'A') + 10
		}
		return -1
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			a, b := hex(s[i+1]), hex(s[i+2])
			if a >= 0 && b >= 0 {
				out.WriteByte(byte(a*16 + b))
				i += 2
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

// unescape accepts escape sequences inside mixed text, NDJSON, and repr
// output. Unknown sequences remain literal. Each pass is linear and cannot
// expand the input; nested encodings are bounded by Views.
func unescape(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 == len(s) {
			out.WriteByte(s[i])
			i++
			continue
		}
		n := 2
		var decoded string
		switch s[i+1] {
		case '\\', '/', '"', '\'':
			decoded = string(s[i+1])
		case 'n':
			decoded = "\n"
		case 'r':
			decoded = "\r"
		case 't':
			decoded = "\t"
		case 'b':
			decoded = "\b"
		case 'f':
			decoded = "\f"
		case 'u':
			if i+6 <= len(s) {
				n = 6
				// Decode a surrogate pair together when present.
				if i+12 <= len(s) && s[i+6:i+8] == `\u` {
					var v string
					if err := json.Unmarshal([]byte(`"`+s[i:i+12]+`"`), &v); err == nil {
						decoded, n = v, 12
					}
				}
				if decoded == "" {
					_ = json.Unmarshal([]byte(`"`+s[i:i+6]+`"`), &decoded)
				}
			}
		}
		if decoded == "" {
			out.WriteByte(s[i])
			i++
			continue
		}
		out.WriteString(decoded)
		i += n
	}
	return out.String()
}
