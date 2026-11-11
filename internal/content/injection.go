package content

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const SuspectedInstructionsMarker = "[GuardFil removed suspected instructions]"

type injectionPattern struct {
	category string
	re       *regexp.Regexp
}

var injectionPatterns = []injectionPattern{
	// Override phrases: "ignore (all) previous instructions", "disregard the above", "SYSTEM OVERRIDE", "new instructions:", "you are now"
	{"override", regexp.MustCompile(`(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|past|former)\s+(?:instructions|prompts|directions|commands)\b`)},
	{"override", regexp.MustCompile(`(?i)\bdisregard\s+(?:the\s+)?(?:above|previous\s+(?:instructions|prompts|directions)|prior\s+(?:instructions|prompts|directions))\b`)},
	{"override", regexp.MustCompile(`(?i)\bsystem\s+override\b`)},
	{"override", regexp.MustCompile(`(?i)\bnew\s+instructions\s*:`)},
	{"override", regexp.MustCompile(`(?i)\byou\s+are\s+now\b`)},

	// Fake roles and chat markup: <|im_start|>, [INST], ### system, <system>, "assistant:" at start of line
	{"role_markup", regexp.MustCompile(`(?i)<\|im_(?:start|end)\|>[^\n]*`)},
	{"role_markup", regexp.MustCompile(`\[/?INST\]`)},
	{"role_markup", regexp.MustCompile(`(?im)^###\s*(?:system|assistant|human|user)\b`)},
	{"role_markup", regexp.MustCompile(`(?i)</?system>`)},
	{"role_markup", regexp.MustCompile(`(?im)^assistant\s*:`)},

	// Commands to act or keep secrets: "do not tell the user", "withdraw / transfer / send ... to" + account or URL
	{"command", regexp.MustCompile(`(?i)\b(?:do\s+not|don't|never)\s+tell\s+the\s+user\b`)},
	{"command", regexp.MustCompile(`(?i)\b(?:withdraw|transfer|send)\b[\s\S]{1,60}?\bto\b\s+(?:account\s+|acct\s+|address\s+)?(?:[A-Z0-9_.-]*[0-9][A-Z0-9_.-]*|https?://\S+)`)},
}

// IsHiddenRune reports whether r is a tag character, zero-width rune, or bidi control.
func IsHiddenRune(r rune) bool {
	// Unicode tag characters U+E0000..E007F
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	switch r {
	// Zero-width characters & invisible formatting
	case 0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E:
		return true
	// Bidi controls
	case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C:
		return true
	}
	return false
}

// StripHidden removes all hidden runes (tag characters, zero-width runes, bidi controls) from s.
func StripHidden(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !IsHiddenRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// injectionSpan represents a matched range [start, end) in bytes.
type injectionSpan struct {
	start    int
	end      int
	category string
}

// scanInjection finds all injection matches in text.
func scanInjection(text string) ([]injectionSpan, map[string]int) {
	counts := make(map[string]int)
	var spans []injectionSpan

	for _, p := range injectionPatterns {
		locs := p.re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			counts[p.category]++
			spans = append(spans, injectionSpan{
				start:    loc[0],
				end:      loc[1],
				category: p.category,
			})
		}
	}

	// Check for hidden unicode
	hiddenCount := 0
	byteIdx := 0
	for _, r := range text {
		runeLen := utf8.RuneLen(r)
		if IsHiddenRune(r) {
			hiddenCount++
			spans = append(spans, injectionSpan{
				start:    byteIdx,
				end:      byteIdx + runeLen,
				category: "hidden_text",
			})
		}
		byteIdx += runeLen
	}
	if hiddenCount > 0 {
		counts["hidden_text"] = hiddenCount
	}

	return spans, counts
}

// sentenceOrLineEnd finds the end of the sentence or line following start.
func sentenceOrLineEnd(text string, start int) int {
	if start >= len(text) {
		return len(text)
	}
	sub := text[start:]

	// Find nearest sentence terminator or newline
	end := len(sub)
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		if c == '\n' {
			return start + i
		}
		// An unescaped quote ends a JSON string: the cut never crosses it, so a
		// filtered JSON result stays valid JSON.
		if c == '"' && !escapedAt(sub, i) {
			return start + i
		}
		if (c == '.' || c == '!' || c == '?') && i < end {
			// Lookahead: end of string, whitespace, or newline
			if i+1 == len(sub) {
				return start + i + 1
			}
			next := sub[i+1]
			if next == ' ' || next == '\t' || next == '\r' || next == '\n' {
				return start + i + 1
			}
		}
	}
	return start + end
}

// escapedAt reports whether s[i] is preceded by an odd number of backslashes.
func escapedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// FilterInjection removes injection matches and the rest of their sentence or line,
// adds SuspectedInstructionsMarker, and strips all hidden unicode.
func FilterInjection(text string) string {
	spans, _ := scanInjection(text)
	if len(spans) == 0 {
		return StripHidden(text)
	}

	// Expand each span to cover the rest of its line or sentence
	type cutRange struct {
		start int
		end   int
	}
	var cuts []cutRange
	for _, sp := range spans {
		cutEnd := sentenceOrLineEnd(text, sp.start)
		cuts = append(cuts, cutRange{start: sp.start, end: cutEnd})
	}

	// Merge overlapping or adjacent cuts
	sort.Slice(cuts, func(i, j int) bool {
		if cuts[i].start == cuts[j].start {
			return cuts[i].end < cuts[j].end
		}
		return cuts[i].start < cuts[j].start
	})

	var merged []cutRange
	for _, c := range cuts {
		if len(merged) == 0 {
			merged = append(merged, c)
			continue
		}
		last := &merged[len(merged)-1]
		if c.start <= last.end {
			if c.end > last.end {
				last.end = c.end
			}
		} else {
			merged = append(merged, c)
		}
	}

	var sb strings.Builder
	lastIdx := 0
	for _, c := range merged {
		if c.start > lastIdx {
			sb.WriteString(text[lastIdx:c.start])
		}
		sb.WriteString(SuspectedInstructionsMarker)
		lastIdx = c.end
	}
	if lastIdx < len(text) {
		sb.WriteString(text[lastIdx:])
	}

	return StripHidden(sb.String())
}
