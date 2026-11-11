package content

import (
	"sort"
)

// Scan evaluates text against the content rules for the given tool and direction.
// Strongest action wins: block > ask > filter > monitor > none.
func (r *Rules) Scan(tool string, direction Direction, text string) Outcome {
	if r == nil {
		return Outcome{Action: ActionNone, Text: text}
	}

	var matches []Match
	strongest := ActionNone
	rewritten := text

	// 1. Evaluate list rules
	for i := range r.Lists {
		l := &r.Lists[i]
		if !MatchesAnyTool(l.Tools, tool) {
			continue
		}
		if l.Direction != DirectionBoth && l.Direction != direction {
			continue
		}

		listMatches := 0

		// Check words
		for _, re := range l.wordRegexps {
			all := re.FindAllStringIndex(text, -1)
			if n := len(all); n > 0 {
				listMatches += n
				if l.Action == ActionFilter {
					rewritten = re.ReplaceAllString(rewritten, "[FILTERED:"+l.ID+"]")
				}
			}
		}

		// Check patterns
		for _, re := range l.patternRegexps {
			all := re.FindAllStringIndex(text, -1)
			if n := len(all); n > 0 {
				listMatches += n
				if l.Action == ActionFilter {
					rewritten = re.ReplaceAllString(rewritten, "[FILTERED:"+l.ID+"]")
				}
			}
		}

		if listMatches > 0 {
			matches = append(matches, Match{
				List:   l.ID,
				Count:  listMatches,
				Action: string(l.Action),
			})
			strongest = MaxAction(strongest, l.Action)
		}
	}

	// 2. Evaluate prompt injection scanning (runs on responses)
	if (direction == DirectionResponse || direction == DirectionBoth) &&
		r.Injection.Action != "" && r.Injection.Action != ActionNone &&
		MatchesAnyTool(r.Injection.Tools, tool) {

		spans, counts := scanInjection(text)
		if len(spans) > 0 {
			// Sort categories deterministically
			var cats []string
			for cat := range counts {
				cats = append(cats, cat)
			}
			sort.Strings(cats)

			for _, cat := range cats {
				matches = append(matches, Match{
					List:     "injection",
					Count:    counts[cat],
					Category: cat,
					Action:   string(r.Injection.Action),
				})
			}

			strongest = MaxAction(strongest, r.Injection.Action)
			if r.Injection.Action == ActionFilter {
				rewritten = FilterInjection(rewritten)
			}
		}
	}

	return Outcome{
		Action:  strongest,
		Text:    rewritten,
		Matches: matches,
	}
}

// ScansResponses reports whether any response rule or the injection scan
// covers tool: its results must then go through GuardFil's filter.
func (r *Rules) ScansResponses(tool string) bool {
	if r == nil {
		return false
	}
	for i := range r.Lists {
		l := &r.Lists[i]
		if l.Direction != DirectionRequest && l.Action != ActionNone && MatchesAnyTool(l.Tools, tool) {
			return true
		}
	}
	return r.Injection.Action != "" && r.Injection.Action != ActionNone && MatchesAnyTool(r.Injection.Tools, tool)
}
