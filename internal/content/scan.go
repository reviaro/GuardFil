package content

import (
	"slices"
	"sort"
	"strings"
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

// GatewayRequestOutcome checks the original policy decision and the values
// that will actually be sent. A filter obligation is satisfied only when the
// outgoing request no longer matches that list.
func (r *Rules) GatewayRequestOutcome(tool string, original, outgoing []string) (Outcome, map[string]bool) {
	before := r.gatewayMatchCounts(tool, original)
	after := before
	if !slices.Equal(original, outgoing) {
		after = r.gatewayMatchCounts(tool, outgoing)
	}
	out := Outcome{Action: ActionNone}
	var unfiltered map[string]bool
	for _, list := range r.Lists {
		n := max(before[list.ID], after[list.ID])
		if n == 0 {
			continue
		}
		out.Matches = append(out.Matches, Match{List: list.ID, Count: n, Action: string(list.Action)})
		if list.Action == ActionFilter {
			if after[list.ID] > 0 {
				if unfiltered == nil {
					unfiltered = make(map[string]bool)
				}
				unfiltered[list.ID] = true
				out.Action = ActionBlock
			}
		} else {
			out.Action = MaxAction(out.Action, list.Action)
		}
	}
	return out, unfiltered
}

// Filters rewrite individual values. The approval service also supports
// patterns spanning values in their canonical order. Keep both views without
// counting the same list match twice.
func (r *Rules) gatewayMatchCounts(tool string, values []string) map[string]int {
	counts := make(map[string]int)
	for _, value := range values {
		for _, m := range r.Scan(tool, DirectionRequest, value).Matches {
			counts[m.List] += m.Count
		}
	}
	if len(values) != 1 {
		for _, m := range r.Scan(tool, DirectionRequest, strings.Join(values, "\n")).Matches {
			counts[m.List] = max(counts[m.List], m.Count)
		}
	}
	return counts
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
