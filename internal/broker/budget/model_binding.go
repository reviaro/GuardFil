package budget

// knownGeminiAliases maps explicit known versioned Gemini model names to canonical model IDs.
var knownGeminiAliases = map[string]string{
	"gemini-3.6-flash-001": "gemini-3.6-flash",
}

// CanonicalReplyModel verifies whether the provider's reported model matches
// the requested model (allowing only explicit known Gemini aliases). If it matches,
// it returns the canonical requested model name and true. Otherwise it returns "", false.
func CanonicalReplyModel(provider, requested, reported string) (string, bool) {
	if reported == requested {
		return requested, true
	}
	if provider == "gemini" {
		if canon, ok := knownGeminiAliases[reported]; ok && canon == requested {
			return requested, true
		}
	}
	return "", false
}
