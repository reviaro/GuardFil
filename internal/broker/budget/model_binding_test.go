package budget

import "testing"

func TestCanonicalReplyModel(t *testing.T) {
	cases := []struct {
		provider  string
		requested string
		reported  string
		wantCanon string
		wantOk    bool
	}{
		{"gemini", "gemini-3.6-flash", "gemini-3.6-flash-001", "gemini-3.6-flash", true},
		{"gemini", "gemini-3.6-flash", "gemini-3.6-flash", "gemini-3.6-flash", true},
		{"gemini", "gemini-3.6-flash", "gemini-3.6-flash-preview", "", false},
		{"gemini", "gemini-3.5-flash-lite", "gemini-3.6-flash-001", "", false},
		{"openai", "gpt-6-luna", "gpt-6-luna", "gpt-6-luna", true},
		{"openai", "gpt-6-luna", "gpt-6-sol", "", false},
		{"anthropic", "claude-sonnet-5-5", "claude-sonnet-5-5", "claude-sonnet-5-5", true},
		{"anthropic", "claude-sonnet-5-5", "claude-3-opus", "", false},
	}
	for _, tc := range cases {
		canon, ok := CanonicalReplyModel(tc.provider, tc.requested, tc.reported)
		if ok != tc.wantOk || canon != tc.wantCanon {
			t.Errorf("CanonicalReplyModel(%q, %q, %q) = (%q, %v), want (%q, %v)",
				tc.provider, tc.requested, tc.reported, canon, ok, tc.wantCanon, tc.wantOk)
		}
	}
}
