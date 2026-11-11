package resource

import "testing"

func TestCommandSelectors(t *testing.T) {
	for _, value := range []string{`["git","status"]`, `["printf","%s","a b"]`, `["echo",""]`} {
		normalized, canonical, err := NormalizeSelector(Command, value)
		if err != nil || !canonical || normalized != value {
			t.Fatalf("invalid command: %s -> %s %v", value, normalized, err)
		}
		if ValidatePattern(Command, value) != nil || !Match(Command, value, value) || !Match(Command, "*", value) {
			t.Fatalf("command did not match: %s", value)
		}
	}
	for _, value := range []string{`[]`, `[""]`, `["git",null]`, `["git", "status"]`, `["git","bad\narg"]`, `["git",1]`, `git status`, `["git"]/**/**`} {
		if ValidatePattern(Command, value) == nil {
			t.Fatalf("invalid command pattern accepted: %s", value)
		}
	}
	if Match(Command, `["git","status"]`, `["git","status","--short"]`) ||
		Match(Command, `["git","status"]`, `["git","status; rm notes"]`) ||
		Match(Command, `["git","status"]`, `["/workspace/git","status"]`) {
		t.Fatal("command matcher widened exact argv permission")
	}
	if !Match(Command, `["rm"]/**`, `["rm","-rf","notes"]`) || !Match(Command, `["rm"]/**`, `["rm"]`) ||
		Match(Command, `["git","status"]/**`, `["git","status-bad"]`) || Match(Command, `["rm"]/**`, `["rmdir","notes"]`) {
		t.Fatal("command prefixes are not argument-boundary aware")
	}
}
