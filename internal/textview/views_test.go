package textview

import (
	"strings"
	"testing"
)

func TestMixedAndNestedViews(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		percent  bool
	}{
		{`prefix {"x":"a\n\u0041\/b"}`, "prefix {\"x\":\"a\nA/b\"}", false},
		{`x=abc%2fdef%2Bxyz`, "x=abc/def+xyz", true},
		{`x=abc\u00252fdef`, "x=abc/def", true},
		{`{"x":"\ud83d\ude00"}`, `{"x":"😀"}`, false},
	} {
		views, ok := Views(tc.in, tc.percent)
		found := false
		for _, v := range views {
			if v == tc.want {
				found = true
			}
		}
		if !ok || !found {
			t.Fatalf("%s: %q complete=%v", tc.in, views, ok)
		}
	}
}

func TestViewBudgetFailsClosed(t *testing.T) {
	s := "%" + strings.Repeat("25", maxViews+1) + "2f"
	if _, complete := Views(s, true); complete {
		t.Fatal("unbounded encoding accepted")
	}
}
