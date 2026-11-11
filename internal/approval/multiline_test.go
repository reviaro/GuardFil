package approval

import (
	"strings"
	"testing"
)

// Multi-line commands and text are judged by policy; other control
// characters, and newlines in keys and paths, are refused with a clear reason.
func TestMultiLineArgumentsAreDecidedByPolicy(t *testing.T) {
	s, log := newService(t)
	cases := []struct {
		name, req, effect, reason string
	}{
		{"heredoc shell", `{"kind":"shell","command":["bash","-lc","cat > a.py <<'PY'\nprint(1)\nPY\npython3 a.py"],"cwd":"/workspace"}`,
			"ALLOW", "POLICY_ALLOWED"},
		{"tab in shell", `{"kind":"shell","command":["bash","-lc","printf 'a\tb'"],"cwd":"/workspace"}`, "ALLOW", "POLICY_ALLOWED"},
		{"multi-line tool text", `{"server":"testmcp","tool":"write_canary","arguments":{"content":"line one\nline two"}}`,
			"BLOCK", "POLICY_DENIED"},
		{"carriage return", `{"kind":"shell","command":["bash","-lc","echo a\r"],"cwd":"/workspace"}`, "BLOCK", "CONTROL_CHARACTER"},
		{"NUL", `{"kind":"shell","command":["bash","-lc","echo a\u0000"],"cwd":"/workspace"}`, "BLOCK", "CONTROL_CHARACTER"},
		{"newline in a key", `{"server":"testmcp","tool":"write_canary","arguments":{"con\ntent":"x"}}`, "BLOCK", "CONTROL_CHARACTER"},
	}
	for _, c := range cases {
		out := s.Decide([]byte(c.req))
		if out.Effect != c.effect || len(out.Reasons) == 0 || out.Reasons[0] != c.reason {
			t.Errorf("%s: got %s %v, want %s %s", c.name, out.Effect, out.Reasons, c.effect, c.reason)
		}
	}
	if strings.Contains(log.String(), "print(1)") || strings.Contains(log.String(), "line two") {
		t.Fatal("argument text reached the decision log")
	}

	// A path is a resource selector: a newline in it is never accepted.
	out := s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/notes/a\n.txt","change":"add"}]}`))
	if out.Effect != "BLOCK" {
		t.Fatalf("newline in a path: %+v", out)
	}
}
