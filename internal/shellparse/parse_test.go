package shellparse

import (
	"reflect"
	"strings"
	"testing"
)

func TestCommandsExposeEveryStage(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   [][]string
	}{
		{`git status`, [][]string{{"git", "status"}}},
		{`git status && rm -rf notes`, [][]string{{"git", "status"}, {"rm", "-rf", "notes"}}},
		{`git status || rm notes; cat ok | wc -c`, [][]string{{"git", "status"}, {"rm", "notes"}, {"cat", "ok"}, {"wc", "-c"}}},
		{`(git status); { rm notes; }`, [][]string{{"git", "status"}, {"rm", "notes"}}},
		{`bash -c 'git status; rm notes'`, [][]string{{"git", "status"}, {"rm", "notes"}}},
		{`echo 'rm -rf /' "literal; $(not executed)"`, nil},
		{`echo 'rm -rf /' 'literal; $(not executed)'`, [][]string{{"echo", "rm -rf /", "literal; $(not executed)"}}},
		{`printf '%s' 'a b' > notes`, [][]string{{"printf", "%s", "a b"}}},
		{`g"i"t $'status'`, [][]string{{"git", "status"}}},
		{`echo $'\0'`, [][]string{{"echo", ""}}},
		{`grep '*' notes`, [][]string{{"grep", "*", "notes"}}},
	} {
		t.Run(tc.script, func(t *testing.T) {
			got, err := Commands([]string{"/bin/bash", "-lc", tc.script})
			if tc.want == nil {
				if err == nil {
					t.Fatal("dynamic substitution accepted")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestUnresolvedCommandsFailClosed(t *testing.T) {
	for _, script := range []string{
		`$CMD status`, `git "$ARGS"`, `git $(rm notes)`, "git `rm notes`", `cat <(rm notes)`,
		`cat >$(rm notes)`, `git status > "$OUTPUT"`, `git status; eval 'rm notes' "$X"`,
		`CMD=rm; $CMD notes`, `PATH=/workspace git status`, `git(){ rm notes; }; git status`,
		`for x in notes; do rm "$x"; done`, `if true; then rm notes; fi`,
		`cat *`, `cat ~/secret`, `echo a{b,c}`, `echo $((1+2))`, `git status &`,
		"cat <<EOF\n$(rm notes)\nEOF", "cat <<'EOF'\nliteral\nEOF", `> notes`,
		`bash script.sh`, `bash -i`, `bash --rcfile script.sh -c 'git status'`,
		`bash -c '$1' ignored rm`, `echo $'\x01'`, `git status "`,
	} {
		t.Run(script, func(t *testing.T) {
			if got, err := Commands([]string{"bash", "-c", script}); err == nil {
				t.Fatalf("unresolved shell accepted: %q", got)
			}
		})
	}
}

func TestDirectArgumentsAndLimits(t *testing.T) {
	argv := []string{"git", "status", "--short"}
	got, err := Commands(argv)
	if err != nil || !reflect.DeepEqual(got, [][]string{argv}) {
		t.Fatalf("%q %v", got, err)
	}
	for _, args := range [][]string{nil, {""}, {"git", "bad\x00arg"}, {"bash", "-c", strings.Repeat("true;", 65)}} {
		if _, err := Commands(args); err == nil {
			t.Fatalf("invalid/oversized command accepted: %q", args)
		}
	}
}

func TestEditorRejectsSyntaxThatWouldChangeRuleMeaning(t *testing.T) {
	for _, input := range []string{`git status && rm notes`, `git status > notes`, `! git status`,
		`git "$ARGS"`, `git $(whoami)`, `git status # ignored`, `bash -c 'rm notes'`, `X=1 git status`,
		`git *`, `git status &`, ``, `git status; rm notes`} {
		if _, err := LiteralCommand(input); err == nil {
			t.Errorf("unsafe rule input accepted: %q", input)
		}
	}
	args := []string{"printf", "%s", "a b", "*", "", "it's quoted"}
	got, err := LiteralCommand(Display(args))
	if err != nil || !reflect.DeepEqual(args, got) {
		t.Fatalf("command display lost argument boundaries: %q %v", got, err)
	}
}
