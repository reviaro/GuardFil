// Package shellparse extracts static command arguments for command-specific
// policy. It never executes a shell or expands the environment. Constructs whose
// executed arguments cannot be determined before dispatch are refused.
package shellparse

import (
	"errors"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

var ErrUnsupported = errors.New("SHELL_COMMAND_UNRESOLVED")

const maxCommands = 64

// LiteralCommand is the policy editor's single-command input. Reject compound
// syntax rather than silently creating a narrower rule than the owner entered.
func LiteralCommand(text string) ([]string, error) {
	if len(text) > 16384 {
		return nil, ErrUnsupported
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true)).Parse(strings.NewReader(text), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Last) != 0 {
		return nil, ErrUnsupported
	}
	s := file.Stmts[0]
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || s.Background || s.Coprocess || s.Disown || s.Negated || len(s.Redirs) != 0 ||
		len(s.Comments) != 0 || len(call.Assigns) != 0 || len(call.Args) == 0 || len(call.Args) > 64 {
		return nil, ErrUnsupported
	}
	args := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		arg, err := literal(word)
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
	}
	if args[0] == "" || shell(args[0]) {
		return nil, ErrUnsupported
	}
	return args, nil
}

// Display preserves argument boundaries when rendering a stored command rule.
func Display(args []string) string {
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i], _ = syntax.Quote(arg, syntax.LangBash)
	}
	return strings.Join(parts, " ")
}

// Commands returns every static simple command, including both branches of
// conditionals and every pipeline stage. The caller must authorize all of them
// before allowing any part of the original request to execute.
func Commands(argv []string) ([][]string, error) {
	p := projection{}
	if err := p.argv(argv, 0); err != nil || len(p.commands) == 0 {
		return nil, ErrUnsupported
	}
	return p.commands, nil
}

type projection struct{ commands [][]string }

func validArg(s string) bool {
	if len(s) > 4096 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func shell(name string) bool {
	switch name {
	case "bash", "sh", "dash", "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh", "/bin/dash", "/usr/bin/dash":
		return true
	}
	return false
}

func (p *projection) argv(argv []string, depth int) error {
	if depth > 8 || len(argv) == 0 || len(argv) > 64 || argv[0] == "" {
		return ErrUnsupported
	}
	if shell(argv[0]) {
		// Recognize the native wrappers exactly. Do not guess at interactive
		// shells, script files, positional parameters or alternate startup files.
		i := 1
		for i < len(argv) && (argv[i] == "--noprofile" || argv[i] == "--norc") {
			i++
		}
		if i+2 != len(argv) || (argv[i] != "-c" && argv[i] != "-lc") {
			return ErrUnsupported
		}
		script := argv[i+1]
		if len(script) > 16384 {
			return ErrUnsupported
		}
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
		if err != nil {
			return ErrUnsupported
		}
		for _, stmt := range file.Stmts {
			if err = p.stmt(stmt, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, arg := range argv {
		if !validArg(arg) {
			return ErrUnsupported
		}
	}
	if len(p.commands) >= maxCommands {
		return ErrUnsupported
	}
	p.commands = append(p.commands, append([]string(nil), argv...))
	return nil
}

func (p *projection) stmt(stmt *syntax.Stmt, depth int) error {
	if depth > 32 || stmt == nil || stmt.Background || stmt.Coprocess || stmt.Disown {
		return ErrUnsupported
	}
	for _, redir := range stmt.Redirs {
		if redir.Hdoc != nil {
			return ErrUnsupported
		}
		if _, err := literal(redir.Word); err != nil {
			return err
		}
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 {
			return ErrUnsupported
		}
		args := make([]string, 0, len(cmd.Args))
		for _, word := range cmd.Args {
			arg, err := literal(word)
			if err != nil {
				return err
			}
			args = append(args, arg)
		}
		return p.argv(args, depth)
	case *syntax.BinaryCmd:
		if err := p.stmt(cmd.X, depth+1); err != nil {
			return err
		}
		return p.stmt(cmd.Y, depth+1)
	case *syntax.Block:
		for _, s := range cmd.Stmts {
			if err := p.stmt(s, depth+1); err != nil {
				return err
			}
		}
		return nil
	case *syntax.Subshell:
		for _, s := range cmd.Stmts {
			if err := p.stmt(s, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrUnsupported
	}
}

func staticParts(parts []syntax.WordPart, quoted bool) bool {
	for _, part := range parts {
		switch x := part.(type) {
		case *syntax.Lit:
			// Unquoted glob, tilde and brace expansion depends on runtime
			// state. Quoted occurrences are ordinary literal arguments.
			if !quoted && strings.ContainsAny(x.Value, "*?[]{}~") {
				return false
			}
		case *syntax.SglQuoted:
		case *syntax.DblQuoted:
			if x.Dollar || !staticParts(x.Parts, true) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func literal(word *syntax.Word) (string, error) {
	if word == nil || !staticParts(word.Parts, false) {
		return "", ErrUnsupported
	}
	// Only quote removal and static escapes remain after staticParts. There
	// are no parameter, arithmetic, command or process substitutions to run.
	value, err := expand.Literal(nil, word)
	if err != nil || !validArg(value) {
		return "", ErrUnsupported
	}
	return value, nil
}
