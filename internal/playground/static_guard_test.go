package playground

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

var allowedImports = map[string]bool{
	"context":       true,
	"crypto/rand":   true,
	"embed":         true,
	"encoding/hex":  true,
	"encoding/json": true,
	"errors":        true,
	"flag":          true,
	"fmt":           true,
	"io":            true,
	"mime":          true,
	"net":           true,
	"net/http":      true,
	"net/url":       true,
	"os":            true,
	"os/signal":     true,
	"sort":          true,
	"strconv":       true,
	"strings":       true,
	"sync":          true,
	"syscall":       true,
	"time":          true,
	"github.com/reviaro/guardfil/internal/action":       true,
	"github.com/reviaro/guardfil/internal/advisorydemo": true,
	"github.com/reviaro/guardfil/internal/decision":     true,
	"github.com/reviaro/guardfil/internal/failure":      true,
	"github.com/reviaro/guardfil/internal/identity":     true,
	"github.com/reviaro/guardfil/internal/playground":   true,
	"github.com/reviaro/guardfil/internal/policy":       true,
	"github.com/reviaro/guardfil/internal/source":       true,
	"github.com/reviaro/guardfil/internal/telemetry":    true,
}

var allowedOSSelectors = map[string]bool{
	"Exit":      true,
	"Stderr":    true,
	"Stdout":    true,
	"Interrupt": true,
}

var allowedSyscallSelectors = map[string]bool{
	"SIGTERM": true,
	"SIGINT":  true,
}

var allowedHTTPExactSelectors = map[string]bool{
	"Handler":         true,
	"HandlerFunc":     true,
	"ResponseWriter":  true,
	"Request":         true,
	"NewServeMux":     true,
	"Server":          true,
	"MaxBytesReader":  true,
	"MaxBytesError":   true,
	"ErrServerClosed": true,
}

func isAllowedHTTPSelector(name string) bool {
	if strings.HasPrefix(name, "Status") || strings.HasPrefix(name, "Method") {
		return true
	}
	return allowedHTTPExactSelectors[name]
}

func isAllowedDispatchEligibleRHS(expr ast.Expr, inRunFixtures bool) bool {
	for {
		if paren, ok := expr.(*ast.ParenExpr); ok {
			expr = paren.X
		} else {
			break
		}
	}

	// Plain field copy r.DispatchEligible inside RunFixtures
	if inRunFixtures {
		if sel, ok := expr.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "r" && sel.Sel.Name == "DispatchEligible" {
				return true
			}
		}
	}

	// Call to <expr>.DispatchEligible() with no arguments and no other operators
	// (including decision.Decision{}.DispatchEligible() or verdict.DispatchEligible())
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 0 {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "DispatchEligible" {
			return true
		}
	}

	return false
}

func checkFileAST(fileAst *ast.File, path string) []string {
	var errs []string

	importMap := make(map[string]string)
	for _, imp := range fileAst.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: failed to unquote import path: %v", path, err))
			continue
		}

		if imp.Name != nil && imp.Name.Name == "." {
			errs = append(errs, fmt.Sprintf("%s: dot import %q is forbidden", path, importPath))
		}
		if imp.Name != nil && imp.Name.Name == "_" && importPath != "embed" {
			errs = append(errs, fmt.Sprintf("%s: blank import %q is forbidden (only embed permitted)", path, importPath))
		}

		if !allowedImports[importPath] {
			errs = append(errs, fmt.Sprintf("%s: import %q is not in the allowlist", path, importPath))
		}

		alias := filepath.Base(importPath)
		if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
			alias = imp.Name.Name
		}
		importMap[alias] = importPath
	}

	for _, decl := range fileAst.Decls {
		inRunFixtures := false
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "RunFixtures" {
			inRunFixtures = true
		}

		ast.Inspect(decl, func(node ast.Node) bool {
			// Selector checks
			if sel, ok := node.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					pkgPath := importMap[ident.Name]
					if pkgPath == "os" && !allowedOSSelectors[sel.Sel.Name] {
						errs = append(errs, fmt.Sprintf("%s: forbidden selector os.%s", path, sel.Sel.Name))
					}
					if pkgPath == "syscall" && !allowedSyscallSelectors[sel.Sel.Name] {
						errs = append(errs, fmt.Sprintf("%s: forbidden selector syscall.%s", path, sel.Sel.Name))
					}
					if pkgPath == "net" && strings.HasPrefix(sel.Sel.Name, "Dial") {
						errs = append(errs, fmt.Sprintf("%s: forbidden selector net.%s", path, sel.Sel.Name))
					}
					if pkgPath == "net/http" && !isAllowedHTTPSelector(sel.Sel.Name) {
						errs = append(errs, fmt.Sprintf("%s: forbidden selector http.%s (not in allowlist)", path, sel.Sel.Name))
					}
				}
			}

			// Composite literal check: setting DispatchEligible field
			if lit, ok := node.(*ast.CompositeLit); ok {
				for _, elt := range lit.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "DispatchEligible" {
							if !isAllowedDispatchEligibleRHS(kv.Value, inRunFixtures) {
								errs = append(errs, fmt.Sprintf("%s: composite literal sets DispatchEligible without allowed right-hand side (<expr>.DispatchEligible(), decision.Decision{}.DispatchEligible(), or r.DispatchEligible in RunFixtures)", path))
							}
						}
					}
				}
			}

			// Assignment check: assigning to DispatchEligible field
			if assign, ok := node.(*ast.AssignStmt); ok {
				for i, lhs := range assign.Lhs {
					setsField := false
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "DispatchEligible" {
						setsField = true
					} else if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "DispatchEligible" {
						setsField = true
					}
					if setsField && i < len(assign.Rhs) {
						if !isAllowedDispatchEligibleRHS(assign.Rhs[i], inRunFixtures) {
							errs = append(errs, fmt.Sprintf("%s: assignment sets DispatchEligible without allowed right-hand side (<expr>.DispatchEligible(), decision.Decision{}.DispatchEligible(), or r.DispatchEligible in RunFixtures)", path))
						}
					}
				}
			}

			return true
		})
	}

	return errs
}

func checkAssetURLString(s string) (bool, string) {
	schemeRE := regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?):`)
	if match := schemeRE.FindString(s); match != "" {
		return false, fmt.Sprintf("URL scheme %q", match)
	}
	jsSchemeRE := regexp.MustCompile(`(?i)\bjavascript:`)
	if match := jsSchemeRE.FindString(s); match != "" {
		return false, fmt.Sprintf("javascript scheme %q", match)
	}
	protoRelativeRE := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']?\s*//|url\(\s*["']?\s*//`)
	if match := protoRelativeRE.FindString(s); match != "" {
		return false, fmt.Sprintf("protocol-relative URL %q", match)
	}
	return true, ""
}

func TestStaticSafetyGuardsPlayground(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))

	dirs := []string{
		filepath.Join(repo, "internal/playground"),
		filepath.Join(repo, "cmd/guardfil-playground"),
	}

	fset := token.NewFileSet()

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("failed to read dir %s: %v", dir, err)
		}

		goFilesCount := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			goFilesCount++
			path := filepath.Join(dir, entry.Name())
			fileAst, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", path, err)
			}

			errs := checkFileAST(fileAst, path)
			for _, e := range errs {
				t.Errorf("static safety guard failure: %s", e)
			}
		}
		if goFilesCount == 0 {
			t.Fatalf("no non-test .go files found in %s", dir)
		}
	}

	// Assert no file in internal/playground/web references a URL scheme, protocol-relative //, or javascript:
	webDir := filepath.Join(repo, "internal/playground/web")
	webEntries, err := os.ReadDir(webDir)
	if err != nil {
		t.Fatalf("failed to read web dir: %v", err)
	}
	for _, entry := range webEntries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(webDir, entry.Name()))
		if err != nil {
			t.Fatalf("failed to read %s: %v", entry.Name(), err)
		}
		ok, reason := checkAssetURLString(string(content))
		if !ok {
			t.Fatalf("file %s in internal/playground/web violates asset safety: %s", entry.Name(), reason)
		}
	}
}

func TestStaticGuardSelfTestProvesRulesFire(t *testing.T) {
	fset := token.NewFileSet()
	mustParse := func(src string) *ast.File {
		f, err := parser.ParseFile(fset, "test_snippet.go", src, 0)
		if err != nil {
			t.Fatalf("parse snippet failed: %v\nsource:\n%s", err, src)
		}
		return f
	}

	tests := []struct {
		name          string
		snippet       string
		wantErrSubstr string
	}{
		{
			name:          "disallowed import",
			snippet:       `package p; import "net/http/httputil"; func f() {}`,
			wantErrSubstr: "is not in the allowlist",
		},
		{
			name:          "dot import",
			snippet:       `package p; import . "fmt"; func f() {}`,
			wantErrSubstr: "dot import",
		},
		{
			name:          "blank import not embed",
			snippet:       `package p; import _ "net/http"; func f() {}`,
			wantErrSubstr: "blank import",
		},
		{
			name:          "forbidden os selector",
			snippet:       `package p; import "os"; func f() { os.StartProcess("a", nil, nil) }`,
			wantErrSubstr: "forbidden selector os.StartProcess",
		},
		{
			name:          "forbidden syscall selector",
			snippet:       `package p; import "syscall"; func f() { _ = syscall.Getpid() }`,
			wantErrSubstr: "forbidden selector syscall.Getpid",
		},
		{
			name:          "forbidden net.Dial",
			snippet:       `package p; import "net"; func f() { _, _ = net.Dial("tcp", "127.0.0.1:80") }`,
			wantErrSubstr: "forbidden selector net.Dial",
		},
		{
			name:          "composite literal DispatchEligible false",
			snippet:       `package p; type R struct { DispatchEligible bool }; func f() { _ = R{DispatchEligible: false} }`,
			wantErrSubstr: "without allowed right-hand side",
		},
		{
			name:          "composite literal DispatchEligible true",
			snippet:       `package p; type R struct { DispatchEligible bool }; func f() { _ = R{DispatchEligible: true} }`,
			wantErrSubstr: "without allowed right-hand side",
		},
		{
			name:          "assignment DispatchEligible false",
			snippet:       `package p; type R struct { DispatchEligible bool }; func f() { var r R; r.DispatchEligible = false }`,
			wantErrSubstr: "without allowed right-hand side",
		},
		{
			name:          "assignment DispatchEligible true",
			snippet:       `package p; type R struct { DispatchEligible bool }; func f() { var r R; r.DispatchEligible = true }`,
			wantErrSubstr: "without allowed right-hand side",
		},
		{
			name:          "assignment DispatchEligible true || d.DispatchEligible()",
			snippet:       `package p; import "github.com/reviaro/guardfil/internal/decision"; type R struct { DispatchEligible bool }; func f(d decision.Decision) { var x R; x.DispatchEligible = true || d.DispatchEligible() }`,
			wantErrSubstr: "without allowed right-hand side",
		},
		{
			name:          "assignment DispatchEligible !d.DispatchEligible()",
			snippet:       `package p; import "github.com/reviaro/guardfil/internal/decision"; type R struct { DispatchEligible bool }; func f(d decision.Decision) { var x R; x.DispatchEligible = !d.DispatchEligible() }`,
			wantErrSubstr: "without allowed right-hand side",
		},
		{
			name:          "forbidden selector http.Get",
			snippet:       `package p; import "net/http"; func f() { http.Get("x") }`,
			wantErrSubstr: "forbidden selector http.Get",
		},
		{
			name:          "forbidden selector http.FileServer and http.Dir",
			snippet:       `package p; import "net/http"; func f() { http.FileServer(http.Dir("/")) }`,
			wantErrSubstr: "forbidden selector http.FileServer",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fileAst := mustParse(tc.snippet)
			errs := checkFileAST(fileAst, "snippet.go")
			if len(errs) == 0 {
				t.Fatalf("expected rule to fire for %s, but got 0 errors", tc.name)
			}
			found := false
			for _, e := range errs {
				if strings.Contains(e, tc.wantErrSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErrSubstr, errs)
			}
		})
	}

	// Positive test: valid DispatchEligible calls and allowlisted selectors pass without error
	validSnippet := `package p
import (
	"context"
	"net"
	"net/http"
	"os"
	"syscall"
	"github.com/reviaro/guardfil/internal/decision"
)
type R struct { DispatchEligible bool }
type MockRow struct { DispatchEligible bool }
type MockPlayground struct{}
func (p *MockPlayground) RunFixtures() {
	var r MockRow
	_ = R{DispatchEligible: r.DispatchEligible}
	var res R
	res.DispatchEligible = r.DispatchEligible
}
func f(ctx context.Context, d decision.Decision) {
	_ = R{DispatchEligible: d.DispatchEligible()}
	_ = R{DispatchEligible: decision.Decision{}.DispatchEligible()}
	var r R
	r.DispatchEligible = d.DispatchEligible()
	_ = syscall.SIGTERM
	_ = os.Interrupt
	_, _ = net.Listen("tcp", "127.0.0.1:0")
	var _ http.Handler
	var _ http.ResponseWriter
	_ = http.StatusOK
	_ = http.MethodPost
}
`
	validAst := mustParse(validSnippet)
	if errs := checkFileAST(validAst, "valid.go"); len(errs) > 0 {
		t.Fatalf("valid snippet had unexpected errors: %v", errs)
	}

	// Asset safety self-test
	assetTests := []struct {
		name    string
		input   string
		wantBad bool
	}{
		{"protocol relative href", `<a href="//evil.com">link</a>`, true},
		{"protocol relative src", `<script src="//evil.com/app.js"></script>`, true},
		{"protocol relative url", `div { background: url(//evil.com/pic.png); }`, true},
		{"javascript scheme", `<a href="javascript:alert(1)">click</a>`, true},
		{"valid local asset", `<link rel="stylesheet" href="/app.css">`, false},
		{"valid data icon", `<link rel="icon" href="data:,">`, false},
	}
	for _, at := range assetTests {
		ok, reason := checkAssetURLString(at.input)
		if at.wantBad && ok {
			t.Fatalf("expected asset scanner to reject %s, but was accepted", at.name)
		}
		if !at.wantBad && !ok {
			t.Fatalf("expected asset scanner to accept %s, but rejected: %s", at.name, reason)
		}
	}
}
