package advisorydemo

import (
	"bytes"
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
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/identity"
)

func TestFixturesUseKernelAndRemainAdvisory(t *testing.T) {
	results, err := EvaluateAll()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := fixtureSet()
	if len(results) != len(fixtures) {
		t.Fatalf("got %d results for %d fixtures", len(results), len(fixtures))
	}
	for i, got := range results {
		want := fixtures[i]
		if !got.Synthetic || got.Effect != want.ExpectedEffect || got.Stage != want.ExpectedStage || got.Auth != want.ExpectedAuth || got.Reason != want.ExpectedReason || got.DispatchEligible {
			t.Fatalf("fixture mismatch: %+v", got)
		}
	}
}

func TestCredentialsCoexistAndFailClosed(t *testing.T) {
	engine, registry, _, err := kernel()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	valid, err := registry.Authenticate(validSecret, "data", "synthetic", "tool.invoke", now)
	if err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}
	actor, err := action.ProjectActor(valid)
	if err != nil {
		t.Fatal(err)
	}
	actCtx, err := demoRegistry.Context(action.Advisory, "synthetic-profile", "route-tool-invoke")
	if err != nil {
		t.Fatal(err)
	}
	env, err := action.NewEnvelope(demoClock{now: now}, demoIDSource{id: "test-act"}, "test-req", "", "", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := action.NormalizeAction(actCtx, actor, "fake.read_note", []byte(`{"note_id":"synthetic-note-credential"}`), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := engine.Authorize(t.Context(), normalized, valid)
	if err != nil || allowed.Effect != decision.ALLOW || allowed.DispatchEligible() {
		t.Fatalf("valid credential did not yield advisory allow: verdict=%+v err=%v", allowed, err)
	}
	if _, err := registry.Authenticate(validSecret, "data", "synthetic", "shell.execute", now); err == nil {
		t.Fatal("valid credential scope unexpectedly authorized shell.execute")
	}
	expired, err := registry.Authenticate(expiredSecret, "data", "synthetic", "tool.invoke", now)
	if err == nil {
		t.Fatal("expired credential authenticated")
	}
	expiredVerdict, err := engine.Authorize(t.Context(), normalized, expired)
	if expiredVerdict.Effect != decision.BLOCK || expiredVerdict.Code() != failure.IDENTITY_UNTRUSTED || expiredVerdict.Stage != failure.StageAuth || expiredVerdict.DispatchEligible() {
		t.Fatalf("expired credential was not fail-closed: verdict=%+v err=%v", expiredVerdict, err)
	}
	key := bytes.Repeat([]byte{0x53}, 32)
	credential := identity.Credential{ID: "duplicate", TenantID: "synthetic", PrincipalID: "demo", Audience: "data", Scopes: demoScopes(), IssuedAt: now.Add(-nowWindow), ExpiresAt: now.Add(nowWindow), Revision: 1, Verifier: identity.Verifier(key, []byte("duplicate-secret-012345678901234567890123456789"))}
	duplicateID := credential
	duplicateID.Verifier = identity.Verifier(key, []byte("other-secret-012345678901234567890123456789012"))
	if _, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credential, duplicateID}, demoResourceSets()); err == nil {
		t.Fatal("duplicate credential ID admitted")
	}
	duplicateVerifier := credential
	duplicateVerifier.ID = "other"
	if _, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{credential, duplicateVerifier}, demoResourceSets()); err == nil {
		t.Fatal("duplicate credential verifier admitted")
	}
}

func TestRedTeamFixturesFailClosed(t *testing.T) {
	results, err := EvaluateAll()
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"duplicate-json-key": false, "non-utf8-payload": false, "nesting-over-limit": false, "numeric-negative-zero": false, "numeric-exponent-out-of-range": false, "numeric-unsafe-integer": false, "case-variant-tool": false, "unicode-lookalike-tool": false, "no-matching-policy": false, "expired-credential": false, "zero-deadline": false}
	for _, result := range results {
		if _, ok := required[result.FixtureID]; ok {
			required[result.FixtureID] = true
			if result.Effect != decision.BLOCK || result.DispatchEligible {
				t.Fatalf("red-team fail-open: %+v", result)
			}
		}
	}
	for id, seen := range required {
		if !seen {
			t.Fatalf("missing %s", id)
		}
	}
}

func TestGoldenReport(t *testing.T) {
	const expected = `SYNTHETIC FIXTURES - NOT REAL AGENT TRAFFIC
ADVISORY ONLY - ALLOW IS DIAGNOSTIC; NOTHING IS DISPATCHED
"synthetic": true fixture=allow-read fake_tool=fake.read_note fake_tool_known=true auth=ok stage=- effect=ALLOW kernel_reason=POLICY_ALLOWED action_digest=sha256:<bound> policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=block-delete fake_tool=fake.delete_record fake_tool_known=true auth=ok stage=policy effect=BLOCK kernel_reason=POLICY_DENIED action_digest=sha256:<bound> policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=unknown-tool fake_tool=fake.unknown_tool fake_tool_known=false auth=ok stage=normalize effect=BLOCK kernel_reason=TOOL_REVISION_UNKNOWN action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=malformed-payload fake_tool=fake.read_note fake_tool_known=true auth=not_attempted stage=parse effect=BLOCK kernel_reason=PARSE_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=schema-violation fake_tool=fake.read_note fake_tool_known=true auth=not_attempted stage=normalize effect=BLOCK kernel_reason=SCHEMA_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=unknown-identity fake_tool=fake.send_message fake_tool_known=true auth=AUTH_INVALID stage=auth effect=BLOCK kernel_reason=AUTH_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=engine-cancelled fake_tool=fake.read_note fake_tool_known=true auth=ok stage=policy effect=BLOCK kernel_reason=CANCELLED action_digest=sha256:<bound> policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=empty-payload fake_tool=fake.read_note fake_tool_known=true auth=not_attempted stage=parse effect=BLOCK kernel_reason=PARSE_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=oversized-payload fake_tool=fake.read_note fake_tool_known=true auth=not_attempted stage=parse effect=BLOCK kernel_reason=LIMIT_EXCEEDED action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=duplicate-json-key fake_tool=fake.read_note fake_tool_known=true auth=not_attempted stage=parse effect=BLOCK kernel_reason=PARSE_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=non-utf8-payload fake_tool=fake.read_note fake_tool_known=true auth=not_attempted stage=parse effect=BLOCK kernel_reason=PARSE_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=nesting-over-limit fake_tool=fake.read_note fake_tool_known=true auth=not_attempted stage=parse effect=BLOCK kernel_reason=LIMIT_EXCEEDED action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=numeric-negative-zero fake_tool=fake.numeric_note fake_tool_known=true auth=not_attempted stage=normalize effect=BLOCK kernel_reason=DECIMAL_LITERAL_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=numeric-exponent-out-of-range fake_tool=fake.numeric_note fake_tool_known=true auth=not_attempted stage=normalize effect=BLOCK kernel_reason=DECIMAL_LITERAL_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=numeric-unsafe-integer fake_tool=fake.numeric_note fake_tool_known=true auth=not_attempted stage=normalize effect=BLOCK kernel_reason=SCHEMA_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=case-variant-tool fake_tool=fake.Read_note fake_tool_known=false auth=not_attempted stage=normalize effect=BLOCK kernel_reason=SCHEMA_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=unicode-lookalike-tool fake_tool=fake.reаd_note fake_tool_known=false auth=not_attempted stage=normalize effect=BLOCK kernel_reason=SCHEMA_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=no-matching-policy fake_tool=fake.send_message fake_tool_known=true auth=ok stage=policy effect=BLOCK kernel_reason=POLICY_DENIED action_digest=sha256:<bound> policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=expired-credential fake_tool=fake.read_note fake_tool_known=true auth=AUTH_INVALID stage=auth effect=BLOCK kernel_reason=AUTH_INVALID action_digest=- policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
"synthetic": true fixture=zero-deadline fake_tool=fake.read_note fake_tool_known=true auth=ok stage=policy effect=BLOCK kernel_reason=DEADLINE_EXCEEDED action_digest=sha256:<bound> policy_digest=sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071 policy_revision=1 dispatch_eligible=false
`
	var report bytes.Buffer
	if err := Run(&report); err != nil {
		t.Fatal(err)
	}
	reDigest := regexp.MustCompile(`action_digest=sha256:[0-9a-f]{64}`)
	normalizedReport := reDigest.ReplaceAllString(report.String(), "action_digest=sha256:<bound>")
	if normalizedReport != expected {
		t.Fatalf("golden report mismatch (-want +got):\n%s", normalizedReport)
	}

	results, err := EvaluateAll()
	if err != nil {
		t.Fatal(err)
	}

	// (a) every authenticated fixture that reaches Authorize has a well-formed digest
	// (b) the five digest-bearing fixtures' digests are pairwise distinct except where payload/tool/fixture inputs are identical
	reWellFormed := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	digests := make(map[string]string)
	for _, res := range results {
		if res.ActionDigest != "" && res.ActionDigest != "-" {
			if !reWellFormed.MatchString(res.ActionDigest) {
				t.Fatalf("fixture %s reached Authorize but has malformed digest: %q", res.FixtureID, res.ActionDigest)
			}
			if prev, dup := digests[res.ActionDigest]; dup {
				t.Fatalf("expected distinct digests for fixtures with distinct inputs, but %s and %s shared digest %s", prev, res.FixtureID, res.ActionDigest)
			}
			digests[res.ActionDigest] = res.FixtureID
		} else {
			if res.ActionDigest != "" && res.ActionDigest != "-" {
				t.Fatalf("fixture %s did not reach Authorize but has digest: %q", res.FixtureID, res.ActionDigest)
			}
		}
	}
	if len(digests) != 5 {
		t.Fatalf("expected 5 digest-bearing fixtures reaching Authorize, got %d", len(digests))
	}

	// (c) running EvaluateAll twice within the same second yields identical digests
	var r1, r2 []Result
	var matched bool
	for attempt := 0; attempt < 5; attempt++ {
		t1 := time.Now().UTC().Truncate(time.Second)
		r1, err = EvaluateAll()
		if err != nil {
			t.Fatal(err)
		}
		r2, err = EvaluateAll()
		if err != nil {
			t.Fatal(err)
		}
		t2 := time.Now().UTC().Truncate(time.Second)
		if t1 == t2 {
			matched = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !matched {
		t.Skip("could not run twice within one second")
	}
	if len(r1) != len(r2) {
		t.Fatalf("EvaluateAll within same second returned different count of results: len(r1)=%d, len(r2)=%d", len(r1), len(r2))
	}
	for i := range r1 {
		if r1[i].ActionDigest != r2[i].ActionDigest {
			t.Fatalf("EvaluateAll within same second yielded different digests for %s: %q vs %q", r1[i].FixtureID, r1[i].ActionDigest, r2[i].ActionDigest)
		}
	}
}

func TestNoCredentialWindowFixedCalendarDate(t *testing.T) {
	_, reg, _, err := kernel()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	// Valid credential is valid at current time.Now(), but not in the distant past or future (e.g. 100 days apart)
	if _, err := reg.Authenticate(validSecret, "data", "synthetic", "tool.invoke", now); err != nil {
		t.Fatalf("valid credential failed authentication at time.Now(): %v", err)
	}
	if _, err := reg.Authenticate(validSecret, "data", "synthetic", "tool.invoke", now.Add(100*24*time.Hour)); err == nil {
		t.Fatal("valid credential unexpectedly succeeded 100 days in future; credential window must be relative to time.Now(), not open indefinitely")
	}
	if _, err := reg.Authenticate(validSecret, "data", "synthetic", "tool.invoke", now.Add(-100*24*time.Hour)); err == nil {
		t.Fatal("valid credential unexpectedly succeeded 100 days in past; credential window must be relative to time.Now(), not open indefinitely")
	}

	// Expired credential is expired relative to current time.Now()
	if _, err := reg.Authenticate(expiredSecret, "data", "synthetic", "tool.invoke", now); err == nil {
		t.Fatal("expired credential unexpectedly authenticated at time.Now()")
	}

	// Statically inspect AST of all non-test .go files in internal/advisorydemo
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	dir := filepath.Dir(file)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		checked++
		filePath := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatal(err)
		}
		violations, err := timeSelectorViolations(string(content))
		if err != nil {
			t.Fatalf("parse error in %s: %v", entry.Name(), err)
		}
		if len(violations) > 0 {
			t.Fatalf("%s contains unallowlisted time selector(s): %v; fixed instants must not be constructed and credential windows must be relative to time.Now()", entry.Name(), violations)
		}
	}
	if checked == 0 {
		t.Fatal("no non-test .go files found to inspect in internal/advisorydemo")
	}
}

func TestStaticSafetyGuards(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	assertImports(t, filepath.Join(repo, "internal/advisorydemo"), map[string]bool{"bytes": true, "context": true, "fmt": true, "io": true, "strings": true, "time": true, "github.com/reviaro/guardfil/internal/action": true, "github.com/reviaro/guardfil/internal/decision": true, "github.com/reviaro/guardfil/internal/identity": true, "github.com/reviaro/guardfil/internal/policy": true})
	assertImports(t, filepath.Join(repo, "cmd/guardfil-advisory-demo"), map[string]bool{"fmt": true, "os": true, "github.com/reviaro/guardfil/internal/advisorydemo": true})
	assertOSSelectorViolation(t, `package main; import "os"; func main() { _ = os.StartProcess }`)
	assertOSSelectorViolation(t, `package main; import "os"; func main() { _, _ = os.Open("x") }`)
	if violations, err := osSelectorViolations(`package main; import "os"; func main() { _ = os.Stdout; _ = os.Stderr; os.Exit(1) }`); err != nil || len(violations) != 0 {
		t.Fatalf("allowed os selector rejected: violations=%v err=%v", violations, err)
	}
	if violations, err := osSelectorViolationsInDir(filepath.Join(repo, "cmd/guardfil-advisory-demo")); err != nil || len(violations) != 0 {
		t.Fatalf("command os selector guard failed: violations=%v err=%v", violations, err)
	}
	entries, err := os.ReadDir(filepath.Join(repo, "internal/advisorydemo"))
	if err != nil {
		t.Fatal(err)
	}
	reason := regexp.MustCompile(`^[A-Z][A-Z_]+$`)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repo, "internal/advisorydemo", entry.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "fixtureSet" {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				if reason.MatchString(value) && value != demoFailClosed {
					t.Fatalf("non-fixture reason literal %q", value)
				}
				return true
			})
		}
	}
}

func TestOSSelectorImportAliasGuards(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantFlagged bool
		wantSubstr  string
	}{
		{
			name:        "aliased import proc with unallowed StartProcess",
			source:      `package p; import proc "os"; func f() { _ = proc.StartProcess }`,
			wantFlagged: true,
			wantSubstr:  "os.StartProcess",
		},
		{
			name:        "aliased import proc with unallowed Open",
			source:      `package p; import proc "os"; func f() { _, _ = proc.Open("x") }`,
			wantFlagged: true,
			wantSubstr:  "os.Open",
		},
		{
			name:        "aliased import proc with allowlisted members only",
			source:      `package p; import proc "os"; func f() { _ = proc.Stdout; _ = proc.Stderr; proc.Exit(1) }`,
			wantFlagged: false,
		},
		{
			name:        "dot import of os",
			source:      `package p; import . "os"; func f() {}`,
			wantFlagged: true,
			wantSubstr:  "os: dot import",
		},
		{
			name:        "plain os import with unallowed Open",
			source:      `package p; import "os"; func f() { _, _ = os.Open("x") }`,
			wantFlagged: true,
			wantSubstr:  "os.Open",
		},
		{
			name:        "plain os import with allowlisted members only",
			source:      `package p; import "os"; func f() { _ = os.Stdout; _ = os.Stderr; os.Exit(1) }`,
			wantFlagged: false,
		},
		{
			name:        "blank import of os",
			source:      `package p; import _ "os"; func f() {}`,
			wantFlagged: false,
		},
		{
			name:        "file without os import with unrelated local os selector",
			source:      `package p; func f() { var os struct{ Open func() }; os.Open() }`,
			wantFlagged: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations, err := osSelectorViolations(tc.source)
			if err != nil {
				t.Fatalf("unexpected parse error for %q: %v", tc.source, err)
			}
			if tc.wantFlagged {
				if len(violations) == 0 {
					t.Fatalf("expected violation for %q, got none", tc.source)
				}
				if tc.wantSubstr != "" {
					found := false
					for _, v := range violations {
						if strings.Contains(v, tc.wantSubstr) {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("expected violation containing %q for %q, got %v", tc.wantSubstr, tc.source, violations)
					}
				}
			} else {
				if len(violations) != 0 {
					t.Fatalf("unexpected violations %v for %q", violations, tc.source)
				}
			}
		})
	}
}

func assertOSSelectorViolation(t *testing.T, source string) {
	t.Helper()
	violations, err := osSelectorViolations(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) == 0 {
		t.Fatalf("missing os selector violation for %q", source)
	}
}

func osSelectorViolations(source string) ([]string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "in-memory.go", source, 0)
	if err != nil {
		return nil, err
	}
	return osSelectorViolationsInFile(parsed), nil
}

func osSelectorViolationsInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			return nil, err
		}
		violations = append(violations, osSelectorViolationsInFile(parsed)...)
	}
	return violations, nil
}

func osSelectorViolationsInFile(parsed *ast.File) []string {
	aliases := make(map[string]bool)
	var violations []string
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || path != "os" {
			continue
		}
		if imported.Name == nil {
			aliases["os"] = true
		} else {
			switch imported.Name.Name {
			case "_":
			case ".":
				violations = append(violations, "os: dot import")
			default:
				aliases[imported.Name.Name] = true
			}
		}
	}
	if len(aliases) == 0 {
		return violations
	}
	allowed := map[string]bool{"Stdout": true, "Stderr": true, "Exit": true}
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		packageName, ok := selector.X.(*ast.Ident)
		if ok && aliases[packageName.Name] && !allowed[selector.Sel.Name] {
			violations = append(violations, "os."+selector.Sel.Name)
		}
		return true
	})
	return violations
}

func assertImports(t *testing.T, dir string, allowed map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		count++
		path := filepath.Join(dir, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !allowed[name] {
				t.Fatalf("unallowlisted import %q in %s", name, path)
			}
		}
	}
	if count == 0 {
		t.Fatalf("no non-test Go files in %s", dir)
	}
}

func TestTimeSelectorGuard(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantFlagged bool
	}{
		{
			name:        "package-level var with time.Date",
			source:      `package p; import "time"; var x = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)`,
			wantFlagged: true,
		},
		{
			name:        "aliased import tm with tm.Date",
			source:      `package p; import tm "time"; func f() { _ = tm.Date(2026, 1, 1, 0, 0, 0, 0, tm.UTC) }`,
			wantFlagged: true,
		},
		{
			name:        "dot import of time",
			source:      `package p; import . "time"; func f() {}`,
			wantFlagged: true,
		},
		{
			name:        "time.Now only",
			source:      `package p; import "time"; func f() { _ = time.Now() }`,
			wantFlagged: false,
		},
		{
			name:        "var mk = time.Date function value",
			source:      `package p; import "time"; var mk = time.Date`,
			wantFlagged: true,
		},
		{
			name:        "time.Unix call",
			source:      `package p; import "time"; func f() { _ = time.Unix(1767225600, 0) }`,
			wantFlagged: true,
		},
		{
			name:        "time.Parse call",
			source:      `package p; import "time"; func f() { _, _ = time.Parse(time.RFC3339, "2026-01-01T00:00:00Z") }`,
			wantFlagged: true,
		},
		{
			name:        "aliased tm.Unix call",
			source:      `package p; import tm "time"; func f() { _ = tm.Unix(0, 0) }`,
			wantFlagged: true,
		},
		{
			name:        "time.Now.Add with 24*time.Hour",
			source:      `package p; import "time"; func f() { _ = time.Now().Add(24 * time.Hour) }`,
			wantFlagged: false,
		},
		{
			name:        "var _ time.Duration = time.Minute",
			source:      `package p; import "time"; var _ time.Duration = time.Minute`,
			wantFlagged: false,
		},
		{
			name:        "func signature with time.Time",
			source:      `package p; import "time"; func f(t time.Time) {}`,
			wantFlagged: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations, err := timeSelectorViolations(tc.source)
			if err != nil {
				t.Fatalf("unexpected parse error for %q: %v", tc.source, err)
			}
			if tc.wantFlagged {
				if len(violations) == 0 {
					t.Fatalf("expected violation for %q, got none", tc.source)
				}
			} else {
				if len(violations) != 0 {
					t.Fatalf("unexpected violations %v for %q", violations, tc.source)
				}
			}
		})
	}
}

func timeSelectorViolations(src string) ([]string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "in-memory.go", src, 0)
	if err != nil {
		return nil, err
	}
	return timeSelectorViolationsInFile(parsed), nil
}

func timeSelectorViolationsInFile(parsed *ast.File) []string {
	aliases := make(map[string]bool)
	var violations []string
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || path != "time" {
			continue
		}
		if imported.Name == nil {
			aliases["time"] = true
		} else {
			switch imported.Name.Name {
			case "_":
			case ".":
				violations = append(violations, "time: dot import")
			default:
				aliases[imported.Name.Name] = true
			}
		}
	}
	if len(aliases) == 0 {
		return violations
	}
	allowed := map[string]bool{
		"Now":         true,
		"Time":        true,
		"Duration":    true,
		"Hour":        true,
		"Minute":      true,
		"Second":      true,
		"Millisecond": true,
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		packageName, ok := selector.X.(*ast.Ident)
		if ok && aliases[packageName.Name] && !allowed[selector.Sel.Name] {
			violations = append(violations, "time."+selector.Sel.Name)
		}
		return true
	})
	return violations
}

func TestDemoDirsContainOnlyGoSources(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	assertDemoDirsContainOnlyAllowedEntries(t, repo)
}

func assertDemoDirsContainOnlyAllowedEntries(t *testing.T, repo string) {
	t.Helper()
	// internal/advisorydemo contains only *.go files; subdirectories are violations
	advisoryDir := filepath.Join(repo, "internal/advisorydemo")
	advisoryEntries, err := os.ReadDir(advisoryDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range advisoryEntries {
		if entry.IsDir() {
			t.Fatalf("internal/advisorydemo contains subdirectory %q; only *.go files allowed", entry.Name())
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			t.Fatalf("internal/advisorydemo contains disallowed entry %q; only *.go files allowed", entry.Name())
		}
	}

	// cmd/guardfil-advisory-demo contains only *.go files and README.md; subdirectories are violations
	cmdDir := filepath.Join(repo, "cmd/guardfil-advisory-demo")
	cmdEntries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range cmdEntries {
		if entry.IsDir() {
			t.Fatalf("cmd/guardfil-advisory-demo contains subdirectory %q; only *.go files and README.md allowed", entry.Name())
		}
		if !strings.HasSuffix(entry.Name(), ".go") && entry.Name() != "README.md" {
			t.Fatalf("cmd/guardfil-advisory-demo contains disallowed entry %q; only *.go files and README.md allowed", entry.Name())
		}
	}
}
