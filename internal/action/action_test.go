package action

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/identity"
	resourceid "github.com/reviaro/guardfil/internal/resource"
)

func TestNumericDigestVectorAndRejections(t *testing.T) {
	got, err := NumericFieldDigest("temperature", "0.10")
	if err != nil || got != "sha256:06f932bc398cc10f3d97a374d808d30f85c8446673017b99f689acb19ea60548" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := NumericFieldDigest("temperature", "-0.0"); err != ErrDecimal {
		t.Fatal(err)
	}
}
func TestCandidateRejectionsAndPreservation(t *testing.T) {
	s := Schema{Fields: map[string]FieldType{"n": Integer}}
	for _, raw := range []string{`{"n":1,"n":2}`, `{"x":1}`, `{"n":1e0}`, `{"n":9007199254740993}`} {
		if _, err := NormalizePayload("fs.read", []byte(raw), s); err == nil {
			t.Fatal(raw)
		}
	}
	a, e := NormalizePayload("fs.read", []byte(`{"n":0.10}`), Schema{Fields: map[string]FieldType{"n": Number}})
	if e != nil || string(a.Payload) != `{"n":0.10}` || !a.Valid() || a.Authorizable() {
		t.Fatalf("%s %v", a.Payload, e)
	}
}

func TestRejectsRepairedUTF8AndUnpairedSurrogates(t *testing.T) {
	schema := Schema{Fields: map[string]FieldType{"s": String}}
	for _, raw := range [][]byte{
		{'{', '"', 's', '"', ':', '"', 0xff, '"', '}'},
		[]byte(`{"s":"\ud800"}`),
		[]byte(`{"s":"\udc00"}`),
	} {
		if _, err := NormalizePayload("fs.read", raw, schema); !errors.Is(err, ErrParse) {
			t.Fatalf("expected ErrParse for repaired input %q, got: %v", raw, err)
		}
	}
	if _, err := NormalizePayload("fs.read", []byte(`{"s":"\ud83d\ude00"}`), schema); err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
}

func TestRegisteredRecursiveSchemaAndDepthBound(t *testing.T) {
	leaf := Field{Type: Object, Properties: map[string]Field{"name": {Type: String}, "count": {Type: Integer}}}
	schema := Schema{RecursiveFields: map[string]Field{"items": {Type: Array, Items: &leaf}}}
	if _, err := NormalizePayload("fs.read", []byte(`{"items":[{"name":"a","count":1}]}`), schema); err != nil {
		t.Fatalf("registered nested schema rejected: %v", err)
	}
	if _, err := NormalizePayload("fs.read", []byte(`{"items":[{"name":"a","unknown":1}]}`), schema); err == nil {
		t.Fatal("unknown nested field admitted")
	}
	node := &Field{Type: Array}
	node.Items = node
	deep := `{"items":` + strings.Repeat("[", 17) + `0` + strings.Repeat("]", 17) + `}`
	if _, err := NormalizePayload("fs.read", []byte(deep), Schema{RecursiveFields: map[string]Field{"items": *node}}); err == nil {
		t.Fatal("recursive schema exceeded bounded depth")
	}
}

func TestParserObjectAndStringBounds(t *testing.T) {
	fields := make([]string, 257)
	for i := range fields {
		fields[i] = `"k` + strconv.Itoa(i) + `":1`
	}
	if _, err := NormalizePayload("fs.read", []byte(`{`+strings.Join(fields, ",")+`}`), Schema{Fields: map[string]FieldType{}}); err == nil {
		t.Fatal("257-member object admitted")
	}
	if _, err := NormalizePayload("fs.read", []byte(`{"s":"`+strings.Repeat("x", (256<<10)+1)+`"}`), Schema{Fields: map[string]FieldType{"s": String}}); err == nil {
		t.Fatal("oversized string admitted")
	}
}

func testNormalizeActionWithResourceAndPayload(t *testing.T, resource string, payload []byte, schema Schema) (Action, error) {
	t.Helper()
	key := []byte("01234567890123456789012345678901")
	secret := "0123456789012345678901234567890123456789012"
	now := time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)
	cred := identity.Credential{
		ID:              "app-key-2",
		TenantID:        "acme",
		PrincipalID:     "coding-app",
		Audience:        "data",
		Scopes:          []identity.Scope{{Operation: "filesystem.read", ResourceSet: "workspace-read"}},
		IssuedAt:        time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 9, 25, 17, 0, 0, 0, time.UTC),
		Revision:        2,
		RevocationEpoch: 8,
		Verifier:        identity.Verifier(key, []byte(secret)),
	}
	idReg, err := identity.NewRegistryWithResourceSets(key, []identity.Credential{cred}, map[string][]identity.Resource{
		"workspace-read": {{Kind: "path", Value: "/work/**"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pCtx, err := idReg.Authenticate(secret, "data", "acme", "filesystem.read", now)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ProjectActor(pCtx)
	if err != nil {
		t.Fatal(err)
	}

	reg, err := NewRegistry(
		[]Profile{{Protocol: "decision_api", ProfileID: "prof-1", AdapterRevision: "sha256:" + strings.Repeat("a", 64)}},
		[]Route{{RouteID: "route-fs", ExecutorID: "exec-1", Operation: "fs.read", ResolutionProfile: "res-1", PayloadSchema: "ps-1", Schema: schema}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := reg.Context(Advisory, "prof-1", "route-fs")
	if err != nil {
		t.Fatal(err)
	}
	c := actionTestClock{now: time.Date(2026, 9, 24, 17, 0, 0, 0, time.UTC)}
	ids := actionTestIDSource{id: "act-1"}
	env, err := NewEnvelope(c, ids, "req-1", "", "", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return NormalizeAction(ctx, actor, resource, payload, env, nil)
}

type actionTestClock struct {
	now time.Time
}

func (c actionTestClock) Now() time.Time {
	return c.now
}

type actionTestIDSource struct {
	id string
}

func (s actionTestIDSource) NewID() (string, error) {
	return s.id, nil
}

func testActionHelper(t *testing.T) Action {
	t.Helper()
	a, err := testNormalizeActionWithResourceAndPayload(t, "/work/file", []byte(`{"n":1}`), Schema{Fields: map[string]FieldType{"n": Integer}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRequestBindingRejectsMutationAndForgery(t *testing.T) {
	// 1. NormalizeRequest produces a valid non-authorizable action with empty digest
	reqAct, err := NormalizeRequest("fs.read", "/work/file", []byte(`{"n":1}`), Schema{Fields: map[string]FieldType{"n": Integer}})
	if err != nil || !reqAct.Valid() || reqAct.Authorizable() || reqAct.Digest != "" {
		t.Fatalf("NormalizeRequest helper mismatch: %+v, %v", reqAct, err)
	}

	// 2. Authorizable Action produced by NormalizeAction
	a := testActionHelper(t)
	if !a.Authorizable() || a.TrustedOperation() != "fs.read" || a.TrustedResourceKind() != "path" || a.TrustedResource() != "/work/file" {
		t.Fatalf("trusted action: %+v", a)
	}

	mutated := a
	mutated.Resource = "/work/private/key"
	if mutated.Valid() || mutated.Authorizable() || mutated.TrustedDigest() != "" {
		t.Fatal("caller mutation retained trusted Action authority")
	}

	forged := Action{SchemaVersion: Version, Operation: "fs.read", Resource: "/work/file", Payload: []byte(`{"n":1}`), Digest: a.Digest}
	if forged.Valid() || forged.Authorizable() {
		t.Fatal("caller-provided Action digest established authority")
	}
}

func TestFilesystemSelectorNormalizationNeverAuthorizesAmbiguity(t *testing.T) {
	schema := Schema{Fields: map[string]FieldType{"n": Integer}}
	payload := []byte(`{"n":1}`)

	for _, selector := range []string{
		"/work/../private/key",
		"/work/./file",
		"/work//file",
	} {
		a, err := testNormalizeActionWithResourceAndPayload(t, selector, payload, schema)
		if err != nil {
			t.Fatalf("retain normalized rejection evidence for %q: %v", selector, err)
		}
		if !a.Valid() || a.Authorizable() || a.Digest != "" || a.TrustedDigest() != "" {
			t.Fatalf("ambiguous selector retained authority or digest: %q => %+v", selector, a)
		}
	}

	canonicalAct, err := testNormalizeActionWithResourceAndPayload(t, "/work/file", payload, schema)
	if err != nil || !canonicalAct.Valid() || !canonicalAct.Authorizable() || canonicalAct.Digest == "" {
		t.Fatalf("canonical selector failed to produce authorizable action: %+v, %v", canonicalAct, err)
	}

	for _, selector := range []string{
		"work/file",
		`/work\..\private`,
		"/work/%2e%2e/private",
	} {
		if _, err := testNormalizeActionWithResourceAndPayload(t, selector, payload, schema); err == nil {
			t.Fatalf("unsupported selector entered Action: %q", selector)
		}
	}
}

func TestURLSelectorRejectsEmptyQuery(t *testing.T) {
	schema := Schema{Fields: map[string]FieldType{"n": Integer}}
	if _, err := NormalizeRequest("http.request", "https://example.com/a?", []byte(`{"n":1}`), schema); err == nil {
		t.Fatal("empty-query URL entered Action")
	}
	a, err := NormalizeRequest("http.request", "https://example.com/a", []byte(`{"n":1}`), schema)
	if err != nil || !a.Valid() || a.Authorizable() || a.Digest != "" {
		t.Fatalf("canonical URL NormalizeRequest mismatch: %+v, %v", a, err)
	}
}

func TestCanonicalStringEncoderVectors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{`empty`, "", `""`},
		{`quote and backslash`, "a\"b\\c", `"a\"b\\c"`},
		{`nul`, "\x00", `"\u0000"`},
		{`newline`, "\n", `"\u000a"`},
		{`tab`, "\t", `"\u0009"`},
		{`us control`, "\x1f", `"\u001f"`},
		{`del raw byte`, "\x7f", "\"\x7f\""},
		{`html characters`, "a<b>&c", `"a<b>&c"`},
		{`separators`, "\u2028\u2029", "\"\u2028\u2029\""},
		{`slash`, "/", `"/"`},
		{`non-ascii scalar`, "é", `"é"`},
		{`invalid utf-8 byte preserved`, string("\xff"), string([]byte{'"', 0xff, '"'})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(appendCanonicalString(nil, tc.in))
			if got != tc.want {
				t.Fatalf("appendCanonicalString(nil, %q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizePayloadCanonicalStringEncoding(t *testing.T) {
	schema := Schema{Fields: map[string]FieldType{"s": String}}

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{`html characters`, `{"s":"a<b>&c"}`, `{"s":"a<b>&c"}`},
		{`u2028 raw bytes`, `{"s":"\u2028"}`, `{"s":"` + "\u2028" + `"}`},
		{`control escapes`, `{"s":"\u0008\u000c"}`, `{"s":"\u0008\u000c"}`},
		{`escaped slash`, `{"s":"\/"}`, `{"s":"/"}`},
		{`escaped quote and backslash`, `{"s":"\"\\"}`, `{"s":"\"\\"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NormalizePayload("fs.read", []byte(tc.raw), schema)
			if err != nil {
				t.Fatalf("NormalizePayload failed: %v", err)
			}
			if got := string(a.Payload); got != tc.want {
				t.Fatalf("Payload mismatch: got %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("object key", func(t *testing.T) {
		keySchema := Schema{Fields: map[string]FieldType{"a<b": String}}
		a, err := NormalizePayload("fs.read", []byte(`{"a\u003cb":"x"}`), keySchema)
		if err != nil {
			t.Fatalf("NormalizePayload failed: %v", err)
		}
		if got := string(a.Payload); got != `{"a<b":"x"}` {
			t.Fatalf("Payload mismatch: got %q, want %q", got, `{"a<b":"x"}`)
		}
	})

	act1, err1 := testNormalizeActionWithResourceAndPayload(t, "/work/file", []byte(`{"s":"\u00e9"}`), schema)
	if err1 != nil {
		t.Fatalf("NormalizeAction with \\u00e9 failed: %v", err1)
	}
	act2, err2 := testNormalizeActionWithResourceAndPayload(t, "/work/file", []byte(`{"s":"é"}`), schema)
	if err2 != nil {
		t.Fatalf("NormalizeAction with é failed: %v", err2)
	}
	if string(act1.Payload) != string(act2.Payload) {
		t.Fatalf("Payload mismatch for \\u00e9 and é: %q vs %q", act1.Payload, act2.Payload)
	}
	if act1.Digest == "" || act2.Digest == "" {
		t.Fatal("expected non-empty digests for authorizable actions")
	}
	if act1.Digest != act2.Digest {
		t.Fatalf("Digest mismatch for \\u00e9 and é: %q vs %q", act1.Digest, act2.Digest)
	}
}

// Newline and tab are allowed in values (multi-line commands and text); NUL
// and carriage return are refused, and so is any of them in a key.
func TestNormalizePayloadControlCharacters(t *testing.T) {
	schema := Schema{Fields: map[string]FieldType{"s": String}}
	for raw, want := range map[string]string{`{"s":"a\nb"}`: "a\nb", `{"s":"a\tb"}`: "a\tb"} {
		a, err := NormalizePayload("fs.read", []byte(raw), schema)
		var got struct{ S string }
		if err != nil || json.Unmarshal(a.Payload, &got) != nil || got.S != want {
			t.Fatalf("%s: got %q, %v", raw, a.Payload, err)
		}
	}
	for _, raw := range []string{`{"s":"a\rb"}`, `{"s":"a\u0000b"}`} {
		if _, err := NormalizePayload("fs.read", []byte(raw), schema); !errors.Is(err, ErrControl) {
			t.Fatalf("%s: got %v, want CONTROL_CHARACTER", raw, err)
		}
	}
	keySchema := Schema{Fields: map[string]FieldType{"a\nb": String}}
	if _, err := NormalizePayload("fs.read", []byte(`{"a\nb":"x"}`), keySchema); !errors.Is(err, ErrControl) {
		t.Fatalf("newline in a key: got %v, want CONTROL_CHARACTER", err)
	}
}

func TestActionOperationsAdmission(t *testing.T) {
	schema := Schema{Fields: map[string]FieldType{"n": Integer}}
	raw := []byte(`{"n":1}`)

	allSix := []string{"llm.request", "tool.invoke", "shell.execute", "fs.read", "fs.write", "http.request"}
	for _, op := range allSix {
		a, err := NormalizePayload(op, raw, schema)
		if err != nil {
			t.Fatalf("NormalizePayload rejected valid operation %q: %v", op, err)
		}
		if a.Authorizable() {
			t.Fatalf("NormalizePayload unexpectedly produced authorizable Action for %q", op)
		}
	}

	requestAdmitted := []struct {
		op       string
		selector string
	}{
		{"fs.read", "/work/file"},
		{"fs.write", "/work/file"},
		{"http.request", "https://example.com/api"},
		{"tool.invoke", "fake.read_note"},
	}
	for _, tc := range requestAdmitted {
		a, err := NormalizeRequest(tc.op, tc.selector, raw, schema)
		if err != nil || !a.Valid() || a.Authorizable() || a.Digest != "" {
			t.Fatalf("NormalizeRequest helper mismatch %q %q: %v, %+v", tc.op, tc.selector, err, a)
		}
	}

	for _, op := range []string{"llm.request", "shell.execute"} {
		if _, err := NormalizeRequest(op, "/work/file", raw, schema); err != ErrSchema {
			t.Fatalf("NormalizeRequest admitted %q without resource kind: %v", op, err)
		}
	}

	rejectedOps := []string{
		"filesystem.read",
		"http.get",
		"tool.read",
		"fs.readx",
		"FS.READ",
		" fs.read",
		"fs.read ",
		"",
	}
	for _, op := range rejectedOps {
		if _, err := NormalizePayload(op, raw, schema); err != ErrSchema {
			t.Fatalf("NormalizePayload admitted rejected operation %q: %v", op, err)
		}
		if _, err := NormalizeRequest(op, "/work/file", raw, schema); err != ErrSchema {
			t.Fatalf("NormalizeRequest admitted rejected operation %q: %v", op, err)
		}
	}
}

func TestSecurityOperation(t *testing.T) {
	cases := []struct {
		op     string
		want   string
		wantOK bool
	}{
		{"fs.read", "filesystem.read", true},
		{"fs.write", "filesystem.write", true},
		{"llm.request", "llm.request", true},
		{"tool.invoke", "tool.invoke", true},
		{"shell.execute", "shell.execute", true},
		{"http.request", "http.request", true},
		{"filesystem.read", "", false},
		{"http.get", "", false},
		{"tool.read", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := SecurityOperation(tc.op)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("SecurityOperation(%q) = (%q, %t), want (%q, %t)", tc.op, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestSecurityOperationImageMatchesResource(t *testing.T) {
	actionOps := []string{
		"fs.read",
		"fs.write",
		"llm.request",
		"tool.invoke",
		"shell.execute",
		"http.request",
	}
	securityOps := []string{
		"filesystem.read",
		"filesystem.write",
		"llm.request",
		"tool.invoke",
		"shell.execute",
		"http.request",
	}

	parsedActionCases := parseSecurityOperationSwitchCases(t, "action.go")
	parsedResourceCases := parseSecurityOperationSwitchCases(t, "../resource/resource.go")
	for _, op := range parsedActionCases {
		if _, ok := SecurityOperation(op); !ok {
			t.Errorf("parsed action case %q gave SecurityOperation ok==false", op)
		}
	}
	for _, op := range parsedResourceCases {
		if !resourceid.SecurityOperation(op) {
			t.Errorf("parsed resource case %q gave resourceid.SecurityOperation==false", op)
		}
	}
	assertEqualOpSets(t, "actionOps vs action.SecurityOperation", actionOps, parsedActionCases)
	assertEqualOpSets(t, "securityOps vs resource.SecurityOperation", securityOps, parsedResourceCases)

	image := make(map[string]struct{}, len(actionOps))
	for _, op := range actionOps {
		secOp, ok := SecurityOperation(op)
		if !ok {
			t.Fatalf("SecurityOperation(%q) not ok", op)
		}
		if !resourceid.SecurityOperation(secOp) {
			t.Errorf("image op %q not accepted by resource.SecurityOperation", secOp)
		}
		image[secOp] = struct{}{}
	}
	if len(image) != 6 {
		t.Fatalf("expected 6 distinct Security operations in image, got %d", len(image))
	}
	for _, secOp := range securityOps {
		if !resourceid.SecurityOperation(secOp) {
			t.Errorf("expected resource.SecurityOperation(%q) = true", secOp)
		}
		if _, ok := image[secOp]; !ok {
			t.Errorf("Security op %q missing from action.SecurityOperation image", secOp)
		}
	}
}

func TestKindForOperationMatchesSecurity(t *testing.T) {
	actionOps := []string{
		"fs.read",
		"fs.write",
		"llm.request",
		"tool.invoke",
		"shell.execute",
		"http.request",
	}

	parsedActionCases := parseSecurityOperationSwitchCases(t, "action.go")
	for _, op := range parsedActionCases {
		if _, ok := SecurityOperation(op); !ok {
			t.Errorf("parsed action case %q gave SecurityOperation ok==false", op)
		}
	}
	assertEqualOpSets(t, "actionOps vs action.SecurityOperation", actionOps, parsedActionCases)

	for _, op := range actionOps {
		secOp, ok := SecurityOperation(op)
		if !ok {
			t.Fatalf("SecurityOperation(%q) not ok", op)
		}
		if got, want := resourceid.KindForOperation(op), resourceid.KindForSecurityOperation(secOp); got != want {
			t.Errorf("KindForOperation(%q) = %q, want KindForSecurityOperation(%q) = %q", op, got, secOp, want)
		}
	}

	nonEnumStrings := []string{
		"filesystem.read",
		"http.get",
		"fs.readx",
		"",
	}
	for _, s := range nonEnumStrings {
		if got := resourceid.KindForOperation(s); got != "" {
			t.Errorf("KindForOperation(%q) = %q, want empty string", s, got)
		}
	}
}

func TestLimitAndParseDistinction(t *testing.T) {
	schema := Schema{Fields: map[string]FieldType{"s": String}}

	// Invalid UTF-8 in raw payload -> PARSE_INVALID (ErrParse)
	badUTF8 := []byte{'{', '"', 's', '"', ':', '"', 0xff, '"', '}'}
	if _, err := NormalizePayload("fs.read", badUTF8, schema); !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse for invalid UTF-8 in NormalizePayload, got %v", err)
	}
	if _, err := NormalizeRequest("fs.read", "/work/a", badUTF8, schema); !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse for invalid UTF-8 in NormalizeRequest, got %v", err)
	}

	// Raw payload size > 1MB (1<<20 bytes) -> LIMIT_EXCEEDED (ErrLimit)
	oversized := []byte(`{"s":"` + strings.Repeat("a", 1<<20) + `"}`)
	if _, err := NormalizePayload("fs.read", oversized, schema); !errors.Is(err, ErrLimit) {
		t.Fatalf("expected ErrLimit for raw payload > 1MB in NormalizePayload, got %v", err)
	}
	if _, err := NormalizeRequest("fs.read", "/work/a", oversized, schema); !errors.Is(err, ErrLimit) {
		t.Fatalf("expected ErrLimit for raw payload > 1MB in NormalizeRequest, got %v", err)
	}

	// Canonical output bound > 1MB (1<<20 bytes) with raw payload <= 1MB -> LIMIT_EXCEEDED (ErrLimit)
	// Raw payload contains escaped control characters (\b) which expand from 2 bytes in raw to 6 bytes in canonical form (\u0008).
	expandingRaw := []byte(`{"s":"` + strings.Repeat(`\b`, 200000) + `"}`)
	if len(expandingRaw) > 1<<20 {
		t.Fatalf("setup error: raw payload > 1MB: %d", len(expandingRaw))
	}
	if _, err := NormalizePayload("fs.read", expandingRaw, schema); !errors.Is(err, ErrLimit) {
		t.Fatalf("expected ErrLimit for canonical output > 1MB in NormalizePayload, got %v", err)
	}
	if _, err := NormalizeRequest("fs.read", "/work/a", expandingRaw, schema); !errors.Is(err, ErrLimit) {
		t.Fatalf("expected ErrLimit for canonical output > 1MB in NormalizeRequest, got %v", err)
	}
}

func parseSecurityOperationSwitchCases(t *testing.T, relPath string) []string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	targetPath := filepath.Clean(filepath.Join(filepath.Dir(file), relPath))
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, targetPath, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", targetPath, err)
	}

	var targetFunc *ast.FuncDecl
	for _, decl := range node.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "SecurityOperation" {
			targetFunc = fn
			break
		}
	}
	if targetFunc == nil {
		t.Fatalf("func SecurityOperation not found in %s", targetPath)
	}
	if targetFunc.Type.Params == nil || len(targetFunc.Type.Params.List) != 1 || len(targetFunc.Type.Params.List[0].Names) != 1 {
		t.Fatalf("expected func SecurityOperation in %s to have exactly one parameter", targetPath)
	}
	paramName := targetFunc.Type.Params.List[0].Names[0].Name

	if targetFunc.Body == nil || len(targetFunc.Body.List) != 1 {
		t.Fatalf("expected func SecurityOperation in %s to have exactly one statement in body", targetPath)
	}

	switchStmt, ok := targetFunc.Body.List[0].(*ast.SwitchStmt)
	if !ok {
		t.Fatalf("expected single statement in func SecurityOperation in %s to be a switch statement, got %T", targetPath, targetFunc.Body.List[0])
	}
	if switchStmt.Init != nil {
		t.Fatalf("expected switch in func SecurityOperation in %s to have no Init statement", targetPath)
	}
	tagIdent, ok := switchStmt.Tag.(*ast.Ident)
	if !ok || tagIdent == nil || tagIdent.Name != paramName {
		t.Fatalf("expected switch Tag in func SecurityOperation in %s to be bare *ast.Ident equal to parameter %q", targetPath, paramName)
	}

	var cases []string
	for _, stmt := range switchStmt.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if clause.List == nil || len(clause.List) == 0 {
			if len(clause.Body) != 1 {
				t.Fatalf("expected default clause in func SecurityOperation in %s to consist only of a single statement", targetPath)
			}
			retStmt, ok := clause.Body[0].(*ast.ReturnStmt)
			if !ok {
				t.Fatalf("expected default clause in func SecurityOperation in %s to consist only of a return, got %T", targetPath, clause.Body[0])
			}
			if len(retStmt.Results) == 0 {
				t.Fatalf("expected return in default clause in func SecurityOperation in %s to have results", targetPath)
			}
			for _, res := range retStmt.Results {
				if !isZeroReturnResult(res) {
					t.Fatalf("default clause in func SecurityOperation in %s returned unexpected result: must be \"\" or false literal/ident", targetPath)
				}
			}
			continue
		}
		for _, expr := range clause.List {
			lit, ok := expr.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("expected string literal in switch case in %s, got %T", targetPath, expr)
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("failed to unquote string literal %s in %s: %v", lit.Value, targetPath, err)
			}
			cases = append(cases, val)
		}
	}
	if len(cases) == 0 {
		t.Fatalf("no switch case string literals found in func SecurityOperation in %s", targetPath)
	}
	return cases
}

func isZeroReturnResult(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			val, err := strconv.Unquote(e.Value)
			return err == nil && val == ""
		}
	case *ast.Ident:
		return e.Name == "false" || e.Name == `""`
	}
	return false
}

func assertEqualOpSets(t *testing.T, label string, handWritten, parsed []string) {
	t.Helper()
	hwSet := make(map[string]struct{}, len(handWritten))
	for _, op := range handWritten {
		hwSet[op] = struct{}{}
	}
	parsedSet := make(map[string]struct{}, len(parsed))
	for _, op := range parsed {
		parsedSet[op] = struct{}{}
	}

	hwSorted := make([]string, 0, len(hwSet))
	for op := range hwSet {
		hwSorted = append(hwSorted, op)
	}
	sort.Strings(hwSorted)

	parsedSorted := make([]string, 0, len(parsedSet))
	for op := range parsedSet {
		parsedSorted = append(parsedSorted, op)
	}
	sort.Strings(parsedSorted)

	if len(hwSorted) != len(parsedSorted) {
		t.Fatalf("%s set mismatch:\nhandwritten (%d): %v\nparsed (%d): %v", label, len(hwSorted), hwSorted, len(parsedSorted), parsedSorted)
	}
	for i := range hwSorted {
		if hwSorted[i] != parsedSorted[i] {
			t.Fatalf("%s set mismatch:\nhandwritten: %v\nparsed: %v", label, hwSorted, parsedSorted)
		}
	}
}
