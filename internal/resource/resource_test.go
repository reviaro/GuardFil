package resource

import "testing"

func TestPathNormalizationAndSegmentMatching(t *testing.T) {
	tests := []struct {
		input     string
		want      string
		canonical bool
		wantErr   bool
	}{
		{input: "/work/file", want: "/work/file", canonical: true},
		{input: "/work/../private/key", want: "/private/key"},
		{input: "/work/./file", want: "/work/file"},
		{input: "/work//file", want: "/work/file"},
		{input: "work/file", wantErr: true},
		{input: `/work\..\private`, wantErr: true},
		{input: "/work/%2e%2e/private", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, canonical, err := NormalizeSelector(Path, test.input)
			if (err != nil) != test.wantErr || got != test.want || canonical != test.canonical {
				t.Fatalf("NormalizeSelector(%q) = %q, %t, %v", test.input, got, canonical, err)
			}
		})
	}
	if !Match(Path, "/work/**", "/work/file") || Match(Path, "/work/**", "/work-other/file") || Match(Path, "/work/**", "/work/../private/key") {
		t.Fatal("path resource matching was not canonical and segment-aware")
	}
}

func TestPatternsAndOtherSelectorKinds(t *testing.T) {
	for _, invalid := range []string{"work/**", "/work/../private/**", "/work//nested/**", "/work/%2e%2e/private/**"} {
		if ValidatePattern(Path, invalid) == nil {
			t.Fatalf("accepted invalid path pattern %q", invalid)
		}
	}
	if ValidatePattern(Path, "/work/**") != nil || ValidatePattern(Tool, "filesystem.read") != nil {
		t.Fatal("rejected canonical resource pattern")
	}
	if got, canonical, err := NormalizeSelector(URL, "https://example.com/a/../b"); err != nil || canonical || got != "https://example.com/b" {
		t.Fatalf("URL normalization = %q, %t, %v", got, canonical, err)
	}
	for _, invalid := range []string{"http://example.com/", "https://example.com/%2e%2e/private", "https://example.com/path?redirect=x", "https://example.com/a?"} {
		if _, _, err := NormalizeSelector(URL, invalid); err == nil {
			t.Fatalf("accepted invalid URL selector %q", invalid)
		}
	}
	if ValidatePattern(URL, "https://example.com/a?") == nil {
		t.Fatal("accepted empty-query URL pattern")
	}
	if ValidatePattern(URL, "https://example.com/a") != nil || !Match(URL, "https://example.com/a", "https://example.com/a") {
		t.Fatal("rejected canonical URL selector")
	}
}

func TestKindForOperation(t *testing.T) {
	cases := []struct {
		op   string
		want string
	}{
		{"fs.read", Path},
		{"fs.write", Path},
		{"http.request", URL},
		{"tool.invoke", Tool},
		{"llm.request", ""},
		{"shell.execute", Command},
		{"fs.readx", ""},
		{"http.get", ""},
		{"tool.read", ""},
		{"filesystem.read", ""},
		{"filesystem.write", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := KindForOperation(tc.op); got != tc.want {
			t.Errorf("KindForOperation(%q) = %q, want %q", tc.op, got, tc.want)
		}
	}
}

func TestSecurityOperation(t *testing.T) {
	accepted := []string{
		"filesystem.read",
		"filesystem.write",
		"llm.request",
		"tool.invoke",
		"shell.execute",
		"http.request",
	}
	for _, op := range accepted {
		if !SecurityOperation(op) {
			t.Errorf("SecurityOperation(%q) = false, want true", op)
		}
	}

	rejected := []string{
		"fs.read",
		"fs.write",
		"http.get",
		"tool.read",
		"tool.execute",
		"Filesystem.read",
		"filesystem.read ",
		" filesystem.read",
		"FILESYSTEM.READ",
		"",
	}
	for _, op := range rejected {
		if SecurityOperation(op) {
			t.Errorf("SecurityOperation(%q) = true, want false", op)
		}
	}
}

func TestKindForSecurityOperation(t *testing.T) {
	cases := []struct {
		op   string
		want string
	}{
		{"filesystem.read", Path},
		{"filesystem.write", Path},
		{"http.request", URL},
		{"tool.invoke", Tool},
		{"llm.request", ""},
		{"shell.execute", Command},
		{"fs.read", ""},
		{"fs.write", ""},
		{"http.get", ""},
		{"tool.read", ""},
		{"unknown", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := KindForSecurityOperation(tc.op); got != tc.want {
			t.Errorf("KindForSecurityOperation(%q) = %q, want %q", tc.op, got, tc.want)
		}
	}
}

func TestAnyFolderPattern(t *testing.T) {
	for _, valid := range []string{"/workspace/**/.envrc", "/workspace/**/.git/**", "/**/.env", "/**/node_modules/**"} {
		if ValidatePattern(Path, valid) != nil {
			t.Errorf("rejected %q", valid)
		}
	}
	for _, invalid := range []string{
		"/workspace/**/", "/workspace/**/a/b", "/workspace/**/a/**/b", "/workspace/**/**", "/workspace/**/*.env",
		"/workspace/**/..", "/workspace/**/.", "/work/../x/**/a", "/work//x/**/a", "work/**/a", "/w/**/a%2f",
		"/w/**/a\\b", "//**/NAME", "//**/.env", "//**/.env/**",
	} {
		if ValidatePattern(Path, invalid) == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"/workspace/**/.envrc", "/workspace/.envrc", true},
		{"/workspace/**/.envrc", "/workspace/a/b/.envrc", true},
		{"/workspace/**/.envrc", "/workspace/a/.envrc/x", false},
		{"/workspace/**/.envrc", "/workspace/a/.envrc.bak", false},
		{"/workspace/**/.envrc", "/workspace/a/x.envrc", false},
		{"/workspace/**/.envrc", "/workspace", false},
		{"/workspace/**/.envrc", "/workspace-other/.envrc", false},
		{"/workspace/**/.envrc", "/other/.envrc", false},
		{"/workspace/**/.envrc", "/workspace/a/../.envrc", false}, // not canonical
		{"/workspace/**/.git/**", "/workspace/.git", true},
		{"/workspace/**/.git/**", "/workspace/.git/hooks/pre-commit", true},
		{"/workspace/**/.git/**", "/workspace/sub/repo/.git/config", true},
		{"/workspace/**/.git/**", "/workspace/sub/.gitignore", false},
		{"/workspace/**/.git/**", "/workspace/.github/workflows/ci.yml", false},
		{"/**/.env", "/.env", true},
		{"/**/.env", "/a/b/.env", true},
		{"/**/.env", "/", false},
		{"//**/NAME", "/NAME", false},
	}
	for _, c := range cases {
		if got := Match(Path, c.pattern, c.value); got != c.want {
			t.Errorf("Match(%q, %q) = %v", c.pattern, c.value, got)
		}
	}
	// URLs and tools keep their old grammar.
	if Match(URL, "https://example.com/**/a", "https://example.com/x/a") {
		t.Error("any-folder pattern applied to a URL")
	}
}
