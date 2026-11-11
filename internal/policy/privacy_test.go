package policy

import "testing"

func TestLocalOnlyClassificationIsGlobalAndStrict(t *testing.T) {
	base := "schema_version: 1\ntenant_id: test\nrevision: 1\ndefault: deny\nrules: []\n"
	s, err := Compile([]byte(base + "local_only_paths: [/workspace/private/**, /workspace/key]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.LocalOnly("/workspace/private/file") || !s.LocalOnly("/workspace/key") || s.LocalOnly("/workspace/private-other/file") || s.PrivacyVersion() == "" {
		t.Fatal("incorrect privacy paths")
	}
	for _, value := range []string{"null", "true", "[/workspace/../key]", "[https://example.com]", "[42]", "{path: /workspace/key}"} {
		if _, err := Compile([]byte(base + "local_only_paths: " + value + "\n")); err == nil {
			t.Errorf("accepted invalid privacy config: %s", value)
		}
	}
}
