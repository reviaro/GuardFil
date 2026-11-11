package webui

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestPrivacyAndFileGrantControlsRequireOwnerAndSameOrigin(t *testing.T) {
	f := newFixture(t)
	for _, route := range []string{"/api/privacy", "/api/file-grants/0123456789abcdef/revoke"} {
		if r := f.do(t, "POST", route, map[string]any{"paths": []string{}}); r.Code != 401 {
			t.Fatalf("unauthenticated %s: %d", route, r.Code)
		}
	}
	f.login(t)
	for _, route := range []string{"/api/privacy", "/api/file-grants/0123456789abcdef/revoke"} {
		if r := f.do(t, "POST", route, map[string]any{"paths": []string{}}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }); r.Code != 403 {
			t.Fatalf("cross-site %s: %d", route, r.Code)
		}
	}
	paths := []string{"/workspace/private/**"}
	if r := f.do(t, "POST", "/api/privacy", map[string]any{"paths": paths}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	state := f.do(t, "GET", "/api/state", nil)
	var st stateView
	if json.Unmarshal(state.Body.Bytes(), &st) != nil || len(st.LocalOnlyPaths) != 1 || st.LocalOnlyPaths[0] != paths[0] {
		t.Fatal(state.Body.String())
	}
	if r := f.do(t, "POST", "/api/rules", map[string]string{"op": "add", "action": "allow", "target": "reads", "value": "/workspace/docs"}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if !strings.Contains(string(f.svc.Policy()), "local_only_paths") {
		t.Fatal("ordinary rule edit discarded privacy classification")
	}
	before := f.svc.PolicyDigest()
	if r := f.do(t, "POST", "/api/privacy", map[string]any{"paths": []string{"/workspace/../secret"}}); r.Code != 400 {
		t.Fatal(r.Code)
	}
	if before != f.svc.PolicyDigest() {
		t.Fatal("invalid privacy input changed policy")
	}
	if r := f.do(t, "POST", "/api/privacy", map[string]any{"paths": []string{}}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if strings.Contains(string(f.svc.Policy()), "local_only_paths") {
		t.Fatal("clear did not remove configured paths")
	}
}
