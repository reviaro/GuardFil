package approval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyStoreVersionsAndStartupChoice(t *testing.T) {
	state := shortTempDir(t)
	base := []byte(notesPolicy)
	ps, eff, err := OpenPolicyStore(state, base)
	if err != nil || string(eff) != notesPolicy || ps.Current() != 0 || len(ps.Versions(10)) != 0 {
		t.Fatalf("fresh store: %v cur=%d", err, ps.Current())
	}
	v1 := []byte(strings.Replace(notesPolicy, "revision: 1", "revision: 2", 1))
	v, err := ps.Save(v1, "sha256:x", "added a rule")
	if err != nil || v.Version != 1 || ps.Current() != 1 {
		t.Fatalf("save: %+v %v", v, err)
	}
	if fi, _ := os.Stat(filepath.Join(state, policyVersionsDir)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("versions dir mode %v", fi.Mode())
	}
	// Restart with the same policy_file: the saved version is in force.
	ps2, eff, err := OpenPolicyStore(state, base)
	if err != nil || string(eff) != string(v1) || ps2.Current() != 1 || ps2.Versions(10)[0].Note != "added a rule" {
		t.Fatalf("reopen: %v cur=%d", err, ps2.Current())
	}
	if got, _ := ps2.Load(0); string(got) != notesPolicy {
		t.Fatal("version 0 is not the policy file")
	}
	// The operator edits policy_file by hand: the file wins at the next start.
	edited := []byte(strings.Replace(notesPolicy, "revision: 1", "revision: 9", 1))
	ps3, eff, err := OpenPolicyStore(state, edited)
	if err != nil || string(eff) != string(edited) || ps3.Current() != 0 {
		t.Fatalf("hand-edited file: %v cur=%d", err, ps3.Current())
	}
	// A tampered saved version is refused, not silently used.
	if err := os.WriteFile(filepath.Join(state, policyVersionsDir, "v000001.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPolicyStore(state, base); err == nil {
		t.Fatal("tampered version admitted")
	}
	if _, err := ps3.Load(7); err == nil {
		t.Fatal("unknown version loaded")
	}
}

func TestPolicyStoreRejectsLooseDirectory(t *testing.T) {
	state := shortTempDir(t)
	if err := os.Mkdir(filepath.Join(state, policyVersionsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(state, policyVersionsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPolicyStore(state, []byte(notesPolicy)); err == nil {
		t.Fatal("world-readable versions dir admitted")
	}
}

func TestSetPolicyRefusesInvalidAndKeepsCurrent(t *testing.T) {
	s, _ := newService(t)
	before := s.PolicyDigest()
	if _, err := s.SetPolicy([]byte("default: allow")); err == nil || s.PolicyDigest() != before {
		t.Fatal("invalid policy replaced the current one")
	}
	d, err := s.SetPolicy([]byte(askPolicy))
	if err != nil || s.PolicyDigest() != d || d == before {
		t.Fatalf("valid policy: %v", err)
	}
	if out := s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/notes/a","change":"add"}]}`)); out.Reasons[0] != ReasonApprovalNeeded {
		t.Fatalf("new policy not used: %+v", out)
	}
}
