// Package security_test contains QA-owned release gates for the P1.1 shell.
package security_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestP11ProcessShellBuilds(t *testing.T) {
	root := repoRoot(t)
	output := filepath.Join(t.TempDir(), "guardfil")
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=true", "-o", output, "./cmd/guardfil")
	cmd.Dir = root
	if result, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("P1.1 process shell must compile before runtime/security claims are accepted: %v\n%s", err, result)
	}
}

func TestP11ContainerPostureIsDeclared(t *testing.T) {
	root := repoRoot(t)
	dockerfile := read(t, filepath.Join(root, "deployments", "Dockerfile"))
	compose := read(t, filepath.Join(root, "deployments", "example", "compose.yaml"))
	for _, want := range []string{"FROM scratch", "USER 65532:65532", "VOLUME [\"/var/lib/guardfil\"]", "@sha256:"} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile missing required posture %q", want)
		}
	}
	for _, want := range []string{"read_only: true", "user: \"65532:65532\"", "no-new-privileges:true", "cap_drop: [\"ALL\"]"} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose example missing required posture %q", want)
		}
	}
}

func TestReproducibilityGateUsesIsolatedCleanBuilds(t *testing.T) {
	root := repoRoot(t)
	script := read(t, filepath.Join(root, "scripts", "reproducibility.sh"))
	for _, want := range []string{
		"GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly", "GOPROXY=off",
		"go -C \"$source_root\" mod verify", "worktree add --detach",
		"outputs outside checkout", "assert_clean \"$source_root\"",
		"GOCACHE=\"$gocache_a\"", "GOCACHE=\"$gocache_b\"",
		"TZ=UTC0 date -d", "vcs\\.time=",
		"vcs\\.modified=", "cmp -s \"$output_dir/guardfil-a\" \"$output_dir/guardfil-b\"",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("reproducibility gate missing %q", want)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func read(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
