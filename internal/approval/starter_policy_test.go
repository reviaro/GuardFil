package approval

import (
	"fmt"
	"os"
	"testing"
)

// The starter policy blocks writes to files the owner's machine runs later
// (git hooks, direnv, editor tasks) and still allows ordinary workspace writes.
func TestStarterPolicyBlocksHostRunFiles(t *testing.T) {
	pol, err := os.ReadFile("../../deployments/local/starter-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../deployments/local/executor-catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := ParseCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	write := func(p string) Output {
		req := fmt.Sprintf(`{"kind":"file_write","changes":[{"path":%q,"change":"add"}]}`, p)
		return EvaluateWithCatalog(pol, cat, []byte(req))
	}
	for _, p := range []string{
		"/workspace/.git/hooks/pre-commit", "/workspace/.git/config", "/workspace/.githooks/pre-push",
		"/workspace/.husky/pre-commit", "/workspace/.pre-commit-config.yaml", "/workspace/.envrc",
		"/workspace/.mise.toml", "/workspace/mise.toml", "/workspace/.vscode/tasks.json",
		"/workspace/.idea/workspace.xml", "/workspace/.zed/tasks.json", "/workspace/.devcontainer/devcontainer.json",
		// the same files in nested folders and repositories
		"/workspace/sub/repo/.git/hooks/post-checkout", "/workspace/app/.envrc", "/workspace/a/b/.vscode/tasks.json",
		"/workspace/pkg/mise.toml", "/workspace/svc/.devcontainer/devcontainer.json",
	} {
		if out := write(p); out.Effect != "BLOCK" || out.Reasons[0] != "POLICY_DENIED" {
			t.Errorf("%s: %+v", p, out)
		}
	}
	for _, p := range []string{"/workspace/src/main.go", "/workspace/.gitignore", "/workspace/README.md",
		"/workspace/.github/workflows/ci.yml", "/workspace/app/.envrc.example", "/workspace/docs/git/notes.md"} {
		if out := write(p); out.Effect != "ALLOW" {
			t.Errorf("%s: %+v", p, out)
		}
	}
}
