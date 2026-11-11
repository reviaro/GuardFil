package workspacefs

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/approval"
)

func TestMountedPrivateDataCannotEscapeThroughCopiedOrEncodedFiles(t *testing.T) {
	source, view, service := mountedPolicy(t, testPolicy+"local_only_paths: [/workspace/private/**]\n", true)
	if err := os.Mkdir(filepath.Join(source, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "private/data"), []byte("private content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(source, "private/data"), filepath.Join(source, "alias")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(view, "alias"))
	if err != nil || string(data) != "private content" {
		t.Fatalf("local read through hard link: %q %v", data, err)
	}
	sessions := service.PrivateSessions()
	if len(sessions) != 1 || service.CheckCloudSession(sessions[0].Session) == nil {
		t.Fatal("mounted alias read did not stop cloud")
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(data))
	if err := os.WriteFile(filepath.Join(view, "public-copy"), encoded, 0600); err == nil {
		t.Fatal("encoded copy escaped into a public file")
	}
	if _, err := os.Stat(filepath.Join(source, "public-copy")); !os.IsNotExist(err) {
		t.Fatalf("blocked copy created a backing file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(view, "private/report"), encoded, 0600); err != nil {
		t.Fatalf("local-only output failed: %v", err)
	}
	for _, script := range []string{`cp private/report shell-copy`, `mv private/report moved-report`, `ln private/report linked-report`} {
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", `cd "$1" && `+script, "privacy-test", view)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("shell disclosed private output: %s: %s", script, out)
		}
	}
	// A fresh session may work publicly until it consumes the private output.
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"default": true, "workspace_mediated": true, "workspace": approval.WorkspaceScope{Mounts: []approval.WorkspaceLocation{{Virtual: "/workspace", Filesystem: "1", Root: source}}}})
	service.ApproverHandler().ServeHTTP(w, httptest.NewRequest("POST", "/sessions", strings.NewReader(string(body))))
	var second approval.SessionInfo
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &second) != nil {
		t.Fatal(w.Body.String())
	}
	if err := service.CheckCloudSession(second.Session); err != nil {
		t.Fatal(err)
	}
	other, err := New(source, "/workspace", SocketAuthorizer(second.ApprovalSocket))
	if err != nil {
		t.Fatal(err)
	}
	secondView := t.TempDir()
	if err := os.Chmod(secondView, 0700); err != nil {
		t.Fatal(err)
	}
	server, err := other.Mount(secondView, false)
	if err != nil {
		other.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Unmount(); server.Wait(); other.Close() })
	if got, err := os.ReadFile(filepath.Join(secondView, "private/report")); err != nil || string(got) != string(encoded) {
		t.Fatalf("local output in another session: %q %v", got, err)
	}
	if service.CheckCloudSession(second.Session) == nil {
		t.Fatal("new session laundered encoded local-only output")
	}
	// Selecting the private folder as another workspace root changes its
	// virtual names, but cannot remove the original storage classification.
	w = httptest.NewRecorder()
	body, _ = json.Marshal(map[string]any{"default": true, "workspace_mediated": true, "workspace": approval.WorkspaceScope{Mounts: []approval.WorkspaceLocation{{Virtual: "/workspace", Filesystem: "1", Root: filepath.Join(source, "private")}}}})
	service.ApproverHandler().ServeHTTP(w, httptest.NewRequest("POST", "/sessions", strings.NewReader(string(body))))
	var child approval.SessionInfo
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &child) != nil {
		t.Fatal(w.Body.String())
	}
	childFS, err := New(filepath.Join(source, "private"), "/workspace", SocketAuthorizer(child.ApprovalSocket))
	if err != nil {
		t.Fatal(err)
	}
	childView := t.TempDir()
	if err := os.Chmod(childView, 0700); err != nil {
		t.Fatal(err)
	}
	childServer, err := childFS.Mount(childView, false)
	if err != nil {
		childFS.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { childServer.Unmount(); childServer.Wait(); childFS.Close() })
	if got, err := os.ReadFile(filepath.Join(childView, "report")); err != nil || string(got) != string(encoded) {
		t.Fatalf("overlapping workspace output: %q %v", got, err)
	}
	if service.CheckCloudSession(child.Session) == nil {
		t.Fatal("changing the workspace root removed the private classification")
	}
}
