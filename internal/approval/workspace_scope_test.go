package approval

import (
	"errors"
	"github.com/reviaro/guardfil/internal/policy"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivacyFollowsStorageAcrossWorkspaceRootsAndRestart(t *testing.T) {
	pol := strings.Replace(fileAskPolicy, "require_approval", "allow", 1)
	pol = strings.Replace(pol, "rules:", "local_only_paths: [/workspace/private/**]\nrules:", 1)
	state := t.TempDir()
	newService := func() *Service {
		t.Helper()
		s, err := NewService([]byte(pol), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ConfigureWorkspacePrivacyStore(state); err != nil {
			t.Fatal(err)
		}
		s.SetApprovalSocket(filepath.Join(shortTempDir(t), "approval.sock"))
		t.Cleanup(s.Close)
		return s
	}
	s := newService()
	parent := &WorkspaceScope{Mounts: []WorkspaceLocation{{Virtual: "/workspace", Filesystem: "abc", Root: "/project"}}}
	first, err := s.createWorkspaceSession("", true, parent)
	if err != nil {
		t.Fatal(err)
	}
	child := &WorkspaceScope{Mounts: []WorkspaceLocation{{Virtual: "/workspace", Filesystem: "abc", Root: "/project/private"}}}
	second, err := s.createWorkspaceSession("", true, child)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCloudSession(second.Session); err != nil {
		t.Fatal(err)
	}
	read := `{"kind":"file_read","paths":["/workspace/report"]}`
	if out := ask(t, second.ApprovalSocket, read); out.Effect != "ALLOW" {
		t.Fatal(out)
	}
	if !errors.Is(s.CheckCloudSession(second.Session), ErrLocalOnly) {
		t.Fatal("child workspace stripped the private path prefix")
	}
	if out := ask(t, second.ApprovalSocket, `{"kind":"file_write","changes":[{"path":"/workspace/encoded","change":"add"}]}`); out.Effect != "ALLOW" {
		t.Fatalf("private physical output was not recognized: %+v", out)
	}
	// The parent need not read the data first. Classification comes from
	// owner-bound storage mappings, not a prior encounter with its contents.
	if err := s.CheckCloudSession(first.Session); err != nil {
		t.Fatal(err)
	}
	if err := s.deleteSession(first.Session); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = newService()
	second, err = s.createWorkspaceSession("", true, child)
	if err != nil {
		t.Fatal(err)
	}
	if out := ask(t, second.ApprovalSocket, read); out.Effect != "ALLOW" {
		t.Fatal(out)
	}
	if !errors.Is(s.CheckCloudSession(second.Session), ErrLocalOnly) {
		t.Fatal("service restart forgot the original private location")
	}
}

func TestPrivacyAcrossBindMappingsAndMountShadowing(t *testing.T) {
	pol := strings.Replace(fileAskPolicy, "require_approval", "allow", 1)
	pol = strings.Replace(pol, "rules:", "local_only_paths: [/workspace/private/**]\nrules:", 1)
	s, err := NewService([]byte(pol), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetApprovalSocket(filepath.Join(shortTempDir(t), "approval.sock"))
	for _, scope := range []*WorkspaceScope{
		{Mounts: []WorkspaceLocation{{Virtual: "/workspace", Filesystem: "a", Root: "/project"}, {Virtual: "/workspace/private", Filesystem: "b", Root: "/secrets"}}},
		{Mounts: []WorkspaceLocation{{Virtual: "/workspace", Filesystem: "a", Root: "/second"}, {Virtual: "/workspace/alias", Filesystem: "b", Root: "/secrets"}}},
	} {
		info, err := s.createWorkspaceSession("", true, scope)
		if err != nil {
			t.Fatal(err)
		}
		if len(scope.Mounts) > 1 && scope.Mounts[1].Virtual == "/workspace/alias" {
			if out := ask(t, info.ApprovalSocket, `{"kind":"file_read","paths":["/workspace/alias/key"]}`); out.Effect != "ALLOW" {
				t.Fatal(out)
			}
			if !errors.Is(s.CheckCloudSession(info.Session), ErrLocalOnly) {
				t.Fatal("bind alias bypassed storage privacy")
			}
		}
	}
	// The underlying directory hidden by /workspace/private's mount is a
	// different object and must not be confused with the mounted volume.
	snapshot, err := policy.Compile([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	public := &WorkspaceScope{Mounts: []WorkspaceLocation{{Virtual: "/workspace", Filesystem: "a", Root: "/project/private"}}}
	if s.localOnly(snapshot, public, "/workspace/file") {
		t.Fatal("shadowed storage was confused with the mounted private volume")
	}
}

func TestNewWorkspaceMappingRetainsOverlappingReadSessionsLocally(t *testing.T) {
	pol := strings.Replace(fileAskPolicy, "require_approval", "allow", 1)
	pol = strings.Replace(pol, "rules:", "local_only_paths: [/workspace/private/**]\nrules:", 1)
	s, err := NewService([]byte(pol), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetApprovalSocket(filepath.Join(shortTempDir(t), "approval.sock"))
	create := func(root string) SessionInfo {
		t.Helper()
		info, err := s.createWorkspaceSession("", true, &WorkspaceScope{Mounts: []WorkspaceLocation{{Virtual: "/workspace", Filesystem: "a", Root: root}}})
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	overlap, disjoint := create("/project/private"), create("/elsewhere")
	for _, info := range []SessionInfo{overlap, disjoint} {
		if out := ask(t, info.ApprovalSocket, `{"kind":"file_read","paths":["/workspace/report"]}`); out.Effect != "ALLOW" {
			t.Fatal(out)
		}
		if err := s.CheckCloudSession(info.Session); err != nil {
			t.Fatal(err)
		}
	}
	create("/project")
	if !errors.Is(s.CheckCloudSession(overlap.Session), ErrLocalOnly) {
		t.Fatal("new protected name did not retain previously read data locally")
	}
	if err := s.CheckCloudSession(disjoint.Session); err != nil {
		t.Fatalf("disjoint session blocked: %v", err)
	}
}
