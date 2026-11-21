package workspacefs

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/reviaro/guardfil/internal/approval"
)

// Moving a relative symlink or containing directory can leave an escaping host link.
// TestRelativeSymlinkRenameEscaping verifies that Rename refuses moves that would cause
// relative symlinks to escape the workspace (both callback and real FUSE).
func TestRelativeSymlinkRenameEscaping(t *testing.T) {
	for _, directoryMove := range []bool{false, true} {
		name := "file"
		if directoryMove {
			name = "directory"
		}
		t.Run(name+"_callback", func(t *testing.T) {
			base := t.TempDir()
			source := filepath.Join(base, "workspace")
			if err := os.MkdirAll(filepath.Join(source, "a", "b"), 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "outside.txt")
			if err := os.WriteFile(outside, []byte("outside marker"), 0600); err != nil {
				t.Fatal(err)
			}

			w, err := New(source, "/workspace", func(_ context.Context, _ bool, _ ...string) error {
				return nil // All policy checks allow; only escaping symlink check should reject
			})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			fs.NewNodeFS(w.root, &fs.Options{})
			ctx := context.Background()

			lookup := func(parent *node, child string) *node {
				inode, errno := parent.Lookup(ctx, child, &fuse.EntryOut{})
				if errno != 0 {
					t.Fatalf("lookup %s: %v", child, errno)
				}
				parent.AddChild(child, inode, true)
				return inode.Operations().(*node)
			}

			a := lookup(w.root, "a")
			parent, target := a, "../outside.txt"
			if directoryMove {
				parent, target = lookup(a, "b"), "../../outside.txt"
			}
			if _, errno := parent.Symlink(ctx, target, "link", &fuse.EntryOut{}); errno != 0 {
				t.Fatalf("initial contained symlink creation failed: %v", errno)
			}

			var errno syscall.Errno
			var newLink string
			if directoryMove {
				errno = a.Rename(ctx, "b", w.root, "moved", 0)
				newLink = filepath.Join(source, "moved", "link")
			} else {
				errno = a.Rename(ctx, "link", w.root, "link", 0)
				newLink = filepath.Join(source, "link")
			}

			if errno != syscall.EACCES {
				t.Fatalf("expected Rename to return EACCES (%v), got: %v", syscall.EACCES, errno)
			}
			if _, err := os.Lstat(newLink); err == nil {
				t.Fatalf("escaping symlink was created on host at %s", newLink)
			}
		})
	}
}

// Real-FUSE regression test for the symlink move above.
func TestMountedRelativeSymlinkRename(t *testing.T) {
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1")
	}
	base := t.TempDir()
	source := filepath.Join(base, "source")
	view := filepath.Join(base, "view")
	for _, p := range []string{source, view, filepath.Join(source, "a", "b")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside marker"), 0600); err != nil {
		t.Fatal(err)
	}

	w, err := New(source, "/workspace", func(_ context.Context, _ bool, _ ...string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	server, err := w.Mount(view, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		server.Unmount()
		server.Wait()
	}()

	// 1. File move with escaping symlink
	if err := os.Symlink("../outside.txt", filepath.Join(view, "a", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Rename(filepath.Join(view, "a", "link"), filepath.Join(view, "link")); err == nil {
		t.Fatal("expected rename of escaping symlink to fail")
	} else if !os.IsPermission(err) {
		t.Logf("rename failed with: %v (expected permission denied)", err)
	}
	if _, err := os.Lstat(filepath.Join(source, "link")); err == nil {
		t.Fatal("escaping symlink was moved on host")
	}

	// 2. Directory move containing escaping symlink
	if err := os.Symlink("../../outside.txt", filepath.Join(view, "a", "b", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Rename(filepath.Join(view, "a", "b"), filepath.Join(view, "moved")); err == nil {
		t.Fatal("expected directory rename with escaping symlink to fail")
	} else if !os.IsPermission(err) {
		t.Logf("directory rename failed with: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(source, "moved")); err == nil {
		t.Fatal("directory with escaping symlink was moved on host")
	}
}

// New destination names omit aliases of the pinned parent.
func TestBindAliasDestinationEnforcement(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(filepath.Join(source, "allowed"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, "staging", "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "allowed", "srcfile"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "staging", "sub", "restricted"), []byte("nested"), 0600); err != nil {
		t.Fatal(err)
	}
	// Create a directory alias `protected` pointing to `allowed` so `allowed` and `protected`
	// share the same directory inode when resolved, exercising `parent()` and `checkMove()`
	// alias expansion across all constructors without requiring CAP_SYS_ADMIN.
	if err := os.Symlink("allowed", filepath.Join(source, "protected")); err != nil {
		t.Fatal(err)
	}

	policy := `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: reads
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/**}]}
  - id: writes
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/**}]}
  - id: deny-protected-new
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources:
        - {kind: path, value: /workspace/protected/new-file}
        - {kind: path, value: /workspace/protected/new-dir}
        - {kind: path, value: /workspace/protected/new-link}
        - {kind: path, value: /workspace/protected/new-hardlink}
        - {kind: path, value: /workspace/protected/new-fifo}
        - {kind: path, value: /workspace/protected/new-renamed}
  - id: deny-protected-descendant
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/protected/moved-dir/sub/restricted}]}
`
	ctx := context.Background()
	authorizer := func(_ context.Context, write bool, paths ...string) error {
		var req any = map[string]any{"kind": "file_read", "paths": paths}
		if write {
			var changes []map[string]string
			for _, p := range paths {
				changes = append(changes, map[string]string{"path": p, "change": "update"})
			}
			req = map[string]any{"kind": "file_write", "changes": changes}
		}
		raw, _ := json.Marshal(req)
		out := approval.Evaluate([]byte(policy), raw)
		if out.Effect != "ALLOW" {
			return syscall.EACCES
		}
		return nil
	}

	w, err := New(source, "/workspace", authorizer)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	fs.NewNodeFS(w.root, &fs.Options{})

	lookup := func(parent *node, child string) *node {
		inode, errno := parent.Lookup(ctx, child, &fuse.EntryOut{})
		if errno != 0 {
			t.Fatalf("lookup %s: %v", child, errno)
		}
		parent.AddChild(child, inode, true)
		return inode.Operations().(*node)
	}

	allowed := lookup(w.root, "allowed")
	srcNode := lookup(allowed, "srcfile")

	if _, h, _, e := allowed.Create(ctx, "new-file", syscall.O_RDWR, 0600, &fuse.EntryOut{}); e != syscall.EACCES {
		if h != nil {
			h.(*handle).Release(ctx)
		}
		t.Fatalf("Create through aliased parent should return EACCES, got %v", e)
	}
	if _, e := allowed.Mkdir(ctx, "new-dir", 0700, &fuse.EntryOut{}); e != syscall.EACCES {
		t.Fatalf("Mkdir through aliased parent should return EACCES, got %v", e)
	}
	if _, e := allowed.Symlink(ctx, "srcfile", "new-link", &fuse.EntryOut{}); e != syscall.EACCES {
		t.Fatalf("Symlink through aliased parent should return EACCES, got %v", e)
	}
	if _, e := allowed.Link(ctx, srcNode.Inode.Operations(), "new-hardlink", &fuse.EntryOut{}); e != syscall.EACCES {
		t.Fatalf("Link through aliased parent should return EACCES, got %v", e)
	}
	if _, e := allowed.Mknod(ctx, "new-fifo", syscall.S_IFIFO|0600, 0, &fuse.EntryOut{}); e != syscall.EACCES {
		t.Fatalf("Mknod through aliased parent should return EACCES, got %v", e)
	}
	if e := allowed.Rename(ctx, "srcfile", allowed, "new-renamed", 0); e != syscall.EACCES {
		t.Fatalf("Rename file through aliased parent should return EACCES, got %v", e)
	}
	if e := w.root.Rename(ctx, "staging", allowed, "moved-dir", 0); e != syscall.EACCES {
		t.Fatalf("Rename directory with restricted descendant under parent alias should return EACCES, got %v", e)
	}
	if _, err := os.Stat(filepath.Join(source, "allowed", "moved-dir")); !os.IsNotExist(err) {
		t.Fatalf("denied directory rename created destination: %v", err)
	}
}

// Kernel symlink traversal can lose requested-path descendant rules.
func TestSymlinkTraversalPolicyAndPrivacy(t *testing.T) {
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1")
	}

	base := t.TempDir()
	source := filepath.Join(base, "source")
	view := filepath.Join(base, "view")
	for _, p := range []string{source, view, filepath.Join(source, "data"), filepath.Join(source, "protected")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}

	// Real data files
	if err := os.WriteFile(filepath.Join(source, "data", "secret"), []byte("super-secret-payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "data", "public"), []byte("public-payload"), 0600); err != nil {
		t.Fatal(err)
	}

	// Symlinks
	// 1. Directory symlink: linkdir -> data
	if err := os.Symlink("data", filepath.Join(source, "linkdir")); err != nil {
		t.Fatal(err)
	}
	// 2. Chained directory symlink: chaindir -> linkdir
	if err := os.Symlink("linkdir", filepath.Join(source, "chaindir")); err != nil {
		t.Fatal(err)
	}
	// 3. Direct symlink: protected/link_to_pub -> ../data/public
	if err := os.Symlink("../data/public", filepath.Join(source, "protected", "link_to_pub")); err != nil {
		t.Fatal(err)
	}
	// 4. Cycle symlink: self -> .
	if err := os.Symlink(".", filepath.Join(source, "self")); err != nil {
		t.Fatal(err)
	}

	policy := `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: read-all
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/**}]}
  - id: write-all
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/**}]}
  - id: deny-linkdir-secret-read
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/linkdir/secret}]}
  - id: deny-protected-write
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/protected/**}]}
local_only_paths: [/workspace/chaindir/public]
`
	svc, err := approval.NewService([]byte(policy), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	sockPath := filepath.Join(base, "test.sock")
	svc.SetApprovalSocket(sockPath)
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"default":            true,
		"workspace_mediated": true,
		"workspace": approval.WorkspaceScope{
			Mounts: []approval.WorkspaceLocation{{Virtual: "/workspace", Filesystem: "1", Root: source}},
		},
	})
	svc.ApproverHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", strings.NewReader(string(body))))
	var sess approval.SessionInfo
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &sess) != nil {
		t.Fatalf("session create failed: %d %s", rec.Code, rec.Body.String())
	}

	w, err := New(source, "/workspace", SocketAuthorizer(sess.ApprovalSocket))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	server, err := w.Mount(view, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		server.Unmount()
		server.Wait()
	}()

	// 1. Read deny through directory symlink (view/linkdir/secret)
	if _, err := os.ReadFile(filepath.Join(view, "linkdir", "secret")); err == nil {
		t.Fatal("expected reading view/linkdir/secret to be denied, but succeeded")
	}

	// 2. Reading canonical path view/data/secret should be allowed under policy
	// Wait, is /workspace/data/secret denied? No, only /workspace/linkdir/secret is denied.
	// But aliases finds linkdir/secret as an alias of data/secret!
	// So accessing data/secret checks all its aliases including linkdir/secret, which is denied!
	// That means once linkdir/secret is denied, accessing data/secret is also denied!
	// Let's verify reading view/data/secret is blocked:
	if _, err := os.ReadFile(filepath.Join(view, "data", "secret")); err == nil {
		t.Fatal("expected reading view/data/secret to be denied because of linkdir alias")
	}

	// 3. Local-only privacy through chained directory symlink (view/chaindir/public)
	cloudErrBefore := svc.CheckCloudSession(sess.Session)
	if cloudErrBefore != nil {
		t.Fatalf("unexpected cloud check failure before read: %v", cloudErrBefore)
	}
	dataRead, err := os.ReadFile(filepath.Join(view, "chaindir", "public"))
	if err != nil {
		t.Fatalf("reading chaindir/public failed: %v", err)
	}
	if string(dataRead) != "public-payload" {
		t.Fatalf("got data %q, expected public-payload", string(dataRead))
	}
	cloudErrAfter := svc.CheckCloudSession(sess.Session)
	if cloudErrAfter == nil {
		t.Fatal("expected cloud check to be blocked after reading local-only path via chained symlink")
	}

	// 4. Write denial through symlink (view/protected/link_to_pub)
	if err := os.WriteFile(filepath.Join(view, "protected", "link_to_pub"), []byte("hacked"), 0600); err == nil {
		t.Fatal("expected writing through protected symlink to fail")
	}
	if content, _ := os.ReadFile(filepath.Join(source, "data", "public")); string(content) != "public-payload" {
		t.Fatalf("target was modified despite write rule: %q", string(content))
	}

	// 5. Self-cycle symlink traversal must be refused with ELOOP
	if _, err := os.ReadFile(filepath.Join(view, "self", "data", "public")); err == nil {
		t.Fatal("expected reading through cyclic self symlink to be refused, but succeeded")
	}
}

// TestRepeatedDirectorySymlinkRefusal verifies that cycle-bearing directory symlinks
// (e.g. self -> .) are refused on traversal for both reads and writes, keeping backing files intact.
func TestRepeatedDirectorySymlinkRefusal(t *testing.T) {
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1")
	}
	base := t.TempDir()
	source, view := filepath.Join(base, "source"), filepath.Join(base, "view")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(view, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "ok.txt"), []byte("initial public content"), 0600); err != nil {
		t.Fatal(err)
	}

	w, err := New(source, "/workspace", func(_ context.Context, _ bool, _ ...string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	server, err := w.Mount(view, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Unmount(); server.Wait() }()

	// Create self -> . in view
	if err := os.Symlink(".", filepath.Join(view, "self")); err != nil {
		t.Fatal(err)
	}

	// 1. Read through repeated symlink must fail
	name := filepath.Join(view, "self/self/ok.txt")
	if b, err := os.ReadFile(name); err == nil {
		t.Fatalf("expected read through self/self/ok.txt to fail, got %q", b)
	}

	// 2. Write through repeated symlink must fail and backing file must remain unchanged
	if err := os.WriteFile(name, []byte("tampered content"), 0600); err == nil {
		t.Fatal("expected write through self/self/ok.txt to fail")
	}
	backing, err := os.ReadFile(filepath.Join(source, "ok.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(backing) != "initial public content" {
		t.Fatalf("backing file was modified: got %q, expected 'initial public content'", string(backing))
	}
}

// TestTwoLinkCycleRefused verifies that multi-link cycles (a/x -> ../b, b/y -> ../a)
// are detected as cyclic and refused on traversal.
func TestTwoLinkCycleRefused(t *testing.T) {
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1")
	}
	base := t.TempDir()
	source, view := filepath.Join(base, "source"), filepath.Join(base, "view")
	for _, p := range []string{filepath.Join(source, "a"), filepath.Join(source, "b"), view} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "a", "target.txt"), []byte("target payload"), 0600); err != nil {
		t.Fatal(err)
	}

	w, err := New(source, "/workspace", func(_ context.Context, _ bool, _ ...string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	server, err := w.Mount(view, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Unmount(); server.Wait() }()

	// Create 2-link cycle: a/x -> ../b, b/y -> ../a
	if err := os.Symlink("../b", filepath.Join(view, "a/x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../a", filepath.Join(view, "b/y")); err != nil {
		t.Fatal(err)
	}

	// Traversing a/x or b/y must be refused
	if _, err := os.ReadFile(filepath.Join(view, "a/x/y/target.txt")); err == nil {
		t.Fatal("expected read through 2-link cycle to be refused, but succeeded")
	}
	if _, err := os.ReadFile(filepath.Join(view, "b/y/target.txt")); err == nil {
		t.Fatal("expected read through b/y to be refused, but succeeded")
	}
}

// TestNonCyclicDirectorySymlinkWorks verifies positive control: non-cyclic directory
// symlinks and chains remain fully traversable.
func TestNonCyclicDirectorySymlinkWorks(t *testing.T) {
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1")
	}
	base := t.TempDir()
	source, view := filepath.Join(base, "source"), filepath.Join(base, "view")
	for _, p := range []string{filepath.Join(source, "data"), view} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "data", "item.txt"), []byte("non-cyclic item"), 0600); err != nil {
		t.Fatal(err)
	}

	w, err := New(source, "/workspace", func(_ context.Context, _ bool, _ ...string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	server, err := w.Mount(view, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Unmount(); server.Wait() }()

	// linkdir -> data (no cycle)
	if err := os.Symlink("data", filepath.Join(view, "linkdir")); err != nil {
		t.Fatal(err)
	}
	// chain -> linkdir (DAG chain, no cycle)
	if err := os.Symlink("linkdir", filepath.Join(view, "chain")); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(view, "linkdir/item.txt"))
	if err != nil || string(content) != "non-cyclic item" {
		t.Fatalf("reading via linkdir: %q %v", content, err)
	}
	chainContent, err := os.ReadFile(filepath.Join(view, "chain/item.txt"))
	if err != nil || string(chainContent) != "non-cyclic item" {
		t.Fatalf("reading via chain: %q %v", chainContent, err)
	}
}

// TestNonCyclicChainEngagesLocalOnlyPrivacy verifies that reading local-only data
// through a non-cyclic directory symlink chain engages local-only privacy and causes
// CheckCloudSession to refuse cloud requests.
func TestNonCyclicChainEngagesLocalOnlyPrivacy(t *testing.T) {
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1")
	}
	base := t.TempDir()
	source, view := filepath.Join(base, "source"), filepath.Join(base, "view")
	for _, p := range []string{filepath.Join(source, "data"), view} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "data", "secret"), []byte("classified-data"), 0600); err != nil {
		t.Fatal(err)
	}

	policy := testPolicy + "local_only_paths: [/workspace/chain/secret]\n"
	svc, err := approval.NewService([]byte(policy), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	svc.SetApprovalSocket(filepath.Join(base, "privacy.sock"))
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"default":            true,
		"workspace_mediated": true,
		"workspace": approval.WorkspaceScope{
			Mounts: []approval.WorkspaceLocation{{Virtual: "/workspace", Filesystem: "1", Root: source}},
		},
	})
	svc.ApproverHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", strings.NewReader(string(body))))
	var session approval.SessionInfo
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &session) != nil {
		t.Fatal(rec.Body.String())
	}
	if err := svc.CheckCloudSession(session.Session); err != nil {
		t.Fatalf("cloud should be enabled initially: %v", err)
	}

	w, err := New(source, "/workspace", SocketAuthorizer(session.ApprovalSocket))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	server, err := w.Mount(view, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Unmount(); server.Wait() }()

	if err := os.Symlink("data", filepath.Join(view, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("linkdir", filepath.Join(view, "chain")); err != nil {
		t.Fatal(err)
	}

	// Reading /workspace/chain/secret matches local_only_paths and must engage privacy
	b, err := os.ReadFile(filepath.Join(view, "chain/secret"))
	if err != nil {
		t.Fatalf("expected read of chain/secret to succeed: %v", err)
	}
	if string(b) != "classified-data" {
		t.Fatalf("got data %q", string(b))
	}

	// CheckCloudSession must now refuse
	if err := svc.CheckCloudSession(session.Session); err == nil {
		t.Fatal("expected CheckCloudSession to refuse after reading local-only path via symlink chain")
	}
}

// TestSemanticDotDotTargetsRefused verifies that linkTarget allows leading .. (e.g. ../x)
// but rejects any target containing a .. after a normal component (e.g. a/../b, shortcut/../x).
func TestSemanticDotDotTargetsRefused(t *testing.T) {
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1")
	}
	base := t.TempDir()
	source, view := filepath.Join(base, "source"), filepath.Join(base, "view")
	for _, p := range []string{filepath.Join(source, "sub"), view} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "ok.txt"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}

	w, err := New(source, "/workspace", func(_ context.Context, _ bool, _ ...string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	server, err := w.Mount(view, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Unmount(); server.Wait() }()

	// 1. Leading .. is allowed: sub/link -> ../ok.txt
	if err := os.Symlink("../ok.txt", filepath.Join(view, "sub/link")); err != nil {
		t.Fatalf("expected leading dot-dot symlink to be allowed, got: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(view, "sub/link"))
	if err != nil || string(got) != "ok" {
		t.Fatalf("reading via leading dot-dot: %q %v", got, err)
	}

	// 2. Non-leading .. is refused on creation: sub/bad -> a/../ok.txt
	if err := os.Symlink("a/../ok.txt", filepath.Join(view, "sub/bad")); err == nil {
		t.Fatal("expected Symlink with a/../b to be rejected with EACCES, but succeeded")
	}

	// 3. shortcut/../outside.txt is refused on creation
	if err := os.Symlink("shortcut/../outside.txt", filepath.Join(view, "sub/bad2")); err == nil {
		t.Fatal("expected Symlink with shortcut/../outside.txt to be rejected with EACCES, but succeeded")
	}

	// 4. Stored host-created link with semantic dot-dot cannot be moved to escape:
	// Host creates shortcut and link directly in source:
	if err := os.Symlink("..", filepath.Join(source, "shortcut")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(source, "sub/shortcut")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("shortcut/../outside.txt", filepath.Join(source, "sub/hostlink")); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside marker"), 0600); err != nil {
		t.Fatal(err)
	}
	// Renaming sub/hostlink to hostlink in view must be refused:
	if err := os.Rename(filepath.Join(view, "sub/hostlink"), filepath.Join(view, "hostlink")); err == nil {
		t.Fatal("expected Rename of stored semantic dot-dot symlink to be refused, but succeeded")
	}
	if _, err := os.Lstat(filepath.Join(source, "hostlink")); err == nil {
		t.Fatal("denied rename created escaping hostlink on host")
	}
}
