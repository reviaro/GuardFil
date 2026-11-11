package workspacefs

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/approval"
)

const testPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: read
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/**}]}
  - id: write
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/**}]}
  - id: secrets
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/secrets/**}]}
  - id: protected
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/protected/**}]}
  - id: nested-config
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/**/.envrc}]}
  - id: move-secret
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/move/secret.txt}]}
`

func mounted(t *testing.T, session ...bool) (source, mount string, service *approval.Service) {
	return mountedPolicy(t, testPolicy, len(session) > 0 && session[0])
}

func mountedPolicy(t *testing.T, policy string, session bool) (source, mount string, service *approval.Service) {
	t.Helper()
	if os.Getenv("GUARDFIL_FUSE_TEST") != "1" {
		t.Skip("real FUSE test: set GUARDFIL_FUSE_TEST=1 on a Linux host with /dev/fuse and fusermount3")
	}
	// Session sockets add an agents/<id>.sock suffix; long test names would
	// otherwise exceed Linux's Unix-socket path limit.
	base, err := os.MkdirTemp("", "gfws-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	source, mount = filepath.Join(base, "source"), filepath.Join(base, "view")
	for _, p := range []string{source, mount, filepath.Join(source, "secrets"), filepath.Join(source, "protected"), filepath.Join(source, "move")} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, contents := range map[string]string{"ok.txt": "public", "secrets/token": "DO-NOT-READ", "protected/config": "DO-NOT-WRITE", "move/secret.txt": "DO-NOT-MOVE"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	service, err = approval.NewService([]byte(policy), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if session {
		if err = service.EnableAsk(5 * time.Second); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(base, "approval.sock")
	l, err := approval.ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	go service.Serve(l)
	t.Cleanup(func() { l.Close(); service.Close() })
	if session {
		service.SetApprovalSocket(socket)
		w := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]any{"default": true, "workspace": approval.WorkspaceScope{Mounts: []approval.WorkspaceLocation{{Virtual: "/workspace", Filesystem: "1", Root: source}}}})
		service.ApproverHandler().ServeHTTP(w, httptest.NewRequest("POST", "/sessions", strings.NewReader(string(body))))
		var info approval.SessionInfo
		if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &info) != nil {
			t.Fatalf("workspace session: %d %s", w.Code, w.Body.String())
		}
		socket = info.ApprovalSocket
	}
	authorize := SocketAuthorizer(socket)
	w, err := New(source, "/workspace", func(ctx context.Context, write bool, paths ...string) error {
		err := authorize(ctx, write, paths...)
		if write && err != nil {
			t.Logf("write decision %q: %v", paths, err)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := w.Mount(mount, false)
	if err != nil {
		w.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Unmount(); err != nil {
			t.Error(err)
		}
		server.Wait()
		w.Close()
	})
	return source, mount, service
}

func TestMountedSessionApprovalCoversLookupOpenAndReads(t *testing.T) {
	_, mount, service := mounted(t, true)
	policy := testPolicy + `
  - id: ask-for-note
    effect: require_approval
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/ok.txt}]}
`
	if _, err := service.SetPolicy([]byte(policy)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := os.ReadFile(filepath.Join(mount, "ok.txt"))
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(service.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	held := service.Pending()
	if len(held) != 1 || !held[0].SessionGrant {
		t.Fatalf("no scoped filesystem prompt: %+v", held)
	}
	if err := service.AnswerWithScope(held[0].ID, true, "session"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("one read still needed multiple approval prompts")
	}
	for i := 0; i < 5; i++ {
		data, err := os.ReadFile(filepath.Join(mount, "ok.txt"))
		if err != nil || string(data) != "public" {
			t.Fatalf("approved read %d: %q %v", i, data, err)
		}
	}
	if grants := service.FileGrants(); len(grants) != 1 || grants[0].Reads != 1 {
		t.Fatalf("unexpected file approval scope: %+v", grants)
	}
}

func TestMountedWorkspace(t *testing.T) {
	source, mount, _ := mounted(t)
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(mount, name)) }
	if got, err := read("ok.txt"); err != nil || string(got) != "public" {
		t.Fatalf("allowed read: %q %v", got, err)
	}
	if _, err := read("secrets/token"); err == nil {
		t.Fatal("secret read succeeded")
	}
	if err := os.WriteFile(filepath.Join(mount, "ok.txt"), []byte("edited"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(source, "ok.txt")); string(got) != "edited" {
		t.Fatalf("write did not reach source: %q", got)
	}
	if err := os.WriteFile(filepath.Join(mount, "protected/config"), []byte("bad"), 0600); err == nil {
		t.Fatal("protected write succeeded")
	}
	if got, _ := os.ReadFile(filepath.Join(source, "protected/config")); string(got) != "DO-NOT-WRITE" {
		t.Fatalf("denied truncate changed source: %q", got)
	}
	if err := os.WriteFile(filepath.Join(mount, "new.txt"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mount, "newdir"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, "newdir/.envrc"), []byte("bad"), 0600); err == nil {
		t.Fatal("future nested protected name was created")
	}
	if err := os.Rename(filepath.Join(mount, "new.txt"), filepath.Join(mount, "newdir/renamed.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(mount, "move"), filepath.Join(mount, "moved")); err == nil {
		t.Fatal("directory rename exposed restricted descendant")
	}
	if err := os.Remove(filepath.Join(mount, "newdir/renamed.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(mount, "newdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(mount, "protected/config")); err == nil {
		t.Fatal("protected unlink succeeded")
	}
	entries, err := os.ReadDir(mount)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if ent.Name() == "secrets" {
			t.Fatal("restricted directory was listed")
		}
	}
}

func TestMountedAliasesAndShell(t *testing.T) {
	source, mount, _ := mounted(t)
	for name, target := range map[string]string{"secret-alias": "secrets/token", "write-alias": "protected/config", "safe-alias": "ok.txt", "proc-alias": "/proc/self/root"} {
		if err := os.Symlink(target, filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(mount, "safe-alias")); err != nil || string(got) != "public" {
		t.Fatalf("safe symlink: %q %v", got, err)
	}
	if _, err := os.ReadFile(filepath.Join(mount, "secret-alias")); err == nil {
		t.Fatal("symlink read escaped policy")
	}
	if err := os.WriteFile(filepath.Join(mount, "write-alias"), []byte("bad"), 0600); err == nil {
		t.Fatal("symlink write escaped policy")
	}
	procPath := filepath.Join("/proc/self/root", mount, "secrets/token")
	if _, err := os.ReadFile(procPath); err == nil {
		t.Fatal("proc root alias escaped policy")
	}
	if _, err := os.Readlink(filepath.Join(mount, "proc-alias")); err == nil {
		t.Fatal("escaping symlink was exposed")
	}
	if err := os.Link(filepath.Join(source, "secrets/token"), filepath.Join(source, "hard-alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(mount, "hard-alias")); err == nil {
		t.Fatal("existing hardlink escaped policy")
	}
	if err := os.Link(filepath.Join(mount, "ok.txt"), filepath.Join(mount, "new-hardlink")); err != nil {
		t.Fatalf("allowed hardlink creation: %v", err)
	}
	for _, script := range []string{`cat secrets/token`, `cat secret-alias`, `printf bad > protected/config`, `printf bad > write-alias`, `rm protected/config`} {
		// Do not chdir into our own FUSE mount in Go's vfork child: the
		// parent runtime cannot serve that request until exec completes.
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", `cd "$1" && `+script, "workspace-test", mount)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Errorf("shell bypassed workspace policy: %s: %s", script, out)
		}
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-c", `cd "$1" && cat ok.txt && printf permitted > from-shell`, "workspace-test", mount)
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "public" {
		t.Fatalf("allowed shell IO: %q %v", out, err)
	}
	if got, _ := os.ReadFile(filepath.Join(source, "from-shell")); string(got) != "permitted" {
		t.Fatalf("shell write missing: %q", got)
	}
}

func TestMountedAppendAndMetadata(t *testing.T) {
	source, mount, _ := mounted(t)
	allowed, denied := filepath.Join(mount, "ok.txt"), filepath.Join(mount, "protected/config")
	f, err := os.OpenFile(allowed, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte(" appended"))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(source, "ok.txt")); string(got) != "public appended" {
		t.Fatalf("append replaced existing bytes: %q", got)
	}
	stamp := time.Unix(1700000000, 0)
	for _, change := range []struct {
		name   string
		mutate func(string) error
	}{
		{"chmod", func(p string) error { return os.Chmod(p, 0640) }},
		{"truncate", func(p string) error { return os.Truncate(p, 3) }},
		{"timestamp", func(p string) error { return os.Chtimes(p, stamp, stamp) }},
	} {
		if err := change.mutate(allowed); err != nil {
			t.Fatalf("allowed %s: %v", change.name, err)
		}
		if err := change.mutate(denied); err == nil {
			t.Fatalf("denied %s succeeded", change.name)
		}
	}
	st, err := os.Stat(filepath.Join(source, "ok.txt"))
	if err != nil || st.Size() != 3 || st.Mode().Perm() != 0640 || !st.ModTime().Equal(stamp) {
		t.Fatalf("metadata not applied: %+v %v", st, err)
	}
	if got, _ := os.ReadFile(filepath.Join(source, "protected/config")); string(got) != "DO-NOT-WRITE" {
		t.Fatalf("protected contents changed: %q", got)
	}
}

func TestMountedOpenHandleRevocation(t *testing.T) {
	_, mount, service := mounted(t)
	f, err := os.OpenFile(filepath.Join(mount, "ok.txt"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 6)
	if _, err = f.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	pol := testPolicy + `  - id: revoked
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.read, filesystem.write], resources: [{kind: path, value: /workspace/ok.txt}]}
`
	if _, err = service.SetPolicy([]byte(pol)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.ReadAt(buf, 0); err == nil {
		t.Fatal("open descriptor read survived policy revocation")
	}
	if _, err = f.WriteAt([]byte("bad"), 0); err == nil {
		t.Fatal("open descriptor write survived policy revocation")
	}
}

func TestMountedServiceLossClosesOpenHandles(t *testing.T) {
	_, mount, _ := mounted(t)
	f, err := os.OpenFile(filepath.Join(mount, "ok.txt"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(filepath.Join(filepath.Dir(mount), "approval.sock")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadAt(make([]byte, 6), 0); err == nil {
		t.Fatal("read survived loss of the decision service")
	}
	if _, err := f.WriteAt([]byte("bad"), 0); err == nil {
		t.Fatal("write survived loss of the decision service")
	}
}

func TestMountedSymlinkSwapRace(t *testing.T) {
	_, mount, _ := mounted(t)
	alias := filepath.Join(mount, "alias")
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 60; i++ {
			target := "ok.txt"
			if i%2 == 0 {
				target = "secrets/token"
			}
			tmp := filepath.Join(mount, "next-alias")
			if err := os.Symlink(target, tmp); err != nil {
				t.Error(err)
				return
			}
			if err := os.Rename(tmp, alias); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		data, err := os.ReadFile(alias)
		if err == nil && string(data) != "public" {
			t.Errorf("alias race disclosed protected contents: %q", data)
			break
		}
	}
	workers.Wait()
}

func TestMountedExecutablePositiveControl(t *testing.T) {
	source, mount, _ := mounted(t)
	data, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "true"), data, 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/sh", "-c", `exec "$1"`, "workspace-test", filepath.Join(mount, "true")).CombinedOutput(); err != nil {
		t.Fatalf("workspace executable: %s: %v", out, err)
	}
}

func TestBackingOpenCannotEscape(t *testing.T) {
	source := t.TempDir()
	if err := os.Symlink("/etc", filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	w, err := New(source, "/workspace", func(context.Context, bool, ...string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, name := range []string{"../etc/passwd", "/etc/passwd", "escape/passwd"} {
		fd, err := w.open(name, syscall.O_RDONLY)
		if err == nil {
			syscall.Close(fd)
			t.Errorf("backing open escaped: %s", name)
		}
	}
	if w.safeLink("a", "../../etc") || w.safeLink("a", "/proc/self/root") || !w.safeLink("dir/a", "../ok") {
		t.Fatal("bad symlink boundary")
	}
}

func TestInterruptedRenameDoesNotBecomeDenialOrMoveSource(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "before"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := New(source, "/workspace", func(ctx context.Context, _ bool, _ ...string) error {
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := w.root.Rename(ctx, "before", w.root, "after", 0); got != syscall.EINTR {
		t.Fatalf("canceled rename returned %v, want EINTR", got)
	}
	if data, err := os.ReadFile(filepath.Join(source, "before")); err != nil || string(data) != "keep" {
		t.Fatalf("canceled rename changed source: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(source, "after")); !os.IsNotExist(err) {
		t.Fatalf("canceled rename created destination: %v", err)
	}
}

func TestOverlappingMediatorsCoordinateOperations(t *testing.T) {
	base := t.TempDir()
	a, child, b := filepath.Join(base, "a"), filepath.Join(base, "a/child"), filepath.Join(base, "b")
	for _, p := range []string{a, child, b} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	authorize := func(context.Context, bool, ...string) error { return nil }
	first, err := New(a, "/workspace", authorize)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	for _, overlapping := range []string{a, child, base, b} {
		other, err := New(overlapping, "/workspace", authorize)
		if err != nil {
			t.Fatalf("overlapping workspace refused: %s: %v", overlapping, err)
		}
		if err := first.lock(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err = other.lock(ctx, false)
		cancel()
		if err == nil {
			other.unlock()
		}
		first.unlock()
		if err != syscall.EINTR {
			t.Fatalf("namespace transaction was not exclusive: %v", err)
		}
		// Concurrent data operations retain independent view identities and
		// share the namespace guard; only same-object writes serialize.
		if err := first.lock(context.Background(), false); err != nil {
			t.Fatal(err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		err = other.lock(ctx, false)
		cancel()
		first.unlock()
		if err != nil {
			t.Fatalf("concurrent data operations refused: %v", err)
		}
		other.unlock()
		other.Close()
	}
}

func TestMountedConcurrentWorkspaceViews(t *testing.T) {
	source, first, _ := mounted(t)
	other, err := New(source, "/workspace", SocketAuthorizer(filepath.Join(filepath.Dir(source), "approval.sock")))
	if err != nil {
		t.Fatal(err)
	}
	second := t.TempDir()
	if err := os.Chmod(second, 0700); err != nil {
		t.Fatal(err)
	}
	server, err := other.Mount(second, false)
	if err != nil {
		other.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Unmount(); server.Wait(); other.Close() })
	if err := os.WriteFile(filepath.Join(source, "ok.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i, view := range []string{first, second} {
		wg.Add(1)
		go func(i int, view string) {
			defer wg.Done()
			f, err := os.OpenFile(filepath.Join(view, "ok.txt"), os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			for j := 0; j < 20; j++ {
				if _, err := f.Write([]byte{byte('a' + i)}); err != nil {
					t.Error(err)
					return
				}
			}
			if err := os.WriteFile(filepath.Join(view, "protected/config"), []byte("bad"), 0600); err == nil {
				t.Error("concurrent view bypassed write policy")
			}
			if _, err := os.ReadFile(filepath.Join(view, "secrets/token")); err == nil {
				t.Error("concurrent view bypassed read policy")
			}
		}(i, view)
	}
	wg.Wait()
	data, err := os.ReadFile(filepath.Join(source, "ok.txt"))
	if err != nil || len(data) != 40 || strings.Count(string(data), "a") != 20 || strings.Count(string(data), "b") != 20 {
		t.Fatalf("concurrent appends lost data: %q %v", data, err)
	}
	// One view changes aliases while another reads. No intermediate path
	// authorization may disclose the protected target.
	if err := os.WriteFile(filepath.Join(source, "ok.txt"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			target := "ok.txt"
			if i%2 == 0 {
				target = "secrets/token"
			}
			if err := os.Symlink(target, filepath.Join(first, "next-alias")); err != nil {
				t.Error(err)
				return
			}
			if err := os.Rename(filepath.Join(first, "next-alias"), filepath.Join(first, "alias")); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 70; i++ {
		data, err := os.ReadFile(filepath.Join(second, "alias"))
		if err == nil && string(data) != "public" {
			t.Errorf("concurrent view disclosed protected data: %q", data)
			break
		}
	}
	wg.Wait()
}
