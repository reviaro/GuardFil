package workspacefs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/approval"
	"golang.org/x/sys/unix"
)

func TestViewInodesIncludeFilesystemIdentity(t *testing.T) {
	w := &Workspace{inodes: map[objectID]uint64{}}
	a := unix.Stat_t{Dev: 1, Ino: 42}
	b := unix.Stat_t{Dev: 2, Ino: 42}
	first := w.inode(&a)
	if first == w.inode(&b) {
		t.Fatal("different filesystems shared a view inode")
	}
	if w.inode(&a) != first {
		t.Fatal("view identity was unstable")
	}
}

func TestMountedStorageMountsAndBindAliases(t *testing.T) {
	if os.Getenv("GUARDFIL_MOUNT_TEST") != "1" {
		t.Skip("requires mount capability on a disposable Linux runner")
	}
	source, view, service := mounted(t)
	policy := testPolicy + `  - id: mounted-secret
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.read], resources: [{kind: path, value: /workspace/nested/secret}]}
  - id: mounted-write
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/nested/locked}]}
`
	if _, err := service.SetPolicy([]byte(policy)); err != nil {
		t.Fatal(err)
	}
	mount := func(from, name, kind string, flags uintptr) string {
		t.Helper()
		dest := filepath.Join(source, name)
		if err := os.Mkdir(dest, 0700); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(from, dest, kind, flags, ""); err != nil {
			t.Fatalf("mount fixture %s: %v", name, err)
		}
		t.Cleanup(func() {
			// FUSE releases handles asynchronously, so the mediator can
			// still hold a descriptor here just after the last view close.
			var err error
			for range 100 {
				if err = unix.Unmount(dest, 0); err != unix.EBUSY {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Error(err)
			}
		})
		return dest
	}
	nested := mount("tmpfs", "nested", "tmpfs", unix.MS_NODEV|unix.MS_NOSUID)
	for name, data := range map[string]string{"ok": "mounted", "secret": "do-not-read", "locked": "do-not-write"} {
		if err := os.WriteFile(filepath.Join(nested, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(view, "nested/ok")); err != nil || string(got) != "mounted" {
		t.Fatalf("ordinary nested mount: %q %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(view, "nested/created"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(view, "nested/secret")); err == nil {
		t.Fatal("nested mount bypassed read policy")
	}
	if err := os.WriteFile(filepath.Join(view, "nested/locked"), []byte("bad"), 0600); err == nil {
		t.Fatal("nested mount bypassed write policy")
	}
	mount(filepath.Join(source, "protected"), "protected-alias", "", unix.MS_BIND)
	mount(filepath.Join(source, "secrets"), "secrets-alias", "", unix.MS_BIND)
	// Exercise the actual host launcher's storage mapping, including Linux's
	// filesystem-relative bind root, rather than a synthetic mountinfo fixture.
	repo, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(repo, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(repo)
		if parent == repo {
			t.Fatal("repository root not found")
		}
		repo = parent
	}
	cmd := exec.Command("python3", "-B", "-c", "import json,sys; from pathlib import Path; from deployments.local.workspace_scope import workspace_scope; print(json.dumps(workspace_scope(Path(sys.argv[1]))))", source)
	cmd.Dir = repo
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("host storage mapping: %s: %v", raw, err)
	}
	var scope approval.WorkspaceScope
	if err := json.Unmarshal(raw, &scope); err != nil {
		t.Fatal(err)
	}
	locations := map[string]approval.WorkspaceLocation{}
	for _, m := range scope.Mounts {
		locations[m.Virtual] = m
	}
	root, alias := locations["/workspace"], locations["/workspace/secrets-alias"]
	if alias.Filesystem != root.Filesystem || alias.Root != filepath.Join(root.Root, "secrets") {
		t.Fatalf("bind alias did not retain source coordinates: %+v", scope)
	}
	if locations["/workspace/nested"].Filesystem == root.Filesystem || locations["/workspace/nested"].Root != "/" {
		t.Fatalf("nested tmpfs did not retain its own storage identity: %+v", scope)
	}
	if err := os.WriteFile(filepath.Join(view, "protected-alias/config"), []byte("bad"), 0600); err == nil {
		t.Fatal("directory bind alias bypassed write policy")
	}
	if _, err := os.ReadFile(filepath.Join(view, "secrets-alias/token")); err == nil {
		t.Fatal("directory bind alias bypassed read policy")
	}
	mount("/proc", "host-proc", "", unix.MS_BIND)
	if _, err := os.ReadFile(filepath.Join(view, "host-proc/self/environ")); err == nil {
		t.Fatal("kernel API mount was exposed")
	}
	if got, err := os.ReadFile(filepath.Join(view, "nested/ok")); err != nil || string(got) != "mounted" {
		t.Fatalf("unsafe sibling mount prevented ordinary storage use: %q %v", got, err)
	}
}

func TestKernelFilesystemsAreNotStorage(t *testing.T) {
	fd, err := unix.Open("/proc", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if storageFilesystem(fd) != syscall.EACCES {
		t.Fatal("procfs accepted as ordinary storage")
	}
}
