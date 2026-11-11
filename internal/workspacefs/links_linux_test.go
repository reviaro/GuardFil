package workspacefs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMountedHardLinksPreserveAllAliasRules(t *testing.T) {
	source, view, service := mounted(t)
	// Existing and newly created links support ordinary package/build IO.
	if err := os.Link(filepath.Join(source, "ok.txt"), filepath.Join(source, "existing-link")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(view, "existing-link")); err != nil || string(got) != "public" {
		t.Fatalf("existing hard link: %q %v", got, err)
	}
	if err := os.Link(filepath.Join(view, "existing-link"), filepath.Join(view, "new-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(view, "new-link"), []byte("linked"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(source, "ok.txt")); err != nil || string(got) != "linked" {
		t.Fatalf("hard link write: %q %v", got, err)
	}
	open, err := os.OpenFile(filepath.Join(view, "new-link"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	policy := testPolicy + `
  - id: restrict-one-alias
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/existing-link}]}
`
	if _, err := service.SetPolicy([]byte(policy)); err != nil {
		t.Fatal(err)
	}
	if _, err := open.WriteAt([]byte("bad"), 0); err == nil {
		t.Fatal("open handle bypassed a restriction on another hard link")
	}
	for label, operation := range map[string]func() error{
		"write":  func() error { return os.WriteFile(filepath.Join(view, "ok.txt"), []byte("bad"), 0600) },
		"chmod":  func() error { return os.Chmod(filepath.Join(view, "new-link"), 0644) },
		"unlink": func() error { return os.Remove(filepath.Join(view, "new-link")) },
		"rename": func() error { return os.Rename(filepath.Join(view, "new-link"), filepath.Join(view, "moved-link")) },
		"link":   func() error { return os.Link(filepath.Join(view, "new-link"), filepath.Join(view, "another-link")) },
	} {
		if err := operation(); err == nil {
			t.Errorf("%s bypassed alias policy", label)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(source, "ok.txt")); string(got) != "linked" {
		t.Fatalf("denied operation changed linked contents: %q", got)
	}
	// A source with an external hard link has no policy name for that alias.
	outside := filepath.Join(filepath.Dir(source), "outside-link")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(source, "external-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(view, "external-link")); err == nil {
		t.Fatal("unaccounted external alias was exposed")
	}
}

func TestMountedAbsoluteLinksInsideWorkspace(t *testing.T) {
	source, view, _ := mounted(t)
	for name, target := range map[string]string{"host-absolute": filepath.Join(source, "ok.txt"), "virtual-absolute": "/workspace/ok.txt", "host-secret": filepath.Join(source, "secrets/token")} {
		if err := os.Symlink(target, filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/workspace/ok.txt", filepath.Join(view, "created-absolute")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host-absolute", "virtual-absolute", "created-absolute"} {
		if got, err := os.ReadFile(filepath.Join(view, name)); err != nil || string(got) != "public" {
			t.Fatalf("absolute workspace link %s: %q %v", name, got, err)
		}
		if link, err := os.Readlink(filepath.Join(view, name)); err != nil || filepath.IsAbs(link) {
			t.Fatalf("link exposed host path: %q %v", link, err)
		}
	}
	if _, err := os.ReadFile(filepath.Join(view, "host-secret")); err == nil {
		t.Fatal("absolute host alias bypassed policy")
	}
}

func TestHardLinkBatchesAndLargeDirectoryRename(t *testing.T) {
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "before"), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(source, "before", fmt.Sprintf("file-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	denied := false
	w, err := New(source, "/workspace", func(_ context.Context, _ bool, paths ...string) error {
		if len(paths) > 16 {
			t.Fatalf("oversized policy batch: %d", len(paths))
		}
		for _, p := range paths {
			if denied && strings.HasSuffix(p, "file-4099") {
				return syscall.EACCES
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx := context.Background()
	if got := w.root.Rename(ctx, "before", w.root, "after", 0); got != 0 {
		t.Fatalf("large directory rename: %v", got)
	}
	denied = true
	if got := w.root.Rename(ctx, "after", w.root, "blocked", 0); got != syscall.EACCES {
		t.Fatalf("late restricted descendant was not checked: %v", got)
	}
	denied = false
	first := filepath.Join(source, "after/file-0000")
	for i := 0; i < 20; i++ {
		if err := os.Link(first, filepath.Join(source, fmt.Sprintf("link-%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := w.open("link-19", unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := w.checkFD(ctx, fd, "link-19", false); err != nil {
		t.Fatalf("many hard links: %v", err)
	}
}
