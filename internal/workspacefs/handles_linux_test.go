package workspacefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMountedUnlinkedHandleRemainsUsableAndRevocable(t *testing.T) {
	source, view, service := mounted(t)
	f, err := os.OpenFile(filepath.Join(view, "ok.txt"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(filepath.Join(view, "ok.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "ok.txt")); !os.IsNotExist(err) {
		t.Fatalf("unlink did not remove the backing name: %v", err)
	}
	buf := make([]byte, 6)
	if _, err := f.ReadAt(buf, 0); err != nil || string(buf) != "public" {
		t.Fatalf("open-unlinked read: %q %v", buf, err)
	}
	if _, err := f.WriteAt([]byte("edited"), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4); err != nil {
		t.Fatalf("open-unlinked truncate: %v", err)
	}
	if info, err := f.Stat(); err != nil || info.Size() != 4 {
		t.Fatalf("open-unlinked stat: %v %v", info, err)
	}
	policy := strings.Replace(testPolicy, "id: read\n    effect: allow", "id: read\n    effect: deny", 1)
	policy = strings.Replace(policy, "id: write\n    effect: allow", "id: write\n    effect: deny", 1)
	if _, err := service.SetPolicy([]byte(policy)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadAt(buf, 0); err == nil {
		t.Fatal("unlinked handle bypassed read revocation")
	}
	if _, err := f.WriteAt([]byte("bad"), 0); err == nil {
		t.Fatal("unlinked handle bypassed write revocation")
	}
	if err := f.Truncate(0); err == nil {
		t.Fatal("unlinked handle bypassed truncate revocation")
	}
}

func TestMountedLiteralDeletedSuffixIsAnOrdinaryFilename(t *testing.T) {
	source, view, _ := mounted(t)
	name := "note (deleted)"
	if err := os.WriteFile(filepath.Join(source, name), []byte("still here"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(view, name)); err != nil || string(got) != "still here" {
		t.Fatalf("literal deleted suffix: %q %v", got, err)
	}
}
