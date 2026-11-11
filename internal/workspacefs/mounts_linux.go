package workspacefs

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Ordinary storage mounts can be mediated. Kernel API filesystems and other
// FUSE servers are excluded: their apparent regular files can expose host
// process state or re-enter this mediator instead of behaving like storage.
func storageFilesystem(fd int) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return err
	}
	switch st.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC,
		unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.NFS_SUPER_MAGIC,
		unix.CIFS_SUPER_MAGIC, unix.SMB2_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, unix.RAMFS_MAGIC:
		return nil
	default:
		return syscall.EACCES
	}
}

var mountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)

// Refresh while holding the namespace lock. Mounts are owner-controlled, but
// an added bind alias must never skip the all-alias policy check.
func (w *Workspace) refreshMounts() error {
	root, err := os.Readlink(fdPath(w.fd))
	if err != nil {
		return err
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()
	roots := map[string]bool{}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 6 {
			return syscall.EIO
		}
		point := mountEscapes.Replace(fields[4])
		rel, err := filepath.Rel(root, point)
		if err == nil && rel != "." && filepath.IsLocal(rel) {
			roots[rel] = true
		}
	}
	if err := scan.Err(); err != nil {
		return err
	}
	w.mountRoots = roots
	return nil
}

// Backing inode numbers are only unique within a filesystem. Give FUSE a
// stable view identity keyed by device and inode, including bind aliases.
func (w *Workspace) inode(st *unix.Stat_t) uint64 {
	id := statID(st)
	if number, ok := w.inodes[id]; ok {
		return number
	}
	number := uint64(len(w.inodes)) + 1
	w.inodes[id] = number
	return number
}
