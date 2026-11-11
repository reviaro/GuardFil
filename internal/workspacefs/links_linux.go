package workspacefs

import (
	"context"
	"io"
	"os"
	"path"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// aliases accounts for every hard link before exposing an object. An alias
// outside this workspace cannot be checked against its policy, so such an
// object remains unavailable. The namespace lock excludes other mediators'
// link, unlink and rename operations for the entire check and backing IO.
func (w *Workspace) aliases(ctx context.Context, st *unix.Stat_t) ([]string, error) {
	directory := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	mounted := len(w.mountRoots) > 0
	if !mounted && (directory || st.Nlink <= 1) {
		return nil, nil
	}
	var found []string
	type entryID struct {
		parent objectID
		name   string
	}
	entriesSeen := map[entryID]bool{}
	ancestors := map[objectID]bool{}
	var walk func(string) error
	walk = func(rel string) error {
		if ctx.Err() != nil {
			return syscall.EINTR
		}
		fd, err := w.open(rel, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		dir := os.NewFile(uintptr(fd), "workspace-aliases")
		defer dir.Close()
		_, parent, err := w.actual(fd)
		if err != nil {
			return err
		}
		id := statID(parent)
		if ancestors[id] {
			return syscall.ELOOP
		}
		ancestors[id] = true
		defer delete(ancestors, id)
		if rel == "." && id == statID(st) {
			found = append(found, rel)
		}
		for {
			entries, err := dir.ReadDir(128)
			if err != nil && err != io.EOF {
				return err
			}
			for _, entry := range entries {
				if ctx.Err() != nil {
					return syscall.EINTR
				}
				name := path.Join(rel, entry.Name())
				child, openErr := w.open(name, unix.O_PATH)
				if openErr != nil {
					continue
				}
				_, info, infoErr := w.actual(child)
				unix.Close(child)
				if infoErr != nil {
					continue
				}
				if statID(info) == statID(st) {
					found = append(found, name)
					// Directory binds repeat the same physical directory
					// entries. File bind roots are aliases, not hard links.
					if !w.mountRoots[name] {
						entriesSeen[entryID{id, entry.Name()}] = true
					}
				}
				if !mounted && uint64(len(entriesSeen)) == uint64(st.Nlink) {
					return nil
				}
				if info.Mode&syscall.S_IFMT == syscall.S_IFDIR {
					if err := walk(name); err != nil {
						return err
					}
				}
				if !mounted && uint64(len(entriesSeen)) == uint64(st.Nlink) {
					return nil
				}
			}
			if err == io.EOF {
				return nil
			}
		}
	}
	if err := walk("."); err != nil {
		return nil, err
	}
	if !directory && st.Nlink > 1 && uint64(len(entriesSeen)) != uint64(st.Nlink) {
		return nil, syscall.EACCES
	}
	return found, nil
}

func (n *node) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if err := n.w.lock(ctx, true); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer n.w.unlock()
	other, ok := target.(*node)
	if !ok || other.w != n.w {
		return nil, syscall.EXDEV
	}
	from, to := other.relative(), path.Join(n.relative(), name)
	fd, err := n.w.open(from, unix.O_PATH)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(fd)
	st, err := n.w.checkFD(ctx, fd, from, false)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	if statID(st) != other.id || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, syscall.EACCES
	}
	if _, err = n.w.checkFD(ctx, fd, from, true); err != nil {
		return nil, fs.ToErrno(err)
	}
	parent, base, err := n.w.parent(ctx, to)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(parent)
	// Link the pinned object; never follow an agent-controlled source path.
	// /proc/self/fd is host-generated and AT_SYMLINK_FOLLOW refers to this FD.
	if err := unix.Linkat(unix.AT_FDCWD, fdPath(fd), parent, base, unix.AT_SYMLINK_FOLLOW); err != nil {
		return nil, fs.ToErrno(err)
	}
	if err := unix.Fstat(fd, st); err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.child(ctx, st, out), 0
}
