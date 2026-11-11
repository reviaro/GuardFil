// Package workspacefs exposes a policy-mediated view of a workspace. The raw
// source must never be mounted into the agent. All backing access is relative
// to a pinned directory descriptor; no agent-supplied path reaches the host
// filesystem through an unconstrained open.
package workspacefs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// Authorize decides the actual read or write under the current policy. It must
// fail closed if the service is unavailable and bind identity outside paths.
type Authorize func(ctx context.Context, write bool, paths ...string) error

type Workspace struct {
	mu          sync.Mutex
	fd          int
	coordinator int
	controlDir  objectID
	controlFile objectID
	virtual     string
	inodes      map[objectID]uint64
	mountRoots  map[string]bool
	authorize   Authorize
	root        *node
}

type node struct {
	fs.Inode
	w  *Workspace
	id objectID
}

// New pins source. Close is called only after the FUSE server has stopped.
func New(source, virtual string, authorize Authorize) (*Workspace, error) {
	if authorize == nil || !path.IsAbs(virtual) || path.Clean(virtual) != virtual || virtual == "/" {
		return nil, errors.New("workspace requires an authorizer and a canonical virtual root")
	}
	fd, err := unix.Open(source, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	w := &Workspace{fd: fd, coordinator: -1, virtual: virtual, authorize: authorize, inodes: map[objectID]uint64{statID(&st): 1}}
	if err := w.openCoordinator(); err != nil {
		w.Close()
		return nil, fmt.Errorf("workspace coordination unavailable: %w", err)
	}
	w.root = &node{w: w, id: statID(&st)}
	// Detect kernel support now, instead of silently falling back to pathname IO.
	probe, err := w.open(".", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("workspace source requires supported storage and openat2: %w", err)
	}
	unix.Close(probe)
	return w, nil
}

func (w *Workspace) Close() error {
	err := unix.Close(w.fd)
	if w.coordinator >= 0 {
		unix.Close(w.coordinator)
		w.coordinator = -1
	}
	return err
}

// Mount deliberately disables data and attribute caching. Every later read or
// write, including through an already open handle, gets a fresh policy check.
func (w *Workspace) Mount(mountpoint string, allowOther bool) (*fuse.Server, error) {
	root, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", w.fd))
	if err != nil {
		return nil, err
	}
	view, err := filepath.EvalSymlinks(mountpoint)
	if err != nil {
		return nil, err
	}
	view, err = filepath.Abs(view)
	if err != nil {
		return nil, err
	}
	if view == root || strings.HasPrefix(view, root+"/") || strings.HasPrefix(root, view+"/") {
		return nil, errors.New("workspace view and source must be disjoint")
	}
	entries, err := os.ReadDir(view)
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		return nil, errors.New("workspace mountpoint must be empty")
	}
	st, err := os.Stat(view)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm() != 0700 {
		return nil, errors.New("workspace mountpoint must have mode 0700")
	}
	zero := time.Duration(0)
	return fs.Mount(view, w.root, &fs.Options{
		AttrTimeout: &zero, EntryTimeout: &zero, NegativeTimeout: &zero,
		NullPermissions: true,
		MountOptions: fuse.MountOptions{
			Name: "guardfil", FsName: "guardfil-workspace", AllowOther: allowOther,
			Options:       []string{"default_permissions", "nosuid", "nodev"},
			DisableXAttrs: true,
		},
	})
}

func (n *node) relative() string {
	p := n.Path(&n.w.root.Inode)
	if p == "" {
		return "."
	}
	return p
}

func (w *Workspace) open(p string, flags int) (int, error) {
	if !filepath.IsLocal(p) {
		return -1, syscall.EACCES
	}
	fd, err := unix.Openat2(w.fd, p, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, err
	}
	if err := storageFilesystem(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func fdPath(fd int) string { return fmt.Sprintf("/proc/self/fd/%d", fd) }

// actual derives the policy path from the opened object, not a prior realpath
// lookup. checkFD also evaluates every hard-link alias of that object.
func (w *Workspace) actual(fd int) (string, *unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", nil, err
	}
	if statID(&st) == w.controlDir || statID(&st) == w.controlFile {
		return "", nil, syscall.EACCES
	}
	typ := st.Mode & syscall.S_IFMT
	if typ != syscall.S_IFREG && typ != syscall.S_IFDIR && typ != syscall.S_IFLNK && typ != syscall.S_IFIFO && typ != syscall.S_IFSOCK {
		return "", nil, syscall.EACCES
	}
	root, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", w.fd))
	if err != nil {
		return "", nil, err
	}
	actual, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "", nil, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(w.fd, &rootStat); err != nil {
		return "", nil, err
	}
	if rootStat.Nlink == 0 {
		return "", nil, syscall.ESTALE
	}
	if st.Nlink == 0 {
		if typ != syscall.S_IFREG || !strings.HasSuffix(actual, " (deleted)") {
			return "", nil, syscall.ESTALE
		}
		// Linux retains the last name on an unlinked descriptor. Keep that
		// name and the original open name as policy subjects for later IO.
		actual = strings.TrimSuffix(actual, " (deleted)")
	}
	rel, err := filepath.Rel(root, actual)
	if err != nil || !filepath.IsLocal(rel) {
		return "", nil, syscall.EACCES
	}
	return rel, &st, nil
}

func (w *Workspace) check(ctx context.Context, write bool, names ...string) error {
	seen := map[string]bool{}
	var paths []string
	for _, name := range names {
		if !filepath.IsLocal(name) {
			return syscall.EACCES
		}
		p := path.Join(w.virtual, name)
		if !seen[p] {
			paths = append(paths, p)
			seen[p] = true
		}
	}
	for len(paths) > 0 {
		count := min(16, len(paths))
		if err := w.authorize(ctx, write, paths[:count]...); err != nil {
			// FUSE interrupts include Go's SIGURG preemption signal. Preserve the
			// interrupt result so a canceled request is not reported as a policy
			// denial; no backing mutation has occurred at this point.
			if ctx.Err() != nil {
				return syscall.EINTR
			}
			return syscall.EACCES
		}
		paths = paths[count:]
	}
	return nil
}

func (w *Workspace) checkFD(ctx context.Context, fd int, original string, write bool) (*unix.Stat_t, error) {
	actual, st, err := w.actual(fd)
	if err != nil {
		return nil, err
	}
	aliases, err := w.aliases(ctx, st)
	if err != nil {
		return nil, err
	}
	return st, w.check(ctx, write, append([]string{original, actual}, aliases...)...)
}

func (n *node) info(ctx context.Context, rel string) (*unix.Stat_t, error) {
	fd, err := n.w.open(rel, unix.O_PATH)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	st, err := n.w.checkFD(ctx, fd, rel, false)
	if err == nil && (st.Mode&syscall.S_IFMT == syscall.S_IFIFO || st.Mode&syscall.S_IFMT == syscall.S_IFSOCK) {
		// Linux implements FIFO/socket IO on the view's inode, without FUSE
		// read/write callbacks. Admit a local IPC capability only when both
		// directions are allowed. It never opens the host IPC object.
		_, err = n.w.checkFD(ctx, fd, rel, true)
	}
	return st, err
}

func (w *Workspace) attr(st *unix.Stat_t, out *fuse.Attr) {
	out.Ino = w.inode(st)
	out.Size = uint64(st.Size)
	out.Blocks = uint64(st.Blocks)
	out.Mode = st.Mode
	out.Nlink = uint32(st.Nlink)
	out.Uid = st.Uid
	out.Gid = st.Gid
	out.Blksize = uint32(st.Blksize)
	out.Atime = uint64(st.Atim.Sec)
	out.Atimensec = uint32(st.Atim.Nsec)
	out.Mtime = uint64(st.Mtim.Sec)
	out.Mtimensec = uint32(st.Mtim.Nsec)
	out.Ctime = uint64(st.Ctim.Sec)
	out.Ctimensec = uint32(st.Ctim.Nsec)
}

func (n *node) child(ctx context.Context, st *unix.Stat_t, out *fuse.EntryOut) *fs.Inode {
	n.w.attr(st, &out.Attr)
	return n.NewInode(ctx, &node{w: n.w, id: statID(st)}, fs.StableAttr{Mode: st.Mode, Ino: n.w.inode(st)})
}

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if err := n.w.lock(ctx, false); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer n.w.unlock()
	st, err := n.info(ctx, path.Join(n.relative(), name))
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.child(ctx, st, out), 0
}

func (n *node) Getattr(ctx context.Context, file fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if err := n.w.lock(ctx, false); err != nil {
		return fs.ToErrno(err)
	}
	defer n.w.unlock()
	var st *unix.Stat_t
	var err error
	if h, ok := file.(*handle); ok && h.w == n.w {
		st, err = n.w.checkFD(ctx, int(h.f.Fd()), h.original, false)
	} else {
		st, err = n.info(ctx, n.relative())
	}
	if err != nil {
		return fs.ToErrno(err)
	}
	if statID(st) != n.id {
		return syscall.ESTALE
	}
	n.w.attr(st, &out.Attr)
	return 0
}

func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if err := n.w.lock(ctx, false); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := n.relative()
	fd, err := n.w.open(rel, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	f := os.NewFile(uintptr(fd), "workspace-directory")
	defer f.Close()
	if _, err := n.w.checkFD(ctx, fd, rel, false); err != nil {
		return nil, fs.ToErrno(err)
	}
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	var result []fuse.DirEntry
	for _, ent := range entries {
		st, err := n.info(ctx, path.Join(rel, ent.Name()))
		if err == nil {
			result = append(result, fuse.DirEntry{Name: ent.Name(), Mode: st.Mode, Ino: n.w.inode(st)})
		}
	}
	return fs.NewListDirStream(result), 0
}

type handle struct {
	w        *Workspace
	f        *os.File
	original string
	append   bool
}

func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if err := n.w.lock(ctx, false); err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := n.relative()
	if n.Mode()&syscall.S_IFMT != syscall.S_IFREG {
		return nil, 0, syscall.EACCES
	}
	// Opening must never truncate, create or modify a file before authorization.
	fd, err := n.w.open(rel, int(flags)&(unix.O_ACCMODE|unix.O_APPEND)|unix.O_NONBLOCK)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	f := os.NewFile(uintptr(fd), "workspace-file")
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	unlock, err := n.w.lockFile(ctx, fd, flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_TRUNC != 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	defer unlock()
	_, st, err := n.w.actual(fd)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	if statID(st) != n.id || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, 0, syscall.ESTALE
	}
	if flags&unix.O_ACCMODE != unix.O_WRONLY {
		if _, err = n.w.checkFD(ctx, fd, rel, false); err != nil {
			return nil, 0, fs.ToErrno(err)
		}
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_TRUNC != 0 {
		if _, err = n.w.checkFD(ctx, fd, rel, true); err != nil {
			return nil, 0, fs.ToErrno(err)
		}
	}
	if flags&unix.O_TRUNC != 0 {
		if err = f.Truncate(0); err != nil {
			return nil, 0, fs.ToErrno(err)
		}
	}
	ok = true
	return &handle{w: n.w, f: f, original: rel, append: flags&unix.O_APPEND != 0}, fuse.FOPEN_DIRECT_IO, 0
}

func (h *handle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if err := h.w.lock(ctx, false); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer h.w.unlock()
	unlock, err := h.w.lockFile(ctx, int(h.f.Fd()), false)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unlock()
	if _, err := h.w.checkFD(ctx, int(h.f.Fd()), h.original, false); err != nil {
		return nil, fs.ToErrno(err)
	}
	n, err := h.f.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, fs.ToErrno(err)
	}
	return fuse.ReadResultData(dest[:n]), 0
}

func (h *handle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if err := h.w.lock(ctx, false); err != nil {
		return 0, fs.ToErrno(err)
	}
	defer h.w.unlock()
	unlock, err := h.w.lockFile(ctx, int(h.f.Fd()), true)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	defer unlock()
	_, err = h.w.checkFD(ctx, int(h.f.Fd()), h.original, true)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	var n int
	if h.append {
		// Let the backing filesystem position each append atomically, including
		// across independent executor sessions using this same source directory.
		n, err = h.f.Write(data)
	} else {
		n, err = h.f.WriteAt(data, off)
	}
	return uint32(n), fs.ToErrno(err)
}

func (h *handle) Release(context.Context) syscall.Errno {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	return fs.ToErrno(h.f.Close())
}
func (h *handle) Fsync(context.Context, uint32) syscall.Errno { return fs.ToErrno(h.f.Sync()) }
func (h *handle) Flush(context.Context) syscall.Errno         { return 0 }

// parent pins the parent directory and authorizes the child under both its
// requested name and the resolved parent. All namespace mutations use this FD.
func (w *Workspace) parent(ctx context.Context, rel string) (int, string, error) {
	if rel == "." || !filepath.IsLocal(rel) {
		return -1, "", syscall.EACCES
	}
	fd, err := w.open(path.Dir(rel), unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return -1, "", err
	}
	actual, _, err := w.actual(fd)
	if err == nil {
		err = w.check(ctx, true, rel, path.Join(actual, path.Base(rel)))
	}
	if err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	return fd, path.Base(rel), nil
}

func (n *node) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if err := n.w.lock(ctx, true); err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := path.Join(n.relative(), name)
	parent, base, err := n.w.parent(ctx, rel)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, base, unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|int(flags&(unix.O_ACCMODE|unix.O_APPEND)), mode&0777)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	f := os.NewFile(uintptr(fd), "workspace-file")
	_, st, err := n.w.actual(fd)
	if err != nil {
		f.Close()
		return nil, nil, 0, fs.ToErrno(err)
	}
	return n.child(ctx, st, out), &handle{w: n.w, f: f, original: rel, append: flags&unix.O_APPEND != 0}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if err := n.w.lock(ctx, true); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := path.Join(n.relative(), name)
	parent, base, err := n.w.parent(ctx, rel)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(parent)
	if err = unix.Mkdirat(parent, base, mode&0777); err != nil {
		return nil, fs.ToErrno(err)
	}
	fd, err := n.w.open(rel, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(fd)
	_, st, err := n.w.actual(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.child(ctx, st, out), 0
}

func (n *node) remove(ctx context.Context, name string, dir bool) syscall.Errno {
	if err := n.w.lock(ctx, true); err != nil {
		return fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := path.Join(n.relative(), name)
	fd, err := n.w.open(rel, unix.O_PATH)
	if err != nil {
		return fs.ToErrno(err)
	}
	_, err = n.w.checkFD(ctx, fd, rel, true)
	unix.Close(fd)
	if err != nil {
		return fs.ToErrno(err)
	}
	parent, base, err := n.w.parent(ctx, rel)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer unix.Close(parent)
	flags := 0
	if dir {
		flags = unix.AT_REMOVEDIR
	}
	return fs.ToErrno(unix.Unlinkat(parent, base, flags))
}
func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	return n.remove(ctx, name, false)
}
func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	return n.remove(ctx, name, true)
}

func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if err := n.w.lock(ctx, false); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := n.relative()
	fd, err := n.w.open(rel, unix.O_PATH)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(fd)
	if _, err = n.w.checkFD(ctx, fd, rel, false); err != nil {
		return nil, fs.ToErrno(err)
	}
	buf := make([]byte, 4096)
	size, err := unix.Readlinkat(fd, "", buf)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	if size == len(buf) {
		return nil, syscall.EACCES
	}
	target, err := n.w.linkTarget(rel, string(buf[:size]))
	return []byte(target), fs.ToErrno(err)
}

func (w *Workspace) safeLink(rel, target string) bool {
	_, err := w.linkTarget(rel, target)
	return err == nil
}

// Absolute links into the selected source or virtual workspace become
// relative links inside the view. The host source path is never exposed and
// the link works even when a container uses a different mountpoint.
func (w *Workspace) linkTarget(rel, target string) (string, error) {
	if path.IsAbs(target) {
		target = path.Clean(target)
		root, err := os.Readlink(fdPath(w.fd))
		if err != nil {
			return "", err
		}
		var inside string
		switch {
		case target == w.virtual || strings.HasPrefix(target, w.virtual+"/"):
			inside = strings.TrimPrefix(target, w.virtual)
		case target == root || strings.HasPrefix(target, root+"/"):
			inside = strings.TrimPrefix(target, root)
		default:
			return "", syscall.EACCES
		}
		return filepath.Rel(path.Dir(path.Join(w.virtual, rel)), path.Join(w.virtual, inside))
	}
	resolved := path.Clean(path.Join(path.Dir(path.Join(w.virtual, rel)), target))
	if resolved != w.virtual && !strings.HasPrefix(resolved, w.virtual+"/") {
		return "", syscall.EACCES
	}
	return target, nil
}

func (n *node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if err := n.w.lock(ctx, true); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := path.Join(n.relative(), name)
	target, err := n.w.linkTarget(rel, target)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	parent, base, err := n.w.parent(ctx, rel)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(parent)
	if err = unix.Symlinkat(target, parent, base); err != nil {
		return nil, fs.ToErrno(err)
	}
	fd, err := n.w.open(rel, unix.O_PATH)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(fd)
	_, st, err := n.w.actual(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.child(ctx, st, out), 0
}

// Device nodes, xattrs and passthrough FDs remain unavailable. FIFO and Unix
// socket endpoints belong to this FUSE view, not the backing host filesystem.

func (n *node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if err := n.w.lock(ctx, true); err != nil {
		return fs.ToErrno(err)
	}
	defer n.w.unlock()
	other, ok := newParent.(*node)
	if !ok || other.w != n.w || flags & ^uint32(unix.RENAME_NOREPLACE) != 0 {
		return syscall.EACCES
	}
	oldRel, newRel := path.Join(n.relative(), name), path.Join(other.relative(), newName)
	if err := n.w.checkMove(ctx, oldRel, newRel); err != nil {
		return fs.ToErrno(err)
	}
	// Replacement also removes a name for the destination object. Its other
	// aliases must not turn a protected file into an unprotected one.
	if fd, err := n.w.open(newRel, unix.O_PATH); err == nil {
		_, err = n.w.checkFD(ctx, fd, newRel, true)
		unix.Close(fd)
		if err != nil {
			return fs.ToErrno(err)
		}
	} else if err != syscall.ENOENT {
		return fs.ToErrno(err)
	}
	oldFD, oldBase, err := n.w.parent(ctx, oldRel)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer unix.Close(oldFD)
	newFD, newBase, err := n.w.parent(ctx, newRel)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer unix.Close(newFD)
	return fs.ToErrno(unix.Renameat2(oldFD, oldBase, newFD, newBase, uint(flags)))
}

// Moving a directory cannot move a restricted descendant out of its rule.
func (w *Workspace) checkMove(ctx context.Context, from, to string) error {
	if ctx.Err() != nil {
		return syscall.EINTR
	}
	fd, err := w.open(from, unix.O_PATH)
	if err != nil {
		return err
	}
	st, err := w.checkFD(ctx, fd, from, false)
	if err == nil {
		_, err = w.checkFD(ctx, fd, from, true)
	}
	unix.Close(fd)
	if err != nil {
		return err
	}
	if err = w.check(ctx, true, to); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil
	}
	dirFD, err := w.open(from, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dirFD), "workspace-move")
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(128)
		if err != nil && err != io.EOF {
			return err
		}
		for _, entry := range entries {
			if err := w.checkMove(ctx, path.Join(from, entry.Name()), path.Join(to, entry.Name())); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func (n *node) Setattr(ctx context.Context, file fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if err := n.w.lock(ctx, false); err != nil {
		return fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := n.relative()
	if n.Mode()&syscall.S_IFMT == syscall.S_IFIFO || n.Mode()&syscall.S_IFMT == syscall.S_IFSOCK {
		return syscall.EOPNOTSUPP
	}
	flags := unix.O_RDONLY | unix.O_NONBLOCK
	if _, yes := in.GetSize(); yes {
		flags = unix.O_WRONLY | unix.O_NONBLOCK
	}
	var fd int
	var err error
	if h, ok := file.(*handle); ok && h.w == n.w {
		fd, err = unix.FcntlInt(h.f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		rel = h.original
	} else {
		fd, err = n.w.open(rel, flags)
	}
	if err != nil {
		return fs.ToErrno(err)
	}
	f := os.NewFile(uintptr(fd), "workspace-attributes")
	defer f.Close()
	unlock, err := n.w.lockFile(ctx, fd, true)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer unlock()
	st, err := n.w.checkFD(ctx, fd, rel, true)
	if err != nil {
		return fs.ToErrno(err)
	}
	if statID(st) != n.id {
		return syscall.ESTALE
	}
	if uid, set := in.GetUID(); set && uid != uint32(os.Getuid()) {
		return syscall.EPERM
	}
	if gid, set := in.GetGID(); set && gid != uint32(os.Getgid()) {
		return syscall.EPERM
	}
	if mode, set := in.GetMode(); set {
		if err = unix.Fchmod(fd, mode&0777); err != nil {
			return fs.ToErrno(err)
		}
	}
	if size, set := in.GetSize(); set {
		if size > 1<<63-1 {
			return syscall.EFBIG
		}
		if err = f.Truncate(int64(size)); err != nil {
			return fs.ToErrno(err)
		}
	}
	mt, mset := in.GetMTime()
	at, aset := in.GetATime()
	if mset || aset {
		times := []unix.Timespec{st.Atim, st.Mtim}
		if aset {
			times[0] = unix.NsecToTimespec(at.UnixNano())
		}
		if mset {
			times[1] = unix.NsecToTimespec(mt.UnixNano())
		}
		if err = unix.UtimesNanoAt(fd, "", times, unix.AT_EMPTY_PATH); err != nil {
			return fs.ToErrno(err)
		}
	}
	if err = unix.Fstat(fd, st); err != nil {
		return fs.ToErrno(err)
	}
	n.w.attr(st, &out.Attr)
	return 0
}
