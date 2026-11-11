package workspacefs

import (
	"context"
	"path"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// Mknod creates only FIFO/socket namespace entries. Linux keeps their live
// endpoints on the FUSE inode: neither the backing inode nor another view
// shares the connection/pipe. Device nodes could expose host IO and are denied.
func (n *node) Mknod(ctx context.Context, name string, mode uint32, dev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	kind := mode & syscall.S_IFMT
	if (kind != syscall.S_IFIFO && kind != syscall.S_IFSOCK) || dev != 0 {
		return nil, syscall.EACCES
	}
	if err := n.w.lock(ctx, true); err != nil {
		return nil, fs.ToErrno(err)
	}
	defer n.w.unlock()
	rel := path.Join(n.relative(), name)
	if err := n.w.check(ctx, false, rel); err != nil {
		return nil, fs.ToErrno(err)
	}
	parent, base, err := n.w.parent(ctx, rel)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(parent)
	if err := unix.Mknodat(parent, base, kind|mode&0777, 0); err != nil {
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
