package workspacefs

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type objectID struct{ dev, ino uint64 }

func statID(st *unix.Stat_t) objectID { return objectID{uint64(st.Dev), st.Ino} }

// Every helper owned by this host user shares the namespace lock. It covers
// bind aliases and overlapping sources too, without depending on their names.
// Ordinary file IO shares this lock and takes a per-inode lock; namespace
// mutations take it exclusively. No lock is held for the lifetime of a view.
func (w *Workspace) openCoordinator() error {
	dir := filepath.Join("/tmp", fmt.Sprintf("guardfil-workspace-%d", os.Geteuid()))
	if err := unix.Mkdir(dir, 0700); err != nil && err != syscall.EEXIST {
		return err
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		return fmt.Errorf("workspace coordination directory must be owner-only")
	}
	w.controlDir = statID(&st)
	w.coordinator, err = unix.Openat(fd, "namespace.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	if err = unix.Fstat(w.coordinator, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Nlink != 1 {
		return fmt.Errorf("workspace coordination file must be a private regular file")
	}
	w.controlFile = statID(&st)
	return nil
}

func flockContext(ctx context.Context, fd, mode int) error {
	for {
		if ctx.Err() != nil {
			return syscall.EINTR
		}
		err := unix.Flock(fd, mode|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			return err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return syscall.EINTR
		case <-timer.C:
		}
	}
}

func (w *Workspace) lock(ctx context.Context, namespaceWrite bool) error {
	w.mu.Lock()
	mode := unix.LOCK_SH
	if namespaceWrite {
		mode = unix.LOCK_EX
	}
	if err := flockContext(ctx, w.coordinator, mode); err != nil {
		w.mu.Unlock()
		return err
	}
	if err := w.refreshMounts(); err != nil {
		w.unlock()
		return err
	}
	return nil
}

func (w *Workspace) unlock() {
	unix.Flock(w.coordinator, unix.LOCK_UN)
	w.mu.Unlock()
}

func (w *Workspace) lockFile(ctx context.Context, fd int, write bool) (func(), error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	var volume unix.Statfs_t
	if err := unix.Fstatfs(fd, &volume); err != nil {
		return nil, err
	}
	// Byte-range locks live on our private local coordination file, so a
	// read-only or network-backed source need not support advisory locks.
	// Hash collisions merely serialize unrelated files; they cannot skip a lock.
	var key [16]byte
	binary.LittleEndian.PutUint64(key[:8], st.Ino)
	binary.LittleEndian.PutUint32(key[8:12], uint32(volume.Fsid.Val[0]))
	binary.LittleEndian.PutUint32(key[12:16], uint32(volume.Fsid.Val[1]))
	h := fnv.New64a()
	h.Write(key[:])
	mode := int16(unix.F_RDLCK)
	if write {
		mode = unix.F_WRLCK
	}
	lock := unix.Flock_t{Type: mode, Whence: int16(unix.SEEK_SET), Start: int64(h.Sum64() & ((1 << 63) - 1)), Len: 1}
	for {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		err := unix.FcntlFlock(uintptr(w.coordinator), unix.F_OFD_SETLK, &lock)
		if err == nil {
			break
		}
		if err != syscall.EAGAIN && err != syscall.EACCES && err != syscall.EINTR {
			return nil, err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, syscall.EINTR
		case <-timer.C:
		}
	}
	return func() {
		lock.Type = unix.F_UNLCK
		unix.FcntlFlock(uintptr(w.coordinator), unix.F_OFD_SETLK, &lock)
	}, nil
}
