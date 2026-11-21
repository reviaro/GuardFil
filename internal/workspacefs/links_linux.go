package workspacefs

import (
	"context"
	"io"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type symlinkInfo struct {
	link        string
	id          objectID
	resolved    string
	resolvedID  objectID
	resolvedDir bool
	dangling    string
}

func (w *Workspace) getSymlinks(ctx context.Context) ([]symlinkInfo, error) {
	w.symlinkMu.Lock()
	if w.locked && w.symlinksCached {
		syms := w.cachedSymlinks
		w.symlinkMu.Unlock()
		return syms, nil
	}
	w.symlinkMu.Unlock()

	syms, err := w.scanSymlinks(ctx)
	if err != nil {
		return nil, err
	}

	w.symlinkMu.Lock()
	if w.locked {
		w.cachedSymlinks = syms
		w.symlinksCached = true
	}
	w.symlinkMu.Unlock()
	return syms, nil
}

func (w *Workspace) scanSymlinks(ctx context.Context) ([]symlinkInfo, error) {
	var symlinks []symlinkInfo
	ancestors := map[objectID]bool{}
	var walk func(string) error
	walk = func(rel string) error {
		if ctx.Err() != nil {
			return syscall.EINTR
		}
		fd, err := w.open(rel, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			if rel != "." && w.mountRoots[rel] {
				// Prune subtrees that are mount points of explicitly excluded/non-storage filesystems
				// (using the workspace mount table and existing storage classification).
				rawFD, openErr := unix.Openat2(w.fd, rel, &unix.OpenHow{
					Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
					Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
				})
				if openErr == nil {
					isStorage := storageFilesystem(rawFD) == nil
					unix.Close(rawFD)
					if !isStorage {
						return nil // prune excluded non-storage mount point without authorizing contents
					}
				}
			}
			return err
		}
		dir := os.NewFile(uintptr(fd), "workspace-symlink-scan")
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
				typ := entry.Type()
				if typ != os.ModeIrregular && !entry.IsDir() && typ&os.ModeSymlink == 0 {
					continue
				}
				if typ&os.ModeSymlink != 0 {
					if info, ok := w.inspectSymlink(ctx, name); ok {
						symlinks = append(symlinks, info)
					}
					continue
				}
				if entry.IsDir() {
					if err := walk(name); err != nil {
						return err
					}
					continue
				}
				child, openErr := w.open(name, unix.O_PATH)
				if openErr != nil {
					continue
				}
				var st unix.Stat_t
				statErr := unix.Fstat(child, &st)
				unix.Close(child)
				if statErr != nil {
					continue
				}
				if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
					if info, ok := w.inspectSymlink(ctx, name); ok {
						symlinks = append(symlinks, info)
					}
				} else if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
					if err := walk(name); err != nil {
						return err
					}
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
	return symlinks, nil
}

func (w *Workspace) inspectSymlink(ctx context.Context, name string) (symlinkInfo, bool) {
	fd, err := w.open(name, unix.O_PATH)
	if err != nil {
		return symlinkInfo{}, false
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return symlinkInfo{}, false
	}
	buf := make([]byte, 4096)
	size, err := unix.Readlinkat(fd, "", buf)
	unix.Close(fd)
	if err != nil || size == len(buf) {
		return symlinkInfo{}, false
	}
	target, err := w.linkTarget(name, string(buf[:size]))
	if err != nil {
		return symlinkInfo{}, false
	}
	return w.resolveSymlink(ctx, name, target, &st)
}

func (w *Workspace) resolveSymlink(ctx context.Context, linkPath, target string, initialStat *unix.Stat_t) (symlinkInfo, bool) {
	initialID := statID(initialStat)
	hops := 0

	startDir := path.Dir(linkPath)
	resolved := startDir
	var resolvedID objectID
	resolvedDir := true

	cfd, err := w.open(resolved, unix.O_PATH)
	if err == nil {
		var cst unix.Stat_t
		if unix.Fstat(cfd, &cst) == nil {
			resolvedID = statID(&cst)
			resolvedDir = (cst.Mode&syscall.S_IFMT == syscall.S_IFDIR)
		}
		unix.Close(cfd)
	}

	remaining := strings.Split(target, "/")

	for len(remaining) > 0 {
		if ctx.Err() != nil {
			return symlinkInfo{}, false
		}
		comp := remaining[0]
		remaining = remaining[1:]
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			if resolved == "." || resolved == "" {
				return symlinkInfo{}, false
			}
			resolved = path.Dir(resolved)
			cfd, err := w.open(resolved, unix.O_PATH)
			if err == nil {
				var cst unix.Stat_t
				if unix.Fstat(cfd, &cst) == nil {
					resolvedID = statID(&cst)
					resolvedDir = (cst.Mode&syscall.S_IFMT == syscall.S_IFDIR)
				}
				unix.Close(cfd)
			}
			continue
		}

		nextPath := path.Join(resolved, comp)
		fd, err := w.open(nextPath, unix.O_PATH)
		if err != nil {
			if err != syscall.ENOENT || !resolvedDir {
				return symlinkInfo{}, false
			}
			for _, rem := range remaining {
				if rem == ".." {
					return symlinkInfo{}, false
				}
			}
			danglingParts := append([]string{comp}, remaining...)
			return symlinkInfo{
				link:        linkPath,
				id:          initialID,
				resolved:    resolved,
				resolvedID:  resolvedID,
				resolvedDir: resolvedDir,
				dangling:    path.Join(danglingParts...),
			}, true
		}

		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return symlinkInfo{}, false
		}

		typ := st.Mode & syscall.S_IFMT
		if typ == syscall.S_IFLNK {
			hops++
			if hops > 40 {
				unix.Close(fd)
				return symlinkInfo{}, false
			}
			buf := make([]byte, 4096)
			size, rerr := unix.Readlinkat(fd, "", buf)
			unix.Close(fd)
			if rerr != nil || size == len(buf) {
				return symlinkInfo{}, false
			}
			subTarget, terr := w.linkTarget(nextPath, string(buf[:size]))
			if terr != nil {
				return symlinkInfo{}, false
			}
			subParts := strings.Split(subTarget, "/")
			remaining = append(subParts, remaining...)
			continue
		}

		unix.Close(fd)
		resolved = nextPath
		resolvedID = statID(&st)
		resolvedDir = (typ == syscall.S_IFDIR)

		if len(remaining) > 0 && !resolvedDir {
			return symlinkInfo{}, false
		}
	}

	return symlinkInfo{
		link:        linkPath,
		id:          initialID,
		resolved:    resolved,
		resolvedID:  resolvedID,
		resolvedDir: resolvedDir,
		dangling:    "",
	}, true
}

const (
	maxAliasExpansionCount = 1024
	maxAliasQueueCount     = 2048
)

func isSameOrDescendant(sub, base string) bool {
	if base == "." || base == "" {
		return true
	}
	if sub == base {
		return true
	}
	return strings.HasPrefix(sub, base+"/")
}

// findCyclicSymlinks builds a directed graph over in-workspace directory symlinks
// (resolved, non-dangling, target is a directory) with edge s1 -> s2 when s2's parent
// directory is the resolved target of s1 or a descendant of it. Any symlink in a cycle
// (including self-loops such as self -> ., up -> .., or multi-link cycles) is cyclic.
func findCyclicSymlinks(syms []symlinkInfo) map[string]bool {
	var dirSyms []symlinkInfo
	for _, s := range syms {
		if s.dangling == "" && s.resolvedDir {
			dirSyms = append(dirSyms, s)
		}
	}
	n := len(dirSyms)
	if n == 0 {
		return nil
	}
	adj := make([][]int, n)
	for i := 0; i < n; i++ {
		target := dirSyms[i].resolved
		for j := 0; j < n; j++ {
			parent := path.Dir(dirSyms[j].link)
			if isSameOrDescendant(parent, target) {
				adj[i] = append(adj[i], j)
			}
		}
	}
	cyclic := make(map[string]bool)
	for i := 0; i < n; i++ {
		visited := make([]bool, n)
		queue := make([]int, 0, n)
		for _, next := range adj[i] {
			if next == i {
				cyclic[dirSyms[i].link] = true
				break
			}
			visited[next] = true
			queue = append(queue, next)
		}
		if cyclic[dirSyms[i].link] {
			continue
		}
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			if curr == i {
				cyclic[dirSyms[i].link] = true
				break
			}
			for _, next := range adj[curr] {
				if next == i {
					cyclic[dirSyms[i].link] = true
					break
				}
				if !visited[next] {
					visited[next] = true
					queue = append(queue, next)
				}
			}
			if cyclic[dirSyms[i].link] {
				break
			}
		}
	}
	return cyclic
}

func (w *Workspace) isCyclicLink(ctx context.Context, rel string) (bool, error) {
	syms, err := w.getSymlinks(ctx)
	if err != nil {
		return false, err
	}
	w.symlinkMu.Lock()
	if w.locked && w.cyclicCached {
		c := w.cachedCyclic[rel]
		w.symlinkMu.Unlock()
		return c, nil
	}
	w.symlinkMu.Unlock()

	cyclic := findCyclicSymlinks(syms)

	w.symlinkMu.Lock()
	if w.locked {
		w.cachedCyclic = cyclic
		w.cyclicCached = true
	}
	w.symlinkMu.Unlock()
	return cyclic[rel], nil
}

func (w *Workspace) expandDestinationNames(ctx context.Context, names []string) ([]string, error) {
	symlinks, err := w.getSymlinks(ctx)
	if err != nil {
		return nil, err
	}
	cyclic := findCyclicSymlinks(symlinks)
	seen := map[string]bool{}
	var result []string
	add := func(p string) error {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
			if len(result) > maxAliasExpansionCount {
				return syscall.EACCES
			}
		}
		return nil
	}
	for _, n := range names {
		if err := add(n); err != nil {
			return nil, err
		}
	}

	for _, s := range symlinks {
		if s.dangling == "" || cyclic[s.link] {
			continue
		}
		targetPath := path.Clean(path.Join(s.resolved, s.dangling))
		for _, d := range names {
			if targetPath == d {
				if err := add(s.link); err != nil {
					return nil, err
				}
			} else if strings.HasPrefix(d, targetPath+"/") {
				suffix := strings.TrimPrefix(d, targetPath+"/")
				if err := add(path.Join(s.link, suffix)); err != nil {
					return nil, err
				}
			}
		}
	}

	type derivedItem struct {
		path string
		used map[string]bool
	}
	var queue []derivedItem
	for _, p := range result {
		queue = append(queue, derivedItem{path: p, used: map[string]bool{}})
	}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		item := queue[0]
		queue = queue[1:]
		for _, s := range symlinks {
			if s.dangling != "" || !s.resolvedDir || cyclic[s.link] {
				continue
			}
			if item.used[s.link] {
				continue
			}
			var suffix string
			var matches bool
			if s.resolved == "." {
				if item.path != "." {
					suffix = item.path
					matches = true
				}
			} else if strings.HasPrefix(item.path, s.resolved+"/") {
				suffix = strings.TrimPrefix(item.path, s.resolved+"/")
				matches = true
			}
			if matches {
				derived := path.Join(s.link, suffix)
				if err := add(derived); err != nil {
					return nil, err
				}
				if len(queue) >= maxAliasQueueCount {
					return nil, syscall.EACCES
				}
				newUsed := make(map[string]bool, len(item.used)+1)
				for k, v := range item.used {
					newUsed[k] = v
				}
				newUsed[s.link] = true
				queue = append(queue, derivedItem{path: derived, used: newUsed})
			}
		}
	}
	return result, nil
}

// aliases accounts for every hard link, bind mount, and symlink before exposing
// an object. An alias outside this workspace cannot be checked against its policy,
// so such an object remains unavailable. The namespace lock excludes other mediators'
// link, unlink and rename operations for the entire check and backing IO.
func (w *Workspace) aliases(ctx context.Context, st *unix.Stat_t, actualPaths ...string) ([]string, error) {
	directory := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	mounted := len(w.mountRoots) > 0

	var found []string
	seenPaths := map[string]bool{}
	addFound := func(p string) {
		if !seenPaths[p] {
			seenPaths[p] = true
			found = append(found, p)
		}
	}
	for _, p := range actualPaths {
		if p != "" {
			addFound(p)
		}
	}

	if mounted || (!directory && st.Nlink > 1) || len(found) == 0 {
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
				addFound(rel)
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
					typ := entry.Type()
					if !mounted && (directory || st.Nlink <= 1) && typ != os.ModeIrregular && !entry.IsDir() && typ&os.ModeSymlink == 0 {
						continue
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
						addFound(name)
						// Directory binds repeat the same physical directory
						// entries. File bind roots are aliases, not hard links.
						if !w.mountRoots[name] {
							entriesSeen[entryID{id, entry.Name()}] = true
						}
					}
					if !mounted && !directory && st.Nlink > 1 && uint64(len(entriesSeen)) == uint64(st.Nlink) {
						return nil
					}
					if info.Mode&syscall.S_IFMT == syscall.S_IFDIR {
						if err := walk(name); err != nil {
							return err
						}
					}
					if !mounted && !directory && st.Nlink > 1 && uint64(len(entriesSeen)) == uint64(st.Nlink) {
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
	}

	symlinks, err := w.getSymlinks(ctx)
	if err != nil {
		return nil, err
	}
	cyclic := findCyclicSymlinks(symlinks)

	for _, s := range symlinks {
		if cyclic[s.link] {
			continue
		}
		if s.id == statID(st) || (s.dangling == "" && s.resolvedID == statID(st)) {
			addFound(s.link)
		}
	}

	type derivedItem struct {
		path string
		used map[string]bool
	}
	var queue []derivedItem
	for _, p := range found {
		queue = append(queue, derivedItem{path: p, used: map[string]bool{}})
	}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		item := queue[0]
		queue = queue[1:]
		for _, s := range symlinks {
			if s.dangling != "" || !s.resolvedDir || cyclic[s.link] {
				continue
			}
			if item.used[s.link] {
				continue
			}
			var suffix string
			var matches bool
			if s.resolved == "." {
				if item.path != "." {
					suffix = item.path
					matches = true
				}
			} else if strings.HasPrefix(item.path, s.resolved+"/") {
				suffix = strings.TrimPrefix(item.path, s.resolved+"/")
				matches = true
			}
			if matches {
				derived := path.Join(s.link, suffix)
				addFound(derived)
				if len(found) > maxAliasExpansionCount || len(queue) >= maxAliasQueueCount {
					return nil, syscall.EACCES
				}
				newUsed := make(map[string]bool, len(item.used)+1)
				for k, v := range item.used {
					newUsed[k] = v
				}
				newUsed[s.link] = true
				queue = append(queue, derivedItem{path: derived, used: newUsed})
			}
		}
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
	parent, base, _, err := n.w.parent(ctx, to)
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
