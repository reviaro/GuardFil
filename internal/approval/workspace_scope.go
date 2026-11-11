package approval

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/reviaro/guardfil/internal/policy"
)

// WorkspaceScope is supplied only by the host launcher through the owner
// socket. Mount roots are filesystem-relative names: a bind alias and its
// source therefore describe the same storage, even under different views.
type WorkspaceScope struct {
	Mounts []WorkspaceLocation `json:"mounts"`
}
type WorkspaceLocation struct {
	Virtual    string `json:"virtual"`
	Filesystem string `json:"filesystem"`
	Root       string `json:"root"`
}

func canonicalScope(in *WorkspaceScope) (*WorkspaceScope, string, error) {
	if in == nil {
		return nil, "", nil
	}
	if len(in.Mounts) == 0 || len(in.Mounts) > 256 {
		return nil, "", errors.New("workspace needs 1 to 256 mount mappings")
	}
	out := &WorkspaceScope{Mounts: append([]WorkspaceLocation(nil), in.Mounts...)}
	seen := map[string]bool{}
	for _, m := range out.Mounts {
		if len(m.Virtual) > 4096 || len(m.Root) > 4096 || (m.Virtual != "/workspace" && !strings.HasPrefix(m.Virtual, "/workspace/")) || path.Clean(m.Virtual) != m.Virtual || !path.IsAbs(m.Root) || path.Clean(m.Root) != m.Root ||
			!regexp.MustCompile(`^[0-9a-f]{1,32}$`).MatchString(m.Filesystem) || seen[m.Virtual] {
			return nil, "", errors.New("invalid workspace mount mapping")
		}
		seen[m.Virtual] = true
	}
	if !seen["/workspace"] {
		return nil, "", errors.New("workspace root mapping is required")
	}
	sort.Slice(out.Mounts, func(i, j int) bool { return out.Mounts[i].Virtual < out.Mounts[j].Virtual })
	encoded, _ := json.Marshal(out)
	return out, string(encoded), nil
}

func beneath(root, name string) bool {
	return name == root || (root == "/" && strings.HasPrefix(name, "/")) || strings.HasPrefix(name, root+"/")
}

func scopesOverlap(a, b *WorkspaceScope) bool {
	if a == nil || b == nil {
		return true
	} // legacy/unbound views cannot prove disjointness
	for _, x := range a.Mounts {
		for _, y := range b.Mounts {
			if x.Filesystem == y.Filesystem && (beneath(x.Root, y.Root) || beneath(y.Root, x.Root)) {
				return true
			}
		}
	}
	return false
}

func (w *WorkspaceScope) physical(name string) (string, string, bool) {
	if w == nil {
		return "", "", false
	}
	var best *WorkspaceLocation
	for i := range w.Mounts {
		m := &w.Mounts[i]
		if beneath(m.Virtual, name) && (best == nil || len(m.Virtual) > len(best.Virtual)) {
			best = m
		}
	}
	if best == nil {
		return "", "", false
	}
	return best.Filesystem, path.Join(best.Root, strings.TrimPrefix(name, best.Virtual)), true
}

func (s *Service) localOnly(snapshot policy.Snapshot, scope *WorkspaceScope, name string) bool {
	if snapshot.LocalOnly(name) {
		return true
	}
	volume, physical, ok := scope.physical(name)
	if !ok {
		return false
	}
	s.scopeMu.RLock()
	defer s.scopeMu.RUnlock()
	for _, known := range s.workspaceScopes {
		for _, mount := range known.Mounts {
			if mount.Filesystem != volume || !beneath(mount.Root, physical) {
				continue
			}
			virtual := path.Join(mount.Virtual, strings.TrimPrefix(physical, mount.Root))
			// A child mount may hide this location in that view.
			v, p, ok := known.physical(virtual)
			if ok && v == volume && p == physical && snapshot.LocalOnly(virtual) {
				return true
			}
		}
	}
	return false
}

// ConfigureWorkspacePrivacyStore loads host mappings retained across sessions
// and service restarts. Deleting a session must not declassify its output.
// Call once during startup, before serving owner or agent requests.
func (s *Service) ConfigureWorkspacePrivacyStore(stateDir string) error {
	s.scopeStore = filepath.Join(stateDir, "workspace-privacy.json")
	f, err := openNoFollow(s.scopeStore)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if err != nil || len(raw) > 16<<20 {
		return errors.New("workspace privacy store is unreadable or too large")
	}
	var scopes []WorkspaceScope
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&scopes) != nil || len(scopes) > 1024 {
		return errors.New("invalid workspace privacy store")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid trailing workspace privacy data")
	}
	for _, scope := range scopes {
		value, key, err := canonicalScope(&scope)
		if err != nil {
			return err
		}
		s.workspaceScopes[key] = value
	}
	return nil
}

// Called while sessionMu is held, before the new session can read anything.
func (s *Service) registerWorkspace(in *WorkspaceScope) (*WorkspaceScope, error) {
	scope, key, err := canonicalScope(in)
	if err != nil || scope == nil {
		return scope, err
	}
	s.scopeMu.Lock()
	if previous := s.workspaceScopes[key]; previous != nil {
		s.scopeMu.Unlock()
		return previous, nil
	}
	if len(s.workspaceScopes) >= 1024 {
		s.scopeMu.Unlock()
		return nil, errors.New("workspace privacy mapping limit reached")
	}
	if s.scopeStore != "" {
		keys := make([]string, 0, len(s.workspaceScopes)+1)
		for k := range s.workspaceScopes {
			keys = append(keys, k)
		}
		keys = append(keys, key)
		sort.Strings(keys)
		raw := []byte("[" + strings.Join(keys, ",") + "]\n")
		if len(raw) > 16<<20 {
			s.scopeMu.Unlock()
			return nil, errors.New("workspace privacy mapping store is full")
		}
		file, err := os.CreateTemp(filepath.Dir(s.scopeStore), ".workspace-privacy-*")
		if err == nil {
			name := file.Name()
			_, err = file.Write(raw)
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = os.Rename(name, s.scopeStore)
			}
			os.Remove(name)
			if err == nil {
				var dir *os.File
				dir, err = os.Open(filepath.Dir(s.scopeStore))
				if err == nil {
					err = dir.Sync()
					dir.Close()
				}
			}
		}
		if err != nil {
			s.scopeMu.Unlock()
			return nil, err
		}
	}
	s.workspaceScopes[key] = scope
	s.scopeMu.Unlock()
	// A new view can give an already-read object a newly protected name.
	// Conservatively retain it locally in every session that has read data.
	snapshot, err := policy.Compile(s.Policy())
	if err != nil {
		return nil, err
	}
	if snapshot.PrivacyVersion() != "" {
		for _, sess := range s.sessions {
			sess.access.mu.Lock()
			if sess.access.hasRead && scopesOverlap(scope, sess.access.scope) {
				sess.access.localOnly = true
			}
			sess.access.mu.Unlock()
		}
	}
	return scope, nil
}
