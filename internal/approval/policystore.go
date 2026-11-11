package approval

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Policies edited in the UI are saved as numbered versions under
// <state_dir>/policy-versions, never written over the operator's policy_file
// (which is often mounted read-only).  At startup the latest saved version is
// in force, unless policy_file changed since that version was saved: then the
// file wins, because the operator edited it by hand.  Version 0 is the file.

const (
	policyVersionsDir = "policy-versions"
	historyFile       = "history.jsonl"
	maxHistoryBytes   = 4 << 20
	maxPolicyBytes    = 1 << 20
	maxVersions       = 10000
	maxNoteBytes      = 200
)

// PolicyVersion is one saved policy.
type PolicyVersion struct {
	Version      int    `json:"version"`
	Time         string `json:"time"`
	SHA256       string `json:"sha256"`
	BaseSHA256   string `json:"base_sha256"`
	PolicyDigest string `json:"policy_digest"`
	Note         string `json:"note"`
}

// PolicyStore keeps the version history.
type PolicyStore struct {
	dir      string
	base     []byte
	baseSHA  string
	mu       sync.Mutex
	versions []PolicyVersion
	current  int
	now      func() time.Time
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// OpenPolicyStore loads the history and returns the policy that should be in force.
func OpenPolicyStore(stateDir string, base []byte) (*PolicyStore, []byte, error) {
	ps := &PolicyStore{dir: filepath.Join(stateDir, policyVersionsDir), base: append([]byte(nil), base...),
		baseSHA: sha(base), now: time.Now}
	if fi, err := os.Lstat(ps.dir); err == nil {
		if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
			return nil, nil, errors.New("policy versions directory must be an owner-only directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err := ps.readHistory(); err != nil {
		return nil, nil, err
	}
	if n := len(ps.versions); n > 0 && ps.versions[n-1].BaseSHA256 == ps.baseSHA {
		last := ps.versions[n-1]
		raw, err := ps.load(last)
		if err != nil {
			return nil, nil, err
		}
		ps.current = last.Version
		return ps, raw, nil
	}
	return ps, ps.Base(), nil
}

func (ps *PolicyStore) readHistory() error {
	f, err := openNoFollow(filepath.Join(ps.dir, historyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxHistoryBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxHistoryBytes {
		return errors.New("policy history too large")
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		var v PolicyVersion
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil || v.Version != len(ps.versions)+1 || len(v.SHA256) != 64 {
			return errors.New("policy history is corrupt")
		}
		ps.versions = append(ps.versions, v)
		if len(ps.versions) > maxVersions {
			return errors.New("policy history too long")
		}
	}
	return sc.Err()
}

func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("%s must be an owner-only regular file", filepath.Base(path))
	}
	return f, nil
}

func (ps *PolicyStore) versionPath(n int) string {
	return filepath.Join(ps.dir, fmt.Sprintf("v%06d.yaml", n))
}

func (ps *PolicyStore) load(v PolicyVersion) ([]byte, error) {
	f, err := openNoFollow(ps.versionPath(v.Version))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPolicyBytes || sha(raw) != v.SHA256 {
		return nil, fmt.Errorf("policy version %d does not match its recorded hash", v.Version)
	}
	return raw, nil
}

// Base is the operator's policy_file content (version 0).
func (ps *PolicyStore) Base() []byte { return append([]byte(nil), ps.base...) }

// Current is the version in force (0 = policy_file).
func (ps *PolicyStore) Current() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.current
}

// Versions lists saved versions, newest first, at most limit.
func (ps *PolicyStore) Versions(limit int) []PolicyVersion {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	out := []PolicyVersion{}
	for i := len(ps.versions) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, ps.versions[i])
	}
	return out
}

// Load returns a saved version's content (0 = policy_file).
func (ps *PolicyStore) Load(version int) ([]byte, error) {
	if version == 0 {
		return ps.Base(), nil
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if version < 1 || version > len(ps.versions) {
		return nil, errors.New("unknown policy version")
	}
	return ps.load(ps.versions[version-1])
}

// Save records raw (already accepted by the service) as the next version.
func (ps *PolicyStore) Save(raw []byte, policyDigest, note string) (PolicyVersion, error) {
	if len(raw) > maxPolicyBytes {
		return PolicyVersion{}, errors.New("policy too large")
	}
	if len(note) > maxNoteBytes {
		note = note[:maxNoteBytes]
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(ps.versions) >= maxVersions {
		return PolicyVersion{}, errors.New("policy history full")
	}
	if err := os.Mkdir(ps.dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return PolicyVersion{}, err
	}
	v := PolicyVersion{Version: len(ps.versions) + 1, Time: ps.now().UTC().Format(time.RFC3339), SHA256: sha(raw),
		BaseSHA256: ps.baseSHA, PolicyDigest: policyDigest, Note: note}
	tmp := ps.versionPath(v.Version) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return PolicyVersion{}, err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, ps.versionPath(v.Version))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return PolicyVersion{}, err
	}
	line, _ := json.Marshal(v)
	h, err := os.OpenFile(filepath.Join(ps.dir, historyFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return PolicyVersion{}, err
	}
	_, err = h.Write(append(line, '\n'))
	if err == nil {
		err = h.Sync()
	}
	if cerr := h.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return PolicyVersion{}, err
	}
	ps.versions = append(ps.versions, v)
	ps.current = v.Version
	return v, nil
}
