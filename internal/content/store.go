package content

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

// Content rules edited in the UI are saved as numbered versions under
// <state_dir>/content-versions, never written over the operator's
// content_rules_file. At startup the latest saved version is in force, unless
// content_rules_file changed since that version was saved. Version 0 is the file.

const (
	contentVersionsDir = "content-versions"
	historyFile        = "history.jsonl"
	maxHistoryBytes    = 4 << 20
	maxContentBytes    = 1 << 20
	maxVersions        = 10000
	maxNoteBytes       = 200
)

// ContentVersion is one saved version of content rules.
type ContentVersion struct {
	Version    int    `json:"version"`
	Time       string `json:"time"`
	SHA256     string `json:"sha256"`
	BaseSHA256 string `json:"base_sha256"`
	Digest     string `json:"digest"`
	Note       string `json:"note"`
}

// ContentStore keeps the version history of content rules.
type ContentStore struct {
	dir      string
	base     []byte
	baseSHA  string
	mu       sync.Mutex
	versions []ContentVersion
	current  int
	now      func() time.Time
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// OpenContentStore loads the history and returns the rules that should be in force.
func OpenContentStore(stateDir string, base []byte) (*ContentStore, []byte, error) {
	cs := &ContentStore{
		dir:     filepath.Join(stateDir, contentVersionsDir),
		base:    append([]byte(nil), base...),
		baseSHA: sha(base),
		now:     time.Now,
	}
	if stateDir == "" {
		return cs, cs.Base(), nil
	}
	if fi, err := os.Lstat(cs.dir); err == nil {
		if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
			return nil, nil, errors.New("content versions directory must be an owner-only directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err := cs.readHistory(); err != nil {
		return nil, nil, err
	}
	if n := len(cs.versions); n > 0 && cs.versions[n-1].BaseSHA256 == cs.baseSHA {
		last := cs.versions[n-1]
		raw, err := cs.load(last)
		if err != nil {
			return nil, nil, err
		}
		cs.current = last.Version
		return cs, raw, nil
	}
	return cs, cs.Base(), nil
}

func (cs *ContentStore) readHistory() error {
	f, err := openNoFollow(filepath.Join(cs.dir, historyFile))
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
		return errors.New("content history too large")
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		var v ContentVersion
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil || v.Version != len(cs.versions)+1 || len(v.SHA256) != 64 {
			return errors.New("content history is corrupt")
		}
		cs.versions = append(cs.versions, v)
		if len(cs.versions) > maxVersions {
			return errors.New("content history too long")
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

func (cs *ContentStore) versionPath(n int) string {
	return filepath.Join(cs.dir, fmt.Sprintf("v%06d.json", n))
}

func (cs *ContentStore) load(v ContentVersion) ([]byte, error) {
	f, err := openNoFollow(cs.versionPath(v.Version))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxContentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxContentBytes || sha(raw) != v.SHA256 {
		return nil, fmt.Errorf("content version %d does not match its recorded hash", v.Version)
	}
	return raw, nil
}

// Base is the operator's content_rules_file content (version 0).
func (cs *ContentStore) Base() []byte { return append([]byte(nil), cs.base...) }

// Current is the version in force (0 = content_rules_file).
func (cs *ContentStore) Current() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.current
}

// Versions lists saved versions, newest first, at most limit.
func (cs *ContentStore) Versions(limit int) []ContentVersion {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := []ContentVersion{}
	for i := len(cs.versions) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, cs.versions[i])
	}
	return out
}

// Load returns a saved version's content (0 = content_rules_file).
func (cs *ContentStore) Load(version int) ([]byte, error) {
	if version == 0 {
		return cs.Base(), nil
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if version < 1 || version > len(cs.versions) {
		return nil, errors.New("unknown content version")
	}
	return cs.load(cs.versions[version-1])
}

// Save records raw as the next version.
func (cs *ContentStore) Save(raw []byte, digest, note string) (ContentVersion, error) {
	if len(raw) > maxContentBytes {
		return ContentVersion{}, errors.New("content rules too large")
	}
	if len(note) > maxNoteBytes {
		note = note[:maxNoteBytes]
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.versions) >= maxVersions {
		return ContentVersion{}, errors.New("content history full")
	}
	if err := os.Mkdir(cs.dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return ContentVersion{}, err
	}
	v := ContentVersion{
		Version:    len(cs.versions) + 1,
		Time:       cs.now().UTC().Format(time.RFC3339),
		SHA256:     sha(raw),
		BaseSHA256: cs.baseSHA,
		Digest:     digest,
		Note:       note,
	}
	tmp := cs.versionPath(v.Version) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return ContentVersion{}, err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, cs.versionPath(v.Version))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return ContentVersion{}, err
	}
	line, _ := json.Marshal(v)
	h, err := os.OpenFile(filepath.Join(cs.dir, historyFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return ContentVersion{}, err
	}
	_, err = h.Write(append(line, '\n'))
	if err == nil {
		err = h.Sync()
	}
	if cerr := h.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return ContentVersion{}, err
	}
	cs.versions = append(cs.versions, v)
	cs.current = v.Version
	return v, nil
}
