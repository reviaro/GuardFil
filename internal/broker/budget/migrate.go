package budget

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type MigrationTombstone struct {
	SchemaVersion      int    `json:"schema_version"`
	Mode               string `json:"mode"`
	MigratedAtUTC      string `json:"migrated_at_utc"`
	TargetCreatedAtUTC string `json:"target_created_at_utc,omitempty"`
	FromExperimentID   string `json:"from_experiment_id"`
	ToExperimentID     string `json:"to_experiment_id"`
	LegacyDir          string `json:"legacy_dir"`
	TargetDir          string `json:"target_dir"`
}

type MigrationIntent struct {
	SchemaVersion       int    `json:"schema_version"`
	Mode                string `json:"mode"`
	TargetCreatedAtUTC  string `json:"target_created_at_utc"`
	StageDirName        string `json:"stage_dir_name"`
	FromExperimentID    string `json:"from_experiment_id"`
	ToExperimentID      string `json:"to_experiment_id"`
	LegacyDir           string `json:"legacy_dir"`
	TargetDir           string `json:"target_dir"`
	EvidenceCount       int    `json:"evidence_count"`
	EvidenceNamesDigest string `json:"evidence_names_digest"`
}

type MigrationResult struct {
	Provider               string `json:"provider"`
	Status                 string `json:"status"`
	LegacyRoot             string `json:"legacy_root"`
	TargetRoot             string `json:"target_root"`
	CommittedSpendMicros   int    `json:"committed_spend_micros"`
	RetainedFailedMicros   int    `json:"retained_failed_micros"`
	TotalReservationsCount int    `json:"total_reservations_count"`
	SettledRequestsCount   int    `json:"settled_requests_count"`
	Halted                 bool   `json:"halted"`
	HaltReason             string `json:"halt_reason,omitempty"`
}

type migrateFaultStep int

const (
	faultNone migrateFaultStep = iota
	faultBeforeIntentPublish
	faultAfterIntentWrite
	faultAfterTargetRename
	faultAfterTombstoneWrite
)

var tombstoneTempName = regexp.MustCompile(`^\.tmp_tomb_[0-9a-f]{32}$`)
var stageNameSuffix = regexp.MustCompile(`^[1-9][0-9]*-[0-9a-f]{16}$`)

func computeEvidenceNamesDigest(names []string) string {
	h := sha256.New()
	for _, name := range names {
		_, _ = fmt.Fprintf(h, "%d:%s\n", len(name), name)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func checkDirPath(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return ErrLedgerNotFound
		}
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return fmt.Errorf("%w: invalid directory %s: %v", ErrLedgerSecurity, path, err)
		}
		return fmt.Errorf("%w: cannot open directory %s: %v", ErrLedgerSecurity, path, err)
	}
	defer syscall.Close(fd)
	return checkDescriptor(fd, true)
}

func checkRegularFile(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return ErrLedgerNotFound
		}
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: symlink detected on %s", ErrLedgerSecurity, path)
		}
		return fmt.Errorf("%w: cannot open file %s: %v", ErrLedgerSecurity, path, err)
	}
	defer syscall.Close(fd)
	return checkDescriptor(fd, false)
}

func verifyRegularWitnessFile(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return ErrLedgerNotFound
		}
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: symlink detected on %s", ErrLedgerSecurity, path)
		}
		return fmt.Errorf("%w: cannot open witness file %s: %v", ErrLedgerSecurity, path, err)
	}
	defer syscall.Close(fd)
	if err := checkDescriptor(fd, false); err != nil {
		return err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: fstat %s failed: %v", ErrLedgerCorrupt, path, err)
	}
	if st.Size > MaxStateFileBytes {
		return fmt.Errorf("%w: %s exceeds maximum witness file size", ErrLedgerCorrupt, path)
	}
	return nil
}

func fsyncDirPath(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open dir for sync %s: %w", path, err)
	}
	syncErr := syscall.Fsync(fd)
	closeErr := syscall.Close(fd)
	if syncErr != nil {
		return fmt.Errorf("fsync dir %s: %w", path, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close dir %s: %w", path, closeErr)
	}
	return nil
}

func isEvidenceFilename(name string) bool {
	return (strings.HasPrefix(name, "live-broker-") || strings.HasPrefix(name, "neutral-broker-")) && strings.HasSuffix(name, ".jsonl")
}

func verifyOneEvidenceFile(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: %w: symlink detected on %s", ErrEvidenceCopy, ErrLedgerSecurity, path)
		}
		return fmt.Errorf("%w: %w: cannot open %s: %v", ErrEvidenceCopy, ErrLedgerSecurity, path, err)
	}
	defer syscall.Close(fd)

	if err := checkDescriptor(fd, false); err != nil {
		return fmt.Errorf("%w: %w", ErrEvidenceCopy, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: fstat %s failed: %v", ErrEvidenceCopy, path, err)
	}
	if st.Size > MaxEvidenceFileBytes {
		return fmt.Errorf("%w: %s exceeds maximum evidence file size (%d > %d)", ErrEvidenceCopy, path, st.Size, MaxEvidenceFileBytes)
	}
	return nil
}

func verifyEvidenceFilesReadOnly(legacyRoot string) ([]string, error) {
	entries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, de := range entries {
		name := de.Name()
		if !isEvidenceFilename(name) {
			continue
		}
		if err := verifyOneEvidenceFile(filepath.Join(legacyRoot, name)); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func verifiedFilesEqual(srcPath, dstPath string, maxBytes int64) error {
	srcFD, err := syscall.Open(srcPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: cannot open %s: %v", ErrLedgerSecurity, srcPath, err)
	}
	defer syscall.Close(srcFD)
	if err := checkDescriptor(srcFD, false); err != nil {
		return err
	}
	var srcSt syscall.Stat_t
	if err := syscall.Fstat(srcFD, &srcSt); err != nil {
		return fmt.Errorf("%w: fstat %s: %v", ErrLedgerCorrupt, srcPath, err)
	}

	dstFD, err := syscall.Open(dstPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: cannot open %s: %v", ErrLedgerSecurity, dstPath, err)
	}
	defer syscall.Close(dstFD)
	if err := checkDescriptor(dstFD, false); err != nil {
		return err
	}
	var dstSt syscall.Stat_t
	if err := syscall.Fstat(dstFD, &dstSt); err != nil {
		return fmt.Errorf("%w: fstat %s: %v", ErrLedgerCorrupt, dstPath, err)
	}

	if srcSt.Size > maxBytes || dstSt.Size > maxBytes || srcSt.Size != dstSt.Size {
		return fmt.Errorf("%w: %w: file size mismatch between %s (%d) and %s (%d)", ErrLedgerCorrupt, ErrMigrationState, srcPath, srcSt.Size, dstPath, dstSt.Size)
	}

	srcBuf := make([]byte, 64*1024)
	dstBuf := make([]byte, 64*1024)
	var compared int64
	for compared < srcSt.Size {
		want := len(srcBuf)
		if rem := int(srcSt.Size - compared); rem < want {
			want = rem
		}
		n1, err1 := readFullFD(srcFD, srcBuf[:want])
		n2, err2 := readFullFD(dstFD, dstBuf[:want])
		if err1 != nil || err2 != nil || n1 != want || n2 != want {
			return fmt.Errorf("%w: %w: read compare failed between %s and %s", ErrLedgerCorrupt, ErrMigrationState, srcPath, dstPath)
		}
		if !bytes.Equal(srcBuf[:want], dstBuf[:want]) {
			return fmt.Errorf("%w: %w: file content mismatch between %s and %s", ErrLedgerCorrupt, ErrMigrationState, srcPath, dstPath)
		}
		compared += int64(want)
	}
	return nil
}

func readFullFD(fd int, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := syscall.Read(fd, buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

func copyVerifiedRegularFile(srcDir, dstDir, name string) error {
	srcPath := filepath.Join(srcDir, name)
	srcFD, err := syscall.Open(srcPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: symlink detected on %s", ErrLedgerSecurity, srcPath)
		}
		return fmt.Errorf("%w: cannot open %s: %v", ErrLedgerSecurity, srcPath, err)
	}
	defer syscall.Close(srcFD)

	if err := checkDescriptor(srcFD, false); err != nil {
		return err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(srcFD, &st); err != nil {
		return fmt.Errorf("%w: fstat %s failed: %v", ErrLedgerCorrupt, srcPath, err)
	}
	if st.Size > MaxStateFileBytes {
		return fmt.Errorf("%w: %s exceeds maximum file size", ErrLedgerCorrupt, srcPath)
	}

	data := make([]byte, st.Size)
	total := 0
	for total < len(data) {
		n, rerr := syscall.Read(srcFD, data[total:])
		if rerr != nil {
			return fmt.Errorf("read %s: %w", srcPath, rerr)
		}
		if n == 0 {
			break
		}
		total += n
	}
	data = data[:total]

	dstPath := filepath.Join(dstDir, name)
	dstF, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create destination %s: %w", dstPath, err)
	}
	if _, err := dstF.Write(data); err != nil {
		_ = dstF.Close()
		return fmt.Errorf("write %s: %w", dstPath, err)
	}
	if err := dstF.Sync(); err != nil {
		_ = dstF.Close()
		return fmt.Errorf("sync %s: %w", dstPath, err)
	}
	return dstF.Close()
}

func copyVerifiedEvidenceFile(srcDir, dstDir, name string) error {
	srcPath := filepath.Join(srcDir, name)
	srcFD, err := syscall.Open(srcPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: %w: symlink detected on %s", ErrEvidenceCopy, ErrLedgerSecurity, srcPath)
		}
		return fmt.Errorf("%w: %w: cannot open %s: %v", ErrEvidenceCopy, ErrLedgerSecurity, srcPath, err)
	}
	defer syscall.Close(srcFD)

	if err := checkDescriptor(srcFD, false); err != nil {
		return fmt.Errorf("%w: %w", ErrEvidenceCopy, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(srcFD, &st); err != nil {
		return fmt.Errorf("%w: fstat %s failed: %v", ErrEvidenceCopy, srcPath, err)
	}
	if st.Size > MaxEvidenceFileBytes {
		return fmt.Errorf("%w: %s exceeds maximum evidence file size (%d > %d)", ErrEvidenceCopy, srcPath, st.Size, MaxEvidenceFileBytes)
	}

	dstPath := filepath.Join(dstDir, name)
	dstF, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("%w: create destination %s: %v", ErrEvidenceCopy, dstPath, err)
	}

	buf := make([]byte, 64*1024)
	var copied int64
	for {
		n, rerr := syscall.Read(srcFD, buf)
		if n > 0 {
			copied += int64(n)
			if copied > MaxEvidenceFileBytes {
				_ = dstF.Close()
				return fmt.Errorf("%w: %s grew past maximum evidence file size (%d)", ErrEvidenceCopy, srcPath, MaxEvidenceFileBytes)
			}
			if _, werr := dstF.Write(buf[:n]); werr != nil {
				_ = dstF.Close()
				return fmt.Errorf("%w: write %s: %v", ErrEvidenceCopy, dstPath, werr)
			}
		}
		if rerr == io.EOF || (rerr == nil && n == 0) {
			break
		}
		if rerr != nil {
			_ = dstF.Close()
			return fmt.Errorf("%w: read %s: %v", ErrEvidenceCopy, srcPath, rerr)
		}
	}
	if err := dstF.Sync(); err != nil {
		_ = dstF.Close()
		return fmt.Errorf("%w: sync %s: %v", ErrEvidenceCopy, dstPath, err)
	}
	if err := dstF.Close(); err != nil {
		return fmt.Errorf("%w: close %s: %v", ErrEvidenceCopy, dstPath, err)
	}
	return nil
}

func validateTombstone(legacyRoot string, spec ProviderLedgerSpec) (*MigrationTombstone, error) {
	m, err := readMigrationRecord(filepath.Join(legacyRoot, TombstoneFilename))
	if err != nil {
		return nil, err
	}
	keys := []string{"schema_version", "mode", "migrated_at_utc", "from_experiment_id", "to_experiment_id", "legacy_dir", "target_dir"}
	if _, present := m["target_created_at_utc"]; present {
		keys = append(keys, "target_created_at_utc")
	}
	if err := checkClosedSchema(m, keys, "tombstone"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	v2 := SchemaVersionV2
	sv, err := validateInt(m["schema_version"], "schema_version", v2, &v2)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	mode, ok := m["mode"].(string)
	if !ok || (mode != TombstoneModeMigrated && mode != TombstoneModeFreshV2) {
		return nil, fmt.Errorf("%w: %w: tombstone mode invalid", ErrLedgerCorrupt, ErrMigrationState)
	}
	ts, _, err := validateTimestamp(m["migrated_at_utc"])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	var targetCreatedAt string
	if rawTargetCreated, hasTargetCreated := m["target_created_at_utc"]; hasTargetCreated {
		if mode != TombstoneModeFreshV2 {
			return nil, fmt.Errorf("%w: %w: target_created_at_utc only permitted on fresh_v2 tombstone", ErrLedgerCorrupt, ErrMigrationState)
		}
		targetCreatedAt, _, err = validateTimestamp(rawTargetCreated)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
		}
	}
	fromID, err := validateIdentifier(m["from_experiment_id"], "from_experiment_id")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	toID, err := validateIdentifier(m["to_experiment_id"], "to_experiment_id")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	legDir, err := validateIdentifier(m["legacy_dir"], "legacy_dir")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	tgtDir, err := validateIdentifier(m["target_dir"], "target_dir")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	if fromID != spec.LegacyID || toID != spec.TargetID || legDir != spec.LegacyDir || tgtDir != spec.TargetDir {
		return nil, fmt.Errorf("%w: %w: tombstone identity mismatch for %s", ErrLedgerCorrupt, ErrMigrationState, spec.Provider)
	}
	return &MigrationTombstone{
		SchemaVersion:      sv,
		Mode:               mode,
		MigratedAtUTC:      ts,
		TargetCreatedAtUTC: targetCreatedAt,
		FromExperimentID:   fromID,
		ToExperimentID:     toID,
		LegacyDir:          legDir,
		TargetDir:          tgtDir,
	}, nil
}

func publishTombstone(legacyRoot string, spec ProviderLedgerSpec, mode string, timestampUTC string, targetCreatedAtUTC string) error {
	tomb := MigrationTombstone{
		SchemaVersion:      SchemaVersionV2,
		Mode:               mode,
		MigratedAtUTC:      timestampUTC,
		TargetCreatedAtUTC: targetCreatedAtUTC,
		FromExperimentID:   spec.LegacyID,
		ToExperimentID:     spec.TargetID,
		LegacyDir:          spec.LegacyDir,
		TargetDir:          spec.TargetDir,
	}
	tombEnc, _ := json.MarshalIndent(tomb, "", "  ")
	return publishBytes(defaultFS, legacyRoot, TombstoneFilename, ".tmp_tomb_", tombEnc)
}

func readMigrationRecord(path string) (map[string]any, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, ErrLedgerNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w: open %s: %v", ErrMigrationState, ErrLedgerSecurity, path, err)
	}
	defer syscall.Close(fd)
	if err := checkDescriptor(fd, false); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: %w: stat %s: %v", ErrLedgerCorrupt, ErrMigrationState, path, err)
	}
	if st.Size > 64*1024 {
		return nil, fmt.Errorf("%w: %w: %s exceeds 64 KiB", ErrLedgerCorrupt, ErrMigrationState, path)
	}
	data := make([]byte, st.Size)
	n, err := readFullFD(fd, data)
	if err != nil || n != len(data) {
		return nil, fmt.Errorf("%w: %w: incomplete migration record %s", ErrLedgerCorrupt, ErrMigrationState, path)
	}
	val, err := safeJSONDecode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	record, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %w: %s must contain a JSON object", ErrLedgerCorrupt, ErrMigrationState, path)
	}
	return record, nil
}

func validateMigrationIntent(legacyLedgerDir string, spec ProviderLedgerSpec) (*MigrationIntent, error) {
	m, err := readMigrationRecord(filepath.Join(legacyLedgerDir, MigrationIntentFilename))
	if err != nil {
		return nil, err
	}
	keys := []string{"schema_version", "mode", "target_created_at_utc", "stage_dir_name", "from_experiment_id", "to_experiment_id", "legacy_dir", "target_dir", "evidence_count", "evidence_names_digest"}
	if err := checkClosedSchema(m, keys, "migration intent"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	v2 := SchemaVersionV2
	sv, err := validateInt(m["schema_version"], "schema_version", v2, &v2)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	mode, ok := m["mode"].(string)
	if !ok || (mode != IntentModeFreshInit && mode != IntentModeRetireEmpty) {
		return nil, fmt.Errorf("%w: %w: migration intent mode invalid", ErrLedgerCorrupt, ErrMigrationState)
	}
	targetCreatedAt, _, err := validateTimestamp(m["target_created_at_utc"])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	stageDirName, err := validateIdentifier(m["stage_dir_name"], "stage_dir_name")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	prefix := ".init-" + spec.Provider + "-"
	if mode == IntentModeRetireEmpty {
		prefix = ".retire-" + spec.Provider + "-"
	}
	suffix, matched := strings.CutPrefix(stageDirName, prefix)
	if !matched || !stageNameSuffix.MatchString(suffix) {
		return nil, fmt.Errorf("%w: %w: invalid stage_dir_name %q", ErrLedgerCorrupt, ErrMigrationState, stageDirName)
	}
	fromID, err := validateIdentifier(m["from_experiment_id"], "from_experiment_id")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	toID, err := validateIdentifier(m["to_experiment_id"], "to_experiment_id")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	legDir, err := validateIdentifier(m["legacy_dir"], "legacy_dir")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	tgtDir, err := validateIdentifier(m["target_dir"], "target_dir")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	if fromID != spec.LegacyID || toID != spec.TargetID || legDir != spec.LegacyDir || tgtDir != spec.TargetDir {
		return nil, fmt.Errorf("%w: %w: migration intent identity mismatch for %s", ErrLedgerCorrupt, ErrMigrationState, spec.Provider)
	}
	evCount, err := validateInt(m["evidence_count"], "evidence_count", 0, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	evDigest, err := validateDigest(m["evidence_names_digest"])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	if !strings.HasPrefix(evDigest, "sha256:") || len(evDigest) != len("sha256:")+64 {
		return nil, fmt.Errorf("%w: %w: invalid evidence_names_digest format", ErrLedgerCorrupt, ErrMigrationState)
	}
	if _, err := hex.DecodeString(evDigest[len("sha256:"):]); err != nil {
		return nil, fmt.Errorf("%w: %w: invalid evidence_names_digest hex", ErrLedgerCorrupt, ErrMigrationState)
	}
	emptyDigest := computeEvidenceNamesDigest(nil)
	if mode == IntentModeFreshInit && (evCount != 0 || evDigest != emptyDigest) {
		return nil, fmt.Errorf("%w: %w: fresh_init migration intent cannot carry evidence files", ErrLedgerCorrupt, ErrMigrationState)
	}
	if (evCount == 0) != (evDigest == emptyDigest) {
		return nil, fmt.Errorf("%w: %w: migration intent evidence_count and evidence_names_digest inconsistent", ErrLedgerCorrupt, ErrMigrationState)
	}
	return &MigrationIntent{
		SchemaVersion:       sv,
		Mode:                mode,
		TargetCreatedAtUTC:  targetCreatedAt,
		StageDirName:        stageDirName,
		FromExperimentID:    fromID,
		ToExperimentID:      toID,
		LegacyDir:           legDir,
		TargetDir:           tgtDir,
		EvidenceCount:       evCount,
		EvidenceNamesDigest: evDigest,
	}, nil
}

func publishMigrationIntent(legacyLedgerDir string, intent *MigrationIntent) error {
	enc, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return err
	}
	return publishBytes(defaultFS, legacyLedgerDir, MigrationIntentFilename, ".tmp_mintent_", enc)
}

func lockLegacyScaffold(legacyLedgerDir string) (func(), error) {
	if err := checkDirPath(legacyLedgerDir); err != nil {
		return nil, fmt.Errorf("%w: %w: invalid legacy ledger directory: %w", ErrLedgerCorrupt, ErrMigrationState, err)
	}
	lockPath := filepath.Join(legacyLedgerDir, LockFilename)
	lockFD, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, ErrLedgerNotFound
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %w: symlink detected on legacy lock %s", ErrLedgerSecurity, ErrMigrationState, lockPath)
		}
		return nil, fmt.Errorf("%w: %w: cannot open legacy lock %s: %v", ErrLedgerSecurity, ErrMigrationState, lockPath, err)
	}
	if err := checkDescriptor(lockFD, false); err != nil {
		_ = syscall.Close(lockFD)
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		_ = syscall.Close(lockFD)
		return nil, fmt.Errorf("lock legacy scaffold: %w", err)
	}
	return func() {
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
		_ = syscall.Close(lockFD)
	}, nil
}

func verifyLegacyScaffoldDuringIntent(legacyRoot, legacyLedgerDir string, intent *MigrationIntent, spec ProviderLedgerSpec) (*MigrationTombstone, []string, error) {
	if err := checkDirPath(legacyRoot); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	if err := checkDirPath(legacyLedgerDir); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	if err := checkRegularFile(filepath.Join(legacyLedgerDir, LockFilename)); err != nil {
		return nil, nil, fmt.Errorf("%w: %w: legacy lock invalid during intent: %w", ErrLedgerCorrupt, ErrMigrationState, err)
	}
	legEntries, err := os.ReadDir(legacyLedgerDir)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w: cannot read legacy ledger dir: %v", ErrLedgerSecurity, ErrMigrationState, err)
	}
	for _, de := range legEntries {
		name := de.Name()
		if name != LockFilename && name != MigrationIntentFilename {
			return nil, nil, fmt.Errorf("%w: %w: unexpected file %s in legacy ledger dir during %s", ErrLedgerCorrupt, ErrMigrationState, name, intent.Mode)
		}
	}

	evOnDisk, err := verifyEvidenceFilesReadOnly(legacyRoot)
	if err != nil {
		return nil, nil, err
	}
	if len(evOnDisk) != intent.EvidenceCount || computeEvidenceNamesDigest(evOnDisk) != intent.EvidenceNamesDigest {
		return nil, nil, fmt.Errorf("%w: %w: legacy evidence file set changed during %s", ErrLedgerCorrupt, ErrMigrationState, intent.Mode)
	}

	expectedRootEntries := make(map[string]bool, len(evOnDisk)+2)
	expectedRootEntries["ledger"] = true
	for _, ev := range evOnDisk {
		expectedRootEntries[ev] = true
	}

	rootEntries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w: cannot read legacy root: %v", ErrLedgerSecurity, ErrMigrationState, err)
	}
	hasTombstone := false
	for _, de := range rootEntries {
		name := de.Name()
		if name == TombstoneFilename {
			hasTombstone = true
			continue
		}
		if tombstoneTempName.MatchString(name) {
			if err := checkRegularFile(filepath.Join(legacyRoot, name)); err != nil {
				return nil, nil, fmt.Errorf("%w: %w: invalid temporary tombstone %s: %w", ErrLedgerCorrupt, ErrMigrationState, name, err)
			}
			continue
		}
		if !expectedRootEntries[name] {
			return nil, nil, fmt.Errorf("%w: %w: unexpected file %s in legacy root during %s", ErrLedgerCorrupt, ErrMigrationState, name, intent.Mode)
		}
	}
	if !hasTombstone {
		return nil, evOnDisk, nil
	}
	tomb, err := validateTombstone(legacyRoot, spec)
	if err != nil {
		return nil, nil, err
	}
	if tomb.Mode != TombstoneModeFreshV2 || tomb.TargetCreatedAtUTC != intent.TargetCreatedAtUTC {
		return nil, nil, fmt.Errorf("%w: %w: tombstone provenance mismatch with migration intent", ErrLedgerCorrupt, ErrMigrationState)
	}
	return tomb, evOnDisk, nil
}

func cleanupStaleTombstoneTemps(legacyRoot string) error {
	entries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return fmt.Errorf("%w: %w: cannot read legacy root %s: %v", ErrLedgerSecurity, ErrMigrationState, legacyRoot, err)
	}
	for _, de := range entries {
		name := de.Name()
		if !tombstoneTempName.MatchString(name) {
			continue
		}
		p := filepath.Join(legacyRoot, name)
		if err := checkRegularFile(p); err != nil {
			return fmt.Errorf("%w: %w: invalid temporary tombstone %s: %w", ErrLedgerCorrupt, ErrMigrationState, name, err)
		}
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("remove stale temporary tombstone %s: %w", p, err)
		}
	}
	return nil
}

func verifyStagedOrTargetFreshV2Dir(dir string, legacyRoot string, intent *MigrationIntent, evidenceFiles []string, spec ProviderLedgerSpec) (*LedgerState, error) {
	if err := checkDirPath(dir); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	ledgerDir := filepath.Join(dir, "ledger")
	if err := checkDirPath(ledgerDir); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	st, err := inspectTargetLedgerReadOnly(ledgerDir, spec.TargetID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrLedgerCorrupt, ErrMigrationState, err)
	}
	if st.SchemaVersion != SchemaVersionV2 || st.ExperimentID != spec.TargetID || st.LegacyExperimentID != "" || migratedInspectionGen(st) != 0 {
		return nil, fmt.Errorf("%w: %w: target metadata invalid for %s intent", ErrLedgerCorrupt, ErrMigrationState, intent.Mode)
	}
	if st.CreatedAtUTC != intent.TargetCreatedAtUTC {
		return nil, fmt.Errorf("%w: %w: target created_at_utc %q != intent provenance %q", ErrLedgerCorrupt, ErrMigrationState, st.CreatedAtUTC, intent.TargetCreatedAtUTC)
	}
	if len(st.Journal) != 1 || st.Journal[0].EntryType != "INITIALIZED" || st.Journal[0].TimestampUTC != intent.TargetCreatedAtUTC ||
		st.TotalReservationsCount != 0 || st.SettledRequestsCount != 0 ||
		st.CommittedSpendMicros != 0 || st.RetainedFailedMicros != 0 ||
		st.Halted || st.PendingReservation != nil {
		return nil, fmt.Errorf("%w: %w: target state is not a clean fresh v2 ledger matching intent", ErrLedgerCorrupt, ErrMigrationState)
	}

	expectedEntries := make(map[string]bool, len(evidenceFiles)+1)
	expectedEntries["ledger"] = true
	for _, ev := range evidenceFiles {
		expectedEntries[ev] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: cannot read target dir %s: %v", ErrLedgerSecurity, ErrMigrationState, dir, err)
	}
	if len(entries) != len(expectedEntries) {
		return nil, fmt.Errorf("%w: %w: target directory %s entry count (%d) != expected (%d)", ErrLedgerCorrupt, ErrMigrationState, dir, len(entries), len(expectedEntries))
	}
	for _, de := range entries {
		if !expectedEntries[de.Name()] {
			return nil, fmt.Errorf("%w: %w: unexpected file %s in target directory %s", ErrLedgerCorrupt, ErrMigrationState, de.Name(), dir)
		}
	}
	for _, ev := range evidenceFiles {
		dstEv := filepath.Join(dir, ev)
		if err := verifyOneEvidenceFile(dstEv); err != nil {
			return nil, fmt.Errorf("%w: %w: %w", ErrLedgerCorrupt, ErrMigrationState, err)
		}
		srcEv := filepath.Join(legacyRoot, ev)
		if err := verifiedFilesEqual(srcEv, dstEv, MaxEvidenceFileBytes); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func resumeOrFinalizeIntentUnderLock(absRoot, legacyRoot, legacyLedgerDir, targetRoot string, spec ProviderLedgerSpec, intent *MigrationIntent, evidenceFiles []string, existingTomb *MigrationTombstone, dryRun bool, faultAfter migrateFaultStep) (*LedgerState, error) {
	stageDir := filepath.Join(absRoot, intent.StageDirName)
	_, stageErr := os.Lstat(stageDir)
	stageExists := stageErr == nil
	if stageErr != nil && !os.IsNotExist(stageErr) {
		return nil, fmt.Errorf("%w: cannot stat staged target %s: %v", ErrLedgerSecurity, stageDir, stageErr)
	}
	_, tgtErr := os.Lstat(targetRoot)
	targetExists := tgtErr == nil
	if tgtErr != nil && !os.IsNotExist(tgtErr) {
		return nil, fmt.Errorf("%w: cannot stat target root %s: %v", ErrLedgerSecurity, targetRoot, tgtErr)
	}

	if stageExists && targetExists {
		return nil, fmt.Errorf("%w: %w: both staged target %s and target %s exist during %s", ErrLedgerCorrupt, ErrMigrationState, stageDir, targetRoot, intent.Mode)
	}
	if !stageExists && !targetExists {
		return nil, fmt.Errorf("%w: %w: target directory %s is missing for in-progress %s", ErrLedgerCorrupt, ErrMigrationState, targetRoot, intent.Mode)
	}
	if stageExists && existingTomb != nil {
		return nil, fmt.Errorf("%w: %w: tombstone already exists while target remains unpromoted at %s", ErrLedgerCorrupt, ErrMigrationState, stageDir)
	}

	var st *LedgerState
	var err error
	if stageExists {
		st, err = verifyStagedOrTargetFreshV2Dir(stageDir, legacyRoot, intent, evidenceFiles, spec)
		if err != nil {
			return nil, err
		}
		if dryRun {
			return st, nil
		}
		if err := unix.Renameat2(unix.AT_FDCWD, stageDir, unix.AT_FDCWD, targetRoot, unix.RENAME_NOREPLACE); err != nil {
			return nil, fmt.Errorf("%w: %w: atomic target directory publish failed: %v", ErrLedgerCorrupt, ErrMigrationState, err)
		}
		if err := fsyncDirPath(absRoot); err != nil {
			return nil, err
		}
		if faultAfter == faultAfterTargetRename {
			return nil, errors.New("injected fault after target directory publish")
		}
	} else {
		st, err = verifyStagedOrTargetFreshV2Dir(targetRoot, legacyRoot, intent, evidenceFiles, spec)
		if err != nil {
			return nil, err
		}
		if dryRun {
			return st, nil
		}
	}

	if err := cleanupStaleTombstoneTemps(legacyRoot); err != nil {
		return nil, err
	}
	if existingTomb == nil {
		if err := publishTombstone(legacyRoot, spec, TombstoneModeFreshV2, nowUTCStr(), intent.TargetCreatedAtUTC); err != nil {
			return nil, err
		}
		if err := fsyncDirPath(legacyRoot); err != nil {
			return nil, err
		}
		if faultAfter == faultAfterTombstoneWrite {
			return nil, errors.New("injected fault after tombstone write")
		}
	}

	if err := os.Remove(filepath.Join(legacyLedgerDir, MigrationIntentFilename)); err != nil {
		return nil, fmt.Errorf("remove migration intent: %w", err)
	}
	if err := fsyncDirPath(legacyLedgerDir); err != nil {
		return nil, err
	}
	return st, nil
}

func verifyRetiredLegacyScaffold(legacyRoot string, spec ProviderLedgerSpec) (*MigrationTombstone, *LedgerState, error) {
	if err := checkDirPath(legacyRoot); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMigrationState, err)
	}
	tomb, err := validateTombstone(legacyRoot, spec)
	if err != nil {
		return nil, nil, err
	}
	legacyLedgerDir := filepath.Join(legacyRoot, "ledger")
	if err := checkDirPath(legacyLedgerDir); err != nil {
		return nil, nil, fmt.Errorf("%w: %w: retired legacy ledger directory invalid: %v", ErrLedgerCorrupt, ErrMigrationState, err)
	}
	if err := checkRegularFile(filepath.Join(legacyLedgerDir, LockFilename)); err != nil {
		return nil, nil, fmt.Errorf("%w: %w: retired legacy lock invalid: %v", ErrLedgerCorrupt, ErrMigrationState, err)
	}
	if _, stErr := os.Lstat(filepath.Join(legacyLedgerDir, StateFilename)); stErr == nil {
		return nil, nil, fmt.Errorf("%w: legacy state file still present alongside tombstone", ErrLedgerMigrationRequired)
	} else if !os.IsNotExist(stErr) {
		return nil, nil, fmt.Errorf("%w: %w: cannot stat legacy state: %v", ErrLedgerSecurity, ErrMigrationState, stErr)
	}

	if tomb.Mode == TombstoneModeMigrated {
		backupState, err := readStateFileByName(legacyLedgerDir, PreMigrationBackupFilename, spec.LegacyID)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w: legacy pre-migration backup invalid: %v", ErrLedgerCorrupt, ErrMigrationState, err)
		}
		if backupState.SchemaVersion != SchemaVersion || backupState.PendingReservation != nil {
			return nil, nil, fmt.Errorf("%w: %w: legacy pre-migration backup schema or pending state invalid", ErrLedgerCorrupt, ErrMigrationState)
		}
		return tomb, backupState, nil
	}

	// TombstoneModeFreshV2: ensure no historical ledger backup or settlement witnesses exist.
	if _, bErr := os.Lstat(filepath.Join(legacyLedgerDir, PreMigrationBackupFilename)); !os.IsNotExist(bErr) {
		return nil, nil, fmt.Errorf("%w: %w: unexpected pre-migration backup under fresh_v2 tombstone", ErrLedgerCorrupt, ErrMigrationState)
	}
	entries, err := os.ReadDir(legacyLedgerDir)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w: cannot list retired legacy ledger dir: %v", ErrLedgerSecurity, ErrMigrationState, err)
	}
	for _, de := range entries {
		if de.Name() != LockFilename {
			return nil, nil, fmt.Errorf("%w: %w: unexpected file %s inside fresh_v2 legacy scaffold", ErrLedgerCorrupt, ErrMigrationState, de.Name())
		}
	}
	return tomb, nil, nil
}

func verifyTargetProvenance(targetState *LedgerState, tomb *MigrationTombstone, backupState *LedgerState, spec ProviderLedgerSpec) error {
	if targetState == nil || tomb == nil {
		return fmt.Errorf("%w: %w: missing target state or retirement tombstone", ErrLedgerCorrupt, ErrMigrationState)
	}
	if targetState.SchemaVersion != SchemaVersionV2 || targetState.ExperimentID != spec.TargetID {
		return fmt.Errorf("%w: %w: target schema (%d) or experiment_id (%q) mismatch", ErrLedgerCorrupt, ErrMigrationState, targetState.SchemaVersion, targetState.ExperimentID)
	}

	if tomb.Mode == TombstoneModeFreshV2 {
		if targetState.LegacyExperimentID != "" || migratedInspectionGen(targetState) != 0 {
			return fmt.Errorf("%w: %w: target ledger carries unexpected migration metadata for fresh_v2 scaffold", ErrLedgerCorrupt, ErrMigrationState)
		}
		if len(targetState.Journal) == 0 || targetState.Journal[0].EntryType != "INITIALIZED" || targetState.Journal[0].TimestampUTC != targetState.CreatedAtUTC {
			return fmt.Errorf("%w: %w: target ledger INITIALIZED entry timestamp mismatch for fresh_v2 scaffold", ErrLedgerCorrupt, ErrMigrationState)
		}
		if tomb.TargetCreatedAtUTC != "" {
			if targetState.CreatedAtUTC != tomb.TargetCreatedAtUTC {
				return fmt.Errorf("%w: %w: target created_at_utc %q != fresh_v2 tombstone provenance %q", ErrLedgerCorrupt, ErrMigrationState, targetState.CreatedAtUTC, tomb.TargetCreatedAtUTC)
			}
		} else {
			_, dtTarget, err1 := validateTimestamp(targetState.CreatedAtUTC)
			_, dtTomb, err2 := validateTimestamp(tomb.MigratedAtUTC)
			if err1 != nil || err2 != nil || dtTarget.After(dtTomb) {
				return fmt.Errorf("%w: %w: target created_at_utc %q postdates fresh_v2 tombstone %q", ErrLedgerCorrupt, ErrMigrationState, targetState.CreatedAtUTC, tomb.MigratedAtUTC)
			}
		}
		return nil
	}

	if backupState == nil {
		return fmt.Errorf("%w: %w: missing legacy pre-migration backup for provenance check", ErrLedgerCorrupt, ErrMigrationState)
	}
	if targetState.LegacyExperimentID != spec.LegacyID {
		return fmt.Errorf("%w: %w: target legacy_experiment_id %q != expected %q", ErrLedgerCorrupt, ErrMigrationState, targetState.LegacyExperimentID, spec.LegacyID)
	}
	if targetState.CreatedAtUTC != backupState.CreatedAtUTC ||
		targetState.GlobalCeilingMicros != backupState.GlobalCeilingMicros ||
		targetState.ReservationAmountMicros != backupState.ReservationAmountMicros {
		return fmt.Errorf("%w: %w: target header fields diverge from legacy backup", ErrLedgerCorrupt, ErrMigrationState)
	}
	if len(targetState.Journal) < len(backupState.Journal)+1 {
		return fmt.Errorf("%w: %w: target journal shorter than migrated prefix", ErrLedgerCorrupt, ErrMigrationState)
	}
	for i := range backupState.Journal {
		lb, err := json.Marshal(backupState.Journal[i])
		if err != nil {
			return err
		}
		tb, err := json.Marshal(targetState.Journal[i])
		if err != nil {
			return err
		}
		if !bytes.Equal(lb, tb) {
			return fmt.Errorf("%w: %w: target journal entry %d diverges from legacy backup", ErrLedgerCorrupt, ErrMigrationState, i)
		}
	}
	mig := targetState.Journal[len(backupState.Journal)]
	if mig.EntryType != "MIGRATED" || mig.ExperimentID != spec.TargetID || mig.FromExperimentID != spec.LegacyID || mig.LegacyDirName != spec.LegacyDir || mig.Reason != MigrationReasonCLI || mig.InspectionGeneration < 2 {
		return fmt.Errorf("%w: %w: target journal missing expected MIGRATED boundary entry", ErrLedgerCorrupt, ErrMigrationState)
	}

	if targetState.TotalReservationsCount < backupState.TotalReservationsCount ||
		targetState.SettledRequestsCount < backupState.SettledRequestsCount ||
		(targetState.CommittedSpendMicros+targetState.RetainedFailedMicros) < (backupState.CommittedSpendMicros+backupState.RetainedFailedMicros) {
		return fmt.Errorf("%w: %w: target spend or reservation totals regressed relative to legacy backup", ErrLedgerCorrupt, ErrMigrationState)
	}
	sawPostUncertainty := false
	for _, e := range targetState.Journal[len(backupState.Journal)+1:] {
		if e.EntryType == "TERMINAL_UNCERTAINTY" {
			sawPostUncertainty = true
			break
		}
	}
	if !sawPostUncertainty && targetState.CommittedSpendMicros < backupState.CommittedSpendMicros {
		return fmt.Errorf("%w: %w: target committed spend regressed relative to legacy backup", ErrLedgerCorrupt, ErrMigrationState)
	}
	if backupState.Halted {
		if !targetState.Halted || (targetState.HaltReason == nil) != (backupState.HaltReason == nil) ||
			(targetState.HaltReason != nil && *targetState.HaltReason != *backupState.HaltReason) ||
			len(targetState.Journal) != len(backupState.Journal)+1 ||
			targetState.CommittedSpendMicros != backupState.CommittedSpendMicros ||
			targetState.RetainedFailedMicros != backupState.RetainedFailedMicros ||
			targetState.TotalReservationsCount != backupState.TotalReservationsCount ||
			targetState.SettledRequestsCount != backupState.SettledRequestsCount {
			return fmt.Errorf("%w: %w: target does not preserve historical halted state", ErrLedgerCorrupt, ErrMigrationState)
		}
	}
	return nil
}

func classifyLegacyWithoutState(legacyRoot string) (bool, error) {
	entries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return false, err
	}
	for _, de := range entries {
		name := de.Name()
		if name == "ledger" {
			legDir := filepath.Join(legacyRoot, "ledger")
			if err := checkDirPath(legDir); err != nil {
				return false, nil
			}
			legEntries, err := os.ReadDir(legDir)
			if err != nil || len(legEntries) != 0 {
				return false, nil
			}
			continue
		}
		if isEvidenceFilename(name) {
			continue
		}
		return false, nil
	}
	return true, nil
}

// OpenProviderLedger opens the provider's migrated/v2 ledger (or initializes a
// fresh schema-v2 ledger plus a legacy sentinel scaffold when neither legacy nor
// target exists and initialize is true), failing closed on unmigrated,
// missing-scaffold, or provenance-mismatched state.
func OpenProviderLedger(stateRoot string, provider string, initialize bool) (*BudgetLedger, error) {
	return openProviderLedgerWithHook(stateRoot, provider, initialize, faultNone)
}

func openProviderLedgerWithHook(stateRoot string, provider string, initialize bool, faultAfter migrateFaultStep) (*BudgetLedger, error) {
	spec, ok := ProviderLedgerSpecs[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
	absRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, err
	}
	legacyRoot := filepath.Join(absRoot, spec.LegacyDir)
	legacyLedgerDir := filepath.Join(legacyRoot, "ledger")
	targetRoot := filepath.Join(absRoot, spec.TargetDir)
	targetLedgerDir := filepath.Join(targetRoot, "ledger")

	legacyExists := false
	legacyTombstoned := false
	var tomb *MigrationTombstone
	var backupState *LedgerState

	if _, lerr := os.Lstat(legacyRoot); lerr == nil {
		legacyExists = true
		if err := checkDirPath(legacyRoot); err != nil {
			return nil, fmt.Errorf("%w: invalid legacy directory for %s: %v", ErrLedgerSecurity, provider, err)
		}
		legacyStatePath := filepath.Join(legacyLedgerDir, StateFilename)
		if _, stErr := os.Lstat(legacyStatePath); stErr == nil {
			return nil, fmt.Errorf("%w: legacy %s ledger at %s must be migrated first: run 'guardfil-broker migrate-ledger --provider %s'", ErrLedgerMigrationRequired, provider, legacyRoot, provider)
		} else if !os.IsNotExist(stErr) {
			return nil, fmt.Errorf("%w: %w: cannot stat legacy state %s: %v", ErrLedgerSecurity, ErrMigrationState, legacyStatePath, stErr)
		}

		var unlockScaffold func()
		if _, lockStatErr := os.Lstat(filepath.Join(legacyLedgerDir, LockFilename)); lockStatErr == nil {
			unlockScaffold, err = lockLegacyScaffold(legacyLedgerDir)
			if err != nil {
				return nil, fmt.Errorf("%w: %w: legacy %s lock invalid: %w", ErrLedgerCorrupt, ErrMigrationState, provider, err)
			}
			defer unlockScaffold()
		} else if !os.IsNotExist(lockStatErr) {
			return nil, fmt.Errorf("%w: %w: cannot stat legacy lock: %v", ErrLedgerSecurity, ErrMigrationState, lockStatErr)
		}

		intentPath := filepath.Join(legacyLedgerDir, MigrationIntentFilename)
		if _, iErr := os.Lstat(intentPath); iErr == nil {
			if unlockScaffold == nil {
				return nil, fmt.Errorf("%w: %w: legacy %s migration intent present without lock file", ErrLedgerCorrupt, ErrMigrationState, provider)
			}
			intent, err := validateMigrationIntent(legacyLedgerDir, spec)
			if err != nil {
				return nil, err
			}
			existingTomb, evFiles, err := verifyLegacyScaffoldDuringIntent(legacyRoot, legacyLedgerDir, intent, spec)
			if err != nil {
				return nil, err
			}
			if intent.Mode == IntentModeRetireEmpty {
				if _, err := resumeOrFinalizeIntentUnderLock(absRoot, legacyRoot, legacyLedgerDir, targetRoot, spec, intent, evFiles, existingTomb, true, faultNone); err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("%w: unretired legacy %s directory at %s must be migrated first: run 'guardfil-broker migrate-ledger --provider %s'", ErrLedgerMigrationRequired, provider, legacyRoot, provider)
			}
			if !initialize {
				if _, err := resumeOrFinalizeIntentUnderLock(absRoot, legacyRoot, legacyLedgerDir, targetRoot, spec, intent, evFiles, existingTomb, true, faultNone); err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("%w: %w: fresh v2 initialization for %s is incomplete", ErrLedgerCorrupt, ErrMigrationState, provider)
			}
			if _, err := resumeOrFinalizeIntentUnderLock(absRoot, legacyRoot, legacyLedgerDir, targetRoot, spec, intent, evFiles, existingTomb, false, faultAfter); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(iErr) {
			return nil, fmt.Errorf("%w: %w: cannot stat migration intent: %v", ErrLedgerSecurity, ErrMigrationState, iErr)
		}

		tomb, backupState, err = verifyRetiredLegacyScaffold(legacyRoot, spec)
		if err != nil {
			if errors.Is(err, ErrLedgerNotFound) {
				_, tgtErr := os.Lstat(targetRoot)
				emptyOK, cErr := classifyLegacyWithoutState(legacyRoot)
				if cErr == nil && emptyOK {
					if _, evErr := verifyEvidenceFilesReadOnly(legacyRoot); evErr != nil {
						return nil, evErr
					}
					if os.IsNotExist(tgtErr) {
						return nil, fmt.Errorf("%w: unretired legacy %s directory at %s must be migrated first: run 'guardfil-broker migrate-ledger --provider %s'", ErrLedgerMigrationRequired, provider, legacyRoot, provider)
					}
				}
			}
			return nil, fmt.Errorf("%w: %w: legacy %s retirement scaffold invalid: %w", ErrLedgerCorrupt, ErrMigrationState, provider, err)
		}
		legacyTombstoned = true
	} else if !os.IsNotExist(lerr) {
		return nil, fmt.Errorf("%w: cannot stat legacy directory %s: %v", ErrLedgerSecurity, legacyRoot, lerr)
	}

	if _, terr := os.Lstat(targetRoot); terr == nil {
		if err := checkDirPath(targetRoot); err != nil {
			return nil, err
		}
		if !legacyExists || !legacyTombstoned {
			return nil, fmt.Errorf("%w: %w: target %s directory %s lacks matching legacy retirement scaffold", ErrLedgerCorrupt, ErrMigrationState, provider, targetRoot)
		}
		if err := checkDirPath(targetLedgerDir); err != nil {
			return nil, err
		}
		targetState, err := readStateFile(targetLedgerDir, spec.TargetID)
		if err != nil {
			return nil, err
		}
		if err := verifyTargetProvenance(targetState, tomb, backupState, spec); err != nil {
			return nil, err
		}
		l, err := Open(targetLedgerDir)
		if err != nil {
			return nil, err
		}
		if l.experimentID != spec.TargetID {
			_ = l.Close()
			return nil, fmt.Errorf("%w: %w: target %s ledger experiment_id %q != expected %q", ErrLedgerCorrupt, ErrMigrationState, provider, l.experimentID, spec.TargetID)
		}
		return l, nil
	} else if !os.IsNotExist(terr) {
		return nil, fmt.Errorf("%w: cannot stat target directory %s: %v", ErrLedgerSecurity, targetRoot, terr)
	}

	if legacyTombstoned || legacyExists {
		return nil, fmt.Errorf("%w: %w: legacy %s ledger is tombstoned as migrated but target directory %s is missing", ErrLedgerCorrupt, ErrMigrationState, provider, targetRoot)
	}
	if !initialize {
		return nil, ErrLedgerNotFound
	}
	if err := os.MkdirAll(absRoot, 0700); err != nil {
		return nil, fmt.Errorf("%w: cannot create state root %s: %v", ErrLedgerSecurity, absRoot, err)
	}

	stageTargetName := fmt.Sprintf(".init-%s-%d-%s", spec.Provider, os.Getpid(), randomHex(8))
	stageTargetDir := filepath.Join(absRoot, stageTargetName)
	if err := os.MkdirAll(stageTargetDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: cannot create target stage dir %s: %v", ErrLedgerSecurity, stageTargetDir, err)
	}
	_ = os.Chmod(stageTargetDir, 0700)
	keepStageTarget := false
	defer func() {
		if !keepStageTarget {
			_ = os.RemoveAll(stageTargetDir)
		}
	}()

	lInit, err := InitializeV2(filepath.Join(stageTargetDir, "ledger"), spec.TargetID)
	if err != nil {
		return nil, err
	}
	_ = lInit.Close()
	stagedState, err := readStateFile(filepath.Join(stageTargetDir, "ledger"), spec.TargetID)
	if err != nil {
		return nil, err
	}
	if err := fsyncDirPath(filepath.Join(stageTargetDir, "ledger")); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(stageTargetDir); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(absRoot); err != nil {
		return nil, err
	}

	stageSentinelName := fmt.Sprintf(".sentinel-%s-%d-%s", spec.Provider, os.Getpid(), randomHex(8))
	stageSentinelDir := filepath.Join(absRoot, stageSentinelName)
	stageSentinelLedgerDir := filepath.Join(stageSentinelDir, "ledger")
	if err := os.MkdirAll(stageSentinelLedgerDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: cannot create legacy sentinel stage dir: %v", ErrLedgerSecurity, err)
	}
	_ = os.Chmod(stageSentinelDir, 0700)
	_ = os.Chmod(stageSentinelLedgerDir, 0700)
	publishedSentinel := false
	defer func() {
		if !publishedSentinel {
			_ = os.RemoveAll(stageSentinelDir)
		}
	}()

	lockPath := filepath.Join(stageSentinelLedgerDir, LockFilename)
	lockFD, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("%w: create legacy sentinel lock: %v", ErrLedgerSecurity, err)
	}
	lockedSentinel := false
	defer func() {
		if lockedSentinel {
			_ = syscall.Flock(lockFD, syscall.LOCK_UN)
		}
		if lockFD >= 0 {
			_ = syscall.Close(lockFD)
		}
	}()
	if err := syscall.Fsync(lockFD); err != nil {
		return nil, err
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock legacy sentinel: %w", err)
	}
	lockedSentinel = true

	intent := &MigrationIntent{
		SchemaVersion:       SchemaVersionV2,
		Mode:                IntentModeFreshInit,
		TargetCreatedAtUTC:  stagedState.CreatedAtUTC,
		StageDirName:        stageTargetName,
		FromExperimentID:    spec.LegacyID,
		ToExperimentID:      spec.TargetID,
		LegacyDir:           spec.LegacyDir,
		TargetDir:           spec.TargetDir,
		EvidenceCount:       0,
		EvidenceNamesDigest: computeEvidenceNamesDigest(nil),
	}
	if err := publishMigrationIntent(stageSentinelLedgerDir, intent); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(stageSentinelLedgerDir); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(stageSentinelDir); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(absRoot); err != nil {
		return nil, err
	}
	if faultAfter == faultBeforeIntentPublish {
		return nil, errors.New("injected fault before migration intent publish")
	}

	if err := unix.Renameat2(unix.AT_FDCWD, stageSentinelDir, unix.AT_FDCWD, legacyRoot, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, syscall.EEXIST) || errors.Is(err, unix.EEXIST) {
			_ = syscall.Flock(lockFD, syscall.LOCK_UN)
			lockedSentinel = false
			_ = syscall.Close(lockFD)
			lockFD = -1
			_ = os.RemoveAll(stageSentinelDir)
			publishedSentinel = true
			_ = os.RemoveAll(stageTargetDir)
			keepStageTarget = true
			return openProviderLedgerWithHook(stateRoot, provider, initialize, faultAfter)
		}
		return nil, fmt.Errorf("%w: publish legacy v2 sentinel failed: %v", ErrMigrationState, err)
	}
	publishedSentinel = true
	keepStageTarget = true
	if err := fsyncDirPath(absRoot); err != nil {
		return nil, err
	}
	if faultAfter == faultAfterIntentWrite {
		return nil, errors.New("injected fault after migration intent write")
	}

	if _, err := resumeOrFinalizeIntentUnderLock(absRoot, legacyRoot, legacyLedgerDir, targetRoot, spec, intent, nil, nil, false, faultAfter); err != nil {
		return nil, err
	}

	_ = syscall.Flock(lockFD, syscall.LOCK_UN)
	lockedSentinel = false
	_ = syscall.Close(lockFD)
	lockFD = -1

	tomb, backupState, err = verifyRetiredLegacyScaffold(legacyRoot, spec)
	if err != nil {
		return nil, err
	}
	targetState, err := readStateFile(targetLedgerDir, spec.TargetID)
	if err != nil {
		return nil, err
	}
	if err := verifyTargetProvenance(targetState, tomb, backupState, spec); err != nil {
		return nil, err
	}
	return Open(targetLedgerDir)
}

func acquireLegacyMigrationLocks(legacyLedgerDir string, dryRun bool) (release func(), err error) {
	lockPath := filepath.Join(legacyLedgerDir, LockFilename)
	lockFD, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%w: legacy lock file missing", ErrLedgerSecurity)
		}
		return nil, fmt.Errorf("%w: cannot open legacy lock file: %v", ErrLedgerSecurity, err)
	}
	if err := checkDescriptor(lockFD, false); err != nil {
		_ = syscall.Close(lockFD)
		return nil, err
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		_ = syscall.Close(lockFD)
		return nil, fmt.Errorf("lock legacy ledger: %w", err)
	}

	leasePath := filepath.Join(legacyLedgerDir, LeaseFilename)
	leaseFlags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | unix.O_CLOEXEC
	if !dryRun {
		leaseFlags |= syscall.O_CREAT
	}
	leaseFD, err := syscall.Open(leasePath, leaseFlags, 0600)
	if err != nil {
		if dryRun && errors.Is(err, syscall.ENOENT) {
			return func() {
				_ = syscall.Flock(lockFD, syscall.LOCK_UN)
				_ = syscall.Close(lockFD)
			}, nil
		}
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
		_ = syscall.Close(lockFD)
		return nil, fmt.Errorf("%w: cannot open legacy lease file: %v", ErrLedgerSecurity, err)
	}
	if err := checkDescriptor(leaseFD, false); err != nil {
		_ = syscall.Close(leaseFD)
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
		_ = syscall.Close(lockFD)
		return nil, err
	}
	if err := syscall.Flock(leaseFD, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(leaseFD)
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
		_ = syscall.Close(lockFD)
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
			return nil, ErrInFlightReservation
		}
		return nil, fmt.Errorf("acquire legacy lease: %w", err)
	}

	return func() {
		_ = syscall.Flock(leaseFD, syscall.LOCK_UN)
		_ = syscall.Close(leaseFD)
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
		_ = syscall.Close(lockFD)
	}, nil
}

func verifyWitnessPairs(ledgerDir string, state *LedgerState) error {
	expID := state.ExperimentID
	knownIDs := make(map[string]bool)
	settledEntries := make(map[string]JournalEntry)
	expectedExpForRes := make(map[string]string)
	seenMigrated := false
	for _, e := range state.Journal {
		if e.EntryType == "MIGRATED" {
			seenMigrated = true
		}
		if e.EntryType == "RESERVED" {
			knownIDs[e.ReservationID] = true
			if state.LegacyExperimentID != "" && !seenMigrated {
				expectedExpForRes[e.ReservationID] = state.LegacyExperimentID
			} else {
				expectedExpForRes[e.ReservationID] = expID
			}
		}
		if e.EntryType == "SETTLED" {
			settledEntries[e.ReservationID] = e
		}
	}

	entries, err := os.ReadDir(ledgerDir)
	if err != nil {
		return err
	}
	resIDsToCheck := make(map[string]bool)
	for id := range knownIDs {
		resIDsToCheck[id] = true
	}
	for _, de := range entries {
		name := de.Name()
		if strings.HasPrefix(name, IntentFilePrefix) && strings.HasSuffix(name, ".json") {
			resIDsToCheck[name[len(IntentFilePrefix):len(name)-len(".json")]] = true
		}
		if strings.HasPrefix(name, ConfirmationFilePrefix) && strings.HasSuffix(name, ".json") {
			resIDsToCheck[name[len(ConfirmationFilePrefix):len(name)-len(".json")]] = true
		}
	}

	for _, resID := range sortedKeysMap(resIDsToCheck) {
		intentName := fmt.Sprintf("%s%s.json", IntentFilePrefix, resID)
		confName := fmt.Sprintf("%s%s.json", ConfirmationFilePrefix, resID)
		witnessExpID := expID
		if mapped, ok := expectedExpForRes[resID]; ok {
			witnessExpID = mapped
		}
		intentRec, intentErr := readWitnessRecord(ledgerDir, intentName, "SETTLEMENT_INTENT", witnessExpID)
		confRec, confErr := readWitnessRecord(ledgerDir, confName, "SETTLEMENT_CONFIRMATION", witnessExpID)
		jSettled, isSettled := settledEntries[resID]
		if isSettled {
			if intentErr != nil {
				return fmt.Errorf("%w: %w: settled reservation %s has invalid intent witness: %w", ErrLedgerCorrupt, ErrSettlementEvidence, resID, intentErr)
			}
			if confErr != nil {
				return fmt.Errorf("%w: %w: settled reservation %s has invalid confirmation witness: %w", ErrLedgerCorrupt, ErrSettlementEvidence, resID, confErr)
			}
			if confRec == nil || intentRec == nil {
				return fmt.Errorf("%w: %w: settled reservation %s has missing witness", ErrLedgerCorrupt, ErrSettlementEvidence, resID)
			}
			if intentRec.ReservationID != jSettled.ReservationID || confRec.ReservationID != jSettled.ReservationID ||
				intentRec.RequestID != jSettled.RequestID || confRec.RequestID != jSettled.RequestID ||
				intentRec.RequestDigest != jSettled.RequestDigest || confRec.RequestDigest != jSettled.RequestDigest ||
				intentRec.ResponseID != jSettled.ResponseID || confRec.ResponseID != jSettled.ResponseID ||
				intentRec.Model != jSettled.Model || confRec.Model != jSettled.Model ||
				intentRec.ServiceTier != jSettled.ServiceTier || confRec.ServiceTier != jSettled.ServiceTier ||
				intentRec.InputTokens != jSettled.InputTokens || confRec.InputTokens != jSettled.InputTokens ||
				intentRec.OutputTokens != jSettled.OutputTokens || confRec.OutputTokens != jSettled.OutputTokens ||
				intentRec.TotalTokens != jSettled.TotalTokens || confRec.TotalTokens != jSettled.TotalTokens ||
				intentRec.SettledAmountMicros != jSettled.SettledAmountMicros || confRec.SettledAmountMicros != jSettled.SettledAmountMicros ||
				intentRec.UnencumberedAmountMicros != jSettled.UnencumberedAmountMicros || confRec.UnencumberedAmountMicros != jSettled.UnencumberedAmountMicros ||
				intentRec.TimestampUTC != jSettled.TimestampUTC || confRec.TimestampUTC != jSettled.TimestampUTC {
				return fmt.Errorf("%w: %w: witness mismatch for reservation %s", ErrLedgerCorrupt, ErrSettlementEvidence, resID)
			}
		} else {
			if intentErr != nil {
				return fmt.Errorf("%w: %w: dangling invalid intent witness for reservation %s: %w", ErrLedgerCorrupt, ErrSettlementEvidence, resID, intentErr)
			}
			if confErr != nil {
				return fmt.Errorf("%w: %w: dangling invalid confirmation witness for reservation %s: %w", ErrLedgerCorrupt, ErrSettlementEvidence, resID, confErr)
			}
			if intentRec != nil || confRec != nil {
				return fmt.Errorf("%w: %w: dangling witness for reservation %s", ErrLedgerCorrupt, ErrSettlementEvidence, resID)
			}
		}
	}
	return nil
}

// inspectTargetLedgerReadOnly validates the target ledger under read-only
// inspection semantics without modifying any guard, completion, lock, lease, or
// ledger file on disk.
func inspectTargetLedgerReadOnly(targetLedgerDir string, expectedExpID string) (*LedgerState, error) {
	if err := checkDirPath(targetLedgerDir); err != nil {
		return nil, err
	}
	statePath := filepath.Join(targetLedgerDir, StateFilename)
	fiState, err := os.Lstat(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: state file missing", ErrLedgerNotFound)
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: symlink detected on state path", ErrLedgerSecurity)
		}
		return nil, err
	}
	if (fiState.Mode() & os.ModeSymlink) != 0 {
		return nil, fmt.Errorf("%w: symlink detected on state path", ErrLedgerSecurity)
	}

	lockPath := filepath.Join(targetLedgerDir, LockFilename)
	lockFD, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%w: runtime lock file missing", ErrLedgerSecurity)
		}
		return nil, fmt.Errorf("%w: cannot open target lock file: %v", ErrLedgerSecurity, err)
	}
	defer syscall.Close(lockFD)
	if err := checkDescriptor(lockFD, false); err != nil {
		return nil, err
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock target ledger: %w", err)
	}
	defer func() {
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
	}()

	leasePath := filepath.Join(targetLedgerDir, LeaseFilename)
	leaseFD, err := syscall.Open(leasePath, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		if cerr := checkDescriptor(leaseFD, false); cerr != nil {
			_ = syscall.Close(leaseFD)
			return nil, cerr
		}
		if ferr := syscall.Flock(leaseFD, syscall.LOCK_EX|syscall.LOCK_NB); ferr != nil {
			_ = syscall.Close(leaseFD)
			if errors.Is(ferr, syscall.EWOULDBLOCK) || errors.Is(ferr, syscall.EAGAIN) || errors.Is(ferr, syscall.EACCES) {
				return nil, ErrInFlightReservation
			}
			return nil, fmt.Errorf("check target lease: %w", ferr)
		}
		_ = syscall.Flock(leaseFD, syscall.LOCK_UN)
		_ = syscall.Close(leaseFD)
	} else if !errors.Is(err, syscall.ENOENT) {
		return nil, fmt.Errorf("%w: cannot inspect target lease file: %v", ErrLedgerSecurity, err)
	}

	state, err := readStateFile(targetLedgerDir, expectedExpID)
	if err != nil {
		return nil, err
	}
	guard, err := readWitnessRecord(targetLedgerDir, InspectionGuardFilename, RecordTypeInspectionGuard, expectedExpID)
	if err != nil {
		return nil, err
	}
	if guard == nil {
		return nil, fmt.Errorf("%w: inspection guard missing", ErrLedgerCorrupt)
	}
	if minGen := migratedInspectionGen(state); minGen > 0 && guard.Generation < minGen {
		return nil, fmt.Errorf("%w: inspection generation %d precedes migration generation %d", ErrLedgerCorrupt, guard.Generation, minGen)
	}
	comp, err := readWitnessRecord(targetLedgerDir, InspectionCompletionFilename, RecordTypeInspectionComp, expectedExpID)
	if err != nil {
		return nil, err
	}
	if state.Halted {
		if comp != nil && comp.Generation != guard.Generation {
			return nil, ErrGuardUnfinished
		}
		return state, nil
	}
	if comp == nil || comp.Generation != guard.Generation {
		return nil, ErrGuardUnfinished
	}
	if state.PendingReservation != nil {
		return nil, fmt.Errorf("%w: target ledger has pending reservation %s", ErrInFlightReservation, state.PendingReservation.ReservationID)
	}
	if err := verifyWitnessPairs(targetLedgerDir, state); err != nil {
		return nil, err
	}
	return state, nil
}

func verifyLegacyWitnessesBeforeMigration(legacyLedgerDir string, legacyState *LedgerState, _ string) ([]string, error) {
	entries, err := os.ReadDir(legacyLedgerDir)
	if err != nil {
		return nil, err
	}

	var witnessFiles []string
	for _, de := range entries {
		name := de.Name()
		isIntent := strings.HasPrefix(name, IntentFilePrefix) && strings.HasSuffix(name, ".json")
		isConf := strings.HasPrefix(name, ConfirmationFilePrefix) && strings.HasSuffix(name, ".json")
		if !isIntent && !isConf {
			continue
		}
		if err := verifyRegularWitnessFile(filepath.Join(legacyLedgerDir, name)); err != nil {
			return nil, fmt.Errorf("%w: legacy witness %s invalid: %w", ErrLedgerCorrupt, name, err)
		}
		witnessFiles = append(witnessFiles, name)
	}
	if !legacyState.Halted {
		if err := verifyWitnessPairs(legacyLedgerDir, legacyState); err != nil {
			return nil, err
		}
	}
	sort.Strings(witnessFiles)
	return witnessFiles, nil
}

func verifyTargetMatchesLegacyPrefix(legacyState *LedgerState, targetState *LedgerState, spec ProviderLedgerSpec, expectedInspectionGen int) error {
	if targetState.SchemaVersion != SchemaVersionV2 {
		return fmt.Errorf("%w: target schema_version=%d != %d", ErrLedgerCorrupt, targetState.SchemaVersion, SchemaVersionV2)
	}
	if targetState.ExperimentID != spec.TargetID || targetState.LegacyExperimentID != spec.LegacyID {
		return fmt.Errorf("%w: target IDs (%q/%q) do not match (%q/%q)", ErrLedgerCorrupt, targetState.ExperimentID, targetState.LegacyExperimentID, spec.TargetID, spec.LegacyID)
	}
	if targetState.CreatedAtUTC != legacyState.CreatedAtUTC ||
		targetState.GlobalCeilingMicros != legacyState.GlobalCeilingMicros ||
		targetState.ReservationAmountMicros != legacyState.ReservationAmountMicros ||
		targetState.CommittedSpendMicros != legacyState.CommittedSpendMicros ||
		targetState.RetainedFailedMicros != legacyState.RetainedFailedMicros ||
		targetState.TotalReservationsCount != legacyState.TotalReservationsCount ||
		targetState.SettledRequestsCount != legacyState.SettledRequestsCount ||
		targetState.PendingReservation != nil ||
		targetState.Halted != legacyState.Halted {
		return fmt.Errorf("%w: target ledger state diverges from legacy ledger", ErrLedgerCorrupt)
	}
	if (legacyState.HaltReason == nil) != (targetState.HaltReason == nil) ||
		(legacyState.HaltReason != nil && *legacyState.HaltReason != *targetState.HaltReason) {
		return fmt.Errorf("%w: target halt_reason diverges from legacy ledger", ErrLedgerCorrupt)
	}
	if len(targetState.Journal) != len(legacyState.Journal)+1 {
		return fmt.Errorf("%w: target journal length (%d) != legacy (%d)+1", ErrLedgerCorrupt, len(targetState.Journal), len(legacyState.Journal))
	}
	last := targetState.Journal[len(targetState.Journal)-1]
	if last.EntryType != "MIGRATED" || last.ExperimentID != spec.TargetID || last.FromExperimentID != spec.LegacyID || last.LegacyDirName != spec.LegacyDir || last.Reason != MigrationReasonCLI || last.InspectionGeneration != expectedInspectionGen {
		return fmt.Errorf("%w: target journal final entry is not matching MIGRATED record", ErrLedgerCorrupt)
	}
	for i := range legacyState.Journal {
		lb, err := json.Marshal(legacyState.Journal[i])
		if err != nil {
			return err
		}
		tb, err := json.Marshal(targetState.Journal[i])
		if err != nil {
			return err
		}
		if !bytes.Equal(lb, tb) {
			return fmt.Errorf("%w: target journal entry %d diverges from legacy prefix", ErrLedgerCorrupt, i)
		}
	}
	return nil
}

func makeMigrationResult(provider, status, legacyRoot, targetRoot string, st *LedgerState) *MigrationResult {
	res := &MigrationResult{
		Provider:   provider,
		Status:     status,
		LegacyRoot: legacyRoot,
		TargetRoot: targetRoot,
	}
	if st != nil {
		res.CommittedSpendMicros = st.CommittedSpendMicros
		res.RetainedFailedMicros = st.RetainedFailedMicros
		res.TotalReservationsCount = st.TotalReservationsCount
		res.SettledRequestsCount = st.SettledRequestsCount
		res.Halted = st.Halted
		if st.HaltReason != nil {
			res.HaltReason = *st.HaltReason
		}
	}
	return res
}

func retireEmptyOrEvidenceOnlyLegacy(absRoot, legacyRoot, targetRoot string, spec ProviderLedgerSpec, evidenceFiles []string, dryRun bool, faultAfter migrateFaultStep) (*MigrationResult, error) {
	if dryRun {
		return makeMigrationResult(spec.Provider, "would_retire_empty_legacy", legacyRoot, targetRoot, nil), nil
	}
	stageName := fmt.Sprintf(".retire-%s-%d-%s", spec.Provider, os.Getpid(), randomHex(8))
	stageDir := filepath.Join(absRoot, stageName)
	if err := os.MkdirAll(stageDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: cannot create retire stage dir: %v", ErrLedgerSecurity, err)
	}
	_ = os.Chmod(stageDir, 0700)
	keepStageDir := false
	defer func() {
		if !keepStageDir {
			_ = os.RemoveAll(stageDir)
		}
	}()

	l, err := InitializeV2(filepath.Join(stageDir, "ledger"), spec.TargetID)
	if err != nil {
		return nil, err
	}
	_ = l.Close()
	stagedState, err := readStateFile(filepath.Join(stageDir, "ledger"), spec.TargetID)
	if err != nil {
		return nil, err
	}

	for _, name := range evidenceFiles {
		if err := copyVerifiedEvidenceFile(legacyRoot, stageDir, name); err != nil {
			return nil, err
		}
	}
	if err := fsyncDirPath(filepath.Join(stageDir, "ledger")); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(stageDir); err != nil {
		return nil, err
	}

	stageLedgerName := fmt.Sprintf(".retire-ledger-%s-%d-%s", spec.Provider, os.Getpid(), randomHex(8))
	stageLedgerDir := filepath.Join(absRoot, stageLedgerName)
	if err := os.MkdirAll(stageLedgerDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: cannot create legacy retirement ledger stage dir: %v", ErrLedgerSecurity, err)
	}
	_ = os.Chmod(stageLedgerDir, 0700)
	publishedLedgerStage := false
	defer func() {
		if !publishedLedgerStage {
			_ = os.RemoveAll(stageLedgerDir)
		}
	}()

	lockPath := filepath.Join(stageLedgerDir, LockFilename)
	lockFD, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot create legacy retirement lock: %v", ErrLedgerSecurity, err)
	}
	defer func() {
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
		_ = syscall.Close(lockFD)
	}()
	if err := syscall.Fsync(lockFD); err != nil {
		return nil, err
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock legacy retirement dir: %w", err)
	}

	intent := &MigrationIntent{
		SchemaVersion:       SchemaVersionV2,
		Mode:                IntentModeRetireEmpty,
		TargetCreatedAtUTC:  stagedState.CreatedAtUTC,
		StageDirName:        stageName,
		FromExperimentID:    spec.LegacyID,
		ToExperimentID:      spec.TargetID,
		LegacyDir:           spec.LegacyDir,
		TargetDir:           spec.TargetDir,
		EvidenceCount:       len(evidenceFiles),
		EvidenceNamesDigest: computeEvidenceNamesDigest(evidenceFiles),
	}
	if err := publishMigrationIntent(stageLedgerDir, intent); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(stageLedgerDir); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(absRoot); err != nil {
		return nil, err
	}
	if faultAfter == faultBeforeIntentPublish {
		return nil, errors.New("injected fault before migration intent publish")
	}

	legacyLedgerDir := filepath.Join(legacyRoot, "ledger")
	if _, lerr := os.Lstat(legacyLedgerDir); lerr == nil {
		if err := checkDirPath(legacyLedgerDir); err != nil {
			return nil, err
		}
		legEntries, err := os.ReadDir(legacyLedgerDir)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot read legacy ledger dir: %v", ErrLedgerSecurity, err)
		}
		if len(legEntries) != 0 {
			return nil, fmt.Errorf("%w: %w: legacy ledger dir %s is not empty", ErrLedgerCorrupt, ErrMigrationState, legacyLedgerDir)
		}
		if err := syscall.Rename(stageLedgerDir, legacyLedgerDir); err != nil {
			return nil, fmt.Errorf("%w: atomic install of legacy retirement ledger dir failed: %v", ErrMigrationState, err)
		}
	} else if os.IsNotExist(lerr) {
		if err := unix.Renameat2(unix.AT_FDCWD, stageLedgerDir, unix.AT_FDCWD, legacyLedgerDir, unix.RENAME_NOREPLACE); err != nil {
			return nil, fmt.Errorf("%w: atomic publish of legacy retirement ledger dir failed: %v", ErrMigrationState, err)
		}
	} else {
		return nil, fmt.Errorf("%w: cannot stat legacy ledger dir %s: %v", ErrLedgerSecurity, legacyLedgerDir, lerr)
	}
	publishedLedgerStage = true
	keepStageDir = true
	if err := fsyncDirPath(legacyRoot); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(absRoot); err != nil {
		return nil, err
	}
	if faultAfter == faultAfterIntentWrite {
		return nil, errors.New("injected fault after migration intent write")
	}

	st, err := resumeOrFinalizeIntentUnderLock(absRoot, legacyRoot, legacyLedgerDir, targetRoot, spec, intent, evidenceFiles, nil, false, faultAfter)
	if err != nil {
		return nil, err
	}
	return makeMigrationResult(spec.Provider, "retired_empty_legacy", legacyRoot, targetRoot, st), nil
}

// MigrateProviderLedger migrates one provider's legacy ledger directory and
// experiment_id to the schema-v2 target path and ID in a crash-safe, fail-closed
// manner, never modifying or deleting legacyRoot/ledger/ (leaving it
// tombstoned without ledger.json so older binaries cannot re-initialize it).
func MigrateProviderLedger(stateRoot string, provider string, dryRun bool) (*MigrationResult, error) {
	return migrateProviderLedgerWithHook(stateRoot, provider, dryRun, faultNone)
}

func migrateProviderLedgerWithHook(stateRoot string, provider string, dryRun bool, faultAfter migrateFaultStep) (*MigrationResult, error) {
	spec, ok := ProviderLedgerSpecs[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
	absRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, err
	}
	legacyRoot := filepath.Join(absRoot, spec.LegacyDir)
	legacyLedgerDir := filepath.Join(legacyRoot, "ledger")
	targetRoot := filepath.Join(absRoot, spec.TargetDir)
	targetLedgerDir := filepath.Join(targetRoot, "ledger")

	_, legStatErr := os.Lstat(legacyRoot)
	legacyExists := legStatErr == nil
	if legStatErr != nil && !os.IsNotExist(legStatErr) {
		return nil, fmt.Errorf("%w: cannot stat legacy root %s: %v", ErrLedgerSecurity, legacyRoot, legStatErr)
	}
	_, tgtStatErr := os.Lstat(targetRoot)
	targetExists := tgtStatErr == nil
	if tgtStatErr != nil && !os.IsNotExist(tgtStatErr) {
		return nil, fmt.Errorf("%w: cannot stat target root %s: %v", ErrLedgerSecurity, targetRoot, tgtStatErr)
	}

	if !legacyExists && !targetExists {
		return makeMigrationResult(provider, "not_initialized", legacyRoot, targetRoot, nil), nil
	}

	if legacyExists {
		if err := checkDirPath(legacyRoot); err != nil {
			return nil, err
		}
	}
	if targetExists {
		if err := checkDirPath(targetRoot); err != nil {
			return nil, err
		}
	}

	legacyStateExists := false
	if legacyExists {
		legacyStatePath := filepath.Join(legacyLedgerDir, StateFilename)
		if _, err := os.Lstat(legacyStatePath); err == nil {
			legacyStateExists = true
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: cannot stat legacy state %s: %v", ErrLedgerSecurity, legacyStatePath, err)
		}
	}

	if !legacyStateExists {
		if !legacyExists {
			return nil, fmt.Errorf("%w: %w: target %s directory %s lacks matching legacy retirement scaffold", ErrLedgerCorrupt, ErrMigrationState, provider, targetRoot)
		}

		var unlockScaffold func()
		if _, lockStatErr := os.Lstat(filepath.Join(legacyLedgerDir, LockFilename)); lockStatErr == nil {
			unlockScaffold, err = lockLegacyScaffold(legacyLedgerDir)
			if err != nil {
				return nil, fmt.Errorf("%w: %w: legacy %s lock invalid: %w", ErrLedgerCorrupt, ErrMigrationState, provider, err)
			}
			defer unlockScaffold()
		} else if !os.IsNotExist(lockStatErr) {
			return nil, fmt.Errorf("%w: %w: cannot stat legacy lock: %v", ErrLedgerSecurity, ErrMigrationState, lockStatErr)
		}

		intentPath := filepath.Join(legacyLedgerDir, MigrationIntentFilename)
		if _, iErr := os.Lstat(intentPath); iErr == nil {
			if unlockScaffold == nil {
				return nil, fmt.Errorf("%w: %w: legacy %s migration intent present without lock file", ErrLedgerCorrupt, ErrMigrationState, provider)
			}
			intent, err := validateMigrationIntent(legacyLedgerDir, spec)
			if err != nil {
				return nil, err
			}
			existingTomb, evFiles, err := verifyLegacyScaffoldDuringIntent(legacyRoot, legacyLedgerDir, intent, spec)
			if err != nil {
				return nil, err
			}
			st, err := resumeOrFinalizeIntentUnderLock(absRoot, legacyRoot, legacyLedgerDir, targetRoot, spec, intent, evFiles, existingTomb, dryRun, faultAfter)
			if err != nil {
				return nil, err
			}
			if intent.Mode == IntentModeRetireEmpty {
				if dryRun {
					return makeMigrationResult(provider, "would_retire_empty_legacy", legacyRoot, targetRoot, st), nil
				}
				return makeMigrationResult(provider, "retired_empty_legacy", legacyRoot, targetRoot, st), nil
			}
			if dryRun {
				return makeMigrationResult(provider, "would_finalize_interrupted_migration", legacyRoot, targetRoot, st), nil
			}
			return makeMigrationResult(provider, "initialized_v2", legacyRoot, targetRoot, st), nil
		} else if !os.IsNotExist(iErr) {
			return nil, fmt.Errorf("%w: %w: cannot stat migration intent: %v", ErrLedgerSecurity, ErrMigrationState, iErr)
		}

		tomb, backupState, err := verifyRetiredLegacyScaffold(legacyRoot, spec)
		if err != nil {
			if errors.Is(err, ErrLedgerNotFound) {
				emptyOK, cErr := classifyLegacyWithoutState(legacyRoot)
				if cErr == nil && emptyOK {
					evFiles, evErr := verifyEvidenceFilesReadOnly(legacyRoot)
					if evErr != nil {
						return nil, evErr
					}
					if !targetExists {
						return retireEmptyOrEvidenceOnlyLegacy(absRoot, legacyRoot, targetRoot, spec, evFiles, dryRun, faultAfter)
					}
				}
			}
			return nil, fmt.Errorf("%w: %w: legacy state missing and retirement scaffold invalid: %w", ErrLedgerCorrupt, ErrMigrationState, err)
		}
		if !targetExists {
			return nil, fmt.Errorf("%w: %w: legacy %s directory is tombstoned but target directory %s is missing", ErrLedgerCorrupt, ErrMigrationState, provider, targetRoot)
		}
		targetState, err := inspectTargetLedgerReadOnly(targetLedgerDir, spec.TargetID)
		if err != nil {
			return nil, err
		}
		if err := verifyTargetProvenance(targetState, tomb, backupState, spec); err != nil {
			return nil, err
		}
		status := "already_migrated"
		if tomb.Mode == TombstoneModeFreshV2 {
			status = "initialized_v2"
		}
		return makeMigrationResult(provider, status, legacyRoot, targetRoot, targetState), nil
	}

	// Legacy ledger.json exists: lock legacy ledger and validate all invariants.
	if err := checkDirPath(legacyLedgerDir); err != nil {
		return nil, err
	}
	releaseLocks, err := acquireLegacyMigrationLocks(legacyLedgerDir, dryRun)
	if err != nil {
		return nil, err
	}
	defer releaseLocks()

	legacyState, err := readStateFile(legacyLedgerDir, spec.LegacyID)
	if err != nil {
		return nil, err
	}
	if legacyState.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unexpected legacy schema_version %d", ErrLedgerCorrupt, legacyState.SchemaVersion)
	}
	if legacyState.PendingReservation != nil {
		return nil, fmt.Errorf("%w: legacy %s ledger has pending reservation %s", ErrInFlightReservation, provider, legacyState.PendingReservation.ReservationID)
	}

	legacyGuard, err := readWitnessRecord(legacyLedgerDir, InspectionGuardFilename, RecordTypeInspectionGuard, spec.LegacyID)
	if err != nil {
		return nil, err
	}
	if legacyGuard == nil {
		return nil, fmt.Errorf("%w: legacy inspection_guard.json missing", ErrLedgerCorrupt)
	}
	legacyComp, err := readWitnessRecord(legacyLedgerDir, InspectionCompletionFilename, RecordTypeInspectionComp, spec.LegacyID)
	if err != nil {
		return nil, err
	}
	hasComp := legacyComp != nil
	if !legacyState.Halted {
		if !hasComp || legacyComp.Generation != legacyGuard.Generation {
			return nil, ErrGuardUnfinished
		}
	} else if hasComp && legacyComp.Generation != legacyGuard.Generation {
		return nil, ErrGuardUnfinished
	}

	nextGen := legacyGuard.Generation + 1
	if nextGen > MaxInspectionGeneration {
		return nil, fmt.Errorf("%w: inspection generation exhausted", ErrLedgerSecurity)
	}

	witnessFiles, err := verifyLegacyWitnessesBeforeMigration(legacyLedgerDir, legacyState, spec.LegacyID)
	if err != nil {
		return nil, err
	}
	evidenceFiles, err := verifyEvidenceFilesReadOnly(legacyRoot)
	if err != nil {
		return nil, err
	}

	// Subcase A: targetRoot already exists -> interrupted migration recovery.
	if targetExists {
		targetState, err := inspectTargetLedgerReadOnly(targetLedgerDir, spec.TargetID)
		if err != nil {
			return nil, err
		}
		if err := verifyTargetMatchesLegacyPrefix(legacyState, targetState, spec, nextGen); err != nil {
			return nil, err
		}
		for _, ev := range evidenceFiles {
			dstEv := filepath.Join(targetRoot, ev)
			if err := verifyOneEvidenceFile(dstEv); err != nil {
				return nil, err
			}
			if err := verifiedFilesEqual(filepath.Join(legacyRoot, ev), dstEv, MaxEvidenceFileBytes); err != nil {
				return nil, err
			}
		}
		if legacyState.Halted {
			for _, wf := range witnessFiles {
				dstWf := filepath.Join(targetLedgerDir, wf)
				if err := verifyRegularWitnessFile(dstWf); err != nil {
					return nil, fmt.Errorf("%w: %w: target witness %s invalid: %w", ErrLedgerCorrupt, ErrMigrationState, wf, err)
				}
				if err := verifiedFilesEqual(filepath.Join(legacyLedgerDir, wf), dstWf, MaxStateFileBytes); err != nil {
					return nil, err
				}
			}
		}
		if dryRun {
			return makeMigrationResult(provider, "would_finalize_interrupted_migration", legacyRoot, targetRoot, targetState), nil
		}

		if err := cleanupStaleTombstoneTemps(legacyRoot); err != nil {
			return nil, err
		}
		if tomb, tombErr := validateTombstone(legacyRoot, spec); tombErr != nil || tomb.Mode != TombstoneModeMigrated {
			if tombErr == nil && tomb.Mode != TombstoneModeMigrated {
				return nil, fmt.Errorf("%w: %w: unexpected tombstone mode %q during recovery", ErrLedgerCorrupt, ErrMigrationState, tomb.Mode)
			}
			if err := publishTombstone(legacyRoot, spec, TombstoneModeMigrated, nowUTCStr(), ""); err != nil {
				return nil, err
			}
			if faultAfter == faultAfterTombstoneWrite {
				return nil, errors.New("injected fault after tombstone write")
			}
		}
		if err := unix.Renameat2(unix.AT_FDCWD, filepath.Join(legacyLedgerDir, StateFilename), unix.AT_FDCWD, filepath.Join(legacyLedgerDir, PreMigrationBackupFilename), unix.RENAME_NOREPLACE); err != nil {
			return nil, fmt.Errorf("move legacy state aside: %w", err)
		}
		if err := fsyncDirPath(legacyLedgerDir); err != nil {
			return nil, err
		}
		return makeMigrationResult(provider, "migrated_recovered", legacyRoot, targetRoot, targetState), nil
	}

	// Subcase B: fresh migration from legacyRoot -> targetRoot.
	if dryRun {
		return makeMigrationResult(provider, "would_migrate", legacyRoot, targetRoot, legacyState), nil
	}

	stageName := fmt.Sprintf(".migrate-%s-%d-%s", provider, os.Getpid(), randomHex(8))
	stageDir := filepath.Join(absRoot, stageName)
	stageLedgerDir := filepath.Join(stageDir, "ledger")
	if err := os.MkdirAll(stageLedgerDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: cannot create stage dir: %v", ErrLedgerSecurity, err)
	}
	if err := os.Chmod(stageDir, 0700); err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, err
	}
	if err := os.Chmod(stageLedgerDir, 0700); err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, err
	}
	committedTarget := false
	defer func() {
		if !committedTarget {
			_ = os.RemoveAll(stageDir)
		}
	}()

	for _, name := range witnessFiles {
		if err := copyVerifiedRegularFile(legacyLedgerDir, stageLedgerDir, name); err != nil {
			return nil, err
		}
	}
	for _, name := range evidenceFiles {
		if err := copyVerifiedEvidenceFile(legacyRoot, stageDir, name); err != nil {
			return nil, err
		}
	}

	stageLockPath := filepath.Join(stageLedgerDir, LockFilename)
	slFD, err := syscall.Open(stageLockPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create stage lock: %w", err)
	}
	_ = syscall.Fsync(slFD)
	_ = syscall.Close(slFD)

	now := nowUTCStr()
	guardRec := WitnessRecord{
		RecordType:   RecordTypeInspectionGuard,
		ExperimentID: spec.TargetID,
		Generation:   nextGen,
		ArmedAtUTC:   now,
	}
	guardEnc, _ := json.MarshalIndent(guardRec, "", "  ")
	if err := publishBytes(defaultFS, stageLedgerDir, InspectionGuardFilename, ".tmp_guard_", guardEnc); err != nil {
		return nil, err
	}
	if hasComp {
		compRec := WitnessRecord{
			RecordType:     RecordTypeInspectionComp,
			ExperimentID:   spec.TargetID,
			Generation:     nextGen,
			CompletedAtUTC: now,
		}
		compEnc, _ := json.MarshalIndent(compRec, "", "  ")
		if err := publishBytes(defaultFS, stageLedgerDir, InspectionCompletionFilename, ".tmp_comp_", compEnc); err != nil {
			return nil, err
		}
	}

	migratedJournal := make([]JournalEntry, len(legacyState.Journal)+1)
	copy(migratedJournal, legacyState.Journal)
	migratedJournal[len(legacyState.Journal)] = JournalEntry{
		EntryType:            "MIGRATED",
		ExperimentID:         spec.TargetID,
		FromExperimentID:     spec.LegacyID,
		InspectionGeneration: nextGen,
		LegacyDirName:        spec.LegacyDir,
		Reason:               MigrationReasonCLI,
		TimestampUTC:         now,
	}

	migratedState := &LedgerState{
		SchemaVersion:           SchemaVersionV2,
		ExperimentID:            spec.TargetID,
		LegacyExperimentID:      spec.LegacyID,
		CreatedAtUTC:            legacyState.CreatedAtUTC,
		UpdatedAtUTC:            now,
		GlobalCeilingMicros:     legacyState.GlobalCeilingMicros,
		ReservationAmountMicros: legacyState.ReservationAmountMicros,
		CommittedSpendMicros:    legacyState.CommittedSpendMicros,
		RetainedFailedMicros:    legacyState.RetainedFailedMicros,
		TotalReservationsCount:  legacyState.TotalReservationsCount,
		SettledRequestsCount:    legacyState.SettledRequestsCount,
		PendingReservation:      nil,
		Halted:                  legacyState.Halted,
		HaltReason:              legacyState.HaltReason,
		Journal:                 migratedJournal,
	}

	if err := writeStateFile(defaultFS, stageLedgerDir, migratedState); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(stageLedgerDir); err != nil {
		return nil, err
	}
	if err := fsyncDirPath(stageDir); err != nil {
		return nil, err
	}

	// Step A: atomically publish target directory without replacing any existing path.
	if err := unix.Renameat2(unix.AT_FDCWD, stageDir, unix.AT_FDCWD, targetRoot, unix.RENAME_NOREPLACE); err != nil {
		return nil, fmt.Errorf("atomic target directory publish failed: %w", err)
	}
	committedTarget = true
	if err := fsyncDirPath(absRoot); err != nil {
		return nil, err
	}
	if faultAfter == faultAfterTargetRename {
		return nil, errors.New("injected fault after target directory publish")
	}

	// Step B.1: write tombstone inside legacyRoot BEFORE moving legacy ledger.json aside.
	if err := publishTombstone(legacyRoot, spec, TombstoneModeMigrated, now, ""); err != nil {
		return nil, err
	}
	if faultAfter == faultAfterTombstoneWrite {
		return nil, errors.New("injected fault after tombstone write")
	}

	// Step B.2: move legacy ledger/ledger.json aside while KEEPING legacyRoot/ledger/
	// permanently in place so older binaries calling OpenOrInitLedger fail closed.
	if err := unix.Renameat2(unix.AT_FDCWD, filepath.Join(legacyLedgerDir, StateFilename), unix.AT_FDCWD, filepath.Join(legacyLedgerDir, PreMigrationBackupFilename), unix.RENAME_NOREPLACE); err != nil {
		return nil, fmt.Errorf("move legacy state aside: %w", err)
	}
	if err := fsyncDirPath(legacyLedgerDir); err != nil {
		return nil, err
	}

	return makeMigrationResult(provider, "migrated", legacyRoot, targetRoot, migratedState), nil
}
