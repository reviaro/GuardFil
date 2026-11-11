package budget

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type JournalEntry struct {
	EntryType                string   `json:"entry_type"`
	ExperimentID             string   `json:"experiment_id,omitempty"`
	GlobalCeilingMicros      int      `json:"global_ceiling_micros,omitempty"`
	ReservationID            string   `json:"reservation_id,omitempty"`
	RequestID                string   `json:"request_id,omitempty"`
	RequestDigest            string   `json:"request_digest,omitempty"`
	ReservedAmountMicros     int      `json:"reserved_amount_micros,omitempty"`
	ReservationIndex         int      `json:"reservation_index,omitempty"`
	ResponseID               string   `json:"response_id,omitempty"`
	Model                    string   `json:"model,omitempty"`
	ServiceTier              string   `json:"service_tier,omitempty"`
	InputTokens              int      `json:"input_tokens,omitempty"`
	OutputTokens             int      `json:"output_tokens,omitempty"`
	TotalTokens              int      `json:"total_tokens,omitempty"`
	SettledAmountMicros      int      `json:"settled_amount_micros,omitempty"`
	UnencumberedAmountMicros int      `json:"unencumbered_amount_micros,omitempty"`
	RetainedAmountMicros     int      `json:"retained_amount_micros,omitempty"`
	Reason                   string   `json:"reason,omitempty"`
	UncertainReservationIDs  []string `json:"uncertain_reservation_ids,omitempty"`
	TimestampUTC             string   `json:"timestamp_utc"`
}

type PendingReservationData struct {
	ReservationID        string `json:"reservation_id"`
	RequestID            string `json:"request_id"`
	RequestDigest        string `json:"request_digest"`
	ReservedAmountMicros int    `json:"reserved_amount_micros"`
	ReservedAtUTC        string `json:"reserved_at_utc"`
	PID                  int    `json:"pid"`
}

type LedgerState struct {
	SchemaVersion           int                     `json:"schema_version"`
	ExperimentID            string                  `json:"experiment_id"`
	CreatedAtUTC            string                  `json:"created_at_utc"`
	UpdatedAtUTC            string                  `json:"updated_at_utc"`
	GlobalCeilingMicros     int                     `json:"global_ceiling_micros"`
	ReservationAmountMicros int                     `json:"reservation_amount_micros"`
	CommittedSpendMicros    int                     `json:"committed_spend_micros"`
	RetainedFailedMicros    int                     `json:"retained_failed_micros"`
	TotalReservationsCount  int                     `json:"total_reservations_count"`
	SettledRequestsCount    int                     `json:"settled_requests_count"`
	PendingReservation      *PendingReservationData `json:"pending_reservation"`
	Halted                  bool                    `json:"halted"`
	HaltReason              *string                 `json:"halt_reason"`
	Journal                 []JournalEntry          `json:"journal"`
}

type WitnessRecord struct {
	RecordType               string `json:"record_type"`
	ExperimentID             string `json:"experiment_id"`
	ReservationID            string `json:"reservation_id,omitempty"`
	RequestID                string `json:"request_id,omitempty"`
	RequestDigest            string `json:"request_digest,omitempty"`
	ResponseID               string `json:"response_id,omitempty"`
	Model                    string `json:"model,omitempty"`
	ServiceTier              string `json:"service_tier,omitempty"`
	InputTokens              int    `json:"input_tokens,omitempty"`
	OutputTokens             int    `json:"output_tokens,omitempty"`
	TotalTokens              int    `json:"total_tokens,omitempty"`
	SettledAmountMicros      int    `json:"settled_amount_micros,omitempty"`
	UnencumberedAmountMicros int    `json:"unencumbered_amount_micros,omitempty"`
	Generation               int    `json:"generation,omitempty"`
	ArmedAtUTC               string `json:"armed_at_utc,omitempty"`
	CompletedAtUTC           string `json:"completed_at_utc,omitempty"`
	TimestampUTC             string `json:"timestamp_utc,omitempty"`
}

type BudgetLedger struct {
	ledgerDir            string
	experimentID         string
	handleDisabled       bool
	handleDisabledReason *string
	poisoned             bool
	poisonReason         string

	heldLeaseFD int
	mu          sync.Mutex
}

func nowUTCStr() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func checkDescriptor(fd int, isDir bool) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: cannot fstat descriptor: %v", ErrLedgerSecurity, err)
	}
	if st.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("%w: file owner mismatch: expected UID %d, got %d", ErrLedgerSecurity, os.Getuid(), st.Uid)
	}
	if (st.Mode & 0077) != 0 {
		return fmt.Errorf("%w: permissions must not allow group/world access (got %o)", ErrLedgerSecurity, st.Mode)
	}
	if isDir {
		if (st.Mode & syscall.S_IFMT) != syscall.S_IFDIR {
			return fmt.Errorf("%w: not a directory", ErrLedgerSecurity)
		}
	} else {
		if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
			return fmt.Errorf("%w: not a regular file", ErrLedgerSecurity)
		}
		if st.Nlink != 1 {
			return fmt.Errorf("%w: hard links are strictly forbidden on ledger files (nlink=%d)", ErrLedgerSecurity, st.Nlink)
		}
	}
	return nil
}

func (l *BudgetLedger) withLock(fn func() error) error {
	lockPath := filepath.Join(l.ledgerDir, LockFilename)
	lockFD, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: runtime lock file missing", ErrLedgerSecurity)
		}
		return fmt.Errorf("%w: cannot open lock file: %v", ErrLedgerSecurity, err)
	}
	defer syscall.Close(lockFD)

	if err := checkDescriptor(lockFD, false); err != nil {
		return err
	}

	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock: %w", err)
	}
	defer func() {
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
	}()

	return fn()
}

func publishBytes(dir string, finalName string, tmpPrefix string, data []byte) error {
	tmpName := fmt.Sprintf("%s%s", tmpPrefix, randomHex(16))
	tmpPath := filepath.Join(dir, tmpName)
	finalPath := filepath.Join(dir, finalName)

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("%w: cannot create temp file: %v", ErrLedgerSecurity, err)
	}
	cleanupTmp := func() {
		_ = os.Remove(tmpPath)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanupTmp()
		return fmt.Errorf("write error: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanupTmp()
		return fmt.Errorf("sync error: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanupTmp()
		return fmt.Errorf("close error: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		cleanupTmp()
		return fmt.Errorf("rename error: %w", err)
	}

	dirF, err := os.Open(dir)
	if err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

func writeStateFile(dir string, state *LedgerState) error {
	state.UpdatedAtUTC = nowUTCStr()
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded) > MaxStateFileBytes {
		return fmt.Errorf("%w: state size exceeds limit", ErrLedgerSecurity)
	}
	val, err := safeJSONDecode(encoded)
	if err != nil {
		return err
	}
	stateMap, ok := val.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: state JSON must be an object", ErrLedgerCorrupt)
	}
	if _, err := ValidateAndReconcileStateStatic(stateMap, state.ExperimentID); err != nil {
		return err
	}
	return publishBytes(dir, StateFilename, ".tmp_ledger_", encoded)
}

func readStateFile(dir string, expectedExpID string) (*LedgerState, error) {
	statePath := filepath.Join(dir, StateFilename)
	fd, err := syscall.Open(statePath, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, ErrLedgerNotFound
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: symlink detected on state path", ErrLedgerSecurity)
		}
		return nil, fmt.Errorf("%w: cannot open state file: %v", ErrLedgerSecurity, err)
	}
	defer syscall.Close(fd)

	if err := checkDescriptor(fd, false); err != nil {
		return nil, err
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: fstat state file failed: %v", ErrLedgerCorrupt, err)
	}
	if st.Size > MaxStateFileBytes {
		return nil, fmt.Errorf("%w: state file too large (%d bytes)", ErrLedgerCorrupt, st.Size)
	}

	data := make([]byte, st.Size)
	n, err := syscall.Read(fd, data)
	if err != nil {
		return nil, fmt.Errorf("%w: read state failed: %v", ErrLedgerCorrupt, err)
	}
	data = data[:n]

	val, err := safeJSONDecode(data)
	if err != nil {
		return nil, err
	}
	stateMap, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: state JSON must be an object", ErrLedgerCorrupt)
	}
	return ValidateAndReconcileStateStatic(stateMap, expectedExpID)
}

func readWitnessRecord(dir string, name string, expectedType string, expID string) (*WitnessRecord, error) {
	p := filepath.Join(dir, name)
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: symlink detected on witness path", ErrLedgerSecurity)
		}
		return nil, fmt.Errorf("%w: cannot open %s: %v", ErrLedgerSecurity, name, err)
	}
	defer syscall.Close(fd)

	if err := checkDescriptor(fd, false); err != nil {
		return nil, err
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: fstat %s failed: %v", ErrLedgerCorrupt, name, err)
	}
	if st.Size > MaxStateFileBytes {
		return nil, fmt.Errorf("%w: %s file too large", ErrLedgerCorrupt, name)
	}

	data := make([]byte, st.Size)
	n, err := syscall.Read(fd, data)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s failed: %v", ErrLedgerCorrupt, name, err)
	}
	data = data[:n]

	return ValidateWitnessRecord(data, expectedType, expID)
}

func armGuard(dir string, expID string) (int, error) {
	guard, err := readWitnessRecord(dir, InspectionGuardFilename, RecordTypeInspectionGuard, expID)
	if err != nil {
		return 0, err
	}
	if guard == nil {
		return 0, fmt.Errorf("%w: guard missing", ErrLedgerCorrupt)
	}
	comp, err := readWitnessRecord(dir, InspectionCompletionFilename, RecordTypeInspectionComp, expID)
	if err != nil {
		return 0, err
	}
	if comp == nil || comp.Generation != guard.Generation {
		return 0, ErrGuardUnfinished
	}

	nextGen := guard.Generation + 1
	if nextGen > MaxInspectionGeneration {
		return 0, fmt.Errorf("%w: inspection generation exhausted", ErrLedgerSecurity)
	}

	_ = os.Remove(filepath.Join(dir, InspectionCompletionFilename))

	guardRec := WitnessRecord{
		RecordType:   RecordTypeInspectionGuard,
		ExperimentID: expID,
		Generation:   nextGen,
		ArmedAtUTC:   nowUTCStr(),
	}
	guardEnc, _ := json.MarshalIndent(guardRec, "", "  ")
	if err := publishBytes(dir, InspectionGuardFilename, ".tmp_guard_", guardEnc); err != nil {
		return 0, err
	}
	return nextGen, nil
}

func completeGuard(dir string, expID string, gen int) error {
	compRec := WitnessRecord{
		RecordType:     RecordTypeInspectionComp,
		ExperimentID:   expID,
		Generation:     gen,
		CompletedAtUTC: nowUTCStr(),
	}
	compEnc, _ := json.MarshalIndent(compRec, "", "  ")
	return publishBytes(dir, InspectionCompletionFilename, ".tmp_comp_", compEnc)
}

func (l *BudgetLedger) guardedState() (*LedgerState, error) {
	gen, err := armGuard(l.ledgerDir, l.experimentID)
	if err != nil {
		if errors.Is(err, ErrGuardUnfinished) {
			l.poisonHandle("UNFINISHED_INSPECTION_GUARD")
		} else {
			l.poisonHandle("INSPECTION_GUARD_CORRUPT")
		}
		l.releaseLease()
		return nil, err
	}
	state, err := readStateFile(l.ledgerDir, l.experimentID)
	if err != nil {
		l.poisonHandle("INSPECTION_EVIDENCE_UNCERTAINTY")
		l.releaseLease()
		return nil, err
	}
	state, uncertain, err := l.validateAndRecoverRecordsUnderLock(state, l.ledgerDir)
	if err != nil {
		l.poisonHandle("INSPECTION_EVIDENCE_UNCERTAINTY")
		l.releaseLease()
		return nil, err
	}
	if uncertain {
		l.poisonHandle("TERMINAL_UNCERTAINTY")
		l.releaseLease()
		return nil, fmt.Errorf("%w: %s", ErrLedgerHalted, *state.HaltReason)
	}
	if err := completeGuard(l.ledgerDir, l.experimentID, gen); err != nil {
		l.poisonHandle("INSPECTION_COMPLETION_FAILED")
		l.releaseLease()
		return nil, err
	}
	return state, nil
}

func isLeaseHeld(dir string) bool {
	leasePath := filepath.Join(dir, LeaseFilename)
	fd, err := syscall.Open(leasePath, syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES)
}

// Initialize initializes a brand new budget ledger in a non-existent directory.
func Initialize(ledgerDir string, experimentID string) (*BudgetLedger, error) {
	if experimentID == "" {
		experimentID = DefaultExperimentID
	}
	absDir, err := filepath.Abs(ledgerDir)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(absDir); err == nil {
		return nil, fmt.Errorf("%w: directory %s already exists", ErrLedgerAlreadyExists, absDir)
	}

	if err := os.MkdirAll(absDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: cannot create directory: %v", ErrLedgerSecurity, err)
	}

	lockPath := filepath.Join(absDir, LockFilename)
	lockFD, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot create lock file: %v", ErrLedgerAlreadyExists, err)
	}
	defer syscall.Close(lockFD)

	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		return nil, err
	}
	defer func() {
		_ = syscall.Flock(lockFD, syscall.LOCK_UN)
	}()

	now := nowUTCStr()
	initialState := &LedgerState{
		SchemaVersion:           SchemaVersion,
		ExperimentID:            experimentID,
		CreatedAtUTC:            now,
		UpdatedAtUTC:            now,
		GlobalCeilingMicros:     GlobalCeilingMicros,
		ReservationAmountMicros: ReservationAmountMicros,
		CommittedSpendMicros:    0,
		RetainedFailedMicros:    0,
		TotalReservationsCount:  0,
		SettledRequestsCount:    0,
		PendingReservation:      nil,
		Halted:                  false,
		HaltReason:              nil,
		Journal: []JournalEntry{
			{
				EntryType:           "INITIALIZED",
				ExperimentID:        experimentID,
				GlobalCeilingMicros: GlobalCeilingMicros,
				TimestampUTC:        now,
			},
		},
	}

	if err := writeStateFile(absDir, initialState); err != nil {
		return nil, err
	}

	guardRec := WitnessRecord{
		RecordType:   RecordTypeInspectionGuard,
		ExperimentID: experimentID,
		Generation:   1,
		ArmedAtUTC:   now,
	}
	guardEnc, _ := json.MarshalIndent(guardRec, "", "  ")
	if err := publishBytes(absDir, InspectionGuardFilename, ".tmp_guard_", guardEnc); err != nil {
		return nil, err
	}

	compRec := WitnessRecord{
		RecordType:     RecordTypeInspectionComp,
		ExperimentID:   experimentID,
		Generation:     1,
		CompletedAtUTC: now,
	}
	compEnc, _ := json.MarshalIndent(compRec, "", "  ")
	if err := publishBytes(absDir, InspectionCompletionFilename, ".tmp_comp_", compEnc); err != nil {
		return nil, err
	}

	return &BudgetLedger{
		ledgerDir:    absDir,
		experimentID: experimentID,
		heldLeaseFD:  -1,
	}, nil
}

func (l *BudgetLedger) validateAndRecoverRecordsUnderLock(state *LedgerState, dir string) (*LedgerState, bool, error) {
	if state.Halted {
		return state, false, nil
	}

	expID := state.ExperimentID
	knownIDs := make(map[string]bool)
	reservedAmounts := make(map[string]int)
	settledEntries := make(map[string]JournalEntry)
	for _, e := range state.Journal {
		if e.EntryType == "RESERVED" {
			knownIDs[e.ReservationID] = true
			reservedAmounts[e.ReservationID] = e.ReservedAmountMicros
		}
		if e.EntryType == "SETTLED" {
			settledEntries[e.ReservationID] = e
		}
	}
	var pendingResID string
	if state.PendingReservation != nil {
		pendingResID = state.PendingReservation.ReservationID
	}

	uncertainResIDs := make(map[string]bool)
	unattributable := false
	hasUnresolvedIntent := false

	entries, err := os.ReadDir(dir)
	if err != nil {
		unattributable = true
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

	sortedResIDs := sortedKeysMap(resIDsToCheck)
	for _, resID := range sortedResIDs {
		intentName := fmt.Sprintf("%s%s.json", IntentFilePrefix, resID)
		confName := fmt.Sprintf("%s%s.json", ConfirmationFilePrefix, resID)

		intentRec, intentErr := readWitnessRecord(dir, intentName, "SETTLEMENT_INTENT", expID)
		confRec, confErr := readWitnessRecord(dir, confName, "SETTLEMENT_CONFIRMATION", expID)

		attributable := knownIDs[resID]
		jSettled, isSettled := settledEntries[resID]

		if intentRec != nil && confRec == nil && confErr == nil {
			hasUnresolvedIntent = true
		}

		bad := false
		if isSettled {
			if confRec == nil || confErr != nil || intentRec == nil || intentErr != nil {
				bad = true
			} else {
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
					bad = true
				}
			}
		} else if intentRec != nil || intentErr != nil {
			bad = true
			hasUnresolvedIntent = true
		} else if confRec != nil || confErr != nil {
			bad = true
		}

		if bad {
			uncertainResIDs[resID] = true
			if !attributable {
				unattributable = true
			}
		}
	}

	if len(uncertainResIDs) == 0 && !unattributable {
		return state, false, nil
	}

	affected := make(map[string]bool)
	if unattributable {
		for k := range knownIDs {
			affected[k] = true
		}
	} else {
		for k := range uncertainResIDs {
			if knownIDs[k] {
				affected[k] = true
			}
		}
	}
	if pendingResID != "" {
		affected[pendingResID] = true
	}
	affectedIDs := sortedKeysMap(affected)

	for _, uid := range affectedIDs {
		if sEnt, ok := settledEntries[uid]; ok {
			state.CommittedSpendMicros -= sEnt.SettledAmountMicros
			state.RetainedFailedMicros += reservedAmounts[uid]
		} else if uid == pendingResID && state.PendingReservation != nil {
			state.RetainedFailedMicros += state.PendingReservation.ReservedAmountMicros
			state.PendingReservation = nil
		}
	}

	now := nowUTCStr()
	termReason := "TERMINAL_UNCERTAINTY"
	if hasUnresolvedIntent {
		termReason = "UNRESOLVED_SETTLEMENT_PUBLICATION"
	}
	state.Halted = true
	state.HaltReason = &termReason
	state.UpdatedAtUTC = now
	state.Journal = append(state.Journal, JournalEntry{
		EntryType:               "TERMINAL_UNCERTAINTY",
		TimestampUTC:            now,
		Reason:                  termReason,
		UncertainReservationIDs: affectedIDs,
	})

	if err := writeStateFile(dir, state); err != nil {
		return nil, true, err
	}
	return state, true, nil
}

// Open opens an existing budget ledger for runtime transactions.
func Open(ledgerDir string) (*BudgetLedger, error) {
	absDir, err := filepath.Abs(ledgerDir)
	if err != nil {
		return nil, err
	}

	fi, err := os.Lstat(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrLedgerNotFound
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: directory is a symlink", ErrLedgerSecurity)
		}
		return nil, err
	}
	if (fi.Mode() & os.ModeSymlink) != 0 {
		return nil, fmt.Errorf("%w: directory is a symlink", ErrLedgerSecurity)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: not a directory", ErrLedgerSecurity)
	}
	if (fi.Mode().Perm() & 0077) != 0 {
		return nil, fmt.Errorf("%w: directory permissions too permissive: %o", ErrLedgerSecurity, fi.Mode().Perm())
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		if sys.Uid != uint32(os.Getuid()) {
			return nil, fmt.Errorf("%w: directory owner mismatch", ErrLedgerSecurity)
		}
	}

	statePath := filepath.Join(absDir, StateFilename)
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

	b := &BudgetLedger{
		ledgerDir:   absDir,
		heldLeaseFD: -1,
	}

	var expID string
	var disabled bool
	var disabledReason *string

	err = b.withLock(func() error {
		guard, err := readWitnessRecord(absDir, InspectionGuardFilename, RecordTypeInspectionGuard, "")
		if err != nil || guard == nil {
			st, err2 := readStateFile(absDir, "")
			if err2 == nil && st != nil && st.Halted {
				expID = st.ExperimentID
				disabled = true
				r := "INSPECTION_GUARD_CORRUPT"
				disabledReason = &r
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("%w: inspection guard missing", ErrLedgerCorrupt)
		}

		expID = guard.ExperimentID
		gen, err := armGuard(absDir, expID)
		if err != nil {
			if errors.Is(err, ErrGuardUnfinished) {
				st, err2 := readStateFile(absDir, expID)
				if err2 != nil {
					return err2
				}
				reason := "UNFINISHED_INSPECTION_GUARD"
				if st != nil && st.Halted && st.HaltReason != nil {
					reason = *st.HaltReason
				}
				disabled = true
				disabledReason = &reason
				return nil
			}
			st, err2 := readStateFile(absDir, expID)
			if err2 == nil && st != nil && st.Halted {
				disabled = true
				r := "INSPECTION_GUARD_CORRUPT"
				disabledReason = &r
				return nil
			}
			return err
		}

		state, err := readStateFile(absDir, expID)
		if err != nil {
			return err
		}

		state, uncertain, err := b.validateAndRecoverRecordsUnderLock(state, absDir)
		if err != nil {
			return err
		}
		if uncertain {
			disabled = true
			disabledReason = state.HaltReason
			return nil
		}

		if err := completeGuard(absDir, expID, gen); err != nil {
			return err
		}

		// Check orphaned pending reservation from crashed process
		if state.PendingReservation != nil && !isLeaseHeld(absDir) {
			amount := state.PendingReservation.ReservedAmountMicros
			reqID := state.PendingReservation.RequestID
			resID := state.PendingReservation.ReservationID
			state.RetainedFailedMicros += amount
			state.PendingReservation = nil
			state.Halted = true
			r := "UNSETTLED_PENDING_RESERVATION_AT_STARTUP"
			state.HaltReason = &r
			state.UpdatedAtUTC = nowUTCStr()
			state.Journal = append(state.Journal, JournalEntry{
				EntryType:            "ORPHANED_PENDING_HALTED",
				ReservationID:        resID,
				RequestID:            reqID,
				RetainedAmountMicros: amount,
				Reason:               r,
				TimestampUTC:         state.UpdatedAtUTC,
			})
			if err := writeStateFile(absDir, state); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	b.experimentID = expID
	b.handleDisabled = disabled
	b.handleDisabledReason = disabledReason
	return b, nil
}

// OpenOrInitLedger opens existing ledger or initializes it if missing.
func OpenOrInitLedger(experimentRoot string, initialize bool, experimentID string) (*BudgetLedger, error) {
	rootPath, err := filepath.Abs(experimentRoot)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(rootPath, 0700); err != nil {
		return nil, err
	}
	ledgerPath := filepath.Join(rootPath, "ledger")
	if initialize {
		if _, err := os.Stat(ledgerPath); os.IsNotExist(err) {
			return Initialize(ledgerPath, experimentID)
		}
	}
	return Open(ledgerPath)
}

func (l *BudgetLedger) acquireLease() error {
	l.releaseLease()
	leasePath := filepath.Join(l.ledgerDir, LeaseFilename)
	fd, err := syscall.Open(leasePath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("%w: cannot open lease: %v", ErrLedgerSecurity, err)
	}
	err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = syscall.Close(fd)
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrInFlightReservation
		}
		return err
	}
	l.heldLeaseFD = fd
	return nil
}

func (l *BudgetLedger) releaseLease() {
	if l.heldLeaseFD >= 0 {
		_ = syscall.Flock(l.heldLeaseFD, syscall.LOCK_UN)
		_ = syscall.Close(l.heldLeaseFD)
		l.heldLeaseFD = -1
	}
}

func (l *BudgetLedger) poisonHandle(reason string) {
	l.poisoned = true
	l.poisonReason = reason
	l.releaseLease()
}

// Reserve atomically reserves funds for a forwarded request.
func (l *BudgetLedger) Reserve(requestID string, requestDigest string, amountMicros int) (*ReservationPermit, error) {
	if _, err := validateIdentifier(requestID, "request_id"); err != nil {
		return nil, err
	}
	if _, err := validateDigest(requestDigest); err != nil {
		return nil, err
	}
	if amountMicros == 0 {
		amountMicros = ReservationAmountMicros
	}
	if amountMicros < MinReservationMicros || amountMicros > ReservationAmountMicros {
		return nil, fmt.Errorf("reservation amount must be in [%d, %d] uUSD", MinReservationMicros, ReservationAmountMicros)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.poisoned {
		return nil, fmt.Errorf("%w: handle poisoned: %s", ErrLedgerHalted, l.poisonReason)
	}
	if l.handleDisabled {
		return nil, fmt.Errorf("%w: handle disabled", ErrLedgerHalted)
	}

	var permit *ReservationPermit

	err := l.withLock(func() error {
		state, err := l.guardedState()
		if err != nil {
			return err
		}

		if state.Halted {
			reason := "HALTED"
			if state.HaltReason != nil {
				reason = *state.HaltReason
			}
			l.poisonHandle(reason)
			return fmt.Errorf("%w: %s", ErrLedgerHalted, reason)
		}

		for _, e := range state.Journal {
			if e.RequestID == requestID {
				return fmt.Errorf("request_id %s was already used in a prior transaction", requestID)
			}
		}

		if state.PendingReservation != nil {
			return fmt.Errorf("%w: request_id=%s", ErrInFlightReservation, state.PendingReservation.RequestID)
		}

		if state.TotalReservationsCount >= MaxForwardedRequests {
			return ErrReservationLimitExceeded
		}

		projected := state.CommittedSpendMicros + state.RetainedFailedMicros + amountMicros
		if projected > GlobalCeilingMicros {
			return fmt.Errorf("%w: projected=%d ceiling=%d", ErrBudgetExceeded, projected, GlobalCeilingMicros)
		}

		if err := l.acquireLease(); err != nil {
			return err
		}

		permitID := fmt.Sprintf("permit_%s", randomHex(16))
		reservedAt := nowUTCStr()

		pending := &PendingReservationData{
			ReservationID:        permitID,
			RequestID:            requestID,
			RequestDigest:        requestDigest,
			ReservedAmountMicros: amountMicros,
			ReservedAtUTC:        reservedAt,
			PID:                  os.Getpid(),
		}

		state.TotalReservationsCount++
		state.PendingReservation = pending
		state.UpdatedAtUTC = reservedAt
		state.Journal = append(state.Journal, JournalEntry{
			EntryType:            "RESERVED",
			ReservationID:        permitID,
			RequestID:            requestID,
			RequestDigest:        requestDigest,
			ReservedAmountMicros: amountMicros,
			ReservationIndex:     state.TotalReservationsCount,
			TimestampUTC:         reservedAt,
		})

		if err := writeStateFile(l.ledgerDir, state); err != nil {
			l.poisonHandle("RESERVE_DURABLE_WRITE_FAILED")
			return err
		}

		permit = &ReservationPermit{
			PermitID:             permitID,
			RequestID:            requestID,
			RequestDigest:        requestDigest,
			ReservedAmountMicros: amountMicros,
			ReservedAtUTC:        reservedAt,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return permit, nil
}

// Settle settles a pending reservation with verified usage evidence.
func (l *BudgetLedger) Settle(permit *ReservationPermit, receipt *Receipt) (*SettlementResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.poisoned {
		return nil, fmt.Errorf("%w: handle poisoned: %s", ErrLedgerHalted, l.poisonReason)
	}

	var result *SettlementResult

	err := l.withLock(func() error {
		state, err := l.guardedState()
		if err != nil {
			return err
		}

		if state.Halted {
			reason := "HALTED"
			if state.HaltReason != nil {
				reason = *state.HaltReason
			}
			l.poisonHandle(reason)
			return fmt.Errorf("%w: %s", ErrLedgerHalted, reason)
		}

		pending := state.PendingReservation
		if pending == nil {
			return ErrNoPendingReservation
		}

		if permit == nil || permit.PermitID != pending.ReservationID ||
			permit.RequestID != pending.RequestID ||
			permit.RequestDigest != pending.RequestDigest {
			l.failAndHalt(state, pending, "PERMIT_MISMATCH")
			return ErrPermitMismatch
		}

		if receipt.Status != TerminalStatusCompleted {
			l.failAndHalt(state, pending, "INVALID_RECEIPT_STATUS")
			return fmt.Errorf("%w: receipt status must be %q", ErrSettlementEvidence, TerminalStatusCompleted)
		}
		respID, err := validateIdentifier(receipt.ResponseID, "response_id")
		if err != nil {
			l.failAndHalt(state, pending, "INVALID_RESPONSE_ID")
			return fmt.Errorf("%w: invalid response_id: %v", ErrSettlementEvidence, err)
		}
		for _, e := range state.Journal {
			if e.ResponseID == respID {
				l.failAndHalt(state, pending, "REPLAYED_RESPONSE_ID")
				return fmt.Errorf("%w: response_id %q already settled in journal", ErrSettlementEvidence, respID)
			}
		}
		if receipt.RequestID != pending.RequestID {
			l.failAndHalt(state, pending, "REQUEST_ID_MISMATCH")
			return fmt.Errorf("%w: request_id mismatch", ErrSettlementEvidence)
		}
		if receipt.RequestDigest != pending.RequestDigest {
			l.failAndHalt(state, pending, "REQUEST_DIGEST_MISMATCH")
			return fmt.Errorf("%w: request_digest mismatch", ErrSettlementEvidence)
		}
		rate, ok := ModelRates[receipt.Model]
		if !ok {
			l.failAndHalt(state, pending, "RECEIPT_MODEL_MISMATCH")
			return fmt.Errorf("%w: unpriced model %s", ErrSettlementEvidence, receipt.Model)
		}
		if receipt.ServiceTier != rate.ServiceTier {
			l.failAndHalt(state, pending, "RECEIPT_SERVICE_TIER_MISMATCH")
			return fmt.Errorf("%w: service tier mismatch %s", ErrSettlementEvidence, receipt.ServiceTier)
		}
		if receipt.InputTokens < 0 || receipt.InputTokens > MaxInputTokens {
			l.failAndHalt(state, pending, "RECEIPT_TOKEN_BOUND_EXCEEDED")
			return fmt.Errorf("%w: input_tokens out of bounds: %d", ErrSettlementEvidence, receipt.InputTokens)
		}
		if receipt.OutputTokens < 0 || receipt.OutputTokens > MaxOutputTokens {
			l.failAndHalt(state, pending, "RECEIPT_TOKEN_BOUND_EXCEEDED")
			return fmt.Errorf("%w: output_tokens out of bounds: %d", ErrSettlementEvidence, receipt.OutputTokens)
		}
		if receipt.TotalTokens != receipt.InputTokens+receipt.OutputTokens {
			l.failAndHalt(state, pending, "TOKEN_SUM_INCONSISTENT")
			return fmt.Errorf("%w: total_tokens %d != input %d + output %d", ErrSettlementEvidence, receipt.TotalTokens, receipt.InputTokens, receipt.OutputTokens)
		}

		accountedCost, err := ModelCostMicros(receipt.Model, receipt.ServiceTier, receipt.InputTokens, receipt.OutputTokens)
		if err != nil {
			l.failAndHalt(state, pending, "RECEIPT_MODEL_MISMATCH")
			return fmt.Errorf("%w: %v", ErrSettlementEvidence, err)
		}
		if accountedCost > pending.ReservedAmountMicros {
			l.failAndHalt(state, pending, "COST_EXCEEDS_RESERVATION")
			return fmt.Errorf("%w: cost %d exceeds reservation %d", ErrSettlementEvidence, accountedCost, pending.ReservedAmountMicros)
		}

		unencumbered := pending.ReservedAmountMicros - accountedCost
		settledAt := nowUTCStr()

		// Write intent record
		intentRec := WitnessRecord{
			RecordType:               "SETTLEMENT_INTENT",
			ExperimentID:             state.ExperimentID,
			ReservationID:            permit.PermitID,
			RequestID:                permit.RequestID,
			RequestDigest:            permit.RequestDigest,
			ResponseID:               receipt.ResponseID,
			Model:                    receipt.Model,
			ServiceTier:              receipt.ServiceTier,
			InputTokens:              receipt.InputTokens,
			OutputTokens:             receipt.OutputTokens,
			TotalTokens:              receipt.TotalTokens,
			SettledAmountMicros:      accountedCost,
			UnencumberedAmountMicros: unencumbered,
			TimestampUTC:             settledAt,
		}
		intentEnc, _ := json.MarshalIndent(intentRec, "", "  ")
		intentName := fmt.Sprintf("%s%s.json", IntentFilePrefix, permit.PermitID)
		if err := publishBytes(l.ledgerDir, intentName, ".tmp_intent_", intentEnc); err != nil {
			l.failAndHalt(state, pending, "SETTLEMENT_INTENT_WRITE_FAILED")
			return err
		}

		state.CommittedSpendMicros += accountedCost
		state.SettledRequestsCount++
		state.PendingReservation = nil
		state.UpdatedAtUTC = settledAt
		state.Journal = append(state.Journal, JournalEntry{
			EntryType:                "SETTLED",
			ReservationID:            permit.PermitID,
			RequestID:                permit.RequestID,
			RequestDigest:            permit.RequestDigest,
			ResponseID:               receipt.ResponseID,
			Model:                    receipt.Model,
			ServiceTier:              receipt.ServiceTier,
			InputTokens:              receipt.InputTokens,
			OutputTokens:             receipt.OutputTokens,
			TotalTokens:              receipt.TotalTokens,
			SettledAmountMicros:      accountedCost,
			UnencumberedAmountMicros: unencumbered,
			TimestampUTC:             settledAt,
		})

		if err := writeStateFile(l.ledgerDir, state); err != nil {
			l.poisonHandle("SETTLEMENT_WRITE_FAILED")
			return err
		}

		confRec := WitnessRecord{
			RecordType:               "SETTLEMENT_CONFIRMATION",
			ExperimentID:             state.ExperimentID,
			ReservationID:            permit.PermitID,
			RequestID:                permit.RequestID,
			RequestDigest:            permit.RequestDigest,
			ResponseID:               receipt.ResponseID,
			Model:                    receipt.Model,
			ServiceTier:              receipt.ServiceTier,
			InputTokens:              receipt.InputTokens,
			OutputTokens:             receipt.OutputTokens,
			TotalTokens:              receipt.TotalTokens,
			SettledAmountMicros:      accountedCost,
			UnencumberedAmountMicros: unencumbered,
			TimestampUTC:             settledAt,
		}
		confEnc, _ := json.MarshalIndent(confRec, "", "  ")
		confName := fmt.Sprintf("%s%s.json", ConfirmationFilePrefix, permit.PermitID)
		if err := publishBytes(l.ledgerDir, confName, ".tmp_confirm_", confEnc); err != nil {
			l.poisonHandle("SETTLEMENT_COMMITTED_CONFIRMATION_FAILED")
			result = &SettlementResult{
				RequestID:                permit.RequestID,
				PermitID:                 permit.PermitID,
				ResponseID:               receipt.ResponseID,
				AccountedCostMicros:      accountedCost,
				UnencumberedAmountMicros: unencumbered,
				InputTokens:              receipt.InputTokens,
				OutputTokens:             receipt.OutputTokens,
				TotalTokens:              receipt.TotalTokens,
				SettledAtUTC:             settledAt,
			}
			return nil
		}

		l.releaseLease()

		result = &SettlementResult{
			RequestID:                permit.RequestID,
			PermitID:                 permit.PermitID,
			ResponseID:               receipt.ResponseID,
			AccountedCostMicros:      accountedCost,
			UnencumberedAmountMicros: unencumbered,
			InputTokens:              receipt.InputTokens,
			OutputTokens:             receipt.OutputTokens,
			TotalTokens:              receipt.TotalTokens,
			SettledAtUTC:             settledAt,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

func (l *BudgetLedger) failAndHalt(state *LedgerState, pending *PendingReservationData, reason string) {
	if !AllowedInternalFailureCodes[reason] {
		reason = "INVALID_FAILURE_REASON_REJECTED"
	}
	l.poisonHandle(reason)

	if pending != nil {
		amount := pending.ReservedAmountMicros
		state.RetainedFailedMicros += amount
		state.PendingReservation = nil
		state.Halted = true
		state.HaltReason = &reason
		state.UpdatedAtUTC = nowUTCStr()
		state.Journal = append(state.Journal, JournalEntry{
			EntryType:            "FAILED_RETAINED",
			ReservationID:        pending.ReservationID,
			RequestID:            pending.RequestID,
			RetainedAmountMicros: amount,
			Reason:               reason,
			TimestampUTC:         state.UpdatedAtUTC,
		})
		_ = writeStateFile(l.ledgerDir, state)
	}
}

// RecordFailure atomically records failure for a pending reservation.
func (l *BudgetLedger) RecordFailure(permit *ReservationPermit, reason string) (*FailureResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var result *FailureResult

	err := l.withLock(func() error {
		state, err := l.guardedState()
		if err != nil {
			return err
		}

		pending := state.PendingReservation
		if pending == nil {
			return ErrNoPendingReservation
		}

		if permit == nil || permit.PermitID != pending.ReservationID ||
			permit.RequestID != pending.RequestID ||
			permit.RequestDigest != pending.RequestDigest {
			l.failAndHalt(state, pending, "PERMIT_MISMATCH")
			return ErrPermitMismatch
		}

		if !AllowedInternalFailureCodes[reason] {
			l.failAndHalt(state, pending, "INVALID_FAILURE_REASON_REJECTED")
			return fmt.Errorf("%w: invalid failure reason %s", ErrSettlementEvidence, reason)
		}

		retained := pending.ReservedAmountMicros
		failedAt := nowUTCStr()

		l.failAndHalt(state, pending, reason)

		result = &FailureResult{
			RequestID:            permit.RequestID,
			PermitID:             permit.PermitID,
			RetainedAmountMicros: retained,
			Reason:               reason,
			FailedAtUTC:          failedAt,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetStatus returns the current snapshot of ledger status.
func (l *BudgetLedger) GetStatus() (*LedgerStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var status *LedgerStatus

	err := l.withLock(func() error {
		state, err := l.guardedState()
		if err != nil {
			st, err2 := readStateFile(l.ledgerDir, l.experimentID)
			if err2 == nil {
				committed := st.CommittedSpendMicros
				retained := st.RetainedFailedMicros
				totalSpend := committed + retained
				pendingMicros := 0
				var pendingReqID *string
				if st.PendingReservation != nil {
					pendingMicros = st.PendingReservation.ReservedAmountMicros
					pendingReqID = &st.PendingReservation.RequestID
				}
				totalEnc := totalSpend + pendingMicros
				remaining := GlobalCeilingMicros - totalEnc
				if remaining < 0 {
					remaining = 0
				}
				derivedReason := "INSPECTION_EVIDENCE_UNCERTAINTY"
				if errors.Is(err, ErrGuardUnfinished) {
					derivedReason = "UNFINISHED_INSPECTION_GUARD"
				} else if l.poisonReason != "" {
					derivedReason = l.poisonReason
				}
				halted := st.Halted || derivedReason != ""
				haltReason := st.HaltReason
				if !st.Halted {
					haltReason = &derivedReason
				}
				var disabledReason *string
				if l.poisonReason != "" {
					disabledReason = &l.poisonReason
				} else if l.handleDisabledReason != nil {
					disabledReason = l.handleDisabledReason
				} else {
					disabledReason = &derivedReason
				}
				status = &LedgerStatus{
					ExperimentID:             st.ExperimentID,
					GlobalCeilingMicros:      GlobalCeilingMicros,
					CommittedSpendMicros:     committed,
					RetainedFailedMicros:     retained,
					TotalSpendMicros:         totalSpend,
					PendingReservedMicros:    pendingMicros,
					TotalEncumberedMicros:    totalEnc,
					RemainingAvailableMicros: remaining,
					RemainingBudgetMicros:    remaining,
					TotalReservationsCount:   st.TotalReservationsCount,
					SettledRequestsCount:     st.SettledRequestsCount,
					HasPendingReservation:    st.PendingReservation != nil,
					PendingRequestID:         pendingReqID,
					Halted:                   halted,
					HaltReason:               haltReason,
					HandleDisabled:           l.poisoned || l.handleDisabled,
					HandleDisabledReason:     disabledReason,
				}
				return nil
			}
			return err
		}

		committed := state.CommittedSpendMicros
		retained := state.RetainedFailedMicros
		totalSpend := committed + retained
		pendingMicros := 0
		var pendingReqID *string
		if state.PendingReservation != nil {
			pendingMicros = state.PendingReservation.ReservedAmountMicros
			pendingReqID = &state.PendingReservation.RequestID
		}
		totalEnc := totalSpend + pendingMicros
		remaining := GlobalCeilingMicros - totalEnc
		if remaining < 0 {
			remaining = 0
		}

		status = &LedgerStatus{
			ExperimentID:             state.ExperimentID,
			GlobalCeilingMicros:      GlobalCeilingMicros,
			CommittedSpendMicros:     committed,
			RetainedFailedMicros:     retained,
			TotalSpendMicros:         totalSpend,
			PendingReservedMicros:    pendingMicros,
			TotalEncumberedMicros:    totalEnc,
			RemainingAvailableMicros: remaining,
			RemainingBudgetMicros:    remaining,
			TotalReservationsCount:   state.TotalReservationsCount,
			SettledRequestsCount:     state.SettledRequestsCount,
			HasPendingReservation:    state.PendingReservation != nil,
			PendingRequestID:         pendingReqID,
			Halted:                   state.Halted,
			HaltReason:               state.HaltReason,
			HandleDisabled:           l.poisoned || l.handleDisabled,
			HandleDisabledReason:     l.handleDisabledReason,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return status, nil
}

// Close closes the ledger handle and releases any held lock or lease.
func (l *BudgetLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releaseLease()
	return nil
}

// ModelCost calculates the token cost for model and tier.
func ModelCost(model string, tier string, inTok, outTok int) (int, error) {
	return ModelCostMicros(model, tier, inTok, outTok)
}
