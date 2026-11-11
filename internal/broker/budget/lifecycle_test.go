package budget

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestInitializeCreatesPrivateDirectoryAndState(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")

	l, err := Initialize(ledgerDir, "test-init")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer l.Close()

	fi, err := os.Stat(ledgerDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0700 {
		t.Errorf("expected dir perm 0700, got %o", perm)
	}

	statePath := filepath.Join(ledgerDir, StateFilename)
	sfi, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := sfi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected state perm 0600, got %o", perm)
	}

	lockPath := filepath.Join(ledgerDir, LockFilename)
	lfi, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := lfi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected lock perm 0600, got %o", perm)
	}
}

func TestInitializeRefusesPreexistingDirectory(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")

	if err := os.Mkdir(ledgerDir, 0700); err != nil {
		t.Fatal(err)
	}

	if _, err := Initialize(ledgerDir, "test-init"); !errors.Is(err, ErrLedgerAlreadyExists) {
		t.Fatalf("expected ErrLedgerAlreadyExists, got %v", err)
	}
}

func TestOpenMissingDirectoryFailsClosed(t *testing.T) {
	tempDir := t.TempDir()
	missingDir := filepath.Join(tempDir, "nonexistent")

	if _, err := Open(missingDir); !errors.Is(err, ErrLedgerNotFound) {
		t.Fatalf("expected ErrLedgerNotFound, got %v", err)
	}
}

func TestOpenMissingStateFileFailsClosed(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")
	if err := os.Mkdir(ledgerDir, 0700); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerNotFound) && !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerNotFound or ErrLedgerCorrupt, got %v", err)
	}
}

func TestSecurityRejectsSymlinkedDirectory(t *testing.T) {
	tempDir := t.TempDir()
	realDir := filepath.Join(tempDir, "real_ledger")
	l, err := Initialize(realDir, "symlink-test")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	symDir := filepath.Join(tempDir, "sym_ledger")
	if err := os.Symlink(realDir, symDir); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(symDir); !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity for symlinked directory, got %v", err)
	}
}

func TestSecurityRejectsSymlinkedStateFile(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")
	l, err := Initialize(ledgerDir, "symlink-state")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	statePath := filepath.Join(ledgerDir, StateFilename)
	realState := filepath.Join(tempDir, "external_state.json")
	if err := os.Rename(statePath, realState); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realState, statePath); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity for symlinked state file, got %v", err)
	}
}

func TestSecurityRejectsSymlinkedLockFile(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")
	l, err := Initialize(ledgerDir, "symlink-lock")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	lockPath := filepath.Join(ledgerDir, LockFilename)
	realLock := filepath.Join(tempDir, "external_lock")
	if err := os.Rename(lockPath, realLock); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realLock, lockPath); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity for symlinked lock file, got %v", err)
	}
}

func TestSecurityRejectsHardLinksOnState(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")
	l, err := Initialize(ledgerDir, "hardlink-state")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	statePath := filepath.Join(ledgerDir, StateFilename)
	hardLinkPath := filepath.Join(tempDir, "hardlinked_state.json")
	if err := os.Link(statePath, hardLinkPath); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity for hard-linked state file, got %v", err)
	}
}

func TestSecurityRejectsPermissiveDirectoryPermissions(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")
	l, err := Initialize(ledgerDir, "perm-dir")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	if err := os.Chmod(ledgerDir, 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity for 0755 dir, got %v", err)
	}
}

func TestSecurityRejectsPermissiveStateFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")
	l, err := Initialize(ledgerDir, "perm-state")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	statePath := filepath.Join(ledgerDir, StateFilename)
	if err := os.Chmod(statePath, 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity for 0644 state, got %v", err)
	}
}

func TestConcurrentInitializeRaceOnlyOneSucceeds(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "race_ledger")

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)

	successCount := 0
	errAlreadyExistsCount := 0
	var mu sync.Mutex

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			l, err := Initialize(ledgerDir, "concurrent-init")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
				l.Close()
			} else if errors.Is(err, ErrLedgerAlreadyExists) {
				errAlreadyExistsCount++
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful initialization, got %d", successCount)
	}
	if errAlreadyExistsCount != n-1 {
		t.Fatalf("expected %d ErrLedgerAlreadyExists, got %d", n-1, errAlreadyExistsCount)
	}
}

func TestProcessDeathAndStartupOrphanedReservationHaltsLedger(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "orphan_ledger")

	l, err := Initialize(ledgerDir, "orphan-exp")
	if err != nil {
		t.Fatal(err)
	}

	permit, err := l.Reserve("req-crash", "sha256:crash", 50000)
	if err != nil {
		t.Fatal(err)
	}
	if permit == nil {
		t.Fatal("expected permit")
	}

	// Release lease simulate process crash without settle
	l.releaseLease()
	l.Close()

	// Reopen ledger: must detect orphaned pending reservation from crashed process and halt
	l2, err := Open(ledgerDir)
	if err != nil {
		t.Fatalf("failed to open orphaned ledger: %v", err)
	}
	defer l2.Close()

	st, err := l2.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Halted {
		t.Errorf("expected ledger to be halted on reopen")
	}
	if st.HaltReason == nil || *st.HaltReason != "UNSETTLED_PENDING_RESERVATION_AT_STARTUP" {
		t.Errorf("unexpected halt reason: %v", st.HaltReason)
	}
	if st.RetainedFailedMicros != 50000 {
		t.Errorf("expected 50000 retained failed, got %d", st.RetainedFailedMicros)
	}
	if st.HasPendingReservation {
		t.Errorf("expected pending reservation to be cleared")
	}
}

func TestRuntimeLockFileMissingRejected(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "missing_lock_ledger")

	l, err := Initialize(ledgerDir, "missing-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Remove lock file while handle is open
	lockPath := filepath.Join(ledgerDir, LockFilename)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}

	// Next operation must fail with ErrLedgerSecurity
	_, err = l.Reserve("req-1", "sha256:1", 10000)
	if !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity when lock file missing, got %v", err)
	}
}

func TestRuntimeLockFileReplacementRejected(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "replaced_lock_ledger")

	l, err := Initialize(ledgerDir, "replaced-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Replace lock file with permissive permissions
	lockPath := filepath.Join(ledgerDir, LockFilename)
	_ = os.Remove(lockPath)
	if err := os.WriteFile(lockPath, []byte("tampered"), 0666); err != nil {
		t.Fatal(err)
	}

	_, err = l.Reserve("req-1", "sha256:1", 10000)
	if !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity when lock file replaced, got %v", err)
	}
}

func TestLeaseContentionBetweenTwoHandles(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "contention_ledger")

	l1, err := Initialize(ledgerDir, "contention-exp")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()

	l2, err := Open(ledgerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	// Handle 1 reserves
	p1, err := l1.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}

	// Handle 2 attempts to reserve while lease is held
	_, err = l2.Reserve("req-2", "sha256:2", 20000)
	if !errors.Is(err, ErrInFlightReservation) {
		t.Fatalf("expected ErrInFlightReservation on handle 2, got %v", err)
	}

	// Settle on handle 1 releases lease
	r1 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-1",
		RequestID:     "req-1",
		RequestDigest: "sha256:1",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   10,
		OutputTokens:  10,
		TotalTokens:   20,
	}
	if _, err := l1.Settle(p1, r1); err != nil {
		t.Fatal(err)
	}

	// Handle 2 can now reserve
	p2, err := l2.Reserve("req-2", "sha256:2", 20000)
	if err != nil {
		t.Fatalf("handle 2 failed to reserve after settle: %v", err)
	}
	if p2 == nil {
		t.Fatal("expected permit on handle 2")
	}
}

func TestSwappedDirectoryRejected(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "swap_ledger")

	l, err := Initialize(ledgerDir, "swap-exp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Swap directory by renaming it and creating a dummy in its place
	renamedDir := filepath.Join(tempDir, "moved_ledger")
	if err := os.Rename(ledgerDir, renamedDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ledgerDir, 0700); err != nil {
		t.Fatal(err)
	}

	_, err = l.Reserve("req-1", "sha256:1", 10000)
	if !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity when directory swapped, got %v", err)
	}
}

func TestDirectoryIdentityPreservedOnOpenHandle(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ident_ledger")

	l, err := Initialize(ledgerDir, "ident-exp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	var st syscall.Stat_t
	if err := syscall.Stat(ledgerDir, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != uint32(os.Getuid()) {
		t.Errorf("expected owner %d, got %d", os.Getuid(), st.Uid)
	}
}
