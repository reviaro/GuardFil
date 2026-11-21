package budget

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// faultFS is an unexported test seam that substitutes real filesystem operations.
type faultFS struct {
	base ledgerFS

	createTempFileFunc func(path string) (fileWriter, error)
	renameFunc         func(oldPath, newPath string) error
	removeFunc         func(path string) error
	openDirFunc        func(path string) (dirSyncer, error)
}

func (f *faultFS) getBase() ledgerFS {
	if f != nil && f.base != nil {
		return f.base
	}
	return defaultFS
}

func (f *faultFS) CreateTempFile(path string) (fileWriter, error) {
	if f != nil && f.createTempFileFunc != nil {
		return f.createTempFileFunc(path)
	}
	return f.getBase().CreateTempFile(path)
}

func (f *faultFS) Rename(oldPath, newPath string) error {
	if f != nil && f.renameFunc != nil {
		return f.renameFunc(oldPath, newPath)
	}
	return f.getBase().Rename(oldPath, newPath)
}

func (f *faultFS) Remove(path string) error {
	if f != nil && f.removeFunc != nil {
		return f.removeFunc(path)
	}
	return f.getBase().Remove(path)
}

func (f *faultFS) OpenDir(path string) (dirSyncer, error) {
	if f != nil && f.openDirFunc != nil {
		return f.openDirFunc(path)
	}
	return f.getBase().OpenDir(path)
}

// faultWriter wraps fileWriter substituting actual Write, Sync, or Close operations.
type faultWriter struct {
	base fileWriter

	writeFunc func(p []byte) (n int, err error)
	syncFunc  func() error
	closeFunc func() error
}

func (w *faultWriter) Write(p []byte) (n int, err error) {
	if w != nil && w.writeFunc != nil {
		return w.writeFunc(p)
	}
	return w.base.Write(p)
}

func (w *faultWriter) Sync() error {
	if w != nil && w.syncFunc != nil {
		return w.syncFunc()
	}
	return w.base.Sync()
}

func (w *faultWriter) Close() error {
	if w != nil && w.closeFunc != nil {
		return w.closeFunc()
	}
	return w.base.Close()
}

// faultDirSyncer wraps dirSyncer substituting actual directory Sync or Close operations.
type faultDirSyncer struct {
	base dirSyncer

	syncFunc  func() error
	closeFunc func() error
}

func (d *faultDirSyncer) Sync() error {
	if d != nil && d.syncFunc != nil {
		return d.syncFunc()
	}
	return d.base.Sync()
}

func (d *faultDirSyncer) Close() error {
	if d != nil && d.closeFunc != nil {
		return d.closeFunc()
	}
	return d.base.Close()
}

func assertNoTmpFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp_") {
			t.Errorf("leaked temporary file found: %s", e.Name())
		}
	}
}

func makeTestReceipt(p *ReservationPermit, respID string, inTok, outTok int) *Receipt {
	return &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    respID,
		RequestID:     p.RequestID,
		RequestDigest: p.RequestDigest,
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   inTok,
		OutputTokens:  outTok,
		TotalTokens:   inTok + outTok,
	}
}

// TestDurabilityPublishBytesPreRenameFaults verifies that substituting actual
// file IO operations (create temp, Write short, Write error, Sync error, Close error, Rename error)
// causes publishBytes to return an error, poison the handle, leak no temp files,
// and leave state unmutated on disk. When the fault is removed, fresh handles can open with
// 0 spend and successfully reserve (failures before dispatch need not falsely claim actual spend).
func TestDurabilityPublishBytesPreRenameFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "create_temp",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						if strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return nil, errors.New("simulated temp file creation failure")
						}
						return defaultFS.CreateTempFile(path)
					},
				}
			},
		},
		{
			name: "write_error",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								writeFunc: func(p []byte) (int, error) {
									return 0, errors.New("simulated disk write failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "short_write",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								writeFunc: func(p []byte) (int, error) {
									// Return n < len(p) directly from Write interface
									if len(p) > 1 {
										return realF.Write(p[:1])
									}
									return realF.Write(p)
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "file_sync",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								syncFunc: func() error {
									return errors.New("simulated file fsync failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "file_close",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								closeFunc: func() error {
									_ = realF.Close()
									return errors.New("simulated file close failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "rename",
			setupFS: func() ledgerFS {
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == StateFilename {
							return errors.New("simulated rename failure")
						}
						return defaultFS.Rename(oldPath, newPath)
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-durability-pre")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			// Attach fault filesystem scoped to this ledger handle
			l.fs = tc.setupFS()

			// Attempt Reserve under fault
			permit, err := l.Reserve("req-1", "sha256:1", 20000)
			if err == nil {
				t.Fatalf("expected error on Reserve with fault %s, got nil", tc.name)
			}
			if permit != nil {
				t.Fatalf("no permit should be returned on failed durability, got %+v", permit)
			}

			// Handle must be poisoned
			if !l.poisoned {
				t.Errorf("handle must be poisoned after failed reserve write")
			}
			if l.poisonReason != "RESERVE_DURABLE_WRITE_FAILED" {
				t.Errorf("expected RESERVE_DURABLE_WRITE_FAILED, got %s", l.poisonReason)
			}

			// Subsequent operations on poisoned handle must fail closed
			_, err = l.Reserve("req-2", "sha256:2", 20000)
			if !errors.Is(err, ErrLedgerHalted) {
				t.Errorf("subsequent reserve on poisoned handle must return ErrLedgerHalted, got %v", err)
			}

			// No temporary files leaked
			assertNoTmpFiles(t, ledgerDir)

			// Remove fault by opening a fresh handle with defaultFS
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("fresh Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("fresh GetStatus failed: %v", err)
			}
			if st.Halted {
				t.Errorf("expected fresh ledger to not be halted, halt_reason=%v", st.HaltReason)
			}
			if st.TotalSpendMicros != 0 || st.CommittedSpendMicros != 0 || st.RetainedFailedMicros != 0 {
				t.Errorf("pre-dispatch failure should not claim spend: %+v", st)
			}
			if st.TotalReservationsCount != 0 {
				t.Errorf("reservations count must be 0, got %d", st.TotalReservationsCount)
			}
			if st.HasPendingReservation {
				t.Errorf("expected no pending reservation on fresh open")
			}

			// Fresh handle must be fully functional and able to reserve
			pFresh, err := fresh.Reserve("req-recovered", "sha256:recovered", 20000)
			if err != nil {
				t.Fatalf("fresh Reserve after fault removed failed: %v", err)
			}
			if pFresh == nil || pFresh.PermitID == "" {
				t.Fatalf("expected valid permit, got %+v", pFresh)
			}
		})
	}
}

// TestDurabilityPublishBytesPostRenameFaults verifies directory open, sync, and close faults
// after rename has replaced the file on disk. The caller receives an error, no permit is returned,
// the current handle fails closed, and fresh open retains the reservation as failed
// (cannot undercount possibly dispatched requests).
func TestDurabilityPublishBytesPostRenameFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "open_dir",
			setupFS: func() ledgerFS {
				stateRenamed := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == StateFilename {
							stateRenamed = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					openDirFunc: func(path string) (dirSyncer, error) {
						if stateRenamed {
							return nil, errors.New("simulated directory open failure")
						}
						return defaultFS.OpenDir(path)
					},
				}
			},
		},
		{
			name: "sync_dir",
			setupFS: func() ledgerFS {
				stateRenamed := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == StateFilename {
							stateRenamed = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					openDirFunc: func(path string) (dirSyncer, error) {
						realDir, err := defaultFS.OpenDir(path)
						if err != nil {
							return nil, err
						}
						return &faultDirSyncer{
							base: realDir,
							syncFunc: func() error {
								if stateRenamed {
									return errors.New("simulated directory fsync failure")
								}
								return realDir.Sync()
							},
						}, nil
					},
				}
			},
		},
		{
			name: "close_dir",
			setupFS: func() ledgerFS {
				stateRenamed := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == StateFilename {
							stateRenamed = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					openDirFunc: func(path string) (dirSyncer, error) {
						realDir, err := defaultFS.OpenDir(path)
						if err != nil {
							return nil, err
						}
						return &faultDirSyncer{
							base: realDir,
							closeFunc: func() error {
								_ = realDir.Close()
								if stateRenamed {
									return errors.New("simulated directory close failure")
								}
								return nil
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-durability-post")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			// Attach fault filesystem scoped to this ledger handle
			l.fs = tc.setupFS()

			// Reserve under post-rename fault
			permit, err := l.Reserve("req-post", "sha256:post", 25000)
			if err == nil {
				t.Fatalf("expected error on Reserve with post-rename fault %s, got nil", tc.name)
			}
			if permit != nil {
				t.Fatalf("no permit should be returned on failed durability, got %+v", permit)
			}

			if !l.poisoned {
				t.Errorf("handle must be poisoned after failed reserve write")
			}

			// Current handle fails closed
			_, err = l.Reserve("req-blocked", "sha256:b", 20000)
			if !errors.Is(err, ErrLedgerHalted) {
				t.Errorf("expected ErrLedgerHalted on poisoned handle, got %v", err)
			}

			// Fresh open with defaultFS: because rename completed before directory sync failure,
			// the state file on disk has the reservation. With the lease released,
			// fresh open detects orphaned pending reservation and conservatively halts.
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("fresh Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("fresh GetStatus failed: %v", err)
			}
			if !st.Halted {
				t.Errorf("expected fresh ledger to halt on orphaned pending reservation")
			}
			if st.HaltReason == nil || *st.HaltReason != "UNSETTLED_PENDING_RESERVATION_AT_STARTUP" {
				t.Errorf("expected UNSETTLED_PENDING_RESERVATION_AT_STARTUP, got %v", st.HaltReason)
			}
			if st.RetainedFailedMicros != 25000 {
				t.Errorf("expected full reservation amount 25000 to be retained, got %d", st.RetainedFailedMicros)
			}
			if st.RemainingAvailableMicros != GlobalCeilingMicros-25000 {
				t.Errorf("expected remaining available %d, got %d", GlobalCeilingMicros-25000, st.RemainingAvailableMicros)
			}

			// Cannot reserve on halted ledger
			_, err = fresh.Reserve("req-cant-reserve", "sha256:c", 20000)
			if !errors.Is(err, ErrLedgerHalted) {
				t.Errorf("expected ErrLedgerHalted, got %v", err)
			}
		})
	}
}

// TestDurabilityArmGuardUnlinkFault verifies that failure to remove the inspection completion
// witness in armGuard returns an error, poisons the handle, and leaves state unmutated.
func TestDurabilityArmGuardUnlinkFault(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "ledger")

	l, err := Initialize(ledgerDir, "test-arm-unlink")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer l.Close()

	l.fs = &faultFS{
		removeFunc: func(path string) error {
			if filepath.Base(path) == InspectionCompletionFilename {
				return errors.New("simulated unlink completion witness failure")
			}
			return defaultFS.Remove(path)
		},
	}

	permit, err := l.Reserve("req-unlink", "sha256:u", 20000)
	if err == nil {
		t.Fatalf("expected error on unlink fault, got nil")
	}
	if permit != nil {
		t.Fatalf("no permit should be returned, got %+v", permit)
	}

	if !l.poisoned {
		t.Errorf("handle must be poisoned")
	}
	if l.poisonReason != "INSPECTION_GUARD_CORRUPT" {
		t.Errorf("expected INSPECTION_GUARD_CORRUPT, got %s", l.poisonReason)
	}

	// Since completion file was not removed and guard was not bumped,
	// fresh handle can open cleanly with defaultFS.
	fresh, err := Open(ledgerDir)
	if err != nil {
		t.Fatalf("fresh Open failed: %v", err)
	}
	defer fresh.Close()

	st, err := fresh.GetStatus()
	if err != nil {
		t.Fatalf("fresh GetStatus failed: %v", err)
	}
	if st.Halted || st.HandleDisabled {
		t.Errorf("expected healthy fresh ledger, got halted=%v, disabled=%v", st.Halted, st.HandleDisabled)
	}
}

// TestDurabilityArmGuardPublishFaults verifies faults publishing the inspection guard
// (sync, rename, sync_dir) fail closed, poison the handle, and prevent any state mutation.
func TestDurabilityArmGuardPublishFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "guard_sync",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_guard_") {
							return &faultWriter{
								base: realF,
								syncFunc: func() error {
									return errors.New("simulated guard sync failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "guard_rename",
			setupFS: func() ledgerFS {
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == InspectionGuardFilename {
							return errors.New("simulated guard rename failure")
						}
						return defaultFS.Rename(oldPath, newPath)
					},
				}
			},
		},
		{
			name: "guard_sync_dir",
			setupFS: func() ledgerFS {
				guardRenamed := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == InspectionGuardFilename {
							guardRenamed = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					openDirFunc: func(path string) (dirSyncer, error) {
						realDir, err := defaultFS.OpenDir(path)
						if err != nil {
							return nil, err
						}
						return &faultDirSyncer{
							base: realDir,
							syncFunc: func() error {
								if guardRenamed {
									return errors.New("simulated guard directory fsync failure")
								}
								return realDir.Sync()
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-arm-publish")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			l.fs = tc.setupFS()

			permit, err := l.Reserve("req-guard-fault", "sha256:g", 20000)
			if err == nil {
				t.Fatalf("expected error on guard publish fault %s", tc.name)
			}
			if permit != nil {
				t.Fatalf("no permit should be returned")
			}

			if !l.poisoned {
				t.Errorf("handle must be poisoned")
			}

			// Fresh open fails closed because completion witness was unlinked before guard publish failed
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("GetStatus failed: %v", err)
			}
			if !st.HandleDisabled {
				t.Errorf("expected fresh handle to be disabled with missing/stale completion witness")
			}
			if st.HandleDisabledReason == nil || *st.HandleDisabledReason != "UNFINISHED_INSPECTION_GUARD" {
				t.Errorf("expected UNFINISHED_INSPECTION_GUARD, got %v", st.HandleDisabledReason)
			}
		})
	}
}

// TestDurabilityCompleteGuardPublishFaults verifies faults publishing inspection completion
// witness poison the handle with INSPECTION_COMPLETION_FAILED, prevent any mutation,
// and fresh handles fail closed when completion was lost before rename, or succeed when completion
// survived rename.
func TestDurabilityCompleteGuardPublishFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "comp_sync",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_comp_") {
							return &faultWriter{
								base: realF,
								syncFunc: func() error {
									return errors.New("simulated comp sync failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "comp_rename",
			setupFS: func() ledgerFS {
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == InspectionCompletionFilename {
							return errors.New("simulated comp rename failure")
						}
						return defaultFS.Rename(oldPath, newPath)
					},
				}
			},
		},
		{
			name: "comp_sync_dir",
			setupFS: func() ledgerFS {
				compRenamed := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if filepath.Base(newPath) == InspectionCompletionFilename {
							compRenamed = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					openDirFunc: func(path string) (dirSyncer, error) {
						realDir, err := defaultFS.OpenDir(path)
						if err != nil {
							return nil, err
						}
						return &faultDirSyncer{
							base: realDir,
							syncFunc: func() error {
								if compRenamed {
									return errors.New("simulated comp directory sync failure")
								}
								return realDir.Sync()
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-comp-publish")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			l.fs = tc.setupFS()

			permit, err := l.Reserve("req-comp-fault", "sha256:c", 20000)
			if err == nil {
				t.Fatalf("expected error on completion publish fault %s", tc.name)
			}
			if permit != nil {
				t.Fatalf("no permit should be returned")
			}

			if !l.poisoned {
				t.Errorf("handle must be poisoned")
			}
			if l.poisonReason != "INSPECTION_COMPLETION_FAILED" {
				t.Errorf("expected INSPECTION_COMPLETION_FAILED, got %s", l.poisonReason)
			}

			// Fresh open with defaultFS:
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("GetStatus failed: %v", err)
			}

			if tc.name == "comp_sync_dir" {
				// Completion witness survived rename, so fresh handle can proceed
				if st.HandleDisabled {
					t.Errorf("expected fresh handle to be enabled when completion witness survived rename")
				}
				pFresh, err := fresh.Reserve("req-fresh-comp", "sha256:fc", 20000)
				if err != nil || pFresh == nil {
					t.Errorf("expected successful reserve after completion witness survived: %v", err)
				}
			} else {
				// Completion witness was lost before rename
				if !st.HandleDisabled {
					t.Errorf("expected fresh handle to be disabled when completion witness was lost")
				}
				if st.HandleDisabledReason == nil || *st.HandleDisabledReason != "UNFINISHED_INSPECTION_GUARD" {
					t.Errorf("expected UNFINISHED_INSPECTION_GUARD, got %v", st.HandleDisabledReason)
				}
			}
		})
	}
}

// TestDurabilitySettleIntentFaults verifies that failures publishing settlement intent
// return an error, poison the handle with SETTLEMENT_INTENT_WRITE_FAILED, retain the full
// reserved amount as failed, and fresh opens detect the halt.
func TestDurabilitySettleIntentFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "intent_write",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_intent_") {
							return &faultWriter{
								base: realF,
								writeFunc: func(p []byte) (int, error) {
									return 0, errors.New("simulated intent write failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "intent_sync",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_intent_") {
							return &faultWriter{
								base: realF,
								syncFunc: func() error {
									return errors.New("simulated intent sync failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "intent_rename",
			setupFS: func() ledgerFS {
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if strings.HasPrefix(filepath.Base(newPath), IntentFilePrefix) {
							return errors.New("simulated intent rename failure")
						}
						return defaultFS.Rename(oldPath, newPath)
					},
				}
			},
		},
		{
			name: "intent_sync_dir",
			setupFS: func() ledgerFS {
				intentRenamed := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if strings.HasPrefix(filepath.Base(newPath), IntentFilePrefix) {
							intentRenamed = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					openDirFunc: func(path string) (dirSyncer, error) {
						realDir, err := defaultFS.OpenDir(path)
						if err != nil {
							return nil, err
						}
						return &faultDirSyncer{
							base: realDir,
							syncFunc: func() error {
								if intentRenamed {
									return errors.New("simulated intent dir sync failure")
								}
								return realDir.Sync()
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-intent-fault")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			p, err := l.Reserve("req-intent", "sha256:i", 30000)
			if err != nil {
				t.Fatalf("Reserve failed: %v", err)
			}

			receipt := makeTestReceipt(p, "resp-intent", 10, 10)

			l.fs = tc.setupFS()

			res, err := l.Settle(p, receipt)
			if err == nil {
				t.Fatalf("expected error on intent publish fault %s, got nil", tc.name)
			}
			if res != nil {
				t.Fatalf("no result should be returned on failed intent durability, got %+v", res)
			}

			if !l.poisoned {
				t.Errorf("handle must be poisoned")
			}
			if l.poisonReason != "SETTLEMENT_INTENT_WRITE_FAILED" {
				t.Errorf("expected SETTLEMENT_INTENT_WRITE_FAILED, got %s", l.poisonReason)
			}

			// Fresh open with defaultFS sees FAILED_RETAINED state with full amount retained
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("fresh Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("fresh GetStatus failed: %v", err)
			}
			if !st.Halted {
				t.Errorf("expected fresh ledger to be halted")
			}
			if st.HaltReason == nil || *st.HaltReason != "SETTLEMENT_INTENT_WRITE_FAILED" {
				t.Errorf("expected SETTLEMENT_INTENT_WRITE_FAILED, got %v", st.HaltReason)
			}
			if st.RetainedFailedMicros != 30000 {
				t.Errorf("expected 30000 retained spend, got %d", st.RetainedFailedMicros)
			}
			if st.CommittedSpendMicros != 0 {
				t.Errorf("expected 0 committed spend, got %d", st.CommittedSpendMicros)
			}
		})
	}
}

// TestDurabilitySettleStateFaults verifies that failure writing the state file after intent
// was published poisons the handle, returns error, and recovery on a fresh handle
// detects the unresolved settlement publication and halts conservatively with full retention.
func TestDurabilitySettleStateFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "state_write",
			setupFS: func() ledgerFS {
				intentDone := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if strings.HasPrefix(filepath.Base(newPath), IntentFilePrefix) {
							intentDone = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if intentDone && strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								writeFunc: func(p []byte) (int, error) {
									return 0, errors.New("simulated state write failure during settle")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "state_sync",
			setupFS: func() ledgerFS {
				intentDone := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if strings.HasPrefix(filepath.Base(newPath), IntentFilePrefix) {
							intentDone = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if intentDone && strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								syncFunc: func() error {
									return errors.New("simulated state sync failure during settle")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-settle-state-fault")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			p, err := l.Reserve("req-ss", "sha256:ss", 40000)
			if err != nil {
				t.Fatalf("Reserve failed: %v", err)
			}

			receipt := makeTestReceipt(p, "resp-ss", 10, 10)

			l.fs = tc.setupFS()

			res, err := l.Settle(p, receipt)
			if err == nil {
				t.Fatalf("expected error on settle state fault %s", tc.name)
			}
			if res != nil {
				t.Fatalf("no result should be returned on failed state durability, got %+v", res)
			}

			if !l.poisoned {
				t.Errorf("handle must be poisoned")
			}
			if l.poisonReason != "SETTLEMENT_WRITE_FAILED" {
				t.Errorf("expected SETTLEMENT_WRITE_FAILED, got %s", l.poisonReason)
			}

			// Fresh open runs validateAndRecoverRecordsUnderLock with defaultFS:
			// Sees intent file without matching settlement in state, halts with UNRESOLVED_SETTLEMENT_PUBLICATION
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("fresh Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("fresh GetStatus failed: %v", err)
			}
			if !st.Halted {
				t.Errorf("expected fresh ledger to be halted")
			}
			if st.HaltReason == nil || *st.HaltReason != "UNRESOLVED_SETTLEMENT_PUBLICATION" {
				t.Errorf("expected UNRESOLVED_SETTLEMENT_PUBLICATION, got %v", st.HaltReason)
			}
			if st.RetainedFailedMicros != 40000 {
				t.Errorf("expected 40000 retained spend, got %d", st.RetainedFailedMicros)
			}
			if st.CommittedSpendMicros != 0 {
				t.Errorf("expected 0 committed spend, got %d", st.CommittedSpendMicros)
			}
		})
	}
}

// TestDurabilitySettleConfirmationFaults verifies that failure publishing confirmation witness:
//  1. Returns a non-nil error to the caller (no success returned on failed durability!)
//  2. Returns nil *SettlementResult
//  3. Error can be type-asserted to *SettlementCommittedHandleDisabledOutcome
//  4. Handle is poisoned with SETTLEMENT_COMMITTED_CONFIRMATION_FAILED
//  5. If confirmation was lost before rename (write, sync, close, rename), fresh open detects
//     missing confirmation witness, halts with TERMINAL_UNCERTAINTY/UNRESOLVED_SETTLEMENT_PUBLICATION,
//     reverses committed spend, and retains the full reservation amount (ambiguous settlement
//     does not release unaccounted money).
//  6. If confirmation survived rename but directory sync failed (sync_dir), fresh open finds both
//     witnesses intact and accounts for the settlement cleanly without undercounting.
func TestDurabilitySettleConfirmationFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "conf_write",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_confirm_") {
							return &faultWriter{
								base: realF,
								writeFunc: func(p []byte) (int, error) {
									return 0, errors.New("simulated conf write failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "conf_sync",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_confirm_") {
							return &faultWriter{
								base: realF,
								syncFunc: func() error {
									return errors.New("simulated conf sync failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "conf_close",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_confirm_") {
							return &faultWriter{
								base: realF,
								closeFunc: func() error {
									_ = realF.Close()
									return errors.New("simulated conf close failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "conf_rename",
			setupFS: func() ledgerFS {
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if strings.HasPrefix(filepath.Base(newPath), ConfirmationFilePrefix) {
							return errors.New("simulated conf rename failure")
						}
						return defaultFS.Rename(oldPath, newPath)
					},
				}
			},
		},
		{
			name: "conf_sync_dir",
			setupFS: func() ledgerFS {
				confRenamed := false
				return &faultFS{
					renameFunc: func(oldPath, newPath string) error {
						if strings.HasPrefix(filepath.Base(newPath), ConfirmationFilePrefix) {
							confRenamed = true
						}
						return defaultFS.Rename(oldPath, newPath)
					},
					openDirFunc: func(path string) (dirSyncer, error) {
						realDir, err := defaultFS.OpenDir(path)
						if err != nil {
							return nil, err
						}
						return &faultDirSyncer{
							base: realDir,
							syncFunc: func() error {
								if confRenamed {
									return errors.New("simulated conf directory sync failure")
								}
								return realDir.Sync()
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-conf-fault")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			p, err := l.Reserve("req-conf", "sha256:c", 50000)
			if err != nil {
				t.Fatalf("Reserve failed: %v", err)
			}

			receipt := makeTestReceipt(p, "resp-conf", 100, 50) // cost = 100*1 + 50*1 = 150 uUSD

			l.fs = tc.setupFS()

			res, err := l.Settle(p, receipt)

			// Invariant: No success returned on failed durability!
			if err == nil {
				t.Fatalf("expected non-nil error when confirmation publication fails, got nil")
			}
			if res != nil {
				t.Fatalf("expected nil SettlementResult on failed durability, got %+v", res)
			}

			// Must be type-assertable to SettlementCommittedHandleDisabledOutcome
			outcome, ok := err.(*SettlementCommittedHandleDisabledOutcome)
			if !ok {
				t.Fatalf("expected error to be *SettlementCommittedHandleDisabledOutcome, got %T: %v", err, err)
			}
			if !outcome.HandleDisabled || !outcome.IsCommitted {
				t.Errorf("outcome flags mismatch: %+v", outcome)
			}
			if outcome.AccountedCostMicros != 150 {
				t.Errorf("expected accounted cost 150, got %d", outcome.AccountedCostMicros)
			}

			// errors.Is must match ErrLedgerHalted
			if !errors.Is(err, ErrLedgerHalted) {
				t.Errorf("expected errors.Is(err, ErrLedgerHalted) to be true")
			}

			if !l.poisoned {
				t.Errorf("handle must be poisoned")
			}
			if l.poisonReason != "SETTLEMENT_COMMITTED_CONFIRMATION_FAILED" {
				t.Errorf("expected SETTLEMENT_COMMITTED_CONFIRMATION_FAILED, got %s", l.poisonReason)
			}

			// Fresh open with defaultFS:
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("fresh Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("fresh GetStatus failed: %v", err)
			}

			if tc.name == "conf_sync_dir" {
				// Confirmation survived rename, so fresh handle has clean verified settlement
				if st.Halted {
					t.Errorf("expected fresh ledger to not be halted when confirmation survived rename")
				}
				if st.CommittedSpendMicros != 150 {
					t.Errorf("expected 150 committed spend, got %d", st.CommittedSpendMicros)
				}
			} else {
				// Missing confirmation witness causes bad=true -> halts with TERMINAL_UNCERTAINTY
				// Committed spend reversed, full 50000 retained as failed!
				if !st.Halted {
					t.Errorf("expected fresh ledger to halt on missing confirmation")
				}
				if st.HaltReason == nil || (*st.HaltReason != "TERMINAL_UNCERTAINTY" && *st.HaltReason != "UNRESOLVED_SETTLEMENT_PUBLICATION") {
					var gotReason string
					if st.HaltReason != nil {
						gotReason = *st.HaltReason
					}
					t.Errorf("expected TERMINAL_UNCERTAINTY or UNRESOLVED_SETTLEMENT_PUBLICATION, got %s", gotReason)
				}
				if st.CommittedSpendMicros != 0 {
					t.Errorf("expected committed spend to be reversed to 0, got %d", st.CommittedSpendMicros)
				}
				if st.RetainedFailedMicros != 50000 {
					t.Errorf("expected entire reservation 50000 to be retained as failed, got %d", st.RetainedFailedMicros)
				}
			}
		})
	}
}

// TestDurabilityRecordFailureFaults verifies that failure during RecordFailure state write
// returns an error (no success returned on failed durability), poisons handle,
// and fresh open conservatively halts on orphaned pending reservation.
func TestDurabilityRecordFailureFaults(t *testing.T) {
	faultCases := []struct {
		name    string
		setupFS func() ledgerFS
	}{
		{
			name: "recfail_write",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								writeFunc: func(p []byte) (int, error) {
									return 0, errors.New("simulated state write failure during record failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
		{
			name: "recfail_sync",
			setupFS: func() ledgerFS {
				return &faultFS{
					createTempFileFunc: func(path string) (fileWriter, error) {
						realF, err := defaultFS.CreateTempFile(path)
						if err != nil {
							return nil, err
						}
						if strings.HasPrefix(filepath.Base(path), ".tmp_ledger_") {
							return &faultWriter{
								base: realF,
								syncFunc: func() error {
									return errors.New("simulated state sync failure during record failure")
								},
							}, nil
						}
						return realF, nil
					},
				}
			},
		},
	}

	for _, tc := range faultCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			l, err := Initialize(ledgerDir, "test-recfail-fault")
			if err != nil {
				t.Fatalf("Initialize failed: %v", err)
			}
			defer l.Close()

			p, err := l.Reserve("req-rf", "sha256:rf", 35000)
			if err != nil {
				t.Fatalf("Reserve failed: %v", err)
			}

			l.fs = tc.setupFS()

			res, err := l.RecordFailure(p, "REQUEST_TRANSPORT_FAILURE")
			if err == nil {
				t.Fatalf("expected error on RecordFailure with fault %s, got nil", tc.name)
			}
			if res != nil {
				t.Fatalf("no result should be returned on failed durability, got %+v", res)
			}

			if !l.poisoned {
				t.Errorf("handle must be poisoned")
			}

			// Fresh open with defaultFS: state write failed, so pending reservation is still in state without lease.
			// Conservatively halts with UNSETTLED_PENDING_RESERVATION_AT_STARTUP and retains 35000.
			fresh, err := Open(ledgerDir)
			if err != nil {
				t.Fatalf("fresh Open failed: %v", err)
			}
			defer fresh.Close()

			st, err := fresh.GetStatus()
			if err != nil {
				t.Fatalf("fresh GetStatus failed: %v", err)
			}
			if !st.Halted {
				t.Errorf("expected fresh ledger to halt on orphaned pending reservation")
			}
			if st.RetainedFailedMicros != 35000 {
				t.Errorf("expected 35000 retained, got %d", st.RetainedFailedMicros)
			}
		})
	}
}

// TestDurabilityInitializeFaults verifies that failures during Initialize
// (state, guard, or completion publication) return an error, leave no working ledger,
// and fresh Initialize succeeds once the fault is removed.
func TestDurabilityInitializeFaults(t *testing.T) {
	targets := []struct {
		name   string
		prefix string
	}{
		{"state", ".tmp_ledger_"},
		{"guard", ".tmp_guard_"},
		{"comp", ".tmp_comp_"},
	}

	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")

			faultyFS := &faultFS{
				createTempFileFunc: func(path string) (fileWriter, error) {
					realF, err := defaultFS.CreateTempFile(path)
					if err != nil {
						return nil, err
					}
					if strings.HasPrefix(filepath.Base(path), tc.prefix) {
						return &faultWriter{
							base: realF,
							syncFunc: func() error {
								return fmt.Errorf("injected init fault on %s", tc.name)
							},
						}, nil
					}
					return realF, nil
				},
			}

			l, err := initializeInternal(ledgerDir, "test-init-fault", faultyFS)
			if err == nil {
				t.Fatalf("expected error during Initialize on %s fault, got nil", tc.name)
			}
			if l != nil {
				t.Fatalf("expected nil ledger on failed Initialize")
			}

			// Clean retry on fresh directory with defaultFS must succeed
			retryDir := filepath.Join(tempDir, "ledger_retry")
			lOk, err := Initialize(retryDir, "test-init-retry")
			if err != nil {
				t.Fatalf("fresh Initialize after fault removed failed: %v", err)
			}
			defer lOk.Close()

			st, err := lOk.GetStatus()
			if err != nil || st.Halted || st.HandleDisabled {
				t.Errorf("expected healthy new ledger, got st=%+v, err=%v", st, err)
			}
		})
	}
}

// TestDurabilityDirectoryFsyncRealErrorHandling directly proves that directory open, sync,
// and close errors in publishBytes are not swallowed and return proper error messages.
// If publishBytes did not check dirF.Sync() or dirF.Close(), these tests would fail.
func TestDurabilityDirectoryFsyncRealErrorHandling(t *testing.T) {
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "test_dir_sync")
	if err := os.MkdirAll(testDir, 0700); err != nil {
		t.Fatal(err)
	}

	testData := []byte(`{"hello": "world"}`)

	// 1. Test directory open failure
	fsOpenErr := &faultFS{
		openDirFunc: func(path string) (dirSyncer, error) {
			return nil, errors.New("simulated open_dir failure")
		},
	}
	err := publishBytes(fsOpenErr, testDir, "test1.json", ".tmp_t1_", testData)
	if err == nil || !strings.Contains(err.Error(), "directory open error") {
		t.Errorf("expected directory open error, got %v", err)
	}

	// 2. Test directory sync failure - proves real dirSyncer.Sync() error is handled
	fsSyncErr := &faultFS{
		openDirFunc: func(path string) (dirSyncer, error) {
			realDir, err := defaultFS.OpenDir(path)
			if err != nil {
				return nil, err
			}
			return &faultDirSyncer{
				base: realDir,
				syncFunc: func() error {
					return errors.New("simulated sync_dir failure")
				},
			}, nil
		},
	}
	err = publishBytes(fsSyncErr, testDir, "test2.json", ".tmp_t2_", testData)
	if err == nil || !strings.Contains(err.Error(), "directory sync error") {
		t.Errorf("expected directory sync error, got %v", err)
	}

	// 3. Test directory close failure - proves real dirSyncer.Close() error is handled
	fsCloseErr := &faultFS{
		openDirFunc: func(path string) (dirSyncer, error) {
			realDir, err := defaultFS.OpenDir(path)
			if err != nil {
				return nil, err
			}
			return &faultDirSyncer{
				base: realDir,
				closeFunc: func() error {
					_ = realDir.Close()
					return errors.New("simulated close_dir failure")
				},
			}, nil
		},
	}
	err = publishBytes(fsCloseErr, testDir, "test3.json", ".tmp_t3_", testData)
	if err == nil || !strings.Contains(err.Error(), "directory close error") {
		t.Errorf("expected directory close error, got %v", err)
	}

	// 4. Healthy publish with defaultFS succeeds cleanly
	err = publishBytes(defaultFS, testDir, "test_healthy.json", ".tmp_th_", testData)
	if err != nil {
		t.Errorf("expected successful publishBytes, got %v", err)
	}
	content, err := os.ReadFile(filepath.Join(testDir, "test_healthy.json"))
	if err != nil || string(content) != string(testData) {
		t.Errorf("unexpected content: %s (err: %v)", string(content), err)
	}
}
